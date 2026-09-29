package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/link"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// A warm receipt can only adopt an existing kernel generation in this boot
// and namespace. It is not a Durable agreement and cannot recreate a Link.
// Key material is derived from the current configuration, never serialized.
type warmLink struct {
	Interface string
	Owner     string
	PublicKey wgtypes.Key
	Port      int
	Result    engine.Result
	Remote    netip.Addr
	Static    bool
	LastPong  time.Time
}

type warmFile struct {
	Version int
	Config  [32]byte
	Boot    string
	NetNS   string
	Links   map[string]warmLink
}

type warmLinks struct {
	path    string
	file    warmFile // protected by links.resourceMu after startup
	adopted []warmAdoption
}

type warmAdoption struct {
	receipt warmLink
	plan    reconcile.LinkPlan
	lease   *portLease
}

func (r *Runner) prepareWarmLinks(ctx context.Context) []reconcile.LinkPlan {
	dir := r.PolicyStateDir
	if dir == "" {
		dir = "/var/lib/velvet"
	}
	data, err := json.Marshal(struct {
		UUID    uuid.UUID
		Key     wgtypes.Key
		PSK     []byte
		VFPPort int
	}{r.Desired.UUID, r.Desired.PrivateKey.PublicKey(), r.Desired.FabricPSK, r.Desired.VFPPort})
	if err != nil {
		r.warmError(err)
		return nil
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		r.warmError(err)
		return nil
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		r.warmError(err)
		return nil
	}
	r.warm = &warmLinks{path: filepath.Join(dir, r.Desired.UUID.String(), "warm-links.json"),
		file: warmFile{Version: 2, Config: sha256.Sum256(data), Boot: string(boot), NetNS: ns, Links: map[string]warmLink{}}}
	f, err := os.Open(r.warm.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		r.warmError(err)
		return nil
	}
	defer f.Close()
	data, err = io.ReadAll(io.LimitReader(f, 1<<20+1))
	var saved warmFile
	if err != nil || len(data) > 1<<20 || json.Unmarshal(data, &saved) != nil {
		r.warmError(errors.New("invalid warm Link receipt file; using ordinary recovery"))
		return nil
	}
	compatible := saved.Version == 2 && saved.Config == r.warm.file.Config
	if saved.Version == 1 {
		old, _ := json.Marshal(r.Desired)
		compatible = saved.Config == sha256.Sum256(old)
	}
	if !compatible || saved.Boot != string(boot) || saved.NetNS != ns || len(saved.Links) > maxDynamicLinks+len(r.Desired.Links) {
		return nil
	}
	var retained []reconcile.LinkPlan
	seen := map[uuid.UUID]bool{}
	for _, receipt := range saved.Links {
		plan, ok := r.warmPlan(receipt)
		if !ok || (!receipt.Static && seen[receipt.Result.RemoteUID.UUID]) {
			continue
		}
		local, _ := link.EndpointAddresses(receipt.Result.Proposal, r.Desired.UUID, receipt.Result.RemoteUID.UUID)
		if !r.Reconciler.CanAdoptLink(ctx, plan, local) {
			continue
		}
		if receipt.LastPong.IsZero() {
			if info, e := f.Stat(); e == nil {
				receipt.LastPong = info.ModTime()
			}
		}
		if receipt.LastPong.IsZero() || receipt.LastPong.After(time.Now()) {
			continue
		}
		// The kernel still owns this socket. Reserve it in our shared allocator
		// without binding, reconfiguring, or interrupting its WG session.
		lease, err := r.ports.bind(spec.PortChoice{Port: plan.ListenPort}, 0, func(port int) (int, error) { return port, nil })
		if err != nil {
			continue
		}
		if !receipt.Static {
			seen[receipt.Result.RemoteUID.UUID] = true
		}
		r.links.own(plan, lease)
		r.warm.file.Links[plan.OwnerAlias] = receipt
		r.warm.adopted = append(r.warm.adopted, warmAdoption{receipt, plan, lease})
		retained = append(retained, plan)
	}
	return retained
}

func (r *Runner) warmPlan(receipt warmLink) (reconcile.LinkPlan, bool) {
	remote := receipt.Result.RemoteUID
	if remote.UUID == uuid.Nil || remote.UUID == r.Desired.UUID || receipt.PublicKey == (wgtypes.Key{}) || receipt.PublicKey == r.Desired.PrivateKey.PublicKey() || !receipt.Remote.Is6() || !receipt.Remote.IsLinkLocalUnicast() || receipt.Remote.Zone() != "" {
		return reconcile.LinkPlan{}, false
	}
	if receipt.Port < 1 || receipt.Port > 65535 || len(receipt.Interface) > 15 {
		return reconcile.LinkPlan{}, false
	}
	if !r.Desired.LoopbackPoolV6.Contains(receipt.Result.RemoteLoopbackV6) || receipt.Result.RemoteLoopbackV6 == r.Desired.LoopbackV6 {
		return reconcile.LinkPlan{}, false
	}
	for _, item := range []struct {
		prefix, pool netip.Prefix
		bits         int
	}{{receipt.Result.Proposal.V4, r.Desired.LinkPoolV4, 30}, {receipt.Result.Proposal.V6, r.Desired.LinkPoolV6, 126}} {
		if item.prefix.IsValid() && (item.prefix.Bits() != item.bits || item.prefix != item.prefix.Masked() || !item.pool.Contains(item.prefix.Addr()) || item.prefix.Bits() < item.pool.Bits()) {
			return reconcile.LinkPlan{}, false
		}
	}
	if receipt.Static {
		for _, plan := range r.Desired.Links {
			if plan.InterfaceName == receipt.Interface && plan.OwnerAlias == receipt.Owner && plan.PeerPublicKey == receipt.PublicKey && warmPortAllowed(plan.Ports, receipt.Port) && link.MatchesOverrides(receipt.Result.Proposal, plan.LinkOverrides) {
				plan.ListenPort = receipt.Port
				return plan, true
			}
		}
		return reconcile.LinkPlan{}, false
	}
	if r.Desired.DynamicLinks == nil || r.Desired.DynamicLinks.Mode == spec.DynamicLinksOff || !warmPortAllowed(r.Desired.Ports, receipt.Port) || !strings.HasPrefix(receipt.Interface, "vdl-") {
		return reconcile.LinkPlan{}, false
	}
	plan := reconcile.BuildDynamicLink(r.Desired, nodeUID(remote))
	if !strings.HasPrefix(receipt.Owner, plan.OwnerAlias+":") {
		return reconcile.LinkPlan{}, false
	}
	generation := strings.TrimPrefix(receipt.Owner, plan.OwnerAlias+":")
	if _, err := canonicalUUID(generation, "warm Link generation"); err != nil {
		return reconcile.LinkPlan{}, false
	}
	plan.InterfaceName, plan.OwnerAlias, plan.ListenPort, plan.PeerPublicKey = receipt.Interface, receipt.Owner, receipt.Port, receipt.PublicKey
	plan.BootstrapAddress = link.DeriveLinkLocal(r.Desired.FabricPSK, r.Desired.UUID, plan.InterfaceName)
	plan.PresharedKey, _ = link.DeriveWGLinkPSK(r.Desired.FabricPSK, plan.PrivateKey.PublicKey(), receipt.PublicKey)
	return plan, true
}

func warmPortAllowed(choice spec.PortChoice, port int) bool {
	return (choice.Port == 0 || choice.Port == port) && (choice.Range.First == 0 || port >= choice.Range.First && port <= choice.Range.Last)
}

// Called before the dynamic engine starts discovery or durable restore workers.
func (r *Runner) adoptWarmLinks() error {
	if r.warm == nil {
		return nil
	}
	d := r.dynamic
	d.resourceMu.Lock()
	defer d.resourceMu.Unlock()
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, item := range r.warm.adopted {
		receipt, plan := item.receipt, item.plan
		local, _ := link.EndpointAddresses(receipt.Result.Proposal, r.Desired.UUID, receipt.Result.RemoteUID.UUID)
		if err := r.Reconciler.KeepLinkAlive(d.ctx, plan); err != nil {
			return err
		}
		peers := []netip.Addr{receipt.Result.RemoteLoopbackV6}
		if err := r.Reconciler.Materialize(d.ctx, r.Desired, plan, local, peers); err != nil {
			return err
		}
		r.mu.Lock()
		r.states[plan.InterfaceName] = materializedState{desired: plan, local: local, peers: peers, remote: receipt.Result.RemoteUID.UUID, dynamic: !receipt.Static, committed: true, lastPong: receipt.LastPong}
		r.mu.Unlock()
		if r.babel != nil {
			r.babel.SetLinkState(plan.InterfaceName, true, local)
		}
		if receipt.Static {
			continue
		}
		a := &dynamicAttempt{remote: receipt.Result.RemoteUID.UUID, plan: plan, port: item.lease, state: dynamicRecovering, localProposal: d.active()}
		d.attempts[a.remote] = a
		d.startConnectivityLocked(a)
		r.log(Event{Event: "velvet-link-adopt", Status: "adopted", Interface: plan.InterfaceName, RemoteUID: a.remote.String()})
	}
	r.warm.adopted = nil
	return nil
}

func (r *Runner) takeWarmLink(plan reconcile.LinkPlan) *warmLink {
	r.links.resourceMu.Lock()
	defer r.links.resourceMu.Unlock()
	if r.warm == nil {
		return nil
	}
	if value, ok := r.warm.file.Links[plan.OwnerAlias]; ok {
		return &value
	}
	return nil
}

func (r *Runner) rememberWarmLink(plan reconcile.LinkPlan, result engine.Result, remote netip.Addr) {
	if r.warm == nil {
		return
	}
	r.links.resourceMu.Lock()
	defer r.links.resourceMu.Unlock()
	r.mu.RLock()
	state := r.states[plan.InterfaceName]
	r.mu.RUnlock()
	if !state.active || state.desired.OwnerAlias != plan.OwnerAlias {
		return
	}
	r.warm.file.Links[plan.OwnerAlias] = warmLink{Interface: plan.InterfaceName, Owner: plan.OwnerAlias, PublicKey: plan.PeerPublicKey, Port: plan.ListenPort, Result: result, Remote: remote, Static: !state.dynamic, LastPong: state.lastPong}
	r.saveWarmLinks()
}

// Requires resourceMu, so a delayed withdrawal cannot erase a newer receipt.
func (r *Runner) forgetWarmLink(plan reconcile.LinkPlan) {
	if r.warm == nil {
		return
	}
	if _, ok := r.warm.file.Links[plan.OwnerAlias]; ok {
		delete(r.warm.file.Links, plan.OwnerAlias)
		r.saveWarmLinks()
	}
}

func (r *Runner) saveWarmLinks() {
	if err := r.warm.save(); err != nil {
		// Do not leave an older receipt eligible after a failed withdrawal write.
		if removeErr := os.Remove(r.warm.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			r.warmError(removeErr)
		}
		r.warmError(err)
	}
}

func (r *Runner) warmError(err error) {
	r.log(Event{Event: "velvet-link-adopt", Status: "receipt-unavailable", Error: err.Error()})
}

func (w *warmLinks) save() error {
	data, err := json.Marshal(w.file)
	if err != nil {
		return err
	}
	dir := filepath.Dir(w.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".warm-links-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write warm Link receipts: %w", err)
	}
	// Atomic replacement suffices: these receipts are invalid after a reboot.
	return os.Rename(f.Name(), w.path)
}
