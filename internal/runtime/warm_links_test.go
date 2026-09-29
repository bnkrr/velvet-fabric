package runtime

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/link"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type warmBackend struct {
	runtimeBackend
	accepted reconcile.LinkPlan
	valid    bool
}

func (b *warmBackend) CanAdoptLink(_ context.Context, plan reconcile.LinkPlan, _ []netip.Prefix) bool {
	return b.valid && reflect.DeepEqual(plan, b.accepted)
}

func warmFixture(t *testing.T) (*Runner, warmLink, *warmBackend) {
	t.Helper()
	private, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	r := &Runner{PolicyStateDir: t.TempDir(), Desired: &reconcile.DesiredState{
		UUID: uuid.New(), PrivateKey: private, FabricPSK: make([]byte, 32),
		LoopbackPoolV6: netip.MustParsePrefix("fd00::/64"), LoopbackV6: netip.MustParseAddr("fd00::1"),
		DynamicLinks: &reconcile.DynamicLinksPlan{Mode: spec.DynamicLinksActive},
	}}
	result := engine.Result{RemoteUID: message.UID{UUID: uuid.New(), Name: "peer"}, RemoteLoopbackV6: netip.MustParseAddr("fd00::2")}
	plan := reconcile.BuildDynamicLink(r.Desired, nodeUID(result.RemoteUID))
	w := warmLink{Interface: plan.InterfaceName, Owner: plan.OwnerAlias + ":" + uuid.NewString(), PublicKey: peer.PublicKey(), Port: 53000, Result: result, Remote: netip.MustParseAddr("fe80::2")}
	accepted, ok := r.warmPlan(w)
	if !ok {
		t.Fatal("fixture rejected")
	}
	b := &warmBackend{accepted: accepted, valid: true}
	r.Reconciler = reconcile.New(b)
	r.prepareWarmLinks(context.Background())
	r.warm.file.Links[w.Owner] = w
	if err := r.warm.save(); err != nil {
		t.Fatal(err)
	}
	return r, w, b
}

func TestWarmLinkRecoveryKeepsGenerationAndReservesPort(t *testing.T) {
	r, w, b := warmFixture(t)
	restarted := &Runner{Desired: r.Desired, PolicyStateDir: r.PolicyStateDir, Reconciler: r.Reconciler}
	plans := restarted.prepareWarmLinks(context.Background())
	if len(plans) != 1 || plans[0].OwnerAlias != w.Owner || plans[0].ListenPort != w.Port {
		t.Fatalf("retained = %#v", plans)
	}
	if b.prepared != 0 || b.configured != 0 || len(b.removed) != 0 {
		t.Fatal("adoption rewrote the kernel")
	}
	if _, err := restarted.ports.bind(spec.PortChoice{Port: w.Port}, 0, func(p int) (int, error) { return p, nil }); err == nil {
		t.Fatal("adopted port was reused")
	}
	if restarted.Status().DynamicLinks != 0 {
		t.Fatal("unvalidated receipt counted as healthy")
	}
	restarted.forgetWarmLink(plans[0])
	again := &Runner{Desired: r.Desired, PolicyStateDir: r.PolicyStateDir, Reconciler: r.Reconciler}
	if plans := again.prepareWarmLinks(context.Background()); len(plans) != 0 {
		t.Fatal("withdrawn receipt survived")
	}
}

func TestWarmLinkRecoveryRejectsStaleState(t *testing.T) {
	for _, kind := range []string{"config", "boot", "namespace", "version", "kernel", "generation", "foreign-owner", "port", "remote", "proposal", "corrupt"} {
		t.Run(kind, func(t *testing.T) {
			r, w, b := warmFixture(t)
			switch kind {
			case "config":
				r.Desired.VFPPort++
			case "boot":
				r.warm.file.Boot = "previous boot"
			case "namespace":
				r.warm.file.NetNS = "other namespace"
			case "version":
				r.warm.file.Version++
			case "kernel":
				b.valid = false
			case "generation":
				w.Owner += ":replaced"
			case "foreign-owner":
				w.Owner = uuid.NewString()
			case "port":
				w.Port = 0
			case "remote":
				w.Remote = netip.MustParseAddr("2001:db8::1")
			case "proposal":
				w.Result.Proposal = link.Proposal{V4: netip.MustParsePrefix("192.0.2.0/30")}
			}
			r.warm.file.Links = map[string]warmLink{w.Owner: w}
			if err := r.warm.save(); err != nil {
				t.Fatal(err)
			}
			if kind == "corrupt" {
				if err := os.WriteFile(r.warm.path, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			restarted := &Runner{Desired: r.Desired, PolicyStateDir: r.PolicyStateDir, Reconciler: r.Reconciler}
			if plans := restarted.prepareWarmLinks(context.Background()); len(plans) != 0 {
				t.Fatalf("adopted %s", kind)
			}
		})
	}
}

func TestWarmReceiptHasNoSecretKeys(t *testing.T) {
	r, _, _ := warmFixture(t)
	data, err := os.ReadFile(r.warm.path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	for _, raw := range value["Links"].(map[string]any) {
		v := raw.(map[string]any)
		if v["PrivateKey"] != nil || v["PresharedKey"] != nil || v["FabricPSK"] != nil {
			t.Fatalf("unexpected receipt fields: %v", v)
		}
	}
	info, err := os.Stat(r.warm.path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("receipt must be private")
	}
}

func TestWarmAdjacencyWithdrawalBeforeConfirmation(t *testing.T) {
	r, w, b := warmFixture(t)
	plan, _ := r.warmPlan(w)
	r.dynamic = newDynamicLinkEngine(r)
	r.states = map[string]materializedState{plan.InterfaceName: {desired: plan, dynamic: true, remote: w.Result.RemoteUID.UUID, peers: []netip.Addr{w.Result.RemoteLoopbackV6}}}
	if got := r.takeWarmLink(plan); got == nil || r.takeWarmLink(plan) == nil {
		t.Fatal("receipt must survive control-session retries")
	}
	if err := r.withdrawLinkAdjacency(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if b.materialized != 1 || len(b.peers) != 0 || len(r.states[plan.InterfaceName].peers) != 0 || len(r.warm.file.Links) != 0 {
		t.Fatal("unconfirmed warm adjacency was not withdrawn")
	}
}

func TestWarmReceiptRequiresCommittedGeneration(t *testing.T) {
	r, w, _ := warmFixture(t)
	plan, _ := r.warmPlan(w)
	r.warm.file.Links = map[string]warmLink{}
	r.states = map[string]materializedState{plan.InterfaceName: {desired: plan, dynamic: true}}
	r.rememberWarmLink(plan, w.Result, w.Remote)
	if len(r.warm.file.Links) != 0 {
		t.Fatal("saved a tentative Link")
	}
	state := r.states[plan.InterfaceName]
	state.active = true
	r.states[plan.InterfaceName] = state
	r.rememberWarmLink(plan, w.Result, w.Remote)
	stale := plan
	stale.OwnerAlias += ":old"
	r.forgetWarmLink(stale)
	r.rememberWarmLink(stale, w.Result, w.Remote)
	if len(r.warm.file.Links) != 1 || r.warm.file.Links[plan.OwnerAlias].Owner != plan.OwnerAlias {
		t.Fatal("stale generation changed the committed receipt")
	}
}

func TestControlLossAndShutdownRetainCommittedLink(t *testing.T) {
	r, w, b := warmFixture(t)
	plan, _ := r.warmPlan(w)
	r.states = map[string]materializedState{plan.InterfaceName: {desired: plan, active: true, committed: true, dynamic: true, peers: []netip.Addr{w.Result.RemoteLoopbackV6}}}
	d := newDynamicLinkEngine(r)
	r.dynamic = d
	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.attempts[w.Result.RemoteUID.UUID] = &dynamicAttempt{remote: w.Result.RemoteUID.UUID, plan: plan, state: dynamicUp}
	r.markLinkLost(plan)
	state, exists := r.committedLink(plan)
	if !exists || state.active || len(state.peers) != 1 || b.materialized != 0 || len(r.warm.file.Links) != 1 {
		t.Fatal("control loss changed committed data plane")
	}
	d.stop()
	if len(b.removed) != 0 || len(r.warm.file.Links) != 1 {
		t.Fatal("normal shutdown removed committed Link")
	}
}

func TestWarmLinkAllowsUnrelatedConfigChange(t *testing.T) {
	r, _, _ := warmFixture(t)
	r.Desired.Forwarding = !r.Desired.Forwarding
	restarted := &Runner{Desired: r.Desired, PolicyStateDir: r.PolicyStateDir, Reconciler: r.Reconciler}
	if len(restarted.prepareWarmLinks(context.Background())) != 1 {
		t.Fatal("unrelated config change discarded warm Link")
	}
}

func TestWarmStaticAdoptionAndPort(t *testing.T) {
	r, w, b := warmFixture(t)
	plan, _ := r.warmPlan(w)
	w.Static = true
	r.Desired.Links = []reconcile.LinkPlan{plan}
	r.warm.file.Links = map[string]warmLink{w.Owner: w}
	if err := r.warm.save(); err != nil {
		t.Fatal(err)
	}
	restarted := &Runner{Desired: r.Desired, PolicyStateDir: r.PolicyStateDir, Reconciler: r.Reconciler}
	if len(restarted.prepareWarmLinks(context.Background())) != 1 {
		t.Fatal("static receipt rejected")
	}
	restarted.dynamic = newDynamicLinkEngine(restarted)
	restarted.dynamic.ctx = context.Background()
	restarted.states = make(map[string]materializedState)
	if err := restarted.adoptWarmLinks(); err != nil {
		t.Fatal(err)
	}
	state, ok := restarted.committedLink(plan)
	if !ok || state.active || len(state.peers) != 1 || b.materialized != 1 {
		t.Fatal("static adoption waited for remote control")
	}
	if len(restarted.dynamic.attempts) != 0 {
		t.Fatal("static adoption started dynamic discovery")
	}
}
