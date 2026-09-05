//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
)

const (
	StaticProtocol netlink.RouteProtocol = 201
	LinkProtocol   netlink.RouteProtocol = 202
	ownerPrefix                          = "velvet:"
)

type Backend struct {
	mu       sync.Mutex
	attempts map[string]endpointAttempt
	kernelMu sync.Mutex
}

func New() *Backend { return &Backend{attempts: make(map[string]endpointAttempt)} }

func (b *Backend) Reconcile(ctx context.Context, desired *reconcile.DesiredState, preserveRuntimeLinks bool) error {
	b.kernelMu.Lock()
	defer b.kernelMu.Unlock()

	if os.Geteuid() != 0 {
		return errors.New("velvetd must run as root or with equivalent network capabilities")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if desired.Babel == nil {
		if err := cleanupDisabledBabelState(); err != nil {
			return err
		}
	}
	if err := rejectForeignTableState(desired); err != nil {
		return err
	}
	if err := reconcileNodeLoopback(desired); err != nil {
		return err
	}

	desiredLinks := desiredLinkNames(desired)
	if preserveRuntimeLinks {
		if err := retainOwnedLinkNames(desiredLinks); err != nil {
			return err
		}
	}
	// A renamed WireGuard interface may retain the same listen port. Remove it
	// before creating its replacement so the port can be rebound.
	if err := cleanupStaleLinks(desiredLinks); err != nil {
		return err
	}

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open WireGuard control client: %w", err)
	}
	defer client.Close()
	for _, plan := range desired.Links {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := b.applyBootstrapLink(client, plan); err != nil {
			return fmt.Errorf("peer %q: %w", plan.PeerName, err)
		}
	}
	if desired.Forwarding {
		if err := enableForwarding(); err != nil {
			return err
		}
	}
	if err := reconcileRoutesAndRules(desired); err != nil {
		return err
	}
	return cleanupLinkRoutes(desired, desiredLinks)
}

func (b *Backend) Verify(ctx context.Context, desired *reconcile.DesiredState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open WireGuard control client: %w", err)
	}
	defer client.Close()
	if err := verifyNodeLoopback(desired); err != nil {
		return err
	}
	for _, plan := range desired.Links {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := verifyBootstrapLink(client, plan); err != nil {
			return fmt.Errorf("peer %q: %w", plan.PeerName, err)
		}
	}
	if err := verifyStaticRoutes(desired); err != nil {
		return err
	}
	if err := verifyPolicyRules(desired); err != nil {
		return err
	}
	if desired.Forwarding {
		return verifyForwarding()
	}
	return nil
}

func desiredLinkNames(desired *reconcile.DesiredState) map[string]struct{} {
	names := make(map[string]struct{}, len(desired.Links)+1)
	names[reconcile.LoopbackInterface] = struct{}{}
	for _, plan := range desired.Links {
		names[plan.InterfaceName] = struct{}{}
	}
	return names
}

func reconcileNodeLoopback(desired *reconcile.DesiredState) error {
	device, err := ensureOwnedDummy(reconcile.LoopbackInterface, desired.LoopbackOwnerAlias)
	if err != nil {
		return err
	}
	if err := reconcileLoopbackAddresses(device, netip.PrefixFrom(desired.LoopbackV6, 128)); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(device); err != nil {
		return fmt.Errorf("set loopback interface up: %w", err)
	}
	return nil
}

func verifyNodeLoopback(desired *reconcile.DesiredState) error {
	device, err := netlink.LinkByName(reconcile.LoopbackInterface)
	if err != nil || device.Type() != "dummy" || device.Attrs().Alias != desired.LoopbackOwnerAlias {
		return errors.New("node loopback interface is missing or not owned by this node")
	}
	if device.Attrs().Flags&net.FlagUp == 0 {
		return errors.New("node loopback interface is down")
	}
	addresses, err := netlink.AddrList(device, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	loopback := netip.PrefixFrom(desired.LoopbackV6, 128)
	if !addressPresent(addresses, loopback) {
		return fmt.Errorf("node loopback %s is missing", loopback)
	}
	return nil
}
