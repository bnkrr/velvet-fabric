//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"

	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (b *Backend) PrepareDynamic(ctx context.Context, desired reconcile.LinkPlan) (_ reconcile.LinkPlan, retErr error) {
	b.kernelMu.Lock()
	defer b.kernelMu.Unlock()
	if err := ctx.Err(); err != nil {
		return reconcile.LinkPlan{}, err
	}
	device, err := ensureExactlyOwnedWireGuardInterface(desired.InterfaceName, desired.OwnerAlias)
	if err != nil {
		return reconcile.LinkPlan{}, err
	}
	// Preparation is transactional. A failed reservation is unusable and must
	// not survive as an owned interface that maintenance would preserve.
	defer func() {
		if retErr == nil {
			return
		}
		if err := b.deleteDynamicInterface(desired); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("roll back dynamic interface %q: %w", desired.InterfaceName, err))
		}
	}()
	if err := reconcileBootstrapAddress(device, desired.BootstrapAddress); err != nil {
		return reconcile.LinkPlan{}, fmt.Errorf("assign dynamic bootstrap address: %w", err)
	}
	if err := netlink.LinkSetUp(device); err != nil {
		return reconcile.LinkPlan{}, fmt.Errorf("set dynamic interface up: %w", err)
	}
	client, err := wgctrl.New()
	if err != nil {
		return reconcile.LinkPlan{}, fmt.Errorf("open WireGuard control client: %w", err)
	}
	defer client.Close()
	listenPort := 0
	privateKey := desired.PrivateKey
	if err := client.ConfigureDevice(desired.InterfaceName, wgtypes.Config{
		PrivateKey: &privateKey, ListenPort: &listenPort, ReplacePeers: true,
	}); err != nil {
		return reconcile.LinkPlan{}, fmt.Errorf("reserve dynamic WireGuard endpoint: %w", err)
	}
	configured, err := client.Device(desired.InterfaceName)
	if err != nil {
		return reconcile.LinkPlan{}, fmt.Errorf("read dynamic WireGuard endpoint: %w", err)
	}
	if configured.ListenPort < 1 || configured.ListenPort > 65535 {
		return reconcile.LinkPlan{}, errors.New("kernel did not allocate a dynamic WireGuard listen port")
	}
	desired.ListenPort = configured.ListenPort
	return desired, nil
}

func (b *Backend) ConfigureDynamic(ctx context.Context, desired reconcile.LinkPlan) error {
	b.kernelMu.Lock()
	defer b.kernelMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := requireExactlyOwnedWireGuardInterface(desired.InterfaceName, desired.OwnerAlias); err != nil {
		return err
	}
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open WireGuard control client: %w", err)
	}
	defer client.Close()
	return b.applyBootstrapLink(client, desired)
}

func (b *Backend) RemoveDynamic(ctx context.Context, desired reconcile.LinkPlan) error {
	b.kernelMu.Lock()
	defer b.kernelMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return b.deleteDynamicInterface(desired)
}

// deleteDynamicInterface runs with kernelMu held and never deletes an
// interface unless its complete owner alias still matches the Link plan.
func (b *Backend) deleteDynamicInterface(desired reconcile.LinkPlan) error {
	device, err := requireExactlyOwnedWireGuardInterface(desired.InterfaceName, desired.OwnerAlias)
	if isLinkNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("look up dynamic interface %q: %w", desired.InterfaceName, err)
	}
	if err := netlink.LinkDel(device); err != nil {
		return fmt.Errorf("delete dynamic interface %q: %w", desired.InterfaceName, err)
	}
	b.mu.Lock()
	delete(b.attempts, desired.InterfaceName)
	b.mu.Unlock()
	return nil
}

func ensureExactlyOwnedWireGuardInterface(name, owner string) (netlink.Link, error) {
	device, created, err := ensureLink(name, "wireguard", func() error { return addWireGuard(name) })
	if err != nil {
		return nil, err
	}
	if !created && device.Attrs().Alias != owner {
		return nil, fmt.Errorf("interface %q is not owned by dynamic Link %q", name, owner)
	}
	if created {
		createdDevice := device
		device, err = setLinkAlias(device, owner)
		if err != nil {
			_ = netlink.LinkDel(createdDevice)
			return nil, err
		}
	}
	return device, err
}

func requireExactlyOwnedWireGuardInterface(name, owner string) (netlink.Link, error) {
	device, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	if !isExactlyOwnedWireGuardInterface(device, owner) {
		return nil, fmt.Errorf("interface %q is not owned by dynamic Link %q", name, owner)
	}
	return device, nil
}

func isExactlyOwnedWireGuardInterface(device netlink.Link, owner string) bool {
	return device != nil && device.Type() == "wireguard" && device.Attrs().Alias == owner
}
