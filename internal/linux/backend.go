//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/velvet-fabric/velvet-fabric/internal/link"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Backend struct{}

func New() *Backend { return &Backend{} }

func (b *Backend) ApplyBootstrap(ctx context.Context, plan *reconcile.Plan) error {
	if os.Geteuid() != 0 {
		return errors.New("velvetd must run as root or with equivalent network capabilities")
	}
	loop, err := ensureOwnedDummy(reconcile.LoopbackInterface, plan.LoopbackOwnerAlias)
	if err != nil {
		return err
	}
	loopback := netip.PrefixFrom(plan.LoopbackV6, 128)
	if err := netlink.AddrReplace(loop, &netlink.Addr{IPNet: prefixIPNet(loopback)}); err != nil {
		return fmt.Errorf("assign node loopback %s: %w", loopback, err)
	}
	if err := netlink.LinkSetUp(loop); err != nil {
		return fmt.Errorf("set loopback interface up: %w", err)
	}
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open WireGuard control client: %w", err)
	}
	defer client.Close()
	for _, desired := range plan.Links {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := applyBootstrapLink(client, desired); err != nil {
			return fmt.Errorf("peer %q: %w", desired.PeerName, err)
		}
	}
	return nil
}

func (b *Backend) VerifyBootstrap(ctx context.Context, plan *reconcile.Plan) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open WireGuard control client: %w", err)
	}
	defer client.Close()
	loop, err := netlink.LinkByName(reconcile.LoopbackInterface)
	if err != nil || loop.Type() != "dummy" || loop.Attrs().Alias != plan.LoopbackOwnerAlias {
		return errors.New("node loopback interface is missing or not owned by this node")
	}
	loopAddrs, err := netlink.AddrList(loop, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	loopback := netip.PrefixFrom(plan.LoopbackV6, 128)
	if !addressPresent(loopAddrs, loopback) {
		return fmt.Errorf("node loopback %s is missing", loopback)
	}
	for _, desired := range plan.Links {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := verifyBootstrapLink(client, desired); err != nil {
			return fmt.Errorf("peer %q: %w", desired.PeerName, err)
		}
	}
	return nil
}

func (b *Backend) ProposalAvailable(ctx context.Context, desired reconcile.LinkPlan, proposal link.Proposal, local []netip.Prefix) bool {
	if ctx.Err() != nil {
		return false
	}
	device, err := netlink.LinkByName(desired.InterfaceName)
	if err != nil {
		return false
	}
	links, err := netlink.LinkList()
	if err != nil {
		return false
	}
	for _, candidate := range []netip.Prefix{proposal.V4, proposal.V6} {
		if !candidate.IsValid() {
			continue
		}
		for _, item := range links {
			addresses, err := netlink.AddrList(item, family(candidate.Addr()))
			if err != nil {
				return false
			}
			for _, address := range addresses {
				addr, ok := netipAddr(address.IP)
				if !ok || !candidate.Contains(addr) {
					continue
				}
				if item.Attrs().Index == device.Attrs().Index && prefixAddressPresent(local, addr) {
					continue
				}
				return false
			}
		}
		routes, err := netlink.RouteList(nil, family(candidate.Addr()))
		if err != nil {
			return false
		}
		for _, route := range routes {
			if route.Dst == nil {
				continue
			}
			routePrefix, ok := prefixFromIPNet(route.Dst)
			if !ok || !prefixesOverlap(candidate, routePrefix) {
				continue
			}
			if route.LinkIndex == device.Attrs().Index && routePrefix == candidate {
				continue
			}
			return false
		}
	}
	return true
}

func (b *Backend) Materialize(ctx context.Context, desired reconcile.LinkPlan, local []netip.Prefix, peerLoopbacks []netip.Addr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	device, err := netlink.LinkByName(desired.InterfaceName)
	if err != nil {
		return fmt.Errorf("look up interface: %w", err)
	}
	for _, prefix := range local {
		if err := netlink.AddrReplace(device, &netlink.Addr{IPNet: prefixIPNet(prefix)}); err != nil {
			return fmt.Errorf("assign negotiated address %s: %w", prefix, err)
		}
	}
	for _, address := range peerLoopbacks {
		if !address.IsValid() {
			continue
		}
		bits := 128
		if address.Is4() {
			bits = 32
		}
		dst := prefixIPNet(netip.PrefixFrom(address, bits))
		if err := netlink.RouteReplace(&netlink.Route{LinkIndex: device.Attrs().Index, Dst: dst, Scope: netlink.SCOPE_LINK}); err != nil {
			return fmt.Errorf("install peer loopback route %s: %w", address, err)
		}
	}
	return nil
}

func applyBootstrapLink(client *wgctrl.Client, desired reconcile.LinkPlan) error {
	device, err := ensureOwnedWireGuardInterface(desired.InterfaceName, desired.OwnerAlias)
	if err != nil {
		return err
	}
	if err := netlink.AddrReplace(device, &netlink.Addr{IPNet: prefixIPNet(desired.BootstrapAddress)}); err != nil {
		return fmt.Errorf("assign bootstrap address: %w", err)
	}
	if err := netlink.LinkSetUp(device); err != nil {
		return fmt.Errorf("set interface up: %w", err)
	}
	endpoint, err := net.ResolveUDPAddr("udp", desired.Endpoints[0])
	if err != nil {
		return fmt.Errorf("resolve endpoint %q: %w", desired.Endpoints[0], err)
	}
	peer := wgtypes.PeerConfig{PublicKey: desired.PeerPublicKey, PresharedKey: &desired.PresharedKey, Endpoint: endpoint, ReplaceAllowedIPs: true, AllowedIPs: defaultAllowedIPs()}
	if desired.Keepalive > 0 {
		keepalive := desired.Keepalive
		peer.PersistentKeepaliveInterval = &keepalive
	}
	privateKey, listenPort := desired.PrivateKey, desired.ListenPort
	if err := client.ConfigureDevice(desired.InterfaceName, wgtypes.Config{PrivateKey: &privateKey, ListenPort: &listenPort, ReplacePeers: true, Peers: []wgtypes.PeerConfig{peer}}); err != nil {
		return fmt.Errorf("configure WireGuard device: %w", err)
	}
	return nil
}

func verifyBootstrapLink(client *wgctrl.Client, desired reconcile.LinkPlan) error {
	device, err := netlink.LinkByName(desired.InterfaceName)
	if err != nil {
		return fmt.Errorf("look up interface: %w", err)
	}
	if device.Type() != "wireguard" || device.Attrs().Alias != desired.OwnerAlias {
		return errors.New("interface type or ownership does not match")
	}
	if device.Attrs().Flags&net.FlagUp == 0 {
		return errors.New("interface is down")
	}
	addresses, err := netlink.AddrList(device, netlink.FAMILY_V6)
	if err != nil || !addressPresent(addresses, desired.BootstrapAddress) {
		return errors.New("bootstrap address is missing")
	}
	wgDevice, err := client.Device(desired.InterfaceName)
	if err != nil {
		return fmt.Errorf("read WireGuard device: %w", err)
	}
	if wgDevice.PublicKey != desired.PrivateKey.PublicKey() || wgDevice.ListenPort != desired.ListenPort {
		return errors.New("WireGuard local configuration does not match")
	}
	if len(wgDevice.Peers) != 1 || wgDevice.Peers[0].PublicKey != desired.PeerPublicKey || wgDevice.Peers[0].PresharedKey != desired.PresharedKey {
		return errors.New("WireGuard peer key material does not match")
	}
	return nil
}

func ensureOwnedWireGuardInterface(name, owner string) (netlink.Link, error) {
	device, err := netlink.LinkByName(name)
	if err != nil {
		if !isLinkNotFound(err) {
			return nil, fmt.Errorf("look up interface %q: %w", name, err)
		}
		candidate := &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name}, LinkType: "wireguard"}
		if err := netlink.LinkAdd(candidate); err != nil {
			return nil, fmt.Errorf("create WireGuard interface %q: %w", name, err)
		}
		device, err = netlink.LinkByName(name)
		if err != nil {
			return nil, err
		}
	} else if device.Type() != "wireguard" || device.Attrs().Alias != owner {
		return nil, fmt.Errorf("interface %q exists but is not an owned WireGuard interface", name)
	}
	if device.Attrs().Alias == "" {
		if err := netlink.LinkSetAlias(device, owner); err != nil {
			return nil, err
		}
	}
	return device, nil
}

func ensureOwnedDummy(name, owner string) (netlink.Link, error) {
	device, err := netlink.LinkByName(name)
	if err != nil {
		if !isLinkNotFound(err) {
			return nil, err
		}
		if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
			return nil, fmt.Errorf("create loopback interface: %w", err)
		}
		device, err = netlink.LinkByName(name)
		if err != nil {
			return nil, err
		}
	} else if device.Type() != "dummy" || device.Attrs().Alias != owner {
		return nil, fmt.Errorf("interface %q exists but is not the owned node loopback", name)
	}
	if device.Attrs().Alias == "" {
		if err := netlink.LinkSetAlias(device, owner); err != nil {
			return nil, err
		}
	}
	return device, nil
}

func addressPresent(addresses []netlink.Addr, wanted netip.Prefix) bool {
	for _, current := range addresses {
		if current.IPNet != nil && prefixMatchesIPNet(wanted, current.IPNet) {
			return true
		}
	}
	return false
}
func prefixAddressPresent(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Addr() == address {
			return true
		}
	}
	return false
}
func prefixIPNet(prefix netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: net.IP(prefix.Addr().AsSlice()), Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())}
}
func prefixMatchesIPNet(prefix netip.Prefix, network *net.IPNet) bool {
	ones, bits := network.Mask.Size()
	return ones == prefix.Bits() && bits == prefix.Addr().BitLen() && network.IP.Equal(net.IP(prefix.Addr().AsSlice()))
}
func netipAddr(ip net.IP) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if ok {
		addr = addr.Unmap()
	}
	return addr, ok
}
func prefixFromIPNet(value *net.IPNet) (netip.Prefix, bool) {
	addr, ok := netipAddr(value.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := value.Mask.Size()
	return netip.PrefixFrom(addr, ones).Masked(), true
}
func prefixesOverlap(a, b netip.Prefix) bool { return a.Contains(b.Addr()) || b.Contains(a.Addr()) }
func family(addr netip.Addr) int {
	if addr.Is4() {
		return netlink.FAMILY_V4
	}
	return netlink.FAMILY_V6
}
func defaultAllowedIPs() []net.IPNet {
	_, v4, _ := net.ParseCIDR("0.0.0.0/0")
	_, v6, _ := net.ParseCIDR("::/0")
	return []net.IPNet{*v4, *v6}
}
func isLinkNotFound(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}
