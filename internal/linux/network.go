//go:build linux

package linux

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
)

var forwardingPaths = [...]string{
	"/proc/sys/net/ipv4/ip_forward",
	"/proc/sys/net/ipv6/conf/all/forwarding",
}

func enableForwarding() error {
	for _, path := range forwardingPaths {
		if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
			return fmt.Errorf("enable forwarding through %s: %w", path, err)
		}
	}
	return nil
}

func verifyForwarding() error {
	for _, path := range forwardingPaths {
		value, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read forwarding state %s: %w", path, err)
		}
		if strings.TrimSpace(string(value)) != "1" {
			return fmt.Errorf("forwarding state %s is not enabled", path)
		}
	}
	return nil
}

func reconcileLoopbackAddresses(device netlink.Link, wanted netip.Prefix) error {
	addresses, err := netlink.AddrList(device, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("list node loopback addresses: %w", err)
	}
	for i := range addresses {
		prefix, ok := prefixFromAddressIPNet(addresses[i].IPNet)
		if !ok || prefix == wanted || prefix.Addr().IsLinkLocalUnicast() {
			continue
		}
		if err := netlink.AddrDel(device, &addresses[i]); err != nil {
			return fmt.Errorf("delete stale node loopback address %s: %w", prefix, err)
		}
	}
	if err := netlink.AddrReplace(device, &netlink.Addr{IPNet: prefixIPNet(wanted)}); err != nil {
		return fmt.Errorf("assign node loopback %s: %w", wanted, err)
	}
	return nil
}

func reconcileBootstrapAddress(device netlink.Link, wanted netip.Prefix) error {
	addresses, err := netlink.AddrList(device, netlink.FAMILY_V6)
	if err != nil {
		return err
	}
	for i := range addresses {
		prefix, ok := prefixFromAddressIPNet(addresses[i].IPNet)
		if !ok || prefix == wanted || !prefix.Addr().IsLinkLocalUnicast() {
			continue
		}
		if err := netlink.AddrDel(device, &addresses[i]); err != nil {
			return err
		}
	}
	return netlink.AddrReplace(device, &netlink.Addr{IPNet: prefixIPNet(wanted)})
}

func reconcileMaterializedAddresses(device netlink.Link, bootstrap netip.Prefix, wanted []netip.Prefix) error {
	wantedSet := make(map[netip.Prefix]struct{}, len(wanted)+1)
	wantedSet[bootstrap] = struct{}{}
	for _, prefix := range wanted {
		wantedSet[prefix] = struct{}{}
		if err := netlink.AddrReplace(device, &netlink.Addr{IPNet: prefixIPNet(prefix)}); err != nil {
			return fmt.Errorf("assign negotiated address %s: %w", prefix, err)
		}
	}
	addresses, err := netlink.AddrList(device, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for i := range addresses {
		prefix, ok := prefixFromAddressIPNet(addresses[i].IPNet)
		if !ok || prefix.Addr().IsLinkLocalUnicast() {
			continue
		}
		if _, keep := wantedSet[prefix]; keep {
			continue
		}
		if err := netlink.AddrDel(device, &addresses[i]); err != nil {
			return fmt.Errorf("delete stale negotiated address %s: %w", prefix, err)
		}
	}
	return nil
}

func ensureOwnedWireGuardInterface(name, owner string) (netlink.Link, error) {
	return ensureOwnedLink(name, owner, "wireguard", "an owned WireGuard interface", func() error { return addWireGuard(name) })
}

func ensureOwnedDummy(name, owner string) (netlink.Link, error) {
	return ensureOwnedLink(name, owner, "dummy", "the owned node loopback", func() error {
		return netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}})
	})
}

func addWireGuard(name string) error {
	return netlink.LinkAdd(&netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name}, LinkType: "wireguard"})
}

func ensureOwnedLink(name, owner, linkType, description string, create func() error) (netlink.Link, error) {
	device, created, err := ensureLink(name, linkType, create)
	if err != nil {
		return nil, err
	}
	if !created && !strings.HasPrefix(device.Attrs().Alias, ownerPrefix) {
		return nil, fmt.Errorf("interface %q exists but is not %s", name, description)
	}
	return setLinkAlias(device, owner)
}

func setLinkAlias(device netlink.Link, owner string) (netlink.Link, error) {
	if device.Attrs().Alias == owner {
		return device, nil
	}
	if err := netlink.LinkSetAlias(device, owner); err != nil {
		return nil, err
	}
	return netlink.LinkByName(device.Attrs().Name)
}

func ensureLink(name, linkType string, create func() error) (netlink.Link, bool, error) {
	device, err := netlink.LinkByName(name)
	if err == nil {
		if device.Type() != linkType {
			return nil, false, fmt.Errorf("interface %q has type %q, want %q", name, device.Type(), linkType)
		}
		return device, false, nil
	}
	if !isLinkNotFound(err) {
		return nil, false, fmt.Errorf("look up interface %q: %w", name, err)
	}
	if err := create(); err != nil {
		return nil, false, fmt.Errorf("create interface %q: %w", name, err)
	}
	device, err = netlink.LinkByName(name)
	return device, true, err
}

func addressPresent(addresses []netlink.Addr, wanted netip.Prefix) bool {
	for _, current := range addresses {
		if prefix, ok := prefixFromAddressIPNet(current.IPNet); ok && prefix == wanted {
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

func netipAddr(ip net.IP) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if ok {
		addr = addr.Unmap()
	}
	return addr, ok
}

func prefixFromIPNet(value *net.IPNet) (netip.Prefix, bool) {
	if value == nil {
		return netip.Prefix{}, false
	}
	addr, ok := netipAddr(value.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := value.Mask.Size()
	return netip.PrefixFrom(addr, ones).Masked(), true
}

func prefixFromAddressIPNet(value *net.IPNet) (netip.Prefix, bool) {
	if value == nil {
		return netip.Prefix{}, false
	}
	addr, ok := netipAddr(value.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := value.Mask.Size()
	return netip.PrefixFrom(addr, ones), true
}

func prefixesOverlap(a, b netip.Prefix) bool {
	return a.Addr().BitLen() == b.Addr().BitLen() && (a.Contains(b.Addr()) || b.Contains(a.Addr()))
}

func family(addr netip.Addr) int {
	if addr.Is4() {
		return netlink.FAMILY_V4
	}
	return netlink.FAMILY_V6
}

func isLinkNotFound(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "not found")
}
