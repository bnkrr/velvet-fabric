//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/velvet-fabric/velvet-fabric/internal/link"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
)

func (b *Backend) ProposalAvailable(ctx context.Context, desired reconcile.LinkPlan, proposal link.Proposal, local []netip.Prefix) bool {
	b.kernelMu.Lock()
	defer b.kernelMu.Unlock()
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

func (b *Backend) Materialize(ctx context.Context, state *reconcile.DesiredState, desired reconcile.LinkPlan, local []netip.Prefix, peerLoopbacks []netip.Addr) error {
	b.kernelMu.Lock()
	defer b.kernelMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	device, err := netlink.LinkByName(desired.InterfaceName)
	if err != nil {
		return fmt.Errorf("look up interface: %w", err)
	}
	if !isExactlyOwnedWireGuardInterface(device, desired.OwnerAlias) {
		return fmt.Errorf("interface %q is not owned by Link %q", desired.InterfaceName, desired.OwnerAlias)
	}
	if err := reconcileMaterializedAddresses(device, desired.BootstrapAddress, local); err != nil {
		return err
	}
	wanted := materializedLinkRoutes(state, device.Attrs().Index, local, peerLoopbacks)
	for i := range wanted {
		if err := netlink.RouteReplace(&wanted[i]); err != nil {
			return fmt.Errorf("install Link route %s: %w", routeDestination(wanted[i]), err)
		}
	}
	current, err := routesByProtocol(LinkProtocol)
	if err != nil {
		return err
	}
	for i := range current {
		if current[i].LinkIndex == device.Attrs().Index && !anyRouteMatches(current[i], wanted) {
			if err := netlink.RouteDel(&current[i]); err != nil {
				return fmt.Errorf("delete stale adjacent route: %w", err)
			}
		}
	}
	if err := deleteLegacyMainPeerRoutes(device.Attrs().Index, state.LoopbackPoolV6, wanted); err != nil {
		return err
	}
	// Address materialization can invalidate device routes already attached to
	// this interface. Reassert the complete static desired state before commit.
	wantedStatic, err := desiredNetlinkRoutes(state)
	if err != nil {
		return err
	}
	if err := replaceStaticRoutes(wantedStatic); err != nil {
		return err
	}
	return reconcilePolicyRules(state)
}

func materializedLinkRoutes(state *reconcile.DesiredState, linkIndex int, local []netip.Prefix, peerLoopbacks []netip.Addr) []netlink.Route {
	result := make([]netlink.Route, 0, len(local)+len(peerLoopbacks))
	for _, prefix := range local {
		if !prefix.IsValid() {
			continue
		}
		result = append(result, netlink.Route{
			LinkIndex: linkIndex, Dst: prefixIPNet(prefix.Masked()), Scope: netlink.SCOPE_LINK,
			Protocol: LinkProtocol, Table: state.FabricTableID, Type: unix.RTN_UNICAST,
		})
	}
	for _, address := range peerLoopbacks {
		if !address.IsValid() {
			continue
		}
		bits := 128
		if address.Is4() {
			bits = 32
		}
		result = append(result, netlink.Route{
			LinkIndex: linkIndex, Dst: prefixIPNet(netip.PrefixFrom(address, bits)), Src: net.IP(state.LoopbackV6.AsSlice()),
			Scope: netlink.SCOPE_LINK, Protocol: LinkProtocol, Table: state.FabricTableID, Type: unix.RTN_UNICAST,
		})
	}
	return result
}

func (b *Backend) ObservedEndpoint(ctx context.Context, interfaceName string) (netip.AddrPort, bool, error) {
	if err := ctx.Err(); err != nil {
		return netip.AddrPort{}, false, err
	}
	client, err := wgctrl.New()
	if err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("open WireGuard control client: %w", err)
	}
	defer client.Close()
	device, err := client.Device(interfaceName)
	if err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("read WireGuard device %q: %w", interfaceName, err)
	}
	if len(device.Peers) != 1 || device.Peers[0].Endpoint == nil {
		return netip.AddrPort{}, false, nil
	}
	addr, ok := netip.AddrFromSlice(device.Peers[0].Endpoint.IP)
	if !ok || device.Peers[0].Endpoint.Port < 1 || device.Peers[0].Endpoint.Port > 65535 {
		return netip.AddrPort{}, false, errors.New("WireGuard reported an invalid peer endpoint")
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(device.Peers[0].Endpoint.Port)), true, nil
}

func (b *Backend) ListenPort(ctx context.Context, interfaceName string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	client, err := wgctrl.New()
	if err != nil {
		return 0, fmt.Errorf("open WireGuard control client: %w", err)
	}
	defer client.Close()
	device, err := client.Device(interfaceName)
	if err != nil {
		return 0, fmt.Errorf("read WireGuard device %q: %w", interfaceName, err)
	}
	if device.ListenPort < 1 || device.ListenPort > 65535 {
		return 0, errors.New("WireGuard reported an invalid local listen port")
	}
	return device.ListenPort, nil
}

func (b *Backend) ReachableLoopbacks(ctx context.Context, table int, pool netip.Prefix) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	routes, err := routesInTable(table)
	if err != nil {
		return nil, err
	}
	seen := map[netip.Addr]struct{}{}
	for i := range routes {
		prefix, ok := prefixFromIPNet(routes[i].Dst)
		if ok && prefix.Bits() == 128 && prefix.Addr().Is6() && pool.Contains(prefix.Addr()) && routes[i].Type == unix.RTN_UNICAST {
			seen[prefix.Addr()] = struct{}{}
		}
	}
	result := make([]netip.Addr, 0, len(seen))
	for address := range seen {
		result = append(result, address)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Compare(result[j]) < 0 })
	return result, nil
}

func cleanupLinkRoutes(desired *reconcile.DesiredState, desiredLinks map[string]struct{}) error {
	indices := make(map[int]struct{}, len(desiredLinks))
	for name := range desiredLinks {
		device, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		indices[device.Attrs().Index] = struct{}{}
	}
	routes, err := routesByProtocol(LinkProtocol)
	if err != nil {
		return err
	}
	for i := range routes {
		_, linkExists := indices[routes[i].LinkIndex]
		prefix, validPrefix := prefixFromIPNet(routes[i].Dst)
		if linkExists && routes[i].Table == desired.FabricTableID && validPrefix && managedLinkRoutePrefix(desired, prefix) {
			continue
		}
		if err := netlink.RouteDel(&routes[i]); err != nil {
			return fmt.Errorf("delete stale Link route: %w", err)
		}
	}
	return nil
}

func retainOwnedLinkNames(names map[string]struct{}) error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list links: %w", err)
	}
	for _, item := range links {
		if item.Type() == "wireguard" && strings.HasPrefix(item.Attrs().Alias, ownerPrefix) {
			names[item.Attrs().Name] = struct{}{}
		}
	}
	return nil
}

func managedLinkRoutePrefix(desired *reconcile.DesiredState, prefix netip.Prefix) bool {
	for _, pool := range []netip.Prefix{desired.LinkPoolV4, desired.LinkPoolV6, desired.LoopbackPoolV6} {
		if pool.IsValid() && pool.Addr().BitLen() == prefix.Addr().BitLen() && pool.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func cleanupStaleLinks(desired map[string]struct{}) error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list links: %w", err)
	}
	for _, item := range links {
		if !strings.HasPrefix(item.Attrs().Alias, ownerPrefix) {
			continue
		}
		if _, keep := desired[item.Attrs().Name]; keep {
			continue
		}
		if err := netlink.LinkDel(item); err != nil {
			return fmt.Errorf("delete stale owned interface %q: %w", item.Attrs().Name, err)
		}
	}
	return nil
}

func deleteLegacyMainPeerRoutes(linkIndex int, loopbackPool netip.Prefix, wanted []netlink.Route) error {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V6)
	if err != nil {
		return err
	}
	for i := range routes {
		prefix, ok := prefixFromIPNet(routes[i].Dst)
		if !ok || prefix.Bits() != 128 || !loopbackPool.Contains(prefix.Addr()) || routes[i].LinkIndex != linkIndex || anyRouteMatches(routes[i], wanted) {
			continue
		}
		if err := netlink.RouteDel(&routes[i]); err != nil {
			return fmt.Errorf("delete legacy main-table peer loopback route %s: %w", prefix, err)
		}
	}
	return nil
}
