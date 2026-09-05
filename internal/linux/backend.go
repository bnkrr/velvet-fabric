//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/link"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	StaticProtocol netlink.RouteProtocol = 201
	LinkProtocol   netlink.RouteProtocol = 202
	ownerPrefix                          = "velvet:"
)

type managedRoute struct {
	route  netlink.Route
	metric *uint32
}

type Backend struct {
	mu       sync.Mutex
	attempts map[string]endpointAttempt
	kernelMu sync.Mutex
}

type endpointAttempt struct {
	index         int
	since         time.Time
	lastHandshake time.Time
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
	loop, err := ensureOwnedDummy(reconcile.LoopbackInterface, desired.LoopbackOwnerAlias)
	if err != nil {
		return err
	}
	loopback := netip.PrefixFrom(desired.LoopbackV6, 128)
	if err := reconcileLoopbackAddresses(loop, loopback); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(loop); err != nil {
		return fmt.Errorf("set loopback interface up: %w", err)
	}
	desiredLinks := make(map[string]struct{}, len(desired.Links)+1)
	desiredLinks[reconcile.LoopbackInterface] = struct{}{}
	for _, item := range desired.Links {
		desiredLinks[item.InterfaceName] = struct{}{}
	}
	if preserveRuntimeLinks {
		if err := retainOwnedLinkNames(desiredLinks); err != nil {
			return err
		}
	}
	// A renamed WireGuard interface may retain the same listen port. Remove stale
	// owned interfaces before creating replacements so the port can be rebound.
	if err := cleanupStaleLinks(desiredLinks); err != nil {
		return err
	}

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open WireGuard control client: %w", err)
	}
	defer client.Close()
	for _, item := range desired.Links {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := b.applyBootstrapLink(client, item); err != nil {
			return fmt.Errorf("peer %q: %w", item.PeerName, err)
		}
	}
	if desired.Forwarding {
		if err := enableForwarding(); err != nil {
			return err
		}
	}
	if err := ensureStaticRoutes(desired); err != nil {
		return err
	}
	if err := reconcilePolicyRules(desired); err != nil {
		return err
	}
	if err := cleanupStaticRoutes(desired); err != nil {
		return err
	}
	if err := cleanupLinkRoutes(desired, desiredLinks); err != nil {
		return err
	}
	return nil
}

func cleanupDisabledBabelState() error {
	routes, err := routesByProtocol(netlink.RouteProtocol(reconcile.BabelDynamicProtocol))
	if err != nil {
		return err
	}
	for i := range routes {
		if err := netlink.RouteDel(&routes[i]); err != nil {
			return fmt.Errorf("delete disabled Babel route %s from table %d: %w", routeDestination(routes[i]), routes[i].Table, err)
		}
	}
	rules, err := rulesByProtocol(uint8(reconcile.BabelDynamicProtocol))
	if err != nil {
		return err
	}
	for i := range rules {
		if err := netlink.RuleDel(&rules[i]); err != nil {
			return fmt.Errorf("delete disabled Babel rule priority %d table %d: %w", rules[i].Priority, rules[i].Table, err)
		}
	}
	return nil
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
	loop, err := netlink.LinkByName(reconcile.LoopbackInterface)
	if err != nil || loop.Type() != "dummy" || loop.Attrs().Alias != desired.LoopbackOwnerAlias {
		return errors.New("node loopback interface is missing or not owned by this node")
	}
	loopAddrs, err := netlink.AddrList(loop, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	loopback := netip.PrefixFrom(desired.LoopbackV6, 128)
	if !addressPresent(loopAddrs, loopback) {
		return fmt.Errorf("node loopback %s is missing", loopback)
	}
	for _, item := range desired.Links {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := verifyBootstrapLink(client, item); err != nil {
			return fmt.Errorf("peer %q: %w", item.PeerName, err)
		}
	}
	if err := verifyStaticRoutes(desired); err != nil {
		return err
	}
	if err := verifyPolicyRules(desired); err != nil {
		return err
	}
	if desired.Forwarding {
		if err := verifyForwarding(); err != nil {
			return err
		}
	}
	return nil
}

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
	if err := reconcileMaterializedAddresses(device, desired.BootstrapAddress, local); err != nil {
		return err
	}
	wanted := make([]netlink.Route, 0, len(local)+len(peerLoopbacks))
	for _, prefix := range local {
		if !prefix.IsValid() {
			continue
		}
		network := prefix.Masked()
		route := netlink.Route{
			LinkIndex: device.Attrs().Index,
			Dst:       prefixIPNet(network),
			Scope:     netlink.SCOPE_LINK,
			Protocol:  LinkProtocol,
			Table:     state.FabricTableID,
			Type:      unix.RTN_UNICAST,
		}
		if err := netlink.RouteReplace(&route); err != nil {
			return fmt.Errorf("install negotiated Link route %s: %w", network, err)
		}
		wanted = append(wanted, route)
	}
	for _, address := range peerLoopbacks {
		if !address.IsValid() {
			continue
		}
		bits := 128
		if address.Is4() {
			bits = 32
		}
		route := netlink.Route{
			LinkIndex: device.Attrs().Index,
			Dst:       prefixIPNet(netip.PrefixFrom(address, bits)),
			Src:       net.IP(state.LoopbackV6.AsSlice()),
			Scope:     netlink.SCOPE_LINK,
			Protocol:  LinkProtocol,
			Table:     state.FabricTableID,
			Type:      unix.RTN_UNICAST,
		}
		if err := netlink.RouteReplace(&route); err != nil {
			return fmt.Errorf("install adjacent peer loopback route %s: %w", address, err)
		}
		wanted = append(wanted, route)
	}
	current, err := routesByProtocol(LinkProtocol)
	if err != nil {
		return err
	}
	for i := range current {
		if current[i].LinkIndex != device.Attrs().Index {
			continue
		}
		if !anyRouteMatches(current[i], wanted) {
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
	if err := ensureStaticRoutes(state); err != nil {
		return err
	}
	if err := reconcilePolicyRules(state); err != nil {
		return err
	}
	return nil
}

func (b *Backend) PrepareDynamic(ctx context.Context, desired reconcile.LinkPlan) (reconcile.LinkPlan, error) {
	b.kernelMu.Lock()
	defer b.kernelMu.Unlock()
	if err := ctx.Err(); err != nil {
		return reconcile.LinkPlan{}, err
	}
	device, err := ensureOwnedWireGuardInterface(desired.InterfaceName, desired.OwnerAlias)
	if err != nil {
		return reconcile.LinkPlan{}, err
	}
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
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open WireGuard control client: %w", err)
	}
	defer client.Close()
	return b.applyBootstrapLink(client, desired)
}

func (b *Backend) RemoveDynamic(ctx context.Context, interfaceName string) error {
	b.kernelMu.Lock()
	defer b.kernelMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	device, err := netlink.LinkByName(interfaceName)
	if isLinkNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("look up dynamic interface %q: %w", interfaceName, err)
	}
	if device.Type() != "wireguard" || !strings.HasPrefix(device.Attrs().Alias, ownerPrefix) {
		return fmt.Errorf("interface %q is not an owned WireGuard interface", interfaceName)
	}
	if err := netlink.LinkDel(device); err != nil {
		return fmt.Errorf("delete dynamic interface %q: %w", interfaceName, err)
	}
	b.mu.Lock()
	delete(b.attempts, interfaceName)
	b.mu.Unlock()
	return nil
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
	addr = addr.Unmap()
	return netip.AddrPortFrom(addr, uint16(device.Peers[0].Endpoint.Port)), true, nil
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
		if !ok || prefix.Bits() != 128 || !prefix.Addr().Is6() || !pool.Contains(prefix.Addr()) || routes[i].Type != unix.RTN_UNICAST {
			continue
		}
		seen[prefix.Addr()] = struct{}{}
	}
	result := make([]netip.Addr, 0, len(seen))
	for address := range seen {
		result = append(result, address)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Compare(result[j]) < 0 })
	return result, nil
}

func ensureStaticRoutes(desired *reconcile.DesiredState) error {
	wanted, err := desiredNetlinkRoutes(desired)
	if err != nil {
		return err
	}
	for i := range wanted {
		if err := netlink.RouteReplace(&wanted[i].route); err != nil {
			return fmt.Errorf("replace route %s in table %d: %w", routeDestination(wanted[i].route), wanted[i].route.Table, err)
		}
	}
	return nil
}

func cleanupStaticRoutes(desired *reconcile.DesiredState) error {
	wanted, err := desiredNetlinkRoutes(desired)
	if err != nil {
		return err
	}
	current, err := routesByProtocol(StaticProtocol)
	if err != nil {
		return err
	}
	for i := range current {
		if !anyManagedRouteMatches(current[i], wanted) {
			if err := netlink.RouteDel(&current[i]); err != nil {
				return fmt.Errorf("delete stale route %s from table %d: %w", routeDestination(current[i]), current[i].Table, err)
			}
		}
	}
	return nil
}

func desiredNetlinkRoutes(desired *reconcile.DesiredState) ([]managedRoute, error) {
	result := make([]managedRoute, 0, len(desired.Routes))
	for _, item := range desired.Routes {
		route := netlink.Route{
			Dst:      prefixIPNet(item.Prefix),
			Table:    item.TableID,
			Protocol: StaticProtocol,
			Scope:    netlink.SCOPE_UNIVERSE,
		}
		if item.Metric != nil {
			route.Priority = int(*item.Metric)
		}
		switch item.Type {
		case reconcile.RouteViaPeer:
			device, err := netlink.LinkByName(item.InterfaceName)
			if err != nil {
				return nil, fmt.Errorf("route %s peer %q interface: %w", item.Prefix, item.PeerName, err)
			}
			route.LinkIndex = device.Attrs().Index
			route.Scope = netlink.SCOPE_LINK
			route.Type = unix.RTN_UNICAST
			if item.TableID == desired.FabricTableID && item.Prefix.Addr().Is6() && desired.LoopbackPoolV6.Contains(item.Prefix.Addr()) {
				route.Src = net.IP(desired.LoopbackV6.AsSlice())
			}
		case reconcile.RouteThrow:
			route.Type = unix.RTN_THROW
		case reconcile.RouteUnreachable:
			route.Type = unix.RTN_UNREACHABLE
		default:
			return nil, fmt.Errorf("route %s has unsupported type %d", item.Prefix, item.Type)
		}
		result = append(result, managedRoute{route: route, metric: item.Metric})
	}
	return result, nil
}

func reconcilePolicyRules(desired *reconcile.DesiredState) error {
	wanted := desiredNetlinkRules(desired)
	current, err := rulesByProtocol(uint8(StaticProtocol))
	if err != nil {
		return err
	}
	for i := range wanted {
		if anyRuleMatches(wanted[i], current) {
			continue
		}
		if err := netlink.RuleAdd(&wanted[i]); err != nil {
			return fmt.Errorf("add rule priority %d table %d: %w", wanted[i].Priority, wanted[i].Table, err)
		}
	}
	current, err = rulesByProtocol(uint8(StaticProtocol))
	if err != nil {
		return err
	}
	for i := range current {
		if !anyRuleMatches(current[i], wanted) {
			if err := netlink.RuleDel(&current[i]); err != nil {
				return fmt.Errorf("delete stale rule priority %d table %d: %w", current[i].Priority, current[i].Table, err)
			}
		}
	}
	return nil
}

func desiredNetlinkRules(desired *reconcile.DesiredState) []netlink.Rule {
	result := make([]netlink.Rule, 0, len(desired.Rules))
	for _, item := range desired.Rules {
		rule := netlink.NewRule()
		rule.Table = item.TableID
		rule.Priority = item.Priority
		rule.Protocol = uint8(StaticProtocol)
		prefix := item.Source
		if prefix.IsValid() {
			rule.Src = prefixIPNet(prefix)
		} else {
			prefix = item.Destination
			rule.Dst = prefixIPNet(prefix)
		}
		rule.Family = family(prefix.Addr())
		result = append(result, *rule)
	}
	return result
}

func verifyStaticRoutes(desired *reconcile.DesiredState) error {
	wanted, err := desiredNetlinkRoutes(desired)
	if err != nil {
		return err
	}
	current, err := routesByProtocol(StaticProtocol)
	if err != nil {
		return err
	}
	for _, route := range wanted {
		if !managedRoutePresent(route, current) {
			return fmt.Errorf("route %s in table %d is missing", routeDestination(route.route), route.route.Table)
		}
	}
	for _, route := range current {
		if !anyManagedRouteMatches(route, wanted) {
			return fmt.Errorf("stale route %s remains in table %d", routeDestination(route), route.Table)
		}
	}
	return nil
}

func verifyPolicyRules(desired *reconcile.DesiredState) error {
	wanted := desiredNetlinkRules(desired)
	current, err := rulesByProtocol(uint8(StaticProtocol))
	if err != nil {
		return err
	}
	for _, rule := range wanted {
		if !anyRuleMatches(rule, current) {
			return fmt.Errorf("rule priority %d table %d is missing", rule.Priority, rule.Table)
		}
	}
	for _, rule := range current {
		if !anyRuleMatches(rule, wanted) {
			return fmt.Errorf("stale rule priority %d table %d remains", rule.Priority, rule.Table)
		}
	}
	return nil
}

func rejectForeignTableState(desired *reconcile.DesiredState) error {
	tables := map[int]struct{}{desired.FabricTableID: {}}
	for _, route := range desired.Routes {
		tables[route.TableID] = struct{}{}
	}
	for _, rule := range desired.Rules {
		tables[rule.TableID] = struct{}{}
	}
	for table := range tables {
		routes, err := routesInTable(table)
		if err != nil {
			return err
		}
		for _, route := range routes {
			babelOwned := desired.Babel != nil && route.Protocol == netlink.RouteProtocol(desired.Babel.Protocol)
			if route.Protocol != StaticProtocol && route.Protocol != LinkProtocol && !babelOwned {
				return fmt.Errorf("routing table %d contains foreign route %s with protocol %d", table, routeDestination(route), route.Protocol)
			}
		}
	}
	return nil
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

func routesByProtocol(protocol netlink.RouteProtocol) ([]netlink.Route, error) {
	filter := &netlink.Route{Table: unix.RT_TABLE_UNSPEC, Protocol: protocol}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, filter, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return nil, fmt.Errorf("list protocol %d routes: %w", protocol, err)
	}
	return routes, nil
}

func routesInTable(table int) ([]netlink.Route, error) {
	filter := &netlink.Route{Table: table}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, filter, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, fmt.Errorf("list routes in table %d: %w", table, err)
	}
	return routes, nil
}

func rulesByProtocol(protocol uint8) ([]netlink.Rule, error) {
	var result []netlink.Rule
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			return nil, fmt.Errorf("list family %d rules: %w", family, err)
		}
		for _, rule := range rules {
			if rule.Protocol == protocol {
				result = append(result, rule)
			}
		}
	}
	return result, nil
}

func anyRouteMatches(route netlink.Route, candidates []netlink.Route) bool {
	for _, candidate := range candidates {
		if routesMatch(route, candidate) {
			return true
		}
	}
	return false
}

func routesMatch(a, b netlink.Route) bool {
	if a.Table != b.Table || a.Protocol != b.Protocol || a.Type != b.Type || !ipEqual(a.Src, b.Src) {
		return false
	}
	ap, aok := prefixFromIPNet(a.Dst)
	bp, bok := prefixFromIPNet(b.Dst)
	if !aok || !bok || ap != bp {
		return false
	}
	if a.Type == unix.RTN_UNICAST && a.LinkIndex != b.LinkIndex {
		return false
	}
	return true
}

func managedRoutePresent(wanted managedRoute, current []netlink.Route) bool {
	for _, route := range current {
		if managedRouteMatches(route, wanted) {
			return true
		}
	}
	return false
}

func anyManagedRouteMatches(current netlink.Route, wanted []managedRoute) bool {
	for _, route := range wanted {
		if managedRouteMatches(current, route) {
			return true
		}
	}
	return false
}

func managedRouteMatches(current netlink.Route, wanted managedRoute) bool {
	if !routesMatch(current, wanted.route) {
		return false
	}
	return wanted.metric == nil || current.Priority == int(*wanted.metric)
}

func ipEqual(a, b net.IP) bool {
	if len(a) == 0 || len(b) == 0 {
		return len(a) == 0 && len(b) == 0
	}
	return a.Equal(b)
}

func anyRuleMatches(rule netlink.Rule, candidates []netlink.Rule) bool {
	for _, candidate := range candidates {
		if rulesMatch(rule, candidate) {
			return true
		}
	}
	return false
}

func rulesMatch(a, b netlink.Rule) bool {
	return a.Family == b.Family && a.Table == b.Table && a.Priority == b.Priority && a.Protocol == b.Protocol && ipNetEqual(a.Src, b.Src) && ipNetEqual(a.Dst, b.Dst)
}

func ipNetEqual(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	ap, aok := prefixFromIPNet(a)
	bp, bok := prefixFromIPNet(b)
	return aok && bok && ap == bp
}

func routeDestination(route netlink.Route) string {
	if prefix, ok := prefixFromIPNet(route.Dst); ok {
		return prefix.String()
	}
	return "default"
}

func enableForwarding() error {
	for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
			return fmt.Errorf("enable forwarding through %s: %w", path, err)
		}
	}
	return nil
}

func verifyForwarding() error {
	for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
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
		if !ok || prefix == wanted {
			continue
		}
		if prefix.Addr().IsLinkLocalUnicast() {
			if err := netlink.AddrDel(device, &addresses[i]); err != nil {
				return err
			}
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

func deleteLegacyMainPeerRoutes(linkIndex int, loopbackPool netip.Prefix, wanted []netlink.Route) error {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V6)
	if err != nil {
		return err
	}
	for i := range routes {
		prefix, ok := prefixFromIPNet(routes[i].Dst)
		if !ok || prefix.Bits() != 128 || !loopbackPool.Contains(prefix.Addr()) || routes[i].LinkIndex != linkIndex {
			continue
		}
		if anyRouteMatches(routes[i], wanted) {
			continue
		}
		if err := netlink.RouteDel(&routes[i]); err != nil {
			return fmt.Errorf("delete legacy main-table peer loopback route %s: %w", prefix, err)
		}
	}
	return nil
}

func (b *Backend) applyBootstrapLink(client *wgctrl.Client, desired reconcile.LinkPlan) error {
	device, err := ensureOwnedWireGuardInterface(desired.InterfaceName, desired.OwnerAlias)
	if err != nil {
		return err
	}
	if err := reconcileBootstrapAddress(device, desired.BootstrapAddress); err != nil {
		return fmt.Errorf("assign bootstrap address: %w", err)
	}
	if err := netlink.LinkSetUp(device); err != nil {
		return fmt.Errorf("set interface up: %w", err)
	}
	current, err := client.Device(desired.InterfaceName)
	if err != nil {
		return fmt.Errorf("read current WireGuard device: %w", err)
	}
	peers := make([]wgtypes.PeerConfig, 0, len(current.Peers)+1)
	for _, existing := range current.Peers {
		if existing.PublicKey != desired.PeerPublicKey {
			peers = append(peers, wgtypes.PeerConfig{PublicKey: existing.PublicKey, Remove: true})
		}
	}
	endpointIndex, changeEndpoint := b.endpointChoice(desired, current)
	var endpoint *net.UDPAddr
	if changeEndpoint {
		endpoint, err = net.ResolveUDPAddr("udp", desired.Endpoints[endpointIndex])
		if err != nil {
			return fmt.Errorf("resolve endpoint %q: %w", desired.Endpoints[endpointIndex], err)
		}
	}
	peer := wgtypes.PeerConfig{PublicKey: desired.PeerPublicKey, PresharedKey: &desired.PresharedKey, Endpoint: endpoint, ReplaceAllowedIPs: true, AllowedIPs: defaultAllowedIPs()}
	if desired.Keepalive != nil {
		peer.PersistentKeepaliveInterval = desired.Keepalive
	}
	peers = append(peers, peer)
	privateKey, listenPort := desired.PrivateKey, desired.ListenPort
	if err := client.ConfigureDevice(desired.InterfaceName, wgtypes.Config{PrivateKey: &privateKey, ListenPort: &listenPort, Peers: peers}); err != nil {
		return fmt.Errorf("configure WireGuard device: %w", err)
	}
	return nil
}

func (b *Backend) endpointChoice(desired reconcile.LinkPlan, current *wgtypes.Device) (int, bool) {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	attempt, exists := b.attempts[desired.InterfaceName]
	currentMatches := len(current.Peers) == 1 && current.Peers[0].PublicKey == desired.PeerPublicKey
	changeEndpoint := !currentMatches || current.Peers[0].Endpoint == nil
	if !exists || attempt.index >= len(desired.Endpoints) {
		attempt = endpointAttempt{since: now}
		if currentMatches && current.Peers[0].Endpoint != nil {
			matched := false
			for index, raw := range desired.Endpoints {
				resolved, err := net.ResolveUDPAddr("udp", raw)
				if err == nil && resolved.String() == current.Peers[0].Endpoint.String() {
					attempt.index = index
					matched = true
					break
				}
			}
			// A fresh endpoint outside the configured list may be WireGuard's
			// authenticated endpoint roaming. Preserve it rather than resetting
			// every reconciliation pass.
			if !matched && !current.Peers[0].LastHandshakeTime.IsZero() && now.Sub(current.Peers[0].LastHandshakeTime) < 3*time.Minute {
				changeEndpoint = false
			} else if !matched {
				changeEndpoint = true
			}
		}
	}
	if currentMatches {
		handshake := current.Peers[0].LastHandshakeTime
		if handshake.After(attempt.lastHandshake) {
			attempt.lastHandshake = handshake
			attempt.since = now
		}
	}
	attemptThreshold := 15 * time.Second
	staleThreshold := 3 * time.Minute
	if desired.Keepalive != nil && *desired.Keepalive*3 > staleThreshold {
		staleThreshold = *desired.Keepalive * 3
	}
	stale := attempt.lastHandshake.IsZero() || now.Sub(attempt.lastHandshake) >= staleThreshold
	if len(desired.Endpoints) > 1 && now.Sub(attempt.since) >= attemptThreshold && stale {
		attempt.index = (attempt.index + 1) % len(desired.Endpoints)
		attempt.since = now
		changeEndpoint = true
	}
	b.attempts[desired.InterfaceName] = attempt
	return attempt.index, changeEndpoint
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
	if desired.Keepalive != nil && wgDevice.Peers[0].PersistentKeepaliveInterval != *desired.Keepalive {
		return errors.New("WireGuard persistent keepalive does not match")
	}
	return nil
}

func ensureOwnedWireGuardInterface(name, owner string) (netlink.Link, error) {
	device, created, err := ensureLink(name, "wireguard", func() error {
		return netlink.LinkAdd(&netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name}, LinkType: "wireguard"})
	})
	if err != nil {
		return nil, err
	}
	if !created && !strings.HasPrefix(device.Attrs().Alias, ownerPrefix) {
		return nil, fmt.Errorf("interface %q exists but is not an owned WireGuard interface", name)
	}
	if device.Attrs().Alias != owner {
		if err := netlink.LinkSetAlias(device, owner); err != nil {
			return nil, err
		}
		device, err = netlink.LinkByName(name)
	}
	return device, err
}

func ensureOwnedDummy(name, owner string) (netlink.Link, error) {
	device, created, err := ensureLink(name, "dummy", func() error {
		return netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}})
	})
	if err != nil {
		return nil, err
	}
	if !created && !strings.HasPrefix(device.Attrs().Alias, ownerPrefix) {
		return nil, fmt.Errorf("interface %q exists but is not the owned node loopback", name)
	}
	if device.Attrs().Alias != owner {
		if err := netlink.LinkSetAlias(device, owner); err != nil {
			return nil, err
		}
		device, err = netlink.LinkByName(name)
	}
	return device, err
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

func defaultAllowedIPs() []net.IPNet {
	_, v4, _ := net.ParseCIDR("0.0.0.0/0")
	_, v6, _ := net.ParseCIDR("::/0")
	return []net.IPNet{*v4, *v6}
}

func isLinkNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}
