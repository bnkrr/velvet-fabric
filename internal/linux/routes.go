//go:build linux

package linux

import (
	"fmt"
	"net"

	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type managedRoute struct {
	route  netlink.Route
	metric *uint32
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

func reconcileRoutesAndRules(desired *reconcile.DesiredState) error {
	wanted, err := desiredNetlinkRoutes(desired)
	if err != nil {
		return err
	}
	if err := replaceStaticRoutes(wanted); err != nil {
		return err
	}
	if err := reconcilePolicyRules(desired); err != nil {
		return err
	}
	return deleteStaleStaticRoutes(wanted)
}

func deleteStaleStaticRoutes(wanted []managedRoute) error {
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

func replaceStaticRoutes(wanted []managedRoute) error {
	for i := range wanted {
		route := &wanted[i].route
		if err := netlink.RouteReplace(route); err != nil {
			return fmt.Errorf("replace route %s in table %d: %w", routeDestination(*route), route.Table, err)
		}
	}
	return nil
}

func desiredNetlinkRoutes(desired *reconcile.DesiredState) ([]managedRoute, error) {
	result := make([]managedRoute, 0, len(desired.Routes))
	for _, item := range desired.Routes {
		route := netlink.Route{Dst: prefixIPNet(item.Prefix), Table: item.TableID, Protocol: StaticProtocol, Scope: netlink.SCOPE_UNIVERSE}
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
	return a.Type != unix.RTN_UNICAST || a.LinkIndex == b.LinkIndex
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
