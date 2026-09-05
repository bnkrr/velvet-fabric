//go:build linux

package linux

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestPrefixIPNetPreservesHostAddress(t *testing.T) {
	prefix := netip.MustParsePrefix("10.77.0.1/30")
	converted := prefixIPNet(prefix)
	if got, want := converted.IP.String(), "10.77.0.1"; got != want {
		t.Fatalf("converted IP = %q, want %q", got, want)
	}
	roundTrip, ok := prefixFromAddressIPNet(converted)
	if !ok || roundTrip != prefix {
		t.Fatalf("address round trip = %s, %v; want %s, true", roundTrip, ok, prefix)
	}
	network, ok := prefixFromIPNet(converted)
	if !ok || network != prefix.Masked() {
		t.Fatalf("route prefix round trip = %s, %v; want %s, true", network, ok, prefix.Masked())
	}
}

func TestEndpointRotationAndFreshHandshake(t *testing.T) {
	backend := New()
	plan := reconcile.LinkPlan{InterfaceName: "vl-a-b", Endpoints: []string{"192.0.2.1:5000", "192.0.2.2:5000"}}
	device := &wgtypes.Device{}
	if got, change := backend.endpointChoice(plan, device); got != 0 || !change {
		t.Fatalf("initial endpoint = %d, want 0", got)
	}
	backend.mu.Lock()
	attempt := backend.attempts[plan.InterfaceName]
	attempt.since = time.Now().Add(-16 * time.Second)
	backend.attempts[plan.InterfaceName] = attempt
	backend.mu.Unlock()
	if got, change := backend.endpointChoice(plan, device); got != 1 || !change {
		t.Fatalf("endpoint after timeout = %d, want 1", got)
	}
	device.Peers = []wgtypes.Peer{{LastHandshakeTime: time.Now()}}
	if got, _ := backend.endpointChoice(plan, device); got != 1 {
		t.Fatalf("fresh handshake changed endpoint to %d", got)
	}
}

func TestManagedLinkRoutePrefixUsesConfiguredPools(t *testing.T) {
	desired := &reconcile.DesiredState{
		LinkPoolV4:     netip.MustParsePrefix("10.240.0.0/16"),
		LinkPoolV6:     netip.MustParsePrefix("fd77::/48"),
		LoopbackPoolV6: netip.MustParsePrefix("fd78::/48"),
	}
	for _, raw := range []string{"10.240.1.0/30", "fd77::4/126", "fd78::1/128"} {
		if prefix := netip.MustParsePrefix(raw); !managedLinkRoutePrefix(desired, prefix) {
			t.Fatalf("configured pool did not own %s", prefix)
		}
	}
	for _, raw := range []string{"10.241.1.0/30", "fd79::1/128"} {
		if prefix := netip.MustParsePrefix(raw); managedLinkRoutePrefix(desired, prefix) {
			t.Fatalf("unconfigured pool unexpectedly owned %s", prefix)
		}
	}
}

func TestManagedRouteOnlyMatchesExplicitMetric(t *testing.T) {
	current := netlink.Route{Table: 20000, Protocol: StaticProtocol, Type: unix.RTN_UNICAST, Priority: 1024, LinkIndex: 10, Dst: prefixIPNet(netip.MustParsePrefix("2001:db8::/64"))}
	unspecified := managedRoute{route: current}
	unspecified.route.Priority = 0
	if !managedRouteMatches(current, unspecified) {
		t.Fatal("kernel-selected metric was compared for an unspecified metric")
	}
	value := uint32(10)
	explicit := managedRoute{route: current, metric: &value}
	explicit.route.Priority = int(value)
	if managedRouteMatches(current, explicit) {
		t.Fatal("different metric matched an explicitly configured metric")
	}
	current.Priority = int(value)
	if !managedRouteMatches(current, explicit) {
		t.Fatal("identical explicit metric did not match")
	}
}

func TestRoutesMatchOwnershipAndShape(t *testing.T) {
	prefix := prefixIPNet(netip.MustParsePrefix("192.0.2.0/24"))
	base := netlink.Route{Table: 20000, Protocol: StaticProtocol, Type: unix.RTN_UNICAST, Priority: 7, LinkIndex: 10, Dst: prefix}
	if !routesMatch(base, base) {
		t.Fatal("identical routes did not match")
	}
	differentLink := base
	differentLink.LinkIndex = 11
	if routesMatch(base, differentLink) {
		t.Fatal("unicast routes on different interfaces matched")
	}
	differentProtocol := base
	differentProtocol.Protocol = LinkProtocol
	if routesMatch(base, differentProtocol) {
		t.Fatal("routes with different owner protocols matched")
	}
	differentSource := base
	differentSource.Src = net.ParseIP("192.0.2.1")
	if routesMatch(base, differentSource) {
		t.Fatal("routes with different preferred sources matched")
	}
	unreachableA := base
	unreachableA.Type = unix.RTN_UNREACHABLE
	unreachableA.LinkIndex = 0
	unreachableB := unreachableA
	unreachableB.LinkIndex = 99
	if !routesMatch(unreachableA, unreachableB) {
		t.Fatal("non-unicast route comparison should ignore link index")
	}
}

func TestRulesMatchIncludesOwnershipAndSelectors(t *testing.T) {
	source := &net.IPNet{IP: net.ParseIP("10.100.1.0"), Mask: net.CIDRMask(24, 32)}
	base := netlink.NewRule()
	base.Family = netlink.FAMILY_V4
	base.Table = 20001
	base.Priority = 20001
	base.Protocol = uint8(StaticProtocol)
	base.Src = source
	if !rulesMatch(*base, *base) {
		t.Fatal("identical rules did not match")
	}
	differentProtocol := *base
	differentProtocol.Protocol = uint8(LinkProtocol)
	if rulesMatch(*base, differentProtocol) {
		t.Fatal("rules with different owner protocols matched")
	}
	differentDestination := *base
	differentDestination.Src = nil
	differentDestination.Dst = source
	if rulesMatch(*base, differentDestination) {
		t.Fatal("source and destination selectors matched")
	}
}

func TestIsLinkNotFoundHandlesNil(t *testing.T) {
	if isLinkNotFound(nil) {
		t.Fatal("nil error was treated as link-not-found")
	}
}

func TestDynamicOwnershipRequiresExactAliasAndType(t *testing.T) {
	owner := "velvet:link:local:dynamic:remote-a"
	device := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{Name: "vdl-a-1234", Alias: owner},
		LinkType:  "wireguard",
	}
	if !isExactlyOwnedWireGuardInterface(device, owner) {
		t.Fatal("exact dynamic owner did not match")
	}
	if isExactlyOwnedWireGuardInterface(device, "velvet:link:local:dynamic:remote-b") {
		t.Fatal("a different Velvet owner alias matched")
	}
	device.LinkType = "dummy"
	if isExactlyOwnedWireGuardInterface(device, owner) {
		t.Fatal("a non-WireGuard interface matched")
	}
}

func TestDesiredLinkNamesIncludesLoopbackAndConfiguredLinks(t *testing.T) {
	desired := &reconcile.DesiredState{Links: []reconcile.LinkPlan{{InterfaceName: "vl-a"}, {InterfaceName: "vl-b"}}}
	names := desiredLinkNames(desired)
	for _, name := range []string{reconcile.LoopbackInterface, "vl-a", "vl-b"} {
		if _, ok := names[name]; !ok {
			t.Fatalf("desired names missing %q", name)
		}
	}
}

func TestDesiredRoutesAndRules(t *testing.T) {
	metric := uint32(42)
	desired := &reconcile.DesiredState{
		Routes: []reconcile.RoutePlan{
			{TableID: 20000, Prefix: netip.MustParsePrefix("0.0.0.0/0"), Type: reconcile.RouteThrow, Metric: &metric},
			{TableID: 20001, Prefix: netip.MustParsePrefix("fd00::/64"), Type: reconcile.RouteUnreachable},
		},
		Rules: []reconcile.RulePlan{
			{TableID: 20000, Priority: 20000, Source: netip.MustParsePrefix("10.0.0.0/8")},
			{TableID: 20001, Priority: 20001, Destination: netip.MustParsePrefix("fd00::/64")},
		},
	}
	routes, err := desiredNetlinkRoutes(desired)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 || routes[0].route.Type != unix.RTN_THROW || routes[0].route.Priority != 42 || routes[1].route.Type != unix.RTN_UNREACHABLE {
		t.Fatalf("unexpected routes: %#v", routes)
	}
	rules := desiredNetlinkRules(desired)
	if len(rules) != 2 || rules[0].Src == nil || rules[0].Family != netlink.FAMILY_V4 || rules[1].Dst == nil || rules[1].Family != netlink.FAMILY_V6 {
		t.Fatalf("unexpected rules: %#v", rules)
	}
	desired.Routes[0].Type = 255
	if _, err := desiredNetlinkRoutes(desired); err == nil {
		t.Fatal("unsupported route type was accepted")
	}
}

func TestMaterializedLinkRoutes(t *testing.T) {
	state := &reconcile.DesiredState{FabricTableID: 20000, LoopbackV6: netip.MustParseAddr("fd00::1")}
	routes := materializedLinkRoutes(
		state,
		7,
		[]netip.Prefix{{}, netip.MustParsePrefix("10.0.0.2/30")},
		[]netip.Addr{{}, netip.MustParseAddr("fd00::2")},
	)
	if len(routes) != 2 {
		t.Fatalf("materialized %d routes, want 2", len(routes))
	}
	if got, ok := prefixFromIPNet(routes[0].Dst); !ok || got.String() != "10.0.0.0/30" {
		t.Fatalf("Link route destination = %v, %v", got, ok)
	}
	if routes[1].Src.String() != "fd00::1" || routeDestination(routes[1]) != "fd00::2/128" {
		t.Fatalf("peer loopback route = %#v", routes[1])
	}
}

func TestNetworkValueHelpers(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.4/30")
	addresses := []netlink.Addr{{IPNet: prefixIPNet(prefix)}}
	if !addressPresent(addresses, prefix) || addressPresent(addresses, netip.MustParsePrefix("192.0.2.8/30")) {
		t.Fatal("addressPresent returned the wrong result")
	}
	if !prefixAddressPresent([]netip.Prefix{prefix}, prefix.Addr()) || prefixAddressPresent(nil, prefix.Addr()) {
		t.Fatal("prefixAddressPresent returned the wrong result")
	}
	if !prefixesOverlap(prefix, netip.MustParsePrefix("192.0.2.5/32")) || prefixesOverlap(prefix, netip.MustParsePrefix("2001:db8::/64")) {
		t.Fatal("prefix overlap returned the wrong result")
	}
	if family(prefix.Addr()) != netlink.FAMILY_V4 || family(netip.MustParseAddr("2001:db8::1")) != netlink.FAMILY_V6 {
		t.Fatal("address family returned the wrong result")
	}
	if _, ok := prefixFromIPNet(nil); ok {
		t.Fatal("nil IPNet produced a prefix")
	}
	if got := forwardingPaths; len(got) != 2 {
		t.Fatalf("forwarding paths = %v", got)
	}
}

func TestRouteAndRuleCollectionMatching(t *testing.T) {
	route := netlink.Route{Table: 20000, Protocol: StaticProtocol, Type: unix.RTN_THROW, Dst: prefixIPNet(netip.MustParsePrefix("10.0.0.0/8"))}
	if !anyRouteMatches(route, []netlink.Route{route}) || anyRouteMatches(route, nil) {
		t.Fatal("route collection match returned the wrong result")
	}
	wanted := managedRoute{route: route}
	if !managedRoutePresent(wanted, []netlink.Route{route}) || !anyManagedRouteMatches(route, []managedRoute{wanted}) {
		t.Fatal("managed route collection match returned the wrong result")
	}
	rule := *netlink.NewRule()
	rule.Table, rule.Priority, rule.Protocol = 20000, 20000, uint8(StaticProtocol)
	if !anyRuleMatches(rule, []netlink.Rule{rule}) || anyRuleMatches(rule, nil) {
		t.Fatal("rule collection match returned the wrong result")
	}
	if routeDestination(netlink.Route{}) != "default" {
		t.Fatal("nil route destination was not rendered as default")
	}
}

func TestWireGuardValueHelpers(t *testing.T) {
	wanted := wgtypes.Key{1}
	removed := stalePeerRemovals([]wgtypes.Peer{{PublicKey: wanted}, {PublicKey: wgtypes.Key{2}}}, wanted)
	if len(removed) != 1 || !removed[0].Remove || removed[0].PublicKey != (wgtypes.Key{2}) {
		t.Fatalf("stale removals = %#v", removed)
	}
	now := time.Now()
	if endpointStale(now.Add(-time.Minute), now, nil) || !endpointStale(time.Time{}, now, nil) {
		t.Fatal("default endpoint staleness was wrong")
	}
	keepalive := 2 * time.Minute
	if endpointStale(now.Add(-4*time.Minute), now, &keepalive) || endpointStale(now, now, &keepalive) {
		t.Fatal("keepalive endpoint staleness was wrong")
	}
	allowed := defaultAllowedIPs()
	if len(allowed) != 2 || allowed[0].String() != "0.0.0.0/0" || allowed[1].String() != "::/0" {
		t.Fatalf("default allowed IPs = %v", allowed)
	}
}
