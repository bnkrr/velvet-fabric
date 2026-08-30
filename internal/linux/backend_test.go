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
