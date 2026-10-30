package reconcile

import (
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func nodeFixture() *spec.NodeSpec {
	key, peer := wgtypes.Key{1}, wgtypes.Key{8, 2}
	return &spec.NodeSpec{
		APIVersion: spec.APIVersion, Kind: spec.Kind,
		Fabric: spec.FabricSpec{PSK: key.String(), LoopbackPrefixV6: "fd41::/48"},
		Node:   spec.Node{UID: spec.NodeUID{Name: "a", UUID: "10000000-0000-4000-8000-000000000001"}, PrivateKey: key.String()},
		Peers:  []spec.Peer{{Name: "b", PublicKey: peer.PublicKey().String(), Endpoints: []string{"192.0.2.2:51002"}}},
	}
}

func TestBuildDesiredStateContainsLinkAndRoutingState(t *testing.T) {
	value := nodeFixture()
	value.Fabric.StaticRoutes = spec.Routes{"b": {{Prefix: "fd41::20/128"}}}
	value.Domains = map[string]spec.DomainSpec{"production": {SourceTableID: 20001, SourcePrefixes: []string{"10.100.1.0/24"}, StaticRoutes: spec.Routes{"b": {{Prefix: "192.168.20.0/24"}}}, Announcements: []spec.Announcement{{Prefix: "0.0.0.0/0"}}}}
	desired, err := BuildDesiredState(value)
	if err != nil {
		t.Fatal(err)
	}
	if len(desired.Links) != 1 {
		t.Fatal("missing Link plan")
	}
	item := desired.Links[0]
	if item.Keepalive != nil || desired.LinkPoolV4.IsValid() || desired.LinkPoolV6.IsValid() {
		t.Fatal("omitted settings became explicit defaults")
	}
	if !item.BootstrapAddress.Addr().IsLinkLocalUnicast() || !desired.LoopbackPoolV6.Contains(desired.LoopbackV6) || !desired.Forwarding {
		t.Fatal("incorrect infrastructure state")
	}
	wantRoutes := []RoutePlan{
		{TableID: 20000, Prefix: netip.MustParsePrefix("fd41::20/128"), Type: RouteViaPeer, PeerName: "b", InterfaceName: item.InterfaceName},
		{TableID: 20001, Prefix: netip.MustParsePrefix("fd41::20/128"), Type: RouteViaPeer, PeerName: "b", InterfaceName: item.InterfaceName},
		{TableID: 20001, Prefix: netip.MustParsePrefix("192.168.20.0/24"), Type: RouteViaPeer, PeerName: "b", InterfaceName: item.InterfaceName},
		{TableID: 20001, Prefix: netip.MustParsePrefix("0.0.0.0/0"), Type: RouteThrow},
	}
	var reachable []RoutePlan
	for _, route := range desired.Routes {
		if route.Type != RouteUnreachable {
			reachable = append(reachable, route)
		}
	}
	if diff := cmp.Diff(wantRoutes, reachable, cmpopts.EquateComparable(netip.Prefix{}, netip.Addr{}), cmpopts.SortSlices(func(a, b RoutePlan) bool {
		if a.TableID != b.TableID {
			return a.TableID < b.TableID
		}
		return a.Prefix.String() < b.Prefix.String()
	})); diff != "" {
		t.Fatalf("routes (-want +got):\n%s", diff)
	}
	assertRules(t, desired.Rules, []RulePlan{
		{TableID: 20000, Priority: 20000, Destination: netip.MustParsePrefix("fd41::/48")},
		{TableID: 20000, Priority: 20000, Destination: netip.MustParsePrefix("10.100.1.0/24")},
		{TableID: 20001, Priority: 20001, Source: netip.MustParsePrefix("10.100.1.0/24")},
	})
}

func TestBuildDesiredStateCompilesManagedBabel(t *testing.T) {
	value := nodeFixture()
	enabled := true
	value.Babel = &spec.BabelSpec{Enabled: &enabled, Executable: "/usr/local/bin/babel-rs"}
	value.Domains = map[string]spec.DomainSpec{"production": {SourceTableID: 20001, SourcePrefixes: []string{"10.100.1.0/24", "10.100.2.0/24", "fd10:100:1::/64"}, Announcements: []spec.Announcement{{Prefix: "10.100.1.0/24"}, {Prefix: "0.0.0.0/0"}, {Prefix: "::/0"}}}}
	for _, interfaceName := range []string{"", "mesh0"} {
		t.Run("interface="+interfaceName, func(t *testing.T) {
			value.Peers[0].InterfaceName = interfaceName
			desired, err := BuildDesiredState(value)
			if err != nil {
				t.Fatal(err)
			}
			plan := desired.Babel
			if plan == nil || plan.ManageRules || !plan.DeviceOnly || plan.Protocol != 203 {
				t.Fatalf("invalid Babel ownership: %#v", plan)
			}
			if diff := cmp.Diff([]string(nil), plan.Interfaces); diff != "" {
				t.Fatal(diff)
			}
			src4, src6 := netip.MustParsePrefix("10.100.1.0/24"), netip.MustParsePrefix("fd10:100:1::/64")
			infra, alias := netip.MustParsePrefix("fd41::/48"), netip.MustParsePrefix("10.100.2.0/24")
			if diff := cmp.Diff([]netip.Prefix{infra, src4, alias, src6}, plan.ImportPrefixes, cmpopts.EquateComparable(netip.Prefix{})); diff != "" {
				t.Fatalf("ordinary admission: %s", diff)
			}
			if diff := cmp.Diff([]netip.Prefix{src4, src6}, plan.ImportSources, cmpopts.EquateComparable(netip.Prefix{})); diff != "" {
				t.Fatalf("source admission: %s", diff)
			}
			views := []BabelView{
				{TableID: 20000, ReturnPrefixes: []netip.Prefix{infra, src4, alias, src6}},
				{TableID: 20001, Source: src4, RulePriority: DomainRulePriority, ReturnPrefixes: []netip.Prefix{src4, alias}},
				{TableID: 20001, Source: src6, RulePriority: DomainRulePriority, ReturnPrefixes: []netip.Prefix{infra, src6}},
			}
			if diff := cmp.Diff(views, plan.Views, cmpopts.EquateComparable(netip.Prefix{}, netip.Addr{})); diff != "" {
				t.Fatalf("views: %s", diff)
			}
			origins := []BabelOrigin{
				{Destination: netip.PrefixFrom(desired.LoopbackV6, 128)},
				{Destination: netip.MustParsePrefix("10.100.1.0/24")},
				{Destination: netip.MustParsePrefix("0.0.0.0/0"), Source: src4},
				{Destination: netip.MustParsePrefix("::/0"), Source: src6},
			}
			if diff := cmp.Diff(origins, plan.Origins, cmpopts.EquateComparable(netip.Prefix{}, netip.Addr{}), cmpopts.SortSlices(func(a, b BabelOrigin) bool {
				return a.Destination.String()+a.Source.String() < b.Destination.String()+b.Source.String()
			})); diff != "" {
				t.Fatalf("origins: %s", diff)
			}
			assertRules(t, desired.Rules, []RulePlan{
				{TableID: 20000, Priority: 20000, Destination: netip.MustParsePrefix("fd41::/48")},
				{TableID: 20000, Priority: 20000, Destination: src4},
				{TableID: 20000, Priority: 20000, Destination: netip.MustParsePrefix("10.100.2.0/24")},
				{TableID: 20000, Priority: 20000, Destination: src6},
				{TableID: 20001, Priority: 20001, Source: src4},
				{TableID: 20001, Priority: 20001, Source: netip.MustParsePrefix("10.100.2.0/24")},
				{TableID: 20001, Priority: 20001, Source: src6},
			})
		})
	}
}

func assertRules(t *testing.T, got, want []RulePlan) {
	t.Helper()
	if diff := cmp.Diff(want, got, cmpopts.EquateComparable(netip.Prefix{}, netip.Addr{}), cmpopts.SortSlices(func(a, b RulePlan) bool {
		if a.TableID != b.TableID {
			return a.TableID < b.TableID
		}
		return a.Source.String()+a.Destination.String() < b.Source.String()+b.Destination.String()
	})); diff != "" {
		t.Fatalf("rules (-want +got):\n%s", diff)
	}
}

func TestDomainReturnOwnershipAndFailClosedViews(t *testing.T) {
	value := nodeFixture()
	enabled := true
	value.Babel = &spec.BabelSpec{Enabled: &enabled}
	value.Domains = map[string]spec.DomainSpec{
		"p1": {SourceTableID: 100, SourcePrefixes: []string{"10.100.1.0/24", "10.100.3.0/24"}, StaticRoutes: spec.Routes{"b": {{Prefix: "10.100.3.0/24"}}}, Announcements: []spec.Announcement{{Prefix: "10.100.1.0/24"}, {Prefix: "0.0.0.0/0"}}},
		"p2": {SourceTableID: 101, SourcePrefixes: []string{"10.100.2.0/24"}, Announcements: []spec.Announcement{{Prefix: "10.100.2.0/24"}, {Prefix: "0.0.0.0/0"}}},
	}
	desired, err := BuildDesiredState(value)
	if err != nil {
		t.Fatal(err)
	}
	p1, alias, p2 := netip.MustParsePrefix("10.100.1.0/24"), netip.MustParsePrefix("10.100.3.0/24"), netip.MustParsePrefix("10.100.2.0/24")
	for _, view := range desired.Babel.Views {
		for _, prefix := range view.ReturnPrefixes {
			if view.TableID == 100 && prefix == p2 || view.TableID == 101 && (prefix == p1 || prefix == alias) {
				t.Fatalf("foreign return prefix leaked into view: %#v", view)
			}
		}
	}
	for _, origin := range desired.Babel.Origins {
		if origin.Source == alias {
			t.Fatal("alias published as independent Babel source")
		}
	}
	for _, rule := range desired.Rules {
		if rule.TableID == 100 && rule.Source.IsValid() && rule.Priority != DomainRulePriority {
			t.Fatal("table ID used as rule priority")
		}
	}
	for _, table := range []int{100, 101} {
		guard := false
		for _, route := range desired.Routes {
			if route.TableID == table && route.Prefix.Bits() == 0 && route.Type == RouteUnreachable && route.Metric != nil && *route.Metric > 131070 {
				guard = true
			}
			if route.TableID == table && (table == 100 && route.Prefix == p2 || table == 101 && (route.Prefix == p1 || route.Prefix == alias)) {
				t.Fatalf("foreign static return in Domain table: %#v", route)
			}
		}
		if !guard {
			t.Fatalf("table %d has no persistent no-path guard", table)
		}
	}
	sharedReturn, domainReturn := false, false
	for _, route := range desired.Routes {
		if route.Prefix == alias && route.Type == RouteViaPeer {
			sharedReturn = sharedReturn || route.TableID == 20000
			domainReturn = domainReturn || route.TableID == 100
		}
	}
	if !sharedReturn || !domainReturn {
		t.Fatal("static return missing from public or owning source view")
	}
}
