package babel

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
)

func TestRenderManagedConfig(t *testing.T) {
	plan := &reconcile.BabelPlan{
		StatePath: "/tmp/state", Interfaces: []string{"vl-a-b", "vl-a-c"},
		Protocol: 203, DeviceOnly: true, ManageRules: false,
		Origins: []reconcile.BabelOrigin{{Destination: netip.MustParsePrefix("fd78::1/128")}},
		Views: []reconcile.BabelView{
			{TableID: 20000},
			{TableID: 20001, Source: netip.MustParsePrefix("10.0.0.0/8"), RulePriority: 20001},
		},
	}
	data := string(Render(plan, map[string][]netip.Prefix{
		"vl-a-b": {netip.MustParsePrefix("10.240.0.1/30"), netip.MustParsePrefix("fe80::1/64")},
	}))
	for _, expected := range []string{
		`interfaces = ["vl-a-b", "vl-a-c"]`,
		`destination = "10.240.0.0/30"`,
		`destination = "fd78::1/128"`,
		"manage_rules = false",
		"table = 20001",
		`source = "10.0.0.0/8"`,
		"rule_priority = 20001",
	} {
		if !strings.Contains(data, expected) {
			t.Fatalf("rendered config missing %q:\n%s", expected, data)
		}
	}
	if strings.Contains(data, "fe80::") {
		t.Fatalf("link-local prefix must not be originated:\n%s", data)
	}
}
