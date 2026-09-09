package babel

import (
	"net/netip"
	"path/filepath"
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
		"shutdown_timeout_ms = 5000\n\n[[interfaces]]",
		"[[interfaces]]\nmatch = [\"vl-a-b\", \"vl-a-c\"]\nlink_type = \"wired\"",
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

func TestOnlyCommittedDynamicLinksEnterManagedRouting(t *testing.T) {
	dir := t.TempDir()
	manager := New(&reconcile.BabelPlan{ConfigPath: filepath.Join(dir, "babel.toml"), StatePath: filepath.Join(dir, "state"), Interfaces: []string{"vl-*"}}, nil)
	render := func() string {
		t.Helper()
		data, _, err := manager.prepare()
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	if strings.Contains(render(), "vdl-") {
		t.Fatal("tentative dynamic interfaces admitted by default")
	}
	// A default unnumbered Link has no ordinary origin. Its committed interface
	// must still enter routing; filtering link-local origins must not erase it.
	manager.SetLinkState("vdl-second", true, []netip.Prefix{netip.MustParsePrefix("fe80::2/64")})
	manager.SetLinkState("vdl-first", true, nil)
	committed := render()
	if !strings.Contains(committed, `match = ["vl-*", "vdl-first", "vdl-second"]`) || strings.Contains(committed, "fe80::") {
		t.Fatalf("committed link-local routing set incorrect:\n%s", committed)
	}
	manager.SetLinkState("vdl-first", true, nil)
	if render() != committed {
		t.Fatal("idempotent commit changed routing config")
	}
	manager.SetLinkState("vdl-first", false, nil)
	withdrawn := render()
	if strings.Contains(withdrawn, "vdl-first") || !strings.Contains(withdrawn, "vdl-second") {
		t.Fatal("withdrawal removed wrong committed interface")
	}
	manager.SetLinkState("vdl-second", false, nil)
	if strings.Contains(render(), "vdl-") {
		t.Fatal("withdrawn dynamic Link retained in routing")
	}
}
