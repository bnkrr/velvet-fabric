package spec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/google/uuid"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestLoadGeneratesAndAtomicallyPersistsUUID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.json")
	value := validSpec(t)
	value.Node.UID.UUID = ""
	writeJSON(t, path, value)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if uuid.MustParse(loaded.Node.UID.UUID) == uuid.Nil {
		t.Fatal("UUID was not generated")
	}
	loadedAgain, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loadedAgain.Node.UID.UUID != loaded.Node.UID.UUID {
		t.Fatal("persisted UUID changed")
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	a, b := before.Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t)
	if before.Mode().Perm() != after.Mode().Perm() || a.Uid != b.Uid || a.Gid != b.Gid {
		t.Fatal("UUID rewrite changed permissions or ownership")
	}
}

func TestLoadRejectsInsecurePermissionsAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.json")
	writeJSON(t, path, validSpec(t))
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("group-readable config was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "node-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); err == nil {
		t.Fatal("symlink config was accepted")
	}
}

func TestLoadRejectsRemoteIdentityAndKeyFileFields(t *testing.T) {
	for _, field := range []string{"uuid", "private_key_file"} {
		t.Run(field, func(t *testing.T) {
			data, err := json.Marshal(validSpec(t))
			if err != nil {
				t.Fatal(err)
			}
			var raw map[string]any
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatal(err)
			}
			if field == "uuid" {
				raw["peers"].([]any)[0].(map[string]any)[field] = uuid.NewString()
			} else {
				raw["node"].(map[string]any)[field] = "/tmp/key"
			}
			path := filepath.Join(t.TempDir(), "node.json")
			writeJSON(t, path, raw)
			if _, err := Load(path); err == nil || !strings.Contains(err.Error(), field) {
				t.Fatalf("Load = %v, want rejected %s", err, field)
			}
		})
	}
}

func TestValidationRequiresCanonicalLinkOverrides(t *testing.T) {
	value := validSpec(t)
	value.Fabric.LinkPrefixV4 = "10.40.0.0/16"
	value.Peers[0].LinkAddresses = []string{"10.40.0.1/30"}
	if err := value.Validate(); err == nil {
		t.Fatal("host bits were accepted")
	}
	value.Peers[0].LinkAddresses = []string{"10.40.0.0/30", "10.40.0.4/30"}
	if err := value.Validate(); err == nil {
		t.Fatal("duplicate address family was accepted")
	}
}

func TestLinkOverrideRequiresCorrespondingOptionalPool(t *testing.T) {
	value := validSpec(t)
	value.Peers[0].LinkAddresses = []string{"10.40.0.0/30"}
	if err := value.Validate(); err == nil {
		t.Fatal("IPv4 Link override without an IPv4 pool was accepted")
	}
	value.Fabric.LinkPrefixV4 = "10.40.0.0/16"
	if err := value.Validate(); err != nil {
		t.Fatalf("override inside configured pool was rejected: %v", err)
	}
}

func TestRouteAcceptsScalarAndExpandedForms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.json")
	value := validSpec(t)
	value.Node.UID.UUID = ""
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	fabric := raw["fabric"].(map[string]any)
	fabric["routes"] = map[string]any{
		"b": []any{"fd41::20/128", map[string]any{"prefix": "fd41::21/128", "metric": 10}},
	}
	writeJSON(t, path, raw)
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Fabric.Routes["b"]; len(got) != 2 || got[0].Prefix != "fd41::20/128" || got[0].Metric != nil || got[1].Metric == nil || *got[1].Metric != 10 {
		t.Fatalf("decoded routes = %#v", got)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip map[string]any
	if err := json.Unmarshal(persisted, &roundTrip); err != nil {
		t.Fatal(err)
	}
	items := roundTrip["fabric"].(map[string]any)["routes"].(map[string]any)["b"].([]any)
	if _, ok := items[0].(string); !ok {
		t.Fatalf("route shorthand was not preserved: %#v", items[0])
	}
	if _, ok := items[1].(map[string]any); !ok {
		t.Fatalf("expanded route was not preserved: %#v", items[1])
	}
}

func TestRouteAndAnnouncementJSON(t *testing.T) {
	for _, kind := range []string{"route", "announcement"} {
		t.Run(kind, func(t *testing.T) {
			for _, raw := range []string{`"192.0.2.0/24"`, `{"prefix":"192.0.2.0/24","metric":20}`, `{"prefix":"192.0.2.0/24","weight":20}`} {
				var prefix string
				var metric *uint32
				var err error
				if kind == "route" {
					var v Route
					err = json.Unmarshal([]byte(raw), &v)
					prefix, metric = v.Prefix, v.Metric
				} else {
					var v Announcement
					err = json.Unmarshal([]byte(raw), &v)
					prefix, metric = v.Prefix, v.Metric
				}
				if strings.Contains(raw, "weight") {
					if err == nil {
						t.Fatal("unknown field accepted")
					}
					continue
				}
				if err != nil || prefix != "192.0.2.0/24" || (metric != nil) != strings.Contains(raw, "metric") || metric != nil && *metric != 20 {
					t.Fatalf("decode %s: %s %v %v", raw, prefix, metric, err)
				}
			}
		})
	}
}

func TestValidationAcceptsStaticCoreRouting(t *testing.T) {
	value := validSpec(t)
	tableID := 21000
	value.Fabric.RoutingTableID = &tableID
	value.Fabric.Routes = Routes{"b": {{Prefix: "fd41::20/128"}}}
	value.Domains = map[string]DomainSpec{
		"production": {
			TableID:        21001,
			SourcePrefixes: []string{"10.100.1.0/24", "fd10:100:1::/64"},
			Routes:         Routes{"b": {{Prefix: "192.168.20.0/24"}}},
			Announcements:  []Announcement{{Prefix: "0.0.0.0/0"}},
		},
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("valid static Core routing was rejected: %v", err)
	}
}

func TestValidationRejectsEachInvalidConstraint(t *testing.T) {
	enabled := true
	for _, tc := range []struct {
		name, want string
		change     func(*NodeSpec)
	}{
		{"unknown-peer", "unknown peer", func(s *NodeSpec) { s.Fabric.Routes = Routes{"missing": {{Prefix: "fd41::20/128"}}} }},
		{"fabric-table-conflict", "greater than", func(s *NodeSpec) { d := s.Domains["one"]; d.TableID = DefaultRoutingTableID; s.Domains["one"] = d }},
		{"table-before-fabric", "greater than", func(s *NodeSpec) { d := s.Domains["one"]; d.TableID = 19000; s.Domains["one"] = d }},
		{"duplicate-domain-table", "duplicates", func(s *NodeSpec) {
			s.Domains["two"] = DomainSpec{TableID: 20001, SourcePrefixes: []string{"10.20.0.0/16"}}
		}},
		{"overlapping-sources", "overlaps", func(s *NodeSpec) {
			s.Domains["two"] = DomainSpec{TableID: 20002, SourcePrefixes: []string{"10.10.1.0/24"}}
		}},
		{"domain-route-announcement", "conflicts", func(s *NodeSpec) {
			d := s.Domains["one"]
			d.Routes = Routes{"b": {{Prefix: "192.0.2.0/24"}}}
			d.Announcements = []Announcement{{Prefix: "192.0.2.0/24"}}
			s.Domains["one"] = d
		}},
		{"fabric-route-announcement", "conflicts", func(s *NodeSpec) {
			s.Fabric.Routes = Routes{"b": {{Prefix: "fd30::/64"}}}
			s.Fabric.Announcements = []Announcement{{Prefix: "fd30::/64"}}
		}},
		{"announcement-family", "same-family", func(s *NodeSpec) {
			d := s.Domains["one"]
			d.Announcements = []Announcement{{Prefix: "fd40::/64"}}
			s.Domains["one"] = d
		}},
		{"babel-enabled-missing", "babel.enabled", func(s *NodeSpec) { s.Babel = &BabelSpec{Executable: "/usr/bin/babel-rs"} }},
		{"babel-relative-path", "absolute", func(s *NodeSpec) { s.Babel = &BabelSpec{Enabled: &enabled, Executable: "babel-rs"} }},
		{"dynamic-mode-missing", "mode is required", func(s *NodeSpec) { s.DynamicLinks = &DynamicLinksSpec{} }},
		{"dynamic-mode-unknown", "mode must be", func(s *NodeSpec) {
			s.DynamicLinks = &DynamicLinksSpec{Mode: "automatic", AllowCandidatePrefixes: []string{"192.0.2.0/24"}}
		}},
		{"dynamic-empty-allowlist", "must not be empty", func(s *NodeSpec) { s.DynamicLinks = &DynamicLinksSpec{Mode: DynamicLinksActive} }},
		{"dynamic-host-bits", "canonical", func(s *NodeSpec) {
			s.DynamicLinks = &DynamicLinksSpec{Mode: DynamicLinksActive, AllowCandidatePrefixes: []string{"192.0.2.1/24"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := validSpec(t)
			s.Domains = map[string]DomainSpec{"one": {TableID: 20001, SourcePrefixes: []string{"10.10.0.0/16"}}}
			if err := s.Validate(); err != nil {
				t.Fatal(err)
			}
			tc.change(&s)
			if err := s.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestDynamicLinksModes(t *testing.T) {
	for _, mode := range []string{DynamicLinksActive, DynamicLinksPassive, DynamicLinksOff} {
		t.Run(mode, func(t *testing.T) {
			s := validSpec(t)
			s.DynamicLinks = &DynamicLinksSpec{Mode: mode}
			if mode != DynamicLinksOff {
				s.DynamicLinks.AllowCandidatePrefixes = []string{"0.0.0.0/0", "::/0"}
			}
			enabled := true
			s.Babel = &BabelSpec{Enabled: &enabled, Executable: "/usr/bin/babel-rs"}
			if err := s.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDynamicInterfaceName(t *testing.T) {
	withName := NodeUID{Name: "srv1", UUID: "a13f0000-0000-4000-8000-000000000001"}
	if got := DynamicInterfaceName(withName); got != "vdl-srv1-a13f" {
		t.Fatalf("dynamic interface name = %q", got)
	}
	withName.Name = ""
	if got := DynamicInterfaceName(withName); got != "vdl-a13f" {
		t.Fatalf("unnamed dynamic interface name = %q", got)
	}
}

func validSpec(t *testing.T) NodeSpec {
	t.Helper()
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return NodeSpec{
		APIVersion: APIVersion, Kind: Kind,
		Fabric: FabricSpec{PSK: privateKey.String(), LoopbackPrefixV6: "fd41::/48"},
		Node:   Node{UID: NodeUID{Name: "alpha", UUID: uuid.NewString()}, PrivateKey: privateKey.String()},
		Peers:  []Peer{{Name: "b", PublicKey: peerKey.PublicKey().String(), Endpoints: []string{"192.0.2.2:51002"}}},
	}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
