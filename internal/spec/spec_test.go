package spec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestLoadGeneratesAndAtomicallyPersistsUUID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.json")
	value := validSpec(t)
	value.Node.UID.UUID = ""
	writeJSON(t, path, value)
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
}

func TestLoadRejectsRemoteIdentityAndKeyFileFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.json")
	value := validSpec(t)
	data, _ := json.Marshal(value)
	var raw map[string]any
	_ = json.Unmarshal(data, &raw)
	peer := raw["peers"].([]any)[0].(map[string]any)
	peer["uuid"] = uuid.NewString()
	node := raw["node"].(map[string]any)
	node["private_key_file"] = "/tmp/key"
	writeJSON(t, path, raw)
	if _, err := Load(path); err == nil {
		t.Fatal("removed schema fields were accepted")
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

func TestRouteExpandedFormRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.json")
	value := validSpec(t)
	data, _ := json.Marshal(value)
	var raw map[string]any
	_ = json.Unmarshal(data, &raw)
	raw["fabric"].(map[string]any)["routes"] = map[string]any{"b": []any{map[string]any{"prefix": "fd41::20/128", "weight": 10}}}
	writeJSON(t, path, raw)
	if _, err := Load(path); err == nil {
		t.Fatal("unknown expanded route field was accepted")
	}
}

func TestValidationChecksRoutingOwnershipAndDomains(t *testing.T) {
	value := validSpec(t)
	metric := uint32(10)
	value.Fabric.Routes = Routes{"missing": {{Prefix: "fd41::20/128"}}}
	value.Domains = map[string]DomainSpec{
		"one": {
			TableID:        DefaultRoutingTableID,
			SourcePrefixes: []string{"10.10.0.0/16"},
			Routes:         Routes{"b": {{Prefix: "192.0.2.0/24", Metric: &metric}}},
			Announcements:  []Announcement{{Prefix: "192.0.2.0/24"}},
		},
		"two": {TableID: 20002, SourcePrefixes: []string{"10.10.1.0/24"}},
	}
	if err := value.Validate(); err == nil {
		t.Fatal("invalid route ownership, duplicate table, overlapping domains, and conflicting announcement were accepted")
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

func TestAnnouncementAcceptsScalarAndExpandedForms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.json")
	value := validSpec(t)
	data, _ := json.Marshal(value)
	var raw map[string]any
	_ = json.Unmarshal(data, &raw)
	raw["fabric"].(map[string]any)["announcements"] = []any{
		"fd30::/64",
		map[string]any{"prefix": "198.51.100.0/24", "metric": 20},
	}
	writeJSON(t, path, raw)
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Fabric.Announcements; len(got) != 2 || got[0].Metric != nil || got[1].Metric == nil || *got[1].Metric != 20 {
		t.Fatalf("decoded announcements = %#v", got)
	}
}

func TestAnnouncementsRequireLocalOwnershipAndDomainFamily(t *testing.T) {
	value := validSpec(t)
	value.Fabric.Routes = Routes{"b": {{Prefix: "fd30::/64"}}}
	value.Fabric.Announcements = []Announcement{{Prefix: "fd30::/64"}}
	value.Domains = map[string]DomainSpec{
		"production": {
			TableID:        20001,
			SourcePrefixes: []string{"10.100.1.0/24"},
			Announcements:  []Announcement{{Prefix: "fd40::/64"}},
		},
	}
	if err := value.Validate(); err == nil {
		t.Fatal("conflicting Fabric ownership and family-less Domain announcement were accepted")
	}
}

func TestBabelSectionRequiresEnabledAndAbsoluteExecutable(t *testing.T) {
	value := validSpec(t)
	value.Babel = &BabelSpec{Executable: "babel-rs"}
	if err := value.Validate(); err == nil {
		t.Fatal("babel section without enabled and with relative executable was accepted")
	}
	enabled := true
	value.Babel = &BabelSpec{Enabled: &enabled, Executable: "/usr/local/bin/babel-rs"}
	if err := value.Validate(); err != nil {
		t.Fatalf("valid Babel section rejected: %v", err)
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
