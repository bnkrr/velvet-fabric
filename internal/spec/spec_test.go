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
