package reconcile

import (
	"testing"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestBuildPlanContainsOnlyBootstrapLinkState(t *testing.T) {
	local, _ := wgtypes.GeneratePrivateKey()
	peer, _ := wgtypes.GeneratePrivateKey()
	psk, _ := wgtypes.GenerateKey()
	value := &spec.NodeSpec{
		APIVersion: spec.APIVersion, Kind: spec.Kind,
		Fabric: spec.FabricSpec{PSK: psk.String(), LoopbackPrefixV6: "fd41::/48"},
		Node:   spec.Node{UID: spec.NodeUID{Name: "a", UUID: uuid.NewString()}, PrivateKey: local.String()},
		Peers:  []spec.Peer{{Name: "b", PublicKey: peer.PublicKey().String(), Endpoints: []string{"192.0.2.2:51002"}}},
	}
	plan, err := BuildPlan(value)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Links) != 1 {
		t.Fatal("missing Link plan")
	}
	item := plan.Links[0]
	if !item.BootstrapAddress.Addr().IsLinkLocalUnicast() {
		t.Fatalf("bootstrap is not link-local: %s", item.BootstrapAddress)
	}
	if plan.LinkPoolV4.IsValid() || plan.LinkPoolV6.IsValid() {
		t.Fatal("omitted Link pools became configured")
	}
	if !plan.LoopbackPoolV6.Contains(plan.LoopbackV6) {
		t.Fatal("IPv6 loopback derivation failed")
	}
}
