package reconcile

import (
	"testing"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestBuildDesiredStateContainsLinkAndRoutingState(t *testing.T) {
	local, _ := wgtypes.GeneratePrivateKey()
	peer, _ := wgtypes.GeneratePrivateKey()
	psk, _ := wgtypes.GenerateKey()
	value := &spec.NodeSpec{
		APIVersion: spec.APIVersion, Kind: spec.Kind,
		Fabric: spec.FabricSpec{PSK: psk.String(), LoopbackPrefixV6: "fd41::/48"},
		Node:   spec.Node{UID: spec.NodeUID{Name: "a", UUID: uuid.NewString()}, PrivateKey: local.String()},
		Peers:  []spec.Peer{{Name: "b", PublicKey: peer.PublicKey().String(), Endpoints: []string{"192.0.2.2:51002"}}},
		Routes: spec.Routes{"b": {{Prefix: "fd41::20/128"}}},
		Domains: map[string]spec.DomainSpec{
			"production": {
				TableID:        20001,
				SourcePrefixes: []string{"10.100.1.0/24"},
				Routes:         spec.Routes{"b": {{Prefix: "192.168.20.0/24"}}},
				Exceptions:     []string{"10.100.1.0/24"},
			},
		},
	}
	desired, err := BuildDesiredState(value)
	if err != nil {
		t.Fatal(err)
	}
	if len(desired.Links) != 1 {
		t.Fatal("missing Link plan")
	}
	item := desired.Links[0]
	if item.Keepalive != nil {
		t.Fatal("omitted keepalive became an explicit default")
	}
	if !item.BootstrapAddress.Addr().IsLinkLocalUnicast() {
		t.Fatalf("bootstrap is not link-local: %s", item.BootstrapAddress)
	}
	if desired.LinkPoolV4.IsValid() || desired.LinkPoolV6.IsValid() {
		t.Fatal("omitted Link pools became configured")
	}
	if !desired.LoopbackPoolV6.Contains(desired.LoopbackV6) {
		t.Fatal("IPv6 loopback derivation failed")
	}
	if !desired.Forwarding {
		t.Fatal("routing did not enable forwarding")
	}
	if len(desired.Routes) != 4 {
		t.Fatalf("routes = %#v, want Fabric route, loopback protection, Domain route, and exception", desired.Routes)
	}
	for _, route := range desired.Routes {
		if route.Prefix.String() == "fd41::20/128" && route.Metric != nil {
			t.Fatal("omitted route metric became an explicit default")
		}
	}
	if len(desired.Rules) != 4 {
		t.Fatalf("rules = %#v, want Fabric destination selectors and Domain from/to selectors", desired.Rules)
	}
}
