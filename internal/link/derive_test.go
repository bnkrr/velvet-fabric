package link

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestBootstrapDerivesLocalOnlyAddressesAndSharedPSK(t *testing.T) {
	a, _ := wgtypes.GeneratePrivateKey()
	b, _ := wgtypes.GeneratePrivateKey()
	psk := bytes.Repeat([]byte{7}, 32)
	aUID, bUID := uuid.New(), uuid.New()
	aSide, err := DeriveBootstrap(psk, a, b.PublicKey(), spec.NodeUID{Name: "a", UUID: aUID.String()}, spec.Peer{Name: "b", PublicKey: b.PublicKey().String()})
	if err != nil {
		t.Fatal(err)
	}
	bSide, err := DeriveBootstrap(psk, b, a.PublicKey(), spec.NodeUID{Name: "b", UUID: bUID.String()}, spec.Peer{Name: "a", PublicKey: a.PublicKey().String()})
	if err != nil {
		t.Fatal(err)
	}
	if aSide.PresharedKey != bSide.PresharedKey {
		t.Fatal("per-Link PSKs differ")
	}
	if aSide.LocalAddress != DeriveLinkLocal(psk, aUID, aSide.InterfaceName) || bSide.LocalAddress != DeriveLinkLocal(psk, bUID, bSide.InterfaceName) {
		t.Fatal("bootstrap address depends on remote state")
	}
	if aSide.LocalAddress == bSide.LocalAddress {
		t.Fatal("different Node UUIDs produced the same test address")
	}
}

func TestLinkLocalIsUniquePerLocalInterface(t *testing.T) {
	psk, uid := bytes.Repeat([]byte{3}, 32), uuid.New()
	a := DeriveLinkLocal(psk, uid, "vl-a-b")
	b := DeriveLinkLocal(psk, uid, "vl-a-c")
	if a == b {
		t.Fatal("different local interfaces share a control address")
	}
	if !a.Addr().IsLinkLocalUnicast() || !b.Addr().IsLinkLocalUnicast() {
		t.Fatalf("derived addresses are not link-local: %s %s", a, b)
	}
}

func TestLinkLocalFixedVector(t *testing.T) {
	uid := uuid.MustParse("10000000-0000-4000-8000-000000000001")
	got := DeriveLinkLocal(bytes.Repeat([]byte{3}, 32), uid, "vl-a-b")
	want := netip.MustParsePrefix("fe80::ca74:207a:39ca:6942/64")
	if got != want {
		t.Fatalf("DeriveLinkLocal() = %s, want %s", got, want)
	}
}

func TestProposalAndEndpointRolesAgree(t *testing.T) {
	psk := bytes.Repeat([]byte{8}, 32)
	a, b := uuid.New(), uuid.New()
	p, err := DeriveProposal(psk, a, b, netip.MustParsePrefix("10.40.0.0/16"), netip.MustParsePrefix("fd40::/48"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	q, _ := DeriveProposal(psk, b, a, netip.MustParsePrefix("10.40.0.0/16"), netip.MustParsePrefix("fd40::/48"), nil, 0)
	if p != q {
		t.Fatalf("proposals differ: %v %v", p, q)
	}
	aLocal, aPeer := EndpointAddresses(p, a, b)
	bLocal, bPeer := EndpointAddresses(p, b, a)
	for i := range aLocal {
		if aLocal[i].Addr() != bPeer[i] || bLocal[i].Addr() != aPeer[i] {
			t.Fatal("endpoint address roles disagree")
		}
	}
}

func TestLinkPSKUsesWireGuardKeysNotNodeUID(t *testing.T) {
	a, _ := wgtypes.GeneratePrivateKey()
	b, _ := wgtypes.GeneratePrivateKey()
	psk := bytes.Repeat([]byte{9}, 32)
	one, _ := DeriveBootstrap(psk, a, b.PublicKey(), spec.NodeUID{Name: "a", UUID: uuid.NewString()}, spec.Peer{Name: "x", PublicKey: b.PublicKey().String()})
	two, _ := DeriveBootstrap(psk, a, b.PublicKey(), spec.NodeUID{Name: "z", UUID: uuid.NewString()}, spec.Peer{Name: "y", PublicKey: b.PublicKey().String()})
	if one.PresharedKey != two.PresharedKey {
		t.Fatal("Node names or UUIDs affected WG link PSK")
	}
}

func TestExplicitAddressIsAnAcceptanceConstraint(t *testing.T) {
	p := Proposal{V4: netip.MustParsePrefix("10.40.0.0/30"), V6: netip.MustParsePrefix("fd40::/126")}
	if !MatchesOverrides(p, []string{"10.40.0.0/30"}) {
		t.Fatal("matching override was refused")
	}
	if MatchesOverrides(p, []string{"10.40.0.4/30"}) {
		t.Fatal("different override was accepted")
	}
}

func TestOmittedLinkPoolsProduceEmptyProposal(t *testing.T) {
	p, err := DeriveProposal(bytes.Repeat([]byte{4}, 32), uuid.New(), uuid.New(), netip.Prefix{}, netip.Prefix{}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Empty() {
		t.Fatalf("proposal is numbered without Link pools: %#v", p)
	}
}

func TestLinkPoolsAreIndependent(t *testing.T) {
	psk, a, b := bytes.Repeat([]byte{5}, 32), uuid.New(), uuid.New()
	v4, err := DeriveProposal(psk, a, b, netip.MustParsePrefix("10.40.0.0/16"), netip.Prefix{}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !v4.V4.IsValid() || v4.V6.IsValid() {
		t.Fatalf("IPv4-only pool produced %#v", v4)
	}
	v6, err := DeriveProposal(psk, a, b, netip.Prefix{}, netip.MustParsePrefix("fd40::/48"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if v6.V4.IsValid() || !v6.V6.IsValid() {
		t.Fatalf("IPv6-only pool produced %#v", v6)
	}
}
