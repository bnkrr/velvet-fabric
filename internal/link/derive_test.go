package link

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestBootstrapAgreesAtBothEnds(t *testing.T) {
	a, _ := wgtypes.GeneratePrivateKey()
	b, _ := wgtypes.GeneratePrivateKey()
	psk := bytes.Repeat([]byte{7}, 32)
	aSide, err := DeriveBootstrap(psk, a, b.PublicKey(), spec.NodeUID{Name: "a", UUID: uuid.NewString()}, spec.Peer{Name: "b", PublicKey: b.PublicKey().String()})
	if err != nil {
		t.Fatal(err)
	}
	bSide, err := DeriveBootstrap(psk, b, a.PublicKey(), spec.NodeUID{Name: "b", UUID: uuid.NewString()}, spec.Peer{Name: "a", PublicKey: a.PublicKey().String()})
	if err != nil {
		t.Fatal(err)
	}
	if aSide.PresharedKey != bSide.PresharedKey {
		t.Fatal("per-Link PSKs differ")
	}
	if aSide.LocalAddress.Addr() != bSide.PeerAddress || bSide.LocalAddress.Addr() != aSide.PeerAddress {
		t.Fatal("bootstrap roles disagree")
	}
	if aSide.Dialer == bSide.Dialer {
		t.Fatal("both sides selected the same TCP role")
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
