package inference

import (
	"net/netip"
	"testing"
)

func TestEvidenceRecordsCompleteObservedMapping(t *testing.T) {
	evidence, err := NewEvidence("vl-a", 51001, netip.MustParseAddrPort("203.0.113.8:62001"))
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Link != "vl-a" || evidence.LocalListenPort != 51001 || evidence.ObservedEndpoint != netip.MustParseAddrPort("203.0.113.8:62001") {
		t.Fatalf("evidence = %#v", evidence)
	}
}

func TestNewEvidenceRejectsIncompleteMapping(t *testing.T) {
	valid := netip.MustParseAddrPort("203.0.113.8:62001")
	for _, test := range []struct {
		link string
		port int
		seen netip.AddrPort
	}{
		{port: 51001, seen: valid},
		{link: "vl-a", seen: valid},
		{link: "vl-a", port: 65536, seen: valid},
		{link: "vl-a", port: 51001},
		{link: "vl-a", port: 51001, seen: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.8"), 0)},
	} {
		if _, err := NewEvidence(test.link, test.port, test.seen); err == nil {
			t.Fatalf("accepted incomplete evidence: %#v", test)
		}
	}
}

func TestBaselineUsesFirstObservedIPAndTentativePort(t *testing.T) {
	first, _ := NewEvidence("vl-a", 51001, netip.MustParseAddrPort("203.0.113.8:62001"))
	second, _ := NewEvidence("vl-b", 51002, netip.MustParseAddrPort("198.51.100.9:62002"))
	candidate, ok := Baseline([]Evidence{first, second}, 53000)
	if !ok || candidate != netip.MustParseAddrPort("203.0.113.8:53000") {
		t.Fatalf("candidate = %s, %v", candidate, ok)
	}
	if _, ok := Baseline(nil, 53000); ok {
		t.Fatal("inferred a Candidate without Evidence")
	}
	if _, ok := Baseline([]Evidence{first}, 0); ok {
		t.Fatal("inferred a Candidate without an allocated listen port")
	}
	if _, ok := Baseline([]Evidence{{Link: "vl-a", ObservedEndpoint: first.ObservedEndpoint}}, 53000); ok {
		t.Fatal("inferred a Candidate from Evidence without its local listen port")
	}
}
