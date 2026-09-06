package inference

import (
	"net/netip"
	"testing"
)

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

func TestBaselineCandidates(t *testing.T) {
	for _, tc := range []struct {
		name     string
		observed string
		port     int
		want     string
	}{
		{"ipv4", "203.0.113.8:62001", 53000, "203.0.113.8:53000"},
		{"ipv6", "[2001:db8::8]:62001", 53000, "[2001:db8::8]:53000"},
		{"zero-port", "203.0.113.8:62001", 0, ""},
		{"overflow-port", "203.0.113.8:62001", 65536, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first, err := NewEvidence("vl-a", 51001, netip.MustParseAddrPort(tc.observed))
			if err != nil {
				t.Fatal(err)
			}
			second, err := NewEvidence("vl-b", 51002, netip.MustParseAddrPort("198.51.100.9:62002"))
			if err != nil {
				t.Fatal(err)
			}
			got, ok := Baseline([]Evidence{first, second}, tc.port)
			if tc.want == "" {
				if ok {
					t.Fatal("invalid port accepted")
				}
				return
			}
			if !ok || got != netip.MustParseAddrPort(tc.want) {
				t.Fatalf("Candidate=%v,%v; want %s", got, ok, tc.want)
			}
		})
	}
	for _, evidence := range [][]Evidence{nil, {{Link: "incomplete", ObservedEndpoint: netip.MustParseAddrPort("203.0.113.8:62001")}}} {
		if _, ok := Baseline(evidence, 53000); ok {
			t.Fatal("inferred Candidate without complete Evidence")
		}
	}
}
