package spec

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestListenPortsJSON(t *testing.T) {
	for _, raw := range []string{"0", "51001", "[40000,49999]", "[51000,51000]"} {
		var ports ListenPorts
		if err := json.Unmarshal([]byte(raw), &ports); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		encoded, err := json.Marshal(ports)
		if err != nil || string(encoded) != raw {
			t.Fatalf("round trip %s: %s %v", raw, encoded, err)
		}
	}
	for _, raw := range []string{"-1", "65536", "1.5", `"51000"`, "true", "{}", "[]", "[1]", "[1,2,3]", "[0,1]", "[3,2]", "[1,65536]", "[1,2.5]"} {
		var ports ListenPorts
		if err := json.Unmarshal([]byte(raw), &ports); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}

func TestWireGuardPortsExcludeVFP(t *testing.T) {
	for _, vfp := range []int{DefaultVFPPort, 42000} {
		for _, mode := range []string{"dynamic-fixed", "peer-fixed", "dynamic-only-range", "peer-only-range", "range-includes", "system"} {
			t.Run(mode+"/"+strconv.Itoa(vfp), func(t *testing.T) {
				s := validSpec(t)
				s.Fabric.VFPPort = &vfp
				s.DynamicLinks = &DynamicLinksSpec{Mode: DynamicLinksOff}
				switch mode {
				case "dynamic-fixed":
					s.DynamicLinks.ListenPorts = &ListenPorts{Port: vfp}
				case "peer-fixed":
					s.Peers[0].ListenPorts = &ListenPorts{Port: vfp}
				case "dynamic-only-range":
					s.DynamicLinks.ListenPorts = &ListenPorts{Range: PortRange{vfp, vfp}}
				case "peer-only-range":
					s.Peers[0].ListenPorts = &ListenPorts{Range: PortRange{vfp, vfp}}
				case "range-includes":
					s.DynamicLinks.ListenPorts = &ListenPorts{Range: PortRange{vfp - 1, vfp + 1}}
				}
				err := s.Validate()
				valid := mode == "range-includes" || mode == "system"
				if valid && err != nil || !valid && (err == nil || !strings.Contains(err.Error(), "fabric.vfp_port")) {
					t.Fatalf("valid=%v: %v", valid, err)
				}
			})
		}
	}
}

func TestStaticAndDynamicPortsAreIndependent(t *testing.T) {
	s := validSpec(t)
	s.DynamicLinks = &DynamicLinksSpec{Mode: DynamicLinksOff, ListenPorts: &ListenPorts{Range: PortRange{40000, 49999}}}
	s.Peers[0].Endpoints = nil
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.PeerPorts(s.Peers[0]) != (PortChoice{}) {
		t.Fatal("static peer inherited dynamic port range")
	}
	s.Peers[0].ListenPorts = &ListenPorts{Port: 51000}
	if s.PeerPorts(s.Peers[0]).Port != 51000 || s.DynamicPorts().Range.First != 40000 {
		t.Fatal("independent port choice lost")
	}
}
