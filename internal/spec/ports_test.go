package spec

import (
	"strconv"
	"strings"
	"testing"
)

func TestWireGuardPortsExcludeVFP(t *testing.T) {
	for _, vfp := range []int{DefaultVFPPort, 42000} {
		for _, mode := range []string{"node-fixed", "peer-fixed", "node-only-range", "peer-only-range", "range-includes", "system"} {
			t.Run(mode+"/"+strconv.Itoa(vfp), func(t *testing.T) {
				s := validSpec(t)
				s.Fabric.VFPPort = &vfp
				s.Node.ListenPort = nil
				s.Peers[0].ListenPort = nil
				switch mode {
				case "node-fixed":
					s.Node.ListenPort = &vfp
				case "peer-fixed":
					s.Peers[0].ListenPort = &vfp
				case "node-only-range":
					s.Node.PortRange = &PortRange{First: vfp, Last: vfp}
				case "peer-only-range":
					s.Peers[0].PortRange = &PortRange{First: vfp, Last: vfp}
				case "range-includes":
					s.Node.PortRange = &PortRange{First: vfp - 1, Last: vfp + 1}
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

func TestPortModesAndReceiveOnlyStatic(t *testing.T) {
	s := validSpec(t)
	zero, fixed := 0, 42000
	s.Node.PortRange = &PortRange{First: 40000, Last: 49999}
	s.Peers[0].Endpoints = nil
	s.Peers[0].ListenPort = nil
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.PeerPorts(s.Peers[0]).Range.First != 40000 {
		t.Fatal("range not inherited")
	}
	s.Peers[0].ListenPort = &zero
	if s.PeerPorts(s.Peers[0]) != (PortChoice{}) {
		t.Fatal("explicit zero did not override inherited range")
	}
	s.Peers[0].ListenPort = &fixed
	if s.PeerPorts(s.Peers[0]).Port != fixed {
		t.Fatal("explicit fixed port not applied")
	}
	s.Peers[0].PortRange = &PortRange{First: 1, Last: 2}
	if err := s.Validate(); err == nil {
		t.Fatal("same-level port/range combination accepted")
	}
	for _, span := range []PortRange{{0, 10}, {10, 9}, {1, 65536}} {
		if ValidatePorts(nil, &span) == nil {
			t.Fatal("invalid range accepted")
		}
	}
	if ChoosePorts(nil, nil) != (PortChoice{}) {
		t.Fatal("implicit default range")
	}
}
