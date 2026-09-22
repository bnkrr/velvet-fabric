package spec

import "testing"

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
