package policy

import (
	"net"
	"net/netip"
	"testing"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
	"golang.org/x/net/ipv6"
)

func TestPolicyDatagramIngressIsolation(t *testing.T) {
	local, remote := netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
	s := &Socket{local: local, pool: netip.MustParsePrefix("fd00::/64"), port: 58420, ingress: func(index int) bool { return index == 7 }}
	packet, _ := message.EncodeDatagram(message.Message{Type: message.PolicyQuery, UID: &message.UID{UUID: uuid.New()}})
	for _, scenario := range []string{"valid", "underlay", "wrong-destination", "outside-pool", "link-local", "self", "wrong-port", "no-metadata", "discovery", "tcp-message", "oversize", "truncated"} {
		t.Run(scenario, func(t *testing.T) {
			control := &ipv6.ControlMessage{Dst: net.IP(local.AsSlice()), IfIndex: 7}
			source := &net.UDPAddr{IP: net.IP(remote.AsSlice()), Port: 58420}
			b := append([]byte(nil), packet...)
			switch scenario {
			case "underlay":
				control.IfIndex = 8
			case "wrong-destination":
				control.Dst = net.ParseIP("fd00::3")
			case "outside-pool":
				source.IP = net.ParseIP("2001:db8::2")
			case "link-local":
				source.IP = net.ParseIP("fe80::2")
			case "self":
				source.IP = net.IP(local.AsSlice())
			case "wrong-port":
				source.Port++
			case "no-metadata":
				control = nil
			case "discovery":
				b, _ = message.EncodeDatagram(message.Message{Type: message.DiscoveryHello})
			case "tcp-message":
				b, _ = message.Encode(message.Message{Type: message.DynamicLinkDecline})
			case "oversize":
				b = append(b, make([]byte, 1201)...)
			case "truncated":
				b = b[:len(b)-1]
			}
			addr, _, ok := s.decode(b, control, source)
			if ok != (scenario == "valid") || (ok && addr != remote) {
				t.Fatalf("isolation failed: %v %v", addr, ok)
			}
		})
	}
}
