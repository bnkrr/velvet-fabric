package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
)

func TestAuthenticatedEnvelope(t *testing.T) {
	for _, raw := range []string{"192.0.2.1:51000", "[2001:db8::1]:51000"} {
		t.Run(raw, func(t *testing.T) {
			dst := netip.MustParseAddrPort(raw)
			r, err := NewReceiver([16]byte{1}, time.Now().Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			packet, err := Seal(r.ID, r.Key, 7, 3, dst)
			if err != nil {
				t.Fatal(err)
			}
			plain, _ := message.EndpointValue(dst)
			if bytes.Contains(packet, plain) {
				t.Fatal("plaintext endpoint leaked")
			}
			// Every header, context, ciphertext and tag octet is authenticated or
			// structurally checked. Rejected forgeries must not consume the sequence.
			for i := range packet {
				bad := bytes.Clone(packet)
				bad[i] ^= 1
				if _, ok := r.Open(bad, dst); ok {
					t.Fatalf("accepted mutation at %d", i)
				}
			}
			for n := 0; n < len(packet); n++ {
				if _, ok := r.Open(packet[:n], dst); ok {
					t.Fatal("accepted truncation")
				}
			}
			otherFamily := netip.MustParseAddrPort("[2001:db8::2]:51000")
			if dst.Addr().Is6() {
				otherFamily = netip.MustParseAddrPort("192.0.2.2:51000")
			}
			if _, ok := r.Open(packet, otherFamily); ok {
				t.Fatal("source/destination address family mismatch accepted")
			}
			got, ok := r.Open(packet, dst)
			if !ok || got.Round != 3 || got.Sequence != 7 || got.Destination != dst {
				t.Fatalf("valid packet: %#v %v", got, ok)
			}
			if _, ok = r.Open(packet, dst); ok {
				t.Fatal("replay accepted")
			}
			packet, _ = Seal(r.ID, r.Key, 6, 3, dst)
			if _, ok = r.Open(packet, dst); !ok {
				t.Fatal("out-of-order fresh sequence rejected")
			}
			expired, _ := NewReceiver(r.ID, time.Now().Add(-time.Second))
			expired.Key = r.Key
			expired.aead = r.aead
			if _, ok = expired.Open(packet, dst); ok {
				t.Fatal("expired context accepted")
			}
			wrong, _ := NewReceiver(r.ID, time.Now().Add(time.Minute))
			if _, ok = wrong.Open(packet, dst); ok {
				t.Fatal("wrong key accepted")
			}
			if _, err := Seal(r.ID, r.Key, MaxPackets+1, 1, dst); err == nil {
				t.Fatal("quota not enforced")
			}
		})
	}
}
func TestPublicSocketIsSilent(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			testPublicSocketIsSilent(t, netip.MustParseAddr(host))
		})
	}
}
func testPublicSocketIsSilent(t *testing.T, host netip.Addr) {
	t.Helper()
	network := "udp4"
	if host.Is6() {
		network = "udp6"
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err := NewReceiver([16]byte{2}, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan Received, 8)
	socket, err := Listen(ctx, netip.AddrPortFrom(host, 0), r, func(v Received) { received <- v })
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	sender, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(host, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	good, _ := Seal(r.ID, r.Key, 1, 1, socket.Local)
	wrong := bytes.Clone(good)
	wrong[len(wrong)-1] ^= 1
	hello, _ := message.EncodeDatagram(message.Message{Type: message.DiscoveryHello})
	oversized := append(bytes.Clone(good), make([]byte, 1201-len(good))...)
	binary.BigEndian.PutUint16(oversized[6:8], 1201)
	for _, packet := range [][]byte{[]byte("garbage"), hello, wrong, oversized, good, good} {
		if _, err = sender.WriteToUDPAddrPort(packet, socket.Local); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case v := <-received:
		if v.Seen != sender.LocalAddr().(*net.UDPAddr).AddrPort() || v.Destination != socket.Local {
			t.Fatal("wrong source observation")
		}
	case <-time.After(time.Second):
		t.Fatal("authorized probe missing")
	}
	_ = sender.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buffer := make([]byte, 2048)
	if _, _, err = sender.ReadFromUDP(buffer); err == nil {
		t.Fatal("public listener sent a UDP response")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatal("expected silent read timeout", err)
	}
	select {
	case <-received:
		t.Fatal("invalid or duplicate probe reached collector")
	default:
	}
	cancel()
	socket.Close()
	rebound, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(socket.Local))
	if err != nil {
		t.Fatal("socket not released", err)
	}
	rebound.Close()
}

func FuzzPublicProbeEnvelope(f *testing.F) {
	// Stable test credentials keep saved seeds valid across fuzz workers/runs.
	receiver := &Receiver{ID: [16]byte{7}, Key: [32]byte{19}, until: time.Now().Add(time.Hour)}
	var err error
	receiver.aead, err = newAEAD(receiver.Key)
	if err != nil {
		f.Fatal(err)
	}
	endpoints := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:51000"), netip.MustParseAddrPort("[2001:db8::1]:51000")}
	for _, endpoint := range endpoints {
		packet, err := Seal(receiver.ID, receiver.Key, 1, 1, endpoint)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(packet)
	}
	f.Add([]byte("VFP\x00"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, endpoint := range endpoints {
			r := &Receiver{ID: receiver.ID, Key: receiver.Key, aead: receiver.aead, until: receiver.until}
			v, ok := r.Open(b, endpoint)
			if ok {
				if v.Seen != endpoint || v.Sequence == 0 || v.Sequence > MaxPackets || v.Round > 16 || !v.Destination.IsValid() || v.Destination.Addr().Is6() != endpoint.Addr().Is6() {
					t.Fatal("accepted invalid public probe")
				}
				if _, again := r.Open(b, endpoint); again {
					t.Fatal("accepted replay")
				}
			}
		}
	})
}

// WireGuard takes a wildcard port in both families. An address-specific probe
// must not accept a port already occupied at another address or in IPv6.
func TestProbeReservesWireGuardPortScope(t *testing.T) {
	for _, occupied := range []string{"127.0.0.2", "::1"} {
		t.Run(occupied, func(t *testing.T) {
			host := netip.MustParseAddr(occupied)
			network := "udp4"
			if host.Is6() {
				network = "udp6"
			}
			blocker, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(host, 0)))
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Close()
			port := blocker.LocalAddr().(*net.UDPAddr).AddrPort().Port()
			receiver, err := NewReceiver([16]byte{9}, time.Now().Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			socket, err := Listen(context.Background(), netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), receiver, func(Received) {})
			if err == nil {
				socket.Close()
				t.Fatal("probe accepted a port that WireGuard cannot bind")
			}
		})
	}
}

func TestProbePinsSourceAndRejectsOtherLocalAddresses(t *testing.T) {
	for _, source := range []string{"127.0.0.2", "::1"} {
		t.Run(source, func(t *testing.T) {
			host := netip.MustParseAddr(source)
			peerHost, network := netip.MustParseAddr("127.0.0.1"), "udp4"
			if host.Is6() {
				peerHost, network = host, "udp6"
			}
			peer, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(peerHost, 0)))
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			receiver, err := NewReceiver([16]byte{10}, time.Now().Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			arrivals := make(chan Received, 2)
			socket, err := Listen(context.Background(), netip.AddrPortFrom(host, 0), receiver, func(v Received) { arrivals <- v })
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			remote := peer.LocalAddr().(*net.UDPAddr).AddrPort()
			if err := socket.Send([]byte("source-test"), remote); err != nil {
				t.Fatal(err)
			}
			peer.SetReadDeadline(time.Now().Add(time.Second))
			buffer := make([]byte, 100)
			n, seen, err := peer.ReadFromUDPAddrPort(buffer)
			if err != nil || seen != socket.Local || string(buffer[:n]) != "source-test" {
				t.Fatalf("measurement source changed: seen %v, want %v, error %v", seen, socket.Local, err)
			}
			good, err := Seal(receiver.ID, receiver.Key, 1, 1, socket.Local)
			if err != nil {
				t.Fatal(err)
			}
			if host.Is4() {
				wrong := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.3"), socket.Local.Port())
				if _, err := peer.WriteToUDPAddrPort(good, wrong); err != nil {
					t.Fatal(err)
				}
				select {
				case <-arrivals:
					t.Fatal("accepted a packet addressed to another local IP")
				case <-time.After(100 * time.Millisecond):
				}
			}
			if _, err := peer.WriteToUDPAddrPort(good, socket.Local); err != nil {
				t.Fatal(err)
			}
			select {
			case v := <-arrivals:
				if v.Seen != remote {
					t.Fatal("observed source changed")
				}
			case <-time.After(time.Second):
				t.Fatal("valid path rejected or replay state consumed by wrong path")
			}
			// While listening, neither family nor another local address can take the
			// future WG port; close releases both families for actual WG binding.
			for _, endpoint := range []string{"127.0.0.3", "::1"} {
				ip := netip.MustParseAddr(endpoint)
				network := "udp4"
				if ip.Is6() {
					network = "udp6"
				}
				other, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, socket.Local.Port())))
				if err == nil {
					other.Close()
					t.Fatal("another socket stole the reserved WG port")
				}
			}
			socket.Close()
			for _, network := range []string{"udp4", "udp6"} {
				rebound, err := net.ListenUDP(network, &net.UDPAddr{Port: int(socket.Local.Port())})
				if err != nil {
					t.Fatal("wildcard port not released", err)
				}
				rebound.Close()
			}
		})
	}
}
