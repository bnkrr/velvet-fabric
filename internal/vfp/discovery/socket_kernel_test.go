//go:build linux

package discovery

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/policy"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func discoveryMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func discoveryNamespace(t *testing.T) {
	t.Helper()
	if os.Getenv("VELVET_KERNEL_DISCOVERY_TEST") != "1" {
		t.Skip("requires explicit disposable-netns opt-in")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	discoveryMust(t, err)
	init, err := os.Readlink("/proc/1/ns/net")
	discoveryMust(t, err)
	if self == init {
		t.Fatal("refusing the host network namespace")
	}
	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)
	lo, err := netlink.LinkByName("lo")
	discoveryMust(t, err)
	discoveryMust(t, netlink.LinkSetUp(lo))
}

func discoveryAddress(t *testing.T, link netlink.Link, address string) {
	t.Helper()
	a, err := netlink.ParseAddr(address)
	discoveryMust(t, err)
	a.Flags = unix.IFA_F_NODAD
	discoveryMust(t, netlink.AddrAdd(link, a))
}

// Force the exact temporary-socket -> WG window from Durable restoration.
// The old Discovery sender takes the only free ephemeral port deterministically.
func TestKernelDiscoveryPortHandoff(t *testing.T) {
	discoveryNamespace(t)
	c, err := wgctrl.New()
	discoveryMust(t, err)
	defer c.Close()
	makeWG := func(name string, port int) netlink.Link {
		t.Helper()
		link := &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name}, LinkType: "wireguard"}
		discoveryMust(t, netlink.LinkAdd(link))
		t.Cleanup(func() { discoveryMust(t, netlink.LinkDel(link)) })
		key, err := wgtypes.GeneratePrivateKey()
		discoveryMust(t, err)
		discoveryMust(t, c.ConfigureDevice(name, wgtypes.Config{PrivateKey: &key, ListenPort: &port}))
		return link
	}
	link := makeWG("wg-discovery", 52000)
	discoveryAddress(t, link, "fe80::1/64")
	discoveryMust(t, netlink.LinkSetUp(link))
	const rangePath = "/proc/sys/net/ipv4/ip_local_port_range"
	previous, err := os.ReadFile(rangePath)
	discoveryMust(t, err)
	t.Cleanup(func() { discoveryMust(t, os.WriteFile(rangePath, previous, 0600)) })
	discoveryMust(t, os.WriteFile(rangePath, []byte("31000 31001"), 0600))
	occupied, err := net.ListenUDP("udp", &net.UDPAddr{Port: 31001})
	discoveryMust(t, err)
	defer occupied.Close()
	probe, err := net.ListenUDP("udp", &net.UDPAddr{Port: 31000})
	discoveryMust(t, err)
	discoveryMust(t, probe.Close())
	s, err := Listen(link.Attrs().Name, netip.MustParseAddr("fe80::1"), 58420)
	discoveryMust(t, err)
	defer s.Close()
	restored := makeWG("wg-restored", 31000)
	discoveryMust(t, netlink.LinkSetUp(restored))
	wg, err := c.Device(restored.Attrs().Name)
	discoveryMust(t, err)
	if wg.ListenPort != 31000 {
		t.Fatalf("restored port = %d", wg.ListenPort)
	}
	unexpected, err := net.ListenUDP("udp", &net.UDPAddr{Port: 31000})
	if unexpected != nil {
		unexpected.Close()
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("WG must own the restored port: %v", err)
	}
}

// Two independent Links deliberately use identical scoped addresses. Verify
// actual datagram metadata, bidirectional liveness and routed-policy demux.
func TestKernelDiscoverySocketScopes(t *testing.T) {
	discoveryNamespace(t)
	localNS, err := netns.Get()
	discoveryMust(t, err)
	defer localNS.Close()
	peerNS, err := netns.New()
	discoveryMust(t, err)
	defer peerNS.Close()
	discoveryMust(t, netns.Set(localNS))
	inPeer := func(f func()) {
		t.Helper()
		discoveryMust(t, netns.Set(peerNS))
		defer func() { discoveryMust(t, netns.Set(localNS)) }()
		f()
	}
	local, remote := netip.MustParseAddr("fe80::1"), netip.MustParseAddr("fe80::2")
	var sockets, peers []*Socket
	for i := range 2 {
		name, peer := fmt.Sprintf("disc%d", i), fmt.Sprintf("peer%d", i)
		link := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: peer}
		discoveryMust(t, netlink.LinkAdd(link))
		t.Cleanup(func() { discoveryMust(t, netlink.LinkDel(link)) })
		other, err := netlink.LinkByName(peer)
		discoveryMust(t, err)
		discoveryMust(t, netlink.LinkSetNsFd(other, int(peerNS)))
		discoveryAddress(t, link, "fe80::1/64")
		discoveryAddress(t, link, "fe80::99/64") // Source selection must stay explicit.
		discoveryMust(t, netlink.LinkSetUp(link))
		s, err := Listen(name, local, 58420)
		discoveryMust(t, err)
		defer s.Close()
		sockets = append(sockets, s)
		inPeer(func() {
			other, err := netlink.LinkByName(peer)
			discoveryMust(t, err)
			discoveryAddress(t, other, "fe80::2/64")
			discoveryMust(t, netlink.LinkSetUp(other))
			s, err := Listen(peer, remote, 58420)
			discoveryMust(t, err)
			t.Cleanup(func() { s.Close() })
			peers = append(peers, s)
		})
	}
	read := func(s *Socket, source, destination netip.Addr, kind message.Type) {
		t.Helper()
		discoveryMust(t, s.receivePacket.SetControlMessage(ipv6.FlagHopLimit, true))
		discoveryMust(t, s.receiver.SetReadDeadline(time.Now().Add(3*time.Second)))
		buf := make([]byte, 1201)
		n, cm, addr, err := s.receivePacket.ReadFrom(buf)
		discoveryMust(t, err)
		udp := addr.(*net.UDPAddr)
		if udp.Port != 58420 || !udp.IP.Equal(net.IP(source.AsSlice())) || cm.IfIndex != s.interfaceIndex || cm.HopLimit != 1 || !cm.Dst.Equal(net.IP(destination.AsSlice())) {
			t.Fatalf("wrong source/scope: %v %+v", addr, cm)
		}
		m, err := message.DecodeDatagram(buf[:n])
		discoveryMust(t, err)
		if m.Type != kind {
			t.Fatalf("message = %v, want %v", m.Type, kind)
		}
	}
	for i, s := range sockets {
		discoveryMust(t, s.SendHello())
		read(peers[i], local, MulticastAddress, Hello)
		discoveryMust(t, peers[i].SendAck(local))
		read(s, remote, local, HelloAck)
		for _, kind := range []message.Type{message.LinkPing, message.LinkPong} {
			discoveryMust(t, s.Send(remote, message.Message{Type: kind, OperationID: [16]byte{1}}))
			read(peers[i], local, remote, kind)
		}
		// Exercise the production decoder as well as inspecting raw metadata.
		discoveryMust(t, peers[i].SendHello())
		v, err := s.Read()
		discoveryMust(t, err)
		if v.Source != remote || v.Type != Hello {
			t.Fatalf("discovery decode: %+v", v)
		}
	}
	// A loopback policy binding shares the port but must receive its own unicast.
	loop := netip.MustParseAddr("fd78:ee::1")
	lo, err := netlink.LinkByName("lo")
	discoveryMust(t, err)
	discoveryAddress(t, lo, loop.String()+"/128")
	p, err := policy.Listen(loop, netip.MustParsePrefix("fd78:ee::/64"), 58420, func(index int) bool { return index == sockets[0].interfaceIndex })
	discoveryMust(t, err)
	defer p.Close()
	peerLoop := netip.MustParseAddr("fd78:ee::2")
	inPeer(func() {
		dev, err := netlink.LinkByName("peer0")
		discoveryMust(t, err)
		discoveryAddress(t, dev, peerLoop.String()+"/64")
		discoveryMust(t, netlink.RouteAdd(&netlink.Route{LinkIndex: dev.Attrs().Index,
			Dst: &net.IPNet{IP: net.IP(loop.AsSlice()), Mask: net.CIDRMask(128, 128)}, Gw: net.IP(local.AsSlice())}))
	})
	packet, err := message.EncodeDatagram(message.Message{Type: message.PolicyQuery, UID: &message.UID{UUID: uuid.New()}})
	discoveryMust(t, err)
	_, err = peers[0].receivePacket.WriteTo(packet, &ipv6.ControlMessage{Src: net.IP(peerLoop.AsSlice()), IfIndex: peers[0].interfaceIndex}, &net.UDPAddr{IP: net.IP(loop.AsSlice()), Port: 58420})
	discoveryMust(t, err)
	done := make(chan error, 1)
	go func() {
		src, m, err := p.Read()
		if err == nil && (src != peerLoop || m.Type != message.PolicyQuery) {
			err = fmt.Errorf("policy demux: %v %v", src, m.Type)
		}
		done <- err
	}()
	select {
	case err := <-done:
		discoveryMust(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("policy packet did not reach loopback listener")
	}
	// No multicast echo, cross-Link packets or policy packet may be queued here.
	for _, s := range append(sockets, peers...) {
		discoveryMust(t, s.receiver.SetReadDeadline(time.Now().Add(30*time.Millisecond)))
		_, _, _, err := s.receivePacket.ReadFrom(make([]byte, 1201))
		if e, ok := err.(net.Error); !ok || !e.Timeout() {
			t.Fatalf("unexpected queued packet on %s: %v", s.interfaceName, err)
		}
	}
}
