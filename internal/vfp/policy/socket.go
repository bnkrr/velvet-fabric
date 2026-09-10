// Package policy implements the Fabric-routed UDP binding, separate from
// link-local discovery and from the authenticated public probe listener.
package policy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

type Socket struct {
	conn    *net.UDPConn
	packet  *ipv6.PacketConn
	local   netip.Addr
	pool    netip.Prefix
	port    int
	ingress func(int) bool
}

func Listen(local netip.Addr, pool netip.Prefix, port int, ingress func(int) bool) (*Socket, error) {
	if !local.Is6() || local.Is4In6() || local.IsLinkLocalUnicast() || local.IsMulticast() || !pool.Contains(local) || ingress == nil {
		return nil, errors.New("invalid routed policy binding")
	}
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var sockErr error
		if err := raw.Control(func(fd uintptr) { sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1) }); err != nil {
			return err
		}
		return sockErr
	}}
	// Link discovery also binds this port, on individual WG devices. Reuse is
	// needed for those wildcard multicast binds; the policy socket stays unicast.
	packet, err := lc.ListenPacket(context.Background(), "udp6", (&net.UDPAddr{IP: net.IP(local.AsSlice()), Port: port}).String())
	if err != nil {
		return nil, err
	}
	c := packet.(*net.UDPConn)
	p := ipv6.NewPacketConn(c)
	if err := p.SetControlMessage(ipv6.FlagInterface|ipv6.FlagDst, true); err != nil {
		c.Close()
		return nil, err
	}
	return &Socket{conn: c, packet: p, local: local, pool: pool, port: c.LocalAddr().(*net.UDPAddr).Port, ingress: ingress}, nil
}

func (s *Socket) Close() error { return s.conn.Close() }

func (s *Socket) Read() (netip.Addr, message.Message, error) {
	buffer := make([]byte, message.MaxDatagramLength+1)
	for {
		n, control, source, err := s.packet.ReadFrom(buffer)
		if err != nil {
			return netip.Addr{}, message.Message{}, err
		}
		if src, m, ok := s.decode(buffer[:n], control, source); ok {
			return src, m, nil
		}

	}
}

// A single runtime worker owns writes and their deadline.
func (s *Socket) Send(remote netip.Addr, m message.Message) error {
	if !m.Type.IsPolicy() || !s.pool.Contains(remote) || remote == s.local {
		return errors.New("invalid policy destination or message")
	}
	b, err := message.EncodeDatagram(m)
	if err != nil {
		return err
	}
	if err := s.conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	_, err = s.conn.WriteToUDP(b, &net.UDPAddr{IP: net.IP(remote.AsSlice()), Port: s.port})
	return err
}

// decode validates the kernel packet metadata before exposing a policy message.
func (s *Socket) decode(packet []byte, control *ipv6.ControlMessage, source net.Addr) (netip.Addr, message.Message, bool) {
	udp, ok := source.(*net.UDPAddr)
	if !ok || udp.Port != s.port || control == nil {
		return netip.Addr{}, message.Message{}, false
	}
	src, ok := netip.AddrFromSlice(udp.IP)
	dst, dstOK := netip.AddrFromSlice(control.Dst)
	if !ok || !dstOK || dst != s.local || src == s.local || !src.Is6() || src.Is4In6() || src.IsLinkLocalUnicast() || src.IsMulticast() || !s.pool.Contains(src) || !s.ingress(control.IfIndex) {
		return netip.Addr{}, message.Message{}, false
	}
	m, err := message.DecodeDatagram(packet)
	if err != nil || !m.Type.IsPolicy() {
		return netip.Addr{}, message.Message{}, false
	}
	return src, m, true
}
