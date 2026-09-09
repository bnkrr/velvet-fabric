// Package discovery implements the link-scoped datagram exchange used to find
// the remote VFP/TCP endpoint on an already configured WireGuard Link.
package discovery

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	Hello    = message.DiscoveryHello
	HelloAck = message.DiscoveryHelloAck
)

var (
	MulticastAddress = netip.MustParseAddr("ff02::1")
	ErrInvalidHello  = errors.New("invalid VFP discovery message")
)

type MessageType = message.Type

type Observation struct {
	Source  netip.Addr
	Type    MessageType
	Message message.Message
}

// Encode uses the common VFP codec. Identity remains in WG-protected TCP sessions.
func Encode(messageType MessageType) ([]byte, error) {
	if !messageType.IsDiscovery() {
		return nil, ErrInvalidHello
	}
	packet, err := message.EncodeDatagram(message.Message{Type: messageType})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidHello, err)
	}
	return packet, nil
}

func Parse(packet []byte) (MessageType, error) {
	m, err := message.DecodeDatagram(packet)
	if err != nil || !m.Type.IsDiscovery() {
		return 0, fmt.Errorf("%w: %v", ErrInvalidHello, err)
	}
	return m.Type, nil
}

type Socket struct {
	interfaceIndex int
	interfaceName  string
	receiver       *net.UDPConn
	receivePacket  *ipv6.PacketConn
	sender         *net.UDPConn
	sendPacket     *ipv6.PacketConn
	destination    *net.UDPAddr
}

func Listen(interfaceName string, local netip.Addr, port int) (*Socket, error) {
	if !local.Is6() || !local.IsLinkLocalUnicast() {
		return nil, fmt.Errorf("discovery local address %s is not IPv6 link-local", local)
	}
	ifi, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("look up discovery interface: %w", err)
	}
	// Go caches interface-name zones. A recreated same-name WG interface has a
	// different index; numeric zones avoid binding/sending through the old one.
	zone := strconv.Itoa(ifi.Index)
	destination := &net.UDPAddr{IP: net.IP(MulticastAddress.AsSlice()), Port: port, Zone: zone}
	listenConfig := net.ListenConfig{Control: bindToDevice(interfaceName, true)}
	packetConn, err := listenConfig.ListenPacket(context.Background(), "udp6", fmt.Sprintf("[::]:%d", port))
	if err != nil {
		return nil, fmt.Errorf("listen for discovery multicast: %w", err)
	}
	receiver, ok := packetConn.(*net.UDPConn)
	if !ok {
		_ = packetConn.Close()
		return nil, errors.New("discovery listener is not UDP")
	}
	receivePacket := ipv6.NewPacketConn(receiver)
	if err := receivePacket.JoinGroup(ifi, &net.UDPAddr{IP: net.IP(MulticastAddress.AsSlice())}); err != nil {
		_ = receiver.Close()
		return nil, fmt.Errorf("join discovery multicast group: %w", err)
	}
	if err := receivePacket.SetControlMessage(ipv6.FlagInterface|ipv6.FlagDst, true); err != nil {
		_ = receiver.Close()
		return nil, fmt.Errorf("enable discovery interface metadata: %w", err)
	}
	sender, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IP(local.AsSlice()), Zone: zone})
	if err != nil {
		_ = receiver.Close()
		return nil, fmt.Errorf("bind discovery sender: %w", err)
	}
	sendPacket := ipv6.NewPacketConn(sender)
	if err := sendPacket.SetMulticastInterface(ifi); err != nil {
		_ = sender.Close()
		_ = receiver.Close()
		return nil, fmt.Errorf("select discovery multicast interface: %w", err)
	}
	if err := sendPacket.SetMulticastHopLimit(1); err != nil {
		_ = sender.Close()
		_ = receiver.Close()
		return nil, fmt.Errorf("set discovery hop limit: %w", err)
	}
	_ = sendPacket.SetMulticastLoopback(false)
	return &Socket{
		interfaceIndex: ifi.Index, interfaceName: interfaceName,
		receiver: receiver, receivePacket: receivePacket,
		sender: sender, sendPacket: sendPacket, destination: destination,
	}, nil
}

func bindToDevice(interfaceName string, reuseAddress bool) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var socketError error
		if err := raw.Control(func(fd uintptr) {
			if reuseAddress {
				socketError = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			}
			if socketError == nil {
				socketError = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, interfaceName)
			}
		}); err != nil {
			return err
		}
		return socketError
	}
}

func (s *Socket) Close() error {
	_ = s.sender.Close()
	return s.receiver.Close()
}

func (s *Socket) SendHello() error {
	packet, _ := Encode(Hello)
	if _, err := s.sender.WriteToUDP(packet[:], s.destination); err != nil {
		return fmt.Errorf("send discovery Hello: %w", err)
	}
	return nil
}

func (s *Socket) SendAck(remote netip.Addr) error {
	packet, _ := Encode(HelloAck)
	destination := &net.UDPAddr{IP: net.IP(remote.AsSlice()), Port: s.destination.Port, Zone: strconv.Itoa(s.interfaceIndex)}
	if _, err := s.sender.WriteToUDP(packet[:], destination); err != nil {
		return fmt.Errorf("send discovery Hello ACK: %w", err)
	}
	return nil
}

// Send transmits one link-local unicast datagram on the selected WG interface.
func (s *Socket) Send(remote netip.Addr, m message.Message) error {
	packet, err := message.EncodeDatagram(m)
	if err != nil {
		return err
	}
	_, err = s.sender.WriteToUDP(packet, &net.UDPAddr{IP: net.IP(remote.AsSlice()), Port: s.destination.Port, Zone: strconv.Itoa(s.interfaceIndex)})
	return err
}

// Read validates both the receiving interface and the link-local scope. Public
// probes and multicast liveness packets are never admitted on this socket.
func (s *Socket) Read() (Observation, error) {
	buffer := make([]byte, message.MaxDatagramLength+1)
	for {
		n, control, source, err := s.receivePacket.ReadFrom(buffer)
		if err != nil {
			return Observation{}, err
		}
		m, err := message.DecodeDatagram(buffer[:n])
		if err != nil || (!m.Type.IsDiscovery() && !m.Type.IsLinkProbe()) || control == nil || control.IfIndex != s.interfaceIndex {
			continue
		}
		dst, ok := netip.AddrFromSlice(control.Dst)
		if !ok || (m.Type.IsLinkProbe() && !dst.IsLinkLocalUnicast()) {
			continue
		}
		udp, ok := source.(*net.UDPAddr)
		if !ok {
			continue
		}
		address, ok := netip.AddrFromSlice(udp.IP)
		if !ok || !address.Is6() || !address.IsLinkLocalUnicast() {
			continue
		}
		return Observation{Source: address.Unmap(), Type: m.Type, Message: m}, nil
	}
}

func (s *Socket) ReadHello() (Observation, error) {
	for {
		v, err := s.Read()
		if err != nil || v.Type.IsDiscovery() {
			return v, err
		}
	}
}

// Announce sends immediately, then continues with jittered bounded backoff
// until the session owner cancels the context.
func (s *Socket) Announce(ctx context.Context) error {
	delay := 250 * time.Millisecond
	for {
		if err := s.SendHello(); err != nil {
			return err
		}
		timer := time.NewTimer(withJitter(delay))
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
		if delay < 2*time.Second {
			delay *= 2
			if delay > 2*time.Second {
				delay = 2 * time.Second
			}
		}
	}
}

func withJitter(base time.Duration) time.Duration {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return base
	}
	// Uniformly select 87.5% through 112.5% of the base interval.
	span := base / 4
	if span <= 0 {
		return base
	}
	offset := time.Duration(binary.BigEndian.Uint64(random[:]) % uint64(span))
	return base - base/8 + offset
}
