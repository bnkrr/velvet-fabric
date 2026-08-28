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
	"syscall"
	"time"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	Version   = 1
	HelloSize = 8
	Hello     = MessageType(1)
	HelloAck  = MessageType(2)
)

var (
	MulticastAddress = netip.MustParseAddr("ff02::1")
	magic            = [4]byte{'V', 'F', 'P', 'D'}
	ErrInvalidHello  = errors.New("invalid VFP discovery message")
)

type MessageType uint8

type Observation struct {
	Source netip.Addr
	Type   MessageType
}

// Encode produces a fixed-size pre-session marker. Node identity and
// resources remain in authenticated-by-WireGuard VFP/TCP messages.
func Encode(messageType MessageType) ([HelloSize]byte, error) {
	if messageType != Hello && messageType != HelloAck {
		return [HelloSize]byte{}, fmt.Errorf("%w: unknown type %d", ErrInvalidHello, messageType)
	}
	return [HelloSize]byte{magic[0], magic[1], magic[2], magic[3], Version, byte(messageType), 0, HelloSize}, nil
}

func Parse(packet []byte) (MessageType, error) {
	if len(packet) != HelloSize || packet[0] != magic[0] || packet[1] != magic[1] || packet[2] != magic[2] || packet[3] != magic[3] {
		return 0, ErrInvalidHello
	}
	messageType := MessageType(packet[5])
	if packet[4] != Version || (messageType != Hello && messageType != HelloAck) || binary.BigEndian.Uint16(packet[6:8]) != HelloSize {
		return 0, ErrInvalidHello
	}
	return messageType, nil
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
	destination := &net.UDPAddr{IP: net.IP(MulticastAddress.AsSlice()), Port: port, Zone: interfaceName}
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
	if err := receivePacket.SetControlMessage(ipv6.FlagInterface, true); err != nil {
		_ = receiver.Close()
		return nil, fmt.Errorf("enable discovery interface metadata: %w", err)
	}
	sender, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IP(local.AsSlice()), Zone: interfaceName})
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
	destination := &net.UDPAddr{IP: net.IP(remote.AsSlice()), Port: s.destination.Port, Zone: s.interfaceName}
	if _, err := s.sender.WriteToUDP(packet[:], destination); err != nil {
		return fmt.Errorf("send discovery Hello ACK: %w", err)
	}
	return nil
}

// ReadHello ignores unrelated or malformed datagrams and returns only a valid
// link-local source received on the requested interface.
func (s *Socket) ReadHello() (Observation, error) {
	buffer := make([]byte, 256)
	for {
		n, control, source, err := s.receivePacket.ReadFrom(buffer)
		if err != nil {
			return Observation{}, err
		}
		messageType, parseErr := Parse(buffer[:n])
		if control == nil || control.IfIndex != s.interfaceIndex || parseErr != nil {
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
		return Observation{Source: address.Unmap(), Type: messageType}, nil
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
