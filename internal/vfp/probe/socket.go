// Package probe implements leased, authenticated, one-way public VFP UDP probes.
package probe

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const MaxPackets = 12000

type Received struct {
	Round             uint16
	Sequence          uint64
	Destination, Seen netip.AddrPort
}

// Receiver shares a replay namespace across all sockets in one observer lease.
type Receiver struct {
	mu    sync.Mutex
	ID    [16]byte
	Key   [32]byte
	aead  cipher.AEAD
	seen  [MaxPackets + 1]bool
	until time.Time
}

func NewReceiver(id [16]byte, until time.Time) (*Receiver, error) {
	r := &Receiver{ID: id, until: until}
	if _, err := rand.Read(r.Key[:]); err != nil {
		return nil, err
	}
	var err error
	r.aead, err = newAEAD(r.Key)
	return r, err
}
func newAEAD(key [32]byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func Seal(id [16]byte, key [32]byte, seq uint64, round uint16, dst netip.AddrPort) ([]byte, error) {
	if seq == 0 || seq > MaxPackets || round > 16 {
		return nil, errors.New("probe budget or round invalid")
	}
	ep, err := message.EndpointValue(dst)
	if err != nil {
		return nil, err
	}
	plain := binary.BigEndian.AppendUint16(nil, round)
	plain = append(plain, ep...)
	data := append([]byte(nil), id[:]...)
	data = binary.BigEndian.AppendUint64(data, seq)
	data = append(data, make([]byte, len(plain)+16)...)
	frame, err := message.EncodeDatagram(message.Message{Type: message.PublicProbe, Data: data})
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], seq)
	// Exactly one canonical TLV; header (8), TLV header (4), context (24).
	sealed := aead.Seal(nil, nonce[:], plain, frame[:36])
	copy(frame[36:], sealed)
	return frame, nil
}
func (r *Receiver) Open(packet []byte, seen netip.AddrPort) (Received, bool) {
	// Authenticate the canonical envelope before decoding plaintext or changing state.
	if len(packet) < 62 || len(packet) > message.MaxDatagramLength || binary.BigEndian.Uint32(packet[:4]) != message.Magic || packet[4] != message.Version || packet[5] != byte(message.PublicProbe) || int(binary.BigEndian.Uint16(packet[6:8])) != len(packet) || binary.BigEndian.Uint16(packet[8:10]) != message.SealedProbeTLV || int(binary.BigEndian.Uint16(packet[10:12])) != len(packet)-12 {
		return Received{}, false
	}
	var id [16]byte
	copy(id[:], packet[12:28])
	seq := binary.BigEndian.Uint64(packet[28:36])
	if id != r.ID || seq == 0 || seq > MaxPackets {
		return Received{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !time.Now().Before(r.until) || r.seen[seq] {
		return Received{}, false
	}
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], seq)
	plain, err := r.aead.Open(nil, nonce[:], packet[36:], packet[:36])
	if err != nil || len(plain) < 2 {
		return Received{}, false
	}
	round := binary.BigEndian.Uint16(plain[:2])
	dst, err := message.ParseEndpointValue(plain[2:])
	if err != nil || round > 16 || seen.Addr().Is4() != dst.Addr().Is4() {
		return Received{}, false
	}
	r.seen[seq] = true
	return Received{Round: round, Sequence: seq, Destination: dst, Seen: seen}, true
}

type Socket struct {
	conn          *net.UDPConn
	Local         netip.AddrPort
	done          chan struct{}
	closeOnce     sync.Once
	sourceControl []byte
}

func Listen(ctx context.Context, local netip.AddrPort, r *Receiver, receive func(Received)) (*Socket, error) {
	if !local.IsValid() || local.Addr().IsUnspecified() || local.Addr().IsMulticast() {
		return nil, errors.New("probe requires a concrete local address")
	}
	// WireGuard binds the same wildcard port in IPv4 and IPv6. Reserve that
	// scope now: a single-address bind can otherwise coexist with a discovery
	// sender on another address/family and fail only after successful punching.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6zero, Port: int(local.Port())})
	if err != nil {
		return nil, err
	}
	s := &Socket{conn: conn, Local: netip.AddrPortFrom(local.Addr(), conn.LocalAddr().(*net.UDPAddr).AddrPort().Port()), done: make(chan struct{})}
	if local.Addr().Is4() {
		err = ipv4.NewPacketConn(conn).SetControlMessage(ipv4.FlagDst, true)
		s.sourceControl = (&ipv4.ControlMessage{Src: net.IP(local.Addr().AsSlice())}).Marshal()
	} else {
		err = ipv6.NewPacketConn(conn).SetControlMessage(ipv6.FlagDst, true)
		s.sourceControl = (&ipv6.ControlMessage{Src: net.IP(local.Addr().AsSlice())}).Marshal()
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	go func() {
		select {
		case <-ctx.Done():
			s.Close()
		case <-s.done:
		}
	}()
	go func() {
		defer s.Close()
		buffer := make([]byte, message.MaxDatagramLength+1)
		control := make([]byte, len(ipv4.NewControlMessage(ipv4.FlagDst))+len(ipv6.NewControlMessage(ipv6.FlagDst)))
		for {
			n, controlLength, _, from, err := conn.ReadMsgUDPAddrPort(buffer, control)
			if err != nil {
				return
			}
			from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			// A wildcard reservation must not expand the measurement to other local
			// addresses, or consume replay state for a packet on the wrong path.
			var destination net.IP
			if local.Addr().Is4() {
				var cm ipv4.ControlMessage
				if cm.Parse(control[:controlLength]) != nil {
					continue
				}
				destination = cm.Dst
			} else {
				var cm ipv6.ControlMessage
				if cm.Parse(control[:controlLength]) != nil {
					continue
				}
				destination = cm.Dst
			}
			ip, ok := netip.AddrFromSlice(destination)
			if !ok || ip.Unmap() != local.Addr().Unmap().WithZone("") {
				continue
			}
			if v, ok := r.Open(buffer[:n], from); ok {
				receive(v)
			}
		}
	}()
	return s, nil
}
func (s *Socket) Send(packet []byte, dst netip.AddrPort) error {
	if dst.Addr().Is4() != s.Local.Addr().Is4() {
		return errors.New("probe destination family differs from local address")
	}
	// Pin the measured source despite the wildcard bind and destination changes.
	_, _, err := s.conn.WriteMsgUDPAddrPort(packet, s.sourceControl, dst)
	return err
}
func (s *Socket) Close() error {
	s.closeOnce.Do(func() { _ = s.conn.Close(); close(s.done) })
	return nil
}

// Source resolves the kernel's current source selection without sending data.
func Source(target netip.AddrPort) (netip.Addr, error) {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(target))
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(), nil
}

func (s *Socket) Endpoint() netip.AddrPort { return s.Local }
