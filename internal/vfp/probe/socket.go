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
	conn      *net.UDPConn
	Local     netip.AddrPort
	done      chan struct{}
	closeOnce sync.Once
}

func Listen(ctx context.Context, local netip.AddrPort, r *Receiver, receive func(Received)) (*Socket, error) {
	network := "udp6"
	if local.Addr().Is4() {
		network = "udp4"
	}
	conn, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(local))
	if err != nil {
		return nil, err
	}
	s := &Socket{conn: conn, Local: conn.LocalAddr().(*net.UDPAddr).AddrPort(), done: make(chan struct{})}
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
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			if v, ok := r.Open(buffer[:n], from); ok {
				receive(v)
			}
		}
	}()
	return s, nil
}
func (s *Socket) Send(packet []byte, dst netip.AddrPort) error {
	_, err := s.conn.WriteToUDPAddrPort(packet, dst)
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
