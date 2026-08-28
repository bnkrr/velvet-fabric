package message

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/tlv"
)

const (
	Version        = 1
	HeaderLength   = 4
	MaxFrameLength = 4096
)

type Type uint8

const (
	Open        Type = 0x01
	NodeState   Type = 0x02
	LinkPropose Type = 0x03
	LinkAccept  Type = 0x04
)

const (
	NodeUIDTLV      uint16 = 0x0001
	LoopbackV6TLV   uint16 = 0x0003
	LinkPrefixV4TLV uint16 = 0x0004
	LinkPrefixV6TLV uint16 = 0x0005
)

var ErrFrame = errors.New("invalid VFP frame")
var ErrConnection = errors.New("invalid VFP connection")

type UID struct {
	UUID uuid.UUID
	Name string
}

type Message struct {
	Type         Type
	UID          *UID
	LoopbackV6   netip.Addr
	LinkPrefixV4 netip.Prefix
	LinkPrefixV6 netip.Prefix
}

func Read(r io.Reader) ([]byte, error) {
	header := make([]byte, HeaderLength)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("%w: read header: %v", ErrConnection, err)
	}
	length := int(binary.BigEndian.Uint16(header[2:4]))
	if length < HeaderLength || length > MaxFrameLength {
		return nil, fmt.Errorf("%w: declared length %d", ErrConnection, length)
	}
	frame := make([]byte, length)
	copy(frame, header)
	if _, err := io.ReadFull(r, frame[HeaderLength:]); err != nil {
		return nil, fmt.Errorf("%w: read body: %v", ErrConnection, err)
	}
	if frame[0] != Version {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrConnection, frame[0])
	}
	return frame, nil
}

func Decode(frame []byte) (Message, error) {
	if len(frame) < HeaderLength || len(frame) > MaxFrameLength || int(binary.BigEndian.Uint16(frame[2:4])) != len(frame) || frame[0] != Version {
		return Message{}, ErrFrame
	}
	result := Message{Type: Type(frame[1])}
	if result.Type < Open || result.Type > LinkAccept {
		return Message{}, fmt.Errorf("%w: unknown message type 0x%02x", ErrFrame, frame[1])
	}
	selected := map[uint16][]byte{}
	cursor := tlv.NewCursor(frame[HeaderLength:])
	for {
		view, ok, err := cursor.Next()
		if err != nil {
			return Message{}, fmt.Errorf("%w: %v", ErrFrame, err)
		}
		if !ok {
			break
		}
		if !usedBy(result.Type, view.Type) {
			continue
		}
		if _, exists := selected[view.Type]; !exists {
			selected[view.Type] = view.Value
		}
	}
	var err error
	switch result.Type {
	case Open:
		value, ok := selected[NodeUIDTLV]
		if !ok {
			return Message{}, fmt.Errorf("%w: OPEN requires NODE_UID", ErrFrame)
		}
		uid, parseErr := parseUID(value)
		if parseErr != nil {
			return Message{}, fmt.Errorf("%w: %v", ErrFrame, parseErr)
		}
		result.UID = &uid
	case NodeState:
		result.LoopbackV6, err = parseAddress(selected[LoopbackV6TLV], false)
		if err != nil {
			return Message{}, fmt.Errorf("%w: %v", ErrFrame, err)
		}
		if !result.LoopbackV6.IsValid() {
			return Message{}, fmt.Errorf("%w: NODE_STATE requires LOOPBACK_V6", ErrFrame)
		}
	case LinkPropose:
		result.LinkPrefixV4, err = parsePrefix(selected[LinkPrefixV4TLV], true)
		if err != nil {
			return Message{}, fmt.Errorf("%w: %v", ErrFrame, err)
		}
		result.LinkPrefixV6, err = parsePrefix(selected[LinkPrefixV6TLV], false)
		if err != nil {
			return Message{}, fmt.Errorf("%w: %v", ErrFrame, err)
		}
	case LinkAccept:
		// Every known TLV is unused for LINK_ACCEPT and was ignored above.
	}
	return result, nil
}

func Encode(m Message) ([]byte, error) {
	body := make([]byte, 0, 64)
	switch m.Type {
	case Open:
		if m.UID == nil {
			return nil, errors.New("OPEN requires UID")
		}
		value, err := encodeUID(*m.UID)
		if err != nil {
			return nil, err
		}
		body = tlv.Append(body, NodeUIDTLV, value)
	case NodeState:
		if m.LoopbackV6.IsValid() {
			if !m.LoopbackV6.Is6() {
				return nil, errors.New("invalid IPv6 loopback")
			}
			value := m.LoopbackV6.As16()
			body = tlv.Append(body, LoopbackV6TLV, value[:])
		}
		if len(body) == 0 {
			return nil, errors.New("NODE_STATE requires an IPv6 loopback")
		}
	case LinkPropose:
		if m.LinkPrefixV4.IsValid() {
			if m.LinkPrefixV4.Bits() != 30 || m.LinkPrefixV4 != m.LinkPrefixV4.Masked() {
				return nil, errors.New("invalid IPv4 link prefix")
			}
			value := m.LinkPrefixV4.Addr().As4()
			body = tlv.Append(body, LinkPrefixV4TLV, value[:])
		}
		if m.LinkPrefixV6.IsValid() {
			if m.LinkPrefixV6.Bits() != 126 || m.LinkPrefixV6 != m.LinkPrefixV6.Masked() {
				return nil, errors.New("invalid IPv6 link prefix")
			}
			value := m.LinkPrefixV6.Addr().As16()
			body = tlv.Append(body, LinkPrefixV6TLV, value[:])
		}
	case LinkAccept:
	default:
		return nil, errors.New("unknown message type")
	}
	length := HeaderLength + len(body)
	if length > MaxFrameLength {
		return nil, errors.New("frame too large")
	}
	frame := []byte{Version, byte(m.Type), 0, 0}
	binary.BigEndian.PutUint16(frame[2:4], uint16(length))
	return append(frame, body...), nil
}

func Write(w io.Writer, m Message) error {
	frame, err := Encode(m)
	if err != nil {
		return err
	}
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if err != nil {
			return err
		}
		frame = frame[n:]
	}
	return nil
}

func usedBy(messageType Type, tlvType uint16) bool {
	switch messageType {
	case Open:
		return tlvType == NodeUIDTLV
	case NodeState:
		return tlvType == LoopbackV6TLV
	case LinkPropose:
		return tlvType == LinkPrefixV4TLV || tlvType == LinkPrefixV6TLV
	case LinkAccept:
		return false
	default:
		return false
	}
}

func parseUID(value []byte) (UID, error) {
	if len(value) < 16 || len(value) > 21 {
		return UID{}, errors.New("NODE_UID length must be 16..21")
	}
	parsed, err := uuid.FromBytes(value[:16])
	if err != nil || parsed == uuid.Nil {
		return UID{}, errors.New("NODE_UID UUID is invalid")
	}
	for _, b := range value[16:] {
		if !((b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')) {
			return UID{}, errors.New("NODE_UID name is invalid")
		}
	}
	return UID{UUID: parsed, Name: string(value[16:])}, nil
}

func encodeUID(value UID) ([]byte, error) {
	if value.UUID == uuid.Nil || len(value.Name) > 5 {
		return nil, errors.New("invalid UID")
	}
	for _, b := range []byte(value.Name) {
		if !((b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')) {
			return nil, errors.New("invalid UID name")
		}
	}
	result := append([]byte(nil), value.UUID[:]...)
	return append(result, value.Name...), nil
}

func parseAddress(value []byte, ipv4 bool) (netip.Addr, error) {
	if value == nil {
		return netip.Addr{}, nil
	}
	if ipv4 {
		if len(value) != 4 {
			return netip.Addr{}, errors.New("IPv4 address length is not 4")
		}
		var raw [4]byte
		copy(raw[:], value)
		addr := netip.AddrFrom4(raw)
		if !validAddress(addr) {
			return netip.Addr{}, errors.New("invalid IPv4 address")
		}
		return addr, nil
	}
	if len(value) != 16 {
		return netip.Addr{}, errors.New("IPv6 address length is not 16")
	}
	var raw [16]byte
	copy(raw[:], value)
	addr := netip.AddrFrom16(raw)
	if !validAddress(addr) {
		return netip.Addr{}, errors.New("invalid IPv6 address")
	}
	return addr, nil
}

func parsePrefix(value []byte, ipv4 bool) (netip.Prefix, error) {
	addr, err := parseAddress(value, ipv4)
	if err != nil || !addr.IsValid() {
		return netip.Prefix{}, err
	}
	bits := 126
	if ipv4 {
		bits = 30
	}
	prefix := netip.PrefixFrom(addr, bits)
	if prefix != prefix.Masked() {
		return netip.Prefix{}, errors.New("link prefix has host bits set")
	}
	return prefix, nil
}

func validAddress(addr netip.Addr) bool {
	return !addr.IsUnspecified() && !addr.IsMulticast() && !addr.IsLinkLocalUnicast() && addr.String() != "255.255.255.255"
}
