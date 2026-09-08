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
	Magic             = 0x56465000 // "VFP\x00", shared by TCP and UDP.
	Version           = 1
	HeaderLength      = 8
	MaxFrameLength    = 4096
	MaxDatagramLength = 1200
)

type Type uint8

const (
	Open                Type = 0x01
	NodeState           Type = 0x02
	LinkPropose         Type = 0x03
	LinkAccept          Type = 0x04
	EndpointObservation Type = 0x05
	DynamicLinkPropose  Type = 0x06
	DynamicLinkAccept   Type = 0x07
	DynamicLinkDecline  Type = 0x08
	DiscoveryHello      Type = 0x09
	DiscoveryHelloAck   Type = 0x0a
	DiscoveryControl    Type = 0x0b
	PublicProbe         Type = 0x0c
)

func (t Type) IsDiscovery() bool { return t == DiscoveryHello || t == DiscoveryHelloAck }

const (
	NodeUIDTLV       uint16 = 0x0001
	LoopbackV6TLV    uint16 = 0x0003
	LinkPrefixV4TLV  uint16 = 0x0004
	LinkPrefixV6TLV  uint16 = 0x0005
	OperationIDTLV   uint16 = 0x0006
	WGPublicKeyTLV   uint16 = 0x0007
	WGEndpointTLV    uint16 = 0x0008
	ProbeKeyTLV      uint16 = 0x0009
	DiscoveryDataTLV uint16 = 0x000a
	SealedProbeTLV   uint16 = 0x000b
)

var ErrFrame = errors.New("invalid VFP frame")
var ErrConnection = errors.New("invalid VFP connection")

type UID struct {
	UUID uuid.UUID
	Name string
}

type Message struct {
	Type         Type
	ProbeKey     [32]byte
	Data         []byte
	UID          *UID
	LoopbackV6   netip.Addr
	LinkPrefixV4 netip.Prefix
	LinkPrefixV6 netip.Prefix
	OperationID  [16]byte
	WGPublicKey  [32]byte
	Endpoint     netip.AddrPort
}

func Read(r io.Reader) ([]byte, error) {
	header := make([]byte, HeaderLength)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("%w: read header: %v", ErrConnection, err)
	}
	length, err := frameLength(header)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnection, err)
	}
	frame := make([]byte, length)
	copy(frame, header)
	if _, err := io.ReadFull(r, frame[HeaderLength:]); err != nil {
		return nil, fmt.Errorf("%w: read body: %v", ErrConnection, err)
	}
	return frame, nil
}

// frameLength checks the common header before any body allocation or read.
func frameLength(frame []byte) (int, error) {
	if len(frame) < HeaderLength {
		return 0, fmt.Errorf("%w: short header", ErrFrame)
	}
	if binary.BigEndian.Uint32(frame[:4]) != Magic {
		return 0, fmt.Errorf("%w: invalid magic", ErrFrame)
	}
	if frame[4] != Version {
		return 0, fmt.Errorf("%w: unsupported version %d", ErrFrame, frame[4])
	}
	length := int(binary.BigEndian.Uint16(frame[6:8]))
	if length < HeaderLength || length > MaxFrameLength {
		return 0, fmt.Errorf("%w: declared length %d", ErrFrame, length)
	}
	return length, nil
}

// Decode validates a complete message; its caller supplies transport/session context.
func Decode(frame []byte) (Message, error) {
	length, err := frameLength(frame)
	if err != nil || length != len(frame) {
		return Message{}, ErrFrame
	}
	result := Message{Type: Type(frame[5])}
	if result.Type < Open || result.Type > PublicProbe {
		return Message{}, fmt.Errorf("%w: unknown message type 0x%02x", ErrFrame, frame[5])
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
	case LinkAccept, DiscoveryHello, DiscoveryHelloAck:
		// These messages have no used TLVs; structural validation still applies.
	case EndpointObservation:
		result.Endpoint, err = parseEndpoint(selected[WGEndpointTLV])
		if err != nil || !result.Endpoint.IsValid() {
			return Message{}, fmt.Errorf("%w: ENDPOINT_OBSERVATION requires a valid WG_ENDPOINT", ErrFrame)
		}
	case DynamicLinkPropose, DynamicLinkAccept:
		if len(selected[ProbeKeyTLV]) != 32 {
			return Message{}, ErrFrame
		}
		copy(result.ProbeKey[:], selected[ProbeKeyTLV])
		if err = parseOperationID(selected[OperationIDTLV], &result.OperationID); err != nil {
			return Message{}, fmt.Errorf("%w: %v", ErrFrame, err)
		}
		if err = parsePublicKey(selected[WGPublicKeyTLV], &result.WGPublicKey); err != nil {
			return Message{}, fmt.Errorf("%w: %v", ErrFrame, err)
		}
		result.Endpoint, err = parseEndpoint(selected[WGEndpointTLV])
		if err != nil || !result.Endpoint.IsValid() {
			return Message{}, fmt.Errorf("%w: dynamic Link message requires a valid WG_ENDPOINT", ErrFrame)
		}
	case DiscoveryControl:
		if err = parseOperationID(selected[OperationIDTLV], &result.OperationID); err != nil {
			return Message{}, ErrFrame
		}
		result.Data = append([]byte(nil), selected[DiscoveryDataTLV]...)
		if _, err = DecodeControl(result.Data); err != nil {
			return Message{}, err
		}
	case PublicProbe:
		result.Data = append([]byte(nil), selected[SealedProbeTLV]...)
		if len(result.Data) != 50 && len(result.Data) != 62 {
			return Message{}, ErrFrame
		}
	case DynamicLinkDecline:
		if err = parseOperationID(selected[OperationIDTLV], &result.OperationID); err != nil {
			return Message{}, fmt.Errorf("%w: %v", ErrFrame, err)
		}
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
	case LinkAccept, DiscoveryHello, DiscoveryHelloAck:
	case EndpointObservation:
		value, err := encodeEndpoint(m.Endpoint)
		if err != nil {
			return nil, err
		}
		body = tlv.Append(body, WGEndpointTLV, value)
	case DynamicLinkPropose, DynamicLinkAccept:
		body = tlv.Append(body, OperationIDTLV, m.OperationID[:])
		if allZero(m.WGPublicKey[:]) {
			return nil, errors.New("dynamic Link message requires a non-zero WireGuard public key")
		}
		body = tlv.Append(body, WGPublicKeyTLV, m.WGPublicKey[:])
		value, err := encodeEndpoint(m.Endpoint)
		if err != nil {
			return nil, err
		}
		body = tlv.Append(body, WGEndpointTLV, value)
		body = tlv.Append(body, ProbeKeyTLV, m.ProbeKey[:])
	case DiscoveryControl:
		if _, err := DecodeControl(m.Data); err != nil {
			return nil, err
		}
		body = tlv.Append(body, OperationIDTLV, m.OperationID[:])
		body = tlv.Append(body, DiscoveryDataTLV, m.Data)
	case PublicProbe:
		if len(m.Data) != 50 && len(m.Data) != 62 {
			return nil, ErrFrame
		}
		body = tlv.Append(body, SealedProbeTLV, m.Data)
	case DynamicLinkDecline:
		body = tlv.Append(body, OperationIDTLV, m.OperationID[:])
	default:
		return nil, errors.New("unknown message type")
	}
	length := HeaderLength + len(body)
	if length > MaxFrameLength {
		return nil, errors.New("frame too large")
	}
	frame := make([]byte, HeaderLength, length)
	binary.BigEndian.PutUint32(frame[:4], Magic)
	frame[4], frame[5] = Version, byte(m.Type)
	binary.BigEndian.PutUint16(frame[6:8], uint16(length))
	return append(frame, body...), nil
}

// DecodeDatagram applies the current UDP binding. The socket reader must not
// pass a truncated prefix as a complete datagram (see VFP section 5.4).
func DecodeDatagram(packet []byte) (Message, error) {
	if len(packet) > MaxDatagramLength {
		return Message{}, fmt.Errorf("%w: datagram too large", ErrFrame)
	}
	m, err := Decode(packet)
	if err != nil {
		return Message{}, err
	}
	if !m.Type.IsDiscovery() && m.Type != PublicProbe {
		return Message{}, fmt.Errorf("%w: message is not valid over UDP", ErrFrame)
	}
	return m, nil
}

func EncodeDatagram(m Message) ([]byte, error) {
	if !m.Type.IsDiscovery() && m.Type != PublicProbe {
		return nil, fmt.Errorf("%w: message is not valid over UDP", ErrFrame)
	}
	frame, err := Encode(m)
	if err == nil && len(frame) > MaxDatagramLength {
		return nil, ErrFrame
	}
	return frame, err
}

func Write(w io.Writer, m Message) error {
	if m.Type.IsDiscovery() || m.Type == PublicProbe {
		return fmt.Errorf("%w: discovery is not valid over TCP", ErrFrame)
	}
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
	case EndpointObservation:
		return tlvType == WGEndpointTLV
	case DynamicLinkPropose, DynamicLinkAccept:
		return tlvType == OperationIDTLV || tlvType == WGPublicKeyTLV || tlvType == WGEndpointTLV || tlvType == ProbeKeyTLV
	case DiscoveryControl:
		return tlvType == OperationIDTLV || tlvType == DiscoveryDataTLV
	case PublicProbe:
		return tlvType == SealedProbeTLV
	case DynamicLinkDecline:
		return tlvType == OperationIDTLV
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

func parseOperationID(value []byte, output *[16]byte) error {
	if len(value) != len(output) {
		return errors.New("OPERATION_ID length must be 16")
	}
	copy(output[:], value)
	return nil
}

func parsePublicKey(value []byte, output *[32]byte) error {
	if len(value) != len(output) || allZero(value) {
		return errors.New("WG_PUBLIC_KEY must be 32 non-zero octets")
	}
	copy(output[:], value)
	return nil
}

func parseEndpoint(value []byte) (netip.AddrPort, error) {
	if len(value) != 8 && len(value) != 20 {
		return netip.AddrPort{}, errors.New("IP endpoint length must be 8 or 20")
	}
	afi := binary.BigEndian.Uint16(value[:2])
	port := binary.BigEndian.Uint16(value[2:4])
	if port == 0 {
		return netip.AddrPort{}, errors.New("IP endpoint port must be non-zero")
	}
	var addr netip.Addr
	switch afi {
	case 1:
		if len(value) != 8 {
			return netip.AddrPort{}, errors.New("IPv4 endpoint length must be 8")
		}
		var raw [4]byte
		copy(raw[:], value[4:])
		addr = netip.AddrFrom4(raw)
	case 2:
		if len(value) != 20 {
			return netip.AddrPort{}, errors.New("IPv6 endpoint length must be 20")
		}
		var raw [16]byte
		copy(raw[:], value[4:])
		addr = netip.AddrFrom16(raw)
	default:
		return netip.AddrPort{}, errors.New("IP endpoint address family is unknown")
	}
	if !validEndpointAddress(addr) {
		return netip.AddrPort{}, errors.New("IP endpoint address is invalid")
	}
	return netip.AddrPortFrom(addr, port), nil
}

func encodeEndpoint(value netip.AddrPort) ([]byte, error) {
	addr := value.Addr()
	if !value.IsValid() || value.Port() == 0 || !validEndpointAddress(addr) {
		return nil, errors.New("invalid IP endpoint")
	}
	length, afi := 20, uint16(2)
	if addr.Is4() {
		length, afi = 8, 1
	}
	result := make([]byte, length)
	binary.BigEndian.PutUint16(result[:2], afi)
	binary.BigEndian.PutUint16(result[2:4], value.Port())
	if addr.Is4() {
		raw := addr.As4()
		copy(result[4:], raw[:])
	} else {
		raw := addr.As16()
		copy(result[4:], raw[:])
	}
	return result, nil
}

func validEndpointAddress(addr netip.Addr) bool {
	return addr.IsValid() && !addr.Is4In6() && !addr.IsUnspecified() && !addr.IsMulticast() && !addr.IsLinkLocalUnicast() && addr.String() != "255.255.255.255"
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
