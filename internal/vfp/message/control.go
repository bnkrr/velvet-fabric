package message

import (
	"encoding/binary"
	"net/netip"
)

type ControlCode uint8

const (
	Candidates ControlCode = 1 + iota
	ProbeReport
	RoundDone
	WGReady
	DiscoveryEnd
	ObserveOpen
	ObserveReady
)

type Control struct {
	Code      ControlCode
	Round     uint16
	Sequence  uint64
	Changed   bool
	Key       [32]byte
	Endpoints []netip.AddrPort
}

func (c Control) Encode() ([]byte, error) {
	if len(c.Endpoints) > 32 {
		return nil, ErrFrame
	}
	b := make([]byte, 45)
	b[0] = byte(c.Code)
	binary.BigEndian.PutUint16(b[1:3], c.Round)
	binary.BigEndian.PutUint64(b[3:11], c.Sequence)
	if c.Changed {
		b[11] = 1
	}
	copy(b[12:44], c.Key[:])
	b[44] = byte(len(c.Endpoints))
	for _, ep := range c.Endpoints {
		v, err := encodeEndpoint(ep)
		if err != nil {
			return nil, err
		}
		b = append(b, byte(len(v)))
		b = append(b, v...)
	}
	if _, err := DecodeControl(b); err != nil {
		return nil, err
	}
	return b, nil
}
func DecodeControl(b []byte) (Control, error) {
	var c Control
	if len(b) < 45 || b[11] > 1 || b[44] > 32 {
		return c, ErrFrame
	}
	c.Code = ControlCode(b[0])
	c.Round = binary.BigEndian.Uint16(b[1:3])
	c.Sequence = binary.BigEndian.Uint64(b[3:11])
	c.Changed = b[11] == 1
	copy(c.Key[:], b[12:44])
	count := int(b[44])
	b = b[45:]
	for range count {
		if len(b) < 1 || len(b) < 1+int(b[0]) {
			return Control{}, ErrFrame
		}
		n := int(b[0])
		ep, err := parseEndpoint(b[1 : 1+n])
		if err != nil {
			return Control{}, err
		}
		c.Endpoints = append(c.Endpoints, ep)
		b = b[1+n:]
	}
	if len(b) != 0 {
		return Control{}, ErrFrame
	}
	keyZero := c.Key == [32]byte{}
	valid := false
	switch c.Code {
	case Candidates:
		valid = c.Round >= 1 && c.Round <= 16 && c.Sequence == 0 && keyZero
	case ProbeReport:
		valid = c.Round <= 16 && c.Sequence > 0 && c.Sequence <= 12000 && count == 1 && !c.Changed && keyZero
	case RoundDone:
		valid = c.Round >= 1 && c.Round <= 16 && c.Sequence == 0 && (count == 0 || count == 2) && !c.Changed && keyZero
	case WGReady, DiscoveryEnd:
		valid = c.Round == 0 && c.Sequence == 0 && count == 0 && !c.Changed && keyZero
	case ObserveOpen:
		valid = c.Round == 0 && c.Sequence == 0 && count == 1 && !c.Changed && keyZero
	case ObserveReady:
		valid = c.Round == 0 && c.Sequence == 0 && count >= 1 && count <= 2 && !c.Changed && !keyZero
	}
	if !valid {
		return Control{}, ErrFrame
	}
	return c, nil
}

// EndpointValue is the shared AFI/port/address representation.
func EndpointValue(ep netip.AddrPort) ([]byte, error)     { return encodeEndpoint(ep) }
func ParseEndpointValue(b []byte) (netip.AddrPort, error) { return parseEndpoint(b) }
