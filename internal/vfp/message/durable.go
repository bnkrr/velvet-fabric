package message

import (
	"bytes"
	"encoding/binary"
	"net/netip"

	"github.com/velvet-fabric/velvet-fabric/internal/tlv"
)

type Flags uint32

const NoDurable Flags = 1

type Status uint8

const (
	Ready Status = iota
	NotReady
	Absent
)

// FixedEndpoint identifies the owner of an endpoint, not the message sender.
// Entries are ordered by UUID. Authentication still comes from the session.
type FixedEndpoint struct {
	UID      UID            `json:"uid"`
	Endpoint netip.AddrPort `json:"endpoint"`
}

func (t Type) IsDurable() bool { return t >= DurablePropose && t <= DurableStatus }

func durableOccurrences(t Type, field uint16) int {
	switch field {
	case OperationIDTLV:
		if t == DurableCheck || t == DurableStatus {
			return 2
		}
		return 1
	case NodeUIDTLV, WGEndpointTLV:
		if t == DurablePropose {
			return 2
		}
	case FlagsTLV:
		if t == DurablePropose {
			return 1
		}
	case StatusTLV:
		if t == DurableStatus {
			return 1
		}
	case DeclineReasonTLV, DynamicLinkPolicyTLV:
		if t == DurableDecline {
			return 1
		}
	}
	return 0
}

func decodeDurable(kind Type, body []byte) (Message, error) {
	m := Message{Type: kind}
	fields := map[uint16][][]byte{}
	cursor := tlv.NewCursor(body)
	for {
		v, ok, err := cursor.Next()
		if err != nil {
			return Message{}, ErrFrame
		}
		if !ok {
			break
		}
		if len(fields[v.Type]) < durableOccurrences(kind, v.Type) {
			fields[v.Type] = append(fields[v.Type], v.Value)
		}
	}
	ids := fields[OperationIDTLV]
	if len(ids) != durableOccurrences(kind, OperationIDTLV) {
		return Message{}, ErrFrame
	}
	if parseOperationID(ids[0], &m.OperationID) != nil || allZero(m.OperationID[:]) {
		return Message{}, ErrFrame
	}
	if len(ids) == 2 {
		if parseOperationID(ids[1], &m.AgreementID) != nil || allZero(m.AgreementID[:]) {
			return Message{}, ErrFrame
		}
	}
	switch kind {
	case DurablePropose:
		uids, endpoints := fields[NodeUIDTLV], fields[WGEndpointTLV]
		if len(uids) == 0 || len(uids) != len(endpoints) {
			return Message{}, ErrFrame
		}
		for i := range uids {
			uid, err := parseUID(uids[i])
			if err != nil {
				return Message{}, ErrFrame
			}
			ep, err := parseEndpoint(endpoints[i])
			if err != nil {
				return Message{}, ErrFrame
			}
			if i > 0 && bytes.Compare(m.FixedEndpoints[i-1].UID.UUID[:], uid.UUID[:]) >= 0 {
				return Message{}, ErrFrame
			}
			m.FixedEndpoints = append(m.FixedEndpoints, FixedEndpoint{uid, ep})
		}
		if f := fields[FlagsTLV]; len(f) != 0 {
			if len(f[0]) != 4 {
				return Message{}, ErrFrame
			}
			m.Flags = Flags(binary.BigEndian.Uint32(f[0]))
		}
	case DurableStatus:
		v := fields[StatusTLV]
		if len(v) != 1 || len(v[0]) != 1 || v[0][0] > byte(Absent) {
			return Message{}, ErrFrame
		}
		m.Status = Status(v[0][0])
	case DurableDecline:
		v := fields[DeclineReasonTLV]
		if len(v) != 1 || len(v[0]) != 1 || v[0][0] > byte(DeclinePolicy) {
			return Message{}, ErrFrame
		}
		m.DeclineReason = DeclineReason(v[0][0])
		if p := fields[DynamicLinkPolicyTLV]; len(p) != 0 {
			var err error
			m.Policy, err = parseDynamicLinkPolicy(p[0])
			if err != nil {
				return Message{}, err
			}
		}
		if m.DeclineReason == DeclinePolicy && (m.Policy == nil || m.Policy.Accept) {
			return Message{}, ErrFrame
		}
	}
	return m, nil
}

func encodeDurable(m Message) ([]byte, error) {
	b := tlv.Append(nil, OperationIDTLV, m.OperationID[:])
	if m.Type == DurableCheck || m.Type == DurableStatus {
		b = tlv.Append(b, OperationIDTLV, m.AgreementID[:])
	}
	switch m.Type {
	case DurablePropose:
		if len(m.FixedEndpoints) < 1 || len(m.FixedEndpoints) > 2 {
			return nil, ErrFrame
		}
		for _, fixed := range m.FixedEndpoints {
			uid, err := encodeUID(fixed.UID)
			if err != nil {
				return nil, err
			}
			ep, err := encodeEndpoint(fixed.Endpoint)
			if err != nil {
				return nil, err
			}
			b = tlv.Append(b, NodeUIDTLV, uid)
			b = tlv.Append(b, WGEndpointTLV, ep)
		}
		if m.Flags != 0 {
			var raw [4]byte
			binary.BigEndian.PutUint32(raw[:], uint32(m.Flags))
			b = tlv.Append(b, FlagsTLV, raw[:])
		}
	case DurableStatus:
		b = tlv.Append(b, StatusTLV, []byte{byte(m.Status)})
	case DurableDecline:
		b = tlv.Append(b, DeclineReasonTLV, []byte{byte(m.DeclineReason)})
		if m.Policy != nil {
			v, err := encodeDynamicLinkPolicy(m.Policy)
			if err != nil {
				return nil, err
			}
			b = tlv.Append(b, DynamicLinkPolicyTLV, v)
		}
	}
	_, err := decodeDurable(m.Type, b)
	return b, err
}
