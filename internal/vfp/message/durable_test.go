package message

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/tlv"
)

func TestDurableCodec(t *testing.T) {
	a := UID{UUID: uuid.MustParse("10000000-0000-4000-8000-000000000001")}
	b := UID{UUID: uuid.MustParse("20000000-0000-4000-8000-000000000002")}
	fixed := []FixedEndpoint{{a, netip.MustParseAddrPort("192.0.2.1:42000")}, {b, netip.MustParseAddrPort("[2001:db8::2]:42001")}}
	values := []Message{
		{Type: DurablePropose, OperationID: [16]byte{1}, FixedEndpoints: fixed, Flags: NoDurable},
		{Type: DurableSaved, OperationID: [16]byte{1}},
		{Type: DurableDecline, OperationID: [16]byte{1}, DeclineReason: DeclinePolicy, Policy: &DynamicLinkPolicy{Revision: 2}},
		{Type: DurableCheck, OperationID: [16]byte{2}, AgreementID: [16]byte{1}},
		{Type: DurableStatus, OperationID: [16]byte{2}, AgreementID: [16]byte{1}, Status: Ready},
	}
	for _, value := range values {
		encoded, err := Encode(value)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Decode(encoded)
		if err != nil || !reflect.DeepEqual(value, decoded) {
			t.Fatalf("roundtrip: %#v %v", decoded, err)
		}
		if _, err = DecodeDatagram(encoded); err == nil {
			t.Fatal("durable message accepted over UDP")
		}
		// Unused fields and excess occurrences remain ignored, as in v1.
		encoded = append(encoded, tlv.Append(nil, OperationIDTLV, []byte{99})...)
		encoded = append(encoded, tlv.Append(nil, 0x7fff, []byte{99})...)
		binary.BigEndian.PutUint16(encoded[6:8], uint16(len(encoded)))
		decoded, err = Decode(encoded)
		if err != nil || !reflect.DeepEqual(value, decoded) {
			t.Fatal("occurrence limit changed existing decoding rules", err)
		}
	}
	for _, value := range []Message{
		{Type: DurableCheck, OperationID: [16]byte{1}},
		{Type: DurableStatus, OperationID: [16]byte{1}, AgreementID: [16]byte{2}, Status: 9},
		{Type: DurablePropose, OperationID: [16]byte{1}, FixedEndpoints: []FixedEndpoint{fixed[1], fixed[0]}},
		{Type: DurablePropose, OperationID: [16]byte{1}, FixedEndpoints: []FixedEndpoint{fixed[0], fixed[0]}},
		{Type: DurableDecline, OperationID: [16]byte{1}, DeclineReason: DeclinePolicy},
	} {
		if _, err := Encode(value); err == nil {
			t.Fatalf("invalid message accepted: %#v", value)
		}
	}
}

func FuzzDurableDecode(f *testing.F) {
	for _, kind := range []Type{DurableCheck, DurableStatus, DurableSaved} {
		b, _ := Encode(Message{Type: kind, OperationID: [16]byte{1}, AgreementID: [16]byte{2}})
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Decode(b)
		if err != nil {
			return
		}
		encoded, err := Encode(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = Decode(encoded); err != nil {
			t.Fatal(err)
		}
	})
}
