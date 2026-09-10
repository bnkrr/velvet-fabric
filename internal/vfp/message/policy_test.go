package message

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/tlv"
)

func TestPolicyMessagesAndDeclineSchemas(t *testing.T) {
	uid := &UID{UUID: uuid.MustParse("10000000-0000-4000-8000-000000000001")}
	for _, tc := range []struct {
		name   string
		m      Message
		length int
		valid  bool
	}{
		{"query", Message{Type: PolicyQuery, UID: uid}, 28, true},
		{"update", Message{Type: PolicyUpdate, UID: uid, Policy: &DynamicLinkPolicy{3, true}}, 41, true},
		{"update denied", Message{Type: PolicyUpdate, UID: uid, Policy: &DynamicLinkPolicy{4, false}}, 41, true},
		{"ordinary absent", Message{Type: DynamicLinkDecline}, 33, true},
		{"ordinary snapshot", Message{Type: DynamicLinkDecline, Policy: &DynamicLinkPolicy{2, true}}, 46, true},
		{"ordinary denied snapshot", Message{Type: DynamicLinkDecline, Policy: &DynamicLinkPolicy{2, false}}, 46, true},
		{"policy denied", Message{Type: DynamicLinkDecline, DeclineReason: DeclinePolicy, Policy: &DynamicLinkPolicy{2, false}}, 46, true},
		{"policy missing", Message{Type: DynamicLinkDecline, DeclineReason: DeclinePolicy}, 0, false},
		{"policy allowed", Message{Type: DynamicLinkDecline, DeclineReason: DeclinePolicy, Policy: &DynamicLinkPolicy{2, true}}, 0, false},
		{"unknown reason", Message{Type: DynamicLinkDecline, DeclineReason: 2}, 0, false},
		{"zero revision", Message{Type: PolicyUpdate, UID: uid, Policy: &DynamicLinkPolicy{}}, 0, false},
		{"missing update", Message{Type: PolicyUpdate, UID: uid}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := Encode(tc.m)
			if !tc.valid {
				if err == nil {
					t.Fatal("encoded invalid message")
				}
				return
			}
			if err != nil || len(b) != tc.length {
				t.Fatalf("encode: %v, length %d", err, len(b))
			}
			got, err := Decode(b)
			if err != nil || !reflect.DeepEqual(got, tc.m) {
				t.Fatalf("roundtrip: %#v %v", got, err)
			}
			if tc.m.Type.IsPolicy() {
				if _, err := DecodeDatagram(b); err != nil {
					t.Fatal(err)
				}
				if err := Write(&bytes.Buffer{}, tc.m); err == nil {
					t.Fatal("policy allowed on TCP")
				}
			} else if _, err := DecodeDatagram(b); err == nil {
				t.Fatal("Decline allowed on UDP")
			}
		})
	}
}

func TestPolicyMalformedAndExtensionRules(t *testing.T) {
	uid := &UID{UUID: uuid.New()}
	valid, _ := Encode(Message{Type: PolicyUpdate, UID: uid, Policy: &DynamicLinkPolicy{7, true}})
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { b[len(b)-1] = 2; return b },
		func(b []byte) []byte { clear(b[len(b)-9 : len(b)-1]); return b },
		func(b []byte) []byte { binary.BigEndian.PutUint16(b[30:32], 8); return b },
		func(b []byte) []byte { b = b[:28]; binary.BigEndian.PutUint16(b[6:8], uint16(len(b))); return b },
	} {
		if _, err := Decode(mutate(bytes.Clone(valid))); err == nil {
			t.Fatal("accepted malformed policy")
		}
	}
	// First selected singleton wins; ignored extensions still need valid bounds.
	b := tlv.Append(bytes.Clone(valid), DynamicLinkPolicyTLV, []byte{99})
	b = tlv.Append(b, 0xeeee, []byte{1, 2, 3})
	binary.BigEndian.PutUint16(b[6:8], uint16(len(b)))
	if m, err := Decode(b); err != nil || m.Policy.Revision != 7 {
		t.Fatalf("extensions: %v", err)
	}
	// The old operation-only Decline cannot silently masquerade as ORDINARY.
	b, _ = Encode(Message{Type: DynamicLinkDecline})
	b = b[:28]
	binary.BigEndian.PutUint16(b[6:8], uint16(len(b)))
	if _, err := Decode(b); err == nil {
		t.Fatal("accepted unclassified legacy Decline")
	}
}

func TestPolicyValidatesButIgnoresDisplayName(t *testing.T) {
	uid := []byte{0x10, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 1}
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b, Magic)
	b[4] = Version
	b[5] = byte(PolicyQuery)
	b = tlv.Append(b, NodeUIDTLV, append(uid, []byte("peer")...))
	binary.BigEndian.PutUint16(b[6:8], uint16(len(b)))
	m, err := Decode(b)
	if err != nil || m.UID.Name != "" {
		t.Fatalf("ignored name: %#v %v", m, err)
	}
	b[len(b)-1] = '!'
	if _, err := Decode(b); err == nil {
		t.Fatal("invalid optional name accepted")
	}
}
