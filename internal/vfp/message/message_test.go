package message

import (
	"encoding/binary"
	"testing"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/tlv"
)

func TestMessageRoundTripAndUnknownTLV(t *testing.T) {
	want := Message{Type: Open, UID: &UID{UUID: uuid.New(), Name: "node1"}}
	frame, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	body := tlv.Append(frame[4:], 0xff00, []byte("ignored"))
	frame = append(frame[:4], body...)
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(frame)))
	got, err := Decode(frame)
	if err != nil {
		t.Fatal(err)
	}
	if got.UID.UUID != want.UID.UUID || got.UID.Name != want.UID.Name {
		t.Fatalf("round trip mismatch: %#v", got)
	}
}

func TestDuplicateSingletonSelectsFirst(t *testing.T) {
	first, second := uuid.New(), uuid.New()
	body := tlv.Append(nil, NodeUIDTLV, first[:])
	body = tlv.Append(body, NodeUIDTLV, second[:])
	frame := []byte{Version, byte(Open), 0, 0}
	frame = append(frame, body...)
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(frame)))
	got, err := Decode(frame)
	if err != nil {
		t.Fatal(err)
	}
	if got.UID.UUID != first {
		t.Fatal("later singleton occurrence replaced first")
	}
}

func TestProposalMayBeEmpty(t *testing.T) {
	frame, err := Encode(Message{Type: LinkPropose})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(frame)
	if err != nil || got.LinkPrefixV4.IsValid() {
		t.Fatal("empty proposal rejected")
	}
	_, err = Encode(Message{Type: NodeState})
	if err == nil {
		t.Fatal("empty NODE_STATE accepted")
	}
}
