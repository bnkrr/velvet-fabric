package message

import (
	"encoding/binary"
	"net/netip"
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

func TestDynamicMessagesRoundTrip(t *testing.T) {
	operation := [16]byte{1, 2, 3}
	key := [32]byte{4, 5, 6}
	endpoint := netip.MustParseAddrPort("[2001:db8::1]:51820")
	for _, kind := range []Type{DynamicLinkPropose, DynamicLinkAccept} {
		frame, err := Encode(Message{Type: kind, OperationID: operation, WGPublicKey: key, Endpoint: endpoint})
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(frame)
		if err != nil {
			t.Fatal(err)
		}
		if got.OperationID != operation || got.WGPublicKey != key || got.Endpoint != endpoint {
			t.Fatalf("dynamic message mismatch: %#v", got)
		}
	}
	frame, err := Encode(Message{Type: DynamicLinkDecline, OperationID: operation})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(frame)
	if err != nil || got.OperationID != operation {
		t.Fatalf("decline mismatch: %#v %v", got, err)
	}
}

func TestEndpointObservationRoundTrip(t *testing.T) {
	want := netip.MustParseAddrPort("192.0.2.9:49152")
	frame, err := Encode(Message{Type: EndpointObservation, Endpoint: want})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(frame)
	if err != nil || got.Endpoint != want {
		t.Fatalf("observation mismatch: %#v %v", got, err)
	}
}

func TestObservationAndCandidateUseWGEndpointTLV(t *testing.T) {
	operation := [16]byte{1}
	key := [32]byte{2}
	endpoint := netip.MustParseAddrPort("192.0.2.9:49152")
	for _, value := range []Message{
		{Type: EndpointObservation, Endpoint: endpoint},
		{Type: DynamicLinkPropose, OperationID: operation, WGPublicKey: key, Endpoint: endpoint},
		{Type: DynamicLinkAccept, OperationID: operation, WGPublicKey: key, Endpoint: endpoint},
	} {
		frame, err := Encode(value)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		cursor := tlv.NewCursor(frame[HeaderLength:])
		for {
			view, ok, err := cursor.Next()
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				break
			}
			if view.Type == WGEndpointTLV {
				found = true
			}
			if view.Type == 0x0009 {
				t.Fatalf("message %x used reserved endpoint TLV 0x0009", value.Type)
			}
		}
		if !found {
			t.Fatalf("message %x omitted WG_ENDPOINT", value.Type)
		}
	}

	endpointValue, err := encodeEndpoint(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	body := tlv.Append(nil, OperationIDTLV, operation[:])
	body = tlv.Append(body, WGPublicKeyTLV, key[:])
	body = tlv.Append(body, 0x0009, endpointValue)
	frame := []byte{Version, byte(DynamicLinkPropose), 0, 0}
	frame = append(frame, body...)
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(frame)))
	if _, err := Decode(frame); err == nil {
		t.Fatal("reserved TLV 0x0009 was accepted as WG_ENDPOINT")
	}
}

func TestDynamicMessageRequiresCompleteParameters(t *testing.T) {
	if _, err := Encode(Message{Type: EndpointObservation, Endpoint: netip.MustParseAddrPort("[fe80::1]:1")}); err == nil {
		t.Fatal("scoped IPv6 endpoint without a zone was accepted")
	}
	if _, err := Encode(Message{Type: DynamicLinkPropose, Endpoint: netip.MustParseAddrPort("192.0.2.1:1")}); err == nil {
		t.Fatal("zero public key was accepted")
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
