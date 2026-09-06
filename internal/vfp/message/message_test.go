package message

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"reflect"
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

func TestOperationalMessagesRoundTrip(t *testing.T) {
	for _, endpoint := range []string{"192.0.2.9:49152", "[2001:db8::1]:51820"} {
		for _, kind := range []Type{EndpointObservation, DynamicLinkPropose, DynamicLinkAccept, DynamicLinkDecline} {
			if kind == DynamicLinkDecline && endpoint != "192.0.2.9:49152" {
				continue
			}
			want := Message{Type: kind}
			if kind != DynamicLinkDecline {
				want.Endpoint = netip.MustParseAddrPort(endpoint)
			}
			if kind != EndpointObservation {
				want.OperationID = [16]byte{1, 2, 3}
			}
			if kind == DynamicLinkPropose || kind == DynamicLinkAccept {
				want.WGPublicKey = [32]byte{4, 5, 6}
			}
			frame, err := Encode(want)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Decode(frame)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("%v: got %#v, want %#v: %v", kind, got, want, err)
			}
		}
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

// A literal protocol vector prevents encoder and decoder from sharing a wire-format bug.
func TestEndpointObservationWireVector(t *testing.T) {
	frame, err := hex.DecodeString("01050010000800080001c000c0000209")
	if err != nil {
		t.Fatal(err)
	}
	want := Message{Type: EndpointObservation, Endpoint: netip.MustParseAddrPort("192.0.2.9:49152")}
	got, err := Decode(frame)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("decode: %#v %v", got, err)
	}
	encoded, err := Encode(want)
	if err != nil || !bytes.Equal(encoded, frame) {
		t.Fatalf("encode: %x %v", encoded, err)
	}
}

func TestReadRejectsInvalidFraming(t *testing.T) {
	for name, frame := range map[string][]byte{
		"short-header": {1, 4, 0}, "short-body": {1, 4, 0, 5},
		"undersize": {1, 4, 0, 3}, "oversize": {1, 4, 0x10, 1}, "version": {2, 4, 0, 4},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Read(bytes.NewReader(frame)); !errors.Is(err, ErrConnection) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestDecodeRequiresEachDynamicParameter(t *testing.T) {
	for _, kind := range []Type{DynamicLinkPropose, DynamicLinkAccept} {
		for _, missing := range []uint16{OperationIDTLV, WGPublicKeyTLV, WGEndpointTLV} {
			var body []byte
			for _, field := range []struct {
				kind  uint16
				value []byte
			}{
				{OperationIDTLV, make([]byte, 16)}, {WGPublicKeyTLV, append([]byte{1}, make([]byte, 31)...)},
				{WGEndpointTLV, []byte{0, 1, 0, 1, 192, 0, 2, 1}},
			} {
				if field.kind != missing {
					body = tlv.Append(body, field.kind, field.value)
				}
			}
			frame := append([]byte{1, byte(kind), 0, byte(4 + len(body))}, body...)
			if _, err := Decode(frame); !errors.Is(err, ErrFrame) {
				t.Fatalf("kind %d missing %d: %v", kind, missing, err)
			}
		}
	}
}

func FuzzMessageDecode(f *testing.F) {
	for _, seed := range []string{"01040004", "01050010000800080001c000c0000209", "01ff0004", "01010004"} {
		data, _ := hex.DecodeString(seed)
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxFrameLength+1 {
			return
		}
		_, _ = Read(bytes.NewReader(data))
		value, err := Decode(data)
		if err != nil {
			return
		}
		encoded, err := Encode(value)
		if err != nil {
			t.Fatalf("decoded message cannot encode: %v", err)
		}
		again, err := Decode(encoded)
		if err != nil || !reflect.DeepEqual(value, again) {
			t.Fatalf("unstable message: %#v => %#v: %v", value, again, err)
		}
	})
}
