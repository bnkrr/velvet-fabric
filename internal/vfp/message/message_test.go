package message

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"testing/iotest"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/tlv"
)

func TestMessageRoundTripAndUnknownTLV(t *testing.T) {
	want := Message{Type: Open, UID: &UID{UUID: uuid.New(), Name: "node1"}}
	frame, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	body := tlv.Append(frame[HeaderLength:], 0xff00, []byte("ignored"))
	frame = append(frame[:HeaderLength], body...)
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(frame)))
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
			if view.Type == 0x000c {
				t.Fatalf("message %x used reserved endpoint TLV 0x000c", value.Type)
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
	body = tlv.Append(body, ProbeKeyTLV, make([]byte, 32))
	body = tlv.Append(body, 0x000c, endpointValue)
	frame := []byte{0x56, 0x46, 0x50, 0, 1, byte(DynamicLinkPropose), 0, 0}
	frame = append(frame, body...)
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(frame)))
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
	frame := []byte{0x56, 0x46, 0x50, 0, 1, byte(Open), 0, 0}
	frame = append(frame, body...)
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(frame)))
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
	frame, err := hex.DecodeString("5646500001050014000800080001c000c0000209")
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
		"short-header":     []byte("VFP\x00\x01\x04\x00"),
		"short-body":       []byte("VFP\x00\x01\x04\x00\x09"),
		"undersize":        []byte("VFP\x00\x01\x04\x00\x07"),
		"oversize":         []byte("VFP\x00\x01\x04\x10\x01"),
		"version":          []byte("VFP\x00\x02\x04\x00\x08"),
		"magic":            []byte("NOPE\x01\x04\x00\x08"),
		"legacy-tcp":       {1, 4, 0, 4},
		"legacy-discovery": []byte("VFPD\x01\x01\x00\x08"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Read(bytes.NewReader(frame)); !errors.Is(err, ErrConnection) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestReadValidatesHeaderBeforeBody(t *testing.T) {
	for _, header := range []string{"NOPE\x01\x04\x00\x0c", "VFP\x00\x02\x04\x00\x0c"} {
		reader := bytes.NewReader(append([]byte(header), []byte("body")...))
		if _, err := Read(reader); !errors.Is(err, ErrConnection) || reader.Len() != 4 {
			t.Fatalf("invalid header consumed body: remaining=%d err=%v", reader.Len(), err)
		}
	}
}

func TestReadPreservesStreamBoundaries(t *testing.T) {
	first := []byte("VFP\x00\x01\x04\x00\x08")
	second, _ := hex.DecodeString("5646500001050014000800080001c000c0000209")
	stream := append(bytes.Clone(first), second...)
	for _, fragmented := range []bool{false, true} {
		reader := bytes.NewReader(stream)
		for _, want := range [][]byte{first, second} {
			var got []byte
			var err error
			if fragmented {
				got, err = Read(iotest.OneByteReader(reader))
			} else {
				got, err = Read(reader)
			}
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("fragmented=%v got=%x err=%v", fragmented, got, err)
			}
		}
		if reader.Len() != 0 {
			t.Fatal("stream not fully consumed")
		}
	}
}

func TestDatagramBoundariesAndContext(t *testing.T) {
	hello := []byte("VFP\x00\x01\x09\x00\x08")
	for name, packet := range map[string][]byte{
		"concatenated": append(bytes.Clone(hello), hello...),
		"truncated":    hello[:7],
		"tcp-only":     []byte("VFP\x00\x01\x04\x00\x08"),
		"unknown-type": []byte("VFP\x00\x01\xff\x00\x08"),
		"bad-tlv":      []byte("VFP\x00\x01\x09\x00\x0c\xff\x00\x00\x01"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeDatagram(packet); !errors.Is(err, ErrFrame) {
				t.Fatalf("accepted invalid datagram: %v", err)
			}
		})
	}
	// Unused fields still follow the shared TLV rules, including the UDP cap.
	for _, size := range []int{MaxDatagramLength, MaxDatagramLength + 1} {
		packet := tlv.Append(bytes.Clone(hello), 0xff00, make([]byte, size-HeaderLength-4))
		binary.BigEndian.PutUint16(packet[6:8], uint16(size))
		if _, err := Decode(packet); err != nil {
			t.Fatalf("structurally valid common frame rejected: %v", err)
		}
		_, err := DecodeDatagram(packet)
		if (err == nil) != (size == MaxDatagramLength) {
			t.Fatalf("UDP size %d: %v", size, err)
		}
	}
	if _, err := EncodeDatagram(Message{Type: LinkAccept}); err == nil {
		t.Fatal("encoded TCP-only message over UDP")
	}
	var output bytes.Buffer
	if err := Write(&output, Message{Type: DiscoveryHello}); err == nil || output.Len() != 0 {
		t.Fatal("wrote discovery to TCP")
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
			frame := append([]byte{0x56, 0x46, 0x50, 0, 1, byte(kind), 0, byte(HeaderLength + len(body))}, body...)
			if _, err := Decode(frame); !errors.Is(err, ErrFrame) {
				t.Fatalf("kind %d missing %d: %v", kind, missing, err)
			}
		}
	}
}

func FuzzMessageDecode(f *testing.F) {
	for _, seed := range []string{"5646500001040008", "5646500001050014000800080001c000c0000209", "5646500001ff0008", "5646500001010008", "5646500001090008", "01040004"} {
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
