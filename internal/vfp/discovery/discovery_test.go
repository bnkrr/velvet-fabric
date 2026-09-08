package discovery

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/velvet-fabric/velvet-fabric/internal/tlv"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
)

func TestHelloRoundTrip(t *testing.T) {
	for _, want := range []MessageType{Hello, HelloAck} {
		packet, err := Encode(want)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(packet[:])
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("type = %d, want %d", got, want)
		}
	}
}

func TestDiscoveryUsesCommonWireFormat(t *testing.T) {
	for kind, vector := range map[MessageType]string{
		Hello:    "VFP\x00\x01\x09\x00\x08",
		HelloAck: "VFP\x00\x01\x0a\x00\x08",
	} {
		packet, err := Encode(kind)
		if err != nil || !bytes.Equal(packet, []byte(vector)) {
			t.Fatalf("encode %d: %x %v", kind, packet, err)
		}
		decoded, err := message.Decode(packet)
		if err != nil || decoded.Type != kind {
			t.Fatalf("common decode: %#v %v", decoded, err)
		}
		// Known-but-unused TLVs need structural validity, not field-value validity.
		packet = tlv.Append(packet, message.NodeUIDTLV, []byte("unused"))
		packet = tlv.Append(packet, 0xff00, nil)
		binary.BigEndian.PutUint16(packet[6:8], uint16(len(packet)))
		if got, err := Parse(packet); err != nil || got != kind {
			t.Fatalf("ignored TLVs rejected: %d %v", got, err)
		}
	}
}

func TestEncodeRejectsUnknownType(t *testing.T) {
	if _, err := Encode(99); !errors.Is(err, ErrInvalidHello) {
		t.Fatalf("Encode unknown type = %v", err)
	}
}

func TestHelloRejectsMalformedDatagrams(t *testing.T) {
	tests := [][]byte{
		nil,
		[]byte("VFPD\x01\x01\x00\x08"), // Old discovery is not a fallback.
		[]byte("VFPD\x01\x02\x00\x08"),
		[]byte("NOPE\x01\x09\x00\x08"),
		[]byte("VFP\x00\x02\x09\x00\x08"),
		[]byte("VFP\x00\x01\x03\x00\x08"), // TCP-only message.
		[]byte("VFP\x00\x01\x09\x00\x09"),
	}
	for _, packet := range tests {
		if _, err := Parse(packet); !errors.Is(err, ErrInvalidHello) {
			t.Fatalf("Parse(%x) = %v", packet, err)
		}
	}
}

func FuzzParseNeverPanics(f *testing.F) {
	for _, messageType := range []MessageType{Hello, HelloAck} {
		packet, _ := Encode(messageType)
		f.Add(packet[:])
	}
	f.Add([]byte("not discovery"))
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, _ = Parse(packet)
	})
}
