package discovery

import (
	"errors"
	"testing"
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

func TestEncodeRejectsUnknownType(t *testing.T) {
	if _, err := Encode(99); !errors.Is(err, ErrInvalidHello) {
		t.Fatalf("Encode unknown type = %v", err)
	}
}

func TestHelloRejectsMalformedDatagrams(t *testing.T) {
	tests := [][]byte{
		nil,
		[]byte("VFPD\x01\x00\x00"),
		[]byte("NOPE\x01\x00\x00\x08"),
		[]byte("VFPD\x02\x00\x00\x08"),
		[]byte("VFPD\x01\x03\x00\x08"),
		[]byte("VFPD\x01\x00\x00\x09"),
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
