package message

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"
)

func TestDiscoveryControlSchemas(t *testing.T) {
	ep := netip.MustParseAddrPort("192.0.2.1:50000")
	values := []Control{
		{Code: Candidates, Round: 1, Changed: true, Endpoints: []netip.AddrPort{ep}},
		{Code: ProbeReport, Round: 1, Sequence: 7, Endpoints: []netip.AddrPort{ep}},
		{Code: RoundDone, Round: 1, Endpoints: []netip.AddrPort{ep, ep}},
		{Code: WGReady}, {Code: DiscoveryEnd}, {Code: ObserveOpen, Endpoints: []netip.AddrPort{ep}},
		{Code: ObserveReady, Key: [32]byte{1}, Endpoints: []netip.AddrPort{ep}},
	}
	for _, c := range values {
		data, err := c.Encode()
		if err != nil {
			t.Fatal(err)
		}
		m := Message{Type: DiscoveryControl, OperationID: [16]byte{2}, Data: data}
		frame, err := Encode(m)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Decode(frame)
		if err != nil || !reflect.DeepEqual(decoded, m) {
			t.Fatalf("frame: %#v %v", decoded, err)
		}
		got, err := DecodeControl(decoded.Data)
		if err != nil || !reflect.DeepEqual(got, c) {
			t.Fatalf("control: %#v %v", got, err)
		}
		if _, err = EncodeDatagram(m); err == nil {
			t.Fatal("control accepted on UDP")
		}
		for n := 0; n < len(data); n++ {
			if _, err = DecodeControl(data[:n]); err == nil {
				t.Fatal("truncated control accepted")
			}
		}
		if _, err = DecodeControl(append(data, 0)); err == nil {
			t.Fatal("trailing bytes accepted")
		}
	}
	for _, c := range []Control{{Code: WGReady, Changed: true}, {Code: Candidates, Round: 17}, {Code: ProbeReport, Sequence: 0, Endpoints: []netip.AddrPort{ep}}, {Code: ObserveReady, Endpoints: []netip.AddrPort{ep}}, {Code: RoundDone, Round: 1, Endpoints: []netip.AddrPort{ep}}} {
		if _, err := c.Encode(); err == nil {
			t.Fatalf("invalid control accepted: %#v", c)
		}
	}
	frame := make([]byte, MaxDatagramLength+1)
	binary.BigEndian.PutUint32(frame[:4], Magic)
	if _, err := DecodeDatagram(frame); err == nil {
		t.Fatal("oversize UDP accepted")
	}
}
