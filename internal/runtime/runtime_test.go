package runtime

import (
	"net/netip"
	"testing"
)

func TestTCPRoleUsesDiscoveredAddresses(t *testing.T) {
	lower := netip.MustParseAddr("fe80::10")
	higher := netip.MustParseAddr("fe80::20")
	if !shouldDial(lower, higher) {
		t.Fatal("lower discovered address did not become dialer")
	}
	if shouldDial(higher, lower) {
		t.Fatal("higher discovered address became dialer")
	}
	if !shouldAcceptDiscovered(higher, lower) {
		t.Fatal("higher address did not accept the lower address before a reverse Hello")
	}
	for _, remote := range []netip.Addr{higher, netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1")} {
		if shouldAcceptDiscovered(lower, remote) {
			t.Fatalf("accepted invalid or dialer-side source %s", remote)
		}
	}
}
