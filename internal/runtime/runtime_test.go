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
}
