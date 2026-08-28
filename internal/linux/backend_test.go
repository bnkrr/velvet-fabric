//go:build linux

package linux

import (
	"net/netip"
	"testing"
)

func TestPrefixIPNetPreservesHostAddress(t *testing.T) {
	prefix := netip.MustParsePrefix("10.77.0.1/30")
	converted := prefixIPNet(prefix)
	if got, want := converted.IP.String(), "10.77.0.1"; got != want {
		t.Fatalf("converted IP = %q, want %q", got, want)
	}
}
