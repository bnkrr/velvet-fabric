//go:build linux

package runtime

import (
	"context"
	"net/netip"
	"os"
	"syscall"
	"testing"

	"github.com/velvet-fabric/velvet-fabric/internal/linux"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestKernelParallelFallbacks(t *testing.T) {
	if os.Getenv("VELVET_KERNEL_ROUTE_TEST") != "1" {
		t.Skip("requires explicit disposable-netns opt-in")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	init, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if self == init {
		t.Fatal("refusing the host network namespace")
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	must(err)
	t.Cleanup(func() { unix.Close(fd) })
	must(unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 0x40 | 0x400}))
	events := func() int {
		t.Helper()
		count := 0
		data := make([]byte, 65536)
		for {
			n, _, err := unix.Recvfrom(fd, data, 0)
			if err == unix.EAGAIN {
				return count
			}
			if err == unix.EINTR {
				continue
			}
			must(err)
			messages, err := syscall.ParseNetlinkMessage(data[:n])
			must(err)
			for _, m := range messages {
				if (m.Header.Type == unix.RTM_NEWROUTE || m.Header.Type == unix.RTM_DELROUTE) && len(m.Data) >= 12 && m.Data[5] == 202 {
					count++
				}
			}
		}
	}
	lo, err := netlink.LinkByName("lo")
	must(err)
	must(netlink.LinkSetUp(lo))
	addr, err := netlink.ParseAddr("fd78:e2ee::1/128")
	must(err)
	must(netlink.AddrAdd(lo, addr))
	peers := []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("fd78:e2ee::2")}
	r := &Runner{Desired: &reconcile.DesiredState{FabricTableID: 20000, LoopbackV6: netip.MustParseAddr("fd78:e2ee::1"), LoopbackPoolV6: netip.MustParsePrefix("fd78:e2ee::/48")}, Reconciler: reconcile.New(linux.New()), states: make(map[string]materializedState)}
	r.dynamic = newDynamicLinkEngine(r)
	for i, name := range []string{"test-b", "test-a"} {
		must(netlink.LinkAdd(&netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name}, LinkType: "wireguard"}))
		dev, err := netlink.LinkByName(name)
		must(err)
		must(netlink.LinkSetAlias(dev, "velvet:parallel-test"))
		must(netlink.LinkSetUp(dev))
		local := []netip.Prefix{netip.MustParsePrefix([]string{"10.244.0.1/30", "10.244.0.5/30"}[i]), netip.MustParsePrefix([]string{"fd77:1111::1/126", "fd77:1111::5/126"}[i])}
		state := materializedState{desired: reconcile.LinkPlan{InterfaceName: name, OwnerAlias: "velvet:parallel-test", BootstrapAddress: netip.MustParsePrefix("fe80::1/64")}, local: local, peers: peers, committed: true, active: true}
		must(r.materializeLink(context.Background(), state.desired, local, peers))
		r.states[name] = state
	}
	maintain := func() {
		t.Helper()
		if !r.maintainMaterialized(context.Background()) {
			t.Fatal("maintenance failed")
		}
	}
	check := func(name string) {
		t.Helper()
		dev, err := netlink.LinkByName(name)
		must(err)
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: 20000, Protocol: 202}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL)
		must(err)
		count := 0
		for _, route := range routes {
			if route.Priority == reconcile.NeighborFallbackPriority {
				count++
				if route.LinkIndex != dev.Attrs().Index {
					t.Fatalf("fallback points to %d, want %s", route.LinkIndex, name)
				}
			}
		}
		if count != 2 {
			t.Fatalf("got %d fallbacks, want both families", count)
		}
	}
	maintain()
	events()
	check("test-a")
	for range 20 {
		maintain()
	}
	if n := events(); n != 0 {
		t.Fatalf("parallel maintenance emitted %d writes", n)
	}
	// Recommit of the non-owner cannot steal the peer fallback. Both Links keep
	// their full peer metadata even though only one owns the kernel fallback.
	other := r.states["test-b"]
	must(r.materializeLink(context.Background(), other.desired, other.local, other.peers))
	if events() != 0 {
		t.Fatal("non-owner recommit rewrote fallback")
	}
	// Loss of the control session alone preserves the owner.
	owner := r.states["test-a"]
	owner.active = false
	r.states["test-a"] = owner
	maintain()
	check("test-a")
	if events() != 0 {
		t.Fatal("control loss changed fallback")
	}
	// External deletion is repaired, without rewriting unaffected entries.
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: 20000, Protocol: 202}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL)
	must(err)
	for _, route := range routes {
		if route.Priority == reconcile.NeighborFallbackPriority {
			must(netlink.RouteDel(&route))
		}
	}
	events()
	maintain()
	check("test-a")
	if events() != 2 {
		t.Fatal("missing fallbacks were not repaired once each")
	}
	// Revoking the owner's adjacency elects the remaining committed Link.
	must(r.materializeLink(context.Background(), owner.desired, owner.local, nil))
	owner.peers = nil
	owner.committed = false
	r.states["test-a"] = owner
	maintain()
	check("test-b")
	events()
	for range 5 {
		maintain()
	}
	if events() != 0 {
		t.Fatal("fallback takeover did not stabilize")
	}
	// Restore the earlier candidate, then delete its kernel generation and
	// bookkeeping. The surviving Link must take over without a restart.
	must(r.materializeLink(context.Background(), owner.desired, owner.local, peers))
	owner.peers = peers
	owner.committed = true
	r.states["test-a"] = owner
	maintain()
	check("test-a")
	dev, err := netlink.LinkByName("test-a")
	must(err)
	must(netlink.LinkDel(dev))
	delete(r.states, "test-a")
	maintain()
	check("test-b")
	events()
	for range 5 {
		maintain()
	}
	if events() != 0 {
		t.Fatal("fallback after interface deletion did not stabilize")
	}
}
