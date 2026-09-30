//go:build linux

package linux

import (
	"context"
	"net/netip"
	"os"
	"syscall"
	"testing"

	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Run the compiled test binary inside a disposable network namespace. Ordinary
// go test skips this; the namespace check prevents an opt-in on the host network.
func TestKernelRouteMaintenance(t *testing.T) {
	if os.Getenv("VELVET_KERNEL_ROUTE_TEST") != "1" {
		t.Skip("requires explicit disposable-netns opt-in")
	}
	currentNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initNS, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if currentNS == initNS {
		t.Fatal("refusing to test in the host network namespace")
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
				if m.Header.Type == unix.RTM_NEWROUTE && len(m.Data) >= 12 && (m.Data[5] == 201 || m.Data[5] == 202) {
					count++
				}
			}
		}
	}
	for _, name := range []string{"vdl-test", "vdl-other"} {
		must(netlink.LinkAdd(&netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name, Alias: "velvet:route-test"}, LinkType: "wireguard"}))
		dev, err := netlink.LinkByName(name)
		must(err)
		must(netlink.LinkSetAlias(dev, "velvet:route-test"))
		must(netlink.LinkSetUp(dev))
	}
	dev, err := netlink.LinkByName("vdl-test")
	must(err)
	other, err := netlink.LinkByName("vdl-other")
	must(err)
	lo, err := netlink.LinkByName("lo")
	must(err)
	must(netlink.LinkSetUp(lo))
	must(netlink.AddrAdd(lo, &netlink.Addr{IPNet: prefixIPNet(netip.MustParsePrefix("fd78:e2ee::1/128"))}))
	wanted := []managedRoute{}
	for _, prefix := range []string{"192.0.2.0/24", "2001:db8::/64"} {
		wanted = append(wanted, managedRoute{route: netlink.Route{Dst: prefixIPNet(netip.MustParsePrefix(prefix)),
			LinkIndex: dev.Attrs().Index, Table: 20000, Protocol: StaticProtocol, Type: unix.RTN_UNICAST, Scope: netlink.SCOPE_LINK}})
	}
	must(replaceStaticRoutes(wanted))
	if events() != 2 {
		t.Fatal("initial static routes did not generate exactly two events")
	}
	installed, err := routesByProtocol(StaticProtocol)
	must(err)
	for _, route := range wanted {
		if !installedRoutePresent(route.route, installed) {
			t.Fatalf("installed route did not match kernel normalization: wanted %#v; current %#v", route.route, installed)
		}
	}
	for range 20 {
		must(replaceStaticRoutes(wanted))
	}
	if events() != 0 {
		t.Fatal("unchanged static maintenance emitted route updates")
	}
	for _, route := range wanted {
		broken := route.route
		broken.LinkIndex = other.Attrs().Index
		must(netlink.RouteReplace(&broken))
		events()
		must(replaceStaticRoutes(wanted))
		if events() != 1 {
			t.Fatal("mutated static route was not repaired")
		}
		must(netlink.RouteDel(&route.route))
		events()
		must(replaceStaticRoutes(wanted))
		if events() != 1 {
			t.Fatal("deleted static route was not repaired")
		}
	}
	backend := New()
	state := &reconcile.DesiredState{FabricTableID: 20000, LoopbackV6: netip.MustParseAddr("fd78:e2ee::1"), LoopbackPoolV6: netip.MustParsePrefix("fd78:e2ee::/48")}
	plan := reconcile.LinkPlan{InterfaceName: "vdl-test", OwnerAlias: "velvet:route-test", BootstrapAddress: netip.MustParsePrefix("fe80::1/64")}
	local := []netip.Prefix{netip.MustParsePrefix("10.244.0.1/30"), netip.MustParsePrefix("fd77:1111::1/126")}
	peers := []netip.Addr{netip.MustParseAddr("198.51.100.2"), netip.MustParseAddr("fd78:e2ee::2")}
	materialize := func() { must(backend.Materialize(context.Background(), state, plan, local, peers)) }
	materialize()
	if events() != 4 {
		t.Fatal("initial Link materialization did not generate four route events")
	}
	for range 20 {
		materialize()
	}
	if events() != 0 {
		t.Fatal("unchanged Link maintenance emitted route updates")
	}
	for _, route := range materializedLinkRoutes(state, dev.Attrs().Index, local, peers) {
		must(netlink.RouteDel(&route))
		events()
		materialize()
		if events() != 1 {
			t.Fatal("deleted Link route was not repaired")
		}
	}
}
