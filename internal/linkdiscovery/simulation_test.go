package linkdiscovery

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/inference"
)

// This model is deliberately test-only. Its ground truth is available to the
// test, never to Infer or Run. The simulated control channel is out of band;
// accepting a UDP probe emits a report without sending a reverse UDP packet.
type mappingKind string
type filteringKind string
type allocationKind string

const (
	eim        mappingKind    = "EIM"
	adm        mappingKind    = "ADM"
	apdm       mappingKind    = "APDM"
	eif        filteringKind  = "EIF"
	adf        filteringKind  = "ADF"
	apdf       filteringKind  = "APDF"
	preserve   allocationKind = "preserve"
	offset     allocationKind = "offset"
	sequential allocationKind = "sequential"
	random     allocationKind = "random"
)

type mappingKey struct {
	local netip.AddrPort
	scope netip.AddrPort
}

type binding struct {
	local       netip.AddrPort
	public      netip.AddrPort
	permissions map[netip.AddrPort]bool
}

type simNode struct {
	ip         netip.Addr
	publicIP   netip.Addr
	mapping    mappingKind
	filter     filteringKind
	allocation allocationKind
	next       uint16
	rng        uint32
	bindings   map[mappingKey]*binding
	byPublic   map[netip.AddrPort]*binding
}

func (n *simNode) outbound(local, remote netip.AddrPort) *binding {
	key := mappingKey{local: local}
	switch n.mapping {
	case adm:
		key.scope = netip.AddrPortFrom(remote.Addr(), 0)
	case apdm:
		key.scope = remote
	}
	b := n.bindings[key]
	if b == nil {
		port := local.Port()
		if n.allocation == offset {
			port = uint16(1024 + (int(local.Port())+7000-1024)%64000)
		}
		for {
			switch n.allocation {
			case sequential:
				port = n.next
				n.next++
			case random:
				n.rng = n.rng*1664525 + 1013904223
				port = uint16(1024 + n.rng%64000)
			}
			public := netip.AddrPortFrom(n.publicIP, port)
			if n.byPublic[public] == nil {
				b = &binding{local: local, public: public, permissions: map[netip.AddrPort]bool{}}
				n.bindings[key], n.byPublic[public] = b, b
				break
			}
			// Port preservation is a preference, not permission to overload.
			port = n.next
			n.next++
		}
	}
	b.permissions[remote] = true
	return b
}

func (n *simNode) accepts(b *binding, source netip.AddrPort) bool {
	if n.filter == eif {
		return true
	}
	for destination := range b.permissions {
		if destination == source || (n.filter == adf && destination.Addr() == source.Addr()) {
			return true
		}
	}
	return false
}

type simNetwork struct {
	nodes          [2]*simNode
	listeners      map[netip.AddrPort]bool
	opened         map[socket]bool
	clock          time.Time
	queue          []Report
	log            []Probe
	delivered      []Probe
	dropFirst      int
	dropAll        bool
	duplicate      bool
	reverseReports bool
	openError      netip.AddrPort
	oldReport      *Report
	background     bool
	readyAt        time.Time
}

func newSimulation(am, bm mappingKind, af, bf filteringKind, aa, ba allocationKind) (*simNetwork, Peer, Peer) {
	n := &simNetwork{
		listeners: map[netip.AddrPort]bool{}, opened: map[socket]bool{}, clock: time.Unix(0, 0),
	}
	for side := A; side <= B; side++ {
		n.nodes[side] = &simNode{
			ip:       netip.MustParseAddr(fmt.Sprintf("10.0.%d.2", side)),
			publicIP: netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", side+1)),
			mapping:  []mappingKind{am, bm}[side], filter: []filteringKind{af, bf}[side],
			allocation: []allocationKind{aa, ba}[side], next: 42000 + uint16(side)*1000,
			rng: 17 + uint32(side), bindings: map[mappingKey]*binding{}, byPublic: map[netip.AddrPort]*binding{},
		}
	}
	observers := []inference.Observer{
		{Bootstrap: true, Endpoints: []netip.AddrPort{ep("192.0.2.10:40000"), ep("192.0.2.10:40001")}},
		{Endpoints: []netip.AddrPort{ep("192.0.2.11:40000"), ep("192.0.2.11:40001")}},
	}
	for _, observer := range observers {
		for _, endpoint := range observer.Endpoints {
			n.listeners[endpoint] = true
		}
	}
	peers := [2]Peer{}
	for side := A; side <= B; side++ {
		peers[side] = Peer{
			Local:     netip.AddrPortFrom(n.nodes[side].ip, 51000),
			Target:    netip.AddrPortFrom(n.nodes[1-side].publicIP, 51000),
			Observers: observers, Store: &inference.Store{},
		}
	}
	return n, peers[A], peers[B]
}

func ep(value string) netip.AddrPort { return netip.MustParseAddrPort(value) }

func (n *simNetwork) seed(side Side, peer Peer, local netip.AddrPort) {
	n.opened[socket{side, local}] = true
	remote := peer.Observers[0].Endpoints[0]
	b := n.nodes[side].outbound(local, remote)
	peer.Store.Add(inference.Observation{Local: local, Remote: remote, Seen: b.public})
}

func (n *simNetwork) Open(ctx context.Context, side Side, local netip.AddrPort) error {
	if local == n.openError {
		return errors.New("simulated bind failure")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	n.opened[socket{side, local}] = true
	return nil
}

func (n *simNetwork) Close(side Side, local netip.AddrPort) error {
	delete(n.opened, socket{side, local})
	return nil // Closing a host socket does not itself delete a NAT mapping.
}

func (n *simNetwork) Send(ctx context.Context, p Probe) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !n.opened[socket{p.Side, p.Local}] {
		return errors.New("send on unowned socket")
	}
	n.log = append(n.log, p)
	b := n.nodes[p.Side].outbound(p.Local, p.Remote)
	if n.background {
		n.nodes[p.Side].next += uint16(len(n.log) % 7)
	}
	if n.dropAll || len(n.log) <= n.dropFirst || n.clock.Before(n.readyAt) {
		return nil // Outbound mapping and permissions still exist after loss.
	}
	accepted := n.listeners[p.Remote]
	remoteNode := n.nodes[1-p.Side]
	if destination := remoteNode.byPublic[p.Remote]; destination != nil && n.opened[socket{1 - p.Side, destination.local}] {
		accepted = remoteNode.accepts(destination, b.public)
	}
	if accepted {
		n.delivered = append(n.delivered, p)
		n.queue = append(n.queue, Report{ID: p.ID, Seen: b.public})
		if n.duplicate {
			n.queue = append(n.queue, Report{ID: p.ID, Seen: b.public})
		}
	}
	return nil
}

func (n *simNetwork) Reports(ctx context.Context) ([]Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reports := n.queue
	n.queue = nil
	if n.reverseReports {
		slices.Reverse(reports)
	}
	if n.oldReport != nil {
		reports = append(reports, *n.oldReport)
	}
	return reports, nil
}

func (n *simNetwork) Wait(ctx context.Context, d time.Duration) error {
	n.clock = n.clock.Add(d)
	return ctx.Err()
}

func (n *simNetwork) Now() time.Time { return n.clock }

func assertBounded(t *testing.T, n *simNetwork, result Result, limits Limits) {
	t.Helper()
	if result.Stats.Packets > limits.Packets || result.Stats.Measurements > limits.Measurements ||
		result.Stats.Iterations > limits.MaxIterations || n.clock.Sub(time.Unix(0, 0)) > limits.Timeout {
		t.Fatalf("limits exceeded: %+v time=%v", result, n.clock)
	}
	if result.Path != nil {
		p := result.Path
		// Independently check the simulator's actual mappings and permissions.
		ab := n.nodes[A].outbound(p.LocalA, p.EndpointB)
		bb := n.nodes[B].outbound(p.LocalB, p.EndpointA)
		if ab.public != p.EndpointA || bb.public != p.EndpointB ||
			!n.nodes[A].accepts(ab, p.EndpointB) || !n.nodes[B].accepts(bb, p.EndpointA) {
			t.Fatalf("reported an incompatible path: %+v", p)
		}
	}
	for resource := range n.opened {
		if resource.local.Port() >= 51000 && resource.local.Port() <= 51002 {
			if result.Path == nil || resource.local.Port() != 51000 {
				t.Fatalf("leaked task resource: %+v result=%+v", resource, result)
			}
		}
	}
}

func TestSimulationMappingFilteringMatrix(t *testing.T) {
	connected := 0
	for _, am := range []mappingKind{eim, adm, apdm} {
		for _, bm := range []mappingKind{eim, adm, apdm} {
			for _, af := range []filteringKind{eif, adf, apdf} {
				for _, bf := range []filteringKind{eif, adf, apdf} {
					t.Run(fmt.Sprintf("%s-%s/%s-%s", am, af, bm, bf), func(t *testing.T) {
						n, a, b := newSimulation(am, bm, af, bf, sequential, sequential)
						n.seed(A, a, a.Local)
						n.seed(B, b, b.Local)
						limits := DefaultLimits()
						result, err := Run(context.Background(), n, a, b, limits)
						if err != nil {
							t.Fatal(err)
						}
						assertBounded(t, n, result, limits)
						if result.Path != nil {
							connected++
						}
						if (am != apdm || bm != apdm) && result.Path == nil {
							t.Fatalf("expected this bounded sequential model to connect: %+v", result)
						}
					})
				}
			}
		}
	}
	t.Logf("81 mapping/filtering pairs: %d connected; %d bounded fallbacks", connected, 81-connected)
}

func TestSimulationEIMRandomPortReuse(t *testing.T) {
	for _, allocation := range []allocationKind{preserve, offset, sequential, random} {
		t.Run(string(allocation), func(t *testing.T) {
			n, a, b := newSimulation(eim, eim, apdf, apdf, allocation, allocation)
			n.seed(A, a, a.Local)
			n.seed(B, b, b.Local)
			n.dropFirst = 2
			n.readyAt = n.Now().Add(20 * time.Millisecond)
			n.duplicate, n.reverseReports = true, true
			result, err := Run(context.Background(), n, a, b, DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if result.Path == nil || result.Stats.Measurements != 0 {
				t.Fatalf("existing socket mapping should work without survey: %+v", result)
			}
			assertBounded(t, n, result, DefaultLimits())
		})
	}
}

func TestSimulationBaselineNeedsNoActiveObserve(t *testing.T) {
	n, a, b := newSimulation(eim, eim, apdf, apdf, preserve, preserve)
	n.seed(A, a, netip.AddrPortFrom(a.Local.Addr(), 52000))
	n.seed(B, b, netip.AddrPortFrom(b.Local.Addr(), 52000))
	result, err := Run(context.Background(), n, a, b, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if result.Path == nil || result.Stats.Measurements != 0 || result.Stats.Iterations != 1 {
		t.Fatalf("baseline failed: %+v", result)
	}
	assertBounded(t, n, result, DefaultLimits())
}

func TestSimulationSequentialDestinationDependentMapping(t *testing.T) {
	for _, mapping := range []mappingKind{adm, apdm} {
		t.Run(string(mapping), func(t *testing.T) {
			n, a, b := newSimulation(mapping, eim, apdf, apdf, sequential, random)
			n.seed(A, a, a.Local)
			n.seed(B, b, b.Local)
			result, err := Run(context.Background(), n, a, b, DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if result.Path == nil || result.Stats.Measurements == 0 {
				t.Fatalf("expected bounded prediction after survey: %+v", result)
			}
			assertBounded(t, n, result, DefaultLimits())
		})
	}
}

func TestSimulationObserverFallbackAndNoProgress(t *testing.T) {
	n, a, b := newSimulation(apdm, apdm, apdf, apdf, random, random)
	n.seed(A, a, a.Local)
	n.seed(B, b, b.Local)
	for _, endpoint := range a.Observers[0].Endpoints {
		n.listeners[endpoint] = false
	}
	result, err := Run(context.Background(), n, a, b, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if result.Path != nil || result.Reason != "no-progress" || result.Stats.OtherBranches == 0 || result.Stats.RejectedBatches == 0 {
		t.Fatalf("expected finite broad-search refusal after observer fallback: %+v", result)
	}
	first, other := -1, -1
	for i, p := range n.log {
		if p.Remote.Addr() == a.Observers[0].Endpoints[0].Addr() && first < 0 {
			first = i
		}
		if p.Remote.Addr() == a.Observers[1].Endpoints[0].Addr() && other < 0 {
			other = i
		}
	}
	if first < 0 || other <= first {
		t.Fatalf("bootstrap observer not attempted first: %d %d", first, other)
	}
	assertBounded(t, n, result, DefaultLimits())
}

func TestSimulationFailuresRemainBounded(t *testing.T) {
	for _, scenario := range []string{"loss", "packets", "time", "cancel", "bind", "background"} {
		t.Run(scenario, func(t *testing.T) {
			n, a, b := newSimulation(apdm, apdm, apdf, apdf, random, random)
			if scenario == "background" {
				n.nodes[A].allocation, n.nodes[B].allocation = sequential, sequential
			}
			n.seed(A, a, a.Local)
			n.seed(B, b, b.Local)
			limits := DefaultLimits()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "loss":
				n.dropAll = true
			case "packets":
				limits.Packets = 5
			case "time":
				limits.Timeout = time.Millisecond
			case "cancel":
				cancel()
			case "bind":
				n.openError = netip.AddrPortFrom(a.Local.Addr(), 51001)
			case "background":
				n.background = true
			}
			n.oldReport = &Report{ID: 999999, Seen: ep("198.51.100.99:50000")}
			result, err := Run(ctx, n, a, b, limits)
			if scenario == "cancel" || scenario == "bind" {
				if err == nil {
					t.Fatal("expected execution error")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if result.Path != nil && scenario != "background" {
				t.Fatalf("unexpected success: %+v", result)
			}
			if scenario != "cancel" {
				assertBounded(t, n, result, limits)
			}
			if scenario == "loss" && result.Stats.NewObservations != 0 {
				t.Fatal("invented evidence from loss/stale reports")
			}
		})
	}
}

func TestPathRequiresMatchingEndpoints(t *testing.T) {
	_, a, b := newSimulation(eim, eim, eif, eif, preserve, preserve)
	observations := [2][]inference.Observation{
		{{Local: a.Local, Remote: ep("198.51.100.2:50001"), Seen: ep("198.51.100.1:50000")}},
		{{Local: b.Local, Remote: ep("198.51.100.1:50000"), Seen: ep("198.51.100.2:50002")}},
	}
	if matchedPath(observations, [2]Peer{a, b}) != nil {
		t.Fatal("combined incompatible one-way successes")
	}
}

func TestSimulationModelMappingAndFiltering(t *testing.T) {
	for _, mapping := range []mappingKind{eim, adm, apdm} {
		n, a, _ := newSimulation(mapping, eim, eif, eif, sequential, preserve)
		x := n.nodes[A].outbound(a.Local, ep("192.0.2.10:40000")).public
		y := n.nodes[A].outbound(a.Local, ep("192.0.2.10:40001")).public
		z := n.nodes[A].outbound(a.Local, ep("192.0.2.11:40000")).public
		if (x == y) != (mapping != apdm) || (x == z) != (mapping == eim) {
			t.Fatalf("simulator mapping %s: %s %s %s", mapping, x, y, z)
		}
	}
	for _, filtering := range []filteringKind{eif, adf, apdf} {
		n, a, _ := newSimulation(eim, eim, filtering, eif, preserve, preserve)
		binding := n.nodes[A].outbound(a.Local, ep("192.0.2.10:40000"))
		if !n.nodes[A].accepts(binding, ep("192.0.2.10:40000")) ||
			n.nodes[A].accepts(binding, ep("192.0.2.10:40001")) != (filtering != apdf) ||
			n.nodes[A].accepts(binding, ep("192.0.2.11:40000")) != (filtering == eif) {
			t.Fatalf("simulator filtering %s is incorrect", filtering)
		}
	}
}

func TestCollectorOrdersAndCorrelatesBeforeIngest(t *testing.T) {
	n, a, b := newSimulation(apdm, eim, eif, eif, sequential, preserve)
	n.reverseReports, n.duplicate = true, true
	n.oldReport = &Report{ID: 999999, Seen: ep("198.51.100.99:50000")}
	e := engine{network: n, peers: [2]Peer{a, b}, limits: DefaultLimits(), until: n.Now().Add(time.Second)}
	if err := e.open(context.Background(), A, a.Local); err != nil {
		t.Fatal(err)
	}
	defer n.Close(A, a.Local)
	observations, err := e.window(context.Background(), []Probe{
		{Side: A, Local: a.Local, Remote: a.Observers[0].Endpoints[0]},
		{Side: A, Local: a.Local, Remote: a.Observers[0].Endpoints[1]},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.ingest(observations)
	samples := a.Store.Snapshot()
	if len(samples) != 2 || samples[0].Remote != a.Observers[0].Endpoints[0] || samples[1].Remote != a.Observers[0].Endpoints[1] ||
		samples[0].Seen.Port() != 42000 || samples[1].Seen.Port() != 42001 {
		t.Fatalf("collector leaked duplicates, stale data or arrival order: %+v", samples)
	}
}

func TestDiscoveryDoesNotReturnSuccessAfterDeadline(t *testing.T) {
	n, a, b := newSimulation(eim, eim, eif, eif, preserve, preserve)
	n.seed(A, a, a.Local)
	n.seed(B, b, b.Local)
	limits := DefaultLimits()
	limits.Timeout = limits.Interval
	result, err := Run(context.Background(), n, a, b, limits)
	if err != nil {
		t.Fatal(err)
	}
	if result.Path != nil || result.Reason != "budget-exhausted" {
		t.Fatalf("late success: %+v", result)
	}
	assertBounded(t, n, result, limits)
}

func TestSimulationIPv6(t *testing.T) {
	n, a, b := newSimulation(eim, eim, apdf, apdf, preserve, preserve)
	n.nodes[A].ip, n.nodes[B].ip = netip.MustParseAddr("fd00::a"), netip.MustParseAddr("fd00::b")
	n.nodes[A].publicIP, n.nodes[B].publicIP = netip.MustParseAddr("2001:db8::a"), netip.MustParseAddr("2001:db8::b")
	a.Local, b.Local = netip.AddrPortFrom(n.nodes[A].ip, 51000), netip.AddrPortFrom(n.nodes[B].ip, 51000)
	a.Target, b.Target = netip.AddrPortFrom(n.nodes[B].publicIP, 51000), netip.AddrPortFrom(n.nodes[A].publicIP, 51000)
	a.Observers = []inference.Observer{{Bootstrap: true, Endpoints: []netip.AddrPort{ep("[2001:db8::d]:40000")}}}
	b.Observers = a.Observers
	n.listeners[a.Observers[0].Endpoints[0]] = true
	n.seed(A, a, a.Local)
	n.seed(B, b, b.Local)
	result, err := Run(context.Background(), n, a, b, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if result.Path == nil {
		t.Fatalf("IPv6 path failed: %+v", result)
	}
	assertBounded(t, n, result, DefaultLimits())
}
