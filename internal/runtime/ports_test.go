package runtime

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/probe"
)

func TestReserveProbeOccupiedPort(t *testing.T) {
	occupied, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6zero})
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	d := newDynamicLinkEngine(&Runner{})
	endpoint := netip.AddrPortFrom(netip.IPv6Loopback(), occupied.LocalAddr().(*net.UDPAddr).AddrPort().Port())
	socket, err := d.reserveProbe(context.Background(), endpoint, nil, nil, spec.PortChoice{})
	if socket != nil || !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("occupied port: socket=%v, err=%v", socket, err)
	}
	if len(d.runner.ports.leases) != 0 {
		t.Fatal("failed bind retained a lease")
	}
}

func TestReserveProbeRetriesTypedNilFailure(t *testing.T) {
	for _, exhaust := range []bool{false, true} {
		t.Run(map[bool]string{false: "retry-success", true: "exhausted"}[exhaust], func(t *testing.T) {
			d := newDynamicLinkEngine(&Runner{})
			calls := 0
			bindErr := errors.New("bind failed")
			d.listenProbe = func(_ context.Context, local netip.AddrPort, _ *probe.Receiver, _ func(probe.Received)) (probeSocket, error) {
				calls++
				if calls == 1 || exhaust {
					// Match the production adapter: a nil *probe.Socket becomes
					// a non-nil interface when returned alongside the bind error.
					return (*probe.Socket)(nil), bindErr
				}
				return &fakeProbeSocket{local: local}, nil
			}
			choice := spec.PortChoice{Range: spec.PortRange{First: 41000, Last: 41001}}
			socket, err := d.reserveProbe(context.Background(), netip.AddrPortFrom(netip.IPv6Loopback(), 0), nil, nil, choice)
			if calls != 2 {
				t.Fatalf("attempts=%d, want both range ports", calls)
			}
			if exhaust {
				if socket != nil || !errors.Is(err, bindErr) {
					t.Fatalf("exhausted range: socket=%v, err=%v", socket, err)
				}
			} else {
				if err != nil || socket == nil {
					t.Fatalf("retry: socket=%v, err=%v", socket, err)
				}
				if len(d.runner.ports.leases) != 1 {
					t.Fatal("successful retry did not acquire exactly one lease")
				}
				socket.Close()
			}
			if len(d.runner.ports.leases) != 0 {
				t.Fatal("reservation leaked a lease")
			}
		})
	}
}

func TestPortLeaseExhaustionAndStaleRelease(t *testing.T) {
	p := &portPool{}
	choice := spec.PortChoice{Range: spec.PortRange{First: 41000, Last: 41001}}
	bind := func(port int) (int, error) {
		if port < 41000 || port > 41001 {
			t.Fatalf("escaped explicit pool: %d", port)
		}
		return port, nil
	}
	a, err := p.bind(choice, 41000, bind)
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.bind(choice, 41000, bind)
	if err != nil {
		t.Fatal(err)
	}
	if a.port != 41000 || a.port == b.port {
		t.Fatal("sticky/conflict handling")
	}
	if _, err := p.bind(choice, 0, bind); err == nil {
		t.Fatal("exhausted range fell back")
	}
	a.release()
	c, err := p.bind(choice, 41000, bind)
	if err != nil {
		t.Fatal(err)
	}
	a.release()
	if _, err := p.bind(choice, 0, bind); err == nil {
		t.Fatal("stale release freed replacement")
	}
	b.release()
	c.release()
}

func TestFixedPortNeverFallsBack(t *testing.T) {
	p := &portPool{}
	calls := 0
	_, err := p.bind(spec.PortChoice{Port: 42000}, 42001, func(port int) (int, error) {
		calls++
		if port != 42000 {
			t.Fatal("fixed port changed")
		}
		return 0, errors.New("occupied")
	})
	if err == nil || calls != 1 {
		t.Fatal("fixed allocation was not bounded")
	}
}

func TestPortHeldUntilKernelCleanupSucceeds(t *testing.T) {
	p := &portPool{}
	lease, err := p.bind(spec.PortChoice{Port: 42000}, 0, func(port int) (int, error) { return port, nil })
	if err != nil {
		t.Fatal(err)
	}
	m := &linkManager{}
	plan := reconcile.LinkPlan{InterfaceName: "auto", OwnerAlias: "generation-1"}
	m.own(plan, lease)
	m.removed(plan, errors.New("kernel failure"))
	if p.leases[42000] != lease {
		t.Fatal("failed deletion released live port")
	}
	m.removed(plan, nil)
	if p.leases[42000] != nil {
		t.Fatal("successful deletion retained port")
	}
}

func TestStaleCleanupLeavesReplacementState(t *testing.T) {
	backend := &runtimeBackend{}
	old := reconcile.LinkPlan{InterfaceName: "auto", OwnerAlias: "old"}
	current := reconcile.LinkPlan{InterfaceName: "auto", OwnerAlias: "new"}
	r := &Runner{Desired: &reconcile.DesiredState{}, Reconciler: reconcile.New(backend), states: map[string]materializedState{"auto": {desired: current, active: true, dynamic: true}}}
	r.dynamic = newDynamicLinkEngine(r)
	r.dynamic.ctx = context.Background()
	if err := r.dynamic.setEvidence("auto", 42000, netip.MustParseAddrPort("192.0.2.1:42000")); err != nil {
		t.Fatal(err)
	}
	r.dynamic.removeInterface(old, "late cleanup")
	if len(backend.removed) != 0 || !r.states["auto"].active || len(r.dynamic.evidence) != 1 {
		t.Fatal("old generation damaged replacement")
	}
}

func TestStaticPriorityAtAutomaticCommit(t *testing.T) {
	for _, healthy := range []bool{false, true} {
		t.Run(map[bool]string{false: "configured-only", true: "healthy"}[healthy], func(t *testing.T) {
			backend := &runtimeBackend{}
			d, session, proposal := dynamicFixture(t, backend)
			a := d.prepareInbound(session, proposal)
			if a == nil {
				t.Fatal("prepare")
			}
			a.state = dynamicAttempting
			// Two explicitly configured Static Links are independent. Their
			// health, not configuration presence, decides automatic precedence.
			for _, name := range []string{"static-a", "static-b"} {
				d.runner.states[name] = materializedState{desired: reconcile.LinkPlan{InterfaceName: name}, remote: session.RemoteUID.UUID, active: healthy}
			}
			err := d.commitLink(d.ctx, a, engine.Result{RemoteUID: session.RemoteUID, RemoteLoopbackV6: session.RemoteLoopbackV6})
			if healthy {
				if err == nil || len(backend.removed) != 1 || backend.materialized != 0 || len(d.runner.states) != 2 {
					t.Fatalf("late automatic commit displaced Static: err=%v", err)
				}
			} else if err != nil || !d.runner.states[a.plan.InterfaceName].active {
				t.Fatalf("unavailable Static suppressed automatic Link: %v", err)
			}
		})
	}
}

type partiallyPreparedBackend struct{ runtimeBackend }

func (b *partiallyPreparedBackend) PrepareDynamic(_ context.Context, plan reconcile.LinkPlan) (reconcile.LinkPlan, error) {
	b.plan = plan
	return reconcile.LinkPlan{}, errors.New("failure after interface creation")
}

func TestFailedPreparationRetainsCleanupIdentity(t *testing.T) {
	backend := &partiallyPreparedBackend{}
	d, session, proposal := dynamicFixture(t, &backend.runtimeBackend)
	d.runner.Reconciler = reconcile.New(backend)
	if a := d.prepareInbound(session, proposal); a != nil {
		t.Fatal("failed preparation accepted")
	}
	if len(backend.removed) != 1 || backend.removed[0].OwnerAlias != backend.plan.OwnerAlias || backend.removed[0].InterfaceName == "" {
		t.Fatal("partial interface was not cleaned with its original identity")
	}
	if len(d.attempts) != 0 || len(d.runner.ports.leases) != 0 || len(d.runner.links.resources) != 0 {
		t.Fatal("failed preparation leaked owned resources")
	}
}
