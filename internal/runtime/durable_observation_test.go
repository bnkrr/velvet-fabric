package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
)

type durableObservationBackend struct {
	*runtimeBackend
	reads    int
	endpoint netip.AddrPort
	err      error
	before   func(string)
}

func (b *durableObservationBackend) ListenPort(ctx context.Context, name string) (int, error) {
	b.reads++
	if b.before != nil {
		b.before("port")
	}
	return b.runtimeBackend.ListenPort(ctx, name)
}

func (b *durableObservationBackend) ObservedEndpoint(context.Context, string) (netip.AddrPort, bool, error) {
	b.reads++
	if b.before != nil {
		b.before("endpoint")
	}
	return b.endpoint, b.endpoint.IsValid(), b.err
}

func durableObservationFixture(t *testing.T) (*Runner, *dynamicAttempt, *durableObservationBackend) {
	t.Helper()
	b := &durableObservationBackend{runtimeBackend: &runtimeBackend{listenPort: 53000}, endpoint: netip.MustParseAddrPort("192.0.2.2:54000")}
	e, session, proposal := dynamicFixture(t, b.runtimeBackend)
	r := e.runner
	r.Reconciler = reconcile.New(b)
	a := e.prepareInbound(session, proposal)
	if a == nil {
		t.Fatal("could not prepare automatic Link")
	}
	a.state = dynamicUp
	r.states[a.plan.InterfaceName] = materializedState{desired: a.plan, remote: a.remote, active: true, dynamic: true, committed: true}
	r.PolicyStateDir = t.TempDir()
	if err := r.openDurable(); err != nil {
		t.Fatal(err)
	}
	r.durable.records[a.remote] = durableRecord{ID: [16]byte{1}, Peer: message.UID{UUID: a.remote}, Confirmed: true}
	return r, a, b
}

func TestDurableQueuedObservationAfterStaticTakeover(t *testing.T) {
	r, a, b := durableObservationFixture(t)
	r.durable.observeLater(a.plan, netip.MustParseAddrPort("192.0.2.1:53000"), netip.MustParseAddr("fe80::2"), time.Now())
	r.states["vl-static"] = materializedState{remote: a.remote, active: true}
	r.staticTakesOver(a.remote)
	if len(b.removed) != 1 {
		t.Fatal("Static did not retire the automatic interface")
	}
	b.listenPortErr = fmt.Errorf("read WireGuard device %q: %w", a.plan.InterfaceName, os.ErrNotExist)
	update := <-r.durable.updates
	if err := r.durable.observe(context.Background(), update.plan, update.local, update.control, update.at); err != nil {
		t.Fatalf("queued observation became a fatal runtime error after normal cleanup: %v", err)
	}
	if b.reads != 0 || len(r.durable.observations) != 0 {
		t.Fatal("retired observation accessed the kernel or created endpoint evidence")
	}
	if !r.hasHealthyStatic(a.remote) || !r.durable.has(a.remote) {
		t.Fatal("ignoring an old observation damaged Static or the saved agreement")
	}
}

func TestDurableObservationRejectsStaleWorkBeforeKernelRead(t *testing.T) {
	for _, kind := range []string{"replaced", "inactive", "static", "expired"} {
		t.Run(kind, func(t *testing.T) {
			r, a, b := durableObservationFixture(t)
			state := r.states[a.plan.InterfaceName]
			now := time.Now()
			switch kind {
			case "replaced":
				state.desired.OwnerAlias += ":replacement"
			case "inactive":
				state.active = false
			case "static":
				state.dynamic = false
			case "expired":
				now = now.Add(-linkFailureTimeout)
			}
			r.states[a.plan.InterfaceName] = state
			b.listenPortErr = errors.New("must not read an obsolete interface")
			if err := r.durable.observe(context.Background(), a.plan, netip.MustParseAddrPort("192.0.2.1:53000"), netip.MustParseAddr("fe80::2"), now); err != nil {
				t.Fatal(err)
			}
			if b.reads != 0 || len(r.durable.observations) != 0 {
				t.Fatal("stale observation reached kernel or updated stability")
			}
		})
	}
}

func TestDurableObservationSerializesBothKernelReadsWithCleanup(t *testing.T) {
	for _, blocked := range []string{"port", "endpoint"} {
		t.Run(blocked, func(t *testing.T) {
			r, a, b := durableObservationFixture(t)
			r.states["vl-static"] = materializedState{remote: a.remote, active: true}
			entered, release := make(chan struct{}), make(chan struct{})
			b.before = func(stage string) {
				if stage == blocked {
					close(entered)
					<-release
				}
			}
			observed := make(chan error, 1)
			go func() {
				observed <- r.durable.observe(context.Background(), a.plan, netip.MustParseAddrPort("192.0.2.1:53000"), netip.MustParseAddr("fe80::2"), time.Now())
			}()
			<-entered
			removed := make(chan struct{})
			started := make(chan struct{})
			go func() { close(started); r.staticTakesOver(a.remote); close(removed) }()
			<-started
			raced := false
			select {
			case <-removed:
				raced = true
			case <-time.After(50 * time.Millisecond):
			}
			close(release)
			err := <-observed
			<-removed
			if raced {
				t.Fatal("interface cleanup raced an in-flight durable kernel read")
			}
			if err != nil || len(b.removed) != 1 || !r.hasHealthyStatic(a.remote) || !r.durable.has(a.remote) {
				t.Fatalf("observation/takeover failed: %v", err)
			}
		})
	}
}

func TestDurableObservationStillReportsCurrentBackendErrors(t *testing.T) {
	for _, stage := range []string{"port", "endpoint"} {
		t.Run(stage, func(t *testing.T) {
			r, a, b := durableObservationFixture(t)
			injected := errors.New("current WireGuard read failed")
			if stage == "port" {
				b.listenPortErr = injected
			} else {
				b.err = injected
			}
			if err := r.durable.observe(context.Background(), a.plan, netip.MustParseAddrPort("192.0.2.1:53000"), netip.MustParseAddr("fe80::2"), time.Now()); !errors.Is(err, injected) {
				t.Fatalf("current backend error was hidden: %v", err)
			}
		})
	}
}
