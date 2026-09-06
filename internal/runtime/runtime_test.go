package runtime

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/link"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
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

func TestDynamicFailureRemovesOnlyItsMaterializedPlan(t *testing.T) {
	backend := &runtimeBackend{}
	localID := uuid.MustParse("10000000-0000-4000-8000-000000000001")
	remoteID := uuid.MustParse("20000000-0000-4000-8000-000000000002")
	plan := reconcile.LinkPlan{InterfaceName: "vdl-b-2000", OwnerAlias: "velvet:link:local:dynamic:remote"}
	runner := &Runner{
		Desired:    &reconcile.DesiredState{UUID: localID},
		Reconciler: reconcile.New(backend),
		states: map[string]materializedState{
			plan.InterfaceName: {desired: plan, dynamic: true},
		},
	}
	dynamic := newDynamicLinkEngine(runner)
	dynamic.ctx = context.Background()
	operation := [16]byte{1}
	dynamic.attempts[remoteID] = &dynamicAttempt{
		remote: remoteID, operationID: operation, plan: plan,
		state: dynamicRecovering,
	}
	dynamic.failAttempt(dynamic.attempts[remoteID], "response timeout", dynamicProposing)
	if len(runner.states) != 1 || len(backend.removed) != 0 {
		t.Fatal("state-scoped response timeout removed a recovering Link")
	}
	dynamic.failAttempt(dynamic.attempts[remoteID], "test failure", dynamicRecovering)
	if len(runner.states) != 0 {
		t.Fatal("failed dynamic Link remained materialized")
	}
	if len(backend.removed) != 1 || backend.removed[0].OwnerAlias != plan.OwnerAlias {
		t.Fatalf("removed plans = %#v", backend.removed)
	}
}

func TestDynamicCleanupDoesNotHoldStateLock(t *testing.T) {
	backend := &runtimeBackend{removeStarted: make(chan struct{}), removeRelease: make(chan struct{})}
	remote := uuid.MustParse("20000000-0000-4000-8000-000000000002")
	plan := reconcile.LinkPlan{InterfaceName: "vdl-b-2000", OwnerAlias: "owner"}
	runner := &Runner{
		Desired:    &reconcile.DesiredState{},
		Reconciler: reconcile.New(backend),
		states:     make(map[string]materializedState),
	}
	dynamic := newDynamicLinkEngine(runner)
	dynamic.ctx = context.Background()
	attempt := &dynamicAttempt{remote: remote, plan: plan, state: dynamicAttempting}
	dynamic.attempts[remote] = attempt

	done := make(chan struct{})
	go func() {
		dynamic.failAttempt(attempt, "test failure", dynamicAttempting)
		close(done)
	}()
	<-backend.removeStarted
	lockAvailable := make(chan struct{})
	go func() {
		dynamic.mu.Lock()
		dynamic.mu.Unlock()
		close(lockAvailable)
	}()
	select {
	case <-lockAvailable:
	case <-time.After(time.Second):
		close(backend.removeRelease)
		t.Fatal("dynamic state lock remained held during kernel cleanup")
	}
	close(backend.removeRelease)
	<-done
}

func TestDynamicRoutedDialRetriesAreBounded(t *testing.T) {
	target := netip.MustParseAddr("fd41::2")
	dynamic := newDynamicLinkEngine(&Runner{})
	for attempt := 1; attempt <= maxRoutedDialAttempts; attempt++ {
		dynamic.targets[target] = &dynamicTarget{dialing: true, failures: uint8(attempt - 1)}
		dynamic.finishRoutedDial(target, true)
		exhausted := dynamic.targets[target].attempted
		if exhausted != (attempt == maxRoutedDialAttempts) {
			t.Fatalf("attempt %d exhausted=%v", attempt, exhausted)
		}
	}
}

func TestRunnerOnceWithoutLinks(t *testing.T) {
	backend := &runtimeBackend{}
	runner := &Runner{
		Desired: &reconcile.DesiredState{
			UUID: uuid.MustParse("10000000-0000-4000-8000-000000000001"),
			UID:  spec.NodeUID{Name: "test"}, LoopbackV6: netip.MustParseAddr("::1"),
		},
		Reconciler: reconcile.New(backend),
		Ready:      make(chan error, 1),
	}
	if err := runner.Run(context.Background(), true); err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skip("test sandbox does not permit loopback sockets")
		}
		t.Fatal(err)
	}
	if backend.reconciles != 1 || backend.verifies != 1 {
		t.Fatalf("backend calls: reconcile=%d verify=%d", backend.reconciles, backend.verifies)
	}
}

func TestRunnerStatus(t *testing.T) {
	staticID := uuid.MustParse("20000000-0000-4000-8000-000000000002")
	dynamicID := uuid.MustParse("30000000-0000-4000-8000-000000000003")
	dynamicPlan := reconcile.LinkPlan{InterfaceName: "vdl-test", OwnerAlias: "dynamic-owner"}
	runner := &Runner{
		Desired: &reconcile.DesiredState{UUID: uuid.MustParse("10000000-0000-4000-8000-000000000001"), Links: make([]reconcile.LinkPlan, 3)},
		states: map[string]materializedState{
			"vl-static": {remote: staticID, peers: []netip.Addr{netip.MustParseAddr("fd00::2")}},
			"vdl-test":  {desired: dynamicPlan, remote: dynamicID, peers: []netip.Addr{netip.MustParseAddr("fd00::3")}, dynamic: true},
		},
	}
	status := runner.Status()
	if status.ConfiguredLinks != 3 || status.EstablishedLinks != 1 || status.DynamicLinks != 1 {
		t.Fatalf("status = %#v", status)
	}
}

func TestDynamicPolicy(t *testing.T) {
	d, _, _ := dynamicFixture(t, &runtimeBackend{})
	for _, tc := range []struct {
		mode            string
		active, inbound bool
	}{{spec.DynamicLinksActive, true, true}, {spec.DynamicLinksPassive, false, true}, {spec.DynamicLinksOff, false, false}} {
		t.Run(tc.mode, func(t *testing.T) {
			d.runner.Desired.DynamicLinks.Mode = tc.mode
			if d.active() != tc.active || d.allowsInbound() != tc.inbound {
				t.Fatal("incorrect participation policy")
			}
		})
	}
	if !d.candidateAllowed(netip.MustParseAddrPort("192.0.2.1:1")) || d.candidateAllowed(netip.MustParseAddrPort("198.51.100.1:1")) {
		t.Fatal("incorrect Candidate allowlist")
	}
	d.runner.Desired.DynamicLinks = nil
	if d.active() || d.allowsInbound() || d.candidateAllowed(netip.MustParseAddrPort("192.0.2.1:1")) {
		t.Fatal("omitted configuration enabled Dynamic Links")
	}
}

func TestEvidenceStoreUpdateAndRemoval(t *testing.T) {
	d, _, _ := dynamicFixture(t, &runtimeBackend{})
	second := netip.MustParseAddrPort("[2001:db8::2]:62002")
	if err := d.setEvidence("vl-second", 51002, second); err != nil {
		t.Fatal(err)
	}
	updated := netip.MustParseAddrPort("192.0.2.9:62009")
	if err := d.setEvidence("vl-seed", 51009, updated); err != nil {
		t.Fatal(err)
	}
	if len(d.evidence) != 2 || d.evidence[0].Link != "vl-seed" || d.evidence[0].LocalListenPort != 51009 || d.evidence[0].ObservedEndpoint != updated {
		t.Fatalf("update changed order or mapping: %#v", d.evidence)
	}
	d.mu.Lock()
	d.removeEvidenceLocked("vl-seed")
	d.mu.Unlock()
	if len(d.evidence) != 1 || d.evidence[0].Link != "vl-second" || d.evidence[0].ObservedEndpoint != second {
		t.Fatalf("deletion did not promote next Evidence: %#v", d.evidence)
	}
}

func TestDialReservationExcludesSelfAndDirectPeers(t *testing.T) {
	self, direct, target := netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2"), netip.MustParseAddr("fd00::3")
	d := newDynamicLinkEngine(&Runner{Desired: &reconcile.DesiredState{LoopbackV6: self}, states: map[string]materializedState{"direct": {peers: []netip.Addr{direct}}}})
	if d.reserveDial(self) || d.reserveDial(direct) || !d.reserveDial(target) || d.reserveDial(target) {
		t.Fatal("incorrect reservation")
	}
	<-d.outboundSessions
	d.finishRoutedDial(target, false)
}

func TestPendingLinksStopOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- waitForLinks(ctx, make(chan struct{}), 1) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("wait=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending Links did not stop")
	}
}

func TestCommitLinkMaterializesAndRecordsState(t *testing.T) {
	backend := &runtimeBackend{}
	local := uuid.MustParse("10000000-0000-4000-8000-000000000001")
	remote := uuid.MustParse("20000000-0000-4000-8000-000000000002")
	plan := reconcile.LinkPlan{PeerName: "peer", InterfaceName: "vdl-peer", OwnerAlias: "owner"}
	runner := &Runner{
		Desired:    &reconcile.DesiredState{UUID: local},
		Reconciler: reconcile.New(backend),
		states:     make(map[string]materializedState),
	}
	called := false
	result := engine.Result{
		RemoteUID:        message.UID{UUID: remote},
		RemoteLoopbackV6: netip.MustParseAddr("fd00::2"),
		Proposal:         link.Proposal{V4: netip.MustParsePrefix("10.0.0.0/30")},
	}
	if err := runner.commitLink(context.Background(), plan, false, result, func(engine.Result) { called = true }); err != nil {
		t.Fatal(err)
	}
	state, ok := runner.states[plan.InterfaceName]
	if !ok || state.dynamic || state.remote != remote || !called || backend.materialized != 1 {
		t.Fatalf("commit state=%#v exists=%v callback=%v materialized=%d", state, ok, called, backend.materialized)
	}

	if !reflect.DeepEqual(backend.local, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/30")}) || !reflect.DeepEqual(backend.peers, []netip.Addr{result.RemoteLoopbackV6}) || backend.plan.InterfaceName != plan.InterfaceName {
		t.Fatalf("wrong materialization: local=%v peers=%v plan=%v", backend.local, backend.peers, backend.plan)
	}
	backend.materializeErr = errors.New("materialize failed")
	if err := runner.commitLink(context.Background(), reconcile.LinkPlan{InterfaceName: "failed"}, false, result, nil); !errors.Is(err, backend.materializeErr) {
		t.Fatalf("materialize error = %v", err)
	}
	if _, exists := runner.states["failed"]; exists {
		t.Fatal("failed materialization was recorded")
	}
}

type runtimeBackend struct {
	local        []netip.Prefix
	peers        []netip.Addr
	plan         reconcile.LinkPlan
	configureErr error
	onRemove     func()

	prepared      int
	configured    int
	listenPort    int
	listenPortErr error
	prepareCalled chan struct{}

	reachable      []netip.Addr
	removed        []reconcile.LinkPlan
	reconciles     int
	verifies       int
	materialized   int
	materializeErr error
	removeStarted  chan struct{}
	removeRelease  chan struct{}
}

func (b *runtimeBackend) Reconcile(context.Context, *reconcile.DesiredState, bool) error {
	b.reconciles++
	return nil
}
func (b *runtimeBackend) Verify(context.Context, *reconcile.DesiredState) error {
	b.verifies++
	return nil
}
func (b *runtimeBackend) ProposalAvailable(context.Context, reconcile.LinkPlan, link.Proposal, []netip.Prefix) bool {
	return true
}
func (b *runtimeBackend) Materialize(_ context.Context, _ *reconcile.DesiredState, plan reconcile.LinkPlan, local []netip.Prefix, peers []netip.Addr) error {
	b.plan, b.local, b.peers = plan, append([]netip.Prefix(nil), local...), append([]netip.Addr(nil), peers...)
	b.materialized++
	return b.materializeErr
}
func (b *runtimeBackend) PrepareDynamic(_ context.Context, plan reconcile.LinkPlan) (reconcile.LinkPlan, error) {
	b.prepared++
	if b.prepareCalled != nil {
		b.prepareCalled <- struct{}{}
	}
	plan.ListenPort = 53000
	return plan, nil
}
func (b *runtimeBackend) ConfigureDynamic(context.Context, reconcile.LinkPlan) error {
	b.configured++
	return b.configureErr
}
func (b *runtimeBackend) ListenPort(context.Context, string) (int, error) {
	return b.listenPort, b.listenPortErr
}
func (b *runtimeBackend) RemoveDynamic(_ context.Context, plan reconcile.LinkPlan) error {
	if b.onRemove != nil {
		b.onRemove()
	}
	if b.removeStarted != nil {
		close(b.removeStarted)
		<-b.removeRelease
	}
	b.removed = append(b.removed, plan)
	return nil
}
func (b *runtimeBackend) ObservedEndpoint(context.Context, string) (netip.AddrPort, bool, error) {
	return netip.AddrPort{}, false, nil
}
func (b *runtimeBackend) ReachableLoopbacks(context.Context, int, netip.Prefix) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), b.reachable...), nil
}
