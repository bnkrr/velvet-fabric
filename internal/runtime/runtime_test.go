package runtime

import (
	"context"
	"errors"
	"net/netip"
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
	dynamic := newDynamicRuntime(runner)
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
	dynamic := newDynamicRuntime(runner)
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
	dynamic := newDynamicRuntime(&Runner{})
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

func TestRunnerStatusAndStateQueries(t *testing.T) {
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
	if !runner.hasDirectLink(staticID) || runner.hasDirectLink(uuid.Nil) || !runner.hasDirectLinkToLoopback(netip.MustParseAddr("fd00::3")) {
		t.Fatal("direct Link lookup returned the wrong result")
	}
	if got := runner.materializedStates(); len(got) != 2 {
		t.Fatalf("materialized states = %d", len(got))
	}
	runner.removeDynamicState(dynamicPlan)
	if len(runner.states) != 1 {
		t.Fatalf("dynamic state was not removed: %#v", runner.states)
	}
}

func TestDynamicPolicyEvidenceAndReservation(t *testing.T) {
	self := netip.MustParseAddr("fd00::1")
	direct := netip.MustParseAddr("fd00::2")
	target := netip.MustParseAddr("fd00::3")
	runner := &Runner{
		Desired: &reconcile.DesiredState{
			LoopbackV6:   self,
			DynamicLinks: &reconcile.DynamicLinksPlan{Mode: spec.DynamicLinksActive, AllowCandidatePrefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}},
		},
		states: map[string]materializedState{"direct": {peers: []netip.Addr{direct}}},
	}
	dynamic := newDynamicRuntime(runner)
	if !dynamic.active() || !dynamic.allowsInbound() {
		t.Fatal("active mode policy was not enabled")
	}
	if !dynamic.candidateAllowed(netip.MustParseAddrPort("198.51.100.7:5000")) || dynamic.candidateAllowed(netip.MustParseAddrPort("203.0.113.7:5000")) {
		t.Fatal("candidate policy returned the wrong result")
	}
	dynamic.setEvidence("vl-a", netip.MustParseAddrPort("198.51.100.1:1"))
	dynamic.setEvidence("vl-b", netip.MustParseAddrPort("198.51.100.2:2"))
	dynamic.setEvidence("vl-a", netip.MustParseAddrPort("198.51.100.3:3"))
	dynamic.mu.Lock()
	first, ok := dynamic.firstEvidenceLocked()
	dynamic.mu.Unlock()
	if !ok || first != netip.MustParseAddrPort("198.51.100.3:3") {
		t.Fatalf("first evidence = %s, %v", first, ok)
	}
	dynamic.mu.Lock()
	dynamic.removeEvidenceLocked("vl-a")
	dynamic.mu.Unlock()
	if dynamic.reserveDial(self) || dynamic.reserveDial(direct) || !dynamic.reserveDial(target) || dynamic.reserveDial(target) {
		t.Fatal("dial reservation returned the wrong result")
	}
	<-dynamic.outboundSessions
	dynamic.finishRoutedDial(target, false)
	runner.Desired.DynamicLinks.Mode = spec.DynamicLinksPassive
	if dynamic.active() || !dynamic.allowsInbound() {
		t.Fatal("passive mode policy was wrong")
	}
	runner.Desired.DynamicLinks = nil
	if dynamic.active() || dynamic.allowsInbound() || dynamic.candidateAllowed(netip.MustParseAddrPort("198.51.100.7:5000")) {
		t.Fatal("disabled policy was enabled")
	}
}

func TestDynamicAttemptCommitAndUtilities(t *testing.T) {
	remote := uuid.MustParse("20000000-0000-4000-8000-000000000002")
	var events []Event
	runner := &Runner{Desired: &reconcile.DesiredState{}, Log: func(event Event) { events = append(events, event) }}
	dynamic := newDynamicRuntime(runner)
	attempt := &dynamicAttempt{remote: remote, state: dynamicAttempting}
	dynamic.attempts[remote] = attempt
	dynamic.commitAttempt(attempt, engine.Result{RemoteUID: message.UID{UUID: remote}})
	if attempt.state != dynamicUp || len(events) != 1 || events[0].Status != "up" {
		t.Fatalf("first commit: attempt=%#v events=%#v", attempt, events)
	}
	attempt.state = dynamicRecovering
	dynamic.commitAttempt(attempt, engine.Result{RemoteUID: message.UID{UUID: remote}})
	if events[len(events)-1].Status != "recovered" {
		t.Fatalf("recovery event = %#v", events[len(events)-1])
	}
	first, err := newOperationID()
	if err != nil || first == ([16]byte{}) {
		t.Fatalf("operation ID = %x, %v", first, err)
	}
	if got := nodeUID(message.UID{Name: "peer", UUID: remote}); got.Name != "peer" || got.UUID != remote.String() {
		t.Fatalf("node UID = %#v", got)
	}
	if errorText(nil) != "Link establishment stopped" || errorText(errors.New("boom")) != "boom" {
		t.Fatal("error text returned the wrong value")
	}
}

func TestCommitLinkMaterializesAndRecordsState(t *testing.T) {
	backend := &runtimeBackend{}
	local := uuid.MustParse("10000000-0000-4000-8000-000000000001")
	remote := uuid.MustParse("20000000-0000-4000-8000-000000000002")
	plan := reconcile.LinkPlan{PeerName: "peer", InterfaceName: "vdl-peer", OwnerAlias: "owner"}
	var events []Event
	runner := &Runner{
		Desired:    &reconcile.DesiredState{UUID: local},
		Reconciler: reconcile.New(backend),
		states:     make(map[string]materializedState),
		Log:        func(event Event) { events = append(events, event) },
	}
	called := false
	result := engine.Result{
		RemoteUID:        message.UID{UUID: remote},
		RemoteLoopbackV6: netip.MustParseAddr("fd00::2"),
		Proposal:         link.Proposal{V4: netip.MustParsePrefix("10.0.0.0/30")},
	}
	if err := runner.commitLink(context.Background(), plan, true, result, func(engine.Result) { called = true }); err != nil {
		t.Fatal(err)
	}
	state, ok := runner.states[plan.InterfaceName]
	if !ok || !state.dynamic || state.remote != remote || !called || backend.materialized != 1 {
		t.Fatalf("commit state=%#v exists=%v callback=%v materialized=%d", state, ok, called, backend.materialized)
	}
	if len(events) != 1 || events[0].Event != "velvet-dynamic-link-established" {
		t.Fatalf("events = %#v", events)
	}
	backend.materializeErr = errors.New("materialize failed")
	if err := runner.commitLink(context.Background(), reconcile.LinkPlan{InterfaceName: "failed"}, false, result, nil); !errors.Is(err, backend.materializeErr) {
		t.Fatalf("materialize error = %v", err)
	}
	if _, exists := runner.states["failed"]; exists {
		t.Fatal("failed materialization was recorded")
	}
}

func TestRunnerSignalsAndWaits(t *testing.T) {
	ready := make(chan error, 1)
	runner := &Runner{Ready: ready}
	runner.signalReady(nil)
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	established := make(chan struct{}, 2)
	established <- struct{}{}
	established <- struct{}{}
	if err := waitForLinks(context.Background(), established, 2); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForLinks(ctx, make(chan struct{}), 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait error = %v", err)
	}
	closed := make(chan struct{})
	close(closed)
	waitForBabel(closed)
	waitForBabel(nil)
}

type runtimeBackend struct {
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
func (b *runtimeBackend) Materialize(context.Context, *reconcile.DesiredState, reconcile.LinkPlan, []netip.Prefix, []netip.Addr) error {
	b.materialized++
	return b.materializeErr
}
func (b *runtimeBackend) PrepareDynamic(_ context.Context, plan reconcile.LinkPlan) (reconcile.LinkPlan, error) {
	return plan, nil
}
func (b *runtimeBackend) ConfigureDynamic(context.Context, reconcile.LinkPlan) error { return nil }
func (b *runtimeBackend) RemoveDynamic(_ context.Context, plan reconcile.LinkPlan) error {
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
