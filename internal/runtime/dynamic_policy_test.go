package runtime

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
)

func TestPolicyRevisionPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node", "revision")
	seen := make(chan uint64, 12)
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			v, err := reservePolicyRevision(path)
			if err != nil {
				t.Error(err)
			}
			seen <- v
		})
	}
	wg.Wait()
	close(seen)
	values := map[uint64]bool{}
	for v := range seen {
		if v == 0 || values[v] {
			t.Fatal("reused or zero revision")
		}
		values[v] = true
	}
	if v, err := reservePolicyRevision(path); err != nil || v != 13 {
		t.Fatalf("restart: %d %v", v, err)
	}
	for _, b := range [][]byte{{}, {1}, make([]byte, 8), make([]byte, 9)} {
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := reservePolicyRevision(path); err == nil {
			t.Fatal("corruption reset counter")
		}
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, ^uint64(0))
	os.WriteFile(path, b, 0600)
	if _, err := reservePolicyRevision(path); err == nil {
		t.Fatal("wrapped revision")
	}
	if _, err := reservePolicyRevision(filepath.Join(path, "child")); err == nil {
		t.Fatal("ignored persistence failure")
	}
}

func TestDirectedPolicyOrderingAndIndependentBudgets(t *testing.T) {
	d, peer, _ := dynamicFixture(t, &runtimeBackend{})
	addr, id := peer.RemoteLoopbackV6, peer.RemoteUID.UUID
	if err := d.bindPolicyPeer(addr, id); err != nil {
		t.Fatal(err)
	}
	state := d.targets[addr]
	due := time.Now().Add(time.Minute)
	state.nextAttempt, state.nextQuery = due, due.Add(time.Minute)
	update := func(rev uint64, allow bool) {
		d.receivePolicy(addr, message.Message{Type: message.PolicyUpdate, UID: &peer.RemoteUID, Policy: &message.DynamicLinkPolicy{Revision: rev, Accept: allow}}, time.Now())
	}
	update(10, false)
	update(9, true)
	update(10, true)
	if state.policy.Revision != 10 || state.policy.Accept {
		t.Fatal("old/conflicting allowance overwrote denial")
	}
	update(11, true)
	for i := uint64(12); i < 100; i++ {
		update(i, true)
	}
	if state.nextAttempt != due || state.nextQuery != due.Add(time.Minute) || d.reserveDial(addr) {
		t.Fatal("updates bypassed an independent budget")
	}
	state.nextAttempt = time.Time{}
	if !d.reserveDial(addr) {
		t.Fatal("allowance failed to enable budgeted retry")
	}
	<-d.outboundSessions
	d.finishRoutedDial(addr, false)
	update(100, false)
	state.nextAttempt = time.Time{}
	if d.reserveDial(addr) {
		t.Fatal("denial allowed proposal")
	}
}

func TestPolicyQueryRecoveryAndIdentity(t *testing.T) {
	d, peer, _ := dynamicFixture(t, &runtimeBackend{})
	addr := peer.RemoteLoopbackV6
	query := message.Message{Type: message.PolicyQuery, UID: &peer.RemoteUID}
	d.receivePolicy(addr, message.Message{Type: message.PolicyUpdate, UID: &peer.RemoteUID, Policy: &message.DynamicLinkPolicy{Revision: 1, Accept: true}}, time.Now())
	if len(d.targets) != 0 {
		t.Fatal("unknown update created target")
	}
	d.receivePolicy(addr, query, time.Now())
	state := d.targets[addr]
	if state == nil || !state.pendingUpdate || state.bound {
		t.Fatal("query could not recover lost publisher cache")
	}
	d.receivePolicy(addr, message.Message{Type: message.PolicyUpdate, UID: &peer.RemoteUID, Policy: &message.DynamicLinkPolicy{Revision: 1, Accept: false}}, time.Now())
	if state.policy != nil {
		t.Fatal("query assertion authorized incoming updates")
	}
	state.pendingUpdate = false
	bad := query
	bad.UID = &message.UID{UUID: uuid.New()}
	d.receivePolicy(addr, bad, time.Now())
	if state.pendingUpdate || state.uid != peer.RemoteUID.UUID {
		t.Fatal("conflicting source changed identity")
	}
	d.runner.Desired.DynamicLinks.Mode = spec.DynamicLinksOff
	d.receivePolicy(addr, query, time.Now())
	if state.pendingUpdate {
		t.Fatal("denied query elicited response")
	}
	d.runner.Desired.DynamicLinks.Mode = spec.DynamicLinksPassive
	d.receivePolicy(addr, query, time.Now())
	if !state.pendingUpdate {
		t.Fatal("passive publisher did not answer")
	}
}

func TestDeclineSnapshotAndLateOperation(t *testing.T) {
	for _, reason := range []message.DeclineReason{message.DeclineOrdinary, message.DeclinePolicy} {
		d, session, _ := dynamicFixture(t, &runtimeBackend{})
		a, err := d.prepareOutbound(session)
		if err != nil {
			t.Fatal(err)
		}
		state := d.targets[session.RemoteLoopbackV6]
		state.policy = &message.DynamicLinkPolicy{Revision: 9, Accept: true}
		m := message.Message{Type: message.DynamicLinkDecline, OperationID: a.operationID, DeclineReason: reason, Policy: &message.DynamicLinkPolicy{Revision: 8, Accept: false}}
		d.handleDecline(session, m)
		if state.policy.Revision != 9 || !state.policy.Accept || len(d.attempts) != 0 {
			t.Fatal("old snapshot revived or overwrote attempt")
		}
		m.Policy.Revision = 10
		d.handleDecline(session, m)
		if state.policy.Revision != 9 {
			t.Fatal("late operation injected policy")
		}
	}
}

type recordedPolicySend struct {
	to netip.Addr
	m  message.Message
}
type fakePolicyTransport struct{ sends []recordedPolicySend }

func (f *fakePolicyTransport) Read() (netip.Addr, message.Message, error) {
	return netip.Addr{}, message.Message{}, net.ErrClosed
}
func (f *fakePolicyTransport) Send(to netip.Addr, m message.Message) error {
	f.sends = append(f.sends, recordedPolicySend{to, m})
	return nil
}
func (*fakePolicyTransport) Close() error { return nil }

func TestPolicySendingBudgetsAndNoReplyLoop(t *testing.T) {
	d, peer, _ := dynamicFixture(t, &runtimeBackend{})
	wire := &fakePolicyTransport{}
	d.policySocket = wire
	d.policyRevision = 7
	now := time.Now()
	addr := peer.RemoteLoopbackV6
	query := message.Message{Type: message.PolicyQuery, UID: &peer.RemoteUID}
	for range 100 {
		d.receivePolicy(addr, query, now)
		d.flushPolicy(now)
	}
	if len(wire.sends) != 1 || wire.sends[0].m.Policy.Revision != 7 {
		t.Fatal("query flood bypassed reply cooldown")
	}
	d.flushPolicy(now.Add(dynamicUpdateInterval))
	if len(wire.sends) != 2 {
		t.Fatal("coalesced reply was starved")
	}
	state := d.targets[addr]
	state.bound = true
	state.policy = &message.DynamicLinkPolicy{Revision: 3, Accept: false}
	state.pendingQuery = true
	state.nextAttempt = now.Add(time.Hour)
	d.flushPolicy(now.Add(dynamicUpdateInterval))
	if len(wire.sends) != 3 || wire.sends[2].m.Type != message.PolicyQuery {
		t.Fatal("attempt budget incorrectly blocked query")
	}
	nextQuery := state.nextQuery
	state.pendingQuery = true
	d.flushPolicy(now.Add(2 * dynamicUpdateInterval))
	if len(wire.sends) != 3 || state.nextQuery != nextQuery {
		t.Fatal("query budget not independent")
	}
	d.receivePolicy(addr, message.Message{Type: message.PolicyUpdate, UID: &peer.RemoteUID, Policy: &message.DynamicLinkPolicy{Revision: 4, Accept: true}}, now)
	d.flushPolicy(now.Add(3 * dynamicUpdateInterval))
	if len(wire.sends) != 3 || state.nextAttempt != now.Add(time.Hour) || state.nextQuery != nextQuery {
		t.Fatal("UPDATE replied or reset budget")
	}
}

func TestReloadPreservesBudgetsAndQueuesNewPolicy(t *testing.T) {
	d, peer, _ := dynamicFixture(t, &runtimeBackend{})
	d.bindPolicyPeer(peer.RemoteLoopbackV6, peer.RemoteUID.UUID)
	state := d.targets[peer.RemoteLoopbackV6]
	state.nextAttempt = time.Now().Add(time.Hour)
	state.nextQuery = time.Now().Add(2 * time.Hour)
	state.policy = &message.DynamicLinkPolicy{Revision: 50, Accept: false}
	next := &Runner{Desired: d.runner.Desired}
	next.InheritDynamic(d.runner)
	copy := next.policySeed[peer.RemoteLoopbackV6]
	if copy == state || copy.nextAttempt != state.nextAttempt || copy.nextQuery != state.nextQuery || copy.policy.Revision != 50 {
		t.Fatal("reload reset peer state")
	}
}

func TestPolicySendFairnessAndCapacity(t *testing.T) {
	d, peer, _ := dynamicFixture(t, &runtimeBackend{})
	wire := &fakePolicyTransport{}
	d.policySocket = wire
	d.policyRevision = 9
	now := time.Now()
	for i := 1; i <= maxPolicySendsPerTick*3; i++ {
		addr := netip.AddrFrom16([16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i >> 8), byte(i)})
		d.targets[addr] = &dynamicTarget{uid: uuid.New(), pendingUpdate: true, reachable: true}
	}
	for tick := range 3 {
		d.flushPolicy(now.Add(time.Duration(tick) * time.Second))
		if len(wire.sends) != (tick+1)*maxPolicySendsPerTick {
			t.Fatal("node-wide send budget failed")
		}
	}
	seen := map[netip.Addr]bool{}
	for _, send := range wire.sends {
		if seen[send.to] {
			t.Fatal("busy peer starved pending peer")
		}
		seen[send.to] = true
	}
	for len(d.targets) < maxDynamicTargets {
		addr := netip.AddrFrom16([16]byte{0xfd, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(len(d.targets) >> 8), byte(len(d.targets))})
		d.targets[addr] = &dynamicTarget{}
	}
	before := len(d.targets)
	d.receivePolicy(peer.RemoteLoopbackV6, message.Message{Type: message.PolicyQuery, UID: &peer.RemoteUID}, now)
	if len(d.targets) != before {
		t.Fatal("query overflow grew cache")
	}
}
