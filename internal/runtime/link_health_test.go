package runtime

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
)

func TestLinkHealthRejectsUnknownExpiredDuplicateAndPreviousChallenges(t *testing.T) {
	now := time.Unix(1000, 0)
	var h linkHealth
	first, err := h.challenge(now)
	if err != nil {
		t.Fatal(err)
	}
	if h.pong([16]byte{99}, now) || !h.lastPong.IsZero() {
		t.Fatal("unsolicited PONG changed liveness")
	}
	if !h.pong(first, now.Add(time.Second)) {
		t.Fatal("current PONG rejected")
	}
	confirmed := h.lastPong
	if h.pong(first, now.Add(2*time.Second)) || h.lastPong != confirmed {
		t.Fatal("duplicate renewed liveness")
	}
	previous, _ := h.challenge(now.Add(3 * time.Second))
	current, _ := h.challenge(now.Add(4 * time.Second))
	if h.pong(previous, now.Add(5*time.Second)) {
		t.Fatal("superseded PONG accepted")
	}
	if h.pong(current, now.Add(14*time.Second)) {
		t.Fatal("expired PONG accepted")
	}
	if !h.expired(now.Add(31 * time.Second)) {
		t.Fatal("invalid responses kept a dead link up")
	}
	// Restart loses pending work, and the replacement challenge is unrelated.
	h = linkHealth{}
	replacement, _ := h.challenge(now.Add(time.Minute))
	if replacement == current || h.pong(current, now.Add(time.Minute)) {
		t.Fatal("old supervisor response accepted")
	}
	if !h.pong(replacement, now.Add(time.Minute+time.Second)) {
		t.Fatal("fresh response did not recover liveness")
	}
}

// Exercise the runtime's negotiation configuration (including loopback scope),
// not only the protocol FSM. Closing TCP must not remove committed state.
func TestRuntimeShortNegotiationPreservesLinkAfterTCPCloses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	makeRunner := func(id, addr string) *Runner {
		r := &Runner{Desired: &reconcile.DesiredState{UUID: uuid.MustParse(id), LoopbackV6: netip.MustParseAddr(addr), LoopbackPoolV6: netip.MustParsePrefix("fd00::/64"), FabricPSK: bytes.Repeat([]byte{3}, 32)}, Reconciler: reconcile.New(&runtimeBackend{}), states: map[string]materializedState{}}
		r.dynamic = newDynamicLinkEngine(r)
		return r
	}
	a := makeRunner("10000000-0000-4000-8000-000000000001", "fd00::1")
	b := makeRunner("20000000-0000-4000-8000-000000000002", "fd00::2")
	ac, bc := net.Pipe()
	done := make(chan error, 2)
	for _, peer := range []struct {
		r    *Runner
		c    net.Conn
		name string
	}{{a, ac, "vl-a"}, {b, bc, "vl-b"}} {
		go func() {
			plan := reconcile.LinkPlan{InterfaceName: peer.name}
			done <- peer.r.negotiateLink(ctx, peer.c, plan, func(result engine.Result) error { return peer.r.commitLink(ctx, plan, false, result, nil) })
		}()
	}
	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("negotiation did not close itself")
		}
	}
	if !a.hasDirectLink(b.Desired.UUID) || !b.hasDirectLink(a.Desired.UUID) {
		t.Fatal("closed TCP removed Link state")
	}
}
