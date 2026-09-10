package runtime

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/inference"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// prepareAttemptLocked is the common entry after admission and simultaneous
// Proposal arbitration. Reserve a UDP socket and a DOWN WG interface, then
// freeze the initial baseline hint. A reused reservation
// belongs to a superseded Proposal, not a retry of a failed Candidate.
// Requires resourceMu and mu. Even on error the caller owns the returned Attempt
// and must pass it to fallbackLocked before releasing the locks.
func (d *dynamicLinkEngine) prepareAttemptLocked(session *engine.Session, operationID [16]byte, localProposal bool, reserved reconcile.LinkPlan) (*dynamicAttempt, error) {
	attempt := &dynamicAttempt{
		remote: session.RemoteUID.UUID, operationID: operationID, localProposal: localProposal,
		plan: reserved, session: session, state: dynamicPreparing,
	}
	d.attempts[attempt.remote] = attempt
	hint, ok := inference.Baseline(d.evidence, 1)
	if !ok {
		return attempt, errors.New("cannot infer Candidate from Endpoint Evidence")
	}
	u, err := d.prepareUDP(attempt, hint)
	if err != nil {
		return attempt, err
	}
	attempt.udp = u
	if attempt.plan.InterfaceName == "" {
		plan, err := d.runner.Reconciler.PrepareProbe(d.ctx, d.runner.Desired, nodeUID(session.RemoteUID), int(u.primary.Endpoint().Port()))
		if err != nil {
			return attempt, err
		}
		attempt.plan = plan
	}
	attempt.plan.ListenPort = int(u.primary.Endpoint().Port())
	attempt.plan.Probing = true
	candidate, ok := inference.Baseline(d.evidence, attempt.plan.ListenPort)
	if !ok {
		return attempt, errors.New("cannot infer Candidate")
	}
	attempt.candidate = candidate
	d.runner.log(Event{Event: "velvet-udp-probe", Status: "prepared", RemoteUID: attempt.remote.String(), Interface: attempt.plan.InterfaceName, LocalEndpoint: u.primary.Endpoint().String()})
	return attempt, nil
}

// configureAttemptLocked binds the remote probe parameters without enabling WG.
// UDP discovery starts only after the corresponding Accept has been sent or
// received. Requires resourceMu and mu; the caller handles failure via fallback.
func (d *dynamicLinkEngine) configureAttemptLocked(attempt *dynamicAttempt, value message.Message) error {
	if !d.candidateAllowed(value.Endpoint) {
		return errors.New("remote Candidate rejected")
	}
	if value.ProbeKey == [32]byte{} {
		return errors.New("missing probe receive key")
	}
	if wgtypes.Key(value.WGPublicKey) == attempt.plan.PrivateKey.PublicKey() {
		return errors.New("peer WireGuard key equals local key")
	}
	attempt.udp.remoteEndpoint = value.Endpoint
	attempt.udp.remoteKey = value.ProbeKey
	attempt.udp.remotePublicKey = wgtypes.Key(value.WGPublicKey)
	attempt.state = dynamicProbing
	if attempt.responseTimer != nil {
		attempt.responseTimer.Stop()
	}
	return nil
}

func (d *dynamicLinkEngine) commitLink(ctx context.Context, attempt *dynamicAttempt, result engine.Result) error {
	d.resourceMu.Lock()
	defer d.resourceMu.Unlock()
	var cleanup *reconcile.LinkPlan
	var failure error
	d.mu.Lock()
	defer func() {
		d.mu.Unlock()
		if cleanup != nil {
			d.removeInterface(*cleanup, failure.Error())
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if d.stopped || d.attempts[attempt.remote] != attempt || (attempt.state != dynamicAttempting && attempt.state != dynamicRecovering) {
		return errors.New("dynamic Link Attempt is no longer awaiting connectivity")
	}
	if result.RemoteUID.UUID != attempt.remote {
		failure = errors.New("dynamic Link Node UID does not match routed target")
	} else {
		failure = d.runner.commitLink(ctx, attempt.plan, true, result, nil)
	}
	if failure != nil {
		cleanup = d.fallbackLocked(attempt, failure.Error())
		return failure
	}
	d.commitAttemptLocked(attempt)
	return nil
}

func (d *dynamicLinkEngine) commitAttemptLocked(attempt *dynamicAttempt) {
	recovered := attempt.state == dynamicRecovering
	attempt.state = dynamicUp
	if t := d.targetForPeerLocked(attempt.remote); t != nil {
		t.failures = 0
		t.nextAttempt = time.Time{}
	}
	if attempt.localProposal && attempt.session != nil {
		_ = attempt.session.Close()
	}
	if attempt.deadlineTimer != nil {
		attempt.deadlineTimer.Stop()
	}
	status := "up"
	if recovered {
		status = "recovered"
	}
	d.runner.log(Event{Event: "velvet-dynamic-link", Status: status, RemoteUID: attempt.remote.String(), Interface: attempt.plan.InterfaceName})
}

// fallbackLocked is the terminal failure decision after a discovery task:
// stop this Attempt, release its Link, and leave the existing routed path alone.
// It schedules a future budgeted opportunity without starting another task.
// A stale result cannot stop a replacement Attempt.
//
// Requires mu. The returned plan must be removed under resourceMu after releasing
// mu. Decline alone defers removal to allow a crossing winning Proposal to reuse
// the reservation; that protocol race does not keep the failed Attempt alive.
func (d *dynamicLinkEngine) fallbackLocked(attempt *dynamicAttempt, reason string) *reconcile.LinkPlan {
	if !d.isCurrentAttemptLocked(attempt) {
		return nil
	}
	d.discardAttemptLocked(attempt.remote, attempt)
	if t := d.targetForPeerLocked(attempt.remote); t != nil {
		next := time.Now().Add(retryDelay(t.failures))
		if next.After(t.nextAttempt) {
			t.nextAttempt = next
		}
	}
	if attempt.localProposal && attempt.session != nil {
		_ = attempt.session.Close()
	}
	d.runner.log(Event{Event: "velvet-dynamic-attempt", Status: "failed", RemoteUID: attempt.remote.String(), Error: reason})
	if attempt.plan.InterfaceName == "" {
		return nil
	}
	plan := attempt.plan
	return &plan
}

func (d *dynamicLinkEngine) failAttempt(attempt *dynamicAttempt, reason string, allowed ...dynamicAttemptState) {
	d.resourceMu.Lock()
	defer d.resourceMu.Unlock()
	d.mu.Lock()
	var cleanup *reconcile.LinkPlan
	if d.isCurrentAttemptLocked(attempt) && slices.Contains(allowed, attempt.state) {
		cleanup = d.fallbackLocked(attempt, reason)
	}
	d.mu.Unlock()
	if cleanup != nil {
		d.removeInterface(*cleanup, reason)
	}
}
