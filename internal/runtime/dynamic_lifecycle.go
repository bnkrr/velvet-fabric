package runtime

import (
	"context"
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/inference"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
)

func (d *dynamicLinkEngine) startConnectivityLocked(attempt *dynamicAttempt) {
	ctx, cancel := context.WithCancel(d.ctx)
	attempt.cancel = cancel
	d.armConnectivityDeadlineLocked(attempt, ctx)
	d.workers.Go(func() { d.establishDynamic(ctx, attempt) })
}

func (d *dynamicLinkEngine) establishDynamic(ctx context.Context, attempt *dynamicAttempt) {
	// Discovery/TCP/VFP may reconnect within this Attempt's deadline. This is
	// connectivity work on the frozen Candidate, not another inference round.
	for ctx.Err() == nil {
		conn, err := d.runner.discoverPeer(ctx, attempt.plan)
		if err == nil {
			err = d.runner.serveLinkSession(ctx, conn, attempt.plan, attempt, dynamicConnectivityTimeout, nil)
		}
		if ctx.Err() != nil {
			break
		}
		d.mu.Lock()
		current := d.attempts[attempt.remote]
		if current != attempt {
			d.mu.Unlock()
			return
		}
		if attempt.state == dynamicUp {
			attempt.state = dynamicRecovering
			d.armConnectivityDeadlineLocked(attempt, ctx)
			d.runner.log(Event{Event: "velvet-dynamic-link", Status: "recovering", RemoteUID: attempt.remote.String(), Interface: attempt.plan.InterfaceName, Error: errorText(err)})
		}
		d.mu.Unlock()
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
		}
	}
	if d.ctx.Err() == nil {
		d.failAttempt(attempt, "connectivity deadline", dynamicAttempting, dynamicRecovering)
	}
}

func (d *dynamicLinkEngine) discardAttemptLocked(remote uuid.UUID, attempt *dynamicAttempt) {
	delete(d.attempts, remote)
	stopAttempt(attempt)
}

func stopAttempt(attempt *dynamicAttempt) {
	attempt.state = dynamicStopped
	if attempt.responseTimer != nil {
		attempt.responseTimer.Stop()
	}
	if attempt.deadlineTimer != nil {
		attempt.deadlineTimer.Stop()
	}
	if attempt.cancel != nil {
		attempt.cancel()
	}
}

func (d *dynamicLinkEngine) deferCleanupLocked(remote uuid.UUID, plan reconcile.LinkPlan, reason string) {
	d.cancelDeferredCleanupLocked(remote)
	cleanup := &dynamicCleanup{plan: plan}
	cleanup.timer = time.AfterFunc(dynamicResponseTimeout, func() {
		d.resourceMu.Lock()
		defer d.resourceMu.Unlock()
		d.mu.Lock()
		if d.pendingCleanups[remote] != cleanup {
			d.mu.Unlock()
			return
		}
		delete(d.pendingCleanups, remote)
		if attempt := d.attempts[remote]; attempt != nil && attempt.plan.InterfaceName == plan.InterfaceName {
			d.mu.Unlock()
			return
		}
		d.mu.Unlock()
		d.removeInterface(plan, reason)
	})
	d.pendingCleanups[remote] = cleanup
}

func (d *dynamicLinkEngine) cancelDeferredCleanupLocked(remote uuid.UUID) {
	if cleanup := d.pendingCleanups[remote]; cleanup != nil {
		cleanup.timer.Stop()
		delete(d.pendingCleanups, remote)
	}
}

func (d *dynamicLinkEngine) routedSessionClosed(session *engine.Session) {
	d.resourceMu.Lock()
	defer d.resourceMu.Unlock()
	d.mu.Lock()
	var cleanup *reconcile.LinkPlan
	attempt, exists := d.attempts[session.RemoteUID.UUID]
	if exists && attempt.session == session && attempt.state == dynamicProposing {
		cleanup = d.fallbackLocked(attempt, "routed session closed before response")
	}
	d.mu.Unlock()
	if cleanup != nil {
		d.removeInterface(*cleanup, "routed session closed before response")
	}
}

func (d *dynamicLinkEngine) candidateAllowed(candidate netip.AddrPort) bool {
	plan := d.runner.Desired.DynamicLinks
	if plan == nil {
		return false
	}
	for _, prefix := range plan.AllowCandidatePrefixes {
		if prefix.Contains(candidate.Addr()) {
			return true
		}
	}
	return false
}

func (d *dynamicLinkEngine) setEvidence(interfaceName string, localListenPort int, endpoint netip.AddrPort) error {
	value, err := inference.NewEvidence(interfaceName, localListenPort, endpoint)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range d.evidence {
		if d.evidence[i].Link == interfaceName {
			d.evidence[i] = value
			return nil
		}
	}
	d.evidence = append(d.evidence, value)
	return nil
}

func (d *dynamicLinkEngine) removeEvidenceLocked(interfaceName string) {
	for i := range d.evidence {
		if d.evidence[i].Link == interfaceName {
			d.evidence = slices.Delete(d.evidence, i, i+1)
			return
		}
	}
}

// removeInterface requires resourceMu. No new Attempt can reuse the interface
// between dropping its runtime state and completing kernel deletion.
func (d *dynamicLinkEngine) removeInterface(plan reconcile.LinkPlan, reason string) {
	d.mu.Lock()
	d.removeEvidenceLocked(plan.InterfaceName)
	d.mu.Unlock()
	d.runner.removeDynamicState(plan)
	d.runner.log(Event{Event: "velvet-dynamic-link", Status: "cleanup", Interface: plan.InterfaceName, Error: reason})
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(d.ctx), 5*time.Second)
	defer cancel()
	if err := d.runner.Reconciler.RemoveDynamic(cleanupCtx, plan); err != nil {
		d.runner.log(Event{Event: "velvet-dynamic-link", Status: "cleanup-failed", Interface: plan.InterfaceName, Error: err.Error()})
	}
}

func (d *dynamicLinkEngine) armConnectivityDeadlineLocked(attempt *dynamicAttempt, ctx context.Context) {
	if attempt.deadlineTimer != nil {
		attempt.deadlineTimer.Stop()
	}
	attempt.deadlineEpoch++
	epoch := attempt.deadlineEpoch
	attempt.deadlineTimer = time.AfterFunc(dynamicConnectivityTimeout, func() {
		d.expireConnectivity(attempt, ctx, epoch)
	})
}

func (d *dynamicLinkEngine) expireConnectivity(attempt *dynamicAttempt, ctx context.Context, epoch uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.attempts[attempt.remote] == attempt && attempt.deadlineEpoch == epoch && attempt.state != dynamicUp && ctx.Err() == nil && attempt.cancel != nil {
		attempt.cancel()
	}
}
