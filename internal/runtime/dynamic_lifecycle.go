package runtime

import (
	"context"
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
)

func (d *dynamicRuntime) startConnectivityLocked(attempt *dynamicAttempt) {
	ctx, cancel := context.WithCancel(d.ctx)
	attempt.cancel = cancel
	d.armConnectivityDeadlineLocked(attempt, ctx)
	go d.establishDynamic(ctx, attempt)
}

func (d *dynamicRuntime) establishDynamic(ctx context.Context, attempt *dynamicAttempt) {
	for ctx.Err() == nil {
		conn, err := d.runner.discoverPeer(ctx, attempt.plan)
		if err == nil {
			err = d.runner.serveLinkSession(ctx, conn, attempt.plan, true, dynamicConnectivityTimeout, func(result engine.Result) {
				d.commitAttempt(attempt, result)
			})
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
		d.failAttempt(attempt, "connectivity recovery deadline", dynamicAttempting, dynamicRecovering)
	}
}

func (d *dynamicRuntime) commitAttempt(attempt *dynamicAttempt, result engine.Result) {
	d.mu.Lock()
	defer d.mu.Unlock()
	current := d.attempts[attempt.remote]
	if current != attempt || result.RemoteUID.UUID != attempt.remote {
		return
	}
	recovered := attempt.state == dynamicRecovering
	attempt.state = dynamicUp
	if attempt.deadlineTimer != nil {
		attempt.deadlineTimer.Stop()
	}
	status := "up"
	if recovered {
		status = "recovered"
	}
	d.runner.log(Event{Event: "velvet-dynamic-link", Status: status, RemoteUID: attempt.remote.String(), Interface: attempt.plan.InterfaceName})
}

func (d *dynamicRuntime) failAttempt(attempt *dynamicAttempt, reason string, allowed ...dynamicAttemptState) {
	d.mu.Lock()
	if d.attempts[attempt.remote] != attempt || !slices.Contains(allowed, attempt.state) {
		d.mu.Unlock()
		return
	}
	d.discardAttemptLocked(attempt.remote, attempt)
	d.mu.Unlock()
	d.removeInterface(attempt.plan, reason)
	d.runner.log(Event{Event: "velvet-dynamic-attempt", Status: "failed", RemoteUID: attempt.remote.String(), Error: reason})
}

func (d *dynamicRuntime) discardAttemptLocked(remote uuid.UUID, attempt *dynamicAttempt) {
	delete(d.attempts, remote)
	stopAttempt(attempt)
}

func stopAttempt(attempt *dynamicAttempt) {
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

func (d *dynamicRuntime) deferCleanupLocked(remote uuid.UUID, plan reconcile.LinkPlan, reason string) {
	d.cancelDeferredCleanupLocked(remote)
	cleanup := &dynamicCleanup{plan: plan}
	cleanup.timer = time.AfterFunc(dynamicResponseTimeout, func() {
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

func (d *dynamicRuntime) cancelDeferredCleanupLocked(remote uuid.UUID) {
	if cleanup := d.pendingCleanups[remote]; cleanup != nil {
		cleanup.timer.Stop()
		delete(d.pendingCleanups, remote)
	}
}

func (d *dynamicRuntime) routedSessionClosed(session *engine.Session) {
	d.mu.Lock()
	attempt, exists := d.attempts[session.RemoteUID.UUID]
	if exists && attempt.session == session && attempt.state == dynamicProposing {
		d.discardAttemptLocked(session.RemoteUID.UUID, attempt)
	} else {
		attempt = nil
	}
	d.mu.Unlock()
	if attempt != nil {
		d.removeInterface(attempt.plan, "routed session closed before response")
	}
}

func (d *dynamicRuntime) candidateAllowed(candidate netip.AddrPort) bool {
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

func (d *dynamicRuntime) setEvidence(interfaceName string, endpoint netip.AddrPort) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range d.evidence {
		if d.evidence[i].interfaceName == interfaceName {
			d.evidence[i].endpoint = endpoint
			return
		}
	}
	d.evidence = append(d.evidence, endpointEvidence{interfaceName: interfaceName, endpoint: endpoint})
}

func (d *dynamicRuntime) firstEvidenceLocked() (netip.AddrPort, bool) {
	if len(d.evidence) == 0 {
		return netip.AddrPort{}, false
	}
	return d.evidence[0].endpoint, true
}

func (d *dynamicRuntime) removeEvidenceLocked(interfaceName string) {
	for i := range d.evidence {
		if d.evidence[i].interfaceName == interfaceName {
			d.evidence = slices.Delete(d.evidence, i, i+1)
			return
		}
	}
}

func (d *dynamicRuntime) removeInterface(plan reconcile.LinkPlan, reason string) {
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

func (d *dynamicRuntime) armConnectivityDeadlineLocked(attempt *dynamicAttempt, ctx context.Context) {
	if attempt.deadlineTimer != nil {
		attempt.deadlineTimer.Stop()
	}
	attempt.deadlineTimer = time.AfterFunc(dynamicConnectivityTimeout, func() {
		d.mu.Lock()
		current := d.attempts[attempt.remote]
		shouldCancel := current == attempt && attempt.state != dynamicUp && ctx.Err() == nil
		cancel := attempt.cancel
		d.mu.Unlock()
		if shouldCancel && cancel != nil {
			cancel()
		}
	})
}
