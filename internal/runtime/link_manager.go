package runtime

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
)

// Link resources outlive discovery Attempts. The generation is the complete
// owner alias installed in the kernel, rather than the reusable interface name.
type linkResources struct {
	plan    reconcile.LinkPlan
	port    *portLease
	cleanup bool
}
type linkManager struct {
	resourceMu sync.Mutex
	mu         sync.Mutex
	resources  map[string]*linkResources
}

func (m *linkManager) own(plan reconcile.LinkPlan, lease *portLease) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.resources == nil {
		m.resources = map[string]*linkResources{}
	}
	m.resources[plan.OwnerAlias] = &linkResources{plan: plan, port: lease}
}
func (m *linkManager) removed(plan reconcile.LinkPlan, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	resource := m.resources[plan.OwnerAlias]
	if resource == nil {
		return
	}
	if err != nil {
		resource.cleanup = true
		return
	}
	resource.port.release()
	delete(m.resources, plan.OwnerAlias)
}

func (r *Runner) retryLinkCleanup(ctx context.Context) {
	r.links.resourceMu.Lock()
	defer r.links.resourceMu.Unlock()
	r.links.mu.Lock()
	var plans []reconcile.LinkPlan
	for _, resource := range r.links.resources {
		if resource.cleanup {
			plans = append(plans, resource.plan)
		}
	}
	r.links.mu.Unlock()
	for _, plan := range plans {
		attemptCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := r.Reconciler.RemoveDynamic(attemptCtx, plan)
		cancel()
		r.links.removed(plan, err)
	}
}

// A configured Static takes over only after it is healthy. Explicit Static
// interfaces do not suppress each other; an automatic standby keeps its record.
func (r *Runner) hasHealthyStatic(remote uuid.UUID) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, state := range r.states {
		if state.active && !state.dynamic && state.remote == remote {
			return true
		}
	}
	return false
}

func (r *Runner) staticTakesOver(remote uuid.UUID) {
	d := r.dynamic
	d.mu.Lock()
	a := d.attempts[remote]
	d.mu.Unlock()
	if a != nil {
		d.failAttempt(a, "healthy static Link takes priority", dynamicPreparing, dynamicProposing, dynamicProbing, dynamicAttempting, dynamicRecovering, dynamicUp)
	}
}

// The health loop reports lifecycle events without knowing discovery states or
// retaining a discovery session. Resource policy is selected at this boundary.
type linkControl struct {
	ready              func(bool)
	automatic, passive bool
	peer               uuid.UUID
	commit             func(context.Context, engine.Result) error
	failed             func(context.Context)
}

func (r *Runner) staticControl(plan reconcile.LinkPlan, onCommit func(engine.Result)) *linkControl {
	return &linkControl{commit: func(ctx context.Context, result engine.Result) error {
		r.links.resourceMu.Lock()
		defer r.links.resourceMu.Unlock()
		return r.commitLink(ctx, plan, false, result, onCommit)
	}}
}
func (d *dynamicLinkEngine) linkControl(a *dynamicAttempt) *linkControl {
	return &linkControl{automatic: true, passive: !a.localProposal, peer: a.remote,
		ready: func(value bool) {
			d.mu.Lock()
			defer d.mu.Unlock()
			if d.isCurrentAttemptLocked(a) {
				a.controlReady = value
			}
		},
		commit: func(ctx context.Context, result engine.Result) error { return d.commitLink(ctx, a, result) },
		failed: func(ctx context.Context) {
			d.mu.Lock()
			defer d.mu.Unlock()
			if d.isCurrentAttemptLocked(a) && a.state == dynamicUp {
				a.state = dynamicRecovering
				d.armConnectivityDeadlineLocked(a, ctx)
				d.runner.log(Event{Event: "velvet-dynamic-link", Status: "recovering", Interface: a.plan.InterfaceName, RemoteUID: a.remote.String(), Error: "Link PONG deadline"})
			}
		}}
}

func (r *Runner) liveDesired() *reconcile.DesiredState {
	state := *r.Desired
	state.Links = append([]reconcile.LinkPlan(nil), state.Links...)
	r.links.mu.Lock()
	defer r.links.mu.Unlock()
	for i, plan := range state.Links {
		if owned := r.links.resources[plan.OwnerAlias]; owned != nil && !owned.cleanup {
			state.Links[i] = owned.plan
		}
	}
	return &state
}

func (r *Runner) retryStaticPort(ctx context.Context, plan reconcile.LinkPlan) (reconcile.LinkPlan, error) {
	r.links.resourceMu.Lock()
	defer r.links.resourceMu.Unlock()
	lease, err := r.reserveStaticPort(ctx, plan)
	if err != nil {
		return plan, err
	}
	next := plan
	next.ListenPort = lease.port
	next.WaitingPort = false
	r.links.own(next, lease)
	next, err = r.Reconciler.PrepareLink(ctx, next)
	if err == nil {
		err = r.Reconciler.ConfigureLink(ctx, next)
	}
	if err != nil {
		cleanupErr := r.Reconciler.RemoveDynamic(ctx, plan)
		r.links.removed(plan, cleanupErr)
		return plan, err
	}
	r.links.own(next, lease)
	return next, nil
}

func (d *dynamicLinkEngine) resourceCountLocked() int {
	count := len(d.attempts) + len(d.pendingCleanups)
	d.runner.links.mu.Lock()
	defer d.runner.links.mu.Unlock()
	for _, resource := range d.runner.links.resources {
		if resource.cleanup {
			count++
		}
	}
	return count
}
