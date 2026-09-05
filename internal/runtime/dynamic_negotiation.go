package runtime

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/inference"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (d *dynamicRuntime) startOutbound(session *engine.Session) error {
	attempt, candidate, err := d.prepareOutbound(session)
	if err != nil || attempt == nil {
		return err
	}
	if err := session.Send(dynamicLinkMessage(message.DynamicLinkPropose, attempt, candidate)); err != nil {
		d.abortAttempt(attempt, "send Proposal failed")
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.isCurrentAttemptLocked(attempt) || attempt.state != dynamicProposing {
		return nil
	}
	attempt.responseTimer = time.AfterFunc(dynamicResponseTimeout, func() {
		d.failAttempt(attempt, "response timeout", dynamicProposing)
	})
	d.runner.log(Event{Event: "velvet-dynamic-attempt", Status: "proposed", RemoteUID: attempt.remote.String(), Interface: attempt.plan.InterfaceName})
	return nil
}

func (d *dynamicRuntime) prepareOutbound(session *engine.Session) (*dynamicAttempt, netip.AddrPort, error) {
	d.resourceMu.Lock()
	defer d.resourceMu.Unlock()
	var cleanup *reconcile.LinkPlan
	d.mu.Lock()
	defer func() {
		d.mu.Unlock()
		if cleanup != nil {
			d.removeInterface(*cleanup, "candidate inference failed")
		}
	}()
	if d.stopped || d.ctx.Err() != nil {
		return nil, netip.AddrPort{}, context.Canceled
	}
	remoteID := session.RemoteUID.UUID
	remoteLoopback := session.RemoteLoopbackV6
	// Reaching operational state completes UID binding. The Dynamic Link
	// decision is one-shot for this configuration generation.
	target := d.targets[remoteLoopback]
	if target == nil {
		target = &dynamicTarget{}
		d.targets[remoteLoopback] = target
	}
	target.attempted = true
	target.failures = 0
	if d.runner.hasDirectLink(remoteID) || d.attempts[remoteID] != nil {
		return nil, netip.AddrPort{}, nil
	}
	if len(d.attempts)+len(d.pendingCleanups) >= maxDynamicLinks {
		d.runner.log(Event{Event: "velvet-dynamic-attempt", Status: "failed", RemoteUID: remoteID.String(), Error: "dynamic Link limit reached"})
		return nil, netip.AddrPort{}, nil
	}
	if len(d.evidence) == 0 {
		d.runner.log(Event{Event: "velvet-dynamic-attempt", Status: "failed", RemoteUID: remoteID.String(), Error: "no Endpoint Observation"})
		return nil, netip.AddrPort{}, nil
	}
	operationID, err := newOperationID()
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	plan, err := d.runner.Reconciler.PrepareDynamic(d.ctx, d.runner.Desired, nodeUID(session.RemoteUID))
	if err != nil {
		d.runner.log(Event{Event: "velvet-dynamic-attempt", Status: "failed", RemoteUID: remoteID.String(), Error: err.Error()})
		return nil, netip.AddrPort{}, nil
	}
	candidate, ok := inference.Baseline(d.evidence, plan.ListenPort)
	if !ok {
		cleanup = &plan
		return nil, netip.AddrPort{}, errors.New("cannot infer Candidate from Endpoint Evidence")
	}
	attempt := &dynamicAttempt{
		remote: remoteID, operationID: operationID, localProposal: true,
		plan: plan, session: session, state: dynamicProposing,
	}
	d.attempts[remoteID] = attempt
	return attempt, candidate, nil
}

func (d *dynamicRuntime) handleRoutedMessage(session *engine.Session, value message.Message) error {
	switch value.Type {
	case message.DynamicLinkPropose:
		return d.handleProposal(session, value)
	case message.DynamicLinkAccept:
		return d.handleAccept(session, value)
	case message.DynamicLinkDecline:
		d.handleDecline(session, value)
	}
	return nil
}

func (d *dynamicRuntime) handleProposal(session *engine.Session, value message.Message) error {
	attempt, candidate := d.prepareInbound(session, value)
	if attempt == nil {
		return session.Send(message.Message{Type: message.DynamicLinkDecline, OperationID: value.OperationID})
	}
	if err := session.Send(dynamicLinkMessage(message.DynamicLinkAccept, attempt, candidate)); err != nil {
		d.abortAttempt(attempt, "send Accept failed")
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.isCurrentAttemptLocked(attempt) {
		d.startConnectivityLocked(attempt)
		d.runner.log(Event{Event: "velvet-dynamic-attempt", Status: "accepted", RemoteUID: attempt.remote.String(), Interface: attempt.plan.InterfaceName})
	}
	return nil
}

func (d *dynamicRuntime) prepareInbound(session *engine.Session, value message.Message) (*dynamicAttempt, netip.AddrPort) {
	d.resourceMu.Lock()
	defer d.resourceMu.Unlock()
	var cleanup *reconcile.LinkPlan
	d.mu.Lock()
	defer func() {
		d.mu.Unlock()
		if cleanup != nil {
			d.removeInterface(*cleanup, "configure accepted Proposal failed")
		}
	}()
	remoteID := session.RemoteUID.UUID
	if d.stopped || d.ctx.Err() != nil || !d.allowsInbound() || !d.candidateAllowed(value.Endpoint) || d.runner.hasDirectLink(remoteID) {
		return nil, netip.AddrPort{}
	}
	current := d.attempts[remoteID]
	_, pending := d.pendingCleanups[remoteID]
	if current == nil && !pending && len(d.attempts)+len(d.pendingCleanups) >= maxDynamicLinks {
		return nil, netip.AddrPort{}
	}
	if len(d.evidence) == 0 {
		return nil, netip.AddrPort{}
	}

	var plan reconcile.LinkPlan
	if current != nil {
		// In simultaneous proposals the smaller UUID wins. The other side keeps
		// its reserved interface so the winning operation can reuse its ifindex.
		if current.state != dynamicProposing || !current.localProposal || bytes.Compare(d.runner.Desired.UUID[:], remoteID[:]) < 0 {
			return nil, netip.AddrPort{}
		}
		plan = current.plan
		d.discardAttemptLocked(remoteID, current)
	}
	if cleanup := d.pendingCleanups[remoteID]; cleanup != nil && plan.InterfaceName == "" {
		plan = cleanup.plan
	}
	d.cancelDeferredCleanupLocked(remoteID)
	if plan.InterfaceName == "" {
		var err error
		plan, err = d.runner.Reconciler.PrepareDynamic(d.ctx, d.runner.Desired, nodeUID(session.RemoteUID))
		if err != nil {
			return nil, netip.AddrPort{}
		}
	}
	candidate, ok := inference.Baseline(d.evidence, plan.ListenPort)
	if !ok {
		cleanup = &plan
		return nil, netip.AddrPort{}
	}
	configured, err := d.runner.Reconciler.ConfigureDynamic(
		d.ctx, d.runner.Desired, plan, wgtypes.Key(value.WGPublicKey), value.Endpoint,
	)
	if err != nil {
		cleanup = &plan
		return nil, netip.AddrPort{}
	}
	attempt := &dynamicAttempt{
		remote: remoteID, operationID: value.OperationID,
		plan: configured, session: session, state: dynamicAttempting,
	}
	d.attempts[remoteID] = attempt
	return attempt, candidate
}

func (d *dynamicRuntime) handleAccept(session *engine.Session, value message.Message) error {
	d.resourceMu.Lock()
	defer d.resourceMu.Unlock()
	var cleanup *reconcile.LinkPlan
	var cleanupReason string
	d.mu.Lock()
	defer func() {
		d.mu.Unlock()
		if cleanup != nil {
			d.removeInterface(*cleanup, cleanupReason)
		}
	}()
	attempt := d.proposingAttemptLocked(session, value.OperationID)
	if attempt == nil {
		d.runner.log(Event{Event: "velvet-frame", Status: "discarded", Error: "DYNAMIC_LINK_ACCEPT references an unknown operation"})
		return nil
	}
	if !d.candidateAllowed(value.Endpoint) {
		d.discardAttemptLocked(attempt.remote, attempt)
		cleanup = &attempt.plan
		cleanupReason = "Accept candidate rejected"
		return nil
	}
	plan, err := d.runner.Reconciler.ConfigureDynamic(
		d.ctx, d.runner.Desired, attempt.plan, wgtypes.Key(value.WGPublicKey), value.Endpoint,
	)
	if err != nil {
		d.discardAttemptLocked(attempt.remote, attempt)
		cleanup = &attempt.plan
		cleanupReason = "configure accepted Link failed"
		return nil
	}
	attempt.plan = plan
	attempt.state = dynamicAttempting
	if attempt.responseTimer != nil {
		attempt.responseTimer.Stop()
	}
	d.startConnectivityLocked(attempt)
	return nil
}

func (d *dynamicRuntime) handleDecline(session *engine.Session, value message.Message) {
	d.mu.Lock()
	defer d.mu.Unlock()
	attempt := d.proposingAttemptLocked(session, value.OperationID)
	if attempt == nil {
		d.runner.log(Event{Event: "velvet-frame", Status: "discarded", Error: "DYNAMIC_LINK_DECLINE references an unknown operation"})
		return
	}
	// The peer's winning simultaneous Proposal can cross this DECLINE. Delay
	// deletion so it can reuse the ifindex and avoid a stale IPv6 zone cache.
	d.discardAttemptLocked(attempt.remote, attempt)
	d.deferCleanupLocked(attempt.remote, attempt.plan, "Proposal declined")
	d.runner.log(Event{Event: "velvet-dynamic-attempt", Status: "declined", RemoteUID: attempt.remote.String()})
}

func (d *dynamicRuntime) proposingAttemptLocked(session *engine.Session, operationID [16]byte) *dynamicAttempt {
	attempt := d.attempts[session.RemoteUID.UUID]
	if attempt == nil || attempt.session != session || attempt.operationID != operationID || attempt.state != dynamicProposing {
		return nil
	}
	return attempt
}

func (d *dynamicRuntime) isCurrentAttemptLocked(attempt *dynamicAttempt) bool {
	return d.attempts[attempt.remote] == attempt
}

func (d *dynamicRuntime) abortAttempt(attempt *dynamicAttempt, reason string) {
	d.resourceMu.Lock()
	defer d.resourceMu.Unlock()
	d.mu.Lock()
	current := d.isCurrentAttemptLocked(attempt)
	if current {
		d.discardAttemptLocked(attempt.remote, attempt)
	}
	d.mu.Unlock()
	if current {
		d.removeInterface(attempt.plan, reason)
	}
}

func dynamicLinkMessage(kind message.Type, attempt *dynamicAttempt, candidate netip.AddrPort) message.Message {
	return message.Message{
		Type: kind, OperationID: attempt.operationID,
		WGPublicKey: [32]byte(attempt.plan.PrivateKey.PublicKey()),
		Endpoint:    candidate,
	}
}
