package runtime

import (
	"bytes"
	"context"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
)

func (d *dynamicLinkEngine) startOutbound(session *engine.Session) error {
	attempt, err := d.prepareOutbound(session)
	if err != nil || attempt == nil {
		return err
	}
	if err := session.Send(dynamicLinkMessage(message.DynamicLinkPropose, attempt)); err != nil {
		d.failAttempt(attempt, "send Proposal failed", dynamicProposing)
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

func (d *dynamicLinkEngine) prepareOutbound(session *engine.Session) (*dynamicAttempt, error) {
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
	if d.stopped || d.ctx.Err() != nil {
		return nil, context.Canceled
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
		return nil, nil
	}
	if len(d.attempts)+len(d.pendingCleanups) >= maxDynamicLinks {
		d.runner.log(Event{Event: "velvet-dynamic-attempt", Status: "failed", RemoteUID: remoteID.String(), Error: "dynamic Link limit reached"})
		return nil, nil
	}
	if len(d.evidence) == 0 {
		d.runner.log(Event{Event: "velvet-dynamic-attempt", Status: "failed", RemoteUID: remoteID.String(), Error: "no Endpoint Observation"})
		return nil, nil
	}
	operationID, err := newOperationID()
	if err != nil {
		return nil, err
	}
	attempt, err := d.prepareAttemptLocked(session, operationID, true, reconcile.LinkPlan{})
	if err != nil {
		failure = err
		cleanup = d.fallbackLocked(attempt, err.Error())
		return nil, err
	}
	attempt.state = dynamicProposing
	return attempt, nil
}

func (d *dynamicLinkEngine) handleRoutedMessage(session *engine.Session, value message.Message) error {
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

func (d *dynamicLinkEngine) handleProposal(session *engine.Session, value message.Message) error {
	attempt := d.prepareInbound(session, value)
	if attempt == nil {
		return session.Send(message.Message{Type: message.DynamicLinkDecline, OperationID: value.OperationID})
	}
	if err := session.Send(dynamicLinkMessage(message.DynamicLinkAccept, attempt)); err != nil {
		d.failAttempt(attempt, "send Accept failed", dynamicAttempting)
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

func (d *dynamicLinkEngine) prepareInbound(session *engine.Session, value message.Message) *dynamicAttempt {
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
	remoteID := session.RemoteUID.UUID
	if d.stopped || d.ctx.Err() != nil || !d.allowsInbound() || !d.candidateAllowed(value.Endpoint) || d.runner.hasDirectLink(remoteID) {
		return nil
	}
	current := d.attempts[remoteID]
	_, pending := d.pendingCleanups[remoteID]
	if current == nil && !pending && len(d.attempts)+len(d.pendingCleanups) >= maxDynamicLinks {
		return nil
	}
	if len(d.evidence) == 0 {
		return nil
	}

	var plan reconcile.LinkPlan
	if current != nil {
		// In simultaneous proposals the smaller UUID wins. The other side keeps
		// its reserved interface so the winning operation can reuse its ifindex.
		if current.state != dynamicProposing || !current.localProposal || bytes.Compare(d.runner.Desired.UUID[:], remoteID[:]) < 0 {
			return nil
		}
		plan = current.plan
		d.discardAttemptLocked(remoteID, current)
	}
	if cleanup := d.pendingCleanups[remoteID]; cleanup != nil && plan.InterfaceName == "" {
		plan = cleanup.plan
	}
	d.cancelDeferredCleanupLocked(remoteID)
	attempt, err := d.prepareAttemptLocked(session, value.OperationID, false, plan)
	if err == nil {
		err = d.configureAttemptLocked(attempt, value)
	}
	if err != nil {
		failure = err
		cleanup = d.fallbackLocked(attempt, err.Error())
		return nil
	}
	return attempt
}

func (d *dynamicLinkEngine) handleAccept(session *engine.Session, value message.Message) error {
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
	if err := d.configureAttemptLocked(attempt, value); err != nil {
		cleanupReason = err.Error()
		cleanup = d.fallbackLocked(attempt, cleanupReason)
		return nil
	}
	d.startConnectivityLocked(attempt)
	return nil
}

func (d *dynamicLinkEngine) handleDecline(session *engine.Session, value message.Message) {
	d.mu.Lock()
	defer d.mu.Unlock()
	attempt := d.proposingAttemptLocked(session, value.OperationID)
	if attempt == nil {
		d.runner.log(Event{Event: "velvet-frame", Status: "discarded", Error: "DYNAMIC_LINK_DECLINE references an unknown operation"})
		return
	}
	// The peer's winning simultaneous Proposal can cross this DECLINE. Delay
	// deletion so it can reuse the ifindex and avoid a stale IPv6 zone cache.
	if plan := d.fallbackLocked(attempt, "Proposal declined"); plan != nil {
		d.deferCleanupLocked(attempt.remote, *plan, "Proposal declined")
	}
}

func (d *dynamicLinkEngine) proposingAttemptLocked(session *engine.Session, operationID [16]byte) *dynamicAttempt {
	attempt := d.attempts[session.RemoteUID.UUID]
	if attempt == nil || attempt.session != session || attempt.operationID != operationID || attempt.state != dynamicProposing {
		return nil
	}
	return attempt
}

func (d *dynamicLinkEngine) isCurrentAttemptLocked(attempt *dynamicAttempt) bool {
	return d.attempts[attempt.remote] == attempt
}

func dynamicLinkMessage(kind message.Type, attempt *dynamicAttempt) message.Message {
	return message.Message{
		Type: kind, OperationID: attempt.operationID,
		WGPublicKey: [32]byte(attempt.plan.PrivateKey.PublicKey()),
		Endpoint:    attempt.candidate,
	}
}
