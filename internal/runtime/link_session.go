package runtime

import (
	"context"
	"net"
	"net/netip"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/link"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
)

// negotiateLink ends after local installation and LINK_ACCEPT. Link liveness
// is owned by the caller's UDP supervisor, never by this TCP connection.
func (r *Runner) negotiateLink(ctx context.Context, conn net.Conn, desired reconcile.LinkPlan, install func(engine.Result) error) error {
	protocol := engine.New(engine.Config{
		Context:         engine.LinkBoundSession,
		LocalUID:        message.UID{UUID: r.Desired.UUID, Name: r.Desired.UID.Name},
		LocalLoopbackV6: r.Desired.LoopbackV6,
		LoopbackPoolV6:  r.Desired.LoopbackPoolV6,
		LinkPoolV4:      r.Desired.LinkPoolV4, LinkPoolV6: r.Desired.LinkPoolV6,
		FabricPSK: r.Desired.FabricPSK, LinkOverrides: desired.LinkOverrides,
		Accept: func(remote message.UID, proposal link.Proposal) bool {
			if !link.MatchesOverrides(proposal, desired.LinkOverrides) {
				return false
			}
			local, _ := link.EndpointAddresses(proposal, r.Desired.UUID, remote.UUID)
			return r.Reconciler.ProposalAvailable(ctx, desired, proposal, local)
		},
		Commit: install,
		FrameError: func(err error) {
			r.log(Event{Event: "velvet-frame", Status: "discarded", Peer: desired.PeerName, Error: err.Error()})
		},
	})
	return protocol.Run(ctx, conn)
}

func (r *Runner) recordEndpointEvidence(ctx context.Context, interfaceName string, endpoint netip.AddrPort) error {
	r.dynamic.resourceMu.Lock()
	defer r.dynamic.resourceMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	port, err := r.Reconciler.ListenPort(ctx, interfaceName)
	if err != nil {
		return err
	}
	return r.dynamic.setEvidence(interfaceName, port, endpoint)
}

func (r *Runner) commitLink(ctx context.Context, desired reconcile.LinkPlan, dynamic bool, result engine.Result, onCommit func(engine.Result)) error {
	localAddresses, _ := link.EndpointAddresses(result.Proposal, r.Desired.UUID, result.RemoteUID.UUID)
	var peerLoopbacks []netip.Addr
	if result.RemoteLoopbackV6.IsValid() {
		peerLoopbacks = []netip.Addr{result.RemoteLoopbackV6}
	}
	if err := r.Reconciler.Materialize(ctx, r.Desired, desired, localAddresses, peerLoopbacks); err != nil {
		return err
	}
	r.mu.Lock()
	r.states[desired.InterfaceName] = materializedState{
		desired: desired,
		local:   append([]netip.Prefix(nil), localAddresses...),
		peers:   append([]netip.Addr(nil), peerLoopbacks...),
		remote:  result.RemoteUID.UUID,
		dynamic: dynamic,
		active:  true,
	}
	r.mu.Unlock()
	if r.babel != nil {
		r.babel.SetLinkState(desired.InterfaceName, true, localAddresses)
	}
	event := "velvet-link-established"
	if dynamic {
		event = "velvet-dynamic-link-established"
	}
	r.log(Event{Event: event, Status: "success", NodeUID: r.Desired.UUID.String(), Peer: desired.PeerName, Interface: desired.InterfaceName, RemoteUID: result.RemoteUID.UUID.String()})
	if onCommit != nil {
		onCommit(result)
	}
	return nil
}

func (r *Runner) hasDirectLink(remote uuid.UUID) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, state := range r.states {
		if state.active && state.remote == remote {
			return true
		}
	}
	return false
}

func (r *Runner) hasDirectLinkToLoopback(loopback netip.Addr) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, state := range r.states {
		if !state.active {
			continue
		}
		for _, peer := range state.peers {
			if peer == loopback {
				return true
			}
		}
	}
	return false
}

func (r *Runner) removeDynamicState(plan reconcile.LinkPlan) {
	r.mu.Lock()
	if state, exists := r.states[plan.InterfaceName]; exists && state.dynamic && state.desired.OwnerAlias == plan.OwnerAlias {
		delete(r.states, plan.InterfaceName)
	}
	r.mu.Unlock()
	if r.babel != nil {
		r.babel.SetLinkState(plan.InterfaceName, false, nil)
	}
}

// withdrawLinkAdjacency withdraws an expired adjacency, retaining WG and local
// addresses for recovery. It is also used by dynamic Link supervision.
func (r *Runner) withdrawLinkAdjacency(ctx context.Context, plan reconcile.LinkPlan) error {
	r.dynamic.resourceMu.Lock()
	defer r.dynamic.resourceMu.Unlock()
	r.mu.RLock()
	state, exists := r.states[plan.InterfaceName]
	r.mu.RUnlock()
	if !exists || !state.active || state.desired.OwnerAlias != plan.OwnerAlias {
		return nil
	}
	if err := r.Reconciler.Materialize(ctx, r.Desired, plan, state.local, nil); err != nil {
		return err // Retain bookkeeping so runLink retries the withdrawal.
	}
	r.mu.Lock()
	state.active = false
	state.peers = nil
	r.states[plan.InterfaceName] = state
	r.mu.Unlock()
	r.dynamic.mu.Lock()
	r.dynamic.removeEvidenceLocked(plan.InterfaceName)
	r.dynamic.mu.Unlock()
	if r.babel != nil {
		r.babel.SetLinkState(plan.InterfaceName, false, nil)
	}
	r.log(Event{Event: "velvet-link-withdraw", Status: "success", Interface: plan.InterfaceName})
	return nil
}
