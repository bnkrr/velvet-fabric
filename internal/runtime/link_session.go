package runtime

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/link"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
)

func (r *Runner) serveSession(ctx context.Context, conn net.Conn, desired reconcile.LinkPlan, once *sync.Once, established chan<- struct{}) error {
	return r.serveLinkSession(ctx, conn, desired, false, 0, func(engine.Result) {
		once.Do(func() { established <- struct{}{} })
	})
}

func (r *Runner) serveLinkSession(ctx context.Context, conn net.Conn, desired reconcile.LinkPlan, dynamic bool, timeout time.Duration, onCommit func(engine.Result)) error {
	protocol := engine.New(engine.Config{
		Context:         engine.LinkBoundSession,
		LocalUID:        message.UID{UUID: r.Desired.UUID, Name: r.Desired.UID.Name},
		LocalLoopbackV6: r.Desired.LoopbackV6,
		LinkPoolV4:      r.Desired.LinkPoolV4,
		LinkPoolV6:      r.Desired.LinkPoolV6,
		LoopbackPoolV6:  r.Desired.LoopbackPoolV6,
		FabricPSK:       r.Desired.FabricPSK,
		LinkOverrides:   desired.LinkOverrides,
		Accept: func(remote message.UID, proposal link.Proposal) bool {
			if !link.MatchesOverrides(proposal, desired.LinkOverrides) {
				return false
			}
			localAddresses, _ := link.EndpointAddresses(proposal, r.Desired.UUID, remote.UUID)
			return r.Reconciler.ProposalAvailable(ctx, desired, proposal, localAddresses)
		},
		Commit: func(result engine.Result) error {
			return r.commitLink(ctx, desired, dynamic, result, onCommit)
		},
		Operational: func(session *engine.Session) error {
			return r.startEndpointObserver(session, desired.InterfaceName)
		},
		OperationalMessage: func(_ *engine.Session, value message.Message) error {
			if value.Type == message.EndpointObservation {
				r.dynamic.setEvidence(desired.InterfaceName, value.Endpoint)
			}
			return nil
		},
		FrameError: func(err error) {
			r.log(Event{Event: "velvet-frame", Status: "discarded", Peer: desired.PeerName, Error: err.Error()})
		},
		EstablishmentTimeout: timeout,
	})
	return protocol.Run(ctx, conn)
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
	}
	r.mu.Unlock()
	if r.babel != nil {
		r.babel.SetLinkPrefixes(desired.InterfaceName, localAddresses)
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

func (r *Runner) startEndpointObserver(session *engine.Session, interfaceName string) error {
	var last netip.AddrPort
	if endpoint, ok, err := r.Reconciler.ObservedEndpoint(session.Context, interfaceName); err != nil {
		return err
	} else if ok {
		if err := session.Send(message.Message{Type: message.EndpointObservation, Endpoint: endpoint}); err != nil {
			return err
		}
		last = endpoint
	}
	go r.observeEndpoints(session, interfaceName, last)
	return nil
}

func (r *Runner) observeEndpoints(session *engine.Session, interfaceName string, last netip.AddrPort) {
	ticker := time.NewTicker(endpointObservationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-session.Context.Done():
			return
		case <-ticker.C:
			endpoint, ok, err := r.Reconciler.ObservedEndpoint(session.Context, interfaceName)
			if err != nil {
				r.log(Event{Event: "velvet-endpoint-observation", Status: "failed", Interface: interfaceName, Error: err.Error()})
				_ = session.Close()
				return
			}
			if !ok || endpoint == last {
				continue
			}
			if err := session.Send(message.Message{Type: message.EndpointObservation, Endpoint: endpoint}); err != nil {
				_ = session.Close()
				return
			}
			last = endpoint
		}
	}
}

func (r *Runner) hasDirectLink(remote uuid.UUID) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, state := range r.states {
		if state.remote == remote {
			return true
		}
	}
	return false
}

func (r *Runner) hasDirectLinkToLoopback(loopback netip.Addr) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, state := range r.states {
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
		r.babel.SetLinkPrefixes(plan.InterfaceName, nil)
	}
}
