package runtime

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/link"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
)

type Event struct {
	Event     string `json:"event"`
	Status    string `json:"status,omitempty"`
	NodeUID   string `json:"node_uid,omitempty"`
	Peer      string `json:"peer,omitempty"`
	Interface string `json:"interface,omitempty"`
	RemoteUID string `json:"remote_uid,omitempty"`
	Error     string `json:"error,omitempty"`
}

type Runner struct {
	Desired    *reconcile.DesiredState
	Reconciler *reconcile.Reconciler
	Interval   time.Duration
	Log        func(Event)
	mu         sync.RWMutex
	states     map[string]materializedState
}

type materializedState struct {
	desired reconcile.LinkPlan
	local   []netip.Prefix
	peers   []netip.Addr
}

func (r *Runner) Run(ctx context.Context, once bool) error {
	if err := r.Reconciler.Reconcile(ctx, r.Desired); err != nil {
		return err
	}
	r.log(Event{Event: "velvet-reconcile", Status: "success", NodeUID: r.Desired.UUID.String()})
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	r.mu.Lock()
	r.states = make(map[string]materializedState)
	r.mu.Unlock()
	established := make(chan struct{}, len(r.Desired.Links))
	for i := range r.Desired.Links {
		desired := r.Desired.Links[i]
		go r.runLink(ctx, desired, established)
	}
	if once {
		for range r.Desired.Links {
			select {
			case <-established:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	if r.Interval > 0 {
		go r.maintain(ctx)
	}
	<-ctx.Done()
	return nil
}

func (r *Runner) runLink(ctx context.Context, desired reconcile.LinkPlan, established chan<- struct{}) {
	var establishedOnce sync.Once
	for ctx.Err() == nil {
		var err error
		if desired.Dialer {
			err = r.dialAndServe(ctx, desired, &establishedOnce, established)
		} else {
			err = r.listenAndServe(ctx, desired, &establishedOnce, established)
		}
		if ctx.Err() != nil {
			return
		}
		r.log(Event{Event: "velvet-session", Status: "retrying", Peer: desired.PeerName, Interface: desired.InterfaceName, Error: err.Error()})
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return
		}
	}
}

func (r *Runner) dialAndServe(ctx context.Context, desired reconcile.LinkPlan, once *sync.Once, established chan<- struct{}) error {
	remote := &net.TCPAddr{IP: net.IP(desired.BootstrapPeer.AsSlice()), Port: r.Desired.VFPPort, Zone: desired.InterfaceName}
	local := &net.TCPAddr{IP: net.IP(desired.BootstrapAddress.Addr().AsSlice()), Zone: desired.InterfaceName}
	conn, err := (&net.Dialer{LocalAddr: local, Timeout: 3 * time.Second}).DialContext(ctx, "tcp6", remote.String())
	if err != nil {
		return err
	}
	return r.serveSession(ctx, conn, desired, once, established)
}

func (r *Runner) listenAndServe(ctx context.Context, desired reconcile.LinkPlan, once *sync.Once, established chan<- struct{}) error {
	address := &net.TCPAddr{IP: net.IP(desired.BootstrapAddress.Addr().AsSlice()), Port: r.Desired.VFPPort, Zone: desired.InterfaceName}
	listener, err := net.ListenTCP("tcp6", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() { <-ctx.Done(); _ = listener.Close() }()
	conn, err := listener.AcceptTCP()
	if err != nil {
		return err
	}
	return r.serveSession(ctx, conn, desired, once, established)
}

func (r *Runner) serveSession(ctx context.Context, conn net.Conn, desired reconcile.LinkPlan, once *sync.Once, established chan<- struct{}) error {
	localUID := message.UID{UUID: r.Desired.UUID, Name: r.Desired.UID.Name}
	protocol := engine.New(engine.Config{
		LocalUID:        localUID,
		LocalLoopbackV6: r.Desired.LoopbackV6,
		LinkPoolV4:      r.Desired.LinkPoolV4, LinkPoolV6: r.Desired.LinkPoolV6,
		LoopbackPoolV6: r.Desired.LoopbackPoolV6,
		FabricPSK:      r.Desired.FabricPSK, LinkOverrides: desired.LinkOverrides,
		Accept: func(remote message.UID, proposal link.Proposal) bool {
			if !link.MatchesOverrides(proposal, desired.LinkOverrides) {
				return false
			}
			localAddresses, _ := link.EndpointAddresses(proposal, r.Desired.UUID, remote.UUID)
			return r.Reconciler.ProposalAvailable(ctx, desired, proposal, localAddresses)
		},
		Commit: func(result engine.Result) error {
			localAddresses, _ := link.EndpointAddresses(result.Proposal, r.Desired.UUID, result.RemoteUID.UUID)
			peerLoopbacks := validAddresses(result.RemoteLoopbackV6)
			if err := r.Reconciler.Materialize(ctx, r.Desired, desired, localAddresses, peerLoopbacks); err != nil {
				return err
			}
			r.mu.Lock()
			r.states[desired.InterfaceName] = materializedState{
				desired: desired,
				local:   append([]netip.Prefix(nil), localAddresses...),
				peers:   append([]netip.Addr(nil), peerLoopbacks...),
			}
			r.mu.Unlock()
			r.log(Event{Event: "velvet-link-established", Status: "success", NodeUID: r.Desired.UUID.String(), Peer: desired.PeerName, Interface: desired.InterfaceName, RemoteUID: result.RemoteUID.UUID.String()})
			once.Do(func() { established <- struct{}{} })
			return nil
		},
		FrameError: func(err error) {
			r.log(Event{Event: "velvet-frame", Status: "discarded", Peer: desired.PeerName, Error: err.Error()})
		},
	})
	return protocol.Run(ctx, conn)
}

func (r *Runner) maintain(ctx context.Context) {
	ticker := time.NewTicker(r.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.Reconciler.Reconcile(ctx, r.Desired); err != nil {
				r.log(Event{Event: "velvet-reconcile", Status: "failed", NodeUID: r.Desired.UUID.String(), Error: err.Error()})
				continue
			}
			r.mu.RLock()
			states := make([]materializedState, 0, len(r.states))
			for _, state := range r.states {
				states = append(states, state)
			}
			r.mu.RUnlock()
			for _, state := range states {
				if err := r.Reconciler.Materialize(ctx, r.Desired, state.desired, state.local, state.peers); err != nil {
					r.log(Event{Event: "velvet-reconcile", Status: "failed", Peer: state.desired.PeerName, Interface: state.desired.InterfaceName, Error: err.Error()})
				}
			}
		}
	}
}

func (r *Runner) log(event Event) {
	if r.Log != nil {
		r.Log(event)
	}
}
func validAddresses(values ...netip.Addr) []netip.Addr {
	var result []netip.Addr
	for _, value := range values {
		if value.IsValid() {
			result = append(result, value)
		}
	}
	return result
}
