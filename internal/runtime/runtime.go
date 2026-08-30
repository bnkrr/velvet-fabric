package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/babel"
	"github.com/velvet-fabric/velvet-fabric/internal/link"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/discovery"
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
	RemoteIP  string `json:"remote_ip,omitempty"`
	Error     string `json:"error,omitempty"`
}

type Runner struct {
	Desired    *reconcile.DesiredState
	Reconciler *reconcile.Reconciler
	Interval   time.Duration
	Log        func(Event)
	Ready      chan<- error
	mu         sync.RWMutex
	states     map[string]materializedState
	babel      *babel.Manager
}

type Status struct {
	NodeUID          string        `json:"node_uid"`
	ConfiguredLinks  int           `json:"configured_links"`
	EstablishedLinks int           `json:"established_links"`
	Babel            *babel.Status `json:"babel,omitempty"`
}

type materializedState struct {
	desired reconcile.LinkPlan
	local   []netip.Prefix
	peers   []netip.Addr
}

func (r *Runner) Run(ctx context.Context, once bool) error {
	if err := r.Reconciler.Reconcile(ctx, r.Desired); err != nil {
		r.signalReady(err)
		return err
	}
	r.log(Event{Event: "velvet-reconcile", Status: "success", NodeUID: r.Desired.UUID.String()})
	ctx, cancel := context.WithCancel(ctx)
	var babelDone chan struct{}
	defer func() {
		cancel()
		if babelDone != nil {
			select {
			case <-babelDone:
			case <-time.After(6 * time.Second):
			}
		}
	}()
	if r.Desired.Babel != nil {
		r.babel = babel.New(r.Desired.Babel, func(event babel.Event) {
			r.log(Event{Event: "babel-rs", Status: event.Status, NodeUID: r.Desired.UUID.String(), Error: event.Error})
		})
		babelDone = make(chan struct{})
		go func() {
			defer close(babelDone)
			r.babel.Run(ctx)
		}()
	}
	r.mu.Lock()
	r.states = make(map[string]materializedState)
	r.mu.Unlock()
	if err := r.waitBabelReady(ctx); err != nil {
		r.signalReady(err)
		return err
	}
	r.signalReady(nil)
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

func (r *Runner) waitBabelReady(ctx context.Context) error {
	if r.babel == nil {
		return nil
	}
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		status := r.babel.Status()
		if status.State == "running" && status.AttachedInterfaces == len(r.Desired.Links) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("babel-rs did not attach all configured interfaces: %s", status.LastError)
		case <-ticker.C:
		}
	}
}

func (r *Runner) signalReady(err error) {
	if r.Ready != nil {
		select {
		case r.Ready <- err:
		default:
		}
	}
}

func (r *Runner) Status() Status {
	r.mu.RLock()
	established := len(r.states)
	r.mu.RUnlock()
	status := Status{NodeUID: r.Desired.UUID.String(), ConfiguredLinks: len(r.Desired.Links), EstablishedLinks: established}
	if r.babel != nil {
		value := r.babel.Status()
		status.Babel = &value
	}
	return status
}

func (r *Runner) runLink(ctx context.Context, desired reconcile.LinkPlan, established chan<- struct{}) {
	var establishedOnce sync.Once
	for ctx.Err() == nil {
		conn, err := r.discoverPeer(ctx, desired)
		if err == nil {
			err = r.serveSession(ctx, conn, desired, &establishedOnce, established)
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

type acceptedConnection struct {
	conn *net.TCPConn
	err  error
}

func (r *Runner) discoverPeer(ctx context.Context, desired reconcile.LinkPlan) (net.Conn, error) {
	localAddress := desired.BootstrapAddress.Addr()
	address := &net.TCPAddr{IP: net.IP(desired.BootstrapAddress.Addr().AsSlice()), Port: r.Desired.VFPPort, Zone: desired.InterfaceName}
	listener, err := net.ListenTCP("tcp6", address)
	if err != nil {
		return nil, fmt.Errorf("listen for VFP: %w", err)
	}
	defer listener.Close()
	socket, err := discovery.Listen(desired.InterfaceName, localAddress, r.Desired.VFPPort)
	if err != nil {
		return nil, err
	}
	defer socket.Close()
	discoveryContext, cancel := context.WithCancel(ctx)
	defer cancel()

	accepted := make(chan acceptedConnection, 1)
	go func() {
		for {
			conn, acceptErr := listener.AcceptTCP()
			select {
			case accepted <- acceptedConnection{conn: conn, err: acceptErr}:
			case <-discoveryContext.Done():
				if conn != nil {
					_ = conn.Close()
				}
				return
			}
			if acceptErr != nil {
				return
			}
		}
	}()
	discovered := make(chan discovery.Observation, 1)
	readErrors := make(chan error, 1)
	go func() {
		for {
			observation, readErr := socket.ReadHello()
			if readErr != nil {
				select {
				case readErrors <- readErr:
				case <-discoveryContext.Done():
				}
				return
			}
			select {
			case discovered <- observation:
			case <-discoveryContext.Done():
				return
			}
		}
	}()
	announceErrors := make(chan error, 1)
	go func() { announceErrors <- socket.Announce(discoveryContext) }()

	var remoteAddress netip.Addr
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case readErr := <-readErrors:
			if ctx.Err() != nil || errors.Is(readErr, net.ErrClosed) {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("receive discovery Hello: %w", readErr)
		case announceErr := <-announceErrors:
			if ctx.Err() != nil || errors.Is(announceErr, context.Canceled) || errors.Is(announceErr, net.ErrClosed) {
				return nil, ctx.Err()
			}
			return nil, announceErr
		case observation := <-discovered:
			remote := observation.Source
			if remote == localAddress {
				return nil, fmt.Errorf("discovery address collision on %s: %s", desired.InterfaceName, remote)
			}
			if observation.Type == discovery.Hello {
				if err := socket.SendAck(remote); err != nil {
					return nil, err
				}
			}
			if remote != remoteAddress {
				r.log(Event{Event: "velvet-discovery", Status: "peer-found", Peer: desired.PeerName, Interface: desired.InterfaceName, RemoteIP: remote.String()})
			}
			remoteAddress = remote
			if shouldDial(localAddress, remoteAddress) {
				conn, dialErr := dialVFP(ctx, desired.InterfaceName, localAddress, remoteAddress, r.Desired.VFPPort)
				if dialErr != nil {
					return nil, dialErr
				}
				cancel()
				_ = listener.Close()
				return conn, nil
			}
		case result := <-accepted:
			if result.err != nil {
				if ctx.Err() != nil || errors.Is(result.err, net.ErrClosed) {
					return nil, ctx.Err()
				}
				return nil, fmt.Errorf("accept VFP: %w", result.err)
			}
			acceptedRemote, ok := tcpRemoteAddress(result.conn)
			if !ok || !remoteAddress.IsValid() || acceptedRemote != remoteAddress || shouldDial(localAddress, remoteAddress) {
				_ = result.conn.Close()
				continue
			}
			configureTCP(result.conn)
			cancel()
			return result.conn, nil
		}
	}
}

func dialVFP(ctx context.Context, interfaceName string, local, remote netip.Addr, port int) (*net.TCPConn, error) {
	localAddress := &net.TCPAddr{IP: net.IP(local.AsSlice()), Zone: interfaceName}
	remoteAddress := &net.TCPAddr{IP: net.IP(remote.AsSlice()), Port: port, Zone: interfaceName}
	conn, err := (&net.Dialer{LocalAddr: localAddress, Timeout: 3 * time.Second}).DialContext(ctx, "tcp6", remoteAddress.String())
	if err != nil {
		return nil, fmt.Errorf("dial discovered VFP peer %s: %w", remoteAddress, err)
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("VFP dial did not return a TCP connection")
	}
	configureTCP(tcp)
	return tcp, nil
}

func shouldDial(local, remote netip.Addr) bool { return local.Compare(remote) < 0 }

func tcpRemoteAddress(conn *net.TCPConn) (netip.Addr, bool) {
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	address, ok := netip.AddrFromSlice(remote.IP)
	return address.Unmap(), ok
}

func configureTCP(conn *net.TCPConn) {
	_ = conn.SetKeepAlive(true)
	_ = conn.SetKeepAlivePeriod(30 * time.Second)
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
			if r.babel != nil {
				r.babel.SetLinkPrefixes(desired.InterfaceName, localAddresses)
			}
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
