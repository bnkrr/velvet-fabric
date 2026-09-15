package runtime

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/link"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/discovery"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
)

const linkPingInterval = 10 * time.Second
const linkFailureTimeout = 30 * time.Second

func linkHelloDelay() time.Duration {
	return 750*time.Millisecond + time.Duration(mathrand.Int64N(int64(500*time.Millisecond)))
}

// One outstanding challenge bounds memory and rejects replay/late observations.
// Its random value is fresh across supervisor restarts, without a wire Link ID.
type linkHealth struct {
	pending  [16]byte
	expires  time.Time
	lastPong time.Time
}

func (h *linkHealth) challenge(now time.Time) ([16]byte, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return id, err
	}
	h.pending = id
	h.expires = now.Add(linkPingInterval)
	return id, nil
}
func (h *linkHealth) pong(id [16]byte, now time.Time) bool {
	if id == [16]byte{} || id != h.pending || !now.Before(h.expires) {
		return false
	}
	h.pending = [16]byte{}
	h.lastPong = now
	return true
}
func (h *linkHealth) expired(now time.Time) bool {
	return !h.lastPong.IsZero() && !now.Before(h.lastPong.Add(linkFailureTimeout))
}

type linkInstall struct {
	result engine.Result
	remote netip.Addr
	done   chan error
}

// manageLink owns the link-local listener for the lifetime of a WG interface.
// TCP negotiations are short workers; UDP handling continues while they run.
func (r *Runner) manageLink(parent context.Context, plan reconcile.LinkPlan, attempt *dynamicAttempt, onCommit func(engine.Result)) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	local := plan.BootstrapAddress.Addr()
	zone, err := linkZone(plan.InterfaceName)
	if err != nil {
		return err
	}
	socket, err := discovery.Listen(plan.InterfaceName, local, r.Desired.VFPPort)
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IP(local.AsSlice()), Port: r.Desired.VFPPort, Zone: zone})
	if err != nil {
		socket.Close()
		return err
	}
	var workers sync.WaitGroup
	defer func() { cancel(); listener.Close(); socket.Close(); workers.Wait() }()
	packets := make(chan discovery.Observation, 32)
	readErrors := make(chan error, 1)
	accepted := make(chan acceptedConnection)
	installs := make(chan linkInstall)
	finished := make(chan error, 1)
	workers.Go(func() {
		for {
			v, e := socket.Read()
			if e != nil {
				select {
				case readErrors <- e:
				case <-ctx.Done():
				}
				return
			}
			select {
			case packets <- v:
			case <-ctx.Done():
				return
			}
		}
	})
	workers.Go(func() {
		for {
			conn, e := listener.AcceptTCP()
			select {
			case accepted <- acceptedConnection{conn, e}:
			case <-ctx.Done():
				if conn != nil {
					conn.Close()
				}
				return
			}
			if e != nil {
				return
			}
		}
	})
	var result *engine.Result
	var remote netip.Addr
	var health linkHealth
	healthy, busy := false, false
	ready, changed := false, false
	nextPing, nextNegotiation := time.Time{}, time.Time{}
	start := func(conn net.Conn, target netip.Addr) {
		busy = true
		changed = false
		nextNegotiation = time.Now().Add(time.Second)
		workers.Go(func() {
			var e error
			if conn == nil {
				conn, e = dialVFP(ctx, plan.InterfaceName, local, target, r.Desired.VFPPort)
			}
			if e == nil {
				e = r.negotiateLink(ctx, conn, plan, func(value engine.Result) error {
					request := linkInstall{value, target, make(chan error, 1)}
					select {
					case installs <- request:
					case <-ctx.Done():
						return ctx.Err()
					}
					select {
					case e := <-request.done:
						return e
					case <-ctx.Done():
						return ctx.Err()
					}
				})
			}
			select {
			case finished <- e:
			case <-ctx.Done():
			}
		})
	}
	ping := func(now time.Time) error {
		if result == nil || !ready {
			return nil
		}
		id, e := health.challenge(now)
		if e != nil {
			return e
		}
		nextPing = now.Add(linkPingInterval)
		// Local send errors are not proof of peer failure; the liveness budget owns it.
		_ = socket.Send(remote, message.Message{Type: message.LinkPing, OperationID: id})
		return nil
	}
	withdraw := func() error {
		if e := r.withdrawLinkAdjacency(ctx, plan); e != nil {
			return e
		}
		healthy = false
		if attempt != nil {
			d := r.dynamic
			d.mu.Lock()
			if d.isCurrentAttemptLocked(attempt) && attempt.state == dynamicUp {
				attempt.state = dynamicRecovering
				d.armConnectivityDeadlineLocked(attempt, ctx)
				r.log(Event{Event: "velvet-dynamic-link", Status: "recovering", Interface: plan.InterfaceName, RemoteUID: attempt.remote.String(), Error: "Link PONG deadline"})
			}
			d.mu.Unlock()
		}
		return nil
	}
	confirm := func(now time.Time) error {
		if !healthy {
			if attempt != nil {
				err = r.dynamic.commitLink(ctx, attempt, *result)
			} else {
				r.dynamic.resourceMu.Lock()
				err = r.commitLink(ctx, plan, false, *result, onCommit)
				r.dynamic.resourceMu.Unlock()
			}
			if err != nil {
				return fmt.Errorf("confirm Link adjacency: %w", err)
			}
			healthy = true
		}
		health.lastPong = now
		return nil
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	helloDelay := linkHelloDelay()
	if attempt != nil && !attempt.localProposal {
		// The routed proposer starts WG traffic. Give its handshake and
		// Hello a head start before independently announcing from this end;
		// simultaneous WG initiations can repeatedly invalidate each other.
		helloDelay = 2 * time.Second
	} else {
		_ = socket.SendHello()
	}
	// Keep Hello schedules independent across endpoints and separate from the
	// health ticker so its resolution does not erase the sampled jitter.
	hello := time.NewTimer(helloDelay)
	defer hello.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-readErrors:
			return e
		case incoming := <-accepted:
			if incoming.err != nil {
				return incoming.err
			}
			target, ok := tcpRemoteAddress(incoming.conn)
			if !ok || !shouldAcceptDiscovered(local, target) || busy || time.Now().Before(nextNegotiation) {
				incoming.conn.Close()
				continue
			}
			configureTCP(incoming.conn)
			start(incoming.conn, target)
		case e := <-finished:
			busy = false
			if e == nil {
				ready = result != nil
				if ready {
					if err = confirm(time.Now()); err != nil {
						return err
					}
				}
				if err = ping(time.Now()); err != nil {
					return err
				}
			} else if changed {
				ready = false
				result = nil
				health = linkHealth{}
			}
			if e != nil && ctx.Err() == nil {
				r.log(Event{Event: "velvet-link-negotiation", Status: "failed", Interface: plan.InterfaceName, Error: e.Error()})
			}
			// EOF/errors do not invalidate existing liveness. Only a completed
			// negotiation or a matching PONG can confirm installed Link state.
		case request := <-installs:
			value := request.result
			if attempt != nil && value.RemoteUID.UUID != attempt.remote {
				request.done <- errors.New("negotiated UID differs from routed target")
				continue
			}
			same := result != nil && remote == request.remote && result.RemoteUID.UUID == value.RemoteUID.UUID && result.RemoteLoopbackV6 == value.RemoteLoopbackV6 && result.Proposal == value.Proposal
			if !same {
				ready = false
				changed = true
				if err = withdraw(); err != nil {
					request.done <- err
					return err
				}
				addresses, _ := link.EndpointAddresses(value.Proposal, r.Desired.UUID, value.RemoteUID.UUID)
				r.dynamic.resourceMu.Lock()
				err = r.Reconciler.Materialize(ctx, r.Desired, plan, addresses, nil)
				if err == nil {
					r.mu.Lock()
					r.states[plan.InterfaceName] = materializedState{desired: plan, local: addresses, remote: value.RemoteUID.UUID, dynamic: attempt != nil}
					r.mu.Unlock()
				}
				r.dynamic.resourceMu.Unlock()
				if err != nil {
					request.done <- err
					continue
				}
				result = &value
				remote = request.remote
				health = linkHealth{}
			}
			request.done <- nil
			if err = ping(time.Now()); err != nil {
				return err
			}
		case v := <-packets:
			now := time.Now()
			if v.Source == local {
				continue
			}
			if v.Type.IsDiscovery() {
				if v.Type == message.DiscoveryHello {
					_ = socket.SendAck(v.Source)
				}
				if !busy && !now.Before(nextNegotiation) && shouldDial(local, v.Source) && (!healthy || v.Type == message.DiscoveryHello) {
					r.log(Event{Event: "velvet-discovery", Status: "peer-found", Peer: plan.PeerName, Interface: plan.InterfaceName, RemoteIP: v.Source.String()})
					start(nil, v.Source)
				}
				continue
			}
			if result == nil || !ready || v.Source != remote {
				continue
			}
			switch v.Type {
			case message.LinkPing:
				endpoint, ok, e := r.Reconciler.ObservedEndpoint(ctx, plan.InterfaceName)
				reply := message.Message{Type: message.LinkPong, OperationID: v.Message.OperationID}
				if e == nil && ok {
					reply.Endpoint = endpoint
				}
				_ = socket.Send(remote, reply)
			case message.LinkPong:
				if !health.pong(v.Message.OperationID, now) {
					continue
				}
				if err = confirm(now); err != nil {
					return err
				}
				if v.Message.Endpoint.IsValid() {
					if e := r.recordEndpointEvidence(ctx, plan.InterfaceName, v.Message.Endpoint); e != nil {
						r.log(Event{Event: "velvet-endpoint-observation", Status: "failed", Interface: plan.InterfaceName, Error: e.Error()})
					}
				}
			}
		case <-hello.C:
			if !healthy && !busy {
				_ = socket.SendHello()
			}
			hello.Reset(linkHelloDelay())
		case now := <-ticker.C:
			if healthy && health.expired(now) {
				if err = withdraw(); err != nil {
					return err
				}
			}
			if result != nil && !now.Before(nextPing) {
				if err = ping(now); err != nil {
					return err
				}
			}
		}
	}
}
