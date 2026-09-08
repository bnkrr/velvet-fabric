package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/inference"
	"github.com/velvet-fabric/velvet-fabric/internal/linkdiscovery"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/probe"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type probeSocket interface {
	Endpoint() netip.AddrPort
	Send([]byte, netip.AddrPort) error
	Close() error
}
type probeListener func(context.Context, netip.AddrPort, *probe.Receiver, func(probe.Received)) (probeSocket, error)

type udpAttempt struct {
	d                  *dynamicLinkEngine
	attempt            *dynamicAttempt
	ctx                context.Context
	cancel             context.CancelFunc
	receiver           *probe.Receiver
	primary            probeSocket
	remoteKey          [32]byte
	remoteEndpoint     netip.AddrPort
	remotePublicKey    wgtypes.Key
	inbox              chan message.Control
	arrivals           chan probe.Received
	mu                 sync.Mutex
	sockets            map[netip.AddrPort]probeSocket
	sequence           uint64
	measurements       int
	observers          []*observerClient
	observersLoaded    bool
	remainingObservers []observerTarget
	pending            *message.Control
	measured           map[inference.Measurement]bool
}

func (d *dynamicLinkEngine) prepareUDP(attempt *dynamicAttempt, hint netip.AddrPort) (*udpAttempt, error) {
	ctx, cancel := context.WithTimeout(d.ctx, 30*time.Second)
	u := &udpAttempt{d: d, attempt: attempt, ctx: ctx, cancel: cancel, inbox: make(chan message.Control, 256), arrivals: make(chan probe.Received, 1024), sockets: map[netip.AddrPort]probeSocket{}, measured: map[inference.Measurement]bool{}}
	var err error
	u.receiver, err = probe.NewReceiver(attempt.operationID, time.Now().Add(30*time.Second))
	if err != nil {
		cancel()
		return nil, err
	}
	source, err := d.probeSource(hint)
	if err != nil {
		cancel()
		return nil, err
	}
	port := uint16(attempt.plan.ListenPort)
	u.primary, err = d.listenProbe(ctx, netip.AddrPortFrom(source, port), u.receiver, func(v probe.Received) {
		select {
		case u.arrivals <- v:
		default:
			cancel()
			return
		}
		if err := u.send(message.Control{Code: message.ProbeReport, Round: v.Round, Sequence: v.Sequence, Endpoints: []netip.AddrPort{v.Seen}}); err != nil {
			cancel()
		}
	})
	if err != nil {
		cancel()
		return nil, err
	}
	u.sockets[u.primary.Endpoint()] = u.primary
	return u, nil
}
func (u *udpAttempt) close() {
	u.cancel()
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, s := range u.sockets {
		s.Close()
	}
}
func (u *udpAttempt) send(c message.Control) error {
	return sendDiscovery(u.attempt.session, u.attempt.operationID, c)
}
func sendDiscovery(s *engine.Session, id [16]byte, c message.Control) error {
	b, err := c.Encode()
	if err != nil {
		return err
	}
	return s.Send(message.Message{Type: message.DiscoveryControl, OperationID: id, Data: b})
}

func (d *dynamicLinkEngine) startProbeLocked(a *dynamicAttempt) {
	a.state = dynamicProbing
	a.cancel = a.udp.cancel
	d.workers.Go(func() { d.runProbe(a) })
}
func (d *dynamicLinkEngine) runProbe(a *dynamicAttempt) {
	u := a.udp
	defer u.close()
	defer func() {
		for _, o := range u.observers {
			o.close()
		}
	}()
	limits := linkdiscovery.DefaultLimits()
	limits.Timeout = 30 * time.Second
	result, err := linkdiscovery.RunPeer(u.ctx, u, linkdiscovery.Peer{Local: u.primary.Endpoint(), Target: u.remoteEndpoint, PublicIPs: []netip.Addr{a.candidate.Addr()}, Store: &inference.Store{}}, limits)
	if err == nil && !result.Endpoint.IsValid() {
		err = errors.New(result.Reason)
	}
	if err == nil {
		err = d.handoff(a, result)
	}
	if err != nil {
		_ = u.send(message.Control{Code: message.DiscoveryEnd})
		d.failAttempt(a, "UDP discovery: "+err.Error(), dynamicProbing)
	}
}

func (d *dynamicLinkEngine) handoff(a *dynamicAttempt, result linkdiscovery.PeerResult) error {
	u := a.udp
	source, err := d.probeSource(result.Endpoint)
	if err != nil {
		return err
	}
	if source != result.Local.Addr() {
		return errors.New("handoff route source changed")
	}
	// Cancellation/removal and WG binding serialize on the resource lock.
	d.resourceMu.Lock()
	d.mu.Lock()
	if !d.isCurrentAttemptLocked(a) || a.state != dynamicProbing || u.ctx.Err() != nil {
		d.mu.Unlock()
		d.resourceMu.Unlock()
		return context.Canceled
	}
	u.primary.Close()
	plan := a.plan
	plan.Probing = false
	plan.ReceiveOnly = true
	plan, err = d.runner.Reconciler.ConfigureDynamic(u.ctx, d.runner.Desired, plan, u.remotePublicKey, result.Endpoint)
	if err == nil {
		a.plan = plan
	}
	d.mu.Unlock()
	d.resourceMu.Unlock()
	if err != nil {
		return fmt.Errorf("WG receive readiness: %w", err)
	}
	d.runner.log(Event{Event: "velvet-udp-probe", Status: "handoff", LocalEndpoint: result.Local.String(), RemoteUID: a.remote.String(), Interface: plan.InterfaceName, RemoteIP: result.Endpoint.String()})
	if err = u.send(message.Control{Code: message.WGReady}); err != nil {
		return err
	}
	if _, err = u.wait(message.WGReady, 0); err != nil {
		return err
	}
	d.resourceMu.Lock()
	defer d.resourceMu.Unlock()
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.isCurrentAttemptLocked(a) || a.state != dynamicProbing || u.ctx.Err() != nil {
		return context.Canceled
	}
	plan.ReceiveOnly = false
	plan, err = d.runner.Reconciler.ConfigureDynamic(u.ctx, d.runner.Desired, plan, u.remotePublicKey, result.Endpoint)
	if err != nil {
		return err
	}
	a.plan = plan
	a.state = dynamicAttempting
	d.startConnectivityLocked(a)
	return nil
}
func (u *udpAttempt) wait(code message.ControlCode, round uint16) (message.Control, error) {
	if u.pending != nil {
		c := *u.pending
		u.pending = nil
		if c.Code == code && c.Round == round {
			return c, nil
		}
		return c, errors.New("unexpected pending phase")
	}
	for {
		select {
		case <-u.ctx.Done():
			return message.Control{}, u.ctx.Err()
		case c := <-u.inbox:
			if c.Code == message.DiscoveryEnd {
				return c, errors.New("peer ended discovery")
			}
			if c.Code == code && c.Round == round {
				return c, nil
			}
			// Reports arriving after their window cannot be used in another round.
			if c.Code != message.ProbeReport {
				return c, errors.New("unexpected discovery phase")
			}
		}
	}
}
func (u *udpAttempt) Exchange(ctx context.Context, round uint16, b linkdiscovery.Batch) (linkdiscovery.Batch, error) {
	if err := u.send(message.Control{Code: message.Candidates, Round: round, Changed: b.Changed, Endpoints: b.Endpoints}); err != nil {
		return linkdiscovery.Batch{}, err
	}
	c, err := u.wait(message.Candidates, round)
	for _, ep := range c.Endpoints {
		if !u.d.candidateAllowed(ep) || ep.Addr().Is4() != u.primary.Endpoint().Addr().Is4() {
			return linkdiscovery.Batch{}, errors.New("candidate policy or family rejected")
		}
	}
	return linkdiscovery.Batch{Endpoints: c.Endpoints, Changed: c.Changed}, err
}
func (u *udpAttempt) Agree(ctx context.Context, round uint16, path []netip.AddrPort) ([]netip.AddrPort, error) {
	if err := u.send(message.Control{Code: message.RoundDone, Round: round, Endpoints: path}); err != nil {
		return nil, err
	}
	c, err := u.wait(message.RoundDone, round)
	return c.Endpoints, err
}
func (u *udpAttempt) Try(ctx context.Context, round uint16, endpoints []netip.AddrPort) ([]inference.Observation, []linkdiscovery.Arrival, error) {
	sent := map[uint64]inference.Measurement{}
	received := map[uint64]netip.AddrPort{}
	var incoming []linkdiscovery.Arrival
	// The sending window and the Fabric reporting deadline are separate. A
	// delayed control report is not evidence that the underlay probe was lost.
	for repeat := 0; repeat < 5; repeat++ {
		for _, ep := range endpoints {
			u.sequence++
			if u.sequence > probe.MaxPackets {
				return nil, nil, errors.New("packet budget exhausted")
			}
			packet, err := probe.Seal(u.attempt.operationID, u.remoteKey, u.sequence, round, ep)
			if err != nil {
				return nil, nil, err
			}
			sent[u.sequence] = inference.Measurement{Local: u.primary.Endpoint(), Remote: ep}
			if err = u.primary.Send(packet, ep); err != nil {
				return nil, nil, err
			}
		}
		if err := u.collectRound(ctx, round, sent, received, &incoming, 100*time.Millisecond, false); err != nil {
			return nil, nil, err
		}
	}
	if len(sent) > 0 {
		if err := u.collectRound(ctx, round, sent, received, &incoming, probeReportTimeout, true); err != nil {
			return nil, nil, err
		}
	}
	return normalizeReports(sent, received), incoming, nil
}

// probeReportTimeout bounds late delivery over the routed control path; it
// never extends the parent operation deadline.
const probeReportTimeout = 2 * time.Second

func (u *udpAttempt) collectRound(ctx context.Context, round uint16, sent map[uint64]inference.Measurement, received map[uint64]netip.AddrPort, incoming *[]linkdiscovery.Arrival, duration time.Duration, stopOnPath bool) error {
	ready := func() bool {
		for id, seen := range received {
			p := sent[id]
			for _, a := range *incoming {
				if a.Destination == seen && a.Source == p.Remote {
					return true
				}
			}
		}
		return false
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	for {
		if stopOnPath && ready() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		case v := <-u.arrivals:
			if v.Round == round {
				*incoming = append(*incoming, linkdiscovery.Arrival{Destination: v.Destination, Source: v.Seen})
			}
		case c := <-u.inbox:
			if c.Code == message.DiscoveryEnd {
				return errors.New("peer ended discovery")
			}
			if c.Code == message.RoundDone && c.Round == round {
				if u.pending != nil {
					return errors.New("duplicate round barrier")
				}
				u.pending = &c
				continue
			}
			if c.Code != message.ProbeReport {
				return errors.New("unexpected control during probes")
			}
			if _, ok := sent[c.Sequence]; ok && c.Round == round {
				received[c.Sequence] = c.Endpoints[0]
			}
		}
	}
}

func normalizeReports(sent map[uint64]inference.Measurement, received map[uint64]netip.AddrPort) []inference.Observation {
	ids := make([]uint64, 0, len(received))
	for id := range received {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	var out []inference.Observation
	for _, id := range ids {
		p, ok := sent[id]
		if !ok {
			continue
		}
		o := inference.Observation{Local: p.Local, Remote: p.Remote, Seen: received[id]}
		if o.Valid() {
			out = append(out, o)
		}
	}
	return out
}
func (u *udpAttempt) localSocket(ep netip.AddrPort) (probeSocket, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if s := u.sockets[ep]; s != nil {
		return s, nil
	}
	s, err := u.d.listenProbe(u.ctx, ep, u.receiver, func(probe.Received) {})
	if err != nil {
		return nil, err
	}
	u.sockets[ep] = s
	return s, nil
}
