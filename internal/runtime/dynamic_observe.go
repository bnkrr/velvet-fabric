package runtime

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/inference"
	"github.com/velvet-fabric/velvet-fabric/internal/linkdiscovery"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/probe"
)

type observerLease struct {
	id     [16]byte
	cancel context.CancelFunc
}
type observerTarget struct {
	loopback  netip.Addr
	bootstrap bool
}
type observerClient struct {
	id      [16]byte
	session *engine.Session
	cancel  context.CancelFunc
	done    chan struct{}
	inbox   chan message.Control
	key     [32]byte
	offer   inference.Observer
}

func (o *observerClient) close() {
	o.cancel()
	if o.session != nil {
		o.session.Close()
	}
	<-o.done
}

func (d *dynamicLinkEngine) handleDiscoveryControl(s *engine.Session, m message.Message) error {
	c, err := message.DecodeControl(m.Data)
	if err != nil {
		return err
	}
	if c.Code == message.ObserveOpen {
		return d.startObserver(s, m.OperationID, c.Endpoints[0])
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if lease := d.observerLeases[s]; lease != nil && lease.id == m.OperationID {
		if c.Code == message.DiscoveryEnd {
			lease.cancel()
		}
		return nil
	}
	a := d.attempts[s.RemoteUID.UUID]
	if a == nil || a.session != s || a.operationID != m.OperationID || a.udp == nil || a.state != dynamicProbing {
		return nil
	}
	select {
	case a.udp.inbox <- c:
	default:
		a.udp.cancel()
	}
	return nil
}
func (d *dynamicLinkEngine) startObserver(s *engine.Session, id [16]byte, target netip.AddrPort) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopped || d.ctx.Err() != nil {
		return context.Canceled
	}
	if d.observerLeases == nil {
		d.observerLeases = map[*engine.Session]*observerLease{}
	}
	if d.observerLeases[s] != nil || len(d.observerLeases) >= maxRoutedSessions {
		return sendDiscovery(s, id, message.Control{Code: message.DiscoveryEnd})
	}
	ctx, cancel := context.WithTimeout(s.Context, 30*time.Second)
	lease := &observerLease{id: id, cancel: cancel}
	d.observerLeases[s] = lease
	// Read only the observer's existing passive evidence. No recursive engine.
	var public netip.Addr
	for _, e := range d.evidence {
		if e.ObservedEndpoint.Addr().Is4() == target.Addr().Is4() {
			public = e.ObservedEndpoint.Addr()
			break
		}
	}
	d.workers.Go(func() {
		defer cancel()
		defer func() {
			d.mu.Lock()
			if d.observerLeases[s] == lease {
				delete(d.observerLeases, s)
			}
			d.mu.Unlock()
		}()
		var sockets []*probe.Socket
		defer func() {
			for _, socket := range sockets {
				socket.Close()
			}
		}()
		fail := func() { _ = sendDiscovery(s, id, message.Control{Code: message.DiscoveryEnd}) }
		local, err := probe.Source(target)
		if err != nil {
			fail()
			return
		}
		if !public.IsValid() {
			public = local
		}
		receiver, err := probe.NewReceiver(id, time.Now().Add(30*time.Second))
		if err != nil {
			fail()
			return
		}
		var endpoints []netip.AddrPort
		for range 2 {
			socket, err := probe.Listen(ctx, netip.AddrPortFrom(local, 0), receiver, func(v probe.Received) {
				if v.Round != 0 {
					return
				}
				if err := sendDiscovery(s, id, message.Control{Code: message.ProbeReport, Sequence: v.Sequence, Endpoints: []netip.AddrPort{v.Seen}}); err != nil {
					cancel()
				}
			})
			if err != nil {
				fail()
				return
			}
			sockets = append(sockets, socket)
			prediction := inference.Infer(nil, inference.SurveyInput{Local: socket.Local, Target: target, PublicIPs: []netip.Addr{public}, BaseOnly: true})
			endpoints = append(endpoints, linkdiscovery.CandidatesFor(prediction, 1)...)
		}
		if err = sendDiscovery(s, id, message.Control{Code: message.ObserveReady, Key: receiver.Key, Endpoints: endpoints}); err != nil {
			return
		}
		<-ctx.Done()
	})
	return nil
}

func (u *udpAttempt) observerTargets(ctx context.Context) []observerTarget {
	var out []observerTarget
	seen := map[netip.Addr]bool{u.d.runner.Desired.LoopbackV6: true, u.attempt.session.RemoteLoopbackV6: true}
	states := u.d.runner.materializedStates()
	sort.Slice(states, func(i, j int) bool { return states[i].desired.InterfaceName < states[j].desired.InterfaceName })
	for _, state := range states {
		if state.dynamic {
			continue
		}
		for _, ip := range state.peers {
			if !seen[ip] {
				out = append(out, observerTarget{ip, true})
				seen[ip] = true
			}
		}
	}
	targets, _ := u.d.runner.Reconciler.ReachableLoopbacks(ctx, u.d.runner.Desired)
	sort.Slice(targets, func(i, j int) bool { return targets[i].Less(targets[j]) })
	for _, ip := range targets {
		if !seen[ip] {
			out = append(out, observerTarget{ip, false})
			seen[ip] = true
		}
	}
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}
func (u *udpAttempt) openObserver(ctx context.Context, target observerTarget) (*observerClient, error) {
	ctx, cancel := context.WithCancel(ctx)
	id, err := newOperationID()
	if err != nil {
		cancel()
		return nil, err
	}
	o := &observerClient{id: id, cancel: cancel, done: make(chan struct{}), inbox: make(chan message.Control, 128)}
	conn, err := dialTCP(ctx, &net.TCPAddr{IP: net.IP(u.d.runner.Desired.LoopbackV6.AsSlice())}, &net.TCPAddr{IP: net.IP(target.loopback.AsSlice()), Port: u.d.runner.Desired.VFPPort})
	if err != nil {
		cancel()
		return nil, err
	}
	ready := make(chan *engine.Session, 1)
	protocol := engine.New(engine.Config{Context: engine.RoutedSession, LocalUID: message.UID{UUID: u.d.runner.Desired.UUID, Name: u.d.runner.Desired.UID.Name}, LocalLoopbackV6: u.d.runner.Desired.LoopbackV6, ExpectedRemoteLoopbackV6: target.loopback, LoopbackPoolV6: u.d.runner.Desired.LoopbackPoolV6,
		Operational: func(s *engine.Session) error { ready <- s; return nil },
		OperationalMessage: func(s *engine.Session, m message.Message) error {
			if m.Type != message.DiscoveryControl || m.OperationID != id {
				return nil
			}
			c, err := message.DecodeControl(m.Data)
			if err != nil {
				return err
			}
			select {
			case o.inbox <- c:
				return nil
			default:
				return errors.New("observer report queue full")
			}
		}})
	go func() { defer close(o.done); defer cancel(); _ = protocol.Run(ctx, conn) }()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case o.session = <-ready:
	case <-timer.C:
		o.close()
		return nil, errors.New("observer open timeout")
	case <-ctx.Done():
		o.close()
		return nil, ctx.Err()
	}
	if err = sendDiscovery(o.session, id, message.Control{Code: message.ObserveOpen, Endpoints: []netip.AddrPort{u.attempt.candidate}}); err != nil {
		o.close()
		return nil, err
	}
	select {
	case c := <-o.inbox:
		if c.Code != message.ObserveReady {
			o.close()
			return nil, errors.New("observer unavailable")
		}
		for _, ep := range c.Endpoints {
			if !u.d.candidateAllowed(ep) || ep.Addr().Is4() != u.primary.Endpoint().Addr().Is4() {
				o.close()
				return nil, errors.New("observer candidate rejected")
			}
		}
		o.key = c.Key
		o.offer = inference.Observer{Bootstrap: target.bootstrap, Endpoints: c.Endpoints}
		u.d.runner.log(Event{Event: "velvet-udp-observe", Status: "prepared", RemoteUID: o.session.RemoteUID.UUID.String()})
		return o, nil
	case <-timer.C:
		o.close()
		return nil, errors.New("observer readiness timeout")
	case <-ctx.Done():
		o.close()
		return nil, ctx.Err()
	}
}
func (u *udpAttempt) Observe(ctx context.Context, input inference.SurveyInput, samples []inference.Observation) ([]inference.Observation, error) {
	if !u.observersLoaded {
		u.observersLoaded = true
		u.remainingObservers = u.observerTargets(ctx)
	}
	// First consume already prepared branches, then lazily prepare further nodes.
	for index := 0; ; index++ {
		if index >= len(u.observers) {
			if len(u.remainingObservers) == 0 {
				return nil, nil
			}
			target := u.remainingObservers[0]
			u.remainingObservers = u.remainingObservers[1:]
			o, err := u.openObserver(ctx, target)
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				index--
				continue
			}
			u.observers = append(u.observers, o)
		}
		observer := u.observers[index]
		input.Observers = []inference.Observer{observer.offer}
		prediction := inference.Infer(samples, input)
		var observations []inference.Observation
		for _, group := range prediction.Plan {
			for _, step := range group.Steps {
				if u.measured[step] {
					continue
				}
				u.measured[step] = true
				u.measurements++
				if u.measurements > 64 {
					return nil, errors.New("measurement budget exhausted")
				}
				socket, err := u.localSocket(step.Local)
				if err != nil {
					continue
				} // unavailable adjacent port is an unavailable dimension
				found, err := u.measure(ctx, observer, socket, step)
				if err != nil {
					if ctx.Err() != nil {
						return nil, ctx.Err()
					}
					continue
				}
				observations = append(observations, found...)
			}
		}
		if len(observations) > 0 {
			u.d.runner.log(Event{Event: "velvet-udp-observe", Status: "measured", RemoteUID: observer.session.RemoteUID.UUID.String()})
			return observations, nil
		}
	}
}
func (u *udpAttempt) measure(ctx context.Context, o *observerClient, socket probeSocket, step inference.Measurement) ([]inference.Observation, error) {
	sent := map[uint64]inference.Measurement{}
	seen := map[uint64]netip.AddrPort{}
	for range 3 {
		u.sequence++
		if u.sequence > probe.MaxPackets {
			return nil, errors.New("packet budget exhausted")
		}
		packet, err := probe.Seal(o.id, o.key, u.sequence, 0, step.Remote)
		if err != nil {
			return nil, err
		}
		sent[u.sequence] = step
		if err = socket.Send(packet, step.Remote); err != nil {
			return nil, err
		}
		timer := time.NewTimer(100 * time.Millisecond)
	wait:
		for {
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-o.done:
				timer.Stop()
				return nil, errors.New("observer closed")
			case <-timer.C:
				break wait
			case c := <-o.inbox:
				if c.Code == message.DiscoveryEnd {
					timer.Stop()
					return nil, errors.New("observer ended")
				}
				if c.Code == message.ProbeReport && c.Round == 0 {
					if _, ok := sent[c.Sequence]; ok {
						seen[c.Sequence] = c.Endpoints[0]
					}
				}
			}
		}
	}
	// Three sends are a retransmission schedule, not the reporting deadline.
	timer := time.NewTimer(probeReportTimeout)
	defer timer.Stop()
	for len(seen) == 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-o.done:
			return nil, errors.New("observer closed")
		case <-timer.C:
			return nil, nil
		case c := <-o.inbox:
			if c.Code == message.DiscoveryEnd {
				return nil, errors.New("observer ended")
			}
			if c.Code == message.ProbeReport && c.Round == 0 {
				if _, ok := sent[c.Sequence]; ok {
					seen[c.Sequence] = c.Endpoints[0]
				}
			}
		}
	}
	return normalizeReports(sent, seen), nil
}
