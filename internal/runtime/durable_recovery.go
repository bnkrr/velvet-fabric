package runtime

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
)

const (
	durableCheckInterval  = 10 * time.Second
	durableReadyFreshness = 30 * time.Second
	durableFailureTimeout = 30 * time.Minute
)

type durableCheckState struct {
	query                                       [16]byte
	agreement                                   [16]byte
	next, readyUntil, failedSince, restoreAfter time.Time
	busy                                        bool
}

// Continuity belongs to READY freshness, not to a particular TCP connection.
func (c *durableCheckState) failed(now time.Time, localReady, connected bool) bool {
	if connected || !localReady || !now.Before(c.readyUntil) {
		c.failedSince = time.Time{}
		return false
	}
	if c.failedSince.IsZero() {
		c.failedSince = now
	}
	return now.Sub(c.failedSince) >= durableFailureTimeout
}

func (d *durableManager) restoreAndCheck(ctx context.Context, now time.Time) {
	d.mu.Lock()
	records := make([]durableRecord, 0, len(d.records))
	for _, record := range d.records {
		records = append(records, record)
	}
	d.mu.Unlock()
	for _, record := range records {
		peer := record.Peer.UUID
		connected := d.r.hasDirectLink(peer)
		d.mu.Lock()
		c := d.checks[peer]
		if c == nil {
			c = &durableCheckState{agreement: record.ID}
			d.checks[peer] = c
		}
		inspect := !now.Before(c.restoreAfter)
		if inspect {
			c.restoreAfter = now.Add(10 * time.Second)
		}
		d.mu.Unlock()
		if inspect {
			d.retireUnavailable(ctx, peer)
			connected = d.r.hasDirectLink(peer)
			if !connected {
				if err := d.restore(ctx, record); err != nil && ctx.Err() == nil {
					d.r.log(Event{Event: "velvet-durable", Status: "restore-retry", RemoteUID: peer.String(), Error: err.Error()})
				}
			}
		}
		localReady := d.localReady(record)
		d.mu.Lock()
		if current, exists := d.records[peer]; !exists || current.ID != record.ID {
			d.mu.Unlock()
			continue
		}
		if c.failed(now, localReady, connected) {
			if err := d.deleteLocked(peer, "continuous direct failure while both peers ready"); err != nil {
				d.r.dynamic.reportError(err)
			}
			d.mu.Unlock()
			d.removeFailed(record)
			continue
		}
		if connected || c.busy || now.Before(c.next) {
			d.mu.Unlock()
			continue
		}
		query, err := newOperationID()
		if err != nil {
			d.mu.Unlock()
			continue
		}
		c.query, c.busy, c.next = query, true, now.Add(durableCheckInterval)
		d.mu.Unlock()
		d.workers.Go(func() { d.check(ctx, record, c, query) })
	}
}

// A retained agreement must not retain a dead kernel incarnation forever.
// Keep healthy receive resources even without a handshake; rebuild missing or
// damaged resources through the ordinary ownership-fenced cleanup path.
func (d *durableManager) retireUnavailable(ctx context.Context, peer uuid.UUID) {
	e := d.r.dynamic
	e.mu.Lock()
	a := e.attempts[peer]
	var plan reconcile.LinkPlan
	if a != nil && (a.state == dynamicAttempting || a.state == dynamicRecovering || a.state == dynamicUp) {
		plan = a.plan
	}
	e.mu.Unlock()
	if plan.InterfaceName != "" && !d.r.Reconciler.LinkReady(ctx, plan) && ctx.Err() == nil {
		e.failAttempt(a, "durable receive resources unavailable", dynamicAttempting, dynamicRecovering, dynamicUp)
	}
}

func (d *durableManager) restore(ctx context.Context, record durableRecord) error {
	engine := d.r.dynamic
	engine.resourceMu.Lock()
	defer engine.resourceMu.Unlock()
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.stopped || ctx.Err() != nil || !engine.allowsInbound() || !d.has(record.Peer.UUID) {
		return nil
	}
	if engine.attempts[record.Peer.UUID] != nil || d.r.hasDirectLink(record.Peer.UUID) {
		return nil
	}
	if engine.resourceCountLocked() >= maxDynamicLinks {
		return errors.New("automatic Link resource limit reached")
	}
	plan := reconcile.BuildDynamicLink(d.r.Desired, nodeUID(record.Peer))
	generation, err := newOperationID()
	if err != nil {
		return err
	}
	plan.OwnerAlias += ":" + uuid.UUID(generation).String()
	choice := d.r.Desired.Ports
	if fixedFor(record, d.r.Desired.UUID).IsValid() {
		choice = spec.PortChoice{Port: record.LocalPort}
	}
	var socket *net.UDPConn
	lease, err := d.r.ports.bind(choice, record.LocalPort, func(port int) (int, error) {
		if socket != nil {
			socket.Close()
			socket = nil
		}
		var err error
		socket, err = net.ListenUDP("udp", &net.UDPAddr{Port: port})
		if err != nil {
			return 0, err
		}
		return socket.LocalAddr().(*net.UDPAddr).Port, nil
	})
	if socket != nil {
		socket.Close()
	}
	if err != nil {
		return err
	}
	plan.ListenPort = lease.port
	d.r.links.own(plan, lease)
	prepared, err := d.r.Reconciler.PrepareLink(ctx, plan)
	if err != nil {
		d.r.links.removed(plan, d.r.Reconciler.RemoveDynamic(ctx, plan))
		return err
	}
	plan = prepared
	endpoint := fixedFor(record, record.Peer.UUID)
	if !engine.active() {
		endpoint = netip.AddrPort{}
	}
	plan, err = d.r.Reconciler.ConfigureDynamic(ctx, d.r.Desired, plan, record.PublicKey, endpoint)
	if err == nil {
		err = d.confirmRestore(record, plan.ListenPort)
	}
	if err != nil {
		d.r.links.removed(plan, d.r.Reconciler.RemoveDynamic(ctx, plan))
		return err
	}
	a := &dynamicAttempt{remote: record.Peer.UUID, operationID: record.ID, plan: plan, port: lease, state: dynamicAttempting, localProposal: endpoint.IsValid()}
	d.r.links.own(plan, lease)
	engine.attempts[a.remote] = a
	engine.startConnectivityLocked(a)
	d.r.log(Event{Event: "velvet-durable", Status: "restored", RemoteUID: a.remote.String(), Interface: plan.InterfaceName})
	return nil
}

func (d *durableManager) localReady(record durableRecord) bool {
	e := d.r.dynamic
	e.mu.Lock()
	a := e.attempts[record.Peer.UUID]
	var plan reconcile.LinkPlan
	if a != nil && a.controlReady && a.state != dynamicStopped {
		plan = a.plan
	}
	e.mu.Unlock()
	if plan.InterfaceName == "" {
		return false
	}
	return (!fixedFor(record, d.r.Desired.UUID).IsValid() || plan.ListenPort == record.LocalPort) && d.r.Reconciler.LinkReady(e.ctx, plan)
}

func (d *durableManager) check(ctx context.Context, record durableRecord, c *durableCheckState, query [16]byte) {
	defer func() { d.mu.Lock(); c.busy = false; d.mu.Unlock() }()
	if !record.LastLoopback.IsValid() || !d.r.Desired.LoopbackPoolV6.Contains(record.LastLoopback) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := dialTCP(ctx, &net.TCPAddr{IP: net.IP(d.r.Desired.LoopbackV6.AsSlice())}, &net.TCPAddr{IP: net.IP(record.LastLoopback.AsSlice()), Port: d.r.Desired.VFPPort})
	if err != nil {
		return
	}
	config := engine.Config{Context: engine.RoutedSession, LocalUID: message.UID{UUID: d.r.Desired.UUID, Name: d.r.Desired.UID.Name}, LocalLoopbackV6: d.r.Desired.LoopbackV6, ExpectedRemoteLoopbackV6: record.LastLoopback, LoopbackPoolV6: d.r.Desired.LoopbackPoolV6,
		Operational: func(s *engine.Session) error {
			if s.RemoteUID.UUID != record.Peer.UUID {
				return errors.New("durable check peer identity mismatch")
			}
			return s.Send(message.Message{Type: message.DurableCheck, OperationID: query, AgreementID: record.ID})
		},
		OperationalMessage: func(s *engine.Session, m message.Message) error {
			return d.acceptStatus(ctx, record, c, query, m, time.Now())
		}}
	_ = engine.New(config).Run(ctx, conn)
}

// acceptStatus fences replies by agreement, check generation and query, rather
// than by TCP lifetime. Reconnecting the control path preserves fresh READY.
func (d *durableManager) acceptStatus(ctx context.Context, record durableRecord, c *durableCheckState, query [16]byte, m message.Message, now time.Time) error {
	if m.Type != message.DurableStatus || m.OperationID != query || m.AgreementID != record.ID {
		return nil
	}
	d.mu.Lock()
	current, ok := d.records[record.Peer.UUID]
	if !ok || current.ID != record.ID || d.checks[record.Peer.UUID] != c || c.query != query || ctx.Err() != nil {
		d.mu.Unlock()
		return errDurableComplete
	}
	switch m.Status {
	case message.Ready:
		c.readyUntil = now.Add(durableReadyFreshness)
	case message.NotReady:
		c.readyUntil, c.failedSince = time.Time{}, time.Time{}
	case message.Absent:
		// Keep an in-flight confirmation on a recovered healthy Link.
		// Otherwise explicit peer absence ends even a partial recovery record.
		if current.Confirmed || !d.r.hasDirectLink(record.Peer.UUID) {
			if err := d.deleteLocked(record.Peer.UUID, "peer no longer has agreement"); err != nil {
				d.mu.Unlock()
				return err
			}
		}
	}
	d.mu.Unlock()
	if m.Status == message.Absent && !d.has(record.Peer.UUID) {
		d.removeFailed(record)
	}
	return errDurableComplete
}

func (d *durableManager) handleCheck(s *engine.Session, m message.Message) error {
	status := message.Absent
	d.mu.Lock()
	record, ok := d.records[s.RemoteUID.UUID]
	matched := ok && record.ID == m.AgreementID
	if matched {
		if record.Peer != s.RemoteUID || record.LastLoopback != s.RemoteLoopbackV6 {
			record.Peer = s.RemoteUID
			record.LastLoopback = s.RemoteLoopbackV6
			if err := d.saveLocked(record); err != nil {
				d.mu.Unlock()
				return err
			}
		}
	}
	d.mu.Unlock()
	if matched {
		status = message.NotReady
		if d.localReady(record) {
			status = message.Ready
		}
	}
	return s.Send(message.Message{Type: message.DurableStatus, OperationID: m.OperationID, AgreementID: m.AgreementID, Status: status})
}

func (d *durableManager) removeFailed(record durableRecord) {
	e := d.r.dynamic
	e.mu.Lock()
	a := e.attempts[record.Peer.UUID]
	e.mu.Unlock()
	if a != nil {
		e.failAttempt(a, "durable agreement invalidated", dynamicAttempting, dynamicRecovering)
	}
}

func (d *durableManager) confirmRestore(record durableRecord, port int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	current, ok := d.records[record.Peer.UUID]
	if !ok || current.ID != record.ID || d.closed {
		return errors.New("durable restore superseded")
	}
	if current.LocalPort == port {
		return nil
	}
	if fixedFor(current, d.r.Desired.UUID).IsValid() {
		return errors.New("fixed durable port changed")
	}
	current.LocalPort = port
	return d.saveLocked(current)
}
