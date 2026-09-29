package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
)

var errDurableComplete = errors.New("durable operation complete")

func newAgreementID() ([16]byte, error) {
	id, err := uuid.NewRandom()
	return [16]byte(id), err
}

type durableObservation struct {
	local, remote netip.AddrPort
	control       netip.Addr
	port          int
	since, seen   time.Time
}
type durableOperation struct {
	record                     durableRecord
	session                    *engine.Session
	outgoing, saved, peerSaved bool
	until                      time.Time
}
type durableObservationEvent struct {
	plan    reconcile.LinkPlan
	local   netip.AddrPort
	control netip.Addr
	at      time.Time
}

type durableManager struct {
	updates      chan durableObservationEvent
	cooldown     map[uuid.UUID]time.Time
	closed       bool
	r            *Runner
	mu           sync.Mutex
	path         string
	owner        durableOwner
	records      map[uuid.UUID]durableRecord
	observations map[string]durableObservation
	operations   map[uuid.UUID]*durableOperation
	checks       map[uuid.UUID]*durableCheckState
	workers      sync.WaitGroup
}

func (r *Runner) openDurable() error {
	dir := r.PolicyStateDir
	if dir == "" {
		dir = "/var/lib/velvet"
	}
	d := &durableManager{updates: make(chan durableObservationEvent, 256), r: r, path: filepath.Join(dir, r.Desired.UUID.String(), "durable.json"), owner: r.durableOwner(), cooldown: map[uuid.UUID]time.Time{}, observations: map[string]durableObservation{}, operations: map[uuid.UUID]*durableOperation{}, checks: map[uuid.UUID]*durableCheckState{}}
	var err error
	d.records, err = loadDurable(d.path, d.owner)
	if err != nil {
		return err
	}
	if !r.dynamic.allowsInbound() && len(d.records) != 0 {
		if err = saveDurable(d.path, d.owner, map[uuid.UUID]durableRecord{}); err != nil {
			return err
		}
		clear(d.records)
	}
	changed := false
	for peer, record := range d.records {
		choice := r.Desired.Ports
		fixedLocal, fixedRemote := fixedFor(record, r.Desired.UUID), fixedFor(record, peer)
		invalid := fixedLocal.IsValid() && ((choice.Port != 0 && choice.Port != record.LocalPort) || (choice.Range.First != 0 && (record.LocalPort < choice.Range.First || record.LocalPort > choice.Range.Last)))
		invalid = invalid || (fixedRemote.IsValid() && !r.dynamic.candidateAllowed(fixedRemote))
		if invalid {
			delete(d.records, peer)
			changed = true
			r.log(Event{Event: "velvet-durable", Status: "invalidated", RemoteUID: peer.String(), Error: "configuration no longer permits fixed endpoint"})
		}
	}
	if changed {
		if err := saveDurable(d.path, d.owner, d.records); err != nil {
			return err
		}
	}
	r.durable = d
	return nil
}

func (d *durableManager) countLocked() int { return len(d.records) }
func (d *durableManager) confirmedCountLocked() int {
	n := 0
	for _, record := range d.records {
		if record.Confirmed {
			n++
		}
	}
	return n
}
func (d *durableManager) has(remote uuid.UUID) bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.records[remote]
	return ok
}

// Peer names and loopbacks are authenticated session metadata, not agreement
// parameters. Refreshing either keeps the same agreement generation.
func (d *durableManager) refreshPeerMetadata(peer message.UID, publicKey [32]byte, loopback netip.Addr) error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	record, exists := d.records[peer.UUID]
	if !exists {
		return nil
	}
	if record.PublicKey != publicKey {
		return d.deleteLocked(peer.UUID, "peer WireGuard identity changed")
	}
	if record.Peer == peer && record.LastLoopback == loopback {
		return nil
	}
	record.Peer = peer
	record.LastLoopback = loopback
	return d.saveLocked(record)
}

func (d *durableManager) saveLocked(record durableRecord) error {
	next := make(map[uuid.UUID]durableRecord, len(d.records)+1)
	for key, value := range d.records {
		next[key] = value
	}
	next[record.Peer.UUID] = record
	if err := saveDurable(d.path, d.owner, next); err != nil {
		return err
	}
	if previous, exists := d.records[record.Peer.UUID]; exists && previous.ID != record.ID {
		delete(d.checks, record.Peer.UUID)
	}
	d.records = next
	return nil
}

func (d *durableManager) deleteLocked(remote uuid.UUID, reason string) error {
	if _, exists := d.records[remote]; !exists {
		return nil
	}
	next := make(map[uuid.UUID]durableRecord, len(d.records))
	for key, value := range d.records {
		if key != remote {
			next[key] = value
		}
	}
	if err := saveDurable(d.path, d.owner, next); err != nil {
		return err
	}
	d.records = next
	if d.cooldown == nil {
		d.cooldown = map[uuid.UUID]time.Time{}
	}
	d.cooldown[remote] = time.Now().Add(d.r.Desired.Durable.Stable)
	delete(d.operations, remote)
	delete(d.checks, remote)
	// Only this peer must earn a fresh interval; unrelated candidates retain
	// their observations when another agreement is deleted.
	d.r.mu.RLock()
	for name, state := range d.r.states {
		if state.remote == remote {
			delete(d.observations, name)
		}
	}
	d.r.mu.RUnlock()
	d.r.log(Event{Event: "velvet-durable", Status: "invalidated", RemoteUID: remote.String(), Error: reason})
	return nil
}

func fixedFor(record durableRecord, id uuid.UUID) netip.AddrPort {
	for _, ep := range record.FixedEndpoints {
		if ep.UID.UUID == id {
			return ep.Endpoint
		}
	}
	return netip.AddrPort{}
}

func (d *durableManager) observe(ctx context.Context, plan reconcile.LinkPlan, local netip.AddrPort, control netip.Addr, now time.Time) error {
	if d == nil {
		return nil
	}
	// Queued PONG observations can outlive their automatic interface, e.g.
	// after Static takes over. Fence the generation before reading WG and keep
	// cleanup/reuse excluded through both reads and the observation update.
	d.r.links.resourceMu.Lock()
	defer d.r.links.resourceMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if time.Since(now) >= linkFailureTimeout {
		return nil
	}
	d.r.mu.RLock()
	initial, current := d.r.states[plan.InterfaceName]
	d.r.mu.RUnlock()
	if !current || !initial.active || !initial.dynamic || initial.desired.OwnerAlias != plan.OwnerAlias {
		return nil
	}
	port, err := d.r.Reconciler.ListenPort(ctx, plan.InterfaceName)
	if err != nil {
		return err
	}
	remote, ok, err := d.r.Reconciler.ObservedEndpoint(ctx, plan.InterfaceName)
	if err != nil || !ok {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if time.Since(now) >= linkFailureTimeout {
		return nil
	}
	d.r.mu.RLock()
	observedState, current := d.r.states[plan.InterfaceName]
	d.r.mu.RUnlock()
	if !current || !observedState.active || !observedState.dynamic || observedState.desired.OwnerAlias != plan.OwnerAlias {
		return nil
	}
	previous := d.observations[plan.InterfaceName]
	if now.Before(previous.seen) {
		return nil
	}
	if previous.local != local || previous.port != port || now.Sub(previous.seen) >= linkFailureTimeout {
		previous.since = now
	}
	previous.local, previous.remote, previous.control, previous.port, previous.seen = local, remote, control, port, now
	d.observations[plan.InterfaceName] = previous
	d.r.mu.RLock()
	state := d.r.states[plan.InterfaceName]
	d.r.mu.RUnlock()
	if record, exists := d.records[state.remote]; exists {
		own, peer := fixedFor(record, d.r.Desired.UUID), fixedFor(record, state.remote)
		if (own.IsValid() && (own != local || int(own.Port()) != port)) || (peer.IsValid() && peer != remote) {
			return d.deleteLocked(state.remote, "agreed endpoint changed")
		}
	}
	return nil
}

func (d *durableManager) eligibleLocked(plan reconcile.LinkPlan, now time.Time) (message.FixedEndpoint, bool) {
	v, ok := d.observations[plan.InterfaceName]
	if !ok || now.Sub(v.seen) >= linkFailureTimeout || now.Sub(v.since) < d.r.Desired.Durable.Stable || int(v.local.Port()) != v.port {
		return message.FixedEndpoint{}, false
	}
	return message.FixedEndpoint{UID: message.UID{UUID: d.r.Desired.UUID, Name: d.r.Desired.UID.Name}, Endpoint: v.local}, true
}

func (d *durableManager) run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	defer func() { d.mu.Lock(); d.closed = true; d.mu.Unlock(); d.workers.Wait() }()
	for {
		d.tick(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case update := <-d.updates:
			if err := d.observe(ctx, update.plan, update.local, update.control, update.at); err != nil && ctx.Err() == nil {
				d.r.dynamic.reportError(err)
			}
		case <-ticker.C:
		}
	}
}

func (d *durableManager) tick(ctx context.Context, now time.Time) {
	d.r.retryLinkCleanup(ctx)
	d.restoreAndCheck(ctx, now)
	if !d.r.dynamic.allowsInbound() {
		return
	}
	for _, state := range d.r.materializedStates() {
		if !state.dynamic || !state.active {
			continue
		}
		d.mu.Lock()
		if op := d.operations[state.remote]; op != nil && now.Before(op.until) {
			d.mu.Unlock()
			continue
		}
		record, exists := d.records[state.remote]
		if exists && record.Confirmed {
			d.mu.Unlock()
			continue
		}
		observation := d.observations[state.desired.InterfaceName]
		if !observation.control.IsValid() || now.Sub(observation.seen) >= linkFailureTimeout {
			d.mu.Unlock()
			continue
		}
		if !exists {
			if !d.r.dynamic.active() {
				d.mu.Unlock()
				continue
			}
			fixed, eligible := d.eligibleLocked(state.desired, now)
			if !eligible || d.countLocked()+d.reservationsLocked() >= d.r.Desired.Durable.SoftLimit {
				d.mu.Unlock()
				continue
			}
			id, err := newAgreementID()
			if err != nil {
				d.mu.Unlock()
				continue
			}
			record = durableRecord{ID: id, Peer: message.UID{UUID: state.remote}, LocalPort: observation.port, PublicKey: state.desired.PeerPublicKey, FixedEndpoints: []message.FixedEndpoint{fixed}}
			if len(state.peers) != 0 {
				record.LastLoopback = state.peers[0]
			}
		}
		op := &durableOperation{record: record, outgoing: true, until: now.Add(30 * time.Second)}
		d.operations[state.remote] = op
		flags := message.Flags(0)
		if d.confirmedCountLocked() == 0 {
			flags = message.NoDurable
		}
		d.mu.Unlock()
		d.workers.Go(func() {
			attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			conn, err := dialVFP(attemptCtx, state.desired.InterfaceName, state.desired.BootstrapAddress.Addr(), observation.control, d.r.Desired.VFPPort)
			if err == nil {
				first := message.Message{Type: message.DurablePropose, OperationID: record.ID, FixedEndpoints: record.FixedEndpoints, Flags: flags}
				config := d.r.linkProtocol(attemptCtx, state.desired, true, nil)
				config.FirstMessage = &first
				config.Operational = func(s *engine.Session) error {
					d.mu.Lock()
					defer d.mu.Unlock()
					if d.operations[state.remote] != op || s.RemoteUID.UUID != state.remote {
						return errors.New("superseded durable operation")
					}
					op.session = s
					op.record.Peer = s.RemoteUID
					op.record.LastLoopback = s.RemoteLoopbackV6
					return nil
				}
				err = engine.New(config).Run(attemptCtx, conn)
			}
			if err != nil && !errors.Is(err, errDurableComplete) && ctx.Err() == nil {
				d.r.log(Event{Event: "velvet-durable", Status: "retry", RemoteUID: state.remote.String(), Error: err.Error()})
			}
		})
	}
}

func (d *durableManager) reservationsLocked() int {
	n := 0
	for peer, op := range d.operations {
		if _, exists := d.records[peer]; !exists && time.Now().Before(op.until) {
			n++
		}
	}
	return n
}

func (d *durableManager) handleLink(plan reconcile.LinkPlan, s *engine.Session, m message.Message) error {
	if d == nil {
		return errors.New("durable manager unavailable")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.r.mu.RLock()
	state := d.r.states[plan.InterfaceName]
	d.r.mu.RUnlock()
	if !state.active || !state.dynamic || state.remote != s.RemoteUID.UUID || state.desired.OwnerAlias != plan.OwnerAlias {
		return errors.New("durable negotiation requires current healthy automatic Link")
	}
	peer := s.RemoteUID.UUID
	decline := func() error {
		v := message.Message{Type: message.DurableDecline, OperationID: m.OperationID}
		if !d.r.dynamic.allowsInbound() {
			v.DeclineReason = message.DeclinePolicy
			v.Policy = &message.DynamicLinkPolicy{Revision: d.r.dynamic.policyRevision, Accept: false}
		}
		if err := s.Send(v); err != nil {
			return err
		}
		return errDurableComplete
	}
	switch m.Type {
	case message.DurablePropose:
		if d.closed || time.Now().Before(d.cooldown[peer]) || !d.r.dynamic.allowsInbound() {
			return decline()
		}
		current := d.operations[peer]
		if current != nil && current.session != s && time.Now().Before(current.until) && current.record.ID != m.OperationID {
			if !current.outgoing || bytes.Compare(d.r.Desired.UUID[:], peer[:]) < 0 {
				return decline()
			}
		}
		stored, exists := d.records[peer]
		// A peer may have lost or deliberately retired its old record. A fresh
		// proposal can replace that agreement on this healthy Link, using the
		// existing capacity slot but requiring a new bilateral save exchange.
		resume := exists && stored.ID == m.OperationID
		reserved := d.reservationsLocked()
		if current != nil && time.Now().Before(current.until) && !exists {
			reserved--
		}
		if !exists && (d.countLocked() >= maxDynamicLinks || (d.countLocked()+reserved >= d.r.Desired.Durable.SoftLimit && m.Flags&message.NoDurable == 0)) {
			return decline()
		}
		observation := d.observations[plan.InterfaceName]
		if time.Since(observation.seen) >= linkFailureTimeout {
			return decline()
		}
		fixed := append([]message.FixedEndpoint(nil), m.FixedEndpoints...)
		for _, endpoint := range fixed {
			switch endpoint.UID.UUID {
			case d.r.Desired.UUID:
				if !exists || fixedFor(stored, d.r.Desired.UUID) != endpoint.Endpoint {
					if _, eligible := d.eligibleLocked(plan, time.Now()); !eligible {
						return decline()
					}
				}
				if endpoint.Endpoint != observation.local || int(endpoint.Endpoint.Port()) != observation.port {
					return decline()
				}
			case peer:
				if endpoint.Endpoint != observation.remote {
					return decline()
				}
			default:
				return decline()
			}
		}
		if resume && !sameFixed(stored.FixedEndpoints, fixed) {
			return decline()
		}
		record := durableRecord{ID: m.OperationID, Peer: s.RemoteUID, LastLoopback: s.RemoteLoopbackV6, PublicKey: plan.PeerPublicKey, LocalPort: observation.port, FixedEndpoints: fixed}
		if own, eligible := d.eligibleLocked(plan, time.Now()); !resume && eligible && !fixedFor(record, d.r.Desired.UUID).IsValid() {
			id, err := newAgreementID()
			if err != nil {
				return err
			}
			record.ID = id
			record.FixedEndpoints = append(record.FixedEndpoints, own)
			slices.SortFunc(record.FixedEndpoints, func(a, b message.FixedEndpoint) int { return bytes.Compare(a.UID.UUID[:], b.UID.UUID[:]) })
			d.operations[peer] = &durableOperation{record: record, session: s, until: time.Now().Add(30 * time.Second)}
			return s.Send(message.Message{Type: message.DurablePropose, OperationID: record.ID, FixedEndpoints: record.FixedEndpoints})
		}
		if resume {
			record.Confirmed = stored.Confirmed
		}
		if err := d.saveLocked(record); err != nil {
			return fmt.Errorf("save durable agreement: %w", err)
		}
		d.operations[peer] = &durableOperation{record: record, session: s, saved: true, until: time.Now().Add(30 * time.Second)}
		if !d.healthy(plan, peer, s) {
			return errors.New("Link changed during durable save")
		}
		return s.Send(message.Message{Type: message.DurableSaved, OperationID: record.ID})
	case message.DurableSaved:
		op := d.operations[peer]
		if d.closed || op == nil || !time.Now().Before(op.until) || op.record.ID != m.OperationID || op.session != s {
			return errors.New("stale durable confirmation")
		}
		if !op.saved {
			if err := d.saveLocked(op.record); err != nil {
				return err
			}
			op.saved = true
			if !d.healthy(plan, peer, s) {
				return errors.New("Link changed during durable save")
			}
			if err := s.Send(message.Message{Type: message.DurableSaved, OperationID: op.record.ID}); err != nil {
				return err
			}
		}
		if !d.healthy(plan, peer, s) {
			return errors.New("Link changed during durable confirmation")
		}
		op.peerSaved = true
		record := op.record
		record.Confirmed = true
		if err := d.saveLocked(record); err != nil {
			return err
		}
		delete(d.operations, peer)
		d.r.log(Event{Event: "velvet-durable", Status: "established", RemoteUID: peer.String(), Interface: plan.InterfaceName})
		return errDurableComplete
	case message.DurableDecline:
		if op := d.operations[peer]; op != nil && op.session == s && op.record.ID == m.OperationID {
			op.until = time.Now().Add(time.Minute)
		}
		return errDurableComplete
	}
	return errors.New("unexpected durable Link message")
}

func sameFixed(a, b []message.FixedEndpoint) bool {
	return slices.EqualFunc(a, b, func(x, y message.FixedEndpoint) bool { return x.UID.UUID == y.UID.UUID && x.Endpoint == y.Endpoint })
}

// Health reporting never waits for durable disk I/O. Missing observations make
// promotion less likely; they cannot create stability or extend READY.
func (d *durableManager) observeLater(plan reconcile.LinkPlan, local netip.AddrPort, control netip.Addr, now time.Time) {
	if d == nil {
		return
	}
	select {
	case d.updates <- durableObservationEvent{plan, local, control, now}:
	default:
	}
}

func (d *durableManager) healthy(plan reconcile.LinkPlan, peer uuid.UUID, session *engine.Session) bool {
	if session.Context != nil && session.Context.Err() != nil {
		return false
	}
	d.r.mu.RLock()
	defer d.r.mu.RUnlock()
	state, ok := d.r.states[plan.InterfaceName]
	return ok && state.active && state.dynamic && state.remote == peer && state.desired.OwnerAlias == plan.OwnerAlias
}
