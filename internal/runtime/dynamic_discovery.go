package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
)

func (d *dynamicLinkEngine) acceptRouted(ctx context.Context) {
	for {
		conn, err := d.listener.AcceptTCP()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				d.reportError(fmt.Errorf("accept routed VFP: %w", err))
			}
			return
		}
		configureTCP(conn)
		select {
		case d.inboundSessions <- struct{}{}:
			d.workers.Go(func() {
				defer func() { <-d.inboundSessions }()
				d.serveRouted(ctx, conn, netip.Addr{})
			})
		default:
			d.runner.log(Event{Event: "velvet-routed-session", Status: "rejected", Error: "inbound session limit reached"})
			_ = conn.Close()
		}
	}
}

func (d *dynamicLinkEngine) discoverLoopbacks(ctx context.Context) {
	ticker := time.NewTicker(dynamicDiscoveryInterval)
	defer ticker.Stop()
	for {
		d.scanLoopbacks(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *dynamicLinkEngine) scanLoopbacks(ctx context.Context) {
	targets, err := d.runner.Reconciler.ReachableLoopbacks(ctx, d.runner.Desired)
	if err != nil {
		if ctx.Err() == nil {
			d.runner.log(Event{Event: "velvet-dynamic-discovery", Status: "failed", Error: err.Error()})
		}
		return
	}

	now := time.Now()
	d.mu.Lock()
	hasEvidence := len(d.evidence) != 0
	for _, t := range d.targets {
		t.reachable = false
		t.pendingQuery = false
	}
	for _, addr := range targets {
		if t := d.targets[addr]; t != nil {
			t.reachable = true
			t.lastSeen = now
		}
	}
	for addr, t := range d.targets {
		if !t.reachable && !t.dialing && d.attempts[t.uid] == nil && d.pendingCleanups[t.uid] == nil && now.Sub(t.lastSeen) > dynamicTargetRetention && !now.Before(t.nextAttempt) && !now.Before(t.nextQuery) {
			delete(d.targets, addr)
		}
	}
	d.mu.Unlock()
	if d.active() {
		for _, target := range targets {
			if target == d.runner.Desired.LoopbackV6 || d.runner.hasDirectLinkToLoopback(target) {
				continue
			}
			d.mu.Lock()
			t := d.targets[target]
			denied := t != nil && t.policy != nil && !t.policy.Accept
			if denied && !t.dialing && d.attempts[t.uid] == nil && d.pendingCleanups[t.uid] == nil {
				t.pendingQuery = true
			}
			d.mu.Unlock()
			if denied || !hasEvidence || !d.reserveDial(target) {
				continue
			}
			d.workers.Go(func() {
				defer func() { <-d.outboundSessions }()
				d.dialRouted(ctx, target)
			})
		}
	}
	d.flushPolicy(now)
}

func (d *dynamicLinkEngine) reserveDial(target netip.Addr) bool {
	if target == d.runner.Desired.LoopbackV6 || d.runner.hasDirectLinkToLoopback(target) {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	state := d.targets[target]
	if d.stopped || (state != nil && (state.dialing || now.Before(state.nextAttempt) || (state.policy != nil && !state.policy.Accept) || d.attempts[state.uid] != nil || d.pendingCleanups[state.uid] != nil)) {
		return false
	}
	if state == nil && len(d.targets) >= maxDynamicTargets {
		return false
	}
	if now.Sub(d.dialWindow) >= time.Second {
		d.dialWindow = now
		d.dialCount = 0
	}
	if d.dialCount >= maxDynamicDialsPerSecond {
		return false
	}
	select {
	case d.outboundSessions <- struct{}{}:
		if state == nil {
			state = &dynamicTarget{lastSeen: now}
			d.targets[target] = state
		}
		state.dialing = true
		state.failures = min(state.failures+1, uint8(7))
		state.nextAttempt = now.Add(retryDelay(state.failures))
		d.dialCount++
		return true
	default:
		return false
	}
}

func (d *dynamicLinkEngine) dialRouted(ctx context.Context, target netip.Addr) {
	local := &net.TCPAddr{IP: net.IP(d.runner.Desired.LoopbackV6.AsSlice())}
	remote := &net.TCPAddr{IP: net.IP(target.AsSlice()), Port: d.runner.Desired.VFPPort}
	conn, err := dialTCP(ctx, local, remote)
	if err != nil {
		d.runner.log(Event{Event: "velvet-dynamic-attempt", Status: "failed", RemoteIP: target.String(), Error: err.Error()})
		d.finishRoutedDial(target, ctx.Err() == nil)
		return
	}
	d.serveRouted(ctx, conn, target)
}

func (d *dynamicLinkEngine) serveRouted(ctx context.Context, conn net.Conn, expected netip.Addr) {
	if expected.IsValid() {
		defer func() { d.finishRoutedDial(expected, ctx.Err() == nil) }()
	}
	// Bind incoming NODE_STATE to the actual routed TCP source too.
	source := expected
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		source, _ = netip.AddrFromSlice(addr.IP)
	}
	var session *engine.Session
	protocol := engine.New(engine.Config{
		Context:                  engine.RoutedSession,
		LocalUID:                 message.UID{UUID: d.runner.Desired.UUID, Name: d.runner.Desired.UID.Name},
		LocalLoopbackV6:          d.runner.Desired.LoopbackV6,
		ExpectedRemoteLoopbackV6: source,
		LoopbackPoolV6:           d.runner.Desired.LoopbackPoolV6,
		Operational: func(value *engine.Session) error {
			session = value
			if err := d.bindPolicyPeer(value.RemoteLoopbackV6, value.RemoteUID.UUID); err != nil {
				return err
			}
			if expected.IsValid() {
				return d.startOutbound(value)
			}
			return nil
		},
		OperationalMessage: d.handleRoutedMessage,
		FrameError: func(err error) {
			d.runner.log(Event{Event: "velvet-frame", Status: "discarded", Error: err.Error()})
		},
	})
	err := protocol.Run(ctx, conn)
	if session != nil {
		d.routedSessionClosed(session)
	}
	if err != nil && ctx.Err() == nil {
		d.runner.log(Event{Event: "velvet-routed-session", Status: "closed", RemoteIP: expected.String(), Error: err.Error()})
	}
}

func (d *dynamicLinkEngine) finishRoutedDial(target netip.Addr, failed bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	state, exists := d.targets[target]
	if !exists {
		return
	}
	state.dialing = false
	if failed {
		if a := d.attempts[state.uid]; a != nil && a.state == dynamicUp {
			return
		}
		next := time.Now().Add(retryDelay(state.failures))
		if next.After(state.nextAttempt) {
			state.nextAttempt = next
		}
	}
}
