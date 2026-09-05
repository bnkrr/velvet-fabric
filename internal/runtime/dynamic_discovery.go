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

func (d *dynamicRuntime) acceptRouted(ctx context.Context) {
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
			go func() {
				defer func() { <-d.inboundSessions }()
				d.serveRouted(ctx, conn, netip.Addr{})
			}()
		default:
			d.runner.log(Event{Event: "velvet-routed-session", Status: "rejected", Error: "inbound session limit reached"})
			_ = conn.Close()
		}
	}
}

func (d *dynamicRuntime) discoverLoopbacks(ctx context.Context) {
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

func (d *dynamicRuntime) scanLoopbacks(ctx context.Context) {
	d.mu.Lock()
	_, hasEvidence := d.firstEvidenceLocked()
	d.mu.Unlock()
	if !hasEvidence {
		return
	}
	targets, err := d.runner.Reconciler.ReachableLoopbacks(ctx, d.runner.Desired)
	if err != nil {
		if ctx.Err() == nil {
			d.runner.log(Event{Event: "velvet-dynamic-discovery", Status: "failed", Error: err.Error()})
		}
		return
	}
	for _, target := range targets {
		if !d.reserveDial(target) {
			continue
		}
		go func() {
			defer func() { <-d.outboundSessions }()
			d.dialRouted(ctx, target)
		}()
	}
}

func (d *dynamicRuntime) reserveDial(target netip.Addr) bool {
	if target == d.runner.Desired.LoopbackV6 || d.runner.hasDirectLinkToLoopback(target) {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	state := d.targets[target]
	if state != nil && (state.attempted || state.dialing) {
		return false
	}
	if state == nil && len(d.targets) >= maxDynamicTargets {
		return false
	}
	select {
	case d.outboundSessions <- struct{}{}:
		if state == nil {
			state = &dynamicTarget{}
			d.targets[target] = state
		}
		state.dialing = true
		return true
	default:
		return false
	}
}

func (d *dynamicRuntime) dialRouted(ctx context.Context, target netip.Addr) {
	local := &net.TCPAddr{IP: net.IP(d.runner.Desired.LoopbackV6.AsSlice())}
	remote := &net.TCPAddr{IP: net.IP(target.AsSlice()), Port: d.runner.Desired.VFPPort}
	conn, err := dialTCP(ctx, local, remote)
	if err != nil {
		d.runner.log(Event{Event: "velvet-dynamic-attempt", Status: "failed", RemoteIP: target.String(), Error: err.Error()})
		d.finishRoutedDial(target, ctx.Err() == nil)
		return
	}
	d.serveRouted(ctx, conn, target)
	d.finishRoutedDial(target, ctx.Err() == nil)
}

func (d *dynamicRuntime) serveRouted(ctx context.Context, conn net.Conn, expected netip.Addr) {
	var session *engine.Session
	protocol := engine.New(engine.Config{
		Context:                  engine.RoutedSession,
		LocalUID:                 message.UID{UUID: d.runner.Desired.UUID, Name: d.runner.Desired.UID.Name},
		LocalLoopbackV6:          d.runner.Desired.LoopbackV6,
		ExpectedRemoteLoopbackV6: expected,
		LoopbackPoolV6:           d.runner.Desired.LoopbackPoolV6,
		Operational: func(value *engine.Session) error {
			session = value
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

func (d *dynamicRuntime) finishRoutedDial(target netip.Addr, failed bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	state, exists := d.targets[target]
	if !exists {
		return
	}
	state.dialing = false
	if !failed {
		if !state.attempted {
			delete(d.targets, target)
		}
		return
	}
	if state.attempted {
		return
	}
	state.failures++
	if state.failures >= maxRoutedDialAttempts {
		state.attempted = true
		state.failures = 0
	}
}
