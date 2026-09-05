package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	dynamicResponseTimeout      = 10 * time.Second
	dynamicConnectivityTimeout  = 30 * time.Second
	dynamicDiscoveryInterval    = time.Second
	endpointObservationInterval = time.Second
)

type dynamicRuntime struct {
	runner *Runner
	ctx    context.Context

	mu                 sync.Mutex
	evidence           map[string]netip.AddrPort
	evidenceOrder      []string
	attemptedLoopbacks map[netip.Addr]struct{}
	dialingLoopbacks   map[netip.Addr]struct{}
	attempts           map[uuid.UUID]*dynamicAttempt
	pendingCleanups    map[uuid.UUID]*dynamicCleanup
	listener           *net.TCPListener
	errors             chan error
}

type dynamicAttempt struct {
	remote        message.UID
	operationID   [16]byte
	initiator     uuid.UUID
	plan          reconcile.LinkPlan
	session       *engine.Session
	state         string
	responseTimer *time.Timer
	deadlineTimer *time.Timer
	cancel        context.CancelFunc
}

type dynamicCleanup struct {
	interfaceName string
	timer         *time.Timer
}

func newDynamicRuntime(runner *Runner) *dynamicRuntime {
	return &dynamicRuntime{
		runner: runner, evidence: make(map[string]netip.AddrPort),
		attemptedLoopbacks: make(map[netip.Addr]struct{}), dialingLoopbacks: make(map[netip.Addr]struct{}),
		attempts:        make(map[uuid.UUID]*dynamicAttempt),
		pendingCleanups: make(map[uuid.UUID]*dynamicCleanup),
		errors:          make(chan error, 1),
	}
}

func (d *dynamicRuntime) start(ctx context.Context) error {
	d.ctx = ctx
	address := &net.TCPAddr{IP: net.IP(d.runner.Desired.LoopbackV6.AsSlice()), Port: d.runner.Desired.VFPPort}
	listener, err := net.ListenTCP("tcp6", address)
	if err != nil {
		return fmt.Errorf("listen for routed VFP on %s: %w", address, err)
	}
	d.listener = listener
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	go d.acceptRouted(ctx)
	if d.active() {
		go d.discoverLoopbacks(ctx)
	}
	return nil
}

func (d *dynamicRuntime) stop() {
	if d.listener != nil {
		_ = d.listener.Close()
	}
	d.mu.Lock()
	interfaces := make([]string, 0, len(d.attempts))
	for _, attempt := range d.attempts {
		if attempt.responseTimer != nil {
			attempt.responseTimer.Stop()
		}
		if attempt.deadlineTimer != nil {
			attempt.deadlineTimer.Stop()
		}
		if attempt.cancel != nil {
			attempt.cancel()
		}
		interfaces = append(interfaces, attempt.plan.InterfaceName)
	}
	for _, cleanup := range d.pendingCleanups {
		cleanup.timer.Stop()
		interfaces = append(interfaces, cleanup.interfaceName)
	}
	d.attempts = make(map[uuid.UUID]*dynamicAttempt)
	d.pendingCleanups = make(map[uuid.UUID]*dynamicCleanup)
	d.mu.Unlock()
	for _, name := range interfaces {
		d.removeInterface(name, "dynamic runtime stopped")
	}
}

func (d *dynamicRuntime) active() bool {
	return d.runner.Desired.DynamicLinks != nil && d.runner.Desired.DynamicLinks.Mode == spec.DynamicLinksActive
}

func (d *dynamicRuntime) allowsInbound() bool {
	plan := d.runner.Desired.DynamicLinks
	return plan != nil && (plan.Mode == spec.DynamicLinksActive || plan.Mode == spec.DynamicLinksPassive)
}

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
		go d.serveRouted(ctx, conn, netip.Addr{})
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
		if target == d.runner.Desired.LoopbackV6 || d.runner.hasDirectLinkToLoopback(target) {
			continue
		}
		d.mu.Lock()
		_, attempted := d.attemptedLoopbacks[target]
		_, dialing := d.dialingLoopbacks[target]
		if attempted || dialing {
			d.mu.Unlock()
			continue
		}
		d.dialingLoopbacks[target] = struct{}{}
		d.mu.Unlock()
		go d.dialRouted(ctx, target)
	}
}

func (d *dynamicRuntime) dialRouted(ctx context.Context, target netip.Addr) {
	defer func() {
		d.mu.Lock()
		delete(d.dialingLoopbacks, target)
		d.mu.Unlock()
	}()
	local := &net.TCPAddr{IP: net.IP(d.runner.Desired.LoopbackV6.AsSlice())}
	remote := &net.TCPAddr{IP: net.IP(target.AsSlice()), Port: d.runner.Desired.VFPPort}
	conn, err := (&net.Dialer{LocalAddr: local, Timeout: 3 * time.Second}).DialContext(ctx, "tcp6", remote.String())
	if err != nil {
		d.runner.log(Event{Event: "velvet-dynamic-attempt", Status: "failed", RemoteIP: target.String(), Error: err.Error()})
		return
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		return
	}
	configureTCP(tcp)
	d.serveRouted(ctx, tcp, target)
}

func (d *dynamicRuntime) serveRouted(ctx context.Context, conn net.Conn, expected netip.Addr) {
	var session *engine.Session
	protocol := engine.New(engine.Config{
		Context:         engine.RoutedSession,
		LocalUID:        message.UID{UUID: d.runner.Desired.UUID, Name: d.runner.Desired.UID.Name},
		LocalLoopbackV6: d.runner.Desired.LoopbackV6, ExpectedRemoteLoopbackV6: expected,
		LoopbackPoolV6: d.runner.Desired.LoopbackPoolV6,
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

func (d *dynamicRuntime) startOutbound(session *engine.Session) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	remoteID := session.RemoteUID.UUID
	remoteLoopback := session.RemoteLoopbackV6
	if d.runner.hasDirectLink(remoteID) {
		return nil
	}
	if _, attempted := d.attemptedLoopbacks[remoteLoopback]; attempted {
		return nil
	}
	if _, exists := d.attempts[remoteID]; exists {
		return nil
	}
	observation, ok := d.firstEvidenceLocked()
	if !ok {
		d.runner.log(Event{Event: "velvet-dynamic-attempt", Status: "failed", RemoteUID: remoteID.String(), Error: "no Endpoint Observation"})
		return nil
	}
	d.attemptedLoopbacks[remoteLoopback] = struct{}{}
	plan, err := d.runner.Reconciler.PrepareDynamic(d.ctx, d.runner.Desired, nodeUID(session.RemoteUID))
	if err != nil {
		d.runner.log(Event{Event: "velvet-dynamic-attempt", Status: "failed", RemoteUID: remoteID.String(), Error: err.Error()})
		return nil
	}
	operationID, err := newOperationID()
	if err != nil {
		d.removeInterfaceLocked(plan.InterfaceName, "operation ID generation failed")
		return err
	}
	attempt := &dynamicAttempt{
		remote: session.RemoteUID, operationID: operationID, initiator: d.runner.Desired.UUID,
		plan: plan, session: session, state: "proposing",
	}
	d.attempts[remoteID] = attempt
	candidate := netip.AddrPortFrom(observation.Addr(), uint16(plan.ListenPort))
	publicKey := [32]byte(plan.PrivateKey.PublicKey())
	if err := session.Send(message.Message{
		Type: message.DynamicLinkPropose, OperationID: operationID,
		WGPublicKey: publicKey, Endpoint: candidate,
	}); err != nil {
		delete(d.attempts, remoteID)
		d.removeInterfaceLocked(plan.InterfaceName, "send Proposal failed")
		return err
	}
	attempt.responseTimer = time.AfterFunc(dynamicResponseTimeout, func() {
		d.failAttempt(remoteID, operationID, "response timeout")
	})
	d.runner.log(Event{Event: "velvet-dynamic-attempt", Status: "proposed", RemoteUID: remoteID.String(), Interface: plan.InterfaceName})
	return nil
}

func (d *dynamicRuntime) handleRoutedMessage(session *engine.Session, value message.Message) error {
	switch value.Type {
	case message.DynamicLinkPropose:
		return d.handleProposal(session, value)
	case message.DynamicLinkAccept:
		return d.handleAccept(session, value)
	case message.DynamicLinkDecline:
		d.handleDecline(session, value)
	}
	return nil
}

func (d *dynamicRuntime) handleProposal(session *engine.Session, value message.Message) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	remoteID := session.RemoteUID.UUID
	var plan reconcile.LinkPlan
	decline := func() error {
		return session.Send(message.Message{Type: message.DynamicLinkDecline, OperationID: value.OperationID})
	}
	if !d.allowsInbound() || !d.candidateAllowed(value.Endpoint) || d.runner.hasDirectLink(remoteID) {
		return decline()
	}
	observation, ok := d.firstEvidenceLocked()
	if !ok {
		return decline()
	}
	if current, exists := d.attempts[remoteID]; exists {
		if current.initiator == d.runner.Desired.UUID && bytes.Compare(d.runner.Desired.UUID[:], remoteID[:]) < 0 {
			return decline()
		}
		if current.initiator != d.runner.Desired.UUID {
			return decline()
		}
		// Both nodes may propose concurrently. The greater UUID adopts the
		// smaller UUID's operation, but keeps its already reserved interface and
		// ephemeral listen port. Deleting and immediately recreating the same
		// interface lets the canceled operation race with the replacement.
		plan = current.plan
		d.discardAttemptLocked(remoteID, current, false)
	}
	d.cancelDeferredCleanupLocked(remoteID)
	if plan.InterfaceName == "" {
		var err error
		plan, err = d.runner.Reconciler.PrepareDynamic(d.ctx, d.runner.Desired, nodeUID(session.RemoteUID))
		if err != nil {
			return decline()
		}
	}
	peerKey := wgtypes.Key(value.WGPublicKey)
	plan, err := d.runner.Reconciler.ConfigureDynamic(d.ctx, d.runner.Desired, plan, peerKey, value.Endpoint)
	if err != nil {
		d.removeInterfaceLocked(plan.InterfaceName, "configure accepted Proposal failed")
		return decline()
	}
	attempt := &dynamicAttempt{
		remote: session.RemoteUID, operationID: value.OperationID, initiator: remoteID,
		plan: plan, session: session, state: "attempting",
	}
	d.attempts[remoteID] = attempt
	localCandidate := netip.AddrPortFrom(observation.Addr(), uint16(plan.ListenPort))
	if err := session.Send(message.Message{
		Type: message.DynamicLinkAccept, OperationID: value.OperationID,
		WGPublicKey: [32]byte(plan.PrivateKey.PublicKey()), Endpoint: localCandidate,
	}); err != nil {
		d.dropAttemptLocked(remoteID, attempt, "send Accept failed")
		return err
	}
	d.startConnectivityLocked(attempt)
	d.runner.log(Event{Event: "velvet-dynamic-attempt", Status: "accepted", RemoteUID: remoteID.String(), Interface: plan.InterfaceName})
	return nil
}

func (d *dynamicRuntime) handleAccept(session *engine.Session, value message.Message) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	remoteID := session.RemoteUID.UUID
	attempt, exists := d.attempts[remoteID]
	if !exists || attempt.session != session || attempt.operationID != value.OperationID || attempt.state != "proposing" {
		d.frameError("DYNAMIC_LINK_ACCEPT references an unknown operation")
		return nil
	}
	if !d.candidateAllowed(value.Endpoint) {
		d.dropAttemptLocked(remoteID, attempt, "Accept candidate rejected")
		return nil
	}
	peerKey := wgtypes.Key(value.WGPublicKey)
	plan, err := d.runner.Reconciler.ConfigureDynamic(d.ctx, d.runner.Desired, attempt.plan, peerKey, value.Endpoint)
	if err != nil {
		d.dropAttemptLocked(remoteID, attempt, "configure accepted Link failed")
		return nil
	}
	attempt.plan = plan
	attempt.state = "attempting"
	if attempt.responseTimer != nil {
		attempt.responseTimer.Stop()
	}
	d.startConnectivityLocked(attempt)
	return nil
}

func (d *dynamicRuntime) handleDecline(session *engine.Session, value message.Message) {
	d.mu.Lock()
	defer d.mu.Unlock()
	remoteID := session.RemoteUID.UUID
	attempt, exists := d.attempts[remoteID]
	if !exists || attempt.session != session || attempt.operationID != value.OperationID || attempt.state != "proposing" {
		d.frameError("DYNAMIC_LINK_DECLINE references an unknown operation")
		return
	}
	// A DECLINE and the peer's winning simultaneous Proposal travel on separate
	// routed sessions and can be observed in either order. Keep the reserved
	// interface briefly so that the winning Proposal can reuse its ifindex. A
	// delete/recreate cycle would leave Go's IPv6 zone cache pointing at the old
	// ifindex and make the link-local VFP bind fail with ENODEV.
	d.discardAttemptLocked(remoteID, attempt, false)
	d.deferCleanupLocked(remoteID, attempt.plan.InterfaceName, "Proposal declined")
	d.runner.log(Event{Event: "velvet-dynamic-attempt", Status: "declined", RemoteUID: remoteID.String()})
}

func (d *dynamicRuntime) startConnectivityLocked(attempt *dynamicAttempt) {
	ctx, cancel := context.WithCancel(d.ctx)
	attempt.cancel = cancel
	attempt.deadlineTimer = time.AfterFunc(dynamicConnectivityTimeout, cancel)
	go d.establishDynamic(ctx, attempt)
}

func (d *dynamicRuntime) establishDynamic(ctx context.Context, attempt *dynamicAttempt) {
	for ctx.Err() == nil {
		conn, err := d.runner.discoverPeer(ctx, attempt.plan)
		if err == nil {
			err = d.runner.serveLinkSession(ctx, conn, attempt.plan, true, dynamicConnectivityTimeout, func(result engine.Result) {
				d.commitAttempt(attempt, result)
			})
		}
		if ctx.Err() != nil {
			break
		}
		d.mu.Lock()
		current := d.attempts[attempt.remote.UUID]
		up := current == attempt && attempt.state == "up"
		d.mu.Unlock()
		if !up {
			d.failAttempt(attempt.remote.UUID, attempt.operationID, errorText(err))
			return
		}
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
		}
	}
	d.mu.Lock()
	current := d.attempts[attempt.remote.UUID]
	up := current == attempt && attempt.state == "up"
	d.mu.Unlock()
	if !up {
		d.failAttempt(attempt.remote.UUID, attempt.operationID, "connectivity deadline")
	}
}

func (d *dynamicRuntime) commitAttempt(attempt *dynamicAttempt, result engine.Result) {
	d.mu.Lock()
	defer d.mu.Unlock()
	current := d.attempts[attempt.remote.UUID]
	if current != attempt || result.RemoteUID.UUID != attempt.remote.UUID {
		return
	}
	attempt.state = "up"
	if attempt.deadlineTimer != nil {
		attempt.deadlineTimer.Stop()
	}
	d.runner.log(Event{Event: "velvet-dynamic-link", Status: "up", RemoteUID: attempt.remote.UUID.String(), Interface: attempt.plan.InterfaceName})
}

func (d *dynamicRuntime) failAttempt(remote uuid.UUID, operationID [16]byte, reason string) {
	d.mu.Lock()
	attempt, exists := d.attempts[remote]
	if !exists || attempt.operationID != operationID || attempt.state == "up" {
		d.mu.Unlock()
		return
	}
	d.dropAttemptLocked(remote, attempt, reason)
	d.mu.Unlock()
	d.runner.log(Event{Event: "velvet-dynamic-attempt", Status: "failed", RemoteUID: remote.String(), Error: reason})
}

func (d *dynamicRuntime) dropAttemptLocked(remote uuid.UUID, attempt *dynamicAttempt, reason string) {
	d.discardAttemptLocked(remote, attempt, true, reason)
}

func (d *dynamicRuntime) discardAttemptLocked(remote uuid.UUID, attempt *dynamicAttempt, removeInterface bool, reason ...string) {
	delete(d.attempts, remote)
	if attempt.responseTimer != nil {
		attempt.responseTimer.Stop()
	}
	if attempt.deadlineTimer != nil {
		attempt.deadlineTimer.Stop()
	}
	if attempt.cancel != nil {
		attempt.cancel()
	}
	if removeInterface {
		why := "attempt ended"
		if len(reason) > 0 {
			why = reason[0]
		}
		d.removeInterfaceLocked(attempt.plan.InterfaceName, why)
	}
}

func (d *dynamicRuntime) deferCleanupLocked(remote uuid.UUID, interfaceName, reason string) {
	d.cancelDeferredCleanupLocked(remote)
	cleanup := &dynamicCleanup{interfaceName: interfaceName}
	cleanup.timer = time.AfterFunc(dynamicResponseTimeout, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.pendingCleanups[remote] != cleanup {
			return
		}
		delete(d.pendingCleanups, remote)
		if attempt := d.attempts[remote]; attempt != nil && attempt.plan.InterfaceName == interfaceName {
			return
		}
		d.removeInterfaceLocked(interfaceName, reason)
	})
	d.pendingCleanups[remote] = cleanup
}

func (d *dynamicRuntime) cancelDeferredCleanupLocked(remote uuid.UUID) {
	if cleanup := d.pendingCleanups[remote]; cleanup != nil {
		cleanup.timer.Stop()
		delete(d.pendingCleanups, remote)
	}
}

func (d *dynamicRuntime) routedSessionClosed(session *engine.Session) {
	d.mu.Lock()
	defer d.mu.Unlock()
	attempt, exists := d.attempts[session.RemoteUID.UUID]
	if exists && attempt.session == session && attempt.state == "proposing" {
		d.dropAttemptLocked(session.RemoteUID.UUID, attempt, "routed session closed before response")
	}
}

func (d *dynamicRuntime) candidateAllowed(candidate netip.AddrPort) bool {
	plan := d.runner.Desired.DynamicLinks
	if plan == nil {
		return false
	}
	for _, prefix := range plan.AllowCandidatePrefixes {
		if prefix.Contains(candidate.Addr()) {
			return true
		}
	}
	return false
}

func (d *dynamicRuntime) setEvidence(interfaceName string, endpoint netip.AddrPort) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.evidence[interfaceName]; !exists {
		d.evidenceOrder = append(d.evidenceOrder, interfaceName)
	}
	d.evidence[interfaceName] = endpoint
}

func (d *dynamicRuntime) removeEvidence(interfaceName string) {
	d.mu.Lock()
	delete(d.evidence, interfaceName)
	d.mu.Unlock()
}

func (d *dynamicRuntime) firstEvidenceLocked() (netip.AddrPort, bool) {
	for _, name := range d.evidenceOrder {
		if endpoint, exists := d.evidence[name]; exists {
			return endpoint, true
		}
	}
	return netip.AddrPort{}, false
}

func (d *dynamicRuntime) removeInterface(name, reason string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.removeInterfaceLocked(name, reason)
}

func (d *dynamicRuntime) removeInterfaceLocked(name, reason string) {
	delete(d.evidence, name)
	if d.runner.babel != nil {
		d.runner.babel.SetLinkPrefixes(name, nil)
	}
	d.runner.log(Event{Event: "velvet-dynamic-link", Status: "cleanup", Interface: name, Error: reason})
	if err := d.runner.Reconciler.RemoveDynamic(context.Background(), name); err != nil {
		d.runner.log(Event{Event: "velvet-dynamic-link", Status: "cleanup-failed", Interface: name, Error: err.Error()})
	}
}

func (d *dynamicRuntime) reportError(err error) {
	select {
	case d.errors <- err:
	default:
	}
}

func (d *dynamicRuntime) frameError(text string) {
	d.runner.log(Event{Event: "velvet-frame", Status: "discarded", Error: text})
}

func newOperationID() ([16]byte, error) {
	var result [16]byte
	_, err := rand.Read(result[:])
	return result, err
}

func nodeUID(value message.UID) spec.NodeUID {
	return spec.NodeUID{Name: value.Name, UUID: value.UUID.String()}
}

func errorText(err error) string {
	if err == nil {
		return "Link establishment stopped"
	}
	return err.Error()
}
