package runtime

import (
	"context"
	"crypto/rand"
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
)

const (
	dynamicResponseTimeout      = 10 * time.Second
	dynamicConnectivityTimeout  = 30 * time.Second
	dynamicDiscoveryInterval    = time.Second
	endpointObservationInterval = time.Second
	maxRoutedSessions           = 128
	maxDynamicLinks             = 128
	maxDynamicTargets           = 4096
	maxRoutedDialAttempts       = 3
)

type dynamicAttemptState uint8

const (
	dynamicProposing dynamicAttemptState = iota
	dynamicAttempting
	dynamicUp
	dynamicRecovering
)

type dynamicRuntime struct {
	runner *Runner
	ctx    context.Context

	mu               sync.Mutex
	evidence         []endpointEvidence
	targets          map[netip.Addr]*dynamicTarget
	attempts         map[uuid.UUID]*dynamicAttempt
	pendingCleanups  map[uuid.UUID]*dynamicCleanup
	listener         *net.TCPListener
	errors           chan error
	inboundSessions  chan struct{}
	outboundSessions chan struct{}
}

type endpointEvidence struct {
	interfaceName string
	endpoint      netip.AddrPort
}

type dynamicTarget struct {
	dialing   bool
	attempted bool
	failures  uint8
}

type dynamicAttempt struct {
	remote        uuid.UUID
	operationID   [16]byte
	localProposal bool
	plan          reconcile.LinkPlan
	session       *engine.Session
	state         dynamicAttemptState
	responseTimer *time.Timer
	deadlineTimer *time.Timer
	cancel        context.CancelFunc
}

type dynamicCleanup struct {
	plan  reconcile.LinkPlan
	timer *time.Timer
}

func newDynamicRuntime(runner *Runner) *dynamicRuntime {
	return &dynamicRuntime{
		runner:           runner,
		targets:          make(map[netip.Addr]*dynamicTarget),
		attempts:         make(map[uuid.UUID]*dynamicAttempt),
		pendingCleanups:  make(map[uuid.UUID]*dynamicCleanup),
		errors:           make(chan error, 1),
		inboundSessions:  make(chan struct{}, maxRoutedSessions),
		outboundSessions: make(chan struct{}, maxRoutedSessions),
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
	plans := make([]reconcile.LinkPlan, 0, len(d.attempts)+len(d.pendingCleanups))
	for _, attempt := range d.attempts {
		stopAttempt(attempt)
		plans = append(plans, attempt.plan)
	}
	for _, cleanup := range d.pendingCleanups {
		cleanup.timer.Stop()
		plans = append(plans, cleanup.plan)
	}
	clear(d.attempts)
	clear(d.pendingCleanups)
	d.mu.Unlock()
	for _, plan := range plans {
		d.removeInterface(plan, "dynamic runtime stopped")
	}
}

func (d *dynamicRuntime) active() bool {
	return d.runner.Desired.DynamicLinks != nil && d.runner.Desired.DynamicLinks.Mode == spec.DynamicLinksActive
}

func (d *dynamicRuntime) allowsInbound() bool {
	plan := d.runner.Desired.DynamicLinks
	return plan != nil && (plan.Mode == spec.DynamicLinksActive || plan.Mode == spec.DynamicLinksPassive)
}

func (d *dynamicRuntime) reportError(err error) {
	select {
	case d.errors <- err:
	default:
	}
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
