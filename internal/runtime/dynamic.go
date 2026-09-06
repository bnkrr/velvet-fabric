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
	"github.com/velvet-fabric/velvet-fabric/internal/inference"
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
	dynamicPreparing dynamicAttemptState = iota
	dynamicProposing
	dynamicAttempting
	dynamicUp
	dynamicRecovering
	dynamicStopped
)

// dynamicLinkEngine owns Dynamic Link creation and recovery, including execution,
// timers and resource lifetime. It uses the existing Reconciler/backend and VFP
// sessions directly; there is no separate state-aware runtime executor.
//
// prepare + baseline inference -> propose/accept -> connectivity -> commit -> up
// Every failed Attempt stops and retains the existing routed path. Recovery uses
// the same committed Link within its deadline; it never restarts inference.
// See dynamic_engine.go for candidate preparation and the terminal decision.
type dynamicLinkEngine struct {
	runner  *Runner
	ctx     context.Context
	cancel  context.CancelFunc
	workers sync.WaitGroup

	// Resource operations take resourceMu before mu. Keep it across removal
	// and reuse of an interface, while releasing mu during kernel cleanup.
	resourceMu sync.Mutex
	stopped    bool

	mu               sync.Mutex
	evidence         []inference.Evidence
	targets          map[netip.Addr]*dynamicTarget
	attempts         map[uuid.UUID]*dynamicAttempt
	pendingCleanups  map[uuid.UUID]*dynamicCleanup
	listener         *net.TCPListener
	errors           chan error
	inboundSessions  chan struct{}
	outboundSessions chan struct{}
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
	candidate     netip.AddrPort // frozen for this Attempt, independent of later Evidence
	session       *engine.Session
	state         dynamicAttemptState
	responseTimer *time.Timer
	deadlineTimer *time.Timer
	deadlineEpoch uint64
	cancel        context.CancelFunc
}

type dynamicCleanup struct {
	plan  reconcile.LinkPlan
	timer *time.Timer
}

func newDynamicLinkEngine(runner *Runner) *dynamicLinkEngine {
	return &dynamicLinkEngine{
		runner:           runner,
		targets:          make(map[netip.Addr]*dynamicTarget),
		attempts:         make(map[uuid.UUID]*dynamicAttempt),
		pendingCleanups:  make(map[uuid.UUID]*dynamicCleanup),
		errors:           make(chan error, 1),
		inboundSessions:  make(chan struct{}, maxRoutedSessions),
		outboundSessions: make(chan struct{}, maxRoutedSessions),
	}
}

func (d *dynamicLinkEngine) start(ctx context.Context) error {
	ctx, d.cancel = context.WithCancel(ctx)
	d.ctx = ctx
	address := &net.TCPAddr{IP: net.IP(d.runner.Desired.LoopbackV6.AsSlice()), Port: d.runner.Desired.VFPPort}
	listener, err := net.ListenTCP("tcp6", address)
	if err != nil {
		d.cancel()
		return fmt.Errorf("listen for routed VFP on %s: %w", address, err)
	}
	d.listener = listener
	d.workers.Go(func() {
		<-ctx.Done()
		_ = listener.Close()
	})
	d.workers.Go(func() { d.acceptRouted(ctx) })
	if d.active() {
		d.workers.Go(func() { d.discoverLoopbacks(ctx) })
	}
	return nil
}

func (d *dynamicLinkEngine) stop() {
	if d.cancel != nil {
		d.cancel()
	}
	if d.listener != nil {
		_ = d.listener.Close()
	}
	d.resourceMu.Lock()
	d.mu.Lock()
	d.stopped = true
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
	d.resourceMu.Unlock()
	d.workers.Wait()
	d.resourceMu.Lock()
	defer d.resourceMu.Unlock()
	for _, plan := range plans {
		d.removeInterface(plan, "dynamic Link engine stopped")
	}
}

func (d *dynamicLinkEngine) active() bool {
	return d.runner.Desired.DynamicLinks != nil && d.runner.Desired.DynamicLinks.Mode == spec.DynamicLinksActive
}

func (d *dynamicLinkEngine) allowsInbound() bool {
	plan := d.runner.Desired.DynamicLinks
	return plan != nil && (plan.Mode == spec.DynamicLinksActive || plan.Mode == spec.DynamicLinksPassive)
}

func (d *dynamicLinkEngine) reportError(err error) {
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
