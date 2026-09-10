package runtime

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/inference"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/policy"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/probe"
)

const (
	dynamicResponseTimeout     = 10 * time.Second
	dynamicConnectivityTimeout = 30 * time.Second
	dynamicDiscoveryInterval   = time.Second
	maxRoutedSessions          = 128
	maxDynamicLinks            = 128
	maxDynamicTargets          = 4096
)

type dynamicAttemptState uint8

const (
	dynamicPreparing dynamicAttemptState = iota
	dynamicProposing
	dynamicProbing
	dynamicAttempting
	dynamicUp
	dynamicRecovering
	dynamicStopped
)

// dynamicLinkEngine owns Dynamic Link creation and recovery, including execution,
// timers and resource lifetime. It uses the existing Reconciler/backend and VFP
// sessions directly; there is no separate state-aware runtime executor.
//
// prepare -> propose/accept -> UDP infer/observe/probe -> handoff -> WG/VFP -> up
// Every failed Attempt stops and retains the existing routed path. Recovery uses
// the same committed Link within its deadline; it never restarts inference.
// See dynamic_engine.go for candidate preparation and the terminal decision.
type dynamicLinkEngine struct {
	listenProbe probeListener
	probeSource func(netip.AddrPort) (netip.Addr, error)
	runner      *Runner
	ctx         context.Context
	cancel      context.CancelFunc
	workers     sync.WaitGroup

	// Resource operations take resourceMu before mu. Keep it across removal
	// and reuse of an interface, while releasing mu during kernel cleanup.
	resourceMu sync.Mutex
	stopped    bool

	mu               sync.Mutex
	observerLeases   map[*engine.Session]*observerLease
	evidence         []inference.Evidence
	targets          map[netip.Addr]*dynamicTarget
	attempts         map[uuid.UUID]*dynamicAttempt
	pendingCleanups  map[uuid.UUID]*dynamicCleanup
	listener         *net.TCPListener
	policySocket     policyTransport
	policyRevision   uint64
	policyCursor     int
	dialWindow       time.Time
	dialCount        int
	errors           chan error
	inboundSessions  chan struct{}
	outboundSessions chan struct{}
}

type dynamicTarget struct {
	dialing       bool
	uid           uuid.UUID
	bound         bool // learned through OPEN/NODE_STATE, not a UDP query
	failures      uint8
	nextAttempt   time.Time
	nextQuery     time.Time
	nextUpdate    time.Time
	policy        *message.DynamicLinkPolicy
	pendingUpdate bool
	pendingQuery  bool
	reachable     bool
	lastSeen      time.Time
}

type dynamicAttempt struct {
	udp           *udpAttempt
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
		runner:      runner,
		probeSource: probe.Source,
		listenProbe: func(ctx context.Context, local netip.AddrPort, r *probe.Receiver, f func(probe.Received)) (probeSocket, error) {
			return probe.Listen(ctx, local, r, f)
		},
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
	dir := d.runner.PolicyStateDir
	if dir == "" {
		dir = "/var/lib/velvet"
	}
	revision, err := reservePolicyRevision(filepath.Join(dir, d.runner.Desired.UUID.String(), "dynamic-link-revision"))
	if err != nil {
		listener.Close()
		d.cancel()
		return fmt.Errorf("reserve policy revision: %w", err)
	}
	d.policyRevision = revision
	ps, err := policy.Listen(d.runner.Desired.LoopbackV6, d.runner.Desired.LoopbackPoolV6, d.runner.Desired.VFPPort, d.policyIngress)
	if err != nil {
		listener.Close()
		d.cancel()
		return fmt.Errorf("listen for routed policy: %w", err)
	}
	d.policySocket = ps
	d.targets = d.runner.policySeed
	if d.targets == nil {
		d.targets = make(map[netip.Addr]*dynamicTarget)
	}
	for _, target := range d.targets {
		target.pendingUpdate = target.uid != uuid.Nil
	}
	d.workers.Go(func() { d.readPolicy(ctx) })
	d.workers.Go(func() {
		<-ctx.Done()
		_ = listener.Close()
		_ = ps.Close()
	})
	d.workers.Go(func() { d.acceptRouted(ctx) })
	d.workers.Go(func() { d.discoverLoopbacks(ctx) })
	return nil
}

func (d *dynamicLinkEngine) stop() {
	if d.cancel != nil {
		d.cancel()
	}
	if d.listener != nil {
		_ = d.listener.Close()
	}
	if d.policySocket != nil {
		_ = d.policySocket.Close()
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

type policyTransport interface {
	Read() (netip.Addr, message.Message, error)
	Send(netip.Addr, message.Message) error
	Close() error
}
