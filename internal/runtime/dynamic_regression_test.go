package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/inference"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func dynamicFixture(t *testing.T, backend *runtimeBackend) (*dynamicLinkEngine, *engine.Session, message.Message) {
	t.Helper()
	local := uuid.MustParse("30000000-0000-4000-8000-000000000003")
	remote := uuid.MustParse("20000000-0000-4000-8000-000000000002")
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	runner := &Runner{
		Desired: &reconcile.DesiredState{
			UUID: local, PrivateKey: key, FabricPSK: make([]byte, 32),
			DynamicLinks: &reconcile.DynamicLinksPlan{Mode: spec.DynamicLinksActive, AllowCandidatePrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
		},
		Reconciler: reconcile.New(backend), states: make(map[string]materializedState),
	}
	d := newDynamicLinkEngine(runner)
	runner.dynamic = d
	d.ctx, d.cancel = context.WithCancel(context.Background())
	t.Cleanup(d.stop)
	if err := d.setEvidence("vl-seed", 51000, netip.MustParseAddrPort("192.0.2.1:62000")); err != nil {
		t.Fatal(err)
	}
	session := &engine.Session{Context: d.ctx, RemoteUID: message.UID{UUID: remote, Name: "peer"}, RemoteLoopbackV6: netip.MustParseAddr("fd00::2")}
	proposal := message.Message{Type: message.DynamicLinkPropose, OperationID: [16]byte{2}, WGPublicKey: [32]byte(peerKey.PublicKey()), Endpoint: netip.MustParseAddrPort("192.0.2.2:54000")}
	return d, session, proposal
}

func TestDynamicCommitValidatesBeforeMaterialization(t *testing.T) {
	for _, scenario := range []string{"wrong-node", "superseded", "cancelled", "stopped", "preparing", "proposing", "materialize-failed", "valid", "recovering"} {
		t.Run(scenario, func(t *testing.T) {
			backend := &runtimeBackend{}
			d, session, proposal := dynamicFixture(t, backend)
			attempt := d.prepareInbound(session, proposal)
			if attempt == nil {
				t.Fatal("inbound preparation failed")
			}
			result := engine.Result{RemoteUID: session.RemoteUID, RemoteLoopbackV6: session.RemoteLoopbackV6}
			ctx, cancel := context.WithCancel(d.ctx)
			defer cancel()
			attempt.cancel = cancel
			switch scenario {
			case "wrong-node":
				result.RemoteUID.UUID = uuid.New()
			case "superseded":
				replacement := *attempt
				d.attempts[attempt.remote] = &replacement
			case "cancelled":
				cancel()
			case "stopped":
				d.stopped = true
			case "proposing":
				attempt.state = dynamicProposing
			case "preparing":
				attempt.state = dynamicPreparing
			case "recovering":
				attempt.state = dynamicRecovering
			case "materialize-failed":
				backend.materializeErr = errors.New("kernel failure")
			}
			var recovered bool
			d.runner.Log = func(event Event) {
				if event.Event == "velvet-dynamic-link" && event.Status == "recovered" {
					recovered = true
				}
			}
			err := d.commitLink(ctx, attempt, result)
			if scenario == "valid" || scenario == "recovering" {
				if recovered != (scenario == "recovering") {
					t.Fatal("incorrect recovery notification")
				}
				if err != nil || attempt.state != dynamicUp || len(d.runner.states) != 1 || backend.materialized != 1 {
					t.Fatalf("valid commit: err=%v state=%v calls=%d", err, attempt.state, backend.materialized)
				}
				return
			}
			if err == nil || attempt.state == dynamicUp || len(d.runner.states) != 0 {
				t.Fatalf("invalid commit changed state: err=%v state=%v", err, attempt.state)
			}
			if scenario != "materialize-failed" && backend.materialized != 0 {
				t.Fatal("invalid commit reached kernel materialization")
			}
			if scenario == "wrong-node" || scenario == "materialize-failed" {
				if attempt.state != dynamicStopped || len(d.attempts) != 0 || len(backend.removed) != 1 || ctx.Err() == nil {
					t.Fatal("failed commit did not stop and clean the Attempt")
				}
				calls := backend.materialized
				if err := d.commitLink(d.ctx, attempt, result); err == nil || backend.materialized != calls || len(backend.removed) != 1 {
					t.Fatal("late commit restarted a failed Attempt")
				}
			} else if len(backend.removed) != 0 {
				t.Fatal("stale commit removed a current reservation")
			}
		})
	}
}

func TestDynamicDeclineThenWinningProposalReusesReservation(t *testing.T) {
	backend := &runtimeBackend{}
	d, session, proposal := dynamicFixture(t, backend)
	old, err := d.prepareOutbound(session)
	if err != nil || old == nil || old.candidate.Port() != 53000 {
		t.Fatalf("outbound: %v, %v", old, err)
	}
	d.handleDecline(session, message.Message{OperationID: old.operationID})
	next := d.prepareInbound(session, proposal)
	if next == nil || backend.prepared != 1 || next.plan.ListenPort != old.plan.ListenPort || next.candidate.Port() != uint16(old.plan.ListenPort) {
		t.Fatalf("reservation was replaced: next=%v prepares=%d", next, backend.prepared)
	}
	if len(d.pendingCleanups) != 0 || len(backend.removed) != 0 {
		t.Fatal("winning Proposal retained a stale cleanup")
	}
}

func TestDynamicAcceptedAttemptCannotBeSuperseded(t *testing.T) {
	d, session, proposal := dynamicFixture(t, &runtimeBackend{})
	old, err := d.prepareOutbound(session)
	if err != nil || old == nil {
		t.Fatal("outbound preparation failed")
	}
	old.state = dynamicAttempting
	if next := d.prepareInbound(session, proposal); next != nil || d.attempts[old.remote] != old {
		t.Fatal("a new Proposal superseded an already accepted Attempt")
	}
}

func TestDynamicOldDeadlineCannotCancelRecovery(t *testing.T) {
	d, session, proposal := dynamicFixture(t, &runtimeBackend{})
	attempt := d.prepareInbound(session, proposal)
	if attempt == nil {
		t.Fatal("inbound preparation failed")
	}
	ctx, cancel := context.WithCancel(d.ctx)
	defer cancel()
	attempt.cancel = cancel
	d.mu.Lock()
	d.armConnectivityDeadlineLocked(attempt, ctx)
	oldEpoch := attempt.deadlineEpoch
	d.commitAttemptLocked(attempt)
	attempt.state = dynamicRecovering
	d.armConnectivityDeadlineLocked(attempt, ctx)
	d.mu.Unlock()
	// Timer.Stop cannot retract a callback already waiting for the state lock.
	d.expireConnectivity(attempt, ctx, oldEpoch)
	if ctx.Err() != nil {
		t.Fatal("old establishment deadline cancelled a fresh recovery window")
	}
	d.expireConnectivity(attempt, ctx, attempt.deadlineEpoch)
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("current recovery deadline did not cancel connectivity")
	}
}

func TestDynamicInferenceFailureCleansReservation(t *testing.T) {
	for _, inbound := range []bool{false, true} {
		backend := &runtimeBackend{}
		d, session, proposal := dynamicFixture(t, backend)
		d.evidence = []inference.Evidence{{Link: "invalid"}}
		if inbound {
			if attempt := d.prepareInbound(session, proposal); attempt != nil {
				t.Fatal("accepted invalid inference")
			}
		} else if attempt, err := d.prepareOutbound(session); attempt != nil || err == nil {
			t.Fatal("proposed invalid inference")
		}
		if backend.prepared != 1 || len(backend.removed) != 1 || len(d.attempts) != 0 || backend.configured != 0 {
			t.Fatal("failed inference leaked or configured a reservation")
		}
	}
}

func TestDynamicCleanupSerializesInterfaceReuse(t *testing.T) {
	backend := &runtimeBackend{removeStarted: make(chan struct{}), removeRelease: make(chan struct{}), prepareCalled: make(chan struct{}, 2)}
	d, session, proposal := dynamicFixture(t, backend)
	old := d.prepareInbound(session, proposal)
	if old == nil {
		t.Fatal("inbound preparation failed")
	}
	<-backend.prepareCalled
	removed := make(chan struct{})
	go func() { d.failAttempt(old, "failure", dynamicAttempting); close(removed) }()
	<-backend.removeStarted
	prepared := make(chan *dynamicAttempt, 1)
	go func() { next := d.prepareInbound(session, proposal); prepared <- next }()
	select {
	case <-backend.prepareCalled:
		close(backend.removeRelease)
		t.Fatal("new reservation raced old interface deletion")
	case <-time.After(50 * time.Millisecond):
	}
	close(backend.removeRelease)
	<-removed
	if next := <-prepared; next == nil || d.attempts[session.RemoteUID.UUID] != next {
		t.Fatal("new reservation did not resume after cleanup")
	}
	backend.removeStarted = nil
}

func TestEndpointEvidenceUsesActualListenPort(t *testing.T) {
	backend := &runtimeBackend{listenPort: 55000}
	d, _, _ := dynamicFixture(t, backend)
	observed := netip.MustParseAddrPort("192.0.2.1:63000")
	if err := d.runner.recordEndpointEvidence(d.ctx, "vl-seed", observed); err != nil {
		t.Fatal(err)
	}
	if got := d.evidence[0]; got.LocalListenPort != 55000 || got.ObservedEndpoint != observed {
		t.Fatalf("incorrect kernel mapping: %#v", got)
	}
	backend.listenPortErr = errors.New("device disappeared")
	if err := d.runner.recordEndpointEvidence(d.ctx, "vl-seed", netip.MustParseAddrPort("192.0.2.2:63000")); err == nil || d.evidence[0].ObservedEndpoint != observed {
		t.Fatal("failed kernel read replaced valid Evidence")
	}
}

func TestDynamicStopWaitsForWorkersBeforeCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		backend := &runtimeBackend{}
		d, session, proposal := dynamicFixture(t, backend)
		if attempt := d.prepareInbound(session, proposal); attempt == nil {
			t.Fatal("inbound preparation failed")
		}
		release := make(chan struct{})
		workerExited := make(chan struct{})
		order := make(chan bool, 1)
		backend.onRemove = func() {
			select {
			case <-workerExited:
				order <- true
			default:
				order <- false
			}
		}
		d.workers.Go(func() { <-d.ctx.Done(); <-release; close(workerExited) })
		stopped := make(chan struct{})
		go func() { d.stop(); close(stopped) }()
		synctest.Wait()
		<-d.ctx.Done()
		select {
		case <-stopped:
			close(release)
			t.Fatal("stop returned before its worker exited")
		default:
		}
		close(release)
		<-stopped
		if len(backend.removed) != 1 || !<-order {
			t.Fatal("interface cleanup preceded worker exit or was omitted")
		}
		if attempt := d.prepareInbound(session, proposal); attempt != nil || backend.prepared != 1 {
			t.Fatal("stopped runtime prepared another Link")
		}
	})
}

func TestDynamicResponsesCannotAffectAnotherAttempt(t *testing.T) {
	for _, kind := range []message.Type{message.DynamicLinkAccept, message.DynamicLinkDecline} {
		for _, scenario := range []string{"wrong-session", "wrong-operation", "late-response"} {
			t.Run(fmt.Sprintf("%d/%s", kind, scenario), func(t *testing.T) {
				backend := &runtimeBackend{}
				d, session, proposal := dynamicFixture(t, backend)
				attempt, err := d.prepareOutbound(session)
				if err != nil || attempt == nil {
					t.Fatal("preparation failed")
				}
				response := proposal
				response.Type = kind
				response.OperationID = attempt.operationID
				responding := session
				switch scenario {
				case "wrong-session":
					copy := *session
					responding = &copy
				case "wrong-operation":
					response.OperationID[0] ^= 1
				case "late-response":
					d.failAttempt(attempt, "timeout", dynamicProposing)
				}
				removed := len(backend.removed)
				if err := d.handleRoutedMessage(responding, response); err != nil {
					t.Fatal(err)
				}
				if backend.configured != 0 || len(backend.removed) != removed || len(d.pendingCleanups) != 0 {
					t.Fatal("unmatched response changed resources")
				}
				if scenario != "late-response" && d.attempts[attempt.remote] != attempt {
					t.Fatal("unmatched response replaced active Attempt")
				}
			})
		}
	}
}

func TestDynamicConfigurationFailureCleansReservation(t *testing.T) {
	for _, inbound := range []bool{false, true} {
		t.Run(fmt.Sprintf("inbound=%v", inbound), func(t *testing.T) {
			backend := &runtimeBackend{configureErr: errors.New("kernel rejected configuration")}
			d, session, response := dynamicFixture(t, backend)
			if inbound {
				if attempt := d.prepareInbound(session, response); attempt != nil {
					t.Fatal("failed configuration was accepted")
				}
			} else {
				attempt, err := d.prepareOutbound(session)
				if err != nil || attempt == nil {
					t.Fatal("preparation failed")
				}
				response.Type = message.DynamicLinkAccept
				response.OperationID = attempt.operationID
				if err := d.handleAccept(session, response); err != nil {
					t.Fatal(err)
				}
			}
			if backend.configured != 1 || len(backend.removed) != 1 || len(d.attempts) != 0 || len(d.runner.states) != 0 {
				t.Fatal("configuration failure leaked state")
			}
		})
	}
}

func TestDynamicCandidateRemainsFrozenAfterEvidenceUpdate(t *testing.T) {
	d, session, _ := dynamicFixture(t, &runtimeBackend{})
	attempt, err := d.prepareOutbound(session)
	if err != nil || attempt == nil {
		t.Fatal("outbound preparation failed")
	}
	if err := d.setEvidence("vl-seed", 51000, netip.MustParseAddrPort("192.0.2.9:63000")); err != nil {
		t.Fatal(err)
	}
	proposal := dynamicLinkMessage(message.DynamicLinkPropose, attempt)
	if proposal.Endpoint != netip.MustParseAddrPort("192.0.2.1:53000") {
		t.Fatalf("store update changed the frozen Candidate: %v", proposal.Endpoint)
	}
}

// Exercise the real routed VFP callbacks and response timer. Only the kernel
// backend and the remote peer's decision are faked; no connectivity sockets are
// needed for these failures before an accepted Attempt starts connectivity.
func TestDynamicRoutedFailureRetainsPathWithoutRetry(t *testing.T) {
	for _, scenario := range []string{"timeout", "decline", "closed", "rejected-candidate"} {
		t.Run(scenario, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				backend := &runtimeBackend{}
				d, remote, response := dynamicFixture(t, backend)
				d.runner.Desired.LoopbackV6 = netip.MustParseAddr("fd00::1")
				d.runner.Desired.LoopbackPoolV6 = netip.MustParsePrefix("fd00::/64")
				seed := reconcile.LinkPlan{InterfaceName: "vl-seed", OwnerAlias: "seed"}
				d.runner.states[seed.InterfaceName] = materializedState{desired: seed}
				backend.reachable = []netip.Addr{remote.RemoteLoopbackV6}
				var proposed message.Message
				peer := engine.New(engine.Config{
					Context: engine.RoutedSession, LocalUID: remote.RemoteUID,
					LocalLoopbackV6: remote.RemoteLoopbackV6, LoopbackPoolV6: d.runner.Desired.LoopbackPoolV6,
					OperationalMessage: func(session *engine.Session, value message.Message) error {
						proposed = value
						switch scenario {
						case "decline":
							return session.Send(message.Message{Type: message.DynamicLinkDecline, OperationID: value.OperationID})
						case "closed":
							return session.Close()
						case "rejected-candidate":
							response.Type, response.OperationID = message.DynamicLinkAccept, value.OperationID
							response.Endpoint = netip.MustParseAddrPort("198.51.100.1:54000")
							return session.Send(response)
						}
						return nil
					},
				})
				localConn, remoteConn := net.Pipe()
				d.workers.Go(func() { d.serveRouted(d.ctx, localConn, remote.RemoteLoopbackV6) })
				d.workers.Go(func() { _ = peer.Run(d.ctx, remoteConn) })
				synctest.Wait()
				if proposed.Type != message.DynamicLinkPropose || proposed.Endpoint != netip.MustParseAddrPort("192.0.2.1:53000") {
					t.Fatalf("baseline Proposal did not reach routed peer: %#v", proposed)
				}
				// Also expire Decline's reservation reuse window.
				time.Sleep(2 * dynamicResponseTimeout)
				synctest.Wait()
				if len(d.attempts) != 0 || len(d.pendingCleanups) != 0 || len(backend.removed) != 1 || backend.configured != 0 {
					t.Fatal("routed failure did not clean its tentative Attempt")
				}
				if len(d.runner.states) != 1 || d.runner.states[seed.InterfaceName].desired.OwnerAlias != seed.OwnerAlias || len(d.evidence) != 1 || d.evidence[0].Link != seed.InterfaceName {
					t.Fatal("fallback removed the provisioned Link or its Evidence")
				}
				if err := d.setEvidence(seed.InterfaceName, 51000, netip.MustParseAddrPort("192.0.2.9:63000")); err != nil {
					t.Fatal(err)
				}
				d.scanLoopbacks(d.ctx)
				synctest.Wait()
				if backend.prepared != 1 || len(d.outboundSessions) != 0 || !d.targets[remote.RemoteLoopbackV6].attempted {
					t.Fatal("store update or discovery restarted the failed target")
				}
			})
		})
	}
}
