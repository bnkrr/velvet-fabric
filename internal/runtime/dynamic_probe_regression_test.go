package runtime

import (
	"context"
	"encoding/binary"
	"github.com/velvet-fabric/velvet-fabric/internal/linkdiscovery"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/inference"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/probe"
)

type reportingProbeSocket struct {
	local netip.AddrPort
	send  func([]byte, netip.AddrPort)
}

func (s *reportingProbeSocket) Endpoint() netip.AddrPort               { return s.local }
func (s *reportingProbeSocket) Close() error                           { return nil }
func (s *reportingProbeSocket) Send(b []byte, ep netip.AddrPort) error { s.send(b, ep); return nil }

func TestMeasurementWaitsForDelayedFabricReport(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		local := netip.MustParseAddrPort("10.0.0.1:31000")
		remote := netip.MustParseAddrPort("192.0.2.3:52000")
		seen := netip.MustParseAddrPort("192.0.2.1:45000")
		o := &observerClient{id: [16]byte{1}, key: [32]byte{2}, inbox: make(chan message.Control, 10), done: make(chan struct{})}
		s := &reportingProbeSocket{local: local, send: func(b []byte, _ netip.AddrPort) {
			seq := binary.BigEndian.Uint64(b[28:36])
			go func() {
				select {
				case <-time.After(350 * time.Millisecond):
				case <-ctx.Done():
					return
				}
				o.inbox <- message.Control{Code: message.ProbeReport, Sequence: seq, Endpoints: []netip.AddrPort{seen}}
			}()
		}}
		u := &udpAttempt{}
		observations, err := u.measure(ctx, o, s, inference.Measurement{Local: local, Remote: remote})
		if err != nil || len(observations) == 0 {
			t.Fatalf("discarded a valid delayed report: samples=%v err=%v", observations, err)
		}
		for _, observation := range observations {
			if observation.Local != local || observation.Remote != remote || observation.Seen != seen {
				t.Fatal(observation)
			}
		}
	})
}

func TestProbeWindowWaitsForDelayedFabricReport(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		local := netip.MustParseAddrPort("10.0.0.1:31000")
		remote := netip.MustParseAddrPort("192.0.2.2:45000")
		seen := netip.MustParseAddrPort("192.0.2.1:45000")
		u := &udpAttempt{attempt: &dynamicAttempt{}, remoteKey: [32]byte{2}, inbox: make(chan message.Control, 10), arrivals: make(chan probe.Received, 10)}
		u.primary = &reportingProbeSocket{local: local, send: func(b []byte, _ netip.AddrPort) {
			seq := binary.BigEndian.Uint64(b[28:36])
			go func() {
				select {
				case <-time.After(650 * time.Millisecond):
				case <-ctx.Done():
					return
				}
				u.arrivals <- probe.Received{Round: 1, Destination: seen, Seen: remote}
				u.inbox <- message.Control{Code: message.ProbeReport, Round: 1, Sequence: seq, Endpoints: []netip.AddrPort{seen}}
			}()
		}}
		observations, arrivals, err := u.Try(ctx, 1, []netip.AddrPort{remote})
		if err != nil || len(observations) == 0 || len(arrivals) == 0 {
			t.Fatalf("window ended before control delivery: samples=%v arrivals=%v err=%v", observations, arrivals, err)
		}
	})
}

func TestDiscoveryControlIsBoundToCurrentOperation(t *testing.T) {
	for _, scenario := range []string{"current", "wrong-session", "wrong-operation", "committed", "overflow"} {
		t.Run(scenario, func(t *testing.T) {
			d, s, proposal := dynamicFixture(t, &runtimeBackend{})
			a := d.prepareInbound(s, proposal)
			if a == nil {
				t.Fatal("prepare")
			}
			c := message.Control{Code: message.Candidates, Round: 1, Changed: true}
			data, err := c.Encode()
			if err != nil {
				t.Fatal(err)
			}
			m := message.Message{Type: message.DiscoveryControl, OperationID: a.operationID, Data: data}
			switch scenario {
			case "wrong-session":
				copy := *s
				s = &copy
			case "wrong-operation":
				m.OperationID[0] ^= 1
			case "committed":
				a.state = dynamicUp
			case "overflow":
				for range cap(a.udp.inbox) {
					a.udp.inbox <- c
				}
			}
			if err = d.handleDiscoveryControl(s, m); err != nil {
				t.Fatal(err)
			}
			if scenario == "current" {
				if len(a.udp.inbox) != 1 {
					t.Fatal("valid operation lost control record")
				}
			} else if scenario == "overflow" {
				if a.udp.ctx.Err() == nil {
					t.Fatal("overflow did not cancel task")
				}
			} else if len(a.udp.inbox) != 0 || a.udp.ctx.Err() != nil {
				t.Fatal("stale control affected task")
			}
		})
	}
}

func TestProbeReportWaitDoesNotExtendTaskDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
		defer cancel()
		local := netip.MustParseAddrPort("10.0.0.1:31000")
		remote := netip.MustParseAddrPort("192.0.2.2:45000")
		u := &udpAttempt{attempt: &dynamicAttempt{}, remoteKey: [32]byte{2}, inbox: make(chan message.Control, 10), arrivals: make(chan probe.Received, 10)}
		u.primary = &reportingProbeSocket{local: local, send: func([]byte, netip.AddrPort) {}}
		start := time.Now()
		_, _, err := u.Try(ctx, 1, []netip.AddrPort{remote})
		if err != context.DeadlineExceeded || time.Since(start) != 600*time.Millisecond {
			t.Fatalf("task deadline extended: %v %v", time.Since(start), err)
		}
	})
}

func TestHandoffRequiresCurrentPeerWGReady(t *testing.T) {
	for _, cancelBeforeReady := range []bool{false, true} {
		t.Run(map[bool]string{false: "ready", true: "cancelled"}[cancelBeforeReady], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				backend := &runtimeBackend{}
				d, remote, proposal := dynamicFixture(t, backend)
				localConn, remoteConn := net.Pipe()
				ready := make(chan *engine.Session, 1)
				observed := make(chan struct{})
				release := make(chan struct{})
				localProtocol := engine.New(engine.Config{Context: engine.RoutedSession, LocalUID: message.UID{UUID: d.runner.Desired.UUID}, LocalLoopbackV6: netip.MustParseAddr("fd00::1"), LoopbackPoolV6: netip.MustParsePrefix("fd00::/64"), Operational: func(s *engine.Session) error { ready <- s; return nil }, OperationalMessage: d.handleRoutedMessage})
				remoteProtocol := engine.New(engine.Config{Context: engine.RoutedSession, LocalUID: remote.RemoteUID, LocalLoopbackV6: remote.RemoteLoopbackV6, LoopbackPoolV6: netip.MustParsePrefix("fd00::/64"), OperationalMessage: func(s *engine.Session, m message.Message) error {
					c, err := message.DecodeControl(m.Data)
					if err != nil {
						return err
					}
					if c.Code != message.WGReady {
						return nil
					}
					close(observed)
					select {
					case <-release:
					case <-d.ctx.Done():
						return d.ctx.Err()
					}
					return sendDiscovery(s, m.OperationID, message.Control{Code: message.WGReady})
				}})
				d.workers.Go(func() { _ = localProtocol.Run(d.ctx, localConn) })
				d.workers.Go(func() { _ = remoteProtocol.Run(d.ctx, remoteConn) })
				session := <-ready
				a := d.prepareInbound(session, proposal)
				if a == nil {
					t.Fatal("prepare")
				}
				backend.onConfigure = func(plan reconcile.LinkPlan) {
					if !plan.ReceiveOnly {
						d.cancel()
					}
				} // Prevent starting real discovery on the fake WG device.
				done := make(chan error, 1)
				go func() {
					done <- d.handoff(a, linkdiscovery.PeerResult{Local: a.udp.primary.Endpoint(), Endpoint: proposal.Endpoint})
				}()
				<-observed
				if len(backend.configuredPlans) != 1 || !backend.configuredPlans[0].ReceiveOnly || backend.configuredPlans[0].ListenPort != int(a.udp.primary.Endpoint().Port()) {
					t.Fatal("WG was enabled before peer readiness, or changed port")
				}
				if cancelBeforeReady {
					d.cancel()
				}
				close(release)
				err := <-done
				if cancelBeforeReady {
					if err == nil || len(backend.configuredPlans) != 1 {
						t.Fatal("cancelled readiness enabled WG")
					}
				} else {
					if err != nil || len(backend.configuredPlans) != 2 || backend.configuredPlans[1].ReceiveOnly {
						t.Fatalf("valid readiness did not enable WG: %v", err)
					}
				}
				if backend.materialized != 0 {
					t.Fatal("readiness committed before link-bound VFP verification")
				}
			})
		})
	}
}
