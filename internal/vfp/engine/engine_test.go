package engine

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/link"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
)

func TestTwoEndpointFSMConvergesThroughCounterproposal(t *testing.T) {
	aID := uuid.MustParse("10000000-0000-4000-8000-000000000001")
	bID := uuid.MustParse("20000000-0000-4000-8000-000000000002")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	aConn, bConn := net.Pipe()
	aResult, bResult := make(chan Result, 1), make(chan Result, 1)
	var bChecks atomic.Int32
	a := New(testConfig(aID, "a", netip.MustParseAddr("fd41::1"), func(_ message.UID, _ link.Proposal) bool { return true }, aResult))
	b := New(testConfig(bID, "b", netip.MustParseAddr("fd41::2"), func(_ message.UID, _ link.Proposal) bool { return bChecks.Add(1) > 1 }, bResult))
	errors := make(chan error, 2)
	go func() { errors <- a.Run(ctx, aConn) }()
	go func() { errors <- b.Run(ctx, bConn) }()
	var ar, br Result
	select {
	case ar = <-aResult:
	case <-time.After(2 * time.Second):
		t.Fatal("A did not establish")
	}
	select {
	case br = <-bResult:
	case <-time.After(2 * time.Second):
		t.Fatal("B did not establish")
	}
	if ar.Proposal != br.Proposal {
		t.Fatalf("endpoints committed different proposals: %#v %#v", ar.Proposal, br.Proposal)
	}
	if ar.RemoteUID.UUID != bID || br.RemoteUID.UUID != aID {
		t.Fatal("OPEN identities were not associated with the peer")
	}
	if ar.RemoteLoopbackV6 != netip.MustParseAddr("fd41::2") || br.RemoteLoopbackV6 != netip.MustParseAddr("fd41::1") {
		t.Fatal("NODE_STATE resources were not committed")
	}
	if bChecks.Load() < 2 {
		t.Fatal("counterproposal path was not exercised")
	}
	cancel()
	for range 2 {
		select {
		case <-errors:
		case <-time.After(time.Second):
			t.Fatal("engine did not stop")
		}
	}
}

func TestEstablishmentTimeoutInterruptsHungPeer(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	config := testConfig(
		uuid.MustParse("10000000-0000-4000-8000-000000000001"),
		"a",
		netip.MustParseAddr("fd41::1"),
		func(message.UID, link.Proposal) bool { return true },
		make(chan Result, 1),
	)
	config.EstablishmentTimeout = 20 * time.Millisecond
	started := time.Now()
	if err := New(config).Run(context.Background(), local); err == nil {
		t.Fatal("hung session did not time out")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("hung session took %s to stop", elapsed)
	}
}

func TestWriteLoopBoundsBlockedWrite(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	requests := make(chan writeRequest, 1)
	done := make(chan struct{})
	go func() {
		writeLoop(ctx, local, requests)
		close(done)
	}()
	result := make(chan error, 1)
	requests <- writeRequest{message: message.Message{Type: message.Open, UID: &message.UID{UUID: uuid.New()}}, done: result, timeout: 20 * time.Millisecond}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("blocked write unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked write did not respect its deadline")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("writer did not stop after a write error")
	}
}

func TestRoutedSessionCarriesDynamicOperation(t *testing.T) {
	aID := uuid.MustParse("10000000-0000-4000-8000-000000000001")
	bID := uuid.MustParse("20000000-0000-4000-8000-000000000002")
	aLoopback := netip.MustParseAddr("fd41::1")
	bLoopback := netip.MustParseAddr("fd41::2")
	operation := [16]byte{9, 8, 7}
	key := [32]byte{1}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	aConn, bConn := net.Pipe()
	declined := make(chan struct{}, 1)
	aConfig := Config{
		Context: RoutedSession, LocalUID: message.UID{UUID: aID, Name: "a"},
		LocalLoopbackV6: aLoopback, ExpectedRemoteLoopbackV6: bLoopback,
		LoopbackPoolV6: netip.MustParsePrefix("fd41::/48"),
		Operational: func(session *Session) error {
			return session.Send(message.Message{Type: message.DynamicLinkPropose, OperationID: operation, WGPublicKey: key, Endpoint: netip.MustParseAddrPort("192.0.2.1:51820")})
		},
		OperationalMessage: func(_ *Session, value message.Message) error {
			if value.Type == message.DynamicLinkDecline && value.OperationID == operation {
				declined <- struct{}{}
			}
			return nil
		},
	}
	bConfig := Config{
		Context: RoutedSession, LocalUID: message.UID{UUID: bID, Name: "b"}, LocalLoopbackV6: bLoopback,
		LoopbackPoolV6: netip.MustParsePrefix("fd41::/48"),
		OperationalMessage: func(session *Session, value message.Message) error {
			if value.Type != message.DynamicLinkPropose {
				t.Fatalf("unexpected routed message %v", value.Type)
			}
			return session.Send(message.Message{Type: message.DynamicLinkDecline, OperationID: value.OperationID})
		},
	}
	errors := make(chan error, 2)
	go func() { errors <- New(aConfig).Run(ctx, aConn) }()
	go func() { errors <- New(bConfig).Run(ctx, bConn) }()
	select {
	case <-declined:
	case <-time.After(time.Second):
		t.Fatal("dynamic decline was not delivered")
	}
	cancel()
	for range 2 {
		select {
		case <-errors:
		case <-time.After(time.Second):
			t.Fatal("routed engine did not stop")
		}
	}
}

func testConfig(id uuid.UUID, name string, v6 netip.Addr, accept func(message.UID, link.Proposal) bool, result chan<- Result) Config {
	return Config{
		LocalUID: message.UID{UUID: id, Name: name}, LocalLoopbackV6: v6,
		LinkPoolV4: netip.MustParsePrefix("10.40.0.0/16"), LinkPoolV6: netip.MustParsePrefix("fd40::/48"),
		LoopbackPoolV6: netip.MustParsePrefix("fd41::/48"),
		FabricPSK:      bytes.Repeat([]byte{3}, 32), Accept: accept,
		Commit: func(value Result) error { result <- value; return nil },
	}
}

func TestSessionIdentityGuards(t *testing.T) {
	for _, scenario := range []string{"self", "wrong-target", "outside-pool"} {
		t.Run(scenario, func(t *testing.T) {
			config := Config{Context: RoutedSession, LocalUID: message.UID{UUID: uuid.New()}, LocalLoopbackV6: netip.MustParseAddr("fd41::1"), ExpectedRemoteLoopbackV6: netip.MustParseAddr("fd41::2"), LoopbackPoolV6: netip.MustParsePrefix("fd41::/48")}
			state := &sessionFSM{config: config}
			remote := message.UID{UUID: uuid.New()}
			if scenario == "self" {
				remote = config.LocalUID
			}
			_, disposition, err := state.handle(message.Message{Type: message.Open, UID: &remote})
			if scenario == "self" {
				if err == nil || disposition != closeConnection || state.opened {
					t.Fatal("self connection accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			address := netip.MustParseAddr("fd41::3")
			want := closeConnection
			if scenario == "outside-pool" {
				address = netip.MustParseAddr("fd42::2")
				want = discardFrame
			}
			_, disposition, err = state.handle(message.Message{Type: message.NodeState, LoopbackV6: address})
			if err == nil || disposition != want || state.operational {
				t.Fatal("invalid remote entered operational state")
			}
			if scenario == "outside-pool" {
				_, _, err = state.handle(message.Message{Type: message.NodeState, LoopbackV6: config.ExpectedRemoteLoopbackV6})
				if err != nil || !state.operational {
					t.Fatal("valid correction did not establish session")
				}
			}
		})
	}
}

func TestOperationalSessionDiscardsBadFramesAndContinues(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	local, remote := net.Pipe()
	defer remote.Close()
	_ = remote.SetDeadline(time.Now().Add(2 * time.Second))
	received := make(chan message.Message, 1)
	var discarded atomic.Int32
	done := make(chan error, 1)
	config := Config{Context: RoutedSession, LocalUID: message.UID{UUID: uuid.New()}, LocalLoopbackV6: netip.MustParseAddr("fd41::1"), LoopbackPoolV6: netip.MustParsePrefix("fd41::/48"), FrameError: func(error) { discarded.Add(1) }, OperationalMessage: func(_ *Session, m message.Message) error { received <- m; return nil }}
	go func() { done <- New(config).Run(ctx, local) }()
	for _, reply := range []message.Message{
		{Type: message.Open, UID: &message.UID{UUID: uuid.New()}},
		{Type: message.NodeState, LoopbackV6: netip.MustParseAddr("fd41::2")},
	} {
		if _, err := message.Read(remote); err != nil {
			t.Fatal(err)
		}
		if err := message.Write(remote, reply); err != nil {
			t.Fatal(err)
		}
	}
	// Both an unknown message and a legal message in the wrong context are
	// frame errors, so neither may tear down the following valid operation.
	if _, err := remote.Write([]byte{1, 255, 0, 4}); err != nil {
		t.Fatal(err)
	}
	if err := message.Write(remote, message.Message{Type: message.EndpointObservation, Endpoint: netip.MustParseAddrPort("192.0.2.1:5000")}); err != nil {
		t.Fatal(err)
	}
	want := message.Message{Type: message.DynamicLinkDecline, OperationID: [16]byte{9}}
	if err := message.Write(remote, want); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if got.Type != want.Type || got.OperationID != want.OperationID || discarded.Load() != 2 {
			t.Fatalf("got %#v, discarded %d", got, discarded.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("valid frame lost after discarded frames")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("session did not stop")
	}
}
