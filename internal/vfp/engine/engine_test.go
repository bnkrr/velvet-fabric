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

func testConfig(id uuid.UUID, name string, v6 netip.Addr, accept func(message.UID, link.Proposal) bool, result chan<- Result) Config {
	return Config{
		LocalUID: message.UID{UUID: id, Name: name}, LocalLoopbackV6: v6,
		LinkPoolV4: netip.MustParsePrefix("10.40.0.0/16"), LinkPoolV6: netip.MustParsePrefix("fd40::/48"),
		LoopbackPoolV6: netip.MustParsePrefix("fd41::/48"),
		FabricPSK:      bytes.Repeat([]byte{3}, 32), Accept: accept,
		Commit: func(value Result) error { result <- value; return nil },
	}
}
