package runtime

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestNewAgreementIDUsesUUIDv4(t *testing.T) {
	for range 32 {
		id, err := newAgreementID()
		if err != nil {
			t.Fatal(err)
		}
		value := uuid.UUID(id)
		if value == uuid.Nil || value.Version() != 4 || value.Variant() != uuid.RFC4122 {
			t.Fatalf("agreement ID is not UUIDv4: %s", value)
		}
	}
}

func TestDurableReadyContinuity(t *testing.T) {
	start := time.Now()
	c := &durableCheckState{}
	for elapsed := time.Duration(0); elapsed < durableFailureTimeout; elapsed += 10 * time.Second {
		now := start.Add(elapsed)
		c.readyUntil = now.Add(durableReadyFreshness) // A fresh TCP session does not reset failure.
		if c.failed(now, true, false) {
			t.Fatal("deleted before 30 minutes")
		}
	}
	if !c.failed(start.Add(durableFailureTimeout), true, false) {
		t.Fatal("continuous ready failure did not expire")
	}
	c.failed(start.Add(durableFailureTimeout+time.Minute), true, false)
	if !c.failedSince.IsZero() {
		t.Fatal("offline interval accumulated")
	}
	now := start.Add(time.Hour)
	c.readyUntil = now.Add(durableReadyFreshness)
	if c.failed(now, true, false) || !c.failedSince.Equal(now) {
		t.Fatal("recovery did not start from zero")
	}
	c.failed(now, true, true)
	if !c.failedSince.IsZero() {
		t.Fatal("healthy Link retained failure budget")
	}
	c.failed(now, true, false)
	c.failed(now, false, false)
	if !c.failedSince.IsZero() {
		t.Fatal("local not-ready retained failure budget")
	}
}

func TestDurableKernelResourceLossRetainsAgreement(t *testing.T) {
	for _, state := range []dynamicAttemptState{dynamicAttempting, dynamicRecovering, dynamicUp} {
		for _, ready := range []bool{false, true} {
			backend := &runtimeBackend{listenPort: 42000}
			if !ready {
				backend.listenPortErr = errors.New("interface removed externally")
			}
			peer := uuid.New()
			plan := reconcile.LinkPlan{InterfaceName: "auto", OwnerAlias: "incarnation-1", ListenPort: 42000}
			r := &Runner{Desired: &reconcile.DesiredState{}, Reconciler: reconcile.New(backend), states: map[string]materializedState{"auto": {desired: plan, remote: peer, active: true, dynamic: true}}}
			r.dynamic = newDynamicLinkEngine(r)
			r.dynamic.ctx = context.Background()
			a := &dynamicAttempt{remote: peer, plan: plan, state: state}
			r.dynamic.attempts[peer] = a
			r.durable = &durableManager{r: r, records: map[uuid.UUID]durableRecord{peer: {ID: [16]byte{1}, Confirmed: true}}}
			r.durable.retireUnavailable(context.Background(), peer)
			if _, exists := r.dynamic.attempts[peer]; exists != ready {
				t.Fatalf("state=%v ready=%v: incorrect resource retention", state, ready)
			}
			if r.durable.records[peer].ID != [16]byte{1} || !r.durable.records[peer].Confirmed {
				t.Fatal("kernel resource failure invalidated the agreement")
			}
			if !ready && (len(backend.removed) != 1 || len(r.states) != 0) {
				t.Fatal("dead incarnation left adjacency or cleanup responsibility behind")
			}
		}
	}
}

func TestDurableStorePreservesInvalidData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "durable.json")
	local, peer := uuid.New(), uuid.New()
	owner := durableOwner{UUID: local, PublicKey: wgtypes.Key{9}}
	record := durableRecord{ID: [16]byte{1}, Peer: message.UID{UUID: peer}, LastLoopback: netip.MustParseAddr("fd00::2"), PublicKey: wgtypes.Key{1}, LocalPort: 42000, FixedEndpoints: []message.FixedEndpoint{{UID: message.UID{UUID: local}, Endpoint: netip.MustParseAddrPort("192.0.2.1:42000")}}}
	if err := saveDurable(path, owner, map[uuid.UUID]durableRecord{peer: record}); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadDurable(path, owner)
	if err != nil || loaded[peer].LocalPort != 42000 {
		t.Fatalf("load: %v %#v", err, loaded)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"agreement_id": "01000000-0000-0000-0000-000000000000"`)) ||
		!bytes.Contains(data, []byte(`"public_key": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`)) ||
		!bytes.Contains(data, []byte(`"recovery_endpoint"`)) || bytes.Contains(data, []byte(`"binding"`)) {
		t.Fatalf("durable store is not canonical readable JSON:\n%s", data)
	}
	otherOwner := owner
	otherOwner.PublicKey = wgtypes.Key{8}
	if _, err := loadDurable(path, otherOwner); err == nil {
		t.Fatal("identity mismatch accepted")
	}
	uppercase := bytes.Replace(data, []byte(`"agreement_id": "01`), []byte(`"agreement_id": "AB`), 1)
	if err := os.WriteFile(path, uppercase, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDurable(path, owner); err == nil {
		t.Fatal("non-canonical agreement UUID accepted")
	}
	broken := []byte(`{"version":900,"owner":{}}`)
	if err := os.WriteFile(path, broken, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDurable(path, owner); err == nil {
		t.Fatal("unknown version accepted")
	}
	data, _ = os.ReadFile(path)
	if string(data) != string(broken) {
		t.Fatal("failed load overwrote store")
	}
}

func TestDurablePeerLoopbackIsMutableMetadata(t *testing.T) {
	local, peer := uuid.New(), uuid.New()
	owner := durableOwner{UUID: local, PublicKey: wgtypes.Key{9}}
	record := durableRecord{
		ID: [16]byte{1}, Peer: message.UID{UUID: peer, Name: "old"},
		LastLoopback: netip.MustParseAddr("fd00::2"), PublicKey: wgtypes.Key{2}, LocalPort: 42000,
		FixedEndpoints: []message.FixedEndpoint{{UID: message.UID{UUID: peer}, Endpoint: netip.MustParseAddrPort("192.0.2.2:42001")}},
		Confirmed:      true,
	}
	d := &durableManager{path: filepath.Join(t.TempDir(), "durable.json"), owner: owner, records: map[uuid.UUID]durableRecord{peer: record}, checks: map[uuid.UUID]*durableCheckState{}}
	if err := saveDurable(d.path, owner, d.records); err != nil {
		t.Fatal(err)
	}
	updated := message.UID{UUID: peer, Name: "new"}
	if err := d.refreshPeerMetadata(updated, record.PublicKey, netip.MustParseAddr("fd99::2")); err != nil {
		t.Fatal(err)
	}
	stored, err := loadDurable(d.path, owner)
	if err != nil {
		t.Fatal(err)
	}
	if got := stored[peer]; got.ID != record.ID || got.Peer != updated || got.LastLoopback != netip.MustParseAddr("fd99::2") || !got.Confirmed {
		t.Fatalf("metadata refresh changed agreement: %#v", got)
	}
}

func TestDurableSavedHandshakeBothTCPDirections(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, both := range []bool{false, true} {
			for _, storedState := range []string{"none", "partial", "confirmed"} {
				t.Run(map[bool]string{false: "forward", true: "reverse"}[reverse]+map[bool]string{false: "-one-fixed", true: "-both-fixed"}[both]+"-"+storedState, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					ids := []uuid.UUID{uuid.MustParse("10000000-0000-4000-8000-000000000001"), uuid.MustParse("20000000-0000-4000-8000-000000000002")}
					var runners [2]*Runner
					plans := [2]reconcile.LinkPlan{{InterfaceName: "auto-a", OwnerAlias: "a", PeerPublicKey: wgtypes.Key{2}}, {InterfaceName: "auto-b", OwnerAlias: "b", PeerPublicKey: wgtypes.Key{1}}}
					endpoints := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:42000"), netip.MustParseAddrPort("192.0.2.2:42001")}
					for i := range 2 {
						r := &Runner{Desired: &reconcile.DesiredState{UUID: ids[i], LoopbackV6: netip.MustParseAddr([]string{"fd00::1", "fd00::2"}[i]), LoopbackPoolV6: netip.MustParsePrefix("fd00::/64"), DynamicLinks: &reconcile.DynamicLinksPlan{Mode: spec.DynamicLinksActive}, Durable: spec.DurableSettings{SoftLimit: 1, Stable: time.Minute}}, PolicyStateDir: t.TempDir(), states: map[string]materializedState{plans[i].InterfaceName: {desired: plans[i], dynamic: true, active: true, remote: ids[1-i]}}}
						r.dynamic = newDynamicLinkEngine(r)
						r.dynamic.ctx = ctx
						if err := r.openDurable(); err != nil {
							t.Fatal(err)
						}
						r.durable.observations[plans[i].InterfaceName] = durableObservation{local: endpoints[i], remote: endpoints[1-i], port: int(endpoints[i].Port()), since: time.Now().Add(-time.Hour), seen: time.Now()}
						runners[i] = r
					}
					origin := 0
					if reverse {
						origin = 1
					}
					receiver := 1 - origin
					if !both {
						v := runners[receiver].durable.observations[plans[receiver].InterfaceName]
						v.since = time.Now()
						runners[receiver].durable.observations[plans[receiver].InterfaceName] = v
					}
					record := durableRecord{ID: [16]byte{4}, Peer: message.UID{UUID: ids[receiver]}, LastLoopback: runners[receiver].Desired.LoopbackV6, PublicKey: plans[origin].PeerPublicKey, LocalPort: int(endpoints[origin].Port()), FixedEndpoints: []message.FixedEndpoint{{UID: message.UID{UUID: ids[origin]}, Endpoint: endpoints[origin]}}}
					if storedState != "none" {
						old := durableRecord{ID: [16]byte{9}, Peer: message.UID{UUID: ids[origin]}, LastLoopback: runners[origin].Desired.LoopbackV6, PublicKey: plans[receiver].PeerPublicKey, LocalPort: int(endpoints[receiver].Port()), FixedEndpoints: record.FixedEndpoints, Confirmed: storedState == "confirmed"}
						if err := runners[receiver].durable.saveLocked(old); err != nil {
							t.Fatal(err)
						}
						runners[receiver].durable.checks[ids[origin]] = &durableCheckState{agreement: old.ID, failedSince: time.Now().Add(-time.Hour)}
					}
					op := &durableOperation{record: record, outgoing: true, until: time.Now().Add(time.Minute)}
					runners[origin].durable.operations[ids[receiver]] = op
					conns := [2]net.Conn{}
					conns[0], conns[1] = net.Pipe()
					done := make(chan error, 2)
					for i := range 2 {
						config := runners[i].linkProtocol(ctx, plans[i], i == origin, nil)
						if i == origin {
							config.FirstMessage = &message.Message{Type: message.DurablePropose, OperationID: record.ID, FixedEndpoints: record.FixedEndpoints, Flags: message.NoDurable}
							config.Operational = func(s *engine.Session) error { op.session = s; return nil }
						}
						go func() { done <- engine.New(config).Run(ctx, conns[i]) }()
					}
					for range 2 {
						if err := <-done; !errors.Is(err, errDurableComplete) {
							t.Fatalf("handshake: %v", err)
						}
					}
					if runners[0].durable.records[ids[1]].ID != runners[1].durable.records[ids[0]].ID {
						t.Fatal("peers finalized different agreements")
					}
					if storedState != "none" && runners[receiver].durable.checks[ids[origin]] != nil {
						t.Fatal("replacement kept the retired agreement's failure timer")
					}
					for i, r := range runners {
						stored, err := loadDurable(r.durable.path, r.durable.owner)
						if err != nil {
							t.Fatal(err)
						}
						if !stored[ids[1-i]].Confirmed {
							t.Fatal("peer confirmation did not persist")
						}
						want := 1
						if both {
							want = 2
						}
						if len(stored[ids[1-i]].FixedEndpoints) != want {
							t.Fatalf("fixed endpoints: %#v", stored)
						}
					}
				})
			}
		}
	}
}

func TestDurableInterruptedSaveAndConfirmation(t *testing.T) {
	for _, diskFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "lost-confirmation", true: "write-failure"}[diskFailure], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			local, peer := uuid.New(), uuid.New()
			plan := reconcile.LinkPlan{InterfaceName: "auto", OwnerAlias: "generation", PeerPublicKey: wgtypes.Key{2}}
			r := &Runner{Desired: &reconcile.DesiredState{UUID: local, LoopbackV6: netip.MustParseAddr("fd00::1"), LoopbackPoolV6: netip.MustParsePrefix("fd00::/64"), DynamicLinks: &reconcile.DynamicLinksPlan{Mode: spec.DynamicLinksActive}, Durable: spec.DurableSettings{SoftLimit: 2, Stable: time.Hour}}, PolicyStateDir: t.TempDir(), states: map[string]materializedState{"auto": {desired: plan, remote: peer, dynamic: true, active: true}}}
			r.dynamic = newDynamicLinkEngine(r)
			r.dynamic.ctx = ctx
			if err := r.openDurable(); err != nil {
				t.Fatal(err)
			}
			remoteEndpoint := netip.MustParseAddrPort("192.0.2.2:42001")
			r.durable.observations["auto"] = durableObservation{local: netip.MustParseAddrPort("192.0.2.1:42000"), remote: remoteEndpoint, port: 42000, since: time.Now(), seen: time.Now()}
			if diskFailure {
				obstruction := filepath.Join(t.TempDir(), "file")
				if err := os.WriteFile(obstruction, []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
				r.durable.path = filepath.Join(obstruction, "durable.json")
			}
			request := message.Message{Type: message.DurablePropose, OperationID: [16]byte{8}, FixedEndpoints: []message.FixedEndpoint{{UID: message.UID{UUID: peer}, Endpoint: remoteEndpoint}}}
			read := func(conn net.Conn) (message.Message, error) {
				frame, err := message.Read(conn)
				if err != nil {
					return message.Message{}, err
				}
				return message.Decode(frame)
			}
			for round := range 2 {
				server, client := net.Pipe()
				done := make(chan error, 1)
				go func() { done <- engine.New(r.linkProtocol(ctx, plan, false, nil)).Run(ctx, server) }()
				for _, value := range []message.Message{{Type: message.Open, UID: &message.UID{UUID: peer}}, {Type: message.NodeState, LoopbackV6: netip.MustParseAddr("fd00::2")}} {
					if _, err := read(client); err != nil {
						t.Fatal(err)
					}
					if err := message.Write(client, value); err != nil {
						t.Fatal(err)
					}
				}
				if err := message.Write(client, request); err != nil {
					t.Fatal(err)
				}
				reply, err := read(client)
				if diskFailure {
					if err == nil {
						t.Fatalf("write failure emitted success: %#v", reply)
					}
					client.Close()
					<-done
					if len(r.durable.records) != 0 {
						t.Fatal("failed save published in memory")
					}
					break
				}
				if err != nil || reply.Type != message.DurableSaved {
					t.Fatalf("expected persisted confirmation: %#v %v", reply, err)
				}
				if round == 1 {
					if err := message.Write(client, message.Message{Type: message.DurableSaved, OperationID: request.OperationID}); err != nil {
						t.Fatal(err)
					}
					if err := <-done; !errors.Is(err, errDurableComplete) {
						t.Fatal(err)
					}
					client.Close()
				} else {
					client.Close()
					<-done
				}
				stored, err := loadDurable(r.durable.path, r.durable.owner)
				if err != nil {
					t.Fatal(err)
				}
				if stored[peer].Confirmed != (round == 1) {
					t.Fatal("confirmed state ignored bilateral confirmation")
				}
			}
		})
	}
}

func TestDurableDeleteRejectsStaleConfirmation(t *testing.T) {
	ctx := context.Background()
	local, peer, other := uuid.New(), uuid.New(), uuid.New()
	plan := reconcile.LinkPlan{InterfaceName: "auto", OwnerAlias: "generation", PeerPublicKey: wgtypes.Key{2}}
	r := &Runner{Desired: &reconcile.DesiredState{UUID: local, DynamicLinks: &reconcile.DynamicLinksPlan{Mode: spec.DynamicLinksActive}, Durable: spec.DurableSettings{SoftLimit: 2, Stable: time.Minute}}, PolicyStateDir: t.TempDir(), states: map[string]materializedState{"auto": {desired: plan, remote: peer, dynamic: true, active: true}, "other": {remote: other}}}
	r.dynamic = newDynamicLinkEngine(r)
	r.dynamic.ctx = ctx
	if err := r.openDurable(); err != nil {
		t.Fatal(err)
	}
	d := r.durable
	record := durableRecord{ID: [16]byte{1}, Peer: message.UID{UUID: peer}, LocalPort: 42000, LastLoopback: netip.MustParseAddr("fd00::2"), PublicKey: wgtypes.Key{2}, FixedEndpoints: []message.FixedEndpoint{{UID: message.UID{UUID: peer}, Endpoint: netip.MustParseAddrPort("192.0.2.2:42001")}}}
	if err := d.saveLocked(record); err != nil {
		t.Fatal(err)
	}
	session := &engine.Session{RemoteUID: record.Peer}
	d.operations[peer] = &durableOperation{record: record, session: session, until: time.Now().Add(time.Minute)}
	d.observations["auto"] = durableObservation{since: time.Now().Add(-time.Hour)}
	d.observations["other"] = durableObservation{since: time.Now().Add(-time.Hour)}
	if err := r.DeleteDurable(peer.String()); err != nil {
		t.Fatal(err)
	}
	if d.has(peer) || d.operations[peer] != nil {
		t.Fatal("deleted agreement still current")
	}
	if _, ok := d.observations["auto"]; ok {
		t.Fatal("deleted peer kept its old stability")
	}
	if _, ok := d.observations["other"]; !ok {
		t.Fatal("unrelated peer lost stability")
	}
	if err := d.handleLink(plan, session, message.Message{Type: message.DurableSaved, OperationID: record.ID}); err == nil {
		t.Fatal("late confirmation resurrected agreement")
	}
	if !r.states["auto"].active {
		t.Fatal("deletion tore down healthy Dynamic Link")
	}
}

type observedRuntimeBackend struct {
	runtimeBackend
	endpoint netip.AddrPort
}

func (b *observedRuntimeBackend) ObservedEndpoint(context.Context, string) (netip.AddrPort, bool, error) {
	return b.endpoint, true, nil
}

func TestDurableFixedAndVariableEndpointChanges(t *testing.T) {
	for _, change := range []struct {
		name                                   string
		localFixed, moveLocal, invalid, static bool
	}{
		{"fixed-local", true, true, true, false}, {"variable-peer", true, false, false, false},
		{"fixed-peer", false, false, true, false}, {"variable-local", false, true, false, false},
		{"static-local", true, true, false, true}, {"static-peer", false, false, false, true},
	} {
		t.Run(change.name, func(t *testing.T) {
			local, peer := uuid.New(), uuid.New()
			ownEndpoint := netip.MustParseAddrPort("192.0.2.1:42000")
			peerEndpoint := netip.MustParseAddrPort("192.0.2.2:42001")
			backend := &observedRuntimeBackend{runtimeBackend: runtimeBackend{listenPort: 42000}, endpoint: peerEndpoint}
			plan := reconcile.LinkPlan{InterfaceName: "auto", OwnerAlias: "generation"}
			r := &Runner{Desired: &reconcile.DesiredState{UUID: local, DynamicLinks: &reconcile.DynamicLinksPlan{Mode: spec.DynamicLinksActive}, Durable: spec.DurableSettings{SoftLimit: 2, Stable: time.Minute}}, Reconciler: reconcile.New(backend), PolicyStateDir: t.TempDir(), states: map[string]materializedState{"auto": {desired: plan, remote: peer, dynamic: true, active: true}}}
			r.dynamic = newDynamicLinkEngine(r)
			r.dynamic.ctx = context.Background()
			if change.static {
				state := r.states["auto"]
				state.dynamic = false
				r.states["auto"] = state
			}
			if err := r.openDurable(); err != nil {
				t.Fatal(err)
			}
			fixed := message.FixedEndpoint{UID: message.UID{UUID: peer}, Endpoint: peerEndpoint}
			if change.localFixed {
				fixed = message.FixedEndpoint{UID: message.UID{UUID: local}, Endpoint: ownEndpoint}
			}
			record := durableRecord{ID: [16]byte{1}, Peer: message.UID{UUID: peer}, Confirmed: true, LocalPort: 42000, PublicKey: wgtypes.Key{2}, LastLoopback: netip.MustParseAddr("fd00::2"), FixedEndpoints: []message.FixedEndpoint{fixed}}
			if err := r.durable.saveLocked(record); err != nil {
				t.Fatal(err)
			}
			if change.moveLocal {
				ownEndpoint = netip.MustParseAddrPort("192.0.2.1:45000")
			} else {
				backend.endpoint = netip.MustParseAddrPort("192.0.2.3:42002")
			}
			if err := r.durable.observe(context.Background(), plan, ownEndpoint, netip.MustParseAddr("fe80::2"), time.Now()); err != nil {
				t.Fatal(err)
			}
			if r.durable.has(peer) == change.invalid {
				t.Fatal("fixed/variable endpoint rule violated")
			}
			if !r.states["auto"].active {
				t.Fatal("healthy Link torn down on retention change")
			}
		})
	}
}

func TestDurableStatusFreshnessAndGeneration(t *testing.T) {
	for _, kind := range []string{"ready", "not-ready", "old-query", "old-agreement", "replaced-check", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			now := time.Now()
			peer := uuid.New()
			record := durableRecord{ID: [16]byte{1}, Peer: message.UID{UUID: peer}}
			query := [16]byte{2}
			c := &durableCheckState{query: query, agreement: record.ID, readyUntil: now.Add(time.Second), failedSince: now.Add(-time.Minute)}
			d := &durableManager{records: map[uuid.UUID]durableRecord{peer: record}, checks: map[uuid.UUID]*durableCheckState{peer: c}}
			m := message.Message{Type: message.DurableStatus, OperationID: query, AgreementID: record.ID, Status: message.Ready}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "not-ready":
				m.Status = message.NotReady
			case "old-query":
				c.query = [16]byte{3}
			case "old-agreement":
				next := record
				next.ID = [16]byte{3}
				d.records[peer] = next
			case "replaced-check":
				d.checks[peer] = &durableCheckState{query: query, agreement: record.ID}
			case "canceled":
				cancel()
			}
			before := *c
			if err := d.acceptStatus(ctx, record, c, query, m, now); !errors.Is(err, errDurableComplete) {
				t.Fatalf("status: %v", err)
			}
			switch kind {
			case "ready":
				if c.readyUntil != now.Add(durableReadyFreshness) || c.failedSince != before.failedSince {
					t.Fatal("fresh response did not preserve continuous failure")
				}
			case "not-ready":
				if !c.readyUntil.IsZero() || !c.failedSince.IsZero() {
					t.Fatal("NOT_READY retained a failure interval")
				}
			default:
				if *c != before {
					t.Fatal("stale response changed check state")
				}
			}
		})
	}
}

func TestDurableStabilityRequiresFreshPreservedPort(t *testing.T) {
	now := time.Now()
	plan := reconcile.LinkPlan{InterfaceName: "auto"}
	d := &durableManager{r: &Runner{Desired: &reconcile.DesiredState{UUID: uuid.New(), Durable: spec.DurableSettings{Stable: 30 * time.Minute}}}, observations: map[string]durableObservation{}}
	for _, tc := range []struct {
		name      string
		age, last time.Duration
		port      int
		want      bool
	}{
		{"before-threshold", 30*time.Minute - time.Nanosecond, 0, 42000, false},
		{"at-threshold", 30 * time.Minute, 0, 42000, true},
		{"stale-pong", time.Hour, 30 * time.Second, 42000, false},
		{"translated-port", time.Hour, 0, 42001, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d.observations[plan.InterfaceName] = durableObservation{local: netip.MustParseAddrPort("192.0.2.1:42000"), port: tc.port, since: now.Add(-tc.age), seen: now.Add(-tc.last)}
			if _, got := d.eligibleLocked(plan, now); got != tc.want {
				t.Fatalf("eligible = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDurableSoftAdmissionAndReservations(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		full, reserved, noDurable bool
		want                      message.Type
	}{
		{"room", false, false, false, message.DurableSaved},
		{"full", true, false, false, message.DurableDecline},
		{"reservation-full", false, true, false, message.DurableDecline},
		{"first-durable-exception", true, false, true, message.DurableSaved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			local, peer, other := uuid.New(), uuid.New(), uuid.New()
			plan := reconcile.LinkPlan{InterfaceName: "auto", OwnerAlias: "generation", PeerPublicKey: wgtypes.Key{2}}
			r := &Runner{Desired: &reconcile.DesiredState{UUID: local, LoopbackV6: netip.MustParseAddr("fd00::1"), LoopbackPoolV6: netip.MustParsePrefix("fd00::/64"), DynamicLinks: &reconcile.DynamicLinksPlan{Mode: spec.DynamicLinksActive}, Durable: spec.DurableSettings{SoftLimit: 1, Stable: time.Hour}}, PolicyStateDir: t.TempDir(), states: map[string]materializedState{"auto": {desired: plan, remote: peer, active: true, dynamic: true}}}
			r.dynamic = newDynamicLinkEngine(r)
			if err := r.openDurable(); err != nil {
				t.Fatal(err)
			}
			if tc.full {
				r.durable.records[other] = durableRecord{Peer: message.UID{UUID: other}, Confirmed: true}
			}
			if tc.reserved {
				r.durable.operations[other] = &durableOperation{until: time.Now().Add(time.Minute)}
			}
			ep := netip.MustParseAddrPort("192.0.2.2:42001")
			r.durable.observations["auto"] = durableObservation{local: netip.MustParseAddrPort("192.0.2.1:42000"), remote: ep, port: 42000, since: time.Now(), seen: time.Now()}
			server, client := net.Pipe()
			done := make(chan error, 1)
			go func() { done <- engine.New(r.linkProtocol(ctx, plan, false, nil)).Run(ctx, server) }()
			defer func() { client.Close(); <-done }()
			for _, value := range []message.Message{{Type: message.Open, UID: &message.UID{UUID: peer}}, {Type: message.NodeState, LoopbackV6: netip.MustParseAddr("fd00::2")}} {
				if _, err := message.Read(client); err != nil {
					t.Fatal(err)
				}
				if err := message.Write(client, value); err != nil {
					t.Fatal(err)
				}
			}
			request := message.Message{Type: message.DurablePropose, OperationID: [16]byte{4}, FixedEndpoints: []message.FixedEndpoint{{UID: message.UID{UUID: peer}, Endpoint: ep}}}
			if tc.noDurable {
				request.Flags = message.NoDurable
			}
			if err := message.Write(client, request); err != nil {
				t.Fatal(err)
			}
			frame, err := message.Read(client)
			if err != nil {
				t.Fatal(err)
			}
			reply, err := message.Decode(frame)
			if err != nil || reply.Type != tc.want {
				t.Fatalf("reply = %#v, %v", reply, err)
			}
		})
	}
}

func TestDurableLocalStabilitySurvivesVariablePeerMovement(t *testing.T) {
	now := time.Now()
	plan := reconcile.LinkPlan{InterfaceName: "auto", OwnerAlias: "generation"}
	local, peer := uuid.New(), uuid.New()
	own := netip.MustParseAddrPort("192.0.2.1:42000")
	backend := &observedRuntimeBackend{runtimeBackend: runtimeBackend{listenPort: 42000}, endpoint: netip.MustParseAddrPort("192.0.2.99:49000")}
	r := &Runner{Desired: &reconcile.DesiredState{UUID: local, Durable: spec.DurableSettings{Stable: 30 * time.Minute}}, Reconciler: reconcile.New(backend), states: map[string]materializedState{"auto": {desired: plan, remote: peer, active: true, dynamic: true}}}
	d := &durableManager{r: r, records: map[uuid.UUID]durableRecord{}, observations: map[string]durableObservation{"auto": {local: own, remote: netip.MustParseAddrPort("192.0.2.2:45000"), port: 42000, since: now.Add(-time.Hour), seen: now.Add(-10 * time.Second)}}}
	if err := d.observe(context.Background(), plan, own, netip.MustParseAddr("fe80::2"), now); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.eligibleLocked(plan, now); !ok {
		t.Fatal("variable peer movement reset local stability")
	}
	own = netip.MustParseAddrPort("192.0.2.3:42000")
	if err := d.observe(context.Background(), plan, own, netip.MustParseAddr("fe80::2"), now); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.eligibleLocked(plan, now); ok {
		t.Fatal("changed local endpoint inherited old stability")
	}
}

func TestDurableStorageFailureStages(t *testing.T) {
	owner := durableOwner{UUID: uuid.New(), PublicKey: wgtypes.Key{9}}
	oldOwner := owner
	oldOwner.PublicKey = wgtypes.Key{8}
	for _, stage := range []string{"write", "file-sync", "rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "durable.json")
			if err := saveDurable(path, oldOwner, nil); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected " + stage)
			var reached bool
			ops := durableStoreIO{(*os.File).Write, (*os.File).Sync, os.Rename}
			switch stage {
			case "write":
				ops.write = func(f *os.File, data []byte) (int, error) {
					reached = true
					// A partial write must not become the replacement record.
					n, _ := f.Write(data[:len(data)/2])
					return n, injected
				}
			case "rename":
				ops.rename = func(string, string) error { reached = true; return injected }
			default:
				ops.sync = func(f *os.File) error {
					info, err := f.Stat()
					if err != nil {
						return err
					}
					if info.IsDir() == (stage == "directory-sync") {
						reached = true
						return injected
					}
					return f.Sync()
				}
			}
			if err := saveDurableWithIO(path, owner, nil, ops); !errors.Is(err, injected) || !reached {
				t.Fatalf("fault not propagated: %v, reached=%v", err, reached)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if stage != "directory-sync" && string(after) != string(before) {
				t.Fatal("failed replacement damaged previous state")
			}
			if stage == "directory-sync" && string(after) == string(before) {
				t.Fatal("test did not reach post-rename durability boundary")
			}
			leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".durable-*"))
			if err != nil || len(leftovers) != 0 {
				t.Fatalf("temporary files leaked: %v, %v", leftovers, err)
			}
			if err := saveDurable(path, owner, nil); err != nil {
				t.Fatalf("retry did not converge: %v", err)
			}
		})
	}
}
