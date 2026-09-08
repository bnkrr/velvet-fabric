package linkdiscovery

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/inference"
)

// Reuse the independent NAT ground truth with the actual per-node RunPeer
// entry point. Each engine sees only its own reports and exchanged candidates.
// This tests distributed orchestration; real VFP/UDP remains a netns concern.
type peerNATWorld struct {
	mu           sync.Mutex
	model        *simNetwork
	next         uint64
	observations [2]map[uint16][]inference.Observation
	arrivals     [2]map[uint16][]Arrival
}
type peerNATAdapter struct {
	distributedFixture
	world    *peerNATWorld
	side     Side
	peer     Peer
	measured map[inference.Measurement]bool
}

func (n *peerNATAdapter) send(ctx context.Context, round uint16, p inference.Measurement) (*inference.Observation, error) {
	w := n.world
	w.mu.Lock()
	defer w.mu.Unlock()
	w.next++
	before := len(w.model.queue)
	err := w.model.Send(ctx, Probe{ID: w.next, Side: n.side, Local: p.Local, Remote: p.Remote})
	if err != nil {
		return nil, err
	}
	if len(w.model.queue) == before {
		return nil, nil
	}
	report := w.model.queue[before]
	w.model.queue = nil
	o := inference.Observation{Local: p.Local, Remote: p.Remote, Seen: report.Seen}
	if round != 0 {
		w.observations[n.side][round] = append(w.observations[n.side][round], o)
		if b := w.model.nodes[1-n.side].byPublic[p.Remote]; b != nil && b.local.Port() == 51000 {
			w.arrivals[1-n.side][round] = append(w.arrivals[1-n.side][round], Arrival{Destination: p.Remote, Source: report.Seen})
		}
	}
	return &o, nil
}
func (n *peerNATAdapter) Try(ctx context.Context, round uint16, candidates []netip.AddrPort) ([]inference.Observation, []Arrival, error) {
	for range 3 {
		for _, remote := range candidates {
			if _, err := n.send(ctx, round, inference.Measurement{Local: n.peer.Local, Remote: remote}); err != nil {
				return nil, nil, err
			}
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
	n.world.mu.Lock()
	defer n.world.mu.Unlock()
	return append([]inference.Observation(nil), n.world.observations[n.side][round]...), append([]Arrival(nil), n.world.arrivals[n.side][round]...), nil
}
func (n *peerNATAdapter) Observe(ctx context.Context, input inference.SurveyInput, samples []inference.Observation) ([]inference.Observation, error) {
	for _, group := range inference.Infer(samples, input).Plan {
		var out []inference.Observation
		for _, step := range group.Steps {
			if n.measured[step] {
				continue
			}
			n.measured[step] = true
			n.world.mu.Lock()
			err := n.world.model.Open(ctx, n.side, step.Local)
			n.world.mu.Unlock()
			if err != nil {
				return nil, err
			}
			o, err := n.send(ctx, 0, step)
			if err != nil {
				return nil, err
			}
			if o != nil {
				out = append(out, *o)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	return nil, nil
}
func TestPeerMappingFilteringMatrix(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, seeded := range []bool{false, true} {
			name := "fresh-store"
			if seeded {
				name = "existing-evidence"
			}
			t.Run(fmt.Sprintf("ipv6=%t/%s", ipv6, name), func(t *testing.T) { testPeerMappingFilteringMatrix(t, seeded, ipv6) })
		}
	}
}

func testPeerMappingFilteringMatrix(t *testing.T, seeded, ipv6 bool) {
	connected := 0
	for _, am := range []mappingKind{eim, adm, apdm} {
		for _, bm := range []mappingKind{eim, adm, apdm} {
			for _, af := range []filteringKind{eif, adf, apdf} {
				for _, bf := range []filteringKind{eif, adf, apdf} {
					t.Run(fmt.Sprintf("%s-%s/%s-%s", am, af, bm, bf), func(t *testing.T) {
						synctest.Test(t, func(t *testing.T) {
							model, a, b := newSimulation(am, bm, af, bf, sequential, sequential)
							if ipv6 {
								a, b = peerSimulationIPv6(model, a, b)
							}
							if seeded {
								model.seed(A, a, a.Local)
								model.seed(B, b, b.Local)
							} else {
								// Match daemon startup: passive public IP hints, but
								// no observations for these new primary sockets.
								a.PublicIPs = []netip.Addr{model.nodes[A].publicIP}
								b.PublicIPs = []netip.Addr{model.nodes[B].publicIP}
								for side, peer := range []Peer{a, b} {
									if err := model.Open(context.Background(), Side(side), peer.Local); err != nil {
										t.Fatal(err)
									}
								}
							}
							results := runPeerSimulation(t, model, a, b)
							success := results[0].Endpoint.IsValid()
							if success {
								connected++
							} else if am != apdm || bm != apdm {
								t.Fatalf("distributed loop regressed supported sequential case: %#v", results)
							}
						})
					})
				}
			}
		}
	}
	t.Logf("RunPeer: 81 mapping/filter pairs, %d connected, %d bounded fallback", connected, 81-connected)
}

func runPeerSimulation(t *testing.T, model *simNetwork, a, b Peer) [2]PeerResult {
	t.Helper()
	w := &peerNATWorld{model: model, observations: [2]map[uint16][]inference.Observation{{}, {}}, arrivals: [2]map[uint16][]Arrival{{}, {}}}
	ab, ba := make(chan testControl, 1), make(chan testControl, 1)
	adapters := [2]*peerNATAdapter{{distributedFixture: distributedFixture{in: ba, out: ab}, world: w, side: A, peer: a, measured: map[inference.Measurement]bool{}}, {distributedFixture: distributedFixture{in: ab, out: ba}, world: w, side: B, peer: b, measured: map[inference.Measurement]bool{}}}
	var results [2]PeerResult
	var errs [2]error
	var wg sync.WaitGroup
	for i, n := range adapters {
		wg.Go(func() { results[i], errs[i] = RunPeer(context.Background(), n, n.peer, DefaultLimits()) })
	}
	wg.Wait()
	for i, r := range results {
		if errs[i] != nil || r.Rounds > 16 || len(adapters[i].measured) > 64 {
			t.Fatalf("peer budget/error: %#v %v", r, errs[i])
		}
	}
	success := results[0].Endpoint.IsValid()
	if success != results[1].Endpoint.IsValid() {
		t.Fatalf("disagreed outcome: %#v", results)
	}
	if success {
		if results[0].Seen != results[1].Endpoint || results[1].Seen != results[0].Endpoint {
			t.Fatal("disagreed endpoint pair")
		}
		for side := A; side <= B; side++ {
			r := results[side]
			mapping := model.nodes[side].outbound(r.Local, r.Endpoint)
			if mapping.public != r.Seen || !model.nodes[side].accepts(mapping, r.Endpoint) {
				t.Fatalf("false success: %#v", r)
			}
		}
	}
	return results
}

// Convert all topology inputs, including observer listeners, before creating
// any mappings. The same independent NAT semantics then exercise IPv6 paths.
func peerSimulationIPv6(model *simNetwork, a, b Peer) (Peer, Peer) {
	peers := []*Peer{&a, &b}
	model.listeners = map[netip.AddrPort]bool{}
	for side, peer := range peers {
		model.nodes[side].ip = netip.MustParseAddr(fmt.Sprintf("fd42:77:%d::2", side+1))
		model.nodes[side].publicIP = netip.MustParseAddr(fmt.Sprintf("2001:db8:77::%d", side+11))
		peer.Local = netip.AddrPortFrom(model.nodes[side].ip, 51000)
		peer.Observers = []inference.Observer{
			{Bootstrap: true, Endpoints: []netip.AddrPort{ep("[2001:db8:77::1]:40000"), ep("[2001:db8:77::1]:40001")}},
			{Endpoints: []netip.AddrPort{ep("[2001:db8:77::2]:40000"), ep("[2001:db8:77::2]:40001")}},
		}
		for _, o := range peer.Observers {
			for _, remote := range o.Endpoints {
				model.listeners[remote] = true
			}
		}
	}
	a.Target = netip.AddrPortFrom(model.nodes[B].publicIP, 51000)
	b.Target = netip.AddrPortFrom(model.nodes[A].publicIP, 51000)
	return a, b
}

func TestPeerSinglePublicMappingFilteringMatrix(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, publicSide := range []Side{A, B} {
			for _, mapping := range []mappingKind{eim, adm, apdm} {
				for _, filter := range []filteringKind{eif, adf, apdf} {
					for _, allocation := range []allocationKind{preserve, offset, sequential, random} {
						t.Run(fmt.Sprintf("ipv6=%t/public=%d/%s-%s-%s", ipv6, publicSide, mapping, filter, allocation), func(t *testing.T) {
							synctest.Test(t, func(t *testing.T) {
								model, a, b := newSimulation(mapping, mapping, filter, filter, allocation, allocation)
								if ipv6 {
									a, b = peerSimulationIPv6(model, a, b)
								}
								public := model.nodes[publicSide]
								public.mapping, public.filter, public.allocation = eim, eif, preserve
								public.ip = public.publicIP
								peers := []*Peer{&a, &b}
								peers[publicSide].Local = netip.AddrPortFrom(public.ip, 51000)
								for side, p := range peers {
									p.PublicIPs = []netip.Addr{model.nodes[side].publicIP}
									if err := model.Open(context.Background(), Side(side), p.Local); err != nil {
										t.Fatal(err)
									}
								}
								results := runPeerSimulation(t, model, a, b)
								if !results[0].Endpoint.IsValid() {
									t.Fatalf("single public peer must connect: %#v", results)
								}
							})
						})
					}
				}
			}
		}
	}
}
