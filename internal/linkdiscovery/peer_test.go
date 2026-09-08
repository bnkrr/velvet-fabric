package linkdiscovery

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/inference"
)

type testControl struct {
	round uint16
	batch Batch
	path  []netip.AddrPort
}
type distributedFixture struct {
	in, out               chan testControl
	local, public, remote netip.AddrPort
	upgrade, loss         bool
	rounds                int
}

func (f *distributedFixture) exchange(ctx context.Context, v testControl) (testControl, error) {
	select {
	case f.out <- v:
	case <-ctx.Done():
		return testControl{}, ctx.Err()
	}
	select {
	case other := <-f.in:
		if other.round != v.round {
			return other, errors.New("wrong round")
		}
		return other, nil
	case <-ctx.Done():
		return testControl{}, ctx.Err()
	}
}
func (f *distributedFixture) Exchange(ctx context.Context, r uint16, b Batch) (Batch, error) {
	f.rounds++
	c, err := f.exchange(ctx, testControl{round: r, batch: b})
	return c.batch, err
}
func (f *distributedFixture) Agree(ctx context.Context, r uint16, p []netip.AddrPort) ([]netip.AddrPort, error) {
	c, err := f.exchange(ctx, testControl{round: r, path: p})
	return c.path, err
}
func (f *distributedFixture) Try(ctx context.Context, r uint16, eps []netip.AddrPort) ([]inference.Observation, []Arrival, error) {
	if f.loss || r == 1 {
		return nil, nil, nil
	}
	var obs []inference.Observation
	for _, ep := range eps {
		if ep == f.remote {
			obs = append(obs, inference.Observation{Local: f.local, Remote: ep, Seen: f.public})
		}
	}
	return obs, []Arrival{{Destination: f.public, Source: f.remote}}, nil
}
func (f *distributedFixture) Observe(ctx context.Context, _ inference.SurveyInput, _ []inference.Observation) ([]inference.Observation, error) {
	if !f.upgrade {
		return nil, nil
	}
	f.upgrade = false
	// The peer must wait for our bounded active measurement, even though its
	// own store is unchanged. This is a control-path delay, not simulated UDP.
	select {
	case <-time.After(2 * time.Second):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return []inference.Observation{{Local: f.local, Remote: netip.MustParseAddrPort("192.0.2.3:55555"), Seen: f.public}}, nil
}
func TestIndependentPeerEngines(t *testing.T) {
	for _, loss := range []bool{false, true} {
		t.Run(map[bool]string{false: "one-sided-upgrade", true: "no-progress"}[loss], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ab, ba := make(chan testControl, 1), make(chan testControl, 1)
				aLocal := netip.MustParseAddrPort("10.0.0.1:53000")
				aPublic := netip.MustParseAddrPort("192.0.2.1:45000")
				b := netip.MustParseAddrPort("192.0.2.2:54000")
				fixtures := [2]*distributedFixture{{in: ba, out: ab, local: aLocal, public: aPublic, remote: b, upgrade: true, loss: loss}, {in: ab, out: ba, local: b, public: b, remote: aPublic, loss: loss}}
				var results [2]PeerResult
				var errs [2]error
				var wg sync.WaitGroup
				for i, f := range fixtures {
					wg.Go(func() {
						results[i], errs[i] = RunPeer(context.Background(), f, Peer{Local: f.local, Target: f.remote, PublicIPs: []netip.Addr{f.public.Addr()}, Store: &inference.Store{}}, DefaultLimits())
					})
				}
				wg.Wait()
				for i := range results {
					if errs[i] != nil {
						t.Fatal(errs[i])
					}
					if loss {
						if results[i].Reason != "no-progress" || results[i].Rounds != 3 {
							t.Fatalf("unbounded loop: %#v", results[i])
						}
					} else if results[i].Reason != "connected" || results[i].Rounds != 2 {
						t.Fatalf("peer update did not advance: %#v", results[i])
					}
				}
			})
		})
	}
}
func TestPeerControlLossCancels(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &distributedFixture{in: make(chan testControl), out: make(chan testControl, 1)}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := f.Exchange(ctx, 1, Batch{})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	})
}
