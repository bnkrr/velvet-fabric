package linkdiscovery

import (
	"context"
	"errors"
	"net/netip"
	"slices"

	"github.com/velvet-fabric/velvet-fabric/internal/inference"
)

// Arrival is a probe received on our primary socket. Destination is the public
// endpoint to which the peer actually sent; Source is observed locally.
type Arrival struct{ Destination, Source netip.AddrPort }
type Batch struct {
	Endpoints []netip.AddrPort
	Changed   bool
}

// PeerNetwork adapts one node, never accesses the other node's evidence store.
// Exchange/Agree publish before waiting. Try sends both nodes' windows without
// requiring a UDP reply. Observe resolves finite observer offers and executes
// Infer's resulting ordered plan; it must not upgrade an observer recursively.
type PeerNetwork interface {
	Exchange(context.Context, uint16, Batch) (Batch, error)
	Try(context.Context, uint16, []netip.AddrPort) ([]inference.Observation, []Arrival, error)
	Agree(context.Context, uint16, []netip.AddrPort) ([]netip.AddrPort, error)
	Observe(context.Context, inference.SurveyInput, []inference.Observation) ([]inference.Observation, error)
}

type PeerResult struct {
	Local, Endpoint, Seen netip.AddrPort
	Rounds, Observations  int
	Reason                string
}

func CandidatesFor(prediction inference.Prediction, limit int) []netip.AddrPort {
	e := engine{limits: Limits{Candidates: limit}}
	return e.selectCandidates(prediction)
}

// RunPeer owns the infer/execute loop. New peer evidence permits a round even
// when our own store is unchanged. Neither side can keep it alive by waiting.
func RunPeer(ctx context.Context, n PeerNetwork, p Peer, limits Limits) (out PeerResult, err error) {
	if n == nil || p.Store == nil || !validEndpoint(p.Local) || !validEndpoint(p.Target) || limits.MaxIterations < 1 || limits.MaxIterations > 16 || limits.Timeout <= 0 || limits.Candidates < 1 || limits.Candidates > 32 {
		return out, errors.New("invalid peer discovery configuration")
	}
	ctx, cancel := context.WithTimeout(ctx, limits.Timeout)
	defer cancel()
	input := inference.SurveyInput{Local: p.Local, Target: p.Target, PublicIPs: p.PublicIPs, Observers: p.Observers}
	changed := true
	for round := uint16(1); int(round) <= limits.MaxIterations; round++ {
		out.Rounds = int(round)
		prediction := inference.Infer(p.Store.Snapshot(), input)
		batch, err := n.Exchange(ctx, round, Batch{Endpoints: CandidatesFor(prediction, limits.Candidates), Changed: changed})
		if err != nil {
			return out, err
		}
		if len(batch.Endpoints) > limits.Candidates {
			return out, errors.New("peer candidate budget exceeded")
		}
		if !changed && !batch.Changed {
			out.Reason = "no-progress"
			return out, nil
		}
		before := len(p.Store.Snapshot())
		observations, arrivals, err := n.Try(ctx, round, batch.Endpoints)
		if err != nil {
			return out, err
		}
		for _, o := range observations {
			if p.Store.Add(o) {
				out.Observations++
			}
		}
		path := reciprocal(observations, arrivals, p.Local)
		other, err := n.Agree(ctx, round, path)
		if err != nil {
			return out, err
		}
		if len(path) == 2 && len(other) == 2 && path[0] == other[1] && path[1] == other[0] {
			out.Local = p.Local
			out.Seen = path[0]
			out.Endpoint = path[1]
			out.Reason = "connected"
			return out, nil
		}
		if len(p.Store.Snapshot()) == before {
			observations, err = n.Observe(ctx, input, p.Store.Snapshot())
			if err != nil {
				return out, err
			}
			for _, o := range observations {
				if p.Store.Add(o) {
					out.Observations++
				}
			}
		}
		changed = len(p.Store.Snapshot()) > before
	}
	out.Reason = "budget-exhausted"
	return out, nil
}
func reciprocal(observations []inference.Observation, arrivals []Arrival, local netip.AddrPort) []netip.AddrPort {
	var paths [][2]netip.AddrPort
	for _, o := range observations {
		if o.Local != local {
			continue
		}
		for _, a := range arrivals {
			if o.Seen == a.Destination && o.Remote == a.Source {
				paths = append(paths, [2]netip.AddrPort{o.Seen, o.Remote})
			}
		}
	}
	// Symmetric ordering: both sides choose the same pair even with reordered input.
	key := func(p [2]netip.AddrPort) string {
		a, b := p[0].String(), p[1].String()
		if a > b {
			a, b = b, a
		}
		return a + "/" + b
	}
	slices.SortFunc(paths, func(a, b [2]netip.AddrPort) int {
		ka, kb := key(a), key(b)
		if ka < kb {
			return -1
		}
		if ka > kb {
			return 1
		}
		return 0
	})
	if len(paths) == 0 {
		return nil
	}
	return paths[0][:]
}
