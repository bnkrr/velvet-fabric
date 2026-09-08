// Package linkdiscovery implements a bounded, transport-independent candidate
// search. Run is the centralized algorithm harness; RunPeer is the local
// engine integrated with velvetd through its VFP/UDP adapter.
package linkdiscovery

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/inference"
)

type Side uint8

const (
	A Side = iota
	B
)

type Probe struct {
	ID     uint64
	Side   Side
	Local  netip.AddrPort
	Remote netip.AddrPort
}

// Report represents an authenticated observation returned over the control
// path, not a UDP reply. The adapter must verify the observer and probe binding.
type Report struct {
	ID   uint64
	Seen netip.AddrPort
}

// Network owns actual sockets and observer preparation. Send does not wait for
// delivery, so both sides can punch during one overlapping execution window.
// Calls must honor ctx. Now/Wait also allow deterministic virtual-time tests.
// One Network observation namespace belongs to one Run; adapters must not
// deliver reports from a prior task that happens to reuse a numeric probe ID.
type Network interface {
	Open(context.Context, Side, netip.AddrPort) error
	Close(Side, netip.AddrPort) error
	Send(context.Context, Probe) error
	Reports(context.Context) ([]Report, error)
	Wait(context.Context, time.Duration) error
	Now() time.Time
}

type Peer struct {
	Local     netip.AddrPort
	Target    netip.AddrPort
	PublicIPs []netip.Addr
	Observers []inference.Observer
	Store     *inference.Store
}

type Limits struct {
	Timeout       time.Duration
	Interval      time.Duration
	Packets       int
	Measurements  int
	Candidates    int
	Pairs         int
	Repeats       int
	MaxIterations int
}

func DefaultLimits() Limits {
	return Limits{
		Timeout: 10 * time.Second, Interval: 10 * time.Millisecond,
		Packets: 12000, Measurements: 64, Candidates: 32, Pairs: 1024,
		Repeats: 3, MaxIterations: 16,
	}
}

type Stats struct {
	Iterations        int
	Packets           int
	Measurements      int
	NewObservations   int
	RejectedBatches   int
	BootstrapBranches int
	OtherBranches     int
}

// Path names the retained local sockets and matched observed public endpoints.
// Success is only underlay discovery; a caller still has to validate WG/VFP.
type Path struct {
	LocalA    netip.AddrPort
	LocalB    netip.AddrPort
	EndpointA netip.AddrPort
	EndpointB netip.AddrPort
}

type Result struct {
	Path   *Path
	Reason string
	Stats  Stats
}

type socket struct {
	side  Side
	local netip.AddrPort
}

type engine struct {
	network  Network
	peers    [2]Peer
	limits   Limits
	until    time.Time
	stats    Stats
	nextID   uint64
	opened   []socket
	tried    map[[2]netip.AddrPort]bool
	measured [2]map[inference.Measurement]bool
}

var errBudget = errors.New("discovery budget exhausted")

// Run retains the primary sockets on success and releases every acquired socket
// on failure. Auxiliary observations are invalidated when their sockets close.
func Run(ctx context.Context, network Network, a, b Peer, limits Limits) (result Result, err error) {
	if network == nil || a.Store == nil || b.Store == nil || a.Store == b.Store ||
		!validEndpoint(a.Local) || !validEndpoint(b.Local) || !validEndpoint(a.Target) || !validEndpoint(b.Target) ||
		a.Local.Addr().Is4() != b.Local.Addr().Is4() ||
		a.Local.Addr().Is4() != a.Target.Addr().Is4() || b.Local.Addr().Is4() != b.Target.Addr().Is4() ||
		limits.Timeout <= 0 || limits.Interval <= 0 || limits.Packets <= 0 || limits.Measurements <= 0 ||
		limits.Candidates <= 0 || limits.Pairs <= 0 || limits.Repeats <= 0 || limits.MaxIterations <= 0 {
		return result, errors.New("invalid discovery configuration")
	}
	ctx, cancel := context.WithTimeout(ctx, limits.Timeout)
	defer cancel()
	e := engine{
		network: network, peers: [2]Peer{a, b}, limits: limits, until: network.Now().Add(limits.Timeout),
		tried: map[[2]netip.AddrPort]bool{}, measured: [2]map[inference.Measurement]bool{{}, {}},
	}
	defer func() {
		for _, resource := range e.opened {
			if result.Path != nil && resource.local == e.peers[resource.side].Local {
				continue
			}
			err = errors.Join(err, network.Close(resource.side, resource.local))
			e.peers[resource.side].Store.ForgetLocal(resource.local)
		}
		result.Stats = e.stats
	}()
	for side := A; side <= B; side++ {
		if err = e.open(ctx, side, e.peers[side].Local); err != nil {
			result.Reason = "resource-error"
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				result.Reason = "cancelled"
			}
			return
		}
	}
	for e.stats.Iterations < limits.MaxIterations {
		if err = e.check(ctx); err != nil {
			break
		}
		e.stats.Iterations++
		before := e.stats.NewObservations
		var predictions [2]inference.Prediction
		var candidates [2][]netip.AddrPort
		for side := A; side <= B; side++ {
			peer := e.peers[side]
			predictions[side] = inference.Infer(peer.Store.Snapshot(), inference.SurveyInput{
				Local: peer.Local, Target: peer.Target, PublicIPs: peer.PublicIPs, Observers: peer.Observers,
			})
			candidates[side] = e.selectCandidates(predictions[side])
		}
		var observations [2][]inference.Observation
		observations, err = e.try(ctx, candidates)
		e.ingest(observations)
		if err != nil {
			break
		}
		if path := matchedPath(observations, e.peers); path != nil {
			result.Path, result.Reason = path, "connected"
			return result, nil
		}
		if e.stats.NewObservations > before {
			continue // Re-evaluate instead of executing a stale survey plan.
		}
		for side := A; side <= B; side++ {
			err = e.observe(ctx, side, predictions[side].Plan)
			if err != nil {
				break
			}
		}
		if err != nil {
			break
		}
		if e.stats.NewObservations == before {
			result.Reason = "no-progress"
			return result, nil
		}
	}
	result.Reason = "budget-exhausted"
	if errors.Is(err, errBudget) {
		err = nil
	} else if err != nil {
		result.Reason = "execution-error"
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			result.Reason = "cancelled"
		}
	}
	return
}

func validEndpoint(ep netip.AddrPort) bool {
	return ep.IsValid() && ep.Port() != 0 && !ep.Addr().IsUnspecified() && !ep.Addr().IsMulticast()
}

func (e *engine) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !e.network.Now().Before(e.until) || e.stats.Packets >= e.limits.Packets {
		return errBudget
	}
	return nil
}

func (e *engine) open(ctx context.Context, side Side, local netip.AddrPort) error {
	if err := e.check(ctx); err != nil {
		return err
	}
	resource := socket{side, local}
	for _, existing := range e.opened {
		if existing == resource {
			return nil
		}
	}
	if err := e.network.Open(ctx, side, local); err != nil {
		return err
	}
	e.opened = append(e.opened, resource)
	return nil
}

func (e *engine) selectCandidates(prediction inference.Prediction) []netip.AddrPort {
	var selected []netip.AddrPort
	seen := map[netip.AddrPort]bool{}
	for _, batch := range prediction.Candidates {
		count := 0
		for _, r := range batch.Ranges {
			count += r.Count()
			if count > e.limits.Candidates {
				break
			}
		}
		if count > e.limits.Candidates {
			e.stats.RejectedBatches++
			continue
		}
		for _, r := range batch.Ranges {
			if r.Count() == 0 {
				continue
			}
			for port := int(r.First); port <= int(r.Last); port++ {
				ep := netip.AddrPortFrom(r.Addr, uint16(port))
				if !seen[ep] && len(selected) < e.limits.Candidates {
					selected = append(selected, ep)
					seen[ep] = true
				}
			}
		}
	}
	return selected
}

func (e *engine) try(ctx context.Context, candidates [2][]netip.AddrPort) ([2][]inference.Observation, error) {
	var probes []Probe
	sends := [2]map[netip.AddrPort]bool{{}, {}}
	add := func(side Side, remote netip.AddrPort) {
		if !sends[side][remote] {
			probes = append(probes, Probe{Side: side, Local: e.peers[side].Local, Remote: remote})
			sends[side][remote] = true
		}
	}
	pairs := 0
	for _, a := range candidates[A] {
		for _, b := range candidates[B] {
			key := [2]netip.AddrPort{a, b}
			if e.tried[key] || pairs >= e.limits.Pairs {
				continue
			}
			e.tried[key] = true
			pairs++
			// The same outbound destination may occur in many candidate pairs;
			// its NAT mapping does not depend on our guessed public source port.
			add(A, b)
			add(B, a)
		}
	}
	return e.window(ctx, probes)
}

func (e *engine) observe(ctx context.Context, side Side, groups []inference.MeasurementGroup) error {
	for _, group := range groups {
		before := e.stats.NewObservations
		entered := false
		for _, step := range group.Steps {
			if e.measured[side][step] {
				continue
			}
			if e.stats.Measurements >= e.limits.Measurements {
				return errBudget
			}
			if !entered {
				entered = true
				if group.Bootstrap {
					e.stats.BootstrapBranches++
				} else {
					e.stats.OtherBranches++
				}
			}
			e.measured[side][step] = true
			e.stats.Measurements++
			if err := e.open(ctx, side, step.Local); err != nil {
				return err
			}
			observations, err := e.window(ctx, []Probe{{Side: side, Local: step.Local, Remote: step.Remote}})
			e.ingest(observations)
			if err != nil {
				return err
			}
		}
		if e.stats.NewObservations > before {
			return nil // Let Infer use this branch before paying for more observers.
		}
	}
	return nil
}

// window collects reports and normalizes them into send order before ingest.
// Unknown, duplicate, invalid and late reports cannot invent new observations.
func (e *engine) window(ctx context.Context, templates []Probe) (out [2][]inference.Observation, err error) {
	sent := map[uint64]Probe{}
	reports := map[uint64]netip.AddrPort{}
	defer func() {
		ids := make([]uint64, 0, len(reports))
		for id := range reports {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, id := range ids {
			probe := sent[id]
			out[probe.Side] = append(out[probe.Side], inference.Observation{Local: probe.Local, Remote: probe.Remote, Seen: reports[id]})
		}
	}()
	if len(templates) == 0 {
		return
	}
	for repeat := 0; repeat < e.limits.Repeats; repeat++ {
		for _, probe := range templates {
			if err = e.check(ctx); err != nil {
				return
			}
			e.nextID++
			probe.ID = e.nextID
			sent[probe.ID] = probe
			e.stats.Packets++
			if err = e.network.Send(ctx, probe); err != nil {
				return
			}
		}
		if err = e.network.Wait(ctx, min(e.limits.Interval, max(0, e.until.Sub(e.network.Now())))); err != nil {
			return
		}
		if !e.network.Now().Before(e.until) {
			err = errBudget
			return
		}
		var received []Report
		received, err = e.network.Reports(ctx)
		if err != nil {
			return
		}
		for _, report := range received {
			probe, known := sent[report.ID]
			observation := inference.Observation{Local: probe.Local, Remote: probe.Remote, Seen: report.Seen}
			if known && observation.Valid() {
				if _, duplicate := reports[report.ID]; !duplicate {
					reports[report.ID] = report.Seen
				}
			}
		}
	}
	return
}

func (e *engine) ingest(observations [2][]inference.Observation) {
	for side := A; side <= B; side++ {
		for _, o := range observations[side] {
			if e.peers[side].Store.Add(o) {
				e.stats.NewObservations++
			}
		}
	}
}

func matchedPath(observations [2][]inference.Observation, peers [2]Peer) *Path {
	for _, a := range observations[A] {
		if a.Local != peers[A].Local {
			continue
		}
		for _, b := range observations[B] {
			if b.Local == peers[B].Local && a.Remote == b.Seen && b.Remote == a.Seen {
				return &Path{LocalA: a.Local, LocalB: b.Local, EndpointA: a.Seen, EndpointB: b.Seen}
			}
		}
	}
	return nil
}
