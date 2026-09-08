package inference

import (
	"net/netip"
	"slices"
)

// Observation is an actual mapping sample. The collector supplies samples in
// send order after authenticating and correlating reports. Socket lifetimes and
// network changes are managed outside Infer; this is not a persistent store.
type Observation struct {
	Local  netip.AddrPort
	Remote netip.AddrPort
	Seen   netip.AddrPort
}

func usableEndpoint(ep netip.AddrPort) bool {
	return ep.IsValid() && ep.Port() != 0 && !ep.Addr().IsUnspecified() && !ep.Addr().IsMulticast()
}

func (o Observation) Valid() bool {
	return usableEndpoint(o.Local) && usableEndpoint(o.Remote) && usableEndpoint(o.Seen) &&
		o.Local.Addr().Is4() == o.Remote.Addr().Is4() && o.Local.Addr().Is4() == o.Seen.Addr().Is4()
}

// Store is owned by one engine. Re-delivering a sample is not new information.
// Distinct destinations observing the same mapping are distinct information.
type Store struct {
	observations []Observation
}

func (s *Store) Add(o Observation) bool {
	if !o.Valid() || slices.Contains(s.observations, o) {
		return false
	}
	s.observations = append(s.observations, o)
	return true
}

func (s *Store) Snapshot() []Observation { return slices.Clone(s.observations) }

// ForgetLocal invalidates samples when their socket is released. Historical
// prediction across resource lifetimes is deliberately not supported yet.
func (s *Store) ForgetLocal(local netip.AddrPort) {
	s.observations = slices.DeleteFunc(s.observations, func(o Observation) bool { return o.Local == local })
}

// Observer describes offered measurement endpoints, not inferred NAT behavior.
// A future coordinator must resolve and prepare these endpoints before sending.
type Observer struct {
	Bootstrap bool
	Endpoints []netip.AddrPort
}

type Measurement struct {
	Local  netip.AddrPort
	Remote netip.AddrPort
}

// MeasurementGroup is one observer branch. Steps are ordered and reuse sockets.
type MeasurementGroup struct {
	Bootstrap bool
	Steps     []Measurement
}

// EndpointRange is a compact, inclusive candidate set. Large sets are returned
// honestly; the engine, rather than Infer, decides whether to enumerate them.
type EndpointRange struct {
	Addr  netip.Addr
	First uint16
	Last  uint16
}

func (r EndpointRange) Count() int {
	if !r.Addr.IsValid() || r.First == 0 || r.Last < r.First {
		return 0
	}
	return int(r.Last) - int(r.First) + 1
}

type CandidateBatch struct {
	Basis  string
	Ranges []EndpointRange
}

type SurveyInput struct {
	Local     netip.AddrPort
	Target    netip.AddrPort
	PublicIPs []netip.Addr
	Observers []Observer
	BaseOnly  bool
}

type Prediction struct {
	Candidates []CandidateBatch
	Plan       []MeasurementGroup
}

// Infer derives candidates and an optional measurement plan from the current
// snapshot. There is no stage, filtering classification, clock, or network I/O.
// Models below are hypotheses, not proofs about every destination of a NAT.
func Infer(samples []Observation, input SurveyInput) Prediction {
	var out Prediction
	if !usableEndpoint(input.Local) || !usableEndpoint(input.Target) || input.Local.Addr().Is4() != input.Target.Addr().Is4() {
		return out
	}
	var relevant, current []Observation
	ips := []netip.Addr{}
	addIP := func(ip netip.Addr) {
		if ip.IsValid() && !ip.IsUnspecified() && !ip.IsMulticast() &&
			ip.Is4() == input.Local.Addr().Is4() && !slices.Contains(ips, ip) {
			ips = append(ips, ip)
		}
	}
	for _, ip := range input.PublicIPs {
		addIP(ip)
	}
	for _, o := range samples {
		if !o.Valid() || o.Local.Addr() != input.Local.Addr() {
			continue
		}
		relevant = append(relevant, o)
		addIP(o.Seen.Addr())
		if o.Local == input.Local {
			current = append(current, o)
		}
	}
	add := func(basis string, endpoints ...netip.AddrPort) {
		batch := CandidateBatch{Basis: basis}
		for _, ep := range endpoints {
			r := EndpointRange{Addr: ep.Addr(), First: ep.Port(), Last: ep.Port()}
			if usableEndpoint(ep) && !slices.Contains(batch.Ranges, r) {
				batch.Ranges = append(batch.Ranges, r)
			}
		}
		if len(batch.Ranges) > 0 {
			out.Candidates = append(out.Candidates, batch)
		}
	}
	baseline := func() {
		for _, ip := range ips {
			add("port-preservation-hypothesis", netip.AddrPortFrom(ip, input.Local.Port()))
		}
	}
	if input.BaseOnly {
		baseline()
		return out
	}

	// Prefer observations to this destination, then address-scoped observations.
	for _, o := range current {
		if o.Remote == input.Target {
			add("observed-target", o.Seen)
		}
	}
	for _, o := range current {
		if o.Remote.Addr() == input.Target.Addr() && o.Remote != input.Target {
			add("target-address-mapping-hypothesis", o.Seen)
		}
	}
	if len(current) > 0 {
		shared := current[0].Seen
		if all(current, func(o Observation) bool { return o.Seen == shared }) {
			// Even one sample offers a cheap reuse hypothesis. The plan seeks
			// distinct destinations rather than treating that sample as proof.
			add("shared-mapping-hypothesis", shared)
		}
	}
	if len(current) == 0 || all(current, func(o Observation) bool { return o.Seen.Port() == o.Local.Port() }) {
		baseline()
	}

	// A stable offset requires three distinct local ports sampled against one
	// destination. Cross-destination use remains a hypothesis tested by Try.
	byRemote := map[netip.AddrPort][]Observation{}
	var destinations []netip.AddrPort
	for _, o := range relevant {
		if _, ok := byRemote[o.Remote]; !ok {
			destinations = append(destinations, o.Remote)
		}
		byRemote[o.Remote] = append(byRemote[o.Remote], o)
	}
	for _, remote := range destinations {
		group := byRemote[remote]
		first := group[0]
		delta := int(first.Seen.Port()) - int(first.Local.Port())
		locals := map[netip.AddrPort]bool{}
		consistent := true
		for _, o := range group {
			locals[o.Local] = true
			consistent = consistent && o.Seen.Addr() == first.Seen.Addr() && int(o.Seen.Port())-int(o.Local.Port()) == delta
		}
		port := int(input.Local.Port()) + delta
		if consistent && len(locals) >= 3 && port > 0 && port <= 65535 {
			add("local-port-offset-hypothesis", netip.AddrPortFrom(first.Seen.Addr(), uint16(port)))
		}
	}

	// A small observed allocation stride supplies a bounded neighborhood, not
	// an exact next-port promise. Include recent ports: candidate attempts may
	// already have allocated an unobserved target mapping before this survey.
	for _, ip := range ips {
		var ports []uint16
		for _, o := range relevant {
			if o.Seen.Addr() == ip && !slices.Contains(ports, o.Seen.Port()) {
				ports = append(ports, o.Seen.Port())
			}
		}
		if len(ports) < 3 {
			continue
		}
		n := len(ports)
		d1, d2 := int(ports[n-1])-int(ports[n-2]), int(ports[n-2])-int(ports[n-3])
		if d1 > 0 && d1 <= 8 && d1 == d2 {
			low := max(1, int(ports[n-3])-4)
			high := min(65535, int(ports[n-1])+d1+4)
			out.Candidates = append(out.Candidates, CandidateBatch{
				Basis:  "allocation-sequence-hypothesis",
				Ranges: []EndpointRange{{Addr: ip, First: uint16(low), Last: uint16(high)}},
			})
		}
	}
	if len(out.Candidates) == 0 {
		for _, ip := range ips {
			out.Candidates = append(out.Candidates, CandidateBatch{
				Basis:  "unconstrained-port-space",
				Ranges: []EndpointRange{{Addr: ip, First: 1, Last: 65535}},
			})
		}
	}
	out.Plan = surveyPlan(relevant, input)
	return out
}

func all(samples []Observation, predicate func(Observation) bool) bool {
	for _, o := range samples {
		if !predicate(o) {
			return false
		}
	}
	return true
}

func surveyPlan(samples []Observation, input SurveyInput) []MeasurementGroup {
	observers := slices.Clone(input.Observers)
	slices.SortStableFunc(observers, func(a, b Observer) int {
		if a.Bootstrap == b.Bootstrap {
			return 0
		}
		if a.Bootstrap {
			return -1
		}
		return 1
	})
	// Keep the final socket plus two finite auxiliary sockets for port sampling.
	locals := []netip.AddrPort{input.Local}
	for offset := 1; offset <= 2; offset++ {
		port := int(input.Local.Port()) + offset
		if port > 65535 {
			port = int(input.Local.Port()) - offset
		}
		locals = append(locals, netip.AddrPortFrom(input.Local.Addr(), uint16(port)))
	}
	seen := map[Measurement]bool{}
	for _, o := range samples {
		seen[Measurement{Local: o.Local, Remote: o.Remote}] = true
	}
	var plan []MeasurementGroup
	for _, observer := range observers {
		group := MeasurementGroup{Bootstrap: observer.Bootstrap}
		// Endpoint offers are prepared outside Infer. Sampling at most two per
		// observer bounds one branch; the next observer can supply another IP.
		for _, local := range locals {
			for _, remote := range observer.Endpoints[:min(2, len(observer.Endpoints))] {
				step := Measurement{Local: local, Remote: remote}
				if usableEndpoint(remote) && local.Addr().Is4() == remote.Addr().Is4() && !seen[step] {
					group.Steps = append(group.Steps, step)
					seen[step] = true
				}
			}
		}
		if len(group.Steps) > 0 {
			plan = append(plan, group)
		}
	}
	return plan
}
