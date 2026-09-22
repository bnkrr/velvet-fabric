package runtime

import (
	"cmp"
	"slices"

	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
)

type LinkStatus struct {
	Interface      string          `json:"interface"`
	Peer           string          `json:"peer"`
	Retention      string          `json:"retention"`
	Active         bool            `json:"active"`
	ListenPort     int             `json:"listen_port"`
	PortMode       string          `json:"port_mode"`
	PortRange      *spec.PortRange `json:"port_range,omitempty"`
	WaitingPort    bool            `json:"waiting_port,omitempty"`
	CleanupPending bool            `json:"cleanup_pending,omitempty"`
}

func (r *Runner) linkStatus(durable []DurableStatus) []LinkStatus {
	confirmed := map[string]bool{}
	for _, record := range durable {
		confirmed[record.Peer.UUID] = record.Confirmed
	}
	static := map[string]bool{}
	plans := map[string]reconcile.LinkPlan{}
	for _, plan := range r.Desired.Links {
		static[plan.InterfaceName] = true
		plans[plan.InterfaceName] = plan
	}
	cleanups := map[string]bool{}
	r.links.mu.Lock()
	for _, resource := range r.links.resources {
		plans[resource.plan.InterfaceName] = resource.plan
		cleanups[resource.plan.InterfaceName] = resource.cleanup
	}
	r.links.mu.Unlock()
	states := map[string]materializedState{}
	for _, state := range r.materializedStates() {
		states[state.desired.InterfaceName] = state
	}
	result := make([]LinkStatus, 0, len(plans))
	for name, plan := range plans {
		retention := "dynamic"
		if static[name] {
			retention = "static"
		} else if confirmed[plan.PeerName] {
			retention = "durable"
		}
		state := states[name]
		value := LinkStatus{Interface: name, Peer: plan.PeerName, Retention: retention, Active: state.active && state.desired.OwnerAlias == plan.OwnerAlias, ListenPort: plan.ListenPort, PortMode: "system", WaitingPort: plan.WaitingPort, CleanupPending: cleanups[name]}
		if plan.WaitingPort {
			value.ListenPort = 0
		}
		if plan.Ports.Port != 0 {
			value.PortMode = "fixed"
		} else if plan.Ports.Range.First != 0 {
			value.PortMode = "range"
			span := plan.Ports.Range
			value.PortRange = &span
		}
		result = append(result, value)
	}
	slices.SortFunc(result, func(a, b LinkStatus) int { return cmp.Compare(a.Interface, b.Interface) })
	return result
}
