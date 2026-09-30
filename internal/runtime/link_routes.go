package runtime

import (
	"context"
	"net/netip"
	"slices"

	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
)

// Each adjacency keeps its own subnet routes. The peer loopback fallback has
// only one kernel slot, so elect one output across all committed Links. Use the
// interface name rather than map iteration order, including during recommit and
// warm adoption. Control-session loss does not revoke an existing candidate.
func (r *Runner) materializeLink(ctx context.Context, plan reconcile.LinkPlan, local []netip.Prefix, peers []netip.Addr) error {
	selected := make([]netip.Addr, 0, len(peers))
	r.mu.RLock()
	for _, peer := range peers {
		owner := plan.InterfaceName
		for name, state := range r.states {
			if name < owner && state.committed && slices.Contains(state.peers, peer) {
				owner = name
			}
		}
		if owner == plan.InterfaceName {
			selected = append(selected, peer)
		}
	}
	r.mu.RUnlock()
	return r.Reconciler.Materialize(ctx, r.Desired, plan, local, selected)
}
