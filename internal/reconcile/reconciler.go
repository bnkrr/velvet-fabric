package reconcile

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/velvet-fabric/velvet-fabric/internal/link"
)

type Backend interface {
	Reconcile(context.Context, *DesiredState) error
	Verify(context.Context, *DesiredState) error
	ProposalAvailable(context.Context, LinkPlan, link.Proposal, []netip.Prefix) bool
	Materialize(context.Context, *DesiredState, LinkPlan, []netip.Prefix, []netip.Addr) error
}

type Reconciler struct{ backend Backend }

func New(backend Backend) *Reconciler { return &Reconciler{backend: backend} }

func (r *Reconciler) Reconcile(ctx context.Context, desired *DesiredState) error {
	if err := r.backend.Reconcile(ctx, desired); err != nil {
		return fmt.Errorf("reconcile kernel state: %w", err)
	}
	if err := r.backend.Verify(ctx, desired); err != nil {
		return fmt.Errorf("verify reconciled kernel state: %w", err)
	}
	return nil
}

func (r *Reconciler) ProposalAvailable(ctx context.Context, desired LinkPlan, proposal link.Proposal, local []netip.Prefix) bool {
	return r.backend.ProposalAvailable(ctx, desired, proposal, local)
}

func (r *Reconciler) Materialize(ctx context.Context, state *DesiredState, desired LinkPlan, local []netip.Prefix, peers []netip.Addr) error {
	return r.backend.Materialize(ctx, state, desired, local, peers)
}
