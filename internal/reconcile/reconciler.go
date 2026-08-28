package reconcile

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/velvet-fabric/velvet-fabric/internal/link"
)

type Backend interface {
	ApplyBootstrap(context.Context, *Plan) error
	VerifyBootstrap(context.Context, *Plan) error
	ProposalAvailable(context.Context, LinkPlan, link.Proposal, []netip.Prefix) bool
	Materialize(context.Context, LinkPlan, []netip.Prefix, []netip.Addr) error
}

type Reconciler struct{ backend Backend }

func New(backend Backend) *Reconciler { return &Reconciler{backend: backend} }
func (r *Reconciler) Bootstrap(ctx context.Context, plan *Plan) error {
	if err := r.backend.ApplyBootstrap(ctx, plan); err != nil {
		return fmt.Errorf("apply bootstrap kernel plan: %w", err)
	}
	if err := r.backend.VerifyBootstrap(ctx, plan); err != nil {
		return fmt.Errorf("verify bootstrap kernel plan: %w", err)
	}
	return nil
}
func (r *Reconciler) MaintainBootstrap(ctx context.Context, plan *Plan) error {
	if err := r.backend.VerifyBootstrap(ctx, plan); err == nil {
		return nil
	}
	return r.Bootstrap(ctx, plan)
}
func (r *Reconciler) ProposalAvailable(ctx context.Context, desired LinkPlan, proposal link.Proposal, local []netip.Prefix) bool {
	return r.backend.ProposalAvailable(ctx, desired, proposal, local)
}
func (r *Reconciler) Materialize(ctx context.Context, desired LinkPlan, local []netip.Prefix, peers []netip.Addr) error {
	return r.backend.Materialize(ctx, desired, local, peers)
}
