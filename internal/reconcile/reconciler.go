package reconcile

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/velvet-fabric/velvet-fabric/internal/link"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Backend interface {
	Reconcile(context.Context, *DesiredState, bool) error
	Verify(context.Context, *DesiredState) error
	ProposalAvailable(context.Context, LinkPlan, link.Proposal, []netip.Prefix) bool
	Materialize(context.Context, *DesiredState, LinkPlan, []netip.Prefix, []netip.Addr) error
	PrepareDynamic(context.Context, LinkPlan) (LinkPlan, error)
	ConfigureDynamic(context.Context, LinkPlan) error
	RemoveDynamic(context.Context, LinkPlan) error
	ObservedEndpoint(context.Context, string) (netip.AddrPort, bool, error)
	ReachableLoopbacks(context.Context, int, netip.Prefix) ([]netip.Addr, error)
}

type Reconciler struct{ backend Backend }

func New(backend Backend) *Reconciler { return &Reconciler{backend: backend} }

func (r *Reconciler) Reconcile(ctx context.Context, desired *DesiredState) error {
	return r.reconcile(ctx, desired, false)
}

func (r *Reconciler) Maintain(ctx context.Context, desired *DesiredState) error {
	return r.reconcile(ctx, desired, true)
}

func (r *Reconciler) reconcile(ctx context.Context, desired *DesiredState, preserveRuntimeLinks bool) error {
	if err := r.backend.Reconcile(ctx, desired, preserveRuntimeLinks); err != nil {
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

func BuildDynamicLink(state *DesiredState, remote spec.NodeUID) LinkPlan {
	interfaceName := spec.DynamicInterfaceName(remote)
	return LinkPlan{
		PeerName: remote.UUID, InterfaceName: interfaceName,
		OwnerAlias:       "velvet:link:" + state.UUID.String() + ":dynamic:" + remote.UUID,
		PrivateKey:       state.PrivateKey,
		BootstrapAddress: link.DeriveLinkLocal(state.FabricPSK, state.UUID, interfaceName),
	}
}

func (r *Reconciler) PrepareDynamic(ctx context.Context, state *DesiredState, remote spec.NodeUID) (LinkPlan, error) {
	return r.backend.PrepareDynamic(ctx, BuildDynamicLink(state, remote))
}

func (r *Reconciler) ConfigureDynamic(ctx context.Context, state *DesiredState, plan LinkPlan, peerPublicKey wgtypes.Key, endpoint netip.AddrPort) (LinkPlan, error) {
	if peerPublicKey == plan.PrivateKey.PublicKey() {
		return LinkPlan{}, fmt.Errorf("dynamic peer WireGuard public key equals local public key")
	}
	psk, err := link.DeriveWGLinkPSK(state.FabricPSK, plan.PrivateKey.PublicKey(), peerPublicKey)
	if err != nil {
		return LinkPlan{}, err
	}
	plan.PeerPublicKey = peerPublicKey
	plan.PresharedKey = psk
	plan.Endpoints = []string{endpoint.String()}
	return plan, r.backend.ConfigureDynamic(ctx, plan)
}

func (r *Reconciler) RemoveDynamic(ctx context.Context, plan LinkPlan) error {
	return r.backend.RemoveDynamic(ctx, plan)
}

func (r *Reconciler) ObservedEndpoint(ctx context.Context, interfaceName string) (netip.AddrPort, bool, error) {
	return r.backend.ObservedEndpoint(ctx, interfaceName)
}

func (r *Reconciler) ReachableLoopbacks(ctx context.Context, state *DesiredState) ([]netip.Addr, error) {
	return r.backend.ReachableLoopbacks(ctx, state.FabricTableID, state.LoopbackPoolV6)
}
