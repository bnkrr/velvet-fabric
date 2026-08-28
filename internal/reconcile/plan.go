package reconcile

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/link"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const LoopbackInterface = "vl-loop"

type Plan struct {
	UID                spec.NodeUID
	UUID               uuid.UUID
	FabricPSK          []byte
	LinkPoolV4         netip.Prefix
	LinkPoolV6         netip.Prefix
	LoopbackPoolV6     netip.Prefix
	LoopbackV6         netip.Addr
	VFPPort            int
	LoopbackOwnerAlias string
	Links              []LinkPlan
}

type LinkPlan struct {
	PeerName         string
	InterfaceName    string
	OwnerAlias       string
	PrivateKey       wgtypes.Key
	PeerPublicKey    wgtypes.Key
	PresharedKey     wgtypes.Key
	ListenPort       int
	Endpoints        []string
	Keepalive        time.Duration
	BootstrapAddress netip.Prefix
	BootstrapPeer    netip.Addr
	Dialer           bool
	LinkOverrides    []string
}

func BuildPlan(nodeSpec *spec.NodeSpec) (*Plan, error) {
	if err := nodeSpec.Validate(); err != nil {
		return nil, err
	}
	fabricPSK, err := spec.ParsePSK(nodeSpec.Fabric.PSK)
	if err != nil {
		return nil, err
	}
	link4, link6, loop6, err := spec.ParseFabricPrefixes(nodeSpec.Fabric)
	if err != nil {
		return nil, err
	}
	privateKey, err := spec.ParseKey(nodeSpec.Node.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse node private key: %w", err)
	}
	uid := nodeSpec.ParsedUUID()
	localLoop6, err := link.DeriveLoopbackV6(fabricPSK, uid, loop6, nodeSpec.Node.LoopbackAddressV6)
	if err != nil {
		return nil, fmt.Errorf("derive loopbacks: %w", err)
	}
	plan := &Plan{
		UID: nodeSpec.Node.UID, UUID: uid, FabricPSK: fabricPSK,
		LinkPoolV4: link4, LinkPoolV6: link6, LoopbackPoolV6: loop6,
		LoopbackV6: localLoop6, VFPPort: nodeSpec.Fabric.EffectiveVFPPort(),
		LoopbackOwnerAlias: "velvet:loopback:" + uid.String(),
	}
	ports := map[int]string{}
	for _, peer := range nodeSpec.Peers {
		peerKey, err := spec.ParseKey(peer.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("peer %q public key: %w", peer.Name, err)
		}
		bootstrap, err := link.DeriveBootstrap(fabricPSK, privateKey, peerKey, nodeSpec.Node.UID, peer)
		if err != nil {
			return nil, fmt.Errorf("peer %q: %w", peer.Name, err)
		}
		if other, exists := ports[bootstrap.ListenPort]; exists {
			return nil, fmt.Errorf("peer %q and peer %q use listen port %d; set a listen_port override", peer.Name, other, bootstrap.ListenPort)
		}
		ports[bootstrap.ListenPort] = peer.Name
		var keepalive time.Duration
		if peer.PersistentKeepaliveSeconds != nil {
			keepalive = time.Duration(*peer.PersistentKeepaliveSeconds) * time.Second
		}
		plan.Links = append(plan.Links, LinkPlan{
			PeerName: peer.Name, InterfaceName: bootstrap.InterfaceName,
			OwnerAlias: "velvet:link:" + uid.String() + ":" + peer.Name,
			PrivateKey: privateKey, PeerPublicKey: peerKey, PresharedKey: bootstrap.PresharedKey,
			ListenPort: bootstrap.ListenPort, Endpoints: append([]string(nil), peer.Endpoints...), Keepalive: keepalive,
			BootstrapAddress: bootstrap.LocalAddress, BootstrapPeer: bootstrap.PeerAddress, Dialer: bootstrap.Dialer,
			LinkOverrides: append([]string(nil), peer.LinkAddresses...),
		})
	}
	return plan, nil
}
