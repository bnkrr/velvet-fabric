package reconcile

import (
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/link"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const LoopbackInterface = "vl-loop"

type RouteType uint8

const (
	RouteViaPeer RouteType = iota + 1
	RouteThrow
	RouteUnreachable
)

type DesiredState struct {
	UID                spec.NodeUID
	UUID               uuid.UUID
	FabricPSK          []byte
	LinkPoolV4         netip.Prefix
	LinkPoolV6         netip.Prefix
	LoopbackPoolV6     netip.Prefix
	LoopbackV6         netip.Addr
	VFPPort            int
	FabricTableID      int
	LoopbackOwnerAlias string
	Forwarding         bool
	Links              []LinkPlan
	Routes             []RoutePlan
	Rules              []RulePlan
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
	Keepalive        *time.Duration
	BootstrapAddress netip.Prefix
	LinkOverrides    []string
}

type RoutePlan struct {
	TableID       int
	Prefix        netip.Prefix
	Type          RouteType
	PeerName      string
	InterfaceName string
	Metric        *uint32
}

type RulePlan struct {
	TableID     int
	Priority    int
	Source      netip.Prefix
	Destination netip.Prefix
}

func BuildDesiredState(nodeSpec *spec.NodeSpec) (*DesiredState, error) {
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
	desired := &DesiredState{
		UID: nodeSpec.Node.UID, UUID: uid, FabricPSK: fabricPSK,
		LinkPoolV4: link4, LinkPoolV6: link6, LoopbackPoolV6: loop6,
		LoopbackV6: localLoop6, VFPPort: nodeSpec.Fabric.EffectiveVFPPort(),
		FabricTableID:      nodeSpec.Fabric.EffectiveRoutingTableID(),
		LoopbackOwnerAlias: "velvet:loopback:" + uid.String(),
		Forwarding:         len(nodeSpec.Routes) > 0 || len(nodeSpec.Domains) > 0,
	}
	ports := map[int]string{}
	links := make(map[string]LinkPlan, len(nodeSpec.Peers))
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
		var keepalive *time.Duration
		if peer.PersistentKeepaliveSeconds != nil {
			value := time.Duration(*peer.PersistentKeepaliveSeconds) * time.Second
			keepalive = &value
		}
		item := LinkPlan{
			PeerName: peer.Name, InterfaceName: bootstrap.InterfaceName,
			OwnerAlias: "velvet:link:" + uid.String() + ":" + peer.Name,
			PrivateKey: privateKey, PeerPublicKey: peerKey, PresharedKey: bootstrap.PresharedKey,
			ListenPort: bootstrap.ListenPort, Endpoints: append([]string(nil), peer.Endpoints...), Keepalive: keepalive,
			BootstrapAddress: bootstrap.LocalAddress,
			LinkOverrides:    append([]string(nil), peer.LinkAddresses...),
		}
		desired.Links = append(desired.Links, item)
		links[peer.Name] = item
	}
	if err := compileRouting(desired, nodeSpec, links); err != nil {
		return nil, err
	}
	return desired, nil
}

func compileRouting(desired *DesiredState, nodeSpec *spec.NodeSpec, links map[string]LinkPlan) error {
	routeKeys := make(map[string]struct{})
	ruleKeys := make(map[string]struct{})
	addRoute := func(route RoutePlan) {
		key := fmt.Sprintf("%d|%s", route.TableID, route.Prefix)
		if _, exists := routeKeys[key]; exists {
			return
		}
		routeKeys[key] = struct{}{}
		desired.Routes = append(desired.Routes, route)
	}
	addRule := func(rule RulePlan) {
		key := fmt.Sprintf("%d|%s|%s", rule.TableID, rule.Source, rule.Destination)
		if _, exists := ruleKeys[key]; exists {
			return
		}
		ruleKeys[key] = struct{}{}
		desired.Rules = append(desired.Rules, rule)
	}
	addDestinationRule := func(table int, prefix netip.Prefix) {
		addRule(RulePlan{TableID: table, Priority: table, Destination: prefix})
	}

	if err := compilePeerRoutes(nodeSpec.Routes, desired.FabricTableID, links, addRoute, addDestinationRule); err != nil {
		return err
	}
	for _, pool := range []netip.Prefix{desired.LinkPoolV4, desired.LinkPoolV6, desired.LoopbackPoolV6} {
		if !pool.IsValid() {
			continue
		}
		addDestinationRule(desired.FabricTableID, pool)
		addRoute(RoutePlan{TableID: desired.FabricTableID, Prefix: pool, Type: RouteUnreachable})
	}

	domainNames := make([]string, 0, len(nodeSpec.Domains))
	for name := range nodeSpec.Domains {
		domainNames = append(domainNames, name)
	}
	sort.Strings(domainNames)
	for _, name := range domainNames {
		domain := nodeSpec.Domains[name]
		for _, raw := range domain.SourcePrefixes {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return fmt.Errorf("domain %q source prefix: %w", name, err)
			}
			addRule(RulePlan{TableID: domain.TableID, Priority: domain.TableID, Source: prefix})
			addRule(RulePlan{TableID: domain.TableID, Priority: domain.TableID, Destination: prefix})
		}
		if err := compilePeerRoutes(domain.Routes, domain.TableID, links, addRoute, nil); err != nil {
			return fmt.Errorf("domain %q: %w", name, err)
		}
		for _, raw := range domain.Exceptions {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return fmt.Errorf("domain %q exception: %w", name, err)
			}
			addRoute(RoutePlan{TableID: domain.TableID, Prefix: prefix, Type: RouteThrow})
		}
	}
	return nil
}

func compilePeerRoutes(routes spec.Routes, tableID int, links map[string]LinkPlan, addRoute func(RoutePlan), addDestinationRule func(int, netip.Prefix)) error {
	peerNames := make([]string, 0, len(routes))
	for name := range routes {
		peerNames = append(peerNames, name)
	}
	sort.Strings(peerNames)
	for _, peerName := range peerNames {
		link, exists := links[peerName]
		if !exists {
			return fmt.Errorf("route references unknown peer %q", peerName)
		}
		for _, item := range routes[peerName] {
			prefix, err := netip.ParsePrefix(item.Prefix)
			if err != nil {
				return fmt.Errorf("route prefix %q: %w", item.Prefix, err)
			}
			var metric *uint32
			if item.Metric != nil {
				value := *item.Metric
				metric = &value
			}
			addRoute(RoutePlan{TableID: tableID, Prefix: prefix, Type: RouteViaPeer, PeerName: peerName, InterfaceName: link.InterfaceName, Metric: metric})
			if addDestinationRule != nil {
				addDestinationRule(tableID, prefix)
			}
		}
	}
	return nil
}
