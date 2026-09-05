package reconcile

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/link"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const LoopbackInterface = "vv-loop"

const BabelDynamicProtocol = 203

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
	Babel              *BabelPlan
	DynamicLinks       *DynamicLinksPlan
	PrivateKey         wgtypes.Key
}

type DynamicLinksPlan struct {
	Mode                   string
	AllowCandidatePrefixes []netip.Prefix
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

type BabelPlan struct {
	Executable  string
	ConfigPath  string
	ControlPath string
	StatePath   string
	Interfaces  []string
	Origins     []BabelOrigin
	Views       []BabelView
	Protocol    uint8
	DeviceOnly  bool
	ManageRules bool
}

type BabelOrigin struct {
	Destination netip.Prefix
	Source      netip.Prefix
	Metric      uint16
}

type BabelView struct {
	TableID      int
	Source       netip.Prefix
	RulePriority int
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
		Forwarding:         len(nodeSpec.Fabric.Routes) > 0 || len(nodeSpec.Domains) > 0 || nodeSpec.Babel.IsEnabled(),
		PrivateKey:         privateKey,
	}
	if nodeSpec.DynamicLinks != nil {
		dynamic := &DynamicLinksPlan{Mode: nodeSpec.DynamicLinks.Mode}
		for _, raw := range nodeSpec.DynamicLinks.AllowCandidatePrefixes {
			dynamic.AllowCandidatePrefixes = append(dynamic.AllowCandidatePrefixes, netip.MustParsePrefix(raw))
		}
		desired.DynamicLinks = dynamic
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
	if nodeSpec.Babel.IsEnabled() {
		desired.Babel = compileBabel(desired, nodeSpec)
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

	if err := compilePeerRoutes(nodeSpec.Fabric.Routes, desired.FabricTableID, links, addRoute, addDestinationRule); err != nil {
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
		}
		if err := compilePeerRoutes(domain.Routes, domain.TableID, links, addRoute, nil); err != nil {
			return fmt.Errorf("domain %q: %w", name, err)
		}
	}
	for _, announcement := range nodeSpec.Fabric.Announcements {
		prefix, _ := netip.ParsePrefix(announcement.Prefix)
		addRoute(RoutePlan{TableID: desired.FabricTableID, Prefix: prefix, Type: RouteThrow})
		addDestinationRule(desired.FabricTableID, prefix)
		for _, name := range domainNames {
			addRoute(RoutePlan{TableID: nodeSpec.Domains[name].TableID, Prefix: prefix, Type: RouteThrow})
		}
	}
	for _, name := range domainNames {
		domain := nodeSpec.Domains[name]
		for _, announcement := range domain.Announcements {
			prefix, _ := netip.ParsePrefix(announcement.Prefix)
			if hasAddressFamily(domain.SourcePrefixes, prefix.Addr().Is4()) {
				addRoute(RoutePlan{TableID: domain.TableID, Prefix: prefix, Type: RouteThrow})
			}
		}
	}
	return nil
}

func compileBabel(desired *DesiredState, nodeSpec *spec.NodeSpec) *BabelPlan {
	executable := nodeSpec.Babel.Executable
	if executable == "" {
		executable = "babel-rs"
	}
	runtimeRoot := filepath.Join("/run/velvet", desired.UUID.String())
	stateRoot := filepath.Join("/var/lib/velvet", desired.UUID.String())
	plan := &BabelPlan{
		Executable:  executable,
		ConfigPath:  filepath.Join(runtimeRoot, "babel-rs.toml"),
		ControlPath: filepath.Join(runtimeRoot, "babel-rs.ctl"),
		StatePath:   filepath.Join(stateRoot, "babel-rs-state.toml"),
		Protocol:    BabelDynamicProtocol, DeviceOnly: true, ManageRules: false,
		Views:      []BabelView{{TableID: desired.FabricTableID}},
		Interfaces: []string{"vl-*", "vdl-*"},
	}
	for _, link := range desired.Links {
		if !strings.HasPrefix(link.InterfaceName, "vl-") {
			plan.Interfaces = append(plan.Interfaces, link.InterfaceName)
		}
	}
	plan.Origins = append(plan.Origins, BabelOrigin{Destination: netip.PrefixFrom(desired.LoopbackV6, 128)})
	for _, announcement := range nodeSpec.Fabric.Announcements {
		prefix, _ := netip.ParsePrefix(announcement.Prefix)
		plan.Origins = append(plan.Origins, BabelOrigin{Destination: prefix, Metric: announcementMetric(announcement)})
	}
	domainNames := make([]string, 0, len(nodeSpec.Domains))
	for name := range nodeSpec.Domains {
		domainNames = append(domainNames, name)
	}
	sort.Strings(domainNames)
	for _, name := range domainNames {
		domain := nodeSpec.Domains[name]
		canonical := canonicalSources(domain.SourcePrefixes)
		for _, source := range canonical {
			plan.Views = append(plan.Views, BabelView{TableID: domain.TableID, Source: source, RulePriority: domain.TableID})
			for _, announcement := range domain.Announcements {
				destination, _ := netip.ParsePrefix(announcement.Prefix)
				if destination.Addr().Is4() == source.Addr().Is4() {
					plan.Origins = append(plan.Origins, BabelOrigin{Destination: destination, Source: source, Metric: announcementMetric(announcement)})
				}
			}
		}
	}
	return plan
}

func canonicalSources(raw []string) []netip.Prefix {
	seen := map[bool]bool{}
	var result []netip.Prefix
	for _, value := range raw {
		prefix, _ := netip.ParsePrefix(value)
		family := prefix.Addr().Is4()
		if seen[family] {
			continue
		}
		seen[family] = true
		result = append(result, prefix)
	}
	return result
}

func hasAddressFamily(raw []string, ipv4 bool) bool {
	for _, value := range raw {
		prefix, _ := netip.ParsePrefix(value)
		if prefix.Addr().Is4() == ipv4 {
			return true
		}
	}
	return false
}

func announcementMetric(value spec.Announcement) uint16 {
	if value.Metric == nil {
		return 0
	}
	return uint16(*value.Metric)
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
