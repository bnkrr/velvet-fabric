package reconcile

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/link"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const LoopbackInterface = "vv-loop"

const BabelDynamicProtocol = 203

// Managed Babel uses cost 96 and loopback origin metrics divisible by 96.
// Finite routes therefore end at 65535+65472; infinity exports at 131070.
const NeighborFallbackPriority = 131008

const DefaultKeepalive = 25 * time.Second

type RouteType uint8

const (
	RouteViaPeer RouteType = iota + 1
	RouteThrow
	RouteUnreachable
)

type DesiredState struct {
	// RetainedLinks protects verified runtime generations during startup cleanup.
	// They are not configured or treated as static peers.
	RetainedLinks      []LinkPlan `json:"-"`
	Ports              spec.PortChoice
	Durable            spec.DurableSettings
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
	RecoveryTimeout        time.Duration
}

type LinkPlan struct {
	WaitingPort bool // Runtime placeholder while a configured port is unavailable.
	Ports       spec.PortChoice
	// Probing keeps a tentative interface DOWN; ReceiveOnly gates outbound WG.
	Probing          bool
	ReceiveOnly      bool
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
	ServiceName    string
	Executable     string
	ConfigPath     string
	ControlPath    string
	StatePath      string
	Interfaces     []string
	Origins        []BabelOrigin
	Views          []BabelView
	ImportPrefixes []netip.Prefix
	ImportSources  []netip.Prefix
	Protocol       uint8
	DeviceOnly     bool
	ManageRules    bool
}

type BabelOrigin struct {
	Destination netip.Prefix
	Source      netip.Prefix
	Metric      uint16
}

type BabelView struct {
	ReturnPrefixes []netip.Prefix
	TableID        int
	Source         netip.Prefix
	RulePriority   int
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
		Ports:   nodeSpec.DynamicPorts(),
		Durable: spec.EffectiveDurable(nodeSpec.DynamicLinks),
		UID:     nodeSpec.Node.UID, UUID: uid, FabricPSK: fabricPSK,
		LinkPoolV4: link4, LinkPoolV6: link6, LoopbackPoolV6: loop6,
		LoopbackV6: localLoop6, VFPPort: nodeSpec.Fabric.EffectiveVFPPort(),
		FabricTableID:      nodeSpec.Fabric.EffectiveRoutingTableID(),
		LoopbackOwnerAlias: "velvet:loopback:" + uid.String(),
		Forwarding:         len(nodeSpec.Fabric.StaticRoutes) > 0 || len(nodeSpec.Domains) > 0 || nodeSpec.Babel.IsEnabled(),
		PrivateKey:         privateKey,
	}
	if nodeSpec.DynamicLinks != nil {
		dynamic := &DynamicLinksPlan{Mode: nodeSpec.DynamicLinks.Mode, RecoveryTimeout: 30 * time.Minute}
		if nodeSpec.DynamicLinks.RecoveryTimeoutSeconds != nil {
			dynamic.RecoveryTimeout = time.Duration(*nodeSpec.DynamicLinks.RecoveryTimeoutSeconds) * time.Second
		}
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
		if other, exists := ports[bootstrap.ListenPort]; exists && bootstrap.ListenPort != 0 {
			return nil, fmt.Errorf("peer %q and peer %q use listen port %d; set different listen_ports", peer.Name, other, bootstrap.ListenPort)
		}
		ports[bootstrap.ListenPort] = peer.Name
		var keepalive *time.Duration
		if peer.PersistentKeepaliveSeconds != nil {
			value := time.Duration(*peer.PersistentKeepaliveSeconds) * time.Second
			keepalive = &value
		}
		item := LinkPlan{
			Ports:    nodeSpec.PeerPorts(peer),
			PeerName: peer.Name, InterfaceName: bootstrap.InterfaceName,
			OwnerAlias: "velvet:link:" + uid.String() + ":" + peer.Name,
			PrivateKey: privateKey, PeerPublicKey: peerKey, PresharedKey: bootstrap.PresharedKey,
			ListenPort: nodeSpec.PeerPorts(peer).Port, Endpoints: append([]string(nil), peer.Endpoints...), Keepalive: keepalive,
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

// Kernel rule priorities are independent of the user-visible table IDs.
const FabricRulePriority = 20000
const DomainRulePriority = 20001
const UnreachableMetric uint32 = 2147483647

func sortedDomainNames(nodeSpec *spec.NodeSpec) []string {
	names := make([]string, 0, len(nodeSpec.Domains))
	for name := range nodeSpec.Domains {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sourcePrefixes(domain spec.DomainSpec) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(domain.SourcePrefixes))
	for _, raw := range domain.SourcePrefixes {
		result = append(result, netip.MustParsePrefix(raw))
	}
	return result
}

func compileRouting(desired *DesiredState, nodeSpec *spec.NodeSpec, links map[string]LinkPlan) error {
	routeKeys, ruleKeys := map[string]bool{}, map[string]bool{}
	addRoute := func(route RoutePlan) {
		metric := uint32(0)
		if route.Metric != nil {
			metric = *route.Metric
		}
		key := fmt.Sprintf("%d|%s|%d|%d", route.TableID, route.Prefix, route.Type, metric)
		if !routeKeys[key] {
			routeKeys[key] = true
			desired.Routes = append(desired.Routes, route)
		}
	}
	addRule := func(rule RulePlan) {
		key := fmt.Sprintf("%d|%s|%s", rule.TableID, rule.Source, rule.Destination)
		if !ruleKeys[key] {
			ruleKeys[key] = true
			desired.Rules = append(desired.Rules, rule)
		}
	}
	guard := func(table int, prefix netip.Prefix) {
		metric := UnreachableMetric
		addRoute(RoutePlan{TableID: table, Prefix: prefix, Type: RouteUnreachable, Metric: &metric})
	}
	names := sortedDomainNames(nodeSpec)
	tables := []int{desired.FabricTableID}
	for _, name := range names {
		tables = append(tables, nodeSpec.Domains[name].SourceTableID)
	}
	for _, pool := range nodeSpec.Fabric.InfrastructurePrefixes() {
		addRule(RulePlan{TableID: desired.FabricTableID, Priority: FabricRulePriority, Destination: pool})
		for _, table := range tables {
			guard(table, pool)
		}
	}
	// Shared infrastructure is available in every Domain; business return paths
	// are copied only into the Domain that owns their destination prefix.
	if err := compilePeerRoutes(nodeSpec.Fabric.StaticRoutes, desired.FabricTableID, links, func(route RoutePlan) {
		for _, table := range tables {
			item := route
			item.TableID = table
			addRoute(item)
		}
	}); err != nil {
		return err
	}
	for _, name := range names {
		domain := nodeSpec.Domains[name]
		for _, prefix := range sourcePrefixes(domain) {
			addRule(RulePlan{TableID: domain.SourceTableID, Priority: DomainRulePriority, Source: prefix})
			addRule(RulePlan{TableID: desired.FabricTableID, Priority: FabricRulePriority, Destination: prefix})
			guard(desired.FabricTableID, prefix)
			guard(domain.SourceTableID, prefix)
		}
		for _, canonical := range canonicalSources(domain.SourcePrefixes) {
			zero := netip.PrefixFrom(netip.IPv6Unspecified(), 0)
			if canonical.Addr().Is4() {
				zero = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
			}
			guard(domain.SourceTableID, zero)
		}
		if err := compilePeerRoutes(domain.StaticRoutes, domain.SourceTableID, links, func(route RoutePlan) {
			addRoute(route)
			if domain.IsAccessPrefix(route.Prefix) {
				route.TableID = desired.FabricTableID
				addRoute(route)
			}
		}); err != nil {
			return fmt.Errorf("domain %q: %w", name, err)
		}
		for _, announcement := range domain.Announcements {
			prefix := netip.MustParsePrefix(announcement.Prefix)
			addRoute(RoutePlan{TableID: domain.SourceTableID, Prefix: prefix, Type: RouteThrow})
			if domain.IsAccessPrefix(prefix) {
				addRoute(RoutePlan{TableID: desired.FabricTableID, Prefix: prefix, Type: RouteThrow})
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
	runtimeRoot := filepath.Join("/run/velvet-babel", desired.UUID.String())
	stateRoot := filepath.Join("/var/lib/velvet", desired.UUID.String())
	ordinary := append([]netip.Prefix(nil), nodeSpec.Fabric.InfrastructurePrefixes()...)
	names := sortedDomainNames(nodeSpec)
	for _, name := range names {
		ordinary = append(ordinary, sourcePrefixes(nodeSpec.Domains[name])...)
	}
	plan := &BabelPlan{
		Executable: executable, ConfigPath: filepath.Join(stateRoot, "babel-rs.toml"), ControlPath: filepath.Join(runtimeRoot, "babel-rs.ctl"), StatePath: filepath.Join(stateRoot, "babel-rs-state.toml"),
		Protocol: BabelDynamicProtocol, DeviceOnly: true, ManageRules: false,
		ImportPrefixes: ordinary,
		Views:          []BabelView{{TableID: desired.FabricTableID, ReturnPrefixes: ordinary}},
	}
	plan.Origins = append(plan.Origins, BabelOrigin{Destination: netip.PrefixFrom(desired.LoopbackV6, 128)})
	for _, name := range names {
		domain := nodeSpec.Domains[name]
		allowed := append([]netip.Prefix(nil), nodeSpec.Fabric.InfrastructurePrefixes()...)
		allowed = append(allowed, sourcePrefixes(domain)...)
		for _, canonical := range canonicalSources(domain.SourcePrefixes) {
			plan.ImportSources = append(plan.ImportSources, canonical)
			var family []netip.Prefix
			for _, prefix := range allowed {
				if prefix.Addr().Is4() == canonical.Addr().Is4() {
					family = append(family, prefix)
				}
			}
			plan.Views = append(plan.Views, BabelView{TableID: domain.SourceTableID, Source: canonical, RulePriority: DomainRulePriority, ReturnPrefixes: family})
			for _, announcement := range domain.Announcements {
				prefix := netip.MustParsePrefix(announcement.Prefix)
				if !domain.IsAccessPrefix(prefix) && prefix.Addr().Is4() == canonical.Addr().Is4() {
					plan.Origins = append(plan.Origins, BabelOrigin{Destination: prefix, Source: canonical, Metric: announcementMetric(announcement)})
				}
			}
		}
		for _, announcement := range domain.Announcements {
			prefix := netip.MustParsePrefix(announcement.Prefix)
			if domain.IsAccessPrefix(prefix) {
				plan.Origins = append(plan.Origins, BabelOrigin{Destination: prefix, Metric: announcementMetric(announcement)})
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

func announcementMetric(value spec.Announcement) uint16 {
	if value.Metric == nil {
		return 0
	}
	return uint16(*value.Metric)
}

func compilePeerRoutes(routes spec.Routes, tableID int, links map[string]LinkPlan, addRoute func(RoutePlan)) error {
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
		}
	}
	return nil
}
