"""Host-owned membership and independent kernel/WireGuard forwarding oracle."""
import ipaddress
import os
import random
import re


class NotConverged(Exception):
    pass


class PendingLinks:
    """Track actual kernel interface incarnations, never daemon attempt claims."""
    def __init__(self):
        self.since = {}

    def forget(self, node):
        # A reborn namespace can reuse ifindices from the previous birth.
        self.since = {key: value for key, value in self.since.items() if key[0] != node}

    def observe(self, observations, now):
        current = {}
        for node, obs in observations.items():
            materialized = set(obs['materialized_ifindices'])
            pending = {name for name in obs['wg'] if name.startswith('vdl-')
                       and obs['ifindices'].get(name) not in materialized}
            pending.update(obs.get('durable_waiting', ()))
            obs['pending'] = sorted(pending)
            for name in pending:
                index = obs['ifindices'].get(name)
                if index is None:
                    raise NotConverged(f'node {node}/{name}: interface changed during observation')
                key = node, index
                current[key] = self.since.get(key, now)
        # Remember first observation even if an admission check below fails.
        # Otherwise a continuous violation could keep restarting its lifetime.
        self.since = current
        for node, obs in observations.items():
            for name in obs['pending']:
                key = node, obs['ifindices'][name]
                # UDP 30s + final validation 30s + deferred cleanup 10s +
                # cleanup 5s, with 15s for observation/scheduling. No refresh
                # merely because a new proposal reused the same interface.
                if now - current[key] > 90 and name not in obs.get('durable_by_interface', {}):
                    raise AssertionError(f'node {node}/{name}: tentative WG incarnation exceeded 90s')
                if any(route.get('dev') == name for route in obs['fib']):
                    raise NotConverged(f'node {node}/{name}: tentative WG entered FIB')
                if any(re.search(r'%'+re.escape(name)+r'\]?:6696\b', line)
                       for line in obs['babel_sockets'].splitlines()):
                    raise NotConverged(f'node {node}/{name}: Babel attached to tentative WG')


def nat_heartbeat_fresh(status, now):
    # Network namespaces share the host monotonic clock. File mtimes use wall
    # time and can falsely report a stalled translator after a clock step.
    updated = status.get('updated_monotonic')
    return isinstance(updated, (int, float)) and 0 <= now - updated <= 5


def address(node):
    return f"fd78:e2ee::{node + 1:x}"


def prefix(node):
    return address(node) + "/128"


def network(value):
    if value == 'default':
        return '::/0'  # These observations come from ip -6 route.
    return str(ipaddress.ip_network(value, strict=False))


class Topology:
    """Per-node underlay profiles and one chosen outbound bootstrap per birth."""
    def __init__(self, nodes, min_nodes, seed, dynamic=True, underlay='ipv4'):
        if not 3 <= min_nodes < nodes <= 16:
            raise ValueError("require 3 <= min-nodes < nodes <= 16")
        self.size, self.minimum, self.dynamic = nodes, min_nodes, dynamic
        self.mixed = dynamic and underlay == 'dual'
        if self.mixed and nodes < 8:
            raise ValueError('mixed dynamic underlay requires at least 8 slots: 2 transit, 4 public, 2 NAT')
        self.transit = {0, 1} if self.mixed else set()
        self.discovery_family = dict.fromkeys(range(nodes), {'ipv4': 4, 'ipv6': 6, 'dual': None}[underlay])
        if self.mixed:
            self.discovery_family.update({node: 4 if node % 2 == 0 else 6
                                          for node in range(nodes) if node not in self.transit})
        self.modes = {node: 'active' if dynamic else 'off' for node in range(nodes)}
        self.modes.update({node: 'off' for node in self.transit})
        self.rng = random.Random(seed)
        self.public = set(range(6 if self.mixed else max(2, nodes // 4)))
        self.active = set(range(nodes))
        self.boot = {}
        self.profiles = {}
        self.births = {node: 0 for node in range(nodes)}
        # Edges earned by a successful audit or bilateral kernel evidence.
        # Absence from a later observation must not silently shrink reachability.
        self.automatic = {}
        self.catalog = [(m, f, a) for a in ('preserve', 'offset', 'sequential', 'random')
                        for m in ('eim', 'adm', 'apdm') for f in ('eif', 'adf', 'apdf')]
        available = []
        for node in range(nodes):
            candidates = self.bootstrap_candidates(node, available)
            self.boot[node] = self.rng.choice(candidates) if candidates else None
            if node in self.public:
                available.append(node)
                self.profiles[node] = None
            else:
                # Spread all three axes across the initial population, then
                # rotate the profile on subsequent births of that slot.
                index = (node - len(self.public)) * 7 % len(self.catalog)
                self.profiles[node] = self.catalog[index]

    def next_event(self):
        choices = []
        if len(self.active) > self.minimum:
            choices.append('delete')
        if len(self.active) < self.size:
            choices.append('add')
        operation = self.rng.choice(choices)
        if operation == 'delete':
            candidates = self.active.copy()
            if len(self.active & self.public) == 1:
                candidates -= self.public
            if self.mixed:
                # Preserve one public listener per family, while allowing every
                # slot (including both transit nodes) to leave and return.
                for family in (4, 6):
                    public = {n for n in self.active & self.public if self.discovery_family[n] == family}
                    if len(public) == 1:
                        candidates -= public
        else:
            candidates = set(range(self.size)) - self.active
        node = self.rng.choice(sorted(candidates))
        self.forget(node)
        event = {'operation': operation, 'node': node}
        if operation == 'delete':
            self.active.remove(node)
            event['abrupt'] = bool(self.rng.getrandbits(1))
        else:
            self.boot[node] = self.rng.choice(self.bootstrap_candidates(node, self.active & self.public))
            self.active.add(node)
            self.births[node] += 1
            if node not in self.public:
                index = ((node - len(self.public)) * 7 + self.births[node]) % len(self.catalog)
                self.profiles[node] = self.catalog[index]
            event.update(bootstrap=self.boot[node], profile=self.profiles[node])
        return event

    def bootstrap_candidates(self, node, available):
        return sorted(peer for peer in available if not self.mixed or node in self.transit
                      or peer in self.transit or self.discovery_family[node] == self.discovery_family[peer])

    def dynamic_pair(self, left, right):
        return (self.dynamic and self.want_pair(left, right) and
                (not self.mixed or self.discovery_family[left] is not None and
                 self.discovery_family[left] == self.discovery_family[right]))

    def static_family(self, left, right):
        if not self.mixed:
            return None
        return self.discovery_family[left] or self.discovery_family[right]

    def configured(self, node):
        result = {f'vl-in-{peer:02d}': peer for peer in range(self.size) if peer != node} if node in self.public else {}
        if self.boot[node] is not None:
            result[f'vl-boot-{self.boot[node]:02d}'] = self.boot[node]
        return result

    def static_links(self, node):
        result = {}
        if self.boot[node] in self.active:
            result[f'vl-boot-{self.boot[node]:02d}'] = self.boot[node]
        if node in self.public:
            result.update({f'vl-in-{peer:02d}': peer for peer in self.active - {node} if self.boot[peer] == node})
        return result

    def required(self, node):
        result = set(self.static_links(node).values())
        if self.dynamic:
            result |= {peer for peer in self.components()[node] - {node}
                       if (node in self.public or peer in self.public) and self.dynamic_pair(node, peer)}
        return result

    def forget(self, node):
        self.automatic = {edge: births for edge, births in self.automatic.items() if node not in edge}

    def live_history(self):
        return {edge: births for edge, births in self.automatic.items()
                if self.dynamic and set(edge) <= self.active
                and births == tuple(self.births[n] for n in edge)
                and all(self.modes[n] != 'off' for n in edge)
                and (not self.mixed or self.discovery_family[edge[0]] is not None
                     and self.discovery_family[edge[0]] == self.discovery_family[edge[1]])
                and edge[1] not in self.static_links(edge[0]).values()}

    def automatic_evidence(self, observations, verified=False):
        """Only reciprocal, materialized, active WG links can expand expectations.

        In particular a saved Durable agreement or one stale WG handshake is
        insufficient. The full audit and payload probes still have to pass.
        No route or advertised neighbor count supplies an edge here.
        """
        components = self.components() if verified else None
        receivers = {}
        for node, obs in observations.items():
            if node not in self.active or self.modes[node] == 'off':
                continue
            states = {link['interface']: link for link in obs['status']['runtime'].get('links', [])}
            for name, link in obs['wg'].items():
                state = states.get(name, {})
                if (not name.startswith('vdl-') or name in obs.get('pending', ())
                        or name in obs.get('retained', ())
                        or (not verified and not state.get('active')) or not state.get('committed')
                        or obs.get('ifindices', {}).get(name) not in obs.get('materialized_ifindices', ())
                        or len(link['peers']) != 1):
                    continue
                peer = link['peers'][0]
                if peer['handshake'] and {'0.0.0.0/0', '::/0'} <= set(peer['allowed']):
                    receivers[node, link['public'], peer['public']] = True
        edges = {}
        for node, public, peer in receivers:
            for remote, reverse_public, reverse_peer in receivers:
                if (node < remote and public == reverse_peer and peer == reverse_public
                        and (not self.mixed or self.discovery_family[node] is not None
                             and self.discovery_family[node] == self.discovery_family[remote])
                        and remote not in self.static_links(node).values()
                        and (not verified or remote in components[node])):
                    edges[node, remote] = self.births[node], self.births[remote]
        return edges if self.dynamic else {}

    def observe_automatic(self, observations):
        self.automatic = self.live_history() | self.automatic_evidence(observations)

    def verified(self, observations):
        # Safe to retire unused edges only after the complete route/traffic
        # audit passed; a disappearing link cannot make its own failure pass.
        # Control-session loss alone does not discard a Link whose ordinary
        # audit and forwarding checks passed. It cannot expand a partition.
        self.automatic = self.automatic_evidence(observations, verified=True)

    def plan_verified(self):
        """--plan assumes required links pass; optional NAT/NAT is not predicted."""
        self.automatic = self.live_history() | {
            (node, peer): (self.births[node], self.births[peer])
            for node in sorted(self.active) for peer in self.required(node)
            if node < peer and peer not in self.static_links(node).values()}

    def want_pair(self, left, right):
        a, b = self.modes[left], self.modes[right]
        return (a == 'active' and b != 'off') or (b == 'active' and a != 'off')

    def components(self):
        graph = {node: set(self.static_links(node).values()) for node in self.active}
        for left, right in self.live_history():
            graph[left].add(right)
            graph[right].add(left)
        components = {}
        for node in self.active:
            seen, pending = set(), [node]
            while pending:
                current = pending.pop()
                if current not in seen:
                    seen.add(current)
                    pending.extend(graph[current] - seen)
            components[node] = seen
        return components

    def state(self):
        return {'active': sorted(self.active), 'dynamic': self.dynamic, 'public': sorted(self.public),
                'bootstrap': self.boot, 'profiles': self.profiles, 'births': self.births, 'modes': self.modes,
                'mixed': self.mixed, 'transit': sorted(self.transit), 'discovery_family': self.discovery_family,
                'automatic_links': sorted(self.live_history()),
                'components': [sorted(c) for c in sorted(set(map(frozenset, self.components().values())), key=lambda c: min(c))]}


def parse_wg(dump):
    """Discard private and preshared keys immediately; never persist raw wg dump."""
    result = {}
    for line in dump.splitlines():
        fields = line.split("\t")
        if len(fields) == 5:
            interface, _private, public, port, _mark = fields
            result[interface] = {"public": public, "port": int(port), "peers": []}
        elif len(fields) == 9:
            interface, public, _psk, endpoint, allowed, handshake, rx, tx, _keepalive = fields
            result[interface]["peers"].append({"public": public, "endpoint": endpoint,
                "allowed": allowed.split(","), "handshake": int(handshake), "rx": int(rx), "tx": int(tx)})
        else:
            raise ValueError("unexpected wg dump field count")
    return result


def is_retained_fallback(route, retained):
    """Match only the neighbor fallback of an independently validated Link."""
    peer = retained.get(route.get('dev'))
    return (peer is not None and network(route['dst']) == prefix(peer)
            and str(route.get('protocol')) == '202' and route.get('metric') == 131008
            and not route.get('gateway') and not route.get('multipath'))


def audit(topology, observations):
    """Membership/underlay model is the oracle; WG/FIB/status are observations."""
    owners = {}
    for node, observation in observations.items():
        for name, link in observation['wg'].items():
            if name in observation.get('pending', ()):
                continue
            key = link['public']
            if key in owners and owners[key] != node:
                raise NotConverged('WireGuard public key shared by different nodes')
            owners[key] = node
    # Stable fixture identities include absent members. A retained resource is
    # allowed only after this exact kernel incarnation was observed committed.
    for obs in observations.values():
        for key, node in obs.get('known_peer_keys', {}).items():
            if key in owners and owners[key] != node:
                raise NotConverged('WireGuard key differs from provisioned identity')
            owners[key] = node
    forwarding, pairs = {}, []
    known = {prefix(n): n for n in range(topology.size)}
    components = topology.components()
    for node in sorted(topology.active):
        observation = observations[node]
        configured, static = topology.configured(node), topology.static_links(node)
        if {n for n in observation['wg'] if n.startswith('vl-')} != set(configured):
            raise NotConverged(f'node {node}: configured static WG interfaces differ')
        interfaces, peers = {}, set()
        dynamic_count = 0
        retained = {}
        states = {x['interface']: x for x in observation['status']['runtime'].get('links', [])}
        for name, link in observation['wg'].items():
            if name in observation.get('pending', ()):
                continue
            if len(link['peers']) != 1:
                raise NotConverged(f'node {node}/{name}: expected one WG peer')
            peer = link['peers'][0]
            remote = owners.get(peer['public'])
            state = states.get(name, {})
            materialized = observation.get('ifindices', {}).get(name) in observation.get('materialized_ifindices', ())
            # A cold peer's tentative receiver does not make the survivor's
            # retained incarnation reciprocal, even when its keys match.
            reciprocal_present = remote in observations and any(
                candidate.startswith('vdl-') and candidate not in observations[remote].get('pending', ())
                and any(p['public'] == link['public'] for p in value['peers'])
                for candidate, value in observations[remote]['wg'].items())
            # A partition can leave both committed WG interfaces intact while
            # neither control session nor the Babel adjacency remains usable.
            obsolete = (name not in static if name in configured else
                        remote not in components[node] or not reciprocal_present)
            if (obsolete and materialized and state.get('committed') and not state.get('active')
                    and remote is not None and remote != node
                    and {'0.0.0.0/0', '::/0'} <= set(peer['allowed'])):
                retained[name] = remote
                continue
            if name in configured:
                if name not in static:
                    continue  # Preprovisioned public receivers need no session.
                if remote != static[name]:
                    raise NotConverged(f'node {node}/{name}: wrong static identity')
            elif name.startswith('vdl-'):
                if state.get('active', True) and not observation.get('durable_by_interface', {}).get(name, {}).get('confirmed'):
                    dynamic_count += 1
                if not topology.dynamic or remote not in topology.active:
                    raise NotConverged(f'node {node}/{name}: stale/unexpected dynamic WG interface')
                if topology.modes[node] == 'off' or topology.modes[remote] == 'off':
                    raise NotConverged(f'node {node}/{name}: automatic Link bypassed off')
                if topology.mixed and topology.discovery_family[node] != topology.discovery_family[remote]:
                    raise NotConverged(f'node {node}/{name}: automatic Link crossed discovery families')
            else:
                raise NotConverged(f'node {node}: unexpected WG interface {name}')
            if remote == node or not peer['handshake']:
                raise NotConverged(f'node {node}/{name}: self or unhandshaken WG link')
            family = topology.static_family(node, remote)
            if family is not None:
                endpoint = peer.get('endpoint', '').rsplit(':', 1)[0].strip('[]')
                if not endpoint or ipaddress.ip_address(endpoint).version != family:
                    raise NotConverged(f'node {node}/{name}: WG endpoint escaped fixture family IPv{family}')
            if name.startswith('vdl-'):
                reverse = lambda candidate: candidate.startswith('vdl-')
            else:
                expected = f'vl-in-{node:02d}' if name.startswith('vl-boot-') else f'vl-boot-{node:02d}'
                reverse = lambda candidate: candidate == expected
            reciprocal = [candidate for candidate_name, candidate in observations[remote]['wg'].items()
                          if candidate_name not in observations[remote].get('pending', ())
                          if reverse(candidate_name)
                          if candidate['public'] == peer['public'] and any(
                              p['public'] == link['public'] and p['handshake'] for p in candidate['peers'])]
            if not reciprocal:
                raise NotConverged(f'node {node}/{name}: nonreciprocal WG peer')
            if name.startswith('vdl-') and remote in static.values():
                raise NotConverged(f'node {node}/{name}: automatic Link duplicates healthy Static')
            if not {'0.0.0.0/0', '::/0'} <= set(peer['allowed']):
                raise NotConverged(f'node {node}/{name}: uncommitted WG AllowedIPs')
            interfaces[name] = remote
            peers.add(remote)
        observation['retained'] = sorted(retained)
        observation['retained_peers'] = retained
        required = topology.required(node) - set(observation.get('durable_recovery_peers', ()))
        if not required <= peers:
            raise NotConverged(f'node {node}: missing required neighbors {sorted(required - peers)}')
        runtime = observation['status']['runtime']
        if runtime['established_links'] != len(static) or runtime['dynamic_links'] != dynamic_count:
            raise NotConverged(f'node {node}: VFP counts disagree with current WG topology')
        if runtime['babel']['state'] != 'running':
            raise NotConverged(f'node {node}: managed Babel is not running')
        forwarding[node], routes = {}, {}
        for route in observation['fib']:
            if route.get('type', 'unicast') != 'unicast':
                continue
            key = network(route['dst'])
            if key in known and known[key] != node and is_retained_fallback(route, retained):
                # The best path to a live destination must still beat this
                # retained fallback; an absent destination need not lose it.
                if known[key] in components[node]:
                    routes.setdefault(key, []).append(route)
                continue
            if key not in known or known[key] == node or known[key] not in components[node]:
                raise NotConverged(f'node {node}: unexpected/stale unicast destination {key}')
            if route.get('dev') not in interfaces or route.get('multipath') or route.get('gateway'):
                raise NotConverged(f'node {node}: FIB uses a dead/unknown interface: {route}')
            routes.setdefault(key, []).append(route)
        if set(routes) != {prefix(n) for n in components[node] - {node}}:
            raise NotConverged(f'node {node}: FIB differs from model reachability')
        for key, options in routes.items():
            best = min(option.get('metric', 0) for option in options)
            if any(option['dev'] not in interfaces for option in options if option.get('metric', 0) == best):
                raise NotConverged(f'node {node}: retained dead fallback is best path to {key}')
            hops = {interfaces[option['dev']] for option in options if option.get('metric', 0) == best}
            if len(hops) != 1:
                raise NotConverged(f'node {node}: ambiguous FIB next hop {key}')
            forwarding[node][key] = hops.pop()
        for route in observation['main']:
            if route.get('type', 'unicast') == 'unicast' and network(route['dst']) in known:
                if network(route['dst']) == prefix(node) and route.get('dev') == 'vv-loop' and route.get('protocol') == 'kernel':
                    continue
                raise NotConverged(f'node {node}: overlay route leaked to main table')
        for peer in required:
            if forwarding[node][prefix(peer)] != peer:
                raise NotConverged(f'node {node}: required direct link uses fallback to {peer}')
    for source in sorted(topology.active):
        for destination in sorted(components[source] - {source}):
            node, seen = source, set()
            while node != destination:
                if node in seen:
                    raise NotConverged(f'FIB cycle {source}->{destination}')
                seen.add(node)
                node = forwarding[node][prefix(destination)]
            pairs.append((source, destination))
    return pairs


def is_babel_check(parent, executable, argv, daemon, babel, config):
    """Only the supervisor's exact config validator is an expected transient."""
    return (parent == daemon and executable == os.path.realpath(babel)
            and len(argv) == 4 and argv[:3] == [babel, 'check', '--config']
            and (argv[3] == config or (os.path.dirname(argv[3]) == os.path.dirname(config)
                 and os.path.basename(argv[3]).startswith('.babel-check-'))))


def process_fd_limit(role, nodes):
    """Account for Link resources and the separate bounded observer pool."""
    if role == 'nat':
        return 4112  # 4096 translated sockets, packet socket, selector and files.
    limit = 64 + 16 * nodes
    if role == 'velvetd':
        # Each other node can observe for each of its other targets. The
        # production inbound/observer pool is capped at 128. Each accepted
        # observer owns one routed TCP session and two public UDP listeners;
        # these are additional to this node's own per-Link discovery resources.
        observers = min(128, max(0, (nodes - 1) * (nodes - 2)))
        limit += 3 * observers
    return limit
