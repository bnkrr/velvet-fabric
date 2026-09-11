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

    def observe(self, observations, now):
        current = {}
        for node, obs in observations.items():
            materialized = {route.get('dev') for route in obs['fib'] if str(route.get('protocol')) == '202'}
            pending = set(obs['wg']) - materialized
            pending = {name for name in pending if name.startswith('vdl-')}
            obs['pending'] = sorted(pending)
            for name in pending:
                index = obs['ifindices'].get(name)
                if index is None:
                    raise NotConverged(f'node {node}/{name}: interface changed during observation')
                key = node, index
                current[key] = self.since.get(key, now)
                # UDP 30s + final validation 30s + deferred cleanup 10s +
                # cleanup 5s, with 15s for observation/scheduling. No refresh
                # merely because a new proposal reused the same interface.
                if now - current[key] > 90:
                    raise AssertionError(f'node {node}/{name}: tentative WG incarnation exceeded 90s')
                if any(route.get('dev') == name for route in obs['fib']):
                    raise NotConverged(f'node {node}/{name}: tentative WG entered FIB')
                if any(re.search(r'%'+re.escape(name)+r'\]?:6696\b', line)
                       for line in obs['babel_sockets'].splitlines()):
                    raise NotConverged(f'node {node}/{name}: Babel attached to tentative WG')
        self.since = current


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
    def __init__(self, nodes, min_nodes, seed, dynamic=True):
        if not 3 <= min_nodes < nodes <= 16:
            raise ValueError("require 3 <= min-nodes < nodes <= 16")
        self.size, self.minimum, self.dynamic = nodes, min_nodes, dynamic
        self.modes = {node: 'active' if dynamic else 'off' for node in range(nodes)}
        self.rng = random.Random(seed)
        self.public = set(range(max(2, nodes // 4)))
        self.active = set(range(nodes))
        self.boot = {}
        self.profiles = {}
        self.births = {node: 0 for node in range(nodes)}
        self.catalog = [(m, f, a) for a in ('preserve', 'offset', 'sequential', 'random')
                        for m in ('eim', 'adm', 'apdm') for f in ('eif', 'adf', 'apdf')]
        available = []
        for node in range(nodes):
            self.boot[node] = self.rng.choice(available) if available else None
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
        else:
            candidates = set(range(self.size)) - self.active
        node = self.rng.choice(sorted(candidates))
        event = {'operation': operation, 'node': node}
        if operation == 'delete':
            self.active.remove(node)
            event['abrupt'] = bool(self.rng.getrandbits(1))
        else:
            self.boot[node] = self.rng.choice(sorted(self.active & self.public))
            self.active.add(node)
            self.births[node] += 1
            if node not in self.public:
                index = ((node - len(self.public)) * 7 + self.births[node]) % len(self.catalog)
                self.profiles[node] = self.catalog[index]
            event.update(bootstrap=self.boot[node], profile=self.profiles[node])
        return event

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
            result |= {peer for peer in self.active - {node}
                       if (node in self.public or peer in self.public) and self.want_pair(node, peer)}
        return result

    def want_pair(self, left, right):
        a, b = self.modes[left], self.modes[right]
        return (a == 'active' and b != 'off') or (b == 'active' and a != 'off')

    def components(self):
        if self.dynamic:
            # One live public bootstrap suffices for membership. Extra NAT
            # links are best-effort, but every member must remain reachable.
            return {node: self.active.copy() for node in self.active}
        graph = {node: self.required(node) for node in self.active}
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
                'bootstrap': self.boot, 'profiles': self.profiles, 'births': self.births, 'modes': self.modes}


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
        for name, link in observation['wg'].items():
            if name in observation.get('pending', ()):
                continue
            if len(link['peers']) != 1:
                raise NotConverged(f'node {node}/{name}: expected one WG peer')
            peer = link['peers'][0]
            remote = owners.get(peer['public'])
            if name in configured:
                if name not in static:
                    continue  # Preprovisioned public receivers need no session.
                if remote != static[name]:
                    raise NotConverged(f'node {node}/{name}: wrong static identity')
            elif name.startswith('vdl-'):
                dynamic_count += 1
                if not topology.dynamic or remote not in topology.active:
                    raise NotConverged(f'node {node}/{name}: stale/unexpected dynamic WG interface')
            else:
                raise NotConverged(f'node {node}: unexpected WG interface {name}')
            if remote == node or not peer['handshake']:
                raise NotConverged(f'node {node}/{name}: self or unhandshaken WG link')
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
            if not {'0.0.0.0/0', '::/0'} <= set(peer['allowed']):
                raise NotConverged(f'node {node}/{name}: uncommitted WG AllowedIPs')
            interfaces[name] = remote
            peers.add(remote)
        if not topology.required(node) <= peers:
            raise NotConverged(f'node {node}: missing required neighbors {sorted(topology.required(node) - peers)}')
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
            if key not in known or known[key] == node or known[key] not in components[node]:
                raise NotConverged(f'node {node}: unexpected/stale unicast destination {key}')
            if route.get('dev') not in interfaces or route.get('multipath') or route.get('gateway'):
                raise NotConverged(f'node {node}: FIB uses a dead/unknown interface: {route}')
            routes.setdefault(key, []).append(route)
        if set(routes) != {prefix(n) for n in components[node] - {node}}:
            raise NotConverged(f'node {node}: FIB differs from model reachability')
        for key, options in routes.items():
            best = min(option.get('metric', 0) for option in options)
            hops = {interfaces[option['dev']] for option in options if option.get('metric', 0) == best}
            if len(hops) != 1:
                raise NotConverged(f'node {node}: ambiguous FIB next hop {key}')
            forwarding[node][key] = hops.pop()
        for route in observation['main']:
            if route.get('type', 'unicast') == 'unicast' and network(route['dst']) in known:
                if network(route['dst']) == prefix(node) and route.get('dev') == 'vv-loop' and route.get('protocol') == 'kernel':
                    continue
                raise NotConverged(f'node {node}: overlay route leaked to main table')
        for peer in topology.required(node):
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
            and argv == [babel, 'check', '--config', config])


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
