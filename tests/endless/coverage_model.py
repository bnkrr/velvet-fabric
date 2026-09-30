"""Bounded, host-owned coverage counts; called only after kernel/FIB audit."""
from collections import Counter
from model import NotConverged, network, prefix
from underlay import endpoint_family


def profile(topology, node):
    return 'public' if node in topology.public else '/'.join(topology.profiles[node])


class Coverage:
    def __init__(self, family):
        self.family = family
        self.matrix, self.pairs, self.operations = Counter(), {}, Counter()
        self.probes = Counter()
        self.proposals = Counter()
        self.endpoint_probes = Counter()

    def reset(self, node):
        for counts in (self.probes, self.proposals, self.pairs):
            for pair in list(counts):
                if node in pair:
                    del counts[pair]

    def proposed(self, node, peer):
        self.proposals[node, peer] += 1

    def ping(self, source, destination, endpoint_family=None):
        self.probes[source, destination] += 1
        if endpoint_family is not None:
            self.endpoint_probes[endpoint_family] += 1

    def require_families(self):
        if self.family == 'dual' and any(not self.endpoint_probes[family] for family in ('ipv4', 'ipv6')):
            raise NotConverged('dual underlay has not carried successful payload probes over both endpoint families')

    def verified(self, topology, observations):
        self.pairs = {}
        owners = {link['public']: node for node, obs in observations.items() for name, link in obs['wg'].items()
                  if name not in obs.get('pending', ())}
        for source in sorted(topology.active):
            links = observations[source]['wg']
            static = topology.static_links(source)
            direct = {owners[peer['public']]: name for name, link in links.items()
                      if name not in observations[source].get('pending', ())
                      if name not in observations[source].get('retained', ())
                      if name in static or name.startswith('vdl-') for peer in link['peers']}
            for target in sorted(topology.components()[source] - {source}):
                name = direct.get(target)
                durable = observations[source].get('durable_by_interface', {}).get(name, {}).get('confirmed')
                outcome = 'static' if name in static else 'durable' if durable else 'dynamic' if name else 'fallback'
                recovering = target in observations[source].get('durable_recovery_peers', ())
                requirement = 'durable-recovery' if recovering else 'direct' if target in topology.required(source) else 'reachable'
                if topology.mixed and requirement == 'reachable' and source not in topology.transit and target not in topology.transit:
                    if topology.discovery_family[source] != topology.discovery_family[target]:
                        requirement = 'relay'
                routes = [route for route in observations[source]['fib']
                          if network(route['dst']) == prefix(target) and route.get('type', 'unicast') == 'unicast']
                route = min(routes, key=lambda route: route.get('metric', 0))
                endpoint = links[route['dev']]['peers'][0].get('endpoint')
                actual_family = endpoint_family(endpoint) if endpoint else 'unknown'
                key = (self.family, actual_family, profile(topology, source), profile(topology, target),
                       topology.modes[source], topology.modes[target], requirement, outcome)
                self.matrix[key] += 1
                self.pairs[source, target] = {'source': source, 'target': target,
                    'source_profile': profile(topology, source), 'target_profile': profile(topology, target),
                    'requirement': requirement, 'outcome': outcome,
                    'source_discovery_family': topology.discovery_family[source],
                    'target_discovery_family': topology.discovery_family[target],
                    'endpoint_family': actual_family,
                    'successful_pings': self.probes[source, target],
                    'local_proposals': self.proposals[source, target],
                    'remote_proposals': self.proposals[target, source]}

    def state(self):
        fields = ('family', 'endpoint_family', 'source_profile', 'target_profile', 'source_mode', 'target_mode', 'requirement', 'outcome')
        return {'operations': dict(self.operations),
                'endpoint_probes': dict(self.endpoint_probes),
                'matrix': [dict(zip(fields, key), verified_samples=count) for key, count in sorted(self.matrix.items())],
                'pairs': [self.pairs[key] for key in sorted(self.pairs)]}
