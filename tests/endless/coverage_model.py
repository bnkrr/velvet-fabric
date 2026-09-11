"""Bounded, host-owned coverage counts; called only after kernel/FIB audit."""
from collections import Counter


def profile(topology, node):
    return 'public' if node in topology.public else '/'.join(topology.profiles[node])


class Coverage:
    def __init__(self, family):
        self.family = family
        self.matrix, self.pairs, self.operations = Counter(), {}, Counter()
        self.probes = Counter()
        self.proposals = Counter()

    def reset(self, node):
        for counts in (self.probes, self.proposals, self.pairs):
            for pair in list(counts):
                if node in pair:
                    del counts[pair]

    def proposed(self, node, peer):
        self.proposals[node, peer] += 1

    def ping(self, source, destination):
        self.probes[source, destination] += 1

    def verified(self, topology, observations):
        self.pairs = {}
        owners = {link['public']: node for node, obs in observations.items() for name, link in obs['wg'].items()
                  if name not in obs.get('pending', ())}
        for source in sorted(topology.active):
            links = observations[source]['wg']
            static = topology.static_links(source)
            direct = {owners[peer['public']]: name for name, link in links.items()
                      if name not in observations[source].get('pending', ())
                      if name in static or name.startswith('vdl-') for peer in link['peers']}
            for target in sorted(topology.components()[source] - {source}):
                name = direct.get(target)
                outcome = 'static' if name in static else 'dynamic' if name else 'fallback'
                requirement = 'direct' if target in topology.required(source) else 'reachable'
                key = (self.family, profile(topology, source), profile(topology, target),
                       topology.modes[source], topology.modes[target], requirement, outcome)
                self.matrix[key] += 1
                self.pairs[source, target] = {'source': source, 'target': target,
                    'source_profile': profile(topology, source), 'target_profile': profile(topology, target),
                    'requirement': requirement, 'outcome': outcome,
                    'successful_pings': self.probes[source, target],
                    'local_proposals': self.proposals[source, target],
                    'remote_proposals': self.proposals[target, source]}

    def state(self):
        fields = ('family', 'source_profile', 'target_profile', 'source_mode', 'target_mode', 'requirement', 'outcome')
        return {'operations': dict(self.operations),
                'matrix': [dict(zip(fields, key), verified_samples=count) for key, count in sorted(self.matrix.items())],
                'pairs': [self.pairs[key] for key in sorted(self.pairs)]}
