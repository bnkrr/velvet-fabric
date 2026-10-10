#!/usr/bin/env python3
"""Real WG/Babel regression for discovery across changing routed partitions."""
import time

import netns


def partition_topology(topology):
    if topology.size != 10 or not topology.mixed:
        raise ValueError('partition check requires --nodes 10 --underlay dual --dynamic active')
    topology.active = {0, 1, 2, 3, 5, 7, 8, 9}
    topology.boot = {0: 3, 1: 3, 2: 4, 3: 1, 4: 1, 5: 0, 6: 0, 7: 1, 8: 2, 9: 3}
    topology.profiles.update({6: ('eim', 'apdf', 'offset'), 7: ('eim', 'apdf', 'sequential'),
                             8: ('apdm', 'apdf', 'sequential'), 9: ('eim', 'eif', 'preserve')})


class PartitionRunner(netns.Runner):
    def __init__(self, args, topology, runtime, artifacts):
        partition_topology(topology)
        if not args.wg_access or args.duration_seconds or args.exercise:
            raise ValueError('partition check requires --wg-access, no duration or other exercises')
        super().__init__(args, topology, runtime, artifacts)

    def check(self, label, components):
        self.phase = label
        self.verify()
        assert self.topology.state()['components'] == components, self.topology.state()
        self.record('partition-verified', components=components, access_probes=self.access.probes)

    def add(self, node, bootstrap):
        self.round += 1
        self.topology.forget(node)
        self.topology.boot[node] = bootstrap
        self.topology.active.add(node)
        self.topology.births[node] += 1
        self.deadline = time.monotonic() + self.args.settle_timeout
        self.add_node(node)
        self.counts['add'] += 1

    def remove(self, node):
        self.round += 1
        self.topology.active.remove(node)
        self.deadline = time.monotonic() + self.args.settle_timeout
        self.stop_node(node, abrupt=True)
        self.counts['delete'] += 1
        self.counts['abrupt'] += 1

    def execute(self):
        self.deadline = time.monotonic() + self.args.settle_timeout
        self.prepare()
        for node in sorted(self.topology.active):
            self.add_node(node)
        self.check('initial-partitions', [[0, 1, 3, 5, 7, 9], [2, 8]])
        survivors = {n: info['proc'].pid for n, info in self.nodes.items()}
        self.add(6, 0)
        self.check('join-without-routed-bridge', [[0, 1, 3, 5, 6, 7, 9], [2, 8]])
        assert 2 not in self.topology.required(6)
        assert not self.ping(6, 2) and not self.ping(2, 6)
        self.add(4, 0)
        self.check('bootstrap-bridge', [list(range(10))])
        assert 2 in self.topology.required(6)
        assert self.ping(6, 2) and self.ping(2, 6)
        self.remove(4)
        self.check('automatic-bridge-survives', [[0, 1, 2, 3, 5, 6, 7, 8, 9]])
        assert all(self.nodes[n]['proc'].pid == pid for n, pid in survivors.items())
        self.record('complete', result='PASS', check='partition lifecycle',
                    operations=self.counts, access_probes=self.access.probes)


if __name__ == '__main__':
    netns.Runner = PartitionRunner
    raise SystemExit(netns.main())
