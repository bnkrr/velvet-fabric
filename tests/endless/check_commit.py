#!/usr/bin/env python3
"""Real WG/Babel regression: failed tentative Links must not enter routing."""
import json

import netns


class CommitRunner(netns.Runner):
    def __init__(self, args, topology, runtime, artifacts):
        if topology.size != 4 or not topology.dynamic:
            raise ValueError('commit-boundary check requires --nodes 4 --dynamic active')
        for node in (2, 3):
            topology.profiles[node] = ('eim', 'eif', 'preserve')
        super().__init__(args, topology, runtime, artifacts)
        self.tentative_seen = set()

    def add_node(self, node):
        super().add_node(node)
        if node in (2, 3):
            # Allow actual WG handshakes and Babel, but prevent final link-local
            # discovery/VFP commit only on the NAT-to-NAT candidate Link.
            peer = 5 - node
            rules = f'''table inet commit_test {{
 chain input {{ type filter hook input priority 0; policy accept;
  iifname "vdl-n{peer}-*" udp dport 58420 counter drop
  iifname "vdl-n{peer}-*" tcp dport 58420 counter drop
 }}
}}
'''
            self.ns(node, 'nft', '-f', '-', input=rules)

    def observe(self):
        observations = super().observe()
        for node in (2, 3):
            prefix = f'vdl-n{5 - node}-'
            names = [name for name in observations[node]['wg'] if name.startswith(prefix)]
            if names:
                self.tentative_seen.add(node)
            sockets = self.ns(node, 'ss', '-uanp')
            for line in sockets.splitlines():
                if prefix in line and ':6696' in line:
                    raise AssertionError(f'Babel attached to uncommitted node {node} Link: {line}')
        return observations

    def execute(self):
        self.prepare()
        for node in sorted(self.topology.active):
            self.add_node(node)
        self.verify()
        if self.tentative_seen != {2, 3}:
            raise AssertionError('did not observe both tentative WG interfaces')
        for node in (2, 3):
            peer = self.uids[5 - node]
            events = [json.loads(line) for line in (self.artifacts / f'node-{node}.log').read_text().splitlines()
                      if line.startswith('{')]
            if not any(e.get('event') == 'velvet-udp-probe' and e.get('status') == 'handoff'
                       and e.get('remote_uid') == peer for e in events):
                raise AssertionError('test did not reach real UDP-to-WG handoff')
            if not any(e.get('event') == 'velvet-dynamic-attempt' and e.get('status') == 'failed'
                       and e.get('remote_uid') == peer for e in events):
                raise AssertionError('test did not exercise failed final Link validation')
            if any(e.get('event') == 'velvet-dynamic-link-established'
                   and e.get('remote_uid') == peer for e in events):
                raise AssertionError('the deliberately blocked Link committed')
        self.record('complete', result='PASS', check='uncommitted WG excluded from Babel; routed fallback verified')


if __name__ == '__main__':
    netns.Runner = CommitRunner
    raise SystemExit(netns.main())
