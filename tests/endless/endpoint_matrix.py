"""Cold bilateral hints and live endpoint fallback, using real WG and payloads.

A hub and three spokes provide both underlay families. The tested public pair
has no alternate routed path; a ping cannot hide a broken tested Link.
"""
from collections import Counter
import json
import time

from model import NotConverged, parse_wg
from mutations import hold, wait_for
from underlay import sampled_family


CASES = (
    ('passive/4', (), (4,), None),
    ('passive/6', (), (6,), None),
    ('4/4', (4,), (4,), None),
    ('6/6', (6,), (6,), None),
    ('4/6', (4,), (6,), None),
    ('6/4', (6,), (4,), None),
    ('46/64', (4, 6), (6, 4), None),
    ('64/46', (6, 4), (4, 6), None),
    ('dead4/6', (), (4, 6), 4),
    ('dead6/4', (), (6, 4), 6),
    ('all-down/recover', (4, 6), (6, 4), 'all'),
    ('live4/6', (), (4, 6), None),
    ('live6/4', (), (6, 4), None),
    ('live4/6-single', (4,), (6,), 6),
    ('live6/4-single', (6,), (4,), 4),
    ('dynamic-mixed-fallback', (), (4,), None),
)


class EndpointMatrix:
    def write_config(self, node):
        super().write_config(node)
        path = self.runtime / f'{node}.json'
        config = json.loads(path.read_text())
        for peer in config['peers']:
            peer['endpoints'] = []
            if node == 0 and peer['name'] == 'in-1':
                peer['endpoints'] = [self.endpoint(1, 51001, f) for f in self.case[1]]
            if peer['name'] == 'bootstrap':
                order = (6,)
                if node == 1:
                    order = self.case[2]
                elif node == 2 and self.case[0] != 'dynamic-mixed-fallback':
                    order = (4,)
                peer['endpoints'] = [self.endpoint(0, 52000 + node, f) for f in order]
        path.write_text(json.dumps(config))

    def on_event(self, node, event):
        if (self.case[0] == 'dynamic-mixed-fallback' and node in (1, 2)
                and event.get('event') == 'velvet-dynamic-attempt'
                and event.get('status') == 'failed'
                and event.get('error') == 'UDP discovery: no-progress'
                and event.get('remote_uid') == self.uids[3 - node]):
            self.failed_attempts[node] += 1

    def routed_fallback(self):
        # This bounded case checks the existing protocol limitation explicitly;
        # the normal mixed membership oracle still requires public direct Links.
        wait_for(self, lambda: all(self.failed_attempts[n] for n in (1, 2)), 90,
                 'mixed-family dynamic discovery did not reach a terminal result')
        self.verify()
        probes = []
        for source, target in ((1, 2), (2, 1)):
            before = self.endpoint_sample(source, target)
            assert before['dev'] == 'vl-boot-00' and before['public'] == self.pubs[0], 'expected routed fallback through hub'
            assert self.ping(source, target), 'failed discovery interrupted routed traffic'
            if self.access:
                self.access.probe(source, target)
            after = self.endpoint_sample(source, target)
            probes.append({'source': source, 'target': target, 'via': 0,
                           'family': sampled_family(before, after), 'endpoint': after['endpoint'],
                           'rx_delta': after['rx'] - before['rx'], 'tx_delta': after['tx'] - before['tx']})
        return {'outcome': 'routed-fallback; dynamic cross-family discovery unsupported',
                'failed_attempts': dict(self.failed_attempts), 'fallback_probes': probes}

    def start_daemon(self, node):
        # Install cold faults before either endpoint can exchange a packet.
        if node == 1 and self.case[3] is not None:
            self.block(self.case[3])
        super().start_daemon(node)

    def block(self, family):
        self.ns(1, 'nft', '-f', '-', input='''table inet endpoint_fault {
 counter hits { }
 chain output { type filter hook output priority -30; policy accept;
  %s udp sport 51001 udp dport 52001 counter name hits drop
 }
 chain input { type filter hook input priority -30; policy accept;
  %s udp sport 52001 udp dport 51001 counter name hits drop
 }
}''' % ((f'meta nfproto ipv{family}' if family != 'all' else '',) * 2))

    def fault_hits(self):
        data = json.loads(self.ns(1, 'nft', '-j', 'list', 'table', 'inet', 'endpoint_fault'))
        return sum(e.get('counter', {}).get('packets', 0) for e in data['nftables'])

    def pair_probes(self, expected=None):
        result = []
        for source, target, dev in ((0, 1, 'vl-in-01'), (1, 0, 'vl-boot-00')):
            before = self.endpoint_sample(source, target)
            if before['dev'] != dev:
                raise AssertionError('endpoint matrix traffic bypassed tested static Link')
            if not self.ping(source, target):
                raise NotConverged('tested static Link has no bidirectional payload')
            if self.access:
                self.access.probe(source, target)
            after = self.endpoint_sample(source, target)
            family = sampled_family(before, after)
            if expected and family != f'ipv{expected}':
                raise NotConverged(f'expected IPv{expected} endpoint, got {after["endpoint"]}')
            result.append({'source': source, 'target': target, 'interface': dev,
                           'endpoint': after['endpoint'], 'family': family,
                           'rx_delta': after['rx'] - before['rx'], 'tx_delta': after['tx'] - before['tx']})
        return result

    def live_fallback(self, family):
        before = self.pair_probes(family)
        processes = {n: (info['proc'].pid, info['resources']['babel']['pid']) for n, info in self.nodes.items()}
        generations = {n: self.command(n)['config_generation'] for n in self.nodes}
        self.block(family)
        started = time.monotonic()
        try:
            # Current policy: stale handshake after 180s, candidate rotation
            # every 15s, then VFP/Babel recovery. Do not reset/reload the daemon
            # or rewrite WG endpoints to make this test pass faster.
            def switched():
                try:
                    self.pair_probes(10 - family)
                    return True
                except (NotConverged, RuntimeError):
                    return False
            wait_for(self, switched, 300, f'live IPv{family} endpoint did not fall back')
            hits = self.fault_hits()
            assert hits > 0, 'runtime fault did not intercept traffic'
            self.verify()
            after = self.pair_probes(10 - family)
            for n, (velvet, babel) in processes.items():
                assert self.nodes[n]['proc'].pid == velvet
                assert self.nodes[n]['resources']['babel']['pid'] == babel
                assert self.command(n)['config_generation'] == generations[n], 'failover reloaded configuration'
            return {'before': before, 'after': after, 'fault_packets': hits,
                    'recovery_seconds': round(time.monotonic() - started, 3)}
        finally:
            self.deadline = None
            self.ns(1, 'nft', 'delete', 'table', 'inet', 'endpoint_fault')

    def execute(self):
        self.prepare()
        results = []
        cases = [c for c in CASES if not self.args.endpoint_case or c[0] in self.args.endpoint_case]
        for self.round, self.case in enumerate(cases):
            name, left, right, fault = self.case
            self.phase = 'endpoints:' + name
            self.failed_attempts = Counter()
            self.topology.modes = {n: 'active' if name == 'dynamic-mixed-fallback' and n in (1, 2) else 'off'
                                   for n in self.topology.active}
            self.record('endpoint-case-start', left=list(left), right=list(right), fault=fault)
            self.deadline = time.monotonic() + self.args.settle_timeout
            for node in sorted(self.topology.active):
                self.add_node(node)
            details = {}
            if fault == 'all':
                hold(self, 20)
                for node, dev in ((0, 'vl-in-01'), (1, 'vl-boot-00')):
                    peer = parse_wg(self.ns(node, 'wg', 'show', 'all', 'dump'))[dev]['peers'][0]
                    assert peer['handshake'] == 0, 'all-down case established an authenticated session'
                assert not self.ping(0, 1) and not self.ping(1, 0), 'all-down path carried payload'
                details['fault_packets'] = self.fault_hits()
                assert details['fault_packets'] > 0, 'cold fault did not intercept traffic'
                self.ns(1, 'nft', 'delete', 'table', 'inet', 'endpoint_fault')
            self.verify()
            expected = None
            if isinstance(fault, int):
                expected = 10 - fault
            elif not left or left == right and len(left) == 1:
                expected = right[0]
            details['probes'] = self.pair_probes(expected)
            if isinstance(fault, int):
                details['fault_packets'] = self.fault_hits()
                assert details['fault_packets'] > 0, 'first candidate was never attempted'
            if name.startswith('live'):
                if isinstance(fault, int):
                    # Pin the initial roaming direction, then fail that path.
                    # The sole surviving hint is on the other address family.
                    details['initial_fault_packets'] = details.pop('fault_packets')
                    self.ns(1, 'nft', 'delete', 'table', 'inet', 'endpoint_fault')
                selected = {p['family'] for p in details['probes']}
                assert len(selected) == 1, 'live fault requires a settled bidirectional endpoint family'
                details.update(self.live_fallback(int(selected.pop()[3:])))
            if name == 'dynamic-mixed-fallback':
                details.update(self.routed_fallback())
            results.append({'case': name, 'left': left, 'right': right, 'result': 'PASS', **details})
            self.save('endpoint-matrix.json', results)
            self.record('endpoint-case-pass', **results[-1])
            self.deadline = time.monotonic() + 60
            for node in sorted(self.nodes):
                self.stop_node(node)
                self.topology.births[node] += 1
            self.deadline = None
        self.record('complete', result='PASS', endpoint_cases=len(results))
