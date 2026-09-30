"""Dual-stack configuration and negative controls for actual family coverage."""
import copy
import json
from collections import Counter
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from coverage_model import Coverage
from endpoint_matrix import CASES, EndpointMatrix
from model import NotConverged, Topology, audit, prefix
from netns import Runner
from test_model import observation_fixture
from underlay import candidate_order, endpoint_family, sampled_family


class UnderlayTests(unittest.TestCase):
    def test_mixed_churn_preserves_family_listeners_and_all_slots_can_leave(self):
        topology = Topology(8, 3, 1, underlay='dual')
        removed, added, partitioned = set(), set(), False
        for _ in range(2000):
            event = topology.next_event()
            (removed if event['operation'] == 'delete' else added).add(event['node'])
            for family in (4, 6):
                self.assertTrue(any(topology.discovery_family[n] == family for n in topology.active & topology.public))
            if event['operation'] == 'add':
                node = event['node']
                self.assertIn(topology.boot[node], topology.bootstrap_candidates(node, topology.active & topology.public))
            partitioned |= len(topology.components()[min(topology.active)]) != len(topology.active)
        self.assertEqual(removed, set(range(8)))
        self.assertEqual(added, removed)
        self.assertTrue(partitioned)

    def test_mixed_routes_require_same_family_direct_and_cross_family_transit(self):
        topology, observations = observation_fixture(topology=Topology(8, 3, 1, underlay='dual'))
        self.assertEqual(len(audit(topology, observations)), 56)
        coverage = Coverage('dual')
        coverage.verified(topology, observations)
        self.assertEqual(coverage.pairs[6, 7]['requirement'], 'relay')
        self.assertEqual(coverage.pairs[6, 7]['outcome'], 'fallback')
        peer = next(n for n in (2, 4) if n != topology.boot[6])
        broken = copy.deepcopy(observations)
        for a, b in ((6, peer), (peer, 6)):
            del broken[a]['wg'][f'vdl-{b}']
            broken[a]['status']['runtime']['dynamic_links'] -= 1
        with self.assertRaisesRegex(NotConverged, 'missing required neighbors'):
            audit(topology, broken)
        for node in (6, 7):
            broken = copy.deepcopy(observations)
            broken[node]['fib'] = [r for r in broken[node]['fib'] if r['dst'] != prefix(13 - node)]
            with self.assertRaises(NotConverged):
                audit(topology, broken)

    def test_mixed_components_follow_inputs_when_transit_disappears(self):
        topology = Topology(8, 3, 1, underlay='dual')
        topology.active -= topology.transit
        self.assertEqual(topology.components()[6], {2, 4, 6})
        self.assertEqual(topology.components()[7], {3, 5, 7})
        topology, observations = observation_fixture(topology=topology)
        self.assertEqual(len(audit(topology, observations)), 12)
        observations[6]['fib'].append({'dst': prefix(7), 'dev': observations[6]['fib'][0]['dev'], 'metric': 1024})
        with self.assertRaises(NotConverged):
            audit(topology, observations)

    def test_ten_slots_include_optional_nat_pairs_in_each_family(self):
        topology, observations = observation_fixture(topology=Topology(10, 6, 1, underlay='dual'))
        self.assertEqual(len(audit(topology, observations)), 90)
        for left, right in ((6, 8), (7, 9)):
            self.assertTrue(topology.dynamic_pair(left, right))
            self.assertNotIn(right, topology.required(left))
            self.assertIn(right, topology.components()[left])

    def test_mixed_audit_rejects_wrong_kernel_endpoint_family(self):
        topology, observations = observation_fixture(topology=Topology(8, 3, 1, underlay='dual'))
        name = next(name for name in observations[6]['wg'] if name.startswith('vdl-'))
        observations[6]['wg'][name]['peers'][0]['endpoint'] = '[2001:db8::1]:52000'
        with self.assertRaisesRegex(NotConverged, 'endpoint escaped fixture family'):
            audit(topology, observations)

    def test_mixed_audit_rejects_an_automatic_cross_family_link(self):
        topology, observations = observation_fixture(topology=Topology(8, 3, 1, underlay='dual'))
        for node, peer in ((6, 3), (3, 6)):
            observations[node]['wg'][f'vdl-{peer}'] = {
                'public': f'dynamic-{node}-{peer}', 'port': 31000 + peer, 'peers': [
                    {'public': f'dynamic-{peer}-{node}', 'handshake': 100, 'allowed': ['0.0.0.0/0', '::/0']}]}
        with self.assertRaisesRegex(NotConverged, 'crossed discovery families'):
            audit(topology, observations)

    def test_mixed_configs_pin_discovery_but_transit_retains_bilateral_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            r = self.runner('dual', directory)
            r.topology = Topology(8, 3, 1, underlay='dual')
            for attr in ('wan_epochs', 'uids', 'keys', 'pubs'):
                getattr(r, attr).update({n: 0 if attr == 'wan_epochs' else f'test-{n}' for n in (6, 7)})
            for node in range(8):
                r.write_config(node)
                config = json.loads((r.runtime / f'{node}.json').read_text())
                family = r.topology.discovery_family[node]
                if family:
                    self.assertEqual(config['dynamic_links']['allow_candidate_prefixes'],
                                     ['192.0.2.0/24' if family == 4 else '2001:db8:ee::/64'])
                    for peer in config['peers']:
                        self.assertTrue(all(endpoint_family(ep) == f'ipv{family}' for ep in peer['endpoints']))
                else:
                    self.assertEqual(config['dynamic_links']['mode'], 'off')
            self.assertEqual(tuple(map(endpoint_family, r.bootstrap_endpoints(1, 0))), ('ipv6',))
            self.assertEqual(tuple(map(endpoint_family, r.receiver_endpoints(0, 1))), ('ipv4',))

    def runner(self, mode, directory):
        r = Runner.__new__(Runner)
        r.args = SimpleNamespace(underlay=mode, babel=Path('/opt/babel-rs'))
        r.topology = Topology(6, 3, 1, dynamic=False, underlay=mode)
        r.wan_epochs = {node: 0 for node in range(6)}
        r.uids = {node: f'node-{node}' for node in range(6)}
        r.keys = r.pubs = {node: f'key-{node}' for node in range(6)}
        r.runtime, r.psk, r.access = Path(directory), 'test-psk', None
        return r

    def test_dual_hints_cover_all_orders_and_independent_bilateral_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            r = self.runner('dual', directory)
            for node in (0, 1, 2, 3):
                seen = set()
                for birth in range(4):
                    r.topology.births[node] = birth
                    r.write_config(node)
                    config = json.loads((r.runtime / f'{node}.json').read_text())
                    name = 'in-1' if node == 0 else 'bootstrap'
                    endpoints = next(p for p in config['peers'] if p['name'] == name)['endpoints']
                    seen.add(tuple(endpoint_family(x) for x in endpoints))
                    self.assertEqual(config['dynamic_links']['allow_candidate_prefixes'],
                                     ['192.0.2.0/24', '2001:db8:ee::/64'])
                self.assertEqual(seen, {('ipv4',), ('ipv6',), ('ipv4', 'ipv6'), ('ipv6', 'ipv4')})
            self.assertEqual(r.receiver_endpoints(0, 2), [])  # NAT ports must be learned, never invented.
            r.topology.births[0] = r.topology.births[1] = 0
            self.assertEqual(candidate_order('dual', 0, 0), (4,))
            self.assertEqual(candidate_order('dual', 1, 0), (6,))
            r.wan_epochs[0] = 1
            self.assertEqual(r.wan(0, 4), '192.0.2.129')
            self.assertEqual(r.wan(0, 6), '2001:db8:ee::81')

    def test_single_family_configurations_remain_single(self):
        with tempfile.TemporaryDirectory() as directory:
            for mode in ('ipv4', 'ipv6'):
                r = self.runner(mode, directory)
                r.write_config(2)
                config = json.loads((r.runtime / '2.json').read_text())
                endpoints = config['peers'][0]['endpoints']
                self.assertEqual(len(endpoints), 1)
                self.assertEqual(endpoint_family(endpoints[0]), mode)
                self.assertEqual(len(config['dynamic_links']['allow_candidate_prefixes']), 1)

    def test_only_unchanged_outgoing_payload_path_counts(self):
        for endpoint in ('192.0.2.1:52001', '[2001:db8:ee::1]:52001'):
            before = {'dev': 'vdl-peer', 'public': 'peer-key', 'endpoint': endpoint,
                      'handshake': 100, 'rx': 100, 'tx': 200}
            after = {**before, 'rx': 300, 'tx': 400}
            self.assertEqual(sampled_family(before, after), endpoint_family(endpoint))
            self.assertEqual(sampled_family(before, {**after, 'rx': 100}), endpoint_family(endpoint))
            for changed in ({'dev': 'vl-other'}, {'public': 'wrong-peer'}, {'handshake': 0},
                            {'endpoint': '192.0.2.9:52001'}, {'rx': 99}, {'tx': 200}, {'tx': 0}):
                with self.subTest(endpoint=endpoint, changed=changed):
                    with self.assertRaises(NotConverged):
                        sampled_family(before, {**after, **changed})

    def test_configured_dual_does_not_claim_both_payload_families(self):
        coverage = Coverage('dual')
        for family in (None, 'ipv4'):
            coverage.ping(1, 2, endpoint_family=family)
            with self.assertRaises(NotConverged):
                coverage.require_families()
        coverage.ping(2, 1, endpoint_family='ipv6')
        coverage.require_families()
        self.assertEqual(coverage.state()['endpoint_probes'], {'ipv4': 1, 'ipv6': 1})

    def test_fallback_family_comes_from_selected_hop(self):
        topology, observations = observation_fixture()
        audit(topology, observations)
        for obs in observations.values():
            for link in obs['wg'].values():
                link['peers'][0]['endpoint'] = '192.0.2.1:52001'
        route = next(x for x in observations[2]['fib'] if x['dst'] == 'fd78:e2ee::4/128')
        # iproute2 renders host routes without /128 on real kernels.
        route['dst'] = 'fd78:e2ee::4'
        observations[2]['wg'][route['dev']]['peers'][0]['endpoint'] = '[2001:db8:ee::1]:52001'
        coverage = Coverage('dual')
        coverage.verified(topology, observations)
        self.assertEqual(coverage.pairs[2, 3]['outcome'], 'fallback')
        self.assertEqual(coverage.pairs[2, 3]['endpoint_family'], 'ipv6')
        self.assertEqual(coverage.state()['endpoint_probes'], {})

    def test_endpoint_matrix_has_exact_bilateral_hints_without_extra_active_receivers(self):
        class Matrix(EndpointMatrix, Runner):
            pass
        with tempfile.TemporaryDirectory() as directory:
            r = Matrix.__new__(Matrix)
            r.__dict__.update(self.runner('dual', directory).__dict__)
            for case in CASES:
                r.case = case
                for node in (0, 1):
                    r.write_config(node)
                    config = json.loads((r.runtime / f'{node}.json').read_text())
                    tested = 'in-1' if node == 0 else 'bootstrap'
                    for peer in config['peers']:
                        expected = tuple(f'ipv{f}' for f in case[1 if node == 0 else 2]) if peer['name'] == tested else ()
                        self.assertEqual(tuple(endpoint_family(ep) for ep in peer['endpoints']), expected,
                                         (case[0], node, peer['name']))

    def test_endpoint_matrix_rejects_routed_bypass(self):
        r = EndpointMatrix()
        r.endpoint_sample = lambda *pair: {'dev': 'vdl-bypass'}
        with self.assertRaisesRegex(AssertionError, 'bypassed'):
            r.pair_probes()

    def test_expected_family_limitation_does_not_hide_other_discovery_errors(self):
        r = EndpointMatrix()
        r.case = ('dynamic-mixed-fallback', (), (4,), None)
        r.uids = {1: 'left', 2: 'right'}
        r.failed_attempts = Counter()
        event = {'event': 'velvet-dynamic-attempt', 'status': 'failed', 'remote_uid': 'right',
                 'error': 'UDP discovery: no-progress'}
        r.on_event(1, {**event, 'error': 'UDP discovery: unexpected discovery phase'})
        r.on_event(1, {**event, 'remote_uid': 'other'})
        self.assertFalse(r.failed_attempts)
        r.on_event(1, event)
        self.assertEqual(r.failed_attempts, {1: 1})


if __name__ == '__main__':
    unittest.main()
