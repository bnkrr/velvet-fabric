"""Dual-stack configuration and negative controls for actual family coverage."""
import json
from collections import Counter
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from coverage_model import Coverage
from endpoint_matrix import CASES, EndpointMatrix
from model import NotConverged, Topology, audit
from netns import Runner
from test_model import observation_fixture
from underlay import candidate_order, endpoint_family, sampled_family


class UnderlayTests(unittest.TestCase):
    def runner(self, mode, directory):
        r = Runner.__new__(Runner)
        r.args = SimpleNamespace(underlay=mode, babel=Path('/opt/babel-rs'))
        r.topology = Topology(6, 3, 1)
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

    def test_only_unchanged_bidirectional_payload_path_counts(self):
        for endpoint in ('192.0.2.1:52001', '[2001:db8:ee::1]:52001'):
            before = {'dev': 'vdl-peer', 'public': 'peer-key', 'endpoint': endpoint,
                      'handshake': 100, 'rx': 100, 'tx': 200}
            after = {**before, 'rx': 300, 'tx': 400}
            self.assertEqual(sampled_family(before, after), endpoint_family(endpoint))
            for changed in ({'dev': 'vl-other'}, {'public': 'wrong-peer'}, {'handshake': 0},
                            {'endpoint': '192.0.2.9:52001'}, {'rx': 100}, {'tx': 0}):
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
