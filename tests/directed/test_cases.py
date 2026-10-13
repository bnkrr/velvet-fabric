"""Negative controls for coverage claims and partition expectations."""
from itertools import product
import copy
import unittest
from cases import catalog, PROFILES, pair_requirements
from run import DirectedTopology
from advanced import await_event
from resources import assert_quiescent, classify_socket
from scenarios import delete_table
from model import NotConverged, audit, prefix, process_fd_limit
from test_model import observation_fixture


class CoverageTests(unittest.TestCase):
    def test_matrix_covers_every_profile_pair_including_same_profile(self):
        covered = set()
        for name, case in catalog().items():
            if not name.startswith('matrix-'):
                continue
            profiles = case['profiles']
            self.assertLessEqual(len(profiles) + 2, 16)
            covered.update((a, b) for i, a in enumerate(profiles) for j, b in enumerate(profiles) if i != j)
        self.assertEqual(covered, set(product(PROFILES, repeat=2)))

    def test_predictive_nat_does_not_inherit_guaranteed_direct_requirement(self):
        profiles = [('eim', 'apdf', 'preserve'), ('eim', 'adf', 'preserve'),
                    ('apdm', 'apdf', 'random')]
        self.assertEqual(pair_requirements(profiles), {(2, 3), (3, 2)})
        t = DirectedTopology(profiles)
        self.assertIn(4, t.required(1))  # Single public remains required.
        self.assertNotIn(4, t.required(2))
        self.assertEqual(pair_requirements([('eim', 'apdf', 'random'), ('eim', 'adf', 'sequential')]),
                         {(2, 3), (3, 2)})
        t.modes[3] = 'off'
        self.assertNotIn(3, t.required(2))

    def test_partition_keeps_configured_receivers_but_changes_reachability(self):
        t = DirectedTopology([('eim', 'eif', 'preserve')] * 2)
        t.boot[3] = 1
        configured = {n: t.configured(n) for n in t.active}
        t.groups = ({0, 2}, {1, 3})
        self.assertEqual(t.components(), {0: {0, 2}, 2: {0, 2}, 1: {1, 3}, 3: {1, 3}})
        self.assertEqual(configured, {n: t.configured(n) for n in t.active})
        for node, group in t.components().items():
            self.assertLessEqual(t.required(node), group - {node})
            self.assertLessEqual(set(t.static_links(node).values()), group - {node})
        t.groups = None
        self.assertIn(1, t.required(0))
        self.assertIn(3, t.required(2))

    def test_without_fault_groups_reachability_follows_actual_bootstrap_graph(self):
        t = DirectedTopology([('eim', 'eif', 'preserve')] * 2)
        self.assertEqual(t.components()[2], {0, 1, 2, 3})
        t.boot[1], t.boot[3] = None, 1
        self.assertEqual(t.components(), {0: {0, 2}, 2: {0, 2}, 1: {1, 3}, 3: {1, 3}})
        self.assertEqual(t.required(2), {0})
        self.assertEqual(t.required(3), {1})

    def test_partition_keeps_only_proven_inactive_neighbor_fallbacks(self):
        t = DirectedTopology([('eim', 'eif', 'preserve')] * 2)
        t.boot[3] = 1
        _, observations = observation_fixture(topology=t)
        owners = {link['public']: node for node, obs in observations.items() for link in obs['wg'].values()}
        t.groups = ({0, 2}, {1, 3})
        for node, obs in observations.items():
            group = t.components()[node]
            obs['fib'] = [route for route in obs['fib'] if route['dst'] in {prefix(n) for n in group}]
            obs.update(ifindices={}, materialized_ifindices=[])
            runtime = obs['status']['runtime']
            runtime['links'] = []
            runtime['established_links'] = len(t.static_links(node))
            for index, (name, link) in enumerate(obs['wg'].items(), 1):
                peer = link['peers'][0]
                remote = owners[peer['public']]
                if remote in group or not peer['handshake']:
                    continue
                obs['ifindices'][name] = index
                obs['materialized_ifindices'].append(index)
                runtime['links'].append({'interface': name, 'active': False, 'committed': True})
                runtime['dynamic_links'] -= int(name.startswith('vdl-'))
                obs['fib'].append({'dst': prefix(remote), 'dev': name, 'protocol': 202, 'metric': 131008})
        self.assertEqual(set(audit(t, observations)), {(0, 2), (2, 0), (1, 3), (3, 1)})
        # Both ends still exist and retain reciprocal WG interfaces. This does
        # not authorize a stale Babel route, a preferred fallback or a new Link.
        for mutation in ('protocol', 'metric', 'gateway', 'multipath', 'active', 'committed', 'incarnation'):
            broken = copy.deepcopy(observations)
            item = broken[0]
            route = next(route for route in item['fib'] if route['dev'] == 'vdl-3')
            state = next(state for state in item['status']['runtime']['links'] if state['interface'] == 'vdl-3')
            if mutation == 'protocol': route['protocol'] = 203
            elif mutation == 'metric': route['metric'] = 1
            elif mutation == 'gateway': route['gateway'] = 'fe80::1'
            elif mutation == 'multipath': route['multipath'] = [{'dev': 'vdl-3'}]
            elif mutation == 'active': state['active'] = True
            elif mutation == 'committed': state['committed'] = False
            else: item['materialized_ifindices'] = []
            with self.subTest(mutation=mutation), self.assertRaises(NotConverged):
                audit(t, broken)

    def test_observer_resource_checks_reject_leaked_sockets_and_unbounded_growth(self):
        snapshot = dict(fds=50, probe_listeners=[], routed_inbound=[])
        assert_quiescent(snapshot, 14)
        for field in ('probe_listeners', 'routed_inbound'):
            with self.assertRaises(AssertionError):
                assert_quiescent(dict(snapshot, **{field: ['leaked']}), 14)
        with self.assertRaises(AssertionError):
            assert_quiescent(dict(snapshot, fds=289), 14)
        self.assertEqual(process_fd_limit('velvetd', 14), 288 + 3 * 128)
        self.assertEqual(process_fd_limit('babel', 14), 288)
        self.assertEqual(process_fd_limit('nat', 14), 4112)
        self.assertEqual(classify_socket('udp6', '0' * 32 + ':7918', '07', 'fd78:e2ee::1'), 'probe_listeners')
        self.assertEqual(classify_socket('udp6', '0' * 32 + ':E434', '07', 'fd78:e2ee::1'), 'other')
        self.assertEqual(classify_socket('tcp6', '0' * 32 + ':7918', '0A', 'fd78:e2ee::1'), 'other')
        local = 'EEE278FD000000000000000001000000:E434'
        self.assertEqual(classify_socket('tcp6', local, '01', 'fd78:e2ee::1'), 'routed_inbound')
        self.assertEqual(classify_socket('tcp6', local, '0A', 'fd78:e2ee::1'), 'other')

    def test_phase_trigger_honors_stop_before_waiting_for_logs(self):
        class Cancelled(Exception):
            pass
        class Runner:
            def timeout(self):
                raise Cancelled()
        with self.assertRaises(Cancelled):
            await_event(Runner(), lambda: self.fail('checked predicate after cancellation'), 'unreachable')

    def test_partition_teardown_runs_after_deadline_or_cancellation(self):
        class Runner:
            deadline = 1
            stop_signal = 15

            def run(r, *args):
                self.assertIsNone(r.deadline)
                self.assertIsNone(r.stop_signal)
                self.assertEqual(args, ('nft', 'delete', 'table', 'bridge', 'partition'))

        runner = Runner()
        with self.assertRaisesRegex(TimeoutError, 'original failure'):
            try:
                raise TimeoutError('original failure')
            finally:
                delete_table(runner, None, 'partition', 'bridge')
        self.assertEqual((runner.deadline, runner.stop_signal), (1, 15))


if __name__ == '__main__':
    unittest.main()
