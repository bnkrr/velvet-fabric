"""Negative controls for coverage claims and partition expectations."""
from itertools import product
import unittest
from cases import catalog, PROFILES, pair_requirements
from run import DirectedTopology
from advanced import await_event
from resources import assert_quiescent, classify_socket
from model import process_fd_limit


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


if __name__ == '__main__':
    unittest.main()
