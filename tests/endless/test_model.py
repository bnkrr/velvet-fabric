"""Negative controls for the independent verifier and NAT packet fixture."""
import copy
import json
import socket
import unittest
from unittest.mock import Mock, patch

from model import Topology, PendingLinks, NotConverged, audit, parse_wg, prefix, is_babel_check, nat_heartbeat_fresh
from nat import admits, decode, encode, mapping_key, checksum
from coverage_model import Coverage
from netns import Runner
from check_commit import CommitRunner


def observation_fixture(dynamic=True):
    topology = Topology(6, 3, 1, dynamic)
    observations = {}
    for node in topology.active:
        wg = {}
        static = topology.static_links(node)
        for name, remote in topology.configured(node).items():
            wg[name] = {'public': f'static-{node}', 'port': 51000 + node, 'peers': [
                {'public': f'static-{remote}', 'handshake': 100 if name in static else 0,
                 'allowed': ['0.0.0.0/0', '::/0']}]}
        peers = set(static.values())
        optional = (topology.active - {node} if node in topology.public else topology.active & topology.public) if dynamic else set()
        neighbors = topology.required(node) | optional
        for remote in neighbors - peers:
            wg[f'vdl-{remote}'] = {'public': f'dynamic-{node}-{remote}', 'port': 31000 + remote, 'peers': [
                {'public': f'dynamic-{remote}-{node}', 'handshake': 100, 'allowed': ['0.0.0.0/0', '::/0']}]}
        observations[node] = {'wg': wg, 'fib': [], 'main': [
            {'dst': prefix(node), 'dev': 'vv-loop', 'protocol': 'kernel'}], 'status': {'runtime': {
                'established_links': len(static), 'dynamic_links': len(neighbors - peers),
                'babel': {'state': 'running'}}}}
    for node in topology.active:
        first = {remote: name for name, remote in topology.static_links(node).items()}
        first.update({remote: f'vdl-{remote}' for remote in topology.required(node) - set(first)})
        for remote in topology.components()[node] - {node}:
            paths = [(node, [])]
            seen = set()
            while paths:
                current, path = paths.pop(0)
                if current == remote:
                    observations[node]['fib'].append({'dst': prefix(remote), 'dev': first[path[0]], 'metric': 1024})
                    break
                seen.add(current)
                paths.extend((peer, path + [peer]) for peer in topology.required(current) - seen)
    return topology, observations


class OracleTests(unittest.TestCase):
    def test_each_public_nat_pair_is_required(self):
        topology, observations = observation_fixture()
        for node in topology.active - topology.public:
            self.assertTrue(topology.public <= topology.required(node))
            for public in topology.public:
                self.assertIn(node, topology.required(public))
        # Other NATs continue to punch successfully. One lost required pair
        # still fails even if runtime counts honestly omit that pair.
        for node in topology.active - topology.public:
            public = next(p for p in topology.public if p != topology.boot[node])
            broken = copy.deepcopy(observations)
            for a, b in ((node, public), (public, node)):
                del broken[a]['wg'][f'vdl-{b}']
                broken[a]['status']['runtime']['dynamic_links'] -= 1
            with self.assertRaisesRegex(NotConverged, 'missing required neighbors'):
                audit(topology, broken)

    def test_policy_controls_new_link_requirement(self):
        topology = Topology(6, 3, 1)
        node = 2
        public = next(p for p in topology.public if p != topology.boot[node])
        for left in ('active', 'passive', 'off'):
            for right in ('active', 'passive', 'off'):
                topology.modes[node], topology.modes[public] = left, right
                expected = 'off' not in (left, right) and 'active' in (left, right)
                self.assertEqual(topology.want_pair(node, public), expected)
                self.assertEqual(public in topology.required(node), expected)
                self.assertEqual(node in topology.required(public), expected)
                self.assertIn(topology.boot[node], topology.required(node))

    def test_static_peer_cannot_fake_dynamic_reciprocity(self):
        topology, observations = observation_fixture()
        owners = {link['public']: n for n, obs in observations.items() for link in obs['wg'].values()}
        for node, obs in observations.items():
            for link in obs['wg'].values():
                link['public'] = f'node-{node}'
                for peer in link['peers']:
                    peer['public'] = f"node-{owners[peer['public']]}"
        node = 2
        public = topology.boot[node]
        observations[public]['wg'][f'vdl-{node}'] = {
            'public': f'node-{public}', 'port': 33333,
            'peers': [{'public': f'node-{node}', 'handshake': 100, 'allowed': ['0.0.0.0/0', '::/0']}]}
        observations[public]['status']['runtime']['dynamic_links'] += 1
        with self.assertRaisesRegex(NotConverged, 'nonreciprocal WG peer'):
            audit(topology, observations)

    def test_nat_heartbeat_survives_clock_step_but_still_detects_stall(self):
        heartbeat = {'updated_monotonic': 100.0}
        # Replay the observed 8301-second wall-clock step with only 2.6 seconds
        # of elapsed runtime. Backwards steps must not conceal a real stall.
        for wall in (1789036749.0, 1789036749.0 + 8301, 1789036749.0 - 8301):
            with patch('time.time', return_value=wall):
                self.assertTrue(nat_heartbeat_fresh(heartbeat, 102.6))
                self.assertFalse(nat_heartbeat_fresh(heartbeat, 105.1))
        for invalid in ({}, {'updated_monotonic': float('nan')}, {'updated_monotonic': 110}):
            self.assertFalse(nat_heartbeat_fresh(invalid, 102.6))

    def test_public_nat_reachability_and_nat_nat_fallback(self):
        for dynamic in (True, False):
            topology, observations = observation_fixture(dynamic)
            self.assertEqual(len(audit(topology, observations)), 30)

    def test_false_status_cannot_hide_missing_direct_link(self):
        topology, observations = observation_fixture()
        node = 2
        name = next(iter(topology.static_links(node)))
        del observations[node]['wg'][name]
        with self.assertRaises(NotConverged): audit(topology, observations)

    def test_missing_stale_and_dead_fib(self):
        topology, observations = observation_fixture()
        for mutate in (lambda o: o[2]['fib'].pop(),
                       lambda o: o[2]['fib'].append({'dst': 'fd78:e2ee::ffff/128', 'dev': 'dead'}),
                       lambda o: o[2]['fib'][0].update(dev='missing')):
            broken = copy.deepcopy(observations)
            mutate(broken)
            with self.assertRaises(NotConverged): audit(topology, broken)

    def test_uncommitted_wg(self):
        topology, observations = observation_fixture()
        name = next(iter(topology.static_links(2)))
        for field, value in (('handshake', 0), ('allowed', []), ('public', 'unknown')):
            broken = copy.deepcopy(observations)
            broken[2]['wg'][name]['peers'][0][field] = value
            with self.assertRaises(NotConverged): audit(topology, broken)

    def test_fib_cycle(self):
        topology, observations = observation_fixture()
        # NAT slots 2 and 3 legitimately share public 0, but redirect 0's
        # destination-3 route back to 2: every interface exists, path loops.
        route = next(r for r in observations[0]['fib'] if r['dst'] == prefix(3))
        route['dev'] = next(r['dev'] for r in observations[0]['fib'] if r['dst'] == prefix(2))
        with self.assertRaises(NotConverged): audit(topology, observations)

    def test_main_leak(self):
        topology, observations = observation_fixture()
        observations[2]['main'].append({'dst': prefix(3), 'dev': 'wrong', 'protocol': '203'})
        with self.assertRaisesRegex(NotConverged, 'main table'): audit(topology, observations)

    def test_secret_redaction(self):
        result = parse_wg('vl-a\tPRIVATE\tPUBLIC\t123\toff\nvl-a\tPEER\tPSK\t192.0.2.1:12\t::/0\t1\t2\t3\t0\n')
        self.assertNotIn('PRIVATE', str(result))
        self.assertNotIn('PSK', str(result))

    def test_arbitrary_public_bootstrap_and_public_churn(self):
        left, right = Topology(16, 8, 1), Topology(16, 8, 1)
        removed_public, chosen_public, profiles = set(), set(), set()
        for _ in range(1000):
            before = left.active.copy()
            event = left.next_event()
            self.assertEqual(event, right.next_event())
            self.assertTrue(8 <= len(left.active) <= 16)
            self.assertTrue(left.public & left.active)
            if event['operation'] == 'add':
                self.assertIn(event['bootstrap'], before & left.public)
                chosen_public.add(event['bootstrap'])
                if event['profile']: profiles.add(tuple(event['profile']))
            elif event['node'] in left.public:
                removed_public.add(event['node'])
        self.assertEqual(removed_public, left.public)
        self.assertEqual(chosen_public, left.public)
        self.assertEqual(len(profiles), 36)


class NATTests(unittest.TestCase):
    def test_mapping_dimensions(self):
        local = ('10.0.0.2', 30000)
        peers = [('192.0.2.1', 10), ('192.0.2.1', 20), ('192.0.2.2', 10)]
        for mode, count in (('eim', 1), ('adm', 2), ('apdm', 3)):
            self.assertEqual(len({mapping_key(local, peer, mode) for peer in peers}), count)

    def test_filter_dimensions(self):
        sent = {('192.0.2.1', 10)}
        probes = [('192.0.2.1', 10), ('192.0.2.1', 20), ('192.0.2.2', 10)]
        for mode, expected in (('eif', [True, True, True]), ('adf', [True, True, False]), ('apdf', [True, False, False])):
            self.assertEqual([admits(peer, sent, mode) for peer in probes], expected)

    def test_packet_roundtrip_and_ip_checksum(self):
        for src, dst in (('192.0.2.1', '10.0.0.2'), ('2001:db8::1', 'fd00::2')):
            frame = encode((src, 30000), (dst, 40000), b'odd payload', b'123456', b'abcdef')
            packet = decode(frame)
            self.assertEqual(packet[:3], ((src, 30000), (dst, 40000), b'odd payload'))
            if ':' not in src:
                self.assertEqual(checksum(frame[14:34]), 0)
            self.assertIsNone(decode(frame[:-1]))


class ProcessIdentityTests(unittest.TestCase):
    def test_only_exact_supervised_babel_check_is_transient(self):
        argv = ['/opt/babel-rs', 'check', '--config', '/run/velvet/node/babel-rs.toml']
        def accepts(parent=10, executable='/opt/babel-rs', command=None):
            return is_babel_check(parent, executable, argv if command is None else command,
                                  10, '/opt/babel-rs', '/run/velvet/node/babel-rs.toml')
        self.assertTrue(accepts())
        self.assertFalse(accepts(parent=1))  # orphan / unrelated parent
        self.assertFalse(accepts(executable='/bin/sleep'))  # forged argv
        self.assertFalse(accepts(command=[argv[0], 'run', '--config', argv[3]]))
        self.assertFalse(accepts(command=[*argv[:3], '/tmp/other.toml']))
        self.assertFalse(accepts(command=[*argv, '--extra']))


class EvidenceTests(unittest.TestCase):
    def test_commit_negative_control_survives_transient_base_audit(self):
        runner = CommitRunner.__new__(CommitRunner)
        runner.latest = {2: {'wg': {'vdl-n3-test': {}}}}
        runner.tentative_seen, runner.failed_seen = set(), set()
        runner.ns = Mock(return_value='UNCONN 0 0 [fe80::1%vdl-n3-test]:6696 [::]:*')
        with patch.object(Runner, 'observe', side_effect=NotConverged('tentative WG entered FIB')):
            with self.assertRaisesRegex(AssertionError, 'Babel attached to uncommitted'):
                runner.observe()

    def test_pending_incarnation_must_retire_without_entering_routing(self):
        obs = {0: {'wg': {'vdl-a': {'public': '(none)', 'peers': []}},
                   'fib': [], 'ifindices': {'vdl-a': 10}, 'babel_sockets': '',
                   'materialized_ifindices': []}}
        tracker = PendingLinks()
        tracker.observe(obs, 1)
        tracker.observe(obs, 90)
        with self.assertRaisesRegex(AssertionError, 'exceeded 90s'):
            tracker.observe(obs, 92)
        # A real deletion/recreation has another kernel ifindex.
        obs[0]['ifindices']['vdl-a'] = 11
        tracker.observe(obs, 92)
        self.assertEqual(len(tracker.since), 1)
        for fib, sockets in (([{'dev': 'vdl-a', 'protocol': 203}], ''),
                             ([], 'UNCONN 0 0 [fe80::1%vdl-a]:6696 [::]:*')):
            obs[0].update(fib=fib, babel_sockets=sockets)
            with self.assertRaises(NotConverged):
                tracker.observe(obs, 93)
        obs[0].update(fib=[{'dev': 'vdl-a', 'protocol': 202}], babel_sockets='', materialized_ifindices=[11])
        tracker.observe(obs, 94)
        self.assertEqual(obs[0]['pending'], [])
        self.assertEqual(tracker.since, {})

    def test_failed_admission_does_not_reset_any_pending_lifetime(self):
        obs = {node: {'wg': {'vdl-a': {}}, 'fib': [], 'ifindices': {'vdl-a': 10},
                      'babel_sockets': '', 'materialized_ifindices': []} for node in (0, 1)}
        obs[0]['fib'] = [{'dev': 'vdl-a', 'protocol': 203}]
        tracker = PendingLinks()
        for now in (1, 60):
            with self.assertRaisesRegex(NotConverged, 'entered FIB'):
                tracker.observe(obs, now)
        self.assertEqual(tracker.since, {(0, 10): 1, (1, 10): 1})
        tracker.forget(0)
        self.assertEqual(tracker.since, {(1, 10): 1})
        del obs[0]
        with self.assertRaisesRegex(AssertionError, 'exceeded 90s'):
            tracker.observe(obs, 92)

    def test_pending_does_not_satisfy_a_required_peer(self):
        topology, observations = observation_fixture()
        node = 2
        public = next(p for p in topology.public if p != topology.boot[node])
        for a, b in ((node, public), (public, node)):
            observations[a]['pending'] = [f'vdl-{b}']
            observations[a]['status']['runtime']['dynamic_links'] -= 1
        with self.assertRaisesRegex(NotConverged, 'missing required neighbors'):
            audit(topology, observations)

    def test_coverage_distinguishes_real_probe_direction_and_fallback(self):
        topology, observations = observation_fixture()
        audit(topology, observations)
        coverage = Coverage('ipv6')
        self.assertEqual(coverage.state()['matrix'], [])
        coverage.ping(2, 3)
        coverage.proposed(1, 2)
        coverage.verified(topology, observations)
        self.assertEqual(len(coverage.pairs), 30)
        self.assertEqual(coverage.pairs[2, 3]['outcome'], 'fallback')
        self.assertEqual(coverage.pairs[2, 3]['successful_pings'], 1)
        self.assertEqual(coverage.pairs[3, 2]['successful_pings'], 0)
        self.assertEqual(coverage.pairs[2, 1]['remote_proposals'], 1)
        self.assertEqual(coverage.pairs[2, 1]['local_proposals'], 0)
        self.assertTrue(all(row['family'] == 'ipv6' for row in coverage.state()['matrix']))
        coverage.reset(2)
        self.assertFalse(any(2 in pair for pair in coverage.pairs))
        self.assertEqual(coverage.probes[2, 3], 0)
        self.assertEqual(coverage.proposals[1, 2], 0)

    def test_partial_observations_survive_a_later_read_failure(self):
        runner = Runner.__new__(Runner)
        runner.capture, runner.round, runner.phase, runner.started = None, 12, 'control-loss', 0
        runner.latest, runner.snapshots = {}, Mock()
        def partial():
            runner.latest[0] = {'wg': parse_wg('vdl-a\tPRIVATE\tPUBLIC\t123\toff\n')}
            raise NotConverged('node 1 not ready')
        runner._observe = partial
        with self.assertRaises(NotConverged):
            runner.observe()
        raw = runner.snapshots.info.call_args.args[0]
        entry = json.loads(raw)
        self.assertEqual(entry['round'], 12)
        self.assertEqual(entry['phase'], 'control-loss')
        self.assertIn('0', entry['observations'])
        self.assertNotIn('PRIVATE', raw)

    def test_dead_capture_cannot_pass_as_evidence(self):
        runner = Runner.__new__(Runner)
        runner.capture = Mock()
        runner.capture.poll.return_value = 1
        runner.round, runner.phase, runner.started = 0, 'membership', 0
        runner.latest, runner.snapshots, runner._observe = {}, Mock(), Mock()
        with self.assertRaisesRegex(RuntimeError, 'capture exited'):
            runner.observe()
        runner._observe.assert_not_called()


if __name__ == '__main__':
    unittest.main()
