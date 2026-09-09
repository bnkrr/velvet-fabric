"""Negative controls for the independent verifier and NAT packet fixture."""
import copy
import socket
import unittest

from model import Topology, NotConverged, audit, parse_wg, prefix, is_babel_check
from nat import admits, decode, encode, mapping_key, checksum


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


if __name__ == '__main__':
    unittest.main()


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
