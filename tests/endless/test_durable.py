"""Negative controls for persistent listeners, accounting and immutable state."""
import base64
import copy
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import Mock, patch

from coverage_model import Coverage
from durable_model import DurableAudit, agreement
from model import NotConverged, PendingLinks, audit, address, prefix
from netns import Runner
from mutations import policy, direct_pair
from test_model import observation_fixture


def fixture():
    topology, obs = observation_fixture()
    uids = {n: str(uuid.UUID(int=n + 1)) for n in range(topology.size)}
    pubs = {n: base64.b64encode(bytes([n + 1]) * 32).decode() for n in uids}
    node = 2
    peer = next(n for n in topology.public if n != topology.boot[node])
    for n, item in obs.items():
        item.update(durable_records=[], durable_waiting=[], babel_sockets='', materialized_ifindices=[], ifindices={})
        runtime = item['status']['runtime']
        runtime.update(durable=[], durable_links=0, links=[])
        for index, (name, link) in enumerate(item['wg'].items(), 1):
            remote = topology.configured(n)[name] if name.startswith('vl-') else int(name[4:])
            link['public'], link['peers'][0]['public'] = pubs[n], pubs[remote]
            item['ifindices'][name] = index
            item['materialized_ifindices'].append(index)
            runtime['links'].append({'interface': name, 'active': True})
    recovery_endpoint = '192.0.2.2:' + str(obs[peer]['wg'][f'vdl-{node}']['port'])
    for a, b in ((node, peer), (peer, node)):
        record = {'agreement_id': '550e8400-e29b-41d4-a716-446655440000', 'confirmed': True,
                  'local': {'listen_port': obs[a]['wg'][f'vdl-{b}']['port']},
                  'peer': {'uuid': uids[b], 'public_key': pubs[b], 'last_loopback': address(b)}}
        if a == peer:
            record['local']['recovery_endpoint'] = recovery_endpoint
        else:
            record['peer']['recovery_endpoint'] = recovery_endpoint
        obs[a]['durable_records'] = [record]
        runtime = obs[a]['status']['runtime']
        runtime['dynamic_links'] -= 1
        runtime['durable_links'] = 1
        runtime['durable'] = [copy.deepcopy(record)]
    return topology, obs, DurableAudit(uids, pubs), node, peer


class DurableTests(unittest.TestCase):
    def test_direct_pair_checks_selected_path_not_neighbor_fallback_owner(self):
        import json
        r = SimpleNamespace(ip=Mock(), ping=Mock(return_value=True))
        link = {'vdl-peer': {'handshake': 100, 'allowed': ['0.0.0.0/0', '::/0']}}
        with patch('mutations.dynamic', return_value=link):
            for selected, expected in (('vdl-peer', True), ('vl-old', False)):
                routes = [{'protocol': 202, 'metric': 131008, 'dev': 'vl-old'},
                          {'protocol': 203, 'metric': 65631, 'dev': selected}]
                r.ip.return_value = json.dumps(routes)
                self.assertEqual(direct_pair(r, 1, 2), expected)
            r.ip.return_value = '[]'
            self.assertFalse(direct_pair(r, 1, 2))

    def test_confirmed_accounting_and_coverage(self):
        topology, obs, checker, node, peer = fixture()
        checker.observe(topology, obs)
        audit(topology, obs)
        coverage = Coverage('ipv4')
        coverage.verified(topology, obs)
        self.assertEqual(coverage.pairs[node, peer]['outcome'], 'durable')
        obs[node]['status']['runtime']['dynamic_links'] += 1
        with self.assertRaisesRegex(NotConverged, 'counts disagree'):
            audit(topology, obs)

    def waiting(self):
        topology, obs, checker, node, peer = fixture()
        item, name = obs[node], f'vdl-{peer}'
        next(s for s in item['status']['runtime']['links'] if s['interface'] == name)['active'] = False
        item['fib'] = [r for r in item['fib'] if r['dev'] != name]
        obs = {node: item}
        topology.active.remove(peer)
        checker.observe(topology, obs)
        return topology, obs, checker, node, peer

    def test_committed_durable_control_loss_keeps_routing_admission(self):
        topology, obs, checker, node, peer = fixture()
        item, name = obs[node], f'vdl-{peer}'
        state = next(s for s in item['status']['runtime']['links'] if s['interface'] == name)
        state.update(active=False, committed=True)
        item['babel_sockets'] = f'[fe80::1%{name}]:6696'
        checker.observe(topology, obs)
        PendingLinks().observe(obs, 1)
        self.assertNotIn(name, item['pending'])
        self.assertIn(name, item['durable_inactive'])

    def test_offline_saved_listener_can_outlive_attempt(self):
        _, obs, _, node, peer = self.waiting()
        tracker = PendingLinks()
        tracker.observe(obs, 1)
        tracker.observe(obs, 3601)
        self.assertIn(f'vdl-{peer}', obs[node]['pending'])

    def test_saved_listener_does_not_authorize_routes_or_babel(self):
        for leak in ('fib', 'babel'):
            with self.subTest(leak=leak):
                _, obs, _, node, peer = self.waiting()
                name = f'vdl-{peer}'
                if leak == 'fib':
                    obs[node]['fib'].append({'dev': name, 'protocol': 203})
                else:
                    obs[node]['babel_sockets'] = f'[fe80::1%{name}]:6696'
                with self.assertRaises(NotConverged):
                    PendingLinks().observe(obs, 1)

    def test_status_claim_without_disk_does_not_exempt_interface(self):
        topology, obs, checker, node, _ = fixture()
        obs[node]['durable_records'] = []
        with self.assertRaisesRegex(NotConverged, 'disagrees with disk'):
            checker.observe(topology, obs)

    def test_partial_save_is_dynamic_until_confirmation(self):
        topology, obs, checker, node, peer = fixture()
        obs[node]['durable_records'][0]['confirmed'] = False
        runtime = obs[node]['status']['runtime']
        runtime['durable'][0]['confirmed'] = False
        runtime['durable_links'] = 0
        runtime['dynamic_links'] += 1
        checker.observe(topology, obs)
        audit(topology, obs)
        coverage = Coverage('ipv4')
        coverage.verified(topology, obs)
        self.assertEqual(coverage.pairs[node, peer]['outcome'], 'dynamic')

    def test_two_live_records_must_agree(self):
        topology, obs, checker, node, _ = fixture()
        record = obs[node]['durable_records'][0]
        record['agreement_id'] = '6ba7b810-9dad-41d1-80b4-00c04fd430c8'
        obs[node]['status']['runtime']['durable'][0]['agreement_id'] = agreement(record)
        with self.assertRaisesRegex(NotConverged, 'differs between'):
            checker.observe(topology, obs)

    def test_bad_peer_port_and_confirmed_count_are_rejected(self):
        for kind in ('key', 'port', 'count'):
            with self.subTest(kind=kind):
                topology, obs, checker, node, peer = fixture()
                if kind == 'key':
                    obs[node]['durable_records'][0]['peer']['public_key'] = 'wrong'
                elif kind == 'port':
                    obs[node]['wg'][f'vdl-{peer}']['port'] += 1
                else:
                    obs[node]['status']['runtime']['durable_links'] += 1
                with self.assertRaises((AssertionError, NotConverged)):
                    checker.observe(topology, obs)

    def test_same_agreement_cannot_change_recovery_endpoints(self):
        topology, obs, checker, node, _ = fixture()
        checker.observe(topology, obs)
        record = obs[node]['durable_records'][0]
        target = record['local'] if record['local'].get('recovery_endpoint') else record['peer']
        target['recovery_endpoint'] = '192.0.2.99:31002'
        with self.assertRaisesRegex(AssertionError, 'mutated'):
            checker.observe(topology, obs)

    def test_off_cannot_retain_records(self):
        topology, obs, checker, node, _ = fixture()
        topology.modes[node] = 'off'
        with self.assertRaisesRegex(NotConverged, 'off retained'):
            checker.observe(topology, obs)

    def test_range_is_enforced_independently(self):
        topology, obs, checker, node, _ = fixture()
        obs[node]['automatic_ports'] = {'port_range': {'first': 40000, 'last': 40999}}
        with self.assertRaisesRegex(AssertionError, 'escaped'):
            checker.observe(topology, obs)

    def test_pending_still_cannot_satisfy_required_neighbor(self):
        topology, obs, checker, node, peer = fixture()
        item = obs[node]
        name = f'vdl-{peer}'
        next(s for s in item['status']['runtime']['links'] if s['interface'] == name)['active'] = False
        item['fib'] = [r for r in item['fib'] if r['dev'] != name]
        checker.observe(topology, obs)
        PendingLinks().observe(obs, 1)
        with self.assertRaises(NotConverged):
            audit(topology, obs)

    def test_bilateral_waiting_allows_bounded_real_fallback(self):
        topology, obs, checker, node, peer = fixture()
        for a, b in ((node, peer), (peer, node)):
            item, name = obs[a], f'vdl-{b}'
            next(s for s in item['status']['runtime']['links'] if s['interface'] == name)['active'] = False
            for route in item['fib']:
                if route['dev'] == name:
                    route['dev'] = 'vl-boot-00'
        checker.observe(topology, obs, now=1)
        PendingLinks().observe(obs, 1)
        audit(topology, obs)  # Still follows real routes and requires every payload pair.
        self.assertEqual(obs[node]['durable_recovery_peers'], [peer])
        checker.observe(topology, obs, now=1801)
        with self.assertRaisesRegex(AssertionError, 'exceeded failure window'):
            checker.observe(topology, obs, now=1892)

    def asymmetric_recovery(self):
        topology, obs, checker, node, peer = fixture()
        for a, b in ((node, peer), (peer, node)):
            item, name = obs[a], f'vdl-{b}'
            state = next(s for s in item['status']['runtime']['links'] if s['interface'] == name)
            state.update(active=False, committed=a == peer)
            for route in item['fib']:
                if route['dev'] == name:
                    route['dev'] = 'vl-boot-00'
        # The cold node has a new, uncommitted receiver; its survivor retains
        # the previously committed incarnation and only a neighbor fallback.
        cold, name = obs[node], f'vdl-{peer}'
        cold['materialized_ifindices'].remove(cold['ifindices'][name])
        cold['wg'][name]['peers'][0]['handshake'] = 0
        obs[peer]['fib'].append({'dst': prefix(node), 'dev': f'vdl-{node}',
                                 'protocol': 202, 'metric': 131008})
        checker.observe(topology, obs, now=1)
        PendingLinks().observe(obs, 1)
        return topology, obs, checker, node, peer

    def test_cold_durable_receiver_allows_survivor_retention_and_live_fallback(self):
        topology, obs, checker, node, peer = self.asymmetric_recovery()
        self.assertEqual(len(audit(topology, obs)), 30)
        self.assertIn(f'vdl-{peer}', obs[node]['pending'])
        self.assertIn(f'vdl-{node}', obs[peer]['retained'])
        coverage = Coverage('ipv4')
        coverage.verified(topology, obs)
        for pair in ((node, peer), (peer, node)):
            self.assertEqual(coverage.pairs[pair]['outcome'], 'fallback')
            self.assertEqual(coverage.pairs[pair]['requirement'], 'durable-recovery')
        checker.observe(topology, obs, now=1801)
        with self.assertRaisesRegex(AssertionError, 'exceeded failure window'):
            checker.observe(topology, obs, now=1892)

    def test_cold_durable_receiver_cannot_hide_survivor_routing_faults(self):
        for fault, error in (('selected-fallback', 'retained dead fallback is best'),
                             ('learned-route', 'FIB uses a dead/unknown interface')):
            with self.subTest(fault=fault):
                topology, obs, _, node, peer = self.asymmetric_recovery()
                item, name = obs[peer], f'vdl-{node}'
                if fault == 'selected-fallback':
                    item['fib'] = [r for r in item['fib'] if r['dst'] != prefix(node) or r['dev'] == name]
                else:
                    item['fib'].append({'dst': prefix(node), 'dev': name, 'protocol': 203, 'metric': 140000})
                with self.assertRaisesRegex(NotConverged, error):
                    audit(topology, obs)

    def test_offline_peer_does_not_accumulate_recovery_budget(self):
        topology, obs, checker, node, peer = self.waiting()
        checker.observe(topology, obs, now=1)
        checker.observe(topology, obs, now=10000)
        self.assertEqual(obs[node]['durable_recovery_peers'], [])
        self.assertEqual(checker.recovering, {})

    def test_explicit_mixed_modes(self):
        runner = Runner.__new__(Runner)
        runner.args = SimpleNamespace(automatic_ports='mixed')
        self.assertEqual(runner.automatic_ports(0), {'listen_port': 0})
        self.assertEqual(runner.automatic_ports(1), {'port_range': {'first': 40000, 'last': 40999}})

    def test_off_allows_one_policy_probe_but_rejects_loops_and_initiation(self):
        for kind in ('single-inbound', 'repeated-inbound', 'outbound'):
            with self.subTest(kind=kind):
                r = SimpleNamespace(topology=SimpleNamespace(active={0, 1, 2}, modes={2: 'active'}),
                                    coverage=Coverage('ipv6'), verify=Mock(), durable_records=Mock(return_value=[]))

                def inject(*_):
                    self.assertEqual(r.topology.modes[2], 'off')
                    if kind == 'outbound':
                        r.coverage.proposed(2, 1)
                    else:
                        r.coverage.proposed(1, 2)
                        if kind == 'repeated-inbound':
                            r.coverage.proposed(1, 2)

                with patch('mutations.reload_mode', side_effect=lambda runner, node, mode: runner.topology.modes.update({node: mode})), \
                     patch('mutations.wait_for'), patch('mutations.hold', side_effect=inject):
                    if kind == 'single-inbound':
                        policy(r, 2)
                    else:
                        with self.assertRaises(AssertionError):
                            policy(r, 2)


if __name__ == '__main__':
    unittest.main()
