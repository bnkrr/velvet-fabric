import copy
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from access import Access, configure, has_return_rule, check_routes, client, service, source_prefix, service_prefix
from model import NotConverged, Topology, audit, prefix
from netns import Runner, DurationReached, StopRequested, arguments
from test_model import observation_fixture


class AccessTests(unittest.TestCase):
    def test_all_kernel_queues_drain_before_first_unready_node(self):
        monitors = {n: Mock() for n in (0, 1)}
        r = SimpleNamespace(latest={}, materialized_links=monitors,
                            nodes={0: {'proc': SimpleNamespace(poll=lambda: None), 'ready': False}},
                            command=Mock(side_effect=FileNotFoundError))
        with self.assertRaises(NotConverged):
            Runner._observe(r)
        for monitor in monitors.values():
            monitor.read.assert_called_once_with()

    def test_ipv6_zero_slot_uses_kernel_canonical_form(self):
        self.assertEqual(client(0, 6), 'fd30:100::2')
        self.assertEqual(service(0, 6), 'fd30:60::1')
        self.assertEqual(source_prefix(0, 6), 'fd30:100::/64')

    def test_return_selector_requires_destination_fabric_and_ownership(self):
        for prefix in ('10.100.2.0/24', 'fd30:100:2::/64'):
            rule = {'dst': prefix, 'table': 20000, 'protocol': 201}
            self.assertTrue(has_return_rule([rule], prefix))
            # Old source-only behavior and unowned external test rules fail.
            for invalid in ({'src': prefix, 'table': 20001, 'protocol': 201},
                            {**rule, 'table': 20001}, {**rule, 'protocol': 4}):
                self.assertFalse(has_return_rule([invalid], prefix))

    def test_config_announces_clients_and_services_in_their_domain(self):
        spec = {'fabric': {}}
        configure(spec, 2, 4)
        self.assertNotIn('announcements',spec['fabric'])
        domain = spec['domains']['access']
        self.assertEqual(len(domain['source_prefixes']), 8)
        self.assertEqual(domain['announcements'], ['10.100.2.0/24','fd30:100:2::/64','10.60.2.1/32', 'fd30:60:2::1/128'])

    def test_routes_require_live_set_and_ignore_local_throw(self):
        routes = [{'dst': '10.100.1.0/24'}, {'type': 'throw', 'dst': '10.100.0.0/24'}]
        check_routes(routes, ['10.100.1.0/24'], 'test')
        for expected in ([], ['10.100.2.0/24']):
            with self.assertRaises(NotConverged):
                check_routes(routes, expected, 'test')

    def test_retained_fallback_requires_exact_route_and_peer(self):
        route = {'dst': prefix(0), 'dev': 'vl-old', 'protocol': '202', 'metric': 131008}
        retained = {'vl-old': 0}
        check_routes([route], [], 'test', retained)
        for change in ({'protocol': 203}, {'metric': 1024}, {'dst': prefix(1)},
                       {'dst': source_prefix(0, 6)}, {'dev': 'vl-unknown'},
                       {'gateway': 'fe80::1'}, {'multipath': [{'dev': 'vl-old'}]}):
            with self.subTest(change=change), self.assertRaises(NotConverged):
                check_routes([{**route, **change}], [], 'test', retained)
        with self.assertRaises(NotConverged):
            check_routes([route], [], 'test')
        # A valid fallback cannot hide a stale learned route to the same peer.
        with self.assertRaises(NotConverged):
            check_routes([route, {**route, 'protocol': 203, 'dev': 'vl-live'}], [], 'test', retained)

    def test_retained_fallback_cannot_win_or_tie_for_live_destination(self):
        fallback = {'dst': prefix(2), 'dev': 'vl-old', 'protocol': 202, 'metric': 131008}
        retained = {'vl-old': 2}
        for metric in (1024, 131007, 131008, 131009, None):
            routes = [fallback]
            if metric is not None:
                routes.append({'dst': prefix(2), 'dev': 'vl-live', 'protocol': 203, 'metric': metric})
            with self.subTest(metric=metric):
                if metric is not None and metric < fallback['metric']:
                    check_routes(routes, [prefix(2)], 'test', retained)
                else:
                    with self.assertRaisesRegex(NotConverged, 'retained dead fallback is best'):
                        check_routes(routes, [prefix(2)], 'test', retained)

    def departed_domain_fixture(self):
        topology = Topology(6, 3, 1, dynamic=False)
        gone = 5
        topology.active.remove(gone)
        _, observations = observation_fixture(topology=topology)
        node, name = topology.boot[gone], f'vl-in-{gone:02d}'
        item = observations[node]
        item.update(known_peer_keys={f'static-{gone}': gone}, ifindices={name: 100},
                    materialized_ifindices=[100])
        item['wg'][name]['peers'][0]['handshake'] = 100
        item['status']['runtime']['links'] = [{'interface': name, 'active': False, 'committed': True}]
        fallback = {'dst': prefix(gone), 'dev': name, 'protocol': 202, 'metric': 131008}
        item['fib'].append(fallback)
        for member, obs in observations.items():
            obs['access'] = {'families': {}}
            for f in (4, 6):
                reachable = topology.components()[member] - {member}
                expected = [p(n, f) for n in reachable for p in (source_prefix, service_prefix)]
                if f == 6:
                    expected += [prefix(n) for n in reachable]
                obs['access']['families'][f] = {'domain': [
                    {'dst': dst, 'dev': obs['fib'][0]['dev'], 'protocol': 203, 'metric': 1024}
                    for dst in expected]}
        item['access']['families'][6]['domain'].append(dict(fallback))
        return topology, observations, node, name

    def test_domain_accepts_mirrored_fallback_after_membership_removal(self):
        topology, observations, _, _ = self.departed_domain_fixture()
        self.assertEqual(len(audit(topology, observations)), 20)
        Access(SimpleNamespace(topology=topology)).audit(observations)

    def test_domain_cannot_claim_retention_from_status_alone(self):
        for change in ('incarnation', 'commit', 'identity', 'allowed'):
            topology, observations, node, name = self.departed_domain_fixture()
            item = observations[node]
            if change == 'incarnation': item['materialized_ifindices'] = []
            elif change == 'commit': item['status']['runtime']['links'][0]['committed'] = False
            elif change == 'identity': item['wg'][name]['peers'][0]['public'] = 'unknown'
            else: item['wg'][name]['peers'][0]['allowed'] = ['::/0']
            with self.subTest(change=change), self.assertRaises(NotConverged):
                audit(topology, observations)

    def test_domain_still_requires_live_services_and_rejects_stale_routes(self):
        topology, observations, node, name = self.departed_domain_fixture()
        audit(topology, observations)
        checker = Access(SimpleNamespace(topology=topology))
        for family, change in ((4, 'missing'), (6, 'missing'), (4, 'stale'),
                               (6, 'stale'), (6, 'learned_on_retained')):
            broken = copy.deepcopy(observations)
            routes = broken[node]['access']['families'][family]['domain']
            if change == 'missing': routes.pop(0)
            elif change == 'stale':
                routes.append({'dst': service_prefix(5, family), 'dev': routes[0]['dev'], 'protocol': 203})
            else:
                routes.append({'dst': prefix(5), 'dev': name, 'protocol': 203, 'metric': 1024})
            with self.subTest(family=family, change=change), self.assertRaises(NotConverged):
                checker.audit(broken)

    def test_working_pings_do_not_excuse_wrong_policy_table(self):
        for wrong in (None, 'return', 'outbound'):
            with self.subTest(wrong=wrong):
                returned = '[{"table":20000,"dev":"vl-peer"}]' if wrong != 'return' else '[{"dev":"wan"}]'
                outbound = '[{"table":20001,"dev":"vdl-peer"}]' if wrong != 'outbound' else returned
                r = SimpleNamespace(namespace=lambda n: str(n), timeout=lambda n: n,
                                    ip=Mock(side_effect=[returned, outbound] * 2))
                with patch('access.sp.run', return_value=SimpleNamespace(returncode=0)):
                    if wrong:
                        with self.assertRaises(NotConverged):
                            Access(r).probe(0, 1)
                    else:
                        Access(r).probe(0, 1)


class DurationTests(unittest.TestCase):
    def test_total_budget_does_not_hide_phase_failure_or_manual_stop(self):
        r = SimpleNamespace(stop_signal=None, run_until=200, deadline=150)
        with patch('netns.time.time', return_value=100), patch('netns.time.monotonic', return_value=151):
            with self.assertRaises(TimeoutError):
                Runner.timeout(r)
        with patch('netns.time.time', return_value=201):
            with self.assertRaises(DurationReached):
                Runner.timeout(r)
            r.stop_signal = 15
            with self.assertRaises(StopRequested):
                Runner.timeout(r)

    def test_cleanup_can_disable_total_budget(self):
        r = SimpleNamespace(stop_signal=None, run_until=None, deadline=None)
        self.assertEqual(Runner.timeout(r), 5)

    def test_duration_cli(self):
        with patch('sys.argv', ['netns.py', '--validate', '--wg-access', '--duration-seconds', '28800']):
            args, _ = arguments()
        self.assertEqual(args.duration_seconds, 28800)
        self.assertTrue(args.wg_access)
        for value in ('-1', 'nan', 'inf'):
            with patch('sys.argv', ['netns.py', '--validate', '--duration-seconds', value]), patch('sys.stderr'):
                with self.assertRaises(SystemExit):
                    arguments()


if __name__ == '__main__':
    unittest.main()
