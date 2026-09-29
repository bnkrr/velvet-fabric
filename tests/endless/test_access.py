import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from access import Access, configure, has_return_rule, check_routes, client, service, source_prefix
from model import NotConverged
from netns import Runner, DurationReached, StopRequested, arguments


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

    def test_config_announces_clients_in_fabric_and_services_in_domain(self):
        spec = {'fabric': {}}
        configure(spec, 2, 4)
        self.assertEqual(spec['fabric']['announcements'], ['10.100.2.0/24', 'fd30:100:2::/64'])
        domain = spec['domains']['access']
        self.assertEqual(len(domain['source_prefixes']), 8)
        self.assertEqual(domain['announcements'], ['10.60.2.1/32', 'fd30:60:2::1/128'])

    def test_routes_require_live_set_and_ignore_local_throw(self):
        routes = [{'dst': '10.100.1.0/24'}, {'type': 'throw', 'dst': '10.100.0.0/24'}]
        check_routes(routes, ['10.100.1.0/24'], 'test')
        for expected in ([], ['10.100.2.0/24']):
            with self.assertRaises(NotConverged):
                check_routes(routes, expected, 'test')

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
