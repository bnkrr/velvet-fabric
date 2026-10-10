"""Partition oracle regressions, including missing-link negative controls."""
import copy
import unittest

from check_partition import partition_topology
from model import NotConverged, Topology, audit, prefix
from test_model import observation_fixture


def physical_observations(topology):
    _, observations = observation_fixture(topology=topology)
    for obs in observations.values():
        names = [name for name in obs['wg'] if name.startswith('vdl-')]
        obs['ifindices'] = {name: index for index, name in enumerate(names, 10)}
        obs['materialized_ifindices'] = list(obs['ifindices'].values())
        obs['status']['runtime']['links'] = [
            {'interface': name, 'active': True, 'committed': True} for name in names]
    return observations


class TopologyTests(unittest.TestCase):
    def partitioned(self):
        t = Topology(10, 6, 1, underlay='dual')
        partition_topology(t)
        t.plan_verified()
        t.active.add(6)
        return t

    def established(self):
        t = self.partitioned()
        t.active.add(4)
        t.boot[4] = 0
        obs = physical_observations(t)
        audit(t, obs)
        t.verified(obs)
        t.active.remove(4)
        t.forget(4)
        return t

    def test_new_member_cannot_negotiate_across_disconnected_components(self):
        t = self.partitioned()
        self.assertEqual(t.components()[6], {0, 1, 3, 5, 6, 7, 9})
        self.assertEqual(t.components()[2], {2, 8})
        self.assertEqual(t.required(6), {0})
        obs = physical_observations(t)
        self.assertEqual(len(audit(t, obs)), 44)
        obs[6]['fib'].append({'dst': prefix(2), 'dev': 'vl-boot-00', 'metric': 1024})
        with self.assertRaisesRegex(NotConverged, 'unexpected/stale unicast destination'):
            audit(t, obs)

    def test_bootstrap_bridge_enables_required_discovery_and_link_survives_its_removal(self):
        t = self.established()
        self.assertEqual(t.components()[6], t.active)
        self.assertIn(2, t.required(6))
        obs = physical_observations(t)
        self.assertEqual(len(audit(t, obs)), 72)
        for node, peer in ((2, 6), (6, 2)):
            del obs[node]['wg'][f'vdl-{peer}']
            obs[node]['status']['runtime']['dynamic_links'] -= 1
        t.observe_automatic(obs)
        self.assertEqual(t.components()[6], t.active)
        with self.assertRaisesRegex(NotConverged, 'missing required neighbors'):
            audit(t, obs)

    def test_rebirth_or_explicit_removal_does_not_resurrect_an_old_link(self):
        for invalidate in ('birth', 'forget', 'membership'):
            with self.subTest(invalidate=invalidate):
                t = self.established()
                if invalidate == 'birth':
                    t.births[6] += 1
                elif invalidate == 'forget':
                    t.forget(6)
                else:
                    t.active.remove(6)
                    t.observe_automatic({})
                    t.active.add(6)
                self.assertNotIn(2, t.components()[6])
                self.assertNotIn(2, t.required(6))

    def test_off_retires_history_but_passive_preserves_existing_links(self):
        t = self.established()
        t.modes[2] = t.modes[6] = 'passive'
        self.assertIn(2, t.components()[6])
        t.modes[6] = 'off'
        t.observe_automatic({})
        self.assertNotIn(2, t.components()[6])
        t.modes[6] = 'active'
        self.assertNotIn(2, t.components()[6])

    def test_verified_automatic_recovery_can_reconnect_partition(self):
        connected = self.established()
        obs = physical_observations(connected)
        t = self.partitioned()
        t.observe_automatic(obs)
        self.assertEqual(t.components()[6], t.active)
        # Routes remain mandatory even with valid physical link evidence.
        obs[6]['fib'] = [r for r in obs[6]['fib'] if r['dst'] != prefix(2)]
        with self.assertRaises(NotConverged):
            audit(t, obs)

    def test_control_session_loss_does_not_erase_verified_forwarding(self):
        t = self.established()
        obs = physical_observations(t)
        for node, peer in ((2, 6), (6, 2)):
            state = next(s for s in obs[node]['status']['runtime']['links'] if s['interface'] == f'vdl-{peer}')
            state['active'] = False
            obs[node]['status']['runtime']['dynamic_links'] -= 1
        audit(t, obs)
        t.verified(obs)
        self.assertEqual(t.components()[6], t.active)

    def test_saved_tentative_stale_or_unilateral_evidence_cannot_merge_partitions(self):
        connected = self.established()
        original = physical_observations(connected)
        for defect in ('one-sided', 'unmaterialized', 'pending', 'inactive', 'uncommitted',
                       'unhandshaken', 'allowedips', 'wrong-key', 'routes-only'):
            with self.subTest(defect=defect):
                t = self.partitioned()
                obs = copy.deepcopy(original)
                item, name = obs[6], 'vdl-2'
                if defect == 'one-sided': del item['wg'][name]
                elif defect == 'unmaterialized': item['materialized_ifindices'] = []
                elif defect == 'pending': item['pending'] = [name]
                elif defect in ('inactive', 'uncommitted'):
                    link = next(x for x in item['status']['runtime']['links'] if x['interface'] == name)
                    link['active' if defect == 'inactive' else 'committed'] = False
                elif defect == 'unhandshaken': item['wg'][name]['peers'][0]['handshake'] = 0
                elif defect == 'allowedips': item['wg'][name]['peers'][0]['allowed'] = ['::/0']
                elif defect == 'wrong-key': item['wg'][name]['peers'][0]['public'] = 'unrelated'
                else:
                    for o in obs.values(): o['wg'] = {}
                t.observe_automatic(obs)
                self.assertNotIn(2, t.components()[6])

    def test_single_stack_uses_the_same_routed_discovery_precondition(self):
        for family in ('ipv4', 'ipv6'):
            t = Topology(6, 3, 1, underlay=family)
            t.boot = {0: None, 1: None, 2: 0, 3: 0, 4: 1, 5: 1}
            self.assertEqual(t.components()[2], {0, 2, 3})
            self.assertEqual(t.required(2), {0})
            t.boot[1] = 0
            t.plan_verified()
            t.boot[1] = None
            self.assertEqual(t.components()[2], t.active)

    def test_optional_nat_link_is_preserved_when_its_public_relays_leave(self):
        t = self.partitioned()
        t.active.add(4)
        t.boot[4] = 0
        obs = physical_observations(t)
        for node, peer in ((6, 8), (8, 6)):
            item, name = obs[node], f'vdl-{peer}'
            item['wg'][name] = {'public': f'dynamic-{node}-{peer}', 'port': 31000 + peer,
                'peers': [{'public': f'dynamic-{peer}-{node}', 'handshake': 100,
                           'allowed': ['0.0.0.0/0', '::/0'], 'endpoint': '192.0.2.1:52000'}]}
            item['ifindices'][name] = 100
            item['materialized_ifindices'].append(100)
            item['status']['runtime']['links'].append({'interface': name, 'active': True, 'committed': True})
            item['status']['runtime']['dynamic_links'] += 1
        audit(t, obs)
        t.verified(obs)
        for node in (2, 4):
            t.active.remove(node)
            t.forget(node)
        self.assertIn(8, t.components()[6])
        self.assertIn(0, t.components()[8])
        self.assertNotIn(8, t.required(6))  # Still not a required direct NAT/NAT pair.


if __name__ == '__main__':
    unittest.main()
