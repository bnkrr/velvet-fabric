#!/usr/bin/env python3
"""Bounded dynamic-link E2E; reuse the host-owned WG/FIB/ping oracle."""
import argparse
from collections import deque
import json
from pathlib import Path
import shutil
import sys
import time
import traceback
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'endless'))
import netns
from model import Topology, NotConverged
from cases import catalog, pair_requirements


class DirectedTopology(Topology):
    def __init__(self, profiles):
        super().__init__(len(profiles) + 2, 3, 1)
        self.public = {0, 1}
        self.boot = {n: 0 if n else None for n in self.active}
        self.profiles = {0: None, 1: None, **dict(enumerate(profiles, 2))}
        self.extra_required = pair_requirements(profiles)
        self.groups = None
        self.blocked_pairs = set()

    def required(self, node):
        peers = super().required(node) | {b for a, b in self.extra_required if a == node and self.want_pair(a, b)}
        return (peers & self.components()[node]) - {b for a, b in self.blocked_pairs if a == node}

    def static_links(self, node):
        links = super().static_links(node)
        return {name: peer for name, peer in links.items() if peer in self.components()[node]}

    def components(self):
        return ({n: next(set(g) for g in self.groups if n in g) for n in self.active}
                if self.groups else super().components())


class DirectedRunner(netns.Runner):
    def __init__(self, *args):
        super().__init__(*args)
        self.history = deque(maxlen=20000)
        self.helpers = []
        self.helper_nodes = {}
        self.root_tables = set()
        self.kind = self.args.spec['kind']
        self.started_nodes = set()
        self.resource_peaks = {}

    def resources(self, node, role, pid):
        super().resources(node, role, pid)
        if self.kind == 'observer-concurrency' and role == 'velvetd' and node in (0, 1) and node not in self.resource_peaks:
            from resources import census
            snapshot = census(pid, netns.address(node))
            if snapshot['fds'] > 64 + 16 * self.topology.size:
                self.resource_peaks[node] = snapshot
                self.record('observer-pool-peak', node=node, fds=snapshot['fds'],
                            udp=len(snapshot['probe_listeners']), tcp=len(snapshot['routed_inbound']))

    def expected_helpers(self, node):
        return {p.pid for p in self.helpers if self.helper_nodes.get(p.pid) == node and p.poll() is None}

    def nat_options(self, node):
        if self.kind == 'observer-conflict' and node in (2, 3):
            secondary = f'192.0.2.{node + 129}' if self.args.underlay == 'ipv4' else f'2001:db8:ee::{node + 129:x}'
            self.ip(f'r{node}', 'addr', 'add', secondary + ('/24' if self.args.underlay == 'ipv4' else '/64'), 'dev', 'wan')
            return ['--other-wan', secondary, '--primary-destination', self.wan(0)]
        return ['--idle-timeout', '12'] if self.kind == 'expiry' and node == 2 else []

    def on_event(self, node, event):
        self.history.append((node, event))

    def find_events(self, node=None, event=None, status=None, remote=None, since=0):
        return [e for n, e in list(self.history) if (node is None or node == n)
                and (event is None or e.get('event') == event)
                and (status is None or e.get('status') == status)
                and (remote is None or e.get('remote_uid') == self.uids[remote])
                and e['observed_elapsed'] >= since]

    def pair_finished(self, left, right):
        for a, b in ((left, right), (right, left)):
            if self.find_events(a, 'velvet-dynamic-link', 'up', b):
                return True
            if any(e.get('error', '').startswith('UDP discovery:') for e in
                   self.find_events(a, 'velvet-dynamic-attempt', 'failed', b)):
                return True
        return False

    def observe(self):
        result = super().observe()
        if self.kind in ('matrix', 'observer-concurrency'):
            nodes = sorted(self.topology.active - self.topology.public)
            missing = [(a, b) for a in nodes for b in nodes if a < b and not self.pair_finished(a, b)]
            if missing:
                raise NotConverged(f'waiting for real dual-NAT attempt outcomes: {missing[:8]} ({len(missing)} total)')
        return result

    def start_daemon(self, node):
        from scenarios import prepare_node
        if node not in self.started_nodes:
            prepare_node(self, node)
            self.started_nodes.add(node)
        super().start_daemon(node)

    def write_config(self, node):
        super().write_config(node)
        from scenarios import configure
        path = self.runtime / f'{node}.json'
        config = json.loads(path.read_text())
        configure(self, node, config)
        path.write_text(json.dumps(config))

    def execute(self):
        from scenarios import execute
        for source in Path(__file__).parent.glob('*.py'):
            shutil.copyfile(source, self.artifacts / ('directed-' + source.name))
        self.phase = self.args.case
        self.prepare()
        self.deadline = time.monotonic() + self.args.settle_timeout
        for node in sorted(self.topology.active):
            self.add_node(node)
        self.deadline = None
        execute(self)
        self.save('outcomes.json', {'case': self.args.case, 'family': self.args.underlay,
            'profiles': self.topology.profiles, 'pairs': self.coverage.state()['pairs'],
            'terminal_events': [dict(node=n, **e) for n, e in self.history if
                e.get('event') in ('velvet-dynamic-attempt', 'velvet-dynamic-link', 'velvet-udp-observe')]})
        self.record('complete', result='PASS', case=self.args.case)

    def cleanup(self):
        self.deadline = None
        self.stop_signal = None
        errors = []
        for family, name in sorted(self.root_tables):
            try:
                self.run('nft', 'delete', 'table', family, name)
            except Exception as error:
                errors.append(str(error))
        for process in self.helpers:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except netns.sp.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        self.record('auxiliary-cleanup', result='FAIL' if errors else 'PASS', errors=errors)
        return errors + super().cleanup()

    def snapshot_failure(self, error):
        self.save('exception.json', {'type': type(error).__name__, 'traceback': traceback.format_exc()})
        super().snapshot_failure(error)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('daemon', type=Path, nargs='?')
    parser.add_argument('babel', type=Path, nargs='?')
    parser.add_argument('--case', choices=catalog(), default='data-mtu')
    parser.add_argument('--underlay', choices=('ipv4', 'ipv6'), default='ipv4')
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--list', action='store_true')
    cli = parser.parse_args()
    if cli.list:
        print(json.dumps(catalog(), indent=2))
        return 0
    for path in (cli.daemon, cli.babel):
        if path is None or not path.is_file():
            parser.error('velvetd and pinned babel-rs binaries required')
    spec = catalog()[cli.case]
    profiles = spec.get('profiles', [('eim', 'eif', 'preserve')] * 2)
    if spec['kind'].startswith('observer') and spec['kind'] != 'observer-concurrency' or spec['kind'] == 'crash-observe':
        profiles = [('eim', 'eif', 'offset')] * 2 + [('eim', 'eif', 'preserve')]
        if spec['kind'] == 'observer-conflict':
            profiles = [('eim', 'apdf', 'offset')] * 2 + [('eim', 'eif', 'preserve')]
        if spec['kind'] == 'observer-loss':
            profiles = [('apdm', 'apdf', 'sequential')] * 2 + [('eim', 'eif', 'preserve')]
    topology = DirectedTopology(profiles)
    if spec['kind'].startswith('observer') and spec['kind'] != 'observer-concurrency':
        # Only node 2 initiates. With node 4 off and node 0 already static,
        # node 2's measured evidence from observer 1 belongs to target 3 (the
        # target itself is excluded from observer selection). This prevents an
        # unrelated concurrent attempt from satisfying the observer assertion.
        topology.modes = {0: 'passive', 1: 'passive', 2: 'active', 3: 'passive', 4: 'off'}
    if spec['kind'] in ('dual-stack', 'dual-stack-failure', 'egress-switch', 'data-mtu'):
        topology.public = topology.active.copy()
        topology.profiles = {n: None for n in topology.active}
    if spec['kind'] == 'partition':
        topology.boot[3] = 1
    args = SimpleNamespace(**vars(cli), spec=spec, nodes=topology.size, min_nodes=3,
        seed=1, rounds=1, dynamic='active', nat_policy='active', capture=True,
        exercise=[], settle_timeout=180, stable_seconds=10, probe_pairs=16,
        rss_growth_mib=64, plan=False, validate=False)
    netns.arguments = lambda: (args, topology)
    netns.Runner = DirectedRunner
    return netns.main()


if __name__ == '__main__':
    raise SystemExit(main())
