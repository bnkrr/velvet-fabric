"""Bounded online faults with explicit affected paths and recovery assertions."""
import ipaddress
import json
from pathlib import Path
import signal
import time

from model import NotConverged, address, parse_wg


def observe(r):
    try:
        r.observe()
    except NotConverged:
        pass  # The injected fault owns this interval; recovery uses full audit.


def wait_for(r, predicate, seconds, reason):
    r.deadline = time.monotonic() + seconds
    next_report = time.monotonic() + 30
    try:
        while time.monotonic() < r.deadline:
            observe(r)
            if predicate():
                return
            if time.monotonic() >= next_report:
                r.record('waiting', reason=reason)
                next_report = time.monotonic() + 30
            time.sleep(min(0.2, r.timeout(0.2)))
        raise AssertionError(reason)
    finally:
        r.deadline = None


def hold(r, seconds):
    until = time.monotonic() + seconds
    r.deadline = until + 5
    try:
        while time.monotonic() < until:
            observe(r)
            time.sleep(min(1, max(0, until - time.monotonic())))
    finally:
        r.deadline = None


def dynamic(r, source, target):
    return {name: peer for name, link in parse_wg(r.ns(source, 'wg', 'show', 'all', 'dump')).items()
            if name.startswith('vdl-') for peer in link['peers'] if peer['public'] == r.pubs[target]}


def reload_mode(r, node, mode):
    generation = r.command(node)['config_generation']
    old_babel = r.nodes[node]['resources']['babel']['pid']
    r.topology.modes[node] = mode
    r.write_config(node)
    r.nodes[node]['proc'].send_signal(signal.SIGHUP)
    # Current SIGHUP replaces this node's runtime and managed Babel, while
    # keeping velvetd itself alive. This is the only permitted child replacement.
    r.deadline = time.monotonic() + 15
    try:
        while r.command(node)['config_generation'] <= generation:
            time.sleep(min(0.1, r.timeout(0.1)))
        assert not Path(f'/proc/{old_babel}').exists(), 'reload left its previous Babel process alive'
        r.nodes[node]['resources'].pop('babel')
    finally:
        r.deadline = None
    r.record('policy-applied', node=node, mode=mode, retired_babel_pid=old_babel)


def proposals_to(r, node):
    return sum(r.coverage.proposals[peer, node] for peer in r.topology.active - {node})


def proposals_from(r, node):
    return sum(r.coverage.proposals[node, peer] for peer in r.topology.active - {node})


def policy(r, node):
    original = r.topology.modes[node]
    reload_mode(r, node, 'off')
    # First retire the old Links (30s liveness + 30s recovery + cleanup), so
    # an already healthy Link cannot make the no-proposal assertion vacuous.
    def retired():
        if set(r.latest) != r.topology.active:
            return False
        return all(not any(name.startswith('vdl-' if peer == node else f'vdl-n{node}-')
                           for name in r.latest[peer]['wg']) for peer in r.topology.active)
    wait_for(r, retired, 75, 'pre-policy dynamic interfaces have not retired')
    before = proposals_to(r, node), proposals_from(r, node)
    hold(r, 18)
    assert before == (proposals_to(r, node), proposals_from(r, node)), 'off caused a proposal loop'
    r.verify()
    before_passive = proposals_from(r, node)
    reload_mode(r, node, 'passive')
    r.verify()
    assert proposals_from(r, node) == before_passive, 'passive node initiated a new proposal'
    if original != 'passive':
        reload_mode(r, node, original)
        r.verify()


def packet_count(r, node):
    data = json.loads(r.ns(node, 'nft', '-j', 'list', 'table', 'inet', 'coverage_fault'))
    return sum(e.get('counter', {}).get('packets', 0) for e in data['nftables'])


def blocked_pair(r, node, peer, control=False):
    before = {n: list(dynamic(r, n, t)) for n, t in ((node, peer), (peer, node))}
    assert all(before.values()), 'fault requires an established non-bootstrap Dynamic Link'
    family = 'ip' if r.args.underlay == 'ipv4' else 'ip6'
    if control:
        incoming = f'ip6 saddr {address(peer)} meta l4proto {{ tcp, udp }} th dport 58420'
        outgoing = f'ip6 daddr {address(peer)} meta l4proto {{ tcp, udp }} th dport 58420'
    else:
        incoming = f'iifname "lan" {family} saddr {r.wan(peer)} meta l4proto udp'
        outgoing = None  # A one-way underlay blackhole; bootstrap remains usable.
    rules = f'''table inet coverage_fault {{
 counter dropped {{ }}
 chain input {{ type filter hook input priority -20; policy accept;
 {incoming} counter name dropped drop
 }}
'''
    if outgoing:
        rules += f''' chain output {{ type filter hook output priority -20; policy accept;
 {outgoing} counter name dropped drop
 }}
'''
    rules += '}\n'
    r.ns(node, 'nft', '-f', '-', input=rules)
    r.record('fault-start', node=node, peer=peer, fault='routed-control' if control else 'one-way-underlay')
    try:
        if control:
            # Destroy only this known pair's WG interfaces. The daemon must
            # negotiate fresh resources over the blocked routed control path.
            for n, names in before.items():
                for name in names:
                    r.ip(n, 'link', 'del', name)
        hold(r, 20 if control else 40)
        def fallback():
            # Interface loss may still be inside the ordinary retry backoff;
            # wait until a real packet reaches the rule before accepting it.
            if not packet_count(r, node):
                return False
            for n, target in ((node, peer), (peer, node)):
                routes = json.loads(r.ip(n, '-6', '-j', 'route', 'show', 'table', '20000',
                                        'exact', address(target) + '/128'))
                if any(str(route.get('protocol')) == '202' for route in routes):
                    return False
            return r.ping(node, peer) and r.ping(peer, node)
        wait_for(r, fallback, r.args.settle_timeout, 'fallback did not converge during fault')
        assert packet_count(r, node) > 0, 'fault rule did not intercept packets'
        r.record('fallback-verified', node=node, peer=peer, dropped=packet_count(r, node))
    finally:
        r.ns(node, 'nft', 'delete', 'table', 'inet', 'coverage_fault')
        r.record('fault-restored', node=node, peer=peer)
    r.verify()


def reset_nat(r, node, rebind=False):
    before = {peer: dynamic(r, peer, node) for peer in sorted(r.topology.active & r.topology.public)
              if peer != r.topology.boot[node]}
    old_wan = r.wan(node)
    old_process = r.nat_processes[node]
    old_process.terminate()
    old_process.wait(timeout=5)
    assert old_process.returncode == 0, 'NAT fixture shutdown failed'
    r.nat_epochs[node] += 1
    if rebind:
        r.wan_epochs[node] += 1
        width = '/24' if r.args.underlay == 'ipv4' else '/64'
        r.ip(f'r{node}', 'addr', 'del', old_wan + width, 'dev', 'wan')
        # Deleting an IPv4 primary can also remove its secondary addresses.
        # Install the replacement afterwards while the translator is stopped.
        r.ip(f'r{node}', 'addr', 'add', r.wan(node) + width, 'dev', 'wan')
        mapping, filtering, allocation = r.topology.profiles[node]
        r.topology.profiles[node] = (mapping, filtering, 'offset' if allocation == 'preserve' else 'preserve')
    r.nodes[node]['resources'].pop('nat', None)  # Explicit fixture-only replacement.
    r.coverage.reset(node)
    r.start_nat(node)
    r.record('nat-restarted', node=node, old_pid=old_process.pid, new_pid=r.nat_processes[node].pid,
             epoch=r.nat_epochs[node], old_wan=old_wan, new_wan=r.wan(node), profile=r.topology.profiles[node])
    r.verify()
    status = json.loads((r.runtime / f'nat-{node}.json').read_text())
    assert status['created'] > 0 and status['in'] > 0, 'replacement NAT did not forward real traffic'
    if rebind:
        for peer, old_links in before.items():
            current = dynamic(r, peer, node)
            assert current, 'rebound NAT lost required direct link'
            for value in current.values():
                host, port = value['endpoint'].rsplit(':', 1)
                assert ipaddress.ip_address(host.strip('[]')) == ipaddress.ip_address(r.wan(node)), 'stale WAN endpoint'
                assert all(value['endpoint'] != old['endpoint'] for old in old_links.values()), 'endpoint did not change'
        r.record('endpoint-change-verified', node=node, wan=r.wan(node))


def exercise(r, name):
    candidates = sorted(r.topology.active - r.topology.public)
    if not candidates:
        raise ValueError('online mutations require a NAT member')
    node = candidates[0]
    peer = next(n for n in sorted(r.topology.active & r.topology.public) if n != r.topology.boot[node])
    identities = {n: (info['proc'].pid, info['resources']['babel']['pid']) for n, info in r.nodes.items()}
    r.record('exercise-start', exercise=name, node=node, peer=peer)
    if name == 'policy':
        policy(r, node)
    elif name in ('blackout', 'control-loss'):
        blocked_pair(r, node, peer, control=name == 'control-loss')
    else:
        reset_nat(r, node, rebind=name == 'nat-rebind')
    for n, info in r.nodes.items():
        assert identities[n][0] == info['proc'].pid, 'online mutation restarted velvetd'
        if name != 'policy' or n != node:
            assert identities[n][1] == info['resources']['babel']['pid'], 'online mutation restarted unrelated Babel'
    r.record('exercise-verified', exercise=name, node=node, peer=peer)
