"""Bounded online faults with explicit affected paths and recovery assertions."""
import ipaddress
import json
from pathlib import Path
import signal
import time

from model import NotConverged, address, parse_wg
from durable_model import agreement, fixed
from underlay import families


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
        assert Path(f'/proc/{old_babel}').exists(), 'reload stopped independent Babel'
        r.nodes[node]['resources'].pop('babel')
    finally:
        r.deadline = None
    r.record('policy-applied', node=node, mode=mode, babel_pid=old_babel)


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
    before = {peer: r.coverage.proposals[peer, node] for peer in r.topology.active - {node}}
    outgoing = proposals_from(r, node)
    # ABSENT retires a saved agreement but says nothing about admission. A peer
    # whose policy update was lost may make one bounded proposal and learn the
    # current refusal. Reject repeated attempts, not that first legitimate query.
    hold(r, 36)
    assert proposals_from(r, node) == outgoing, 'off node initiated a proposal'
    assert all(r.coverage.proposals[peer, node] - count <= 1 for peer, count in before.items()), 'off caused repeated proposals'
    r.verify()
    assert not r.durable_records(node), 'off retained saved Durable agreements'
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
    saved = paired_agreement(r, node, peer)
    if control:
        incoming = f'ip6 saddr {address(peer)} meta l4proto {{ tcp, udp }} th dport 58420'
        outgoing = f'ip6 daddr {address(peer)} meta l4proto {{ tcp, udp }} th dport 58420'
    else:
        incoming = '\n'.join(f'iifname "lan" {"ip" if family == 4 else "ip6"} saddr {r.wan(peer, family)} meta l4proto udp counter name dropped drop'
                             for family in families(r.args.underlay))
        outgoing = None  # A one-way underlay blackhole; bootstrap remains usable.
    if control:
        incoming += ' counter name dropped drop'
    rules = f'''table inet coverage_fault {{
 counter dropped {{ }}
 chain input {{ type filter hook input priority -20; policy accept;
 {incoming}
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
        if control and saved:
            wait_for(r, lambda: direct_pair(r, node, peer) and paired_agreement(r, node, peer) == saved,
                     r.args.settle_timeout, 'Durable could not recover without routed control')
            r.record('durable-control-independent', node=node, peer=peer, agreement=saved)
            r.verify()
            return
        hold(r, 20 if control else 40)
        def fallback():
            # Interface loss may still be inside the ordinary retry backoff;
            # wait until a real packet reaches the rule before accepting it.
            if not packet_count(r, node):
                return False
            for n, target in ((node, peer), (peer, node)):
                routes = json.loads(r.ip(n, '-6', '-j', 'route', 'show', 'table', '20000',
                                        'exact', address(target) + '/128'))
                finite = [route for route in routes if route.get('type', 'unicast') == 'unicast']
                if not finite:
                    return False
                best = min(finite, key=lambda route: route.get('metric', 0))
                if str(best.get('protocol')) != '203' or best.get('dev') in before[n]:
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
    saved = {peer: r.durable_records(peer) for peer in r.topology.active}
    before = {peer: dynamic(r, peer, node) for peer in sorted(r.topology.active & r.topology.public)
              if peer != r.topology.boot[node]}
    old_wan = {family: r.wan(node, family) for family in families(r.args.underlay)}
    old_process = r.nat_processes[node]
    old_process.terminate()
    old_process.wait(timeout=5)
    assert old_process.returncode == 0, 'NAT fixture shutdown failed'
    r.nat_epochs[node] += 1
    if rebind:
        r.wan_epochs[node] += 1
        for family, address in old_wan.items():
            width = '/24' if family == 4 else '/64'
            r.ip(f'r{node}', 'addr', 'del', address + width, 'dev', 'wan')
            # Replace addresses while the translator is stopped.
            r.ip(f'r{node}', 'addr', 'add', r.wan(node, family) + width, 'dev', 'wan')
        mapping, filtering, allocation = r.topology.profiles[node]
        r.topology.profiles[node] = (mapping, filtering, 'offset' if allocation == 'preserve' else 'preserve')
    r.nodes[node]['resources'].pop('nat', None)  # Explicit fixture-only replacement.
    r.coverage.reset(node)
    r.start_nat(node)
    r.record('nat-restarted', node=node, old_pid=old_process.pid, new_pid=r.nat_processes[node].pid,
             epoch=r.nat_epochs[node], old_wan=old_wan,
             new_wan={family: r.wan(node, family) for family in families(r.args.underlay)}, profile=r.topology.profiles[node])
    r.verify()
    status = json.loads((r.runtime / f'nat-{node}.json').read_text())
    assert status['created'] > 0 and status['in'] > 0, 'replacement NAT did not forward real traffic'
    if rebind:
        for peer, old_links in before.items():
            current = dynamic(r, peer, node)
            assert current, 'rebound NAT lost required direct link'
            for value in current.values():
                host, port = value['endpoint'].rsplit(':', 1)
                endpoint = ipaddress.ip_address(host.strip('[]'))
                assert endpoint == ipaddress.ip_address(r.wan(node, endpoint.version)), 'stale WAN endpoint'
                assert all(value['endpoint'] != old['endpoint'] for old in old_links.values()), 'endpoint did not change'
        r.record('endpoint-change-verified', node=node, wan=r.wan(node))
        for owner, records in saved.items():
            for record in records:
                if r.uids[node] not in (r.uids[owner], record['peer']['uuid']):
                    continue
                other = next(n for n, uid in r.uids.items() if uid == record['peer']['uuid']) if owner == node else owner
                if other not in before:
                    # An optional NAT/NAT Link may still be disconnected. No
                    # new authenticated endpoint observation has invalidated it;
                    # that agreement follows the controlled failure window.
                    # A Static-suppressed agreement likewise has no observation
                    # of its own endpoint merely because Static carries traffic.
                    continue
                current = {agreement(item): item for item in r.durable_records(owner)}
                if any(uid == r.uids[node] for uid, _ in fixed(record, r.uids[owner])):
                    old_id = agreement(record)
                    wait_for(r, lambda: all(agreement(item) != old_id for item in r.durable_records(owner)),
                             30, 'changed fixed endpoint kept old agreement after fresh health observations')
                elif record['confirmed']:
                    assert agreement(record) in current, 'variable endpoint change lost agreement'


def exercise(r, name):
    if name == 'durable':
        durable_recovery(r)
        return
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


def paired_agreement(r, node, peer):
    records = []
    for a, b in ((node, peer), (peer, node)):
        value = next((item for item in r.durable_records(a)
                      if item['peer']['uuid'] == r.uids[b] and item['confirmed']), None)
        if value is None:
            return None
        records.append(value)
    if (agreement(records[0]) == agreement(records[1])
            and fixed(records[0], r.uids[node]) == fixed(records[1], r.uids[peer])):
        return agreement(records[0])
    return None


def direct_pair(r, node, peer):
    for a, b in ((node, peer), (peer, node)):
        links = dynamic(r, a, b)
        if not links or not all(p['handshake'] and {'0.0.0.0/0', '::/0'} <= set(p['allowed'])
                                for p in links.values()):
            return False
        routes = json.loads(r.ip(a, '-6', '-j', 'route', 'show', 'table', '20000', 'exact', address(b) + '/128'))
        finite = [route for route in routes if route.get('type', 'unicast') == 'unicast']
        if not finite:
            return False
        best = min(route.get('metric', 0) for route in finite)
        if any(route.get('dev') not in links for route in finite if route.get('metric', 0) == best):
            return False
    return r.ping(node, peer) and r.ping(peer, node)


def durable_recovery(r):
    selected = []

    def qualified():
        # Soft admission does not promise that any particular pair promotes.
        # Select an actually bilateral agreement without changing product limits.
        for node in sorted(r.topology.active - r.topology.public):
            for peer in sorted(r.topology.active & r.topology.public):
                if peer != r.topology.boot[node] and paired_agreement(r, node, peer):
                    selected[:] = node, peer
                    return True
        return False

    wait_for(r, qualified,
             r.args.settle_timeout + getattr(r.args, 'durable_stable_seconds', 1800),
             'both peers did not durably save the same agreement')
    node, peer = selected
    saved = paired_agreement(r, node, peer)
    records = {n: next(item for item in r.durable_records(n) if agreement(item) == saved) for n in (node, peer)}
    survivors = {n: info['proc'].pid for n, info in r.nodes.items() if n not in (node, peer)}
    r.record('durable-cold-start', node=node, peer=peer, agreement=saved)
    r.isolated_static.update((node, peer))
    try:
        # Both namespaces and NAT state disappear; only node identity/configuration
        # and saved Durable state survive. No old WG interface can satisfy this.
        for n in (node, peer):
            r.stop_node(n, abrupt=True)
        for n in (node, peer):
            r.add_node(n)
        wait_for(r, lambda: paired_agreement(r, node, peer) == saved and direct_pair(r, node, peer),
                 r.args.settle_timeout, 'cold Durable could not recover with all Static paths blocked')
        for n, record in records.items():
            current = next(item for item in r.durable_records(n) if agreement(item) == saved)
            assert fixed(current, r.uids[n]) == fixed(record, r.uids[n]), 'cold recovery changed recovery endpoints'
            if any(uid == r.uids[n] for uid, _ in fixed(record, r.uids[n])):
                assert current['local']['listen_port'] == record['local']['listen_port'], 'cold recovery lost fixed port'
        for n, pid in survivors.items():
            assert r.nodes[n]['proc'].pid == pid, 'cold exercise restarted an unrelated node'
        r.record('durable-cold-verified', node=node, peer=peer, agreement=saved)
    finally:
        r.isolated_static.difference_update((node, peer))
        for n in (node, peer):
            if n in r.nodes:
                r.ns(n, 'nft', 'delete', 'table', 'inet', 'durable_isolation')
    r.verify()
    # Let a configured Static take over this exact peer pair. Its different WG
    # ports must not be mistaken for a mutation of the standby Durable agreement.
    original_bootstrap = r.topology.boot[node]
    try:
        r.topology.boot[node] = peer
        reload_mode(r, node, r.topology.modes[node])
        r.verify()
        assert paired_agreement(r, node, peer) == saved, 'Static takeover erased standby Durable'
        assert not dynamic(r, node, peer) and not dynamic(r, peer, node), 'Static left duplicate automatic resources'
        r.record('durable-static-standby', node=node, peer=peer, agreement=saved)
    finally:
        r.topology.boot[node] = original_bootstrap
        reload_mode(r, node, r.topology.modes[node])
    r.verify()
    assert paired_agreement(r, node, peer) == saved and direct_pair(r, node, peer), 'standby Durable did not resume'
    r.record('durable-standby-resumed', node=node, peer=peer, agreement=saved)
