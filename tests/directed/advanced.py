"""Observer, phase-specific crash, address-family and routed NAT scenarios."""
import ipaddress
import json
from pathlib import Path
import signal
import socket
import time

from model import address, parse_wg
from mutations import wait_for
from scenarios import (MAGIC, table, hits, delete_table,
                       data, assert_direct, direct_names)


def await_event(r, predicate, reason, seconds=90):
    # Sample logs frequently to inject before the next protocol stage. Logs
    # select the trigger; kernel/WG/FIB and packets decide acceptance.
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        r.timeout()  # Honor operator cancellation even before the first audit.
        if predicate():
            r.record('stage-trigger', reason=reason)
            return
        for info in r.nodes.values():
            assert info['proc'].poll() is None, 'velvetd exited before fault injection'
        time.sleep(0.02)
    raise TimeoutError(reason)


def babel(r, node, command, **params):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(2)
        sock.connect(f'/run/velvet/{r.uids[node]}/babel-rs.ctl')
        with sock.makefile('rwb') as stream:
            json.loads(stream.readline())
            stream.write((json.dumps({'api_version': 1, 'id': 1, 'command': command, 'params': params}) + '\n').encode())
            stream.flush()
            response = json.loads(stream.readline())
            if not response.get('ok'):
                raise RuntimeError(response)
            return response['result']


def routing_prerequisite(r, node, peer=0):
    started, last = time.monotonic(), {}
    while time.monotonic() - started < 240:
        r.timeout()
        try:
            states = {n: babel(r, n, 'status') for n in (peer, node)}
            routes = {n: babel(r, n, 'routes', destination=address(p) + '/128') for n, p in ((peer, node), (node, peer))}
            last = {'states': states, 'routes': routes}
            healthy = all(s.get('ready') and not s['export']['last_error'] for s in states.values())
            fresh = all(any(x.get('selected') and x.get('source') is None and
                           x.get('sequence_number') == states[p]['sequence_number'] for x in routes[n]['routes'])
                        for n, p in ((peer, node), (node, peer)))
            if healthy and fresh:
                r.save('babel-recovery.json', last)
                r.record('babel-prerequisite-verified', seconds=round(time.monotonic() - started, 3))
                return
        except (OSError, ValueError, RuntimeError) as error:
            last = {'error': str(error)}
        time.sleep(1)
    r.save('babel-recovery.json', last)
    raise TimeoutError('Babel current-sequence prerequisite exceeded 240s')


def restart(r, node):
    old = r.nodes[node]
    old_pid = old['proc'].pid
    old['proc'].kill()
    old['proc'].wait(timeout=5)
    old['thread'].join(timeout=3)
    # Preserve namespace, addresses, NAT mappings, UUID/state and old kernel
    # interfaces. This is an actual velvetd crash, not a delete/re-add event.
    until = time.monotonic() + 12
    while r.run('ip', 'netns', 'pids', r.namespace(node)):
        if time.monotonic() >= until:
            raise AssertionError('managed Babel survived its killed parent')
        time.sleep(0.1)
    r.start_daemon(node)
    assert r.nodes[node]['proc'].pid != old_pid
    r.record('crash-restarted', node=node, old_pid=old_pid, new_pid=r.nodes[node]['proc'].pid)


def observer(r):
    if r.kind == 'observer-loss':
        # First gate proves the listener was prepared and actual measurement
        # packets reached it. Remove it, then interrupt after a received sample.
        delete_table(r, 0, 'observer_gate')
        r.ns(0, 'tc', 'qdisc', 'add', 'dev', 'wan', 'root', 'netem', 'delay', '500ms')
        await_event(r, lambda: bool(r.find_events(2, 'velvet-udp-observe', 'prepared', 0)), 'observer 0 ready')
        table(r, 0, 'observer_gate', f'meta l4proto udp {MAGIC}')
        delete_table(r, 1, 'observer_gate')
        wait_for(r, lambda: hits(r, 0, 'observer_gate') > 0 and
                 bool(r.find_events(2, 'velvet-udp-observe', 'measured', 1)), 90,
                 'measurement loss did not fall back to second observer')
        r.ns(0, 'tc', 'qdisc', 'del', 'dev', 'wan', 'root')
        delete_table(r, 0, 'observer_gate')
    elif r.kind == 'observer-nat':
        wait_for(r, lambda: r.pair_finished(2, 3) and
                 bool(r.find_events(2, 'velvet-udp-observe', 'prepared', 4)), 90,
                 'NAT observer was not tried before bounded failure')
        assert not r.find_events(None, 'velvet-udp-observe', 'measured', 4), 'unexpected unsolicited NAT observer reachability'
        assert r.ping(2, 3) and r.ping(3, 2), 'observer failure lost routed fallback'
        for node in (2, 3):
            assert hits(r, node, 'observer_control_gate') > 0
            delete_table(r, node, 'observer_control_gate')
        for node in (0, 1):
            delete_table(r, node, 'observer_gate')
        r.record('observer-baseline-boundary', result='unmapped NAT listener unavailable; bounded fallback passed')
    elif r.kind == 'observer-ports':
        wait_for(r, lambda: r.pair_finished(2, 3), 90, 'unavailable observer ports did not terminate attempt')
        assert r.ping(2, 3) and r.ping(3, 2)
        for process in r.helpers:
            assert process.poll() is None, 'port reservation ended before the failure assertion'
            process.terminate()
            process.wait(timeout=3)
        r.record('observer-resource-fallback-verified', unavailable_ports_per_observer=1001)
    else:
        # Destination-dependent external addresses are configured on the NAT
        # fixture. Require actual measurements and both observed WAN addresses.
        wait_for(r, lambda: bool(r.find_events(2, 'velvet-udp-observe', 'measured', 1)), 90,
                 'alternate observer never supplied new evidence')
        for node in (2, 3):
            state = json.loads((r.runtime / f'nat-{node}.json').read_text())
            assert len(state['wan_created']) == 2 and all(state['wan_created'].values()), 'both real egress mappings were not exercised'
        r.record('observer-egress-disagreement-verified')
    r.verify()
    data(r, label=r.kind)


def stage_fault(r):
    node, peer = 2, 3
    if r.kind == 'crash-observe':
        await_event(r, lambda: bool(r.find_events(node, 'velvet-udp-observe', 'prepared')),
                    'active observation prepared before crash')
    else:
        stage = 'prepared' if r.kind == 'stale-candidate' else 'handoff'
        await_event(r, lambda: bool(r.find_events(node, 'velvet-udp-probe', stage, peer)),
                    f'pair {node}/{peer} reached {stage}')
    if r.kind == 'crash-commit':
        await_event(r, lambda: any(p['handshake'] for name, v in
                    parse_wg(r.ns(node, 'wg', 'show', 'all', 'dump')).items()
                    if name.startswith(f'vdl-n{peer}-') for p in v['peers']),
                    'real handshake before blocked commit', 25)
    snapshot = {str(n): {'wg': parse_wg(r.ns(n, 'wg', 'show', 'all', 'dump')),
        'fib': json.loads(r.ip(n, '-6', '-j', 'route', 'show', 'table', '20000')),
        'babel_sockets': r.ns(n, 'ss', '-H', '-uan', 'sport', '=', ':6696')} for n in (node, peer)}
    r.save('at-injection.json', snapshot)
    if r.kind in ('crash-handoff', 'crash-commit'):
        for n, p in ((node, peer), (peer, node)):
            state = snapshot[str(n)]
            names = {name for name in state['wg'] if name.startswith(f'vdl-n{p}-')}
            assert not any(route.get('dev') in names for route in state['fib']), 'blocked tentative WG entered FIB'
            assert not any(name + ':' in state['babel_sockets'] or name + ']' in state['babel_sockets'] for name in names), 'Babel attached before commit'
    if r.kind == 'stale-candidate':
        before = r.wan(node)
        process = r.nat_processes[node]
        process.terminate()
        process.wait(timeout=5)
        assert process.returncode == 0
        width = '/24' if r.args.underlay == 'ipv4' else '/64'
        r.ip('r2', 'addr', 'del', before + width, 'dev', 'wan')
        r.wan_epochs[node] += 1
        r.nat_epochs[node] += 1
        r.ip('r2', 'addr', 'add', r.wan(node) + width, 'dev', 'wan')
        r.nodes[node]['resources'].pop('nat', None)
        r.start_nat(node)
        r.record('candidate-invalidated', old_wan=before, new_wan=r.wan(node))
    else:
        restart(r, node)
    for n in ((0, 1) if r.kind == 'crash-observe' else (2, 3)):
        delete_table(r, n, 'observer_gate' if r.kind == 'crash-observe' else 'stage_gate')
    if r.kind != 'stale-candidate':
        routing_prerequisite(r, node)
    r.verify()
    assert_direct(r, 1, node)
    data(r, label=r.kind)


def family_change(r):
    r.verify()
    data(r, label='both-families-present')
    if r.kind == 'dual-stack-failure':
        family = 'ip' if r.args.underlay == 'ipv4' else 'ip6'
        r.topology.blocked_pairs.update(((2, 3), (3, 2)))
        for n, peer in ((2, 3), (3, 2)):
            table(r, n, 'family_gate', f'{family} saddr {r.wan(peer)} meta l4proto udp')
        try:
            def withdrawn():
                return all(not any(str(route.get('protocol')) == '202' for route in
                    json.loads(r.ip(n, '-6', '-j', 'route', 'show', 'table', '20000',
                                    'exact', address(p) + '/128'))) for n, p in ((2, 3), (3, 2)))
            wait_for(r, withdrawn, 40, 'failed direct adjacency did not withdraw within health budget')
            # A higher-cost Babel alternative can wait for feasibility history.
            # Require current selected routes before testing Fabric forwarding.
            routing_prerequisite(r, 2, 3)
            r.verify()
            assert all(hits(r, n, 'family_gate') for n in (2, 3))
            # Record whether the implementation migrated itself or chose the
            # supported routed fallback. Neither log claims nor a second local
            # address alone establish an alternate-family direct Link.
            names = direct_names(r, 2, 3)
            wg = parse_wg(r.ns(2, 'wg', 'show', 'all', 'dump'))
            endpoints = [wg[n]['peers'][0]['endpoint'] for n in names if wg[n]['peers']]
            r.record('single-family-loss-verified', endpoints=endpoints,
                     outcomes=r.coverage.state()['pairs'])
            data(r, label='one-family-unavailable')
        finally:
            for n in (2, 3):
                delete_table(r, n, 'family_gate')
            r.topology.blocked_pairs.clear()
        r.verify()
    elif r.kind == 'dual-stack':
        # Reordering hints alone preserves a healthy authenticated WG roaming
        # endpoint. Make the old underlay actually unavailable, then wait for
        # the production static-peer endpoint rotation (3min stale).
        old_family = r.args.underlay
        for n in r.topology.active:
            table(r, n, 'old_family', f'iifname "wan" meta nfproto {old_family} meta l4proto udp',
                  f'oifname "wan" meta nfproto {old_family} meta l4proto udp')
        r.args.underlay = 'ipv6' if old_family == 'ipv4' else 'ipv4'
        old_pids = {n: r.nodes[n]['proc'].pid for n in r.topology.active}
        for n in r.topology.active:
            old_babel = r.nodes[n]['resources']['babel']['pid']
            generation = r.command(n)['config_generation']
            r.write_config(n)
            r.nodes[n]['proc'].send_signal(signal.SIGHUP)
            until = time.monotonic() + 15
            while r.command(n)['config_generation'] <= generation:
                if time.monotonic() >= until:
                    raise TimeoutError('family configuration reload')
                time.sleep(0.1)
            assert not Path(f'/proc/{old_babel}').exists()
            r.nodes[n]['resources'].pop('babel', None)
        def switched():
            family = 6 if r.args.underlay == 'ipv6' else 4
            for n in (1, 2, 3):
                wg = parse_wg(r.ns(n, 'wg', 'show', 'all', 'dump'))
                link = wg.get('vl-boot-00')
                if not link or not link['peers']:
                    return False
                peer = link['peers'][0]
                if (not peer['handshake'] or ipaddress.ip_address(peer['endpoint'].rsplit(':', 1)[0].strip('[]')).version != family
                        or not r.ping(n, 0)):
                    return False
            return True
        await_event(r, switched, 'static bootstrap did not rotate onto working family', 240)
        assert all(hits(r, n, 'old_family') for n in r.topology.active), 'old-family failure was not exercised'
        # Fresh origin sequences are a separate routing dependency.
        routing_prerequisite(r, 2)
        r.verify()
        assert old_pids == {n: r.nodes[n]['proc'].pid for n in r.topology.active}
        for n in (2, 3):
            names = direct_names(r, n, 5 - n)
            wg = parse_wg(r.ns(n, 'wg', 'show', 'all', 'dump'))
            assert names
            assert all(ipaddress.ip_address(wg[name]['peers'][0]['endpoint'].rsplit(':', 1)[0].strip('[]')).version
                       == (6 if r.args.underlay == 'ipv6' else 4) for name in names)
        r.record('configured-family-migration-verified', before=old_family, after=r.args.underlay)
    else:
        # A second physical egress, a new source address, and route replacement
        # without reloading/restarting velvetd or managed Babel.
        node = 2
        pids = {n: (v['proc'].pid, v['resources']['babel']['pid']) for n, v in r.nodes.items()}
        root, other = 'vex' + r.token, 'vey' + r.token
        r.run('ip', 'link', 'add', root, 'type', 'veth', 'peer', 'name', other)
        r.root_links.update((root, other))
        r.run('ip', 'link', 'set', root, 'master', r.bridge)
        r.run('ip', 'link', 'set', root, 'up')
        r.run('ip', 'link', 'set', other, 'netns', r.namespace(node), 'name', 'wan2')
        r.root_links.discard(other)
        r.wan_epochs[node] += 1
        r.ip(node, 'link', 'set', 'wan2', 'up')
        r.ip(node, 'addr', 'add', r.wan(node) + ('/24' if r.args.underlay == 'ipv4' else '/64'), 'dev', 'wan2')
        r.ip(node, 'link', 'set', 'wan', 'down')
        subnet = '192.0.2.0/24' if r.args.underlay == 'ipv4' else '2001:db8:ee::/64'
        r.ip(node, '-4' if r.args.underlay == 'ipv4' else '-6', 'route', 'replace', subnet, 'dev', 'wan2', 'src', r.wan(node))
        r.verify()
        assert pids == {n: (v['proc'].pid, v['resources']['babel']['pid']) for n, v in r.nodes.items()}
        r.record('egress-migration-verified', node=node, source=r.wan(node), interface='wan2')
    data(r, label='after-migration')


def execute(r):
    if r.kind.startswith('observer'):
        observer(r)
    elif r.kind.startswith('crash') or r.kind == 'stale-candidate':
        stage_fault(r)
    elif r.kind in ('dual-stack', 'dual-stack-failure', 'egress-switch'):
        family_change(r)
    elif r.kind in ('nested-nat', 'shared-nat'):
        from kernel_nat import exercise
        exercise(r)
    else:
        raise ValueError(r.kind)
