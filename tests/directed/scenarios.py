"""Fault injection and real-packet assertions for the bounded E2E suite."""
import ipaddress
import json
from pathlib import Path
import subprocess as sp
import sys
import time

from model import address, parse_wg
from mutations import hold, reset_nat

# Match the public encrypted probe type too. Magic alone would also drop
# LINK_PING/PONG inside WG and destroy the very Fabric used for observation.
MAGIC = '@th,64,32 0x56465000 @th,104,8 0x0c'


def alt_wan(r, node):
    return f'2001:db8:ee::{node + 1:x}' if r.args.underlay == 'ipv4' else f'192.0.2.{node + 1}'


def endpoint(host, port):
    return f'[{host}]:{port}' if ':' in host else f'{host}:{port}'


def table(r, node, name, incoming='', outgoing=''):
    rules = f'table inet {name} {{\n counter hits {{ }}\n'
    for chain, match in (('input', incoming), ('output', outgoing)):
        if match:
            rules += f' chain {chain} {{ type filter hook {chain} priority -30; policy accept;\n {match} counter name hits drop\n }}\n'
    r.ns(node, 'nft', '-f', '-', input=rules + '}\n')


def hits(r, node, name):
    data = json.loads(r.ns(node, 'nft', '-j', 'list', 'table', 'inet', name))
    return sum(e.get('counter', {}).get('packets', 0) for e in data['nftables'])


def delete_table(r, node, name):
    # Teardown remains bounded but must run after a phase deadline/cancellation.
    previous = r.deadline, r.stop_signal
    r.deadline, r.stop_signal = None, None
    try:
        r.ns(node, 'nft', 'delete', 'table', 'inet', name)
    finally:
        r.deadline, r.stop_signal = previous


def helper(r, node, kind, host, duration=60):
    status = r.runtime / f'helper-{kind}-{node}.json'
    with (r.artifacts / f'helper-{kind}-{node}.log').open('w') as log:
        p = sp.Popen(['ip', 'netns', 'exec', r.namespace(node), sys.executable,
            str(Path(__file__).with_name('helper.py')), kind, host, str(status),
            '--duration', str(duration)], stdout=log, stderr=log)
    r.helpers.append(p)
    r.helper_nodes[p.pid] = node
    until = time.monotonic() + 5
    while not status.exists():
        assert p.poll() is None, 'fault helper failed before readiness'
        if time.monotonic() >= until:
            raise TimeoutError('fault helper did not become ready')
        time.sleep(0.05)
    return p, status


def configure(r, node, config):
    if r.kind in ('dual-stack', 'dual-stack-failure', 'egress-switch'):
        config['dynamic_links']['allow_candidate_prefixes'] = ['192.0.2.0/24', '2001:db8:ee::/64']
        for peer in config['peers']:
            if peer['name'] == 'bootstrap':
                peer['endpoints'].append(endpoint(alt_wan(r, r.topology.boot[node]), 52000 + node))


def prepare_node(r, node):
    if r.kind == 'contention' and node == 2:
        # Begin competing allocations before this daemon can create its first
        # Link. Deleting an established Link first would additionally inject
        # Babel feasibility recovery and obscure the allocation experiment.
        until = time.monotonic() + 5
        while True:
            assert r.nat_processes[node].poll() is None, 'translator exited before contention'
            try:
                baseline = json.loads((r.runtime / 'nat-2.json').read_text())
                break
            except (FileNotFoundError, json.JSONDecodeError):
                if time.monotonic() >= until:
                    raise TimeoutError('translator readiness before contention')
                time.sleep(0.05)
        process, status = helper(r, node, 'traffic', r.wan(1), 210)
        r.contention = process, status, baseline
        r.record('allocation-contention-start', node=node)
    if r.kind in ('shared-nat', 'nested-nat'):
        from kernel_nat import prepare
        prepare(r, node)
    if r.kind in ('dual-stack', 'dual-stack-failure', 'egress-switch'):
        other = alt_wan(r, node)
        r.ip(node, 'addr', 'add', other + ('/64' if ':' in other else '/24'), 'dev', 'wan')
    if r.kind.startswith('observer') or r.kind == 'crash-observe':
        if r.kind == 'observer-nat' and node in (2, 3):
            # Skip unavailable public observers at the control-open stage, so
            # the 30s task has time to actually try the baseline NAT observer.
            table(r, node, 'observer_control_gate', outgoing=
                  f'ip6 daddr {{ {address(0)}, {address(1)} }} tcp dport 58420')
        if node in (0, 1):
            # Keep static WG and Fabric working; only public measurement UDP
            # is gated. The fallback observer is node 4, itself behind NAT.
            if r.kind in ('observer-nat', 'observer-loss', 'crash-observe'):
                table(r, node, 'observer_gate', f'meta l4proto udp {MAGIC}')
        if r.kind == 'observer-ports' and node == 2:
            # Static WG receivers need ephemeral sockets during initial setup.
            # Exhaust the remaining pool only after both public daemons have
            # reconciled it; the clients have not started discovery yet.
            for observer in (0, 1):
                until = time.monotonic() + 15
                while True:
                    assert r.nodes[observer]['proc'].poll() is None
                    try:
                        if r.command(observer)['runtime'].get('babel', {}).get('pid'):
                            break
                    except (OSError, ValueError):
                        pass
                    if time.monotonic() >= until:
                        raise TimeoutError('public observer startup before exhaustion')
                    time.sleep(0.1)
                _, status = helper(r, observer, 'ports', r.wan(observer), 120)
                ownership = json.loads(status.read_text())
                assert ownership['bound'] > 0 and sum(ownership.values()) == 1001
                r.record('observer-pool-exhausted', node=observer, **ownership)
    if r.kind in ('crash-handoff', 'crash-commit', 'stale-candidate') and node in (2, 3):
        peer = 5 - node
        if r.kind == 'crash-commit':
            table(r, node, 'stage_gate', f'iifname "vdl-n{peer}-*" meta l4proto {{ tcp, udp }} th dport 58420')
        elif r.kind == 'crash-handoff':
            # Block WG packets (little-endian packet types 1..4), not VFP
            # encrypted probes, to hold the Link before its first handshake.
            fam = 'ip' if r.args.underlay == 'ipv4' else 'ip6'
            table(r, node, 'stage_gate', f'{fam} saddr {r.wan(peer)} meta l4proto udp @th,64,32 {{ 0x01000000, 0x02000000, 0x03000000, 0x04000000 }}')
        else:
            table(r, node, 'stage_gate', f'meta l4proto udp {MAGIC}')


def direct_names(r, a, b):
    # Select this dynamic interface explicitly: the same node key can also
    # appear on static links, which must not stand in for this adjacency.
    return [n for n in parse_wg(r.ns(a, 'wg', 'show', 'all', 'dump')) if n.startswith(f'vdl-n{b}-')]


def assert_direct(r, a, b):
    for node, peer in ((a, b), (b, a)):
        names = direct_names(r, node, peer)
        routes = json.loads(r.ip(node, '-6', '-j', 'route', 'show', 'table', '20000',
                                'exact', address(peer) + '/128'))
        assert any(route.get('dev') in names and str(route.get('protocol')) == '202' for route in routes), 'missing direct adjacency'
        assert r.ping(node, peer), 'direct traffic failed'


def data(r, a=2, b=3, label='healthy'):
    for protocol in ('tcp', 'udp'):
        for source, target in ((a, b), (b, a)):
            filename = f'{label}-{protocol}-{source}-{target}'
            log_path = r.artifacts / (filename + '-server.json')
            with log_path.open('w') as log:
                process = sp.Popen(['ip', 'netns', 'exec', r.namespace(target), 'iperf3', '-s', '-1',
                    '-B', address(target), '-p', '59001', '-J'], stdout=log, stderr=log)
            r.helpers.append(process)
            r.helper_nodes[process.pid] = target
            try:
                until = time.monotonic() + 5
                while ':59001' not in r.ns(target, 'ss', '-H', '-ltn'):
                    assert process.poll() is None, 'iperf server exited before listen'
                    if time.monotonic() >= until:
                        raise TimeoutError('iperf server readiness')
                    time.sleep(0.05)
                options = ['-u', '-b', '1M', '-l', '1000'] if protocol == 'udp' else ['-b', '4M']
                result = sp.run(['ip', 'netns', 'exec', r.namespace(source), 'iperf3', '-6',
                    '-c', address(target), '-B', address(source), '-p', '59001', '-t', '5', '-J', *options],
                    capture_output=True, text=True, timeout=20)
                (r.artifacts / (filename + '-client.json')).write_text(result.stdout)
                assert result.returncode == 0, result.stderr
                client = json.loads(result.stdout)
                assert 'error' not in client, client.get('error')
                process.wait(timeout=5)
                assert process.returncode == 0, 'iperf receiver failed'
                server = json.loads(log_path.read_text())
                assert 'error' not in server, server.get('error')
                received = server['end']['sum_received']
                assert received['bytes'] >= 300000, f'{protocol} receiver did not receive expected business traffic'
                if protocol == 'udp':
                    assert received['lost_packets'] == 0, 'UDP lost data on restored stable path'
                r.record('traffic-verified', protocol=protocol, source=source, target=target,
                         received=received['bytes'], label=label)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=3)


def partition(r):
    r.verify()
    identities = {n: (i['proc'].pid, i['resources']['babel']['pid']) for n, i in r.nodes.items()}
    groups = ({0, 2}, {1, 3})
    def devices(group):
        return '{ ' + ', '.join(f'"ver{r.token}{n:x}"' for n in sorted(group)) + ' }'
    name = 'vp' + r.token
    rules = f'''table bridge {name} {{
 counter cut {{ }}
 chain forward {{ type filter hook forward priority -200; policy accept;
 iifname {devices(groups[0])} oifname {devices(groups[1])} counter name cut drop
 iifname {devices(groups[1])} oifname {devices(groups[0])} counter name cut drop
 }}
}}'''
    r.run('nft', '-f', '-', input=rules)
    r.root_tables.add(('bridge', name))
    r.topology.groups = groups
    try:
        r.record('partition-start', groups=[sorted(g) for g in groups])
        r.verify()
        for a in groups[0]:
            for b in groups[1]:
                assert not r.ping(a, b) and not r.ping(b, a), 'partition leaked traffic'
        counters = json.loads(r.run('nft', '-j', 'list', 'table', 'bridge', name))
        dropped = sum(e.get('counter', {}).get('packets', 0) for e in counters['nftables'])
        assert dropped, 'partition rules never matched'
        r.record('partition-verified', dropped=dropped)
    finally:
        r.run('nft', 'delete', 'table', 'bridge', name)
        r.root_tables.discard(('bridge', name))
        r.topology.groups = None
    r.verify()
    assert identities == {n: (i['proc'].pid, i['resources']['babel']['pid']) for n, i in r.nodes.items()}, 'partition recovery restarted a daemon'
    data(r, label='merged')


def nat_change(r):
    r.verify()
    before = r.contention[2] if r.kind == 'contention' else json.loads((r.runtime / 'nat-2.json').read_text())
    if r.kind == 'rebind':
        # This verifies arbitrary allocation modes too; the old helper matches
        # node keys, so explicitly inspect actual dynamic interface endpoints.
        old = r.wan(2)
        reset_nat(r, 2, rebind=True)
        names = direct_names(r, 1, 2)
        wg = parse_wg(r.ns(1, 'wg', 'show', 'all', 'dump'))
        assert names and all(ipaddress.ip_address(wg[n]['peers'][0]['endpoint'].rsplit(':', 1)[0].strip('[]'))
                             == ipaddress.ip_address(r.wan(2)) for n in names), 'rebind kept old endpoint'
        r.record('wan-migration-verified', old=old, new=r.wan(2))
    elif r.kind == 'expiry':
        router = 'r2'
        # Stop refreshing mappings in both directions; translator remains alive
        # and expires them by idle timer, not a test command that clears state.
        fam = 'ip' if r.args.underlay == 'ipv4' else 'ip6'
        table(r, 2, 'idle_gate', 'meta l4proto udp', 'meta l4proto udp')
        table(r, router, 'idle_gate', 'iifname "wan" meta l4proto udp')
        try:
            hold(r, 16)
            after = json.loads((r.runtime / 'nat-2.json').read_text())
            assert after['expired'] > before['expired'] and after['entries'] == 0, 'idle mappings did not actually expire'
            r.record('mapping-expiry-verified', before=before, after=after)
        finally:
            delete_table(r, 2, 'idle_gate')
            delete_table(r, router, 'idle_gate')
        r.verify()
    else:
        process, status, _ = r.contention
        try:
            assert process.poll() is None, 'competing allocations ended before Link validation'
            assert json.loads(status.read_text())['sent'] >= 10, 'no competing traffic'
            after = json.loads((r.runtime / 'nat-2.json').read_text())
            assert after['created'] >= before['created'] + 10, 'competing packets did not create real mappings'
            r.record('allocation-contention-verified', before=before, after=after)
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=3)
    assert_direct(r, 1, 2)
    data(r, 1, 2, label=r.kind)


def mtu(r):
    r.verify()
    assert_direct(r, 2, 3)
    data(r)
    for source, target in ((2, 3), (3, 2)):
        names = direct_names(r, source, target)
        link = json.loads(r.ip(source, '-j', 'link', 'show', 'dev', names[0]))[0]
        maximum = link['mtu'] - 48  # Inner IPv6 + ICMPv6.
        for payload in (0, 1200, maximum):
            r.ns(source, 'ping', '-6', '-c', '2', '-W', '2', '-M', 'do', '-s', str(payload), address(target))
        result = sp.run(['ip', 'netns', 'exec', r.namespace(source), 'ping', '-6', '-c', '1',
            '-W', '1', '-M', 'do', '-s', str(maximum + 1), address(target)], capture_output=True, text=True, timeout=3)
        assert result.returncode != 0 and ('too long' in result.stderr.lower() or 'mtu' in result.stderr.lower()), 'oversized DF packet was not explicitly rejected'
        r.record('mtu-boundary-verified', source=source, maximum_payload=maximum)
    # Keep the production WG MTU; introduce a smaller underlay and verify PMTU
    # / kernel fragmentation with real business packets, including UDP 1000 B.
    for node in r.topology.active:
        r.ip(node, 'link', 'set', 'wan', 'mtu', '1360')
    data(r, label='underlay-1360')
    r.verify()


def execute(r):
    if r.kind == 'observer-concurrency':
        from resources import exercise
        exercise(r)
    elif r.kind == 'matrix':
        r.verify()
    elif r.kind == 'partition':
        partition(r)
    elif r.kind in ('expiry', 'contention', 'rebind'):
        nat_change(r)
    elif r.kind == 'data-mtu':
        mtu(r)
    else:
        from advanced import execute as advanced
        advanced(r)
