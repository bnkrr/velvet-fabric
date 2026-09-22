"""Durable acceptance checks on the real public A--C--B test topology."""
from datetime import datetime, timezone
import json
from pathlib import Path
import signal
import socket
import subprocess as sp
import time


def exercise_durable(config, ns, ip, runtime, processes, logs, uuids, daemon, wan, match):
    namespaces = {node: sp.check_output(['ip', 'netns', 'identify', str(processes[i].pid)], text=True).strip()
                  for i, node in enumerate('abc')}

    def control(node, command, params=None):
        path = '/run/velvet/' + uuids['abc'.index(node)] + '/velvetd.ctl'
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(5)
            conn.connect(path)
            with conn.makefile('rwb') as stream:
                json.loads(stream.readline())
                stream.write((json.dumps({'api_version': 1, 'id': 1, 'command': command, 'params': params}) + '\n').encode())
                stream.flush()
                reply = json.loads(stream.readline())
                assert reply['ok'], reply
                return reply['result']

    def status(node):
        return control(node, 'status')['runtime']

    def records(node):
        path = Path('/var/lib/velvet') / uuids['abc'.index(node)] / 'durable.json'
        return json.loads(path.read_text())['records'] if path.exists() else []

    def recovery_count(record):
        return sum(bool(record[side].get('recovery_endpoint')) for side in ('local', 'peer'))

    def wait_for(predicate, description, seconds=60):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            if any(p.poll() is not None for p in processes):
                raise AssertionError('daemon exited during ' + description)
            if predicate():
                return
            time.sleep(.5)
        raise AssertionError(description)

    def restart(node):
        i = 'abc'.index(node)
        # Obtain the test namespace via the running process, avoiding any
        # dependency on the caller's namespace naming convention.
        namespace = namespaces[node]
        processes[i].terminate()
        processes[i].wait(timeout=15)
        processes[i] = sp.Popen(['ip', 'netns', 'exec', namespace, daemon,
                                '--config', str(runtime / f'{node}.json'), '--reconcile-interval', '1s'],
                               stdout=logs[i], stderr=sp.STDOUT)

    wait_for(lambda: all(records(n) and records(n)[0]['confirmed'] for n in 'ab'), 'bilateral durable promotion')
    saved = {n: records(n)[0] for n in 'ab'}
    assert saved['a']['agreement_id'] == saved['b']['agreement_id'], 'agreement IDs differ'
    assert all(recovery_count(saved[n]) == config.get('fixed_count', 2) for n in 'ab'), 'incorrect recovery endpoint set'
    if config['ports'] == 'range':
        assert all(40000 <= saved[n]['local']['listen_port'] <= 40031 for n in 'ab'), 'range escaped'
    if config['ports'] == 'fixed':
        assert [saved[n]['local']['listen_port'] for n in 'ab'] == [42001, 42002], 'fixed allocation changed'
    print('durable: both peers saved; cutting all static bootstrap paths', flush=True)
    for node in 'ab':
        ns(node, 'nft', '-f', '-', input=f'''table inet durable_static_cut {{
 chain input {{ type filter hook input priority -50; policy accept; {match} saddr {wan['c']} drop; }}
 chain output {{ type filter hook output priority -50; policy accept; {match} daddr {wan['c']} drop; }}
}}''')
    def restored():
        for node, remote in (('a', 'b'), ('b', 'a')):
            interface = f'vdl-{remote}-7100'
            if interface not in ns(node, 'wg', 'show', 'interfaces').split():
                return False
            if ns(node, 'wg', 'show', interface, 'listen-port') != str(saved[node]['local']['listen_port']):
                raise AssertionError('cold restore changed persisted port')
            if int(ns(node, 'wg', 'show', interface, 'latest-handshakes').split()[1]) == 0:
                return False
            target = 'fd78:7777::' + ('2' if remote == 'b' else '1') + '/128'
            if ('dev ' + interface) not in ip(node, '-6', 'route', 'show', 'table', '20000', 'exact', target):
                return False
        return True
    for node in 'ab':
        restart(node)
        wait_for(restored, 'cold bootstrap without routed VFP after restarting ' + node)
    ns('a', 'ping', '-6', '-n', '-c', '2', '-W', '2', '-I', 'fd78:7777::1', 'fd78:7777::2')
    print('durable: cold bootstrap and payload passed', flush=True)
    if config.get('fixed_count') == 1:
        path = runtime / 'b.json'
        spec = json.loads(path.read_text())
        spec['node']['port_range'] = {'first': 41000, 'last': 41031}
        path.write_text(json.dumps(spec))
        # The remap fixture originally has exactly one external port. Move the
        # mapping too, so its old conntrack entry cannot occupy the only tuple
        # and prevent the new local socket from emitting any packets.
        ns('rb', 'nft', 'flush', 'chain', 'ip', 'velvet_test', 'post')
        ns('rb', 'nft', 'add', 'rule', 'ip', 'velvet_test', 'post',
           'oifname', 'wan', 'meta', 'l4proto', 'udp', 'snat', 'to', wan['rb'] + ':45001')
        restart('b')
        wait_for(lambda: records('b') and 41000 <= records('b')[0]['local']['listen_port'] <= 41031
                 and 'dev vdl-a-7100' in ip('b', '-6', 'route', 'show', 'table', '20000', 'exact', 'fd78:7777::1/128'),
                 'variable side failed to restore on its changed local port')
        assert all(records(n)[0]['agreement_id'] == saved[n]['agreement_id'] for n in 'ab'), 'variable side changed agreement'
        assert ns('a', 'wg', 'show', 'vdl-b-7100', 'endpoints').endswith(':45001'), 'peer did not learn new variable endpoint'
        ns('b', 'ping', '-6', '-n', '-c', '2', '-W', '2', '-I', 'fd78:7777::2', 'fd78:7777::1')
        print('durable: variable side changed port without losing agreement', flush=True)
    for node in 'ab':
        ns(node, 'nft', 'delete', 'table', 'inet', 'durable_static_cut')
    if config.get('long_failure'):
        for node in 'ab':
            peer = 'b' if node == 'a' else 'a'
            ns(node, 'nft', '-f', '-', input=f'''table inet durable_direct_cut {{
 chain input {{ type filter hook input priority -50; policy accept; {match} saddr {wan[peer]} meta l4proto udp drop; }}
 chain output {{ type filter hook output priority -50; policy accept; {match} daddr {wan[peer]} meta l4proto udp drop; }}
}}''')
        def checking(node):
            entries = status(node).get('durable', [])
            return entries and entries[0].get('failed_since')
        wait_for(lambda: all(checking(n) for n in 'ab'), 'READY failure timer did not start', 120)
        processes[1].terminate()
        processes[1].wait(timeout=15)
        time.sleep(40)
        assert records('a') and not checking('a'), 'offline peer did not reset failure time'
        restart('b')
        wait_for(lambda: all(checking(n) for n in 'ab'), 'READY failure timer did not restart', 90)
        earliest = min(datetime.fromisoformat(checking(n)) for n in 'ab')
        started = time.monotonic() - (datetime.now(timezone.utc) - earliest).total_seconds()
        next_report = time.monotonic()
        print('durable: offline reset passed; checking real 30-minute READY failure budget', flush=True)
        while time.monotonic() - started < 1790:
            assert all(records(n) for n in 'ab'), 'agreement deleted before failure budget'
            assert all(p.poll() is None for p in processes), 'daemon exited'
            if time.monotonic() >= next_report:
                print('durable: failure windows ' + str({n: checking(n) for n in 'ab'}), flush=True)
                next_report += 300
            time.sleep(5)
        wait_for(lambda: all(not records(n) for n in 'ab'), '30-minute controlled failure deletion', 150)
        print(f'durable: failed agreement deleted after {time.monotonic()-started:.1f}s', flush=True)
    else:
        if config['ports'] == 'range' and config.get('fixed_count', 2) == 2:
            control('a', 'durable-delete', {'peer': saved['a']['peer']['uuid']})
            wait_for(lambda: all(len(records(n)) == 1 and records(n)[0]['confirmed']
                                 and records(n)[0]['agreement_id'] != saved[n]['agreement_id'] for n in 'ab')
                     and records('a')[0]['agreement_id'] == records('b')[0]['agreement_id'],
                     'one-sided deletion did not converge to a fresh bilateral agreement')
            ns('a', 'ping', '-6', '-n', '-c', '2', '-W', '2', '-I', 'fd78:7777::1', 'fd78:7777::2')
            print('durable: unilateral deletion and fresh bilateral promotion passed', flush=True)
        path = runtime / 'a.json'
        spec = json.loads(path.read_text())
        spec['dynamic_links']['mode'] = 'off'
        path.write_text(json.dumps(spec))
        processes[0].send_signal(signal.SIGHUP)
        wait_for(lambda: not records('a') and not any(n.startswith('vdl-') for n in ns('a', 'wg', 'show', 'interfaces').split()),
                 'off did not remove durable state/resources')
        wait_for(lambda: not records('b') and not any(n.startswith('vdl-') for n in ns('b', 'wg', 'show', 'interfaces').split()),
                 'peer ABSENT did not release the other agreement', 90)
        print('durable: off and peer ABSENT invalidation passed', flush=True)
