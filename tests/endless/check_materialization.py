#!/usr/bin/env python3
"""Root-only real kernel regression for parallel Link route replacement."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

from materialization import MaterializedLinks
from model import NotConverged, PendingLinks


def main():
    namespace = 'vfm-' + uuid.uuid4().hex[:10]

    def run(*args, **kwargs):
        return subprocess.check_output(args, text=True, timeout=10, **kwargs)

    def ip(*args):
        return run('ip', '-n', namespace, *args)

    observer = None
    run('ip', 'netns', 'add', namespace)
    try:
        original = os.readlink('/proc/thread-self/ns/net')
        observer = MaterializedLinks(namespace)
        assert os.readlink('/proc/thread-self/ns/net') == original, 'observer changed runner namespace'
        for name in ('vdl-test', 'vl-bootstrap'):
            ip('link', 'add', name, 'type', 'wireguard')
            ip('link', 'set', name, 'up')
        def replace(name, protocol):
            ip('-6', 'route', 'replace', 'fd78:e2ee::2/128', 'dev', name,
               'table', '20000', 'proto', str(protocol))

        def observations():
            links = json.loads(ip('-j', 'link', 'show', 'type', 'wireguard'))
            return {0: {'wg': {link['ifname']: {} for link in links},
                        'ifindices': {link['ifname']: link['ifindex'] for link in links},
                        'fib': json.loads(ip('-6', '-j', 'route', 'show', 'table', '20000')),
                        'babel_sockets': '', 'materialized_ifindices': observer.read()}}

        # Both commits can precede the first poll. The current FIB retains only
        # the static route, exactly the condition that broke endless round159.
        replace('vdl-test', 202)
        replace('vl-bootstrap', 202)
        tracker = PendingLinks()
        obs = observations()
        assert all(route['dev'] == 'vl-bootstrap' for route in obs[0]['fib'])
        tracker.observe(obs, 1)
        assert obs[0]['pending'] == []
        replace('vdl-test', 203)
        tracker.observe(observations(), 92)  # Previously committed, no tentative timeout.

        # Main-thread sampling pauses while a real route burst is generated.
        # The independent collector must continue consuming, including unrelated
        # Babel notifications, without losing earlier materialization evidence.
        before = observer.statistics()['routes_by_protocol'].get('new:203', 0)
        burst = ''.join('route replace fd78:e2ee::99/128 dev vl-bootstrap table 20000 proto 203\n'
                        for _ in range(20000))
        run('ip', '-n', namespace, '-6', '-batch', '-', input=burst)
        until = time.monotonic() + 5
        while observer.statistics()['routes_by_protocol'].get('new:203', 0) < before + 20000:
            stats = observer.statistics()
            assert stats['error'] is None, stats
            assert time.monotonic() < until, stats
            time.sleep(0.01)
        stats = observer.statistics()
        assert stats['collector_alive'] and stats['error'] is None, stats
        assert stats['receive_buffer_bytes'] >= 2 * stats['requested_buffer_bytes'], stats
        print('PASS: background collector consumed 20000 kernel events without sampling:', json.dumps(stats))

        # Bound the capacity requirement independently of CPU scheduling: hold
        # the consumer while the entire burst arrives, then require every event.
        # Payload length alone underestimates kernel skb accounting substantially.
        before = stats['routes_by_protocol'].get('new:203', 0)
        with observer.lock:
            run('ip', '-n', namespace, '-6', '-batch', '-', input=burst)
        observer.read()
        stats = observer.statistics()
        assert stats['routes_by_protocol'].get('new:203', 0) == before + 20000, stats
        assert stats['collector_alive'] and stats['error'] is None, stats
        print('PASS: complete 20000-event burst survives a paused consumer:', json.dumps(stats))
        # Remove the burst-only route before checking tentative FIB admission.
        ip('-6', 'route', 'del', 'fd78:e2ee::99/128', 'table', '20000')

        # Recreating the name must not inherit its old materialization. Babel
        # export alone still cannot authorize the new interface incarnation.
        ip('link', 'del', 'vdl-test')
        ip('link', 'add', 'vdl-test', 'type', 'wireguard')
        ip('link', 'set', 'vdl-test', 'up')
        obs = observations()
        tracker.observe(obs, 93)
        assert obs[0]['pending'] == ['vdl-test']
        replace('vdl-test', 203)
        try:
            tracker.observe(observations(), 94)
        except NotConverged as error:
            assert 'tentative WG entered FIB' in str(error)
        else:
            raise AssertionError('Babel route admitted a tentative interface')
        try:
            tracker.observe(observations(), 184)
        except AssertionError as error:
            assert 'exceeded 90s' in str(error)
        else:
            raise AssertionError('failed admission reset the tentative lifetime')
        print('PASS: parallel route replacement; deletion/recreation; precommit FIB and lifetime guards')
    finally:
        if observer is not None:
            observer.close()
            assert not observer.statistics()['collector_alive'], 'collector thread leaked'
        run('ip', 'netns', 'del', namespace)
    assert namespace not in run('ip', 'netns', 'list').split(), 'namespace leaked'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--linux-test', type=Path, help='compiled internal/linux test binary for real route-maintenance checks')
    parser.add_argument('--runtime-test', type=Path, help='compiled internal/runtime test binary for parallel fallback checks')
    args = parser.parse_args()
    for binary, test in ((args.linux_test, 'TestKernelRouteMaintenance'),
                         (args.runtime_test, 'TestKernelParallelFallbacks')):
        if binary is None:
            continue
        namespace = 'vfk-' + uuid.uuid4().hex[:10]
        subprocess.run(['ip', 'netns', 'add', namespace], check=True, timeout=5)
        try:
            subprocess.run(['ip', 'netns', 'exec', namespace, 'env', 'VELVET_KERNEL_ROUTE_TEST=1',
                            str(binary.resolve()), '-test.run', '^' + test + '$', '-test.v'],
                           check=True, timeout=30)
        finally:
            subprocess.run(['ip', 'netns', 'del', namespace], check=True, timeout=5)
    main()
