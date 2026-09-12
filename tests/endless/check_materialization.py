#!/usr/bin/env python3
"""Root-only real kernel regression for parallel Link route replacement."""
import json
import os
import subprocess
import uuid

from materialization import MaterializedLinks
from model import NotConverged, PendingLinks


def main():
    namespace = 'vfm-' + uuid.uuid4().hex[:10]

    def run(*args):
        return subprocess.check_output(args, text=True, timeout=5)

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
        run('ip', 'netns', 'del', namespace)
    assert namespace not in run('ip', 'netns', 'list').split(), 'namespace leaked'


if __name__ == '__main__':
    main()
