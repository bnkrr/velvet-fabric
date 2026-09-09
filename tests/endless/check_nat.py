#!/usr/bin/env python3
"""Root-only black-box validation of all 36 NAT profiles, IPv4 and IPv6."""
import ctypes
import itertools
import json
import os
from pathlib import Path
import socket
import subprocess as sp
import tempfile
import time
import uuid


def run(*command):
    result = sp.run(command, capture_output=True, text=True, timeout=5)
    if result.returncode:
        raise RuntimeError(f'{command}: {result.stderr}')
    return result.stdout


def socket_in(namespace, address, port):
    # Sockets retain their namespace after restoring this single-threaded host
    # process. ctypes keeps compatibility with Python versions before os.setns.
    libc = ctypes.CDLL(None, use_errno=True)
    with open('/proc/self/ns/net', 'rb') as previous, open('/run/netns/' + namespace, 'rb') as target:
        if libc.setns(target.fileno(), 0):
            raise OSError(ctypes.get_errno(), 'enter netns')
        try:
            sock = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((address, port))
            sock.settimeout(0.25)
        finally:
            if libc.setns(previous.fileno(), 0):
                raise OSError(ctypes.get_errno(), 'restore netns')
    return sock


def family_check(family, directory):
    token = uuid.uuid4().hex[:8]
    names = {n: f'vfn-{token}-{n}' for n in ('c', 'r', 'o')}
    links, created, sockets = [], [], []
    lan = ['10.88.1.1', '10.88.1.2'] if family == 4 else ['fd42:ee::1', 'fd42:ee::2']
    wan = ['192.0.2.254', '192.0.2.1', '192.0.2.2'] if family == 4 else ['2001:db8:ee::ff', '2001:db8:ee::1', '2001:db8:ee::2']
    def ip(node, *args): return run('ip', '-n', names[node], *args)
    try:
        for name in names.values():
            run('ip', 'netns', 'add', name)
            created.append(name)
            run('ip', '-n', name, 'link', 'set', 'lo', 'up')
            run('ip', 'netns', 'exec', name, 'sysctl', '-qw', 'net.ipv6.conf.default.accept_dad=0', 'net.ipv6.conf.default.autoconf=0')
        for index, (a, b, interface, aa, ba) in enumerate((('c', 'r', 'lan', lan[1], lan[0]), ('r', 'o', 'wan', wan[0], wan[1]))):
            left, right = f'vfl{token}{index}', f'vfr{token}{index}'
            run('ip', 'link', 'add', left, 'type', 'veth', 'peer', 'name', right)
            links.extend((left, right))
            for node, dev, address in ((a, left, aa), (b, right, ba)):
                run('ip', 'link', 'set', dev, 'netns', names[node], 'name', interface)
                ip(node, 'addr', 'add', address + ('/24' if family == 4 else '/64'), 'dev', interface)
                ip(node, 'link', 'set', interface, 'up')
        ip('o', 'addr', 'add', wan[2] + ('/24' if family == 4 else '/64'), 'dev', 'wan')
        ip('c', f'-{family}', 'route', 'add', 'default', 'via', lan[0])
        rules = 'table inet fixture {\n chain pre {\n type filter hook prerouting priority -300; policy accept;\n iifname "lan" meta l4proto udp drop\n }\n}\n'
        result = sp.run(['ip', 'netns', 'exec', names['r'], 'nft', '-f', '-'], input=rules, text=True, capture_output=True)
        if result.returncode: raise RuntimeError(result.stderr)
        client = socket_in(names['c'], lan[1], 31011)
        client2 = socket_in(names['c'], lan[1], 31012)
        observers = [socket_in(names['o'], addr, port) for addr, port in ((wan[1], 43001), (wan[1], 43002), (wan[2], 43001))]
        sockets.extend((client, client2, *observers))
        results = []
        for mapping, filtering, allocation in itertools.product(('eim', 'adm', 'apdm'), ('eif', 'adf', 'apdf'), ('preserve', 'offset', 'sequential', 'random')):
            status = directory / 'status.json'
            status.unlink(missing_ok=True)
            process = sp.Popen(['ip', 'netns', 'exec', names['r'], 'python3', str(Path(__file__).with_name('nat.py')),
                '--wan', wan[0], '--mapping', mapping, '--filter', filtering, '--allocation', allocation,
                '--seed', '7', '--status', str(status)], stdout=sp.DEVNULL, stderr=sp.PIPE)
            try:
                until = time.monotonic() + 5
                while not status.exists():
                    if process.poll() is not None or time.monotonic() > until:
                        raise RuntimeError('NAT process did not become ready')
                    time.sleep(0.02)
                client.sendto(b'first', observers[0].getsockname()[:2])
                payload, observed = observers[0].recvfrom(100)
                assert payload == b'first' and observed[0] == wan[0]
                observers[0].sendto(b'reply', observed)
                assert client.recvfrom(100)[0] == b'reply'
                for index in (1, 2):
                    observers[index].sendto(b'filter', observed)
                    allowed = filtering == 'eif' or (filtering == 'adf' and index == 1)
                    try:
                        data, source = client.recvfrom(100)
                    except socket.timeout:
                        assert not allowed, (family, mapping, filtering, allocation, 'valid reply filtered')
                    else:
                        assert allowed and data == b'filter' and source[:2] == observers[index].getsockname()[:2]
                ports = [observed[1]]
                for observer in observers[1:]:
                    client.sendto(b'next', observer.getsockname()[:2])
                    payload, source = observer.recvfrom(100)
                    assert payload == b'next'
                    ports.append(source[1])
                assert len(set(ports)) == {'eim': 1, 'adm': 2, 'apdm': 3}[mapping], (mapping, ports)
                if mapping == 'adm': assert ports[0] == ports[1]
                if allocation == 'preserve': assert ports[0] == 31011
                elif allocation == 'offset': assert ports[0] == 41011
                elif allocation == 'sequential':
                    assert sorted(set(ports)) == list(range(40000, 40000 + len(set(ports))))
                else: assert all(40000 <= port < 60000 for port in ports)
                client2.sendto(b'other-local', observers[0].getsockname()[:2])
                payload, source = observers[0].recvfrom(100)
                assert payload == b'other-local' and source[1] not in ports
                results.append({'family': family, 'mapping': mapping, 'filter': filtering, 'allocation': allocation, 'ports': ports})
            finally:
                process.terminate()
                process.wait(timeout=3)
                error = process.stderr.read().decode()
                process.stderr.close()
                if process.returncode != 0: raise RuntimeError(error)
        return results
    finally:
        for sock in sockets: sock.close()
        for name in created:
            sp.run(['ip', 'netns', 'del', name], capture_output=True)
        for dev in links:
            sp.run(['ip', 'link', 'del', dev], capture_output=True)


def main():
    if os.geteuid() != 0: raise SystemExit('root required')
    with tempfile.TemporaryDirectory(prefix='velvet-nat-check-') as directory:
        results = family_check(4, Path(directory)) + family_check(6, Path(directory))
        print(json.dumps(results))
        print(f'PASS: {len(results)} real UDP mapping/filter/allocation profiles, including IPv4 and IPv6 reply checksums')


if __name__ == '__main__': main()
