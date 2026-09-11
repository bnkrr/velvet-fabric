"""Independent socket census and observer-pool release regression."""
import ipaddress
import json
import os
from pathlib import Path

from model import address
from mutations import hold
from scenarios import table, delete_table, data


def classify_socket(protocol, local, state, node_address):
    raw_address, raw_port = local.split(':')
    port = int(raw_port, 16)
    raw = bytes.fromhex(raw_address)
    width = 4
    # /proc/net exposes native-endian 32-bit words on the supported Linux host.
    import sys
    if sys.byteorder == 'little':
        raw = b''.join(raw[i:i + width][::-1] for i in range(0, len(raw), width))
    host = ipaddress.ip_address(raw)
    if protocol.startswith('udp') and host.is_unspecified and 31000 <= port <= 32000:
        return 'probe_listeners'
    if protocol.startswith('tcp') and host == ipaddress.ip_address(node_address) and port == 58420 and state != '0A':
        return 'routed_inbound'
    return 'other'


def census(pid, node_address):
    proc = Path(f'/proc/{pid}')
    owned = set()
    count = 0
    for fd in (proc / 'fd').iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:
            continue
        count += 1
        if target.startswith('socket:['):
            owned.add(target[8:-1])
    result = {'fds': count, 'probe_listeners': [], 'routed_inbound': []}
    for protocol in ('tcp', 'tcp6', 'udp', 'udp6'):
        for line in (proc / 'net' / protocol).read_text().splitlines()[1:]:
            fields = line.split()
            # Kernel WG and the separately supervised Babel sockets are not
            # velvetd FDs. Count only inodes held by this exact process.
            if fields[9] not in owned:
                continue
            category = classify_socket(protocol, fields[1], fields[3], node_address)
            if category != 'other':
                result[category].append({'protocol': protocol, 'local': fields[1],
                                        'remote': fields[2], 'state': fields[3]})
    return result


def assert_quiescent(snapshot, nodes):
    assert not snapshot['probe_listeners'], 'observer UDP listener survived lease drain'
    assert not snapshot['routed_inbound'], 'routed observer TCP survived lease drain'
    assert snapshot['fds'] <= 64 + 16 * nodes, 'FDs did not return to the original non-observer budget'


def exercise(r):
    r.verify()
    assert r.resource_peaks, 'scenario never exercised concurrent observer FD pressure'
    r.save('observer-peak-census.json', r.resource_peaks)
    for node in (0, 1):
        table(r, node, 'resource_gate',
              f'ip6 daddr {address(node)} tcp dport 58420 tcp flags & (syn | ack) == syn')
    try:
        # No new accepted routed session; existing observer leases expire in
        # 30s. WG health, routing, established TCP and business traffic continue.
        hold(r, 45)
        snapshots = {}
        for node in (0, 1):
            snapshot = census(r.nodes[node]['proc'].pid, address(node))
            assert_quiescent(snapshot, r.topology.size)
            snapshots[node] = snapshot
        r.save('observer-drained-census.json', snapshots)
        r.record('observer-pool-drained', fds={n: s['fds'] for n, s in snapshots.items()})
        r.verify()
        data(r, label='observer-pool-drained')
    finally:
        for node in (0, 1):
            delete_table(r, node, 'resource_gate')
