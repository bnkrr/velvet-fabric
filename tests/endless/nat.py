#!/usr/bin/env python3
"""Protocol-agnostic UDP NAT fixture, real packets on isolated LAN/WAN netns.

Mapping and filtering are independent. AF_PACKET sees LAN datagrams before the
kernel's deliberate UDP drop; external UDP sockets own translated endpoints.
Replies are injected as Ethernet/IP/UDP frames with the original remote source.
No Velvet/VFP/WG decoding or connectivity decisions occur here.
"""
import argparse
import ipaddress
import json
import random
import selectors
import signal
import socket
import struct
import time
from pathlib import Path

MAPPINGS = ('eim', 'adm', 'apdm')
FILTERS = ('eif', 'adf', 'apdf')
ALLOCATIONS = ('preserve', 'offset', 'sequential', 'random')


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def decode(frame):
    if len(frame) < 42:
        return None
    kind = struct.unpack('!H', frame[12:14])[0]
    data = frame[14:]
    if kind == 0x800:
        size = (data[0] & 15) * 4
        if size < 20 or len(data) < size + 8 or data[9] != 17 or struct.unpack('!H', data[6:8])[0] & 0x3fff:
            return None
        src, dst = map(lambda x: str(ipaddress.ip_address(x)), (data[12:16], data[16:20]))
    elif kind == 0x86dd:
        if len(data) < 48 or data[6] != 17:
            return None  # This fixture does not implement extension headers/fragments.
        size = 40
        src, dst = map(lambda x: str(ipaddress.ip_address(x)), (data[8:24], data[24:40]))
    else:
        return None
    sport, dport, length, _sum = struct.unpack('!HHHH', data[size:size + 8])
    if length < 8 or len(data) < size + length:
        return None
    return (src, sport), (dst, dport), data[size + 8:size + length], frame[6:12], frame[:6]


def encode(source, destination, payload, dst_mac, src_mac):
    src, dst = ipaddress.ip_address(source[0]), ipaddress.ip_address(destination[0])
    length = 8 + len(payload)
    udp = struct.pack('!HHHH', source[1], destination[1], length, 0) + payload
    pseudo = src.packed + dst.packed
    pseudo += struct.pack('!BBH', 0, 17, length) if src.version == 4 else struct.pack('!I3xB', length, 17)
    udp = udp[:6] + struct.pack('!H', checksum(pseudo + udp) or 65535) + udp[8:]
    if src.version == 4:
        header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + length, 0, 0, 64, 17, 0, src.packed, dst.packed)
        header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
        kind = 0x800
    else:
        header = struct.pack('!IHBB16s16s', 6 << 28, length, 17, 64, src.packed, dst.packed)
        kind = 0x86dd
    return dst_mac + src_mac + struct.pack('!H', kind) + header + udp


def mapping_key(local, remote, mapping):
    if mapping == 'eim':
        return local
    return (local, remote[0]) if mapping == 'adm' else (local, remote)


def admits(remote, destinations, filtering):
    return filtering == 'eif' or (remote in destinations if filtering == 'apdf'
                                 else any(peer[0] == remote[0] for peer in destinations))


class Translator:
    def __init__(self, wan, mapping, filtering, allocation, seed, interface='lan'):
        self.wan, self.mapping, self.filtering, self.allocation = wan, mapping, filtering, allocation
        self.rng = random.Random(seed)
        self.sequence = 40000
        self.entries = {}
        self.selector = selectors.DefaultSelector()
        self.lan = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        self.lan.bind((interface, 0))
        self.lan.setblocking(False)
        self.selector.register(self.lan, selectors.EVENT_READ, None)
        self.stats = {'out': 0, 'in': 0, 'filtered': 0, 'created': 0, 'expired': 0}

    def allocate(self, local):
        if self.allocation == 'preserve':
            desired = local[1]
        elif self.allocation == 'offset':
            desired = 1024 + ((local[1] - 1024 + 10000) % (65536 - 1024))
        elif self.allocation == 'sequential':
            desired = self.sequence
            self.sequence = 40000 + (self.sequence - 40000 + 1) % 20000
        else:
            desired = self.rng.randrange(40000, 60000)
        sock = socket.socket(socket.AF_INET6 if ':' in self.wan else socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Collision fallback is explicit; the reported mapping remains the
            # real socket endpoint. No fabricated evidence is injected into VFP.
            try:
                sock.bind((self.wan, desired))
            except OSError:
                sock.bind((self.wan, 0))
            sock.setblocking(False)
            return sock
        except BaseException:
            sock.close()
            raise

    def outbound(self, frame):
        packet = decode(frame)
        if packet is None:
            return
        local, remote, payload, client_mac, router_mac = packet
        if ipaddress.ip_address(remote[0]).is_multicast or ipaddress.ip_address(remote[0]).is_link_local:
            return
        key = mapping_key(local, remote, self.mapping)
        entry = self.entries.get(key)
        if entry is None:
            if len(self.entries) >= 4096:
                raise RuntimeError('NAT fixture mapping capacity exceeded')
            entry = {'socket': self.allocate(local), 'local': local, 'destinations': set(),
                     'client_mac': client_mac, 'router_mac': router_mac}
            self.entries[key] = entry
            self.selector.register(entry['socket'], selectors.EVENT_READ, entry)
            self.stats['created'] += 1
        if len(entry['destinations']) >= 4096 and remote not in entry['destinations']:
            raise RuntimeError('NAT fixture destination capacity exceeded')
        entry['destinations'].add(remote)
        entry['last'] = time.monotonic()
        entry['socket'].sendto(payload, remote)
        self.stats['out'] += 1

    def receive(self, entry):
        try:
            payload, source = entry['socket'].recvfrom(65535)
        except (ConnectionRefusedError, BlockingIOError):
            return
        source = source[:2]
        if not admits(source, entry['destinations'], self.filtering):
            self.stats['filtered'] += 1
            return
        entry['last'] = time.monotonic()
        self.lan.send(encode(source, entry['local'], payload, entry['client_mac'], entry['router_mac']))
        self.stats['in'] += 1

    def step(self):
        for key, _ in self.selector.select(0.25):
            if key.data is None:
                frame, origin = self.lan.recvfrom(65535)
                if origin[2] != socket.PACKET_OUTGOING:
                    self.outbound(frame)
            else:
                self.receive(key.data)
        now = time.monotonic()
        for key, entry in list(self.entries.items()):
            if now - entry['last'] > 180:
                self.selector.unregister(entry['socket'])
                entry['socket'].close()
                del self.entries[key]
                self.stats['expired'] += 1

    def close(self):
        for entry in self.entries.values():
            entry['socket'].close()
        self.lan.close()
        self.selector.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wan', required=True)
    parser.add_argument('--mapping', choices=MAPPINGS, required=True)
    parser.add_argument('--filter', choices=FILTERS, required=True)
    parser.add_argument('--allocation', choices=ALLOCATIONS, required=True)
    parser.add_argument('--seed', type=int, required=True)
    parser.add_argument('--status', type=Path, required=True)
    args = parser.parse_args()
    translator = Translator(args.wan, args.mapping, args.filter, args.allocation, args.seed)
    stopped = False
    def stop(_signum, _frame):
        nonlocal stopped
        stopped = True
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, stop)
    last = 0
    try:
        while not stopped:
            translator.step()
            if time.monotonic() - last >= 1:
                temporary = args.status.with_suffix('.tmp')
                temporary.write_text(json.dumps({'mapping': args.mapping, 'filter': args.filter,
                    'allocation': args.allocation, 'entries': len(translator.entries), **translator.stats}))
                temporary.replace(args.status)
                last = time.monotonic()
    finally:
        translator.close()


if __name__ == '__main__':
    main()
