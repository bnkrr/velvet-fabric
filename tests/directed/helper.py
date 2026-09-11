#!/usr/bin/env python3
"""Finite unrelated UDP traffic or port ownership for fault injection."""
import argparse
import errno
import json
from pathlib import Path
import signal
import socket
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('kind', choices=('ports', 'traffic'))
    parser.add_argument('address')
    parser.add_argument('status', type=Path)
    parser.add_argument('--duration', type=float, default=60)
    args = parser.parse_args()
    family = socket.AF_INET6 if ':' in args.address else socket.AF_INET
    sockets, sent, stopped = [], 0, False
    occupied = 0
    def stop(*_):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop)
    try:
        if args.kind == 'ports':
            for port in range(31000, 32001):
                sock = socket.socket(family, socket.SOCK_DGRAM)
                try:
                    sock.bind((args.address, port))
                except OSError as error:
                    sock.close()
                    if error.errno != errno.EADDRINUSE:
                        raise
                    occupied += 1  # Existing static WG listeners own these.
                else:
                    sockets.append(sock)
            args.status.write_text(json.dumps({'bound': len(sockets), 'occupied': occupied}))
        until = time.monotonic() + args.duration
        while not stopped and time.monotonic() < until:
            if args.kind == 'traffic':
                sock = socket.socket(family, socket.SOCK_DGRAM)
                # New local socket and remote port consume an actual mapping,
                # independent of the application and its probe port choices.
                sock.bind(('::' if family == socket.AF_INET6 else '0.0.0.0', 0))
                sock.sendto(b'unrelated-test-traffic', (args.address, 60000 + sent % 128))
                sockets.append(sock)
                sent += 1
                if len(sockets) > 128:
                    sockets.pop(0).close()
                args.status.write_text(json.dumps({'sent': sent}))
            time.sleep(0.1)
    finally:
        for sock in sockets:
            sock.close()


if __name__ == '__main__':
    main()
