"""Remember kernel adjacency installation for each live interface incarnation."""
from collections import Counter
import ctypes
import os
import select
import socket
import struct
import threading
import time


class MaterializedLinks:
    """Subscribe before velvetd starts; route replacement must not erase commit evidence."""
    def __init__(self, namespace):
        self._initialize(namespace)
        self.socket = None
        # setns changes only the calling thread. Restore it before doing any
        # other runner work; the socket retains the target network namespace.
        libc = ctypes.CDLL(None, use_errno=True)
        libc.setns.argtypes = (ctypes.c_int, ctypes.c_int)
        libc.setns.restype = ctypes.c_int

        def enter(fd):
            if libc.setns(fd, 0x40000000):  # CLONE_NEWNET
                error = ctypes.get_errno()
                raise OSError(error, os.strerror(error))

        with open('/proc/thread-self/ns/net', 'rb') as original:
            with open('/run/netns/' + namespace, 'rb') as target:
                enter(target.fileno())
            try:
                self.socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.requested_buffer)
                self.receive_buffer = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                # Linux reports twice the requested size for bookkeeping. The
                # privileged fixture can override rmem_max on this socket only.
                if self.receive_buffer < 2 * self.requested_buffer:
                    self.socket.setsockopt(socket.SOL_SOCKET, getattr(socket, 'SO_RCVBUFFORCE', 33), self.requested_buffer)
                    self.receive_buffer = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                if self.receive_buffer < 2 * self.requested_buffer:
                    raise RuntimeError('materialization receive buffer smaller than requested')
                self.socket.bind((0, 1 | 0x400))  # RTMGRP_LINK | RTMGRP_IPV6_ROUTE
                self.socket.setblocking(False)
            except BaseException:
                self.close()
                raise
            finally:
                enter(original.fileno())

        # Start after restoring the caller's namespace. Only the socket retains
        # the target namespace; this thread must not keep it alive after close.
        self.thread = threading.Thread(target=self._collect, name='routes-' + namespace, daemon=True)
        try:
            self.thread.start()
        except BaseException:
            self.thread = None
            self.close()
            raise

    def _initialize(self, namespace):
        self.namespace = namespace
        self.indices = set()
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = None
        self.error = None
        self.requested_buffer = 1024 * 1024
        self.receive_buffer = 0
        self.counts = Counter()
        self.routes = Counter()  # Message kind × u8 protocol: at most 512 keys.
        self.started = self.last_drain = time.monotonic()
        self.max_drain_gap = 0
        self.bucket, self.bucket_messages, self.peak_messages = int(self.started), 0, 0

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=2)
            if self.thread.is_alive():
                raise RuntimeError(f'{self.namespace}: materialization collector did not stop')
            self.thread = None
        if self.socket is not None:
            self.socket.close()
            self.socket = None

    def _collect(self):
        try:
            while not self.stop.is_set():
                select.select([self.socket], [], [], 0.1)
                with self.lock:
                    if self.error is not None:
                        return
                    try:
                        self._drain()
                    except BaseException as error:
                        # Publish loss before releasing the evidence lock. A
                        # concurrent read must never use the incomplete history.
                        self.error = error
                        return
        except BaseException as error:
            with self.lock:
                self.error = error

    def _raise_if_failed(self):
        if self.error is not None:
            raise RuntimeError(f'{self.namespace}: kernel event collector failed: {self.error}') from self.error

    def read(self):
        # Serialize with the background consumer and drain through the current
        # kernel queue before exposing evidence to the WG/FIB snapshot.
        with self.lock:
            self._raise_if_failed()
            try:
                until = time.monotonic() + 2
                while not self._drain():
                    if time.monotonic() >= until:
                        raise RuntimeError('kernel event collector could not synchronize snapshot within 2s')
            except BaseException as error:
                self.error = error
                self._raise_if_failed()
            return sorted(self.indices)

    def statistics(self):
        # Diagnostics remain readable after failure; lost events never authorize
        # more links, even if a later recv would succeed.
        with self.lock:
            return {'requested_buffer_bytes': self.requested_buffer,
                    'receive_buffer_bytes': self.receive_buffer,
                    'seconds': round(time.monotonic() - self.started, 3),
                    'max_drain_gap_seconds': round(self.max_drain_gap, 6),
                    'peak_messages_per_second': self.peak_messages,
                    'counts': dict(self.counts), 'routes_by_protocol': dict(self.routes),
                    'materialized_interfaces': len(self.indices),
                    'collector_alive': bool(self.thread and self.thread.is_alive()),
                    'error': str(self.error) if self.error is not None else None}

    def _drain(self):
        now = time.monotonic()
        self.max_drain_gap = max(self.max_drain_gap, now - self.last_drain)
        self.last_drain = now
        for _ in range(4096):
            try:
                data, _, flags, sender = self.socket.recvmsg(1024 * 1024)
            except BlockingIOError:
                return True
            # ENOBUFS, truncation, malformed messages and overrun are fatal:
            # a current FIB dump cannot recover incarnation history.
            if flags & socket.MSG_TRUNC or sender[0] != 0:
                raise RuntimeError('invalid kernel materialization observation')
            self.counts['datagrams'] += 1
            self.counts['bytes'] += len(data)
            self.consume(data)
        # Yield the lock between batches in the background collector so close
        # and snapshots cannot starve. A full batch is not evidence of loss.
        self.counts['full_batches'] += 1
        return False

    def consume(self, data):
        while data:
            if len(data) < 16:
                raise ValueError('truncated netlink header')
            length, kind, _, _, _ = struct.unpack_from('=IHHII', data)
            if not 16 <= length <= len(data):
                raise ValueError('invalid netlink message length')
            payload, data = data[16:length], data[(length + 3) & ~3:]
            self.counts['messages'] += 1
            self.counts[{16: 'newlink', 17: 'dellink', 24: 'newroute', 25: 'delroute'}.get(kind, 'other')] += 1
            second = int(time.monotonic())
            if second != self.bucket:
                self.bucket, self.bucket_messages = second, 0
            self.bucket_messages += 1
            self.peak_messages = max(self.peak_messages, self.bucket_messages)
            if kind == 17:  # RTM_DELLINK
                if len(payload) < 16:
                    raise ValueError('truncated interface deletion')
                self.indices.discard(struct.unpack_from('=i', payload, 4)[0])
            elif kind in (24, 25):  # Route deletion does not undo materialization
                if len(payload) < 12:
                    raise ValueError('truncated route message')
                family, _, _, _, table, protocol, _, route_type, _ = struct.unpack_from('=8BI', payload)
                self.routes[f'{"new" if kind == 24 else "del"}:{protocol}'] += 1
                if kind != 24 or family != socket.AF_INET6 or protocol != 202 or route_type != 1:
                    continue
                index, attrs = None, payload[12:]
                while attrs:
                    if len(attrs) < 4:
                        raise ValueError('truncated route attribute')
                    size, attr = struct.unpack_from('=HH', attrs)
                    if not 4 <= size <= len(attrs):
                        raise ValueError('invalid route attribute length')
                    if attr in (4, 15):  # RTA_OIF, RTA_TABLE
                        if size != 8:
                            raise ValueError('invalid route interface/table')
                        value = struct.unpack_from('=I', attrs, 4)[0]
                        if attr == 4:
                            index = value
                        else:
                            table = value
                    attrs = attrs[(size + 3) & ~3:]
                if table == 20000 and index is not None:
                    self.indices.add(index)
            elif kind in (2, 4):  # NLMSG_ERROR, NLMSG_OVERRUN
                raise RuntimeError('kernel materialization observation lost')
