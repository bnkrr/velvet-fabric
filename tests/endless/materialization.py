"""Remember kernel adjacency installation for each live interface incarnation."""
import ctypes
import os
import socket
import struct


class MaterializedLinks:
    """Subscribe before velvetd starts; route replacement must not erase commit evidence."""
    def __init__(self, namespace):
        self.indices = set()
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
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
                self.socket.bind((0, 1 | 0x400))  # RTMGRP_LINK | RTMGRP_IPV6_ROUTE
                self.socket.setblocking(False)
            except BaseException:
                self.close()
                raise
            finally:
                enter(original.fileno())

    def close(self):
        if self.socket is not None:
            self.socket.close()
            self.socket = None

    def read(self):
        for _ in range(4096):
            try:
                data, _, flags, sender = self.socket.recvmsg(1024 * 1024)
            except BlockingIOError:
                return sorted(self.indices)
            # ENOBUFS and other read errors deliberately propagate: after lost
            # events an old incarnation could otherwise authorize a new one.
            if flags & socket.MSG_TRUNC or sender[0] != 0:
                raise RuntimeError('invalid kernel materialization observation')
            self.consume(data)
        raise RuntimeError('kernel materialization observation backlog exceeded')

    def consume(self, data):
        while data:
            if len(data) < 16:
                raise ValueError('truncated netlink header')
            length, kind, _, _, _ = struct.unpack_from('=IHHII', data)
            if not 16 <= length <= len(data):
                raise ValueError('invalid netlink message length')
            payload, data = data[16:length], data[(length + 3) & ~3:]
            if kind == 17:  # RTM_DELLINK
                if len(payload) < 16:
                    raise ValueError('truncated interface deletion')
                self.indices.discard(struct.unpack_from('=i', payload, 4)[0])
            elif kind == 24:  # RTM_NEWROUTE; RTM_DELROUTE does not undo materialization
                if len(payload) < 12:
                    raise ValueError('truncated route message')
                family, _, _, _, table, protocol, _, route_type, _ = struct.unpack_from('=8BI', payload)
                if family != socket.AF_INET6 or protocol != 202 or route_type != 1:
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
