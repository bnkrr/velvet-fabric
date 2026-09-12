"""Kernel event ordering and loss controls for the independent commit witness."""
import errno
import socket
import struct
import unittest
from unittest.mock import Mock

from materialization import MaterializedLinks
from model import NotConverged, PendingLinks


def message(kind, payload):
    return struct.pack('=IHHII', 16 + len(payload), kind, 0, 0, 0) + payload


def route(index, protocol=202, table=20000, kind=24):
    return message(kind, struct.pack('=8BI', socket.AF_INET6, 128, 0, 0, 0, protocol, 253, 1, 0)
                   + struct.pack('=HHI', 8, 4, index) + struct.pack('=HHI', 8, 15, table))


def deleted(index):
    return message(17, struct.pack('=BBHiII', 0, 0, 0, index, 0, 0))


class MaterializationTests(unittest.TestCase):
    def observer(self, *datagrams):
        observer = MaterializedLinks.__new__(MaterializedLinks)
        observer.indices = set()
        observer.socket = Mock()
        observer.socket.recvmsg.side_effect = [*(
            (data, [], 0, (0, 0)) for data in datagrams), BlockingIOError()]
        return observer

    def test_parallel_route_replacement_before_first_snapshot(self):
        observer = self.observer(route(10) + route(20))
        obs = {0: {'wg': {'vdl-a': {}}, 'ifindices': {'vdl-a': 10},
                   'fib': [{'dev': 'vl-bootstrap', 'protocol': 202}, {'dev': 'vdl-a', 'protocol': 203}],
                   'babel_sockets': '[fe80::1%vdl-a]:6696', 'materialized_ifindices': observer.read()}}
        PendingLinks().observe(obs, 1)
        self.assertEqual(obs[0]['pending'], [])

    def test_babel_route_and_up_claim_cannot_authorize_pending_link(self):
        observer = self.observer(route(20), route(10, protocol=203), route(10, table=254))
        obs = {0: {'wg': {'vdl-a': {}}, 'ifindices': {'vdl-a': 10},
                   'fib': [{'dev': 'vl-bootstrap', 'protocol': 202}, {'dev': 'vdl-a', 'protocol': 203}],
                   'babel_sockets': '', 'status': {'runtime': {'dynamic_links': 1}},
                   'materialized_ifindices': observer.read()}}
        with self.assertRaisesRegex(NotConverged, 'tentative WG entered FIB'):
            PendingLinks().observe(obs, 1)
        obs[0].update(fib=[], babel_sockets='[fe80::1%vdl-a]:6696')
        with self.assertRaisesRegex(NotConverged, 'Babel attached to tentative'):
            PendingLinks().observe(obs, 1)

    def test_only_interface_deletion_forgets_materialization(self):
        observer = self.observer(route(10), route(10, kind=25))
        self.assertEqual(observer.read(), [10])
        observer.consume(deleted(10) + route(10, protocol=203))
        self.assertEqual(observer.indices, set())  # Reused ifindex needs new proof.
        observer.consume(route(10))
        self.assertEqual(observer.indices, {10})

    def test_lost_or_untrusted_events_fail_closed(self):
        for response in (OSError(errno.ENOBUFS, 'lost messages'),
                         (route(10), [], socket.MSG_TRUNC, (0, 0)),
                         (route(10), [], 0, (99, 0)),
                         (message(4, b''), [], 0, (0, 0))):
            with self.subTest(response=response):
                observer = self.observer()
                observer.socket.recvmsg.side_effect = [response]
                with self.assertRaises((OSError, RuntimeError)):
                    observer.read()

    def test_malformed_events_fail_closed(self):
        for data in (b'x', message(24, b'x'), message(17, b'x'),
                     route(10)[:-1], route(10) + b'x'):
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    self.observer(data).read()


if __name__ == '__main__':
    unittest.main()
