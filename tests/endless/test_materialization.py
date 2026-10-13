"""Kernel event ordering and loss controls for the independent commit witness."""
import errno
import socket
import struct
import unittest
from unittest.mock import Mock, patch

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
        observer._initialize('test-observer')
        observer.socket = Mock()
        observer.socket.recvmsg.side_effect = [*(
            (data, [], 0, (0, 0)) for data in datagrams), BlockingIOError()]
        def receive_into(buffers):
            data, ancillary, flags, sender = observer.socket.recvmsg()
            buffers[0][:len(data)] = data
            return len(data), ancillary, flags, sender
        observer.socket.recvmsg_into.side_effect = receive_into
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
                # Loss is sticky: an empty queue on a later read must never
                # make incomplete interface history usable again.
                observer.socket.recvmsg.side_effect = BlockingIOError()
                with self.assertRaisesRegex(RuntimeError, 'test-observer'):
                    observer.read()
                self.assertIsNotNone(observer.statistics()['error'])

    def test_malformed_events_fail_closed(self):
        for data in (b'x', message(24, b'x'), message(17, b'x'),
                     route(10)[:-1], route(10) + b'x'):
            with self.subTest(data=data):
                with self.assertRaises(RuntimeError) as raised:
                    self.observer(data).read()
                self.assertIsInstance(raised.exception.__cause__, ValueError)

    def test_event_counts_keep_protocols_separate_without_authorizing_routes(self):
        observer = self.observer(route(10), route(11, protocol=201), route(12, protocol=203),
                                 route(10, kind=25), deleted(10))
        self.assertEqual(observer.read(), [])
        stats = observer.statistics()
        self.assertEqual(stats['counts']['messages'], 5)
        self.assertEqual(stats['counts']['newroute'], 3)
        self.assertEqual(stats['routes_by_protocol'], {'new:202': 1, 'new:201': 1, 'new:203': 1, 'del:202': 1})

    def test_background_failure_is_reported_to_the_next_snapshot(self):
        observer = self.observer()
        observer.socket.recvmsg.side_effect = OSError(errno.ENOBUFS, 'lost messages')
        with patch('materialization.select.select', return_value=([observer.socket], [], [])):
            observer._collect()
        self.assertEqual(observer.error.errno, errno.ENOBUFS)
        with self.assertRaisesRegex(RuntimeError, 'kernel event collector failed') as raised:
            observer.read()
        self.assertIs(raised.exception.__cause__, observer.error)

    def test_full_batch_is_not_mistaken_for_lost_events(self):
        observer = self.observer(*([route(10)] * 5000), deleted(10), route(10, protocol=203))
        self.assertEqual(observer.read(), [])
        self.assertEqual(observer.statistics()['counts']['full_batches'], 1)
        self.assertIsNone(observer.statistics()['error'])


if __name__ == '__main__':
    unittest.main()
