"""Connection capacity, handshake deadlines and teardown source regressions."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "owner-open"))
import owner_open_broker_connections as connections
from owner_open_broker_common import BrokerError, MAX_LINE_BYTES, read_line
from owner_open_broker_connections import ClientWorkers, SocketLineReader


class ClientWorkersTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pool = ClientWorkers(2)
        self.release = threading.Event()
        self.peers: list[socket.socket] = []
        self.addCleanup(self.cleanup)

    def cleanup(self) -> None:
        self.release.set()
        self.pool.close()
        self.pool.join(2)
        for peer in self.peers:
            peer.close()

    def pair(self) -> tuple[socket.socket, socket.socket]:
        connection, peer = socket.socketpair()
        self.peers.extend((connection, peer))
        return connection, peer

    def test_limits_are_strict_and_finite(self) -> None:
        for value in (True, False, 0, -1, 1.5, float("inf"), 1025, "2"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ClientWorkers(value)

    def test_capacity_is_reserved_before_thread_start(self) -> None:
        for _ in range(2):
            connection, _ = self.pair()
            self.assertTrue(self.pool.start_reader(connection, lambda _: self.release.wait(2)))
        extra, peer = self.pair()
        with mock.patch.object(connections.threading, "Thread") as constructor:
            self.assertFalse(self.pool.start_reader(extra, lambda _: None))
            constructor.assert_not_called()
        self.assertEqual(peer.recv(1), b"")
        self.assertEqual(self.pool.snapshot()["connections"], 2)

    def test_concurrent_admission_cannot_exceed_limit(self) -> None:
        sockets = [self.pair()[0] for _ in range(32)]
        with ThreadPoolExecutor(max_workers=8) as executor:
            outcomes = list(executor.map(lambda s: self.pool.start_reader(s, lambda _: self.release.wait(2)), sockets))
        self.assertEqual(sum(outcomes), 2)
        self.assertEqual(self.pool.snapshot()["readers_alive"], 2)

    def test_reader_start_failure_closes_socket_and_releases_slot(self) -> None:
        connection, peer = self.pair()
        with mock.patch.object(threading.Thread, "start", side_effect=RuntimeError("start failed")):
            with self.assertRaisesRegex(RuntimeError, "start failed"):
                self.pool.start_reader(connection, lambda _: None)
        self.assertEqual(self.pool.snapshot()["connections"], 0)
        self.assertEqual(peer.recv(1), b"")

    def test_interrupted_reader_start_retains_unconfirmed_capacity(self) -> None:
        connection, peer = self.pair()
        with mock.patch.object(threading.Thread, "start", side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                self.pool.start_reader(connection, lambda _: None)
        self.assertEqual(self.pool.snapshot()["connections"], 1)
        self.assertFalse(self.pool.join(0))
        self.assertEqual(peer.recv(1), b"")

    def test_interrupted_writer_start_retains_unconfirmed_capacity(self) -> None:
        connection, _ = self.pair()
        interrupted = threading.Event()
        def reader(sock: socket.socket) -> None:
            with mock.patch.object(threading.Thread, "start", side_effect=KeyboardInterrupt()):
                try:
                    self.pool.start_writer(sock, lambda: None, name="test-writer")
                except KeyboardInterrupt:
                    interrupted.set()
        self.pool.start_reader(connection, reader)
        self.assertTrue(interrupted.wait(2))
        self.assertFalse(self.pool.join(.01))
        self.assertEqual(self.pool.snapshot()["connections"], 1)

    def test_reader_constructor_failure_closes_socket(self) -> None:
        connection, peer = self.pair()
        with mock.patch.object(connections.threading, "Thread", side_effect=RuntimeError("construct failed")):
            with self.assertRaisesRegex(RuntimeError, "construct failed"):
                self.pool.start_reader(connection, lambda _: None)
        self.assertEqual(self.pool.snapshot()["connections"], 0)
        self.assertEqual(peer.recv(1), b"")

    def test_reader_exception_does_not_leak_a_slot(self) -> None:
        connection, peer = self.pair()
        def fail(_: socket.socket) -> None:
            raise RuntimeError("reader failed")
        with mock.patch.object(threading, "excepthook"):
            self.pool.start_reader(connection, fail)
            self.assertTrue(self.pool.join(2))
        self.assertEqual(peer.recv(1), b"")

    def test_connection_churn_retains_no_dead_worker_history(self) -> None:
        for _ in range(80):
            connection, _ = self.pair()
            self.assertTrue(self.pool.start_reader(connection, lambda _: None))
            self.assertTrue(self.pool.join(2))
            self.assertEqual(self.pool.snapshot()["connections"], 0)

    def test_slot_is_retained_until_writer_really_terminates(self) -> None:
        self.pool = ClientWorkers(1)
        connection, _ = self.pair()
        writer_started = threading.Event()
        def reader(sock: socket.socket) -> None:
            self.pool.start_writer(sock, lambda: (writer_started.set(), self.release.wait(2)), name="test-writer")
        self.pool.start_reader(connection, reader)
        self.assertTrue(writer_started.wait(2))
        self.assertFalse(self.pool.join(.01))
        self.assertEqual(self.pool.snapshot()["writers_alive"], 1)
        rejected, _ = self.pair()
        self.assertFalse(self.pool.start_reader(rejected, lambda _: None))
        self.release.set()
        self.assertTrue(self.pool.join(2))
        accepted, _ = self.pair()
        self.assertTrue(self.pool.start_reader(accepted, lambda _: None))

    def test_writer_start_failure_does_not_leak_connection(self) -> None:
        connection, _ = self.pair()
        failed = threading.Event()
        def reader(sock: socket.socket) -> None:
            with mock.patch.object(threading.Thread, "start", side_effect=RuntimeError("writer start")):
                try:
                    self.pool.start_writer(sock, lambda: None, name="test-writer")
                except RuntimeError:
                    failed.set()
        self.pool.start_reader(connection, reader)
        self.assertTrue(self.pool.join(2))
        self.assertTrue(failed.is_set())

    def test_duplicate_writer_is_rejected_even_if_first_has_exited(self) -> None:
        connection, _ = self.pair()
        rejected = threading.Event()
        def reader(sock: socket.socket) -> None:
            writer = self.pool.start_writer(sock, lambda: None, name="test-writer")
            writer.join(2)
            try:
                self.pool.start_writer(sock, lambda: None, name="duplicate")
            except BrokerError:
                rejected.set()
        self.pool.start_reader(connection, reader)
        self.assertTrue(self.pool.join(2))
        self.assertTrue(rejected.is_set())

    def test_unregistered_socket_cannot_start_writer(self) -> None:
        connection, _ = self.pair()
        with self.assertRaisesRegex(BrokerError, "not admitted"):
            self.pool.start_writer(connection, lambda: None, name="unknown")

    def test_close_unblocks_silent_readers_and_rejects_new_connections(self) -> None:
        connection, _ = self.pair()
        ready = threading.Event()
        def reader(sock: socket.socket) -> None:
            ready.set()
            try:
                sock.recv(1)
            except OSError:
                pass
        self.pool.start_reader(connection, reader)
        self.assertTrue(ready.wait(2))
        self.pool.close()
        self.assertTrue(self.pool.join(2))
        another, peer = self.pair()
        self.assertFalse(self.pool.start_reader(another, lambda _: None))
        self.assertEqual(peer.recv(1), b"")

    def test_close_fences_a_late_writer_start(self) -> None:
        connection, _ = self.pair()
        ready, rejected = threading.Event(), threading.Event()
        def reader(sock: socket.socket) -> None:
            ready.set()
            self.release.wait(2)
            try:
                self.pool.start_writer(sock, lambda: None, name="late")
            except BrokerError:
                rejected.set()
        self.pool.start_reader(connection, reader)
        self.assertTrue(ready.wait(2))
        self.pool.close()
        self.release.set()
        self.assertTrue(self.pool.join(2))
        self.assertTrue(rejected.is_set())

    def test_join_returns_false_with_one_bounded_total_wait(self) -> None:
        for _ in range(2):
            connection, _ = self.pair()
            self.pool.start_reader(connection, lambda _: self.release.wait(2))
        started = time.monotonic()
        self.assertFalse(self.pool.join(.02))
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(self.pool.snapshot()["connections"], 2)

    def test_join_rejects_unbounded_or_invalid_timeouts(self) -> None:
        for value in (True, -1, float("nan"), float("inf"), "1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.pool.join(value)

    def test_deadline_is_bound_before_the_reader_runs(self) -> None:
        connection, _ = self.pair()
        self.pool.start_reader(connection, lambda _: self.release.wait(2))
        deadline = self.pool.hello_deadline(connection)
        time.sleep(.01)
        self.assertEqual(self.pool.hello_deadline(connection), deadline)
        self.pool.close()
        with self.assertRaisesRegex(BrokerError, "shutting down"):
            self.pool.hello_deadline(connection)


class SocketLineReaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection, self.peer = socket.socketpair()
        self.reader = SocketLineReader(self.connection, deadline=time.monotonic() + 2)
        self.addCleanup(self.peer.close)
        self.addCleanup(self.connection.close)
        self.addCleanup(self.reader.close)

    def test_pipelined_hello_and_request_are_preserved(self) -> None:
        self.peer.sendall(b'hello\nrequest\n')
        self.assertEqual(read_line(self.reader, label="hello"), b"hello")
        self.reader.authenticated()
        self.assertEqual(read_line(self.reader, label="request"), b"request")
        self.assertTrue(self.connection.getblocking())
        self.assertIsNone(self.connection.gettimeout())

    def test_silent_peer_hits_absolute_deadline(self) -> None:
        self.reader._deadline = time.monotonic() + .02
        with self.assertRaisesRegex(TimeoutError, "hello deadline"):
            self.reader.readline(32)

    def test_trickled_bytes_do_not_renew_deadline(self) -> None:
        self.reader._deadline = 3.0
        receiver = mock.Mock()
        receiver.recv.return_value = b"x"
        with mock.patch.object(self.reader, "_connection", receiver), mock.patch.object(self.reader._selector, "select", return_value=[True]), mock.patch.object(connections.time, "monotonic", side_effect=[0.0, 1.0, 2.0, 3.0]):
            with self.assertRaisesRegex(TimeoutError, "hello deadline"):
                self.reader.readline(32)
        self.assertEqual(receiver.recv.call_count, 3)

    def test_spurious_readiness_and_eintr_do_not_reset_deadline(self) -> None:
        self.reader._deadline = 3.0
        receiver = mock.Mock()
        receiver.recv.side_effect = [InterruptedError(), BlockingIOError(), b"x"]
        with mock.patch.object(self.reader, "_connection", receiver), mock.patch.object(self.reader._selector, "select", return_value=[True]), mock.patch.object(connections.time, "monotonic", side_effect=[0.0, 1.0, 2.0, 3.0]):
            with self.assertRaises(TimeoutError):
                self.reader.readline(32)

    def test_expired_deadline_rejects_already_buffered_hello(self) -> None:
        self.reader._buffer.extend(b"hello\n")
        self.reader._deadline = time.monotonic() - 1
        with self.assertRaises(TimeoutError):
            self.reader.readline(32)

    def test_authentication_disables_hello_deadline_not_line_bound(self) -> None:
        self.reader._deadline = time.monotonic() - 1
        self.reader.authenticated()
        self.peer.sendall(b"request\n")
        self.assertEqual(read_line(self.reader, label="request"), b"request")
        with self.assertRaises(ValueError):
            self.reader.readline(MAX_LINE_BYTES + 3)

    def test_empty_and_unterminated_lines_fail_closed(self) -> None:
        self.peer.sendall(b"\npartial")
        self.peer.shutdown(socket.SHUT_WR)
        with self.assertRaisesRegex(BrokerError, "empty"):
            read_line(self.reader, label="hello")
        with self.assertRaisesRegex(BrokerError, "newline terminated"):
            read_line(self.reader, label="hello")
        self.assertIsNone(read_line(self.reader, label="hello"))

    def test_oversize_line_never_expands_past_requested_bound(self) -> None:
        self.peer.sendall(b"x" * 64)
        with self.assertRaisesRegex(BrokerError, "oversized"):
            read_line(self.reader, label="hello", maximum=8)
        self.assertLessEqual(len(self.reader._buffer), 10)

    def test_original_fd_close_wakes_authenticated_reader(self) -> None:
        self.reader.authenticated()
        waiting = threading.Event()
        outcome: list[bytes | None] = []
        select = self.reader._selector.select
        def wait(timeout: float | None) -> list:
            waiting.set()
            return select(timeout)
        def read() -> None:
            outcome.append(read_line(self.reader, label="request"))
        with mock.patch.object(self.reader._selector, "select", side_effect=wait):
            worker = threading.Thread(target=read, daemon=True)
            worker.start()
            self.assertTrue(waiting.wait(2))
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            worker.join(1)
            try:
                self.assertFalse(worker.is_alive(), "closed original FD lost the selector wakeup")
                self.assertEqual(outcome, [None])
            finally:
                self.peer.close()
                worker.join(2)

    def test_selector_constructor_failure_closes_duplicate_fd(self) -> None:
        duplicate = self.connection.dup()
        with mock.patch.object(socket.socket, "dup", return_value=duplicate), mock.patch.object(connections.selectors, "DefaultSelector", side_effect=OSError("selector failed")):
            with self.assertRaises(OSError):
                SocketLineReader(self.connection, deadline=time.monotonic() + 1)
        self.assertEqual(duplicate.fileno(), -1)

    def test_invalid_size_rejected_before_io(self) -> None:
        for value in (True, 0, -1, 1.5, MAX_LINE_BYTES + 3):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.reader.readline(value)

    def test_selector_registration_failure_closes_selector(self) -> None:
        selector = mock.Mock()
        selector.register.side_effect = OSError("register failed")
        with mock.patch.object(connections.selectors, "DefaultSelector", return_value=selector):
            with self.assertRaises(OSError):
                SocketLineReader(self.connection, deadline=time.monotonic() + 1)
        selector.close.assert_called_once()

    def test_invalid_deadline_rejected(self) -> None:
        for value in (True, float("nan"), float("inf"), "2"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                SocketLineReader(self.connection, deadline=value)

    def test_close_is_idempotent_and_rejects_more_reads(self) -> None:
        self.reader.close()
        self.reader.close()
        with self.assertRaisesRegex(ValueError, "closed"):
            self.reader.readline(32)


@unittest.skipUnless(sys.platform.startswith("linux") and Path("/proc/self/task").is_dir(), "Linux source thread accounting")
class ProductionConnectionBoundTests(unittest.TestCase):
    def test_silent_connections_are_bounded_before_authentication(self) -> None:
        with tempfile.TemporaryDirectory(prefix="g1-broker-connection-") as raw:
            root = Path(raw)
            upstream = root / "host"
            upstream.write_text('#!/usr/bin/env python3\nimport json,sys\njson.loads(next(sys.stdin))\nprint(json.dumps({"kind":"hello.ack","seq":0,"direction":"host_to_client","payload":{}}),flush=True)\nfor line in sys.stdin: pass\n')
            upstream.chmod(0o700)
            broker = ROOT / "owner-open/owner_open_connection_broker.py"
            process = subprocess.Popen([sys.executable, str(broker), "--socket", str(root / "sock"), "--descriptor", str(root / "desc"), "--token-file", str(root / "token"), "--broker-id", "connection-bound", "--upstream", str(upstream), "--max-clients", "2", "--max-inflight-requests", "1"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            peers: list[socket.socket] = []
            try:
                deadline = time.monotonic() + 5
                while not (root / "desc").exists():
                    if process.poll() is not None:
                        self.fail(process.communicate()[1].decode())
                    if time.monotonic() >= deadline:
                        self.fail("broker startup deadline exceeded")
                    time.sleep(.01)
                # Descriptor publication precedes static worker startup.
                time.sleep(.1)
                baseline = len(list(Path(f"/proc/{process.pid}/task").iterdir()))
                for _ in range(12):
                    peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    peers.append(peer)
                    peer.settimeout(1)
                    connect_deadline = time.monotonic() + 1
                    while True:
                        try:
                            peer.connect(str(root / "sock"))
                            break
                        except BlockingIOError:
                            if time.monotonic() >= connect_deadline:
                                raise
                            time.sleep(.005)
                    time.sleep(.01)
                time.sleep(.1)
                threads = len(list(Path(f"/proc/{process.pid}/task").iterdir()))
                self.assertLessEqual(threads - baseline, 2)
                # Authenticate one reserved connection while another stays silent.
                # Shutdown must retire both states without losing epoll wakeups.
                token = (root / "token").read_text().strip()
                peers[0].sendall(json.dumps({"kind": "broker.hello", "client_id": "bound-client", "token": token}).encode() + b"\n")
                reply = bytearray()
                while not reply.endswith(b"\n"):
                    chunk = peers[0].recv(1)
                    self.assertTrue(chunk, "hello ack was not delivered")
                    reply.extend(chunk)
                    self.assertLess(len(reply), 65536)
                self.assertEqual(json.loads(reply)["kind"], "broker.hello.ack")
                process.terminate()
                _, errors = process.communicate(timeout=6)
                self.assertEqual(process.returncode, 0, errors.decode())
            finally:
                for peer in peers:
                    peer.close()
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
