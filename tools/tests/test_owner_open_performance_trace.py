from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "owner-open"))
import owner_open_broker_common as common
from owner_open_broker_audit import BrokerAuditJournal
from owner_open_broker_mux import WeightedFairMux
from owner_open_broker_runtime import Client


class ActualBoundedTraceTests(unittest.TestCase):
    def setUp(self):
        self.previous = common._PERFORMANCE_TRACE
        common._PERFORMANCE_TRACE = None

    def tearDown(self):
        common._PERFORMANCE_TRACE = self.previous

    def test_disabled_has_no_clock_or_export_effect(self):
        with mock.patch.object(common.time, "monotonic_ns", side_effect=AssertionError("disabled clock")):
            with common.performance_span("tool_spawn", "off"):
                pass
            common.performance_span("tool_exit", "off", deferred=True).finish()
        self.assertIsNone(common._PERFORMANCE_TRACE)
        class Caller:
            @property
            def request_sha256(self):
                raise AssertionError("disabled hook changed business behavior")
        @common.performance_stage("broker_auth")
        def actual_function(value):
            return 17
        self.assertEqual(actual_function(Caller()), 17)

    def test_real_pending_mux_wait_and_abandoned_pending_are_distinct(self):
        recorder = common.configure_performance_trace("real-mux", "broker", 16)
        mux = WeightedFairMux(max_pending=4, max_inflight=1, max_retired=4)
        def request(seq):
            return SimpleNamespace(owner_id="owner", request_id=f"request-{seq}", ordering_key="same-key", upstream_seq=seq,
                                   request_sha256=str(seq) * 64, performance_queue_span=None)
        first, second, removed = request(1), request(2), request(3)
        mux.enqueue(first); self.assertIs(mux.acquire(0.01), first)
        mux.enqueue(second)
        self.assertIsNone(mux.acquire(0.002))
        time.sleep(0.01)
        mux.complete(first, reason="actual-return")
        self.assertIs(mux.acquire(0.01), second)
        snapshot = recorder.snapshot()
        waits = [row for row in snapshot["records"] if row["stage"] == "broker_queue_wait"]
        self.assertEqual(len(waits), 2)
        self.assertGreaterEqual(waits[1]["end_ns"] - waits[1]["start_ns"], 10_000_000)
        self.assertTrue(snapshot["snapshot_without_observed_loss"])
        mux.enqueue(removed); self.assertTrue(mux.remove_pending(removed, reason="owned-test-removal"))
        self.assertFalse(recorder.snapshot()["snapshot_without_observed_loss"])
        self.assertEqual(recorder.snapshot()["records"][-1]["end"], "abandoned")

    def test_actual_socket_queue_wait_write_and_durable_terminal(self):
        recorder = common.configure_performance_trace("socket-journal", "broker", 64)
        local, peer = socket.socketpair()
        peer.settimeout(2)
        client = Client("owned-client", local, os.getpid(), os.getuid(), os.getgid(), 8192, 4)
        try:
            self.assertTrue(client.enqueue({"kind": "owned-observation"}))
            time.sleep(0.01)
            thread = threading.Thread(target=client.writer)
            thread.start()
            self.assertIn(b"owned-observation", peer.recv(8192))
            client.close(); thread.join(2); self.assertFalse(thread.is_alive())
        finally:
            client.close(); peer.close()
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            journal = BrokerAuditJournal(Path(root) / "audit", broker_id="owned-broker")
            try:
                binding = journal.admit(broker_epoch="epoch", client_id="client", request_id="request", request_sha256="a" * 64,
                                        client_seq=0, upstream_seq=1, request_kind="job.inspect", correlation={}).binding
                journal.terminal(binding, owner_message={"kind": "result", "request_id": "request", "frame": {"kind": "job.inspect.result"}})
            finally:
                journal.close()
        snapshot = recorder.snapshot()
        stages = {row["stage"] for row in snapshot["records"]}
        self.assertTrue({"delivery_queue_wait", "client_delivery", "journal_append", "journal_fsync", "terminal_persistence"} <= stages)
        wait = next(row for row in snapshot["records"] if row["stage"] == "delivery_queue_wait")
        self.assertGreaterEqual(wait["end_ns"] - wait["start_ns"], 10_000_000)
        self.assertTrue(snapshot["snapshot_without_observed_loss"])
        self.assertFalse(snapshot["installed_qualified"])

    def test_real_client_lock_wait_is_not_queue_residence(self):
        recorder = common.configure_performance_trace("client-lock-boundary", "broker", 32)
        local, peer = socket.socketpair(); peer.settimeout(2)
        client = Client("owned-client", local, os.getpid(), os.getuid(), os.getgid(), 8192, 4)
        started = threading.Event(); outcome = {}; enqueuer = writer = None
        try:
            client.lock.acquire()
            def enqueue():
                started.set()
                outcome["accepted"] = client.enqueue({"kind": "owned-after-real-lock"})
            enqueuer = threading.Thread(target=enqueue); enqueuer.start()
            self.assertTrue(started.wait(1))
            # Synthetic scheduling only: actual lock/socket/queue/monotonic clock.
            time.sleep(0.075)
            self.assertTrue(enqueuer.is_alive()); self.assertEqual(client.queue.qsize(), 0)
            self.assertEqual(recorder.snapshot()["open_spans"], 0)
            released_ns = time.monotonic_ns(); client.lock.release()
            enqueuer.join(2); self.assertFalse(enqueuer.is_alive()); self.assertTrue(outcome["accepted"])
            self.assertEqual(client.queue.qsize(), 1)
            time.sleep(0.01)
            writer = threading.Thread(target=client.writer); writer.start()
            self.assertIn(b"owned-after-real-lock", peer.recv(8192))
            client.close(); writer.join(2); self.assertFalse(writer.is_alive())
            waits = [row for row in recorder.snapshot()["records"] if row["stage"] == "delivery_queue_wait"]
            self.assertEqual(len(waits), 1)
            self.assertGreaterEqual(waits[0]["start_ns"], released_ns)
            self.assertGreaterEqual(waits[0]["end_ns"] - waits[0]["start_ns"], 10_000_000)
        finally:
            if client.lock.locked(): client.lock.release()
            client.close(); peer.close()
            if enqueuer: enqueuer.join(2)
            if writer: writer.join(2)

    def test_real_closed_byte_capacity_and_full_queue_reject_without_new_span(self):
        recorder = common.configure_performance_trace("client-rejection-boundaries", "broker", 32)
        for kind, maximum_bytes, maximum_frames in (("closed",8192,4),("bytes",1,4),("full",8192,1)):
            local, peer = socket.socketpair()
            client = Client("owned-" + kind, local, os.getpid(), os.getuid(), os.getgid(), maximum_bytes, maximum_frames)
            try:
                if kind == "closed": client.close()
                if kind == "full": self.assertTrue(client.enqueue({"kind": "owned-first"}))
                before = recorder.snapshot()
                self.assertFalse(client.enqueue({"kind": "owned-rejected"}))
                after = recorder.snapshot()
                self.assertEqual(after["open_spans"], before["open_spans"])
                self.assertEqual(after["records"], before["records"])
                self.assertEqual(client.queue.qsize(), 1 if kind == "full" else 0)
            finally:
                client.close(); peer.close()

    def test_bounded_capacity_contention_and_unfinished_span_fail_closed(self):
        recorder = common.PerformanceTrace("capacity", "test", 1)
        first = recorder.start("tool_exit", "owned", True)
        recorder.start("tool_spawn", "overflow").finish()
        self.assertFalse(recorder.snapshot()["snapshot_without_observed_loss"])
        first.finish()
        self.assertEqual(len(recorder.snapshot()["records"]), 1)
        other = common.PerformanceTrace("contention", "test", 4)
        with other.lock:
            thread = threading.Thread(target=lambda: other.start("tool_output", "owned").finish())
            thread.start(); thread.join(1); self.assertFalse(thread.is_alive())
        self.assertTrue(other.snapshot()["loss_observed"])

    def test_real_export_new_inode_refuses_collision_and_symlink_parent(self):
        recorder = common.configure_performance_trace("export", "test", 8)
        with common.performance_span("tool_output", "not-raw-private-command"):
            pass
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            path = Path(root) / "trace"
            with mock.patch.dict(os.environ, {"TRILLIONNIUM_OWNER_TRACE_OUTPUT": str(path)}):
                common.export_performance_trace_from_env()
                payload = json.loads(Path(str(path) + ".test").read_bytes())
                self.assertTrue(payload["snapshot_without_observed_loss"])
                self.assertEqual(Path(str(path) + ".test").stat().st_mode & 0o777, 0o600)
                with self.assertRaises(FileExistsError): common.export_performance_trace_from_env()
            alias = Path(root) / "alias"; alias.symlink_to(root, target_is_directory=True)
            with mock.patch.dict(os.environ, {"TRILLIONNIUM_OWNER_TRACE_OUTPUT": str(alias / "other")}):
                with self.assertRaises(OSError): common.export_performance_trace_from_env()


if __name__ == "__main__":
    unittest.main()
