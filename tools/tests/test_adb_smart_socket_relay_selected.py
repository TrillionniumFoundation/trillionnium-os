from __future__ import annotations

import asyncio
import importlib.util
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

RELAY = (
    Path(__file__).resolve().parents[1]
    / "owner-open"
    / "adb_smart_socket_relay_selected.py"
)


class EchoServer:
    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.settimeout(0.05)
        self.port = self.listener.getsockname()[1]
        self.stopping = threading.Event()
        self.workers: list[threading.Thread] = []
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self) -> None:
        while not self.stopping.is_set():
            try:
                client, _address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            worker = threading.Thread(target=self.echo, args=(client,), daemon=True)
            self.workers.append(worker)
            worker.start()

    @staticmethod
    def echo(client: socket.socket) -> None:
        with client:
            while True:
                raw = client.recv(65536)
                if not raw:
                    return
                client.sendall(raw)

    def close(self) -> None:
        self.stopping.set()
        self.listener.close()
        self.thread.join(timeout=1)
        for worker in self.workers:
            worker.join(timeout=1)


class SelectedAdbSmartSocketRelayTest(unittest.TestCase):
    RELAY = RELAY

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.upstream = EchoServer()

    def tearDown(self) -> None:
        self.upstream.close()
        self.temp.cleanup()

    def start_relay(self, *, max_clients: int = 8, event_bytes: int = 1048576):
        descriptor = self.root / f"descriptor-{time.monotonic_ns()}.json"
        events = self.root / f"events-{time.monotonic_ns()}.jsonl"
        child = subprocess.Popen(
            [
                str(Path(sys.executable).resolve()),
                str(self.RELAY),
                "--listen-port",
                "0",
                "--upstream-port",
                str(self.upstream.port),
                "--max-clients",
                str(max_clients),
                "--buffer-bytes",
                "65536",
                "--event-bytes",
                str(event_bytes),
                "--idle-timeout",
                "5",
                "--shutdown-grace",
                "1",
                "--descriptor",
                str(descriptor),
                "--events",
                str(events),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if descriptor.exists():
                return child, json.loads(descriptor.read_text()), events
            if child.poll() is not None:
                stdout, stderr = child.communicate()
                self.fail(
                    f"relay exited before ready rc={child.returncode} "
                    f"stdout={stdout!r} stderr={stderr!r}"
                )
            time.sleep(0.02)
        child.kill()
        child.wait(timeout=2)
        self.fail("relay did not create its descriptor")

    @staticmethod
    def stop_relay(child: subprocess.Popen[bytes]) -> tuple[bytes, bytes]:
        child.terminate()
        try:
            return child.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            child.kill()
            return child.communicate(timeout=2)

    def exchange(self, descriptor: dict, payload: bytes) -> bytes:
        with socket.create_connection(
            (descriptor["listen_host"], descriptor["listen_port"]), timeout=2
        ) as client:
            client.settimeout(3)
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
            result = bytearray()
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                result.extend(chunk)
            return bytes(result)

    def test_arbitrary_bytes_and_half_close_are_preserved(self) -> None:
        child, descriptor, events = self.start_relay()
        payload = (
            b"0012host:transport-any"
            b"000chost:version"
            b"\x00\xffunknown-service\n"
            + os.urandom(131072)
        )
        terminal = None
        try:
            self.assertEqual(self.exchange(descriptor, payload), payload)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                records = [
                    json.loads(line)
                    for line in events.read_text().splitlines()
                ]
                terminal = next(
                    (
                        item
                        for item in records
                        if item["kind"] == "connection_terminal"
                    ),
                    None,
                )
                if terminal is not None:
                    break
                time.sleep(0.02)
        finally:
            _stdout, stderr = self.stop_relay(child)
        self.assertEqual(stderr, b"")
        self.assertEqual(
            descriptor["selected_entry"],
            f"tools/owner-open/{self.RELAY.name}",
        )
        self.assertTrue(descriptor["byte_transparent"])
        self.assertFalse(descriptor["adb_protocol_parsed"])
        self.assertFalse(descriptor["argv_or_serial_injected"])
        if terminal is None:
            self.fail(
                "relay did not durably record connection_terminal before shutdown"
            )
        self.assertEqual(terminal["client_to_upstream_bytes"], len(payload))
        self.assertEqual(terminal["upstream_to_client_bytes"], len(payload))
        self.assertFalse(terminal["payload_logged"])
        self.assertNotIn("raw_line_base64", events.read_text())

    def test_multiple_connections_are_isolated(self) -> None:
        child, descriptor, _events = self.start_relay(max_clients=8)
        errors: list[BaseException] = []

        def worker(index: int) -> None:
            payload = (f"connection-{index}:".encode() + os.urandom(1024)) * 16
            try:
                if self.exchange(descriptor, payload) != payload:
                    raise AssertionError("relay changed bytes")
            except BaseException as error:
                errors.append(error)

        threads = [threading.Thread(target=worker, args=(index,)) for index in range(6)]
        try:
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=8)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(errors, [])
        finally:
            self.stop_relay(child)

    def test_network_exposure_is_rejected_before_bind(self) -> None:
        for option in ("--listen-host", "--upstream-host"):
            completed = subprocess.run(
                [
                    str(Path(sys.executable).resolve()),
                    str(self.RELAY),
                    "--listen-port",
                    "0",
                    "--upstream-port",
                    str(self.upstream.port),
                    option,
                    "192.0.2.1",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(b"must be loopback", completed.stderr)

    def test_event_journal_bound_is_explicit(self) -> None:
        child, descriptor, _events = self.start_relay(event_bytes=4096)
        try:
            for index in range(50):
                try:
                    self.exchange(descriptor, f"event-{index}".encode())
                except (ConnectionError, OSError, socket.timeout):
                    break
        finally:
            self.stop_relay(child)
        self.assertIsNotNone(child.returncode)


# These are host-only fault fixtures. They do not contact ADB or a device and
# cannot establish installed identities, destructive faults or release evidence.
def _load_fault_relay(name, filename):
    spec = importlib.util.spec_from_file_location(name, RELAY.parent / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fault_base = _load_fault_relay("selected_relay_fault_fixture", "adb_smart_socket_relay_selected.py")
with mock.patch.dict(sys.modules, {"adb_smart_socket_relay_selected": fault_base}):
    fault_release = _load_fault_relay("release_relay_fault_fixture", "adb_smart_socket_relay_release.py")


class ShortWriteHandle:
    def __init__(self, handle, chunk=7):
        self.handle = handle
        self.chunk = chunk
        self.calls = 0

    def write(self, raw):
        self.calls += 1
        return self.handle.write(raw[:self.chunk])

    def flush(self):
        self.handle.flush()

    def fileno(self):
        return self.handle.fileno()


class SelectedRelayPersistenceTest(unittest.IsolatedAsyncioTestCase):
    async def test_positive_short_writes_commit_one_complete_record(self):
        with tempfile.TemporaryFile(mode="w+b", buffering=0) as handle:
            short = ShortWriteHandle(handle)
            writer = fault_base.EventWriter(short, 4096)
            await writer.append("fixture", payload_logged=False)
            handle.seek(0)
            raw = handle.read()
            self.assertTrue(raw.endswith(b"\n"), "short write was falsely committed")
            self.assertEqual(json.loads(raw)["sequence"], 0)
            self.assertEqual(writer.written, len(raw))
            self.assertEqual(writer.sequence, 1)
            self.assertGreater(short.calls, 1)

    async def test_invalid_write_progress_fails_and_fences_the_writer(self):
        for result in (0, -1, None, True, 0.5, "1", 100000):
            with self.subTest(result=result), tempfile.TemporaryFile(mode="w+b", buffering=0) as handle:
                wrapped = ShortWriteHandle(handle)
                with mock.patch.object(wrapped, "write", return_value=result) as write:
                    writer = fault_base.EventWriter(wrapped, 4096)
                    with self.assertRaises(fault_base.RelayError):
                        await writer.append("invalid-progress")
                    with self.assertRaises(fault_base.RelayError):
                        await writer.append("must-not-append")
                    self.assertEqual(write.call_count, 1)
                    self.assertEqual((writer.sequence, writer.written), (0, 0))

    async def test_partial_write_failure_preserves_bytes_and_never_appends_again(self):
        with tempfile.TemporaryFile(mode="w+b", buffering=0) as handle:
            wrapped = ShortWriteHandle(handle)
            original = wrapped.write
            def write(raw):
                if wrapped.calls:
                    raise OSError("injected write failure")
                return original(raw)
            with mock.patch.object(wrapped, "write", side_effect=write):
                writer = fault_base.EventWriter(wrapped, 4096)
                with self.assertRaises(OSError):
                    await writer.append("partial")
                size = os.fstat(handle.fileno()).st_size
                self.assertGreater(size, 0)
                with self.assertRaises(fault_base.RelayError):
                    await writer.append("no-repair")
                self.assertEqual(os.fstat(handle.fileno()).st_size, size)
                self.assertEqual((writer.sequence, writer.written), (0, 0))

    async def test_fsync_failure_is_sticky_without_advancing_committed_counters(self):
        with tempfile.TemporaryFile(mode="w+b", buffering=0) as handle:
            writer = fault_base.EventWriter(handle, 4096)
            with mock.patch.object(fault_base.os, "fsync", side_effect=OSError("injected fsync")) as sync:
                with self.assertRaises(OSError):
                    await writer.append("undurable")
                size = os.fstat(handle.fileno()).st_size
                with self.assertRaises(fault_base.RelayError):
                    await writer.append("must-not-follow-uncertain-record")
                self.assertEqual(sync.call_count, 1)
                self.assertEqual(os.fstat(handle.fileno()).st_size, size)
                self.assertEqual((writer.sequence, writer.written), (0, 0))

    async def test_flush_failure_is_sticky(self):
        with tempfile.TemporaryFile(mode="w+b", buffering=0) as handle:
            wrapped = ShortWriteHandle(handle, chunk=4096)
            writer = fault_base.EventWriter(wrapped, 4096)
            with mock.patch.object(wrapped, "flush", side_effect=OSError("injected flush")):
                with self.assertRaises(OSError):
                    await writer.append("flush-error")
            size = os.fstat(handle.fileno()).st_size
            with self.assertRaises(fault_base.RelayError):
                await writer.append("must-not-resume")
            self.assertEqual(os.fstat(handle.fileno()).st_size, size)
            self.assertEqual(writer.sequence, 0)

    async def test_capacity_failure_cannot_resume_with_a_smaller_record(self):
        with tempfile.TemporaryFile(mode="w+b", buffering=0) as handle:
            writer = fault_base.EventWriter(handle, 256)
            with self.assertRaises(fault_base.RelayError):
                await writer.append("large", detail="x" * 300)
            with self.assertRaises(fault_base.RelayError):
                await writer.append("small")
            self.assertEqual(os.fstat(handle.fileno()).st_size, 0)

    async def test_concurrent_records_are_complete_and_monotonic(self):
        with tempfile.TemporaryFile(mode="w+b", buffering=0) as handle:
            writer = fault_base.EventWriter(ShortWriteHandle(handle), 16384)
            await asyncio.gather(*(writer.append("concurrent", index=i) for i in range(8)))
            handle.seek(0)
            raw = handle.read()
            records = [json.loads(line) for line in raw.splitlines()]
            self.assertEqual([r["sequence"] for r in records], list(range(8)))
            self.assertEqual({r["index"] for r in records}, set(range(8)))
            self.assertEqual(writer.written, len(raw))

    async def test_disabled_log_does_not_claim_persisted_records(self):
        writer = fault_base.EventWriter(None, 4096)
        await writer.append("disabled")
        self.assertEqual((writer.sequence, writer.written), (0, 0))


class RelayTransferOwnershipTest(unittest.IsolatedAsyncioTestCase):
    async def test_transfer_error_collects_its_other_direction_before_return(self):
        entered = asyncio.Event()
        collected = asyncio.Event()
        owners = []
        async def pump(_reader, _writer, _state, direction):
            owners.append(asyncio.current_task())
            if direction == "client_to_upstream":
                await entered.wait()
                raise ConnectionError("injected transport failure")
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                collected.set()
        try:
            with mock.patch.object(fault_base, "pump", side_effect=pump):
                with self.assertRaises(ConnectionError):
                    await fault_base.transfer_pair(None, None, None, None, None)
            self.assertTrue(collected.is_set(), "sibling pump escaped transfer ownership")
        finally:
            for owner in owners:
                if owner is not None and not owner.done():
                    owner.cancel()
            await asyncio.gather(*(t for t in owners if t is not None), return_exceptions=True)

    async def test_half_close_does_not_cancel_the_remaining_direction(self):
        half_closed = asyncio.Event()
        release = asyncio.Event()
        delivered = asyncio.Event()
        async def pump(_reader, _writer, _state, direction):
            if direction == "client_to_upstream":
                half_closed.set()
                return
            await release.wait()
            delivered.set()
        with mock.patch.object(fault_base, "pump", side_effect=pump):
            pair = asyncio.create_task(fault_base.transfer_pair(None, None, None, None, None))
            try:
                await asyncio.wait_for(half_closed.wait(), 1)
                self.assertFalse(pair.done())
                release.set()
                await asyncio.wait_for(pair, 1)
                self.assertTrue(delivered.is_set())
            finally:
                pair.cancel()
                await asyncio.gather(pair, return_exceptions=True)

    async def test_timed_out_close_aborts_the_transport(self):
        writer = mock.Mock()
        writer.wait_closed = mock.AsyncMock(side_effect=lambda: None)
        async def blocked_close():
            await asyncio.Event().wait()
        writer.wait_closed.side_effect = blocked_close
        await fault_base.close_writer(writer, 0.01)
        writer.transport.abort.assert_called_once()


class RecordingFaultEvents:
    def __init__(self):
        self.records = []
        self.started = asyncio.Event()
        self.terminal = asyncio.Event()
        self.failed = asyncio.Event()
        self.fail_kind = None

    async def append(self, kind, **fields):
        if kind == self.fail_kind:
            self.failed.set()
            raise OSError("injected relay journal failure")
        self.records.append({"kind": kind, **fields})
        if kind == "connection_started":
            self.started.set()
        if kind == "connection_terminal":
            self.terminal.set()


class ReleaseRelayJournalFailureTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.initial_tasks = set(asyncio.all_tasks())
        self.writers = []
        self.upstream_tasks = set()
        async def echo(reader, writer):
            task = asyncio.current_task()
            self.upstream_tasks.add(task)
            self.writers.append(writer)
            try:
                while raw := await reader.read(65536):
                    writer.write(raw)
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
                self.upstream_tasks.discard(task)
        self.upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        self.events = RecordingFaultEvents()
        self.relay = fault_release.ReleaseRelay(
            "127.0.0.1", 0, "127.0.0.1", self.upstream.sockets[0].getsockname()[1],
            fault_base.Limits(1, 4096, 16384, 1, 30, 0.2), self.events,
        )
        self.descriptor = await self.relay.start(None)

    async def asyncTearDown(self):
        self.relay.stop()
        self.relay.server.close()
        self.upstream.close()
        for writer in self.writers:
            writer.close()
            writer.transport.abort()
        # Only this isolated loop's fixture tasks are collected, including on
        # the defective implementation. No external process/device is touched.
        remaining = [t for t in asyncio.all_tasks() if t not in self.initial_tasks
                     and t is not asyncio.current_task()]
        for task in remaining:
            task.cancel()
        if remaining:
            await asyncio.wait_for(asyncio.gather(*remaining, return_exceptions=True), 2)
        await asyncio.wait_for(self.relay.server.wait_closed(), 1)
        await asyncio.wait_for(self.upstream.wait_closed(), 1)
        for writer in self.writers:
            try:
                await asyncio.wait_for(writer.wait_closed(), 1)
            except (OSError, RuntimeError, asyncio.CancelledError):
                pass

    async def connect(self):
        reader, writer = await asyncio.open_connection(
            self.descriptor["listen_host"], self.descriptor["listen_port"])
        self.writers.append(writer)
        return reader, writer

    async def test_normal_eof_is_completed_before_idle_timeout(self):
        reader, writer = await self.connect()
        payload = b"opaque\x00\xff" * 1024
        writer.write(payload)
        await writer.drain()
        writer.write_eof()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), payload)
        await asyncio.wait_for(self.events.terminal.wait(), 2)
        terminal = [r for r in self.events.records if r["kind"] == "connection_terminal"][0]
        self.assertEqual(terminal["terminal"], "completed")
        self.assertFalse(terminal["automatic_redispatch"])
        self.assertFalse(self.relay.semaphore.locked())

    async def test_stop_with_live_client_drains_before_waiting_for_server_close(self):
        _reader, writer = await self.connect()
        await asyncio.wait_for(self.events.started.wait(), 1)
        serving = asyncio.create_task(self.relay.serve())
        self.relay.stop()
        try:
            try:
                result = await asyncio.wait_for(asyncio.shield(serving), 1)
            except asyncio.TimeoutError:
                self.fail("shutdown waited for clients before cancelling their handlers")
            self.assertEqual(result, 0)
            self.assertFalse(self.relay.connections)
            self.assertFalse(self.relay.semaphore.locked())
        finally:
            writer.close()
            writer.transport.abort()
            serving.cancel()
            await asyncio.gather(serving, return_exceptions=True)

    async def test_started_journal_failure_inhibits_further_admission(self):
        self.events.fail_kind = "connection_started"
        await self.connect()
        await asyncio.wait_for(self.events.failed.wait(), 1)
        await asyncio.sleep(0)
        self.assertTrue(self.relay.stop_event.is_set(), "journal failure did not inhibit admission")
        self.assertEqual(await asyncio.wait_for(self.relay.serve(), 2), 1)

    async def test_terminal_journal_failure_stops_with_nonzero_result(self):
        self.events.fail_kind = "connection_terminal"
        reader, writer = await self.connect()
        await asyncio.wait_for(self.events.started.wait(), 1)
        writer.write_eof()
        await asyncio.wait_for(reader.read(), 1)
        await asyncio.wait_for(self.events.failed.wait(), 1)
        await asyncio.sleep(0)
        self.assertTrue(self.relay.stop_event.is_set(), "terminal persistence failure was ignored")
        self.assertEqual(await asyncio.wait_for(self.relay.serve(), 2), 1)
        self.assertFalse(self.relay.semaphore.locked())
        self.assertFalse(self.relay.connections)

    async def test_stop_prevents_even_an_upstream_connection(self):
        self.relay.stop()
        writer = mock.Mock()
        writer.wait_closed = mock.AsyncMock()
        with mock.patch.object(fault_base.asyncio, "open_connection", new_callable=mock.AsyncMock) as upstream:
            await self.relay.accept(asyncio.StreamReader(), writer)
        upstream.assert_not_called()
        writer.close.assert_called()

    async def test_rejection_journal_failure_stops_and_collects_the_live_client(self):
        await self.connect()
        await asyncio.wait_for(self.events.started.wait(), 1)
        self.events.fail_kind = "connection_rejected"
        await self.connect()
        await asyncio.wait_for(self.events.failed.wait(), 1)
        self.assertTrue(self.relay.stop_event.is_set())
        self.assertEqual(await asyncio.wait_for(self.relay.serve(), 2), 1)
        self.assertFalse(self.relay.connections)
        self.assertFalse(self.relay.semaphore.locked())

    async def test_cancelling_serve_still_closes_listener_and_connection_owners(self):
        await self.connect()
        await asyncio.wait_for(self.events.started.wait(), 1)
        serving = asyncio.create_task(self.relay.serve())
        await asyncio.sleep(0)
        serving.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(serving, 2)
        self.assertFalse(self.relay.server.is_serving())
        self.assertFalse(self.relay.connections)
        self.assertFalse(self.relay.semaphore.locked())

    async def test_release_descriptor_failure_closes_its_listener(self):
        other = fault_release.ReleaseRelay(
            "127.0.0.1", 0, "127.0.0.1", self.upstream.sockets[0].getsockname()[1],
            fault_base.Limits(1, 4096, 16384, 1, 30, 0.2), RecordingFaultEvents(),
        )
        try:
            with mock.patch.object(fault_base, "atomic_private_json", side_effect=OSError("injected publication")):
                with self.assertRaises(OSError):
                    await other.start(Path("/unused/fixture-descriptor.json"))
            self.assertFalse(other.server.is_serving(), "failed startup left a live listener")
        finally:
            if other.server is not None:
                other.server.close()
                await other.server.wait_closed()


class SelectedRelayContractTest(unittest.TestCase):
    def test_module_contract_binds_the_product_entry_and_its_shared_implementation(self):
        path = RELAY.parents[2] / "docs/modules/MOD-ADB.md"
        document = path.read_text(encoding="utf-8")
        self.assertIn("`tools/owner-open/adb_smart_socket_relay_release.py` — `ReleaseRelay`", document)
        self.assertIn("`tools/owner-open/adb_smart_socket_relay_selected.py` — `EventWriter`", document)
        self.assertNotIn("- Implementation source: `tools/owner-open/owner_open_adb_relay_v2.py`", document)


if __name__ == "__main__":
    unittest.main()
