from __future__ import annotations

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
                str(RELAY),
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
        try:
            self.assertEqual(self.exchange(descriptor, payload), payload)
        finally:
            _stdout, stderr = self.stop_relay(child)
        self.assertEqual(stderr, b"")
        self.assertEqual(
            descriptor["selected_entry"],
            "tools/owner-open/adb_smart_socket_relay_selected.py",
        )
        self.assertTrue(descriptor["byte_transparent"])
        self.assertFalse(descriptor["adb_protocol_parsed"])
        self.assertFalse(descriptor["argv_or_serial_injected"])
        records = [json.loads(line) for line in events.read_text().splitlines()]
        terminal = next(item for item in records if item["kind"] == "connection_terminal")
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
                    str(RELAY),
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


if __name__ == "__main__":
    unittest.main()
