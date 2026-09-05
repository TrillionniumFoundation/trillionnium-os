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

RELAY = Path(__file__).resolve().parents[1] / "owner-open" / "owner_open_adb_relay.py"


class EchoServer:
    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.port = self.listener.getsockname()[1]
        self.stopping = threading.Event()
        self.threads: list[threading.Thread] = []
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self) -> None:
        self.listener.settimeout(0.05)
        while not self.stopping.is_set():
            try:
                client, _address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            thread = threading.Thread(target=self.echo, args=(client,), daemon=True)
            self.threads.append(thread)
            thread.start()

    @staticmethod
    def echo(client: socket.socket) -> None:
        with client:
            while True:
                data = client.recv(65536)
                if not data:
                    try:
                        client.shutdown(socket.SHUT_RD)
                    except OSError:
                        pass
                    return
                client.sendall(data)

    def close(self) -> None:
        self.stopping.set()
        self.listener.close()
        self.thread.join(timeout=1)
        for thread in self.threads:
            thread.join(timeout=1)


class OwnerOpenAdbRelayTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.upstream = EchoServer()

    def tearDown(self) -> None:
        self.upstream.close()
        self.temp.cleanup()

    def start_relay(self, **overrides: object) -> tuple[subprocess.Popen[bytes], dict]:
        descriptor = self.root / "relay.json"
        events = self.root / "events.jsonl"
        command = [
            sys.executable,
            str(RELAY),
            "--listen-port",
            str(overrides.get("listen_port", 0)),
            "--upstream-port",
            str(self.upstream.port),
            "--descriptor",
            str(descriptor),
            "--events",
            str(events),
            "--idle-timeout",
            str(overrides.get("idle_timeout", 5)),
            "--buffer-bytes",
            str(overrides.get("buffer_bytes", 65536)),
            "--max-clients",
            str(overrides.get("max_clients", 4)),
        ]
        child = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if descriptor.exists():
                return child, json.loads(descriptor.read_text())
            if child.poll() is not None:
                stdout, stderr = child.communicate()
                self.fail(
                    f"relay exited early rc={child.returncode}\n"
                    f"stdout={stdout!r}\nstderr={stderr!r}"
                )
            time.sleep(0.02)
        child.terminate()
        child.wait(timeout=2)
        self.fail("relay descriptor was not created")

    def stop_relay(self, child: subprocess.Popen[bytes]) -> tuple[bytes, bytes]:
        child.terminate()
        try:
            return child.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            child.kill()
            return child.communicate(timeout=2)

    def test_relay_preserves_arbitrary_adb_smart_socket_bytes(self) -> None:
        child, descriptor = self.start_relay()
        payload = (
            b"0012host:transport-any"
            b"000Chost:version"
            b"\x00\xffunknown-service\n"
            + os.urandom(8192)
        )
        try:
            with socket.create_connection(
                (descriptor["listen_host"], descriptor["listen_port"]), timeout=2
            ) as client:
                client.sendall(payload)
                client.shutdown(socket.SHUT_WR)
                received = bytearray()
                while len(received) < len(payload):
                    chunk = client.recv(65536)
                    if not chunk:
                        break
                    received.extend(chunk)
            self.assertEqual(bytes(received), payload)
        finally:
            _stdout, stderr = self.stop_relay(child)
        self.assertEqual(stderr, b"")
        self.assertEqual(descriptor["byte_transparent"], True)
        self.assertEqual(descriptor["adb_protocol_parsed"], False)
        self.assertEqual(descriptor["argv_or_serial_injected"], False)
        self.assertEqual(descriptor["payload_logged"], False)
        events = [
            json.loads(line)
            for line in (self.root / "events.jsonl").read_text().splitlines()
        ]
        terminal = next(item for item in events if item["kind"] == "connection_terminal")
        self.assertEqual(terminal["client_to_upstream_bytes"], len(payload))
        self.assertEqual(terminal["upstream_to_client_bytes"], len(payload))
        self.assertFalse(terminal["payload_logged"])
        encoded_events = json.dumps(events)
        self.assertNotIn(payload[:16].hex(), encoded_events)
        self.assertNotIn("raw_line_base64", encoded_events)

    def test_relay_supports_multiple_independent_connections(self) -> None:
        child, descriptor = self.start_relay(max_clients=8)
        errors: list[BaseException] = []

        def exchange(index: int) -> None:
            payload = f"connection-{index}".encode() * 2048
            try:
                with socket.create_connection(
                    (descriptor["listen_host"], descriptor["listen_port"]), timeout=2
                ) as client:
                    client.sendall(payload)
                    received = bytearray()
                    while len(received) < len(payload):
                        received.extend(client.recv(65536))
                if bytes(received) != payload:
                    raise AssertionError("relay changed concurrent connection bytes")
            except BaseException as error:
                errors.append(error)

        threads = [threading.Thread(target=exchange, args=(index,)) for index in range(4)]
        try:
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(errors, [])
        finally:
            self.stop_relay(child)

    def test_non_loopback_listener_and_upstream_are_rejected(self) -> None:
        for option in ("--listen-host", "--upstream-host"):
            completed = subprocess.run(
                [
                    sys.executable,
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

    def test_small_buffer_failure_is_finite_and_does_not_log_payload(self) -> None:
        child, descriptor = self.start_relay(buffer_bytes=4096)
        try:
            with socket.create_connection(
                (descriptor["listen_host"], descriptor["listen_port"]), timeout=2
            ) as client:
                client.settimeout(2)
                client.sendall(os.urandom(256 * 1024))
                try:
                    while client.recv(65536):
                        pass
                except (ConnectionError, socket.timeout):
                    pass
        finally:
            self.stop_relay(child)
        text = (self.root / "events.jsonl").read_text()
        self.assertNotIn("raw_line_base64", text)
        self.assertIn("automatic_redispatch", text)


if __name__ == "__main__":
    unittest.main()
