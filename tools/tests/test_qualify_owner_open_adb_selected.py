from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

TOOLS = Path(__file__).resolve().parents[1] / "owner-open"
QUALIFIER = TOOLS / "qualify_owner_open_adb_selected.py"
RELAY = TOOLS / "adb_smart_socket_relay_selected.py"


class CaptureEchoServer:
    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.settimeout(0.05)
        self.port = self.listener.getsockname()[1]
        self.records: list[bytes] = []
        self.lock = threading.Lock()
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
            worker = threading.Thread(target=self.capture, args=(client,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def capture(self, client: socket.socket) -> None:
        raw = bytearray()
        with client:
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                raw.extend(chunk)
            with self.lock:
                self.records.append(bytes(raw))
            client.sendall(raw)

    def close(self) -> None:
        self.stopping.set()
        self.listener.close()
        self.thread.join(timeout=1)
        for worker in self.workers:
            worker.join(timeout=1)


FAKE_ADB = r'''#!/usr/bin/env python3
import json
import os
import socket
import sys

endpoint = os.environ.get("ADB_SERVER_SOCKET", "")
if not endpoint.startswith("tcp:"):
    print("missing ADB_SERVER_SOCKET", file=sys.stderr)
    raise SystemExit(91)
_prefix, host, port = endpoint.split(":", 2)
payload = json.dumps(
    {
        "argv": sys.argv[1:],
        "android_serial": os.environ.get("ANDROID_SERIAL"),
        "adb_server_port": os.environ.get("ADB_SERVER_PORT"),
        "android_adb_server_port": os.environ.get("ANDROID_ADB_SERVER_PORT"),
        "adb_server_socket": endpoint,
    },
    sort_keys=True,
    separators=(",", ":"),
).encode()
with socket.create_connection((host, int(port)), timeout=3) as client:
    client.sendall(payload)
    client.shutdown(socket.SHUT_WR)
    echoed = bytearray()
    while True:
        chunk = client.recv(65536)
        if not chunk:
            break
        echoed.extend(chunk)
if echoed != payload:
    print("relay changed fake adb bytes", file=sys.stderr)
    raise SystemExit(92)
print(json.dumps({"observed": sys.argv[1:]}, separators=(",", ":")))
if "fail-exactly-once" in sys.argv[1:]:
    raise SystemExit(7)
'''


class SelectedAdbQualificationTest(unittest.TestCase):
    QUALIFIER = QUALIFIER
    RELAY = RELAY

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.python = self.root / "python"
        shutil.copyfile(Path(sys.executable).resolve(), self.python)
        self.python.chmod(0o700)
        self.workspace = self.root / "workspace"
        self.state = self.root / "state"
        self.workspace.mkdir(mode=0o700)
        self.state.mkdir(mode=0o700)
        self.adb = self.root / "adb"
        self.adb.write_text(FAKE_ADB, encoding="utf-8")
        self.adb.chmod(0o700)
        self.server = CaptureEchoServer()

    def tearDown(self) -> None:
        self.server.close()
        self.temp.cleanup()

    def plan(self, steps: list[dict]) -> Path:
        path = self.root / f"plan-{time.monotonic_ns()}.json"
        path.write_text(
            json.dumps(
                {
                    "schema": "org.trillionnium.owner-open.adb-qualification-plan.v1",
                    "plan_id": "fixture-plan",
                    "steps": steps,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return path

    def command(self, plan: Path, evidence: Path) -> list[str]:
        return [
            str(Path(sys.executable).resolve()),
            str(self.QUALIFIER),
            "--execute",
            "--plan",
            str(plan),
            "--adb",
            str(self.adb),
            "--python",
            str(self.python),
            "--relay",
            str(self.RELAY),
            "--upstream-port",
            str(self.server.port),
            "--workspace",
            str(self.workspace),
            "--state-dir",
            str(self.state),
            "--evidence-dir",
            str(evidence),
            "--relay-start-timeout",
            "5",
            "--idle-timeout",
            "5",
        ]

    def wait_records(self, count: int) -> None:
        deadline = time.monotonic() + 3
        while len(self.server.records) < count and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(len(self.server.records), count)

    def test_exact_argv_including_empty_argument_and_no_route_injection(self) -> None:
        plan = self.plan(
            [
                {"operation_id": "devices", "argv": ["devices", "-l"]},
                {
                    "operation_id": "unknown",
                    "argv": ["future-unknown-subcommand", "", "value with spaces"],
                },
                {
                    "operation_id": "shell",
                    "argv": ["shell", "printf", "opaque"],
                },
            ]
        )
        evidence = self.root / "evidence-pass"
        environment = os.environ.copy()
        environment.update(
            ANDROID_SERIAL="must-not-leak",
            ADB_SERVER_PORT="1111",
            ANDROID_ADB_SERVER_PORT="2222",
        )
        completed = subprocess.run(
            self.command(plan, evidence),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=30,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            completed.stderr.decode("utf-8", errors="replace"),
        )
        report = json.loads((evidence / "qualification-report.json").read_text())
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["steps_executed_once"], 3)
        self.assertEqual([item["spawn_count"] for item in report["steps"]], [1, 1, 1])
        self.assertTrue(all(item["passed"] for item in report["steps"]))
        self.wait_records(3)
        decoded = [json.loads(item) for item in self.server.records]
        self.assertEqual(decoded[0]["argv"], ["devices", "-l"])
        self.assertEqual(
            decoded[1]["argv"],
            ["future-unknown-subcommand", "", "value with spaces"],
        )
        for item in decoded:
            self.assertIsNone(item["android_serial"])
            self.assertIsNone(item["adb_server_port"])
            self.assertIsNone(item["android_adb_server_port"])
            self.assertTrue(item["adb_server_socket"].startswith("tcp:127.0.0.1:"))

    def test_failed_step_is_recorded_once_before_runner_stops(self) -> None:
        plan = self.plan(
            [
                {
                    "operation_id": "fail-once",
                    "argv": ["fail-exactly-once", "opaque"],
                    "expected_exit_codes": [0],
                },
                {"operation_id": "must-not-run", "argv": ["version"]},
            ]
        )
        evidence = self.root / "evidence-fail"
        completed = subprocess.run(
            self.command(plan, evidence),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.wait_records(1)
        report = json.loads((evidence / "qualification-report.json").read_text())
        self.assertEqual(report["status"], "failed")
        self.assertEqual(len(report["steps"]), 1)
        self.assertEqual(report["steps"][0]["operation_id"], "fail-once")
        self.assertEqual(report["steps"][0]["spawn_count"], 1)
        self.assertFalse(report["steps"][0]["passed"])
        self.assertFalse(report["automatic_redispatch"])
        self.assertTrue((evidence / "step-000-fail-once.json").exists())

    def test_invalid_plan_fails_before_creating_evidence_or_starting_relay(self) -> None:
        plan = self.plan(
            [
                {"operation_id": "same", "argv": ["version"]},
                {"operation_id": "same", "argv": ["devices"]},
            ]
        )
        evidence = self.root / "evidence-invalid"
        completed = subprocess.run(
            self.command(plan, evidence),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(evidence.exists())
        self.assertEqual(self.server.records, [])

    def test_execute_flag_is_mandatory(self) -> None:
        plan = self.plan([{"operation_id": "version", "argv": ["version"]}])
        command = self.command(plan, self.root / "evidence-no-execute")
        command.remove("--execute")
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"--execute is required", completed.stderr)


if __name__ == "__main__":
    unittest.main()
