from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
QUALIFIER = ROOT / "owner-open" / "qualify_codex_mcp_jobs.py"
TRACE_PROXY = ROOT / "owner-open" / "trace_mcp_stdio.py"

spec = importlib.util.spec_from_file_location("qualify_codex_mcp_jobs", QUALIFIER)
assert spec is not None and spec.loader is not None
qualifier = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = qualifier
spec.loader.exec_module(qualifier)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def trace_frame(sequence: int, direction: str, message: dict) -> dict:
    raw = canonical(message)
    return {
        "schema": "org.trillionnium.owner-open.mcp-stdio-trace.v1",
        "connection_id": "connection-test",
        "sequence": sequence,
        "elapsed_ms": sequence,
        "kind": "frame",
        "direction": direction,
        "byte_count": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "raw_line_base64": base64.b64encode(raw).decode("ascii"),
        "message": message,
    }


class CodexMcpQualificationLifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_trace_proxy_closes_and_reaps_a_downstream_that_ignores_eof(self) -> None:
        server = self.root / "server.py"
        server.write_text(
            "#!/usr/bin/env python3\n"
            "import json, signal, sys, time\n"
            "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\n"
            "time.sleep(1.25)\n"
            "for line in sys.stdin:\n"
            "    value=json.loads(line)\n"
            "    print(json.dumps({'jsonrpc':'2.0','id':value.get('id'),'result':{}}, separators=(',',':')), flush=True)\n"
            "time.sleep(60)\n",
            encoding="utf-8",
        )
        server.chmod(0o700)
        trace = self.root / "trace.jsonl"
        stderr = self.root / "stderr.bin"
        child = subprocess.Popen(
            [
                sys.executable,
                str(TRACE_PROXY),
                "--trace",
                str(trace),
                "--stderr",
                str(stderr),
                "--connection-id",
                "connection-test",
                "--",
                str(server),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        request = b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
        started = time.monotonic()
        stdout, process_stderr = child.communicate(request, timeout=8)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 6)
        self.assertEqual(
            json.loads(stdout.decode("utf-8")),
            {"jsonrpc": "2.0", "id": 1, "result": {}},
            process_stderr.decode("utf-8", errors="replace"),
        )
        records = [json.loads(line) for line in trace.read_text().splitlines()]
        self.assertTrue(any(item["kind"] == "upstream_eof" for item in records))
        self.assertTrue(
            any(
                item["kind"] in {"downstream_terminal", "downstream_termination_requested"}
                for item in records
            )
        )

    def test_validate_trace_binds_exact_tools_operations_and_bridge(self) -> None:
        bridge = "bridge-instance-test"
        calls = [
            ("trillionnium_connection_info", {}),
            ("trillionnium_job_start", {"job_id": "pipe-job", "operation_id": "pipe-start", "mode": "pipe", "command": "cat", "bridge_instance_id": bridge}),
            ("trillionnium_job_write", {"job_id": "pipe-job", "operation_id": "pipe-write", "data": "hello from pipe\n", "bridge_instance_id": bridge}),
            ("trillionnium_job_close_stdin", {"job_id": "pipe-job", "operation_id": "pipe-close", "bridge_instance_id": bridge}),
            ("trillionnium_job_wait", {"job_id": "pipe-job"}),
            ("trillionnium_job_start", {"job_id": "pty-job", "operation_id": "pty-start", "mode": "pty", "command": "cat", "pty": {"rows": 24, "cols": 80}, "bridge_instance_id": bridge}),
            ("trillionnium_job_write", {"job_id": "pty-job", "operation_id": "pty-write", "data": "hello from pty\n", "bridge_instance_id": bridge}),
            ("trillionnium_job_resize", {"job_id": "pty-job", "operation_id": "pty-resize", "rows": 40, "cols": 120, "bridge_instance_id": bridge}),
            ("trillionnium_job_inspect", {"job_id": "pty-job"}),
            ("trillionnium_job_kill", {"job_id": "pty-job", "operation_id": "pty-kill", "signal": 15, "bridge_instance_id": bridge}),
            ("trillionnium_job_wait", {"job_id": "pty-job"}),
        ]
        records: list[dict] = []
        sequence = 0
        for index, (name, arguments) in enumerate(calls, start=1):
            request = {
                "jsonrpc": "2.0",
                "id": index,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
            records.append(trace_frame(sequence, "client_to_server", request))
            sequence += 1
            structured = (
                {"bridge_instance_id": bridge, "automatic_redispatch": False}
                if index == 1
                else {"automatic_redispatch": False}
            )
            response = {
                "jsonrpc": "2.0",
                "id": index,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(structured)}],
                    "structuredContent": structured,
                    "isError": False,
                },
            }
            records.append(trace_frame(sequence, "server_to_client", response))
            sequence += 1
        trace = self.root / "qualification-trace.jsonl"
        trace.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in records))
        result = qualifier.validate_trace(trace)
        self.assertEqual(result["tool_calls"], 11)
        self.assertEqual(result["validated_tools"], qualifier.EXPECTED_TOOLS)

        records[14]["message"]["params"]["arguments"]["cols"] = 121
        raw = canonical(records[14]["message"])
        records[14]["raw_line_base64"] = base64.b64encode(raw).decode("ascii")
        records[14]["byte_count"] = len(raw)
        records[14]["sha256"] = hashlib.sha256(raw).hexdigest()
        trace.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in records))
        with self.assertRaisesRegex(qualifier.QualificationError, "resize dimensions"):
            qualifier.validate_trace(trace)

    def test_bounded_run_terminates_a_timed_out_process_group(self) -> None:
        sleeper = self.root / "sleeper.py"
        marker = self.root / "child-pid"
        sleeper.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, subprocess, time\n"
            f"child=subprocess.Popen(['sleep','60']); pathlib.Path({str(marker)!r}).write_text(str(child.pid)); time.sleep(60)\n",
            encoding="utf-8",
        )
        sleeper.chmod(0o700)
        started = time.monotonic()
        with self.assertRaisesRegex(qualifier.QualificationError, "timed out"):
            qualifier.bounded_run(
                [str(sleeper)],
                environment=os.environ.copy(),
                timeout=0.2,
            )
        self.assertLess(time.monotonic() - started, 4)
        if marker.exists():
            pid = int(marker.read_text())
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.02)
            else:
                self.fail("timed-out process descendant survived process-group cleanup")

    def test_codex_event_validation_requires_completion_and_marker(self) -> None:
        good = (
            json.dumps({"type": "item.completed", "text": qualifier.FINAL_MARKER})
            + "\n"
            + json.dumps({"type": "turn.completed"})
            + "\n"
        ).encode()
        self.assertTrue(qualifier.validate_codex_events(good)["completed"])
        with self.assertRaises(qualifier.QualificationError):
            qualifier.validate_codex_events(b'{"type":"turn.completed"}\n')


if __name__ == "__main__":
    unittest.main()
