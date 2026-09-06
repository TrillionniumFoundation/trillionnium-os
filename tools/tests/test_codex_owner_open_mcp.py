from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "owner-open" / "codex_owner_open_mcp.py"
spec = importlib.util.spec_from_file_location("codex_owner_open_mcp", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

BRIDGE_ID = "bridge-test"

FAKE_HOST = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

record = Path(os.environ["FAKE_HOST_RECORD"])
terminal = False

def emit(kind, seq, payload, job_id=None):
    frame = {"kind": kind, "seq": seq, "direction": "host_to_client", "payload": payload}
    if job_id:
        frame["job_id"] = job_id
    print(json.dumps(frame, sort_keys=True, separators=(",", ":")), flush=True)

host_seq = 0
for line in sys.stdin:
    value = json.loads(line)
    with record.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, sort_keys=True) + "\n")
    kind = value["kind"]
    payload = value["payload"]
    if kind == "hello":
        emit("hello.ack", host_seq, {"long_running_jobs": True})
    elif kind == "job.start":
        job_id = payload["job_id"]
        emit("job.start.result", host_seq, {"status": "started", "automatic_redispatch": False}, job_id)
        host_seq += 1
        emit("job.started", host_seq, {"pid": 4242, "cursor": 0}, job_id)
    elif kind == "job.write":
        emit("job.control.result", host_seq, {"status": "applied", "operation": kind, "operation_id": payload["operation_id"], "automatic_redispatch": False}, payload["job_id"])
    elif kind == "job.resize":
        emit("job.control.result", host_seq, {"status": "applied", "operation": kind, "operation_id": payload["operation_id"], "automatic_redispatch": False}, payload["job_id"])
    elif kind == "job.close_stdin":
        terminal = True
        emit("job.control.result", host_seq, {"status": "applied", "operation": kind, "operation_id": payload["operation_id"], "automatic_redispatch": False}, payload["job_id"])
        host_seq += 1
        emit("job.result", host_seq, {"terminal_kind": "exited", "exit_code": 0, "cursor": 1}, payload["job_id"])
    elif kind == "job.kill":
        terminal = True
        emit("job.control.result", host_seq, {"status": "applied", "operation": kind, "operation_id": payload["operation_id"], "automatic_redispatch": False}, payload["job_id"])
    elif kind == "job.inspect":
        events = [{"kind": "job.started", "cursor": 0}]
        if terminal:
            events.append({"kind": "job.result", "terminal_kind": "exited", "cursor": 1})
        emit("job.inspect.result", host_seq, {"status": "found", "inspection": {"runtime_events": events, "next_cursor": len(events), "terminal": terminal}, "read_only": True, "automatic_redispatch": False}, payload["job_id"])
    elif kind == "job.attach":
        emit("job.attach.result", host_seq, {"status": "found", "attachment_id": payload["attachment_id"], "read_only": True, "automatic_redispatch": False}, payload["job_id"])
    elif kind == "job.detach":
        emit("job.detach.result", host_seq, {"status": "detached", "attachment_id": payload["attachment_id"], "automatic_redispatch": False}, payload["job_id"])
    else:
        emit("job.error", host_seq, {"message": f"unsupported {kind}"}, payload.get("job_id"))
    host_seq += 1
'''


class CodexOwnerOpenMcpTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.host = root / "fake-host.py"
        self.provider = root / "provider.sh"
        self.job_store = root / "jobs.jsonl"
        self.event_store = root / "events.jsonl"
        self.record = root / "host-input.jsonl"
        self.host.write_text(FAKE_HOST, encoding="utf-8")
        self.provider.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
        self.host.chmod(0o700)
        self.provider.chmod(0o700)
        self.env = os.environ.copy()
        self.env["FAKE_HOST_RECORD"] = str(self.record)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def command(self) -> list[str]:
        return [
            sys.executable,
            str(SCRIPT),
            "--host",
            str(self.host),
            "--provider",
            str(self.provider),
            "--job-store",
            str(self.job_store),
            "--event-store",
            str(self.event_store),
            "--session-id",
            "session-test",
            "--task-id",
            "task-test",
            "--turn-id",
            "turn-test",
            "--turn-stream-id",
            "stream-test",
            "--bridge-instance-id",
            BRIDGE_ID,
        ]

    def request(self, child: subprocess.Popen[str], value: dict) -> dict:
        assert child.stdin is not None and child.stdout is not None
        child.stdin.write(json.dumps(value, separators=(",", ":")) + "\n")
        child.stdin.flush()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            line = child.stdout.readline()
            if not line:
                break
            response = json.loads(line)
            if response.get("id") == value.get("id"):
                return response
        self.fail(f"no response for {value}")

    def close_child(self, child: subprocess.Popen[str]) -> None:
        if child.stdin:
            child.stdin.close()
        child.wait(timeout=5)
        if child.stdout:
            child.stdout.close()
        if child.stderr:
            child.stderr.close()

    def test_stdio_mcp_exposes_connection_and_drives_job_tools(self) -> None:
        child = subprocess.Popen(
            self.command(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=self.env,
        )
        try:
            initialize = self.request(
                child,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "fixture", "version": "1"},
                    },
                },
            )
            self.assertEqual(
                initialize["result"]["protocolVersion"], "2025-06-18"
            )
            self.assertIn(BRIDGE_ID, initialize["result"]["instructions"])
            tools = self.request(
                child,
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "params": {},
                },
            )
            names = {item["name"] for item in tools["result"]["tools"]}
            self.assertIn("trillionnium_connection_info", names)
            self.assertIn("trillionnium_job_start", names)
            self.assertIn("trillionnium_job_wait", names)

            connection = self.request(
                child,
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "trillionnium_connection_info",
                        "arguments": {},
                    },
                },
            )
            self.assertEqual(
                connection["result"]["structuredContent"]["bridge_instance_id"],
                BRIDGE_ID,
            )
            self.assertFalse(
                connection["result"]["structuredContent"]["connection_model"]
                ["cross_process_live_descriptor_control"]
            )

            start = self.request(
                child,
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "trillionnium_job_start",
                        "arguments": {
                            "job_id": "job-one",
                            "bridge_instance_id": BRIDGE_ID,
                            "operation_id": "start-one",
                            "mode": "pipe",
                            "command": "cat",
                        },
                    },
                },
            )
            self.assertFalse(start["result"]["isError"])
            structured = start["result"]["structuredContent"]
            self.assertEqual(structured["scope"]["session_id"], "session-test")
            self.assertEqual(structured["bridge_instance_id"], BRIDGE_ID)
            self.assertEqual(structured["response"]["kind"], "job.start.result")

            write = self.request(
                child,
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": "trillionnium_job_write",
                        "arguments": {
                            "job_id": "job-one",
                            "bridge_instance_id": BRIDGE_ID,
                            "operation_id": "write-one",
                            "data": {
                                "encoding": "base64",
                                "data": "aGVsbG8K",
                            },
                        },
                    },
                },
            )
            self.assertEqual(
                write["result"]["structuredContent"]["response"]["kind"],
                "job.control.result",
            )

            close = self.request(
                child,
                {
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {
                        "name": "trillionnium_job_close_stdin",
                        "arguments": {
                            "job_id": "job-one",
                            "bridge_instance_id": BRIDGE_ID,
                            "operation_id": "close-one",
                        },
                    },
                },
            )
            self.assertFalse(close["result"]["isError"])

            wait = self.request(
                child,
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {
                        "name": "trillionnium_job_wait",
                        "arguments": {
                            "job_id": "job-one",
                            "timeout_seconds": 1,
                            "poll_interval_ms": 10,
                        },
                    },
                },
            )
            self.assertEqual(
                wait["result"]["structuredContent"]["wait_status"],
                "terminal_observed",
            )
        finally:
            self.close_child(child)

        requests = [
            json.loads(line)
            for line in self.record.read_text(encoding="utf-8").splitlines()
        ]
        start_frame = next(item for item in requests if item["kind"] == "job.start")
        self.assertEqual(start_frame["payload"]["turn_stream_id"], "stream-test")
        self.assertEqual(start_frame["payload"]["tool"], "shell.job")
        self.assertEqual(start_frame["payload"]["operation_id"], "start-one")
        self.assertNotIn("bridge_instance_id", start_frame["payload"])
        self.assertNotIn("approval", start_frame["payload"])

    def test_tool_annotations_and_schemas_distinguish_connection_boundary(self) -> None:
        tools = {item["name"]: item for item in module.TOOLS}
        self.assertTrue(
            tools["trillionnium_connection_info"]["annotations"]["readOnlyHint"]
        )
        self.assertTrue(
            tools["trillionnium_job_inspect"]["annotations"]["readOnlyHint"]
        )
        self.assertTrue(
            tools["trillionnium_job_wait"]["annotations"]["readOnlyHint"]
        )
        self.assertFalse(
            tools["trillionnium_job_attach"]["annotations"]["readOnlyHint"]
        )
        self.assertFalse(
            tools["trillionnium_job_attach"]["annotations"]["destructiveHint"]
        )
        self.assertTrue(
            tools["trillionnium_job_start"]["annotations"]["destructiveHint"]
        )
        self.assertTrue(
            tools["trillionnium_job_start"]["annotations"]["openWorldHint"]
        )
        self.assertFalse(
            tools["trillionnium_job_resize"]["annotations"]["destructiveHint"]
        )
        self.assertTrue(
            tools["trillionnium_job_resize"]["annotations"]["openWorldHint"]
        )
        self.assertFalse(
            tools["trillionnium_job_inspect"]["annotations"]["openWorldHint"]
        )
        self.assertIn(
            "bridge_instance_id",
            tools["trillionnium_job_start"]["inputSchema"]["required"],
        )
        self.assertNotIn(
            "bridge_instance_id",
            tools["trillionnium_job_inspect"]["inputSchema"]["required"],
        )

    def test_duplicate_json_and_invalid_effect_arguments_fail_mechanically(self) -> None:
        child = subprocess.Popen(
            self.command(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=self.env,
        )
        try:
            assert child.stdin is not None and child.stdout is not None
            child.stdin.write(
                '{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}\n'
            )
            child.stdin.flush()
            parse_error = json.loads(child.stdout.readline())
            self.assertEqual(parse_error["error"]["code"], -32700)

            invalid = self.request(
                child,
                {
                    "jsonrpc": "2.0",
                    "id": 9,
                    "method": "tools/call",
                    "params": {
                        "name": "trillionnium_job_start",
                        "arguments": {
                            "job_id": "job-two",
                            "bridge_instance_id": BRIDGE_ID,
                            "operation_id": "start-two",
                            "mode": "pipe",
                            "command": "pwd",
                            "argv": ["pwd"],
                        },
                    },
                },
            )
            self.assertEqual(invalid["error"]["code"], -32602)
        finally:
            self.close_child(child)

    def test_mismatched_bridge_identity_fails_before_host_dispatch(self) -> None:
        child = subprocess.Popen(
            self.command(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=self.env,
        )
        try:
            response = self.request(
                child,
                {
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": "tools/call",
                    "params": {
                        "name": "trillionnium_job_start",
                        "arguments": {
                            "job_id": "job-wrong-connection",
                            "bridge_instance_id": "another-bridge",
                            "operation_id": "start-wrong",
                            "mode": "pipe",
                            "command": "pwd",
                        },
                    },
                },
            )
            self.assertEqual(response["error"]["code"], -32602)
            self.assertIn("does not match", response["error"]["message"])
        finally:
            self.close_child(child)
        requests = [
            json.loads(line)
            for line in self.record.read_text(encoding="utf-8").splitlines()
        ]
        self.assertFalse(
            any(item.get("kind") == "job.start" for item in requests),
            "a mismatched live connection must fail before Host dispatch",
        )

    def test_exact_duplicate_host_control_result_is_returned_without_server_retry(self) -> None:
        scope = module.Scope("session", "owner-open", "task", "turn", "stream")
        host_argv = [
            str(self.host),
            "--provider",
            str(self.provider),
            "--job-store",
            str(self.job_store),
        ]
        old = os.environ.get("FAKE_HOST_RECORD")
        os.environ["FAKE_HOST_RECORD"] = str(self.record)
        try:
            host = module.HostClient(
                host_argv,
                startup_timeout=2,
                request_timeout=2,
            )
            bridge = module.JobBridge(host, scope, BRIDGE_ID)
            arguments = {
                "job_id": "job-three",
                "bridge_instance_id": BRIDGE_ID,
                "operation_id": "start-three",
                "mode": "pipe",
                "command": "sleep 1",
            }
            first = bridge.call(
                "trillionnium_job_start",
                arguments,
                module.threading.Event(),
            )
            second = bridge.call(
                "trillionnium_job_start",
                arguments,
                module.threading.Event(),
            )
            self.assertEqual(first["response"]["kind"], "job.start.result")
            self.assertEqual(second["response"]["kind"], "job.start.result")
            host.close()
            requests = [
                json.loads(line)
                for line in self.record.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(
                sum(item.get("kind") == "job.start" for item in requests),
                2,
                "the bridge must not add a hidden third retry",
            )
        finally:
            if old is None:
                os.environ.pop("FAKE_HOST_RECORD", None)
            else:
                os.environ["FAKE_HOST_RECORD"] = old


if __name__ == "__main__":
    unittest.main()
