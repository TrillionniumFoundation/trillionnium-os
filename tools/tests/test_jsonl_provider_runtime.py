#!/usr/bin/env python3
"""Integration tests for the provider-neutral duplex JSONL runtime."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import textwrap
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNTIME_PATH = ROOT / "tools/owner-open/jsonl_provider_runtime.py"
SPEC = importlib.util.spec_from_file_location("owner_open_jsonl_provider_runtime", RUNTIME_PATH)
assert SPEC and SPEC.loader
RUNTIME = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNTIME)


class JsonlProviderRuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.provider = self.root / "provider"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_provider(self, source: str) -> None:
        self.provider.write_text(
            "#!/usr/bin/env python3\n" + textwrap.dedent(source),
            encoding="utf-8",
        )
        self.provider.chmod(0o700)

    def test_duplex_fixture_continues_after_success_and_deliberate_failure(self) -> None:
        self.write_provider(
            r'''
import json
import os
import sys
import time

prompt = sys.argv[1]
print(json.dumps({"type": "provider.start", "prompt": prompt}), flush=True)
os.write(1, b'{"type":"tool')
time.sleep(0.02)
os.write(1, b'.call","call_id":"call-ok","tool":"shell.exec","argv":["/bin/pwd"]}\n')
first = json.loads(sys.stdin.buffer.readline())
print(json.dumps({"type": "provider.continued", "after": first}), flush=True)
print(json.dumps({"type": "tool.call", "call_id": "call-fail", "tool": "shell.exec", "command": "exit 7"}), flush=True)
second = json.loads(sys.stdin.buffer.readline())
print(json.dumps({"type": "provider.continued_after_failure", "after": second}), flush=True)
print(json.dumps({"type": "provider.final", "text": "complete"}), flush=True)
'''
        )
        events: list[object] = []
        handled: list[str] = []

        def handler(event):
            if event.value.get("type") != "tool.call":
                return None
            call_id = event.value["call_id"]
            handled.append(call_id)
            if call_id == "call-ok":
                response = {
                    "type": "tool.result",
                    "call_id": call_id,
                    "terminal": "exited",
                    "exit_code": 0,
                    "stdout": "/workspace\n",
                }
            else:
                response = {
                    "type": "tool.result",
                    "call_id": call_id,
                    "terminal": "exited",
                    "exit_code": 7,
                    "stderr": "deliberate failure",
                }
            return json.dumps(response, sort_keys=True).encode() + b"\n"

        terminal = RUNTIME.run_provider(
            [str(self.provider), "exact prompt with spaces"],
            event_handler=handler,
            event_sink=events.append,
            limits=RUNTIME.ProcessLimits(timeout_seconds=5),
        )

        self.assertTrue(terminal.success, terminal)
        self.assertEqual(handled, ["call-ok", "call-fail"])
        self.assertEqual(terminal.event_count, 6)
        self.assertEqual([event.seq for event in events], list(range(6)))
        self.assertEqual(events[0].value["type"], "provider.start")
        self.assertEqual(events[0].value["prompt"], "exact prompt with spaces")
        self.assertEqual(events[1].value["call_id"], "call-ok")
        self.assertEqual(events[2].value["after"]["exit_code"], 0)
        self.assertEqual(events[3].value["call_id"], "call-fail")
        self.assertEqual(events[4].value["after"]["exit_code"], 7)
        self.assertEqual(events[5].value, {"type": "provider.final", "text": "complete"})
        self.assertGreater(terminal.outbound_bytes, 0)
        self.assertEqual(terminal.stderr, b"")

    def test_unknown_events_and_nested_unknown_fields_are_preserved(self) -> None:
        self.write_provider(
            r'''
import json
print(json.dumps({"type": "future.event", "extension": {"a": [1, 2, {"x": True}]}}), flush=True)
'''
        )
        events = []
        terminal = RUNTIME.run_provider(
            [str(self.provider)],
            event_sink=events.append,
            limits=RUNTIME.ProcessLimits(timeout_seconds=2),
        )
        self.assertTrue(terminal.success)
        self.assertEqual(
            events[0].value,
            {"type": "future.event", "extension": {"a": [1, 2, {"x": True}]}},
        )

    def test_duplicate_members_malformed_and_truncated_records_are_protocol_errors(self) -> None:
        for output, expected in (
            (b'{"type":"one","type":"two"}\n', "duplicate key"),
            (b'{not json}\n', "invalid provider JSONL record"),
            (b'{"type":"truncated"}', "truncated_jsonl_record"),
            (b'[]\n', "must be an object"),
        ):
            self.write_provider(
                f'''
import os
os.write(1, {output!r})
'''
            )
            terminal = RUNTIME.run_provider(
                [str(self.provider)],
                limits=RUNTIME.ProcessLimits(timeout_seconds=2),
            )
            self.assertEqual(terminal.kind, "provider_protocol_error", terminal)
            self.assertIn(expected, terminal.error or "")

    def test_nonzero_exit_and_stderr_are_honest_terminal_observations(self) -> None:
        self.write_provider(
            r'''
import json
import sys
print(json.dumps({"type": "provider.notice", "value": "before exit"}), flush=True)
print("raw provider stderr", file=sys.stderr, flush=True)
raise SystemExit(9)
'''
        )
        events = []
        terminal = RUNTIME.run_provider(
            [str(self.provider)],
            event_sink=events.append,
            limits=RUNTIME.ProcessLimits(timeout_seconds=2),
        )
        self.assertEqual(terminal.kind, "exited")
        self.assertEqual(terminal.exit_code, 9)
        self.assertFalse(terminal.success)
        self.assertEqual(events[0].value["type"], "provider.notice")
        self.assertEqual(terminal.stderr, b"raw provider stderr\n")

    def test_timeout_closes_provider_process_group_and_forked_descendant(self) -> None:
        pid_file = self.root / "descendant.pid"
        self.write_provider(
            r'''
import subprocess
import sys
import time
child = subprocess.Popen(["sleep", "30"])
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    handle.write(str(child.pid))
    handle.flush()
time.sleep(30)
'''
        )
        terminal = RUNTIME.run_provider(
            [str(self.provider), str(pid_file)],
            limits=RUNTIME.ProcessLimits(
                timeout_seconds=0.5,
                terminate_grace_seconds=0.05,
            ),
        )
        self.assertEqual(terminal.kind, "timed_out", terminal)
        descendant = int(pid_file.read_text(encoding="utf-8"))
        deadline = time.monotonic() + 2
        while True:
            try:
                os.kill(descendant, 0)
            except ProcessLookupError:
                break
            self.assertLess(
                time.monotonic(),
                deadline,
                f"provider descendant {descendant} survived process-group cleanup",
            )
            time.sleep(0.01)

    def test_event_sink_can_cancel_after_one_observed_event(self) -> None:
        self.write_provider(
            r'''
import json
import time
print(json.dumps({"type": "provider.start"}), flush=True)
time.sleep(30)
'''
        )
        cancellation = RUNTIME.CancellationToken()
        events = []

        def sink(event):
            events.append(event)
            cancellation.cancel()

        terminal = RUNTIME.run_provider(
            [str(self.provider)],
            event_sink=sink,
            cancellation=cancellation,
            limits=RUNTIME.ProcessLimits(
                timeout_seconds=5,
                terminate_grace_seconds=0.05,
            ),
        )
        self.assertEqual(terminal.kind, "client_cancelled")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].value["type"], "provider.start")

    def test_handler_and_sink_failures_become_bounded_terminal_errors(self) -> None:
        self.write_provider(
            r'''
import json
import time
print(json.dumps({"type": "provider.event"}), flush=True)
time.sleep(30)
'''
        )

        def handler(_event):
            raise RuntimeError("handler exploded")

        terminal = RUNTIME.run_provider(
            [str(self.provider)],
            event_handler=handler,
            limits=RUNTIME.ProcessLimits(timeout_seconds=5),
        )
        self.assertEqual(terminal.kind, "provider_protocol_error")
        self.assertIn("handler exploded", terminal.error or "")

        def sink(_event):
            raise OSError("sink unavailable")

        terminal = RUNTIME.run_provider(
            [str(self.provider)],
            event_sink=sink,
            limits=RUNTIME.ProcessLimits(timeout_seconds=5),
        )
        self.assertEqual(terminal.kind, "io_error")
        self.assertIn("sink unavailable", terminal.error or "")

    def test_line_stdout_stderr_event_and_outbound_limits_fail_mechanically(self) -> None:
        self.write_provider(
            r'''
import os
os.write(1, b'{"type":"large","value":"' + b'x' * 4096 + b'"}\n')
'''
        )
        terminal = RUNTIME.run_provider(
            [str(self.provider)],
            limits=RUNTIME.ProcessLimits(
                max_event_line_bytes=256,
                max_stdout_bytes=8192,
                timeout_seconds=2,
            ),
        )
        self.assertEqual(terminal.kind, "resource_exhausted")
        self.assertIn("record_exceeds", terminal.error or "")

        self.write_provider(
            r'''
import sys
sys.stderr.buffer.write(b'e' * 4096)
sys.stderr.buffer.flush()
'''
        )
        terminal = RUNTIME.run_provider(
            [str(self.provider)],
            limits=RUNTIME.ProcessLimits(max_stderr_bytes=128, timeout_seconds=2),
        )
        self.assertEqual(terminal.kind, "resource_exhausted")
        self.assertEqual(len(terminal.stderr), 128)

        self.write_provider(
            r'''
import json
import time
print(json.dumps({"type": "needs.response"}), flush=True)
time.sleep(30)
'''
        )
        terminal = RUNTIME.run_provider(
            [str(self.provider)],
            event_handler=lambda _event: b"r" * 1024,
            limits=RUNTIME.ProcessLimits(
                max_handler_response_bytes=64,
                timeout_seconds=2,
            ),
        )
        self.assertEqual(terminal.kind, "provider_protocol_error")
        self.assertIn("handler response exceeds", terminal.error or "")

    def test_initial_stdin_policy_and_exact_argv_are_preserved(self) -> None:
        self.write_provider(
            r'''
import json
import sys
payload = sys.stdin.buffer.read()
print(json.dumps({"type": "input", "argv": sys.argv[1:], "payload_hex": payload.hex()}), flush=True)
'''
        )
        events = []
        terminal = RUNTIME.run_provider(
            [str(self.provider), "value with spaces", "$HOME;literal"],
            initial_stdin=b"prompt\x00bytes",
            stdin_policy="close-after-initial",
            event_sink=events.append,
            limits=RUNTIME.ProcessLimits(timeout_seconds=2),
        )
        self.assertTrue(terminal.success)
        self.assertEqual(events[0].value["argv"], ["value with spaces", "$HOME;literal"])
        self.assertEqual(events[0].value["payload_hex"], b"prompt\x00bytes".hex())

    def test_invalid_request_fails_before_spawn(self) -> None:
        with self.assertRaisesRegex(RUNTIME.ProviderRuntimeError, "argv is empty"):
            RUNTIME.run_provider([])
        with self.assertRaisesRegex(RUNTIME.ProviderRuntimeError, "contains NUL"):
            RUNTIME.run_provider(["bad\x00program"])
        with self.assertRaisesRegex(RUNTIME.ProviderRuntimeError, "stdin exceeds"):
            RUNTIME.run_provider(
                [str(self.provider)],
                initial_stdin=b"x" * 10,
                limits=RUNTIME.ProcessLimits(max_initial_stdin_bytes=4),
            )

    def test_strict_decoder_rejects_duplicate_nested_members(self) -> None:
        with self.assertRaisesRegex(RUNTIME.ProviderRuntimeError, "duplicate key x"):
            RUNTIME.decode_strict_event(b'{"type":"event","nested":{"x":1,"x":2}}')


if __name__ == "__main__":
    unittest.main()
