#!/usr/bin/env python3
"""Integration tests for the provider-neutral duplex JSONL runtime."""

from __future__ import annotations

import ctypes
from dataclasses import fields, replace
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
RUNTIME_PATH = ROOT / "tools/owner-open/jsonl_provider_runtime.py"
SPEC = importlib.util.spec_from_file_location("owner_open_jsonl_provider_runtime", RUNTIME_PATH)
assert SPEC and SPEC.loader
RUNTIME = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNTIME
SPEC.loader.exec_module(RUNTIME)


class JsonlProviderRuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.provider = self.root / "provider"
        self.old_subreaper = ctypes.c_int()
        self.libc = ctypes.CDLL(None, use_errno=True)
        if sys.platform == "linux":
            self.assertEqual(self.libc.prctl(37, ctypes.byref(self.old_subreaper), 0, 0, 0), 0)
            self.assertEqual(self.libc.prctl(36, 1, 0, 0, 0), 0)

    def tearDown(self) -> None:
        try:
            marker = self.root / "descendant.pid"
            if marker.exists():
                pid = int(marker.read_text())
                try:
                    os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                except ChildProcessError:
                    pass
                else:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
        finally:
            if sys.platform == "linux":
                self.libc.prctl(36, self.old_subreaper.value, 0, 0, 0)
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
print('{"ready":true}',flush=True)
time.sleep(30)
'''
        )
        # Expire the deadline only after a real child-readiness record. This
        # avoids silently testing interpreter startup rather than descendants.
        expired = [False]
        real_clock = time.monotonic
        with mock.patch.object(RUNTIME.time, "monotonic", side_effect=lambda: real_clock() + (10 if expired[0] else 0)):
            terminal = RUNTIME.run_provider(
                [str(self.provider), str(pid_file)],
                event_sink=lambda event: expired.__setitem__(0, True),
                limits=RUNTIME.ProcessLimits(timeout_seconds=5, terminate_grace_seconds=0.05),
            )
        self.assertTrue(expired[0], "provider must actually create its descendant")
        self.assertEqual(terminal.kind, "timed_out", terminal)
        descendant = int(pid_file.read_text(encoding="utf-8"))
        deadline = time.monotonic() + 2
        while True:
            # Reap only this fixture's adopted descendant, not unrelated children.
            try:
                waited, _ = os.waitpid(descendant, os.WNOHANG)
                if waited == descendant:
                    break
            except ChildProcessError:
                pass
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



@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "WNOWAIT"), "Linux waitable process groups")
class ProviderRetirementTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.provider = self.root / "provider.py"
        self.descendant = self.root / "descendant.pid"
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.old_subreaper = ctypes.c_int()
        self.assertEqual(self.libc.prctl(37, ctypes.byref(self.old_subreaper), 0, 0, 0), 0)
        self.assertEqual(self.libc.prctl(36, 1, 0, 0, 0), 0)
        self.addCleanup(self.restore_subreaper)

    def restore_subreaper(self):
        # Only reap this test's known adopted child; never wait on unrelated PIDs.
        try:
            if self.descendant.exists():
                pid = int(self.descendant.read_text())
                try:
                    os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                except ChildProcessError:
                    return
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                deadline = time.monotonic() + 2
                while os.waitpid(pid, os.WNOHANG)[0] == 0:
                    if time.monotonic() >= deadline:
                        raise AssertionError("test descendant did not exit")
                    time.sleep(0.005)
        finally:
            self.libc.prctl(36, self.old_subreaper.value, 0, 0, 0)

    def run_source(self, source, **kwargs):
        self.provider.write_text(source)
        kwargs.setdefault("limits", RUNTIME.ProcessLimits(timeout_seconds=2, terminate_grace_seconds=0.02))
        return RUNTIME.run_provider([sys.executable, str(self.provider)], **kwargs)

    @staticmethod
    def live(pid):
        try:
            return Path(f"/proc/{pid}/stat").read_bytes().rsplit(b")", 1)[1].split()[0] not in (b"Z", b"X")
        except FileNotFoundError:
            return False

    def fork_source(self, *, exit_leader=True, close_pipes=True, escape=False):
        return (
            "import os,signal,time\n"
            "r,w=os.pipe()\n"
            "pid=os.fork()\n"
            "if pid == 0:\n"
            " os.close(r)\n"
            + (" os.setsid()\n" if escape else "")
            + " signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            + (" os.close(0);os.close(1);os.close(2)\n" if close_pipes else "")
            + f" with open({str(self.descendant)!r},'w') as f: f.write(str(os.getpid()))\n"
            " os.write(w,b'R');os.close(w)\n"
            " while True: time.sleep(1)\n"
            "os.close(w)\n"
            "assert os.read(r,1)==b'R'\n"
            "os.close(r)\n"
            + ("os._exit(0)\n" if exit_leader else "while True: time.sleep(1)\n")
        )

    def test_normal_leader_exit_still_retires_term_resistant_child(self):
        terminal = self.run_source(self.fork_source())
        self.assertTrue(self.descendant.exists())
        self.assertFalse(self.live(int(self.descendant.read_text())), terminal)
        self.assertTrue(terminal.success, terminal)

    def test_sink_cancellation_blocks_handler_and_same_batch_callbacks(self):
        token, events, handled = RUNTIME.CancellationToken(), [], []
        def sink(event):
            events.append(event)
            token.cancel()
        terminal = self.run_source(
            'import os,time\nos.write(1,b\'{"a":1}\\n{"a":2}\\n\')\ntime.sleep(1)\n',
            cancellation=token, event_sink=sink, event_handler=lambda e: handled.append(e),
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(handled, [])
        self.assertEqual(terminal.kind, "client_cancelled")

    def test_precancelled_request_does_not_spawn(self):
        token = RUNTIME.CancellationToken()
        token.cancel()
        with mock.patch.object(RUNTIME.subprocess, "Popen") as spawn:
            terminal = RUNTIME.run_provider([sys.executable], cancellation=token)
            spawn.assert_not_called()
        self.assertEqual(terminal.kind, "client_cancelled")

    def test_nonfinite_duration_is_rejected(self):
        for value in (float('nan'), float('inf'), -float('inf')):
            with self.subTest(value=value), self.assertRaises(RUNTIME.ProviderRuntimeError):
                RUNTIME.ProcessLimits(timeout_seconds=value).validate()

    def test_noninteger_byte_budget_is_rejected(self):
        for value in (True, 1.5, float('nan'), '32'):
            with self.subTest(value=value), self.assertRaises(RUNTIME.ProviderRuntimeError):
                RUNTIME.ProcessLimits(max_event_count=value).validate()

    def test_nonfinite_json_numbers_are_rejected(self):
        for number in (b'NaN', b'Infinity', b'-Infinity', b'1e9999'):
            with self.subTest(number=number), self.assertRaises(RUNTIME.ProviderRuntimeError):
                RUNTIME.decode_strict_event(b'{"number":'+number+b'}')


    def test_descendant_holding_pipes_does_not_hold_retirement_open(self):
        terminal = self.run_source(self.fork_source(close_pipes=False))
        self.assertTrue(terminal.success, terminal)
        self.assertTrue(terminal.cleanup_confirmed)
        self.assertFalse(self.live(int(self.descendant.read_text())))

    def test_escaped_pipe_writer_has_finite_drain_and_is_not_claimed_clean(self):
        terminal = self.run_source(self.fork_source(close_pipes=False, escape=True),
            limits=RUNTIME.ProcessLimits(timeout_seconds=3, terminate_grace_seconds=0.02, drain_seconds=0.05))
        self.assertEqual(terminal.kind, "io_error", terminal)
        self.assertIn("drain_deadline", terminal.error)
        self.assertFalse(terminal.success)
        self.assertTrue(self.live(int(self.descendant.read_text())))

    def test_handler_cancellation_drops_response_and_next_event(self):
        token, handled = RUNTIME.CancellationToken(), []
        def handler(event):
            handled.append(event)
            token.cancel()
            return b'must not send\n'
        terminal = self.run_source('import os,time\nos.write(1,b\'{"a":1}\\n{"a":2}\\n\')\ntime.sleep(1)\n',
                                   cancellation=token, event_handler=handler)
        self.assertEqual(len(handled), 1)
        self.assertEqual(terminal.outbound_bytes, 0)
        self.assertEqual(terminal.kind, "client_cancelled")

    def test_protocol_failure_fences_later_valid_callbacks(self):
        events = []
        terminal = self.run_source('import os,time\nos.write(1,b\'{bad}\\n{"a":2}\\n\')\ntime.sleep(1)\n',
                                   event_handler=events.append)
        self.assertEqual(events, [])
        self.assertEqual(terminal.kind, "provider_protocol_error")
        self.assertTrue(terminal.leader_reaped)

    def test_sink_failure_fences_handler_and_later_callbacks(self):
        handled = []
        def sink(event):
            raise OSError('sink refused')
        terminal = self.run_source('import os,time\nos.write(1,b\'{"a":1}\\n{"a":2}\\n\')\ntime.sleep(1)\n',
                                   event_sink=sink, event_handler=handled.append)
        self.assertEqual(handled, [])
        self.assertEqual(terminal.event_count, 1)
        self.assertEqual(terminal.kind, "io_error")

    def test_handler_timeout_fences_its_response(self):
        real_clock, expired, handled = time.monotonic, [False], []
        def handler(event):
            handled.append(event)
            expired[0] = True
            return b'late response\n'
        with mock.patch.object(RUNTIME.time, 'monotonic', side_effect=lambda: real_clock() + (10 if expired[0] else 0)):
            terminal = self.run_source('import time\nprint("{}",flush=True)\ntime.sleep(30)\n', event_handler=handler)
        self.assertEqual(len(handled), 1)
        self.assertEqual(terminal.kind, 'timed_out')
        self.assertEqual(terminal.outbound_bytes, 0)

    def test_set_blocking_failure_is_reaped_and_returned(self):
        with mock.patch.object(RUNTIME.os, 'set_blocking', side_effect=OSError('setup failure')):
            terminal = self.run_source('import time\ntime.sleep(30)\n')
        self.assertEqual(terminal.kind, 'io_error')
        self.assertIn('setup failure', terminal.error)
        self.assertTrue(terminal.leader_reaped)

    def test_selector_creation_failure_is_reaped_and_returned(self):
        with mock.patch.object(RUNTIME.selectors, 'DefaultSelector', side_effect=OSError('selector failure')):
            terminal = self.run_source('import time\ntime.sleep(30)\n')
        self.assertEqual(terminal.kind, 'io_error')
        self.assertTrue(terminal.leader_reaped)

    def test_selector_registration_failure_closes_all_pipes(self):
        selector = RUNTIME.selectors.DefaultSelector()
        real_spawn, children = RUNTIME.subprocess.Popen, []
        def spawn(*args, **kwargs):
            child = real_spawn(*args, **kwargs)
            children.append(child)
            return child
        with mock.patch.object(RUNTIME.subprocess, 'Popen', side_effect=spawn), \
                mock.patch.object(RUNTIME.selectors, 'DefaultSelector', return_value=selector), \
                mock.patch.object(selector, 'register', side_effect=OSError('register failure')):
            terminal = self.run_source('import time\ntime.sleep(30)\n')
        self.assertEqual(terminal.kind, 'io_error')
        self.assertTrue(terminal.leader_reaped)
        self.assertTrue(all(p.closed for p in (children[0].stdin, children[0].stdout, children[0].stderr)))

    def test_selector_readiness_failure_still_retires(self):
        selector = RUNTIME.selectors.DefaultSelector()
        with mock.patch.object(RUNTIME.selectors, 'DefaultSelector', return_value=selector), \
                mock.patch.object(selector, 'select', side_effect=OSError('select failure')):
            terminal = self.run_source('import time\ntime.sleep(30)\n')
        self.assertEqual(terminal.kind, 'io_error')
        self.assertTrue(terminal.leader_reaped)

    def test_missing_procfs_confirmation_is_not_success(self):
        with mock.patch.object(RUNTIME, '_group_quiet', side_effect=OSError('no complete procfs')):
            terminal = self.run_source('print("{}",flush=True)\n')
        self.assertEqual(terminal.kind, 'io_error')
        self.assertFalse(terminal.cleanup_confirmed)
        self.assertTrue(terminal.leader_reaped)

    def test_reaped_anchor_is_never_signalled(self):
        process = mock.Mock(returncode=0, pid=123456)
        with mock.patch.object(RUNTIME.os, 'killpg') as kill:
            result = RUNTIME._retire_group(process, RUNTIME.ProcessLimits())
        kill.assert_not_called()
        self.assertFalse(result[2])
        self.assertIn('anchor', result[-1])

    def test_sigterm_failure_does_not_skip_sigkill(self):
        real_kill, signals = RUNTIME.os.killpg, []
        def kill(pid, sig):
            signals.append(sig)
            if sig == signal.SIGTERM:
                raise PermissionError('TERM denied')
            return real_kill(pid, sig)
        with mock.patch.object(RUNTIME.os, 'killpg', side_effect=kill):
            terminal = self.run_source('print("{}",flush=True)\n')
        self.assertIn(signal.SIGKILL, signals)
        self.assertFalse(terminal.cleanup_confirmed)
        self.assertTrue(terminal.leader_reaped)

    def test_zero_progress_stdin_is_terminal_error(self):
        with mock.patch.object(RUNTIME.os, 'write', return_value=0):
            terminal = self.run_source('import sys\nsys.stdin.buffer.read()\n', initial_stdin=b'test')
        self.assertEqual(terminal.kind, 'io_error')
        self.assertIn('no valid progress', terminal.error)
        self.assertTrue(terminal.leader_reaped)

    def test_short_stdin_write_preserves_exact_bytes(self):
        real_write, events = RUNTIME.os.write, []
        with mock.patch.object(RUNTIME.os, 'write', side_effect=lambda fd, b: real_write(fd, b[:3])):
            terminal = self.run_source('import sys,json\nb=sys.stdin.buffer.read()\nprint(json.dumps({"hex":b.hex()}),flush=True)\n',
                initial_stdin=b'123\x00' * 9, stdin_policy='close-after-initial', event_sink=events.append)
        self.assertTrue(terminal.success, terminal)
        self.assertEqual(events[0].value['hex'], (b'123\x00' * 9).hex())

    def test_initial_input_is_also_bounded_by_total_outbound(self):
        with mock.patch.object(RUNTIME.subprocess, 'Popen') as spawn, self.assertRaises(RUNTIME.ProviderRuntimeError):
            RUNTIME.run_provider([sys.executable], initial_stdin=b'12', limits=RUNTIME.ProcessLimits(max_outbound_bytes=1))
        spawn.assert_not_called()

    def test_mutable_or_nonbyte_initial_input_is_rejected(self):
        for value in ('str', bytearray(b'x'), 12):
            with self.subTest(value=value), mock.patch.object(RUNTIME.subprocess, 'Popen') as spawn, self.assertRaises(RUNTIME.ProviderRuntimeError):
                RUNTIME.run_provider([sys.executable], initial_stdin=value)
            spawn.assert_not_called()

    def test_argv_type_and_invalid_utf8_are_rejected(self):
        for value in ('/bin/sh', (sys.executable,), [5], ['\ud800']):
            with self.subTest(value=value), self.assertRaises(RUNTIME.ProviderRuntimeError):
                RUNTIME.run_provider(value)

    def test_unsupported_reaper_mode_rejects_before_spawn(self):
        with mock.patch.object(RUNTIME.signal, 'getsignal', return_value=signal.SIG_IGN), \
                mock.patch.object(RUNTIME.subprocess, 'Popen') as spawn, self.assertRaises(RUNTIME.ProviderRuntimeError):
            RUNTIME.run_provider([sys.executable])
        spawn.assert_not_called()

    def test_missing_waitid_rejects_before_spawn(self):
        with mock.patch.object(RUNTIME.os, 'waitid', None), mock.patch.object(RUNTIME.subprocess, 'Popen') as spawn, self.assertRaises(RUNTIME.ProviderRuntimeError):
            RUNTIME.run_provider([sys.executable])
        spawn.assert_not_called()

    def test_depth_is_checked_before_recursive_decoder(self):
        with mock.patch.object(RUNTIME.json, 'loads') as loads, self.assertRaises(RUNTIME.ProviderRuntimeError):
            RUNTIME.decode_strict_event(b'{"x":' + b'[' * 64 + b'0' + b']' * 64 + b'}')
        loads.assert_not_called()

    def test_brackets_and_escaped_quotes_in_json_strings_are_not_nesting(self):
        value = {'x':'[' * 200 + '\\"' + ']' * 200, 'nested':{'valid':True}}
        self.assertEqual(RUNTIME.decode_strict_event(json.dumps(value).encode()), value)

    def test_all_count_limits_reject_boolean_fraction_and_extreme(self):
        for field in fields(RUNTIME.ProcessLimits):
            if field.name.endswith('_seconds'):
                continue
            for value in (True, 0, 0.5, 2**32):
                with self.subTest(field=field.name, value=value), self.assertRaises(RUNTIME.ProviderRuntimeError):
                    replace(RUNTIME.ProcessLimits(), **{field.name:value}).validate()

    def test_all_time_limits_reject_nonfinite_and_boolean(self):
        for field in fields(RUNTIME.ProcessLimits):
            if not field.name.endswith('_seconds'):
                continue
            for value in (True, float('nan'), float('inf'), 10**100):
                with self.subTest(field=field.name, value=value), self.assertRaises(RUNTIME.ProviderRuntimeError):
                    replace(RUNTIME.ProcessLimits(), **{field.name:value}).validate()

    def test_errors_have_a_fixed_retention_bound(self):
        self.assertLessEqual(len(RUNTIME._join_error('x'*5000, 'y'*5000)), 4096)

    def test_success_requires_cleanup_and_reaping(self):
        terminal = RUNTIME.ProviderTerminal('exited', 0, None, 0, 0, b'', 0, 0, None)
        self.assertFalse(terminal.success)
        self.assertFalse(replace(terminal, cleanup_confirmed=True).success)
        self.assertTrue(replace(terminal, cleanup_confirmed=True, leader_reaped=True).success)

    def test_keyboard_interrupt_in_callback_still_reaps(self):
        real_spawn, children = RUNTIME.subprocess.Popen, []
        def spawn(*args, **kwargs):
            child = real_spawn(*args, **kwargs)
            children.append(child)
            return child
        def sink(event):
            raise KeyboardInterrupt('test interruption')
        with mock.patch.object(RUNTIME.subprocess, 'Popen', side_effect=spawn), self.assertRaises(KeyboardInterrupt):
            self.run_source('import time\nprint("{}",flush=True)\ntime.sleep(30)\n', event_sink=sink)
        self.assertIsNotNone(children[0].returncode)
        self.assertTrue(children[0].stdout.closed)


if __name__ == "__main__":
    unittest.main()
