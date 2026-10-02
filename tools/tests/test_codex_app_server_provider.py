#!/usr/bin/env python3
"""Source-only bridge fixtures; no real Codex, authentication or Android evidence."""
from __future__ import annotations

import copy
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "owner_open_codex_app_server_provider", ROOT / "crates/trillionnium-owner-open-provider-jsonl/python/codex_app_server_provider.py")
assert SPEC and SPEC.loader
PROVIDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROVIDER)

SCOPE = {key: key + "-fixture" for key in PROVIDER.SCOPE_FIELDS}
TURN = {**SCOPE, "user_input": "  原样\n$(printf untouched); \"quoted\"  "}


def event(value):
    return PROVIDER.ProviderEvent(0, json.dumps(value).encode("utf-8"), value, 0)


class FakeSession:
    def __init__(self, thread_id=None):
        self.thread_id = thread_id
        self.bindings = []

    def bind(self, thread_id):
        if self.thread_id is not None and self.thread_id != thread_id:
            raise PROVIDER.ProviderRuntimeError("native resumed thread identity changed")
        self.thread_id = thread_id
        self.bindings.append(thread_id)


class FakeHost:
    def __init__(self):
        self.cancelled = False
        self.calls = []
        self.result = {"protocol": PROVIDER.PROTOCOL, "kind": "tool.result", "seq": 1,
                       "call_id": "call-1", "status": "terminal", "terminal": {"kind": "exited", "code": 7}}
        self.error = None

    def outcome(self, call_id, deadline):
        self.calls.append(call_id)
        if self.error is not None:
            raise self.error
        result = copy.deepcopy(self.result)
        result["call_id"] = call_id
        return result


class CodexBridgeTest(unittest.TestCase):
    def setUp(self):
        self.token = PROVIDER.CancellationToken()
        self.host = FakeHost()
        self.session = FakeSession()
        self.frames = []
        self.bridge = PROVIDER.Bridge(copy.deepcopy(TURN), self.session, self.host,
                                      self.frames.append, self.token, True, 30)

    def feed(self, value):
        return self.bridge.handle(event(value))

    def running(self):
        first = self.feed({"id": 1, "result": {}})
        self.feed({"id": 2, "result": {"thread": {"id": "native-thread"}}})
        self.feed({"id": 3, "result": {"turn": {"id": "native-turn"}}})
        return [json.loads(line) for line in first.splitlines()]

    @staticmethod
    def call(rpc_id=20, call_id="call-1", **arguments):
        return {"id": rpc_id, "method": "item/tool/call", "params": {
            "threadId": "native-thread", "turnId": "native-turn", "callId": call_id,
            "tool": "trillionnium_shell_exec", "namespace": None, "arguments": arguments}}

    def test_initialization_and_typed_advertisement_preserve_user_input(self):
        self.assertEqual(json.loads(self.bridge.initial())["id"], 1)
        messages = self.feed({"id": 1, "result": {}}).splitlines()
        self.assertEqual(json.loads(messages[0]), {"method": "initialized", "params": {}})
        request = json.loads(messages[1])
        self.assertEqual(request["method"], "thread/start")
        tools = request["params"]["dynamicTools"]
        self.assertEqual([tool["type"] for tool in tools], ["function", "function"])
        self.assertEqual([tool["name"] for tool in tools], ["trillionnium_shell_exec", "trillionnium_adb_exec"])
        started = json.loads(self.feed({"id": 2, "result": {"thread": {"id": "native-thread"}}}))
        self.assertEqual(started["params"]["input"], [{"type": "text", "text": TURN["user_input"]}])
        self.assertEqual(self.session.bindings, ["native-thread"])

    def test_resume_binds_existing_thread_and_rejects_changed_native_identity(self):
        self.session.thread_id = self.bridge.thread_id = "existing-thread"
        messages = self.feed({"id": 1, "result": {}}).splitlines()
        self.assertEqual(json.loads(messages[1])["params"], {"threadId": "existing-thread"})
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            self.feed({"id": 2, "result": {"thread": {"id": "different-thread"}}})
        self.assertEqual(self.frames, [])

    def completed_message(self, text, item_id="message-1"):
        return {"method": "item/completed", "params": {
            "threadId": "native-thread", "turnId": "native-turn",
            "item": {"type": "agentMessage", "id": item_id, "text": text}}}

    def test_final_message_without_delta_is_delivered(self):
        self.running()
        self.feed(self.completed_message("完整回复"))
        self.assertEqual(self.frames[0]["event"], "model.message")
        self.assertEqual(self.frames[0]["text"], "完整回复")
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            self.feed(self.completed_message("完整回复"))
        self.assertEqual(len(self.frames), 1)

    def test_completed_message_publishes_only_matching_unicode_suffix(self):
        self.running()
        self.feed({"method": "item/agentMessage/delta", "params": {
            "threadId": "native-thread", "turnId": "native-turn",
            "itemId": "message-1", "delta": "前缀🙂"}})
        self.feed(self.completed_message("前缀🙂后缀"))
        self.assertEqual([v["text"] for v in self.frames], ["前缀🙂", "后缀"])
        self.assertEqual([v["event"] for v in self.frames], ["model.delta", "model.delta"])

    def test_final_message_conflict_and_unfinished_success_fail_closed(self):
        self.running()
        self.feed({"method": "item/agentMessage/delta", "params": {
            "threadId": "native-thread", "turnId": "native-turn",
            "itemId": "message-1", "delta": "prefix"}})
        for value in [self.completed_message("changed"), {"method": "turn/completed", "params": {
                "threadId": "native-thread", "turn": {"id": "native-turn", "status": "completed"}}}]:
            with self.assertRaises(PROVIDER.ProviderRuntimeError):
                self.feed(value)
        self.assertIsNone(self.bridge.terminal)
        self.assertFalse(self.token.cancelled)

    def test_rpc_responses_are_ordered_and_reject_bool_error_or_duplicate(self):
        for invalid in [True, False, None, "1", 2, -1]:
            with self.subTest(invalid=invalid), self.assertRaises(PROVIDER.ProviderRuntimeError):
                self.feed({"id": invalid, "result": {}})
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            self.feed({"id": 1, "result": {}, "error": None})
        self.feed({"id": 1, "result": {}})
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            self.feed({"id": 1, "result": {}})

    def test_started_notification_can_precede_response_but_must_agree(self):
        self.feed({"id": 1, "result": {}})
        self.feed({"id": 2, "result": {"thread": {"id": "native-thread"}}})
        self.feed({"method": "turn/started", "params": {
            "threadId": "native-thread", "turn": {"id": "native-turn"}}})
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            self.feed({"id": 3, "result": {"turn": {"id": "wrong-turn"}}})

    def test_known_notifications_with_request_id_fail_before_state_or_output(self):
        self.running()
        values = [
            {"method": "turn/started", "params": {"threadId": "native-thread", "turn": {"id": "native-turn"}}},
            {"method": "item/agentMessage/delta", "params": {"threadId": "native-thread", "turnId": "native-turn", "itemId": "message-1", "delta": "text"}},
            {"method": "turn/completed", "params": {"threadId": "native-thread", "turn": {"id": "native-turn", "status": "completed"}}},
        ]
        for value in values:
            for rpc_id in [None, True, 20, "request"]:
                with self.subTest(method=value["method"], rpc_id=rpc_id), self.assertRaises(PROVIDER.ProviderRuntimeError):
                    self.feed({**value, "id": rpc_id})
        self.assertEqual(self.frames, [])
        self.assertIsNone(self.bridge.terminal)
        self.assertFalse(self.token.cancelled)

    def test_unknown_server_requests_never_approve_and_notifications_are_observations(self):
        self.running()
        for method in ["item/commandExecution/requestApproval", "item/fileChange/requestApproval", "item/tool/requestUserInput", "unknown"]:
            with self.subTest(method=method), self.assertRaises(PROVIDER.ProviderRuntimeError):
                self.feed({"id": "approval", "method": method, "params": {}})
        self.assertIsNone(self.feed({"method": "unknown", "params": {"observation": "opaque"}}))
        self.assertEqual(self.frames, [])
        self.assertEqual(self.host.calls, [])

    def test_wrong_thread_or_turn_never_dispatches_or_delivers_model_data(self):
        self.running()
        for method in ["item/tool/call", "item/agentMessage/delta", "turn/completed"]:
            for field in ["threadId", "turnId"]:
                value = self.call(command="exit 7") if method == "item/tool/call" else {
                    "method": method, "params": {"threadId": "native-thread", "turnId": "native-turn", "itemId": "message-1", "delta": "text",
                                                   "turn": {"id": "native-turn", "status": "completed"}}}
                if method == "turn/completed" and field == "turnId":
                    value["params"]["turn"]["id"] = "wrong"
                else:
                    value["params"][field] = "wrong"
                with self.subTest(method=method, field=field), self.assertRaises(PROVIDER.ProviderRuntimeError):
                    self.feed(value)
        self.assertEqual(self.frames, [])
        self.assertEqual(self.host.calls, [])
        self.assertIsNone(self.bridge.terminal)

    def test_invalid_rpc_request_identity_fails_before_host_effect(self):
        self.running()
        for rpc_id in [True, False, None, 1.5, [], {}, 1 << 63, -(1 << 63) - 1, "x" * 257, "\ud800"]:
            with self.subTest(rpc_id=rpc_id), self.assertRaises(PROVIDER.ProviderRuntimeError):
                self.feed(self.call(rpc_id, command="must not execute"))
        self.assertEqual(self.frames, [])
        self.assertEqual(self.host.calls, [])
        self.assertEqual(self.bridge.pending_calls, set())

    def test_native_rpc_identity_and_call_identity_each_prevent_replay(self):
        self.running()
        self.feed(self.call(20, "call-1", command="exit 7"))
        for value in [self.call(20, "different-call", command="exit 7"), self.call(21, "call-1", command="exit 7")]:
            with self.assertRaises(PROVIDER.ProviderRuntimeError):
                self.feed(value)
        self.assertEqual(self.host.calls, ["call-1"])
        self.assertEqual(len(self.frames), 1)

    def test_string_and_integer_rpc_ids_do_not_alias(self):
        self.running()
        for rpc_id, call_id in [(20, "call-1"), ("20", "call-2"), ("", "call-3"), (-1, "call-4")]:
            reply = json.loads(self.feed(self.call(rpc_id, call_id, argv=["/bin/true"])))
            self.assertEqual(reply["id"], rpc_id)
            self.assertIs(type(reply["id"]), type(rpc_id))
        self.assertEqual(len(self.host.calls), 4)

    def test_uncertain_callback_is_permanently_bound_before_wait(self):
        self.running()
        self.host.error = PROVIDER.ProviderRuntimeError("observation unavailable")
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            self.feed(self.call(command="do not replay"))
        self.host.error = None
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            self.feed(self.call(21, command="do not replay"))
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            self.feed(self.call(20, "other-call", command="do not replay"))
        self.assertEqual(self.host.calls, ["call-1"])
        self.assertEqual(len(self.frames), 1)

    def test_callback_identity_capacity_fails_before_dispatch(self):
        self.running()
        self.bridge.pending_calls.update(f"old-{i}" for i in range(4096))
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            self.feed(self.call(argv=["/bin/true"]))
        self.assertEqual(self.frames, [])

    def test_exact_command_argv_stdin_environment_and_target_are_not_rewritten(self):
        self.running()
        arguments = {"command": " printf 'a|b\\n'; exit 7 ", "argv": ["/bin/echo", "a b", "", "$(literal)"],
                     "cwd": "/tmp/a b", "env": {"KEEP": "  原样\n", "REMOVE": None},
                     "stdin": {"text": "binary?\u0000", "nested": [False, 0]}, "mode": "host", "pty": {"rows": 24},
                     "timeout_ms": 0, "stream": False, "target_id": "phone-A"}
        original = copy.deepcopy(arguments)
        self.feed(self.call(**arguments))
        call = self.frames[0]["call"]
        for key, value in original.items():
            self.assertEqual(call[key], value)
        self.assertEqual({key: call[key] for key in PROVIDER.SCOPE_FIELDS}, SCOPE)
        self.assertEqual(call["tool"], "shell.exec")
        self.assertEqual(arguments, original)

    def test_unknown_existing_inhibited_and_failed_observation_are_preserved(self):
        self.running()
        for index, status in enumerate(["unknown", "existing", "inhibited", "terminal", "error"]):
            outcome = {"protocol": PROVIDER.PROTOCOL, "kind": "tool.result", "seq": index + 1,
                       "status": status, "terminal": {"kind": "unknown", "reason": "unconfirmed cleanup"},
                       "registry": {"state": "CompletedUnknown", "effect": None}, "events": [{"bytes": "AA=="}]}
            self.host.result = outcome
            result = json.loads(self.feed(self.call(20 + index, f"call-{index}", argv=["/bin/false"])))
            observed = json.loads(result["result"]["contentItems"][0]["text"])
            self.assertEqual(observed, {**outcome, "call_id": f"call-{index}"})
            self.assertEqual(result["result"]["success"], status in {"terminal", "existing", "inhibited"})

    def test_adb_callback_and_unsupported_surface(self):
        self.running()
        value = self.call(argv=["shell", "printf", "%s", "unchanged"])
        value["params"]["tool"] = "trillionnium_adb_exec"
        self.feed(value)
        self.assertEqual(self.frames[0]["call"]["tool"], "adb.exec")
        for mutation in [{"tool": "native_shell"}, {"namespace": "other"}, {"arguments": {"approval": True}}, {"arguments": "text"}]:
            value = self.call(21, "call-other", command="forbidden")
            value["params"].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(PROVIDER.ProviderRuntimeError):
                self.feed(value)
        self.assertEqual(len(self.frames), 1)

    def test_native_terminal_failure_and_interruption_are_truthful(self):
        for status in ["completed", "failed", "interrupted"]:
            with self.subTest(status=status):
                self.setUp()
                self.running()
                self.feed({"method": "turn/completed", "params": {"threadId": "native-thread",
                    "turn": {"id": "native-turn", "status": status}}})
                self.assertEqual(self.bridge.terminal, status)
                self.assertTrue(self.token.cancelled)
                self.assertEqual(self.frames, [])
                with self.assertRaises(PROVIDER.ProviderRuntimeError):
                    self.feed(self.call(command="after terminal"))

    def test_unknown_terminal_is_not_promoted_and_model_text_stays_exact(self):
        self.running()
        text = "  原生\ntext \"exact\"  "
        self.feed({"method": "item/agentMessage/delta", "params": {
            "threadId": "native-thread", "turnId": "native-turn", "itemId": "message-1", "delta": text}})
        self.assertEqual(self.frames[0]["text"], text)
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            self.feed({"method": "turn/completed", "params": {"threadId": "native-thread",
                "turn": {"id": "native-turn", "status": "unknown"}}})
        self.assertIsNone(self.bridge.terminal)
        self.assertFalse(self.token.cancelled)

    def test_shared_token_cancellation_fences_delivery_even_without_cancel_frame(self):
        self.running()
        self.token.cancel()
        self.assertFalse(self.host.cancelled)
        for value in [self.call(command="after EOF"), {"method": "item/agentMessage/delta", "params": {
                "threadId": "native-thread", "turnId": "native-turn", "delta": "after overflow"}}]:
            with self.assertRaises(PROVIDER.ProviderRuntimeError):
                self.feed(value)
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            self.bridge.emit("provider.event", text="also fenced")
        self.assertEqual(self.frames, [])

    def test_cancellation_while_callback_finishes_does_not_forward_success(self):
        self.running()
        original = self.host.outcome
        def outcome(call_id, deadline):
            result = original(call_id, deadline)
            self.token.cancel()
            return result
        self.host.outcome = outcome
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            self.feed(self.call(command="accepted before cancellation"))
        self.assertEqual(self.host.calls, ["call-1"])
        self.assertEqual(len(self.frames), 1)

    def test_int64_endpoints_and_multibyte_string_bound_are_explicit(self):
        self.running()
        for index, rpc_id in enumerate([-(1 << 63), (1 << 63) - 1, "界" * 85]):
            result = json.loads(self.feed(self.call(rpc_id, f"edge-{index}", argv=["/bin/true"])))
            self.assertEqual(result["id"], rpc_id)
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            self.feed(self.call("界" * 86, "over-bound", argv=["/bin/true"]))
        self.assertEqual(len(self.frames), 3)


class CodexHostInputTest(unittest.TestCase):
    def host(self, frames=()):
        token = PROVIDER.CancellationToken()
        host = PROVIDER.HostInput(io.BytesIO(b"".join(PROVIDER.encoded(frame) for frame in frames)), token)
        host.scope = dict(SCOPE)
        return host, token

    @staticmethod
    def result(seq=0, **fields):
        return {"protocol": PROVIDER.PROTOCOL, "kind": "tool.result", "seq": seq,
                "call_id": "call-1", "status": "existing", **fields}

    def test_optional_scope_free_v1_outcome_remains_exact(self):
        host, token = self.host()
        frame = self.result(registry={"state": "CompletedUnknown"})
        host.frames.put(frame)
        self.assertEqual(host.outcome("call-1", time.monotonic() + 1), frame)
        self.assertFalse(token.cancelled)

    def test_each_explicit_scope_mismatch_is_rejected_at_consumption(self):
        for key in PROVIDER.SCOPE_FIELDS:
            for field in [key, "turn", "scope", "registry"]:
                value = "wrong" if field == key else {key: "wrong"}
                for registry_nested in ([False, True] if field in {"turn", "scope"} else [False]):
                    frame = self.result(**({"registry": {field: value}} if registry_nested else {field: value}))
                    host, _ = self.host()
                    host.frames.put(frame)
                    with self.subTest(key=key, field=field, nested=registry_nested), self.assertRaises(PROVIDER.ProviderRuntimeError):
                        host.outcome("call-1", time.monotonic() + 1)

    def test_matching_explicit_scope_is_preserved_and_malformed_scope_is_rejected(self):
        host, _ = self.host()
        frame = self.result(turn=dict(SCOPE), scope=dict(SCOPE), registry={**SCOPE, "scope": dict(SCOPE)}, **SCOPE)
        host.frames.put(frame)
        self.assertEqual(host.outcome("call-1", time.monotonic() + 1), frame)
        for field in ["turn", "scope"]:
            for invalid in [None, "wrong", []]:
                host, _ = self.host()
                host.frames.put(self.result(**{field: invalid}))
                with self.subTest(field=field, invalid=invalid), self.assertRaises(PROVIDER.ProviderRuntimeError):
                    host.outcome("call-1", time.monotonic() + 1)

    def test_pump_rejects_wrong_scope_before_enqueue(self):
        host, token = self.host([self.result(scope={"task_id": "wrong"})])
        host.pump()
        self.assertTrue(token.cancelled)
        self.assertIsInstance(host.frames.get_nowait(), PROVIDER.ProviderRuntimeError)

    def test_callback_identity_and_deadline_do_not_consume_as_success(self):
        host, _ = self.host()
        host.frames.put(self.result(call_id="other"))
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            host.outcome("call-1", time.monotonic() + 1)
        host, _ = self.host()
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            host.outcome("call-1", time.monotonic() - 1)

    def test_eof_and_two_slot_overflow_cancel_without_losing_bound(self):
        host, token = self.host()
        host.pump()
        self.assertTrue(token.cancelled)
        self.assertLessEqual(host.frames.qsize(), 2)
        host, token = self.host([self.result(seq=i) for i in range(3)])
        host.pump()
        self.assertTrue(token.cancelled)
        self.assertEqual(host.frames.qsize(), 2)
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            host.outcome("call-1", time.monotonic() + 1)

    def test_cancel_requires_all_scope_fields_and_has_no_callback(self):
        for supplied in [{**SCOPE, "turn_id": "wrong"}, {key: value for key, value in SCOPE.items() if key != "profile_id"}, dict(SCOPE)]:
            frame = {"protocol": PROVIDER.PROTOCOL, "kind": "turn.cancel", "seq": 0, "turn": supplied}
            host, token = self.host([frame])
            host.pump()
            self.assertTrue(token.cancelled)
            self.assertEqual(host.cancelled, supplied == SCOPE)

    def test_host_sequence_and_duplicate_json_keys_fail_closed(self):
        for seq in [True, False, 1, -1, "0"]:
            host, token = self.host([self.result(seq=seq)])
            host.pump()
            self.assertTrue(token.cancelled)
            self.assertIsInstance(host.frames.get_nowait(), PROVIDER.ProviderRuntimeError)
        host, token = self.host()
        host.stream = io.BytesIO(b'{"protocol":"x","protocol":"y","seq":0}\n')
        host.pump()
        self.assertTrue(token.cancelled)

    def test_fd_reader_retirement_does_not_require_writer_eof(self):
        read_fd, write_fd = os.pipe()
        token = PROVIDER.CancellationToken()
        with os.fdopen(read_fd, "rb") as stream:
            host = PROVIDER.HostInput(stream, token)
            try:
                os.write(write_fd, PROVIDER.encoded({"protocol": PROVIDER.PROTOCOL, "kind": "turn.start", "seq": 0, "turn": TURN}))
                self.assertEqual(host.start(), TURN)
                host.close()
                self.assertFalse(host.thread.is_alive())
                self.assertLessEqual(len(host.buffer), PROVIDER.MAX_LINE + 2)
            finally:
                host.close()
                os.close(write_fd)

    def test_host_byte_bounds_unterminated_and_invalid_start_fail_closed(self):
        for raw in [b"{}", b"x" * (PROVIDER.MAX_LINE + 1) + b"\n"]:
            host, _ = self.host()
            host.stream = io.BytesIO(raw)
            with self.subTest(length=len(raw)), self.assertRaises(PROVIDER.ProviderRuntimeError):
                host.read()
        for turn in [{**TURN, "session_id": True}, {**TURN, "user_input": "nul\0"}, {**TURN, "user_input": []}]:
            host, _ = self.host([{"protocol": PROVIDER.PROTOCOL, "kind": "turn.start", "seq": 0, "turn": turn}])
            with self.subTest(turn=turn), self.assertRaises(PROVIDER.ProviderRuntimeError):
                host.start()
            self.assertIsNone(host.thread)

    def test_interrupted_thread_start_can_be_retired_without_second_failure(self):
        host, _ = self.host([{"protocol": PROVIDER.PROTOCOL, "kind": "turn.start", "seq": 0, "turn": TURN}])
        with mock.patch.object(PROVIDER.threading.Thread, "start", side_effect=RuntimeError("thread unavailable")):
            with self.assertRaises(RuntimeError):
                host.start()
        host.close()


class CodexNativeConfigurationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.native = self.root / "codex-home"
        self.home.mkdir(mode=0o700)
        self.native.mkdir(mode=0o700)
        self.config = dict(home_directory=str(self.home), codex_home=str(self.native), codex_config_sha256=None)

    def tearDown(self):
        self.temp.cleanup()

    def test_explicit_home_and_neutral_cwd_replace_ambient_injection(self):
        with mock.patch.dict(PROVIDER.os.environ, {"HOME": "/unbound-home", "CODEX_HOME": "/unbound-native",
                "PYTHONPATH": "/unbound-python", "LD_PRELOAD": "/unbound-loader", "LANG": "C.UTF-8"}, clear=True):
            environment, cwd = PROVIDER.native_configuration(self.config)
        self.assertEqual(cwd, self.native)
        self.assertEqual(environment, {"HOME": str(self.home), "CODEX_HOME": str(self.native), "LANG": "C.UTF-8"})

    def test_digest_and_absence_change_fail_without_reading_auth(self):
        (self.native / "auth.json").write_text("not inspected by adapter")
        path = self.native / "config.toml"
        path.write_text('model = "fixture"\n')
        path.chmod(0o600)
        with self.assertRaisesRegex(PROVIDER.ProviderRuntimeError, "digest/absence"):
            PROVIDER.native_configuration(self.config)
        self.config["codex_config_sha256"] = PROVIDER.hashlib.sha256(path.read_bytes()).hexdigest()
        PROVIDER.native_configuration(self.config)
        path.write_text('model = "changed"\n')
        with self.assertRaisesRegex(PROVIDER.ProviderRuntimeError, "digest/absence"):
            PROVIDER.native_configuration(self.config)
        path.unlink()
        with self.assertRaisesRegex(PROVIDER.ProviderRuntimeError, "digest/absence"):
            PROVIDER.native_configuration(self.config)

    def test_config_symlink_and_nonprivate_native_home_fail(self):
        path = self.native / "config.toml"
        path.symlink_to(self.root / "outside-config")
        with self.assertRaises(OSError):
            PROVIDER.native_configuration(self.config)
        path.unlink()
        self.native.chmod(0o750)
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            PROVIDER.native_configuration(self.config)


    def test_user_extension_inputs_fail_before_native_startup(self):
        inputs = [
            '[mcp_servers.unbound]\ncommand = "must-never-run"\n',
            'notify = ["must-never-run"]\n',
            'profile = "unbound"\n',
            '[features]\nhooks = true\n',
            '[features]\nplugins = "false"\n',
            'web_search = "live"\n',
            '[model_providers.unbound.auth]\ncommand = "must-never-run"\n',
            '[model_providers.unbound]\nexperimental_bearer_token = "fixture-not-credential"\n',
            '[model_providers.unbound.aws]\nprofile = "unbound"\n',
        ]
        for source in inputs:
            with self.subTest(source=source), self.assertRaises(PROVIDER.ProviderRuntimeError):
                PROVIDER.validate_public_native_config(source.encode())
        PROVIDER.validate_public_native_config(
            b'model = "fixture"\n[features]\nhooks = false\nplugins = false\n')
        PROVIDER.validate_public_native_config(
            b'[model_providers.fixture]\nname = "public fixture"\nwire_api = "responses"\n')

    def test_unbound_project_layer_and_dangling_source_fail(self):
        project = self.root / ".codex"
        project.mkdir()
        with self.assertRaisesRegex(PROVIDER.ProviderRuntimeError, "unbound native configuration"):
            PROVIDER.native_configuration(self.config)
        project.rmdir()
        (self.native / "managed_config.toml").symlink_to(self.root / "absent")
        with self.assertRaisesRegex(PROVIDER.ProviderRuntimeError, "unbound native configuration"):
            PROVIDER.native_configuration(self.config)

    def test_system_contributor_is_rejected_without_opening_contents(self):
        lstat = PROVIDER.os.lstat
        def observed(path):
            if path == Path("/etc/codex"):
                return object()
            return lstat(path)
        with mock.patch.object(PROVIDER.os, "lstat", side_effect=observed), \
                mock.patch.object(PROVIDER, "read_private_bytes_at", side_effect=AssertionError("must not open")), \
                self.assertRaisesRegex(PROVIDER.ProviderRuntimeError, "startup refused"):
            PROVIDER.native_configuration(self.config)

    def test_native_toml_byte_bound_applies_before_parser(self):
        with mock.patch.object(PROVIDER.tomllib, "loads", side_effect=AssertionError("must not allocate")), \
                self.assertRaisesRegex(PROVIDER.ProviderRuntimeError, "byte bound"):
            PROVIDER.validate_public_native_config(b" " * (PROVIDER.MAX_NATIVE_PUBLIC_CONFIG_BYTES + 1))


class CodexSessionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.directory.chmod(0o700)

    def tearDown(self):
        self.temp.cleanup()

    def session(self, **kwargs):
        return PROVIDER.Session(self.directory, kwargs.pop("turn", TURN), kwargs.pop("binding", "binding-A"), **kwargs)

    def test_binding_persists_and_new_turn_resumes_same_thread(self):
        session = self.session()
        try:
            self.assertIsNone(session.thread_id)
            session.bind("native-thread")
            session.bind("native-thread")
            with self.assertRaises(PROVIDER.ProviderRuntimeError):
                session.bind("wrong-thread")
            state = json.loads((self.directory / session.name).read_bytes())
            self.assertEqual(state["scope"], {key: SCOPE[key] for key in PROVIDER.SCOPE_FIELDS[:3]})
            self.assertEqual((self.directory / session.name).stat().st_mode & 0o777, 0o600)
        finally:
            session.close()
        session = self.session(turn={**TURN, "turn_id": "new-turn", "turn_stream_id": "new-stream"})
        try:
            self.assertEqual(session.thread_id, "native-thread")
        finally:
            session.close()

    def test_concurrent_same_session_and_global_admission_lease_fail_without_adoption(self):
        session = self.session()
        try:
            with self.assertRaises(BlockingIOError):
                self.session()
        finally:
            session.close()
        fd = os.open(self.directory / ".admission.lock", os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                self.session()
        finally:
            os.close(fd)

    def test_binding_change_and_tampered_state_are_not_resumed(self):
        session = self.session()
        session.bind("native-thread")
        path = self.directory / session.name
        session.close()
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            self.session(binding="binding-B")
        original = json.loads(path.read_bytes())
        variants = [{**original, "scope": {**original["scope"], "task_id": "wrong"}},
                    {**original, "schema": "wrong"}, {**original, "thread_id": True}, {**original, "extra": 1}]
        for value in variants:
            path.write_bytes(PROVIDER.encoded(value))
            with self.subTest(value=value), self.assertRaises(PROVIDER.ProviderRuntimeError):
                self.session()

    def test_symlink_hardlink_public_or_nonempty_lease_is_rejected(self):
        session = self.session()
        lease = self.directory / (session.key + ".lock")
        session.close()
        lease.write_bytes(b"not a stale PID to adopt")
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            self.session()
        lease.write_bytes(b"")
        lease.chmod(0o640)
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            self.session()
        lease.chmod(0o600)
        os.link(lease, self.directory / "second-link")
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            self.session()
        (self.directory / "second-link").unlink()
        lease.unlink()
        (self.directory / "target").write_bytes(b"")
        lease.symlink_to("target")
        with self.assertRaises(OSError):
            self.session()

    def test_session_state_public_hardlinked_or_symlinked_is_rejected(self):
        session = self.session()
        session.bind("native-thread")
        path = self.directory / session.name
        session.close()
        path.chmod(0o640)
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            self.session()
        path.chmod(0o600)
        os.link(path, self.directory / "other-state")
        with self.assertRaises(PROVIDER.ProviderRuntimeError):
            self.session()
        (self.directory / "other-state").unlink()
        path.rename(self.directory / "state-target")
        path.symlink_to("state-target")
        with self.assertRaises(OSError):
            self.session()

    def test_exact_session_capacity_preserves_existing_lease_but_rejects_new(self):
        for index in range(PROVIDER.MAX_SESSIONS):
            session = self.session(turn={**TURN, "session_id": f"session-{index}"})
            session.close()
        existing = self.session(turn={**TURN, "session_id": "session-0"})
        existing.close()
        with self.assertRaisesRegex(PROVIDER.ProviderRuntimeError, "at capacity"):
            self.session(turn={**TURN, "session_id": "new-session"})
        self.assertEqual(len(list(self.directory.glob("*.lock"))), PROVIDER.MAX_SESSIONS + 1)

    def test_directory_pollution_scan_is_bounded_and_crash_leftovers_are_held(self):
        for index in range(2 * PROVIDER.MAX_SESSIONS + 16):
            (self.directory / f".orphan-{index}").touch(mode=0o600)
        with self.assertRaisesRegex(PROVIDER.ProviderRuntimeError, "entry bound"):
            self.session()
        self.assertEqual(len(list(self.directory.iterdir())), 2 * PROVIDER.MAX_SESSIONS + 17)

    def test_scandir_stops_without_materializing_unbounded_directory(self):
        class InfiniteLeaves:
            def __init__(self):
                self.count = 0
                self.closed = False
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.closed = True
            def __iter__(self):
                return self
            def __next__(self):
                self.count += 1
                return type("Leaf", (), {"name": f"orphan-{self.count}"})()
        leaves = InfiniteLeaves()
        with mock.patch.object(PROVIDER.os, "scandir", return_value=leaves):
            with self.assertRaisesRegex(PROVIDER.ProviderRuntimeError, "entry bound"):
                self.session()
        self.assertEqual(leaves.count, 2 * PROVIDER.MAX_SESSIONS + 17)
        self.assertTrue(leaves.closed)


if __name__ == "__main__":
    unittest.main()
