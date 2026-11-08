#!/usr/bin/env python3
"""Host-only real selector -> native process -> original typed parser probe.

The native sidecar is the real r6 HEPTA_TESTING build and the model process is
the frozen C worker linked to an explicitly labelled host SDK fixture. Only
external Android file pins and the transport environment are injected. This
never opens a phone connection, starts the provider listener or emits actions.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import threading
import time
import uuid
from unittest import mock


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--counter", type=Path, required=True)
    parser.add_argument("--tokenizer-library", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    options = parser.parse_args()
    sys.path.insert(0, str(options.source))
    import daily_phone_local as daily
    import native_backend as b
    import prompt_budget as pb
    import provider_bridge as bridge
    import provider_phone_local as provider
    from provider_openai_compatible import PROTOCOL, ProviderError
    from retirement_recovery import EXECUTOR_BINDING
    from model_health import ModelHealth, ModelFailure

    root = options.root.resolve(); root.mkdir(mode=0o700)
    state = root / "provider-state"; state.mkdir(mode=0o700)
    evidence = state / "evidence"; evidence.mkdir(mode=0o700)
    (evidence / "claims").mkdir(mode=0o700)
    native_evidence = root / "native-requests"; native_evidence.mkdir(mode=0o700)
    stage = root / "stage"; stage.mkdir(mode=0o700)
    def write(path, value):
        raw = value if isinstance(value, bytes) else b.canonical_json(value)
        b.exclusive(path, raw)
        return path

    key = write(root / "unused-legacy-api-key", b"host-fixture-unused-credential\n")
    base_config = {
        "schema": "hepta.phone-local-provider.v150.2",
        "endpoint": "http://127.0.0.1:18080/v1/chat/completions", "api_key_file": str(key),
        "model": "legacy-host-fixture", "service_manifest_sha256": "a" * 64,
        "max_tokens": 256, "max_prompt_bytes": 24576, "inference_location": "phone", "expected_parallel_slots": 1,
        "approved_apps": {"Settings": {"label": "Settings", "component": "com.android.settings/.Settings"},
                          "Calculator": {"label": "Calculator", "component": "com.example.calculator/.Calculator"}},
        "executor": {"mode": "phone_local_sidecar", "python": "/usr/bin/python3",
                     "client_path": EXECUTOR_BINDING["client_path"], "client_sha256": EXECUTOR_BINDING["client_sha256"],
                     "timeout_ms": 5000},
        "operation_profile": provider.ORDINARY_PROFILE, "context_tokens": 8192,
    }
    base_path = write(root / "base-provider.json", base_config)
    backend_config = b.BackendConfig(native_evidence, stage, str(stage), str(options.worker.resolve()),
        b.sha(options.worker.read_bytes()), str(options.bundle / "genie_config.json"), str(options.bundle / "tokenizer.json"),
        str(options.bundle), str(options.bundle), "/usr/lib:/lib", "/tmp", "c" * 64, pb.QWEN_TOKENIZER_SHA,
        str(options.counter), b.sha(options.counter.read_bytes()), str(options.tokenizer_library), b.sha(options.tokenizer_library.read_bytes()),
        max_worker_ms=55000, max_native_ms=60000)
    backend_value = dataclasses.asdict(backend_config)
    for field in ("evidence_root", "stage_root"):
        backend_value[field] = str(backend_value[field])
    info = stage.stat()
    template_contract = {
        "schema": "hepta.qairt-template-bound.v1", "sdk_commit": b.SDK_COMMIT,
        "template_sha256": pb.QWEN_TEMPLATE_SHA,
        "formatter_commit": pb.FORMATTER_COMMIT, "formatter_blob": pb.FORMATTER_BLOB,
        "pipeline_blob": pb.PIPELINE_BLOB, "formatter_fixed_utf8_bytes": 80,
        "method": "exact_sdk_formatted_text_segments_plus_bos_upper_bound",
        "vision_boundary_tokens": 2, "bos_token_upper_bound": 1,
        "roles": ["system", "user"], "max_images": 1, "enable_thinking": False,
        "tools_passed_to_sdk": False,
        "image_tokens": 256, "vision_shape": [512, 512], "context_tokens": 4096,
    }
    geniex_path = write(root / "geniex-provider.json", {
        "schema": "hepta.provider-geniex-native.v1", "base_provider_config_sha256": b.sha(base_path.read_bytes()),
        "model_id": "Qwen3-VL-4B-Instruct-QAIRT-w4a16-SM8750-v79", "backend": backend_value,
        "tokenizer_gnu_path": str(options.bundle / "tokenizer.json"),
        "tokenizer_config_gnu_path": str(options.bundle / "tokenizer_config.json"), "template_contract": template_contract,
        "deployment_binding": {"schema": "hepta.geniex-shared-mount.v1", "execution_uid": 2000, "execution_gid": 2000,
            "new_dedicated_mount": True, "old_state_permissions_changed": False, "instance": uuid.uuid4().hex,
            "gnu_path": str(stage), "android_path": str(stage), "st_dev": info.st_dev, "st_ino": info.st_ino},
    })
    retained = write(root / "fixture-retained-unread.json", b"[]\n")
    policy = b.NativePolicy(server_uid=os.getuid(), execution_uid=os.getuid(),
        server_context="host_fixture_parent_not_android_selinux", caller_context=b.ANDROID_POLICY.caller_context,
        worker_context="host_fixture_worker_not_android_selinux", credential_scope="host_fixture_current_identity_not_android_shell",
        supplementary_group_count=len(os.getgroups()), production=False)
    native_class = b.NativeBackend
    def host_backend(config):
        return native_class(config, b.R6Transport(options.endpoint, policy))
    captured = []
    argv = ["daily_phone_local.py", "--state", str(state), "--config", str(base_path),
            "--retained-claims", str(retained), "--retained-claims-sha256", b.sha(retained.read_bytes()),
            "--geniex-config", str(geniex_path)]
    cpu_gate_checked = False
    if "--slot-cleanup-binding" in (options.source / "daily_phone_local.py").read_text():
        with mock.patch.object(sys, "argv", argv[:-2]), mock.patch.object(daily, "serve", side_effect=AssertionError("CPU service must not start without its original binding")), \
             mock.patch.object(daily, "load_local_config", side_effect=AssertionError("CPU rejection must precede config/model access")):
            try:
                daily.main()
            except SystemExit as error:
                assert error.code == 2
                cpu_gate_checked = True
        assert cpu_gate_checked
    # No serve() body executes. These two file-pin seams cover only Android
    # installed locations; all selectors, config parsing, admissions and source
    # hash checks are the actual candidate code.
    with mock.patch.object(sys, "argv", argv), mock.patch.object(daily, "serve", side_effect=captured.append), \
         mock.patch.object(provider, "validate_executor", side_effect=lambda value, **_: value), \
         mock.patch("phone_local_tools.validate_executor", side_effect=lambda value, **_: value), \
         mock.patch.object(b, "NativeBackend", side_effect=host_backend), \
         mock.patch.object(daily, "load_binding", side_effect=AssertionError("NPU selector must not read CPU cleanup/READY/identity"), create=True):
        daily.main()
    assert len(captured) == 1
    args = captured[0]; args.contracts = None
    args.model_health = ModelHealth(state / "model-health.json", args.model, daily.replace_json)
    assert args.local_config["operation_profile"] == b.PROFILE["name"]
    assert args.local_config["context_tokens"] == 4096 and args.local_config["max_tokens"] == 256
    # This is the regression for confusing the 55-second generation cap with
    # the full 60-second supervisor/session budget.
    assert provider.OPERATION_PROFILES[b.PROFILE["name"]]["max_inference_seconds"] == 55

    rows = []
    for index, marker in enumerate(("", " [[case=malformed_json]]", " [[case=hard_hang]]")):
        run = evidence / ("20261108-000000-" + uuid.uuid4().hex); run.mkdir(mode=0o700)
        read_fd, write_fd = os.pipe(); source = os.fdopen(read_fd, "rb", buffering=0); sink = io.StringIO()
        owner_text = "  Open Settings and inspect the current screen.\nKeep these owner bytes.  " + marker
        identity = {"session_id": "fixture-session", "profile_id": "fixture-profile", "task_id": "same-ui-task",
                    "turn_id": "owner-turn-" + str(index), "turn_stream_id": "owner-stream-" + str(index)}
        with mock.patch("phone_local_tools.validate_executor", side_effect=lambda value, **_: value):
            adapter = daily.DailyAdapter(args, source, sink, run, threading.Event())
        try:
            frame = {"protocol": PROTOCOL, "seq": 0, "kind": "turn.start", "turn": dict(identity, user_input=owner_text)}
            os.write(write_fd, (json.dumps(frame) + "\n").encode())
            accepted = adapter.receive("turn.start", timeout=0)
            assert accepted is not None and adapter.accepted_identity == identity
            assert adapter.operation_profile["max_inference_seconds"] == 55
            assert 0 < adapter.remaining_inference_seconds() <= 55
            messages = [{"role": "user", "content": owner_text}]
            rejected = False
            deadline_cancelled = False
            if index == 2:
                started = time.monotonic()
                original_receive = adapter.receive
                def expire_during_native(*a, **kw):
                    if time.monotonic() - started > 0.25:
                        adapter.session_deadline = time.monotonic() - 0.01
                    return original_receive(*a, **kw)
                adapter.receive = expire_during_native
            try:
                with mock.patch("phone_local_tools.validate_executor", side_effect=lambda value, **_: value), \
                     mock.patch.object(provider, "inspect_single_slot", side_effect=AssertionError("NPU branch must not call HTTP")), \
                     mock.patch.object(daily, "inspect_single_slot", side_effect=AssertionError("NPU cleanup must not call HTTP")), \
                     mock.patch.object(adapter, "spawn_model", side_effect=AssertionError("NPU branch must not spawn HTTP worker")):
                    answer = adapter.completion(messages)
            except ModelFailure as error:
                if index != 2 or error.category != "model_timeout":
                    raise
                deadline_cancelled = True
                answer = None
            except (ProviderError, json.JSONDecodeError, ValueError):
                if index != 1:
                    raise
                rejected = True
                answer = None
            receipt = b.strict_json((run / "local-01.geniex-receipt.json").read_bytes())
            request = native_evidence / adapter.last_request_id
            native = b.strict_json((request / "native-result.json").read_bytes())["receipt"]
            prompt = (stage / adapter.last_request_id / "prompt.txt").read_bytes()
            assert prompt.endswith(owner_text.encode())
            assert native["waitpid_joined"] is True and native["process_group_absent"] is True
            assert receipt["proof_environment"] == "host_fixture"
            # Complete model text still needs the separate original JSON/phone
            # authority. A session deadline permits cleanup only.
            assert receipt["model_result_usable"] is (index != 2)
            if index == 0:
                call_id = answer["choices"][0]["message"]["tool_calls"][0]["id"]
                assert adapter.phone_tools.calls[call_id]["semantic_tool"] == "phone.screenshot"
                assert (run / "local-01.mapping.json").is_file()
                if hasattr(adapter, "ledger_prefix"):
                    assert len(adapter.ledger_prefix.bindings) == 1
                    assert adapter.ledger_prefix.bindings[0]["value"]["allowed_call_id"] == call_id
            elif index == 1:
                assert rejected and not adapter.phone_tools.calls
                assert not (run / "local-01.decision.json").exists()
            else:
                assert deadline_cancelled and receipt["state"] == "cancelled"
                assert receipt["cleanup_confirmed"] and not adapter.phone_tools.calls
            assert "tool.call" not in sink.getvalue() and not adapter.dispatched_calls
            rows.append({"rejected": rejected, "deadline_cancelled": deadline_cancelled,
                         "receipt_state": receipt["state"], "owner_sha256": b.sha(owner_text.encode())})
        finally:
            adapter.frames.close(); adapter.inputs.close(); source.close(); os.close(write_fd)
    print(json.dumps({"selector_selected_geniex": True, "native_waitpid_proven": True,
        "owner_bytes_preserved": True, "original_typed_parser_used": True,
        "phone_actions_dispatched": False, "malformed_json_rejected": rows[1]["rejected"],
        "task_deadline_cancelled_with_native_cleanup": rows[2]["deadline_cancelled"],
        "cpu_cleanup_binding_absent": not getattr(args, "slot_cleanup_binding", None),
        "cpu_mode_without_binding_rejected": cpu_gate_checked,
        "http_transport_called": False,
        "proof_environment": "host_fixture", "cases": rows}))


if __name__ == "__main__":
    main()
