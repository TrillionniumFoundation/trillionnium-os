#!/usr/bin/env python3
"""Contract checks and real r6 host process integration.

Run --unit-only where AF_UNIX is prohibited. The complete test is required on a
host permitting AF_UNIX; it uses the real native r6 supervisor and frozen C worker
linked only to an explicitly labelled host SDK fixture. No phone is contacted.
"""
from __future__ import annotations
import base64
import copy
import dataclasses
import importlib
import io
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
import uuid
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT.parent
PHONE = ROOT.parents[2]
sys.path.insert(0, str(ROOT))
import native_backend as b
import prompt_budget as pb
import provider_bridge as bridge
from apply_provider_overlay import build
from native_fixture import NativeFixture, HOST_PARENT_CONTEXT, HOST_WORKER_CONTEXT, HOST_CREDENTIAL_SCOPE


def write(path, raw):
    path.write_bytes(raw); path.chmod(0o600); return path


def owner(root, text="打开 Settings 并检查当前页面。"):
    run = root / ("owner-" + uuid.uuid4().hex); run.mkdir(mode=0o700)
    identity = {"session_id": "session", "profile_id": "profile", "task_id": "same-ui-task",
                "turn_id": uuid.uuid4().hex, "turn_stream_id": uuid.uuid4().hex}
    raw = text.encode()
    evidence = {"schema": "hepta.accepted-owner-request.v150.1", "source": "accepted_turn_start_frame", "identity": identity,
                "request_utf8_b64": base64.b64encode(raw).decode(), "request_sha256": b.sha(raw)}
    claim = {"identity": identity, "request_sha256": b.sha(raw), "run_dir": str(run), "state": "accepted_no_redispatch"}
    return write(run / "accepted-owner-request.json", b.canonical_json(evidence)), write(run / "claim", b.canonical_json(claim))


def budget(prompt, system, grammar=None, image=None, tokenizer="a" * 64, grammar_profile=None, schema_conversion=None):
    return {"schema": "hepta.qairt-token-budget.v1", "profile": b.PROFILE["name"], "method": "native_pre_generation_tokenizer_required",
            "python_token_count_performed": False,
            "tokenizer_sha256": tokenizer, "input_sha256": {key: b.sha(value) if value is not None else None for key, value in
            {"prompt": prompt, "system": system, "grammar": grammar, "image": image}.items()},
            "admission_limit_tokens": 3584, "generation_tokens": 256, "reserved_tokens": 256,
            "context_tokens": 4096, "counter_contract_sha256": "b" * 64,
            "grammar_profile": grammar_profile, "schema_conversion": schema_conversion}


def conversion_fixture(grammar, schema=b"{}", compiler_sha="d" * 64):
    """Binding fixture only; this does not claim that a converter executed."""
    return {"schema": "hepta.schema-gbnf-conversion.v1", "subset": b.GRAMMAR_SUBSET,
        "reference_converter_commit": b.GRAMMAR_CONVERTER_COMMIT,
        "compiler_kind": b.GRAMMAR_COMPILER_KIND, "compiler_source_sha256": compiler_sha,
        "original_schema_bytes": len(schema), "original_schema_sha256": b.sha(schema),
        "canonical_schema_sha256": b.sha(schema), "grammar_bytes": len(grammar), "grammar_sha256": b.sha(grammar),
        "grammar_root": "root", "root_schema_kind": "mobile_use", "input_bytes_preserved": True,
        "conversion_completed": True, "model_loaded": False, "native_action_authorized": False, "production_receipt": False}


def native_row():
    row = {"action_id": "a" * 32, "command_sha256": "b" * 64, "server_instance": "c" * 32,
           "executor_revision": 6, "dispatch_count": 1, "pid": 123, "pgid": 123,
           "executor_context": b.ANDROID_POLICY.server_context, "peer_context": b.ANDROID_POLICY.caller_context,
           "execution_context": b.ANDROID_POLICY.worker_context, "execution_credentials_scope": "android_shell_uid2000",
           "handshake_stage": "worker_entry_after_exec_transition", "state": "completed", "exit_code": 0, "term_signal": None,
           "error": "", "client_disconnected": False, "can_redispatch": False, "waitpid_identity_lost": False,
           "execution_supplementary_group_count": 0, "supplementary_groups_cleared": True,
           "stdout_bytes": 0, "stderr_bytes": 0, "stdout_sha256": b.sha(b""), "stderr_sha256": b.sha(b"")}
    for key in ("terminal", "effect_started", "process_group_established", "waitpid_joined", "process_group_absent",
                "execution_credentials_verified", "worker_domain_verified"):
        row[key] = True
    for key in ("required_execution_uid", "required_execution_gid", "execution_uid", "execution_euid", "execution_gid", "execution_egid"):
        row[key] = 2000
    return {"version": 1, "protocol": b.PROTOCOL, "duplicate": False, "receipt": row, "stdout_b64": "", "stderr_b64": ""}


def config_contract_fixture(root):
    """Config/path tests only: no Android library or native process is loaded."""
    evidence, stage = root / "requests", root / "stage"
    evidence.mkdir(mode=0o700); stage.mkdir(mode=0o700)
    runtime, bundle = root / "runtime", root / "bundle"
    return b.BackendConfig(evidence, stage, str(stage), str(root / "worker"), "a" * 64,
        str(bundle / "genie_config.json"), str(bundle / "tokenizer.json"), str(runtime), str(runtime / "htp-files"),
        str(runtime) + ":/system/lib64:/vendor/lib64", "/vendor/dsp", "c" * 64, pb.QWEN_TOKENIZER_SHA,
        str(root / "counter"), "b" * 64, str(runtime / "libgeniex-proc.so"), b.TOKENIZER_LIBRARY_SHA)


def production_grammar_layout_fixture(original, profile=b.GRAMMAR_R3_PROFILE):
    """Actual bundle layout and pins; no library/model is loaded by this helper."""
    plugin = original.plugin_path
    qairt = plugin + "/qairt"
    return dataclasses.replace(original, grammar_profile=profile,
        core_android=qairt + "/libgeniex_core.so", core_sha256=b.GRAMMAR_CORE_SHA,
        schema_compiler_sha256="d" * 64, vlm_android=qairt + "/libgeniex_vlm.so",
        vlm_sha256=b.GRAMMAR_R3_VLM_SHA if profile == b.GRAMMAR_R3_PROFILE else b.ORIGINAL_VLM_SHA,
        qairt_lib_path=qairt + "/htp-files", tokenizer_library_android=qairt + "/libgeniex-proc.so",
        tokenizer_library_sha256=b.TOKENIZER_LIBRARY_SHA,
        ld_library_path=":".join((plugin, plugin + "/llama_cpp", qairt, qairt + "/htp-files",
                                  "/system/lib64", "/vendor/lib64")))


class ContractTests(unittest.TestCase):
    def test_native_terminal_validator_rejects_every_missing_essential_proof(self):
        valid = native_row()
        b.validate_native(valid, request_id="a" * 32, command_sha256="b" * 64, server_instance="c" * 32)
        mutations = [("waitpid_joined", False), ("waitpid_identity_lost", True), ("process_group_absent", False),
            ("execution_uid", 0), ("execution_context", "u:r:magisk:s0"), ("dispatch_count", True), ("exit_code", False),
            ("term_signal", 9), ("server_instance", "d" * 32), ("command_sha256", "e" * 64), ("can_redispatch", True),
            ("execution_supplementary_group_count", 1), ("state", "indeterminate"), ("stdout_sha256", "0" * 64)]
        for key, value in mutations:
            with self.subTest(field=key):
                item = copy.deepcopy(valid); item["receipt"][key] = value
                with self.assertRaises(b.BackendError):
                    b.validate_native(item, request_id="a" * 32, command_sha256="b" * 64, server_instance="c" * 32)
        duplicate = copy.deepcopy(valid); duplicate["duplicate"] = True
        with self.assertRaises(b.BackendError):
            b.validate_native(duplicate, request_id="a" * 32, command_sha256="b" * 64, server_instance="c" * 32)

    def test_cancellation_wins_serialized_acceptance_and_records_original_order(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp); gate = b.CancelGate(); gate.bind(path); gate.cancel()
            self.assertFalse(gate.accept_completion())
            self.assertEqual(b.strict_json((path / "order-000.json").read_bytes())["kind"], "cancel_accepted")
            self.assertEqual(len(list(path.glob("order-*.json"))), 1)

    def test_owner_bytes_and_claim_must_match(self):
        with tempfile.TemporaryDirectory() as temp:
            original, claim = owner(Path(temp), " 保留空格、换行\n和中文。 ")
            result = b.owner_binding(original, claim)
            self.assertEqual(result["owner_request_sha256"], b.sha(" 保留空格、换行\n和中文。 ".encode()))
            value = b.strict_json(claim.read_bytes()); value["request_sha256"] = "f" * 64
            write(claim, b.canonical_json(value))
            with self.assertRaises(b.BackendError):
                b.owner_binding(original, claim)

    def test_context_admission_rejects_8192_and_unbound_or_overflow_budget(self):
        value = budget(b"prompt", b"system")
        inputs = value["input_sha256"]
        self.assertEqual(b.validate_budget(value, inputs, "a" * 64), 3584)
        for field, new in (("context_tokens", 8192), ("admission_limit_tokens", 3585),
                           ("generation_tokens", True), ("tokenizer_sha256", "b" * 64),
                           ("method", "unmeasured_python_byte_count"), ("python_token_count_performed", True)):
            changed = dict(value); changed[field] = new
            with self.assertRaises(b.BackendError):
                b.validate_budget(changed, inputs, "a" * 64)

    def test_output_grammar_requires_explicit_profile_and_exact_conversion_binding(self):
        grammar = b'root ::= "B"\n'
        value = budget(b"prompt", b"system", grammar=grammar, grammar_profile=b.GRAMMAR_PROFILE,
                       schema_conversion=conversion_fixture(grammar))
        inputs = value["input_sha256"]
        kwargs = {"grammar_profile": b.GRAMMAR_PROFILE, "schema_compiler_sha256": "d" * 64}
        self.assertEqual(b.validate_budget(value, inputs, "a" * 64, **kwargs), 3584)
        with self.assertRaises(b.BackendError):
            b.validate_budget(value, inputs, "a" * 64)
        for field, new in (("grammar_sha256", "0" * 64), ("compiler_source_sha256", "0" * 64),
                           ("input_bytes_preserved", False), ("conversion_completed", 1), ("grammar_bytes", 65537),
                           ("native_action_authorized", True), ("production_receipt", True),
                           ("returncode", 0)):
            with self.subTest(field=field):
                changed = copy.deepcopy(value); changed["schema_conversion"][field] = new
                with self.assertRaises(b.BackendError):
                    b.validate_budget(changed, inputs, "a" * 64, **kwargs)

    def test_r3_uses_its_actual_profile_without_changing_the_token_budget(self):
        grammar = b'root ::= "B"\n'
        value = budget(b"prompt", b"system", grammar=grammar, grammar_profile=b.GRAMMAR_R3_PROFILE,
                       schema_conversion=conversion_fixture(grammar))
        self.assertEqual(b.validate_budget(value, value["input_sha256"], "a" * 64,
            grammar_profile=b.GRAMMAR_R3_PROFILE, schema_compiler_sha256="d" * 64), 3584)
        with self.assertRaisesRegex(b.BackendError, "profile/budget"):
            b.validate_budget(value, value["input_sha256"], "a" * 64,
                grammar_profile=b.GRAMMAR_PROFILE, schema_compiler_sha256="d" * 64)
        self.assertEqual({key: value[key] for key in ("context_tokens", "admission_limit_tokens", "generation_tokens", "reserved_tokens")},
            {"context_tokens": 4096, "admission_limit_tokens": 3584, "generation_tokens": 256, "reserved_tokens": 256})

    def test_production_r3_requires_exact_pins_and_actual_qairt_bundle_layout(self):
        with tempfile.TemporaryDirectory() as temp:
            original = config_contract_fixture(Path(temp))
            # Only the private staging UID is adapted for this config-only
            # test. Production artifact and loader checks remain enabled.
            policy = dataclasses.replace(b.ANDROID_POLICY, execution_uid=os.getuid())
            good = production_grammar_layout_fixture(original)
            good.validate(policy)
            bad_values = [
                {"vlm_android": None}, {"vlm_sha256": None}, {"vlm_sha256": "0" * 64},
                {"vlm_sha256": b.ORIGINAL_VLM_SHA}, {"core_sha256": "0" * 64},
                {"vlm_android": original.plugin_path + "/libgeniex_core.so"},
                {"vlm_android": original.plugin_path + "/../libgeniex_vlm.so"},
                {"vlm_android": "/other/libgeniex_vlm.so"},
                {"core_android": original.plugin_path + "/libgeniex_core.so"},
                {"vlm_android": original.plugin_path + "/libgeniex_vlm.so"},
                {"core_android": original.plugin_path + "/qairt/other.so"},
                {"qairt_lib_path": original.plugin_path + "/htp-files"},
                {"qairt_lib_path": original.plugin_path + "/qairt"},
                {"tokenizer_library_android": original.plugin_path + "/libgeniex-proc.so"},
                {"tokenizer_library_android": original.plugin_path + "/qairt/other.so"},
                {"tokenizer_library_sha256": "0" * 64},
                {"ld_library_path": "/other:" + good.ld_library_path},
                {"ld_library_path": good.ld_library_path.replace("/llama_cpp:", "/qairt:", 1)},
                {"ld_library_path": good.ld_library_path.replace(original.plugin_path + "/llama_cpp:", "", 1)},
                {"ld_library_path": good.ld_library_path.replace("/system/lib64:/vendor/lib64", "/vendor/lib64:/system/lib64")},
                {"grammar_profile": b.GRAMMAR_PROFILE}, {"grammar_profile": None},
            ]
            transport = types.SimpleNamespace(policy=policy)
            for changes in bad_values:
                with self.subTest(changes=changes), self.assertRaises(b.BackendError):
                    b.NativeBackend(dataclasses.replace(good, **changes), transport)
            self.assertFalse(list(original.evidence_root.iterdir()))
            self.assertFalse(list(original.stage_root.iterdir()))

    def test_production_shadow_files_and_dangling_symlinks_stop_before_artifact_checks(self):
        # Run the complete production command with shell tracing. Deliberately
        # absent Android programs are never reached; trace and empty stage prove
        # this is the shadow guard, not a later artifact failure returning 65.
        with tempfile.TemporaryDirectory(prefix="hepta layout ") as temp:
            root = Path(temp)
            config = production_grammar_layout_fixture(config_contract_fixture(root))
            Path(config.model_android).parent.mkdir(mode=0o700)
            Path(config.plugin_path).mkdir(mode=0o700)
            Path(config.plugin_path, "llama_cpp").mkdir(mode=0o700)
            policy = dataclasses.replace(b.ANDROID_POLICY, execution_uid=os.getuid())
            runner = b.NativeBackend(config, types.SimpleNamespace(policy=policy))
            for directory in (config.plugin_path, config.plugin_path + "/llama_cpp"):
                for name in ("libgeniex_core.so", "libgeniex_vlm.so"):
                    for kind in ("regular", "dangling_symlink"):
                        with self.subTest(directory=directory, name=name, kind=kind):
                            path = Path(directory, name)
                            if kind == "regular":
                                write(path, b"unexpected earlier loader entry")
                            else:
                                path.symlink_to(root / ("missing-" + uuid.uuid4().hex))
                                self.assertFalse(path.exists())
                                self.assertTrue(path.is_symlink())
                            try:
                                request_id = uuid.uuid4().hex
                                stage = config.stage_root / request_id; stage.mkdir(mode=0o700)
                                command = runner._command(request_id, str(stage), True, True, False)
                                result = subprocess.run(["/bin/sh", "-c", "set -x; " + command],
                                    capture_output=True, timeout=3)
                                self.assertEqual(result.returncode, 65, result.stderr)
                                trace = result.stderr.decode("utf-8", errors="strict")
                                self.assertIn(str(path), trace)
                                self.assertTrue(trace.rstrip().endswith("exit 65"), trace)
                                self.assertNotIn("/system/bin/sha256sum", trace)
                                self.assertNotIn("/system/bin/env", trace)
                                self.assertEqual(result.stdout, b"")
                                self.assertFalse(list(stage.iterdir()))
                            finally:
                                path.unlink()

    def test_flat_grammar_layout_is_only_accepted_by_explicit_python_host_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            original = config_contract_fixture(Path(temp))
            flat = dataclasses.replace(original, grammar_profile=b.GRAMMAR_R3_PROFILE,
                core_android=original.plugin_path + "/libgeniex_core.so", core_sha256="e" * 64,
                schema_compiler_sha256="d" * 64, vlm_android=original.plugin_path + "/libgeniex_vlm.so",
                vlm_sha256="f" * 64)
            host = dataclasses.replace(b.ANDROID_POLICY, execution_uid=os.getuid(), production=False)
            flat.validate(host)
            with self.assertRaisesRegex(b.BackendError, "selected QAIRT directory"):
                flat.validate(dataclasses.replace(host, production=True))
            self.assertNotIn("production", {field.name for field in dataclasses.fields(b.BackendConfig)})
            self.assertNotIn("policy", {field.name for field in dataclasses.fields(b.BackendConfig)})

    def test_old_v1_and_r2_json_without_new_vlm_fields_still_parse_and_pin_original_vlm(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            original = config_contract_fixture(root)
            policy = dataclasses.replace(b.ANDROID_POLICY, execution_uid=os.getuid())
            old_r2 = dataclasses.replace(production_grammar_layout_fixture(original, b.GRAMMAR_PROFILE),
                vlm_android=None, vlm_sha256=None)
            captured = []
            class ReachedArtifactBoundary(Exception):
                pass
            def inspect_before_any_artifact_or_process(config):
                config.validate(policy)
                captured.append(config)
                raise ReachedArtifactBoundary()
            provider = types.ModuleType("provider_phone_local")
            for name, selected in (("v1", original), ("v1-original-fields", original), ("r2", old_r2)):
                values = dataclasses.asdict(selected)
                values.update(evidence_root=str(selected.evidence_root), stage_root=str(selected.stage_root))
                for key in ("vlm_android", "vlm_sha256"):
                    del values[key]
                if name == "v1-original-fields":
                    for key in ("grammar_profile", "core_android", "core_sha256", "schema_compiler_sha256"):
                        del values[key]
                info = selected.stage_root.stat()
                raw = {"schema": "hepta.provider-geniex-native.v2" if name == "r2" else "hepta.provider-geniex-native.v1",
                    "base_provider_config_sha256": "a" * 64, "model_id": "Qwen3-VL-4B-Instruct-QAIRT-w4a16-SM8750-v79",
                    "backend": values, "tokenizer_gnu_path": "/not-read/tokenizer.json",
                    "tokenizer_config_gnu_path": "/not-read/tokenizer_config.json", "template_contract": {},
                    "deployment_binding": {"schema": "hepta.geniex-shared-mount.v1", "execution_uid": 2000,
                        "execution_gid": 2000, "new_dedicated_mount": True, "old_state_permissions_changed": False,
                        "instance": "1" * 32, "gnu_path": str(selected.stage_root), "android_path": selected.android_stage_root,
                        "st_dev": info.st_dev, "st_ino": info.st_ino}}
                if name == "r2":
                    raw["schema_compiler"] = {"kind": b.GRAMMAR_COMPILER_KIND, "sha256": "d" * 64, "subset": b.GRAMMAR_SUBSET}
                path = write(root / (name + ".json"), b.canonical_json(raw))
                with self.subTest(config=name), mock.patch.dict(sys.modules, {"provider_phone_local": provider}), \
                     mock.patch.object(b, "NativeBackend", side_effect=inspect_before_any_artifact_or_process), \
                     mock.patch.object(bridge, "_read_artifact", side_effect=AssertionError("artifact stage not reached")), \
                     self.assertRaises(ReachedArtifactBoundary):
                    bridge.configure(types.SimpleNamespace(local_config_sha256="a" * 64), str(path))
            self.assertEqual(len(captured), 3)
            self.assertEqual(captured[0].selected_vlm(), (None, None))
            self.assertEqual(captured[1].selected_vlm(), (None, None))
            self.assertEqual(captured[2].selected_vlm(), (original.plugin_path + "/qairt/libgeniex_vlm.so", b.ORIGINAL_VLM_SHA))
            command = b.NativeBackend(captured[2], types.SimpleNamespace(policy=policy))._command(
                "a" * 32, str(original.stage_root / ("a" * 32)), True, True, False)
            self.assertIn(b.ORIGINAL_VLM_SHA + "  " + original.plugin_path + "/qairt/libgeniex_vlm.so", command)
            self.assertLess(command.index(b.ORIGINAL_VLM_SHA), command.index(" -i "))
            self.assertNotIn(b.GRAMMAR_R3_VLM_SHA, command)

    def test_grammar_prompt_keeps_all_open_choices_without_unavailable_click_example(self):
        schema = self.closed_action_schema({"action": {"const": "open"},
            "text": {"type": "string", "enum": ["Calculator", "Settings"]}, "summary": {"type": "string"}})
        aliases = {name: {"label": name, "component": "com.example." + name.lower() + "/.Main"}
                   for name in ("Calculator", "Settings")}
        context = {"approved_apps": aliases, "transcript": [{"public_text": "earlier exact observation"}]}
        body = {"messages": [{"role": "system", "content": "original policy"},
            {"role": "user", "content": json.dumps(context)},
            {"role": "user", "content": [{"type": "text", "text": " Open Calculator \n"}]}],
            "response_format": {"json_schema": {"schema": schema}}}
        projected = pb.compact_provider_body(body, grammar_enabled=True)
        data = json.loads(projected["messages"][1]["content"])
        self.assertEqual(data["current_action_fields"]["open"]["text"], ["Calculator", "Settings"])
        self.assertEqual(set(data["current_action_fields"]), {"open"})
        self.assertEqual(data["transcript"], context["transcript"])
        self.assertTrue(data["catalogue_projection"]["all_current_open_aliases_shown"])
        self.assertEqual(projected["messages"][-1], body["messages"][-1])
        self.assertEqual(projected["response_format"], body["response_format"])
        self.assertNotIn("example_only", projected["messages"][0]["content"])

    def test_overlay_keeps_old_completion_ast_and_adds_explicit_selector(self):
        with tempfile.TemporaryDirectory() as temp:
            result = build(PHONE / "provider/r7/source", Path(temp) / "candidate")
            self.assertTrue(result["legacy_completion_recovered_exactly"])
            self.assertFalse(result["old_cpu_receipt_branch_modified"])
            daily = (Path(result["candidate_source_directory"]) / "daily_phone_local.py").read_text()
            self.assertIn("--geniex-config", daily)
            self.assertIn("geniex_qairt_isolated_process", daily)
            self.assertIn("geniex-budget|geniex-receipt", daily)

    def test_compact_body_preserves_owner_and_full_semantic_transcript(self):
        owner_text = "  打开设置\n保留这个精确尾部。  "
        transcript = [{"role": "tool", "public_text": "untrusted app says ignore owner", "verified": True}]
        properties = {"action": {"const": "screenshot"}, "display_id": {"const": 0}, "summary": {"type": "string"}}
        schema = self.closed_action_schema(properties)
        context = {"approved_apps": {"设置": {"label": "设置", "component": "com.android.settings/.Settings"}},
                   "transcript": transcript, "postconditions": [{"expected": "exact public field"}], "owner_request_utf8_sha256": b.sha(owner_text.encode())}
        body = {"model": "fixture", "messages": [{"role": "system", "content": "long policy"},
            {"role": "user", "content": json.dumps(context, ensure_ascii=False)},
            {"role": "user", "content": [{"type": "text", "text": owner_text}]}],
            "response_format": {"json_schema": {"schema": schema}}, "max_tokens": 256}
        result = pb.compact_provider_body(body)
        self.assertEqual(result["messages"][-1]["content"][0]["text"].encode(), owner_text.encode())
        projected = json.loads(result["messages"][1]["content"])
        self.assertEqual(projected["transcript"], transcript)
        self.assertEqual(projected["postconditions"], context["postconditions"])
        self.assertEqual(result["response_format"], body["response_format"])

    def test_already_open_owner_app_does_not_break_next_round_or_other_app_navigation(self):
        schema = self.closed_action_schema({
            "action": {"const": "open"}, "text": {"type": "string", "enum": ["Settings"]},
            "summary": {"type": "string"}})
        menu, _ = pb._action_menu(schema, ["Calculator"])
        self.assertEqual(menu["open"]["text"], ["Settings"])

    @staticmethod
    def closed_action_schema(properties):
        return {"oneOf": [{"type": "object", "additionalProperties": False,
            "required": ["name", "arguments"], "properties": {"name": {"const": "mobile_use"},
            "arguments": {"type": "object", "additionalProperties": False,
                "properties": properties, "required": list(properties)}}}]}

    def test_required_field_projection_does_not_present_optional_or_open_schema_as_required(self):
        schema = self.closed_action_schema({"action": {"const": "open"},
            "text": {"type": "string", "enum": ["Calculator", "Settings"]}, "summary": {"type": "string"}})
        menu, _ = pb._action_menu(schema, ["Calculator"])
        self.assertEqual(menu["open"], {"text": ["Calculator"]})
        self.assertIn("All fields listed for the chosen action in current_action_fields are REQUIRED", pb.SMALL_POLICY)
        self.assertIn("arguments.text is REQUIRED", pb.SMALL_POLICY)
        self.assertIn("summary cannot replace text", pb.SMALL_POLICY)
        mutations = [([], "additionalProperties", True), ([], "required", ["name"]),
            (["properties", "arguments"], "required", ["action", "summary"]),
            (["properties", "arguments"], "required", ["action", "text", "text", "summary"]),
            (["properties", "arguments"], "additionalProperties", True)]
        for path, key, value in mutations:
            with self.subTest(path=path, key=key, value=value):
                changed = copy.deepcopy(schema); node = changed["oneOf"][0]
                for part in path:
                    node = node[part]
                node[key] = value
                with self.assertRaises(b.BackendError):
                    pb._action_menu(changed, ["Calculator"])


class NativeIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.core_limit = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (0, cls.core_limit[1]))
        cls.tmp = tempfile.TemporaryDirectory(prefix="hepta-geniex-real-native-")
        cls.root = Path(cls.tmp.name).resolve()
        cls.fixture = NativeFixture(cls.root).__enter__()
        cls.worker = cls.root / "geniex-frozen-worker-host-sdk"
        subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-isystem", str(RUNTIME / "vendor"),
                        str(RUNTIME / "worker.c"), str(ROOT / "tests/broker_stub.c"), "-o", str(cls.worker)], check=True, capture_output=True)
        cls.counter = cls.root / "geniex-token-counter-host"
        cls.tokenizer_library = cls.root / "libtokenizer-host-fixture.so"
        subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-I", str(ROOT / "vendor"),
                        str(ROOT / "token_count.c"), "-ldl", "-o", str(cls.counter)], check=True, capture_output=True)
        subprocess.run(["cc", "-std=c11", "-O2", "-fPIC", "-shared", "-I", str(ROOT / "vendor"),
                        str(ROOT / "tests/tokenizer_stub.c"), "-o", str(cls.tokenizer_library)], check=True, capture_output=True)
        cls.policy = b.NativePolicy(server_uid=os.getuid(), execution_uid=os.getuid(),
            server_context=HOST_PARENT_CONTEXT, caller_context=b.ANDROID_POLICY.caller_context,
            worker_context=HOST_WORKER_CONTEXT, credential_scope=HOST_CREDENTIAL_SCOPE,
            supplementary_group_count=len(os.getgroups()), production=False)

    @classmethod
    def tearDownClass(cls):
        cls.fixture.close(); cls.tmp.cleanup()
        resource.setrlimit(resource.RLIMIT_CORE, cls.core_limit)

    def setUp(self):
        self.directory = self.root / ("case-" + uuid.uuid4().hex); self.directory.mkdir(mode=0o700)
        self.evidence = self.directory / "requests"; self.evidence.mkdir(mode=0o700)
        self.stage = self.directory / "stage"; self.stage.mkdir(mode=0o700)
        self.model = self.directory / "bundle"; self.model.mkdir(mode=0o700)
        write(self.model / "genie_config.json", b"{}")
        write(self.model / "tokenizer.json", b"{}")
        self.config = b.BackendConfig(self.evidence, self.stage, str(self.stage), str(self.worker), b.sha(self.worker.read_bytes()),
            str(self.model / "genie_config.json"), str(self.model / "tokenizer.json"), str(self.model), str(self.model),
            "/usr/lib:/lib", "/tmp", "c" * 64, b.sha((self.model / "tokenizer.json").read_bytes()),
            str(self.counter), b.sha(self.counter.read_bytes()), str(self.tokenizer_library), b.sha(self.tokenizer_library.read_bytes()),
            max_worker_ms=2000, max_native_ms=3000)
        self.transport = b.R6Transport(self.fixture.endpoint, self.policy)
        self.runner = b.NativeBackend(self.config, self.transport)
        self.owner_path, self.claim_path = owner(self.directory)

    def run_request(self, marker="", gate=None, on_poll=None, request_id=None, image=None, grammar=None):
        prompt = ("Fixture evidence " + "p" * 800 + marker).encode(); system = b"fixture system"
        return self.runner.run(request_id=request_id or uuid.uuid4().hex, prompt=prompt, system=system, grammar=grammar, image=image,
            owner_path=self.owner_path, owner_claim_path=self.claim_path,
            budget=budget(prompt, system, grammar=grammar, image=image, tokenizer=self.config.tokenizer_sha256,
                grammar_profile=self.config.grammar_profile,
                schema_conversion=conversion_fixture(grammar) if grammar is not None else None),
            gate=gate or b.CancelGate(), on_poll=on_poll)

    def test_grammar_binding_and_loader_hash_are_checked_with_real_native_cleanup(self):
        # This host SDK does not enforce grammar. It checks transport, pins,
        # inputs, counter separation and cleanup; Android enforcement is separate.
        core = write(self.model / "libgeniex_core.so", b"HOST FIXTURE loader hash only")
        vlm = write(self.model / "libgeniex_vlm.so", b"HOST FIXTURE R2 VLM hash only")
        self.config = dataclasses.replace(self.config, grammar_profile=b.GRAMMAR_PROFILE,
            core_android=str(core), core_sha256=b.sha(core.read_bytes()), schema_compiler_sha256="d" * 64,
            vlm_android=str(vlm), vlm_sha256=b.sha(vlm.read_bytes()),
            ld_library_path=str(self.model) + ":/usr/lib:/lib")
        self.runner = b.NativeBackend(self.config, self.transport)
        grammar = b'root ::= "B"\n'
        answer = self.run_request(grammar=grammar)
        self.assertTrue(answer["receipt"]["model_result_usable"], answer)
        directory = self.evidence / answer["receipt"]["request_id"]
        intent = b.strict_json((directory / "intent.json").read_bytes())
        worker = b.strict_json((directory / "worker-result.json").read_bytes())
        counter = b.strict_json((directory / "counter-result.json").read_bytes())
        self.assertEqual(worker["input_sha256"]["grammar"], b.sha(grammar))
        self.assertNotIn("grammar", counter["input_sha256"])
        self.assertEqual(intent["core_sha256"], self.config.core_sha256)
        self.assertEqual(intent["vlm_android"], str(vlm))
        self.assertEqual(intent["vlm_sha256"], self.config.vlm_sha256)
        self.assertEqual(answer["receipt"]["grammar_profile"], b.GRAMMAR_PROFILE)
        write(core, b"CHANGED HOST FIXTURE")
        rejected = self.run_request(grammar=grammar)
        self.assertEqual(rejected["receipt"]["state"], "failed")
        self.assertTrue(rejected["receipt"]["cleanup_confirmed"])
        self.assertFalse((self.stage / rejected["receipt"]["request_id"] / "counter-result.json").exists())
        self.assertFalse((self.stage / rejected["receipt"]["request_id"] / "worker-result.json").exists())

    def test_r3_vlm_mutation_stops_before_counter_or_worker_and_preserves_native_cleanup(self):
        # These are deliberately non-ELF host pin fixtures, accepted only by
        # this test's Python-injected nonproduction NativePolicy.
        core = write(self.model / "libgeniex_core.so", b"HOST FIXTURE R2 core hash only")
        vlm_raw = b"HOST FIXTURE R3 VLM hash only"
        vlm = write(self.model / "libgeniex_vlm.so", vlm_raw)
        self.config = dataclasses.replace(self.config, grammar_profile=b.GRAMMAR_R3_PROFILE,
            core_android=str(core), core_sha256=b.sha(core.read_bytes()), schema_compiler_sha256="d" * 64,
            vlm_android=str(vlm), vlm_sha256=b.sha(vlm_raw), ld_library_path=str(self.model) + ":/usr/lib:/lib")
        for changes in ({"vlm_sha256": None}, {"vlm_android": None},
                        {"vlm_android": str(self.directory / "libgeniex_vlm.so")}):
            with self.subTest(changes=changes), self.assertRaises(b.BackendError):
                b.NativeBackend(dataclasses.replace(self.config, **changes), self.transport)
        self.assertFalse(list(self.evidence.iterdir()) or list(self.stage.iterdir()))
        self.runner = b.NativeBackend(self.config, self.transport)
        grammar = b'root ::= "B"\n'
        answer = self.run_request(grammar=grammar)
        self.assertTrue(answer["receipt"]["model_result_usable"], answer)
        directory = self.evidence / answer["receipt"]["request_id"]
        intent = b.strict_json((directory / "intent.json").read_bytes())
        for value in (intent, answer["receipt"]):
            self.assertEqual(value["grammar_profile"], b.GRAMMAR_R3_PROFILE)
            self.assertEqual(value["vlm_android"], str(vlm))
            self.assertEqual(value["vlm_sha256"], self.config.vlm_sha256)
        self.assertEqual(intent["token_budget"]["grammar_profile"], b.GRAMMAR_R3_PROFILE)
        write(vlm, b"CHANGED HOST FIXTURE VLM")
        rejected = self.run_request(grammar=grammar)
        self.assertEqual(rejected["receipt"]["state"], "failed")
        self.assertTrue(rejected["receipt"]["cleanup_confirmed"])
        self.assertFalse(rejected["receipt"]["model_result_usable"])
        failed_request = self.evidence / rejected["receipt"]["request_id"]
        native = b.strict_json((failed_request / "native-result.json").read_bytes())["receipt"]
        self.assertEqual(native["exit_code"], 65)
        self.assertTrue(native["waitpid_joined"] and native["process_group_absent"])
        failed_stage = self.stage / rejected["receipt"]["request_id"]
        self.assertFalse((failed_stage / "counter-result.json").exists())
        self.assertFalse((failed_stage / "worker-result.json").exists())
        self.assertFalse((failed_stage / "generated.bin").exists())
        write(vlm, vlm_raw)
        # A distinct, explicitly requested call may proceed after proven cleanup;
        # the failed request is not retried or rewritten.
        recovered = self.run_request(grammar=grammar)
        self.assertTrue(recovered["receipt"]["model_result_usable"], recovered)
        self.assertNotEqual(recovered["receipt"]["request_id"], rejected["receipt"]["request_id"])

    def test_actual_production_shadow_guard_exits_65_with_real_native_cleanup(self):
        # Construct under production layout/pin validation, then run its complete
        # command through the real HOST r6 supervisor. Only the temporary shadow
        # files exist: the first guard must prevent every artifact/counter/model
        # program from being reached. This is not an Android-domain receipt.
        config = production_grammar_layout_fixture(self.config)
        Path(config.plugin_path, "llama_cpp").mkdir(mode=0o700)
        construction_policy = dataclasses.replace(b.ANDROID_POLICY, execution_uid=os.getuid())
        command_builder = b.NativeBackend(config, types.SimpleNamespace(policy=construction_policy))
        server_instance = self.transport.health()["server_instance"]
        for directory in (config.plugin_path, config.plugin_path + "/llama_cpp"):
            for name in ("libgeniex_core.so", "libgeniex_vlm.so"):
                for kind in ("regular", "dangling_symlink"):
                    with self.subTest(directory=directory, name=name, kind=kind):
                        shadow = Path(directory, name)
                        if kind == "regular":
                            write(shadow, b"unexpected earlier loader entry")
                        else:
                            shadow.symlink_to(self.directory / ("missing-" + uuid.uuid4().hex))
                        try:
                            request_id = uuid.uuid4().hex
                            stage = self.stage / request_id; stage.mkdir(mode=0o700)
                            command = "set -x; " + command_builder._command(request_id, str(stage), True, True, False)
                            command_sha = b.sha(command.encode("utf-8"))
                            envelope = self.fixture.request({"op": "execute", "action_id": request_id,
                                "command_sha256": command_sha, "command": command, "timeout_ms": 2000})
                            native = b.validate_native(envelope, request_id=request_id,
                                command_sha256=command_sha, server_instance=server_instance, policy=self.policy)
                            self.assertEqual(native["state"], "failed", envelope)
                            self.assertEqual(native["exit_code"], 65, envelope)
                            self.assertTrue(native["waitpid_joined"] and native["process_group_absent"])
                            self.assertFalse(native["can_redispatch"])
                            trace = base64.b64decode(envelope["stderr_b64"], validate=True).decode("utf-8", errors="strict")
                            self.assertIn(str(shadow), trace)
                            self.assertTrue(trace.rstrip().endswith("exit 65"), trace)
                            self.assertNotIn("/system/bin/sha256sum", trace)
                            self.assertNotIn("/system/bin/env", trace)
                            self.assertEqual(base64.b64decode(envelope["stdout_b64"], validate=True), b"")
                            self.assertFalse(list(stage.iterdir()))
                            inspected = self.fixture.inspect(request_id, command_sha, include_output=True)
                            b.validate_native(inspected, request_id=request_id, command_sha256=command_sha,
                                server_instance=server_instance, policy=self.policy)
                            self.assertEqual(inspected["receipt"], native)
                        finally:
                            shadow.unlink()

    def test_original_profile_and_wrong_loader_cannot_enable_output_grammar(self):
        with self.assertRaises(b.BackendError):
            self.run_request(grammar=b'root ::= "B"\n')
        self.assertFalse(list(self.evidence.iterdir()))
        bad = dataclasses.replace(self.config, grammar_profile=b.GRAMMAR_PROFILE,
            core_android=str(self.model / "libgeniex_core.so"), core_sha256="e" * 64,
            schema_compiler_sha256="d" * 64)
        with self.assertRaisesRegex(b.BackendError, "first loader"):
            b.NativeBackend(bad, self.transport)

    def test_real_native_success_joins_exact_worker_and_host_proof_stays_host(self):
        answer = self.run_request()
        self.assertEqual(answer["receipt"]["state"], "completed", answer)
        self.assertTrue(answer["receipt"]["model_result_usable"])
        self.assertEqual(answer["receipt"]["proof_environment"], "host_fixture")
        request = self.evidence / answer["receipt"]["request_id"]
        native = b.strict_json((request / "native-result.json").read_bytes())
        worker = b.strict_json((request / "worker-result.json").read_bytes())
        self.assertEqual(worker["pid"], native["receipt"]["pid"])
        self.assertTrue(native["receipt"]["waitpid_joined"] and native["receipt"]["process_group_absent"])
        with self.assertRaises(b.BackendError):
            b.validate_native(native, request_id=answer["receipt"]["request_id"],
                command_sha256=native["receipt"]["command_sha256"], server_instance=native["receipt"]["server_instance"])

    def test_eos_negative_rc_and_length_do_not_produce_usable_model_result(self):
        for marker in ("[[case=generate_fail_with_text]]", "[[case=length]]"):
            answer = self.run_request(marker)
            self.assertFalse(answer["receipt"]["model_result_usable"], answer)
            self.assertTrue(answer["receipt"]["cleanup_confirmed"])

    def test_native_token_limit_prevents_model_creation_and_preserves_counter_evidence(self):
        answer = self.run_request("p" * 4000)
        receipt = answer["receipt"]
        self.assertEqual(receipt["state"], "failed")
        self.assertTrue(receipt["cleanup_confirmed"])
        self.assertFalse(receipt["model_result_usable"])
        stage = self.stage / receipt["request_id"]
        counter_raw = (stage / "counter-result.json").read_bytes()
        counter = b.strict_json(counter_raw)
        self.assertEqual(counter["status"], "oversize")
        self.assertGreater(counter["prompt_tokens_upper_bound"], 3584)
        self.assertEqual(receipt["counter_sha"], b.sha(counter_raw))
        self.assertFalse((stage / "worker-result.json").exists() or (stage / "generated.bin").exists())
        self.assertTrue(self.run_request()["receipt"]["model_result_usable"])

    def test_counter_input_or_formatter_tampering_cannot_authorize_model_text(self):
        original = self.transport.exchange
        def corrupt_counter(payload, **kwargs):
            result = original(payload, **kwargs)
            if payload.get("op") == "execute":
                path = self.stage / payload["action_id"] / "counter-result.json"
                counter = b.strict_json(path.read_bytes())
                counter["segment_sha256"][0] = "0" * 64
                write(path, b.canonical_json(counter))
            return result
        with mock.patch.object(self.transport, "exchange", side_effect=corrupt_counter):
            answer = self.run_request()
        self.assertEqual(answer["receipt"]["state"], "failed")
        self.assertTrue(answer["receipt"]["cleanup_confirmed"])
        self.assertFalse(answer["receipt"]["model_result_usable"])
        self.assertIn("formatter", answer["receipt"]["error"])

    def test_worker_template_change_cannot_use_a_count_for_different_formatted_text(self):
        original = self.transport.exchange
        def corrupt_worker(payload, **kwargs):
            result = original(payload, **kwargs)
            if payload.get("op") == "execute":
                path = self.stage / payload["action_id"] / "worker-result.json"
                value = b.strict_json(path.read_bytes())
                value["formatted_prompt_sha256"] = "0" * 64
                write(path, b.canonical_json(value))
            return result
        with mock.patch.object(self.transport, "exchange", side_effect=corrupt_worker):
            answer = self.run_request()
        self.assertFalse(answer["receipt"]["model_result_usable"])
        self.assertTrue(answer["receipt"]["cleanup_confirmed"])
        self.assertIn("formatted prompt", answer["receipt"]["error"])

    def test_image_splice_is_counted_and_missing_image_tokens_in_sdk_profile_are_rejected(self):
        image = b"\x89PNG\r\n\x1a\nHOST FIXTURE, not a decoded phone screenshot"
        answer = self.run_request(image=image)
        self.assertTrue(answer["receipt"]["model_result_usable"], answer)
        original = self.transport.exchange
        def remove_visual_count(payload, **kwargs):
            result = original(payload, **kwargs)
            if payload.get("op") == "execute":
                path = self.stage / payload["action_id"] / "worker-result.json"
                value = b.strict_json(path.read_bytes()); value["profile"]["prompt_tokens"] -= 256
                write(path, b.canonical_json(value))
            return result
        with mock.patch.object(self.transport, "exchange", side_effect=remove_visual_count):
            rejected = self.run_request(image=image)
        self.assertFalse(rejected["receipt"]["model_result_usable"])
        self.assertTrue(rejected["receipt"]["cleanup_confirmed"])
        self.assertIn("SDK token count differs", rejected["receipt"]["error"])

    def test_sdk_abort_without_worker_outputs_is_cleanup_only_and_never_replayed(self):
        for marker in ("[[case=sdk_abort]]", "[[case=exit134]]"):
            answer = self.run_request(marker)
            receipt = answer["receipt"]
            self.assertEqual(receipt["state"], "failed", answer)
            self.assertTrue(receipt["cleanup_confirmed"])
            self.assertFalse(receipt["model_result_usable"] or receipt["native_action_authorized"])
            self.assertIsNone(answer["text"])
            stage = self.stage / receipt["request_id"]
            self.assertFalse((stage / "worker-result.json").exists() or (stage / "generated.bin").exists())
            native = b.strict_json((self.evidence / receipt["request_id"] / "native-result.json").read_bytes())["receipt"]
            self.assertTrue(native["waitpid_joined"] and native["process_group_absent"])
            self.assertTrue(native["term_signal"] == signal.SIGABRT or native["exit_code"] == 134)
            with self.assertRaises(FileExistsError):
                self.run_request(request_id=receipt["request_id"])
        self.assertTrue(self.run_request()["receipt"]["model_result_usable"])

    def test_incomplete_native_proof_stays_unknown_and_blocks_fresh_request(self):
        original = self.transport.exchange
        def missing_proof(payload, **kwargs):
            result = original(payload, **kwargs)
            if payload.get("op") == "execute":
                result["receipt"].pop("waitpid_joined")
            return result
        with mock.patch.object(self.transport, "exchange", side_effect=missing_proof):
            answer = self.run_request()
        self.assertEqual(answer["receipt"]["state"], "unknown")
        self.assertFalse(answer["receipt"]["cleanup_confirmed"] or answer["receipt"]["model_result_usable"])
        with self.assertRaisesRegex(b.BackendError, "UNKNOWN"):
            self.run_request()

    def test_real_disconnect_cancel_kills_and_joins_then_new_request_succeeds(self):
        gate = b.CancelGate(); started = time.monotonic()
        def cancel_later():
            if time.monotonic() - started > 0.2:
                gate.cancel()
        answer = self.run_request("[[case=hard_hang]]", gate=gate, on_poll=cancel_later)
        self.assertEqual(answer["receipt"]["state"], "cancelled", answer)
        self.assertTrue(answer["receipt"]["cleanup_confirmed"])
        request = self.evidence / answer["receipt"]["request_id"]
        native = b.strict_json((request / "native-result.json").read_bytes())["receipt"]
        self.assertTrue(native["waitpid_joined"] and native["process_group_absent"])
        self.assertIn(native["term_signal"], (signal.SIGKILL, signal.SIGTERM))
        fresh = self.run_request()
        self.assertTrue(fresh["receipt"]["model_result_usable"], fresh)

    def test_real_native_timeout_is_cleanup_only(self):
        answer = self.run_request("[[case=hard_hang]]")
        self.assertFalse(answer["receipt"]["model_result_usable"])
        self.assertTrue(answer["receipt"]["cleanup_confirmed"])
        self.assertEqual(answer["receipt"]["state"], "timed_out")
        self.assertEqual(answer["receipt"]["timeout_origin"], "native_supervisor")
        native = b.strict_json((self.evidence / answer["receipt"]["request_id"] / "native-result.json").read_bytes())["receipt"]
        self.assertEqual(native["state"], "timed_out")

    def test_real_worker_deadline_requires_bound_metadata_and_never_uses_partial_text(self):
        self.config = dataclasses.replace(self.config, max_worker_ms=500, max_native_ms=2000)
        self.runner = b.NativeBackend(self.config, self.transport)
        answer = self.run_request("[[case=worker_deadline]]")
        receipt = answer["receipt"]
        self.assertEqual(receipt["state"], "timed_out", answer)
        self.assertEqual(receipt["timeout_origin"], "frozen_worker")
        self.assertTrue(receipt["cleanup_confirmed"])
        self.assertFalse(receipt["model_result_usable"])
        self.assertIsNone(answer["text"])
        directory = self.evidence / receipt["request_id"]
        native = b.strict_json((directory / "native-result.json").read_bytes())["receipt"]
        worker = b.strict_json((directory / "worker-result.json").read_bytes())
        self.assertEqual(native["exit_code"], 124)
        self.assertTrue(native["waitpid_joined"] and native["process_group_absent"])
        kwargs = {"request_id": receipt["request_id"], "expected_inputs": worker["input_sha256"],
                  "expected_model": self.config.model_android, "expected_output_path": worker["raw_text_file"]}
        for key, value in (("deadline_observed", False), ("generation_complete", True), ("pid", 1),
                           ("input_sha256", {}), ("sdk_source_commit", "0" * 40), ("worker_exit_status_planned", 0)):
            with self.subTest(field=key):
                changed = copy.deepcopy(worker); changed[key] = value
                with self.assertRaises(b.BackendError):
                    b.validate_worker_deadline(changed, native, **kwargs)

    def test_exit_124_without_original_worker_deadline_metadata_is_not_classified_as_timeout(self):
        answer = self.run_request("[[case=exit124]]")
        self.assertEqual(answer["receipt"]["state"], "failed", answer)
        self.assertIn("unverified_worker_deadline", answer["receipt"]["error"])
        self.assertTrue(answer["receipt"]["cleanup_confirmed"])
        self.assertFalse(answer["receipt"]["model_result_usable"])

    def test_duplicate_request_and_unresolved_local_intent_are_not_dispatched(self):
        identity = uuid.uuid4().hex
        answer = self.run_request(request_id=identity)
        original = (self.fixture.state_dir / "actions" / identity / "receipt.json").read_bytes()
        with self.assertRaises(FileExistsError):
            self.run_request(request_id=identity)
        self.assertEqual((self.fixture.state_dir / "actions" / identity / "receipt.json").read_bytes(), original)
        unresolved = self.evidence / uuid.uuid4().hex; unresolved.mkdir(mode=0o700)
        with self.assertRaisesRegex(b.BackendError, "unresolved"):
            self.run_request()
        self.assertEqual(len(list((self.fixture.state_dir / "actions").glob(identity))), 1)

    def test_cancel_at_native_return_cannot_accept_success(self):
        gate = b.CancelGate()
        original = self.transport.exchange
        def intercept(payload, **kwargs):
            value = original(payload, **kwargs)
            if payload.get("op") == "execute":
                gate.cancel()
            return value
        with mock.patch.object(self.transport, "exchange", side_effect=intercept):
            answer = self.run_request(gate=gate)
        self.assertEqual(answer["receipt"]["state"], "cancelled")
        self.assertIsNone(answer["text"])

    def test_actual_selector_bridge_and_unchanged_parser_tail(self):
        bundle = os.environ.get("HEPTA_QAIRT_BUNDLE")
        self.assertTrue(bundle, "full test requires verified tokenizer bundle via HEPTA_QAIRT_BUNDLE")
        candidate = self.directory / "provider-overlay"
        manifest = build(PHONE / "provider/r7/source", candidate)
        result = subprocess.run([sys.executable, str(ROOT / "tests/provider_flow_probe.py"),
            "--source", manifest["candidate_source_directory"], "--root", str(self.directory / "flow"),
            "--endpoint", self.fixture.endpoint, "--worker", str(self.worker), "--bundle", bundle,
            "--counter", str(self.counter), "--tokenizer-library", str(self.tokenizer_library)],
            capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode() + result.stdout.decode())
        report = json.loads(result.stdout)
        self.assertTrue(report["selector_selected_geniex"] and report["native_waitpid_proven"]
                        and report["owner_bytes_preserved"] and report["original_typed_parser_used"])
        self.assertFalse(report["phone_actions_dispatched"])
        self.assertTrue(report["malformed_json_rejected"])
        self.assertTrue(report["task_deadline_cancelled_with_native_cleanup"])
        self.assertTrue(report["native_timeout_classified"] and report["worker_deadline_classified"]
                        and report["owner_cancel_preserved"])
        self.assertTrue(report["cpu_cleanup_binding_absent"])
        self.assertFalse(report["http_transport_called"])
        private_source = os.environ.get("HEPTA_PRIVATE_GENIEX_SOURCE")
        private_root = os.environ.get("HEPTA_PRIVATE_TEST_ROOT")
        if private_source or private_root:
            self.assertTrue(private_source and private_root, "private source and test directory must be supplied together")
            result = subprocess.run([sys.executable, str(ROOT / "tests/provider_flow_probe.py"),
                "--source", private_source, "--root", str(Path(private_root) / "selector-flow"),
                "--endpoint", self.fixture.endpoint, "--worker", str(self.worker), "--bundle", bundle,
                "--counter", str(self.counter), "--tokenizer-library", str(self.tokenizer_library)],
                capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode() + result.stdout.decode())
            report = json.loads(result.stdout)
            self.assertTrue(report["selector_selected_geniex"] and report["original_typed_parser_used"]
                            and report["cpu_cleanup_binding_absent"] and report["cpu_mode_without_binding_rejected"]
                            and report["task_deadline_cancelled_with_native_cleanup"])
        sources = [(manifest["candidate_source_directory"], self.directory / "grammar-flow")]
        if private_source:
            sources.append((private_source, Path(private_root) / "grammar-selector-flow"))
        for source, flow_root in sources:
            for profile in (b.GRAMMAR_PROFILE, b.GRAMMAR_R3_PROFILE):
                current_root = flow_root if profile == b.GRAMMAR_PROFILE else flow_root.with_name(flow_root.name + "-r3")
                profile_args = ["--schema-grammar"] if profile == b.GRAMMAR_PROFILE else ["--grammar-profile", profile]
                with self.subTest(grammar_selector_source=source, grammar_profile=profile):
                    result = subprocess.run([sys.executable, str(ROOT / "tests/provider_flow_probe.py"),
                        "--source", source, "--root", str(current_root), "--endpoint", self.fixture.endpoint,
                        "--worker", str(self.worker), "--bundle", bundle, "--counter", str(self.counter),
                        "--tokenizer-library", str(self.tokenizer_library), *profile_args],
                        capture_output=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr.decode() + result.stdout.decode())
                    report = json.loads(result.stdout)
                    self.assertTrue(report["schema_compiler_executed"] and report["original_typed_parser_used"]
                                    and report["native_waitpid_proven"] and report["malformed_json_rejected"]
                                    and report["task_deadline_cancelled_with_native_cleanup"]
                                    and report["native_timeout_classified"] and report["worker_deadline_classified"]
                                    and report["owner_cancel_preserved"] and report["vlm_bound_in_intent_and_receipt"])
                    self.assertEqual(report["grammar_profile"], profile)
                    self.assertEqual(len(report["cases"]), 6)
                    self.assertFalse(report["phone_actions_dispatched"] or report["http_transport_called"]
                                     or report["grammar_enforced_by_host_model_fixture"])


if __name__ == "__main__":
    unit_only = "--unit-only" in sys.argv
    if unit_only:
        sys.argv.remove("--unit-only")
    suite = unittest.TestSuite()
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(ContractTests))
    if not unit_only:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(NativeIntegrationTests))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
