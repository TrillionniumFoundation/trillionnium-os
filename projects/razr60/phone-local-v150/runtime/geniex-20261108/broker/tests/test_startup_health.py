#!/usr/bin/env python3
"""Startup-only contracts and real r6 host integration; no Android assertions.

--unit-only executes without AF_UNIX. Full mode also executes the unchanged r6
supervisor and frozen worker/counter, with explicitly synthetic host SDK code.
"""
from __future__ import annotations
import ast
import copy
import dataclasses
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import types
import unittest
import uuid
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(HERE))
import native_backend as b
import prompt_budget as pb
import startup_health as h
import test_backend as existing

spec = importlib.util.spec_from_file_location("health_schema_compiler_fixture", ROOT.parent / "schema-grammar-python-r1/python_schema_grammar.py")
converter = importlib.util.module_from_spec(spec); spec.loader.exec_module(converter)
COMPILER_SHA = b.sha(Path(spec.origin).read_bytes())
COMPILER = {"kind": b.GRAMMAR_COMPILER_KIND, "subset": b.GRAMMAR_SUBSET, "sha256": COMPILER_SHA,
            "convert": converter.convert_schema}


class CounterFixture:
    """Use actual reservation logic; native host counter still measures bytes."""
    def __init__(self, config):
        self.tokenizer_sha = config.tokenizer_sha256
        self.grammar_profile = config.grammar_profile
        self.schema_compiler_sha256 = config.schema_compiler_sha256
        self.contract = {"host_fixture_counter_not_official_tokenizer": True}
    budget = pb.NativeTokenizerBudget.budget


def write(path, value):
    raw = value if isinstance(value, bytes) else b.canonical_json(value)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(raw); path.chmod(0o600)
    return raw


def candidate_proof(root, config, policy, health):
    candidate = root / ("geniex-candidate-" + uuid.uuid4().hex); candidate.mkdir(mode=0o700)
    (candidate / "model-evidence").mkdir(mode=0o700); (candidate / "stage").mkdir(mode=0o700)
    config = dataclasses.replace(config, evidence_root=candidate / "model-evidence", stage_root=candidate / "stage",
                                  android_stage_root=str(candidate / "stage"))
    params = dataclasses.asdict(config)
    params.update(evidence_root=str(config.evidence_root), stage_root=str(config.stage_root))
    config_raw = write(candidate / "geniex-config.json", {"backend": params})
    info = (candidate / "stage").stat(); stage = {"st_dev": info.st_dev, "st_ino": info.st_ino}
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    instance = candidate.name.removeprefix("geniex-candidate-")
    launch = {"schema": "hepta.geniex-provider-start.v1", "instance": instance, "mode": "serve",
              "geniex_config_sha256": b.sha(config_raw), "stage": stage}
    launch_raw = write(candidate / "startup/provider-start.json", launch)
    plan_raw = write(candidate / "startup/entry-plan.json", {"schema": "hepta.init-owned-geniex-provider.v1",
                                                           "launch_config_sha256": b.sha(launch_raw), "stage": stage})
    identity = h.kernel_identity(policy)
    entry = {"schema": "hepta.geniex-provider-entry-intent.v1", "instance": instance,
             "entry_plan_sha256": b.sha(plan_raw), **identity, "stage": stage,
             "state": "validated_exec_intent_not_ready", "automatic_request_replay": False,
             "native_execution_qualified": False}
    entry_raw = write(candidate / "startup-evidence" / ("entry-" + boot + ".json"), entry)
    post = {"schema": "hepta.geniex-provider-post-exec-preflight.v1", "instance": instance, "mode": "serve", "boot_id": boot,
            "identity": {"pid": identity["pid"], "context": identity["context"],
                         "CapEff": f'{identity["effective_capabilities"]:016x}', "CapPrm": f'{identity["permitted_capabilities"]:016x}'},
            "native_health": health, "entry_intent_sha256": b.sha(entry_raw), "entry_plan_sha256": b.sha(plan_raw),
            "launch_config_sha256": b.sha(launch_raw), "stage": stage,
            "state": "identity_and_health_verified_provider_listen_not_yet_proved", "model_executed": False,
            "phone_action_executed": False, "model_or_app_qualified": False}
    write(candidate / "startup-evidence" / ("post-exec-" + boot + ".json"), post)
    return candidate, config, boot


def contract_runner(root):
    original = existing.config_contract_fixture(root)
    policy = dataclasses.replace(b.ANDROID_POLICY, server_uid=os.getuid(), execution_uid=os.getuid(), production=False)
    config = dataclasses.replace(original, grammar_profile=b.GRAMMAR_R3_PROFILE,
        core_android=original.plugin_path + "/libgeniex_core.so", core_sha256="1" * 64,
        vlm_android=original.plugin_path + "/libgeniex_vlm.so", vlm_sha256="2" * 64,
        ld_library_path=original.plugin_path + ":/usr/lib:/lib", schema_compiler_sha256=COMPILER_SHA)
    health = {"protocol": b.PROTOCOL, "executor_revision": 6, "state": "ready", "execute_authorized": True,
              "server_instance": "c" * 32}
    candidate, config, boot = candidate_proof(root, config, policy, health)
    class NoDispatchTransport:
        endpoint = "host_fixture_no_native_socket"
        def __init__(self): self.policy = policy; self.execute_count = 0
        def health(self): raise b.BackendError("host_fixture_native_unavailable")
        def exchange(self, *_args, **_kwargs): self.execute_count += 1; raise AssertionError("must not dispatch")
    transport = NoDispatchTransport()
    return candidate, b.NativeBackend(config, transport), CounterFixture(config), boot


def signal_child(point, directory):
    """Real process signals around a stub model boundary, never native proof.

    Only run_prelisten's signal lifecycle/evidence code is under test here. The
    separate contract/native cases exercise the actual binding and supervisor.
    """
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.default_int_handler)
    directory = Path(directory)
    (directory / "startup-evidence").mkdir(mode=0o700)
    boot = "host-signal-fixture"
    prepared = {"request_id": "a" * 32, "grammar": b"host fixture, not native grammar",
                "binding": {"startup_binding": {"boot_id": boot}}, "budget": {"host_fixture": True}}
    class StubRunner:
        policy = types.SimpleNamespace(production=True)  # seam only; never a NativePolicy/native execution
        config = types.SimpleNamespace(max_native_ms=60000)
        def run_startup_health(self, **_kwargs):
            write(directory / "model-boundary-stub-called.json", {"native_execution": False})
            return {"host_fixture": "model boundary, not a receipt"}
    def configure(args, _config):
        args.geniex_backend = {"runner": StubRunner(), "counter": object(), "schema_compiler": {}}
    provider = types.ModuleType("provider_phone_local")
    provider.load_local_config = lambda _path: ({"host_fixture": True}, "0" * 64)
    import provider_bridge
    calls = []
    def no_stop():
        calls.append(True)
        if point == "post_validation" and len(calls) == 3:
            os.kill(os.getpid(), signal.SIGTERM)
        if point == "after_restore" and len(calls) == 4:
            if signal.getsignal(signal.SIGTERM) is not signal.SIG_DFL:
                raise AssertionError("shutdown handler was not restored before final sticky check")
            os.kill(os.getpid(), signal.SIGTERM)
    def validate(*_args):
        if point == "during_validation":
            os.kill(os.getpid(), signal.SIGTERM)
        return {"answer_42_verified": True, "native_uid2000_npu_qualified": False,
                "host_signal_fixture_not_native_qualification": True}
    if point == "ignored": signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if point == "custom": signal.signal(signal.SIGTERM, lambda *_args: None)
    try:
        with mock.patch.dict(sys.modules, {"provider_phone_local": provider}), \
             mock.patch.object(provider_bridge, "configure", configure), \
             mock.patch.object(h, "prepare_request", lambda *_args: prepared), \
             mock.patch.object(h, "validate_answer", validate):
            h.run_prelisten(ROOT, directory, no_stop=no_stop)
        if point == "after_return":
            if signal.getsignal(signal.SIGTERM) is not signal.SIG_DFL:
                raise AssertionError("successful health return retained a swallowing handler")
            os.kill(os.getpid(), signal.SIGTERM)
        write(directory / "handoff-reached.json", {"host_fixture": True, "listener_opened": False})
    except BaseException as error:
        write(directory / "child-failure.json", {"type": type(error).__name__, "error": str(error)})
        return 70
    return 0


class StartupContractTests(unittest.TestCase):
    def test_overlay_pins_startup_helper_and_real_daily_import_refuses_changed_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = existing.build(existing.PHONE / "provider/r7/source", Path(tmp) / "candidate")
            source = Path(manifest["candidate_source_directory"])
            helper = source / "startup_health.py"
            digest = b.sha(helper.read_bytes())
            self.assertEqual(manifest["candidate_sha256"]["startup_health.py"], digest)
            tree = ast.parse((source / "daily_phone_local.py").read_text())
            pins = ast.literal_eval(next(node.value for node in tree.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == "PARENTS" for target in node.targets)))
            self.assertEqual(pins["startup_health.py"], digest)
            command = [sys.executable, "-I", "-c", "import runpy,sys;runpy.run_path(sys.argv[1],run_name='host_import_only')",
                       str(source / "daily_phone_local.py")]
            clean = subprocess.run(command, capture_output=True, timeout=10)
            self.assertEqual(clean.returncode, 0, clean.stderr.decode())
            helper.write_bytes(helper.read_bytes() + b"\n# changed host fixture\n")
            changed = subprocess.run(command, capture_output=True, timeout=10)
            self.assertNotEqual(changed.returncode, 0)
            self.assertIn(b"protocol source pin differs", changed.stderr)

    def test_fixed_schema_does_not_force_42_and_has_no_phone_actions(self):
        schema = h.health_schema()
        self.assertEqual(schema["properties"]["summary"], {"type": "string", "maxLength": 1024})
        grammar, proof = converter.convert_schema(b.canonical_json(schema), compiler_source_sha256=COMPILER_SHA)
        self.assertEqual(proof["root_schema_kind"], "health_final_only")
        self.assertNotIn(b'"42"', grammar)
        self.assertEqual(schema["properties"]["tool"], {"type": "string", "const": "none"})
        self.assertNotIn(b"mobile_use", grammar)

    def test_startup_binding_records_actual_host_identity_without_owner_turn(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate, runner, counter, _ = contract_runner(Path(tmp))
            prepared = h.prepare_request(runner, candidate, counter, COMPILER)
            self.assertEqual(prepared["binding"]["request_kind"], "startup_health")
            self.assertEqual(prepared["binding"]["startup_binding"]["proof_environment"], "host_fixture")
            self.assertEqual(prepared["binding"]["startup_binding"]["pid"], os.getpid())
            self.assertFalse(prepared["binding"]["startup_binding"]["user_turn_created"])
            self.assertNotIn("owner_request_sha256", prepared["binding"])
            self.assertNotIn("identity", prepared["binding"])
            self.assertEqual(prepared["budget"]["input_sha256"]["image"], None)
            self.assertEqual(h.prepare_request(runner, candidate, counter, COMPILER)["request_id"], prepared["request_id"])

    def test_production_policy_rejects_current_host_as_init_bootstrap(self):
        with self.assertRaises(b.BackendError):
            h.kernel_identity(b.ANDROID_POLICY)

    def test_changed_proof_config_pid_or_preflight_mode_is_rejected(self):
        for kind in ("pid", "config", "mode", "boot", "post_sha"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                candidate, runner, counter, boot = contract_runner(Path(tmp))
                post = candidate / "startup-evidence" / ("post-exec-" + boot + ".json")
                value = b.strict_json(post.read_bytes())
                if kind == "pid": value["identity"]["pid"] += 1
                elif kind == "boot": value["boot_id"] = "0" * 36
                elif kind == "post_sha": value["entry_intent_sha256"] = "0" * 64
                elif kind == "mode": value["mode"] = "preflight_only"
                elif kind == "config":
                    path = candidate / "geniex-config.json"; write(path, {"backend": {}})
                write(post, value)
                with self.assertRaises(b.BackendError): h.prepare_request(runner, candidate, counter, COMPILER)
                self.assertEqual(runner.transport.execute_count, 0)

    def test_real_shared_failure_path_is_durable_and_never_becomes_user_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate, runner, counter, _ = contract_runner(Path(tmp))
            answer = runner.run_startup_health(candidate=candidate, counter=counter, compiler=COMPILER, gate=b.CancelGate())
            receipt = answer["receipt"]
            self.assertEqual(receipt["schema"], "hepta.geniex-startup-process-receipt.v1")
            self.assertEqual(receipt["state"], "failed")
            self.assertEqual(receipt["proof_type"], "known_not_dispatched.v1")
            self.assertTrue(receipt["cleanup_confirmed"])
            self.assertFalse(receipt["model_result_usable"])
            self.assertFalse(receipt["native_action_authorized"])
            directory = runner.config.evidence_root / receipt["request_id"]
            intent = b.strict_json((directory / "intent.json").read_bytes())
            self.assertEqual(intent["schema"], "hepta.geniex-startup-native-intent.v1")
            self.assertNotIn("owner_request_sha256", intent)
            self.assertEqual((directory / "terminal.json").read_bytes(), b.canonical_json(receipt))
            self.assertFalse(list(candidate.rglob("accepted-owner-request.json")))
            with self.assertRaises(b.BackendError): h.validate_answer(runner, h.prepare_request(runner, candidate, counter, COMPILER), answer)
            with self.assertRaises(FileExistsError):
                runner.run_startup_health(candidate=candidate, counter=counter, compiler=COMPILER, gate=b.CancelGate())
            self.assertEqual(runner.transport.execute_count, 0)

    def test_prior_unknown_remains_global_and_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate, runner, counter, _ = contract_runner(Path(tmp))
            unresolved = runner.config.evidence_root / ("f" * 32); unresolved.mkdir(mode=0o700)
            original = write(unresolved / "intent.json", {"host_fixture": "unresolved original"})
            with self.assertRaisesRegex(b.BackendError, "unresolved"):
                runner.run_startup_health(candidate=candidate, counter=counter, compiler=COMPILER, gate=b.CancelGate())
            self.assertEqual((unresolved / "intent.json").read_bytes(), original)
            self.assertEqual(runner.transport.execute_count, 0)
            self.assertEqual(len(list(runner.config.evidence_root.iterdir())), 2)  # old dir plus unchanged global lock

    def test_cancelled_before_dispatch_cannot_pass_startup_or_create_owner_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate, runner, counter, _ = contract_runner(Path(tmp))
            gate = b.CancelGate(); gate.cancel()
            answer = runner.run_startup_health(candidate=candidate, counter=counter, compiler=COMPILER, gate=gate)
            self.assertEqual(answer["receipt"]["state"], "cancelled")
            self.assertFalse(answer["receipt"]["model_result_usable"])
            self.assertEqual(runner.transport.execute_count, 0)

    def test_answer_validation_uses_persisted_bytes_and_refuses_repaired_wrong_or_user_receipts(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate, runner, counter, _ = contract_runner(Path(tmp))
            prepared = h.prepare_request(runner, candidate, counter, COMPILER)
            directory = runner.config.evidence_root / prepared["request_id"]; directory.mkdir(mode=0o700)
            expected = {"kind": "turn.complete", "call_id": "", "tool": "none", "command": "", "argv": [],
                        "task_status": "completed", "summary": "42"}
            raw = b.canonical_json(expected)
            receipt = {"schema": "hepta.geniex-startup-process-receipt.v1", "request_kind": "startup_health",
                "request_id": prepared["request_id"], "startup_binding_sha256": b.sha(b.canonical_json(prepared["binding"]["startup_binding"])),
                "state": "completed", "cleanup_confirmed": True, "model_result_usable": True, "native_action_authorized": False,
                "automatic_retry": False, "can_redispatch": False, "proof_type": "native_r6_waitpid_process_group.v1",
                "proof_environment": "host_fixture", "text_sha": b.sha(raw)}
            write(directory / "terminal.json", receipt); write(directory / "generated.bin", raw)
            proof = h.validate_answer(runner, prepared, {"receipt": receipt, "text": raw.decode()})
            self.assertTrue(proof["answer_42_verified"]); self.assertFalse(proof["native_uid2000_npu_qualified"])
            for bad in (dict(expected, summary="41"), dict(expected, tool="open_app")):
                data = b.canonical_json(bad); changed = dict(receipt, text_sha=b.sha(data))
                write(directory / "terminal.json", changed); write(directory / "generated.bin", data)
                with self.assertRaises(b.BackendError): h.validate_answer(runner, prepared, {"receipt": changed, "text": data.decode()})
            write(directory / "terminal.json", receipt); write(directory / "generated.bin", raw[:-1])
            with self.assertRaises(b.BackendError): h.validate_answer(runner, prepared, {"receipt": receipt, "text": raw.decode()})

    def test_post_model_sigterm_sticky_latch_prevents_handoff(self):
        for point in ("during_validation", "post_validation"):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                child = subprocess.run([sys.executable, str(__file__), "--signal-child", point, tmp],
                                       capture_output=True, timeout=10)
                self.assertEqual(child.returncode, 70, child.stderr.decode())
                result = b.strict_json((directory / "startup-evidence/npu-health-result-host-signal-fixture.json").read_bytes())
                self.assertEqual(result["state"], "failed_no_listen")
                self.assertFalse(result["listen_authorized"])
                self.assertFalse(result["listener_ready"])
                self.assertIn("before handoff", result["error"])
                self.assertTrue((directory / "startup-evidence/npu-health-intent-host-signal-fixture.json").is_file())
                self.assertFalse((directory / "handoff-reached.json").exists())

    def test_sigterm_after_restoration_or_result_return_terminates_before_handoff(self):
        for point in ("after_restore", "after_return"):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                child = subprocess.run([sys.executable, str(__file__), "--signal-child", point, tmp],
                                       capture_output=True, timeout=10)
                self.assertEqual(child.returncode, -signal.SIGTERM, child.stderr.decode())
                self.assertFalse((directory / "handoff-reached.json").exists())
                self.assertTrue((directory / "startup-evidence/npu-health-intent-host-signal-fixture.json").is_file())
                result_path = directory / "startup-evidence/npu-health-result-host-signal-fixture.json"
                if point == "after_return":
                    result = b.strict_json(result_path.read_bytes())
                    self.assertTrue(result["listen_authorized"])
                    self.assertFalse(result["listener_ready"])  # completed model health is not a listening service
                else:
                    self.assertFalse(result_path.exists())

    def test_ignored_or_custom_inherited_sigterm_rejected_before_model_boundary(self):
        for point in ("ignored", "custom"):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                child = subprocess.run([sys.executable, str(__file__), "--signal-child", point, tmp],
                                       capture_output=True, timeout=10)
                self.assertEqual(child.returncode, 70, child.stderr.decode())
                result = b.strict_json((directory / "startup-evidence/npu-health-result-host-signal-fixture.json").read_bytes())
                self.assertFalse(result["listen_authorized"])
                self.assertIn("may swallow shutdown", result["error"])
                self.assertFalse((directory / "model-boundary-stub-called.json").exists())
                self.assertFalse((directory / "handoff-reached.json").exists())


class StartupNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        existing.NativeIntegrationTests.setUpClass.__func__(cls)
        cls.aborting_worker = cls.root / "startup-aborting-host-worker"
        subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
            "-DHEPTA_HOST_STARTUP_ABORT", "-isystem", str(ROOT.parent / "vendor"), str(ROOT.parent / "worker.c"),
            str(HERE / "broker_stub.c"), "-o", str(cls.aborting_worker)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        existing.NativeIntegrationTests.tearDownClass.__func__(cls)

    def setUp(self):
        existing.NativeIntegrationTests.setUp(self)
        core = write(self.model / "libgeniex_core.so", b"HOST CORE IDENTITY FIXTURE")
        vlm = write(self.model / "libgeniex_vlm.so", b"HOST VLM IDENTITY FIXTURE")
        config = dataclasses.replace(self.config, grammar_profile=b.GRAMMAR_R3_PROFILE,
            core_android=str(self.model / "libgeniex_core.so"), core_sha256=b.sha(core),
            vlm_android=str(self.model / "libgeniex_vlm.so"), vlm_sha256=b.sha(vlm),
            ld_library_path=str(self.model) + ":/usr/lib:/lib", schema_compiler_sha256=COMPILER_SHA)
        self.candidate, self.config, self.boot = candidate_proof(self.directory, config, self.policy, self.transport.health())
        self.runner = b.NativeBackend(self.config, self.transport); self.counter_budget = CounterFixture(self.config)

    def run_health(self, gate=None, on_poll=None):
        return self.runner.run_startup_health(candidate=self.candidate, counter=self.counter_budget, compiler=COMPILER,
                                               gate=gate or b.CancelGate(), on_poll=on_poll)

    def test_fixed_health_uses_real_supervisor_counter_worker_and_never_user_receipt(self):
        answer = self.run_health()
        prepared = h.prepare_request(self.runner, self.candidate, self.counter_budget, COMPILER)
        proof = h.validate_answer(self.runner, prepared, answer)
        self.assertTrue(proof["answer_42_verified"]); self.assertFalse(proof["native_uid2000_npu_qualified"])
        self.assertEqual(answer["receipt"]["proof_environment"], "host_fixture")
        self.assertFalse(list(self.candidate.rglob("accepted-owner-request.json")))
        native = b.strict_json((self.config.evidence_root / prepared["request_id"] / "native-result.json").read_bytes())
        self.assertTrue(native["receipt"]["waitpid_joined"]); self.assertTrue(native["receipt"]["process_group_absent"])

    def test_native_sdk_abort_cleans_up_but_cannot_authorize_listen(self):
        self.config = dataclasses.replace(self.config, worker_android=str(self.aborting_worker), worker_sha256=b.sha(self.aborting_worker.read_bytes()))
        # New private fixture/proofs bind the changed host-only worker; not a
        # replacement of any original production result or source pin.
        self.candidate, self.config, self.boot = candidate_proof(self.directory, self.config, self.policy, self.transport.health())
        self.runner = b.NativeBackend(self.config, self.transport); self.counter_budget = CounterFixture(self.config)
        answer = self.run_health()
        self.assertEqual(answer["receipt"]["state"], "failed")
        self.assertTrue(answer["receipt"]["cleanup_confirmed"])
        self.assertFalse(answer["receipt"]["model_result_usable"])
        with self.assertRaises(b.BackendError):
            h.validate_answer(self.runner, h.prepare_request(self.runner, self.candidate, self.counter_budget, COMPILER), answer)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--signal-child":
        raise SystemExit(signal_child(sys.argv[2], sys.argv[3]))
    unit_only = "--unit-only" in sys.argv
    if unit_only: sys.argv.remove("--unit-only")
    suite = unittest.TestSuite()
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(StartupContractTests))
    if not unit_only: suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(StartupNativeTests))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
