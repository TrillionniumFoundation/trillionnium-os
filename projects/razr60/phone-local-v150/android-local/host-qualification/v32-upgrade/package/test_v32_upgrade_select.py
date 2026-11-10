"""Synthetic host guards only: no ADB, socket, real model or Android execution.

The fixture substitutes only the content hash of its synthetic 1194-file tree;
the production CLI has no override for the published content/commit anchors.
Real source_inputs and asset generation run over the complete synthetic tree.
"""
from __future__ import annotations

from contextlib import ExitStack
import copy
import hashlib
import io
import json
import importlib.util
import marshal
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

import v32_identity as identity
import select_runtime_once_v32_r1 as selector
import upgrade_v32_once_r1 as upgrade

HERE = Path(__file__).resolve().parent
# Only the three public producer files below are used as test inputs.
# This fixture is not the complete live 1194-file application source.
REAL_SOURCE = HERE.parent / "tests/fixtures/producer"
PRODUCER_PINS = {
    "tools/build_identity.py": "7d5ad2641e9a3635fd04aa47ce3ea50a1a4f16b883a98b2ab407878eef36f6e6",
    "tools/model_profiles.py": "9ba9403bdf64c2d765b31ffbbed2e95ac846f50df6ecb4e21efd4ebc926a397a",
    "tools/run_host_checks.py": "2ab4d162ddf9512df9f3bfba616559706a6fbf5e34bae1e121ff061552cbaa48",
}
for producer_name, producer_sha in PRODUCER_PINS.items():
    if hashlib.sha256((REAL_SOURCE / producer_name).read_bytes()).hexdigest() != producer_sha:
        raise RuntimeError("public test producer differs from pinned source: " + producer_name)


def deny_transport(event, args):
    if event.startswith("socket.") or event in ("subprocess.Popen", "os.system", "os.posix_spawn", "os.posix_spawnp", "os.exec", "os.fork", "os.forkpty"):
        raise RuntimeError("test process forbids real transport/child creation: " + event)


sys.addaudithook(deny_transport)
sys.dont_write_bytecode = True


def zip_bytes(members):
    value = io.BytesIO()
    with zipfile.ZipFile(value, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, raw in members.items():
            z.writestr(name, raw)
    return value.getvalue()


def write_json(path, value):
    path.write_bytes(identity.encoded(value))


class Fixture:
    def __init__(self, root):
        self.root = root
        self.source = root / "source"
        self.source.mkdir()
        self.out = root / "build"
        self.out.mkdir()
        (self.out / "dex").mkdir()
        def put(relative, raw):
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        for name in ("AndroidManifest.xml", "build_mac.py", "assemble_pocket4.py", "tools/build_identity.py",
                     "tools/verify_runtime.py", "tools/fetch_pinned_runtime.py", "tools/model_profiles.py",
                     "tools/verify_mobimind_runtime.py", "tools/verify_ui_venus_runtime.py",
                     "provenance/mobimind-worker-r4-build.json", "provenance/mobimind-worker-r4/SOURCE-MANIFEST.json"):
            put(name, b"# synthetic host fixture\n")
        put("AndroidManifest.xml", ("<manifest xmlns:android='http://schemas.android.com/apk/res/android' package='" + identity.PACKAGE
            + "' android:versionCode='32' android:versionName='" + identity.VERSION_NAME + "'><application/></manifest>\n").encode())
        put("tools/build_identity.py", (REAL_SOURCE / "tools/build_identity.py").read_bytes())
        self.profiles = {}
        scope = {}
        exec((REAL_SOURCE / "tools/model_profiles.py").read_text(), scope)
        self.profiles = scope["PROFILES"]
        put("tools/model_profiles.py", (REAL_SOURCE / "tools/model_profiles.py").read_bytes())
        put("tools/run_host_checks.py", (REAL_SOURCE / "tools/run_host_checks.py").read_bytes())
        put("tests/action-parser/ActionDecisionHostTest.java", b"// synthetic host gate input\n")
        put("tests/action-grammar/DecisionGrammarHostTest.java", b"// synthetic host gate input\n")
        for name in ("phone_acceptance", "phone_inventory", "warm_receipts"):
            put("tools/" + name + ".py", b"# synthetic host driver: deliberately no transport\n")
        # 11 fixed compile inputs plus 152 Java inputs = the real v32 count, 163.
        for i in range(152):
            put("src/Synthetic%d.java" % i, ("// synthetic %d\n" % i).encode())
        current = len([p for p in self.source.rglob("*") if p.is_file()])
        for i in range(identity.FILE_COUNT - current):
            put("fixture-docs/%04d.txt" % i, ("synthetic source fixture %d\n" % i).encode())
        rows = []
        for p in sorted((p for p in self.source.rglob("*") if p.is_file()), key=lambda p: p.relative_to(self.source).as_posix()):
            raw = p.read_bytes()
            rows.append({"path": p.relative_to(self.source).as_posix(), "bytes": len(raw), "sha256": identity.sha(raw),
                         "git_blob_sha": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()})
        self.portable = identity.sha(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode())
        self.inventory = {"schema": "hepta.independent-v32-source-integration.v1", "source_commit": identity.COMMIT,
            "source_tree": identity.TREE, "file_count": identity.FILE_COUNT, "actual_source_assembly_verified": True,
            "actual_build_input_asset": False, "portable_inventory_sha256": self.portable, "files": rows}
        self.identity_module = identity.isolated_module("synthetic_asset_producer", self.source / "tools/build_identity.py")
        self.build = {"schema": "hepta.local-model.mac-build.v2", "source_head_from_ci": identity.COMMIT,
            "runtime": "llama_cpp", "java_target": 8, "geniex_source_commit": identity.SDK_COMMIT,
            "llama_source_commit": identity.LLAMA_COMMIT, "source_inputs": self.identity_module.source_inputs(self.source),
            "model_profiles": self.profiles, "artifacts": []}
        self.artifacts = {"classes.dex": b"synthetic DEX never executed\n",
            "base.apk": zip_bytes({"AndroidManifest.xml": b"synthetic compiled XML", "resources.arsc": b"synthetic resources"}),
            "libhepta_local_runner.so": b"synthetic native worker never executed\n"}
        for name, raw in self.artifacts.items():
            p = self.out / ("dex/classes.dex" if name == "classes.dex" else name)
            p.write_bytes(raw)
            self.build["artifacts"].append({"path": "/synthetic-mac/" + name, "bytes": len(raw), "sha256": identity.sha(raw)})
        self.asset = self.identity_module.actual_build_identity(self.source, self.build)
        self.apk_members = {"AndroidManifest.xml": b"synthetic compiled XML", "resources.arsc": b"synthetic resources",
            identity.ASSET: self.asset, "classes.dex": self.artifacts["classes.dex"],
            "lib/arm64-v8a/libhepta_local_runner.so": self.artifacts["libhepta_local_runner.so"]}
        self.apk = root / "synthetic-v32.apk"
        self.old_apk = root / "synthetic-v30.apk"
        self.old_apk.write_bytes(b"retained synthetic old package")
        self.static = {"schema": "hepta.local-model.static-acceptance.v3", "package": identity.PACKAGE,
            "version_code": 32, "version_name": identity.VERSION_NAME, "permissions": [], "abi": ["arm64-v8a"],
            "actual_build_identity_asset": identity.ASSET, "actual_build_identity_sha256": identity.sha(self.asset),
            "fallback_allowed": False, "dsp_arch": "v79", "model_profiles": self.profiles,
            "libraries": [{"name": "libhepta_local_runner.so", "bytes": len(self.artifacts["libhepta_local_runner.so"]),
                           "sha256": identity.sha(self.artifacts["libhepta_local_runner.so"])}]}
        self.args = SimpleNamespace(source=self.source, source_inventory=root / "inventory.json",
            build_receipt=root / "mac-build-receipt.json", static_acceptance=root / "STATIC-ACCEPTANCE.json",
            build_output=self.out, apk=self.apk, old_apk=self.old_apk, aapt2="/usr/bin/true", apksigner="/usr/bin/true",
            profile="nanbeige4.2-3b-q4_k_m", compute="npu", context_tokens=8192, threads=4,
            adb="/usr/bin/true", adb_host="127.0.0.1", adb_port=5037, serial="SYNTHETIC_ONLY",
            command_timeout=25, execute=True, exclusive_idle_window=True, restore_observed_accessibility=False)
        (root / "host-checks").mkdir()
        self.args.host_checks = root / "host-checks/HOST-CHECKS.json"
        self.args.host_gate_qualification = root / "HOST-GATE-QUALIFICATION.json"
        inputs, names = identity.host_gate_contract(self.source)
        self.gate = {"schema": "hepta.host-checks.v3", "scope": "host_only", "all_pass": True,
                     "phone_tested": False, "external_model_used": False, "source_inputs": inputs, "checks": []}
        for name in names:
            stdout, stderr = ("synthetic host log " + name + "\n").encode(), b""
            (self.args.host_checks.parent / (name + ".stdout")).write_bytes(stdout)
            (self.args.host_checks.parent / (name + ".stderr")).write_bytes(stderr)
            self.gate["checks"].append({"name": name, "exit_code": 0, "stdout_sha256": identity.sha(stdout),
                                        "stderr_sha256": identity.sha(stderr)})
        self.gate_qualification = {"schema": "hepta.v32-applicable-host-gates.v1", "source_commit": identity.COMMIT,
            "source_tree": identity.TREE, "full_host_checks": {"schema": "hepta.host-checks.v3", "all_pass": True,
            "check_records": len(names), "all_records_exit_zero": True, "source_input_count": len(inputs),
            "source_input_set_matches_current": True, "runner_source_sha256": identity.sha((self.source / "tools/run_host_checks.py").read_bytes())},
            "historical_extra_runner": {"actual_exit": 1, "not_applicable_to_v32": True, "synthetic": True}}
        self.refresh()

    def refresh(self, apk=True):
        if apk:
            self.apk.write_bytes(zip_bytes(self.apk_members))
        self.static.update(apk_sha256=identity.sha(self.apk.read_bytes()), apk_bytes=self.apk.stat().st_size)
        for name, value in (("source_inventory", self.inventory), ("build_receipt", self.build), ("static_acceptance", self.static)):
            p = getattr(self.args, name)
            write_json(p, value)
            setattr(self.args, name + "_sha256", identity.sha(p.read_bytes()))
        self.args.apk_sha256 = self.static["apk_sha256"]
        self.args.build_asset_sha256 = identity.sha(self.asset)
        write_json(self.args.host_checks, self.gate)
        self.args.host_checks_sha256 = identity.sha(self.args.host_checks.read_bytes())
        self.gate_qualification["source_integration_sha256"] = self.args.source_inventory_sha256
        self.gate_qualification["full_host_checks"]["sha256"] = self.args.host_checks_sha256
        write_json(self.args.host_gate_qualification, self.gate_qualification)
        self.args.host_gate_qualification_sha256 = identity.sha(self.args.host_gate_qualification.read_bytes())


def control_journal():
    return {"schema": "hepta.local-session.v1", "app_uid": selector.UID, "updated_wall_ms": 1,
        "cleanup_known": True, "pending": False, "running": False, "automatic_resume": False,
        "blocked": False, "external_model": False, "state": "idle", "origin": "user_button",
        "instruction_sha256": "1" * 64, "debug_nonce_sha256": None, "status": "failed", "task_id": "2" * 32}


class FakePhone:
    def __init__(self, fixture, version=32):
        self.f = fixture
        self.version = version
        self.config = selector.encoded({"schema": "hepta.local-runtime.v2", "model_profile": "orvena-4b-q4_k_m",
            "compute": "npu", "context_tokens": 8192, "threads": 4})
        self.f.args.config_sha256 = selector.sha(self.config)
        self.control = control_journal()
        self.scope = b'{"synthetic_preserved_not_qualified":true}\n'
        self.prefs = {"enabled_accessibility_services": b"synthetic-original-services\n", "accessibility_enabled": b"1\n"}
        self.calls, self.mutations = [], []
        self.worker = False
        self.stopped = False
        self.pending = None
        self.change_on_main = None
        self.fail_mutation = None
        self.base = ["SYNTHETIC_ADB_NOT_EXECUTABLE"]

    def app_bytes(self, relative, optional=False):
        if relative == selector.TARGET:
            return self.config
        if relative == "files/control-session.json":
            return selector.encoded(self.control)
        if relative == "files/" + selector.SCOPE_FILE:
            return self.scope
        if relative in ("files/mobi-probe-session.json", "files/ui-venus-probe-session.json"):
            if optional:
                return None
            raise RuntimeError("synthetic absent optional journal")
        raise AssertionError("unexpected private read: " + relative)

    def command(self, words, label="command", input_data=None, allowed=(0,), **kwargs):
        self.calls.append((label, words, input_data))
        if words[:3] == ["am", "force-stop", "--user"]:
            self.mutations.append(label)
            if self.fail_mutation == "stop":
                raise RuntimeError("synthetic timeout; phone-side stop outcome unknown")
            self.stopped = True
            return 0, b""
        if words == selector.MAIN:
            self.mutations.append(label)
            self.stopped = False
            if self.change_on_main == "journal":
                self.control["running"] = True
            if self.change_on_main == "scope":
                self.scope = b"changed"
            return 0, b"Status: ok\n"
        if words == ["am", "get-current-user"]:
            return 0, b"0\n"
        if words == ["getprop", "ro.soc.model"]:
            return 0, b"SM8750\n"
        if words[:2] == ["pm", "path"]:
            return 0, b"package:/data/app/synthetic/base.apk\n"
        if words[:1] == ["sha256sum"]:
            value = upgrade.OLD_APK_SHA if self.version == 30 else self.f.args.apk_sha256
            return 0, (value + "  " + words[1] + "\n").encode()
        if words[:2] == ["dumpsys", "package"]:
            return 0, selector.encoded({"version_code": self.version,
                "version_name": identity.VERSION_NAME if self.version == 32 else "0.30.0-local-exact-admission",
                "app_id": selector.UID, "current_user_installed": True, "internet_permission_declared": False,
                "requested_permissions": []})
        if words[:1] == ["ps"]:
            return 0, b"PID PPID UID NAME ARGS\n" + (b"10 1 10481 libhepta_local_runner.so\n" if self.worker else b"")
        if words[:1] == ["settings"]:
            return 0, self.prefs[words[-1]]
        if words[:1] == ["pidof"]:
            return (1, b"") if self.stopped else (0, b"4321\n")
        if words[:1] == ["run-as"]:
            script = words[-1]
            if script == "id -u":
                return 0, b"10481\n"
            if "cat > " in script:
                self.mutations.append(label)
                self.pending = input_data
                return 0, b""
            if "mv -f " in script:
                self.mutations.append(label)
                if self.fail_mutation == "rename":
                    raise RuntimeError("synthetic rename timeout; outcome unknown")
                self.config = self.pending
                return 0, b"REPLACED\n"
            if script.startswith("sha256sum "):
                filename = script.split("/")[-1].strip("'")
                profile = next(row for row in self.f.profiles.values() if row["file"] == filename)
                return 0, (profile["sha256"] + "  synthetic-model\n").encode()
            if "stat -c '%i %s %Y %Z'" in script:
                return 0, b"123 2783447904 1 1\n"
            return 0, b""
        if words == ["dumpsys", "SurfaceFlinger", "--display-id"]:
            return 0, b"synthetic display\n"
        if words == ["wm", "size"]:
            return 0, b"synthetic size\n"
        raise AssertionError("unexpected command: " + repr(words))

    def modules(self):
        acceptance = SimpleNamespace(Adb=lambda args, output: self)
        inventory = SimpleNamespace(validate_connection=lambda args: None,
            require_existing_adb_server=lambda *args: {"synthetic_existing_server": True},
            parse_package_dump=lambda raw, user: selector.strict(raw))
        profiles = SimpleNamespace(profile=lambda name: dict(self.f.profiles[name]))
        return acceptance, inventory, profiles


class HostGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-v32-synthetic-")
        self.root = Path(self.temp.name)
        self.f = Fixture(self.root)
        self.stack = ExitStack()
        self.stack.enter_context(patch.object(identity, "PORTABLE_SHA", self.f.portable))
        self.saved_modules = {name: sys.modules.pop(name, None) for name in identity.HELPERS}
        self.old_path = list(sys.path)
        self.output = self.root / "evidence"
        self.output.mkdir(mode=0o700)
        self.f.args.output = self.output

    def tearDown(self):
        for name, previous in self.saved_modules.items():
            sys.modules.pop(name, None)
            if previous is not None:
                sys.modules[name] = previous
        sys.path[:] = self.old_path
        self.stack.close()
        self.temp.cleanup()

    def load(self):
        return selector.load_source(self.f.args)

    def host_report(self, proof, pins):
        return {"host_build_identity": proof, "_source_pins": pins,
                "host_apk_permission_evidence": {"apk_sha256": self.f.args.apk_sha256, "internet_permission_declared": False}}

    def test_complete_source_receipt_asset_and_payload_chain(self):
        modules, pins, proof = self.load()
        self.assertEqual(len(pins), 1194)
        self.assertEqual(proof["actual_build_source_input_count"], 163)
        self.assertTrue(proof["actual_signed_apk_payload_verified"])
        self.assertFalse(proof["phone_contacted"])
        self.assertFalse(proof["host_signature_independently_verified"])

    def test_inventory_rejects_wrong_generation_commit_count_and_boolean(self):
        original = copy.deepcopy(self.f.inventory)
        for changes in ({"schema": "hepta.local-source.v3"}, {"source_commit": "0" * 40},
                        {"file_count": 1193}, {"actual_source_assembly_verified": 1}):
            with self.subTest(changes=changes):
                self.f.inventory = {**original, **changes}
                self.f.refresh()
                with self.assertRaises(RuntimeError):
                    self.load()

    def test_expected_prediction_is_not_actual_inventory(self):
        self.f.inventory["schema"] = "hepta.expected-source-inventory.v1"
        self.f.inventory["actual_source_assembly_verified"] = False
        self.f.refresh()
        with self.assertRaises(RuntimeError):
            self.load()

    def test_source_file_mutation_is_rejected(self):
        (self.f.source / "src/Synthetic0.java").write_bytes(b"changed")
        with self.assertRaisesRegex(RuntimeError, "source differs"):
            self.load()

    def test_extra_importable_driver_is_rejected(self):
        (self.f.source / "tools/extra.py").write_text("raise RuntimeError('must not import')")
        with self.assertRaisesRegex(RuntimeError, "unlisted importable"):
            self.load()

    def test_added_compile_input_is_rejected(self):
        (self.f.source / "src/Unlisted.java").write_text("// unlisted")
        with self.assertRaisesRegex(RuntimeError, "compiler source inputs"):
            self.load()

    def test_stale_compiler_commit_and_input_map_are_rejected(self):
        self.f.build["source_head_from_ci"] = "0" * 40
        self.f.refresh()
        with self.assertRaisesRegex(RuntimeError, "compiler receipt"):
            self.load()
        self.f.build["source_head_from_ci"] = identity.COMMIT
        self.f.build["source_inputs"][0]["sha256"] = "0" * 64
        self.f.refresh()
        with self.assertRaisesRegex(RuntimeError, "compiler source inputs"):
            self.load()

    def test_asset_in_signed_apk_must_equal_real_compiler_inputs(self):
        self.f.apk_members[identity.ASSET] = b'{"schema":"hepta.actual-build-inputs.v1","version_code":32}\n'
        self.f.refresh()
        with self.assertRaisesRegex(RuntimeError, "asset differs"):
            self.load()

    def test_dex_and_base_resources_are_bound_to_compiler_outputs(self):
        for name in ("classes.dex", "resources.arsc"):
            with self.subTest(name=name):
                before = self.f.apk_members[name]
                self.f.apk_members[name] = b"uncompiled payload"
                self.f.refresh()
                with self.assertRaises(RuntimeError):
                    self.load()
                self.f.apk_members[name] = before

    def test_extra_dex_and_native_library_cannot_bypass_payload_closure(self):
        for name in ("classes2.dex", "lib/arm64-v8a/libextra.so"):
            with self.subTest(name=name):
                self.f.apk_members[name] = b"not compiled"
                self.f.refresh()
                with self.assertRaises(RuntimeError):
                    self.load()
                del self.f.apk_members[name]

    def test_actual_static_receipt_and_external_hash_required(self):
        self.f.static["permissions"] = ["android.permission.INTERNET"]
        self.f.refresh()
        with self.assertRaisesRegex(RuntimeError, "static acceptance"):
            self.load()
        self.f.static["permissions"] = []
        self.f.refresh()
        self.f.args.static_acceptance_sha256 = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "proof SHA"):
            self.load()

    def test_other_source_preloaded_driver_is_rejected(self):
        sys.modules["phone_acceptance"] = SimpleNamespace(__file__="/synthetic-other-source/phone_acceptance.py")
        with self.assertRaisesRegex(RuntimeError, "different source"):
            self.load()

    def test_unlisted_timestamp_valid_bytecode_cannot_replace_verified_source(self):
        for name in ("build_identity", "phone_acceptance"):
            path = self.f.source / "tools" / (name + ".py")
            cache = Path(importlib.util.cache_from_source(str(path)))
            cache.parent.mkdir(exist_ok=True)
            source_stat = path.stat()
            header = importlib.util.MAGIC_NUMBER + struct.pack("<III", 0, int(source_stat.st_mtime), source_stat.st_size)
            code = compile("raise RuntimeError('unverified bytecode executed')", str(path), "exec")
            cache.write_bytes(header + marshal.dumps(code))
        self.assertTrue(self.load()[2]["actual_complete_source_files_verified"])

    def test_upgrade_loader_executes_verified_selector_bytes_not_unlisted_bytecode(self):
        helper = self.root / "isolated-helper"
        helper.mkdir()
        path = helper / "select_runtime_once_v32_r1.py"
        path.write_bytes((HERE / path.name).read_bytes())
        cache = Path(importlib.util.cache_from_source(str(path)))
        cache.parent.mkdir()
        source_stat = path.stat()
        header = importlib.util.MAGIC_NUMBER + struct.pack("<III", 0, int(source_stat.st_mtime), source_stat.st_size)
        cache.write_bytes(header + marshal.dumps(compile("raise RuntimeError('unverified selector bytecode executed')", str(path), "exec")))
        FakePhone(self.f)
        with patch.object(upgrade, "__file__", str(helper / "upgrade_v32_once_r1.py")):
            self.assertTrue(upgrade.load(self.f.args)[3]["actual_complete_source_files_verified"])

    def test_symlinked_source_member_is_rejected(self):
        p = self.f.source / "src/Synthetic0.java"
        raw = p.read_bytes()
        p.unlink()
        target = self.root / "elsewhere.java"
        target.write_bytes(raw)
        p.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, "non-symlink"):
            self.load()

    def test_source_recheck_after_idle_detects_mutation(self):
        modules, pins, proof = self.load()
        (self.f.source / "src/Synthetic1.java").write_text("changed after first proof")
        with self.assertRaises(RuntimeError):
            identity.recheck_bundle(self.f.args, pins, proof)

    def test_original_host_gate_sequence_and_exit_must_match_not_only_summary(self):
        original = copy.deepcopy(self.f.gate)
        for kind in ("missing", "nonzero", "bool_exit", "wrong_inputs"):
            with self.subTest(kind=kind):
                self.f.gate = copy.deepcopy(original)
                if kind == "missing":
                    self.f.gate["checks"].pop()
                elif kind == "nonzero":
                    self.f.gate["checks"][0]["exit_code"] = 1
                elif kind == "bool_exit":
                    self.f.gate["checks"][0]["exit_code"] = False
                else:
                    self.f.gate["source_inputs"][0]["sha256"] = "0" * 64
                self.f.refresh()
                with self.assertRaises(RuntimeError):
                    self.load()

    def test_original_host_gate_logs_cannot_be_replaced_after_receipt(self):
        (self.f.args.host_checks.parent / "java-compile.stdout").write_text("different log")
        with self.assertRaisesRegex(RuntimeError, "log differs"):
            self.load()

    def test_applicable_gate_requires_actual_inventory_and_runner_hash(self):
        for field in ("runner_source_sha256", "all_records_exit_zero"):
            with self.subTest(field=field):
                previous = self.f.gate_qualification["full_host_checks"][field]
                self.f.gate_qualification["full_host_checks"][field] = "0" * 64 if field.endswith("sha256") else 1
                self.f.refresh()
                with self.assertRaisesRegex(RuntimeError, "qualification differs"):
                    self.load()
                self.f.gate_qualification["full_host_checks"][field] = previous

    def test_duplicate_json_and_nonfinite_refused(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises((RuntimeError, ValueError)):
                identity.strict(raw)

    def test_clean_idle_contract_rejects_running_pending_unknown_and_acknowledged(self):
        self.assertTrue(selector.clean_journal(control_journal(), 0))
        self.assertTrue(selector.clean_journal(None, 0))
        for changes in ({"running": True}, {"pending": True}, {"blocked": True}, {"cleanup_known": False},
                        {"cleanup_known": 1}, {"automatic_resume": True}, {"status": "acknowledged_idle"}, {"app_uid": 1}):
            with self.subTest(changes=changes):
                self.assertFalse(selector.clean_journal({**control_journal(), **changes}, 0))

    def test_config_contract_admits_only_explicit_new_nano_npu_profile(self):
        modules, _, _ = self.load()
        cfg, profile = selector.config_for(self.f.args, modules[2])
        self.assertEqual(cfg["model_profile"], "nanbeige4.2-3b-q4_k_m")
        self.assertEqual(profile["architecture"], "nanbeige")
        for changes in ({"profile": "spark-x2.6-4b-q4_k_m"}, {"threads": True}, {"context_tokens": 4097}, {"context_tokens": 8192.0}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                selector.config_for(SimpleNamespace(**{**vars(self.f.args), **changes}), modules[2])

    def test_private_replace_rechecks_config_journals_scope_and_private_temp(self):
        old, new = b"old-config", b"new-config"
        scope = b"preserved-scope"
        script = selector.replace_script("files/model/.runtime-select-synthetic.tmp", old, new,
            {"control-session.json": b"known-clean", selector.SCOPE_FILE: scope, "mobi-probe-session.json": None})
        for value in (selector.sha(old), selector.sha(new), selector.sha(scope), selector.sha(b"known-clean")):
            self.assertIn(value, script)
        self.assertIn("mv -f", script)
        self.assertNotIn("rm ", script)
        self.assertIn("test ! -e files/mobi-probe-session.json", script)
        with self.assertRaises(RuntimeError):
            selector.replace_script("../../bad", old, new, {})

    def test_accessibility_restoration_requires_exact_observed_preference(self):
        original = {"enabled_accessibility_services": b"synthetic-list\n", "accessibility_enabled": b"1\n"}
        selector.observed_stop_preferences(original, original, False)
        wrong = {**original, "enabled_accessibility_services": b"unrelated-list\n"}
        with self.assertRaises(RuntimeError):
            selector.observed_stop_preferences(original, wrong, False)
        with self.assertRaises(RuntimeError):
            selector.observed_stop_preferences(original, original, True)
        with patch.object(selector, "ORIGINAL_SERVICES_SHA", selector.sha(original["enabled_accessibility_services"])):
            observed = {**original, "enabled_accessibility_services": selector.STOPPED_SERVICES[0]}
            script = selector.restore_services_script(observed, original)
            self.assertIn("settings --user 0 put secure enabled_accessibility_services", script)
            self.assertNotIn("put secure accessibility_enabled", script)
            with self.assertRaises(RuntimeError):
                selector.observed_stop_preferences(original, wrong, True)

    def test_single_signature_matches_original_and_rejects_other_or_multiple_signers(self):
        correct = b"Signer #1 certificate SHA-256 digest: " + identity.CERT_SHA.encode() + b"\n"
        for number, (stdout, code, expected) in enumerate(((correct, 0, True),
                (correct.replace(identity.CERT_SHA.encode(), b"0" * 64), 0, False),
                (correct + correct.replace(b"#1", b"#2"), 0, False), (correct, 1, False))):
            with self.subTest(number=number), patch.object(identity.subprocess, "run", return_value=SimpleNamespace(stdout=stdout, stderr=b"", returncode=code)):
                if expected:
                    self.assertTrue(identity.verify_signature(self.f.apk, self.f.args.apk_sha256, "/usr/bin/true", self.output, str(number))["signature_verified"])
                else:
                    with self.assertRaises(RuntimeError):
                        identity.verify_signature(self.f.apk, self.f.args.apk_sha256, "/usr/bin/true", self.output, str(number))

    def test_selector_success_one_stop_one_rename_normal_main_and_no_task(self):
        modules, pins, proof = self.load()
        phone = FakePhone(self.f)
        report = self.host_report(proof, pins)
        selector.execute(self.f.args, self.output, phone.modules(), *selector.config_for(self.f.args, modules[2]), report)
        self.assertEqual(report["status"], "configuration_verified")
        self.assertEqual(phone.mutations, ["01-force-stop", "02-create-private-temp", "03-atomic-replace", "05-normal-main"])
        self.assertEqual(selector.strict(phone.config)["model_profile"], "nanbeige4.2-3b-q4_k_m")
        self.assertTrue(report["qualification_scope_file_unchanged"])
        self.assertEqual([words for label, words, data in phone.calls if words[:2] == ["am", "start"]], [selector.MAIN])
        self.assertNotIn("auto_", repr(phone.calls))

    def test_selector_busy_journal_or_native_worker_blocks_every_mutation(self):
        modules, pins, proof = self.load()
        for kind in ("journal", "worker"):
            with self.subTest(kind=kind):
                folder = self.output / kind
                folder.mkdir()
                phone = FakePhone(self.f)
                if kind == "journal":
                    phone.control["running"] = True
                else:
                    phone.worker = True
                with self.assertRaises(RuntimeError):
                    selector.execute(self.f.args, folder, phone.modules(), *selector.config_for(self.f.args, modules[2]), self.host_report(proof, pins))
                self.assertEqual(phone.mutations, [])

    def test_selector_stop_timeout_retains_intent_without_second_stop_or_replace(self):
        modules, pins, proof = self.load()
        phone = FakePhone(self.f)
        phone.fail_mutation = "stop"
        with self.assertRaisesRegex(RuntimeError, "unknown"):
            selector.execute(self.f.args, self.output, phone.modules(), *selector.config_for(self.f.args, modules[2]), self.host_report(proof, pins))
        self.assertEqual(phone.mutations, ["01-force-stop"])
        self.assertTrue((self.output / "01-force-stop.intent.json").is_file())
        self.assertFalse((self.output / "01-force-stop.returned.json").exists())
        self.assertFalse((self.output / "candidate.json").exists())

    def test_selector_post_main_scope_or_journal_change_never_publishes_candidate(self):
        modules, pins, proof = self.load()
        for change in ("scope", "journal"):
            with self.subTest(change=change):
                folder = self.output / change
                folder.mkdir()
                phone = FakePhone(self.f)
                phone.change_on_main = change
                report = self.host_report(proof, pins)
                with self.assertRaises(RuntimeError):
                    selector.execute(self.f.args, folder, phone.modules(), *selector.config_for(self.f.args, modules[2]), report)
                self.assertTrue(report["configuration_replacement_verified"])
                self.assertFalse((folder / "candidate.json").exists())
                self.assertEqual(phone.mutations.count("01-force-stop"), 1)

    def test_upgrade_success_keeps_runtime_and_journals_and_has_no_force_stop(self):
        modules, pins, proof = self.load()
        phone = FakePhone(self.f, 30)
        initial = phone.config
        upgrade.NEW_APK_SHA = self.f.args.apk_sha256
        upgrade.CONFIG_SHA = self.f.args.config_sha256
        report = {"host_build_identity": proof, "host_apks": {"new_permission_evidence": {"apk_sha256": self.f.args.apk_sha256,
                  "internet_permission_declared": False}, "old": {}, "new": {}}}
        for label, p, digest in (("old", self.f.old_apk, upgrade.OLD_APK_SHA), ("new", self.f.apk, upgrade.NEW_APK_SHA)):
            report["host_apks"][label]["stat"] = list(identity.stat_key(p.stat()))
        def install(args, output, b, adb, report):
            report["install_invocation_attempted"] = True
            phone.mutations.append("install")
            phone.version = 32
        with patch.object(upgrade, "file_identity", side_effect=lambda b, path, digest: identity.stat_key(path.stat())), patch.object(upgrade, "install_once", side_effect=install):
            upgrade.execute(self.f.args, self.output, (selector, phone.modules(), pins, proof), report)
        self.assertEqual(report["status"], "upgrade_verified")
        self.assertEqual(phone.config, initial)
        self.assertEqual(phone.mutations, ["install", "02-normal-main"])
        self.assertTrue(report["journals_unchanged"])
        self.assertTrue(report["qualification_scope_file_unchanged"])
        candidate = selector.strict((self.output / "candidate.json").read_bytes())
        self.assertEqual(candidate["actual_build_identity_sha256"], self.f.args.build_asset_sha256)

    def test_install_timeout_is_once_unknown_with_durable_intent(self):
        phone = FakePhone(self.f, 30)
        report = {}
        with patch.object(upgrade.subprocess, "run", side_effect=subprocess.TimeoutExpired(["synthetic-install"], 120, output=b"partial")) as run:
            with self.assertRaisesRegex(RuntimeError, "unknown, no retry"):
                upgrade.install_once(self.f.args, self.output, selector, phone, report)
        self.assertEqual(run.call_count, 1)
        self.assertTrue(report["install_invocation_attempted"])
        self.assertTrue((self.output / "01-install.intent.json").is_file())
        result = selector.strict((self.output / "01-install.returned.json").read_bytes())
        self.assertIsNone(result["exit_code"])
        self.assertEqual(result["phone_outcome"], "unknown")

    def test_install_acknowledgement_is_not_installed_identity_proof(self):
        phone = FakePhone(self.f, 30)
        for number, (code, stdout, accepted) in enumerate(((0, b"Success\n", True), (0, b"partial\n", False), (1, b"Success\n", False))):
            with self.subTest(number=number):
                folder = self.output / str(number)
                folder.mkdir()
                report = {}
                with patch.object(upgrade.subprocess, "run", return_value=SimpleNamespace(returncode=code, stdout=stdout, stderr=b"")) as run:
                    if accepted:
                        upgrade.install_once(self.f.args, folder, selector, phone, report)
                        self.assertTrue(report["install_success_acknowledged"])
                    else:
                        with self.assertRaises(RuntimeError):
                            upgrade.install_once(self.f.args, folder, selector, phone, report)
                self.assertEqual(run.call_count, 1)
                returned = identity.strict((folder / "01-install.returned.json").read_bytes())
                self.assertIs(returned["installed_identity_verified"], False)

    def test_upgrade_private_state_change_after_install_blocks_launch_and_candidate(self):
        modules, pins, proof = self.load()
        phone = FakePhone(self.f, 30)
        upgrade.NEW_APK_SHA = self.f.args.apk_sha256
        upgrade.CONFIG_SHA = self.f.args.config_sha256
        report = {"host_build_identity": proof, "host_apks": {"new_permission_evidence": {
            "apk_sha256": self.f.args.apk_sha256, "internet_permission_declared": False},
            "old": {"stat": list(identity.stat_key(self.f.old_apk.stat()))},
            "new": {"stat": list(identity.stat_key(self.f.apk.stat()))}}}
        def changed_install(args, output, b, adb, report):
            report["install_invocation_attempted"] = True
            phone.mutations.append("install")
            phone.version = 32
            phone.scope = b"unexpected change"
        with patch.object(upgrade, "file_identity", side_effect=lambda b, path, digest: identity.stat_key(path.stat())), patch.object(upgrade, "install_once", side_effect=changed_install):
            with self.assertRaisesRegex(RuntimeError, "install changed"):
                upgrade.execute(self.f.args, self.output, (selector, phone.modules(), pins, proof), report)
        self.assertEqual(phone.mutations, ["install"])
        self.assertFalse((self.output / "candidate.json").exists())
        self.assertNotIn("install_readback_verified", report)

    def test_frozen_selector_hash_and_normal_main_argv(self):
        self.assertEqual(identity.sha((HERE / "select_runtime_once_v32_r1.py").read_bytes()), upgrade.SELECTOR_SHA)
        self.assertEqual(selector.MAIN, ["am", "start", "-W", "--user", "0", "-a", "android.intent.action.MAIN", "-c",
            "android.intent.category.LAUNCHER", "-n", identity.PACKAGE + "/.MainActivity"])
        self.assertNotIn("SOURCE-MANIFEST.json", selector.load_source.__code__.co_consts)

    def test_default_plan_uses_only_host_tools_and_never_contacts_phone(self):
        FakePhone(self.f)  # supplies a synthetic current configuration SHA only
        output = self.output / "plan"
        args = []
        for name in ("source", "source_inventory", "source_inventory_sha256", "build_receipt", "build_receipt_sha256",
                     "static_acceptance", "static_acceptance_sha256", "build_output", "apk", "apk_sha256", "build_asset_sha256",
                     "host_checks", "host_checks_sha256", "host_gate_qualification", "host_gate_qualification_sha256", "aapt2", "apksigner",
                     "profile", "compute", "context_tokens", "threads", "config_sha256"):
            args += ["--" + name.replace("_", "-"), str(getattr(self.f.args, name))]
        args += ["--output", str(output)]
        calls = []
        def host_only(argv, **kwargs):
            calls.append(argv)
            if "verify" in argv:
                raw = b"Signer #1 certificate SHA-256 digest: " + identity.CERT_SHA.encode() + b"\n"
            elif "badging" in argv:
                raw = ("package: name='" + identity.PACKAGE + "' versionCode='32' versionName='" + identity.VERSION_NAME
                       + "'\nnative-code: 'arm64-v8a'\n").encode()
            elif "permissions" in argv:
                raw = ("package: " + identity.PACKAGE + "\n").encode()
            elif "xmltree" in argv:
                raw = b"E: manifest\n"
            else:
                raise AssertionError("not a host-only APK operation")
            return SimpleNamespace(returncode=0, stdout=raw, stderr=b"")
        with patch.object(sys, "argv", [str(HERE / "select_runtime_once_v32_r1.py"), *args]), patch.object(subprocess, "run", side_effect=host_only):
            self.assertEqual(selector.main(), 0)
        result = identity.strict((output / "RESULT.json").read_bytes())
        self.assertEqual(result["status"], "planned")
        self.assertFalse(result["phone_contacted"])
        self.assertEqual(len(calls), 4)
        self.assertFalse((output / "candidate.json").exists())
        self.assertTrue(result["host_build_identity"]["host_signature_independently_verified"])

    def test_upgrade_default_plan_verifies_both_host_certificates_without_adb(self):
        FakePhone(self.f)
        args = []
        for name in ("source", "source_inventory", "source_inventory_sha256", "build_receipt", "build_receipt_sha256",
                     "static_acceptance", "static_acceptance_sha256", "build_output", "apk", "apk_sha256", "build_asset_sha256",
                     "host_checks", "host_checks_sha256", "host_gate_qualification", "host_gate_qualification_sha256", "aapt2", "apksigner",
                     "old_apk", "config_sha256"):
            args += ["--" + name.replace("_", "-"), str(getattr(self.f.args, name))]
        output = self.output / "upgrade-plan"
        args += ["--output", str(output)]
        calls = []
        def host_only(argv, **kwargs):
            calls.append(argv)
            if "verify" in argv:
                raw = b"Signer #1 certificate SHA-256 digest: " + identity.CERT_SHA.encode() + b"\n"
            elif "badging" in argv:
                raw = ("package: name='" + identity.PACKAGE + "' versionCode='32' versionName='" + identity.VERSION_NAME
                       + "'\nnative-code: 'arm64-v8a'\n").encode()
            elif "permissions" in argv:
                raw = ("package: " + identity.PACKAGE + "\n").encode()
            elif "xmltree" in argv:
                raw = b"E: manifest\n"
            else:
                raise AssertionError("not a host-only APK operation")
            return SimpleNamespace(returncode=0, stdout=raw, stderr=b"")
        with patch.object(sys, "argv", [str(HERE / "upgrade_v32_once_r1.py"), *args]), patch.object(subprocess, "run", side_effect=host_only), patch.object(upgrade, "OLD_APK_SHA", identity.sha(self.f.old_apk.read_bytes())):
            self.assertEqual(upgrade.main(), 0)
        result = identity.strict((output / "RESULT.json").read_bytes())
        self.assertEqual(result["status"], "planned")
        self.assertFalse(result["phone_contacted"])
        self.assertEqual(len(calls), 5)
        self.assertFalse(result["install_invocation_attempted"])
        self.assertTrue(result["host_apks"]["old"]["signature_verified"])
        self.assertTrue(result["host_apks"]["new"]["signature_verified"])
        self.assertFalse((output / "candidate.json").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
