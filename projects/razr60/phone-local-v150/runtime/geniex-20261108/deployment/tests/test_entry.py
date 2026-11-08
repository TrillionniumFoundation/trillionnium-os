#!/usr/bin/env python3
"""Host contract tests; never claim Android init, capabilities or NPU execution."""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parents[1]
PHONE = HERE.parents[2]
VENDOR = PHONE / "executor/r6/vendor"
spec = importlib.util.spec_from_file_location("candidate_provider_entry", HERE / "provider_entry.py")
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)


def launch_value():
    names = ["daily_phone_local.py", "native_backend.py", "provider_bridge.py", "prompt_budget.py",
             "provider_phone_local.py", "provider_codex_host.py", "action_ledger.py", "phone_local_tools.py",
             "phone_observation_tools.py", "task_postconditions.py", "startup_health.py"]
    return {"schema": "hepta.geniex-provider-start.v1", "instance": "a" * 32,
            "source_sha256": {name: "1" * 64 for name in names}, "base_config_sha256": "2" * 64,
            "geniex_config_sha256": "3" * 64, "retained_claims_sha256": "4" * 64,
            "stage": {"st_dev": 10, "st_ino": 20}, "mode": "preflight_only"}


def native_value():
    launch = launch_value()
    files = {"source/" + name: {"bytes": 1, "sha256": digest} for name, digest in launch["source_sha256"].items()}
    for name in ("startup/provider_entry.py", "startup/provider-start.json", "local-config-base.json",
                 "geniex-config.json", "ARTIFACT-MANIFEST.json"):
        files[name] = {"bytes": 1, "sha256": "5" * 64}
    return {"schema": "hepta.init-owned-geniex-provider.v1", "instance": "a" * 32,
            "rootfs_python": {"bytes": 100, "sha256": "6" * 64}, "files": files,
            "stage": {"st_dev": 10, "st_ino": 20}, "retained_claims_sha256": "4" * 64,
            "launch_config_sha256": "5" * 64}


class NativeEntryContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hepta-entry-contract-")
        cls.root = Path(cls.temporary.name)
        cls.binary = cls.root / "entry-parser"
        commands = [
            ["cc", "-O1", "-c", str(VENDOR / "hash/sha256/sha256.c"), "-I" + str(VENDOR / "hash"),
             "-o", str(cls.root / "sha.o")],
            ["c++", "-std=c++17", "-O1", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
             "-DHEPTA_ENTRY_HOST_FIXTURE", "-I" + str(VENDOR), str(HERE / "provider_entry.cpp"),
             str(VENDOR / "hash/hash.cpp"), str(cls.root / "sha.o"), "-o", str(cls.binary)],
            ["c++", "-std=c++17", "-O1", "-Wall", "-Wextra", "-Werror", "-Wpedantic", "-I" + str(VENDOR),
             "-c", str(HERE / "provider_entry.cpp"), "-o", str(cls.root / "production-entry.o")],
        ]
        for command in commands:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            if result.returncode:
                raise RuntimeError(result.stderr.decode(errors="replace"))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def call(self, value=None, *, raw=None, digest=None, mode=0o600):
        raw = raw if raw is not None else json.dumps(value).encode()
        with tempfile.NamedTemporaryFile(dir=self.root, delete=False) as stream:
            stream.write(raw)
            path = Path(stream.name)
        path.chmod(mode)
        try:
            return subprocess.run([str(self.binary), "--parse-fixture", str(path),
                                   digest or hashlib.sha256(raw).hexdigest()], capture_output=True, timeout=3)
        finally:
            path.unlink()

    def test_valid_plan_is_explicitly_parser_only(self):
        result = self.call(native_value())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"HOST_CONTRACT_ONLY_NO_CHROOT_NO_SERVICE\n")

    def test_plan_digest_and_private_file_mode_are_enforced(self):
        self.assertNotEqual(self.call(native_value(), digest="0" * 64).returncode, 0)
        self.assertNotEqual(self.call(native_value(), mode=0o644).returncode, 0)

    def test_duplicate_key_rejected_even_with_matching_raw_sha(self):
        raw = json.dumps(native_value()).encode().replace(b'"schema":', b'"instance":"b","schema":', 1)
        result = self.call(raw=raw)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"duplicate_json_key", result.stderr)

    def test_unknown_config_fields_and_paths_do_not_become_commands(self):
        for field, value in (("command", "true"), ("uid", 2000), ("context", "u:r:magisk:s0")):
            candidate = native_value(); candidate[field] = value
            with self.subTest(field=field):
                self.assertNotEqual(self.call(candidate).returncode, 0)
        for path in ("source/../arbitrary.py", "source/a/b.py", "startup/other.py", "source/a.py\n"):
            candidate = native_value(); candidate["files"][path] = {"bytes": 1, "sha256": "5" * 64}
            with self.subTest(path=path):
                self.assertNotEqual(self.call(candidate).returncode, 0)

    def test_stage_integer_types_and_instance_are_not_coerced(self):
        for replacement in (True, -1, "20", 1.0, None):
            candidate = native_value(); candidate["stage"]["st_ino"] = replacement
            with self.subTest(replacement=replacement):
                self.assertNotEqual(self.call(candidate).returncode, 0)
        candidate = native_value(); candidate["instance"] = "A" * 32
        self.assertNotEqual(self.call(candidate).returncode, 0)

    def test_missing_entry_and_disagreeing_launch_pin_rejected(self):
        candidate = native_value(); del candidate["files"]["source/native_backend.py"]
        self.assertNotEqual(self.call(candidate).returncode, 0)
        candidate = native_value(); candidate["launch_config_sha256"] = "6" * 64
        self.assertNotEqual(self.call(candidate).returncode, 0)

    def test_json_depth_bounded_before_any_activation(self):
        raw = (b'"x"')
        for _ in range(50):
            raw = b'{"x":' + raw + b'}'
        result = self.call(raw=raw)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"json_depth_limit", result.stderr)

    def test_actual_immutable_python_mode_is_accepted(self):
        with tempfile.TemporaryDirectory(dir=self.root) as tmp:
            path = Path(tmp) / "python3"; raw = b"HOST_FILE_IDENTITY_FIXTURE_NOT_AN_INTERPRETER"
            path.write_bytes(raw); path.chmod(0o555)
            result = subprocess.run([str(self.binary), "--python-file-fixture", str(path),
                                     hashlib.sha256(raw).hexdigest()], capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"HOST_FILE_IDENTITY_ONLY_NO_CHROOT_NO_SERVICE\n")

    def test_python_file_checker_rejects_symlink_or_writable_mode(self):
        with tempfile.TemporaryDirectory(dir=self.root) as tmp:
            target = Path(tmp) / "python3.real"; raw = b"HOST_FILE_IDENTITY_FIXTURE_NOT_AN_INTERPRETER"
            target.write_bytes(raw); target.chmod(0o555)
            link = Path(tmp) / "python3"; link.symlink_to(target)
            argv = [str(self.binary), "--python-file-fixture", str(link), hashlib.sha256(raw).hexdigest()]
            self.assertNotEqual(subprocess.run(argv, capture_output=True, timeout=3).returncode, 0)
            link.unlink(); target.rename(link)
            for mode in (0o755, 0o644, 0o777):
                link.chmod(mode)
                self.assertNotEqual(subprocess.run(argv, capture_output=True, timeout=3).returncode, 0)


class PythonEntryContract(unittest.TestCase):
    def test_explicit_preflight_and_serve_modes(self):
        for mode in ("preflight_only", "serve"):
            value = launch_value(); value["mode"] = mode
            self.assertIs(entry.config_contract(value), value)

    def test_no_shell_argv_uid_or_context_override(self):
        for key, value in (("argv", ["/bin/sh"]), ("uid", 2000), ("context", "u:r:magisk:s0")):
            candidate = launch_value(); candidate[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                entry.config_contract(candidate)

    def test_sources_must_be_complete_pinned_python_basenames(self):
        candidate = launch_value(); del candidate["source_sha256"]["daily_phone_local.py"]
        with self.assertRaises(RuntimeError):
            entry.config_contract(candidate)
        for path in ("../unsafe.py", "a/b.py", "x;true.py", "x.py\n"):
            candidate = launch_value(); candidate["source_sha256"][path] = "a" * 64
            with self.subTest(path=path), self.assertRaises(RuntimeError):
                entry.config_contract(candidate)

    def test_stage_bool_and_unknown_modes_rejected(self):
        for change in ({"st_dev": False, "st_ino": 20}, {"st_dev": 10, "st_ino": "20"}):
            candidate = launch_value(); candidate["stage"] = change
            with self.assertRaises(RuntimeError):
                entry.config_contract(candidate)
        candidate = launch_value(); candidate["mode"] = "serve_with_cpu_fallback"
        with self.assertRaises(RuntimeError):
            entry.config_contract(candidate)

    def test_duplicate_and_nonfinite_json_rejected(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            with self.assertRaises((RuntimeError, ValueError)):
                entry.strict_json(raw)

    def post_exec_fixture(self, root):
        value = launch_value()
        candidate = root / ("geniex-candidate-" + value["instance"])
        candidate.mkdir(mode=0o700)
        evidence = candidate / "startup-evidence"; evidence.mkdir(mode=0o700)
        startup = candidate / "startup"; startup.mkdir(mode=0o700)
        boot = "12345678-1234-1234-1234-123456789abc"
        config_sha = "7" * 64
        plan_raw = json.dumps({"launch_config_sha256": config_sha}).encode()
        (startup / "entry-plan.json").write_bytes(plan_raw)
        identity = {"pid": 2345, "context": entry.CONTEXT, "CapEff": "0000000000040023", "CapPrm": "0000000000040023"}
        intent = {"schema": "hepta.geniex-provider-entry-intent.v1", "instance": value["instance"],
                  "pid": identity["pid"], "ppid": 1, "context": entry.CONTEXT,
                  "effective_capabilities": entry.CAPS, "permitted_capabilities": entry.CAPS,
                  "stage": value["stage"], "state": "validated_exec_intent_not_ready",
                  "entry_plan_sha256": hashlib.sha256(plan_raw).hexdigest()}
        (evidence / ("entry-" + boot + ".json")).write_text(json.dumps(intent))
        return candidate, value, config_sha, identity, boot

    def test_post_exec_evidence_binds_original_intent_and_is_create_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate, value, config_sha, identity, boot = self.post_exec_fixture(Path(tmp))
            # This host fixture tests the record/intent binding only. Android
            # root ownership and the kernel identity are not being simulated as
            # production proof; the actual entry validates them before this call.
            with mock.patch.object(entry, "private_file", side_effect=lambda p, *_: Path(p).read_bytes()):
                record = entry.record_post_exec(candidate, value, config_sha, identity, {"host_fixture": True}, boot)
                path = candidate / "startup-evidence" / ("post-exec-" + boot + ".json")
                before = path.read_bytes()
                self.assertFalse(record["model_or_app_qualified"])
                self.assertFalse(record["model_executed"])
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                with self.assertRaises(FileExistsError):
                    entry.record_post_exec(candidate, value, config_sha, identity, {"host_fixture": True}, boot)
                self.assertEqual(path.read_bytes(), before)

    def test_post_exec_wrong_pid_or_launch_hash_cannot_publish_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate, value, config_sha, identity, boot = self.post_exec_fixture(Path(tmp))
            with mock.patch.object(entry, "private_file", side_effect=lambda p, *_: Path(p).read_bytes()):
                for actual_identity, actual_sha in ((dict(identity, pid=9999), config_sha), (identity, "8" * 64)):
                    with self.assertRaises(RuntimeError):
                        entry.record_post_exec(candidate, value, actual_sha, actual_identity, {"host_fixture": True}, boot)
                self.assertFalse((candidate / "startup-evidence" / ("post-exec-" + boot + ".json")).exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
