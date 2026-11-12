#!/usr/bin/env python3
"""Host-only negative-path tests. No H, ADB process, device, or real lease IO.

The dependency objects below are explicit fakes. They exercise orchestration,
receipt parsing and no-replay behavior, not actual APK signing or phone safety.
"""
from __future__ import annotations
import contextlib
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
import v54_upgrade_once as upgrade

ROOT = Path(__file__).absolute().parent
HARNESS = upgrade.load_harness(ROOT / "background_notes_v54_acceptance.py")


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True).encode()


class FakeIdentity:
    def __init__(self, path):
        self.OPERATION_LOCK_PATH = path
        self.active, self.acquisitions, self.checks, self.lose_before_install, self.busy = False, 0, [], False, False
        self.held_inode = upgrade.LOCK_INODE

    @contextlib.contextmanager
    def operation_lock(self, report):
        if self.active:
            raise RuntimeError("fake nested lease")
        if self.busy:
            report["operation_lock"] = {"acquired": False, "released": False, "held_by_another_operator": True}
            raise RuntimeError("fake original operation lock busy")
        self.acquisitions += 1
        self.active = True
        record = {"acquired": True, "released": False, "continuity_verified": True, "held_inode": self.held_inode}
        report["operation_lock"] = record
        try:
            yield self
        finally:
            record.update(released=True, continuity_verified=self.active)
            self.active = False

    def require_operation_lock(self, label):
        self.checks.append(label)
        if self.lose_before_install and label == "immediately_before_sole_adb_install_r":
            self.active = False
        if not self.active:
            raise RuntimeError("fake lease is not held")
        return self

    def guard_adb(self, adb):
        self.require_operation_lock("guard_adb")
        original = adb.command
        def guarded(*args, **kwargs):
            self.require_operation_lock("adb.command")
            return original(*args, **kwargs)
        adb.command = guarded
        return adb

    encoded = staticmethod(encoded)

    @staticmethod
    def write_new(path, raw):
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())


class FakePhone:
    def __init__(self, args, config, identity):
        self.args, self.identity = args, identity
        self.uid, self.version, self.apk_sha, self.version_name = 10481, 51, upgrade.BASELINE_SHA, upgrade.BASELINE_VERSION_NAME
        self.files = {upgrade.RUNTIME_CONFIG: config}
        self.system = {"errors": [], "displays": {0: {"name": "Built-in Screen"}}, "processes": []}
        self.commands, self.installs, self.identity_reads, self.config_reads = [], [], 0, 0
        self.result_mode, self.config_race = "success", False

    def adb(self, args, evidence):
        state = self
        class FakeAdb:
            base = [str(args.adb), "-H", args.adb_host, "-P", str(args.adb_port), "-s", args.serial]
            def command(self, words, **kwargs):
                state.commands.append(words)
                if words[0] == "_fixture_identity":
                    state.identity_reads += 1
                    return 0, encoded({"package": upgrade.PACKAGE, "uid": state.uid,
                        "apks": [{"path": "/data/app/fixture/base.apk", "sha256": state.apk_sha}]})
                if words[:2] == ["dumpsys", "package"]:
                    return 0, ("versionCode=%s versionName=%s\n" % (state.version, state.version_name)).encode()
                if words[:3] == ["run-as", upgrade.PACKAGE, "id"]:
                    return 0, (str(state.uid) + "\n").encode()
                if words == ["am", "get-current-user"]:
                    return 0, b"0\n"
                if words[:3] == ["run-as", upgrade.PACKAGE, "find"]:
                    names = {p.split("/")[1] for p in state.files}
                    return 0, ("".join("files/" + n + "\n" for n in sorted(names))).encode()
                if words[0] in {"_fixture_read", "_fixture_system"}:
                    return 0, b""
                raise AssertionError("unexpected fake read: " + repr(words))
            def app_bytes(self, name, *, optional=False):
                self.command(["_fixture_read", name])
                if name == upgrade.RUNTIME_CONFIG:
                    state.config_reads += 1
                    if state.config_race and state.config_reads >= 2:
                        return state.files[name] + b" "
                if not optional and name not in state.files:
                    raise RuntimeError("fixture missing required file")
                return state.files.get(name)
        return FakeAdb()

    def run_install(self, argv, **kwargs):
        if not self.identity.active:
            raise AssertionError("install without original fake lease")
        if argv[-3:] != ["install", "-r", str(self.args.out / "candidate.apk")]:
            raise AssertionError("unexpected mutation argv")
        self.installs.append(argv)
        if len(self.installs) != 1:
            raise AssertionError("installation replayed")
        if self.result_mode == "nonzero":
            return subprocess.CompletedProcess(argv, 1, b"", b"fixture refused")
        self.version, self.apk_sha, self.version_name = 54, self.args.apk_sha256, HARNESS.VERSION_NAME
        if self.result_mode == "changed_config":
            self.files[upgrade.RUNTIME_CONFIG] += b" "
        if self.result_mode == "changed_uid":
            self.uid = 10482
        if self.result_mode == "timeout":
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output=b"Performing Streamed Install\n")
        return subprocess.CompletedProcess(argv, 0, b"Performing Streamed Install\nSuccess\n", b"")


class FakeReference:
    def __init__(self, state):
        self.state = state

    @staticmethod
    def bounded_private_reader(adb):
        pass  # FakeAdb already has a local dictionary reader; no subprocess is reachable.

    @staticmethod
    def text(adb, words, label):
        return adb.command(words, label=label)[1].decode()

    @staticmethod
    def package_identity(adb, package, label):
        return json.loads(adb.command(["_fixture_identity", package], label=label)[1])

    def system_snapshot(self, adb, directory, index, target):
        adb.command(["_fixture_system", str(index)])
        return copy.deepcopy(self.state.system)


class UpgradeChecks(unittest.TestCase):
    def setUp(self):
        self.subprocess_fuse = patch("subprocess.run", side_effect=AssertionError("real subprocess forbidden in fake-I/O tests"))
        self.subprocess_fuse.start()
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-upgrade-fake-")
        self.root = Path(self.temp.name)
        self.out = self.root / "evidence"
        self.out.mkdir(mode=0o700)
        self.adb = self.root / "fake-adb-NOT-EXECUTABLE"
        self.adb.write_bytes(b"fixture only; no executable or device connection")
        self.staged = self.out / "candidate.apk"
        self.staged.write_bytes(b"fixture candidate, not a real APK")
        self.config = encoded({"schema": "hepta.local-runtime.v2", "model_profile": "lfm3-1.7b-qad-q4_0",
                               "compute": "npu", "context_tokens": 8192, "threads": 4})
        self.args = SimpleNamespace(out=self.out, adb=self.adb, adb_host="fixture", adb_port=5037, serial="fixture",
            command_timeout=1, install_timeout=1, apk_sha256=upgrade.sha(self.staged.read_bytes()),
            assembly_result_sha256="1" * 64)
        self.lock_path, self.attempt_path = str(self.root / "original-fake-lease"), str(self.root / "consumed.json")
        self.constants = patch.multiple(upgrade, LOCK_PATH=self.lock_path, ATTEMPT_PATH=self.attempt_path)
        self.constants.start()
        self.identity = FakeIdentity(self.lock_path)
        self.phone = FakePhone(self.args, self.config, self.identity)
        self.modules = {"v35_identity": self.identity, "background_reference": FakeReference(self.phone),
                        "phone_acceptance": SimpleNamespace(Adb=self.phone.adb)}
        self.report = {"host_tools": {"adb": {"sha256": upgrade.sha(self.adb.read_bytes())}}}

    def tearDown(self):
        self.subprocess_fuse.stop()
        self.constants.stop()
        self.temp.cleanup()

    def execute(self):
        return upgrade.execute_phone(self.args, HARNESS, self.modules, self.staged, self.config, self.report,
                                     run=self.phone.run_install)

    def refuse_without_install(self):
        with self.assertRaises(RuntimeError):
            self.execute()
        self.assertEqual(self.phone.installs, [])
        self.assertFalse(Path(self.attempt_path).exists())
        self.assertTrue(self.report["operation_lock"]["released"])

    def test_success_one_install_and_original_lease_released(self):
        result = self.execute()
        self.assertTrue(result["all_pass"])
        self.assertFalse(result["phone_qualified"])
        self.assertEqual(len(self.phone.installs), 1)
        self.assertEqual(self.identity.acquisitions, 1)
        self.assertEqual(self.phone.identity_reads, 3)
        self.assertTrue(result["config_after"]["same_exact_bytes"])
        self.assertTrue(Path(self.attempt_path).exists())
        self.assertIn("immediately_before_sole_adb_install_r", self.identity.checks)

    def test_busy_original_lock_means_zero_adb_commands(self):
        self.identity.busy = True
        with self.assertRaisesRegex(RuntimeError, "original operation lock busy"):
            self.execute()
        self.assertEqual(self.phone.commands, [])
        self.assertEqual(self.phone.installs, [])
        self.assertEqual(self.identity.acquisitions, 0)
        self.assertFalse(Path(self.attempt_path).exists())

    def test_wrong_original_lock_inode_means_zero_adb_commands(self):
        self.identity.held_inode = upgrade.LOCK_INODE + 1
        with self.assertRaisesRegex(RuntimeError, "lock inode differs"):
            self.execute()
        self.assertEqual(self.phone.commands, [])
        self.assertEqual(self.phone.installs, [])
        self.assertTrue(self.report["operation_lock"]["released"])
        self.assertFalse(Path(self.attempt_path).exists())

    def test_baseline_sha_uid_and_unknown_versions_refused(self):
        for field, value in (("apk_sha", "0" * 64), ("uid", 10482), ("version", 52), ("version", 53), ("version", 54)):
            original = getattr(self.phone, field)
            with self.subTest(field=field, value=value):
                setattr(self.phone, field, value)
                self.refuse_without_install()
                setattr(self.phone, field, original)

    def test_active_or_malformed_control_refused(self):
        value = self.clean_control()
        for field, item in (("pending", True), ("running", True), ("cleanup_known", False), ("pending", 0), ("background_lease_unreleased", True)):
            with self.subTest(field=field, item=item):
                changed = dict(value, **{field: item})
                self.phone.files["files/control-session.json"] = encoded(changed)
                self.refuse_without_install()

    @staticmethod
    def clean_control():
        return {"schema": "hepta.local-session.v1", "app_uid": 10481, "pending": False, "running": False,
            "blocked": False, "cleanup_known": True, "external_model": False, "automatic_resume": False,
            "background_lease_unreleased": False, "updated_wall_ms": 1, "state": "finished",
            "task_id": "a" * 32, "instruction_sha256": "b" * 64, "debug_nonce_sha256": None,
            "origin": "user_button", "status": "controller_verified_done"}

    def test_clean_historical_control_is_not_replayed(self):
        raw = encoded(self.clean_control())
        self.phone.files["files/control-session.json"] = raw
        self.assertTrue(self.execute()["all_pass"])
        self.assertEqual(self.phone.files["files/control-session.json"], raw)

    def test_barriers_and_uncommitted_journals_refused(self):
        for name in ("background-session.active.json", "qualification-scope.json", "control-session.interrupted.json",
                     "control-session.json.new", "control-session.recovery-pending-" + "c" * 32 + ".record",
                     "background-permission-interrupted.json"):
            with self.subTest(name=name):
                self.phone.files["files/" + name] = b"{}"
                self.refuse_without_install()
                del self.phone.files["files/" + name]

    def test_live_worker_or_broker_or_display_refused(self):
        for token in upgrade.WORKERS:
            with self.subTest(process=token):
                self.phone.system["processes"] = [{"args": "/some/path/" + token}]
                self.refuse_without_install()
        self.phone.system["processes"] = []
        self.phone.system["displays"][17] = {"name": "hepta-bg-fixture"}
        self.refuse_without_install()

    def test_config_change_between_preflights_refused(self):
        self.phone.config_race = True
        self.refuse_without_install()

    def test_timeout_reconciles_actual_v54_without_replay_or_success_claim(self):
        self.phone.result_mode = "timeout"
        result = self.execute()
        self.assertFalse(result["all_pass"])
        self.assertTrue(result["target_v54_observed"])
        self.assertTrue(result["install"]["client_timed_out"])
        self.assertEqual(len(self.phone.installs), 1)
        self.assertEqual(self.phone.identity_reads, 3)

    def test_nonzero_reconciles_v51_without_replay(self):
        self.phone.result_mode = "nonzero"
        result = self.execute()
        self.assertFalse(result["all_pass"])
        self.assertTrue(result["known_v51_still_observed"])
        self.assertEqual(len(self.phone.installs), 1)

    def test_post_config_change_is_not_repaired(self):
        self.phone.result_mode = "changed_config"
        result = self.execute()
        self.assertFalse(result["all_pass"])
        self.assertFalse(result["config_after"]["same_exact_bytes"])
        self.assertEqual(self.phone.files[upgrade.RUNTIME_CONFIG], self.config + b" ")

    def test_post_uid_change_is_reported_before_private_read_rejected(self):
        self.phone.result_mode = "changed_uid"
        result = self.execute()
        self.assertFalse(result["all_pass"])
        self.assertEqual(result["installed_identity_after"]["uid"], 10482)
        self.assertEqual(len(self.phone.installs), 1)

    def test_consumed_attempt_rejects_even_before_phone_contact(self):
        self.execute()
        before = len(self.phone.commands)
        with self.assertRaisesRegex(RuntimeError, "previous v54 attempt consumed"):
            self.execute()
        self.assertEqual(len(self.phone.commands), before)
        self.assertEqual(len(self.phone.installs), 1)

    def test_lost_lease_prevents_install_and_reconciliation_commands(self):
        self.identity.lose_before_install = True
        result = self.execute()
        self.assertFalse(result["all_pass"])
        self.assertEqual(self.phone.installs, [])
        self.assertTrue(Path(self.attempt_path).exists())
        self.assertFalse(result["install_attempted"])
        self.assertEqual(result["install"]["attempts"], 0)

    def test_changed_stage_or_adb_refused_before_consuming_attempt(self):
        for path in (self.staged, self.adb):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.write_bytes(original + b"changed")
                self.refuse_without_install()
                path.write_bytes(original)

    def test_permission_terminal_receipt_must_match(self):
        value = {"schema": "hepta.background-permission-preparation.v1", "source": "visible_owner_button",
            "package_name": upgrade.PACKAGE, "app_uid": 10481, "installed_uid": 10481,
            "command": ["su", "-c", "/system/bin/id -u"], "timeout_ms": 60000, "phase": "terminal",
            "automatic_retry": False, "automatic_resume": False, "permanent_authorization_proven": False,
            "display_created": False, "broker_started": False, "task_started": False, "model_started": False,
            "policy_database_modified": False, "cleanup_known": True, "terminal_receipt_published": True,
            "request_id": "a" * 32, "app_pid": 123, "boot_count": 1, "started_elapsed_ms": 10,
            "deadline_elapsed_ms": 60010, "process_started": False, "process_exit_observed": False,
            "permission_verified": False, "exit_code": None, "status": "cancelled_before_start"}
        receipt = encoded(value)
        path = "files/background-permission-runs/" + "a" * 32 + "/result.json"
        self.phone.files[path] = receipt + b"changed"
        self.phone.files["files/background-permission-session.json"] = encoded(dict(value,
            result_sha256=upgrade.sha(receipt), result_file="result.json"))
        self.refuse_without_install()
        self.phone.files[path] = receipt
        self.assertTrue(self.execute()["all_pass"])

    def test_changed_harness_is_not_executed(self):
        target = self.root / "SHOULD-NOT-EXIST"
        bad = self.root / "unreviewed.py"
        bad.write_text("from pathlib import Path\nPath(" + repr(str(target)) + ").write_text('bad')\n")
        with self.assertRaisesRegex(RuntimeError, "harness differs"):
            upgrade.load_harness(bad)
        self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
