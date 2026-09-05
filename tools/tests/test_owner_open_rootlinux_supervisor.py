from __future__ import annotations

import ctypes
import importlib.util
import json
import os
import signal
import subprocess
from pathlib import Path
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "owner-open"
    / "owner_open_rootlinux_supervisor.py"
)
spec = importlib.util.spec_from_file_location("owner_open_rootlinux_supervisor", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class SupervisorFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.child = self.root / "child.py"
        self.config_path = self.root / "supervisor.json"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_child(self, source: str) -> None:
        self.child.write_text("#!/usr/bin/env python3\n" + source, encoding="utf-8")
        self.child.chmod(0o500)

    def config(self, *, restart_limit: int = 0) -> dict:
        return {
            "schema": module.SCHEMA,
            "state_root": str(self.state),
            "emergency_stop": str(self.state / "emergency-stop"),
            "status_path": str(self.state / "status" / "supervisor.json"),
            "event_log_path": str(self.state / "events" / "supervisor.jsonl"),
            "poll_seconds": 0.01,
            "shutdown_grace_seconds": 0.1,
            "kill_grace_seconds": 1.0,
            "environment": {"ADB_SERVER_SOCKET": "tcp:127.0.0.1:15038"},
            "children": [
                {
                    "name": "host",
                    "argv": [str(self.child)],
                    "environment": {},
                    "critical": True,
                    "restart_limit": restart_limit,
                    "restart_window_seconds": 5.0,
                    "restart_backoff_seconds": 0.01,
                }
            ],
            "automatic_effect_redispatch": False,
        }

    def write_config(self, value: dict) -> module.Config:
        # The fixture owns this path. Restore write access before replacing a
        # prior read-only config, then reapply the production input mode below.
        if self.config_path.exists():
            self.config_path.chmod(0o600)
        self.config_path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        self.config_path.chmod(0o400)
        return module.load_config(self.config_path)



class OwnerOpenRootLinuxSupervisorTest(SupervisorFixture):
    def test_emergency_stop_inhibits_spawn(self) -> None:
        marker = self.root / "spawned"
        self.write_child(f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n")
        (self.state / "emergency-stop").write_text("owner stop\n", encoding="utf-8")
        config = self.write_config(self.config())
        result = module.Supervisor(config).run()
        self.assertEqual(result, 75)
        self.assertFalse(marker.exists())
        status = json.loads(config.status_path.read_text(encoding="utf-8"))
        self.assertEqual(status["state"], "inhibited")
        self.assertFalse(status["automatic_effect_redispatch"])

    def test_critical_restart_budget_is_finite(self) -> None:
        counter = self.state / "counter"
        self.write_child(
            "from pathlib import Path\n"
            f"p=Path({str(counter)!r})\n"
            "n=int(p.read_text()) if p.exists() else 0\n"
            "p.write_text(str(n+1))\n"
            "raise SystemExit(3)\n"
        )
        config = self.write_config(self.config(restart_limit=1))
        result = module.Supervisor(config).run()
        self.assertEqual(result, 70)
        self.assertEqual(counter.read_text(encoding="utf-8"), "2")
        status = json.loads(config.status_path.read_text(encoding="utf-8"))
        self.assertIn("restart_budget_exhausted", status["reason"])
        events = config.event_log_path.read_text(encoding="utf-8")
        self.assertEqual(events.count('"kind":"child_started"'), 2)
        self.assertIn('"automatic_effect_redispatch":false', events)

    def test_requested_stop_reaps_child_process_group(self) -> None:
        pid_path = self.state / "child.pid"
        self.write_child(
            "import os,time\n"
            f"open({str(pid_path)!r},'w',encoding='utf-8').write(str(os.getpid()))\n"
            "while True: time.sleep(1)\n"
        )
        config = self.write_config(self.config(restart_limit=0))
        supervisor = module.Supervisor(config)

        def stop_when_started() -> None:
            deadline = time.monotonic() + 5
            while not pid_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            supervisor.request_stop("test_stop")

        stopper = threading.Thread(target=stop_when_started)
        stopper.start()
        result = supervisor.run()
        stopper.join(timeout=1)
        self.assertEqual(result, 0)
        pid = int(pid_path.read_text(encoding="utf-8"))
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        status = json.loads(config.status_path.read_text(encoding="utf-8"))
        self.assertEqual(status["state"], "terminal")
        self.assertEqual(status["reason"], "test_stop")

    def test_android_serial_and_semantic_redispatch_are_rejected(self) -> None:
        self.write_child("raise SystemExit(0)\n")
        value = self.config()
        value["environment"]["ANDROID_SERIAL"] = "implicit"
        with self.assertRaisesRegex(module.SupervisorError, "ANDROID_SERIAL"):
            self.write_config(value)
        self.config_path.chmod(0o600)
        value = self.config()
        value["automatic_effect_redispatch"] = True
        with self.assertRaisesRegex(module.SupervisorError, "must be false"):
            self.write_config(value)

    def test_config_and_executable_must_be_non_writable(self) -> None:
        self.write_child("raise SystemExit(0)\n")
        self.child.chmod(0o722)
        with self.assertRaisesRegex(module.SupervisorError, "non-writable executable"):
            self.write_config(self.config())


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "waitid"), "Linux lifecycle contract")
class RootLinuxGroupLifecycleTest(SupervisorFixture):
    """Real local fork/exit tests; no device, installed or release qualification."""

    def setUp(self) -> None:
        super().setUp()
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.old_subreaper = ctypes.c_int()
        if self.libc.prctl(37, ctypes.byref(self.old_subreaper), 0, 0, 0) != 0:
            self.skipTest("test runner cannot inspect subreaper state")
        if self.libc.prctl(36, 1, 0, 0, 0) != 0:
            self.skipTest("test runner cannot adopt its fixture descendants")
        self.supervisors: list[module.Supervisor] = []

    @staticmethod
    def live(pid: int) -> bool:
        try:
            return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] not in {"Z", "X"}
        except FileNotFoundError:
            return False

    def tearDown(self) -> None:
        # Test-only subreaping avoids leaving orphan zombies even on the old,
        # intentionally broken implementation used for regression reproduction.
        try:
            for marker in self.state.glob("desc-*.pid"):
                pid = int(marker.read_text())
                if self.live(pid):
                    os.kill(pid, signal.SIGKILL)
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
            for supervisor in self.supervisors:
                for managed in supervisor.children.values():
                    if managed.process.returncode is None:
                        try:
                            os.kill(managed.process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        managed.process.wait(timeout=2)
        finally:
            self.libc.prctl(36, self.old_subreaper.value, 0, 0, 0)
            super().tearDown()

    def fork_fixture(self, *, leader_exits: bool = True) -> None:
        self.write_child(
            "import os,signal,time\nfrom pathlib import Path\n"
            f"state=Path({str(self.state)!r})\n"
            "counter=state/'generation'\n"
            "generation=int(counter.read_text())+1 if counter.exists() else 1\n"
            "counter.write_text(str(generation))\n"
            "if generation > 1:\n"
            "    previous=int((state/f'desc-{generation-1}.pid').read_text())\n"
            "    try:\n"
            "        live=Path(f'/proc/{previous}/stat').read_text().rsplit(')',1)[1].split()[0] not in {'Z','X'}\n"
            "    except FileNotFoundError: live=False\n"
            "    if live: (state/'overlap').write_text('old group still executing')\n"
            "reader,writer=os.pipe()\n"
            "pid=os.fork()\n"
            "if pid == 0:\n"
            "    os.close(reader)\n"
            "    signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            "    (state/f'desc-{generation}.pid').write_text(str(os.getpid()))\n"
            "    os.write(writer,b'R');os.close(writer)\n"
            "    while True: time.sleep(1)\n"
            "os.close(writer)\n"
            "assert os.read(reader,1) == b'R'\n"
            "os.close(reader)\n"
            + ("os._exit(3)\n" if leader_exits else "while True: time.sleep(1)\n")
        )

    def supervisor(self, value: dict | None = None) -> module.Supervisor:
        instance = module.Supervisor(self.write_config(value or self.config()))
        self.supervisors.append(instance)
        self.addCleanup(instance.close_state)
        return instance

    def stop_after_marker(self, supervisor: module.Supervisor, path: Path) -> threading.Thread:
        def stop() -> None:
            deadline = time.monotonic() + 5
            while not path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            supervisor.request_stop("test_stop")
        thread = threading.Thread(target=stop)
        thread.start()
        return thread

    def assert_no_live_descendants(self) -> None:
        markers = list(self.state.glob("desc-*.pid"))
        self.assertTrue(markers, "fixture must create an actual descendant")
        for path in markers:
            self.assertFalse(self.live(int(path.read_text())), f"surviving descendant: {path}")

    def test_exited_leader_does_not_hide_term_resistant_descendant(self) -> None:
        self.fork_fixture()
        supervisor = self.supervisor()
        self.assertEqual(supervisor.run(), 70)
        self.assert_no_live_descendants()

    def test_restart_waits_for_previous_group_cleanup(self) -> None:
        self.fork_fixture()
        supervisor = self.supervisor(self.config(restart_limit=1))
        self.assertEqual(supervisor.run(), 70)
        self.assertEqual((self.state / "generation").read_text(), "2")
        self.assertFalse((self.state / "overlap").exists(), "replacement must not overlap prior group")
        self.assert_no_live_descendants()

    def test_shutdown_escalates_after_leader_exits_on_term(self) -> None:
        self.fork_fixture(leader_exits=False)
        supervisor = self.supervisor()
        thread = self.stop_after_marker(supervisor, self.state / "desc-1.pid")
        try:
            self.assertEqual(supervisor.run(), 0)
            self.assert_no_live_descendants()
        finally:
            thread.join(timeout=6)

    def test_noncritical_exit_cleans_before_forgetting_group(self) -> None:
        self.fork_fixture()
        keepalive = self.root / "keepalive.py"
        keepalive.write_text("#!/usr/bin/env python3\nimport time\nwhile True: time.sleep(1)\n")
        keepalive.chmod(0o500)
        value = self.config()
        value["children"][0]["critical"] = False
        other = dict(value["children"][0], name="keepalive", argv=[str(keepalive)], critical=True)
        value["children"].append(other)
        supervisor = self.supervisor(value)
        def stop_after_retirement() -> None:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if (self.state / "desc-1.pid").exists() and "host" not in supervisor.children:
                    break
                time.sleep(0.01)
            supervisor.request_stop("test_stop")
        thread = threading.Thread(target=stop_after_retirement)
        thread.start()
        try:
            self.assertEqual(supervisor.run(), 0)
            self.assert_no_live_descendants()
        finally:
            thread.join(timeout=6)

    def test_dangling_emergency_marker_inhibits_spawn(self) -> None:
        marker = self.state / "spawned"
        self.write_child(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
        (self.state / "emergency-stop").symlink_to(self.state / "missing")
        supervisor = self.supervisor()
        self.assertEqual(supervisor.run(), 75)
        self.assertFalse(marker.exists())

    def test_state_outputs_cannot_alias_emergency_inhibit(self) -> None:
        self.write_child("raise SystemExit(0)\n")
        value = self.config()
        value["status_path"] = value["emergency_stop"]
        with self.assertRaises(module.SupervisorError):
            self.write_config(value)

    def test_status_observation_does_not_reap_group_anchor(self) -> None:
        self.write_child("raise SystemExit(3)\n")
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        managed = supervisor.spawn(supervisor.config.children[0])
        # WNOWAIT is a deterministic exit barrier that retains the PGID anchor.
        os.waitid(os.P_PID, managed.process.pid, os.WEXITED | os.WNOWAIT)
        supervisor.write_status("running")
        self.assertIsNone(managed.process.returncode)
        self.assertEqual(os.waitid(os.P_PID, managed.process.pid, os.WEXITED | os.WNOWAIT).si_status, 3)
        supervisor.shutdown()

    def test_unobservable_group_prevents_respawn(self) -> None:
        self.write_child("raise SystemExit(3)\n")
        supervisor = self.supervisor(self.config(restart_limit=1))
        with mock.patch.object(module.Supervisor, "live_group_members", side_effect=module.SupervisorError("procfs unavailable")):
            self.assertEqual(supervisor.run(), 70)
        events = supervisor.config.event_log_path.read_text()
        self.assertEqual(events.count('"kind":"child_started"'), 1)
        self.assertNotIn('"kind":"child_restart_scheduled"', events)

    def test_stop_between_initial_spawns_prevents_next_child(self) -> None:
        self.write_child("import time\nwhile True: time.sleep(1)\n")
        value = self.config()
        value["children"].append(dict(value["children"][0], name="second"))
        supervisor = self.supervisor(value)
        original = supervisor.spawn
        def stop_after_first(*args, **kwargs):
            managed = original(*args, **kwargs)
            supervisor.request_stop("test_stop")
            return managed
        with mock.patch.object(supervisor, "spawn", side_effect=stop_after_first):
            self.assertEqual(supervisor.run(), 0)
        self.assertEqual(set(supervisor.children), {"host"})


    def test_reaped_anchor_never_receives_a_group_signal(self) -> None:
        self.write_child("raise SystemExit(3)\n")
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        managed = supervisor.spawn(supervisor.config.children[0])
        managed.process.wait(timeout=2)  # Simulate an unsupported external reaper.
        with mock.patch.object(module.os, "killpg") as kill:
            with self.assertRaisesRegex(module.SupervisorError, "reaped"):
                supervisor.signal_group(managed, signal.SIGKILL)
            kill.assert_not_called()

    def test_missing_waitid_backend_rejects_before_spawn(self) -> None:
        self.write_child("raise SystemExit(0)\n")
        supervisor = self.supervisor()
        with mock.patch.object(module.os, "waitid", None):
            with self.assertRaisesRegex(module.SupervisorError, "waitid"):
                supervisor.run()
        self.assertEqual(supervisor.children, {})

    def test_ignored_sigchld_rejects_before_spawn(self) -> None:
        self.write_child("raise SystemExit(0)\n")
        supervisor = self.supervisor()
        original = signal.getsignal
        with mock.patch.object(module.signal, "getsignal", side_effect=lambda sig: signal.SIG_IGN if sig == signal.SIGCHLD else original(sig)):
            with self.assertRaisesRegex(module.SupervisorError, "SIGCHLD"):
                supervisor.run()
        self.assertEqual(supervisor.children, {})

    def test_cleanup_timeout_prevents_replacement(self) -> None:
        self.write_child("raise SystemExit(3)\n")
        supervisor = self.supervisor(self.config(restart_limit=1))
        with mock.patch.object(module.Supervisor, "wait_groups", return_value=False):
            self.assertEqual(supervisor.run(), 70)
        events = supervisor.config.event_log_path.read_text()
        self.assertEqual(events.count('"kind":"child_started"'), 1)
        self.assertNotIn('"kind":"child_restart_scheduled"', events)
        status = json.loads(supervisor.config.status_path.read_text())
        self.assertIn("unconfirmed", status["reason"])
        self.assertEqual(status["children"]["host"]["group_cleanup"], "pending")

    def test_proc_scan_has_a_finite_entry_budget(self) -> None:
        self.write_child("import time\nwhile True: time.sleep(1)\n")
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        managed = supervisor.spawn(supervisor.config.children[0])
        with mock.patch.object(module, "MAX_PROC_ENTRIES", 0):
            with self.assertRaisesRegex(module.SupervisorError, "budget"):
                supervisor.live_group_members(managed.process.pid)
        supervisor.shutdown()

    def test_group_status_does_not_claim_escaped_descendant_absence(self) -> None:
        self.write_child("raise SystemExit(3)\n")
        supervisor = self.supervisor()
        self.assertEqual(supervisor.run(), 70)
        status = json.loads(supervisor.config.status_path.read_text())
        self.assertEqual(status["cleanup_scope"], "original_process_group_only")
        self.assertFalse(status["escaped_descendants_absence_proven"])
        self.assertEqual(status["children"]["host"]["group_cleanup"], "no_live_original_group_members_observed")
        events = [json.loads(line) for line in supervisor.config.event_log_path.read_text().splitlines()]
        cleanups = [event for event in events if event["kind"] == "child_group_cleaned"]
        self.assertEqual(len(cleanups), 1)
        self.assertFalse(cleanups[0]["escaped_descendants_absence_proven"])

    def test_parenthesized_process_name_keeps_group_identity_parseable(self) -> None:
        self.write_child(
            "import ctypes\n"
            "assert ctypes.CDLL(None).prctl(15,b'name ) ( test',0,0,0) == 0\n"
            "raise SystemExit(3)\n"
        )
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        managed = supervisor.spawn(supervisor.config.children[0])
        os.waitid(os.P_PID, managed.process.pid, os.WEXITED | os.WNOWAIT)
        self.assertEqual(supervisor.live_group_members(managed.process.pid), ())
        supervisor.shutdown()


    def test_lifecycle_suite_remains_in_both_source_workflows(self) -> None:
        workflows = SCRIPT.parents[2] / ".github" / "workflows"
        command = "python3 -m unittest tools.tests.test_owner_open_rootlinux_supervisor -v"
        for filename in ("g1-exact-head-source.yml", "g1-synthetic-merge.yml"):
            with self.subTest(workflow=filename):
                self.assertIn(command, (workflows / filename).read_text())


@unittest.skipUnless(sys.platform == "linux", "Linux state directory contract")
class RootLinuxStateIntegrityTest(SupervisorFixture):
    """Local state I/O regressions, not installed-target/fault qualification."""

    def supervisor(self, value: dict | None = None) -> module.Supervisor:
        self.write_child("raise SystemExit(0)\n")
        instance = module.Supervisor(self.write_config(value or self.config()))
        self.addCleanup(lambda: getattr(instance, "close_state", lambda: None)())
        return instance

    def test_short_event_writes_are_completed(self) -> None:
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        write = os.write
        with mock.patch.object(module.os, "write", side_effect=lambda fd, data: write(fd, data[:7])):
            supervisor.append_event("short_write", value="x" * 100)
        event = json.loads(supervisor.config.event_log_path.read_bytes())
        self.assertEqual(event["value"], "x" * 100)
        self.assertTrue(supervisor.config.event_log_path.read_bytes().endswith(b"\n"))

    def test_zero_progress_event_write_fails(self) -> None:
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        with mock.patch.object(module.os, "write", return_value=0):
            with self.assertRaises(module.SupervisorError):
                supervisor.append_event("zero_write")

    def test_short_status_writes_are_completed(self) -> None:
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        write = os.write
        with mock.patch.object(module.os, "write", side_effect=lambda fd, data: write(fd, data[:11])):
            supervisor.write_status("running")
        self.assertEqual(json.loads(supervisor.config.status_path.read_bytes())["state"], "running")

    def test_status_fsync_failure_preserves_previous_status_and_cleans_temporary(self) -> None:
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        supervisor.write_status("inhibited")
        previous = supervisor.config.status_path.read_bytes()
        with mock.patch.object(module.os, "fsync", side_effect=OSError("injected fsync failure")):
            with self.assertRaises(OSError):
                supervisor.write_status("running")
        self.assertEqual(supervisor.config.status_path.read_bytes(), previous)
        self.assertEqual(list(supervisor.config.status_path.parent.glob(".*.tmp-*")), [])

    def test_status_rename_is_followed_by_parent_fsync(self) -> None:
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        observed = []
        sync, replace = os.fsync, os.replace
        def do_sync(fd):
            observed.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
            return sync(fd)
        def do_replace(*args, **kwargs):
            observed.append("replace")
            return replace(*args, **kwargs)
        with mock.patch.object(module.os, "fsync", side_effect=do_sync), mock.patch.object(module.os, "replace", side_effect=do_replace):
            supervisor.write_status("running")
        self.assertEqual(observed, ["file", "replace", "directory"])

    def test_intermediate_symlink_is_rejected_without_creating_external_directory(self) -> None:
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        (self.state / "alias").symlink_to(outside, target_is_directory=True)
        value = self.config()
        value["status_path"] = str(self.state / "alias" / "new" / "status.json")
        supervisor = self.supervisor(value)
        with self.assertRaises((module.SupervisorError, OSError)):
            supervisor.validate_state_root()
        self.assertFalse((outside / "new").exists())

    def test_existing_public_parent_is_rejected_not_chmodded(self) -> None:
        parent = self.state / "status"
        parent.mkdir(mode=0o755)
        supervisor = self.supervisor()
        with self.assertRaises(module.SupervisorError):
            supervisor.validate_state_root()
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o755)

    def test_two_live_supervisors_cannot_own_same_state_root(self) -> None:
        first = self.supervisor()
        first.validate_state_root()
        second = module.Supervisor(first.config)
        self.addCleanup(lambda: getattr(second, "close_state", lambda: None)())
        with self.assertRaises(module.SupervisorError):
            second.validate_state_root()
        self.assertEqual(second.children, {})


    def test_state_lock_release_allows_later_owner(self) -> None:
        first = self.supervisor()
        first.validate_state_root()
        first.close_state()
        second = module.Supervisor(first.config)
        self.addCleanup(second.close_state)
        second.validate_state_root()

    def test_failed_admission_does_not_release_existing_owner_lock(self) -> None:
        first = self.supervisor()
        first.validate_state_root()
        for _ in range(2):
            other = module.Supervisor(first.config)
            with self.assertRaises(module.SupervisorError):
                other.run()
            self.assertEqual(other.children, {})
            self.assertEqual(other._state_directories, {})
        self.assertTrue(first._state_directories)

    def test_inhibited_run_releases_state_descriptors(self) -> None:
        supervisor = self.supervisor()
        supervisor.config.emergency_stop.touch()
        for _ in range(3):
            self.assertEqual(supervisor.run(), 75)
            self.assertEqual(supervisor._state_directories, {})

    def test_validation_failure_closes_descriptors_and_releases_lock(self) -> None:
        (self.state / "status").mkdir(mode=0o755)
        supervisor = self.supervisor()
        with self.assertRaises(module.SupervisorError):
            supervisor.validate_state_root()
        self.assertEqual(supervisor._state_directories, {})
        (self.state / "status").chmod(0o700)
        other = module.Supervisor(supervisor.config)
        self.addCleanup(other.close_state)
        other.validate_state_root()

    def test_state_root_ancestor_symlink_is_rejected(self) -> None:
        real = self.root / "real"
        real.mkdir(mode=0o700)
        (real / "state").mkdir(mode=0o700)
        (self.root / "alias").symlink_to(real, target_is_directory=True)
        value = self.config()
        for key in ("state_root", "status_path", "event_log_path", "emergency_stop"):
            value[key] = value[key].replace(str(self.state), str(self.root / "alias" / "state"))
        supervisor = self.supervisor(value)
        with self.assertRaises(OSError):
            supervisor.validate_state_root()
        self.assertEqual(list((real / "state").iterdir()), [])

    def test_nested_inhibit_directory_is_pinned_and_marker_is_seen(self) -> None:
        value = self.config()
        value["emergency_stop"] = str(self.state / "controls" / "nested" / "stop")
        supervisor = self.supervisor(value)
        supervisor.validate_state_root()
        self.assertFalse(supervisor.emergency_requested())
        supervisor.config.emergency_stop.touch()
        self.assertTrue(supervisor.emergency_requested())

    def test_replaced_status_parent_never_writes_external_directory(self) -> None:
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        original = supervisor.config.status_path.parent
        original.rename(self.state / "old-status")
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        original.symlink_to(outside, target_is_directory=True)
        with self.assertRaises((OSError, module.SupervisorError)):
            supervisor.write_status("running")
        self.assertEqual(list(outside.iterdir()), [])
        self.assertTrue(supervisor.emergency_requested())

    def test_replaced_root_is_inhibited_and_cannot_spawn(self) -> None:
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        self.state.rename(self.root / "old-state")
        self.state.mkdir(mode=0o700)
        self.assertTrue(supervisor.emergency_requested())
        with mock.patch.object(module.subprocess, "Popen") as spawn:
            with self.assertRaises(module.SupervisorError):
                supervisor.spawn(supervisor.config.children[0])
            spawn.assert_not_called()

    def test_missing_pinned_parent_is_not_absent_emergency_marker(self) -> None:
        value = self.config()
        value["emergency_stop"] = str(self.state / "controls" / "stop")
        supervisor = self.supervisor(value)
        supervisor.validate_state_root()
        supervisor.config.emergency_stop.parent.rmdir()
        self.assertTrue(supervisor.emergency_requested())

    def test_changed_directory_permissions_inhibit(self) -> None:
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        supervisor.config.status_path.parent.chmod(0o755)
        self.assertTrue(supervisor.emergency_requested())

    def test_event_parent_is_synced_after_file(self) -> None:
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        observed = []
        sync = os.fsync
        def do_sync(fd):
            observed.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
            return sync(fd)
        with mock.patch.object(module.os, "fsync", side_effect=do_sync):
            supervisor.append_event("boundary")
        self.assertEqual(observed, ["file", "directory"])

    def test_partial_event_failure_fences_further_writes_and_spawn(self) -> None:
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        write = os.write
        calls = 0
        def fail_after_prefix(fd, data):
            nonlocal calls
            calls += 1
            if calls == 1:
                return write(fd, data[:7])
            raise OSError("injected ENOSPC after prefix")
        with mock.patch.object(module.os, "write", side_effect=fail_after_prefix):
            with self.assertRaises(OSError):
                supervisor.append_event("partial")
        prefix = supervisor.config.event_log_path.read_bytes()
        self.assertEqual(len(prefix), 7)
        with self.assertRaisesRegex(module.SupervisorError, "fenced"):
            supervisor.append_event("must_not_concatenate")
        self.assertEqual(supervisor.config.event_log_path.read_bytes(), prefix)
        with mock.patch.object(module.subprocess, "Popen") as spawn:
            with self.assertRaises(module.SupervisorError):
                supervisor.spawn(supervisor.config.children[0])
            spawn.assert_not_called()

    def test_event_fsync_failure_fences_even_after_complete_write(self) -> None:
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        with mock.patch.object(module.os, "fsync", side_effect=OSError("injected fsync ambiguity")):
            with self.assertRaises(OSError):
                supervisor.append_event("possibly_visible")
        raw = supervisor.config.event_log_path.read_bytes()
        with self.assertRaisesRegex(module.SupervisorError, "fenced"):
            supervisor.append_event("not_authorized")
        self.assertEqual(supervisor.config.event_log_path.read_bytes(), raw)

    def test_torn_existing_event_tail_rejects_before_spawn_without_repair(self) -> None:
        supervisor = self.supervisor()
        supervisor.config.event_log_path.parent.mkdir(mode=0o700)
        torn = b'{"kind":"partial'
        supervisor.config.event_log_path.write_bytes(torn)
        supervisor.config.event_log_path.chmod(0o600)
        with mock.patch.object(module.subprocess, "Popen") as spawn:
            self.assertEqual(supervisor.run(), 70)
            spawn.assert_not_called()
        self.assertEqual(supervisor.config.event_log_path.read_bytes(), torn)
        self.assertEqual(supervisor._state_directories, {})

    def test_event_capacity_rejects_before_spawn(self) -> None:
        supervisor = self.supervisor()
        with mock.patch.object(module, "MAX_EVENT_BYTES", 1), mock.patch.object(module.subprocess, "Popen") as spawn:
            self.assertEqual(supervisor.run(), 70)
            spawn.assert_not_called()

    def test_event_symlink_is_rejected_without_touching_target(self) -> None:
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        outside = self.root / "outside.log"
        outside.write_bytes(b"do not change\n")
        supervisor.config.event_log_path.symlink_to(outside)
        with self.assertRaises(OSError):
            supervisor.append_event("rejected")
        self.assertEqual(outside.read_bytes(), b"do not change\n")

    def test_event_hardlink_is_rejected_without_writing(self) -> None:
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        outside = self.root / "outside.log"
        outside.write_bytes(b"do not change\n")
        outside.chmod(0o600)
        os.link(outside, supervisor.config.event_log_path)
        with self.assertRaises(module.SupervisorError):
            supervisor.append_event("rejected")
        self.assertEqual(outside.read_bytes(), b"do not change\n")

    def test_public_event_file_is_not_silently_adopted(self) -> None:
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        supervisor.config.event_log_path.write_bytes(b"old\n")
        supervisor.config.event_log_path.chmod(0o644)
        with self.assertRaises(module.SupervisorError):
            supervisor.append_event("rejected")
        self.assertEqual(supervisor.config.event_log_path.read_bytes(), b"old\n")

    def test_fifo_event_path_does_not_block(self) -> None:
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        os.mkfifo(supervisor.config.event_log_path, 0o600)
        with self.assertRaises(module.SupervisorError):
            supervisor.append_event("rejected")

    def test_zero_progress_status_preserves_old_and_leaves_no_temporary(self) -> None:
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        supervisor.write_status("inhibited")
        old = supervisor.config.status_path.read_bytes()
        with mock.patch.object(module.os, "write", return_value=0):
            with self.assertRaises(module.SupervisorError):
                supervisor.write_status("running")
        self.assertEqual(supervisor.config.status_path.read_bytes(), old)
        self.assertEqual(list(supervisor.config.status_path.parent.glob(".*.tmp-*")), [])

    def test_replace_failure_preserves_old_and_leaves_no_temporary(self) -> None:
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        supervisor.write_status("inhibited")
        old = supervisor.config.status_path.read_bytes()
        with mock.patch.object(module.os, "replace", side_effect=OSError("injected replace failure")):
            with self.assertRaises(OSError):
                supervisor.write_status("running")
        self.assertEqual(supervisor.config.status_path.read_bytes(), old)
        self.assertEqual(list(supervisor.config.status_path.parent.glob(".*.tmp-*")), [])

    def test_directory_fsync_after_replace_failure_is_not_success(self) -> None:
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        sync = os.fsync
        def do_sync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("injected directory fsync failure")
            return sync(fd)
        with mock.patch.object(module.os, "fsync", side_effect=do_sync):
            with self.assertRaises(OSError):
                supervisor.write_status("running")
        # Rename already occurred: visibility is NOT a durability receipt.
        self.assertEqual(json.loads(supervisor.config.status_path.read_bytes())["state"], "running")
        self.assertEqual(list(supervisor.config.status_path.parent.glob(".*.tmp-*")), [])

    def test_directory_lock_descriptors_do_not_leak_across_validation(self) -> None:
        supervisor = self.supervisor()
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(20):
            supervisor.validate_state_root()
            for fd in supervisor._state_directories.values():
                self.assertFalse(os.get_inheritable(fd))
            supervisor.close_state()
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_short_write_then_exception_cleans_status_temporary(self) -> None:
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        write = os.write
        calls = 0
        def do_write(fd, data):
            nonlocal calls
            calls += 1
            if calls == 1:
                return write(fd, data[:5])
            raise OSError("injected disk error")
        with mock.patch.object(module.os, "write", side_effect=do_write):
            with self.assertRaises(OSError):
                supervisor.write_status("running")
        self.assertFalse(supervisor.config.status_path.exists())
        self.assertEqual(list(supervisor.config.status_path.parent.glob(".*.tmp-*")), [])


    def test_other_process_cannot_start_with_owned_state_root(self) -> None:
        supervisor = self.supervisor()
        supervisor.validate_state_root()
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--execute", "--config", str(self.config_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3,
        )
        self.assertEqual(result.returncode, 70)
        self.assertIn("already owned", result.stderr)
        self.assertFalse(supervisor.config.event_log_path.exists())
        self.assertFalse(supervisor.config.status_path.exists())

    def test_all_settled_leaders_are_reaped_even_when_cleanup_event_write_fails(self) -> None:
        value = self.config()
        value["children"].append(dict(value["children"][0], name="second"))
        supervisor = self.supervisor(value)
        supervisor.validate_state_root()
        managed = []
        try:
            for child in supervisor.config.children:
                item = supervisor.spawn(child)
                managed.append(item)
                os.waitid(os.P_PID, item.process.pid, os.WEXITED | os.WNOWAIT)
            with mock.patch.object(supervisor, "append_event", side_effect=OSError("injected log failure")):
                with self.assertRaises(OSError):
                    supervisor.shutdown()
            self.assertTrue(all(item.process.returncode == 0 for item in managed))
            self.assertTrue(all(item.group_cleaned for item in managed))
        finally:
            for item in managed:
                item.process.wait(timeout=2)

    def test_state_path_components_have_finite_budget(self) -> None:
        self.write_child("raise SystemExit(0)\n")
        value = self.config()
        value["status_path"] = str(self.state) + "/nested" * 65 + "/status.json"
        with self.assertRaisesRegex(module.SupervisorError, "path budget"):
            self.write_config(value)

    def test_state_path_bytes_have_finite_budget(self) -> None:
        self.write_child("raise SystemExit(0)\n")
        value = self.config()
        value["status_path"] = str(self.state) + "/" + "x" * 4096
        with self.assertRaisesRegex(module.SupervisorError, "path budget"):
            self.write_config(value)



@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "waitid"), "Linux session fence")
class RootLinuxSessionFenceTest(SupervisorFixture):
    """Local crash/admission tests, not installed or power-loss evidence."""
    SESSION = ".supervisor-session.json"

    def setUp(self) -> None:
        super().setUp()
        self.marker = self.root / "started"
        self.write_child(f"from pathlib import Path\nPath({str(self.marker)!r}).write_text('started')\n")
        self.loaded = self.write_config(self.config())
        self.supervisor = module.Supervisor(self.loaded)
        self.addCleanup(self.supervisor.close_state)

    def test_existing_session_record_inhibits_before_spawn(self) -> None:
        lease = self.state / self.SESSION
        lease.write_text('{"pid":1,"session_id":"old"}\n')
        lease.chmod(0o600)
        original = lease.read_bytes()
        with self.assertRaisesRegex(module.SupervisorError, "session.*reconcil"):
            self.supervisor.run()
        self.assertFalse(self.marker.exists())
        self.assertEqual(lease.read_bytes(), original)
        self.assertFalse(self.loaded.event_log_path.exists())

    def test_torn_or_empty_session_is_not_automatically_repaired(self) -> None:
        for raw in (b"", b'{"pid":', b"not-json\n"):
            with self.subTest(raw=raw):
                lease = self.state / self.SESSION
                lease.write_bytes(raw)
                lease.chmod(0o600)
                with self.assertRaises(module.SupervisorError):
                    self.supervisor.run()
                self.assertEqual(lease.read_bytes(), raw)
                self.assertFalse(self.marker.exists())

    def test_session_special_file_also_inhibits(self) -> None:
        lease = self.state / self.SESSION
        for kind in ("symlink", "fifo", "directory"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    lease.symlink_to(self.root / "absent")
                elif kind == "fifo":
                    os.mkfifo(lease, 0o600)
                else:
                    lease.mkdir()
                try:
                    with self.assertRaises(module.SupervisorError):
                        self.supervisor.run()
                    self.assertFalse(self.marker.exists())
                finally:
                    lease.rmdir() if kind == "directory" else lease.unlink()

    def test_session_path_is_reserved_from_configured_outputs(self) -> None:
        for field in ("status_path", "event_log_path", "emergency_stop"):
            for suffix in ("", "/nested"):
                with self.subTest(field=field, suffix=suffix):
                    value = self.config()
                    value[field] = str(self.state / (self.SESSION + suffix))
                    with self.assertRaisesRegex(module.SupervisorError, "reserved"):
                        self.write_config(value)

    def test_session_is_durable_before_the_first_spawn(self) -> None:
        self.supervisor.validate_state_root()
        actual_fsync = module.os.fsync
        syncs = []
        def record_sync(fd):
            syncs.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
            return actual_fsync(fd)
        with mock.patch.object(module.os, "fsync", side_effect=record_sync):
            self.supervisor.begin_session()
        self.assertEqual(syncs, ["file", "directory"])
        record = json.loads((self.state / self.SESSION).read_bytes())
        self.assertEqual(record["supervisor_pid"], os.getpid())
        self.assertEqual(record["session_id"], self.supervisor._session_id)
        self.assertFalse(record["automatic_effect_redispatch"])
        self.assertEqual(record["cleanup_scope"], "original_process_group_only")
        self.assertFalse(record["pid_is_recovery_authority"])

    def test_failed_session_sync_keeps_fence_and_spawns_nothing(self) -> None:
        self.supervisor.validate_state_root()
        with mock.patch.object(module.os, "fsync", side_effect=OSError("I/O failure")):
            with self.assertRaises(OSError):
                self.supervisor.begin_session()
        self.assertTrue((self.state / self.SESSION).exists())
        self.assertFalse(self.marker.exists())
        self.supervisor.close_state()
        other = module.Supervisor(self.loaded)
        with self.assertRaises(module.SupervisorError):
            other.run()

    def test_short_session_write_is_completed(self) -> None:
        self.supervisor.validate_state_root()
        original = module.os.write
        with mock.patch.object(module.os, "write", side_effect=lambda fd, data: original(fd, data[:7])):
            self.supervisor.begin_session()
        self.assertEqual(json.loads((self.state / self.SESSION).read_bytes())["session_id"], self.supervisor._session_id)

    def test_zero_session_write_retains_fence(self) -> None:
        self.supervisor.validate_state_root()
        with mock.patch.object(module.os, "write", return_value=0):
            with self.assertRaises(module.SupervisorError):
                self.supervisor.begin_session()
        self.assertEqual((self.state / self.SESSION).read_bytes(), b"")
        self.assertFalse(self.marker.exists())

    def test_replaced_session_blocks_carrier_admission(self) -> None:
        self.supervisor.validate_state_root()
        self.supervisor.begin_session()
        lease = self.state / self.SESSION
        retained = self.state / "retained-lease"
        lease.rename(retained)
        lease.write_bytes(retained.read_bytes())
        lease.chmod(0o600)
        with self.assertRaisesRegex(module.SupervisorError, "session.*identity"):
            self.supervisor.spawn(self.loaded.children[0])
        self.assertFalse(self.marker.exists())

    def test_changed_or_missing_session_blocks_carrier_admission(self) -> None:
        self.supervisor.validate_state_root()
        self.supervisor.begin_session()
        lease = self.state / self.SESSION
        lease.write_bytes(b"changed\n")
        with self.assertRaises(module.SupervisorError):
            self.supervisor.spawn(self.loaded.children[0])
        lease.unlink()
        with self.assertRaises((module.SupervisorError, OSError)):
            self.supervisor.spawn(self.loaded.children[0])
        self.assertFalse(self.marker.exists())

    def test_failed_run_retains_session_for_offline_reconciliation(self) -> None:
        self.assertEqual(self.supervisor.run(), 70)  # restart limit is zero
        lease = self.state / self.SESSION
        self.assertTrue(lease.exists())
        self.assertTrue(all(c.group_cleaned for c in self.supervisor.children.values()))
        before = self.loaded.event_log_path.read_bytes()
        with self.assertRaises(module.SupervisorError):
            module.Supervisor(self.loaded).run()
        self.assertEqual(self.loaded.event_log_path.read_bytes(), before)

    def test_normal_stop_removes_session_only_after_terminal_record(self) -> None:
        original_event = self.supervisor.append_event
        def stop_after_start(kind, **fields):
            original_event(kind, **fields)
            if kind == "child_started":
                self.supervisor.request_stop("test_stop")
        original_unlink = module.os.unlink
        def checked_unlink(path, **kwargs):
            if path == self.SESSION:
                self.assertIn(b'"kind":"supervisor_terminal"', self.loaded.event_log_path.read_bytes())
                self.assertTrue(all(c.group_cleaned for c in self.supervisor.children.values()))
            return original_unlink(path, **kwargs)
        with mock.patch.object(self.supervisor, "append_event", side_effect=stop_after_start), mock.patch.object(module.os, "unlink", side_effect=checked_unlink):
            self.assertEqual(self.supervisor.run(), 0)
        self.assertFalse((self.state / self.SESSION).exists())

    def test_clean_emergency_stop_releases_own_session_not_owner_inhibit(self) -> None:
        original = self.supervisor.append_event
        def inhibit_after_start(kind, **fields):
            original(kind, **fields)
            if kind == "child_started":
                self.loaded.emergency_stop.write_text("stop")
        with mock.patch.object(self.supervisor, "append_event", side_effect=inhibit_after_start):
            self.assertEqual(self.supervisor.run(), 75)
        self.assertFalse((self.state / self.SESSION).exists())
        self.assertTrue(self.loaded.emergency_stop.exists())

    def test_terminal_log_failure_keeps_session_fence(self) -> None:
        original = self.supervisor.append_event
        def fail_terminal(kind, **fields):
            if kind == "supervisor_terminal":
                raise OSError("terminal storage unavailable")
            original(kind, **fields)
            if kind == "child_started":
                self.supervisor.request_stop("test_stop")
        with mock.patch.object(self.supervisor, "append_event", side_effect=fail_terminal):
            self.assertEqual(self.supervisor.run(), 70)
        self.assertTrue((self.state / self.SESSION).exists())
        self.assertTrue(all(c.group_cleaned for c in self.supervisor.children.values()))

    def test_unconfirmed_group_never_releases_session_fence(self) -> None:
        self.supervisor.validate_state_root()
        self.supervisor.begin_session()
        self.supervisor.children["uncertain"] = mock.Mock(group_cleaned=False)
        with self.assertRaisesRegex(module.SupervisorError, "cleanup"):
            self.supervisor.finish_session()
        self.assertTrue((self.state / self.SESSION).exists())

    def test_finish_never_unlinks_replacement_session(self) -> None:
        self.supervisor.validate_state_root()
        self.supervisor.begin_session()
        lease = self.state / self.SESSION
        self.supervisor._terminal_recorded = True
        lease.rename(self.state / "old-session")
        lease.write_text("replacement")
        lease.chmod(0o600)
        with self.assertRaises(module.SupervisorError):
            self.supervisor.finish_session()
        self.assertEqual(lease.read_text(), "replacement")

    def test_supervisor_sigkill_fences_restart_while_old_carrier_is_alive(self) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        old = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(old), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        pidfile = self.state / "live-carriers"
        self.child.chmod(0o700)
        self.write_child(
            "import os,time\n"
            f"with open({str(pidfile)!r}, 'a') as stream: stream.write(str(os.getpid()) + '\\n'); stream.flush()\n"
            "while True: time.sleep(1)\n"
        )
        process = None
        again = None
        try:
            process = subprocess.Popen([sys.executable, str(SCRIPT), "--execute", "--config", str(self.config_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 5
            while (not pidfile.exists() or not pidfile.read_text().strip()) and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(pidfile.exists(), "first carrier must actually start")
            old_pid = int(pidfile.read_text().strip())
            process.kill()
            process.wait(timeout=5)
            os.kill(old_pid, 0)  # demonstrably still alive, not a cleanup receipt
            again = subprocess.Popen([sys.executable, str(SCRIPT), "--execute", "--config", str(self.config_path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                _, stderr = again.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                again.terminate()
                _, stderr = again.communicate(timeout=5)
                self.fail("replacement supervisor started despite unclean prior session")
            self.assertEqual(again.returncode, 70, stderr.decode())
            self.assertIn(b"reconcil", stderr)
            self.assertEqual(pidfile.read_text().splitlines(), [str(old_pid)])
        finally:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
            if again is not None:
                if again.poll() is None:
                    again.kill()
                again.wait(timeout=5)
                if again.stderr is not None:
                    again.stderr.close()
            if pidfile.exists():
                for text in pidfile.read_text().splitlines():
                    pid = int(text)
                    try:
                        # Subreaper retains the exact orphan's waitable PID anchor.
                        os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    except ChildProcessError:
                        continue
                    try:
                        os.killpg(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    os.waitpid(pid, 0)
            libc.prctl(36, old.value, 0, 0, 0)

    def test_session_finish_requires_durable_terminal_even_without_children(self) -> None:
        self.supervisor.validate_state_root()
        self.supervisor.begin_session()
        with self.assertRaisesRegex(module.SupervisorError, "terminal"):
            self.supervisor.finish_session()
        self.assertTrue((self.state / self.SESSION).exists())

    def test_session_directory_sync_failure_prevents_admission(self) -> None:
        self.supervisor.validate_state_root()
        original = module.os.fsync
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("directory durability unknown")
            return original(fd)
        with mock.patch.object(module.os, "fsync", side_effect=fail_directory):
            with self.assertRaises(OSError):
                self.supervisor.begin_session()
        with self.assertRaises(module.SupervisorError):
            self.supervisor.spawn(self.loaded.children[0])
        self.assertFalse(self.marker.exists())
        self.assertTrue((self.state / self.SESSION).exists())

    def test_session_removal_sync_failure_is_not_success(self) -> None:
        self.supervisor.validate_state_root()
        self.supervisor.begin_session()
        self.supervisor._terminal_recorded = True
        with mock.patch.object(module.os, "fsync", side_effect=OSError("release durability unknown")):
            with self.assertRaises(OSError):
                self.supervisor.finish_session()
        self.assertTrue(self.supervisor._session_ready)
        self.assertFalse((self.state / self.SESSION).exists())
        with self.assertRaises((module.SupervisorError, OSError)):
            self.supervisor.spawn(self.loaded.children[0])
        self.assertFalse(self.marker.exists())

    def test_session_creation_is_exclusive_even_after_clear_check(self) -> None:
        self.supervisor.validate_state_root()
        self.supervisor.assert_session_clear()
        lease = self.state / self.SESSION
        lease.write_bytes(b"another session\n")
        with self.assertRaises(OSError):
            self.supervisor.begin_session()
        self.assertEqual(lease.read_bytes(), b"another session\n")
        self.assertFalse(self.marker.exists())

    def test_session_event_and_status_share_exact_session_id(self) -> None:
        self.assertEqual(self.supervisor.run(), 70)
        record = json.loads((self.state / self.SESSION).read_bytes())
        status = json.loads(self.loaded.status_path.read_bytes())
        events = [json.loads(raw) for raw in self.loaded.event_log_path.read_bytes().splitlines()]
        self.assertEqual(status["session_id"], record["session_id"])
        self.assertTrue(events)
        self.assertTrue(all(e["session_id"] == record["session_id"] for e in events))

    def test_normal_completed_session_permits_new_instance(self) -> None:
        original_event = self.supervisor.append_event
        def stop_after_start(kind, **fields):
            original_event(kind, **fields)
            if kind == "child_started":
                self.supervisor.request_stop("test_stop")
        with mock.patch.object(self.supervisor, "append_event", side_effect=stop_after_start):
            self.assertEqual(self.supervisor.run(), 0)
        prior_id = self.supervisor._session_id
        other = module.Supervisor(self.loaded)
        self.assertEqual(other.run(), 70)
        self.assertNotEqual(prior_id, other._session_id)

if __name__ == "__main__":
    unittest.main()
