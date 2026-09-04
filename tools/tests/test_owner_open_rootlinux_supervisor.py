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


if __name__ == "__main__":
    unittest.main()
