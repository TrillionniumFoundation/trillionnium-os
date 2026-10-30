"""Host regressions for exact native startup diagnostics, not device readiness."""
from __future__ import annotations
import errno
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "android-integration/working-tree/vendor/trillionnium/owner-open/native/owner_open_bootstrap.cpp"
SPEC = importlib.util.spec_from_file_location("native_startup_supervisor", ROOT / "tools/owner-open/owner_open_rootlinux_supervisor.py")
assert SPEC and SPEC.loader
supervisor = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = supervisor
SPEC.loader.exec_module(supervisor)

class NativeStartupClassificationTest(unittest.TestCase):
    def call(self, *, native: bool, phase: str, fail_constructor: bool = False, fail_config: bool = False) -> int:
        args = ["--execute", "--config", "/unread-fixture"]
        if native:
            args.append("--same-domain-proc-observation")
        obj = mock.Mock(startup_phase=phase)
        obj.run.side_effect = supervisor.SupervisorError("fixture failure")
        with mock.patch.object(supervisor, "load_config", side_effect=OSError(errno.EACCES, "fixture") if fail_config else None, return_value=object()), mock.patch.object(supervisor, "Supervisor", side_effect=supervisor.SupervisorError("fixture domain") if fail_constructor else None, return_value=obj), mock.patch("sys.stderr", new_callable=io.StringIO):
            return supervisor.main(args)

    def test_config_failure_is_80(self):
        self.assertEqual(self.call(native=True, phase="unused", fail_config=True), 80)

    def test_domain_failure_is_81(self):
        self.assertEqual(self.call(native=True, phase="unused", fail_constructor=True), 81)

    def test_platform_failure_is_82(self):
        self.assertEqual(self.call(native=True, phase="platform"), 82)

    def test_state_handoff_failure_is_83(self):
        self.assertEqual(self.call(native=True, phase="state_root"), 83)

    def test_retained_session_is_84_not_missing_file(self):
        self.assertEqual(self.call(native=True, phase="prior_session"), 84)

    def test_session_creation_failure_is_85(self):
        self.assertEqual(self.call(native=True, phase="session_create"), 85)

    def test_carrier_spawn_failure_is_86(self):
        self.assertEqual(self.call(native=True, phase="carrier_spawn"), 86)

    def test_status_failure_is_87(self):
        self.assertEqual(self.call(native=True, phase="status_publish"), 87)

    def test_runtime_failure_keeps_70(self):
        self.assertEqual(self.call(native=True, phase="runtime"), 70)

    def test_generic_supervisor_abi_unchanged(self):
        for phase in supervisor.NATIVE_STARTUP_EXIT_CODES:
            with self.subTest(phase=phase):
                self.assertEqual(self.call(native=False, phase=phase), 70)
        self.assertEqual(self.call(native=False, phase="unused", fail_config=True), 70)

    def test_unknown_native_phase_fails_closed(self):
        self.assertEqual(supervisor.startup_failure_exit_code(True, "unknown"), 70)

    def test_native_scope_still_requires_exact_domain(self):
        with mock.patch("builtins.open", mock.mock_open(read_data=b"u:r:shell:s0\n")):
            with self.assertRaises(supervisor.SupervisorError):
                supervisor.assert_same_domain_observation()

    def test_prior_session_is_not_removed_or_adopted(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            marker = state / supervisor.SESSION_FILE
            marker.write_bytes(b"retained-unknown-session")
            fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
            obj = supervisor.Supervisor.__new__(supervisor.Supervisor)
            obj.config = SimpleNamespace(state_root=state)
            try:
                with mock.patch.object(obj, "state_parent", return_value=fd):
                    with self.assertRaises(supervisor.SupervisorError):
                        obj.assert_session_clear()
                self.assertEqual(marker.read_bytes(), b"retained-unknown-session")
            finally:
                os.close(fd)

    def test_ready_and_timeout_checks_are_not_relaxed(self):
        text = SOURCE.read_text()
        for expected in ('std::chrono::seconds(15)', 'status["children"].size() == 2', 'descriptor["host_hello_ack"]["payload"]["runtime_ready"] == true', 'relay["automatic_redispatch"] == false', 'errno = failure_errno;', 'ready = WaitForSupervisorReady(child, &readiness);'):
            self.assertIn(expected, text)
        self.assertLess(text.index('const int failure_errno = readiness.error;'), text.index('kill(-child, SIGKILL);', text.index('const int failure_errno = readiness.error;')))

class NativeWaitidExecutableTest(unittest.TestCase):
    def test_compiled_bootstrap_waitid_preserves_generation_and_cause(self):
        jsoncpp = os.environ.get("TRILLIONNIUM_JSONCPP_ROOT")
        compiler = shutil.which(os.environ.get("CXX", "g++"))
        if not jsoncpp or not compiler:
            self.skipTest("set TRILLIONNIUM_JSONCPP_ROOT and CXX to compile the exact bootstrap")
        upstream = Path(jsoncpp)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            harness = base / "test.cpp"
            harness.write_text('#define main owner_open_original_main\n#include "' + str(SOURCE) + '"\n#undef main\n' + r"""
#include <cassert>
int main() {
  // Deliberately poison errno with the original misleading ENOENT.
  pid_t exited = fork(); assert(exited >= 0);
  if (exited == 0) _exit(84);
  siginfo_t info{};
  assert(waitid(P_PID, exited, &info, WEXITED | WNOWAIT) == 0);
  errno = ENOENT;
  ReadinessObservation seen;
  assert(!WaitForSupervisorReady(exited, &seen));
  assert(seen.phase == ReadinessPhase::ChildExited);
  assert(seen.error == ECHILD && errno == ECHILD);
  assert(seen.child_code == CLD_EXITED && seen.child_status == 84);
  errno = ENOSPC; ReportReadinessFailure(seen); assert(errno == ENOSPC);
  int status = 0;
  assert(waitpid(exited, &status, 0) == exited); // WNOWAIT did not reap.
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 84);
  assert(!SupervisorStillAlive(exited, &seen));
  assert(seen.phase == ReadinessPhase::WaitId && seen.error == ECHILD);
  pid_t live = fork(); assert(live >= 0);
  if (live == 0) { for (;;) pause(); }
  assert(SupervisorStillAlive(live, &seen));
  assert(kill(live, SIGTERM) == 0);
  assert(waitid(P_PID, live, &info, WEXITED | WNOWAIT) == 0);
  errno = ENOENT;
  assert(!SupervisorStillAlive(live, &seen));
  assert(seen.child_code == CLD_KILLED && seen.child_status == SIGTERM);
  assert(seen.error == ECHILD);
  assert(waitpid(live, &status, 0) == live);
  return 0;
}
""")
            binary = base / "test"
            cmd = [compiler, "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I" + str(upstream / "include"), str(harness)]
            cmd += [str(upstream / "src/lib_json" / name) for name in ("json_reader.cpp", "json_value.cpp", "json_writer.cpp")]
            crypto_root = os.environ.get("TRILLIONNIUM_BORINGSSL_ROOT")
            crypto_library = os.environ.get("TRILLIONNIUM_CRYPTO_LIBRARY")
            if crypto_root and crypto_library:
                cmd += ["-I" + str(Path(crypto_root) / "include"), crypto_library,
                        "-Wl,-rpath," + str(Path(crypto_library).parent)]
            else:
                cmd += ["-lcrypto"]
            cmd += ["-o", str(binary)]
            built = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=8)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("readiness=4", run.stderr)
            self.assertIn("child_status=84", run.stderr)

if __name__ == "__main__":
    unittest.main()
