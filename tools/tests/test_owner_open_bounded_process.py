#!/usr/bin/env python3
"""Real-process and finite observation regressions for host-only capture."""
from __future__ import annotations

from contextlib import ExitStack
import errno
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "owner_open_bounded_process.py"
SPEC = importlib.util.spec_from_file_location("host_only_bounded_process", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


@unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "WNOWAIT"), "Linux retained-session backend")
class BoundedProcessTests(unittest.TestCase):
    def call(self, source: str = "print('complete')", **kwargs):
        return RUNNER.run_bounded(
            ["/usr/bin/python3", "-c", source],
            timeout_seconds=kwargs.pop("timeout_seconds", 2),
            maximum_output=kwargs.pop("maximum_output", 1024),
            **kwargs,
        )

    def assert_real_failure(self, patchers, *, source="import time; time.sleep(30)", flag="capture_error", after_spawn=None):
        real_spawn = subprocess.Popen
        real_killpg = os.killpg
        processes = []
        pipes = []
        signals = []

        def spawn(*args, **kwargs):
            process = real_spawn(*args, **kwargs)
            processes.append(process)
            pipes.extend((process.stdout, process.stderr))
            if after_spawn is not None:
                after_spawn(process)
            return process

        def killpg(group, selected):
            process = processes[0]
            self.assertEqual(group, process.pid)
            self.assertIsNone(process.returncode)
            os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            signals.append(selected)
            return real_killpg(group, selected)

        started = time.monotonic()
        try:
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(RUNNER.subprocess, "Popen", side_effect=spawn))
                stack.enter_context(mock.patch.object(RUNNER.os, "killpg", side_effect=killpg))
                for patcher in patchers:
                    stack.enter_context(patcher)
                with self.assertRaises(RUNNER.BoundedProcessError) as raised:
                    self.call(source)
            self.assertTrue(getattr(raised.exception, flag))
            self.assertLess(time.monotonic() - started, 3)
            self.assertEqual(signals, [signal.SIGKILL])
            self.assertEqual(len(processes), 1)
            process = processes[0]
            self.assertIsNotNone(process.returncode)
            self.assertTrue(process.stdout.closed)
            self.assertTrue(process.stderr.closed)
            self.assertTrue(all(pipe.closed for pipe in pipes))
            return raised.exception
        finally:
            for process in processes:
                if process.returncode is None:
                    real_killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=2)
            for pipe in pipes:
                pipe.close()

    def test_normal_stdout_stderr_are_captured(self):
        result = self.call("import os; os.write(1,b'out'); os.write(2,b'err')")
        self.assertEqual(result, (0, b"out", b"err"))

    def test_combined_budget_accepts_exact_boundary(self):
        result = self.call("import os; os.write(1,b'a'*64); os.write(2,b'b'*64)", maximum_output=128)
        self.assertEqual(result.stdout, b"a" * 64)
        self.assertEqual(result.stderr, b"b" * 64)

    def test_combined_budget_rejects_two_individually_small_streams(self):
        with self.assertRaises(RUNNER.BoundedProcessError) as raised:
            self.call("import os; os.write(1,b'a'*100); os.write(2,b'b'*100)", maximum_output=128)
        self.assertTrue(raised.exception.output_limit_exceeded)
        self.assertEqual(len(raised.exception.stdout) + len(raised.exception.stderr), 128)

    def test_large_stdout_preserves_only_bounded_partial_capture(self):
        with self.assertRaises(RUNNER.BoundedProcessError) as raised:
            self.call("import os; os.write(1,b'x'*10000000)", maximum_output=128)
        self.assertTrue(raised.exception.output_limit_exceeded)
        self.assertEqual(raised.exception.stdout, b"x" * 128)
        self.assertEqual(raised.exception.stderr, b"")

    def test_large_stderr_preserves_only_bounded_partial_capture(self):
        with self.assertRaises(RUNNER.BoundedProcessError) as raised:
            self.call("import os; os.write(2,b'x'*10000000)", maximum_output=128)
        self.assertTrue(raised.exception.output_limit_exceeded)
        self.assertEqual(raised.exception.stderr, b"x" * 128)
        self.assertEqual(raised.exception.stdout, b"")

    def test_nonzero_status_is_returned_for_caller_policy(self):
        result = self.call("import sys; print('rejected'); sys.exit(9)")
        self.assertEqual(result, (9, b"rejected\n", b""))

    def test_signalled_leader_status_is_returned(self):
        result = self.call("import os,signal; os.kill(os.getpid(),signal.SIGTERM)")
        self.assertEqual(result.returncode, -signal.SIGTERM)

    def test_timeout_retires_live_leader(self):
        with self.assertRaises(RUNNER.BoundedProcessError) as raised:
            self.call("import time; time.sleep(30)", timeout_seconds=0.05)
        self.assertTrue(raised.exception.timed_out)
        self.assertEqual(raised.exception.returncode, -signal.SIGKILL)
        self.assertFalse(raised.exception.cleanup_error)

    def test_closed_pipes_do_not_admit_live_leader(self):
        with self.assertRaises(RUNNER.BoundedProcessError) as raised:
            self.call("import os,time; os.close(1); os.close(2); time.sleep(30)", timeout_seconds=0.05)
        self.assertTrue(raised.exception.timed_out)
        self.assertEqual(raised.exception.returncode, -signal.SIGKILL)

    def test_late_selector_result_cannot_admit_already_exited_leader(self):
        real_selector = RUNNER.selectors.DefaultSelector

        def create():
            selector = real_selector()
            proxy = mock.Mock(wraps=selector)

            def select(_):
                time.sleep(0.12)
                return selector.select(0)

            proxy.select.side_effect = select
            return proxy

        with mock.patch.object(RUNNER.selectors, "DefaultSelector", side_effect=create):
            with self.assertRaises(RUNNER.BoundedProcessError) as raised:
                self.call("import time; time.sleep(0.075)", timeout_seconds=0.03)
        self.assertTrue(raised.exception.timed_out)
        self.assertFalse(raised.exception.cleanup_error)

    def test_late_exit_observation_cannot_admit_capture(self):
        real_observe = RUNNER._leader_exit_unreaped
        delayed = False

        def observe(process):
            nonlocal delayed
            status = real_observe(process)
            if status is not None and not delayed:
                delayed = True
                time.sleep(0.06)
            return status

        with mock.patch.object(RUNNER, "_leader_exit_unreaped", side_effect=observe):
            with self.assertRaises(RUNNER.BoundedProcessError) as raised:
                self.call("pass", timeout_seconds=0.04)
        self.assertTrue(delayed)
        self.assertTrue(raised.exception.timed_out)

    def test_invalid_timeout_rejected_before_spawn(self):
        for timeout in (0, -1, float("nan"), float("inf"), True, 10 ** 1000):
            with self.subTest(timeout=timeout), mock.patch.object(RUNNER.subprocess, "Popen") as spawn:
                with self.assertRaises(RUNNER.BoundedProcessError):
                    self.call(timeout_seconds=timeout)
                spawn.assert_not_called()

    def test_invalid_output_bound_rejected_before_spawn(self):
        for bound in (0, -1, True, float("inf")):
            with self.subTest(bound=bound), mock.patch.object(RUNNER.subprocess, "Popen") as spawn:
                with self.assertRaises(RUNNER.BoundedProcessError):
                    self.call(maximum_output=bound)
                spawn.assert_not_called()

    def test_invalid_argv_rejected_before_spawn(self):
        for argv in ([], [""], ["/usr/bin/true", "nul\x00"], "/usr/bin/true", [1], {"command": "true"}):
            with self.subTest(argv=argv), mock.patch.object(RUNNER.subprocess, "Popen") as spawn:
                with self.assertRaises(RUNNER.BoundedProcessError):
                    RUNNER.run_bounded(argv, timeout_seconds=1, maximum_output=1024)
                spawn.assert_not_called()

    def test_spawn_failure_has_no_capture_or_cleanup_success(self):
        with mock.patch.object(RUNNER.subprocess, "Popen", side_effect=OSError(errno.ENOENT, "fixture")):
            with self.assertRaises(RUNNER.BoundedProcessError) as raised:
                self.call()
        self.assertTrue(raised.exception.spawn_error)
        self.assertIsNone(raised.exception.returncode)

    def test_missing_waitid_rejected_before_spawn(self):
        with mock.patch.object(RUNNER.os, "waitid", None), mock.patch.object(RUNNER.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(RUNNER.BoundedProcessError, "requires Linux WNOWAIT"):
                self.call()
            spawn.assert_not_called()

    def test_ignored_sigchld_rejected_before_spawn(self):
        with mock.patch.object(RUNNER.signal, "getsignal", return_value=signal.SIG_IGN), mock.patch.object(RUNNER.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(RUNNER.BoundedProcessError, "default SIGCHLD"):
                self.call()
            spawn.assert_not_called()

    def test_nonlinux_backend_rejected_before_spawn(self):
        with mock.patch.object(RUNNER.sys, "platform", "win32"), mock.patch.object(RUNNER.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(RUNNER.BoundedProcessError, "requires Linux WNOWAIT"):
                self.call()
            spawn.assert_not_called()

    def test_selector_constructor_failure_cleans_spawned_process(self):
        self.assert_real_failure([mock.patch.object(RUNNER.selectors, "DefaultSelector", side_effect=OSError(errno.EMFILE, "fixture"))])

    def test_descriptor_access_failure_cleans_spawned_process(self):
        def replace_stream(process):
            actual = process.stdout
            proxy = mock.Mock(wraps=actual)
            proxy.fileno.side_effect = OSError(errno.EBADF, "fixture descriptor failure")
            process.stdout = proxy

        self.assert_real_failure([], after_spawn=replace_stream)

    def test_stream_close_failure_still_closes_other_stream(self):
        def replace_stream(process):
            actual = process.stdout
            proxy = mock.Mock(wraps=actual)

            def close():
                actual.close()
                raise OSError(errno.EIO, "fixture close failure")

            proxy.close.side_effect = close
            process.stdout = proxy

        self.assert_real_failure(
            [], source="print('ready')", flag="cleanup_error", after_spawn=replace_stream
        )

    def test_capture_interrupt_still_retires_process_and_closes_pipes(self):
        real_spawn = subprocess.Popen
        processes = []

        def spawn(*args, **kwargs):
            process = real_spawn(*args, **kwargs)
            processes.append(process)
            return process

        with mock.patch.object(RUNNER.subprocess, "Popen", side_effect=spawn), mock.patch.object(
            RUNNER.selectors, "DefaultSelector", side_effect=KeyboardInterrupt
        ):
            with self.assertRaises(KeyboardInterrupt):
                self.call("import time; time.sleep(30)")
        self.assertEqual(processes[0].returncode, -signal.SIGKILL)
        self.assertTrue(processes[0].stdout.closed)
        self.assertTrue(processes[0].stderr.closed)

    def test_cleanup_interrupt_retries_retirement_before_reaping_and_closing(self):
        real_spawn = subprocess.Popen
        real_members = RUNNER._group_live_members
        processes = []
        interrupted = False

        def spawn(*args, **kwargs):
            process = real_spawn(*args, **kwargs)
            processes.append(process)
            return process

        def members(*args):
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                raise KeyboardInterrupt
            return real_members(*args)

        with mock.patch.object(RUNNER.subprocess, "Popen", side_effect=spawn), mock.patch.object(
            RUNNER, "_group_live_members", side_effect=members
        ):
            with self.assertRaises(KeyboardInterrupt):
                self.call("pass")
        self.assertTrue(interrupted)
        self.assertEqual(processes[0].returncode, 0)
        self.assertTrue(processes[0].stdout.closed)
        self.assertTrue(processes[0].stderr.closed)

    def test_consuming_wait_interrupt_retries_reap_before_delivering_interrupt(self):
        real_spawn = subprocess.Popen
        processes = []

        def spawn(*args, **kwargs):
            process = real_spawn(*args, **kwargs)
            processes.append(process)
            real_wait = process.wait
            interrupted = False

            def wait(*args, **kwargs):
                nonlocal interrupted
                if not interrupted:
                    interrupted = True
                    raise KeyboardInterrupt("wait fixture")
                return real_wait(*args, **kwargs)

            process.wait = mock.Mock(side_effect=wait)
            return process

        with mock.patch.object(RUNNER.subprocess, "Popen", side_effect=spawn):
            with self.assertRaisesRegex(KeyboardInterrupt, "wait fixture"):
                self.call("pass")
        self.assertEqual(processes[0].returncode, 0)
        self.assertTrue(processes[0].stdout.closed)
        self.assertTrue(processes[0].stderr.closed)

    def test_selector_close_interrupt_retries_close_before_delivering_interrupt(self):
        real_selector = RUNNER.selectors.DefaultSelector
        selectors = []

        def create():
            actual = real_selector()
            selectors.append(actual)
            proxy = mock.Mock(wraps=actual)
            interrupted = False

            def close():
                nonlocal interrupted
                if not interrupted:
                    interrupted = True
                    raise KeyboardInterrupt("selector fixture")
                actual.close()

            proxy.close.side_effect = close
            return proxy

        try:
            with mock.patch.object(RUNNER.selectors, "DefaultSelector", side_effect=create):
                with self.assertRaisesRegex(KeyboardInterrupt, "selector fixture"):
                    self.call("pass")
            self.assertIsNone(selectors[0].get_map())
        finally:
            for selector in selectors:
                selector.close()

    def test_stream_close_interrupt_retries_both_closes_before_delivering_interrupt(self):
        real_spawn = subprocess.Popen
        pipes = []
        processes = []

        def spawn(*args, **kwargs):
            process = real_spawn(*args, **kwargs)
            processes.append(process)
            actual = process.stdout
            pipes.extend((actual, process.stderr))
            proxy = mock.Mock(wraps=actual)
            interrupted = False

            def close():
                nonlocal interrupted
                if not interrupted:
                    interrupted = True
                    raise KeyboardInterrupt("stream fixture")
                actual.close()

            proxy.close.side_effect = close
            process.stdout = proxy
            return process

        try:
            with mock.patch.object(RUNNER.subprocess, "Popen", side_effect=spawn):
                with self.assertRaisesRegex(KeyboardInterrupt, "stream fixture"):
                    self.call("pass")
            self.assertEqual(processes[0].returncode, 0)
            self.assertTrue(all(pipe.closed for pipe in pipes))
        finally:
            for pipe in pipes:
                pipe.close()

    def test_second_set_blocking_failure_cleans_partial_setup(self):
        real_set_blocking = os.set_blocking
        calls = 0

        def set_blocking(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError(errno.EIO, "fixture")
            return real_set_blocking(*args)

        self.assert_real_failure([mock.patch.object(RUNNER.os, "set_blocking", side_effect=set_blocking)])

    def _selector_fault(self, stage, after_calls=0):
        real_selector = RUNNER.selectors.DefaultSelector
        selectors = []

        def create():
            selector = real_selector()
            selectors.append(selector)
            proxy = mock.Mock(wraps=selector)
            calls = 0

            def operation(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls > after_calls:
                    if stage == "close":
                        selector.close()
                    raise OSError(errno.EIO, "fixture selector failure")
                return getattr(selector, stage)(*args, **kwargs)

            getattr(proxy, stage).side_effect = operation
            return proxy

        try:
            self.assert_real_failure(
                [mock.patch.object(RUNNER.selectors, "DefaultSelector", side_effect=create)],
                source="print('ready', flush=True)" if stage in ("unregister", "close") else "import time; time.sleep(30)",
                flag="cleanup_error" if stage == "close" else "capture_error",
            )
        finally:
            for selector in selectors:
                selector.close()

    def test_first_registration_failure_cleans_process(self):
        self._selector_fault("register")

    def test_second_registration_failure_cleans_partial_selector(self):
        self._selector_fault("register", after_calls=1)

    def test_select_failure_cleans_process(self):
        self._selector_fault("select")

    def test_unregister_failure_cleans_process(self):
        self._selector_fault("unregister")

    def test_selector_close_failure_is_not_success(self):
        self._selector_fault("close")

    def test_pipe_read_error_retires_process(self):
        real_read = os.read

        def read(descriptor, count):
            # Popen's exec-status pipe uses a much larger request. Preserve it
            # so the fault exercises capture after a real successful spawn.
            if count <= 1025:
                raise OSError(errno.EIO, "fixture capture read failure")
            return real_read(descriptor, count)

        self.assert_real_failure(
            [mock.patch.object(RUNNER.os, "read", side_effect=read)],
            source="print('ready', flush=True); import time; time.sleep(30)",
        )

    def test_blocking_read_retry_preserves_output(self):
        real_read = os.read
        retry = True

        def read(descriptor, count):
            nonlocal retry
            if count <= 1025 and retry:
                retry = False
                raise BlockingIOError(errno.EAGAIN, "fixture retry")
            return real_read(descriptor, count)

        with mock.patch.object(RUNNER.os, "read", side_effect=read):
            self.assertEqual(self.call().stdout, b"complete\n")
        self.assertFalse(retry)

    def test_incomplete_procfs_observation_rejects_success(self):
        self.assert_real_failure(
            [mock.patch.object(RUNNER, "_group_live_members", side_effect=PermissionError(errno.EACCES, "fixture"))],
            source="print('ready', flush=True)", flag="cleanup_error",
        )

    def test_procfs_entry_budget_rejects_success(self):
        self.assert_real_failure(
            [mock.patch.object(RUNNER, "MAX_PROC_ENTRIES", 0)],
            source="print('ready', flush=True)", flag="cleanup_error",
        )

    def test_procfs_stat_budget_rejects_success(self):
        self.assert_real_failure(
            [mock.patch.object(RUNNER, "MAX_PROC_STAT_BYTES", 1)],
            source="print('ready', flush=True)", flag="cleanup_error",
        )

    def test_already_reaped_leader_never_signals_recycled_group(self):
        real_spawn = subprocess.Popen
        processes = []

        def spawn(*args, **kwargs):
            process = real_spawn(*args, **kwargs)
            processes.append(process)
            process.wait(timeout=2)
            return process

        with mock.patch.object(RUNNER.subprocess, "Popen", side_effect=spawn), mock.patch.object(RUNNER.os, "killpg") as killpg:
            with self.assertRaises(RUNNER.BoundedProcessError) as raised:
                self.call()
        self.assertTrue(raised.exception.cleanup_error)
        killpg.assert_not_called()
        self.assertTrue(processes[0].stdout.closed)
        self.assertTrue(processes[0].stderr.closed)


if __name__ == "__main__":
    unittest.main()
