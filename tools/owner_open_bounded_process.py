#!/usr/bin/env python3
"""Host-only bounded capture with an unreaped session leader as group anchor.

The caller must be the exclusive direct-child reaper and leave SIGCHLD at its
Linux default. Cleanup observes only the owned group in this procfs namespace;
it cannot prove absence of a descendant that escapes with setsid/setpgid, or
provide cgroup, installed-device or release qualification.
"""
from __future__ import annotations

from collections.abc import Sequence
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
from typing import Mapping, NamedTuple


MAX_PROC_ENTRIES = 65_536
MAX_PROC_TASK_ENTRIES = 65_536
MAX_PROC_STAT_BYTES = 4096
CLEANUP_TIMEOUT_SECONDS = 1.0


class BoundedProcessResult(NamedTuple):
    returncode: int
    stdout: bytes
    stderr: bytes


class BoundedProcessError(RuntimeError):
    def __init__(
        self, message: str, *, stdout: bytes = b"", stderr: bytes = b"",
        returncode: int | None = None, timed_out: bool = False,
        output_limit_exceeded: bool = False, spawn_error: bool = False,
        capture_error: bool = False, cleanup_error: bool = False,
    ) -> None:
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.timed_out = timed_out
        self.output_limit_exceeded = output_limit_exceeded
        self.spawn_error = spawn_error
        self.capture_error = capture_error
        self.cleanup_error = cleanup_error


def _require_owned_environment() -> None:
    if (
        not sys.platform.startswith("linux")
        or not callable(getattr(os, "waitid", None))
        or not hasattr(os, "WNOWAIT")
        or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL
    ):
        raise BoundedProcessError(
            "command ownership requires Linux WNOWAIT and default SIGCHLD",
            capture_error=True,
        )


def _leader_exit_unreaped(process: subprocess.Popen[bytes]) -> int | None:
    # Do not call Popen.poll/wait/kill before the final group signal. Both poll
    # and wait consume the PID anchor; Popen.kill calls poll internally.
    if (
        process.returncode is not None
        or os.getpgid(process.pid) != process.pid
        or os.getsid(process.pid) != process.pid
    ):
        raise BoundedProcessError("command session anchor is unavailable", cleanup_error=True)
    status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if status is None:
        return None
    if status.si_pid != process.pid:
        raise BoundedProcessError("command wait identity differs", cleanup_error=True)
    if status.si_code == os.CLD_EXITED:
        return status.si_status
    if status.si_code in (os.CLD_KILLED, os.CLD_DUMPED):
        return -status.si_status
    raise BoundedProcessError("command wait status is invalid", cleanup_error=True)


def _read_proc_state(path: Path, deadline: float) -> tuple[bytes, int, int] | None:
    if time.monotonic() >= deadline:
        raise BoundedProcessError("command procfs scan budget exceeded", cleanup_error=True)
    try:
        with open(path, "rb") as stream:
            raw = stream.read(MAX_PROC_STAT_BYTES + 1)
    except (FileNotFoundError, ProcessLookupError):
        return None
    if time.monotonic() >= deadline:
        raise BoundedProcessError("command procfs observation exceeded deadline", cleanup_error=True)
    if len(raw) > MAX_PROC_STAT_BYTES:
        raise BoundedProcessError("command procfs stat exceeds bound", cleanup_error=True)
    try:
        fields = raw.rsplit(b") ", 1)[1].split()
        state, group, session = fields[0], int(fields[2]), int(fields[3])
        if state not in (b"R", b"S", b"D", b"Z", b"T", b"t", b"X", b"x", b"K", b"W", b"P", b"I") or group < 0 or session < 0:
            raise ValueError("invalid process state/group/session")
    except (IndexError, ValueError) as error:
        raise BoundedProcessError("command procfs stat is malformed", cleanup_error=True) from error
    return state, group, session


def _group_live_members(process: subprocess.Popen[bytes], deadline: float) -> list[int]:
    live: set[int] = set()
    anchor_seen = False
    anchor_task_seen = False
    task_count = 0
    with os.scandir("/proc") as entries:
        for count, entry in enumerate(entries, 1):
            if count > MAX_PROC_ENTRIES or time.monotonic() >= deadline:
                raise BoundedProcessError("command procfs scan budget exceeded", cleanup_error=True)
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            observed = _read_proc_state(Path(entry.path) / "stat", deadline)
            if observed is None:
                continue
            state, group, session = observed
            pid = int(entry.name)
            if pid == process.pid:
                if group != process.pid or session != process.pid:
                    raise BoundedProcessError("command anchor identity changed", cleanup_error=True)
                anchor_seen = True
            if group != process.pid:
                continue
            if session != process.pid:
                raise BoundedProcessError("command group session changed", cleanup_error=True)
            if state not in (b"Z", b"X", b"x"):
                live.add(pid)
            # A process leader may be Z while other threads in its TGID are
            # live. Every matching process needs a complete bounded task scan;
            # group membership is shared by its Linux thread group.
            try:
                tasks = os.scandir(Path(entry.path) / "task")
            except (FileNotFoundError, ProcessLookupError):
                if pid == process.pid:
                    raise BoundedProcessError("command anchor task directory is unavailable", cleanup_error=True)
                continue
            with tasks:
                for task in tasks:
                    task_count += 1
                    if task_count > MAX_PROC_TASK_ENTRIES or time.monotonic() >= deadline:
                        raise BoundedProcessError("command procfs task scan budget exceeded", cleanup_error=True)
                    if not task.name.isascii() or not task.name.isdecimal():
                        raise BoundedProcessError("command procfs task entry is malformed", cleanup_error=True)
                    observed_task = _read_proc_state(Path(task.path) / "stat", deadline)
                    if observed_task is None:
                        continue
                    task_state, task_group, task_session = observed_task
                    if (task_group, task_session) != (group, session):
                        raise BoundedProcessError("command task group/session changed", cleanup_error=True)
                    tid = int(task.name)
                    if pid == process.pid and tid == process.pid:
                        anchor_task_seen = True
                    if task_state not in (b"Z", b"X", b"x"):
                        live.add(tid)
    if not anchor_seen or not anchor_task_seen:
        raise BoundedProcessError("command anchor is not fully observable", cleanup_error=True)
    if time.monotonic() >= deadline:
        raise BoundedProcessError("command procfs scan budget exceeded", cleanup_error=True)
    return sorted(live)


def _retire_group(process: subprocess.Popen[bytes], *, expect_quiet: bool) -> None:
    deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
    observation_error = None
    unexpected_live = False
    # Capture-complete success requires that no worker was left behind. The
    # cleanup still kills it, but that command must not produce a PASS result.
    try:
        _leader_exit_unreaped(process)
        if expect_quiet:
            unexpected_live = bool(_group_live_members(process, deadline))
    except (BoundedProcessError, OSError) as error:
        observation_error = error
    # Even an incomplete procfs scan does not prevent a safe group signal when
    # the independently observed, unreaped direct-child anchor remains owned.
    _leader_exit_unreaped(process)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    quiet_once = False
    while time.monotonic() < deadline:
        exited = _leader_exit_unreaped(process) is not None
        quiet = exited and not _group_live_members(process, deadline)
        if quiet and quiet_once:
            if time.monotonic() >= deadline:
                raise BoundedProcessError("command group retirement deadline exceeded", cleanup_error=True)
            if observation_error is not None:
                raise BoundedProcessError("command group observation failed", cleanup_error=True) from observation_error
            if unexpected_live:
                raise BoundedProcessError("command left live group members", cleanup_error=True)
            return
        quiet_once = quiet
        time.sleep(min(0.01, max(0, deadline - time.monotonic())))
    raise BoundedProcessError("command group retirement was not observed", cleanup_error=True)


def run_bounded(
    argv: Sequence[str], *, timeout_seconds: float, maximum_output: int,
    cwd: Path | str | None = None, env: Mapping[str, str] | None = None,
) -> BoundedProcessResult:
    """Capture at most maximum_output total bytes, then retire the owned group.

    stdin is DEVNULL, no descriptors are inherited, and the command has its
    own session. Failure preserves only the bounded partial capture; no caller
    may turn a capture/cleanup failure into success from the leader exit code.
    """
    if (
        not isinstance(argv, Sequence) or not argv or isinstance(argv, (str, bytes))
        or any(not isinstance(item, str) or "\x00" in item for item in argv)
        or not argv[0]
        or type(timeout_seconds) not in (int, float)
        or timeout_seconds <= 0
        or type(maximum_output) is not int or maximum_output <= 0
    ):
        raise BoundedProcessError("invalid subprocess bounds or argv", capture_error=True)
    try:
        timeout_seconds = float(timeout_seconds)
    except OverflowError as error:
        raise BoundedProcessError("invalid subprocess timeout", capture_error=True) from error
    if not math.isfinite(timeout_seconds):
        raise BoundedProcessError("invalid subprocess timeout", capture_error=True)
    _require_owned_environment()
    selector = None
    streams = ()
    buffers = [bytearray(), bytearray()]
    failure = None
    capture_complete = False
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            list(argv), cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
            close_fds=True, start_new_session=True,
        )
    except (OSError, ValueError) as error:
        raise BoundedProcessError("subprocess spawn failed", spawn_error=True) from error
    try:
        streams = (process.stdout, process.stderr)
        if any(stream is None for stream in streams):
            raise BoundedProcessError("subprocess output pipes are unavailable", capture_error=True)
        descriptors = {stream.fileno(): buffers[index] for index, stream in enumerate(streams)}
        deadline = started + timeout_seconds
        selector = selectors.DefaultSelector()
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        total = 0
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BoundedProcessError("subprocess timed out", timed_out=True)
            events = selector.select(min(remaining, 0.1))
            if time.monotonic() >= deadline:
                raise BoundedProcessError("subprocess timed out", timed_out=True)
            for key, _ in events:
                if time.monotonic() >= deadline:
                    raise BoundedProcessError("subprocess timed out", timed_out=True)
                try:
                    chunk = os.read(key.fd, min(65_536, maximum_output - total + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                budget = maximum_output - total
                descriptors[key.fd].extend(chunk[:budget])
                total += min(len(chunk), budget)
                if len(chunk) > budget:
                    raise BoundedProcessError("subprocess output exceeded bound", output_limit_exceeded=True)
        while _leader_exit_unreaped(process) is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BoundedProcessError("subprocess timed out", timed_out=True)
            time.sleep(min(remaining, 0.01))
        if time.monotonic() >= deadline:
            raise BoundedProcessError("subprocess timed out", timed_out=True)
        capture_complete = True
    except BoundedProcessError as error:
        failure = error
    except (OSError, ValueError) as error:
        failure = BoundedProcessError("subprocess capture failed", capture_error=True)
        failure.__cause__ = error
    finally:
        cleanup_failure = None
        cleanup_interrupt = None

        def finish_owned(operation) -> None:
            nonlocal cleanup_failure, cleanup_interrupt
            # These are idempotent operations on objects we still own, never
            # signals to a numeric PID/FD after its ownership has been released.
            # Retry at most once, retain failure, and deliver the first interrupt
            # only after every other local resource has received cleanup
            # attempts. Persistent interruption/failure remains unknown;
            # neither the finite retries nor this helper promise closure then.
            for _ in range(2):
                try:
                    operation()
                    return
                except BaseException as error:
                    cleanup_failure = error
                    if (
                        not isinstance(error, (subprocess.TimeoutExpired, OSError, ValueError))
                        and cleanup_interrupt is None
                    ):
                        cleanup_interrupt = error

        try:
            _retire_group(process, expect_quiet=capture_complete)
        except (BoundedProcessError, OSError, ValueError) as error:
            cleanup_failure = error
        except BaseException as error:
            cleanup_failure = cleanup_interrupt = error
            # An interruption during cleanup still leaves a retained anchor.
            # Attempt one bounded retirement before consuming it, then deliver
            # the interruption after attempting every local capture cleanup.
            try:
                _retire_group(process, expect_quiet=False)
            except BaseException as retry_error:
                cleanup_failure = retry_error
        # Consuming waits run strictly after every group signal. Their initial
        # call and one interruption retry share a 200ms reap window.
        reap_deadline = time.monotonic() + 0.2
        finish_owned(lambda: process.wait(timeout=max(0.001, reap_deadline - time.monotonic())))
        if selector is not None:
            finish_owned(selector.close)
        for stream in streams:
            if stream is not None:
                finish_owned(stream.close)
        if cleanup_failure is not None:
            if failure is None:
                failure = BoundedProcessError("subprocess cleanup failed", cleanup_error=True)
                failure.__cause__ = cleanup_failure
            else:
                failure.cleanup_error = True
        if failure is not None:
            failure.stdout, failure.stderr = map(bytes, buffers)
            failure.returncode = process.returncode
        if cleanup_interrupt is not None:
            raise cleanup_interrupt
    if failure is not None:
        raise failure
    return BoundedProcessResult(process.returncode, bytes(buffers[0]), bytes(buffers[1]))
