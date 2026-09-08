#!/usr/bin/env python3
"""Stable CLI facade for the real Host/Core product baseline.

The workload implementation remains byte-identical in the private core. This
facade retains every ``start_new_session`` leader as a waitid/WNOWAIT anchor
until the complete original process group has passed bounded TERM/KILL cleanup.
It reuses the repository's reviewed Root Linux supervisor primitives rather than
inventing a second process-identity boundary.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import signal
import subprocess as _stdlib_subprocess
import sys
import time
from types import SimpleNamespace
from typing import Any


HERE = Path(__file__).resolve().parent
CORE_PATH = HERE / "_run_product_baseline_core.py"
SUPERVISOR_PATH = HERE.parent / "owner-open/owner_open_rootlinux_supervisor.py"


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - import machinery
        raise RuntimeError(f"cannot load {name}: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


CORE = _load("_run_product_baseline_core", CORE_PATH)
SUPERVISOR = _load("_product_baseline_process_group_supervisor", SUPERVISOR_PATH)


class OwnedSessionPopen(_stdlib_subprocess.Popen[bytes]):
    """Popen whose poll/wait observes but does not reap its session anchor."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if kwargs.get("start_new_session") is not True:
            raise CORE.BenchmarkError(
                "product benchmark subprocesses require start_new_session=True"
            )
        super().__init__(*args, **kwargs)
        self._observed_returncode: int | None = None

    def _observe(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        try:
            status = os.waitid(
                os.P_PID,
                self.pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except (OSError, AttributeError) as error:
            raise CORE.BenchmarkError(
                f"cannot retain product process-group anchor: {error}"
            ) from error
        if status is None:
            return None
        if status.si_code == os.CLD_EXITED:
            code = status.si_status
        elif status.si_code in (os.CLD_KILLED, os.CLD_DUMPED):
            code = -status.si_status
        else:
            raise CORE.BenchmarkError("unexpected product process wait status")
        if self._observed_returncode not in (None, code):
            raise CORE.BenchmarkError("product process exit observation changed")
        self._observed_returncode = code
        return code

    def poll(self) -> int | None:
        return self._observe()

    def wait(self, timeout: float | None = None) -> int:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            code = self._observe()
            if code is not None:
                return code
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _stdlib_subprocess.TimeoutExpired(self.args, timeout)
                time.sleep(min(0.01, remaining))
            else:
                time.sleep(0.01)

    def reap_anchor(self) -> int:
        if self.returncode is not None:
            return self.returncode
        try:
            pid, status = os.waitpid(self.pid, 0)
        except ChildProcessError as error:
            raise CORE.BenchmarkError(
                "product process-group anchor was reaped by another owner"
            ) from error
        if pid != self.pid:
            raise CORE.BenchmarkError("reaped the wrong product process")
        code = os.waitstatus_to_exitcode(status)
        if self._observed_returncode not in (None, code):
            raise CORE.BenchmarkError("reaped product status differs from observation")
        self._observed_returncode = code
        self.returncode = code
        return code


class _SubprocessProxy:
    Popen = OwnedSessionPopen

    def __getattr__(self, name: str) -> Any:
        return getattr(_stdlib_subprocess, name)


CORE.subprocess = _SubprocessProxy()


def _managed(process: OwnedSessionPopen) -> SimpleNamespace:
    return SimpleNamespace(process=process, group_cleaned=False)


def _group_settled(managed: SimpleNamespace) -> bool:
    exited = SUPERVISOR.Supervisor.observe_exit(managed) is not None
    live = SUPERVISOR.Supervisor.live_group_members(managed.process.pid)
    return exited and not live


def _wait_group(managed: SimpleNamespace, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    quiet_once = False
    while time.monotonic() < deadline:
        quiet = _group_settled(managed)
        if quiet and quiet_once:
            return True
        quiet_once = quiet
        time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
    return False


def stop(process: OwnedSessionPopen) -> None:
    """Terminate the complete original session, then reap its retained anchor."""
    cleanup_error: BaseException | None = None
    try:
        if not isinstance(process, OwnedSessionPopen):
            raise CORE.BenchmarkError(
                "product cleanup requires its retained-session Popen"
            )
        managed = _managed(process)
        SUPERVISOR.Supervisor.signal_group(managed, signal.SIGTERM)
        _wait_group(managed, 1.0)
        # Escalate before reaping even when TERM ended the leader. A descendant
        # may ignore TERM while holding benchmark stdout/stderr or store locks.
        SUPERVISOR.Supervisor.signal_group(managed, signal.SIGKILL)
        if not _wait_group(managed, 3.0):
            raise CORE.BenchmarkError(
                f"original product process group {process.pid} survived cleanup"
            )
        process.reap_anchor()
        managed.group_cleaned = True
    except BaseException as error:
        cleanup_error = error
    finally:
        for pipe in (process.stdin, process.stdout, process.stderr):
            if pipe is not None:
                try:
                    pipe.close()
                except OSError:
                    pass
    if cleanup_error is not None:
        raise cleanup_error


CORE.stop = stop

# Preserve the established import surface used by source-contract tests.
for _name in dir(CORE):
    if not _name.startswith("__") and _name not in {"stop", "subprocess"}:
        globals()[_name] = getattr(CORE, _name)
subprocess = CORE.subprocess


if __name__ == "__main__":
    raise SystemExit(CORE.main())
