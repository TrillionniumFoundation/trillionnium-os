#!/usr/bin/env python3
"""Stable CLI facade for the real Host/Core product baseline.

Every imported behavior-bearing Python module is read once through a pinned
regular-file descriptor, hashed, compiled and executed from those exact bytes.
The facade also retains every ``start_new_session`` leader as a waitid/WNOWAIT
anchor until the complete original process group has passed bounded TERM/KILL
cleanup.  External product executables are descriptor-pinned by the private
core before any version probe or workload execution.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import signal
import stat
import subprocess as _stdlib_subprocess
import sys
import time
from types import ModuleType, SimpleNamespace
from typing import Any, Callable


HERE = Path(__file__).resolve().parent
REPOSITORY_ROOT = HERE.parents[1]
CORE_PATH = HERE / "_run_product_baseline_core.py"
SUPERVISOR_PATH = HERE.parent / "owner-open/owner_open_rootlinux_supervisor.py"
BROKER_PATH = HERE.parent / "owner-open/owner_open_connection_broker.py"
MAX_PINNED_SOURCE_BYTES = 8 * 1024 * 1024


def _snapshot_source(path: Path, logical_path: str) -> tuple[bytes, dict[str, Any]]:
    """Read one immutable source snapshot and bind the bytes to its descriptor."""
    if path.is_symlink():
        raise RuntimeError(f"pinned Python source is a symlink: {logical_path}")
    resolved_root = REPOSITORY_ROOT.resolve(strict=True)
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(resolved_root):
        raise RuntimeError(f"pinned Python source escaped repository: {logical_path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(resolved, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_PINNED_SOURCE_BYTES:
            raise RuntimeError(f"invalid pinned Python source: {logical_path}")
        chunks: list[bytes] = []
        offset = 0
        while offset < before.st_size:
            block = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
            if not block:
                raise RuntimeError(f"short read from pinned Python source: {logical_path}")
            chunks.append(block)
            offset += len(block)
        source = b"".join(chunks)
        after = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise RuntimeError(f"pinned Python source changed while read: {logical_path}")
        path_state = os.stat(resolved, follow_symlinks=False)
        if (path_state.st_dev, path_state.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError(f"pinned Python source path moved while read: {logical_path}")
        return source, {
            "path": logical_path,
            "size": len(source),
            "sha256": hashlib.sha256(source).hexdigest(),
        }
    finally:
        os.close(descriptor)


def _load_snapshot(
    name: str,
    path: Path,
    logical_path: str,
    *,
    before_exec: Callable[[Path], None] | None = None,
) -> tuple[Any, bytes, dict[str, Any]]:
    """Compile and execute exactly the bytes read by :func:`_snapshot_source`."""
    source, identity = _snapshot_source(path, logical_path)
    code = compile(source, logical_path, "exec", dont_inherit=True)
    if before_exec is not None:  # deterministic hostile test hook
        before_exec(path)
    module = ModuleType(name)
    module.__file__ = str(path.resolve(strict=True))
    module.__package__ = ""
    module.__dict__["__pinned_source_identity__"] = dict(identity)
    sys.modules[name] = module
    try:
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module, source, identity


_FACADE_SOURCE, _FACADE_IDENTITY = _snapshot_source(
    Path(__file__), "tools/perf/run_product_baseline.py"
)
CORE, _CORE_SOURCE, _CORE_IDENTITY = _load_snapshot(
    "_run_product_baseline_core",
    CORE_PATH,
    "tools/perf/_run_product_baseline_core.py",
)
SUPERVISOR, _SUPERVISOR_SOURCE, _SUPERVISOR_IDENTITY = _load_snapshot(
    "_product_baseline_process_group_supervisor",
    SUPERVISOR_PATH,
    "tools/owner-open/owner_open_rootlinux_supervisor.py",
)
_BROKER_SOURCE, _BROKER_IDENTITY = _snapshot_source(
    BROKER_PATH, "tools/owner-open/owner_open_connection_broker.py"
)
PINNED_IMPLEMENTATION_FILES = {
    item["path"]: dict(item)
    for item in (
        _BROKER_IDENTITY,
        _SUPERVISOR_IDENTITY,
        _CORE_IDENTITY,
        _FACADE_IDENTITY,
    )
}
PINNED_IMPLEMENTATION_SOURCES = {
    "tools/owner-open/owner_open_connection_broker.py": _BROKER_SOURCE,
    "tools/owner-open/owner_open_rootlinux_supervisor.py": _SUPERVISOR_SOURCE,
    "tools/perf/_run_product_baseline_core.py": _CORE_SOURCE,
    "tools/perf/run_product_baseline.py": _FACADE_SOURCE,
}
if set(PINNED_IMPLEMENTATION_FILES) != set(CORE.IMPLEMENTATION_PATHS):
    raise RuntimeError("performance implementation snapshot is incomplete")
CORE.PINNED_IMPLEMENTATION_FILES = dict(PINNED_IMPLEMENTATION_FILES)
CORE.PINNED_IMPLEMENTATION_SOURCES = dict(PINNED_IMPLEMENTATION_SOURCES)
CORE.EXECUTION_PASS_FDS = ()
CORE.EXECUTION_PATHS = {}


class OwnedSessionPopen(_stdlib_subprocess.Popen[bytes]):
    """Popen whose poll/wait observes but does not reap its session anchor."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if kwargs.get("start_new_session") is not True:
            raise CORE.BenchmarkError(
                "product benchmark subprocesses require start_new_session=True"
            )
        inherited = tuple(kwargs.pop("pass_fds", ()))
        pinned = tuple(getattr(CORE, "EXECUTION_PASS_FDS", ()))
        kwargs["pass_fds"] = tuple(sorted(set(inherited) | set(pinned)))
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

for _name in dir(CORE):
    if not _name.startswith("__") and _name not in {"stop", "subprocess"}:
        globals()[_name] = getattr(CORE, _name)
subprocess = CORE.subprocess


if __name__ == "__main__":
    raise SystemExit(CORE.main())
