#!/usr/bin/env python3
"""Descriptor-rooted facade for the real Host/Core product baseline.

The separately reviewed minimal launcher reads and authenticates this facade
before compiling these bytes.  This facade then opens every nested Python
source and selected executable by walking each path component from ``/`` with
``openat``-style ``dir_fd`` lookups and ``O_NOFOLLOW``.  Identities are derived
from the opened descriptor and the same admitted bytes are what execute.
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


_REQUIRED_BOOTSTRAP = {
    "_TRILLIONNIUM_LAUNCHER_SOURCE",
    "_TRILLIONNIUM_LAUNCHER_IDENTITY",
    "_TRILLIONNIUM_LAUNCHER_PATH",
    "_TRILLIONNIUM_FACADE_SOURCE",
    "_TRILLIONNIUM_FACADE_IDENTITY",
    "_TRILLIONNIUM_FACADE_PATH",
}
if not _REQUIRED_BOOTSTRAP.issubset(globals()):
    raise RuntimeError("performance facade requires the authenticated minimal launcher")

_LAUNCHER_SOURCE = globals()["_TRILLIONNIUM_LAUNCHER_SOURCE"]
_LAUNCHER_IDENTITY = dict(globals()["_TRILLIONNIUM_LAUNCHER_IDENTITY"])
_LAUNCHER_PATH = Path(globals()["_TRILLIONNIUM_LAUNCHER_PATH"])
_FACADE_SOURCE = globals()["_TRILLIONNIUM_FACADE_SOURCE"]
_FACADE_IDENTITY = dict(globals()["_TRILLIONNIUM_FACADE_IDENTITY"])
_FACADE_PATH = Path(globals()["_TRILLIONNIUM_FACADE_PATH"])
if not isinstance(_LAUNCHER_SOURCE, bytes) or not isinstance(_FACADE_SOURCE, bytes):
    raise RuntimeError("performance bootstrap sources must be exact bytes")
if hashlib.sha256(_LAUNCHER_SOURCE).hexdigest() != _LAUNCHER_IDENTITY.get("sha256"):
    raise RuntimeError("performance launcher bootstrap digest differs")
if hashlib.sha256(_FACADE_SOURCE).hexdigest() != _FACADE_IDENTITY.get("sha256"):
    raise RuntimeError("performance facade bootstrap digest differs")

HERE = _FACADE_PATH.parent
REPOSITORY_ROOT = HERE.parents[1]
CORE_PATH = HERE / "_run_product_baseline_core.py"
SUPERVISOR_PATH = HERE.parent / "owner-open/owner_open_rootlinux_supervisor.py"
BROKER_PATH = HERE.parent / "owner-open/owner_open_connection_broker.py"
MAX_PINNED_SOURCE_BYTES = 8 * 1024 * 1024

BeforeComponentHook = Callable[[Path, str, bool], None]
AfterFinalHook = Callable[[Path, int], None]


def _absolute_lexical(path: Path) -> Path:
    value = Path(os.path.abspath(os.fspath(path)))
    if value == Path("/") or "\x00" in os.fspath(value):
        raise RuntimeError(f"invalid path for descriptor-rooted admission: {path}")
    return value


def _open_nofollow(
    path: Path,
    *,
    before_component: BeforeComponentHook | None = None,
    after_final: AfterFinalHook | None = None,
) -> tuple[int, Path]:
    """Open an absolute lexical path without following any component symlink."""
    absolute = _absolute_lexical(path)
    components = absolute.parts[1:]
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    current = os.open("/", directory_flags)
    try:
        for component in components[:-1]:
            if component in {"", ".", ".."}:
                raise RuntimeError(f"non-normal path component in {absolute}")
            if before_component is not None:
                before_component(absolute, component, False)
            child = os.open(component, directory_flags, dir_fd=current)
            os.close(current)
            current = child
        leaf = components[-1]
        if leaf in {"", ".", ".."}:
            raise RuntimeError(f"non-normal final component in {absolute}")
        if before_component is not None:
            before_component(absolute, leaf, True)
        descriptor = os.open(leaf, file_flags, dir_fd=current)
        if after_final is not None:
            after_final(absolute, descriptor)
        return descriptor, absolute
    finally:
        os.close(current)


def _read_descriptor(
    descriptor: int,
    logical_path: str,
    *,
    maximum: int = MAX_PINNED_SOURCE_BYTES,
    executable: bool = False,
) -> tuple[bytes, os.stat_result]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
        raise RuntimeError(f"invalid admitted regular file: {logical_path}")
    if executable and not before.st_mode & 0o111:
        raise RuntimeError(f"admitted executable has no execute bit: {logical_path}")
    chunks: list[bytes] = []
    offset = 0
    while offset < before.st_size:
        block = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
        if not block:
            raise RuntimeError(f"short descriptor read: {logical_path}")
        chunks.append(block)
        offset += len(block)
    after = os.fstat(descriptor)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise RuntimeError(f"descriptor object changed while read: {logical_path}")
    return b"".join(chunks), before


def _opened_identity(path: Path, logical_path: str, *, maximum: int, executable: bool,
                     before_component: BeforeComponentHook | None = None,
                     after_final: AfterFinalHook | None = None) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    descriptor, absolute = _open_nofollow(
        path, before_component=before_component, after_final=after_final
    )
    try:
        source, value = _read_descriptor(
            descriptor, logical_path, maximum=maximum, executable=executable
        )
    finally:
        os.close(descriptor)
    report = {
        "path": logical_path,
        "size": len(source),
        "sha256": hashlib.sha256(source).hexdigest(),
    }
    internal = {
        "absolute_path": str(absolute),
        "device": value.st_dev,
        "inode": value.st_ino,
        "mode": stat.S_IFMT(value.st_mode),
        "size": value.st_size,
        "mtime_ns": value.st_mtime_ns,
        "sha256": report["sha256"],
    }
    return source, report, internal


def _same_opened_object(left: dict[str, Any], right: dict[str, Any]) -> bool:
    keys = ("absolute_path", "device", "inode", "mode", "size", "mtime_ns", "sha256")
    return all(left.get(key) == right.get(key) for key in keys)


def _reopen_identity(path: Path, logical_path: str, *, maximum: int, executable: bool) -> dict[str, Any]:
    _, _, internal = _opened_identity(
        path, logical_path, maximum=maximum, executable=executable
    )
    return internal


def _snapshot_source(
    path: Path,
    logical_path: str,
    *,
    before_component: BeforeComponentHook | None = None,
    after_final: AfterFinalHook | None = None,
) -> tuple[bytes, dict[str, Any]]:
    absolute = _absolute_lexical(path)
    root = _absolute_lexical(REPOSITORY_ROOT)
    if os.path.commonpath((str(absolute), str(root))) != str(root):
        raise RuntimeError(f"pinned Python source escaped repository: {logical_path}")
    source, report, internal = _opened_identity(
        absolute,
        logical_path,
        maximum=MAX_PINNED_SOURCE_BYTES,
        executable=False,
        before_component=before_component,
        after_final=after_final,
    )
    current = _reopen_identity(
        absolute, logical_path, maximum=MAX_PINNED_SOURCE_BYTES, executable=False
    )
    if not _same_opened_object(internal, current):
        raise RuntimeError(f"pinned Python source selection changed: {logical_path}")
    return source, report


def _load_snapshot(
    name: str,
    path: Path,
    logical_path: str,
    *,
    before_exec: Callable[[Path], None] | None = None,
    before_component: BeforeComponentHook | None = None,
    after_final: AfterFinalHook | None = None,
) -> tuple[Any, bytes, dict[str, Any]]:
    source, identity = _snapshot_source(
        path,
        logical_path,
        before_component=before_component,
        after_final=after_final,
    )
    code = compile(source, logical_path, "exec", dont_inherit=True)
    if before_exec is not None:
        before_exec(path)
    module = ModuleType(name)
    module.__file__ = str(_absolute_lexical(path))
    module.__package__ = ""
    module.__dict__["__pinned_source_identity__"] = dict(identity)
    module.__dict__["_TRILLIONNIUM_BOOTSTRAP_SOURCE"] = source
    module.__dict__["_TRILLIONNIUM_BOOTSTRAP_IDENTITY"] = dict(identity)
    module.__dict__["_TRILLIONNIUM_BOOTSTRAP_PATH"] = logical_path
    sys.modules[name] = module
    try:
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module, source, identity


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
        _LAUNCHER_IDENTITY,
    )
}
PINNED_IMPLEMENTATION_SOURCES = {
    "tools/owner-open/owner_open_connection_broker.py": _BROKER_SOURCE,
    "tools/owner-open/owner_open_rootlinux_supervisor.py": _SUPERVISOR_SOURCE,
    "tools/perf/_run_product_baseline_core.py": _CORE_SOURCE,
    "tools/perf/_run_product_baseline_facade.py": _FACADE_SOURCE,
    "tools/perf/run_product_baseline.py": _LAUNCHER_SOURCE,
}
if set(PINNED_IMPLEMENTATION_FILES) != set(CORE.IMPLEMENTATION_PATHS):
    raise RuntimeError("performance implementation snapshot is incomplete")
CORE.PINNED_IMPLEMENTATION_FILES = dict(PINNED_IMPLEMENTATION_FILES)
CORE.PINNED_IMPLEMENTATION_SOURCES = dict(PINNED_IMPLEMENTATION_SOURCES)
CORE.OPEN_ADMITTED_FILE = _opened_identity
CORE.REOPEN_ADMITTED_IDENTITY = _reopen_identity
CORE.SAME_ADMITTED_OBJECT = _same_opened_object
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
