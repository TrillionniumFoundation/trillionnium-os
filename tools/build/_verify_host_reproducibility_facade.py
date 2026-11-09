#!/usr/bin/env python3
"""Descriptor-rooted facade for bounded Host/Core reproducibility builds.

The separately reviewed launcher authenticates this facade before execution.
Every nested Python source is then opened component-by-component without
following symlinks.  Toolchain executables are admitted from opened descriptor
bytes and executed from write-sealed memfds.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import selectors
import stat
import subprocess
import sys
import time
from types import ModuleType
from typing import Any, Callable


_REQUIRED_BOOTSTRAP = {
    "_TRILLIONNIUM_LAUNCHER_SOURCE",
    "_TRILLIONNIUM_LAUNCHER_IDENTITY",
    "_TRILLIONNIUM_LAUNCHER_PATH",
    "_TRILLIONNIUM_FACADE_SOURCE",
    "_TRILLIONNIUM_FACADE_IDENTITY",
    "_TRILLIONNIUM_FACADE_PATH",
    "_TRILLIONNIUM_BOOTSTRAP_ATTESTATION",
    "_TRILLIONNIUM_BOOTSTRAP_FILE_SOURCE",
    "_TRILLIONNIUM_BOOTSTRAP_FILE_IDENTITY",
    "_TRILLIONNIUM_BOOTSTRAP_FILE_PATH",
}
if not _REQUIRED_BOOTSTRAP.issubset(globals()):
    raise RuntimeError("reproducibility facade requires the authenticated minimal launcher")

_LAUNCHER_SOURCE = globals()["_TRILLIONNIUM_LAUNCHER_SOURCE"]
_LAUNCHER_IDENTITY = dict(globals()["_TRILLIONNIUM_LAUNCHER_IDENTITY"])
_LAUNCHER_PATH = Path(globals()["_TRILLIONNIUM_LAUNCHER_PATH"])
_FACADE_SOURCE = globals()["_TRILLIONNIUM_FACADE_SOURCE"]
_FACADE_IDENTITY = dict(globals()["_TRILLIONNIUM_FACADE_IDENTITY"])
_FACADE_PATH = Path(globals()["_TRILLIONNIUM_FACADE_PATH"])
_BOOTSTRAP_ATTESTATION = dict(globals()["_TRILLIONNIUM_BOOTSTRAP_ATTESTATION"])
_BOOTSTRAP_SOURCE = globals()["_TRILLIONNIUM_BOOTSTRAP_FILE_SOURCE"]
_BOOTSTRAP_IDENTITY = dict(globals()["_TRILLIONNIUM_BOOTSTRAP_FILE_IDENTITY"])
_BOOTSTRAP_PATH = Path(globals()["_TRILLIONNIUM_BOOTSTRAP_FILE_PATH"])
if not isinstance(_LAUNCHER_SOURCE, bytes) or not isinstance(_FACADE_SOURCE, bytes) or not isinstance(_BOOTSTRAP_SOURCE, bytes):
    raise RuntimeError("reproducibility bootstrap sources must be exact bytes")
if hashlib.sha256(_LAUNCHER_SOURCE).hexdigest() != _LAUNCHER_IDENTITY.get("sha256"):
    raise RuntimeError("reproducibility launcher bootstrap digest differs")
if hashlib.sha256(_FACADE_SOURCE).hexdigest() != _FACADE_IDENTITY.get("sha256"):
    raise RuntimeError("reproducibility facade bootstrap digest differs")
if hashlib.sha256(_BOOTSTRAP_SOURCE).hexdigest() != _BOOTSTRAP_IDENTITY.get("sha256"):
    raise RuntimeError("bootstrap source digest differs")
if _BOOTSTRAP_IDENTITY.get("path") != "tools/owner-open/authenticated_python_bootstrap.py":
    raise RuntimeError("bootstrap logical path differs")
if _BOOTSTRAP_ATTESTATION.get("bootstrap") != _BOOTSTRAP_IDENTITY:
    raise RuntimeError("bootstrap attestation identity differs")
if _BOOTSTRAP_ATTESTATION.get("launcher") != _LAUNCHER_IDENTITY:
    raise RuntimeError("bootstrap attestation launcher differs")

HERE = _FACADE_PATH.parent
REPOSITORY_ROOT = HERE.parents[1]
CORE_PATH = HERE / "_verify_host_reproducibility_core.py"
CLEANUP_PATH = HERE.parent / "perf/run_product_baseline.py"
MAX_PINNED_SOURCE_BYTES = 8 * 1024 * 1024

BeforeComponentHook = Callable[[Path, str, bool], None]
AfterFinalHook = Callable[[Path, int], None]


def _absolute_lexical(path: Path) -> Path:
    value = Path(os.path.abspath(os.fspath(path)))
    if value == Path("/") or "\x00" in os.fspath(value):
        raise RuntimeError(f"invalid path for descriptor-rooted admission: {path}")
    return value


def _open_nofollow(path: Path, *, before_component: BeforeComponentHook | None = None,
                   after_final: AfterFinalHook | None = None) -> tuple[int, Path]:
    absolute = _absolute_lexical(path)
    components = absolute.parts[1:]
    directory_flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                       | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
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
        if before_component is not None:
            before_component(absolute, leaf, True)
        descriptor = os.open(leaf, file_flags, dir_fd=current)
        if after_final is not None:
            after_final(absolute, descriptor)
        return descriptor, absolute
    finally:
        os.close(current)


def _read_descriptor(descriptor: int, logical_path: str, *, maximum: int,
                     executable: bool = False) -> tuple[bytes, os.stat_result]:
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
    descriptor, absolute = _open_nofollow(path, before_component=before_component,
                                          after_final=after_final)
    try:
        source, value = _read_descriptor(descriptor, logical_path, maximum=maximum,
                                         executable=executable)
    finally:
        os.close(descriptor)
    report = {"path": logical_path, "size": len(source),
              "sha256": hashlib.sha256(source).hexdigest()}
    internal = {"absolute_path": str(absolute), "device": value.st_dev,
                "inode": value.st_ino, "mode": stat.S_IFMT(value.st_mode),
                "size": value.st_size, "mtime_ns": value.st_mtime_ns,
                "sha256": report["sha256"]}
    return source, report, internal


def _same_opened_object(left: dict[str, Any], right: dict[str, Any]) -> bool:
    keys = ("absolute_path", "device", "inode", "mode", "size", "mtime_ns", "sha256")
    return all(left.get(key) == right.get(key) for key in keys)


def _reopen_identity(path: Path, logical_path: str, *, maximum: int,
                     executable: bool) -> dict[str, Any]:
    _, _, internal = _opened_identity(path, logical_path, maximum=maximum,
                                      executable=executable)
    return internal


def _snapshot_source(path: Path, logical_path: str, *,
                     before_component: BeforeComponentHook | None = None,
                     after_final: AfterFinalHook | None = None) -> tuple[bytes, dict[str, Any]]:
    absolute = _absolute_lexical(path)
    root = _absolute_lexical(REPOSITORY_ROOT)
    if os.path.commonpath((str(absolute), str(root))) != str(root):
        raise RuntimeError(f"pinned Python source escaped repository: {logical_path}")
    source, report, internal = _opened_identity(
        absolute, logical_path, maximum=MAX_PINNED_SOURCE_BYTES, executable=False,
        before_component=before_component, after_final=after_final)
    current = _reopen_identity(absolute, logical_path,
                               maximum=MAX_PINNED_SOURCE_BYTES, executable=False)
    if not _same_opened_object(internal, current):
        raise RuntimeError(f"pinned Python source selection changed: {logical_path}")
    return source, report


def _load_snapshot(name: str, path: Path, logical_path: str, *,
                   before_exec: Callable[[Path], None] | None = None,
                   before_component: BeforeComponentHook | None = None,
                   after_final: AfterFinalHook | None = None) -> tuple[Any, bytes, dict[str, Any]]:
    source, identity = _snapshot_source(path, logical_path,
                                        before_component=before_component,
                                        after_final=after_final)
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
    nested_attestation = dict(_BOOTSTRAP_ATTESTATION)
    nested_attestation["launcher"] = dict(identity)
    module.__dict__["_TRILLIONNIUM_BOOTSTRAP_ATTESTATION"] = nested_attestation
    module.__dict__["_TRILLIONNIUM_BOOTSTRAP_FILE_SOURCE"] = _BOOTSTRAP_SOURCE
    module.__dict__["_TRILLIONNIUM_BOOTSTRAP_FILE_IDENTITY"] = dict(_BOOTSTRAP_IDENTITY)
    module.__dict__["_TRILLIONNIUM_BOOTSTRAP_FILE_PATH"] = str(_BOOTSTRAP_PATH)
    sys.modules[name] = module
    try:
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module, source, identity


CORE, _CORE_SOURCE, _CORE_IDENTITY = _load_snapshot(
    "_verify_host_reproducibility_core", CORE_PATH,
    "tools/build/_verify_host_reproducibility_core.py")
CLEANUP, _CLEANUP_SOURCE, _CLEANUP_IDENTITY = _load_snapshot(
    "_host_reproducibility_process_cleanup", CLEANUP_PATH,
    "tools/perf/run_product_baseline.py")
cleanup_files = getattr(CLEANUP, "PINNED_IMPLEMENTATION_FILES", None)
if not isinstance(cleanup_files, dict):
    raise RuntimeError("cleanup implementation is not snapshot-bound")
if cleanup_files.get("tools/perf/run_product_baseline.py") != _CLEANUP_IDENTITY:
    raise RuntimeError("cleanup launcher executed bytes differ from its nested identity")
_BUILD_ONLY_PATHS = {
    "tools/build/_verify_host_reproducibility_core.py",
    "tools/build/_verify_host_reproducibility_facade.py",
    "tools/build/verify_host_reproducibility.py",
}
if set(cleanup_files) != set(CORE.IMPLEMENTATION_PATHS) - _BUILD_ONLY_PATHS:
    raise RuntimeError("cleanup implementation transitive snapshot is incomplete")
if cleanup_files.get("tools/owner-open/authenticated_python_bootstrap.py") != _BOOTSTRAP_IDENTITY:
    raise RuntimeError("cleanup bootstrap identity differs from the outer bootstrap")
PINNED_IMPLEMENTATION_FILES = {
    **cleanup_files,
    "tools/build/_verify_host_reproducibility_core.py": _CORE_IDENTITY,
    "tools/build/_verify_host_reproducibility_facade.py": _FACADE_IDENTITY,
    "tools/build/verify_host_reproducibility.py": _LAUNCHER_IDENTITY,
}
if set(PINNED_IMPLEMENTATION_FILES) != set(CORE.IMPLEMENTATION_PATHS):
    raise RuntimeError("reproducibility implementation snapshot is incomplete")
CORE.PINNED_BOOTSTRAP_ATTESTATION = dict(_BOOTSTRAP_ATTESTATION)
CORE.PINNED_IMPLEMENTATION_FILES = {
    path: dict(identity) for path, identity in PINNED_IMPLEMENTATION_FILES.items()
}
CORE.OPEN_ADMITTED_FILE = _opened_identity
CORE.REOPEN_ADMITTED_IDENTITY = _reopen_identity
CORE.SAME_ADMITTED_OBJECT = _same_opened_object
CORE.EXECUTION_PASS_FDS = ()
CORE.MAX_QUERY_OUTPUT_BYTES = 1024 * 1024
CORE.QUERY_TIMEOUT_SECONDS = 20


def query(
    command: list[str],
    cwd: Path,
    *,
    pass_fds: tuple[int, ...] = (),
    runtime: Any = None,
    executable: Path | None = None,
) -> str:
    """Read bounded identity output and retain the complete session for cleanup."""
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    if runtime is not None:
        environment.update(runtime.environment())
    started = time.monotonic()
    deadline = started + CORE.QUERY_TIMEOUT_SECONDS
    process = CLEANUP.OwnedSessionPopen(
        command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        pass_fds=pass_fds,
        executable=executable,
    )
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    count = 0
    primary_error: BaseException | None = None
    try:
        with selectors.DefaultSelector() as selector:
            for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
                CORE.require(pipe is not None, "identity query pipe is unavailable")
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                CORE.require(remaining > 0, "identity query exceeded timeout")
                for key, _ in selector.select(min(0.1, remaining)):
                    # Read at most one byte beyond the shared allowance, so
                    # excess output is rejected before unbounded allocation.
                    allowance = CORE.MAX_QUERY_OUTPUT_BYTES - count
                    block = os.read(key.fileobj.fileno(), min(65536, allowance + 1))
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    count += len(block)
                    CORE.require(count <= CORE.MAX_QUERY_OUTPUT_BYTES,
                                 "identity query exceeded combined output bound")
                    captured[key.data].extend(block)
        remaining = deadline - time.monotonic()
        CORE.require(remaining > 0, "identity query exceeded timeout")
        try:
            code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise CORE.VerificationError("identity query exceeded timeout") from None
        CORE.require(code == 0, f"identity query exited with status {code}")
        try:
            stdout = captured["stdout"].decode("utf-8", errors="strict")
            captured["stderr"].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise CORE.VerificationError("identity query output is not strict UTF-8") from None
        return stdout.strip()
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            CLEANUP.stop(process)
        except BaseException as cleanup_error:
            if primary_error is None:
                raise CORE.VerificationError("identity query process-group cleanup failed") from cleanup_error
            raise CORE.VerificationError(
                f"{primary_error}; identity query process-group cleanup failed"
            ) from primary_error

def run_build(
    command: list[str],
    env: dict[str, str],
    repo: Path,
    log: Path,
    timeout: int,
) -> dict[str, Any]:
    started = time.monotonic()
    process = CLEANUP.OwnedSessionPopen(
        command,
        cwd=repo,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        pass_fds=tuple(getattr(CORE, "EXECUTION_PASS_FDS", ())),
    )
    count = 0
    digest = hashlib.sha256()
    primary_error: BaseException | None = None
    try:
        assert process.stdout
        with log.open("xb") as output, selectors.DefaultSelector() as selector:
            os.chmod(log, 0o600)
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                CORE.require(
                    time.monotonic() - started < timeout,
                    "Cargo build exceeded timeout",
                )
                for key, _ in selector.select(0.1):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    count += len(block)
                    CORE.require(
                        count <= CORE.MAX_LOG_BYTES,
                        "Cargo build log exceeded byte bound",
                    )
                    output.write(block)
                    digest.update(block)
            output.flush()
            os.fsync(output.fileno())
        remaining = timeout - (time.monotonic() - started)
        CORE.require(remaining > 0, "Cargo did not finish before deadline")
        code = process.wait(timeout=remaining)
        return {
            "exit_code": code,
            "elapsed_seconds": time.monotonic() - started,
            "log": {
                "path": str(log),
                "bytes": count,
                "sha256": digest.hexdigest(),
            },
        }
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            CLEANUP.stop(process)
        except BaseException as cleanup_error:
            if primary_error is None:
                raise
            raise CORE.VerificationError(
                f"{primary_error}; process-group cleanup failed: {cleanup_error}"
            ) from primary_error


CORE.run_build = run_build
CORE.query = query

for _name in dir(CORE):
    if not _name.startswith("__") and _name != "run_build":
        globals()[_name] = getattr(CORE, _name)


if __name__ == "__main__":
    raise SystemExit(CORE.main())
