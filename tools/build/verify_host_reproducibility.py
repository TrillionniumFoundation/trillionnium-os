#!/usr/bin/env python3
"""Stable CLI facade for bounded Host/Core reproducibility builds.

Every imported behavior-bearing Python module is read once from a regular-file
snapshot, hashed, compiled and executed from those exact bytes.  Cargo, rustc,
cc and ar are later executed from inherited write-sealed memfd snapshots while the
same retained SID/PGID cleanup used by the product benchmark bounds every build.
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


HERE = Path(__file__).resolve().parent
REPOSITORY_ROOT = HERE.parents[1]
CORE_PATH = HERE / "_verify_host_reproducibility_core.py"
CLEANUP_PATH = HERE.parent / "perf/run_product_baseline.py"
MAX_PINNED_SOURCE_BYTES = 8 * 1024 * 1024


def _snapshot_source(path: Path, logical_path: str) -> tuple[bytes, dict[str, Any]]:
    if path.is_symlink():
        raise RuntimeError(f"pinned Python source is a symlink: {logical_path}")
    root = REPOSITORY_ROOT.resolve(strict=True)
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise RuntimeError(f"pinned Python source escaped repository: {logical_path}")
    descriptor = os.open(
        resolved,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_PINNED_SOURCE_BYTES:
            raise RuntimeError(f"invalid pinned Python source: {logical_path}")
        chunks: list[bytes] = []
        offset = 0
        while offset < before.st_size:
            block = os.pread(
                descriptor,
                min(1024 * 1024, before.st_size - offset),
                offset,
            )
            if not block:
                raise RuntimeError(f"short read from pinned Python source: {logical_path}")
            chunks.append(block)
            offset += len(block)
        source = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
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
    Path(__file__), "tools/build/verify_host_reproducibility.py"
)
CORE, _CORE_SOURCE, _CORE_IDENTITY = _load_snapshot(
    "_verify_host_reproducibility_core",
    CORE_PATH,
    "tools/build/_verify_host_reproducibility_core.py",
)
CLEANUP, _CLEANUP_SOURCE, _CLEANUP_IDENTITY = _load_snapshot(
    "_host_reproducibility_process_cleanup",
    CLEANUP_PATH,
    "tools/perf/run_product_baseline.py",
)
cleanup_files = getattr(CLEANUP, "PINNED_IMPLEMENTATION_FILES", None)
if not isinstance(cleanup_files, dict):
    raise RuntimeError("cleanup implementation is not snapshot-bound")
if cleanup_files.get("tools/perf/run_product_baseline.py") != _CLEANUP_IDENTITY:
    raise RuntimeError("cleanup facade executed bytes differ from its nested identity")
PINNED_IMPLEMENTATION_FILES = {
    "tools/build/_verify_host_reproducibility_core.py": _CORE_IDENTITY,
    "tools/build/verify_host_reproducibility.py": _FACADE_IDENTITY,
    "tools/owner-open/owner_open_rootlinux_supervisor.py": cleanup_files[
        "tools/owner-open/owner_open_rootlinux_supervisor.py"
    ],
    "tools/perf/_run_product_baseline_core.py": cleanup_files[
        "tools/perf/_run_product_baseline_core.py"
    ],
    "tools/perf/run_product_baseline.py": _CLEANUP_IDENTITY,
}
if set(PINNED_IMPLEMENTATION_FILES) != set(CORE.IMPLEMENTATION_PATHS):
    raise RuntimeError("reproducibility implementation snapshot is incomplete")
CORE.PINNED_IMPLEMENTATION_FILES = {
    path: dict(identity) for path, identity in PINNED_IMPLEMENTATION_FILES.items()
}
CORE.EXECUTION_PASS_FDS = ()


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

for _name in dir(CORE):
    if not _name.startswith("__") and _name != "run_build":
        globals()[_name] = getattr(CORE, _name)


if __name__ == "__main__":
    raise SystemExit(CORE.main())
