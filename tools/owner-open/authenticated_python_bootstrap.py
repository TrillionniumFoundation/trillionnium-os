#!/usr/bin/env python3
"""Authenticated byte-custody bootstrap for selected Python evidence tools.

This source is never a directly executable trust anchor.  A reviewed isolated
``python -I -c`` loader must descriptor-open this file, verify its exact SHA-256,
compile those same captured bytes, and inject the four outer-loader globals
below.  This bootstrap then descriptor-opens an approved launcher, verifies the
caller-bound launcher digest, compiles those exact bytes and injects an
attestation before any launcher code executes.

Direct pathname execution fails before imports and cannot produce an admitted
measurement or reproducibility report.
"""
from __future__ import annotations

_REQUIRED_OUTER = {
    "_TRILLIONNIUM_BOOTSTRAP_FILE_SOURCE",
    "_TRILLIONNIUM_BOOTSTRAP_FILE_IDENTITY",
    "_TRILLIONNIUM_BOOTSTRAP_FILE_PATH",
    "_TRILLIONNIUM_OUTER_LOADER_POLICY",
}
if not _REQUIRED_OUTER.issubset(globals()):
    raise RuntimeError(
        "authenticated Python bootstrap must be loaded from verified captured bytes"
    )

import hashlib
import os
from pathlib import Path
import stat
import sys
from typing import Any, Callable


BOOTSTRAP_LOGICAL_PATH = "tools/owner-open/authenticated_python_bootstrap.py"
BOOTSTRAP_SCHEMA = "org.trillionnium.authenticated-python-bootstrap.v1"
BOOTSTRAP_POLICY_VERSION = "2026-09-09-v1"
OUTER_LOADER_POLICY = "python-isolated-inline-descriptor-loader-v1"
TRANSPORT = "captured-bootstrap-and-launcher-bytes-v1"
MAX_SOURCE_BYTES = 8 * 1024 * 1024
ALLOWED_LAUNCHERS = {
    "tools/perf/run_product_baseline.py",
    "tools/build/verify_host_reproducibility.py",
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: Any, label: str) -> str:
    _require(
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value),
        f"{label} must be lowercase SHA-256",
    )
    return value


def _absolute(path: Path) -> Path:
    value = Path(os.path.abspath(os.fspath(path)))
    _require(value != Path("/") and "\x00" not in os.fspath(value), "invalid path")
    return value


def _open_nofollow(path: Path) -> tuple[int, Path]:
    absolute = _absolute(path)
    components = absolute.parts[1:]
    _require(bool(components), "path has no components")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    current = os.open("/", directory_flags)
    try:
        for component in components[:-1]:
            _require(component not in {"", ".", ".."}, "path is not normalized")
            child = os.open(component, directory_flags, dir_fd=current)
            os.close(current)
            current = child
        leaf = components[-1]
        _require(leaf not in {"", ".", ".."}, "path is not normalized")
        descriptor = os.open(leaf, file_flags, dir_fd=current)
        return descriptor, absolute
    finally:
        os.close(current)


def _read_identity(
    descriptor: int,
    logical_path: str,
    *,
    after_open: Callable[[int], None] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    if after_open is not None:
        after_open(descriptor)
    before = os.fstat(descriptor)
    _require(stat.S_ISREG(before.st_mode), f"not a regular file: {logical_path}")
    _require(0 < before.st_size <= MAX_SOURCE_BYTES, f"invalid source size: {logical_path}")
    chunks: list[bytes] = []
    offset = 0
    while offset < before.st_size:
        block = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
        _require(bool(block), f"short source read: {logical_path}")
        chunks.append(block)
        offset += len(block)
    raw = b"".join(chunks)
    after = os.fstat(descriptor)
    _require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
        f"source descriptor changed: {logical_path}",
    )
    return raw, {"path": logical_path, "size": len(raw), "sha256": _sha256(raw)}


def _validated_bootstrap_identity() -> tuple[bytes, dict[str, Any], Path]:
    source = globals()["_TRILLIONNIUM_BOOTSTRAP_FILE_SOURCE"]
    identity = dict(globals()["_TRILLIONNIUM_BOOTSTRAP_FILE_IDENTITY"])
    path = _absolute(Path(globals()["_TRILLIONNIUM_BOOTSTRAP_FILE_PATH"]))
    _require(isinstance(source, bytes), "captured bootstrap source is not bytes")
    _require(
        set(identity) == {"path", "size", "sha256"}
        and identity["path"] == BOOTSTRAP_LOGICAL_PATH
        and identity["size"] == len(source)
        and identity["sha256"] == _sha256(source),
        "captured bootstrap identity differs",
    )
    _require(
        globals()["_TRILLIONNIUM_OUTER_LOADER_POLICY"] == OUTER_LOADER_POLICY,
        "outer loader policy differs",
    )
    return source, identity, path


def _parse() -> tuple[Path, str, str, list[str]]:
    _require(len(sys.argv) >= 5, "bootstrap requires launcher path, logical path and digest")
    launcher_path = Path(sys.argv[1])
    logical_path = sys.argv[2]
    expected_sha256 = _digest(sys.argv[3], "launcher digest")
    _require(sys.argv[4] == "--", "bootstrap launcher arguments require -- separator")
    _require(logical_path in ALLOWED_LAUNCHERS, "launcher is not approved by bootstrap policy")
    return launcher_path, logical_path, expected_sha256, sys.argv[5:]


def main() -> None:
    bootstrap_source, bootstrap_identity, bootstrap_path = _validated_bootstrap_identity()
    launcher_path, logical_path, expected_sha256, launcher_args = _parse()
    descriptor, absolute_launcher = _open_nofollow(launcher_path)
    try:
        hook = globals().get("_TRILLIONNIUM_TEST_AFTER_LAUNCHER_OPEN")
        _require(hook is None or callable(hook), "invalid bootstrap test hook")
        launcher_source, launcher_identity = _read_identity(
            descriptor,
            logical_path,
            after_open=(lambda fd: hook(absolute_launcher, fd)) if hook else None,
        )
    finally:
        os.close(descriptor)
    _require(
        launcher_identity["sha256"] == expected_sha256,
        f"unadmitted launcher bytes for {logical_path}: {launcher_identity['sha256']}",
    )
    attestation = {
        "schema": BOOTSTRAP_SCHEMA,
        "policy_version": BOOTSTRAP_POLICY_VERSION,
        "transport": TRANSPORT,
        "outer_loader_policy": OUTER_LOADER_POLICY,
        "bootstrap": dict(bootstrap_identity),
        "launcher": dict(launcher_identity),
        "direct_path_execution": False,
        "automatic_redispatch": False,
        "public_release": False,
    }
    code = compile(launcher_source, logical_path, "exec", dont_inherit=True)
    namespace: dict[str, Any] = {
        "__name__": "__main__",
        "__file__": str(absolute_launcher),
        "__package__": "",
        "_TRILLIONNIUM_BOOTSTRAP_SOURCE": launcher_source,
        "_TRILLIONNIUM_BOOTSTRAP_IDENTITY": dict(launcher_identity),
        "_TRILLIONNIUM_BOOTSTRAP_ATTESTATION": attestation,
        "_TRILLIONNIUM_BOOTSTRAP_FILE_SOURCE": bootstrap_source,
        "_TRILLIONNIUM_BOOTSTRAP_FILE_IDENTITY": dict(bootstrap_identity),
        "_TRILLIONNIUM_BOOTSTRAP_FILE_PATH": str(bootstrap_path),
    }
    sys.argv = [str(absolute_launcher), *launcher_args]
    exec(code, namespace)


main()
