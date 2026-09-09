#!/usr/bin/env python3
"""Minimal reviewed launcher for the Trillionnium Host/Core reproducibility verifier facade.

This file is the intentionally small source-review trust anchor.  It walks the
facade pathname from the filesystem root with descriptor-relative ``open``
operations and ``O_NOFOLLOW`` on every component, verifies the exact facade
digest, compiles those same bytes, and executes that code object.  The launcher
and facade byte identities are injected into the resulting report manifest.
"""
from __future__ import annotations

import hashlib as __launcher_hashlib
import os as __launcher_os
from pathlib import Path as __LauncherPath
import stat as __launcher_stat
from typing import Any as __LauncherAny, Callable as __LauncherCallable

__LAUNCHER_LOGICAL_PATH = 'tools/build/verify_host_reproducibility.py'
__FACADE_LOGICAL_PATH = 'tools/build/_verify_host_reproducibility_facade.py'
__FACADE_FILENAME = '_verify_host_reproducibility_facade.py'
__EXPECTED_FACADE_SHA256 = '8e766f0e82c3c9b5bd127794b1af898f5e8b9c2d5c03c10a32675dd855af61df'
__MAX_LAUNCH_SOURCE_BYTES = 8 * 1024 * 1024


def __launcher_absolute(path: __LauncherPath) -> __LauncherPath:
    value = __LauncherPath(__launcher_os.path.abspath(__launcher_os.fspath(path)))
    if value == __LauncherPath("/") or "\x00" in __launcher_os.fspath(value):
        raise RuntimeError(f"invalid launcher path: {path}")
    return value


def __launcher_open_nofollow(
    path: __LauncherPath,
    *,
    before_component: __LauncherCallable[[__LauncherPath, str, bool], None] | None = None,
    after_final: __LauncherCallable[[__LauncherPath, int], None] | None = None,
) -> tuple[int, __LauncherPath]:
    absolute = __launcher_absolute(path)
    components = absolute.parts[1:]
    directory_flags = (
        __launcher_os.O_RDONLY
        | getattr(__launcher_os, "O_CLOEXEC", 0)
        | getattr(__launcher_os, "O_DIRECTORY", 0)
        | getattr(__launcher_os, "O_NOFOLLOW", 0)
    )
    file_flags = (
        __launcher_os.O_RDONLY
        | getattr(__launcher_os, "O_CLOEXEC", 0)
        | getattr(__launcher_os, "O_NOFOLLOW", 0)
    )
    current = __launcher_os.open("/", directory_flags)
    try:
        for component in components[:-1]:
            if component in {"", ".", ".."}:
                raise RuntimeError(f"non-normal launcher component in {absolute}")
            if before_component is not None:
                before_component(absolute, component, False)
            child = __launcher_os.open(component, directory_flags, dir_fd=current)
            __launcher_os.close(current)
            current = child
        leaf = components[-1]
        if before_component is not None:
            before_component(absolute, leaf, True)
        descriptor = __launcher_os.open(leaf, file_flags, dir_fd=current)
        if after_final is not None:
            after_final(absolute, descriptor)
        return descriptor, absolute
    finally:
        __launcher_os.close(current)


def __launcher_snapshot(
    path: __LauncherPath,
    logical_path: str,
    *,
    expected_sha256: str | None = None,
    before_component: __LauncherCallable[[__LauncherPath, str, bool], None] | None = None,
    after_final: __LauncherCallable[[__LauncherPath, int], None] | None = None,
) -> tuple[bytes, dict[str, __LauncherAny], dict[str, __LauncherAny]]:
    descriptor, absolute = __launcher_open_nofollow(
        path, before_component=before_component, after_final=after_final
    )
    try:
        before = __launcher_os.fstat(descriptor)
        if not __launcher_stat.S_ISREG(before.st_mode):
            raise RuntimeError(f"launcher target is not regular: {logical_path}")
        if not 0 < before.st_size <= __MAX_LAUNCH_SOURCE_BYTES:
            raise RuntimeError(f"launcher target size is invalid: {logical_path}")
        chunks: list[bytes] = []
        offset = 0
        while offset < before.st_size:
            block = __launcher_os.pread(
                descriptor,
                min(1024 * 1024, before.st_size - offset),
                offset,
            )
            if not block:
                raise RuntimeError(f"short launcher read: {logical_path}")
            chunks.append(block)
            offset += len(block)
        source = b"".join(chunks)
        after = __launcher_os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise RuntimeError(f"launcher descriptor changed: {logical_path}")
    finally:
        __launcher_os.close(descriptor)
    digest = __launcher_hashlib.sha256(source).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise RuntimeError(
            f"unadmitted facade bytes for {logical_path}: {digest}"
        )
    report = {"path": logical_path, "size": len(source), "sha256": digest}
    internal = {
        "absolute_path": str(absolute),
        "device": before.st_dev,
        "inode": before.st_ino,
        "mode": __launcher_stat.S_IFMT(before.st_mode),
        "size": before.st_size,
        "mtime_ns": before.st_mtime_ns,
        "sha256": digest,
    }
    return source, report, internal


def __launcher_same(left: dict[str, __LauncherAny], right: dict[str, __LauncherAny]) -> bool:
    keys = ("absolute_path", "device", "inode", "mode", "size", "mtime_ns", "sha256")
    return all(left.get(key) == right.get(key) for key in keys)


def __launcher_authenticate_facade(
    facade_path: __LauncherPath,
    *,
    expected_sha256: str = __EXPECTED_FACADE_SHA256,
    before_component: __LauncherCallable[[__LauncherPath, str, bool], None] | None = None,
    after_final: __LauncherCallable[[__LauncherPath, int], None] | None = None,
    before_exec: __LauncherCallable[[__LauncherPath], None] | None = None,
) -> tuple[bytes, dict[str, __LauncherAny], object]:
    source, identity, internal = __launcher_snapshot(
        facade_path,
        __FACADE_LOGICAL_PATH,
        expected_sha256=expected_sha256,
        before_component=before_component,
        after_final=after_final,
    )
    _, _, current = __launcher_snapshot(
        facade_path,
        __FACADE_LOGICAL_PATH,
        expected_sha256=expected_sha256,
    )
    if not __launcher_same(internal, current):
        raise RuntimeError("facade path changed between descriptor admission and execution")
    code = compile(source, __FACADE_LOGICAL_PATH, "exec", dont_inherit=True)
    if before_exec is not None:
        before_exec(facade_path)
    return source, identity, code


if "_TRILLIONNIUM_BOOTSTRAP_SOURCE" in globals():
    __launcher_source = globals()["_TRILLIONNIUM_BOOTSTRAP_SOURCE"]
    __launcher_identity = dict(globals()["_TRILLIONNIUM_BOOTSTRAP_IDENTITY"])
    __launcher_path = __launcher_absolute(__LauncherPath(__file__))
    if not isinstance(__launcher_source, bytes):
        raise RuntimeError("captured launcher source is not bytes")
    if __launcher_hashlib.sha256(__launcher_source).hexdigest() != __launcher_identity.get("sha256"):
        raise RuntimeError("captured launcher digest differs")
else:
    __launcher_path = __launcher_absolute(__LauncherPath(__file__))
    __launcher_source, __launcher_identity, _ = __launcher_snapshot(
        __launcher_path, __LAUNCHER_LOGICAL_PATH
    )

__facade_path = __launcher_path.with_name(__FACADE_FILENAME)
__facade_source, __facade_identity, __facade_code = __launcher_authenticate_facade(
    __facade_path
)

globals().update({
    "_TRILLIONNIUM_LAUNCHER_SOURCE": __launcher_source,
    "_TRILLIONNIUM_LAUNCHER_IDENTITY": dict(__launcher_identity),
    "_TRILLIONNIUM_LAUNCHER_PATH": str(__launcher_path),
    "_TRILLIONNIUM_FACADE_SOURCE": __facade_source,
    "_TRILLIONNIUM_FACADE_IDENTITY": dict(__facade_identity),
    "_TRILLIONNIUM_FACADE_PATH": str(__facade_path),
})
exec(__facade_code, globals())
