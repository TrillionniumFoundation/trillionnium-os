#!/usr/bin/env python3
"""Create or verify an immutable, closed-world Mobian toolchain snapshot.

Source traversal is descriptor-pinned and rejects unsafe ownership, writable
ancestors, and symlink/magic-link pathname substitution.  This process-local
hardening is not an isolation boundary against a malicious same-UID process
that can write already-open source inodes (or tamper with this process); the
production caller must still provide exclusive source custody.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import posixpath
import shutil
import stat
import tempfile
from typing import Any, Iterator


MANIFEST_SCHEMA = "org.trillionnium.packaging.mobian-toolchain-snapshot-manifest.v1"
VERIFY_SCHEMA = "org.trillionnium.packaging.mobian-toolchain-snapshot-verification.v1"
PASS = "PASS_IMMUTABLE_MOBIAN_TOOLCHAIN_SNAPSHOT"
DIRECTORY_MODE = 0o500
MAX_ENTRY_COUNT = 100_000
MAX_PATH_BYTES = 1_024
MAX_SYMLINK_TARGET_BYTES = 4_096
MAX_REGULAR_FILE_BYTES = 1 * 1024 * 1024 * 1024
MAX_REGULAR_BYTES = 8 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
SOURCE_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
SOURCE_REGULAR_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
SOURCE_SYMLINK_FLAGS = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
SYS_OPENAT2 = 437


class OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


class SnapshotError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _reject_duplicate_json_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotError(f"manifest contains duplicate object key: {key!r}")
        result[key] = value
    return result


def _reject_nonfinite_json_constant(value: str) -> Any:
    raise SnapshotError(f"manifest contains a non-finite number: {value}")


def strict_json_loads(payload: bytes) -> Any:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_pairs,
            parse_constant=_reject_nonfinite_json_constant,
        )
    except SnapshotError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, MemoryError) as exc:
        raise SnapshotError("manifest is not valid strict UTF-8 JSON") from exc
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
        elif type(current) is float and not math.isfinite(current):
            raise SnapshotError("manifest contains a non-finite number")
        elif current is not None and type(current) not in {str, bool, int, float}:
            raise SnapshotError("manifest contains an unsupported JSON scalar")
    return value


_openat2_available: bool | None = None


def openat_beneath(directory_fd: int, name: str, flags: int) -> int:
    """Open one literal child beneath a pinned directory descriptor."""
    global _openat2_available
    if name in {"", ".", ".."} or "/" in name or "\x00" in name:
        raise SnapshotError(f"unsafe source entry name: {name!r}")
    if _openat2_available is not False:
        how = OpenHow(
            flags=flags,
            mode=0,
            resolve=(
                RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS
            ),
        )
        libc = ctypes.CDLL(None, use_errno=True)
        result = libc.syscall(
            SYS_OPENAT2,
            directory_fd,
            ctypes.c_char_p(os.fsencode(name)),
            ctypes.byref(how),
            ctypes.sizeof(how),
        )
        if result >= 0:
            _openat2_available = True
            return int(result)
        error = ctypes.get_errno()
        if error != errno.ENOSYS:
            raise OSError(error, os.strerror(error), name)
        _openat2_available = False
    # Older kernels still get component-by-component dirfd traversal and
    # O_NOFOLLOW.  No untrusted multi-component path is ever reopened here.
    return os.open(name, flags, dir_fd=directory_fd)


def source_stat_version(info: os.stat_result) -> tuple[int, ...]:
    """Metadata a non-privileged writer cannot fully restore after mutation."""
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def source_identity_fields(info: os.stat_result) -> dict[str, int]:
    return {
        "dev": info.st_dev,
        "ino": info.st_ino,
        "uid": info.st_uid,
        "ctime_ns": info.st_ctime_ns,
    }


def require_unchanged_fd(
    fd: int, expected: os.stat_result, relative: str, operation: str
) -> os.stat_result:
    actual = os.fstat(fd)
    if source_stat_version(actual) != source_stat_version(expected):
        raise SnapshotError(f"source entry changed {operation}: {relative}")
    return actual


def require_no_xattrs_fd(fd: int, relative: str) -> None:
    try:
        attributes = os.listxattr(fd)
    except OSError as exc:
        raise SnapshotError(f"unable to inspect xattrs for {relative}") from exc
    if attributes:
        raise SnapshotError(f"xattrs/ACL/capabilities are not allowed: {relative}")


def require_no_xattrs_at(directory_fd: int, name: str, relative: str) -> None:
    # listxattr has no dir_fd argument.  /proc/self/fd pins every ancestor;
    # follow_symlinks=False applies to the literal child being inspected.
    path = Path(f"/proc/self/fd/{directory_fd}") / name
    try:
        attributes = os.listxattr(path, follow_symlinks=False)
    except OSError as exc:
        raise SnapshotError(f"unable to inspect xattrs for {relative}") from exc
    if attributes:
        raise SnapshotError(f"xattrs/ACL/capabilities are not allowed: {relative}")


def validate_secure_source_ancestor(
    info: os.stat_result, path: Path, user_boundary_seen: bool
) -> bool:
    uid = os.getuid()
    if not stat.S_ISDIR(info.st_mode):
        raise SnapshotError(f"source ancestor is not a real directory: {path}")
    if info.st_uid not in {0, uid}:
        raise SnapshotError(f"source ancestor has wrong owner: {path}")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise SnapshotError(f"source ancestor is group/world writable: {path}")
    # A root-owned, non-writable system prefix (/ and usually /home) is a
    # valid trust anchor.  Beneath the first current-user-owned component the
    # ownership chain must remain entirely with that user.
    if user_boundary_seen and info.st_uid != uid:
        raise SnapshotError(f"source ancestor is not current-user-owned: {path}")
    return user_boundary_seen or info.st_uid == uid


def open_secure_absolute(
    path: Path, *, label: str, final_flags: int, final_type: str
) -> tuple[int, os.stat_result]:
    if not path.is_absolute() or path.anchor != "/" or ".." in path.parts:
        raise SnapshotError(f"{label} must be an absolute traversal-free path")
    current_fd = os.open("/", SOURCE_DIRECTORY_FLAGS)
    current_path = Path("/")
    try:
        root_info = os.fstat(current_fd)
        user_boundary_seen = validate_secure_source_ancestor(
            root_info, current_path, False
        )
        parts = path.parts[1:]
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            flags = final_flags if final else SOURCE_DIRECTORY_FLAGS
            try:
                next_fd = openat_beneath(current_fd, part, flags)
            except OSError as exc:
                raise SnapshotError(
                    f"{label} contains a symlink component, magic-link, or non-directory "
                    f"component: {current_path / part}"
                ) from exc
            os.close(current_fd)
            current_fd = next_fd
            current_path /= part
            info = os.fstat(current_fd)
            if not final:
                user_boundary_seen = validate_secure_source_ancestor(
                    info, current_path, user_boundary_seen
                )
        final_info = os.fstat(current_fd)
        if final_type == "directory":
            if not stat.S_ISDIR(final_info.st_mode):
                raise SnapshotError(f"{label} must be a real directory")
        elif final_type == "regular":
            if not stat.S_ISREG(final_info.st_mode):
                raise SnapshotError(f"{label} must be a real regular file")
        else:
            raise AssertionError(f"unknown final_type: {final_type}")
        if final_info.st_uid != os.getuid():
            raise SnapshotError(f"{label} must be current-user-owned")
        if stat.S_IMODE(final_info.st_mode) & 0o022:
            raise SnapshotError(f"{label} must not be group/world writable")
        return current_fd, final_info
    except Exception:
        os.close(current_fd)
        raise


def open_secure_source_root(source: Path) -> tuple[int, os.stat_result]:
    return open_secure_absolute(
        source,
        label="source toolchain",
        final_flags=SOURCE_DIRECTORY_FLAGS,
        final_type="directory",
    )


def open_secure_external_regular(
    path: Path, relative: str
) -> tuple[int, os.stat_result]:
    fd, info = open_secure_absolute(
        path,
        label=f"external source for {relative}",
        final_flags=SOURCE_REGULAR_FLAGS,
        final_type="regular",
    )
    try:
        if info.st_nlink != 1:
            raise SnapshotError(f"external source has multiple hard links: {relative}")
        require_no_xattrs_fd(fd, relative)
        return fd, info
    except Exception:
        os.close(fd)
        raise


def open_source_child(
    directory_fd: int,
    name: str,
    flags: int,
    expected: os.stat_result,
    relative: str,
) -> tuple[int, os.stat_result]:
    try:
        fd = openat_beneath(directory_fd, name, flags)
    except OSError as exc:
        raise SnapshotError(f"source entry changed before open: {relative}") from exc
    opened = os.fstat(fd)
    if source_stat_version(opened) != source_stat_version(expected):
        os.close(fd)
        raise SnapshotError(f"source entry changed before open: {relative}")
    return fd, opened


def sha256_file(path: Path, expected: os.stat_result | None = None) -> str:
    digest = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    opened = os.fstat(fd)
    if not stat.S_ISREG(opened.st_mode):
        os.close(fd)
        raise SnapshotError(f"hash input is not a regular file: {path}")
    if expected is not None and (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
        opened.st_mtime_ns,
    ) != (
        expected.st_dev,
        expected.st_ino,
        expected.st_size,
        expected.st_mtime_ns,
    ):
        os.close(fd)
        raise SnapshotError(f"regular file changed before open: {path}")
    with os.fdopen(fd, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    if (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) != (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
        opened.st_mtime_ns,
    ):
        raise SnapshotError(f"regular file changed while hashing: {path}")
    return digest.hexdigest()


def require_no_xattrs(path: Path, relative: str) -> None:
    try:
        attributes = os.listxattr(path, follow_symlinks=False)
    except OSError as exc:
        raise SnapshotError(f"unable to inspect xattrs for {relative}") from exc
    if attributes:
        raise SnapshotError(f"xattrs/ACL/capabilities are not allowed: {relative}")


def rename_noreplace(source: Path, target: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise SnapshotError("renameat2(RENAME_NOREPLACE) is required")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100,
        os.fsencode(source),
        -100,
        os.fsencode(target),
        1,
    )
    if result != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise SnapshotError(f"output appeared during publication: {target}")
        raise SnapshotError(f"atomic no-replace publication failed: {os.strerror(error)}")


def no_symlink_components(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError as exc:
            raise SnapshotError(f"path component is missing: {current}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise SnapshotError(f"path contains a symlink component: {current}")


def require_secure_parent(path: Path) -> os.stat_result:
    if not path.is_absolute():
        raise SnapshotError("snapshot and manifest paths must be absolute")
    no_symlink_components(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink():
        raise SnapshotError(f"secure parent must be a real directory: {path}")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise SnapshotError(f"secure parent must be current-user-owned mode 0700: {path}")
    return info


def require_new(path: Path, label: str) -> None:
    if path.exists() or path.is_symlink():
        raise SnapshotError(f"refusing to overwrite {label}: {path}")


def normalized_rel(root: Path, path: Path) -> str:
    relative = path.relative_to(root).as_posix()
    if len(os.fsencode(relative)) > MAX_PATH_BYTES:
        raise SnapshotError(f"snapshot entry path exceeds limit: {relative!r}")
    parsed = PurePosixPath(relative)
    if parsed.is_absolute() or any(part in {"", ".", ".."} for part in parsed.parts):
        raise SnapshotError(f"unsafe snapshot entry: {relative!r}")
    return relative


def walk_lstat(root: Path) -> Iterator[tuple[str, Path, os.stat_result]]:
    entry_count = 0

    def recurse(directory: Path) -> Iterator[tuple[str, Path, os.stat_result]]:
        nonlocal entry_count
        child_count = 0
        with os.scandir(directory) as iterator:
            for _ in iterator:
                child_count += 1
                if child_count > MAX_ENTRY_COUNT:
                    raise SnapshotError("toolchain directory entry count exceeds limit")
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
        for child in children:
            entry_count += 1
            if entry_count > MAX_ENTRY_COUNT:
                raise SnapshotError("toolchain entry count exceeds limit")
            path = Path(child.path)
            info = path.lstat()
            relative = normalized_rel(root, path)
            yield relative, path, info
            if stat.S_ISDIR(info.st_mode):
                yield from recurse(path)

    yield from recurse(root)


def validate_source_tree_entry(info: os.stat_result, relative: str) -> None:
    if info.st_uid != os.getuid():
        raise SnapshotError(f"source entry is not current-user-owned: {relative}")
    if not stat.S_ISLNK(info.st_mode) and stat.S_IMODE(info.st_mode) & 0o022:
        raise SnapshotError(f"source entry is group/world writable: {relative}")


def sha256_source_fd(fd: int, expected: os.stat_result, relative: str) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    for chunk in iter(lambda: os.read(fd, 1024 * 1024), b""):
        digest.update(chunk)
    require_unchanged_fd(fd, expected, relative, "while hashing")
    return digest.hexdigest()


def write_all(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(fd, payload[offset:])
        if written <= 0:
            raise SnapshotError("short write while copying source toolchain")
        offset += written


def copy_regular_from_fd(
    source_fd: int,
    expected: os.stat_result,
    destination_fd: int,
    name: str,
    relative: str,
) -> str:
    digest = hashlib.sha256()
    destination_mode = 0o700 if expected.st_mode & 0o111 else 0o600
    output_fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        destination_mode,
        dir_fd=destination_fd,
    )
    try:
        os.lseek(source_fd, 0, os.SEEK_SET)
        for chunk in iter(lambda: os.read(source_fd, 1024 * 1024), b""):
            digest.update(chunk)
            write_all(output_fd, chunk)
    finally:
        os.close(output_fd)
    require_unchanged_fd(source_fd, expected, relative, "while copying")
    return digest.hexdigest()


def source_relative(parent: str, name: str) -> str:
    relative = f"{parent}/{name}" if parent else name
    if len(os.fsencode(relative)) > MAX_PATH_BYTES:
        raise SnapshotError(f"snapshot entry path exceeds limit: {relative!r}")
    parsed = PurePosixPath(relative)
    if parsed.is_absolute() or any(part in {"", ".", ".."} for part in parsed.parts):
        raise SnapshotError(f"unsafe snapshot entry: {relative!r}")
    return relative


def source_tree_state_from_fd(
    root_fd: int, destination_root: Path | None = None
) -> str:
    root_info = os.fstat(root_fd)
    if not stat.S_ISDIR(root_info.st_mode):
        raise SnapshotError("pinned source root is not a directory")
    validate_source_tree_entry(root_info, "<source-root>")
    require_no_xattrs_fd(root_fd, "<source-root>")
    entries: list[dict[str, Any]] = []
    entry_count = 0
    regular_bytes = 0
    destination_root_fd: int | None = None
    if destination_root is not None:
        destination_root_fd = os.open(
            destination_root, SOURCE_DIRECTORY_FLAGS
        )
        if os.listdir(destination_root_fd):
            os.close(destination_root_fd)
            raise SnapshotError("snapshot staging directory is not empty")

    def recurse(directory_fd: int, destination_fd: int | None, parent: str) -> None:
        nonlocal entry_count, regular_bytes
        directory_info = os.fstat(directory_fd)
        names = sorted(os.listdir(directory_fd), key=os.fsencode)
        if len(names) > MAX_ENTRY_COUNT:
            raise SnapshotError("toolchain directory entry count exceeds limit")
        for name in names:
            entry_count += 1
            if entry_count > MAX_ENTRY_COUNT:
                raise SnapshotError("toolchain entry count exceeds limit")
            relative = source_relative(parent, name)
            try:
                expected = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError as exc:
                raise SnapshotError(f"source entry changed before stat: {relative}") from exc
            mode = stat.S_IMODE(expected.st_mode)
            if stat.S_ISDIR(expected.st_mode):
                child_fd, opened = open_source_child(
                    directory_fd,
                    name,
                    SOURCE_DIRECTORY_FLAGS,
                    expected,
                    relative,
                )
                destination_child_fd: int | None = None
                try:
                    validate_source_tree_entry(opened, relative)
                    require_no_xattrs_fd(child_fd, relative)
                    entries.append(
                        {
                            "path": relative,
                            "type": "directory",
                            "mode": f"{mode:04o}",
                            "mtime_ns": opened.st_mtime_ns,
                            **source_identity_fields(opened),
                        }
                    )
                    if destination_fd is not None:
                        os.mkdir(name, 0o700, dir_fd=destination_fd)
                        destination_child_fd = os.open(
                            name, SOURCE_DIRECTORY_FLAGS, dir_fd=destination_fd
                        )
                    recurse(child_fd, destination_child_fd, relative)
                    require_unchanged_fd(
                        child_fd, opened, relative, "while traversing"
                    )
                finally:
                    if destination_child_fd is not None:
                        os.close(destination_child_fd)
                    os.close(child_fd)
            elif stat.S_ISREG(expected.st_mode):
                child_fd, opened = open_source_child(
                    directory_fd,
                    name,
                    SOURCE_REGULAR_FLAGS,
                    expected,
                    relative,
                )
                try:
                    validate_source_tree_entry(opened, relative)
                    require_no_xattrs_fd(child_fd, relative)
                    if opened.st_nlink != 1:
                        raise SnapshotError(
                            f"source regular file has multiple hard links: {relative}"
                        )
                    if opened.st_size > MAX_REGULAR_FILE_BYTES:
                        raise SnapshotError(
                            f"source regular file exceeds size limit: {relative}"
                        )
                    regular_bytes += opened.st_size
                    if regular_bytes > MAX_REGULAR_BYTES:
                        raise SnapshotError(
                            "source regular-file bytes exceed aggregate limit"
                        )
                    if destination_fd is None:
                        file_sha = sha256_source_fd(child_fd, opened, relative)
                    else:
                        file_sha = copy_regular_from_fd(
                            child_fd, opened, destination_fd, name, relative
                        )
                    entries.append(
                        {
                            "path": relative,
                            "type": "regular",
                            "mode": f"{mode:04o}",
                            "bytes": opened.st_size,
                            "mtime_ns": opened.st_mtime_ns,
                            "sha256": file_sha,
                            **source_identity_fields(opened),
                        }
                    )
                finally:
                    os.close(child_fd)
            elif stat.S_ISLNK(expected.st_mode):
                child_fd, opened = open_source_child(
                    directory_fd,
                    name,
                    SOURCE_SYMLINK_FLAGS,
                    expected,
                    relative,
                )
                try:
                    validate_source_tree_entry(opened, relative)
                    require_no_xattrs_at(directory_fd, name, relative)
                    target = os.readlink("", dir_fd=child_fd)
                    if len(os.fsencode(target)) > MAX_SYMLINK_TARGET_BYTES:
                        raise SnapshotError(
                            f"source symlink target exceeds limit: {relative}"
                        )
                    require_unchanged_fd(
                        child_fd, opened, relative, "while reading symlink"
                    )
                    entry: dict[str, Any] = {
                        "path": relative,
                        "type": "symlink",
                        "target": target,
                        "target_sha256": hashlib.sha256(
                            os.fsencode(target)
                        ).hexdigest(),
                        **source_identity_fields(opened),
                    }
                    if os.path.isabs(target) and relative == "cargo/bin/rustup":
                        external_fd, external_info = open_secure_external_regular(
                            Path(target), relative
                        )
                        try:
                            if external_info.st_size > MAX_REGULAR_FILE_BYTES:
                                raise SnapshotError(
                                    "external rustup source exceeds size limit"
                                )
                            regular_bytes += external_info.st_size
                            if regular_bytes > MAX_REGULAR_BYTES:
                                raise SnapshotError(
                                    "source regular-file bytes exceed aggregate limit"
                                )
                            if destination_fd is None:
                                resolved_sha = sha256_source_fd(
                                    external_fd, external_info, relative
                                )
                            else:
                                resolved_sha = copy_regular_from_fd(
                                    external_fd,
                                    external_info,
                                    destination_fd,
                                    name,
                                    relative,
                                )
                            entry.update(
                                {
                                    "resolved_bytes": external_info.st_size,
                                    "resolved_sha256": resolved_sha,
                                    "resolved_dev": external_info.st_dev,
                                    "resolved_ino": external_info.st_ino,
                                    "resolved_ctime_ns": external_info.st_ctime_ns,
                                }
                            )
                        finally:
                            os.close(external_fd)
                    elif os.path.isabs(target):
                        if not relative.startswith("sysroot/"):
                            raise SnapshotError(
                                f"absolute external symlink is not allowlisted: {relative}"
                            )
                        if destination_fd is not None:
                            logical_target = PurePosixPath("sysroot") / target.lstrip("/")
                            replacement = posixpath.relpath(
                                logical_target.as_posix(),
                                PurePosixPath(relative).parent.as_posix(),
                            )
                            os.symlink(replacement, name, dir_fd=destination_fd)
                    elif destination_fd is not None:
                        os.symlink(target, name, dir_fd=destination_fd)
                    entries.append(entry)
                finally:
                    os.close(child_fd)
            else:
                raise SnapshotError(
                    f"unsupported source toolchain entry type: {relative}"
                )
        require_unchanged_fd(
            directory_fd,
            directory_info,
            parent or "<source-root>",
            "while traversing",
        )

    try:
        recurse(root_fd, destination_root_fd, "")
    finally:
        if destination_root_fd is not None:
            os.close(destination_root_fd)
    require_unchanged_fd(root_fd, root_info, "<source-root>", "while traversing")
    entries.sort(key=lambda item: os.fsencode(item["path"]))
    state = {
        "root": {
            "mode": f"{stat.S_IMODE(root_info.st_mode):04o}",
            "mtime_ns": root_info.st_mtime_ns,
            **source_identity_fields(root_info),
        },
        "entries": entries,
    }
    return hashlib.sha256(canonical_json(state)).hexdigest()


def copy_source_tree(root_fd: int, destination_root: Path) -> str:
    return source_tree_state_from_fd(root_fd, destination_root)


def revalidate_source_root_path(
    source: Path, pinned_fd: int, initial: os.stat_result
) -> None:
    pinned = os.fstat(pinned_fd)
    if source_stat_version(pinned) != source_stat_version(initial):
        raise SnapshotError("pinned source root changed while snapshotting")
    reopened_fd, reopened = open_secure_source_root(source)
    try:
        if source_stat_version(reopened) != source_stat_version(pinned):
            raise SnapshotError("source root path changed while snapshotting")
    finally:
        os.close(reopened_fd)


def collect_source_state(source: Path) -> str:
    root_fd, root_info = open_secure_source_root(source)
    try:
        state = source_tree_state_from_fd(root_fd)
        revalidate_source_root_path(source, root_fd, root_info)
        return state
    finally:
        os.close(root_fd)


def normalize_snapshot(root: Path, source_date_epoch: int) -> None:
    timestamp_ns = source_date_epoch * 1_000_000_000
    paths = list(walk_lstat(root))
    for _, path, info in paths:
        if stat.S_ISDIR(info.st_mode):
            continue
        if stat.S_ISREG(info.st_mode):
            os.chmod(path, 0o555 if info.st_mode & 0o111 else 0o444)
            os.utime(path, ns=(timestamp_ns, timestamp_ns), follow_symlinks=False)
        elif stat.S_ISLNK(info.st_mode):
            os.utime(path, ns=(timestamp_ns, timestamp_ns), follow_symlinks=False)
        else:
            raise SnapshotError(f"unsupported toolchain entry type: {path}")
    for _, path, info in reversed(paths):
        if stat.S_ISDIR(info.st_mode):
            os.chmod(path, DIRECTORY_MODE)
            os.utime(path, ns=(timestamp_ns, timestamp_ns), follow_symlinks=False)
    os.chmod(root, DIRECTORY_MODE)
    os.utime(root, ns=(timestamp_ns, timestamp_ns), follow_symlinks=False)


def collect_entries(root: Path, source_date_epoch: int) -> tuple[list[dict[str, Any]], dict[str, int]]:
    root_info = root.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or root.is_symlink():
        raise SnapshotError("snapshot root must be a real directory")
    require_no_xattrs(root, "<snapshot-root>")
    if root_info.st_uid != os.getuid() or stat.S_IMODE(root_info.st_mode) != DIRECTORY_MODE:
        raise SnapshotError("snapshot root must be current-user-owned mode 0500")
    if root_info.st_mtime_ns != source_date_epoch * 1_000_000_000:
        raise SnapshotError("snapshot root mtime does not match SOURCE_DATE_EPOCH")

    entries: list[dict[str, Any]] = []
    symlinks: list[tuple[str, Path, os.stat_result]] = []
    regular_hashes: dict[str, str] = {}
    directory_modes: dict[str, str] = {"": "0500"}
    counts = {"directories": 1, "regular_files": 0, "symlinks": 0, "regular_bytes": 0}
    for relative, path, info in walk_lstat(root):
        require_no_xattrs(path, relative)
        if info.st_uid != os.getuid():
            raise SnapshotError(f"snapshot entry is not current-user owned: {relative}")
        if info.st_mtime_ns != source_date_epoch * 1_000_000_000:
            raise SnapshotError(f"snapshot entry mtime mismatch: {relative}")
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISDIR(info.st_mode):
            if mode != DIRECTORY_MODE:
                raise SnapshotError(f"snapshot directory mode is not 0500: {relative}")
            counts["directories"] += 1
            directory_modes[relative] = "0500"
            entries.append({"path": relative, "type": "directory", "mode": "0500"})
        elif stat.S_ISREG(info.st_mode):
            if mode not in {0o444, 0o555}:
                raise SnapshotError(f"snapshot regular mode is not 0444/0555: {relative}")
            if info.st_nlink != 1:
                raise SnapshotError(f"snapshot regular file has multiple hard links: {relative}")
            if info.st_size > MAX_REGULAR_FILE_BYTES:
                raise SnapshotError(f"snapshot regular file exceeds size limit: {relative}")
            counts["regular_files"] += 1
            counts["regular_bytes"] += info.st_size
            if counts["regular_bytes"] > MAX_REGULAR_BYTES:
                raise SnapshotError("snapshot regular-file bytes exceed aggregate limit")
            file_sha = sha256_file(path, info)
            regular_hashes[relative] = file_sha
            entries.append(
                {
                    "path": relative,
                    "type": "regular",
                    "mode": f"{mode:04o}",
                    "bytes": info.st_size,
                    "sha256": file_sha,
                }
            )
        elif stat.S_ISLNK(info.st_mode):
            symlinks.append((relative, path, info))
        else:
            raise SnapshotError(f"unsupported snapshot entry type: {relative}")
    root_resolved = root.resolve(strict=True)
    for relative, path, _ in symlinks:
        target = os.readlink(path)
        if len(os.fsencode(target)) > MAX_SYMLINK_TARGET_BYTES:
            raise SnapshotError(f"snapshot symlink target exceeds limit: {relative}")
        if "\x00" in target or os.path.isabs(target):
            raise SnapshotError(f"snapshot symlink is not a safe relative link: {relative}")
        try:
            lexical_resolved = path.resolve(strict=False)
            lexical_relative = lexical_resolved.relative_to(root_resolved).as_posix()
            if lexical_relative == ".":
                lexical_relative = ""
        except (OSError, RuntimeError, ValueError) as exc:
            raise SnapshotError(f"snapshot symlink is escaping or cyclic: {relative}") from exc
        try:
            resolved = path.resolve(strict=True)
            resolved_relative = resolved.relative_to(root_resolved).as_posix()
            if resolved_relative == ".":
                resolved_relative = ""
        except FileNotFoundError:
            counts["symlinks"] += 1
            entries.append(
                {
                    "path": relative,
                    "type": "symlink",
                    "target": target,
                    "target_sha256": hashlib.sha256(os.fsencode(target)).hexdigest(),
                    "resolved": False,
                    "contained_unresolved_path": lexical_relative,
                }
            )
            continue
        except (OSError, RuntimeError, ValueError) as exc:
            raise SnapshotError(f"snapshot symlink is escaping or cyclic: {relative}") from exc
        resolved_info = resolved.lstat()
        if stat.S_ISREG(resolved_info.st_mode):
            resolved_type = "regular"
            resolved_sha = regular_hashes.get(resolved_relative)
            if resolved_sha is None:
                raise SnapshotError(f"resolved symlink regular file is not manifested: {relative}")
        elif stat.S_ISDIR(resolved_info.st_mode):
            resolved_type = "directory"
            resolved_sha = hashlib.sha256(
                canonical_json(
                    {
                        "path": resolved_relative,
                        "type": "directory",
                        "mode": directory_modes.get(resolved_relative),
                    }
                )
            ).hexdigest()
        else:
            raise SnapshotError(f"snapshot symlink resolves to unsupported type: {relative}")
        counts["symlinks"] += 1
        entries.append(
            {
                "path": relative,
                "type": "symlink",
                "target": target,
                "target_sha256": hashlib.sha256(os.fsencode(target)).hexdigest(),
                "resolved": True,
                "resolved_path": resolved_relative,
                "resolved_type": resolved_type,
                "resolved_sha256": resolved_sha,
            }
        )
    entries.sort(key=lambda item: os.fsencode(item["path"]))
    return entries, counts


def make_manifest(root: Path, source_date_epoch: int) -> dict[str, Any]:
    entries, counts = collect_entries(root, source_date_epoch)
    tree_digest = hashlib.sha256(canonical_json(entries)).hexdigest()
    manifest: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "source_date_epoch": source_date_epoch,
        "tree_digest": tree_digest,
        "entries": entries,
        "summary": {
            **counts,
            "entry_count": len(entries),
            "closed_world": True,
            "current_user_owned": True,
            "directories_mode_0500": True,
            "regular_files_mode_0444_or_0555": True,
            "regular_files_single_link": True,
            "group_world_writable_entries": 0,
            "symlink_targets_manifested": True,
        },
    }
    manifest["manifest_id"] = hashlib.sha256(canonical_json(manifest)).hexdigest()
    return manifest


def read_manifest(path: Path) -> tuple[dict[str, Any], os.stat_result]:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise SnapshotError(f"manifest is missing: {path}") from exc
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_nlink != 1:
        raise SnapshotError("manifest must be a regular, non-symlink, single-link file")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o444:
        raise SnapshotError("manifest must be current-user-owned mode 0444")
    if info.st_size > MAX_MANIFEST_BYTES:
        raise SnapshotError("manifest exceeds size limit")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            os.close(fd)
            raise SnapshotError("manifest changed before open")
        with os.fdopen(fd, "rb") as stream:
            payload = stream.read()
            after = os.fstat(stream.fileno())
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ):
            raise SnapshotError("manifest changed while reading")
        value = strict_json_loads(payload)
    except SnapshotError:
        raise
    if not isinstance(value, dict) or value.get("schema") != MANIFEST_SCHEMA:
        raise SnapshotError("manifest schema mismatch")
    if set(value) != {
        "schema",
        "source_date_epoch",
        "tree_digest",
        "entries",
        "summary",
        "manifest_id",
    }:
        raise SnapshotError("manifest top-level keyset mismatch")
    if set(value.get("summary", {})) != {
        "directories",
        "regular_files",
        "symlinks",
        "regular_bytes",
        "entry_count",
        "closed_world",
        "current_user_owned",
        "directories_mode_0500",
        "regular_files_mode_0444_or_0555",
        "regular_files_single_link",
        "group_world_writable_entries",
        "symlink_targets_manifested",
    }:
        raise SnapshotError("manifest summary keyset mismatch")
    entries = value.get("entries")
    if not isinstance(entries, list):
        raise SnapshotError("manifest entries must be an array")
    if len(entries) > MAX_ENTRY_COUNT:
        raise SnapshotError("manifest entry count exceeds limit")
    previous: bytes | None = None
    seen: set[str] = set()
    regular_bytes = 0
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise SnapshotError("manifest entry is malformed")
        entry_type = entry.get("type")
        expected_keys = {
            "directory": {"path", "type", "mode"},
            "regular": {"path", "type", "mode", "bytes", "sha256"},
        }.get(entry_type)
        if entry_type == "symlink":
            if entry.get("resolved") is True:
                expected_keys = {
                    "path", "type", "target", "target_sha256", "resolved",
                    "resolved_path", "resolved_type", "resolved_sha256",
                }
            elif entry.get("resolved") is False:
                expected_keys = {
                    "path", "type", "target", "target_sha256", "resolved",
                    "contained_unresolved_path",
                }
            else:
                raise SnapshotError("manifest symlink resolved flag is invalid")
        if expected_keys is None or set(entry) != expected_keys:
            raise SnapshotError("manifest entry keyset mismatch")
        encoded = os.fsencode(entry["path"])
        if len(encoded) > MAX_PATH_BYTES:
            raise SnapshotError("manifest entry path exceeds limit")
        if entry_type == "regular":
            size = entry.get("bytes")
            if not isinstance(size, int) or size < 0 or size > MAX_REGULAR_FILE_BYTES:
                raise SnapshotError("manifest regular file size exceeds limit")
            regular_bytes += size
            if regular_bytes > MAX_REGULAR_BYTES:
                raise SnapshotError("manifest regular-file bytes exceed aggregate limit")
        if entry_type == "symlink":
            target = entry.get("target")
            if not isinstance(target, str) or len(os.fsencode(target)) > MAX_SYMLINK_TARGET_BYTES:
                raise SnapshotError("manifest symlink target exceeds limit")
        if entry["path"] in seen or (previous is not None and encoded <= previous):
            raise SnapshotError("manifest entries are duplicate or unsorted")
        seen.add(entry["path"])
        previous = encoded
    expected_id = value.get("manifest_id")
    unsigned = dict(value)
    unsigned.pop("manifest_id", None)
    if expected_id != hashlib.sha256(canonical_json(unsigned)).hexdigest():
        raise SnapshotError("manifest_id mismatch")
    return value, info


def verify(snapshot: Path, manifest_path: Path) -> dict[str, Any]:
    no_symlink_components(snapshot)
    no_symlink_components(manifest_path)
    manifest, manifest_info = read_manifest(manifest_path)
    epoch = manifest.get("source_date_epoch")
    if (
        not isinstance(epoch, int)
        or epoch <= 0
        or manifest_info.st_mtime_ns != epoch * 1_000_000_000
    ):
        raise SnapshotError("manifest SOURCE_DATE_EPOCH metadata mismatch")
    actual = make_manifest(snapshot, epoch)
    if actual != manifest:
        raise SnapshotError("snapshot does not match its closed-world manifest")
    return {
        "schema": VERIFY_SCHEMA,
        "decision": PASS,
        "passed": True,
        "source_date_epoch": epoch,
        "tree_digest": manifest["tree_digest"],
        "manifest_id": manifest["manifest_id"],
        "manifest_sha256": sha256_file(manifest_path, manifest_info),
        "entry_count": manifest["summary"]["entry_count"],
        "regular_files": manifest["summary"]["regular_files"],
        "symlinks": manifest["summary"]["symlinks"],
        "regular_bytes": manifest["summary"]["regular_bytes"],
    }


PublishedFileToken = tuple[int, int]


def unlink_published_file(path: Path, token: PublishedFileToken | None) -> bool:
    """Remove a final name only while it still names this invocation's inode."""
    if token is None:
        return False
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if (info.st_dev, info.st_ino) != token:
        return False
    # Linux has no conditional unlink-by-inode operation.  The secure 0700
    # output parent excludes other users; a malicious same-UID rename exactly
    # between this lstat and unlink remains part of the documented same-UID
    # custody boundary.
    path.unlink()
    return True


def write_new_file(
    path: Path, payload: bytes, mode: int, epoch: int
) -> PublishedFileToken:
    require_new(path, "output file")
    if len(payload) > MAX_MANIFEST_BYTES:
        raise SnapshotError("manifest payload exceeds size limit")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    published_token: PublishedFileToken | None = None
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.utime(
            temporary,
            ns=(epoch * 1_000_000_000, epoch * 1_000_000_000),
            follow_symlinks=False,
        )
        metadata_fd = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(metadata_fd)
        finally:
            os.close(metadata_fd)
        temporary_info = temporary.lstat()
        rename_noreplace(temporary, path)
        published_token = (temporary_info.st_dev, temporary_info.st_ino)
        fsync_directory(path.parent)
        final_info = path.lstat()
        if (
            not stat.S_ISREG(final_info.st_mode)
            or path.is_symlink()
            or final_info.st_uid != os.getuid()
            or stat.S_IMODE(final_info.st_mode) != mode
            or final_info.st_nlink != 1
            or final_info.st_mtime_ns != epoch * 1_000_000_000
            or final_info.st_size != len(payload)
            or sha256_file(path, final_info) != hashlib.sha256(payload).hexdigest()
        ):
            raise SnapshotError("published manifest failed immutable-file postconditions")
        return published_token
    except Exception:
        if unlink_published_file(path, published_token):
            fsync_directory(path.parent)
        raise
    finally:
        temporary.unlink(missing_ok=True)


def make_tree_removable(root: Path) -> None:
    """Restore owner rwx on directories only so a failed unpublished tree can be removed."""
    if not root.exists() or root.is_symlink():
        return

    def recurse(directory: Path) -> None:
        try:
            with os.scandir(directory) as iterator:
                for child in iterator:
                    if child.is_dir(follow_symlinks=False):
                        recurse(Path(child.path))
        except FileNotFoundError:
            return
        try:
            os.chmod(directory, 0o700)
        except FileNotFoundError:
            return

    recurse(root)


def fsync_tree(root: Path) -> None:
    directories: list[Path] = [root]
    for _, path, info in walk_lstat(root):
        if stat.S_ISREG(info.st_mode):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        elif stat.S_ISDIR(info.st_mode):
            directories.append(path)
    for directory in reversed(directories):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def ensure_disjoint(source: Path, snapshot: Path, manifest_path: Path) -> None:
    if snapshot == manifest_path:
        raise SnapshotError("snapshot and manifest paths must be distinct")
    source_real = source.resolve(strict=True)
    parent_real = snapshot.parent.resolve(strict=True)
    if (
        source_real == parent_real
        or source_real in parent_real.parents
        or parent_real in source_real.parents
    ):
        raise SnapshotError("source and output parent must not be ancestors or descendants")


def recover_incomplete_snapshot(snapshot: Path, manifest_path: Path, epoch: int) -> None:
    snapshot_present = snapshot.exists() or snapshot.is_symlink()
    manifest_present = manifest_path.exists() or manifest_path.is_symlink()
    if manifest_present and not snapshot_present:
        raise SnapshotError("manifest exists without snapshot; refusing automatic recovery")
    if not snapshot_present:
        return
    if manifest_present:
        raise SnapshotError("complete snapshot already exists; refusing overwrite")
    # Recovery is explicit. Reclaim only a fully normalized, closed-world tree
    # at the exact requested path; any mismatch fails without deleting it.
    make_manifest(snapshot, epoch)
    make_tree_removable(snapshot)
    shutil.rmtree(snapshot)
    fsync_directory(snapshot.parent)


def create(
    source: Path,
    snapshot: Path,
    manifest_path: Path,
    epoch: int,
    recover_incomplete: bool = False,
) -> dict[str, Any]:
    if epoch <= 0:
        raise SnapshotError("SOURCE_DATE_EPOCH must be positive")
    if not source.is_absolute() or not snapshot.is_absolute() or not manifest_path.is_absolute():
        raise SnapshotError("source, snapshot, and manifest paths must be absolute")
    source_fd, source_info = open_secure_source_root(source)
    try:
        if snapshot.parent != manifest_path.parent:
            raise SnapshotError("snapshot and manifest must share one secure parent")
        require_secure_parent(snapshot.parent)
        ensure_disjoint(source, snapshot, manifest_path)
        if recover_incomplete:
            recover_incomplete_snapshot(snapshot, manifest_path, epoch)
        require_new(snapshot, "snapshot")
        require_new(manifest_path, "manifest")
        source_state_before = source_tree_state_from_fd(source_fd)
        temporary = Path(
            tempfile.mkdtemp(prefix=f".{snapshot.name}.", dir=snapshot.parent)
        )
        published = False
        manifest_token: PublishedFileToken | None = None
        try:
            copied_source_state = copy_source_tree(source_fd, temporary)
            if copied_source_state != source_state_before:
                raise SnapshotError("source toolchain changed while snapshotting")
            source_state_after = source_tree_state_from_fd(source_fd)
            if source_state_after != source_state_before:
                raise SnapshotError("source toolchain changed while snapshotting")
            revalidate_source_root_path(source, source_fd, source_info)
            normalize_snapshot(temporary, epoch)
            manifest = make_manifest(temporary, epoch)
            fsync_tree(temporary)
            rename_noreplace(temporary, snapshot)
            published = True
            fsync_directory(snapshot.parent)
            # The manifest is the commit marker and is published strictly last.
            manifest_token = write_new_file(
                manifest_path,
                json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n",
                0o444,
                epoch,
            )
            result = verify(snapshot, manifest_path)
            fsync_directory(snapshot.parent)
            return result
        except Exception:
            if published:
                make_tree_removable(snapshot)
                shutil.rmtree(snapshot)
                if snapshot.exists() or snapshot.is_symlink():
                    raise SnapshotError("failed snapshot cleanup left a final path")
                fsync_directory(snapshot.parent)
            unlink_published_file(manifest_path, manifest_token)
            fsync_directory(snapshot.parent)
            raise
        finally:
            if temporary.exists():
                make_tree_removable(temporary)
                shutil.rmtree(temporary)
                if temporary.exists() or temporary.is_symlink():
                    raise SnapshotError("failed staging cleanup left a path")
                fsync_directory(snapshot.parent)
    finally:
        os.close(source_fd)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    create_parser = subparsers.add_parser("create")
    create_parser.add_argument("--source", required=True, type=Path)
    create_parser.add_argument("--snapshot", required=True, type=Path)
    create_parser.add_argument("--manifest", required=True, type=Path)
    create_parser.add_argument("--source-date-epoch", required=True, type=int)
    create_parser.add_argument("--recover-incomplete", action="store_true")
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--snapshot", required=True, type=Path)
    verify_parser.add_argument("--manifest", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "create":
            result = create(
                args.source.absolute(),
                args.snapshot.absolute(),
                args.manifest.absolute(),
                args.source_date_epoch,
                args.recover_incomplete,
            )
        else:
            result = verify(args.snapshot.absolute(), args.manifest.absolute())
    except SnapshotError as exc:
        print(f"mobian-toolchain-snapshot: FAIL: {exc}", file=os.sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
