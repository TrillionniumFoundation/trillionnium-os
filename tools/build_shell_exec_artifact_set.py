#!/usr/bin/env python3
"""Build and bind the three static shell.exec.v1 product executables.

The build is rooted in one exact live-remeasured v2 source BOM, explicit
byte-measured Rust/Cargo inputs, and a literal offline environment.  Cargo's
target directory is private build scratch and is destroyed before publication.
The output directory is then published with Linux renameat2(RENAME_NOREPLACE)
and contains only the three product ELFs plus the canonical artifact-set
receipt consumed by Android's receipt stage.

This remains host build provenance.  It is not device-effect, AVB, OTA, or
release evidence.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import functools
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import secrets
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time
from typing import Mapping, NoReturn, Sequence


# Importing the mature custody/materialization helpers must not create an
# ignored tools/__pycache__ path before the first live graph remeasurement.
sys.dont_write_bytecode = True
TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import build_codex_only_raw_elf_set as raw_primitives  # noqa: E402
import build_p01_userdebug_agent_launchers as bom_primitives  # noqa: E402
import materialize_cross_repo_source_bom as tree_primitives  # noqa: E402
import materialize_userdebug_dogfood_bom as dogfood_primitives  # noqa: E402
import package_current_rootfs as filesystem_primitives  # noqa: E402


SCHEMA = "org.trillionnium.shell-exec-artifact-set.v1"
RECEIPT_NAME = "trillionnium-shell-exec-artifact-set-v1.json"
PACKAGE = "trillionnium-shell-exec"
DOGFOOD_WRAPPER_NAME = "2026-08-24-userdebug-dogfood-source-bom.json"
DOGFOOD_WRAPPER_PATH = (
    Path(__file__).resolve().parents[1] / "docs/evidence" / DOGFOOD_WRAPPER_NAME
)
DOGFOOD_SCHEMA = dogfood_primitives.DOGFOOD_SCHEMA
DOGFOOD_DECISION = dogfood_primitives.DOGFOOD_DECISION
DOGFOOD_RECEIPT_ID_SCOPE = dogfood_primitives.RECEIPT_ID_SCOPE
DOGFOOD_SOURCE_SCHEMA = dogfood_primitives.SOURCE_BOM_SCHEMA
DOGFOOD_SOURCE_DECISION = dogfood_primitives.SOURCE_BOM_HOLD
DOGFOOD_ALLOWED_BLOCKER_KINDS = dogfood_primitives.ALLOWED_FAILURES
TARGET = "aarch64-unknown-linux-musl"
HOST_TARGET = "x86_64-unknown-linux-gnu"
PROFILE = "release"
FEATURES = ("android-product",)
RUSTC_LINKER_FLAVOR = "ld.lld"
RUST_VERSION = "1.95.0"
ZIG_VERSION = "0.14.1"
SOURCE_DATE_EPOCH = "1785110400"
MAX_SOURCE_BOM_BYTES = 8 * 1024 * 1024
MAX_RESOLVED_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_ELF_BYTES = 128 * 1024 * 1024
MAX_BUILD_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_PROBE_OUTPUT_BYTES = 256 * 1024
MAX_HOST_RUNTIME_BYTES = 16 * 1024 * 1024
MAX_TOOLCHAIN_ENTRIES = 250_000
MAX_TOOLCHAIN_BYTES = 4 * 1024 * 1024 * 1024
MAX_CARGO_HOME_ENTRIES = 250_000
MAX_CARGO_HOME_BYTES = 2 * 1024 * 1024 * 1024
MAX_ZIG_TOOLCHAIN_ENTRIES = 250_000
MAX_ZIG_TOOLCHAIN_BYTES = 4 * 1024 * 1024 * 1024
MAX_TARGET_TREE_ENTRIES = 1_000_000
MAX_PROGRAM_HEADERS = 128
# Exclusive ceiling for every admitted AArch64 PT_LOAD.  Android product ELFs
# are expected in the lower 48-bit user range even on hosts that can emulate a
# wider VA configuration; accepting a wider image would not prove it loadable
# on the product kernel.
AARCH64_PRODUCT_USER_VA_LIMIT = 1 << 48
PROBE_TIMEOUT_SECONDS = 15
PROBE_FD_MIN = 200
MIN_LANDLOCK_ABI = 6
MAX_LANDLOCK_ABI = 8
FORBIDDEN_MARKERS = (b"openclaw", b"open_claw", b"5902")
ARTIFACTS = (
    (
        "tool",
        "trillionnium-agent-shell",
        "/system_ext/bin/trillionnium-agent-shell",
    ),
    (
        "broker",
        "trillionnium-shell-exec-broker-userdebug",
        "/system_ext/bin/trillionnium-shell-exec-broker-userdebug",
    ),
    (
        "worker",
        "trillionnium-shell-exec-worker-userdebug",
        "/system_ext/bin/trillionnium-shell-exec-worker-userdebug",
    ),
)
PROBE_SPECS = {
    "tool": (
        (),
        2,
        b"invalid request: usage: trillionnium-agent-shell mcp\n",
    ),
    "broker": (
        ("--trillionnium-invalid-artifact-load-probe",),
        2,
        b"shell exec broker rejected invalid arguments; "
        b"only --cleanup-stale-only is accepted\n",
    ),
    "worker": (
        (),
        1,
        b"shell exec worker failed closed: worker I/O failed: "
        b"Bad file descriptor (os error 9)\n",
    ),
}
HOST_RUNTIME_INPUTS = (
    ("host_dynamic_loader", "host dynamic loader", ("ld-linux-x86-64.so.2",)),
    ("host_libc", "host libc", ("libc.so.6",)),
    ("host_libgcc_s", "host libgcc_s", ("libgcc_s.so.1",)),
    ("host_libm", "host libm", ("libm.so.6",)),
    ("host_libdl", "host libdl", ("libdl.so.2",)),
    ("host_libpthread", "host libpthread", ("libpthread.so.0",)),
    ("host_librt", "host librt", ("librt.so.1",)),
    ("host_libz", "host libz", ("libz.so.1", "libz.so.1.3")),
)
PUBLISHED_NAMES = frozenset(binary for _, binary, _ in ARTIFACTS) | {
    RECEIPT_NAME
}

# ELF constants used by the deliberately small, bounds-checked parser.
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
PF_X = 1
PF_W = 2
PF_R = 4
DT_NULL = 0
DT_NEEDED = 1

# Linux seccomp filter constants.  The Cargo process and every descendant are
# denied all addressable socket creation/use plus session escape. The sole
# AF_UNIX socketpair exception and its data syscalls are needed by Rust's local
# exec-error channel. Cargo deliberately puts compiler children into their own
# process groups, so supervision covers the complete private session rather
# than forbidding setpgid(2). No network descriptor is inherited, so this
# closes build-script egress rather than only asking Cargo's resolver offline.
BPF_LD = 0x00
BPF_W = 0x00
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_JSET = 0x40
BPF_K = 0x00
BPF_RET = 0x06
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000
PR_SET_PDEATHSIG = 1
PR_SET_DUMPABLE = 4
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
RENAME_NOREPLACE = 1
SECCOMP_DATA_NR_OFFSET = 0
SECCOMP_DATA_ARCH_OFFSET = 4
SECCOMP_DATA_ARGS_OFFSET = 16
X32_SYSCALL_BIT = 0x40000000
AF_UNIX = 1
BUILD_INPUT_ROLES = (
    "rustc",
    "target_linker",
    "host_linker_wrapper",
    "zig",
    "zig_root",
    "cargo_home_input",
    "target",
    "cargo",
)

# Landlock ABI 5 is the first revision that can handle device ioctls. ABI 6
# adds the signal and abstract-UNIX scoping used here. Refuse older (or newer,
# unreviewed) kernels rather than silently leaving a right ambient.
LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
LANDLOCK_CREATE_RULESET_ERRATA = 1 << 1
LANDLOCK_RULE_PATH_BENEATH = 1
LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
LANDLOCK_ACCESS_FS_REFER = 1 << 13
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14
LANDLOCK_ACCESS_FS_IOCTL_DEV = 1 << 15
LANDLOCK_ACCESS_NET_BIND_TCP = 1 << 0
LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 1
LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET = 1 << 0
LANDLOCK_SCOPE_SIGNAL = 1 << 1
LANDLOCK_HANDLED_ACCESS_FS = (1 << 16) - 1
LANDLOCK_HANDLED_ACCESS_NET = (
    LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
)
LANDLOCK_SCOPED = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL
LANDLOCK_READ_ONLY = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
LANDLOCK_READ_EXECUTE = LANDLOCK_READ_ONLY | LANDLOCK_ACCESS_FS_EXECUTE
LANDLOCK_RUNTIME_LIBRARY = LANDLOCK_ACCESS_FS_READ_FILE
LANDLOCK_EXECUTABLE = LANDLOCK_RUNTIME_LIBRARY | LANDLOCK_ACCESS_FS_EXECUTE
LANDLOCK_RUNTIME_LOADER = LANDLOCK_EXECUTABLE
LANDLOCK_DEVICE = (
    LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_IOCTL_DEV
)
LANDLOCK_TARGET = LANDLOCK_HANDLED_ACCESS_FS & ~(
    LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_IOCTL_DEV
)
LANDLOCK_ACCESS_NAMES = (
    (LANDLOCK_ACCESS_FS_EXECUTE, "execute"),
    (LANDLOCK_ACCESS_FS_WRITE_FILE, "write_file"),
    (LANDLOCK_ACCESS_FS_READ_FILE, "read_file"),
    (LANDLOCK_ACCESS_FS_READ_DIR, "read_dir"),
    (LANDLOCK_ACCESS_FS_REMOVE_DIR, "remove_dir"),
    (LANDLOCK_ACCESS_FS_REMOVE_FILE, "remove_file"),
    (LANDLOCK_ACCESS_FS_MAKE_CHAR, "make_char"),
    (LANDLOCK_ACCESS_FS_MAKE_DIR, "make_dir"),
    (LANDLOCK_ACCESS_FS_MAKE_REG, "make_reg"),
    (LANDLOCK_ACCESS_FS_MAKE_SOCK, "make_sock"),
    (LANDLOCK_ACCESS_FS_MAKE_FIFO, "make_fifo"),
    (LANDLOCK_ACCESS_FS_MAKE_BLOCK, "make_block"),
    (LANDLOCK_ACCESS_FS_MAKE_SYM, "make_sym"),
    (LANDLOCK_ACCESS_FS_REFER, "refer"),
    (LANDLOCK_ACCESS_FS_TRUNCATE, "truncate"),
    (LANDLOCK_ACCESS_FS_IOCTL_DEV, "ioctl_dev"),
)
LANDLOCK_SYSCALLS = {
    "x86_64": (444, 445, 446),
    "aarch64": (444, 445, 446),
}

AUDIT_ARCH = {
    "x86_64": 0xC000003E,
    "aarch64": 0xC00000B7,
}

DENIED_SYSCALLS = {
    "x86_64": (
        41,  # socket
        42,  # connect
        43,  # accept
        48,  # shutdown
        49,  # bind
        50,  # listen
        51,  # getsockname
        52,  # getpeername
        54,  # setsockopt
        55,  # getsockopt
        101,  # ptrace
        112,  # setsid
        288,  # accept4
        299,  # recvmmsg
        307,  # sendmmsg
        310,  # process_vm_readv
        311,  # process_vm_writev
        312,  # kcmp
        425,  # io_uring_setup
        438,  # pidfd_getfd
    ),
    "aarch64": (
        117,  # ptrace
        157,  # setsid
        198,  # socket
        200,  # bind
        201,  # listen
        202,  # accept
        203,  # connect
        204,  # getsockname
        205,  # getpeername
        208,  # setsockopt
        209,  # getsockopt
        210,  # shutdown
        242,  # accept4
        243,  # recvmmsg
        269,  # sendmmsg
        270,  # process_vm_readv
        271,  # process_vm_writev
        272,  # kcmp
        425,  # io_uring_setup
        438,  # pidfd_getfd
    ),
}

SOCKETPAIR_SYSCALL = {
    "x86_64": 53,
    "aarch64": 199,
}


class BuildError(RuntimeError):
    pass


def deny(message: str) -> NoReturn:
    raise BuildError(message)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def compact_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def pretty_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def absolute_canonical(path: Path, label: str) -> Path:
    if not path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts[1:]):
        deny(f"{label} must use canonical absolute syntax")
    return path


def require_real_directory(path: Path, label: str) -> Path:
    absolute = absolute_canonical(path, label)
    try:
        resolved = absolute.resolve(strict=True)
    except OSError as error:
        raise BuildError(f"{label} is unavailable") from error
    if resolved != absolute or not absolute.is_dir():
        deny(f"{label} must contain no symlinked pathname component")
    return absolute


def file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def read_descriptor(descriptor: int, expected_size: int, label: str) -> bytes:
    result: list[bytes] = []
    offset = 0
    while offset <= expected_size:
        block = os.pread(
            descriptor,
            min(1024 * 1024, expected_size + 1 - offset),
            offset,
        )
        if not block:
            break
        result.append(block)
        offset += len(block)
    raw = b"".join(result)
    if len(raw) != expected_size:
        deny(f"{label} changed size while being read")
    return raw


class RetainedRegular:
    """A no-follow regular input and its complete parent-directory custody."""

    def __init__(
        self,
        path: Path,
        label: str,
        parent: filesystem_primitives.RetainedDirectoryChain,
        descriptor: int,
        initial: os.stat_result,
        raw: bytes,
    ) -> None:
        self.path = path
        self.label = label
        self.parent = parent
        self.descriptor = descriptor
        self.initial = initial
        self.raw = raw

    @classmethod
    def open(cls, path: Path, label: str, maximum: int) -> "RetainedRegular":
        absolute = absolute_canonical(path, label)
        try:
            parent = filesystem_primitives.RetainedDirectoryChain.open(
                absolute.parent, f"{label} parent"
            )
        except RuntimeError as error:
            raise BuildError(f"{label} parent custody failed") from error
        descriptor = -1
        try:
            lexical = os.stat(
                absolute.name,
                dir_fd=parent.directory_fd,
                follow_symlinks=False,
            )
            descriptor = os.open(
                absolute.name,
                os.O_RDONLY
                | os.O_CLOEXEC
                | os.O_NOFOLLOW
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=parent.directory_fd,
            )
            opened = os.fstat(descriptor)
            mode = stat.S_IMODE(opened.st_mode)
            if (
                file_identity(opened) != file_identity(lexical)
                or not stat.S_ISREG(opened.st_mode)
                or not 0 < opened.st_size <= maximum
                or opened.st_nlink != 1
                or opened.st_uid not in {0, os.geteuid()}
                or mode & 0o022
                or not mode & 0o400
            ):
                deny(f"{label} is not one bounded immutable regular file")
            raw = read_descriptor(descriptor, opened.st_size, label)
            if file_identity(os.fstat(descriptor)) != file_identity(opened):
                deny(f"{label} changed while initially retained")
            retained = cls(absolute, label, parent, descriptor, opened, raw)
            retained.assert_stable()
            return retained
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            parent.close()
            raise

    def assert_stable(self) -> None:
        self.parent.assert_stable()
        held_before = os.fstat(self.descriptor)
        raw = read_descriptor(self.descriptor, self.initial.st_size, self.label)
        held_after = os.fstat(self.descriptor)
        lexical = os.stat(
            self.path.name,
            dir_fd=self.parent.directory_fd,
            follow_symlinks=False,
        )
        expected = file_identity(self.initial)
        if (
            file_identity(held_before) != expected
            or file_identity(held_after) != expected
            or file_identity(lexical) != expected
            or raw != self.raw
        ):
            deny(f"{self.label} descriptor, pathname, or bytes changed")

    def close(self) -> None:
        descriptor = self.descriptor
        self.descriptor = -1
        primary: BaseException | None = None
        try:
            if descriptor >= 0:
                os.close(descriptor)
        except BaseException as error:
            primary = error
        try:
            self.parent.close()
        except BaseException as error:
            if primary is None:
                primary = error
        if primary is not None:
            raise BuildError(f"could not close {self.label} custody") from primary


def special_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_rdev,
        metadata.st_nlink,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


class RetainedDevNull:
    """The one explicit host device path admitted to the build domain."""

    def __init__(
        self,
        path: Path,
        parent: filesystem_primitives.RetainedDirectoryChain,
        descriptor: int,
        initial: os.stat_result,
    ) -> None:
        self.path = path
        self.parent = parent
        self.descriptor = descriptor
        self.initial = initial

    @classmethod
    def open(cls, path: Path) -> "RetainedDevNull":
        absolute = absolute_canonical(path, "host /dev/null")
        if absolute != Path("/dev/null"):
            deny("host device input must be exactly /dev/null")
        try:
            parent = filesystem_primitives.RetainedDirectoryChain.open(
                absolute.parent, "host /dev/null parent"
            )
        except RuntimeError as error:
            raise BuildError("host /dev/null parent custody failed") from error
        descriptor = -1
        try:
            lexical = os.stat(
                absolute.name, dir_fd=parent.directory_fd, follow_symlinks=False
            )
            descriptor = os.open(
                absolute.name,
                os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent.directory_fd,
            )
            opened = os.fstat(descriptor)
            if (
                special_file_identity(opened) != special_file_identity(lexical)
                or not stat.S_ISCHR(opened.st_mode)
                or os.major(opened.st_rdev) != 1
                or os.minor(opened.st_rdev) != 3
                or opened.st_uid != 0
                or opened.st_gid != 0
                or stat.S_IMODE(opened.st_mode) != 0o666
            ):
                deny("host /dev/null identity is not the fixed null character device")
            retained = cls(absolute, parent, descriptor, opened)
            retained.assert_stable()
            return retained
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            parent.close()
            raise

    def assert_stable(self) -> None:
        self.parent.assert_stable()
        lexical = os.stat(
            self.path.name,
            dir_fd=self.parent.directory_fd,
            follow_symlinks=False,
        )
        if (
            special_file_identity(os.fstat(self.descriptor))
            != special_file_identity(self.initial)
            or special_file_identity(lexical) != special_file_identity(self.initial)
        ):
            deny("host /dev/null descriptor or pathname changed")

    def receipt_record(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "mode": f"{stat.S_IMODE(self.initial.st_mode):04o}",
            "uid": self.initial.st_uid,
            "gid": self.initial.st_gid,
            "major": os.major(self.initial.st_rdev),
            "minor": os.minor(self.initial.st_rdev),
        }

    def close(self) -> None:
        descriptor = self.descriptor
        self.descriptor = -1
        primary: BaseException | None = None
        try:
            if descriptor >= 0:
                os.close(descriptor)
        except BaseException as error:
            primary = error
        try:
            self.parent.close()
        except BaseException as error:
            if primary is None:
                primary = error
        if primary is not None:
            raise BuildError("could not close host /dev/null custody") from primary


def validate_host_runtime_elf(raw: bytes, label: str) -> None:
    """Admit one bounded x86-64 ET_DYN loader/shared-library input."""

    if len(raw) < 64 or raw[:7] != b"\x7fELF\x02\x01\x01":
        deny(f"{label} is not a little-endian ELF64 runtime object")
    (
        elf_type,
        machine,
        version,
        _entry,
        program_offset,
        _section_offset,
        flags,
        header_bytes,
        program_entry_bytes,
        program_count,
        _section_entry_bytes,
        _section_count,
        _section_names,
    ) = struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
    if (
        elf_type != 3
        or machine != 62
        or version != 1
        or flags != 0
        or header_bytes != 64
        or program_entry_bytes != 56
        or not 1 <= program_count <= MAX_PROGRAM_HEADERS
        or program_offset < header_bytes
        or program_offset > len(raw)
        or program_entry_bytes * program_count > len(raw) - program_offset
    ):
        deny(f"{label} is not one bounded x86-64 ET_DYN runtime object")
    executable_load = False
    for index in range(program_count):
        (
            segment_type,
            segment_flags,
            segment_offset,
            segment_address,
            _physical_address,
            file_bytes,
            memory_bytes,
            alignment,
        ) = struct.unpack_from(
            "<IIQQQQQQ", raw, program_offset + index * program_entry_bytes
        )
        if (
            segment_flags & ~0x7
            or file_bytes > memory_bytes
            or segment_address + memory_bytes >= 1 << 64
            or segment_offset > len(raw)
            or file_bytes > len(raw) - segment_offset
            or alignment not in {0, 1}
            and alignment & (alignment - 1)
        ):
            deny(f"{label} has a malformed runtime program header")
        if segment_type == PT_LOAD and file_bytes and segment_flags & PF_X:
            executable_load = True
    if not executable_load:
        deny(f"{label} lacks an executable runtime PT_LOAD")


def host_runtime_record(
    role: str, retained: RetainedRegular
) -> dict[str, object]:
    return {
        "role": role,
        "path": str(retained.path),
        "sha256": sha256(retained.raw),
        "size_bytes": len(retained.raw),
        "mode": f"{stat.S_IMODE(retained.initial.st_mode):04o}",
        "uid": retained.initial.st_uid,
        "gid": retained.initial.st_gid,
    }


def validate_source_bom(raw: bytes) -> dict[str, object]:
    """Use the mature closed-v2 validator, including its full graph contract."""

    try:
        binding = bom_primitives.validate_source_bom_bytes(raw)
    except RuntimeError as error:
        raise BuildError("source BOM is not the closed exact v2 graph") from error
    if binding.get("file_sha256") != sha256(raw):
        deny("source BOM helper returned an inconsistent file digest")
    return binding


def validate_userdebug_dogfood_source(
    source_raw: bytes,
    wrapper_raw: bytes,
    resolved_manifest_raw: bytes,
    *,
    wrapper_path: Path,
) -> dict[str, object]:
    """Admit the canonical, non-authorizing dirty userdebug wrapper.

    The shared materializer owns the source-BOM, manifest XML, project
    blocker, and posture contract.  Comparing its canonical output byte-for-
    byte also proves the wrapper self-hash and prevents a hand-written,
    self-consistent projection from silently dropping source records.
    """

    canonical_wrapper = absolute_canonical(DOGFOOD_WRAPPER_PATH, "dogfood wrapper")
    if wrapper_path != canonical_wrapper:
        deny("userdebug dogfood wrapper must be the canonical evidence file")
    try:
        expected = dogfood_primitives.materialize_raw(
            source_raw,
            resolved_manifest_raw,
            allow_dirty_userdebug_dogfood=True,
        )
    except dogfood_primitives.DogfoodBomError as error:
        raise BuildError("userdebug dogfood source inputs are invalid") from error
    expected_raw = dogfood_primitives.canonical_json_bytes(expected)
    if wrapper_raw != expected_raw:
        deny("userdebug dogfood wrapper is not canonical materializer output")

    source_descriptor = expected["source_bom"]
    source_set = expected["source_set"]
    manifest_descriptor = expected["resolved_manifest"]
    wrapper_receipt_id = expected["receipt_id"]
    if (
        type(source_descriptor) is not dict
        or type(source_set) is not dict
        or type(manifest_descriptor) is not dict
        or type(wrapper_receipt_id) is not str
        or type(source_descriptor.get("bytes")) is not int
        or type(source_descriptor.get("sha256")) is not str
        or type(source_descriptor.get("receipt_id")) is not str
        or type(source_set.get("sha256")) is not str
        or type(manifest_descriptor.get("bytes")) is not int
        or type(manifest_descriptor.get("sha256")) is not str
    ):
        deny("userdebug dogfood materializer returned an invalid binding")
    if (
        source_descriptor["bytes"] != len(source_raw)
        or source_descriptor["sha256"] != sha256(source_raw)
        or manifest_descriptor["bytes"] != len(resolved_manifest_raw)
        or manifest_descriptor["sha256"] != sha256(resolved_manifest_raw)
    ):
        deny("userdebug dogfood materializer descriptors do not bind input bytes")
    return {
        "file_sha256": source_descriptor["sha256"],
        "bytes": source_descriptor["bytes"],
        "receipt_id": source_descriptor["receipt_id"],
        "control_head": "dogfood-wrapper-bound",
        "source_set_sha256": source_set["sha256"],
        "resolved_manifest_sha256": manifest_descriptor["sha256"],
        "authority": "local_userdebug_dirty_dogfood_not_build_or_release_authority",
        "wrapper_sha256": sha256(wrapper_raw),
        "wrapper_receipt_id": wrapper_receipt_id,
    }


def validate_userdebug_dogfood_live(
    source_bom: "RetainedRegular",
    wrapper: "RetainedRegular",
    resolved_manifest: "RetainedRegular",
    binding: Mapping[str, object],
) -> dict[str, object]:
    """Check only retained custody and byte bindings around the build.

    The initial dogfood admission performs the structural/schema checks.  The
    retained descriptors then make a second full parse unnecessary (and very
    expensive on the external USB estate): ``assert_stable`` proves the held
    descriptor, pathname, parent chain, and bytes are unchanged, while these
    digest/length comparisons prove that the retained inputs still correspond
    to the original binding.
    """

    source_bom.assert_stable()
    wrapper.assert_stable()
    resolved_manifest.assert_stable()
    live_digests = {
        "file_sha256": sha256(source_bom.raw),
        "bytes": len(source_bom.raw),
        "wrapper_sha256": sha256(wrapper.raw),
        "resolved_manifest_sha256": sha256(resolved_manifest.raw),
    }
    for field, observed in live_digests.items():
        if binding.get(field) != observed:
            deny(f"userdebug dogfood live {field} binding changed")
    # The remaining binding fields are derived from the structurally admitted
    # bytes.  Returning a copy preserves the existing equality check in the
    # caller without reparsing a megabyte-scale wrapper twice per build.
    return dict(binding)


def measure_closed_tree(
    path: Path,
    label: str,
    *,
    entry_limit: int,
    byte_limit: int,
) -> dict[str, object]:
    absolute = absolute_canonical(path, label)
    relative = "/".join(absolute.parts[1:])
    if not relative:
        deny(f"{label} may not be the filesystem root")
    try:
        return tree_primitives.inspect_source_tree(
            Path("/"),
            {
                "id": label.replace(" ", "_"),
                "path": relative,
                "entry_limit": entry_limit,
                "byte_limit": byte_limit,
            },
        )
    except RuntimeError as error:
        raise BuildError(f"{label} is not a stable closed tree") from error


def require_same_tree(
    expected: Mapping[str, object], observed: Mapping[str, object], label: str
) -> None:
    if tree_primitives.canonical_json_bytes(expected) != tree_primitives.canonical_json_bytes(
        observed
    ):
        deny(f"{label} changed during the build")


def require_immutable_tree(inventory: Mapping[str, object], label: str) -> None:
    entries = inventory.get("entries")
    if not isinstance(entries, list):
        deny(f"{label} inventory has no closed entry list")
    for entry in entries:
        if not isinstance(entry, dict):
            deny(f"{label} inventory entry is malformed")
        if entry.get("type") == "symlink":
            continue
        mode = entry.get("mode")
        try:
            parsed = int(str(mode), 8)
        except ValueError:
            deny(f"{label} inventory mode is malformed")
        if parsed & 0o222:
            deny(f"{label} contains an owner-writable build input")


def require_empty_retained_directory(
    directory: filesystem_primitives.RetainedDirectoryChain, label: str
) -> None:
    directory.assert_stable()
    metadata = os.fstat(directory.directory_fd)
    if (
        metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or os.listdir(directory.directory_fd)
    ):
        deny(f"{label} must remain invoking-user-owned, controlled, and empty")
    directory.assert_stable()


def inspect_static_elf(
    raw: bytes,
    label: str,
    *,
    expected_machine: int,
    machine_name: str,
    reject_retired_markers: bool,
    user_address_limit: int | None = None,
) -> dict[str, object]:
    """Validate one structurally executable, static, hardened ELF64."""

    if len(raw) < 64 or raw[:4] != b"\x7fELF":
        deny(f"{label} is not an ELF file")
    if raw[4:7] != b"\x02\x01\x01":
        deny(f"{label} must be little-endian ELF64 version 1")
    if raw[7] not in {0, 3} or raw[8] != 0 or any(raw[9:16]):
        deny(f"{label} has an unsupported ELF identification ABI")
    (
        elf_type,
        machine,
        version,
        entry,
        program_offset,
        section_offset,
        flags,
        header_bytes,
        program_entry_bytes,
        program_count,
        section_entry_bytes,
        section_count,
        section_names,
    ) = struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
    if elf_type not in {2, 3} or machine != expected_machine or version != 1:
        deny(f"{label} must be a {machine_name} ET_EXEC/ET_DYN ELF")
    if flags != 0 or header_bytes != 64 or entry == 0:
        deny(f"{label} has an invalid {machine_name} ELF header or entry point")
    if not 1 <= program_count <= MAX_PROGRAM_HEADERS or program_entry_bytes != 56:
        deny(f"{label} has an unsupported or empty program-header table")
    table_bytes = program_entry_bytes * program_count
    if (
        program_offset < header_bytes
        or program_offset > len(raw)
        or table_bytes > len(raw) - program_offset
    ):
        deny(f"{label} has an out-of-bounds program-header table")
    if section_count == 0:
        if section_offset != 0 or section_entry_bytes != 0 or section_names != 0:
            deny(f"{label} uses unsupported extended/partial section metadata")
    elif (
        section_entry_bytes != 64
        or section_names >= section_count
        or section_offset < header_bytes
        or section_offset > len(raw)
        or section_entry_bytes * section_count > len(raw) - section_offset
    ):
        deny(f"{label} has an invalid section-header table")

    if reject_retired_markers:
        lowered = raw.lower()
        if any(marker in lowered for marker in FORBIDDEN_MARKERS):
            deny(f"{label} contains retired provider bytes")

    load_segments: list[tuple[int, int, int, int, int]] = []
    executable_loads: list[tuple[int, int]] = []
    dynamic_count = 0
    stack_count = 0
    for index in range(program_count):
        offset = program_offset + index * program_entry_bytes
        (
            segment_type,
            segment_flags,
            segment_offset,
            segment_address,
            physical_address,
            file_bytes,
            memory_bytes,
            alignment,
        ) = struct.unpack_from("<IIQQQQQQ", raw, offset)
        if segment_flags & ~0x7:
            deny(f"{label} program header {index} has unknown permission flags")
        if file_bytes > memory_bytes:
            deny(f"{label} program header {index} has p_filesz greater than p_memsz")
        # Linux performs these range calculations in an unsigned address
        # type.  An exclusive end exactly equal to 2^64 therefore wraps to
        # zero just as surely as a mathematically larger end does.
        if segment_address + memory_bytes >= 1 << 64:
            deny(f"{label} program header {index} address range wraps uint64")
        if segment_offset > len(raw) or file_bytes > len(raw) - segment_offset:
            deny(f"{label} program header {index} reaches outside the file")
        if alignment not in {0, 1}:
            if alignment & (alignment - 1):
                deny(f"{label} program header {index} has non-power-of-two alignment")
            if segment_offset % alignment != segment_address % alignment:
                deny(f"{label} program header {index} has incongruent alignment")
        if segment_type == PT_INTERP:
            deny(f"{label} contains PT_INTERP")
        if segment_type == PT_LOAD:
            if memory_bytes == 0 or file_bytes == 0:
                deny(f"{label} contains an empty PT_LOAD")
            # Linux rejects a load segment whose file offset and virtual
            # address disagree within a base page.  p_align=0/1 is legal in
            # the generic ELF format, but accepting it here previously let a
            # structurally plausible image pass even though the target kernel
            # could not mmap it.  Product loads must state at least base-page
            # alignment and satisfy both the declared and kernel page
            # congruence constraints.
            if alignment < 0x1000:
                deny(f"{label} PT_LOAD alignment is smaller than one base page")
            if user_address_limit is not None and (
                segment_address >= user_address_limit
                or memory_bytes > user_address_limit - segment_address
            ):
                deny(
                    f"{label} PT_LOAD exceeds the conservative {machine_name} "
                    "product user-address limit"
                )
            if not segment_flags & PF_R:
                deny(f"{label} contains a non-readable PT_LOAD")
            if segment_flags & PF_W and segment_flags & PF_X:
                deny(f"{label} contains a writable-executable PT_LOAD")
            load_segments.append(
                (
                    segment_offset,
                    segment_address,
                    file_bytes,
                    memory_bytes,
                    segment_flags,
                )
            )
            if segment_flags & PF_X:
                executable_loads.append(
                    (segment_address, segment_address + file_bytes)
                )
        elif segment_type == PT_DYNAMIC:
            dynamic_count += 1
            if dynamic_count > 1 or file_bytes == 0 or file_bytes % 16:
                deny(f"{label} has an invalid PT_DYNAMIC segment")
            terminated = False
            for dynamic_offset in range(
                segment_offset, segment_offset + file_bytes, 16
            ):
                tag = struct.unpack_from("<q", raw, dynamic_offset)[0]
                if tag == DT_NULL:
                    terminated = True
                    break
                if tag == DT_NEEDED:
                    deny(f"{label} contains DT_NEEDED")
            if not terminated:
                deny(f"{label} PT_DYNAMIC is not DT_NULL terminated")
        elif segment_type == PT_GNU_STACK:
            stack_count += 1
            if (
                stack_count > 1
                or segment_flags != PF_W | PF_R
                or segment_offset != 0
                or segment_address != 0
                or physical_address != 0
                or file_bytes != 0
            ):
                deny(f"{label} has an executable or malformed PT_GNU_STACK")

    if not load_segments or not executable_loads:
        deny(f"{label} lacks an executable PT_LOAD")
    if not any(start <= entry < end for start, end in executable_loads):
        deny(f"{label} entry point is outside every executable PT_LOAD")
    if stack_count != 1:
        deny(f"{label} must carry exactly one non-executable PT_GNU_STACK")
    if dynamic_count:
        # The dynamic table of a static PIE must itself be mapped from the file.
        dynamic_header = next(
            struct.unpack_from(
                "<IIQQQQQQ", raw, program_offset + index * program_entry_bytes
            )
            for index in range(program_count)
            if struct.unpack_from(
                "<I", raw, program_offset + index * program_entry_bytes
            )[0]
            == PT_DYNAMIC
        )
        dynamic_offset = dynamic_header[2]
        dynamic_address = dynamic_header[3]
        dynamic_bytes = dynamic_header[5]
        if not any(
            load_address <= dynamic_address
            and dynamic_address + dynamic_bytes <= load_address + load_file_bytes
            and load_offset <= dynamic_offset
            and dynamic_offset + dynamic_bytes <= load_offset + load_file_bytes
            and dynamic_address - load_address == dynamic_offset - load_offset
            for (
                load_offset,
                load_address,
                load_file_bytes,
                _load_memory_bytes,
                _segment_flags,
            ) in load_segments
        ):
            deny(f"{label} PT_DYNAMIC is not file-backed by a matching PT_LOAD")
    return {
        "elf_machine": machine_name,
        "elf_type": {2: "ET_EXEC", 3: "ET_DYN"}[elf_type],
        "pt_interp": None,
        "dt_needed": [],
    }


def inspect_static_aarch64_elf(raw: bytes, label: str) -> dict[str, object]:
    """Validate one static hardened AArch64 product ELF64."""

    return inspect_static_elf(
        raw,
        label,
        expected_machine=183,
        machine_name="AArch64",
        reject_retired_markers=True,
        user_address_limit=AARCH64_PRODUCT_USER_VA_LIMIT,
    )


def inspect_static_host_tool(raw: bytes, label: str) -> dict[str, object]:
    """Validate one static hardened x86-64 host-closure ELF64."""

    return inspect_static_elf(
        raw,
        label,
        expected_machine=62,
        machine_name="x86-64",
        reject_retired_markers=False,
    )


class LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
        ("scoped", ctypes.c_uint64),
    ]


class LandlockPathBeneathAttr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


def landlock_syscalls() -> tuple[int, int, int]:
    try:
        return LANDLOCK_SYSCALLS[platform.machine()]
    except KeyError as error:
        raise BuildError("host architecture has no reviewed Landlock syscalls") from error


def landlock_kernel_identity() -> tuple[int, int]:
    create_ruleset, _add_rule, _restrict_self = landlock_syscalls()
    libc = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    abi = libc.syscall(
        create_ruleset,
        ctypes.c_void_p(),
        0,
        LANDLOCK_CREATE_RULESET_VERSION,
    )
    if abi < MIN_LANDLOCK_ABI or abi > MAX_LANDLOCK_ABI:
        error = ctypes.get_errno()
        raise BuildError(
            f"host Landlock ABI {abi} is outside reviewed range "
            f"{MIN_LANDLOCK_ABI}..{MAX_LANDLOCK_ABI}; "
            f"errno={error}"
        )
    ctypes.set_errno(0)
    errata = libc.syscall(
        create_ruleset,
        ctypes.c_void_p(),
        0,
        LANDLOCK_CREATE_RULESET_ERRATA,
    )
    if errata < 0:
        raise BuildError(
            f"host Landlock errata query failed with errno {ctypes.get_errno()}"
        )
    return int(abi), int(errata)


def landlock_access_names(access: int) -> list[str]:
    if access <= 0 or access & ~LANDLOCK_HANDLED_ACCESS_FS:
        deny("Landlock rule contains an unknown or empty access mask")
    return [name for bit, name in LANDLOCK_ACCESS_NAMES if access & bit]


class RetainedLandlockRuleset:
    """One closed filesystem policy retained for a single Cargo invocation."""

    def __init__(
        self,
        descriptor: int,
        initial: os.stat_result,
        abi: int,
        errata: int,
        rules: list[dict[str, object]],
    ) -> None:
        self.descriptor = descriptor
        self.initial = initial
        self.abi = abi
        self.errata = errata
        self.rules = rules

    @classmethod
    def create(
        cls, rules: Sequence[tuple[str, int, int, str]]
    ) -> "RetainedLandlockRuleset":
        abi, errata = landlock_kernel_identity()
        create_ruleset, add_rule, _restrict_self = landlock_syscalls()
        libc = ctypes.CDLL(None, use_errno=True)
        attributes = LandlockRulesetAttr(
            LANDLOCK_HANDLED_ACCESS_FS,
            LANDLOCK_HANDLED_ACCESS_NET,
            LANDLOCK_SCOPED,
        )
        ctypes.set_errno(0)
        descriptor = libc.syscall(
            create_ruleset,
            ctypes.byref(attributes),
            ctypes.sizeof(attributes),
            0,
        )
        if descriptor < 0:
            raise BuildError(
                f"could not create the closed Landlock ruleset; "
                f"errno={ctypes.get_errno()}"
            )
        records: list[dict[str, object]] = []
        seen: set[str] = set()
        try:
            fcntl.fcntl(descriptor, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
            for role, parent_fd, allowed_access, kind in rules:
                if (
                    not role
                    or role in seen
                    or kind not in {"directory", "file"}
                    or parent_fd < 0
                ):
                    deny("Landlock rule identity is malformed or duplicated")
                names = landlock_access_names(allowed_access)
                if kind == "file" and allowed_access & ~(
                    LANDLOCK_ACCESS_FS_EXECUTE
                    | LANDLOCK_ACCESS_FS_WRITE_FILE
                    | LANDLOCK_ACCESS_FS_READ_FILE
                    | LANDLOCK_ACCESS_FS_TRUNCATE
                    | LANDLOCK_ACCESS_FS_IOCTL_DEV
                ):
                    deny(f"Landlock file rule {role} carries directory-only rights")
                rule = LandlockPathBeneathAttr(allowed_access, parent_fd)
                ctypes.set_errno(0)
                result = libc.syscall(
                    add_rule,
                    descriptor,
                    LANDLOCK_RULE_PATH_BENEATH,
                    ctypes.byref(rule),
                    0,
                )
                if result != 0:
                    raise BuildError(
                        f"could not add closed Landlock rule {role}; "
                        f"errno={ctypes.get_errno()}"
                    )
                records.append({"role": role, "kind": kind, "access": names})
                seen.add(role)
            if not records:
                deny("closed Landlock ruleset has no allow rules")
            initial = os.fstat(descriptor)
            retained = cls(descriptor, initial, abi, errata, records)
            retained.assert_stable()
            return retained
        except BaseException:
            os.close(descriptor)
            raise

    def assert_stable(self) -> None:
        if self.descriptor < 0:
            deny("closed Landlock ruleset is already closed")
        if file_identity(os.fstat(self.descriptor)) != file_identity(self.initial):
            deny("closed Landlock ruleset descriptor changed")

    def receipt_record(self) -> dict[str, object]:
        return {
            "schema": "org.trillionnium.shell-exec-landlock-policy.v1",
            "abi": self.abi,
            "errata": self.errata,
            "handled_access_fs": landlock_access_names(
                LANDLOCK_HANDLED_ACCESS_FS
            ),
            "handled_access_net": ["bind_tcp", "connect_tcp"],
            "scoped": ["abstract_unix_socket", "signal"],
            "rules": self.rules,
        }

    def close(self) -> None:
        if self.descriptor >= 0:
            descriptor = self.descriptor
            self.descriptor = -1
            os.close(descriptor)


def restrict_current_process_with_landlock(ruleset_fd: int) -> None:
    _create_ruleset, _add_rule, restrict_self = landlock_syscalls()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed before Landlock")
    ctypes.set_errno(0)
    if libc.syscall(restrict_self, ruleset_fd, 0) != 0:
        raise OSError(ctypes.get_errno(), "landlock_restrict_self failed")
    os.close(ruleset_fd)


class SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class SockFprog(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]


def install_no_egress_seccomp(*, allow_unix_socketpair: bool) -> None:
    """Install one no-new-privs filter with no addressable socket authority."""

    machine = platform.machine()
    denied = DENIED_SYSCALLS.get(machine)
    audit_arch = AUDIT_ARCH.get(machine)
    socketpair_syscall = SOCKETPAIR_SYSCALL.get(machine)
    if denied is None or audit_arch is None or socketpair_syscall is None:
        raise OSError(errno.ENOTSUP, f"unsupported seccomp host architecture: {machine}")
    instructions: list[SockFilter] = [
        SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, SECCOMP_DATA_ARCH_OFFSET),
        SockFilter(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, audit_arch),
        SockFilter(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, SECCOMP_DATA_NR_OFFSET),
    ]
    if machine == "x86_64":
        # A native x86-64 process can issue x32-numbered syscalls when the host
        # enables that ABI. Deny the complete alternate table so the socket
        # filter cannot be bypassed merely by setting __X32_SYSCALL_BIT.
        instructions.extend(
            (
                SockFilter(BPF_JMP | BPF_JSET | BPF_K, 0, 1, X32_SYSCALL_BIT),
                SockFilter(
                    BPF_RET | BPF_K,
                    0,
                    0,
                    SECCOMP_RET_ERRNO | errno.EPERM,
                ),
            )
        )
    if allow_unix_socketpair:
        # Rust's Unix process launcher uses an AF_UNIX socketpair as its
        # close-on-exec error channel. Permit only that local domain; every
        # addressable/network socket syscall remains denied below.
        instructions.extend(
            (
                SockFilter(BPF_JMP | BPF_JEQ | BPF_K, 0, 4, socketpair_syscall),
                SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, SECCOMP_DATA_ARGS_OFFSET),
                SockFilter(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AF_UNIX),
                SockFilter(
                    BPF_RET | BPF_K,
                    0,
                    0,
                    SECCOMP_RET_ERRNO | errno.EPERM,
                ),
                SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, SECCOMP_DATA_NR_OFFSET),
            )
        )
    else:
        denied = (*denied, socketpair_syscall)
    for syscall_number in sorted(set(denied)):
        instructions.append(
            SockFilter(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, syscall_number)
        )
        instructions.append(
            SockFilter(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | errno.EPERM)
        )
    instructions.append(SockFilter(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW))
    array_type = SockFilter * len(instructions)
    array = array_type(*instructions)
    program = SockFprog(len(instructions), array)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(program)) != 0:
        raise OSError(ctypes.get_errno(), "seccomp filter installation failed")


def install_child_sandbox(*, landlock_ruleset_fd: int | None = None) -> None:
    """Popen pre-exec hook: private umask, no core, no egress, no pg escape."""

    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_PDEATHSIG failed")
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_DUMPABLE failed")
    if landlock_ruleset_fd is not None:
        restrict_current_process_with_landlock(landlock_ruleset_fd)
    install_no_egress_seccomp(allow_unix_socketpair=True)


def revalidate_tools(tools: Sequence[raw_primitives.RetainedExecutable]) -> None:
    for tool in tools:
        raw_primitives.revalidate_retained_executable(tool)


def living_session_members(session_id: int) -> tuple[int, ...]:
    """Return non-zombie members of the private Linux process session."""

    if session_id <= 1:
        deny("supervised process session id is invalid")
    try:
        names = os.listdir("/proc")
    except OSError as error:
        raise BuildError("could not enumerate the supervised process session") from error
    members: list[int] = []
    for name in names:
        if not name.isascii() or not name.isdecimal():
            continue
        pid = int(name)
        try:
            with open(f"/proc/{pid}/stat", "rb", buffering=0) as descriptor:
                raw = descriptor.read(4097)
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        if len(raw) > 4096:
            deny("process stat record exceeds its supervision bound")
        closing = raw.rfind(b") ")
        if closing < 0:
            deny("process stat record is malformed")
        fields = raw[closing + 2 :].split()
        if len(fields) < 4 or len(fields[0]) != 1:
            deny("process stat record is incomplete")
        try:
            observed_session = int(fields[3])
        except ValueError:
            deny("process stat session id is malformed")
        if observed_session == session_id and fields[0] != b"Z":
            members.append(pid)
    return tuple(sorted(members))


def terminate_process_session(process: subprocess.Popen[bytes]) -> None:
    """Kill every process that cannot escape the Cargo leader's session."""

    deadline = time.monotonic() + 5
    while True:
        members = living_session_members(process.pid)
        if process.poll() is None and process.pid not in members:
            members = (*members, process.pid)
        for pid in members:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if process.poll() is None:
            try:
                process.wait(timeout=0.05)
            except subprocess.TimeoutExpired:
                pass
        if process.poll() is not None and not living_session_members(process.pid):
            return
        if time.monotonic() >= deadline:
            deny("could not terminate the complete supervised process session")
        time.sleep(0.01)


def run_retained(
    tool: raw_primitives.RetainedExecutable,
    arguments: Sequence[str],
    *,
    environment: Mapping[str, str],
    expected_environment: set[str],
    cwd: Path,
    inherited_tools: Sequence[raw_primitives.RetainedExecutable] = (),
    pass_fds: Sequence[int] = (),
    timeout: int,
    maximum_output: int,
    label: str,
    expected_status: int = 0,
    execution_descriptor: int | None = None,
    landlock_ruleset: RetainedLandlockRuleset | None = None,
) -> bytes:
    if set(environment) != expected_environment:
        deny(f"{label} environment is not the exact allowlisted closure")
    if type(expected_status) is not int or not 0 <= expected_status <= 255:
        deny(f"{label} expected exit status is invalid")
    if type(timeout) is not int or timeout <= 0:
        deny(f"{label} timeout is invalid")
    if type(maximum_output) is not int or maximum_output < 0:
        deny(f"{label} output bound is invalid")
    retained: list[raw_primitives.RetainedExecutable] = []
    seen: set[int] = set()
    for candidate in (tool, *inherited_tools):
        if candidate.descriptor not in seen:
            retained.append(candidate)
            seen.add(candidate.descriptor)
    revalidate_tools(retained)
    if landlock_ruleset is not None:
        landlock_ruleset.assert_stable()
    execution_identity: tuple[int, ...] | None = None
    if execution_descriptor is None:
        executable = tool.fd_path
        inherited_descriptors = [candidate.descriptor for candidate in retained]
    else:
        try:
            execution_identity = file_identity(os.fstat(execution_descriptor))
            retained_identity = file_identity(os.fstat(tool.descriptor))
        except OSError as error:
            raise BuildError(f"{label} retained execution duplicate disappeared") from error
        if execution_identity != retained_identity:
            deny(f"{label} execution duplicate does not bind the retained tool")
        executable = f"/proc/self/fd/{execution_descriptor}"
        # The original tool fd is deliberately not inherited in this mode.
        # This lets the QEMU load probe present no accidental guest fd 3-6
        # while still execing an exact duplicate of the retained QEMU inode.
        inherited_descriptors = [
            execution_descriptor,
            *(candidate.descriptor for candidate in retained if candidate is not tool),
        ]
    extra_descriptors = [*pass_fds]
    if landlock_ruleset is not None:
        extra_descriptors.append(landlock_ruleset.descriptor)
    descriptors = tuple(dict.fromkeys([*inherited_descriptors, *extra_descriptors]))
    preexec = (
        install_child_sandbox
        if landlock_ruleset is None
        else functools.partial(
            install_child_sandbox,
            landlock_ruleset_fd=landlock_ruleset.descriptor,
        )
    )
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            [str(tool.path), *arguments],
            executable=executable,
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            pass_fds=descriptors,
            start_new_session=True,
            preexec_fn=preexec,
        )
        if process.stdout is None:  # pragma: no cover - Popen invariant
            deny(f"{label} did not create its bounded output pipe")
        chunks: list[bytes] = []
        observed = 0
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise BuildError(f"{label} timed out")
                events = selector.select(min(remaining, 1.0))
                if not events:
                    if process.poll() is not None:
                        # The leader exited but a descendant retained stdout.
                        # That descendant is part of the build result and may
                        # not outlive the supervised process session.
                        terminate_process_session(process)
                        deny(f"{label} left a surviving descendant")
                    continue
                for key, _mask in events:
                    block = os.read(
                        key.fd,
                        min(1024 * 1024, maximum_output + 1 - observed),
                    )
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    chunks.append(block)
                    observed += len(block)
                    if observed > maximum_output:
                        terminate_process_session(process)
                        deny(f"{label} output exceeds its bound")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BuildError(f"{label} timed out")
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise BuildError(f"{label} timed out") from error
        output = b"".join(chunks)
        if process.returncode != expected_status:
            deny(
                f"{label} failed with status {process.returncode}; "
                f"expected_status={expected_status}; "
                f"captured_output_bytes={len(output)}; "
                f"captured_output_sha256={sha256(output)}"
            )
        if living_session_members(process.pid):
            terminate_process_session(process)
            deny(f"{label} left a surviving descendant")
    except OSError as error:
        if process is not None:
            terminate_process_session(process)
        raise BuildError(f"{label} could not execute in the closed sandbox") from error
    except BaseException:
        if process is not None:
            terminate_process_session(process)
        raise
    finally:
        try:
            if process is not None and process.stdout is not None:
                process.stdout.close()
        finally:
            if execution_descriptor is not None:
                try:
                    current_execution_identity = file_identity(
                        os.fstat(execution_descriptor)
                    )
                except OSError as error:
                    raise BuildError(
                        f"{label} retained execution duplicate disappeared"
                    ) from error
                if current_execution_identity != execution_identity:
                    deny(f"{label} retained execution duplicate changed")
            if landlock_ruleset is not None:
                landlock_ruleset.assert_stable()
            revalidate_tools(retained)
    return output


def create_sealed_probe_image(raw: bytes, label: str) -> int:
    """Copy one captured artifact into an immutable anonymous probe image."""

    if not 1 <= len(raw) <= MAX_ELF_BYTES:
        deny(f"{label} is not one bounded probe image")
    required = (
        getattr(os, "MFD_CLOEXEC", None),
        getattr(os, "MFD_ALLOW_SEALING", None),
        getattr(fcntl, "F_ADD_SEALS", None),
        getattr(fcntl, "F_GET_SEALS", None),
        getattr(fcntl, "F_SEAL_SEAL", None),
        getattr(fcntl, "F_SEAL_SHRINK", None),
        getattr(fcntl, "F_SEAL_GROW", None),
        getattr(fcntl, "F_SEAL_WRITE", None),
    )
    if not hasattr(os, "memfd_create") or any(item is None for item in required):
        deny("host lacks sealed memfd support for the AArch64 load/start probes")
    descriptor = -1
    try:
        descriptor = os.memfd_create(
            "trillionnium-aarch64-load-probe",
            flags=os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                deny(f"short write while staging {label}")
            view = view[written:]
        os.fchmod(descriptor, 0o500)
        os.fsync(descriptor)
        seals = (
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE
        )
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size != len(raw)
            or stat.S_IMODE(metadata.st_mode) != 0o500
            or fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) != seals
            or read_descriptor(descriptor, len(raw), label) != raw
        ):
            deny(f"{label} sealed probe image verification failed")
        return descriptor
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def duplicate_probe_descriptor(source: int, label: str) -> int:
    """Duplicate a probe-only fd above every fixed product worker fd."""

    try:
        duplicate = fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, PROBE_FD_MIN)
        if duplicate < PROBE_FD_MIN or file_identity(
            os.fstat(duplicate)
        ) != file_identity(os.fstat(source)):
            os.close(duplicate)
            deny(f"{label} high-fd duplicate is invalid")
        return duplicate
    except OSError as error:
        raise BuildError(f"could not duplicate {label} above fixed worker fds") from error


def probe_aarch64_artifact(
    qemu: raw_primitives.RetainedExecutable,
    raw: bytes,
    role: str,
    cwd: Path,
) -> dict[str, object]:
    """Really load and start one captured AArch64 ELF under retained QEMU."""

    try:
        artifact_arguments, expected_status, expected_output = PROBE_SPECS[role]
    except KeyError as error:
        raise BuildError(f"unknown AArch64 load/start probe role: {role}") from error
    image = create_sealed_probe_image(raw, f"built {role} ELF probe image")
    qemu_execution = -1
    image_execution = -1
    try:
        qemu_execution = duplicate_probe_descriptor(
            qemu.descriptor, "qemu-aarch64-static"
        )
        image_execution = duplicate_probe_descriptor(image, f"built {role} ELF")
        if qemu_execution == image_execution:
            deny(f"built {role} ELF probe fd allocation collided")
        environment = {"LANG": "C", "LC_ALL": "C", "PATH": "", "TZ": "UTC"}
        output = run_retained(
            qemu,
            (f"/proc/self/fd/{image_execution}", *artifact_arguments),
            environment=environment,
            expected_environment=set(environment),
            cwd=cwd,
            pass_fds=(image_execution,),
            timeout=PROBE_TIMEOUT_SECONDS,
            maximum_output=MAX_PROBE_OUTPUT_BYTES,
            label=f"qemu AArch64 {role} load/start probe",
            expected_status=expected_status,
            execution_descriptor=qemu_execution,
        )
        if output != expected_output:
            deny(
                f"qemu AArch64 {role} load/start probe emitted the wrong "
                f"bounded diagnostic; captured_output_bytes={len(output)}; "
                f"captured_output_sha256={sha256(output)}"
            )
        return {
            "role": role,
            "arguments": list(artifact_arguments),
            "expected_exit_status": expected_status,
            "captured_output_bytes": len(output),
            "captured_output_sha256": sha256(output),
            "expected_output_sha256": sha256(expected_output),
            "timeout_seconds": PROBE_TIMEOUT_SECONDS,
            "maximum_output_bytes": MAX_PROBE_OUTPUT_BYTES,
        }
    finally:
        for descriptor in (image_execution, qemu_execution, image):
            if descriptor >= 0:
                os.close(descriptor)


def version_line(
    tool: raw_primitives.RetainedExecutable,
    arguments: Sequence[str],
    cwd: Path,
    label: str,
    *,
    environment: Mapping[str, str] | None = None,
    inherited_tools: Sequence[raw_primitives.RetainedExecutable] = (),
    pass_fds: Sequence[int] = (),
) -> str:
    output = version_text(
        tool,
        arguments,
        cwd,
        label,
        environment=environment,
        inherited_tools=inherited_tools,
        pass_fds=pass_fds,
    )
    lines = output.splitlines()
    if not lines or not lines[0] or len(lines[0].encode()) > 96:
        deny(f"{label} emitted no bounded version line")
    return lines[0]


def version_text(
    tool: raw_primitives.RetainedExecutable,
    arguments: Sequence[str],
    cwd: Path,
    label: str,
    *,
    environment: Mapping[str, str] | None = None,
    inherited_tools: Sequence[raw_primitives.RetainedExecutable] = (),
    pass_fds: Sequence[int] = (),
) -> str:
    if environment is None:
        environment = {"LANG": "C", "LC_ALL": "C", "PATH": "", "TZ": "UTC"}
    output = run_retained(
        tool,
        arguments,
        environment=environment,
        expected_environment=set(environment),
        cwd=cwd,
        inherited_tools=inherited_tools,
        pass_fds=pass_fds,
        timeout=30,
        maximum_output=1024 * 1024,
        label=label,
    )
    try:
        result = output.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BuildError(f"{label} version output is not UTF-8") from error
    if not result or "\x00" in result:
        deny(f"{label} emitted invalid version text")
    return result


def tool_identity_string(
    version: str,
    tool: raw_primitives.RetainedExecutable,
    closure_label: str,
    closure_sha256: str,
    extra_label: str | None = None,
    extra_sha256: str | None = None,
) -> str:
    fields = [
        version,
        f"bin={sha256(tool.initial_bytes)}",
        f"{closure_label}={closure_sha256}",
    ]
    if extra_label is not None and extra_sha256 is not None:
        fields.append(f"{extra_label}={extra_sha256}")
    result = "|".join(fields)
    if len(result.encode()) > 256:
        deny(f"{tool.role} identity annotation exceeds Android's schema bound")
    return result


def ensure_no_cargo_config(workspace: Path, control_root: Path, cargo_home: Path) -> None:
    candidates = [cargo_home / "config", cargo_home / "config.toml"]
    try:
        workspace.relative_to(control_root)
    except ValueError:
        deny("workspace escaped the current control checkout")
    current = workspace
    while True:
        candidates.extend((current / ".cargo/config", current / ".cargo/config.toml"))
        if current.parent == current:
            break
        current = current.parent
    for candidate in candidates:
        try:
            os.stat(candidate, follow_symlinks=False)
        except FileNotFoundError:
            continue
        deny(f"ambient Cargo configuration is forbidden: {candidate}")


def retained_self_path(descriptor: int) -> str:
    """Name one explicitly inherited descriptor without an ambient pathname."""

    if type(descriptor) is not int or descriptor < 3:
        deny("retained build descriptor is invalid")
    return f"/proc/self/fd/{descriptor}"


def validate_build_role_descriptors(
    role_descriptors: Mapping[str, int],
) -> dict[str, int]:
    """Require one unique inherited descriptor for every compiler role."""

    if set(role_descriptors) != set(BUILD_INPUT_ROLES):
        deny("retained build role descriptor inventory is not exact")
    normalized = dict(role_descriptors)
    if any(type(value) is not int or value < 3 for value in normalized.values()):
        deny("retained build role descriptor is invalid")
    if len(set(normalized.values())) != len(normalized):
        deny("retained build role descriptors alias each other")
    return normalized


class RetainedBuildRoleDescriptors:
    """Independent read-only OFDs inherited by the Cargo process tree only."""

    DIRECTORY_ROLES = frozenset({"zig_root", "cargo_home_input", "target"})

    def __init__(
        self,
        descriptors: Mapping[str, int],
        identities: Mapping[str, tuple[int, ...]],
        status_flags: Mapping[str, int],
        descriptor_flags: Mapping[str, int],
    ) -> None:
        self.descriptors = dict(descriptors)
        self.identities = dict(identities)
        self.status_flags = dict(status_flags)
        self.descriptor_flags = dict(descriptor_flags)

    @classmethod
    def open(
        cls, source_descriptors: Mapping[str, int]
    ) -> "RetainedBuildRoleDescriptors":
        sources = validate_build_role_descriptors(source_descriptors)
        opened: dict[str, int] = {}
        identities: dict[str, tuple[int, ...]] = {}
        status_flags: dict[str, int] = {}
        descriptor_flags: dict[str, int] = {}
        try:
            for role in BUILD_INPUT_ROLES:
                source_metadata = os.fstat(sources[role])
                is_directory = role in cls.DIRECTORY_ROLES
                if is_directory != stat.S_ISDIR(source_metadata.st_mode):
                    deny(f"retained build role {role} has the wrong object type")
                if not is_directory and not stat.S_ISREG(source_metadata.st_mode):
                    deny(f"retained build role {role} is not a regular file")
                flags = os.O_RDONLY | os.O_CLOEXEC
                if is_directory:
                    flags |= os.O_DIRECTORY
                descriptor = os.open(retained_self_path(sources[role]), flags)
                opened[role] = descriptor
                opened_metadata = os.fstat(descriptor)
                identity_function = (
                    directory_identity if is_directory else file_identity
                )
                identity = identity_function(source_metadata)
                if identity_function(opened_metadata) != identity:
                    deny(f"retained build role {role} changed during reopen")
                identities[role] = identity
                status_flags[role] = fcntl.fcntl(descriptor, fcntl.F_GETFL)
                descriptor_flags[role] = fcntl.fcntl(descriptor, fcntl.F_GETFD)
                if status_flags[role] & os.O_ACCMODE != os.O_RDONLY:
                    deny(f"retained build role {role} is not read-only")
                if descriptor_flags[role] & fcntl.FD_CLOEXEC == 0:
                    deny(f"retained build role {role} is not close-on-exec")
            retained = cls(opened, identities, status_flags, descriptor_flags)
            retained.assert_stable()
            return retained
        except BaseException:
            for descriptor in opened.values():
                os.close(descriptor)
            raise

    def assert_stable(self) -> None:
        if set(self.descriptors) != set(BUILD_INPUT_ROLES):
            deny("retained build role descriptor set is closed or incomplete")
        for role, descriptor in self.descriptors.items():
            metadata = os.fstat(descriptor)
            identity_function = (
                directory_identity if role in self.DIRECTORY_ROLES else file_identity
            )
            if identity_function(metadata) != self.identities[role]:
                deny(f"retained build role {role} changed")
            if fcntl.fcntl(descriptor, fcntl.F_GETFL) != self.status_flags[role]:
                deny(f"retained build role {role} status flags changed")
            if fcntl.fcntl(descriptor, fcntl.F_GETFD) != self.descriptor_flags[role]:
                deny(f"retained build role {role} descriptor flags changed")

    def close(self) -> None:
        descriptors = self.descriptors
        self.descriptors = {}
        errors: list[OSError] = []
        for descriptor in descriptors.values():
            try:
                os.close(descriptor)
            except OSError as error:
                errors.append(error)
        if errors:
            raise BuildError("could not close every inherited build role") from errors[0]


def prepare_operational_cargo_home(
    target_fd: int,
    cargo_home_fd: int,
    inherited_cargo_home_fd: int,
) -> None:
    """Expose immutable dependency payloads under a mutable scratch Cargo home."""

    os.mkdir("cargo-home", 0o700, dir_fd=target_fd)
    operational_fd = os.open(
        "cargo-home",
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=target_fd,
    )
    linked: set[str] = set()
    try:
        for name in ("registry", "git"):
            try:
                metadata = os.stat(
                    name, dir_fd=cargo_home_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                continue
            mode = stat.S_IMODE(metadata.st_mode)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or mode & 0o022
                or mode & 0o500 != 0o500
            ):
                deny(f"Cargo home {name} payload root is not immutable/readable")
            target = f"{retained_self_path(inherited_cargo_home_fd)}/{name}"
            os.symlink(target, name, dir_fd=operational_fd)
            lexical = os.stat(name, dir_fd=operational_fd, follow_symlinks=False)
            if not stat.S_ISLNK(lexical.st_mode) or os.readlink(
                name, dir_fd=operational_fd
            ) != target:
                deny(f"operational Cargo home {name} link changed")
            linked.add(name)
        if "registry" not in linked:
            deny("Cargo home closure lacks its registry payload root")
        if set(os.listdir(operational_fd)) != linked:
            deny("operational Cargo home has an unexpected entry")
        os.fsync(operational_fd)
    finally:
        os.close(operational_fd)


def create_build_landlock_ruleset(
    *,
    workspace_fd: int,
    rust_root_fd: int,
    zig_root_fd: int,
    cargo_home_fd: int,
    target_fd: int,
    build_tools: Sequence[tuple[str, raw_primitives.RetainedExecutable]],
    runtime_inputs: Sequence[tuple[str, RetainedRegular]],
    dev_null: RetainedDevNull,
) -> RetainedLandlockRuleset:
    """Create the exact read-only-input/write-only-scratch Cargo domain."""

    rules: list[tuple[str, int, int, str]] = [
        ("workspace_source", workspace_fd, LANDLOCK_READ_ONLY, "directory"),
        # Compiler children reach the retained rustc/linker/wrapper/Zig inodes
        # through exact inherited /proc/self/fd paths. Landlock's
        # execute check is applied to the underlying file hierarchy, so the
        # two byte-inventoried toolchain roots must carry execute as well as
        # read.  This does not admit any ambient executable: both complete
        # trees are measured before/after the build and every directly selected
        # tool is separately retained and byte-revalidated.
        ("rust_toolchain", rust_root_fd, LANDLOCK_READ_EXECUTE, "directory"),
        ("zig_toolchain", zig_root_fd, LANDLOCK_READ_EXECUTE, "directory"),
        ("cargo_home_input", cargo_home_fd, LANDLOCK_READ_ONLY, "directory"),
    ]
    rules.extend(
        (role, retained.descriptor, LANDLOCK_EXECUTABLE, "file")
        for role, retained in build_tools
    )
    rules.extend(
        (
            role,
            retained.descriptor,
            (
                LANDLOCK_RUNTIME_LOADER
                if role == "host_dynamic_loader"
                else LANDLOCK_RUNTIME_LIBRARY
            ),
            "file",
        )
        for role, retained in runtime_inputs
    )
    rules.extend(
        (
            ("host_dev_null", dev_null.descriptor, LANDLOCK_DEVICE, "file"),
            ("target_scratch", target_fd, LANDLOCK_TARGET, "directory"),
        )
    )
    return RetainedLandlockRuleset.create(rules)


def build_environment(
    *,
    workspace: Path,
    android_root: Path,
    artifact_root: Path,
    resolved_manifest: Path,
    output_parent: Path,
    role_descriptors: Mapping[str, int],
    rust_toolchain_root: Path,
    zig_toolchain_root: Path,
) -> dict[str, str]:
    descriptors = validate_build_role_descriptors(role_descriptors)
    target_path = retained_self_path(descriptors["target"])
    cargo_home_path = retained_self_path(descriptors["cargo_home_input"])
    operational_cargo_home = f"{target_path}/cargo-home"
    zig_root_path = retained_self_path(descriptors["zig_root"])
    remaps = (
        (workspace, "/usr/src/trillionnium-os"),
        (Path(target_path), "/usr/src/trillionnium-target"),
        (rust_toolchain_root, "/usr/src/trillionnium-rust-toolchain"),
        (Path(cargo_home_path), "/usr/src/trillionnium-cargo-home-input"),
        (Path(operational_cargo_home), "/usr/src/trillionnium-cargo-home"),
        (zig_toolchain_root, "/usr/src/trillionnium-zig-toolchain"),
        (Path(zig_root_path), "/usr/src/trillionnium-zig-toolchain"),
        (android_root, "/usr/src/trillionnium-android"),
        (artifact_root, "/usr/src/trillionnium-empty-artifacts"),
        (resolved_manifest.parent, "/usr/src/trillionnium-manifest-parent"),
        (output_parent, "/usr/src/trillionnium-output-parent"),
    )
    rust_flags = [
        "-C",
        "debuginfo=0",
        "-C",
        "strip=symbols",
        "-C",
        "codegen-units=1",
        "-C",
        f"linker={retained_self_path(descriptors['target_linker'])}",
        "-C",
        # Rust 1.95 still exposes the expanded `gnu-lld` spelling only behind
        # `-Z unstable-options`.  `ld.lld` is the stable direct-linker spelling
        # for the retained rust-lld binary and keeps the build on stable Rust.
        f"linker-flavor={RUSTC_LINKER_FLAVOR}",
        "-C",
        "link-arg=--build-id=sha1",
    ]
    for source, replacement in remaps:
        rust_flags.extend(("--remap-path-prefix", f"{source}={replacement}"))
    return {
        "CARGO_BUILD_JOBS": "1",
        "CARGO_CACHE_RUSTC_INFO": "0",
        "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(rust_flags),
        "CARGO_HOME": operational_cargo_home,
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": retained_self_path(
            descriptors["host_linker_wrapper"]
        ),
        "CARGO_TARGET_DIR": target_path,
        "HOME": f"{target_path}/home",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "",
        "RUSTC": retained_self_path(descriptors["rustc"]),
        "RUST_BACKTRACE": "0",
        "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
        "TMPDIR": f"{target_path}/tmp",
        "TRILLIONNIUM_ZIG_REAL": retained_self_path(descriptors["zig"]),
        "TZ": "UTC",
        "ZIG_GLOBAL_CACHE_DIR": f"{target_path}/zig-global-cache",
        "ZIG_LIB_DIR": f"{zig_root_path}/lib",
        "ZIG_LOCAL_CACHE_DIR": f"{target_path}/zig-local-cache",
    }


def receipt_environment(
    environment: Mapping[str, str],
    *,
    role_descriptors: Mapping[str, int],
) -> dict[str, str]:
    """Remove runtime fd allocation while binding every retained role."""

    descriptors = validate_build_role_descriptors(role_descriptors)
    replacements = {
        descriptors["cargo_home_input"]: "@CARGO_HOME_INPUT@",
        descriptors["target"]: "@TARGET_SCRATCH@",
        descriptors["zig_root"]: "@ZIG_ROOT@",
        descriptors["rustc"]: "@RUSTC@",
        descriptors["target_linker"]: "@TARGET_LINKER@",
        descriptors["host_linker_wrapper"]: "@HOST_LINKER_WRAPPER@",
        descriptors["zig"]: "@ZIG_DRIVER@",
        descriptors["cargo"]: "@CARGO@",
    }
    descriptor_pattern = re.compile(r"/proc/self/fd/([0-9]+)")

    def replace_descriptor(match: re.Match[str]) -> str:
        descriptor = int(match.group(1))
        try:
            return replacements[descriptor]
        except KeyError as error:
            raise BuildError(
                "receipt environment contains an unbound inherited descriptor"
            ) from error

    projected: dict[str, str] = {}
    for name, value in environment.items():
        canonical = descriptor_pattern.sub(replace_descriptor, value)
        if "/proc/self/fd/" in canonical:
            deny(f"receipt environment retains an unbound descriptor in {name}")
        projected[name] = canonical
    return projected


class RetainedScratchDirectory:
    def __init__(
        self,
        parent: filesystem_primitives.RetainedDirectoryChain,
        name: str,
        descriptor: int,
        initial: os.stat_result,
    ) -> None:
        self.parent = parent
        self.name = name
        self.descriptor = descriptor
        self.initial = initial
        self.published_name: str | None = None

    def assert_stable(self) -> None:
        self.parent.assert_stable()
        held = os.fstat(self.descriptor)
        name = self.published_name or self.name
        lexical = os.stat(
            name,
            dir_fd=self.parent.directory_fd,
            follow_symlinks=False,
        )
        expected = directory_identity(self.initial)
        if (
            not stat.S_ISDIR(held.st_mode)
            or directory_identity(held) != expected
            or directory_identity(lexical) != expected
        ):
            deny(f"retained scratch directory changed: {name}")

    def close(self) -> None:
        if self.descriptor >= 0:
            descriptor = self.descriptor
            self.descriptor = -1
            os.close(descriptor)


def create_scratch_directory(
    parent: filesystem_primitives.RetainedDirectoryChain, prefix: str
) -> RetainedScratchDirectory:
    for _attempt in range(128):
        name = prefix + secrets.token_hex(16)
        try:
            os.mkdir(name, 0o700, dir_fd=parent.directory_fd)
        except FileExistsError:
            continue
        descriptor = -1
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent.directory_fd,
            )
            metadata = os.fstat(descriptor)
            lexical = os.stat(
                name, dir_fd=parent.directory_fd, follow_symlinks=False
            )
            if (
                directory_identity(metadata) != directory_identity(lexical)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                deny("new scratch directory custody is invalid")
            result = RetainedScratchDirectory(parent, name, descriptor, metadata)
            result.assert_stable()
            return result
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.rmdir(name, dir_fd=parent.directory_fd)
            except OSError:
                pass
            raise
    deny("could not allocate a unique private scratch directory")


def require_output_absent(
    parent: filesystem_primitives.RetainedDirectoryChain, name: str
) -> None:
    parent.assert_stable()
    try:
        os.stat(name, dir_fd=parent.directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    deny("output directory already exists")


def remove_tree_contents(descriptor: int, label: str) -> None:
    for name in sorted(os.listdir(descriptor), key=lambda item: os.fsencode(item)):
        initial = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(initial.st_mode) and not stat.S_ISLNK(initial.st_mode):
            child = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            try:
                if directory_identity(os.fstat(child)) != directory_identity(initial):
                    deny(f"{label} child directory changed before cleanup")
                remove_tree_contents(child, f"{label}/{name}")
                current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if directory_identity(current) != directory_identity(initial):
                    deny(f"{label} child directory changed during cleanup")
                os.rmdir(name, dir_fd=descriptor)
            finally:
                os.close(child)
        else:
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if file_identity(current) != file_identity(initial):
                deny(f"{label} entry changed before cleanup")
            os.unlink(name, dir_fd=descriptor)


def cleanup_scratch(directory: RetainedScratchDirectory) -> None:
    if directory.published_name is not None:
        deny("refusing to clean a committed output directory")
    directory.assert_stable()
    remove_tree_contents(directory.descriptor, directory.name)
    os.fsync(directory.descriptor)
    directory.assert_stable()
    os.rmdir(directory.name, dir_fd=directory.parent.directory_fd)
    os.fsync(directory.parent.directory_fd)
    directory.close()


def write_file_at(directory_fd: int, name: str, raw: bytes, mode: int) -> None:
    if not name or "/" in name or name in {".", ".."}:
        deny("publication filename is invalid")
    descriptor = -1
    initial: os.stat_result | None = None
    try:
        descriptor = os.open(
            name,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        os.fchmod(descriptor, mode)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                deny(f"short write while staging {name}")
            view = view[written:]
        os.fsync(descriptor)
        initial = os.fstat(descriptor)
        lexical = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            file_identity(initial) != file_identity(lexical)
            or not stat.S_ISREG(initial.st_mode)
            or initial.st_nlink != 1
            or stat.S_IMODE(initial.st_mode) != mode
            or read_descriptor(descriptor, len(raw), f"staged {name}") != raw
        ):
            deny(f"staged file verification failed: {name}")
    except BaseException:
        if descriptor >= 0:
            try:
                held = os.fstat(descriptor)
            except OSError:
                held = None
            os.close(descriptor)
            descriptor = -1
            try:
                lexical = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError:
                lexical = None
            if held is not None and lexical is not None and (
                held.st_dev,
                held.st_ino,
            ) == (lexical.st_dev, lexical.st_ino):
                os.unlink(name, dir_fd=directory_fd)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def verify_staged_file(
    directory_fd: int, name: str, raw: bytes, mode: int
) -> None:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=directory_fd,
    )
    try:
        before = os.fstat(descriptor)
        observed = read_descriptor(descriptor, len(raw), f"staged {name}")
        after = os.fstat(descriptor)
        lexical = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            file_identity(before) != file_identity(after)
            or file_identity(after) != file_identity(lexical)
            or stat.S_IMODE(after.st_mode) != mode
            or after.st_nlink != 1
            or observed != raw
        ):
            deny(f"staged publication changed: {name}")
    finally:
        os.close(descriptor)


def verify_exact_inventory(directory_fd: int) -> None:
    if set(os.listdir(directory_fd)) != PUBLISHED_NAMES:
        deny("publication staging does not contain the exact four-file closure")


def rename_noreplace(
    source_parent_fd: int,
    source_name: str,
    target_parent_fd: int,
    target_name: str,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        deny("renameat2(RENAME_NOREPLACE) is required for publication")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        source_parent_fd,
        os.fsencode(source_name),
        target_parent_fd,
        os.fsencode(target_name),
        RENAME_NOREPLACE,
    )
    if result != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            deny("output directory appeared during atomic publication")
        raise BuildError(
            f"atomic no-replace output publication failed: {os.strerror(error)}"
        )


def publish_directory(
    staging: RetainedScratchDirectory,
    output_name: str,
    expected: Mapping[str, tuple[bytes, int]],
) -> None:
    if set(expected) != PUBLISHED_NAMES:
        deny("publication expectation is not the exact four-file closure")
    staging.assert_stable()
    verify_exact_inventory(staging.descriptor)
    for name, (raw, mode) in expected.items():
        verify_staged_file(staging.descriptor, name, raw, mode)
    os.fsync(staging.descriptor)
    staging.parent.assert_stable()
    rename_noreplace(
        staging.parent.directory_fd,
        staging.name,
        staging.parent.directory_fd,
        output_name,
    )
    staging.published_name = output_name
    staging.assert_stable()
    verify_exact_inventory(staging.descriptor)
    for name, (raw, mode) in expected.items():
        verify_staged_file(staging.descriptor, name, raw, mode)
    os.fsync(staging.parent.directory_fd)


def read_built_artifact(
    target_fd: int, relative: str, label: str, maximum: int
) -> bytes:
    components = relative.split("/")
    if any(not item or item in {".", ".."} for item in components):
        deny(f"{label} build path is not canonical")
    directory = os.dup(target_fd)
    try:
        for component in components[:-1]:
            following = os.open(
                component,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory,
            )
            os.close(directory)
            directory = following
        lexical = os.stat(
            components[-1], dir_fd=directory, follow_symlinks=False
        )
        descriptor = os.open(
            components[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory,
        )
        try:
            opened = os.fstat(descriptor)
            if (
                file_identity(opened) != file_identity(lexical)
                or not stat.S_ISREG(opened.st_mode)
                or not 0 < opened.st_size <= maximum
            ):
                deny(f"{label} is not one bounded build output")
            observed_links = count_target_inode_links(
                target_fd,
                opened.st_dev,
                opened.st_ino,
                label,
            )
            if observed_links != opened.st_nlink:
                deny(f"{label} has a hard link outside private target scratch")
            raw = read_descriptor(descriptor, opened.st_size, label)
            after = os.fstat(descriptor)
            current = os.stat(
                components[-1], dir_fd=directory, follow_symlinks=False
            )
            if (
                file_identity(opened) != file_identity(after)
                or file_identity(after) != file_identity(current)
            ):
                deny(f"{label} changed while captured")
            return raw
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def count_target_inode_links(
    target_fd: int, expected_device: int, expected_inode: int, label: str
) -> int:
    """Prove every hard link to one Cargo output stays inside target scratch."""

    pending = [os.dup(target_fd)]
    entries = 0
    links = 0
    try:
        while pending:
            directory = pending.pop()
            try:
                for name in sorted(
                    os.listdir(directory), key=lambda value: os.fsencode(value)
                ):
                    entries += 1
                    if entries > MAX_TARGET_TREE_ENTRIES:
                        deny(f"{label} target tree exceeds its link-audit bound")
                    metadata = os.stat(
                        name, dir_fd=directory, follow_symlinks=False
                    )
                    if (
                        metadata.st_dev == expected_device
                        and metadata.st_ino == expected_inode
                    ):
                        if not stat.S_ISREG(metadata.st_mode):
                            deny(f"{label} inode changed type during link audit")
                        links += 1
                    if not stat.S_ISDIR(metadata.st_mode):
                        continue
                    child = os.open(
                        name,
                        os.O_RDONLY
                        | os.O_CLOEXEC
                        | os.O_DIRECTORY
                        | os.O_NOFOLLOW,
                        dir_fd=directory,
                    )
                    opened = os.fstat(child)
                    if directory_identity(opened) != directory_identity(metadata):
                        os.close(child)
                        deny(f"{label} target directory changed during link audit")
                    pending.append(child)
            finally:
                os.close(directory)
        return links
    except BaseException:
        for descriptor in pending:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def build_receipt(
    *,
    source_bom_sha256: str,
    cargo_identity: str,
    rustc_identity: str,
    artifacts: list[dict[str, object]],
) -> dict[str, object]:
    receipt: dict[str, object] = {
        "schema": SCHEMA,
        "revision": 1,
        "status": "product_candidate",
        "source_bom_sha256": source_bom_sha256,
        "build": {
            "target": TARGET,
            "profile": PROFILE,
            "locked": True,
            "features": list(FEATURES),
            # Android v1 has two bounded string slots.  Preserve schema
            # compatibility while making each one byte/closure-bound rather
            # than a superficial, path-raceable version line.
            "rustc_version": rustc_identity,
            "cargo_version": cargo_identity,
        },
        "artifacts": artifacts,
    }
    receipt["artifact_set_sha256"] = sha256(compact_json(receipt))
    return receipt


def build(args: argparse.Namespace) -> Path:
    if sys.platform != "linux" or platform.machine() != "x86_64":
        deny("the fixed Zig host-linker closure requires Linux x86-64")
    workspace = absolute_canonical(args.workspace, "workspace")
    expected_workspace = Path(__file__).resolve().parents[1]
    if workspace != expected_workspace:
        deny("workspace must be the authoritative trillionnium-os checkout")
    try:
        control_root = bom_primitives.current_control_checkout_root(workspace)
    except RuntimeError as error:
        raise BuildError("could not derive the current control checkout") from error
    if workspace.parent != control_root:
        deny("trillionnium-os workspace is not directly below the control checkout")

    source_bom = RetainedRegular.open(
        args.source_bom, "source BOM", MAX_SOURCE_BOM_BYTES
    )
    resolved_manifest = RetainedRegular.open(
        args.resolved_manifest,
        "resolved manifest",
        MAX_RESOLVED_MANIFEST_BYTES,
    )
    tools: list[raw_primitives.RetainedExecutable] = []
    runtime_inputs: list[tuple[str, RetainedRegular]] = []
    dogfood_wrapper: RetainedRegular | None = None
    dev_null: RetainedDevNull | None = None
    output_parent: filesystem_primitives.RetainedDirectoryChain | None = None
    workspace_input: filesystem_primitives.RetainedDirectoryChain | None = None
    android_input: filesystem_primitives.RetainedDirectoryChain | None = None
    artifact_input: filesystem_primitives.RetainedDirectoryChain | None = None
    rust_root: filesystem_primitives.RetainedDirectoryChain | None = None
    zig_root: filesystem_primitives.RetainedDirectoryChain | None = None
    cargo_home: filesystem_primitives.RetainedDirectoryChain | None = None
    landlock_ruleset: RetainedLandlockRuleset | None = None
    build_roles: RetainedBuildRoleDescriptors | None = None
    target_scratch: RetainedScratchDirectory | None = None
    publish_scratch: RetainedScratchDirectory | None = None
    try:
        allow_userdebug_dogfood = bool(
            getattr(args, "allow_userdebug_dogfood", False)
        )
        if allow_userdebug_dogfood:
            wrapper_path = absolute_canonical(
                getattr(
                    args,
                    "userdebug_dogfood_wrapper",
                    DOGFOOD_WRAPPER_PATH,
                ),
                "userdebug dogfood wrapper",
            )
            if wrapper_path != DOGFOOD_WRAPPER_PATH:
                deny("userdebug dogfood wrapper must be the canonical evidence file")
            dogfood_wrapper = RetainedRegular.open(
                wrapper_path,
                "userdebug dogfood wrapper",
                MAX_SOURCE_BOM_BYTES,
            )
            source_binding = validate_userdebug_dogfood_source(
                source_bom.raw,
                dogfood_wrapper.raw,
                resolved_manifest.raw,
                wrapper_path=dogfood_wrapper.path,
            )
        else:
            source_binding = validate_source_bom(source_bom.raw)
        android_root = require_real_directory(
            args.android_root, "Android source root"
        )
        artifact_root = absolute_canonical(args.artifact_root, "artifact input root")
        rust_toolchain_root = absolute_canonical(
            args.rust_toolchain_root, "Rust toolchain root"
        )
        zig_toolchain_root = absolute_canonical(
            args.zig_toolchain_root, "Zig host toolchain root"
        )
        cargo_home_path = absolute_canonical(args.cargo_home, "Cargo home")
        output = absolute_canonical(args.output, "output directory")
        if not output.name or output.name in {".", ".."}:
            deny("output directory basename is invalid")
        roots = (
            control_root,
            android_root,
            artifact_root,
            source_bom.path.parent,
            resolved_manifest.path.parent,
            rust_toolchain_root,
            zig_toolchain_root,
            cargo_home_path,
        )
        if dogfood_wrapper is not None:
            roots = roots + (dogfood_wrapper.path.parent,)
        for root in roots:
            try:
                output.parent.relative_to(root)
            except ValueError:
                continue
            deny("output parent must be outside every measured input root")
        output_parent = filesystem_primitives.RetainedDirectoryChain.open(
            output.parent, "shell artifact output parent"
        )
        require_output_absent(output_parent, output.name)
        workspace_input = filesystem_primitives.RetainedDirectoryChain.open(
            workspace, "Landlock workspace source root"
        )
        android_input = filesystem_primitives.RetainedDirectoryChain.open(
            android_root, "Landlock Android source root"
        )
        artifact_input = filesystem_primitives.RetainedDirectoryChain.open(
            artifact_root, "source-BOM artifact root"
        )
        require_empty_retained_directory(
            artifact_input, "source-BOM artifact root"
        )
        rust_root = filesystem_primitives.RetainedDirectoryChain.open(
            rust_toolchain_root, "Rust toolchain root"
        )
        zig_root = filesystem_primitives.RetainedDirectoryChain.open(
            zig_toolchain_root, "Zig host toolchain root"
        )
        cargo_home = filesystem_primitives.RetainedDirectoryChain.open(
            cargo_home_path, "Cargo home"
        )
        ensure_no_cargo_config(workspace, control_root, cargo_home_path)

        cargo = raw_primitives.open_retained_executable(args.cargo, "cargo")
        tools.append(cargo)
        rustc = raw_primitives.open_retained_executable(args.rustc, "rustc")
        tools.append(rustc)
        linker = raw_primitives.open_retained_executable(args.linker, "Rust musl linker")
        tools.append(linker)
        host_linker_wrapper = raw_primitives.open_retained_executable(
            args.host_linker_wrapper, "static Zig cc host-linker wrapper"
        )
        tools.append(host_linker_wrapper)
        zig = raw_primitives.open_retained_executable(args.zig, "Zig 0.14.1 driver")
        tools.append(zig)
        qemu = raw_primitives.open_retained_executable(
            args.qemu_aarch64_static, "qemu-aarch64-static load/start probe"
        )
        tools.append(qemu)
        rust_tools = (cargo, rustc, linker)
        zig_tools = (host_linker_wrapper, zig)
        for tool in tools:
            try:
                if tool.path.resolve(strict=True) != tool.path:
                    deny(f"{tool.role} path contains a symlinked component")
            except OSError as error:
                raise BuildError(f"{tool.role} path cannot be resolved") from error
        for tool in rust_tools:
            try:
                tool.path.relative_to(rust_toolchain_root)
            except ValueError as error:
                raise BuildError(
                    f"{tool.role} is outside the explicit Rust toolchain root"
                ) from error
        for tool in zig_tools:
            try:
                tool.path.relative_to(zig_toolchain_root)
            except ValueError as error:
                raise BuildError(
                    f"{tool.role} is outside the explicit Zig host toolchain root"
                ) from error
        inspect_static_host_tool(
            host_linker_wrapper.initial_bytes, "Zig cc host-linker wrapper"
        )
        inspect_static_host_tool(zig.initial_bytes, "Zig 0.14.1 driver")
        inspect_static_host_tool(
            qemu.initial_bytes, "qemu-aarch64-static load/start probe"
        )

        runtime_identities: set[tuple[int, ...]] = set()
        for role, label, expected_names in HOST_RUNTIME_INPUTS:
            retained = RetainedRegular.open(
                getattr(args, role), label, MAX_HOST_RUNTIME_BYTES
            )
            try:
                if retained.path.name not in expected_names:
                    deny(
                        f"{label} canonical basename is not one of "
                        f"{', '.join(expected_names)}"
                    )
                validate_host_runtime_elf(retained.raw, label)
                if role == "host_dynamic_loader" and not stat.S_IMODE(
                    retained.initial.st_mode
                ) & stat.S_IXUSR:
                    deny("host dynamic loader is not owner-executable")
                identity = file_identity(retained.initial)
                if identity in runtime_identities:
                    deny("host runtime inputs alias the same retained file")
                runtime_identities.add(identity)
                runtime_inputs.append((role, retained))
            except BaseException:
                retained.close()
                raise
        dev_null = RetainedDevNull.open(args.host_dev_null)
        runtime_records = [
            host_runtime_record(role, retained)
            for role, retained in runtime_inputs
        ]
        dev_null_record = dev_null.receipt_record()

        rust_inventory = measure_closed_tree(
            rust_toolchain_root,
            "Rust toolchain closure",
            entry_limit=MAX_TOOLCHAIN_ENTRIES,
            byte_limit=MAX_TOOLCHAIN_BYTES,
        )
        zig_inventory = measure_closed_tree(
            zig_toolchain_root,
            "Zig host toolchain closure",
            entry_limit=MAX_ZIG_TOOLCHAIN_ENTRIES,
            byte_limit=MAX_ZIG_TOOLCHAIN_BYTES,
        )
        cargo_home_inventory = measure_closed_tree(
            cargo_home_path,
            "Cargo home closure",
            entry_limit=MAX_CARGO_HOME_ENTRIES,
            byte_limit=MAX_CARGO_HOME_BYTES,
        )
        require_immutable_tree(zig_inventory, "Zig host toolchain closure")
        require_immutable_tree(cargo_home_inventory, "Cargo home closure")
        source_bom.assert_stable()
        resolved_manifest.assert_stable()
        require_empty_retained_directory(
            artifact_input, "source-BOM artifact root"
        )
        rust_root.assert_stable()
        zig_root.assert_stable()
        cargo_home.assert_stable()
        if dogfood_wrapper is not None:
            pre_binding = validate_userdebug_dogfood_live(
                source_bom,
                dogfood_wrapper,
                resolved_manifest,
                source_binding,
            )
        else:
            try:
                pre_binding = bom_primitives.remeasure_live_source_bom_binding(
                    source_bom.path,
                    android_root,
                    artifact_root,
                    resolved_manifest.path,
                    repository=workspace,
                )
            except RuntimeError as error:
                raise BuildError("pre-build live source graph does not match the BOM") from error
        if pre_binding != source_binding:
            deny("pre-build source BOM binding changed")

        rustc_sysroot = run_retained(
            rustc,
            ("--print", "sysroot"),
            environment={"LANG": "C", "LC_ALL": "C", "PATH": "", "TZ": "UTC"},
            expected_environment={"LANG", "LC_ALL", "PATH", "TZ"},
            cwd=workspace,
            timeout=30,
            maximum_output=4096,
            label="rustc sysroot query",
        ).decode("utf-8").strip()
        if rustc_sysroot != str(rust_toolchain_root):
            deny("retained rustc sysroot differs from the explicit toolchain root")
        cargo_version = version_line(cargo, ("-Vv",), workspace, "cargo")
        rustc_verbose = version_text(rustc, ("-Vv",), workspace, "rustc")
        rustc_lines = rustc_verbose.splitlines()
        rustc_version = rustc_lines[0] if rustc_lines else ""
        rustc_fields = {
            name: value
            for line in rustc_lines[1:]
            if ": " in line
            for name, value in (line.split(": ", 1),)
        }
        if (
            not cargo_version.startswith(f"cargo {RUST_VERSION} (")
            or not rustc_version.startswith(f"rustc {RUST_VERSION} (")
            or rustc_fields.get("release") != RUST_VERSION
            or rustc_fields.get("host") != HOST_TARGET
        ):
            deny("Cargo/rustc differs from the fixed Rust 1.95 x86-64 closure")
        zig_version_environment = {
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "",
            "TZ": "UTC",
            "ZIG_LIB_DIR": f"/proc/self/fd/{zig_root.directory_fd}/lib",
        }
        zig_version = version_line(
            zig,
            ("version",),
            workspace,
            "Zig host driver",
            environment=zig_version_environment,
            pass_fds=(zig_root.directory_fd,),
        )
        if zig_version != ZIG_VERSION:
            deny("Zig host driver version differs from the fixed 0.14.1 closure")
        qemu_version = version_line(
            qemu,
            ("--version",),
            workspace,
            "qemu-aarch64-static load/start probe",
        )
        lowered_qemu_version = qemu_version.lower()
        if "qemu" not in lowered_qemu_version or "aarch64" not in lowered_qemu_version:
            deny("qemu-aarch64-static emitted an unexpected version identity")

        target_scratch = create_scratch_directory(
            output_parent, ".shell-exec-target."
        )
        for name in ("home", "tmp", "zig-global-cache", "zig-local-cache"):
            os.mkdir(name, 0o700, dir_fd=target_scratch.descriptor)
        build_roles = RetainedBuildRoleDescriptors.open(
            {
                "rustc": rustc.descriptor,
                "target_linker": linker.descriptor,
                "host_linker_wrapper": host_linker_wrapper.descriptor,
                "zig": zig.descriptor,
                "zig_root": zig_root.directory_fd,
                "cargo_home_input": cargo_home.directory_fd,
                "target": target_scratch.descriptor,
                "cargo": cargo.descriptor,
            }
        )
        role_descriptors = build_roles.descriptors
        prepare_operational_cargo_home(
            target_scratch.descriptor,
            cargo_home.directory_fd,
            role_descriptors["cargo_home_input"],
        )
        environment = build_environment(
            workspace=workspace,
            android_root=android_root,
            artifact_root=artifact_root,
            resolved_manifest=resolved_manifest.path,
            output_parent=output.parent,
            role_descriptors=role_descriptors,
            rust_toolchain_root=rust_toolchain_root,
            zig_toolchain_root=zig_toolchain_root,
        )
        bound_environment = receipt_environment(
            environment,
            role_descriptors=role_descriptors,
        )
        command = [
            "build",
            "--locked",
            "--frozen",
            "--offline",
            "--quiet",
            "--release",
            "--target",
            TARGET,
            "--no-default-features",
            "--features",
            ",".join(FEATURES),
            "-p",
            PACKAGE,
        ]
        for _, binary, _ in ARTIFACTS:
            command.extend(("--bin", binary))
        workspace_input.assert_stable()
        android_input.assert_stable()
        for _role, retained in runtime_inputs:
            retained.assert_stable()
        dev_null.assert_stable()
        landlock_ruleset = create_build_landlock_ruleset(
            workspace_fd=workspace_input.directory_fd,
            rust_root_fd=rust_root.directory_fd,
            zig_root_fd=zig_root.directory_fd,
            cargo_home_fd=cargo_home.directory_fd,
            target_fd=target_scratch.descriptor,
            build_tools=(
                ("cargo_executable", cargo),
                ("rustc_executable", rustc),
                ("target_linker_executable", linker),
                ("host_linker_wrapper_executable", host_linker_wrapper),
                ("zig_executable", zig),
            ),
            runtime_inputs=runtime_inputs,
            dev_null=dev_null,
        )
        landlock_policy = landlock_ruleset.receipt_record()
        revalidate_tools(tools)
        run_retained(
            cargo,
            command,
            environment=environment,
            expected_environment=set(environment),
            cwd=workspace,
            timeout=7200,
            maximum_output=MAX_BUILD_OUTPUT_BYTES,
            label="closed shell.exec.v1 Cargo build",
            pass_fds=tuple(role_descriptors.values()),
            execution_descriptor=role_descriptors["cargo"],
            landlock_ruleset=landlock_ruleset,
        )
        landlock_ruleset.assert_stable()
        build_roles.assert_stable()
        landlock_ruleset.close()
        landlock_ruleset = None
        build_roles.close()
        build_roles = None
        revalidate_tools(tools)
        workspace_input.assert_stable()
        android_input.assert_stable()
        for _role, retained in runtime_inputs:
            retained.assert_stable()
        dev_null.assert_stable()

        documents: list[dict[str, object]] = []
        artifact_bytes: dict[str, bytes] = {}
        for role, binary, installed_path in ARTIFACTS:
            raw = read_built_artifact(
                target_scratch.descriptor,
                f"{TARGET}/{PROFILE}/{binary}",
                f"built {role} ELF",
                MAX_ELF_BYTES,
            )
            elf = inspect_static_aarch64_elf(raw, f"built {role} ELF")
            artifact_bytes[binary] = raw
            documents.append(
                {
                    "role": role,
                    "source_package": PACKAGE,
                    "source_binary": binary,
                    "installed_path": installed_path,
                    "sha256": sha256(raw),
                    "size_bytes": len(raw),
                    **elf,
                }
            )

        probe_results = [
            probe_aarch64_artifact(qemu, artifact_bytes[binary], role, workspace)
            for role, binary, _installed_path in ARTIFACTS
        ]

        # Build scratch is removed before any public name can appear. Cleanup
        # walks only the retained directory fd and refuses a replaced lexical
        # name, so it cannot cross-delete a concurrent sibling build.
        cleanup_scratch(target_scratch)
        target_scratch = None

        revalidate_tools(tools)
        source_bom.assert_stable()
        resolved_manifest.assert_stable()
        require_empty_retained_directory(
            artifact_input, "source-BOM artifact root"
        )
        rust_root.assert_stable()
        zig_root.assert_stable()
        cargo_home.assert_stable()
        workspace_input.assert_stable()
        android_input.assert_stable()
        for _role, retained in runtime_inputs:
            retained.assert_stable()
        dev_null.assert_stable()
        require_same_tree(
            rust_inventory,
            measure_closed_tree(
                rust_toolchain_root,
                "Rust toolchain closure",
                entry_limit=MAX_TOOLCHAIN_ENTRIES,
                byte_limit=MAX_TOOLCHAIN_BYTES,
            ),
            "Rust toolchain closure",
        )
        require_same_tree(
            zig_inventory,
            measure_closed_tree(
                zig_toolchain_root,
                "Zig host toolchain closure",
                entry_limit=MAX_ZIG_TOOLCHAIN_ENTRIES,
                byte_limit=MAX_ZIG_TOOLCHAIN_BYTES,
            ),
            "Zig host toolchain closure",
        )
        require_same_tree(
            cargo_home_inventory,
            measure_closed_tree(
                cargo_home_path,
                "Cargo home closure",
                entry_limit=MAX_CARGO_HOME_ENTRIES,
                byte_limit=MAX_CARGO_HOME_BYTES,
            ),
            "Cargo home closure",
        )
        if dogfood_wrapper is not None:
            post_binding = validate_userdebug_dogfood_live(
                source_bom,
                dogfood_wrapper,
                resolved_manifest,
                source_binding,
            )
        else:
            try:
                post_binding = bom_primitives.remeasure_live_source_bom_binding(
                    source_bom.path,
                    android_root,
                    artifact_root,
                    resolved_manifest.path,
                    repository=workspace,
                )
            except RuntimeError as error:
                raise BuildError("post-build live source graph does not match the BOM") from error
        if post_binding != source_binding:
            deny("post-build source BOM binding changed")
        require_empty_retained_directory(
            artifact_input, "source-BOM artifact root"
        )

        cargo_closure_sha256 = sha256(
            compact_json(
                {
                    "schema": "org.trillionnium.shell-exec-cargo-invocation.v1",
                    "cargo_home_sha256": cargo_home_inventory["sha256"],
                    "command": command,
                    "environment": bound_environment,
                    "host_linker_wrapper_sha256": sha256(
                        host_linker_wrapper.initial_bytes
                    ),
                    "host_runtime": {
                        "files": runtime_records,
                        "dev_null": dev_null_record,
                    },
                    "inherited_fd_roles": list(BUILD_INPUT_ROLES),
                    "landlock_policy": landlock_policy,
                    "qemu_aarch64_static_sha256": sha256(qemu.initial_bytes),
                    "qemu_aarch64_static_version": qemu_version,
                    "qemu_load_start_probes": probe_results,
                    "zig_driver_sha256": sha256(zig.initial_bytes),
                    "zig_toolchain_sha256": zig_inventory["sha256"],
                    "zig_version": zig_version,
                }
            )
        )
        cargo_identity = tool_identity_string(
            cargo_version,
            cargo,
            "closure",
            cargo_closure_sha256,
            "qemu",
            sha256(qemu.initial_bytes),
        )
        rustc_identity = tool_identity_string(
            rustc_version,
            rustc,
            "tree",
            str(rust_inventory["sha256"]),
            "link",
            sha256(linker.initial_bytes),
        )
        receipt = build_receipt(
            source_bom_sha256=sha256(
                dogfood_wrapper.raw if dogfood_wrapper is not None else source_bom.raw
            ),
            cargo_identity=cargo_identity,
            rustc_identity=rustc_identity,
            artifacts=documents,
        )
        receipt_raw = pretty_json(receipt)

        publish_scratch = create_scratch_directory(
            output_parent, ".shell-exec-artifacts."
        )
        expected: dict[str, tuple[bytes, int]] = {}
        for _, binary, _ in ARTIFACTS:
            raw = artifact_bytes[binary]
            write_file_at(publish_scratch.descriptor, binary, raw, 0o555)
            expected[binary] = (raw, 0o555)
        write_file_at(publish_scratch.descriptor, RECEIPT_NAME, receipt_raw, 0o444)
        expected[RECEIPT_NAME] = (receipt_raw, 0o444)
        publish_directory(publish_scratch, output.name, expected)
        publish_scratch.close()
        publish_scratch = None
        return output
    finally:
        cleanup_errors: list[BaseException] = []
        if landlock_ruleset is not None:
            try:
                landlock_ruleset.close()
            except BaseException as error:
                cleanup_errors.append(error)
        if build_roles is not None:
            try:
                build_roles.close()
            except BaseException as error:
                cleanup_errors.append(error)
        for scratch in (publish_scratch, target_scratch):
            if scratch is None:
                continue
            try:
                if scratch.published_name is None:
                    cleanup_scratch(scratch)
                else:
                    scratch.close()
            except BaseException as error:
                cleanup_errors.append(error)
        for tool in reversed(tools):
            try:
                tool.close()
            except BaseException as error:
                cleanup_errors.append(error)
        if dev_null is not None:
            try:
                dev_null.close()
            except BaseException as error:
                cleanup_errors.append(error)
        for _role, retained_file in reversed(runtime_inputs):
            try:
                retained_file.close()
            except BaseException as error:
                cleanup_errors.append(error)
        for retained in (
            cargo_home,
            zig_root,
            rust_root,
            artifact_input,
            android_input,
            workspace_input,
            output_parent,
        ):
            if retained is None:
                continue
            try:
                retained.close()
            except BaseException as error:
                cleanup_errors.append(error)
        for retained_file in (resolved_manifest, source_bom, dogfood_wrapper):
            if retained_file is None:
                continue
            try:
                retained_file.close()
            except BaseException as error:
                cleanup_errors.append(error)
        if cleanup_errors and sys.exc_info()[0] is None:
            raise BuildError("could not close every retained build resource") from cleanup_errors[0]


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--workspace", type=Path, required=True)
    value.add_argument("--source-bom", type=Path, required=True)
    value.add_argument(
        "--allow-userdebug-dogfood",
        action="store_true",
        help="explicitly bind the canonical non-authorizing dirty userdebug wrapper",
    )
    value.add_argument(
        "--userdebug-dogfood-wrapper",
        type=Path,
        default=DOGFOOD_WRAPPER_PATH,
        help="canonical userdebug dogfood source-BOM wrapper evidence",
    )
    value.add_argument("--android-root", type=Path, required=True)
    value.add_argument("--artifact-root", type=Path, required=True)
    value.add_argument("--resolved-manifest", type=Path, required=True)
    value.add_argument("--output", type=Path, required=True)
    value.add_argument("--cargo", type=Path, required=True)
    value.add_argument("--rustc", type=Path, required=True)
    value.add_argument("--linker", type=Path, required=True)
    value.add_argument("--host-linker-wrapper", type=Path, required=True)
    value.add_argument("--zig", type=Path, required=True)
    value.add_argument("--qemu-aarch64-static", type=Path, required=True)
    for destination, _label, _expected_names in HOST_RUNTIME_INPUTS:
        value.add_argument(
            "--" + destination.replace("_", "-"),
            dest=destination,
            type=Path,
            required=True,
        )
    value.add_argument("--host-dev-null", type=Path, required=True)
    value.add_argument("--rust-toolchain-root", type=Path, required=True)
    value.add_argument("--zig-toolchain-root", type=Path, required=True)
    value.add_argument("--cargo-home", type=Path, required=True)
    return value


def main() -> int:
    try:
        output = build(parser().parse_args())
    except (BuildError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"DENY: {error}", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
