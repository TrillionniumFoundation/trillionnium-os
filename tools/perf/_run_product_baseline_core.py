#!/usr/bin/env python3
"""Measure selected owner-open executables on a Linux host, never a device.

This is deliberately separate from run_global_baseline.py's schema probes.
Latency includes process startup, durable store work and client delivery. Only
observed values are recorded; missing runtime instrumentation remains null.
"""
from __future__ import annotations

import argparse
import contextlib
import base64
import ctypes
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import selectors
import shlex
import shutil
import signal
import socket
import stat
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "org.trillionnium.product-host-baseline.v1"
MAX_CAPTURE = 16 * 1024 * 1024
MAX_ARTIFACT = 32 * 1024 * 1024
MIN_GATE_REPETITIONS = 5
MAX_REGRESSION_PERCENT = 25.0
GATE_POLICY_SCHEMA = "org.trillionnium.product-host-baseline-gate-policy.v1"
GATE_POLICY_VERSION = "2026-09-09-v1"
IMPLEMENTATION_MANIFEST_SCHEMA = "org.trillionnium.product-host-baseline-implementation.v1"
GATE_METRICS = ("latency_p50_ms", "latency_p95_ms")
BROKER_SOURCE_PATHS = (
    "tools/owner-open/owner_open_connection_broker.py",
    "tools/owner-open/owner_open_connection_broker_v2.py",
    "tools/owner-open/owner_open_broker_admission_v2.py",
    "tools/owner-open/owner_open_broker_audit.py",
    "tools/owner-open/owner_open_broker_base_v2.py",
    "tools/owner-open/owner_open_broker_common.py",
    "tools/owner-open/owner_open_broker_connections.py",
    "tools/owner-open/owner_open_broker_convergence_v2.py",
    "tools/owner-open/owner_open_broker_mux.py",
    "tools/owner-open/owner_open_broker_runtime.py",
    "tools/owner-open/owner_open_broker_server_v2.py",
)
IMPLEMENTATION_PATHS = (
    "tools/owner-open/authenticated_python_bootstrap.py",
    *BROKER_SOURCE_PATHS,
    "tools/owner-open/owner_open_rootlinux_supervisor.py",
    "tools/perf/_run_product_baseline_core.py",
    "tools/perf/_run_product_baseline_facade.py",
    "tools/perf/run_product_baseline.py",
)
WORKLOADS = {
    "short_turn": "fresh Host/Core, fixture provider, shell callback, durable event store",
    "concurrent_turns": "concurrent independent Host/Core sessions and stores; not shared-core admission",
    "large_output": "real shell output, byte-exact client delivery through Host/Core",
    "slow_consumer": "real large output with paced 4096-byte stdout reads; not zero-credit qualification",
    "pipe_job": "real pipe job, durable job journal, terminal wait and output",
    "pty_job": "real PTY job, durable job journal, terminal wait and output",
    "restart_replay": "clean process restart with same turn bytes/store; no second effect or provider start",
    "broker_inspect": "concurrent authenticated Unix clients inspecting absent jobs through one broker/Host/Core",
}
UNAVAILABLE = {
    name: {"value": None, "status": "unavailable", "reason": "No trustworthy product instrumentation in this harness"}
    for name in ("cpu_seconds", "rss_bytes", "fd_peak", "thread_peak", "process_peak",
                 "io_bytes", "fsync_count", "queue_wait_ms", "lock_wait_ms", "lock_hold_ms",
                 "fairness", "unknown_rate")
}


PINNED_IMPLEMENTATION_FILES: dict[str, dict[str, Any]] | None = None
PINNED_IMPLEMENTATION_SOURCES: dict[str, bytes] | None = None
PINNED_BOOTSTRAP_ATTESTATION: dict[str, Any] | None = None
EXECUTION_PATHS: dict[str, str] = {}
EXECUTION_PASS_FDS: tuple[int, ...] = ()
OPEN_ADMITTED_FILE: Any = None
REOPEN_ADMITTED_IDENTITY: Any = None
SAME_ADMITTED_OBJECT: Any = None
MAX_PINNED_EXECUTABLE_BYTES = 512 * 1024 * 1024
STORAGE_IDENTITY_SCHEMA = "org.trillionnium.product-host-storage-identity.v1"
STORAGE_IDENTITY_SCOPE = "same-boot-observed-mount-filesystem-only"
EXECUTION_CUSTODY = "verified-private-single-link-copies-v1"
PINNED_EXECUTABLE_CUSTODY = "descriptor-rooted-private-single-link-copy-v2"


class BenchmarkError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BenchmarkError(message)


def strict_json(data: bytes | str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            require(key not in value, f"duplicate JSON key: {key}")
            value[key] = item
        return value
    def bad_constant(value: str) -> Any:
        raise BenchmarkError(f"nonfinite JSON constant: {value}")
    def finite_float(value: str) -> float:
        parsed = float(value)
        require(math.isfinite(parsed), "nonfinite JSON number")
        return parsed
    return json.loads(data, object_pairs_hook=pairs, parse_constant=bad_constant, parse_float=finite_float)


def measured_file(path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    require(resolved.is_file(), f"not a regular file: {path}")
    before = resolved.stat()
    hasher = hashlib.sha256()
    with resolved.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    after = resolved.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            f"file changed: {path}")
    return {"path": str(resolved), "size": before.st_size,
            "sha256": hasher.hexdigest()}


def _admit_executable(
    path: Path,
    label: str,
    *,
    before_component: Any = None,
    after_final: Any = None,
) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    require(callable(OPEN_ADMITTED_FILE),
            "descriptor-rooted executable admission is not installed")
    return OPEN_ADMITTED_FILE(
        path,
        str(path.absolute()),
        maximum=MAX_PINNED_EXECUTABLE_BYTES,
        executable=True,
        before_component=before_component,
        after_final=after_final,
    )


def _reopen_executable(path: Path, label: str) -> dict[str, Any]:
    require(callable(REOPEN_ADMITTED_IDENTITY),
            "descriptor-rooted executable revalidation is not installed")
    return REOPEN_ADMITTED_IDENTITY(
        path,
        str(path.absolute()),
        maximum=MAX_PINNED_EXECUTABLE_BYTES,
        executable=True,
    )


def _same_admitted(left: dict[str, Any], right: dict[str, Any]) -> bool:
    require(callable(SAME_ADMITTED_OBJECT),
            "descriptor-rooted identity comparison is not installed")
    return bool(SAME_ADMITTED_OBJECT(left, right))


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        require(written > 0, "zero-progress write while creating pinned executable")
        offset += written


class PinnedExecutable:
    """Private executable copied from one descriptor-rooted admitted object."""

    def __init__(
        self,
        source: Path,
        custody_root: Path,
        label: str,
        *,
        before_component: Any = None,
        after_final: Any = None,
    ) -> None:
        self.requested_path = source.absolute()
        payload, report, internal = _admit_executable(
            self.requested_path,
            label,
            before_component=before_component,
            after_final=after_final,
        )
        self._source_internal = internal
        self.execution_path = custody_root / label
        destination = os.open(
            self.execution_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o500,
        )
        try:
            _write_all(destination, payload)
            os.fsync(destination)
        finally:
            os.close(destination)
        os.chmod(self.execution_path, 0o500, follow_symlinks=False)
        directory = os.open(custody_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        current = _reopen_executable(self.requested_path, label)
        require(_same_admitted(self._source_internal, current),
                f"{label} selected executable changed before custody completed")
        private = measured_file(self.execution_path)
        private_stat = self.execution_path.stat()
        require(private_stat.st_nlink == 1 and private_stat.st_uid == os.geteuid(),
                f"{label} custody copy is not private and single-link")
        require(private_stat.st_mode & 0o077 == 0,
                f"{label} custody copy is group/world accessible")
        require(private["size"] == report["size"] and
                private["sha256"] == report["sha256"],
                f"{label} custody copy differs from admitted bytes")
        self.identity = {
            "path": internal["absolute_path"],
            "requested_path": str(self.requested_path),
            "size": report["size"],
            "sha256": report["sha256"],
            "execution_custody": "descriptor-rooted-private-single-link-copy-v2",
        }

    def assert_execution_copy(self) -> None:
        current = measured_file(self.execution_path)
        value = self.execution_path.stat()
        require(value.st_nlink == 1 and value.st_uid == os.geteuid() and
                value.st_mode & 0o077 == 0,
                f"pinned execution copy custody changed: {self.execution_path.name}")
        require(current["size"] == self.identity["size"] and
                current["sha256"] == self.identity["sha256"],
                f"pinned execution bytes changed: {self.execution_path.name}")

    def assert_source_selection(self) -> None:
        current = _reopen_executable(self.requested_path, self.execution_path.name)
        require(_same_admitted(self._source_internal, current),
                f"selected executable path or bytes moved: {self.requested_path}")


def _write_pinned_source(
    custody_root: Path,
    name: str,
    source: bytes,
    identity: dict[str, Any],
) -> Path:
    require(len(source) == identity["size"] and
            hashlib.sha256(source).hexdigest() == identity["sha256"],
            f"pinned source bytes differ: {identity['path']}")
    target = custody_root / name
    descriptor = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o400,
    )
    try:
        _write_all(descriptor, source)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(target, 0o400, follow_symlinks=False)
    observed = measured_file(target)
    value = target.stat()
    require(value.st_nlink == 1 and value.st_uid == os.geteuid() and
            value.st_mode & 0o077 == 0,
            f"pinned source custody is not private: {identity['path']}")
    require(observed["size"] == identity["size"] and
            observed["sha256"] == identity["sha256"],
            f"pinned source custody bytes differ: {identity['path']}")
    return target


def _assert_broker_custody(directory: Path) -> None:
    require(PINNED_IMPLEMENTATION_FILES is not None,
            "broker source identities are not snapshot-bound")
    directory_value = directory.stat(follow_symlinks=False)
    require(stat.S_ISDIR(directory_value.st_mode) and
            directory_value.st_uid == os.geteuid() and
            directory_value.st_mode & 0o077 == 0,
            "broker custody directory is not private")
    expected_names = {Path(relative).name for relative in BROKER_SOURCE_PATHS}
    require({path.name for path in directory.iterdir()} == expected_names,
            "broker custody inventory differs from the closed implementation")
    for relative in BROKER_SOURCE_PATHS:
        path = directory / Path(relative).name
        _, actual, internal = OPEN_ADMITTED_FILE(
            path, relative, maximum=8 * 1024 * 1024, executable=False
        )
        expected = PINNED_IMPLEMENTATION_FILES[relative]
        value = path.stat(follow_symlinks=False)
        require(value.st_nlink == 1 and value.st_uid == os.geteuid() and
                value.st_mode & 0o077 == 0 and
                (value.st_dev, value.st_ino) == (internal["device"], internal["inode"]),
                f"broker source custody is not private and single-link: {relative}")
        require(actual == expected,
                f"broker custody bytes differ from the admitted snapshot: {relative}")


def _write_broker_custody(parent: Path) -> Path:
    require(PINNED_IMPLEMENTATION_FILES is not None and
            PINNED_IMPLEMENTATION_SOURCES is not None and
            set(PINNED_IMPLEMENTATION_FILES) == set(IMPLEMENTATION_PATHS) and
            set(PINNED_IMPLEMENTATION_SOURCES) == set(IMPLEMENTATION_PATHS),
            "broker implementation snapshot is incomplete")
    directory = parent / "broker-python"
    directory.mkdir(mode=0o700)
    for relative in BROKER_SOURCE_PATHS:
        _write_pinned_source(
            directory, Path(relative).name,
            PINNED_IMPLEMENTATION_SOURCES[relative],
            PINNED_IMPLEMENTATION_FILES[relative],
        )
    _assert_broker_custody(directory)
    return directory / Path(BROKER_SOURCE_PATHS[0]).name


def _live_repository_file_identity(relative: str) -> dict[str, Any]:
    require(relative in IMPLEMENTATION_PATHS,
            f"unregistered implementation path: {relative}")
    require(callable(OPEN_ADMITTED_FILE),
            "descriptor-rooted implementation admission is not installed")
    _, report, _ = OPEN_ADMITTED_FILE(
        ROOT / relative, relative, maximum=8 * 1024 * 1024, executable=False
    )
    return report


def repository_file_identity(relative: str) -> dict[str, Any]:
    if PINNED_IMPLEMENTATION_FILES is not None:
        require(set(PINNED_IMPLEMENTATION_FILES) == set(IMPLEMENTATION_PATHS),
                "pinned implementation inventory differs")
        value = PINNED_IMPLEMENTATION_FILES.get(relative)
        require(isinstance(value, dict),
                f"missing pinned implementation source: {relative}")
        require(set(value) == {"path", "size", "sha256"} and
                value["path"] == relative,
                f"invalid pinned implementation identity: {relative}")
        return dict(value)
    return _live_repository_file_identity(relative)


def _manifest(files: list[dict[str, Any]]) -> dict[str, Any]:
    body = {"schema": IMPLEMENTATION_MANIFEST_SCHEMA, "files": files}
    return {**body, "manifest_sha256": digest(canonical(body))}


def implementation_manifest() -> dict[str, Any]:
    return _manifest([repository_file_identity(relative)
                      for relative in IMPLEMENTATION_PATHS])


def live_implementation_manifest() -> dict[str, Any]:
    return _manifest([_live_repository_file_identity(relative)
                      for relative in IMPLEMENTATION_PATHS])


def validate_bootstrap_attestation(
    value: Any,
    manifest: dict[str, Any],
    *,
    launcher_path: str = "tools/perf/run_product_baseline.py",
) -> dict[str, Any]:
    require(isinstance(value, dict), "missing authenticated bootstrap attestation")
    expected = {
        "schema", "policy_version", "transport", "outer_loader_policy",
        "bootstrap", "launcher", "direct_path_execution",
        "automatic_redispatch", "public_release",
    }
    require(set(value) == expected, "bootstrap attestation keys differ")
    require(value["schema"] == "org.trillionnium.authenticated-python-bootstrap.v1",
            "bootstrap attestation schema differs")
    require(value["policy_version"] == "2026-09-09-v1",
            "bootstrap policy version differs")
    require(value["transport"] == "captured-bootstrap-and-launcher-bytes-v1" and
            value["outer_loader_policy"] == "python-isolated-inline-descriptor-loader-v1",
            "bootstrap transport policy differs")
    require(value["direct_path_execution"] is False and
            value["automatic_redispatch"] is False and
            value["public_release"] is False,
            "bootstrap attestation widened authority")
    files = {item["path"]: item for item in manifest["files"]}
    require(value["bootstrap"] == files["tools/owner-open/authenticated_python_bootstrap.py"],
            "bootstrap attestation does not bind implementation manifest")
    require(value["launcher"] == files[launcher_path],
            "bootstrap attestation does not bind launcher")
    return dict(value)


def bootstrap_attestation() -> dict[str, Any]:
    manifest = implementation_manifest()
    return validate_bootstrap_attestation(PINNED_BOOTSTRAP_ATTESTATION, manifest)


def gate_policy() -> dict[str, Any]:
    return {
        "schema": GATE_POLICY_SCHEMA,
        "version": GATE_POLICY_VERSION,
        "max_regression_percent": MAX_REGRESSION_PERCENT,
        "metrics": list(GATE_METRICS),
        "minimum_repetitions": MIN_GATE_REPETITIONS,
    }


def validate_implementation_manifest(value: Any) -> dict[str, Any]:
    require(isinstance(value, dict), "implementation manifest must be an object")
    require(set(value) == {"schema", "files", "manifest_sha256"},
            "implementation manifest keys differ")
    require(value["schema"] == IMPLEMENTATION_MANIFEST_SCHEMA,
            "implementation manifest schema differs")
    files = value["files"]
    require(isinstance(files, list) and len(files) == len(IMPLEMENTATION_PATHS),
            "implementation manifest file count differs")
    require([item.get("path") if isinstance(item, dict) else None for item in files] ==
            list(IMPLEMENTATION_PATHS), "implementation manifest paths differ")
    for item in files:
        require(isinstance(item, dict) and set(item) == {"path", "size", "sha256"},
                "implementation manifest entry keys differ")
        require(type(item["size"]) is int and item["size"] > 0,
                f"invalid implementation size: {item.get('path')}")
        value_sha = item["sha256"]
        require(isinstance(value_sha, str) and len(value_sha) == 64 and
                all(char in "0123456789abcdef" for char in value_sha),
                f"invalid implementation digest: {item.get('path')}")
    body = {"schema": value["schema"], "files": files}
    require(value["manifest_sha256"] == digest(canonical(body)),
            "implementation manifest digest mismatch")
    return value


def validate_gate_policy(value: Any) -> dict[str, Any]:
    require(value == gate_policy(), "performance gate policy differs from reviewed policy")
    return value


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", "--no-replace-objects", *args], cwd=ROOT,
                                   stderr=subprocess.PIPE, timeout=20)


def source_identity() -> dict[str, Any]:
    status = git("status", "--porcelain=v1", "--untracked-files=all")
    # Bind changed tracked bytes as well as untracked source, not only filenames.
    changed = digest(git("diff", "--binary", "HEAD"))
    untracked = []
    for raw in git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0"):
        if raw:
            name = os.fsdecode(raw)
            path = ROOT / name
            require(path.is_file() and not path.is_symlink(), "untracked input must be a regular file")
            untracked.append({"path": name, "sha256": measured_file(path)["sha256"]})
    return {"commit": git("rev-parse", "HEAD").decode().strip(),
            "tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
            "dirty": bool(status), "status_sha256": digest(status),
            "tracked_diff_sha256": changed, "untracked": untracked,
            "cargo_lock_sha256": measured_file(ROOT / "Cargo.lock")["sha256"]}


def finite_env() -> dict[str, str]:
    # No login, credential, Codex registration, inherited proxy or device access.
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "HOME": "/nonexistent", "PYTHONDONTWRITEBYTECODE": "1"}


def _read_storage_proc(path: Path, maximum: int) -> bytes:
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    require(0 < len(raw) <= maximum, "storage metadata capture exceeded bound")
    return raw


def _storage_mount_id(raw: bytes) -> int:
    values = [line.split(b":", 1)[1].strip() for line in raw.splitlines()
              if line.startswith(b"mnt_id:")]
    require(len(values) == 1 and values[0].isdigit() and len(values[0]) <= 20,
            "storage descriptor mount identity is unavailable")
    result = int(values[0])
    require(0 < result < 2**64, "storage descriptor mount identity is invalid")
    return result


def _storage_mount_record(raw: bytes, mount_id: int, device: int) -> dict[str, Any]:
    lines = raw.splitlines()
    require(len(lines) <= 4096, "storage mount inventory exceeded bound")
    records = []
    seen = set()
    for line in lines:
        require(len(line) <= 16384, "storage mount record exceeded bound")
        fields = line.split(b" ")
        require(len(fields) >= 10 and fields[0].isdigit() and len(fields[0]) <= 20,
                "storage mount record is malformed")
        identity = int(fields[0])
        require(0 < identity < 2**64 and identity not in seen,
                "storage mount inventory has ambiguous identities")
        seen.add(identity)
        if identity == mount_id:
            records.append((line, fields))
    require(len(records) == 1, "storage descriptor mount is absent or ambiguous")
    line, fields = records[0]
    require(fields.count(b"-") == 1, "storage mount separator is ambiguous")
    separator = fields.index(b"-")
    require(separator >= 6 and len(fields) == separator + 4,
            "storage mount fields are incomplete")
    require(fields[1].isdigit() and len(fields[1]) <= 20 and
            0 < int(fields[1]) < 2**64 and
            all(field and not any(byte <= 32 or byte == 127 for byte in field)
                for field in fields), "storage mount fields are malformed")
    for encoded in fields[3:5]:
        require(encoded.startswith(b"/"), "storage mount path is not absolute")
        remainder = re.sub(rb"\\(?:040|011|012|134)", b"", encoded)
        require(b"\\" not in remainder, "storage mount path escape is malformed")
    major_minor = fields[2].split(b":")
    require(len(major_minor) == 2 and all(value.isdigit() and len(value) <= 20
                                        for value in major_minor),
            "storage mount device is malformed")
    require(tuple(map(int, major_minor)) == (os.major(device), os.minor(device)),
            "storage descriptor and mount device disagree")
    fs_type = fields[separator + 1]
    require(re.fullmatch(rb"[A-Za-z0-9_.-]{1,128}", fs_type) is not None,
            "storage filesystem type is malformed")
    # Hash the complete kernel record, including root, source, mount options,
    # superoptions and overlay backing paths. Do not expose those paths or
    # potential mount-source credentials in the public artifact.
    return {"filesystem_type": fs_type.decode("ascii"),
            "mountinfo_record_sha256": digest(line)}


def _storage_statfs(descriptor: int) -> dict[str, Any]:
    # Linux LP64 statfs: seven native-word fields, two 32-bit fsid words,
    # three native-word fields and four spare words, total 120 bytes. Never
    # call the native function with a guessed layout on another ABI.
    require(sys.platform == "linux" and platform.machine().lower() in
            {"x86_64", "amd64", "aarch64", "arm64"} and
            ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_long) == 8 and
            ctypes.sizeof(ctypes.c_int) == 4,
            "storage statfs ABI is unsupported")

    class StatFs(ctypes.Structure):
        _fields_ = [("kind", ctypes.c_long), ("block_size", ctypes.c_long),
                    ("blocks", ctypes.c_ulong), ("free", ctypes.c_ulong),
                    ("available", ctypes.c_ulong), ("files", ctypes.c_ulong),
                    ("free_files", ctypes.c_ulong), ("fsid", ctypes.c_int * 2),
                    ("name_length", ctypes.c_long), ("fragment_size", ctypes.c_long),
                    ("flags", ctypes.c_long), ("spare", ctypes.c_long * 4)]

    require(ctypes.sizeof(StatFs) == 120, "storage statfs layout differs")
    function = ctypes.CDLL(None, use_errno=True).fstatfs
    function.argtypes = [ctypes.c_int, ctypes.POINTER(StatFs)]
    function.restype = ctypes.c_int
    result = StatFs()
    require(function(descriptor, ctypes.byref(result)) == 0,
            "storage statfs probe failed")
    fsid = [int(word) & 0xffffffff for word in result.fsid]
    require(any(fsid) and result.block_size > 0,
            "storage filesystem identity is unavailable")
    return {"type_magic": int(result.kind) & 0xffffffffffffffff,
            "fsid": fsid, "block_size": int(result.block_size),
            "flags": int(result.flags) & 0xffffffffffffffff}


def scratch_storage_identity(directory: Path) -> dict[str, Any]:
    base = {"schema": STORAGE_IDENTITY_SCHEMA, "scope": STORAGE_IDENTITY_SCOPE}
    descriptor = None
    try:
        descriptor = os.open(directory, os.O_RDONLY | os.O_CLOEXEC |
                             os.O_DIRECTORY | os.O_NOFOLLOW)
        before = os.fstat(descriptor)
        namespace = Path("/proc/thread-self/ns/mnt").stat()
        boot = _read_storage_proc(Path("/proc/sys/kernel/random/boot_id"), 128).strip()
        require(re.fullmatch(rb"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot)
                is not None, "storage boot identity is invalid")
        fdinfo = Path(f"/proc/thread-self/fdinfo/{descriptor}")
        mount_id = _storage_mount_id(_read_storage_proc(fdinfo, 4096))
        mountinfo = Path("/proc/thread-self/mountinfo")
        mount = _storage_mount_record(_read_storage_proc(mountinfo, 1024 * 1024),
                                      mount_id, before.st_dev)
        filesystem = _storage_statfs(descriptor)
        after_namespace = Path("/proc/thread-self/ns/mnt").stat()
        after = os.fstat(descriptor)
        require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino) and
                (namespace.st_dev, namespace.st_ino) ==
                (after_namespace.st_dev, after_namespace.st_ino) and
                _storage_mount_id(_read_storage_proc(fdinfo, 4096)) == mount_id and
                _storage_mount_record(_read_storage_proc(mountinfo, 1024 * 1024),
                                      mount_id, after.st_dev) == mount and
                _storage_statfs(descriptor) == filesystem and
                _read_storage_proc(Path("/proc/sys/kernel/random/boot_id"), 128).strip() == boot,
                "storage identity changed during capture")
        return {**base, "status": "known", "boot_id_sha256": digest(boot),
                "mount_namespace": {"device": namespace.st_dev, "inode": namespace.st_ino},
                "mount_id": mount_id,
                "device": {"major": os.major(before.st_dev), "minor": os.minor(before.st_dev)},
                "filesystem": filesystem, **mount}
    except (BenchmarkError, OSError, ValueError, AttributeError):
        return {**base, "status": "unavailable", "reason": "storage_probe_unavailable"}
    finally:
        if descriptor is not None:
            os.close(descriptor)


def validate_storage_projection(artifact: dict[str, Any], *, known: bool = False) -> None:
    environment = artifact.get("environment")
    comparison = artifact.get("comparison_identity")
    require(isinstance(environment, dict) and isinstance(comparison, dict) and
            comparison.get("environment") == environment,
            "storage comparison environment projection differs")
    value = environment.get("scratch_storage_identity")
    require(isinstance(value, dict) and value.get("schema") == STORAGE_IDENTITY_SCHEMA and
            value.get("scope") == STORAGE_IDENTITY_SCOPE,
            "storage identity is missing or has a different schema")
    if value.get("status") == "unavailable":
        require(set(value) == {"schema", "scope", "status", "reason"} and
                value["reason"] == "storage_probe_unavailable" and
                environment.get("scratch_filesystem") == "unavailable" and not known,
                "storage identity is unavailable for comparison")
        return
    require(value.get("status") == "known" and set(value) ==
            {"schema", "scope", "status", "boot_id_sha256", "mount_namespace", "mount_id",
             "device", "filesystem", "filesystem_type", "mountinfo_record_sha256"},
            "storage known identity fields differ")
    for field in ("boot_id_sha256", "mountinfo_record_sha256"):
        require(isinstance(value[field], str) and
                re.fullmatch(r"[0-9a-f]{64}", value[field]) is not None,
                "storage identity digest is invalid")
    require(type(value["mount_id"]) is int and 0 < value["mount_id"] < 2**64,
            "storage mount identity is invalid")
    for field, members, minimum in (("mount_namespace", {"device", "inode"}, 1),
                                     ("device", {"major", "minor"}, 0)):
        item = value[field]
        require(isinstance(item, dict) and set(item) == members and
                all(type(number) is int and minimum <= number < 2**64
                    for number in item.values()), "storage numeric identity is invalid")
    fs = value["filesystem"]
    require(isinstance(fs, dict) and set(fs) == {"type_magic", "fsid", "block_size", "flags"} and
            all(type(fs[field]) is int and 0 <= fs[field] < 2**64
                for field in ("type_magic", "block_size", "flags")) and fs["block_size"] > 0 and
            isinstance(fs["fsid"], list) and len(fs["fsid"]) == 2 and
            all(type(word) is int and 0 <= word < 2**32 for word in fs["fsid"]) and any(fs["fsid"]),
            "storage filesystem identity is invalid")
    require(isinstance(value["filesystem_type"], str) and
            re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value["filesystem_type"]) is not None and
            environment.get("scratch_filesystem") == value["filesystem_type"],
            "storage filesystem type is invalid")


def validate_comparison_projection(artifact: dict[str, Any], *, known_storage: bool = False) -> None:
    validate_storage_projection(artifact, known=known_storage)
    configuration = artifact.get("configuration")
    require(isinstance(configuration, dict) and set(configuration) ==
            {"workloads", "build_profile", "concurrency", "output_bytes", "slow_read_ms",
             "timeout_seconds", "max_regression_percent", "gate_policy_version", "repetitions", "warmup"},
            "comparison configuration fields differ")
    workloads = configuration["workloads"]
    require(isinstance(workloads, list) and workloads and
            all(isinstance(name, str) and name in WORKLOADS for name in workloads) and
            len(set(workloads)) == len(workloads) and
            type(configuration["repetitions"]) is int and 1 <= configuration["repetitions"] <= 100 and
            type(configuration["warmup"]) is int and 0 <= configuration["warmup"] <= 10,
            "comparison sampling configuration is invalid")
    require(isinstance(configuration["build_profile"], str) and
            configuration["build_profile"] in {"debug", "release", "custom"} and
            type(configuration["concurrency"]) is int and 1 <= configuration["concurrency"] <= 16 and
            type(configuration["output_bytes"]) is int and 65536 <= configuration["output_bytes"] <= 1048576,
            "comparison configuration values are invalid")
    for field, low, high in (("slow_read_ms", .1, 10), ("timeout_seconds", 1, 60)):
        number = configuration[field]
        require(type(number) in {int, float} and math.isfinite(number) and low <= number <= high,
                "comparison numeric configuration is invalid")
    manifest = validate_implementation_manifest(artifact.get("implementation_manifest"))
    bootstrap = validate_bootstrap_attestation(artifact.get("bootstrap_attestation"), manifest)
    policy = validate_gate_policy(artifact.get("gate_policy"))
    require(configuration["max_regression_percent"] == policy["max_regression_percent"] and
            configuration["gate_policy_version"] == policy["version"],
            "comparison configuration does not bind gate policy")
    executables = artifact.get("executables")
    require(isinstance(executables, dict) and set(executables) == {"host", "core", "python", "shell", "harness"},
            "comparison executable fields differ")
    for name in ("host", "core", "python", "shell"):
        item = executables[name]
        require(isinstance(item, dict) and set(item) ==
                {"path", "requested_path", "size", "sha256", "execution_custody"} and
                isinstance(item["path"], str) and Path(item["path"]).is_absolute() and
                isinstance(item["requested_path"], str) and Path(item["requested_path"]).is_absolute() and
                type(item["size"]) is int and 0 < item["size"] <= MAX_PINNED_EXECUTABLE_BYTES and
                isinstance(item["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None and
                item["execution_custody"] == PINNED_EXECUTABLE_CUSTODY,
                "comparison executable identity is invalid")
    harness = next(item for item in manifest["files"]
                   if item["path"] == "tools/perf/run_product_baseline.py")
    require(executables["harness"] == harness, "comparison harness differs from implementation manifest")
    environment = artifact["environment"]
    require(environment.get("execution_custody") == EXECUTION_CUSTODY,
            "comparison environment execution custody differs")
    expected = {
        "environment": environment,
        "configuration": {key: value for key, value in configuration.items()
                          if key not in {"repetitions", "warmup"}},
        "python_sha256": executables["python"]["sha256"],
        "shell_sha256": executables["shell"]["sha256"],
        "harness_sha256": harness["sha256"],
        "implementation_manifest_sha256": manifest["manifest_sha256"],
        "bootstrap_attestation_sha256": digest(canonical(bootstrap)),
        "gate_policy_sha256": digest(canonical(policy)),
        "execution_custody": EXECUTION_CUSTODY,
    }
    require(artifact["comparison_identity"] == expected,
            "comparison identity does not project the declared environment, configuration and executables")


def _execution_path(name: str, fallback: Path | str) -> str:
    value = EXECUTION_PATHS.get(name, str(fallback))
    require(isinstance(value, str) and value.startswith("/") and "\n" not in value,
            f"invalid pinned execution path for {name}")
    return value


def _require_owned_process_environment() -> None:
    require(platform.system() == "Linux" and hasattr(os, "WNOWAIT") and hasattr(os, "waitid") and
            signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
            "product process ownership requires Linux WNOWAIT and default SIGCHLD")


def _leader_exit_unreaped(process: subprocess.Popen[bytes]) -> Any:
    # Reaping releases the numeric PID/PGID for reuse. Every caller creates a
    # new session and must retain its leader until all possible group signals
    # have finished, including when that leader already exited successfully.
    require(process.returncode is None, "product process leader was already reaped")
    require(os.getpgid(process.pid) == process.pid and os.getsid(process.pid) == process.pid,
            "product process group is not the owned session")
    status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    require(status is None or status.si_code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED),
            "unexpected product process wait status")
    return status


class _ProcessObservationDeadline(BenchmarkError):
    pass


def _group_live_members(process: subprocess.Popen[bytes], deadline: float) -> list[int]:
    members = []
    anchor_seen = False
    with os.scandir("/proc") as entries:
        for count, entry in enumerate(entries, 1):
            require(count <= 131072, "product process membership exceeds finite bound")
            if time.monotonic() >= deadline:
                raise _ProcessObservationDeadline("product process membership deadline exceeded")
            if not entry.name.isdecimal():
                continue
            try:
                with open(Path(entry.path) / "stat", "rb") as stream:
                    raw = stream.read(4097)
                require(len(raw) <= 4096, "product process stat exceeds finite bound")
                fields = raw.rsplit(b") ", 1)[1].split()
                if int(entry.name) == process.pid:
                    require(int(fields[2]) == process.pid and int(fields[3]) == process.pid,
                            "product process anchor identity changed")
                    anchor_seen = True
                if int(fields[2]) == process.pid:
                    require(int(fields[3]) == process.pid, "product process group session changed")
                    if fields[0] not in {b"Z", b"X"}:
                        members.append(int(entry.name))
            except (FileNotFoundError, ProcessLookupError):
                continue
    require(anchor_seen, "product process anchor is not observable")
    if time.monotonic() >= deadline:
        raise _ProcessObservationDeadline("product process membership deadline exceeded")
    return members


def _group_terminal(process: subprocess.Popen[bytes], deadline: float) -> Any:
    quiet_once = False
    while True:
        if time.monotonic() >= deadline:
            return None
        exited = _leader_exit_unreaped(process)
        try:
            quiet = exited is not None and not _group_live_members(process, deadline)
        except _ProcessObservationDeadline:
            # A partial scan supplies no terminal proof. The caller escalates
            # or rejects at its existing deadline; it never accepts a partial
            # empty membership set as successful cleanup.
            return None
        if quiet and quiet_once:
            return exited
        quiet_once = quiet
        if time.monotonic() >= deadline:
            return None
        time.sleep(min(.01, max(0, deadline - time.monotonic())))


def _signal_owned_group(process: subprocess.Popen[bytes], selected: int) -> None:
    _leader_exit_unreaped(process)
    try:
        os.killpg(process.pid, selected)
    except ProcessLookupError:
        pass


def _reap_process_anchor(process: subprocess.Popen[bytes]) -> None:
    # The authenticated facade supplies the only trusted replacement. Its
    # OwnedSessionPopen.wait observes without reaping; direct core fixtures use
    # ordinary Popen.wait. Neither runs until the last group signal is done.
    reaper = globals().get("REAP_PROCESS_ANCHOR")
    if reaper is None:
        process.wait(timeout=1)
    else:
        reaper(process)


def stop(process: subprocess.Popen[bytes]) -> None:
    terminal = False
    try:
        _signal_owned_group(process, signal.SIGTERM)
        terminal = _group_terminal(process, time.monotonic() + 1) is not None
        if not terminal:
            _signal_owned_group(process, signal.SIGKILL)
            terminal = _group_terminal(process, time.monotonic() + 3) is not None
        require(terminal, "product process group cleanup did not reach terminal state")
    except (BenchmarkError, OSError, ValueError, IndexError):
        # Even observation/setup failures must stop this still-anchored group.
        # Failure to inspect its members remains an error; it never becomes a
        # successful cleanup or product sample. No already-reaped PID is used.
        _signal_owned_group(process, signal.SIGKILL)
        deadline = time.monotonic() + 3
        while _leader_exit_unreaped(process) is None and time.monotonic() < deadline:
            time.sleep(.01)
        if _leader_exit_unreaped(process) is not None:
            _reap_process_anchor(process)
        raise
    finally:
        try:
            if terminal:
                _reap_process_anchor(process)
        finally:
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe:
                    try:
                        pipe.close()
                    except OSError:
                        pass


def collect(command: list[str], frames: list[dict], timeout: float,
            read_delay_ms: float = 0) -> tuple[list[dict], dict]:
    payload = b"".join(canonical(frame) + b"\n" for frame in frames)
    require(len(payload) <= 16 * 1024, "benchmark input exceeded fixed bound")
    _require_owned_process_environment()
    started = time.perf_counter_ns()
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=finite_env(), start_new_session=True)
    output = {"stdout": bytearray(), "stderr": bytearray()}
    observed: list[dict] = []
    pending = bytearray()
    next_read = 0.0
    try:
        assert process.stdin and process.stdout and process.stderr
        os.set_blocking(process.stdin.fileno(), False)
        input_offset = 0
        with selectors.DefaultSelector() as selector:
            if payload:
                selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            else:
                process.stdin.close()
            for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map():
                require((time.perf_counter_ns() - started) / 1e9 < timeout, "product process timed out")
                if next_read > time.monotonic():
                    time.sleep(min(0.01, next_read - time.monotonic()))
                for key, _ in selector.select(timeout=0.01):
                    name = key.data
                    if name == "stdin":
                        try:
                            written = os.write(key.fileobj.fileno(), payload[input_offset:])
                        except BlockingIOError:
                            continue
                        require(written > 0, "product stdin made no progress")
                        input_offset += written
                        if input_offset == len(payload):
                            selector.unregister(key.fileobj)
                            process.stdin.close()
                        continue
                    if name == "stdout" and time.monotonic() < next_read:
                        continue
                    data = os.read(key.fileobj.fileno(), 4096 if read_delay_ms else 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    output[name].extend(data)
                    require(sum(map(len, output.values())) <= MAX_CAPTURE, "product output exceeded capture bound")
                    if name == "stdout":
                        next_read = time.monotonic() + read_delay_ms / 1000
                        pending.extend(data)
                        while b"\n" in pending:
                            line, _, tail = pending.partition(b"\n")
                            pending = bytearray(tail)
                            value = strict_json(line)
                            require(isinstance(value, dict) and isinstance(value.get("kind"), str), "invalid host frame")
                            observed.append({"at_ns": time.perf_counter_ns() - started,
                                             "kind": value["kind"], "frame_sha256": digest(line)})
        remaining = timeout - (time.perf_counter_ns() - started) / 1e9
        require(remaining > 0, "product process exceeded deadline")
        exited = _group_terminal(process, time.monotonic() + remaining)
        require(exited is not None, "product process group exceeded deadline")
        code = exited.si_status if exited.si_code == os.CLD_EXITED else -exited.si_status
        require(code == 0, f"product exit {code}: {bytes(output['stderr'])[:2048]!r}")
        require(not pending, "incomplete host JSONL frame")
        decoded = [strict_json(line) for line in output["stdout"].splitlines()]
        return decoded, {"elapsed_ns": time.perf_counter_ns() - started, "exit_code": code,
                         "stdout_bytes": len(output["stdout"]), "stderr_bytes": len(output["stderr"]),
                         "stdout_sha256": digest(output["stdout"]), "stderr_sha256": digest(output["stderr"]),
                         "frames": observed}
    finally:
        stop(process)


def hello() -> dict:
    return {"kind": "hello", "seq": 0, "payload": {
        "protocol": "trillionnium.agent.turn.v1", "protocol_version": 1}}


def turn() -> dict:
    return {"kind": "turn.start", "seq": 1, "direction": "client_to_host", "payload": {
        "protocol": "trillionnium.agent.turn.v1", "protocol_version": 1,
        "session_id": "session-product-benchmark", "task_id": "task-product-benchmark",
        "turn_id": "turn-product-benchmark", "user_input": "local reproducible source benchmark"}}


def write_provider(root: Path, command: str) -> Path:
    provider = root / "provider.sh"
    call = {"protocol": "trillionnium.owner-open.provider-jsonl.v1", "kind": "tool.call",
            "seq": 0, "call": {"call_id": "call-product-benchmark", "tool": "shell.exec",
                                  "command": command, "timeout_ms": 5000}}
    terminal = {"protocol": "trillionnium.owner-open.provider-jsonl.v1", "kind": "turn.complete",
                "seq": 1, "summary": "benchmark fixture complete"}
    provider.write_text("#!" + _execution_path("shell", "/bin/sh") +
                        "\nset -eu\nprintf x >> " + shlex.quote(str(root / "provider-starts")) +
                        "\nIFS= read -r request\nprintf '%s\\n' " + shlex.quote(canonical(call).decode()) +
                        "\nIFS= read -r result\ncase \"$result\" in *'\"kind\":\"tool.result\"'*) ;; *) exit 12 ;; esac\n" +
                        "printf '%s\\n' " + shlex.quote(canonical(terminal).decode()) + "\n")
    provider.chmod(0o700)
    return provider


def host_command(host: Path, core: Path, root: Path, provider: Path) -> list[str]:
    return [str(host), "--transport-core", str(core), "--provider", str(provider),
            "--shell", _execution_path("shell", "/bin/sh"),
            "--event-store", str(root / "events.jsonl"),
            "--job-store", str(root / "jobs.jsonl")]


def validate_turn(frames: list[dict], expected: bytes) -> dict:
    require(bool(frames) and frames[0]["kind"] == "hello.ack", "missing product handshake")
    require(frames[0]["payload"].get("durable_event_store") is True, "event store not durable")
    terminals = [f["payload"] for f in frames if f["kind"] == "turn.end"]
    results = [f["payload"] for f in frames if f["kind"] == "tool.result"]
    require(len(terminals) == 1 and terminals[0].get("status") == "completed", "turn did not complete")
    require(terminals[0].get("event_log_status") == "durable", "turn lost durability")
    require(len(results) == 1 and results[0].get("terminal_kind") == "exited" and
            results[0].get("exit_code") == 0 and not results[0].get("output_truncated"), "tool failed or truncated")
    chunks = [base64.b64decode(f["payload"]["data"], validate=True)
              for f in frames if f["kind"] == "tool.stdout"]
    require(b"".join(chunks) == expected, "tool output differs from expected exact bytes")
    return {"terminal": "completed", "event_log_status": "durable", "tool_output_bytes": len(expected),
            "tool_output_sha256": digest(expected)}


def run_turn_sample(host: Path, core: Path, root: Path, size: int, timeout: float,
                    slow_ms: float = 0, replay: bool = False) -> dict:
    root.mkdir(mode=0o700)
    expected = b"x" * size
    command = (shlex.quote(_execution_path("python", Path(sys.executable).resolve())) + " -I -c " +
               shlex.quote(f"import sys;sys.stdout.write('x'*{size})") +
               "; printf x >> " + shlex.quote(str(root / "effects")))
    provider = write_provider(root, command)
    args = host_command(host, core, root, provider)
    first, observation = collect(args, [hello(), turn()], timeout, slow_ms)
    validation = validate_turn(first, expected)
    require((root / "effects").read_bytes() == b"x", "effect count differs from one")
    if replay:
        second, replay_observation = collect(args, [hello(), turn()], timeout)
        validate_turn(second, expected)
        require((root / "effects").read_bytes() == b"x", "restart replay repeated tool effect")
        require((root / "provider-starts").read_bytes() == b"x", "restart replay respawned provider")
        ids = lambda frames: [f.get("event_id") for f in frames if f.get("turn_stream_id")]
        require(ids(first) == ids(second), "replayed event identities changed")
        observation = {**replay_observation, "setup_observation": observation,
                       "measured_phase": "second_host_start_to_replayed_completion"}
        validation["repeat_effects"] = 0
    return {**observation, "validation": validation,
            "store_bytes_after": sum(p.stat().st_size for p in root.rglob("*") if p.is_file() and
                any(part.startswith(("events.jsonl", "jobs.jsonl")) for part in p.relative_to(root).parts))}


def run_job_sample(host: Path, core: Path, root: Path, mode: str, timeout: float) -> dict:
    root.mkdir(mode=0o700)
    expected = f"product-{mode}-job".encode()
    provider = write_provider(root, "exit 99")  # Must remain unused for local jobs.
    scope = {"session_id": "session-product-benchmark", "profile_id": "owner-open",
             "task_id": "task-product-benchmark", "turn_id": "turn-product-benchmark",
             "turn_stream_id": "stream-product-benchmark", "job_id": "job-product-benchmark"}
    start = {"kind": "job.start", "seq": 1, "direction": "client_to_host", "payload": {
        **scope, "operation_id": "start-product-benchmark", "tool": "shell.job",
        "target_id": "rootlinux", "mode": mode, "command": "printf " + shlex.quote(expected.decode())}}
    wait = {"kind": "job.wait", "seq": 2, "direction": "client_to_host", "payload": {
        **scope, "operation_id": "wait-product-benchmark", "inclusive_cursor": 0,
        "durable_inclusive_cursor": 0, "limit": 32, "timeout_ms": 5000, "poll_interval_ms": 5}}
    frames, observation = collect(host_command(host, core, root, provider), [hello(), start, wait], timeout)
    require(frames[0]["payload"].get("job_journal_status") == "durable", "job journal unavailable")
    result = [f["payload"] for f in frames if f["kind"] == "job.result"]
    require(len(result) == 1 and result[0].get("terminal_kind") == "exited" and
            result[0].get("exit_code") == 0, "job did not terminate successfully")
    data = b"".join(base64.b64decode(f["payload"]["data"], validate=True)
                    for f in frames if f["kind"] == "job.output")
    require(data == expected, "job output differs from expected bytes")
    require(not (root / "provider-starts").exists(), "local job unexpectedly started provider")
    return {**observation, "validation": {"terminal": "exited", "job_mode": mode,
            "tool_output_sha256": digest(data), "tool_output_bytes": len(data), "job_journal_status": "durable"}}


def socket_line(sock: socket.socket, pending: bytearray, deadline: float) -> dict:
    while b"\n" not in pending:
        remaining = deadline - time.monotonic()
        require(remaining > 0, "broker client deadline exceeded")
        sock.settimeout(remaining)
        data = sock.recv(65536)
        require(bool(data), "broker connection closed before terminal")
        pending.extend(data)
        require(len(pending) <= MAX_CAPTURE, "broker frame exceeded bound")
    line, _, tail = pending.partition(b"\n")
    pending[:] = tail
    return strict_json(line)


def run_broker_sample(host: Path, core: Path, root: Path, clients: int, timeout: float) -> dict:
    root.mkdir(mode=0o700)
    provider = write_provider(root, "exit 99")
    # Broker admission requires a private, single-link executable. These exact
    # copies have the same measured bytes as the caller-selected product ELFs.
    upstream = root / "host"
    shutil.copyfile(host, upstream)
    upstream.chmod(0o700)
    broker = (Path(EXECUTION_PATHS["broker"]) if "broker" in EXECUTION_PATHS
              else _write_broker_custody(root))
    _assert_broker_custody(broker.parent)
    command = [_execution_path("python", Path(sys.executable).resolve()),
               str(broker),
               "--socket", str(root / "socket"), "--descriptor", str(root / "descriptor.json"),
               "--token-file", str(root / "token"), "--broker-id", "product-benchmark",
               "--upstream", str(upstream), "--max-clients", str(clients),
               "--max-inflight-requests", str(clients)]
    # Sibling imports resolve only from this exact private snapshot closure.
    # There is no mutable repository path or PYTHONPATH fallback.
    for arg in host_command(upstream, core, root, provider)[1:]:
        command.append("--upstream-arg=" + arg)
    with tempfile.TemporaryFile() as diagnostic:
        _require_owned_process_environment()
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=diagnostic, stderr=diagnostic,
                                   env=finite_env(), start_new_session=True)
        try:
            deadline = time.monotonic() + timeout
            descriptor = root / "descriptor.json"
            while not descriptor.exists():
                require(_leader_exit_unreaped(process) is None, "broker exited during startup")
                require(time.monotonic() < deadline, "broker startup timed out")
                time.sleep(0.01)
            identity = strict_json(descriptor.read_bytes())
            token = (root / "token").read_text().strip()
            barrier = threading.Barrier(clients, timeout=timeout)
            def inspect(index: int) -> dict:
                with socket.socket(socket.AF_UNIX) as sock:
                    sock.settimeout(timeout)
                    sock.connect(str(root / "socket"))
                    pending = bytearray()
                    sock.sendall(canonical({"kind": "broker.hello", "broker_epoch": identity["broker_epoch"],
                                           "client_id": f"client-{index}", "token": token}) + b"\n")
                    ack = socket_line(sock, pending, time.monotonic() + timeout)
                    require(ack.get("kind") == "broker.hello.ack", "broker handshake failed")
                    barrier.wait()
                    started = time.perf_counter_ns()
                    scope = {"session_id": "session-perf", "profile_id": "owner-open", "task_id": "task-perf",
                             "turn_id": "turn-perf", "turn_stream_id": "stream-perf", "job_id": f"missing-{index}"}
                    request_id = f"inspect-{index}"
                    frame = {"kind": "job.inspect", "seq": index + 1, "direction": "client_to_host", "payload": scope}
                    sock.sendall(canonical({"kind": "request", "request_id": request_id, "frame": frame,
                                           "expected_kinds": ["job.inspect.result"], "expected_job_id": scope["job_id"],
                                           "timeout_ms": min(10000, int(timeout * 1000))}) + b"\n")
                    observations = []
                    while True:
                        value = socket_line(sock, pending, time.monotonic() + timeout)
                        observations.append({"kind": value.get("kind"), "sha256": digest(canonical(value))})
                        require(len(observations) <= 64, "broker observations exceeded bound")
                        if value.get("kind") in {"result", "error"} and value.get("request_id") == request_id:
                            require(value["kind"] == "result", f"broker request failed: {value}")
                            frame = value.get("frame", {})
                            require(frame.get("kind") == "job.error" and
                                    frame.get("payload", {}).get("code") == "job_request_failed" and
                                    frame.get("payload", {}).get("message") == "owner-open job is not registered" and
                                    frame.get("job_id") == scope["job_id"] and
                                    value.get("broker_response_connection_id") == f"client-{index}",
                                    "broker did not preserve exact missing-job response and client ownership")
                            return {"elapsed_ns": time.perf_counter_ns() - started, "observations": observations}
            started = time.perf_counter_ns()
            with ThreadPoolExecutor(max_workers=clients) as executor:
                rows = list(executor.map(inspect, range(clients)))
            return {"elapsed_ns": time.perf_counter_ns() - started, "clients": rows,
                    "validation": {"expected_missing_job_responses": len(rows), "shared_upstream": True},
                    "measured_phase": "connect_authenticate_and_concurrent_inspect_not_broker_startup"}
        except Exception as error:
            diagnostic.seek(0)
            raise BenchmarkError(f"{error}; broker diagnostic={diagnostic.read(2048)!r}") from error
        finally:
            stop(process)


def percentile(values: list[float], q: float) -> float:
    return sorted(values)[max(0, math.ceil(len(values) * q) - 1)]


def summarize(samples: list[dict]) -> dict:
    summaries = {}
    for name in sorted({row["workload"] for row in samples}):
        rows = [row for row in samples if row["workload"] == name and not row["warmup"]]
        if not rows:
            continue
        values = [row["elapsed_ns"] / 1e6 for row in rows]
        summaries[name] = {"samples": len(rows), "latency_p50_ms": statistics.median(values),
                           "latency_p95_ms": percentile(values, .95), "latency_p99_ms": percentile(values, .99),
                           "latency_max_ms": max(values), "latency_min_ms": min(values),
                           "latency_stdev_ms": statistics.stdev(values) if len(values) > 1 else None,
                           "throughput_per_sec": sum(row["operations"] for row in rows) /
                               (sum(row["elapsed_ns"] for row in rows) / 1e9),
                           "measurement_unit": "batch_wall_time_including_declared_client_work"}
    return summaries


def validate_artifact(value: Any) -> dict:
    require(isinstance(value, dict) and value.get("schema") == SCHEMA, "wrong baseline schema")
    body = dict(value)
    claimed = body.pop("artifact_digest", None)
    require(claimed == digest(canonical(body)), "baseline content digest mismatch")
    manifest = validate_implementation_manifest(value.get("implementation_manifest"))
    bootstrap = validate_bootstrap_attestation(
        value.get("bootstrap_attestation"), manifest
    )
    policy = validate_gate_policy(value.get("gate_policy"))
    identity = value.get("comparison_identity")
    require(isinstance(identity, dict), "missing comparison identity")
    validate_comparison_projection(value)
    require(identity.get("implementation_manifest_sha256") == manifest["manifest_sha256"],
            "comparison identity does not bind implementation manifest")
    require(identity.get("bootstrap_attestation_sha256") == digest(canonical(bootstrap)),
            "comparison identity does not bind bootstrap attestation")
    require(identity.get("gate_policy_sha256") == digest(canonical(policy)),
            "comparison identity does not bind gate policy")
    require(value.get("qualification") == "L1_HOST_SOURCE_BENCHMARK_ONLY" and
            value.get("public_release") is False, "baseline widened its claim")
    samples = value.get("samples")
    require(isinstance(samples, list) and 0 < len(samples) <= 8 * 110, "invalid sample count")
    seen = set()
    for row in samples:
        require(isinstance(row, dict) and row.get("workload") in WORKLOADS, "invalid workload sample")
        require(type(row.get("warmup")) is bool and type(row.get("repetition")) is int, "invalid repetition")
        key = (row["workload"], row["warmup"], row["repetition"])
        require(key not in seen, "duplicate sample identity")
        seen.add(key)
        require(type(row.get("elapsed_ns")) is int and 0 < row["elapsed_ns"] < 600 * 10**9, "invalid elapsed sample")
        require(type(row.get("operations")) is int and 1 <= row["operations"] <= 32, "invalid operations")
        require(row.get("correctness_validated") is True, "unvalidated baseline sample")
    configuration = value.get("configuration", {})
    workloads = configuration.get("workloads")
    repetitions, warmup = configuration.get("repetitions"), configuration.get("warmup")
    require(isinstance(workloads, list) and bool(workloads) and
            all(name in WORKLOADS for name in workloads) and len(set(workloads)) == len(workloads), "invalid configured workloads")
    require(type(repetitions) is int and 1 <= repetitions <= 100 and
            type(warmup) is int and 0 <= warmup <= 10, "invalid configured repetitions")
    require(configuration.get("max_regression_percent") == policy["max_regression_percent"] and
            configuration.get("gate_policy_version") == policy["version"],
            "configuration does not bind reviewed gate policy")
    expected = {(name, is_warmup, index) for name in workloads
                for is_warmup, count in ((True, warmup), (False, repetitions)) for index in range(count)}
    require(seen == expected, "baseline omits or adds configured samples")
    require(value.get("summaries") == summarize(samples), "summary does not match raw samples")
    require(value.get("failures") == [], "previous baseline contains correctness failures")
    return value


def regression_gate(current: dict, previous: dict | None,
                    threshold_percent: float | None = None) -> dict:
    policy = validate_gate_policy(current.get("gate_policy"))
    reviewed_threshold = policy["max_regression_percent"]
    if threshold_percent is not None:
        require(threshold_percent == reviewed_threshold,
                "caller threshold differs from reviewed gate policy")
    if current["failures"]:
        return {"status": "FAIL_CORRECTNESS", "passed": False, "regressions": []}
    if previous is None:
        return {"status": "BASELINE_RECORDED_NO_COMPARISON", "passed": False, "regressions": []}
    validate_comparison_projection(current, known_storage=True)
    validate_comparison_projection(previous, known_storage=True)
    previous_policy = validate_gate_policy(previous.get("gate_policy"))
    require(policy == previous_policy, "baseline gate policy differs")
    require(current["comparison_identity"] == previous["comparison_identity"], "incompatible environment or workload configuration")
    require(set(current["summaries"]) == set(previous["summaries"]), "baseline workload set differs")
    if min(s["samples"] for a in (current, previous) for s in a["summaries"].values()) < policy["minimum_repetitions"]:
        return {"status": "INSUFFICIENT_REPETITIONS", "passed": False, "regressions": []}
    comparisons = []
    for name, summary in current["summaries"].items():
        old = previous["summaries"][name]
        for metric in policy["metrics"]:
            delta = (summary[metric] / old[metric] - 1) * 100
            comparisons.append({"workload": name, "metric": metric, "previous": old[metric],
                                "current": summary[metric], "regression_percent": delta,
                                "regressed": delta > reviewed_threshold})
    regressions = [row for row in comparisons if row["regressed"]]
    return {"status": "FAIL_REGRESSION" if regressions else "PASS_COMPARISON",
            "passed": not regressions, "threshold_percent": reviewed_threshold,
            "gate_policy_version": policy["version"],
            "minimum_repetitions": policy["minimum_repetitions"],
            "comparisons": comparisons, "regressions": regressions,
            "interpretation": "deterministic observed P50/P95 reviewed-policy threshold; not a statistical significance or P99 SLO claim"}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, type=Path)
    parser.add_argument("--core", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--build-profile", choices=("debug", "release", "custom"), default="custom")
    parser.add_argument("--scratch-parent", type=Path)
    parser.add_argument("--require-comparison", action="store_true")
    parser.add_argument("--require-clean-source", action="store_true")
    parser.add_argument("--workloads", nargs="+", choices=WORKLOADS, default=list(WORKLOADS))
    parser.add_argument("--repetitions", type=int, default=10)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--output-bytes", type=int, default=262144)
    parser.add_argument("--slow-read-ms", type=float, default=1)
    parser.add_argument("--timeout-seconds", type=float, default=15)
    parser.add_argument("--max-regression-percent", type=float, default=MAX_REGRESSION_PERCENT)
    args = parser.parse_args(argv)
    for name, low, high in (("repetitions", 1, 100), ("warmup", 0, 10), ("concurrency", 1, 16),
                            ("output_bytes", 65536, 1048576), ("slow_read_ms", 0.1, 10),
                            ("timeout_seconds", 1, 60), ("max_regression_percent", 0, 1000)):
        value = getattr(args, name)
        if not math.isfinite(value) or not low <= value <= high:
            parser.error(f"--{name.replace('_', '-')} must be in {low}..{high}")
    if args.max_regression_percent != MAX_REGRESSION_PERCENT:
        parser.error(f"--max-regression-percent is fixed by {GATE_POLICY_VERSION} at {MAX_REGRESSION_PERCENT:g}")
    if len(set(args.workloads)) != len(args.workloads):
        parser.error("workloads must be unique")
    return args


def _run_with_custody(
    args: argparse.Namespace,
    pins: dict[str, PinnedExecutable],
    custody_root: Path,
) -> dict:
    global EXECUTION_PATHS
    host = pins["host"].execution_path
    core = pins["core"].execution_path
    identities = {
        name: dict(pin.identity) for name, pin in pins.items()
    }
    implementation = implementation_manifest()
    validate_implementation_manifest(implementation)
    bootstrap = bootstrap_attestation()
    harness = next(
        item for item in implementation["files"]
        if item["path"] == "tools/perf/run_product_baseline.py"
    )
    identities["harness"] = dict(harness)
    policy = gate_policy()
    source = source_identity()
    require(not args.require_clean_source or not source["dirty"], "clean source required")
    previous = None
    if args.previous:
        require(args.previous.is_file() and not args.previous.is_symlink(),
                "previous baseline must be a regular nonsymlink file")
        with args.previous.open("rb") as stream:
            previous_bytes = stream.read(MAX_ARTIFACT + 1)
        require(len(previous_bytes) <= MAX_ARTIFACT, "previous baseline exceeds bound")
        previous = validate_artifact(strict_json(previous_bytes))
    config = {name: getattr(args, name) for name in (
        "concurrency", "output_bytes", "slow_read_ms", "timeout_seconds", "build_profile"
    )}
    config["workloads"] = args.workloads
    config["max_regression_percent"] = policy["max_regression_percent"]
    config["gate_policy_version"] = policy["version"]
    environment = {
        "system": platform.system(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "python_version": platform.python_version(),
        "cpu_model": next((
            line.split(":", 1)[1].strip()
            for line in Path("/proc/cpuinfo").read_text().splitlines()
            if line.startswith("model name")
        ), "unavailable"),
        "cpu_affinity": sorted(os.sched_getaffinity(0)),
        "machine_id_sha256": digest(Path("/etc/machine-id").read_bytes()),
        "cpu_governors": sorted({
            path.read_text().strip()
            for path in Path("/sys/devices/system/cpu").glob(
                "cpu[0-9]*/cpufreq/scaling_governor"
            )
        }),
        "execution_custody": "verified-private-single-link-copies-v1",
    }
    artifact = {
        "schema": SCHEMA,
        "qualification": "L1_HOST_SOURCE_BENCHMARK_ONLY",
        "public_release": False,
        "generated_at_unix_ns": time.time_ns(),
        "source": source,
        "executables": identities,
        "implementation_manifest": implementation,
        "bootstrap_attestation": bootstrap,
        "gate_policy": policy,
        "binary_source_binding": (
            "caller-selected binaries copied from verified source descriptors "
            "to private single-link execution files; build provenance not attested"
        ),
        "environment": environment,
        "configuration": {
            **config,
            "repetitions": args.repetitions,
            "warmup": args.warmup,
        },
        "comparison_identity": {
            "environment": environment,
            "configuration": config,
            "python_sha256": identities["python"]["sha256"],
            "shell_sha256": identities["shell"]["sha256"],
            "harness_sha256": identities["harness"]["sha256"],
            "implementation_manifest_sha256": implementation["manifest_sha256"],
            "bootstrap_attestation_sha256": digest(canonical(bootstrap)),
            "gate_policy_sha256": digest(canonical(policy)),
            "execution_custody": "verified-private-single-link-copies-v1",
        },
        "workload_descriptions": {
            name: WORKLOADS[name] for name in args.workloads
        },
        "unavailable_measurements": UNAVAILABLE,
        "samples": [],
        "failures": [],
        "limitations": [
            "No installed Root Linux, Android, device, crash, power-loss or release qualification",
            "Fresh processes and independent session stores; not a long-lived production throughput SLO",
            "Raw timing samples and frame metadata retained; full stdout represented by byte count/digest",
            "Replayed fixture completion is clean-restart recovery, not ambiguous-effect crash recovery",
            "No CPU/RSS/lock/fsync/fairness instrumentation; these values remain explicitly unavailable",
            "P99 descriptive only; P50/P95 threshold comparison is not statistical significance",
            "Dynamic libraries, kernel state and the complete runtime filesystem are not recursively attested",
        ],
    }
    with tempfile.TemporaryDirectory(
        prefix="tos-perf-work-", dir=args.scratch_parent
    ) as temporary:
        root = Path(temporary)
        storage = scratch_storage_identity(root)
        artifact["environment"]["scratch_filesystem"] = storage.get("filesystem_type", "unavailable")
        artifact["environment"]["scratch_storage_identity"] = storage
        for name in args.workloads:
            for index in range(args.warmup + args.repetitions):
                warmup = index < args.warmup
                sample_root = root / f"{name}-{index}"
                try:
                    for pin in pins.values():
                        pin.assert_execution_copy()
                    operations = 1
                    if name == "concurrent_turns":
                        sample_root.mkdir(mode=0o700)
                        started = time.perf_counter_ns()
                        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
                            rows = list(executor.map(
                                lambda item: run_turn_sample(
                                    host,
                                    core,
                                    sample_root / str(item),
                                    16,
                                    args.timeout_seconds,
                                ),
                                range(args.concurrency),
                            ))
                        observation = {
                            "elapsed_ns": time.perf_counter_ns() - started,
                            "sessions": rows,
                        }
                        operations = args.concurrency
                    elif name == "broker_inspect":
                        observation = run_broker_sample(
                            host,
                            core,
                            sample_root,
                            args.concurrency,
                            args.timeout_seconds,
                        )
                        operations = args.concurrency
                    elif name in {"pipe_job", "pty_job"}:
                        observation = run_job_sample(
                            host,
                            core,
                            sample_root,
                            name.split("_")[0],
                            args.timeout_seconds,
                        )
                    else:
                        observation = run_turn_sample(
                            host,
                            core,
                            sample_root,
                            args.output_bytes
                            if name in {"large_output", "slow_consumer"}
                            else 16,
                            args.timeout_seconds,
                            args.slow_read_ms if name == "slow_consumer" else 0,
                            replay=name == "restart_replay",
                        )
                    artifact["samples"].append({
                        "workload": name,
                        "warmup": warmup,
                        "repetition": index if warmup else index - args.warmup,
                        "operations": operations,
                        "correctness_validated": True,
                        **observation,
                    })
                except (
                    BenchmarkError,
                    OSError,
                    subprocess.SubprocessError,
                    json.JSONDecodeError,
                ) as error:
                    artifact["failures"].append({
                        "workload": name,
                        "repetition": index,
                        "error": str(error)[:4096],
                    })
                    break
                finally:
                    if sample_root.exists():
                        shutil.rmtree(sample_root)
        if scratch_storage_identity(root) != artifact["environment"]["scratch_storage_identity"]:
            artifact["failures"].append({"error": "scratch storage identity changed during benchmark"})
    artifact["source_after"] = source_identity()
    if artifact["source_after"] != source:
        artifact["failures"].append({"error": "source changed during benchmark"})
    for name, pin in pins.items():
        try:
            pin.assert_execution_copy()
            pin.assert_source_selection()
        except (BenchmarkError, OSError) as error:
            artifact["failures"].append({
                "error": f"{name} executable custody failed: {error}"
            })
    try:
        if live_implementation_manifest() != implementation:
            artifact["failures"].append({
                "error": "measurement implementation source paths changed during benchmark"
            })
    except (BenchmarkError, OSError) as error:
        artifact["failures"].append({
            "error": f"cannot revalidate measurement implementation paths: {error}"
        })
    artifact["summaries"] = summarize(artifact["samples"])
    try:
        artifact["gate"] = regression_gate(artifact, previous)
    except BenchmarkError as error:
        artifact["gate"] = {
            "status": "INCOMPATIBLE_BASELINE",
            "passed": False,
            "reason": str(error),
        }
    artifact["previous_artifact_digest"] = (
        previous["artifact_digest"] if previous else None
    )
    artifact["artifact_digest"] = digest(canonical(artifact))
    return artifact


def run(args: argparse.Namespace) -> dict:
    global EXECUTION_PATHS, EXECUTION_PASS_FDS
    require(sys.platform == "linux", "product benchmark requires Linux")
    custody_parent = args.scratch_parent
    with tempfile.TemporaryDirectory(
        prefix="tos-perf-custody-", dir=custody_parent
    ) as temporary:
        custody_root = Path(temporary)
        os.chmod(custody_root, 0o700)
        require("\n" not in str(custody_root), "invalid custody directory")
        pins = {
            "host": PinnedExecutable(args.host, custody_root, "host"),
            "core": PinnedExecutable(args.core, custody_root, "core"),
            "python": PinnedExecutable(Path(sys.executable).resolve(strict=True), custody_root, "python"),
            "shell": PinnedExecutable(Path("/bin/sh").resolve(strict=True), custody_root, "shell"),
        }
        require(PINNED_IMPLEMENTATION_FILES is not None and
                PINNED_IMPLEMENTATION_SOURCES is not None,
                "performance Python implementation is not snapshot-bound")
        broker = _write_broker_custody(custody_root)
        prior_paths, prior_fds = EXECUTION_PATHS, EXECUTION_PASS_FDS
        EXECUTION_PATHS = {
            name: str(pin.execution_path) for name, pin in pins.items()
        }
        EXECUTION_PATHS["broker"] = str(broker)
        EXECUTION_PASS_FDS = ()
        try:
            result = _run_with_custody(args, pins, custody_root)
            _assert_broker_custody(broker.parent)
            return result
        finally:
            EXECUTION_PATHS = prior_paths
            EXECUTION_PASS_FDS = prior_fds

def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        require(not args.output.exists() and not args.output.is_symlink(), "output already exists")
        require(args.output.parent.is_dir(), "output parent must exist")
        result = run(args)
        encoded = canonical(result) + b"\n"
        require(len(encoded) <= MAX_ARTIFACT, "artifact exceeded bound")
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        print(json.dumps({"output": str(args.output), "samples": len(result["samples"]),
                          "gate": result["gate"]["status"], "failures": result["failures"]}))
        if result["failures"] or result["gate"]["status"] in {"FAIL_REGRESSION", "INCOMPATIBLE_BASELINE"}:
            return 2
        if args.require_comparison and not result["gate"]["passed"]:
            return 2
        return 0
    except (BenchmarkError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(f"product benchmark failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
