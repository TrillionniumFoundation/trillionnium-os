"""Strict mechanical helpers for the owner-open multi-connection broker."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import functools
import threading
import time
from typing import Any, BinaryIO

MAX_LINE_BYTES = 1024 * 1024
MAX_DESCRIPTOR_BYTES = 1024 * 1024
MAX_TOKEN_BYTES = 256
MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
MAX_ARGV_ITEMS = 4096
MAX_ARGUMENT_BYTES = 64 * 1024
MAX_TOTAL_ARGV_BYTES = 1024 * 1024
ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,256}$")
TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")

# Evidence only: off until explicitly configured by the service entrypoint.
# Hooks never do file I/O and never wait behind a product/trace lock. Export is
# a separate outer operation after workers stopped; loss/open spans reject it
# as complete evidence. No semantic success or installed qualification is minted.
TRACE_STAGES = frozenset({
    "broker_accept", "broker_auth", "broker_queue_wait", "broker_forward",
    "host_decode", "host_capacity_wait", "journal_append", "journal_fsync",
    "provider_spawn", "provider_first_event", "provider_wait", "callback_admission",
    "tool_spawn", "tool_output", "tool_exit", "tool_cleanup", "terminal_persistence",
    "delivery_queue_wait", "client_delivery",
})
TRACE_MAX_RECORDS = 8192
TRACE_MAX_EXPORT_BYTES = 8 * 1024 * 1024
_PERFORMANCE_TRACE = None


class PerformanceTrace:
    def __init__(self, sample_id: str, role: str, capacity: int = TRACE_MAX_RECORDS):
        pattern = r"[A-Za-z0-9_.:/-]{1,128}"
        if (not isinstance(sample_id, str) or not re.fullmatch(pattern, sample_id)
                or not isinstance(role, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", role) or role in {".", ".."}
                or type(capacity) is not int or not 1 <= capacity <= TRACE_MAX_RECORDS):
            raise ValueError("trace identifier/capacity outside fixed bounds")
        self.sample_id, self.role, self.capacity = sample_id, role, capacity
        self.records = []
        self.open = self.next = 0
        self.loss_observed = False
        self.lock = threading.Lock()

    def start(self, stage: str, key: str, deferred: bool = False):
        if stage not in TRACE_STAGES or not isinstance(key, str) or len(key) > 4096:
            self.loss_observed = True
            return _NO_PERFORMANCE_SPAN
        try:
            encoded = key.encode()
        except UnicodeError:
            self.loss_observed = True
            return _NO_PERFORMANCE_SPAN
        if len(encoded) > 4096:
            self.loss_observed = True
            return _NO_PERFORMANCE_SPAN
        start = time.monotonic_ns()
        pid, tid = os.getpid(), threading.get_native_id()
        if not (0 <= start < (1 << 64) and 0 < pid < (1 << 32) and 0 < tid < (1 << 63)):
            self.loss_observed = True
            return _NO_PERFORMANCE_SPAN
        scope = hashlib.sha256(encoded).hexdigest()
        if not self.lock.acquire(blocking=False):
            self.loss_observed = True
            return _NO_PERFORMANCE_SPAN
        try:
            if self.next >= (1 << 64) - 1 or self.open + len(self.records) >= self.capacity:
                self.loss_observed = True
                return _NO_PERFORMANCE_SPAN
            sequence = self.next; self.next += 1; self.open += 1
        finally:
            self.lock.release()
        return PerformanceSpan(self, {
            "sequence": sequence, "stage": stage, "scope_sha256": scope,
            "pid": pid, "tid": tid,
            "start_ns": start, "end_ns": None, "end": "unfinished",
        }, deferred)

    def snapshot(self):
        if not self.lock.acquire(blocking=False):
            raise ValueError("trace snapshot busy")
        try:
            return {
                "schema": "org.trillionnium.actual-monotonic-stage-trace.v1",
                "sample_id": self.sample_id, "producer_role": self.role,
                "clock": "CLOCK_MONOTONIC", "capacity_records": self.capacity,
                "loss_observed": self.loss_observed, "lost_records": None,
                "lost_count_semantics": "unavailable", "open_spans": self.open,
                "snapshot_without_observed_loss": not self.loss_observed and self.open == 0,
                "snapshot_only": True, "producer_quiescence_proven": False,
                "trace_complete": False,
                "installed_qualified": False,
                "records": [dict(record) for record in self.records],
            }
        finally:
            self.lock.release()


class PerformanceSpan:
    def __init__(self, recorder=None, record=None, deferred=False):
        self.recorder, self.record, self.deferred = recorder, record, deferred

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        self.finish("exception" if kind else "scope_exit_unclassified")
        return False

    def finish(self, end="observed_boundary"):
        recorder, record = self.recorder, self.record
        self.recorder = self.record = None
        if recorder is None:
            return
        if end not in {"observed_boundary", "abandoned", "exception", "scope_exit_unclassified"}:
            end = "abandoned"
        now = time.monotonic_ns()
        if end == "abandoned" or not record["start_ns"] <= now < (1 << 64):
            recorder.loss_observed = True
        if not record["start_ns"] <= now < (1 << 64):
            now = record["start_ns"]
        record["end_ns"], record["end"] = now, end
        if not recorder.lock.acquire(blocking=False):
            # Open count is intentionally not guessed down after loss.
            recorder.loss_observed = True
            return
        try:
            recorder.open -= 1
            if len(recorder.records) >= recorder.capacity:
                recorder.loss_observed = True
            else:
                recorder.records.append(record)
        finally:
            recorder.lock.release()


class _NoPerformanceSpan:
    __slots__ = ()

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        return False

    def finish(self, end="observed_boundary"):
        pass


_NO_PERFORMANCE_SPAN = _NoPerformanceSpan()


def performance_span(stage: str, key: str = "", deferred: bool = False):
    recorder = _PERFORMANCE_TRACE
    return _NO_PERFORMANCE_SPAN if recorder is None else recorder.start(stage, key, deferred)


def performance_trace_enabled():
    return _PERFORMANCE_TRACE is not None


def performance_stage(stage: str):
    def decorate(function):
        @functools.wraps(function)
        def call(*args, **kwargs):
            # Disabled hooks do not inspect caller properties or arguments.
            if _PERFORMANCE_TRACE is None:
                return function(*args, **kwargs)
            key = kwargs.get("label", function.__qualname__)
            for arg in args:
                digest = getattr(arg, "request_sha256", None)
                if isinstance(digest, str):
                    key = digest; break
            with performance_span(stage, key):
                return function(*args, **kwargs)
        return call
    return decorate


def configure_performance_trace(sample_id: str, role: str, capacity=TRACE_MAX_RECORDS):
    global _PERFORMANCE_TRACE
    if _PERFORMANCE_TRACE is not None:
        raise ValueError("trace already configured")
    _PERFORMANCE_TRACE = PerformanceTrace(sample_id, role, capacity)
    return _PERFORMANCE_TRACE


def export_performance_trace_from_env():
    if _PERFORMANCE_TRACE is None or "TRILLIONNIUM_OWNER_TRACE_OUTPUT" not in os.environ:
        return
    deadline = time.monotonic_ns() + 5_000_000_000
    def budget():
        if time.monotonic_ns() >= deadline:
            raise ValueError("trace export deadline exceeded")
    path = Path(os.environ["TRILLIONNIUM_OWNER_TRACE_OUTPUT"] + "." + _PERFORMANCE_TRACE.role)
    if not path.is_absolute() or '..' in path.parts or len(os.fsencode(path)) > 4096 or len(path.parts) > 64:
        raise ValueError("trace output must be a bounded physical absolute path")
    payload = json.dumps(_PERFORMANCE_TRACE.snapshot(), allow_nan=False, separators=(",", ":")).encode()
    if len(payload) > TRACE_MAX_EXPORT_BYTES:
        raise ValueError("trace export exceeds fixed cap")
    parents = [os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)]
    names = []
    def fixed(metadata):
        return metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid
    try:
        for part in path.parts[1:-1]:
            budget()
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parents[-1])
            parents.append(child); names.append(part)
        parent = parents[-1]
        metadata = os.fstat(parent)
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise ValueError("trace parent must be private and owned")
        import io
        budget()
        with io.FileIO(os.open(path.name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent), 'wb', closefd=True) as output:
            if output.write(payload) != len(payload):
                raise OSError("trace export short write")
            output.flush(); os.fsync(output.fileno())
            actual = os.fstat(output.fileno())
            entry = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (fixed(actual) != fixed(entry) or not stat.S_ISREG(actual.st_mode)
                    or actual.st_nlink != 1 or actual.st_size != len(payload)
                    or actual.st_mode & 0o777 != 0o600):
                raise ValueError("trace output identity/size changed")
            for index, name in enumerate(names):
                budget()
                held = os.fstat(parents[index + 1])
                entry = os.stat(name, dir_fd=parents[index], follow_symlinks=False)
                if fixed(held) != fixed(entry):
                    raise ValueError("trace parent entry changed")
    finally:
        # Attempt each raw directory FD once, never retry a released number.
        first_error = None
        while parents:
            fd = parents.pop()
            try:
                os.close(fd)
            except OSError as error:
                first_error = first_error or error
        if first_error:
            raise first_error
    budget()


class DuplicateMember(ValueError):
    pass


class BrokerError(ValueError):
    pass


def _reject_nonfinite_json(value: str) -> None:
    """Keep protocol JSON in the RFC-8259 finite-number subset."""

    raise ValueError(f"non-finite JSON number {value}")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateMember(f"duplicate key {key}")
        result[key] = value
    return result


def strict_json(raw: bytes, *, label: str, maximum: int = MAX_LINE_BYTES) -> Any:
    if not raw or len(raw) > maximum:
        raise BrokerError(f"{label} is empty or exceeds {maximum} bytes")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_reject_nonfinite_json,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise BrokerError(f"invalid {label}: {error}") from error


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None:
        raise BrokerError(f"{label} is empty, oversized or malformed")
    return value


def require_token(value: Any) -> str:
    if not isinstance(value, str) or TOKEN_RE.fullmatch(value) is None:
        raise BrokerError("broker token must be 32 random bytes encoded as lowercase hex")
    return value


def compare_token(first: str, second: str) -> bool:
    return hmac.compare_digest(first.encode("ascii"), second.encode("ascii"))


def read_line(stream: BinaryIO, *, label: str, maximum: int = MAX_LINE_BYTES) -> bytes | None:
    raw = stream.readline(maximum + 2)
    if not raw:
        return None
    if not raw.endswith(b"\n") or len(raw) > maximum + 1:
        raise BrokerError(f"{label} is oversized or not newline terminated")
    raw = raw[:-1]
    if not raw:
        raise BrokerError(f"{label} is empty")
    return raw


def _executable_stat_tuple(metadata: os.stat_result) -> tuple[int, ...]:
    """Return the metadata that must remain stable while hashing an executable."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_executable_metadata(metadata: os.stat_result, label: str) -> None:
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise BrokerError(f"{label} must be a non-symlink regular file")
    if (
        metadata.st_nlink != 1
        or metadata.st_size == 0
        or metadata.st_size > MAX_EXECUTABLE_BYTES
    ):
        raise BrokerError(f"{label} must be one non-empty file within the executable byte bound")
    if metadata.st_mode & 0o022:
        raise BrokerError(f"{label} must not be group/world writable")
    # Checking the mode bits on the opened inode avoids an additional path
    # lookup (and therefore another pathname race) during startup.
    if metadata.st_mode & 0o111 == 0:
        raise BrokerError(f"{label} is not executable")


def open_validated_executable(
    path: Path,
    label: str,
    *,
    expected_identity: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Open and validate an executable, returning a pinned descriptor.

    The descriptor is intentionally returned to the caller instead of being
    closed here.  A broker can then execute ``/proc/self/fd/<descriptor>``
    while passing that descriptor to the child, so a replacement or symlink
    swap of ``path`` between validation and ``Popen`` cannot redirect startup
    to another inode.  ``expected_identity`` binds a later startup validation
    to the identity captured when the broker was constructed.
    """

    if not path.is_absolute():
        raise BrokerError(f"{label} must be absolute")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise BrokerError(f"{label} cannot be inspected: {error}") from error
    _validate_executable_metadata(metadata, label)
    before = _executable_stat_tuple(metadata)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BrokerError(f"{label} cannot be opened: {error}") from error

    try:
        opened = os.fstat(descriptor)
        _validate_executable_metadata(opened, label)
        if _executable_stat_tuple(opened) != before:
            raise BrokerError(f"{label} changed before open")
        digest = hashlib.sha256()
        read = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            read += len(chunk)
            if read > MAX_EXECUTABLE_BYTES:
                raise BrokerError(f"{label} exceeds the executable byte bound")
        after = os.fstat(descriptor)
        if _executable_stat_tuple(after) != before or read != metadata.st_size:
            raise BrokerError(f"{label} changed while being measured")
        identity = {
            "path": str(path),
            "sha256": digest.hexdigest(),
            "bytes": read,
            "uid": after.st_uid,
            "gid": after.st_gid,
            "mode": f"{stat.S_IMODE(after.st_mode):04o}",
            "device": after.st_dev,
            "inode": after.st_ino,
        }
        if expected_identity is not None:
            identity_fields = (
                "sha256",
                "bytes",
                "uid",
                "gid",
                "mode",
                "device",
                "inode",
            )
            if any(identity.get(field) != expected_identity.get(field) for field in identity_fields):
                raise BrokerError(f"{label} changed since initial validation")
        return descriptor, identity
    except Exception:
        os.close(descriptor)
        raise


def validate_executable(path: Path, label: str) -> dict[str, Any]:
    descriptor, identity = open_validated_executable(path, label)
    os.close(descriptor)
    return identity



def validate_argv(argv: list[str], label: str = "upstream argv") -> None:
    if not argv or len(argv) > MAX_ARGV_ITEMS:
        raise BrokerError(f"{label} is empty or has too many elements")
    total = 0
    for item in argv:
        if not isinstance(item, str):
            raise BrokerError(f"{label} elements must be strings")
        encoded = item.encode("utf-8")
        if b"\x00" in encoded or len(encoded) > MAX_ARGUMENT_BYTES:
            raise BrokerError(f"{label} contains NUL or an oversized argument")
        total += len(encoded)
        if total > MAX_TOTAL_ARGV_BYTES:
            raise BrokerError(f"{label} exceeds the total byte bound")


def validate_private_parent(path: Path, label: str) -> None:
    if not path.is_absolute() or not path.parent.is_dir() or path.parent.is_symlink():
        raise BrokerError(f"{label} path must be absolute with an existing real parent")
    metadata = path.parent.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise BrokerError(f"{label} parent must be a stable real directory")
    mode = stat.S_IMODE(metadata.st_mode)
    effective_uid = os.geteuid()
    trusted_owner = metadata.st_uid in {0, effective_uid}
    root_sticky = metadata.st_uid == 0 and bool(mode & stat.S_ISVTX)
    if not trusted_owner or (mode & 0o022 and not root_sticky):
        raise BrokerError(
            f"{label} parent is not owner-controlled: uid={metadata.st_uid} mode={mode:04o}"
        )


def validate_socket_path(path: Path) -> None:
    if not path.is_absolute():
        raise BrokerError("broker Unix socket path must be absolute")
    encoded = os.fsencode(path)
    if len(encoded) > 100:
        raise BrokerError("broker Unix socket path exceeds the portable byte bound")
    if encoded.startswith(b"@"):  # abstract sockets remain an Android/W6 carrier concern
        raise BrokerError("foundation broker requires a filesystem Unix socket")
    parent = path.parent
    metadata = parent.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise BrokerError("broker socket parent must be a stable real directory")
    mode = stat.S_IMODE(metadata.st_mode)
    effective_uid = os.geteuid()
    trusted_owner = metadata.st_uid in {0, effective_uid}
    root_sticky = metadata.st_uid == 0 and bool(mode & stat.S_ISVTX)
    if not trusted_owner or (mode & 0o022 and not root_sticky):
        raise BrokerError(
            f"broker socket parent is not owner-controlled: uid={metadata.st_uid} mode={mode:04o}"
        )


def _validate_private_metadata(metadata: os.stat_result, label: str) -> None:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise BrokerError(f"{label} must be one regular file")
    if metadata.st_uid != os.geteuid():
        raise BrokerError(f"{label} must be owned by the effective service UID")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise BrokerError(f"{label} must have mode 0600")


def read_private_bytes(path: Path, *, label: str, maximum: int) -> bytes:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or metadata.st_size <= 0 or metadata.st_size > maximum:
        raise BrokerError(f"{label} is absent, symlinked, empty or oversized")
    _validate_private_metadata(metadata, label)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        _validate_private_metadata(opened, label)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise BrokerError(f"{label} changed before open")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(raw) != metadata.st_size or len(raw) > maximum:
        raise BrokerError(f"{label} changed while being read")
    if (after.st_mtime_ns, after.st_ctime_ns, after.st_size) != (
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_size,
    ):
        raise BrokerError(f"{label} changed while being read")
    return raw


def read_private_json(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    raw = read_private_bytes(path, label=label, maximum=MAX_DESCRIPTOR_BYTES)
    value = strict_json(raw, label=label, maximum=MAX_DESCRIPTOR_BYTES)
    if not isinstance(value, dict):
        raise BrokerError(f"{label} must contain an object")
    return value, raw


def atomic_write_private(path: Path, raw: bytes, *, label: str) -> None:
    validate_private_parent(path, label)
    if path.is_symlink():
        raise BrokerError(f"{label} path must not be a symlink")
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load_or_create_token(path: Path) -> str:
    try:
        raw = read_private_bytes(path, label="broker token", maximum=MAX_TOKEN_BYTES)
    except FileNotFoundError:
        raw = b""
    if raw:
        try:
            value = raw.decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise BrokerError("broker token is not ASCII") from error
        return require_token(value)

    validate_private_parent(path, "broker token")
    if path.is_symlink():
        raise BrokerError("broker token path must not be a symlink")
    token = secrets.token_hex(32)
    encoded = (token + "\n").encode("ascii")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        raw = read_private_bytes(path, label="broker token", maximum=MAX_TOKEN_BYTES)
        try:
            return require_token(raw.decode("ascii").strip())
        except UnicodeDecodeError as error:
            raise BrokerError("broker token is not ASCII") from error
    try:
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return token


def descriptor_preimage(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result.pop("descriptor_sha256", None)
    return result


def descriptor_sha256(value: dict[str, Any]) -> str:
    return sha256_bytes(canonical(descriptor_preimage(value)))


def finalize_descriptor(value: dict[str, Any]) -> dict[str, Any]:
    result = descriptor_preimage(value)
    result["descriptor_sha256"] = descriptor_sha256(result)
    return result


def validate_descriptor(value: dict[str, Any]) -> None:
    supplied = value.get("descriptor_sha256")
    if not isinstance(supplied, str) or supplied != descriptor_sha256(value):
        raise BrokerError("broker descriptor SHA-256 does not bind its canonical preimage")
    if value.get("schema") != "org.trillionnium.owner-open.connection-broker.v1":
        raise BrokerError("unsupported broker descriptor schema")
    require_id(value.get("broker_id"), "broker_id")
    socket_path = value.get("socket_path")
    token_file = value.get("token_file")
    if not isinstance(socket_path, str) or not Path(socket_path).is_absolute():
        raise BrokerError("broker descriptor socket_path is invalid")
    if not isinstance(token_file, str) or not Path(token_file).is_absolute():
        raise BrokerError("broker descriptor token_file is invalid")
    if value.get("response_model") != (
        "broker_correlated_result_owner_with_broadcast_observation"
    ):
        raise BrokerError("broker descriptor response model is incompatible")
    for field in (
        "max_clients",
        "client_queue_frames",
        "client_queue_bytes",
        "max_pending_requests",
    ):
        item = value.get(field)
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            raise BrokerError(f"broker descriptor {field} is not a positive integer")
