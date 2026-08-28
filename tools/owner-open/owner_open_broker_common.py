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


class DuplicateMember(ValueError):
    pass


class BrokerError(ValueError):
    pass


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
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateMember) as error:
        raise BrokerError(f"invalid {label}: {error}") from error


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
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


def validate_executable(path: Path, label: str) -> dict[str, Any]:
    if not path.is_absolute():
        raise BrokerError(f"{label} must be absolute")
    metadata = path.lstat()
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
    if metadata.st_mode & 0o111 == 0 or not os.access(path, os.X_OK):
        raise BrokerError(f"{label} is not executable")
    before = (
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
    digest = hashlib.sha256()
    read = 0
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            read += len(chunk)
            if read > MAX_EXECUTABLE_BYTES:
                raise BrokerError(f"{label} exceeds the executable byte bound")
        after_stat = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = (
        after_stat.st_dev,
        after_stat.st_ino,
        after_stat.st_uid,
        after_stat.st_gid,
        after_stat.st_mode,
        after_stat.st_nlink,
        after_stat.st_size,
        after_stat.st_mtime_ns,
        after_stat.st_ctime_ns,
    )
    if before != after or read != metadata.st_size:
        raise BrokerError(f"{label} changed while being measured")
    return {
        "path": str(path),
        "sha256": digest.hexdigest(),
        "bytes": read,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }



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
