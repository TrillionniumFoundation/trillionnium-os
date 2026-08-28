#!/usr/bin/env python3
"""Release-candidate Root Linux payload staging and manifest builder.

The tool verifies an owner-authored exact-digest plan, then creates a private
staging tree using bounded streaming copies. It never builds or claims a
squashfs image; image construction is a later deterministic gate.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import struct
import sys
from typing import Any

PLAN_SCHEMA = "org.trillionnium.owner-open.rootfs-payload-plan.v1"
MANIFEST_SCHEMA = "org.trillionnium.owner-open.rootfs-payload-manifest.v1"
MAX_PLAN_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_ENTRIES = 4096
COPY_BYTES = 1024 * 1024
ALLOWED_PREFIXES = (
    "/bin/",
    "/lib/",
    "/lib64/",
    "/usr/bin/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/libexec/trillionnium/",
    "/etc/trillionnium/",
)
FORBIDDEN_DESTINATION_TOKENS = (
    "auth.json",
    "adbkey",
    ".ssh/",
    "credentials",
    "credential",
    "private_key",
    "secret",
    "token",
)


class StageError(RuntimeError):
    pass


class DuplicateMember(ValueError):
    pass


def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise DuplicateMember(f"duplicate key {key}")
        result[key] = value
    return result


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def load_plan(path: Path) -> tuple[dict[str, Any], bytes]:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > MAX_PLAN_BYTES
        or metadata.st_mode & 0o022
    ):
        raise StageError("payload plan must be a stable non-writable regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        raw = bytearray()
        while True:
            chunk = os.read(descriptor, COPY_BYTES)
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > MAX_PLAN_BYTES:
                raise StageError("payload plan exceeds its byte bound")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if stable_identity(metadata) != stable_identity(after) or len(raw) != metadata.st_size:
        raise StageError("payload plan changed while read")
    try:
        value = json.loads(bytes(raw).decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateMember) as error:
        raise StageError(f"invalid payload plan: {error}") from error
    if not isinstance(value, dict) or value.get("schema") != PLAN_SCHEMA:
        raise StageError(f"payload plan schema must be {PLAN_SCHEMA}")
    return value, bytes(raw)


def require_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", value) is None:
        raise StageError(f"{label} is empty, oversized or malformed")
    return value


def require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise StageError(f"{label} must be a lowercase SHA-256")
    return value


def require_mode(value: Any) -> int:
    if not isinstance(value, str) or re.fullmatch(r"0[0-7]{3}", value) is None:
        raise StageError("entry mode must be a four-digit octal string")
    mode = int(value, 8)
    if mode & 0o022:
        raise StageError("payload entries must not be group/world writable")
    return mode


def require_destination(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        raise StageError("entry destination must be an absolute NUL-free path")
    path = PurePosixPath(value)
    if ".." in path.parts or str(path) != value or value.endswith("/"):
        raise StageError(f"entry destination is not canonical: {value}")
    if not any(value.startswith(prefix) for prefix in ALLOWED_PREFIXES):
        raise StageError(f"entry destination is outside allowed payload prefixes: {value}")
    lowered = value.lower()
    if any(token in lowered for token in FORBIDDEN_DESTINATION_TOKENS):
        raise StageError(f"entry destination appears credential-bearing: {value}")
    return value


def validate_new_output(path: Path) -> None:
    if not path.is_absolute() or not path.parent.is_dir() or path.parent.is_symlink():
        raise StageError("payload output must be an absolute new directory")
    parent = path.parent.lstat()
    if (
        parent.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(parent.st_mode) & 0o022
    ):
        raise StageError("payload output parent must be owner controlled and non-writable by group/world")
    if path.exists() or path.is_symlink():
        raise StageError("payload output already exists")


def parse_elf_header(header: bytes, required: bool) -> dict[str, Any] | None:
    if not header.startswith(b"\x7fELF"):
        if required:
            raise StageError("entry requires AArch64 ELF but has no ELF magic")
        return None
    if len(header) < 64:
        raise StageError("ELF entry is truncated")
    if header[4] != 2 or header[5] != 1:
        raise StageError("ELF entry must be little-endian ELF64")
    file_type = struct.unpack_from("<H", header, 16)[0]
    machine = struct.unpack_from("<H", header, 18)[0]
    if machine != 183:
        raise StageError(f"ELF entry must target AArch64, observed machine={machine}")
    return {
        "elf_class": "ELF64",
        "endianness": "little",
        "machine": "AArch64",
        "machine_id": machine,
        "file_type": file_type,
    }


@dataclass(frozen=True)
class SourceRecord:
    role: str
    source: Path
    destination: str
    mode: int
    uid: int
    gid: int
    expected_sha256: str
    require_aarch64_elf: bool
    source_identity: tuple[int, ...]
    source_bytes: int
    elf: dict[str, Any] | None


def inspect_source(
    role: str,
    source: Path,
    destination: str,
    mode: int,
    uid: int,
    gid: int,
    expected_sha256: str,
    require_aarch64_elf: bool,
) -> SourceRecord:
    if not source.is_absolute():
        raise StageError(f"entry source must be absolute: {role}")
    before = source.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > MAX_FILE_BYTES
        or before.st_mode & 0o022
    ):
        raise StageError(f"entry source is not a stable bounded private file: {source}")
    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256()
    count = 0
    header = bytearray()
    try:
        while True:
            chunk = os.read(descriptor, COPY_BYTES)
            if not chunk:
                break
            if len(header) < 64:
                header.extend(chunk[: 64 - len(header)])
            digest.update(chunk)
            count += len(chunk)
            if count > MAX_FILE_BYTES:
                raise StageError(f"entry source exceeds its byte bound: {source}")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if stable_identity(before) != stable_identity(after) or count != before.st_size:
        raise StageError(f"entry source changed while inspected: {source}")
    actual = digest.hexdigest()
    if actual != expected_sha256:
        raise StageError(f"entry source digest does not match plan: {source}")
    return SourceRecord(
        role,
        source,
        destination,
        mode,
        uid,
        gid,
        expected_sha256,
        require_aarch64_elf,
        stable_identity(before),
        count,
        parse_elf_header(bytes(header), require_aarch64_elf),
    )


def parse_entries(plan: dict[str, Any]) -> tuple[list[SourceRecord], int]:
    require_id(plan.get("payload_id"), "payload_id")
    if plan.get("architecture") != "aarch64":
        raise StageError("payload architecture must be aarch64")
    if plan.get("libc") not in {"glibc", "musl"}:
        raise StageError("payload libc must be glibc or musl")
    values = plan.get("entries")
    if not isinstance(values, list) or not values or len(values) > MAX_ENTRIES:
        raise StageError("payload entries are empty or exceed the count bound")
    roles: set[str] = set()
    destinations: set[str] = set()
    records: list[SourceRecord] = []
    total = 0
    for item in values:
        if not isinstance(item, dict):
            raise StageError("payload entry must be an object")
        role = require_id(item.get("role"), "entry role")
        if role in roles:
            raise StageError(f"payload entry role is duplicated: {role}")
        roles.add(role)
        target = require_destination(item.get("destination"))
        if target in destinations:
            raise StageError(f"payload destination is duplicated: {target}")
        destinations.add(target)
        mode = require_mode(item.get("mode"))
        uid, gid = item.get("uid"), item.get("gid")
        if uid != 0 or gid != 0:
            raise StageError("payload staging v1 requires uid=0 and gid=0")
        expected = require_digest(item.get("expected_sha256"), "expected_sha256")
        source_value = item.get("source")
        if not isinstance(source_value, str):
            raise StageError("payload entry source must be a string")
        record = inspect_source(
            role,
            Path(source_value),
            target,
            mode,
            uid,
            gid,
            expected,
            item.get("require_aarch64_elf") is True,
        )
        total += record.source_bytes
        if total > MAX_TOTAL_BYTES:
            raise StageError("payload entries exceed the total byte bound")
        records.append(record)
    return records, total


def make_parent_directories(root: Path, target_parent: Path) -> None:
    relative = target_parent.relative_to(root)
    current = root
    for part in relative.parts:
        current = current / part
        if current.exists():
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise StageError(f"payload parent is not a real directory: {current}")
        else:
            current.mkdir(mode=0o755)
        os.chmod(current, 0o755)


def copy_record(record: SourceRecord, staging: Path) -> dict[str, Any]:
    target = staging / record.destination.removeprefix("/")
    make_parent_directories(staging, target.parent)
    temporary = target.parent / f".{target.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    source_descriptor = os.open(
        record.source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    )
    target_descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        record.mode,
    )
    digest = hashlib.sha256()
    count = 0
    try:
        while True:
            chunk = os.read(source_descriptor, COPY_BYTES)
            if not chunk:
                break
            offset = 0
            while offset < len(chunk):
                written = os.write(target_descriptor, chunk[offset:])
                if written <= 0:
                    raise StageError("payload copy made no progress")
                offset += written
            digest.update(chunk)
            count += len(chunk)
            if count > record.source_bytes:
                raise StageError(f"payload source grew while copied: {record.source}")
        source_after = os.fstat(source_descriptor)
        os.fsync(target_descriptor)
    finally:
        os.close(source_descriptor)
        os.close(target_descriptor)
    if stable_identity(source_after) != record.source_identity:
        temporary.unlink(missing_ok=True)
        raise StageError(f"payload source changed between inspection and copy: {record.source}")
    if count != record.source_bytes or digest.hexdigest() != record.expected_sha256:
        temporary.unlink(missing_ok=True)
        raise StageError(f"payload copy digest mismatch: {record.source}")
    os.replace(temporary, target)
    os.chmod(target, record.mode)
    target_metadata = target.lstat()
    if (
        stat.S_ISLNK(target_metadata.st_mode)
        or not stat.S_ISREG(target_metadata.st_mode)
        or stat.S_IMODE(target_metadata.st_mode) != record.mode
        or target_metadata.st_nlink != 1
    ):
        raise StageError(f"staged payload file metadata is invalid: {target}")
    return {
        "role": record.role,
        "source_path": str(record.source),
        "destination": record.destination,
        "mode": f"{record.mode:04o}",
        "uid": record.uid,
        "gid": record.gid,
        "sha256": record.expected_sha256,
        "bytes": record.source_bytes,
        "elf": record.elf,
    }


def write_atomic(path: Path, raw: bytes, mode: int) -> None:
    make_parent_directories(path.parents[len(path.parents) - 1], path.parent) if False else None
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise StageError("manifest write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    os.chmod(path, mode)


def stage(plan_path: Path, output: Path) -> dict[str, Any]:
    plan, plan_raw = load_plan(plan_path)
    records, total = parse_entries(plan)
    validate_new_output(output)
    output.mkdir(mode=0o700)
    staging = output / "root"
    staging.mkdir(mode=0o755)
    parent_mode_before = stat.S_IMODE(output.parent.lstat().st_mode)
    try:
        entries = [copy_record(record, staging) for record in sorted(records, key=lambda item: item.destination)]
        manifest = {
            "schema": MANIFEST_SCHEMA,
            "payload_id": plan["payload_id"],
            "plan_sha256": sha256_bytes(plan_raw),
            "architecture": plan["architecture"],
            "libc": plan["libc"],
            "entry_count": len(entries),
            "total_bytes": total,
            "entries": entries,
            "claims": {
                "staging_tree_complete": True,
                "expected_source_digests_verified": True,
                "aarch64_elf_headers_verified_where_required": True,
                "rootfs_image_built": False,
                "android_module_bound": False,
                "image_included": False,
                "physical_device_observed": False,
                "public_release": False,
            },
            "claim_ceiling": "ROOTFS_PAYLOAD_STAGED_NOT_IMAGE",
        }
        manifest_raw = json.dumps(
            manifest, ensure_ascii=False, sort_keys=True, indent=2
        ).encode("utf-8") + b"\n"
        external = output / "owner-open-rootfs.manifest.json"
        write_atomic(external, manifest_raw, 0o600)
        embedded = staging / "etc/trillionnium/owner-open/rootfs.manifest.json"
        make_parent_directories(staging, embedded.parent)
        write_atomic(embedded, manifest_raw, 0o444)
        if stat.S_IMODE(output.parent.lstat().st_mode) != parent_mode_before:
            raise StageError("payload staging changed its output parent mode")
        return {
            **manifest,
            "manifest_sha256": sha256_bytes(manifest_raw),
            "staging_root": str(staging),
        }
    except Exception:
        shutil.rmtree(output, ignore_errors=True)
        raise


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    result = parser.parse_args(argv)
    if not result.execute:
        parser.error("--execute is required to stage a payload")
    return result


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        result = stage(args.plan, args.output)
    except (OSError, StageError) as error:
        print(f"HOLD: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print(
            "PASS_ROOTFS_PAYLOAD_STAGED_NOT_IMAGE "
            f"entries={result['entry_count']} bytes={result['total_bytes']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
