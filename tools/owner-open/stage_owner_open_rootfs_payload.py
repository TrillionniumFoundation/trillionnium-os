#!/usr/bin/env python3
"""Stage an exact Root Linux payload tree and canonical integrity manifest.

This tool does not build a squashfs image. It creates a private deterministic
staging tree after exact digest/path/mode/ELF checks. Image construction and
Android inclusion remain separate gates.
"""
from __future__ import annotations

import argparse
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


def strict_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > MAX_PLAN_BYTES
    ):
        raise StageError(f"{label} is not a bounded real file")
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        raise StageError(f"{label} changed while read")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateMember) as error:
        raise StageError(f"invalid {label}: {error}") from error
    if not isinstance(value, dict):
        raise StageError(f"{label} must contain an object")
    return value, raw


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


def destination(value: Any) -> str:
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


def private_new_directory(path: Path, label: str) -> None:
    if not path.is_absolute() or not path.parent.is_dir() or path.parent.is_symlink():
        raise StageError(f"{label} must be an absolute new directory")
    parent = path.parent.lstat()
    if parent.st_uid not in {0, os.geteuid()} or stat.S_IMODE(parent.st_mode) & 0o022:
        raise StageError(f"{label} parent must be owner controlled and non-writable by group/world")
    if path.exists() or path.is_symlink():
        raise StageError(f"{label} already exists")


def stable_source(path: Path, expected: str) -> tuple[dict[str, Any], bytes]:
    if not path.is_absolute():
        raise StageError("entry source path must be absolute")
    before = path.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > MAX_FILE_BYTES
        or before.st_mode & 0o022
    ):
        raise StageError(f"entry source is not a stable bounded private file: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    raw = bytearray()
    digest = hashlib.sha256()
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            raw.extend(chunk)
            digest.update(chunk)
            if len(raw) > MAX_FILE_BYTES:
                raise StageError(f"entry source exceeded its byte bound: {path}")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_uid,
        before.st_gid,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_uid,
        after.st_gid,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    actual = digest.hexdigest()
    if identity_before != identity_after or len(raw) != before.st_size:
        raise StageError(f"entry source changed while read: {path}")
    if actual != expected:
        raise StageError(f"entry source digest does not match plan: {path}")
    return (
        {
            "source_path": str(path),
            "source_sha256": actual,
            "source_bytes": len(raw),
            "source_device": before.st_dev,
            "source_inode": before.st_ino,
            "source_uid": before.st_uid,
            "source_gid": before.st_gid,
            "source_mode": f"{stat.S_IMODE(before.st_mode):04o}",
        },
        bytes(raw),
    )


def inspect_elf(raw: bytes, *, required: bool) -> dict[str, Any] | None:
    if not raw.startswith(b"\x7fELF"):
        if required:
            raise StageError("entry is required to be an AArch64 ELF but has no ELF magic")
        return None
    if len(raw) < 64:
        raise StageError("ELF entry is truncated")
    elf_class = raw[4]
    data_encoding = raw[5]
    if elf_class != 2 or data_encoding != 1:
        raise StageError("ELF entry must be little-endian ELF64")
    machine = struct.unpack_from("<H", raw, 18)[0]
    if machine != 183:
        raise StageError(f"ELF entry must target AArch64, observed machine={machine}")
    file_type = struct.unpack_from("<H", raw, 16)[0]
    return {
        "elf_class": "ELF64",
        "endianness": "little",
        "machine": "AArch64",
        "machine_id": machine,
        "file_type": file_type,
    }


def atomic_file(path: Path, raw: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    current = path.parent
    while current.name and current != current.parent:
        if current.exists():
            os.chmod(current, 0o755)
        current = current.parent
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
                raise StageError("payload staging write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    os.chmod(path, mode)


def load_plan(path: Path) -> tuple[dict[str, Any], bytes]:
    plan, raw = strict_json(path, "payload plan")
    if plan.get("schema") != PLAN_SCHEMA:
        raise StageError(f"payload plan schema must be {PLAN_SCHEMA}")
    require_id(plan.get("payload_id"), "payload_id")
    if plan.get("architecture") != "aarch64":
        raise StageError("payload architecture must be aarch64")
    if plan.get("libc") not in {"glibc", "musl"}:
        raise StageError("payload libc must be glibc or musl")
    entries = plan.get("entries")
    if not isinstance(entries, list) or not entries or len(entries) > MAX_ENTRIES:
        raise StageError("payload entries are empty or exceed the count bound")
    return plan, raw


def stage(plan_path: Path, output: Path) -> dict[str, Any]:
    plan, plan_raw = load_plan(plan_path)
    entries = plan["entries"]
    parsed: list[dict[str, Any]] = []
    destinations: set[str] = set()
    roles: set[str] = set()
    total = 0
    materialized: list[tuple[str, bytes, int]] = []
    for item in entries:
        if not isinstance(item, dict):
            raise StageError("payload entry must be an object")
        role = require_id(item.get("role"), "entry role")
        if role in roles:
            raise StageError(f"payload entry role is duplicated: {role}")
        roles.add(role)
        target = destination(item.get("destination"))
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
        source, raw = stable_source(Path(source_value), expected)
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise StageError("payload entries exceed the total byte bound")
        elf = inspect_elf(raw, required=item.get("require_aarch64_elf") is True)
        parsed.append(
            {
                "role": role,
                "destination": target,
                "mode": f"{mode:04o}",
                "uid": uid,
                "gid": gid,
                **source,
                "elf": elf,
            }
        )
        materialized.append((target, raw, mode))

    private_new_directory(output, "payload output")
    output.mkdir(mode=0o700)
    staging = output / "root"
    staging.mkdir(mode=0o755)
    try:
        for target, raw, mode in sorted(materialized, key=lambda item: item[0]):
            relative = target.removeprefix("/")
            atomic_file(staging / relative, raw, mode)
        manifest = {
            "schema": MANIFEST_SCHEMA,
            "payload_id": plan["payload_id"],
            "plan_sha256": sha256_bytes(plan_raw),
            "architecture": plan["architecture"],
            "libc": plan["libc"],
            "entry_count": len(parsed),
            "total_bytes": total,
            "entries": sorted(parsed, key=lambda item: item["destination"]),
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
        atomic_file(output / "owner-open-rootfs.manifest.json", manifest_raw, 0o600)
        embedded = staging / "etc/trillionnium/owner-open/rootfs.manifest.json"
        atomic_file(embedded, manifest_raw, 0o444)
        manifest["manifest_sha256"] = sha256_bytes(manifest_raw)
        manifest["staging_root"] = str(staging)
        return manifest
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
    try:
        result = stage(parse_args(argv).plan, parse_args(argv).output)
    except (OSError, StageError) as error:
        print(f"HOLD: {error}", file=sys.stderr)
        return 1
    if "--json" in argv:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print(
            "PASS_ROOTFS_PAYLOAD_STAGED_NOT_IMAGE "
            f"entries={result['entry_count']} bytes={result['total_bytes']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
