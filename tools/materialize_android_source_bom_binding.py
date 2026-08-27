#!/usr/bin/env python3
"""Materialize the bounded source-BOM identity consumed by Android target-files.

This host-only step binds four already-produced, immutable observations:

* a PASS ``source-bom.v2.json`` receipt;
* the exact checked-in source-set contract bytes;
* the exact resolved-manifest bytes used by that receipt; and
* the receipt-stage descriptor for the candidate output.

It does not resolve repositories, build images, sign artifacts, access private
keys, install anything, or write a device.  Every input is read through an
``O_NOFOLLOW`` descriptor and re-stat'ed after the read.  The output is
published with ``O_EXCL`` so a stale binding cannot silently be replaced.
The resulting JSON is provenance only; the release gate still decides whether
an artifact may be signed or installed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import re
import sys
from typing import Any, Mapping


SOURCE_BOM_SCHEMA = "org.trillionnium.local-cross-repo-source-bom.v2"
SOURCE_BOM_PASS = "PASS_LOCAL_EXACT_CLEAN_GRAPH"
SOURCE_BOM_RECEIPT_ID_SCOPE = "sha256(canonical-json-utf8-without-receipt_id)"
SOURCE_SET_SCHEMA = "org.trillionnium.p0-cross-repo-source-set.v2"
BINDING_SCHEMA = "org.trillionnium.android-source-bom-binding.v1"
BINDING_AUTHORITY = "local_source_provenance_not_release_authority"
RESOLVED_MANIFEST_SCHEMA = "org.trillionnium.repo-manifest.v1"
RECEIPT_STAGE_SCHEMA_PREFIX = "org.trillionnium.android.receipt-stage."

MAX_SOURCE_BOM_BYTES = 8 * 1024 * 1024
MAX_SOURCE_SET_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_RECEIPT_STAGE_BYTES = 16 * 1024 * 1024
MAX_BINDING_BYTES = 2 * 1024 * 1024
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RECEIPT_ID = re.compile(r"^sha256:[0-9a-f]{64}$")

SOURCE_BOM_FIELDS = frozenset(
    {
        "schema",
        "decision",
        "posture",
        "source_set",
        "resolved_manifest",
        "projects",
        "trees",
        "artifacts",
        "blockers",
        "receipt_id_scope",
        "receipt_id",
    }
)


class BindingError(ValueError):
    """Raised when an input cannot be safely bound."""


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def parse_canonical_json(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise BindingError(f"{label}_invalid_json") from error
    if type(value) is not dict:
        raise BindingError(f"{label}_must_be_object")
    try:
        if canonical_json_bytes(value) != raw:
            raise BindingError(f"{label}_not_canonical")
    except (TypeError, ValueError) as error:
        raise BindingError(f"{label}_not_canonical") from error
    return value


def _has_symlink_component(path: Path) -> bool:
    absolute = Path(os.path.abspath(os.fspath(path)))
    current = Path(absolute.anchor or os.sep)
    for component in absolute.parts[1:]:
        current /= component
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
    return False


def read_stable(path: Path, label: str, maximum: int) -> bytes:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if _has_symlink_component(absolute):
        raise BindingError(f"{label}_symlink_path")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(os.fspath(absolute), flags)
    except OSError as error:
        raise BindingError(f"{label}_unreadable") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > maximum:
            raise BindingError(f"{label}_boundary_invalid")
        chunks: list[bytes] = []
        observed = 0
        while observed <= maximum:
            block = os.read(descriptor, min(1024 * 1024, maximum + 1 - observed))
            if not block:
                break
            chunks.append(block)
            observed += len(block)
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
            item.st_mode,
            item.st_uid,
            item.st_gid,
            item.st_nlink,
        )
        if observed != before.st_size or identity(before) != identity(after):
            raise BindingError(f"{label}_changed_while_read")
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    try:
        current = os.lstat(absolute)
    except OSError as error:
        raise BindingError(f"{label}_path_changed") from error
    if stat.S_ISLNK(current.st_mode) or identity(current) != identity(before):
        raise BindingError(f"{label}_path_changed")
    return raw


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise BindingError(
            f"{label}_keys_invalid:missing={','.join(sorted(expected - actual))};"
            f"extra={','.join(sorted(actual - expected))}"
        )


def _valid_sha(value: object) -> bool:
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def _valid_receipt_id(value: object) -> bool:
    return isinstance(value, str) and RECEIPT_ID.fullmatch(value) is not None


def _descriptor(schema: str, raw: bytes) -> dict[str, object]:
    return {"schema": schema, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def validate_source_bom(value: Mapping[str, Any], raw: bytes) -> dict[str, Any]:
    _exact_keys(value, SOURCE_BOM_FIELDS, "source_bom")
    if value.get("schema") != SOURCE_BOM_SCHEMA or value.get("decision") != SOURCE_BOM_PASS:
        raise BindingError("source_bom_not_exact_local_pass")
    if value.get("blockers") != [] or value.get("receipt_id_scope") != SOURCE_BOM_RECEIPT_ID_SCOPE:
        raise BindingError("source_bom_posture_or_blockers_invalid")
    posture = value.get("posture")
    if not isinstance(posture, Mapping):
        raise BindingError("source_bom_posture_invalid")
    for key in ("local_only", "signed", "build_authorized", "ota_authorized", "device_write_authorized"):
        if posture.get(key) is not (True if key == "local_only" else False):
            raise BindingError(f"source_bom_posture_{key}_invalid")
    receipt_id = value.get("receipt_id")
    if not _valid_receipt_id(receipt_id):
        raise BindingError("source_bom_receipt_id_invalid")
    preimage = dict(value)
    preimage.pop("receipt_id", None)
    if receipt_id != "sha256:" + hashlib.sha256(canonical_json_bytes(preimage)).hexdigest():
        raise BindingError("source_bom_receipt_id_mismatch")
    source_set = value.get("source_set")
    manifest = value.get("resolved_manifest")
    if not isinstance(source_set, Mapping) or not isinstance(manifest, Mapping):
        raise BindingError("source_bom_source_identity_invalid")
    for descriptor, label in ((source_set, "source_set"), (manifest, "resolved_manifest")):
        if not _valid_sha(descriptor.get("sha256")) or type(descriptor.get("bytes")) is not int:
            raise BindingError(f"source_bom_{label}_descriptor_invalid")
    return {
        "schema": SOURCE_BOM_SCHEMA,
        "receipt_id": receipt_id,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "source_set_sha256": source_set["sha256"],
        "resolved_manifest_sha256": manifest["sha256"],
    }


def materialize(
    source_bom_path: Path,
    source_set_path: Path,
    resolved_manifest_path: Path,
    receipt_stage_path: Path,
) -> bytes:
    source_bom_raw = read_stable(source_bom_path, "source_bom", MAX_SOURCE_BOM_BYTES)
    source_bom = parse_canonical_json(source_bom_raw, "source_bom")
    source_identity = validate_source_bom(source_bom, source_bom_raw)

    source_set_raw = read_stable(source_set_path, "source_set", MAX_SOURCE_SET_BYTES)
    source_set = parse_canonical_json(source_set_raw, "source_set")
    if source_set.get("schema") != SOURCE_SET_SCHEMA:
        raise BindingError("source_set_schema_invalid")
    if source_identity["source_set_sha256"] != hashlib.sha256(source_set_raw).hexdigest():
        raise BindingError("source_set_digest_mismatch")
    if len(source_set_raw) != int(source_bom["source_set"]["bytes"]):
        raise BindingError("source_set_size_mismatch")

    manifest_raw = read_stable(resolved_manifest_path, "resolved_manifest", MAX_MANIFEST_BYTES)
    if source_identity["resolved_manifest_sha256"] != hashlib.sha256(manifest_raw).hexdigest():
        raise BindingError("resolved_manifest_digest_mismatch")
    if len(manifest_raw) != int(source_bom["resolved_manifest"]["bytes"]):
        raise BindingError("resolved_manifest_size_mismatch")

    stage_raw = read_stable(receipt_stage_path, "receipt_stage", MAX_RECEIPT_STAGE_BYTES)
    stage = parse_canonical_json(stage_raw, "receipt_stage")
    stage_schema = stage.get("schema")
    if not isinstance(stage_schema, str) or not stage_schema.startswith(RECEIPT_STAGE_SCHEMA_PREFIX):
        raise BindingError("receipt_stage_schema_invalid")
    if stage.get("decision") != "PASS_HOST_ONLY_ANDROID_USERDEBUG_RECEIPT_STAGE":
        raise BindingError("receipt_stage_decision_invalid")

    binding: dict[str, object] = {
        "schema": BINDING_SCHEMA,
        "authority": BINDING_AUTHORITY,
        "source_bom": source_identity,
        "source_set": _descriptor(SOURCE_SET_SCHEMA, source_set_raw),
        "resolved_manifest": _descriptor(RESOLVED_MANIFEST_SCHEMA, manifest_raw),
        "receipt_stage": _descriptor(stage_schema, stage_raw),
    }
    binding["binding_id"] = "sha256:" + hashlib.sha256(canonical_json_bytes(binding)).hexdigest()
    raw = canonical_json_bytes(binding)
    if len(raw) > MAX_BINDING_BYTES:
        raise BindingError("binding_size_invalid")
    return raw


def publish_exclusive(path: Path, raw: bytes) -> None:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if _has_symlink_component(absolute.parent):
        raise BindingError("output_symlink_path")
    if not absolute.parent.is_dir():
        raise BindingError("output_parent_missing")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(os.fspath(absolute), flags, 0o444)
    except OSError as error:
        raise BindingError("output_must_be_new_regular_file") from error
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise BindingError("output_short_write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--source-bom", type=Path, required=True)
    result.add_argument("--source-set", type=Path, required=True)
    result.add_argument("--resolved-manifest", type=Path, required=True)
    result.add_argument("--receipt-stage", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        raw = materialize(args.source_bom, args.source_set, args.resolved_manifest, args.receipt_stage)
        publish_exclusive(args.output, raw)
    except (BindingError, OSError, ValueError) as error:
        print(f"android source BOM binding error: {error}", file=sys.stderr)
        return 78
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
