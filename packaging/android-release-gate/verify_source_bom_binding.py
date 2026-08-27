#!/usr/bin/env python3
"""Validate the source-BOM identity embedded in Android target-files.

The target-files builder is the future writer of
``META/trillionnium-source-bom-binding.json``.  This module deliberately only
reads that member; it does not build, sign, install, flash, or mutate an
archive.  The binding is a provenance projection, not a release signature or
device authorization.

The default archive check is backwards compatible with existing target-files
fixtures: an absent member is reported as ``present=false`` with no hold.  A
future release gate can pass ``require_binding=True`` to make the member a
mandatory, fail-closed input.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping
import zipfile


BINDING_SCHEMA = "org.trillionnium.android-source-bom-binding.v1"
BINDING_MEMBER = "META/trillionnium-source-bom-binding.json"
BOM_SCHEMA = "org.trillionnium.local-cross-repo-source-bom.v2"
BOM_SOURCE_SET_SCHEMA = "org.trillionnium.p0-cross-repo-source-set.v2"
RESOLVED_MANIFEST_SCHEMA = "org.trillionnium.repo-manifest.v1"
RECEIPT_STAGE_SCHEMA_PREFIX = "org.trillionnium.android.receipt-stage."
BINDING_AUTHORITY = "local_source_provenance_not_release_authority"
MAX_BINDING_BYTES = 2 * 1024 * 1024
MAX_TARGET_BYTES = 16 * 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 2 * 1024 * 1024
MAX_ZIP_ENTRIES = 1_000_000
MAX_CLAIM_BYTES = 1 << 40
HEX64 = re.compile(r"^[0-9a-f]{64}$")
RECEIPT_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
SCHEMA_NAME = re.compile(r"^org\.trillionnium\.[A-Za-z0-9_.-]+$")

_TOP_KEYS = frozenset(
    {
        "schema",
        "binding_id",
        "authority",
        "source_bom",
        "source_set",
        "resolved_manifest",
        "receipt_stage",
    }
)
_SOURCE_BOM_KEYS = frozenset(
    {
        "schema",
        "receipt_id",
        "bytes",
        "sha256",
        "source_set_sha256",
        "resolved_manifest_sha256",
    }
)
_DESCRIPTOR_KEYS = frozenset({"schema", "bytes", "sha256"})
_DIGEST_FIELDS = frozenset(
    {"sha256", "source_set_sha256", "resolved_manifest_sha256"}
)


class BindingError(ValueError):
    """Raised by the exception-oriented convenience API."""


def canonical_json_bytes(value: object) -> bytes:
    """Return the repository's deterministic JSON representation."""

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


def _parse_json(raw: bytes) -> dict[str, object]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise BindingError("source_bom_binding_invalid_json") from error
    if type(value) is not dict:
        raise BindingError("source_bom_binding_must_be_object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> list[str]:
    actual = set(value)
    holds: list[str] = []
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing:
        holds.append(f"source_bom_binding_{label}_missing_keys:{','.join(missing)}")
    if extra:
        holds.append(f"source_bom_binding_{label}_extra_keys:{','.join(extra)}")
    return holds


def _valid_bytes(value: object) -> bool:
    return type(value) is int and 0 < value <= MAX_CLAIM_BYTES


def _valid_hex(value: object) -> bool:
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def _valid_receipt(value: object) -> bool:
    return isinstance(value, str) and RECEIPT_ID.fullmatch(value) is not None


def _safe_zip_member(name: str) -> None:
    """Reject names that could make the archive lookup ambiguous or unsafe."""

    if not name or "\\" in name or name.startswith("/") or "\x00" in name:
        raise BindingError("target_files_source_bom_binding_unsafe_zip_member")
    path = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise BindingError("target_files_source_bom_binding_noncanonical_zip_member")


def _has_symlink_component(path: Path) -> bool:
    """Return true when any absolute path component is a symlink."""

    current = Path(os.sep)
    components = Path(os.path.abspath(os.fspath(path))).parts
    for component in components[1:]:
        current /= component
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
    return False


def _validate_descriptor(
    value: object, *, label: str, schema: str | None = None
) -> list[str]:
    holds: list[str] = []
    if not isinstance(value, Mapping):
        return [f"source_bom_binding_{label}_not_object"]
    holds.extend(_exact_keys(value, _DESCRIPTOR_KEYS, label))
    observed_schema = value.get("schema")
    if schema is not None:
        if observed_schema != schema:
            holds.append(f"source_bom_binding_{label}_schema_invalid")
    elif not isinstance(observed_schema, str) or SCHEMA_NAME.fullmatch(observed_schema) is None:
        holds.append(f"source_bom_binding_{label}_schema_invalid")
    if not _valid_bytes(value.get("bytes")):
        holds.append(f"source_bom_binding_{label}_bytes_invalid")
    if not _valid_hex(value.get("sha256")):
        holds.append(f"source_bom_binding_{label}_sha256_invalid")
    return holds


def _expected_bom_identity(
    *, expected_bom: Mapping[str, Any] | None, expected_bom_bytes: bytes | None
) -> tuple[Mapping[str, Any] | None, bytes | None, list[str]]:
    """Normalize caller-supplied BOM material without reading any path."""

    holds: list[str] = []
    if expected_bom_bytes is not None:
        if len(expected_bom_bytes) == 0 or len(expected_bom_bytes) > MAX_BINDING_BYTES:
            holds.append("source_bom_binding_expected_bom_size_invalid")
        try:
            parsed = _parse_json(expected_bom_bytes)
        except BindingError as error:
            holds.append(str(error).replace("source_bom_binding_", "source_bom_binding_expected_bom_", 1))
            parsed = None
        if expected_bom is not None and parsed is not None and dict(expected_bom) != parsed:
            holds.append("source_bom_binding_expected_bom_object_mismatch")
        if parsed is not None:
            expected_bom = parsed
    if expected_bom is None:
        return None, expected_bom_bytes, holds
    if not isinstance(expected_bom, Mapping):
        holds.append("source_bom_binding_expected_bom_not_object")
        return None, expected_bom_bytes, holds
    if expected_bom_bytes is None:
        try:
            expected_bom_bytes = canonical_json_bytes(expected_bom)
        except (TypeError, ValueError) as error:
            holds.append("source_bom_binding_expected_bom_not_canonical")
            return None, None, holds
    return expected_bom, expected_bom_bytes, holds


def validate_source_bom_binding(
    value: object,
    *,
    raw: bytes | None = None,
    expected_bom: Mapping[str, Any] | None = None,
    expected_bom_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Validate one binding object and return a bounded report.

    ``expected_bom``/``expected_bom_bytes`` are optional cross-check inputs.
    When supplied, the binding must identify that exact BOM receipt and its
    source-set/manifest digests.  The function never treats a binding as a
    signature or release authorization.
    """

    holds: list[str] = []
    if not isinstance(value, Mapping):
        return {"valid": False, "holds": ["source_bom_binding_not_object"]}
    holds.extend(_exact_keys(value, _TOP_KEYS, "top_level"))
    if value.get("schema") != BINDING_SCHEMA:
        holds.append("source_bom_binding_schema_invalid")
    if value.get("authority") != BINDING_AUTHORITY:
        holds.append("source_bom_binding_authority_invalid")

    source_bom = value.get("source_bom")
    if not isinstance(source_bom, Mapping):
        holds.append("source_bom_binding_source_bom_not_object")
    else:
        holds.extend(_exact_keys(source_bom, _SOURCE_BOM_KEYS, "source_bom"))
        if source_bom.get("schema") != BOM_SCHEMA:
            holds.append("source_bom_binding_source_bom_schema_invalid")
        if not _valid_receipt(source_bom.get("receipt_id")):
            holds.append("source_bom_binding_source_bom_receipt_id_invalid")
        if not _valid_bytes(source_bom.get("bytes")):
            holds.append("source_bom_binding_source_bom_bytes_invalid")
        for field in _DIGEST_FIELDS:
            if not _valid_hex(source_bom.get(field)):
                holds.append(f"source_bom_binding_source_bom_{field}_invalid")

    holds.extend(
        _validate_descriptor(
            value.get("source_set"),
            label="source_set",
            schema=BOM_SOURCE_SET_SCHEMA,
        )
    )
    holds.extend(
        _validate_descriptor(
            value.get("resolved_manifest"),
            label="resolved_manifest",
            schema=RESOLVED_MANIFEST_SCHEMA,
        )
    )
    holds.extend(_validate_descriptor(value.get("receipt_stage"), label="receipt_stage"))
    receipt_stage = value.get("receipt_stage")
    if (
        not isinstance(receipt_stage, Mapping)
        or not isinstance(receipt_stage.get("schema"), str)
        or not receipt_stage["schema"].startswith(RECEIPT_STAGE_SCHEMA_PREFIX)
    ):
        holds.append("source_bom_binding_receipt_stage_schema_invalid")

    binding_id = value.get("binding_id")
    if not _valid_receipt(binding_id):
        holds.append("source_bom_binding_binding_id_invalid")
    else:
        preimage = dict(value)
        preimage.pop("binding_id", None)
        try:
            expected_id = "sha256:" + hashlib.sha256(canonical_json_bytes(preimage)).hexdigest()
        except (TypeError, ValueError):
            expected_id = None
        if expected_id is None or binding_id != expected_id:
            holds.append("source_bom_binding_binding_id_mismatch")

    if raw is not None:
        if len(raw) == 0 or len(raw) > MAX_BINDING_BYTES:
            holds.append("source_bom_binding_size_invalid")
        else:
            try:
                if canonical_json_bytes(value) != raw:
                    holds.append("source_bom_binding_not_canonical")
            except (TypeError, ValueError):
                holds.append("source_bom_binding_not_canonical")

    expected_bom, expected_bom_bytes, expected_holds = _expected_bom_identity(
        expected_bom=expected_bom, expected_bom_bytes=expected_bom_bytes
    )
    holds.extend(expected_holds)
    if expected_bom is not None and isinstance(source_bom, Mapping):
        expected_receipt = expected_bom.get("receipt_id")
        if source_bom.get("receipt_id") != expected_receipt:
            holds.append("source_bom_binding_bom_receipt_id_mismatch")
        expected_sha = hashlib.sha256(expected_bom_bytes or b"").hexdigest()
        if source_bom.get("sha256") != expected_sha:
            holds.append("source_bom_binding_bom_sha256_mismatch")
        if source_bom.get("bytes") != len(expected_bom_bytes or b""):
            holds.append("source_bom_binding_bom_bytes_mismatch")
        expected_source_set = expected_bom.get("source_set")
        binding_source_set = value.get("source_set")
        if isinstance(expected_source_set, Mapping) and isinstance(binding_source_set, Mapping):
            if binding_source_set.get("schema") != expected_source_set.get("schema"):
                holds.append("source_bom_binding_source_set_schema_mismatch")
            if source_bom.get("source_set_sha256") != expected_source_set.get("sha256"):
                holds.append("source_bom_binding_source_set_sha256_mismatch")
            if _valid_bytes(expected_source_set.get("bytes")) and binding_source_set.get("bytes") != expected_source_set.get("bytes"):
                holds.append("source_bom_binding_source_set_bytes_mismatch")
        expected_manifest = expected_bom.get("resolved_manifest")
        binding_manifest = value.get("resolved_manifest")
        if isinstance(expected_manifest, Mapping) and isinstance(binding_manifest, Mapping):
            expected_manifest_sha = expected_manifest.get("sha256")
            if _valid_hex(expected_manifest_sha) and source_bom.get("resolved_manifest_sha256") != expected_manifest_sha:
                holds.append("source_bom_binding_resolved_manifest_sha256_mismatch")
            if _valid_bytes(expected_manifest.get("bytes")) and binding_manifest.get("bytes") != expected_manifest.get("bytes"):
                holds.append("source_bom_binding_resolved_manifest_bytes_mismatch")

    # The nested descriptors and the compact source-BOM projection must agree
    # even when no external BOM was supplied.  Otherwise a self-consistent
    # binding could carry two different source-set or manifest identities.
    if isinstance(source_bom, Mapping):
        binding_source_set = value.get("source_set")
        if isinstance(binding_source_set, Mapping) and binding_source_set.get("sha256") != source_bom.get("source_set_sha256"):
            holds.append("source_bom_binding_source_set_sha256_internal_mismatch")
        binding_manifest = value.get("resolved_manifest")
        if isinstance(binding_manifest, Mapping) and binding_manifest.get("sha256") != source_bom.get("resolved_manifest_sha256"):
            holds.append("source_bom_binding_resolved_manifest_sha256_internal_mismatch")

    holds = list(dict.fromkeys(holds))
    return {
        "valid": not holds,
        "holds": holds,
        "binding_id": binding_id if isinstance(binding_id, str) else None,
        "schema": value.get("schema"),
        "source_bom_receipt_id": source_bom.get("receipt_id") if isinstance(source_bom, Mapping) else None,
    }


def assert_valid_source_bom_binding(
    value: object,
    *,
    raw: bytes | None = None,
    expected_bom: Mapping[str, Any] | None = None,
    expected_bom_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Exception-oriented wrapper for build/release callers."""

    report = validate_source_bom_binding(
        value,
        raw=raw,
        expected_bom=expected_bom,
        expected_bom_bytes=expected_bom_bytes,
    )
    if not report["valid"]:
        raise BindingError(",".join(report["holds"]))
    return report


def inspect_target_files_source_bom_binding(
    target_files: Path,
    *,
    require_binding: bool = False,
    expected_bom: Mapping[str, Any] | None = None,
    expected_bom_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Inspect the binding member in a target-files ZIP.

    ``require_binding=False`` intentionally preserves old fixtures.  Set it
    to ``True`` in a future target-files/release gate once the builder embeds
    the member.  No target-files digest is accepted here: putting that digest
    inside the archive would create a circular self-reference.
    """

    result: dict[str, Any] = {
        "present": False,
        "required": require_binding,
        "member": BINDING_MEMBER,
        "valid": True,
        "holds": [],
    }
    try:
        if _has_symlink_component(target_files):
            raise BindingError("target_files_source_bom_binding_symlink_path")
        if target_files.stat().st_size <= 0 or target_files.stat().st_size > MAX_TARGET_BYTES:
            raise BindingError("target_files_source_bom_binding_target_size_invalid")
        with zipfile.ZipFile(target_files, "r") as archive:
            names = archive.namelist()
            if not names or len(names) > MAX_ZIP_ENTRIES:
                raise BindingError("target_files_source_bom_binding_zip_entry_count_invalid")
            if len(names) != len(set(names)):
                raise BindingError("target_files_source_bom_binding_duplicate_zip_member")
            for name in names:
                _safe_zip_member(name)
            try:
                info = archive.getinfo(BINDING_MEMBER)
            except KeyError:
                if require_binding:
                    result["holds"] = ["target_files_source_bom_binding_missing"]
                    result["valid"] = False
                return result
            if info.file_size <= 0 or info.file_size > MAX_MEMBER_BYTES:
                result["holds"] = ["target_files_source_bom_binding_member_size_invalid"]
                result["valid"] = False
                return result
            raw = archive.read(info)
        parsed = _parse_json(raw)
        report = validate_source_bom_binding(
            parsed,
            raw=raw,
            expected_bom=expected_bom,
            expected_bom_bytes=expected_bom_bytes,
        )
        result.update(
            {
                "present": True,
                "valid": report["valid"],
                "holds": report["holds"],
                "binding_id": report.get("binding_id"),
                "source_bom_receipt_id": report.get("source_bom_receipt_id"),
            }
        )
    except (OSError, RuntimeError, EOFError, ValueError, zipfile.BadZipFile, BindingError) as error:
        result["valid"] = False
        result["holds"] = [str(error)]
    return result


def validate_target_files_source_bom_binding(
    target_files: Path,
    *,
    require_binding: bool = False,
    expected_bom: Mapping[str, Any] | None = None,
    expected_bom_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Compatibility spelling for callers that treat inspection as a gate."""

    return inspect_target_files_source_bom_binding(
        target_files,
        require_binding=require_binding,
        expected_bom=expected_bom,
        expected_bom_bytes=expected_bom_bytes,
    )


__all__ = [
    "BINDING_AUTHORITY",
    "BINDING_MEMBER",
    "BINDING_SCHEMA",
    "BindingError",
    "assert_valid_source_bom_binding",
    "canonical_json_bytes",
    "inspect_target_files_source_bom_binding",
    "validate_target_files_source_bom_binding",
    "validate_source_bom_binding",
]
