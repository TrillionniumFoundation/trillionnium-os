#!/usr/bin/env python3
"""Read-only Android target-files release/flash preflight.

This checker is deliberately smaller than the Android signing pipeline.  It
only reads a target-files ZIP and two public, detached evidence documents.  It
does not invoke ``sign_target_files_apks``, ``ota_from_target_files``, fastboot,
ADB, or any other external command; it never opens private-key material.

An ``ELIGIBLE`` result means that the target-files metadata is release-shaped,
the detached signed metadata is explicitly bound to the exact target-files
digest, and detached rollback evidence covers every AVB rollback index in the
target.  It is still a preflight result, not authorization to flash a device.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any, Mapping, Sequence
import zipfile


GATE_SCHEMA = "org.trillionnium.android-release-gate.v1"
SIGNED_METADATA_SCHEMA = "org.trillionnium.android-release-signed-metadata.v1"
ROLLBACK_EVIDENCE_SCHEMA = "org.trillionnium.android-rollback-evidence.v1"
HOLD_EXIT = 78

# These limits keep the verifier a bounded metadata reader.  The v28 target
# files archive is about 3.3 GiB, so the target limit intentionally leaves
# ample room while preventing an accidental unbounded read.
MAX_TARGET_BYTES = 16 * 1024 * 1024 * 1024
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_METADATA_MEMBER_BYTES = 2 * 1024 * 1024
MAX_ZIP_ENTRIES = 1_000_000
MAX_BUILD_PROP_FILES = 128
MAX_ROLLBACK_INDEX = (1 << 64) - 1

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_PRIVATE_SUFFIXES = frozenset(
    {".pem", ".key", ".pk8", ".p12", ".pfx", ".jks", ".keystore", ".der"}
)
_PRIVATE_NAME_PARTS = frozenset(
    {"private", "private-key", "private_key", "secret", "secrets", "passphrase"}
)


class GateError(ValueError):
    """A bounded, public-facing hold reason."""


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GateError("evidence_json_duplicate_key")
        result[key] = value
    return result


def _strict_json(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                GateError(f"{label}_non_finite_number")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise GateError(f"{label}_invalid_json") from error
    if type(value) is not dict:
        raise GateError(f"{label}_must_be_object")
    return value


def _identity(item: os.stat_result) -> tuple[int, ...]:
    return (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_uid,
        item.st_gid,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )


def _open_nofollow_path(
    path: Path, *, label: str
) -> tuple[int, int | None, str | None]:
    """Open a path without following *any* symlink component.

    ``O_NOFOLLOW`` on the final pathname component is not sufficient for a
    read-only gate: a symlinked parent directory could redirect an apparently
    public evidence path into a private-key tree.  Walk the absolute path one
    directory at a time with ``openat(..., O_NOFOLLOW)`` and retain the parent
    descriptor so the caller can perform its post-read identity check against
    the same directory entry.
    """

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise GateError(f"{label}_nofollow_unavailable")
    absolute = os.path.abspath(os.fspath(path))
    components = Path(absolute).parts
    flags = os.O_RDONLY | os.O_CLOEXEC | nofollow
    try:
        parent_fd = os.open(os.sep, flags | directory)
    except OSError as error:
        raise GateError(f"{label}_unreadable") from error

    # ``/`` itself is a valid descriptor but will fail the regular-file check
    # in the caller.  There is no parent directory entry to re-stat.
    if len(components) == 1:
        return parent_fd, None, None

    try:
        for index, component in enumerate(components[1:]):
            last = index == len(components[1:]) - 1
            child_flags = flags | (0 if last else directory)
            child_fd = os.open(component, child_flags, dir_fd=parent_fd)
            if last:
                return child_fd, parent_fd, component
            os.close(parent_fd)
            parent_fd = child_fd
    except OSError as error:
        os.close(parent_fd)
        raise GateError(f"{label}_unreadable") from error

    # The loop always returns on the final component; keep a defensive hold
    # for unusual platform/path implementations.
    os.close(parent_fd)
    raise GateError(f"{label}_unreadable")


def _read_regular(
    path: Path, *, label: str, maximum: int, retain: bool = True
) -> tuple[bytes, str, int]:
    """Read one stable, non-symlink regular file and return bytes/digest/size."""

    descriptor, parent_descriptor, basename = _open_nofollow_path(path, label=label)
    chunks: list[bytes] = []
    digest = hashlib.sha256()
    observed = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise GateError(f"{label}_size_out_of_bounds")
        while observed < maximum:
            block = os.read(descriptor, min(1024 * 1024, maximum - observed))
            if not block:
                break
            observed += len(block)
            if observed > maximum:
                raise GateError(f"{label}_size_out_of_bounds")
            if retain:
                chunks.append(block)
            digest.update(block)
        after = os.fstat(descriptor)
        if observed != before.st_size or _identity(before) != _identity(after):
            raise GateError(f"{label}_changed_while_read")

        if parent_descriptor is not None and basename is not None:
            # This check intentionally uses the retained parent descriptor
            # rather than the pathname, so a replaced/symlinked parent cannot
            # redirect the post-read check.
            current = os.stat(
                basename,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if stat.S_ISLNK(current.st_mode) or _identity(current) != _identity(before):
                raise GateError(f"{label}_changed_after_read")
    except OSError as error:
        raise GateError(f"{label}_unreadable") from error
    finally:
        os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
    return b"".join(chunks), digest.hexdigest(), before.st_size


def _assert_public_evidence_path(path: Path, label: str) -> None:
    """Reject obvious private-material paths before opening them."""

    if path.suffix.lower() in _PRIVATE_SUFFIXES:
        raise GateError(f"{label}_private_material_path")
    components = {part.lower() for part in path.parts}
    if components & _PRIVATE_NAME_PARTS:
        raise GateError(f"{label}_private_material_path")


def _parse_properties(raw: bytes, label: str) -> dict[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GateError(f"{label}_not_utf8") from error
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key:
            value = value.strip()
            if key in result and result[key] != value:
                raise GateError(f"{label}_conflicting_duplicate_property")
            result[key] = value
    return result


def _safe_zip_member(name: str) -> None:
    if not name or "\\" in name or name.startswith("/") or "\x00" in name:
        raise GateError("target_files_unsafe_zip_member")
    path = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise GateError("target_files_non_canonical_zip_member")


def _read_zip_member_safe(
    archive: zipfile.ZipFile, name: str, *, maximum: int
) -> bytes:
    try:
        info = archive.getinfo(name)
    except KeyError as error:
        raise GateError(f"target_files_missing_{name.replace('/', '_')}") from error
    if info.file_size < 0 or info.file_size > maximum:
        raise GateError(f"target_files_member_too_large_{name.replace('/', '_')}")
    try:
        return archive.read(info)
    except (
        OSError,
        RuntimeError,
        zipfile.BadZipFile,
        NotImplementedError,
        EOFError,
        ValueError,
    ) as error:
        raise GateError(f"target_files_member_unreadable_{name.replace('/', '_')}") from error


def _parse_rollback_args(raw: str, label: str) -> int | None:
    tokens = raw.split()
    values: list[int] = []
    for index, token in enumerate(tokens):
        if token == "--rollback_index":
            if index + 1 >= len(tokens):
                raise GateError(f"{label}_invalid_rollback_index")
            value = tokens[index + 1]
        elif token.startswith("--rollback_index="):
            value = token.split("=", 1)[1]
        else:
            continue
        try:
            parsed = int(value, 0)
        except ValueError as error:
            raise GateError(f"{label}_invalid_rollback_index") from error
        if not 0 <= parsed <= MAX_ROLLBACK_INDEX:
            raise GateError(f"{label}_rollback_index_out_of_range")
        values.append(parsed)
    if not values:
        return None
    if len(set(values)) != 1:
        raise GateError(f"{label}_conflicting_rollback_index")
    return values[0]


def _parse_location(value: str | None, label: str) -> int:
    if value is None:
        raise GateError(f"{label}_missing_rollback_location")
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise GateError(f"{label}_invalid_rollback_location") from error
    if not 0 <= parsed <= 31:
        raise GateError(f"{label}_rollback_location_out_of_range")
    return parsed


def _target_metadata(path: Path, baseline: tuple[str, int]) -> dict[str, Any]:
    """Read only target-files metadata needed by the release gate."""

    digest, size = baseline
    try:
        before_identity = _identity(os.stat(path))
    except OSError as error:
        raise GateError("target_files_unreadable") from error
    facts: dict[str, Any] = {
        "sha256": digest,
        "bytes": size,
        "build_types": [],
        "build_tags": [],
        "fingerprints": [],
        "ota_keys_nonempty": False,
        "avb_rollback_indices": {},
    }
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as error:
        raise GateError("target_files_invalid_zip") from error
    try:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_ZIP_ENTRIES:
            raise GateError("target_files_zip_entry_count_out_of_bounds")
        names: set[str] = set()
        for info in infos:
            _safe_zip_member(info.filename)
            if info.filename in names:
                raise GateError("target_files_duplicate_zip_member")
            names.add(info.filename)
            # Android target-files commonly carries intentional symlink
            # entries inside partition trees.  We never extract members, so a
            # safe canonical name is sufficient here; host-side symlink
            # traversal is not possible.

        misc_raw = _read_zip_member_safe(
            archive, "META/misc_info.txt", maximum=MAX_METADATA_MEMBER_BYTES
        )
        misc = _parse_properties(misc_raw, "misc_info")
        facts["ab_update"] = misc.get("ab_update") == "true"
        facts["avb_enabled"] = misc.get("avb_enable") == "true"
        facts["misc_build_type"] = misc.get("build_type")

        ota_name = "META/otakeys.txt"
        try:
            ota_raw = _read_zip_member_safe(
                archive, ota_name, maximum=MAX_METADATA_MEMBER_BYTES
            )
            facts["ota_keys_nonempty"] = any(
                line.strip() and not line.lstrip().startswith(b"#")
                for line in ota_raw.splitlines()
            )
            facts["ota_keys_bytes"] = len(ota_raw)
        except GateError as error:
            facts["ota_keys_error"] = str(error)

        build_prop_names = [
            name
            for name in sorted(names)
            if name == "build.prop" or name.endswith("/build.prop")
        ]
        if len(build_prop_names) > MAX_BUILD_PROP_FILES:
            raise GateError("target_files_build_prop_count_out_of_bounds")
        for name in build_prop_names:
            raw = _read_zip_member_safe(
                archive, name, maximum=MAX_METADATA_MEMBER_BYTES
            )
            props = _parse_properties(raw, name.replace("/", "_"))
            for key, value in props.items():
                lowered = key.lower()
                if lowered == "ro.build.type" or lowered.endswith(".build.type"):
                    if value:
                        facts["build_types"].append(value)
                if lowered == "ro.build.tags" or lowered.endswith(".build.tags"):
                    if value:
                        facts["build_tags"].extend(
                            token.strip() for token in value.split(",") if token.strip()
                        )
                if lowered == "ro.build.fingerprint" or lowered.endswith(
                    ".build.fingerprint"
                ):
                    if value:
                        facts["fingerprints"].append(value)

        if misc.get("build_type"):
            facts["build_types"].append(misc["build_type"])
        # Fingerprints and AVB footer arguments are metadata too; checking them
        # catches a userdebug/test-key value even if one build.prop was omitted.
        for key, value in misc.items():
            if "fingerprint" in key.lower() and value:
                facts["fingerprints"].append(value)

        for key, value in misc.items():
            match = re.fullmatch(r"avb_([a-z0-9_]+)_args", key)
            if not match:
                continue
            partition = match.group(1)
            rollback_index = _parse_rollback_args(value, f"avb_{partition}_args")
            if rollback_index is None:
                # An AVB-enabled target must expose an explicit rollback
                # index for every partition footer argument.  Silently
                # skipping one would let detached evidence cover only a
                # convenient subset while an untracked image remained
                # rollback-ambiguous.
                if facts["avb_enabled"]:
                    raise GateError(
                        f"avb_{partition}_args_missing_rollback_index"
                    )
                continue
            location = 0 if partition == "vbmeta" else _parse_location(
                misc.get(f"avb_{partition}_rollback_index_location"),
                f"avb_{partition}",
            )
            facts["avb_rollback_indices"][partition] = {
                "rollback_index": rollback_index,
                "rollback_index_location": location,
            }
        facts["zip_entry_count"] = len(names)
    finally:
        archive.close()
    # Confirm the ZIP was not replaced while metadata was read.
    current = os.stat(path)
    if _identity(current) != before_identity:  # pragma: no cover - defensive
        raise GateError("target_files_changed_after_metadata_read")
    return facts


def _normalise_tags(value: object) -> set[str]:
    if isinstance(value, str):
        return {part.strip() for part in value.split(",") if part.strip()}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return {item.strip() for item in value if item.strip()}
    return set()


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def _validate_signed_metadata(
    path: Path, target_sha256: str, target_facts: Mapping[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    _assert_public_evidence_path(path, "signed_metadata")
    raw, digest, size = _read_regular(
        path, label="signed_metadata", maximum=MAX_EVIDENCE_BYTES
    )
    value = _strict_json(raw, "signed_metadata")
    holds: list[str] = []
    if value.get("schema") != SIGNED_METADATA_SCHEMA:
        holds.append("signed_metadata_schema_invalid")
    if value.get("signed") is not True:
        holds.append("signed_metadata_not_explicitly_signed")
    evidence_digest = value.get("target_files_sha256")
    if not _is_sha256(evidence_digest):
        holds.append("signed_metadata_target_digest_invalid")
    elif evidence_digest.lower() != target_sha256.lower():
        holds.append("signed_metadata_target_digest_mismatch")
    if value.get("build_type") != "user":
        holds.append("signed_metadata_build_type_not_user")
    expected_tags = {"release-keys"}
    if _normalise_tags(value.get("build_tags")) != expected_tags:
        holds.append("signed_metadata_tags_not_release_keys")

    signature = value.get("signature")
    signature_value: str | None = None
    signature_key_id: str | None = None
    if isinstance(signature, str):
        signature_value = signature.strip()
    elif isinstance(signature, Mapping):
        candidate = signature.get("value")
        if isinstance(candidate, str):
            signature_value = candidate.strip()
        candidate_key = signature.get("key_id")
        if isinstance(candidate_key, str):
            signature_key_id = candidate_key.strip()
    candidate_key = value.get("signing_key_id")
    if isinstance(candidate_key, str):
        signature_key_id = candidate_key.strip()
    if not signature_value:
        holds.append("signed_metadata_signature_missing")
    if not signature_key_id:
        holds.append("signed_metadata_signing_key_id_missing")
    if "signature_verified" in value and value.get("signature_verified") is not True:
        holds.append("signed_metadata_signature_not_verified")

    return (
        {
            "present": True,
            "sha256": digest,
            "bytes": size,
            "schema": value.get("schema"),
            "signature_present": bool(signature_value),
            "signing_key_id_present": bool(signature_key_id),
            "target_files_sha256": evidence_digest,
        },
        holds,
    )


def _validate_rollback_evidence(
    path: Path,
    target_sha256: str,
    target_facts: Mapping[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    _assert_public_evidence_path(path, "rollback_evidence")
    raw, digest, size = _read_regular(
        path, label="rollback_evidence", maximum=MAX_EVIDENCE_BYTES
    )
    value = _strict_json(raw, "rollback_evidence")
    holds: list[str] = []
    if value.get("schema") != ROLLBACK_EVIDENCE_SCHEMA:
        holds.append("rollback_evidence_schema_invalid")
    evidence_digest = value.get("target_files_sha256")
    if not _is_sha256(evidence_digest):
        holds.append("rollback_evidence_target_digest_invalid")
    elif evidence_digest.lower() != target_sha256.lower():
        holds.append("rollback_evidence_target_digest_mismatch")
    proven = value.get("hardware_antirollback_proven")
    if proven is not True and value.get("verified") is not True:
        holds.append("rollback_hardware_proof_missing")
    evidence_id = value.get("evidence_id")
    if not isinstance(evidence_id, str) or not evidence_id.strip():
        holds.append("rollback_evidence_id_missing")

    observed = target_facts.get("avb_rollback_indices")
    if not isinstance(observed, Mapping) or not observed:
        holds.append("target_files_rollback_indices_missing")
        observed = {}
    entries = value.get("indices")
    if entries is None:
        entries = value.get("rollback_indices")
    if not isinstance(entries, Mapping):
        holds.append("rollback_evidence_indices_missing")
        entries = {}
    for partition, expected in observed.items():
        item = entries.get(partition)
        if not isinstance(item, Mapping):
            holds.append(f"rollback_evidence_missing_{partition}")
            continue
        if type(item.get("rollback_index")) is not int:
            holds.append(f"rollback_evidence_index_invalid_{partition}")
        elif item.get("rollback_index") != expected.get("rollback_index"):
            holds.append(f"rollback_evidence_index_mismatch_{partition}")
        if type(item.get("rollback_index_location")) is not int:
            holds.append(f"rollback_evidence_location_invalid_{partition}")
        elif item.get("rollback_index_location") != expected.get("rollback_index_location"):
            holds.append(f"rollback_evidence_location_mismatch_{partition}")

    # Extra entries are rejected as well.  Exact key-set equality prevents a
    # stale attestation for an unrelated partition from being mistaken for a
    # complete description of the current target-files archive.
    if isinstance(entries, Mapping):
        for partition in sorted(set(entries) - set(observed)):
            holds.append(f"rollback_evidence_unexpected_{partition}")

    return (
        {
            "present": True,
            "sha256": digest,
            "bytes": size,
            "schema": value.get("schema"),
            "hardware_antirollback_proven": proven is True
            or value.get("verified") is True,
            "evidence_id_present": isinstance(evidence_id, str)
            and bool(evidence_id.strip()),
            "covered_partitions": sorted(
                partition for partition in observed if partition in entries
            ),
        },
        holds,
    )


def _dedupe(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def verify_target_files(
    target_files: Path,
    *,
    signed_metadata: Path | None = None,
    rollback_evidence: Path | None = None,
) -> dict[str, Any]:
    """Return a public report without mutating any input.

    ``eligible`` is true only when every hold list is empty.  Missing or
    malformed evidence is represented as a HOLD rather than an exception so a
    caller can safely display the complete reason set.
    """

    target_files = Path(target_files)
    holds: list[str] = []
    target_public: dict[str, Any] = {"name": target_files.name, "present": False}
    signed_public: dict[str, Any] = {
        "present": False,
        "required": True,
    }
    rollback_public: dict[str, Any] = {
        "present": False,
        "required": True,
    }
    facts: dict[str, Any] = {}

    try:
        raw, digest, size = _read_regular(
            target_files, label="target_files", maximum=MAX_TARGET_BYTES, retain=False
        )
        # Keep the bytes only long enough to ensure the read path was exercised;
        # ZIP parsing reopens the stable file and does not retain a multi-GB copy.
        del raw
        target_public.update({"present": True, "sha256": digest, "bytes": size})
        facts = _target_metadata(target_files, (digest, size))
        target_public.update(
            {
                key: facts[key]
                for key in (
                    "build_types",
                    "build_tags",
                    "misc_build_type",
                    "fingerprints",
                    "ota_keys_nonempty",
                    "ota_keys_bytes",
                    "avb_rollback_indices",
                    "ab_update",
                    "avb_enabled",
                    "zip_entry_count",
                )
                if key in facts
            }
        )
    except (GateError, OSError, zipfile.BadZipFile) as error:
        holds.append(str(error))

    if facts:
        raw_build_types = [str(item) for item in facts.get("build_types", [])]
        raw_build_tags = {str(item) for item in facts.get("build_tags", [])}
        # Keep normalized views for diagnostics, but admission itself is
        # intentionally case-sensitive: Android's canonical release markers
        # are exactly ``user`` and ``release-keys``.
        build_types = [item.lower() for item in raw_build_types]
        build_tags = {item.lower() for item in raw_build_tags}
        fingerprints = [str(item).lower() for item in facts.get("fingerprints", [])]
        if not build_types:
            holds.append("target_build_type_missing")
        if any(item != "user" for item in raw_build_types):
            holds.append("target_build_type_not_user")
        if not build_tags:
            holds.append("target_build_tags_missing")
        if "release-keys" not in build_tags:
            holds.append("target_build_tags_missing_release_keys")
        # A release build must not carry an unrecognised/additional tag.  In
        # particular, accepting ``release-keys,foo`` would make the detached
        # release attestation weaker than the target-files metadata it claims
        # to describe.
        if raw_build_tags != {"release-keys"}:
            holds.append("target_build_tags_not_exact_release_keys")
        if {"test-keys", "dev-keys"} & build_tags:
            holds.append("target_build_tags_contain_development_keys")
        development_text = "\n".join(
            [*fingerprints, str(facts.get("misc_build_type", ""))]
        ).lower()
        # Fingerprints are conventionally ``...:<type>/<tags>``.  Keep the
        # broad userdebug/test-key checks, and also reject an ``eng`` type or
        # explicit dev keys even if a malformed build.prop reports a friendly
        # ``user`` value elsewhere.
        # ``eng`` also commonly appears in the incremental/build-host field
        # (for example ``.../eng.builder:user/release-keys``), so only treat
        # it as a variant when it is the fingerprint's type token immediately
        # after the final colon.
        eng_fingerprint = re.search(r":eng(?:/|$)", development_text)
        if (
            "userdebug" in development_text
            or "test-keys" in development_text
            or "dev-keys" in development_text
            or eng_fingerprint is not None
        ):
            holds.append("target_metadata_contains_userdebug_or_test_keys")
        if not facts.get("ota_keys_nonempty", False):
            holds.append("target_ota_keys_empty_or_missing")
        if facts.get("ab_update") is not True or facts.get("avb_enabled") is not True:
            holds.append("target_not_avb_enabled_ab_product")
        if not facts.get("avb_rollback_indices"):
            holds.append("target_rollback_indices_missing")

    if signed_metadata is None:
        holds.append("signed_metadata_missing")
    elif target_public.get("present") and facts:
        try:
            signed_public, signed_holds = _validate_signed_metadata(
                Path(signed_metadata), str(target_public["sha256"]), facts
            )
            holds.extend(signed_holds)
        except (GateError, OSError) as error:
            holds.append(str(error))
            signed_public = {"present": False, "required": True}

    if rollback_evidence is None:
        holds.append("rollback_evidence_missing")
    elif target_public.get("present") and facts:
        try:
            rollback_public, rollback_holds = _validate_rollback_evidence(
                Path(rollback_evidence), str(target_public["sha256"]), facts
            )
            holds.extend(rollback_holds)
        except (GateError, OSError) as error:
            holds.append(str(error))
            rollback_public = {"present": False, "required": True}

    holds = _dedupe(holds)
    eligible = not holds
    return {
        "schema": GATE_SCHEMA,
        "decision": "ELIGIBLE" if eligible else "HOLD",
        "eligible": eligible,
        "target_files": target_public,
        "signed_metadata": signed_public,
        "rollback_evidence": rollback_public,
        "holds": holds,
        "effects": {
            "flash_performed": False,
            "signing_performed": False,
            "private_key_accessed": False,
            "files_written": False,
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target_files_positional", type=Path, nargs="?")
    parser.add_argument(
        "--target-files",
        dest="target_files_option",
        type=Path,
        help="target-files ZIP (the positional form is also accepted)",
    )
    parser.add_argument("--signed-metadata", type=Path)
    parser.add_argument("--rollback-evidence", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.target_files_positional is None and args.target_files_option is None:
        parser.error("a target-files ZIP is required")
    if (
        args.target_files_positional is not None
        and args.target_files_option is not None
        and args.target_files_positional != args.target_files_option
    ):
        parser.error("positional target-files and --target-files differ")
    target_files = args.target_files_option or args.target_files_positional
    report = verify_target_files(
        target_files,
        signed_metadata=args.signed_metadata,
        rollback_evidence=args.rollback_evidence,
    )
    sys.stdout.buffer.write(canonical_json_bytes(report))
    return 0 if report["eligible"] else HOLD_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
