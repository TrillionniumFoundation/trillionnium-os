#!/usr/bin/env python3
"""Materialize an explicitly non-authorizing userdebug dirty-source receipt.

The normal cross-repository BOM deliberately fails closed when a checkout has
dirty or ignored paths.  A local test handset sometimes needs a receipt that
describes that *exact* state without pretending that it is a release BOM.  This
tool is the narrow bridge for that case: it consumes an already-materialized
v2 ``HOLD_LOCAL_SOURCE_GRAPH`` BOM, verifies its identity and resolved-manifest
binding, and emits a separate userdebug-dogfood schema.

The command is host-only.  It does not clean a checkout, resolve a manifest,
build an image, sign an OTA, authorize an effect, or talk to a device.  The
explicit ``--allow-dirty-userdebug-dogfood`` switch is mandatory.  Only the
two expected project-state blockers (non-ignored dirt and ignored paths) are
accepted; missing artifacts, manifest drift, malformed source, or any other
blocker remain rejected.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Iterable
import re
import xml.etree.ElementTree as ET


SOURCE_BOM_SCHEMA = "org.trillionnium.local-cross-repo-source-bom.v2"
SOURCE_BOM_HOLD = "HOLD_LOCAL_SOURCE_GRAPH"
DOGFOOD_SCHEMA = "org.trillionnium.userdebug-dogfood-source-bom.v1"
DOGFOOD_DECISION = "PASS_USERDEBUG_DIRTY_DOGFOOD_SNAPSHOT"
RECEIPT_ID_SCOPE = "sha256(canonical-json-utf8-without-receipt_id)"
MAX_BOM_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
SHA256_PREFIX = "sha256:"
ALLOWED_FAILURES = frozenset(
    {"nonignored_worktree_dirty", "ignored_paths_present"}
)
POSTURE_FALSE_KEYS = (
    "signed",
    "release_pin_published",
    "build_authorized",
    "ota_authorized",
    "device_write_authorized",
    "public_release_allowed",
    "release_allowed",
    "effect_authority",
)
REQUIRED_SOURCE_POSTURE_FALSE_KEYS = (
    "signed",
    "release_pin_published",
    "build_authorized",
    "ota_authorized",
    "device_write_authorized",
)
REVISION_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class DogfoodBomError(RuntimeError):
    """Raised for malformed or unsafe input."""


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DogfoodBomError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_symlink_parents(path: Path) -> None:
    absolute = Path(os.path.abspath(os.fspath(path)))
    current = Path(absolute.anchor or os.sep)
    for component in absolute.parts[1:]:
        current /= component
        try:
            mode = os.lstat(current).st_mode
        except OSError as error:
            raise DogfoodBomError(f"path component unavailable: {current}") from error
        if stat.S_ISLNK(mode):
            raise DogfoodBomError(f"symlink path component is forbidden: {current}")


def read_stable_regular(path: Path, label: str, maximum: int) -> bytes:
    """Read one bounded regular file without following links or races."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    _reject_symlink_parents(absolute.parent)
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise DogfoodBomError(f"{label} is unavailable") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > maximum
        ):
            raise DogfoodBomError(f"{label} is not a bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            block = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
        after = os.fstat(descriptor)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
            value.st_mode,
            value.st_uid,
            value.st_gid,
            value.st_nlink,
        )
        if total != before.st_size or identity(before) != identity(after):
            raise DogfoodBomError(f"{label} changed while being read")
    finally:
        os.close(descriptor)
    try:
        current = os.lstat(absolute)
    except OSError as error:
        raise DogfoodBomError(f"{label} disappeared after being read") from error
    if stat.S_ISLNK(current.st_mode) or identity(current) != identity(before):
        raise DogfoodBomError(f"{label} pathname changed while being read")
    return b"".join(chunks)


def parse_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                DogfoodBomError(f"{label} contains non-finite number: {token}")
            ),
        )
    except DogfoodBomError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DogfoodBomError(f"{label} is not strict JSON") from error
    if type(value) is not dict:
        raise DogfoodBomError(f"{label} must be a JSON object")
    return value


def _require_dict(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise DogfoodBomError(f"{label} must be an object")
    return value


def _require_string(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise DogfoodBomError(f"{label} must be a non-empty string")
    return value


def _require_sha(value: object, label: str) -> str:
    text = _require_string(value, label)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise DogfoodBomError(f"{label} must be a lowercase SHA-256 digest")
    return text


def _require_nonnegative_int(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise DogfoodBomError(f"{label} must be a non-negative integer")
    return value


def verify_input_self_hash(document: dict[str, Any], label: str) -> str:
    receipt_id = _require_string(document.get("receipt_id"), f"{label}.receipt_id")
    if not receipt_id.startswith(SHA256_PREFIX) or len(receipt_id) != len(SHA256_PREFIX) + 64:
        raise DogfoodBomError(f"{label}.receipt_id has invalid format")
    _require_sha(receipt_id[len(SHA256_PREFIX) :], f"{label}.receipt_id")
    unsigned = copy.deepcopy(document)
    del unsigned["receipt_id"]
    expected = SHA256_PREFIX + hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    if receipt_id != expected:
        raise DogfoodBomError(f"{label}.receipt_id does not match canonical contents")
    return receipt_id


def _verify_posture(posture: object) -> dict[str, Any]:
    value = _require_dict(posture, "source BOM posture")
    if value.get("local_only") is not True:
        raise DogfoodBomError("source BOM posture must be local_only")
    if value.get("network_access_performed") is not False:
        raise DogfoodBomError("source BOM posture records network access")
    for key in REQUIRED_SOURCE_POSTURE_FALSE_KEYS:
        if value.get(key) is not False:
            raise DogfoodBomError(f"source BOM posture is authorizing: {key}")
    # These fields were added by later host-only receipts.  An older v2 BOM
    # may omit them; if present, they must still be explicitly false.
    for key in set(POSTURE_FALSE_KEYS) - set(REQUIRED_SOURCE_POSTURE_FALSE_KEYS):
        if key in value and value[key] is not False:
            raise DogfoodBomError(f"source BOM posture is authorizing: {key}")
    return value


def _verify_descriptor(value: object, label: str, schema: str | None = None) -> dict[str, Any]:
    descriptor = _require_dict(value, label)
    if schema is not None and descriptor.get("schema") != schema:
        raise DogfoodBomError(f"{label}.schema is not {schema}")
    size = _require_nonnegative_int(descriptor.get("bytes"), f"{label}.bytes")
    if size == 0:
        raise DogfoodBomError(f"{label}.bytes must be positive")
    _require_sha(descriptor.get("sha256"), f"{label}.sha256")
    return descriptor


def _verify_resolved_manifest(
    descriptor: object, manifest_raw: bytes
) -> dict[str, Any]:
    value = _require_dict(descriptor, "source BOM resolved_manifest")
    producer = _require_string(value.get("producer"), "resolved_manifest.producer")
    if producer not in {"local_repo_manifest_r", "local_repo_manifest_direct_pinned"}:
        raise DogfoodBomError("resolved_manifest producer is not a trusted local resolver")
    expected_bytes = _require_nonnegative_int(
        value.get("bytes"), "resolved_manifest.bytes"
    )
    expected_sha = _require_sha(value.get("sha256"), "resolved_manifest.sha256")
    actual_sha = hashlib.sha256(manifest_raw).hexdigest()
    if expected_bytes != len(manifest_raw) or expected_sha != actual_sha:
        raise DogfoodBomError("resolved manifest bytes/digest do not match the BOM")
    project_count = value.get("project_count")
    if type(project_count) is not int or project_count <= 0:
        raise DogfoodBomError("resolved_manifest.project_count is invalid")
    if value.get("all_revisions_exact") is not True:
        raise DogfoodBomError("resolved manifest is not exact")
    if value.get("declared_checkout_revision_drift_count") != 0:
        raise DogfoodBomError("resolved manifest has checkout revision drift")
    if value.get("declared_checkout_revision_drifts") != []:
        raise DogfoodBomError("resolved manifest drift inventory is not empty")
    try:
        root = ET.fromstring(manifest_raw)
    except (ET.ParseError, UnicodeDecodeError) as error:
        raise DogfoodBomError("resolved manifest is not well-formed XML") from error
    manifest_projects = list(root.iter("project"))
    if len(manifest_projects) != project_count:
        raise DogfoodBomError("resolved manifest project count does not match the BOM")
    for index, project in enumerate(manifest_projects):
        revision = project.attrib.get("revision")
        if revision is None or REVISION_RE.fullmatch(revision) is None:
            raise DogfoodBomError(
                f"resolved manifest project[{index}] does not have an exact revision"
            )
    return value


def _verify_project_inventory(
    projects: object, blockers: object
) -> tuple[list[dict[str, Any]], list[str], list[str], list[str]]:
    if type(projects) is not list or not projects:
        raise DogfoodBomError("source BOM projects must be a non-empty list")
    if type(blockers) is not list or not all(type(item) is str for item in blockers):
        raise DogfoodBomError("source BOM blockers must be a string list")
    if blockers != sorted(set(blockers)):
        raise DogfoodBomError("source BOM blockers must be sorted and unique")

    observed: list[dict[str, Any]] = []
    expected_blockers: list[str] = []
    dirty_ids: list[str] = []
    ignored_ids: list[str] = []
    seen_ids: set[str] = set()
    for index, candidate in enumerate(projects):
        project = _require_dict(candidate, f"source BOM projects[{index}]")
        project_id = _require_string(project.get("id"), f"projects[{index}].id")
        if project_id in seen_ids:
            raise DogfoodBomError("source BOM project IDs are duplicated")
        seen_ids.add(project_id)
        failures = project.get("failures")
        if type(failures) is not list or not all(type(item) is str for item in failures):
            raise DogfoodBomError(f"projects[{index}].failures is invalid")
        if len(failures) != len(set(failures)):
            raise DogfoodBomError(f"projects[{index}].failures are duplicated")
        for failure in failures:
            if failure not in ALLOWED_FAILURES:
                raise DogfoodBomError(f"unsupported project blocker: {failure}")
            expected_blockers.append(f"project_{failure}:{project_id}")
            if failure == "nonignored_worktree_dirty":
                dirty_ids.append(project_id)
            else:
                ignored_ids.append(project_id)
        git = project.get("git")
        if type(git) is not dict:
            raise DogfoodBomError(f"projects[{index}].git is unavailable")
        if type(git.get("clean_nonignored")) is not bool:
            raise DogfoodBomError(f"projects[{index}].git cleanliness is invalid")
        ignored = git.get("ignored")
        if type(ignored) is not dict:
            raise DogfoodBomError(f"projects[{index}].ignored inventory is unavailable")
        ignored_count = ignored.get("count")
        ignored_paths = ignored.get("paths")
        if (
            type(ignored_count) is not int
            or ignored_count < 0
            or type(ignored_paths) is not list
            or len(ignored_paths) != ignored_count
            or not all(type(path) is str and path for path in ignored_paths)
            or ignored_paths != sorted(set(ignored_paths))
        ):
            raise DogfoodBomError(f"projects[{index}] ignored inventory is invalid")
        requirements = project.get("requirements")
        if type(requirements) is not dict:
            raise DogfoodBomError(f"projects[{index}] requirements are unavailable")
        if requirements.get("clean") is True and (
            (git["clean_nonignored"] is False)
            != ("nonignored_worktree_dirty" in failures)
        ):
            raise DogfoodBomError(f"projects[{index}] dirty inventory is inconsistent")
        if requirements.get("no_ignored_paths") is True and (
            (ignored_count > 0) != ("ignored_paths_present" in failures)
        ):
            raise DogfoodBomError(f"projects[{index}] ignored inventory is inconsistent")
        if "nonignored_worktree_dirty" in failures and git.get("clean_nonignored") is not False:
            raise DogfoodBomError(f"projects[{index}] dirty inventory is inconsistent")
        if "ignored_paths_present" in failures:
            if ignored_count <= 0:
                raise DogfoodBomError(f"projects[{index}] ignored inventory is inconsistent")
        observed.append(copy.deepcopy(project))

    expected_blockers = sorted(set(expected_blockers))
    if not expected_blockers:
        raise DogfoodBomError("source BOM has no dirty/ignored project blocker")
    if blockers != expected_blockers:
        raise DogfoodBomError(
            "source BOM blocker inventory contains a non-project or missing blocker"
        )
    return observed, sorted(set(dirty_ids)), sorted(set(ignored_ids)), expected_blockers


def _verify_nonproject_inventories(document: dict[str, Any]) -> None:
    for key in ("artifacts", "trees"):
        if key not in document:
            raise DogfoodBomError(f"source BOM {key} is missing")
        value = document[key]
        if type(value) is not list:
            raise DogfoodBomError(f"source BOM {key} must be a list")
        for index, entry in enumerate(value):
            if type(entry) is not dict:
                raise DogfoodBomError(f"source BOM {key}[{index}] is not an object")
            if "failures" not in entry:
                raise DogfoodBomError(f"source BOM {key}[{index}] failures are missing")
            failures = entry["failures"]
            if type(failures) is not list or failures:
                raise DogfoodBomError(
                    f"source BOM {key}[{index}] contains unsupported failures"
                )


def materialize_raw(
    bom_raw: bytes,
    manifest_raw: bytes,
    *,
    allow_dirty_userdebug_dogfood: bool,
) -> dict[str, Any]:
    """Validate retained input bytes and derive the canonical wrapper.

    This pure form is used by builders that already retain race-resistant
    descriptors.  It avoids a second pathname read while preserving exactly
    the same schema, manifest, blocker, and non-authorizing checks as the
    command-line materializer.
    """

    if not allow_dirty_userdebug_dogfood:
        raise DogfoodBomError(
            "refusing dirty userdebug snapshot without --allow-dirty-userdebug-dogfood"
        )
    if (
        type(bom_raw) is not bytes
        or not 0 < len(bom_raw) <= MAX_BOM_BYTES
        or type(manifest_raw) is not bytes
        or not 0 < len(manifest_raw) <= MAX_MANIFEST_BYTES
    ):
        raise DogfoodBomError("retained dogfood inputs exceed bounded byte limits")
    source = parse_json(bom_raw, "source BOM")
    if source.get("schema") != SOURCE_BOM_SCHEMA:
        raise DogfoodBomError("source BOM schema is not v2")
    if source.get("decision") != SOURCE_BOM_HOLD:
        raise DogfoodBomError("source BOM must be HOLD_LOCAL_SOURCE_GRAPH")
    if source.get("receipt_id_scope") != RECEIPT_ID_SCOPE:
        raise DogfoodBomError("source BOM receipt_id_scope is invalid")
    source_receipt_id = verify_input_self_hash(source, "source BOM")
    posture = _verify_posture(source.get("posture"))
    source_set = _verify_descriptor(source.get("source_set"), "source BOM source_set")
    if source_set.get("schema") != "org.trillionnium.p0-cross-repo-source-set.v2":
        raise DogfoodBomError("source BOM source_set is not v2")
    resolved = _verify_resolved_manifest(source.get("resolved_manifest"), manifest_raw)
    projects, dirty_ids, ignored_ids, blockers = _verify_project_inventory(
        source.get("projects"), source.get("blockers")
    )
    _verify_nonproject_inventories(source)

    result: dict[str, Any] = {
        "schema": DOGFOOD_SCHEMA,
        "decision": DOGFOOD_DECISION,
        "posture": {
            "local_only": True,
            "network_access_performed": False,
            "signed": False,
            "release_pin_published": False,
            "build_authorized": False,
            "ota_authorized": False,
            "device_write_authorized": False,
            "public_release_allowed": False,
            "release_allowed": False,
            "effect_authority": False,
        },
        "dogfood": {
            "build_variant": "userdebug",
            "allow_dirty_userdebug_dogfood": True,
            "input_decision": SOURCE_BOM_HOLD,
            "allowed_blocker_kinds": sorted(ALLOWED_FAILURES),
            "non_authorizing": True,
        },
        "source_bom": {
            "schema": SOURCE_BOM_SCHEMA,
            "bytes": len(bom_raw),
            "sha256": hashlib.sha256(bom_raw).hexdigest(),
            "receipt_id": source_receipt_id,
        },
        "source_set": copy.deepcopy(source_set),
        "resolved_manifest": {
            "producer": resolved["producer"],
            "bytes": len(manifest_raw),
            "sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "project_count": resolved["project_count"],
            "all_revisions_exact": True,
            "declared_checkout_revision_drift_count": 0,
            "declared_checkout_revision_drifts": [],
        },
        "projects": projects,
        "project_inventory": {
            "dirty_project_ids": dirty_ids,
            "ignored_project_ids": ignored_ids,
            "blockers": blockers,
        },
        "artifacts": copy.deepcopy(source.get("artifacts", [])),
        "trees": copy.deepcopy(source.get("trees", [])),
        "receipt_id_scope": RECEIPT_ID_SCOPE,
    }
    # The source posture is intentionally inspected above; retaining only the
    # fixed dogfood posture prevents a permissive input field from propagating.
    del posture
    result["receipt_id"] = SHA256_PREFIX + hashlib.sha256(
        canonical_json_bytes(result)
    ).hexdigest()
    return result


def materialize(
    bom_path: Path,
    resolved_manifest_path: Path,
    *,
    allow_dirty_userdebug_dogfood: bool,
) -> dict[str, Any]:
    """Read stable files and derive the canonical wrapper."""

    if not allow_dirty_userdebug_dogfood:
        raise DogfoodBomError(
            "refusing dirty userdebug snapshot without --allow-dirty-userdebug-dogfood"
        )
    bom_raw = read_stable_regular(bom_path, "source BOM", MAX_BOM_BYTES)
    manifest_raw = read_stable_regular(
        resolved_manifest_path, "resolved manifest", MAX_MANIFEST_BYTES
    )
    return materialize_raw(
        bom_raw,
        manifest_raw,
        allow_dirty_userdebug_dogfood=allow_dirty_userdebug_dogfood,
    )


def publish(path: Path, content: bytes) -> None:
    absolute = Path(os.path.abspath(os.fspath(path)))
    _reject_symlink_parents(absolute.parent)
    if not absolute.parent.is_dir():
        raise DogfoodBomError("output parent is unavailable")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags, 0o444)
    except OSError as error:
        raise DogfoodBomError("dogfood BOM output publication failed") from error
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise DogfoodBomError("dogfood BOM output short write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        parent_fd = os.open(absolute.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as error:
        raise DogfoodBomError("dogfood BOM output parent durability failed") from error
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--bom", type=Path, required=True)
    result.add_argument("--resolved-manifest", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument(
        "--allow-dirty-userdebug-dogfood",
        action="store_true",
        help="explicitly opt into the non-authorizing dirty userdebug snapshot lane",
    )
    return result


def main(argv: Iterable[str] | None = None) -> int:
    args = parser().parse_args(list(argv) if argv is not None else None)
    try:
        receipt = materialize(
            args.bom,
            args.resolved_manifest,
            allow_dirty_userdebug_dogfood=args.allow_dirty_userdebug_dogfood,
        )
        publish(args.output, canonical_json_bytes(receipt))
        return 0
    except DogfoodBomError as error:
        print(f"userdebug dogfood BOM error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
