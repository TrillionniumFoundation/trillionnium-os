#!/usr/bin/env python3
"""Read-only Android BOM/target release preflight.

This checker is intentionally independent from the signing and OTA tools.  It
audits a previously materialised cross-repository source BOM and, when given a
target-files archive, reads only its ZIP metadata.  It never builds, signs,
invokes ADB/fastboot, opens key material, or writes a file.  A successful
result is still only a host-side preflight: device lock/green state, KeyMint,
rollback enforcement, and operator authorization remain separate gates.

The source BOM is treated as an attestation, not as permission.  Its receipt
identifier is re-derived from canonical JSON and its clean-graph claims are
checked before any target metadata is considered.  This catches the common
failure mode where an old clean BOM is accidentally paired with a later dirty
source or a userdebug/test-key target.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any, Mapping, Sequence
import zipfile


def _load_source_bom_binding_inspector() -> Any:
    """Load the sibling binding checker for both script and fixture imports."""

    try:
        from verify_source_bom_binding import inspect_target_files_source_bom_binding

        return inspect_target_files_source_bom_binding
    except ModuleNotFoundError:
        sibling = Path(__file__).with_name("verify_source_bom_binding.py")
        spec = importlib.util.spec_from_file_location(
            "_trillionnium_android_source_bom_binding", sibling
        )
        if spec is None or spec.loader is None:
            raise PreflightError("source_bom_binding_checker_unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.inspect_target_files_source_bom_binding


SCHEMA = "org.trillionnium.android-bom-preflight.v1"
BOM_SCHEMA = "org.trillionnium.local-cross-repo-source-bom.v2"
BOM_SOURCE_SET_SCHEMA = "org.trillionnium.p0-cross-repo-source-set.v2"
PASS_BOM = "PASS_LOCAL_EXACT_CLEAN_GRAPH"
HOLD_EXIT = 78
MAX_BOM_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_TARGET_BYTES = 16 * 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 2 * 1024 * 1024
MAX_ZIP_ENTRIES = 1_000_000
HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
PRIVATE_SUFFIXES = frozenset(
    {".pem", ".key", ".pk8", ".p12", ".pfx", ".jks", ".keystore", ".der"}
)
PRIVATE_COMPONENTS = frozenset(
    {"private", "private-key", "private_key", "secret", "secrets", "passphrase"}
)


class PreflightError(ValueError):
    """A bounded, public hold reason."""


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PreflightError("json_duplicate_key")
        result[key] = value
    return result


def _strict_json(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                PreflightError(f"{label}_non_finite_number")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise PreflightError(f"{label}_invalid_json") from error
    if type(value) is not dict:
        raise PreflightError(f"{label}_must_be_object")
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


def _open_nofollow(path: Path, label: str) -> tuple[int, int | None, str | None]:
    """Open a regular file while rejecting every symlinked path component."""

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise PreflightError(f"{label}_nofollow_unavailable")
    components = Path(os.path.abspath(os.fspath(path))).parts
    flags = os.O_RDONLY | os.O_CLOEXEC | nofollow
    try:
        parent = os.open(os.sep, flags | directory)
    except OSError as error:
        raise PreflightError(f"{label}_unreadable") from error
    if len(components) == 1:
        return parent, None, None
    try:
        for index, component in enumerate(components[1:]):
            last = index == len(components[1:]) - 1
            child = os.open(component, flags | (0 if last else directory), dir_fd=parent)
            if last:
                return child, parent, component
            os.close(parent)
            parent = child
    except OSError as error:
        os.close(parent)
        raise PreflightError(f"{label}_unreadable") from error
    os.close(parent)
    raise PreflightError(f"{label}_unreadable")


def _read_regular(path: Path, *, label: str, maximum: int) -> tuple[bytes, str, int]:
    descriptor, parent, basename = _open_nofollow(path, label)
    chunks: list[bytes] = []
    digest = hashlib.sha256()
    observed = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise PreflightError(f"{label}_size_out_of_bounds")
        while observed < maximum:
            block = os.read(descriptor, min(1024 * 1024, maximum - observed))
            if not block:
                break
            observed += len(block)
            digest.update(block)
            chunks.append(block)
        after = os.fstat(descriptor)
        if observed != before.st_size or _identity(before) != _identity(after):
            raise PreflightError(f"{label}_changed_while_read")
        if parent is not None and basename is not None:
            current = os.stat(basename, dir_fd=parent, follow_symlinks=False)
            if stat.S_ISLNK(current.st_mode) or _identity(current) != _identity(before):
                raise PreflightError(f"{label}_changed_after_read")
    except OSError as error:
        raise PreflightError(f"{label}_unreadable") from error
    finally:
        os.close(descriptor)
        if parent is not None:
            os.close(parent)
    return b"".join(chunks), digest.hexdigest(), before.st_size


def _assert_public_path(path: Path, label: str) -> None:
    if path.suffix.lower() in PRIVATE_SUFFIXES:
        raise PreflightError(f"{label}_private_material_path")
    if {part.lower() for part in path.parts} & PRIVATE_COMPONENTS:
        raise PreflightError(f"{label}_private_material_path")


def _hex64(value: object) -> bool:
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def _tags(value: object) -> set[str]:
    if isinstance(value, str):
        return {part.strip() for part in value.split(",") if part.strip()}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return {item.strip() for item in value if item.strip()}
    return set()


def _portable_relative(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value:
        raise PreflightError(f"{label}_path_invalid")
    parts = PurePosixPath(value).parts
    if any(part in {"", ".", ".."} for part in parts) and value != ".":
        raise PreflightError(f"{label}_path_invalid")
    return value


def _contains_symlink_component(root: Path, relative: str) -> bool:
    """Return true if a checkout path has a symlinked component."""

    current = root
    try:
        if root.is_symlink():
            return True
        for component in () if relative == "." else relative.split("/"):
            current = current / component
            if current.is_symlink():
                return True
    except OSError:
        return True
    return False


def _bounded_git(command: Sequence[str], cwd: Path) -> bytes:
    # The release preflight is intentionally a pure file/ZIP reader.  Live
    # checkout revalidation belongs to the source-BOM materializer, which
    # already records the exact Git state in this receipt.  Keeping this
    # helper as an explicit HOLD avoids accidentally reintroducing a process
    # launcher into the release gate.
    del command, cwd
    raise PreflightError("source_recheck_requires_materialized_bom")


def recheck_git_sources(
    bom: Mapping[str, Any], *, android_root: Path, control_root: Path
) -> tuple[dict[str, Any], list[str]]:
    """Recheck only BOM-listed Git projects, without cleaning or fetching."""

    observations: list[dict[str, Any]] = []
    holds: list[str] = []
    projects = bom.get("projects")
    if not isinstance(projects, list):
        return {"requested": True, "projects": []}, ["source_recheck_projects_missing"]
    for item in projects:
        if not isinstance(item, Mapping):
            holds.append("source_recheck_project_invalid")
            continue
        project_id = str(item.get("id", "unknown"))
        checkout_info = item.get("checkout")
        if not isinstance(checkout_info, Mapping):
            holds.append(f"source_recheck_checkout_missing:{project_id}")
            continue
        root_name = checkout_info.get("root")
        relative = checkout_info.get("path")
        if root_name not in {"android", "control"}:
            holds.append(f"source_recheck_root_invalid:{project_id}")
            continue
        try:
            relative = _portable_relative(relative, f"source_recheck_{project_id}")
        except PreflightError as error:
            holds.append(f"{error}:{project_id}")
            continue
        root = android_root if root_name == "android" else control_root
        checkout = root if relative == "." else root / relative
        observation: dict[str, Any] = {
            "id": project_id,
            "checkout": {"root": root_name, "path": relative},
            "present": False,
            "clean_nonignored": False,
            "ignored_count": None,
            "head": None,
        }
        if _contains_symlink_component(root, relative) or not checkout.is_dir():
            holds.append(f"source_recheck_checkout_unavailable:{project_id}")
            observations.append(observation)
            continue
        try:
            status = _bounded_git(
                [
                    "status",
                    "--porcelain=v1",
                    "-z",
                    "--untracked-files=all",
                    "--ignore-submodules=none",
                ],
                checkout,
            )
            ignored = _bounded_git(
                [
                    "ls-files",
                    "--others",
                    "--ignored",
                    "--exclude-standard",
                    "--directory",
                    "-z",
                ],
                checkout,
            )
            head = _bounded_git(["rev-parse", "--verify", "HEAD^{commit}"], checkout).decode("ascii").strip()
            observation.update(
                {
                    "present": True,
                    "clean_nonignored": not bool(status),
                    "status_bytes": len(status),
                    "ignored_count": len([entry for entry in ignored.split(b"\x00") if entry]),
                    "head": head,
                }
            )
            if status:
                holds.append(f"source_recheck_dirty:{project_id}")
            if observation["ignored_count"]:
                holds.append(f"source_recheck_ignored_paths:{project_id}")
            expected_git = item.get("git")
            expected_head = expected_git.get("head") if isinstance(expected_git, Mapping) else None
            if isinstance(expected_head, str) and expected_head and expected_head != head:
                holds.append(f"source_recheck_head_mismatch:{project_id}")
        except (PreflightError, UnicodeError) as error:
            holds.append(f"{error}:{project_id}")
        observations.append(observation)
    return {"requested": True, "projects": observations}, list(dict.fromkeys(holds))


def _parse_properties(raw: bytes, label: str) -> dict[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PreflightError(f"{label}_not_utf8") from error
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if not key:
            continue
        if key in result and result[key] != value:
            raise PreflightError(f"{label}_conflicting_duplicate_property")
        result[key] = value
    return result


def _safe_member(name: str) -> None:
    if not name or "\\" in name or name.startswith("/") or "\x00" in name:
        raise PreflightError("target_files_unsafe_zip_member")
    path = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise PreflightError("target_files_non_canonical_zip_member")


def _member(archive: zipfile.ZipFile, name: str) -> bytes:
    try:
        info = archive.getinfo(name)
    except KeyError as error:
        raise PreflightError(f"target_files_missing_{name.replace('/', '_')}") from error
    if info.file_size < 0 or info.file_size > MAX_MEMBER_BYTES:
        raise PreflightError(f"target_files_member_too_large_{name.replace('/', '_')}")
    try:
        return archive.read(info)
    except (OSError, RuntimeError, zipfile.BadZipFile, EOFError, ValueError) as error:
        raise PreflightError(f"target_files_member_unreadable_{name.replace('/', '_')}") from error


def _rollback(value: str) -> int | None:
    tokens = value.split()
    values: list[int] = []
    for index, token in enumerate(tokens):
        if token == "--rollback_index" and index + 1 < len(tokens):
            candidate = tokens[index + 1]
        elif token.startswith("--rollback_index="):
            candidate = token.split("=", 1)[1]
        else:
            continue
        try:
            parsed = int(candidate, 0)
        except ValueError as error:
            raise PreflightError("target_files_invalid_rollback_index") from error
        if parsed < 0 or parsed >= 1 << 64:
            raise PreflightError("target_files_rollback_index_out_of_range")
        values.append(parsed)
    if not values:
        return None
    if len(set(values)) != 1:
        raise PreflightError("target_files_conflicting_rollback_index")
    return values[0]


def inspect_target_metadata(path: Path) -> tuple[dict[str, Any], list[str]]:
    """Read target-files central-directory metadata without hashing the archive."""

    holds: list[str] = []
    public: dict[str, Any] = {"path": path.name, "present": False}
    try:
        descriptor, parent, basename = _open_nofollow(path, "target_files")
        try:
            identity = os.fstat(descriptor)
            if not stat.S_ISREG(identity.st_mode) or not 0 < identity.st_size <= MAX_TARGET_BYTES:
                raise PreflightError("target_files_size_out_of_bounds")
            # ZipFile needs a pathname/file object; the descriptor is retained
            # only for the no-follow identity check.  Opening the same stable
            # pathname is safe because the parent descriptor is checked below.
            # Bind ZipFile to the already-open descriptor.  Reopening by
            # pathname would create a small TOCTOU window between the
            # no-follow check and central-directory parsing.
            archive_file = os.fdopen(os.dup(descriptor), "rb")
            archive = zipfile.ZipFile(archive_file)
            try:
                infos = archive.infolist()
                if not infos or len(infos) > MAX_ZIP_ENTRIES:
                    raise PreflightError("target_files_zip_entry_count_out_of_bounds")
                names: set[str] = set()
                for info in infos:
                    _safe_member(info.filename)
                    if info.filename in names:
                        raise PreflightError("target_files_duplicate_zip_member")
                    names.add(info.filename)
                misc = _parse_properties(_member(archive, "META/misc_info.txt"), "misc_info")
                ota = _member(archive, "META/otakeys.txt")
                build_types: list[str] = []
                build_tags: set[str] = set()
                fingerprints: list[str] = []
                for name in sorted(names):
                    if name != "build.prop" and not name.endswith("/build.prop"):
                        continue
                    props = _parse_properties(_member(archive, name), name.replace("/", "_"))
                    for key, value in props.items():
                        lowered = key.lower()
                        if lowered == "ro.build.type" or lowered.endswith(".build.type"):
                            if value:
                                build_types.append(value)
                        if lowered == "ro.build.tags" or lowered.endswith(".build.tags"):
                            build_tags.update(_tags(value))
                        if lowered == "ro.build.fingerprint" or lowered.endswith(".build.fingerprint"):
                            if value:
                                fingerprints.append(value)
                if misc.get("build_type"):
                    build_types.append(misc["build_type"])
                facts: dict[str, Any] = {
                    "ab_update": misc.get("ab_update") == "true",
                    "avb_enabled": misc.get("avb_enable") == "true",
                    "build_types": build_types,
                    "build_tags": sorted(build_tags),
                    "ota_keys_nonempty": any(
                        line.strip() and not line.lstrip().startswith(b"#")
                        for line in ota.splitlines()
                    ),
                    "ota_keys_bytes": len(ota),
                    "avb_rollback_indices": {},
                    "zip_entry_count": len(names),
                }
                # The path is public metadata; do not open it.  A target that
                # still names an AOSP test AVB key is never a release candidate
                # even if a malformed build.prop claims ``user/release-keys``.
                key_paths = [
                    value.lower()
                    for key, value in misc.items()
                    if key.endswith("_key_path")
                ]
                avb_test_key_path_marker = any(
                    "/test/" in value
                    or "testkey" in value
                    or "test_key" in value
                    or "aosp" in value
                    for value in key_paths
                )
                if avb_test_key_path_marker:
                    holds.append("target_avb_test_key_path")
                facts["avb_test_key_path_marker"] = avb_test_key_path_marker
                for key, value in misc.items():
                    match = re.fullmatch(r"avb_([a-z0-9_]+)_args", key)
                    if not match:
                        continue
                    partition = match.group(1)
                    index = _rollback(value)
                    if index is None:
                        if facts["avb_enabled"]:
                            holds.append(f"avb_{partition}_args_missing_rollback_index")
                        continue
                    location = 0
                    if partition != "vbmeta":
                        raw_location = misc.get(f"avb_{partition}_rollback_index_location")
                        try:
                            location = int(raw_location, 10) if raw_location is not None else -1
                        except ValueError:
                            location = -1
                        if not 0 <= location <= 31:
                            holds.append(f"avb_{partition}_rollback_location_invalid")
                    facts["avb_rollback_indices"][partition] = {
                        "rollback_index": index,
                        "rollback_index_location": location,
                    }
                public.update({"present": True, "bytes": identity.st_size, "metadata": facts})
                types = facts["build_types"]
                tags = set(facts["build_tags"])
                if not types:
                    holds.append("target_build_type_missing")
                if any(item != "user" for item in types):
                    holds.append("target_build_type_not_user")
                if tags != {"release-keys"}:
                    holds.append("target_build_tags_not_exact_release_keys")
                text = "\n".join(fingerprints + [str(misc.get("build_type", ""))]).lower()
                if "userdebug" in text or "test-keys" in text or "dev-keys" in text or re.search(r":eng(?:/|$)", text):
                    holds.append("target_metadata_contains_userdebug_or_test_keys")
                if not facts["ota_keys_nonempty"]:
                    holds.append("target_ota_keys_empty_or_missing")
                if not facts["ab_update"] or not facts["avb_enabled"]:
                    holds.append("target_not_avb_enabled_ab_product")
                if not facts["avb_rollback_indices"]:
                    holds.append("target_rollback_indices_missing")
            finally:
                archive.close()
                archive_file.close()
            if parent is not None and basename is not None:
                current = os.stat(basename, dir_fd=parent, follow_symlinks=False)
                if stat.S_ISLNK(current.st_mode) or _identity(current) != _identity(identity):
                    raise PreflightError("target_files_changed_after_metadata_read")
        finally:
            os.close(descriptor)
            if parent is not None:
                os.close(parent)
    except (PreflightError, OSError, zipfile.BadZipFile) as error:
        holds.append(str(error))
    return public, list(dict.fromkeys(holds))


def _verify_receipt(bom: Mapping[str, Any]) -> list[str]:
    holds: list[str] = []
    if bom.get("schema") != BOM_SCHEMA:
        holds.append("bom_schema_invalid")
    if bom.get("decision") != PASS_BOM:
        holds.append("bom_decision_not_exact_clean")
    if bom.get("blockers") != []:
        holds.append("bom_blockers_nonempty")
    receipt_id = bom.get("receipt_id")
    if not isinstance(receipt_id, str) or not receipt_id.startswith("sha256:") or not _hex64(receipt_id[7:]):
        holds.append("bom_receipt_id_invalid")
    else:
        without_id = dict(bom)
        without_id.pop("receipt_id", None)
        expected = "sha256:" + hashlib.sha256(canonical_json_bytes(without_id)).hexdigest()
        if receipt_id.lower() != expected.lower():
            holds.append("bom_receipt_id_mismatch")
    if bom.get("receipt_id_scope") != "sha256(canonical-json-utf8-without-receipt_id)":
        holds.append("bom_receipt_id_scope_invalid")
    source_set = bom.get("source_set")
    if not isinstance(source_set, Mapping) or source_set.get("schema") != BOM_SOURCE_SET_SCHEMA or not _hex64(source_set.get("sha256")):
        holds.append("bom_source_set_binding_invalid")
    manifest = bom.get("resolved_manifest")
    drift_count = (
        manifest.get("declared_checkout_revision_drift_count")
        if isinstance(manifest, Mapping)
        else None
    )
    if (
        not isinstance(manifest, Mapping)
        or manifest.get("all_revisions_exact") is not True
        or type(drift_count) is not int
        or drift_count != 0
    ):
        holds.append("bom_manifest_not_exact")
    projects = bom.get("projects")
    if not isinstance(projects, list) or not projects:
        holds.append("bom_projects_missing")
    else:
        for item in projects:
            if not isinstance(item, Mapping):
                holds.append("bom_project_invalid")
                continue
            project_id = str(item.get("id", "unknown"))
            requirements = item.get("requirements")
            git = item.get("git")
            failures = item.get("failures")
            if not isinstance(requirements, Mapping) or requirements.get("clean") is not True or requirements.get("no_ignored_paths") is not True:
                holds.append(f"bom_project_requirements_not_clean:{project_id}")
            ignored = git.get("ignored") if isinstance(git, Mapping) else None
            ignored_count = ignored.get("count") if isinstance(ignored, Mapping) else None
            if (
                not isinstance(git, Mapping)
                or git.get("clean_nonignored") is not True
                or type(ignored_count) is not int
                or ignored_count != 0
            ):
                holds.append(f"bom_project_git_dirty:{project_id}")
            if failures != []:
                holds.append(f"bom_project_failures:{project_id}")
    trees = bom.get("trees")
    if not isinstance(trees, list) or not trees:
        holds.append("bom_source_trees_missing")
    else:
        for item in trees:
            if not isinstance(item, Mapping):
                holds.append("bom_tree_invalid")
                continue
            tree_id = str(item.get("id", "unknown"))
            inventory = item.get("inventory")
            if item.get("failures") != []:
                holds.append(f"bom_tree_failures:{tree_id}")
            if not isinstance(inventory, Mapping) or inventory.get("stable_remeasurement_passed") is not True or inventory.get("no_follow_path_walk_passed") is not True:
                holds.append(f"bom_tree_not_stable:{tree_id}")
    posture = bom.get("posture")
    expected_false = (
        "network_access_performed", "signed", "release_pin_published",
        "build_authorized", "ota_authorized", "device_write_authorized",
        "observed_artifact_hashes_are_release_pins", "observed_tree_hashes_are_release_pins",
    )
    if not isinstance(posture, Mapping) or posture.get("local_only") is not True:
        holds.append("bom_posture_not_local_only")
    else:
        for key in expected_false:
            if posture.get(key) is not False:
                holds.append(f"bom_posture_{key}_not_closed")
    return list(dict.fromkeys(holds))


def _verify_evidence(path: Path, *, label: str, schema: str, target_sha256: str | None, metadata: Mapping[str, Any] | None) -> tuple[dict[str, Any], list[str]]:
    public: dict[str, Any] = {"present": False}
    holds: list[str] = []
    try:
        _assert_public_path(path, label)
        raw, digest, size = _read_regular(path, label=label, maximum=MAX_EVIDENCE_BYTES)
        value = _strict_json(raw, label)
        public.update({"present": True, "sha256": digest, "bytes": size, "schema": value.get("schema")})
        if value.get("schema") != schema:
            holds.append(f"{label}_schema_invalid")
        bound = value.get("target_files_sha256")
        if not _hex64(bound):
            holds.append(f"{label}_target_digest_invalid")
        elif target_sha256 is None:
            holds.append("target_files_digest_not_provided_for_evidence_binding")
        elif bound.lower() != target_sha256.lower():
            holds.append(f"{label}_target_digest_mismatch")
        if label == "signed_metadata":
            if value.get("signed") is not True:
                holds.append("signed_metadata_not_explicitly_signed")
            if value.get("build_type") != "user":
                holds.append("signed_metadata_build_type_not_user")
            if _tags(value.get("build_tags")) != {"release-keys"}:
                holds.append("signed_metadata_tags_not_release_keys")
            signature = value.get("signature")
            sig = signature if isinstance(signature, str) else signature.get("value") if isinstance(signature, Mapping) else None
            key_id = value.get("signing_key_id")
            if isinstance(signature, Mapping) and not key_id:
                key_id = signature.get("key_id")
            if not isinstance(sig, str) or not sig.strip():
                holds.append("signed_metadata_signature_missing")
            if not isinstance(key_id, str) or not key_id.strip():
                holds.append("signed_metadata_signing_key_id_missing")
        else:
            if value.get("hardware_antirollback_proven") is not True and value.get("verified") is not True:
                holds.append("rollback_hardware_proof_missing")
            if not isinstance(value.get("evidence_id"), str) or not value["evidence_id"].strip():
                holds.append("rollback_evidence_id_missing")
            entries = value.get("indices", value.get("rollback_indices"))
            observed = metadata.get("avb_rollback_indices", {}) if metadata else {}
            if not isinstance(entries, Mapping):
                holds.append("rollback_evidence_indices_missing")
            elif isinstance(observed, Mapping):
                if set(entries) != set(observed):
                    holds.append("rollback_evidence_partition_set_mismatch")
                for partition, expected in observed.items():
                    item = entries.get(partition)
                    if not isinstance(item, Mapping) or item.get("rollback_index") != expected.get("rollback_index") or item.get("rollback_index_location") != expected.get("rollback_index_location"):
                        holds.append(f"rollback_evidence_index_mismatch_{partition}")
    except (PreflightError, OSError) as error:
        holds.append(str(error))
    return public, list(dict.fromkeys(holds))


def preflight(
    bom_path: Path,
    *,
    target_files: Path | None = None,
    signed_metadata: Path | None = None,
    rollback_evidence: Path | None = None,
    target_sha256: str | None = None,
    require_source_bom_binding: bool = False,
    source_bom_binding_bom: Path | None = None,
) -> dict[str, Any]:
    holds: list[str] = []
    bom_public: dict[str, Any] = {"present": False, "path": bom_path.name}
    target_public: dict[str, Any] = {"present": False}
    signed_public: dict[str, Any] = {"present": False, "required": True}
    rollback_public: dict[str, Any] = {"present": False, "required": True}
    source_binding_public: dict[str, Any] = {
        "present": False,
        "required": require_source_bom_binding,
        "member": "META/trillionnium-source-bom-binding.json",
        "valid": True,
        "holds": [],
    }
    bom: dict[str, object] = {}
    bom_raw: bytes | None = None
    try:
        raw, digest, size = _read_regular(bom_path, label="bom", maximum=MAX_BOM_BYTES)
        bom_raw = raw
        bom = _strict_json(raw, "bom")
        bom_public.update({"present": True, "sha256": digest, "bytes": size, "schema": bom.get("schema"), "decision": bom.get("decision")})
        holds.extend(_verify_receipt(bom))
    except (PreflightError, OSError) as error:
        holds.append(str(error))
    metadata: Mapping[str, Any] | None = None
    if target_files is None:
        holds.append("target_files_missing")
    else:
        target_public, target_holds = inspect_target_metadata(target_files)
        holds.extend(target_holds)
        metadata = target_public.get("metadata") if isinstance(target_public.get("metadata"), Mapping) else None
        expected_binding_bom = bom_raw
        if source_bom_binding_bom is not None:
            try:
                expected_binding_bom, _, _ = _read_regular(
                    source_bom_binding_bom,
                    label="source_bom_binding_bom",
                    maximum=MAX_BOM_BYTES,
                )
            except (PreflightError, OSError) as error:
                holds.append(str(error))
                expected_binding_bom = None
        try:
            inspect_binding = _load_source_bom_binding_inspector()
            source_binding_public = inspect_binding(
                target_files,
                require_binding=require_source_bom_binding,
                expected_bom_bytes=expected_binding_bom,
            )
            holds.extend(source_binding_public.get("holds", []))
        except (PreflightError, OSError, ValueError) as error:
            source_binding_public["valid"] = False
            source_binding_public["holds"] = [str(error)]
            holds.extend(source_binding_public["holds"])
    if target_sha256 is not None and not _hex64(target_sha256):
        holds.append("target_files_digest_invalid")
        target_sha256 = None
    if signed_metadata is None:
        holds.append("signed_metadata_missing")
    else:
        signed_public, evidence_holds = _verify_evidence(signed_metadata, label="signed_metadata", schema="org.trillionnium.android-release-signed-metadata.v1", target_sha256=target_sha256, metadata=metadata)
        holds.extend(evidence_holds)
    if rollback_evidence is None:
        holds.append("rollback_evidence_missing")
    else:
        rollback_public, evidence_holds = _verify_evidence(rollback_evidence, label="rollback_evidence", schema="org.trillionnium.android-rollback-evidence.v1", target_sha256=target_sha256, metadata=metadata)
        holds.extend(evidence_holds)
    holds = list(dict.fromkeys(holds))
    eligible = not holds
    return {
        "schema": SCHEMA,
        "decision": "ELIGIBLE" if eligible else "HOLD",
        "eligible": eligible,
        "bom": bom_public,
        "target_files": target_public,
        "signed_metadata": signed_public,
        "rollback_evidence": rollback_public,
        "source_bom_binding": source_binding_public,
        "holds": holds,
        "effects": {
            "files_written": False,
            "signing_performed": False,
            "flash_performed": False,
            "private_key_accessed": False,
            "adb_invoked": False,
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bom", type=Path, required=True)
    parser.add_argument("--target-files", type=Path)
    parser.add_argument("--signed-metadata", type=Path)
    parser.add_argument("--rollback-evidence", type=Path)
    parser.add_argument("--target-sha256")
    parser.add_argument(
        "--require-source-bom-binding",
        action="store_true",
        help="require META/trillionnium-source-bom-binding.json in target-files",
    )
    parser.add_argument(
        "--source-bom-binding-bom",
        type=Path,
        help="optional BOM bytes to cross-check against the embedded binding",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    report = preflight(
        args.bom,
        target_files=args.target_files,
        signed_metadata=args.signed_metadata,
        rollback_evidence=args.rollback_evidence,
        target_sha256=args.target_sha256,
        require_source_bom_binding=args.require_source_bom_binding,
        source_bom_binding_bom=args.source_bom_binding_bom,
    )
    sys.stdout.buffer.write(canonical_json_bytes(report))
    return 0 if report["eligible"] else HOLD_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
