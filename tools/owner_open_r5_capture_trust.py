#!/usr/bin/env python3
"""Trust-boundary checks for Owner-Open R5 target evidence capture.

The generic evidence-bundle validator proves byte closure and claim shape. This
module additionally proves that a promoted target bundle was produced by the
root-owned, pre-attested harness selected for its evidence kind, under the
fixed non-inheriting execution environment used by the capture driver.
"""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any

from owner_open_r5_evidence_bundle import (
    EvidenceError,
    REPOSITORY,
    read_json_object,
    require_path_beneath,
    safe_relative_path,
    sha256_file,
)

CAPTURE_DRIVER_SCHEMA = "org.trillionnium.owner-open-r5.capture-driver.v1"
HARNESS_ROOT = PurePosixPath("/opt/owner-open-r5/harnesses")
ATTESTATION_ROOT = PurePosixPath("/etc/owner-open-r5/attestations")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MODE = re.compile(r"^[0-7]{4}$")

FIXED_BASE_ENVIRONMENT = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
    "PYTHONHASHSEED": "0",
    "PYTHONDONTWRITEBYTECODE": "1",
}

IDENTITY_FIELDS = ("path", "bytes", "sha256", "uid", "gid", "mode")


def require_fixed_target_file(
    path: Path,
    *,
    executable: bool,
    require_root_owner: bool = True,
) -> dict[str, Any]:
    """Return a stable identity for one target-owned file or fail closed."""
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise EvidenceError(f"fixed target file is absent or unsafe: {path}")
    resolved = path.resolve(strict=True)
    if resolved != path:
        raise EvidenceError(f"fixed target file contains a symlink component: {path}")
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise EvidenceError(f"fixed target file is not a single-link regular file: {path}")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & 0o022:
        raise EvidenceError(f"fixed target file is group/world writable: {path}")
    if mode & 0o7000:
        raise EvidenceError(f"fixed target file must not carry set-id/sticky bits: {path}")
    if require_root_owner and (metadata.st_uid != 0 or metadata.st_gid != 0):
        raise EvidenceError(f"fixed target file must be root:root owned: {path}")
    if executable and (mode & 0o111 == 0 or not os.access(path, os.X_OK)):
        raise EvidenceError(f"fixed target harness is not executable: {path}")
    if not executable and mode & 0o111:
        raise EvidenceError(f"fixed target attestation must not be executable: {path}")
    size, digest = sha256_file(path)
    return {
        "path": str(path),
        "bytes": size,
        "sha256": digest,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{mode:04o}",
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }


def _validated_identity(
    value: Any,
    *,
    expected_path: PurePosixPath,
    executable: bool,
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    path = value.get("path")
    if not isinstance(path, str) or PurePosixPath(path) != expected_path:
        raise EvidenceError(f"{label}.path must be exactly {expected_path}")
    size = value.get("bytes")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise EvidenceError(f"{label}.bytes must be a positive integer")
    digest = value.get("sha256")
    if not isinstance(digest, str) or HEX64.fullmatch(digest) is None:
        raise EvidenceError(f"{label}.sha256 must be lowercase 64-hex")
    for key in ("uid", "gid"):
        candidate = value.get(key)
        if not isinstance(candidate, int) or isinstance(candidate, bool) or candidate != 0:
            raise EvidenceError(f"{label}.{key} must be root identity 0")
    mode_text = value.get("mode")
    if not isinstance(mode_text, str) or MODE.fullmatch(mode_text) is None:
        raise EvidenceError(f"{label}.mode must be canonical four-digit octal")
    mode = int(mode_text, 8)
    if mode & 0o7022:
        raise EvidenceError(f"{label}.mode contains unsafe write/set-id/sticky bits")
    if executable and mode & 0o111 == 0:
        raise EvidenceError(f"{label}.mode must be executable")
    if not executable and mode & 0o111:
        raise EvidenceError(f"{label}.mode must not be executable")
    return {field: value[field] for field in IDENTITY_FIELDS}


def validate_attested_harness(value: Any, *, kind: str) -> dict[str, Any]:
    return _validated_identity(
        value,
        expected_path=HARNESS_ROOT / kind,
        executable=True,
        label="target_attestation.harness",
    )


def validate_attested_attestation(value: Any, *, kind: str) -> dict[str, Any]:
    return _validated_identity(
        value,
        expected_path=ATTESTATION_ROOT / f"{kind}.json",
        executable=False,
        label="capture_driver.target_attestation",
    )


def assert_harness_identity(
    observed: dict[str, Any],
    attested: Any,
    *,
    kind: str,
) -> dict[str, Any]:
    expected = validate_attested_harness(attested, kind=kind)
    actual = {field: observed.get(field) for field in IDENTITY_FIELDS}
    if actual != expected:
        raise EvidenceError(
            "fixed target harness identity differs from the pre-attested identity"
        )
    return expected


def harness_environment(
    *,
    kind: str,
    source_commit: str,
    source_tree: str,
    raw_dir: Path,
    artifact_index: Path,
    observations: Path,
) -> dict[str, str]:
    environment = dict(FIXED_BASE_ENVIRONMENT)
    environment.update(
        {
            "OWNER_OPEN_R5_KIND": kind,
            "OWNER_OPEN_R5_SOURCE_COMMIT": source_commit,
            "OWNER_OPEN_R5_SOURCE_TREE": source_tree,
            "OWNER_OPEN_R5_RAW_DIR": str(raw_dir),
            "OWNER_OPEN_R5_ARTIFACT_INDEX": str(artifact_index),
            "OWNER_OPEN_R5_OBSERVATIONS": str(observations),
        }
    )
    return environment


def environment_statement(environment: dict[str, str]) -> dict[str, Any]:
    return {
        "inherit_parent": False,
        "base": dict(FIXED_BASE_ENVIRONMENT),
        "keys": sorted(environment),
    }


def _capture_driver_artifact(
    bundle_root: Path, manifest: dict[str, Any]
) -> tuple[Path, str]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise EvidenceError("manifest artifacts must be a list")
    matches = [
        item
        for item in artifacts
        if isinstance(item, dict) and item.get("role") == "capture_driver"
    ]
    if len(matches) != 1:
        raise EvidenceError("bundle must declare exactly one capture_driver artifact")
    item = matches[0]
    relative = safe_relative_path(item.get("path"), label="capture_driver.path")
    path = require_path_beneath(bundle_root, relative, label="capture_driver.path")
    size, digest = sha256_file(path)
    if item.get("bytes") != size or item.get("sha256") != digest:
        raise EvidenceError("capture_driver artifact identity differs from manifest")
    return path, digest


def validate_capture_chain(manifest_path: Path) -> dict[str, Any]:
    """Cross-check attestation, driver, observations and raw artifact bytes."""
    manifest_path = manifest_path.resolve(strict=True)
    manifest = read_json_object(manifest_path)
    bundle_root = manifest_path.parent
    kind = manifest.get("kind")
    source_commit = manifest.get("source_commit")
    source_tree = manifest.get("source_tree")
    if not isinstance(kind, str) or not kind:
        raise EvidenceError("manifest kind is required for capture trust validation")

    attestation_relative = safe_relative_path(
        manifest.get("target_attestation_path"), label="target_attestation_path"
    )
    attestation_path = require_path_beneath(
        bundle_root, attestation_relative, label="target_attestation_path"
    )
    attestation = read_json_object(attestation_path)
    attested_harness = validate_attested_harness(
        attestation.get("harness"), kind=kind
    )
    attestation_bytes, attestation_digest = sha256_file(attestation_path)

    driver_path, driver_digest = _capture_driver_artifact(bundle_root, manifest)
    driver = read_json_object(driver_path)
    if driver.get("schema") != CAPTURE_DRIVER_SCHEMA:
        raise EvidenceError("capture driver schema is unsupported")
    if driver.get("repository") != REPOSITORY:
        raise EvidenceError("capture driver repository is not canonical")
    for key, expected in (
        ("kind", kind),
        ("source_commit", source_commit),
        ("source_tree", source_tree),
    ):
        if driver.get(key) != expected:
            raise EvidenceError(f"capture driver {key} differs from manifest")
    if driver.get("synthetic") is not False:
        raise EvidenceError("capture driver must declare synthetic=false")
    if driver.get("automatic_redispatch") is not False:
        raise EvidenceError("capture driver must declare automatic_redispatch=false")

    observed_harness = driver.get("harness")
    if not isinstance(observed_harness, dict):
        raise EvidenceError("capture driver harness identity is absent")
    if {field: observed_harness.get(field) for field in IDENTITY_FIELDS} != attested_harness:
        raise EvidenceError("capture driver harness differs from target attestation")

    attestation_identity = validate_attested_attestation(
        driver.get("target_attestation"), kind=kind
    )
    if (
        attestation_identity["bytes"] != attestation_bytes
        or attestation_identity["sha256"] != attestation_digest
    ):
        raise EvidenceError("capture driver attestation identity differs from bundled bytes")

    run = driver.get("run")
    if not isinstance(run, dict) or run.get("returncode") != 0:
        raise EvidenceError("capture driver does not record a successful harness run")
    argv = run.get("argv")
    if not isinstance(argv, list) or not argv or argv[0] != attested_harness["path"]:
        raise EvidenceError("capture driver argv does not start with the attested harness")
    statement = run.get("environment")
    expected_statement = {
        "inherit_parent": False,
        "base": FIXED_BASE_ENVIRONMENT,
    }
    if not isinstance(statement, dict):
        raise EvidenceError("capture driver environment statement is absent")
    for key, expected in expected_statement.items():
        if statement.get(key) != expected:
            raise EvidenceError(f"capture driver environment {key} is not fixed")
    keys = statement.get("keys")
    required_keys = set(FIXED_BASE_ENVIRONMENT) | {
        "OWNER_OPEN_R5_KIND",
        "OWNER_OPEN_R5_SOURCE_COMMIT",
        "OWNER_OPEN_R5_SOURCE_TREE",
        "OWNER_OPEN_R5_RAW_DIR",
        "OWNER_OPEN_R5_ARTIFACT_INDEX",
        "OWNER_OPEN_R5_OBSERVATIONS",
    }
    if not isinstance(keys, list) or set(keys) != required_keys or len(keys) != len(required_keys):
        raise EvidenceError("capture driver environment key set is not exact")

    observations = manifest.get("observations")
    if not isinstance(observations, dict):
        raise EvidenceError("manifest observations are absent")
    if observations.get("capture_driver_sha256") != driver_digest:
        raise EvidenceError("observations do not bind the capture driver bytes")

    return {
        "capture_driver_sha256": driver_digest,
        "target_attestation_sha256": attestation_digest,
        "harness_sha256": attested_harness["sha256"],
        "harness_path": attested_harness["path"],
    }
