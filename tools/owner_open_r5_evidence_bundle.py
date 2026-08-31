#!/usr/bin/env python3
"""Strict validation for Owner-Open R5 external evidence bundles.

A bundle is a closed directory tree rooted beside ``manifest.json``. Every
regular file is declared by canonical relative path, byte count, SHA-256 and
role. JSON is parsed with duplicate-member rejection. Promotable bundles bind
an independently authored review attestation; L6 additionally binds a distinct
human release authorization.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Iterable

PLAN_REVISION = "2026-08-29-r6"
REPOSITORY = "TrillionniumFoundation/trillionnium-os"
BUNDLE_SCHEMA = "org.trillionnium.owner-open-r5.evidence-bundle.v1"
ATTESTATION_SCHEMA = "org.trillionnium.owner-open-r5.target-attestation.v1"
REVIEW_SCHEMA = "org.trillionnium.owner-open-r5.evidence-review.v1"
RELEASE_AUTHORIZATION_SCHEMA = (
    "org.trillionnium.owner-open-r5.release-authorization.v1"
)
ARTIFACT_INDEX_SCHEMA = "org.trillionnium.owner-open-r5.artifact-index.v1"
OBSERVATIONS_SCHEMA = "org.trillionnium.owner-open-r5.observations.v1"
LEVELS = {f"L{index}": index for index in range(7)}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024
MAX_SECRET_SCAN_BYTES = 16 * 1024 * 1024

LANE_CLASSES = {
    "L1": {"repository_governance"},
    "L2": {"installed_root_linux", "installed_codex"},
    "L3": {"clean_android_builder"},
    "L4": {"physical_android"},
    "L5": {"destructive_fault_lab"},
    "L6": {"release_signing"},
}

KIND_POLICIES: dict[str, dict[str, Any]] = {
    "repository_governance_controls": {
        "level": "L1",
        "environment_class": "repository_governance",
        "allowed_gaps": {"R5-GAP-GOVERNANCE-001"},
        "required_roles": {
            "branch_snapshot",
            "ruleset_snapshot",
            "required_checks",
            "integration_topology",
        },
        "required_observations": {
            "main_protected": True,
            "required_checks_enforced": True,
            "independent_exact_head_approval": True,
            "direct_push_blocked": True,
            "force_push_blocked": True,
        },
    },
    "installed_root_linux_process_matrix": {
        "level": "L2",
        "environment_class": "installed_root_linux",
        "allowed_gaps": {
            "R5-GAP-PROCESS-LIFECYCLE-001",
            "R5-GAP-STREAM-RECOVERY-001",
            "R5-GAP-BROKER-CORRELATION-001",
            "R5-GAP-ROOTLINUX-PLACEMENT-001",
        },
        "required_roles": {
            "installed_manifest",
            "process_identity",
            "service_manager",
            "namespace_cgroup",
            "stream_resume",
            "broker_trace",
            "restart_trace",
        },
        "required_observations": {
            "installed_entrypoint_verified": True,
            "uid_gid_verified": True,
            "namespace_cgroup_verified": True,
            "service_restart_verified": True,
            "descendants_reaped": True,
            "cursor_resume_verified": True,
            "broker_correlation_verified": True,
            "automatic_redispatch_observed": False,
        },
    },
    "installed_codex_same_turn": {
        "level": "L2",
        "environment_class": "installed_codex",
        "allowed_gaps": {
            "R5-GAP-INSTALLED-CODEX-001",
            "R5-GAP-PROCESS-LIFECYCLE-001",
            "R5-GAP-STREAM-RECOVERY-001",
            "R5-GAP-BROKER-CORRELATION-001",
            "R5-GAP-ROOTLINUX-PLACEMENT-001",
        },
        "required_roles": {
            "installed_manifest",
            "codex_release_verification",
            "codex_capabilities",
            "mcp_trace",
            "same_turn_trace",
            "pipe_pty_trace",
            "reconnect_trace",
        },
        "required_observations": {
            "release_identity_verified": True,
            "authenticated_turn_completed": True,
            "same_turn_effects_observed": True,
            "pipe_pty_controls_observed": True,
            "reconnect_no_retry_observed": True,
            "automatic_redispatch_observed": False,
        },
    },
    "clean_android_target_files": {
        "level": "L3",
        "environment_class": "clean_android_builder",
        "allowed_gaps": {
            "R5-GAP-PRODUCT-ENTRYPOINT-001",
            "R5-GAP-ANDROID-GRAPH-001",
        },
        "required_roles": {
            "source_manifest",
            "project_heads",
            "patch_series",
            "soong_inventory",
            "init_inventory",
            "selinux_inventory",
            "target_files_inventory",
            "image_hashes",
            "installed_manifest",
        },
        "required_observations": {
            "clean_source_verified": True,
            "target_files_built": True,
            "forbidden_nodes_absent": True,
            "init_selinux_verified": True,
            "installed_manifest_matches": True,
        },
    },
    "physical_android_adb": {
        "level": "L4",
        "environment_class": "physical_android",
        "allowed_gaps": {"R5-GAP-PHYSICAL-ADB-001"},
        "required_roles": {
            "device_identity",
            "transport_identity",
            "adb_trace",
            "same_turn_trace",
            "visible_mutation",
            "usb_reconnect_trace",
            "cleanup_terminal",
        },
        "required_observations": {
            "authorized_device": True,
            "ordinary_adb": True,
            "visible_mutation_observed": True,
            "raw_error_states_observed": True,
            "usb_reconnect_no_retry_observed": True,
            "automatic_redispatch_observed": False,
        },
    },
    "destructive_fault_matrix": {
        "level": "L5",
        "environment_class": "destructive_fault_lab",
        "allowed_gaps": {
            "R5-GAP-JOURNAL-CONVERGENCE-001",
            "R5-GAP-FAULT-MATRIX-001",
            "R5-GAP-PROCESS-LIFECYCLE-001",
            "R5-GAP-STREAM-RECOVERY-001",
            "R5-GAP-BROKER-CORRELATION-001",
            "R5-GAP-ROOTLINUX-PLACEMENT-001",
        },
        "required_roles": {
            "fault_matrix",
            "durable_records",
            "recovery_trace",
            "redispatch_audit",
            "cleanup_terminal",
        },
        "required_observations": {
            "fault_families_complete": True,
            "storage_faults_complete": True,
            "process_faults_complete": True,
            "device_faults_complete": True,
            "power_loss_complete": True,
            "automatic_redispatch_observed": False,
        },
    },
    "signed_public_release": {
        "level": "L6",
        "environment_class": "release_signing",
        "allowed_gaps": {"R5-GAP-RELEASE-001"},
        "required_roles": {
            "release_manifest",
            "signature_verification",
            "transparency_verification",
            "avb_rollback",
            "ota_test",
            "key_custody_review",
            "multi_user_review",
            "release_authorization",
        },
        "required_observations": {
            "artifact_signatures_verified": True,
            "transparency_log_verified": True,
            "avb_rollback_verified": True,
            "ota_install_rollback_verified": True,
            "key_custody_approved": True,
            "multi_user_policy_approved": True,
            "human_release_authorized": True,
        },
    },
}

SECRET_NAME_PATTERNS = (
    re.compile(r"(^|[-_.])(private[-_]?key|id_rsa|id_ed25519)([-_.]|$)", re.I),
    re.compile(r"(^|[-_.])(credential|credentials|token|secret)([-_.]|$)", re.I),
    re.compile(r"\.(pem|p12|pfx|key)$", re.I),
)
SECRET_BYTE_PATTERNS = (
    re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(rb"(?:^|[^A-Za-z0-9])ghp_[A-Za-z0-9]{20,}"),
    re.compile(rb"(?:^|[^A-Za-z0-9])github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(rb"(?:^|[^A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}"),
    re.compile(rb"OPENAI_API_KEY\s*="),
    re.compile(rb"Authorization:\s*Bearer\s+[A-Za-z0-9._~+/-]{12,}", re.I),
)


class EvidenceError(ValueError):
    """Raised when evidence is malformed, incomplete or overclaims."""


class DuplicateMember(ValueError):
    """Raised by strict JSON parsing for duplicate object members."""


@dataclass
class BundleReport:
    ok: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)

    def check(self, condition: bool, message: str) -> None:
        if not condition:
            self.ok = False
            self.errors.append(message)


def strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateMember(f"duplicate key {key!r}")
        result[key] = value
    return result


def read_json_object(path: Path, *, maximum: int = MAX_JSON_BYTES) -> dict[str, Any]:
    raw = read_regular_bytes(path, maximum=maximum, label=str(path))
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateMember) as error:
        raise EvidenceError(f"invalid strict JSON at {path}: {error}") from error
    if not isinstance(value, dict):
        raise EvidenceError(f"{path} must contain one JSON object")
    return value


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path, *, maximum: int = MAX_ARTIFACT_BYTES) -> tuple[int, str]:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256()
    total = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise EvidenceError(f"artifact is not regular: {path}")
        if before.st_nlink != 1:
            raise EvidenceError(f"artifact must have exactly one hard link: {path}")
        if before.st_size < 0 or before.st_size > maximum:
            raise EvidenceError(f"artifact is outside byte bound: {path}")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise EvidenceError(f"artifact exceeded byte bound while read: {path}")
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after or total != before.st_size:
            raise EvidenceError(f"artifact changed while hashed: {path}")
    finally:
        os.close(descriptor)
    return total, digest.hexdigest()


def read_regular_bytes(path: Path, *, maximum: int, label: str) -> bytes:
    size, _digest = sha256_file(path, maximum=maximum)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise EvidenceError(f"short read for {label}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise EvidenceError(f"{label} grew while read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def safe_relative_path(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise EvidenceError(f"{label} must be a non-empty POSIX relative path")
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or value.startswith("./") or value.endswith("/"):
        raise EvidenceError(f"{label} is not canonical relative path: {value!r}")
    if any(part in {"", ".", ".."} for part in candidate.parts):
        raise EvidenceError(f"{label} contains unsafe path component: {value!r}")
    normalized = candidate.as_posix()
    if normalized != value:
        raise EvidenceError(f"{label} is not normalized: {value!r}")
    return normalized


def require_path_beneath(root: Path, relative: str, *, label: str) -> Path:
    root_resolved = root.resolve(strict=True)
    candidate = root / Path(*PurePosixPath(relative).parts)
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise EvidenceError(f"{label} is absent: {relative}: {error}") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise EvidenceError(f"{label} contains symlink component: {relative}")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root_resolved)
    except ValueError as error:
        raise EvidenceError(f"{label} escapes bundle root: {relative}") from error
    if not resolved.is_file():
        raise EvidenceError(f"{label} is not a regular file: {relative}")
    return candidate


def parse_utc(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise EvidenceError(f"{label} must be RFC3339 UTC with Z suffix")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise EvidenceError(f"{label} is invalid timestamp: {value!r}") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise EvidenceError(f"{label} is not UTC")
    return parsed


def nonempty_strings(value: Any, *, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise EvidenceError(f"{label} must be a non-empty list")
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise EvidenceError(f"{label}[{index}] must be a non-empty string")
        result.append(item)
    return result


def require_login(value: Any, *, label: str, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or LOGIN.fullmatch(value) is None:
        raise EvidenceError(f"{label} must be a GitHub-style login")
    lowered = value.lower()
    if lowered.endswith("[bot]") or lowered in {"github-actions", "github-actions[bot]"}:
        raise EvidenceError(f"{label} must not be a bot login")
    return value


def _scan_secret_shape(path: str, raw: bytes) -> None:
    name = PurePosixPath(path).name
    for pattern in SECRET_NAME_PATTERNS:
        if pattern.search(name):
            raise EvidenceError(f"artifact filename has secret/private-key shape: {path}")
    for pattern in SECRET_BYTE_PATTERNS:
        if pattern.search(raw):
            raise EvidenceError(f"artifact content has credential/private-key shape: {path}")


def _target_identity_requirements(level: str, target: dict[str, Any]) -> None:
    required = {"id", "kind", "fingerprint"}
    if level == "L2":
        required.add("boot_id")
    elif level == "L3":
        required.add("build_id")
    elif level == "L4":
        required.update({"boot_id", "serial"})
    elif level == "L5":
        required.add("boot_id")
    elif level == "L6":
        required.add("authorization_domain")
    for key in sorted(required):
        value = target.get(key)
        if not isinstance(value, str) or not value.strip():
            raise EvidenceError(f"target.{key} is required for {level}")


def validate_target_attestation(
    path: Path,
    *,
    manifest: dict[str, Any],
    at_time: datetime,
) -> dict[str, Any]:
    value = read_json_object(path)
    if value.get("schema") != ATTESTATION_SCHEMA:
        raise EvidenceError("target attestation schema is unsupported")
    if value.get("plan_revision") != PLAN_REVISION:
        raise EvidenceError("target attestation plan revision drifted")
    level = manifest.get("evidence_level")
    if value.get("lane") != level:
        raise EvidenceError("target attestation lane differs from manifest evidence level")
    if value.get("source_commit") != manifest.get("source_commit"):
        raise EvidenceError("target attestation source commit differs from manifest")
    if value.get("source_tree") != manifest.get("source_tree"):
        raise EvidenceError("target attestation source tree differs from manifest")
    if value.get("synthetic") is not False or value.get("template") is not False:
        raise EvidenceError("target attestation must declare synthetic=false and template=false")

    captured = parse_utc(value.get("captured_at"), label="attestation.captured_at")
    expires = parse_utc(value.get("expires_at"), label="attestation.expires_at")
    if not captured < expires:
        raise EvidenceError("target attestation expiry must follow capture time")
    if at_time.tzinfo is None:
        at_time = at_time.replace(tzinfo=timezone.utc)
    if at_time < captured or at_time > expires:
        raise EvidenceError("target attestation was not valid at capture/review time")

    environment = value.get("environment")
    if not isinstance(environment, dict):
        raise EvidenceError("target attestation environment must be an object")
    environment_class = environment.get("class")
    if environment_class not in LANE_CLASSES.get(str(level), set()):
        raise EvidenceError(
            f"environment class {environment_class!r} is not valid for evidence level {level}"
        )
    if environment.get("independent_control") is not True:
        raise EvidenceError("target environment must declare independent_control=true")
    for key in ("id", "owner"):
        if not isinstance(environment.get(key), str) or not environment[key].strip():
            raise EvidenceError(f"environment.{key} is required")

    runner = value.get("runner")
    if not isinstance(runner, dict):
        raise EvidenceError("target attestation runner must be an object")
    labels = runner.get("labels")
    if not isinstance(labels, list) or not labels or not all(
        isinstance(item, str) and item for item in labels
    ):
        raise EvidenceError("target attestation runner.labels must be non-empty strings")
    if level in {"L2", "L3", "L4", "L5", "L6"}:
        expected = f"owner-open-r5-{str(level).lower()}"
        if "self-hosted" not in labels or expected not in labels:
            raise EvidenceError(
                f"target runner labels must include self-hosted and {expected}"
            )
    for key in ("name", "os", "arch"):
        if not isinstance(runner.get(key), str) or not runner[key].strip():
            raise EvidenceError(f"runner.{key} is required")

    target = value.get("target")
    if not isinstance(target, dict):
        raise EvidenceError("target attestation target must be an object")
    _target_identity_requirements(str(level), target)

    operator = value.get("operator")
    if not isinstance(operator, dict):
        raise EvidenceError("target attestation operator must be an object")
    require_login(operator.get("login"), label="operator.login")
    return value


def _artifact_map(
    bundle_root: Path,
    manifest: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], int, set[str]]:
    raw_artifacts = manifest.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        raise EvidenceError("manifest artifacts must be a non-empty list")
    result: dict[str, dict[str, Any]] = {}
    roles: set[str] = set()
    total_bytes = 0
    for index, item in enumerate(raw_artifacts):
        label = f"artifacts[{index}]"
        if not isinstance(item, dict):
            raise EvidenceError(f"{label} must be an object")
        relative = safe_relative_path(item.get("path"), label=f"{label}.path")
        if relative == "manifest.json":
            raise EvidenceError("manifest.json must not list itself as an artifact")
        if relative in result:
            raise EvidenceError(f"duplicate artifact path: {relative}")
        expected_bytes = item.get("bytes")
        if (
            not isinstance(expected_bytes, int)
            or isinstance(expected_bytes, bool)
            or expected_bytes < 0
        ):
            raise EvidenceError(f"{label}.bytes must be a non-negative integer")
        expected_digest = item.get("sha256")
        if not isinstance(expected_digest, str) or HEX64.fullmatch(expected_digest) is None:
            raise EvidenceError(f"{label}.sha256 must be lowercase 64-hex")
        role = item.get("role")
        if not isinstance(role, str) or not role:
            raise EvidenceError(f"{label}.role is required")
        path = require_path_beneath(bundle_root, relative, label=label)
        observed_bytes, observed_digest = sha256_file(path)
        if observed_bytes != expected_bytes or observed_digest != expected_digest:
            raise EvidenceError(f"artifact identity mismatch: {relative}")
        total_bytes += observed_bytes
        if observed_bytes <= MAX_SECRET_SCAN_BYTES:
            _scan_secret_shape(
                relative,
                read_regular_bytes(path, maximum=MAX_SECRET_SCAN_BYTES, label=relative),
            )
        result[relative] = item
        roles.add(role)

    declared = set(result)
    observed: set[str] = set()
    for path in sorted(bundle_root.rglob("*")):
        relative = path.relative_to(bundle_root).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise EvidenceError(f"bundle contains symlink: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise EvidenceError(f"bundle contains non-regular node: {relative}")
        if relative == "manifest.json":
            continue
        observed.add(relative)
    if declared != observed:
        raise EvidenceError(
            "bundle artifact closure mismatch; undeclared="
            + repr(sorted(observed - declared))
            + " absent="
            + repr(sorted(declared - observed))
        )
    return result, total_bytes, roles


def _validate_review_attestation(
    path: Path,
    *,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    value = read_json_object(path)
    if value.get("schema") != REVIEW_SCHEMA:
        raise EvidenceError("review attestation schema is unsupported")
    for key in ("plan_revision", "repository", "source_commit", "source_tree", "kind", "evidence_level"):
        expected = manifest.get(key)
        if value.get(key) != expected:
            raise EvidenceError(f"review attestation {key} differs from manifest")
    if value.get("approved") is not True:
        raise EvidenceError("review attestation must approve the evidence")
    reviewer = require_login(value.get("reviewer"), label="review_attestation.reviewer")
    review_id = value.get("review_id")
    if not isinstance(review_id, int) or isinstance(review_id, bool) or review_id <= 0:
        raise EvidenceError("review attestation review_id must be positive")
    reviewed_at = parse_utc(value.get("reviewed_at"), label="review_attestation.reviewed_at")
    gap_ids = nonempty_strings(value.get("gap_ids"), label="review_attestation.gap_ids")
    if gap_ids != manifest.get("gap_ids"):
        raise EvidenceError("review attestation gap_ids differ from manifest")
    nonempty_strings(
        value.get("negative_claims"), label="review_attestation.negative_claims"
    )
    return {
        "reviewer": reviewer,
        "review_id": review_id,
        "reviewed_at": reviewed_at,
        "raw": value,
    }


def _validate_release_authorization(
    path: Path,
    *,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    value = read_json_object(path)
    if value.get("schema") != RELEASE_AUTHORIZATION_SCHEMA:
        raise EvidenceError("release authorization schema is unsupported")
    for key in ("plan_revision", "repository", "source_commit", "source_tree"):
        if value.get(key) != manifest.get(key):
            raise EvidenceError(f"release authorization {key} differs from manifest")
    if value.get("authorized") is not True or value.get("public_release") is not True:
        raise EvidenceError("release authorization must explicitly authorize public release")
    authorizer = require_login(
        value.get("authorizer"), label="release_authorization.authorizer"
    )
    authorization_id = value.get("authorization_id")
    if not isinstance(authorization_id, str) or not authorization_id.strip():
        raise EvidenceError("release authorization_id is required")
    authorized_at = parse_utc(
        value.get("authorized_at"), label="release_authorization.authorized_at"
    )
    return {
        "authorizer": authorizer,
        "authorization_id": authorization_id,
        "authorized_at": authorized_at,
        "raw": value,
    }


def validate_bundle(
    manifest_path: Path,
    *,
    require_promotable: bool,
    now: datetime | None = None,
) -> BundleReport:
    report = BundleReport()
    try:
        if manifest_path.name != "manifest.json":
            raise EvidenceError("bundle manifest filename must be manifest.json")
        manifest_path = manifest_path.resolve(strict=True)
        bundle_root = manifest_path.parent
        manifest = read_json_object(manifest_path)
        manifest_bytes = read_regular_bytes(
            manifest_path, maximum=MAX_JSON_BYTES, label="manifest.json"
        )
        manifest_digest = sha256_bytes(manifest_bytes)

        if manifest.get("schema") != BUNDLE_SCHEMA:
            raise EvidenceError("evidence bundle schema is unsupported")
        if manifest.get("plan_revision") != PLAN_REVISION:
            raise EvidenceError("evidence bundle plan revision drifted")
        if manifest.get("repository") != REPOSITORY:
            raise EvidenceError("evidence bundle repository is not canonical")
        for key in ("branch", "kind", "claim_ceiling"):
            if not isinstance(manifest.get(key), str) or not manifest[key].strip():
                raise EvidenceError(f"manifest.{key} is required")
        for key in ("source_commit", "source_tree"):
            value = manifest.get(key)
            if not isinstance(value, str) or HEX40.fullmatch(value) is None:
                raise EvidenceError(f"manifest.{key} must be lowercase 40-hex")
        level = manifest.get("evidence_level")
        if level not in LEVELS:
            raise EvidenceError("manifest.evidence_level is invalid")
        policy = KIND_POLICIES.get(str(manifest.get("kind")))
        if not isinstance(policy, dict):
            raise EvidenceError("manifest.kind is not an approved evidence kind")
        if level != policy["level"]:
            raise EvidenceError("manifest evidence level differs from kind policy")
        if manifest.get("result") != "pass":
            raise EvidenceError("evidence bundle result must be pass")
        if manifest.get("synthetic") is not False:
            raise EvidenceError("evidence bundle must declare synthetic=false")
        if manifest.get("automatic_redispatch") is not False:
            raise EvidenceError("evidence bundle must declare automatic_redispatch=false")

        started_at = parse_utc(manifest.get("started_at"), label="manifest.started_at")
        finished_at = parse_utc(manifest.get("finished_at"), label="manifest.finished_at")
        if started_at > finished_at:
            raise EvidenceError("manifest finished_at precedes started_at")
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)

        gap_ids = nonempty_strings(manifest.get("gap_ids"), label="manifest.gap_ids")
        if len(gap_ids) != len(set(gap_ids)):
            raise EvidenceError("manifest.gap_ids contains duplicates")
        if not set(gap_ids) <= set(policy["allowed_gaps"]):
            raise EvidenceError("manifest gap_ids exceed the evidence-kind policy")
        nonempty_strings(manifest.get("negative_claims"), label="manifest.negative_claims")

        observations = manifest.get("observations")
        if not isinstance(observations, dict):
            raise EvidenceError("manifest.observations must be an object")
        if observations.get("schema") != OBSERVATIONS_SCHEMA:
            raise EvidenceError("manifest observations schema is unsupported")
        if observations.get("kind") != manifest.get("kind"):
            raise EvidenceError("manifest observations kind differs from manifest")
        for key, expected in policy["required_observations"].items():
            if observations.get(key) is not expected:
                raise EvidenceError(
                    f"required observation {key} must be exactly {expected!r}"
                )

        producer = manifest.get("producer")
        if not isinstance(producer, dict):
            raise EvidenceError("manifest.producer must be an object")
        producer_login = require_login(producer.get("login"), label="producer.login")
        for key in ("workflow_run_id", "workflow_run_attempt"):
            value = producer.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise EvidenceError(f"producer.{key} must be a positive integer")
        for key in ("workflow", "job"):
            if not isinstance(producer.get(key), str) or not producer[key].strip():
                raise EvidenceError(f"producer.{key} is required")

        retention = manifest.get("retention")
        if not isinstance(retention, dict):
            raise EvidenceError("manifest.retention must be an object")
        parse_utc(
            retention.get("artifact_expires_at"),
            label="retention.artifact_expires_at",
        )
        for key in ("immutable_location", "reproduction"):
            if not isinstance(retention.get(key), str) or not retention[key].strip():
                raise EvidenceError(f"retention.{key} is required")
        if not isinstance(retention.get("environment_available"), bool):
            raise EvidenceError("retention.environment_available must be boolean")

        promotable = manifest.get("promotable")
        if not isinstance(promotable, bool):
            raise EvidenceError("manifest.promotable must be boolean")
        if require_promotable and promotable is not True:
            raise EvidenceError("bundle is capture-only and is not promotable")

        artifacts, total_artifact_bytes, roles = _artifact_map(bundle_root, manifest)
        base_roles = {"artifact_index", "observation_summary", "target_attestation"}
        missing_roles = (set(policy["required_roles"]) | base_roles) - roles
        if promotable:
            missing_roles.discard("independent_review")
            if "review_attestation" not in roles:
                missing_roles.add("review_attestation")
        if missing_roles:
            raise EvidenceError(
                "bundle is missing required artifact roles: "
                + ", ".join(sorted(missing_roles))
            )

        review = manifest.get("review")
        if not isinstance(review, dict):
            raise EvidenceError("manifest.review must be an object")
        review_info: dict[str, Any] | None = None
        if promotable:
            if review.get("approved") is not True:
                raise EvidenceError("promotable bundle requires review.approved=true")
            review_relative = safe_relative_path(
                review.get("attestation_path"), label="review.attestation_path"
            )
            review_item = artifacts.get(review_relative)
            if not isinstance(review_item, dict) or review_item.get("role") != "review_attestation":
                raise EvidenceError(
                    "review attestation must be a declared artifact with role review_attestation"
                )
            review_info = _validate_review_attestation(
                require_path_beneath(bundle_root, review_relative, label="review.attestation_path"),
                manifest=manifest,
            )
            if review.get("reviewer") != review_info["reviewer"]:
                raise EvidenceError("manifest reviewer differs from review attestation")
            if review.get("review_id") != review_info["review_id"]:
                raise EvidenceError("manifest review_id differs from review attestation")
            if review.get("reviewed_at") != review_info["raw"].get("reviewed_at"):
                raise EvidenceError("manifest reviewed_at differs from review attestation")
            if review_info["reviewer"] == producer_login:
                raise EvidenceError("promotable bundle reviewer must differ from producer")
            attestation_time = review_info["reviewed_at"]
        else:
            if review != {
                "approved": False,
                "attestation_path": None,
                "reviewer": None,
                "review_id": None,
                "reviewed_at": None,
            }:
                raise EvidenceError("capture-only review object is not the canonical false form")
            attestation_time = current

        attestation_relative = safe_relative_path(
            manifest.get("target_attestation_path"), label="target_attestation_path"
        )
        attestation_item = artifacts.get(attestation_relative)
        if not isinstance(attestation_item, dict) or attestation_item.get("role") != "target_attestation":
            raise EvidenceError(
                "target attestation must be a declared artifact with role target_attestation"
            )
        attestation = validate_target_attestation(
            require_path_beneath(
                bundle_root, attestation_relative, label="target_attestation_path"
            ),
            manifest=manifest,
            at_time=attestation_time,
        )
        if attestation["environment"]["class"] != policy["environment_class"]:
            raise EvidenceError("target environment class differs from evidence-kind policy")
        operator_login = attestation.get("operator", {}).get("login")
        if promotable and review_info and review_info["reviewer"] == operator_login:
            raise EvidenceError("promotable bundle reviewer must differ from target operator")

        release_info: dict[str, Any] | None = None
        if level == "L6":
            authorization_relative = safe_relative_path(
                manifest.get("release_authorization_path"),
                label="release_authorization_path",
            )
            authorization_item = artifacts.get(authorization_relative)
            if (
                not isinstance(authorization_item, dict)
                or authorization_item.get("role") != "release_authorization"
            ):
                raise EvidenceError(
                    "release authorization must be a declared artifact with role release_authorization"
                )
            release_info = _validate_release_authorization(
                require_path_beneath(
                    bundle_root,
                    authorization_relative,
                    label="release_authorization_path",
                ),
                manifest=manifest,
            )
            reviewer = review_info["reviewer"] if review_info else None
            if release_info["authorizer"] in {producer_login, reviewer, operator_login}:
                raise EvidenceError(
                    "L6 authorizer must be independent of producer, reviewer and operator"
                )
        elif manifest.get("release_authorization_path") is not None:
            raise EvidenceError("release_authorization_path is permitted only for L6")

        report.facts.update(
            {
                "manifest_path": str(manifest_path),
                "manifest_sha256": manifest_digest,
                "source_commit": manifest["source_commit"],
                "source_tree": manifest["source_tree"],
                "evidence_level": level,
                "gap_ids": gap_ids,
                "kind": manifest["kind"],
                "reviewer": review_info["reviewer"] if review_info else None,
                "promotable": promotable,
                "artifact_count": len(artifacts),
                "artifact_bytes": total_artifact_bytes,
                "environment_class": attestation["environment"]["class"],
                "target_id": attestation["target"]["id"],
                "release_authorizer": release_info["authorizer"] if release_info else None,
            }
        )
    except (EvidenceError, OSError) as error:
        report.ok = False
        report.errors.append(str(error))
    return report


def require_valid_bundle(
    manifest_path: Path,
    *,
    require_promotable: bool,
    now: datetime | None = None,
) -> dict[str, Any]:
    report = validate_bundle(
        manifest_path, require_promotable=require_promotable, now=now
    )
    if not report.ok:
        raise EvidenceError("; ".join(report.errors))
    return report.facts


def validate_evidence_reference(
    repo_root: Path,
    *,
    gap_id: str,
    exit_level: str,
    source_commit: str,
    source_tree: str,
    item: dict[str, Any],
) -> dict[str, Any]:
    if exit_level not in LEVELS:
        raise EvidenceError(f"invalid exit level for {gap_id}: {exit_level}")
    bundle_relative = safe_relative_path(
        item.get("bundle_path"), label="evidence.bundle_path"
    )
    if not bundle_relative.startswith("evidence/owner-open-r5/"):
        raise EvidenceError("evidence bundle_path must be below evidence/owner-open-r5/")
    if not bundle_relative.endswith("/manifest.json"):
        raise EvidenceError("evidence bundle_path must name a manifest.json")
    manifest_path = require_path_beneath(
        repo_root, bundle_relative, label="evidence.bundle_path"
    )
    facts = require_valid_bundle(manifest_path, require_promotable=True)
    if item.get("evidence_sha256") != facts["manifest_sha256"]:
        raise EvidenceError(f"{gap_id} evidence_sha256 does not match manifest bytes")
    level = item.get("level")
    if level not in LEVELS or level != facts["evidence_level"]:
        raise EvidenceError(f"{gap_id} evidence level differs from bundle")
    if LEVELS[level] < LEVELS[exit_level]:
        raise EvidenceError(f"{gap_id} evidence level is below exit level")
    if (
        item.get("source_commit") != source_commit
        or facts["source_commit"] != source_commit
    ):
        raise EvidenceError(f"{gap_id} evidence source commit differs from source evidence")
    if item.get("source_tree") != source_tree or facts["source_tree"] != source_tree:
        raise EvidenceError(f"{gap_id} evidence source tree differs from source evidence")
    if item.get("kind") != facts["kind"]:
        raise EvidenceError(f"{gap_id} evidence kind differs from bundle")
    if item.get("reviewer") != facts["reviewer"]:
        raise EvidenceError(f"{gap_id} reviewer differs from bundle")
    if item.get("synthetic") is not False:
        raise EvidenceError(f"{gap_id} evidence must declare synthetic=false")
    if gap_id not in facts["gap_ids"]:
        raise EvidenceError(f"{gap_id} is absent from bundle gap_ids")
    return facts


def enumerate_bundle_files(bundle_root: Path, *, exclude: Iterable[str] = ()) -> list[Path]:
    excluded = set(exclude)
    result: list[Path] = []
    for path in sorted(bundle_root.rglob("*")):
        relative = path.relative_to(bundle_root).as_posix()
        if relative in excluded:
            continue
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise EvidenceError(f"bundle contains symlink: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise EvidenceError(f"bundle contains non-regular node: {relative}")
        result.append(path)
    return result
