#!/usr/bin/env python3
"""Generate an exact-head Owner-Open R5 resume packet.

The packet is a machine-readable execution handoff, not L2-L6 evidence and not
an automatic state promotion. It summarizes the canonical gap register, checks
that the checked-in claim policy remains fail-closed, and names the exact
material or authority required for the next evidence run.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from owner_open_r5_evidence_bundle import (  # noqa: E402
    EvidenceError,
    validate_evidence_reference,
)

GAPS = Path("docs/status/owner-open-r5-gap-closure.json")
STATUS = Path("docs/status/owner-open-r5-status.json")
EXPECTED_GAP_SCHEMA = "org.trillionnium.owner-open-r5.gap-closure.v1"
EXPECTED_STATUS_SCHEMA = "org.trillionnium.owner-open-r5-status.v2"
EXPECTED_REVISION = "2026-08-29-r6"
EXPECTED_CLAIM_CEILING = "EXACT_COMMIT_SOURCE_GATES_PASSED_NOT_INSTALLED_CODEX"
REQUIRED_GENERATED_POLICY = {
    "checked_in_status_is_claim_policy_not_exact_head_evidence": True,
    "exact_head_evidence_must_be_ci_generated": True,
}
PACKET_SCHEMA = "org.trillionnium.owner-open-r5.resume-packet.v1"
ALLOWED_STATES = {
    "OPEN",
    "SOURCE_CLOSED_PENDING_EVIDENCE",
    "EXTERNAL_HOLD",
    "CLOSED",
}
LEVELS = {f"L{index}": index for index in range(7)}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ARTIFACT_SHA_SUFFIX = re.compile(r"-([0-9a-f]{40})$")
# Immutable R6 identity/issue/level/evidence contract shared by the packet
# generator and the standalone promotion verifiers.
CANONICAL_GAP_SPECS: dict[str, tuple[tuple[int, ...], str, bool]] = {
    "R5-GAP-GOVERNANCE-001": ((20,), "L1", True),
    "R5-GAP-JOB-ADMISSION-001": ((14,), "L1", False),
    "R5-GAP-PROCESS-LIFECYCLE-001": ((15,), "L2", True),
    "R5-GAP-STREAM-RECOVERY-001": ((16,), "L2", True),
    "R5-GAP-JOURNAL-CONVERGENCE-001": ((17,), "L5", True),
    "R5-GAP-BROKER-CORRELATION-001": ((18,), "L2", True),
    "R5-GAP-PRODUCT-ENTRYPOINT-001": ((19,), "L3", True),
    "R5-GAP-INSTALLED-CODEX-001": ((10, 13), "L2", True),
    "R5-GAP-ROOTLINUX-PLACEMENT-001": ((4, 13), "L2", True),
    "R5-GAP-ANDROID-GRAPH-001": ((2,), "L3", True),
    "R5-GAP-PHYSICAL-ADB-001": ((5, 8, 13), "L4", True),
    "R5-GAP-FAULT-MATRIX-001": ((6, 13), "L5", True),
    "R5-GAP-RELEASE-001": ((13,), "L6", True),
}
EXTERNAL_EVIDENCE_GAPS = {
    "R5-GAP-GOVERNANCE-001",
    "R5-GAP-INSTALLED-CODEX-001",
    "R5-GAP-ROOTLINUX-PLACEMENT-001",
    "R5-GAP-ANDROID-GRAPH-001",
    "R5-GAP-PHYSICAL-ADB-001",
    "R5-GAP-FAULT-MATRIX-001",
    "R5-GAP-RELEASE-001",
}
CANONICAL_GAP_ORDER = tuple(CANONICAL_GAP_SPECS)


class PacketError(ValueError):
    """Raised when canonical status cannot produce a trustworthy handoff."""


class Identity:
    def __init__(
        self,
        *,
        repository: str,
        branch: str,
        commit_sha: str,
        tree_sha: str,
        workflow_run_id: int,
        workflow_run_attempt: int,
    ) -> None:
        self.repository = repository
        self.branch = branch
        self.commit_sha = commit_sha
        self.tree_sha = tree_sha
        self.workflow_run_id = workflow_run_id
        self.workflow_run_attempt = workflow_run_attempt

    def validate(self) -> None:
        if not self.repository or "/" not in self.repository:
            raise PacketError("repository identity must be owner/name")
        if not self.branch:
            raise PacketError("branch identity is missing")
        if HEX40.fullmatch(self.commit_sha) is None:
            raise PacketError("commit identity must be lowercase 40-hex")
        if HEX40.fullmatch(self.tree_sha) is None:
            raise PacketError("tree identity must be lowercase 40-hex")
        if self.workflow_run_id <= 0:
            raise PacketError("workflow_run_id must be positive")
        if self.workflow_run_attempt <= 0:
            raise PacketError("workflow_run_attempt must be positive")


def read_object(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise PacketError(
                f"{path} must be a single-link regular file"
            )
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PacketError(f"cannot parse {path}: {error}") from error
    if not isinstance(value, dict):
        raise PacketError(f"{path} must contain one JSON object")
    return value


def nonempty_strings(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and bool(item.strip()) for item in value)
    )


def requires_external_evidence(
    item: dict[str, Any],
    exit_level: str,
    identifier: str,
) -> bool:
    """Resolve immutable external-lane semantics for packet generation."""
    value = item.get("requires_external_evidence")
    if value is not None and not isinstance(value, bool):
        raise PacketError(f"{identifier}.requires_external_evidence must be boolean")
    if identifier in EXTERNAL_EVIDENCE_GAPS:
        if value is not True:
            raise PacketError(
                f"{identifier}.requires_external_evidence must be true for an external lane"
            )
        return True
    if LEVELS[exit_level] >= LEVELS["L2"]:
        if value is False:
            raise PacketError(
                f"{identifier} cannot disable external evidence for {exit_level}"
            )
        return True
    return value is True


def issue_values(item: dict[str, Any], label: str) -> list[int]:
    values: list[int] = []
    issue = item.get("issue")
    if isinstance(issue, int) and not isinstance(issue, bool) and issue > 0:
        values.append(issue)
    issues = item.get("issues")
    if isinstance(issues, list):
        for value in issues:
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise PacketError(f"{label}.issues must contain positive integers")
            values.append(value)
    if not values:
        raise PacketError(f"{label} must bind an issue or issues")
    return values


def validate_canonical_shape(
    item: dict[str, Any], identifier: str, exit_level: str, issues: list[int]
) -> None:
    spec = CANONICAL_GAP_SPECS.get(identifier)
    if spec is None:
        return
    expected_issues, expected_level, expected_external = spec
    if exit_level != expected_level:
        raise PacketError(
            f"{identifier} exit_evidence_level drifted from canonical R6 contract"
        )
    if sorted(issues) != sorted(expected_issues):
        raise PacketError(f"{identifier} issue binding drifted from canonical R6 contract")
    if item.get("requires_external_evidence") is not expected_external:
        raise PacketError(
            f"{identifier} requires_external_evidence drifted from canonical R6 contract"
        )


def validate_source_evidence(
    value: Any,
    label: str,
    source_bindings: list[tuple[str, tuple[Any, ...]]] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PacketError(f"{label}.source_evidence must be an object")
    if value.get("level") != "L1":
        raise PacketError(f"{label}.source_evidence.level must be L1")
    if not isinstance(value.get("branch"), str) or not value["branch"].strip():
        raise PacketError(f"{label}.source_evidence.branch is missing")
    for field in ("commit", "tree"):
        raw = value.get(field)
        if not isinstance(raw, str) or HEX40.fullmatch(raw) is None:
            raise PacketError(
                f"{label}.source_evidence.{field} must be lowercase 40-hex"
            )
    run_id = value.get("workflow_run_id")
    if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0:
        raise PacketError(
            f"{label}.source_evidence.workflow_run_id must be positive"
        )
    if not nonempty_strings(value.get("successful_jobs")):
        raise PacketError(f"{label}.source_evidence.successful_jobs is missing")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise PacketError(f"{label}.source_evidence.artifacts is missing")
    normalized_artifacts: list[tuple[int, str, str]] = []
    artifact_ids: set[int] = set()
    for index, artifact in enumerate(artifacts):
        artifact_label = f"{label}.source_evidence.artifacts[{index}]"
        if not isinstance(artifact, dict):
            raise PacketError(f"{artifact_label} must be an object")
        artifact_id = artifact.get("id")
        if (
            not isinstance(artifact_id, int)
            or isinstance(artifact_id, bool)
            or artifact_id <= 0
        ):
            raise PacketError(f"{artifact_label}.id must be positive")
        if artifact_id in artifact_ids:
            raise PacketError(f"{artifact_label}.id is duplicated")
        artifact_ids.add(artifact_id)
        name = artifact.get("name")
        if not isinstance(name, str) or not name.strip():
            raise PacketError(f"{artifact_label}.name is missing")
        name = name.strip()
        digest = artifact.get("digest")
        if (
            not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or HEX64.fullmatch(digest.removeprefix("sha256:")) is None
        ):
            raise PacketError(
                f"{artifact_label}.digest must be sha256:<64 lowercase hex>"
            )
        suffix = ARTIFACT_SHA_SUFFIX.search(name)
        if suffix is not None and suffix.group(1) != value["commit"]:
            raise PacketError(
                f"{artifact_label}.name is bound to a different source commit"
            )
        normalized_artifacts.append((artifact_id, name, digest))
    if source_bindings is not None:
        source_bindings.append(
            (
                label,
                (
                    value["branch"].strip(),
                    value["commit"],
                    value["tree"],
                    value["workflow_run_id"],
                    tuple(sorted(value["successful_jobs"])),
                    tuple(sorted(normalized_artifacts)),
                ),
            )
        )
    return value


def validate_optional_candidate_identity(
    value: Any, label: str
) -> tuple[str, str, str, int] | None:
    """Validate an optional status/documentation provenance anchor.

    A non-null candidate is part of the promotion identity.  Treating a
    malformed scalar or incomplete object as if it were absent would let a
    resume packet silently discard a checked-in provenance claim.
    """
    if value is None:
        return None
    if not isinstance(value, dict):
        raise PacketError(f"{label} must be an object when present")
    branch = value.get("branch")
    commit = value.get("validated_source_commit")
    tree = value.get("validated_source_tree")
    run_id = value.get("workflow_run_id")
    if not isinstance(branch, str) or not branch.strip():
        raise PacketError(f"{label}.branch is missing")
    if not isinstance(commit, str) or HEX40.fullmatch(commit) is None:
        raise PacketError(f"{label}.validated_source_commit is invalid")
    if not isinstance(tree, str) or HEX40.fullmatch(tree) is None:
        raise PacketError(f"{label}.validated_source_tree is invalid")
    if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0:
        raise PacketError(f"{label}.workflow_run_id is invalid")
    return branch.strip(), commit, tree, run_id


def validate_environment_evidence(
    root: Path,
    value: Any,
    label: str,
    exit_level: str,
    source: dict[str, Any],
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise PacketError(f"{label}.evidence must be a non-empty list")
    expected_commit = source.get("commit")
    expected_tree = source.get("tree")
    if not isinstance(expected_commit, str) or HEX40.fullmatch(expected_commit) is None:
        raise PacketError(f"{label}.source_evidence.commit is invalid")
    if not isinstance(expected_tree, str) or HEX40.fullmatch(expected_tree) is None:
        raise PacketError(f"{label}.source_evidence.tree is invalid")
    observed: list[int] = []
    validated_bundles: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        item_label = f"{label}.evidence[{index}]"
        if not isinstance(item, dict):
            raise PacketError(f"{item_label} must be an object")
        level = item.get("level")
        if not isinstance(level, str) or level not in LEVELS:
            raise PacketError(f"{item_label}.level is invalid")
        observed.append(LEVELS[str(level)])
        source_commit = item.get("source_commit")
        if not isinstance(source_commit, str) or HEX40.fullmatch(source_commit) is None:
            raise PacketError(f"{item_label}.source_commit must be lowercase 40-hex")
        if source_commit != expected_commit:
            raise PacketError(
                f"{item_label}.source_commit does not match source_evidence"
            )
        source_tree = item.get("source_tree")
        if not isinstance(source_tree, str) or HEX40.fullmatch(source_tree) is None:
            raise PacketError(f"{item_label}.source_tree must be lowercase 40-hex")
        if source_tree != expected_tree:
            raise PacketError(
                f"{item_label}.source_tree does not match source_evidence"
            )
        has_bundle = isinstance(item.get("bundle_path"), str) and bool(
            item["bundle_path"].strip()
        )
        for field in (
            "source_lock_sha256",
            "tool_and_artifact_sha256",
            "raw_log_sha256",
            "evidence_sha256",
        ):
            digest = item.get(field)
            if has_bundle and field != "evidence_sha256" and digest is None:
                continue
            if not isinstance(digest, str) or HEX64.fullmatch(digest) is None:
                raise PacketError(
                    f"{item_label}.{field} must be lowercase 64-hex"
                )
        for field in (
            "target_or_device_identity",
            "command_or_operation_identity",
            "result_summary",
        ):
            if has_bundle and field not in item:
                continue
            field_value = item.get(field)
            valid_value = (
                isinstance(field_value, str) and bool(field_value.strip())
            ) or (isinstance(field_value, (dict, list)) and bool(field_value))
            if not valid_value:
                raise PacketError(
                    f"{item_label}.{field} must be a non-empty string, object or list"
                )
        if not isinstance(item.get("kind"), str) or not item["kind"].strip():
            raise PacketError(f"{item_label}.kind is missing")
        if not isinstance(item.get("reviewer"), str) or not item["reviewer"].strip():
            raise PacketError(f"{item_label}.reviewer is missing")
        if item.get("synthetic") is not False:
            raise PacketError(f"{item_label}.synthetic must be false")
        if item.get("automatic_redispatch") is not False:
            raise PacketError(f"{item_label}.automatic_redispatch must be false")
        if has_bundle:
            try:
                facts = validate_evidence_reference(
                    root,
                    gap_id=label,
                    exit_level=exit_level,
                    source_commit=expected_commit,
                    source_tree=expected_tree,
                    item=item,
                )
            except (EvidenceError, OSError) as error:
                raise PacketError(f"{item_label}: {error}") from error
            validated_bundles.append(facts)
    exit_rank = LEVELS.get(exit_level)
    if exit_rank is None:
        raise PacketError(f"{label} has invalid exit evidence level")
    if not any(rank >= exit_rank for rank in observed):
        raise PacketError(f"{label} has no evidence at or above {exit_level}")
    return validated_bundles


def validate_release_authorization_evidence(
    value: Any,
    label: str,
    bundle_facts: list[dict[str, Any]] | None = None,
) -> None:
    """Require explicit signed-manifest and human go fields for L6 release."""
    candidates = [
        item
        for item in value
        if isinstance(item, dict) and item.get("level") == "L6"
    ] if isinstance(value, list) else []
    if not candidates:
        raise PacketError(f"{label} release authorization requires an L6 evidence item")
    complete = False
    for index, evidence in enumerate(candidates):
        item_label = f"{label}.evidence[{index}]"
        if isinstance(evidence.get("bundle_path"), str) and bundle_facts:
            if any(
                isinstance(facts.get("release_authorizer"), str)
                and bool(facts["release_authorizer"].strip())
                for facts in bundle_facts
            ):
                complete = True
                continue
            raise PacketError(
                f"{item_label} reviewed L6 bundle lacks independent release authorization"
            )
        signature = evidence.get("release_signature")
        authorization = evidence.get("release_authorization")
        if not isinstance(signature, dict):
            raise PacketError(f"{item_label}.release_signature must be an object")
        if not isinstance(authorization, dict):
            raise PacketError(f"{item_label}.release_authorization must be an object")
        manifest_sha256 = signature.get("manifest_sha256")
        if not isinstance(manifest_sha256, str) or HEX64.fullmatch(manifest_sha256) is None:
            raise PacketError(
                f"{item_label}.release_signature.manifest_sha256 must be lowercase 64-hex"
            )
        for field in (
            "signature",
            "certificate_identity",
            "oidc_issuer",
            "oidc_subject",
            "transparency_log_entry",
        ):
            if not isinstance(signature.get(field), str) or not signature[field].strip():
                raise PacketError(f"{item_label}.release_signature.{field} is missing")
        if signature.get("cryptographic_signature_verified") is not True:
            raise PacketError(
                f"{item_label}.release_signature.cryptographic_signature_verified must be true"
            )
        if authorization.get("decision") != "GO":
            raise PacketError(f"{item_label}.release_authorization.decision must be GO")
        for field in ("authorization_id", "authorized_by"):
            if not isinstance(authorization.get(field), str) or not authorization[field].strip():
                raise PacketError(f"{item_label}.release_authorization.{field} is missing")
        approved_at = authorization.get("approved_at")
        timestamp_valid = False
        if isinstance(approved_at, str) and approved_at.strip():
            try:
                timestamp_valid = datetime.fromisoformat(
                    approved_at.replace("Z", "+00:00")
                ).tzinfo is not None
            except ValueError:
                timestamp_valid = False
        if not timestamp_valid:
            raise PacketError(
                f"{item_label}.release_authorization.approved_at must be an ISO-8601 timestamp with timezone"
            )
        complete = True
    if not complete:
        raise PacketError(
            f"{label} lacks a complete signed-manifest and human authorization record"
        )


def validate_checkout_identity(root: Path, identity: Identity) -> None:
    """Bind packet provenance to the checkout that produced it.

    The packet accepts explicit identity arguments because CI supplies the
    source branch and workflow metadata, but commit/tree must never be free
    claims.  Compare both values with Git and require a clean tracked tree
    before reading the canonical register.
    """
    root = root.resolve()
    observed_top = Path(run_git(root, "rev-parse", "--show-toplevel")).resolve()
    if observed_top != root:
        raise PacketError(
            "Git checkout top-level does not match packet root "
            f"({observed_top} != {root})"
        )
    observed_commit = run_git(root, "rev-parse", "HEAD")
    observed_tree = run_git(root, "rev-parse", "HEAD^{tree}")
    if run_git(root, "for-each-ref", "refs/replace", allow_empty=True):
        raise PacketError(
            "Git checkout contains replacement refs; refusing packet generation"
        )
    if identity.commit_sha != observed_commit:
        raise PacketError(
            "packet commit identity does not match checkout HEAD "
            f"({identity.commit_sha} != {observed_commit})"
        )
    if identity.tree_sha != observed_tree:
        raise PacketError(
            "packet tree identity does not match checkout HEAD^{tree} "
            f"({identity.tree_sha} != {observed_tree})"
        )
    tracked_status = run_git(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        allow_empty=True,
    )
    if tracked_status:
        raise PacketError(
            "tracked working tree is dirty before packet generation (including untracked files): "
            + tracked_status.replace("\n", "; ")
    )
    index_state = run_git(root, "ls-files", "-v", allow_empty=True)
    index_flags = [line[0] for line in index_state.splitlines() if line]
    if any(flag != "H" for flag in index_flags):
        raise PacketError(
            "Git index contains non-normal tracked-entry flags; refusing packet generation"
        )
    for relative in (GAPS, STATUS):
        path = root / relative
        try:
            metadata = path.lstat()
        except OSError as error:
            raise PacketError(
                f"canonical packet input must be a regular file: {relative}"
            ) from error
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise PacketError(
                f"canonical packet input must be a single-link regular file: {relative}"
            )
        resolved = path.resolve()
        try:
            resolved.relative_to(root)
        except ValueError as error:
            raise PacketError(f"canonical packet input escapes checkout: {relative}") from error
        expected_blob = run_git(root, "rev-parse", f"HEAD:{relative.as_posix()}")
        actual_blob = run_git(root, "hash-object", "--no-filters", "--", relative.as_posix())
        if actual_blob != expected_blob:
            raise PacketError(
                f"canonical packet input differs from checkout HEAD: {relative}"
            )


def source_head(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "branch": value["branch"],
        "commit": value["commit"],
        "tree": value["tree"],
        "workflow_run_id": value["workflow_run_id"],
        "successful_jobs": list(value["successful_jobs"]),
        "artifacts": [
            {
                "id": artifact["id"],
                "name": artifact["name"],
                "digest": artifact["digest"],
            }
            for artifact in value["artifacts"]
        ],
    }


def build_packet(root: Path, identity: Identity) -> dict[str, Any]:
    identity.validate()
    validate_checkout_identity(root, identity)
    gaps = read_object(root / GAPS)
    status = read_object(root / STATUS)
    status_candidate_identity = validate_optional_candidate_identity(
        status.get("current_candidate"), "status.current_candidate"
    )
    documentation_candidate_identity = validate_optional_candidate_identity(
        gaps.get("documentation_candidate"), "documentation_candidate"
    )

    if gaps.get("schema") != EXPECTED_GAP_SCHEMA:
        raise PacketError("gap schema is unsupported")
    if status.get("schema") != EXPECTED_STATUS_SCHEMA:
        raise PacketError("status schema is unsupported")
    if gaps.get("revision") != EXPECTED_REVISION:
        raise PacketError("gap revision is not active r6")
    if status.get("active_plan_revision") != EXPECTED_REVISION:
        raise PacketError("status active_plan_revision is not active r6")
    if status.get("active_plan_revision") != gaps.get("revision"):
        raise PacketError("status and gap revisions differ")
    if status.get("automatic_redispatch") is not False:
        raise PacketError("automatic_redispatch must remain false")
    if status.get("claim_ceiling") != EXPECTED_CLAIM_CEILING:
        raise PacketError("claim_ceiling must remain the exact-source ceiling")
    public_release = status.get("public_release")
    if not isinstance(public_release, bool):
        raise PacketError("public_release must be boolean")
    generated_policy = gaps.get("generated_policy")
    if not isinstance(generated_policy, dict):
        raise PacketError("gap generated_policy must be an object")
    for field, expected in REQUIRED_GENERATED_POLICY.items():
        if generated_policy.get(field) is not expected:
            raise PacketError(
                f"gap generated_policy {field} must be true (CI-generated exact-head evidence is required)"
            )
    if generated_policy.get("automatic_redispatch") is not False:
        raise PacketError("gap generated_policy automatic_redispatch must remain false")
    if generated_policy.get("public_release") is not public_release:
        raise PacketError("gap generated_policy public_release differs from status")

    entries = gaps.get("gaps")
    if not isinstance(entries, list) or not entries:
        raise PacketError("gaps must be a non-empty list")

    seen: set[str] = set()
    states_by_id: dict[str, str] = {}
    ordered: list[str] = []
    counts = {state: 0 for state in sorted(ALLOWED_STATES)}
    remaining: list[dict[str, Any]] = []
    source_heads: dict[tuple[str, str, int], dict[str, Any]] = {}
    source_bindings: list[tuple[str, tuple[Any, ...]]] = []
    required_material: set[str] = set()
    required_authority: set[str] = set()

    for index, raw in enumerate(entries):
        label = f"gaps[{index}]"
        if not isinstance(raw, dict):
            raise PacketError(f"{label} must be an object")
        identifier = raw.get("id")
        if not isinstance(identifier, str) or not identifier.strip():
            raise PacketError(f"{label}.id is missing")
        if identifier in seen:
            raise PacketError(f"duplicate gap id: {identifier}")
        seen.add(identifier)
        ordered.append(identifier)

        state = raw.get("status")
        if not isinstance(state, str) or state not in ALLOWED_STATES:
            raise PacketError(f"{identifier} has invalid state {state!r}")
        counts[str(state)] += 1
        states_by_id[identifier] = str(state)
        exit_level = raw.get("exit_evidence_level")
        if not isinstance(exit_level, str) or exit_level not in LEVELS:
            raise PacketError(f"{identifier} has invalid exit_evidence_level")
        external_required = requires_external_evidence(
            raw, str(exit_level), identifier
        )
        issues = issue_values(raw, identifier)
        validate_canonical_shape(raw, identifier, str(exit_level), issues)
        if not isinstance(raw.get("summary"), str) or not raw["summary"].strip():
            raise PacketError(f"{identifier}.summary is missing")
        if not nonempty_strings(raw.get("acceptance")):
            raise PacketError(f"{identifier}.acceptance is missing")

        source: dict[str, Any] | None = None
        if state == "OPEN":
            if "source_evidence" in raw or "evidence" in raw:
                raise PacketError(f"{identifier} OPEN state carries promotion evidence")
        elif state == "SOURCE_CLOSED_PENDING_EVIDENCE":
            source = validate_source_evidence(
                raw.get("source_evidence"), identifier, source_bindings
            )
            if LEVELS[str(exit_level)] < LEVELS["L2"]:
                raise PacketError(
                    f"{identifier} pending state requires an L2-L6 exit level"
                )
            if not nonempty_strings(raw.get("remaining_evidence")):
                raise PacketError(f"{identifier}.remaining_evidence is missing")
            if "evidence" in raw:
                raise PacketError(f"{identifier} pending state carries full evidence")
        elif state == "EXTERNAL_HOLD":
            if not external_required:
                raise PacketError(
                    f"{identifier} external hold must require external evidence"
                )
            materials = raw.get("required_material")
            authorities = raw.get("required_authority")
            if not nonempty_strings(materials) and not nonempty_strings(authorities):
                raise PacketError(
                    f"{identifier} external hold has no required material or authority"
                )
            if nonempty_strings(materials):
                required_material.update(str(item) for item in materials)
            if nonempty_strings(authorities):
                required_authority.update(str(item) for item in authorities)
            if "source_evidence" in raw:
                source = validate_source_evidence(
                    raw["source_evidence"], identifier, source_bindings
                )
            if "evidence" in raw:
                raise PacketError(f"{identifier} external hold carries full evidence")
        elif state == "CLOSED":
            source = validate_source_evidence(
                raw.get("source_evidence"), identifier, source_bindings
            )
            if external_required:
                bundle_facts = validate_environment_evidence(
                    root, raw.get("evidence"), identifier, str(exit_level), source
                )
                if identifier == "R5-GAP-RELEASE-001":
                    validate_release_authorization_evidence(
                        raw.get("evidence"), identifier, bundle_facts
                    )
            else:
                if exit_level != "L1":
                    raise PacketError(
                        f"{identifier} source-only closure is allowed only at L1"
                    )
                if raw.get("evidence") not in (None, []):
                    raise PacketError(
                        f"{identifier} source-only L1 closure carries external evidence"
                    )

        if source is not None:
            head = source_head(source)
            source_heads[(head["commit"], head["tree"], head["workflow_run_id"])] = head

        if state != "CLOSED":
            item: dict[str, Any] = {
                "id": identifier,
                "status": state,
                "exit_evidence_level": exit_level,
                "requires_external_evidence": external_required,
                "issues": issues,
                "summary": raw["summary"],
            }
            for field in (
                "remaining_evidence",
                "required_material",
                "required_authority",
            ):
                if nonempty_strings(raw.get(field)):
                    item[field] = list(raw[field])
            if source is not None:
                item["source_evidence"] = {
                    "commit": source["commit"],
                    "tree": source["tree"],
                    "workflow_run_id": source["workflow_run_id"],
                }
            remaining.append(item)

    if gaps.get("priority_order") != ordered:
        raise PacketError("priority_order must exactly match gaps order")

    if source_bindings:
        canonical_binding = source_bindings[0][1]
        for label, binding in source_bindings[1:]:
            if binding != canonical_binding:
                raise PacketError(
                    f"{label} source identity or artifact binding differs from the canonical source candidate"
                )

    # Optional status/documentation candidates are provenance anchors too.
    # Bind their four identity fields to the historical source evidence (or to
    # each other when the register is still entirely OPEN); never silently
    # ignore a checked-in candidate object.
    source_identity = (
        source_bindings[0][1][:4] if source_bindings else None
    )
    candidate_anchors = [
        ("status.current_candidate", status_candidate_identity),
        ("documentation_candidate", documentation_candidate_identity),
    ]
    candidate_anchors = [
        (label, value) for label, value in candidate_anchors if value is not None
    ]
    canonical_identity = source_identity
    if canonical_identity is None and candidate_anchors:
        canonical_identity = candidate_anchors[0][1]
    if canonical_identity is not None:
        for label, value in candidate_anchors:
            if value != canonical_identity:
                raise PacketError(
                    f"{label} source identity differs from the canonical source candidate"
                )
        development_branch = status.get("development_branch")
        if development_branch is not None and development_branch != canonical_identity[0]:
            raise PacketError(
                "status development_branch is not bound to the canonical source candidate"
            )

    missing_canonical = set(CANONICAL_GAP_SPECS) - seen
    unknown_canonical = seen - set(CANONICAL_GAP_SPECS)
    if missing_canonical:
        raise PacketError(
            "gap register is missing required canonical lanes: "
            + ", ".join(sorted(missing_canonical))
        )
    if unknown_canonical:
        raise PacketError(
            "gap register contains unknown canonical lanes: "
            + ", ".join(sorted(unknown_canonical))
        )
    if ordered != list(CANONICAL_GAP_ORDER):
        raise PacketError("priority_order must follow the canonical R6 lane order")
    if any(
        states_by_id.get(identifier)
        not in {"SOURCE_CLOSED_PENDING_EVIDENCE", "EXTERNAL_HOLD", "CLOSED"}
        for identifier in EXTERNAL_EVIDENCE_GAPS
    ):
        raise PacketError(
            "required external evidence lanes must remain pending, EXTERNAL_HOLD or CLOSED"
        )

    all_closed = all(item.get("status") == "CLOSED" for item in entries)
    zero_gap = status.get("zero_gap")
    if not isinstance(zero_gap, bool) or zero_gap is not all_closed:
        raise PacketError("zero_gap must be true exactly when every gap is CLOSED")
    release_closed = any(
        item.get("id") == "R5-GAP-RELEASE-001" and item.get("status") == "CLOSED"
        for item in entries
        if isinstance(item, dict)
    )
    if public_release is not (release_closed and all_closed):
        raise PacketError(
            "public_release requires a CLOSED release gap and zero-gap completion"
        )

    if all_closed:
        outcome = "MODULE_CLOSED_CANDIDATE"
    elif counts["OPEN"]:
        outcome = "SOURCE_WORK_REMAINING"
    else:
        outcome = "RESUME_REQUIRED"

    critical_path = status.get("critical_path_next", [])
    if not isinstance(critical_path, list) or not all(
        isinstance(item, str) and item.strip() for item in critical_path
    ):
        raise PacketError("critical_path_next must be a string list")
    negative_claims = status.get("not_claimed", [])
    if not isinstance(negative_claims, list) or not all(
        isinstance(item, str) and item.strip() for item in negative_claims
    ):
        raise PacketError("not_claimed must be a string list")

    return {
        "schema": PACKET_SCHEMA,
        "plan_revision": EXPECTED_REVISION,
        "kind": "exact_head_resume_status_not_promotion_evidence",
        "outcome": outcome,
        "repository": identity.repository,
        "branch": identity.branch,
        "commit_sha": identity.commit_sha,
        "tree_sha": identity.tree_sha,
        "workflow_run_id": identity.workflow_run_id,
        "workflow_run_attempt": identity.workflow_run_attempt,
        "state_counts": counts,
        "gap_count": len(entries),
        "remaining_gap_count": len(remaining),
        "remaining_gaps": remaining,
        "source_evidence_heads": sorted(
            source_heads.values(),
            key=lambda item: (
                item["commit"],
                item["tree"],
                item["workflow_run_id"],
            ),
        ),
        "required_material": sorted(required_material),
        "required_authority": sorted(required_authority),
        "critical_path_next": list(critical_path),
        "claim_ceiling": status.get("claim_ceiling"),
        "negative_claims": list(negative_claims),
        "invariants": {
            "zero_gap": zero_gap,
            "all_gaps_closed": all_closed,
            "public_release": public_release,
            "release_gap_closed": release_closed,
            "automatic_redispatch": False,
            "packet_promotes_gap_state": False,
            "packet_is_environment_evidence": False,
            "packet_is_release_authorization": False,
        },
        "next_action": (
            "independent closeout review and canonical promotion"
            if outcome == "MODULE_CLOSED_CANDIDATE"
            else "execute the listed target/material/authority lanes and import exact reviewed evidence"
        ),
    }


def run_git(root: Path, *args: str, allow_empty: bool = False) -> str:
    try:
        clean_env = {
            key: value for key, value in os.environ.items() if not key.startswith("GIT_")
        }
        completed = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(root.resolve()), *args],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            env=clean_env,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PacketError(f"cannot resolve Git identity: {error}") from error
    value = completed.stdout.strip()
    if not value and not allow_empty:
        raise PacketError(f"git {' '.join(args)} returned an empty value")
    return value


def write_output(root: Path, requested: Path, raw: str) -> Path:
    """Atomically write a packet beneath the checkout without following links."""
    root = root.resolve()
    output = requested if requested.is_absolute() else root / requested
    output = output.absolute()
    try:
        output.relative_to(root)
    except ValueError as error:
        raise PacketError("packet output must remain inside the checkout") from error
    output.parent.mkdir(parents=True, exist_ok=True)
    parent = output.parent.resolve()
    try:
        parent.relative_to(root)
    except ValueError as error:
        raise PacketError("packet output parent escapes the checkout") from error
    if output.parent.is_symlink() or output.is_symlink():
        raise PacketError("packet output path must not be a symbolic link")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".owner-open-r5-resume-", dir=str(parent), text=True
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    except OSError as error:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise PacketError(f"cannot write packet output: {error}") from error
    return output


def positive_int(value: str | None, label: str) -> int:
    try:
        result = int(value or "")
    except ValueError as error:
        raise PacketError(f"{label} must be positive") from error
    if result <= 0:
        raise PacketError(f"{label} must be positive")
    return result


def resolve_identity(args: argparse.Namespace, root: Path) -> Identity:
    repository = args.repository or os.environ.get("GITHUB_REPOSITORY", "")
    branch = (
        args.branch
        or os.environ.get("GITHUB_HEAD_REF")
        or os.environ.get("GITHUB_REF_NAME")
        or run_git(root, "branch", "--show-current")
    )
    commit = args.commit or os.environ.get("GITHUB_SHA") or run_git(root, "rev-parse", "HEAD")
    tree = args.tree or run_git(root, "rev-parse", "HEAD^{tree}")
    run_id = positive_int(
        str(args.workflow_run_id) if args.workflow_run_id is not None else os.environ.get("GITHUB_RUN_ID"),
        "workflow_run_id",
    )
    attempt = positive_int(
        str(args.workflow_run_attempt)
        if args.workflow_run_attempt is not None
        else os.environ.get("GITHUB_RUN_ATTEMPT"),
        "workflow_run_attempt",
    )
    return Identity(
        repository=repository,
        branch=branch,
        commit_sha=commit,
        tree_sha=tree,
        workflow_run_id=run_id,
        workflow_run_attempt=attempt,
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--repository")
    parser.add_argument("--branch")
    parser.add_argument("--commit")
    parser.add_argument("--tree")
    parser.add_argument("--workflow-run-id", type=int)
    parser.add_argument("--workflow-run-attempt", type=int)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    try:
        identity = resolve_identity(args, root)
        packet = build_packet(root, identity)
    except PacketError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    raw = json.dumps(packet, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        write_output(root, args.output, raw)
    if args.json or args.output is None:
        print(raw, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
