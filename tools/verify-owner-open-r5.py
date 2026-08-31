#!/usr/bin/env python3
"""Verify the owner-open R5 graph, active plan, status and zero-gap register.

The Cargo/Android graph contract retains revision ``2026-08-28-r5`` for
compatibility. The active implementation and gap-closure plan is revision
``2026-08-29-r6``. This verifier keeps those identities distinct and never
promotes source presence to installed, image, physical, fault or release
evidence.
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
import tomllib
from typing import Any

CONTRACT = Path("docs/contracts/owner-open-forbidden-default-graph-v2.json")
PLAN = Path("docs/TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md")
STATUS = Path("docs/status/owner-open-r5-status.json")
TRACEABILITY = Path("docs/status/owner-open-r5-traceability.tsv")
GAP_REGISTER = Path("docs/status/owner-open-r5-gap-closure.json")

GRAPH_REVISION = "2026-08-28-r5"
ACTIVE_PLAN_REVISION = "2026-08-29-r6"
GAP_SCHEMA = "org.trillionnium.owner-open-r5.gap-closure.v1"
STATUS_SCHEMA = "org.trillionnium.owner-open-r5-status.v2"
STATUS_LEVELS = {
    "NOT_STARTED",
    "SPEC_ONLY",
    "SOURCE_IMPLEMENTED",
    "HOST_TESTED",
    "IMAGE_INCLUDED",
    "DEVICE_OBSERVED",
    "FAULT_TESTED",
    "RELEASE_QUALIFIED",
}
EVIDENCE_LEVELS = {f"L{index}" for index in range(7)}
GAP_STATES = {
    "OPEN",
    "SOURCE_CLOSED_PENDING_EVIDENCE",
    "EXTERNAL_HOLD",
    "CLOSED",
}
# Immutable R6 identity/issue/level/evidence contract.  The checked-in flag
# documents the decision but cannot rewrite the canonical lane semantics.
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
EXTERNAL_GAPS = {
    "R5-GAP-GOVERNANCE-001",
    "R5-GAP-INSTALLED-CODEX-001",
    "R5-GAP-ROOTLINUX-PLACEMENT-001",
    "R5-GAP-ANDROID-GRAPH-001",
    "R5-GAP-PHYSICAL-ADB-001",
    "R5-GAP-FAULT-MATRIX-001",
    "R5-GAP-RELEASE-001",
}
CANONICAL_GAP_ORDER = tuple(CANONICAL_GAP_SPECS)
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ARTIFACT_SHA_SUFFIX = re.compile(r"-([0-9a-f]{40})$")
EXPECTED_CLAIM_CEILING = "EXACT_COMMIT_SOURCE_GATES_PASSED_NOT_INSTALLED_CODEX"
SourceIdentity = tuple[str, str, str, int]
ArtifactBinding = tuple[tuple[int, str, str], ...]
REQUIRED_R6_DOCS = (
    Path("docs/OWNER_OPEN_R5_START_HERE.md"),
    Path("docs/architecture/2026-08-29-owner-open-runtime-authority-and-process-topology.md"),
    Path("docs/protocols/owner-open-effect-state-machine-v1.md"),
    Path("docs/operations/owner-open-deployment-lifecycle-and-emergency-stop.md"),
    Path("docs/qualification/owner-open-evidence-promotion-and-fault-matrix.md"),
)


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.facts: dict[str, Any] = {}

    def check(self, condition: bool, message: str) -> None:
        if not condition:
            self.errors.append(message)

    def warn(self, message: str) -> None:
        self.warnings.append(message)


def read_json(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"{path} must be a single-link regular file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def read_toml(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"{path} must be a single-link regular file")
    with path.open("rb") as handle:
        return tomllib.load(handle)


def dependency_names(manifest: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        value = manifest.get(section, {})
        if isinstance(value, dict):
            result.update(str(item) for item in value)
    target = manifest.get("target", {})
    if isinstance(target, dict):
        for config in target.values():
            if not isinstance(config, dict):
                continue
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                value = config.get(section, {})
                if isinstance(value, dict):
                    result.update(str(item) for item in value)
    return result


def _positive_issue_values(item: dict[str, Any]) -> list[int]:
    result: list[int] = []
    issue = item.get("issue")
    if isinstance(issue, int) and not isinstance(issue, bool):
        result.append(issue)
    issues = item.get("issues")
    if isinstance(issues, list):
        result.extend(
            value
            for value in issues
            if isinstance(value, int) and not isinstance(value, bool)
        )
    return result


def _source_identity_from_fields(
    value: dict[str, Any],
    label: str,
    report: Report,
    *,
    commit_field: str,
    tree_field: str,
    run_field: str,
) -> SourceIdentity | None:
    branch = value.get("branch")
    commit = value.get(commit_field)
    tree = value.get(tree_field)
    run_id = value.get(run_field)
    branch_valid = isinstance(branch, str) and bool(branch.strip())
    commit_valid = isinstance(commit, str) and HEX40.fullmatch(commit) is not None
    tree_valid = isinstance(tree, str) and HEX40.fullmatch(tree) is not None
    run_valid = (
        isinstance(run_id, int)
        and not isinstance(run_id, bool)
        and run_id > 0
    )
    report.check(branch_valid, f"R5 source evidence branch is missing: {label}")
    report.check(
        commit_valid,
        f"R5 source evidence {commit_field} is invalid: {label}",
    )
    report.check(
        tree_valid,
        f"R5 source evidence {tree_field} is invalid: {label}",
    )
    report.check(
        run_valid,
        f"R5 source evidence {run_field} is invalid: {label}",
    )
    if not (branch_valid and commit_valid and tree_valid and run_valid):
        return None
    return (branch.strip(), commit, tree, run_id)


def _source_evidence(
    value: Any,
    identifier: str,
    report: Report,
    artifact_bindings: list[tuple[str, ArtifactBinding]] | None = None,
) -> SourceIdentity | None:
    """Check the exact L1 source-evidence shape used by promotion gates."""
    report.check(
        isinstance(value, dict),
        f"R5 source evidence must be an object: {identifier}",
    )
    if not isinstance(value, dict):
        return None
    report.check(
        value.get("level") == "L1",
        f"R5 source evidence level must be L1: {identifier}",
    )
    identity = _source_identity_from_fields(
        value,
        identifier,
        report,
        commit_field="commit",
        tree_field="tree",
        run_field="workflow_run_id",
    )
    jobs = value.get("successful_jobs")
    report.check(
        isinstance(jobs, list)
        and bool(jobs)
        and all(isinstance(job, str) and bool(job.strip()) for job in jobs),
        f"R5 source evidence successful_jobs is invalid: {identifier}",
    )
    artifacts = value.get("artifacts")
    report.check(
        isinstance(artifacts, list) and bool(artifacts),
        f"R5 source evidence artifacts are missing: {identifier}",
    )
    if not isinstance(artifacts, list):
        return identity
    normalized: list[tuple[int, str, str]] = []
    artifact_ids: set[int] = set()
    artifacts_valid = True
    for index, artifact in enumerate(artifacts):
        label = f"{identifier} source_evidence.artifacts[{index}]"
        report.check(isinstance(artifact, dict), f"{label} must be an object")
        if not isinstance(artifact, dict):
            artifacts_valid = False
            continue
        artifact_id = artifact.get("id")
        id_valid = (
            isinstance(artifact_id, int)
            and not isinstance(artifact_id, bool)
            and artifact_id > 0
        )
        report.check(id_valid, f"{label}.id must be positive")
        if not id_valid:
            artifacts_valid = False
        elif artifact_id in artifact_ids:
            report.check(False, f"{label}.id is duplicated")
            artifacts_valid = False
        else:
            artifact_ids.add(artifact_id)
        report.check(
            isinstance(artifact.get("name"), str)
            and bool(artifact["name"].strip()),
            f"{label}.name is missing",
        )
        name = artifact.get("name")
        name_valid = isinstance(name, str) and bool(name.strip())
        if not name_valid:
            artifacts_valid = False
        digest = artifact.get("digest")
        digest_valid = (
            isinstance(digest, str)
            and digest.startswith("sha256:")
            and HEX64.fullmatch(digest.removeprefix("sha256:")) is not None
        )
        report.check(digest_valid, f"{label}.digest is invalid")
        if not digest_valid:
            artifacts_valid = False
        if name_valid:
            suffix = ARTIFACT_SHA_SUFFIX.search(name.strip())
            if suffix is not None:
                report.check(
                    identity is None or suffix.group(1) == identity[1],
                    f"{label}.name is bound to a different source commit",
                )
                if identity is not None and suffix.group(1) != identity[1]:
                    artifacts_valid = False
        if id_valid and name_valid and digest_valid:
            normalized.append((artifact_id, name.strip(), digest))
    if artifacts_valid and artifact_bindings is not None:
        binding = tuple(sorted(normalized))
        report.check(
            len(binding) == len(set(binding)),
            f"{identifier} source artifact binding contains duplicates",
        )
        if len(binding) == len(set(binding)):
            artifact_bindings.append((identifier, binding))
    return identity


def _status_candidate_identity(
    status: dict[str, Any], report: Report
) -> SourceIdentity | None:
    candidate = status.get("current_candidate")
    if candidate is None:
        return None
    label = "status.current_candidate"
    report.check(isinstance(candidate, dict), f"{label} must be an object")
    if not isinstance(candidate, dict):
        return None
    return _source_identity_from_fields(
        candidate,
        label,
        report,
        commit_field="validated_source_commit",
        tree_field="validated_source_tree",
        run_field="workflow_run_id",
    )


def _documentation_candidate_identity(
    gap: dict[str, Any], report: Report
) -> SourceIdentity | None:
    candidate = gap.get("documentation_candidate")
    if candidate is None:
        return None
    label = "documentation_candidate"
    report.check(isinstance(candidate, dict), f"{label} must be an object")
    if not isinstance(candidate, dict):
        return None
    return _source_identity_from_fields(
        candidate,
        label,
        report,
        commit_field="validated_source_commit",
        tree_field="validated_source_tree",
        run_field="workflow_run_id",
    )


def _expected_source_pair(
    expected_commit: str | None,
    expected_tree: str | None,
    report: Report,
) -> tuple[str, str] | None:
    if expected_commit is None and expected_tree is None:
        return None
    commit_valid = (
        isinstance(expected_commit, str)
        and HEX40.fullmatch(expected_commit) is not None
    )
    tree_valid = (
        isinstance(expected_tree, str)
        and HEX40.fullmatch(expected_tree) is not None
    )
    report.check(
        commit_valid and tree_valid,
        "expected exact source head requires lowercase 40-hex commit and tree",
    )
    if not (commit_valid and tree_valid):
        return None
    return expected_commit, expected_tree


def _check_checkout_against_expected(
    root: Path,
    expected_commit: str | None,
    expected_tree: str | None,
    report: Report,
) -> None:
    """When an exact head is requested, derive it from Git, never the caller."""
    expected = _expected_source_pair(expected_commit, expected_tree, report)
    if expected is None:
        return
    clean_env = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    checkout = str(root.resolve())
    try:
        observed_top = subprocess.run(
            ["git", "--no-replace-objects", "-C", checkout, "rev-parse", "--show-toplevel"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            env=clean_env,
        ).stdout.strip()
        observed_commit = subprocess.run(
            ["git", "--no-replace-objects", "-C", checkout, "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            env=clean_env,
        ).stdout.strip()
        observed_tree = subprocess.run(
            ["git", "--no-replace-objects", "-C", checkout, "rev-parse", "HEAD^{tree}"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            env=clean_env,
        ).stdout.strip()
        replace_refs = subprocess.run(
            ["git", "--no-replace-objects", "-C", checkout, "for-each-ref", "refs/replace"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            env=clean_env,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as error:
        report.errors.append(f"cannot resolve checkout exact source head: {error}")
        return
    report.check(
        Path(observed_top).resolve() == root.resolve(),
        "checkout Git top-level differs from the verifier root",
    )
    report.check(
        not replace_refs,
        "checkout contains Git replacement refs; refusing exact source verification",
    )
    try:
        working_tree = subprocess.run(
            [
                "git",
                "--no-replace-objects",
                "-C",
                checkout,
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            env=clean_env,
        ).stdout.strip()
        index_state = subprocess.run(
            ["git", "--no-replace-objects", "-C", checkout, "ls-files", "-v"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            env=clean_env,
        ).stdout
        blob_pairs: list[tuple[str, str, str]] = []
        for relative in (GAP_REGISTER, STATUS):
            path = root / relative
            regular = path.is_file() and not path.is_symlink()
            report.check(regular, f"canonical R5 input is not a regular file: {relative}")
            if not regular:
                continue
            expected_blob = subprocess.run(
                [
                    "git",
                    "--no-replace-objects",
                    "-C",
                    checkout,
                    "rev-parse",
                    f"HEAD:{relative.as_posix()}",
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                env=clean_env,
            ).stdout.strip()
            actual_blob = subprocess.run(
                [
                    "git",
                    "--no-replace-objects",
                    "-C",
                    checkout,
                    "hash-object",
                    "--no-filters",
                    "--",
                    relative.as_posix(),
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                env=clean_env,
            ).stdout.strip()
            blob_pairs.append((relative.as_posix(), expected_blob, actual_blob))
    except (OSError, subprocess.SubprocessError) as error:
        report.errors.append(f"cannot verify checkout exact source files: {error}")
        return
    report.check(
        not working_tree,
        "checkout working tree is dirty; refusing exact source verification",
    )
    report.check(
        observed_commit == expected[0],
        "checkout HEAD differs from the expected exact source head",
    )
    report.check(
        observed_tree == expected[1],
        "checkout tree differs from the expected exact source head",
    )
    report.check(
        all(line[:1] == "H" for line in index_state.splitlines() if line),
        "checkout Git index contains non-normal tracked-entry flags",
    )
    for relative, expected_blob, actual_blob in blob_pairs:
        report.check(
            actual_blob == expected_blob,
            f"canonical R5 input differs from checkout HEAD: {relative}",
        )


def _bind_source_identities(
    gap: dict[str, Any],
    status: dict[str, Any],
    identities: list[tuple[str, SourceIdentity]],
    *,
    artifact_bindings: list[tuple[str, ArtifactBinding]] | None = None,
    expected_commit: str | None,
    expected_tree: str | None,
    report: Report,
) -> SourceIdentity | None:
    status_identity = _status_candidate_identity(status, report)
    documentation_identity = _documentation_candidate_identity(gap, report)
    anchors: list[tuple[str, SourceIdentity]] = []
    if status_identity is not None:
        anchors.append(("status.current_candidate", status_identity))
    if documentation_identity is not None:
        anchors.append(("documentation_candidate", documentation_identity))
    anchors.extend(identities)
    canonical: SourceIdentity | None = anchors[0][1] if anchors else None
    if canonical is not None:
        for label, identity in anchors[1:]:
            report.check(
                identity == canonical,
                f"{label} source identity differs from the canonical source candidate",
            )
    if status_identity is not None:
        for label, identity in anchors:
            if label == "status.current_candidate":
                continue
            report.check(
                identity == status_identity,
                f"status.current_candidate source identity differs from {label}",
            )
    # ``expected_*`` authenticates the checkout itself in
    # ``_check_checkout_against_expected``.  Checked-in source records may be
    # historical CI candidates, so do not force them to equal a newer
    # checkout head; their internal cross-record binding remains authoritative.
    if artifact_bindings:
        canonical_artifacts = artifact_bindings[0][1]
        for label, artifacts in artifact_bindings[1:]:
            report.check(
                artifacts == canonical_artifacts,
                f"{label} artifact binding differs from the canonical source candidate",
            )
    if canonical is not None:
        report.facts["source_candidate"] = {
            "branch": canonical[0],
            "commit": canonical[1],
            "tree": canonical[2],
            "workflow_run_id": canonical[3],
        }
    return canonical


def _validate_canonical_shape(
    item: dict[str, Any], identifier: str, level: str, issues: list[int], report: Report
) -> None:
    spec = CANONICAL_GAP_SPECS.get(identifier)
    if spec is None:
        return
    expected_issues, expected_level, expected_external = spec
    report.check(
        level == expected_level,
        f"R5 canonical exit evidence level drifted: {identifier}",
    )
    report.check(
        sorted(issues) == sorted(expected_issues),
        f"R5 canonical issue binding drifted: {identifier}",
    )
    report.check(
        item.get("requires_external_evidence") is expected_external,
        f"R5 canonical external-evidence flag drifted: {identifier}",
    )


def _requires_external_evidence(
    item: dict[str, Any],
    level: str,
    identifier: str,
    report: Report,
) -> bool:
    """Resolve the evidence class without trusting a mutable opt-out flag."""
    value = item.get("requires_external_evidence")
    report.check(
        value is None or isinstance(value, bool),
        f"R5 gap requires_external_evidence is not boolean: {identifier}",
    )
    if identifier in EXTERNAL_GAPS:
        report.check(
            value is True,
            f"R5 external gap requires_external_evidence must be true: {identifier}",
        )
        return True
    if level in {"L2", "L3", "L4", "L5", "L6"}:
        report.check(
            value is not False,
            f"R5 higher-level gap cannot disable external evidence: {identifier}",
        )
        return True
    if isinstance(value, bool):
        return value
    return False


def _nonempty_evidence_value(value: Any) -> bool:
    """Return whether an evidence identity/summary has useful content.

    The runbook permits these fields to be either a string or a structured
    JSON object/list.  Scalars other than strings are deliberately rejected so
    that ``true``/``1`` cannot stand in for an auditable identity or result.
    """
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (dict, list)):
        return bool(value)
    return False


def _validate_environment_contract(
    evidence: dict[str, Any], label: str, report: Report
) -> None:
    """Validate every field required by runbook section 2.

    This is intentionally a strict shape check.  The actual target/tool
    semantics are supplied by the evidence producer and reviewer, while the
    promotion gate must at least guarantee that each claim is bound to a
    source tree, lock/tool/log hashes and a concrete operation/result.
    """
    source_tree = evidence.get("source_tree")
    report.check(
        isinstance(source_tree, str) and HEX40.fullmatch(source_tree) is not None,
        f"{label}.source_tree must be lowercase 40-hex",
    )
    for field in (
        "source_lock_sha256",
        "tool_and_artifact_sha256",
        "raw_log_sha256",
        "evidence_sha256",
    ):
        value = evidence.get(field)
        report.check(
            isinstance(value, str) and HEX64.fullmatch(value) is not None,
            f"{label}.{field} must be lowercase 64-hex",
        )
    for field in (
        "target_or_device_identity",
        "command_or_operation_identity",
        "result_summary",
    ):
        report.check(
            _nonempty_evidence_value(evidence.get(field)),
            f"{label}.{field} must be a non-empty string, object or list",
        )
    report.check(
        isinstance(evidence.get("kind"), str) and bool(evidence["kind"].strip()),
        f"{label}.kind is missing",
    )
    report.check(
        isinstance(evidence.get("reviewer"), str)
        and bool(evidence["reviewer"].strip()),
        f"{label}.reviewer is missing",
    )
    report.check(
        evidence.get("synthetic") is False,
        f"{label} must explicitly declare synthetic=false",
    )
    report.check(
        evidence.get("automatic_redispatch") is False,
        f"{label} must explicitly declare automatic_redispatch=false",
    )


def _environment_evidence(
    value: Any,
    identifier: str,
    exit_level: str,
    report: Report,
    source_identity: SourceIdentity | None = None,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
) -> None:
    """Check the minimum non-synthetic evidence shape used by gap promotion."""
    if not isinstance(exit_level, str) or exit_level not in EVIDENCE_LEVELS:
        report.check(False, f"{identifier} has invalid exit evidence level")
        return
    report.check(
        isinstance(value, list) and bool(value),
        f"closed R5 gap has no evidence: {identifier}",
    )
    if not isinstance(value, list):
        return
    observed: list[int] = []
    for index, evidence in enumerate(value):
        label = f"{identifier} evidence[{index}]"
        report.check(isinstance(evidence, dict), f"{label} must be an object")
        if not isinstance(evidence, dict):
            continue
        level = evidence.get("level")
        valid_level = isinstance(level, str) and level in EVIDENCE_LEVELS
        report.check(valid_level, f"{label}.level is invalid")
        if valid_level:
            observed.append(int(str(level)[1:]))
        source_commit = evidence.get("source_commit")
        source_commit_valid = (
            isinstance(source_commit, str)
            and HEX40.fullmatch(source_commit) is not None
        )
        report.check(
            source_commit_valid,
            f"{label}.source_commit must be lowercase 40-hex",
        )
        if source_commit_valid and source_identity is not None:
            report.check(
                source_commit == source_identity[1],
                f"{label}.source_commit does not match the canonical source candidate",
            )
        elif source_commit_valid and expected_commit is not None:
            report.check(
                source_commit == expected_commit,
                f"{label}.source_commit does not match the expected exact source head",
            )
        _validate_environment_contract(evidence, label, report)
        source_tree = evidence.get("source_tree")
        source_tree_valid = (
            isinstance(source_tree, str) and HEX40.fullmatch(source_tree) is not None
        )
        if source_tree_valid and source_identity is not None:
            report.check(
                source_tree == source_identity[2],
                f"{label}.source_tree does not match the canonical source candidate",
            )
        elif source_tree_valid and expected_tree is not None:
            report.check(
                source_tree == expected_tree,
                f"{label}.source_tree does not match the expected exact source head",
            )
    report.check(
        any(rank >= int(exit_level[1:]) for rank in observed),
        f"{identifier} has no evidence at or above exit level {exit_level}",
    )


def _release_authorization_evidence(
    value: Any, identifier: str, report: Report
) -> None:
    """Require an explicit signed-manifest and human go record for L6."""
    candidates = [
        item
        for item in value
        if isinstance(item, dict) and item.get("level") == "L6"
    ] if isinstance(value, list) else []
    report.check(
        bool(candidates),
        f"{identifier} release authorization requires an L6 evidence item",
    )
    complete = False
    for index, evidence in enumerate(candidates):
        label = f"{identifier} evidence[{index}]"
        signature = evidence.get("release_signature")
        authorization = evidence.get("release_authorization")
        report.check(
            isinstance(signature, dict),
            f"{label}.release_signature must be an object",
        )
        report.check(
            isinstance(authorization, dict),
            f"{label}.release_authorization must be an object",
        )
        if not isinstance(signature, dict) or not isinstance(authorization, dict):
            continue
        manifest_sha256 = signature.get("manifest_sha256")
        report.check(
            isinstance(manifest_sha256, str)
            and HEX64.fullmatch(manifest_sha256) is not None,
            f"{label}.release_signature.manifest_sha256 must be lowercase 64-hex",
        )
        signature_fields_valid = True
        for field in (
            "signature",
            "certificate_identity",
            "oidc_issuer",
            "oidc_subject",
            "transparency_log_entry",
        ):
            field_valid = isinstance(signature.get(field), str) and bool(
                signature[field].strip()
            )
            signature_fields_valid = signature_fields_valid and field_valid
            report.check(field_valid, f"{label}.release_signature.{field} is missing")
        cryptographic_verified = (
            signature.get("cryptographic_signature_verified") is True
        )
        report.check(
            cryptographic_verified,
            f"{label}.release_signature.cryptographic_signature_verified must be true",
        )
        decision_valid = authorization.get("decision") == "GO"
        report.check(
            decision_valid,
            f"{label}.release_authorization.decision must be GO",
        )
        auth_fields_valid = True
        for field in ("authorization_id", "authorized_by"):
            field_valid = isinstance(authorization.get(field), str) and bool(
                authorization[field].strip()
            )
            auth_fields_valid = auth_fields_valid and field_valid
            report.check(
                field_valid,
                f"{label}.release_authorization.{field} is missing",
            )
        approved_at = authorization.get("approved_at")
        timestamp_valid = False
        if isinstance(approved_at, str) and approved_at.strip():
            try:
                timestamp_valid = datetime.fromisoformat(
                    approved_at.replace("Z", "+00:00")
                ).tzinfo is not None
            except ValueError:
                timestamp_valid = False
        report.check(
            timestamp_valid,
            f"{label}.release_authorization.approved_at must be an ISO-8601 timestamp with timezone",
        )
        complete = complete or (
            isinstance(manifest_sha256, str)
            and HEX64.fullmatch(manifest_sha256) is not None
            and signature_fields_valid
            and cryptographic_verified
            and decision_valid
            and auth_fields_valid
            and timestamp_valid
        )
    report.check(
        complete,
        f"{identifier} lacks a complete signed-manifest and human authorization record",
    )


def verify_gap_register(
    root: Path,
    gap: dict[str, Any],
    status: dict[str, Any],
    plan_text: str,
    report: Report,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
) -> None:
    report.check(gap.get("schema") == GAP_SCHEMA, "R5 gap-register schema is invalid")
    report.check(status.get("schema") == STATUS_SCHEMA, "R5 status schema is invalid")
    report.check(
        gap.get("revision") == ACTIVE_PLAN_REVISION,
        f"R5 active gap revision must be {ACTIVE_PLAN_REVISION}",
    )
    report.check(
        status.get("active_plan_revision") == gap.get("revision"),
        "R5 status active plan revision does not match the gap register",
    )
    report.check(
        str(gap.get("revision")) in plan_text,
        "R5 execution plan does not contain the active gap revision",
    )
    report.check(
        "zero_gap=true" in plan_text and "automatic" in plan_text.lower(),
        "R5 plan is missing the zero-gap/no-automatic-redispatch closure rule",
    )

    for path in REQUIRED_R6_DOCS:
        report.check((root / path).is_file(), f"required R6 document is absent: {path}")

    raw_gaps = gap.get("gaps")
    report.check(isinstance(raw_gaps, list) and bool(raw_gaps), "R5 gap list is absent or empty")
    if not isinstance(raw_gaps, list):
        return

    seen: set[str] = set()
    closed: set[str] = set()
    states_by_id: dict[str, str] = {}
    facts: list[dict[str, Any]] = []
    source_identities: list[tuple[str, SourceIdentity]] = []
    artifact_bindings: list[tuple[str, ArtifactBinding]] = []
    deferred_environment: list[
        tuple[str, Any, str, SourceIdentity | None]
    ] = []
    for item in raw_gaps:
        if not isinstance(item, dict):
            report.errors.append("R5 gap entry is not an object")
            continue
        identifier = str(item.get("id", ""))
        report.check(
            bool(identifier) and identifier not in seen,
            f"duplicate or empty R5 gap id: {identifier}",
        )
        seen.add(identifier)
        state = str(item.get("status", ""))
        report.check(state in GAP_STATES, f"invalid R5 gap state for {identifier}: {state}")
        states_by_id[identifier] = state
        level = str(item.get("exit_evidence_level", ""))
        report.check(level in EVIDENCE_LEVELS, f"invalid exit evidence level for {identifier}")
        external_required = _requires_external_evidence(
            item, level, identifier, report
        )
        issues = _positive_issue_values(item)
        report.check(bool(issues) and all(value > 0 for value in issues), f"R5 gap has no valid issue: {identifier}")
        _validate_canonical_shape(item, identifier, level, issues, report)
        summary = item.get("summary")
        report.check(isinstance(summary, str) and bool(summary.strip()), f"R5 gap summary is absent: {identifier}")
        acceptance = item.get("acceptance")
        report.check(
            isinstance(acceptance, list)
            and bool(acceptance)
            and all(isinstance(value, str) and bool(value.strip()) for value in acceptance),
            f"R5 gap acceptance is absent or malformed: {identifier}",
        )
        report.check(identifier in plan_text, f"R5 plan does not reference gap {identifier}")
        if state == "OPEN":
            report.check(
                "source_evidence" not in item and "evidence" not in item,
                f"open R5 gap carries promotion evidence: {identifier}",
            )
        elif state == "SOURCE_CLOSED_PENDING_EVIDENCE":
            source_identity = _source_evidence(
                item.get("source_evidence"),
                identifier,
                report,
                artifact_bindings,
            )
            if source_identity is not None:
                source_identities.append((identifier, source_identity))
            report.check(
                level in {"L2", "L3", "L4", "L5", "L6"},
                f"pending R5 gap must have an L2-L6 exit: {identifier}",
            )
            remaining = item.get("remaining_evidence")
            report.check(
                isinstance(remaining, list)
                and bool(remaining)
                and all(isinstance(value, str) and value.strip() for value in remaining),
                f"pending R5 gap has no remaining evidence list: {identifier}",
            )
            report.check(
                "evidence" not in item,
                f"pending R5 gap carries full evidence: {identifier}",
            )
        elif state == "EXTERNAL_HOLD":
            materials = item.get("required_material")
            authorities = item.get("required_authority")
            report.check(
                (
                    isinstance(materials, list)
                    and bool(materials)
                    and all(isinstance(value, str) and value.strip() for value in materials)
                )
                or (
                    isinstance(authorities, list)
                    and bool(authorities)
                    and all(isinstance(value, str) and value.strip() for value in authorities)
                ),
                f"external-hold R5 gap has no required material or authority: {identifier}",
            )
            report.check(
                "evidence" not in item,
                f"external-hold R5 gap carries full evidence: {identifier}",
            )
            if "source_evidence" in item:
                source_identity = _source_evidence(
                    item.get("source_evidence"),
                    identifier,
                    report,
                    artifact_bindings,
                )
                if source_identity is not None:
                    source_identities.append((identifier, source_identity))
        if state == "CLOSED":
            closed.add(identifier)
            source_identity = _source_evidence(
                item.get("source_evidence"),
                identifier,
                report,
                artifact_bindings,
            )
            if source_identity is not None:
                source_identities.append((identifier, source_identity))
            if external_required:
                deferred_environment.append(
                    (identifier, item.get("evidence"), level, source_identity)
                )
            else:
                report.check(
                    level == "L1",
                    f"source-only R5 gap must exit at L1: {identifier}",
                )
                report.check(
                    item.get("evidence") in (None, []),
                    f"source-only L1 R5 gap carries external evidence: {identifier}",
                )
        if state == "EXTERNAL_HOLD":
            report.check(
                external_required,
                f"external-hold R5 gap does not require external evidence: {identifier}",
            )
        facts.append(
            {
                "id": identifier,
                "status": state,
                "exit_evidence_level": level,
                "issues": issues,
            }
        )

    canonical_source = _bind_source_identities(
        gap,
        status,
        source_identities,
        expected_commit=expected_commit,
        expected_tree=expected_tree,
        artifact_bindings=artifact_bindings,
        report=report,
    )
    for identifier, evidence, level, source_identity in deferred_environment:
        _environment_evidence(
            evidence,
            identifier,
            level,
            report,
            source_identity=canonical_source or source_identity,
            expected_commit=expected_commit,
            expected_tree=expected_tree,
        )
        if identifier == "R5-GAP-RELEASE-001":
            _release_authorization_evidence(evidence, identifier, report)

    order = gap.get("priority_order")
    report.check(isinstance(order, list), "R5 priority_order must be a list")
    if isinstance(order, list):
        normalized_order = [str(value) for value in order]
        report.check(
            len(normalized_order) == len(set(normalized_order)),
            "R5 priority_order contains duplicate gap IDs",
        )
        report.check(
            set(normalized_order) == seen,
            "R5 priority_order does not contain exactly the declared gaps",
        )
        report.check(
            normalized_order == list(CANONICAL_GAP_ORDER),
            "R5 priority_order must follow the canonical R6 lane order",
        )

    missing_canonical = set(CANONICAL_GAP_SPECS) - seen
    unknown_canonical = seen - set(CANONICAL_GAP_SPECS)
    report.check(
        not missing_canonical,
        "R5 gap register is missing required canonical lanes: "
        + ", ".join(sorted(missing_canonical)),
    )
    report.check(
        not unknown_canonical,
        "R5 gap register contains unknown canonical lanes: "
        + ", ".join(sorted(unknown_canonical)),
    )
    report.check(
        all(
            states_by_id.get(identifier)
            in {"SOURCE_CLOSED_PENDING_EVIDENCE", "EXTERNAL_HOLD", "CLOSED"}
            for identifier in EXTERNAL_GAPS
            if identifier in seen
        ),
        "R5 external evidence lanes must remain pending, held or closed with reviewed evidence",
    )

    all_closed = bool(seen) and closed == seen
    report.check(
        status.get("zero_gap") is all_closed,
        "R5 status zero_gap does not equal the complete gap-closure state",
    )
    release_closed = "R5-GAP-RELEASE-001" in closed
    public_release = status.get("public_release")
    report.check(isinstance(public_release, bool), "R5 public_release must be boolean")
    report.check(
        public_release is (release_closed and all_closed),
        "R5 public_release requires a CLOSED release gap and zero-gap completion",
    )
    generated_policy = gap.get("generated_policy")
    report.check(isinstance(generated_policy, dict), "R5 gap policy must be an object")
    if isinstance(generated_policy, dict):
        report.check(
            generated_policy.get("checked_in_status_is_claim_policy_not_exact_head_evidence")
            is True,
            "R5 gap policy must mark checked-in status as claim policy only",
        )
        report.check(
            generated_policy.get("exact_head_evidence_must_be_ci_generated") is True,
            "R5 gap policy must require CI-generated exact-head evidence",
        )
        report.check(
            generated_policy.get("automatic_redispatch") is False,
            "R5 gap policy must keep automatic_redispatch false",
        )
        report.check(
            generated_policy.get("public_release") is public_release,
            "R5 gap policy public_release does not match status",
        )
    report.facts["gap_register"] = sorted(facts, key=lambda value: value["id"])
    report.facts["zero_gap"] = all_closed


def verify(
    root: Path,
    strict_android: bool = False,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
) -> Report:
    report = Report()
    _check_checkout_against_expected(root, expected_commit, expected_tree, report)
    try:
        contract = read_json(root / CONTRACT)
        status = read_json(root / STATUS)
        workspace = read_toml(root / "Cargo.toml")
        plan_text = (root / PLAN).read_text(encoding="utf-8")
        traceability_text = (root / TRACEABILITY).read_text(encoding="utf-8")
    except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        report.errors.append(f"cannot parse R5 verification input: {error}")
        return report

    revision = contract.get("revision")
    report.check(revision == GRAPH_REVISION, f"R5 graph revision must be {GRAPH_REVISION}")
    report.check(
        status.get("schema") == STATUS_SCHEMA,
        "R5 status schema must be " + STATUS_SCHEMA,
    )
    report.check(
        status.get("plan_revision") == revision,
        "R5 status graph-compatible plan revision does not match the graph contract",
    )
    report.check(
        status.get("automatic_redispatch") is False,
        "R5 automatic_redispatch must remain false",
    )
    active_revision = status.get("active_plan_revision", status.get("plan_revision"))
    if active_revision == ACTIVE_PLAN_REVISION:
        report.check(
            status.get("claim_ceiling") == EXPECTED_CLAIM_CEILING,
            "R5 active status claim_ceiling must remain the exact-source ceiling",
        )
    report.check(
        str(active_revision) in plan_text,
        "R5 plan does not contain the active machine revision",
    )
    report.check("ACTIVE" in plan_text, "R5 plan authority statement is missing")
    report.check(
        traceability_text.startswith("requirement_id\twork_package\t"),
        "R5 traceability header is missing or malformed",
    )

    ws = workspace.get("workspace")
    if not isinstance(ws, dict):
        report.errors.append("Cargo.toml has no [workspace] table")
        return report
    members = set(str(value) for value in ws.get("members", []))
    defaults = set(str(value) for value in ws.get("default-members", []))
    cargo = contract.get("cargo")
    if not isinstance(cargo, dict):
        report.errors.append("R5 graph cargo section is not an object")
        return report

    required_members = set(str(value) for value in cargo.get("required_workspace_members", []))
    required_defaults = set(str(value) for value in cargo.get("required_default_members", []))
    allowed_defaults = set(str(value) for value in cargo.get("allowed_default_members", []))
    forbidden_defaults = set(str(value) for value in cargo.get("forbidden_default_members", []))

    report.check(
        required_members <= members,
        "required R5 workspace members are absent: " + ", ".join(sorted(required_members - members)),
    )
    report.check(
        required_defaults <= defaults,
        "required R5 default members are absent: " + ", ".join(sorted(required_defaults - defaults)),
    )
    report.check(
        not (defaults & forbidden_defaults),
        "forbidden legacy default members are present: " + ", ".join(sorted(defaults & forbidden_defaults)),
    )
    report.check(
        defaults == allowed_defaults,
        "Cargo default-members drifted from the exact R5 closure: "
        + ", ".join(sorted(defaults ^ allowed_defaults)),
    )

    host_binary_facts: list[dict[str, str]] = []
    host_contract = cargo.get("host_binary_contract")
    if not isinstance(host_contract, dict):
        report.errors.append("R5 graph host_binary_contract is not an object")
    else:
        host_manifest_path = root / str(host_contract.get("manifest", ""))
        report.check(host_manifest_path.is_file(), f"R5 Host manifest is absent: {host_manifest_path}")
        if host_manifest_path.is_file():
            try:
                host_manifest = read_toml(host_manifest_path)
            except (OSError, ValueError) as error:
                report.errors.append(f"cannot parse R5 Host manifest: {error}")
                host_manifest = {}
            package = host_manifest.get("package", {})
            report.check(
                isinstance(package, dict)
                and package.get("autobins") is host_contract.get("autobins"),
                "R5 Host autobins setting drifted from the exact binary contract",
            )
            raw_bins = host_manifest.get("bin", [])
            actual_bins: set[tuple[str, str]] = set()
            if isinstance(raw_bins, list):
                for item in raw_bins:
                    if isinstance(item, dict):
                        name = str(item.get("name", ""))
                        path = str(item.get("path", ""))
                        actual_bins.add((name, path))
                        host_binary_facts.append({"name": name, "path": path})
            required_bins = {
                (str(item.get("name", "")), str(item.get("path", "")))
                for item in host_contract.get("required_bins", [])
                if isinstance(item, dict)
            }
            report.check(
                actual_bins == required_bins,
                "R5 Host explicit binaries drifted from the exact contract: "
                + ", ".join(sorted(f"{name}={path}" for name, path in actual_bins ^ required_bins)),
            )
            forbidden_paths = {
                str(value) for value in host_contract.get("forbidden_selected_paths", [])
            }
            selected_paths = {path for _, path in actual_bins}
            report.check(
                not (selected_paths & forbidden_paths),
                "a superseded Host entrypoint is selected: "
                + ", ".join(sorted(selected_paths & forbidden_paths)),
            )

    forbidden_dependencies = set(str(value) for value in cargo.get("forbidden_internal_dependencies", []))
    package_specs = cargo.get("owner_open_packages", [])
    if not isinstance(package_specs, list):
        report.errors.append("owner_open_packages must be a list")
        return report

    package_facts: dict[str, list[str]] = {}
    marker_hits: list[str] = []
    for spec in package_specs:
        if not isinstance(spec, dict):
            report.errors.append("owner_open_packages entry is not an object")
            continue
        path = Path(str(spec.get("path", "")))
        manifest_path = root / path / "Cargo.toml"
        report.check(manifest_path.is_file(), f"owner-open package manifest is absent: {manifest_path}")
        if not manifest_path.is_file():
            continue
        try:
            manifest = read_toml(manifest_path)
        except (OSError, ValueError) as error:
            report.errors.append(f"cannot parse owner-open package manifest {manifest_path}: {error}")
            continue
        dependencies = dependency_names(manifest)
        package_facts[str(path)] = sorted(dependencies)
        leaked = dependencies & forbidden_dependencies
        report.check(
            not leaked,
            f"{path} imports forbidden legacy dependencies: " + ", ".join(sorted(leaked)),
        )
        allowed_internal = set(str(value) for value in spec.get("allowed_internal_dependencies", []))
        actual_internal = {value for value in dependencies if value.startswith("trillionnium-")}
        report.check(
            actual_internal <= allowed_internal,
            f"{path} has an unreviewed owner-open internal edge: "
            + ", ".join(sorted(actual_internal - allowed_internal)),
        )
        source_root = root / path / "src"
        if source_root.is_dir():
            for source in sorted(source_root.rglob("*.rs")):
                try:
                    text = source.read_text(encoding="utf-8")
                except (OSError, UnicodeError) as error:
                    report.errors.append(
                        f"cannot read owner-open source {source.relative_to(root)}: {error}"
                    )
                    continue
                for marker in cargo.get("forbidden_source_markers", []):
                    if str(marker) in text:
                        marker_hits.append(f"{source.relative_to(root)}:{marker}")

    report.check(
        not marker_hits,
        "owner-open source contains forbidden legacy markers: " + ", ".join(marker_hits),
    )

    packages = status.get("work_packages", [])
    report.check(isinstance(packages, list), "R5 status work_packages must be a list")
    if isinstance(packages, list):
        seen: set[str] = set()
        for item in packages:
            if not isinstance(item, dict):
                report.errors.append("R5 status work-package entry is not an object")
                continue
            identifier = str(item.get("id", ""))
            report.check(
                bool(identifier) and identifier not in seen,
                f"duplicate or empty R5 work-package id: {identifier}",
            )
            seen.add(identifier)
            report.check(item.get("status") in STATUS_LEVELS, f"invalid status level for {identifier}")
            evidence = str(item.get("latest_evidence_level", ""))
            report.check(evidence in EVIDENCE_LEVELS, f"invalid evidence level for {identifier}")
        report.check(seen == {f"W{index}" for index in range(8)}, "R5 status must contain exactly W0-W7")

    report.check(status.get("public_release") is False or status.get("zero_gap") is True, "R5 source candidate must not claim a public release")
    negative = status.get("not_claimed", [])
    report.check(isinstance(negative, list) and bool(negative), "R5 status must carry explicit negative claims")

    gap_path = root / GAP_REGISTER
    if gap_path.is_file():
        try:
            gap = read_json(gap_path)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            report.errors.append(f"cannot parse R5 gap register: {error}")
        else:
            verify_gap_register(
                root,
                gap,
                status,
                plan_text,
                report,
                expected_commit=expected_commit,
                expected_tree=expected_tree,
            )
    else:
        # R6 promotion and resume workflows are defined over the canonical
        # gap register.  Do not let a caller delete that file and fall back to
        # the older graph-only checks while retaining an R6 status claim.
        report.check(
            status.get("active_plan_revision") != ACTIVE_PLAN_REVISION,
            "R5 active status requires the canonical gap register",
        )

    android = contract.get("android", {})
    android_hits: list[str] = []
    if isinstance(android, dict):
        overlay = root / str(android.get("audit_overlay_path", ""))
        if overlay.is_file():
            try:
                text = overlay.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as error:
                report.errors.append(f"cannot read Android audit overlay {overlay}: {error}")
                text = None
            if text is None:
                text = ""
            android_hits = sorted(
                marker
                for marker in {str(value) for value in android.get("forbidden_owner_open_packages", [])}
                if marker in text
            )
            if android_hits:
                message = "Android overlay still selects forbidden owner-open nodes: " + ", ".join(android_hits)
                if strict_android:
                    report.errors.append(message)
                else:
                    report.warn(message)
        else:
            report.warn(f"Android audit overlay is unavailable: {overlay}")
    else:
        report.errors.append("R5 graph android section is not an object")

    report.facts.update(
        {
            "graph_revision": revision,
            "active_plan_revision": active_revision,
            "workspace_members": sorted(members),
            "default_members": sorted(defaults),
            "host_binaries": sorted(host_binary_facts, key=lambda item: item["name"]),
            "owner_open_package_dependencies": package_facts,
            "forbidden_source_marker_hits": marker_hits,
            "android_forbidden_package_hits": android_hits,
            "claim_ceiling": status.get("claim_ceiling"),
        }
    )
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--strict-android", action="store_true")
    parser.add_argument(
        "--expected-commit",
        help="optional exact source-head commit to bind all source/environment evidence",
    )
    parser.add_argument(
        "--expected-tree",
        help="optional exact source-head tree to bind all source/environment evidence",
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = verify(
        args.root.resolve(),
        strict_android=args.strict_android,
        expected_commit=args.expected_commit,
        expected_tree=args.expected_tree,
    )
    payload = {
        "ok": not report.errors,
        "errors": report.errors,
        "warnings": report.warnings,
        "facts": report.facts,
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for message in report.errors:
            print(f"ERROR: {message}", file=sys.stderr)
        for message in report.warnings:
            print(f"WARN: {message}", file=sys.stderr)
        if not report.errors:
            print("owner-open R5 graph and gap register verified")
    return 1 if report.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
