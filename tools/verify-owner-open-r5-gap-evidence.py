#!/usr/bin/env python3
"""Validate Owner-Open R5 gap states against their declared evidence level.

This verifier deliberately separates repository source closure from installed,
image, physical, destructive-fault and release evidence.  Editing the gap JSON
cannot manufacture a promotion: every non-open state must carry the evidence
shape appropriate to that state, and zero-gap is possible only when every gap
is fully CLOSED.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
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
EXPECTED_SCHEMA = "org.trillionnium.owner-open-r5.gap-closure.v1"
EXPECTED_STATUS_SCHEMA = "org.trillionnium.owner-open-r5-status.v2"
EXPECTED_REVISION = "2026-08-29-r6"
EXPECTED_CLAIM_CEILING = "EXACT_COMMIT_SOURCE_GATES_PASSED_NOT_INSTALLED_CODEX"
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
EXTERNAL_LEVELS = {"L2", "L3", "L4", "L5", "L6"}
# The active R6 register is a closed machine contract.  Keep the identity,
# issue binding and evidence level immutable in every standalone verifier so a
# checked-in edit cannot replace a lane with a weaker or unrelated one.
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
# Governance is L1 but still requires protected-branch/reviewer authority;
# every other true entry is intrinsically external by its L2-L6 exit.
# These seven lanes have an external acceptance boundary even when their
# declared exit is L1 (governance) or when source-closed/pending states exist.
# Other L2-L6 lanes are also intrinsically external at closure, but are not
# required to remain present in this explicit hold set.
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

# branch, commit, tree and workflow run identify one exact source-closure
# candidate.  The branch/run fields are retained for provenance; commit/tree
# are the immutable source binding used by environment evidence.
SourceIdentity = tuple[str, str, str, int]
ArtifactBinding = tuple[tuple[int, str, str], ...]


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.errors

    def check(self, condition: bool, message: str) -> None:
        if not condition:
            self.errors.append(message)


def read_object(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError(f"{path} must be a single-link regular file")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot parse {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def nonempty_strings(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and bool(item.strip()) for item in value)
    )


def declared_issue_values(gap: dict[str, Any]) -> list[int]:
    values: list[int] = []
    issue = gap.get("issue")
    if isinstance(issue, int) and not isinstance(issue, bool) and issue > 0:
        values.append(issue)
    issues = gap.get("issues")
    if isinstance(issues, list):
        values.extend(
            value
            for value in issues
            if isinstance(value, int) and not isinstance(value, bool) and value > 0
        )
    return values


def validate_canonical_shape(
    gap: dict[str, Any], identifier: str, exit_level: Any, report: Report
) -> None:
    spec = CANONICAL_GAP_SPECS.get(identifier)
    if spec is None:
        return
    expected_issues, expected_level, expected_external = spec
    report.check(
        exit_level == expected_level,
        f"{identifier} exit_evidence_level must remain {expected_level}",
    )
    report.check(
        sorted(declared_issue_values(gap)) == sorted(expected_issues),
        f"{identifier} issue binding does not match the canonical R6 contract",
    )
    report.check(
        gap.get("requires_external_evidence") is expected_external,
        f"{identifier} requires_external_evidence does not match the canonical R6 contract",
    )


def requires_external_evidence(
    gap: dict[str, Any],
    exit_level: Any,
    identifier: str,
    report: Report,
) -> bool:
    """Return the immutable evidence requirement for one gap.

    Higher-level exits are external by definition.  The governance lane is
    also external despite its L1 exit because branch protection and
    independent review cannot be established by repository source.  A
    checked-in flag is useful documentation, but it must not be able to turn
    either class into a source-only lane.
    """
    value = gap.get("requires_external_evidence")
    report.check(
        value is None or isinstance(value, bool),
        f"{identifier} requires_external_evidence must be boolean",
    )
    if identifier in EXTERNAL_EVIDENCE_GAPS:
        report.check(
            value is True,
            f"{identifier} requires_external_evidence must be true for an external lane",
        )
        return True
    if isinstance(exit_level, str) and exit_level in EXTERNAL_LEVELS:
        report.check(
            value is not False,
            f"{identifier} cannot disable external evidence for {exit_level}",
        )
        return True
    if isinstance(value, bool):
        return value
    return False


def _source_identity_from_fields(
    value: dict[str, Any],
    label: str,
    report: Report,
    *,
    commit_field: str,
    tree_field: str,
    run_field: str,
) -> SourceIdentity | None:
    """Validate identity fields and return them only when all are usable."""
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
    report.check(branch_valid, f"{label} source evidence branch is missing")
    report.check(
        commit_valid,
        f"{label} source evidence {commit_field} must be lowercase 40-hex",
    )
    report.check(
        tree_valid,
        f"{label} source evidence {tree_field} must be lowercase 40-hex",
    )
    report.check(
        run_valid,
        f"{label} source evidence {run_field} must be positive",
    )
    if not (branch_valid and commit_valid and tree_valid and run_valid):
        return None
    return (branch.strip(), commit, tree, run_id)


def exact_source_evidence(
    value: Any,
    label: str,
    report: Report,
    artifact_bindings: list[tuple[str, ArtifactBinding]] | None = None,
) -> SourceIdentity | None:
    report.check(isinstance(value, dict), f"{label} source_evidence must be an object")
    if not isinstance(value, dict):
        return None
    report.check(value.get("level") == "L1", f"{label} source evidence level must be L1")
    identity = _source_identity_from_fields(
        value,
        label,
        report,
        commit_field="commit",
        tree_field="tree",
        run_field="workflow_run_id",
    )
    report.check(
        nonempty_strings(value.get("successful_jobs")),
        f"{label} source evidence must name successful jobs",
    )
    artifacts = value.get("artifacts")
    report.check(
        isinstance(artifacts, list) and bool(artifacts),
        f"{label} source evidence must bind at least one artifact",
    )
    if isinstance(artifacts, list):
        normalized: list[tuple[int, str, str]] = []
        artifact_ids: set[int] = set()
        artifacts_valid = True
        for index, artifact in enumerate(artifacts):
            artifact_label = f"{label} source_evidence.artifacts[{index}]"
            report.check(isinstance(artifact, dict), f"{artifact_label} must be an object")
            if not isinstance(artifact, dict):
                artifacts_valid = False
                continue
            artifact_id = artifact.get("id")
            id_valid = (
                isinstance(artifact_id, int)
                and not isinstance(artifact_id, bool)
                and artifact_id > 0
            )
            report.check(id_valid, f"{artifact_label}.id must be positive")
            if not id_valid:
                artifacts_valid = False
            elif artifact_id in artifact_ids:
                report.check(False, f"{artifact_label}.id is duplicated")
                artifacts_valid = False
            else:
                artifact_ids.add(artifact_id)
            name = artifact.get("name")
            name_valid = isinstance(name, str) and bool(name.strip())
            report.check(
                name_valid,
                f"{artifact_label}.name is missing",
            )
            if not name_valid:
                artifacts_valid = False
            digest = artifact.get("digest")
            digest_valid = (
                isinstance(digest, str)
                and digest.startswith("sha256:")
                and HEX64.fullmatch(digest.removeprefix("sha256:")) is not None
            )
            report.check(
                digest_valid,
                f"{artifact_label}.digest must be sha256:<64 lowercase hex>",
            )
            if not digest_valid:
                artifacts_valid = False
            if name_valid:
                suffix = ARTIFACT_SHA_SUFFIX.search(name.strip())
                if suffix is not None:
                    report.check(
                        identity is None or suffix.group(1) == identity[1],
                        f"{artifact_label}.name is bound to a different source commit",
                    )
                    if identity is not None and suffix.group(1) != identity[1]:
                        artifacts_valid = False
            if id_valid and name_valid and digest_valid:
                normalized.append((artifact_id, name.strip(), digest))
        if artifacts_valid and artifact_bindings is not None:
            binding = tuple(sorted(normalized))
            report.check(
                len(binding) == len(set(binding)),
                f"{label} source artifact binding contains duplicates",
            )
            if len(binding) == len(set(binding)):
                artifact_bindings.append((label, binding))
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
    gaps: dict[str, Any], report: Report
) -> SourceIdentity | None:
    candidate = gaps.get("documentation_candidate")
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
    """Derive the checkout head from Git when an exact pair is requested."""
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
        for relative in (GAPS, STATUS):
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
    gaps: dict[str, Any],
    status: dict[str, Any],
    identities: list[tuple[str, SourceIdentity]],
    *,
    artifact_bindings: list[tuple[str, ArtifactBinding]] | None = None,
    expected_commit: str | None,
    expected_tree: str | None,
    report: Report,
) -> SourceIdentity | None:
    """Bind every source record to one candidate identity.

    Checked-in registers may refer to a historical CI candidate while a newer
    checkout is being inspected.  Therefore the current checkout is an
    optional assertion (``expected_*``), never an implicit self-reference.
    """
    status_identity = _status_candidate_identity(status, report)
    documentation_identity = _documentation_candidate_identity(gaps, report)
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


def _nonempty_evidence_value(value: Any) -> bool:
    """Accept only useful string/object/list identity and result values."""
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (dict, list)):
        return bool(value)
    return False


def _validate_environment_contract(
    item: dict[str, Any], label: str, report: Report
) -> None:
    """Require the complete evidence object documented in runbook section 2."""
    source_tree = item.get("source_tree")
    report.check(
        isinstance(source_tree, str) and HEX40.fullmatch(source_tree) is not None,
        f"{label}.source_tree must be lowercase 40-hex",
    )
    has_bundle_reference = isinstance(item.get("bundle_path"), str) and bool(
        item["bundle_path"].strip()
    )
    for field in (
        "source_lock_sha256",
        "tool_and_artifact_sha256",
        "raw_log_sha256",
        "evidence_sha256",
    ):
        value = item.get(field)
        if has_bundle_reference and field != "evidence_sha256" and value is None:
            continue
        report.check(
            isinstance(value, str) and HEX64.fullmatch(value) is not None,
            f"{label}.{field} must be lowercase 64-hex",
        )
    for field in (
        "target_or_device_identity",
        "command_or_operation_identity",
        "result_summary",
    ):
        if has_bundle_reference and field not in item:
            continue
        report.check(
            _nonempty_evidence_value(item.get(field)),
            f"{label}.{field} must be a non-empty string, object or list",
        )
    report.check(
        isinstance(item.get("kind"), str) and bool(item["kind"].strip()),
        f"{label}.kind is missing",
    )
    report.check(
        isinstance(item.get("reviewer"), str) and bool(item["reviewer"].strip()),
        f"{label}.reviewer is missing",
    )
    report.check(
        item.get("synthetic") is False,
        f"{label} must explicitly declare synthetic=false",
    )
    report.check(
        item.get("automatic_redispatch") is False,
        f"{label} must explicitly declare automatic_redispatch=false",
    )


def environment_evidence(
    root: Path,
    value: Any,
    label: str,
    exit_level: str,
    report: Report,
    source_identity: SourceIdentity | None = None,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
) -> None:
    report.check(isinstance(value, list) and bool(value), f"{label} evidence must be a non-empty list")
    if not isinstance(value, list):
        report.check(
            False,
            f"{label} has no evidence at or above exit level {exit_level}",
        )
        return
    exit_rank = LEVELS.get(exit_level)
    if exit_rank is None:
        report.check(False, f"{label} has invalid exit evidence level")
        return
    observed_ranks: list[int] = []
    for index, item in enumerate(value):
        item_label = f"{label} evidence[{index}]"
        report.check(isinstance(item, dict), f"{item_label} must be an object")
        if not isinstance(item, dict):
            continue
        level = item.get("level")
        valid_level = isinstance(level, str) and level in LEVELS
        report.check(valid_level, f"{item_label}.level is invalid")
        if valid_level:
            observed_ranks.append(LEVELS[level])
        source_commit = item.get("source_commit")
        source_commit_valid = (
            isinstance(source_commit, str)
            and HEX40.fullmatch(source_commit) is not None
        )
        report.check(
            source_commit_valid,
            f"{item_label}.source_commit must be lowercase 40-hex",
        )
        if source_commit_valid and source_identity is not None:
            report.check(
                source_commit == source_identity[1],
                f"{item_label}.source_commit does not match the canonical source candidate",
            )
        elif source_commit_valid and expected_commit is not None:
            report.check(
                source_commit == expected_commit,
                f"{item_label}.source_commit does not match the expected exact source head",
            )
        _validate_environment_contract(item, item_label, report)
        source_tree = item.get("source_tree")
        source_tree_valid = (
            isinstance(source_tree, str) and HEX40.fullmatch(source_tree) is not None
        )
        if source_tree_valid and source_identity is not None:
            report.check(
                source_tree == source_identity[2],
                f"{item_label}.source_tree does not match the canonical source candidate",
            )
        elif source_tree_valid and expected_tree is not None:
            report.check(
                source_tree == expected_tree,
                f"{item_label}.source_tree does not match the expected exact source head",
            )
        bundle_path = item.get("bundle_path")
        report.check(
            isinstance(bundle_path, str) and bool(bundle_path.strip()),
            f"{item_label}.bundle_path must reference a reviewed evidence bundle",
        )
        bundle_commit = source_identity[1] if source_identity is not None else expected_commit
        bundle_tree = source_identity[2] if source_identity is not None else expected_tree
        if (
            isinstance(bundle_path, str)
            and bool(bundle_path.strip())
            and isinstance(bundle_commit, str)
            and isinstance(bundle_tree, str)
        ):
            try:
                bundle_facts = validate_evidence_reference(
                    root,
                    gap_id=label,
                    exit_level=exit_level,
                    source_commit=bundle_commit,
                    source_tree=bundle_tree,
                    item=item,
                )
            except (EvidenceError, OSError) as error:
                report.errors.append(f"{item_label}: {error}")
            else:
                validated = report.facts.setdefault(
                    "validated_external_evidence", {}
                ).setdefault(label, [])
                if isinstance(validated, list):
                    reference = {
                        "bundle_path": bundle_path,
                        "manifest_sha256": bundle_facts.get("manifest_sha256"),
                        "kind": bundle_facts.get("kind"),
                        "evidence_level": bundle_facts.get("evidence_level"),
                        "release_authorizer": bundle_facts.get("release_authorizer"),
                    }
                    if reference in validated:
                        report.errors.append(f"{item_label} is duplicated")
                    else:
                        validated.append(reference)
    report.check(
        any(rank >= exit_rank for rank in observed_ranks),
        f"{label} has no evidence at or above exit level {exit_level}",
    )


def release_authorization_evidence(
    value: Any, label: str, report: Report
) -> None:
    """Require explicit release-signature and human-go evidence at L6.

    These fields bind an externally reviewed release manifest and authorization;
    this gate checks their shape and affirmative claims, while the dedicated
    signing/transparency tools verify the cryptography itself.
    """
    if not isinstance(value, list):
        report.check(False, f"{label} release authorization evidence is missing")
        return
    candidates = [
        item
        for item in value
        if isinstance(item, dict) and item.get("level") == "L6"
    ]
    report.check(
        bool(candidates),
        f"{label} release authorization requires an L6 evidence item",
    )
    authorized = False
    for index, item in enumerate(candidates):
        item_label = f"{label} evidence[{index}]"
        bundle_path = item.get("bundle_path")
        if isinstance(bundle_path, str) and bundle_path.strip():
            validated = report.facts.get("validated_external_evidence", {}).get(label, [])
            bundle_authorized = any(
                isinstance(reference, dict)
                and reference.get("bundle_path") == bundle_path
                and isinstance(reference.get("release_authorizer"), str)
                and bool(reference["release_authorizer"].strip())
                for reference in validated
            ) if isinstance(validated, list) else False
            report.check(
                bundle_authorized,
                f"{item_label} reviewed L6 bundle lacks independent release authorization",
            )
            authorized = authorized or bundle_authorized
            continue
        signature = item.get("release_signature")
        authorization = item.get("release_authorization")
        report.check(
            isinstance(signature, dict),
            f"{item_label}.release_signature must be an object",
        )
        report.check(
            isinstance(authorization, dict),
            f"{item_label}.release_authorization must be an object",
        )
        if not isinstance(signature, dict) or not isinstance(authorization, dict):
            continue
        manifest_sha256 = signature.get("manifest_sha256")
        report.check(
            isinstance(manifest_sha256, str)
            and HEX64.fullmatch(manifest_sha256) is not None,
            f"{item_label}.release_signature.manifest_sha256 must be lowercase 64-hex",
        )
        for field in (
            "signature",
            "certificate_identity",
            "oidc_issuer",
            "oidc_subject",
            "transparency_log_entry",
        ):
            report.check(
                isinstance(signature.get(field), str)
                and bool(signature[field].strip()),
                f"{item_label}.release_signature.{field} is missing",
            )
        report.check(
            signature.get("cryptographic_signature_verified") is True,
            f"{item_label}.release_signature.cryptographic_signature_verified must be true",
        )
        report.check(
            authorization.get("decision") == "GO",
            f"{item_label}.release_authorization.decision must be GO",
        )
        for field in ("authorization_id", "authorized_by", "approved_at"):
            report.check(
                isinstance(authorization.get(field), str)
                and bool(authorization[field].strip()),
                f"{item_label}.release_authorization.{field} is missing",
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
            f"{item_label}.release_authorization.approved_at must be an ISO-8601 timestamp with timezone",
        )
        authorized = authorized or (
            isinstance(manifest_sha256, str)
            and HEX64.fullmatch(manifest_sha256) is not None
            and signature.get("cryptographic_signature_verified") is True
            and authorization.get("decision") == "GO"
            and all(
                isinstance(signature.get(field), str)
                and bool(signature[field].strip())
                for field in (
                    "signature",
                    "certificate_identity",
                    "oidc_issuer",
                    "oidc_subject",
                    "transparency_log_entry",
                )
            )
            and all(
                isinstance(authorization.get(field), str)
                and bool(authorization[field].strip())
                for field in ("authorization_id", "authorized_by")
            )
            and timestamp_valid
        )
    report.check(
        authorized,
        f"{label} lacks a complete signed-manifest and human authorization record",
    )


def verify_values(
    root: Path,
    gaps: dict[str, Any],
    status: dict[str, Any],
    expected_commit: str | None = None,
    expected_tree: str | None = None,
) -> Report:
    report = Report()
    _check_checkout_against_expected(root, expected_commit, expected_tree, report)
    report.check(gaps.get("schema") == EXPECTED_SCHEMA, "gap schema is unsupported")
    report.check(
        status.get("schema") == EXPECTED_STATUS_SCHEMA,
        "status schema is unsupported",
    )
    report.check(gaps.get("revision") == EXPECTED_REVISION, "gap revision is not active r6")
    report.check(
        status.get("active_plan_revision") == gaps.get("revision"),
        "status and gap active revisions differ",
    )
    report.check(
        status.get("automatic_redispatch") is False,
        "automatic_redispatch must remain false",
    )
    report.check(
        status.get("claim_ceiling") == EXPECTED_CLAIM_CEILING,
        "claim_ceiling must remain the exact-source ceiling",
    )
    public_release = status.get("public_release")
    report.check(isinstance(public_release, bool), "public_release must be boolean")
    generated_policy = gaps.get("generated_policy")
    report.check(
        isinstance(generated_policy, dict),
        "gap generated_policy must be an object",
    )
    if isinstance(generated_policy, dict):
        report.check(
            generated_policy.get("checked_in_status_is_claim_policy_not_exact_head_evidence")
            is True,
            "gap generated_policy must mark checked-in status as claim policy only",
        )
        report.check(
            generated_policy.get("exact_head_evidence_must_be_ci_generated") is True,
            "gap generated_policy must require CI-generated exact-head evidence",
        )
        report.check(
            generated_policy.get("automatic_redispatch") is False,
            "gap generated_policy automatic_redispatch must remain false",
        )
        report.check(
            generated_policy.get("public_release") is public_release,
            "gap generated_policy public_release must match status",
        )

    entries = gaps.get("gaps")
    report.check(isinstance(entries, list) and bool(entries), "gaps must be a non-empty list")
    if not isinstance(entries, list):
        return report

    seen: set[str] = set()
    states_by_id: dict[str, str] = {}
    states: dict[str, int] = {state: 0 for state in sorted(ALLOWED_STATES)}
    ordered: list[str] = []
    source_identities: list[tuple[str, SourceIdentity]] = []
    artifact_bindings: list[tuple[str, ArtifactBinding]] = []
    deferred_environment: list[
        tuple[str, Any, str, SourceIdentity | None]
    ] = []
    for index, gap in enumerate(entries):
        label = f"gaps[{index}]"
        report.check(isinstance(gap, dict), f"{label} must be an object")
        if not isinstance(gap, dict):
            continue
        identifier = gap.get("id")
        report.check(
            isinstance(identifier, str) and bool(identifier),
            f"{label}.id is missing",
        )
        if not isinstance(identifier, str) or not identifier:
            continue
        report.check(identifier not in seen, f"duplicate gap id: {identifier}")
        seen.add(identifier)
        ordered.append(identifier)
        state = gap.get("status")
        report.check(
            isinstance(state, str) and state in ALLOWED_STATES,
            f"{identifier} has invalid state {state!r}",
        )
        if isinstance(state, str) and state in states:
            states[state] += 1
        states_by_id[identifier] = str(state)
        exit_level = gap.get("exit_evidence_level")
        valid_exit_level = isinstance(exit_level, str) and exit_level in LEVELS
        report.check(valid_exit_level, f"{identifier} has invalid exit level")
        validate_canonical_shape(gap, identifier, exit_level, report)
        external_required = requires_external_evidence(
            gap, exit_level, identifier, report
        )
        report.check(
            isinstance(gap.get("summary"), str) and bool(gap.get("summary")),
            f"{identifier} summary is missing",
        )
        report.check(
            nonempty_strings(gap.get("acceptance")),
            f"{identifier} acceptance must be a non-empty string list",
        )
        issue = gap.get("issue")
        issues = gap.get("issues")
        report.check(
            (isinstance(issue, int) and not isinstance(issue, bool) and issue > 0)
            or (
                isinstance(issues, list)
                and bool(issues)
                and all(isinstance(item, int) and item > 0 for item in issues)
            ),
            f"{identifier} must bind an issue or issues",
        )

        if state == "OPEN":
            report.check(
                "source_evidence" not in gap and "evidence" not in gap,
                f"{identifier} OPEN state must not carry promotion evidence",
            )
        elif state == "SOURCE_CLOSED_PENDING_EVIDENCE":
            source_identity = exact_source_evidence(
                gap.get("source_evidence"),
                identifier,
                report,
                artifact_bindings,
            )
            if source_identity is not None:
                source_identities.append((identifier, source_identity))
            report.check(
                isinstance(exit_level, str) and exit_level in EXTERNAL_LEVELS,
                f"{identifier} source-closed pending state requires L2-L6 exit",
            )
            report.check(
                nonempty_strings(gap.get("remaining_evidence")),
                f"{identifier} must list remaining higher-level evidence",
            )
            report.check(
                "evidence" not in gap,
                f"{identifier} pending state must not carry full closure evidence",
            )
        elif state == "EXTERNAL_HOLD":
            report.check(
                external_required,
                f"{identifier} external hold must require external evidence",
            )
            report.check(
                nonempty_strings(gap.get("required_material"))
                or nonempty_strings(gap.get("required_authority")),
                f"{identifier} external hold must list required material or authority",
            )
            if "source_evidence" in gap:
                source_identity = exact_source_evidence(
                    gap.get("source_evidence"),
                    identifier,
                    report,
                    artifact_bindings,
                )
                if source_identity is not None:
                    source_identities.append((identifier, source_identity))
            report.check(
                "evidence" not in gap,
                f"{identifier} external hold must not carry full closure evidence",
            )
        elif state == "CLOSED" and valid_exit_level:
            source_identity = exact_source_evidence(
                gap.get("source_evidence"),
                identifier,
                report,
                artifact_bindings,
            )
            if source_identity is not None:
                source_identities.append((identifier, source_identity))
            if external_required:
                deferred_environment.append(
                    (identifier, gap.get("evidence"), exit_level, source_identity)
                )
            else:
                report.check(
                    exit_level == "L1",
                    f"{identifier} source-only closure is allowed only at L1",
                )
                report.check(
                    "evidence" not in gap or gap.get("evidence") in ([], None),
                    f"{identifier} source-only L1 closure must not carry external evidence",
                )

    canonical_source = _bind_source_identities(
        gaps,
        status,
        source_identities,
        expected_commit=expected_commit,
        expected_tree=expected_tree,
        artifact_bindings=artifact_bindings,
        report=report,
    )
    for identifier, evidence, exit_level, source_identity in deferred_environment:
        environment_evidence(
            root,
            evidence,
            identifier,
            exit_level,
            report,
            source_identity=canonical_source or source_identity,
            expected_commit=expected_commit,
            expected_tree=expected_tree,
        )
        if identifier == "R5-GAP-RELEASE-001":
            release_authorization_evidence(evidence, identifier, report)

    priority = gaps.get("priority_order")
    report.check(priority == ordered, "priority_order must exactly match gaps order")
    report.check(
        ordered == list(CANONICAL_GAP_ORDER),
        "priority_order must follow the canonical R6 lane order",
    )
    missing_canonical = set(CANONICAL_GAP_SPECS) - seen
    unknown_canonical = seen - set(CANONICAL_GAP_SPECS)
    report.check(
        not missing_canonical,
        "gap register is missing required canonical lanes: "
        + ", ".join(sorted(missing_canonical)),
    )
    report.check(
        not unknown_canonical,
        "gap register contains unknown canonical lanes: "
        + ", ".join(sorted(unknown_canonical)),
    )
    externally_tracked = {
        identifier
        for identifier in EXTERNAL_EVIDENCE_GAPS
        if states_by_id.get(identifier)
        in {"SOURCE_CLOSED_PENDING_EVIDENCE", "EXTERNAL_HOLD", "CLOSED"}
    }
    report.check(
        externally_tracked == EXTERNAL_EVIDENCE_GAPS,
        "required external evidence lanes must remain pending, EXTERNAL_HOLD or CLOSED",
    )
    zero_gap = status.get("zero_gap")
    report.check(isinstance(zero_gap, bool), "zero_gap must be boolean")
    all_closed = bool(entries) and all(
        isinstance(item, dict) and item.get("status") == "CLOSED" for item in entries
    )
    report.check(
        zero_gap is all_closed,
        "zero_gap must be true exactly when every gap is CLOSED",
    )
    release_closed = any(
        isinstance(item, dict)
        and item.get("id") == "R5-GAP-RELEASE-001"
        and item.get("status") == "CLOSED"
        for item in entries
    )
    report.check(
        public_release is (release_closed and all_closed),
        "public_release must be true exactly when the release gap is CLOSED and every gap is CLOSED",
    )
    if zero_gap:
        report.check(
            states.get("EXTERNAL_HOLD", 0) == 0
            and states.get("SOURCE_CLOSED_PENDING_EVIDENCE", 0) == 0
            and states.get("OPEN", 0) == 0,
            "zero_gap cannot coexist with open, pending or external-hold states",
        )

    report.facts.update(
        {
            "revision": gaps.get("revision"),
            "gap_count": len(entries),
            "states": states,
            "zero_gap": zero_gap,
            "all_closed": all_closed,
            "release_closed": release_closed,
            "public_release": status.get("public_release"),
            "automatic_redispatch": status.get("automatic_redispatch"),
        }
    )
    return report


def verify(
    root: Path,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
) -> Report:
    report = Report()
    try:
        gaps = read_object(root / GAPS)
        status = read_object(root / STATUS)
    except ValueError as error:
        report.errors.append(str(error))
        return report
    values = verify_values(
        root,
        gaps,
        status,
        expected_commit=expected_commit,
        expected_tree=expected_tree,
    )
    report.errors.extend(values.errors)
    report.warnings.extend(values.warnings)
    report.facts.update(values.facts)
    return report


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--expected-commit",
        help="optional exact source-head commit to bind all source/environment evidence",
    )
    parser.add_argument(
        "--expected-tree",
        help="optional exact source-head tree to bind all source/environment evidence",
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = verify(
        args.root.resolve(),
        expected_commit=args.expected_commit,
        expected_tree=args.expected_tree,
    )
    value = {
        "ok": report.ok,
        "errors": report.errors,
        "warnings": report.warnings,
        "facts": report.facts,
    }
    if args.json:
        print(json.dumps(value, indent=2, sort_keys=True))
    else:
        for error in report.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        for warning in report.warnings:
            print(f"WARNING: {warning}")
        if report.ok:
            print("owner-open R5 gap evidence verified")
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
