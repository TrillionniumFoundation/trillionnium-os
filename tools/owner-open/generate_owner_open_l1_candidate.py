#!/usr/bin/env python3
"""Generate one exact-source-head Owner-Open L1 candidate manifest.

Pull-request workflows normally expose a synthetic merge commit as
``GITHUB_SHA``.  That object is useful integration context, but it is not the
source branch commit.  This generator requires the checkout itself to equal the
explicit source-head SHA and records the workflow trigger SHA separately.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from typing import Any

SCHEMA = "org.trillionnium.owner-open.l1-candidate.v2"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
STATUS = Path("docs/status/owner-open-r5-status.json")
GAPS = Path("docs/status/owner-open-r5-gap-closure.json")
LOCK = Path("Cargo.lock")
EXPECTED_GAP_SCHEMA = "org.trillionnium.owner-open-r5.gap-closure.v1"
EXPECTED_GAP_REVISION = "2026-08-29-r6"
EXPECTED_STATUS_SCHEMA = "org.trillionnium.owner-open-r5-status.v2"
EXPECTED_CLAIM_CEILING = "EXACT_COMMIT_SOURCE_GATES_PASSED_NOT_INSTALLED_CODEX"
ALLOWED_STATES = {
    "OPEN",
    "SOURCE_CLOSED_PENDING_EVIDENCE",
    "EXTERNAL_HOLD",
    "CLOSED",
}
LEVELS = {f"L{index}": index for index in range(7)}
EXTERNAL_GAPS = {
    "R5-GAP-GOVERNANCE-001",
    "R5-GAP-INSTALLED-CODEX-001",
    "R5-GAP-ROOTLINUX-PLACEMENT-001",
    "R5-GAP-ANDROID-GRAPH-001",
    "R5-GAP-PHYSICAL-ADB-001",
    "R5-GAP-FAULT-MATRIX-001",
    "R5-GAP-RELEASE-001",
}
# Keep the candidate generator fail-closed even when a caller invokes it
# directly instead of going through the permanent verifier workflow.  The
# source candidate is allowed to describe only this exact R6 register.
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


class CandidateError(RuntimeError):
    pass


def _git(root: Path, *arguments: str, allow_empty: bool = False) -> str:
    try:
        clean_env = {
            key: value for key, value in os.environ.items() if not key.startswith("GIT_")
        }
        value = subprocess.check_output(
            ["git", "--no-replace-objects", "-C", str(root.resolve()), *arguments],
            cwd=root,
            text=True,
            stderr=subprocess.STDOUT,
            env=clean_env,
        ).strip()
        if not value and not allow_empty:
            raise CandidateError(f"git {' '.join(arguments)} returned an empty value")
        return value
    except (subprocess.CalledProcessError, OSError) as error:
        raise CandidateError(
            f"git {' '.join(arguments)} failed: {getattr(error, 'output', str(error)).strip()}"
        ) from error


def _read_object(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise CandidateError(
                f"canonical input is not a single-link regular file: {path}"
            )
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CandidateError(f"cannot read JSON object {path}: {error}") from error
    if not isinstance(value, dict):
        raise CandidateError(f"{path} must contain one JSON object")
    return value


def _validate_checkout(root: Path, expected_head: str) -> str:
    """Bind the candidate to a real, unmodified Git checkout."""
    root = root.resolve()
    top = Path(_git(root, "rev-parse", "--show-toplevel")).resolve()
    if top != root:
        raise CandidateError("Git checkout top-level does not match candidate root")
    if _git(root, "for-each-ref", "refs/replace", allow_empty=True):
        raise CandidateError("checkout contains Git replacement refs")
    if _git(root, "rev-parse", "HEAD") != expected_head:
        raise CandidateError("checkout HEAD differs from source head")
    status = _git(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        allow_empty=True,
    )
    if status:
        raise CandidateError(
            "tracked working tree is dirty before evidence generation: "
            + status.replace("\n", "; ")
        )
    index_state = _git(root, "ls-files", "-v", allow_empty=True)
    if any(line[:1] != "H" for line in index_state.splitlines() if line):
        raise CandidateError("checkout Git index contains non-normal tracked-entry flags")
    for relative in (STATUS, GAPS, LOCK):
        path = root / relative
        try:
            metadata = path.lstat()
        except OSError as error:
            raise CandidateError(f"candidate input is not a regular file: {relative}") from error
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise CandidateError(
                f"candidate input is not a single-link regular file: {relative}"
            )
        expected_blob = _git(root, "rev-parse", f"HEAD:{relative.as_posix()}")
        actual_blob = _git(
            root, "hash-object", "--no-filters", "--", relative.as_posix()
        )
        if actual_blob != expected_blob:
            raise CandidateError(f"candidate input differs from checkout HEAD: {relative}")
    return _git(root, "rev-parse", "HEAD^{tree}")


def _write_output(root: Path, requested: Path, raw: str) -> None:
    """Atomically write a candidate under the checkout without link traversal."""
    root = root.resolve()
    output = requested if requested.is_absolute() else root / requested
    output = output.absolute()
    try:
        output.relative_to(root)
    except ValueError as error:
        raise CandidateError("candidate output must remain inside the checkout") from error
    output.parent.mkdir(parents=True, exist_ok=True)
    parent = output.parent.resolve()
    try:
        parent.relative_to(root)
    except ValueError as error:
        raise CandidateError("candidate output parent escapes the checkout") from error
    if output.parent.is_symlink() or output.is_symlink():
        raise CandidateError("candidate output path must not be a symbolic link")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".owner-open-l1-candidate-", dir=str(parent), text=True
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
        raise CandidateError(f"cannot write candidate output: {error}") from error


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise CandidateError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def _sha_or_none(value: str | None, label: str) -> str | None:
    if value in (None, ""):
        return None
    if HEX40.fullmatch(value) is None:
        raise CandidateError(f"{label} is not a lowercase 40-hex Git SHA")
    return value


def _declared_issue_values(item: Any) -> list[int]:
    values: list[int] = []
    issue = item.get("issue") if isinstance(item, dict) else None
    if isinstance(issue, int) and not isinstance(issue, bool):
        values.append(issue)
    issues = item.get("issues") if isinstance(item, dict) else None
    if isinstance(issues, list):
        values.extend(
            value
            for value in issues
            if isinstance(value, int) and not isinstance(value, bool)
        )
    return values


def _source_identity(value: Any, label: str) -> tuple[Any, ...]:
    """Validate and normalize one checked-in L1 source-evidence record.

    The candidate manifest is generated from the current checkout, while the
    checked-in gap register may intentionally retain the last reviewed source
    baseline.  We therefore bind all checked-in records to one another (and to
    the status candidate below), rather than pretending that a self-referential
    commit can be written into the commit being generated.
    """
    if not isinstance(value, dict):
        raise CandidateError(f"{label} source_evidence must be an object")
    if value.get("level") != "L1":
        raise CandidateError(f"{label} source_evidence.level must be L1")
    branch = value.get("branch")
    if not isinstance(branch, str) or not branch.strip():
        raise CandidateError(f"{label} source_evidence.branch is missing")
    commit = value.get("commit")
    tree = value.get("tree")
    if not isinstance(commit, str) or HEX40.fullmatch(commit) is None:
        raise CandidateError(f"{label} source_evidence.commit is invalid")
    if not isinstance(tree, str) or HEX40.fullmatch(tree) is None:
        raise CandidateError(f"{label} source_evidence.tree is invalid")
    run_id = value.get("workflow_run_id")
    if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0:
        raise CandidateError(f"{label} source_evidence.workflow_run_id is invalid")
    jobs = value.get("successful_jobs")
    if (
        not isinstance(jobs, list)
        or not jobs
        or not all(isinstance(job, str) and job.strip() for job in jobs)
    ):
        raise CandidateError(f"{label} source_evidence.successful_jobs is invalid")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise CandidateError(f"{label} source_evidence.artifacts is missing")
    normalized_artifacts: list[tuple[int, str, str]] = []
    artifact_ids: set[int] = set()
    for index, artifact in enumerate(artifacts):
        artifact_label = f"{label} source_evidence.artifacts[{index}]"
        if not isinstance(artifact, dict):
            raise CandidateError(f"{artifact_label} must be an object")
        artifact_id = artifact.get("id")
        name = artifact.get("name")
        digest = artifact.get("digest")
        if (
            not isinstance(artifact_id, int)
            or isinstance(artifact_id, bool)
            or artifact_id <= 0
        ):
            raise CandidateError(f"{artifact_label}.id is invalid")
        if artifact_id in artifact_ids:
            raise CandidateError(f"{artifact_label}.id is duplicated")
        artifact_ids.add(artifact_id)
        if not isinstance(name, str) or not name.strip():
            raise CandidateError(f"{artifact_label}.name is missing")
        if (
            not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or HEX64.fullmatch(digest.removeprefix("sha256:")) is None
        ):
            raise CandidateError(f"{artifact_label}.digest is invalid")
        # Artifact names emitted by the permanent workflows carry the source
        # SHA.  If a legacy name has no SHA suffix, retain compatibility, but
        # never allow a mismatching explicit suffix.
        suffix = re.search(r"-([0-9a-f]{40})$", name)
        if suffix is not None and suffix.group(1) != commit:
            raise CandidateError(
                f"{artifact_label}.name is bound to a different source commit"
            )
        normalized_artifacts.append((artifact_id, name, digest))
    return (
        branch.strip(),
        commit,
        tree,
        run_id,
        # Job/artifact arrays are sets of successful bindings in the evidence
        # contract; their presentation order must not change identity.
        tuple(sorted(jobs)),
        tuple(sorted(normalized_artifacts)),
    )


def _optional_candidate_identity(value: Any, label: str) -> tuple[str, str, str, int] | None:
    """Validate an optional checked-in status/documentation candidate.

    These objects are provenance anchors, not free-form notes.  A malformed
    non-null value must fail closed instead of being silently ignored.
    """
    if value is None:
        return None
    if not isinstance(value, dict):
        raise CandidateError(f"{label} must be an object when present")
    branch = value.get("branch")
    commit = value.get("validated_source_commit")
    tree = value.get("validated_source_tree")
    run_id = value.get("workflow_run_id")
    if not isinstance(branch, str) or not branch.strip():
        raise CandidateError(f"{label}.branch is missing")
    if not isinstance(commit, str) or HEX40.fullmatch(commit) is None:
        raise CandidateError(f"{label}.validated_source_commit is invalid")
    if not isinstance(tree, str) or HEX40.fullmatch(tree) is None:
        raise CandidateError(f"{label}.validated_source_tree is invalid")
    if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0:
        raise CandidateError(f"{label}.workflow_run_id is invalid")
    return branch.strip(), commit, tree, run_id


def _validate_environment_evidence(
    value: Any,
    label: str,
    exit_level: str,
    source: tuple[Any, ...],
) -> None:
    if not isinstance(value, list) or not value:
        raise CandidateError(f"{label}.evidence must be a non-empty list")
    expected_commit = source[1]
    expected_tree = source[2]
    observed: list[int] = []
    for index, evidence in enumerate(value):
        item_label = f"{label}.evidence[{index}]"
        if not isinstance(evidence, dict):
            raise CandidateError(f"{item_label} must be an object")
        level = evidence.get("level")
        if not isinstance(level, str) or level not in LEVELS:
            raise CandidateError(f"{item_label}.level is invalid")
        observed.append(LEVELS[level])
        if evidence.get("source_commit") != expected_commit:
            raise CandidateError(
                f"{item_label}.source_commit is not bound to source_evidence"
            )
        source_tree = evidence.get("source_tree")
        if not isinstance(source_tree, str) or HEX40.fullmatch(source_tree) is None:
            raise CandidateError(
                f"{item_label}.source_tree must be lowercase 40-hex"
            )
        if source_tree != expected_tree:
            raise CandidateError(
                f"{item_label}.source_tree is not bound to source_evidence"
            )
        for field in (
            "source_lock_sha256",
            "tool_and_artifact_sha256",
            "raw_log_sha256",
            "evidence_sha256",
        ):
            digest = evidence.get(field)
            if not isinstance(digest, str) or HEX64.fullmatch(digest) is None:
                raise CandidateError(
                    f"{item_label}.{field} must be lowercase 64-hex"
                )
        for field in (
            "target_or_device_identity",
            "command_or_operation_identity",
            "result_summary",
        ):
            value_for_field = evidence.get(field)
            valid_value = (
                isinstance(value_for_field, str)
                and bool(value_for_field.strip())
            ) or (
                isinstance(value_for_field, (dict, list)) and bool(value_for_field)
            )
            if not valid_value:
                raise CandidateError(
                    f"{item_label}.{field} must be a non-empty string, object or list"
                )
        if not isinstance(evidence.get("kind"), str) or not evidence["kind"].strip():
            raise CandidateError(f"{item_label}.kind is missing")
        if not isinstance(evidence.get("reviewer"), str) or not evidence["reviewer"].strip():
            raise CandidateError(f"{item_label}.reviewer is missing")
        if evidence.get("synthetic") is not False:
            raise CandidateError(f"{item_label}.synthetic must be false")
        if evidence.get("automatic_redispatch") is not False:
            raise CandidateError(f"{item_label}.automatic_redispatch must be false")
    if exit_level not in LEVELS:
        raise CandidateError(f"{label} has invalid exit evidence level")
    if not any(rank >= LEVELS[exit_level] for rank in observed):
        raise CandidateError(f"{label} has no evidence at or above {exit_level}")


def _validate_canonical_gap_register(
    gaps: dict[str, Any], status: dict[str, Any]
) -> tuple[Any, ...]:
    if gaps.get("schema") != EXPECTED_GAP_SCHEMA:
        raise CandidateError("gap register schema is not the active R5 schema")
    if gaps.get("revision") != EXPECTED_GAP_REVISION:
        raise CandidateError("gap register revision is not active r6")
    entries = gaps.get("gaps")
    if not isinstance(entries, list) or not entries:
        raise CandidateError("gap register must contain a non-empty gaps list")
    seen: set[str] = set()
    source_identity: tuple[Any, ...] | None = None
    state_counts = {state: 0 for state in ALLOWED_STATES}
    for index, item in enumerate(entries):
        if not isinstance(item, dict):
            raise CandidateError(f"gap register entry {index} is not an object")
        identifier = item.get("id")
        if not isinstance(identifier, str) or not identifier.strip():
            raise CandidateError(f"gap register entry {index} has no id")
        if identifier in seen:
            raise CandidateError(f"gap register contains duplicate id {identifier}")
        seen.add(identifier)
        spec = CANONICAL_GAP_SPECS.get(identifier)
        if spec is None:
            raise CandidateError(f"gap register contains unknown canonical id {identifier}")
        expected_issues, expected_level, expected_external = spec
        if sorted(_declared_issue_values(item)) != sorted(expected_issues):
            raise CandidateError(f"gap register issue binding drifted for {identifier}")
        if item.get("exit_evidence_level") != expected_level:
            raise CandidateError(f"gap register exit level drifted for {identifier}")
        if item.get("requires_external_evidence") is not expected_external:
            raise CandidateError(
                f"gap register external-evidence flag drifted for {identifier}"
            )
        summary = item.get("summary")
        if not isinstance(summary, str) or not summary.strip():
            raise CandidateError(f"gap register summary is missing for {identifier}")
        acceptance = item.get("acceptance")
        if (
            not isinstance(acceptance, list)
            or not acceptance
            or not all(isinstance(value, str) and value.strip() for value in acceptance)
        ):
            raise CandidateError(
                f"gap register acceptance is missing or malformed for {identifier}"
            )
        state = item.get("status")
        if not isinstance(state, str) or state not in ALLOWED_STATES:
            raise CandidateError(f"gap register state is invalid for {identifier}")
        state_counts[state] += 1
        if state == "OPEN":
            raise CandidateError(
                f"source candidate cannot claim an OPEN canonical gap: {identifier}"
            )
        source = _source_identity(item.get("source_evidence"), identifier)
        if source_identity is None:
            source_identity = source
        elif source != source_identity:
            raise CandidateError(
                f"source evidence identity is inconsistent for {identifier}"
            )
        if state == "SOURCE_CLOSED_PENDING_EVIDENCE":
            if LEVELS[expected_level] < LEVELS["L2"]:
                raise CandidateError(
                    f"pending source gap has an invalid exit level: {identifier}"
                )
            remaining = item.get("remaining_evidence")
            if (
                not isinstance(remaining, list)
                or not remaining
                or not all(isinstance(value, str) and value.strip() for value in remaining)
            ):
                raise CandidateError(
                    f"pending source gap has no remaining evidence: {identifier}"
                )
            if "evidence" in item:
                raise CandidateError(
                    f"pending source gap carries environment evidence: {identifier}"
                )
        elif state == "EXTERNAL_HOLD":
            materials = item.get("required_material")
            authorities = item.get("required_authority")
            valid_materials = isinstance(materials, list) and bool(materials) and all(
                isinstance(value, str) and value.strip() for value in materials
            )
            valid_authorities = isinstance(authorities, list) and bool(authorities) and all(
                isinstance(value, str) and value.strip() for value in authorities
            )
            if not (valid_materials or valid_authorities):
                raise CandidateError(
                    f"external hold has no required material or authority: {identifier}"
                )
            if "evidence" in item:
                raise CandidateError(
                    f"external hold carries environment evidence: {identifier}"
                )
        elif state == "CLOSED":
            if item.get("requires_external_evidence") is True:
                _validate_environment_evidence(
                    item.get("evidence"), identifier, expected_level, source
                )
            elif expected_level != "L1" or item.get("evidence") not in (None, []):
                raise CandidateError(
                    f"source-only closure carries invalid external evidence: {identifier}"
                )

    if source_identity is None:
        raise CandidateError("canonical gap register has no source evidence")
    expected = set(CANONICAL_GAP_SPECS)
    if seen != expected:
        missing = ", ".join(sorted(expected - seen))
        extra = ", ".join(sorted(seen - expected))
        detail = []
        if missing:
            detail.append(f"missing {missing}")
        if extra:
            detail.append(f"unknown {extra}")
        raise CandidateError("gap register does not contain the canonical R6 set: " + "; ".join(detail))
    order = gaps.get("priority_order")
    if order != [item["id"] for item in entries]:
        raise CandidateError("gap register priority_order does not match entries")
    policy = gaps.get("generated_policy")
    if not isinstance(policy, dict):
        raise CandidateError("gap register generated_policy must be an object")
    if policy.get("checked_in_status_is_claim_policy_not_exact_head_evidence") is not True:
        raise CandidateError(
            "gap register must mark checked-in status as claim policy only"
        )
    if policy.get("exact_head_evidence_must_be_ci_generated") is not True:
        raise CandidateError(
            "gap register must require CI-generated exact-head evidence"
        )
    if policy.get("automatic_redispatch") is not False:
        raise CandidateError("gap register automatic_redispatch must remain false")
    if policy.get("public_release") is not False:
        raise CandidateError("L1 source candidate cannot claim public release")
    if state_counts["OPEN"]:
        raise CandidateError("L1 source candidate cannot contain OPEN gaps")
    if status.get("zero_gap") is not False:
        raise CandidateError("L1 source candidate must retain zero_gap=false")

    # The checked-in status is historical metadata, but if it carries a
    # candidate identity it must describe the same reviewed source evidence as
    # the gap register.  A mismatched identity would let one file silently
    # replace the other in a resume/promotion handoff.
    actual = source_identity[:4]
    status_candidate = _optional_candidate_identity(
        status.get("current_candidate"), "status.current_candidate"
    )
    if status_candidate is not None and status_candidate != actual:
        for field, expected, observed in zip(
            ("branch", "commit", "tree", "workflow_run_id"), actual, status_candidate
        ):
            if expected != observed:
                raise CandidateError(
                    f"status.current_candidate.{field} is not bound to gap source evidence"
                )
    development_branch = status.get("development_branch")
    if development_branch is not None and development_branch != source_identity[0]:
        raise CandidateError("status development_branch is not bound to source evidence")
    documentation_candidate = _optional_candidate_identity(
        gaps.get("documentation_candidate"), "documentation_candidate"
    )
    if documentation_candidate is not None and documentation_candidate != actual:
        for field, expected, observed in zip(
            ("branch", "commit", "tree", "workflow_run_id"), actual, documentation_candidate
        ):
            if expected != observed:
                raise CandidateError(
                    f"documentation_candidate.{field} is not bound to gap source evidence"
                )
    return source_identity


def build_candidate(
    root: Path,
    *,
    repository: str,
    source_head_sha: str,
    source_head_ref: str,
    workflow_trigger_sha: str,
    pull_request_base_sha: str | None,
    event_name: str,
    workflow_name: str,
    workflow_run_id: int,
    workflow_run_attempt: int,
) -> dict[str, Any]:
    root = root.resolve()
    source_head_sha = _sha_or_none(source_head_sha, "source_head_sha") or ""
    workflow_trigger_sha = (
        _sha_or_none(workflow_trigger_sha, "workflow_trigger_sha") or ""
    )
    pull_request_base_sha = _sha_or_none(
        pull_request_base_sha, "pull_request_base_sha"
    )
    if not repository or "/" not in repository:
        raise CandidateError("repository must be owner/name")
    if not source_head_ref:
        raise CandidateError("source_head_ref is empty")
    if workflow_run_id <= 0 or workflow_run_attempt <= 0:
        raise CandidateError("workflow run identity must be positive")

    tree_sha = _validate_checkout(root, source_head_sha)

    status = _read_object(root / STATUS)
    if status.get("schema") != EXPECTED_STATUS_SCHEMA:
        raise CandidateError("status schema is not the active R5 status schema")
    gaps = _read_object(root / GAPS)
    if status.get("active_plan_revision") != gaps.get("revision"):
        raise CandidateError("status and gap-register active revisions differ")
    _validate_canonical_gap_register(gaps, status)
    payload = {
        "schema": SCHEMA,
        "repository": repository,
        "source_head_ref": source_head_ref,
        "source_head_commit": source_head_sha,
        "source_head_tree": tree_sha,
        "checkout_mode": "exact_source_head",
        "workflow_event": event_name,
        "workflow_trigger_sha": workflow_trigger_sha,
        "pull_request_base_sha": pull_request_base_sha,
        "workflow": workflow_name,
        "workflow_run_id": workflow_run_id,
        "workflow_run_attempt": workflow_run_attempt,
        "required_jobs": {
            "l1_graph_docs_python": "success",
            "l1_rust": "success",
        },
        "tracked_worktree_clean": True,
        "graph_contract_revision": status.get("graph_contract_revision"),
        "active_plan_revision": status.get("active_plan_revision"),
        "gap_register_revision": gaps.get("revision"),
        "zero_gap": status.get("zero_gap"),
        "public_release": status.get("public_release"),
        "automatic_redispatch": status.get("automatic_redispatch"),
        "claim_ceiling": status.get("claim_ceiling"),
        "cargo_lock_sha256": _sha256(root / LOCK),
        "negative_claims": status.get("not_claimed"),
        "evidence_level": "L1",
        "result": "L1_SOURCE_CLOSURE_PASSED",
    }
    if payload["active_plan_revision"] != gaps.get("revision"):
        raise CandidateError("status and gap-register active revisions differ")
    if payload["active_plan_revision"] != EXPECTED_GAP_REVISION:
        raise CandidateError("active plan revision is not the canonical R6 revision")
    if payload["claim_ceiling"] != EXPECTED_CLAIM_CEILING:
        raise CandidateError(
            "source candidate claim ceiling is not the canonical exact-source ceiling"
        )
    if payload["zero_gap"] is not False:
        raise CandidateError("L1 source candidate must retain zero_gap=false")
    if payload["public_release"] is not False:
        raise CandidateError("L1 source candidate must retain public_release=false")
    if payload["automatic_redispatch"] is not False:
        raise CandidateError("automatic_redispatch must remain false")
    negative = payload["negative_claims"]
    if not isinstance(negative, list) or not negative:
        raise CandidateError("negative_claims must be a non-empty list")
    return payload


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-head-sha", required=True)
    parser.add_argument("--source-head-ref", required=True)
    parser.add_argument("--workflow-trigger-sha", required=True)
    parser.add_argument("--pull-request-base-sha")
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--workflow-name", required=True)
    parser.add_argument("--workflow-run-id", required=True, type=int)
    parser.add_argument("--workflow-run-attempt", required=True, type=int)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        payload = build_candidate(
            args.root,
            repository=args.repository,
            source_head_sha=args.source_head_sha,
            source_head_ref=args.source_head_ref,
            workflow_trigger_sha=args.workflow_trigger_sha,
            pull_request_base_sha=args.pull_request_base_sha,
            event_name=args.event_name,
            workflow_name=args.workflow_name,
            workflow_run_id=args.workflow_run_id,
            workflow_run_attempt=args.workflow_run_attempt,
        )
        _write_output(
            args.root,
            args.output,
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
        )
    except (CandidateError, OSError) as error:
        print(f"ERROR: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
