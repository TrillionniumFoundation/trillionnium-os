"""Verify the one direct workflow consumed by the ordinary source gate."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from tools.g1_pr_aggregate_archive import (
    _RepoApi,
    _artifact_metadata,
    _download_artifact,
    _zip_json_members,
)
from tools.g1_pr_aggregate_common import _mapping, _positive_int, _require
from tools.g1_pr_aggregate_live import _verify_jobs
from tools.g1_pr_aggregate_model import Subject, WorkflowRequirement
from tools.g1_pr_aggregate_receipts import (
    _select_artifacts,
    _validate_synthetic_receipt,
)


def _verify_workflow(
    api: _RepoApi,
    requirement: WorkflowRequirement,
    run: Mapping[str, Any],
    subject: Subject,
    now: datetime,
    synthetic_state: dict[str, Any],
) -> dict[str, Any]:
    """Bind the exact successful prospective-merge source receipt.

    Promotion, review-index, Android target-evidence and release workflows are
    deliberately outside this ordinary source gate and therefore have no
    dormant import or dispatch path here.
    """
    _require(
        requirement.artifact_kind == "synthetic",
        "ordinary source aggregate accepts only synthetic source qualification",
    )
    run_id = _positive_int(run.get("id"), "workflow run id")
    _require(
        run.get("status") == "completed"
        and run.get("conclusion") == "success",
        f"latest {requirement.workflow_name} run is not terminal success",
    )
    attempt = _positive_int(
        run.get("run_attempt"), f"workflow run {run_id} attempt"
    )
    jobs = _verify_jobs(
        api,
        run_id,
        attempt,
        requirement.workflow_name,
        subject.head_commit,
        subject.head_ref,
        requirement.job_names,
    )
    artifacts, artifact_list_digest = _artifact_metadata(api, run, now)
    selected = _select_artifacts(artifacts, requirement, subject)

    artifact_reports: list[dict[str, Any]] = []
    for name, artifact in sorted(selected.items()):
        raw, metadata = _download_artifact(api, artifact)
        members = _zip_json_members(
            raw,
            frozenset(
                {
                    "g1-synthetic-merge-evidence.json",
                    "g1-merge-baseline.json",
                }
            ),
            name,
        )
        synthetic = _validate_synthetic_receipt(
            members["g1-synthetic-merge-evidence.json"],
            subject,
            run,
        )
        _require(
            name == f"g1-synthetic-merge-{synthetic['merge_commit']}",
            "synthetic artifact name is not commit-bound",
        )
        baseline = _mapping(
            members["g1-merge-baseline.json"],
            "synthetic baseline",
        )
        _require(
            baseline.get("qualification") == "SOURCE_EVIDENCE_ONLY",
            "synthetic baseline claim widened",
        )
        gate = _mapping(
            baseline.get("gate"), "synthetic baseline gate"
        )
        _require(
            gate.get("passed") is False,
            "host synthetic baseline cannot claim target qualification",
        )
        synthetic_state.update(synthetic)
        metadata["semantic"] = synthetic
        artifact_reports.append(metadata)

    return {
        "workflow": requirement.workflow_name,
        "path": requirement.path,
        "run_id": run_id,
        "run_attempt": attempt,
        "status": "completed",
        "conclusion": "success",
        "jobs": jobs,
        "artifacts": artifact_reports,
        "artifact_list_response_sha256": artifact_list_digest,
    }
