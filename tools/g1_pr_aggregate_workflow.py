"""Exact workflow-family, job-set, artifact-set and receipt verification."""
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
    _validate_android_receipt,
    _validate_evidence_pair,
    _validate_synthetic_receipt,
)
from tools.g1_pr_aggregate_review_receipts import (
    select_review_artifact,
    validate_review_receipts,
)

def _verify_workflow(
    api: _RepoApi,
    requirement: WorkflowRequirement,
    run: Mapping[str, Any],
    subject: Subject,
    now: datetime,
    synthetic_state: dict[str, Any],
) -> dict[str, Any]:
    run_id = _positive_int(run.get("id"), "workflow run id")
    _require(run.get("status") == "completed" and run.get("conclusion") == "success", f"latest {requirement.workflow_name} run is not terminal success")
    attempt = _positive_int(run.get("run_attempt"), f"workflow run {run_id} attempt")
    jobs = _verify_jobs(api, run_id, requirement.job_names)
    artifacts, artifact_list_digest = _artifact_metadata(api, run, now)
    selected = (
        select_review_artifact(artifacts, subject)
        if requirement.artifact_kind == "review_index"
        else _select_artifacts(artifacts, requirement, subject)
    )
    artifact_reports: list[dict[str, Any]] = []
    semantic: dict[str, Any] = {}
    for name, artifact in sorted(selected.items()):
        raw, metadata = _download_artifact(api, artifact)
        if requirement.artifact_kind == "review_index":
            members = _zip_json_members(
                raw,
                frozenset(
                    {
                        "g1-exact-head-review-index-receipt.json",
                        "g1-synthetic-merge-review-index-receipt.json",
                    }
                ),
                name,
            )
            receipt = validate_review_receipts(
                members["g1-exact-head-review-index-receipt.json"],
                members["g1-synthetic-merge-review-index-receipt.json"],
                subject,
                run,
            )
            synthetic_state.update(receipt)
            semantic = receipt
        elif requirement.artifact_kind == "synthetic":
            members = _zip_json_members(
                raw,
                frozenset({"g1-synthetic-merge-evidence.json", "g1-merge-baseline.json"}),
                name,
            )
            synthetic = _validate_synthetic_receipt(members["g1-synthetic-merge-evidence.json"], subject, run)
            _require(name == f"g1-synthetic-merge-{synthetic['merge_commit']}", "synthetic artifact name is not commit-bound")
            baseline = _mapping(members["g1-merge-baseline.json"], "synthetic baseline")
            _require(baseline.get("qualification") == "SOURCE_EVIDENCE_ONLY", "synthetic baseline claim widened")
            gate = _mapping(baseline.get("gate"), "synthetic baseline gate")
            _require(gate.get("passed") is False, "host synthetic baseline cannot claim target qualification")
            synthetic_state.update(synthetic)
            semantic = synthetic
        elif requirement.artifact_kind == "android":
            members = _zip_json_members(
                raw,
                frozenset({"g1-adbroot-source-matrix.json"}) if name.startswith("g1-adbroot-source-matrix-") else frozenset({"g1-adbroot-merge-matrix.json"}),
                name,
            )
            if name.startswith("g1-adbroot-source-matrix-"):
                receipt = _validate_android_receipt(
                    members["g1-adbroot-source-matrix.json"],
                    subject=subject,
                    evaluation_kind="source_head",
                    expected_merge_tree=synthetic_state["merge_tree"],
                )
                _require(name == f"g1-adbroot-source-matrix-{subject.head_commit}", "Android source artifact name is not head-bound")
            else:
                receipt = _validate_android_receipt(
                    members["g1-adbroot-merge-matrix.json"],
                    subject=subject,
                    evaluation_kind="synthetic_merge",
                    expected_merge_tree=synthetic_state["merge_tree"],
                )
                _require(name == f"g1-adbroot-merge-matrix-{receipt['evaluated_commit']}", "Android merge artifact name is not commit-bound")
            semantic[name] = receipt
        else:
            if name.startswith("g1-evidence-source-"):
                members = _zip_json_members(
                    raw,
                    frozenset({"g1-evidence-report.json", "g1-promotion-plan.json"}),
                    name,
                )
                receipt = _validate_evidence_pair(
                    members["g1-evidence-report.json"],
                    members["g1-promotion-plan.json"],
                    subject,
                    "source",
                )
            else:
                members = _zip_json_members(
                    raw,
                    frozenset({"g1-evidence-merge-report.json", "g1-evidence-merge-plan.json"}),
                    name,
                )
                receipt = _validate_evidence_pair(
                    members["g1-evidence-merge-report.json"],
                    members["g1-evidence-merge-plan.json"],
                    subject,
                    "merge",
                )
            semantic[name] = receipt
        metadata["semantic"] = receipt if requirement.artifact_kind != "synthetic" else semantic
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
