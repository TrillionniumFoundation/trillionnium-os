"""Closed-world review-index receipts for exact-head and synthetic subjects."""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from tools.g1_pr_aggregate_common import (
    PROGRAM_REVISION,
    _git_sha,
    _identifier,
    _mapping,
    _positive_int,
    _require,
    _sha256,
)
from tools.g1_pr_aggregate_model import Subject

REVIEW_INDEX_PATH = "governance/pr41-review-index.v1.json"
CLAIM_CEILING = "CLOSED_WORLD_REVIEW_INDEX_RECEIPT_ONLY_NO_APPROVAL_OR_INTEGRATION_AUTHORITY"


def _common(value: Any, subject: Subject, run: Mapping[str, Any], label: str) -> tuple[Mapping[str, Any], dict[str, Any]]:
    receipt = _mapping(value, label)
    required = {
        "schema", "program_revision", "subject_kind", "repository",
        "pull_request_number", "base_commit", "base_tree", "head_commit",
        "head_tree", "parent_commits", "merge_commit", "merge_tree",
        "review_index_path", "review_index_sha256", "path_count",
        "paths_sha256", "change_count", "changes_sha256",
        "workflow_run_id", "workflow_attempt", "result", "claim_ceiling",
        "automatic_redispatch", "integration_authorized",
        "promotion_authorized", "public_release",
    }
    _require(set(receipt) == required, f"{label} keys drifted")
    _require(receipt["schema"] == "org.trillionnium.g1-review-index-receipt.v1", f"{label} schema drifted")
    _require(receipt["program_revision"] == PROGRAM_REVISION, f"{label} program revision drifted")
    _require(receipt["repository"] == subject.repository, f"{label} repository mismatch")
    _require(str(receipt["pull_request_number"]) == str(subject.pr_number), f"{label} PR number mismatch")
    _require(receipt["base_commit"] == subject.base_commit and receipt["base_tree"] == subject.base_tree, f"{label} base identity mismatch")
    _require(receipt["head_commit"] == subject.head_commit and receipt["head_tree"] == subject.head_tree, f"{label} head identity mismatch")
    _require(receipt["review_index_path"] == REVIEW_INDEX_PATH, f"{label} review-index path drifted")
    index_sha = _sha256(receipt["review_index_sha256"], f"{label} review-index digest")
    path_count = _positive_int(receipt["path_count"], f"{label} path count")
    paths_sha = _sha256(receipt["paths_sha256"], f"{label} paths digest")
    change_count = _positive_int(receipt["change_count"], f"{label} change count")
    changes_sha = _sha256(receipt["changes_sha256"], f"{label} changes digest")
    _require(path_count == change_count, f"{label} path/change counts differ")
    _require(str(receipt["workflow_run_id"]) == str(run["id"]), f"{label} workflow run mismatch")
    _require(str(receipt["workflow_attempt"]) == str(run["run_attempt"]), f"{label} workflow attempt mismatch")
    _require(receipt["claim_ceiling"] == CLAIM_CEILING, f"{label} claim ceiling widened")
    for field in (
        "automatic_redispatch", "integration_authorized",
        "promotion_authorized", "public_release",
    ):
        _require(receipt[field] is False, f"{label} {field} must remain false")
    return receipt, {
        "review_index_path": REVIEW_INDEX_PATH,
        "review_index_sha256": index_sha,
        "review_index_path_count": path_count,
        "review_index_paths_sha256": paths_sha,
        "review_index_change_count": change_count,
        "review_index_changes_sha256": changes_sha,
    }


def validate_review_receipts(
    exact_value: Any,
    synthetic_value: Any,
    subject: Subject,
    run: Mapping[str, Any],
) -> dict[str, Any]:
    exact, binding = _common(exact_value, subject, run, "exact-head review-index receipt")
    _require(exact["subject_kind"] == "exact_head", "exact-head receipt subject kind drifted")
    _require(exact["parent_commits"] == [], "exact-head receipt unexpectedly has parents")
    _require(exact["merge_commit"] is None and exact["merge_tree"] is None, "exact-head receipt unexpectedly has merge identity")
    _require(exact["result"] == "L1_EXACT_HEAD_REVIEW_INDEX_BOUND", "exact-head review-index receipt result is not a pass")

    synthetic, synthetic_binding = _common(
        synthetic_value, subject, run, "synthetic-merge review-index receipt"
    )
    _require(synthetic_binding == binding, "exact-head and synthetic review-index bindings differ")
    _require(synthetic["subject_kind"] == "synthetic_merge", "synthetic receipt subject kind drifted")
    _require(synthetic["parent_commits"] == [subject.base_commit, subject.head_commit], "synthetic review-index receipt parent order mismatch")
    merge_commit = _git_sha(synthetic["merge_commit"], "synthetic review-index merge commit")
    merge_tree = _git_sha(synthetic["merge_tree"], "synthetic review-index merge tree")
    _require(merge_commit not in {subject.base_commit, subject.head_commit}, "synthetic review-index merge commit aliases a parent")
    _require(merge_tree == subject.head_tree, "synthetic review-index merge tree differs from exact head tree")
    _require(synthetic["result"] == "L1_SYNTHETIC_MERGE_REVIEW_INDEX_BOUND", "synthetic review-index receipt result is not a pass")
    return {**binding, "review_merge_commit": merge_commit, "review_merge_tree": merge_tree}


def select_review_artifact(
    artifacts: Sequence[Mapping[str, Any]], subject: Subject
) -> dict[str, Mapping[str, Any]]:
    by_name = {
        _identifier(item.get("name"), "review-index artifact name"): item
        for item in artifacts
    }
    _require(len(by_name) == len(artifacts), "review-index artifact names are not unique")
    expected = f"g1-review-index-receipts-{subject.head_commit}"
    _require(set(by_name) == {expected}, "review-index workflow must emit exactly one exact-head-bound artifact")
    return {expected: by_name[expected]}
