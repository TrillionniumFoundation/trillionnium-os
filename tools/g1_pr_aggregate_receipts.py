"""Semantic validators for synthetic, Android and evidence receipts."""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from tools.g1_pr_aggregate_common import (
    PROGRAM_REVISION,
    _canonical,
    _digest,
    _git_sha,
    _identifier,
    _mapping,
    _require,
    _sha256,
)
from tools.g1_pr_aggregate_model import Subject, WorkflowRequirement

def _validate_synthetic_receipt(value: Any, subject: Subject, run: Mapping[str, Any]) -> dict[str, Any]:
    receipt = _mapping(value, "synthetic merge receipt")
    required = {
        "schema", "program_revision", "repository", "head_repository", "event_name",
        "pull_request_number", "base_ref", "head_ref", "base_commit", "base_tree",
        "head_commit", "head_tree", "parent_commits", "merge_commit", "merge_tree",
        "cargo_lock_sha256", "workflow_run_id", "workflow_attempt", "result",
        "claim_ceiling", "automatic_redispatch", "public_release",
    }
    _require(set(receipt) == required, "synthetic merge receipt keys drifted")
    _require(receipt["schema"] == "org.trillionnium.g1-synthetic-merge-evidence.v1", "synthetic receipt schema drifted")
    _require(receipt["program_revision"] == PROGRAM_REVISION, "synthetic receipt program revision drifted")
    _require(receipt["repository"] == subject.repository, "synthetic receipt repository mismatch")
    _require(receipt["head_repository"] == subject.head_repository, "synthetic receipt head repository mismatch")
    _require(receipt["event_name"] == "pull_request", "synthetic receipt event is not pull_request")
    _require(str(receipt["pull_request_number"]) == str(subject.pr_number), "synthetic receipt PR number mismatch")
    _require(receipt["base_ref"] == subject.base_ref and receipt["head_ref"] == subject.head_ref, "synthetic receipt refs mismatch")
    _require(receipt["base_commit"] == subject.base_commit and receipt["base_tree"] == subject.base_tree, "synthetic receipt base identity mismatch")
    _require(receipt["head_commit"] == subject.head_commit and receipt["head_tree"] == subject.head_tree, "synthetic receipt head identity mismatch")
    _require(receipt["parent_commits"] == [subject.base_commit, subject.head_commit], "synthetic receipt parent order mismatch")
    merge_commit = _git_sha(receipt["merge_commit"], "synthetic receipt merge commit")
    merge_tree = _git_sha(receipt["merge_tree"], "synthetic receipt merge tree")
    _require(merge_commit not in {subject.base_commit, subject.head_commit}, "synthetic receipt merge commit aliases a parent")
    _require(merge_tree == subject.head_tree, "canonical fast-forward source stack produced an unexpected merge tree")
    _sha256(receipt["cargo_lock_sha256"], "synthetic receipt Cargo.lock digest")
    _require(str(receipt["workflow_run_id"]) == str(run["id"]), "synthetic receipt workflow run mismatch")
    _require(str(receipt["workflow_attempt"]) == str(run["run_attempt"]), "synthetic receipt workflow attempt mismatch")
    _require(receipt["result"] == "L1_SYNTHETIC_MERGE_SOURCE_CLOSURE_PASSED", "synthetic receipt result is not a pass")
    _require(receipt["claim_ceiling"] == "EXACT_TWO_PARENT_SOURCE_MERGE_GATES_PASSED_NOT_INSTALLED_TARGET", "synthetic receipt claim ceiling widened")
    _require(receipt["automatic_redispatch"] is False and receipt["public_release"] is False, "synthetic receipt must retain no-redispatch/no-release")
    return {"merge_commit": merge_commit, "merge_tree": merge_tree, "cargo_lock_sha256": receipt["cargo_lock_sha256"]}


def _validate_android_receipt(
    value: Any,
    *,
    subject: Subject,
    evaluation_kind: str,
    expected_merge_tree: str,
) -> dict[str, Any]:
    receipt = _mapping(value, f"Android {evaluation_kind} receipt")
    _require(receipt.get("schema") == "org.trillionnium.owner-open.adbroot-evaluated-graph.v1", "Android receipt schema drifted")
    _require(receipt.get("program_revision") == PROGRAM_REVISION, "Android receipt program revision drifted")
    _require(receipt.get("repository") == subject.repository, "Android receipt repository mismatch")
    _require(receipt.get("source_commit") == subject.head_commit, "Android receipt source commit mismatch")
    _require(receipt.get("evaluation_kind") == evaluation_kind, "Android receipt evaluation kind mismatch")
    _require(receipt.get("matrix_case_count") == 12, "Android matrix case count drifted")
    _require(receipt.get("negative_case_count") == 10 and receipt.get("negative_cases_passed") is True, "Android negative matrix is incomplete")
    _require(receipt.get("source_inputs_complete") is True, "Android source inputs are incomplete")
    _require(receipt.get("service_policy_property_coupled") is True, "Android service/policy/property coupling is incomplete")
    for field in ("soong_compiled", "selinux_compiled", "target_files_built", "image_built", "installed", "physical_device_observed", "automatic_redispatch", "public_release"):
        _require(receipt.get(field) is False, f"Android receipt {field} must remain false at this evidence level")
    _require(receipt.get("claim_ceiling") == "EVALUATED_SECURITY_ANDROID_GRAPH_ONLY_NOT_SOONG_OR_SELINUX_COMPILED", "Android receipt claim ceiling widened")
    evaluated_commit = _git_sha(receipt.get("evaluated_commit"), "Android evaluated commit")
    evaluated_tree = _git_sha(receipt.get("evaluated_tree"), "Android evaluated tree")
    parents = receipt.get("parent_commits")
    if evaluation_kind == "source_head":
        _require(receipt.get("base_commit") is None, "source-head Android receipt unexpectedly has a base commit")
        _require(parents == [], "source-head Android receipt unexpectedly has parents")
        _require(evaluated_commit == subject.head_commit and evaluated_tree == subject.head_tree, "source-head Android identity mismatch")
    else:
        _require(receipt.get("base_commit") == subject.base_commit, "merge Android receipt base mismatch")
        _require(parents == [subject.base_commit, subject.head_commit], "merge Android receipt parent order mismatch")
        _require(evaluated_commit not in {subject.base_commit, subject.head_commit}, "merge Android evaluated commit aliases a parent")
        _require(evaluated_tree == expected_merge_tree, "merge Android tree differs from qualified synthetic merge tree")
    receipt_digest = _sha256(receipt.get("receipt_sha256"), "Android receipt digest")
    clone = dict(receipt)
    clone["receipt_sha256"] = ""
    _require(_digest(_canonical(clone)) == receipt_digest, "Android receipt canonical digest mismatch")
    return {"evaluated_commit": evaluated_commit, "evaluated_tree": evaluated_tree, "receipt_sha256": receipt_digest}


def _validate_evidence_pair(report_value: Any, plan_value: Any, subject: Subject, label: str) -> dict[str, Any]:
    report = _mapping(report_value, f"{label} evidence report")
    plan = _mapping(plan_value, f"{label} promotion plan")
    _require(report.get("schema") == "org.trillionnium.g1.evidence-verification-report.v2", f"{label} report schema drifted")
    _require(report.get("program_revision") == PROGRAM_REVISION, f"{label} report program revision drifted")
    _require(report.get("current_source_commit") == subject.head_commit, f"{label} report source mismatch")
    _require(type(report.get("all_gaps_promotable")) is bool, f"{label} report all_gaps_promotable is invalid")
    _require(type(report.get("package_count")) is int and report["package_count"] >= 0, f"{label} report package_count is invalid")
    _require(isinstance(report.get("packages"), list), f"{label} report packages are invalid")
    _require(isinstance(report.get("promotable_gaps"), Mapping), f"{label} report promotable_gaps are invalid")
    _require(isinstance(report.get("unresolved_gaps"), list), f"{label} report unresolved_gaps are invalid")
    _require(report.get("automatic_redispatch") is False and report.get("public_release") is False, f"{label} report widened authority")
    _require(plan.get("schema") == "org.trillionnium.g1.gap-promotion-plan.v1", f"{label} plan schema drifted")
    _require(plan.get("program_revision") == PROGRAM_REVISION, f"{label} plan program revision drifted")
    _require(plan.get("current_source_commit") == subject.head_commit, f"{label} plan source mismatch")
    _require(isinstance(plan.get("transitions"), list) and isinstance(plan.get("unresolved_gaps"), list), f"{label} plan arrays are invalid")
    _require(type(plan.get("zero_gap_after_plan")) is bool, f"{label} plan zero_gap_after_plan is invalid")
    _require(plan.get("automatic_redispatch") is False and plan.get("public_release_after_plan") is False, f"{label} plan widened authority")
    gap_digest = _sha256(report.get("gap_specs_sha256"), f"{label} report gap_specs_sha256")
    _require(_sha256(plan.get("gap_specs_sha256"), f"{label} plan gap_specs_sha256") == gap_digest,
             f"{label} report/plan gap snapshot mismatch")
    _require(plan["unresolved_gaps"] == report["unresolved_gaps"],
             f"{label} report/plan unresolved gaps mismatch")
    _require(plan["zero_gap_after_plan"] == report["all_gaps_promotable"]
             == (not report["unresolved_gaps"]),
             f"{label} report/plan closure flags contradict unresolved gaps")
    return {
        "gap_specs_sha256": gap_digest,
        "package_count": report["package_count"],
        "all_gaps_promotable": report["all_gaps_promotable"],
        "transition_count": len(plan["transitions"]),
        "zero_gap_after_plan": plan["zero_gap_after_plan"],
    }


def _select_artifacts(
    artifacts: Sequence[Mapping[str, Any]],
    requirement: WorkflowRequirement,
    subject: Subject,
) -> dict[str, Mapping[str, Any]]:
    by_name = {_identifier(item.get("name"), "artifact name"): item for item in artifacts}
    _require(len(by_name) == len(artifacts), "artifact names are not unique")
    if requirement.artifact_kind == "synthetic":
        matches = {name: value for name, value in by_name.items() if name.startswith("g1-synthetic-merge-")}
        _require(len(matches) == 1 and len(by_name) == 1, "synthetic workflow must emit exactly one merge artifact")
        return matches
    if requirement.artifact_kind == "android":
        source_name = f"g1-adbroot-source-matrix-{subject.head_commit}"
        merge_matches = {name: value for name, value in by_name.items() if name.startswith("g1-adbroot-merge-matrix-")}
        _require(source_name in by_name and len(merge_matches) == 1 and len(by_name) == 2, "Android workflow artifact set is incomplete or ambiguous")
        return {source_name: by_name[source_name], **merge_matches}
    source_name = f"g1-evidence-source-{subject.head_commit}"
    merge_matches = {name: value for name, value in by_name.items() if name.startswith("g1-evidence-merge-")}
    _require(source_name in by_name and len(merge_matches) == 1 and len(by_name) == 2, "evidence workflow artifact set is incomplete or ambiguous")
    return {source_name: by_name[source_name], **merge_matches}


