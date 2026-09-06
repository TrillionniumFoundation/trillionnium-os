"""Review-index extensions for the legacy aggregate fixture."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json


def prepare_review_index(fixture) -> None:
    fixture.review_index_path = "governance/pr41-review-index.v1.json"
    paths = ["README.md", fixture.review_index_path]
    changes = [
        {"path": "README.md", "status": "modified", "previous_path": None},
        {"path": fixture.review_index_path, "status": "added", "previous_path": None},
    ]
    fixture.review_index_paths_sha = hashlib.sha256(
        b"".join(path.encode("utf-8") + b"\0" for path in sorted(paths))
    ).hexdigest()
    fixture.review_index_changes_sha = hashlib.sha256(
        b"".join(
            json.dumps(
                item,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii") + b"\n"
            for item in sorted(changes, key=lambda item: item["path"])
        )
    ).hexdigest()
    index = {
        "schema": "org.trillionnium.g1-pr-review-index.v1",
        "program_revision": fixture.AGG.PROGRAM_REVISION if hasattr(fixture, "AGG") else "2026-08-31-g1",
        "repository": fixture.repo,
        "pull_request": fixture.pr_number,
        "base": {"commit": fixture.base_commit, "tree": fixture.base_tree},
        "review_predecessor": {"commit": fixture.base_commit, "tree": fixture.base_tree},
        "head_binding": "LIVE_PR_EXACT_HEAD_NO_SELF_REFERENCE",
        "expected": {
            "path_count": len(paths),
            "paths_sha256": fixture.review_index_paths_sha,
            "change_count": len(changes),
            "changes_sha256": fixture.review_index_changes_sha,
        },
        "changed_paths": sorted(paths),
        "changes": sorted(changes, key=lambda item: item["path"]),
        "slices": [
            {
                "id": "aggregate-fixture",
                "security_domain": "test-fixture",
                "accountable_owner": "fixture-owner",
                "independent_reviewers": ["fixture-reviewer"],
                "review_order": 1,
                "paths": sorted(paths),
            }
        ],
        "claim_ceiling": "CLOSED_WORLD_REVIEW_INDEX_ONLY_NO_APPROVAL_OR_INTEGRATION_AUTHORITY",
        "automatic_redispatch": False,
        "integration_authorized": False,
        "promotion_authorized": False,
        "public_release": False,
    }
    path = fixture.repo_root / fixture.review_index_path
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    fixture._git("add", fixture.review_index_path)
    fixture._git("commit", "--amend", "--no-edit")
    fixture.head_commit = fixture._git("rev-parse", "HEAD")
    fixture.head_tree = fixture._git("rev-parse", "HEAD^{tree}")
    fixture.review_index_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    fixture.review_index_path_count = len(paths)
    fixture.review_index_change_count = len(changes)


def augment_review_fixture(fixture, agg) -> None:
    run = fixture._run(
        1004,
        "G1 exact-head and synthetic-merge review-index receipts",
        "g1-review-index-receipts.yml",
    )
    query = f"event=pull_request&head_sha={fixture.head_commit}&per_page=100"
    fixture.values[
        f"repos/{fixture.repo}/actions/workflows/g1-review-index-receipts.yml/runs?{query}"
    ] = {"total_count": 1, "workflow_runs": [run]}
    requirement = next(item for item in agg.REQUIREMENTS if item.artifact_kind == "review_index")
    fixture.values[
        f"repos/{fixture.repo}/actions/runs/1004/jobs?filter=latest&per_page=100"
    ] = fixture._jobs(1004, set(requirement.job_names))

    common = {
        "schema": "org.trillionnium.g1-review-index-receipt.v1",
        "program_revision": agg.PROGRAM_REVISION,
        "repository": fixture.repo,
        "pull_request_number": fixture.pr_number,
        "base_commit": fixture.base_commit,
        "base_tree": fixture.base_tree,
        "head_commit": fixture.head_commit,
        "head_tree": fixture.head_tree,
        "review_index_path": fixture.review_index_path,
        "review_index_sha256": fixture.review_index_sha,
        "path_count": fixture.review_index_path_count,
        "paths_sha256": fixture.review_index_paths_sha,
        "change_count": fixture.review_index_change_count,
        "changes_sha256": fixture.review_index_changes_sha,
        "workflow_run_id": "1004",
        "workflow_attempt": "1",
        "claim_ceiling": "CLOSED_WORLD_REVIEW_INDEX_RECEIPT_ONLY_NO_APPROVAL_OR_INTEGRATION_AUTHORITY",
        "automatic_redispatch": False,
        "integration_authorized": False,
        "promotion_authorized": False,
        "public_release": False,
    }
    exact = {
        **common,
        "subject_kind": "exact_head",
        "parent_commits": [],
        "merge_commit": None,
        "merge_tree": None,
        "result": "L1_EXACT_HEAD_REVIEW_INDEX_BOUND",
    }
    synthetic = {
        **common,
        "subject_kind": "synthetic_merge",
        "parent_commits": [fixture.base_commit, fixture.head_commit],
        "merge_commit": "9" * 40,
        "merge_tree": fixture.head_tree,
        "result": "L1_SYNTHETIC_MERGE_REVIEW_INDEX_BOUND",
    }
    fixture.exact_review_receipt = deepcopy(exact)
    fixture.synthetic_review_receipt = deepcopy(synthetic)
    raw = fixture._zip(
        {
            "g1-exact-head-review-index-receipt.json": exact,
            "g1-synthetic-merge-review-index-receipt.json": synthetic,
        }
    )
    artifact = fixture._artifact(
        2006,
        1004,
        f"g1-review-index-receipts-{fixture.head_commit}",
        raw,
    )
    fixture.values[f"repos/{fixture.repo}/actions/runs/1004/artifacts?per_page=100"] = {
        "artifacts": [artifact]
    }
