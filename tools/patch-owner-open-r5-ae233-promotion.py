#!/usr/bin/env python3
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

ROOT = Path.cwd()
BRANCH = "codex/owner-open-r5-gap-closure-20260829"
SOURCE_COMMIT = "ae2335814b61fc3c5a472d3a207fdb876f9e620c"
SOURCE_TREE = "7e098821b947716cc96c77581259c5422b8b8654"
WORKFLOW_RUN_ID = 33283935102
CLAIM_CEILING = "EXACT_COMMIT_SOURCE_GATES_PASSED_NOT_INSTALLED_CODEX"
ARTIFACTS = [
    {
        "id": 9723810264,
        "name": f"owner-open-r5-l1-graph-docs-python-{SOURCE_COMMIT}",
        "digest": "sha256:0176d8753ea6bed28a585e0d46004dd19bde2852335292e2394fad820b9fb62f",
    },
    {
        "id": 9723815400,
        "name": f"owner-open-r5-l1-rust-{SOURCE_COMMIT}",
        "digest": "sha256:e2844b373ad2613012099b64a43b77a13281363d61b953843b1e5dccab15f88f",
    },
    {
        "id": 9723817403,
        "name": f"owner-open-r5-l1-candidate-{SOURCE_COMMIT}",
        "digest": "sha256:8b86b72774b3281829eb3c6ae4cf4d352965bca2957ad0f12962a7cbe7d89ba4",
    },
]
SOURCE_EVIDENCE = {
    "level": "L1",
    "branch": BRANCH,
    "commit": SOURCE_COMMIT,
    "tree": SOURCE_TREE,
    "workflow_run_id": WORKFLOW_RUN_ID,
    "successful_jobs": [
        "L1 graph, documentation, broker and MCP source closure",
        "L1 Rust 1.93 selected Host, job, flow and recovery closure",
        "L1 exact-source-head aggregate candidate",
    ],
    "artifacts": ARTIFACTS,
}


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def patch_gap_register() -> None:
    path = ROOT / "docs/status/owner-open-r5-gap-closure.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["documentation_candidate"].update(
        {
            "state": "EXACT_SOURCE_HEAD_L1_PASSED",
            "evidence_level": "L1",
            "validated_source_commit": SOURCE_COMMIT,
            "validated_source_tree": SOURCE_TREE,
            "workflow_run_id": WORKFLOW_RUN_ID,
            "checked_in_promotion_requires_new_exact_head_ci": True,
        }
    )
    for gap in value["gaps"]:
        if "source_evidence" in gap:
            gap["source_evidence"] = deepcopy(SOURCE_EVIDENCE)
    write_json(path, value)


def patch_status() -> None:
    path = ROOT / "docs/status/owner-open-r5-status.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["updated_at"] = "2026-08-30"
    value["product_claim"] = (
        f"Exact source commit {SOURCE_COMMIT} and tree {SOURCE_TREE} passed all sixteen permanent "
        "pull-request workflows, including the repaired durable job restart handoff, the permanent "
        "L1 source/gap workflow, source slices, foundation, release-path, product-entrypoint, ADB, "
        "Android source-profile and Root-Linux packaging gates. Job admission is CLOSED at L1. "
        "Process lifecycle, stream recovery, journal convergence, Broker correlation and product "
        "entrypoint are source-closed but still require their declared L2-L5 target evidence. "
        "Repository governance, installed Codex, Root Linux placement, Android image, physical ADB, "
        "destructive faults and public release remain explicit holds."
    )
    value["claim_ceiling"] = CLAIM_CEILING
    value["current_candidate"].update(
        {
            "status": "HOST_TESTED",
            "latest_evidence_level": "L1",
            "validated_source_commit": SOURCE_COMMIT,
            "validated_source_tree": SOURCE_TREE,
            "workflow_run_id": WORKFLOW_RUN_ID,
            "exact_head_validation_pending": False,
            "must_not_inherit_baseline_l1": False,
            "promotion_commit_requires_new_exact_head_ci": True,
        }
    )
    for hold in value.get("external_evidence_holds", []):
        hold["source_evidence_commit"] = SOURCE_COMMIT
    value["known_exact_candidate"] = {
        "status": "HOST_TESTED",
        "evidence_level": "L1",
        "branch": BRANCH,
        "commit": SOURCE_COMMIT,
        "tree": SOURCE_TREE,
        "workflow_run_id": WORKFLOW_RUN_ID,
        "successful_jobs": list(SOURCE_EVIDENCE["successful_jobs"]),
        "artifacts": deepcopy(ARTIFACTS),
        "claim_ceiling": CLAIM_CEILING,
    }
    write_json(path, value)


def patch_entry_docs() -> None:
    plan_path = ROOT / "docs/TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md"
    plan = plan_path.read_text(encoding="utf-8")
    old_run = "candidate evidence: L1 exact-source run 33282230585"
    new_run = f"candidate evidence: L1 exact-source run {WORKFLOW_RUN_ID}"
    if old_run not in plan:
        raise SystemExit("expected previous exact-source run not found in active plan")
    plan_path.write_text(plan.replace(old_run, new_run), encoding="utf-8")

    start_path = ROOT / "docs/OWNER_OPEN_R5_START_HERE.md"
    start = start_path.read_text(encoding="utf-8")
    old_source = (
        "Documentation candidate evidence: **HOST_TESTED / L1 at exact source "
        "`c8790b6b5d0e59dff74f527db1d1173d4a2fb043`**"
    )
    new_source = (
        "Documentation candidate evidence: **HOST_TESTED / L1 at exact source "
        f"`{SOURCE_COMMIT}`**"
    )
    if old_source not in start:
        raise SystemExit("expected previous exact-source identity not found in Start Here")
    start_path.write_text(start.replace(old_source, new_source), encoding="utf-8")


def write_evidence_doc() -> None:
    path = ROOT / "docs/status/owner-open-r5-source-closure-evidence-2026-08-29.md"
    path.write_text(
        f"""# Owner-Open R5 exact-source-head L1 closure evidence

Status: **Repaired exact source passed all permanent L1 and repository workflows; target, device, destructive-fault and release evidence remains open.**

## Current exact source identity

| Field | Value |
| --- | --- |
| Repository | `TrillionniumFoundation/trillionnium-os` |
| Branch | `{BRANCH}` |
| Source commit | `{SOURCE_COMMIT}` |
| Source tree | `{SOURCE_TREE}` |
| Permanent workflow | `L1 owner-open R5 source and gap closure` |
| Workflow run | `{WORKFLOW_RUN_ID}` |
| Result | `L1_SOURCE_CLOSURE_PASSED` |
| All permanent PR workflows | `16/16 success` |
| Claim ceiling | `{CLAIM_CEILING}` |
| Cargo.lock SHA-256 | `a469d72776978b143f47ba71904325404dc77307b25374214e6dd321147b99a0` |

The permanent workflow checked out the pull-request source head rather than GitHub's synthetic merge
commit. The exact source passed graph/document verification, gap/evidence mutation tests, Broker and MCP
fixtures, locked Rust 1.93 formatting/tests/strict Clippy, product-entrypoint checks, release mechanics,
ADB relay checks, Android source-profile checks, Root-Linux packaging checks and the foundation suite.

## Bound artifacts

| Artifact ID | Name | SHA-256 digest |
| --- | --- | --- |
| `9723810264` | `owner-open-r5-l1-graph-docs-python-{SOURCE_COMMIT}` | `sha256:0176d8753ea6bed28a585e0d46004dd19bde2852335292e2394fad820b9fb62f` |
| `9723815400` | `owner-open-r5-l1-rust-{SOURCE_COMMIT}` | `sha256:e2844b373ad2613012099b64a43b77a13281363d61b953843b1e5dccab15f88f` |
| `9723817403` | `owner-open-r5-l1-candidate-{SOURCE_COMMIT}` | `sha256:8b86b72774b3281829eb3c6ae4cf4d352965bca2957ad0f12962a7cbe7d89ba4` |

## Durable restart race closure

A previous exact-head run exposed an intermittent same-process writer-lease handoff race in
`completed_durable_job_never_spawns_again_after_manager_restart`. The implementation removes the
redundant post-publication terminal write; the canonical terminal observation and `job.terminal` record
remain atomically durable before terminal visibility. The regression waits only for the old dispatcher
to release its writer lease and still proves the recovered terminal prevents a second spawn.

Repair commit `50e33e3643501fae4f2ce2107ac5bf15f0bbb3ab` was validated by one-shot run `33283826378` with 50
exact regression repetitions, all workspace tests, strict Clippy, all canonical R5 verifiers and all
Python tests. The repaired human-authored exact head above then passed all sixteen permanent PR
workflows, so no historical L1 result is inherited.

## Source identity versus promotion head

`{SOURCE_COMMIT}` / `{SOURCE_TREE}` is the immutable qualified source identity. A later state-only
promotion commit may update machine status or import independently reviewed evidence without changing
that source pair. It must pass its own repository checks and may not inherit qualification after source,
Cargo, contract, tool or workflow drift.

External evidence bundles must bind their `source_commit` and `source_tree` to this exact pair. The
promotion script rejects a bundle whose source identity differs from the machine gap register.

## Gap transitions

- `R5-GAP-JOB-ADMISSION-001` is **CLOSED at L1**.
- Process lifecycle, stream recovery, journal convergence, Broker correlation and product entrypoint
  are **SOURCE_CLOSED_PENDING_EVIDENCE** and retain their declared L2-L5 exits.
- Repository governance is **EXTERNAL_HOLD** until protected-main enforcement and an independent
  current-head approval exist.
- Installed Codex, Root Linux placement, Android image, physical ADB, destructive faults and public
  release remain **EXTERNAL_HOLD** until their real target or authority evidence exists.

## Non-claims

This evidence does not prove installation, target UID/GID or namespace placement, Android image
inclusion, physical effects, destructive recovery qualification, signed release, protected-main
configuration or zero-gap completion. `zero_gap=false`, `public_release=false` and
`automatic_redispatch=false` remain mandatory.
""",
        encoding="utf-8",
    )


def main() -> None:
    patch_gap_register()
    patch_status()
    patch_entry_docs()
    write_evidence_doc()


if __name__ == "__main__":
    main()
