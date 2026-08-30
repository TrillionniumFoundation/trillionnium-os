#!/usr/bin/env python3
"""Bind canonical Owner-Open R5 machine truth to exact L1 source 60c6d158."""

from __future__ import annotations

import json
import os
import re
from copy import deepcopy
from pathlib import Path

ROOT = Path.cwd()
BRANCH = "codex/owner-open-r5-gap-closure-20260829"
SOURCE_COMMIT = "60c6d1581d2ef2a17cb8515bc27f6dd038f9d5b6"
SOURCE_TREE = "f0fac366e9959b4b471bc8cf3ccedcecfe5bd688"
WORKFLOW_RUN_ID = 33294911756
CLAIM_CEILING = "EXACT_COMMIT_SOURCE_GATES_PASSED_NOT_INSTALLED_CODEX"
CARGO_LOCK_SHA256 = "a469d72776978b143f47ba71904325404dc77307b25374214e6dd321147b99a0"
ARTIFACTS = [
    {
        "id": 9727099892,
        "name": f"owner-open-r5-l1-graph-docs-python-{SOURCE_COMMIT}",
        "digest": "sha256:2a841fc9e476cad10181e049636ca02e75dd124e1709825f7573c4fdfe114935",
    },
    {
        "id": 9727104823,
        "name": f"owner-open-r5-l1-rust-{SOURCE_COMMIT}",
        "digest": "sha256:fae6d8d178a136316e4d2947993c12fba00a40fbfe0aedcf7c4053cea47f3183",
    },
    {
        "id": 9727106502,
        "name": f"owner-open-r5-l1-candidate-{SOURCE_COMMIT}",
        "digest": "sha256:a72d48121a27fea2ca71f7066f3311ab04483195097576d2dd86b8504ac0c4ff",
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
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def replace_one(path: Path, pattern: str, replacement: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    updated, count = re.subn(pattern, replacement, text, count=1)
    if count != 1:
        raise SystemExit(f"{label}: expected one match in {path}, observed {count}")
    path.write_text(updated, encoding="utf-8")


def patch_gap_register() -> None:
    path = ROOT / "docs/status/owner-open-r5-gap-closure.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    candidate = value.get("documentation_candidate")
    if not isinstance(candidate, dict):
        raise SystemExit("gap register documentation_candidate is missing")
    candidate.update(
        {
            "state": "EXACT_SOURCE_HEAD_L1_PASSED",
            "evidence_level": "L1",
            "validated_source_commit": SOURCE_COMMIT,
            "validated_source_tree": SOURCE_TREE,
            "workflow_run_id": WORKFLOW_RUN_ID,
            "checked_in_promotion_requires_new_exact_head_ci": True,
        }
    )
    source_evidence_count = 0
    for gap in value.get("gaps", []):
        if isinstance(gap, dict) and "source_evidence" in gap:
            gap["source_evidence"] = deepcopy(SOURCE_EVIDENCE)
            source_evidence_count += 1
    if source_evidence_count != 13:
        raise SystemExit(
            f"expected source evidence on all 13 gaps, observed {source_evidence_count}"
        )
    write_json(path, value)


def patch_status() -> None:
    path = ROOT / "docs/status/owner-open-r5-status.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["updated_at"] = "2026-08-30"
    value["product_claim"] = (
        f"Exact source commit {SOURCE_COMMIT} and tree {SOURCE_TREE} passed all sixteen permanent "
        "pull-request workflows, including ordered Host worker terminal delivery, transport final-frame "
        "drain and descendant cleanup, Provider stdout/exit convergence, bounded natural Provider exit, "
        "the permanent L1 source/gap workflow, source slices, foundation, release-path, product-entrypoint, "
        "ADB, Android source-profile and Root-Linux packaging gates. Job admission is CLOSED at L1. "
        "Process lifecycle, stream recovery, journal convergence, Broker correlation and product entrypoint "
        "are source-closed but still require their declared L2-L5 target evidence. Repository governance, "
        "installed Codex, Root Linux placement, Android image, physical ADB, destructive faults and public "
        "release remain explicit holds."
    )
    value["claim_ceiling"] = CLAIM_CEILING
    candidate = value.get("current_candidate")
    if not isinstance(candidate, dict):
        raise SystemExit("status current_candidate is missing")
    candidate.update(
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
        if isinstance(hold, dict):
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
    replace_one(
        ROOT / "docs/TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md",
        r"candidate evidence: L1 exact-source run [0-9]+",
        f"candidate evidence: L1 exact-source run {WORKFLOW_RUN_ID}",
        "active-plan candidate run",
    )
    replace_one(
        ROOT / "docs/OWNER_OPEN_R5_START_HERE.md",
        r"Documentation candidate evidence: \*\*HOST_TESTED / L1 at exact source `[0-9a-f]{40}`\*\*",
        (
            "Documentation candidate evidence: **HOST_TESTED / L1 at exact source "
            f"`{SOURCE_COMMIT}`**"
        ),
        "Start Here exact-source identity",
    )


def write_evidence_doc() -> None:
    promotion_run = os.environ.get("PROMOTION_RUN_ID", "unknown")
    path = ROOT / "docs/status/owner-open-r5-source-closure-evidence-2026-08-29.md"
    path.write_text(
        f"""# Owner-Open R5 exact-source-head L1 closure evidence

Status: **Exact repaired source passed all permanent L1 and repository workflows; target, device, destructive-fault and release evidence remains open.**

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
| Cargo.lock SHA-256 | `{CARGO_LOCK_SHA256}` |

The permanent workflow checked out the pull-request source head rather than GitHub's synthetic merge
commit. The exact source passed graph/document verification, gap/evidence mutation tests, Broker and MCP
fixtures, locked Rust 1.93 formatting/tests/strict Clippy, product-entrypoint checks, release mechanics,
ADB relay checks, Android source-profile checks, Root-Linux packaging checks and the foundation suite.

## Bound artifacts

| Artifact ID | Name | SHA-256 digest |
| --- | --- | --- |
| `9727099892` | `owner-open-r5-l1-graph-docs-python-{SOURCE_COMMIT}` | `sha256:2a841fc9e476cad10181e049636ca02e75dd124e1709825f7573c4fdfe114935` |
| `9727104823` | `owner-open-r5-l1-rust-{SOURCE_COMMIT}` | `sha256:fae6d8d178a136316e4d2947993c12fba00a40fbfe0aedcf7c4053cea47f3183` |
| `9727106502` | `owner-open-r5-l1-candidate-{SOURCE_COMMIT}` | `sha256:a72d48121a27fea2ca71f7066f3311ab04483195097576d2dd86b8504ac0c4ff` |

## Terminal and lifecycle convergence closure

The qualified source closes three independently observed ordering failures without weakening the
fail-closed semantics:

- the active-turn worker now sends ordinary errors and panics through the same ordered terminal channel;
  a timeout-side `JoinHandle::is_finished` path can no longer overtake an already queued terminal;
- the transport waits for both core exit status and stdout drain, preserves the final core frame and
  kills/reaps descendants that retain inherited file descriptors;
- the JSONL Provider treats leader exit as an observation rather than an immediate semantic failure,
  waits for the ordered stdout reader outcome, and gives a completed Provider a bounded natural-exit
  window before process-group signal escalation.

The focused one-shot qualifications were transport run `33294435901`, Provider ordering run
`33294701029`, and Provider natural-exit run `33294827071`. They stress-repeated the formerly racy
paths, ran package/workspace tests, strict Clippy and canonical verifiers, and removed their transient
write-capable workflow/helper files before committing the repairs. The human-authored exact source
`{SOURCE_COMMIT}` subsequently passed all sixteen permanent PR workflows, so it inherits no historical
L1 result.

## State-only promotion provenance

This binding is generated by one-shot promotion run `{promotion_run}`. The workflow restricts the
final diff to the five durable plan/status/evidence files, executes the canonical verifier and evidence
mutation suites, commits with the repository bot, and deletes both transient write-capable files. The
resulting promotion head is state-only: it does not change executable source or promote L2-L6 claims.

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
