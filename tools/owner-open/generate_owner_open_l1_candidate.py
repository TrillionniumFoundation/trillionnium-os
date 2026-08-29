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
import subprocess
from typing import Any

SCHEMA = "org.trillionnium.owner-open.l1-candidate.v2"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
STATUS = Path("docs/status/owner-open-r5-status.json")
GAPS = Path("docs/status/owner-open-r5-gap-closure.json")
LOCK = Path("Cargo.lock")


class CandidateError(RuntimeError):
    pass


def _git(root: Path, *arguments: str) -> str:
    try:
        return subprocess.check_output(
            ["git", *arguments],
            cwd=root,
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
    except subprocess.CalledProcessError as error:
        raise CandidateError(
            f"git {' '.join(arguments)} failed: {error.output.strip()}"
        ) from error


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CandidateError(f"cannot read JSON object {path}: {error}") from error
    if not isinstance(value, dict):
        raise CandidateError(f"{path} must contain one JSON object")
    return value


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

    observed_head = _git(root, "rev-parse", "HEAD")
    if observed_head != source_head_sha:
        raise CandidateError(
            f"checkout HEAD {observed_head} differs from source head {source_head_sha}"
        )
    tracked_status = _git(root, "status", "--porcelain", "--untracked-files=no")
    if tracked_status:
        raise CandidateError(
            "tracked working tree is dirty before evidence generation: "
            + tracked_status.replace("\n", "; ")
        )

    status = _read_object(root / STATUS)
    gaps = _read_object(root / GAPS)
    tree_sha = _git(root, "rev-parse", "HEAD^{tree}")
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
        args.output.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (CandidateError, OSError) as error:
        print(f"ERROR: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
