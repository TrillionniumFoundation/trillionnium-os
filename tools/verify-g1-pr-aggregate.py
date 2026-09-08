#!/usr/bin/env python3
"""Fail-closed exact-head plus prospective-merge source aggregate.

The protected ``L1 exact-source-head aggregate candidate`` context is emitted
by the dependent admission job in ``G1 synthetic-merge qualification``. This
command runs in the separately named exact-head direct-source aggregate and
binds that workflow's exact attempt, both job identities, and source receipt to
the same live PR base/head tuple. It deliberately does not require review-index,
Android target, evidence-intake, device, fault, signing or release workflows.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.g1_pr_aggregate_api import GitHubApi
from tools.g1_pr_aggregate_archive import _RepoApi
from tools.g1_pr_aggregate_common import (
    PROGRAM_REVISION,
    REPORT_SCHEMA,
    AggregateError,
    _canonical,
    _digest,
    _require,
)
from tools.g1_pr_aggregate_live import (
    _latest_run,
    _verify_branch_protection,
    _verify_pull_request,
)
from tools.g1_pr_aggregate_model import REQUIREMENTS, Subject
from tools.g1_pr_aggregate_workflow import _verify_workflow


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pr-number", type=int, required=True)
    parser.add_argument("--base-commit", required=True)
    parser.add_argument("--head-commit", required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=900.0)
    parser.add_argument("--poll-seconds", type=float, default=10.0)
    parser.add_argument("--api-base-url", default="https://api.github.com/")
    return parser.parse_args(argv)


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C", "LANG": "C"},
    )
    if completed.returncode != 0:
        raise AggregateError(
            f"git {' '.join(args)} failed: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def _local_binding(
    root: Path, subject: Subject, synthetic: Mapping[str, Any]
) -> dict[str, Any]:
    resolved = root.resolve()
    _require((resolved / ".git").exists(), "repository root has no .git directory")
    _require(
        _git(resolved, "rev-parse", "HEAD^{commit}") == subject.head_commit,
        "local checkout is not the exact PR head",
    )
    _require(
        _git(resolved, "rev-parse", "HEAD^{tree}") == subject.head_tree,
        "local checkout tree differs from live head tree",
    )
    # A successful --is-ancestor has no stdout. A non-ancestor or Git failure is
    # rejected by _git rather than being confused with an empty clean result.
    _git(
        resolved,
        "merge-base",
        "--is-ancestor",
        subject.base_commit,
        subject.head_commit,
    )
    _require(
        _git(
            resolved,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        )
        == "",
        "local checkout is not clean",
    )
    lock = resolved / "Cargo.lock"
    _require(
        lock.is_file() and not lock.is_symlink(),
        "Cargo.lock is unavailable or symlinked",
    )
    lock_sha = _digest(lock.read_bytes())
    _require(
        lock_sha == synthetic["cargo_lock_sha256"],
        "synthetic receipt Cargo.lock digest differs from exact checkout",
    )
    return {
        "root": str(resolved),
        "commit": subject.head_commit,
        "tree": subject.head_tree,
        "cargo_lock_sha256": lock_sha,
        "base_is_ancestor": True,
        "clean": True,
    }


def _run_identity(run: Mapping[str, Any]) -> dict[str, Any]:
    """Freeze the mutable workflow-run subject, including rerun attempt."""
    return {
        "id": run.get("id"),
        "run_attempt": run.get("run_attempt"),
        "name": run.get("name"),
        "path": run.get("path"),
        "event": run.get("event"),
        "head_sha": run.get("head_sha"),
        "head_branch": run.get("head_branch"),
        "pull_requests": run.get("pull_requests"),
        "status": run.get("status"),
        "conclusion": run.get("conclusion"),
    }


def _verify(
    *,
    repository: str,
    pr_number: int,
    base_commit: str,
    head_commit: str,
    repo_root: Path,
    api: GitHubApi,
    timeout_seconds: float,
    poll_seconds: float,
) -> dict[str, Any]:
    _require(
        len(REQUIREMENTS) == 1,
        "source aggregate must have exactly one cross-workflow requirement",
    )
    requirement = REQUIREMENTS[0]
    _require(
        requirement.artifact_kind == "synthetic",
        "only the synthetic source workflow may gate ordinary PRs",
    )
    _require(
        timeout_seconds >= 0 and poll_seconds >= 0,
        "poll bounds must be non-negative",
    )

    generated = datetime.now(timezone.utc).replace(microsecond=0)
    subject, initial_pr_sha = _verify_pull_request(
        api, repository, pr_number, base_commit, head_commit
    )
    protection = _verify_branch_protection(api, subject)
    repo_api = _RepoApi(api, repository)
    deadline = time.monotonic() + timeout_seconds
    selected_run: Mapping[str, Any] | None = None
    list_digest = ""

    while selected_run is None:
        run, list_digest = _latest_run(api, requirement, subject)
        if run is not None and run.get("status") == "completed":
            _require(
                run.get("conclusion") == "success",
                "latest exact-subject synthetic merge concluded "
                f"{run.get('conclusion')!r}",
            )
            selected_run = run
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AggregateError(
                "timed out waiting for exact-subject synthetic merge"
            )
        time.sleep(min(poll_seconds, remaining))

    synthetic_state: dict[str, Any] = {}
    workflow = _verify_workflow(
        repo_api,
        requirement,
        selected_run,
        subject,
        generated,
        synthetic_state,
    )
    selected_run_identity = _run_identity(selected_run)
    local = _local_binding(repo_root, subject, synthetic_state)

    # Re-read every mutable decision object after artifact download. A rerun
    # keeps the same run id but changes run_attempt, jobs and artifacts, so the
    # decision is frozen to the complete run/attempt plus the independently
    # normalized job, artifact and semantic-receipt identities. Re-verifying the
    # workflow also catches in-place mutation within the same attempt.
    final_subject, final_pr_sha = _verify_pull_request(
        api, repository, pr_number, base_commit, head_commit
    )
    _require(
        final_subject == subject,
        "pull-request subject changed during verification",
    )
    final_protection = _verify_branch_protection(api, subject)
    _require(
        {
            key: value
            for key, value in final_protection.items()
            if key != "response_sha256"
        }
        == {
            key: value
            for key, value in protection.items()
            if key != "response_sha256"
        },
        "integration protection changed during verification",
    )
    latest, _ = _latest_run(api, requirement, subject)
    _require(
        latest is not None,
        "synthetic workflow disappeared during final recheck",
    )
    _require(
        _run_identity(latest) == selected_run_identity,
        "synthetic workflow run or rerun attempt changed during verification",
    )

    final_synthetic_state: dict[str, Any] = {}
    final_workflow = _verify_workflow(
        repo_api,
        requirement,
        latest,
        subject,
        generated,
        final_synthetic_state,
    )
    _require(
        _canonical(final_workflow) == _canonical(workflow),
        "synthetic workflow jobs, artifacts or receipt changed during verification",
    )
    _require(
        final_synthetic_state == synthetic_state,
        "synthetic semantic receipt changed during verification",
    )

    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "program_revision": PROGRAM_REVISION,
        "generated_at_utc": generated.isoformat().replace("+00:00", "Z"),
        "repository": repository,
        "pull_request": pr_number,
        "subject": {
            "base": {
                "repository": repository,
                "ref": subject.base_ref,
                "commit": subject.base_commit,
                "tree": subject.base_tree,
            },
            "head": {
                "repository": subject.head_repository,
                "ref": subject.head_ref,
                "commit": subject.head_commit,
                "tree": subject.head_tree,
            },
            "merge": {
                "kind": "deterministic_synthetic",
                "commit": synthetic_state["merge_commit"],
                "tree": synthetic_state["merge_tree"],
                "parents": [subject.base_commit, subject.head_commit],
            },
        },
        "protection": final_protection,
        "local_source": local,
        "workflows": [workflow],
        "live_response_sha256": {
            "pull_request_initial": initial_pr_sha,
            "pull_request_final": final_pr_sha,
            "workflow_lists": {requirement.filename: list_digest},
        },
        "excluded_from_ordinary_pr_gate": [
            "review_index_receipts",
            "android_target_evidence",
            "evidence_intake",
            "physical_device",
            "destructive_fault",
            "signing_and_release",
        ],
        "result": "L1_EXACT_HEAD_AND_SYNTHETIC_SOURCE_PASSED",
        "claim_ceiling": (
            "EXACT_SOURCE_AND_PROSPECTIVE_MERGE_ONLY_NOT_INSTALLED_TARGET"
        ),
        "automatic_redispatch": False,
        "public_release": False,
        "report_sha256": "",
    }
    report["report_sha256"] = _digest(_canonical(report))
    return report


def main(argv: Sequence[str]) -> int:
    args = _parse_args(argv)
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print(
            "G1 PR source aggregate failed: GITHUB_TOKEN is required",
            file=sys.stderr,
        )
        return 2
    try:
        report = _verify(
            repository=args.repository,
            pr_number=args.pr_number,
            base_commit=args.base_commit,
            head_commit=args.head_commit,
            repo_root=args.repo_root,
            api=GitHubApi(base_url=args.api_base_url, token=token),
            timeout_seconds=args.timeout_seconds,
            poll_seconds=args.poll_seconds,
        )
        _write_json(args.output, report)
        print(f"G1 PR source aggregate passed: {report['report_sha256']}")
        return 0
    except (
        AggregateError,
        OSError,
        subprocess.SubprocessError,
        ValueError,
    ) as error:
        print(f"G1 PR source aggregate failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
