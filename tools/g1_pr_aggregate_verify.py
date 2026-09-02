"""Top-level exact-subject G1 aggregate verification."""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
import time
from typing import Any, Callable

from tools.g1_pr_aggregate_api import GitHubApi
from tools.g1_pr_aggregate_archive import _RepoApi
from tools.g1_pr_aggregate_common import (
    PROGRAM_REVISION,
    REPORT_SCHEMA,
    AggregateError,
    _canonical,
    _digest,
    _git_sha,
    _positive_int,
    _repo,
    _require,
)
from tools.g1_pr_aggregate_live import (
    _latest_run,
    _verify_branch_protection,
    _verify_pull_request,
)
from tools.g1_pr_aggregate_model import REQUIREMENTS, Subject
from tools.g1_pr_aggregate_workflow import _verify_workflow

def _local_source_binding(repo_root: Path, subject: Subject, expected_cargo_lock_sha256: str) -> dict[str, Any]:
    resolved = repo_root.resolve()
    _require((resolved / ".git").exists(), f"repository root has no .git directory: {resolved}")
    env = {"PATH": os.environ.get("PATH", ""), "LC_ALL": "C", "LANG": "C"}
    def git(*args: str) -> str:
        completed = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(resolved), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        if completed.returncode != 0:
            raise AggregateError(f"git {' '.join(args)} failed: {completed.stderr.strip()}")
        return completed.stdout.strip()
    _require(git("rev-parse", "HEAD^{commit}") == subject.head_commit, "local checkout is not the exact PR head")
    _require(git("rev-parse", "HEAD^{tree}") == subject.head_tree, "local checkout tree differs from live head tree")
    _require(git("merge-base", "--is-ancestor", subject.base_commit, subject.head_commit) == "", "canonical G1 base is not an ancestor of the source head")
    _require(git("status", "--porcelain=v1", "--untracked-files=all") == "", "local checkout is not clean")
    lock = resolved / "Cargo.lock"
    _require(lock.is_file() and not lock.is_symlink(), "Cargo.lock is unavailable or is a symlink")
    lock_digest = _digest(lock.read_bytes())
    _require(lock_digest == expected_cargo_lock_sha256, "synthetic receipt Cargo.lock digest differs from exact checkout")
    return {
        "root": str(resolved),
        "commit": subject.head_commit,
        "tree": subject.head_tree,
        "cargo_lock_sha256": lock_digest,
        "base_is_ancestor": True,
        "clean": True,
    }


def verify_pr_aggregate(
    *,
    repository: str,
    pr_number: int,
    expected_base_commit: str,
    expected_head_commit: str,
    repo_root: Path,
    api: GitHubApi,
    timeout_seconds: float = 900.0,
    poll_seconds: float = 10.0,
    now: datetime | None = None,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    repository = _repo(repository)
    _positive_int(pr_number, "pr_number")
    _git_sha(expected_base_commit, "expected_base_commit")
    _git_sha(expected_head_commit, "expected_head_commit")
    _require(timeout_seconds >= 0 and poll_seconds >= 0, "poll bounds must be non-negative")
    reference_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject, pr_response_sha = _verify_pull_request(
        api, repository, pr_number, expected_base_commit, expected_head_commit
    )
    protection = _verify_branch_protection(api, subject)
    repo_api = _RepoApi(api, repository)
    deadline = monotonic() + timeout_seconds
    verified: dict[str, dict[str, Any]] = {}
    selected_run_ids: dict[str, int] = {}
    list_response_digests: dict[str, str] = {}
    synthetic_state: dict[str, str] = {}

    while len(verified) < len(REQUIREMENTS):
        pending: list[str] = []
        for requirement in REQUIREMENTS:
            if requirement.filename in verified:
                continue
            if requirement.artifact_kind != "synthetic" and "merge_tree" not in synthetic_state:
                pending.append(requirement.workflow_name)
                continue
            run, list_digest = _latest_run(api, requirement, subject)
            list_response_digests[requirement.filename] = list_digest
            if run is None or run.get("status") != "completed":
                pending.append(requirement.workflow_name)
                continue
            _require(run.get("conclusion") == "success", f"latest exact-subject run for {requirement.workflow_name} concluded {run.get('conclusion')!r}")
            verified[requirement.filename] = _verify_workflow(
                repo_api,
                requirement,
                run,
                subject,
                reference_now,
                synthetic_state,
            )
            selected_run_ids[requirement.filename] = _positive_int(run.get("id"), "workflow run id")
        if not pending:
            break
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise AggregateError(f"timed out waiting for exact-subject workflows: {pending}")
        sleep(min(poll_seconds, remaining))

    local = _local_source_binding(repo_root, subject, synthetic_state["cargo_lock_sha256"])

    # Re-read all mutable live objects after artifact downloads.  A base/head
    # movement, PR retarget, protection change, or newer workflow run makes the
    # aggregate stale and therefore invalid.
    final_subject, final_pr_response_sha = _verify_pull_request(
        api, repository, pr_number, expected_base_commit, expected_head_commit
    )
    _require(final_subject == subject, "pull-request subject changed during aggregate verification")
    final_protection = _verify_branch_protection(api, subject)
    _require(
        {key: value for key, value in final_protection.items() if key != "response_sha256"}
        == {key: value for key, value in protection.items() if key != "response_sha256"},
        "integration protection changed during aggregate verification",
    )
    for requirement in REQUIREMENTS:
        latest, _digest_value = _latest_run(api, requirement, subject)
        _require(latest is not None, f"{requirement.workflow_name} disappeared during final recheck")
        _require(latest.get("id") == selected_run_ids[requirement.filename], f"a newer exact-subject {requirement.workflow_name} run appeared during verification")
        _require(latest.get("status") == "completed" and latest.get("conclusion") == "success", f"{requirement.workflow_name} lost terminal success during final recheck")

    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "program_revision": PROGRAM_REVISION,
        "generated_at_utc": reference_now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
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
        "workflows": [verified[item.filename] for item in REQUIREMENTS],
        "live_response_sha256": {
            "pull_request_initial": pr_response_sha,
            "pull_request_final": final_pr_response_sha,
            "workflow_lists": dict(sorted(list_response_digests.items())),
        },
        "result": "L1_EXACT_PR_WORKFLOW_AGGREGATE_PASSED",
        "claim_ceiling": "PROTECTED_EXACT_SOURCE_AND_REPOSITORY_WORKFLOW_FAMILIES_PASSED_NOT_SIGNED_OR_INSTALLED_TARGET",
        "automatic_redispatch": False,
        "public_release": False,
        "report_sha256": "",
    }
    report["report_sha256"] = _digest(_canonical(report))
    return report


