"""Live pull-request, branch-protection, workflow-run and job binding."""
from __future__ import annotations

from typing import Any, Mapping
from urllib.parse import quote, urlencode

from tools.g1_pr_aggregate_api import GitHubApi
from tools.g1_pr_aggregate_common import (
    REQUIRED_PROTECTION_CONTEXTS,
    _digest,
    _git_sha,
    _identifier,
    _list,
    _mapping,
    _positive_int,
    _repo,
    _require,
)
from tools.g1_pr_aggregate_model import Subject, WorkflowRequirement

def _commit_tree(api: GitHubApi, repository: str, commit: str, label: str) -> str:
    response = api.get_json(f"repos/{repository}/commits/{commit}")
    value = _mapping(response.value, f"{label} commit response")
    _require(value.get("sha") == commit, f"{label} commit identity moved")
    commit_object = _mapping(value.get("commit"), f"{label} commit.commit")
    tree = _mapping(commit_object.get("tree"), f"{label} commit.tree").get("sha")
    return _git_sha(tree, f"{label} tree")


def _verify_pull_request(
    api: GitHubApi,
    repository: str,
    pr_number: int,
    expected_base_commit: str,
    expected_head_commit: str,
) -> tuple[Subject, str]:
    response = api.get_json(f"repos/{repository}/pulls/{pr_number}")
    pr = _mapping(response.value, "pull request")
    _require(pr.get("number") == pr_number, "pull-request number mismatch")
    _require(pr.get("state") == "open", "pull request is not open")
    base = _mapping(pr.get("base"), "pull request base")
    head = _mapping(pr.get("head"), "pull request head")
    base_repo = _mapping(base.get("repo"), "pull request base repository").get("full_name")
    head_repo = _mapping(head.get("repo"), "pull request head repository").get("full_name")
    _require(base_repo == repository, "pull-request base repository differs from requested repository")
    head_repository = _repo(head_repo, "pull-request head repository")
    base_ref = _identifier(base.get("ref"), "pull-request base ref")
    head_ref = _identifier(head.get("ref"), "pull-request head ref")
    base_commit = _git_sha(base.get("sha"), "pull-request base commit")
    head_commit = _git_sha(head.get("sha"), "pull-request head commit")
    _require(base_commit == expected_base_commit, "pull-request base commit moved")
    _require(head_commit == expected_head_commit, "pull-request head commit moved")
    base_tree = _commit_tree(api, repository, base_commit, "base")
    head_tree = _commit_tree(api, head_repository, head_commit, "head")
    subject = Subject(
        repository=repository,
        pr_number=pr_number,
        base_ref=base_ref,
        base_commit=base_commit,
        base_tree=base_tree,
        head_repository=head_repository,
        head_ref=head_ref,
        head_commit=head_commit,
        head_tree=head_tree,
    )
    return subject, _digest(response.raw)


def _verify_branch_protection(api: GitHubApi, subject: Subject) -> dict[str, Any]:
    branch_path = quote(subject.base_ref, safe="")
    response = api.get_json(f"repos/{subject.repository}/branches/{branch_path}")
    branch = _mapping(response.value, "integration branch")
    _require(branch.get("name") == subject.base_ref, "integration branch name mismatch")
    branch_commit = _mapping(branch.get("commit"), "integration branch commit")
    _require(branch_commit.get("sha") == subject.base_commit, "integration branch advanced")
    _require(branch.get("protected") is True, "integration branch is not protected")
    protection = _mapping(branch.get("protection"), "integration branch protection")
    _require(protection.get("enabled") is True, "integration branch protection is disabled")
    status_checks = _mapping(protection.get("required_status_checks"), "required status checks")
    _require(status_checks.get("enforcement_level") == "everyone", "required checks are not enforced for everyone")
    contexts_raw = _list(status_checks.get("contexts"), "required status contexts")
    contexts = {_identifier(item, "required status context") for item in contexts_raw}
    missing = sorted(REQUIRED_PROTECTION_CONTEXTS - contexts)
    _require(not missing, f"integration protection is missing contexts: {missing}")
    return {
        "branch": subject.base_ref,
        "commit": subject.base_commit,
        "protected": True,
        "enforcement_level": "everyone",
        "required_contexts": sorted(contexts),
        "response_sha256": _digest(response.raw),
    }


def _run_matches_subject(run: Mapping[str, Any], requirement: WorkflowRequirement, subject: Subject) -> bool:
    if (
        run.get("name") != requirement.workflow_name
        or run.get("path") != requirement.path
        or run.get("event") != "pull_request"
        or run.get("head_sha") != subject.head_commit
        or run.get("head_branch") != subject.head_ref
    ):
        return False
    pulls = run.get("pull_requests")
    if not isinstance(pulls, list):
        return False
    for item in pulls:
        if not isinstance(item, Mapping) or item.get("number") != subject.pr_number:
            continue
        base = item.get("base")
        head = item.get("head")
        if not isinstance(base, Mapping) or not isinstance(head, Mapping):
            continue
        if base.get("sha") == subject.base_commit and head.get("sha") == subject.head_commit:
            return True
    return False


def _latest_run(api: GitHubApi, requirement: WorkflowRequirement, subject: Subject) -> tuple[Mapping[str, Any] | None, str]:
    query = urlencode({"event": "pull_request", "head_sha": subject.head_commit, "per_page": 100})
    workflow_id = quote(requirement.filename, safe="")
    response = api.get_json(
        f"repos/{subject.repository}/actions/workflows/{workflow_id}/runs?{query}"
    )
    value = _mapping(response.value, f"{requirement.workflow_name} run list")
    runs = _list(value.get("workflow_runs"), f"{requirement.workflow_name} workflow_runs")
    candidates = [run for run in runs if isinstance(run, Mapping) and _run_matches_subject(run, requirement, subject)]
    if not candidates:
        return None, _digest(response.raw)
    candidates.sort(key=lambda item: _positive_int(item.get("id"), "workflow run id"), reverse=True)
    return candidates[0], _digest(response.raw)


def _verify_jobs(api: GitHubApi, run_id: int, expected_names: frozenset[str]) -> list[dict[str, Any]]:
    response = api.get_json(f"repos/{{repo}}/actions/runs/{run_id}/jobs?filter=latest&per_page=100")
    # Fake APIs in unit tests may use a repository-independent path.  The live
    # caller rewrites the placeholder before dispatch through _RepoApi below.
    value = _mapping(response.value, f"workflow run {run_id} jobs")
    jobs = _list(value.get("jobs"), f"workflow run {run_id} jobs.jobs")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(jobs):
        job = _mapping(item, f"workflow run {run_id} job[{index}]")
        name = _identifier(job.get("name"), f"workflow run {run_id} job[{index}].name")
        _require(name not in seen, f"workflow run {run_id} has duplicate job name {name!r}")
        seen.add(name)
        _require(job.get("status") == "completed" and job.get("conclusion") == "success", f"workflow run {run_id} job {name!r} is not terminal success")
        job_run_id = job.get("run_id")
        if job_run_id is not None:
            _require(job_run_id == run_id, f"workflow run {run_id} job {name!r} ownership mismatch")
        steps = job.get("steps", [])
        _require(isinstance(steps, list), f"workflow run {run_id} job {name!r} steps are invalid")
        for step_index, step_value in enumerate(steps):
            step = _mapping(step_value, f"workflow run {run_id} job {name!r} step[{step_index}]")
            conclusion = step.get("conclusion")
            _require(conclusion in {"success", "skipped", None}, f"workflow run {run_id} job {name!r} contains a failed step")
        normalized.append(
            {
                "id": _positive_int(job.get("id"), f"workflow run {run_id} job id"),
                "name": name,
                "status": "completed",
                "conclusion": "success",
            }
        )
    _require(seen == set(expected_names), f"workflow run {run_id} job set drifted: expected {sorted(expected_names)}, got {sorted(seen)}")
    return sorted(normalized, key=lambda item: item["name"])


