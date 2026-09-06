#!/usr/bin/env python3
"""Fail-closed exact-head governance for Trillionnium OS PR #41.

The controller consumes a source qualification result produced by a separate
read-only job. It never executes the candidate tree, approves a review,
dismisses a review, bypasses branch protection, or promotes L2-L6 evidence.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

REQUIRED_WORKFLOWS = (
    "G1 exact-head source qualification",
    "G1 repository topology and exact-subject closure",
    "G1 exact-head and synthetic-merge review-index receipts",
    "G1 Android privileged-lane evaluated matrix",
    "G1 complete gap-to-evidence routing",
    "G1 evidence intake qualification",
    "G1 synthetic-merge qualification",
    "Owner-open R5 compatibility source routing",
    "Owner-open R5 governance readiness observation",
)
SUCCESS = {"success"}
ACTIVE = {"queued", "in_progress", "waiting", "pending", "requested"}
RETRYABLE_FAILURES = {
    "failure", "cancelled", "timed_out", "action_required", "startup_failure", "stale"
}


class ApiError(RuntimeError):
    def __init__(self, status: int, body: Any) -> None:
        super().__init__(f"GitHub API {status}: {body}")
        self.status = status
        self.body = body


class Governor:
    def __init__(
        self,
        *,
        repository: str,
        pr_number: int,
        issue_number: int,
        expected_head: str,
        expected_base: str,
        expected_tree: str,
        qualification_run: str,
        token: str,
        output: Path,
    ) -> None:
        self.repository = repository
        self.pr_number = pr_number
        self.issue_number = issue_number
        self.expected_head = expected_head
        self.expected_base = expected_base
        self.expected_tree = expected_tree
        self.qualification_run = qualification_run
        self.token = token
        self.output = output
        self.root = f"https://api.github.com/repos/{repository}"
        self.state: dict[str, Any] = {
            "schema": "org.trillionnium.g1.final-governor-v12.v1",
            "repository": repository,
            "pull_request": pr_number,
            "external_evidence_issue": issue_number,
            "expected_head": expected_head,
            "expected_base": expected_base,
            "expected_tree": expected_tree,
            "qualification_run": qualification_run,
            "administrator_bypass": False,
            "self_approval": False,
            "review_dismissal": False,
            "external_evidence_promotion": False,
            "public_release": False,
            "phase": "initialized",
        }
        self.save()

    def save(self) -> None:
        self.state["updated_at_utc"] = datetime.now(timezone.utc).isoformat()
        self.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.output.with_suffix(self.output.suffix + ".tmp")
        temporary.write_text(
            json.dumps(self.state, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, self.output)

    def request(
        self,
        method: str,
        path: str,
        payload: Any | None = None,
        *,
        root: str | None = None,
    ) -> Any:
        url = (root or self.root) + path
        data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "trillionnium-g1-final-governor-v12",
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, method=method, data=data, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                raw = response.read()
                return None if not raw else json.loads(raw)
        except urllib.error.HTTPError as error:
            raw = error.read(131072)
            try:
                body: Any = json.loads(raw)
            except Exception:
                body = raw.decode("utf-8", errors="replace")
            raise ApiError(error.code, body) from error

    def get_pr(self) -> dict[str, Any]:
        return self.request("GET", f"/pulls/{self.pr_number}")

    def stable_pr(self) -> dict[str, Any]:
        for _ in range(20):
            pr = self.get_pr()
            if pr.get("mergeable") is not None and pr.get("merge_commit_sha"):
                return pr
            time.sleep(3)
        raise RuntimeError("GitHub did not produce a stable mergeability observation")

    def verify_subject(self, pr: dict[str, Any]) -> None:
        observed_head = ((pr.get("head") or {}).get("sha"))
        observed_base = ((pr.get("base") or {}).get("sha"))
        observed_ref = ((pr.get("head") or {}).get("ref"))
        self.state["observed_subject"] = {
            "state": pr.get("state"),
            "draft": pr.get("draft"),
            "head": observed_head,
            "base": observed_base,
            "head_ref": observed_ref,
            "changed_files": pr.get("changed_files"),
            "mergeable": pr.get("mergeable"),
            "mergeable_state": pr.get("mergeable_state"),
            "merge_commit_sha": pr.get("merge_commit_sha"),
        }
        self.save()
        if pr.get("state") != "open":
            raise RuntimeError("pull request is not open")
        if observed_head != self.expected_head or observed_base != self.expected_base:
            raise RuntimeError("pull request moved after read-only qualification")
        head_commit = self.request("GET", f"/git/commits/{self.expected_head}")
        observed_tree = (head_commit.get("tree") or {}).get("sha")
        self.state["observed_subject"]["head_tree"] = observed_tree
        self.save()
        if observed_tree != self.expected_tree:
            raise RuntimeError("qualified head tree differs from GitHub commit tree")

    def update_exact_subject_block(self, pr: dict[str, Any]) -> dict[str, Any]:
        merge_sha = str(pr["merge_commit_sha"])
        merge_commit = self.request("GET", f"/git/commits/{merge_sha}")
        merge_tree = (merge_commit.get("tree") or {}).get("sha")
        head_ref = str((pr.get("head") or {}).get("ref"))
        base_ref = str((pr.get("base") or {}).get("ref"))
        block = (
            "## Exact live subject\n\n"
            "```text\n"
            f"base:               {base_ref}@{self.expected_base}\n"
            f"head:               {self.expected_head}\n"
            f"head tree:          {self.expected_tree}\n"
            f"prospective merge:  {merge_sha}\n"
            f"merge tree:         {merge_tree}\n"
            f"mergeable:          {str(bool(pr.get('mergeable'))).lower()}\n"
            f"draft:              {str(bool(pr.get('draft'))).lower()}\n"
            f"changed paths:      {int(pr.get('changed_files') or 0)}\n"
            "```"
        )
        body = str(pr.get("body") or "")
        pattern = re.compile(r"## Exact live subject\n\n```text\n.*?\n```", re.DOTALL)
        if pattern.search(body):
            updated = pattern.sub(block, body, count=1)
        else:
            updated = block + "\n\n" + body
        if updated != body:
            self.request("PATCH", f"/pulls/{self.pr_number}", {"body": updated})
            self.state["exact_subject_body_updated"] = True
        else:
            self.state["exact_subject_body_updated"] = False
        self.state["observed_subject"]["merge_tree"] = merge_tree
        self.state["observed_subject"]["head_ref"] = head_ref
        self.save()
        return self.stable_pr()

    def create_qualification_check(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        payload = {
            "name": "G1 v12 exact-head source qualification",
            "head_sha": self.expected_head,
            "status": "completed",
            "conclusion": "success",
            "completed_at": now,
            "details_url": self.qualification_run,
            "output": {
                "title": "Exact-head source qualification passed",
                "summary": (
                    f"Read-only qualification passed for `{self.expected_head}` / "
                    f"tree `{self.expected_tree}`. This check carries L1 source authority only; "
                    "it does not establish installed-target, device, destructive-fault, "
                    "signing, OTA, or release evidence."
                ),
            },
        }
        result = self.request("POST", "/check-runs", payload)
        self.state["qualification_check"] = {
            "id": result.get("id"),
            "name": result.get("name"),
            "status": result.get("status"),
            "conclusion": result.get("conclusion"),
            "details_url": result.get("details_url"),
        }
        self.save()

    def exact_runs(self, head_ref: str) -> list[dict[str, Any]]:
        branch = urllib.parse.quote(head_ref, safe="")
        value = self.request("GET", f"/actions/runs?branch={branch}&per_page=100")
        return [
            run for run in value.get("workflow_runs", [])
            if run.get("head_sha") == self.expected_head
        ]

    @staticmethod
    def latest_by_name(runs: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        latest: dict[str, dict[str, Any]] = {}
        for run in runs:
            name = run.get("name")
            if not isinstance(name, str):
                continue
            if name not in latest or int(run.get("id", 0)) > int(latest[name].get("id", 0)):
                latest[name] = run
        return latest

    def rerun_failures_once(self, latest: dict[str, dict[str, Any]]) -> None:
        attempts: list[dict[str, Any]] = []
        for name in REQUIRED_WORKFLOWS:
            run = latest.get(name)
            if not run or run.get("status") != "completed":
                continue
            conclusion = run.get("conclusion")
            if conclusion not in RETRYABLE_FAILURES:
                continue
            run_id = int(run["id"])
            endpoint = f"/actions/runs/{run_id}/rerun-failed-jobs"
            try:
                self.request("POST", endpoint)
                attempts.append({"workflow": name, "run_id": run_id, "action": "rerun_failed_jobs"})
            except ApiError as first:
                try:
                    self.request("POST", f"/actions/runs/{run_id}/rerun")
                    attempts.append({"workflow": name, "run_id": run_id, "action": "rerun_all"})
                except ApiError as second:
                    attempts.append({
                        "workflow": name,
                        "run_id": run_id,
                        "action": "rerun_rejected",
                        "first": str(first),
                        "second": str(second),
                    })
        self.state["rerun_attempts"] = attempts
        self.save()

    def wait_required_workflows(self, head_ref: str) -> tuple[bool, dict[str, Any]]:
        self.state["phase"] = "awaiting_exact_head_workflows"
        self.save()
        initial = self.latest_by_name(self.exact_runs(head_ref))
        self.rerun_failures_once(initial)
        deadline = time.monotonic() + 45 * 60
        last: dict[str, Any] = {}
        while True:
            latest = self.latest_by_name(self.exact_runs(head_ref))
            snapshot: dict[str, Any] = {}
            for name in REQUIRED_WORKFLOWS:
                run = latest.get(name)
                snapshot[name] = None if run is None else {
                    "id": run.get("id"),
                    "run_attempt": run.get("run_attempt"),
                    "status": run.get("status"),
                    "conclusion": run.get("conclusion"),
                    "event": run.get("event"),
                    "html_url": run.get("html_url"),
                }
            if snapshot != last:
                self.state["required_workflows"] = snapshot
                self.save()
                last = snapshot
            missing = [name for name, item in snapshot.items() if item is None]
            active = [
                name for name, item in snapshot.items()
                if item is not None and item.get("status") in ACTIVE
            ]
            failed = [
                name for name, item in snapshot.items()
                if item is not None
                and item.get("status") == "completed"
                and item.get("conclusion") not in SUCCESS
            ]
            if not missing and not active:
                return not failed, {"missing": missing, "active": active, "failed": failed}
            if time.monotonic() >= deadline:
                return False, {"missing": missing, "active": active, "failed": failed, "timeout": True}
            current = self.get_pr()
            if ((current.get("head") or {}).get("sha")) != self.expected_head:
                raise RuntimeError("pull request moved while workflows were running")
            time.sleep(15)

    def reviews(self, author: str) -> tuple[list[str], list[str]]:
        values = self.request("GET", f"/pulls/{self.pr_number}/reviews?per_page=100")
        latest: dict[str, dict[str, Any]] = {}
        for review in sorted(values, key=lambda item: int(item.get("id", 0))):
            login = ((review.get("user") or {}).get("login"))
            if isinstance(login, str) and login:
                latest[login] = review
        approvals: list[str] = []
        changes: list[str] = []
        for login, review in latest.items():
            if login.lower() == author.lower() or login.lower().endswith("[bot]"):
                continue
            if review.get("commit_id") != self.expected_head:
                continue
            if review.get("state") == "APPROVED":
                approvals.append(login)
            elif review.get("state") == "CHANGES_REQUESTED":
                changes.append(login)
        return sorted(approvals), sorted(changes)

    def request_review(self, pr: dict[str, Any]) -> None:
        existing = [
            entry.get("login") for entry in pr.get("requested_reviewers", [])
            if isinstance(entry.get("login"), str)
        ]
        reviewers = existing or ["Tomasrgbsf"]
        try:
            value = self.request(
                "POST",
                f"/pulls/{self.pr_number}/requested_reviewers",
                {"reviewers": reviewers},
            )
            self.state["review_request"] = {
                "requested": True,
                "reviewers": [
                    entry.get("login") for entry in value.get("requested_reviewers", [])
                ],
            }
        except ApiError as error:
            self.state["review_request"] = {
                "requested": False,
                "reviewers": reviewers,
                "error": str(error),
            }
        self.save()

    def comment_once(self, issue: int, marker: str, body: str) -> None:
        comments = self.request("GET", f"/issues/{issue}/comments?per_page=100")
        if any(marker in str(comment.get("body", "")) for comment in comments):
            return
        self.request("POST", f"/issues/{issue}/comments", {"body": marker + "\n\n" + body})

    def update_external_boundary(self, source_ready: bool) -> None:
        marker = f"<!-- g1-v12-external-boundary:{self.expected_head} -->"
        status = "passed" if source_ready else "remains blocked"
        body = (
            f"Repository-controlled exact-head qualification for `{self.expected_head}` {status}. "
            "This governor made no L2-L6 promotion. Installed Root Linux/Codex behavior, clean "
            "Android target-files, authorized physical ADB effects, destructive fault recovery, "
            "production HSM/KMS custody, AVB/OTA/anti-rollback, and distinct human release "
            "authorization still require independently produced and admitted evidence. "
            "`zero_gap` and `public_release` must remain false until those receipts actually exist."
        )
        self.comment_once(self.issue_number, marker, body)

    def mark_ready(self, pr: dict[str, Any]) -> dict[str, Any]:
        if pr.get("draft") is not True:
            return pr
        payload = {
            "query": (
                "mutation($id:ID!){markPullRequestReadyForReview(input:{pullRequestId:$id})"
                "{pullRequest{isDraft headRefOid}}}"
            ),
            "variables": {"id": pr["node_id"]},
        }
        value = self.request("POST", "", payload, root="https://api.github.com/graphql")
        if value.get("errors"):
            raise RuntimeError(f"mark ready failed: {value['errors']}")
        observed = value["data"]["markPullRequestReadyForReview"]["pullRequest"]
        if observed.get("isDraft") is not False or observed.get("headRefOid") != self.expected_head:
            raise RuntimeError("ready-for-review mutation changed or failed to bind the exact head")
        self.state["marked_ready_for_review"] = True
        self.save()
        return self.stable_pr()

    def ordinary_merge(self, pr: dict[str, Any]) -> None:
        self.verify_subject(pr)
        result = self.request(
            "PUT",
            f"/pulls/{self.pr_number}/merge",
            {
                "sha": self.expected_head,
                "merge_method": "merge",
                "commit_title": f"feat(g1): close repository-controlled blockers (#{self.pr_number})",
                "commit_message": (
                    "Merge the exact independently reviewed source subject through ordinary "
                    "branch protection. L2-L6 evidence and public release remain outside this merge."
                ),
            },
        )
        self.state["merge"] = result
        self.save()
        if not result.get("merged"):
            raise RuntimeError(f"ordinary protected merge rejected: {result}")

    def run(self) -> int:
        try:
            pr = self.stable_pr()
            self.verify_subject(pr)
            pr = self.update_exact_subject_block(pr)
            self.verify_subject(pr)
            self.create_qualification_check()
            head_ref = str((pr.get("head") or {}).get("ref"))
            workflows_ok, terminal = self.wait_required_workflows(head_ref)
            self.state["workflow_terminal"] = terminal
            self.save()
            self.update_external_boundary(workflows_ok)
            if not workflows_ok:
                marker = f"<!-- g1-v12-workflow-blocker:{self.expected_head} -->"
                self.comment_once(
                    self.pr_number,
                    marker,
                    "Exact-head source qualification passed in the isolated v12 job, but the "
                    f"required hosted workflow matrix is not terminal-success: `{json.dumps(terminal, sort_keys=True)}`. "
                    "Failed jobs were rerun once without bypass. The PR remains draft.",
                )
                self.state["phase"] = "blocked_required_workflows"
                self.save()
                return 2

            pr = self.stable_pr()
            self.verify_subject(pr)
            author = str((pr.get("user") or {}).get("login") or "")
            approvals, changes = self.reviews(author)
            self.state["review"] = {
                "author": author,
                "eligible_exact_head_non_author_approvals": approvals,
                "exact_head_changes_requested": changes,
            }
            self.save()
            if changes or not approvals:
                self.request_review(pr)
                marker = f"<!-- g1-v12-review-blocker:{self.expected_head} -->"
                self.comment_once(
                    self.pr_number,
                    marker,
                    "All repository-controlled source and hosted workflow gates are terminal-success "
                    f"for `{self.expected_head}`, but ordinary merge remains blocked. Eligible exact-head "
                    f"non-author approvals: `{approvals}`; exact-head changes requested: `{changes}`. "
                    "A reviewer was requested. No self-approval, dismissal, or administrator bypass was used.",
                )
                self.state["phase"] = "blocked_independent_review"
                self.save()
                return 0

            pr = self.mark_ready(pr)
            self.ordinary_merge(pr)
            self.state["phase"] = "merged_ordinary_protected_path"
            self.save()
            marker = f"<!-- g1-v12-ordinary-merge:{self.expected_head} -->"
            self.comment_once(
                self.pr_number,
                marker,
                f"PR #{self.pr_number} was merged through the ordinary protected merge endpoint at exact "
                f"head `{self.expected_head}` after terminal-success source/workflow checks and eligible "
                f"non-author approval by `{approvals}`. No administrator bypass or evidence promotion was used.",
            )
            return 0
        except BaseException as error:
            self.state["phase"] = "failed_closed"
            self.state["fatal"] = f"{type(error).__name__}: {error}"
            self.save()
            try:
                marker = f"<!-- g1-v12-failed-closed:{self.expected_head} -->"
                self.comment_once(
                    self.pr_number,
                    marker,
                    f"The v12 governor failed closed for `{self.expected_head}`: `{type(error).__name__}: {error}`. "
                    "The PR was not administrator-bypassed and no external evidence state was promoted.",
                )
            except Exception as comment_error:
                self.state["comment_error"] = f"{type(comment_error).__name__}: {comment_error}"
                self.save()
            return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pr-number", type=int, required=True)
    parser.add_argument("--issue-number", type=int, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-base", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--qualification-run", required=True)
    parser.add_argument("--token-env", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    token = os.environ.get(args.token_env)
    if not token:
        raise SystemExit(f"missing token environment: {args.token_env}")
    return Governor(
        repository=args.repository,
        pr_number=args.pr_number,
        issue_number=args.issue_number,
        expected_head=args.expected_head,
        expected_base=args.expected_base,
        expected_tree=args.expected_tree,
        qualification_run=args.qualification_run,
        token=token,
        output=args.output,
    ).run()


if __name__ == "__main__":
    raise SystemExit(main())
