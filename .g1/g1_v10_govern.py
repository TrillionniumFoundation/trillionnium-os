#!/usr/bin/env python3
"""Run the exact-head hosted gate, independent-review request and ordinary merge.

This script never approves a pull request, dismisses a review, bypasses branch
protection, or promotes target/device/release evidence. GitHub remains the final
arbiter for the ordinary merge.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

SUCCESS_CONCLUSIONS = {"success", "neutral", "skipped"}
ACTIVE_STATES = {"queued", "in_progress", "waiting", "pending", "requested"}


class ApiError(RuntimeError):
    def __init__(self, status: int, body: Any):
        super().__init__(f"GitHub API {status}: {body}")
        self.status = status
        self.body = body


class Controller:
    def __init__(self, *, repository: str, target_branch: str, target_sha: str,
                 pr_number: int, token: str, output: Path) -> None:
        self.repository = repository
        self.target_branch = target_branch
        self.target_sha = target_sha
        self.pr_number = pr_number
        self.token = token
        self.output = output
        self.api_root = f"https://api.github.com/repos/{repository}"
        self.state: dict[str, Any] = {
            "schema": "org.trillionnium.g1.final-closure-v10.v1",
            "repository": repository,
            "target_branch": target_branch,
            "target_sha": target_sha,
            "pull_request": pr_number,
            "administrator_bypass": False,
            "self_approval": False,
            "automatic_evidence_promotion": False,
            "public_release": False,
            "phase": "initialized",
        }
        self.save()

    def save(self) -> None:
        self.state["updated_at_utc"] = datetime.now(timezone.utc).isoformat()
        self.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.output.with_suffix(self.output.suffix + ".tmp")
        temporary.write_text(json.dumps(self.state, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, self.output)

    def request(self, method: str, path: str, payload: Any | None = None,
                *, api_root: str | None = None) -> Any:
        url = (api_root or self.api_root) + path
        data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "trillionnium-g1-final-closure-v10",
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, method=method, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                raw = response.read()
                if not raw:
                    return None
                return json.loads(raw)
        except urllib.error.HTTPError as error:
            raw = error.read(65536)
            try:
                body: Any = json.loads(raw)
            except Exception:
                body = raw.decode("utf-8", errors="replace")
            raise ApiError(error.code, body) from error

    def get_pr(self) -> dict[str, Any]:
        return self.request("GET", f"/pulls/{self.pr_number}")

    def ref_sha(self, branch: str) -> str:
        encoded = urllib.parse.quote(f"heads/{branch}", safe="/")
        value = self.request("GET", f"/git/ref/{encoded}")
        return value["object"]["sha"]

    @staticmethod
    def parse_time(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def latest_runs(self) -> list[dict[str, Any]]:
        branch = urllib.parse.quote(self.target_branch, safe="")
        value = self.request(
            "GET",
            f"/actions/workflows/g1-synthetic-merge.yml/runs?branch={branch}&event=workflow_dispatch&per_page=100",
        )
        return [run for run in value.get("workflow_runs", []) if run.get("head_sha") == self.target_sha]

    def dispatch_and_wait(self, base_sha: str) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        active = [run for run in self.latest_runs() if run.get("status") in ACTIVE_STATES]
        recent_active = [
            run for run in active
            if self.parse_time(run["created_at"]) >= now - timedelta(minutes=10)
        ]
        if recent_active:
            selected = max(recent_active, key=lambda run: run["id"])
            run_id = selected["id"]
            threshold = self.parse_time(selected["created_at"]) - timedelta(seconds=1)
            self.state["dispatch"] = {"decision": "reuse_recent_active", "run_id": run_id}
        else:
            threshold = now - timedelta(seconds=5)
            payload = {
                "ref": self.target_branch,
                "inputs": {
                    "base_sha": base_sha,
                    "head_sha": self.target_sha,
                    "head_repository": self.repository,
                },
            }
            self.request("POST", "/actions/workflows/g1-synthetic-merge.yml/dispatches", payload)
            run_id = None
            self.state["dispatch"] = {
                "decision": "dispatched_fresh_exact_pair",
                "base_sha": base_sha,
                "head_sha": self.target_sha,
                "dispatched_at_utc": now.isoformat(),
            }
        self.state["phase"] = "awaiting_synthetic_merge"
        self.save()

        for attempt in range(1, 181):
            if run_id is None:
                candidates = [
                    run for run in self.latest_runs()
                    if self.parse_time(run["created_at"]) >= threshold
                ]
                if candidates:
                    run_id = max(candidates, key=lambda run: run["id"])["id"]
                    self.state["dispatch"]["run_id"] = run_id
                    self.save()
            if run_id is not None:
                run = self.request("GET", f"/actions/runs/{run_id}")
                if run.get("head_sha") != self.target_sha:
                    raise RuntimeError("synthetic-merge run head moved")
                self.state["synthetic_merge"] = {
                    "run_id": run_id,
                    "status": run.get("status"),
                    "conclusion": run.get("conclusion"),
                    "event": run.get("event"),
                    "html_url": run.get("html_url"),
                }
                self.save()
                if run.get("status") == "completed":
                    if run.get("conclusion") != "success":
                        jobs = self.request("GET", f"/actions/runs/{run_id}/jobs?per_page=100")
                        self.state["synthetic_merge"]["jobs"] = [
                            {
                                "id": job.get("id"),
                                "name": job.get("name"),
                                "status": job.get("status"),
                                "conclusion": job.get("conclusion"),
                                "failed_steps": [
                                    step.get("name") for step in job.get("steps", [])
                                    if step.get("conclusion") == "failure"
                                ],
                            }
                            for job in jobs.get("jobs", [])
                        ]
                        self.save()
                        raise RuntimeError(f"synthetic-merge run {run_id} failed")
                    return run
            if attempt == 180:
                raise RuntimeError("synthetic-merge run did not complete within 30 minutes")
            time.sleep(10)
        raise AssertionError("unreachable")

    def verify_current_checks(self) -> None:
        value = self.request("GET", f"/commits/{self.target_sha}/check-runs?per_page=100")
        checks = value.get("check_runs", [])
        if not checks:
            raise RuntimeError("current target has no check runs")
        latest: dict[str, dict[str, Any]] = {}
        for check in checks:
            name = check.get("name")
            if not isinstance(name, str):
                continue
            if name not in latest or check.get("id", 0) > latest[name].get("id", 0):
                latest[name] = check
        bad = [
            {
                "name": name,
                "status": check.get("status"),
                "conclusion": check.get("conclusion"),
                "details_url": check.get("details_url"),
            }
            for name, check in sorted(latest.items())
            if check.get("status") != "completed" or check.get("conclusion") not in SUCCESS_CONCLUSIONS
        ]
        combined = self.request("GET", f"/commits/{self.target_sha}/status")
        statuses = combined.get("statuses", [])
        if statuses and combined.get("state") != "success":
            bad.append({"legacy_combined_status": combined.get("state")})
        self.state["current_head_checks"] = {
            "latest_by_name": [
                {
                    "id": check.get("id"),
                    "name": name,
                    "status": check.get("status"),
                    "conclusion": check.get("conclusion"),
                    "details_url": check.get("details_url"),
                }
                for name, check in sorted(latest.items())
            ],
            "legacy_status_count": len(statuses),
            "legacy_combined_state": combined.get("state"),
            "strict_success": not bad,
            "failures": bad,
        }
        self.save()
        if bad:
            raise RuntimeError(f"current-head checks are not strictly successful: {bad}")

    def mark_ready(self, pr: dict[str, Any]) -> dict[str, Any]:
        if pr.get("draft") is not True:
            return pr
        payload = {
            "query": "mutation($id:ID!){markPullRequestReadyForReview(input:{pullRequestId:$id}){pullRequest{isDraft headRefOid}}}",
            "variables": {"id": pr["node_id"]},
        }
        value = self.request("POST", "", payload, api_root="https://api.github.com/graphql")
        if value.get("errors"):
            raise RuntimeError(f"mark ready failed: {value['errors']}")
        observed = value["data"]["markPullRequestReadyForReview"]["pullRequest"]
        if observed.get("isDraft") is not False or observed.get("headRefOid") != self.target_sha:
            raise RuntimeError("ready-for-review mutation did not preserve exact head")
        self.state["ready_for_review"] = True
        self.save()
        return self.get_pr()

    def codeowners(self) -> tuple[list[str], list[str]]:
        raw = ""
        source_path = None
        for path in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
            completed = subprocess.run(
                ["git", "--no-replace-objects", "show", f"{self.target_sha}:{path}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if completed.returncode == 0:
                raw = completed.stdout.decode("utf-8", errors="replace")
                source_path = path
                break
        author = ((self.get_pr().get("user") or {}).get("login") or "").lower()
        users: set[str] = set()
        teams: set[str] = set()
        for source_line in raw.splitlines():
            line = source_line.split("#", 1)[0]
            fields = line.split()
            for token in fields[1:]:
                if not token.startswith("@"):
                    continue
                owner = token[1:]
                if "/" in owner:
                    org, slug = owner.split("/", 1)
                    if org.lower() == "trillionniumfoundation" and re.fullmatch(r"[A-Za-z0-9_.-]+", slug):
                        teams.add(slug)
                elif (
                    owner.lower() != author
                    and not owner.lower().endswith("[bot]")
                    and re.fullmatch(r"[A-Za-z0-9_.-]+", owner)
                ):
                    users.add(owner)
        self.state["codeowners"] = {
            "source_path": source_path,
            "reviewers": sorted(users),
            "team_reviewers": sorted(teams),
        }
        self.save()
        return sorted(users)[:15], sorted(teams)[:15]

    def request_reviewers(self) -> None:
        users, teams = self.codeowners()
        if not users and not teams:
            self.state["review_request"] = {"requested": False, "reason": "no_eligible_codeowners"}
            self.save()
            return
        payload = {"reviewers": users, "team_reviewers": teams}
        try:
            value = self.request("POST", f"/pulls/{self.pr_number}/requested_reviewers", payload)
            self.state["review_request"] = {
                "requested": True,
                "users": [entry.get("login") for entry in value.get("requested_reviewers", [])],
                "teams": [entry.get("slug") for entry in value.get("requested_teams", [])],
            }
        except ApiError as error:
            # A stale/ineligible CODEOWNER cannot be silently presented as requested.
            self.state["review_request"] = {
                "requested": False,
                "users": users,
                "teams": teams,
                "error": str(error),
            }
        self.save()

    def exact_approvals(self, author: str) -> list[str]:
        reviews = self.request("GET", f"/pulls/{self.pr_number}/reviews?per_page=100")
        latest: dict[str, dict[str, Any]] = {}
        for review in reviews:
            login = ((review.get("user") or {}).get("login"))
            if login:
                latest[login] = review
        return sorted(
            login for login, review in latest.items()
            if login.lower() != author.lower()
            and not login.lower().endswith("[bot]")
            and review.get("state") == "APPROVED"
            and review.get("commit_id") == self.target_sha
        )

    def comment_once(self, marker: str, body: str) -> None:
        comments = self.request("GET", f"/issues/{self.pr_number}/comments?per_page=100")
        if any(marker in str(comment.get("body", "")) for comment in comments):
            return
        self.request("POST", f"/issues/{self.pr_number}/comments", {"body": marker + "\n\n" + body})

    def await_review(self, author: str) -> list[str]:
        self.state["phase"] = "awaiting_independent_review"
        self.save()
        for attempt in range(1, 81):
            pr = self.get_pr()
            if pr.get("merged") is True:
                self.state["phase"] = "merged_by_concurrent_ordinary_actor"
                self.state["merge_commit_sha"] = pr.get("merge_commit_sha")
                self.save()
                return ["concurrent_merge"]
            if pr.get("state") != "open" or (pr.get("head") or {}).get("sha") != self.target_sha:
                raise RuntimeError("pull request closed or moved while awaiting review")
            approvals = self.exact_approvals(author)
            self.state["eligible_exact_head_non_author_approvals"] = approvals
            self.save()
            if approvals:
                return approvals
            if attempt < 80:
                time.sleep(15)
        marker = f"<!-- g1-v10-review-blocker:{self.target_sha} -->"
        body = (
            f"Exact-head source qualification passed for `{self.target_sha}`, but ordinary merge remains "
            "blocked pending an eligible non-author approval bound to this exact head. No self-approval, "
            "review dismissal, or administrator bypass was used."
        )
        self.comment_once(marker, body)
        self.state["phase"] = "blocked_independent_review"
        self.state["blocking_reason"] = body
        self.save()
        raise SystemExit(20)

    def merge(self) -> None:
        pr = self.get_pr()
        if pr.get("merged") is True:
            self.state["phase"] = "merged"
            self.state["merge_commit_sha"] = pr.get("merge_commit_sha")
            self.save()
            return
        if pr.get("state") != "open" or pr.get("draft") is not False:
            raise RuntimeError("pull request is not an open ready-for-review subject")
        if (pr.get("head") or {}).get("sha") != self.target_sha:
            raise RuntimeError("pull request head moved before merge")
        payload = {
            "sha": self.target_sha,
            "merge_method": "merge",
            "commit_title": "Merge PR #41: close repository-controlled G1 blockers",
            "commit_message": (
                "Ordinary protected merge of the exact qualified PR head. No administrator bypass, "
                "target-evidence, signing, promotion, or public-release claim is implied."
            ),
        }
        try:
            value = self.request("PUT", f"/pulls/{self.pr_number}/merge", payload)
        except ApiError as error:
            self.state["phase"] = "ordinary_merge_rejected"
            self.state["merge_error"] = str(error)
            self.save()
            raise
        self.state["merge_api_result"] = value
        if value.get("merged") is not True:
            self.state["phase"] = "ordinary_merge_rejected"
            self.save()
            raise RuntimeError(f"ordinary merge rejected: {value}")
        self.state["phase"] = "merged"
        self.state["merge_commit_sha"] = value.get("sha")
        self.save()

    def run(self) -> None:
        target = self.ref_sha(self.target_branch)
        if target != self.target_sha:
            raise RuntimeError(f"target branch moved: expected {self.target_sha}, observed {target}")
        base = self.ref_sha("main")
        self.state["base_sha"] = base
        pr = self.get_pr()
        if pr.get("merged") is True:
            self.state["phase"] = "already_merged"
            self.state["merge_commit_sha"] = pr.get("merge_commit_sha")
            self.save()
            return
        if pr.get("state") != "open" or (pr.get("head") or {}).get("sha") != self.target_sha:
            raise RuntimeError("pull request is not the exact open target subject")
        self.dispatch_and_wait(base)
        self.verify_current_checks()
        pr = self.mark_ready(self.get_pr())
        author = ((pr.get("user") or {}).get("login") or "")
        self.request_reviewers()
        approvals = self.await_review(author)
        self.state["eligible_exact_head_non_author_approvals"] = approvals
        self.save()
        self.verify_current_checks()
        self.merge()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--target-branch", required=True)
    parser.add_argument("--target-sha", required=True)
    parser.add_argument("--pr-number", required=True, type=int)
    parser.add_argument("--token-env", default="G1_TOKEN")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    token = os.environ.get(args.token_env)
    if not token:
        raise SystemExit(f"missing token environment: {args.token_env}")
    controller = Controller(
        repository=args.repository,
        target_branch=args.target_branch,
        target_sha=args.target_sha,
        pr_number=args.pr_number,
        token=token,
        output=args.output,
    )
    try:
        controller.run()
    except SystemExit:
        raise
    except BaseException as error:
        controller.state["phase"] = "failed"
        controller.state["error"] = f"{type(error).__name__}: {error}"
        controller.save()
        raise
    finally:
        controller.token = ""
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
