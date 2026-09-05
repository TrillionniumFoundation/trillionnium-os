#!/usr/bin/env python3
"""Verify that a pull request, its prose and the checked-out Git object agree.

This is a source-subject verifier, not an integration-readiness evaluator. An
open draft pull request is a valid exact-head source subject and remains
ineligible for merge until the independent governance path marks it ready.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


class SubjectError(Exception):
    pass


SHA40 = re.compile(r"^[0-9a-f]{40}$")
CLAIM_PATTERNS = {
    "base_commit": re.compile(
        r"(?im)^\s*base\s+(?:commit|sha)\s*:\s*`?([0-9a-f]{40})`?\s*$"
    ),
    "head_commit": re.compile(
        r"(?im)^\s*head\s+(?:commit|sha)\s*:\s*`?([0-9a-f]{40})`?\s*$"
    ),
    "head_tree": re.compile(
        r"(?im)^\s*head\s+tree\s*:\s*`?([0-9a-f]{40})`?\s*$"
    ),
}
WORKFLOW_REFERENCE = re.compile(
    r"`?(\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml)`?"
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SubjectError(message)


def git(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", *args],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise SubjectError(f"git {' '.join(args)} failed: {error}") from error
    return result.stdout.strip()


def extract_claims(body: str) -> dict[str, str]:
    claims: dict[str, str] = {}
    for name, pattern in CLAIM_PATTERNS.items():
        matches = pattern.findall(body)
        require(
            len(set(matches)) <= 1,
            f"PR body contains conflicting {name} claims",
        )
        if matches:
            claims[name] = matches[0]
    return claims


def referenced_workflows(body: str) -> set[str]:
    return set(WORKFLOW_REFERENCE.findall(body))


def observe_pull_lifecycle(pull: Any) -> dict[str, bool]:
    """Validate source-subject lifecycle without implying merge readiness."""
    require(isinstance(pull, dict), "pull request API response is not an object")
    require(pull.get("state") == "open", "pull request is not open")
    draft = pull.get("draft")
    require(isinstance(draft, bool), "pull request draft state is not observable")
    return {
        "draft": draft,
        "source_subject_valid": True,
        "integration_eligibility_evaluated": False,
    }


def api_get(repository: str, path: str, token: str) -> Any:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "trillionnium-pr-subject-verifier",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except (urllib.error.URLError, ValueError) as error:
        raise SubjectError(f"GitHub API read failed for {path}: {error}") from error


def verify(
    root: Path,
    repository: str,
    pr_number: int,
    event_head: str,
    event_base: str,
    token: str,
) -> dict[str, Any]:
    require(
        bool(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)),
        "repository must be owner/name",
    )
    require(pr_number > 0, "PR number must be positive")
    require(
        SHA40.fullmatch(event_head) is not None,
        "event head is not a lowercase SHA-1",
    )
    require(
        SHA40.fullmatch(event_base) is not None,
        "event base is not a lowercase SHA-1",
    )
    require(bool(token), "GITHUB_TOKEN is required for live subject verification")

    root = root.resolve()
    local_head = git(root, "rev-parse", "HEAD")
    local_tree = git(root, "rev-parse", "HEAD^{tree}")
    require(
        local_head == event_head,
        "checked-out HEAD differs from pull-request event head",
    )
    require(
        not git(root, "status", "--porcelain=v1", "--untracked-files=all"),
        "checked-out source is dirty",
    )

    pull = api_get(repository, f"/pulls/{pr_number}", token)
    lifecycle = observe_pull_lifecycle(pull)
    actual_head = pull.get("head", {}).get("sha")
    actual_base = pull.get("base", {}).get("sha")
    require(
        actual_head == event_head == local_head,
        "live PR head, event head and checkout differ",
    )
    require(actual_base == event_base, "live PR base and event base differ")

    body = pull.get("body") or ""
    require(isinstance(body, str), "pull request body is not text")
    claims = extract_claims(body)
    if "base_commit" in claims:
        require(claims["base_commit"] == actual_base, "PR body base commit is stale")
    if "head_commit" in claims:
        require(claims["head_commit"] == actual_head, "PR body head commit is stale")
    if "head_tree" in claims:
        require(claims["head_tree"] == local_tree, "PR body head tree is stale")

    workflow_root = root / ".github/workflows"
    local_workflows = {
        str(path.relative_to(root))
        for path in workflow_root.iterdir()
        if path.is_file() and path.suffix in {".yml", ".yaml"}
    }
    references = referenced_workflows(body)
    missing_references = sorted(references - local_workflows)
    require(
        not missing_references,
        f"PR body references absent workflow files: {missing_references}",
    )

    merge_ref_sha = None
    try:
        merge_ref = api_get(repository, f"/git/ref/pull/{pr_number}/merge", token)
        merge_ref_sha = (
            merge_ref.get("object", {}).get("sha")
            if isinstance(merge_ref, dict)
            else None
        )
    except SubjectError:
        # A transiently absent prospective merge object does not rewrite source
        # identity; synthetic-merge qualification remains a separate required job.
        merge_ref_sha = None

    return {
        "schema": "org.trillionnium.pr-subject-observation.v1",
        "status": "PASS_LIVE_PR_SUBJECT_MATCH",
        "repository": repository,
        "pr_number": pr_number,
        "base_ref": pull["base"]["ref"],
        "base_commit": actual_base,
        "head_ref": pull["head"]["ref"],
        "head_commit": actual_head,
        "head_tree": local_tree,
        "draft": lifecycle["draft"],
        "source_subject_valid": lifecycle["source_subject_valid"],
        "integration_eligibility_evaluated": lifecycle[
            "integration_eligibility_evaluated"
        ],
        "prospective_merge_commit": merge_ref_sha,
        "body_identity_claims": claims,
        "body_workflow_references": sorted(references),
        "workflow_count": len(local_workflows),
        "claim_ceiling": "LIVE_PR_SOURCE_SUBJECT_ONLY",
        "approval_observed": False,
        "attestation_observed": False,
        "promotion_authorized": False,
        "public_release": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pr-number", type=int, required=True)
    parser.add_argument("--event-head", required=True)
    parser.add_argument("--event-base", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    token = os.environ.get("GITHUB_TOKEN", "")
    try:
        report = verify(
            args.root,
            args.repository,
            args.pr_number,
            args.event_head,
            args.event_base,
            token,
        )
    except SubjectError as error:
        print(f"PR subject verification failed: {error}", file=sys.stderr)
        return 1
    encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
