#!/usr/bin/env python3
"""Verify immutable PR/source identity without recursively qualifying CI.

This command intentionally does not inspect workflow runs, artifacts, review
indexes, evidence receipts, branch-protection contexts, or release state. The
calling workflow already owns the source test jobs; this final check only
confirms that those jobs are bound to the current pull-request base/head and to
this clean checkout.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Sequence
from urllib.request import Request, urlopen

SHA40 = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def fail(message: str) -> None:
    raise ValueError(message)


def git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C", "LANG": "C"},
    )
    if completed.returncode != 0:
        fail(f"git {' '.join(args)} failed")
    return completed.stdout.strip()


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pr-number", type=int, required=True)
    parser.add_argument("--base-commit", required=True)
    parser.add_argument("--head-commit", required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    # Retained as compatibility arguments for the historical workflow command.
    parser.add_argument("--timeout-seconds", type=float, default=0)
    parser.add_argument("--poll-seconds", type=float, default=0)
    parser.add_argument("--api-base-url", default="https://api.github.com/")
    return parser.parse_args(argv)


def get_pull(repository: str, pr_number: int, api_base: str, token: str) -> dict[str, Any]:
    url = f"{api_base.rstrip('/')}/repos/{repository}/pulls/{pr_number}"
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "trillionnium-source-identity-gate",
        },
    )
    with urlopen(request, timeout=30) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        fail("pull request API response is not an object")
    return value


def verify(args: argparse.Namespace, token: str) -> dict[str, Any]:
    if not REPOSITORY.fullmatch(args.repository):
        fail("repository identity is malformed")
    if args.pr_number <= 0:
        fail("pull request number must be positive")
    if not SHA40.fullmatch(args.base_commit) or not SHA40.fullmatch(args.head_commit):
        fail("base/head commit must be lowercase 40-hex SHA")

    pull = get_pull(args.repository, args.pr_number, args.api_base_url, token)
    live_base = pull.get("base", {}).get("sha")
    live_head = pull.get("head", {}).get("sha")
    if live_base != args.base_commit:
        fail("pull request base moved")
    if live_head != args.head_commit:
        fail("pull request head moved")

    root = args.repo_root.resolve()
    if git(root, "rev-parse", "HEAD^{commit}") != args.head_commit:
        fail("local checkout is not the exact pull-request head")
    if git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        fail("local checkout is not clean")
    if git(root, "merge-base", "--is-ancestor", args.base_commit, args.head_commit):
        fail("pull-request base is not an ancestor of source head")

    report: dict[str, Any] = {
        "schema": "org.trillionnium.source-identity-gate.v1",
        "result": "SOURCE_IDENTITY_PASSED",
        "repository": args.repository,
        "pull_request": args.pr_number,
        "base_commit": args.base_commit,
        "head_commit": args.head_commit,
        "head_tree": git(root, "rev-parse", "HEAD^{tree}"),
        "cross_workflow_requirements": [],
        "review_index_required": False,
        "evidence_receipts_required": False,
        "report_sha256": "",
    }
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    report["report_sha256"] = hashlib.sha256(encoded).hexdigest()
    return report


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print("source identity gate failed: GITHUB_TOKEN is required", file=sys.stderr)
        return 2
    try:
        report = verify(args, token)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"source identity gate passed: {report['report_sha256']}")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"source identity gate failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
