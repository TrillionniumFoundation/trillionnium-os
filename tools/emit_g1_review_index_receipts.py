#!/usr/bin/env python3
"""Emit non-authorizing exact-head and synthetic review-index receipts."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

SHA40 = re.compile(r"^[0-9a-f]{40}$")
PATH = "governance/pr41-review-index.v1.json"
CLAIM = "CLOSED_WORLD_REVIEW_INDEX_RECEIPT_ONLY_NO_APPROVAL_OR_INTEGRATION_AUTHORITY"


def fail(message: str) -> None:
    raise ValueError(message)


def sha(value: str, label: str) -> str:
    if SHA40.fullmatch(value) is None:
        fail(f"{label} must be lowercase 40-hex")
    return value


def load(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        fail("review index root must be an object")
    return value, raw


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
        fail(f"git {' '.join(args)} failed: {completed.stderr.strip()}")
    return completed.stdout.strip()


def write(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def parse(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pr-number", required=True, type=int)
    parser.add_argument("--base-commit", required=True)
    parser.add_argument("--base-tree", required=True)
    parser.add_argument("--head-commit", required=True)
    parser.add_argument("--head-tree", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--workflow-attempt", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse(argv)
    try:
        root = args.root.resolve()
        base = sha(args.base_commit, "base commit")
        base_tree = sha(args.base_tree, "base tree")
        head = sha(args.head_commit, "head commit")
        head_tree = sha(args.head_tree, "head tree")
        if git(root, "rev-parse", "HEAD^{commit}") != head:
            fail("checkout is not exact head")
        if git(root, "rev-parse", f"{base}^{{tree}}") != base_tree:
            fail("base tree differs")
        if git(root, "rev-parse", f"{head}^{{tree}}") != head_tree:
            fail("head tree differs")
        if git(root, "merge-base", "--is-ancestor", base, head) != "":
            fail("base is not an ancestor of head")
        if git(root, "status", "--porcelain=v1", "--untracked-files=all") != "":
            fail("checkout is dirty")

        index, raw = load(root / PATH)
        if index.get("schema") != "org.trillionnium.g1-pr-review-index.v1":
            fail("review index schema drifted")
        if index.get("repository") != args.repository or index.get("pull_request") != args.pr_number:
            fail("review index subject differs")
        if index.get("base") != {"commit": base, "tree": base_tree}:
            fail("review index base differs")
        expected = index.get("expected")
        if not isinstance(expected, dict):
            fail("review index expected inventory is absent")
        path_count = expected.get("path_count")
        change_count = expected.get("change_count")
        if type(path_count) is not int or path_count <= 0 or path_count != change_count:
            fail("review index counts are invalid")
        paths_sha = expected.get("paths_sha256")
        changes_sha = expected.get("changes_sha256")
        if not isinstance(paths_sha, str) or len(paths_sha) != 64:
            fail("review index paths digest is invalid")
        if not isinstance(changes_sha, str) or len(changes_sha) != 64:
            fail("review index changes digest is invalid")
        for field in (
            "automatic_redispatch", "integration_authorized",
            "promotion_authorized", "public_release",
        ):
            if index.get(field) is not False:
                fail(f"review index {field} widened")

        env = {
            "GIT_AUTHOR_NAME": "g1-review-index",
            "GIT_AUTHOR_EMAIL": "g1-review-index@invalid",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
            "GIT_COMMITTER_NAME": "g1-review-index",
            "GIT_COMMITTER_EMAIL": "g1-review-index@invalid",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
        }
        completed = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(root), "commit-tree", head_tree, "-p", base, "-p", head],
            input=f"G1 review-index synthetic merge {base} + {head}\n",
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C", "LANG": "C", **env},
        )
        if completed.returncode != 0:
            fail(f"commit-tree failed: {completed.stderr.strip()}")
        merge_commit = sha(completed.stdout.strip(), "merge commit")
        common = {
            "schema": "org.trillionnium.g1-review-index-receipt.v1",
            "program_revision": "2026-08-31-g1",
            "repository": args.repository,
            "pull_request_number": args.pr_number,
            "base_commit": base,
            "base_tree": base_tree,
            "head_commit": head,
            "head_tree": head_tree,
            "review_index_path": PATH,
            "review_index_sha256": hashlib.sha256(raw).hexdigest(),
            "path_count": path_count,
            "paths_sha256": paths_sha,
            "change_count": change_count,
            "changes_sha256": changes_sha,
            "workflow_run_id": args.workflow_run_id,
            "workflow_attempt": args.workflow_attempt,
            "claim_ceiling": CLAIM,
            "automatic_redispatch": False,
            "integration_authorized": False,
            "promotion_authorized": False,
            "public_release": False,
        }
        exact = {
            **common,
            "subject_kind": "exact_head",
            "parent_commits": [],
            "merge_commit": None,
            "merge_tree": None,
            "result": "L1_EXACT_HEAD_REVIEW_INDEX_BOUND",
        }
        synthetic = {
            **common,
            "subject_kind": "synthetic_merge",
            "parent_commits": [base, head],
            "merge_commit": merge_commit,
            "merge_tree": head_tree,
            "result": "L1_SYNTHETIC_MERGE_REVIEW_INDEX_BOUND",
        }
        args.output_dir.mkdir(parents=True, exist_ok=True)
        write(args.output_dir / "g1-exact-head-review-index-receipt.json", exact)
        write(args.output_dir / "g1-synthetic-merge-review-index-receipt.json", synthetic)
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        print(f"review-index receipt emission failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
