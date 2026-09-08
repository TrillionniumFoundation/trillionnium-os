#!/usr/bin/env python3
"""Fail-closed source aggregate for the canonical G1 pull request.

The protected branch requires the existing ``L1 exact-source-head aggregate
candidate`` context. This entry point binds the real prospective-merge source
qualification to the same live pull-request base/head tuple. It does not require
Android target, review-index, promotion, device, fault, signing or release
receipts and cannot promote an evidence claim.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.g1_pr_aggregate_api import GitHubApi
from tools.g1_pr_aggregate_common import AggregateError
from tools.g1_pr_aggregate_verify import verify_pr_aggregate


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


def main(argv: Sequence[str]) -> int:
    args = _parse_args(argv)
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("G1 PR source aggregate failed: GITHUB_TOKEN is required", file=sys.stderr)
        return 2
    try:
        report = verify_pr_aggregate(
            repository=args.repository,
            pr_number=args.pr_number,
            expected_base_commit=args.base_commit,
            expected_head_commit=args.head_commit,
            repo_root=args.repo_root,
            api=GitHubApi(base_url=args.api_base_url, token=token),
            timeout_seconds=args.timeout_seconds,
            poll_seconds=args.poll_seconds,
        )
        _write_json(args.output, report)
        print(
            f"G1 exact PR source aggregate passed: {report['report_sha256']}",
            file=sys.stdout,
        )
        return 0
    except (AggregateError, OSError, subprocess.SubprocessError) as error:
        print(f"G1 PR source aggregate failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
