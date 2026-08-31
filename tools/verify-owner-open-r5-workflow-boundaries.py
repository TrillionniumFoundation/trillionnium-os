#!/usr/bin/env python3
"""Fail closed on transient/self-modifying Owner-Open R5 workflows.

The R5 evidence program separates capture, independent review, and promotion.
Tracked CI must therefore be read-only with respect to repository contents,
checkout the exact PR head rather than GitHub's synthetic merge commit, and
must not retain bootstrap/converger executors after migration.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any

FORBIDDEN_NAME_PARTS = (
    "one-shot",
    "converger",
    "bootstrap",
    "watchdog",
    "migration",
    "executor",
    "history-hardening",
)
EXACT_REF_TOKENS = (
    "github.event.pull_request.head.sha",
    "env.EXPECTED_SHA",
    "env.EXPECTED_HEAD",
    "inputs.source_commit",
)
WRITE_PERMISSION = re.compile(
    r"(?m)^\s*(?:contents|actions|pull-requests|issues|checks|deployments):\s*write\s*$"
)
API_WRITE = re.compile(
    r"(?:--method\s+(?:POST|PUT|PATCH|DELETE)\b|"
    r"method\s*=\s*['\"](?:POST|PUT|PATCH|DELETE)['\"])",
    re.IGNORECASE,
)
CHECKOUT = re.compile(r"^\s*- uses: actions/checkout@")
EXACT_HEAD_ASSERTION = re.compile(
    r"\bgit\s+(?:--no-replace-objects\s+)?rev-parse\s+HEAD\b"
)


class BoundaryError(ValueError):
    pass


def _checkout_blocks(lines: list[str]) -> list[tuple[int, str]]:
    blocks: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        if CHECKOUT.match(line) is None:
            continue
        indent = len(line) - len(line.lstrip())
        block = [line]
        for following in lines[index + 1 :]:
            stripped = following.strip()
            following_indent = len(following) - len(following.lstrip())
            if stripped and following_indent <= indent and stripped.startswith("-"):
                break
            if stripped and following_indent < indent:
                break
            block.append(following)
        blocks.append((index + 1, "\n".join(block)))
    return blocks


def verify(root: Path) -> dict[str, Any]:
    root = root.resolve()
    workflow_dir = root / ".github" / "workflows"
    errors: list[str] = []
    checked: list[str] = []

    required = {
        "owner-open-r5-tool-loop.yml",
        "owner-open-r5-target-evidence-capture.yml",
        "owner-open-r5-governance-readiness.yml",
    }
    observed = {path.name for path in workflow_dir.glob("owner-open-r5*.yml")}
    for name in sorted(required - observed):
        errors.append(f"required permanent workflow is absent: {name}")

    for path in sorted(workflow_dir.glob("owner-open-r5*.yml")):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            errors.append(f"cannot read workflow {path.name}: {error}")
            continue
        lines = text.splitlines()
        checked.append(path.name)
        lowered = path.name.lower()

        if any(part in lowered for part in FORBIDDEN_NAME_PARTS):
            errors.append(f"transient workflow remains tracked: {path.name}")
        if WRITE_PERMISSION.search(text):
            errors.append(f"repository write permission remains: {path.name}")
        if re.search(r"\bgit\s+push\b", text):
            errors.append(f"workflow can push repository refs: {path.name}")
        if API_WRITE.search(text) and "api.github.com/repos/" in text:
            errors.append(f"workflow can mutate GitHub repository controls: {path.name}")

        has_pull_request = bool(re.search(r"(?m)^\s{2}pull_request\s*:", text))
        if not has_pull_request:
            continue

        blocks = _checkout_blocks(lines)
        if not blocks:
            errors.append(f"pull-request workflow has no checkout: {path.name}")
        for line_number, block in blocks:
            if not any(token in block for token in EXACT_REF_TOKENS):
                errors.append(
                    f"PR checkout is not exact-head-bound: {path.name}:{line_number}"
                )
            if "fetch-depth: 0" not in block:
                errors.append(
                    f"PR checkout lacks complete history: {path.name}:{line_number}"
                )
            if "persist-credentials: false" not in block:
                errors.append(
                    f"PR checkout persists credentials: {path.name}:{line_number}"
                )

        if EXACT_HEAD_ASSERTION.search(text) is None:
            errors.append(f"PR workflow lacks exact-head assertion: {path.name}")
        for line_number, line in enumerate(lines, 1):
            if (
                "name:" in line
                and "${{ github.sha }}" in line
                and "pull_request.head.sha" not in line
            ):
                errors.append(
                    f"PR artifact/check identity uses merge-trigger SHA: "
                    f"{path.name}:{line_number}"
                )

    forbidden_paths = [root / ".github" / "r5-bootstrap"]
    forbidden_paths.extend(
        sorted((root / "tools" / "owner-open").glob("apply_r5_*.py"))
    )
    for path in forbidden_paths:
        if path.exists():
            errors.append(f"retired migration material remains: {path.relative_to(root)}")

    return {
        "ok": not errors,
        "errors": errors,
        "facts": {
            "checked_workflows": checked,
            "workflow_count": len(checked),
            "repository_write_workflows": 0 if not any(
                "write permission" in error or "push repository" in error
                for error in errors
            ) else None,
            "automatic_redispatch": False,
        },
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = verify(args.root)
    except (OSError, BoundaryError) as error:
        report = {"ok": False, "errors": [str(error)], "facts": {}}
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for error in report["errors"]:
            print(f"ERROR: {error}", file=sys.stderr)
        if report["ok"]:
            print("owner-open R5 workflow boundaries verified")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
