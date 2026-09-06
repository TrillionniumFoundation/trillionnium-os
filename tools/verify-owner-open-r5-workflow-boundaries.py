#!/usr/bin/env python3
"""Fail closed on transient, self-modifying, or authority-inflating R5 workflows."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any
from urllib.parse import urlsplit

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
    "env.WORKFLOW_SOURCE_SHA",
    "env.SOURCE_HEAD_SHA",
)
WRITE_PERMISSION = re.compile(
    r"(?im)^\s*(?:(?:contents|actions|pull-requests|issues|checks|deployments|statuses)"
    r"\s*:\s*['\"]?write['\"]?|permissions\s*:\s*['\"]?write-all['\"]?|"
    r"permissions\s*:\s*\{[^}\n]*\b(?:contents|actions|pull-requests|issues|checks|"
    r"deployments|statuses)\s*:\s*['\"]?write['\"]?[^}\n]*\})\s*(?:#.*)?$"
)
GITHUB_API_SYMBOL = re.compile(r"(?i)\b(?:GITHUB_API_URL|github\.api_url)\b")
URL_CANDIDATE = re.compile(r"https://[^\s\'\"<>`]+", re.IGNORECASE)
API_WRITE = re.compile(
    r"(?:--method(?:=|\s+)[\s'\"]*(?:POST|PUT|PATCH|DELETE)\b|"
    r"(?:-X|--request)(?:=|\s+)[\s'\"]*(?:POST|PUT|PATCH|DELETE)\b|"
    r"method\s*=\s*['\"](?:POST|PUT|PATCH|DELETE)['\"])",
    re.IGNORECASE,
)
STEP_START = re.compile(r"^(?P<indent>\s*)-\s+[A-Za-z_][A-Za-z0-9_-]*\s*:")
CHECKOUT = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*actions/checkout@")
EXACT_HEAD_ASSERTION = re.compile(
    r"\bgit\s+(?:--no-replace-objects\s+)?rev-parse\s+HEAD\b"
)
TARGET_WORKFLOW = "owner-open-r5-target-evidence-capture.yml"
GOVERNANCE_WORKFLOW = "owner-open-r5-governance-readiness.yml"
TARGET_ROUTE_MARKERS = (
    '"status": "ROUTE_ONLY_PENDING_EXTERNAL_ADMISSION"',
    '"candidate_checkout_performed": False',
    '"candidate_code_executed": False',
    '"external_runner_allocated": False',
    '"capture_scheduled": False',
    '"promotion_authorized": False',
    '"public_release": False',
)
GOVERNANCE_NO_AUTHORITY_MARKERS = (
    'report["readiness_claimed"] is False',
    'report["ready_for_protected_integration"] is False',
    'report["promotion_authorized"] is False',
    'report["public_release"] is False',
)


class BoundaryError(ValueError):
    pass


def _workflow_step_blocks(lines: list[str]) -> list[tuple[int, str]]:
    blocks: list[tuple[int, str]] = []
    index = 0
    while index < len(lines):
        match = STEP_START.match(lines[index])
        if match is None:
            index += 1
            continue
        indent = len(match.group("indent"))
        block = [lines[index]]
        following_index = index + 1
        while following_index < len(lines):
            following = lines[following_index]
            stripped = following.strip()
            following_indent = len(following) - len(following.lstrip())
            following_match = STEP_START.match(following)
            if stripped and following_match is not None and following_indent == indent:
                break
            if stripped and following_indent < indent:
                break
            block.append(following)
            following_index += 1
        blocks.append((index + 1, "\n".join(block)))
        index = following_index
    return blocks


def _checkout_blocks(lines: list[str]) -> list[tuple[int, str]]:
    return [
        (line_number, block)
        for line_number, block in _workflow_step_blocks(lines)
        if CHECKOUT.search(block) is not None
    ]


def _workflow_paths(workflow_dir: Path) -> list[Path]:
    return sorted(
        set(workflow_dir.glob("owner-open*.yml"))
        | set(workflow_dir.glob("owner-open*.yaml"))
    )


def _references_github_api(text: str) -> bool:
    """Recognize symbolic endpoints or literal URLs with the exact API host."""
    if GITHUB_API_SYMBOL.search(text):
        return True
    for candidate in URL_CANDIDATE.findall(text):
        try:
            if urlsplit(candidate).hostname == "api.github.com":
                return True
        except ValueError:
            continue
    return False


def _verify_target_route_only(path: Path, text: str, errors: list[str]) -> None:
    if re.search(r"(?i)\bself-hosted\b", text):
        errors.append(f"target evidence workflow allocates a self-hosted runner: {path.name}")
    if CHECKOUT.search(text):
        errors.append(f"target evidence workflow checks out candidate code: {path.name}")
    if "$GITHUB_WORKSPACE" in text:
        errors.append(f"target evidence workflow references candidate workspace: {path.name}")
    if re.search(r"(?im)^\s*working-directory\s*:.*GITHUB_WORKSPACE", text):
        errors.append(f"target evidence workflow enters candidate workspace: {path.name}")
    if "runs-on: ubuntu-24.04" not in text:
        errors.append(f"target evidence route is not GitHub-hosted: {path.name}")
    for marker in TARGET_ROUTE_MARKERS:
        if marker not in text:
            errors.append(f"target evidence route omits fail-closed marker {marker}: {path.name}")


def _verify_governance_observation(path: Path, text: str, errors: list[str]) -> None:
    if re.search(r"ready_for_protected_integration\s*['\"]?\s*:\s*true", text, re.I):
        errors.append(f"governance workflow can claim readiness true: {path.name}")
    for marker in GOVERNANCE_NO_AUTHORITY_MARKERS:
        if marker not in text:
            errors.append(f"governance workflow omits no-authority marker {marker}: {path.name}")


def verify(root: Path) -> dict[str, Any]:
    root = root.resolve()
    workflow_dir = root / ".github" / "workflows"
    errors: list[str] = []
    checked: list[str] = []

    required = {
        "owner-open-r5-tool-loop.yml",
        TARGET_WORKFLOW,
        GOVERNANCE_WORKFLOW,
    }
    workflow_paths = _workflow_paths(workflow_dir)
    observed = {path.name for path in workflow_paths}
    for name in sorted(required - observed):
        errors.append(f"required permanent workflow is absent: {name}")

    for path in workflow_paths:
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
        if (
            API_WRITE.search(text)
            and "repos/" in text
            and _references_github_api(text)
        ):
            errors.append(f"workflow can mutate GitHub repository controls: {path.name}")

        if path.name == TARGET_WORKFLOW:
            _verify_target_route_only(path, text, errors)
        if path.name == GOVERNANCE_WORKFLOW:
            _verify_governance_observation(path, text, errors)

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
            "target_capture_is_route_only": not any(
                "target evidence" in error for error in errors
            ),
            "governance_claims_readiness": any(
                "claim readiness true" in error for error in errors
            ),
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
