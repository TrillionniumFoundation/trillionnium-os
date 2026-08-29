#!/usr/bin/env python3
"""Evaluate real GitHub governance snapshots without promoting the gap."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


def read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def bool_field(value: Any, *path: str) -> bool:
    current = value
    for key in path:
        if not isinstance(current, dict):
            return False
        current = current.get(key)
    if isinstance(current, dict) and "enabled" in current:
        current = current.get("enabled")
    return current is True


def latest_reviews(reviews: Any) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    if not isinstance(reviews, list):
        return result
    for review in reviews:
        if not isinstance(review, dict):
            continue
        user = review.get("user")
        login = user.get("login") if isinstance(user, dict) else None
        if not isinstance(login, str) or not login:
            continue
        previous = result.get(login)
        marker = str(review.get("submitted_at") or "")
        if previous is None or marker >= str(previous.get("submitted_at") or ""):
            result[login] = review
    return result


def evaluate(
    policy: dict[str, Any],
    branch: dict[str, Any],
    protection: dict[str, Any],
    rulesets: Any,
    pull: dict[str, Any],
    reviews: Any,
    checks: dict[str, Any],
    expected_head: str,
) -> dict[str, Any]:
    required = set(str(item) for item in policy.get("required_checks", []))
    branch_protected = branch.get("protected") is True
    protection_available = bool(protection)

    contexts: set[str] = set()
    raw_contexts = protection.get("required_status_checks", {}).get("contexts", []) if isinstance(protection, dict) else []
    if isinstance(raw_contexts, list):
        contexts.update(str(item) for item in raw_contexts)
    raw_checks = protection.get("required_status_checks", {}).get("checks", []) if isinstance(protection, dict) else []
    if isinstance(raw_checks, list):
        for item in raw_checks:
            if isinstance(item, dict) and isinstance(item.get("context"), str):
                contexts.add(item["context"])

    active_rulesets = []
    if isinstance(rulesets, list):
        active_rulesets = [
            item
            for item in rulesets
            if isinstance(item, dict) and item.get("enforcement") == "active"
        ]

    check_runs = checks.get("check_runs", []) if isinstance(checks, dict) else []
    successful_names: set[str] = set()
    if isinstance(check_runs, list):
        for item in check_runs:
            if not isinstance(item, dict):
                continue
            if (
                item.get("head_sha") == expected_head
                and item.get("status") == "completed"
                and item.get("conclusion") in {"success", "neutral"}
                and isinstance(item.get("name"), str)
            ):
                successful_names.add(item["name"])

    pull_head = pull.get("head", {}).get("sha") if isinstance(pull.get("head"), dict) else None
    author = pull.get("user", {}).get("login") if isinstance(pull.get("user"), dict) else None
    approved: list[dict[str, Any]] = []
    for login, review in latest_reviews(reviews).items():
        if login == author or login.lower().endswith("[bot]"):
            continue
        if review.get("state") == "APPROVED" and review.get("commit_id") == expected_head:
            approved.append(review)

    approvals_required = int(policy.get("minimum_approvals", 1))
    pull_reviews = protection.get("required_pull_request_reviews", {}) if isinstance(protection, dict) else {}
    configured_approvals = pull_reviews.get("required_approving_review_count") if isinstance(pull_reviews, dict) else None
    conversation_required = bool_field(
        protection, "required_conversation_resolution"
    )
    force_push_blocked = not bool_field(protection, "allow_force_pushes")
    deletion_blocked = not bool_field(protection, "allow_deletions")
    direct_push_blocked = (
        branch_protected
        and isinstance(pull_reviews, dict)
        and int(configured_approvals or 0) >= approvals_required
    )
    required_checks_enforced = required <= contexts and required <= successful_names
    exact_head_approval = pull_head == expected_head and len(approved) >= approvals_required

    observations = {
        "schema": "org.trillionnium.owner-open-r5.observations.v1",
        "kind": "repository_governance_controls",
        "main_protected": branch_protected,
        "required_checks_enforced": required_checks_enforced,
        "independent_exact_head_approval": exact_head_approval,
        "direct_push_blocked": direct_push_blocked,
        "force_push_blocked": force_push_blocked,
    }
    ready = all(
        observations[key] is True
        for key in (
            "main_protected",
            "required_checks_enforced",
            "independent_exact_head_approval",
            "direct_push_blocked",
            "force_push_blocked",
        )
    ) and deletion_blocked and (
        not policy.get("require_conversation_resolution") or conversation_required
    )
    return {
        "schema": "org.trillionnium.owner-open-r5.governance-readiness.v1",
        "ready": ready,
        "expected_head": expected_head,
        "observations": observations,
        "facts": {
            "branch_protected": branch_protected,
            "protection_available": protection_available,
            "active_ruleset_count": len(active_rulesets),
            "configured_required_contexts": sorted(contexts),
            "successful_exact_head_checks": sorted(successful_names),
            "required_checks": sorted(required),
            "independent_exact_head_approval_count": len(approved),
            "configured_approval_count": configured_approvals,
            "conversation_resolution_required": conversation_required,
            "force_push_blocked": force_push_blocked,
            "deletion_blocked": deletion_blocked,
            "pull_head_matches": pull_head == expected_head,
        },
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--branch", required=True, type=Path)
    parser.add_argument("--protection", required=True, type=Path)
    parser.add_argument("--rulesets", required=True, type=Path)
    parser.add_argument("--pull-request", required=True, type=Path)
    parser.add_argument("--reviews", required=True, type=Path)
    parser.add_argument("--check-runs", required=True, type=Path)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        result = evaluate(
            read(args.policy),
            read(args.branch),
            read(args.protection),
            read(args.rulesets),
            read(args.pull_request),
            read(args.reviews),
            read(args.check_runs),
            args.expected_head,
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    raw = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(raw, encoding="utf-8")
    print(raw, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
