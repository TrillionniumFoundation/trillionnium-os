#!/usr/bin/env python3
"""Produce fail-closed governance observations without authorizing integration.

This evaluator intentionally does not decide whether a pull request may merge.
It records granular, exact-head facts and keeps the compatibility readiness
field hard-false. Protected integration remains a server-side decision made
by GitHub branch protection/rulesets and eligible human reviewers.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys
from typing import Any

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SUCCESSFUL_CONCLUSIONS = {"success"}


class ObservationError(ValueError):
    pass


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, member in pairs:
        if key in value:
            raise ObservationError(f"duplicate JSON member {key!r}")
        value[key] = member
    return value


def _reject_nonfinite(value: str) -> None:
    raise ObservationError(f"non-finite JSON number {value}")


def read(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=_reject_nonfinite,
        )
    except (OSError, UnicodeError, ValueError) as error:
        raise ObservationError(f"cannot read strict JSON {path}: {error}") from error


def read_optional(path: Path | None, default: Any) -> Any:
    return default if path is None else read(path)


def bool_field(value: Any, *path: str) -> bool | None:
    current = value
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    if isinstance(current, dict) and "enabled" in current:
        current = current.get("enabled")
    return current if isinstance(current, bool) else None


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
        marker = (str(review.get("submitted_at") or ""), int(review.get("id") or 0))
        previous = result.get(login)
        previous_marker = (
            str(previous.get("submitted_at") or ""),
            int(previous.get("id") or 0),
        ) if previous else ("", 0)
        if marker >= previous_marker:
            result[login] = review
    return result


def latest_check_runs(checks: Any, expected_head: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    check_runs = checks.get("check_runs", []) if isinstance(checks, dict) else []
    if not isinstance(check_runs, list):
        return result
    for item in check_runs:
        if not isinstance(item, dict) or item.get("head_sha") != expected_head:
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name:
            continue
        marker = (
            str(item.get("completed_at") or item.get("started_at") or ""),
            int(item.get("id") or 0),
        )
        previous = result.get(name)
        previous_marker = (
            str(previous.get("completed_at") or previous.get("started_at") or ""),
            int(previous.get("id") or 0),
        ) if previous else ("", 0)
        if marker >= previous_marker:
            result[name] = item
    return result


def protection_contexts(protection: Any) -> set[str]:
    contexts: set[str] = set()
    if not isinstance(protection, dict):
        return contexts
    status = protection.get("required_status_checks")
    if not isinstance(status, dict):
        return contexts
    raw_contexts = status.get("contexts", [])
    if isinstance(raw_contexts, list):
        contexts.update(item for item in raw_contexts if isinstance(item, str) and item)
    raw_checks = status.get("checks", [])
    if isinstance(raw_checks, list):
        for item in raw_checks:
            if isinstance(item, dict) and isinstance(item.get("context"), str):
                contexts.add(item["context"])
    return contexts


def ruleset_requirements(rulesets: Any) -> tuple[set[str], int, bool]:
    checks: set[str] = set()
    approvals = 0
    conversations = False
    if not isinstance(rulesets, list):
        return checks, approvals, conversations
    for ruleset in rulesets:
        if not isinstance(ruleset, dict) or ruleset.get("enforcement") != "active":
            continue
        rules = ruleset.get("rules", [])
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            rule_type = rule.get("type")
            parameters = rule.get("parameters")
            if not isinstance(parameters, dict):
                parameters = {}
            if rule_type == "required_status_checks":
                for item in parameters.get("required_status_checks", []):
                    if isinstance(item, dict) and isinstance(item.get("context"), str):
                        checks.add(item["context"])
            elif rule_type == "pull_request":
                candidate = parameters.get("required_approving_review_count")
                if isinstance(candidate, int) and not isinstance(candidate, bool):
                    approvals = max(approvals, candidate)
                conversations = conversations or parameters.get(
                    "required_review_thread_resolution"
                ) is True
    return checks, approvals, conversations


def _observation(value: bool | None, *, required: bool = True) -> dict[str, Any]:
    return {
        "observed": value is not None,
        "satisfied": value is True,
        "required": required,
    }


def evaluate(
    policy: dict[str, Any],
    branch: dict[str, Any],
    protection: dict[str, Any],
    rulesets: Any,
    pull: dict[str, Any],
    reviews: Any,
    checks: dict[str, Any],
    expected_head: str,
    *,
    threads: Any = None,
    commit: Any = None,
    comparison: Any = None,
) -> dict[str, Any]:
    if SHA_RE.fullmatch(expected_head) is None:
        raise ObservationError("expected_head must be lowercase 40-hex")
    if not isinstance(policy, dict) or not isinstance(pull, dict):
        raise ObservationError("policy and pull request snapshots must be objects")

    configured_contexts = protection_contexts(protection)
    ruleset_contexts, ruleset_approvals, ruleset_conversations = ruleset_requirements(rulesets)
    policy_contexts = {
        item for item in policy.get("required_checks", [])
        if isinstance(item, str) and item
    }
    required_contexts = configured_contexts | ruleset_contexts | policy_contexts
    latest_checks = latest_check_runs(checks, expected_head)
    successful_contexts = {
        name for name, item in latest_checks.items()
        if item.get("status") == "completed"
        and item.get("conclusion") in SUCCESSFUL_CONCLUSIONS
    }
    required_checks_ok = bool(required_contexts) and required_contexts <= successful_contexts

    pull_head = pull.get("head", {}).get("sha") if isinstance(pull.get("head"), dict) else None
    pull_base = pull.get("base", {}).get("sha") if isinstance(pull.get("base"), dict) else None
    branch_tip = branch.get("commit", {}).get("sha") if isinstance(branch.get("commit"), dict) else None
    author = pull.get("user", {}).get("login") if isinstance(pull.get("user"), dict) else None

    review_map = latest_reviews(reviews)
    approvals: list[str] = []
    change_requests: list[str] = []
    for login, review in review_map.items():
        if review.get("commit_id") != expected_head:
            continue
        state = review.get("state")
        if state == "CHANGES_REQUESTED":
            change_requests.append(login)
        if login != author and not login.lower().endswith("[bot]") and state == "APPROVED":
            approvals.append(login)
    approvals.sort()
    change_requests.sort()

    policy_approvals = policy.get("minimum_approvals", 1)
    if not isinstance(policy_approvals, int) or isinstance(policy_approvals, bool) or policy_approvals < 1:
        raise ObservationError("minimum_approvals must be a positive integer")
    pull_reviews = protection.get("required_pull_request_reviews") if isinstance(protection, dict) else None
    configured_approvals = (
        pull_reviews.get("required_approving_review_count")
        if isinstance(pull_reviews, dict)
        else None
    )
    configured_approvals_value = (
        configured_approvals
        if isinstance(configured_approvals, int) and not isinstance(configured_approvals, bool)
        else 0
    )
    approvals_required = max(policy_approvals, configured_approvals_value, ruleset_approvals)
    approvals_ok = len(approvals) >= approvals_required and not change_requests

    thread_resolution_required = policy.get("require_conversation_resolution") is True
    protection_thread_rule = bool_field(protection, "required_conversation_resolution") is True
    thread_resolution_required = (
        thread_resolution_required or protection_thread_rule or ruleset_conversations
    )
    if threads is None:
        threads_ok: bool | None = None if thread_resolution_required else True
        unresolved_threads: int | None = None
    elif isinstance(threads, list):
        unresolved_threads = sum(
            1 for item in threads
            if not isinstance(item, dict) or item.get("isResolved") is not True
        )
        threads_ok = unresolved_threads == 0
    else:
        threads_ok = None
        unresolved_threads = None

    require_signed = policy.get("require_signed_commit") is True
    if isinstance(commit, dict):
        verified = bool_field(commit, "verification", "verified")
    else:
        verified = None
    signed_ok: bool | None = verified if require_signed else True

    merge_state = pull.get("mergeable_state")
    mergeable_clean = bool(
        pull.get("state") == "open"
        and pull.get("draft") is False
        and pull.get("mergeable") is True
        and merge_state == "clean"
        and pull_head == expected_head
    )
    base_fresh = (
        pull_base == branch_tip
        if isinstance(pull_base, str) and isinstance(branch_tip, str)
        else None
    )
    comparison_status = comparison.get("status") if isinstance(comparison, dict) else None

    branch_protected = branch.get("protected") if isinstance(branch, dict) else None
    if not isinstance(branch_protected, bool):
        branch_protected = None
    force_pushes = bool_field(protection, "allow_force_pushes")
    deletions = bool_field(protection, "allow_deletions")
    force_push_blocked = None if force_pushes is None else not force_pushes
    deletion_blocked = None if deletions is None else not deletions
    direct_push_blocked = (
        True
        if branch_protected is True and approvals_required > 0
        and isinstance(pull_reviews, dict)
        else None
    )

    observations = {
        "protected_base": _observation(branch_protected),
        "required_checks_successful_on_exact_head": _observation(required_checks_ok),
        "independent_exact_head_approvals": _observation(approvals_ok),
        "no_unresolved_review_threads": _observation(
            threads_ok, required=thread_resolution_required
        ),
        "signed_exact_head": _observation(signed_ok, required=require_signed),
        "mergeable_clean_exact_head": _observation(mergeable_clean),
        "base_tip_matches_pull_snapshot": _observation(base_fresh),
        "direct_push_blocked": _observation(direct_push_blocked),
        "force_push_blocked": _observation(force_push_blocked),
        "branch_deletion_blocked": _observation(deletion_blocked),
    }

    blockers: list[str] = []
    for name, item in observations.items():
        if item["required"] and not item["observed"]:
            blockers.append(f"UNOBSERVED:{name}")
        elif item["required"] and not item["satisfied"]:
            blockers.append(f"UNSATISFIED:{name}")

    duplicate_approvals = [name for name, count in Counter(approvals).items() if count > 1]
    if duplicate_approvals:
        blockers.append("INVALID:duplicate_approval_identity")

    return {
        "schema": "org.trillionnium.governance-observation.v2",
        "posture": "OBSERVE_ONLY",
        "decision": "NO_INTEGRATION_AUTHORITY",
        "readiness_claimed": False,
        "ready_for_protected_integration": False,
        "promotion_authorized": False,
        "public_release": False,
        "expected_head": expected_head,
        "observations": observations,
        "blockers": sorted(blockers),
        "facts": {
            "pull_head": pull_head,
            "pull_base": pull_base,
            "branch_tip": branch_tip,
            "mergeable_state": merge_state,
            "comparison_status": comparison_status,
            "required_contexts": sorted(required_contexts),
            "successful_exact_head_checks": sorted(successful_contexts),
            "independent_exact_head_approvals": approvals,
            "change_requests_on_exact_head": change_requests,
            "approvals_required": approvals_required,
            "unresolved_review_threads": unresolved_threads,
            "commit_signature_verified": verified,
            "protection_observed": bool(protection),
            "rulesets_observed": isinstance(rulesets, list),
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
    parser.add_argument("--threads", type=Path)
    parser.add_argument("--commit", type=Path)
    parser.add_argument("--comparison", type=Path)
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
            threads=read_optional(args.threads, None),
            commit=read_optional(args.commit, None),
            comparison=read_optional(args.comparison, None),
        )
    except ObservationError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    raw = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(raw, encoding="utf-8")
    print(raw, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
