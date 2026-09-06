#!/usr/bin/env python3
"""Verify that every canonical G1 gap has one level-correct closure route.

The routing table is an operator handoff, not evidence and not a status writer.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


class RoutingError(Exception):
    pass


ROUTING_KEYS = {
    "schema",
    "program_revision",
    "gap_authority",
    "capture_workflow",
    "global_negative_claims",
    "routes",
}
ROUTE_KEYS = {
    "gap_id",
    "exit_level",
    "route_kind",
    "evidence_kinds",
    "required_roles",
    "closure_rule",
}
TARGET_KIND_LEVEL = {
    "installed_root_linux_process_matrix": "L2",
    "installed_codex_same_turn": "L2",
    "clean_android_target_files": "L3",
    "physical_android_adb": "L4",
    "destructive_fault_matrix": "L5",
    "signed_public_release": "L6",
}
L1_KINDS = {
    "exact_head_source",
    "independent_review_attestation",
    "protected_integration",
}
ROUTE_KINDS = {
    "repository_source",
    "repository_and_governance",
    "governance",
    "independent_target",
    "independent_android_image",
    "independent_physical_target",
    "independent_destructive_target",
    "independent_release",
}
REQUIRED_NEGATIVE_CLAIMS = {
    "no_synthetic_evidence",
    "capture_cannot_change_gap_status",
    "capture_cannot_authorize_promotion",
    "source_checks_cannot_claim_installed_target",
    "no_automatic_redispatch",
    "no_public_release_without_independent_l6_authorization",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RoutingError(message)


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise RoutingError(f"non-finite JSON number {value}")


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object,
            parse_constant=_constant,
        )
    except (OSError, UnicodeError, ValueError) as error:
        raise RoutingError(f"cannot read strict JSON {path}: {error}") from error
    require(isinstance(value, dict), f"{path} root must be an object")
    return value


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    require(
        actual == expected,
        f"{label} key drift; missing={sorted(expected-actual)}, extra={sorted(actual-expected)}",
    )


def text(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(value.strip()), f"{label} must be non-empty text")
    require("\x00" not in value, f"{label} contains NUL")
    return value


def strings(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    require(isinstance(value, list), f"{label} must be an array")
    require(allow_empty or bool(value), f"{label} must not be empty")
    result = [text(item, f"{label}[{index}]") for index, item in enumerate(value)]
    duplicates = [item for item, count in Counter(result).items() if count > 1]
    require(not duplicates, f"{label} duplicates: {duplicates}")
    return result


def verify(root: Path) -> dict[str, Any]:
    root = root.resolve()
    routing = load(root / "governance/gap-evidence-routing.v1.json")
    register = load(root / "docs/machine/gap-register.v2.json")
    exact_keys(routing, ROUTING_KEYS, "routing")
    require(routing["schema"] == "org.trillionnium.gap-evidence-routing.v1", "unsupported routing schema")
    require(routing["gap_authority"] == "docs/machine/gap-register.v2.json", "gap authority drifted")
    text(routing["program_revision"], "routing.program_revision")
    capture = text(routing["capture_workflow"], "routing.capture_workflow")
    require(capture == ".github/workflows/owner-open-r5-target-evidence-capture.yml",
            "capture workflow identity drifted")
    require((root / capture).is_file(), "capture workflow is absent from the real checkout")
    negative = set(strings(routing["global_negative_claims"], "routing.global_negative_claims"))
    require(negative == REQUIRED_NEGATIVE_CLAIMS, "global negative-claim set is incomplete or drifted")

    gaps = register.get("gaps")
    require(isinstance(gaps, list) and bool(gaps), "gap register gaps must be a non-empty array")
    gap_order: list[str] = []
    gap_map: dict[str, dict[str, Any]] = {}
    for index, gap in enumerate(gaps):
        require(isinstance(gap, dict), f"gap register entry {index} is not an object")
        gap_id = text(gap.get("id"), f"gaps[{index}].id")
        require(gap_id not in gap_map, f"duplicate canonical gap {gap_id}")
        exit_level = text(gap.get("exit_level"), f"{gap_id}.exit_level")
        require(exit_level in {f"L{level}" for level in range(1, 7)}, f"invalid exit level {exit_level}")
        gap_order.append(gap_id)
        gap_map[gap_id] = gap

    routes = routing["routes"]
    require(isinstance(routes, list), "routing.routes must be an array")
    route_ids: list[str] = []
    counts_by_level: Counter[str] = Counter()
    target_kind_usage: Counter[str] = Counter()
    for index, route in enumerate(routes):
        require(isinstance(route, dict), f"routing.routes[{index}] must be an object")
        exact_keys(route, ROUTE_KEYS, f"routing.routes[{index}]")
        gap_id = text(route["gap_id"], f"routing.routes[{index}].gap_id")
        require(gap_id in gap_map, f"route references unknown gap {gap_id}")
        route_ids.append(gap_id)
        exit_level = text(route["exit_level"], f"{gap_id}.exit_level")
        require(exit_level == gap_map[gap_id]["exit_level"], f"{gap_id} route exit level drifted")
        counts_by_level[exit_level] += 1
        route_kind = text(route["route_kind"], f"{gap_id}.route_kind")
        require(route_kind in ROUTE_KINDS, f"{gap_id} route kind is unsupported")
        evidence_kinds = strings(route["evidence_kinds"], f"{gap_id}.evidence_kinds")
        roles = strings(route["required_roles"], f"{gap_id}.required_roles")
        closure_rule = text(route["closure_rule"], f"{gap_id}.closure_rule")
        require(len(closure_rule) >= 64, f"{gap_id} closure rule is underspecified")
        require("independent_reviewer" in roles, f"{gap_id} lacks an independent reviewer role")

        if exit_level == "L1":
            require(set(evidence_kinds) <= L1_KINDS, f"{gap_id} L1 route contains target evidence")
            require(route_kind in {"repository_source", "repository_and_governance", "governance"},
                    f"{gap_id} L1 route kind is not repository/governance")
        else:
            require(route_kind.startswith("independent_"), f"{gap_id} L2-L6 route is not independent")
            for kind in evidence_kinds:
                require(kind in TARGET_KIND_LEVEL, f"{gap_id} uses unknown target evidence kind {kind}")
                require(TARGET_KIND_LEVEL[kind] == exit_level,
                        f"{gap_id} uses {kind} at wrong level {exit_level}")
                target_kind_usage[kind] += 1
            require("producer" in roles, f"{gap_id} L2-L6 route lacks a producer")
            require(any(role.endswith(("operator", "builder", "custodian")) for role in roles),
                    f"{gap_id} L2-L6 route lacks a target/build/custody role")

        if exit_level == "L5":
            require("destructive_authorizer" in roles, f"{gap_id} L5 route lacks destructive authorization")
        if exit_level == "L6":
            require("release_authorizer" in roles and "signing_custodian" in roles,
                    f"{gap_id} L6 route lacks release role separation")

    require(route_ids == gap_order, "routing must cover every canonical gap exactly once in register order")
    require(len(route_ids) == len(set(route_ids)), "routing contains duplicate gap routes")
    require(set(target_kind_usage) == set(TARGET_KIND_LEVEL),
            "one or more fixed target evidence kinds are unreachable")

    statuses = Counter(text(gap.get("status"), f"{gap['id']}.status") for gap in gaps)
    zero_gap = all(gap.get("status") == "CLOSED" for gap in gaps)
    return {
        "schema": "org.trillionnium.gap-evidence-routing-report.v1",
        "status": "PASS_COMPLETE_LEVEL_CORRECT_ROUTING",
        "gap_count": len(gaps),
        "counts_by_level": dict(sorted(counts_by_level.items())),
        "counts_by_status": dict(sorted(statuses.items())),
        "reachable_target_evidence_kinds": sorted(target_kind_usage),
        "claim_ceiling": "ROUTING_ONLY_NO_EVIDENCE",
        "capture_can_change_status": False,
        "promotion_authorized": False,
        "zero_gap": zero_gap,
        "public_release": zero_gap and statuses.get("CLOSED", 0) == len(gaps),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = verify(args.root)
    except (RoutingError, UnicodeError) as error:
        print(f"gap routing verification failed: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2))
    else:
        print("gap routing verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
