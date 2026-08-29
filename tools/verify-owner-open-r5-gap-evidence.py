#!/usr/bin/env python3
"""Validate Owner-Open R5 gap states against their declared evidence level.

This verifier deliberately separates repository source closure from installed,
image, physical, destructive-fault and release evidence.  Editing the gap JSON
cannot manufacture a promotion: every non-open state must carry the evidence
shape appropriate to that state, and zero-gap is possible only when every gap
is fully CLOSED.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import sys
from typing import Any

GAPS = Path("docs/status/owner-open-r5-gap-closure.json")
STATUS = Path("docs/status/owner-open-r5-status.json")
EXPECTED_SCHEMA = "org.trillionnium.owner-open-r5.gap-closure.v1"
EXPECTED_REVISION = "2026-08-29-r6"
ALLOWED_STATES = {
    "OPEN",
    "SOURCE_CLOSED_PENDING_EVIDENCE",
    "EXTERNAL_HOLD",
    "CLOSED",
}
LEVELS = {f"L{index}": index for index in range(7)}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
EXTERNAL_LEVELS = {"L2", "L3", "L4", "L5", "L6"}


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.errors

    def check(self, condition: bool, message: str) -> None:
        if not condition:
            self.errors.append(message)


def read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot parse {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def nonempty_strings(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and bool(item.strip()) for item in value)
    )


def exact_source_evidence(value: Any, label: str, report: Report) -> None:
    report.check(isinstance(value, dict), f"{label} source_evidence must be an object")
    if not isinstance(value, dict):
        return
    report.check(value.get("level") == "L1", f"{label} source evidence level must be L1")
    report.check(
        isinstance(value.get("branch"), str) and bool(value.get("branch")),
        f"{label} source evidence branch is missing",
    )
    report.check(
        isinstance(value.get("commit"), str)
        and HEX40.fullmatch(value["commit"]) is not None,
        f"{label} source evidence commit must be lowercase 40-hex",
    )
    report.check(
        isinstance(value.get("tree"), str)
        and HEX40.fullmatch(value["tree"]) is not None,
        f"{label} source evidence tree must be lowercase 40-hex",
    )
    report.check(
        isinstance(value.get("workflow_run_id"), int)
        and not isinstance(value.get("workflow_run_id"), bool)
        and value["workflow_run_id"] > 0,
        f"{label} source evidence workflow_run_id must be positive",
    )
    report.check(
        nonempty_strings(value.get("successful_jobs")),
        f"{label} source evidence must name successful jobs",
    )
    artifacts = value.get("artifacts")
    report.check(
        isinstance(artifacts, list) and bool(artifacts),
        f"{label} source evidence must bind at least one artifact",
    )
    if isinstance(artifacts, list):
        for index, artifact in enumerate(artifacts):
            artifact_label = f"{label} source_evidence.artifacts[{index}]"
            report.check(isinstance(artifact, dict), f"{artifact_label} must be an object")
            if not isinstance(artifact, dict):
                continue
            report.check(
                isinstance(artifact.get("id"), int)
                and not isinstance(artifact.get("id"), bool)
                and artifact["id"] > 0,
                f"{artifact_label}.id must be positive",
            )
            report.check(
                isinstance(artifact.get("name"), str) and bool(artifact.get("name")),
                f"{artifact_label}.name is missing",
            )
            digest = artifact.get("digest")
            report.check(
                isinstance(digest, str)
                and digest.startswith("sha256:")
                and HEX64.fullmatch(digest.removeprefix("sha256:")) is not None,
                f"{artifact_label}.digest must be sha256:<64 lowercase hex>",
            )


def environment_evidence(
    value: Any,
    label: str,
    exit_level: str,
    report: Report,
) -> None:
    report.check(isinstance(value, list) and bool(value), f"{label} evidence must be a non-empty list")
    if not isinstance(value, list):
        return
    exit_rank = LEVELS[exit_level]
    observed_ranks: list[int] = []
    for index, item in enumerate(value):
        item_label = f"{label} evidence[{index}]"
        report.check(isinstance(item, dict), f"{item_label} must be an object")
        if not isinstance(item, dict):
            continue
        level = item.get("level")
        report.check(level in LEVELS, f"{item_label}.level is invalid")
        if level in LEVELS:
            observed_ranks.append(LEVELS[level])
        report.check(
            isinstance(item.get("source_commit"), str)
            and HEX40.fullmatch(item["source_commit"]) is not None,
            f"{item_label}.source_commit must be lowercase 40-hex",
        )
        report.check(
            isinstance(item.get("evidence_sha256"), str)
            and HEX64.fullmatch(item["evidence_sha256"]) is not None,
            f"{item_label}.evidence_sha256 must be lowercase 64-hex",
        )
        report.check(
            isinstance(item.get("kind"), str) and bool(item.get("kind")),
            f"{item_label}.kind is missing",
        )
        report.check(
            isinstance(item.get("reviewer"), str) and bool(item.get("reviewer")),
            f"{item_label}.reviewer is missing",
        )
        report.check(
            item.get("synthetic") is False,
            f"{item_label} must explicitly declare synthetic=false",
        )
    report.check(
        any(rank >= exit_rank for rank in observed_ranks),
        f"{label} has no evidence at or above exit level {exit_level}",
    )


def verify(root: Path) -> Report:
    report = Report()
    try:
        gaps = read_object(root / GAPS)
        status = read_object(root / STATUS)
    except ValueError as error:
        report.errors.append(str(error))
        return report

    report.check(gaps.get("schema") == EXPECTED_SCHEMA, "gap schema is unsupported")
    report.check(gaps.get("revision") == EXPECTED_REVISION, "gap revision is not active r6")
    report.check(
        status.get("active_plan_revision") == gaps.get("revision"),
        "status and gap active revisions differ",
    )
    report.check(
        status.get("automatic_redispatch") is False,
        "automatic_redispatch must remain false",
    )
    report.check(status.get("public_release") is False, "public_release must remain false")

    entries = gaps.get("gaps")
    report.check(isinstance(entries, list) and bool(entries), "gaps must be a non-empty list")
    if not isinstance(entries, list):
        return report

    seen: set[str] = set()
    states: dict[str, int] = {state: 0 for state in sorted(ALLOWED_STATES)}
    ordered: list[str] = []
    for index, gap in enumerate(entries):
        label = f"gaps[{index}]"
        report.check(isinstance(gap, dict), f"{label} must be an object")
        if not isinstance(gap, dict):
            continue
        identifier = gap.get("id")
        report.check(
            isinstance(identifier, str) and bool(identifier),
            f"{label}.id is missing",
        )
        if not isinstance(identifier, str) or not identifier:
            continue
        report.check(identifier not in seen, f"duplicate gap id: {identifier}")
        seen.add(identifier)
        ordered.append(identifier)
        state = gap.get("status")
        report.check(state in ALLOWED_STATES, f"{identifier} has invalid state {state!r}")
        if state in states:
            states[state] += 1
        exit_level = gap.get("exit_evidence_level")
        report.check(exit_level in LEVELS, f"{identifier} has invalid exit level")
        report.check(
            isinstance(gap.get("summary"), str) and bool(gap.get("summary")),
            f"{identifier} summary is missing",
        )
        report.check(
            nonempty_strings(gap.get("acceptance")),
            f"{identifier} acceptance must be a non-empty string list",
        )
        issue = gap.get("issue")
        issues = gap.get("issues")
        report.check(
            (isinstance(issue, int) and not isinstance(issue, bool) and issue > 0)
            or (
                isinstance(issues, list)
                and bool(issues)
                and all(isinstance(item, int) and item > 0 for item in issues)
            ),
            f"{identifier} must bind an issue or issues",
        )

        if state == "OPEN":
            report.check(
                "source_evidence" not in gap and "evidence" not in gap,
                f"{identifier} OPEN state must not carry promotion evidence",
            )
        elif state == "SOURCE_CLOSED_PENDING_EVIDENCE":
            exact_source_evidence(gap.get("source_evidence"), identifier, report)
            report.check(
                exit_level in EXTERNAL_LEVELS,
                f"{identifier} source-closed pending state requires L2-L6 exit",
            )
            report.check(
                nonempty_strings(gap.get("remaining_evidence")),
                f"{identifier} must list remaining higher-level evidence",
            )
            report.check(
                "evidence" not in gap,
                f"{identifier} pending state must not carry full closure evidence",
            )
        elif state == "EXTERNAL_HOLD":
            report.check(
                nonempty_strings(gap.get("required_material"))
                or nonempty_strings(gap.get("required_authority")),
                f"{identifier} external hold must list required material or authority",
            )
            if "source_evidence" in gap:
                exact_source_evidence(gap.get("source_evidence"), identifier, report)
            report.check(
                "evidence" not in gap,
                f"{identifier} external hold must not carry full closure evidence",
            )
        elif state == "CLOSED" and exit_level in LEVELS:
            exact_source_evidence(gap.get("source_evidence"), identifier, report)
            if exit_level == "L1":
                report.check(
                    "evidence" not in gap or gap.get("evidence") in ([], None),
                    f"{identifier} L1 closure must not pretend to carry external evidence",
                )
            else:
                environment_evidence(gap.get("evidence"), identifier, exit_level, report)

    priority = gaps.get("priority_order")
    report.check(priority == ordered, "priority_order must exactly match gaps order")
    zero_gap = status.get("zero_gap")
    all_closed = bool(entries) and all(
        isinstance(item, dict) and item.get("status") == "CLOSED" for item in entries
    )
    report.check(
        zero_gap is all_closed,
        "zero_gap must be true exactly when every gap is CLOSED",
    )
    if zero_gap:
        report.check(
            states.get("EXTERNAL_HOLD", 0) == 0
            and states.get("SOURCE_CLOSED_PENDING_EVIDENCE", 0) == 0
            and states.get("OPEN", 0) == 0,
            "zero_gap cannot coexist with open, pending or external-hold states",
        )

    report.facts.update(
        {
            "revision": gaps.get("revision"),
            "gap_count": len(entries),
            "states": states,
            "zero_gap": zero_gap,
            "all_closed": all_closed,
            "public_release": status.get("public_release"),
            "automatic_redispatch": status.get("automatic_redispatch"),
        }
    )
    return report


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = verify(args.root.resolve())
    value = {
        "ok": report.ok,
        "errors": report.errors,
        "warnings": report.warnings,
        "facts": report.facts,
    }
    if args.json:
        print(json.dumps(value, indent=2, sort_keys=True))
    else:
        for error in report.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        for warning in report.warnings:
            print(f"WARNING: {warning}")
        if report.ok:
            print("owner-open R5 gap evidence verified")
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
