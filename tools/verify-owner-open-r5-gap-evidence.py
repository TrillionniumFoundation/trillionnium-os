#!/usr/bin/env python3
"""Validate Owner-Open R5 gap states against exact source and target evidence."""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import sys
from typing import Any

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from owner_open_r5_evidence_bundle import (  # noqa: E402
    EvidenceError,
    LEVELS,
    validate_evidence_reference,
)

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
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


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


def exact_source_evidence(
    value: Any, label: str, report: Report
) -> tuple[str, str] | None:
    report.check(isinstance(value, dict), f"{label} source_evidence must be an object")
    if not isinstance(value, dict):
        return None
    report.check(value.get("level") == "L1", f"{label} source evidence level must be L1")
    report.check(
        isinstance(value.get("branch"), str) and bool(value.get("branch")),
        f"{label} source evidence branch is missing",
    )
    commit = value.get("commit")
    tree = value.get("tree")
    report.check(
        isinstance(commit, str) and HEX40.fullmatch(commit) is not None,
        f"{label} source evidence commit must be lowercase 40-hex",
    )
    report.check(
        isinstance(tree, str) and HEX40.fullmatch(tree) is not None,
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
    if isinstance(commit, str) and isinstance(tree, str):
        return commit, tree
    return None


def requires_external_evidence(
    gap: dict[str, Any], exit_level: Any, identifier: str, report: Report
) -> bool:
    value = gap.get("requires_external_evidence")
    report.check(
        value is None or isinstance(value, bool),
        f"{identifier} requires_external_evidence must be boolean",
    )
    if isinstance(value, bool):
        return value
    return exit_level in LEVELS and LEVELS[str(exit_level)] >= LEVELS["L2"]


def environment_evidence(
    root: Path,
    value: Any,
    label: str,
    exit_level: str,
    source_commit: str,
    source_tree: str,
    report: Report,
) -> list[dict[str, Any]]:
    report.check(
        isinstance(value, list) and bool(value),
        f"{label} evidence must be a non-empty list",
    )
    if not isinstance(value, list):
        report.check(False, f"{label} has no evidence at or above exit level {exit_level}")
        return []
    observed_ranks: list[int] = []
    facts: list[dict[str, Any]] = []
    seen_references: set[tuple[str, str]] = set()
    for index, item in enumerate(value):
        item_label = f"{label} evidence[{index}]"
        report.check(isinstance(item, dict), f"{item_label} must be an object")
        if not isinstance(item, dict):
            continue
        try:
            item_facts = validate_evidence_reference(
                root,
                gap_id=label,
                exit_level=exit_level,
                source_commit=source_commit,
                source_tree=source_tree,
                item=item,
            )
        except (EvidenceError, OSError) as error:
            report.errors.append(f"{item_label}: {error}")
            continue
        reference = (str(item.get("bundle_path")), str(item.get("evidence_sha256")))
        report.check(reference not in seen_references, f"{item_label} is duplicated")
        seen_references.add(reference)
        level = str(item_facts["evidence_level"])
        observed_ranks.append(LEVELS[level])
        facts.append(item_facts)
    report.check(
        any(rank >= LEVELS[exit_level] for rank in observed_ranks),
        f"{label} has no evidence at or above exit level {exit_level}",
    )
    return facts


def verify_values(
    root: Path, gaps: dict[str, Any], status: dict[str, Any]
) -> Report:
    report = Report()
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
    public_release = status.get("public_release")
    report.check(isinstance(public_release, bool), "public_release must be boolean")
    generated_policy = gaps.get("generated_policy")
    report.check(isinstance(generated_policy, dict), "gap generated_policy must be an object")
    if isinstance(generated_policy, dict):
        report.check(
            generated_policy.get("automatic_redispatch") is False,
            "gap generated_policy automatic_redispatch must remain false",
        )
        report.check(
            generated_policy.get("public_release") is public_release,
            "gap generated_policy public_release must match status",
        )

    entries = gaps.get("gaps")
    report.check(isinstance(entries, list) and bool(entries), "gaps must be a non-empty list")
    if not isinstance(entries, list):
        return report

    seen: set[str] = set()
    states: dict[str, int] = {state: 0 for state in sorted(ALLOWED_STATES)}
    ordered: list[str] = []
    source_heads: set[tuple[str, str]] = set()
    evidence_facts: dict[str, list[dict[str, Any]]] = {}
    release_closed = False
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
        external_required = requires_external_evidence(
            gap, exit_level, identifier, report
        )
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
                and all(
                    isinstance(item, int) and not isinstance(item, bool) and item > 0
                    for item in issues
                )
            ),
            f"{identifier} must bind an issue or issues",
        )

        source_identity: tuple[str, str] | None = None
        if state == "OPEN":
            report.check(
                "source_evidence" not in gap and "evidence" not in gap,
                f"{identifier} OPEN state must not carry promotion evidence",
            )
        elif state == "SOURCE_CLOSED_PENDING_EVIDENCE":
            source_identity = exact_source_evidence(
                gap.get("source_evidence"), identifier, report
            )
            report.check(
                external_required,
                f"{identifier} pending state must require external evidence",
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
                external_required,
                f"{identifier} external hold must require external evidence",
            )
            report.check(
                nonempty_strings(gap.get("required_material"))
                or nonempty_strings(gap.get("required_authority")),
                f"{identifier} external hold must list required material or authority",
            )
            if "source_evidence" in gap:
                source_identity = exact_source_evidence(
                    gap.get("source_evidence"), identifier, report
                )
            report.check(
                "evidence" not in gap,
                f"{identifier} external hold must not carry full closure evidence",
            )
        elif state == "CLOSED" and exit_level in LEVELS:
            source_identity = exact_source_evidence(
                gap.get("source_evidence"), identifier, report
            )
            if external_required:
                if source_identity is not None:
                    evidence_facts[identifier] = environment_evidence(
                        root,
                        gap.get("evidence"),
                        identifier,
                        str(exit_level),
                        source_identity[0],
                        source_identity[1],
                        report,
                    )
                else:
                    report.errors.append(
                        f"{identifier} external closure cannot validate without source identity"
                    )
            else:
                report.check(
                    exit_level == "L1",
                    f"{identifier} source-only closure is allowed only at L1",
                )
                report.check(
                    gap.get("evidence") in (None, []),
                    f"{identifier} source-only L1 closure must not carry external evidence",
                )
            if identifier == "R5-GAP-RELEASE-001":
                release_closed = True
        if source_identity is not None:
            source_heads.add(source_identity)

    priority = gaps.get("priority_order")
    report.check(priority == ordered, "priority_order must exactly match gaps order")
    all_closed = bool(entries) and all(
        isinstance(item, dict) and item.get("status") == "CLOSED" for item in entries
    )
    report.check(
        public_release is release_closed,
        "public_release must be true exactly when the release gap is CLOSED",
    )
    report.check(
        not release_closed or all_closed,
        "the release gap cannot close before every other gap is CLOSED",
    )
    zero_gap = status.get("zero_gap")
    report.check(
        isinstance(zero_gap, bool) and zero_gap is all_closed,
        "zero_gap must be true exactly when every gap is CLOSED",
    )
    if all_closed:
        report.check(
            len(source_heads) == 1,
            "zero-gap closure must bind one exact source commit/tree across all gaps",
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
            "release_closed": release_closed,
            "public_release": public_release,
            "automatic_redispatch": status.get("automatic_redispatch"),
            "source_heads": [
                {"commit": commit, "tree": tree}
                for commit, tree in sorted(source_heads)
            ],
            "validated_external_evidence": evidence_facts,
        }
    )
    return report


def verify(root: Path) -> Report:
    try:
        gaps = read_object(root / GAPS)
        status = read_object(root / STATUS)
    except ValueError as error:
        report = Report()
        report.errors.append(str(error))
        return report
    return verify_values(root, gaps, status)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
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
