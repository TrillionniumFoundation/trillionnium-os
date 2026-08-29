#!/usr/bin/env python3
"""Generate an exact-head Owner-Open R5 resume packet.

The packet is a machine-readable execution handoff, not L2-L6 evidence and not
an automatic state promotion. It summarizes the canonical gap register, checks
that the checked-in claim policy remains fail-closed, and names the exact
material or authority required for the next evidence run.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

GAPS = Path("docs/status/owner-open-r5-gap-closure.json")
STATUS = Path("docs/status/owner-open-r5-status.json")
EXPECTED_GAP_SCHEMA = "org.trillionnium.owner-open-r5.gap-closure.v1"
EXPECTED_STATUS_SCHEMA = "org.trillionnium.owner-open-r5-status.v2"
EXPECTED_REVISION = "2026-08-29-r6"
PACKET_SCHEMA = "org.trillionnium.owner-open-r5.resume-packet.v1"
ALLOWED_STATES = {
    "OPEN",
    "SOURCE_CLOSED_PENDING_EVIDENCE",
    "EXTERNAL_HOLD",
    "CLOSED",
}
LEVELS = {f"L{index}": index for index in range(7)}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class PacketError(ValueError):
    """Raised when canonical status cannot produce a trustworthy handoff."""


class Identity:
    def __init__(
        self,
        *,
        repository: str,
        branch: str,
        commit_sha: str,
        tree_sha: str,
        workflow_run_id: int,
        workflow_run_attempt: int,
    ) -> None:
        self.repository = repository
        self.branch = branch
        self.commit_sha = commit_sha
        self.tree_sha = tree_sha
        self.workflow_run_id = workflow_run_id
        self.workflow_run_attempt = workflow_run_attempt

    def validate(self) -> None:
        if not self.repository or "/" not in self.repository:
            raise PacketError("repository identity must be owner/name")
        if not self.branch:
            raise PacketError("branch identity is missing")
        if HEX40.fullmatch(self.commit_sha) is None:
            raise PacketError("commit identity must be lowercase 40-hex")
        if HEX40.fullmatch(self.tree_sha) is None:
            raise PacketError("tree identity must be lowercase 40-hex")
        if self.workflow_run_id <= 0:
            raise PacketError("workflow_run_id must be positive")
        if self.workflow_run_attempt <= 0:
            raise PacketError("workflow_run_attempt must be positive")


def read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PacketError(f"cannot parse {path}: {error}") from error
    if not isinstance(value, dict):
        raise PacketError(f"{path} must contain one JSON object")
    return value


def nonempty_strings(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and bool(item.strip()) for item in value)
    )


def issue_values(item: dict[str, Any], label: str) -> list[int]:
    values: list[int] = []
    issue = item.get("issue")
    if isinstance(issue, int) and not isinstance(issue, bool) and issue > 0:
        values.append(issue)
    issues = item.get("issues")
    if isinstance(issues, list):
        for value in issues:
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise PacketError(f"{label}.issues must contain positive integers")
            values.append(value)
    if not values:
        raise PacketError(f"{label} must bind an issue or issues")
    return values


def validate_source_evidence(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PacketError(f"{label}.source_evidence must be an object")
    if value.get("level") != "L1":
        raise PacketError(f"{label}.source_evidence.level must be L1")
    if not isinstance(value.get("branch"), str) or not value["branch"].strip():
        raise PacketError(f"{label}.source_evidence.branch is missing")
    for field in ("commit", "tree"):
        raw = value.get(field)
        if not isinstance(raw, str) or HEX40.fullmatch(raw) is None:
            raise PacketError(
                f"{label}.source_evidence.{field} must be lowercase 40-hex"
            )
    run_id = value.get("workflow_run_id")
    if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0:
        raise PacketError(
            f"{label}.source_evidence.workflow_run_id must be positive"
        )
    if not nonempty_strings(value.get("successful_jobs")):
        raise PacketError(f"{label}.source_evidence.successful_jobs is missing")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise PacketError(f"{label}.source_evidence.artifacts is missing")
    for index, artifact in enumerate(artifacts):
        artifact_label = f"{label}.source_evidence.artifacts[{index}]"
        if not isinstance(artifact, dict):
            raise PacketError(f"{artifact_label} must be an object")
        artifact_id = artifact.get("id")
        if (
            not isinstance(artifact_id, int)
            or isinstance(artifact_id, bool)
            or artifact_id <= 0
        ):
            raise PacketError(f"{artifact_label}.id must be positive")
        if not isinstance(artifact.get("name"), str) or not artifact["name"].strip():
            raise PacketError(f"{artifact_label}.name is missing")
        digest = artifact.get("digest")
        if (
            not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or HEX64.fullmatch(digest.removeprefix("sha256:")) is None
        ):
            raise PacketError(
                f"{artifact_label}.digest must be sha256:<64 lowercase hex>"
            )
    return value


def validate_environment_evidence(
    value: Any,
    label: str,
    exit_level: str,
) -> None:
    if not isinstance(value, list) or not value:
        raise PacketError(f"{label}.evidence must be a non-empty list")
    observed: list[int] = []
    for index, item in enumerate(value):
        item_label = f"{label}.evidence[{index}]"
        if not isinstance(item, dict):
            raise PacketError(f"{item_label} must be an object")
        level = item.get("level")
        if level not in LEVELS:
            raise PacketError(f"{item_label}.level is invalid")
        observed.append(LEVELS[str(level)])
        source_commit = item.get("source_commit")
        if not isinstance(source_commit, str) or HEX40.fullmatch(source_commit) is None:
            raise PacketError(f"{item_label}.source_commit must be lowercase 40-hex")
        digest = item.get("evidence_sha256")
        if not isinstance(digest, str) or HEX64.fullmatch(digest) is None:
            raise PacketError(f"{item_label}.evidence_sha256 must be lowercase 64-hex")
        if not isinstance(item.get("kind"), str) or not item["kind"].strip():
            raise PacketError(f"{item_label}.kind is missing")
        if not isinstance(item.get("reviewer"), str) or not item["reviewer"].strip():
            raise PacketError(f"{item_label}.reviewer is missing")
        if item.get("synthetic") is not False:
            raise PacketError(f"{item_label}.synthetic must be false")
    if not any(rank >= LEVELS[exit_level] for rank in observed):
        raise PacketError(f"{label} has no evidence at or above {exit_level}")


def source_head(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "branch": value["branch"],
        "commit": value["commit"],
        "tree": value["tree"],
        "workflow_run_id": value["workflow_run_id"],
        "successful_jobs": list(value["successful_jobs"]),
        "artifacts": [
            {
                "id": artifact["id"],
                "name": artifact["name"],
                "digest": artifact["digest"],
            }
            for artifact in value["artifacts"]
        ],
    }


def build_packet(root: Path, identity: Identity) -> dict[str, Any]:
    identity.validate()
    gaps = read_object(root / GAPS)
    status = read_object(root / STATUS)

    if gaps.get("schema") != EXPECTED_GAP_SCHEMA:
        raise PacketError("gap schema is unsupported")
    if status.get("schema") != EXPECTED_STATUS_SCHEMA:
        raise PacketError("status schema is unsupported")
    if gaps.get("revision") != EXPECTED_REVISION:
        raise PacketError("gap revision is not active r6")
    if status.get("active_plan_revision") != EXPECTED_REVISION:
        raise PacketError("status active_plan_revision is not active r6")
    if status.get("active_plan_revision") != gaps.get("revision"):
        raise PacketError("status and gap revisions differ")
    if status.get("automatic_redispatch") is not False:
        raise PacketError("automatic_redispatch must remain false")

    entries = gaps.get("gaps")
    if not isinstance(entries, list) or not entries:
        raise PacketError("gaps must be a non-empty list")

    seen: set[str] = set()
    ordered: list[str] = []
    counts = {state: 0 for state in sorted(ALLOWED_STATES)}
    remaining: list[dict[str, Any]] = []
    source_heads: dict[tuple[str, str, int], dict[str, Any]] = {}
    required_material: set[str] = set()
    required_authority: set[str] = set()

    for index, raw in enumerate(entries):
        label = f"gaps[{index}]"
        if not isinstance(raw, dict):
            raise PacketError(f"{label} must be an object")
        identifier = raw.get("id")
        if not isinstance(identifier, str) or not identifier.strip():
            raise PacketError(f"{label}.id is missing")
        if identifier in seen:
            raise PacketError(f"duplicate gap id: {identifier}")
        seen.add(identifier)
        ordered.append(identifier)

        state = raw.get("status")
        if state not in ALLOWED_STATES:
            raise PacketError(f"{identifier} has invalid state {state!r}")
        counts[str(state)] += 1
        exit_level = raw.get("exit_evidence_level")
        if exit_level not in LEVELS:
            raise PacketError(f"{identifier} has invalid exit_evidence_level")
        issues = issue_values(raw, identifier)
        if not isinstance(raw.get("summary"), str) or not raw["summary"].strip():
            raise PacketError(f"{identifier}.summary is missing")
        if not nonempty_strings(raw.get("acceptance")):
            raise PacketError(f"{identifier}.acceptance is missing")

        source: dict[str, Any] | None = None
        if state == "OPEN":
            if "source_evidence" in raw or "evidence" in raw:
                raise PacketError(f"{identifier} OPEN state carries promotion evidence")
        elif state == "SOURCE_CLOSED_PENDING_EVIDENCE":
            source = validate_source_evidence(raw.get("source_evidence"), identifier)
            if LEVELS[str(exit_level)] < LEVELS["L2"]:
                raise PacketError(
                    f"{identifier} pending state requires an L2-L6 exit level"
                )
            if not nonempty_strings(raw.get("remaining_evidence")):
                raise PacketError(f"{identifier}.remaining_evidence is missing")
            if "evidence" in raw:
                raise PacketError(f"{identifier} pending state carries full evidence")
        elif state == "EXTERNAL_HOLD":
            materials = raw.get("required_material")
            authorities = raw.get("required_authority")
            if not nonempty_strings(materials) and not nonempty_strings(authorities):
                raise PacketError(
                    f"{identifier} external hold has no required material or authority"
                )
            if nonempty_strings(materials):
                required_material.update(str(item) for item in materials)
            if nonempty_strings(authorities):
                required_authority.update(str(item) for item in authorities)
            if "source_evidence" in raw:
                source = validate_source_evidence(raw["source_evidence"], identifier)
            if "evidence" in raw:
                raise PacketError(f"{identifier} external hold carries full evidence")
        elif state == "CLOSED":
            source = validate_source_evidence(raw.get("source_evidence"), identifier)
            requires_external = (
                raw.get("requires_external_evidence") is True
                or LEVELS[str(exit_level)] >= LEVELS["L2"]
            )
            if requires_external:
                validate_environment_evidence(
                    raw.get("evidence"), identifier, str(exit_level)
                )
            elif raw.get("evidence") not in (None, []):
                raise PacketError(
                    f"{identifier} source-only L1 closure must not carry external evidence"
                )

        if source is not None:
            head = source_head(source)
            source_heads[(head["commit"], head["tree"], head["workflow_run_id"])] = head

        if state != "CLOSED":
            item: dict[str, Any] = {
                "id": identifier,
                "status": state,
                "exit_evidence_level": exit_level,
                "issues": issues,
                "summary": raw["summary"],
            }
            for field in (
                "remaining_evidence",
                "required_material",
                "required_authority",
            ):
                if nonempty_strings(raw.get(field)):
                    item[field] = list(raw[field])
            if source is not None:
                item["source_evidence"] = {
                    "commit": source["commit"],
                    "tree": source["tree"],
                    "workflow_run_id": source["workflow_run_id"],
                }
            remaining.append(item)

    if gaps.get("priority_order") != ordered:
        raise PacketError("priority_order must exactly match gaps order")

    all_closed = all(item.get("status") == "CLOSED" for item in entries)
    zero_gap = status.get("zero_gap")
    if not isinstance(zero_gap, bool) or zero_gap is not all_closed:
        raise PacketError("zero_gap must be true exactly when every gap is CLOSED")
    release_closed = any(
        item.get("id") == "R5-GAP-RELEASE-001" and item.get("status") == "CLOSED"
        for item in entries
        if isinstance(item, dict)
    )
    public_release = status.get("public_release")
    if not isinstance(public_release, bool):
        raise PacketError("public_release must be boolean")
    if public_release is not release_closed:
        raise PacketError(
            "public_release must be true exactly when the release gap is CLOSED"
        )
    if release_closed and not all_closed:
        raise PacketError("release gap cannot close before every other gap")

    if all_closed:
        outcome = "MODULE_CLOSED_CANDIDATE"
    elif counts["OPEN"]:
        outcome = "SOURCE_WORK_REMAINING"
    else:
        outcome = "RESUME_REQUIRED"

    critical_path = status.get("critical_path_next", [])
    if not isinstance(critical_path, list) or not all(
        isinstance(item, str) and item.strip() for item in critical_path
    ):
        raise PacketError("critical_path_next must be a string list")
    negative_claims = status.get("not_claimed", [])
    if not isinstance(negative_claims, list) or not all(
        isinstance(item, str) and item.strip() for item in negative_claims
    ):
        raise PacketError("not_claimed must be a string list")

    return {
        "schema": PACKET_SCHEMA,
        "plan_revision": EXPECTED_REVISION,
        "kind": "exact_head_resume_status_not_promotion_evidence",
        "outcome": outcome,
        "repository": identity.repository,
        "branch": identity.branch,
        "commit_sha": identity.commit_sha,
        "tree_sha": identity.tree_sha,
        "workflow_run_id": identity.workflow_run_id,
        "workflow_run_attempt": identity.workflow_run_attempt,
        "state_counts": counts,
        "gap_count": len(entries),
        "remaining_gap_count": len(remaining),
        "remaining_gaps": remaining,
        "source_evidence_heads": sorted(
            source_heads.values(),
            key=lambda item: (
                item["commit"],
                item["tree"],
                item["workflow_run_id"],
            ),
        ),
        "required_material": sorted(required_material),
        "required_authority": sorted(required_authority),
        "critical_path_next": list(critical_path),
        "claim_ceiling": status.get("claim_ceiling"),
        "negative_claims": list(negative_claims),
        "invariants": {
            "zero_gap": zero_gap,
            "all_gaps_closed": all_closed,
            "public_release": public_release,
            "release_gap_closed": release_closed,
            "automatic_redispatch": False,
            "packet_promotes_gap_state": False,
            "packet_is_environment_evidence": False,
            "packet_is_release_authorization": False,
        },
        "next_action": (
            "independent closeout review and canonical promotion"
            if outcome == "MODULE_CLOSED_CANDIDATE"
            else "execute the listed target/material/authority lanes and import exact reviewed evidence"
        ),
    }


def run_git(root: Path, *args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PacketError(f"cannot resolve Git identity: {error}") from error
    value = completed.stdout.strip()
    if not value:
        raise PacketError(f"git {' '.join(args)} returned an empty value")
    return value


def positive_int(value: str | None, label: str) -> int:
    try:
        result = int(value or "")
    except ValueError as error:
        raise PacketError(f"{label} must be positive") from error
    if result <= 0:
        raise PacketError(f"{label} must be positive")
    return result


def resolve_identity(args: argparse.Namespace, root: Path) -> Identity:
    repository = args.repository or os.environ.get("GITHUB_REPOSITORY", "")
    branch = (
        args.branch
        or os.environ.get("GITHUB_HEAD_REF")
        or os.environ.get("GITHUB_REF_NAME")
        or run_git(root, "branch", "--show-current")
    )
    commit = args.commit or os.environ.get("GITHUB_SHA") or run_git(root, "rev-parse", "HEAD")
    tree = args.tree or run_git(root, "rev-parse", "HEAD^{tree}")
    run_id = positive_int(
        str(args.workflow_run_id) if args.workflow_run_id is not None else os.environ.get("GITHUB_RUN_ID"),
        "workflow_run_id",
    )
    attempt = positive_int(
        str(args.workflow_run_attempt)
        if args.workflow_run_attempt is not None
        else os.environ.get("GITHUB_RUN_ATTEMPT"),
        "workflow_run_attempt",
    )
    return Identity(
        repository=repository,
        branch=branch,
        commit_sha=commit,
        tree_sha=tree,
        workflow_run_id=run_id,
        workflow_run_attempt=attempt,
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--repository")
    parser.add_argument("--branch")
    parser.add_argument("--commit")
    parser.add_argument("--tree")
    parser.add_argument("--workflow-run-id", type=int)
    parser.add_argument("--workflow-run-attempt", type=int)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    try:
        identity = resolve_identity(args, root)
        packet = build_packet(root, identity)
    except PacketError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    raw = json.dumps(packet, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        output = args.output if args.output.is_absolute() else root / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(raw, encoding="utf-8")
    if args.json or args.output is None:
        print(raw, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
