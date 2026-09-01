"""G1 evidence package validation and non-mutating gap-promotion planning."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Mapping

from g1_evidence_contract import *  # noqa: F403,F401
from g1_evidence_types import (
    DuplicateJsonMember,
    EvidenceError,
    GapSpec,
    PackageAssessment,
    _exact_keys,
    _git_sha,
    _mapping,
    _nonnegative_int,
    _positive_int,
    _require,
    _sha256,
    _string,
    _string_list,
    _timestamp,
    _validate_artifacts,
    _validate_authorization,
    _validate_holds,
    _validate_observations,
    _validate_role,
    _validate_source,
    canonical_bytes,
    load_gap_specs,
    package_id,
    sha256_bytes,
    strict_json_bytes,
    strict_json_file,
)

def validate_package(
    package: dict[str, Any],
    gap_specs: Mapping[str, GapSpec],
    *,
    current_source_commit: str | None = None,
    now: datetime | None = None,
) -> PackageAssessment:
    _exact_keys(package, PACKAGE_KEYS, "evidence package")
    _require(package["schema"] == PACKAGE_SCHEMA, "evidence package schema is unsupported")
    _require(package["version"] == PACKAGE_VERSION, "evidence package version is unsupported")
    _require(package["program_revision"] == PROGRAM_REVISION, "evidence package program revision drifted")
    evidence_class = _string(package["evidence_class"], "evidence_class")
    _require(evidence_class in EVIDENCE_CLASS_LEVEL, "evidence_class is unsupported")
    level = _string(package["level"], "level")
    _require(level == EVIDENCE_CLASS_LEVEL[evidence_class], "level does not match evidence_class")
    status = _string(package["status"], "status")
    _require(status in {COMPLETE, HOLD}, "status must be COMPLETE or HOLD")
    _require(package["automatic_redispatch"] is False, "automatic_redispatch must remain false")
    expected_public_release = evidence_class == "signed_release" and status == COMPLETE
    _require(
        package["public_release"] is expected_public_release,
        "public_release does not match the evidence class and status",
    )
    expected_ceiling = CLASS_CLAIM_CEILING[evidence_class]
    _require(package["claim_ceiling"] == expected_ceiling, "claim_ceiling exceeds or drifts from class")

    source = _validate_source(package["source"])
    lineage = _mapping(package["lineage"], "lineage")
    _exact_keys(lineage, LINEAGE_KEYS, "lineage")
    parent_ids = _string_list(lineage["parent_package_ids"], "lineage.parent_package_ids", allow_empty=True)
    for index, parent_id in enumerate(parent_ids):
        _require(PACKAGE_ID_RE.fullmatch(parent_id) is not None, f"lineage.parent_package_ids[{index}] is malformed")
    predecessor = lineage["predecessor_source_commit"]
    if predecessor is not None:
        _git_sha(predecessor, "lineage.predecessor_source_commit")
        _require(predecessor != source["commit"], "predecessor_source_commit equals source.commit")
    if evidence_class != "source_qualification" and status == COMPLETE:
        _require(bool(parent_ids), "complete L2-L6 evidence requires parent packages")

    gaps = _string_list(package["gaps"], "gaps")
    for gap_id in gaps:
        spec = gap_specs.get(gap_id)
        _require(spec is not None, f"evidence references unknown gap {gap_id}")
        _require(spec.evidence_class == evidence_class, f"{gap_id} requires {spec.evidence_class}, not {evidence_class}")
        _require(
            LEVEL_ORDER[level] >= LEVEL_ORDER[spec.exit_level],
            f"{gap_id} exit level {spec.exit_level} exceeds package level {level}",
        )

    _validate_artifacts(package["artifacts"], required=status == COMPLETE)
    _validate_observations(
        package["observations"], evidence_class=evidence_class, status=status
    )
    roles = _mapping(package["roles"], "roles")
    _exact_keys(roles, ROLE_KEYS, "roles")
    producer = _validate_role(roles["producer"], "roles.producer", required=status == COMPLETE)
    operator = _validate_role(
        roles["operator"],
        "roles.operator",
        required=status == COMPLETE and evidence_class != "source_qualification",
    )
    reviewer = _validate_role(roles["reviewer"], "roles.reviewer", required=status == COMPLETE)
    authorizer = _validate_role(roles["authorizer"], "roles.authorizer", required=status == COMPLETE)
    if status == COMPLETE:
        _require(producer != reviewer, "producer and reviewer must be different principals")
        _require(producer != authorizer, "producer and authorizer must be different principals")
        if operator is not None:
            _require(operator != reviewer, "operator and reviewer must be different principals")
        if evidence_class in {"destructive_fault", "signed_release"}:
            _require(operator != authorizer, "fault/release operator and authorizer must differ")
        if evidence_class == "signed_release":
            _require(reviewer != authorizer, "release reviewer and authorizer must differ")
    _validate_authorization(package["authorization"], evidence_class=evidence_class, status=status)

    created = _timestamp(package["created_at"], "created_at")
    expires = _timestamp(package["expires_at"], "expires_at")
    _require(created < expires, "expires_at must be later than created_at")
    retention_days = _positive_int(package["retention_days"], "retention_days", 3650)
    _require((expires - created).total_seconds() <= retention_days * 86400 + 1, "expires_at exceeds retention_days")
    negative_claims = set(_string_list(package["negative_claims"], "negative_claims", allow_empty=True))
    _require(
        CLASS_NEGATIVE_CLAIMS[evidence_class].issubset(negative_claims),
        "negative_claims omit required lower-bound non-claims",
    )
    if evidence_class == "signed_release" and status == COMPLETE:
        _require(not negative_claims, "complete signed release must not retain stale negative claims")
    _validate_holds(package["holds"], status=status)

    claimed_id = _string(package["package_id"], "package_id")
    _require(PACKAGE_ID_RE.fullmatch(claimed_id) is not None, "package_id is malformed")
    _require(claimed_id == package_id(package), "package_id does not match canonical package bytes")

    reference_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expired = expires <= reference_now
    current_matches = current_source_commit is None or source["commit"] == current_source_commit
    promotable = status == COMPLETE and not expired and current_matches
    return PackageAssessment(
        package_id=claimed_id,
        level=level,
        evidence_class=evidence_class,
        status=status,
        source_commit=source["commit"],
        gaps=tuple(gaps),
        structurally_valid=True,
        expired=expired,
        promotable_for_current_source=promotable,
    )


def verify_evidence_directory(
    evidence_dir: Path,
    gap_register: Path,
    *,
    current_source_commit: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    gap_specs = load_gap_specs(gap_register)
    _require(evidence_dir.is_dir(), f"evidence directory does not exist: {evidence_dir}")
    paths = sorted(path for path in evidence_dir.glob("*.json") if path.is_file())
    _require(bool(paths), f"evidence directory contains no JSON packages: {evidence_dir}")
    assessments: list[PackageAssessment] = []
    package_ids: set[str] = set()
    packages: dict[str, dict[str, Any]] = {}
    for path in paths:
        package = strict_json_file(path, str(path))
        assessment = validate_package(
            package,
            gap_specs,
            current_source_commit=current_source_commit,
            now=now,
        )
        _require(assessment.package_id not in package_ids, "duplicate package_id across evidence files")
        package_ids.add(assessment.package_id)
        assessments.append(assessment)
        packages[assessment.package_id] = package

    for assessment in assessments:
        package = packages[assessment.package_id]
        for parent_id in package["lineage"]["parent_package_ids"]:
            _require(parent_id in packages, f"{assessment.package_id} references missing parent {parent_id}")
            parent = packages[parent_id]
            _require(
                LEVEL_ORDER[parent["level"]] < LEVEL_ORDER[assessment.level],
                f"{assessment.package_id} parent {parent_id} is not a lower evidence level",
            )
            _require(
                parent["source"]["commit"] == package["source"]["commit"],
                f"{assessment.package_id} parent {parent_id} uses another source commit",
            )

    promotable_gaps: dict[str, str] = {}
    for assessment in assessments:
        if not assessment.promotable_for_current_source:
            continue
        for gap_id in assessment.gaps:
            existing = promotable_gaps.get(gap_id)
            _require(existing is None, f"gap {gap_id} has multiple current promotable packages")
            promotable_gaps[gap_id] = assessment.package_id

    unresolved = sorted(
        gap_id
        for gap_id, spec in gap_specs.items()
        if spec.status != "CLOSED" and gap_id not in promotable_gaps
    )
    return {
        "schema": "org.trillionnium.g1.evidence-verification-report.v1",
        "program_revision": PROGRAM_REVISION,
        "current_source_commit": current_source_commit,
        "package_count": len(assessments),
        "packages": [
            {
                "package_id": item.package_id,
                "level": item.level,
                "evidence_class": item.evidence_class,
                "status": item.status,
                "source_commit": item.source_commit,
                "gaps": list(item.gaps),
                "expired": item.expired,
                "promotable_for_current_source": item.promotable_for_current_source,
            }
            for item in assessments
        ],
        "promotable_gaps": promotable_gaps,
        "unresolved_gaps": unresolved,
        "all_gaps_promotable": not unresolved,
        "public_release": False,
        "automatic_redispatch": False,
    }


def promotion_plan(
    report: Mapping[str, Any],
    gap_register: Path,
) -> dict[str, Any]:
    gap_specs = load_gap_specs(gap_register)
    promotable = _mapping(report.get("promotable_gaps"), "report.promotable_gaps")
    transitions = []
    for gap_id in sorted(gap_specs):
        spec = gap_specs[gap_id]
        evidence_id = promotable.get(gap_id)
        if evidence_id is not None and spec.status != "CLOSED":
            transitions.append(
                {
                    "gap_id": gap_id,
                    "from": spec.status,
                    "to": "CLOSED",
                    "evidence_package_id": evidence_id,
                }
            )
    return {
        "schema": "org.trillionnium.g1.gap-promotion-plan.v1",
        "program_revision": PROGRAM_REVISION,
        "current_source_commit": report.get("current_source_commit"),
        "transitions": transitions,
        "unresolved_gaps": list(report.get("unresolved_gaps", [])),
        "zero_gap_after_plan": not report.get("unresolved_gaps"),
        "public_release_after_plan": False,
        "automatic_redispatch": False,
    }


def write_json(path: Path, value: Any) -> None:
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(encoded, encoding="utf-8")
