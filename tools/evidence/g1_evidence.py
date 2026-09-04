"""Hardened G1 evidence intake with live retention and continuous lineage checks."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from g1_evidence_core import *  # noqa: F401,F403
from g1_evidence_core import (
    promotion_plan,
    validate_package,
    _verify_evidence_snapshot as _verify_structural_directory,
)
from g1_evidence_contract import COMPLETE, LEVEL_ORDER, PROGRAM_REVISION
from g1_evidence_types import EvidenceError, _timestamp


def _require_live(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def verify_evidence_directory(
    evidence_dir: Path,
    gap_register: Path,
    *,
    current_source_commit: str | None = None,
    expected_subject: dict[str, Any] | None = None,
    now: datetime | None = None,
    attestation_path: Path | None = None,
    attestation_sha256: str | None = None,
    attestation_signature_path: Path | None = None,
    attestation_public_key_path: Path | None = None,
    attestation_public_key_sha256: str | None = None,
    repository_root: Path | None = None,
) -> dict[str, Any]:
    """Validate receipts and return only live, continuously rooted promotions.

    The structural core validates schemas, digests, roles and evidence classes.
    This layer additionally prevents a still-unexpired package from borrowing an
    expired authorization/artifact or a HOLD, expired, stale-source, or skipped
    evidence-level parent.
    """

    reference_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    structural, gap_specs, packages = _verify_structural_directory(
        evidence_dir,
        gap_register,
        current_source_commit=current_source_commit,
        expected_subject=expected_subject,
        now=reference_now,
        attestation_path=attestation_path,
        attestation_sha256=attestation_sha256,
        attestation_signature_path=attestation_signature_path,
        attestation_public_key_path=attestation_public_key_path,
        attestation_public_key_sha256=attestation_public_key_sha256,
        repository_root=repository_root,
    )
    # Continue with exactly the packages and gap definitions validated above.
    # Re-opening the directory here can introduce unattested packages or a new
    # gap register between structural/signature and live-retention validation.
    assessments: dict[str, PackageAssessment] = {}  # noqa: F405
    for package in packages.values():
        assessment = validate_package(
            package, gap_specs,
            current_source_commit=current_source_commit, now=reference_now,
        )
        assessments[assessment.package_id] = assessment

    live_ids: set[str] = set()
    for package_id_value, assessment in assessments.items():
        if not assessment.promotable_for_current_source:
            continue
        package = packages[package_id_value]
        created = _timestamp(package["created_at"], "created_at")
        expires = _timestamp(package["expires_at"], "expires_at")
        _require_live(created <= reference_now, f"{package_id_value} was created in the future")

        authorization_expires = _timestamp(
            package["authorization"]["expires_at"],
            "authorization.expires_at",
        )
        _require_live(
            authorization_expires > reference_now,
            f"{package_id_value} authorization expired",
        )
        _require_live(
            authorization_expires >= expires,
            f"{package_id_value} outlives its authorization",
        )
        for artifact in package["artifacts"]:
            retained_until = _timestamp(
                artifact["retention_expires_at"],
                f"artifact {artifact['name']} retention_expires_at",
            )
            _require_live(
                retained_until > reference_now,
                f"{package_id_value} artifact {artifact['name']} expired",
            )
            _require_live(
                retained_until >= expires,
                f"{package_id_value} outlives artifact {artifact['name']}",
            )

        level_number = LEVEL_ORDER[assessment.level]
        parent_ids = package["lineage"]["parent_package_ids"]
        if level_number == 1:
            _require_live(
                not parent_ids,
                f"{package_id_value} L1 source evidence must be a lineage root",
            )
        else:
            immediate_level = f"L{level_number - 1}"
            immediate_parent = False
            for parent_id in parent_ids:
                parent_assessment = assessments[parent_id]
                _require_live(
                    parent_assessment.status == COMPLETE,
                    f"{package_id_value} parent {parent_id} is not COMPLETE",
                )
                _require_live(
                    parent_assessment.promotable_for_current_source,
                    f"{package_id_value} parent {parent_id} is expired or source-stale",
                )
                if parent_assessment.level == immediate_level:
                    immediate_parent = True
            _require_live(
                immediate_parent,
                f"{package_id_value} skips required immediate parent level {immediate_level}",
            )
        live_ids.add(package_id_value)

    promotable_gaps: dict[str, str] = {}
    for package_id_value in sorted(live_ids):
        assessment = assessments[package_id_value]
        for gap_id in assessment.gaps:
            previous = promotable_gaps.get(gap_id)
            _require_live(
                previous is None,
                f"gap {gap_id} has multiple live promotable packages",
            )
            promotable_gaps[gap_id] = package_id_value

    unresolved = sorted(
        gap_id
        for gap_id, spec in gap_specs.items()
        if spec.status != "CLOSED" and gap_id not in promotable_gaps
    )
    structural.update(
        schema="org.trillionnium.g1.evidence-verification-report.v2",
        program_revision=PROGRAM_REVISION,
        promotable_gaps=promotable_gaps,
        unresolved_gaps=unresolved,
        all_gaps_promotable=not unresolved,
        public_release=False,
        automatic_redispatch=False,
    )
    return structural
