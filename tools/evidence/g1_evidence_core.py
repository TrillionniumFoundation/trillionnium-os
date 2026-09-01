"""G1 evidence package validation and non-mutating gap-promotion planning."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
from typing import Any, Mapping

from g1_evidence_contract import *  # noqa: F403,F401
from g1_evidence_types import (
    DuplicateJsonMember,
    EvidenceError,
    GapSpec,
    PackageAssessment,
    TrustedAttestation,
    _exact_keys,
    _identifier,
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


def _validate_attestation_receipt(receipt: Mapping[str, Any]) -> tuple[list[str], str, Any, Any]:
    """Validate the shape of an out-of-band attestation receipt.

    The receipt is deliberately not accepted as proof by itself.  Callers must
    provide the expected raw-byte digest separately (for example from an
    independently administered secret or review system).
    """

    _exact_keys(receipt, ATTESTATION_KEYS, "trusted attestation")
    _require(receipt["schema"] == ATTESTATION_SCHEMA, "trusted attestation schema is unsupported")
    _require(receipt["version"] == ATTESTATION_VERSION, "trusted attestation version is unsupported")
    _require(
        receipt["signature_algorithm"] == ATTESTATION_SIGNATURE_ALGORITHM,
        "trusted attestation signature_algorithm is unsupported",
    )
    package_ids = _string_list(receipt["package_ids"], "trusted attestation.package_ids")
    for index, value in enumerate(package_ids):
        _require(
            PACKAGE_ID_RE.fullmatch(value) is not None,
            f"trusted attestation.package_ids[{index}] is malformed",
        )
    source_commit = _git_sha(receipt["source_commit"], "trusted attestation.source_commit")
    _identifier(receipt["authority"], "trusted attestation.authority")
    _identifier(receipt["verification_method"], "trusted attestation.verification_method")
    _identifier(receipt["trust_root"], "trusted attestation.trust_root")
    _require(
        receipt["trust_root"] == ATTESTATION_TRUST_ROOT_ID,
        "trusted attestation trust_root is not the configured root",
    )
    _require(
        receipt["independent_verification"] is True,
        "trusted attestation.independent_verification must be true",
    )
    verified_at = _timestamp(receipt["verified_at"], "trusted attestation.verified_at")
    expires_at = _timestamp(receipt["expires_at"], "trusted attestation.expires_at")
    _require(verified_at < expires_at, "trusted attestation expires_at must be later than verified_at")
    evidence_ids = _string_list(receipt["evidence_ids"], "trusted attestation.evidence_ids")
    for index, value in enumerate(evidence_ids):
        _require(
            IDENTIFIER_RE.fullmatch(value) is not None,
            f"trusted attestation.evidence_ids[{index}] is malformed",
        )
    return package_ids, source_commit, verified_at, expires_at


def load_trusted_attestation(
    path: Path,
    expected_sha256: str,
    *,
    repository_root: Path | None = None,
) -> TrustedAttestation:
    """Load a receipt only when its raw bytes match an out-of-band digest.

    A receipt inside the repository is rejected: repository-controlled JSON
    must never be able to make its own COMPLETE evidence trusted.  The core
    remains network-free; obtaining and independently checking the digest is a
    caller/operations boundary.
    """

    _sha256(expected_sha256, "trusted attestation expected_sha256")
    try:
        if path.is_symlink():
            raise EvidenceError("trusted attestation path must not be a symlink")
        lexical = path.absolute()
        resolved = path.resolve(strict=True)
        if not resolved.is_file():
            raise EvidenceError("trusted attestation path is not a regular file")
        if repository_root is not None:
            root = repository_root.resolve(strict=True)
            _require(
                not lexical.is_relative_to(root),
                "trusted attestation must be outside the repository root",
            )
            _require(
                not resolved.is_relative_to(root),
                "trusted attestation resolves inside the repository root",
            )
        content = resolved.read_bytes()
    except EvidenceError:
        raise
    except (OSError, RuntimeError) as error:
        raise EvidenceError(f"cannot read trusted attestation: {error}") from error
    actual_sha256 = sha256_bytes(content)
    _require(
        actual_sha256 == expected_sha256,
        "trusted attestation raw-byte digest does not match the out-of-band digest",
    )
    receipt = strict_json_bytes(content, str(resolved))
    _validate_attestation_receipt(receipt)
    return TrustedAttestation(path=resolved, digest=actual_sha256, receipt=receipt)


def _read_external_trust_file(
    path: Path,
    *,
    label: str,
    repository_root: Path | None,
    evidence_dir: Path,
) -> bytes:
    """Read a detached trust input only from outside repository evidence."""

    try:
        if path.is_symlink():
            raise EvidenceError(f"{label} path must not be a symlink")
        lexical = path.absolute()
        resolved = path.resolve(strict=True)
        if not resolved.is_file():
            raise EvidenceError(f"{label} path is not a regular file")
        evidence_root = evidence_dir.resolve(strict=True)
        _require(
            not lexical.is_relative_to(evidence_root)
            and not resolved.is_relative_to(evidence_root),
            f"{label} must be outside the evidence directory",
        )
        if repository_root is not None:
            root = repository_root.resolve(strict=True)
            _require(
                not lexical.is_relative_to(root)
                and not resolved.is_relative_to(root),
                f"{label} must be outside the repository root",
            )
        return resolved.read_bytes()
    except EvidenceError:
        raise
    except (OSError, RuntimeError) as error:
        raise EvidenceError(f"cannot read {label}: {error}") from error


def verify_attestation_signature(
    attestation: TrustedAttestation,
    *,
    signature_path: Path,
    public_key_path: Path,
    public_key_sha256: str,
    repository_root: Path | None,
    evidence_dir: Path,
) -> dict[str, str]:
    """Verify a detached RSA-SHA256 signature under an out-of-band key.

    The public key and signature must be supplied outside repository-controlled
    paths.  The caller additionally pins the public-key bytes by digest; the
    core performs no network access and does not infer trust from receipt
    fields alone.
    """

    _sha256(public_key_sha256, "trusted attestation public_key_sha256")
    signature = _read_external_trust_file(
        signature_path,
        label="trusted attestation signature",
        repository_root=repository_root,
        evidence_dir=evidence_dir,
    )
    public_key = _read_external_trust_file(
        public_key_path,
        label="trusted attestation public key",
        repository_root=repository_root,
        evidence_dir=evidence_dir,
    )
    actual_public_key_sha256 = sha256_bytes(public_key)
    _require(
        actual_public_key_sha256 == public_key_sha256,
        "trusted attestation public-key digest does not match the out-of-band digest",
    )
    public_key_resolved = public_key_path.resolve(strict=True)
    try:
        key_info = subprocess.run(
            [
                "openssl",
                "pkey",
                "-pubin",
                "-in",
                str(public_key_resolved),
                "-text",
                "-noout",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise EvidenceError(f"trusted attestation public-key type check failed: {error}") from error
    _require(
        key_info.returncode == 0
        and b"Modulus:" in key_info.stdout
        and b"Exponent:" in key_info.stdout,
        "trusted attestation public key is not an RSA key",
    )
    try:
        result = subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(public_key_resolved),
                "-signature",
                str(signature_path.resolve(strict=True)),
                str(attestation.path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise EvidenceError(f"trusted attestation signature verification failed: {error}") from error
    _require(
        result.returncode == 0,
        "trusted attestation detached signature is invalid",
    )
    return {
        "algorithm": ATTESTATION_SIGNATURE_ALGORITHM,
        "signature_sha256": sha256_bytes(signature),
        "public_key_sha256": actual_public_key_sha256,
    }

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


def _require_trusted_attestation_for_promotions(
    assessments: list[PackageAssessment],
    packages: Mapping[str, dict[str, Any]],
    *,
    current_source_commit: str | None,
    now: datetime,
    attestation_path: Path | None,
    attestation_sha256: str | None,
    attestation_signature_path: Path | None,
    attestation_public_key_path: Path | None,
    attestation_public_key_sha256: str | None,
    repository_root: Path | None,
    evidence_dir: Path,
) -> dict[str, Any] | None:
    """Require an out-of-band binding before any COMPLETE package can promote.

    Historical/stale and HOLD receipts remain inspectable without an
    attestation because they cannot produce a current promotion.  Every live
    COMPLETE package that could influence a promotion (including parents) is
    bound as an exact set in one trusted receipt.
    """

    promotable_ids = sorted(
        assessment.package_id
        for assessment in assessments
        if assessment.promotable_for_current_source
    )
    if not promotable_ids:
        _require(
            attestation_path is None
            and attestation_sha256 is None
            and attestation_signature_path is None
            and attestation_public_key_path is None
            and attestation_public_key_sha256 is None,
            "trusted attestation supplied but no current COMPLETE package requires it",
        )
        return None
    _require(
        attestation_path is not None and attestation_sha256 is not None,
        "current-source COMPLETE evidence requires an out-of-band trusted attestation",
    )
    _require(
        attestation_signature_path is not None
        and attestation_public_key_path is not None
        and attestation_public_key_sha256 is not None,
        "current-source COMPLETE evidence requires a detached trusted signature and public key",
    )
    _require(
        repository_root is not None,
        "repository_root is required when promoting evidence with a trusted attestation",
    )
    trusted = load_trusted_attestation(
        attestation_path,
        attestation_sha256,
        repository_root=repository_root,
    )
    evidence_root = evidence_dir.resolve(strict=True)
    _require(
        not trusted.path.is_relative_to(evidence_root),
        "trusted attestation must be outside the evidence directory",
    )
    signature_metadata = verify_attestation_signature(
        trusted,
        signature_path=attestation_signature_path,
        public_key_path=attestation_public_key_path,
        public_key_sha256=attestation_public_key_sha256,
        repository_root=repository_root,
        evidence_dir=evidence_dir,
    )
    receipt = trusted.receipt
    package_ids, source_commit, verified_at, expires_at = _validate_attestation_receipt(receipt)
    _require(
        set(package_ids) == set(promotable_ids),
        "trusted attestation package_ids do not exactly match current COMPLETE evidence",
    )
    if current_source_commit is not None:
        _require(
            source_commit == current_source_commit,
            "trusted attestation source_commit does not match current source",
        )
    else:
        source_commits = {
            assessment.source_commit
            for assessment in assessments
            if assessment.package_id in promotable_ids
        }
        _require(
            len(source_commits) == 1 and source_commit in source_commits,
            "trusted attestation source_commit does not match COMPLETE evidence",
        )
    _require(verified_at <= now, "trusted attestation was created in the future")
    _require(expires_at > now, "trusted attestation has expired")
    for package_id_value in promotable_ids:
        package = packages[package_id_value]
        package_expires = _timestamp(package["expires_at"], "expires_at")
        _require(
            expires_at >= package_expires,
            f"trusted attestation expires before package {package_id_value}",
        )
    return {
        "sha256": trusted.digest,
        "path": str(trusted.path),
        "authority": receipt["authority"],
        "verification_method": receipt["verification_method"],
        "trust_root": receipt["trust_root"],
        "package_ids": package_ids,
        "source_commit": source_commit,
        "verified_at": receipt["verified_at"],
        "expires_at": receipt["expires_at"],
        **signature_metadata,
    }


def verify_evidence_directory(
    evidence_dir: Path,
    gap_register: Path,
    *,
    current_source_commit: str | None = None,
    now: datetime | None = None,
    attestation_path: Path | None = None,
    attestation_sha256: str | None = None,
    attestation_signature_path: Path | None = None,
    attestation_public_key_path: Path | None = None,
    attestation_public_key_sha256: str | None = None,
    repository_root: Path | None = None,
) -> dict[str, Any]:
    reference_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    gap_specs = load_gap_specs(gap_register)
    _require(evidence_dir.is_dir(), f"evidence directory does not exist: {evidence_dir}")
    candidates = sorted(evidence_dir.glob("*.json"))
    _require(bool(candidates), f"evidence directory contains no JSON packages: {evidence_dir}")
    _require(
        all(not path.is_symlink() and path.is_file() for path in candidates),
        "evidence directory contains a symlink or non-regular JSON entry",
    )
    paths = candidates
    assessments: list[PackageAssessment] = []
    package_ids: set[str] = set()
    packages: dict[str, dict[str, Any]] = {}
    for path in paths:
        package = strict_json_file(path, str(path))
        assessment = validate_package(
            package,
            gap_specs,
            current_source_commit=current_source_commit,
            now=reference_now,
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

    trusted_attestation = _require_trusted_attestation_for_promotions(
        assessments,
        packages,
        current_source_commit=current_source_commit,
        now=reference_now,
        attestation_path=attestation_path,
        attestation_sha256=attestation_sha256,
        attestation_signature_path=attestation_signature_path,
        attestation_public_key_path=attestation_public_key_path,
        attestation_public_key_sha256=attestation_public_key_sha256,
        repository_root=repository_root,
        evidence_dir=evidence_dir,
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
        "trusted_attestation": trusted_attestation,
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
