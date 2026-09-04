"""Strict JSON, primitive validators, and typed G1 evidence records."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from g1_evidence_contract import *  # noqa: F403

class EvidenceError(ValueError):
    """An evidence package is malformed, overclaims, or is not promotable."""


class DuplicateJsonMember(EvidenceError):
    """A JSON object contains two members with the same name."""


@dataclass(frozen=True)
class GapSpec:
    gap_id: str
    status: str
    exit_level: str
    evidence_class: str


@dataclass(frozen=True)
class PackageAssessment:
    package_id: str
    level: str
    evidence_class: str
    status: str
    source_commit: str
    gaps: tuple[str, ...]
    structurally_valid: bool
    expired: bool
    promotable_for_current_source: bool


@dataclass(frozen=True)
class TrustedAttestation:
    """A receipt whose raw bytes were supplied and digest-checked out of band."""

    path: Path
    digest: str
    receipt: dict[str, Any]
    raw_bytes: bytes


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonMember(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise EvidenceError(f"non-finite JSON number {value}")


def strict_json_bytes(content: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, EvidenceError) as error:
        raise EvidenceError(f"{label} is not strict JSON: {error}") from error
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} root must be an object")
    return value


def strict_json_file(path: Path, label: str | None = None) -> dict[str, Any]:
    try:
        content = path.read_bytes()
    except OSError as error:
        raise EvidenceError(f"cannot read {label or path}: {error}") from error
    return strict_json_bytes(content, label or str(path))


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def package_id(package: Mapping[str, Any]) -> str:
    preimage = dict(package)
    preimage["package_id"] = ""
    return "sha256:" + sha256_bytes(canonical_bytes(preimage))


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    _require(
        actual == expected,
        f"{label} keys drift; missing={sorted(expected - actual)}, "
        f"extra={sorted(actual - expected)}",
    )


def _mapping(value: Any, label: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{label} must be an object")
    return value


def _string(value: Any, label: str) -> str:
    _require(isinstance(value, str) and bool(value), f"{label} must be a non-empty string")
    _require("\x00" not in value, f"{label} contains a NUL")
    return value


def _identifier(value: Any, label: str) -> str:
    text = _string(value, label)
    _require(IDENTIFIER_RE.fullmatch(text) is not None, f"{label} is malformed")
    return text


def _sha256(value: Any, label: str) -> str:
    text = _string(value, label)
    _require(SHA256_RE.fullmatch(text) is not None, f"{label} must be lowercase SHA-256")
    return text


def _git_sha(value: Any, label: str) -> str:
    text = _string(value, label)
    _require(GIT_SHA_RE.fullmatch(text) is not None, f"{label} must be a 40-byte Git SHA")
    return text


def _positive_int(value: Any, label: str, maximum: int | None = None) -> int:
    _require(isinstance(value, int) and not isinstance(value, bool), f"{label} must be an integer")
    _require(value > 0, f"{label} must be positive")
    if maximum is not None:
        _require(value <= maximum, f"{label} exceeds {maximum}")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    _require(isinstance(value, int) and not isinstance(value, bool), f"{label} must be an integer")
    _require(value >= 0, f"{label} must be nonnegative")
    return value


def _string_list(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    _require(isinstance(value, list), f"{label} must be an array")
    if not allow_empty:
        _require(bool(value), f"{label} must not be empty")
    result = [_string(item, f"{label}[{index}]") for index, item in enumerate(value)]
    _require(len(result) == len(set(result)), f"{label} contains duplicates")
    return result


def _timestamp(value: Any, label: str) -> datetime:
    text = _string(value, label)
    _require(text.endswith("Z"), f"{label} must be UTC RFC3339 ending in Z")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        raise EvidenceError(f"{label} is not RFC3339: {error}") from error
    _require(parsed.tzinfo is not None, f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _validate_role(value: Any, label: str, *, required: bool) -> str | None:
    if value is None:
        _require(not required, f"{label} is required")
        return None
    role = _mapping(value, label)
    _exact_keys(role, ROLE_VALUE_KEYS, label)
    principal = _identifier(role["principal"], f"{label}.principal")
    _identifier(role["identity_provider"], f"{label}.identity_provider")
    _identifier(role["evidence_id"], f"{label}.evidence_id")
    return principal


def _validate_source(source_value: Any) -> dict[str, Any]:
    source = _mapping(source_value, "source")
    _exact_keys(source, SOURCE_KEYS, "source")
    repository = _identifier(source["repository"], "source.repository")
    _require("/" in repository, "source.repository must use owner/repository form")
    _identifier(source["branch"], "source.branch")
    _git_sha(source["commit"], "source.commit")
    _git_sha(source["tree"], "source.tree")
    _sha256(source["cargo_lock_sha256"], "source.cargo_lock_sha256")
    pull_request = _positive_int(source["pull_request"], "source.pull_request", 1_000_000_000)
    runs = source["workflow_runs"]
    _require(isinstance(runs, list) and bool(runs), "source.workflow_runs must be a non-empty array")
    run_ids: set[int] = set()
    for index, value in enumerate(runs):
        run = _mapping(value, f"source.workflow_runs[{index}]")
        _exact_keys(run, WORKFLOW_RUN_KEYS, f"source.workflow_runs[{index}]")
        _string(run["name"], f"source.workflow_runs[{index}].name")
        run_id = _positive_int(run["run_id"], f"source.workflow_runs[{index}].run_id")
        _require(run_id not in run_ids, "source.workflow_runs contains duplicate run IDs")
        run_ids.add(run_id)
        _positive_int(run["attempt"], f"source.workflow_runs[{index}].attempt", 1_000)
        _require(run["result"] == "success", f"source.workflow_runs[{index}].result is not success")
        _positive_int(run["artifact_id"], f"source.workflow_runs[{index}].artifact_id")
        _identifier(run["artifact_name"], f"source.workflow_runs[{index}].artifact_name")
        _sha256(run["artifact_sha256"], f"source.workflow_runs[{index}].artifact_sha256")
    _require(pull_request > 0, "source.pull_request must identify an actual pull request")
    return source


def _validate_subject(subject_value: Any, label: str = "subject") -> dict[str, Any]:
    """Validate the exact integration subject shared by packages/receipts.

    The ordered parent tuple is part of the signed subject.  Merely recording
    a merge ZIP digest is insufficient because an old archive can be replayed
    after the PR base moves or is retargeted.
    """

    subject = _mapping(subject_value, label)
    _exact_keys(subject, SUBJECT_KEYS, label)

    def validate_ref(value: Any, ref_label: str) -> dict[str, Any]:
        ref = _mapping(value, ref_label)
        _exact_keys(ref, SUBJECT_REF_KEYS, ref_label)
        repository = _string(ref["repository"], f"{ref_label}.repository")
        _require(
            "/" in repository and ".." not in repository,
            f"{ref_label}.repository must use a safe owner/repository form",
        )
        _identifier(ref["ref"], f"{ref_label}.ref")
        _git_sha(ref["commit"], f"{ref_label}.commit")
        _git_sha(ref["tree"], f"{ref_label}.tree")
        return ref

    base = validate_ref(subject["base"], f"{label}.base")
    head = validate_ref(subject["head"], f"{label}.head")
    merge = _mapping(subject["merge"], f"{label}.merge")
    _exact_keys(merge, SUBJECT_MERGE_KEYS, f"{label}.merge")
    kind = _string(merge["kind"], f"{label}.merge.kind")
    _require(kind in SUBJECT_MERGE_KINDS, f"{label}.merge.kind is unsupported")
    merge_commit = _git_sha(merge["commit"], f"{label}.merge.commit")
    _git_sha(merge["tree"], f"{label}.merge.tree")
    parents = merge["parents"]
    _require(isinstance(parents, list), f"{label}.merge.parents must be an array")
    _require(len(parents) == 2, f"{label}.merge.parents must contain exactly two ordered parents")
    parent_values = [
        _git_sha(value, f"{label}.merge.parents[{index}]")
        for index, value in enumerate(parents)
    ]
    _require(
        parent_values == [base["commit"], head["commit"]],
        f"{label}.merge.parents must be ordered base then head",
    )
    _require(merge_commit not in parent_values, f"{label}.merge.commit must differ from both parents")
    return subject


def _validate_artifacts(value: Any, *, required: bool) -> None:
    _require(isinstance(value, list), "artifacts must be an array")
    if required:
        _require(bool(value), "complete evidence requires artifacts")
    names: set[str] = set()
    for index, item in enumerate(value):
        artifact = _mapping(item, f"artifacts[{index}]")
        _exact_keys(artifact, ARTIFACT_KEYS, f"artifacts[{index}]")
        name = _identifier(artifact["name"], f"artifacts[{index}].name")
        _require(name not in names, "artifacts contains duplicate names")
        names.add(name)
        _identifier(artifact["kind"], f"artifacts[{index}].kind")
        _sha256(artifact["sha256"], f"artifacts[{index}].sha256")
        _positive_int(artifact["bytes"], f"artifacts[{index}].bytes")
        _string(artifact["uri"], f"artifacts[{index}].uri")
        _timestamp(artifact["retention_expires_at"], f"artifacts[{index}].retention_expires_at")


def _validate_holds(value: Any, *, status: str) -> None:
    _require(isinstance(value, list), "holds must be an array")
    if status == HOLD:
        _require(bool(value), "HOLD evidence requires at least one hold")
    else:
        _require(not value, "COMPLETE evidence must not contain holds")
    fields: set[str] = set()
    for index, item in enumerate(value):
        hold = _mapping(item, f"holds[{index}]")
        _exact_keys(hold, HOLD_KEYS, f"holds[{index}]")
        field = _identifier(hold["field"], f"holds[{index}].field")
        _require(field not in fields, "holds contains duplicate fields")
        fields.add(field)
        _require(hold["status"] == "NOT_OBSERVED", f"holds[{index}].status must be NOT_OBSERVED")
        _string(hold["reason"], f"holds[{index}].reason")


def _validate_observations(
    observations_value: Any,
    *,
    evidence_class: str,
    status: str,
) -> None:
    observations = _mapping(observations_value, "observations")
    _require(bool(observations), "observations must not be empty")
    if status == COMPLETE:
        for field in sorted(CLASS_REQUIRED_TRUE[evidence_class]):
            _require(observations.get(field) is True, f"observations.{field} must be true")
        for field in sorted(CLASS_REQUIRED_ZERO[evidence_class]):
            _require(
                observations.get(field) == 0 and not isinstance(observations.get(field), bool),
                f"observations.{field} must be integer zero",
            )


def _validate_authorization(value: Any, *, evidence_class: str, status: str) -> None:
    authorization = _mapping(value, "authorization")
    _exact_keys(authorization, AUTHORIZATION_KEYS, "authorization")
    _identifier(authorization["authority"], "authorization.authority")
    _string(authorization["scope"], "authorization.scope")
    _identifier(authorization["evidence_id"], "authorization.evidence_id")
    _require(isinstance(authorization["revoked"], bool), "authorization.revoked must be boolean")
    _timestamp(authorization["expires_at"], "authorization.expires_at")
    expected = "APPROVED" if status == COMPLETE else "PENDING"
    _require(authorization["status"] == expected, f"authorization.status must be {expected}")
    if status == COMPLETE:
        _require(authorization["revoked"] is False, "complete evidence authorization is revoked")
    if evidence_class == "signed_release" and status == COMPLETE:
        _require("release" in authorization["scope"].lower(), "L6 authorization scope must name release")


def load_gap_specs(path: Path) -> dict[str, GapSpec]:
    register = strict_json_file(path, "G1 gap register")
    _require(register.get("schema") == GAP_REGISTER_SCHEMA, "gap register schema is unsupported")
    _require(register.get("program_revision") == PROGRAM_REVISION, "gap register program revision drifted")
    gaps = register.get("gaps")
    _require(isinstance(gaps, list) and bool(gaps), "gap register gaps must be a non-empty array")
    result: dict[str, GapSpec] = {}
    for index, item in enumerate(gaps):
        gap = _mapping(item, f"gap register.gaps[{index}]")
        gap_id = _identifier(gap.get("id"), f"gap register.gaps[{index}].id")
        _require(gap_id not in result, f"duplicate gap {gap_id}")
        exit_level = _string(gap.get("exit_level"), f"{gap_id}.exit_level")
        _require(exit_level in LEVEL_ORDER, f"{gap_id}.exit_level is unsupported")
        evidence_class = GAP_EVIDENCE_CLASS.get(gap_id)
        _require(evidence_class is not None, f"no evidence class is registered for {gap_id}")
        result[gap_id] = GapSpec(
            gap_id=gap_id,
            status=_string(gap.get("status"), f"{gap_id}.status"),
            exit_level=exit_level,
            evidence_class=evidence_class,
        )
    _require(set(result) == set(GAP_EVIDENCE_CLASS), "gap evidence-class map drifted from register")
    return result
