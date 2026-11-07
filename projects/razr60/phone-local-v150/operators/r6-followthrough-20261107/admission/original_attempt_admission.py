#!/usr/bin/env python3
"""Read-only, source-only admission hold for the exact unresolved R6 bound02.

This reviewed blocker register is NOT an enumeration of the runtime's jobs.
There is intentionally no disposition/override/force flag in this candidate.
Removing a record, changing a successor nonce, or asserting a terminal cannot
turn the historical unknown into permission. A future disposition requires a
separately reviewed original-evidence verifier and a new source derivation.
"""
import hashlib
import json
import os
from pathlib import Path
import stat

REGISTER_NAME = "ORIGINAL-ATTEMPTS.json"
REGISTER_BYTES = 2943
REGISTER_SHA256 = "331e135d43cbe8dc8fa4136ff2b1af40a2fb2fab1e83ed71533e2d29df3dde70"
SCHEMA = "hepta.r6.known-original-attempts.v1"
DECISION_SCHEMA = "hepta.r6.original-attempt-admission.v1"
REGISTER_KIND = "FIXED_REVIEWED_BLOCKERS_NOT_RUNTIME_CENSUS"
MAX_REGISTER_BYTES = 65536
_STAT_KEYS = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
              "st_size", "st_mtime_ns", "st_ctime_ns")
_IDENTITY = (
    ("host", "mac"),
    ("job_id", "1a1b3420986-fc05-8183"),
    ("request_digest", "bd0a05f5d0e196efe71a3e18012d241a11214cca994c6fc240b9a70206485629"),
    ("plan_sha256", "0fbfd5aa0ed86e0bad846f2e541c3117ee1c7a46c98af7000c96f2e7d25a4bfa"),
    ("plan_bytes", 4842),
    ("owner_request_sha256", "b25d5c139aebdec8a222ca4298e91cd57500b0836c0c9f1629cb4ce769ad6d3f"),
    ("owner_request_bytes", 317),
    ("nonce", "731dc46ccaad6e5717306d0c5f029a82"),
    ("label", "root-r10-neg01-fc33-r6-bound02"),
    ("case_id", "NEG-01"),
    ("boot_id", "f8019f83-20a7-4f18-bea1-51c980621e4d"),
    ("profile_id", "owner-open"),
    ("session_id", "session-ee897738-8fc2-4d3e-a916-5fe368b340ef"),
    ("package_sha256", "270357b7649af61414d31580b3c1eaddc47174bd1bac3c8adfc02934a92c8cf5"),
    ("combination_sha256", "7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411"),
    ("root_source_sha256", "53c2e7c26c960d76ac5d3201420d33f13fb06c241d30d40fc7b2b7577e690257"),
    ("root_source_bytes", 78567),
)
_EFFECT_FIELDS = ("phone_calls", "native_send_attempts", "model_requests",
                  "root_fixture_attempts", "ui_mutation_attempts",
                  "resource_mutation_attempts")


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                       allow_nan=False) + "\n").encode("utf-8")


def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(_):
        raise ValueError("nonfinite JSON number")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject_constant)


def _same(left, right):
    # JSON byte comparison also distinguishes false from 0, unlike == in Python.
    try:
        return encoded(left) == encoded(right)
    except (TypeError, ValueError, OverflowError, RecursionError):
        return False


def known_identity():
    return dict(_IDENTITY)


def known_observation():
    return {
        "original_launch_state": "launch_unknown",
        "original_task_outcome": "UNKNOWN_UNCHANGED",
        "original_terminal": None,
        "complete_original_output": None,
        "remote_owner": "UNRESOLVED",
        "producer_fencing_proven": False,
        "effect_counts": {name: None for name in _EFFECT_FIELDS},
        "draft_outcome": "UNRESOLVED",
        "cancellation_observation": {
            "request_attempts": 1,
            "observed_result": "TIMEOUT_NO_CANCELLATION_RECEIPT",
            "response_original": {
                "bytes": 182,
                "sha256": "5f0646f9deefaa026258095a3fe49ef5defc1475ef87bec6119962d1dd4fc639",
            },
            "cancellation_proven": False,
            "signals_sent": None,
            "termination_proven": False,
        },
    }


def known_pending_draft():
    # This is a separate original, not evidence about bound02 execution/counts.
    return {
        "label": "root-r10-neg01-fc33-r6-bound01",
        "nonce": "5f94c6a88805eefb0e2320cae5265d46",
        "sender_result_original": {
            "bytes": 704,
            "sha256": "09eb6d6a460c893f7da5ad6a0fbb383cbffb5d29f78a5ba7b373520fd92ed00b",
        },
        "observed_state": "PRE_SEND_OR_ACTOR_FAILURE",
        "send_attempt_count": 0,
        "draft_restore": {
            "state": "RESTORE_NOT_AUTOMATED_INPUT_OUTCOME_UNCONFIRMED",
            "restore_attempts": 0,
            "original_draft_submitted": False,
        },
        "ui_effect_count": None,
        "current_draft_verified": False,
        "accepted_draft_disposition": None,
    }


def required_register():
    """The fixed source-review record; it cannot itself prove a disposition."""
    return {
        "schema": SCHEMA,
        "register_kind": REGISTER_KIND,
        "attempts": [{
            "identity": known_identity(),
            "observation": known_observation(),
            "accepted_disposition": None,
        }],
        "independent_pending_drafts": [known_pending_draft()],
    }


def evaluate(document, *, evidence_errors=()):
    """Pure decision shared by runtime entry guards and the CURRENT checker.

    A caller may provide observations, never authority to bypass this hold.
    Unknowns below come from the retained known original, not a caller's flags.
    """
    errors = list(evidence_errors)
    required = required_register()
    if type(document) is not dict:
        errors.append("KNOWN_ATTEMPT_REGISTER_MISSING_OR_INVALID")
    else:
        if set(document) != set(required) or document.get("schema") != SCHEMA:
            errors.append("REGISTER_SCHEMA_OR_FIELDS_DIFFER")
        if document.get("register_kind") != REGISTER_KIND:
            errors.append("REGISTER_AUTHORITY_DIFFERS")
        attempts = document.get("attempts")
        if type(attempts) is not list or len(attempts) != 1:
            errors.append("MANDATORY_BOUND02_RECORD_MISSING_OR_DUPLICATED")
        else:
            row = attempts[0]
            if type(row) is not dict or set(row) != {"identity", "observation", "accepted_disposition"}:
                errors.append("BOUND02_RECORD_FIELDS_DIFFER")
            if type(row) is not dict or not _same(row.get("identity"), known_identity()):
                errors.append("BOUND02_ORIGINAL_IDENTITY_DIFFERS")
            if type(row) is not dict or not _same(row.get("observation"), known_observation()):
                errors.append("ORIGINAL_UNKNOWN_OBSERVATION_WAS_REWRITTEN")
            if type(row) is dict and row.get("accepted_disposition") is not None:
                errors.append("NO_BOUND02_DISPOSITION_VERIFIER_IN_THIS_SOURCE")
        if not _same(document.get("independent_pending_drafts"), [known_pending_draft()]):
            errors.append("INDEPENDENT_BOUND01_DRAFT_RECORD_DIFFERS")
    # No positive eligibility path exists in this source-only guard candidate.
    return {
        "schema": DECISION_SCHEMA,
        "state": "BLOCKED_ORIGINAL_ATTEMPT_UNRESOLVED",
        "source_only": True,
        "successor_execution_eligible": False,
        "accepted_disposition_verifier": None,
        "known_original": {
            "identity": known_identity(),
            "observation": known_observation(),
        },
        "independent_pending_drafts": [known_pending_draft()],
        "required_register": {"bytes": REGISTER_BYTES, "sha256": REGISTER_SHA256},
        "evidence_valid": not errors,
        "evidence_errors": sorted(set(errors)),
        "blockers": [
            "ORIGINAL_BOUND02_OUTCOME_UNRESOLVED",
            "ORIGINAL_BOUND02_PRODUCER_FENCING_UNPROVEN",
            "BOUND01_DRAFT_RECONCILIATION_UNCONFIRMED",
            "NO_BOUND02_DISPOSITION_VERIFIER_IN_THIS_SOURCE",
        ],
        "unknown_counts_are_zero": False,
        "missing_paths_establish_no_execution": False,
        "recovery_results_are_substitutable_between_originals": False,
    }


def read_stable(path, limit=MAX_REGISTER_BYTES):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("canonical original required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not (stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 < before.st_size <= limit):
            raise ValueError("bounded single-link original required")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        after, named = os.fstat(fd), path.lstat()
        if len(raw) != before.st_size or any(
            getattr(before, key) != getattr(after, key)
            or getattr(before, key) != getattr(named, key)
            for key in _STAT_KEYS
        ):
            raise ValueError("original changed while reading")
        return raw
    finally:
        os.close(fd)


def evaluate_current(register_path=None):
    path = (Path(__file__).resolve().with_name(REGISTER_NAME)
            if register_path is None else Path(register_path).absolute())
    try:
        raw = read_stable(path)
    except (OSError, ValueError, RuntimeError):
        return evaluate(None, evidence_errors=("KNOWN_ATTEMPT_REGISTER_UNAVAILABLE",))
    errors = []
    if len(raw) != REGISTER_BYTES or hashlib.sha256(raw).hexdigest() != REGISTER_SHA256:
        errors.append("KNOWN_ATTEMPT_REGISTER_PIN_DIFFERS")
    try:
        document = strict(raw)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return evaluate(None, evidence_errors=errors + ["KNOWN_ATTEMPT_REGISTER_JSON_INVALID"])
    return evaluate(document, evidence_errors=errors)


class AdmissionBlocked(RuntimeError):
    def __init__(self, decision, stage):
        self.decision = decision
        self.stage = stage
        super().__init__("BLOCKED_ORIGINAL_ATTEMPT_UNRESOLVED: " + stage
                         + "; original job 1a1b3420986-fc05-8183 remains unknown")


def require_successor_admission(*, stage):
    """No caller-controlled eligibility, replacement identity, or force input."""
    raise AdmissionBlocked(evaluate_current(), stage)


def main():
    print(encoded(evaluate_current()).decode("utf-8"), end="")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
