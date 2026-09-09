#!/usr/bin/env python3
"""Android build-host consumer for the exact shared module-contract vectors."""
from __future__ import annotations
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
MAX_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 32
MAX_U64 = (1 << 64) - 1
SHA64 = re.compile(r"^[0-9a-f]{64}$")
STATES = {
    "RECEIVED", "VALIDATED", "CAPACITY_RESERVED", "ACCEPTED_DURABLE",
    "EFFECT_ATTEMPTING", "EFFECT_STARTED_OBSERVED", "TERMINAL_OBSERVED",
    "TERMINAL_DURABLE", "DELIVERY_PENDING", "DELIVERED", "ACKNOWLEDGED",
    "REJECTED_BEFORE_EFFECT", "UNKNOWN_RECONCILIATION_REQUIRED", "FENCED",
    "CLOSED", "STATELESS",
}
ERROR_CLASSES = {
    "REJECTED_BEFORE_EFFECT", "TRANSIENT_BEFORE_EFFECT", "EFFECT_UNCERTAIN",
    "TERMINAL_FAILURE", "INTERNAL_INVARIANT",
}
RETRY_DISPOSITIONS = {
    "MAY_RETRY_BEFORE_EFFECT",
    "RECONCILE_REQUIRED_NO_AUTOMATIC_REDISPATCH",
    "DO_NOT_RETRY",
}


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"duplicate member: {key}")
        result[key] = value
    return result


def bad(value):
    raise ValueError(f"nonfinite: {value}")


def depth(value):
    if isinstance(value, dict):
        return 1 + max((depth(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((depth(item) for item in value), default=0)
    return 1


def load(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"not a regular vector: {path}")
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError("vector byte bound differs")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=bad)
    if depth(value) > MAX_DEPTH:
        raise ValueError("vector depth bound differs")
    return value


def text(value, maximum):
    return (
        isinstance(value, str)
        and bool(value)
        and len(value.encode("utf-8")) <= maximum
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
    )


def u64(value):
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_U64


def validate(value, kind, module_id, label):
    required = {
        "api": {"schema","module_id","operation_id","request_digest","ordering_key","host_epoch","writer_epoch","fencing_token","payload"},
        "state": {"schema","module_id","operation_id","request_digest","state","host_epoch","writer_epoch","fencing_token","durable_sequence","monotonic_ns","payload"},
        "errors": {"schema","module_id","operation_id","request_digest","code","class","retry_disposition","effect_uncertain","original_cause"},
    }[kind]
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("field set differs")
    if value["schema"] != label or value["module_id"] != module_id or not module_id.startswith("MOD-"):
        raise ValueError("contract identity differs")
    if not text(value["operation_id"], 256):
        raise ValueError("operation identity differs")
    if not isinstance(value["request_digest"], str) or not SHA64.fullmatch(value["request_digest"]):
        raise ValueError("digest differs")
    if kind in {"api", "state"}:
        if not isinstance(value["payload"], dict) or len(value["payload"]) > 64:
            raise ValueError("payload differs")
        if not u64(value["host_epoch"]) or not u64(value["writer_epoch"]):
            raise ValueError("epoch differs")
        if not text(value["fencing_token"], 512):
            raise ValueError("fencing token differs")
    if kind == "api":
        if not text(value["ordering_key"], 512):
            raise ValueError("ordering key differs")
    elif kind == "state":
        if value["state"] not in STATES:
            raise ValueError("state differs")
        if not u64(value["durable_sequence"]) or not u64(value["monotonic_ns"]):
            raise ValueError("state ordering differs")
    else:
        if not text(value["code"], 128) or not text(value["original_cause"], 4096):
            raise ValueError("error text differs")
        if value["class"] not in ERROR_CLASSES or value["retry_disposition"] not in RETRY_DISPOSITIONS:
            raise ValueError("error enum differs")
        if not isinstance(value["effect_uncertain"], bool):
            raise ValueError("effect uncertainty type differs")
        uncertain = value["class"] == "EFFECT_UNCERTAIN"
        reconcile = value["retry_disposition"] == "RECONCILE_REQUIRED_NO_AUTOMATIC_REDISPATCH"
        if uncertain != value["effect_uncertain"] or reconcile != value["effect_uncertain"]:
            raise ValueError("uncertainty semantics differ")


def main():
    valid = invalid = 0
    for directory in sorted((ROOT / "schemas/modules").iterdir()):
        if not directory.is_dir() or directory.name == "_shared":
            continue
        compatibility = load(directory / "compatibility.json")
        module_id = compatibility["module_id"]
        for kind in ("api", "state", "errors"):
            label = compatibility["contracts"][kind]["logical_label"]
            validate(load(directory / "golden/valid" / f"{kind}.json"), kind, module_id, label)
            valid += 1
        for path in sorted((directory / "golden/invalid").glob("*.json")):
            kind = path.name.split("-", 1)[0]
            try:
                validate(load(path), kind, module_id, compatibility["contracts"][kind]["logical_label"])
            except Exception:
                invalid += 1
            else:
                raise SystemExit(f"invalid Android vector accepted: {path}")
    if valid == 0 or invalid == 0:
        raise SystemExit("vector set is empty")
    print(json.dumps({"android_build_host_valid":valid,"android_build_host_invalid":invalid,"public_release":False},sort_keys=True))


if __name__ == "__main__":
    main()
