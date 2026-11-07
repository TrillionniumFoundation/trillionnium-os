#!/usr/bin/env python3
"""Recompute the fixed admission decision and check the project's CURRENT.json.

Exit 2 means a consistent, blocked CURRENT; exit 3 means invalid/missing evidence
or an inconsistent CURRENT. This source-only checker never returns eligibility.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import types

GUARD_BYTES = 10422
GUARD_SHA256 = "e268d050959228423003717a63e57106d608cd763d5d977b3f376982e8e9da0b"


def load_guard():
    path = Path(__file__).resolve().with_name("original_attempt_admission.py")
    if path.resolve(strict=True) != path:
        raise ValueError("canonical admission guard required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not (stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size == GUARD_BYTES and 0 < GUARD_BYTES <= 65536):
            raise ValueError("exact admission guard size/type required")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(GUARD_BYTES + 1)
        after, named = os.fstat(fd), path.lstat()
        keys = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                "st_size", "st_mtime_ns", "st_ctime_ns")
        if (len(raw) != GUARD_BYTES or hashlib.sha256(raw).hexdigest() != GUARD_SHA256
                or any(getattr(before, k) != getattr(after, k)
                       or getattr(before, k) != getattr(named, k) for k in keys)):
            raise ValueError("exact admission guard original/pin required")
    finally:
        os.close(fd)
    module = types.ModuleType("reviewed_original_attempt_admission")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def check_current(current_path):
    guard = load_guard()
    decision = guard.evaluate_current()
    errors = []
    try:
        current = guard.strict(guard.read_stable(Path(current_path).absolute(), 1048576))
    except (OSError, ValueError, RuntimeError, TypeError, RecursionError, UnicodeError):
        current = None
        errors.append("CURRENT_UNAVAILABLE_OR_INVALID")
    if type(current) is not dict:
        errors.append("CURRENT_OBJECT_REQUIRED")
    else:
        if current.get("execution_eligible") is not False:
            errors.append("CURRENT_EXECUTION_ELIGIBILITY_DIFFERS")
        if not guard._same(current.get("original_attempt_admission"), decision):
            errors.append("CURRENT_ADMISSION_DECISION_DIFFERS")
    if decision["evidence_valid"] is not True:
        errors.append("ADMISSION_REGISTER_INVALID_OR_MISSING")
    result = {
        "schema": "hepta.r6.current-consistency-check.v1",
        "state": "INCONSISTENT_OR_UNVERIFIABLE_CURRENT" if errors else "CONSISTENT_BLOCKED_CURRENT",
        "source_only": True,
        "execution_eligible": False,
        "current_document_valid": not errors,
        "errors": sorted(set(errors)),
        "original_attempt_admission": decision,
    }
    return result, 3 if errors else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current", type=Path, required=True)
    args = parser.parse_args()
    try:
        result, status = check_current(args.current)
    except (OSError, ValueError, RuntimeError, TypeError, RecursionError, UnicodeError):
        result = {
            "schema": "hepta.r6.current-consistency-check.v1",
            "state": "BLOCKED_ADMISSION_GUARD_UNAVAILABLE_OR_DIFFERENT",
            "source_only": True,
            "execution_eligible": False,
            "current_document_valid": False,
        }
        status = 3
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
