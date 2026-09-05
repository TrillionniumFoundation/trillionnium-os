"""Shared fail-closed primitives for the G1 pull-request aggregate."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
import re
from typing import Any, Mapping


PROGRAM_REVISION = "2026-08-31-g1"
REPORT_SCHEMA = "org.trillionnium.g1-pr-workflow-aggregate.v1"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REPO_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$"
)
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024

REQUIRED_PROTECTION_CONTEXTS = frozenset(
    {
        "L1 graph, documentation, broker and MCP source closure",
        "L1 Rust 1.93 selected Host, job, flow and recovery closure",
        "L1 exact-source-head aggregate candidate",
        "L1 protected-main and exact-head independent-review readiness",
    }
)


class AggregateError(RuntimeError):
    """The live PR/workflow/artifact set is incomplete, stale, or ambiguous."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AggregateError(message)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    _require(isinstance(value, Mapping), f"{label} is not an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    _require(isinstance(value, list), f"{label} is not an array")
    return value


def _positive_int(value: Any, label: str) -> int:
    _require(type(value) is int and value > 0, f"{label} must be a positive integer")
    return value


def _git_sha(value: Any, label: str) -> str:
    _require(isinstance(value, str) and SHA_RE.fullmatch(value) is not None, f"{label} is not a 40-character lowercase Git SHA")
    return value


def _sha256(value: Any, label: str) -> str:
    _require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None, f"{label} is not a lowercase SHA-256")
    return value


def _identifier(value: Any, label: str) -> str:
    _require(isinstance(value, str) and value and "\x00" not in value, f"{label} is empty or contains NUL")
    _require(len(value.encode("utf-8")) <= 512, f"{label} is too long")
    return value


def _repo(value: Any, label: str = "repository") -> str:
    _require(isinstance(value, str) and REPO_RE.fullmatch(value) is not None and ".." not in value, f"{label} must use owner/repository form")
    return value


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AggregateError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise AggregateError(f"non-finite JSON number {value}")


def _finite_json_float(text: str) -> float:
    value = float(text)
    _require(math.isfinite(value), "non-finite JSON floating-point value")
    return value


def _strict_json(raw: bytes, label: str) -> Any:
    _require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_MEMBER_BYTES,
             f"{label} exceeds its JSON byte bound or is empty")
    try:
        text = raw.decode("utf-8")
        depth, quoted, escaped = 0, False, False
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                _require(depth <= 64, "JSON nesting exceeds 64")
            elif char in "]}":
                depth -= 1
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=_reject_nonfinite,
            parse_float=_finite_json_float,
        )
    except (UnicodeDecodeError, ValueError, RecursionError, AggregateError) as error:
        raise AggregateError(f"{label} is not strict JSON: {str(error)[:512]}") from error


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _parse_time(value: Any, label: str) -> datetime:
    _require(isinstance(value, str) and value, f"{label} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AggregateError(f"{label} is not an ISO-8601 timestamp") from error
    _require(parsed.tzinfo is not None, f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


