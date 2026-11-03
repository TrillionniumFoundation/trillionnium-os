"""Shared mechanism-only helpers for the Trillionnium owner-open MCP bridge."""
from __future__ import annotations

import base64
from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any

MAX_LINE_BYTES = 1024 * 1024
MAX_RESULT_BYTES = 1024 * 1024
ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,256}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class DuplicateMember(ValueError):
    pass


class InvalidArguments(ValueError):
    pass


class HostProtocolError(RuntimeError):
    def __init__(self, message: str, *, frame: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.frame = frame


class HostUnavailable(RuntimeError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateMember(f"duplicate key {key}")
        result[key] = value
    return result


def strict_json(raw: bytes, *, label: str, maximum: int = MAX_LINE_BYTES) -> Any:
    if not raw or len(raw) > maximum:
        raise ValueError(f"{label} is empty or exceeds {maximum} bytes")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateMember) as error:
        raise ValueError(f"invalid {label}: {error}") from error


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InvalidArguments(f"{label} must be an object")
    return value


def require_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None:
        raise InvalidArguments(f"{label} is empty, oversized, or malformed")
    return value


def optional_sha256(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise InvalidArguments(f"{label} must be a lowercase SHA-256")
    return value


def require_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidArguments(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise InvalidArguments(f"{label} must be between {minimum} and {maximum}")
    return value


def job_bytes(value: Any) -> Any:
    if isinstance(value, str):
        if "\0" in value:
            raise InvalidArguments("UTF-8 job data contains NUL")
        return value
    obj = require_object(value, "data")
    if set(obj) != {"encoding", "data"}:
        raise InvalidArguments("data object requires exactly encoding and data")
    encoding, data = obj.get("encoding"), obj.get("data")
    if encoding not in {"utf8", "utf-8", "base64"} or not isinstance(data, str):
        raise InvalidArguments("data encoding must be utf8 or base64")
    if encoding == "base64":
        try:
            base64.b64decode(data, validate=True)
        except ValueError as error:
            raise InvalidArguments(f"data is not canonical base64: {error}") from error
    elif "\0" in data:
        raise InvalidArguments("UTF-8 job data contains NUL")
    return {"encoding": encoding, "data": data}


@dataclass(frozen=True)
class Scope:
    session_id: str
    profile_id: str
    task_id: str
    turn_id: str
    turn_stream_id: str

    def payload(self) -> dict[str, str]:
        return {
            "session_id": self.session_id,
            "profile_id": self.profile_id,
            "task_id": self.task_id,
            "turn_id": self.turn_id,
            "turn_stream_id": self.turn_stream_id,
        }


def contains_terminal(value: Any) -> bool:
    if isinstance(value, dict):
        if value.get("kind") == "job.result" or value.get("terminal") is True:
            return True
        if value.get("terminal_kind") is not None:
            return True
        if value.get("state") in {"terminal", "Terminal"}:
            return True
        return any(contains_terminal(item) for item in value.values())
    return isinstance(value, list) and any(contains_terminal(item) for item in value)


def mcp_result(value: dict[str, Any], *, error: bool = False) -> dict[str, Any]:
    encoded = canonical(value)
    if len(encoded) > MAX_RESULT_BYTES:
        value = {
            "schema": "org.trillionnium.owner-open.mcp-job-result.v1",
            "is_truncated": True,
            "error": "result exceeds MCP byte bound; inspect with a narrower cursor page",
            "automatic_redispatch": False,
        }
        encoded, error = canonical(value), True
    return {
        "content": [{"type": "text", "text": encoded.decode("utf-8")}],
        "structuredContent": value,
        "isError": error,
    }
