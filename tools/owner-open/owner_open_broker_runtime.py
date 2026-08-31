"""Bounded client/request mechanics for the owner-open connection broker."""
from __future__ import annotations

from dataclasses import dataclass, field
import queue
import socket
import struct
import threading
from typing import Any

from owner_open_broker_common import BrokerError, canonical

CORRELATION_FIELDS = (
    "session_id",
    "profile_id",
    "task_id",
    "turn_id",
    "turn_stream_id",
    "call_id",
    "job_id",
    "operation_id",
    "attachment_id",
    "request_sha256",
)


def _optional_string(
    mapping: dict[str, Any],
    name: str,
    *,
    location: str,
) -> str | None:
    """Read an optional correlation member without silently coercing it.

    Correlation is intentionally opaque, but when a protocol-defined member is
    present it is still an identifier and therefore must be a string (or an
    explicit null omission).  Ignoring a non-string top-level value would let a
    payload copy win implicitly, which is the same ambiguity as a conflicting
    mirror.
    """

    if name not in mapping:
        return None
    value = mapping[name]
    if value is None:
        return None
    if not isinstance(value, str):
        raise BrokerError(f"{location}.{name} must be a string or null")
    return value


def frame_value(frame: dict[str, Any], name: str) -> str | None:
    """Return one correlation value, rejecting conflicting mirrors/aliases.

    The wire contract permits correlation fields in the envelope and in the
    payload, but they are mirrors rather than precedence layers.  In
    particular, ``stream_id`` is an alias for ``turn_stream_id``.  Never choose
    one copy when two supplied values disagree; fail closed instead.
    """

    names = ("turn_stream_id", "stream_id") if name in {
        "turn_stream_id",
        "stream_id",
    } else (name,)
    values: list[str] = []
    for member in names:
        value = _optional_string(frame, member, location="frame")
        if value is not None:
            values.append(value)
    payload = frame.get("payload")
    if isinstance(payload, dict):
        for member in names:
            value = _optional_string(payload, member, location="frame.payload")
            if value is not None:
                values.append(value)
    if values and any(value != values[0] for value in values[1:]):
        raise BrokerError(f"conflicting mirrored correlation field {name}")
    return values[0] if values else None


def frame_job_id(frame: dict[str, Any]) -> str | None:
    return frame_value(frame, "job_id")


def frame_correlation(frame: dict[str, Any]) -> dict[str, str | None]:
    return {name: frame_value(frame, name) for name in CORRELATION_FIELDS}


def correlation_matches(request: "Request", frame: dict[str, Any]) -> bool:
    actual = frame_correlation(frame)
    if request.expected_job_id is not None and actual["job_id"] != request.expected_job_id:
        return False
    for name, expected in request.correlation.items():
        if expected is not None and actual.get(name) != expected:
            return False
    return True


def response_matches(request: "Request", frame: dict[str, Any]) -> bool:
    kind = frame.get("kind")
    return kind in request.expected_kinds and correlation_matches(request, frame)


def peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise BrokerError("SO_PEERCRED is required for the foundation broker")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    return struct.unpack("3i", raw)


@dataclass
class Client:
    client_id: str
    connection: socket.socket
    pid: int
    uid: int
    gid: int
    maximum_bytes: int
    maximum_frames: int
    queue: queue.Queue[bytes] = field(init=False)
    queued_bytes: int = 0
    last_client_seq: int | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)
    closed: threading.Event = field(default_factory=threading.Event)

    def __post_init__(self) -> None:
        self.queue = queue.Queue(maxsize=self.maximum_frames)

    def accept_sequence(self, value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise BrokerError("client frame seq must be a nonnegative integer")
        if self.last_client_seq is not None and value != self.last_client_seq + 1:
            raise BrokerError(
                f"client frame seq {value} does not follow {self.last_client_seq}"
            )
        self.last_client_seq = value
        return value

    def enqueue(self, value: dict[str, Any]) -> bool:
        encoded = canonical(value) + b"\n"
        with self.lock:
            if self.closed.is_set() or self.queued_bytes + len(encoded) > self.maximum_bytes:
                return False
            try:
                self.queue.put_nowait(encoded)
            except queue.Full:
                return False
            self.queued_bytes += len(encoded)
            return True

    def writer(self) -> None:
        try:
            while not self.closed.is_set():
                try:
                    encoded = self.queue.get(timeout=0.1)
                except queue.Empty:
                    continue
                with self.lock:
                    self.queued_bytes -= len(encoded)
                try:
                    self.connection.sendall(encoded)
                except OSError:
                    return
        finally:
            self.close()

    def close(self) -> None:
        if self.closed.is_set():
            return
        self.closed.set()
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.connection.close()
        except OSError:
            pass


@dataclass
class Request:
    owner_id: str
    request_id: str
    frame: dict[str, Any]
    expected_kinds: frozenset[str]
    expected_job_id: str | None
    timeout_ms: int
    client_seq: int
    upstream_seq: int
    request_sha256: str
    correlation: dict[str, str | None]
    audit_binding: Any
