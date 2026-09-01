"""Bounded client/request mechanics for the owner-open connection broker."""
from __future__ import annotations

from dataclasses import dataclass, field
import copy
import math
import os
import queue
import re
import selectors
import socket
import struct
import threading
import time
from typing import Any

from owner_open_broker_common import BrokerError, canonical, require_id

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

# A broker worker must never remain indefinitely in a pipe or client-socket
# write.  The bound is deliberately independent of the Host's semantic
# timeout: a partial write can have already crossed the effect boundary, so a
# timeout is reported as an uncertain upstream state rather than retried.
BROKER_WRITE_TIMEOUT_SECONDS = 5.0

# Transport members describe one wire hop, not the requested effect.  They
# must be excluded from the request identity so an exact reconnect replay can
# use a fresh connection-local sequence without becoming a new effect.  The
# plain ``request_sha256`` member is intentionally *not* volatile: for job
# requests it is a semantic generation binding and changing it must create a
# request-id conflict rather than replaying a result for a different job.
VOLATILE_REQUEST_FIELDS = frozenset(
    {
        "seq",
        "client_seq",
        "host_seq",
        "frame_sha256",
        "event_id",
        "connection_id",
        "server_request_id",
    }
)

BROKER_RESPONSE_DIRECTION = "host_to_client"
BROKER_REQUEST_ID_FIELD = "broker_request_id"
BROKER_REQUEST_SHA256_FIELD = "broker_request_sha256"
BROKER_REQUEST_UPSTREAM_SEQ_FIELD = "broker_request_upstream_seq"
BROKER_ENVELOPE_FIELDS = (
    BROKER_REQUEST_ID_FIELD,
    BROKER_REQUEST_SHA256_FIELD,
    BROKER_REQUEST_UPSTREAM_SEQ_FIELD,
)
# These members are authored by the broker when it forwards a request or
# returns broker-local metadata.  Accepting a caller-supplied value would make
# the admitted semantic digest differ from the bytes actually forwarded after
# the broker overwrites its envelope, while a payload mirror could poison Host
# correlation.  Reject them at both protocol envelope levels instead.
BROKER_OWNED_REQUEST_FIELDS = frozenset(
    {
        "broker_epoch",
        "broker_response_connection_id",
        "broker_request_id",
        "broker_request_upstream_seq",
        "broker_request_downstream_seq",
        "broker_request_kind",
        "broker_request_sha256",
        "broker_ordering_key",
    }
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _alias_value(
    frame: dict[str, Any],
    payload: dict[str, Any],
    aliases: tuple[str, ...],
) -> str | None:
    """Resolve an envelope/payload alias without precedence ambiguity."""

    values: list[str] = []
    for mapping, location in ((frame, "frame"), (payload, "frame.payload")):
        for name in aliases:
            value = _optional_string(mapping, name, location=location)
            if value is not None:
                values.append(value)
    if values and any(value != values[0] for value in values[1:]):
        raise BrokerError(f"conflicting mirrored correlation field {aliases[0]}")
    return values[0] if values else None


def canonical_request_frame(frame: dict[str, Any]) -> dict[str, Any]:
    """Return the reconnect-stable semantic portion of a request frame.

    Correlation fields may be mirrored at the envelope and payload levels;
    equivalent mirrors collapse to one payload spelling while disagreements
    fail closed.  Sequence, connection and caller-supplied digest fields are
    observations of the transport hop and never participate in the effect
    digest.
    """

    if not isinstance(frame, dict):
        raise BrokerError("request frame must be an object")
    raw_payload = frame.get("payload")
    if not isinstance(raw_payload, dict):
        raise BrokerError("request frame payload must be an object")
    for mapping, location in ((frame, "frame"), (raw_payload, "frame.payload")):
        supplied = sorted(BROKER_OWNED_REQUEST_FIELDS.intersection(mapping))
        if supplied:
            raise BrokerError(
                f"{location}.{supplied[0]} is broker-owned request metadata"
            )
    payload = copy.deepcopy(raw_payload)
    normalized = {
        key: copy.deepcopy(value)
        for key, value in frame.items()
        if key not in VOLATILE_REQUEST_FIELDS and key != "stream_id"
    }

    # Transport mirrors are not semantic bytes.  If both copies exist, they
    # must agree before either is removed.
    for name in ("direction", "seq", "client_seq", "host_seq"):
        envelope_value = frame.get(name)
        payload_value = payload.get(name)
        if (
            envelope_value is not None
            and payload_value is not None
            and envelope_value != payload_value
        ):
            raise BrokerError(f"conflicting mirrored transport field {name}")
        payload.pop(name, None)
        normalized.pop(name, None)

    # Correlation aliases are semantic context, not separate request bytes.
    for name in CORRELATION_FIELDS:
        aliases = ("turn_stream_id", "stream_id") if name == "turn_stream_id" else (name,)
        value = _alias_value(frame, payload, aliases)
        for alias in aliases:
            normalized.pop(alias, None)
            payload.pop(alias, None)
        if value is not None:
            payload[name] = value

    target = _alias_value(frame, payload, ("target_id", "target"))
    normalized.pop("target", None)
    normalized.pop("target_id", None)
    payload.pop("target", None)
    payload.pop("target_id", None)
    if target is not None:
        payload["target_id"] = target

    for name in VOLATILE_REQUEST_FIELDS:
        normalized.pop(name, None)
        payload.pop(name, None)
    normalized["payload"] = payload
    return normalized


def _write_deadline(timeout_seconds: float, label: str) -> float:
    """Return a finite monotonic deadline for one bounded write operation."""

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ValueError(f"{label} timeout must be a finite positive number")
    return time.monotonic() + float(timeout_seconds)


def _wait_writable(
    selector: selectors.BaseSelector,
    descriptor: int | socket.socket,
    deadline: float,
    label: str,
) -> None:
    """Wait for one writable notification without exceeding ``deadline``."""

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"{label} write deadline exceeded")
        try:
            ready = selector.select(remaining)
        except InterruptedError:
            continue
        if ready:
            return
        raise TimeoutError(f"{label} write deadline exceeded")


def write_all_bounded(
    stream: Any,
    data: bytes,
    *,
    timeout_seconds: float = BROKER_WRITE_TIMEOUT_SECONDS,
    label: str = "stream",
) -> None:
    """Write all bytes to a pipe/file descriptor with finite backpressure.

    ``Popen.stdin.write`` may block forever when an upstream stops consuming
    its pipe.  This helper uses a nonblocking descriptor and readiness polling,
    while restoring the descriptor's original blocking mode before returning.
    A timeout is intentionally an exception: a short write leaves the stream
    framing/effect boundary uncertain and callers must converge conservatively.
    """

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"{label} data must be bytes-like")
    view = memoryview(data)
    if not view:
        return
    try:
        descriptor = stream.fileno()
        if descriptor < 0:
            raise OSError(f"{label} descriptor is closed")
        was_blocking = os.get_blocking(descriptor)
    except (AttributeError, OSError, ValueError) as error:
        raise OSError(f"{label} descriptor is unavailable") from error
    deadline = _write_deadline(timeout_seconds, label)
    selector = selectors.DefaultSelector()
    try:
        os.set_blocking(descriptor, False)
        try:
            selector.register(descriptor, selectors.EVENT_WRITE)
        except (OSError, ValueError) as error:
            raise OSError(f"{label} descriptor cannot be monitored") from error
        offset = 0
        while offset < len(view):
            try:
                written = os.write(descriptor, view[offset:])
            except InterruptedError:
                continue
            except BlockingIOError:
                _wait_writable(selector, descriptor, deadline, label)
                continue
            except BrokenPipeError as error:
                raise OSError(f"{label} closed while writing") from error
            if written <= 0:
                raise OSError(f"{label} write made no progress")
            offset += written
    finally:
        selector.close()
        try:
            os.set_blocking(descriptor, was_blocking)
        except OSError:
            # The peer may have closed the descriptor concurrently.  Preserve
            # the original write/close error rather than masking it here.
            pass


def send_all_bounded(
    connection: socket.socket,
    data: bytes,
    *,
    timeout_seconds: float = BROKER_WRITE_TIMEOUT_SECONDS,
    label: str = "socket",
) -> None:
    """Send all bytes with finite backpressure without changing reader mode.

    Linux's ``MSG_DONTWAIT`` applies nonblocking semantics to this send call
    only, so the broker's concurrent socket reader remains a normal blocking
    stream.  The readiness wait and total deadline make a stalled client a
    bounded delivery failure instead of a permanently wedged writer thread.
    """

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"{label} data must be bytes-like")
    view = memoryview(data)
    if not view:
        return
    deadline = _write_deadline(timeout_seconds, label)
    selector = selectors.DefaultSelector()
    send_flags = getattr(socket, "MSG_DONTWAIT", 0)
    fallback_blocking: bool | None = None
    try:
        descriptor = connection.fileno()
        if descriptor < 0:
            raise OSError(f"{label} descriptor is closed")
    except (OSError, ValueError) as error:
        raise OSError(f"{label} descriptor is unavailable") from error
    try:
        # Android/Linux exposes MSG_DONTWAIT.  Keep a portable fallback for
        # test hosts that do not, restoring the socket mode in all cases.
        if not send_flags:
            fallback_blocking = connection.getblocking()
            connection.setblocking(False)
        try:
            selector.register(connection, selectors.EVENT_WRITE)
        except (OSError, ValueError) as error:
            raise OSError(f"{label} descriptor cannot be monitored") from error
        offset = 0
        while offset < len(view):
            try:
                written = connection.send(view[offset:], send_flags)
            except InterruptedError:
                continue
            except BlockingIOError:
                _wait_writable(selector, connection, deadline, label)
                continue
            except (BrokenPipeError, ConnectionResetError) as error:
                raise OSError(f"{label} closed while writing") from error
            if written <= 0:
                raise OSError(f"{label} write made no progress")
            offset += written
    finally:
        selector.close()
        if fallback_blocking is not None:
            try:
                connection.setblocking(fallback_blocking)
            except OSError:
                pass


def _optional_string(
    mapping: dict[str, Any],
    name: str,
    *,
    location: str,
) -> str | None:
    """Read an optional correlation member without silently coercing it."""

    if name not in mapping:
        return None
    value = mapping[name]
    if value is None:
        return None
    if not isinstance(value, str):
        raise BrokerError(f"{location}.{name} must be a string or null")
    return value


def frame_value(frame: dict[str, Any], name: str) -> str | None:
    """Return one correlation value, rejecting conflicting mirrors/aliases."""

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
    try:
        actual = frame_correlation(frame)
    except BrokerError:
        return False
    if request.expected_job_id is not None and actual["job_id"] != request.expected_job_id:
        return False
    for name, expected in request.correlation.items():
        if expected is not None and actual.get(name) != expected:
            return False
    return True


def response_envelope_matches(request: "Request", frame: dict[str, Any]) -> bool:
    """Require the immutable broker dispatch envelope on a direct response."""

    if frame.get("direction") != BROKER_RESPONSE_DIRECTION:
        return False
    payload = frame.get("payload")
    if not isinstance(payload, dict):
        return False
    for name in ("direction", "seq", *BROKER_ENVELOPE_FIELDS):
        if name in payload and payload[name] != frame.get(name):
            return False
    if frame.get(BROKER_REQUEST_ID_FIELD) != request.request_id:
        return False
    if frame.get(BROKER_REQUEST_SHA256_FIELD) != request.request_sha256:
        return False
    response_seq = frame.get("seq")
    if isinstance(response_seq, bool) or not isinstance(response_seq, int) or response_seq < 0:
        return False
    upstream_seq = frame.get(BROKER_REQUEST_UPSTREAM_SEQ_FIELD)
    if (
        isinstance(upstream_seq, bool)
        or not isinstance(upstream_seq, int)
        or upstream_seq != request.upstream_seq
    ):
        return False
    return True


def validate_upstream_frame(frame: dict[str, Any]) -> None:
    """Validate a Host response envelope before it can be broadcast."""

    if not isinstance(frame, dict):
        raise BrokerError("upstream frame must be an object")
    if frame.get("direction") != BROKER_RESPONSE_DIRECTION:
        raise BrokerError("upstream frame direction must be host_to_client")
    payload = frame.get("payload")
    if not isinstance(payload, dict):
        raise BrokerError("upstream frame payload must be an object")
    require_id(frame.get(BROKER_REQUEST_ID_FIELD), BROKER_REQUEST_ID_FIELD)
    request_sha256 = frame.get(BROKER_REQUEST_SHA256_FIELD)
    if not isinstance(request_sha256, str) or SHA256_RE.fullmatch(request_sha256) is None:
        raise BrokerError(
            f"{BROKER_REQUEST_SHA256_FIELD} must be a lowercase SHA-256 digest"
        )
    response_seq = frame.get("seq")
    if isinstance(response_seq, bool) or not isinstance(response_seq, int) or response_seq < 0:
        raise BrokerError("upstream frame seq must be a nonnegative integer")
    upstream_seq = frame.get(BROKER_REQUEST_UPSTREAM_SEQ_FIELD)
    if (
        isinstance(upstream_seq, bool)
        or not isinstance(upstream_seq, int)
        or upstream_seq < 0
    ):
        raise BrokerError(
            f"{BROKER_REQUEST_UPSTREAM_SEQ_FIELD} must be a nonnegative integer"
        )
    for name in ("direction", "seq", *BROKER_ENVELOPE_FIELDS):
        if name in payload and payload[name] != frame.get(name):
            raise BrokerError(f"upstream payload mirror for {name} conflicts")


def response_matches(request: "Request", frame: dict[str, Any]) -> bool:
    kind = frame.get("kind")
    return (
        kind in request.expected_kinds
        and response_envelope_matches(request, frame)
        and correlation_matches(request, frame)
    )


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
                    send_all_bounded(
                        self.connection,
                        encoded,
                        timeout_seconds=BROKER_WRITE_TIMEOUT_SECONDS,
                        label=f"client {self.client_id}",
                    )
                except (OSError, TimeoutError):
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
    ordering_key: str = "legacy-unassigned"
    deadline_monotonic: float = float("inf")
