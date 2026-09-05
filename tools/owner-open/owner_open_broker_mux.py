"""Bounded weighted-fair multi-inflight scheduling for the owner-open broker.

This module is mechanism only.  It never interprets an operation, retries an
accepted request, or converts timeout/disconnect into proof of cancellation.
"""
from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass
import threading
import time
from typing import Any, Callable, Iterable

from owner_open_broker_common import canonical, require_id

MAX_WEIGHT = 1_024
# A request's ordering identity is a complete immutable lineage, not a
# best-effort choice of whichever identifier happens to be present.  The
# selected Host's job protocol defines this scope for every job operation;
# keeping it here (rather than in a caller) makes all broker entry paths use
# the same serialization boundary.
_IDENTITY_SCOPE_FIELDS = (
    "session_id",
    "profile_id",
    "task_id",
    "turn_id",
    "turn_stream_id",
)
_JOB_KINDS = frozenset(
    {
        "job.start",
        "job.inspect",
        "job.wait",
        "job.attach",
        "job.detach",
        "job.write",
        "job.resize",
        "job.close_stdin",
        "job.kill",
    }
)
_JOB_EFFECT_KINDS = frozenset(
    {
        "job.start",
        "job.write",
        "job.resize",
        "job.close_stdin",
        "job.kill",
    }
)
_JOB_ATTACHMENT_KINDS = frozenset({"job.attach", "job.detach"})
_TURN_KINDS = frozenset({"turn.inspect", "turn.cancel"})
_CALL_KINDS = frozenset({"call.inspect", "tool.cancel"})
_IDENTITY_FIELDS = frozenset(
    {
        *_IDENTITY_SCOPE_FIELDS,
        "stream_id",
        "call_id",
        "job_id",
        "operation_id",
        "attachment_id",
    }
)
_ORDERING_KEY_VERSION = "v1"


def _length_delimited_key(parts: Iterable[str]) -> str:
    """Encode an effect lineage as an unambiguous versioned tuple.

    A fixed schema plus UTF-8 byte-length-delimited members avoids collisions
    from separators, escaping and future field aliases.  Hex encoding keeps
    the scheduler key printable while preserving the exact byte tuple.
    """

    encoded = bytearray()
    for part in parts:
        try:
            raw = part.encode("utf-8")
        except UnicodeEncodeError as error:
            raise MuxError("ordering identity contains non-UTF-8 text") from error
        encoded.extend(len(raw).to_bytes(8, "big"))
        encoded.extend(raw)
    return encoded.hex()


def _effect_key(
    family: str,
    scope: dict[str, str],
    extras: tuple[tuple[str, str], ...],
) -> str:
    """Build the versioned key for one complete protocol-family lineage."""

    parts: list[str] = ["effect-lineage", family]
    for name in _IDENTITY_SCOPE_FIELDS:
        parts.extend((name, scope[name]))
    for name, value in extras:
        parts.extend((name, value))
    return f"effect:{_ORDERING_KEY_VERSION}:" + _length_delimited_key(parts)


class MuxError(RuntimeError):
    """The scheduler observed an invalid or ambiguous correlation state."""


@dataclass(frozen=True)
class RetiredRequest:
    upstream_seq: int
    owner_id: str
    request_id: str
    ordering_key: str
    reason: str
    retired_monotonic: float


def _upstream_sequence(frame: dict[str, Any]) -> int | None:
    """Resolve the immutable broker sequence from an upstream frame.

    ``seq`` is the Host response-stream sequence and may be allocated from a
    different domain.  It is never an ownership key.  Only the broker-owned
    ``broker_request_upstream_seq`` can select an accepted request; a host-only
    frame is explicitly unsequenced and remains unowned.
    """

    has_broker_seq = "broker_request_upstream_seq" in frame
    broker_seq = frame.get("broker_request_upstream_seq")
    host_seq = frame.get("seq")
    if host_seq is not None and (
        isinstance(host_seq, bool) or not isinstance(host_seq, int) or host_seq < 0
    ):
        raise MuxError("upstream frame seq must be a nonnegative integer")
    if not has_broker_seq:
        return None
    if isinstance(broker_seq, bool) or not isinstance(broker_seq, int) or broker_seq < 0:
        raise MuxError(
            "upstream broker_request_upstream_seq must be a nonnegative integer"
        )
    return broker_seq


def _optional_string(mapping: dict[str, Any], name: str, location: str) -> str | None:
    if name not in mapping or mapping[name] is None:
        return None
    value = mapping[name]
    if not isinstance(value, str) or not value:
        raise MuxError(f"{location}.{name} must be a non-empty string or null")
    return value


def _identity_value(frame: dict[str, Any], name: str) -> str | None:
    """Resolve one canonical lineage field and all documented mirrors."""

    payload = frame.get("payload")
    payload_mapping = payload if isinstance(payload, dict) else {}
    names = ("turn_stream_id", "stream_id") if name == "turn_stream_id" else (name,)
    values: list[str] = []
    for mapping, location in ((frame, "frame"), (payload_mapping, "frame.payload")):
        for member in names:
            value = _optional_string(mapping, member, location)
            if value is not None:
                values.append(value)
    if values and any(value != values[0] for value in values[1:]):
        raise MuxError(f"conflicting mirrored ordering field {name}")
    if not values:
        return None
    try:
        return require_id(values[0], f"ordering identity {name}")
    except Exception as error:
        raise MuxError(str(error)) from error


def _complete_scope(values: dict[str, str | None], family: str) -> dict[str, str]:
    missing = [name for name in _IDENTITY_SCOPE_FIELDS if values.get(name) is None]
    if missing:
        raise MuxError(
            f"{family} ordering identity requires complete scope: missing "
            + ", ".join(missing)
        )
    return {name: values[name] for name in _IDENTITY_SCOPE_FIELDS}  # type: ignore[misc]


def ordering_key_for_frame(frame: dict[str, Any], owner_id: str) -> str:
    """Derive one canonical immutable effect identity.

    Known protocol families require their complete hierarchy.  In particular,
    every ``job.*`` request is keyed by the complete session/profile/task/turn/
    stream scope plus ``job_id``; ``operation_id`` and ``attachment_id`` are
    validated as required aliases for the operation kinds that define them but
    deliberately do not split the broader job serialization key.  Thus a
    partial ``operation_id`` request cannot bypass a job fence, and two clients
    cannot silently fall back to unrelated client-local keys for one session.
    Unknown opaque frames with no lineage remain serialized per owner.  A
    frame that supplies only a partial lineage is rejected instead of being
    assigned an unsafe best-effort key.
    """

    if not owner_id:
        raise MuxError("owner_id must be non-empty")
    kind = frame.get("kind")
    if not isinstance(kind, str) or not kind:
        raise MuxError("frame.kind must be a non-empty string")
    values = {name: _identity_value(frame, name) for name in _IDENTITY_FIELDS}

    if kind in _JOB_KINDS:
        scope = _complete_scope(values, "job")
        job_id = values.get("job_id")
        if job_id is None:
            raise MuxError("job ordering identity requires job_id")
        if kind in _JOB_EFFECT_KINDS and values.get("operation_id") is None:
            raise MuxError(f"{kind} ordering identity requires operation_id")
        if kind in _JOB_ATTACHMENT_KINDS and values.get("attachment_id") is None:
            raise MuxError(f"{kind} ordering identity requires attachment_id")
        return _effect_key("job", scope, (("job_id", job_id),))

    if kind in _TURN_KINDS:
        scope = _complete_scope(values, "turn")
        if values.get("turn_id") is None:
            raise MuxError("turn ordering identity requires turn_id")
        return _effect_key("turn", scope, ())

    if kind in _CALL_KINDS:
        scope = _complete_scope(values, "call")
        call_id = values.get("call_id")
        if call_id is None:
            raise MuxError("call ordering identity requires call_id")
        return _effect_key("call", scope, (("call_id", call_id),))

    supplied = {name: value for name, value in values.items() if value is not None}
    if supplied:
        # A future protocol family must explicitly define its hierarchy before
        # it can use a shared ordering key.  Do not let one subset of fields
        # accidentally run concurrently with another subset.
        raise MuxError(
            f"unsupported request kind {kind} has a partial ordering identity"
        )
    return f"client:{owner_id}"


class WeightedFairMux:
    """Thread-safe bounded scheduler with per-key serialization.

    Accepted requests live in exactly one of pending, active, or retired.
    Active requests are keyed by the broker-assigned upstream sequence, which
    gives exact late-result isolation even when semantic correlation is equal.
    """

    def __init__(
        self,
        *,
        max_pending: int,
        max_inflight: int,
        max_retired: int,
        owner_weights: dict[str, int] | None = None,
    ) -> None:
        if max_pending <= 0:
            raise ValueError("max_pending must be positive")
        if max_inflight <= 0 or max_inflight > max_pending:
            raise ValueError("max_inflight must be within max_pending")
        if max_retired <= 0:
            raise ValueError("max_retired must be positive")
        self.max_pending = max_pending
        self.max_inflight = max_inflight
        self.max_retired = max_retired
        self._condition = threading.Condition()
        self._pending: dict[str, deque[Any]] = {}
        self._owners: deque[str] = deque()
        self._credits: dict[str, int] = {}
        self._weights: dict[str, int] = {}
        for owner, weight in (owner_weights or {}).items():
            self._weights[owner] = self._validated_weight(weight)
        self._active: dict[int, Any] = {}
        self._active_keys: dict[str, int] = {}
        # A pending request that is being terminalized must keep its exact
        # ordering key unavailable until the durable terminal append and
        # owner-queue publication finish.  This is a *transient* hold (unlike
        # ``_fenced_keys``, which survives for the broker epoch after an
        # uncertain effect), and is counted so two independent timeout workers
        # cannot accidentally release one another's hold when a key has more
        # than one pending request.
        self._held_keys: dict[str, int] = {}
        self._retired: OrderedDict[int, RetiredRequest] = OrderedDict()
        # An active timeout is not proof that an effect stopped.  Fence its
        # ordering key for the rest of this broker epoch so a later request on
        # the same effect lineage cannot overlap the uncertain execution.
        self._fenced_keys: OrderedDict[str, str] = OrderedDict()
        self._pending_count = 0
        self._closed = False

    @staticmethod
    def _validated_weight(weight: int) -> int:
        if isinstance(weight, bool) or not isinstance(weight, int) or not 1 <= weight <= MAX_WEIGHT:
            raise ValueError(f"owner weight must be in 1..={MAX_WEIGHT}")
        return weight

    def set_weight(self, owner_id: str, weight: int) -> None:
        if not owner_id:
            raise ValueError("owner_id must be non-empty")
        weight = self._validated_weight(weight)
        with self._condition:
            self._weights[owner_id] = weight
            self._credits[owner_id] = min(self._credits.get(owner_id, weight), weight)
            self._condition.notify_all()

    def _weight(self, owner_id: str) -> int:
        return self._weights.get(owner_id, 1)

    @staticmethod
    def _validate_request(request: Any) -> None:
        for name in ("owner_id", "request_id", "ordering_key"):
            value = getattr(request, name, None)
            if not isinstance(value, str) or not value:
                raise MuxError(f"request.{name} must be a non-empty string")
        seq = getattr(request, "upstream_seq", None)
        if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
            raise MuxError("request.upstream_seq must be a positive integer")

    def enqueue(self, request: Any) -> None:
        self._validate_request(request)
        with self._condition:
            if self._closed:
                raise MuxError("scheduler is closed")
            fenced_reason = self._fenced_keys.get(request.ordering_key)
            if fenced_reason is not None:
                raise MuxError(
                    f"ordering key is fenced after unresolved effect: {fenced_reason}"
                )
            if (
                self._pending_count
                + len(self._active)
                + sum(self._held_keys.values())
                >= self.max_pending
            ):
                raise MuxError("scheduler capacity is exhausted")
            seq = request.upstream_seq
            if seq in self._active or seq in self._retired:
                raise MuxError("upstream sequence is already bound")
            if any(
                any(item.upstream_seq == seq for item in queue)
                for queue in self._pending.values()
            ):
                raise MuxError("upstream sequence is already pending")
            owner = request.owner_id
            queue = self._pending.get(owner)
            if queue is None:
                queue = deque()
                self._pending[owner] = queue
                self._owners.append(owner)
                self._credits[owner] = self._weight(owner)
            queue.append(request)
            self._pending_count += 1
            self._condition.notify_all()

    @staticmethod
    def _pop_dispatchable(
        queue: deque[Any],
        active_keys: dict[str, int],
        held_keys: dict[str, int] | None = None,
    ) -> Any | None:
        held_keys = held_keys or {}
        for index, request in enumerate(queue):
            if (
                request.ordering_key not in active_keys
                and request.ordering_key not in held_keys
            ):
                if index == 0:
                    return queue.popleft()
                queue.rotate(-index)
                selected = queue.popleft()
                queue.rotate(index)
                return selected
        return None

    def _remove_owner_if_empty(self, owner: str) -> None:
        queue = self._pending.get(owner)
        if queue:
            return
        self._pending.pop(owner, None)
        self._credits.pop(owner, None)
        try:
            self._owners.remove(owner)
        except ValueError:
            pass

    def acquire(self, timeout: float | None = None) -> Any | None:
        """Reserve one dispatchable request as active, or return None on timeout/close."""

        deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
        with self._condition:
            while True:
                if self._closed:
                    return None
                if len(self._active) < self.max_inflight and self._pending_count:
                    owners_to_scan = len(self._owners)
                    for _ in range(owners_to_scan):
                        owner = self._owners[0]
                        queue = self._pending.get(owner)
                        if not queue:
                            self._owners.popleft()
                            self._pending.pop(owner, None)
                            self._credits.pop(owner, None)
                            continue
                        credit = self._credits.get(owner, self._weight(owner))
                        if credit <= 0:
                            self._credits[owner] = self._weight(owner)
                            self._owners.rotate(-1)
                            continue
                        request = self._pop_dispatchable(
                            queue,
                            self._active_keys,
                            self._held_keys,
                        )
                        if request is None:
                            self._owners.rotate(-1)
                            continue
                        self._pending_count -= 1
                        credit -= 1
                        self._credits[owner] = credit
                        if not queue:
                            self._remove_owner_if_empty(owner)
                        elif credit <= 0:
                            self._credits[owner] = self._weight(owner)
                            self._owners.rotate(-1)
                        seq = request.upstream_seq
                        if seq in self._active or request.ordering_key in self._active_keys:
                            raise MuxError("scheduler activation invariant failed")
                        self._active[seq] = request
                        self._active_keys[request.ordering_key] = seq
                        return request
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return None
                    self._condition.wait(remaining)
                else:
                    self._condition.wait()

    def is_active(self, request: Any) -> bool:
        with self._condition:
            return self._active.get(request.upstream_seq) is request

    def active_snapshot(self) -> list[Any]:
        with self._condition:
            return list(self._active.values())

    def active_for_frame(self, frame: dict[str, Any]) -> Any | None:
        """Return the active request selected by the broker sequence, if any.

        Non-terminal observations intentionally do not satisfy ``match``.
        Their publication nevertheless needs the exact request-local lifecycle
        lock so a concurrent timeout cannot publish an observation after the
        sequence has been retired.
        """

        seq = _upstream_sequence(frame)
        if seq is None:
            return None
        with self._condition:
            return self._active.get(seq)

    def pending_snapshot(self) -> list[Any]:
        with self._condition:
            return [request for queue in self._pending.values() for request in queue]

    def _remember_retired(self, request: Any, reason: str) -> None:
        seq = request.upstream_seq
        self._retired[seq] = RetiredRequest(
            upstream_seq=seq,
            owner_id=request.owner_id,
            request_id=request.request_id,
            ordering_key=request.ordering_key,
            reason=reason,
            retired_monotonic=time.monotonic(),
        )
        self._retired.move_to_end(seq)
        while len(self._retired) > self.max_retired:
            self._retired.popitem(last=False)

    def complete(self, request: Any, *, reason: str) -> bool:
        """Atomically leave active state and retain a bounded late-result tombstone."""

        with self._condition:
            if self._active.get(request.upstream_seq) is not request:
                return False
            self._active.pop(request.upstream_seq, None)
            if self._active_keys.get(request.ordering_key) == request.upstream_seq:
                self._active_keys.pop(request.ordering_key, None)
            self._remember_retired(request, reason)
            self._condition.notify_all()
            return True

    def remove_pending(self, request: Any, *, reason: str) -> bool:
        with self._condition:
            queue = self._pending.get(request.owner_id)
            if queue is None:
                return False
            try:
                queue.remove(request)
            except ValueError:
                return False
            self._pending_count -= 1
            self._remove_owner_if_empty(request.owner_id)
            self._remember_retired(request, reason)
            self._condition.notify_all()
            return True

    def hold_pending(self, request: Any, *, reason: str) -> bool:
        """Remove one pending request while retaining its ordering-key hold.

        Timeout/disconnect convergence must append a terminal audit record
        before another request on the same effect lineage can be dispatched.
        Removing a pending entry with :meth:`remove_pending` alone would make
        the key immediately eligible while that append (and its fsync) is in
        flight.  This operation performs the removal and hold publication in
        one condition-lock critical section; callers then do the slow durable
        work without holding the broker-wide scheduler lock and finally call
        :meth:`release_ordering_hold` after owner delivery.

        The request is already retired for correlation purposes, so a stale
        upstream sequence cannot resolve it while its terminal transition is
        pending.  The transient key hold is independent of that bounded
        retired tombstone.
        """

        with self._condition:
            queue = self._pending.get(request.owner_id)
            if queue is None:
                return False
            try:
                queue.remove(request)
            except ValueError:
                return False
            self._pending_count -= 1
            self._remove_owner_if_empty(request.owner_id)
            self._held_keys[request.ordering_key] = (
                self._held_keys.get(request.ordering_key, 0) + 1
            )
            self._remember_retired(request, reason)
            self._condition.notify_all()
            return True

    def release_ordering_hold(self, ordering_key: str) -> bool:
        """Release one transient pending-terminalization hold."""

        with self._condition:
            count = self._held_keys.get(ordering_key)
            if count is None:
                return False
            if count <= 1:
                self._held_keys.pop(ordering_key, None)
            else:
                self._held_keys[ordering_key] = count - 1
            self._condition.notify_all()
            return True

    def match(
        self,
        frame: dict[str, Any],
        matcher: Callable[[Any, dict[str, Any]], bool],
    ) -> Any | None:
        """Return one exact active owner, rejecting correlation ambiguity.

        Upstream sequence is authoritative when supplied.  A retired sequence
        can never bind a later request.  Frames without a sequence are never
        eligible for ownership.  Falling back to semantic matching would let a
        delayed terminal for an older request bind the only currently-active
        request with the same job/turn fields.  Callers may still handle such a
        frame as an unowned observation, but it must not complete a request.
        """

        with self._condition:
            seq = _upstream_sequence(frame)
            if seq is not None:
                request = self._active.get(seq)
                if request is not None:
                    request_id = frame.get("broker_request_id")
                    if request_id is not None and request_id != request.request_id:
                        raise MuxError("upstream sequence conflicts with broker_request_id")
                    request_sha256 = frame.get("broker_request_sha256")
                    expected_sha256 = getattr(request, "request_sha256", None)
                    if (
                        request_sha256 is not None
                        and expected_sha256 is not None
                        and request_sha256 != expected_sha256
                    ):
                        raise MuxError(
                            "upstream sequence conflicts with broker_request_sha256"
                        )
                    echoed_seq = frame.get("broker_request_upstream_seq")
                    if echoed_seq is not None and echoed_seq != request.upstream_seq:
                        raise MuxError(
                            "upstream sequence conflicts with broker_request_upstream_seq"
                        )
                    if not matcher(request, frame):
                        # The upstream sequence also labels non-terminal observations
                        # such as job.started.  They remain broadcast observations and
                        # do not terminalize the active request.
                        return None
                    return request
                # A supplied upstream sequence is authoritative.  Retired and
                # unknown sequences are never allowed to fall back to semantic
                # matching, even after a bounded tombstone is evicted.
                return None
            # There is no safe owner identity without the immutable sequence.
            # In particular, do not use broker_request_id or semantic fields as
            # a fallback: a stale Host line can omit either one and otherwise
            # look identical to a later request.
            return None

    def sequence_state(self, frame: dict[str, Any]) -> str:
        """Classify a supplied upstream sequence without semantic fallback."""

        seq = _upstream_sequence(frame)
        if seq is None:
            return "unsequenced"
        with self._condition:
            if seq in self._active:
                return "active"
            if seq in self._retired:
                return "retired"
            return "unknown"

    def fenced_reason(self, ordering_key: str) -> str | None:
        with self._condition:
            return self._fenced_keys.get(ordering_key)

    def fence_active(self, request: Any, *, reason: str) -> list[Any]:
        """Retire one active request and reject queued work on its exact key.

        The returned requests were accepted but never forwarded.  The caller
        must durably terminalize them and release their admission reservations.
        """

        with self._condition:
            if self._active.get(request.upstream_seq) is not request:
                return []
            if request.ordering_key not in self._fenced_keys:
                if len(self._fenced_keys) >= self.max_retired:
                    raise MuxError("ordering-key fence capacity is exhausted")
                self._fenced_keys[request.ordering_key] = reason
            self._active.pop(request.upstream_seq, None)
            if self._active_keys.get(request.ordering_key) == request.upstream_seq:
                self._active_keys.pop(request.ordering_key, None)
            self._remember_retired(request, reason)

            blocked: list[Any] = []
            for owner in tuple(self._owners):
                queue = self._pending.get(owner)
                if not queue:
                    self._remove_owner_if_empty(owner)
                    continue
                kept = deque()
                while queue:
                    candidate = queue.popleft()
                    if candidate.ordering_key == request.ordering_key:
                        blocked.append(candidate)
                        self._pending_count -= 1
                        self._remember_retired(candidate, f"blocked_by:{reason}")
                    else:
                        kept.append(candidate)
                self._pending[owner] = kept
                self._remove_owner_if_empty(owner)
            self._condition.notify_all()
            return blocked

    def expired_active(self, now: float | None = None) -> list[Any]:
        now = time.monotonic() if now is None else now
        with self._condition:
            return [
                request
                for request in self._active.values()
                if getattr(request, "deadline_monotonic", float("inf")) <= now
            ]

    def expired_pending(self, now: float | None = None) -> list[Any]:
        now = time.monotonic() if now is None else now
        with self._condition:
            return [
                request
                for queue in self._pending.values()
                for request in queue
                if getattr(request, "deadline_monotonic", float("inf")) <= now
            ]

    def drain(self, *, reason: str) -> list[Any]:
        """Close and remove every accepted request without redispatch."""

        with self._condition:
            self._closed = True
            requests = list(self._active.values())
            requests.extend(request for queue in self._pending.values() for request in queue)
            for request in requests:
                self._remember_retired(request, reason)
            self._active.clear()
            self._active_keys.clear()
            # A holder may still be completing a terminal audit outside this
            # condition lock.  Keep its transient key count until that owner
            # calls `release_ordering_hold`; the scheduler is closed, so the
            # retained hold cannot admit new work, and clearing it here would
            # make the holder's later release silently lose lifecycle state.
            self._pending.clear()
            self._owners.clear()
            self._credits.clear()
            self._pending_count = 0
            self._condition.notify_all()
            return requests

    def close_and_snapshot(self) -> list[Any]:
        """Stop admission/dispatch and return all unresolved requests.

        Unlike :meth:`drain`, this leaves the active and pending entries in
        place so callers can retire each request under its own transition lock
        before doing a durable terminal append.  The close and snapshot share
        one condition-lock critical section; therefore no dispatcher can
        activate a pending request after the returned set is captured.
        """

        with self._condition:
            self._closed = True
            requests = list(self._active.values())
            requests.extend(request for queue in self._pending.values() for request in queue)
            self._condition.notify_all()
            return requests

    def close(self) -> None:
        with self._condition:
            self._closed = True
            self._condition.notify_all()

    @property
    def pending_count(self) -> int:
        with self._condition:
            return self._pending_count

    @property
    def active_count(self) -> int:
        with self._condition:
            return len(self._active)

    @property
    def retired_count(self) -> int:
        with self._condition:
            return len(self._retired)

    def retired_snapshot(self) -> Iterable[RetiredRequest]:
        with self._condition:
            return tuple(self._retired.values())

    @property
    def fenced_count(self) -> int:
        with self._condition:
            return len(self._fenced_keys)

    @property
    def held_count(self) -> int:
        """Number of transient ordering-key holds currently in progress."""

        with self._condition:
            return sum(self._held_keys.values())

    def fenced_snapshot(self) -> dict[str, str]:
        with self._condition:
            return dict(self._fenced_keys)
