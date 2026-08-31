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

MAX_WEIGHT = 1_024
_ORDERING_FIELDS = (
    # Serialize the broadest mutable effect lineage first.  In particular,
    # distinct operation_id values for one job must not bypass job ordering.
    "job_id",
    "call_id",
    "turn_stream_id",
    "turn_id",
    "task_id",
    "operation_id",
)


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


def _optional_string(mapping: dict[str, Any], name: str, location: str) -> str | None:
    if name not in mapping or mapping[name] is None:
        return None
    value = mapping[name]
    if not isinstance(value, str) or not value:
        raise MuxError(f"{location}.{name} must be a non-empty string or null")
    return value


def ordering_key_for_frame(frame: dict[str, Any], owner_id: str) -> str:
    """Derive a stable per-effect serialization key from mirrored identifiers.

    Envelope and payload values are mirrors.  Conflicting copies are rejected
    instead of choosing a precedence rule.  Requests with no protocol key are
    serialized per client, which is conservative and finite.
    """

    payload = frame.get("payload")
    payload_mapping = payload if isinstance(payload, dict) else {}
    for name in _ORDERING_FIELDS:
        envelope = _optional_string(frame, name, "frame")
        body = _optional_string(payload_mapping, name, "frame.payload")
        if envelope is not None and body is not None and envelope != body:
            raise MuxError(f"conflicting mirrored ordering field {name}")
        value = envelope if envelope is not None else body
        if value is not None:
            return f"{name}:{value}"
    if not owner_id:
        raise MuxError("owner_id must be non-empty")
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
            if self._pending_count + len(self._active) >= self.max_pending:
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
    def _pop_dispatchable(queue: deque[Any], active_keys: dict[str, int]) -> Any | None:
        for index, request in enumerate(queue):
            if request.ordering_key not in active_keys:
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
                        request = self._pop_dispatchable(queue, self._active_keys)
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

    def match(
        self,
        frame: dict[str, Any],
        matcher: Callable[[Any, dict[str, Any]], bool],
    ) -> Any | None:
        """Return one exact active owner, rejecting correlation ambiguity.

        Upstream sequence is authoritative when supplied.  A retired sequence
        can never bind a later request.  Frames without a sequence are accepted
        only when semantic matching identifies exactly one active request.
        """

        with self._condition:
            seq = frame.get("seq")
            if seq is not None:
                if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                    raise MuxError("upstream frame seq must be a nonnegative integer")
                request = self._active.get(seq)
                if request is not None:
                    request_id = frame.get("broker_request_id")
                    if request_id is not None and request_id != request.request_id:
                        raise MuxError("upstream sequence conflicts with broker_request_id")
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
            request_id = frame.get("broker_request_id")
            candidates: list[Any] = []
            for request in self._active.values():
                if request_id is not None and request_id != request.request_id:
                    continue
                if matcher(request, frame):
                    candidates.append(request)
            if not candidates:
                return None
            if len(candidates) != 1:
                raise MuxError("upstream terminal correlation is ambiguous")
            return candidates[0]

    def sequence_state(self, frame: dict[str, Any]) -> str:
        """Classify a supplied upstream sequence without semantic fallback."""

        seq = frame.get("seq")
        if seq is None:
            return "unsequenced"
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise MuxError("upstream frame seq must be a nonnegative integer")
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
            self._pending.clear()
            self._owners.clear()
            self._credits.clear()
            self._pending_count = 0
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

    def fenced_snapshot(self) -> dict[str, str]:
        with self._condition:
            return dict(self._fenced_keys)
