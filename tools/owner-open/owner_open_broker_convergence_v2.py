"""Dispatch, correlation and conservative convergence for broker v2."""
from __future__ import annotations

import hashlib
from typing import Any

from owner_open_broker_common import BrokerError, canonical, read_line, strict_json
from owner_open_broker_base_v2 import (
    DIRECT_ERROR_KINDS as _DIRECT_ERROR_KINDS,
    TIMEOUT_SCAN_SECONDS as _TIMEOUT_SCAN_SECONDS,
    WIRE,
)
from owner_open_broker_mux import MuxError
from owner_open_broker_runtime import (
    Request,
    correlation_matches,
    frame_correlation,
    response_matches,
)


class BrokerConvergenceMixin:
    def _finish_active(
        self,
        request: Request,
        owner_message: dict[str, Any],
        *,
        details: dict[str, Any],
        retire_reason: str,
    ) -> bool:
        audit_failure: BrokerError | None = None
        with self.transition_lock:
            if not self.mux.is_active(request):
                return False
            try:
                self.audit.terminal(
                    request.audit_binding,
                    owner_message=owner_message,
                    details=details,
                )
            except BrokerError as error:
                audit_failure = error
                owner_message = self._request_error(
                    request,
                    "broker_terminal_audit_failed",
                    str(error),
                )
            if not self.mux.complete(request, reason=retire_reason):
                return False
        self.request_slots.release()
        self._owner(request.owner_id, owner_message)
        if audit_failure is not None:
            self._mark_upstream_unknown(
                audit_failure,
                code="broker_terminal_audit_failed",
            )
            return False
        return True

    def _finish_pending(
        self,
        request: Request,
        owner_message: dict[str, Any],
        *,
        details: dict[str, Any],
        retire_reason: str,
    ) -> bool:
        audit_failure: BrokerError | None = None
        with self.transition_lock:
            if not self.mux.remove_pending(request, reason=retire_reason):
                return False
            try:
                self.audit.terminal(
                    request.audit_binding,
                    owner_message=owner_message,
                    details=details,
                )
            except BrokerError as error:
                audit_failure = error
                owner_message = self._request_error(
                    request,
                    "broker_terminal_audit_failed",
                    str(error),
                )
        self.request_slots.release()
        self._owner(request.owner_id, owner_message)
        if audit_failure is not None:
            self._mark_upstream_unknown(
                audit_failure,
                code="broker_terminal_audit_failed",
            )
            return False
        return True

    @staticmethod
    def _terminal_matches(request: Request, frame: dict[str, Any]) -> bool:
        direct_error = frame.get("kind") in _DIRECT_ERROR_KINDS
        return response_matches(request, frame) or (
            direct_error and correlation_matches(request, frame)
        )

    def _upstream_reader(self) -> None:
        upstream = self.upstream
        if upstream is None or upstream.stdout is None:
            self._mark_upstream_unknown(BrokerError("upstream stdout is unavailable"))
            return
        try:
            while not self.stopping.is_set():
                raw = read_line(upstream.stdout, label="upstream frame")
                if raw is None:
                    raise BrokerError("upstream disconnected")
                frame = strict_json(raw, label="upstream frame")
                if not isinstance(frame, dict) or not isinstance(frame.get("kind"), str):
                    raise BrokerError("upstream frame has no valid kind")
                # Conflicting mirrored fields are invalid before any observer
                # can receive the frame.  A supplied sequence is authoritative:
                # retired or unknown sequences are never exposed as raw Host
                # observations and cannot semantically bind another request.
                frame_correlation(frame)
                with self.transition_lock:
                    sequence_state = self.mux.sequence_state(frame)
                    request = self.mux.match(frame, self._terminal_matches)
                if sequence_state in {"retired", "unknown"}:
                    continue
                observation = {
                    "schema": WIRE,
                    "kind": "observation",
                    "broker_epoch": self.broker_epoch,
                    "frame": frame,
                    "automatic_redispatch": False,
                }
                # The wire contract keeps observations globally visible while
                # delivering the correlated terminal result only to its owner.
                # Broadcasting the terminal observation also preserves durable
                # observability when the owner disconnects after acceptance; it
                # never transfers result ownership or authorizes redispatch.
                self._broadcast(observation)
                if request is None:
                    continue
                self._finish_active(
                    request,
                    self._result(request, frame),
                    details={
                        "status": "host_terminal_observed",
                        "frame_kind": frame["kind"],
                        "frame_sha256": hashlib.sha256(canonical(frame)).hexdigest(),
                        "late_result_isolation": "upstream_seq",
                    },
                    retire_reason="terminal",
                )
        except Exception as error:
            self._mark_upstream_unknown(error)

    def _terminalize_drained(
        self,
        requests: list[Request],
        error: Exception,
        code: str,
    ) -> list[tuple[str, dict[str, Any]]]:
        deliveries: list[tuple[str, dict[str, Any]]] = []
        for request in requests:
            message = self._request_error(request, code, str(error))
            try:
                self.audit.terminal(
                    request.audit_binding,
                    owner_message=message,
                    details={
                        "status": code,
                        "effect_may_have_started": request.audit_binding.stage
                        == "broker.forwarded",
                    },
                )
            except BrokerError:
                # The original uncertainty is retained.  Never synthesize a
                # durable terminal record after audit storage itself failed.
                pass
            deliveries.append((request.owner_id, message))
        return deliveries

    def _mark_upstream_unknown(
        self,
        error: Exception,
        *,
        code: str = "unknown_after_disconnect",
    ) -> None:
        with self.unknown_lock:
            if self.upstream_uncertain.is_set():
                return
            self.upstream_uncertain.set()
            self.stopping.set()
            with self.transition_lock:
                unresolved = self.mux.drain(reason=code)
                deliveries = self._terminalize_drained(unresolved, error, code)
        for _request in unresolved:
            self.request_slots.release()
        for owner_id, message in deliveries:
            self._owner(owner_id, message)
        self._broadcast(
            {
                "schema": WIRE,
                "kind": "broker.status",
                "broker_epoch": self.broker_epoch,
                "status": "upstream_unavailable",
                "code": code,
                "message": str(error),
                "active_requests_converged": len(unresolved),
                "automatic_redispatch": False,
            }
        )

    def _request_worker(self) -> None:
        while not self.stopping.is_set():
            request = self.mux.acquire(timeout=0.1)
            if request is None:
                continue
            if self.upstream_uncertain.is_set():
                self._finish_active(
                    request,
                    self._request_error(
                        request,
                        "upstream_uncertain",
                        "broker refuses dispatch after uncertain upstream state",
                    ),
                    details={
                        "status": "rejected_after_acceptance_before_forward",
                        "effect_may_have_started": False,
                    },
                    retire_reason="upstream_uncertain_before_forward",
                )
                continue
            upstream = self.upstream
            if upstream is None or upstream.stdin is None:
                self._mark_upstream_unknown(
                    BrokerError("upstream stdin is unavailable before forward")
                )
                return
            frame = dict(request.frame)
            if "client_seq" in frame and frame["client_seq"] != request.client_seq:
                self._finish_active(
                    request,
                    self._request_error(
                        request,
                        "client_seq_conflict",
                        "Host frame client_seq conflicts with its original seq",
                    ),
                    details={
                        "status": "rejected_after_acceptance_before_forward",
                        "effect_may_have_started": False,
                    },
                    retire_reason="client_seq_conflict",
                )
                continue
            frame.update(
                seq=request.upstream_seq,
                client_seq=request.client_seq,
                direction="client_to_host",
                broker_request_id=request.request_id,
                broker_request_sha256=request.request_sha256,
                broker_ordering_key=request.ordering_key,
            )
            encoded = canonical(frame) + b"\n"
            try:
                with self.transition_lock:
                    if not self.mux.is_active(request):
                        continue
                    upstream.stdin.write(encoded)
                    upstream.stdin.flush()
                    self.audit.forwarded(
                        request.audit_binding,
                        frame_sha256=hashlib.sha256(encoded).hexdigest(),
                        frame_bytes=len(encoded),
                    )
            except (OSError, BrokerError) as error:
                # A pipe write or its durable forwarded transition may be
                # ambiguous for every in-flight request sharing the process.
                self._mark_upstream_unknown(error)
                return

    def _fence_uncertain_active(self, request: Request) -> bool:
        """Terminalize a timed-out request and fence its ordering key.

        A timeout proves neither cancellation nor descendant absence.  Work on
        unrelated keys may continue, but accepted waiters and future requests
        on this exact key are rejected without forwarding.
        """

        current_message = self._request_error(
            request,
            "unknown_after_timeout",
            "forwarded request did not reach a correlated terminal before deadline",
        )
        blocked: list[Request] = []
        blocked_deliveries: list[tuple[str, dict[str, Any]]] = []
        audit_failure: BrokerError | None = None
        fence_failure: MuxError | None = None
        with self.transition_lock:
            if not self.mux.is_active(request):
                return False
            try:
                self.audit.terminal(
                    request.audit_binding,
                    owner_message=current_message,
                    details={
                        "status": "unknown_after_timeout",
                        "effect_may_have_started": request.audit_binding.stage
                        == "broker.forwarded",
                        "ordering_key_fenced": request.ordering_key,
                    },
                )
            except BrokerError as error:
                audit_failure = error
                current_message = self._request_error(
                    request,
                    "broker_terminal_audit_failed",
                    str(error),
                )
            try:
                blocked = self.mux.fence_active(
                    request,
                    reason="unknown_after_timeout",
                )
            except MuxError as error:
                # The active request remains owned by the mux when fencing
                # fails, so global convergence will release its reservation.
                # Defer global convergence until after transition_lock is
                # released to preserve unknown_lock -> transition_lock order.
                fence_failure = error
            if fence_failure is not None:
                blocked = []
            for waiting in blocked:
                message = self._request_error(
                    waiting,
                    "ordering_key_uncertain",
                    "an earlier request on this ordering key timed out after forward",
                )
                try:
                    self.audit.terminal(
                        waiting.audit_binding,
                        owner_message=message,
                        details={
                            "status": "rejected_after_acceptance_before_forward",
                            "effect_may_have_started": False,
                            "blocked_by_upstream_seq": request.upstream_seq,
                            "ordering_key_fenced": request.ordering_key,
                        },
                    )
                except BrokerError as error:
                    audit_failure = audit_failure or error
                    message = self._request_error(
                        waiting,
                        "broker_terminal_audit_failed",
                        str(error),
                    )
                blocked_deliveries.append((waiting.owner_id, message))

        if fence_failure is not None:
            self._mark_upstream_unknown(
                fence_failure,
                code="broker_fence_capacity_failed",
            )
            return False
        self.request_slots.release()
        for _waiting in blocked:
            self.request_slots.release()
        self._owner(request.owner_id, current_message)
        for owner_id, message in blocked_deliveries:
            self._owner(owner_id, message)
        if audit_failure is not None:
            self._mark_upstream_unknown(
                audit_failure,
                code="broker_terminal_audit_failed",
            )
            return False
        return True

    def _timeout_worker(self) -> None:
        while not self.stopping.wait(_TIMEOUT_SCAN_SECONDS):
            for request in self.mux.expired_pending():
                self._finish_pending(
                    request,
                    self._request_error(
                        request,
                        "timeout_before_forward",
                        "accepted request expired before it could be forwarded",
                    ),
                    details={
                        "status": "timeout_before_forward",
                        "effect_may_have_started": False,
                    },
                    retire_reason="timeout_before_forward",
                )
            for request in self.mux.expired_active():
                self._fence_uncertain_active(request)
