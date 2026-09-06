"""Dispatch, correlation and conservative convergence for broker v2."""
from __future__ import annotations

import hashlib
import time
from typing import Any

from owner_open_broker_common import BrokerError, canonical, read_line, strict_json
from owner_open_broker_base_v2 import (
    DIRECT_ERROR_KINDS as _DIRECT_ERROR_KINDS,
    TIMEOUT_SCAN_SECONDS as _TIMEOUT_SCAN_SECONDS,
    WIRE,
)
from owner_open_broker_mux import MuxError
from owner_open_broker_runtime import (
    BROKER_WRITE_TIMEOUT_SECONDS,
    Request,
    correlation_matches,
    frame_correlation,
    response_envelope_matches,
    response_matches,
    validate_upstream_frame,
    write_all_bounded,
)


class BrokerConvergenceMixin:
    @staticmethod
    def _restart_admission_fence_is_set(broker: Any) -> bool:
        """Read the transient restart-admission fence consistently.

        ``BrokerAdmissionMixin`` owns the counter and event, but the
        convergence/dispatch mixin is also exercised by small contract-test
        doubles that do not include that mixin.  Keep this compatibility read
        local and lock-aware: a terminal replay sets/clears the event while
        holding ``admission_fence_lock``.  A missing event means that the
        legacy test double has no transient fence to honor.
        """

        fence = getattr(broker, "admission_fence", None)
        if fence is None:
            return False
        lock = getattr(broker, "admission_fence_lock", None)
        if lock is None:
            return fence.is_set()
        with lock:
            return fence.is_set()

    def _request_for_upstream_frame(self, frame: dict[str, Any]) -> Request | None:
        """Return the unique live request owning a broker response envelope.

        The v2 scheduler stores ownership in ``WeightedFairMux``.  A small
        compatibility path is retained for older contract probes that build a
        broker test double with ``pending_requests``; both paths apply the
        same immutable envelope check and fail closed on ambiguity, retired
        requests, or an uncertain upstream transition.
        """

        uncertain = getattr(self, "upstream_uncertain", None)
        if uncertain is not None and uncertain.is_set():
            return None
        try:
            validate_upstream_frame(frame)
        except BrokerError:
            return None

        pending = getattr(self, "pending_requests", None)
        pending_lock = getattr(self, "pending_requests_lock", None)
        if pending is not None and pending_lock is not None:
            with pending_lock:
                matches = tuple(
                    request
                    for request in pending.values()
                    if not getattr(request, "terminalized", False)
                    and response_envelope_matches(request, frame)
                )
            return matches[0] if len(matches) == 1 else None

        # Production v2 ownership is keyed by the broker-assigned upstream
        # sequence in the mux.  Keep this fallback defensive for source
        # contract probes that exercise the helper on a minimally initialized
        # object rather than a running BrokerBase instance.
        mux = getattr(self, "mux", None)
        transition_lock = getattr(self, "transition_lock", None)
        if mux is None or transition_lock is None:
            return None
        with transition_lock:
            try:
                return mux.match(frame, self._terminal_matches)
            except (BrokerError, MuxError):
                return None

    def _finish_active(
        self,
        request: Request,
        owner_message: dict[str, Any],
        *,
        details: dict[str, Any],
        retire_reason: str,
        observation: dict[str, Any] | None = None,
    ) -> bool:
        """Durably deliver and retire one active request.

        The request-local lock orders a dispatch write/audit transition against
        timeout, disconnect and Host-terminal paths for this exact request.
        ``transition_lock`` is retained only around the short mux metadata
        operation; the audit append (which fsyncs) and client delivery happen
        outside that broker-wide lock.  Terminal delivery is enqueued before
        the mux releases the ordering key, so a waiter on that key cannot be
        forwarded ahead of the prior terminal observation/result.

        An audit failure deliberately leaves the request active until global
        uncertainty convergence starts.  Completing it first would wake a
        same-key waiter in the interval before ``upstream_uncertain`` is set,
        allowing a second effect to cross an unresolved journal boundary.
        """

        # The concrete journal currently raises ``BrokerError`` for expected
        # durability failures, but this boundary also wraps injected/storage
        # implementations that may surface an ``OSError``/``RuntimeError``.
        # Any ordinary exception after acceptance is equally ambiguous: keep
        # the request live and converge globally instead of letting a worker
        # thread die with an unresolved effect.
        audit_failure: Exception | None = None
        with request.transition_lock:
            with self.transition_lock:
                if not self.mux.is_active(request):
                    return False
            try:
                self.audit.terminal(
                    request.audit_binding,
                    owner_message=owner_message,
                    details=details,
                )
            except Exception as error:
                audit_failure = error
                owner_message = self._request_error(
                    request,
                    "broker_terminal_audit_failed",
                    str(error),
                )
            if audit_failure is None:
                # Broadcast the raw terminal observation only for a successful
                # durable transition.  This preserves the v1 observation
                # contract for surviving clients when the original owner
                # disconnected, without exposing a terminal that was not
                # durably bound.  The uncertainty lock orders publication
                # against the global upstream fence: whichever acquires it
                # first is the committed observable order, and an already
                # published fence suppresses the stale observation.
                if observation is not None:
                    with self.unknown_lock:
                        if (
                            not self.upstream_uncertain.is_set()
                            and not self.stopping.is_set()
                        ):
                            self._broadcast(observation)
                # Client queues are bounded/non-blocking.  Enqueue both
                # terminal views before freeing the ordering key; physical
                # socket delivery remains the client's independent writer
                # responsibility.
                self._owner(request.owner_id, owner_message)
                with self.transition_lock:
                    if not self.mux.complete(request, reason=retire_reason):
                        return False

        if audit_failure is not None:
            # The active mux entry is intentionally still present here.  Thus
            # a same-key waiter cannot activate before _mark_upstream_unknown
            # publishes the global fence and snapshots every unresolved
            # request.  That convergence owns slot release and owner delivery
            # for this request; doing either here would double-complete it.
            self._mark_upstream_unknown(
                audit_failure,
                code="broker_terminal_audit_failed",
            )
            return False
        self.request_slots.release()
        return True

    def _finish_pending(
        self,
        request: Request,
        owner_message: dict[str, Any],
        *,
        details: dict[str, Any],
        retire_reason: str,
    ) -> bool:
        audit_failure: Exception | None = None
        # Remove a pending request and retain a transient hold on its exact
        # ordering key before the audit append.  A plain removal would wake a
        # same-key waiter while this method is fsyncing; on an audit failure
        # that waiter could cross the unresolved journal boundary before the
        # global uncertainty fence is published.  The mux hold is metadata
        # only, so unrelated keys remain dispatchable while the append runs.
        with request.transition_lock:
            with self.transition_lock:
                if not self.mux.hold_pending(request, reason=retire_reason):
                    return False
            try:
                self.audit.terminal(
                    request.audit_binding,
                    owner_message=owner_message,
                    details=details,
                )
            except Exception as error:
                audit_failure = error
                owner_message = self._request_error(
                    request,
                    "broker_terminal_audit_failed",
                    str(error),
                )
        if audit_failure is not None:
            # Keep the key hold through uncertainty publication and owner
            # enqueue.  This ordering ensures a waiter cannot acquire the key
            # in the interval between an audit failure and _mark's event set.
            # The nested finally blocks release both reservations even if a
            # test double/client cleanup raises unexpectedly.
            try:
                self._mark_upstream_unknown(
                    audit_failure,
                    code="broker_terminal_audit_failed",
                )
            finally:
                try:
                    self._owner(request.owner_id, owner_message)
                finally:
                    self.mux.release_ordering_hold(request.ordering_key)
                    self.request_slots.release()
            return False
        try:
            # The durable terminal and owner queue entry precede key release,
            # preserving the same terminal-before-next-dispatch ordering used
            # by _finish_active.
            self._owner(request.owner_id, owner_message)
        finally:
            self.mux.release_ordering_hold(request.ordering_key)
            self.request_slots.release()
        return True

    @staticmethod
    def _terminal_matches(request: Request, frame: dict[str, Any]) -> bool:
        direct_error = frame.get("kind") in _DIRECT_ERROR_KINDS
        return response_matches(request, frame) or (
            direct_error
            and response_envelope_matches(request, frame)
            and correlation_matches(request, frame)
        )

    def _publish_active_observation(
        self,
        request: Request,
        observation: dict[str, Any],
    ) -> bool:
        """Publish one non-terminal frame only while its sequence is active.

        The request-local lock is acquired before the broker metadata lock,
        matching every other lifecycle transition.  Keeping it through the
        bounded client-queue publication makes the observation-versus-timeout
        order deterministic: either the observation is published first, or a
        retired sequence is suppressed entirely.
        """

        # All request lifecycle paths acquire the request lock first.  The
        # uncertainty marker holds ``unknown_lock`` only while setting its
        # events and releases it before waiting on request/metadata state, so
        # this order cannot form an unknown -> request cycle.  It also lets a
        # terminal path retain the same lifecycle lock through publication and
        # ordering-key release.
        with request.transition_lock:
            with self.unknown_lock:
                if self.upstream_uncertain.is_set() or self.stopping.is_set():
                    return False
                with self.transition_lock:
                    if not self.mux.is_active(request):
                        return False
                self._broadcast(observation)
                return True

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
                # Host observations from older providers may be completely
                # unbound; they are never eligible to resolve a request, but
                # can still be discarded/handled by the sequence gate.  Once
                # any broker envelope member appears, however, require the
                # complete strict envelope before it can reach observers.
                envelope_fields = (
                    "broker_request_id",
                    "broker_request_sha256",
                    "broker_request_upstream_seq",
                )
                envelope_present = sum(name in frame for name in envelope_fields)
                if envelope_present == len(envelope_fields):
                    validate_upstream_frame(frame)
                elif envelope_present:
                    # A partial envelope is an unowned/stale line.  It must
                    # not poison the whole upstream epoch, but it also must
                    # never be guessed into ownership by semantic fields.
                    continue
                elif "seq" in frame:
                    # Host ``seq`` belongs to the response stream, not to the
                    # broker's immutable request namespace.  The production
                    # reader must discard a host-only sequence before it can
                    # reach the strict mux ownership API (that is, the
                    # production reader must discard a host-only sequence,
                    # never reinterpret it as broker ownership).
                    continue
                # Conflicting mirrored fields are invalid before any observer
                # can receive the frame.  A supplied sequence is authoritative:
                # retired or unknown sequences are never exposed as raw Host
                # observations and cannot semantically bind another request.
                # Unsequenced frames are malformed at this broker boundary and
                # are isolated rather than guessed against the active set.
                frame_correlation(frame)
                observation = {
                    "schema": WIRE,
                    "kind": "observation",
                    "broker_epoch": self.broker_epoch,
                    "frame": frame,
                    "automatic_redispatch": False,
                }
                with self.transition_lock:
                    sequence_state = self.mux.sequence_state(frame)
                    request = self.mux.match(frame, self._terminal_matches)
                    if request is None and sequence_state == "active":
                        # ``match`` deliberately returns no owner for a
                        # non-terminal observation. Recover the exact active
                        # sequence only so publication can share its
                        # request-local lifecycle lock; never derive an owner
                        # from semantic fields.
                        request = self.mux.active_for_frame(frame)
                if sequence_state in {"retired", "unknown", "unsequenced"}:
                    # Never broadcast a line whose owner cannot be proved.
                    # In particular this prevents an omitted-seq duplicate
                    # terminal from being mistaken for a live request.
                    continue
                if request is None:
                    # The active entry may have retired between the sequence
                    # snapshot and the lookup. An unowned line is never
                    # broadcast, even when its semantic fields look unique.
                    continue
                # Revalidate the exact sequence while holding its lifecycle
                # lock, and keep that lock through the selected transition.
                # Releasing it after only the classification check lets the
                # timeout worker win a request whose terminal frame already
                # crossed the correlation barrier (the reader test exercises
                # that interleaving deterministically).
                with request.transition_lock:
                    with self.transition_lock:
                        if not self.mux.is_active(request):
                            continue
                        terminal = self._terminal_matches(request, frame)
                    if not terminal:
                        self._publish_active_observation(request, observation)
                        continue
                    # Do not hold the broker-wide transition lock while the
                    # durable terminal append fsyncs. ``_finish_active`` uses
                    # an RLock and retains this request-local lock across the
                    # exact terminal transition.
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
                        observation=observation,
                    )
        except Exception as error:
            self._mark_upstream_unknown(error)

    def _terminalize_drained(
        self,
        requests: list[Request],
        error: Exception,
        code: str,
    ) -> tuple[list[Request], list[tuple[str, dict[str, Any]]], Exception | None]:
        """Retire a closed scheduler snapshot one request at a time.

        ``close_and_snapshot`` only closes activation; it intentionally leaves
        entries in the mux until each request-local transition lock is held.
        This prevents a worker that was already in a bounded write from racing
        a disconnect drain and also avoids holding ``transition_lock`` across
        any audit fsync.
        """

        retired: list[Request] = []
        deliveries: list[tuple[str, dict[str, Any]]] = []
        audit_failure: Exception | None = None
        for request in requests:
            with request.transition_lock:
                with self.transition_lock:
                    removed = self.mux.complete(request, reason=code)
                    if not removed:
                        removed = self.mux.remove_pending(request, reason=code)
                if not removed:
                    # Another exact transition won the request-local race and
                    # already released its admission slot/owner delivery.
                    continue
                message = self._request_error(request, code, str(error))
                effect_may_have_started = bool(
                    getattr(request, "effect_attempted", False)
                    or getattr(request.audit_binding, "stage", None)
                    == "broker.forwarded"
                )
                try:
                    self.audit.terminal(
                        request.audit_binding,
                        owner_message=message,
                        details={
                            "status": code,
                            "effect_may_have_started": effect_may_have_started,
                        },
                    )
                except Exception as audit_error:
                    # The original uncertainty is retained.  Never synthesize
                    # a durable terminal record after audit storage itself
                    # failed, but still release this request's slot below.  Do
                    # not deliver the original status as if it were durable;
                    # the owner must see the explicit storage failure and can
                    # reconcile the unresolved binding out of band.
                    audit_failure = audit_failure or audit_error
                    message = self._request_error(
                        request,
                        "broker_terminal_audit_failed",
                        str(audit_error),
                    )
                retired.append(request)
                deliveries.append((request.owner_id, message))
        return retired, deliveries, audit_failure

    def _mark_upstream_unknown(
        self,
        error: Exception,
        *,
        code: str = "unknown_after_disconnect",
    ) -> None:
        # Publish the uncertainty flag before waiting for any lifecycle lock,
        # so a dispatcher queued at the write boundary cannot start a new
        # effect after this failure is observed.  Only one caller performs the
        # drain; concurrent callers wait for its completion instead of
        # returning while a pending terminalizer still holds a key reservation.
        completion = getattr(self, "unknown_convergence_complete", None)
        with self.unknown_lock:
            if self.upstream_uncertain.is_set():
                leader = False
            else:
                self.upstream_uncertain.set()
                self.stopping.set()
                if completion is not None:
                    completion.clear()
                leader = True
        if not leader:
            if completion is not None:
                completion.wait()
            return

        # Release ``unknown_lock`` before taking the writer/transition locks:
        # holding it across either operation would deadlock a concurrent
        # terminal failure that is itself reporting uncertainty.
        try:
            # Do not snapshot the mux until the one shared upstream byte
            # stream is quiescent. Without this gate, a worker could pass the
            # metadata check, lose the transition lock to this method, and
            # still write a request after the uncertainty fence was published.
            with self.upstream_write_lock:
                with self.transition_lock:
                    unresolved = self.mux.close_and_snapshot()
            retired, deliveries, audit_failure = self._terminalize_drained(
                unresolved,
                error,
                code,
            )
            for _request in retired:
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
                    "active_requests_converged": len(retired),
                    "automatic_redispatch": False,
                }
            )
            if audit_failure is not None:
                # The uncertainty boundary is already published; retain the
                # storage failure as an additional status rather than retrying
                # any accepted effect.
                self._broadcast(
                    {
                        "schema": WIRE,
                        "kind": "broker.status",
                        "broker_epoch": self.broker_epoch,
                        "status": "audit_unavailable",
                        "code": "broker_terminal_audit_failed",
                        "message": str(audit_failure),
                        "automatic_redispatch": False,
                    }
                )
        finally:
            if completion is not None:
                completion.set()

    def _before_forward(self, request: Request) -> str | None:
        """Return a rejection reason at the exact pre-write metadata barrier."""

        with request.transition_lock:
            with self.transition_lock:
                if not self.mux.is_active(request):
                    return "request_retired"
                if self.upstream_uncertain.is_set():
                    return "upstream_uncertain_before_forward"
                if self.stopping.is_set():
                    return "broker_stopping_before_forward"
                if self._restart_admission_fence_is_set(self):
                    return "admission_fenced_before_forward"
        return None

    def _acquire_upstream_writer(self, request: Request) -> str | None:
        """Wait for the one upstream byte-stream writer without holding state."""

        # Waiting for pipe ownership is not itself an effect attempt.  Do not
        # hold the request-local lock here: the timeout worker must be able to
        # retire an unrelated active request while another writer is stalled.
        deadline = min(
            request.deadline_monotonic,
            time.monotonic() + BROKER_WRITE_TIMEOUT_SECONDS,
        )
        while True:
            if not self.mux.is_active(request):
                return "request_retired"
            if self.upstream_uncertain.is_set():
                return "upstream_uncertain_before_forward"
            if self.stopping.is_set():
                return "broker_stopping_before_forward"
            if self._restart_admission_fence_is_set(self):
                return "admission_fenced_before_forward"
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return "timeout_before_forward"
            if self.upstream_write_lock.acquire(timeout=min(0.05, remaining)):
                return None

    def _finish_before_forward(
        self,
        request: Request,
        reason: str,
    ) -> None:
        if reason == "request_retired":
            return
        code = (
            "upstream_uncertain"
            if reason == "upstream_uncertain_before_forward"
            else "broker_stopping"
            if reason == "broker_stopping_before_forward"
            else "admission_fenced"
            if reason == "admission_fenced_before_forward"
            else "timeout_before_forward"
        )
        self._finish_active(
            request,
            self._request_error(
                request,
                code,
                "broker refused dispatch before the upstream effect boundary",
            ),
            details={
                "status": reason,
                "effect_may_have_started": False,
            },
            retire_reason=reason,
        )

    def _forward_request(self, request: Request) -> None:
        """Forward one active request while keeping global locks metadata-only."""

        reason = self._before_forward(request)
        if reason is not None:
            self._finish_before_forward(request, reason)
            return
        upstream = self.upstream
        if upstream is None or upstream.stdin is None:
            self._mark_upstream_unknown(BrokerError("upstream stdin is unavailable before forward"))
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
            return
        frame.update(
            seq=request.upstream_seq,
            client_seq=request.client_seq,
            direction="client_to_host",
            broker_request_id=request.request_id,
            # Host ``seq`` belongs to its response stream and may be
            # rewritten independently.  Carry the broker's immutable
            # sequence explicitly so the reader can bind a response without
            # guessing from the Host sequence.
            broker_request_upstream_seq=request.upstream_seq,
            broker_request_sha256=request.request_sha256,
            broker_ordering_key=request.ordering_key,
        )
        encoded = canonical(frame) + b"\n"

        reason = self._acquire_upstream_writer(request)
        if reason is not None:
            self._finish_before_forward(request, reason)
            return

        # The concrete writer/audit implementations use the narrow error
        # classes below, but an injected storage/provider implementation may
        # surface any ordinary ``Exception``.  Treat every such failure as an
        # ambiguous effect boundary; letting it escape would kill the
        # dispatcher thread while leaving this accepted request active.
        write_error: Exception | None = None
        reject_before_forward: str | None = None
        writer_released = False
        try:
            # Recheck ownership and uncertainty after waiting for the shared
            # byte-stream writer.  The request lock prevents a terminal path
            # from removing this request between the check and the write.
            with request.transition_lock:
                with self.transition_lock:
                    if not self.mux.is_active(request):
                        reject_before_forward = "request_retired"
                    elif self.upstream_uncertain.is_set():
                        reject_before_forward = "upstream_uncertain_before_forward"
                    elif self.stopping.is_set():
                        reject_before_forward = "broker_stopping_before_forward"
                    elif self._restart_admission_fence_is_set(self):
                        reject_before_forward = "admission_fenced_before_forward"
                if reject_before_forward is None:
                    request.effect_attempted = True
                    try:
                        # ``upstream_write_lock`` is intentionally the only
                        # broker-wide lock held over this bounded pipe write.
                        # The request-local lock remains held through the
                        # durable forwarded append: a Host terminal frame
                        # cannot overtake the accepted -> forwarded journal
                        # transition for this exact request.
                        write_all_bounded(
                            upstream.stdin,
                            encoded,
                            timeout_seconds=min(
                                BROKER_WRITE_TIMEOUT_SECONDS,
                                max(
                                    0.001,
                                    request.deadline_monotonic - time.monotonic(),
                                ),
                            ),
                            label=f"upstream request {request.upstream_seq}",
                        )
                    except Exception as error:
                        write_error = error
                    finally:
                        # The byte-stream gate is needed only for framing the
                        # write.  Release it before the durable audit fsync so
                        # another key can enqueue bytes while this request's
                        # request-local transition remains serialized.
                        self.upstream_write_lock.release()
                        writer_released = True
                    if write_error is None:
                        try:
                            # Keep this append under the request-local lock,
                            # but outside ``transition_lock``.  BrokerAudit's
                            # own bounded journal lock serializes durable bytes
                            # without blocking unrelated mux metadata.
                            self.audit.forwarded(
                                request.audit_binding,
                                frame_sha256=hashlib.sha256(encoded).hexdigest(),
                                frame_bytes=len(encoded),
                            )
                        except Exception as error:
                            write_error = error
        finally:
            # Covers a metadata/check failure before the write block.  In the
            # normal path the gate was released immediately after write.
            if not writer_released:
                self.upstream_write_lock.release()

        if reject_before_forward is not None:
            self._finish_before_forward(request, reject_before_forward)
            return
        if write_error is not None:
            # A pipe write can be partial/ambiguous for every request sharing
            # this upstream.  Converge globally, but only after releasing the
            # request and writer locks so the drain cannot deadlock.
            self._mark_upstream_unknown(write_error)
            return


    def _request_worker(self) -> None:
        while not self.stopping.is_set():
            request = self.mux.acquire(timeout=0.1)
            if request is None:
                continue
            try:
                self._forward_request(request)
            except Exception as error:
                # Keep a provider/storage surprise from terminating this
                # worker with an unresolved active mux entry.  The request
                # has already crossed admission, so the only safe response
                # is global uncertainty convergence; that path owns draining
                # and releasing the request reservation exactly once.
                self._mark_upstream_unknown(error, code="broker_dispatcher_failure")

    def _fence_uncertain_active(self, request: Request) -> bool:
        """Terminalize a timed-out request and fence its ordering key.

        A timeout proves neither cancellation nor descendant absence.  Work on
        unrelated keys may continue, but accepted waiters and future requests
        on this exact key are rejected without forwarding.
        """

        # ``mux.acquire`` makes a request active before the dispatcher obtains
        # the shared upstream writer.  Waiting for that byte-stream gate is
        # not an effect attempt, so an expired request in that interval can be
        # retired normally and must not poison its ordering key.  Keep the
        # classification and retirement under the request-local lock; the
        # latter is re-entrant in ``_finish_active`` and prevents a dispatcher
        # that is already at the write boundary from overtaking this decision.
        with request.transition_lock:
            with self.transition_lock:
                if not self.mux.is_active(request):
                    return False
                effect_may_have_started = bool(
                    getattr(request, "effect_attempted", False)
                    or getattr(request.audit_binding, "stage", None)
                    == "broker.forwarded"
                )
            if not effect_may_have_started:
                return self._finish_active(
                    request,
                    self._request_error(
                        request,
                        "timeout_before_forward",
                        "active request expired before the upstream write boundary",
                    ),
                    details={
                        "status": "timeout_before_forward",
                        "effect_may_have_started": False,
                    },
                    retire_reason="timeout_before_forward",
                )

        current_message = self._request_error(
            request,
            "unknown_after_timeout",
            "forwarded request did not reach a correlated terminal before deadline",
        )
        blocked: list[Request] = []
        blocked_deliveries: list[tuple[str, dict[str, Any]]] = []
        audit_failure: Exception | None = None
        fence_failure: MuxError | None = None

        # Fence the exact active sequence while holding only metadata locks.
        # The durable terminal appends below may fsync and therefore must not
        # run under the broker-wide transition lock.  The request-local lock
        # keeps its dispatcher/terminal path from overtaking this timeout.
        with request.transition_lock:
            with self.transition_lock:
                if not self.mux.is_active(request):
                    return False
                try:
                    blocked = self.mux.fence_active(
                        request,
                        reason="unknown_after_timeout",
                    )
                except MuxError as error:
                    # The active request remains owned by the mux when
                    # fencing fails, so global convergence will release its
                    # reservation.  Defer that convergence until all locks
                    # are released to preserve unknown_lock -> transition_lock
                    # ordering.
                    fence_failure = error

            if fence_failure is not None:
                blocked = []
            else:
                try:
                    self.audit.terminal(
                        request.audit_binding,
                        owner_message=current_message,
                        details={
                            "status": "unknown_after_timeout",
                            "effect_may_have_started": bool(
                                getattr(request, "effect_attempted", False)
                                or getattr(request.audit_binding, "stage", None)
                                == "broker.forwarded"
                            ),
                            "ordering_key_fenced": request.ordering_key,
                        },
                    )
                except Exception as error:
                    audit_failure = error
                    current_message = self._request_error(
                        request,
                        "broker_terminal_audit_failed",
                        str(error),
                    )

                for waiting in blocked:
                    # ``fence_active`` already removed this request from the
                    # pending queues.  Serialize only its own durable terminal
                    # transition; no global lock is held while fsyncing.
                    with waiting.transition_lock:
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
                        except Exception as error:
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
        if audit_failure is not None:
            # The active key is already fenced, but the audit failure still
            # requires a global uncertainty boundary for unrelated keys.  Do
            # that before releasing any admission slots; otherwise another
            # client could consume a newly-freed slot and forward an effect
            # while this unresolved journal transition is being reported.
            try:
                self._mark_upstream_unknown(
                    audit_failure,
                    code="broker_terminal_audit_failed",
                )
            finally:
                self.request_slots.release()
                for _waiting in blocked:
                    self.request_slots.release()
                self._owner(request.owner_id, current_message)
                for owner_id, message in blocked_deliveries:
                    self._owner(owner_id, message)
            return False
        self.request_slots.release()
        for _waiting in blocked:
            self.request_slots.release()
        self._owner(request.owner_id, current_message)
        for owner_id, message in blocked_deliveries:
            self._owner(owner_id, message)
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
