"""Authenticated admission and client protocol handling for broker v2."""
from __future__ import annotations

import hashlib
import os
import socket
import threading
import time
from typing import Any

from owner_open_broker_base_v2 import (
    DEFAULT_TIMEOUT_MS,
    MAX_EXPECTED_KINDS,
    MAX_TIMEOUT_MS,
    WIRE,
)
from owner_open_broker_common import (
    BrokerError,
    canonical,
    compare_token,
    read_line,
    require_id,
    require_token,
    strict_json,
)
from owner_open_broker_mux import MuxError, ordering_key_for_frame
from owner_open_broker_runtime import (
    BROKER_WRITE_TIMEOUT_SECONDS,
    Client,
    Request,
    canonical_request_frame,
    frame_correlation,
    frame_job_id,
    peer_credentials,
    send_all_bounded,
)


# Lightweight compatibility initialization for source-contract test doubles
# that mix in admission behavior without calling ``BrokerBase.__init__``.
# Production brokers create these members eagerly in the base constructor;
# keeping the fallback here makes the fence helpers safe for those minimal
# objects without weakening the lock/flag ordering.
_FENCE_STATE_INIT_LOCK = threading.Lock()


class BrokerAdmissionMixin:
    def _fence_state(self) -> tuple[threading.Lock, threading.Event]:
        lock = getattr(self, "admission_fence_lock", None)
        fence = getattr(self, "admission_fence", None)
        if lock is None or fence is None:
            with _FENCE_STATE_INIT_LOCK:
                lock = getattr(self, "admission_fence_lock", None)
                if lock is None:
                    lock = threading.Lock()
                    setattr(self, "admission_fence_lock", lock)
                fence = getattr(self, "admission_fence", None)
                if fence is None:
                    fence = threading.Event()
                    setattr(self, "admission_fence", fence)
                if not hasattr(self, "_admission_fence_count"):
                    setattr(self, "_admission_fence_count", 0)
        if not hasattr(self, "_admission_fence_count"):
            with _FENCE_STATE_INIT_LOCK:
                if not hasattr(self, "_admission_fence_count"):
                    setattr(self, "_admission_fence_count", 0)
        return lock, fence

    def _temporary_admission_fence_active(self) -> bool:
        lock, fence = self._fence_state()
        with lock:
            return fence.is_set()

    def _begin_temporary_admission_fence(self) -> None:
        lock, fence = self._fence_state()
        # Publish the admission bit immediately under its own lock, before
        # waiting for the shared byte-stream gate.  Otherwise a writer holding
        # ``upstream_write_lock`` could leave a capacity window in which a new
        # request is admitted while an old-epoch replay is already committed
        # to convergence but has not yet raised its fence.  The dispatcher
        # checks this same bit while holding the byte-stream gate from its
        # final check through the bounded write: a writer that checked before
        # publication is already in the pre-fence linearization interval,
        # while every later writer observes the bit and rejects.  Release the
        # metadata lock before taking the gate (F -> U would otherwise cycle
        # with the dispatcher's U -> request -> transition -> F order).
        with lock:
            count = getattr(self, "_admission_fence_count", 0)
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                count = 0
            setattr(self, "_admission_fence_count", count + 1)
            fence.set()

        # Synchronize with a writer that was already in its check/write
        # interval.  This gate is held only for the short acquire/release
        # barrier; terminal audit/fsync remains outside it.
        upstream_gate = getattr(self, "upstream_write_lock", None)
        if upstream_gate is not None:
            upstream_gate.acquire()
            upstream_gate.release()

    def _end_temporary_admission_fence(self) -> None:
        lock, fence = self._fence_state()
        with lock:
            count = getattr(self, "_admission_fence_count", 0)
            if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
                setattr(self, "_admission_fence_count", 0)
                fence.clear()
                return
            count -= 1
            setattr(self, "_admission_fence_count", count)
            if count == 0:
                fence.clear()

    def _admission_block_reason(self) -> str | None:
        if self.upstream_uncertain.is_set():
            return "upstream_uncertain"
        if self.stopping.is_set():
            return "broker_stopping"
        if self._temporary_admission_fence_active():
            return "admission_fenced"
        return None

    def _authenticate(self, connection: socket.socket, stream: Any) -> Client:
        pid, uid, gid = peer_credentials(connection)
        if uid != os.geteuid():
            raise BrokerError(f"peer UID {uid} does not match broker UID {os.geteuid()}")
        raw = read_line(stream, label="broker hello")
        if raw is None:
            raise BrokerError("client disconnected before broker hello")
        value = strict_json(raw, label="broker hello")
        if not isinstance(value, dict) or value.get("kind") != "broker.hello":
            raise BrokerError("first client frame must be broker.hello")
        client_id = require_id(value.get("client_id"), "client_id")
        if not compare_token(require_token(value.get("token")), self.token):
            raise BrokerError("broker token mismatch")
        supplied_epoch = value.get("broker_epoch")
        if supplied_epoch is not None and supplied_epoch != self.broker_epoch:
            raise BrokerError("broker descriptor epoch is stale")
        client: Client | None = None
        inserted = False
        try:
            with self.clients_lock:
                if client_id in self.clients:
                    raise BrokerError("client_id is already connected")
                if len(self.clients) >= self.args.max_clients:
                    raise BrokerError("broker client limit reached")
                client = Client(
                    client_id,
                    connection,
                    pid,
                    uid,
                    gid,
                    self.args.client_queue_bytes,
                    self.args.client_queue_frames,
                )
                self.clients[client_id] = client
                inserted = True

            # Everything after publication in ``self.clients`` is part of one
            # admission transaction.  In particular, a scheduler, writer,
            # descriptor or hello-ack failure must not leave a ghost client
            # occupying the ID (or a writer holding the socket) forever.
            if client_id in getattr(self.args, "client_weights", {}):
                self.mux.set_weight(client_id, self.args.client_weights[client_id])
            writer = threading.Thread(
                target=client.writer,
                daemon=True,
                name=f"broker-writer-{client_id}",
            )
            writer.start()
            self.worker_threads.append(writer)
            descriptor = self.descriptor
            host_hello_ack = self.host_hello_ack
            if descriptor is None or host_hello_ack is None:
                raise BrokerError("broker descriptor is unavailable")
            descriptor_sha256 = descriptor.get("descriptor_sha256")
            if not isinstance(descriptor_sha256, str) or not descriptor_sha256:
                raise BrokerError("broker descriptor digest is unavailable")
            ack = {
                "schema": WIRE,
                "kind": "broker.hello.ack",
                "broker_id": self.args.broker_id,
                "broker_epoch": self.broker_epoch,
                "token_epoch": self.token_epoch,
                "client_id": client_id,
                "descriptor_sha256": descriptor_sha256,
                "host_hello_ack": host_hello_ack,
                "peer": {"pid": pid, "uid": uid, "gid": gid},
                "max_inflight_requests": self.args.max_inflight_requests,
                "automatic_redispatch": False,
            }
            if not client.enqueue(ack):
                raise BrokerError("client closed before broker hello ack")
            return client
        except BaseException:
            # ``_client_reader`` cannot see a client when this method raises,
            # so rollback must happen here.  The identity-aware removal also
            # prevents a late cleanup from evicting a newer connection that
            # reused the same client ID.
            if client is not None:
                if inserted:
                    self._remove_client(client)
                else:
                    client.close()
            raise

    @staticmethod
    def _request_preimage(
        frame: dict[str, Any],
        expected: frozenset[str],
        expected_job: str | None,
        timeout_ms: int,
        ordering_key: str,
    ) -> dict[str, Any]:
        return {
            # Hash only reconnect-stable semantic bytes.  Connection-local
            # cursors/IDs and caller-supplied digests are separately bound by
            # the accepted audit record and must not turn an exact replay into
            # a second effect.
            "frame": canonical_request_frame(frame),
            "expected_kinds": sorted(expected),
            "expected_job_id": expected_job,
            "timeout_ms": timeout_ms,
            # The scheduler identity is part of the authenticated request
            # bytes.  A replay/conflict therefore cannot retain the same
            # request id while silently changing its serialization boundary.
            "ordering_key": ordering_key,
        }

    def _handle_existing_admission(
        self,
        client: Client,
        request_id: str,
        request_sha256: str,
        existing: Any,
        *,
        reserved_slot: bool = False,
    ) -> None:
        """Replay or converge a request already present in the audit.

        ``BrokerAuditJournal.admit`` is the atomic identity gate.  This helper
        is deliberately called after the short broker metadata gate has been
        released: the restart terminal append can fsync and must not block an
        unrelated client's admission.  ``reserved_slot`` is used only by the
        audit-disposition race path: that caller has already reserved one
        speculative capacity slot, and it must remain held until an old-epoch
        fence is raised (or the durable terminal/uncertainty transition
        completes).
        """

        slot_held = reserved_slot

        def release_reserved_slot() -> None:
            # Keep the release idempotent across the normal early-return paths
            # and the defensive ``finally`` below.  A disposition race must
            # never over-release a bounded semaphore if an owner queue or test
            # double raises while replaying the existing binding.
            nonlocal slot_held
            if slot_held:
                self.request_slots.release()
                slot_held = False

        try:
            self._handle_existing_admission_inner(
                client,
                request_id,
                request_sha256,
                existing,
                release_reserved_slot=release_reserved_slot,
            )
        finally:
            # The inner helper releases on successful/failed convergence before
            # owner delivery where needed.  If malformed test-double state or a
            # client queue exception escapes earlier, do not leak the
            # speculative slot; the accepted binding is already represented in
            # the audit and the broker's surrounding failure path is fail
            # closed.
            release_reserved_slot()

    def _handle_existing_admission_inner(
        self,
        client: Client,
        request_id: str,
        request_sha256: str,
        existing: Any,
        *,
        release_reserved_slot: Any,
    ) -> None:
        """Implementation split out so the slot guard stays exception-safe."""

        if existing.request_sha256 != request_sha256:
            client.enqueue(
                self._error(
                    request_id,
                    "request_id_conflict",
                    "request_id is already bound to different canonical bytes",
                )
            )
            release_reserved_slot()
            return
        if existing.terminal_message is not None:
            client.enqueue(existing.terminal_message)
            release_reserved_slot()
            return
        if existing.broker_epoch == self.broker_epoch:
            # An accepted request in this epoch is already owned by the mux;
            # the reconnecting client must not create a second effect.
            release_reserved_slot()
            return
        owner_message = {
            **self._error(
                request_id,
                "unknown_after_restart",
                "request was accepted in an earlier broker epoch without a durable terminal",
            ),
            "broker_epoch": self.broker_epoch,
            "prior_broker_epoch": existing.broker_epoch,
            "broker_request_upstream_seq": existing.upstream_seq,
            "broker_request_downstream_seq": existing.client_seq,
            "broker_request_sha256": existing.request_sha256,
        }
        # An older-epoch unresolved binding has no live mux entry to reserve
        # its ordering key.  Raise a short-lived admission fence before the
        # terminal append instead.  New requests check this flag before
        # reserving capacity, and the dispatcher rechecks it at the exact
        # upstream write boundary; a successful durable replay clears it,
        # while a failed append leaves it set for global convergence.
        try:
            # Raise the fence before the slow terminal append.  In the
            # disposition-race path the speculative slot is still held here,
            # so a concurrent new admission cannot pass through a window where
            # the old binding is unresolved but capacity has been returned.
            self._begin_temporary_admission_fence()
            self.audit.terminal(
                existing,
                owner_message=owner_message,
                details={
                    "status": "unknown_after_restart",
                    "effect_may_have_started": existing.stage == "broker.forwarded",
                },
            )
        except Exception as error:
            # The old-epoch request is already an accepted effect boundary.
            # If its restart terminal cannot be durably appended, do not let
            # the exception fall through as a generic client protocol error:
            # that would leave the binding unresolved while the broker keeps
            # admitting new effects.  Publish the uncertainty fence first;
            # the journal remains unresolved/poisoned and no redispatch is
            # attempted.
            failure = {
                **owner_message,
                "code": "broker_terminal_audit_failed",
                "message": str(error),
            }
            try:
                self._mark_upstream_unknown(error, code="broker_terminal_audit_failed")
            finally:
                release_reserved_slot()
                client.enqueue(failure)
            return
        self._end_temporary_admission_fence()
        # The terminal bytes are durable and the transient fence is cleared;
        # release the speculative slot only after both barriers are complete.
        release_reserved_slot()
        client.enqueue(owner_message)

    def _terminalize_unenqueued_request(
        self,
        client: Client,
        request: Request | None,
        *,
        binding: Any | None = None,
        request_id: str,
        code: str,
        message: str,
        details_status: str,
    ) -> None:
        """Durably reject an accepted binding that never reached the mux.

        This path is used when a temporary restart fence (or a scheduler
        failure) wins after the journal's accepted append.  Keep the
        speculative capacity slot reserved until the terminal append has
        either succeeded or published global uncertainty; otherwise another
        admission could cross an unresolved audit boundary.
        """

        owner_message: dict[str, Any]
        if request is None:
            owner_message = self._error(request_id, code, message)
        else:
            owner_message = self._request_error(request, code, message)
        audit_failure: Exception | None = None
        try:
            audit_binding = request.audit_binding if request is not None else binding
            if audit_binding is None:
                raise BrokerError("accepted request binding is unavailable")
            self.audit.terminal(
                audit_binding,
                owner_message=owner_message,
                details={
                    "status": details_status,
                    "effect_may_have_started": False,
                },
            )
        except Exception as error:
            audit_failure = error
            if request is None:
                owner_message = self._error(
                    request_id,
                    "broker_terminal_audit_failed",
                    str(error),
                )
            else:
                owner_message = self._request_error(
                    request,
                    "broker_terminal_audit_failed",
                    str(error),
                )
        if audit_failure is not None:
            try:
                self._mark_upstream_unknown(
                    audit_failure,
                    code="broker_terminal_audit_failed",
                )
            finally:
                self.request_slots.release()
                client.enqueue(owner_message)
            return
        self.request_slots.release()
        client.enqueue(owner_message)

    def _admit_request(
        self,
        client: Client,
        request_id: str,
        frame: dict[str, Any],
        expected: frozenset[str],
        expected_job: str | None,
        timeout_ms: int,
    ) -> None:
        initial_block = self._admission_block_reason()
        if initial_block in {"upstream_uncertain", "broker_stopping"}:
            client.enqueue(
                self._error(
                    request_id,
                    "upstream_uncertain",
                    "broker is not accepting work after upstream uncertainty",
                )
            )
            return
        client_seq_value = frame.get("seq")
        correlation = frame_correlation(frame)
        try:
            ordering_key = ordering_key_for_frame(frame, client.client_id)
        except MuxError as error:
            raise BrokerError(str(error)) from error
        preimage = self._request_preimage(
            frame,
            expected,
            expected_job,
            timeout_ms,
            ordering_key,
        )
        request_sha256 = hashlib.sha256(canonical(preimage)).hexdigest()

        # Serialize only the bounded per-client metadata reservation.  In
        # particular, this gate must be released before ``audit.admit`` or
        # ``audit.terminal``: those operations fsync and their own journal
        # lock is the atomic identity/durability boundary.  Independent
        # clients therefore never wait on a broker-wide admission gate.
        existing = None
        preflight_error: str | None = None
        client_seq: int | None = None
        upstream_seq: int | None = None
        # Serialize reconnect/duplicate admission only within this
        # authenticated client's namespace.  The old broker-wide admission
        # lock covered audit fsync and made one slow journal append stall every
        # client; a client-local key gate preserves exact request-id ordering
        # without a process-wide slow-path lock.
        with client.admission_lock:
            existing = self.audit.lookup(client.client_id, request_id)
            if existing is None:
                # Recheck the short-lived restart fence at the same
                # per-client reservation boundary.  Existing request-id
                # replays are intentionally allowed through to
                # `_handle_existing_admission`; only a genuinely new effect
                # is rejected here.
                admission_block = self._admission_block_reason()
                if admission_block is not None:
                    preflight_error = admission_block
                else:
                    client_seq = client.accept_sequence(client_seq_value)
                    fenced_reason = self.mux.fenced_reason(ordering_key)
                    if fenced_reason is not None:
                        preflight_error = "ordering_key_uncertain"
                    elif not self.request_slots.acquire(blocking=False):
                        preflight_error = "resource_exhausted"
                    else:
                        with self.sequence_lock:
                            upstream_seq = self.next_upstream_seq
                            self.next_upstream_seq += 1

        # Everything below this point is intentionally outside
        # ``client.admission_lock``.  The audit journal remains the sole atomic
        # identity gate for races with another client/reconnect.
        if existing is not None:
            self._handle_existing_admission(
                client,
                request_id,
                request_sha256,
                existing,
            )
            return
        if preflight_error == "ordering_key_uncertain":
            client.enqueue(
                self._error(
                    request_id,
                    "ordering_key_uncertain",
                    f"ordering key is fenced after unresolved effect: {self.mux.fenced_reason(ordering_key)}",
                )
            )
            return
        if preflight_error in {"admission_fenced", "broker_stopping", "upstream_uncertain"}:
            client.enqueue(
                self._error(
                    request_id,
                    preflight_error,
                    "broker is not accepting a new effect during convergence",
                )
            )
            return
        if preflight_error == "resource_exhausted":
            client.enqueue(
                self._error(
                    request_id,
                    "resource_exhausted",
                    "broker request capacity is exhausted before acceptance",
                )
            )
            return

        # ``preflight_error`` is set only after a failed slot acquire; an
        # absent value therefore means this request owns one slot and one
        # broker sequence.  Keep the assertion local so a future edit cannot
        # accidentally call the journal with an uninitialised reservation.
        if client_seq is None or upstream_seq is None:
            raise BrokerError("broker admission reservation is incomplete")

        try:
            admission = self.audit.admit(
                broker_epoch=self.broker_epoch,
                client_id=client.client_id,
                request_id=request_id,
                request_sha256=request_sha256,
                client_seq=client_seq,
                upstream_seq=upstream_seq,
                request_kind=frame["kind"],
                correlation=correlation,
            )
        except Exception as error:
            # ``audit.admit`` is the accepted-effect boundary.  An I/O/fsync
            # failure can occur after the accepted bytes reached the journal
            # but before this call returns, so treating every exception as a
            # local client rejection would let the broker continue admitting
            # effects against an unresolved binding.  Publish the global
            # uncertainty fence before replying; the journal remains the
            # authority for later offline reconciliation.  This is
            # intentionally conservative for capacity/validation failures as
            # well: stopping is safer than guessing whether an append crossed
            # the durability boundary.
            # Publish the uncertainty boundary while this speculative slot is
            # still reserved.  Releasing it first would let another client
            # pass the initial admission check and reach a transiently
            # healthy scheduler before the failed durable append is fenced.
            try:
                self._mark_upstream_unknown(
                    error,
                    code="broker_acceptance_audit_failed",
                )
            finally:
                self.request_slots.release()
            client.enqueue(
                self._error(
                    request_id,
                    "broker_acceptance_failed",
                    str(error),
                )
            )
            return

        if admission.disposition != "new":
            # A concurrent/reconnect race won the journal identity gate while
            # this request was waiting for the durable append.  No effect was
            # enqueued by this path.  Keep its speculative slot reserved while
            # replaying/converging the existing binding: if the winner is an
            # older unresolved epoch, the helper raises its temporary fence
            # before doing the slow terminal append.  Releasing here would
            # create a capacity window in which a new effect could pass before
            # that fence is visible.
            self._handle_existing_admission(
                client,
                request_id,
                request_sha256,
                admission.binding,
                reserved_slot=True,
            )
            return

        request: Request | None = None
        try:
            request = Request(
                owner_id=client.client_id,
                request_id=request_id,
                frame=frame,
                expected_kinds=expected,
                expected_job_id=expected_job,
                timeout_ms=timeout_ms,
                client_seq=client_seq,
                upstream_seq=upstream_seq,
                request_sha256=request_sha256,
                correlation=correlation,
                audit_binding=admission.binding,
                ordering_key=ordering_key,
                deadline_monotonic=time.monotonic() + timeout_ms / 1000,
            )
        except Exception as error:
            # Request construction is local, but retain the same conservative
            # terminalization path if a malformed/changed Request type fails
            # after the durable ``admit`` append.
            self._terminalize_unenqueued_request(
                client,
                request,
                binding=admission.binding,
                request_id=request_id,
                code="broker_acceptance_failed",
                message=str(error),
                details_status="rejected_after_acceptance_before_forward",
            )
            return

        # A restart replay can raise the short-lived fence after this
        # request's audit acceptance returned.  Recheck immediately before
        # publishing the mux entry; the dispatcher performs the same check
        # again at the byte-write boundary for the remaining check-to-enqueue
        # race.  Keep this outside the broad exception handler above: the
        # terminalizer owns the one-and-only slot release and must never be
        # invoked a second time if its uncertainty callback raises.
        admission_block = self._admission_block_reason()
        if admission_block is not None:
            self._terminalize_unenqueued_request(
                client,
                request,
                binding=admission.binding,
                request_id=request_id,
                code=admission_block,
                message="broker refused dispatch during admission convergence",
                details_status="rejected_after_acceptance_before_forward",
            )
            return
        try:
            self.mux.enqueue(request)
        except Exception as error:
            self._terminalize_unenqueued_request(
                client,
                request,
                binding=admission.binding,
                request_id=request_id,
                code="broker_acceptance_failed",
                message=str(error),
                details_status="rejected_after_acceptance_before_forward",
            )

    def _client_reader(self, connection: socket.socket) -> None:
        client: Client | None = None
        stream = connection.makefile("rb", buffering=0)
        try:
            client = self._authenticate(connection, stream)
            while not self.stopping.is_set() and not client.closed.is_set():
                raw = read_line(stream, label="broker request")
                if raw is None:
                    return
                value = strict_json(raw, label="broker request")
                if not isinstance(value, dict) or value.get("kind") != "request":
                    raise BrokerError("client frame must be request")
                request_id = require_id(value.get("request_id"), "request_id")
                frame, expected_raw = value.get("frame"), value.get("expected_kinds")
                if not isinstance(frame, dict) or not isinstance(frame.get("kind"), str):
                    raise BrokerError("broker request frame is invalid")
                if (
                    not isinstance(expected_raw, list)
                    or not expected_raw
                    or len(expected_raw) > MAX_EXPECTED_KINDS
                    or any(not isinstance(item, str) or not item for item in expected_raw)
                ):
                    raise BrokerError("expected_kinds must be a finite non-empty string list")
                expected = frozenset(expected_raw)
                expected_job = value.get("expected_job_id")
                if expected_job is not None:
                    expected_job = require_id(expected_job, "expected_job_id")
                frame_job = frame_job_id(frame)
                if expected_job is not None and frame_job != expected_job:
                    raise BrokerError("expected_job_id conflicts with the request frame")
                timeout_ms = value.get("timeout_ms", DEFAULT_TIMEOUT_MS)
                if (
                    isinstance(timeout_ms, bool)
                    or not isinstance(timeout_ms, int)
                    or not 1 <= timeout_ms <= MAX_TIMEOUT_MS
                ):
                    raise BrokerError("timeout_ms is outside the finite bound")
                self._admit_request(
                    client,
                    request_id,
                    frame,
                    expected,
                    expected_job,
                    timeout_ms,
                )
        except Exception as error:
            failure = self._error(None, "client_protocol_error", str(error))
            if client:
                client.enqueue(failure)
                time.sleep(0.01)
            else:
                try:
                    send_all_bounded(
                        connection,
                        canonical(failure) + b"\n",
                        timeout_seconds=BROKER_WRITE_TIMEOUT_SECONDS,
                        label="unauthenticated client error",
                    )
                except (OSError, TimeoutError):
                    pass
        finally:
            try:
                stream.close()
            except OSError:
                pass
            if client:
                self._remove_client(client)
            else:
                try:
                    connection.close()
                except OSError:
                    pass
