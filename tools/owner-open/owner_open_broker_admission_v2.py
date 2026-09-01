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


class BrokerAdmissionMixin:
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

    def _admit_request(
        self,
        client: Client,
        request_id: str,
        frame: dict[str, Any],
        expected: frozenset[str],
        expected_job: str | None,
        timeout_ms: int,
    ) -> None:
        if self.upstream_uncertain.is_set() or self.stopping.is_set():
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
        with self.admission_lock:
            existing = self.audit.lookup(client.client_id, request_id)
            if existing is not None:
                if existing.request_sha256 != request_sha256:
                    client.enqueue(
                        self._error(
                            request_id,
                            "request_id_conflict",
                            "request_id is already bound to different canonical bytes",
                        )
                    )
                    return
                if existing.terminal_message is not None:
                    client.enqueue(existing.terminal_message)
                    return
                if existing.broker_epoch == self.broker_epoch:
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
                self.audit.terminal(
                    existing,
                    owner_message=owner_message,
                    details={
                        "status": "unknown_after_restart",
                        "effect_may_have_started": existing.stage == "broker.forwarded",
                    },
                )
                client.enqueue(owner_message)
                return
            client_seq = client.accept_sequence(client_seq_value)
            fenced_reason = self.mux.fenced_reason(ordering_key)
            if fenced_reason is not None:
                client.enqueue(
                    self._error(
                        request_id,
                        "ordering_key_uncertain",
                        f"ordering key is fenced after unresolved effect: {fenced_reason}",
                    )
                )
                return
            if not self.request_slots.acquire(blocking=False):
                client.enqueue(
                    self._error(
                        request_id,
                        "resource_exhausted",
                        "broker request capacity is exhausted before acceptance",
                    )
                )
                return
            with self.sequence_lock:
                upstream_seq = self.next_upstream_seq
                self.next_upstream_seq += 1
            admission = None
            request: Request | None = None
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
                if admission.disposition != "new":
                    raise BrokerError("broker audit admission changed during serialized admission")
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
                self.mux.enqueue(request)
            except Exception as error:
                owner_message = self._error(
                    request_id,
                    "broker_acceptance_failed",
                    str(error),
                )
                audit_failure: BrokerError | None = None
                if admission is not None and admission.disposition == "new":
                    if request is not None:
                        owner_message = self._request_error(
                            request,
                            "broker_acceptance_failed",
                            str(error),
                        )
                    try:
                        self.audit.terminal(
                            admission.binding,
                            owner_message=owner_message,
                            details={
                                "status": "rejected_after_acceptance_before_forward",
                                "effect_may_have_started": False,
                            },
                        )
                    except BrokerError as terminal_error:
                        audit_failure = terminal_error
                self.request_slots.release()
                client.enqueue(owner_message)
                if audit_failure is not None:
                    self._mark_upstream_unknown(
                        audit_failure,
                        code="broker_terminal_audit_failed",
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
