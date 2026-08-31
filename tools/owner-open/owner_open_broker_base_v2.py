"""Process, descriptor and delivery state for the owner-open broker v2."""
from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import signal
import socket
import subprocess
import threading
from typing import Any

from owner_open_broker_audit import BrokerAuditJournal
from owner_open_broker_common import (
    BrokerError,
    canonical,
    finalize_descriptor,
    load_or_create_token,
    read_line,
    strict_json,
    validate_argv,
    validate_executable,
)
from owner_open_broker_mux import WeightedFairMux
from owner_open_broker_runtime import Client, Request

SCHEMA = "org.trillionnium.owner-open.connection-broker.v1"
WIRE = "org.trillionnium.owner-open.connection-broker-wire.v1"
DEFAULT_TIMEOUT_MS = 30_000
MAX_TIMEOUT_MS = 600_000
MAX_EXPECTED_KINDS = 32
TIMEOUT_SCAN_SECONDS = 0.01
DIRECT_ERROR_KINDS = frozenset({"host.error", "job.error"})


class BrokerBase:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.token = load_or_create_token(args.token_file)
        self.token_epoch = hashlib.sha256(self.token.encode("ascii")).hexdigest()[:32]
        self.broker_epoch = secrets.token_hex(16)
        self.clients: dict[str, Client] = {}
        self.clients_lock = threading.Lock()
        self.request_slots = threading.BoundedSemaphore(args.max_pending_requests)
        self.mux = WeightedFairMux(
            max_pending=args.max_pending_requests,
            max_inflight=args.max_inflight_requests,
            max_retired=args.max_retired_requests,
            owner_weights=args.client_weights,
        )
        self.admission_lock = threading.Lock()
        self.sequence_lock = threading.Lock()
        # One transition lock orders pipe write -> durable forwarded record ->
        # terminal record.  It is never held while waiting for a Host result.
        self.transition_lock = threading.RLock()
        self.stopping = threading.Event()
        self.upstream_uncertain = threading.Event()
        self.unknown_lock = threading.Lock()
        self.upstream_stderr = bytearray()
        self.upstream_stderr_lock = threading.Lock()
        self.upstream_argv = [str(args.upstream), *args.upstream_arg]
        validate_argv(self.upstream_argv)
        self.upstream_identity = validate_executable(args.upstream, "--upstream")
        self.audit = BrokerAuditJournal(args.audit_file, broker_id=args.broker_id)
        self.next_upstream_seq = self.audit.next_upstream_seq
        self.upstream: subprocess.Popen[bytes] | None = None
        self.host_hello_ack: dict[str, Any] | None = None
        self.descriptor: dict[str, Any] | None = None
        self.listener: socket.socket | None = None
        self.socket_identity: tuple[int, int] | None = None
        self.descriptor_identity: tuple[int, int] | None = None
        self.worker_threads: list[threading.Thread] = []

    def _start_upstream(self) -> None:
        upstream = subprocess.Popen(
            self.upstream_argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            bufsize=0,
        )
        if upstream.stdin is None or upstream.stdout is None or upstream.stderr is None:
            try:
                os.killpg(upstream.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            upstream.wait()
            raise BrokerError("upstream standard streams were not piped")
        self.upstream = upstream
        stderr_thread = threading.Thread(
            target=self._drain_stderr,
            daemon=True,
            name="broker-upstream-stderr",
        )
        stderr_thread.start()
        self.worker_threads.append(stderr_thread)
        self.host_hello_ack = self._handshake()

    def _drain_stderr(self) -> None:
        upstream = self.upstream
        if upstream is None or upstream.stderr is None:
            return
        while not self.stopping.is_set():
            try:
                chunk = upstream.stderr.read(8192)
            except OSError:
                return
            if not chunk:
                return
            with self.upstream_stderr_lock:
                remaining = 1024 * 1024 - len(self.upstream_stderr)
                self.upstream_stderr.extend(chunk[: max(0, remaining)])

    def _handshake(self) -> dict[str, Any]:
        upstream = self.upstream
        if upstream is None or upstream.stdin is None or upstream.stdout is None:
            raise BrokerError("upstream is not available for handshake")
        request = {
            "kind": "hello",
            "seq": 0,
            "direction": "client_to_host",
            "payload": {
                "protocol": "trillionnium.agent.turn.v1",
                "protocol_version": 1,
            },
        }
        upstream.stdin.write(canonical(request) + b"\n")
        upstream.stdin.flush()
        raw = read_line(upstream.stdout, label="upstream hello")
        if raw is None:
            raise BrokerError("upstream exited before hello.ack")
        value = strict_json(raw, label="upstream hello")
        if not isinstance(value, dict) or value.get("kind") != "hello.ack":
            raise BrokerError("upstream first response is not hello.ack")
        return value

    def _build_descriptor(self) -> dict[str, Any]:
        if self.host_hello_ack is None:
            raise BrokerError("cannot build descriptor before Host handshake")
        return finalize_descriptor(
            {
                "schema": SCHEMA,
                "broker_id": self.args.broker_id,
                "broker_epoch": self.broker_epoch,
                "token_epoch": self.token_epoch,
                "socket_path": str(self.args.socket),
                "token_file": str(self.args.token_file),
                "audit_file": str(self.args.audit_file),
                "audit_status": "durable_fsync_hash_chain",
                "service_uid": os.geteuid(),
                "trust_domain": "same_euid_and_private_token_not_same_uid_process_isolation",
                "response_model": "broker_correlated_result_owner_with_broadcast_observation",
                "scheduler_version": 2,
                "scheduler": {
                    "kind": "bounded_weighted_round_robin",
                    "per_ordering_key_serialization": True,
                    "ordering_key_precedence": [
                        "job_id",
                        "call_id",
                        "turn_stream_id",
                        "turn_id",
                        "task_id",
                        "operation_id",
                        "client_id_fallback",
                    ],
                    "late_result_isolation": "bounded_retired_upstream_sequence_tombstones",
                },
                "max_clients": self.args.max_clients,
                "client_queue_frames": self.args.client_queue_frames,
                "client_queue_bytes": self.args.client_queue_bytes,
                "max_pending_requests": self.args.max_pending_requests,
                "max_inflight_requests": self.args.max_inflight_requests,
                "max_retired_requests": self.args.max_retired_requests,
                "client_weights": self.args.client_weights,
                "request_audit_stages": [
                    "broker.accepted",
                    "broker.forwarded",
                    "broker.terminal",
                ],
                "upstream": self.upstream_identity,
                "upstream_argv_sha256": hashlib.sha256(
                    canonical(self.upstream_argv)
                ).hexdigest(),
                "host_hello_ack": self.host_hello_ack,
                "automatic_redispatch": False,
            }
        )

    def _owner(self, owner_id: str, value: dict[str, Any]) -> None:
        with self.clients_lock:
            client = self.clients.get(owner_id)
        if client is not None and not client.enqueue(value):
            self._remove(owner_id)

    def _broadcast(self, value: dict[str, Any]) -> None:
        with self.clients_lock:
            clients = list(self.clients.items())
        dead = [client_id for client_id, client in clients if not client.enqueue(value)]
        for client_id in dead:
            self._remove(client_id)

    def _remove(self, client_id: str) -> None:
        with self.clients_lock:
            client = self.clients.pop(client_id, None)
        if client:
            client.close()

    def _correlation_payload(self, request: Request) -> dict[str, Any]:
        return {
            "broker_epoch": self.broker_epoch,
            "broker_response_connection_id": request.owner_id,
            "broker_request_id": request.request_id,
            "broker_request_upstream_seq": request.upstream_seq,
            "broker_request_downstream_seq": request.client_seq,
            "broker_request_kind": request.frame["kind"],
            "broker_request_sha256": request.request_sha256,
            "broker_ordering_key": request.ordering_key,
        }

    def _result(self, request: Request, frame: dict[str, Any]) -> dict[str, Any]:
        return {
            "schema": WIRE,
            "kind": "result",
            "request_id": request.request_id,
            **self._correlation_payload(request),
            "frame": frame,
            "automatic_redispatch": False,
        }

    @staticmethod
    def _error(request_id: str | None, code: str, message: str) -> dict[str, Any]:
        return {
            "schema": WIRE,
            "kind": "error",
            "request_id": request_id,
            "code": code,
            "message": message,
            "automatic_redispatch": False,
        }

    def _request_error(
        self,
        request: Request,
        code: str,
        message: str,
    ) -> dict[str, Any]:
        return {
            **self._error(request.request_id, code, message),
            **self._correlation_payload(request),
        }
