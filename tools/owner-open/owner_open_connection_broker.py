#!/usr/bin/env python3
"""Mechanism-only multi-connection broker for one owner-open Host process."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import secrets
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from typing import Any

from owner_open_broker_audit import AuditBinding, BrokerAuditJournal
from owner_open_broker_common import (
    BrokerError,
    atomic_write_private,
    canonical,
    compare_token,
    finalize_descriptor,
    load_or_create_token,
    read_line,
    require_id,
    require_token,
    strict_json,
    validate_argv,
    validate_executable,
    validate_socket_path,
)
from owner_open_broker_runtime import (
    Client,
    Request,
    correlation_matches,
    frame_correlation,
    frame_job_id,
    peer_credentials,
    response_matches,
)

SCHEMA = "org.trillionnium.owner-open.connection-broker.v1"
WIRE = "org.trillionnium.owner-open.connection-broker-wire.v1"
DEFAULT_TIMEOUT_MS = 30_000
MAX_TIMEOUT_MS = 600_000
MAX_EXPECTED_KINDS = 32


class Broker:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.token = load_or_create_token(args.token_file)
        self.token_epoch = hashlib.sha256(self.token.encode("ascii")).hexdigest()[:32]
        self.broker_epoch = secrets.token_hex(16)
        self.clients: dict[str, Client] = {}
        self.clients_lock = threading.Lock()
        self.requests: queue.Queue[Request] = queue.Queue(args.max_pending_requests)
        self.request_slots = threading.BoundedSemaphore(args.max_pending_requests)
        self.active_request: Request | None = None
        self.active_condition = threading.Condition()
        self.admission_lock = threading.Lock()
        self.sequence_lock = threading.Lock()
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
        threading.Thread(
            target=self._drain_stderr,
            daemon=True,
            name="broker-upstream-stderr",
        ).start()
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
                "response_model": (
                    "broker_correlated_result_owner_with_broadcast_observation"
                ),
                "max_clients": self.args.max_clients,
                "client_queue_frames": self.args.client_queue_frames,
                "client_queue_bytes": self.args.client_queue_bytes,
                "max_pending_requests": self.args.max_pending_requests,
                "max_inflight_requests": 1,
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

    def _finish_active(
        self,
        request: Request,
        owner_message: dict[str, Any],
        *,
        details: dict[str, Any],
    ) -> bool:
        try:
            self.audit.terminal(
                request.audit_binding,
                owner_message=owner_message,
                details=details,
            )
        except BrokerError as error:
            self.upstream_uncertain.set()
            self._owner(
                request.owner_id,
                self._request_error(
                    request,
                    "broker_terminal_audit_failed",
                    str(error),
                ),
            )
            self.stopping.set()
            completed = False
        else:
            self._owner(request.owner_id, owner_message)
            completed = True
        with self.active_condition:
            if self.active_request is request:
                self.active_request = None
            self.active_condition.notify_all()
        return completed

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
                self._broadcast(
                    {
                        "schema": WIRE,
                        "kind": "observation",
                        "broker_epoch": self.broker_epoch,
                        "frame": frame,
                        "automatic_redispatch": False,
                    }
                )
                with self.active_condition:
                    active = self.active_request
                if active is None:
                    continue
                direct_error = frame["kind"] in {"host.error", "job.error"}
                if response_matches(active, frame) or (
                    direct_error and correlation_matches(active, frame)
                ):
                    self._finish_active(
                        active,
                        self._result(active, frame),
                        details={
                            "status": "host_terminal_observed",
                            "frame_kind": frame["kind"],
                            "frame_sha256": hashlib.sha256(canonical(frame)).hexdigest(),
                        },
                    )
        except Exception as error:
            self._mark_upstream_unknown(error)

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
            with self.active_condition:
                active, self.active_request = self.active_request, None
                self.active_condition.notify_all()
            if active:
                owner_message = self._request_error(active, code, str(error))
                try:
                    self.audit.terminal(
                        active.audit_binding,
                        owner_message=owner_message,
                        details={
                            "status": code,
                            "effect_may_have_started": active.audit_binding.stage
                            == "broker.forwarded",
                        },
                    )
                except BrokerError:
                    pass
                self._owner(active.owner_id, owner_message)
            self._broadcast(
                {
                    "schema": WIRE,
                    "kind": "broker.status",
                    "broker_epoch": self.broker_epoch,
                    "status": "upstream_unavailable",
                    "code": code,
                    "message": str(error),
                    "automatic_redispatch": False,
                }
            )
            self.stopping.set()

    def _request_worker(self) -> None:
        while not self.stopping.is_set():
            try:
                request = self.requests.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
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
                    )
                    continue
                frame.update(
                    seq=request.upstream_seq,
                    client_seq=request.client_seq,
                    direction="client_to_host",
                    broker_request_id=request.request_id,
                    broker_request_sha256=request.request_sha256,
                )
                encoded = canonical(frame) + b"\n"
                with self.active_condition:
                    self.active_request = request
                try:
                    upstream.stdin.write(encoded)
                    upstream.stdin.flush()
                except OSError as error:
                    self._mark_upstream_unknown(error)
                    return
                try:
                    self.audit.forwarded(
                        request.audit_binding,
                        frame_sha256=hashlib.sha256(encoded).hexdigest(),
                        frame_bytes=len(encoded),
                    )
                except BrokerError as error:
                    self._mark_upstream_unknown(error)
                    return
                deadline = time.monotonic() + request.timeout_ms / 1000
                with self.active_condition:
                    while self.active_request is request and not self.stopping.is_set():
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            break
                        self.active_condition.wait(min(remaining, 0.1))
                    timed_out = self.active_request is request
                if timed_out:
                    self._mark_upstream_unknown(
                        BrokerError(
                            "accepted request did not reach a correlated result before deadline"
                        ),
                        code="unknown_after_timeout",
                    )
                    return
            finally:
                self.request_slots.release()
                self.requests.task_done()

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
        threading.Thread(
            target=client.writer,
            daemon=True,
            name=f"broker-writer-{client_id}",
        ).start()
        if self.descriptor is None or self.host_hello_ack is None:
            raise BrokerError("broker descriptor is unavailable")
        client.enqueue(
            {
                "schema": WIRE,
                "kind": "broker.hello.ack",
                "broker_id": self.args.broker_id,
                "broker_epoch": self.broker_epoch,
                "token_epoch": self.token_epoch,
                "client_id": client_id,
                "descriptor_sha256": self.descriptor["descriptor_sha256"],
                "host_hello_ack": self.host_hello_ack,
                "peer": {"pid": pid, "uid": uid, "gid": gid},
                "automatic_redispatch": False,
            }
        )
        return client

    @staticmethod
    def _request_preimage(
        frame: dict[str, Any],
        expected: frozenset[str],
        expected_job: str | None,
        timeout_ms: int,
    ) -> dict[str, Any]:
        return {
            "frame": frame,
            "expected_kinds": sorted(expected),
            "expected_job_id": expected_job,
            "timeout_ms": timeout_ms,
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
        client_seq_value = frame.get("seq")
        preimage = self._request_preimage(frame, expected, expected_job, timeout_ms)
        request_sha256 = hashlib.sha256(canonical(preimage)).hexdigest()
        correlation = frame_correlation(frame)
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
            if not self.request_slots.acquire(blocking=False):
                client.enqueue(
                    self._error(
                        request_id,
                        "resource_exhausted",
                        "broker pending request capacity is exhausted before acceptance",
                    )
                )
                return
            with self.sequence_lock:
                upstream_seq = self.next_upstream_seq
                self.next_upstream_seq += 1
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
                )
                self.requests.put_nowait(request)
            except Exception as error:
                self.request_slots.release()
                client.enqueue(
                    self._error(
                        request_id,
                        "broker_acceptance_failed",
                        str(error),
                    )
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
                    connection.sendall(canonical(failure) + b"\n")
                except OSError:
                    pass
        finally:
            try:
                stream.close()
            except OSError:
                pass
            if client:
                self._remove(client.client_id)
            else:
                try:
                    connection.close()
                except OSError:
                    pass

    @staticmethod
    def _path_identity(path: Path, *, socket_path: bool = False) -> tuple[int, int]:
        metadata = path.lstat()
        if socket_path:
            if not stat.S_ISSOCK(metadata.st_mode):
                raise BrokerError("bound broker path is not a Unix socket")
        elif not stat.S_ISREG(metadata.st_mode):
            raise BrokerError("broker descriptor path is not a regular file")
        return metadata.st_dev, metadata.st_ino

    @staticmethod
    def _remove_proven_path(
        path: Path,
        identity: tuple[int, int] | None,
        *,
        socket_path: bool = False,
    ) -> None:
        if identity is None:
            return
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return
        correct_type = (
            stat.S_ISSOCK(metadata.st_mode)
            if socket_path
            else stat.S_ISREG(metadata.st_mode)
        )
        if correct_type and (metadata.st_dev, metadata.st_ino) == identity:
            path.unlink()

    def serve(self) -> int:
        validate_socket_path(self.args.socket)
        if self.args.socket.exists() or self.args.socket.is_symlink():
            raise BrokerError("refusing to replace an existing broker socket path")
        signal.signal(signal.SIGTERM, lambda *_: self.stopping.set())
        signal.signal(signal.SIGINT, lambda *_: self.stopping.set())
        try:
            self._start_upstream()
            self.descriptor = self._build_descriptor()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.listener = listener
            listener.bind(str(self.args.socket))
            os.chmod(self.args.socket, 0o600)
            self.socket_identity = self._path_identity(self.args.socket, socket_path=True)
            listener.listen(self.args.max_clients)
            listener.settimeout(0.2)
            atomic_write_private(
                self.args.descriptor,
                json.dumps(self.descriptor, indent=2, sort_keys=True).encode() + b"\n",
                label="broker descriptor",
            )
            self.descriptor_identity = self._path_identity(self.args.descriptor)
            threading.Thread(
                target=self._upstream_reader,
                daemon=True,
                name="broker-upstream-reader",
            ).start()
            threading.Thread(
                target=self._request_worker,
                daemon=True,
                name="broker-request-worker",
            ).start()
            while not self.stopping.is_set():
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                threading.Thread(
                    target=self._client_reader,
                    args=(connection,),
                    daemon=True,
                ).start()
        finally:
            self.stopping.set()
            if self.listener is not None:
                try:
                    self.listener.close()
                except OSError:
                    pass
            with self.clients_lock:
                clients, self.clients = list(self.clients.values()), {}
            for client in clients:
                client.close()
            self._remove_proven_path(
                self.args.socket,
                self.socket_identity,
                socket_path=True,
            )
            self._remove_proven_path(
                self.args.descriptor,
                self.descriptor_identity,
            )
            self._stop_upstream()
            self.audit.close()
        return 0

    def _stop_upstream(self) -> None:
        upstream = self.upstream
        if upstream is None:
            return
        if upstream.poll() is None:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(upstream.pid, sig)
                except ProcessLookupError:
                    break
                try:
                    upstream.wait(timeout=1)
                    break
                except subprocess.TimeoutExpired:
                    continue
        else:
            try:
                upstream.wait(timeout=0)
            except subprocess.TimeoutExpired:
                pass
        for pipe in (upstream.stdin, upstream.stdout, upstream.stderr):
            if pipe is None:
                continue
            try:
                pipe.close()
            except OSError:
                pass


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--descriptor", required=True, type=Path)
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--audit-file", type=Path)
    parser.add_argument("--broker-id", required=True)
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--upstream-arg", action="append", default=[])
    parser.add_argument("--max-clients", type=int, default=16)
    parser.add_argument("--client-queue-frames", type=int, default=1024)
    parser.add_argument("--client-queue-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--max-pending-requests", type=int, default=256)
    args = parser.parse_args(argv)
    args.broker_id = require_id(args.broker_id, "broker_id")
    if args.audit_file is None:
        args.audit_file = Path(f"{args.descriptor}.audit.jsonl")
    bounds = {
        "max_clients": 1024,
        "client_queue_frames": 65_536,
        "client_queue_bytes": 1024 * 1024 * 1024,
        "max_pending_requests": 65_536,
    }
    for field, maximum in bounds.items():
        if not 1 <= getattr(args, field) <= maximum:
            parser.error(f"--{field.replace('_', '-')} is outside the finite bound")
    return args


def main(argv: list[str]) -> int:
    try:
        return Broker(parse_args(argv)).serve()
    except (BrokerError, OSError, subprocess.SubprocessError) as error:
        print(f"owner-open broker failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
