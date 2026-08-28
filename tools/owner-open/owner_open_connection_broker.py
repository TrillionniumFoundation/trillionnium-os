#!/usr/bin/env python3
"""Mechanism-only multi-connection broker for one owner-open Host process."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import Any

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
from owner_open_broker_runtime import Client, Request, frame_job_id, peer_credentials

SCHEMA = "org.trillionnium.owner-open.connection-broker.v1"
WIRE = "org.trillionnium.owner-open.connection-broker-wire.v1"
DEFAULT_TIMEOUT_MS = 30_000
MAX_TIMEOUT_MS = 600_000


class Broker:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.token = load_or_create_token(args.token_file)
        self.clients: dict[str, Client] = {}
        self.clients_lock = threading.Lock()
        self.requests: queue.Queue[Request] = queue.Queue(args.max_pending_requests)
        self.pending: Request | None = None
        self.pending_condition = threading.Condition()
        self.stopping = threading.Event()
        self.upstream_uncertain = threading.Event()
        self.next_upstream_seq = 1
        self.upstream_stderr = bytearray()
        self.upstream_stderr_lock = threading.Lock()
        self.upstream_argv = [str(args.upstream), *args.upstream_arg]
        validate_argv(self.upstream_argv)
        upstream_identity = validate_executable(args.upstream, "--upstream")
        self.upstream = subprocess.Popen(
            self.upstream_argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            bufsize=0,
        )
        assert self.upstream.stdin and self.upstream.stdout and self.upstream.stderr
        threading.Thread(
            target=self._drain_stderr,
            daemon=True,
            name="broker-upstream-stderr",
        ).start()
        self.host_hello_ack = self._handshake()
        self.descriptor = finalize_descriptor(
            {
                "schema": SCHEMA,
                "broker_id": args.broker_id,
                "socket_path": str(args.socket),
                "token_file": str(args.token_file),
                "service_uid": os.geteuid(),
                "response_model": (
                    "broker_correlated_result_owner_with_broadcast_observation"
                ),
                "max_clients": args.max_clients,
                "client_queue_frames": args.client_queue_frames,
                "client_queue_bytes": args.client_queue_bytes,
                "max_pending_requests": args.max_pending_requests,
                "upstream": upstream_identity,
                "upstream_argv_sha256": hashlib.sha256(
                    canonical(self.upstream_argv)
                ).hexdigest(),
                "host_hello_ack": self.host_hello_ack,
                "automatic_redispatch": False,
            }
        )

    def _drain_stderr(self) -> None:
        while not self.stopping.is_set():
            try:
                chunk = self.upstream.stderr.read(8192)
            except OSError:
                return
            if not chunk:
                return
            with self.upstream_stderr_lock:
                remaining = 1024 * 1024 - len(self.upstream_stderr)
                self.upstream_stderr.extend(chunk[: max(0, remaining)])

    def _handshake(self) -> dict[str, Any]:
        request = {
            "kind": "hello",
            "seq": 0,
            "direction": "client_to_host",
            "payload": {
                "protocol": "trillionnium.agent.turn.v1",
                "protocol_version": 1,
            },
        }
        self.upstream.stdin.write(canonical(request) + b"\n")
        self.upstream.stdin.flush()
        raw = read_line(self.upstream.stdout, label="upstream hello")
        if raw is None:
            raise BrokerError("upstream exited before hello.ack")
        value = strict_json(raw, label="upstream hello")
        if not isinstance(value, dict) or value.get("kind") != "hello.ack":
            raise BrokerError("upstream first response is not hello.ack")
        return value

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

    def _upstream_reader(self) -> None:
        try:
            while not self.stopping.is_set():
                raw = read_line(self.upstream.stdout, label="upstream frame")
                if raw is None:
                    raise BrokerError("upstream disconnected")
                frame = strict_json(raw, label="upstream frame")
                if not isinstance(frame, dict) or not isinstance(frame.get("kind"), str):
                    raise BrokerError("upstream frame has no valid kind")
                self._broadcast(
                    {
                        "schema": WIRE,
                        "kind": "observation",
                        "frame": frame,
                        "automatic_redispatch": False,
                    }
                )
                with self.pending_condition:
                    pending = self.pending
                    if pending and frame["kind"] in pending.expected_kinds:
                        job_id = frame_job_id(frame)
                        if pending.expected_job_id is None or job_id == pending.expected_job_id:
                            self._owner(
                                pending.owner_id,
                                {
                                    "schema": WIRE,
                                    "kind": "result",
                                    "request_id": pending.request_id,
                                    "frame": frame,
                                    "automatic_redispatch": False,
                                },
                            )
                            self.pending = None
                            self.pending_condition.notify_all()
        except Exception as error:
            self._mark_upstream_unknown(error)

    def _mark_upstream_unknown(self, error: Exception) -> None:
        self.upstream_uncertain.set()
        with self.pending_condition:
            pending, self.pending = self.pending, None
            self.pending_condition.notify_all()
        if pending:
            self._owner(
                pending.owner_id,
                {
                    "schema": WIRE,
                    "kind": "error",
                    "request_id": pending.request_id,
                    "code": "unknown_after_disconnect",
                    "message": str(error),
                    "automatic_redispatch": False,
                },
            )
        self._broadcast(
            {
                "schema": WIRE,
                "kind": "broker.status",
                "status": "upstream_unavailable",
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
            if self.upstream_uncertain.is_set():
                self._owner(
                    request.owner_id,
                    self._error(
                        request.request_id,
                        "upstream_uncertain",
                        "broker refuses dispatch after uncertain upstream state",
                    ),
                )
                continue
            frame = dict(request.frame)
            frame.update(seq=self.next_upstream_seq, direction="client_to_host")
            self.next_upstream_seq += 1
            with self.pending_condition:
                self.pending = request
            try:
                self.upstream.stdin.write(canonical(frame) + b"\n")
                self.upstream.stdin.flush()
            except OSError as error:
                self._mark_upstream_unknown(error)
                return
            deadline = time.monotonic() + request.timeout_ms / 1000
            with self.pending_condition:
                while self.pending is request and not self.stopping.is_set():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self.pending = None
                        self.upstream_uncertain.set()
                        self._owner(
                            request.owner_id,
                            self._error(
                                request.request_id,
                                "unknown_after_timeout",
                                "accepted request did not reach a correlated result before deadline",
                            ),
                        )
                        break
                    self.pending_condition.wait(min(remaining, 0.1))

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
        client.enqueue(
            {
                "schema": WIRE,
                "kind": "broker.hello.ack",
                "broker_id": self.args.broker_id,
                "client_id": client_id,
                "descriptor_sha256": self.descriptor["descriptor_sha256"],
                "host_hello_ack": self.host_hello_ack,
                "peer": {"pid": pid, "uid": uid, "gid": gid},
                "automatic_redispatch": False,
            }
        )
        return client

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
                frame, expected = value.get("frame"), value.get("expected_kinds")
                if not isinstance(frame, dict) or not isinstance(frame.get("kind"), str):
                    raise BrokerError("broker request frame is invalid")
                if not isinstance(expected, list) or not expected or any(
                    not isinstance(item, str) or not item for item in expected
                ):
                    raise BrokerError("expected_kinds must be a non-empty string list")
                expected_job = value.get("expected_job_id")
                if expected_job is not None:
                    expected_job = require_id(expected_job, "expected_job_id")
                timeout_ms = value.get("timeout_ms", DEFAULT_TIMEOUT_MS)
                if (
                    isinstance(timeout_ms, bool)
                    or not isinstance(timeout_ms, int)
                    or not 1 <= timeout_ms <= MAX_TIMEOUT_MS
                ):
                    raise BrokerError("timeout_ms is outside the finite bound")
                try:
                    self.requests.put_nowait(
                        Request(
                            client.client_id,
                            request_id,
                            frame,
                            frozenset(expected),
                            expected_job,
                            timeout_ms,
                        )
                    )
                except queue.Full:
                    client.enqueue(
                        self._error(
                            request_id,
                            "resource_exhausted",
                            "broker pending request queue is full",
                        )
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

    def serve(self) -> int:
        validate_socket_path(self.args.socket)
        signal.signal(signal.SIGTERM, lambda *_: self.stopping.set())
        signal.signal(signal.SIGINT, lambda *_: self.stopping.set())
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.args.socket))
        os.chmod(self.args.socket, 0o600)
        listener.listen(self.args.max_clients)
        listener.settimeout(0.2)
        atomic_write_private(
            self.args.descriptor,
            json.dumps(self.descriptor, indent=2, sort_keys=True).encode() + b"\n",
            label="broker descriptor",
        )
        threading.Thread(target=self._upstream_reader, daemon=True).start()
        threading.Thread(target=self._request_worker, daemon=True).start()
        try:
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
            listener.close()
            with self.clients_lock:
                clients, self.clients = list(self.clients.values()), {}
            for client in clients:
                client.close()
            self.args.socket.unlink(missing_ok=True)
            self._stop_upstream()
        return 0

    def _stop_upstream(self) -> None:
        if self.upstream.poll() is None:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(self.upstream.pid, sig)
                except ProcessLookupError:
                    break
                try:
                    self.upstream.wait(timeout=1)
                    break
                except subprocess.TimeoutExpired:
                    continue
        for pipe in (self.upstream.stdin, self.upstream.stdout, self.upstream.stderr):
            try:
                pipe.close()
            except OSError:
                pass


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--descriptor", required=True, type=Path)
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--broker-id", required=True)
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--upstream-arg", action="append", default=[])
    parser.add_argument("--max-clients", type=int, default=16)
    parser.add_argument("--client-queue-frames", type=int, default=1024)
    parser.add_argument("--client-queue-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--max-pending-requests", type=int, default=256)
    args = parser.parse_args(argv)
    args.broker_id = require_id(args.broker_id, "broker_id")
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
