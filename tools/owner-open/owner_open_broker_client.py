#!/usr/bin/env python3
"""STDIO Host-compatible client for the owner-open multi-connection broker."""
from __future__ import annotations

import argparse
from pathlib import Path
import socket
import sys
from typing import Any

from owner_open_broker_common import (
    BrokerError,
    canonical,
    read_line,
    read_private_bytes,
    read_private_json,
    require_id,
    require_token,
    strict_json,
    validate_descriptor,
)

WIRE_SCHEMA = "org.trillionnium.owner-open.connection-broker-wire.v1"
MAX_TIMEOUT_MS = 600_000


def expected_for(frame: dict[str, Any]) -> tuple[list[str], str | None]:
    kind = frame.get("kind")
    job_id = frame.get("job_id")
    payload = frame.get("payload")
    if job_id is None and isinstance(payload, dict):
        job_id = payload.get("job_id")
    mapping = {
        "job.start": ["job.start.result"],
        "job.inspect": ["job.inspect.result"],
        "job.wait": ["job.inspect.result"],
        "job.attach": ["job.attach.result"],
        "job.detach": ["job.detach.result"],
        "job.write": ["job.control.result"],
        "job.resize": ["job.control.result"],
        "job.close_stdin": ["job.control.result"],
        "job.kill": ["job.control.result"],
        "turn.inspect": ["turn.inspect.result"],
        "call.inspect": ["call.inspect.result"],
        "turn.cancel": ["turn.cancel.accepted", "turn.end"],
        "tool.cancel": ["tool.cancel.accepted", "tool.result"],
    }
    expected = mapping.get(kind)
    if expected is None:
        raise BrokerError(f"broker client has no finite response mapping for Host frame {kind}")
    return expected, require_id(job_id, "job_id") if job_id is not None else None


def write_frame(value: dict[str, Any]) -> None:
    sys.stdout.buffer.write(canonical(value) + b"\n")
    sys.stdout.buffer.flush()


class Client:
    def __init__(self, args: argparse.Namespace) -> None:
        descriptor, _ = read_private_json(args.descriptor, label="broker descriptor")
        validate_descriptor(descriptor)
        self.descriptor = descriptor
        self.broker_epoch = require_id(descriptor.get("broker_epoch"), "broker_epoch")
        token_path = Path(descriptor["token_file"])
        token_raw = read_private_bytes(token_path, label="broker token", maximum=256)
        try:
            token = require_token(token_raw.decode("ascii").strip())
        except UnicodeDecodeError as error:
            raise BrokerError("broker token is not ASCII") from error
        self.client_id = require_id(args.client_id, "client_id")
        self.timeout_ms = args.timeout_ms
        self.connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.connection.connect(descriptor["socket_path"])
        self.stream = self.connection.makefile("rb", buffering=0)
        self.connection.sendall(
            canonical(
                {
                    "schema": WIRE_SCHEMA,
                    "kind": "broker.hello",
                    "broker_epoch": self.broker_epoch,
                    "client_id": self.client_id,
                    "token": token,
                }
            )
            + b"\n"
        )
        raw = read_line(self.stream, label="broker hello ack")
        if raw is None:
            raise BrokerError("broker disconnected during hello")
        ack = strict_json(raw, label="broker hello ack")
        if not isinstance(ack, dict) or ack.get("kind") != "broker.hello.ack":
            raise BrokerError(f"broker rejected client hello: {ack}")
        if ack.get("broker_epoch") != self.broker_epoch:
            raise BrokerError("broker hello ack epoch differs from the descriptor")
        if ack.get("descriptor_sha256") != descriptor.get("descriptor_sha256"):
            raise BrokerError("broker hello ack descriptor digest differs from the loaded descriptor")
        self.host_hello_ack = ack.get("host_hello_ack")
        if not isinstance(self.host_hello_ack, dict):
            raise BrokerError("broker hello ack has no upstream Host hello.ack")
        self.next_request = 0

    def close(self) -> None:
        try:
            self.stream.close()
        except OSError:
            pass
        try:
            self.connection.close()
        except OSError:
            pass

    def transact(self, frame: dict[str, Any]) -> None:
        if frame.get("kind") == "hello":
            ack = dict(self.host_hello_ack)
            ack["seq"] = 0
            payload = dict(ack.get("payload") or {})
            payload.update(
                {
                    "connection_broker": True,
                    "broker_id": self.descriptor["broker_id"],
                    "broker_epoch": self.broker_epoch,
                    "broker_descriptor_sha256": self.descriptor["descriptor_sha256"],
                }
            )
            ack["payload"] = payload
            write_frame(ack)
            return
        expected, job_id = expected_for(frame)
        request_id = f"{self.client_id}-{self.broker_epoch}-{self.next_request}"
        self.next_request += 1
        self.connection.sendall(
            canonical(
                {
                    "schema": WIRE_SCHEMA,
                    "kind": "request",
                    "request_id": request_id,
                    "frame": frame,
                    "expected_kinds": expected,
                    "expected_job_id": job_id,
                    "timeout_ms": self.timeout_ms,
                }
            )
            + b"\n"
        )
        while True:
            raw = read_line(self.stream, label="broker response")
            if raw is None:
                raise BrokerError("broker disconnected with request unresolved")
            value = strict_json(raw, label="broker response")
            if not isinstance(value, dict):
                raise BrokerError("broker response is not an object")
            kind = value.get("kind")
            if kind == "observation":
                observed = value.get("frame")
                if isinstance(observed, dict):
                    write_frame(observed)
                continue
            if kind == "result" and value.get("request_id") == request_id:
                return
            if kind == "error" and value.get("request_id") in {None, request_id}:
                error_kind = "job.error" if job_id else "host.error"
                write_frame(
                    {
                        "kind": error_kind,
                        "seq": 0,
                        "direction": "host_to_client",
                        "job_id": job_id,
                        "payload": {
                            "code": value.get("code", "broker_error"),
                            "message": value.get("message", "broker request failed"),
                            "automatic_redispatch": False,
                        },
                    }
                )
                return


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--descriptor", required=True, type=Path)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--timeout-ms", type=int, default=30_000)
    args = parser.parse_args(argv)
    if not 1 <= args.timeout_ms <= MAX_TIMEOUT_MS:
        parser.error("--timeout-ms is outside the finite bound")
    return args


def main(argv: list[str]) -> int:
    client: Client | None = None
    try:
        client = Client(parse_args(argv))
        while True:
            raw = read_line(sys.stdin.buffer, label="Host request")
            if raw is None:
                return 0
            frame = strict_json(raw, label="Host request")
            if not isinstance(frame, dict):
                raise BrokerError("Host request must be an object")
            client.transact(frame)
    except (BrokerError, OSError) as error:
        print(f"owner-open broker client failed: {error}", file=sys.stderr)
        return 2
    finally:
        if client:
            client.close()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
