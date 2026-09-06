#!/usr/bin/env python3
"""Bounded byte-transparent loopback relay for an ordinary ADB smart socket.

The relay does not parse ADB framing or service strings. It only transports
bytes between a local loopback listener and one configured upstream endpoint.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import stat
import sys
import threading
import time
from typing import Any, BinaryIO

DESCRIPTOR_SCHEMA = "org.trillionnium.owner-open.adb-smart-socket-relay.v1"
EVENT_SCHEMA = "org.trillionnium.owner-open.adb-smart-socket-relay-event.v1"
DEFAULT_MAX_CLIENTS = 16
DEFAULT_BUFFER_BYTES = 1024 * 1024
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_IDLE_TIMEOUT = 300.0
POLL_SECONDS = 0.05
READ_BYTES = 64 * 1024


class RelayError(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def loopback_address(value: str, label: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise RelayError(f"{label} must be a numeric IP address") from error
    if not address.is_loopback:
        raise RelayError(f"{label} must be loopback; network exposure is not allowed")
    return str(address)


def private_new_file(path: Path, label: str) -> BinaryIO:
    if not path.is_absolute() or not path.parent.is_dir() or path.parent.is_symlink():
        raise RelayError(f"{label} must be an absolute new path with a real parent")
    parent = path.parent.lstat()
    mode = stat.S_IMODE(parent.st_mode)
    trusted = parent.st_uid in {0, os.geteuid()}
    root_sticky = parent.st_uid == 0 and bool(mode & stat.S_ISVTX)
    if not trusted or (mode & 0o022 and not root_sticky):
        raise RelayError(f"{label} parent is not owner controlled")
    if path.exists() or path.is_symlink():
        raise RelayError(f"{label} already exists")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    return os.fdopen(descriptor, "wb", buffering=0)


def atomic_private_json(path: Path, value: dict[str, Any]) -> None:
    if not path.is_absolute() or not path.parent.is_dir() or path.parent.is_symlink():
        raise RelayError("descriptor path must be absolute with a real parent")
    if path.exists() or path.is_symlink():
        raise RelayError("descriptor path already exists")
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}"
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise RelayError("descriptor write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


class EventWriter:
    def __init__(self, handle: BinaryIO | None) -> None:
        self.handle = handle
        self.lock = threading.Lock()
        self.sequence = 0
        self.started = time.monotonic()

    def append(self, kind: str, **fields: Any) -> None:
        if self.handle is None:
            return
        with self.lock:
            record = {
                "schema": EVENT_SCHEMA,
                "sequence": self.sequence,
                "elapsed_ms": max(0, int((time.monotonic() - self.started) * 1000)),
                "kind": kind,
                **fields,
            }
            raw = canonical(record) + b"\n"
            self.handle.write(raw)
            self.handle.flush()
            os.fsync(self.handle.fileno())
            self.sequence += 1


@dataclass(frozen=True)
class Limits:
    max_clients: int
    buffer_bytes: int
    connect_timeout: float
    idle_timeout: float

    def validate(self) -> None:
        if not 1 <= self.max_clients <= 1024:
            raise RelayError("max clients must be between 1 and 1024")
        if not 4096 <= self.buffer_bytes <= 64 * 1024 * 1024:
            raise RelayError("buffer bytes must be between 4096 and 67108864")
        if not 0.1 <= self.connect_timeout <= 120:
            raise RelayError("connect timeout is outside the finite bound")
        if not 1 <= self.idle_timeout <= 86400:
            raise RelayError("idle timeout is outside the finite bound")


@dataclass
class Side:
    sock: socket.socket
    name: str
    read_open: bool = True
    write_open: bool = True


def safe_shutdown(sock: socket.socket, how: int) -> None:
    try:
        sock.shutdown(how)
    except OSError:
        pass


def relay_connection(
    connection_id: int,
    client_socket: socket.socket,
    upstream_address: tuple[str, int],
    limits: Limits,
    events: EventWriter,
    stopping: threading.Event,
) -> None:
    upstream: socket.socket | None = None
    selector = selectors.DefaultSelector()
    client = Side(client_socket, "client")
    c2u = bytearray()
    u2c = bytearray()
    client_eof_pending = False
    upstream_eof_pending = False
    bytes_client_to_upstream = 0
    bytes_upstream_to_client = 0
    started = time.monotonic()
    last_progress = started
    terminal = "completed"
    error_text: str | None = None
    try:
        client_socket.setblocking(False)
        client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        upstream = socket.create_connection(upstream_address, timeout=limits.connect_timeout)
        upstream.setblocking(False)
        upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        server = Side(upstream, "upstream")
        selector.register(client.sock, selectors.EVENT_READ, client)
        selector.register(server.sock, selectors.EVENT_READ, server)
        events.append("connection_started", connection_id=connection_id)

        while not stopping.is_set():
            if time.monotonic() - last_progress > limits.idle_timeout:
                terminal = "idle_timeout"
                break
            if client_eof_pending and not c2u and server.write_open:
                safe_shutdown(server.sock, socket.SHUT_WR)
                server.write_open = False
                client_eof_pending = False
            if upstream_eof_pending and not u2c and client.write_open:
                safe_shutdown(client.sock, socket.SHUT_WR)
                client.write_open = False
                upstream_eof_pending = False
            if not client.read_open and not server.read_open and not c2u and not u2c:
                break

            for key in list(selector.get_map().values()):
                side: Side = key.data
                mask = 0
                if side.read_open:
                    if side is client and len(c2u) < limits.buffer_bytes:
                        mask |= selectors.EVENT_READ
                    elif side is server and len(u2c) < limits.buffer_bytes:
                        mask |= selectors.EVENT_READ
                if side is client and u2c and client.write_open:
                    mask |= selectors.EVENT_WRITE
                if side is server and c2u and server.write_open:
                    mask |= selectors.EVENT_WRITE
                if mask:
                    selector.modify(side.sock, mask, side)

            selected = selector.select(POLL_SECONDS)
            for key, mask in selected:
                side: Side = key.data
                if mask & selectors.EVENT_READ:
                    try:
                        chunk = side.sock.recv(READ_BYTES)
                    except BlockingIOError:
                        chunk = None
                    if chunk == b"":
                        side.read_open = False
                        if side is client:
                            client_eof_pending = True
                        else:
                            upstream_eof_pending = True
                    elif chunk:
                        target = c2u if side is client else u2c
                        if len(target) + len(chunk) > limits.buffer_bytes:
                            terminal = "resource_exhausted"
                            raise RelayError(f"{side.name} direction exceeded the bounded buffer")
                        target.extend(chunk)
                        last_progress = time.monotonic()
                if mask & selectors.EVENT_WRITE:
                    pending = u2c if side is client else c2u
                    if pending:
                        try:
                            written = side.sock.send(pending)
                        except BlockingIOError:
                            written = 0
                        if written > 0:
                            del pending[:written]
                            if side is client:
                                bytes_upstream_to_client += written
                            else:
                                bytes_client_to_upstream += written
                            last_progress = time.monotonic()
        if stopping.is_set() and terminal == "completed":
            terminal = "relay_shutdown"
    except Exception as error:
        if terminal == "completed":
            terminal = "transport_error"
        error_text = f"{type(error).__name__}: {error}"
    finally:
        selector.close()
        for sock in (client_socket, upstream):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        events.append(
            "connection_terminal",
            connection_id=connection_id,
            terminal=terminal,
            error=error_text,
            client_to_upstream_bytes=bytes_client_to_upstream,
            upstream_to_client_bytes=bytes_upstream_to_client,
            elapsed_ms=max(0, int((time.monotonic() - started) * 1000)),
            payload_logged=False,
            automatic_redispatch=False,
        )


class RelayServer:
    def __init__(
        self,
        listen: tuple[str, int],
        upstream: tuple[str, int],
        limits: Limits,
        events: EventWriter,
    ) -> None:
        self.listen = listen
        self.upstream = upstream
        self.limits = limits
        self.events = events
        self.stopping = threading.Event()
        self.listener: socket.socket | None = None
        self.semaphore = threading.BoundedSemaphore(limits.max_clients)
        self.threads: list[threading.Thread] = []
        self.next_connection_id = 0

    def stop(self) -> None:
        self.stopping.set()
        if self.listener is not None:
            try:
                self.listener.close()
            except OSError:
                pass

    def serve(self, descriptor: Path | None) -> int:
        family = socket.AF_INET6 if ":" in self.listen[0] else socket.AF_INET
        listener = socket.socket(family, socket.SOCK_STREAM)
        self.listener = listener
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(self.listen)
        listener.listen(self.limits.max_clients)
        listener.settimeout(POLL_SECONDS)
        address = listener.getsockname()
        if descriptor is not None:
            atomic_private_json(
                descriptor,
                {
                    "schema": DESCRIPTOR_SCHEMA,
                    "pid": os.getpid(),
                    "listen_host": self.listen[0],
                    "listen_port": address[1],
                    "upstream_host": self.upstream[0],
                    "upstream_port": self.upstream[1],
                    "adb_server_socket": f"tcp:{self.listen[0]}:{address[1]}",
                    "max_clients": self.limits.max_clients,
                    "buffer_bytes_per_direction": self.limits.buffer_bytes,
                    "connect_timeout_seconds": self.limits.connect_timeout,
                    "idle_timeout_seconds": self.limits.idle_timeout,
                    "byte_transparent": True,
                    "adb_protocol_parsed": False,
                    "argv_or_serial_injected": False,
                    "payload_logged": False,
                    "automatic_redispatch": False,
                },
            )
        self.events.append(
            "relay_ready",
            listen_host=self.listen[0],
            listen_port=address[1],
            upstream_host=self.upstream[0],
            upstream_port=self.upstream[1],
        )
        try:
            while not self.stopping.is_set():
                try:
                    client, _peer = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self.stopping.is_set():
                        break
                    raise
                if not self.semaphore.acquire(blocking=False):
                    self.events.append("connection_rejected", reason="max_clients")
                    client.close()
                    continue
                connection_id = self.next_connection_id
                self.next_connection_id += 1

                def worker(sock: socket.socket, identifier: int) -> None:
                    try:
                        relay_connection(
                            identifier,
                            sock,
                            self.upstream,
                            self.limits,
                            self.events,
                            self.stopping,
                        )
                    finally:
                        self.semaphore.release()

                thread = threading.Thread(
                    target=worker,
                    args=(client, connection_id),
                    daemon=True,
                    name=f"owner-open-adb-relay-{connection_id}",
                )
                self.threads.append(thread)
                thread.start()
        finally:
            self.stop()
            for thread in self.threads:
                thread.join(timeout=2)
            self.events.append("relay_terminal", active_threads=sum(thread.is_alive() for thread in self.threads))
        return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", required=True, type=int)
    parser.add_argument("--upstream-host", default="127.0.0.1")
    parser.add_argument("--upstream-port", required=True, type=int)
    parser.add_argument("--max-clients", type=int, default=DEFAULT_MAX_CLIENTS)
    parser.add_argument("--buffer-bytes", type=int, default=DEFAULT_BUFFER_BYTES)
    parser.add_argument("--connect-timeout", type=float, default=DEFAULT_CONNECT_TIMEOUT)
    parser.add_argument("--idle-timeout", type=float, default=DEFAULT_IDLE_TIMEOUT)
    parser.add_argument("--descriptor", type=Path)
    parser.add_argument("--events", type=Path)
    result = parser.parse_args(argv)
    result.listen_host = loopback_address(result.listen_host, "listen host")
    result.upstream_host = loopback_address(result.upstream_host, "upstream host")
    if not 0 <= result.listen_port <= 65535 or not 1 <= result.upstream_port <= 65535:
        parser.error("listen or upstream port is invalid")
    Limits(
        result.max_clients,
        result.buffer_bytes,
        result.connect_timeout,
        result.idle_timeout,
    ).validate()
    return result


def main(argv: list[str]) -> int:
    try:
        args = parse_args(argv)
        limits = Limits(
            args.max_clients,
            args.buffer_bytes,
            args.connect_timeout,
            args.idle_timeout,
        )
        event_handle = private_new_file(args.events, "event log") if args.events else None
        events = EventWriter(event_handle)
        server = RelayServer(
            (args.listen_host, args.listen_port),
            (args.upstream_host, args.upstream_port),
            limits,
            events,
        )
        for current in (signal.SIGTERM, signal.SIGINT):
            signal.signal(current, lambda _signum, _frame: server.stop())
        try:
            return server.serve(args.descriptor)
        finally:
            if event_handle is not None:
                event_handle.close()
    except (OSError, RelayError) as error:
        print(f"owner-open ADB relay failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
