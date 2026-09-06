#!/usr/bin/env python3
"""Bounded byte-transparent loopback relay for an ordinary ADB smart socket.

Version 2 uses asyncio backpressure, a bounded lifecycle journal, strict private
outputs, finite idle/shutdown handling and no ADB protocol interpretation.
"""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import stat
import sys
import time
from typing import Any, BinaryIO

DESCRIPTOR_SCHEMA = "org.trillionnium.owner-open.adb-smart-socket-relay.v2"
EVENT_SCHEMA = "org.trillionnium.owner-open.adb-smart-socket-relay-event.v2"
READ_BYTES = 64 * 1024
DEFAULT_MAX_CLIENTS = 16
DEFAULT_BUFFER_BYTES = 1024 * 1024
DEFAULT_EVENT_BYTES = 16 * 1024 * 1024
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_IDLE_TIMEOUT = 300.0
DEFAULT_SHUTDOWN_GRACE = 2.0


class RelayError(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def loopback(value: str, label: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise RelayError(f"{label} must be a numeric IP address") from error
    if not address.is_loopback:
        raise RelayError(f"{label} must be loopback")
    return str(address)


def validate_private_parent(path: Path, label: str) -> None:
    if not path.is_absolute() or not path.parent.is_dir() or path.parent.is_symlink():
        raise RelayError(f"{label} must be an absolute path with a real parent")
    metadata = path.parent.lstat()
    mode = stat.S_IMODE(metadata.st_mode)
    trusted = metadata.st_uid in {0, os.geteuid()}
    root_sticky = metadata.st_uid == 0 and bool(mode & stat.S_ISVTX)
    if not trusted or (mode & 0o022 and not root_sticky):
        raise RelayError(f"{label} parent is not owner controlled")
    if path.exists() or path.is_symlink():
        raise RelayError(f"{label} already exists")


def open_private_new(path: Path, label: str) -> BinaryIO:
    validate_private_parent(path, label)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    return os.fdopen(descriptor, "wb", buffering=0)


def atomic_private_json(path: Path, value: dict[str, Any]) -> None:
    validate_private_parent(path, "relay descriptor")
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
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
                raise RelayError("relay descriptor write made no progress")
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
    def __init__(self, handle: BinaryIO | None, maximum: int) -> None:
        self.handle = handle
        self.maximum = maximum
        self.bytes = 0
        self.sequence = 0
        self.started = time.monotonic()
        self.lock = asyncio.Lock()

    async def append(self, kind: str, **fields: Any) -> None:
        if self.handle is None:
            return
        async with self.lock:
            record = {
                "schema": EVENT_SCHEMA,
                "sequence": self.sequence,
                "elapsed_ms": max(0, int((time.monotonic() - self.started) * 1000)),
                "kind": kind,
                **fields,
            }
            raw = canonical(record) + b"\n"
            if self.bytes + len(raw) > self.maximum:
                raise RelayError("relay lifecycle journal exceeds the configured byte bound")
            self.handle.write(raw)
            self.handle.flush()
            os.fsync(self.handle.fileno())
            self.bytes += len(raw)
            self.sequence += 1


@dataclass(frozen=True)
class Limits:
    max_clients: int
    buffer_bytes: int
    event_bytes: int
    connect_timeout: float
    idle_timeout: float
    shutdown_grace: float

    def validate(self) -> None:
        if not 1 <= self.max_clients <= 1024:
            raise RelayError("max clients must be between 1 and 1024")
        if not 4096 <= self.buffer_bytes <= 64 * 1024 * 1024:
            raise RelayError("buffer bytes must be between 4096 and 67108864")
        if not 4096 <= self.event_bytes <= 256 * 1024 * 1024:
            raise RelayError("event bytes must be between 4096 and 268435456")
        if not 0.1 <= self.connect_timeout <= 120:
            raise RelayError("connect timeout is outside the finite bound")
        if not 1 <= self.idle_timeout <= 86400:
            raise RelayError("idle timeout is outside the finite bound")
        if not 0.1 <= self.shutdown_grace <= 60:
            raise RelayError("shutdown grace is outside the finite bound")


@dataclass
class ConnectionState:
    identifier: int
    last_activity: float
    client_to_upstream: int = 0
    upstream_to_client: int = 0
    terminal: str = "completed"
    error: str | None = None


async def half_close(writer: asyncio.StreamWriter) -> None:
    try:
        if writer.can_write_eof():
            writer.write_eof()
            await writer.drain()
        else:
            writer.close()
    except (ConnectionError, OSError, RuntimeError):
        writer.close()


async def pump(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    state: ConnectionState,
    direction: str,
) -> None:
    while True:
        chunk = await reader.read(READ_BYTES)
        if not chunk:
            await half_close(writer)
            return
        writer.write(chunk)
        await writer.drain()
        state.last_activity = time.monotonic()
        if direction == "client_to_upstream":
            state.client_to_upstream += len(chunk)
        else:
            state.upstream_to_client += len(chunk)


async def watchdog(state: ConnectionState, idle_timeout: float) -> None:
    interval = min(1.0, max(0.05, idle_timeout / 10))
    while True:
        await asyncio.sleep(interval)
        if time.monotonic() - state.last_activity > idle_timeout:
            state.terminal = "idle_timeout"
            raise RelayError("relay connection exceeded the idle timeout")


class RelayServer:
    def __init__(
        self,
        listen_host: str,
        listen_port: int,
        upstream_host: str,
        upstream_port: int,
        limits: Limits,
        events: EventWriter,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.limits = limits
        self.events = events
        self.semaphore = asyncio.Semaphore(limits.max_clients)
        self.stop_event = asyncio.Event()
        self.server: asyncio.Server | None = None
        self.tasks: set[asyncio.Task[None]] = set()
        self.next_connection = 0

    async def handle(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        if self.semaphore.locked():
            await self.events.append("connection_rejected", reason="max_clients")
            client_writer.close()
            await client_writer.wait_closed()
            return
        await self.semaphore.acquire()
        identifier = self.next_connection
        self.next_connection += 1
        task = asyncio.current_task()
        if task is not None:
            self.tasks.add(task)
        state = ConnectionState(identifier, time.monotonic())
        upstream_writer: asyncio.StreamWriter | None = None
        started = time.monotonic()
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(self.upstream_host, self.upstream_port),
                timeout=self.limits.connect_timeout,
            )
            for writer in (client_writer, upstream_writer):
                transport = writer.transport
                transport.set_write_buffer_limits(
                    high=self.limits.buffer_bytes,
                    low=max(1, self.limits.buffer_bytes // 4),
                )
            await self.events.append("connection_started", connection_id=identifier)
            pumps = [
                asyncio.create_task(
                    pump(client_reader, upstream_writer, state, "client_to_upstream"),
                    name=f"adb-relay-c2u-{identifier}",
                ),
                asyncio.create_task(
                    pump(upstream_reader, client_writer, state, "upstream_to_client"),
                    name=f"adb-relay-u2c-{identifier}",
                ),
                asyncio.create_task(
                    watchdog(state, self.limits.idle_timeout),
                    name=f"adb-relay-watchdog-{identifier}",
                ),
            ]
            done, pending = await asyncio.wait(pumps, return_when=asyncio.FIRST_EXCEPTION)
            error: BaseException | None = None
            for completed in done:
                try:
                    completed.result()
                except BaseException as caught:
                    error = caught
                    break
            if error is None:
                non_watchdog = pumps[:2]
                if all(item.done() for item in non_watchdog):
                    pumps[2].cancel()
                    await asyncio.gather(pumps[2], return_exceptions=True)
                else:
                    await asyncio.gather(*non_watchdog)
                    pumps[2].cancel()
                    await asyncio.gather(pumps[2], return_exceptions=True)
            else:
                for item in pending:
                    item.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                raise error
        except asyncio.CancelledError:
            state.terminal = "relay_shutdown"
            raise
        except Exception as error:
            if state.terminal == "completed":
                state.terminal = "transport_error"
            state.error = f"{type(error).__name__}: {error}"
        finally:
            for writer in (client_writer, upstream_writer):
                if writer is not None:
                    writer.close()
            for writer in (client_writer, upstream_writer):
                if writer is not None:
                    try:
                        await writer.wait_closed()
                    except (ConnectionError, OSError, RuntimeError):
                        pass
            await self.events.append(
                "connection_terminal",
                connection_id=identifier,
                terminal=state.terminal,
                error=state.error,
                client_to_upstream_bytes=state.client_to_upstream,
                upstream_to_client_bytes=state.upstream_to_client,
                elapsed_ms=max(0, int((time.monotonic() - started) * 1000)),
                payload_logged=False,
                automatic_redispatch=False,
            )
            self.semaphore.release()
            if task is not None:
                self.tasks.discard(task)

    async def start(self, descriptor: Path | None) -> tuple[str, int]:
        self.server = await asyncio.start_server(
            self.handle,
            self.listen_host,
            self.listen_port,
            limit=READ_BYTES,
        )
        sockets = self.server.sockets or []
        if len(sockets) != 1:
            raise RelayError("relay did not bind exactly one listener")
        address = sockets[0].getsockname()
        host, port = str(address[0]), int(address[1])
        value = {
            "schema": DESCRIPTOR_SCHEMA,
            "pid": os.getpid(),
            "listen_host": host,
            "listen_port": port,
            "upstream_host": self.upstream_host,
            "upstream_port": self.upstream_port,
            "adb_server_socket": f"tcp:{host}:{port}",
            "max_clients": self.limits.max_clients,
            "buffer_bytes_per_direction": self.limits.buffer_bytes,
            "event_log_max_bytes": self.limits.event_bytes,
            "connect_timeout_seconds": self.limits.connect_timeout,
            "idle_timeout_seconds": self.limits.idle_timeout,
            "shutdown_grace_seconds": self.limits.shutdown_grace,
            "byte_transparent": True,
            "adb_protocol_parsed": False,
            "argv_or_serial_injected": False,
            "payload_logged": False,
            "automatic_redispatch": False,
        }
        if descriptor is not None:
            atomic_private_json(descriptor, value)
        await self.events.append(
            "relay_ready",
            listen_host=host,
            listen_port=port,
            upstream_host=self.upstream_host,
            upstream_port=self.upstream_port,
        )
        return host, port

    async def serve(self) -> int:
        assert self.server is not None
        async with self.server:
            serving = asyncio.create_task(self.server.serve_forever())
            await self.stop_event.wait()
            self.server.close()
            await self.server.wait_closed()
            serving.cancel()
            await asyncio.gather(serving, return_exceptions=True)
        if self.tasks:
            for task in list(self.tasks):
                task.cancel()
            done, pending = await asyncio.wait(
                list(self.tasks), timeout=self.limits.shutdown_grace
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*done, *pending, return_exceptions=True)
            if pending:
                await self.events.append(
                    "relay_shutdown_incomplete", active_tasks=len(pending)
                )
                return 1
        await self.events.append("relay_terminal", active_tasks=0)
        return 0

    def stop(self) -> None:
        self.stop_event.set()


async def async_main(args: argparse.Namespace) -> int:
    limits = Limits(
        args.max_clients,
        args.buffer_bytes,
        args.event_bytes,
        args.connect_timeout,
        args.idle_timeout,
        args.shutdown_grace,
    )
    limits.validate()
    event_handle = open_private_new(args.events, "event log") if args.events else None
    events = EventWriter(event_handle, limits.event_bytes)
    relay = RelayServer(
        args.listen_host,
        args.listen_port,
        args.upstream_host,
        args.upstream_port,
        limits,
        events,
    )
    loop = asyncio.get_running_loop()
    for current in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(current, relay.stop)
        except NotImplementedError:
            pass
    try:
        await relay.start(args.descriptor)
        return await relay.serve()
    finally:
        if event_handle is not None:
            event_handle.close()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", required=True, type=int)
    parser.add_argument("--upstream-host", default="127.0.0.1")
    parser.add_argument("--upstream-port", required=True, type=int)
    parser.add_argument("--max-clients", type=int, default=DEFAULT_MAX_CLIENTS)
    parser.add_argument("--buffer-bytes", type=int, default=DEFAULT_BUFFER_BYTES)
    parser.add_argument("--event-bytes", type=int, default=DEFAULT_EVENT_BYTES)
    parser.add_argument("--connect-timeout", type=float, default=DEFAULT_CONNECT_TIMEOUT)
    parser.add_argument("--idle-timeout", type=float, default=DEFAULT_IDLE_TIMEOUT)
    parser.add_argument("--shutdown-grace", type=float, default=DEFAULT_SHUTDOWN_GRACE)
    parser.add_argument("--descriptor", type=Path)
    parser.add_argument("--events", type=Path)
    result = parser.parse_args(argv)
    result.listen_host = loopback(result.listen_host, "listen host")
    result.upstream_host = loopback(result.upstream_host, "upstream host")
    if not 0 <= result.listen_port <= 65535 or not 1 <= result.upstream_port <= 65535:
        parser.error("listen or upstream port is invalid")
    Limits(
        result.max_clients,
        result.buffer_bytes,
        result.event_bytes,
        result.connect_timeout,
        result.idle_timeout,
        result.shutdown_grace,
    ).validate()
    return result


def main(argv: list[str]) -> int:
    try:
        return asyncio.run(async_main(parse_args(argv)))
    except (OSError, RelayError) as error:
        print(f"owner-open ADB relay v2 failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
