#!/usr/bin/env python3
"""Selected bounded byte-transparent ADB smart-socket relay.

This is the R5 canonical relay entry. Earlier owner_open_adb_relay* and
adb_smart_socket_relay.py files are retained as source-review history only.
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

DESCRIPTOR_SCHEMA = "org.trillionnium.owner-open.adb-smart-socket-relay.v1"
EVENT_SCHEMA = "org.trillionnium.owner-open.adb-smart-socket-relay-event.v1"
READ_BYTES = 64 * 1024


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


def validate_new_private_path(path: Path, label: str) -> None:
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


def open_private(path: Path, label: str) -> BinaryIO:
    validate_new_private_path(path, label)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    return os.fdopen(descriptor, "wb", buffering=0)


def prepare_private_json(path: Path, value: dict[str, Any]) -> Path:
    """Write and sync a private descriptor without making it observable."""
    validate_new_private_path(path, "relay descriptor")
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
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)
    return temporary


def publish_private_json(path: Path, temporary: Path) -> None:
    """Publish a prepared descriptor and sync its directory entry."""
    if temporary.parent != path.parent or temporary.is_symlink():
        raise RelayError("prepared relay descriptor identity changed")
    validate_new_private_path(path, "relay descriptor")
    try:
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_private_json(path: Path, value: dict[str, Any]) -> None:
    """Compatibility helper for one-step private JSON publication."""
    temporary = prepare_private_json(path, value)
    try:
        publish_private_json(path, temporary)
    finally:
        temporary.unlink(missing_ok=True)


class EventWriter:
    def __init__(self, handle: BinaryIO | None, maximum: int) -> None:
        self.handle = handle
        self.maximum = maximum
        self.written = 0
        self.sequence = 0
        self.started = time.monotonic()
        self.lock = asyncio.Lock()
        self.failed = False

    async def append(self, kind: str, **fields: Any) -> None:
        if self.handle is None:
            return
        async with self.lock:
            if self.failed:
                raise RelayError("relay lifecycle journal is fenced after a prior failure")
            record = {
                "schema": EVENT_SCHEMA,
                "sequence": self.sequence,
                "elapsed_ms": max(0, int((time.monotonic() - self.started) * 1000)),
                "kind": kind,
                **fields,
            }
            raw = canonical(record) + b"\n"
            try:
                if self.written + len(raw) > self.maximum:
                    raise RelayError("relay lifecycle journal exceeds its byte bound")
                offset = 0
                while offset < len(raw):
                    remaining = memoryview(raw)[offset:]
                    written = self.handle.write(remaining)
                    if type(written) is not int or not 0 < written <= len(remaining):
                        raise RelayError("relay lifecycle journal write made invalid progress")
                    offset += written
                self.handle.flush()
                os.fsync(self.handle.fileno())
            except BaseException:
                # Preserve any partial/visible bytes. No later record may be
                # concatenated onto an uncertain tail or reuse its sequence.
                self.failed = True
                raise
            self.written += len(raw)
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


async def transfer_pair(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
    state: ConnectionState,
) -> None:
    # gather propagates the first error without cancelling its other child.
    # Retain both owners until every normal/error/cancellation path collects
    # them. A successful half-close still waits for the opposite direction.
    children = [
        asyncio.create_task(pump(client_reader, upstream_writer, state, "client_to_upstream")),
        asyncio.create_task(pump(upstream_reader, client_writer, state, "upstream_to_client")),
    ]
    try:
        await asyncio.gather(*children)
    finally:
        for child in children:
            if not child.done():
                child.cancel()
        await asyncio.gather(*children, return_exceptions=True)


async def idle_watchdog(state: ConnectionState, timeout: float) -> None:
    interval = min(1.0, max(0.05, timeout / 10))
    while True:
        await asyncio.sleep(interval)
        if time.monotonic() - state.last_activity > timeout:
            state.terminal = "idle_timeout"
            raise RelayError("relay connection exceeded the idle timeout")


async def close_writer(writer: asyncio.StreamWriter | None, timeout: float) -> None:
    if writer is None:
        return
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=timeout)
    except (asyncio.TimeoutError, ConnectionError, OSError, RuntimeError):
        # close() may retain buffered bytes and its socket indefinitely when
        # the peer stops reading. Do not return that live transport's slot.
        writer.transport.abort()
    except asyncio.CancelledError:
        writer.transport.abort()
        raise


class Relay:
    selected_entry = "tools/owner-open/adb_smart_socket_relay_selected.py"

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
        self.admission_open = False
        self.connections: set[asyncio.Task[None]] = set()
        self.next_identifier = 0
        self.journal_failed = False

    async def record_event(self, kind: str, **fields: Any) -> bool:
        if self.journal_failed:
            return False
        try:
            await self.events.append(kind, **fields)
        except Exception:
            # Journal failure is an instance-wide admission failure, not just
            # a lost callback exception. Cleanup remains possible without I/O.
            self.journal_failed = True
            self.stop()
            return False
        return True

    async def accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if not self.admission_open or self.stop_event.is_set() or self.semaphore.locked():
            try:
                if self.admission_open and not self.stop_event.is_set():
                    await self.record_event("connection_rejected", reason="max_clients")
            finally:
                await close_writer(writer, self.limits.shutdown_grace)
            return
        await self.semaphore.acquire()
        identifier = self.next_identifier
        self.next_identifier += 1
        current = asyncio.current_task()
        if current is not None:
            self.connections.add(current)
        state = ConnectionState(identifier, time.monotonic())
        upstream_writer: asyncio.StreamWriter | None = None
        transfers: asyncio.Task[None] | None = None
        watchdog: asyncio.Task[None] | None = None
        started = time.monotonic()
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(self.upstream_host, self.upstream_port),
                timeout=self.limits.connect_timeout,
            )
            if self.stop_event.is_set():
                state.terminal = "relay_shutdown"
                return
            for output in (writer, upstream_writer):
                output.transport.set_write_buffer_limits(
                    high=self.limits.buffer_bytes,
                    low=max(1, self.limits.buffer_bytes // 4),
                )
            if not await self.record_event("connection_started", connection_id=identifier):
                state.terminal = "transport_error"
                return
            transfers = asyncio.create_task(
                transfer_pair(reader, writer, upstream_reader, upstream_writer, state),
                name=f"adb-relay-transfer-{identifier}",
            )
            watchdog = asyncio.create_task(
                idle_watchdog(state, self.limits.idle_timeout),
                name=f"adb-relay-watchdog-{identifier}",
            )
            done, _pending = await asyncio.wait(
                {transfers, watchdog}, return_when=asyncio.FIRST_COMPLETED
            )
            if watchdog in done:
                watchdog.result()
            else:
                await transfers
        except asyncio.CancelledError:
            state.terminal = "relay_shutdown"
            raise
        except Exception as error:
            if state.terminal == "completed":
                state.terminal = "transport_error"
            state.error = f"{type(error).__name__}: {error}"
        finally:
            try:
                for task in (transfers, watchdog):
                    if task is not None and not task.done():
                        task.cancel()
                await asyncio.gather(
                    *(task for task in (transfers, watchdog) if task is not None),
                    return_exceptions=True,
                )
                await close_writer(writer, self.limits.shutdown_grace)
                await close_writer(upstream_writer, self.limits.shutdown_grace)
                await self.record_event(
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
            finally:
                # Even cancellation during cleanup cannot strand a permit.
                # Closing/aborting writers is still required independently.
                for output in (writer, upstream_writer):
                    if output is not None and not output.is_closing():
                        output.close()
                        output.transport.abort()
                self.semaphore.release()
                if current is not None:
                    self.connections.discard(current)

    async def start(self, descriptor: Path | None) -> dict[str, Any]:
        self.server = await asyncio.start_server(
            self.accept,
            self.listen_host,
            self.listen_port,
            limit=READ_BYTES,
            start_serving=False,
        )
        try:
            return await self._publish_start(descriptor)
        except BaseException:
            self.stop()
            await self.server.wait_closed()
            raise

    async def _publish_start(self, descriptor: Path | None) -> dict[str, Any]:
        assert self.server is not None
        sockets = self.server.sockets or []
        if len(sockets) != 1:
            raise RelayError("relay did not bind exactly one listener")
        address = sockets[0].getsockname()
        host, port = str(address[0]), int(address[1])
        result = {
            "schema": DESCRIPTOR_SCHEMA,
            "selected_entry": self.selected_entry,
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
        temporary = prepare_private_json(descriptor, result) if descriptor is not None else None
        try:
            if not await self.record_event(
                "relay_ready",
                listen_host=host,
                listen_port=port,
                upstream_host=self.upstream_host,
                upstream_port=self.upstream_port,
            ):
                raise RelayError("relay lifecycle journal failed before readiness")
            if self.stop_event.is_set():
                raise RelayError("relay startup was inhibited")
            # A descriptor is the consumer's connection barrier. Install the
            # accept callback before making the already-synced bytes visible.
            await self.server.start_serving()
            if descriptor is not None:
                assert temporary is not None
                publish_private_json(descriptor, temporary)
                temporary = None
            # publish_private_json is synchronous. Even if another process
            # connects as the file appears, this loop cannot dispatch accept()
            # until the admission fence is opened before the next await.
            self.admission_open = True
            return result
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    async def serve(self) -> int:
        assert self.server is not None
        incomplete = False
        try:
            # start_server already serves after the readiness barrier.
            await self.stop_event.wait()
        finally:
            self.stop()
            # Server.wait_closed also waits for active clients on current
            # Python. Cancel their owners first, or shutdown waits on itself.
            active = list(self.connections)
            for task in active:
                task.cancel()
            if active:
                done, pending = await asyncio.wait(
                    active, timeout=self.limits.shutdown_grace
                )
                if pending:
                    incomplete = True
                    for task in pending:
                        task.cancel()
                    settled, pending = await asyncio.wait(
                        pending, timeout=self.limits.shutdown_grace
                    )
                    done |= settled
                # Never gather an unconfirmed task without a deadline. Keep
                # outstanding owners visible and return failure, not zero.
                await asyncio.gather(*done, return_exceptions=True)
                incomplete = incomplete or bool(pending)
            try:
                await asyncio.wait_for(
                    self.server.wait_closed(), timeout=self.limits.shutdown_grace
                )
            except asyncio.TimeoutError:
                incomplete = True
        if incomplete:
            await self.record_event(
                "relay_shutdown_incomplete", active_connections=len(self.connections)
            )
            return 1
        if self.journal_failed:
            return 1
        return 0 if await self.record_event("relay_terminal", active_connections=0) else 1

    def stop(self) -> None:
        self.admission_open = False
        self.stop_event.set()
        if self.server is not None:
            self.server.close()


async def run(args: argparse.Namespace) -> int:
    limits = Limits(
        args.max_clients,
        args.buffer_bytes,
        args.event_bytes,
        args.connect_timeout,
        args.idle_timeout,
        args.shutdown_grace,
    )
    limits.validate()
    event_handle = open_private(args.events, "event log") if args.events else None
    events = EventWriter(event_handle, limits.event_bytes)
    relay = Relay(
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
    parser.add_argument("--max-clients", type=int, default=16)
    parser.add_argument("--buffer-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--event-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--connect-timeout", type=float, default=5.0)
    parser.add_argument("--idle-timeout", type=float, default=300.0)
    parser.add_argument("--shutdown-grace", type=float, default=2.0)
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
        return asyncio.run(run(parse_args(argv)))
    except (OSError, RelayError) as error:
        print(f"owner-open ADB smart-socket relay failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
