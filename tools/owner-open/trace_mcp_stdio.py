#!/usr/bin/env python3
"""Exact-byte bounded STDIO trace proxy for one local MCP server.

The proxy is transport-only. It forwards newline-delimited JSON-RPC bytes
without rewriting them, records both directions, and closes the downstream
process group deterministically when the upstream client closes its input.
"""
from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time
from typing import Any, BinaryIO

MAX_DEFAULT_LINE_BYTES = 1024 * 1024
MAX_DEFAULT_TRACE_BYTES = 64 * 1024 * 1024
MAX_DEFAULT_STDERR_BYTES = 4 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
POLL_SECONDS = 0.05
TERM_GRACE_SECONDS = 1.0
KILL_GRACE_SECONDS = 1.0
TRACE_SCHEMA = "org.trillionnium.owner-open.mcp-stdio-trace.v1"


class TraceError(RuntimeError):
    pass


class DuplicateMember(ValueError):
    pass


def strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateMember(f"duplicate key {key}")
        result[key] = value
    return result


def strict_json(raw: bytes, *, label: str, maximum: int) -> dict[str, Any]:
    if not raw or len(raw) > maximum:
        raise TraceError(f"{label} is empty or exceeds {maximum} bytes")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateMember) as error:
        raise TraceError(f"invalid {label}: {error}") from error
    if not isinstance(value, dict):
        raise TraceError(f"{label} must be a JSON object")
    return value


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def private_output(path: Path, label: str) -> BinaryIO:
    if not path.is_absolute() or not path.parent.is_dir() or path.parent.is_symlink():
        raise TraceError(f"{label} must be an absolute new path with a real parent")
    parent = path.parent.lstat()
    mode = stat.S_IMODE(parent.st_mode)
    trusted = parent.st_uid in {0, os.geteuid()}
    root_sticky = parent.st_uid == 0 and bool(mode & stat.S_ISVTX)
    if not trusted or (mode & 0o022 and not root_sticky):
        raise TraceError(f"{label} parent is not owner controlled")
    if path.exists() or path.is_symlink():
        raise TraceError(f"{label} already exists")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    return os.fdopen(descriptor, "wb", buffering=0)


def validate_command(argv: list[str]) -> None:
    if not argv or len(argv) > 4096:
        raise TraceError("downstream command is empty or oversized")
    total = 0
    for item in argv:
        if not isinstance(item, str):
            raise TraceError("downstream arguments must be strings")
        encoded = item.encode("utf-8")
        if not encoded or b"\x00" in encoded or len(encoded) > 64 * 1024:
            raise TraceError("downstream argument is empty, contains NUL, or is oversized")
        total += len(encoded)
        if total > 1024 * 1024:
            raise TraceError("downstream argv exceeds the total byte bound")
    executable = Path(argv[0])
    if not executable.is_absolute():
        raise TraceError("downstream executable path must be absolute")
    metadata = executable.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o022
        or not os.access(executable, os.X_OK)
    ):
        raise TraceError("downstream executable is not a stable private executable")


class TraceWriter:
    def __init__(self, handle: BinaryIO, *, connection_id: str, maximum: int) -> None:
        self.handle = handle
        self.connection_id = connection_id
        self.maximum = maximum
        self.bytes = 0
        self.sequence = 0
        self.started = time.monotonic()

    def append(self, kind: str, **fields: Any) -> None:
        record = {
            "schema": TRACE_SCHEMA,
            "connection_id": self.connection_id,
            "sequence": self.sequence,
            "elapsed_ms": max(0, int((time.monotonic() - self.started) * 1000)),
            "kind": kind,
            **fields,
        }
        encoded = canonical(record) + b"\n"
        if self.bytes + len(encoded) > self.maximum:
            raise TraceError("MCP trace exceeds the configured byte bound")
        self.handle.write(encoded)
        self.handle.flush()
        os.fsync(self.handle.fileno())
        self.bytes += len(encoded)
        self.sequence += 1

    def frame(self, direction: str, raw: bytes, value: dict[str, Any]) -> None:
        self.append(
            "frame",
            direction=direction,
            byte_count=len(raw),
            sha256=hashlib.sha256(raw).hexdigest(),
            raw_line_base64=base64.b64encode(raw).decode("ascii"),
            message=value,
        )


def set_nonblocking(handle: BinaryIO) -> None:
    os.set_blocking(handle.fileno(), False)


def write_all_nonblocking(handle: BinaryIO, pending: bytearray) -> None:
    while pending:
        try:
            written = os.write(handle.fileno(), pending)
        except BlockingIOError:
            return
        except BrokenPipeError as error:
            raise TraceError("downstream MCP stdin closed while forwarding a frame") from error
        if written <= 0:
            raise TraceError("downstream MCP stdin made no write progress")
        del pending[:written]


def consume_lines(
    buffer: bytearray,
    *,
    direction: str,
    maximum: int,
    trace: TraceWriter,
    sink: BinaryIO,
    pending: bytearray | None = None,
) -> None:
    while True:
        position = buffer.find(b"\n")
        if position < 0:
            if len(buffer) > maximum:
                raise TraceError(f"{direction} MCP frame exceeds {maximum} bytes")
            return
        raw = bytes(buffer[:position])
        del buffer[: position + 1]
        if len(raw) > maximum:
            raise TraceError(f"{direction} MCP frame exceeds {maximum} bytes")
        value = strict_json(raw, label=f"{direction} MCP frame", maximum=maximum)
        trace.frame(direction, raw, value)
        wire = raw + b"\n"
        if pending is not None:
            pending.extend(wire)
        else:
            sink.write(wire)
            sink.flush()


def terminate_group(process: subprocess.Popen[bytes], trace: TraceWriter, reason: str) -> None:
    if process.poll() is not None:
        return
    trace.append("downstream_termination_requested", reason=reason, signal=signal.SIGTERM)
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + TERM_GRACE_SECONDS
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.02)
    if process.poll() is None:
        trace.append("downstream_termination_escalated", signal=signal.SIGKILL)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=KILL_GRACE_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise TraceError("downstream MCP process group could not be reaped") from error


def run(args: argparse.Namespace) -> int:
    argv = list(args.command)
    if argv and argv[0] == "--":
        argv = argv[1:]
    validate_command(argv)
    if args.trace == args.stderr:
        raise TraceError("trace and stderr outputs must be different paths")
    trace_handle = private_output(args.trace, "trace output")
    stderr_handle = private_output(args.stderr, "stderr output")
    trace = TraceWriter(
        trace_handle, connection_id=args.connection_id, maximum=args.max_trace_bytes
    )
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    stderr_bytes = 0
    upstream = sys.stdin.buffer
    downstream_output = sys.stdout.buffer
    client_buffer = bytearray()
    server_buffer = bytearray()
    child_pending = bytearray()
    client_eof = False
    child_stdout_eof = False
    child_stderr_eof = False
    eof_deadline: float | None = None
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            bufsize=0,
        )
        assert process.stdin and process.stdout and process.stderr
        for handle in (upstream, process.stdin, process.stdout, process.stderr):
            set_nonblocking(handle)
        selector.register(upstream, selectors.EVENT_READ, "client")
        selector.register(process.stdout, selectors.EVENT_READ, "server")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        trace.append(
            "downstream_started",
            pid=process.pid,
            argv_sha256=hashlib.sha256(canonical(argv)).hexdigest(),
            argv_count=len(argv),
        )

        while True:
            if child_pending and process.stdin and not process.stdin.closed:
                write_all_nonblocking(process.stdin, child_pending)
            if client_eof and not child_pending and process.stdin and not process.stdin.closed:
                process.stdin.close()
                eof_deadline = time.monotonic() + TERM_GRACE_SECONDS
                trace.append("upstream_eof")
            if eof_deadline is not None and process.poll() is None and time.monotonic() >= eof_deadline:
                terminate_group(process, trace, "upstream_eof_grace_expired")
                eof_deadline = None
            if process.poll() is not None and child_stdout_eof and child_stderr_eof:
                break

            events = selector.select(POLL_SECONDS)
            for key, _mask in events:
                label = key.data
                try:
                    chunk = os.read(key.fd, READ_CHUNK_BYTES)
                except BlockingIOError:
                    continue
                if label == "client":
                    if not chunk:
                        client_eof = True
                        selector.unregister(key.fileobj)
                    else:
                        client_buffer.extend(chunk)
                        consume_lines(
                            client_buffer,
                            direction="client_to_server",
                            maximum=args.max_line_bytes,
                            trace=trace,
                            sink=process.stdin,
                            pending=child_pending,
                        )
                elif label == "server":
                    if not chunk:
                        child_stdout_eof = True
                        selector.unregister(key.fileobj)
                        if server_buffer:
                            raise TraceError("downstream MCP stdout ended with an unterminated frame")
                    else:
                        server_buffer.extend(chunk)
                        consume_lines(
                            server_buffer,
                            direction="server_to_client",
                            maximum=args.max_line_bytes,
                            trace=trace,
                            sink=downstream_output,
                        )
                else:
                    if not chunk:
                        child_stderr_eof = True
                        selector.unregister(key.fileobj)
                    else:
                        remaining = args.max_stderr_bytes - stderr_bytes
                        if remaining <= 0 or len(chunk) > remaining:
                            raise TraceError("downstream MCP stderr exceeds the configured byte bound")
                        stderr_handle.write(chunk)
                        stderr_handle.flush()
                        stderr_bytes += len(chunk)

        returncode = process.wait(timeout=KILL_GRACE_SECONDS)
        if client_buffer:
            raise TraceError("upstream MCP input ended with an unterminated frame")
        trace.append(
            "downstream_terminal",
            returncode=returncode,
            exit_code=returncode if returncode >= 0 else None,
            signal=-returncode if returncode < 0 else None,
            stderr_bytes=stderr_bytes,
        )
        return returncode if returncode >= 0 else 128 + (-returncode)
    except BaseException as error:
        if process is not None:
            try:
                terminate_group(process, trace, f"proxy_error:{type(error).__name__}")
            except Exception:
                pass
        try:
            trace.append("transport_error", error_type=type(error).__name__, error=str(error))
        except Exception:
            pass
        if isinstance(error, KeyboardInterrupt):
            return 130
        if isinstance(error, TraceError):
            print(f"owner-open MCP trace proxy failed: {error}", file=sys.stderr)
            return 1
        raise
    finally:
        selector.close()
        for handle in (trace_handle, stderr_handle):
            try:
                handle.flush()
                os.fsync(handle.fileno())
            except Exception:
                pass
            handle.close()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace", "--trace-output", dest="trace", required=True, type=Path)
    parser.add_argument("--stderr", "--stderr-output", dest="stderr", required=True, type=Path)
    parser.add_argument("--connection-id", required=True)
    parser.add_argument("--max-line-bytes", type=int, default=MAX_DEFAULT_LINE_BYTES)
    parser.add_argument("--max-trace-bytes", type=int, default=MAX_DEFAULT_TRACE_BYTES)
    parser.add_argument("--max-stderr-bytes", type=int, default=MAX_DEFAULT_STDERR_BYTES)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    result = parser.parse_args(argv)
    if (
        not 1 <= result.max_line_bytes <= 16 * 1024 * 1024
        or not 1024 <= result.max_trace_bytes <= 1024 * 1024 * 1024
        or not 1024 <= result.max_stderr_bytes <= 64 * 1024 * 1024
        or not result.connection_id
        or len(result.connection_id.encode("utf-8")) > 256
        or "\x00" in result.connection_id
    ):
        parser.error("trace bounds or connection ID are invalid")
    return result


def main(argv: list[str]) -> int:
    try:
        return run(parse_args(argv))
    except (OSError, TraceError, subprocess.SubprocessError) as error:
        print(f"owner-open MCP trace proxy failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
