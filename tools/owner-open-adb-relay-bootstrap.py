#!/usr/bin/env python3
"""Owner-open P0 independent-host ADB relay bootstrap.

This is a mechanism-only developer bootstrap for the accepted r4 ADB topology.
It executes one ordinary adb process with exact argv and returns raw bytes as
base64. It does not inject a serial, host, port, transport, approval, risk tier
or privilege downgrade. The integrated Rust Host/relay and durable recovery
remain separate W4/W5 work.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from typing import Any, BinaryIO, TextIO

PROTOCOL = "trillionnium.owner-open.adb-relay.v1"
PROTOCOL_VERSION = 1
DEFAULT_TIMEOUT_MS = 120_000
DEFAULT_KILL_GRACE_MS = 1_000
DEFAULT_OUTPUT_LIMIT_BYTES = 16 * 1024 * 1024
MAX_REQUEST_BYTES = 1024 * 1024
MAX_REQUEST_ID_BYTES = 256
MAX_ARGV_ITEMS = 4096
MAX_ARGUMENT_BYTES = 64 * 1024
MAX_TOTAL_ARGV_BYTES = 1024 * 1024
MAX_STDIN_BYTES = 16 * 1024 * 1024
MAX_TIMEOUT_MS = 24 * 60 * 60 * 1000
MAX_KILL_GRACE_MS = 60 * 1000
MAX_OUTPUT_LIMIT_BYTES = 1024 * 1024 * 1024


class RelayError(ValueError):
    """Stable request/configuration error for one relay request."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class DuplicateMemberError(RelayError):
    def __init__(self, key: str) -> None:
        super().__init__("invalid_json", f"duplicate JSON member: {key}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateMemberError(key)
        value[key] = item
    return value


def _reject_json_constant(value: str) -> Any:
    raise RelayError("invalid_json", f"non-finite JSON number is forbidden: {value}")


def decode_request_line(encoded: bytes) -> dict[str, Any]:
    if not encoded or len(encoded) > MAX_REQUEST_BYTES:
        raise RelayError("frame_boundary", "request is empty or exceeds the byte bound")
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RelayError("invalid_json", f"request is not UTF-8: {error}") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except DuplicateMemberError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        raise RelayError("invalid_json", f"invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise RelayError("invalid_frame", "request must be a JSON object")
    return value


def _valid_text(value: str, max_bytes: int) -> bool:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return (
        bool(value)
        and len(encoded) <= max_bytes
        and "\x00" not in value
        and not any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in value
        )
    )


def _required_string(request: dict[str, Any], key: str, max_bytes: int) -> str:
    value = request.get(key)
    if not isinstance(value, str) or not _valid_text(value, max_bytes):
        raise RelayError("invalid_frame", f"{key} is missing or mechanically invalid")
    return value


def _parse_argv(request: dict[str, Any]) -> list[str]:
    raw = request.get("argv")
    if not isinstance(raw, list):
        raise RelayError("invalid_frame", "argv must be an array")
    if len(raw) > MAX_ARGV_ITEMS:
        raise RelayError("resource_exhausted", "argv exceeds the item bound")
    argv: list[str] = []
    total = 0
    for item in raw:
        if not isinstance(item, str):
            raise RelayError("invalid_frame", "argv elements must be strings")
        try:
            encoded = item.encode("utf-8")
        except UnicodeEncodeError as error:
            raise RelayError(
                "invalid_frame", "argv element is not valid UTF-8 text"
            ) from error
        if len(encoded) > MAX_ARGUMENT_BYTES or "\x00" in item:
            raise RelayError(
                "invalid_frame", "argv element is not mechanically representable"
            )
        total += len(encoded)
        if total > MAX_TOTAL_ARGV_BYTES:
            raise RelayError("resource_exhausted", "argv exceeds the total byte bound")
        argv.append(item)
    return argv


def _parse_nonnegative_int(
    request: dict[str, Any], key: str, default: int, maximum: int
) -> int:
    raw = request.get(key, default)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0 or raw > maximum:
        raise RelayError(
            "invalid_frame", f"{key} must be a nonnegative integer <= {maximum}"
        )
    return raw


def _parse_stdin(request: dict[str, Any]) -> bytes | None:
    raw = request.get("stdin_base64")
    if raw is None:
        return None
    if not isinstance(raw, str) or len(raw) > (MAX_STDIN_BYTES * 4 // 3 + 8):
        raise RelayError("invalid_frame", "stdin_base64 is not a bounded string")
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (ValueError, binascii.Error) as error:
        raise RelayError(
            "invalid_frame", "stdin_base64 is not canonical RFC 4648 base64"
        ) from error
    if len(decoded) > MAX_STDIN_BYTES:
        raise RelayError("resource_exhausted", "stdin exceeds the byte bound")
    return decoded


@dataclass(frozen=True)
class RelayRequest:
    request_id: str
    argv: list[str]
    timeout_ms: int
    stdin: bytes | None
    extensions: dict[str, Any]

    @classmethod
    def from_object(
        cls, request: dict[str, Any], default_timeout_ms: int
    ) -> "RelayRequest":
        if request.get("protocol") != PROTOCOL:
            raise RelayError("invalid_frame", "unsupported relay protocol")
        if request.get("protocol_version") not in (
            PROTOCOL_VERSION,
            str(PROTOCOL_VERSION),
        ):
            raise RelayError("invalid_frame", "unsupported relay protocol_version")
        request_id = _required_string(request, "request_id", MAX_REQUEST_ID_BYTES)
        argv = _parse_argv(request)
        requested_timeout_ms = _parse_nonnegative_int(
            request,
            "timeout_ms",
            default_timeout_ms,
            MAX_TIMEOUT_MS,
        )
        timeout_ms = (
            default_timeout_ms if requested_timeout_ms == 0 else requested_timeout_ms
        )
        stdin = _parse_stdin(request)
        known = {
            "protocol",
            "protocol_version",
            "request_id",
            "argv",
            "timeout_ms",
            "stdin_base64",
        }
        extensions = {key: value for key, value in request.items() if key not in known}
        return cls(
            request_id=request_id,
            argv=argv,
            timeout_ms=timeout_ms,
            stdin=stdin,
            extensions=extensions,
        )


@dataclass(frozen=True)
class RelayConfig:
    adb_executable: Path
    default_timeout_ms: int = DEFAULT_TIMEOUT_MS
    kill_grace_ms: int = DEFAULT_KILL_GRACE_MS
    output_limit_bytes: int = DEFAULT_OUTPUT_LIMIT_BYTES

    def __post_init__(self) -> None:
        validate_executable(self.adb_executable)
        if not 0 < self.default_timeout_ms <= MAX_TIMEOUT_MS:
            raise RelayError(
                "configuration_error",
                f"default timeout must be between 1 and {MAX_TIMEOUT_MS} ms",
            )
        if not 0 <= self.kill_grace_ms <= MAX_KILL_GRACE_MS:
            raise RelayError(
                "configuration_error",
                f"kill grace must be between 0 and {MAX_KILL_GRACE_MS} ms",
            )
        if not 0 < self.output_limit_bytes <= MAX_OUTPUT_LIMIT_BYTES:
            raise RelayError(
                "configuration_error",
                f"output limit must be between 1 and {MAX_OUTPUT_LIMIT_BYTES} bytes",
            )

    @classmethod
    def from_environment(cls, configured: str | None = None) -> "RelayConfig":
        requested = (
            configured
            or os.environ.get("TRILLIONNIUM_OWNER_OPEN_ADB_EXECUTABLE")
            or "adb"
        )
        resolved = shutil.which(requested) if os.sep not in requested else requested
        if not resolved:
            raise RelayError(
                "configuration_error", f"adb executable is not found: {requested}"
            )
        path = Path(resolved)
        return cls(adb_executable=path.resolve(strict=True))


def validate_executable(path: Path) -> None:
    if not path.is_absolute():
        raise RelayError(
            "configuration_error", "adb executable must resolve to an absolute path"
        )
    try:
        entry = path.lstat()
    except OSError as error:
        raise RelayError(
            "configuration_error", f"cannot inspect adb executable: {error}"
        ) from error
    if stat.S_ISLNK(entry.st_mode):
        raise RelayError(
            "configuration_error", "adb executable configuration must not be a symlink"
        )
    if not stat.S_ISREG(entry.st_mode) or not os.access(path, os.X_OK):
        raise RelayError(
            "configuration_error", "adb executable is not a regular executable"
        )
    if entry.st_mode & 0o022:
        raise RelayError(
            "configuration_error", "adb executable is group/world writable"
        )
    if entry.st_uid not in (0, os.geteuid()):
        raise RelayError(
            "configuration_error", "adb executable is not root/current-user owned"
        )


@dataclass
class _Capture:
    limit: int
    data: bytearray
    total: int = 0
    truncated: bool = False
    error: str | None = None


def _drain_stream(
    stream: BinaryIO,
    capture: _Capture,
    overflow: threading.Event,
) -> None:
    try:
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                return
            capture.total += len(chunk)
            remaining = max(0, capture.limit - len(capture.data))
            if remaining:
                capture.data.extend(chunk[:remaining])
            if len(chunk) > remaining:
                capture.truncated = True
                overflow.set()
    except OSError as error:
        capture.error = str(error)
        overflow.set()
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _write_stdin(stream: BinaryIO, data: bytes, error_slot: list[str]) -> None:
    try:
        stream.write(data)
        stream.flush()
    except (BrokenPipeError, OSError) as error:
        error_slot.append(str(error))
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _signal_process_group(process_group: int, requested_signal: int) -> None:
    try:
        os.killpg(process_group, requested_signal)
    except ProcessLookupError:
        pass


def _terminate_process_group(process: subprocess.Popen[bytes], grace_ms: int) -> None:
    process_group = process.pid
    _signal_process_group(process_group, signal.SIGTERM)
    try:
        process.wait(timeout=grace_ms / 1000 if grace_ms else 0)
    except subprocess.TimeoutExpired:
        _signal_process_group(process_group, signal.SIGKILL)
        process.wait()


def _join_io_threads(
    process_group: int,
    threads: list[threading.Thread],
    grace_ms: int,
) -> None:
    join_budget = max(grace_ms / 1000, 0.05)
    deadline = time.monotonic() + join_budget
    for thread in threads:
        thread.join(max(0, deadline - time.monotonic()))
    if any(thread.is_alive() for thread in threads):
        # A descendant retained an inherited pipe after the client leader
        # exited. This is a mechanical FD/process-lifetime failure. Tear down
        # that exact process group so the relay cannot hang forever.
        _signal_process_group(process_group, signal.SIGTERM)
        time.sleep(min(join_budget, 0.05))
        _signal_process_group(process_group, signal.SIGKILL)
        for thread in threads:
            thread.join(join_budget)


def execute_request(request: RelayRequest, config: RelayConfig) -> dict[str, Any]:
    started = time.monotonic()
    status = "spawn_error"
    error: str | None = None
    exit_code: int | None = None
    termination_signal: int | None = None
    timed_out = False
    resource_exhausted = False
    stdin_errors: list[str] = []
    stdout_capture = _Capture(limit=config.output_limit_bytes, data=bytearray())
    stderr_capture = _Capture(limit=config.output_limit_bytes, data=bytearray())
    overflow = threading.Event()

    try:
        process = subprocess.Popen(
            [os.fspath(config.adb_executable), *request.argv],
            stdin=subprocess.PIPE if request.stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
        )
    except OSError as spawn_error:
        error = f"cannot spawn configured adb executable: {spawn_error}"
    else:
        assert process.stdout is not None
        assert process.stderr is not None
        threads = [
            threading.Thread(
                target=_drain_stream,
                args=(process.stdout, stdout_capture, overflow),
                name=f"adb-relay-stdout-{process.pid}",
                daemon=True,
            ),
            threading.Thread(
                target=_drain_stream,
                args=(process.stderr, stderr_capture, overflow),
                name=f"adb-relay-stderr-{process.pid}",
                daemon=True,
            ),
        ]
        for thread in threads:
            thread.start()
        if request.stdin is not None:
            assert process.stdin is not None
            stdin_thread = threading.Thread(
                target=_write_stdin,
                args=(process.stdin, request.stdin, stdin_errors),
                name=f"adb-relay-stdin-{process.pid}",
                daemon=True,
            )
            stdin_thread.start()
            threads.append(stdin_thread)

        deadline = (
            time.monotonic() + request.timeout_ms / 1000
            if request.timeout_ms
            else None
        )
        while process.poll() is None:
            if overflow.is_set():
                resource_exhausted = True
                _terminate_process_group(process, config.kill_grace_ms)
                break
            if deadline is not None and time.monotonic() >= deadline:
                timed_out = True
                _terminate_process_group(process, config.kill_grace_ms)
                break
            time.sleep(0.01)
        if process.poll() is None:
            process.wait()
        _join_io_threads(process.pid, threads, config.kill_grace_ms)
        if stdout_capture.truncated or stderr_capture.truncated:
            resource_exhausted = True

        return_code = process.returncode
        stream_errors = [
            value for value in (stdout_capture.error, stderr_capture.error) if value
        ]
        if resource_exhausted:
            status = "resource_exhausted"
            error = "adb output exceeded the configured mechanical byte ceiling"
        elif timed_out:
            status = "timed_out"
        elif stream_errors:
            status = "io_error"
            error = "; ".join(stream_errors)
        elif return_code is None:
            status = "unknown_after_disconnect"
            error = "adb process terminal state is unavailable"
        elif return_code < 0:
            status = "signaled"
            termination_signal = -return_code
        else:
            status = "exited"
            exit_code = return_code

    duration_ms = int((time.monotonic() - started) * 1000)
    stdout = bytes(stdout_capture.data)
    stderr = bytes(stderr_capture.data)
    return {
        "protocol": PROTOCOL,
        "protocol_version": PROTOCOL_VERSION,
        "request_id": request.request_id,
        "ok": status == "exited" and exit_code == 0,
        "status": status,
        "error": error,
        "resolved_executable": os.fspath(config.adb_executable),
        "argv": request.argv,
        "serial_host_port_or_privilege_injected": False,
        "exit_code": exit_code,
        "signal": termination_signal,
        "timed_out": timed_out,
        "resource_exhausted": resource_exhausted,
        "duration_ms": duration_ms,
        "stdout_base64": base64.b64encode(stdout).decode("ascii"),
        "stderr_base64": base64.b64encode(stderr).decode("ascii"),
        "stdout_bytes": stdout_capture.total,
        "stderr_bytes": stderr_capture.total,
        "stdout_truncated": stdout_capture.truncated,
        "stderr_truncated": stderr_capture.truncated,
        "stdin_error": stdin_errors[0] if stdin_errors else None,
        "event_log_status": "best_effort_bootstrap",
        "runtime_profile": "owner-open-developer-bootstrap",
        "request_extensions": request.extensions,
    }


def error_response(request_id: str | None, error: RelayError) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL,
        "protocol_version": PROTOCOL_VERSION,
        "request_id": request_id,
        "ok": False,
        "status": error.code,
        "error": error.message,
        "serial_host_port_or_privilege_injected": False,
        "runtime_profile": "owner-open-developer-bootstrap",
    }


def process_line(encoded: bytes, config: RelayConfig) -> dict[str, Any]:
    request_id: str | None = None
    try:
        value = decode_request_line(encoded)
        raw_request_id = value.get("request_id")
        if isinstance(raw_request_id, str):
            request_id = raw_request_id
        request = RelayRequest.from_object(value, config.default_timeout_ms)
        return execute_request(request, config)
    except RelayError as error:
        return error_response(request_id, error)


def serve(reader: BinaryIO, writer: TextIO, config: RelayConfig, once: bool) -> int:
    while True:
        encoded = reader.readline(MAX_REQUEST_BYTES + 2)
        if not encoded:
            return 0
        if not encoded.endswith(b"\n"):
            response = error_response(
                None,
                RelayError(
                    "frame_boundary",
                    "request is not newline terminated or is oversized",
                ),
            )
        else:
            response = process_line(encoded[:-1], config)
        writer.write(
            json.dumps(
                response,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        )
        writer.flush()
        if once:
            return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--adb",
        help=(
            "owner-configured adb executable path/name; defaults to "
            "TRILLIONNIUM_OWNER_OPEN_ADB_EXECUTABLE or PATH adb"
        ),
    )
    parser.add_argument("--once", action="store_true", help="process one JSONL request")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        config = RelayConfig.from_environment(args.adb)
    except RelayError as error:
        print(
            json.dumps(
                error_response(None, error),
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ),
            flush=True,
        )
        return 2
    return serve(sys.stdin.buffer, sys.stdout, config, args.once)


if __name__ == "__main__":
    raise SystemExit(main())
