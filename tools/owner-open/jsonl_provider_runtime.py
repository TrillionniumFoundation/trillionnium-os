#!/usr/bin/env python3
"""Provider-neutral bounded duplex JSONL process runtime.

The runtime knows only process, bytes, JSON record framing, cancellation,
resource liveness and one terminal observation. It does not interpret provider
event semantics, select tools, execute effects, open credentials or contact a
provider by itself. A caller-supplied handler may return exact response bytes
for a parsed event.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time
from typing import Any, Callable, Literal


class ProviderRuntimeError(ValueError):
    pass


@dataclass(frozen=True)
class ProcessLimits:
    max_argv_items: int = 4096
    max_argument_bytes: int = 64 * 1024
    max_total_argument_bytes: int = 256 * 1024
    max_initial_stdin_bytes: int = 256 * 1024
    max_handler_response_bytes: int = 1024 * 1024
    max_outbound_bytes: int = 16 * 1024 * 1024
    max_event_line_bytes: int = 1024 * 1024
    max_stdout_bytes: int = 16 * 1024 * 1024
    max_stderr_bytes: int = 1024 * 1024
    max_event_count: int = 4096
    read_chunk_bytes: int = 16 * 1024
    timeout_seconds: float = 300.0
    poll_seconds: float = 0.02
    terminate_grace_seconds: float = 0.25

    def validate(self) -> None:
        integer_fields = (
            self.max_argv_items,
            self.max_argument_bytes,
            self.max_total_argument_bytes,
            self.max_initial_stdin_bytes,
            self.max_handler_response_bytes,
            self.max_outbound_bytes,
            self.max_event_line_bytes,
            self.max_stdout_bytes,
            self.max_stderr_bytes,
            self.max_event_count,
            self.read_chunk_bytes,
        )
        if any(value <= 0 for value in integer_fields):
            raise ProviderRuntimeError("provider mechanical byte/count limits must be positive")
        if (
            self.timeout_seconds <= 0
            or self.poll_seconds <= 0
            or self.terminate_grace_seconds < 0
        ):
            raise ProviderRuntimeError("provider lifecycle durations are invalid")


class CancellationToken:
    def __init__(self) -> None:
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    @property
    def cancelled(self) -> bool:
        return self._cancelled


@dataclass(frozen=True)
class ProviderEvent:
    seq: int
    raw: bytes
    value: dict[str, Any]
    elapsed_ms: int


TerminalKind = Literal[
    "exited",
    "signaled",
    "timed_out",
    "client_cancelled",
    "spawn_failed",
    "provider_protocol_error",
    "resource_exhausted",
    "io_error",
]


@dataclass(frozen=True)
class ProviderTerminal:
    kind: TerminalKind
    exit_code: int | None
    signal: int | None
    event_count: int
    stdout_bytes: int
    stderr: bytes
    outbound_bytes: int
    elapsed_ms: int
    error: str | None

    @property
    def success(self) -> bool:
        return self.kind == "exited" and self.exit_code == 0 and self.error is None


EventHandler = Callable[[ProviderEvent], bytes | str | None]
EventSink = Callable[[ProviderEvent], None]


class _DuplicateMember(ValueError):
    pass


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateMember(f"duplicate key {key}")
        value[key] = item
    return value


def decode_strict_event(raw: bytes) -> dict[str, Any]:
    if not raw:
        raise ProviderRuntimeError("provider JSONL record is empty")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProviderRuntimeError("provider JSONL record is not UTF-8") from error
    try:
        value = json.loads(text, object_pairs_hook=_strict_object_pairs)
    except (_DuplicateMember, json.JSONDecodeError) as error:
        raise ProviderRuntimeError(f"invalid provider JSONL record: {error}") from error
    if not isinstance(value, dict):
        raise ProviderRuntimeError("provider JSONL record must be an object")
    return value


def validate_argv(argv: list[str], limits: ProcessLimits) -> None:
    if not argv or len(argv) > limits.max_argv_items:
        raise ProviderRuntimeError("provider argv is empty or has too many elements")
    total = 0
    for argument in argv:
        if not isinstance(argument, str):
            raise ProviderRuntimeError("provider argv elements must be strings")
        encoded = argument.encode("utf-8")
        if b"\x00" in encoded or len(encoded) > limits.max_argument_bytes:
            raise ProviderRuntimeError("provider argument contains NUL or exceeds the byte bound")
        total += len(encoded)
        if total > limits.max_total_argument_bytes:
            raise ProviderRuntimeError("provider argv exceeds the total byte bound")


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))


def _terminate_group(
    process: subprocess.Popen[bytes], grace_seconds: float
) -> tuple[int | None, int | None, str | None]:
    if process.poll() is not None:
        return _status(process.returncode)
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError as error:
        return None, None, f"provider_sigterm_failed: {error}"
    deadline = time.monotonic() + grace_seconds
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as error:
            return None, None, f"provider_sigkill_failed: {error}"
    try:
        returncode = process.wait(timeout=max(1.0, grace_seconds + 1.0))
    except (OSError, subprocess.TimeoutExpired) as error:
        return None, None, f"provider_reap_failed: {error}"
    return _status(returncode)


def _status(returncode: int | None) -> tuple[int | None, int | None, str | None]:
    if returncode is None:
        return None, None, None
    if returncode < 0:
        return None, -returncode, None
    return returncode, None, None


def _join_error(existing: str | None, next_error: str) -> str:
    return f"{existing}; {next_error}" if existing else next_error


def run_provider(
    argv: list[str],
    *,
    initial_stdin: bytes = b"",
    stdin_policy: Literal["keep-open", "close-after-initial"] = "keep-open",
    event_handler: EventHandler | None = None,
    event_sink: EventSink | None = None,
    limits: ProcessLimits | None = None,
    cancellation: CancellationToken | None = None,
    environment: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> ProviderTerminal:
    limits = limits or ProcessLimits()
    limits.validate()
    cancellation = cancellation or CancellationToken()
    validate_argv(argv, limits)
    if len(initial_stdin) > limits.max_initial_stdin_bytes:
        raise ProviderRuntimeError("initial provider stdin exceeds the byte bound")
    if stdin_policy not in {"keep-open", "close-after-initial"}:
        raise ProviderRuntimeError("unknown provider stdin policy")
    if cwd is not None and (not cwd.exists() or not cwd.is_dir()):
        raise ProviderRuntimeError("provider cwd is absent or not a directory")

    started = time.monotonic()
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=environment,
            shell=False,
            start_new_session=True,
            bufsize=0,
        )
    except OSError as error:
        return ProviderTerminal(
            kind="spawn_failed",
            exit_code=None,
            signal=None,
            event_count=0,
            stdout_bytes=0,
            stderr=b"",
            outbound_bytes=0,
            elapsed_ms=_elapsed_ms(started),
            error=str(error),
        )

    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    stdin_fd = process.stdin.fileno()
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    for descriptor in (stdin_fd, stdout_fd, stderr_fd):
        os.set_blocking(descriptor, False)

    selector = selectors.DefaultSelector()
    selector.register(stdout_fd, selectors.EVENT_READ, "stdout")
    selector.register(stderr_fd, selectors.EVENT_READ, "stderr")

    outbound = bytearray(initial_stdin)
    total_outbound = len(outbound)
    if outbound:
        selector.register(stdin_fd, selectors.EVENT_WRITE, "stdin")
    elif stdin_policy == "close-after-initial":
        process.stdin.close()
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    stdout_bytes = 0
    event_count = 0
    forced_kind: TerminalKind | None = None
    error: str | None = None
    stdout_open = True
    stderr_open = True
    stdin_open = not process.stdin.closed

    def queue_response(response: bytes | str | None) -> None:
        nonlocal total_outbound, stdin_open
        if response is None:
            return
        encoded = response.encode("utf-8") if isinstance(response, str) else response
        if not isinstance(encoded, bytes):
            raise ProviderRuntimeError("provider event handler returned a non-byte response")
        if len(encoded) > limits.max_handler_response_bytes:
            raise ProviderRuntimeError("provider handler response exceeds its byte bound")
        if total_outbound + len(encoded) > limits.max_outbound_bytes:
            raise ProviderRuntimeError("provider outbound stream exceeds its byte bound")
        total_outbound += len(encoded)
        outbound.extend(encoded)
        if stdin_open:
            try:
                selector.get_key(stdin_fd)
            except KeyError:
                selector.register(stdin_fd, selectors.EVENT_WRITE, "stdin")

    try:
        while True:
            returncode = process.poll()
            if returncode is not None and not stdout_open and not stderr_open:
                break

            if forced_kind is None:
                if cancellation.cancelled:
                    forced_kind = "client_cancelled"
                elif time.monotonic() - started >= limits.timeout_seconds:
                    forced_kind = "timed_out"
            if forced_kind is not None and process.poll() is None:
                exit_code, terminal_signal, terminate_error = _terminate_group(
                    process, limits.terminate_grace_seconds
                )
                if terminate_error:
                    error = _join_error(error, terminate_error)
                    forced_kind = "io_error"
                # Continue draining the already-created pipe bytes.

            selected = selector.select(limits.poll_seconds)
            if not selected and process.poll() is not None:
                # Ensure EOF notifications are consumed even when poll is already terminal.
                selected = selector.select(0)

            for key, mask in selected:
                descriptor = key.fd
                channel = key.data
                if channel == "stdin" and mask & selectors.EVENT_WRITE:
                    if not outbound:
                        try:
                            selector.unregister(stdin_fd)
                        except KeyError:
                            pass
                        if stdin_policy == "close-after-initial" and stdin_open:
                            process.stdin.close()
                            stdin_open = False
                        continue
                    try:
                        written = os.write(stdin_fd, outbound)
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        outbound.clear()
                        try:
                            selector.unregister(stdin_fd)
                        except KeyError:
                            pass
                        stdin_open = False
                        continue
                    except OSError as write_error:
                        error = _join_error(error, f"provider_stdin_io_error: {write_error}")
                        forced_kind = "io_error"
                        outbound.clear()
                        try:
                            selector.unregister(stdin_fd)
                        except KeyError:
                            pass
                        stdin_open = False
                        continue
                    del outbound[:written]
                    continue

                if channel not in {"stdout", "stderr"} or not mask & selectors.EVENT_READ:
                    continue
                try:
                    chunk = os.read(descriptor, limits.read_chunk_bytes)
                except BlockingIOError:
                    continue
                except OSError as read_error:
                    error = _join_error(error, f"provider_{channel}_io_error: {read_error}")
                    forced_kind = "io_error"
                    chunk = b""

                if not chunk:
                    try:
                        selector.unregister(descriptor)
                    except KeyError:
                        pass
                    if channel == "stdout":
                        stdout_open = False
                    else:
                        stderr_open = False
                    continue

                if channel == "stderr":
                    if len(stderr_buffer) + len(chunk) > limits.max_stderr_bytes:
                        remaining = max(0, limits.max_stderr_bytes - len(stderr_buffer))
                        stderr_buffer.extend(chunk[:remaining])
                        forced_kind = "resource_exhausted"
                        error = _join_error(error, "provider_stderr_exceeds_byte_bound")
                    else:
                        stderr_buffer.extend(chunk)
                    continue

                stdout_bytes += len(chunk)
                if stdout_bytes > limits.max_stdout_bytes:
                    forced_kind = "resource_exhausted"
                    error = _join_error(error, "provider_stdout_exceeds_byte_bound")
                    continue
                stdout_buffer.extend(chunk)
                if len(stdout_buffer) > limits.max_event_line_bytes and b"\n" not in stdout_buffer:
                    forced_kind = "resource_exhausted"
                    error = _join_error(error, "provider_jsonl_record_exceeds_byte_bound")
                    continue

                while True:
                    newline = stdout_buffer.find(b"\n")
                    if newline < 0:
                        break
                    raw = bytes(stdout_buffer[:newline])
                    del stdout_buffer[: newline + 1]
                    if len(raw) > limits.max_event_line_bytes:
                        forced_kind = "resource_exhausted"
                        error = _join_error(error, "provider_jsonl_record_exceeds_byte_bound")
                        break
                    try:
                        value = decode_strict_event(raw)
                    except ProviderRuntimeError as decode_error:
                        forced_kind = "provider_protocol_error"
                        error = _join_error(error, str(decode_error))
                        break
                    if event_count >= limits.max_event_count:
                        forced_kind = "resource_exhausted"
                        error = _join_error(error, "provider_event_count_exceeds_bound")
                        break
                    event = ProviderEvent(
                        seq=event_count,
                        raw=raw,
                        value=value,
                        elapsed_ms=_elapsed_ms(started),
                    )
                    event_count += 1
                    if event_sink is not None:
                        try:
                            event_sink(event)
                        except Exception as sink_error:  # noqa: BLE001 - boundary converts to terminal
                            forced_kind = "io_error"
                            error = _join_error(
                                error, f"provider_event_sink_failed: {sink_error}"
                            )
                            break
                    if event_handler is not None:
                        try:
                            queue_response(event_handler(event))
                        except Exception as handler_error:  # noqa: BLE001 - boundary converts to terminal
                            forced_kind = "provider_protocol_error"
                            error = _join_error(
                                error, f"provider_event_handler_failed: {handler_error}"
                            )
                            break
                # A forced terminal closes the provider after this select batch.

            if process.poll() is not None and not stdout_open and not stderr_open:
                break
    finally:
        selector.close()
        if process.poll() is None:
            exit_code, terminal_signal, terminate_error = _terminate_group(
                process, limits.terminate_grace_seconds
            )
            if terminate_error:
                error = _join_error(error, terminate_error)
                forced_kind = "io_error"
        else:
            exit_code, terminal_signal, _ = _status(process.returncode)
        for pipe in (process.stdin, process.stdout, process.stderr):
            try:
                if pipe is not None and not pipe.closed:
                    pipe.close()
            except OSError as close_error:
                error = _join_error(error, f"provider_pipe_close_failed: {close_error}")
                forced_kind = "io_error"

    if stdout_buffer:
        forced_kind = forced_kind or "provider_protocol_error"
        error = _join_error(error, "provider_stdout_ended_with_truncated_jsonl_record")
    if forced_kind is None:
        kind: TerminalKind = "signaled" if terminal_signal is not None else "exited"
    else:
        kind = forced_kind
    return ProviderTerminal(
        kind=kind,
        exit_code=exit_code,
        signal=terminal_signal,
        event_count=event_count,
        stdout_bytes=stdout_bytes,
        stderr=bytes(stderr_buffer),
        outbound_bytes=total_outbound,
        elapsed_ms=_elapsed_ms(started),
        error=error,
    )
