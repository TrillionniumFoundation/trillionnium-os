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
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
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
    kill_grace_seconds: float = 1.0
    drain_seconds: float = 1.0

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
        if any(type(value) is not int or not 0 < value <= 2**31 for value in integer_fields):
            raise ProviderRuntimeError("provider mechanical byte/count limits must be positive bounded integers")
        for name, value, minimum, maximum in (
            ("timeout", self.timeout_seconds, 0.001, 3600),
            ("poll", self.poll_seconds, 0.001, 1),
            ("terminate grace", self.terminate_grace_seconds, 0, 30),
            ("kill grace", self.kill_grace_seconds, 0.01, 30),
            ("drain", self.drain_seconds, 0.01, 30),
        ):
            if type(value) not in (int, float) or not minimum <= value <= maximum:
                raise ProviderRuntimeError(f"provider {name} duration must be finite within {minimum}..{maximum}")
        if self.read_chunk_bytes > 1024 * 1024 or self.max_event_line_bytes > 16 * 1024 * 1024:
            raise ProviderRuntimeError("provider read chunk or JSON line exceeds the hard allocation bound")


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
    cleanup_confirmed: bool = False
    leader_reaped: bool = False
    process_id: int | None = None

    @property
    def success(self) -> bool:
        return (self.kind == "exited" and self.exit_code == 0 and self.error is None
                and self.cleanup_confirmed and self.leader_reaped)


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


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("non-finite JSON number")
    return value


def _reject_constant(text: str) -> None:
    raise ValueError(f"non-finite JSON constant {text}")


def decode_strict_event(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > 16 * 1024 * 1024:
        raise ProviderRuntimeError("provider JSONL record is empty or oversized")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProviderRuntimeError("provider JSONL record is not UTF-8") from error
    # Bound nesting before entering the recursive standard-library decoder.
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 64:
                raise ProviderRuntimeError("provider JSON nesting exceeds 64")
        elif char in "]}":
            depth -= 1
    try:
        value = json.loads(text, object_pairs_hook=_strict_object_pairs,
                           parse_constant=_reject_constant, parse_float=_finite_float)
    except (ValueError, RecursionError) as error:
        raise ProviderRuntimeError(f"invalid provider JSONL record: {str(error)[:512]}") from error
    if not isinstance(value, dict):
        raise ProviderRuntimeError("provider JSONL record must be an object")
    return value


def validate_argv(argv: list[str], limits: ProcessLimits) -> None:
    if not isinstance(argv, list) or not argv or len(argv) > limits.max_argv_items:
        raise ProviderRuntimeError("provider argv is empty or has too many elements")
    total = 0
    for argument in argv:
        if not isinstance(argument, str):
            raise ProviderRuntimeError("provider argv elements must be strings")
        try:
            encoded = argument.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ProviderRuntimeError("provider argument is not UTF-8") from error
        if b"\x00" in encoded or len(encoded) > limits.max_argument_bytes:
            raise ProviderRuntimeError("provider argument contains NUL or exceeds the byte bound")
        total += len(encoded)
        if total > limits.max_total_argument_bytes:
            raise ProviderRuntimeError("provider argv exceeds the total byte bound")


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))


def _observe_exit(process: subprocess.Popen[bytes]) -> int | None:
    """Observe without consuming the sole direct-child PID/PGID anchor."""
    if process.returncode is not None:
        raise ProviderRuntimeError("provider anchor was reaped before group retirement")
    status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if status is None:
        return None
    if status.si_pid != process.pid:
        raise ProviderRuntimeError("provider wait identity differs")
    if status.si_code == os.CLD_EXITED:
        return status.si_status
    if status.si_code in (os.CLD_KILLED, os.CLD_DUMPED):
        return -status.si_status
    raise ProviderRuntimeError("provider wait did not observe an exit")


def _group_quiet(pid: int, deadline: float) -> bool:
    """Bounded same-namespace /proc observation; never proves escaped children absent."""
    anchor, quiet = False, True
    with os.scandir("/proc") as entries:
        for count, entry in enumerate(entries, 1):
            if count > 65536 or time.monotonic() >= deadline:
                raise ProviderRuntimeError("provider procfs scan budget exceeded")
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            try:
                with open(f"/proc/{entry.name}/stat", "rb") as source:
                    raw = source.read(8193)
            except (FileNotFoundError, ProcessLookupError):
                continue
            if len(raw) > 8192:
                raise ProviderRuntimeError("provider procfs stat exceeds bound")
            fields = raw.rsplit(b")", 1)[1].split()
            group, session = int(fields[2]), int(fields[3])
            if int(entry.name) == pid:
                if group != pid or session != pid:
                    raise ProviderRuntimeError("provider group anchor identity differs")
                anchor = True
            if group == pid and fields[0] not in (b"Z", b"X"):
                quiet = False
    if not anchor:
        raise ProviderRuntimeError("provider group anchor is not observable")
    return quiet


def _retire_group(process: subprocess.Popen[bytes], limits: ProcessLimits):
    """TERM then KILL while the leader is retained, then reap exactly once.

    The caller must be the sole reaper. Scan/signalling errors remain errors
    even when the leader can be reaped. There are no signals after reaping.
    """
    error = None
    confirmed = reaped = False
    code = None
    try:
        _observe_exit(process)
    except Exception as failure:
        return None, None, False, False, f"provider_anchor_unavailable: {failure}"
    for sig, duration in ((signal.SIGTERM, limits.terminate_grace_seconds),
                          (signal.SIGKILL, limits.kill_grace_seconds)):
        try:
            _observe_exit(process)
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        except Exception as failure:
            error = _join_error(error, f"provider_signal_failed: {failure}")
        deadline = time.monotonic() + duration
        quiet_once = False
        while time.monotonic() < deadline:
            try:
                exited = _observe_exit(process) is not None
                quiet = _group_quiet(process.pid, min(deadline, time.monotonic() + 1))
            except Exception as failure:
                error = _join_error(error, f"provider_cleanup_observation_failed: {failure}")
                break
            if exited and quiet and quiet_once:
                if sig == signal.SIGKILL:
                    confirmed = True
                break
            quiet_once = exited and quiet
            time.sleep(min(0.005, max(0, deadline - time.monotonic())))
    try:
        # Losing the anchor never grants permission to signal a recycled PID.
        observed = _observe_exit(process)
        code = process.wait(timeout=0 if observed is not None else limits.kill_grace_seconds)
        reaped = True
    except Exception as failure:
        error = _join_error(error, f"provider_reap_failed: {failure}")
    if not confirmed:
        error = _join_error(error, "provider_original_group_cleanup_unconfirmed")
    exit_code, terminal_signal, _ = _status(code)
    return exit_code, terminal_signal, confirmed and error is None, reaped, error


def _status(returncode: int | None) -> tuple[int | None, int | None, str | None]:
    if returncode is None:
        return None, None, None
    if returncode < 0:
        return None, -returncode, None
    return returncode, None, None


def _join_error(existing: str | None, next_error: str) -> str:
    return (f"{existing}; {next_error}" if existing else next_error)[:4096]


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
    if not isinstance(initial_stdin, bytes) or len(initial_stdin) > min(
        limits.max_initial_stdin_bytes, limits.max_outbound_bytes,
    ):
        raise ProviderRuntimeError("initial provider stdin exceeds the byte bound or is not bytes")
    if stdin_policy not in {"keep-open", "close-after-initial"}:
        raise ProviderRuntimeError("unknown provider stdin policy")
    if cwd is not None and (not cwd.exists() or not cwd.is_dir()):
        raise ProviderRuntimeError("provider cwd is absent or not a directory")
    if (not sys.platform.startswith("linux") or not callable(getattr(os, "waitid", None))
            or not hasattr(os, "WNOWAIT") or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL):
        raise ProviderRuntimeError("Linux WNOWAIT and exclusive default-SIGCHLD reaping are required")
    started = time.monotonic()
    if cancellation.cancelled:
        return ProviderTerminal("client_cancelled", None, None, 0, 0, b"", 0, 0, None)
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=cwd, env=environment, shell=False, close_fds=True,
            start_new_session=True, bufsize=0,
        )
    except OSError as failure:
        return ProviderTerminal("spawn_failed", None, None, 0, 0, b"", 0,
                                _elapsed_ms(started), str(failure)[:4096])

    selector = None
    stdout_buffer, stderr_buffer, outbound = bytearray(), bytearray(), bytearray(initial_stdin)
    total_outbound, stdout_bytes, event_count = len(outbound), 0, 0
    forced_kind = error = None
    exit_code = terminal_signal = None
    cleanup_confirmed = leader_reaped = retired = False
    stdout_open = stderr_open = stdin_open = True
    drain_deadline = None

    def force(kind, detail=None):
        nonlocal forced_kind, error
        if forced_kind is None:
            forced_kind = kind
        if detail is not None:
            error = _join_error(error, detail)

    def checkpoint():
        if forced_kind is None:
            if cancellation.cancelled:
                force("client_cancelled")
            elif time.monotonic() - started >= limits.timeout_seconds:
                force("timed_out")
        return forced_kind is not None

    def close_input():
        nonlocal stdin_open
        if stdin_open:
            stdin_open = False
            if selector is not None:
                try:
                    selector.unregister(process.stdin.fileno())
                except KeyError:
                    pass
            process.stdin.close()
        outbound.clear()

    def queue_response(response):
        nonlocal total_outbound
        if response is None or checkpoint():
            return
        encoded = response.encode("utf-8") if isinstance(response, str) else response
        if not isinstance(encoded, bytes):
            raise ProviderRuntimeError("provider event handler returned a non-byte response")
        if len(encoded) > limits.max_handler_response_bytes:
            raise ProviderRuntimeError("provider handler response exceeds its byte bound")
        if total_outbound + len(encoded) > limits.max_outbound_bytes:
            raise ProviderRuntimeError("provider outbound stream exceeds its byte bound")
        if not encoded:
            return
        if not stdin_open:
            raise ProviderRuntimeError("provider stdin is closed; response not sent")
        total_outbound += len(encoded)
        outbound.extend(encoded)
        try:
            selector.get_key(process.stdin.fileno())
        except KeyError:
            selector.register(process.stdin.fileno(), selectors.EVENT_WRITE, "stdin")

    def retire():
        nonlocal retired, exit_code, terminal_signal, cleanup_confirmed, leader_reaped, error, forced_kind, drain_deadline
        if retired:
            return
        retired = True
        exit_code, terminal_signal, cleanup_confirmed, leader_reaped, failure = _retire_group(process, limits)
        drain_deadline = time.monotonic() + limits.drain_seconds
        if failure:
            forced_kind = "io_error"
            error = _join_error(error, failure)
        close_input()

    try:
        # Initialization belongs inside the same lifetime guard as the pump.
        for pipe in (process.stdin, process.stdout, process.stderr):
            os.set_blocking(pipe.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout.fileno(), selectors.EVENT_READ, "stdout")
        selector.register(process.stderr.fileno(), selectors.EVENT_READ, "stderr")
        if outbound:
            selector.register(process.stdin.fileno(), selectors.EVENT_WRITE, "stdin")
        elif stdin_policy == "close-after-initial":
            close_input()
        while True:
            checkpoint()
            if not retired and (forced_kind is not None or _observe_exit(process) is not None):
                retire()
            if retired and not stdout_open and not stderr_open:
                break
            if drain_deadline is not None and time.monotonic() >= drain_deadline:
                force("io_error", "provider_pipe_drain_deadline_exceeded")
                break
            wait = min(limits.poll_seconds, max(0, started + limits.timeout_seconds - time.monotonic()))
            if retired:
                wait = min(limits.poll_seconds, max(0, drain_deadline - time.monotonic()))
            for key, mask in selector.select(wait):
                checkpoint()
                channel = key.data
                if channel == "stdin":
                    if forced_kind is not None or not stdin_open:
                        close_input()
                        continue
                    if not outbound:
                        selector.unregister(key.fd)
                        if stdin_policy == "close-after-initial":
                            close_input()
                        continue
                    try:
                        written = os.write(key.fd, outbound)
                        if written <= 0 or written > len(outbound):
                            raise OSError("provider stdin write made no valid progress")
                        del outbound[:written]
                    except BlockingIOError:
                        pass
                    except OSError as failure:
                        force("io_error", f"provider_stdin_io_error: {failure}")
                        close_input()
                    continue
                try:
                    chunk = os.read(key.fd, limits.read_chunk_bytes)
                except BlockingIOError:
                    continue
                except OSError as failure:
                    force("io_error", f"provider_{channel}_io_error: {failure}")
                    chunk = b""
                if not chunk:
                    selector.unregister(key.fd)
                    if channel == "stdout":
                        stdout_open = False
                    else:
                        stderr_open = False
                    continue
                if channel == "stderr":
                    available = max(0, limits.max_stderr_bytes - len(stderr_buffer))
                    stderr_buffer.extend(chunk[:available])
                    if len(chunk) > available and forced_kind is None:
                        force("resource_exhausted", "provider_stderr_exceeds_byte_bound")
                    continue
                stdout_bytes += len(chunk)
                if checkpoint():
                    continue  # bounded drain, no callbacks after a forced terminal
                if stdout_bytes > limits.max_stdout_bytes:
                    force("resource_exhausted", "provider_stdout_exceeds_byte_bound")
                    continue
                stdout_buffer.extend(chunk)
                while not checkpoint():
                    newline = stdout_buffer.find(b"\n")
                    if newline < 0:
                        if len(stdout_buffer) > limits.max_event_line_bytes:
                            force("resource_exhausted", "provider_jsonl_record_exceeds_byte_bound")
                        break
                    if newline > limits.max_event_line_bytes:
                        force("resource_exhausted", "provider_jsonl_record_exceeds_byte_bound")
                        break
                    raw = bytes(stdout_buffer[:newline])
                    del stdout_buffer[:newline + 1]
                    try:
                        value = decode_strict_event(raw)
                    except ProviderRuntimeError as failure:
                        force("provider_protocol_error", str(failure))
                        break
                    if event_count >= limits.max_event_count:
                        force("resource_exhausted", "provider_event_count_exceeds_bound")
                        break
                    event = ProviderEvent(event_count, raw, value, _elapsed_ms(started))
                    event_count += 1
                    if event_sink is not None:
                        try:
                            event_sink(event)
                        except Exception as failure:
                            force("io_error", f"provider_event_sink_failed: {failure}")
                    if checkpoint():
                        break
                    if event_handler is not None:
                        try:
                            response = event_handler(event)
                            if not checkpoint():
                                queue_response(response)
                        except Exception as failure:
                            force("provider_protocol_error", f"provider_event_handler_failed: {failure}")
                if forced_kind is not None:
                    stdout_buffer.clear()
    except Exception as failure:
        force("io_error", f"provider_runtime_io_error: {failure}")
    finally:
        try:
            retire()
        except Exception as failure:
            forced_kind = "io_error"
            error = _join_error(error, f"provider_retirement_failed: {failure}")
        if selector is not None:
            try:
                selector.close()
            except Exception as failure:
                force("io_error", f"provider_selector_close_failed: {failure}")
        for pipe in (process.stdin, process.stdout, process.stderr):
            try:
                if pipe is not None and not pipe.closed:
                    pipe.close()
            except OSError as failure:
                force("io_error", f"provider_pipe_close_failed: {failure}")
    if stdout_buffer and forced_kind is None:
        force("provider_protocol_error", "provider_stdout_ended_with_truncated_jsonl_record")
    return ProviderTerminal(
        kind=forced_kind or ("signaled" if terminal_signal is not None else "exited"),
        exit_code=exit_code, signal=terminal_signal, event_count=event_count,
        stdout_bytes=stdout_bytes, stderr=bytes(stderr_buffer), outbound_bytes=total_outbound,
        elapsed_ms=_elapsed_ms(started), error=error, cleanup_confirmed=cleanup_confirmed,
        leader_reaped=leader_reaped, process_id=process.pid,
    )
