"""Bounded exact-frame client for the selected owner-open Host."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import os
import signal
import subprocess
import threading
import time
from typing import Any

from owner_open_mcp_common import (
    HostProtocolError,
    HostUnavailable,
    InvalidArguments,
    MAX_LINE_BYTES,
    canonical,
    strict_json,
)

MAX_FRAMES = 4096
MAX_BUFFER_BYTES = 32 * 1024 * 1024
MAX_STDERR_BYTES = 1024 * 1024


@dataclass(frozen=True)
class Record:
    ordinal: int
    size: int
    frame: dict[str, Any]


class Journal:
    def __init__(self) -> None:
        self.records: deque[Record] = deque()
        self.bytes = 0
        self.next = 0
        self.earliest = 0

    def append(self, frame: dict[str, Any], size: int) -> None:
        self.records.append(Record(self.next, size, frame))
        self.next += 1
        self.bytes += size
        while len(self.records) > MAX_FRAMES or self.bytes > MAX_BUFFER_BYTES:
            removed = self.records.popleft()
            self.bytes -= removed.size
            self.earliest = removed.ordinal + 1

    def from_ordinal(self, ordinal: int) -> list[Record]:
        if ordinal < self.earliest:
            raise HostProtocolError(
                f"Host response journal dropped ordinal {ordinal}; earliest={self.earliest}"
            )
        return [item for item in self.records if item.ordinal >= ordinal]


class HostClient:
    def __init__(self, argv: list[str], *, startup_timeout: float, request_timeout: float) -> None:
        if not argv:
            raise InvalidArguments("Host argv is empty")
        self.argv = list(argv)
        self.request_timeout = request_timeout
        self.condition = threading.Condition()
        self.send_lock = threading.Lock()
        self.transaction_lock = threading.Lock()
        self.journal = Journal()
        self.client_seq = 0
        self.stderr = bytearray()
        self.reader_error: str | None = None
        self.closed = False
        self.process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            bufsize=0,
        )
        assert self.process.stdin and self.process.stdout and self.process.stderr
        self.out_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self.err_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self.out_thread.start()
        self.err_thread.start()
        start = self.send(
            "hello",
            {"protocol": "trillionnium.agent.turn.v1", "protocol_version": 1},
        )
        self.wait(start, {"hello.ack"}, None, startup_timeout, None)

    def _read_stdout(self) -> None:
        assert self.process.stdout
        try:
            while True:
                raw = self.process.stdout.readline(MAX_LINE_BYTES + 2)
                if not raw:
                    break
                if not raw.endswith(b"\n") or len(raw) > MAX_LINE_BYTES + 1:
                    raise HostProtocolError("Host response is oversized or not newline terminated")
                value = strict_json(raw[:-1], label="Host response")
                if not isinstance(value, dict):
                    raise HostProtocolError("Host response is not an object")
                with self.condition:
                    self.journal.append(value, len(raw) - 1)
                    self.condition.notify_all()
        except Exception as error:  # reader boundary
            with self.condition:
                self.reader_error = str(error)
                self.condition.notify_all()

    def _read_stderr(self) -> None:
        assert self.process.stderr
        while True:
            chunk = self.process.stderr.read(8192)
            if not chunk:
                return
            with self.condition:
                remaining = MAX_STDERR_BYTES - len(self.stderr)
                if remaining > 0:
                    self.stderr.extend(chunk[:remaining])

    def stderr_text(self) -> str:
        with self.condition:
            return bytes(self.stderr).decode("utf-8", errors="replace")

    def send(self, kind: str, payload: dict[str, Any]) -> int:
        with self.send_lock:
            if self.closed:
                raise HostUnavailable("Host client is closed")
            if self.process.poll() is not None:
                raise HostUnavailable(
                    f"Host exited with {self.process.returncode}: {self.stderr_text()}"
                )
            with self.condition:
                start = self.journal.next
            frame = {
                "kind": kind,
                "seq": self.client_seq,
                "direction": "client_to_host",
                "payload": payload,
            }
            self.client_seq += 1
            encoded = canonical(frame)
            if len(encoded) > MAX_LINE_BYTES:
                raise InvalidArguments("Host request exceeds frame byte bound")
            assert self.process.stdin
            try:
                self.process.stdin.write(encoded + b"\n")
                self.process.stdin.flush()
            except (BrokenPipeError, OSError) as error:
                raise HostUnavailable(f"failed to write Host request: {error}") from error
            return start

    @staticmethod
    def _job_id(frame: dict[str, Any]) -> str | None:
        direct = frame.get("job_id")
        if isinstance(direct, str):
            return direct
        payload = frame.get("payload")
        return payload.get("job_id") if isinstance(payload, dict) and isinstance(payload.get("job_id"), str) else None

    def wait(
        self,
        start: int,
        expected: set[str],
        job_id: str | None,
        timeout: float | None,
        cancelled: threading.Event | None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        deadline = time.monotonic() + (timeout or self.request_timeout)
        while True:
            if cancelled is not None and cancelled.is_set():
                raise HostProtocolError("MCP tool request was cancelled")
            with self.condition:
                records = self.journal.from_ordinal(start)
                observed = [item.frame for item in records]
                for item in records:
                    frame, kind = item.frame, item.frame.get("kind")
                    frame_job = self._job_id(frame)
                    if kind == "job.error" and (job_id is None or frame_job in {None, job_id}):
                        payload = frame.get("payload")
                        message = payload.get("message") if isinstance(payload, dict) else "job.error"
                        raise HostProtocolError(str(message), frame=frame)
                    if kind in expected and (job_id is None or frame_job == job_id):
                        return frame, observed
                if self.reader_error:
                    raise HostUnavailable(self.reader_error)
                if self.process.poll() is not None:
                    raise HostUnavailable(
                        f"Host exited with {self.process.returncode}: {self.stderr_text()}"
                    )
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise HostProtocolError(f"timed out waiting for {sorted(expected)}")
                self.condition.wait(min(remaining, 0.1))

    def transact(
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        expected: set[str],
        job_id: str | None,
        timeout: float | None = None,
        cancelled: threading.Event | None = None,
    ) -> dict[str, Any]:
        with self.transaction_lock:
            start = self.send(kind, payload)
            response, observed = self.wait(start, expected, job_id, timeout, cancelled)
            return {
                "response": response,
                "observed_frames": observed[-128:],
                "observed_frame_count": len(observed),
            }

    def close(self) -> None:
        with self.send_lock:
            if self.closed:
                return
            self.closed = True
            if self.process.stdin:
                try:
                    self.process.stdin.close()
                except OSError:
                    pass
        try:
            self.process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(self.process.pid, sig)
                except ProcessLookupError:
                    pass
                try:
                    self.process.wait(timeout=1)
                    break
                except subprocess.TimeoutExpired:
                    continue
        for pipe in (self.process.stdout, self.process.stderr):
            if pipe:
                try:
                    pipe.close()
                except OSError:
                    pass
        self.out_thread.join(timeout=1)
        self.err_thread.join(timeout=1)
