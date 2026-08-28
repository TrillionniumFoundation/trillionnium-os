"""Bounded client/request mechanics for the owner-open connection broker."""
from __future__ import annotations

from dataclasses import dataclass, field
import queue
import socket
import struct
import threading
from typing import Any

from owner_open_broker_common import BrokerError, canonical


def frame_job_id(frame: dict[str, Any]) -> str | None:
    value = frame.get("job_id")
    if isinstance(value, str):
        return value
    payload = frame.get("payload")
    if isinstance(payload, dict) and isinstance(payload.get("job_id"), str):
        return payload["job_id"]
    return None


def peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise BrokerError("SO_PEERCRED is required for the foundation broker")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    return struct.unpack("3i", raw)


@dataclass
class Client:
    client_id: str
    connection: socket.socket
    pid: int
    uid: int
    gid: int
    maximum_bytes: int
    maximum_frames: int
    queue: queue.Queue[bytes] = field(init=False)
    queued_bytes: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)
    closed: threading.Event = field(default_factory=threading.Event)

    def __post_init__(self) -> None:
        self.queue = queue.Queue(maxsize=self.maximum_frames)

    def enqueue(self, value: dict[str, Any]) -> bool:
        encoded = canonical(value) + b"\n"
        with self.lock:
            if self.closed.is_set() or self.queued_bytes + len(encoded) > self.maximum_bytes:
                return False
            try:
                self.queue.put_nowait(encoded)
            except queue.Full:
                return False
            self.queued_bytes += len(encoded)
            return True

    def writer(self) -> None:
        try:
            while not self.closed.is_set():
                try:
                    encoded = self.queue.get(timeout=0.1)
                except queue.Empty:
                    continue
                with self.lock:
                    self.queued_bytes -= len(encoded)
                try:
                    self.connection.sendall(encoded)
                except OSError:
                    return
        finally:
            self.close()

    def close(self) -> None:
        if self.closed.is_set():
            return
        self.closed.set()
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.connection.close()
        except OSError:
            pass


@dataclass(frozen=True)
class Request:
    owner_id: str
    request_id: str
    frame: dict[str, Any]
    expected_kinds: frozenset[str]
    expected_job_id: str | None
    timeout_ms: int
