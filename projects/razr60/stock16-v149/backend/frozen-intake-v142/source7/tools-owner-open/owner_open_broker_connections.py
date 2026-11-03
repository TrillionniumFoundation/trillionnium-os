"""Bound connection lifetimes before authentication, not only client IDs.

Linux/Android source mechanism only: no effect retries or target qualification.
A slot is retained until BOTH its reader and optional writer have terminated.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import selectors
import socket
import threading
import time
from typing import Callable

from owner_open_broker_common import BrokerError, MAX_LINE_BYTES

HELLO_TIMEOUT_SECONDS = 5.0
MAX_CONNECTIONS = 1024
READ_CHUNK_BYTES = 64 * 1024


def _close_socket(connection: socket.socket) -> None:
    # shutdown wakes a reader even when another file wrapper retains the FD.
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        connection.close()
    except OSError:
        pass


@dataclass
class _Connection:
    hello_deadline: float
    reader: threading.Thread
    writer: threading.Thread | None = None
    reader_start_uncertain: bool = False
    writer_start_uncertain: bool = False


class ClientWorkers:
    """One bounded slot per accepted socket, including pre-auth and teardown.

    Thread construction/publication/start share the metadata lock with close.
    Reaping uses actual thread termination, not a callback just before exit.
    No join or client callback runs while the metadata lock is held.
    """

    def __init__(self, maximum: int) -> None:
        if isinstance(maximum, bool) or not isinstance(maximum, int) or not 1 <= maximum <= MAX_CONNECTIONS:
            raise ValueError(f"connection limit must be in 1..={MAX_CONNECTIONS}")
        self.maximum = maximum
        self._lock = threading.Lock()
        self._connections: dict[socket.socket, _Connection] = {}
        self._closed = False

    def _reap_locked(self) -> None:
        for connection, state in tuple(self._connections.items()):
            # An interrupted Thread.start can precede ident publication. An
            # unobserved start is not proof that no native worker will appear.
            if state.reader_start_uncertain and state.reader.ident is None:
                continue
            if state.writer_start_uncertain and state.writer is not None and state.writer.ident is None:
                continue
            if not state.reader.is_alive() and (state.writer is None or not state.writer.is_alive()):
                del self._connections[connection]

    def start_reader(self, connection: socket.socket, target: Callable[[socket.socket], None]) -> bool:
        """Take ownership of a socket; overload closes it without a new thread."""
        with self._lock:
            self._reap_locked()
            if connection in self._connections:
                raise BrokerError("connection already owns a reader slot")
            if self._closed or len(self._connections) >= self.maximum:
                _close_socket(connection)
                return False

            def run() -> None:
                try:
                    target(connection)
                finally:
                    _close_socket(connection)

            reader: threading.Thread | None = None
            try:
                reader = threading.Thread(target=run, daemon=True, name="broker-client-reader")
                self._connections[connection] = _Connection(time.monotonic() + HELLO_TIMEOUT_SECONDS, reader)
                reader.start()
            except BaseException as error:
                if reader is None or (isinstance(error, RuntimeError) and reader.ident is None):
                    self._connections.pop(connection, None)
                else:
                    self._connections[connection].reader_start_uncertain = True
                _close_socket(connection)
                raise
            return True

    def hello_deadline(self, connection: socket.socket) -> float:
        with self._lock:
            state = self._connections.get(connection)
            if self._closed or state is None:
                raise BrokerError("connection is not admitted or is shutting down")
            return state.hello_deadline

    def start_writer(self, connection: socket.socket, target: Callable[[], None], *, name: str) -> threading.Thread:
        with self._lock:
            state = self._connections.get(connection)
            if self._closed or state is None:
                raise BrokerError("connection is not admitted or is shutting down")
            if state.writer is not None:
                raise BrokerError("connection already owns a writer")
            writer = threading.Thread(target=target, daemon=True, name=name)
            state.writer = writer
            try:
                writer.start()
            except BaseException as error:
                if isinstance(error, RuntimeError) and writer.ident is None:
                    state.writer = None
                else:
                    state.writer_start_uncertain = True
                raise
            return writer

    def snapshot(self) -> dict[str, int | bool]:
        with self._lock:
            self._reap_locked()
            return {
                "closed": self._closed,
                "connections": len(self._connections),
                "readers_alive": sum(state.reader.is_alive() for state in self._connections.values()),
                "writers_alive": sum(state.writer is not None and state.writer.is_alive() for state in self._connections.values()),
            }

    def close(self) -> None:
        with self._lock:
            self._closed = True
            connections = tuple(self._connections)
        for connection in connections:
            _close_socket(connection)

    def join(self, timeout: float) -> bool:
        """Use one total deadline; false means some worker is still unconfirmed."""
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout < 0:
            raise ValueError("join timeout must be finite and nonnegative")
        deadline = time.monotonic() + timeout
        with self._lock:
            workers = [worker for state in self._connections.values() for worker in (state.reader, state.writer) if worker is not None]
        for worker in workers:
            if worker is not threading.current_thread() and worker.ident is not None:
                worker.join(max(0.0, deadline - time.monotonic()))
        return self.snapshot()["connections"] == 0


class SocketLineReader:
    """Bounded buffered lines with an absolute, non-renewable hello deadline.

    MSG_DONTWAIT affects only recv, so a concurrent writer never observes a
    changed socket timeout/blocking mode. Buffering preserves bytes after the
    hello newline, including a pipelined first request. No data is replayed.
    """

    def __init__(self, connection: socket.socket, *, deadline: float) -> None:
        if isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline):
            raise ValueError("hello deadline must be finite")
        # Retain a separate descriptor, like makefile's retained ownership.
        # Closing the original FD must not remove the selected FD from epoll
        # before shutdown/EOF wakes the reader (including post-auth reads).
        self._connection = connection.dup()
        self._deadline: float | None = deadline
        self._buffer = bytearray()
        self._closed = False
        try:
            self._selector = selectors.DefaultSelector()
            try:
                self._selector.register(self._connection, selectors.EVENT_READ)
            except BaseException:
                self._selector.close()
                raise
        except BaseException:
            self._connection.close()
            raise

    def authenticated(self) -> None:
        self._deadline = None

    def readline(self, size: int) -> bytes:
        if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= MAX_LINE_BYTES + 2:
            raise ValueError("line read must have a finite protocol bound")
        if self._closed:
            raise ValueError("line reader is closed")
        while True:
            remaining = None if self._deadline is None else self._deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise TimeoutError("broker hello deadline exceeded")
            newline = self._buffer.find(b"\n", 0, size)
            if newline >= 0 or len(self._buffer) >= size:
                end = newline + 1 if newline >= 0 else size
                result = bytes(self._buffer[:end])
                del self._buffer[:end]
                return result
            if not self._selector.select(remaining):
                # Recompute the absolute deadline, including spurious wakeups.
                continue
            try:
                chunk = self._connection.recv(min(READ_CHUNK_BYTES, size - len(self._buffer)), socket.MSG_DONTWAIT)
            except (BlockingIOError, InterruptedError):
                continue
            if not chunk:
                result = bytes(self._buffer)
                self._buffer.clear()
                return result
            self._buffer.extend(chunk)

    def close(self) -> None:
        self._closed = True
        try:
            self._selector.close()
        finally:
            self._connection.close()
            self._buffer.clear()
