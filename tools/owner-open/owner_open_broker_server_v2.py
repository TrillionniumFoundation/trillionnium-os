"""Socket lifecycle and process cleanup for the owner-open broker v2."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import socket
import stat
import threading

from owner_open_broker_base_v2 import terminate_upstream_bounded
from owner_open_broker_common import BrokerError, atomic_write_private, validate_socket_path


class BrokerServerMixin:
    @staticmethod
    def _path_identity(path: Path, *, socket_path: bool = False) -> tuple[int, int]:
        try:
            metadata = path.lstat()
        except OSError as error:
            raise BrokerError(f"broker bound path cannot be inspected: {error}") from error
        if socket_path:
            if not stat.S_ISSOCK(metadata.st_mode):
                raise BrokerError("bound broker path is not a Unix socket")
        elif not stat.S_ISREG(metadata.st_mode):
            raise BrokerError("broker descriptor path is not a regular file")
        return metadata.st_dev, metadata.st_ino

    @staticmethod
    def _fd_identity(fd: int, *, socket_path: bool = False) -> tuple[int, int]:
        """Return the identity of an opened descriptor after type validation."""

        try:
            metadata = os.fstat(fd)
        except OSError as error:
            raise BrokerError("bound broker descriptor cannot be inspected") from error
        if socket_path and not stat.S_ISSOCK(metadata.st_mode):
            raise BrokerError("bound broker descriptor is not a Unix socket")
        if not socket_path and not stat.S_ISREG(metadata.st_mode):
            raise BrokerError("broker descriptor is not a regular file")
        return metadata.st_dev, metadata.st_ino

    @classmethod
    def _bind_private_listener(
        cls,
        path: Path,
    ) -> tuple[socket.socket, tuple[int, int], tuple[int, int]]:
        """Bind a private filesystem socket while pinning its inode identity.

        A Unix socket's pathname mode is set at ``bind`` time.  Use a narrow
        umask for that creation, then apply the authoritative mode through the
        opened listener FD.  The pathname is only inspected (never chmod'ed),
        and its ``st_dev``/``st_ino`` identity is checked on both sides of the
        FD operation so a same-UID unlink/recreate cannot receive a chmod or
        cleanup intended for this listener.
        """

        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        bound_identity: tuple[int, int] | None = None
        try:
            # AF_UNIX bind derives the initial pathname mode from umask.  The
            # broker has not started worker threads yet, so the short-lived
            # process umask transition cannot race broker work.
            previous_umask = os.umask(0o177)
            try:
                listener.bind(str(path))
            finally:
                os.umask(previous_umask)

            # Linux exposes different ``st_dev/st_ino`` pairs for an opened
            # AF_UNIX socket FD and its filesystem dentry.  Keep both
            # identities separately: the FD pair proves that the listener
            # itself did not change, while the pathname pair detects an
            # unlink/recreate race around permission setup.
            fd_identity = cls._fd_identity(listener.fileno(), socket_path=True)
            pathname_before = cls._path_identity(path, socket_path=True)
            bound_identity = pathname_before
            if pathname_before != cls._path_identity(path, socket_path=True):
                raise BrokerError("bound broker socket changed before permission setup")

            try:
                os.fchmod(listener.fileno(), 0o600)
            except (AttributeError, OSError) as error:
                raise BrokerError("bound broker socket FD cannot be made private") from error

            descriptor_after = os.fstat(listener.fileno())
            if (
                not stat.S_ISSOCK(descriptor_after.st_mode)
                or (descriptor_after.st_dev, descriptor_after.st_ino) != fd_identity
                or stat.S_IMODE(descriptor_after.st_mode) != 0o600
            ):
                raise BrokerError("bound broker socket FD changed during permission setup")
            pathname_after = cls._path_identity(path, socket_path=True)
            if pathname_after != bound_identity:
                raise BrokerError("bound broker socket pathname changed during permission setup")
            try:
                pathname_metadata = path.lstat()
            except OSError as error:
                raise BrokerError("bound broker socket pathname disappeared") from error
            if stat.S_IMODE(pathname_metadata.st_mode) != 0o600:
                raise BrokerError("bound broker socket pathname is not mode 0600")
            return listener, bound_identity, fd_identity
        except Exception:
            try:
                listener.close()
            finally:
                # Only remove the inode we actually bound.  If an attacker
                # replaced the pathname, this identity check leaves the
                # replacement untouched.
                cls._remove_proven_path(path, bound_identity, socket_path=True)
            raise

    @classmethod
    def _verify_bound_listener(
        cls,
        listener: socket.socket,
        pathname_identity: tuple[int, int],
        fd_identity: tuple[int, int],
        path: Path,
    ) -> None:
        """Re-check listener and pathname identity before publication."""

        if cls._fd_identity(listener.fileno(), socket_path=True) != fd_identity:
            raise BrokerError("bound broker socket FD identity changed")
        if cls._path_identity(path, socket_path=True) != pathname_identity:
            raise BrokerError("bound broker socket pathname identity changed")

    @staticmethod
    def _remove_proven_path(
        path: Path,
        identity: tuple[int, int] | None,
        *,
        socket_path: bool = False,
    ) -> None:
        if identity is None:
            return
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return
        correct_type = (
            stat.S_ISSOCK(metadata.st_mode)
            if socket_path
            else stat.S_ISREG(metadata.st_mode)
        )
        if correct_type and (metadata.st_dev, metadata.st_ino) == identity:
            path.unlink()

    def _start_workers(self) -> None:
        workers: list[tuple[str, object]] = [
            ("broker-upstream-reader", self._upstream_reader),
            ("broker-timeout-monitor", self._timeout_worker),
        ]
        # Let independent mux keys reach the byte-stream writer gate from
        # separate workers.  A stalled write on one active request must not
        # prevent timeout/terminal convergence for another key.  The writer
        # gate itself still serializes bytes on the one upstream pipe so line
        # framing cannot interleave.
        for index in range(max(1, self.args.max_inflight_requests)):
            name = (
                "broker-request-dispatcher"
                if index == 0
                else f"broker-request-dispatcher-{index}"
            )
            workers.append((name, self._request_worker))
        for name, target in workers:
            worker = threading.Thread(target=target, daemon=True, name=name)
            worker.start()
            self.worker_threads.append(worker)

    def serve(self) -> int:
        validate_socket_path(self.args.socket)
        if self.args.socket.exists() or self.args.socket.is_symlink():
            raise BrokerError("refusing to replace an existing broker socket path")
        signal.signal(signal.SIGTERM, lambda *_: self.stopping.set())
        signal.signal(signal.SIGINT, lambda *_: self.stopping.set())
        try:
            self._start_upstream()
            self.descriptor = self._build_descriptor()
            listener, socket_identity, socket_fd_identity = self._bind_private_listener(
                self.args.socket
            )
            self.listener = listener
            self.socket_identity = socket_identity
            self.socket_fd_identity = socket_fd_identity
            listener.listen(self.args.max_clients)
            self._verify_bound_listener(
                listener,
                socket_identity,
                socket_fd_identity,
                self.args.socket,
            )
            listener.settimeout(0.2)
            atomic_write_private(
                self.args.descriptor,
                json.dumps(self.descriptor, indent=2, sort_keys=True).encode() + b"\n",
                label="broker descriptor",
            )
            self.descriptor_identity = self._path_identity(self.args.descriptor)
            self._start_workers()
            while not self.stopping.is_set():
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                # Reserve before Thread.start, including silent/unauthenticated peers.
                self.connection_workers.start_reader(connection, self._client_reader)
        finally:
            self.stopping.set()
            self.connection_workers.close()
            if not self.upstream_uncertain.is_set():
                self._mark_upstream_unknown(
                    BrokerError("broker stopped with accepted requests unresolved"),
                    code="broker_shutdown",
                )
            else:
                self.stopping.set()
                self.mux.close()
            if self.listener is not None:
                try:
                    self.listener.close()
                except OSError:
                    pass
            with self.clients_lock:
                clients, self.clients = list(self.clients.values()), {}
            for client in clients:
                client.close()
            self._remove_proven_path(
                self.args.socket,
                self.socket_identity,
                socket_path=True,
            )
            self._remove_proven_path(
                self.args.descriptor,
                self.descriptor_identity,
            )
            self._stop_upstream()
            # One deadline for all client readers/writers, not per historical client.
            client_workers_stopped = self.connection_workers.join(timeout=1.0)
            for worker in self.worker_threads:
                if worker is threading.current_thread():
                    continue
                worker.join(timeout=0.5)
            self.audit.close()
        if not client_workers_stopped:
            raise BrokerError("client worker cleanup is unconfirmed; no clean shutdown claim")
        return 0

    def _stop_upstream(self) -> None:
        upstream = self.upstream
        if upstream is None:
            return
        terminate_upstream_bounded(upstream, self.upstream_process_identity)
        self.upstream = None
        self.upstream_process_identity = None
        for pipe in (upstream.stdin, upstream.stdout, upstream.stderr):
            if pipe is None:
                continue
            try:
                pipe.close()
            except OSError:
                pass
