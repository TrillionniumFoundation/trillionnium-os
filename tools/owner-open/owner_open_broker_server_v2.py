"""Socket lifecycle and process cleanup for the owner-open broker v2."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import threading

from owner_open_broker_common import BrokerError, atomic_write_private, validate_socket_path


class BrokerServerMixin:
    @staticmethod
    def _path_identity(path: Path, *, socket_path: bool = False) -> tuple[int, int]:
        metadata = path.lstat()
        if socket_path:
            if not stat.S_ISSOCK(metadata.st_mode):
                raise BrokerError("bound broker path is not a Unix socket")
        elif not stat.S_ISREG(metadata.st_mode):
            raise BrokerError("broker descriptor path is not a regular file")
        return metadata.st_dev, metadata.st_ino

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
        for name, target in (
            ("broker-upstream-reader", self._upstream_reader),
            ("broker-request-dispatcher", self._request_worker),
            ("broker-timeout-monitor", self._timeout_worker),
        ):
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
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.listener = listener
            listener.bind(str(self.args.socket))
            os.chmod(self.args.socket, 0o600)
            self.socket_identity = self._path_identity(self.args.socket, socket_path=True)
            listener.listen(self.args.max_clients)
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
                reader = threading.Thread(
                    target=self._client_reader,
                    args=(connection,),
                    daemon=True,
                    name="broker-client-reader",
                )
                reader.start()
                self.worker_threads.append(reader)
        finally:
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
            for worker in self.worker_threads:
                if worker is threading.current_thread():
                    continue
                worker.join(timeout=0.5)
            self.audit.close()
        return 0

    def _stop_upstream(self) -> None:
        upstream = self.upstream
        if upstream is None:
            return
        if upstream.poll() is None:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(upstream.pid, sig)
                except ProcessLookupError:
                    break
                try:
                    upstream.wait(timeout=1)
                    break
                except subprocess.TimeoutExpired:
                    continue
        else:
            try:
                upstream.wait(timeout=0)
            except subprocess.TimeoutExpired:
                pass
        for pipe in (upstream.stdin, upstream.stdout, upstream.stderr):
            if pipe is None:
                continue
            try:
                pipe.close()
            except OSError:
                pass
