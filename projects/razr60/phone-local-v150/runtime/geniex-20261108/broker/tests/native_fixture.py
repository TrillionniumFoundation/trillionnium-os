"""Real r6 process supervision on the host; never Android identity evidence.

Only HEPTA_TESTING substitutions in the existing native sources are enabled:
the current host UID/groups, synthetic contexts, and /bin/sh.  The fork,
setsid, handshake, journal, socket-disconnect cancellation, waitpid, and
process-group cleanup are the real r6 implementation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import socket
import struct
import subprocess
import time
import uuid


R6_SOURCE = Path(__file__).resolve().parents[4] / "executor" / "r6"
BOOTSTRAP_CONTEXT = "u:r:trillionnium_owner_open_bootstrap:s0"
HOST_PARENT_CONTEXT = "host_fixture_parent_not_android_selinux"
HOST_WORKER_CONTEXT = "host_fixture_worker_not_android_selinux"
HOST_CREDENTIAL_SCOPE = "host_fixture_current_identity_not_android_shell"
MAX_REQUEST = 262144
MAX_RESPONSE = 12 * 1024 * 1024


class NativeFixture:
    """Use with ``with NativeFixture(private_test_root) as native:``.

    All files and sockets belong to this fixture.  ``close`` terminates only
    its own Popen server and leaves evidence files for the test owner to read.
    Production validators must reject the host contexts exposed here.
    """

    def __init__(self, root: Path | str):
        parent = Path(root).resolve()
        parent.mkdir(parents=True, exist_ok=True)
        self.root = parent / ("native-fixture-" + uuid.uuid4().hex)
        self.state_dir = self.root / "state"
        self.socket_name = "hepta_geniex_host_" + uuid.uuid4().hex
        self.endpoint = self.socket_name
        self.process: subprocess.Popen | None = None
        self.ready: dict | None = None
        self.build_steps: list[dict] = []
        self.source_hashes: dict[str, str] = {}
        self.server_exit_code: int | None = None
        self._stderr = None
        self._sockets: set[socket.socket] = set()
        self._entered = False
        self.host_identity = {
            "fixture_only": True,
            "executor_context": HOST_PARENT_CONTEXT,
            "execution_context": HOST_WORKER_CONTEXT,
            "peer_context": BOOTSTRAP_CONTEXT,
            "execution_credentials_scope": HOST_CREDENTIAL_SCOPE,
            "uid": os.getuid(),
            "gid": os.getgid(),
            "supplementary_group_count": len(os.getgroups()),
        }

    @staticmethod
    def _write_new(path: Path, data: bytes) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)

    def _build(self) -> None:
        cc = shutil.which("cc")
        cxx = shutil.which("c++")
        if cc is None or cxx is None:
            raise RuntimeError("Host fixture requires existing cc and c++; it does not install dependencies")
        sources = (
            "phone_tool_sidecar.cpp", "phone_tool_worker.cpp", "phone_security.h",
            "vendor/json.hpp", "vendor/hash/hash.cpp", "vendor/hash/hash.h",
            "vendor/hash/sha256/sha256.c", "vendor/hash/sha256/sha256.h",
        )
        for name in sources:
            self.source_hashes[name] = hashlib.sha256((R6_SOURCE / name).read_bytes()).hexdigest()
        vendor = R6_SOURCE / "vendor"
        sha_object = self.root / "sha256.o"
        self.sidecar_binary = self.root / "sidecar-host-fixture"
        self.worker_binary = self.root / "worker-host-fixture"
        commands = (
            ("sha256", [cc, "-O1", "-c", str(vendor / "hash/sha256/sha256.c"),
                        "-I" + str(vendor / "hash"), "-o", str(sha_object)]),
            ("sidecar", [cxx, "-std=c++17", "-O1", "-pthread", "-DHEPTA_TESTING",
                         "-I" + str(vendor), str(R6_SOURCE / "phone_tool_sidecar.cpp"),
                         str(vendor / "hash/hash.cpp"), str(sha_object), "-o", str(self.sidecar_binary)]),
            ("worker", [cxx, "-std=c++17", "-O1", "-DHEPTA_TESTING",
                        str(R6_SOURCE / "phone_tool_worker.cpp"), "-o", str(self.worker_binary)]),
        )
        for name, argv in commands:
            before = time.monotonic()
            result = subprocess.run(argv, capture_output=True, timeout=90, check=False)
            self._write_new(self.root / ("build-" + name + ".stdout"), result.stdout)
            self._write_new(self.root / ("build-" + name + ".stderr"), result.stderr)
            self.build_steps.append({"name": name, "argv": argv, "exit_code": result.returncode,
                                     "elapsed_seconds": time.monotonic() - before})
            if result.returncode:
                raise RuntimeError("Native host fixture build failed: " + name + ": "
                                   + result.stderr.decode("utf-8", "replace")[-4000:])

    def __enter__(self):
        if self._entered:
            raise RuntimeError("NativeFixture is single-use")
        self._entered = True
        self.root.mkdir(mode=0o700)
        try:
            self._build()
            stderr_fd = os.open(self.root / "server.stderr", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            self._stderr = os.fdopen(stderr_fd, "wb")
            argv = [str(self.sidecar_binary), "--state-dir", str(self.state_dir),
                    "--socket-name", self.socket_name, "--fixture-uid", str(os.getuid()),
                    "--fixture-worker", str(self.worker_binary),
                    "--fixture-peer-context", BOOTSTRAP_CONTEXT]
            self.process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=self._stderr,
                                            stdin=subprocess.DEVNULL, start_new_session=True)
            self.ready = self._read_ready()
            if (self.ready.get("protocol") != "hepta_phone_local_v150"
                    or self.ready.get("executor_revision") != 6
                    or self.ready.get("executor_context") != HOST_PARENT_CONTEXT
                    or self.ready.get("state") != "ready"):
                raise RuntimeError("Host fixture did not report a fresh, explicit host identity")
            self._write_new(self.root / "fixture-build-and-start.json", json.dumps({
                "fixture_only": True, "android_or_npu_validated": False,
                "host_identity": self.host_identity, "ready": self.ready,
                "build_steps": self.build_steps, "source_hashes": self.source_hashes,
            }, indent=2).encode() + b"\n")
            return self
        except BaseException:
            self.close()
            raise

    def _read_ready(self) -> dict:
        assert self.process is not None and self.process.stdout is not None
        deadline = time.monotonic() + 5.0
        data = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            while b"\n" not in data:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TimeoutError("Native fixture readiness deadline")
                block = os.read(self.process.stdout.fileno(), 4096)
                if not block:
                    detail = (self.root / "server.stderr").read_bytes()[-4000:].decode("utf-8", "replace")
                    raise RuntimeError("Native fixture exited before readiness: " + str(self.process.poll())
                                       + "; stderr=" + detail)
                data.extend(block)
                if len(data) > 65536:
                    raise ValueError("Native fixture readiness size limit")
        return json.loads(bytes(data).split(b"\n", 1)[0].decode("utf-8"))

    def _connect(self, timeout: float) -> socket.socket:
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError("Native fixture server is not running")
        stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            stream.settimeout(timeout)
            stream.connect("\0" + self.socket_name)
        except BaseException:
            stream.close()
            raise
        self._sockets.add(stream)
        return stream

    @staticmethod
    def _send(stream: socket.socket, payload: dict) -> None:
        raw = json.dumps({"version": 1, **payload}, ensure_ascii=False,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
        if not 0 < len(raw) <= MAX_REQUEST:
            raise ValueError("Fixture request size limit")
        stream.sendall(struct.pack(">I", len(raw)) + raw)

    def receive(self, stream: socket.socket) -> dict:
        """Receive one complete native frame; caller may then close the socket."""
        deadline = time.monotonic() + (stream.gettimeout() or 72.0)

        def exact(count: int) -> bytes:
            data = bytearray()
            while len(data) < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Fixture response deadline")
                stream.settimeout(remaining)
                part = stream.recv(count - len(data))
                if not part:
                    raise ConnectionError("Native fixture response ended before the complete frame")
                data.extend(part)
            return bytes(data)

        size = struct.unpack(">I", exact(4))[0]
        if not 0 < size <= MAX_RESPONSE:
            raise ValueError("Fixture response size limit")
        result = json.loads(exact(size).decode("utf-8"))
        if not isinstance(result, dict):
            raise ValueError("Fixture response must be an object")
        return result

    def request(self, payload: dict) -> dict:
        stream = self._connect(10.0)
        try:
            self._send(stream, payload)
            return self.receive(stream)
        finally:
            stream.close()
            self._sockets.discard(stream)

    def execute_async(self, command: str, action_id: str, timeout_ms: int = 2000) -> socket.socket:
        """Return the live connection; closing it exercises native cancellation."""
        stream = self._connect(min(72.0, max(1.0, timeout_ms / 1000.0 + 12.0)))
        try:
            self._send(stream, {"op": "execute", "action_id": action_id,
                "command_sha256": hashlib.sha256(command.encode("utf-8")).hexdigest(),
                "command": command, "timeout_ms": timeout_ms})
        except BaseException:
            stream.close()
            self._sockets.discard(stream)
            raise
        return stream

    def inspect(self, action_id: str, command_sha256: str = "", include_output: bool = False) -> dict:
        return self.request({"op": "inspect", "action_id": action_id,
                             "command_sha256": command_sha256, "include_output": include_output})

    def close(self) -> None:
        for stream in self._sockets:
            stream.close()
        self._sockets.clear()
        try:
            if self.process is not None:
                if self.process.poll() is None:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(timeout=2)
                        raise RuntimeError("Native host fixture required forced server cleanup")
                self.server_exit_code = self.process.returncode
                if self.process.stdout is not None:
                    self.process.stdout.close()
        finally:
            if self._stderr is not None:
                self._stderr.close()
                self._stderr = None

    def __exit__(self, exc_type, exc, traceback):
        try:
            self.close()
        except BaseException as cleanup_error:
            if exc is None:
                raise
            if hasattr(exc, "add_note"):
                exc.add_note("Native fixture cleanup also failed: " + repr(cleanup_error))
        return False
