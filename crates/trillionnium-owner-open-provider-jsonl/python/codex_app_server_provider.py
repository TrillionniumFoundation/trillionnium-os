#!/usr/bin/env python3
"""Mechanical Codex app-server <-> owner-open provider JSONL bridge.

This is source implementation, not installed/authenticated provider evidence.
The native Codex harness supplies reasoning. All advertised direct effects use
the existing Host callback, and an uncertain callback is never resubmitted.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import queue
import secrets
import selectors
import stat
import sys
import threading
import time
import tomllib
from typing import Any, BinaryIO, Callable

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
# The source tree keeps the shared process helper under its broker owner.
# Materialized payloads place these three pinned modules in one directory.
if not (SCRIPT_DIR / "jsonl_provider_runtime.py").is_file():
    sys.path.insert(0, str(SCRIPT_DIR.parents[2] / "tools" / "owner-open"))
from jsonl_provider_runtime import (  # noqa: E402
    CancellationToken, ProcessLimits, ProviderEvent, ProviderRuntimeError,
    decode_strict_event, run_provider,
)
from codex_callback_observation import (  # noqa: E402
    MAX_HOST_FRAME_BYTES, decode_host_observation, native_tool_result_reply,
)

PROTOCOL = "trillionnium.owner-open.provider-jsonl.v1"
CONFIG_SCHEMA = "org.trillionnium.owner-open.codex-app-server-config.v1"
SESSION_SCHEMA = "org.trillionnium.owner-open.codex-app-server-session.v1"
MAX_LINE = 256 * 1024
MAX_SESSIONS = 256
MAX_NATIVE_RPC_ID_BYTES = 256
MAX_NATIVE_PUBLIC_CONFIG_BYTES = 16 * 1024
PUBLIC_NATIVE_CONFIG_KEYS = frozenset({
    "model", "model_provider", "model_providers", "model_reasoning_effort",
    "model_reasoning_summary", "model_verbosity", "model_context_window",
    "model_auto_compact_token_limit", "model_supports_reasoning_summaries",
    "disable_response_storage", "web_search", "features",
})
PUBLIC_MODEL_PROVIDER_KEYS = frozenset({
    "name", "base_url", "wire_api", "requires_openai_auth", "env_key",
    "env_key_instructions", "query_params", "env_http_headers",
    "request_max_retries", "stream_max_retries", "stream_idle_timeout_ms",
    "websocket_connect_timeout_ms", "supports_websockets",
})
SCOPE_FIELDS = ("session_id", "profile_id", "task_id", "turn_id", "turn_stream_id")


def encoded(value: dict[str, Any]) -> bytes:
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False,
                     sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_LINE:
        raise ProviderRuntimeError("provider frame exceeds its byte bound")
    return raw + b"\n"


def identifier(value: Any, label: str) -> str:
    if (not isinstance(value, str) or not value or len(value.encode("utf-8")) > 256
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ProviderRuntimeError(f"invalid {label}")
    return value


def private_directory(path: Path, *, private: bool = True) -> int:
    if not path.is_absolute() or ".." in path.parts:
        raise ProviderRuntimeError("state directory must be canonical and absolute")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        meta = os.fstat(fd)
        if (meta.st_uid not in {0, os.geteuid()} or meta.st_mode & 0o7022
                or private and (meta.st_uid != os.geteuid() or meta.st_mode & 0o7077)):
            raise ProviderRuntimeError("state directory must be private and owner controlled")
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_private_bytes_at(parent: int, name: str, *, allow_empty: bool = False) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=parent)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.geteuid() or before.st_mode & 0o7077
                or not (0 if allow_empty else 1) <= before.st_size <= MAX_LINE):
            raise ProviderRuntimeError("state/config must be one private bounded regular file")
        raw = bytearray()
        while len(raw) <= MAX_LINE:
            chunk = os.read(fd, min(16384, MAX_LINE + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        version = lambda m: (m.st_dev, m.st_ino, m.st_size, m.st_mtime_ns, m.st_ctime_ns,
                             m.st_mode, m.st_uid, m.st_nlink)
        if version(before) != version(after) or version(after) != version(named):
            raise ProviderRuntimeError("state/config changed while read")
        return bytes(raw)
    finally:
        os.close(fd)


def read_private_at(parent: int, name: str) -> dict[str, Any]:
    return decode_strict_event(read_private_bytes_at(parent, name))


def reject_unbound_native_layers(codex_home: Path, home: Path) -> None:
    """Reject known filesystem contributors before native startup.

    These absence checks do not make paths immutable or bind remote/cloud
    requirements. The installed namespace and authenticated resume still need
    independent qualification. Never open authentication files here.
    """
    candidates = {Path("/etc/codex"), codex_home / "managed_config.toml",
                  codex_home / "requirements.toml", codex_home / "hooks.json",
                  codex_home / "plugins", home / ".codex"}
    # The selected CODEX_HOME may itself be HOME/.codex; its public config is
    # already digest-bound below. Other ancestors' project layers are not.
    candidates.discard(codex_home)
    for ancestor in (codex_home, *codex_home.parents):
        project = ancestor / ".codex"
        if project != codex_home:
            candidates.add(project)
        candidates.add(ancestor / ".git")
    for path in sorted(candidates):
        try:
            os.lstat(path)
        except FileNotFoundError:
            continue
        raise ProviderRuntimeError("unbound native configuration source present; startup refused")


def validate_public_native_config(raw: bytes) -> None:
    # TOML has no native JSON allocation preflight. Keep this public model-only
    # input small before decoding/parsing, and exclude extension/profile inputs.
    if len(raw) > MAX_NATIVE_PUBLIC_CONFIG_BYTES:
        raise ProviderRuntimeError("native public model configuration exceeds its byte bound")
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as error:
        raise ProviderRuntimeError("invalid native public model configuration") from error
    if set(value) - PUBLIC_NATIVE_CONFIG_KEYS:
        raise ProviderRuntimeError("unbound native extension/profile configuration")
    features = value.get("features", {})
    if not isinstance(features, dict) or any(enabled is not False for enabled in features.values()):
        raise ProviderRuntimeError("native effect features must be explicitly disabled")
    if "web_search" in value and value["web_search"] != "disabled":
        raise ProviderRuntimeError("unbound native web tool configuration")
    providers = value.get("model_providers", {})
    if not isinstance(providers, dict) or len(providers) > 16:
        raise ProviderRuntimeError("invalid native public model provider table")
    for name, provider in providers.items():
        identifier(name, "native model provider name")
        if not isinstance(provider, dict) or set(provider) - PUBLIC_MODEL_PROVIDER_KEYS:
            # Frozen ModelProviderInfo.auth runs a configured subprocess. AWS
            # credential providers and inline bearer/header material are not
            # public model settings and cannot enter this callback-only bridge.
            raise ProviderRuntimeError("unbound native model authentication/extension configuration")


def native_configuration(config: dict[str, Any]) -> tuple[dict[str, str], Path]:
    """Bind native config and neutral cwd; never inspect credential contents.

    This does not attest system/cloud layers or pathname immutability. Those
    remain installed qualification requirements, not inferred from stat().
    """
    codex_home = Path(config["codex_home"])
    home = Path(config["home_directory"])
    for directory in (home, codex_home):
        fd = private_directory(directory)
        os.close(fd)
    reject_unbound_native_layers(codex_home, home)
    parent = private_directory(codex_home)
    try:
        try:
            raw = read_private_bytes_at(parent, "config.toml", allow_empty=True)
        except FileNotFoundError:
            measured = None
        else:
            measured = hashlib.sha256(raw).hexdigest()
        if config["codex_config_sha256"] != measured:
            raise ProviderRuntimeError("native Codex configuration digest/absence conflict")
        if measured is not None:
            validate_public_native_config(raw)
    finally:
        os.close(parent)
    # Native authentication stays owned by Codex. Do not copy the ambient
    # process environment (PYTHONPATH, LD_PRELOAD or unbound native config).
    allowed = {"PATH", "LANG", "LC_ALL", "TERM", "NO_COLOR", "SSL_CERT_FILE", "SSL_CERT_DIR",
               "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy",
               "all_proxy", "no_proxy", "OPENAI_API_KEY", "OPENAI_BASE_URL"}
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    if (any(len(value.encode("utf-8")) > 65536 for value in environment.values())
            or sum(len(key.encode()) + len(value.encode("utf-8")) for key, value in environment.items()) > 1024 * 1024):
        raise ProviderRuntimeError("native environment exceeds its byte bound")
    environment.update(HOME=str(home), CODEX_HOME=str(codex_home))
    return environment, codex_home


class Session:
    """One nonblocking per-session lease; no PID or stale-lock adoption."""
    def __init__(self, directory: Path, turn: dict[str, Any], binding: str):
        self.parent = private_directory(directory)
        self.lock: int | None = None
        self.scope = {k: turn[k] for k in SCOPE_FIELDS[:3]}
        self.binding = binding
        self.key = hashlib.sha256(encoded(self.scope)).hexdigest()
        self.name = self.key + ".json"
        try:
            # Count under the directory lease so distinct sessions cannot all
            # pass the finite admission check concurrently.
            admission = os.open(".admission.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
                                | os.O_CLOEXEC | os.O_NONBLOCK, 0o600, dir_fd=self.parent)
            try:
                self.validate_lock(admission)
                fcntl.flock(admission, fcntl.LOCK_EX | fcntl.LOCK_NB)
                # Crash leftovers are held for inspection, never silently
                # adopted or removed. Bound scanning as well as admission.
                lock_count = 0
                own_lock = False
                with os.scandir(self.parent) as leaves:
                    for index, leaf in enumerate(leaves):
                        if index >= 2 * MAX_SESSIONS + 16:
                            raise ProviderRuntimeError("provider session directory exceeds its entry bound")
                        own_lock |= leaf.name == self.key + ".lock"
                        lock_count += leaf.name.endswith(".lock") and leaf.name != ".admission.lock"
                if not own_lock and lock_count >= MAX_SESSIONS:
                    raise ProviderRuntimeError("provider session registry is at capacity")
                self.lock = os.open(self.key + ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
                                    | os.O_CLOEXEC | os.O_NONBLOCK, 0o600, dir_fd=self.parent)
                self.validate_lock(self.lock)
                fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(admission)
            try:
                state = read_private_at(self.parent, self.name)
            except FileNotFoundError:
                self.thread_id = None
            else:
                if (set(state) != {"schema", "scope", "binding", "thread_id"}
                        or state["schema"] != SESSION_SCHEMA or state["scope"] != self.scope
                        or state["binding"] != binding):
                    raise ProviderRuntimeError("provider session binding conflict")
                self.thread_id = identifier(state["thread_id"], "native thread id")
        except BaseException:
            self.close()
            raise

    @staticmethod
    def validate_lock(fd: int) -> None:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1
                or meta.st_uid != os.geteuid() or meta.st_mode & 0o7077 or meta.st_size != 0):
            raise ProviderRuntimeError("session lease must be an empty private regular file")

    def bind(self, thread_id: str) -> None:
        thread_id = identifier(thread_id, "native thread id")
        if self.thread_id is not None:
            if thread_id != self.thread_id:
                raise ProviderRuntimeError("native resumed thread identity changed")
            return
        temporary = "." + self.key + ".tmp-" + secrets.token_hex(8)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_CLOEXEC, 0o600, dir_fd=self.parent)
        try:
            raw = encoded({"schema": SESSION_SCHEMA, "scope": self.scope,
                           "binding": self.binding, "thread_id": thread_id})
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.rename(temporary, self.name, src_dir_fd=self.parent, dst_dir_fd=self.parent)
            os.fsync(self.parent)
            self.thread_id = thread_id
        finally:
            try:
                os.unlink(temporary, dir_fd=self.parent)
            except FileNotFoundError:
                pass

    def close(self) -> None:
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None
        if self.parent is not None:
            os.close(self.parent)
            self.parent = None


class HostInput:
    def __init__(self, stream: BinaryIO, token: CancellationToken):
        self.stream = stream
        self.token = token
        self.frames: queue.Queue[dict[str, Any] | BaseException] = queue.Queue(maxsize=2)
        self.scope: dict[str, str] | None = None
        self.cancelled = False
        self.expected = 0
        self.stopping = threading.Event()
        self.thread: threading.Thread | None = None
        self.buffer = bytearray()
        try:
            self.fd = stream.fileno()
        except (AttributeError, OSError):
            self.fd = None

    def read(self) -> dict[str, Any]:
        maximum = MAX_LINE if self.scope is None else MAX_HOST_FRAME_BYTES
        if self.fd is None:
            raw = self.stream.readline(maximum + 2)
            if not raw or not raw.endswith(b"\n") or len(raw) > maximum + 1:
                raise ProviderRuntimeError("host frame missing, unterminated or over budget")
            with memoryview(raw)[:-1] as frame:
                value = decode_host_observation(frame)
        else:
            # BufferedIO.readline holds a Python lock across a blocking read;
            # a daemon using it can abort interpreter shutdown. This reader
            # owns only an fd, a bounded buffer and short selector waits.
            deadline = time.monotonic() + 30
            with selectors.DefaultSelector() as selector:
                selector.register(self.fd, selectors.EVENT_READ)
                newline = self.buffer.find(b"\n")
                while newline < 0:
                    if self.stopping.is_set() or self.token.cancelled:
                        raise ProviderRuntimeError("host reader stopped")
                    if time.monotonic() >= deadline or len(self.buffer) > maximum:
                        raise ProviderRuntimeError("host input deadline/byte bound exhausted")
                    if not selector.select(timeout=0.02):
                        continue
                    previous = len(self.buffer)
                    chunk = os.read(self.fd, min(16384, maximum + 2 - previous))
                    if not chunk:
                        raise ProviderRuntimeError("host disconnected")
                    self.buffer.extend(chunk)
                    newline = self.buffer.find(b"\n", previous)
                if newline > maximum:
                    raise ProviderRuntimeError("host frame missing, unterminated or over budget")
                # Large callback events are validated/projected while borrowing
                # this single raw buffer; no full-size slice or DOM is made.
                with memoryview(self.buffer)[:newline] as frame:
                    value = decode_host_observation(frame)
                del self.buffer[:newline + 1]
        if (value.get("protocol") != PROTOCOL or type(value.get("seq")) is not int
                or value["seq"] != self.expected):
            raise ProviderRuntimeError("host protocol/sequence conflict")
        self.expected += 1
        return value

    def start(self) -> dict[str, Any]:
        frame = self.read()
        turn = frame.get("turn")
        if frame.get("kind") != "turn.start" or not isinstance(turn, dict):
            raise ProviderRuntimeError("first host frame must be turn.start")
        self.scope = {k: identifier(turn.get(k), k) for k in SCOPE_FIELDS}
        text = turn.get("user_input")
        if not isinstance(text, str) or "\0" in text:
            raise ProviderRuntimeError("turn user_input must be text")
        self.thread = threading.Thread(target=self.pump, daemon=True)
        self.thread.start()
        return {**self.scope, "user_input": text}

    def pump(self) -> None:
        try:
            while True:
                frame = self.read()
                if frame.get("kind") == "turn.cancel":
                    if frame.get("turn") != self.scope:
                        raise ProviderRuntimeError("cancellation scope conflict")
                    self.cancelled = True
                    self.token.cancel()
                    return
                if frame.get("kind") != "tool.result":
                    raise ProviderRuntimeError("unexpected host frame")
                self.check_scope(frame)
                self.frames.put_nowait(frame)
        except BaseException as error:
            self.frames.put_nowait(error) if not self.frames.full() else None
            self.token.cancel()

    def outcome(self, call_id: str, deadline: float) -> dict[str, Any]:
        while time.monotonic() < deadline and not self.token.cancelled:
            try:
                frame = self.frames.get(timeout=min(0.02, max(0.001, deadline - time.monotonic())))
            except queue.Empty:
                continue
            if isinstance(frame, BaseException):
                raise ProviderRuntimeError("host input failed") from frame
            if frame.get("call_id") != call_id:
                raise ProviderRuntimeError("host callback identity conflict")
            self.check_scope(frame)
            return frame
        raise ProviderRuntimeError("callback cancelled/disconnected/expired; no automatic redispatch")

    def check_scope(self, frame: dict[str, Any]) -> None:
        # Canonical v1 tool.result has no scope fields. The per-turn channel
        # and call identity bind it; any explicitly supplied scope must agree.
        if self.scope is None:
            raise ProviderRuntimeError("host callback before accepted turn")
        objects = [frame]
        registry = frame.get("registry")
        if isinstance(registry, dict):
            objects.append(registry)
        for value in objects:
            for field in SCOPE_FIELDS:
                if field in value and value[field] != self.scope[field]:
                    raise ProviderRuntimeError("host callback scope conflict")
            for field in ("turn", "scope"):
                if field in value:
                    supplied = value[field]
                    if not isinstance(supplied, dict) or any(
                            key in supplied and supplied[key] != self.scope[key] for key in SCOPE_FIELDS):
                        raise ProviderRuntimeError("host callback scope conflict")

    def close(self) -> None:
        self.stopping.set()
        if self.thread is not None and self.thread.ident is not None:
            self.thread.join(timeout=1)
            if self.thread.is_alive():
                raise ProviderRuntimeError("host reader retirement unconfirmed")


def direct_tools(typed: bool) -> list[dict[str, Any]]:
    fields = {
        "command": {"type": "string"}, "argv": {"type": "array", "items": {"type": "string"}},
        "cwd": {"type": "string"}, "env": {"type": "object", "additionalProperties": {"type": ["string", "null"]}},
        "stdin": {}, "mode": {"type": "string"}, "pty": {"type": "object"},
        "timeout_ms": {"type": "integer", "minimum": 0}, "stream": {"type": "boolean"},
        "target_id": {"type": "string"},
    }
    return [dict({"name": name, "description": description, "inputSchema": {
        "type": "object", "properties": fields, "additionalProperties": False}, "deferLoading": False},
        **({"type": "function"} if typed else {})) for name, description in (
            ("trillionnium_shell_exec", "Execute exact shell command or argv through the owner-open Host; preserves terminal and uncertainty."),
            ("trillionnium_adb_exec", "Execute exact ordinary ADB argv through the owner-open Host; target selection belongs to Codex."))]


class Bridge:
    def __init__(self, turn: dict[str, Any], session: Session, host: HostInput,
                 output: Callable[[dict[str, Any]], None], token: CancellationToken,
                 typed: bool, timeout: float):
        self.turn, self.session, self.host, self.output, self.token = turn, session, host, output, token
        self.typed = typed
        self.deadline = time.monotonic() + timeout
        self.seq = 0
        self.stage = "initialize"
        self.next_response: int | None = 1
        self.thread_id = session.thread_id
        self.turn_id: str | None = None
        self.terminal: str | None = None
        self.pending_calls: set[str] = set()
        self.pending_rpc_ids: set[tuple[type, int | str]] = set()
        # Retain only streaming digests, never a second copy of model text.
        # Completed items can arrive without any delta in the frozen native API.
        self.messages: dict[str, tuple[int, Any, bool]] = {}

    def emit(self, kind: str, **fields: Any) -> None:
        if self.host.cancelled or self.token.cancelled:
            raise ProviderRuntimeError("host cancelled/disconnected; further delivery is fenced")
        self.output({"protocol": PROTOCOL, "seq": self.seq, "kind": kind, **fields})
        self.seq += 1

    @staticmethod
    def request(number: int, method: str, params: dict[str, Any]) -> bytes:
        return encoded({"id": number, "method": method, "params": params})

    def initial(self) -> bytes:
        return self.request(1, "initialize", {"clientInfo": {
            "name": "trillionnium_owner_open", "title": "Trillionnium Owner Open", "version": "1.0.0"},
            "capabilities": {"experimentalApi": True}})

    def handle(self, event: ProviderEvent) -> bytes | None:
        value = event.value
        if self.host.cancelled or self.token.cancelled:
            raise ProviderRuntimeError("host cancelled/disconnected; native delivery is fenced")
        if self.terminal is not None:
            raise ProviderRuntimeError("native data after terminal")
        if "method" not in value:
            number = value.get("id")
            expected = self.next_response
            if type(number) is not int or number != expected or "error" in value or not isinstance(value.get("result"), dict):
                raise ProviderRuntimeError("unexpected or failed native RPC response")
            result = value["result"]
            if number == 1:
                self.next_response = 2
                self.stage = "thread"
                initialized = encoded({"method": "initialized", "params": {}})
                if self.thread_id:
                    return initialized + self.request(2, "thread/resume", {"threadId": self.thread_id})
                return initialized + self.request(2, "thread/start", {"dynamicTools": direct_tools(self.typed), "environments": []})
            if number == 2:
                self.next_response = 3
                thread = result.get("thread", {})
                if not isinstance(thread, dict):
                    raise ProviderRuntimeError("native thread missing")
                self.thread_id = identifier(thread.get("id"), "native thread id")
                self.session.bind(self.thread_id)
                self.stage = "turn"
                return self.request(3, "turn/start", {"threadId": self.thread_id,
                    "environments": [],
                    "input": [{"type": "text", "text": self.turn["user_input"]}]})
            turn = result.get("turn", {})
            if not isinstance(turn, dict):
                raise ProviderRuntimeError("native turn missing")
            native_id = identifier(turn.get("id"), "native turn id")
            if self.turn_id is not None and self.turn_id != native_id:
                raise ProviderRuntimeError("native started turn conflict")
            self.turn_id, self.stage = native_id, "running"
            self.next_response = None
            return None
        method, params = value["method"], value.get("params", {})
        if not isinstance(params, dict):
            raise ProviderRuntimeError("native notification params must be an object")
        if "id" in value and method != "item/tool/call":
            raise ProviderRuntimeError("unsupported native server request; no implicit approval")
        if method == "turn/started":
            if self.stage not in {"turn", "running"}:
                raise ProviderRuntimeError("native turn started before requested")
            self.check_thread(params)
            turn = params.get("turn", {})
            native_id = identifier(turn.get("id") if isinstance(turn, dict) else None, "native turn id")
            if self.turn_id is not None and self.turn_id != native_id:
                raise ProviderRuntimeError("native turn notification conflict")
            self.turn_id = native_id
            self.stage = "running"
            return None
        if method in {"item/tool/call", "item/agentMessage/delta", "item/completed", "turn/completed"}:
            self.check_thread(params)
            turn_id = params.get("turn", {}).get("id") if method == "turn/completed" and isinstance(params.get("turn"), dict) else params.get("turnId")
            if self.turn_id is None or turn_id != self.turn_id:
                raise ProviderRuntimeError("native turn scope conflict")
        if method == "item/tool/call":
            if self.stage != "running" or "id" not in value:
                raise ProviderRuntimeError("tool callback before accepted native turn")
            rpc_id = value["id"]
            try:
                bounded_string_id = isinstance(rpc_id, str) and len(rpc_id.encode("utf-8")) <= MAX_NATIVE_RPC_ID_BYTES
            except UnicodeEncodeError:
                bounded_string_id = False
            if not ((type(rpc_id) is int and -(1 << 63) <= rpc_id < (1 << 63))
                    or bounded_string_id):
                raise ProviderRuntimeError("invalid native callback RPC identity")
            rpc_key = (type(rpc_id), rpc_id)
            call_id = identifier(params.get("callId"), "native call id")
            if (call_id in self.pending_calls or rpc_key in self.pending_rpc_ids
                    or len(self.pending_calls) >= 4096):
                raise ProviderRuntimeError("duplicate or exhausted callback identity; no redispatch")
            tools = {"trillionnium_shell_exec": "shell.exec", "trillionnium_adb_exec": "adb.exec"}
            tool = tools.get(params.get("tool"))
            arguments = params.get("arguments")
            if tool is None or params.get("namespace") is not None or not isinstance(arguments, dict):
                raise ProviderRuntimeError("unsupported native callback shape")
            allowed = set(direct_tools(self.typed)[0]["inputSchema"]["properties"])
            if set(arguments) - allowed:
                raise ProviderRuntimeError("callback fields outside direct mechanical schema")
            self.pending_calls.add(call_id)
            self.pending_rpc_ids.add(rpc_key)
            self.emit("tool.call", call={**arguments, **{k: self.turn[k] for k in SCOPE_FIELDS},
                                         "call_id": call_id, "tool": tool})
            outcome = self.host.outcome(call_id, self.deadline)
            if self.host.cancelled or self.token.cancelled:
                raise ProviderRuntimeError("host cancelled/disconnected during callback; no redispatch")
            # Deliver the exact observation, including existing/inhibited and
            # unknown terminals. Transport success does not imply effect success.
            return native_tool_result_reply(value["id"], outcome)
        if method == "item/agentMessage/delta":
            text = params.get("delta")
            if not isinstance(text, str):
                raise ProviderRuntimeError("native model delta is not text")
            item_id = identifier(params.get("itemId"), "native message item id")
            size, digest, completed = self.message_state(item_id)
            raw = text.encode("utf-8")
            if completed or size + len(raw) > MAX_LINE:
                raise ProviderRuntimeError("native model message completed or over its byte bound")
            digest.update(raw)
            self.messages[item_id] = (size + len(raw), digest, False)
            self.emit("provider.event", event="model.delta", text=text)
        elif method == "item/completed":
            item = params.get("item")
            if not isinstance(item, dict):
                raise ProviderRuntimeError("native completed item is not an object")
            if item.get("type") == "agentMessage":
                item_id = identifier(item.get("id"), "native message item id")
                text = item.get("text")
                if not isinstance(text, str):
                    raise ProviderRuntimeError("native completed model message is not text")
                raw = text.encode("utf-8")
                size, digest, completed = self.message_state(item_id)
                if (completed or len(raw) > MAX_LINE or size > len(raw)
                        or hashlib.sha256(raw[:size]).digest() != digest.digest()):
                    raise ProviderRuntimeError("native completed message conflicts with delivered deltas")
                self.messages[item_id] = (len(raw), hashlib.sha256(raw), True)
                # The Android observer appends both kinds. Publish only the
                # verified suffix if deltas already supplied the prefix.
                suffix = raw[size:].decode("utf-8")
                if suffix:
                    self.emit("provider.event", event="model.delta" if size else "model.message", text=suffix)
        elif method == "turn/completed":
            status = params["turn"].get("status")
            if status not in {"completed", "failed", "interrupted"}:
                raise ProviderRuntimeError("unknown native terminal status")
            if status == "completed" and any(not value[2] for value in self.messages.values()):
                raise ProviderRuntimeError("native turn completed with an unfinished model message")
            self.terminal = status
            self.token.cancel()  # retire this process before publishing a terminal
        elif "id" in value:
            raise ProviderRuntimeError("unsupported native server request; no implicit approval")
        return None

    def message_state(self, item_id: str) -> tuple[int, Any, bool]:
        if item_id not in self.messages:
            if len(self.messages) >= 4096:
                raise ProviderRuntimeError("native message identity registry is at capacity")
            self.messages[item_id] = (0, hashlib.sha256(), False)
        return self.messages[item_id]

    def check_thread(self, params: dict[str, Any]) -> None:
        if self.thread_id is None or params.get("threadId") != self.thread_id:
            raise ProviderRuntimeError("native thread scope conflict")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/etc/trillionnium/codex-provider.json"))
    args = parser.parse_args(argv)
    session = None
    host = None
    executable_fd = None
    seq = 0
    def output(value: dict[str, Any]) -> None:
        nonlocal seq
        sys.stdout.buffer.write(encoded(value))
        sys.stdout.buffer.flush()
        seq = value["seq"] + 1
    try:
        # Config includes no credentials. Native Codex owns authentication.
        parent = private_directory(args.config.parent, private=False)
        try:
            config = read_private_at(parent, args.config.name)
        finally:
            os.close(parent)
        required = {"schema", "codex_executable", "codex_sha256", "dynamic_tool_format", "state_directory",
                    "home_directory", "codex_home", "codex_config_sha256"}
        if set(config) != required or config["schema"] != CONFIG_SCHEMA or config["dynamic_tool_format"] not in {"0.144.1-function", "0.159.2-function"}:
            raise ProviderRuntimeError("provider configuration shape/revision conflict")
        executable = Path(config["codex_executable"])
        if not executable.is_absolute() or ".." in executable.parts:
            raise ProviderRuntimeError("Codex executable path must be canonical and absolute")
        parent = private_directory(executable.parent, private=False)
        try:
            executable_fd = os.open(executable.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                                    | os.O_NONBLOCK, dir_fd=parent)
        finally:
            os.close(parent)
        metadata = os.fstat(executable_fd)
        if (not executable.is_absolute() or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1 or metadata.st_uid not in {0, os.geteuid()}
                or metadata.st_mode & 0o7022 or not os.access(executable, os.X_OK)
                or not 0 < metadata.st_size <= 512 * 1024 * 1024):
            raise ProviderRuntimeError("Codex executable is not an owner-controlled regular file")
        with os.fdopen(os.dup(executable_fd), "rb") as handle:
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
        version = lambda m: (m.st_dev, m.st_ino, m.st_size, m.st_mtime_ns, m.st_ctime_ns,
                             m.st_mode, m.st_uid, m.st_nlink)
        if version(os.fstat(executable_fd)) != version(metadata):
            raise ProviderRuntimeError("Codex executable changed while hashed")
        if digest != config["codex_sha256"]:
            raise ProviderRuntimeError("Codex executable digest conflict")
        environment, cwd = native_configuration(config)
        token = CancellationToken()
        host = HostInput(sys.stdin.buffer, token)
        turn = host.start()
        binding = hashlib.sha256(encoded(config)).hexdigest()
        session = Session(Path(config["state_directory"]), turn, binding)
        bridge = Bridge(turn, session, host, output, token,
                        True, 30)
        # These overrides are defense in depth. Installed qualification must
        # still bind every native configuration/managed-requirement layer;
        # pinned managed features can override ordinary CLI feature values.
        terminal = run_provider([f"/proc/self/fd/{executable_fd}", "app-server", "--strict-config",
                                 "-c", "features.shell_tool=false", "-c", "features.unified_exec=false",
                                 "-c", "features.image_generation=false", "-c", "features.hooks=false",
                                 "-c", "notify=[]", "-c", "features.plugins=false", "-c", "features.apps=false"],
            initial_stdin=bridge.initial(), event_handler=bridge.handle, cancellation=token,
            pass_fds=(executable_fd,), environment=environment, cwd=cwd,
            limits=ProcessLimits(max_event_line_bytes=MAX_LINE, max_stdout_bytes=8 * 1024 * 1024,
                max_stderr_bytes=64 * 1024, max_initial_stdin_bytes=MAX_LINE,
                max_handler_response_bytes=2 * MAX_LINE, max_outbound_bytes=8 * 1024 * 1024,
                timeout_seconds=30))
        host.close()
        # The immutable rootfs and installed containment remain qualification
        # obligations; stat observations alone do not establish either.
        if (host.cancelled and terminal.kind == "client_cancelled" and terminal.process_id is None):
            output({"protocol": PROTOCOL, "seq": seq, "kind": "turn.cancelled",
                    "summary": "cancelled before native process admission"})
            return 0
        if terminal.cleanup_confirmed and terminal.leader_reaped and not terminal.error:
            if host.cancelled or bridge.terminal == "interrupted":
                output({"protocol": PROTOCOL, "seq": seq, "kind": "turn.cancelled",
                        "summary": "native session retired; no automatic redispatch"})
                return 0
            if bridge.terminal == "completed":
                output({"protocol": PROTOCOL, "seq": seq, "kind": "turn.complete"})
                return 0
        raise ProviderRuntimeError("native turn failed or cleanup/terminal was unconfirmed; no automatic redispatch")
    except (OSError, ValueError, RuntimeError) as error:
        output({"protocol": PROTOCOL, "seq": seq, "kind": "turn.fail", "error": str(error)[:4096]})
        return 1
    finally:
        if host is not None:
            host.close()
        if session is not None:
            session.close()
        if executable_fd is not None:
            os.close(executable_fd)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
