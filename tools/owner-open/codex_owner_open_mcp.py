#!/usr/bin/env python3
"""Codex STDIO MCP bridge for Trillionnium owner-open long-running jobs.

The bridge is mechanism-only. It exposes the reviewed job wire, allocates one
correlation scope and one live bridge identity for the MCP server lifetime, and
never classifies commands, requires approval, rewrites arguments, or
automatically retries uncertainty.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import secrets
import stat
import sys
import threading
from typing import Any, BinaryIO

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from owner_open_mcp_common import (  # noqa: E402
    HostProtocolError,
    HostUnavailable,
    InvalidArguments,
    MAX_LINE_BYTES,
    Scope,
    canonical,
    mcp_result,
    require_id,
    require_object,
    strict_json,
)
from owner_open_mcp_host import HostClient  # noqa: E402
from owner_open_mcp_jobs import JobBridge, TOOLS, TOOL_NAMES  # noqa: E402

MCP_VERSION = "2025-06-18"
SERVER_NAME = "trillionnium-owner-open-jobs"
SERVER_VERSION = "0.2.0"


def validate_executable(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise InvalidArguments(f"{label} must be absolute")
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise InvalidArguments(f"{label} must be a non-symlink regular file")
    if metadata.st_nlink != 1 or not os.access(path, os.X_OK):
        raise InvalidArguments(f"{label} must be singly linked and executable")
    return path


def validate_store(path: Path, label: str) -> Path:
    if not path.is_absolute() or not path.parent.is_dir() or path.is_symlink():
        raise InvalidArguments(
            f"{label} must be an absolute non-symlink path with an existing parent"
        )
    return path


def generated(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(16)}"


class Server:
    def __init__(
        self,
        bridge: JobBridge,
        input_stream: BinaryIO,
        output_stream: BinaryIO,
    ) -> None:
        self.bridge = bridge
        self.input = input_stream
        self.output = output_stream
        self.output_lock = threading.Lock()
        self.pending_lock = threading.Lock()
        self.pending: dict[str, threading.Event] = {}
        self.workers: list[threading.Thread] = []
        self.stopping = threading.Event()

    @staticmethod
    def id_key(value: Any) -> str:
        return canonical(value).decode("utf-8")

    def write(self, value: dict[str, Any]) -> None:
        encoded = canonical(value)
        if len(encoded) > MAX_LINE_BYTES:
            encoded = canonical(
                {
                    "jsonrpc": "2.0",
                    "id": value.get("id"),
                    "error": {
                        "code": -32603,
                        "message": "MCP response exceeds byte bound",
                    },
                }
            )
        with self.output_lock:
            self.output.write(encoded + b"\n")
            self.output.flush()

    def error(
        self,
        request_id: Any,
        code: int,
        message: str,
        data: Any = None,
    ) -> None:
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        self.write({"jsonrpc": "2.0", "id": request_id, "error": error})

    def serve(self) -> int:
        while not self.stopping.is_set():
            raw = self.input.readline(MAX_LINE_BYTES + 2)
            if not raw:
                break
            if not raw.endswith(b"\n") or len(raw) > MAX_LINE_BYTES + 1:
                self.error(
                    None,
                    -32700,
                    "MCP message is oversized or not newline terminated",
                )
                continue
            try:
                message = strict_json(raw[:-1], label="MCP message")
            except ValueError as error:
                self.error(None, -32700, str(error))
                continue
            if not isinstance(message, dict):
                self.error(None, -32600, "MCP message must be an object")
                continue
            self.dispatch(message)
        self.stopping.set()
        for worker in self.workers:
            worker.join(timeout=1)
        return 0

    def dispatch(self, message: dict[str, Any]) -> None:
        if message.get("jsonrpc") != "2.0" or not isinstance(
            message.get("method"), str
        ):
            self.error(message.get("id"), -32600, "invalid JSON-RPC request")
            return
        method = message["method"]
        request_id = message.get("id")
        params = message.get("params", {})
        if method == "notifications/initialized":
            return
        if method == "notifications/cancelled":
            if isinstance(params, dict) and "requestId" in params:
                with self.pending_lock:
                    token = self.pending.get(self.id_key(params["requestId"]))
                if token:
                    token.set()
            return
        if method == "exit":
            self.stopping.set()
            return
        if request_id is None:
            return
        if method == "initialize":
            bridge_id = self.bridge.bridge_instance_id
            self.write(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": MCP_VERSION,
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {
                            "name": SERVER_NAME,
                            "version": SERVER_VERSION,
                        },
                        "instructions": (
                            "Owner-open local job tools. First call "
                            "trillionnium_connection_info, then echo its exact "
                            f"bridge_instance_id ({bridge_id}) on every start, "
                            "attach, detach, write, resize, close or kill. "
                            "Inspect uncertainty and never blindly retry effects."
                        ),
                    },
                }
            )
        elif method == "ping":
            self.write({"jsonrpc": "2.0", "id": request_id, "result": {}})
        elif method == "tools/list":
            self.write(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"tools": TOOLS},
                }
            )
        elif method == "shutdown":
            self.write({"jsonrpc": "2.0", "id": request_id, "result": None})
        elif method == "tools/call":
            key = self.id_key(request_id)
            token = threading.Event()
            with self.pending_lock:
                if key in self.pending:
                    self.error(
                        request_id,
                        -32600,
                        "duplicate in-flight JSON-RPC id",
                    )
                    return
                self.pending[key] = token
            worker = threading.Thread(
                target=self.call_tool,
                args=(request_id, params, key, token),
                daemon=True,
                name=(
                    "owner-open-mcp-"
                    f"{hashlib.sha256(key.encode()).hexdigest()[:8]}"
                ),
            )
            self.workers.append(worker)
            worker.start()
        else:
            self.error(request_id, -32601, f"method not found: {method}")

    def call_tool(
        self,
        request_id: Any,
        params_value: Any,
        key: str,
        cancelled: threading.Event,
    ) -> None:
        try:
            params = require_object(params_value, "tools/call params")
            name = params.get("name")
            if not isinstance(name, str) or name not in TOOL_NAMES:
                raise InvalidArguments(f"unknown tool {name}")
            value = self.bridge.call(
                name,
                params.get("arguments", {}),
                cancelled,
            )
            self.write(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": mcp_result(value),
                }
            )
        except InvalidArguments as error:
            self.error(request_id, -32602, str(error))
        except HostProtocolError as error:
            value = {
                "schema": "org.trillionnium.owner-open.mcp-job-error.v1",
                "error": str(error),
                "host_frame": error.frame,
                "bridge_instance_id": self.bridge.bridge_instance_id,
                "automatic_redispatch": False,
            }
            self.write(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": mcp_result(value, error=True),
                }
            )
        except HostUnavailable as error:
            value = {
                "schema": "org.trillionnium.owner-open.mcp-job-error.v1",
                "error": str(error),
                "host_unavailable": True,
                "bridge_instance_id": self.bridge.bridge_instance_id,
                "automatic_redispatch": False,
            }
            self.write(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": mcp_result(value, error=True),
                }
            )
        except Exception as error:  # JSON-RPC server boundary
            self.error(
                request_id,
                -32603,
                "internal MCP bridge error",
                str(error),
            )
        finally:
            with self.pending_lock:
                self.pending.pop(key, None)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True, type=Path)
    parser.add_argument("--core", type=Path)
    parser.add_argument("--provider", required=True, type=Path)
    parser.add_argument("--job-store", required=True, type=Path)
    parser.add_argument("--event-store", type=Path)
    parser.add_argument("--shell", type=Path)
    parser.add_argument("--host-arg", action="append", default=[])
    parser.add_argument("--session-id")
    parser.add_argument("--profile-id", default="owner-open")
    parser.add_argument("--task-id")
    parser.add_argument("--turn-id")
    parser.add_argument("--turn-stream-id")
    parser.add_argument("--bridge-instance-id")
    parser.add_argument("--startup-timeout", type=float, default=10.0)
    parser.add_argument("--request-timeout", type=float, default=30.0)
    return parser.parse_args(argv)


def host_argv(
    args: argparse.Namespace,
) -> tuple[list[str], Scope, str]:
    host = validate_executable(args.host, "--host")
    provider = validate_executable(args.provider, "--provider")
    job_store = validate_store(args.job_store, "--job-store")
    argv = [str(host)]
    if args.core:
        argv += [
            "--transport-core",
            str(validate_executable(args.core, "--core")),
        ]
    argv += ["--provider", str(provider), "--job-store", str(job_store)]
    if args.event_store:
        argv += [
            "--event-store",
            str(validate_store(args.event_store, "--event-store")),
        ]
    if args.shell:
        argv += [
            "--shell",
            str(validate_executable(args.shell, "--shell")),
        ]
    for item in args.host_arg:
        if "\0" in item:
            raise InvalidArguments("--host-arg must be NUL-free")
        argv.append(item)
    if not 0 < args.startup_timeout <= 120 or not 0 < args.request_timeout <= 600:
        raise InvalidArguments(
            "startup/request timeout is outside the finite bound"
        )
    scope = Scope(
        require_id(
            args.session_id or generated("mcp-session"),
            "session_id",
        ),
        require_id(args.profile_id, "profile_id"),
        require_id(
            args.task_id or generated("mcp-task"),
            "task_id",
        ),
        require_id(
            args.turn_id or generated("mcp-turn"),
            "turn_id",
        ),
        require_id(
            args.turn_stream_id or generated("mcp-stream"),
            "turn_stream_id",
        ),
    )
    bridge_instance_id = require_id(
        args.bridge_instance_id or generated("mcp-bridge"),
        "bridge_instance_id",
    )
    return argv, scope, bridge_instance_id


def main(argv: list[str]) -> int:
    try:
        args = parse_args(argv)
        invocation, scope, bridge_instance_id = host_argv(args)
        host = HostClient(
            invocation,
            startup_timeout=args.startup_timeout,
            request_timeout=args.request_timeout,
        )
    except (
        OSError,
        InvalidArguments,
        HostUnavailable,
        HostProtocolError,
    ) as error:
        print(f"owner-open MCP startup failed: {error}", file=sys.stderr)
        return 2
    try:
        return Server(
            JobBridge(host, scope, bridge_instance_id),
            sys.stdin.buffer,
            sys.stdout.buffer,
        ).serve()
    finally:
        host.close()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
