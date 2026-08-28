"""MCP job definitions and exact mapping onto the owner-open Host job wire."""
from __future__ import annotations

import threading
import time
from typing import Any

from owner_open_mcp_common import (
    HostProtocolError,
    InvalidArguments,
    Scope,
    contains_terminal,
    job_bytes,
    optional_sha256,
    require_id,
    require_int,
    require_object,
)
from owner_open_mcp_host import HostClient

MAX_WAIT_SECONDS = 300.0


def _schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


def _common() -> dict[str, Any]:
    return {"job_id": {"type": "string"}, "request_sha256": {"type": "string"}}


def _tool(
    name: str,
    title: str,
    description: str,
    schema: dict[str, Any],
    *,
    read_only: bool,
    destructive: bool,
    open_world: bool,
) -> dict[str, Any]:
    return {
        "name": name,
        "title": title,
        "description": description,
        "inputSchema": schema,
        "annotations": {
            "readOnlyHint": read_only,
            "destructiveHint": destructive,
            "openWorldHint": open_world,
        },
    }


TOOLS = [
    _tool(
        "trillionnium_job_start",
        "Start owner-open shell job",
        "Start or attach to one exact shell.job. Stable job_id and operation_id prevent blind redispatch.",
        _schema(
            {
                **_common(),
                "operation_id": {"type": "string"},
                "mode": {"type": "string", "enum": ["pipe", "pty"]},
                "command": {"type": "string"},
                "argv": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                "cwd": {"type": "string"},
                "env": {"type": "object", "additionalProperties": {"type": ["string", "null"]}},
                "stdin": {},
                "pty": _schema(
                    {"rows": {"type": "integer", "minimum": 1, "maximum": 65535}, "cols": {"type": "integer", "minimum": 1, "maximum": 65535}},
                    ["rows", "cols"],
                ),
                "target_id": {"type": "string"},
                "binding_fingerprint": {"type": "string"},
                "extensions": {"type": "object"},
            },
            ["job_id", "operation_id", "mode"],
        ),
        read_only=False,
        destructive=True,
        open_world=True,
    ),
    _tool(
        "trillionnium_job_inspect",
        "Inspect owner-open job",
        "Read bounded resident and durable job observations without dispatching an effect.",
        _schema({**_common(), "inclusive_cursor": {"type": "integer", "minimum": 0}, "limit": {"type": "integer", "minimum": 1, "maximum": 256}}, ["job_id"]),
        read_only=True,
        destructive=False,
        open_world=False,
    ),
    _tool(
        "trillionnium_job_attach",
        "Attach to owner-open job",
        "Register one live attachment and return bounded observations. Cross-Host FD adoption is not implied.",
        _schema({**_common(), "attachment_id": {"type": "string"}, "inclusive_cursor": {"type": "integer", "minimum": 0}, "limit": {"type": "integer", "minimum": 1, "maximum": 256}}, ["job_id", "attachment_id"]),
        read_only=False,
        destructive=False,
        open_world=False,
    ),
    _tool(
        "trillionnium_job_detach",
        "Detach from owner-open job",
        "Remove one attachment without terminating the job.",
        _schema({**_common(), "attachment_id": {"type": "string"}}, ["job_id", "attachment_id"]),
        read_only=False,
        destructive=False,
        open_world=False,
    ),
    _tool(
        "trillionnium_job_write",
        "Write owner-open job stdin",
        "Write exact UTF-8 or base64 bytes. operation_id binds accepted-before-effect durability.",
        _schema({**_common(), "operation_id": {"type": "string"}, "data": {}}, ["job_id", "operation_id", "data"]),
        read_only=False,
        destructive=True,
        open_world=True,
    ),
    _tool(
        "trillionnium_job_resize",
        "Resize owner-open PTY",
        "Apply exact non-zero PTY rows and columns using a stable operation_id.",
        _schema({**_common(), "operation_id": {"type": "string"}, "rows": {"type": "integer", "minimum": 1, "maximum": 65535}, "cols": {"type": "integer", "minimum": 1, "maximum": 65535}}, ["job_id", "operation_id", "rows", "cols"]),
        read_only=False,
        destructive=False,
        open_world=True,
    ),
    _tool(
        "trillionnium_job_close_stdin",
        "Close owner-open job stdin",
        "Close pipe stdin or send PTY EOT. Unknown outcomes are not retried automatically.",
        _schema({**_common(), "operation_id": {"type": "string"}}, ["job_id", "operation_id"]),
        read_only=False,
        destructive=True,
        open_world=True,
    ),
    _tool(
        "trillionnium_job_kill",
        "Signal owner-open job",
        "Signal the job process group with a stable operation_id.",
        _schema({**_common(), "operation_id": {"type": "string"}, "signal": {"type": "integer", "minimum": 1, "maximum": 128}}, ["job_id", "operation_id"]),
        read_only=False,
        destructive=True,
        open_world=True,
    ),
    _tool(
        "trillionnium_job_wait",
        "Wait for owner-open job observation",
        "Poll read-only job.inspect until terminal observation or bounded timeout.",
        _schema({**_common(), "inclusive_cursor": {"type": "integer", "minimum": 0}, "limit": {"type": "integer", "minimum": 1, "maximum": 256}, "timeout_seconds": {"type": "number", "minimum": 0, "maximum": 300}, "poll_interval_ms": {"type": "integer", "minimum": 10, "maximum": 5000}}, ["job_id"]),
        read_only=True,
        destructive=False,
        open_world=False,
    ),
]
TOOL_NAMES = {item["name"] for item in TOOLS}


class JobBridge:
    def __init__(self, host: HostClient, scope: Scope) -> None:
        self.host, self.scope = host, scope

    def common(self, args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        job_id = require_id(args.get("job_id"), "job_id")
        payload: dict[str, Any] = self.scope.payload()
        payload["job_id"] = job_id
        digest = optional_sha256(args.get("request_sha256"), "request_sha256")
        if digest is not None:
            payload["request_sha256"] = digest
        return job_id, payload

    def result(self, job_id: str, transaction: dict[str, Any]) -> dict[str, Any]:
        return {
            "schema": "org.trillionnium.owner-open.mcp-job-result.v1",
            "job_id": job_id,
            "scope": self.scope.payload(),
            "automatic_redispatch": False,
            **transaction,
        }

    def call(self, name: str, value: Any, cancelled: threading.Event) -> dict[str, Any]:
        args = require_object(value, "tool arguments")
        if name == "trillionnium_job_start":
            return self.start(args, cancelled)
        if name == "trillionnium_job_inspect":
            return self.inspect(args, cancelled, "job.inspect", "job.inspect.result")
        if name == "trillionnium_job_attach":
            return self.inspect(args, cancelled, "job.attach", "job.attach.result")
        if name == "trillionnium_job_detach":
            return self.detach(args, cancelled)
        if name == "trillionnium_job_write":
            return self.effect(args, cancelled, "job.write", data=True)
        if name == "trillionnium_job_resize":
            return self.effect(args, cancelled, "job.resize", resize=True)
        if name == "trillionnium_job_close_stdin":
            return self.effect(args, cancelled, "job.close_stdin")
        if name == "trillionnium_job_kill":
            return self.effect(args, cancelled, "job.kill", signal=True)
        if name == "trillionnium_job_wait":
            return self.wait(args, cancelled)
        raise InvalidArguments(f"unknown tool {name}")

    def start(self, args: dict[str, Any], cancelled: threading.Event) -> dict[str, Any]:
        job_id, payload = self.common(args)
        payload.update(
            operation_id=require_id(args.get("operation_id"), "operation_id"),
            tool="shell.job",
        )
        mode = args.get("mode")
        if mode not in {"pipe", "pty"}:
            raise InvalidArguments("mode must be pipe or pty")
        payload["mode"] = mode
        command, argv = args.get("command"), args.get("argv")
        if (command is None) == (argv is None):
            raise InvalidArguments("exactly one command or argv is required")
        if command is not None:
            if not isinstance(command, str) or not command or "\0" in command:
                raise InvalidArguments("command must be nonempty and NUL-free")
            payload["command"] = command
        else:
            if not isinstance(argv, list) or not argv or any(not isinstance(item, str) or not item or "\0" in item for item in argv):
                raise InvalidArguments("argv must contain nonempty NUL-free strings")
            payload["argv"] = list(argv)
        if "cwd" in args:
            cwd = args["cwd"]
            if not isinstance(cwd, str) or "\0" in cwd:
                raise InvalidArguments("cwd must be a NUL-free string")
            payload["cwd"] = cwd
        if "env" in args:
            env = require_object(args["env"], "env")
            for key, item in env.items():
                if not isinstance(key, str) or not key or "\0" in key or "=" in key:
                    raise InvalidArguments("env key is not mechanically representable")
                if item is not None and (not isinstance(item, str) or "\0" in item):
                    raise InvalidArguments("env value must be a string or null")
            payload["env"] = env
        if "stdin" in args:
            payload["stdin"] = job_bytes(args["stdin"])
        if mode == "pty":
            pty = require_object(args.get("pty", {"rows": 24, "cols": 80}), "pty")
            payload["pty"] = {
                "rows": require_int(pty.get("rows"), "pty.rows", 1, 65535),
                "cols": require_int(pty.get("cols"), "pty.cols", 1, 65535),
            }
        elif "pty" in args:
            raise InvalidArguments("pipe mode must not carry pty")
        if "target_id" in args:
            payload["target_id"] = require_id(args["target_id"], "target_id")
        binding = optional_sha256(args.get("binding_fingerprint"), "binding_fingerprint")
        if binding:
            payload["binding_fingerprint"] = binding
        if "extensions" in args:
            for key, item in require_object(args["extensions"], "extensions").items():
                if key in payload:
                    raise InvalidArguments(f"extension {key} conflicts with a standard field")
                payload[key] = item
        return self.result(
            job_id,
            self.host.transact("job.start", payload, expected={"job.start.result"}, job_id=job_id, cancelled=cancelled),
        )

    def inspect(self, args: dict[str, Any], cancelled: threading.Event, kind: str, expected: str) -> dict[str, Any]:
        job_id, payload = self.common(args)
        payload["inclusive_cursor"] = require_int(args.get("inclusive_cursor", 0), "inclusive_cursor", 0, (1 << 63) - 1)
        payload["limit"] = require_int(args.get("limit", 128), "limit", 1, 256)
        if kind == "job.attach":
            payload["attachment_id"] = require_id(args.get("attachment_id"), "attachment_id")
        return self.result(job_id, self.host.transact(kind, payload, expected={expected}, job_id=job_id, cancelled=cancelled))

    def detach(self, args: dict[str, Any], cancelled: threading.Event) -> dict[str, Any]:
        job_id, payload = self.common(args)
        payload["attachment_id"] = require_id(args.get("attachment_id"), "attachment_id")
        return self.result(job_id, self.host.transact("job.detach", payload, expected={"job.detach.result"}, job_id=job_id, cancelled=cancelled))

    def effect(
        self,
        args: dict[str, Any],
        cancelled: threading.Event,
        kind: str,
        *,
        data: bool = False,
        resize: bool = False,
        signal: bool = False,
    ) -> dict[str, Any]:
        job_id, payload = self.common(args)
        payload["operation_id"] = require_id(args.get("operation_id"), "operation_id")
        if data:
            payload["data"] = job_bytes(args.get("data"))
        if resize:
            payload["rows"] = require_int(args.get("rows"), "rows", 1, 65535)
            payload["cols"] = require_int(args.get("cols"), "cols", 1, 65535)
        if signal:
            payload["signal"] = require_int(args.get("signal", 15), "signal", 1, 128)
        return self.result(job_id, self.host.transact(kind, payload, expected={"job.control.result"}, job_id=job_id, cancelled=cancelled))

    def wait(self, args: dict[str, Any], cancelled: threading.Event) -> dict[str, Any]:
        raw_timeout = args.get("timeout_seconds", 60.0)
        if isinstance(raw_timeout, bool) or not isinstance(raw_timeout, (int, float)):
            raise InvalidArguments("timeout_seconds must be a number")
        timeout = float(raw_timeout)
        if not 0 <= timeout <= MAX_WAIT_SECONDS:
            raise InvalidArguments(f"timeout_seconds must be between 0 and {MAX_WAIT_SECONDS}")
        poll_ms = require_int(args.get("poll_interval_ms", 100), "poll_interval_ms", 10, 5000)
        deadline = time.monotonic() + timeout
        while True:
            if cancelled.is_set():
                raise HostProtocolError("MCP job_wait was cancelled")
            result = self.inspect(args, cancelled, "job.inspect", "job.inspect.result")
            if contains_terminal(result):
                result["wait_status"] = "terminal_observed"
                return result
            if time.monotonic() >= deadline:
                result["wait_status"] = "timeout"
                return result
            cancelled.wait(min(poll_ms / 1000, max(0.0, deadline - time.monotonic())))
