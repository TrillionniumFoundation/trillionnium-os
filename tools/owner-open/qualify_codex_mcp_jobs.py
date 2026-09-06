#!/usr/bin/env python3
"""Qualify one installed Codex CLI against the owner-open MCP job bridge.

Execution is explicit and evidence-bound. The tool registers one temporary
STDIO MCP server inside a dedicated private CODEX_HOME, runs one bounded Codex
turn, validates the exact job-tool sequence from an exact-byte trace, removes
the server, and restores the original configuration bytes.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import time
from typing import Any

REPORT_SCHEMA = "org.trillionnium.owner-open.codex-mcp-job-qualification.v1"
PROBE_SCHEMA = "org.trillionnium.owner-open.codex-mcp-probe.v1"
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_JSON_LINE_BYTES = 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 300.0
FINAL_MARKER = "TRILLIONNIUM_OWNER_OPEN_MCP_JOBS_QUALIFIED"
EXPECTED_TOOLS = [
    "trillionnium_connection_info",
    "trillionnium_job_start",
    "trillionnium_job_write",
    "trillionnium_job_close_stdin",
    "trillionnium_job_wait",
    "trillionnium_job_start",
    "trillionnium_job_write",
    "trillionnium_job_resize",
    "trillionnium_job_inspect",
    "trillionnium_job_kill",
    "trillionnium_job_wait",
]


class QualificationError(RuntimeError):
    pass


class DuplicateMember(ValueError):
    pass


def strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateMember(f"duplicate key {key}")
        value[key] = item
    return value


def strict_json(raw: bytes, *, label: str, maximum: int = MAX_JSON_LINE_BYTES) -> Any:
    if not raw or len(raw) > maximum:
        raise QualificationError(f"{label} is empty or exceeds {maximum} bytes")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=strict_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateMember) as error:
        raise QualificationError(f"invalid {label}: {error}") from error


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require_private_directory(path: Path, label: str, *, empty: bool = False) -> Path:
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise QualificationError(f"{label} must be an absolute real directory")
    metadata = path.lstat()
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise QualificationError(f"{label} must be owned by the service UID and private")
    if empty and any(path.iterdir()):
        raise QualificationError(f"{label} must be empty")
    return path


def require_new_output_directory(path: Path) -> Path:
    if not path.is_absolute() or not path.parent.is_dir() or path.parent.is_symlink():
        raise QualificationError("evidence directory must be an absolute new path")
    parent = path.parent.lstat()
    if parent.st_uid not in {0, os.geteuid()}:
        raise QualificationError("evidence parent is not owner controlled")
    if path.exists() or path.is_symlink():
        raise QualificationError("evidence directory already exists")
    path.mkdir(mode=0o700)
    return path


def measure_file(path: Path, label: str, *, executable: bool) -> dict[str, Any]:
    if not path.is_absolute():
        raise QualificationError(f"{label} must be absolute")
    before = path.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > MAX_FILE_BYTES
        or before.st_mode & 0o022
        or (executable and (before.st_mode & 0o111 == 0 or not os.access(path, os.X_OK)))
    ):
        raise QualificationError(f"{label} is not a stable bounded file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256()
    size = 0
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            if size > MAX_FILE_BYTES:
                raise QualificationError(f"{label} exceeds the byte bound")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_uid,
        before.st_gid,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_uid,
        after.st_gid,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after or size != before.st_size:
        raise QualificationError(f"{label} changed while measured")
    return {
        "path": str(path),
        "sha256": digest.hexdigest(),
        "bytes": size,
        "uid": before.st_uid,
        "gid": before.st_gid,
        "mode": f"{stat.S_IMODE(before.st_mode):04o}",
        "device": before.st_dev,
        "inode": before.st_ino,
    }


def check_expected(measurement: dict[str, Any], expected: str | None, label: str) -> None:
    if expected is None:
        return
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise QualificationError(f"expected {label} digest is malformed")
    if measurement["sha256"] != expected:
        raise QualificationError(f"{label} digest does not match the expected value")


def atomic_write(path: Path, raw: bytes) -> None:
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise QualificationError("evidence write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def write_json(path: Path, value: Any) -> None:
    atomic_write(path, json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n")


@dataclass(frozen=True)
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: bytes
    stderr: bytes
    elapsed_ms: int

    def record(self) -> dict[str, Any]:
        return {
            "argv": self.argv,
            "returncode": self.returncode,
            "elapsed_ms": self.elapsed_ms,
            "stdout_bytes": len(self.stdout),
            "stderr_bytes": len(self.stderr),
            "stdout_sha256": sha256_bytes(self.stdout),
            "stderr_sha256": sha256_bytes(self.stderr),
            "stdout_base64": base64.b64encode(self.stdout).decode("ascii"),
            "stderr_base64": base64.b64encode(self.stderr).decode("ascii"),
        }


def bounded_run(
    argv: list[str],
    *,
    environment: dict[str, str],
    cwd: Path | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    stdin: bytes | None = None,
) -> CommandResult:
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=environment,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(stdin, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=1.0)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate(timeout=2.0)
        raise QualificationError(f"command timed out after {timeout}s: {argv[:3]}") from error
    if len(stdout) + len(stderr) > MAX_OUTPUT_BYTES:
        raise QualificationError(f"command output exceeds {MAX_OUTPUT_BYTES} bytes")
    return CommandResult(
        argv=list(argv),
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
        elapsed_ms=max(0, int((time.monotonic() - started) * 1000)),
    )


def require_success(result: CommandResult, label: str) -> CommandResult:
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace")[-2048:]
        raise QualificationError(f"{label} failed with {result.returncode}: {detail}")
    return result


def parse_json_output(result: CommandResult, label: str) -> Any:
    require_success(result, label)
    return strict_json(result.stdout.strip(), label=label, maximum=MAX_OUTPUT_BYTES)


def parse_jsonl(raw: bytes, label: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    if len(raw) > MAX_OUTPUT_BYTES:
        raise QualificationError(f"{label} exceeds the byte bound")
    for index, line in enumerate(raw.splitlines()):
        if not line:
            continue
        value = strict_json(line, label=f"{label} line {index}")
        if not isinstance(value, dict):
            raise QualificationError(f"{label} line {index} is not an object")
        result.append(value)
    if not result:
        raise QualificationError(f"{label} contains no records")
    return result


def tool_call(message: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    if message.get("method") != "tools/call":
        return None
    params = message.get("params")
    if not isinstance(params, dict) or not isinstance(params.get("name"), str):
        raise QualificationError("traced tools/call params are malformed")
    arguments = params.get("arguments", {})
    if not isinstance(arguments, dict):
        raise QualificationError("traced tools/call arguments are not an object")
    return params["name"], arguments


def validate_trace(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    records = parse_jsonl(raw, "MCP trace")
    calls: list[tuple[str, dict[str, Any]]] = []
    responses: dict[str, dict[str, Any]] = {}
    request_ids: list[str] = []
    for record in records:
        if record.get("schema") != "org.trillionnium.owner-open.mcp-stdio-trace.v1":
            raise QualificationError("MCP trace schema drifted")
        if record.get("kind") != "frame":
            continue
        message = record.get("message")
        if not isinstance(message, dict):
            raise QualificationError("MCP trace frame has no parsed message")
        raw_line = base64.b64decode(record.get("raw_line_base64", ""), validate=True)
        if len(raw_line) != record.get("byte_count") or sha256_bytes(raw_line) != record.get("sha256"):
            raise QualificationError("MCP trace raw byte identity is inconsistent")
        if record.get("direction") == "client_to_server":
            call = tool_call(message)
            if call is not None:
                calls.append(call)
                request_ids.append(canonical(message.get("id")).decode("utf-8"))
        elif record.get("direction") == "server_to_client" and "id" in message:
            responses[canonical(message.get("id")).decode("utf-8")] = message

    names = [name for name, _arguments in calls]
    if names != EXPECTED_TOOLS:
        raise QualificationError(f"unexpected MCP tool sequence: {names}")
    if len(request_ids) != len(set(request_ids)):
        raise QualificationError("MCP tool request IDs are not unique")
    for request_id in request_ids:
        response = responses.get(request_id)
        if response is None or response.get("error") is not None:
            raise QualificationError(f"MCP tool request {request_id} has no successful response")
        result = response.get("result")
        if not isinstance(result, dict) or result.get("isError") is True:
            raise QualificationError(f"MCP tool request {request_id} returned a tool error")

    connection = calls[0][1]
    if connection:
        raise QualificationError("connection_info must receive an empty argument object")
    bridge_id: str | None = None
    first_response = responses[request_ids[0]].get("result")
    if isinstance(first_response, dict):
        structured = first_response.get("structuredContent")
        if isinstance(structured, dict) and isinstance(structured.get("bridge_instance_id"), str):
            bridge_id = structured["bridge_instance_id"]
    if not bridge_id:
        raise QualificationError("connection_info did not return bridge_instance_id")

    expected = [
        (1, "pipe-job", "pipe-start"),
        (2, "pipe-job", "pipe-write"),
        (3, "pipe-job", "pipe-close"),
        (5, "pty-job", "pty-start"),
        (6, "pty-job", "pty-write"),
        (7, "pty-job", "pty-resize"),
        (9, "pty-job", "pty-kill"),
    ]
    for index, job_id, operation_id in expected:
        arguments = calls[index][1]
        if arguments.get("job_id") != job_id or arguments.get("operation_id") != operation_id:
            raise QualificationError(f"tool call {index + 1} has unexpected job or operation identity")
        if arguments.get("bridge_instance_id") != bridge_id:
            raise QualificationError(f"tool call {index + 1} is not bound to the live bridge")
    for index in (4, 8, 10):
        if calls[index][1].get("job_id") not in {"pipe-job", "pty-job"}:
            raise QualificationError(f"read-only call {index + 1} has an unexpected job")
    if calls[1][1].get("mode") != "pipe" or calls[5][1].get("mode") != "pty":
        raise QualificationError("pipe or PTY start mode drifted")
    if calls[7][1].get("rows") != 40 or calls[7][1].get("cols") != 120:
        raise QualificationError("PTY resize dimensions drifted")
    if calls[9][1].get("signal") != 15:
        raise QualificationError("PTY kill signal drifted")
    return {
        "trace_sha256": sha256_bytes(raw),
        "trace_bytes": len(raw),
        "records": len(records),
        "tool_calls": len(calls),
        "bridge_instance_id_sha256": sha256_bytes(bridge_id.encode("utf-8")),
        "validated_tools": names,
    }


def validate_codex_events(raw: bytes) -> dict[str, Any]:
    events = parse_jsonl(raw, "Codex JSONL")
    kinds = [event.get("type") or event.get("kind") for event in events]
    if any(kind in {"turn.failed", "error", "item.failed"} for kind in kinds):
        raise QualificationError(f"Codex JSONL contains failure events: {kinds}")
    completed = any(kind in {"turn.completed", "task.completed"} for kind in kinds)
    text = raw.decode("utf-8", errors="replace")
    if not completed:
        raise QualificationError("Codex JSONL has no completed turn event")
    if FINAL_MARKER not in text:
        raise QualificationError("Codex JSONL does not contain the final qualification marker")
    return {
        "events": len(events),
        "event_types": kinds,
        "sha256": sha256_bytes(raw),
        "bytes": len(raw),
        "completed": True,
        "final_marker": FINAL_MARKER,
    }


def qualification_prompt() -> str:
    return f"""Use only the Trillionnium owner-open MCP tools and perform exactly this sequence.
1. Call trillionnium_connection_info with an empty object and retain bridge_instance_id.
2. Start pipe-job with operation_id pipe-start, mode pipe, command 'cat'.
3. Write 'hello from pipe\\n' using operation_id pipe-write and the bridge ID.
4. Close pipe-job stdin using operation_id pipe-close and the bridge ID.
5. Wait for pipe-job terminal observation.
6. Start pty-job with operation_id pty-start, mode pty, command 'cat', rows 24, cols 80, and the bridge ID.
7. Write 'hello from pty\\n' using operation_id pty-write and the bridge ID.
8. Resize pty-job to rows 40 and cols 120 using operation_id pty-resize and the bridge ID.
9. Inspect pty-job.
10. Kill pty-job with signal 15 using operation_id pty-kill and the bridge ID.
11. Wait for pty-job terminal observation.
Do not call any additional tool and do not retry an uncertain effect. After all eleven successful calls, output exactly {FINAL_MARKER}.
"""


def config_snapshot(path: Path) -> tuple[bool, bytes, int]:
    if not path.exists():
        return False, b"", 0o600
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise QualificationError("CODEX_HOME config.toml is not a regular file")
    raw = path.read_bytes()
    if len(raw) != metadata.st_size or len(raw) > MAX_OUTPUT_BYTES:
        raise QualificationError("CODEX_HOME config.toml changed or is oversized")
    return True, raw, stat.S_IMODE(metadata.st_mode)


def restore_config(path: Path, snapshot: tuple[bool, bytes, int]) -> None:
    existed, raw, mode = snapshot
    if existed:
        atomic_write(path, raw)
        os.chmod(path, mode)
    else:
        path.unlink(missing_ok=True)


def server_command(args: argparse.Namespace, evidence: Path, connection_id: str) -> list[str]:
    downstream = [
        str(args.python),
        str(args.mcp_bridge),
        "--host",
        str(args.host),
        "--provider",
        str(args.provider),
        "--job-store",
        str(args.job_store),
        "--event-store",
        str(args.event_store),
        "--session-id",
        "qualification-session",
        "--task-id",
        "qualification-task",
        "--turn-id",
        "qualification-turn",
        "--turn-stream-id",
        "qualification-stream",
    ]
    if args.core:
        downstream += ["--core", str(args.core)]
    if args.shell:
        downstream += ["--shell", str(args.shell)]
    return [
        str(args.python),
        str(args.trace_proxy),
        "--trace",
        str(evidence / "mcp-trace.jsonl"),
        "--stderr",
        str(evidence / "mcp-stderr.bin"),
        "--connection-id",
        connection_id,
        "--",
        *downstream,
    ]


def execute(args: argparse.Namespace) -> dict[str, Any]:
    codex_home = require_private_directory(args.codex_home, "CODEX_HOME")
    workspace = require_private_directory(args.workspace, "workspace")
    evidence = require_new_output_directory(args.evidence_dir)
    lock = codex_home / ".trillionnium-mcp-qualification.lock"
    lock_fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(lock_fd, f"pid={os.getpid()}\n".encode("ascii"))
    os.fsync(lock_fd)
    os.close(lock_fd)
    environment = os.environ.copy()
    environment["CODEX_HOME"] = str(codex_home)
    config = codex_home / "config.toml"
    snapshot = config_snapshot(config)
    registered = False
    commands: dict[str, Any] = {}
    terminal: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "status": "failed",
        "public_release": False,
        "claims": {
            "installed_codex_measured": False,
            "mcp_registered": False,
            "codex_turn_completed": False,
            "exact_job_sequence_validated": False,
            "physical_device_effect": False,
            "release_qualified": False,
        },
    }
    try:
        measurements: dict[str, Any] = {}
        for name, path, executable, expected in [
            ("codex", args.codex, True, args.expected_codex_sha256),
            ("python", args.python, True, args.expected_python_sha256),
            ("trace_proxy", args.trace_proxy, False, args.expected_trace_proxy_sha256),
            ("mcp_bridge", args.mcp_bridge, False, args.expected_mcp_bridge_sha256),
            ("host", args.host, True, args.expected_host_sha256),
            ("provider", args.provider, True, args.expected_provider_sha256),
        ]:
            measurement = measure_file(path, name, executable=executable)
            check_expected(measurement, expected, name)
            measurements[name] = measurement
        for name, path, expected in [
            ("core", args.core, args.expected_core_sha256),
            ("shell", args.shell, args.expected_shell_sha256),
        ]:
            if path is not None:
                measurement = measure_file(path, name, executable=True)
                check_expected(measurement, expected, name)
                measurements[name] = measurement
        terminal["measurements"] = measurements
        terminal["claims"]["installed_codex_measured"] = True

        for label, command in {
            "version": [str(args.codex), "--version"],
            "root_help": [str(args.codex), "--help"],
            "mcp_help": [str(args.codex), "mcp", "--help"],
            "exec_help": [str(args.codex), "exec", "--help"],
            "login_status": [str(args.codex), "login", "status"],
        }.items():
            result = require_success(
                bounded_run(command, environment=environment, cwd=workspace, timeout=args.command_timeout),
                label,
            )
            commands[label] = result.record()
        help_text = base64.b64decode(commands["mcp_help"]["stdout_base64"]).decode("utf-8", errors="replace")
        for token in ("add", "get", "list", "remove"):
            if token not in help_text:
                raise QualificationError(f"installed Codex MCP help does not advertise {token}")

        existing = bounded_run(
            [str(args.codex), "mcp", "get", args.server_name, "--json"],
            environment=environment,
            cwd=workspace,
            timeout=args.command_timeout,
        )
        commands["preexisting_get"] = existing.record()
        if existing.returncode == 0:
            raise QualificationError("qualification MCP server name already exists")

        connection_id = f"qualification-{secrets.token_hex(16)}"
        command = server_command(args, evidence, connection_id)
        add = require_success(
            bounded_run(
                [str(args.codex), "mcp", "add", args.server_name, "--", *command],
                environment=environment,
                cwd=workspace,
                timeout=args.command_timeout,
            ),
            "codex mcp add",
        )
        registered = True
        terminal["claims"]["mcp_registered"] = True
        commands["mcp_add"] = add.record()
        get_result = bounded_run(
            [str(args.codex), "mcp", "get", args.server_name, "--json"],
            environment=environment,
            cwd=workspace,
            timeout=args.command_timeout,
        )
        list_result = bounded_run(
            [str(args.codex), "mcp", "list", "--json"],
            environment=environment,
            cwd=workspace,
            timeout=args.command_timeout,
        )
        get_json = parse_json_output(get_result, "codex mcp get")
        list_json = parse_json_output(list_result, "codex mcp list")
        commands["mcp_get"] = get_result.record()
        commands["mcp_list"] = list_result.record()
        write_json(evidence / "mcp-get.json", get_json)
        write_json(evidence / "mcp-list.json", list_json)
        serialized = canonical(get_json)
        if str(args.trace_proxy).encode("utf-8") not in serialized or str(args.mcp_bridge).encode("utf-8") not in serialized:
            raise QualificationError("registered MCP command does not bind the trace proxy and bridge")

        exec_argv = [str(args.codex), "exec", "--json"]
        exec_help = base64.b64decode(commands["exec_help"]["stdout_base64"]).decode("utf-8", errors="replace")
        if "--dangerously-bypass-approvals-and-sandbox" in exec_help:
            exec_argv.append("--dangerously-bypass-approvals-and-sandbox")
        elif "danger-full-access" in exec_help and "--sandbox" in exec_help:
            exec_argv += ["--sandbox", "danger-full-access"]
        else:
            raise QualificationError("installed Codex exposes no observed owner-open execution mode")
        if args.model:
            exec_argv += ["--model", args.model]
        exec_argv.append(qualification_prompt())
        run = require_success(
            bounded_run(
                exec_argv,
                environment=environment,
                cwd=workspace,
                timeout=args.turn_timeout,
            ),
            "codex exec qualification turn",
        )
        commands["codex_exec"] = run.record()
        atomic_write(evidence / "codex-events.jsonl", run.stdout)
        atomic_write(evidence / "codex-stderr.bin", run.stderr)
        event_summary = validate_codex_events(run.stdout)
        trace_summary = validate_trace(evidence / "mcp-trace.jsonl")
        terminal["claims"]["codex_turn_completed"] = True
        terminal["claims"]["exact_job_sequence_validated"] = True
        terminal.update(
            status="passed",
            connection_id_sha256=sha256_bytes(connection_id.encode("utf-8")),
            codex_events=event_summary,
            mcp_trace=trace_summary,
            automatic_redispatch=False,
            claim_ceiling="INSTALLED_CODEX_MCP_HOST_PROCESS_QUALIFIED_L2_CANDIDATE",
        )
        return terminal
    except Exception as error:
        terminal["error_type"] = type(error).__name__
        terminal["error"] = str(error)
        terminal["automatic_redispatch"] = False
        terminal["claim_ceiling"] = "QUALIFICATION_FAILED_NO_PROMOTION"
        raise
    finally:
        if registered:
            remove = bounded_run(
                [str(args.codex), "mcp", "remove", args.server_name],
                environment=environment,
                cwd=workspace,
                timeout=args.command_timeout,
            )
            commands["mcp_remove"] = remove.record()
            if remove.returncode != 0 and terminal.get("status") == "passed":
                terminal["status"] = "failed_cleanup"
                terminal["error"] = "codex mcp remove failed"
        try:
            restore_config(config, snapshot)
        finally:
            lock.unlink(missing_ok=True)
        terminal["commands"] = commands
        terminal["config_restored_sha256"] = sha256_bytes(config.read_bytes()) if config.exists() else None
        write_json(evidence / "qualification-terminal.json", terminal)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--codex", required=True, type=Path)
    parser.add_argument("--python", required=True, type=Path)
    parser.add_argument("--trace-proxy", required=True, type=Path)
    parser.add_argument("--mcp-bridge", required=True, type=Path)
    parser.add_argument("--host", required=True, type=Path)
    parser.add_argument("--core", type=Path)
    parser.add_argument("--provider", required=True, type=Path)
    parser.add_argument("--shell", type=Path)
    parser.add_argument("--job-store", required=True, type=Path)
    parser.add_argument("--event-store", required=True, type=Path)
    parser.add_argument("--codex-home", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--server-name", default="trillionnium-owner-open-jobs-qualification")
    parser.add_argument("--model")
    parser.add_argument("--command-timeout", type=float, default=30.0)
    parser.add_argument("--turn-timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    for name in ("codex", "python", "trace-proxy", "mcp-bridge", "host", "core", "provider", "shell"):
        parser.add_argument(f"--expected-{name}-sha256")
    result = parser.parse_args(argv)
    if not result.execute:
        parser.error("--execute is required; qualification mutates a dedicated CODEX_HOME temporarily")
    if not 1 <= result.command_timeout <= 120 or not 1 <= result.turn_timeout <= 1800:
        parser.error("command or turn timeout is outside the finite bound")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", result.server_name):
        parser.error("server name is malformed")
    return result


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    terminal: dict[str, Any] | None = None
    try:
        terminal = execute(args)
    except (OSError, QualificationError, subprocess.SubprocessError) as error:
        print(f"HOLD: {error}", file=sys.stderr)
        return 1
    print(
        "PASS_INSTALLED_CODEX_MCP_JOB_QUALIFICATION "
        f"events={terminal['codex_events']['events']} calls={terminal['mcp_trace']['tool_calls']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
