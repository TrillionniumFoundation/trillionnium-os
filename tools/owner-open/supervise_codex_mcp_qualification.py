#!/usr/bin/env python3
"""Selected outer supervisor for installed-Codex MCP qualification.

The inner qualifier remains responsible for the MCP/Host evidence. This outer
boundary owns timeout, process-group reap, best-effort server removal, exact
config restoration and final status validation so cleanup cannot be mistaken
for a qualification pass.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys
import time
from typing import Any

REPORT_SCHEMA = "org.trillionnium.owner-open.codex-mcp-qualification-supervisor.v1"
MAX_CONFIG_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
TERM_GRACE = 1.0
KILL_GRACE = 2.0
FORBIDDEN_FORWARD = {
    "--execute",
    "--codex",
    "--python",
    "--codex-home",
    "--workspace",
    "--evidence-dir",
    "--server-name",
}


class SupervisorError(RuntimeError):
    pass


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def private_directory(path: Path, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise SupervisorError(f"{label} must be an absolute real directory")
    metadata = path.lstat()
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise SupervisorError(f"{label} must be private and service-owned")
    return path


def stable_file(path: Path, label: str, *, executable: bool) -> Path:
    if not path.is_absolute():
        raise SupervisorError(f"{label} must be absolute")
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_mode & 0o022
        or (executable and (metadata.st_mode & 0o111 == 0 or not os.access(path, os.X_OK)))
    ):
        raise SupervisorError(f"{label} is not a stable private file")
    return path


def snapshot_config(path: Path) -> tuple[bool, bytes, int]:
    if not path.exists():
        return False, b"", 0o600
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size > MAX_CONFIG_BYTES
    ):
        raise SupervisorError("CODEX_HOME config.toml is not a bounded real file")
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        raise SupervisorError("CODEX_HOME config.toml changed while read")
    return True, raw, stat.S_IMODE(metadata.st_mode)


def atomic_write(path: Path, raw: bytes, mode: int = 0o600) -> None:
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise SupervisorError("atomic write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        os.chmod(path, mode)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def restore_config(path: Path, snapshot: tuple[bool, bytes, int]) -> None:
    existed, raw, mode = snapshot
    if existed:
        atomic_write(path, raw, mode)
    else:
        path.unlink(missing_ok=True)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def terminate_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + TERM_GRACE
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.02)
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=KILL_GRACE)
    except subprocess.TimeoutExpired as error:
        raise SupervisorError("qualification process group could not be reaped") from error


def bounded_run(
    argv: list[str],
    *,
    environment: dict[str, str],
    cwd: Path,
    timeout: float,
) -> dict[str, Any]:
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        cwd=cwd,
        start_new_session=True,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        terminate_group(process)
        stdout, stderr = process.communicate(timeout=KILL_GRACE)
    if len(stdout) + len(stderr) > MAX_OUTPUT_BYTES:
        raise SupervisorError("qualification command output exceeds its byte bound")
    return {
        "argv_sha256": sha256_bytes(json.dumps(argv, separators=(",", ":")).encode()),
        "returncode": process.returncode,
        "timed_out": timed_out,
        "elapsed_ms": max(0, int((time.monotonic() - started) * 1000)),
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_sha256": sha256_bytes(stderr),
        "stdout_base64": base64.b64encode(stdout).decode("ascii"),
        "stderr_base64": base64.b64encode(stderr).decode("ascii"),
    }


def read_terminal(evidence: Path) -> dict[str, Any] | None:
    path = evidence / "qualification-terminal.json"
    if not path.exists():
        return None
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_CONFIG_BYTES:
        raise SupervisorError("qualification terminal is not a bounded real file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SupervisorError(f"invalid qualification terminal: {error}") from error
    if not isinstance(value, dict):
        raise SupervisorError("qualification terminal is not an object")
    return value


def validate_forwarded(values: list[str]) -> list[str]:
    result = list(values)
    if result and result[0] == "--":
        result = result[1:]
    for item in result:
        if item in FORBIDDEN_FORWARD:
            raise SupervisorError(f"forwarded qualifier args may not override {item}")
        if "\x00" in item:
            raise SupervisorError("forwarded qualifier argument contains NUL")
    return result


def execute(args: argparse.Namespace) -> dict[str, Any]:
    python = stable_file(args.python, "Python", executable=True)
    qualifier = stable_file(args.qualifier, "inner qualifier", executable=False)
    codex = stable_file(args.codex, "Codex", executable=True)
    codex_home = private_directory(args.codex_home, "CODEX_HOME")
    workspace = private_directory(args.workspace, "workspace")
    if not args.evidence_dir.is_absolute() or not args.evidence_dir.parent.is_dir():
        raise SupervisorError("evidence directory must be an absolute child of an existing parent")
    if args.evidence_dir.exists() or args.evidence_dir.is_symlink():
        raise SupervisorError("evidence directory already exists")
    if re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", args.server_name) is None:
        raise SupervisorError("server name is malformed")
    forwarded = validate_forwarded(args.qualifier_args)
    config = codex_home / "config.toml"
    snapshot = snapshot_config(config)
    snapshot_digest = sha256_bytes(snapshot[1]) if snapshot[0] else None
    lock = codex_home / ".trillionnium-qualification-supervisor.lock"
    lock_descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(lock_descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(lock_descriptor)
    finally:
        os.close(lock_descriptor)
    environment = os.environ.copy()
    environment["CODEX_HOME"] = str(codex_home)
    child_argv = [
        str(python),
        str(qualifier),
        "--execute",
        "--codex",
        str(codex),
        "--python",
        str(python),
        "--codex-home",
        str(codex_home),
        "--workspace",
        str(workspace),
        "--evidence-dir",
        str(args.evidence_dir),
        "--server-name",
        args.server_name,
        *forwarded,
    ]
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "status": "failed",
        "server_name": args.server_name,
        "config_before_sha256": snapshot_digest,
        "automatic_redispatch": False,
        "public_release": False,
    }
    cleanup: dict[str, Any] = {}
    try:
        child = bounded_run(
            child_argv,
            environment=environment,
            cwd=workspace,
            timeout=args.timeout,
        )
        report["inner_process"] = child
        terminal = read_terminal(args.evidence_dir)
        report["inner_terminal"] = terminal
        passed = (
            not child["timed_out"]
            and child["returncode"] == 0
            and isinstance(terminal, dict)
            and terminal.get("status") == "passed"
        )
        if not passed:
            raise SupervisorError("inner qualification did not produce status=passed")
        report["status"] = "passed"
        report["claim_ceiling"] = "INSTALLED_CODEX_MCP_HOST_PROCESS_QUALIFIED_L2_CANDIDATE"
        return report
    except Exception as error:
        report["error_type"] = type(error).__name__
        report["error"] = str(error)
        report["claim_ceiling"] = "QUALIFICATION_FAILED_NO_PROMOTION"
        raise
    finally:
        try:
            cleanup["mcp_remove"] = bounded_run(
                [str(codex), "mcp", "remove", args.server_name],
                environment=environment,
                cwd=workspace,
                timeout=args.cleanup_timeout,
            )
        except Exception as error:
            cleanup["mcp_remove_error"] = f"{type(error).__name__}: {error}"
        try:
            restore_config(config, snapshot)
            current = config.read_bytes() if config.exists() else b""
            cleanup["config_restored"] = (config.exists() == snapshot[0]) and current == snapshot[1]
            cleanup["config_after_sha256"] = sha256_bytes(current) if config.exists() else None
        except Exception as error:
            cleanup["config_restored"] = False
            cleanup["config_restore_error"] = f"{type(error).__name__}: {error}"
        lock.unlink(missing_ok=True)
        report["cleanup"] = cleanup
        if report.get("status") == "passed" and not cleanup.get("config_restored"):
            report["status"] = "failed_cleanup"
            report["claim_ceiling"] = "QUALIFICATION_FAILED_NO_PROMOTION"
        output = args.evidence_dir.parent / f"{args.evidence_dir.name}.supervisor.json"
        atomic_write(
            output,
            json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n",
        )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--python", required=True, type=Path)
    parser.add_argument("--qualifier", required=True, type=Path)
    parser.add_argument("--codex", required=True, type=Path)
    parser.add_argument("--codex-home", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--server-name", required=True)
    parser.add_argument("--timeout", type=float, default=600.0)
    parser.add_argument("--cleanup-timeout", type=float, default=30.0)
    parser.add_argument("qualifier_args", nargs=argparse.REMAINDER)
    result = parser.parse_args(argv)
    if not result.execute:
        parser.error("--execute is required")
    if not 1 <= result.timeout <= 3600 or not 0.1 <= result.cleanup_timeout <= 120:
        parser.error("qualification or cleanup timeout is outside the finite bound")
    return result


def main(argv: list[str]) -> int:
    try:
        report = execute(parse_args(argv))
    except (OSError, SupervisorError, subprocess.SubprocessError) as error:
        print(f"HOLD: {error}", file=sys.stderr)
        return 1
    if report.get("status") != "passed" or not report.get("cleanup", {}).get("config_restored"):
        print("HOLD: supervisor did not finish with a restored passed state", file=sys.stderr)
        return 1
    print("PASS_SUPERVISED_INSTALLED_CODEX_MCP_QUALIFICATION")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
