#!/usr/bin/env python3
"""Read-only capability probe for an installed Codex CLI.

The probe executes only version/help commands. It never starts `codex exec`,
opens a credential file, contacts a provider, starts an MCP server, or claims a
live turn. The resulting report is configuration evidence, not provider
admission or release evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from typing import Any


REPORT_SCHEMA = "org.trillionnium.owner-open.codex-cli-probe.v1"
MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
PROBE_TIMEOUT_SECONDS = 10


class ProbeError(ValueError):
    pass


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def inspect_executable(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    mode = stat.S_IMODE(metadata.st_mode)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ProbeError("Codex executable must be a real regular file")
    if metadata.st_nlink == 0 or metadata.st_size == 0:
        raise ProbeError("Codex executable is unlinked or empty")
    if metadata.st_size > MAX_EXECUTABLE_BYTES:
        raise ProbeError("Codex executable exceeds the probe byte bound")
    if mode & 0o111 == 0:
        raise ProbeError("Codex executable has no executable bit")
    if mode & 0o022:
        raise ProbeError("Codex executable is group/world writable")

    before = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
    with path.open("rb") as handle:
        digest = hashlib.sha256()
        read = 0
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            read += len(chunk)
            if read > MAX_EXECUTABLE_BYTES:
                raise ProbeError("Codex executable exceeds the probe byte bound")
            digest.update(chunk)
        after_stat = os.fstat(handle.fileno())
    after = (
        after_stat.st_dev,
        after_stat.st_ino,
        after_stat.st_uid,
        after_stat.st_gid,
        after_stat.st_mode,
        after_stat.st_nlink,
        after_stat.st_size,
        after_stat.st_mtime_ns,
        after_stat.st_ctime_ns,
    )
    if before != after or read != metadata.st_size:
        raise ProbeError("Codex executable changed while being measured")
    return {
        "path": str(path),
        "sha256": digest.hexdigest(),
        "bytes": read,
        "mode": f"{mode:04o}",
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }


def bounded_probe(path: Path, arguments: list[str]) -> dict[str, Any]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            [str(path), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=PROBE_TIMEOUT_SECONDS,
            check=False,
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired as error:
        raise ProbeError(f"Codex help probe timed out: {arguments}") from error
    stdout = completed.stdout
    stderr = completed.stderr
    if len(stdout) + len(stderr) > MAX_OUTPUT_BYTES:
        raise ProbeError(f"Codex help probe output exceeded the byte bound: {arguments}")
    try:
        stdout_text = stdout.decode("utf-8")
        stderr_text = stderr.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProbeError(f"Codex help probe output is not UTF-8: {arguments}") from error
    if completed.returncode != 0:
        raise ProbeError(
            f"Codex help probe failed for {arguments}: exit={completed.returncode}; "
            f"stderr={stderr_text[:512]!r}"
        )
    return {
        "argv": arguments,
        "exit_code": completed.returncode,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "stdout": stdout_text,
        "stderr": stderr_text,
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_sha256": sha256_bytes(stderr),
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
    }


def option_present(text: str, option: str) -> bool:
    return re.search(rf"(?<![A-Za-z0-9_-]){re.escape(option)}(?![A-Za-z0-9_-])", text) is not None


def probe(path: Path) -> dict[str, Any]:
    executable = inspect_executable(path)
    version = bounded_probe(path, ["--version"])
    root_help = bounded_probe(path, ["--help"])
    exec_help = bounded_probe(path, ["exec", "--help"])
    combined_root = root_help["stdout"] + "\n" + root_help["stderr"]
    combined_exec = exec_help["stdout"] + "\n" + exec_help["stderr"]
    version_text = version["stdout"] + "\n" + version["stderr"]

    capabilities = {
        "exec_subcommand_observed": bool(re.search(r"(?m)^\s*exec\b", combined_root))
        or "codex exec" in combined_exec.lower(),
        "json_event_flag_observed": option_present(combined_exec, "--json"),
        "sandbox_long_flag_observed": option_present(combined_exec, "--sandbox"),
        "sandbox_short_flag_observed": option_present(combined_exec, "-s"),
        "danger_full_access_value_observed": "danger-full-access" in combined_exec,
        "bypass_approvals_and_sandbox_flag_observed": option_present(
            combined_exec, "--dangerously-bypass-approvals-and-sandbox"
        ),
        "model_flag_observed": option_present(combined_exec, "--model")
        or option_present(combined_exec, "-m"),
        "config_override_flag_observed": option_present(combined_exec, "--config")
        or option_present(combined_exec, "-c"),
    }

    return {
        "schema": REPORT_SCHEMA,
        "observed_at_unix_ms": int(time.time() * 1000),
        "executable": executable,
        "version_text": version_text.strip(),
        "probes": {
            "version": version,
            "root_help": root_help,
            "exec_help": exec_help,
        },
        "capabilities": capabilities,
        "claims": {
            "help_only": True,
            "credentials_opened_by_probe": False,
            "provider_contacted": False,
            "model_invoked": False,
            "exec_turn_started": False,
            "mcp_server_started": False,
            "owner_open_flags_verified_by_execution": False,
            "integrated_host": False,
            "same_turn_tool_effect": False,
            "release_evidence": False,
        },
        "claim_ceiling": "INSTALLED_CLI_HELP_OBSERVATION_ONLY",
    }


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}"
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--codex", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    arguments = parse_args(argv)
    try:
        report = probe(arguments.codex)
        if arguments.output:
            atomic_write(arguments.output, report)
    except (OSError, ProbeError, subprocess.SubprocessError) as error:
        response = {"schema": REPORT_SCHEMA, "ok": False, "error": str(error)}
        if arguments.json:
            print(json.dumps(response, sort_keys=True))
        else:
            print(f"HOLD: {error}", file=sys.stderr)
        return 1
    if arguments.json or not arguments.output:
        print(json.dumps({"ok": True, **report}, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print(
            "PASS_HELP_OBSERVATION_ONLY "
            f"sha256={report['executable']['sha256']} version={report['version_text']!r}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
