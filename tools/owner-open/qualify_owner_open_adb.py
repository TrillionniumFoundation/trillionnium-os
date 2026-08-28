#!/usr/bin/env python3
"""Execute an explicit ordinary-adb qualification plan through the relay.

The runner configures only ADB_SERVER_SOCKET. Every plan argv is passed to the
measured adb executable exactly once and in order. It never injects a serial,
selects a transport, interprets a subcommand, or retries an uncertain step.
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
import signal
import stat
import subprocess
import sys
import time
from typing import Any

PLAN_SCHEMA = "org.trillionnium.owner-open.adb-qualification-plan.v1"
REPORT_SCHEMA = "org.trillionnium.owner-open.adb-qualification-report.v1"
MAX_PLAN_BYTES = 4 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_STEPS = 256
MAX_ARGV_ITEMS = 4096
MAX_ARGUMENT_BYTES = 64 * 1024
MAX_TOTAL_ARGV_BYTES = 1024 * 1024


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


def strict_json(raw: bytes, label: str, maximum: int) -> Any:
    if not raw or len(raw) > maximum:
        raise QualificationError(f"{label} is empty or exceeds {maximum} bytes")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=strict_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateMember) as error:
        raise QualificationError(f"invalid {label}: {error}") from error


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def validate_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", value) is None:
        raise QualificationError(f"{label} is empty, oversized or malformed")
    return value


def validate_argv(value: Any) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > MAX_ARGV_ITEMS:
        raise QualificationError("step argv is empty or has too many elements")
    result: list[str] = []
    total = 0
    for item in value:
        if not isinstance(item, str):
            raise QualificationError("step argv elements must be strings")
        encoded = item.encode("utf-8")
        if not encoded or b"\x00" in encoded or len(encoded) > MAX_ARGUMENT_BYTES:
            raise QualificationError("step argv contains an empty, NUL or oversized argument")
        total += len(encoded)
        if total > MAX_TOTAL_ARGV_BYTES:
            raise QualificationError("step argv exceeds the total byte bound")
        result.append(item)
    return result


def private_directory(path: Path, label: str, *, new: bool = False) -> Path:
    if new:
        if not path.is_absolute() or not path.parent.is_dir() or path.parent.is_symlink():
            raise QualificationError(f"{label} must be an absolute new directory")
        if path.exists() or path.is_symlink():
            raise QualificationError(f"{label} already exists")
        path.mkdir(mode=0o700)
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise QualificationError(f"{label} must be an absolute real directory")
    metadata = path.lstat()
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise QualificationError(f"{label} must be private and service-owned")
    return path


def measure(path: Path, label: str, *, executable: bool) -> dict[str, Any]:
    if not path.is_absolute():
        raise QualificationError(f"{label} path must be absolute")
    before = path.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > MAX_EXECUTABLE_BYTES
        or before.st_mode & 0o022
        or (executable and (before.st_mode & 0o111 == 0 or not os.access(path, os.X_OK)))
    ):
        raise QualificationError(f"{label} is not a stable bounded file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256()
    count = 0
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            count += len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        count != before.st_size
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    ):
        raise QualificationError(f"{label} changed while measured")
    return {
        "path": str(path),
        "sha256": digest.hexdigest(),
        "bytes": count,
        "uid": before.st_uid,
        "gid": before.st_gid,
        "mode": f"{stat.S_IMODE(before.st_mode):04o}",
        "device": before.st_dev,
        "inode": before.st_ino,
    }


def check_digest(measurement: dict[str, Any], expected: str | None, label: str) -> None:
    if expected is None:
        return
    if re.fullmatch(r"[0-9a-f]{64}", expected) is None or expected != measurement["sha256"]:
        raise QualificationError(f"{label} does not match the expected SHA-256")


def atomic_write(path: Path, raw: bytes) -> None:
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}"
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
class Step:
    operation_id: str
    argv: list[str]
    timeout: float
    expected_exit_codes: tuple[int, ...]


def load_plan(path: Path) -> tuple[dict[str, Any], list[Step], bytes]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_PLAN_BYTES:
        raise QualificationError("qualification plan is not a bounded real file")
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        raise QualificationError("qualification plan changed while read")
    value = strict_json(raw, "qualification plan", MAX_PLAN_BYTES)
    if not isinstance(value, dict) or value.get("schema") != PLAN_SCHEMA:
        raise QualificationError(f"qualification plan schema must be {PLAN_SCHEMA}")
    raw_steps = value.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps or len(raw_steps) > MAX_STEPS:
        raise QualificationError("qualification plan steps are empty or oversized")
    steps: list[Step] = []
    seen: set[str] = set()
    for raw_step in raw_steps:
        if not isinstance(raw_step, dict):
            raise QualificationError("qualification step must be an object")
        operation_id = validate_id(raw_step.get("operation_id"), "operation_id")
        if operation_id in seen:
            raise QualificationError("qualification operation_id is duplicated")
        seen.add(operation_id)
        argv = validate_argv(raw_step.get("argv"))
        timeout_value = raw_step.get("timeout_seconds", 30.0)
        if isinstance(timeout_value, bool) or not isinstance(timeout_value, (int, float)):
            raise QualificationError("step timeout must be numeric")
        timeout = float(timeout_value)
        if not 0.1 <= timeout <= 600:
            raise QualificationError("step timeout is outside the finite bound")
        exits = raw_step.get("expected_exit_codes", [0])
        if not isinstance(exits, list) or not exits or any(isinstance(item, bool) or not isinstance(item, int) or not -255 <= item <= 255 for item in exits):
            raise QualificationError("expected_exit_codes is malformed")
        steps.append(Step(operation_id, argv, timeout, tuple(exits)))
    return value, steps, raw


def wait_descriptor(path: Path, process: subprocess.Popen[bytes], timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            value = strict_json(path.read_bytes(), "relay descriptor", MAX_PLAN_BYTES)
            if not isinstance(value, dict) or value.get("schema") != "org.trillionnium.owner-open.adb-smart-socket-relay.v1":
                raise QualificationError("relay descriptor schema is incompatible")
            return value
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=1)
            raise QualificationError(f"relay exited before ready: rc={process.returncode} stderr={stderr[-2048:]!r}")
        time.sleep(0.02)
    raise QualificationError("relay did not become ready within the finite timeout")


def stop_group(process: subprocess.Popen[bytes]) -> tuple[bytes, bytes]:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        return process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return process.communicate(timeout=2)


def run_step(adb: Path, step: Step, environment: dict[str, str], cwd: Path) -> dict[str, Any]:
    argv = [str(adb), *step.argv]
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
        stdout, stderr = process.communicate(timeout=step.timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        stdout, stderr = stop_group(process)
    if len(stdout) + len(stderr) > MAX_OUTPUT_BYTES:
        raise QualificationError(f"ADB step {step.operation_id} output exceeds the byte bound")
    result = {
        "operation_id": step.operation_id,
        "argv": step.argv,
        "argv_sha256": sha256_bytes(canonical(step.argv)),
        "spawn_count": 1,
        "timed_out": timed_out,
        "returncode": process.returncode,
        "elapsed_ms": max(0, int((time.monotonic() - started) * 1000)),
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_sha256": sha256_bytes(stderr),
        "stdout_base64": base64.b64encode(stdout).decode("ascii"),
        "stderr_base64": base64.b64encode(stderr).decode("ascii"),
        "automatic_redispatch": False,
    }
    if timed_out or process.returncode not in step.expected_exit_codes:
        raise QualificationError(
            f"ADB step {step.operation_id} failed: timeout={timed_out} rc={process.returncode}"
        )
    return result


def execute(args: argparse.Namespace) -> dict[str, Any]:
    workspace = private_directory(args.workspace, "workspace")
    evidence = private_directory(args.evidence_dir, "evidence directory", new=True)
    state = private_directory(args.state_dir, "state directory")
    plan, steps, plan_raw = load_plan(args.plan)
    measurements = {
        "adb": measure(args.adb, "adb", executable=True),
        "python": measure(args.python, "python", executable=True),
        "relay": measure(args.relay, "relay", executable=False),
    }
    check_digest(measurements["adb"], args.expected_adb_sha256, "adb")
    check_digest(measurements["python"], args.expected_python_sha256, "python")
    check_digest(measurements["relay"], args.expected_relay_sha256, "relay")
    descriptor = state / f"relay-{os.getpid()}.json"
    event_log = state / f"relay-{os.getpid()}.events.jsonl"
    for path in (descriptor, event_log):
        if path.exists() or path.is_symlink():
            raise QualificationError("relay state output already exists")
    relay_argv = [
        str(args.python),
        str(args.relay),
        "--listen-port",
        "0",
        "--upstream-host",
        args.upstream_host,
        "--upstream-port",
        str(args.upstream_port),
        "--descriptor",
        str(descriptor),
        "--events",
        str(event_log),
        "--max-clients",
        str(args.max_clients),
        "--buffer-bytes",
        str(args.buffer_bytes),
        "--idle-timeout",
        str(args.idle_timeout),
    ]
    relay = subprocess.Popen(
        relay_argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "status": "failed",
        "plan_sha256": sha256_bytes(plan_raw),
        "plan_id": plan.get("plan_id"),
        "measurements": measurements,
        "steps": [],
        "automatic_redispatch": False,
        "public_release": False,
    }
    try:
        relay_descriptor = wait_descriptor(descriptor, relay, args.relay_start_timeout)
        environment = os.environ.copy()
        environment["ADB_SERVER_SOCKET"] = relay_descriptor["adb_server_socket"]
        environment.pop("ANDROID_SERIAL", None)
        for step in steps:
            report["steps"].append(run_step(args.adb, step, environment, workspace))
        report.update(
            status="passed",
            relay_descriptor=relay_descriptor,
            exact_argv_preserved=True,
            serial_injected=False,
            host_or_port_argv_injected=False,
            steps_executed_once=len(steps),
            claim_ceiling="ADB_RELAY_HOST_PROCESS_QUALIFIED_PHYSICAL_EFFECT_NOT_PROVEN",
        )
        return report
    except Exception as error:
        report["error_type"] = type(error).__name__
        report["error"] = str(error)
        report["claim_ceiling"] = "QUALIFICATION_FAILED_NO_PROMOTION"
        raise
    finally:
        relay_stdout, relay_stderr = stop_group(relay)
        report["relay_terminal"] = {
            "returncode": relay.returncode,
            "stdout_bytes": len(relay_stdout),
            "stderr_bytes": len(relay_stderr),
            "stdout_sha256": sha256_bytes(relay_stdout),
            "stderr_sha256": sha256_bytes(relay_stderr),
            "stderr_base64": base64.b64encode(relay_stderr).decode("ascii"),
        }
        if descriptor.exists():
            atomic_write(evidence / "relay-descriptor.json", descriptor.read_bytes())
        if event_log.exists():
            atomic_write(evidence / "relay-events.jsonl", event_log.read_bytes())
        write_json(evidence / "qualification-report.json", report)
        descriptor.unlink(missing_ok=True)
        event_log.unlink(missing_ok=True)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--adb", required=True, type=Path)
    parser.add_argument("--python", required=True, type=Path)
    parser.add_argument("--relay", required=True, type=Path)
    parser.add_argument("--upstream-host", default="127.0.0.1")
    parser.add_argument("--upstream-port", required=True, type=int)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--expected-adb-sha256")
    parser.add_argument("--expected-python-sha256")
    parser.add_argument("--expected-relay-sha256")
    parser.add_argument("--max-clients", type=int, default=16)
    parser.add_argument("--buffer-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--idle-timeout", type=float, default=300)
    parser.add_argument("--relay-start-timeout", type=float, default=10)
    result = parser.parse_args(argv)
    if not result.execute:
        parser.error("--execute is required to run adb qualification steps")
    if not 1 <= result.upstream_port <= 65535:
        parser.error("upstream port is invalid")
    if not 1 <= result.max_clients <= 1024 or not 4096 <= result.buffer_bytes <= 64 * 1024 * 1024:
        parser.error("relay client or buffer bounds are invalid")
    if not 1 <= result.idle_timeout <= 86400 or not 0.1 <= result.relay_start_timeout <= 120:
        parser.error("relay timeout bounds are invalid")
    return result


def main(argv: list[str]) -> int:
    try:
        report = execute(parse_args(argv))
    except (OSError, QualificationError, subprocess.SubprocessError) as error:
        print(f"HOLD: {error}", file=sys.stderr)
        return 1
    print(
        "PASS_ADB_RELAY_HOST_PROCESS_QUALIFICATION "
        f"steps={len(report['steps'])} physical_effect=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
