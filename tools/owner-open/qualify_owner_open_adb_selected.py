#!/usr/bin/env python3
"""Selected exact-argv qualification runner for ordinary adb through the relay.

The runner applies one owner-authored plan. It sets only the selected
ADB_SERVER_SOCKET routing variable, executes each operation ID once, preserves
bounded binary observations and never retries an uncertain step.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time
from typing import Any

PLAN_SCHEMA = "org.trillionnium.owner-open.adb-qualification-plan.v1"
REPORT_SCHEMA = "org.trillionnium.owner-open.adb-qualification-report.v1"
MAX_PLAN_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_STEPS = 256
MAX_ARGV_ITEMS = 4096
MAX_ARGUMENT_BYTES = 64 * 1024
MAX_TOTAL_ARGV_BYTES = 1024 * 1024
READ_BYTES = 64 * 1024
POLL_SECONDS = 0.02
TERM_GRACE = 1.0
KILL_GRACE = 2.0


class QualificationError(RuntimeError):
    pass


class DuplicateMember(ValueError):
    pass


def pairs(pairs_value: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs_value:
        if key in result:
            raise DuplicateMember(f"duplicate key {key}")
        result[key] = value
    return result


def strict_json(raw: bytes, label: str, maximum: int) -> Any:
    if not raw or len(raw) > maximum:
        raise QualificationError(f"{label} is empty or exceeds {maximum} bytes")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateMember) as error:
        raise QualificationError(f"invalid {label}: {error}") from error


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", value) is None:
        raise QualificationError(f"{label} is empty, oversized or malformed")
    return value


def require_loopback(value: str, label: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise QualificationError(f"{label} must be a numeric IP address") from error
    if not address.is_loopback:
        raise QualificationError(f"{label} must be loopback")
    return str(address)


def private_existing_directory(path: Path, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise QualificationError(f"{label} must be an absolute real directory")
    metadata = path.lstat()
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise QualificationError(f"{label} must be private and service-owned")
    return path


def validate_new_directory(path: Path, label: str) -> None:
    if not path.is_absolute() or not path.parent.is_dir() or path.parent.is_symlink():
        raise QualificationError(f"{label} must be an absolute new directory")
    parent = path.parent.lstat()
    if parent.st_uid not in {0, os.geteuid()}:
        raise QualificationError(f"{label} parent is not owner controlled")
    if path.exists() or path.is_symlink():
        raise QualificationError(f"{label} already exists")


def measure(path: Path, label: str, *, executable: bool) -> dict[str, Any]:
    if not path.is_absolute():
        raise QualificationError(f"{label} path must be absolute")
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
    count = 0
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            count += len(chunk)
            if count > MAX_FILE_BYTES:
                raise QualificationError(f"{label} exceeds the byte bound")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    before_identity = (
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
    after_identity = (
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
    if before_identity != after_identity or count != before.st_size:
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
class Step:
    operation_id: str
    argv: tuple[str, ...]
    timeout: float
    expected_exit_codes: tuple[int, ...]
    stdout_sha256: str | None
    stderr_sha256: str | None


def validate_argv(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > MAX_ARGV_ITEMS:
        raise QualificationError("step argv is empty or has too many elements")
    total = 0
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise QualificationError("step argv elements must be strings")
        encoded = item.encode("utf-8")
        if b"\x00" in encoded or len(encoded) > MAX_ARGUMENT_BYTES:
            raise QualificationError("step argv contains NUL or an oversized argument")
        total += len(encoded)
        if total > MAX_TOTAL_ARGV_BYTES:
            raise QualificationError("step argv exceeds the total byte bound")
        result.append(item)
    return tuple(result)


def optional_digest(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise QualificationError(f"{label} must be a lowercase SHA-256")
    return value


def load_plan(path: Path) -> tuple[dict[str, Any], tuple[Step, ...], bytes]:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > MAX_PLAN_BYTES
    ):
        raise QualificationError("qualification plan is not a bounded real file")
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        raise QualificationError("qualification plan changed while read")
    value = strict_json(raw, "qualification plan", MAX_PLAN_BYTES)
    if not isinstance(value, dict) or value.get("schema") != PLAN_SCHEMA:
        raise QualificationError(f"qualification plan schema must be {PLAN_SCHEMA}")
    require_id(value.get("plan_id"), "plan_id")
    raw_steps = value.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps or len(raw_steps) > MAX_STEPS:
        raise QualificationError("qualification plan steps are empty or oversized")
    result: list[Step] = []
    seen: set[str] = set()
    for raw_step in raw_steps:
        if not isinstance(raw_step, dict):
            raise QualificationError("qualification step must be an object")
        operation_id = require_id(raw_step.get("operation_id"), "operation_id")
        if operation_id in seen:
            raise QualificationError("qualification operation_id is duplicated")
        seen.add(operation_id)
        timeout_value = raw_step.get("timeout_seconds", 30.0)
        if isinstance(timeout_value, bool) or not isinstance(timeout_value, (int, float)):
            raise QualificationError("step timeout must be numeric")
        timeout = float(timeout_value)
        if not 0.1 <= timeout <= 600:
            raise QualificationError("step timeout is outside the finite bound")
        exits = raw_step.get("expected_exit_codes", [0])
        if (
            not isinstance(exits, list)
            or not exits
            or any(isinstance(item, bool) or not isinstance(item, int) or not -255 <= item <= 255 for item in exits)
        ):
            raise QualificationError("expected_exit_codes is malformed")
        result.append(
            Step(
                operation_id,
                validate_argv(raw_step.get("argv")),
                timeout,
                tuple(exits),
                optional_digest(raw_step.get("expected_stdout_sha256"), "expected_stdout_sha256"),
                optional_digest(raw_step.get("expected_stderr_sha256"), "expected_stderr_sha256"),
            )
        )
    return value, tuple(result), raw


def terminate_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + TERM_GRACE
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(POLL_SECONDS)
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=KILL_GRACE)
    except subprocess.TimeoutExpired as error:
        raise QualificationError("ADB process group could not be reaped") from error


def run_step(adb: Path, step: Step, environment: dict[str, str], cwd: Path) -> tuple[dict[str, Any], bool]:
    argv = [str(adb), *step.argv]
    started = time.monotonic()
    stdout = bytearray()
    stderr = bytearray()
    timed_out = False
    resource_exhausted = False
    spawn_error: str | None = None
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=environment,
            start_new_session=True,
            bufsize=0,
        )
    except OSError as error:
        process = None
        spawn_error = str(error)
    if process is not None:
        assert process.stdout and process.stderr
        for handle in (process.stdout, process.stderr):
            os.set_blocking(handle.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        deadline = started + step.timeout
        try:
            while selector.get_map() or process.poll() is None:
                if time.monotonic() >= deadline and process.poll() is None:
                    timed_out = True
                    terminate_group(process)
                for key, _mask in selector.select(POLL_SECONDS):
                    try:
                        chunk = os.read(key.fd, READ_BYTES)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    target = stdout if key.data == "stdout" else stderr
                    target.extend(chunk)
                    if len(stdout) + len(stderr) > MAX_OUTPUT_BYTES:
                        resource_exhausted = True
                        terminate_group(process)
                if process.poll() is not None and not selector.get_map():
                    break
        finally:
            selector.close()
            for handle in (process.stdout, process.stderr):
                handle.close()
        returncode = process.returncode
    else:
        returncode = None
    stdout_digest = sha256_bytes(bytes(stdout))
    stderr_digest = sha256_bytes(bytes(stderr))
    passed = (
        process is not None
        and not timed_out
        and not resource_exhausted
        and returncode in step.expected_exit_codes
        and (step.stdout_sha256 is None or step.stdout_sha256 == stdout_digest)
        and (step.stderr_sha256 is None or step.stderr_sha256 == stderr_digest)
    )
    record = {
        "operation_id": step.operation_id,
        "argv": list(step.argv),
        "argv_sha256": sha256_bytes(canonical(list(step.argv))),
        "spawn_count": 1,
        "spawn_error": spawn_error,
        "timed_out": timed_out,
        "resource_exhausted": resource_exhausted,
        "returncode": returncode,
        "expected_exit_codes": list(step.expected_exit_codes),
        "elapsed_ms": max(0, int((time.monotonic() - started) * 1000)),
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "stdout_sha256": stdout_digest,
        "stderr_sha256": stderr_digest,
        "stdout_base64": base64.b64encode(stdout).decode("ascii"),
        "stderr_base64": base64.b64encode(stderr).decode("ascii"),
        "passed": passed,
        "automatic_redispatch": False,
    }
    return record, passed


def wait_descriptor(path: Path, process: subprocess.Popen[bytes], timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            value = strict_json(path.read_bytes(), "relay descriptor", MAX_PLAN_BYTES)
            if not isinstance(value, dict) or value.get("schema") != "org.trillionnium.owner-open.adb-smart-socket-relay.v1":
                raise QualificationError("relay descriptor schema is incompatible")
            if value.get("selected_entry") != "tools/owner-open/adb_smart_socket_relay_selected.py":
                raise QualificationError("relay descriptor does not identify the selected entry")
            return value
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=1)
            raise QualificationError(
                f"relay exited before ready: rc={process.returncode} stderr={stderr[-2048:]!r}"
            )
        time.sleep(POLL_SECONDS)
    raise QualificationError("relay did not become ready within its timeout")


def stop_relay(process: subprocess.Popen[bytes]) -> tuple[bytes, bytes]:
    terminate_group(process)
    stdout, stderr = process.communicate(timeout=KILL_GRACE)
    if len(stdout) + len(stderr) > MAX_OUTPUT_BYTES:
        raise QualificationError("relay output exceeds the byte bound")
    return stdout, stderr


def execute(args: argparse.Namespace) -> dict[str, Any]:
    plan, steps, plan_raw = load_plan(args.plan)
    workspace = private_existing_directory(args.workspace, "workspace")
    state = private_existing_directory(args.state_dir, "state directory")
    validate_new_directory(args.evidence_dir, "evidence directory")
    upstream_host = require_loopback(args.upstream_host, "upstream host")
    measurements = {
        "adb": measure(args.adb, "adb", executable=True),
        "python": measure(args.python, "python", executable=True),
        "relay": measure(args.relay, "relay", executable=False),
    }
    check_digest(measurements["adb"], args.expected_adb_sha256, "adb")
    check_digest(measurements["python"], args.expected_python_sha256, "python")
    check_digest(measurements["relay"], args.expected_relay_sha256, "relay")

    evidence = args.evidence_dir
    evidence.mkdir(mode=0o700)
    descriptor = state / f"adb-relay-{os.getpid()}-{secrets.token_hex(8)}.json"
    events = state / f"adb-relay-{os.getpid()}-{secrets.token_hex(8)}.jsonl"
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "status": "failed",
        "plan_id": plan["plan_id"],
        "plan_sha256": sha256_bytes(plan_raw),
        "measurements": measurements,
        "steps": [],
        "exact_argv_preserved": True,
        "serial_injected": False,
        "host_or_port_argv_injected": False,
        "automatic_redispatch": False,
        "physical_effect_proven": False,
        "public_release": False,
    }
    relay_argv = [
        str(args.python),
        str(args.relay),
        "--listen-port",
        "0",
        "--upstream-host",
        upstream_host,
        "--upstream-port",
        str(args.upstream_port),
        "--max-clients",
        str(args.max_clients),
        "--buffer-bytes",
        str(args.buffer_bytes),
        "--event-bytes",
        str(args.event_bytes),
        "--idle-timeout",
        str(args.idle_timeout),
        "--shutdown-grace",
        str(args.shutdown_grace),
        "--descriptor",
        str(descriptor),
        "--events",
        str(events),
    ]
    relay = subprocess.Popen(
        relay_argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        relay_descriptor = wait_descriptor(descriptor, relay, args.relay_start_timeout)
        report["relay_descriptor"] = relay_descriptor
        environment = os.environ.copy()
        environment["ADB_SERVER_SOCKET"] = relay_descriptor["adb_server_socket"]
        for variable in ("ANDROID_SERIAL", "ADB_SERVER_PORT", "ANDROID_ADB_SERVER_PORT"):
            environment.pop(variable, None)
        for index, step in enumerate(steps):
            record, passed = run_step(args.adb, step, environment, workspace)
            report["steps"].append(record)
            write_json(evidence / f"step-{index:03d}-{step.operation_id}.json", record)
            if not passed:
                raise QualificationError(
                    f"ADB operation {step.operation_id} failed without redispatch"
                )
        report.update(
            status="passed",
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
        try:
            relay_stdout, relay_stderr = stop_relay(relay)
            report["relay_terminal"] = {
                "returncode": relay.returncode,
                "stdout_bytes": len(relay_stdout),
                "stderr_bytes": len(relay_stderr),
                "stdout_sha256": sha256_bytes(relay_stdout),
                "stderr_sha256": sha256_bytes(relay_stderr),
                "stderr_base64": base64.b64encode(relay_stderr).decode("ascii"),
            }
        except Exception as cleanup_error:
            report["relay_cleanup_error"] = f"{type(cleanup_error).__name__}: {cleanup_error}"
            report["status"] = "failed_cleanup"
            report["claim_ceiling"] = "QUALIFICATION_FAILED_NO_PROMOTION"
        if descriptor.exists():
            atomic_write(evidence / "relay-descriptor.json", descriptor.read_bytes())
        if events.exists():
            atomic_write(evidence / "relay-events.jsonl", events.read_bytes())
        write_json(evidence / "qualification-report.json", report)
        descriptor.unlink(missing_ok=True)
        events.unlink(missing_ok=True)


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
    parser.add_argument("--event-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--idle-timeout", type=float, default=300.0)
    parser.add_argument("--shutdown-grace", type=float, default=2.0)
    parser.add_argument("--relay-start-timeout", type=float, default=10.0)
    result = parser.parse_args(argv)
    if not result.execute:
        parser.error("--execute is required to run adb qualification steps")
    if not 1 <= result.upstream_port <= 65535:
        parser.error("upstream port is invalid")
    Limits = (result.max_clients, result.buffer_bytes, result.event_bytes)
    if not 1 <= Limits[0] <= 1024 or not 4096 <= Limits[1] <= 64 * 1024 * 1024 or not 4096 <= Limits[2] <= 256 * 1024 * 1024:
        parser.error("relay count or byte bounds are invalid")
    if not 1 <= result.idle_timeout <= 86400 or not 0.1 <= result.shutdown_grace <= 60 or not 0.1 <= result.relay_start_timeout <= 120:
        parser.error("relay timeout bounds are invalid")
    return result


def main(argv: list[str]) -> int:
    try:
        report = execute(parse_args(argv))
    except (OSError, QualificationError, subprocess.SubprocessError) as error:
        print(f"HOLD: {error}", file=sys.stderr)
        return 1
    if report.get("status") != "passed":
        print("HOLD: qualification did not finish with status=passed", file=sys.stderr)
        return 1
    print(
        "PASS_ADB_RELAY_HOST_PROCESS_QUALIFICATION "
        f"steps={len(report['steps'])} physical_effect=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
