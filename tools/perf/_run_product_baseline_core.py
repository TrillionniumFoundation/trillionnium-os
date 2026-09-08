#!/usr/bin/env python3
"""Measure selected owner-open executables on a Linux host, never a device.

This is deliberately separate from run_global_baseline.py's schema probes.
Latency includes process startup, durable store work and client delivery. Only
observed values are recorded; missing runtime instrumentation remains null.
"""
from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import selectors
import shlex
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "org.trillionnium.product-host-baseline.v1"
MAX_CAPTURE = 16 * 1024 * 1024
MAX_ARTIFACT = 32 * 1024 * 1024
MIN_GATE_REPETITIONS = 5
MAX_REGRESSION_PERCENT = 25.0
GATE_POLICY_SCHEMA = "org.trillionnium.product-host-baseline-gate-policy.v1"
GATE_POLICY_VERSION = "2026-09-09-v1"
IMPLEMENTATION_MANIFEST_SCHEMA = "org.trillionnium.product-host-baseline-implementation.v1"
GATE_METRICS = ("latency_p50_ms", "latency_p95_ms")
IMPLEMENTATION_PATHS = (
    "tools/owner-open/owner_open_rootlinux_supervisor.py",
    "tools/perf/_run_product_baseline_core.py",
    "tools/perf/run_product_baseline.py",
)
WORKLOADS = {
    "short_turn": "fresh Host/Core, fixture provider, shell callback, durable event store",
    "concurrent_turns": "concurrent independent Host/Core sessions and stores; not shared-core admission",
    "large_output": "real shell output, byte-exact client delivery through Host/Core",
    "slow_consumer": "real large output with paced 4096-byte stdout reads; not zero-credit qualification",
    "pipe_job": "real pipe job, durable job journal, terminal wait and output",
    "pty_job": "real PTY job, durable job journal, terminal wait and output",
    "restart_replay": "clean process restart with same turn bytes/store; no second effect or provider start",
    "broker_inspect": "concurrent authenticated Unix clients inspecting absent jobs through one broker/Host/Core",
}
UNAVAILABLE = {
    name: {"value": None, "status": "unavailable", "reason": "No trustworthy product instrumentation in this harness"}
    for name in ("cpu_seconds", "rss_bytes", "fd_peak", "thread_peak", "process_peak",
                 "io_bytes", "fsync_count", "queue_wait_ms", "lock_wait_ms", "lock_hold_ms",
                 "fairness", "unknown_rate")
}


class BenchmarkError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BenchmarkError(message)


def strict_json(data: bytes | str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            require(key not in value, f"duplicate JSON key: {key}")
            value[key] = item
        return value
    def bad_constant(value: str) -> Any:
        raise BenchmarkError(f"nonfinite JSON constant: {value}")
    def finite_float(value: str) -> float:
        parsed = float(value)
        require(math.isfinite(parsed), "nonfinite JSON number")
        return parsed
    return json.loads(data, object_pairs_hook=pairs, parse_constant=bad_constant, parse_float=finite_float)


def measured_file(path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    require(resolved.is_file(), f"not a regular file: {path}")
    before = resolved.stat()
    hasher = hashlib.sha256()
    with resolved.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    after = resolved.stat()
    require((before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_ino, after.st_size, after.st_mtime_ns), f"file changed: {path}")
    return {"path": str(resolved), "size": before.st_size, "sha256": hasher.hexdigest()}


def repository_file_identity(relative: str) -> dict[str, Any]:
    require(relative in IMPLEMENTATION_PATHS, f"unregistered implementation path: {relative}")
    candidate = ROOT / relative
    require(not candidate.is_symlink(), f"implementation path is a symlink: {relative}")
    resolved_root = ROOT.resolve(strict=True)
    resolved = candidate.resolve(strict=True)
    require(resolved.is_relative_to(resolved_root), f"implementation path escaped repository: {relative}")
    identity = measured_file(candidate)
    return {"path": relative, "size": identity["size"], "sha256": identity["sha256"]}


def implementation_manifest() -> dict[str, Any]:
    files = [repository_file_identity(relative) for relative in IMPLEMENTATION_PATHS]
    body = {"schema": IMPLEMENTATION_MANIFEST_SCHEMA, "files": files}
    return {**body, "manifest_sha256": digest(canonical(body))}


def gate_policy() -> dict[str, Any]:
    return {
        "schema": GATE_POLICY_SCHEMA,
        "version": GATE_POLICY_VERSION,
        "max_regression_percent": MAX_REGRESSION_PERCENT,
        "metrics": list(GATE_METRICS),
        "minimum_repetitions": MIN_GATE_REPETITIONS,
    }


def validate_implementation_manifest(value: Any) -> dict[str, Any]:
    require(isinstance(value, dict), "implementation manifest must be an object")
    require(set(value) == {"schema", "files", "manifest_sha256"},
            "implementation manifest keys differ")
    require(value["schema"] == IMPLEMENTATION_MANIFEST_SCHEMA,
            "implementation manifest schema differs")
    files = value["files"]
    require(isinstance(files, list) and len(files) == len(IMPLEMENTATION_PATHS),
            "implementation manifest file count differs")
    require([item.get("path") if isinstance(item, dict) else None for item in files] ==
            list(IMPLEMENTATION_PATHS), "implementation manifest paths differ")
    for item in files:
        require(isinstance(item, dict) and set(item) == {"path", "size", "sha256"},
                "implementation manifest entry keys differ")
        require(type(item["size"]) is int and item["size"] > 0,
                f"invalid implementation size: {item.get('path')}")
        value_sha = item["sha256"]
        require(isinstance(value_sha, str) and len(value_sha) == 64 and
                all(char in "0123456789abcdef" for char in value_sha),
                f"invalid implementation digest: {item.get('path')}")
    body = {"schema": value["schema"], "files": files}
    require(value["manifest_sha256"] == digest(canonical(body)),
            "implementation manifest digest mismatch")
    return value


def validate_gate_policy(value: Any) -> dict[str, Any]:
    require(value == gate_policy(), "performance gate policy differs from reviewed policy")
    return value


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", "--no-replace-objects", *args], cwd=ROOT,
                                   stderr=subprocess.PIPE, timeout=20)


def source_identity() -> dict[str, Any]:
    status = git("status", "--porcelain=v1", "--untracked-files=all")
    # Bind changed tracked bytes as well as untracked source, not only filenames.
    changed = digest(git("diff", "--binary", "HEAD"))
    untracked = []
    for raw in git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0"):
        if raw:
            name = os.fsdecode(raw)
            path = ROOT / name
            require(path.is_file() and not path.is_symlink(), "untracked input must be a regular file")
            untracked.append({"path": name, "sha256": measured_file(path)["sha256"]})
    return {"commit": git("rev-parse", "HEAD").decode().strip(),
            "tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
            "dirty": bool(status), "status_sha256": digest(status),
            "tracked_diff_sha256": changed, "untracked": untracked,
            "cargo_lock_sha256": measured_file(ROOT / "Cargo.lock")["sha256"]}


def finite_env() -> dict[str, str]:
    # No login, credential, Codex registration, inherited proxy or device access.
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "HOME": "/nonexistent", "PYTHONDONTWRITEBYTECODE": "1"}


def stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            # The still-owned leader has not been reaped; only its created group.
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
    for pipe in (process.stdin, process.stdout, process.stderr):
        if pipe:
            pipe.close()


def collect(command: list[str], frames: list[dict], timeout: float,
            read_delay_ms: float = 0) -> tuple[list[dict], dict]:
    payload = b"".join(canonical(frame) + b"\n" for frame in frames)
    require(len(payload) <= 16 * 1024, "benchmark input exceeded fixed bound")
    started = time.perf_counter_ns()
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=finite_env(), start_new_session=True)
    output = {"stdout": bytearray(), "stderr": bytearray()}
    observed: list[dict] = []
    pending = bytearray()
    next_read = 0.0
    try:
        assert process.stdin and process.stdout and process.stderr
        process.stdin.write(payload)
        process.stdin.close()
        with selectors.DefaultSelector() as selector:
            for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map():
                require((time.perf_counter_ns() - started) / 1e9 < timeout, "product process timed out")
                if next_read > time.monotonic():
                    time.sleep(min(0.01, next_read - time.monotonic()))
                for key, _ in selector.select(timeout=0.01):
                    name = key.data
                    if name == "stdout" and time.monotonic() < next_read:
                        continue
                    data = os.read(key.fileobj.fileno(), 4096 if read_delay_ms else 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    output[name].extend(data)
                    require(sum(map(len, output.values())) <= MAX_CAPTURE, "product output exceeded capture bound")
                    if name == "stdout":
                        next_read = time.monotonic() + read_delay_ms / 1000
                        pending.extend(data)
                        while b"\n" in pending:
                            line, _, tail = pending.partition(b"\n")
                            pending = bytearray(tail)
                            value = strict_json(line)
                            require(isinstance(value, dict) and isinstance(value.get("kind"), str), "invalid host frame")
                            observed.append({"at_ns": time.perf_counter_ns() - started,
                                             "kind": value["kind"], "frame_sha256": digest(line)})
        remaining = timeout - (time.perf_counter_ns() - started) / 1e9
        require(remaining > 0, "product process exceeded deadline")
        code = process.wait(timeout=remaining)
        require(code == 0, f"product exit {code}: {bytes(output['stderr'])[:2048]!r}")
        require(not pending, "incomplete host JSONL frame")
        decoded = [strict_json(line) for line in output["stdout"].splitlines()]
        return decoded, {"elapsed_ns": time.perf_counter_ns() - started, "exit_code": code,
                         "stdout_bytes": len(output["stdout"]), "stderr_bytes": len(output["stderr"]),
                         "stdout_sha256": digest(output["stdout"]), "stderr_sha256": digest(output["stderr"]),
                         "frames": observed}
    finally:
        stop(process)


def hello() -> dict:
    return {"kind": "hello", "seq": 0, "payload": {
        "protocol": "trillionnium.agent.turn.v1", "protocol_version": 1}}


def turn() -> dict:
    return {"kind": "turn.start", "seq": 1, "direction": "client_to_host", "payload": {
        "protocol": "trillionnium.agent.turn.v1", "protocol_version": 1,
        "session_id": "session-product-benchmark", "task_id": "task-product-benchmark",
        "turn_id": "turn-product-benchmark", "user_input": "local reproducible source benchmark"}}


def write_provider(root: Path, command: str) -> Path:
    provider = root / "provider.sh"
    call = {"protocol": "trillionnium.owner-open.provider-jsonl.v1", "kind": "tool.call",
            "seq": 0, "call": {"call_id": "call-product-benchmark", "tool": "shell.exec",
                                  "command": command, "timeout_ms": 5000}}
    terminal = {"protocol": "trillionnium.owner-open.provider-jsonl.v1", "kind": "turn.complete",
                "seq": 1, "summary": "benchmark fixture complete"}
    provider.write_text("#!/bin/sh\nset -eu\nprintf x >> " + shlex.quote(str(root / "provider-starts")) +
                        "\nIFS= read -r request\nprintf '%s\\n' " + shlex.quote(canonical(call).decode()) +
                        "\nIFS= read -r result\ncase \"$result\" in *'\"kind\":\"tool.result\"'*) ;; *) exit 12 ;; esac\n" +
                        "printf '%s\\n' " + shlex.quote(canonical(terminal).decode()) + "\n")
    provider.chmod(0o700)
    return provider


def host_command(host: Path, core: Path, root: Path, provider: Path) -> list[str]:
    return [str(host), "--transport-core", str(core), "--provider", str(provider),
            "--event-store", str(root / "events.jsonl"), "--job-store", str(root / "jobs.jsonl")]


def validate_turn(frames: list[dict], expected: bytes) -> dict:
    require(bool(frames) and frames[0]["kind"] == "hello.ack", "missing product handshake")
    require(frames[0]["payload"].get("durable_event_store") is True, "event store not durable")
    terminals = [f["payload"] for f in frames if f["kind"] == "turn.end"]
    results = [f["payload"] for f in frames if f["kind"] == "tool.result"]
    require(len(terminals) == 1 and terminals[0].get("status") == "completed", "turn did not complete")
    require(terminals[0].get("event_log_status") == "durable", "turn lost durability")
    require(len(results) == 1 and results[0].get("terminal_kind") == "exited" and
            results[0].get("exit_code") == 0 and not results[0].get("output_truncated"), "tool failed or truncated")
    chunks = [base64.b64decode(f["payload"]["data"], validate=True)
              for f in frames if f["kind"] == "tool.stdout"]
    require(b"".join(chunks) == expected, "tool output differs from expected exact bytes")
    return {"terminal": "completed", "event_log_status": "durable", "tool_output_bytes": len(expected),
            "tool_output_sha256": digest(expected)}


def run_turn_sample(host: Path, core: Path, root: Path, size: int, timeout: float,
                    slow_ms: float = 0, replay: bool = False) -> dict:
    root.mkdir(mode=0o700)
    expected = b"x" * size
    command = (shlex.quote(str(Path(sys.executable).resolve())) + " -I -c " +
               shlex.quote(f"import sys;sys.stdout.write('x'*{size})") +
               "; printf x >> " + shlex.quote(str(root / "effects")))
    provider = write_provider(root, command)
    args = host_command(host, core, root, provider)
    first, observation = collect(args, [hello(), turn()], timeout, slow_ms)
    validation = validate_turn(first, expected)
    require((root / "effects").read_bytes() == b"x", "effect count differs from one")
    if replay:
        second, replay_observation = collect(args, [hello(), turn()], timeout)
        validate_turn(second, expected)
        require((root / "effects").read_bytes() == b"x", "restart replay repeated tool effect")
        require((root / "provider-starts").read_bytes() == b"x", "restart replay respawned provider")
        ids = lambda frames: [f.get("event_id") for f in frames if f.get("turn_stream_id")]
        require(ids(first) == ids(second), "replayed event identities changed")
        observation = {**replay_observation, "setup_observation": observation,
                       "measured_phase": "second_host_start_to_replayed_completion"}
        validation["repeat_effects"] = 0
    return {**observation, "validation": validation,
            "store_bytes_after": sum(p.stat().st_size for p in root.rglob("*") if p.is_file() and
                any(part.startswith(("events.jsonl", "jobs.jsonl")) for part in p.relative_to(root).parts))}


def run_job_sample(host: Path, core: Path, root: Path, mode: str, timeout: float) -> dict:
    root.mkdir(mode=0o700)
    expected = f"product-{mode}-job".encode()
    provider = write_provider(root, "exit 99")  # Must remain unused for local jobs.
    scope = {"session_id": "session-product-benchmark", "profile_id": "owner-open",
             "task_id": "task-product-benchmark", "turn_id": "turn-product-benchmark",
             "turn_stream_id": "stream-product-benchmark", "job_id": "job-product-benchmark"}
    start = {"kind": "job.start", "seq": 1, "direction": "client_to_host", "payload": {
        **scope, "operation_id": "start-product-benchmark", "tool": "shell.job",
        "target_id": "rootlinux", "mode": mode, "command": "printf " + shlex.quote(expected.decode())}}
    wait = {"kind": "job.wait", "seq": 2, "direction": "client_to_host", "payload": {
        **scope, "operation_id": "wait-product-benchmark", "inclusive_cursor": 0,
        "durable_inclusive_cursor": 0, "limit": 32, "timeout_ms": 5000, "poll_interval_ms": 5}}
    frames, observation = collect(host_command(host, core, root, provider), [hello(), start, wait], timeout)
    require(frames[0]["payload"].get("job_journal_status") == "durable", "job journal unavailable")
    result = [f["payload"] for f in frames if f["kind"] == "job.result"]
    require(len(result) == 1 and result[0].get("terminal_kind") == "exited" and
            result[0].get("exit_code") == 0, "job did not terminate successfully")
    data = b"".join(base64.b64decode(f["payload"]["data"], validate=True)
                    for f in frames if f["kind"] == "job.output")
    require(data == expected, "job output differs from expected bytes")
    require(not (root / "provider-starts").exists(), "local job unexpectedly started provider")
    return {**observation, "validation": {"terminal": "exited", "job_mode": mode,
            "tool_output_sha256": digest(data), "tool_output_bytes": len(data), "job_journal_status": "durable"}}


def socket_line(sock: socket.socket, pending: bytearray, deadline: float) -> dict:
    while b"\n" not in pending:
        remaining = deadline - time.monotonic()
        require(remaining > 0, "broker client deadline exceeded")
        sock.settimeout(remaining)
        data = sock.recv(65536)
        require(bool(data), "broker connection closed before terminal")
        pending.extend(data)
        require(len(pending) <= MAX_CAPTURE, "broker frame exceeded bound")
    line, _, tail = pending.partition(b"\n")
    pending[:] = tail
    return strict_json(line)


def run_broker_sample(host: Path, core: Path, root: Path, clients: int, timeout: float) -> dict:
    root.mkdir(mode=0o700)
    provider = write_provider(root, "exit 99")
    # Broker admission requires a private, single-link executable. These exact
    # copies have the same measured bytes as the caller-selected product ELFs.
    upstream = root / "host"
    shutil.copyfile(host, upstream)
    upstream.chmod(0o700)
    command = [sys.executable, str(ROOT / "tools/owner-open/owner_open_connection_broker.py"),
               "--socket", str(root / "socket"), "--descriptor", str(root / "descriptor.json"),
               "--token-file", str(root / "token"), "--broker-id", "product-benchmark",
               "--upstream", str(upstream), "--max-clients", str(clients),
               "--max-inflight-requests", str(clients)]
    # The broker imports sibling source modules under a finite clean environment.
    for arg in host_command(upstream, core, root, provider)[1:]:
        command.append("--upstream-arg=" + arg)
    with tempfile.TemporaryFile() as diagnostic:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=diagnostic, stderr=diagnostic,
                                   env=finite_env(), start_new_session=True)
        try:
            deadline = time.monotonic() + timeout
            descriptor = root / "descriptor.json"
            while not descriptor.exists():
                require(process.poll() is None, "broker exited during startup")
                require(time.monotonic() < deadline, "broker startup timed out")
                time.sleep(0.01)
            identity = strict_json(descriptor.read_bytes())
            token = (root / "token").read_text().strip()
            barrier = threading.Barrier(clients, timeout=timeout)
            def inspect(index: int) -> dict:
                with socket.socket(socket.AF_UNIX) as sock:
                    sock.settimeout(timeout)
                    sock.connect(str(root / "socket"))
                    pending = bytearray()
                    sock.sendall(canonical({"kind": "broker.hello", "broker_epoch": identity["broker_epoch"],
                                           "client_id": f"client-{index}", "token": token}) + b"\n")
                    ack = socket_line(sock, pending, time.monotonic() + timeout)
                    require(ack.get("kind") == "broker.hello.ack", "broker handshake failed")
                    barrier.wait()
                    started = time.perf_counter_ns()
                    scope = {"session_id": "session-perf", "profile_id": "owner-open", "task_id": "task-perf",
                             "turn_id": "turn-perf", "turn_stream_id": "stream-perf", "job_id": f"missing-{index}"}
                    request_id = f"inspect-{index}"
                    frame = {"kind": "job.inspect", "seq": index + 1, "direction": "client_to_host", "payload": scope}
                    sock.sendall(canonical({"kind": "request", "request_id": request_id, "frame": frame,
                                           "expected_kinds": ["job.inspect.result"], "expected_job_id": scope["job_id"],
                                           "timeout_ms": min(10000, int(timeout * 1000))}) + b"\n")
                    observations = []
                    while True:
                        value = socket_line(sock, pending, time.monotonic() + timeout)
                        observations.append({"kind": value.get("kind"), "sha256": digest(canonical(value))})
                        require(len(observations) <= 64, "broker observations exceeded bound")
                        if value.get("kind") in {"result", "error"} and value.get("request_id") == request_id:
                            require(value["kind"] == "result", f"broker request failed: {value}")
                            frame = value.get("frame", {})
                            require(frame.get("kind") == "job.error" and
                                    frame.get("payload", {}).get("code") == "job_request_failed" and
                                    frame.get("payload", {}).get("message") == "owner-open job is not registered" and
                                    frame.get("job_id") == scope["job_id"] and
                                    value.get("broker_response_connection_id") == f"client-{index}",
                                    "broker did not preserve exact missing-job response and client ownership")
                            return {"elapsed_ns": time.perf_counter_ns() - started, "observations": observations}
            started = time.perf_counter_ns()
            with ThreadPoolExecutor(max_workers=clients) as executor:
                rows = list(executor.map(inspect, range(clients)))
            return {"elapsed_ns": time.perf_counter_ns() - started, "clients": rows,
                    "validation": {"expected_missing_job_responses": len(rows), "shared_upstream": True},
                    "measured_phase": "connect_authenticate_and_concurrent_inspect_not_broker_startup"}
        except Exception as error:
            diagnostic.seek(0)
            raise BenchmarkError(f"{error}; broker diagnostic={diagnostic.read(2048)!r}") from error
        finally:
            stop(process)


def percentile(values: list[float], q: float) -> float:
    return sorted(values)[max(0, math.ceil(len(values) * q) - 1)]


def summarize(samples: list[dict]) -> dict:
    summaries = {}
    for name in sorted({row["workload"] for row in samples}):
        rows = [row for row in samples if row["workload"] == name and not row["warmup"]]
        if not rows:
            continue
        values = [row["elapsed_ns"] / 1e6 for row in rows]
        summaries[name] = {"samples": len(rows), "latency_p50_ms": statistics.median(values),
                           "latency_p95_ms": percentile(values, .95), "latency_p99_ms": percentile(values, .99),
                           "latency_max_ms": max(values), "latency_min_ms": min(values),
                           "latency_stdev_ms": statistics.stdev(values) if len(values) > 1 else None,
                           "throughput_per_sec": sum(row["operations"] for row in rows) /
                               (sum(row["elapsed_ns"] for row in rows) / 1e9),
                           "measurement_unit": "batch_wall_time_including_declared_client_work"}
    return summaries


def validate_artifact(value: Any) -> dict:
    require(isinstance(value, dict) and value.get("schema") == SCHEMA, "wrong baseline schema")
    body = dict(value)
    claimed = body.pop("artifact_digest", None)
    require(claimed == digest(canonical(body)), "baseline content digest mismatch")
    manifest = validate_implementation_manifest(value.get("implementation_manifest"))
    policy = validate_gate_policy(value.get("gate_policy"))
    identity = value.get("comparison_identity")
    require(isinstance(identity, dict), "missing comparison identity")
    require(identity.get("implementation_manifest_sha256") == manifest["manifest_sha256"],
            "comparison identity does not bind implementation manifest")
    require(identity.get("gate_policy_sha256") == digest(canonical(policy)),
            "comparison identity does not bind gate policy")
    require(value.get("qualification") == "L1_HOST_SOURCE_BENCHMARK_ONLY" and
            value.get("public_release") is False, "baseline widened its claim")
    samples = value.get("samples")
    require(isinstance(samples, list) and 0 < len(samples) <= 8 * 110, "invalid sample count")
    seen = set()
    for row in samples:
        require(isinstance(row, dict) and row.get("workload") in WORKLOADS, "invalid workload sample")
        require(type(row.get("warmup")) is bool and type(row.get("repetition")) is int, "invalid repetition")
        key = (row["workload"], row["warmup"], row["repetition"])
        require(key not in seen, "duplicate sample identity")
        seen.add(key)
        require(type(row.get("elapsed_ns")) is int and 0 < row["elapsed_ns"] < 600 * 10**9, "invalid elapsed sample")
        require(type(row.get("operations")) is int and 1 <= row["operations"] <= 32, "invalid operations")
        require(row.get("correctness_validated") is True, "unvalidated baseline sample")
    configuration = value.get("configuration", {})
    workloads = configuration.get("workloads")
    repetitions, warmup = configuration.get("repetitions"), configuration.get("warmup")
    require(isinstance(workloads, list) and bool(workloads) and
            all(name in WORKLOADS for name in workloads) and len(set(workloads)) == len(workloads), "invalid configured workloads")
    require(type(repetitions) is int and 1 <= repetitions <= 100 and
            type(warmup) is int and 0 <= warmup <= 10, "invalid configured repetitions")
    require(configuration.get("max_regression_percent") == policy["max_regression_percent"] and
            configuration.get("gate_policy_version") == policy["version"],
            "configuration does not bind reviewed gate policy")
    expected = {(name, is_warmup, index) for name in workloads
                for is_warmup, count in ((True, warmup), (False, repetitions)) for index in range(count)}
    require(seen == expected, "baseline omits or adds configured samples")
    require(value.get("summaries") == summarize(samples), "summary does not match raw samples")
    require(value.get("failures") == [], "previous baseline contains correctness failures")
    return value


def regression_gate(current: dict, previous: dict | None,
                    threshold_percent: float | None = None) -> dict:
    policy = validate_gate_policy(current.get("gate_policy"))
    reviewed_threshold = policy["max_regression_percent"]
    if threshold_percent is not None:
        require(threshold_percent == reviewed_threshold,
                "caller threshold differs from reviewed gate policy")
    if current["failures"]:
        return {"status": "FAIL_CORRECTNESS", "passed": False, "regressions": []}
    if previous is None:
        return {"status": "BASELINE_RECORDED_NO_COMPARISON", "passed": False, "regressions": []}
    previous_policy = validate_gate_policy(previous.get("gate_policy"))
    require(policy == previous_policy, "baseline gate policy differs")
    require(current["comparison_identity"] == previous["comparison_identity"], "incompatible environment or workload configuration")
    require(set(current["summaries"]) == set(previous["summaries"]), "baseline workload set differs")
    if min(s["samples"] for a in (current, previous) for s in a["summaries"].values()) < policy["minimum_repetitions"]:
        return {"status": "INSUFFICIENT_REPETITIONS", "passed": False, "regressions": []}
    comparisons = []
    for name, summary in current["summaries"].items():
        old = previous["summaries"][name]
        for metric in policy["metrics"]:
            delta = (summary[metric] / old[metric] - 1) * 100
            comparisons.append({"workload": name, "metric": metric, "previous": old[metric],
                                "current": summary[metric], "regression_percent": delta,
                                "regressed": delta > reviewed_threshold})
    regressions = [row for row in comparisons if row["regressed"]]
    return {"status": "FAIL_REGRESSION" if regressions else "PASS_COMPARISON",
            "passed": not regressions, "threshold_percent": reviewed_threshold,
            "gate_policy_version": policy["version"],
            "minimum_repetitions": policy["minimum_repetitions"],
            "comparisons": comparisons, "regressions": regressions,
            "interpretation": "deterministic observed P50/P95 reviewed-policy threshold; not a statistical significance or P99 SLO claim"}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, type=Path)
    parser.add_argument("--core", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--build-profile", choices=("debug", "release", "custom"), default="custom")
    parser.add_argument("--scratch-parent", type=Path)
    parser.add_argument("--require-comparison", action="store_true")
    parser.add_argument("--require-clean-source", action="store_true")
    parser.add_argument("--workloads", nargs="+", choices=WORKLOADS, default=list(WORKLOADS))
    parser.add_argument("--repetitions", type=int, default=10)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--output-bytes", type=int, default=262144)
    parser.add_argument("--slow-read-ms", type=float, default=1)
    parser.add_argument("--timeout-seconds", type=float, default=15)
    parser.add_argument("--max-regression-percent", type=float, default=MAX_REGRESSION_PERCENT)
    args = parser.parse_args(argv)
    for name, low, high in (("repetitions", 1, 100), ("warmup", 0, 10), ("concurrency", 1, 16),
                            ("output_bytes", 65536, 1048576), ("slow_read_ms", 0.1, 10),
                            ("timeout_seconds", 1, 60), ("max_regression_percent", 0, 1000)):
        value = getattr(args, name)
        if not math.isfinite(value) or not low <= value <= high:
            parser.error(f"--{name.replace('_', '-')} must be in {low}..{high}")
    if args.max_regression_percent != MAX_REGRESSION_PERCENT:
        parser.error(f"--max-regression-percent is fixed by {GATE_POLICY_VERSION} at {MAX_REGRESSION_PERCENT:g}")
    if len(set(args.workloads)) != len(args.workloads):
        parser.error("workloads must be unique")
    return args


def run(args: argparse.Namespace) -> dict:
    require(sys.platform == "linux", "product benchmark requires Linux")
    host, core = args.host.resolve(strict=True), args.core.resolve(strict=True)
    require(os.access(host, os.X_OK) and os.access(core, os.X_OK), "product executable not executable")
    identities = {"host": measured_file(host), "core": measured_file(core),
                  "python": measured_file(Path(sys.executable)), "shell": measured_file(Path("/bin/sh")),
                  "harness": measured_file(Path(__file__))}
    implementation = implementation_manifest()
    policy = gate_policy()
    source = source_identity()
    require(not args.require_clean_source or not source["dirty"], "clean source required")
    previous = None
    if args.previous:
        require(args.previous.is_file() and not args.previous.is_symlink(), "previous baseline must be a regular nonsymlink file")
        with args.previous.open("rb") as stream:
            previous_bytes = stream.read(MAX_ARTIFACT + 1)
        require(len(previous_bytes) <= MAX_ARTIFACT, "previous baseline exceeds bound")
        previous = validate_artifact(strict_json(previous_bytes))
    config = {name: getattr(args, name) for name in ("concurrency", "output_bytes", "slow_read_ms", "timeout_seconds", "build_profile")}
    config["workloads"] = args.workloads
    config["max_regression_percent"] = policy["max_regression_percent"]
    config["gate_policy_version"] = policy["version"]
    environment = {"system": platform.system(), "kernel": platform.release(), "machine": platform.machine(),
                   "cpu_count": os.cpu_count(), "python_version": platform.python_version(),
                   "cpu_model": next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                                      if line.startswith("model name")), "unavailable"),
                   "cpu_affinity": sorted(os.sched_getaffinity(0)),
                   "machine_id_sha256": digest(Path("/etc/machine-id").read_bytes()),
                   "cpu_governors": sorted({p.read_text().strip() for p in
                       Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq/scaling_governor")})}
    artifact = {"schema": SCHEMA, "qualification": "L1_HOST_SOURCE_BENCHMARK_ONLY", "public_release": False,
                "generated_at_unix_ns": time.time_ns(), "source": source, "executables": identities,
                "implementation_manifest": implementation, "gate_policy": policy,
                "binary_source_binding": "caller_supplied_binaries_measured_not_attested_build_provenance",
                "environment": environment, "configuration": {**config, "repetitions": args.repetitions, "warmup": args.warmup},
                "comparison_identity": {"environment": environment, "configuration": config,
                                        "python_sha256": identities["python"]["sha256"], "shell_sha256": identities["shell"]["sha256"],
                                        "harness_sha256": identities["harness"]["sha256"],
                                        "implementation_manifest_sha256": implementation["manifest_sha256"],
                                        "gate_policy_sha256": digest(canonical(policy))},
                "workload_descriptions": {name: WORKLOADS[name] for name in args.workloads},
                "unavailable_measurements": UNAVAILABLE, "samples": [], "failures": [],
                "limitations": ["No installed Root Linux, Android, device, crash, power-loss or release qualification",
                                "Fresh processes and independent session stores; not a long-lived production throughput SLO",
                                "Raw timing samples and frame metadata retained; full stdout represented by byte count/digest",
                                "Replayed fixture completion is clean-restart recovery, not ambiguous-effect crash recovery",
                                "No CPU/RSS/lock/fsync/fairness instrumentation; these values remain explicitly unavailable",
                                "P99 descriptive only; P50/P95 threshold comparison is not statistical significance"]}
    with tempfile.TemporaryDirectory(prefix="tos-perf-", dir=args.scratch_parent) as temporary:
        root = Path(temporary)
        filesystem = subprocess.check_output(["stat", "-f", "-c", "%T", str(root)], env=finite_env(), timeout=5).decode().strip()
        artifact["environment"]["scratch_filesystem"] = filesystem
        for name in args.workloads:
            for index in range(args.warmup + args.repetitions):
                warmup = index < args.warmup
                sample_root = root / f"{name}-{index}"
                try:
                    operations = 1
                    if name == "concurrent_turns":
                        sample_root.mkdir(mode=0o700)
                        started = time.perf_counter_ns()
                        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
                            rows = list(executor.map(lambda i: run_turn_sample(host, core, sample_root / str(i), 16,
                                                                              args.timeout_seconds), range(args.concurrency)))
                        observation = {"elapsed_ns": time.perf_counter_ns() - started, "sessions": rows}
                        operations = args.concurrency
                    elif name == "broker_inspect":
                        observation = run_broker_sample(host, core, sample_root, args.concurrency, args.timeout_seconds)
                        operations = args.concurrency
                    elif name in {"pipe_job", "pty_job"}:
                        observation = run_job_sample(host, core, sample_root, name.split("_")[0], args.timeout_seconds)
                    else:
                        observation = run_turn_sample(host, core, sample_root,
                            args.output_bytes if name in {"large_output", "slow_consumer"} else 16,
                            args.timeout_seconds, args.slow_read_ms if name == "slow_consumer" else 0,
                            replay=name == "restart_replay")
                    artifact["samples"].append({"workload": name, "warmup": warmup,
                        "repetition": index if warmup else index - args.warmup,
                        "operations": operations, "correctness_validated": True, **observation})
                except (BenchmarkError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
                    artifact["failures"].append({"workload": name, "repetition": index,
                                                 "error": str(error)[:4096]})
                    break
                finally:
                    # Each sample has reaped its carriers before scratch reclamation.
                    # Retain measurements, not an ever-growing set of fixture stores.
                    if sample_root.exists():
                        shutil.rmtree(sample_root)
    artifact["source_after"] = source_identity()
    if artifact["source_after"] != source:
        artifact["failures"].append({"error": "source changed during benchmark"})
    for name, path in (("host", host), ("core", core)):
        if measured_file(path) != identities[name]:
            artifact["failures"].append({"error": f"{name} bytes changed during benchmark"})
    if implementation_manifest() != implementation:
        artifact["failures"].append({"error": "measurement implementation changed during benchmark"})
    artifact["summaries"] = summarize(artifact["samples"])
    try:
        artifact["gate"] = regression_gate(artifact, previous)
    except BenchmarkError as error:
        artifact["gate"] = {"status": "INCOMPATIBLE_BASELINE", "passed": False, "reason": str(error)}
    artifact["previous_artifact_digest"] = previous["artifact_digest"] if previous else None
    artifact["artifact_digest"] = digest(canonical(artifact))
    return artifact


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        require(not args.output.exists() and not args.output.is_symlink(), "output already exists")
        require(args.output.parent.is_dir(), "output parent must exist")
        result = run(args)
        encoded = canonical(result) + b"\n"
        require(len(encoded) <= MAX_ARTIFACT, "artifact exceeded bound")
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        print(json.dumps({"output": str(args.output), "samples": len(result["samples"]),
                          "gate": result["gate"]["status"], "failures": result["failures"]}))
        if result["failures"] or result["gate"]["status"] in {"FAIL_REGRESSION", "INCOMPATIBLE_BASELINE"}:
            return 2
        if args.require_comparison and not result["gate"]["passed"]:
            return 2
        return 0
    except (BenchmarkError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(f"product benchmark failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
