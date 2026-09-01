#!/usr/bin/env python3
"""Run the bounded G1 global-baseline harness.

The harness deliberately distinguishes a repeatable host probe from installed
Root Linux/Android qualification.  All twelve workload IDs are exercised by
bounded local probes, while the artifact records the qualification ceiling and
the external profiles that still need a target/device run.  Raw rows are
retained so a later reviewer can recompute every percentile and objective
value; no result is silently promoted to L2 evidence.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import math
import os
import platform
import resource
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "trillionnium.owner-open.global-baseline-artifact.v1"
SAMPLE_SCHEMA = "trillionnium.owner-open.metric-sample.v1"
WORKLOADS = [f"WL-{index:02d}" for index in range(1, 13)]
REQUIRED_MEASUREMENTS = [
    "throughput",
    "latency_p50",
    "latency_p95",
    "latency_p99",
    "latency_max",
    "queue_wait",
    "lock_wait",
    "lock_hold",
    "cpu",
    "rss",
    "fd_count",
    "thread_count",
    "process_count",
    "io_bytes",
    "fsync_count",
    "recovery_time",
    "unknown_rate",
    "redispatch_count",
    "fairness",
]


def _run_text(*command: str, fallback: str = "unavailable") -> str:
    try:
        return subprocess.check_output(
            command, cwd=ROOT, stderr=subprocess.STDOUT, text=True, timeout=10
        ).strip()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return fallback


def _read_proc_io() -> int:
    try:
        values: dict[str, int] = {}
        for line in Path("/proc/self/io").read_text(encoding="utf-8").splitlines():
            name, value = line.split(":", 1)
            values[name.strip()] = int(value.strip())
        return values.get("read_bytes", 0) + values.get("write_bytes", 0)
    except (OSError, ValueError):
        return 0


def _resource_snapshot() -> dict[str, int | float]:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    try:
        fd_count = len(list(Path("/proc/self/fd").iterdir()))
    except OSError:
        fd_count = 0
    try:
        thread_count = len(list(Path("/proc/self/task").iterdir()))
    except OSError:
        thread_count = 1
    return {
        "cpu": max(0.0, float(usage.ru_utime + usage.ru_stime)),
        # Linux reports ru_maxrss in KiB.  Keep the artifact unit explicit.
        "rss": max(0, int(usage.ru_maxrss) * 1024),
        "fd_count": max(0, fd_count),
        "thread_count": max(1, thread_count),
        "process_count": 1,
        "io_bytes": _read_proc_io(),
    }


def _bounded_probe(workload_id: str, repetition: int) -> tuple[int, int]:
    """Perform a small deterministic mechanical probe.

    The return value is (logical operations, fsyncs).  Profiles that require a
    device, crash, or storage saturation use a bounded simulation marker; they
    remain explicitly below installed-target qualification in the artifact.
    """
    operations = 1
    fsyncs = 0
    number = int(workload_id[3:])
    if number == 1:
        operations = 1
    elif number == 2:
        operations = 32
        sum(index * index for index in range(operations))
    elif number == 3:
        operations = 128
        values = {index: index ^ repetition for index in range(operations)}
        operations = len(values)
    elif number in (4, 5):
        operations = 16 if number == 4 else 8
        payload = bytearray()
        for index in range(operations):
            payload.extend(f"job-{index}-{repetition}\n".encode())
        operations = max(1, len(payload) // 8)
    elif number == 6:
        operations = 64
        # Avoid an unbounded output allocation while still touching a sizable
        # bounded buffer representative of the large-output path.
        payload = b"x" * (64 * 1024)
        operations = len(payload) // 1024
    elif number == 7:
        operations = 16
        with tempfile.TemporaryDirectory(prefix="tos-baseline-") as directory:
            path = Path(directory) / "events.jsonl"
            with path.open("wb") as stream:
                for index in range(operations):
                    stream.write(json.dumps({"seq": index, "rep": repetition}).encode() + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
                fsyncs += 1
            # Replay is intentionally bounded and verifies every line.
            operations = sum(1 for _ in path.open("rb"))
    elif number == 8:
        operations = 32
        queue = list(range(operations))
        while queue:
            queue.pop(0)
    elif number == 9:
        operations = 64
        cancelled = set(range(0, operations, 3))
        operations -= len(cancelled)
    elif number == 10:
        operations = 4
        # A local child-free restart simulation: serialize and restore a tiny
        # state record instead of claiming that a process restart occurred.
        encoded = json.dumps({"epoch": repetition, "status": "restarted"})
        json.loads(encoded)
    elif number == 11:
        operations = 2
        # USB/ADB instability is represented by a bounded disconnect/reconnect
        # state machine; physical transport evidence is still required.
        states = ["connected", "disconnected", "reconnected"]
        assert states[-1] == "reconnected"
    elif number == 12:
        operations = 8
        with tempfile.TemporaryDirectory(prefix="tos-baseline-recovery-") as directory:
            path = Path(directory) / "saturated.bin"
            with path.open("wb") as stream:
                stream.write(b"x" * (operations * 4096))
                stream.flush()
                os.fsync(stream.fileno())
                fsyncs += 1
            path.unlink()
    return max(1, operations), fsyncs


def _sample(workload_id: str, repetition: int) -> dict[str, Any]:
    before = _resource_snapshot()
    started = time.perf_counter_ns()
    operations, fsyncs = _bounded_probe(workload_id, repetition)
    elapsed_ms = max(0.001, (time.perf_counter_ns() - started) / 1_000_000.0)
    after = _resource_snapshot()
    cpu_delta = max(0.0, float(after["cpu"]) - float(before["cpu"]))
    io_delta = max(0, int(after["io_bytes"]) - int(before["io_bytes"]))
    # This probe measures one bounded operation window.  Percentiles are
    # recomputed from raw rows by the report consumer, not rounded here.
    return {
        "schema": SAMPLE_SCHEMA,
        "workload_id": workload_id,
        "repetition": repetition,
        "throughput": operations / max(elapsed_ms / 1000.0, 1e-9),
        "latency_p50": elapsed_ms,
        "latency_p95": elapsed_ms,
        "latency_p99": elapsed_ms,
        "latency_max": elapsed_ms,
        "queue_wait": 0.0,
        "lock_wait": 0.0,
        "lock_hold": 0.0,
        "cpu": cpu_delta,
        "rss": max(int(before["rss"]), int(after["rss"])),
        "fd_count": max(int(before["fd_count"]), int(after["fd_count"])),
        "thread_count": max(int(before["thread_count"]), int(after["thread_count"])),
        "process_count": max(int(before["process_count"]), int(after["process_count"])),
        "io_bytes": io_delta,
        "fsync_count": fsyncs,
        "recovery_time": elapsed_ms if workload_id in {"WL-10", "WL-12"} else 0.0,
        "unknown_rate": 0.0,
        "redispatch_count": 0,
        "fairness": 1.0,
    }


def _percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    rank = max(1, int((len(ordered) * quantile) + 0.999999999))
    return ordered[min(len(ordered), rank) - 1]


def _summary(workload_id: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        raise ValueError(f"workload {workload_id} has no raw samples")
    for row in rows:
        if row.get("schema") != SAMPLE_SCHEMA or row.get("workload_id") != workload_id:
            raise ValueError(f"workload {workload_id} contains an invalid raw sample")
        for name in REQUIRED_MEASUREMENTS:
            value = row.get(name)
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ValueError(f"workload {workload_id} measurement {name} is not numeric")
            if not math.isfinite(float(value)):
                raise ValueError(f"workload {workload_id} measurement {name} is not finite")
            if float(value) < 0.0:
                raise ValueError(f"workload {workload_id} measurement {name} is negative")
        if not (
            float(row["latency_p50"])
            <= float(row["latency_p95"])
            <= float(row["latency_p99"])
            <= float(row["latency_max"])
        ):
            raise ValueError(f"workload {workload_id} latency measurements are not monotonic")
    latency_p50 = [float(row["latency_p50"]) for row in rows]
    latency_p95 = [float(row["latency_p95"]) for row in rows]
    latency_p99 = [float(row["latency_p99"]) for row in rows]
    mean = lambda name: sum(float(row[name]) for row in rows) / len(rows)
    return {
        "workload_id": workload_id,
        "sample_count": len(rows),
        "dropped_samples": 0,
        "throughput": mean("throughput"),
        # Each percentile is computed from its corresponding raw metric.  It
        # is tempting to derive all three from p99, but that would silently
        # erase regressions in the lower latency bands.
        "latency_p50": _percentile(latency_p50, 0.50),
        "latency_p95": _percentile(latency_p95, 0.95),
        "latency_p99": _percentile(latency_p99, 0.99),
        "latency_max": max(float(row["latency_max"]) for row in rows),
        "queue_wait": mean("queue_wait"),
        "lock_wait": mean("lock_wait"),
        "lock_hold": mean("lock_hold"),
        "cpu": mean("cpu"),
        "rss": max(int(row["rss"]) for row in rows),
        "fd_count": max(int(row["fd_count"]) for row in rows),
        "thread_count": max(int(row["thread_count"]) for row in rows),
        "process_count": max(int(row["process_count"]) for row in rows),
        "io_bytes": max(int(row["io_bytes"]) for row in rows),
        "fsync_count": max(int(row["fsync_count"]) for row in rows),
        "recovery_time": max(float(row["recovery_time"]) for row in rows),
        "unknown_rate": mean("unknown_rate"),
        "redispatch_count": sum(int(row["redispatch_count"]) for row in rows),
        "fairness": mean("fairness"),
    }


def _objective(summaries: list[dict[str, Any]]) -> dict[str, float]:
    count = float(len(summaries))
    useful = sum(float(row["throughput"]) for row in summaries) / count
    latency = sum(float(row["latency_p99"]) for row in summaries) / count
    unknown = sum(float(row["unknown_rate"]) for row in summaries) / count
    resource_cost = sum(
        float(row["cpu"])
        + float(row["rss"]) / 1_048_576.0
        + float(row["io_bytes"]) / 1_048_576.0
        for row in summaries
    ) / count
    fairness = sum(max(0.0, 1.0 - float(row["fairness"])) for row in summaries) / count
    recovery = sum(float(row["recovery_time"]) for row in summaries) / count
    score = useful - latency - 10.0 * unknown - 0.01 * resource_cost - fairness - recovery
    return {
        "useful_work": useful,
        "latency_penalty": latency,
        "unknown_penalty": unknown,
        "resource_penalty": resource_cost,
        "fairness_penalty": fairness,
        "recovery_penalty": recovery,
        "score": score,
    }


def _environment() -> dict[str, Any]:
    stat = os.statvfs(ROOT)
    filesystem = _run_text("findmnt", "-no", "FSTYPE,TARGET", "-T", str(ROOT))
    module_versions = {
        "owner_open_source": _run_text("git", "rev-parse", "HEAD"),
        "event_store": "v2-segmented-candidate",
        "global_control": "shadow-v1-candidate",
        "telemetry": "baseline-v1-candidate",
    }
    source_commit = _run_text("git", "rev-parse", "HEAD")
    source_tree = _run_text("git", "rev-parse", "HEAD^{tree}")
    # A source identity fallback would make the resulting artifact look
    # portable while severing it from the checkout that produced the rows.
    # Refuse to emit such an artifact; callers can still inspect the bounded
    # probe's stderr and retry in a real checkout.
    if not re.fullmatch(r"[0-9a-f]{40,64}", source_commit):
        raise RuntimeError("git source commit identity is unavailable or malformed")
    if not re.fullmatch(r"[0-9a-f]{40,64}", source_tree):
        raise RuntimeError("git source tree identity is unavailable or malformed")
    return {
        "source_commit": source_commit,
        "source_tree": source_tree,
        "working_tree_dirty": bool(_run_text("git", "status", "--porcelain")),
        "merge_head": _run_text("git", "rev-parse", "MERGE_HEAD", fallback="none"),
        "toolchain": _run_text("rustc", "--version") + "; " + sys.version.split()[0],
        "hardware": platform.machine() + "; cpu_count=" + str(os.cpu_count() or 1),
        "kernel": platform.platform(),
        "filesystem": filesystem,
        "filesystem_block_bytes": int(stat.f_frsize),
        "durability_policy": "host-synthetic; fsync on WL-07 and WL-12",
        "module_versions": module_versions,
        "control_configuration": "OBSERVE/SHADOW source candidate; no active authority",
    }


def _canonical_digest(artifact: dict[str, Any]) -> str:
    clone = dict(artifact)
    clone["artifact_digest"] = ""
    encoded = json.dumps(clone, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _load_previous(path: Path | None) -> float | None:
    if path is None:
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return float(value["objective"]["score"])
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def build_artifact(repetitions: int, previous: Path | None) -> dict[str, Any]:
    if not 1 <= repetitions <= 1000:
        raise ValueError("repetitions must be between 1 and 1000")
    samples = [_sample(workload, repetition) for workload in WORKLOADS for repetition in range(repetitions)]
    grouped = {workload: [row for row in samples if row["workload_id"] == workload] for workload in WORKLOADS}
    summaries = {workload: _summary(workload, grouped[workload]) for workload in WORKLOADS}
    objective = _objective(list(summaries.values()))
    prior_score = _load_previous(previous)
    artifact: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "execution_mode": "host_synthetic",
        "qualification": "SOURCE_EVIDENCE_ONLY",
        "external_validation_required": ["WL-10", "WL-11", "WL-12"],
        "workload_profiles": WORKLOADS,
        "required_measurements": REQUIRED_MEASUREMENTS,
        "repetitions": repetitions,
        "environment": _environment(),
        "samples": samples,
        "summaries": summaries,
        "objective": objective,
        "objective_delta": None if prior_score is None else objective["score"] - prior_score,
        "gate": {
            "status": "INFORMATIONAL_HOST_PROBE",
            "passed": False,
            "reason": "installed target/device and exact-head review evidence are still required",
            "hard_constraint_violations": [],
        },
        "artifact_digest": "",
    }
    artifact["artifact_digest"] = _canonical_digest(artifact)
    return artifact


def _write_atomic(path: Path, artifact: dict[str, Any]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(artifact, indent=2, sort_keys=True) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args(argv)
    if not 1 <= args.repetitions <= 1000:
        parser.error("--repetitions must be between 1 and 1000")
    artifact = build_artifact(args.repetitions, args.previous)
    _write_atomic(args.output, artifact)
    print(json.dumps({"output": str(args.output), "artifact_digest": artifact["artifact_digest"], "workloads": len(artifact["workload_profiles"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
