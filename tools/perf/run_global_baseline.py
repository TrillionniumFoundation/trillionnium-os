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
import stat
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
MAX_REPETITIONS = 1000
MAX_RAW_SAMPLES_PER_WORKLOAD = MAX_REPETITIONS
MAX_OBJECTIVE_SUMMARIES = len(WORKLOADS)
MAX_U64 = (1 << 64) - 1
# A 1000-repetition artifact is currently well below this ceiling.  The bound
# keeps a user-supplied comparison artifact from becoming an unbounded read at
# the same trust boundary that consumes its objective score.
MAX_PREVIOUS_ARTIFACT_BYTES = 64 * 1024 * 1024
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
INTEGER_MEASUREMENTS = {
    "rss",
    "fd_count",
    "thread_count",
    "process_count",
    "io_bytes",
    "fsync_count",
    "redispatch_count",
}
INTEGER_SUMMARY_MEASUREMENTS = {"rss", "io_bytes"}
ARTIFACT_FIELDS = {
    "schema",
    "generated_at_utc",
    "execution_mode",
    "qualification",
    "external_validation_required",
    "workload_profiles",
    "required_measurements",
    "repetitions",
    "environment",
    "samples",
    "summaries",
    "objective",
    "objective_delta",
    "gate",
    "artifact_digest",
}
SAMPLE_FIELDS = {"schema", "workload_id", "repetition", *REQUIRED_MEASUREMENTS}
SUMMARY_FIELDS = {
    "workload_id",
    "sample_count",
    "dropped_samples",
    *REQUIRED_MEASUREMENTS,
}
OBJECTIVE_FIELDS = {
    "useful_work",
    "latency_penalty",
    "unknown_penalty",
    "resource_penalty",
    "fairness_penalty",
    "recovery_penalty",
    "score",
}
ENVIRONMENT_FIELDS = {
    "source_commit",
    "source_tree",
    "working_tree_dirty",
    "merge_head",
    "toolchain",
    "hardware",
    "kernel",
    "filesystem",
    "filesystem_block_bytes",
    "durability_policy",
    "module_versions",
    "control_configuration",
}
GATE_FIELDS = {"status", "passed", "reason", "hard_constraint_violations"}


def _reject_json_constant(value: str) -> Any:
    """Reject the non-standard NaN/Infinity tokens accepted by ``json``.

    Python's decoder and encoder are permissive by default and will otherwise
    let these values cross the artifact boundary even though the Rust report
    schema (and ordinary JSON consumers) only admit finite numbers.
    """

    raise ValueError(f"non-finite JSON number {value!r} is not permitted")


def _bounded_json_integer(value: str) -> int:
    parsed = int(value)
    if not -MAX_U64 <= parsed <= MAX_U64:
        raise ValueError("JSON integer exceeds the supported 64-bit bound")
    return parsed


def _finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("JSON floating-point value is not finite")
    return parsed


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _strict_json_loads(payload: str) -> Any:
    return json.loads(
        payload,
        parse_constant=_reject_json_constant,
        parse_float=_finite_json_float,
        parse_int=_bounded_json_integer,
        object_pairs_hook=_unique_json_object,
    )


def _read_bounded_regular_file(path: Path, maximum_bytes: int) -> bytes:
    """Read one stable, single-link regular file without following links."""

    try:
        path_metadata = path.lstat()
    except OSError:
        raise
    if not stat.S_ISREG(path_metadata.st_mode) or path_metadata.st_nlink != 1:
        raise ValueError("input must be a single-link regular file")
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    # A non-blocking open makes a FIFO/other special file fail closed even on
    # platforms where O_NOFOLLOW is unavailable; regular files are unaffected.
    flags |= getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        opened_metadata = os.fstat(descriptor)
        if not stat.S_ISREG(opened_metadata.st_mode) or opened_metadata.st_nlink != 1:
            raise ValueError("input changed into a non-regular file")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _run_text(*command: str, fallback: str = "unavailable") -> str:
    try:
        return subprocess.check_output(
            command, cwd=ROOT, stderr=subprocess.STDOUT, text=True, timeout=10
        ).strip()
    except (
        OSError,
        UnicodeError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ):
        return fallback


def _read_proc_io() -> int:
    try:
        values: dict[str, int] = {}
        for line in Path("/proc/self/io").read_text(encoding="utf-8").splitlines():
            name, value = line.split(":", 1)
            parsed = int(value.strip())
            if parsed < 0:
                raise ValueError(f"negative /proc I/O counter {name}")
            values[name.strip()] = parsed
        if "read_bytes" not in values or "write_bytes" not in values:
            raise ValueError("/proc/self/io is missing read_bytes/write_bytes")
        return values["read_bytes"] + values["write_bytes"]
    except (OSError, ValueError) as error:
        raise RuntimeError(f"unable to obtain a trustworthy /proc I/O sample: {error}") from error


def _resource_snapshot() -> dict[str, int | float]:
    try:
        usage = resource.getrusage(resource.RUSAGE_SELF)
    except OSError as error:
        raise RuntimeError(f"unable to obtain process resource usage: {error}") from error
    try:
        fd_count = len(list(Path("/proc/self/fd").iterdir()))
    except OSError as error:
        raise RuntimeError(f"unable to enumerate process file descriptors: {error}") from error
    try:
        thread_count = len(list(Path("/proc/self/task").iterdir()))
    except OSError as error:
        raise RuntimeError(f"unable to enumerate process threads: {error}") from error
    cpu = float(usage.ru_utime + usage.ru_stime)
    rss = int(usage.ru_maxrss) * 1024
    if not math.isfinite(cpu) or cpu < 0.0 or rss < 0 or fd_count <= 0 or thread_count <= 0:
        raise RuntimeError("process resource counters are invalid")
    return {
        "cpu": cpu,
        # Linux reports ru_maxrss in KiB.  Keep the artifact unit explicit.
        "rss": rss,
        "fd_count": fd_count,
        "thread_count": thread_count,
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
            with path.open("rb") as replay:
                operations = sum(1 for _ in replay)
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
    if not isinstance(workload_id, str) or workload_id not in WORKLOADS:
        raise ValueError(f"unknown workload profile {workload_id!r}")
    if isinstance(repetition, bool) or not isinstance(repetition, int):
        raise ValueError("repetition must be an integer")
    if not 0 <= repetition < MAX_REPETITIONS:
        raise ValueError(f"repetition must be between 0 and {MAX_REPETITIONS - 1}")
    before = _resource_snapshot()
    started = time.perf_counter_ns()
    operations, fsyncs = _bounded_probe(workload_id, repetition)
    elapsed_ns = time.perf_counter_ns() - started
    if elapsed_ns < 0:
        raise RuntimeError("monotonic timer regressed during sample")
    elapsed_ms = max(0.001, elapsed_ns / 1_000_000.0)
    after = _resource_snapshot()
    cpu_delta = float(after["cpu"]) - float(before["cpu"])
    io_delta = int(after["io_bytes"]) - int(before["io_bytes"])
    if not math.isfinite(cpu_delta) or cpu_delta < 0.0:
        raise RuntimeError("process CPU counter regressed during sample")
    if io_delta < 0:
        raise RuntimeError("process I/O counter regressed during sample")
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
    if not values or not math.isfinite(quantile) or not 0.0 <= quantile <= 1.0:
        raise ValueError("percentile requires nonempty values and q in [0,1]")
    if len(values) > MAX_RAW_SAMPLES_PER_WORKLOAD:
        raise ValueError("percentile input exceeds hard bound")
    if any(not math.isfinite(value) or value < 0.0 for value in values):
        raise ValueError("percentile values must be finite and nonnegative")
    ordered = sorted(values)
    rank = max(1, int((len(ordered) * quantile) + 0.999999999))
    return ordered[min(len(ordered), rank) - 1]


def _summary(workload_id: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(rows, (list, tuple)) or not rows:
        raise ValueError(f"workload {workload_id} has no raw samples")
    if not isinstance(workload_id, str) or workload_id not in WORKLOADS:
        raise ValueError(f"unknown workload profile {workload_id!r}")
    if len(rows) > MAX_RAW_SAMPLES_PER_WORKLOAD:
        raise ValueError(f"workload {workload_id} has too many raw samples")
    repetitions: set[int] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError(f"workload {workload_id} contains a non-object raw sample")
        if row.get("schema") != SAMPLE_SCHEMA or row.get("workload_id") != workload_id:
            raise ValueError(f"workload {workload_id} contains an invalid raw sample")
        repetition = row.get("repetition")
        if isinstance(repetition, bool) or not isinstance(repetition, int):
            raise ValueError(f"workload {workload_id} repetition is not an integer")
        if not 0 <= repetition < len(rows):
            raise ValueError(f"workload {workload_id} repetition is outside the exact sample set")
        if repetition in repetitions:
            raise ValueError(f"workload {workload_id} contains duplicate repetitions")
        repetitions.add(repetition)
        for name in REQUIRED_MEASUREMENTS:
            value = row.get(name)
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ValueError(f"workload {workload_id} measurement {name} is not numeric")
            if name in INTEGER_MEASUREMENTS and type(value) is not int:
                raise ValueError(f"workload {workload_id} measurement {name} is not an integer")
            if name in INTEGER_MEASUREMENTS and not 0 <= value <= MAX_U64:
                raise ValueError(f"workload {workload_id} measurement {name} exceeds u64 bound")
            try:
                numeric_value = float(value)
            except (OverflowError, TypeError, ValueError) as error:
                raise ValueError(
                    f"workload {workload_id} measurement {name} is not representable"
                ) from error
            if not math.isfinite(numeric_value):
                raise ValueError(f"workload {workload_id} measurement {name} is not finite")
            if numeric_value < 0.0:
                raise ValueError(f"workload {workload_id} measurement {name} is negative")
        if not (
            float(row["latency_p50"])
            <= float(row["latency_p95"])
            <= float(row["latency_p99"])
            <= float(row["latency_max"])
        ):
            raise ValueError(f"workload {workload_id} latency measurements are not monotonic")
        if not 0.0 <= float(row["unknown_rate"]) <= 1.0:
            raise ValueError(f"workload {workload_id} unknown_rate is outside [0,1]")
        if not 0.0 <= float(row["fairness"]) <= 1.0:
            raise ValueError(f"workload {workload_id} fairness is outside [0,1]")
    if repetitions != set(range(len(rows))):
        raise ValueError(f"workload {workload_id} repetitions are not an exact ordinal set")
    latency_p50 = [float(row["latency_p50"]) for row in rows]
    latency_p95 = [float(row["latency_p95"]) for row in rows]
    latency_p99 = [float(row["latency_p99"]) for row in rows]
    def mean(name: str) -> float:
        value = sum(float(row[name]) for row in rows) / len(rows)
        if not math.isfinite(value):
            raise ValueError(f"workload {workload_id} mean {name} is not finite")
        return value

    integer_max = {}
    for name in INTEGER_MEASUREMENTS:
        value = max(int(row[name]) for row in rows)
        integer_max[name] = value
    redispatch_count = sum(int(row["redispatch_count"]) for row in rows)
    if not 0 <= redispatch_count <= MAX_U64:
        raise ValueError(f"workload {workload_id} redispatch count overflow")
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
        "rss": integer_max["rss"],
        "fd_count": integer_max["fd_count"],
        "thread_count": integer_max["thread_count"],
        "process_count": integer_max["process_count"],
        "io_bytes": integer_max["io_bytes"],
        "fsync_count": integer_max["fsync_count"],
        "recovery_time": max(float(row["recovery_time"]) for row in rows),
        "unknown_rate": mean("unknown_rate"),
        "redispatch_count": redispatch_count,
        "fairness": mean("fairness"),
    }


def _objective(summaries: list[dict[str, Any]]) -> dict[str, float]:
    # This is a trust boundary for derived values.  Keep the accepted shape
    # deliberately narrow instead of allowing an arbitrary iterable (which
    # could be unbounded) or leaking AttributeError/TypeError for malformed
    # JSON objects to callers.
    if not isinstance(summaries, (list, tuple)):
        raise ValueError("objective requires a bounded nonempty summary set")
    if not summaries:
        raise ValueError(
            "objective requires exactly one summary for each workload profile"
        )
    # Keep the validation input bounded, but defer the exact-cardinality check
    # until after each supplied member has been validated.  This preserves
    # actionable fail-closed diagnostics (for example, a non-object or a
    # duplicate workload is reported as such instead of being hidden behind a
    # generic cardinality error).
    if len(summaries) > len(WORKLOADS):
        raise ValueError("objective summary set exceeds the workload profile bound")
    required_summary_fields = {
        "workload_id",
        "throughput",
        "latency_p99",
        "cpu",
        "rss",
        "io_bytes",
        "unknown_rate",
        "fairness",
        "recovery_time",
    }

    def finite_nonnegative(value: Any, name: str) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"objective summary field {name} is not numeric")
        try:
            converted = float(value)
        except (OverflowError, TypeError, ValueError) as error:
            raise ValueError(f"objective summary field {name} is not representable") from error
        if not math.isfinite(converted) or converted < 0.0:
            raise ValueError(f"objective summary field {name} is invalid")
        return converted

    workload_ids: set[str] = set()
    for index, summary in enumerate(summaries):
        if not isinstance(summary, dict):
            raise ValueError(f"objective summary {index} is not an object")
        if not required_summary_fields <= summary.keys():
            raise ValueError("objective summary is missing required fields")
        workload_id = summary["workload_id"]
        if not isinstance(workload_id, str) or workload_id not in WORKLOADS:
            raise ValueError("objective summary workload_id is unknown")
        if workload_id in workload_ids:
            raise ValueError(f"objective contains duplicate workload {workload_id}")
        workload_ids.add(workload_id)
        for name in required_summary_fields:
            if name == "workload_id":
                continue
            value = summary[name]
            if name in INTEGER_SUMMARY_MEASUREMENTS and (
                type(value) is not int or not 0 <= value <= MAX_U64
            ):
                raise ValueError(
                    f"objective summary field {name} must be an integer in [0, {MAX_U64}]"
                )
            finite_nonnegative(value, name)
        if not 0.0 <= finite_nonnegative(summary["unknown_rate"], "unknown_rate") <= 1.0:
            raise ValueError("objective unknown_rate is outside [0,1]")
        if not 0.0 <= finite_nonnegative(summary["fairness"], "fairness") <= 1.0:
            raise ValueError("objective fairness is outside [0,1]")
    if len(summaries) != len(WORKLOADS):
        raise ValueError(
            "objective requires exactly one summary for each workload profile"
        )
    if workload_ids != set(WORKLOADS):
        raise ValueError("objective workload summaries are incomplete")
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
    values = (useful, latency, unknown, resource_cost, fairness, recovery, score)
    if any(not math.isfinite(value) for value in values):
        raise ValueError("objective projection is not finite")
    return {
        "useful_work": useful,
        "latency_penalty": latency,
        "unknown_penalty": unknown,
        "resource_penalty": resource_cost,
        "fairness_penalty": fairness,
        "recovery_penalty": recovery,
        "score": score,
    }


def _require_exact_object(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        raise ValueError(
            f"{label} fields differ: missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)}"
        )
    return value


def _validate_previous_artifact(value: Any) -> float:
    """Validate the complete prior artifact before using its objective score."""

    artifact = _require_exact_object(value, ARTIFACT_FIELDS, "previous artifact")
    if artifact["schema"] != SCHEMA:
        raise ValueError("previous artifact schema is invalid")
    if not isinstance(artifact["generated_at_utc"], str):
        raise ValueError("previous artifact timestamp is invalid")
    try:
        timestamp = _dt.datetime.fromisoformat(artifact["generated_at_utc"])
    except ValueError as error:
        raise ValueError("previous artifact timestamp is invalid") from error
    if timestamp.tzinfo is None or timestamp.utcoffset() != _dt.timedelta(0):
        raise ValueError("previous artifact timestamp must be UTC")
    if artifact["execution_mode"] != "host_synthetic":
        raise ValueError("previous artifact execution mode is invalid")
    if artifact["qualification"] != "SOURCE_EVIDENCE_ONLY":
        raise ValueError("previous artifact qualification is invalid")
    if artifact["external_validation_required"] != ["WL-10", "WL-11", "WL-12"]:
        raise ValueError("previous artifact external validation set is invalid")
    if artifact["workload_profiles"] != WORKLOADS:
        raise ValueError("previous artifact workload profile list is invalid")
    if artifact["required_measurements"] != REQUIRED_MEASUREMENTS:
        raise ValueError("previous artifact measurement list is invalid")
    repetitions = artifact["repetitions"]
    if type(repetitions) is not int or not 1 <= repetitions <= MAX_REPETITIONS:
        raise ValueError("previous artifact repetitions are invalid")

    environment = _require_exact_object(
        artifact["environment"], ENVIRONMENT_FIELDS, "previous artifact environment"
    )
    digest_re = r"(?:[0-9a-f]{40}|[0-9a-f]{64})"
    for name in ("source_commit", "source_tree"):
        if not isinstance(environment[name], str) or not re.fullmatch(
            digest_re, environment[name]
        ):
            raise ValueError(f"previous artifact environment {name} is invalid")
    for name in (
        "toolchain",
        "hardware",
        "kernel",
        "filesystem",
        "durability_policy",
        "control_configuration",
    ):
        if not isinstance(environment[name], str) or not environment[name].strip():
            raise ValueError(f"previous artifact environment {name} is invalid")
    if type(environment["working_tree_dirty"]) is not bool:
        raise ValueError("previous artifact environment working_tree_dirty is invalid")
    merge_head = environment["merge_head"]
    if not isinstance(merge_head, str) or (
        merge_head != "none" and not re.fullmatch(digest_re, merge_head)
    ):
        raise ValueError("previous artifact environment merge_head is invalid")
    block_bytes = environment["filesystem_block_bytes"]
    if type(block_bytes) is not int or not 1 <= block_bytes <= MAX_U64:
        raise ValueError("previous artifact filesystem block size is invalid")
    versions = environment["module_versions"]
    if not isinstance(versions, dict) or not versions:
        raise ValueError("previous artifact module versions are invalid")
    for module, version in versions.items():
        if (
            not isinstance(module, str)
            or not module.strip()
            or not isinstance(version, str)
            or not version.strip()
        ):
            raise ValueError("previous artifact module version identity is invalid")

    samples = artifact["samples"]
    expected_sample_count = len(WORKLOADS) * repetitions
    if not isinstance(samples, list) or len(samples) != expected_sample_count:
        raise ValueError("previous artifact raw sample set is incomplete")
    grouped: dict[str, list[dict[str, Any]]] = {workload: [] for workload in WORKLOADS}
    for index, sample in enumerate(samples):
        sample_object = _require_exact_object(
            sample, SAMPLE_FIELDS, f"previous artifact sample {index}"
        )
        workload_index, repetition = divmod(index, repetitions)
        workload_id = WORKLOADS[workload_index]
        if sample_object["workload_id"] != workload_id or sample_object["repetition"] != repetition:
            raise ValueError("previous artifact raw samples are out of order")
        grouped[workload_id].append(sample_object)
    summaries = artifact["summaries"]
    if not isinstance(summaries, dict) or set(summaries) != set(WORKLOADS):
        raise ValueError("previous artifact workload summaries are incomplete")
    for workload in WORKLOADS:
        summary = _require_exact_object(
            summaries[workload], SUMMARY_FIELDS, f"previous artifact summary {workload}"
        )
        if summary != _summary(workload, grouped[workload]):
            raise ValueError(f"previous artifact summary {workload} does not match samples")

    objective = _require_exact_object(
        artifact["objective"], OBJECTIVE_FIELDS, "previous artifact objective"
    )
    expected_objective = _objective([summaries[workload] for workload in WORKLOADS])
    if objective != expected_objective:
        raise ValueError("previous artifact objective does not match summaries")
    delta = artifact["objective_delta"]
    if delta is not None:
        if isinstance(delta, bool) or not isinstance(delta, (int, float)):
            raise ValueError("previous artifact objective delta is invalid")
        if not math.isfinite(float(delta)):
            raise ValueError("previous artifact objective delta is invalid")
    gate = _require_exact_object(artifact["gate"], GATE_FIELDS, "previous artifact gate")
    if (
        gate["status"] != "INFORMATIONAL_HOST_PROBE"
        or type(gate["passed"]) is not bool
        or gate["passed"]
        or not isinstance(gate["reason"], str)
        or not gate["reason"].strip()
        or gate["hard_constraint_violations"] != []
    ):
        raise ValueError("previous artifact gate is invalid")
    digest = artifact["artifact_digest"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("previous artifact digest is invalid")
    if _canonical_digest(artifact) != digest:
        raise ValueError("previous artifact digest does not match content")
    score = objective["score"]
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise ValueError("previous objective score is not numeric")
    score = float(score)
    if not math.isfinite(score):
        raise ValueError("previous objective score is not finite")
    return score


def _environment() -> dict[str, Any]:
    try:
        stat = os.statvfs(ROOT)
    except OSError as error:
        raise RuntimeError(f"unable to inspect baseline filesystem: {error}") from error
    if stat.f_frsize <= 0:
        raise RuntimeError("filesystem reports an invalid block size")
    filesystem = _run_text("findmnt", "-no", "FSTYPE,TARGET", "-T", str(ROOT))
    toolchain = _run_text("rustc", "--version") + "; " + sys.version.split()[0]
    hardware = platform.machine() + "; cpu_count=" + str(os.cpu_count() or 1)
    kernel = platform.platform()
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
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source_commit):
        raise RuntimeError("git source commit identity is unavailable or malformed")
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source_tree):
        raise RuntimeError("git source tree identity is unavailable or malformed")
    for name, value in {
        "filesystem": filesystem,
        "toolchain": toolchain,
        "hardware": hardware,
        "kernel": kernel,
    }.items():
        if not value.strip() or value.strip() == "unavailable" or "unavailable;" in value:
            raise RuntimeError(f"environment identity field {name} is unavailable")
    return {
        "source_commit": source_commit,
        "source_tree": source_tree,
        "working_tree_dirty": bool(_run_text("git", "status", "--porcelain")),
        "merge_head": _run_text("git", "rev-parse", "MERGE_HEAD", fallback="none"),
        "toolchain": toolchain,
        "hardware": hardware,
        "kernel": kernel,
        "filesystem": filesystem,
        "filesystem_block_bytes": int(stat.f_frsize),
        "durability_policy": "host-synthetic; fsync on WL-07 and WL-12",
        "module_versions": module_versions,
        "control_configuration": "OBSERVE/SHADOW source candidate; no active authority",
    }


def _canonical_digest(artifact: dict[str, Any]) -> str:
    clone = dict(artifact)
    clone["artifact_digest"] = ""
    encoded = json.dumps(
        clone,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _load_previous(path: Path | None) -> float | None:
    if path is None:
        return None
    try:
        # Read through a bounded descriptor rather than trusting a potentially
        # huge or concurrently replaced path.  The generated 1000-repetition
        # artifact is comfortably below this ceiling.
        payload = _read_bounded_regular_file(path, MAX_PREVIOUS_ARTIFACT_BYTES)
        if len(payload) > MAX_PREVIOUS_ARTIFACT_BYTES:
            raise ValueError("previous artifact exceeds the bounded input size")
        return _validate_previous_artifact(_strict_json_loads(payload.decode("utf-8")))
    except FileNotFoundError as error:
        raise ValueError(f"previous artifact does not exist: {path}") from error
    except (
        OSError,
        UnicodeError,
        ValueError,
        KeyError,
        TypeError,
        OverflowError,
        RecursionError,
        json.JSONDecodeError,
    ) as error:
        raise ValueError(f"previous artifact is malformed: {path}") from error


def build_artifact(repetitions: int, previous: Path | None) -> dict[str, Any]:
    if isinstance(repetitions, bool) or not isinstance(repetitions, int):
        raise ValueError("repetitions must be an integer")
    if not 1 <= repetitions <= MAX_REPETITIONS:
        raise ValueError(f"repetitions must be between 1 and {MAX_REPETITIONS}")
    samples = [_sample(workload, repetition) for workload in WORKLOADS for repetition in range(repetitions)]
    if len(samples) > len(WORKLOADS) * MAX_REPETITIONS:
        raise ValueError("baseline raw sample set exceeds hard bound")
    grouped = {workload: [row for row in samples if row["workload_id"] == workload] for workload in WORKLOADS}
    summaries = {workload: _summary(workload, grouped[workload]) for workload in WORKLOADS}
    objective = _objective(list(summaries.values()))
    prior_score = _load_previous(previous)
    objective_delta = None
    if prior_score is not None:
        objective_delta = objective["score"] - prior_score
        if not math.isfinite(objective_delta):
            raise ValueError("objective delta is not finite")
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
        "objective_delta": objective_delta,
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
    if not isinstance(path, Path):
        path = Path(path)
    if not path.name or path.name in {".", ".."}:
        raise ValueError("output path must name a regular artifact file")
    path.parent.mkdir(parents=True, exist_ok=True)
    # Resolve only the parent.  Resolving the final component would follow an
    # attacker-controlled output symlink and publish into its target instead
    # of atomically replacing the requested directory entry.
    path = path.parent.resolve() / path.name
    if path.is_symlink():
        raise ValueError("output path must not be a symlink")
    payload = json.dumps(
        artifact,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    ) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_descriptor = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
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
    if not 1 <= args.repetitions <= MAX_REPETITIONS:
        parser.error(f"--repetitions must be between 1 and {MAX_REPETITIONS}")
    artifact = build_artifact(args.repetitions, args.previous)
    _write_atomic(args.output, artifact)
    print(json.dumps({"output": str(args.output), "artifact_digest": artifact["artifact_digest"], "workloads": len(artifact["workload_profiles"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
