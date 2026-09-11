#!/usr/bin/env python3
"""Fail-closed qualification of controlled product-performance batches.

This module does not manufacture measurements. It validates immutable raw
batch artifacts produced on a controlled runner, recomputes every statistic,
requires the A1/A2/A3 same-binary stability sequence, and only then compares a
candidate. L1 source fixtures may retain explicit unavailable observations;
an L2 decision rejects every unavailable applicable stage or core resource.

WL-11 (physical ADB/USB) and WL-12 (destructive storage/recovery) are retained
as explicit L4/L5 holds. Source or installed-host data cannot promote them.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import statistics
import sys
from typing import Any, Iterable, Mapping, Sequence

_OS_LINK_SUPPORTS_DIR_FD = os.link in os.supports_dir_fd
_OS_LINK_SUPPORTS_FOLLOW_SYMLINKS = os.link in os.supports_follow_symlinks

BATCH_SCHEMA = "org.trillionnium.product-performance-batch.v1"
REPORT_SCHEMA = "org.trillionnium.performance-qualification-report.v1"
POLICY_SCHEMA = "org.trillionnium.performance-qualification-policy.v2"
POLICY_REGISTRY_SCHEMA = "org.trillionnium.performance-qualification-policy-registry.v1"
POLICY_REGISTRY_PATH = Path(__file__).with_name("performance_qualification_policy_registry.v1.json")
POLICY_REGISTRY_MAX_BYTES = 64 * 1024
WORK_CONTRACT_SCHEMA = "org.trillionnium.performance-work-contract.v1"
SOURCE_LEVEL = "L1_SOURCE"
INSTALLED_LEVEL = "L2_INSTALLED"
LEVELS = {SOURCE_LEVEL, INSTALLED_LEVEL}
SOURCE_WORKLOADS = tuple(f"WL-{index:02d}" for index in range(1, 11))
EXTERNAL_HOLDS = {
    "WL-11": {"required_level": "L4", "reason": "authorized physical ADB/USB evidence required"},
    "WL-12": {"required_level": "L5", "reason": "authorized destructive storage/recovery evidence required"},
}
PHASES = ("cold_start", "steady_state")
BASELINE_BATCH_IDS = ("A1", "A2", "A3")
CANDIDATE_BATCH_IDS = ("C1", "C2", "C3")
MIN_REPETITIONS = 50
MAX_REPETITIONS = 10_000
MAX_BATCH_BYTES = 256 * 1024 * 1024
MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_SELF_DRIFT_PERCENT = 10.0
MAX_REGRESSION_PERCENT = 25.0
MAX_UNKNOWN_RATE_INCREASE = 0.0
MAX_FAIRNESS_DROP = 0.05
MAX_SAMPLE_ELAPSED_NS = 3_600 * 1_000_000_000
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}$")

REQUIRED_STAGE_NAMES = (
    "broker_accept",
    "broker_auth",
    "broker_queue_wait",
    "broker_forward",
    "host_decode",
    "host_capacity_wait",
    "journal_append",
    "journal_fsync",
    "provider_spawn",
    "provider_first_event",
    "provider_wait",
    "callback_admission",
    "tool_spawn",
    "tool_output",
    "tool_exit",
    "tool_cleanup",
    "terminal_persistence",
    "delivery_queue_wait",
    "client_delivery",
)

# A not-applicable observation is permitted only where the workload deliberately
# excludes the component. Everything else is required at L2.
STAGE_NOT_APPLICABLE: Mapping[str, frozenset[str]] = {
    "WL-03": frozenset({
        "provider_spawn", "provider_first_event", "provider_wait",
        "callback_admission", "tool_spawn", "tool_output", "tool_exit", "tool_cleanup",
    }),
    "WL-04": frozenset({"provider_spawn", "provider_first_event", "provider_wait", "callback_admission"}),
    "WL-05": frozenset({"provider_spawn", "provider_first_event", "provider_wait", "callback_admission"}),
    "WL-07": frozenset({
        "broker_accept", "broker_auth", "broker_queue_wait", "broker_forward",
        "provider_spawn", "provider_first_event", "provider_wait", "callback_admission",
        "tool_spawn", "tool_output", "tool_exit", "tool_cleanup", "client_delivery",
    }),
}

REQUIRED_RESOURCE_UNITS: Mapping[str, str] = {
    "cpu_user_ns": "ns",
    "cpu_system_ns": "ns",
    "rss_current_bytes": "bytes",
    "rss_peak_bytes": "bytes",
    "fd_peak": "count",
    "thread_peak": "count",
    "process_peak": "count",
    "context_switches_voluntary": "count",
    "context_switches_involuntary": "count",
    "cgroup_cpu_usage_usec": "usec",
    "cgroup_memory_current_bytes": "bytes",
    "cgroup_memory_peak_bytes": "bytes",
    "cgroup_io_read_bytes": "bytes",
    "cgroup_io_write_bytes": "bytes",
    "cgroup_pids_current": "count",
    "cgroup_pids_peak": "count",
    "read_bytes": "bytes",
    "write_bytes": "bytes",
    "fsync_count": "count",
    "queue_depth_peak": "count",
    "queue_wait_ns": "ns",
    "lock_wait_ns": "ns",
    "lock_hold_ns": "ns",
    "unknown_rate": "ratio",
    "redispatch_count": "count",
    "fairness": "ratio",
}

BATCH_KEYS = {
    "schema", "policy", "batch_id", "qualification_level", "source", "environment",
    "workload_profiles", "workload_configurations", "phases", "repetitions",
    "raw_samples_preserved", "outlier_deletion", "samples",
    "work_contract_sha256", "automatic_redispatch", "public_release",
    "content_sha256",
}
POLICY_KEYS = {
    "schema", "version", "registry_schema", "registry_version", "registry_sha256",
    "minimum_repetitions", "maximum_repetitions", "required_batches",
    "max_self_drift_percent", "max_latency_regression_percent",
    "max_throughput_regression_percent", "max_unknown_rate_increase",
    "max_fairness_drop", "max_sample_elapsed_ns", "workloads", "phases",
    "statistics", "raw_samples_preserved", "outlier_deletion",
    "unknown_rate_source", "l2_unknown_outcomes_allowed",
    "same_work_contract_required", "automatic_redispatch", "public_release",
}
SOURCE_KEYS = {
    "repository", "commit", "tree", "host_sha256", "core_sha256",
    "harness_sha256", "build_log_sha256", "toolchain_sha256",
}
ENVIRONMENT_KEYS = {
    "runner_id_sha256", "kernel", "cpu_model", "cpu_count", "cpu_affinity",
    "cpu_governors", "filesystem", "mount_options", "scratch_device",
    "cgroup_mode", "numa_policy", "power_profile",
}
SAMPLE_KEYS = {
    "workload_id", "phase", "repetition", "elapsed_ns", "operations",
    "correctness_validated", "stage_durations", "resources", "unknown_outcome",
}
STAGE_OBSERVATION_KEYS = {"status", "value_ns", "reason"}
RESOURCE_OBSERVATION_KEYS = {"status", "value", "unit", "reason"}
STATISTIC_NAMES = (
    "median_ms", "p90_ms", "p95_ms", "p99_ms", "max_ms", "mad_ms",
    "stdev_ms", "mean_ci95_lower_ms", "mean_ci95_upper_ms",
)


class QualificationError(ValueError):
    """A batch or report violates the reviewed qualification contract."""


@dataclass(frozen=True)
class Batch:
    path: Path
    raw: bytes
    value: dict[str, Any]
    digest: str


@dataclass(frozen=True)
class SeriesSummary:
    workload_id: str
    phase: str
    samples: int
    operations: int
    throughput_per_sec: float
    median_ms: float
    p90_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    mad_ms: float
    stdev_ms: float
    mean_ci95_lower_ms: float
    mean_ci95_upper_ms: float
    unknown_rate_mean: float | None
    fairness_mean: float | None
    redispatch_count_total: int | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "workload_id": self.workload_id,
            "phase": self.phase,
            "samples": self.samples,
            "operations": self.operations,
            "throughput_per_sec": self.throughput_per_sec,
            "median_ms": self.median_ms,
            "p90_ms": self.p90_ms,
            "p95_ms": self.p95_ms,
            "p99_ms": self.p99_ms,
            "max_ms": self.max_ms,
            "mad_ms": self.mad_ms,
            "stdev_ms": self.stdev_ms,
            "mean_ci95_lower_ms": self.mean_ci95_lower_ms,
            "mean_ci95_upper_ms": self.mean_ci95_upper_ms,
            "unknown_rate_mean": self.unknown_rate_mean,
            "fairness_mean": self.fairness_mean,
            "redispatch_count_total": self.redispatch_count_total,
        }


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationError(message)


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{label} must be an object")
    actual = set(value)
    _require(actual == expected, f"{label} keys differ: missing={sorted(expected-actual)} extra={sorted(actual-expected)}")
    return value


def _reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise QualificationError(f"non-finite JSON number: {value}")


def _finite_float(value: str) -> float:
    parsed = float(value)
    _require(math.isfinite(parsed), f"non-finite JSON number: {value}")
    return parsed


def strict_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_pairs,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, QualificationError) as error:
        raise QualificationError(f"{label} is not strict JSON: {error}") from error
    _require(isinstance(value, dict), f"{label} root must be an object")
    return value


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise QualificationError(f"value is not canonical JSON: {error}") from error


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def content_digest(value: Mapping[str, Any], field: str = "content_sha256") -> str:
    clone = dict(value)
    clone[field] = ""
    return sha256(canonical(clone))


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid,
        metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _stable_directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid,
    )


def _read_bounded(path: Path, maximum: int) -> bytes:
    absolute = Path(os.path.abspath(os.fspath(path)))
    _require(absolute.name not in {"", ".", ".."}, f"invalid input path: {path}")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise QualificationError(f"cannot open {path}: {error}") from error
    try:
        before = os.fstat(descriptor)
        _require(
            stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            f"input is not a singly-linked regular file: {path}",
        )
        _require(0 < before.st_size <= maximum, f"input size outside 1..={maximum}: {path}")
        chunks: list[bytes] = []
        offset = 0
        while offset < before.st_size:
            block = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
            _require(bool(block), f"short read from {path}")
            chunks.append(block)
            offset += len(block)
        after = os.fstat(descriptor)
        _require(
            _stable_file_identity(before) == _stable_file_identity(after),
            f"input changed while read: {path}",
        )
    finally:
        os.close(descriptor)
    try:
        current = os.lstat(absolute)
    except OSError as error:
        raise QualificationError(f"input pathname disappeared after read: {path}") from error
    _require(
        not stat.S_ISLNK(current.st_mode)
        and _stable_file_identity(current) == _stable_file_identity(before),
        f"input pathname changed while read: {path}",
    )
    return b"".join(chunks)


def _load_policy_registry() -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    raw = _read_bounded(POLICY_REGISTRY_PATH, POLICY_REGISTRY_MAX_BYTES)
    registry = _exact_keys(
        strict_json_bytes(raw, "performance policy registry"),
        {"schema", "version", "policy"},
        "performance policy registry",
    )
    _require(registry["schema"] == POLICY_REGISTRY_SCHEMA, "policy registry schema differs")
    _require(
        isinstance(registry["version"], str)
        and IDENTIFIER_RE.fullmatch(registry["version"]) is not None,
        "policy registry version is malformed",
    )
    policy = _exact_keys(registry["policy"], POLICY_KEYS - {
        "registry_schema", "registry_version", "registry_sha256"
    }, "policy registry entry")
    _require(policy["schema"] == POLICY_SCHEMA, "policy schema differs")
    _require(
        isinstance(policy["version"], str)
        and IDENTIFIER_RE.fullmatch(policy["version"]) is not None,
        "policy version is malformed",
    )
    _require(policy["minimum_repetitions"] == MIN_REPETITIONS, "policy minimum repetitions differ")
    _require(policy["maximum_repetitions"] == MAX_REPETITIONS, "policy maximum repetitions differ")
    _require(policy["required_batches"] == 3, "policy batch count differs")
    _require(policy["max_self_drift_percent"] == MAX_SELF_DRIFT_PERCENT, "policy self-drift differs")
    _require(policy["max_latency_regression_percent"] == MAX_REGRESSION_PERCENT, "policy latency threshold differs")
    _require(policy["max_throughput_regression_percent"] == MAX_REGRESSION_PERCENT, "policy throughput threshold differs")
    _require(policy["max_unknown_rate_increase"] == MAX_UNKNOWN_RATE_INCREASE, "policy unknown threshold differs")
    _require(policy["max_fairness_drop"] == MAX_FAIRNESS_DROP, "policy fairness threshold differs")
    _require(policy["max_sample_elapsed_ns"] == MAX_SAMPLE_ELAPSED_NS, "policy elapsed bound differs")
    _require(policy["workloads"] == list(SOURCE_WORKLOADS), "policy workload registry differs")
    _require(policy["phases"] == list(PHASES), "policy phase registry differs")
    _require(policy["statistics"] == list(STATISTIC_NAMES), "policy statistics differ")
    _require(policy["raw_samples_preserved"] is True, "policy must preserve raw samples")
    _require(policy["outlier_deletion"] is False, "policy must forbid outlier deletion")
    _require(policy["unknown_rate_source"] == "raw_unknown_outcome_boolean_mean", "policy unknown source differs")
    _require(policy["l2_unknown_outcomes_allowed"] is False, "policy must reject L2 unknown outcomes")
    _require(policy["same_work_contract_required"] is True, "policy must require equal work")
    _require(policy["automatic_redispatch"] is False, "policy cannot enable redispatch")
    _require(policy["public_release"] is False, "policy cannot authorize release")
    projected = dict(policy)
    projected.update({
        "registry_schema": registry["schema"],
        "registry_version": registry["version"],
        "registry_sha256": sha256(raw),
    })
    return raw, registry, projected


_POLICY_REGISTRY_RAW, _POLICY_REGISTRY, _AUTHORITATIVE_POLICY = _load_policy_registry()


def reviewed_policy() -> dict[str, Any]:
    current = _read_bounded(POLICY_REGISTRY_PATH, POLICY_REGISTRY_MAX_BYTES)
    _require(current == _POLICY_REGISTRY_RAW, "policy registry changed after admission")
    return json.loads(json.dumps(_AUTHORITATIVE_POLICY))


def _string(value: Any, label: str, maximum: int = 4096) -> str:
    _require(isinstance(value, str) and 0 < len(value) <= maximum and value.strip() == value,
             f"{label} must be a nonempty trimmed string")
    return value


def _identifier(value: Any, label: str) -> str:
    text = _string(value, label, 256)
    _require(IDENTIFIER_RE.fullmatch(text) is not None, f"{label} is malformed")
    return text


def _sha(value: Any, label: str) -> str:
    text = _string(value, label, 64)
    _require(SHA256_RE.fullmatch(text) is not None, f"{label} must be a lowercase SHA-256")
    return text


def _git_sha(value: Any, label: str) -> str:
    text = _string(value, label, 40)
    _require(GIT_SHA_RE.fullmatch(text) is not None, f"{label} must be a 40-character Git SHA")
    return text


def _positive_int(value: Any, label: str, maximum: int) -> int:
    _require(type(value) is int and 0 < value <= maximum, f"{label} must be in 1..={maximum}")
    return value


def _nonnegative_number(value: Any, label: str) -> float | int:
    _require(type(value) in {int, float}, f"{label} must be numeric and not boolean")
    number = float(value)
    _require(math.isfinite(number) and number >= 0.0, f"{label} must be finite and nonnegative")
    return value


def _validate_source(value: Any) -> dict[str, Any]:
    source = _exact_keys(value, SOURCE_KEYS, "source")
    repository = _string(source["repository"], "source.repository", 256)
    _require(repository.count("/") == 1 and not repository.startswith("/") and not repository.endswith("/"),
             "source.repository must be owner/name")
    _git_sha(source["commit"], "source.commit")
    _git_sha(source["tree"], "source.tree")
    for field in SOURCE_KEYS - {"repository", "commit", "tree"}:
        _sha(source[field], f"source.{field}")
    return source


def _validate_environment(value: Any) -> dict[str, Any]:
    environment = _exact_keys(value, ENVIRONMENT_KEYS, "environment")
    _sha(environment["runner_id_sha256"], "environment.runner_id_sha256")
    _positive_int(environment["cpu_count"], "environment.cpu_count", 1_048_576)
    for field in ENVIRONMENT_KEYS - {"runner_id_sha256", "cpu_count"}:
        _string(environment[field], f"environment.{field}", 4096)
    return environment


def _validate_stage_observation(
    value: Any,
    *,
    workload_id: str,
    stage: str,
    level: str,
) -> None:
    observation = _exact_keys(value, STAGE_OBSERVATION_KEYS, f"stage {stage}")
    status = observation["status"]
    _require(status in {"observed", "not_applicable", "unavailable"}, f"stage {stage} has invalid status")
    reason = observation["reason"]
    if status == "observed":
        _require(reason is None, f"observed stage {stage} must not carry a reason")
        _require(type(observation["value_ns"]) is int and 0 <= observation["value_ns"] <= MAX_SAMPLE_ELAPSED_NS,
                 f"observed stage {stage} value is invalid")
    else:
        _require(observation["value_ns"] is None, f"non-observed stage {stage} must have null value")
        _string(reason, f"stage {stage}.reason", 512)
    if status == "not_applicable":
        _require(stage in STAGE_NOT_APPLICABLE.get(workload_id, frozenset()),
                 f"stage {stage} is applicable to {workload_id}")
    if level == INSTALLED_LEVEL:
        _require(status != "unavailable", f"L2 stage {stage} is unavailable for {workload_id}")
        if stage not in STAGE_NOT_APPLICABLE.get(workload_id, frozenset()):
            _require(status == "observed", f"L2 applicable stage {stage} is not observed for {workload_id}")


def _validate_resource_observation(value: Any, *, name: str, level: str) -> None:
    observation = _exact_keys(value, RESOURCE_OBSERVATION_KEYS, f"resource {name}")
    status = observation["status"]
    _require(status in {"observed", "unavailable"}, f"resource {name} has invalid status")
    _require(observation["unit"] == REQUIRED_RESOURCE_UNITS[name], f"resource {name} unit differs")
    if status == "observed":
        _require(observation["reason"] is None, f"observed resource {name} must not carry a reason")
        number = _nonnegative_number(observation["value"], f"resource {name}.value")
        if observation["unit"] == "ratio":
            _require(float(number) <= 1.0, f"resource {name} ratio exceeds 1")
    else:
        _require(observation["value"] is None, f"unavailable resource {name} must have null value")
        _string(observation["reason"], f"resource {name}.reason", 512)
    if level == INSTALLED_LEVEL:
        _require(status == "observed", f"L2 core resource {name} is unavailable")


def _validate_sample(value: Any, *, level: str, repetitions: int) -> tuple[str, str, int]:
    sample = _exact_keys(value, SAMPLE_KEYS, "sample")
    workload_id = sample["workload_id"]
    _require(workload_id in SOURCE_WORKLOADS, f"sample workload is not WL-01..WL-10: {workload_id!r}")
    phase = sample["phase"]
    _require(phase in PHASES, f"sample phase is invalid: {phase!r}")
    repetition = sample["repetition"]
    _require(type(repetition) is int and 0 <= repetition < repetitions, "sample repetition is outside configured range")
    _require(type(sample["elapsed_ns"]) is int and 0 < sample["elapsed_ns"] <= MAX_SAMPLE_ELAPSED_NS,
             "sample elapsed_ns is invalid")
    _positive_int(sample["operations"], "sample.operations", 1_048_576)
    _require(sample["correctness_validated"] is True, "sample correctness was not validated")
    _require(type(sample["unknown_outcome"]) is bool, "sample unknown_outcome must be boolean")
    if level == INSTALLED_LEVEL:
        _require(not sample["unknown_outcome"], "L2 sample has an unknown outcome")

    stages = _exact_keys(sample["stage_durations"], set(REQUIRED_STAGE_NAMES), "sample.stage_durations")
    for stage in REQUIRED_STAGE_NAMES:
        _validate_stage_observation(stages[stage], workload_id=workload_id, stage=stage, level=level)

    resources = _exact_keys(sample["resources"], set(REQUIRED_RESOURCE_UNITS), "sample.resources")
    for name in REQUIRED_RESOURCE_UNITS:
        _validate_resource_observation(resources[name], name=name, level=level)
    unknown = resources["unknown_rate"]
    if unknown["status"] == "observed":
        expected_unknown = 1.0 if sample["unknown_outcome"] else 0.0
        _require(
            float(unknown["value"]) == expected_unknown,
            "observed unknown_rate contradicts raw unknown_outcome",
        )
    redispatch = resources["redispatch_count"]
    if redispatch["status"] == "observed":
        _require(redispatch["value"] == 0, "automatic redispatch count must be zero")
    return workload_id, phase, repetition


def work_contract_digest(batch: Mapping[str, Any]) -> str:
    operations = [
        {
            "workload_id": sample["workload_id"],
            "phase": sample["phase"],
            "repetition": sample["repetition"],
            "operations": sample["operations"],
        }
        for sample in sorted(
            batch["samples"],
            key=lambda item: (item["workload_id"], item["phase"], item["repetition"]),
        )
    ]
    contract = {
        "schema": WORK_CONTRACT_SCHEMA,
        "workload_configurations": batch["workload_configurations"],
        "phases": batch["phases"],
        "repetitions": batch["repetitions"],
        "operations": operations,
    }
    return sha256(canonical(contract))


def validate_batch(value: Any, *, expected_level: str | None = None) -> dict[str, Any]:
    batch = _exact_keys(value, BATCH_KEYS, "performance batch")
    _require(batch["schema"] == BATCH_SCHEMA, "performance batch schema differs")
    policy = _exact_keys(batch["policy"], POLICY_KEYS, "batch.policy")
    _require(policy == reviewed_policy(), "batch policy differs from reviewed policy")
    _identifier(batch["batch_id"], "batch_id")
    level = batch["qualification_level"]
    _require(level in LEVELS, "qualification_level is unsupported")
    if expected_level is not None:
        _require(level == expected_level, "batch qualification level differs from requested level")
    _validate_source(batch["source"])
    _validate_environment(batch["environment"])
    _require(batch["workload_profiles"] == list(SOURCE_WORKLOADS), "batch must contain WL-01 through WL-10 in order")
    configurations = _exact_keys(
        batch["workload_configurations"], set(SOURCE_WORKLOADS), "workload_configurations"
    )
    for workload in SOURCE_WORKLOADS:
        _sha(configurations[workload], f"workload_configurations.{workload}")
    _require(batch["phases"] == list(PHASES), "batch must contain cold_start and steady_state in order")
    repetitions = _positive_int(batch["repetitions"], "repetitions", MAX_REPETITIONS)
    _require(repetitions >= MIN_REPETITIONS, f"batch requires at least {MIN_REPETITIONS} repetitions")
    _require(batch["raw_samples_preserved"] is True, "raw samples must be preserved")
    _require(batch["outlier_deletion"] is False, "outlier deletion is forbidden")
    _require(batch["automatic_redispatch"] is False, "automatic_redispatch must remain false")
    _require(batch["public_release"] is False, "performance evidence cannot authorize public release")

    samples = batch["samples"]
    expected_count = len(SOURCE_WORKLOADS) * len(PHASES) * repetitions
    _require(isinstance(samples, list) and len(samples) == expected_count,
             f"batch sample count differs: expected={expected_count} observed={len(samples) if isinstance(samples, list) else 'non-list'}")
    observed: set[tuple[str, str, int]] = set()
    for sample in samples:
        key = _validate_sample(sample, level=level, repetitions=repetitions)
        _require(key not in observed, f"duplicate sample identity: {key}")
        observed.add(key)
    expected = {
        (workload, phase, repetition)
        for workload in SOURCE_WORKLOADS
        for phase in PHASES
        for repetition in range(repetitions)
    }
    _require(observed == expected, "batch raw sample matrix is incomplete")
    _sha(batch["work_contract_sha256"], "work_contract_sha256")
    _require(
        batch["work_contract_sha256"] == work_contract_digest(batch),
        "batch work contract digest mismatch",
    )
    claimed = batch["content_sha256"]
    _sha(claimed, "content_sha256")
    _require(claimed == content_digest(batch), "batch content digest mismatch")
    return batch


def load_batch(path: Path, *, expected_level: str | None = None) -> Batch:
    raw = _read_bounded(path, MAX_BATCH_BYTES)
    value = strict_json_bytes(raw, str(path))
    validate_batch(value, expected_level=expected_level)
    return Batch(path=path.absolute(), raw=raw, value=value, digest=sha256(raw))


def percentile(values: Sequence[float], quantile: float) -> float:
    _require(bool(values), "percentile requires at least one value")
    _require(math.isfinite(quantile) and 0.0 < quantile <= 1.0, "percentile quantile is invalid")
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * quantile) - 1)]


def summarize_series(workload_id: str, phase: str, samples: Sequence[Mapping[str, Any]]) -> SeriesSummary:
    _require(bool(samples), f"no samples for {workload_id}/{phase}")
    elapsed_ms = [sample["elapsed_ns"] / 1_000_000.0 for sample in samples]
    operations = sum(sample["operations"] for sample in samples)
    total_seconds = sum(sample["elapsed_ns"] for sample in samples) / 1_000_000_000.0
    _require(total_seconds > 0.0, "summary elapsed total is zero")
    median = statistics.median(elapsed_ms)
    absolute_deviations = [abs(value - median) for value in elapsed_ms]
    stdev = statistics.stdev(elapsed_ms) if len(elapsed_ms) > 1 else 0.0
    mean = statistics.fmean(elapsed_ms)
    half_width = 1.96 * stdev / math.sqrt(len(elapsed_ms)) if len(elapsed_ms) > 1 else 0.0
    values = {
        "throughput_per_sec": operations / total_seconds,
        "median_ms": median,
        "p90_ms": percentile(elapsed_ms, 0.90),
        "p95_ms": percentile(elapsed_ms, 0.95),
        "p99_ms": percentile(elapsed_ms, 0.99),
        "max_ms": max(elapsed_ms),
        "mad_ms": statistics.median(absolute_deviations),
        "stdev_ms": stdev,
        "mean_ci95_lower_ms": max(0.0, mean - half_width),
        "mean_ci95_upper_ms": mean + half_width,
    }

    def observed_resource(name: str) -> list[float]:
        rows: list[float] = []
        for sample in samples:
            observation = sample["resources"][name]
            if observation["status"] == "observed":
                rows.append(float(observation["value"]))
        return rows

    unknown_rate = sum(1 for sample in samples if sample["unknown_outcome"]) / len(samples)
    fairness_values = observed_resource("fairness")
    redispatch_values = observed_resource("redispatch_count")
    for name, value in values.items():
        _require(math.isfinite(value) and value >= 0.0, f"summary {name} is not finite and nonnegative")
    return SeriesSummary(
        workload_id=workload_id,
        phase=phase,
        samples=len(samples),
        operations=operations,
        unknown_rate_mean=unknown_rate,
        fairness_mean=statistics.fmean(fairness_values) if fairness_values else None,
        redispatch_count_total=int(sum(redispatch_values)) if redispatch_values else None,
        **values,
    )


def summarize_batch(batch: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for workload in SOURCE_WORKLOADS:
        for phase in PHASES:
            rows = [
                sample for sample in batch["samples"]
                if sample["workload_id"] == workload and sample["phase"] == phase
            ]
            key = f"{workload}/{phase}"
            result[key] = summarize_series(workload, phase, rows).as_dict()
    return result


def summarize_batches(batches: Sequence[Batch]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for workload in SOURCE_WORKLOADS:
        for phase in PHASES:
            rows: list[Mapping[str, Any]] = []
            for batch in batches:
                rows.extend(
                    sample for sample in batch.value["samples"]
                    if sample["workload_id"] == workload and sample["phase"] == phase
                )
            key = f"{workload}/{phase}"
            result[key] = summarize_series(workload, phase, rows).as_dict()
    return result


def _relative_spread(values: Sequence[float]) -> float:
    _require(bool(values), "relative spread requires values")
    low, high = min(values), max(values)
    if low == 0.0:
        return 0.0 if high == 0.0 else math.inf
    return (high / low - 1.0) * 100.0


def _ci_overlap(summaries: Sequence[Mapping[str, Any]]) -> bool:
    lower = max(float(summary["mean_ci95_lower_ms"]) for summary in summaries)
    upper = min(float(summary["mean_ci95_upper_ms"]) for summary in summaries)
    return lower <= upper


def stability_assessment(batches: Sequence[Batch]) -> dict[str, Any]:
    _require(len(batches) == 3, "stability requires exactly three batches")
    batch_summaries = {batch.value["batch_id"]: summarize_batch(batch.value) for batch in batches}
    series: list[dict[str, Any]] = []
    unstable: list[dict[str, Any]] = []
    for key in sorted(next(iter(batch_summaries.values()))):
        summaries = [batch_summaries[batch.value["batch_id"]][key] for batch in batches]
        median_spread = _relative_spread([float(summary["median_ms"]) for summary in summaries])
        p95_spread = _relative_spread([float(summary["p95_ms"]) for summary in summaries])
        overlap = _ci_overlap(summaries)
        row = {
            "series": key,
            "median_spread_percent": median_spread,
            "p95_spread_percent": p95_spread,
            "mean_ci95_overlap": overlap,
            "stable": median_spread <= float(_AUTHORITATIVE_POLICY["max_self_drift_percent"]) and p95_spread <= float(_AUTHORITATIVE_POLICY["max_self_drift_percent"]),
        }
        series.append(row)
        if not row["stable"]:
            unstable.append(row)
    return {
        "status": "STABLE" if not unstable else "UNSTABLE_ENVIRONMENT",
        "passed": not unstable,
        "policy_max_self_drift_percent": _AUTHORITATIVE_POLICY["max_self_drift_percent"],
        "series": series,
        "unstable_series": unstable,
    }


def _identity_without_candidate_bytes(source: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "repository": source["repository"],
        "harness_sha256": source["harness_sha256"],
        "toolchain_sha256": source["toolchain_sha256"],
    }


def _validate_batch_set(
    batches: Sequence[Batch],
    *,
    expected_ids: Sequence[str],
    label: str,
    level: str,
) -> None:
    _require(len(batches) == len(expected_ids), f"{label} requires exactly {len(expected_ids)} batches")
    ids = tuple(batch.value["batch_id"] for batch in batches)
    _require(ids == tuple(expected_ids), f"{label} batch IDs must be {list(expected_ids)} in order")
    first = batches[0].value
    for batch in batches[1:]:
        current = batch.value
        _require(current["qualification_level"] == level, f"{label} level differs")
        _require(current["source"] == first["source"], f"{label} is not a same-binary/source batch set")
        _require(current["environment"] == first["environment"], f"{label} environment identity differs")
        _require(current["repetitions"] == first["repetitions"], f"{label} repetitions differ")
        _require(
            current["work_contract_sha256"] == first["work_contract_sha256"],
            f"{label} work contract differs",
        )


def compare(
    baseline: Sequence[Batch],
    candidate: Sequence[Batch],
) -> dict[str, Any]:
    baseline_summary = summarize_batches(baseline)
    candidate_summary = summarize_batches(candidate)
    comparisons: list[dict[str, Any]] = []
    regressions: list[dict[str, Any]] = []
    for key in sorted(baseline_summary):
        old = baseline_summary[key]
        new = candidate_summary[key]
        for metric in ("median_ms", "p95_ms", "p99_ms"):
            old_value = float(old[metric])
            new_value = float(new[metric])
            delta = 0.0 if old_value == 0.0 and new_value == 0.0 else (
                math.inf if old_value == 0.0 else (new_value / old_value - 1.0) * 100.0
            )
            row = {
                "series": key,
                "metric": metric,
                "baseline": old_value,
                "candidate": new_value,
                "regression_percent": delta,
                "threshold_percent": _AUTHORITATIVE_POLICY["max_latency_regression_percent"],
                "regressed": delta > float(_AUTHORITATIVE_POLICY["max_latency_regression_percent"]),
            }
            comparisons.append(row)
            if row["regressed"]:
                regressions.append(row)
        old_throughput = float(old["throughput_per_sec"])
        new_throughput = float(new["throughput_per_sec"])
        throughput_drop = (1.0 - new_throughput / old_throughput) * 100.0
        throughput_row = {
            "series": key,
            "metric": "throughput_per_sec",
            "baseline": old_throughput,
            "candidate": new_throughput,
            "regression_percent": throughput_drop,
            "threshold_percent": _AUTHORITATIVE_POLICY["max_throughput_regression_percent"],
            "regressed": throughput_drop > float(
                _AUTHORITATIVE_POLICY["max_throughput_regression_percent"]
            ),
        }
        comparisons.append(throughput_row)
        if throughput_row["regressed"]:
            regressions.append(throughput_row)
        if old["unknown_rate_mean"] is not None and new["unknown_rate_mean"] is not None:
            increase = float(new["unknown_rate_mean"]) - float(old["unknown_rate_mean"])
            row = {
                "series": key, "metric": "unknown_rate_mean",
                "baseline": old["unknown_rate_mean"], "candidate": new["unknown_rate_mean"],
                "absolute_increase": increase, "threshold": _AUTHORITATIVE_POLICY["max_unknown_rate_increase"],
                "regressed": increase > float(_AUTHORITATIVE_POLICY["max_unknown_rate_increase"]),
            }
            comparisons.append(row)
            if row["regressed"]:
                regressions.append(row)
        if old["fairness_mean"] is not None and new["fairness_mean"] is not None:
            drop = float(old["fairness_mean"]) - float(new["fairness_mean"])
            row = {
                "series": key, "metric": "fairness_mean",
                "baseline": old["fairness_mean"], "candidate": new["fairness_mean"],
                "absolute_drop": drop, "threshold": _AUTHORITATIVE_POLICY["max_fairness_drop"],
                "regressed": drop > float(_AUTHORITATIVE_POLICY["max_fairness_drop"]),
            }
            comparisons.append(row)
            if row["regressed"]:
                regressions.append(row)
    return {
        "status": "PASS_COMPARISON" if not regressions else "FAIL_REGRESSION",
        "passed": not regressions,
        "threshold_percent": _AUTHORITATIVE_POLICY["max_latency_regression_percent"],
        "throughput_threshold_percent": _AUTHORITATIVE_POLICY["max_throughput_regression_percent"],
        "comparisons": comparisons,
        "regressions": regressions,
        "baseline_summary": baseline_summary,
        "candidate_summary": candidate_summary,
    }


def qualify(
    baseline: Sequence[Batch],
    candidate: Sequence[Batch],
    *,
    level: str,
) -> dict[str, Any]:
    _require(level in LEVELS, "requested qualification level is unsupported")
    _validate_batch_set(
        baseline, expected_ids=BASELINE_BATCH_IDS, label="baseline", level=level
    )
    _validate_batch_set(
        candidate, expected_ids=CANDIDATE_BATCH_IDS, label="candidate", level=level
    )
    base_first, candidate_first = baseline[0].value, candidate[0].value
    _require(base_first["environment"] == candidate_first["environment"],
             "candidate environment differs from stable baseline")
    _require(
        base_first["work_contract_sha256"] == candidate_first["work_contract_sha256"],
        "candidate measured work/configuration differs from stable baseline",
    )
    _require(
        _identity_without_candidate_bytes(base_first["source"])
        == _identity_without_candidate_bytes(candidate_first["source"]),
        "candidate changed repository, harness or toolchain identity",
    )
    baseline_stability = stability_assessment(baseline)
    candidate_stability = stability_assessment(candidate)
    if not baseline_stability["passed"] or not candidate_stability["passed"]:
        comparison = {
            "status": "NOT_RUN_UNSTABLE_ENVIRONMENT",
            "passed": False,
            "comparisons": [],
            "regressions": [],
        }
        status = "UNSTABLE_ENVIRONMENT"
    else:
        comparison = compare(baseline, candidate)
        status = comparison["status"]
    l2_qualified = level == INSTALLED_LEVEL and status == "PASS_COMPARISON"
    if level == SOURCE_LEVEL and status == "PASS_COMPARISON":
        status = "SOURCE_COMPARISON_PASS_NOT_L2"
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "policy": reviewed_policy(),
        "work_contract_sha256": base_first["work_contract_sha256"],
        "qualification_level": level,
        "status": status,
        "passed": status in {"PASS_COMPARISON", "SOURCE_COMPARISON_PASS_NOT_L2"},
        "l2_qualified": l2_qualified,
        "baseline_batches": [
            {"batch_id": batch.value["batch_id"], "path": str(batch.path), "sha256": batch.digest,
             "content_sha256": batch.value["content_sha256"]}
            for batch in baseline
        ],
        "candidate_batches": [
            {"batch_id": batch.value["batch_id"], "path": str(batch.path), "sha256": batch.digest,
             "content_sha256": batch.value["content_sha256"]}
            for batch in candidate
        ],
        "baseline_stability": baseline_stability,
        "candidate_stability": candidate_stability,
        "comparison": comparison,
        "external_holds": EXTERNAL_HOLDS,
        "claim_ceiling": (
            "INSTALLED_ROOTLINUX_PERFORMANCE_ONLY_NOT_L3_L6"
            if level == INSTALLED_LEVEL
            else "SOURCE_CONTRACT_ONLY_NOT_INSTALLED_TARGET"
        ),
        "raw_samples_preserved": True,
        "outlier_deletion": False,
        "automatic_redispatch": False,
        "public_release": False,
        "content_sha256": "",
    }
    report["content_sha256"] = content_digest(report)
    return report


def _write_private_atomic(path: Path, report: Mapping[str, Any]) -> None:
    absolute = Path(os.path.abspath(os.fspath(path)))
    _require(absolute.name not in {"", ".", ".."}, "output path must name a file")
    payload = canonical(report) + b"\n"
    _require(len(payload) <= MAX_REPORT_BYTES, "qualification report exceeds size bound")

    for flag_name in ("O_CLOEXEC", "O_NOFOLLOW", "O_DIRECTORY"):
        _require(getattr(os, flag_name, 0) != 0, f"platform lacks required {flag_name}")
    _require(hasattr(os, "geteuid"), "platform lacks effective UID identity")
    _require(Path("/proc/self/fd").is_dir(), "platform lacks descriptor-bound /proc/self/fd publication")
    for operation in (os.open, os.stat, os.unlink):
        _require(operation in os.supports_dir_fd, "platform lacks required dir_fd semantics")
    _require(_OS_LINK_SUPPORTS_DIR_FD, "platform lacks required link dir_fd semantics")
    _require(_OS_LINK_SUPPORTS_FOLLOW_SYMLINKS, "platform lacks link follow-symlink control")

    parent = absolute.parent
    try:
        parent_path_before = os.lstat(parent)
    except OSError as error:
        raise QualificationError(f"cannot inspect output parent: {error}") from error
    _require(stat.S_ISDIR(parent_path_before.st_mode), "output parent must be a real directory")
    _require(parent_path_before.st_uid == os.geteuid(), "output parent must be owned by effective uid")
    _require(stat.S_IMODE(parent_path_before.st_mode) & 0o022 == 0, "output parent must not be group/world writable")

    parent_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
    parent_descriptor = os.open(parent, parent_flags)
    descriptor = -1
    temporary_name: str | None = None
    staged_dev_ino: tuple[int, int] | None = None
    published = False
    succeeded = False

    def parent_identity_matches() -> bool:
        try:
            current = os.lstat(parent)
        except OSError:
            return False
        return _stable_directory_identity(current) == _stable_directory_identity(parent_before)

    def entry_matches(name: str, dev_ino: tuple[int, int]) -> bool:
        try:
            metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return (metadata.st_dev, metadata.st_ino) == dev_ino and not stat.S_ISLNK(metadata.st_mode)

    def remove_owned(name: str, dev_ino: tuple[int, int]) -> None:
        if entry_matches(name, dev_ino):
            os.unlink(name, dir_fd=parent_descriptor)

    try:
        parent_before = os.fstat(parent_descriptor)
        _require(
            _stable_directory_identity(parent_before) == _stable_directory_identity(parent_path_before),
            "output parent changed during descriptor acquisition",
        )
        _require(parent_identity_matches(), "output parent pathname changed before publication")
        try:
            os.stat(absolute.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise QualificationError("output already exists")

        staging_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        for _ in range(32):
            candidate = f".{absolute.name}.{secrets.token_hex(16)}.tmp"
            try:
                descriptor = os.open(candidate, staging_flags, 0o600, dir_fd=parent_descriptor)
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        _require(descriptor >= 0 and temporary_name is not None, "cannot allocate unique private staging file")

        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            _require(written > 0, "zero-progress output write")
            offset += written
        os.fsync(descriptor)
        staged = os.fstat(descriptor)
        staged_dev_ino = (staged.st_dev, staged.st_ino)
        _require(stat.S_ISREG(staged.st_mode), "staging object is not regular")
        _require(stat.S_IMODE(staged.st_mode) == 0o600, "staging mode differs from 0600")
        _require(staged.st_uid == os.geteuid(), "staging object owner differs")
        _require(staged.st_nlink == 1, "staging object link count differs before publication")
        _require(staged.st_size == len(payload), "staging object size differs")
        _require(entry_matches(temporary_name, staged_dev_ino), "staging pathname no longer names writer-owned inode")
        _require(parent_identity_matches(), "output parent pathname changed before publication")

        os.link(
            temporary_name,
            absolute.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        published = True

        final_before = os.stat(absolute.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (final_before.st_dev, final_before.st_ino) != staged_dev_ino:
            os.unlink(absolute.name, dir_fd=parent_descriptor)
            published = False
            raise QualificationError("staging pathname was replaced during publication")
        _require(
            stat.S_ISREG(final_before.st_mode)
            and stat.S_IMODE(final_before.st_mode) == 0o600
            and final_before.st_uid == os.geteuid()
            and final_before.st_nlink == 2
            and final_before.st_size == len(payload),
            "published output identity differs from admitted staging inode",
        )
        _require(parent_identity_matches(), "output parent pathname changed during publication")

        final_descriptor = os.open(
            absolute.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
        try:
            verify_before = os.fstat(final_descriptor)
            _require((verify_before.st_dev, verify_before.st_ino) == staged_dev_ino, "published descriptor identity differs")
            chunks: list[bytes] = []
            read_offset = 0
            while read_offset < len(payload):
                block = os.pread(final_descriptor, min(1024 * 1024, len(payload) - read_offset), read_offset)
                _require(bool(block), "short read while verifying published output")
                chunks.append(block)
                read_offset += len(block)
            verify_after = os.fstat(final_descriptor)
            _require(_stable_file_identity(verify_before) == _stable_file_identity(verify_after), "published output changed during verification")
            _require(b"".join(chunks) == payload, "published output bytes differ from admitted payload")
        finally:
            os.close(final_descriptor)

        _require(entry_matches(temporary_name, staged_dev_ino), "staging pathname was replaced during publication")
        os.unlink(temporary_name, dir_fd=parent_descriptor)
        temporary_name = None
        os.fsync(parent_descriptor)

        final_after = os.stat(absolute.name, dir_fd=parent_descriptor, follow_symlinks=False)
        _require(
            (final_after.st_dev, final_after.st_ino) == staged_dev_ino
            and stat.S_ISREG(final_after.st_mode)
            and stat.S_IMODE(final_after.st_mode) == 0o600
            and final_after.st_uid == os.geteuid()
            and final_after.st_nlink == 1
            and final_after.st_size == len(payload),
            "published output final identity differs",
        )
        _require(parent_identity_matches(), "output parent pathname changed after publication")
        succeeded = True
    finally:
        if not succeeded and published and staged_dev_ino is not None:
            try:
                remove_owned(absolute.name, staged_dev_ino)
            except OSError:
                pass
        if temporary_name is not None and staged_dev_ino is not None:
            try:
                remove_owned(temporary_name, staged_dev_ino)
            except OSError:
                pass
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.fsync(parent_descriptor)
        except OSError:
            pass
        os.close(parent_descriptor)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", action="append", required=True, type=Path)
    parser.add_argument("--candidate", action="append", required=True, type=Path)
    parser.add_argument("--level", choices=sorted(LEVELS), required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if len(args.baseline) != 3 or len(args.candidate) != 3:
        parser.error("exactly three --baseline and three --candidate artifacts are required")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        baseline = [load_batch(path, expected_level=args.level) for path in args.baseline]
        candidate = [load_batch(path, expected_level=args.level) for path in args.candidate]
        report = qualify(baseline, candidate, level=args.level)
        _write_private_atomic(args.output, report)
        print(json.dumps({
            "status": report["status"],
            "l2_qualified": report["l2_qualified"],
            "output": str(args.output),
            "sha256": report["content_sha256"],
        }, sort_keys=True))
        return 0 if report["passed"] else 2
    except (QualificationError, OSError, ValueError, TypeError, OverflowError) as error:
        print(f"performance qualification failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())