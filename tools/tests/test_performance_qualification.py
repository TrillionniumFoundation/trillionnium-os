from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "tools/perf/performance_qualification.py"
SPEC = importlib.util.spec_from_file_location("performance_qualification", PATH)
assert SPEC and SPEC.loader
QUAL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = QUAL
SPEC.loader.exec_module(QUAL)


def observation(*, value: int | float = 1, unit: str, level: str) -> dict:
    if level == QUAL.INSTALLED_LEVEL:
        return {"status": "observed", "value": value, "unit": unit, "reason": None}
    return {
        "status": "unavailable",
        "value": None,
        "unit": unit,
        "reason": "source fixture does not mint installed observations",
    }


def stage(*, applicable: bool, level: str, value: int = 1_000) -> dict:
    if not applicable:
        return {
            "status": "not_applicable",
            "value_ns": None,
            "reason": "workload profile excludes this component",
        }
    if level == QUAL.INSTALLED_LEVEL:
        return {"status": "observed", "value_ns": value, "reason": None}
    return {
        "status": "unavailable",
        "value_ns": None,
        "reason": "source fixture does not mint installed stage timing",
    }


def make_batch(
    batch_id: str,
    *,
    level: str = QUAL.SOURCE_LEVEL,
    base_ns: int = 10_000_000,
    source_tag: str = "a",
    runner_tag: str = "1",
) -> dict:
    repetitions = QUAL.MIN_REPETITIONS
    source = {
        "repository": "TrillionniumFoundation/trillionnium-os",
        "commit": source_tag * 40,
        "tree": ("b" if source_tag != "b" else "c") * 40,
        "host_sha256": source_tag * 64,
        "core_sha256": ("c" if source_tag != "c" else "d") * 64,
        "harness_sha256": "d" * 64,
        "build_log_sha256": "e" * 64,
        "toolchain_sha256": "f" * 64,
    }
    environment = {
        "runner_id_sha256": runner_tag * 64,
        "kernel": "Linux 6.8.0 fixture",
        "cpu_model": "fixture-cpu",
        "cpu_count": 8,
        "cpu_affinity": "0-7",
        "cpu_governors": "performance",
        "filesystem": "ext4",
        "mount_options": "rw,noatime",
        "scratch_device": "fixture-device",
        "cgroup_mode": "v2",
        "numa_policy": "local",
        "power_profile": "performance",
    }
    samples = []
    for workload_index, workload in enumerate(QUAL.SOURCE_WORKLOADS):
        not_applicable = QUAL.STAGE_NOT_APPLICABLE.get(workload, frozenset())
        for phase_index, phase in enumerate(QUAL.PHASES):
            for repetition in range(repetitions):
                elapsed = base_ns + workload_index * 100_000 + phase_index * 50_000 + repetition * 1_000
                stages = {
                    name: stage(
                        applicable=name not in not_applicable,
                        level=level,
                        value=1_000 + index,
                    )
                    for index, name in enumerate(QUAL.REQUIRED_STAGE_NAMES)
                }
                resources = {}
                for index, (name, unit) in enumerate(QUAL.REQUIRED_RESOURCE_UNITS.items()):
                    value: int | float = index + 1
                    if name == "unknown_rate":
                        value = 0.0
                    elif name == "fairness":
                        value = 1.0
                    elif name == "redispatch_count":
                        value = 0
                    resources[name] = observation(value=value, unit=unit, level=level)
                samples.append({
                    "workload_id": workload,
                    "phase": phase,
                    "repetition": repetition,
                    "elapsed_ns": elapsed,
                    "operations": 1,
                    "correctness_validated": True,
                    "stage_durations": stages,
                    "resources": resources,
                    "unknown_outcome": False,
                })
    value = {
        "schema": QUAL.BATCH_SCHEMA,
        "policy": QUAL.reviewed_policy(),
        "batch_id": batch_id,
        "qualification_level": level,
        "source": source,
        "environment": environment,
        "workload_profiles": list(QUAL.SOURCE_WORKLOADS),
        "phases": list(QUAL.PHASES),
        "repetitions": repetitions,
        "raw_samples_preserved": True,
        "outlier_deletion": False,
        "samples": samples,
        "automatic_redispatch": False,
        "public_release": False,
        "content_sha256": "",
    }
    value["content_sha256"] = QUAL.content_digest(value)
    return value


def reseal(value: dict) -> dict:
    value["content_sha256"] = ""
    value["content_sha256"] = QUAL.content_digest(value)
    return value


def loaded(value: dict, path: str) -> QUAL.Batch:
    raw = QUAL.canonical(value) + b"\n"
    return QUAL.Batch(Path(path), raw, value, QUAL.sha256(raw))


class PerformanceQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source_baseline = [make_batch(name, base_ns=10_000_000) for name in QUAL.BASELINE_BATCH_IDS]
        cls.source_candidate = [
            make_batch(name, base_ns=10_500_000, source_tag="b")
            for name in QUAL.CANDIDATE_BATCH_IDS
        ]

    def baseline_batches(self, *, level: str = QUAL.SOURCE_LEVEL, base_ns: int = 10_000_000):
        return [
            loaded(make_batch(name, level=level, base_ns=base_ns), f"/{name}.json")
            for name in QUAL.BASELINE_BATCH_IDS
        ]

    def candidate_batches(self, *, level: str = QUAL.SOURCE_LEVEL, base_ns: int = 10_500_000):
        return [
            loaded(make_batch(name, level=level, base_ns=base_ns, source_tag="b"), f"/{name}.json")
            for name in QUAL.CANDIDATE_BATCH_IDS
        ]

    def test_source_batch_requires_complete_raw_matrix_and_preserves_holds(self) -> None:
        value = copy.deepcopy(self.source_baseline[0])
        QUAL.validate_batch(value, expected_level=QUAL.SOURCE_LEVEL)
        value["samples"].pop()
        reseal(value)
        with self.assertRaisesRegex(QUAL.QualificationError, "sample count"):
            QUAL.validate_batch(value)

        report = QUAL.qualify(self.baseline_batches(), self.candidate_batches(), level=QUAL.SOURCE_LEVEL)
        self.assertEqual(report["status"], "SOURCE_COMPARISON_PASS_NOT_L2")
        self.assertFalse(report["l2_qualified"])
        self.assertEqual(report["external_holds"]["WL-11"]["required_level"], "L4")
        self.assertEqual(report["external_holds"]["WL-12"]["required_level"], "L5")
        self.assertFalse(report["automatic_redispatch"])
        self.assertFalse(report["public_release"])

    def test_statistics_include_percentiles_mad_stdev_and_confidence_interval(self) -> None:
        summary = QUAL.summarize_batch(self.source_baseline[0])["WL-01/cold_start"]
        for name in QUAL.STATISTIC_NAMES:
            self.assertIn(name, summary)
            self.assertGreaterEqual(summary[name], 0.0)
        self.assertEqual(summary["samples"], QUAL.MIN_REPETITIONS)
        self.assertLessEqual(summary["median_ms"], summary["p90_ms"])
        self.assertLessEqual(summary["p90_ms"], summary["p95_ms"])
        self.assertLessEqual(summary["p95_ms"], summary["p99_ms"])
        self.assertLessEqual(summary["p99_ms"], summary["max_ms"])
        self.assertLessEqual(summary["mean_ci95_lower_ms"], summary["mean_ci95_upper_ms"])

    def test_same_binary_and_environment_are_mandatory(self) -> None:
        batches = self.baseline_batches()
        drifted = copy.deepcopy(batches[1].value)
        drifted["environment"]["kernel"] = "different"
        reseal(drifted)
        batches[1] = loaded(drifted, "/A2.json")
        with self.assertRaisesRegex(QUAL.QualificationError, "environment identity"):
            QUAL.qualify(batches, self.candidate_batches(), level=QUAL.SOURCE_LEVEL)

        batches = self.baseline_batches()
        drifted = copy.deepcopy(batches[2].value)
        drifted["source"]["host_sha256"] = "9" * 64
        reseal(drifted)
        batches[2] = loaded(drifted, "/A3.json")
        with self.assertRaisesRegex(QUAL.QualificationError, "same-binary"):
            QUAL.qualify(batches, self.candidate_batches(), level=QUAL.SOURCE_LEVEL)

    def test_unstable_environment_prevents_candidate_comparison(self) -> None:
        batches = self.baseline_batches()
        unstable = copy.deepcopy(batches[2].value)
        for sample in unstable["samples"]:
            sample["elapsed_ns"] *= 2
        reseal(unstable)
        batches[2] = loaded(unstable, "/A3.json")
        report = QUAL.qualify(batches, self.candidate_batches(), level=QUAL.SOURCE_LEVEL)
        self.assertEqual(report["status"], "UNSTABLE_ENVIRONMENT")
        self.assertEqual(report["comparison"]["status"], "NOT_RUN_UNSTABLE_ENVIRONMENT")
        self.assertFalse(report["passed"])

    def test_regression_gate_uses_stable_raw_batches(self) -> None:
        report = QUAL.qualify(
            self.baseline_batches(),
            self.candidate_batches(base_ns=20_000_000),
            level=QUAL.SOURCE_LEVEL,
        )
        self.assertEqual(report["status"], "FAIL_REGRESSION")
        self.assertTrue(report["comparison"]["regressions"])
        self.assertFalse(report["passed"])

    def test_l2_rejects_unavailable_stage_or_resource(self) -> None:
        value = make_batch("A1", level=QUAL.INSTALLED_LEVEL)
        value["samples"][0]["resources"]["fsync_count"] = {
            "status": "unavailable", "value": None, "unit": "count", "reason": "missing counter"
        }
        reseal(value)
        with self.assertRaisesRegex(QUAL.QualificationError, "L2 core resource fsync_count"):
            QUAL.validate_batch(value, expected_level=QUAL.INSTALLED_LEVEL)

        value = make_batch("A1", level=QUAL.INSTALLED_LEVEL)
        value["samples"][0]["stage_durations"]["host_decode"] = {
            "status": "unavailable", "value_ns": None, "reason": "missing span"
        }
        reseal(value)
        with self.assertRaisesRegex(QUAL.QualificationError, "L2 stage host_decode"):
            QUAL.validate_batch(value, expected_level=QUAL.INSTALLED_LEVEL)

    def test_l2_observed_batches_can_pass_without_promoting_external_holds(self) -> None:
        report = QUAL.qualify(
            self.baseline_batches(level=QUAL.INSTALLED_LEVEL),
            self.candidate_batches(level=QUAL.INSTALLED_LEVEL),
            level=QUAL.INSTALLED_LEVEL,
        )
        self.assertEqual(report["status"], "PASS_COMPARISON")
        self.assertTrue(report["l2_qualified"])
        self.assertEqual(set(report["external_holds"]), {"WL-11", "WL-12"})
        self.assertFalse(report["public_release"])

    def test_duplicate_nonfinite_digest_and_outlier_deletion_fail_closed(self) -> None:
        raw = b'{"schema":"x","schema":"y"}'
        with self.assertRaisesRegex(QUAL.QualificationError, "duplicate"):
            QUAL.strict_json_bytes(raw, "fixture")
        with self.assertRaisesRegex(QUAL.QualificationError, "non-finite"):
            QUAL.strict_json_bytes(b'{"value":NaN}', "fixture")
        with self.assertRaisesRegex(QUAL.QualificationError, "non-finite"):
            QUAL.strict_json_bytes(b'{"value":1e9999}', "fixture")

        value = copy.deepcopy(self.source_baseline[0])
        value["outlier_deletion"] = True
        reseal(value)
        with self.assertRaisesRegex(QUAL.QualificationError, "outlier deletion"):
            QUAL.validate_batch(value)

        value = copy.deepcopy(self.source_baseline[0])
        value["content_sha256"] = "0" * 64
        with self.assertRaisesRegex(QUAL.QualificationError, "digest mismatch"):
            QUAL.validate_batch(value)

    def test_not_applicable_is_workload_scoped(self) -> None:
        value = copy.deepcopy(self.source_baseline[0])
        value["samples"][0]["stage_durations"]["host_decode"] = {
            "status": "not_applicable",
            "value_ns": None,
            "reason": "attempted escape",
        }
        reseal(value)
        with self.assertRaisesRegex(QUAL.QualificationError, "applicable"):
            QUAL.validate_batch(value)

    def test_private_atomic_output_refuses_overwrite(self) -> None:
        report = QUAL.qualify(self.baseline_batches(), self.candidate_batches(), level=QUAL.SOURCE_LEVEL)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            QUAL._write_private_atomic(output, report)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            parsed = QUAL.strict_json_bytes(output.read_bytes(), "report")
            self.assertEqual(parsed["content_sha256"], QUAL.content_digest(parsed))
            with self.assertRaisesRegex(QUAL.QualificationError, "already exists"):
                QUAL._write_private_atomic(output, report)


if __name__ == "__main__":
    unittest.main()
