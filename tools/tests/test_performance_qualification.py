from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import time
import sys
import tempfile
import unittest
from unittest import mock

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
        "workload_configurations": {
            workload: QUAL.sha256(f"fixture-configuration:{workload}".encode("ascii"))
            for workload in QUAL.SOURCE_WORKLOADS
        },
        "phases": list(QUAL.PHASES),
        "repetitions": repetitions,
        "raw_samples_preserved": True,
        "outlier_deletion": False,
        "samples": samples,
        "work_contract_sha256": "",
        "automatic_redispatch": False,
        "public_release": False,
        "content_sha256": "",
    }
    value["work_contract_sha256"] = QUAL.work_contract_digest(value)
    value["content_sha256"] = QUAL.content_digest(value)
    return value


def reseal(value: dict, *, recompute_work_contract: bool = True) -> dict:
    if recompute_work_contract:
        value["work_contract_sha256"] = QUAL.work_contract_digest(value)
    value["content_sha256"] = ""
    value["content_sha256"] = QUAL.content_digest(value)
    return value


def loaded(value: dict, path: str) -> QUAL.Batch:
    raw = QUAL.canonical(value) + b"\n"
    return QUAL.Batch(Path(path), raw, value, QUAL.sha256(raw))


def set_operations(value: dict, operations: int) -> dict:
    for sample in value["samples"]:
        sample["operations"] = operations
    return reseal(value)


def set_unknown(value: dict, *, unknown: bool, reported: float | None) -> dict:
    for sample in value["samples"]:
        sample["unknown_outcome"] = unknown
        if reported is not None:
            sample["resources"]["unknown_rate"] = {
                "status": "observed", "value": reported, "unit": "ratio", "reason": None
            }
    return reseal(value)


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

    def test_authoritative_policy_registry_is_exact_and_reported(self) -> None:
        policy = QUAL.reviewed_policy()
        self.assertEqual(policy["registry_schema"], QUAL.POLICY_REGISTRY_SCHEMA)
        self.assertEqual(policy["registry_sha256"], QUAL.sha256(QUAL._POLICY_REGISTRY_RAW))
        self.assertEqual(policy["max_latency_regression_percent"], 25.0)
        self.assertEqual(policy["max_throughput_regression_percent"], 25.0)
        report = QUAL.qualify(
            self.baseline_batches(), self.candidate_batches(), level=QUAL.SOURCE_LEVEL
        )
        self.assertEqual(report["policy"], policy)
        self.assertEqual(
            report["work_contract_sha256"],
            self.baseline_batches()[0].value["work_contract_sha256"],
        )

    def test_every_policy_tolerance_is_payload_immutable(self) -> None:
        mutations = {
            "minimum_repetitions": 1,
            "maximum_repetitions": QUAL.MAX_REPETITIONS + 1,
            "required_batches": 1,
            "max_self_drift_percent": 100.0,
            "max_latency_regression_percent": 100.0,
            "max_throughput_regression_percent": 100.0,
            "max_unknown_rate_increase": 1.0,
            "max_fairness_drop": 1.0,
            "max_sample_elapsed_ns": QUAL.MAX_SAMPLE_ELAPSED_NS + 1,
            "raw_samples_preserved": False,
            "outlier_deletion": True,
            "unknown_rate_source": "producer_reported",
            "l2_unknown_outcomes_allowed": True,
            "same_work_contract_required": False,
            "automatic_redispatch": True,
            "public_release": True,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                value = make_batch("A1")
                value["policy"][field] = replacement
                reseal(value)
                with self.assertRaisesRegex(QUAL.QualificationError, "policy differs"):
                    QUAL.validate_batch(value)

    def test_bounded_reader_rejects_fifo_socket_and_directory_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            regular = root / "regular.json"
            regular.write_bytes(b"{}")
            self.assertEqual(QUAL._read_bounded(regular, 2), b"{}")

            fifo = root / "input.fifo"
            os.mkfifo(fifo, 0o600)
            started = time.monotonic()
            with self.assertRaisesRegex(QUAL.QualificationError, "regular file"):
                QUAL._read_bounded(fifo, 1024)
            self.assertLess(time.monotonic() - started, 1.0)

            with self.assertRaises(QUAL.QualificationError):
                QUAL._read_bounded(root, 1024)

            socket_path = root / "input.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                server.bind(str(socket_path))
                started = time.monotonic()
                with self.assertRaises(QUAL.QualificationError):
                    QUAL._read_bounded(socket_path, 1024)
                self.assertLess(time.monotonic() - started, 1.0)
            finally:
                server.close()

    def test_work_contract_and_throughput_are_fail_closed_end_to_end(self) -> None:
        baseline = self.baseline_batches()
        candidate = self.candidate_batches()

        for batch in candidate:
            set_operations(batch.value, 2)
        with self.assertRaisesRegex(QUAL.QualificationError, "measured work/configuration"):
            QUAL.qualify(baseline, candidate, level=QUAL.SOURCE_LEVEL)
        for batch in candidate:
            set_operations(batch.value, 1)

        candidate[1].value["samples"][0]["operations"] = 2
        reseal(candidate[1].value)
        with self.assertRaisesRegex(QUAL.QualificationError, "work contract differs"):
            QUAL.qualify(baseline, candidate, level=QUAL.SOURCE_LEVEL)
        candidate[1].value["samples"][0]["operations"] = 1
        reseal(candidate[1].value)

        for batch in candidate:
            batch.value["workload_configurations"]["WL-01"] = "9" * 64
            reseal(batch.value)
        with self.assertRaisesRegex(QUAL.QualificationError, "measured work/configuration"):
            QUAL.qualify(baseline, candidate, level=QUAL.SOURCE_LEVEL)
        for batch in candidate:
            batch.value["workload_configurations"]["WL-01"] = QUAL.sha256(
                b"fixture-configuration:WL-01"
            )
            for sample in batch.value["samples"]:
                sample["elapsed_ns"] = sample["elapsed_ns"] * 3 // 2
            reseal(batch.value)

        report = QUAL.qualify(baseline, candidate, level=QUAL.SOURCE_LEVEL)
        metrics = {row["metric"] for row in report["comparison"]["regressions"]}
        self.assertIn("throughput_per_sec", metrics)

    def test_unknown_outcomes_reconcile_with_raw_samples_and_block_l2(self) -> None:
        contradictory = make_batch("A1", level=QUAL.SOURCE_LEVEL)
        set_unknown(contradictory, unknown=True, reported=0.0)
        with self.assertRaisesRegex(QUAL.QualificationError, "contradicts raw"):
            QUAL.validate_batch(contradictory)

        installed = make_batch("A1", level=QUAL.INSTALLED_LEVEL)
        set_unknown(installed, unknown=True, reported=1.0)
        with self.assertRaisesRegex(QUAL.QualificationError, "L2 sample has an unknown"):
            QUAL.validate_batch(installed, expected_level=QUAL.INSTALLED_LEVEL)

        baseline = self.baseline_batches()
        candidate = []
        for index, name in enumerate(QUAL.CANDIDATE_BATCH_IDS):
            value = make_batch(name, source_tag="b")
            set_unknown(value, unknown=True, reported=1.0)
            candidate.append(loaded(value, f"/C{index + 1}.json"))
        report = QUAL.qualify(baseline, candidate, level=QUAL.SOURCE_LEVEL)
        self.assertEqual(report["status"], "FAIL_REGRESSION")
        self.assertEqual(
            report["comparison"]["candidate_summary"]["WL-01/cold_start"]["unknown_rate_mean"],
            1.0,
        )

    def test_work_contract_claim_is_recomputed_from_raw_matrix(self) -> None:
        value = make_batch("A1")
        value["samples"][0]["operations"] = 2
        reseal(value, recompute_work_contract=False)
        with self.assertRaisesRegex(QUAL.QualificationError, "work contract digest mismatch"):
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

    def test_private_atomic_output_rejects_staging_byte_replacement(self) -> None:
        report = QUAL.qualify(self.baseline_batches(), self.candidate_batches(), level=QUAL.SOURCE_LEVEL)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "report.json"
            original_link = os.link

            def replace_staging(src, dst, **kwargs):
                parent_fd = kwargs["dst_dir_fd"]
                staging = next(name for name in os.listdir(parent_fd) if name.endswith(".tmp"))
                os.unlink(staging, dir_fd=parent_fd)
                attacker = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent_fd)
                try:
                    os.write(attacker, b"attacker\n")
                finally:
                    os.close(attacker)
                return original_link(src, dst, **kwargs)

            with mock.patch.object(QUAL.os, "link", side_effect=replace_staging):
                with self.assertRaisesRegex(QUAL.QualificationError, "staging pathname was replaced"):
                    QUAL._write_private_atomic(output, report)
            self.assertFalse(output.exists())
            self.assertTrue(any(path.name.endswith(".tmp") for path in root.iterdir()))

    def test_private_atomic_output_rejects_staging_symlink_replacement(self) -> None:
        report = QUAL.qualify(self.baseline_batches(), self.candidate_batches(), level=QUAL.SOURCE_LEVEL)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "report.json"
            attacker = root / "attacker"
            attacker.write_bytes(b"attacker\n")
            original_link = os.link

            def replace_staging(src, dst, **kwargs):
                parent_fd = kwargs["dst_dir_fd"]
                staging = next(name for name in os.listdir(parent_fd) if name.endswith(".tmp"))
                os.unlink(staging, dir_fd=parent_fd)
                os.symlink("attacker", staging, dir_fd=parent_fd)
                return original_link(src, dst, **kwargs)

            with mock.patch.object(QUAL.os, "link", side_effect=replace_staging):
                with self.assertRaisesRegex(QUAL.QualificationError, "staging pathname was replaced"):
                    QUAL._write_private_atomic(output, report)
            self.assertFalse(output.exists())
            self.assertEqual(attacker.read_bytes(), b"attacker\n")

    def test_private_atomic_output_rejects_parent_replacement(self) -> None:
        report = QUAL.qualify(self.baseline_batches(), self.candidate_batches(), level=QUAL.SOURCE_LEVEL)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "out"
            parent.mkdir(mode=0o700)
            moved = root / "out-original"
            output = parent / "report.json"
            original_link = os.link

            def replace_parent(src, dst, **kwargs):
                parent.rename(moved)
                parent.mkdir(mode=0o700)
                return original_link(src, dst, **kwargs)

            with mock.patch.object(QUAL.os, "link", side_effect=replace_parent):
                with self.assertRaisesRegex(QUAL.QualificationError, "output parent pathname changed"):
                    QUAL._write_private_atomic(output, report)
            self.assertFalse(output.exists())
            self.assertFalse((moved / "report.json").exists())

    def test_private_atomic_output_rejects_late_destination_collision(self) -> None:
        report = QUAL.qualify(self.baseline_batches(), self.candidate_batches(), level=QUAL.SOURCE_LEVEL)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "report.json"
            original_link = os.link

            def collide_destination(src, dst, **kwargs):
                parent_fd = kwargs["dst_dir_fd"]
                collision = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent_fd)
                os.close(collision)
                return original_link(src, dst, **kwargs)

            with mock.patch.object(QUAL.os, "link", side_effect=collide_destination):
                with self.assertRaises(FileExistsError):
                    QUAL._write_private_atomic(output, report)
            self.assertEqual(output.read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()