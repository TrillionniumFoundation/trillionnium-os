#!/usr/bin/env python3
"""Contract tests for the bounded G1 baseline harness."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "perf" / "run_global_baseline.py"
WORKLOADS = [f"WL-{index:02d}" for index in range(1, 13)]
MEASUREMENTS = {
    "throughput", "latency_p50", "latency_p95", "latency_p99", "latency_max",
    "queue_wait", "lock_wait", "lock_hold", "cpu", "rss", "fd_count",
    "thread_count", "process_count", "io_bytes", "fsync_count", "recovery_time",
    "unknown_rate", "redispatch_count", "fairness",
}

_SPEC = importlib.util.spec_from_file_location("run_global_baseline", SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(HARNESS)


class BaselineHarnessTests(unittest.TestCase):
    def test_generates_all_profiles_raw_rows_and_content_digest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tos-baseline-test-") as directory:
            output = Path(directory) / "baseline.json"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--output", str(output), "--repetitions", "1"],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("artifact_digest", result.stdout)
            artifact = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(artifact["schema"], "trillionnium.owner-open.global-baseline-artifact.v1")
            self.assertEqual(artifact["workload_profiles"], WORKLOADS)
            self.assertEqual(len(artifact["samples"]), 12)
            self.assertEqual(set(artifact["summaries"]), set(WORKLOADS))
            self.assertTrue(MEASUREMENTS <= set(artifact["required_measurements"]))
            self.assertEqual(artifact["qualification"], "SOURCE_EVIDENCE_ONLY")
            clone = dict(artifact)
            clone["artifact_digest"] = ""
            encoded = json.dumps(clone, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
            self.assertEqual(artifact["artifact_digest"], hashlib.sha256(encoded).hexdigest())

    def test_repetition_bound_is_enforced(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--output", "/tmp/should-not-be-written.json", "--repetitions", "0"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("between 1 and 1000", result.stderr)

    def test_summary_preserves_each_latency_percentile_series(self) -> None:
        rows = []
        for repetition, base in enumerate((10.0, 20.0, 30.0, 40.0)):
            row = HARNESS._sample("WL-01", repetition)
            row["latency_p50"] = base
            row["latency_p95"] = base + 100.0
            row["latency_p99"] = base + 200.0
            row["latency_max"] = base + 300.0
            rows.append(row)
        summary = HARNESS._summary("WL-01", rows)
        self.assertEqual(summary["latency_p50"], 20.0)
        self.assertEqual(summary["latency_p95"], 140.0)
        self.assertEqual(summary["latency_p99"], 240.0)

    def test_objective_rejects_non_objects_duplicate_workloads_and_u64_drift(self) -> None:
        summary = HARNESS._summary("WL-01", [HARNESS._sample("WL-01", 0)])
        with self.assertRaisesRegex(ValueError, "not an object"):
            HARNESS._objective([None])
        with self.assertRaisesRegex(ValueError, "duplicate workload"):
            HARNESS._objective([summary, dict(summary)])
        for field in ("rss", "io_bytes"):
            with self.subTest(field=field):
                malformed = dict(summary)
                malformed[field] = HARNESS.MAX_U64 + 1
                with self.assertRaisesRegex(ValueError, "must be an integer"):
                    HARNESS._objective([malformed])
                malformed[field] = 1.5
                with self.assertRaisesRegex(ValueError, "must be an integer"):
                    HARNESS._objective([malformed])

    def test_strict_json_boundary_rejects_nonfinite_and_duplicate_members(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-finite"):
            HARNESS._strict_json_loads('{"value": NaN}')
        with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
            HARNESS._strict_json_loads('{"value": 1, "value": 2}')
        with self.assertRaisesRegex(ValueError, "64-bit bound"):
            HARNESS._strict_json_loads('{"value": 18446744073709551616}')

    def test_atomic_writer_rejects_nonfinite_and_syncs_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tos-baseline-write-test-") as directory:
            output = Path(directory) / "artifact.json"
            output.write_text("original\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                HARNESS._write_atomic(output, {"value": float("nan")})
            self.assertEqual(output.read_text(encoding="utf-8"), "original\n")

            with mock.patch.object(HARNESS.os, "fsync", wraps=HARNESS.os.fsync) as fsync:
                HARNESS._write_atomic(output, {"value": 1})
            self.assertEqual(fsync.call_count, 2)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), {"value": 1})

            target = Path(directory) / "target.json"
            target.write_text("target\n", encoding="utf-8")
            link = Path(directory) / "link.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "must not be a symlink"):
                HARNESS._write_atomic(link, {"value": 2})
            self.assertEqual(target.read_text(encoding="utf-8"), "target\n")

    def test_previous_artifact_is_structurally_validated_before_score_use(self) -> None:
        artifact = HARNESS.build_artifact(1, None)
        with tempfile.TemporaryDirectory(prefix="tos-baseline-previous-test-") as directory:
            path = Path(directory) / "previous.json"

            def write(value: dict) -> None:
                path.write_text(
                    json.dumps(value, sort_keys=True, allow_nan=False), encoding="utf-8"
                )

            write(artifact)
            self.assertTrue(math.isfinite(HARNESS._load_previous(path)))
            for field, replacement in (
                ("samples", []),
                ("workload_profiles", []),
                ("repetitions", 0),
            ):
                malformed = deepcopy(artifact)
                malformed[field] = replacement
                malformed["artifact_digest"] = HARNESS._canonical_digest(malformed)
                write(malformed)
                with self.subTest(field=field):
                    with self.assertRaisesRegex(ValueError, "previous artifact"):
                        HARNESS._load_previous(path)

    def test_objective_delta_overflow_fails_closed(self) -> None:
        sample = HARNESS._sample("WL-01", 0)
        summary = HARNESS._summary("WL-01", [sample])
        objective = {
            "useful_work": 0.0,
            "latency_penalty": 0.0,
            "unknown_penalty": 0.0,
            "resource_penalty": 0.0,
            "fairness_penalty": 0.0,
            "recovery_penalty": 0.0,
            "score": float("1.7976931348623157e308"),
        }
        with mock.patch.object(HARNESS, "_sample", return_value=sample), mock.patch.object(
            HARNESS, "_summary", return_value=summary
        ), mock.patch.object(HARNESS, "_objective", return_value=objective), mock.patch.object(
            HARNESS,
            "_load_previous",
            return_value=-float("1.7976931348623157e308"),
        ), mock.patch.object(HARNESS, "_environment", return_value={}), mock.patch.object(
            HARNESS, "_canonical_digest", return_value="0" * 64
        ):
            with self.assertRaisesRegex(ValueError, "objective delta"):
                HARNESS.build_artifact(1, Path("previous.json"))


if __name__ == "__main__":
    unittest.main()
