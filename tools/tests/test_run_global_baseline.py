#!/usr/bin/env python3
"""Contract tests for the bounded G1 baseline harness."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
