"""Host-benchmark contract tests; real selected products run when explicitly supplied.

TRILLIONNIUM_PERF_HOST / TRILLIONNIUM_PERF_CORE enable the integration test.
The CLI itself always requires real binaries and cannot substitute fixtures.
"""
from __future__ import annotations

import contextlib
import copy
import io
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[1] / "perf/run_product_baseline.py"
SPEC = importlib.util.spec_from_file_location("product_baseline", PATH)
BENCH = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(BENCH)


def reseal(value: dict) -> dict:
    value.pop("artifact_digest", None)
    value["artifact_digest"] = BENCH.digest(BENCH.canonical(value))
    return value


def artifact(latencies: list[int] | None = None) -> dict:
    latencies = latencies or [10, 11, 12, 13, 14]
    samples = [{"workload": "short_turn", "repetition": i, "warmup": False,
                "elapsed_ns": n * 1_000_000, "operations": 1, "correctness_validated": True}
               for i, n in enumerate(latencies)]
    manifest = BENCH.implementation_manifest()
    policy = BENCH.gate_policy()
    return reseal({"schema": BENCH.SCHEMA, "qualification": "L1_HOST_SOURCE_BENCHMARK_ONLY",
        "public_release": False, "samples": samples, "summaries": BENCH.summarize(samples),
        "implementation_manifest": manifest, "gate_policy": policy,
        "configuration": {"workloads": ["short_turn"], "repetitions": len(samples), "warmup": 0,
                          "max_regression_percent": policy["max_regression_percent"],
                          "gate_policy_version": policy["version"]},
        "comparison_identity": {"controlled_environment": "fixture",
                                "implementation_manifest_sha256": manifest["manifest_sha256"],
                                "gate_policy_sha256": BENCH.digest(BENCH.canonical(policy))},
        "failures": []})


class ProductBaselineContractTests(unittest.TestCase):
    def test_warmup_excluded_and_raw_percentiles_recomputed(self) -> None:
        value = artifact()
        value["samples"].append({"workload": "short_turn", "repetition": 0, "warmup": True,
            "elapsed_ns": 999_000_000, "operations": 1, "correctness_validated": True})
        self.assertEqual(BENCH.summarize(value["samples"]), value["summaries"])
        self.assertEqual(value["summaries"]["short_turn"]["latency_p50_ms"], 12)
        self.assertEqual(value["summaries"]["short_turn"]["latency_p95_ms"], 14)

    def test_regression_and_improvement_have_explicit_decisions(self) -> None:
        previous = BENCH.validate_artifact(artifact())
        self.assertEqual(BENCH.regression_gate(artifact([20, 21, 22, 23, 24]), previous, 25)["status"], "FAIL_REGRESSION")
        self.assertTrue(BENCH.regression_gate(artifact([8, 9, 10, 11, 12]), previous, 25)["passed"])

    def test_baseline_and_small_sample_never_claim_comparison_pass(self) -> None:
        self.assertFalse(BENCH.regression_gate(artifact(), None, 25)["passed"])
        gate = BENCH.regression_gate(artifact([10]), artifact([10]), 25)
        self.assertEqual(gate["status"], "INSUFFICIENT_REPETITIONS")
        self.assertFalse(gate["passed"])

    def test_changed_environment_or_parameters_rejected(self) -> None:
        current = artifact()
        current["comparison_identity"]["controlled_environment"] = "different"
        with self.assertRaisesRegex(BENCH.BenchmarkError, "incompatible"):
            BENCH.regression_gate(current, artifact(), 25)

    def test_implementation_manifest_is_closed_and_changes_break_compatibility(self) -> None:
        manifest = BENCH.implementation_manifest()
        self.assertEqual([item["path"] for item in manifest["files"]],
                         list(BENCH.IMPLEMENTATION_PATHS))
        with tempfile.TemporaryDirectory() as directory:
            copied_root = Path(directory)
            for relative in BENCH.IMPLEMENTATION_PATHS:
                source = BENCH.CORE.ROOT / relative
                destination = copied_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            with mock.patch.object(BENCH.CORE, "ROOT", copied_root):
                before = BENCH.implementation_manifest()
                target = copied_root / BENCH.IMPLEMENTATION_PATHS[0]
                target.write_bytes(target.read_bytes() + b"\n# identity mutation\n")
                after = BENCH.implementation_manifest()
        self.assertNotEqual(before["manifest_sha256"], after["manifest_sha256"])

        previous = artifact()
        current = artifact()
        current_manifest = copy.deepcopy(current["implementation_manifest"])
        current_manifest["files"][0]["sha256"] = "b" * 64
        body = {"schema": current_manifest["schema"], "files": current_manifest["files"]}
        current_manifest["manifest_sha256"] = BENCH.digest(BENCH.canonical(body))
        current["implementation_manifest"] = current_manifest
        current["comparison_identity"]["implementation_manifest_sha256"] = current_manifest["manifest_sha256"]
        current = reseal(current)
        BENCH.validate_artifact(current)
        with self.assertRaisesRegex(BENCH.BenchmarkError, "incompatible"):
            BENCH.regression_gate(current, previous)

    def test_threshold_is_reviewed_policy_not_caller_mutable(self) -> None:
        previous = BENCH.validate_artifact(artifact())
        current = artifact([20, 21, 22, 23, 24])
        with self.assertRaisesRegex(BENCH.BenchmarkError, "caller threshold"):
            BENCH.regression_gate(current, previous, BENCH.MAX_REGRESSION_PERCENT + 1)
        self.assertEqual(BENCH.regression_gate(current, previous)["threshold_percent"],
                         BENCH.MAX_REGRESSION_PERCENT)

    def test_modified_digest_or_summary_rejected(self) -> None:
        current = artifact()
        current["samples"][0]["elapsed_ns"] += 1
        with self.assertRaisesRegex(BENCH.BenchmarkError, "digest"):
            BENCH.validate_artifact(current)
        current = artifact()
        current["summaries"]["short_turn"]["latency_p50_ms"] = 1
        with self.assertRaisesRegex(BENCH.BenchmarkError, "summary"):
            BENCH.validate_artifact(reseal(current))

    def test_duplicate_missing_nonfinite_unvalidated_or_widened_inputs_rejected(self) -> None:
        changes = [lambda a: a["samples"].append(copy.deepcopy(a["samples"][0])),
                   lambda a: a["samples"].pop(),
                   lambda a: a["samples"][0].update(elapsed_ns=True),
                   lambda a: a["samples"][0].update(correctness_validated=False),
                   lambda a: a.update(public_release=True),
                   lambda a: a.update(failures=[{"error": "failed"}])]
        for change in changes:
            with self.subTest(change=change):
                value = artifact()
                change(value)
                with self.assertRaises(BENCH.BenchmarkError):
                    BENCH.validate_artifact(reseal(value))
        for invalid in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', '{"a":1e999}'):
            with self.assertRaises(BENCH.BenchmarkError):
                BENCH.strict_json(invalid)

    def test_failures_override_performance_and_unavailable_is_not_zero(self) -> None:
        value = artifact()
        value["failures"].append({"error": "tool bytes differ"})
        self.assertEqual(BENCH.regression_gate(value, artifact(), 25)["status"], "FAIL_CORRECTNESS")
        for metric in BENCH.UNAVAILABLE.values():
            self.assertIsNone(metric["value"])
            self.assertEqual(metric["status"], "unavailable")

    def test_product_validation_rejects_no_durability_and_wrong_effect(self) -> None:
        frames = [{"kind": "hello.ack", "payload": {"durable_event_store": False}}]
        with self.assertRaisesRegex(BENCH.BenchmarkError, "durable"):
            BENCH.validate_turn(frames, b"x")
        frames[0]["payload"]["durable_event_store"] = True
        frames += [{"kind": "turn.end", "payload": {"status": "completed", "event_log_status": "durable"}},
                   {"kind": "tool.result", "payload": {"terminal_kind": "exited", "exit_code": 0}},
                   {"kind": "tool.stdout", "payload": {"data": "eQ=="}}]
        with self.assertRaisesRegex(BENCH.BenchmarkError, "exact bytes"):
            BENCH.validate_turn(frames, b"x")

    def test_cli_rejects_nonfinite_and_unbounded_work(self) -> None:
        common = ["--host", "/host", "--core", "/core", "--output", "/output"]
        for args in (["--repetitions", "0"], ["--concurrency", "17"],
                     ["--slow-read-ms", "nan"], ["--timeout-seconds", "inf"],
                     ["--max-regression-percent", "26"],
                     ["--workloads", "short_turn", "short_turn"]):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                BENCH.parse_args(common + args)

    def test_output_collision_rejected_before_running(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output.json"
            output.write_text("keep")
            with contextlib.redirect_stderr(io.StringIO()):
                result = BENCH.main(["--host", "/missing", "--core", "/missing", "--output", str(output)])
            self.assertEqual(result, 2)
            self.assertEqual(output.read_text(), "keep")


@unittest.skipUnless(os.environ.get("TRILLIONNIUM_PERF_HOST") and os.environ.get("TRILLIONNIUM_PERF_CORE"),
                     "set TRILLIONNIUM_PERF_HOST and TRILLIONNIUM_PERF_CORE for real-binary integration")
class RealProductBaselineTests(unittest.TestCase):
    def test_real_selected_products_all_workloads(self) -> None:
        host = Path(os.environ["TRILLIONNIUM_PERF_HOST"]).resolve(strict=True)
        core = Path(os.environ["TRILLIONNIUM_PERF_CORE"]).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="perf-integration-") as directory:
            root = Path(directory)
            for name, size, slow, replay in (("short", 16, 0, False), ("large", 65536, 0, False),
                                            ("slow", 65536, 1, False), ("replay", 16, 0, True)):
                with self.subTest(workload=name):
                    result = BENCH.run_turn_sample(host, core, root / name, size, 15, slow, replay)
                    self.assertGreater(result["elapsed_ns"], 0)
                    self.assertEqual(result["validation"]["event_log_status"], "durable")
            for mode in ("pipe", "pty"):
                with self.subTest(workload=mode):
                    result = BENCH.run_job_sample(host, core, root / mode, mode, 15)
                    self.assertEqual(result["validation"]["terminal"], "exited")
            result = BENCH.run_broker_sample(host, core, root / "broker", 2, 15)
            self.assertEqual(result["validation"]["expected_missing_job_responses"], 2)
            with BENCH.ThreadPoolExecutor(max_workers=2) as executor:
                rows = list(executor.map(lambda i: BENCH.run_turn_sample(host, core, root / f"parallel-{i}", 16, 15), range(2)))
            self.assertEqual(len(rows), 2)


if __name__ == "__main__":
    unittest.main()
