"""Host-benchmark contract tests; real selected products run when explicitly supplied.

TRILLIONNIUM_PERF_HOST / TRILLIONNIUM_PERF_CORE enable the integration test.
The CLI itself always requires real binaries and cannot substitute fixtures.
"""
from __future__ import annotations

import ast
import contextlib
import copy
import fcntl
import io
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from tools.tests.authenticated_python_bootstrap_fixture import (
    BOOTSTRAP_LOGICAL_PATH,
    load_authenticated_module,
    run_authenticated,
)

PATH = Path(__file__).resolve().parents[1] / "perf/run_product_baseline.py"
LOGICAL_PATH = "tools/perf/run_product_baseline.py"
BENCH = load_authenticated_module("product_baseline", PATH, LOGICAL_PATH)


def reseal(value: dict) -> dict:
    value.pop("artifact_digest", None)
    value["artifact_digest"] = BENCH.digest(BENCH.canonical(value))
    return value


def storage_fixture() -> dict:
    # Test-only observation bytes; never a real storage/runner qualification.
    return {"schema": BENCH.STORAGE_IDENTITY_SCHEMA, "scope": BENCH.STORAGE_IDENTITY_SCOPE,
            "status": "known", "boot_id_sha256": "a" * 64,
            "mount_namespace": {"device": 4, "inode": 123}, "mount_id": 17,
            "device": {"major": 8, "minor": 1}, "filesystem_type": "ext4",
            "filesystem": {"type_magic": 0xef53, "fsid": [1, 2], "block_size": 4096, "flags": 0},
            "mountinfo_record_sha256": "b" * 64}


def artifact(latencies: list[int] | None = None) -> dict:
    latencies = latencies or [10, 11, 12, 13, 14]
    samples = [{"workload": "short_turn", "repetition": i, "warmup": False,
                "elapsed_ns": n * 1_000_000, "operations": 1, "correctness_validated": True}
               for i, n in enumerate(latencies)]
    manifest = BENCH.implementation_manifest()
    bootstrap = BENCH.bootstrap_attestation()
    policy = BENCH.gate_policy()
    environment = {"controlled_environment": "fixture",
                   "execution_custody": BENCH.EXECUTION_CUSTODY,
                   "scratch_filesystem": "ext4",
                   "scratch_storage_identity": storage_fixture()}
    configuration = {"workloads": ["short_turn"], "repetitions": len(samples), "warmup": 0,
                     "max_regression_percent": policy["max_regression_percent"],
                     "gate_policy_version": policy["version"], "build_profile": "custom",
                     "concurrency": 4, "output_bytes": 65536, "slow_read_ms": 1.0, "timeout_seconds": 15.0}
    executables = {name: {"path": f"/test-only/{name}", "requested_path": f"/test-only/{name}",
                          "size": 1, "sha256": str(index) * 64,
                          "execution_custody": BENCH.PINNED_EXECUTABLE_CUSTODY}
                   for index, name in enumerate(("host", "core", "python", "shell"), 1)}
    executables["harness"] = next(dict(item) for item in manifest["files"]
                                  if item["path"] == LOGICAL_PATH)
    return reseal({"schema": BENCH.SCHEMA, "qualification": "L1_HOST_SOURCE_BENCHMARK_ONLY",
        "public_release": False, "samples": samples, "summaries": BENCH.summarize(samples),
        "implementation_manifest": manifest, "bootstrap_attestation": bootstrap,
        "environment": environment,
        "gate_policy": policy,
        "configuration": configuration, "executables": executables,
        "comparison_identity": {"configuration": {key: value for key, value in configuration.items()
                                                    if key not in {"repetitions", "warmup"}},
                                "environment": copy.deepcopy(environment),
                                "python_sha256": executables["python"]["sha256"],
                                "shell_sha256": executables["shell"]["sha256"],
                                "harness_sha256": executables["harness"]["sha256"],
                                "execution_custody": BENCH.EXECUTION_CUSTODY,
                                "implementation_manifest_sha256": manifest["manifest_sha256"],
                                "bootstrap_attestation_sha256": BENCH.digest(BENCH.canonical(bootstrap)),
                                "gate_policy_sha256": BENCH.digest(BENCH.canonical(policy))},
        "failures": []})


class ProductBaselineContractTests(unittest.TestCase):
    def test_real_same_mount_directories_have_equal_storage_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "one", root / "two"
            first.mkdir(); second.mkdir()
            a, b = BENCH.scratch_storage_identity(first), BENCH.scratch_storage_identity(second)
            self.assertEqual(a["status"], "known", a)
            self.assertEqual(a, b)
            self.assertNotIn(str(root), json.dumps(a))
            value = artifact()
            value["environment"]["scratch_storage_identity"] = a
            value["environment"]["scratch_filesystem"] = a["filesystem_type"]
            value["comparison_identity"]["environment"] = copy.deepcopy(value["environment"])
            BENCH.validate_artifact(reseal(value))

    def test_storage_mount_selection_uses_fd_id_and_complete_record(self) -> None:
        outer = b"17 1 8:1 / /data rw - ext4 /dev/vda rw\n"
        inner = b"18 17 8:1 /sub /data/covered ro - ext4 /dev/vda ro\n"
        actual = BENCH._storage_mount_record(outer + inner, 17, os.makedev(8, 1))
        self.assertEqual(actual["mountinfo_record_sha256"], BENCH.digest(outer.rstrip()))
        self.assertNotEqual(actual, BENCH._storage_mount_record(outer + inner, 18, os.makedev(8, 1)))
        overlay = b"19 1 0:42 / /data rw - overlay overlay rw,lowerdir=/lower-one,upperdir=/upper,workdir=/work\n"
        changed = overlay.replace(b"/lower-one", b"/lower-two")
        self.assertNotEqual(BENCH._storage_mount_record(overlay, 19, os.makedev(0, 42)),
                            BENCH._storage_mount_record(changed, 19, os.makedev(0, 42)))
        private_source = outer.replace(b"/dev/vda", b"server:fake-secret")
        self.assertNotIn("fake-secret", repr(BENCH._storage_mount_record(private_source, 17, os.makedev(8, 1))))
        for raw, selected, device in ((outer + outer, 17, os.makedev(8, 1)),
                                       (outer, 18, os.makedev(8, 1)),
                                       (outer, 17, os.makedev(8, 2)),
                                       (outer.replace(b"17 1", b"17 garbage"), 17, os.makedev(8, 1)),
                                       (outer.replace(b"8:1 / /data", b"8:1 relative /data"), 17, os.makedev(8, 1)),
                                       (outer.replace(b"/data", b"/bad\\077path"), 17, os.makedev(8, 1)),
                                       (outer.replace(b" rw -", b"  -"), 17, os.makedev(8, 1)),
                                       (b"17 1 8:1 incomplete\n", 17, os.makedev(8, 1))):
            with self.subTest(raw=raw), self.assertRaises(BENCH.BenchmarkError):
                BENCH._storage_mount_record(raw, selected, device)
        for raw in (b"mnt_id: 17\nmnt_id: 18\n", b"mnt_id: true\n", b"pos: 0\n"):
            with self.subTest(raw=raw), self.assertRaises(BENCH.BenchmarkError):
                BENCH._storage_mount_id(raw)

    def test_unsupported_statfs_abi_never_calls_native_function(self) -> None:
        with mock.patch.object(BENCH.CORE.platform, "machine", return_value="unknown"), \
             mock.patch.object(BENCH.CORE.ctypes, "CDLL") as library:
            with self.assertRaisesRegex(BENCH.BenchmarkError, "ABI"):
                BENCH._storage_statfs(0)
            library.assert_not_called()

    def test_unavailable_storage_can_be_recorded_but_cannot_compare(self) -> None:
        value = artifact()
        unknown = {"schema": BENCH.STORAGE_IDENTITY_SCHEMA, "scope": BENCH.STORAGE_IDENTITY_SCOPE,
                   "status": "unavailable", "reason": "storage_probe_unavailable"}
        value["environment"]["scratch_storage_identity"] = unknown
        value["environment"]["scratch_filesystem"] = "unavailable"
        value["comparison_identity"]["environment"] = copy.deepcopy(value["environment"])
        value = reseal(value)
        BENCH.validate_artifact(value)
        self.assertFalse(BENCH.regression_gate(value, None)["passed"])
        with self.assertRaisesRegex(BENCH.BenchmarkError, "unavailable"):
            BENCH.regression_gate(value, copy.deepcopy(value))
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(BENCH.CORE, "_read_storage_proc", side_effect=OSError("private detail")):
            captured = BENCH.scratch_storage_identity(Path(directory))
        self.assertEqual(captured, unknown)

    def test_changed_storage_same_type_and_mount_context_cannot_compare(self) -> None:
        for field, replacement in (("device", {"major": 259, "minor": 2}),
                                    ("mount_id", 18), ("boot_id_sha256", "c" * 64),
                                    ("mount_namespace", {"device": 4, "inode": 124}),
                                    ("mountinfo_record_sha256", "d" * 64),
                                    ("filesystem", {"type_magic": 0xef53, "fsid": [3, 4], "block_size": 4096, "flags": 0})):
            with self.subTest(field=field):
                current = artifact()
                current["environment"]["scratch_storage_identity"][field] = replacement
                current["comparison_identity"]["environment"] = copy.deepcopy(current["environment"])
                current = reseal(current)
                BENCH.validate_artifact(current)
                with self.assertRaisesRegex(BENCH.BenchmarkError, "incompatible"):
                    BENCH.regression_gate(current, artifact())

    def test_storage_projection_and_closed_metadata_reject_resealed_tampering(self) -> None:
        for mutation in ("top", "comparison", "missing", "boolean", "zero_fsid", "extra"):
            with self.subTest(mutation=mutation):
                value = artifact()
                selected = value["environment"]["scratch_storage_identity"]
                if mutation == "top": selected["device"]["minor"] = 2
                elif mutation == "comparison": value["comparison_identity"]["environment"]["scratch_storage_identity"]["mount_id"] = 18
                elif mutation == "missing": value["environment"].pop("scratch_storage_identity")
                else:
                    if mutation == "boolean": selected["mount_id"] = True
                    elif mutation == "zero_fsid": selected["filesystem"]["fsid"] = [0, 0]
                    else: selected["unexpected"] = "field"
                    value["comparison_identity"]["environment"] = copy.deepcopy(value["environment"])
                with self.assertRaisesRegex(BENCH.BenchmarkError, "storage"):
                    BENCH.validate_artifact(reseal(value))

    def test_full_comparison_projection_rejects_resealed_metadata_changes(self) -> None:
        for field in ("output_bytes", "concurrency", "timeout_seconds", "build_profile",
                      "python", "shell", "harness", "comparison_only", "custody"):
            with self.subTest(field=field):
                value = artifact()
                if field in {"python", "shell", "harness"}:
                    value["executables"][field]["sha256"] = "0" * 64
                elif field == "comparison_only":
                    value["comparison_identity"]["configuration"]["concurrency"] = 2
                elif field == "custody":
                    value["environment"]["execution_custody"] = "unadmitted"
                    value["comparison_identity"]["environment"] = copy.deepcopy(value["environment"])
                    value["comparison_identity"]["execution_custody"] = "unadmitted"
                else:
                    value["configuration"][field] = {
                        "output_bytes": 131072, "concurrency": 2,
                        "timeout_seconds": 1.0, "build_profile": "debug",
                    }[field]
                with self.assertRaisesRegex(BENCH.BenchmarkError, "comparison"):
                    BENCH.validate_artifact(reseal(value))

    def test_sampling_counts_may_differ_and_selected_products_may_change(self) -> None:
        previous = artifact([10, 11, 12, 13, 14])
        current = artifact([8, 9, 10, 11, 12, 13])
        current["configuration"]["warmup"] = 1
        current["samples"].append({"workload": "short_turn", "repetition": 0, "warmup": True,
                                   "elapsed_ns": 1000, "operations": 1, "correctness_validated": True})
        current["executables"]["host"]["sha256"] = "8" * 64
        current["executables"]["core"]["sha256"] = "9" * 64
        current = reseal(current)
        BENCH.validate_artifact(current)
        self.assertTrue(BENCH.regression_gate(current, previous)["passed"])

    def test_direct_comparison_rejects_invalid_sampling_metadata(self) -> None:
        for field, replacement in (("workloads", ["short_turn", "short_turn"]),
                                    ("workloads", ["missing_workload"]),
                                    ("repetitions", True), ("repetitions", 0),
                                    ("warmup", False), ("warmup", 11)):
            with self.subTest(field=field, replacement=replacement):
                value = artifact()
                value["configuration"][field] = replacement
                with self.assertRaisesRegex(BENCH.BenchmarkError, "sampling"):
                    BENCH.regression_gate(value, artifact())

    def test_broker_manifest_covers_actual_transitive_sibling_imports(self) -> None:
        modules = {Path(path).stem: path for path in BENCH.BROKER_SOURCE_PATHS}
        pending = ["owner_open_connection_broker"]
        reached = set()
        while pending:
            name = pending.pop()
            if name in reached:
                continue
            self.assertIn(name, modules, f"unadmitted broker sibling import: {name}")
            reached.add(name)
            source = BENCH.PINNED_IMPLEMENTATION_SOURCES[modules[name]]
            for node in ast.walk(ast.parse(source)):
                imports = []
                if isinstance(node, ast.Import):
                    imports = [item.name.split(".")[0] for item in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports = [node.module.split(".")[0]]
                pending.extend(item for item in imports if item.startswith("owner_open_"))
        self.assertEqual(reached, set(modules))
        self.assertTrue(set(BENCH.BROKER_SOURCE_PATHS).issubset(BENCH.IMPLEMENTATION_PATHS))

    def test_private_broker_closure_starts_without_repository_import_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            entrypoint = BENCH._write_broker_custody(Path(directory))
            result = subprocess.run(
                [sys.executable, str(entrypoint), "--help"],
                cwd=directory, env=BENCH.finite_env(),
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("--max-inflight-requests", result.stdout)
            BENCH._assert_broker_custody(entrypoint.parent)

    def test_private_broker_executes_all_admitted_siblings_after_source_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / "source"
            for relative in BENCH.BROKER_SOURCE_PATHS:
                path = selected / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(BENCH.PINNED_IMPLEMENTATION_SOURCES[relative])
            with mock.patch.object(BENCH, "REPOSITORY_ROOT", selected):
                captured = BENCH._snapshot_broker_sources()
            # Source modules move after descriptor admission. Execution must
            # use the captured closure, including imports below the wrapper.
            for relative in BENCH.BROKER_SOURCE_PATHS:
                (selected / relative).write_text("raise RuntimeError('changed source executed')\n")
            sources = dict(BENCH.PINNED_IMPLEMENTATION_SOURCES)
            identities = dict(BENCH.PINNED_IMPLEMENTATION_FILES)
            for relative, (source, identity) in captured.items():
                sources[relative] = source
                identities[relative] = identity
            with mock.patch.object(BENCH.CORE, "PINNED_IMPLEMENTATION_SOURCES", sources), \
                 mock.patch.object(BENCH.CORE, "PINNED_IMPLEMENTATION_FILES", identities):
                entrypoint = BENCH._write_broker_custody(root)
                result = subprocess.run(
                    [sys.executable, str(entrypoint), "--help"],
                    cwd=directory, env=BENCH.finite_env(),
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                BENCH._assert_broker_custody(entrypoint.parent)

    def test_missing_or_tampered_private_broker_source_refuses_before_spawn(self) -> None:
        for mutation in ("missing", "tampered", "extra", "symlink", "hardlink", "public_parent"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                entrypoint = BENCH._write_broker_custody(root)
                source = entrypoint.parent / "owner_open_broker_common.py"
                if mutation == "missing":
                    source.unlink()
                elif mutation == "tampered":
                    source.chmod(0o600)
                    source.write_text("raise RuntimeError('unadmitted source executed')\n")
                    source.chmod(0o400)
                elif mutation == "extra":
                    (entrypoint.parent / "owner_open_unadmitted.py").write_text("VALUE = 1\n")
                elif mutation == "symlink":
                    source.unlink()
                    source.symlink_to(BENCH.CORE.ROOT / "tools/owner-open/owner_open_broker_common.py")
                elif mutation == "hardlink":
                    os.link(source, root / "outside-custody.py")
                else:
                    entrypoint.parent.chmod(0o777)
                with mock.patch.object(BENCH.CORE, "EXECUTION_PATHS", {"broker": str(entrypoint)}), \
                     mock.patch.object(BENCH.CORE.subprocess, "Popen") as spawn:
                    with self.assertRaises((BENCH.BenchmarkError, OSError)):
                        BENCH.run_broker_sample(Path(sys.executable), Path(sys.executable),
                                               root / "sample", 2, 2)
                    spawn.assert_not_called()

    def test_incomplete_broker_snapshot_refuses_custody_publication(self) -> None:
        for field in ("PINNED_IMPLEMENTATION_SOURCES", "PINNED_IMPLEMENTATION_FILES"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                incomplete = dict(getattr(BENCH.CORE, field))
                incomplete.pop("tools/owner-open/owner_open_broker_mux.py")
                with mock.patch.object(BENCH.CORE, field, incomplete):
                    with self.assertRaisesRegex(BENCH.BenchmarkError, "snapshot is incomplete"):
                        BENCH._write_broker_custody(Path(directory))
                self.assertEqual(list(Path(directory).iterdir()), [])

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
        current["environment"]["controlled_environment"] = "different"
        current["comparison_identity"]["environment"] = copy.deepcopy(current["environment"])
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
            with mock.patch.object(BENCH.CORE, "ROOT", copied_root), \
                 mock.patch.object(BENCH.CORE, "PINNED_IMPLEMENTATION_FILES", None):
                before = BENCH.live_implementation_manifest()
                target = copied_root / BENCH.IMPLEMENTATION_PATHS[0]
                target.write_bytes(target.read_bytes() + b"\n# identity mutation\n")
                after = BENCH.live_implementation_manifest()
        self.assertNotEqual(before["manifest_sha256"], after["manifest_sha256"])

        previous = artifact()
        current = artifact()
        current_manifest = copy.deepcopy(current["implementation_manifest"])
        current_manifest["files"][2]["sha256"] = "b" * 64
        body = {"schema": current_manifest["schema"], "files": current_manifest["files"]}
        current_manifest["manifest_sha256"] = BENCH.digest(BENCH.canonical(body))
        current["implementation_manifest"] = current_manifest
        current["comparison_identity"]["implementation_manifest_sha256"] = current_manifest["manifest_sha256"]
        current = reseal(current)
        BENCH.validate_artifact(current)
        with self.assertRaisesRegex(BENCH.BenchmarkError, "incompatible"):
            BENCH.regression_gate(current, previous)

    def test_snapshot_loader_executes_the_admitted_bytes_after_path_swap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module_path = root / "module.py"
            safe = b"VALUE = 'safe'\n"
            module_path.write_bytes(safe)

            def swap(path: Path) -> None:
                path.write_text("raise RuntimeError('hostile path bytes executed')\n")

            with mock.patch.object(BENCH, "REPOSITORY_ROOT", root):
                module, loaded, identity = BENCH._load_snapshot(
                    "product_baseline_snapshot_test",
                    module_path,
                    "module.py",
                    before_exec=swap,
                )
            self.assertEqual(loaded, safe)
            self.assertEqual(module.VALUE, "safe")
            self.assertEqual(identity["sha256"], BENCH.digest(safe))
            sys.modules.pop("product_baseline_snapshot_test", None)

    def test_private_executable_copy_runs_pinned_bytes_after_source_swap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "python-source"
            custody = root / "custody"
            custody.mkdir(mode=0o700)
            shutil.copyfile(sys.executable, source)
            source.chmod(0o700)
            pin = BENCH.PinnedExecutable(source, custody, "python")
            source.write_bytes(b"#!/bin/sh\nexit 97\n")
            source.chmod(0o700)
            result = subprocess.run(
                [str(pin.execution_path), "-I", "-c", "print('pinned-safe')"],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.stdout.strip(), "pinned-safe")
            pin.assert_execution_copy()
            with self.assertRaisesRegex(BENCH.BenchmarkError, "selected executable"):
                pin.assert_source_selection()

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


    def test_direct_performance_launcher_is_non_authorizing(self) -> None:
        result = subprocess.run(
            [sys.executable, str(PATH), "--help"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("direct pathname execution is non-authorizing", result.stderr)

    def test_authenticated_performance_bootstrap_runs_help(self) -> None:
        result = run_authenticated(PATH, LOGICAL_PATH, ["--help"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage:", result.stdout.lower())
        manifest = BENCH.implementation_manifest()
        bootstrap = manifest["files"][0]
        self.assertEqual(bootstrap["path"], BOOTSTRAP_LOGICAL_PATH)
        self.assertEqual(bootstrap, BENCH.PINNED_IMPLEMENTATION_FILES[BOOTSTRAP_LOGICAL_PATH])

    def test_preinterpreter_performance_swap_restore_cannot_emit_admitted_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = root / "run_product_baseline.py"
            backup = root / "run_product_baseline.reviewed"
            marker = root / "hostile-ran"
            shutil.copyfile(PATH, backup)
            launcher.write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('ran')\n"
                "raise SystemExit(0)\n",
                encoding="utf-8",
            )
            result = run_authenticated(
                launcher,
                LOGICAL_PATH,
                ["--help"],
                restore_backup=backup,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unadmitted launcher bytes", result.stderr)
            self.assertFalse(marker.exists())
            self.assertEqual(launcher.read_bytes(), PATH.read_bytes())

    def test_minimal_launcher_rejects_swap_restore_before_facade_admission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            facade = root / "facade.py"
            backup = root / "facade.reviewed"
            marker = root / "hostile-ran"
            reviewed = b"VALUE = 'reviewed'\n"
            facade.write_bytes(reviewed)
            hostile = (
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('ran')\n"
            ).encode()
            swapped = False

            def before(_absolute: Path, _component: str, final: bool) -> None:
                nonlocal swapped
                if final and not swapped:
                    facade.rename(backup)
                    facade.write_bytes(hostile)
                    swapped = True

            def restore(_absolute: Path, _descriptor: int) -> None:
                facade.unlink()
                backup.rename(facade)

            with self.assertRaisesRegex(RuntimeError, "unadmitted facade bytes"):
                getattr(BENCH, "__launcher_authenticate_facade")(
                    facade,
                    expected_sha256=BENCH.digest(reviewed),
                    before_component=before,
                    after_final=restore,
                )
            self.assertFalse(marker.exists())
            self.assertEqual(facade.read_bytes(), reviewed)

    def test_descriptor_walk_rejects_parent_symlink_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / "selected"
            backup = root / "selected-reviewed"
            attacker = root / "attacker"
            parent.mkdir()
            attacker.mkdir()
            (parent / "module.py").write_text("VALUE = 'reviewed'\n")
            (attacker / "module.py").write_text("raise RuntimeError('hostile')\n")
            swapped = False

            def swap(_absolute: Path, component: str, final: bool) -> None:
                nonlocal swapped
                if component == parent.name and not final and not swapped:
                    parent.rename(backup)
                    parent.symlink_to(attacker, target_is_directory=True)
                    swapped = True

            try:
                with mock.patch.object(BENCH, "REPOSITORY_ROOT", root):
                    with self.assertRaises(OSError):
                        BENCH._snapshot_source(
                            parent / "module.py",
                            "selected/module.py",
                            before_component=swap,
                        )
            finally:
                if parent.is_symlink():
                    parent.unlink()
                if backup.exists():
                    backup.rename(parent)

    def test_python_final_component_swap_restore_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "module.py"
            backup = root / "module.reviewed"
            source.write_text("VALUE = 'reviewed'\n")
            swapped = False

            def before(_absolute: Path, _component: str, final: bool) -> None:
                nonlocal swapped
                if final and not swapped:
                    source.rename(backup)
                    source.write_text("raise RuntimeError('hostile')\n")
                    swapped = True

            def restore(_absolute: Path, _descriptor: int) -> None:
                source.unlink()
                backup.rename(source)

            with mock.patch.object(BENCH, "REPOSITORY_ROOT", root):
                with self.assertRaisesRegex(RuntimeError, "selection changed"):
                    BENCH._snapshot_source(
                        source,
                        "module.py",
                        before_component=before,
                        after_final=restore,
                    )
            self.assertIn("reviewed", source.read_text())

    def test_all_product_executable_roles_reject_parent_substitution(self) -> None:
        for role in ("host", "core", "python", "shell"):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                parent = root / "selected"
                backup = root / "selected-reviewed"
                attacker = root / "attacker"
                custody = root / "custody"
                parent.mkdir()
                attacker.mkdir()
                custody.mkdir(mode=0o700)
                source = parent / role
                shutil.copyfile(sys.executable, source)
                source.chmod(0o700)
                hostile = attacker / role
                hostile.write_text("#!/bin/sh\nexit 99\n")
                hostile.chmod(0o700)
                swapped = False

                def before(_absolute: Path, component: str, final: bool) -> None:
                    nonlocal swapped
                    if component == parent.name and not final and not swapped:
                        parent.rename(backup)
                        parent.symlink_to(attacker, target_is_directory=True)
                        swapped = True

                try:
                    with self.assertRaises(OSError):
                        BENCH.PinnedExecutable(
                            source,
                            custody,
                            role,
                            before_component=before,
                        )
                finally:
                    if parent.is_symlink():
                        parent.unlink()
                    if backup.exists():
                        backup.rename(parent)

    def test_all_product_executable_roles_reject_final_swap_restore(self) -> None:
        for role in ("host", "core", "python", "shell"):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / f"{role}-source"
                backup = root / f"{role}-reviewed"
                custody = root / "custody"
                custody.mkdir(mode=0o700)
                shutil.copyfile(sys.executable, source)
                source.chmod(0o700)
                swapped = False

                def before(_absolute: Path, _component: str, final: bool) -> None:
                    nonlocal swapped
                    if final and not swapped:
                        source.rename(backup)
                        source.write_text("#!/bin/sh\nexit 97\n")
                        source.chmod(0o700)
                        swapped = True

                def restore(_absolute: Path, _descriptor: int) -> None:
                    source.unlink()
                    backup.rename(source)

                with self.assertRaisesRegex(
                    BENCH.BenchmarkError, "changed before custody completed"
                ):
                    BENCH.PinnedExecutable(
                        source,
                        custody,
                        role,
                        before_component=before,
                        after_final=restore,
                    )
                self.assertEqual(
                    source.read_bytes()[:4], Path(sys.executable).read_bytes()[:4]
                )


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open") and hasattr(os, "WNOWAIT"),
                     "owned process group fixtures require Linux pidfd and WNOWAIT")
class ProductProcessCleanupTests(unittest.TestCase):
    def _exercise(self, mode: str, *, broker: bool = False) -> None:
        fd_before = len(os.listdir("/proc/self/fd"))
        owned = []
        original_spawn = BENCH.CORE.subprocess.Popen

        def own_process(*args, **kwargs):
            process = original_spawn(*args, **kwargs)
            owned.append(process)
            if mode in {"unread_stdin", "partial_stdin"}:
                fcntl.fcntl(process.stdin.fileno(), fcntl.F_SETPIPE_SZ, 4096)
                self.assertEqual(fcntl.fcntl(process.stdin.fileno(), fcntl.F_GETPIPE_SZ), 4096)
            return process

        with tempfile.TemporaryDirectory(prefix="perf-owned-process-") as directory:
            root = Path(directory)
            pid_path, release = root / "child.json", root / "release"
            child = (
                "import json,os,signal,sys,time\n"
                + ("signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                   if mode in {"ignore_term", "flood"} else "")
                + "with open(sys.argv[1]+'.tmp','x') as stream:\n"
                  " stream.write(json.dumps({'pid':os.getpid(),'pgid':os.getpgrp(),'sid':os.getsid(0)}))\n"
                  "os.replace(sys.argv[1]+'.tmp',sys.argv[1])\n"
                  "while not os.path.exists(sys.argv[2]): time.sleep(.01)\n"
                + ("print('{\"kind\":\"fixture.normal\"}',flush=True)\n" if mode == "normal" else
                   "import hashlib\ndata=sys.stdin.buffer.read()\nprint(json.dumps({'kind':'fixture.read','sha256':hashlib.sha256(data).hexdigest()}),flush=True)\n" if mode == "partial_stdin" else
                   "os.write(1,b'x'*(17*1024*1024))\ntime.sleep(60)\n" if mode == "flood" else
                   "time.sleep(60)\n")
            )
            leader = (
                "import os,subprocess,sys,time\n"
                f"subprocess.Popen([sys.executable,'-I','-c',{child!r},{str(pid_path)!r},{str(release)!r}])\n"
                f"while not os.path.exists({str(pid_path)!r}): time.sleep(.005)\n"
                "raise SystemExit(0)\n"
            )
            input_frames = []
            if broker:
                wrapper = root / "python-fixture"
                wrapper.write_text("#!" + sys.executable + "\n" + leader)
                wrapper.chmod(0o700)
                selected = mock.patch.dict(BENCH.CORE.EXECUTION_PATHS, {"python": str(wrapper)})
                invoke = lambda: BENCH.run_broker_sample(
                    Path(sys.executable), Path(sys.executable), root / "broker", 1, 2
                )
            else:
                selected = contextlib.nullcontext()
                if mode in {"unread_stdin", "partial_stdin"}:
                    if os.sysconf("SC_PAGE_SIZE") > 4096:
                        self.skipTest("legal 16KiB input cannot exceed this kernel's minimum pipe size")
                    input_frames = [{"kind": "fixture.valid-bounded-input", "payload": "x" * 12000}]
                invoke = lambda: BENCH.collect([sys.executable, "-I", "-c", leader], input_frames,
                                               6 if mode in {"normal", "partial_stdin"} else 2)
            pidfd = None
            try:
                with selected, mock.patch.object(BENCH.CORE.subprocess, "Popen", side_effect=own_process), \
                        BENCH.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(invoke)
                    deadline = time.monotonic() + 2
                    while not pid_path.exists() and time.monotonic() < deadline:
                        time.sleep(.01)
                    self.assertTrue(pid_path.exists(), "owned descendant fixture did not start")
                    identity = json.loads(pid_path.read_bytes())
                    self.assertEqual(identity["pgid"], identity["sid"])
                    pidfd = os.pidfd_open(identity["pid"], 0)
                    release.touch()
                    if mode in {"normal", "partial_stdin"}:
                        frames, observation = future.result(timeout=12)
                        if mode == "normal":
                            self.assertEqual(frames, [{"kind": "fixture.normal"}])
                        else:
                            raw = b"".join(json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
                                           for value in input_frames)
                            self.assertGreater(len(raw), 4096)
                            self.assertLessEqual(len(raw), 16384)
                            self.assertEqual(frames, [{"kind": "fixture.read", "sha256": BENCH.digest(raw)}])
                        self.assertEqual(observation["exit_code"], 0)
                    else:
                        expected = ("broker exited during startup" if broker else
                                    "product output exceeded capture bound" if mode == "flood" else
                                    "product process timed out")
                        with self.assertRaisesRegex(BENCH.BenchmarkError, expected):
                            future.result(timeout=12)
                    self.assertTrue(select.select([pidfd], [], [], 1)[0],
                                    "exact owned descendant outlived product cleanup")
                    self.assertEqual(len(owned), 1)
                    self.assertIsNotNone(owned[0].returncode, "owned leader was not reaped after group cleanup")
            finally:
                if pidfd is not None:
                    if not select.select([pidfd], [], [], 0)[0]:
                        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                        self.assertTrue(select.select([pidfd], [], [], 3)[0])
                    os.close(pidfd)
        self.assertEqual(len(os.listdir("/proc/self/fd")), fd_before)

    def test_normal_group_is_terminal_before_return(self) -> None:
        self._exercise("normal")

    def test_exited_leader_child_holding_stdout_is_stopped(self) -> None:
        self._exercise("held_stdout")

    def test_exited_leader_child_ignoring_term_is_killed(self) -> None:
        self._exercise("ignore_term")

    def test_output_flood_stops_exact_owned_descendant(self) -> None:
        self._exercise("flood")

    def test_broker_startup_exit_does_not_reap_before_child_cleanup(self) -> None:
        self._exercise("ignore_term", broker=True)

    def test_bounded_input_above_real_pipe_capacity_times_out(self) -> None:
        self._exercise("unread_stdin")

    def test_nonblocking_partial_input_is_delivered_exactly(self) -> None:
        self._exercise("partial_stdin")

    def test_terminal_reap_error_closes_all_pipes_and_remains_error(self) -> None:
        fd_before = len(os.listdir("/proc/self/fd"))
        owned = []
        spawn = BENCH.CORE.subprocess.Popen
        reaper = BENCH.CORE.REAP_PROCESS_ANCHOR

        def own_process(*args, **kwargs):
            process = spawn(*args, **kwargs)
            owned.append(process)
            return process

        try:
            with mock.patch.object(BENCH.CORE.subprocess, "Popen", side_effect=own_process), \
                    mock.patch.object(BENCH.CORE, "REAP_PROCESS_ANCHOR", side_effect=OSError("fixture reap failure")):
                with self.assertRaisesRegex(OSError, "fixture reap failure"):
                    BENCH.collect([sys.executable, "-I", "-c", "pass"], [], 2)
            self.assertEqual(len(owned), 1)
            self.assertTrue(all(pipe.closed for pipe in (owned[0].stdin, owned[0].stdout, owned[0].stderr)))
            self.assertIsNone(owned[0].returncode, "failed reaping was silently accepted")
            self.assertIsNotNone(os.waitid(os.P_PID, owned[0].pid, os.WEXITED | os.WNOHANG | os.WNOWAIT))
        finally:
            for process in owned:
                if process.returncode is None:
                    reaper(process)
                for pipe in (process.stdin, process.stdout, process.stderr):
                    pipe.close()
        self.assertEqual(len(os.listdir("/proc/self/fd")), fd_before)

    def test_sigchld_ignore_rejects_before_spawn_in_isolated_interpreter(self) -> None:
        with tempfile.TemporaryDirectory(prefix="perf-sigchld-") as directory:
            marker = Path(directory) / "spawned"
            source = BENCH.CORE.PINNED_IMPLEMENTATION_SOURCES["tools/perf/_run_product_baseline_core.py"]
            script = (
                "import json,signal,sys\n"
                "namespace={'__name__':'isolated_source_fixture','__file__':sys.argv[1]}\n"
                "exec(compile(sys.stdin.buffer.read(),sys.argv[1],'exec'),namespace)\n"
                "signal.signal(signal.SIGCHLD,signal.SIG_IGN)\n"
                "try:\n"
                " namespace['collect']([sys.executable,'-I','-c',\"from pathlib import Path;Path(\"+repr(sys.argv[2])+\").write_text('spawned')\"],[],1)\n"
                "except namespace['BenchmarkError'] as error:\n"
                " print(json.dumps({'error':str(error)}))\n"
                "else: raise SystemExit('SIGCHLD ignore accepted')\n"
            )
            result = subprocess.run([sys.executable, "-I", "-c", script, str(PATH), str(marker)],
                                    input=source, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertIn("requires Linux WNOWAIT and default SIGCHLD", json.loads(result.stdout)["error"])
            self.assertFalse(marker.exists())


@unittest.skipUnless(os.environ.get("TRILLIONNIUM_PERF_HOST") and os.environ.get("TRILLIONNIUM_PERF_CORE"),
                     "set TRILLIONNIUM_PERF_HOST and TRILLIONNIUM_PERF_CORE for real-binary integration")

class RealProductBaselineTests(unittest.TestCase):
    def test_real_selected_products_all_workloads_with_private_custody(self) -> None:
        host = Path(os.environ["TRILLIONNIUM_PERF_HOST"]).resolve(strict=True)
        core = Path(os.environ["TRILLIONNIUM_PERF_CORE"]).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="perf-private-integration-") as directory:
            args = BENCH.parse_args([
                "--host", str(host), "--core", str(core),
                "--output", str(Path(directory) / "report.json"),
                "--scratch-parent", directory,
                "--repetitions", "1", "--warmup", "0", "--output-bytes", "65536",
            ])
            report = BENCH.run(args)
            self.assertEqual(report["failures"], [])
            self.assertEqual({row["workload"] for row in report["samples"]}, set(BENCH.WORKLOADS))
            self.assertTrue(all(row["correctness_validated"] for row in report["samples"]))
            self.assertFalse(report["gate"]["passed"])
            self.assertFalse(report["public_release"])

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
