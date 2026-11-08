"""Source custody and an unadopted pure guard; no installed-target claims."""

from __future__ import annotations

import ast
import copy
import hashlib
import itertools
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest

from tools.verify_razr60_r10_source_closure import (
    CHECKPOINT, NEGATIVE_CLAIMS, materialize_checkpoint, member_path, strict_json,
    stable_stat_identity, verify_checkpoint, verify_members, verify_unbound_preparer,
    verify_source_parent_candidate,
    verify_followup_candidates, FOLLOWUP_PUBLIC_DELIVERIES,
)


ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / CHECKPOINT
CANDIDATE = PACKAGE / "unadopted/topology-20261107"
PREPARER = PACKAGE / "unadopted/preparer-next-generation"


class R10SourceCheckpointTest(unittest.TestCase):
    def test_exact_frozen_closure_and_claim_ceiling(self):
        report = verify_checkpoint(PACKAGE)
        self.assertEqual(report["native_runtime_members"], 38)
        self.assertEqual(report["root_chain_members"], 3)
        self.assertFalse(report["runtime_imported"])
        self.assertEqual(report["fixed19_credits_added"], 0)

    def test_manifest_claims_do_not_supply_github_review_or_adoption(self):
        manifest = json.loads((PACKAGE / "MANIFEST.json").read_text())
        self.assertEqual(manifest["negative_claims"], NEGATIVE_CLAIMS)
        self.assertFalse(manifest["negative_claims"]["github_independent_review_supplied"])

    def test_path_traversal_and_aliases_are_rejected(self):
        for value in ("", "../x.py", "/x.py", "x/../y.py", "x//y.py", "./x.py"):
            with self.subTest(path=value), self.assertRaises(ValueError):
                member_path(Path("/unused"), value)

    def test_symlink_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.py").write_text("pass\n")
            (root / "b.py").symlink_to(root / "a.py")
            with self.assertRaisesRegex(ValueError, "symlink"):
                member_path(root, "b.py")

    def test_source_tampering_and_duplicate_members_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = b"pass\n"
            (root / "a.py").write_bytes(raw)
            row = {"path": "a.py", "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            self.assertEqual(verify_members(root, [row]), {"a.py": raw})
            with self.assertRaisesRegex(ValueError, "unique"):
                verify_members(root, [row, row])
            (root / "a.py").write_bytes(b"#pass")
            with self.assertRaisesRegex(ValueError, "source bytes differ"):
                verify_members(root, [row])

    def test_first_read_allows_access_time_only_and_preserves_nanosecond_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = b"# fresh source\n"
            path = root / "fresh.py"
            path.write_bytes(raw)
            initial = path.stat()
            row = {"path": path.name, "bytes": len(raw),
                   "sha256": hashlib.sha256(raw).hexdigest()}
            self.assertEqual(verify_members(root, [row]), {path.name: raw})
            fields = {name: getattr(initial, name) for name in (
                "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                "st_size", "st_mtime_ns", "st_ctime_ns", "st_atime_ns")}
            access_only = types.SimpleNamespace(**(fields | {"st_atime_ns": fields["st_atime_ns"] + 1}))
            self.assertEqual(stable_stat_identity(initial), stable_stat_identity(access_only))
            for timestamp in ("st_mtime_ns", "st_ctime_ns"):
                changed = types.SimpleNamespace(**(fields | {timestamp: fields[timestamp] + 1}))
                self.assertNotEqual(stable_stat_identity(initial), stable_stat_identity(changed))

    def test_private_archive_is_not_a_source_member(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = {"path": "ORIGINALS.zlib", "bytes": 0, "sha256": "0" * 64}
            with self.assertRaisesRegex(ValueError, "archive"):
                verify_members(root, [row])

    def test_ambiguous_json_is_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                strict_json(raw)

    def test_third_party_materialization_rebuilds_all_current_source_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "reconstructed"
            report = materialize_checkpoint(PACKAGE, output)
            self.assertEqual(report["native_runtime_members"], 38)
            manifest = json.loads((PACKAGE / "MANIFEST.json").read_text())
            for row in manifest["files"]:
                if row["path"].startswith(("frozen/", "preparation/", "release/", "external-source/")):
                    self.assertEqual((output / row["path"]).read_bytes(),
                                     (PACKAGE / row["path"]).read_bytes())
            self.assertFalse(report["runtime_adopted"])
            with self.assertRaisesRegex(ValueError, "output must be absent"):
                materialize_checkpoint(PACKAGE, output)

    def test_missing_dependency_and_reassigned_source_identity_fail_before_materialization(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copied = root / "checkpoint"
            shutil.copytree(PACKAGE, copied)
            dependency = "frozen/native/dependencies/p4/phone_once.py"
            (copied / dependency).unlink()
            manifest = json.loads((copied / "MANIFEST.json").read_text())
            manifest["files"] = [row for row in manifest["files"] if row["path"] != dependency]
            (copied / "MANIFEST.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "selected external dependency is missing"):
                materialize_checkpoint(copied, root / "must-not-exist")
            self.assertFalse((root / "must-not-exist").exists())
            (copied / dependency).write_bytes((PACKAGE / dependency).read_bytes())
            manifest = json.loads((PACKAGE / "MANIFEST.json").read_text())
            source = "frozen/native/runtime/source/late_boundary.py"
            raw = (copied / source).read_bytes() + b"\n"
            (copied / source).write_bytes(raw)
            for row in manifest["files"]:
                if row["path"] == source:
                    row.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            (copied / "MANIFEST.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "frozen R10 identity was reassigned"):
                verify_checkpoint(copied)

    def test_missing_native_member_cannot_be_hidden_by_editing_the_public_membership(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "checkpoint"
            shutil.copytree(PACKAGE, copied)
            member = "frozen/native/runtime/source/component_common.py"
            (copied / member).unlink()
            manifest = json.loads((copied / "MANIFEST.json").read_text())
            manifest["files"] = [row for row in manifest["files"] if row["path"] != member]
            (copied / "MANIFEST.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "original family source is missing"):
                verify_checkpoint(copied)

    def test_missing_nonselected_external_source_cannot_be_hidden_by_membership_edit(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "checkpoint"
            shutil.copytree(PACKAGE, copied)
            bindings = json.loads((copied / "EXTERNAL-SOURCE-BINDINGS.json").read_text())
            row = next(row for row in bindings["source_bindings"]
                       if row.get("checkpoint_path", "").startswith("external-source/"))
            member = row["checkpoint_path"]
            (copied / member).unlink()
            manifest = json.loads((copied / "MANIFEST.json").read_text())
            manifest["files"] = [row for row in manifest["files"] if row["path"] != member]
            (copied / "MANIFEST.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "resolved external source member is missing"):
                verify_checkpoint(copied)

    def test_ancestor_exemption_must_bind_its_original_json_field(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "checkpoint"
            shutil.copytree(PACKAGE, copied)
            name = "EXTERNAL-SOURCE-BINDINGS.json"
            bindings = json.loads((copied / name).read_text())
            bindings["unmaterialized_development_ancestors"][0]["metadata_references"][0]["json_pointer"] = "/absent"
            raw = json.dumps(bindings).encode()
            (copied / name).write_bytes(raw)
            manifest = json.loads((copied / "MANIFEST.json").read_text())
            for row in manifest["files"]:
                if row["path"] == name:
                    row.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            (copied / "MANIFEST.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "source JSON pointer does not resolve"):
                verify_checkpoint(copied)

    def test_offline_selector_cannot_promote_runtime_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "checkpoint"
            shutil.copytree(PACKAGE, copied)
            name = "unadopted/topology-20261107/SELECTOR-CANDIDATE-MANIFEST.json"
            value = json.loads((copied / name).read_text())
            value["runtime_admission"] = True
            raw = json.dumps(value).encode()
            (copied / name).write_bytes(raw)
            manifest = json.loads((copied / "MANIFEST.json").read_text())
            for row in manifest["files"]:
                if row["path"] == name:
                    row.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            (copied / "MANIFEST.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "offline selector claim ceiling differs"):
                verify_checkpoint(copied)

    def test_unbound_preparer_cannot_be_promoted_or_lose_a_public_member(self):
        prefix = "unadopted/preparer-next-generation/"
        contents = {str(path.relative_to(PACKAGE)): path.read_bytes()
                    for path in PREPARER.rglob("*") if path.is_file()}
        origin = "preparation/r10/prepare_native_bound_components_r10_fc33.py"
        contents[origin] = (PACKAGE / origin).read_bytes()
        verify_unbound_preparer(contents)
        changed = dict(contents)
        key = prefix + "FUTURE-BINDING-UNBOUND.json"
        value = json.loads(changed[key])
        value["state"] = "READY"
        changed[key] = json.dumps(value).encode()
        with self.assertRaisesRegex(ValueError, "future bindings must remain unset"):
            verify_unbound_preparer(changed)
        changed = dict(contents)
        del changed[prefix + "tests/test_unbound_preparer.py"]
        with self.assertRaisesRegex(ValueError, "public membership differs"):
            verify_unbound_preparer(changed)

    def test_full_source_parent_cannot_claim_runtime_budget_or_drop_a_member(self):
        rows = json.loads((PACKAGE / "MANIFEST.json").read_text())["files"]
        contents = {row["path"]: (PACKAGE / row["path"]).read_bytes() for row in rows}
        verify_source_parent_candidate(contents)
        prefix = "unadopted/topology-20261107/source-parent-v3/"
        changed = dict(contents)
        key = prefix + "SOURCE-PARENT-CANDIDATE-MANIFEST-v3.json"
        value = json.loads(changed[key])
        value["whole_stage_budget_verified"] = True
        changed[key] = json.dumps(value).encode()
        with self.assertRaisesRegex(ValueError, "full source-parent claim ceiling differs"):
            verify_source_parent_candidate(changed)
        changed = dict(contents)
        del changed[prefix + "tests/replay_source_parent_fixture.py"]
        with self.assertRaisesRegex(ValueError, "full source-parent public membership differs"):
            verify_source_parent_candidate(changed)

    def test_sealed_followup_sources_cannot_promote_claims_or_hide_a_missing_member(self):
        rows = json.loads((PACKAGE / "MANIFEST.json").read_text())["files"]
        contents = {row["path"]: (PACKAGE / row["path"]).read_bytes() for row in rows}
        verify_followup_candidates(contents)
        for package in FOLLOWUP_PUBLIC_DELIVERIES:
            with self.subTest(package=package["prefix"]):
                key = package["prefix"] + package["manifest"]
                changed = dict(contents); value = json.loads(changed[key])
                value["runtime_admission"] = True; changed[key] = json.dumps(value).encode()
                with self.assertRaisesRegex(ValueError, "followup delivery claim ceiling differs"):
                    verify_followup_candidates(changed)
                changed = dict(contents); value = json.loads(changed[key]); row = value["files"].pop()
                del changed[package["prefix"] + row["path"]]
                value["file_count"] -= 1; value["total_bytes"] -= row["bytes"]
                changed[key] = json.dumps(value).encode()
                with self.assertRaisesRegex(ValueError, "sealed followup delivery identity was reassigned"):
                    verify_followup_candidates(changed)
        changed = dict(contents)
        key = "unadopted/retained-r10-failure-v1/PORTABLE-DELIVERY-MANIFEST-v1.json"
        value = json.loads(changed[key]); value["global_unknown_effect_count"] = 0
        changed[key] = json.dumps(value).encode()
        with self.assertRaisesRegex(ValueError, "retained failure unknown boundary differs"):
            verify_followup_candidates(changed)


class UnadoptedTopologyGuardTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        common = ast.parse((PACKAGE / "frozen/native/runtime/source/component_common.py").read_text())
        nodes = [n for n in common.body if
                 (isinstance(n, ast.FunctionDef) and n.name == "need") or
                 (isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
                  and n.targets[0].id == "HASH")]
        namespace = {"re": re}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "<pinned-common-pure>", "exec"), namespace)
        support = types.SimpleNamespace(need=namespace["need"], HASH=namespace["HASH"])
        implementations = []
        for path in (PACKAGE / "frozen/native/runtime/source/late_boundary.py",
                     CANDIDATE / "candidate/inventory_value.py"):
            nodes = [n for n in ast.parse(path.read_text()).body
                     if isinstance(n, ast.FunctionDef) and n.name == "inventory_value"]
            if len(nodes) != 1:
                raise AssertionError("one pure inventory function is required")
            namespace = {"C": support, "Path": Path, "re": re, "stat": stat}
            exec(compile(ast.Module(body=nodes, type_ignores=[]), "<pure-inventory>", "exec"), namespace)
            implementations.append(namespace["inventory_value"])
        cls.implementations = implementations

    @staticmethod
    def inventory(roots):
        return {"schema": "hepta.native-guard.complete-inventory.v1", "roots": list(roots),
                "entries": {r: {"kind": "directory", "metadata":
                                  [1, i + 1, stat.S_IFDIR | 0o700, 0, 0, 2, 0, 0, 0],
                                  "names": []} for i, r in enumerate(roots)},
                "file_bytes_hashed": 0, "elapsed_seconds": 0.0,
                "inventory_is_closure_or_retirement": False}

    @staticmethod
    def result(function, value):
        original = copy.deepcopy(value)
        try:
            outcome = ("accepted", function(value))
        except Exception as error:
            outcome = ("rejected", type(error).__name__, str(error))
        if original != value:
            raise AssertionError("pure validator mutated input")
        return outcome

    def test_complete_pure_function_preserves_posix_edges_and_rejection_order(self):
        names = ["/", "//", "/a", "//a", "/a/b", "//a/b", "/b", "/A", "/Å", "/A\u030a",
                 "relative", "/a/", "/a//b", "/a/../b"]
        old, new = self.implementations
        for roots in itertools.product(names, repeat=2):
            with self.subTest(roots=roots):
                value = self.inventory(roots)
                self.assertEqual(self.result(old, copy.deepcopy(value)),
                                 self.result(new, copy.deepcopy(value)))
        for count in (1, 2, 49, 64, 65):
            value = self.inventory(["/scope/r-%03d" % i for i in range(count)])
            self.assertEqual(self.result(old, copy.deepcopy(value)),
                             self.result(new, copy.deepcopy(value)))

    def test_candidate_is_one_declared_source_change_and_has_no_admission(self):
        source = (PACKAGE / "frozen/native/runtime/source/late_boundary.py").read_text()
        build = ast.parse((CANDIDATE / "tools/build_candidate.py").read_text())
        literals = {n.targets[0].id: ast.literal_eval(n.value) for n in build.body
                    if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
                    and n.targets[0].id in {"OLD_BLOCK", "NEW_BLOCK"}}
        self.assertEqual(source.count(literals["OLD_BLOCK"]), 1)
        derived = source.replace(literals["OLD_BLOCK"], literals["NEW_BLOCK"], 1)
        self.assertEqual(derived.replace(literals["NEW_BLOCK"], literals["OLD_BLOCK"], 1), source)
        manifest = json.loads((CANDIDATE / "CANDIDATE-MANIFEST.json").read_text())
        self.assertEqual(hashlib.sha256(derived.encode()).hexdigest(),
                         manifest["derived_full_source_if_applied"]["sha256"])
        self.assertFalse(manifest["runtime_admission"])
        self.assertFalse(manifest["whole_stage_budget_verified"])

    def test_portable_constructors_rebuild_exact_fragments_and_synthetic_differentials(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "candidate"
            shutil.copytree(CANDIDATE, target)
            environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", HEPTA_TOPOLOGY_SYNTHETIC_ONLY="1")
            for script, manifest in (
                ("tools/build_candidate.py", "CANDIDATE-MANIFEST.json"),
                ("tools/build_derived_fragments.py", "DERIVED-CANDIDATE-MANIFEST.json"),
            ):
                result = subprocess.run([sys.executable, script], cwd=target, env=environment,
                                        text=True, capture_output=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual((target / manifest).read_bytes(), (CANDIDATE / manifest).read_bytes())
            for source in (CANDIDATE / "candidate").rglob("*"):
                if source.is_file():
                    self.assertEqual(source.read_bytes(), (target / source.relative_to(CANDIDATE)).read_bytes())
            for script, report in (
                ("tests/test_inventory_topology.py", "reports/differential-synthetic-results.json"),
                ("tests/test_derived_topology.py", "reports/derived-differential-synthetic-results.json"),
            ):
                result = subprocess.run([sys.executable, script], cwd=target, env=environment,
                                        text=True, capture_output=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                value = json.loads((target / report).read_text())
                self.assertEqual(value["state"], "PASS")
                self.assertFalse(value["runtime_admission"])
                self.assertFalse(value["whole_stage_budget_verified"])
                self.assertEqual(value["native_case_credit"], 0)
            inventory = json.loads((target / "reports/differential-synthetic-results.json").read_text())
            scope = json.loads((target / "reports/derived-differential-synthetic-results.json").read_text())
            self.assertEqual(inventory["inventory_comparisons"], 788)
            self.assertEqual(inventory["topology_comparisons"], 1754)
            self.assertEqual(scope["source_parent_inventory"]["inventory_comparisons"], 788)
            self.assertEqual(scope["scope_topology_subgraph"]["comparisons"], 285)

    def test_bound_offline_selector_rebuilds_and_rejects_source_or_receipt_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "candidate"
            shutil.copytree(CANDIDATE, target)
            environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", HEPTA_TOPOLOGY_SYNTHETIC_ONLY="1")
            built = subprocess.run([sys.executable, "-B", "tools/build_selector_manifest.py"],
                                   cwd=target, env=environment, capture_output=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            self.assertEqual(built.stdout, (CANDIDATE / "SELECTOR-CANDIDATE-MANIFEST.json").read_bytes())
            result = subprocess.run([sys.executable, "-B", "tests/test_reader_selector.py"],
                                    cwd=target, env=environment, text=True, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["state"], "PASS")
            self.assertEqual(report["tests_run"], 11)
            self.assertEqual(len(report["skips"]), 1)
            self.assertEqual(len(report["constructed_modules"]), 5)
            self.assertEqual(report["rejected_source_or_binding_cases"], 36)
            self.assertEqual(report["inventory_comparisons"], 30)
            self.assertEqual(report["retained_inventory_comparisons"], 0)

    def test_next_preparer_stays_unbound_under_actual_negative_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "preparer"
            shutil.copytree(PREPARER, target)
            environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
            built = subprocess.run([sys.executable, "-B", "tools/build_candidate.py", "--check"],
                                   cwd=target, env=environment, capture_output=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run([sys.executable, "-B", "tests/test_unbound_preparer.py"],
                                    cwd=target, env=environment, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["state"], "PASS")
            self.assertEqual(report["tests_run"], 11)
            self.assertEqual(report["counters"]["negative_cases"], 79)
            self.assertTrue(all(value == 0 for value in report["counters"]["unbound_entry_effects"].values()))
            self.assertFalse(report["original_preparer_executed"])
            self.assertFalse(report["freeze_executed"])

    def test_complete_source_parent_constructor_and_portable_differentials(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "candidate"
            shutil.copytree(CANDIDATE, target)
            environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", HEPTA_TOPOLOGY_SYNTHETIC_ONLY="1")
            built = subprocess.run([sys.executable, "-B", "source-parent-v3/tools/build_manifest.py", "--base", "."],
                                   cwd=target, env=environment, capture_output=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            self.assertEqual(built.stdout, (CANDIDATE / "source-parent-v3/SOURCE-PARENT-CANDIDATE-MANIFEST-v3.json").read_bytes())
            result = subprocess.run([sys.executable, "-B", "source-parent-v3/tests/test_source_parent_candidate.py", "--base", "."],
                                    cwd=target, env=environment, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["state"], "PASS")
            self.assertEqual(report["tests_run"], 14)
            self.assertEqual(len(report["skips"]), 2)
            self.assertEqual(report["source_contract_cases"], {
                "source_binding_rejections": 10, "guarded_constructor_rejections": 3, "new_envelope_cases": 2})
            self.assertEqual(report["inventory_differential"]["inventory_comparisons"], 788)
            self.assertEqual(report["inventory_differential"]["topology_comparisons"], 1754)
            self.assertFalse(report["private_complete_reader_test_performed"])

    def test_actual_current_source_parent_consumer_rebuilds_and_checks_envelopes(self):
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", HEPTA_TOPOLOGY_SYNTHETIC_ONLY="1")
        for script, args in (
            ("source-parent-consumer-v4/tools/build_manifest.py", ["--base", ".", "--check"]),
            ("source-parent-consumer-v4/tests/test_source_parent_consumer.py", ["--base", "."]),
        ):
            result = subprocess.run([sys.executable, "-B", script, *args], cwd=CANDIDATE,
                                    env=environment, text=True, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["state"], "PASS")
        self.assertEqual((report["tests"], report["skipped"]), (16, 2))
        self.assertEqual(report["counters"]["consumer_envelope_rejections"], 16)
        self.assertEqual(report["inventory_suite_counters"]["inventory_comparisons"], 788)
        self.assertFalse(report["runtime_admission"])
        self.assertFalse(report["whole_stage_budget_verified"])

    def test_actual_retained_current_consumer_rebuilds_and_binds_in_process_producers(self):
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        for script, args in (
            ("retained-current-consumer-v5/tools/build_manifest.py", ["--base", ".", "--check"]),
            ("retained-current-consumer-v5/tests/test_retained_current_consumer.py", ["--base", "."]),
        ):
            result = subprocess.run([sys.executable, "-B", script, *args], cwd=CANDIDATE,
                                    env=environment, text=True, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual((report["state"], report["tests"]), ("PASS", 12))
        self.assertEqual(report["counters"]["source_binding_rejections"], 10)
        self.assertEqual(report["counters"]["constructor_rejections"], 12)
        self.assertEqual(report["counters"]["new_envelope_rejections"], 17)
        self.assertEqual(report["counters"]["wrong_in_process_producer_rejections"], 4)
        self.assertEqual(report["counters"]["actual_selected_reader_rejections_before_provider"], 3)
        self.assertFalse(report["runtime_admission"])
        self.assertFalse(report["whole_stage_budget_verified"])

    def test_retained_r10_host_failure_reader_checks_portable_negatives_without_promoting_unknowns(self):
        root = PACKAGE / "unadopted/retained-r10-failure-v1"
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        for script in ("tools/verify_candidate.py", "tests/test_retained_r10_failure.py"):
            result = subprocess.run([sys.executable, "-B", script], cwd=root, env=environment,
                                    text=True, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual((report["state"], report["tests_run"], report["negative_cases"]), ("PASS", 6, 49))
        self.assertEqual(len(report["skipped"]), 1)
        self.assertFalse(report["private_originals_supplied"])
        self.assertFalse(report["runtime_admission"])

    def test_freeze_controller_semantics_are_type_exact_complete_and_do_not_enable_preparer(self):
        root = PACKAGE / "unadopted/freeze-preparation-semantics-v2"
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        for args in (["tools/verify_candidate.py"],
                     ["tests/test_freeze_semantics.py", "--retained-base", "../retained-r10-failure-v1"]):
            result = subprocess.run([sys.executable, "-B", *args], cwd=root, env=environment,
                                    text=True, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual((report["result"], report["tests"], report["negative_cases"]), ("PASS", 12, 105))
        self.assertTrue(report["synthetic_originals_only"])
        self.assertFalse(report["actual_future_freeze_or_controller_attested"])
        self.assertFalse(report["runtime_admission"])


if __name__ == "__main__":
    unittest.main()
