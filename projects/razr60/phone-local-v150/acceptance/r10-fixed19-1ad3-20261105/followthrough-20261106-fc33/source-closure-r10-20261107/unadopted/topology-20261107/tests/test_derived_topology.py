#!/usr/bin/env python3
"""Portable derived-fragment differential tests, separate from live selectors."""

from __future__ import annotations

import ast
import copy
import json
import os
from pathlib import Path, PurePosixPath
import platform
import random
import sys
import time
import unittest

from harness import BASE, fixtures, function_ast, load_inventory, pin
import test_inventory_topology as current_suite

sys.path.insert(0, str(BASE / "tools"))
from build_derived_fragments import SCOPE_OLD, SCOPE_NEW, SPECS
from build_candidate import OLD_BLOCK, NEW_BLOCK


SCOPE_REPORT = {"comparisons": 0, "accepted": 0, "rejected": 0,
                "need_call_order_equal": True, "mismatches": []}


class SourceParentDifferentialTests(current_suite.TopologyDifferentialTests):
    @classmethod
    def setUpClass(cls):
        original = (BASE / "originals/source_parent_late_boundary_r4.original.py").read_bytes()
        candidate = (BASE / "candidate/derived/source_parent_inventory_value.py").read_bytes()
        spec = SPECS[0]
        assert pin(original) == {k: spec[k] for k in ("bytes", "sha256")}
        cls.original = load_inventory(original, "<original-source-parent-inventory>")
        cls.candidate = load_inventory(candidate, "<UNADOPTED-derived-source-parent-inventory>")
        cls.real = fixtures()

    def test_exact_declared_source_change(self):
        original = (BASE / "originals/source_parent_late_boundary_r4.original.py").read_text()
        derived = (BASE / "candidate/derived/source_parent_inventory_value.py").read_text()
        self.assertEqual(original.count(OLD_BLOCK), 1)
        full = original.replace(OLD_BLOCK, NEW_BLOCK, 1)
        self.assertEqual(full.replace(NEW_BLOCK, OLD_BLOCK, 1), original)
        self.assertEqual(ast.dump(function_ast(full, "inventory_value"), include_attributes=False),
                         ast.dump(function_ast(derived, "inventory_value"), include_attributes=False))
        # The original source-parent function is byte-for-byte the same pure
        # function tested for current R10, but keeps its own source provenance.
        original_current = (BASE / "originals/late_boundary.r10.original.py").read_bytes()
        self.assertEqual(ast.dump(function_ast(original, "inventory_value"), include_attributes=False),
                         ast.dump(function_ast(original_current, "inventory_value"), include_attributes=False))


def block_outcome(block, old, after):
    trace = []
    def need(ok, reason):
        trace.append({"ok": bool(ok), "reason": reason})
        if not ok:
            raise ValueError(reason)
    namespace = {"Path": Path, "need": need}
    exec(compile("def check(old, after):\n" + block, "<exact-topology-subgraph>", "exec"), namespace)
    inputs = copy.deepcopy((old, after))
    before = copy.deepcopy(inputs)
    try:
        result = namespace["check"](*inputs)
    except Exception as error:
        outcome = {"accepted": False, "exception_type": type(error).__name__, "message": str(error)}
    else:
        outcome = {"accepted": True, "output": result}
    if inputs != before:
        raise AssertionError("topology subgraph changed an input")
    return outcome, trace


class ScopeTopologySubgraphTests(unittest.TestCase):
    def compare(self, old, after, label, accepted=None):
        # These are the already-validated path conditions at the insertion
        # site.  The full original and derived scope retain the same pin gates.
        for name in list(old["roots"]) + list(after["entries"]):
            path = PurePosixPath(name)
            self.assertTrue(path.is_absolute() and str(path) == name and ".." not in path.parts)
        original = block_outcome(SCOPE_OLD, old, after)
        derived = block_outcome(SCOPE_NEW, old, after)
        SCOPE_REPORT["comparisons"] += 1
        if original != derived:
            SCOPE_REPORT["mismatches"].append({"case": label, "original": original, "derived": derived})
        self.assertEqual(original, derived, label)
        SCOPE_REPORT["accepted" if original[0]["accepted"] else "rejected"] += 1
        if accepted is not None:
            self.assertEqual(original[0]["accepted"], accepted, label)

    def test_scope_whole_byte_inverse_and_signature(self):
        source = (BASE / "originals/retained_r8_scope.original.py").read_text()
        candidate = (BASE / "candidate/derived/retained_r8_verify_complete_scope.py").read_text()
        self.assertEqual(source.count(SCOPE_OLD), 1)
        derived = source.replace(SCOPE_OLD, SCOPE_NEW, 1)
        self.assertEqual(derived.replace(SCOPE_NEW, SCOPE_OLD, 1), source)
        self.assertEqual(ast.dump(function_ast(derived, "verify_complete_scope"), include_attributes=False),
                         ast.dump(function_ast(candidate, "verify_complete_scope"), include_attributes=False))
        self.assertEqual(ast.dump(function_ast(source, "verify_complete_scope").args),
                         ast.dump(function_ast(candidate, "verify_complete_scope").args))

    def test_real_before_after_3991_entry_topology(self):
        real_fixtures = fixtures()
        if not real_fixtures:
            self.skipTest("explicit synthetic-only run: private retained fixtures are not loaded")
        for descriptor, complete in real_fixtures:
            # This is a labelled topology projection, not a fabricated R7
            # original.  The exact full R7 proof is used by the Mac full test.
            old_roots = complete["roots"][:-2]
            self.assertEqual(len(old_roots), 47)
            self.assertTrue(all("fc33-r8-bound01" in root for root in complete["roots"][-2:]))
            root_parts = frozenset(Path(root).parts for root in old_roots)
            depths = frozenset(map(len, root_parts))
            old_entries = {name: row for name, row in complete["entries"].items()
                           if any(Path(name).parts[:depth] in root_parts for depth in depths
                                  if depth <= len(Path(name).parts))}
            self.assertEqual(len(old_entries), 3918)
            old = {"roots": old_roots, "entries": old_entries}
            after = {"entries": complete["entries"]}
            self.compare(old, after, "retained:" + descriptor["name"], True)
            missing = copy.deepcopy(old)
            missing["entries"].pop(next(iter(old_entries)))
            self.compare(missing, after, "retained-missing:" + descriptor["name"], False)
            extra = copy.deepcopy(after)
            extra["entries"][old_roots[0] + "/new-unretained-child"] = {}
            self.compare(old, extra, "retained-added-child:" + descriptor["name"], False)

    def test_anchors_equal_depth_unicode_and_rejection_order(self):
        roots = ["/a", "//a", "/Å", "/A\u030a", "/中文", "//中文", "/a\0b", "/...", "/\\x"]
        for root in roots:
            old = {"roots": [root], "entries": {root: {}, root + "/ok": {}}}
            self.compare(old, {"entries": {root: {}, root + "/ok": {}, root + "-sibling": {}}},
                         "literal:" + root, True)
            self.compare(old, {"entries": {root + "/bad": {}, root + "/ok": {}}},
                         "first-invalid:" + root, False)
            self.compare(old, {"entries": {root + "/ok": {}, root + "/bad": {}}},
                         "later-invalid:" + root, False)
        for old_root, name in [("/", "/a"), ("//", "//a"), ("/", "//a"), ("//", "/a")]:
            old = {"roots": [old_root], "entries": {old_root: {}}}
            expected = PurePosixPath(old_root).anchor != PurePosixPath(name).anchor
            self.compare(old, {"entries": {name: {}}}, "anchor:" + old_root + ":" + name, expected)
        for count in (1, 2, 47, 64):
            roots = ["/same-depth/r%03d" % n for n in range(count)]
            old = {"roots": roots, "entries": {root: {} for root in roots}}
            self.compare(old, {"entries": old["entries"]}, "same-depth:%d" % count, True)

    def test_generated_topology_preservation(self):
        rng = random.Random(480849)
        alphabet = ["a", "b", "same-prefix", "Å", "A\u030a", "中文", "😀", "...", "\\x"]
        for case in range(250):
            roots = [rng.choice(["/", "//"]) + "/".join(rng.choice(alphabet)
                     for _ in range(rng.randrange(1, 6))) for _ in range(rng.randrange(1, 9))]
            old_entries = {root: {} for root in roots}
            after = {"entries": dict(old_entries)}
            for root in roots:
                child = root + "/child"
                after["entries"][child] = {}
                if rng.choice([True, False]):
                    old_entries[child] = {}
            self.compare({"roots": roots, "entries": old_entries}, after, "generated:%d" % case)


if __name__ == "__main__":
    started = time.monotonic()
    suite = unittest.TestSuite([
        unittest.defaultTestLoader.loadTestsFromTestCase(SourceParentDifferentialTests),
        unittest.defaultTestLoader.loadTestsFromTestCase(ScopeTopologySubgraphTests),
    ])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {"schema": "hepta.offline.derived-topology-differential.v1",
              "state": "PASS" if result.wasSuccessful() else "FAIL", "tests_run": result.testsRun,
              "source_parent_inventory": current_suite.REPORT, "scope_topology_subgraph": SCOPE_REPORT,
              "elapsed_seconds": time.monotonic() - started, "python": sys.version,
              "platform": platform.platform(), "complete_scope_execution_in_this_report": False,
              "complete_scope_execution_report": "reports/scope-full-mac-results.json",
              "runtime_admission": False, "native_case_credit": 0,
              "production_selector_implemented": False, "validation_result_cache": False,
              "whole_stage_budget_verified": False,
              "synthetic_only": os.environ.get("HEPTA_TOPOLOGY_SYNTHETIC_ONLY") == "1",
              "skipped_tests": [{"test": str(test), "reason": reason} for test, reason in result.skipped],
              "failures": [{"test": str(test), "traceback": trace}
                           for test, trace in result.failures + result.errors]}
    report_path = BASE / ("reports/derived-differential-synthetic-results.json" if report["synthetic_only"]
                          else "reports/derived-differential-results.json")
    report_path.write_text(
        json.dumps(report, sort_keys=True, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"state": report["state"], "tests_run": result.testsRun,
          "source_parent_inventory_comparisons": current_suite.REPORT["inventory_comparisons"],
          "source_parent_topology_comparisons": current_suite.REPORT["topology_comparisons"],
          "scope_subgraph_comparisons": SCOPE_REPORT["comparisons"],
          "elapsed_seconds": report["elapsed_seconds"]}, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
