#!/usr/bin/env python3
"""Portable source-construction, identity, rejection, and pure-binding checks.

This does not run retained phone work or turn a saved result into an admission.
Reports are written only to an explicit --report path, never over raw evidence.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import types
import unittest

from harness import (BASE, directory_inventory, file_inventory, fixtures,
                     load_inventory, original_common, outcome, pin)


SELECTOR_PIN = {"bytes": 11956, "sha256": "de7dc784654dec65f0e6d2d7fd81918caf9c3c634d152295c1fb7928cf04a5c2"}
SOURCES = {
    "r7-reader": "originals/verify_retained_preaccept_r7.original.py",
    "r8-reader": "originals/verify_retained_staged_r8.original.py",
    "r8-scope": "originals/retained_r8_scope.original.py",
    "r9-reader": "originals/verify_retained_transport_r9.original.py",
    "r9-scope": "originals/retained_r9_scope.original.py",
}
DERIVED_PINS = {
    "r7-reader": {"bytes": 37442, "sha256": "9c8c09cd0296d769f255876253ddd88d7b607c99d2ac1a924f297855a279ae52"},
    "r8-reader": {"bytes": 96044, "sha256": "df682dd96ec97ee0371d054d18f57a6ea421fd6cac81195236095ef5fa8c8727"},
    "r8-scope": {"bytes": 22151, "sha256": "520f0f9a1eab1de60a165908536c03559f3bc49214a3e74b4c5d9036197619ed"},
    "r9-reader": {"bytes": 34737, "sha256": "8d582d044e3e80bbc824ec6878927825b1a04cae7f4efbedd76ed8b7e53020d7"},
    "r9-scope": {"bytes": 37770, "sha256": "5c6ae675180c119b1cca647dc486638abe6f3a9b6ace3cd67bf17099ed06e9cf"},
}
ENTRYPOINTS = {"r7-reader": "verify_retained_preaccept_archive",
    "r8-reader": "verify_retained_staged_archive", "r8-scope": "verify_complete_scope",
    "r9-reader": "verify_retained_transport_archive", "r9-scope": "verify_failed_r9_scope"}
REPORT = {"schema": "hepta.offline.reader-selector-portable-tests.v1",
          "constructed_modules": [], "rejected_source_or_binding_cases": 0,
          "inventory_comparisons": 0, "retained_inventory_comparisons": 0,
          "source_only": True, "phone_calls": 0, "runtime_admission": False,
          "native_case_credit": 0, "validation_result_cache": False,
          "whole_stage_budget_verified": False, "production_selector_adopted": False}


def load(raw, name):
    result = types.ModuleType(name)
    result.__file__ = "<portable-" + name + ">"
    exec(compile(raw, result.__file__, "exec"), result.__dict__)
    return result


class SelectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (BASE / "candidate/derived/reader_selector.py").read_bytes()
        assert pin(cls.raw) == SELECTOR_PIN
        cls.m = load(cls.raw, "UNADOPTED_portable_selector")
        cls.loader = load((BASE / "candidate/derived/bound_selector_loader.py").read_bytes(),
                          "UNADOPTED_bound_selector_loader")
        cls.inventory = cls.m.function_source((BASE / "candidate/inventory_value.py").read_bytes(),
                                              "inventory_value")
        cls.scope = cls.m.function_source(
            (BASE / "candidate/derived/retained_r8_verify_complete_scope.py").read_bytes(),
            "verify_complete_scope")

    def selector(self):
        return self.loader.make_selector(selector_source=self.raw,
            implementation_source=self.raw, inventory_function=self.inventory, scope_function=self.scope)

    def test_loader_binds_actual_compiled_source_to_declared_implementation(self):
        self.assertEqual(self.selector().receipt()["selector_source"], SELECTOR_PIN)
        for actual, declared, reason in [
                (self.raw, self.raw + b"\n", "declared implementation source must be the exact bytes loaded as selector code"),
                (self.raw, b"unrelated source", "declared implementation source must be the exact bytes loaded as selector code"),
                (self.raw, self.raw.decode(), "declared implementation source must be the exact bytes loaded as selector code"),
                (self.raw[:-1], self.raw[:-1], "actual selector bytes must match the independently pinned implementation"),
                (self.raw.decode(), self.raw, "actual selector bytes must match the independently pinned implementation")]:
            self.rejects(lambda: self.loader.make_selector(selector_source=actual,
                implementation_source=declared, inventory_function=self.inventory, scope_function=self.scope), reason)

    def rejects(self, call, message):
        with self.assertRaisesRegex(ValueError, "^" + re.escape(message) + "$"):
            call()
        REPORT["rejected_source_or_binding_cases"] += 1

    def test_all_five_module_constructors_keep_distinct_identity_and_fresh_globals(self):
        selected = self.selector()
        for kind, path in SOURCES.items():
            source = (BASE / path).read_bytes()
            self.assertEqual(pin(source), self.m.PINS[kind])
            old = load(source, "old_" + kind)
            before = dict(old.__dict__)
            new = getattr(selected, kind.replace("-", "_"))(source)
            self.assertEqual(new.__reference_source_identity__, self.m.PINS[kind])
            self.assertEqual(new.__derived_implementation_identity__, DERIVED_PINS[kind])
            self.assertIn(DERIVED_PINS[kind]["sha256"], new.__file__)
            self.assertTrue(new.__name__.startswith("UNADOPTED_derived_"))
            self.assertNotEqual(new.__file__, old.__file__)
            self.assertNotIn("__reviewed_source_sha256__", new.__dict__)
            self.assertIs(getattr(new, ENTRYPOINTS[kind]).__globals__, new.__dict__)
            self.assertIsNot(getattr(new, ENTRYPOINTS[kind]).__globals__, old.__dict__)
            self.assertEqual(set(old.__dict__), set(before))
            self.assertTrue(all(old.__dict__[key] is value for key, value in before.items()))
            self.assertEqual((BASE / path).read_bytes(), source)
        rows = selected.receipt()["constructions"]
        self.assertEqual(len(rows), 5)
        self.assertTrue(all(row["whole_byte_inverse_verified"] for row in rows))
        REPORT["constructed_modules"] = rows

    def test_all_constructor_original_pins_fail_closed(self):
        selected = self.selector()
        for kind, path in SOURCES.items():
            raw = (BASE / path).read_bytes()
            method = getattr(selected, kind.replace("-", "_"))
            for bad in (raw[:-1], raw + b"\n", raw[:-2] + b"X" + raw[-1:]):
                with self.assertRaises(ValueError):
                    method(bad)
                REPORT["rejected_source_or_binding_cases"] += 1
        self.assertEqual(selected.constructions, [])

    def test_candidate_function_identity_is_fixed_before_construction(self):
        for field, raw in (("inventory_function", self.inventory), ("scope_function", self.scope)):
            for bad in (raw[:-1], raw + b"\n"):
                values = {"inventory_function": self.inventory, "scope_function": self.scope,
                          "implementation_source": self.raw}
                values[field] = bad
                with self.assertRaises(ValueError):
                    self.m.OfflineDerivedSelector(**values)
                REPORT["rejected_source_or_binding_cases"] += 1

    def test_derived_transformation_requires_unique_site_and_exact_whole_inverse(self):
        self.assertEqual(self.m.derive(b"A old Z", [("one", b"old", b"new")]), b"A new Z")
        for raw, changes in [(b"missing", [("one", b"old", b"new")]),
                             (b"old old", [("one", b"old", b"new")]),
                             (b"old new", [("one", b"old", b"new")])]:
            with self.assertRaises(ValueError):
                self.m.derive(raw, changes)
            REPORT["rejected_source_or_binding_cases"] += 1

    def test_inventory_source_context_and_namespace_are_checked_before_execution(self):
        selected = self.selector()
        source = (BASE / "originals/source_parent_late_boundary_r4.original.py").read_bytes()
        namespace = {"C": original_common(), "Path": Path, "re": re, "stat": stat}
        for bad_source, context in [(source[:-1], "source-parent-inventory-only"),
                                    (source, "current-inventory-only"), (source, "unknown")]:
            self.rejects(lambda: selected.inventory_function(bad_source, namespace=namespace, context=context),
                         "exact original inventory source for declared selector context")
        variants = [{**namespace, "extra": 1}, {k: v for k, v in namespace.items() if k != "C"},
                    {**namespace, "Path": lambda value: Path(value)},
                    {**namespace, "re": object()}, {**namespace, "stat": object()}]
        for bad in variants:
            self.rejects(lambda: selected.inventory_function(source, namespace=bad,
                         context="source-parent-inventory-only"),
                         "same explicit pure inventory binding names and POSIX standard library objects")
        self.assertEqual(selected.constructions, [])

    def test_current_and_source_parent_bindings_recompute_acceptance_and_rejection(self):
        cases = [directory_inventory(roots) for roots in [
            ["/a", "//a"], ["/", "//a"], ["//", "/a"], ["/a", "/a/child"],
            ["//", "//a"], ["/a", "/a"], ["/Å", "/A\u030a", "/中文", "/😀"],
            ["/same/depth/r-%02d" % i for i in range(64)],
            ["/same/depth/r-%02d" % i for i in range(65)], ["/a/.."], ["///a"], ["/a/"]]]
        cases.extend([file_inventory(), {**file_inventory(), "unexpected": True}])
        first_bad = file_inventory()
        first_bad["roots"] += [first_bad["roots"][0]]
        first_bad["entries"]["/scope/file-00"]["bytes"] = -1
        cases.append(first_bad)
        for context, path in [("source-parent-inventory-only", "originals/source_parent_late_boundary_r4.original.py"),
                              ("current-inventory-only", "originals/late_boundary.r10.original.py")]:
            raw = (BASE / path).read_bytes()
            namespace = {"C": original_common(), "Path": Path, "re": re, "stat": stat}
            before = dict(namespace)
            selector = self.selector()
            new = selector.inventory_function(raw, namespace=namespace, context=context)
            old = load_inventory(raw, "<unchanged-original-pure-inventory>")
            for value in cases:
                self.assertEqual(outcome(old, value), outcome(new, value))
                REPORT["inventory_comparisons"] += 1
            # A valid result does not suppress the next invalid input's checks.
            self.assertTrue(outcome(new, file_inventory())["accepted"])
            self.assertFalse(outcome(new, first_bad)["accepted"])
            self.assertEqual(namespace, before)
            self.assertIsNot(new.__globals__, namespace)
            self.assertNotIn("__builtins__", namespace)
            self.assertEqual(len(selector.constructions), 1)

    def test_actual_retained_3991_entry_inventory_binding_if_private_fixtures_enabled(self):
        real = fixtures()
        if not real:
            self.skipTest("explicit synthetic-only run: private original inventories not loaded")
        for context, path in [("source-parent-inventory-only", "originals/source_parent_late_boundary_r4.original.py"),
                              ("current-inventory-only", "originals/late_boundary.r10.original.py")]:
            raw = (BASE / path).read_bytes()
            selector = self.selector()
            new = selector.inventory_function(raw,
                namespace={"C": original_common(), "Path": Path, "re": re, "stat": stat}, context=context)
            old = load_inventory(raw, "<exact-original-inventory>")
            for row, value in real:
                self.assertEqual((len(value["roots"]), len(value["entries"])), (49, 3991))
                self.assertEqual(outcome(old, value), outcome(new, value))
                REPORT["retained_inventory_comparisons"] += 1

    def test_r8_explicit_scope_selector_after_original_embedded_pin_check(self):
        selected = self.selector()
        reader = selected.r8_reader((BASE / SOURCES["r8-reader"]).read_bytes())
        original_modules = copy.deepcopy(reader.MODULES)
        scope = reader.load_module("scope")
        self.assertEqual(scope.__derived_implementation_identity__, DERIVED_PINS["r8-scope"])
        self.assertEqual(reader.MODULES, original_modules)
        self.assertEqual(len(selected.constructions), 2)
        # This is a private new test module, not any historical module object.
        reader.MODULES["scope"] = {**reader.MODULES["scope"], "sha256": "0" * 64}
        self.rejects(lambda: reader.load_module("scope"), "one complete unchanged pure-reader module")
        self.assertEqual(len(selected.constructions), 2)

    def test_construction_receipt_is_separate_and_cannot_award_runtime_credit(self):
        selected = self.selector()
        reader = selected.r9_reader((BASE / SOURCES["r9-reader"]).read_bytes())
        receipt = selected.receipt()
        self.assertEqual(receipt["selector_source"], SELECTOR_PIN)
        for key in ("validation_result_cache", "live_observation_cache", "runtime_admission",
                    "production_selector_adopted", "whole_stage_budget_verified",
                    "original_module_globals_reassigned", "original_source_bytes_changed"):
            self.assertIs(receipt[key], False)
        self.assertEqual(receipt["native_case_credit"], 0)
        self.assertEqual(receipt["production_policy_status"], "HOLD")
        self.assertEqual(receipt["source_parent_boundary_reader_status"], "HOLD_REQUIRES_NEW_PROVENANCE_POLICY")
        self.assertTrue(receipt["new_validator_implementation_identity"])
        self.assertEqual(len(receipt["constructions"]), 1)
        self.assertIs(reader.__derived_selector__, selected)
        self.assertFalse(any(name in selected.__dict__ for name in ("results", "cache", "PASS", "observations")))

    def test_frozen_v1_file_identities_are_unchanged(self):
        value = json.loads((BASE / "PORTABLE-DELIVERY-MANIFEST-v1.json").read_text())
        rows = value["files"]
        for row in rows:
            self.assertEqual(pin((BASE / row["path"]).read_bytes()),
                             {key: row[key] for key in ("bytes", "sha256")})
        self.assertEqual(len(rows), 35)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    began = time.monotonic()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SelectorTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {**REPORT, "state": "PASS" if result.wasSuccessful() else "FAIL",
        "tests_run": result.testsRun, "skips": [{"test": str(test), "reason": reason} for test, reason in result.skipped],
        "failure_count": len(result.failures), "error_count": len(result.errors),
        "elapsed_seconds": time.monotonic() - began,
        "synthetic_only": os.environ.get("HEPTA_TOPOLOGY_SYNTHETIC_ONLY") == "1"}
    if args.report:
        # The caller supplies a scratch output, not the retained Mac originals.
        if args.report.exists():
            raise ValueError("portable report destination already exists; preserve existing evidence")
        args.report.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
