#!/usr/bin/env python3
"""Negative gates for inert preparer scaffolding; synthetic inputs never admit."""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("unbound_preparer_binding", ROOT / "candidate/preparer_binding.py")
binding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binding)
ORIGINAL = (ROOT / "originals/prepare_native_bound_components_r10_fc33.original.py").read_bytes()
COUNTERS = {"negative_cases": 0, "unbound_entry_effects": {"source_reads": 0, "imports": 0, "nonces": 0, "writes": 0, "phone": 0}}


def synthetic_review_draft():
    """Synthetic byte/shape fixtures, explicitly not actual freeze/admission."""
    value = binding.binding_template()
    value["state"] = "ORIGINALS_SUPPLIED_FOR_REVIEW"
    value["labels"] = {"NEG-01": "synthetic-next-neg01-01", "NEG-02": "synthetic-next-neg02-01"}
    originals = {}

    def row(role, raw):
        originals[role] = raw
        return {"path": "/synthetic-review-only/" + role.replace("/", "-") + ".original", **binding.pin(raw)}

    for name in binding.REQUIRED_ROLES:
        value["originals"][name] = row(name, ("SYNTHETIC_NOT_ACTUAL_" + name).encode())
    for name in binding.ADMISSION_NAMES:
        value["admission_sources"][name] = row("admission/" + name, ("SYNTHETIC_SOURCE_ONLY_" + name).encode())
    freeze = {
        "schema": "hepta.fc33.native-bound.actual-host-freeze.v1",
        "state": "FROZEN_FOR_NEW_NEG01_THEN_NEG02_NOT_QUALIFIED",
        "source": value["originals"]["actual_freezer_source"],
        "phone_calls": 0, "native_submissions": 0, "new_nonces": 0,
        "full19_qualified": False, "production_ready": False, "automatic_retry": False,
        "rollback_admission_is_separate_required_gate": True,
        "files": {"dependencies/admission/" + name + ".py": descriptor
                  for name, descriptor in value["admission_sources"].items()},
        "synthetic_review_fixture_not_actual_evidence": True,
    }
    value["originals"]["actual_freeze"] = row("actual_freeze", binding.encoded(freeze))
    return value, originals


class UnboundPreparerTests(unittest.TestCase):
    def reject(self, value, originals, message=None):
        if message:
            with self.assertRaisesRegex(binding.BindingError, message):
                binding.validate_binding_structure(value, originals)
        else:
            with self.assertRaises(binding.BindingError):
                binding.validate_binding_structure(value, originals)
        COUNTERS["negative_cases"] += 1

    def test_template_has_no_future_identities_or_execution_toggle(self):
        value = binding.binding_template()
        self.assertEqual(value["state"], "UNBOUND")
        self.assertTrue(all(x is None for x in value["originals"].values()))
        self.assertTrue(all(x is None for x in value["admission_sources"].values()))
        self.assertEqual(value["labels"], {"NEG-01": None, "NEG-02": None})
        self.reject(value, {}, "UNBOUND")
        for flag in ("runtime_admission", "production_adopted"):
            changed, raws = synthetic_review_draft()
            changed[flag] = True
            self.reject(changed, raws, "claim ceiling")

    def test_derive_preserves_reviewed_functions_and_all_original_bytes(self):
        generated, receipt = binding.derive_unbound_preparer(ORIGINAL)
        self.assertTrue(receipt["whole_byte_inverse_verified"])
        self.assertTrue(receipt["all_retained_function_class_bodies_unchanged"])
        self.assertNotEqual(receipt["original"], receipt["derived"])
        self.assertEqual(generated, (ROOT / "candidate/prepare_next_generation_UNBOUND.py").read_bytes())
        top = ast.parse(generated)
        assigned = {node.targets[0].id: node.value for node in top.body
                    if isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)}
        for name in binding.SLOTS:
            self.assertIsInstance(assigned[name], ast.Constant)
            self.assertIsNone(assigned[name].value)
        for altered in (ORIGINAL + b"\n", ORIGINAL[:-1], ORIGINAL.replace(b"import argparse", b"import socket", 1)):
            with self.assertRaisesRegex(binding.BindingError, "exact reviewed"):
                binding.derive_unbound_preparer(altered)
            COUNTERS["negative_cases"] += 1

    def test_generated_module_rejects_before_any_import_or_effect(self):
        generated, _ = binding.derive_unbound_preparer(ORIGINAL)
        def effect(name):
            def forbidden(*args, **kwargs):
                COUNTERS["unbound_entry_effects"][name] += 1
                raise AssertionError("forbidden effect before UNBOUND rejection: " + name)
            return forbidden
        # This executes only the new unconditional guard, never the preparer.
        namespace = {"__builtins__": {"RuntimeError": RuntimeError,
                    "__import__": effect("imports"), "open": effect("source_reads")},
                    "nonce_factory": effect("nonces"), "writer": effect("writes"), "phone": effect("phone")}
        with self.assertRaisesRegex(RuntimeError, binding.GUARD_REASON):
            exec(compile(generated, "<unbound-guard-test>", "exec"), namespace)
        self.assertEqual(COUNTERS["unbound_entry_effects"], {name: 0 for name in COUNTERS["unbound_entry_effects"]})
        self.assertNotIn("argparse", namespace)

    def test_prepare_rejects_before_even_inspecting_binding_or_callbacks(self):
        class Poison:
            def __iter__(self):
                raise AssertionError("unbound binding inspected")
            def __getitem__(self, key):
                raise AssertionError("unbound binding inspected")
        def forbidden(*args, **kwargs):
            raise AssertionError("disabled preparer called an effect callback")
        for state in (None, Poison(), synthetic_review_draft()[0]):
            with self.assertRaisesRegex(binding.UnboundPreparerError, binding.GUARD_REASON):
                binding.prepare(state, read_source=forbidden, nonce_factory=forbidden,
                                writer=forbidden, phone=forbidden)
            COUNTERS["negative_cases"] += 1

    def test_structural_review_cannot_grant_controller_admission_or_freshness(self):
        value, raws = synthetic_review_draft()
        result = binding.validate_binding_structure(value, raws)
        self.assertEqual(result["state"], "STRUCTURAL_REVIEW_ONLY_EXECUTION_DISABLED")
        for key in ("actual_controller_semantics_verified", "retained_R10_failure_semantics_verified",
                    "namespace_absence_or_freshness_verified", "complete_freeze_verified",
                    "runtime_admission", "production_adopted", "execution_enabled"):
            self.assertIs(result[key], False)
        self.assertTrue(result["pending_executable_semantics"])
        with self.assertRaises(binding.UnboundPreparerError):
            binding.prepare(value, raws)

    def test_old_consumed_and_prior_generation_labels_are_rejected(self):
        for label in sorted(binding.KNOWN_CONSUMED_LABELS | binding.OLD_GENERATION_LABELS):
            value, raws = synthetic_review_draft()
            value["labels"]["NEG-01"] = label
            self.reject(value, raws, "label")
        value, raws = synthetic_review_draft()
        value["labels"]["NEG-02"] = value["labels"]["NEG-01"]
        self.reject(value, raws, "distinct")

    def test_old_freeze_controller_and_namespace_cannot_be_relabelled(self):
        for role, original in (("actual_freeze", binding.OLD_FREEZE),
                               ("actual_freezer_source", binding.OLD_FREEZER),
                               ("actual_controller", binding.OLD_CONTROLLER)):
            value, raws = synthetic_review_draft()
            value["originals"][role].update(original)
            self.reject(value, raws, "old R10")
        value, raws = synthetic_review_draft()
        value["originals"]["actual_freeze"]["path"] = binding.OLD_FROZEN_ROOT + "/FREEZE-RESULT.json"
        self.reject(value, raws, "frozen R10 namespace")

    def test_each_actual_original_is_required_and_byte_bound(self):
        value, originals = synthetic_review_draft()
        for role in sorted(originals):
            missing = dict(originals)
            del missing[role]
            self.reject(value, missing, "every declared original")
            changed = dict(originals)
            changed[role] += b"\n"
            self.reject(value, changed, "original bytes differ")
        for role in binding.REQUIRED_ROLES:
            changed = copy.deepcopy(value)
            changed["originals"][role] = None
            self.reject(changed, originals, "complete exact original descriptor")

    def test_six_sources_must_exist_and_match_the_supplied_freeze(self):
        for name in binding.ADMISSION_NAMES:
            value, raws = synthetic_review_draft()
            del value["admission_sources"][name]
            self.reject(value, raws, "all six")
            value, raws = synthetic_review_draft()
            freeze = json.loads(raws["actual_freeze"])
            del freeze["files"]["dependencies/admission/" + name + ".py"]
            raws["actual_freeze"] = binding.encoded(freeze)
            value["originals"]["actual_freeze"].update(binding.pin(raws["actual_freeze"]))
            self.reject(value, raws, "six-source freeze linkage")

    def test_ambiguous_json_and_noncanonical_or_boolean_descriptors_are_rejected(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            with self.assertRaises(binding.BindingError):
                binding.strict_json(raw)
            COUNTERS["negative_cases"] += 1
        for path in ("relative", "/a/../b", "/a//b", "//a/b", "/a\x00b"):
            value, raws = synthetic_review_draft()
            value["originals"]["actual_freeze"]["path"] = path
            self.reject(value, raws, "canonical")
        value, raws = synthetic_review_draft()
        value["originals"]["actual_freeze"]["bytes"] = True
        self.reject(value, raws, "bounded exact")

    def test_rebuild_is_exact_and_does_not_overwrite_saved_products(self):
        result = subprocess.run([sys.executable, "-B", str(ROOT / "tools/build_candidate.py"), "--check"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["state"], "PASS_INERT_SOURCE_REBUILD_ONLY")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(UnboundPreparerTests))
    report = {"schema": "hepta.UNADOPTED.unbound-preparer-tests.v1",
              "state": "PASS" if result.wasSuccessful() else "FAIL", "tests_run": result.testsRun,
              "counters": COUNTERS, "effect_counter_scope": "disabled preparer entry only; static builder/test reads are not counted as runtime effects",
              "synthetic_binding_inputs_not_actual_evidence": True,
              "original_preparer_executed": False, "freeze_executed": False,
              "runtime_admission": False, "production_adopted": False,
              "failures": [{"test": str(case), "traceback": trace} for case, trace in result.failures + result.errors]}
    output = json.dumps(report, sort_keys=True, ensure_ascii=False, indent=2) + "\n"
    if args.report:
        with args.report.open("x", encoding="utf-8") as target:
            target.write(output)
    print(output, end="")
    raise SystemExit(0 if result.wasSuccessful() else 1)
