"""Regression tests for the concrete G1 module-contract graph gate."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.docs import verify_global_docs as verifier
from tools.docs import generate_global_docs as generator


ROOT = Path(__file__).resolve().parents[2]


def catalog() -> dict:
    return json.loads(
        (ROOT / "docs/machine/module-catalog.v1.json").read_text(encoding="utf-8")
    )


def evidence_index() -> dict:
    return json.loads(
        (ROOT / "docs/machine/evidence-index.v1.json").read_text(encoding="utf-8")
    )


class ModuleContractVerificationTests(unittest.TestCase):
    def test_checked_in_catalog_has_concrete_contracts(self) -> None:
        known = verifier.verify_modules(catalog())
        self.assertEqual(len(known), 16)

    def test_segmented_journal_modules_declare_v1_to_v2_fenced_migration(self) -> None:
        modules = {
            module["id"]: module for module in catalog()["modules"]
        }
        for module_id in ("MOD-TRANSPORT", "MOD-JOB-RUNTIME", "MOD-EVENT-STORE"):
            self.assertEqual(
                modules[module_id]["migration"],
                {
                    "from_versions": ["v1"],
                    "to_version": "v2",
                    "strategy": "fenced_prefix_reconcile",
                    "dual_read": False,
                    "dual_write": False,
                },
            )

    def test_missing_version_fails_closed(self) -> None:
        value = catalog()
        del value["modules"][0]["module_version"]
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_modules(value)

    def test_placeholder_resource_budget_fails_closed(self) -> None:
        value = catalog()
        value["modules"][0]["resource_contract"]["memory_bytes"] = 0
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_modules(value)

    def test_concurrency_is_bounded_by_module_budget_not_schema_ceiling(self) -> None:
        value = catalog()
        module = value["modules"][0]
        module["resource_contract"]["queue_items"] = 1
        module["concurrency_contract"]["max_concurrency"] = 2
        with self.assertRaisesRegex(verifier.VerificationError, "queue item budget"):
            verifier.verify_modules(value)

    def test_concurrency_equal_to_actual_admission_budget_is_allowed(self) -> None:
        value = catalog()
        module = value["modules"][0]
        module["resource_contract"]["queue_items"] = 16
        module["concurrency_contract"]["max_concurrency"] = 16
        verifier.verify_modules(value)

    def test_placeholder_api_type_fails_closed(self) -> None:
        value = catalog()
        value["modules"][0]["api_contract"]["inputs"] = ["typed_request"]
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_modules(value)

    def test_unimplemented_migration_strategy_fails_closed(self) -> None:
        value = catalog()
        value["modules"][0]["migration"] = {
            "from_versions": ["v1"],
            "to_version": "v2",
            "strategy": "invented_copy",
            "dual_read": False,
            "dual_write": False,
        }
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_modules(value)

    def test_unknown_open_gap_fails_closed(self) -> None:
        value = catalog()
        value["modules"][0]["open_gaps"].append("GAP-NOT-DECLARED-999")
        gaps = json.loads(
            (ROOT / "docs/machine/gap-register.v2.json").read_text(encoding="utf-8")
        )
        # Structural module checks run first; this assertion isolates the
        # cross-document reference gate from the rest of the verifier.
        verifier.verify_modules(value)
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_module_gap_refs(value, gaps)

    def test_malformed_gap_entry_fails_closed_without_indexing_crash(self) -> None:
        gaps = json.loads(
            (ROOT / "docs/machine/gap-register.v2.json").read_text(encoding="utf-8")
        )
        gaps["gaps"][0] = "not-an-object"
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_gaps(gaps, {module["id"] for module in catalog()["modules"]})

    def test_malformed_requirement_entry_fails_closed(self) -> None:
        graph = json.loads(
            (ROOT / "docs/machine/requirement-graph.v1.json").read_text(encoding="utf-8")
        )
        graph["requirements"][0] = None
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_requirements(graph, set(), set(), set(), set())

    def test_evidence_record_without_package_fails_closed(self) -> None:
        value = evidence_index()
        del value["records"][0]["package"]
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_evidence_index(value)

    def test_evidence_null_without_not_observed_hold_fails_closed(self) -> None:
        value = evidence_index()
        binding = value["records"][0]["package"]["binding"]
        binding["holds"] = [hold for hold in binding["holds"] if hold["field"] != "branch"]
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_evidence_index(value)

    def test_evidence_binding_identity_mismatch_fails_closed(self) -> None:
        value = evidence_index()
        value["records"][0]["package"]["binding"]["source_commit"] = "0" * 40
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_evidence_index(value)

    def test_malformed_evidence_hold_fails_closed(self) -> None:
        value = evidence_index()
        value["records"][0]["package"]["binding"]["holds"][0] = "not-an-object"
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_evidence_index(value)

    def test_observed_evidence_cannot_hide_unretained_fields(self) -> None:
        value = evidence_index()
        package = value["records"][0]["package"]
        package["status"] = "OBSERVED"
        package["binding"]["status"] = "OBSERVED"
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_evidence_index(value)


class ModuleGapProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = catalog()
        self.register = json.loads(
            (ROOT / "docs/machine/gap-register.v2.json").read_text(encoding="utf-8")
        )

    def check(self) -> None:
        verifier.verify_module_gap_refs(self.catalog, self.register)

    def test_checked_in_projection_is_complete(self) -> None:
        self.check()

    def test_removing_any_nonclosed_relationship_fails(self) -> None:
        # Enumerate the register, not the projection under test. This also
        # protects future gaps and external holds without a hard-coded list.
        modules = {module["id"]: module for module in self.catalog["modules"]}
        for gap in self.register["gaps"]:
            if gap["status"] == "CLOSED":
                continue
            for module_id in gap["modules"]:
                with self.subTest(gap=gap["id"], module=module_id):
                    original = list(modules[module_id]["open_gaps"])
                    modules[module_id]["open_gaps"] = [item for item in original if item != gap["id"]]
                    try:
                        with self.assertRaisesRegex(verifier.VerificationError, "missing open gap"):
                            self.check()
                    finally:
                        modules[module_id]["open_gaps"] = original

    def test_all_nonclosed_statuses_require_reverse_reference(self) -> None:
        gap = next(gap for gap in self.register["gaps"] if gap["status"] != "CLOSED")
        module = next(module for module in self.catalog["modules"] if module["id"] in gap["modules"])
        module["open_gaps"].remove(gap["id"])
        for status in ("OPEN", "SOURCE_CLOSED_PENDING_EVIDENCE", "EXTERNAL_HOLD"):
            gap["status"] = status
            with self.subTest(status=status):
                with self.assertRaisesRegex(verifier.VerificationError, "missing open gap"):
                    self.check()

    def test_closed_gap_is_not_required_as_open(self) -> None:
        gap = next(gap for gap in self.register["gaps"] if gap["status"] != "CLOSED")
        gap["status"] = "CLOSED"
        for module in self.catalog["modules"]:
            if gap["id"] in module["open_gaps"]:
                module["open_gaps"].remove(gap["id"])
        self.check()

    def test_closed_gap_cannot_remain_in_open_projection(self) -> None:
        gap = next(gap for gap in self.register["gaps"] if gap["status"] != "CLOSED")
        gap["status"] = "CLOSED"
        with self.assertRaisesRegex(verifier.VerificationError, "lists CLOSED gap"):
            self.check()

    def test_duplicate_gap_id_cannot_overwrite_required_edges(self) -> None:
        self.register["gaps"].append(dict(self.register["gaps"][0], status="CLOSED"))
        with self.assertRaisesRegex(verifier.VerificationError, "duplicate gap id"):
            self.check()

    def test_unknown_module_fails(self) -> None:
        self.register["gaps"][0]["modules"].append("MOD-UNKNOWN")
        with self.assertRaisesRegex(verifier.VerificationError, "unknown modules"):
            self.check()

    def test_unknown_status_fails(self) -> None:
        self.register["gaps"][0]["status"] = "ASSUMED_COMPLETE"
        with self.assertRaisesRegex(verifier.VerificationError, "invalid status"):
            self.check()

    def test_duplicate_projection_fails(self) -> None:
        module = next(module for module in self.catalog["modules"] if module["open_gaps"])
        module["open_gaps"].append(module["open_gaps"][0])
        with self.assertRaisesRegex(verifier.VerificationError, "duplicate"):
            self.check()

    def test_unrelated_gap_cannot_be_assigned_to_module(self) -> None:
        gap = self.register["gaps"][0]
        module = next(module for module in self.catalog["modules"] if module["id"] not in gap["modules"])
        module["open_gaps"].append(gap["id"])
        with self.assertRaisesRegex(verifier.VerificationError, "does not affect"):
            self.check()

    def test_recorded_baseline_is_not_presented_as_live_state(self) -> None:
        rendered = generator.current_state()
        baseline = json.loads((ROOT / "docs/machine/current-baseline.v1.json").read_text(encoding="utf-8"))
        self.assertIn("not live PR status", rendered)
        self.assertIn(baseline["observed_at"], rendered)
        self.assertIn("Recorded source CI", rendered)
        self.assertNotIn("| Latest source CI |", rendered)
        self.assertIn("newly retained exact-head report", rendered)


if __name__ == "__main__":
    unittest.main()
