"""Hostile tests for the machine metric authority and generated status view."""
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from tools.docs import generate_global_docs as generator
from tools.docs import verify_global_docs as verifier

ROOT = Path(__file__).resolve().parents[2]


def catalog() -> dict:
    return json.loads(
        (ROOT / "docs/machine/metric-catalog.v1.json").read_text(encoding="utf-8")
    )


def modules() -> set[str]:
    value = json.loads(
        (ROOT / "docs/machine/module-catalog.v1.json").read_text(encoding="utf-8")
    )
    return {item["id"] for item in value["modules"]}


class MetricCatalogTests(unittest.TestCase):
    def test_checked_in_catalog_is_complete_and_generated(self) -> None:
        names = verifier.verify_metric_catalog(catalog(), modules())
        self.assertGreaterEqual(len(names), 40)
        status = generator.metric_status()
        self.assertIn("# Metric Status", status)
        self.assertIn("`broker.accept.duration_ms`", status)
        self.assertIn("Semantic authority: `false`", status)

    def test_semantic_authority_and_active_mode_fail_closed(self) -> None:
        value = catalog()
        value["semantic_authority"] = True
        with self.assertRaisesRegex(verifier.VerificationError, "semantic authority"):
            verifier.verify_metric_catalog(value, modules())
        value = catalog()
        value["activation_ceiling"] = "ACTIVE"
        with self.assertRaisesRegex(verifier.VerificationError, "SHADOW"):
            verifier.verify_metric_catalog(value, modules())

    def test_sensitive_dimension_or_metric_vocabulary_fails_closed(self) -> None:
        value = catalog()
        value["metrics"][0]["forbidden_dimensions"].remove("credential")
        with self.assertRaisesRegex(verifier.VerificationError, "sensitive dimension"):
            verifier.verify_metric_catalog(value, modules())
        value = catalog()
        value["metrics"][0]["name"] = "broker.command.duration_ms"
        with self.assertRaisesRegex(verifier.VerificationError, "sensitive vocabulary"):
            verifier.verify_metric_catalog(value, modules())

    def test_unknown_module_clock_and_missing_data_meaning_fail_closed(self) -> None:
        for field, replacement, message in (
            ("source_module", "MOD-NOT-REAL", "unknown source module"),
            ("clock_source", "WALL_CLOCK", "clock source"),
            ("missing_data", "ZERO", "missing-data"),
        ):
            value = catalog()
            value["metrics"][0][field] = replacement
            with self.subTest(field=field):
                with self.assertRaisesRegex(verifier.VerificationError, message):
                    verifier.verify_metric_catalog(value, modules())

    def test_duplicate_unsorted_and_missing_required_metric_fail_closed(self) -> None:
        value = catalog()
        value["metrics"].append(copy.deepcopy(value["metrics"][0]))
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_metric_catalog(value, modules())
        value = catalog()
        value["metrics"][0], value["metrics"][1] = value["metrics"][1], value["metrics"][0]
        with self.assertRaisesRegex(verifier.VerificationError, "name-sorted"):
            verifier.verify_metric_catalog(value, modules())
        value = catalog()
        value["metrics"] = [
            metric for metric in value["metrics"]
            if metric["name"] != "terminal.persistence.duration_ms"
        ]
        with self.assertRaisesRegex(verifier.VerificationError, "lacks required"):
            verifier.verify_metric_catalog(value, modules())

    def test_restricted_metric_requires_pseudonymous_digest(self) -> None:
        value = catalog()
        metric = next(
            item for item in value["metrics"]
            if item["privacy_class"] == "PSEUDONYMOUS_RESTRICTED"
        )
        metric["required_dimensions"].remove("ordering_key_digest")
        with self.assertRaisesRegex(verifier.VerificationError, "pseudonymous"):
            verifier.verify_metric_catalog(value, modules())


if __name__ == "__main__":
    unittest.main()
