"""Regression tests for the G1 gap-to-evidence routing table."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools import verify_g1_gap_routing as verifier


ROOT = Path(__file__).resolve().parents[2]


class GapRoutingTests(unittest.TestCase):
    def test_checked_in_routing_covers_every_gap(self) -> None:
        report = verifier.verify(ROOT)
        self.assertEqual(report["status"], "PASS_COMPLETE_LEVEL_CORRECT_ROUTING")
        self.assertEqual(report["gap_count"], 21)
        self.assertEqual(
            report["reachable_target_evidence_kinds"],
            sorted(verifier.TARGET_KIND_LEVEL),
        )
        self.assertFalse(report["capture_can_change_status"])
        self.assertFalse(report["promotion_authorized"])

    def test_duplicate_json_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text('{"schema":"one","schema":"two"}', encoding="utf-8")
            with self.assertRaises(verifier.RoutingError):
                verifier.load(path)

    def test_each_non_l1_route_matches_its_fixed_kind_level(self) -> None:
        routing = verifier.load(ROOT / "governance/gap-evidence-routing.v1.json")
        for route in routing["routes"]:
            if route["exit_level"] == "L1":
                self.assertTrue(set(route["evidence_kinds"]) <= verifier.L1_KINDS)
                continue
            for kind in route["evidence_kinds"]:
                self.assertEqual(verifier.TARGET_KIND_LEVEL[kind], route["exit_level"])

    def test_route_order_and_set_match_canonical_register(self) -> None:
        routing = verifier.load(ROOT / "governance/gap-evidence-routing.v1.json")
        register = verifier.load(ROOT / "docs/machine/gap-register.v2.json")
        self.assertEqual(
            [route["gap_id"] for route in routing["routes"]],
            [gap["id"] for gap in register["gaps"]],
        )

    def test_l5_and_l6_require_distinct_authorizers(self) -> None:
        routing = verifier.load(ROOT / "governance/gap-evidence-routing.v1.json")
        by_id = {route["gap_id"]: route for route in routing["routes"]}
        for gap_id in ("GAP-JOURNAL-CONVERGENCE-001", "GAP-FAULT-MATRIX-001"):
            self.assertIn("destructive_authorizer", by_id[gap_id]["required_roles"])
        self.assertIn("release_authorizer", by_id["GAP-RELEASE-001"]["required_roles"])
        self.assertIn("signing_custodian", by_id["GAP-RELEASE-001"]["required_roles"])


if __name__ == "__main__":
    unittest.main()
