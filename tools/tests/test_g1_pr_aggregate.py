from __future__ import annotations

import unittest

from tools.g1_pr_aggregate_model import REQUIREMENTS


class SourceGateBoundaryTest(unittest.TestCase):
    def test_ordinary_pr_has_no_cross_workflow_requirements(self) -> None:
        self.assertEqual(REQUIREMENTS, ())

    def test_gate_does_not_reintroduce_review_receipt_modules(self) -> None:
        # The final source gate is intentionally independent of review-index,
        # evidence-receipt, Android/device and release qualification workflows.
        forbidden = {
            "review-index-receipts",
            "evidence-intake",
            "android-privilege-matrix",
            "synthetic-merge-receipts",
        }
        self.assertTrue(forbidden.isdisjoint({item.filename for item in REQUIREMENTS}))


if __name__ == "__main__":
    unittest.main()
