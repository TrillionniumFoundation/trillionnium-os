from __future__ import annotations

import unittest

from tools.g1_pr_aggregate_model import REQUIREMENTS
from tools.g1_pr_aggregate_workflow import _verify_workflow


class SourceGateBoundaryTest(unittest.TestCase):
    def test_ordinary_pr_requires_the_real_synthetic_source_workflow(self) -> None:
        self.assertEqual(len(REQUIREMENTS), 1)
        requirement = REQUIREMENTS[0]
        self.assertEqual(requirement.filename, "g1-synthetic-merge.yml")
        self.assertEqual(requirement.workflow_name, "G1 synthetic-merge qualification")
        self.assertEqual(
            requirement.job_names,
            frozenset({"L1 exact two-parent merge source qualification"}),
        )
        self.assertEqual(requirement.artifact_kind, "synthetic")

    def test_gate_excludes_promotion_and_release_workflows(self) -> None:
        forbidden = {
            "g1-review-index-receipts.yml",
            "g1-evidence-intake.yml",
            "g1-android-privilege-matrix.yml",
        }
        self.assertTrue(forbidden.isdisjoint({item.filename for item in REQUIREMENTS}))

    def test_workflow_implementation_has_no_retired_receipt_import(self) -> None:
        # Importing this module is part of the production aggregate path. This
        # regression prevents deletion of a retired receipt helper from leaving
        # a dormant top-level import that fails before any live verification.
        self.assertTrue(callable(_verify_workflow))


if __name__ == "__main__":
    unittest.main()
