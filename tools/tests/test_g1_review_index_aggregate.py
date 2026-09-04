"""Hostile aggregate tests for closed-world review-index receipts."""
from __future__ import annotations

from copy import deepcopy
import unittest

from tools.tests.g1_pr_aggregate_fixture import AGG, AggregateFixture


class ReviewIndexAggregateTest(AggregateFixture):
    def test_receipt_workflow_is_separately_bound(self) -> None:
        report = self.verify()
        self.assertEqual(
            report["local_source"]["review_index"]["sha256"],
            self.review_index_sha,
        )

    def test_review_index_digest_drift_fails(self) -> None:
        exact = deepcopy(self.exact_review_receipt)
        exact["review_index_sha256"] = "0" * 64
        raw = self._zip({
            "g1-exact-head-review-index-receipt.json": exact,
            "g1-synthetic-merge-review-index-receipt.json": self.synthetic_review_receipt,
        })
        self._replace_artifact_blob(1004, 0, raw)
        with self.assertRaisesRegex(AGG.AggregateError, "bindings differ|review-index digest"):
            self.verify()

    def test_review_index_inventory_drift_fails(self) -> None:
        exact = deepcopy(self.exact_review_receipt)
        synthetic = deepcopy(self.synthetic_review_receipt)
        for receipt in (exact, synthetic):
            receipt["path_count"] += 1
            receipt["change_count"] += 1
        raw = self._zip({
            "g1-exact-head-review-index-receipt.json": exact,
            "g1-synthetic-merge-review-index-receipt.json": synthetic,
        })
        self._replace_artifact_blob(1004, 0, raw)
        with self.assertRaisesRegex(AGG.AggregateError, "path count differs"):
            self.verify()

    def test_synthetic_parent_splice_fails(self) -> None:
        synthetic = deepcopy(self.synthetic_review_receipt)
        synthetic["parent_commits"] = [self.head_commit, self.base_commit]
        raw = self._zip({
            "g1-exact-head-review-index-receipt.json": self.exact_review_receipt,
            "g1-synthetic-merge-review-index-receipt.json": synthetic,
        })
        self._replace_artifact_blob(1004, 0, raw)
        with self.assertRaisesRegex(AGG.AggregateError, "parent order mismatch"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
