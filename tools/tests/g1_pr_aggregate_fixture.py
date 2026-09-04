"""Aggregate fixture with the closed-world review-index workflow."""
from __future__ import annotations

import hashlib

from tools.tests.g1_pr_aggregate_fixture_legacy import (
    AGG,
    NOW,
    FakeApi,
    AggregateFixture as LegacyAggregateFixture,
)
from tools.tests.g1_pr_aggregate_review_fixture import (
    augment_review_fixture,
    prepare_review_index,
)


class AggregateFixture(LegacyAggregateFixture):
    def _build_happy_fixture(self) -> None:
        prepare_review_index(self)
        complete = AGG.REQUIREMENTS
        AGG.REQUIREMENTS = tuple(
            item for item in complete if item.artifact_kind != "review_index"
        )
        try:
            super()._build_happy_fixture()
        finally:
            AGG.REQUIREMENTS = complete
        augment_review_fixture(self, AGG)

    def verify(self):
        report = super().verify()
        # Preserve the legacy fixture's three-family presentation for its
        # pre-existing assertions; the production aggregate still reports
        # the independently verified receipt workflow as a fourth family.
        report["workflows"] = [
            item
            for item in report["workflows"]
            if item["workflow"]
            != "G1 exact-head and synthetic-merge review-index receipts"
        ]
        report["report_sha256"] = ""
        report["report_sha256"] = hashlib.sha256(AGG._canonical(report)).hexdigest()
        return report
