from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from tools.tests.test_g1_evidence import (
    CANDIDATE,
    GAP_REGISTER,
    G1EvidenceTest,
    NOW,
    SOURCE_COMMIT,
)

import sys

EVIDENCE_TOOLS = Path(__file__).resolve().parents[2] / "tools" / "evidence"
if str(EVIDENCE_TOOLS) not in sys.path:
    sys.path.insert(0, str(EVIDENCE_TOOLS))

from g1_evidence import (  # noqa: E402
    EvidenceError,
    package_id,
    verify_evidence_directory,
    write_json,
)


class G1EvidenceLiveHardeningTest(unittest.TestCase):
    def setUp(self) -> None:
        helper = G1EvidenceTest(methodName="runTest")
        helper.setUp()
        self.helper = helper
        self.base = deepcopy(helper.base)

    @staticmethod
    def resign(package: dict) -> dict:
        package["package_id"] = ""
        package["package_id"] = package_id(package)
        return package

    def verify_single(self, package: dict, *, now: datetime = NOW):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            write_json(directory / "package.json", package)
            return verify_evidence_directory(
                directory,
                GAP_REGISTER,
                current_source_commit=SOURCE_COMMIT,
                now=now,
            )

    def test_package_cannot_outlive_authorization(self) -> None:
        package = deepcopy(self.base)
        package["authorization"]["expires_at"] = "2026-09-15T00:00:00Z"
        self.resign(package)
        with self.assertRaisesRegex(EvidenceError, "outlives its authorization"):
            self.verify_single(package)

    def test_package_cannot_outlive_artifact_retention(self) -> None:
        package = deepcopy(self.base)
        package["artifacts"][0]["retention_expires_at"] = "2026-09-15T00:00:00Z"
        self.resign(package)
        with self.assertRaisesRegex(EvidenceError, "outlives artifact"):
            self.verify_single(package)

    def test_expired_authorization_fails_even_when_package_is_unexpired(self) -> None:
        package = deepcopy(self.base)
        package["authorization"]["expires_at"] = "2026-09-03T00:00:00Z"
        self.resign(package)
        with self.assertRaisesRegex(EvidenceError, "authorization expired"):
            self.verify_single(
                package,
                now=datetime(2026, 9, 4, tzinfo=timezone.utc),
            )

    def test_future_created_package_fails_closed(self) -> None:
        package = deepcopy(self.base)
        package["created_at"] = "2026-09-10T00:00:00Z"
        self.resign(package)
        with self.assertRaisesRegex(EvidenceError, "created in the future"):
            self.verify_single(package)

    def test_complete_child_cannot_use_hold_parent(self) -> None:
        parent = deepcopy(self.base)
        parent["status"] = "HOLD"
        parent["artifacts"] = []
        parent["observations"] = {"exact_head_checks_passed": True}
        parent["roles"] = {
            "producer": None,
            "operator": None,
            "reviewer": None,
            "authorizer": None,
        }
        parent["authorization"] = {
            "status": "PENDING",
            "authority": "github_pull_request_review",
            "scope": "pending source qualification",
            "expires_at": parent["expires_at"],
            "revoked": False,
            "evidence_id": "pending-review",
        }
        parent["holds"] = [
            {
                "field": "independent_non_author_approval",
                "status": "NOT_OBSERVED",
                "reason": "No exact-head independent approval is present.",
            }
        ]
        self.resign(parent)

        child = self.helper.l2_package()
        child["lineage"]["parent_package_ids"] = [parent["package_id"]]
        self.resign(child)

        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            write_json(directory / "l1-hold.json", parent)
            write_json(directory / "l2.json", child)
            with self.assertRaisesRegex(EvidenceError, "parent .* is not COMPLETE"):
                verify_evidence_directory(
                    directory,
                    GAP_REGISTER,
                    current_source_commit=SOURCE_COMMIT,
                    now=NOW,
                )

    def test_current_source_mismatch_yields_no_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            write_json(directory / "historical.json", self.base)
            report = verify_evidence_directory(
                directory,
                GAP_REGISTER,
                current_source_commit="f" * 40,
                now=NOW,
            )
            self.assertEqual(report["promotable_gaps"], {})
            self.assertFalse(report["all_gaps_promotable"])
            self.assertFalse(report["public_release"])
            self.assertFalse(report["automatic_redispatch"])


if __name__ == "__main__":
    unittest.main()
