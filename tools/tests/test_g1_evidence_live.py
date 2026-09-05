from __future__ import annotations

from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]

from tools.tests.test_g1_evidence import (
    CANDIDATE,
    GAP_REGISTER,
    G1EvidenceTest,
    evidence_fixture_directory,
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
        with evidence_fixture_directory() as temp:
            directory = Path(temp)
            write_json(directory / "package.json", package)
            (
                attestation_path,
                attestation_sha256,
                attestation_signature_path,
                attestation_public_key_path,
                attestation_public_key_sha256,
            ) = G1EvidenceTest.write_trusted_attestation(
                directory.parent / "g1-live-attestation.json", [package]
            )
            return verify_evidence_directory(
                directory,
                GAP_REGISTER,
                current_source_commit=SOURCE_COMMIT,
                expected_subject=package["subject"],
                now=now,
                attestation_path=attestation_path,
                attestation_sha256=attestation_sha256,
                attestation_signature_path=attestation_signature_path,
                attestation_public_key_path=attestation_public_key_path,
                attestation_public_key_sha256=attestation_public_key_sha256,
                repository_root=ROOT,
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

        with evidence_fixture_directory() as temp:
            directory = Path(temp)
            write_json(directory / "l1-hold.json", parent)
            write_json(directory / "l2.json", child)
            (
                attestation_path,
                attestation_sha256,
                attestation_signature_path,
                attestation_public_key_path,
                attestation_public_key_sha256,
            ) = G1EvidenceTest.write_trusted_attestation(
                directory.parent / "g1-live-attestation.json", [child]
            )
            with self.assertRaisesRegex(EvidenceError, "parent .* is not COMPLETE"):
                verify_evidence_directory(
                    directory,
                    GAP_REGISTER,
                    current_source_commit=SOURCE_COMMIT,
                    expected_subject=child["subject"],
                    now=NOW,
                    attestation_path=attestation_path,
                    attestation_sha256=attestation_sha256,
                    attestation_signature_path=attestation_signature_path,
                    attestation_public_key_path=attestation_public_key_path,
                    attestation_public_key_sha256=attestation_public_key_sha256,
                    repository_root=ROOT,
                )

    def test_current_source_mismatch_yields_no_promotion(self) -> None:
        with evidence_fixture_directory() as temp:
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


class G1EvidenceFixtureIsolationTest(unittest.TestCase):
    """Real fixture signatures; no target qualification or verifier weakening."""

    def setUp(self) -> None:
        self.case = G1EvidenceLiveHardeningTest(methodName="runTest")
        self.case.setUp()
        # Contain deliberate old-code collision reproductions within this test.
        storage = tempfile.TemporaryDirectory(prefix="g1-fixture-isolation-")
        self.addCleanup(storage.cleanup)
        patcher = mock.patch.object(tempfile, "tempdir", storage.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.storage = Path(storage.name)

    def test_overlapping_verifications_keep_independent_signature_material(self) -> None:
        first = deepcopy(self.case.base)
        second = deepcopy(first)
        second["authorization"]["scope"] += " second fixture"
        self.case.resign(second)
        first_written, second_written = threading.Event(), threading.Event()
        writer = G1EvidenceTest.write_trusted_attestation
        paths = []

        def write(path, packages):
            is_first = packages[0]["package_id"] == first["package_id"]
            if not is_first and not first_written.wait(15):
                raise AssertionError("first signing fixture never completed")
            result = writer(path, packages)
            paths.append(path)
            if is_first:
                first_written.set()
                if not second_written.wait(15):
                    raise AssertionError("second signing fixture never completed")
            else:
                second_written.set()
            return result

        with mock.patch.object(G1EvidenceTest, "write_trusted_attestation", side_effect=write):
            with ThreadPoolExecutor(max_workers=2) as workers:
                futures = [workers.submit(self.case.verify_single, package)
                           for package in (first, second)]
                reports = [future.result(timeout=30) for future in futures]
        self.assertTrue(all(report["promotable_gaps"] for report in reports))
        self.assertEqual(len({path.parent for path in paths}), 2)
        self.assertEqual(list(self.storage.iterdir()), [])

    def test_core_negative_case_cleans_receipt_signature_and_test_keys(self) -> None:
        # The original signature-negative assertion must still execute and pass.
        case = G1EvidenceTest(methodName="test_attestation_signature_tampering_is_rejected")
        result = unittest.TestResult()
        case.run(result)
        self.assertTrue(result.wasSuccessful(), result.errors + result.failures)
        self.assertEqual(result.testsRun, 1)
        self.assertEqual(list(self.storage.iterdir()), [])

    def test_signing_failure_cleans_partial_detached_material(self) -> None:
        writer = G1EvidenceTest.write_trusted_attestation
        def fail_after_signing(path, packages):
            writer(path, packages)
            raise OSError("injected fixture signing failure")
        with mock.patch.object(G1EvidenceTest, "write_trusted_attestation", side_effect=fail_after_signing):
            with self.assertRaisesRegex(OSError, "injected fixture signing failure"):
                self.case.verify_single(self.case.base)
        self.assertEqual(list(self.storage.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
