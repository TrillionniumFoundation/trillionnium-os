from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-r5.py"
spec = importlib.util.spec_from_file_location("verify_owner_open_r5_gap", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

RELEASE_FIELDS = {
    "release_signature": {
        "manifest_sha256": "a" * 64,
        "signature": "detached-signature",
        "cryptographic_signature_verified": True,
        "certificate_identity": "release-cert",
        "oidc_issuer": "https://issuer.example",
        "oidc_subject": "release-bot",
        "transparency_log_entry": "rekor-entry-1",
    },
    "release_authorization": {
        "decision": "GO",
        "authorization_id": "approval-1",
        "authorized_by": "release-authority",
        "approved_at": "2026-08-29T12:00:00Z",
    },
}


def source_evidence() -> dict:
    return {
        "level": "L1",
        "branch": "codex/r5",
        "commit": "a" * 40,
        "tree": "b" * 40,
        "workflow_run_id": 123,
        "successful_jobs": ["source-check"],
        "artifacts": [
            {"id": 456, "name": "source-report", "digest": "sha256:" + "c" * 64}
        ],
    }


def environment_evidence(
    level: str,
    *,
    source_commit: str = "a" * 40,
    source_tree: str = "b" * 40,
    evidence_sha256: str = "b" * 64,
    kind: str = "reviewed-observation",
    reviewer: str = "independent-reviewer",
    synthetic: bool = False,
) -> dict:
    return {
        "level": level,
        "kind": kind,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "source_lock_sha256": "1" * 64,
        "target_or_device_identity": "target-fixture-01",
        "tool_and_artifact_sha256": "2" * 64,
        "command_or_operation_identity": "qualification-command-01",
        "raw_log_sha256": "3" * 64,
        "result_summary": "reviewed target observation",
        "evidence_sha256": evidence_sha256,
        "reviewer": reviewer,
        "synthetic": synthetic,
        "automatic_redispatch": False,
    }


class VerifyOwnerOpenR5GapClosureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for path in module.REQUIRED_R6_DOCS:
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("active\n", encoding="utf-8")
        self.status = {
            "schema": module.STATUS_SCHEMA,
            "active_plan_revision": module.ACTIVE_PLAN_REVISION,
            "zero_gap": False,
            "public_release": False,
            "current_candidate": {
                "branch": "codex/r5",
                "validated_source_commit": "a" * 40,
                "validated_source_tree": "b" * 40,
                "workflow_run_id": 123,
            },
        }
        self.gap = self._gap_fixture()
        self.plan = (
            f"Revision {module.ACTIVE_PLAN_REVISION}\n"
            "zero_gap=true only after all gaps close; automatic redispatch is false\n"
            + "\n".join(item["id"] for item in self.gap["gaps"])
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _item(identifier: str, status: str, issue: int, level: str) -> dict:
        spec = module.CANONICAL_GAP_SPECS[identifier]
        expected_issues, expected_level, external = spec
        assert issue in expected_issues
        assert level == expected_level
        value = {
            "id": identifier,
            "status": status,
            "requires_external_evidence": external,
            "exit_evidence_level": level,
            "summary": f"Close {identifier}",
            "acceptance": ["exact evidence is bound"],
        }
        if len(expected_issues) == 1:
            value["issue"] = expected_issues[0]
        else:
            value["issues"] = list(expected_issues)
        if status == "EXTERNAL_HOLD":
            value["required_material"] = ["authorized target"]
        if status == "SOURCE_CLOSED_PENDING_EVIDENCE":
            value["source_evidence"] = source_evidence()
            value["remaining_evidence"] = ["target observation"]
        if status == "CLOSED":
            value["source_evidence"] = source_evidence()
        return value

    def _gap_fixture(self) -> dict:
        gaps = [
            self._item("R5-GAP-GOVERNANCE-001", "EXTERNAL_HOLD", 20, "L1"),
            self._item("R5-GAP-JOB-ADMISSION-001", "CLOSED", 14, "L1"),
            self._item("R5-GAP-PROCESS-LIFECYCLE-001", "SOURCE_CLOSED_PENDING_EVIDENCE", 15, "L2"),
            self._item("R5-GAP-STREAM-RECOVERY-001", "SOURCE_CLOSED_PENDING_EVIDENCE", 16, "L2"),
            self._item("R5-GAP-JOURNAL-CONVERGENCE-001", "SOURCE_CLOSED_PENDING_EVIDENCE", 17, "L5"),
            self._item("R5-GAP-BROKER-CORRELATION-001", "SOURCE_CLOSED_PENDING_EVIDENCE", 18, "L2"),
            self._item("R5-GAP-PRODUCT-ENTRYPOINT-001", "SOURCE_CLOSED_PENDING_EVIDENCE", 19, "L3"),
            self._item("R5-GAP-INSTALLED-CODEX-001", "EXTERNAL_HOLD", 10, "L2"),
            self._item("R5-GAP-ROOTLINUX-PLACEMENT-001", "EXTERNAL_HOLD", 4, "L2"),
            self._item("R5-GAP-ANDROID-GRAPH-001", "EXTERNAL_HOLD", 2, "L3"),
            self._item("R5-GAP-PHYSICAL-ADB-001", "EXTERNAL_HOLD", 5, "L4"),
            self._item("R5-GAP-FAULT-MATRIX-001", "EXTERNAL_HOLD", 6, "L5"),
            self._item("R5-GAP-RELEASE-001", "EXTERNAL_HOLD", 13, "L6"),
        ]
        return {
            "schema": module.GAP_SCHEMA,
            "revision": module.ACTIVE_PLAN_REVISION,
            "generated_policy": {
                "checked_in_status_is_claim_policy_not_exact_head_evidence": True,
                "exact_head_evidence_must_be_ci_generated": True,
                "automatic_redispatch": False,
                "public_release": False,
            },
            "priority_order": [item["id"] for item in gaps],
            "gaps": gaps,
        }

    def verify(self, gap: dict | None = None, status: dict | None = None) -> object:
        report = module.Report()
        module.verify_gap_register(
            self.root,
            gap if gap is not None else self.gap,
            status if status is not None else self.status,
            self.plan,
            report,
        )
        return report

    def test_clean_open_register_passes(self) -> None:
        report = self.verify()
        self.assertEqual(report.errors, [])
        self.assertFalse(report.facts["zero_gap"])

    def test_duplicate_gap_id_fails(self) -> None:
        gap = copy.deepcopy(self.gap)
        gap["gaps"].append(copy.deepcopy(gap["gaps"][0]))
        gap["priority_order"].append(gap["gaps"][0]["id"])
        report = self.verify(gap=gap)
        self.assertTrue(any("duplicate or empty R5 gap id" in value for value in report.errors))
        self.assertTrue(any("priority_order contains duplicate" in value for value in report.errors))

    def test_l1_source_closed_gap_accepts_source_evidence(self) -> None:
        gap = copy.deepcopy(self.gap)
        gap["gaps"][1]["status"] = "CLOSED"
        gap["gaps"][1]["source_evidence"] = source_evidence()
        report = self.verify(gap=gap)
        self.assertEqual(report.errors, [])

    def test_external_lane_cannot_close_without_real_evidence(self) -> None:
        gap = copy.deepcopy(self.gap)
        gap["gaps"][7]["status"] = "CLOSED"
        report = self.verify(gap=gap)
        self.assertTrue(any("closed R5 gap has no evidence" in value for value in report.errors))

    def test_external_lane_closes_with_reviewed_evidence(self) -> None:
        gap = copy.deepcopy(self.gap)
        entry = gap["gaps"][7]
        entry["status"] = "CLOSED"
        entry["source_evidence"] = source_evidence()
        entry["evidence"] = [
            environment_evidence(
                "L2", evidence_sha256="b" * 64, kind="installed-observation"
            )
        ]
        report = self.verify(gap=gap)
        self.assertEqual(report.errors, [])

    def test_false_zero_gap_fails(self) -> None:
        status = dict(self.status)
        status["zero_gap"] = True
        report = self.verify(status=status)
        self.assertTrue(any("zero_gap" in value for value in report.errors))

    def test_public_release_requires_closed_release_gap(self) -> None:
        status = dict(self.status)
        status["public_release"] = True
        report = self.verify(status=status)
        self.assertTrue(any("public_release" in value for value in report.errors))

    def test_public_release_requires_zero_gap_even_when_release_is_closed(self) -> None:
        gap = copy.deepcopy(self.gap)
        release = gap["gaps"][-1]
        release["status"] = "CLOSED"
        release["source_evidence"] = source_evidence()
        release["evidence"] = [
            environment_evidence(
                "L6",
                evidence_sha256="c" * 64,
                kind="authorized-release-observation",
            )
        ]
        status = dict(self.status)
        status["public_release"] = True
        gap["generated_policy"]["public_release"] = True
        report = self.verify(gap=gap, status=status)
        self.assertTrue(any("zero-gap" in value or "public_release" in value for value in report.errors))

    def test_missing_normative_document_fails(self) -> None:
        (self.root / module.REQUIRED_R6_DOCS[0]).unlink()
        report = self.verify()
        self.assertTrue(any("required R6 document is absent" in value for value in report.errors))

    def test_revision_drift_fails(self) -> None:
        gap = copy.deepcopy(self.gap)
        gap["revision"] = "2026-08-29-r7"
        report = self.verify(gap=gap)
        self.assertTrue(any("active gap revision" in value for value in report.errors))
        self.assertTrue(any("status active plan revision" in value for value in report.errors))

    def test_mutable_external_flag_cannot_downgrade_governance(self) -> None:
        gap = copy.deepcopy(self.gap)
        governance = gap["gaps"][0]
        governance["requires_external_evidence"] = False
        governance["status"] = "CLOSED"
        governance["source_evidence"] = {}
        report = self.verify(gap=gap)
        self.assertTrue(any("external-evidence flag" in value for value in report.errors))

    def test_missing_required_external_lane_fails_closed(self) -> None:
        gap = copy.deepcopy(self.gap)
        gap["gaps"] = [
            item
            for item in gap["gaps"]
            if item["id"] != "R5-GAP-RELEASE-001"
        ]
        gap["priority_order"] = [item["id"] for item in gap["gaps"]]
        report = self.verify(gap=gap)
        self.assertTrue(any("missing required" in value for value in report.errors))

    def test_unknown_lane_cannot_replace_canonical_lane(self) -> None:
        gap = copy.deepcopy(self.gap)
        gap["gaps"][0]["id"] = "R5-GAP-FAKE-001"
        gap["priority_order"][0] = "R5-GAP-FAKE-001"
        report = self.verify(gap=gap)
        self.assertTrue(any("unknown canonical" in value for value in report.errors))

    def test_source_evidence_shape_is_required(self) -> None:
        gap = copy.deepcopy(self.gap)
        job = gap["gaps"][1]
        job["status"] = "CLOSED"
        job["source_evidence"] = {}
        report = self.verify(gap=gap)
        self.assertTrue(any("source evidence branch" in value for value in report.errors))

    def test_source_identity_must_match_every_gap(self) -> None:
        gap = copy.deepcopy(self.gap)
        gap["gaps"][2]["source_evidence"]["commit"] = "d" * 40
        report = self.verify(gap=gap)
        self.assertTrue(
            any("source identity differs from the canonical source candidate" in value for value in report.errors)
        )

    def test_artifact_binding_must_match_every_source_record(self) -> None:
        gap = copy.deepcopy(self.gap)
        gap["gaps"][2]["source_evidence"]["artifacts"][0]["digest"] = (
            "sha256:" + "d" * 64
        )
        report = self.verify(gap=gap)
        self.assertTrue(
            any("artifact binding differs from the canonical source candidate" in value for value in report.errors)
        )

    def test_artifact_name_with_explicit_source_suffix_must_match(self) -> None:
        gap = copy.deepcopy(self.gap)
        artifact = gap["gaps"][2]["source_evidence"]["artifacts"][0]
        artifact["name"] = "source-report-" + "d" * 40
        report = self.verify(gap=gap)
        self.assertTrue(
            any("name is bound to a different source commit" in value for value in report.errors)
        )

    def test_status_candidate_identity_mismatch_fails_closed(self) -> None:
        status = copy.deepcopy(self.status)
        status["current_candidate"]["validated_source_tree"] = "e" * 40
        report = self.verify(status=status)
        self.assertTrue(
            any("status.current_candidate source identity differs" in value for value in report.errors)
        )

    def test_expected_exact_source_head_does_not_rebind_historical_records(self) -> None:
        report = self.verify()
        self.assertEqual(report.errors, [])
        report = module.Report()
        module.verify_gap_register(
            self.root,
            self.gap,
            self.status,
            self.plan,
            report,
            expected_commit="d" * 40,
            expected_tree="e" * 40,
        )
        self.assertEqual(report.errors, [])

    def test_environment_source_commit_must_match_source_candidate(self) -> None:
        gap = copy.deepcopy(self.gap)
        entry = gap["gaps"][7]
        entry["status"] = "CLOSED"
        entry["source_evidence"] = source_evidence()
        entry["evidence"] = [
            environment_evidence(
                "L2",
                source_commit="d" * 40,
                evidence_sha256="b" * 64,
                kind="installed-observation",
            )
        ]
        report = self.verify(gap=gap)
        self.assertTrue(
            any("source_commit does not match the canonical source candidate" in value for value in report.errors)
        )

    def test_status_schema_is_required(self) -> None:
        status = copy.deepcopy(self.status)
        status["schema"] = "org.example.wrong-status"
        report = self.verify(status=status)
        self.assertTrue(any("status schema" in value for value in report.errors))

    def test_release_l6_requires_explicit_signature_and_authorization(self) -> None:
        gap = copy.deepcopy(self.gap)
        for entry in gap["gaps"]:
            entry["status"] = "CLOSED"
            entry["source_evidence"] = source_evidence()
            if entry["requires_external_evidence"]:
                level = entry["exit_evidence_level"]
                entry["evidence"] = [
                    environment_evidence(
                        level,
                        evidence_sha256="b" * 64,
                        kind="reviewed-observation",
                    )
                ]
        release = gap["gaps"][-1]
        release["evidence"][0].update(copy.deepcopy(RELEASE_FIELDS))
        gap["generated_policy"]["public_release"] = True
        status = dict(self.status)
        status["zero_gap"] = True
        status["public_release"] = True
        report = self.verify(gap=gap, status=status)
        self.assertEqual(report.errors, [])

        release["evidence"][0]["release_authorization"].pop("decision")
        report = self.verify(gap=gap, status=status)
        self.assertTrue(any("release_authorization.decision" in value for value in report.errors))


if __name__ == "__main__":
    unittest.main()
