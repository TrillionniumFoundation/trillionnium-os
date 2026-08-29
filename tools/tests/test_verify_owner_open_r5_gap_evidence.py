from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from tools.tests.test_owner_open_r5_evidence_bundle import BundleFixture  # noqa: E402

SCRIPT = TOOLS / "verify-owner-open-r5-gap-evidence.py"
spec = importlib.util.spec_from_file_location("verify_owner_open_r5_gap_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


SOURCE = {
    "level": "L1",
    "branch": "feature/gap",
    "commit": "a" * 40,
    "tree": "b" * 40,
    "workflow_run_id": 123,
    "successful_jobs": ["python", "rust"],
    "artifacts": [
        {
            "id": 456,
            "name": "l1-candidate",
            "digest": "sha256:" + "c" * 64,
        }
    ],
}

RELEASE_FIELDS = {
    "release_signature": {
        "manifest_sha256": "d" * 64,
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


def environment_evidence(
    level: str,
    *,
    source_commit: str = "a" * 40,
    source_tree: str = "b" * 40,
    evidence_sha256: str = "d" * 64,
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


class GapEvidenceVerifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "docs/status").mkdir(parents=True)
        self.status = {
            "schema": module.EXPECTED_STATUS_SCHEMA,
            "active_plan_revision": module.EXPECTED_REVISION,
            "zero_gap": False,
            "public_release": False,
            "automatic_redispatch": False,
            "claim_ceiling": module.EXPECTED_CLAIM_CEILING,
            "current_candidate": {
                "branch": SOURCE["branch"],
                "validated_source_commit": SOURCE["commit"],
                "validated_source_tree": SOURCE["tree"],
                "workflow_run_id": SOURCE["workflow_run_id"],
            },
        }
        self.gaps = {
            "schema": module.EXPECTED_SCHEMA,
            "revision": module.EXPECTED_REVISION,
            "generated_policy": {
                "checked_in_status_is_claim_policy_not_exact_head_evidence": True,
                "exact_head_evidence_must_be_ci_generated": True,
                "automatic_redispatch": False,
                "public_release": False,
            },
            "priority_order": [],
            "gaps": [],
        }
        # Include the complete canonical R6 identity set so the standalone
        # verifier exercises its required-lane and issue/level allowlist.
        for index, (identifier, (issues, level, external)) in enumerate(
            module.CANONICAL_GAP_SPECS.items(), start=10
        ):
            if identifier == "R5-GAP-JOB-ADMISSION-001":
                state = "OPEN"
            elif identifier in {
                "R5-GAP-PROCESS-LIFECYCLE-001",
                "R5-GAP-STREAM-RECOVERY-001",
                "R5-GAP-JOURNAL-CONVERGENCE-001",
                "R5-GAP-BROKER-CORRELATION-001",
                "R5-GAP-PRODUCT-ENTRYPOINT-001",
            }:
                state = "SOURCE_CLOSED_PENDING_EVIDENCE"
            else:
                state = "EXTERNAL_HOLD"
            entry = {
                "id": identifier,
                "status": state,
                "summary": f"canonical {identifier}",
                "exit_evidence_level": level,
                "requires_external_evidence": external,
                "acceptance": ["canonical evidence is bound"],
            }
            if len(issues) == 1:
                entry["issue"] = issues[0]
            else:
                entry["issues"] = list(issues)
            if external:
                entry["required_material"] = [f"material-{index}"]
            if state == "SOURCE_CLOSED_PENDING_EVIDENCE":
                entry["source_evidence"] = dict(SOURCE)
                entry["remaining_evidence"] = ["target observation"]
            self.gaps["gaps"].append(entry)
        self.gaps["priority_order"] = [entry["id"] for entry in self.gaps["gaps"]]
        self.write()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self) -> None:
        (self.root / module.STATUS).write_text(
            json.dumps(self.status, indent=2) + "\n", encoding="utf-8"
        )
        (self.root / module.GAPS).write_text(
            json.dumps(self.gaps, indent=2) + "\n", encoding="utf-8"
        )

    def verify(self):
        self.write()
        return module.verify(self.root)

    @staticmethod
    def _git_result(stdout: str) -> mock.Mock:
        result = mock.Mock()
        result.stdout = stdout
        return result

    def test_verify_forwards_expected_source_pair_to_value_verifier(self) -> None:
        self.write()
        expected_commit = "d" * 40
        expected_tree = "e" * 40
        with mock.patch.object(
            module, "verify_values", return_value=module.Report()
        ) as verify_values:
            report = module.verify(
                self.root,
                expected_commit=expected_commit,
                expected_tree=expected_tree,
            )
        self.assertEqual(report.errors, [])
        verify_values.assert_called_once()
        args, kwargs = verify_values.call_args
        self.assertEqual(args[:3], (self.root, self.gaps, self.status))
        self.assertEqual(kwargs["expected_commit"], expected_commit)
        self.assertEqual(kwargs["expected_tree"], expected_tree)

    def test_checkout_status_probe_failure_is_fail_closed(self) -> None:
        self.write()
        report = module.Report()
        with mock.patch.object(
            module.subprocess,
            "run",
            side_effect=[
                self._git_result(str(self.root)),
                self._git_result("a" * 40),
                self._git_result("b" * 40),
                self._git_result(""),
                subprocess.CalledProcessError(128, ["git", "status"]),
            ],
        ):
            module._check_checkout_against_expected(
                self.root, "a" * 40, "b" * 40, report
            )
        self.assertTrue(
            any("cannot verify checkout exact source files" in error for error in report.errors)
        )

    def test_checkout_hash_probe_failure_is_fail_closed(self) -> None:
        self.write()
        report = module.Report()
        with mock.patch.object(
            module.subprocess,
            "run",
            side_effect=[
                self._git_result(str(self.root)),
                self._git_result("a" * 40),
                self._git_result("b" * 40),
                self._git_result(""),
                self._git_result(""),
                self._git_result("H docs/status/owner-open-r5-gap-closure.json\n"),
                self._git_result("f" * 40),
                subprocess.CalledProcessError(128, ["git", "hash-object"]),
            ],
        ):
            module._check_checkout_against_expected(
                self.root, "a" * 40, "b" * 40, report
            )
        self.assertTrue(
            any("cannot verify checkout exact source files" in error for error in report.errors)
        )

    def test_invalid_utf8_canonical_object_is_wrapped_as_verifier_error(self) -> None:
        path = self.root / module.GAPS
        path.write_bytes(b"{\n  \xff\n}\n")
        with self.assertRaisesRegex(ValueError, r"cannot parse .*gap-closure"):
            module.read_object(path)

    def reviewed_bundle_entry(self, kind: str, gap_id: str) -> dict:
        """Create a real reviewed bundle reference for the integration gate."""
        bundle_parent = self.root / "evidence/owner-open-r5" / kind
        bundle_parent.mkdir(parents=True)
        fixture = BundleFixture(bundle_parent, kind=kind)
        fixture.source_commit = SOURCE["commit"]
        fixture.source_tree = SOURCE["tree"]
        fixture.gaps = [gap_id]
        fixture._write_attestation()
        fixture._write_review()
        fixture._write_release()
        captured = fixture.finalize(promotable=False)
        self.assertEqual(captured.returncode, 0, captured.stderr)
        promoted = fixture.finalize(promotable=True, replace=True)
        self.assertEqual(promoted.returncode, 0, promoted.stderr)
        manifest = fixture.bundle / "manifest.json"
        return {
            "level": fixture.level,
            "source_commit": SOURCE["commit"],
            "source_tree": SOURCE["tree"],
            "evidence_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
            "kind": kind,
            "reviewer": fixture.reviewer,
            "synthetic": False,
            "automatic_redispatch": False,
            "bundle_path": manifest.relative_to(self.root).as_posix(),
        }

    def test_open_and_explicit_external_hold_pass(self) -> None:
        report = self.verify()
        self.assertEqual(report.errors, [])
        self.assertFalse(report.facts["zero_gap"])

    def test_l1_source_gap_closes_only_with_exact_source_evidence(self) -> None:
        gap = self.gaps["gaps"][1]
        gap["status"] = "CLOSED"
        gap["source_evidence"] = dict(SOURCE)
        report = self.verify()
        self.assertEqual(report.errors, [])
        del gap["source_evidence"]
        report = self.verify()
        self.assertTrue(any("source_evidence" in error for error in report.errors))

    def test_l2_source_complete_remains_pending_without_installed_evidence(self) -> None:
        gap = self.gaps["gaps"][2]
        gap.update(
            status="SOURCE_CLOSED_PENDING_EVIDENCE",
            source_evidence=dict(SOURCE),
            remaining_evidence=["installed target process matrix"],
        )
        report = self.verify()
        self.assertEqual(report.errors, [])

    def test_source_only_evidence_cannot_fully_close_l2(self) -> None:
        gap = self.gaps["gaps"][2]
        gap.update(status="CLOSED", source_evidence=dict(SOURCE))
        report = self.verify()
        self.assertTrue(any("non-empty list" in error for error in report.errors))
        self.assertTrue(any("exit level L2" in error for error in report.errors))

    def test_inline_environment_evidence_without_bundle_is_rejected(self) -> None:
        gap = self.gaps["gaps"][2]
        gap.update(
            status="CLOSED",
            source_evidence=dict(SOURCE),
            evidence=[
                environment_evidence(
                    "L2",
                    evidence_sha256="d" * 64,
                    kind="installed_root_linux_process_matrix",
                )
            ],
        )
        report = self.verify()
        self.assertTrue(any("bundle_path" in error for error in report.errors))

    def test_reviewed_bundle_can_close_declared_exit(self) -> None:
        gap = self.gaps["gaps"][2]
        gap.update(
            status="CLOSED",
            source_evidence=dict(SOURCE),
            evidence=[
                self.reviewed_bundle_entry(
                    "installed_root_linux_process_matrix",
                    "R5-GAP-PROCESS-LIFECYCLE-001",
                )
            ],
        )
        report = self.verify()
        self.assertEqual(report.errors, [], report.errors)
        validated = report.facts["validated_external_evidence"]
        self.assertIn("R5-GAP-PROCESS-LIFECYCLE-001", validated)

    def test_fixture_or_synthetic_environment_evidence_fails(self) -> None:
        gap = self.gaps["gaps"][10]
        gap.update(
            status="CLOSED",
            source_evidence=dict(SOURCE),
            evidence=[
                environment_evidence(
                    "L4",
                    evidence_sha256="e" * 64,
                    kind="fake_device_fixture",
                    reviewer="self",
                    synthetic=True,
                )
            ],
        )
        report = self.verify()
        self.assertTrue(any("synthetic=false" in error for error in report.errors))

    def test_zero_gap_requires_every_gap_closed(self) -> None:
        self.status["zero_gap"] = True
        report = self.verify()
        self.assertTrue(any("every gap is CLOSED" in error for error in report.errors))

    def test_all_closed_requires_zero_gap_true(self) -> None:
        for gap in self.gaps["gaps"]:
            gap["status"] = "CLOSED"
            gap["source_evidence"] = dict(SOURCE)
            if (
                gap["exit_evidence_level"] != "L1"
                or gap["id"] in module.EXTERNAL_EVIDENCE_GAPS
            ):
                level = gap["exit_evidence_level"]
                gap["evidence"] = [
                    environment_evidence(
                        level,
                        evidence_sha256="f" * 64,
                        kind=f"real_{level.lower()}_evidence",
                    )
                ]
                if gap["id"] == "R5-GAP-RELEASE-001":
                    gap["evidence"][0].update(copy.deepcopy(RELEASE_FIELDS))
        self.status["zero_gap"] = True
        self.status["public_release"] = True
        self.gaps["generated_policy"]["public_release"] = True
        # Deliberately break the zero-gap invariant after making every lane
        # otherwise closeable.
        self.status["zero_gap"] = False
        report = self.verify()
        self.assertTrue(any("true exactly" in error for error in report.errors))

    def test_priority_order_drift_fails(self) -> None:
        self.gaps["priority_order"].reverse()
        report = self.verify()
        self.assertTrue(any("priority_order" in error for error in report.errors))

    def test_missing_canonical_governance_lane_fails_closed(self) -> None:
        self.gaps["gaps"] = [
            item
            for item in self.gaps["gaps"]
            if item["id"] != "R5-GAP-GOVERNANCE-001"
        ]
        self.gaps["priority_order"] = [item["id"] for item in self.gaps["gaps"]]
        report = self.verify()
        self.assertTrue(any("R5-GAP-GOVERNANCE-001" in error for error in report.errors))

    def test_missing_canonical_release_lane_fails_closed(self) -> None:
        self.gaps["gaps"] = [
            item for item in self.gaps["gaps"] if item["id"] != "R5-GAP-RELEASE-001"
        ]
        self.gaps["priority_order"] = [item["id"] for item in self.gaps["gaps"]]
        report = self.verify()
        self.assertTrue(any("R5-GAP-RELEASE-001" in error for error in report.errors))

    def test_unknown_lane_cannot_replace_canonical_lane(self) -> None:
        gaps = copy.deepcopy(self.gaps)
        entry = next(
            item
            for item in gaps["gaps"]
            if item["id"] == "R5-GAP-RELEASE-001"
        )
        entry["id"] = "R5-GAP-FAKE-001"
        gaps["priority_order"][-1] = entry["id"]
        self.gaps = gaps
        report = self.verify()
        self.assertTrue(any("unknown canonical" in error for error in report.errors))

    def test_external_flag_false_cannot_downgrade_canonical_lane(self) -> None:
        governance = next(
            item
            for item in self.gaps["gaps"]
            if item["id"] == "R5-GAP-GOVERNANCE-001"
        )
        governance["requires_external_evidence"] = False
        report = self.verify()
        self.assertTrue(any("must be true" in error for error in report.errors))

    def test_generated_policy_flags_are_immutable(self) -> None:
        self.gaps["generated_policy"][
            "exact_head_evidence_must_be_ci_generated"
        ] = False
        report = self.verify()
        self.assertTrue(any("CI-generated exact-head" in error for error in report.errors))

    def test_claim_ceiling_is_immutable(self) -> None:
        self.status["claim_ceiling"] = "FULL_RELEASE"
        report = self.verify()
        self.assertTrue(any("claim_ceiling" in error for error in report.errors))

    def test_source_identity_must_match_across_gaps(self) -> None:
        gap = next(
            item
            for item in self.gaps["gaps"]
            if item["id"] == "R5-GAP-PROCESS-LIFECYCLE-001"
        )
        gap["source_evidence"]["tree"] = "d" * 40
        report = self.verify()
        self.assertTrue(
            any("source identity differs from the canonical source candidate" in error for error in report.errors)
        )

    def test_artifact_binding_must_match_across_gaps(self) -> None:
        gap = next(
            item
            for item in self.gaps["gaps"]
            if item["id"] == "R5-GAP-PROCESS-LIFECYCLE-001"
        )
        gap["source_evidence"] = copy.deepcopy(gap["source_evidence"])
        gap["source_evidence"]["artifacts"][0]["digest"] = "sha256:" + "d" * 64
        report = self.verify()
        self.assertTrue(
            any("artifact binding differs from the canonical source candidate" in error for error in report.errors)
        )

    def test_artifact_name_with_explicit_source_suffix_must_match(self) -> None:
        gap = next(
            item
            for item in self.gaps["gaps"]
            if item["id"] == "R5-GAP-PROCESS-LIFECYCLE-001"
        )
        gap["source_evidence"] = copy.deepcopy(gap["source_evidence"])
        gap["source_evidence"]["artifacts"][0]["name"] = "l1-candidate-" + "d" * 40
        report = self.verify()
        self.assertTrue(
            any("name is bound to a different source commit" in error for error in report.errors)
        )

    def test_status_candidate_identity_mismatch_fails_closed(self) -> None:
        self.status["current_candidate"]["validated_source_commit"] = "e" * 40
        report = self.verify()
        self.assertTrue(
            any("status.current_candidate source identity differs" in error for error in report.errors)
        )

    def test_environment_source_commit_must_match(self) -> None:
        gap = next(
            item
            for item in self.gaps["gaps"]
            if item["id"] == "R5-GAP-INSTALLED-CODEX-001"
        )
        gap.update(
            status="CLOSED",
            source_evidence=dict(SOURCE),
            evidence=[
                environment_evidence(
                    "L2",
                    source_commit="e" * 40,
                    evidence_sha256="f" * 64,
                    kind="installed-observation",
                )
            ],
        )
        report = self.verify()
        self.assertTrue(
            any("source_commit does not match the canonical source candidate" in error for error in report.errors)
        )

    def test_status_schema_is_required(self) -> None:
        self.status["schema"] = "org.example.wrong-status"
        report = self.verify()
        self.assertTrue(any("status schema is unsupported" in error for error in report.errors))


if __name__ == "__main__":
    unittest.main()
