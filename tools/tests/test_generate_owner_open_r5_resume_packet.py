from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "generate-owner-open-r5-resume-packet.py"
spec = importlib.util.spec_from_file_location("generate_owner_open_r5_resume_packet", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

HEX_A = "a" * 40
HEX_B = "b" * 40
DIGEST = "c" * 64
RELEASE_FIELDS = {
    "release_signature": {
        "manifest_sha256": DIGEST,
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
        "commit": HEX_A,
        "tree": HEX_B,
        "workflow_run_id": 123,
        "successful_jobs": ["L1 exact source"],
        "artifacts": [
            {
                "id": 456,
                "name": "l1-source",
                "digest": f"sha256:{DIGEST}",
            }
        ],
    }


def environment_evidence(
    level: str,
    *,
    source_commit: str = HEX_A,
    source_tree: str = HEX_B,
    evidence_sha256: str = DIGEST,
    kind: str = "target-observation",
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


def item(identifier: str, state: str, level: str, issue: int) -> dict:
    spec = module.CANONICAL_GAP_SPECS.get(identifier)
    if spec is None:
        expected_issues = (issue,)
        expected_level = level
        external = level != "L1"
    else:
        expected_issues, expected_level, external = spec
        assert level == expected_level
    value = {
        "id": identifier,
        "status": state,
        "exit_evidence_level": level,
        "requires_external_evidence": external,
        "summary": f"Close {identifier}",
        "acceptance": ["exact reviewed evidence is bound"],
    }
    if len(expected_issues) == 1:
        value["issue"] = expected_issues[0]
    else:
        value["issues"] = list(expected_issues)
    if state in {"CLOSED", "SOURCE_CLOSED_PENDING_EVIDENCE", "EXTERNAL_HOLD"}:
        value["source_evidence"] = source_evidence()
    if state == "SOURCE_CLOSED_PENDING_EVIDENCE":
        value["remaining_evidence"] = ["installed target observation"]
    if state == "EXTERNAL_HOLD":
        value["required_material"] = ["authorized target"]
    return value


class GenerateOwnerOpenR5ResumePacketTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.identity = module.Identity(
            repository="TrillionniumFoundation/trillionnium-os",
            branch="codex/r5",
            commit_sha=HEX_A,
            tree_sha=HEX_B,
            workflow_run_id=999,
            workflow_run_attempt=1,
        )
        self.gaps = {
            "schema": module.EXPECTED_GAP_SCHEMA,
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
        canonical_states = {
            "R5-GAP-GOVERNANCE-001": "EXTERNAL_HOLD",
            "R5-GAP-JOB-ADMISSION-001": "CLOSED",
            "R5-GAP-PROCESS-LIFECYCLE-001": "SOURCE_CLOSED_PENDING_EVIDENCE",
            "R5-GAP-STREAM-RECOVERY-001": "SOURCE_CLOSED_PENDING_EVIDENCE",
            "R5-GAP-JOURNAL-CONVERGENCE-001": "SOURCE_CLOSED_PENDING_EVIDENCE",
            "R5-GAP-BROKER-CORRELATION-001": "SOURCE_CLOSED_PENDING_EVIDENCE",
            "R5-GAP-PRODUCT-ENTRYPOINT-001": "SOURCE_CLOSED_PENDING_EVIDENCE",
            "R5-GAP-INSTALLED-CODEX-001": "EXTERNAL_HOLD",
            "R5-GAP-ROOTLINUX-PLACEMENT-001": "EXTERNAL_HOLD",
            "R5-GAP-ANDROID-GRAPH-001": "EXTERNAL_HOLD",
            "R5-GAP-PHYSICAL-ADB-001": "EXTERNAL_HOLD",
            "R5-GAP-FAULT-MATRIX-001": "EXTERNAL_HOLD",
            "R5-GAP-RELEASE-001": "EXTERNAL_HOLD",
        }
        for identifier, state in canonical_states.items():
            issues, level, _ = module.CANONICAL_GAP_SPECS[identifier]
            self.gaps["gaps"].append(item(identifier, state, level, issues[0]))
        self.gaps["priority_order"] = [entry["id"] for entry in self.gaps["gaps"]]
        self.status = {
            "schema": module.EXPECTED_STATUS_SCHEMA,
            "active_plan_revision": module.EXPECTED_REVISION,
            "zero_gap": False,
            "public_release": False,
            "automatic_redispatch": False,
            "claim_ceiling": module.EXPECTED_CLAIM_CEILING,
            "critical_path_next": ["execute target evidence"],
            "not_claimed": ["installed target"],
        }
        self.write()
        self._git("init", "-q")
        self._git("config", "user.email", "owner-open-test@example.invalid")
        self._git("config", "user.name", "Owner-Open Test")
        self._commit_fixture()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self) -> None:
        gap_path = self.root / module.GAPS
        status_path = self.root / module.STATUS
        gap_path.parent.mkdir(parents=True, exist_ok=True)
        gap_path.write_text(json.dumps(self.gaps), encoding="utf-8")
        status_path.write_text(json.dumps(self.status), encoding="utf-8")

    def _git(self, *args: str) -> str:
        completed = subprocess.run(
            ["git", *args],
            cwd=self.root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return completed.stdout.strip()

    def _commit_fixture(self) -> None:
        self._git("add", "-A")
        subprocess.run(
            ["git", "commit", "-qm", "fixture update"],
            cwd=self.root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.identity.commit_sha = self._git("rev-parse", "HEAD")
        self.identity.tree_sha = self._git("rev-parse", "HEAD^{tree}")

    def build(self) -> dict:
        self.write()
        self._commit_fixture()
        return module.build_packet(self.root, self.identity)

    def test_resume_required_packet_is_fail_closed(self) -> None:
        packet = self.build()
        self.assertEqual(packet["outcome"], "RESUME_REQUIRED")
        self.assertEqual(packet["state_counts"]["CLOSED"], 1)
        self.assertEqual(packet["state_counts"]["SOURCE_CLOSED_PENDING_EVIDENCE"], 5)
        self.assertEqual(packet["state_counts"]["EXTERNAL_HOLD"], 7)
        self.assertEqual(packet["remaining_gap_count"], 12)
        self.assertFalse(packet["invariants"]["packet_promotes_gap_state"])
        self.assertFalse(packet["invariants"]["packet_is_environment_evidence"])

    def test_all_closed_becomes_module_closed_candidate(self) -> None:
        for entry in self.gaps["gaps"]:
            entry["status"] = "CLOSED"
            entry.pop("remaining_evidence", None)
            entry.pop("required_material", None)
            if (
                entry["exit_evidence_level"] != "L1"
                or entry["id"] in module.EXTERNAL_EVIDENCE_GAPS
            ):
                entry["evidence"] = [
                    environment_evidence(entry["exit_evidence_level"])
                ]
            if entry["id"] == "R5-GAP-RELEASE-001":
                entry["evidence"][0].update(copy.deepcopy(RELEASE_FIELDS))
        self.status["zero_gap"] = True
        self.status["public_release"] = True
        self.gaps["generated_policy"]["public_release"] = True
        packet = self.build()
        self.assertEqual(packet["outcome"], "MODULE_CLOSED_CANDIDATE")
        self.assertTrue(packet["invariants"]["all_gaps_closed"])
        self.assertEqual(packet["remaining_gap_count"], 0)

    def test_open_gap_reports_source_work_remaining(self) -> None:
        entry = next(
            value
            for value in self.gaps["gaps"]
            if value["id"] == "R5-GAP-JOB-ADMISSION-001"
        )
        entry["status"] = "OPEN"
        entry.pop("source_evidence", None)
        entry.pop("remaining_evidence", None)
        packet = self.build()
        self.assertEqual(packet["outcome"], "SOURCE_WORK_REMAINING")
        self.assertEqual(packet["state_counts"]["OPEN"], 1)

    def test_false_zero_gap_is_rejected(self) -> None:
        self.status["zero_gap"] = True
        with self.assertRaisesRegex(module.PacketError, "zero_gap"):
            self.build()

    def test_claim_ceiling_cannot_be_overridden(self) -> None:
        self.status["claim_ceiling"] = "FULL_RELEASE"
        with self.assertRaisesRegex(module.PacketError, "claim_ceiling"):
            self.build()

    def test_generated_policy_cannot_disable_ci_exact_head_requirement(self) -> None:
        self.gaps["generated_policy"]["exact_head_evidence_must_be_ci_generated"] = False
        with self.assertRaisesRegex(module.PacketError, "CI-generated"):
            self.build()

    def test_malformed_optional_candidate_is_rejected(self) -> None:
        self.status["current_candidate"] = "not-an-object"
        with self.assertRaisesRegex(module.PacketError, "current_candidate"):
            self.build()

    def test_optional_candidate_identity_must_match_source_records(self) -> None:
        self.status["current_candidate"] = {
            "branch": "codex/r5",
            "validated_source_commit": "d" * 40,
            "validated_source_tree": HEX_B,
            "workflow_run_id": 123,
        }
        with self.assertRaisesRegex(module.PacketError, "source identity differs"):
            self.build()

    def test_pending_without_remaining_evidence_is_rejected(self) -> None:
        next(
            value
            for value in self.gaps["gaps"]
            if value["id"] == "R5-GAP-PROCESS-LIFECYCLE-001"
        ).pop("remaining_evidence")
        with self.assertRaisesRegex(module.PacketError, "remaining_evidence"):
            self.build()

    def test_external_hold_without_material_or_authority_is_rejected(self) -> None:
        next(
            value
            for value in self.gaps["gaps"]
            if value["id"] == "R5-GAP-GOVERNANCE-001"
        ).pop("required_material")
        with self.assertRaisesRegex(module.PacketError, "required material or authority"):
            self.build()

    def test_bad_identity_is_rejected(self) -> None:
        identity = module.Identity(
            repository=self.identity.repository,
            branch=self.identity.branch,
            commit_sha="not-a-commit",
            tree_sha=self.identity.tree_sha,
            workflow_run_id=self.identity.workflow_run_id,
            workflow_run_attempt=self.identity.workflow_run_attempt,
        )
        with self.assertRaisesRegex(module.PacketError, "commit identity"):
            module.build_packet(self.root, identity)

    def test_valid_identity_must_match_checkout_head(self) -> None:
        identity = module.Identity(
            repository=self.identity.repository,
            branch=self.identity.branch,
            commit_sha=HEX_A,
            tree_sha=HEX_B,
            workflow_run_id=self.identity.workflow_run_id,
            workflow_run_attempt=self.identity.workflow_run_attempt,
        )
        with self.assertRaisesRegex(module.PacketError, "does not match checkout HEAD"):
            module.build_packet(self.root, identity)

    def test_tracked_dirty_checkout_is_rejected(self) -> None:
        (self.root / module.STATUS).write_text(
            json.dumps({**self.status, "not_claimed": ["tampered"]}),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(module.PacketError, "tracked working tree is dirty"):
            module.build_packet(self.root, self.identity)

    def test_source_artifact_binding_must_match_across_gaps(self) -> None:
        entry = next(
            value
            for value in self.gaps["gaps"]
            if value["id"] == "R5-GAP-PROCESS-LIFECYCLE-001"
        )
        entry["source_evidence"] = copy.deepcopy(entry["source_evidence"])
        entry["source_evidence"]["artifacts"][0]["digest"] = "sha256:" + "d" * 64
        with self.assertRaisesRegex(module.PacketError, "artifact binding"):
            self.build()

    def test_source_artifact_suffix_must_match_commit(self) -> None:
        entry = next(
            value
            for value in self.gaps["gaps"]
            if value["id"] == "R5-GAP-PROCESS-LIFECYCLE-001"
        )
        entry["source_evidence"] = copy.deepcopy(entry["source_evidence"])
        entry["source_evidence"]["artifacts"][0]["name"] = "l1-source-" + "d" * 40
        with self.assertRaisesRegex(module.PacketError, "different source commit"):
            self.build()

    def test_priority_order_drift_is_rejected(self) -> None:
        self.gaps["priority_order"] = list(reversed(self.gaps["priority_order"]))
        with self.assertRaisesRegex(module.PacketError, "priority_order"):
            self.build()

    def test_open_state_cannot_carry_source_evidence(self) -> None:
        self.gaps["gaps"].append(item("G-OPEN", "OPEN", "L1", 4))
        self.gaps["gaps"][-1]["source_evidence"] = source_evidence()
        self.gaps["priority_order"].append("G-OPEN")
        with self.assertRaisesRegex(module.PacketError, "OPEN state carries"):
            self.build()

    def test_missing_canonical_release_lane_is_rejected(self) -> None:
        self.gaps["gaps"] = [
            entry
            for entry in self.gaps["gaps"]
            if entry["id"] != "R5-GAP-RELEASE-001"
        ]
        self.gaps["priority_order"] = [entry["id"] for entry in self.gaps["gaps"]]
        with self.assertRaisesRegex(module.PacketError, "missing required"):
            self.build()

    def test_unknown_lane_cannot_replace_canonical_lane(self) -> None:
        self.gaps["gaps"].append(item("R5-GAP-FAKE-001", "EXTERNAL_HOLD", "L2", 99))
        self.gaps["priority_order"].append("R5-GAP-FAKE-001")
        with self.assertRaisesRegex(module.PacketError, "unknown canonical"):
            self.build()

    def test_mutable_governance_flag_cannot_downgrade_lane(self) -> None:
        governance = next(
            entry
            for entry in self.gaps["gaps"]
            if entry["id"] == "R5-GAP-GOVERNANCE-001"
        )
        governance["requires_external_evidence"] = False
        with self.assertRaisesRegex(module.PacketError, "must be true"):
            self.build()

    def test_release_evidence_without_explicit_authorization_is_rejected(self) -> None:
        release = next(
            entry
            for entry in self.gaps["gaps"]
            if entry["id"] == "R5-GAP-RELEASE-001"
        )
        release["status"] = "CLOSED"
        release.pop("required_material", None)
        release["evidence"] = [
            environment_evidence("L6", kind="release-observation")
        ]
        with self.assertRaisesRegex(module.PacketError, "release_signature"):
            self.build()

    def test_public_release_requires_zero_gap_after_release_close(self) -> None:
        release = next(
            entry
            for entry in self.gaps["gaps"]
            if entry["id"] == "R5-GAP-RELEASE-001"
        )
        release["status"] = "CLOSED"
        release.pop("required_material", None)
        release["evidence"] = [
            environment_evidence(
                "L6",
                kind="authorized-release-observation",
                reviewer="release-authority",
            )
        ]
        release["evidence"][0].update(copy.deepcopy(RELEASE_FIELDS))
        self.status["public_release"] = True
        self.gaps["generated_policy"]["public_release"] = True
        with self.assertRaisesRegex(module.PacketError, "zero-gap"):
            self.build()


if __name__ == "__main__":
    unittest.main()
