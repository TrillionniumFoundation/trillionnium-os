from __future__ import annotations

import importlib.util
import json
from pathlib import Path
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


def item(identifier: str, state: str, level: str, issue: int) -> dict:
    value = {
        "id": identifier,
        "status": state,
        "issue": issue,
        "exit_evidence_level": level,
        "summary": f"Close {identifier}",
        "acceptance": ["exact reviewed evidence is bound"],
    }
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
            "priority_order": ["G-L1", "G-L2", "G-HOLD"],
            "gaps": [
                item("G-L1", "CLOSED", "L1", 1),
                item("G-L2", "SOURCE_CLOSED_PENDING_EVIDENCE", "L2", 2),
                item("G-HOLD", "EXTERNAL_HOLD", "L3", 3),
            ],
        }
        self.status = {
            "schema": module.EXPECTED_STATUS_SCHEMA,
            "active_plan_revision": module.EXPECTED_REVISION,
            "zero_gap": False,
            "public_release": False,
            "automatic_redispatch": False,
            "claim_ceiling": "EXACT_SOURCE_ONLY",
            "critical_path_next": ["execute target evidence"],
            "not_claimed": ["installed target"],
        }
        self.write()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self) -> None:
        gap_path = self.root / module.GAPS
        status_path = self.root / module.STATUS
        gap_path.parent.mkdir(parents=True, exist_ok=True)
        gap_path.write_text(json.dumps(self.gaps), encoding="utf-8")
        status_path.write_text(json.dumps(self.status), encoding="utf-8")

    def build(self) -> dict:
        self.write()
        return module.build_packet(self.root, self.identity)

    def test_resume_required_packet_is_fail_closed(self) -> None:
        packet = self.build()
        self.assertEqual(packet["outcome"], "RESUME_REQUIRED")
        self.assertEqual(packet["state_counts"]["CLOSED"], 1)
        self.assertEqual(packet["state_counts"]["SOURCE_CLOSED_PENDING_EVIDENCE"], 1)
        self.assertEqual(packet["state_counts"]["EXTERNAL_HOLD"], 1)
        self.assertEqual(packet["remaining_gap_count"], 2)
        self.assertFalse(packet["invariants"]["packet_promotes_gap_state"])
        self.assertFalse(packet["invariants"]["packet_is_environment_evidence"])

    def test_all_closed_becomes_module_closed_candidate(self) -> None:
        for entry in self.gaps["gaps"]:
            entry["status"] = "CLOSED"
            entry.pop("remaining_evidence", None)
            entry.pop("required_material", None)
            if entry["exit_evidence_level"] != "L1":
                entry["evidence"] = [
                    {
                        "level": entry["exit_evidence_level"],
                        "source_commit": HEX_A,
                        "evidence_sha256": DIGEST,
                        "kind": "target-observation",
                        "reviewer": "independent-reviewer",
                        "synthetic": False,
                    }
                ]
        self.status["zero_gap"] = True
        packet = self.build()
        self.assertEqual(packet["outcome"], "MODULE_CLOSED_CANDIDATE")
        self.assertTrue(packet["invariants"]["all_gaps_closed"])
        self.assertEqual(packet["remaining_gap_count"], 0)

    def test_open_gap_reports_source_work_remaining(self) -> None:
        entry = self.gaps["gaps"][1]
        entry["status"] = "OPEN"
        entry.pop("source_evidence")
        entry.pop("remaining_evidence")
        packet = self.build()
        self.assertEqual(packet["outcome"], "SOURCE_WORK_REMAINING")
        self.assertEqual(packet["state_counts"]["OPEN"], 1)

    def test_false_zero_gap_is_rejected(self) -> None:
        self.status["zero_gap"] = True
        with self.assertRaisesRegex(module.PacketError, "zero_gap"):
            self.build()

    def test_pending_without_remaining_evidence_is_rejected(self) -> None:
        self.gaps["gaps"][1].pop("remaining_evidence")
        with self.assertRaisesRegex(module.PacketError, "remaining_evidence"):
            self.build()

    def test_external_hold_without_material_or_authority_is_rejected(self) -> None:
        self.gaps["gaps"][2].pop("required_material")
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


if __name__ == "__main__":
    unittest.main()
