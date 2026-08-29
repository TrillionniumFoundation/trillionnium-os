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


class VerifyOwnerOpenR5GapClosureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for path in module.REQUIRED_R6_DOCS:
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("active\n", encoding="utf-8")
        self.status = {
            "active_plan_revision": module.ACTIVE_PLAN_REVISION,
            "zero_gap": False,
            "public_release": False,
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
        return {
            "id": identifier,
            "status": status,
            "issue": issue,
            "exit_evidence_level": level,
            "summary": f"Close {identifier}",
            "acceptance": ["exact evidence is bound"],
        }

    def _gap_fixture(self) -> dict:
        gaps = [
            self._item("R5-GAP-GOVERNANCE-001", "OPEN", 20, "L1"),
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
            "generated_policy": {"automatic_redispatch": False},
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
        gap["gaps"][0]["status"] = "CLOSED"
        gap["gaps"][0]["source_evidence"] = {}
        report = self.verify(gap=gap)
        self.assertEqual(report.errors, [])

    def test_external_lane_cannot_close_without_real_evidence(self) -> None:
        gap = copy.deepcopy(self.gap)
        gap["gaps"][1]["status"] = "CLOSED"
        report = self.verify(gap=gap)
        self.assertTrue(any("closed R5 gap has no evidence" in value for value in report.errors))
        self.assertTrue(any("external evidence lane cannot be closed" in value for value in report.errors))

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


if __name__ == "__main__":
    unittest.main()
