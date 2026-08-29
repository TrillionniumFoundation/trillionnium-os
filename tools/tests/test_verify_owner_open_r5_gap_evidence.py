from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-r5-gap-evidence.py"
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


class GapEvidenceVerifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "docs/status").mkdir(parents=True)
        self.status = {
            "active_plan_revision": module.EXPECTED_REVISION,
            "zero_gap": False,
            "public_release": False,
            "automatic_redispatch": False,
        }
        self.gaps = {
            "schema": module.EXPECTED_SCHEMA,
            "revision": module.EXPECTED_REVISION,
            "priority_order": ["SOURCE-L1", "SOURCE-L2", "EXTERNAL-L4"],
            "gaps": [
                {
                    "id": "SOURCE-L1",
                    "status": "OPEN",
                    "issue": 1,
                    "summary": "source gap",
                    "exit_evidence_level": "L1",
                    "acceptance": ["source passes"],
                },
                {
                    "id": "SOURCE-L2",
                    "status": "OPEN",
                    "issue": 2,
                    "summary": "installed gap",
                    "exit_evidence_level": "L2",
                    "acceptance": ["installed passes"],
                },
                {
                    "id": "EXTERNAL-L4",
                    "status": "EXTERNAL_HOLD",
                    "issue": 3,
                    "summary": "device gap",
                    "exit_evidence_level": "L4",
                    "required_material": ["authorized device"],
                    "acceptance": ["physical pass"],
                },
            ],
        }
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

    def test_open_and_explicit_external_hold_pass(self) -> None:
        report = self.verify()
        self.assertEqual(report.errors, [])
        self.assertFalse(report.facts["zero_gap"])

    def test_l1_source_gap_closes_only_with_exact_source_evidence(self) -> None:
        gap = self.gaps["gaps"][0]
        gap["status"] = "CLOSED"
        gap["source_evidence"] = dict(SOURCE)
        report = self.verify()
        self.assertEqual(report.errors, [])
        del gap["source_evidence"]
        report = self.verify()
        self.assertTrue(any("source_evidence" in error for error in report.errors))

    def test_l2_source_complete_remains_pending_without_installed_evidence(self) -> None:
        gap = self.gaps["gaps"][1]
        gap.update(
            status="SOURCE_CLOSED_PENDING_EVIDENCE",
            source_evidence=dict(SOURCE),
            remaining_evidence=["installed target process matrix"],
        )
        report = self.verify()
        self.assertEqual(report.errors, [])

    def test_source_only_evidence_cannot_fully_close_l2(self) -> None:
        gap = self.gaps["gaps"][1]
        gap.update(status="CLOSED", source_evidence=dict(SOURCE))
        report = self.verify()
        self.assertTrue(any("non-empty list" in error for error in report.errors))
        self.assertTrue(any("exit level L2" in error for error in report.errors))

    def test_real_environment_evidence_can_close_declared_exit(self) -> None:
        gap = self.gaps["gaps"][1]
        gap.update(
            status="CLOSED",
            source_evidence=dict(SOURCE),
            evidence=[
                {
                    "level": "L2",
                    "source_commit": "a" * 40,
                    "evidence_sha256": "d" * 64,
                    "kind": "installed_root_linux_process_matrix",
                    "reviewer": "independent-reviewer",
                    "synthetic": False,
                }
            ],
        )
        report = self.verify()
        self.assertEqual(report.errors, [])

    def test_fixture_or_synthetic_environment_evidence_fails(self) -> None:
        gap = self.gaps["gaps"][2]
        gap.update(
            status="CLOSED",
            source_evidence=dict(SOURCE),
            evidence=[
                {
                    "level": "L4",
                    "source_commit": "a" * 40,
                    "evidence_sha256": "e" * 64,
                    "kind": "fake_device_fixture",
                    "reviewer": "self",
                    "synthetic": True,
                }
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
            if gap["exit_evidence_level"] != "L1":
                level = gap["exit_evidence_level"]
                gap["evidence"] = [
                    {
                        "level": level,
                        "source_commit": "a" * 40,
                        "evidence_sha256": "f" * 64,
                        "kind": f"real_{level.lower()}_evidence",
                        "reviewer": "independent-reviewer",
                        "synthetic": False,
                    }
                ]
        self.status["zero_gap"] = False
        report = self.verify()
        self.assertTrue(any("true exactly" in error for error in report.errors))

    def test_priority_order_drift_fails(self) -> None:
        self.gaps["priority_order"].reverse()
        report = self.verify()
        self.assertTrue(any("priority_order" in error for error in report.errors))


if __name__ == "__main__":
    unittest.main()
