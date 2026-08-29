from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

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
            "generated_policy": {
                "automatic_redispatch": False,
                "public_release": False,
            },
            "priority_order": ["R5-GAP-JOB-ADMISSION-001", "R5-GAP-GOVERNANCE-001", "R5-GAP-ROOTLINUX-PLACEMENT-001"],
            "gaps": [
                {
                    "id": "R5-GAP-JOB-ADMISSION-001",
                    "status": "OPEN",
                    "issue": 1,
                    "summary": "source gap",
                    "exit_evidence_level": "L1",
                    "acceptance": ["source passes"],
                },
                {
                    "id": "R5-GAP-GOVERNANCE-001",
                    "status": "EXTERNAL_HOLD",
                    "requires_external_evidence": True,
                    "issue": 20,
                    "summary": "governance gap",
                    "exit_evidence_level": "L1",
                    "required_authority": ["independent repository administrator"],
                    "acceptance": ["protected main and exact-head review"],
                    "source_evidence": dict(SOURCE),
                },
                {
                    "id": "R5-GAP-ROOTLINUX-PLACEMENT-001",
                    "status": "SOURCE_CLOSED_PENDING_EVIDENCE",
                    "issue": 2,
                    "summary": "installed gap",
                    "exit_evidence_level": "L2",
                    "acceptance": ["installed passes"],
                    "source_evidence": dict(SOURCE),
                    "remaining_evidence": ["installed target process matrix"],
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

    def make_bundle(self, kind: str) -> BundleFixture:
        base = self.root / "evidence/owner-open-r5" / kind
        base.mkdir(parents=True)
        fixture = BundleFixture(base, kind=kind)
        fixture.source_commit = SOURCE["commit"]
        fixture.source_tree = SOURCE["tree"]
        fixture._write_attestation()
        fixture._write_review()
        fixture._write_release()
        return fixture

    def reference(self, fixture: BundleFixture) -> dict:
        manifest = fixture.bundle / "manifest.json"
        value = json.loads(manifest.read_text(encoding="utf-8"))
        import hashlib

        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        return {
            "level": value["evidence_level"],
            "source_commit": value["source_commit"],
            "source_tree": value["source_tree"],
            "evidence_sha256": digest,
            "kind": value["kind"],
            "reviewer": value["review"]["reviewer"],
            "synthetic": False,
            "bundle_path": manifest.relative_to(self.root).as_posix(),
        }

    def test_open_pending_and_external_hold_pass(self) -> None:
        report = self.verify()
        self.assertEqual(report.errors, [])
        self.assertFalse(report.facts["zero_gap"])

    def test_source_only_l1_closes_without_external_evidence(self) -> None:
        gap = self.gaps["gaps"][0]
        gap["status"] = "CLOSED"
        gap["source_evidence"] = dict(SOURCE)
        report = self.verify()
        self.assertEqual(report.errors, [])

    def test_external_l1_cannot_close_without_bundle(self) -> None:
        gap = self.gaps["gaps"][1]
        gap["status"] = "CLOSED"
        report = self.verify()
        self.assertTrue(any("non-empty list" in error for error in report.errors))

    def test_promotable_l2_bundle_closes_declared_exit(self) -> None:
        fixture = self.make_bundle("installed_root_linux_process_matrix")
        fixture.gaps = ["R5-GAP-ROOTLINUX-PLACEMENT-001"]
        fixture._write_review()
        self.assertEqual(fixture.finalize(promotable=False).returncode, 0)
        self.assertEqual(fixture.finalize(promotable=True, replace=True).returncode, 0)
        gap = self.gaps["gaps"][2]
        gap["status"] = "CLOSED"
        gap.pop("remaining_evidence")
        gap["evidence"] = [self.reference(fixture)]
        report = self.verify()
        self.assertEqual(report.errors, [])
        self.assertIn("R5-GAP-ROOTLINUX-PLACEMENT-001", report.facts["validated_external_evidence"])

    def test_capture_only_bundle_cannot_close_gap(self) -> None:
        fixture = self.make_bundle("installed_root_linux_process_matrix")
        fixture.gaps = ["R5-GAP-ROOTLINUX-PLACEMENT-001"]
        fixture._write_review()
        self.assertEqual(fixture.finalize(promotable=False).returncode, 0)
        gap = self.gaps["gaps"][2]
        gap["status"] = "CLOSED"
        gap.pop("remaining_evidence")
        reference = self.reference(fixture)
        reference["reviewer"] = None
        gap["evidence"] = [reference]
        report = self.verify()
        self.assertTrue(any("capture-only" in error for error in report.errors))

    def test_bundle_path_traversal_fails(self) -> None:
        gap = self.gaps["gaps"][2]
        gap["status"] = "CLOSED"
        gap.pop("remaining_evidence")
        gap["evidence"] = [
            {
                "level": "L2",
                "source_commit": SOURCE["commit"],
                "source_tree": SOURCE["tree"],
                "evidence_sha256": "d" * 64,
                "kind": "installed_root_linux_process_matrix",
                "reviewer": "independent-reviewer",
                "synthetic": False,
                "bundle_path": "../outside/manifest.json",
            }
        ]
        report = self.verify()
        self.assertTrue(any("unsafe path" in error or "below evidence" in error for error in report.errors))

    def test_release_cannot_close_before_all_other_gaps(self) -> None:
        fixture = self.make_bundle("signed_public_release")
        fixture.gaps = ["R5-GAP-RELEASE-001"]
        fixture._write_review()
        self.assertEqual(fixture.finalize(promotable=False).returncode, 0)
        self.assertEqual(fixture.finalize(promotable=True, replace=True).returncode, 0)
        release_gap = {
            "id": "R5-GAP-RELEASE-001",
            "status": "CLOSED",
            "requires_external_evidence": True,
            "issue": 13,
            "summary": "release",
            "exit_evidence_level": "L6",
            "acceptance": ["human authorization"],
            "source_evidence": dict(SOURCE),
            "evidence": [self.reference(fixture)],
        }
        self.gaps["gaps"].append(release_gap)
        self.gaps["priority_order"].append(release_gap["id"])
        self.status["public_release"] = True
        self.gaps["generated_policy"]["public_release"] = True
        report = self.verify()
        self.assertTrue(any("cannot close before every other gap" in error for error in report.errors))


if __name__ == "__main__":
    unittest.main()
