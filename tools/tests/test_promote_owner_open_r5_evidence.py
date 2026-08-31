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

SCRIPT = TOOLS / "promote-owner-open-r5-evidence.py"
spec = importlib.util.spec_from_file_location("promote_owner_open_r5_evidence", SCRIPT)
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


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


class PromotionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "docs/status").mkdir(parents=True)
        self.gaps = {
            "schema": "org.trillionnium.owner-open-r5.gap-closure.v1",
            "revision": "2026-08-29-r6",
            "generated_policy": {
                "automatic_redispatch": False,
                "public_release": False,
            },
            "priority_order": [
                "R5-GAP-JOB-ADMISSION-001",
                "R5-GAP-ROOTLINUX-PLACEMENT-001",
                "R5-GAP-RELEASE-001",
            ],
            "gaps": [
                {
                    "id": "R5-GAP-JOB-ADMISSION-001",
                    "status": "CLOSED",
                    "issue": 14,
                    "summary": "job admission",
                    "exit_evidence_level": "L1",
                    "acceptance": ["source pass"],
                    "source_evidence": dict(SOURCE),
                },
                {
                    "id": "R5-GAP-ROOTLINUX-PLACEMENT-001",
                    "status": "SOURCE_CLOSED_PENDING_EVIDENCE",
                    "issues": [4, 13],
                    "summary": "root linux placement",
                    "exit_evidence_level": "L2",
                    "acceptance": ["installed placement"],
                    "source_evidence": dict(SOURCE),
                    "remaining_evidence": ["target placement"],
                },
                {
                    "id": "R5-GAP-RELEASE-001",
                    "status": "EXTERNAL_HOLD",
                    "requires_external_evidence": True,
                    "issue": 13,
                    "summary": "release",
                    "exit_evidence_level": "L6",
                    "acceptance": ["human release authorization"],
                    "source_evidence": dict(SOURCE),
                    "required_authority": ["release authority"],
                },
            ],
        }
        # Exercise promotion against the same immutable thirteen-lane R6
        # register used in production.  A three-lane toy register can hide
        # missing-lane or mutable-external-flag regressions in the promoter.
        verifier = module.gap_verifier_module()
        by_id = {
            str(item["id"]): item for item in self.gaps["gaps"]
        }
        for identifier, (issues, level, external) in verifier.CANONICAL_GAP_SPECS.items():
            if identifier in by_id:
                item = by_id[identifier]
                item["requires_external_evidence"] = external
                continue
            state = (
                "SOURCE_CLOSED_PENDING_EVIDENCE"
                if identifier in {
                    "R5-GAP-PROCESS-LIFECYCLE-001",
                    "R5-GAP-STREAM-RECOVERY-001",
                    "R5-GAP-JOURNAL-CONVERGENCE-001",
                    "R5-GAP-BROKER-CORRELATION-001",
                    "R5-GAP-PRODUCT-ENTRYPOINT-001",
                }
                else "EXTERNAL_HOLD"
            )
            item = {
                "id": identifier,
                "status": state,
                "summary": identifier,
                "exit_evidence_level": level,
                "requires_external_evidence": external,
                "acceptance": ["exact reviewed evidence"],
                "source_evidence": dict(SOURCE),
            }
            if len(issues) == 1:
                item["issue"] = issues[0]
            else:
                item["issues"] = list(issues)
            if state == "SOURCE_CLOSED_PENDING_EVIDENCE":
                item["remaining_evidence"] = ["target observation"]
            else:
                item["required_material"] = ["authorized target evidence"]
            by_id[identifier] = item
        self.gaps["gaps"] = [
            by_id[identifier] for identifier in verifier.CANONICAL_GAP_ORDER
        ]
        self.gaps["priority_order"] = [item["id"] for item in self.gaps["gaps"]]
        self.gaps["generated_policy"].update(
            {
                "checked_in_status_is_claim_policy_not_exact_head_evidence": True,
                "exact_head_evidence_must_be_ci_generated": True,
            }
        )
        self.status = {
            "schema": "org.trillionnium.owner-open-r5-status.v2",
            "active_plan_revision": "2026-08-29-r6",
            "zero_gap": False,
            "public_release": False,
            "automatic_redispatch": False,
            "claim_ceiling": "EXACT_COMMIT_SOURCE_GATES_PASSED_NOT_INSTALLED_CODEX",
            "development_branch": SOURCE["branch"],
            "open_repository_gaps": [],
            "external_evidence_holds": [
                {"id": "R5-GAP-RELEASE-001"}
            ],
            "source_closed_pending_evidence": [
                {"id": "R5-GAP-ROOTLINUX-PLACEMENT-001"}
            ],
            "work_packages": [
                {
                    "id": f"W{index}",
                    "open_gap_ids": [],
                    "complete": False,
                    "latest_evidence_level": "L1",
                    "status": "HOST_TESTED",
                }
                for index in range(8)
            ],
            "critical_path_next": ["collect target evidence"],
            "not_claimed": ["target placement", "release"],
            "current_candidate": {
                "branch": SOURCE["branch"],
                "validated_source_commit": SOURCE["commit"],
                "validated_source_tree": SOURCE["tree"],
                "workflow_run_id": SOURCE["workflow_run_id"],
            },
        }
        self.write()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self) -> None:
        write_json(self.root / module.GAPS_PATH, self.gaps)
        write_json(self.root / module.STATUS_PATH, self.status)

    def bundle(self, kind: str, gaps: list[str]) -> BundleFixture:
        base = self.root / "evidence/owner-open-r5" / kind
        base.mkdir(parents=True)
        fixture = BundleFixture(base, kind=kind)
        fixture.source_commit = SOURCE["commit"]
        fixture.source_tree = SOURCE["tree"]
        fixture.gaps = gaps
        fixture._write_attestation()
        fixture._write_review()
        fixture._write_release()
        self.assertEqual(fixture.finalize(promotable=False).returncode, 0)
        promoted = fixture.finalize(promotable=True, replace=True)
        self.assertEqual(promoted.returncode, 0, promoted.stderr)
        return fixture

    def test_reviewed_bundle_promotes_only_its_declared_gap(self) -> None:
        fixture = self.bundle(
            "installed_root_linux_process_matrix",
            ["R5-GAP-ROOTLINUX-PLACEMENT-001"],
        )
        gaps, status, summary = module.apply_promotion(
            self.root, fixture.bundle / "manifest.json"
        )
        states = {item["id"]: item["status"] for item in gaps["gaps"]}
        self.assertEqual(states["R5-GAP-ROOTLINUX-PLACEMENT-001"], "CLOSED")
        self.assertEqual(states["R5-GAP-RELEASE-001"], "EXTERNAL_HOLD")
        self.assertFalse(status["zero_gap"])
        self.assertFalse(status["public_release"])
        self.assertEqual(
            summary["promoted_gap_ids"], ["R5-GAP-ROOTLINUX-PLACEMENT-001"]
        )
        self.assertEqual(status["source_closed_pending_evidence"], [])
        self.assertTrue(status["work_packages"][0]["complete"])

    def test_release_promotion_is_rejected_while_prior_gap_open(self) -> None:
        fixture = self.bundle(
            "signed_public_release", ["R5-GAP-RELEASE-001"]
        )
        with self.assertRaisesRegex(module.EvidenceError, "prior gaps"):
            module.apply_promotion(self.root, fixture.bundle / "manifest.json")

    def test_source_identity_mismatch_is_rejected(self) -> None:
        fixture = self.bundle(
            "installed_root_linux_process_matrix",
            ["R5-GAP-ROOTLINUX-PLACEMENT-001"],
        )
        self.gaps["gaps"][1]["source_evidence"]["commit"] = "d" * 40
        self.write()
        with self.assertRaisesRegex(
            module.EvidenceError,
            "source evidence differs|source identity differs",
        ):
            module.apply_promotion(self.root, fixture.bundle / "manifest.json")


if __name__ == "__main__":
    unittest.main()
