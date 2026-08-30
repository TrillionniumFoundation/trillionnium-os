from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/owner-open-r5-governance-readiness.yml"


class RepositoryGovernanceBaselineTest(unittest.TestCase):
    def test_public_policy_files_exist_and_are_coherent(self) -> None:
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        codeowners = (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8")

        self.assertTrue(license_text.startswith("MIT License\n"))
        self.assertIn("private GitHub Security Advisory", security)
        self.assertIn("must not promote an L2-L6 claim", security)
        for level in range(7):
            self.assertIn(f"L{level}", contributing)
        self.assertIn("Do not push directly to `main`", contributing)
        for critical in (
            "/.github/",
            "/docs/status/",
            "/tools/owner_open_r5_evidence_bundle.py",
            "/tools/owner_open_r5_capture_trust.py",
            "/tools/promote-owner-open-r5-evidence.py",
            "/apps/trillionnium-owner-open-host/",
            "/crates/trillionnium-owner-open-*/",
            "/android-integration/",
        ):
            self.assertIn(critical, codeowners)
        self.assertIn(
            "CODEOWNERS alone does not establish independence", codeowners
        )

    def test_governance_workflow_uses_immutable_actions_and_exact_checkout(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
            workflow,
        )
        self.assertIn(
            "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
            workflow,
        )
        self.assertIn(
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
            workflow,
        )
        self.assertNotRegex(
            workflow,
            re.compile(r"uses:\s+[^\s@]+@v\d+", re.MULTILINE),
        )
        self.assertIn("--untracked-files=all", workflow)
        self.assertNotIn("--untracked-files=no", workflow)
        self.assertIn("test_repository_governance_baseline", workflow)


if __name__ == "__main__":
    unittest.main()
