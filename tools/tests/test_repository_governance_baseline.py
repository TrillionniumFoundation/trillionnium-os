from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = (
    ROOT / ".github/workflows/g1-exact-head-source.yml",
    ROOT / ".github/workflows/g1-synthetic-merge.yml",
)


class RepositoryGovernanceBaselineTest(unittest.TestCase):
    def test_public_policy_files_exist_and_are_coherent(self) -> None:
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        codeowners = (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8")

        self.assertTrue(license_text.startswith("MIT License\n"))
        self.assertIn("private GitHub Security Advisory", security)
        self.assertIn("must not promote an L2-L6 claim", security)
        self.assertIn("docs/START_HERE.md", contributing)
        self.assertIn("docs/machine/", contributing)
        self.assertIn("Historical development documents must not be reintroduced", contributing)
        self.assertIn("exact clean source head", contributing)
        self.assertIn("automatic_redispatch=false", contributing)
        self.assertIn("Do not push directly to `main`", contributing)
        for critical in (
            "/.github/",
            "/docs/machine/",
            "/docs/generated/",
            "/tools/docs/",
            "/apps/trillionnium-owner-open-host/",
            "/crates/trillionnium-owner-open-types/",
            "/android-integration/",
            "/packaging/",
        ):
            self.assertIn(critical, codeowners)
        self.assertIn(
            "Branch protection must still require a non-author approval", codeowners
        )

    def test_governance_workflow_uses_immutable_actions_and_exact_checkout(self) -> None:
        for path in WORKFLOWS:
            workflow = path.read_text(encoding="utf-8")
            self.assertIn(
                "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
                workflow,
            )
            self.assertIn(
                "persist-credentials: false",
                workflow,
            )
            self.assertNotRegex(
                workflow,
                re.compile(r"uses:\s+[^\s@]+@v\d+", re.MULTILINE),
            )
            self.assertIn("--no-replace-objects", workflow)
            self.assertIn("--untracked-files=all", workflow)
            self.assertNotIn("--untracked-files=no", workflow)
            self.assertIn("python3 tools/docs/verify_global_docs.py", workflow)

        exact = WORKFLOWS[0].read_text(encoding="utf-8")
        self.assertIn('ref: ${{ env.SOURCE_HEAD_SHA }}', exact)
        self.assertIn('test "$(git --no-replace-objects rev-parse HEAD)" = "$SOURCE_HEAD_SHA"', exact)
        synthetic = WORKFLOWS[1].read_text(encoding="utf-8")
        self.assertIn('rev-parse HEAD^1', synthetic)
        self.assertIn('rev-parse HEAD^2', synthetic)


if __name__ == "__main__":
    unittest.main()
