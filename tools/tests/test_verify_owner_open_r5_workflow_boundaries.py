from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-r5-workflow-boundaries.py"
spec = importlib.util.spec_from_file_location("r5_workflow_boundaries", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class WorkflowBoundaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.workflows = self.root / ".github" / "workflows"
        self.workflows.mkdir(parents=True)
        for name in (
            "owner-open-r5-tool-loop.yml",
            "owner-open-r5-target-evidence-capture.yml",
            "owner-open-r5-governance-readiness.yml",
        ):
            self.write(name, self.clean_workflow())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def clean_workflow() -> str:
        return """name: clean
on:
  pull_request:
permissions:
  contents: read
jobs:
  check:
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          persist-credentials: false
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
      - run: test \"$(git rev-parse HEAD)\" = \"${{ github.event.pull_request.head.sha || github.sha }}\"
      - uses: actions/upload-artifact@v4
        with:
          name: evidence-${{ github.event.pull_request.head.sha || github.sha }}
"""

    def write(self, name: str, value: str) -> None:
        (self.workflows / name).write_text(value, encoding="utf-8")

    def errors(self) -> list[str]:
        return module.verify(self.root)["errors"]

    def test_clean_permanent_workflows_pass(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_transient_executor_is_rejected(self) -> None:
        self.write("owner-open-r5-one-shot.yml", self.clean_workflow())
        self.assertTrue(any("transient workflow" in item for item in self.errors()))

    def test_contents_write_and_git_push_are_rejected(self) -> None:
        value = self.clean_workflow().replace("contents: read", "contents: write")
        value += "      - run: git push origin HEAD:main\n"
        self.write("owner-open-r5-tool-loop.yml", value)
        errors = self.errors()
        self.assertTrue(any("write permission" in item for item in errors))
        self.assertTrue(any("push repository" in item for item in errors))

    def test_pr_merge_checkout_is_rejected(self) -> None:
        value = self.clean_workflow().replace(
            "          ref: ${{ github.event.pull_request.head.sha || github.sha }}\n",
            "          ref: ${{ github.sha }}\n",
            1,
        )
        self.write("owner-open-r5-tool-loop.yml", value)
        self.assertTrue(any("not exact-head-bound" in item for item in self.errors()))

    def test_persisted_checkout_credentials_are_rejected(self) -> None:
        value = self.clean_workflow().replace("persist-credentials: false", "persist-credentials: true")
        self.write("owner-open-r5-tool-loop.yml", value)
        self.assertTrue(any("persists credentials" in item for item in self.errors()))

    def test_raw_pr_artifact_sha_is_rejected(self) -> None:
        value = self.clean_workflow().replace(
            "evidence-${{ github.event.pull_request.head.sha || github.sha }}",
            "evidence-${{ github.sha }}",
        )
        self.write("owner-open-r5-tool-loop.yml", value)
        self.assertTrue(any("merge-trigger SHA" in item for item in self.errors()))

    def test_repository_control_mutation_is_rejected(self) -> None:
        value = self.clean_workflow() + "      - run: python -c \"urllib.request.Request('https://api.github.com/repos/x/y/branches/main/protection', method='PUT')\"\n"
        self.write("owner-open-r5-tool-loop.yml", value)
        self.assertTrue(any("mutate GitHub repository" in item for item in self.errors()))

    def test_retired_migration_material_is_rejected(self) -> None:
        path = self.root / ".github" / "r5-bootstrap"
        path.mkdir(parents=True)
        self.assertTrue(any("retired migration material" in item for item in self.errors()))
        path.rmdir()
        applicator = self.root / "tools" / "owner-open" / "apply_r5_dead_patch.py"
        applicator.parent.mkdir(parents=True)
        applicator.write_text("# retired\n", encoding="utf-8")
        self.assertTrue(any("apply_r5_dead_patch.py" in item for item in self.errors()))


if __name__ == "__main__":
    unittest.main()
