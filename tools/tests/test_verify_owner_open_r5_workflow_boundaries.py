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
        self.write("owner-open-r5-tool-loop.yml", self.clean_pr_workflow())
        self.write("owner-open-r5-governance-readiness.yml", self.clean_governance_workflow())
        self.write("owner-open-r5-target-evidence-capture.yml", self.clean_target_route())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def clean_pr_workflow() -> str:
        return """name: clean
on:
  pull_request:
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          persist-credentials: false
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
      - run: test \"$(git --no-replace-objects rev-parse HEAD)\" = \"${{ github.event.pull_request.head.sha || github.sha }}\"
      - uses: actions/upload-artifact@v4
        with:
          name: evidence-${{ github.event.pull_request.head.sha || github.sha }}
"""

    @staticmethod
    def clean_governance_workflow() -> str:
        return WorkflowBoundaryTest.clean_pr_workflow() + """
      - run: |
          assert report[\"readiness_claimed\"] is False
          assert report[\"ready_for_protected_integration\"] is False
          assert report[\"promotion_authorized\"] is False
          assert report[\"public_release\"] is False
"""

    @staticmethod
    def clean_target_route() -> str:
        return """name: target route
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  route:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          request = {
              \"status\": \"ROUTE_ONLY_PENDING_EXTERNAL_ADMISSION\",
              \"candidate_checkout_performed\": False,
              \"candidate_code_executed\": False,
              \"external_runner_allocated\": False,
              \"capture_scheduled\": False,
              \"promotion_authorized\": False,
              \"public_release\": False,
          }
"""

    def write(self, name: str, value: str) -> None:
        (self.workflows / name).write_text(value, encoding="utf-8")

    def errors(self) -> list[str]:
        return module.verify(self.root)["errors"]

    def test_clean_permanent_workflows_pass(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_transient_executor_is_rejected(self) -> None:
        self.write("owner-open-r5-one-shot.yml", self.clean_pr_workflow())
        self.assertTrue(any("transient workflow" in item for item in self.errors()))

    def test_contents_write_and_git_push_are_rejected(self) -> None:
        value = self.clean_pr_workflow().replace("contents: read", "contents: write")
        value += "      - run: git push origin HEAD:main\n"
        self.write("owner-open-r5-tool-loop.yml", value)
        errors = self.errors()
        self.assertTrue(any("write permission" in item for item in errors))
        self.assertTrue(any("push repository" in item for item in errors))

    def test_pr_merge_checkout_is_rejected(self) -> None:
        value = self.clean_pr_workflow().replace(
            "          ref: ${{ github.event.pull_request.head.sha || github.sha }}\n",
            "          ref: ${{ github.sha }}\n",
            1,
        )
        self.write("owner-open-r5-tool-loop.yml", value)
        self.assertTrue(any("not exact-head-bound" in item for item in self.errors()))

    def test_persisted_checkout_credentials_are_rejected(self) -> None:
        value = self.clean_pr_workflow().replace("persist-credentials: false", "persist-credentials: true")
        self.write("owner-open-r5-tool-loop.yml", value)
        self.assertTrue(any("persists credentials" in item for item in self.errors()))

    def test_raw_pr_artifact_sha_is_rejected(self) -> None:
        value = self.clean_pr_workflow().replace(
            "evidence-${{ github.event.pull_request.head.sha || github.sha }}",
            "evidence-${{ github.sha }}",
        )
        self.write("owner-open-r5-tool-loop.yml", value)
        self.assertTrue(any("merge-trigger SHA" in item for item in self.errors()))

    def test_repository_control_mutation_is_rejected(self) -> None:
        value = self.clean_pr_workflow() + "      - run: python -c \"urllib.request.Request('https://api.github.com/repos/x/y/branches/main/protection', method='PUT')\"\n"
        self.write("owner-open-r5-tool-loop.yml", value)
        self.assertTrue(any("mutate GitHub repository" in item for item in self.errors()))

    def test_target_route_cannot_allocate_self_hosted_runner(self) -> None:
        value = self.clean_target_route().replace("runs-on: ubuntu-24.04", "runs-on: self-hosted")
        self.write("owner-open-r5-target-evidence-capture.yml", value)
        self.assertTrue(any("self-hosted runner" in item for item in self.errors()))

    def test_target_route_cannot_checkout_or_reference_candidate_workspace(self) -> None:
        value = self.clean_target_route() + """
      - uses: actions/checkout@v4
      - run: cd \"$GITHUB_WORKSPACE\"; python3 -m json.tool candidate.json
"""
        self.write("owner-open-r5-target-evidence-capture.yml", value)
        errors = self.errors()
        self.assertTrue(any("checks out candidate code" in item for item in errors))
        self.assertTrue(any("references candidate workspace" in item for item in errors))

    def test_target_route_must_keep_every_no_authority_marker(self) -> None:
        value = self.clean_target_route().replace(
            '              "capture_scheduled": False,\n', ""
        )
        self.write("owner-open-r5-target-evidence-capture.yml", value)
        self.assertTrue(any("capture_scheduled" in item for item in self.errors()))

    def test_governance_workflow_cannot_claim_true_readiness(self) -> None:
        value = self.clean_governance_workflow() + "ready_for_protected_integration: true\n"
        self.write("owner-open-r5-governance-readiness.yml", value)
        self.assertTrue(any("claim readiness true" in item for item in self.errors()))

    def test_yaml_write_all_inline_permissions_and_curl_patch_are_rejected(self) -> None:
        write_all = self.clean_pr_workflow().replace(
            "permissions:\n  contents: read", "permissions: write-all"
        )
        write_all += (
            '      - run: curl --request PATCH '
            '"$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/branches/main/protection"\n'
        )
        self.write("owner-open-r16-write-evasion.yaml", write_all)
        inline = self.clean_pr_workflow().replace(
            "permissions:\n  contents: read", "permissions: {contents: write}"
        )
        self.write("owner-open-r16-inline-write.yaml", inline)
        errors = self.errors()
        self.assertTrue(any("write-evasion.yaml" in item and "write permission" in item for item in errors))
        self.assertTrue(any("write-evasion.yaml" in item and "mutate GitHub" in item for item in errors))
        self.assertTrue(any("inline-write.yaml" in item and "write permission" in item for item in errors))

    def test_retired_migration_material_is_rejected(self) -> None:
        path = self.root / ".github" / "r5-bootstrap"
        path.mkdir(parents=True)
        self.assertTrue(any("retired migration material" in item for item in self.errors()))
        path.rmdir()
        applicator = self.root / "tools" / "owner-open" / "apply_r5_dead_patch.py"
        applicator.parent.mkdir(parents=True)
        applicator.write_text("# retired\n", encoding="utf-8")
        self.assertTrue(any("apply_r5_dead_patch.py" in item for item in self.errors()))

    def test_unreadable_utf8_workflow_fails_closed(self) -> None:
        path = self.workflows / "owner-open-r5-unreadable.yml"
        path.write_bytes(b"name: invalid-\xff\n")
        self.assertTrue(any("cannot read workflow" in item for item in self.errors()))


if __name__ == "__main__":
    unittest.main()
