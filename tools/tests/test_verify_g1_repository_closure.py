"""Regression coverage for repository topology and live PR-subject parsing."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools import verify_g1_pr_subject as subject
from tools import verify_g1_repository_closure as closure


ROOT = Path(__file__).resolve().parents[2]


class RepositoryClosureTests(unittest.TestCase):
    @staticmethod
    def route_only_target() -> str:
        lanes = "\n".join(f"owner-open-r5-l{level}" for level in range(2, 7))
        return f"""name: target admission route
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  route-only:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          cd "$RUNNER_TEMP"
          unset PYTHONPATH PYTHONHOME
          /usr/bin/python3 -I - <<'PY'
          request = {{
              \"status\": \"ROUTE_ONLY_PENDING_EXTERNAL_ADMISSION\",
              \"candidate_checkout_performed\": False,
              \"candidate_code_executed\": False,
              \"external_runner_allocated\": False,
              \"capture_scheduled\": False,
              \"synthetic\": False,
              \"promotion_authorized\": False,
              \"public_release\": False,
          }}
          PY
          printf '%s\\n' '{lanes}'
"""

    @staticmethod
    def operator_contract() -> str:
        return """The independently administered executor uses
`/opt/owner-open-r5/harnesses/<kind>` and
`/etc/owner-open-r5/attestations/<kind>.json`.
Candidate checkout content is inert content-addressed data only.
"""

    def test_checked_in_repository_closure_passes(self) -> None:
        report = closure.verify(ROOT)
        self.assertEqual(
            report["status"], "PASS_REPOSITORY_CONTROLLED_TOPOLOGY_ONLY"
        )
        self.assertEqual(report["workspace_members"], 24)
        self.assertEqual(report["default_members"], 11)
        self.assertEqual(report["non_product_members"], 13)
        self.assertEqual(report["catalog_modules"], 16)
        self.assertEqual(
            report["target_evidence_posture"],
            "ROUTE_ONLY_EXTERNAL_ADMISSION_REQUIRED",
        )
        self.assertFalse(report["synthetic"])
        self.assertFalse(report["zero_gap"])
        self.assertFalse(report["public_release"])

    def test_lifecycle_rejects_duplicate_json_member(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schema":"one","schema":"two"}', encoding="utf-8")
            with self.assertRaises(closure.VerificationError):
                closure.load_json(path)

    def test_pr_body_rejects_conflicting_head_claims(self) -> None:
        body = "head commit: " + "1" * 40 + "\nhead sha: " + "2" * 40
        with self.assertRaises(subject.SubjectError):
            subject.extract_claims(body)

    def test_pr_body_extracts_exact_subject_and_workflows(self) -> None:
        base = "a" * 40
        head = "b" * 40
        tree = "c" * 40
        body = (
            f"base commit: {base}\n"
            f"head commit: `{head}`\n"
            f"head tree: {tree}\n"
            "`.github/workflows/owner-open-r5-tool-loop.yml`\n"
        )
        self.assertEqual(
            subject.extract_claims(body),
            {"base_commit": base, "head_commit": head, "head_tree": tree},
        )
        self.assertEqual(
            subject.referenced_workflows(body),
            {".github/workflows/owner-open-r5-tool-loop.yml"},
        )

    def test_open_draft_is_a_valid_source_subject_without_merge_claim(self) -> None:
        observed = subject.observe_pull_lifecycle(
            {"state": "open", "draft": True}
        )
        self.assertTrue(observed["draft"])
        self.assertTrue(observed["source_subject_valid"])
        self.assertFalse(observed["integration_eligibility_evaluated"])

    def test_closed_pr_is_not_a_live_source_subject(self) -> None:
        with self.assertRaisesRegex(subject.SubjectError, "not open"):
            subject.observe_pull_lifecycle(
                {"state": "closed", "draft": False}
            )

    def test_unobservable_draft_state_fails_closed(self) -> None:
        with self.assertRaisesRegex(subject.SubjectError, "not observable"):
            subject.observe_pull_lifecycle({"state": "open", "draft": None})

    def test_lifecycle_covers_exact_non_default_workspace_set(self) -> None:
        members, defaults = closure.parse_workspace(ROOT)
        lifecycle = closure.load_json(
            ROOT / "governance/component-lifecycle.v1.json"
        )
        excluded = [entry["path"] for entry in lifecycle["non_product_members"]]
        self.assertEqual(
            excluded,
            [member for member in members if member not in set(defaults)],
        )

    def test_route_only_target_boundary_passes(self) -> None:
        closure.verify_target_evidence_boundary(
            self.route_only_target(), self.operator_contract()
        )

    def test_target_boundary_rejects_self_hosted_allocation(self) -> None:
        target = self.route_only_target().replace(
            "runs-on: ubuntu-24.04", "runs-on: self-hosted"
        )
        with self.assertRaisesRegex(
            closure.VerificationError, "GitHub-hosted runner"
        ):
            closure.verify_target_evidence_boundary(
                target, self.operator_contract()
            )

    def test_target_boundary_rejects_candidate_checkout(self) -> None:
        target = self.route_only_target() + "\n- uses: actions/checkout@deadbeef\n"
        with self.assertRaisesRegex(
            closure.VerificationError, "must not check out candidate code"
        ):
            closure.verify_target_evidence_boundary(
                target, self.operator_contract()
            )

    def test_target_boundary_rejects_candidate_workspace_reference(self) -> None:
        target = self.route_only_target() + '\n- run: cd "$GITHUB_WORKSPACE"\n'
        with self.assertRaisesRegex(
            closure.VerificationError, "candidate workspace"
        ):
            closure.verify_target_evidence_boundary(
                target, self.operator_contract()
            )

    def test_fixed_harness_identity_belongs_to_external_operator_contract(self) -> None:
        operator = self.operator_contract().replace(
            "/opt/owner-open-r5/harnesses/<kind>", "/tmp/candidate/harness"
        )
        with self.assertRaisesRegex(
            closure.VerificationError, "external harness root"
        ):
            closure.verify_target_evidence_boundary(
                self.route_only_target(), operator
            )


if __name__ == "__main__":
    unittest.main()
