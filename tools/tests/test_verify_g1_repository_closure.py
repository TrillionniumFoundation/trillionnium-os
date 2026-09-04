"""Regression coverage for repository topology and live PR-subject parsing."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools import verify_g1_pr_subject as subject
from tools import verify_g1_repository_closure as closure


ROOT = Path(__file__).resolve().parents[2]


class RepositoryClosureTests(unittest.TestCase):
    def test_checked_in_repository_closure_passes(self) -> None:
        report = closure.verify(ROOT)
        self.assertEqual(report["status"], "PASS_REPOSITORY_CONTROLLED_TOPOLOGY_ONLY")
        self.assertEqual(report["workspace_members"], 24)
        self.assertEqual(report["default_members"], 11)
        self.assertEqual(report["non_product_members"], 13)
        self.assertEqual(report["catalog_modules"], 16)
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

    def test_lifecycle_covers_exact_non_default_workspace_set(self) -> None:
        members, defaults = closure.parse_workspace(ROOT)
        lifecycle = closure.load_json(ROOT / "governance/component-lifecycle.v1.json")
        excluded = [entry["path"] for entry in lifecycle["non_product_members"]]
        self.assertEqual(excluded, [member for member in members if member not in set(defaults)])


if __name__ == "__main__":
    unittest.main()
