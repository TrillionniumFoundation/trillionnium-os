"""Hostile regression tests for the exact-path G1 review index."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from tools import verify_g1_review_index as review


def changes() -> list[dict[str, object]]:
    return [
        {"path": "apps/runtime.rs", "status": "modified", "previous_path": None},
        {"path": "docs/design.md", "status": "added", "previous_path": None},
        {"path": "legacy/old.txt", "status": "removed", "previous_path": None},
        {"path": "tools/new.py", "status": "renamed", "previous_path": "tools/old.py"},
    ]


def observation(value: list[dict[str, object]] | None = None) -> dict[str, object]:
    return review.observation_from_changes(
        repository=review.REPOSITORY,
        pull_request=41,
        base_commit="a" * 40,
        base_tree="b" * 40,
        head_commit="c" * 40,
        head_tree="d" * 40,
        pages=1,
        raw_changes=changes() if value is None else value,
    )


def index_for(observed: dict[str, object]) -> dict[str, object]:
    paths = list(observed["changed_paths"])
    records = deepcopy(observed["changes"])
    return {
        "schema": review.SCHEMA,
        "program_revision": "2026-08-31-g1",
        "repository": review.REPOSITORY,
        "pull_request": 41,
        "base": {"commit": "a" * 40, "tree": "b" * 40},
        "review_predecessor": {"commit": "e" * 40, "tree": "f" * 40},
        "head_binding": "LIVE_PR_EXACT_HEAD_NO_SELF_REFERENCE",
        "expected": {
            "path_count": len(paths),
            "paths_sha256": review.canonical_paths_digest(paths),
            "change_count": len(records),
            "changes_sha256": review.canonical_changes_digest(records),
        },
        "changed_paths": paths,
        "changes": records,
        "slices": [
            {
                "id": "runtime-source",
                "security_domain": "runtime",
                "accountable_owner": "owner-runtime",
                "independent_reviewers": ["reviewer-runtime"],
                "review_order": 1,
                "paths": ["apps/runtime.rs"],
            },
            {
                "id": "docs-and-tools",
                "security_domain": "governance",
                "accountable_owner": "owner-governance",
                "independent_reviewers": ["reviewer-governance"],
                "review_order": 2,
                "paths": ["docs/design.md", "legacy/old.txt", "tools/new.py"],
            },
        ],
        "claim_ceiling": "CLOSED_WORLD_REVIEW_INDEX_ONLY_NO_APPROVAL_OR_INTEGRATION_AUTHORITY",
        "automatic_redispatch": False,
        "integration_authorized": False,
        "promotion_authorized": False,
        "public_release": False,
    }


class ReviewIndexTest(unittest.TestCase):
    def validate(self, value: dict[str, object], observed: dict[str, object] | None = None):
        return review.validate_index(
            value,
            observation() if observed is None else observed,
            index_sha256=hashlib.sha256(b"fixture-index").hexdigest(),
        )

    def test_proposal_covers_every_path_and_preserves_rename_removal(self) -> None:
        observed = observation()
        value = review.propose_index(
            observed, predecessor_commit="e" * 40, predecessor_tree="f" * 40,
            accountable_owner="author", runtime_reviewer="runtime-reviewer",
            evidence_reviewer="evidence-reviewer",
        )
        result = self.validate(value, observed)
        self.assertEqual(result["path_count"], 4)
        self.assertEqual(result["rename_count"], 1)
        self.assertEqual(result["removal_count"], 1)
        self.assertFalse(result["integration_authorized"])
        self.assertFalse(result["promotion_authorized"])
        self.assertFalse(result["public_release"])

    def test_proposal_rejects_self_review(self) -> None:
        with self.assertRaisesRegex(review.ReviewIndexError, "independent reviewer"):
            review.propose_index(
                observation(), predecessor_commit="e" * 40, predecessor_tree="f" * 40,
                accountable_owner="author", runtime_reviewer="author",
                evidence_reviewer="evidence-reviewer",
            )

    def _observe(self, declared_count: int = 4, moved: str | None = None):
        pull = {"state": "open", "base": {"sha": "a" * 40},
                "head": {"sha": "c" * 40}, "changed_files": declared_count}
        final = deepcopy(pull)
        if moved == "head":
            final["head"]["sha"] = "f" * 40
        elif moved == "base":
            final["base"]["sha"] = "f" * 40
        elif moved == "count":
            final["changed_files"] += 1
        elif moved == "closed":
            final["state"] = "closed"
        files = [{"filename": item["path"], "status": item["status"],
                  "previous_filename": item["previous_path"]} for item in changes()]
        def git_result(root, *args, **kwargs):
            return {("rev-parse", "HEAD^{commit}"): "c" * 40,
                    ("status", "--porcelain=v1", "--untracked-files=all"): "",
                    ("rev-parse", "c" * 40 + "^{tree}"): "d" * 40,
                    ("rev-parse", "a" * 40 + "^{tree}"): "b" * 40}[args]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".git").mkdir()
            with patch.object(review, "git", side_effect=git_result), \
                 patch.object(review, "_api_get", side_effect=[pull, files, final]):
                return review.observe_live(root=root, repository=review.REPOSITORY,
                                           pull_request=41, expected_base="a" * 40,
                                           expected_head="c" * 40, token="fixture")

    def test_complete_live_observation_requires_stable_subject(self) -> None:
        self.assertEqual(self._observe()["path_count"], 4)

    def test_live_pagination_must_match_pr_declared_count(self) -> None:
        with self.assertRaisesRegex(review.ReviewIndexError, "truncated or incomplete"):
            self._observe(declared_count=5)

    def test_live_subject_movement_or_closure_invalidates_observation(self) -> None:
        for moved in ("head", "base", "count", "closed"):
            with self.subTest(moved=moved), self.assertRaisesRegex(review.ReviewIndexError, "during observation"):
                self._observe(moved=moved)

    def test_complete_index_passes_and_retains_no_authority(self) -> None:
        result = self.validate(index_for(observation()))
        self.assertEqual(result["result"], "PASS_EXACT_HEAD_CLOSED_WORLD_REVIEW_INDEX")
        self.assertEqual(result["path_count"], 4)
        self.assertEqual(result["rename_count"], 1)
        self.assertEqual(result["removal_count"], 1)
        self.assertFalse(result["integration_authorized"])

    def test_omitted_path_fails_closed(self) -> None:
        value = index_for(observation())
        value["changed_paths"].pop()
        with self.assertRaisesRegex(review.ReviewIndexError, "changes and changed_paths|path count"):
            self.validate(value)

    def test_duplicate_path_or_slice_assignment_fails_closed(self) -> None:
        value = index_for(observation())
        value["changed_paths"].append(value["changed_paths"][-1])
        with self.assertRaisesRegex(review.ReviewIndexError, "sorted|duplicates"):
            self.validate(value)
        value = index_for(observation())
        value["slices"][0]["paths"].append("docs/design.md")
        value["slices"][0]["paths"].sort()
        with self.assertRaisesRegex(review.ReviewIndexError, "belongs to both"):
            self.validate(value)

    def test_rename_source_or_destination_drift_fails_closed(self) -> None:
        live = changes()
        live[-1] = {
            "path": "tools/renamed-again.py",
            "status": "renamed",
            "previous_path": "tools/new.py",
        }
        with self.assertRaisesRegex(review.ReviewIndexError, "path count differs|path digest differs|omits, adds or renames"):
            self.validate(index_for(observation()), observation(live))

    def test_deleted_status_drift_fails_closed(self) -> None:
        live = changes()
        live[2] = {"path": "legacy/old.txt", "status": "modified", "previous_path": None}
        with self.assertRaisesRegex(review.ReviewIndexError, "change digest differs|statuses"):
            self.validate(index_for(observation()), observation(live))

    def test_post_index_added_path_fails_closed(self) -> None:
        live = changes() + [
            {"path": "post/index.txt", "status": "added", "previous_path": None}
        ]
        with self.assertRaisesRegex(review.ReviewIndexError, "path count differs"):
            self.validate(index_for(observation()), observation(live))

    def test_path_cannot_be_owned_by_self_review_only(self) -> None:
        value = index_for(observation())
        value["slices"][0]["independent_reviewers"] = ["owner-runtime"]
        with self.assertRaisesRegex(review.ReviewIndexError, "own independent reviewer"):
            self.validate(value)

    def test_nonfinite_and_duplicate_json_members_are_rejected(self) -> None:
        with self.assertRaises(review.ReviewIndexError):
            review.load_json_bytes(b'{"a":1,"a":2}', "duplicate")
        with self.assertRaises(review.ReviewIndexError):
            review.load_json_bytes(b'{"a":NaN}', "nonfinite")


if __name__ == "__main__":
    unittest.main()
