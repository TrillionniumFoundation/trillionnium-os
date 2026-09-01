from __future__ import annotations

from pathlib import Path
import re
import unittest


WORKFLOW_ROOT = Path(__file__).resolve().parents[2] / ".github" / "workflows"
ACTIVE_WORKFLOW_NAMES = (
    "g1-exact-head-source.yml",
    "g1-synthetic-merge.yml",
)


def workflow_paths() -> list[Path]:
    return [WORKFLOW_ROOT / name for name in ACTIVE_WORKFLOW_NAMES]


class OwnerOpenWorkflowExactHeadTest(unittest.TestCase):
    def test_direct_verifier_invocations_bind_checkout_pair(self) -> None:
        paths = workflow_paths()
        self.assertTrue(paths, f"no G1 workflows found under {WORKFLOW_ROOT}")
        for path in paths:
            with self.subTest(workflow=path.name):
                workflow = path.read_text(encoding="utf-8")
                self.assertIn(
                    "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
                    workflow,
                )
                self.assertIn("fetch-depth: 0", workflow)
                self.assertIn("persist-credentials: false", workflow)
                self.assertIn("git --no-replace-objects", workflow)
                self.assertIn("python3 tools/docs/verify_global_docs.py", workflow)
                if path.name == "g1-exact-head-source.yml":
                    self.assertIn('ref: ${{ env.SOURCE_HEAD_SHA }}', workflow)
                    self.assertIn('SOURCE_HEAD_SHA', workflow)
                    self.assertIn(
                        'rev-parse HEAD^{tree}', workflow
                    )
                else:
                    self.assertIn('EVENT_BASE_SHA', workflow)
                    self.assertIn('EVENT_HEAD_SHA', workflow)
                    self.assertIn('rev-parse HEAD^1', workflow)
                    self.assertIn('rev-parse HEAD^2', workflow)

    def test_head_status_and_diff_checks_disable_replacement_objects(self) -> None:
        paths = workflow_paths()
        self.assertTrue(paths, f"no G1 workflows found under {WORKFLOW_ROOT}")
        checked = 0
        for path in paths:
            for line_number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if "git " not in line:
                    continue
                if re.search(r"\b(?:rev-parse|status|diff)\b", line) is None:
                    continue
                checked += 1
                with self.subTest(workflow=path.name, line=line_number):
                    self.assertIn(
                        "--no-replace-objects",
                        line,
                        "exact-head/status/diff git checks must ignore replace refs",
                    )
        self.assertGreaterEqual(checked, 1, "no git exact-head/status/diff check found")

    def test_synthetic_merge_binds_fork_and_manual_source_identity(self) -> None:
        workflow = (WORKFLOW_ROOT / "g1-synthetic-merge.yml").read_text(
            encoding="utf-8"
        )
        # The checkout must target the event's source repository explicitly;
        # otherwise a fork PR can accidentally run the base repository's head.
        self.assertIn("repository: ${{ env.EVENT_HEAD_REPOSITORY }}", workflow)
        self.assertIn("head_repository:", workflow)
        # A PR's hidden ref is served by the base repository and remains
        # verifiable for private forks without trusting an anonymous fork URL.
        self.assertIn('refs/pull/$EVENT_PR_NUMBER/head', workflow)
        self.assertIn('base_remote_url="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY}.git"', workflow)
        self.assertNotIn(
            'git ls-remote "$EVENT_HEAD_REPOSITORY"',
            workflow,
            "parent movement must use the canonical base-repository PR ref",
        )
        # Missing manual inputs must not fall back to github.sha (the
        # workflow commit), which would silently qualify the wrong source.
        self.assertIn("INVALID_BASE_SHA", workflow)
        self.assertIn("INVALID_HEAD_SHA", workflow)
        self.assertIn("invalid/empty-head-repository", workflow)
        # The read-only token must not be inherited by source-controlled test
        # commands.  It is scoped to the provenance fetch/check steps and is
        # explicitly unset before checkout/merge processing.
        self.assertNotIn("GITHUB_TOKEN: ${{ github.token }}", workflow)
        self.assertIn("G1_GIT_TOKEN: ${{ github.token }}", workflow)
        self.assertIn("unset G1_GIT_TOKEN", workflow)
        self.assertIn('[[ -e "$MERGE_DIR" || -L "$MERGE_DIR" ]]', workflow)
        self.assertNotIn('rm -rf -- "$MERGE_DIR"', workflow)
        self.assertIn("python3 -m unittest discover -s tools/tests -p 'test*.py' -q", workflow)
        for field in (
            '"head_repository"',
            '"event_name"',
            '"pull_request_number"',
            '"base_ref"',
            '"head_ref"',
        ):
            self.assertIn(field, workflow)


if __name__ == "__main__":
    unittest.main()
