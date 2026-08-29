from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "owner-open"
    / "generate_owner_open_l1_candidate.py"
)
spec = importlib.util.spec_from_file_location("generate_owner_open_l1_candidate", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class GenerateOwnerOpenL1CandidateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "docs/status").mkdir(parents=True)
        (self.root / "docs/status/owner-open-r5-status.json").write_text(
            json.dumps(
                {
                    "graph_contract_revision": "2026-08-28-r5",
                    "active_plan_revision": "2026-08-29-r6",
                    "zero_gap": False,
                    "public_release": False,
                    "automatic_redispatch": False,
                    "claim_ceiling": "SOURCE_ONLY",
                    "not_claimed": ["installed Codex"],
                }
            )
            + "\n"
        )
        (self.root / "docs/status/owner-open-r5-gap-closure.json").write_text(
            json.dumps({"revision": "2026-08-29-r6"}) + "\n"
        )
        (self.root / "Cargo.lock").write_text("# lock\n")
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.invalid"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "test"], cwd=self.root, check=True
        )
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=self.root, check=True)
        self.head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.root, text=True
        ).strip()

    def tearDown(self) -> None:
        last_error: OSError | None = None
        for _ in range(25):
            try:
                self.temp.cleanup()
                return
            except OSError as error:
                last_error = error
                time.sleep(0.02)
        if last_error is not None:
            raise last_error

    def build(self, source_head_sha: str | None = None) -> dict:
        return module.build_candidate(
            self.root,
            repository="TrillionniumFoundation/trillionnium-os",
            source_head_sha=source_head_sha or self.head,
            source_head_ref="feature/test",
            workflow_trigger_sha="f" * 40,
            pull_request_base_sha="e" * 40,
            event_name="pull_request",
            workflow_name="L1 owner-open R5 source and gap closure",
            workflow_run_id=123,
            workflow_run_attempt=1,
        )

    def test_exact_source_head_manifest_passes_and_keeps_merge_sha_separate(self) -> None:
        payload = self.build()
        self.assertEqual(payload["schema"], module.SCHEMA)
        self.assertEqual(payload["source_head_commit"], self.head)
        self.assertEqual(payload["workflow_trigger_sha"], "f" * 40)
        self.assertNotEqual(
            payload["source_head_commit"], payload["workflow_trigger_sha"]
        )
        self.assertEqual(payload["checkout_mode"], "exact_source_head")
        self.assertTrue(payload["tracked_worktree_clean"])
        self.assertEqual(payload["result"], "L1_SOURCE_CLOSURE_PASSED")

    def test_merge_or_other_sha_cannot_impersonate_the_source_head(self) -> None:
        with self.assertRaisesRegex(module.CandidateError, "differs from source head"):
            self.build("f" * 40)

    def test_tracked_dirty_checkout_fails_closed(self) -> None:
        (self.root / "Cargo.lock").write_text("changed\n")
        with self.assertRaisesRegex(module.CandidateError, "tracked working tree is dirty"):
            self.build()

    def test_status_revision_drift_fails_closed(self) -> None:
        path = self.root / "docs/status/owner-open-r5-gap-closure.json"
        path.write_text(json.dumps({"revision": "2026-08-29-r7"}) + "\n")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "drift"], cwd=self.root, check=True)
        self.head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.root, text=True
        ).strip()
        with self.assertRaisesRegex(module.CandidateError, "active revisions differ"):
            self.build()

    def test_zero_gap_and_release_overclaims_fail_closed(self) -> None:
        path = self.root / "docs/status/owner-open-r5-status.json"
        value = json.loads(path.read_text())
        value["zero_gap"] = True
        value["public_release"] = True
        path.write_text(json.dumps(value) + "\n")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "overclaim"], cwd=self.root, check=True)
        self.head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.root, text=True
        ).strip()
        with self.assertRaisesRegex(module.CandidateError, "zero_gap=false"):
            self.build()


if __name__ == "__main__":
    unittest.main()
