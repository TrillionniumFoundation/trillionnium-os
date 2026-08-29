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
                    "schema": module.EXPECTED_STATUS_SCHEMA,
                    "graph_contract_revision": "2026-08-28-r5",
                    "active_plan_revision": "2026-08-29-r6",
                    "zero_gap": False,
                    "public_release": False,
                    "automatic_redispatch": False,
                    "claim_ceiling": module.EXPECTED_CLAIM_CEILING,
                    "not_claimed": ["installed Codex"],
                }
            )
            + "\n"
        )
        (self.root / "docs/status/owner-open-r5-gap-closure.json").write_text(
            json.dumps(self._gap_register()) + "\n"
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

    @staticmethod
    def _gap_register() -> dict:
        entries = []
        pending = {
            "R5-GAP-PROCESS-LIFECYCLE-001",
            "R5-GAP-STREAM-RECOVERY-001",
            "R5-GAP-JOURNAL-CONVERGENCE-001",
            "R5-GAP-BROKER-CORRELATION-001",
            "R5-GAP-PRODUCT-ENTRYPOINT-001",
        }
        holds = {
            "R5-GAP-GOVERNANCE-001",
            "R5-GAP-INSTALLED-CODEX-001",
            "R5-GAP-ROOTLINUX-PLACEMENT-001",
            "R5-GAP-ANDROID-GRAPH-001",
            "R5-GAP-PHYSICAL-ADB-001",
            "R5-GAP-FAULT-MATRIX-001",
            "R5-GAP-RELEASE-001",
        }
        source = {
            "level": "L1",
            "branch": "feature/test",
            "commit": "a" * 40,
            "tree": "b" * 40,
            "workflow_run_id": 123,
            "successful_jobs": ["L1 source"],
            "artifacts": [
                {
                    "id": 456,
                    "name": "l1-candidate",
                    "digest": "sha256:" + "c" * 64,
                }
            ],
        }
        for identifier, (issues, level, external) in module.CANONICAL_GAP_SPECS.items():
            entry = {
                "id": identifier,
                "issue": issues[0] if len(issues) == 1 else None,
                "issues": list(issues) if len(issues) > 1 else None,
                "exit_evidence_level": level,
                "requires_external_evidence": external,
                "status": (
                    "SOURCE_CLOSED_PENDING_EVIDENCE"
                    if identifier in pending
                    else "EXTERNAL_HOLD"
                    if identifier in holds
                    else "CLOSED"
                ),
                "summary": "canonical source candidate",
                "acceptance": ["source closure is represented"],
                "source_evidence": source,
            }
            if entry["issue"] is None:
                del entry["issue"]
            if entry["issues"] is None:
                del entry["issues"]
            if identifier in pending:
                entry["remaining_evidence"] = ["target observation"]
            if identifier in holds:
                entry["required_material"] = ["authorized target"]
            entries.append(entry)
        return {
            "schema": module.EXPECTED_GAP_SCHEMA,
            "revision": module.EXPECTED_GAP_REVISION,
            "generated_policy": {
                "checked_in_status_is_claim_policy_not_exact_head_evidence": True,
                "exact_head_evidence_must_be_ci_generated": True,
                "automatic_redispatch": False,
                "public_release": False,
            },
            "priority_order": [entry["id"] for entry in entries],
            "gaps": entries,
        }

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

    def test_duplicate_source_artifact_id_fails_closed(self) -> None:
        path = self.root / "docs/status/owner-open-r5-gap-closure.json"
        value = json.loads(path.read_text())
        artifact = value["gaps"][0]["source_evidence"]["artifacts"][0]
        value["gaps"][0]["source_evidence"]["artifacts"].append(dict(artifact))
        path.write_text(json.dumps(value) + "\n")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "duplicate-artifact"], cwd=self.root, check=True)
        self.head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.root, text=True
        ).strip()
        with self.assertRaisesRegex(module.CandidateError, "artifact.*duplicated"):
            self.build()

    def test_source_binding_array_order_is_not_identity(self) -> None:
        source = json.loads(
            json.dumps(self._gap_register()["gaps"][0]["source_evidence"])
        )
        source["successful_jobs"].append("L1 second source")
        source["artifacts"].append(
            {
                "id": 789,
                "name": "l1-second-source",
                "digest": "sha256:" + "d" * 64,
            }
        )
        reordered = json.loads(json.dumps(source))
        reordered["successful_jobs"] = list(reversed(reordered["successful_jobs"]))
        reordered["artifacts"] = list(reversed(reordered["artifacts"]))
        self.assertEqual(
            module._source_identity(source, "source"),
            module._source_identity(reordered, "source"),
        )

    def test_malformed_optional_candidate_fails_closed(self) -> None:
        path = self.root / "docs/status/owner-open-r5-status.json"
        value = json.loads(path.read_text())
        value["current_candidate"] = "not-an-object"
        path.write_text(json.dumps(value) + "\n")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "bad-candidate"], cwd=self.root, check=True)
        self.head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.root, text=True
        ).strip()
        with self.assertRaisesRegex(module.CandidateError, "current_candidate"):
            self.build()

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

    def test_missing_canonical_gap_cannot_be_hidden_from_candidate(self) -> None:
        path = self.root / "docs/status/owner-open-r5-gap-closure.json"
        value = json.loads(path.read_text())
        value["gaps"] = value["gaps"][1:]
        value["priority_order"] = [entry["id"] for entry in value["gaps"]]
        path.write_text(json.dumps(value) + "\n")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "missing-gap"], cwd=self.root, check=True)
        self.head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.root, text=True
        ).strip()
        with self.assertRaisesRegex(module.CandidateError, "canonical"):
            self.build()

    def test_noncanonical_claim_ceiling_is_rejected(self) -> None:
        path = self.root / "docs/status/owner-open-r5-status.json"
        value = json.loads(path.read_text())
        value["claim_ceiling"] = "SOURCE_ONLY"
        path.write_text(json.dumps(value) + "\n")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "bad-ceiling"], cwd=self.root, check=True)
        self.head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.root, text=True
        ).strip()
        with self.assertRaisesRegex(module.CandidateError, "claim ceiling"):
            self.build()

    def test_policy_cannot_disable_ci_exact_head_requirement(self) -> None:
        path = self.root / "docs/status/owner-open-r5-gap-closure.json"
        value = json.loads(path.read_text())
        value["generated_policy"]["exact_head_evidence_must_be_ci_generated"] = False
        path.write_text(json.dumps(value) + "\n")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "bad-policy"], cwd=self.root, check=True)
        self.head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.root, text=True
        ).strip()
        with self.assertRaisesRegex(module.CandidateError, "CI-generated"):
            self.build()

    def test_inconsistent_gap_source_identity_is_rejected(self) -> None:
        path = self.root / "docs/status/owner-open-r5-gap-closure.json"
        value = json.loads(path.read_text())
        value["gaps"][1]["source_evidence"]["tree"] = "d" * 40
        path.write_text(json.dumps(value) + "\n")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "source-drift"], cwd=self.root, check=True)
        self.head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.root, text=True
        ).strip()
        with self.assertRaisesRegex(module.CandidateError, "source evidence identity"):
            self.build()

    def test_closed_external_gap_requires_reviewed_environment_evidence(self) -> None:
        path = self.root / "docs/status/owner-open-r5-gap-closure.json"
        value = json.loads(path.read_text())
        entry = value["gaps"][0]
        entry["status"] = "CLOSED"
        entry.pop("required_material", None)
        path.write_text(json.dumps(value) + "\n")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "fake-close"], cwd=self.root, check=True)
        self.head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.root, text=True
        ).strip()
        with self.assertRaisesRegex(module.CandidateError, "evidence must be a non-empty list"):
            self.build()

    def test_status_candidate_identity_must_match_gap_source(self) -> None:
        path = self.root / "docs/status/owner-open-r5-status.json"
        value = json.loads(path.read_text())
        value["current_candidate"] = {
            "branch": "feature/test",
            "validated_source_commit": "e" * 40,
            "validated_source_tree": "b" * 40,
            "workflow_run_id": 123,
        }
        path.write_text(json.dumps(value) + "\n")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "candidate-drift"], cwd=self.root, check=True)
        self.head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.root, text=True
        ).strip()
        with self.assertRaisesRegex(module.CandidateError, "current_candidate.commit"):
            self.build()


if __name__ == "__main__":
    unittest.main()
