from __future__ import annotations

from copy import deepcopy
import hashlib
import unittest

from tools.tests.g1_pr_aggregate_fixture import AGG, FakeApi, AggregateFixture


class AggregateTest(AggregateFixture):
    def test_happy_path_binds_all_workflow_families(self) -> None:
        report = self.verify()
        self.assertEqual(report["result"], "L1_EXACT_PR_WORKFLOW_AGGREGATE_PASSED")
        self.assertEqual(len(report["workflows"]), 3)
        self.assertEqual(report["subject"]["merge"]["parents"], [self.base_commit, self.head_commit])
        clone = deepcopy(report)
        expected = clone["report_sha256"]
        clone["report_sha256"] = ""
        self.assertEqual(expected, hashlib.sha256(AGG._canonical(clone)).hexdigest())

    def test_missing_required_protection_context_fails(self) -> None:
        path = f"repos/{self.repo}/branches/integration%2Fbase"
        branch = deepcopy(self.values[path])
        assert isinstance(branch, dict)
        branch["protection"]["required_status_checks"]["contexts"].remove(
            "L1 exact-source-head aggregate candidate"
        )
        self.values[path] = branch
        with self.assertRaisesRegex(AGG.AggregateError, "missing contexts"):
            self.verify()

    def test_latest_failed_run_cannot_reuse_older_success(self) -> None:
        path = self._run_list_path("g1-synthetic-merge.yml")
        value = deepcopy(self.values[path])
        assert isinstance(value, dict)
        older = deepcopy(value["workflow_runs"][0])
        failed = self._run(1009, "G1 synthetic-merge qualification", "g1-synthetic-merge.yml", conclusion="failure")
        value["workflow_runs"] = [older, failed]
        value["total_count"] = 2
        self.values[path] = value
        with self.assertRaisesRegex(AGG.AggregateError, "concluded 'failure'"):
            self.verify()

    def test_stale_base_run_is_not_a_candidate(self) -> None:
        path = self._run_list_path("g1-synthetic-merge.yml")
        value = deepcopy(self.values[path])
        assert isinstance(value, dict)
        run = value["workflow_runs"][0]
        run["pull_requests"][0]["base"]["sha"] = "a" * 40
        self.values[path] = value
        with self.assertRaisesRegex(AGG.AggregateError, "timed out waiting"):
            self.verify()

    def test_artifact_digest_mismatch_fails(self) -> None:
        url = "https://objects.example/2001.zip"
        self.blobs[url] += b"tamper"
        with self.assertRaisesRegex(AGG.AggregateError, "byte count differs|digest mismatch"):
            self.verify()

    def test_old_synthetic_base_receipt_fails(self) -> None:
        receipt = {
            "schema": "org.trillionnium.g1-synthetic-merge-evidence.v1",
            "program_revision": AGG.PROGRAM_REVISION,
            "repository": self.repo,
            "head_repository": self.repo,
            "event_name": "pull_request",
            "pull_request_number": str(self.pr_number),
            "base_ref": self.base_ref,
            "head_ref": self.head_ref,
            "base_commit": "a" * 40,
            "base_tree": self.base_tree,
            "head_commit": self.head_commit,
            "head_tree": self.head_tree,
            "parent_commits": ["a" * 40, self.head_commit],
            "merge_commit": "d" * 40,
            "merge_tree": self.head_tree,
            "cargo_lock_sha256": self.lock_sha,
            "workflow_run_id": "1001",
            "workflow_attempt": "1",
            "result": "L1_SYNTHETIC_MERGE_SOURCE_CLOSURE_PASSED",
            "claim_ceiling": "EXACT_TWO_PARENT_SOURCE_MERGE_GATES_PASSED_NOT_INSTALLED_TARGET",
            "automatic_redispatch": False,
            "public_release": False,
        }
        raw = self._zip(
            {
                "g1-synthetic-merge-evidence.json": receipt,
                "g1-merge-baseline.json": {"qualification": "SOURCE_EVIDENCE_ONLY", "gate": {"passed": False}},
            }
        )
        self._replace_artifact_blob(1001, 0, raw)
        with self.assertRaisesRegex(AGG.AggregateError, "base identity mismatch"):
            self.verify()

    def test_android_parent_reordering_fails(self) -> None:
        receipt = self._android_receipt("synthetic_merge")
        receipt["parent_commits"] = [self.head_commit, self.base_commit]
        receipt["receipt_sha256"] = ""
        receipt["receipt_sha256"] = hashlib.sha256(AGG._canonical(receipt)).hexdigest()
        self._replace_artifact_blob(
            1002,
            1,
            self._zip({"g1-adbroot-merge-matrix.json": receipt}),
        )
        with self.assertRaisesRegex(AGG.AggregateError, "parent order mismatch"):
            self.verify()

    def test_evidence_report_source_drift_fails(self) -> None:
        report = self._evidence_report()
        report["current_source_commit"] = "a" * 40
        self._replace_artifact_blob(
            1003,
            0,
            self._zip(
                {
                    "g1-evidence-report.json": report,
                    "g1-promotion-plan.json": self._promotion_plan(),
                }
            ),
        )
        with self.assertRaisesRegex(AGG.AggregateError, "report source mismatch"):
            self.verify()

    def test_newer_run_during_final_recheck_invalidates_aggregate(self) -> None:
        path = self._run_list_path("g1-evidence-intake.yml")
        initial = deepcopy(self.values[path])
        final = deepcopy(initial)
        assert isinstance(final, dict)
        newer = self._run(1010, "G1 evidence intake qualification", "g1-evidence-intake.yml")
        final["workflow_runs"] = [newer, *final["workflow_runs"]]
        final["total_count"] = 2
        self.values[path] = [
            FakeApi._response(initial, path),
            FakeApi._response(final, path),
        ]
        with self.assertRaisesRegex(AGG.AggregateError, "newer exact-subject"):
            self.verify()

    def test_pull_request_movement_during_verification_fails(self) -> None:
        path = f"repos/{self.repo}/pulls/{self.pr_number}"
        initial = self._pr()
        moved = self._pr(head="a" * 40)
        self.values[path] = [
            FakeApi._response(initial, path),
            FakeApi._response(moved, path),
        ]
        with self.assertRaisesRegex(AGG.AggregateError, "head commit moved"):
            self.verify()

    def test_local_cargo_lock_drift_fails(self) -> None:
        (self.repo_root / "Cargo.lock").write_text("tampered\n", encoding="utf-8")
        with self.assertRaisesRegex(AGG.AggregateError, "checkout is not clean|Cargo.lock digest"):
            self.verify()

    def test_zip_extra_member_fails(self) -> None:
        receipt = self._android_receipt("source_head")
        raw = self._zip(
            {
                "g1-adbroot-source-matrix.json": receipt,
                "unexpected.json": {},
            }
        )
        self._replace_artifact_blob(1002, 0, raw)
        with self.assertRaisesRegex(AGG.AggregateError, "member set drifted"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
