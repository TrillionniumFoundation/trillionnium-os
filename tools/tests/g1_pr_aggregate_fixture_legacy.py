from __future__ import annotations

from copy import deepcopy
import hashlib

from tools.tests.g1_pr_aggregate_fixture_base import AGG, NOW, FakeApi, AggregateFixtureBase


class AggregateFixture(AggregateFixtureBase):
    def _build_happy_fixture(self) -> None:
        self.values[f"repos/{self.repo}/pulls/{self.pr_number}"] = self._pr()
        self.values[f"repos/{self.repo}/commits/{self.base_commit}"] = self._commit(self.base_commit, self.base_tree, [])
        self.values[f"repos/{self.repo}/commits/{self.head_commit}"] = self._commit(self.head_commit, self.head_tree, [self.base_commit])
        self.values[f"repos/{self.repo}/branches/integration%2Fbase"] = {
            "name": self.base_ref,
            "commit": {"sha": self.base_commit},
            "protected": True,
            "protection": {
                "enabled": True,
                "required_status_checks": {
                    "enforcement_level": "everyone",
                    "contexts": sorted(AGG.REQUIRED_PROTECTION_CONTEXTS),
                    "checks": [],
                },
            },
        }

        synthetic_run = self._run(1001, "G1 synthetic-merge qualification", "g1-synthetic-merge.yml")
        android_run = self._run(1002, "G1 Android privileged-lane evaluated matrix", "g1-android-privilege-matrix.yml")
        evidence_run = self._run(1003, "G1 evidence intake qualification", "g1-evidence-intake.yml")
        for filename, run in [
            ("g1-synthetic-merge.yml", synthetic_run),
            ("g1-android-privilege-matrix.yml", android_run),
            ("g1-evidence-intake.yml", evidence_run),
        ]:
            query = f"event=pull_request&head_sha={self.head_commit}&per_page=100"
            self.values[f"repos/{self.repo}/actions/workflows/{filename}/runs?{query}"] = {
                "total_count": 1,
                "workflow_runs": [run],
            }

        for requirement, run_id in zip(AGG.REQUIREMENTS, (1001, 1002, 1003), strict=True):
            self.values[f"repos/{self.repo}/actions/runs/{run_id}/jobs?filter=latest&per_page=100"] = self._jobs(run_id, set(requirement.job_names))

        synthetic_receipt = {
            "schema": "org.trillionnium.g1-synthetic-merge-evidence.v1",
            "program_revision": AGG.PROGRAM_REVISION,
            "repository": self.repo,
            "head_repository": self.repo,
            "event_name": "pull_request",
            "pull_request_number": str(self.pr_number),
            "base_ref": self.base_ref,
            "head_ref": self.head_ref,
            "base_commit": self.base_commit,
            "base_tree": self.base_tree,
            "head_commit": self.head_commit,
            "head_tree": self.head_tree,
            "parent_commits": [self.base_commit, self.head_commit],
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
        synthetic_raw = self._zip(
            {
                "g1-synthetic-merge-evidence.json": synthetic_receipt,
                "g1-merge-baseline.json": {
                    "qualification": "SOURCE_EVIDENCE_ONLY",
                    "gate": {"passed": False},
                },
            }
        )
        synthetic_artifact = self._artifact(2001, 1001, f"g1-synthetic-merge-{'d' * 40}", synthetic_raw)
        diagnostic_raw = self._zip(
            {
                "g1-merge-test-diagnostics.json": {
                    "qualification": "DIAGNOSTIC_ONLY_NO_SOURCE_OR_TARGET_AUTHORITY"
                }
            }
        )
        diagnostic_artifact = self._artifact(
            2010,
            1001,
            f"g1-merge-test-diagnostics-{self.head_commit}",
            diagnostic_raw,
        )
        self.values[f"repos/{self.repo}/actions/runs/1001/artifacts?per_page=100"] = {
            "artifacts": [synthetic_artifact, diagnostic_artifact]
        }

        source_android = self._android_receipt("source_head")
        merge_android = self._android_receipt("synthetic_merge")
        source_android_raw = self._zip({"g1-adbroot-source-matrix.json": source_android})
        merge_android_raw = self._zip({"g1-adbroot-merge-matrix.json": merge_android})
        android_artifacts = [
            self._artifact(2002, 1002, f"g1-adbroot-source-matrix-{self.head_commit}", source_android_raw),
            self._artifact(2003, 1002, f"g1-adbroot-merge-matrix-{'e' * 40}", merge_android_raw),
        ]
        self.values[f"repos/{self.repo}/actions/runs/1002/artifacts?per_page=100"] = {"artifacts": android_artifacts}

        report = self._evidence_report()
        plan = self._promotion_plan()
        source_evidence_raw = self._zip(
            {"g1-evidence-report.json": report, "g1-promotion-plan.json": plan}
        )
        merge_evidence_raw = self._zip(
            {"g1-evidence-merge-report.json": report, "g1-evidence-merge-plan.json": plan}
        )
        evidence_artifacts = [
            self._artifact(2004, 1003, f"g1-evidence-source-{self.head_commit}", source_evidence_raw),
            self._artifact(2005, 1003, f"g1-evidence-merge-{'f' * 40}", merge_evidence_raw),
        ]
        self.values[f"repos/{self.repo}/actions/runs/1003/artifacts?per_page=100"] = {"artifacts": evidence_artifacts}

    def verify(self) -> dict[str, object]:
        return AGG.verify_pr_aggregate(
            repository=self.repo,
            pr_number=self.pr_number,
            expected_base_commit=self.base_commit,
            expected_head_commit=self.head_commit,
            repo_root=self.repo_root,
            api=FakeApi(self.values, self.blobs),
            timeout_seconds=0,
            poll_seconds=0,
            now=NOW,
        )

    def _run_list_path(self, filename: str) -> str:
        return f"repos/{self.repo}/actions/workflows/{filename}/runs?event=pull_request&head_sha={self.head_commit}&per_page=100"

    def _replace_artifact_blob(self, run_id: int, index: int, raw: bytes) -> None:
        path = f"repos/{self.repo}/actions/runs/{run_id}/artifacts?per_page=100"
        payload = deepcopy(self.values[path])
        assert isinstance(payload, dict)
        artifacts = payload["artifacts"]
        assert isinstance(artifacts, list)
        artifact = artifacts[index]
        assert isinstance(artifact, dict)
        url = artifact["archive_download_url"]
        assert isinstance(url, str)
        artifact["size_in_bytes"] = len(raw)
        artifact["digest"] = f"sha256:{hashlib.sha256(raw).hexdigest()}"
        self.blobs[url] = raw
        self.values[path] = payload

