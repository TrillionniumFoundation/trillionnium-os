from __future__ import annotations

import json
import unittest

from tools.g1_pr_aggregate_api import ApiResponse
from tools.g1_pr_aggregate_common import AggregateError
from tools.g1_pr_aggregate_live import _verify_jobs


class JobsApi:
    def __init__(self, expected_path: str, value: object) -> None:
        self.expected_path = expected_path
        self.value = value
        self.calls: list[str] = []

    def get_json(self, path: str) -> ApiResponse:
        self.calls.append(path)
        if path != self.expected_path:
            raise AggregateError(f"unexpected path: {path}")
        raw = json.dumps(
            self.value, sort_keys=True, separators=(",", ":")
        ).encode()
        return ApiResponse(self.value, raw, path, {})


class WorkflowJobAttemptBindingTest(unittest.TestCase):
    run_id = 1001
    attempt = 3
    workflow_name = "G1 synthetic-merge qualification"
    head_sha = "a" * 40
    head_branch = "feature/exact-head"
    job_name = "L1 exact two-parent merge source qualification"

    @property
    def path(self) -> str:
        return (
            "repos/{repo}/actions/runs/1001/attempts/3/"
            "jobs?per_page=100"
        )

    def job(self, **changes: object) -> dict[str, object]:
        value: dict[str, object] = {
            "id": 2001,
            "run_id": self.run_id,
            "run_attempt": self.attempt,
            "workflow_name": self.workflow_name,
            "head_sha": self.head_sha,
            "head_branch": self.head_branch,
            "name": self.job_name,
            "status": "completed",
            "conclusion": "success",
            "steps": [
                {"name": "source", "conclusion": "success"},
                {"name": "post", "conclusion": "skipped"},
            ],
        }
        value.update(changes)
        return value

    def verify(self, job: dict[str, object]) -> tuple[JobsApi, list[dict[str, object]]]:
        api = JobsApi(self.path, {"total_count": 1, "jobs": [job]})
        result = _verify_jobs(
            api,
            self.run_id,
            self.attempt,
            self.workflow_name,
            self.head_sha,
            self.head_branch,
            frozenset({self.job_name}),
        )
        return api, result

    def test_attempt_specific_endpoint_and_complete_identity_are_retained(self) -> None:
        api, jobs = self.verify(self.job())
        self.assertEqual(api.calls, [self.path])
        self.assertEqual(
            jobs,
            [
                {
                    "id": 2001,
                    "run_id": self.run_id,
                    "run_attempt": self.attempt,
                    "workflow_name": self.workflow_name,
                    "head_sha": self.head_sha,
                    "head_branch": self.head_branch,
                    "name": self.job_name,
                    "status": "completed",
                    "conclusion": "success",
                }
            ],
        )

    def test_later_attempt_jobs_cannot_be_credited_to_selected_attempt(self) -> None:
        with self.assertRaisesRegex(AggregateError, "attempt mismatch"):
            self.verify(self.job(run_attempt=self.attempt + 1))

    def test_job_workflow_name_must_match_selected_run(self) -> None:
        with self.assertRaisesRegex(AggregateError, "workflow mismatch"):
            self.verify(self.job(workflow_name="different workflow"))

    def test_job_head_sha_must_match_selected_source(self) -> None:
        with self.assertRaisesRegex(AggregateError, "head SHA mismatch"):
            self.verify(self.job(head_sha="b" * 40))

    def test_job_head_branch_must_match_selected_source(self) -> None:
        with self.assertRaisesRegex(AggregateError, "head branch mismatch"):
            self.verify(self.job(head_branch="different/head"))

    def test_job_run_id_must_match_selected_run(self) -> None:
        with self.assertRaisesRegex(AggregateError, "ownership mismatch"):
            self.verify(self.job(run_id=self.run_id + 1))


if __name__ == "__main__":
    unittest.main()
