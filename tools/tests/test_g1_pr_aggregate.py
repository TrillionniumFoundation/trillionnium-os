from __future__ import annotations

from copy import deepcopy
import hashlib
import io
import json
from email.message import Message
from http.client import HTTPException
from pathlib import Path
import stat
from urllib.error import HTTPError, URLError
from unittest import mock
import unittest
import zipfile

from tools import g1_pr_aggregate_api as HTTP
from tools import g1_pr_aggregate_archive as ARCHIVE
from tools import g1_pr_aggregate_common as COMMON
from tools.g1_pr_aggregate_model import REQUIREMENTS
from tools.g1_pr_aggregate_workflow import _verify_workflow
from tools.tests.g1_pr_aggregate_fixture_base import (
    AGG,
    AggregateFixtureBase,
    FakeApi,
)

# The current aggregate imports GitHubApi rather than ApiResponse directly.
# The shared in-memory fixture uses this public response value at runtime.
AGG.ApiResponse = HTTP.ApiResponse


class SourceAggregateFixture(AggregateFixtureBase):
    """One-workflow fixture for the current ordinary source gate."""

    def _build_happy_fixture(self) -> None:
        self.values[f"repos/{self.repo}/pulls/{self.pr_number}"] = self._pr()
        self.values[f"repos/{self.repo}/commits/{self.base_commit}"] = self._commit(
            self.base_commit, self.base_tree, []
        )
        self.values[f"repos/{self.repo}/commits/{self.head_commit}"] = self._commit(
            self.head_commit, self.head_tree, [self.base_commit]
        )
        self.values[f"repos/{self.repo}/branches/integration%2Fbase"] = {
            "name": self.base_ref,
            "commit": {"sha": self.base_commit},
            "protected": True,
            "protection": {
                "enabled": True,
                "required_status_checks": {
                    "enforcement_level": "everyone",
                    "contexts": sorted(COMMON.REQUIRED_PROTECTION_CONTEXTS),
                    "checks": [],
                },
            },
        }

        self.requirement = REQUIREMENTS[0]
        self.run = self._run(
            1001,
            self.requirement.workflow_name,
            self.requirement.filename,
        )
        self.values[self.run_list_path] = {
            "total_count": 1,
            "workflow_runs": [self.run],
        }
        self.values[self.jobs_path] = self._jobs(
            1001, set(self.requirement.job_names)
        )

        receipt = self.synthetic_receipt()
        semantic_raw = self._zip(
            {
                "g1-synthetic-merge-evidence.json": receipt,
                "g1-merge-baseline.json": {
                    "qualification": "SOURCE_EVIDENCE_ONLY",
                    "gate": {"passed": False},
                },
            }
        )
        diagnostic_raw = self._zip(
            {
                "g1-merge-test-diagnostics.json": {
                    "qualification": (
                        "DIAGNOSTIC_ONLY_NO_SOURCE_OR_TARGET_AUTHORITY"
                    )
                }
            }
        )
        self.semantic_artifact = self._artifact(
            2001,
            1001,
            f"g1-synthetic-merge-{'d' * 40}",
            semantic_raw,
        )
        self.diagnostic_artifact = self._artifact(
            2002,
            1001,
            f"g1-merge-test-diagnostics-{self.head_commit}",
            diagnostic_raw,
        )
        self.values[self.artifacts_path] = {
            "artifacts": [self.semantic_artifact, self.diagnostic_artifact]
        }

    @property
    def run_list_path(self) -> str:
        return (
            f"repos/{self.repo}/actions/workflows/"
            f"{self.requirement.filename}/runs?event=pull_request&"
            f"head_sha={self.head_commit}&per_page=100"
        )

    @property
    def jobs_path(self) -> str:
        return f"repos/{self.repo}/actions/runs/1001/jobs?filter=latest&per_page=100"

    @property
    def artifacts_path(self) -> str:
        return f"repos/{self.repo}/actions/runs/1001/artifacts?per_page=100"

    def synthetic_receipt(self, *, attempt: str = "1") -> dict[str, object]:
        return {
            "schema": "org.trillionnium.g1-synthetic-merge-evidence.v1",
            "program_revision": COMMON.PROGRAM_REVISION,
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
            "workflow_attempt": attempt,
            "result": "L1_SYNTHETIC_MERGE_SOURCE_CLOSURE_PASSED",
            "claim_ceiling": (
                "EXACT_TWO_PARENT_SOURCE_MERGE_GATES_PASSED_NOT_INSTALLED_TARGET"
            ),
            "automatic_redispatch": False,
            "public_release": False,
        }

    def replace_semantic_archive(self, raw: bytes) -> None:
        payload = deepcopy(self.values[self.artifacts_path])
        artifact = payload["artifacts"][0]
        url = artifact["archive_download_url"]
        artifact["size_in_bytes"] = len(raw)
        artifact["digest"] = f"sha256:{hashlib.sha256(raw).hexdigest()}"
        self.blobs[url] = raw
        self.values[self.artifacts_path] = payload

    def response(self, value: object, path: str) -> HTTP.ApiResponse:
        return FakeApi._response(value, path)

    def verify(self) -> dict[str, object]:
        return AGG._verify(
            repository=self.repo,
            pr_number=self.pr_number,
            base_commit=self.base_commit,
            head_commit=self.head_commit,
            repo_root=self.repo_root,
            api=FakeApi(self.values, self.blobs),
            timeout_seconds=0,
            poll_seconds=0,
        )


class SourceGateBoundaryTest(SourceAggregateFixture):
    def test_ordinary_pr_requires_the_real_synthetic_source_workflow(self) -> None:
        self.assertEqual(len(REQUIREMENTS), 1)
        requirement = REQUIREMENTS[0]
        self.assertEqual(requirement.filename, "g1-synthetic-merge.yml")
        self.assertEqual(
            requirement.workflow_name,
            "G1 synthetic-merge qualification",
        )
        self.assertEqual(
            requirement.job_names,
            frozenset(
                {
                    "L1 exact two-parent merge source qualification",
                    "L1 exact-source-head aggregate candidate",
                }
            ),
        )
        self.assertEqual(requirement.artifact_kind, "synthetic")
        self.assertTrue(callable(_verify_workflow))

    def test_happy_path_binds_run_attempt_jobs_artifact_and_receipt(self) -> None:
        report = self.verify()
        self.assertEqual(
            report["result"],
            "L1_EXACT_HEAD_AND_SYNTHETIC_SOURCE_PASSED",
        )
        workflow = report["workflows"][0]
        self.assertEqual(workflow["run_id"], 1001)
        self.assertEqual(workflow["run_attempt"], 1)
        self.assertEqual(len(workflow["jobs"]), 2)
        self.assertEqual(len(workflow["artifacts"]), 1)
        self.assertEqual(
            workflow["artifacts"][0]["semantic"]["merge_commit"],
            "d" * 40,
        )

    def test_same_run_id_new_attempt_during_final_recheck_fails(self) -> None:
        initial = deepcopy(self.values[self.run_list_path])
        final = deepcopy(initial)
        final["workflow_runs"][0]["run_attempt"] = 2
        self.values[self.run_list_path] = [
            self.response(initial, self.run_list_path),
            self.response(final, self.run_list_path),
        ]
        with self.assertRaisesRegex(
            COMMON.AggregateError,
            "rerun attempt changed",
        ):
            self.verify()

    def test_same_attempt_job_identity_movement_fails(self) -> None:
        initial = deepcopy(self.values[self.jobs_path])
        final = deepcopy(initial)
        final["jobs"][0]["id"] += 1
        self.values[self.jobs_path] = [
            self.response(initial, self.jobs_path),
            self.response(final, self.jobs_path),
        ]
        with self.assertRaisesRegex(
            COMMON.AggregateError,
            "jobs, artifacts or receipt changed",
        ):
            self.verify()

    def test_same_attempt_artifact_metadata_movement_fails(self) -> None:
        initial = deepcopy(self.values[self.artifacts_path])
        final = deepcopy(initial)
        final["artifacts"][0]["expires_at"] = "2026-11-30T00:00:00Z"
        self.values[self.artifacts_path] = [
            self.response(initial, self.artifacts_path),
            self.response(final, self.artifacts_path),
        ]
        with self.assertRaisesRegex(
            COMMON.AggregateError,
            "jobs, artifacts or receipt changed",
        ):
            self.verify()

    def test_latest_failed_run_cannot_reuse_older_success(self) -> None:
        value = deepcopy(self.values[self.run_list_path])
        failed = self._run(
            1002,
            self.requirement.workflow_name,
            self.requirement.filename,
            conclusion="failure",
        )
        value["workflow_runs"].append(failed)
        value["total_count"] = 2
        self.values[self.run_list_path] = value
        with self.assertRaisesRegex(COMMON.AggregateError, "concluded 'failure'"):
            self.verify()

    def test_stale_base_run_is_not_a_candidate(self) -> None:
        value = deepcopy(self.values[self.run_list_path])
        value["workflow_runs"][0]["pull_requests"][0]["base"]["sha"] = "a" * 40
        self.values[self.run_list_path] = value
        with self.assertRaisesRegex(COMMON.AggregateError, "timed out waiting"):
            self.verify()

    def test_receipt_attempt_mismatch_fails(self) -> None:
        raw = self._zip(
            {
                "g1-synthetic-merge-evidence.json": self.synthetic_receipt(
                    attempt="2"
                ),
                "g1-merge-baseline.json": {
                    "qualification": "SOURCE_EVIDENCE_ONLY",
                    "gate": {"passed": False},
                },
            }
        )
        self.replace_semantic_archive(raw)
        with self.assertRaisesRegex(COMMON.AggregateError, "attempt mismatch"):
            self.verify()

    def test_pull_request_movement_during_verification_fails(self) -> None:
        path = f"repos/{self.repo}/pulls/{self.pr_number}"
        initial = self._pr()
        moved = self._pr(head="a" * 40)
        self.values[path] = [
            self.response(initial, path),
            self.response(moved, path),
        ]
        with self.assertRaisesRegex(COMMON.AggregateError, "head commit moved"):
            self.verify()

    def test_missing_required_protection_context_fails(self) -> None:
        path = f"repos/{self.repo}/branches/integration%2Fbase"
        branch = deepcopy(self.values[path])
        branch["protection"]["required_status_checks"]["contexts"].remove(
            "L1 exact-source-head aggregate candidate"
        )
        self.values[path] = branch
        with self.assertRaisesRegex(COMMON.AggregateError, "missing contexts"):
            self.verify()

    def test_local_cargo_lock_drift_fails(self) -> None:
        (self.repo_root / "Cargo.lock").write_text(
            "tampered\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            COMMON.AggregateError,
            "checkout is not clean|Cargo.lock digest",
        ):
            self.verify()

    def test_artifact_digest_mismatch_fails(self) -> None:
        url = self.semantic_artifact["archive_download_url"]
        self.blobs[url] += b"tamper"
        with self.assertRaisesRegex(
            COMMON.AggregateError,
            "byte count differs|digest mismatch",
        ):
            self.verify()

    def test_expired_artifact_fails(self) -> None:
        payload = deepcopy(self.values[self.artifacts_path])
        payload["artifacts"][0]["expired"] = True
        self.values[self.artifacts_path] = payload
        with self.assertRaisesRegex(COMMON.AggregateError, "is expired"):
            self.verify()

    def test_third_artifact_fails_closed(self) -> None:
        payload = deepcopy(self.values[self.artifacts_path])
        raw = self._zip({"unexpected.json": {}})
        payload["artifacts"].append(
            self._artifact(2003, 1001, "g1-unexpected-third-artifact", raw)
        )
        self.values[self.artifacts_path] = payload
        with self.assertRaisesRegex(
            COMMON.AggregateError,
            "incomplete or ambiguous",
        ):
            self.verify()

    def test_extra_zip_member_fails(self) -> None:
        raw = self._zip(
            {
                "g1-synthetic-merge-evidence.json": self.synthetic_receipt(),
                "g1-merge-baseline.json": {
                    "qualification": "SOURCE_EVIDENCE_ONLY",
                    "gate": {"passed": False},
                },
                "unexpected.json": {},
            }
        )
        self.replace_semantic_archive(raw)
        with self.assertRaisesRegex(COMMON.AggregateError, "member set drifted"):
            self.verify()

    def test_duplicate_json_member_in_receipt_fails(self) -> None:
        receipt = json.dumps(self.synthetic_receipt(), separators=(",", ":"))
        receipt = receipt[:-1] + ',"schema":"forged"}'
        baseline = json.dumps(
            {
                "qualification": "SOURCE_EVIDENCE_ONLY",
                "gate": {"passed": False},
            }
        )
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("g1-synthetic-merge-evidence.json", receipt)
            archive.writestr("g1-merge-baseline.json", baseline)
        self.replace_semantic_archive(output.getvalue())
        with self.assertRaisesRegex(COMMON.AggregateError, "duplicate JSON member"):
            self.verify()


class ArchiveAndJsonBoundaryTest(unittest.TestCase):
    def test_duplicate_zip_members_are_rejected(self) -> None:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("receipt.json", "{}")
            archive.writestr("receipt.json", "{}")
        with self.assertRaisesRegex(COMMON.AggregateError, "duplicate ZIP"):
            ARCHIVE._zip_json_members(
                output.getvalue(), frozenset({"receipt.json"}), "fixture"
            )

    def test_zip_path_traversal_is_rejected(self) -> None:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("../receipt.json", "{}")
        with self.assertRaisesRegex(COMMON.AggregateError, "unsafe path"):
            ARCHIVE._zip_json_members(
                output.getvalue(),
                frozenset({"../receipt.json"}),
                "fixture",
            )

    def test_zip_symlink_member_is_rejected(self) -> None:
        output = io.BytesIO()
        info = zipfile.ZipInfo("receipt.json")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr(info, "target")
        with self.assertRaisesRegex(COMMON.AggregateError, "symlink"):
            ARCHIVE._zip_json_members(
                output.getvalue(), frozenset({"receipt.json"}), "fixture"
            )

    def test_json_rejects_duplicate_nonfinite_and_excessive_depth(self) -> None:
        cases = (
            b'{"x":1,"x":2}',
            b'{"x":NaN}',
            b"[" * 65 + b"0" + b"]" * 65,
        )
        for raw in cases:
            with self.subTest(raw=raw[:30]), self.assertRaises(
                COMMON.AggregateError
            ):
                COMMON._strict_json(raw, "fixture")

    def test_json_size_checked_before_decoder(self) -> None:
        with mock.patch.object(
            COMMON, "MAX_MEMBER_BYTES", 8
        ), mock.patch.object(COMMON.json, "loads") as loads:
            with self.assertRaisesRegex(COMMON.AggregateError, "byte bound"):
                COMMON._strict_json(b'{"oversized":true}', "fixture")
        loads.assert_not_called()


class AggregateHttpBoundaryTest(unittest.TestCase):
    """In-memory transports test budgets and credentials, not live GitHub CI."""

    class Response(io.BytesIO):
        def __init__(
            self,
            raw: bytes = b"{}",
            *,
            url: str = "https://api.github.com/test",
            headers: tuple[tuple[str, str], ...] = (),
        ) -> None:
            super().__init__(raw)
            self.url = url
            self.status = 200
            self.requests: list[int] = []
            self.headers = Message()
            for name, value in headers:
                self.headers[name] = value

        def geturl(self) -> str:
            return self.url

        def getcode(self) -> int:
            return self.status

        def read(self, size: int = -1) -> bytes:
            self.requests.append(size)
            return super().read(size)

        def read1(self, size: int = -1) -> bytes:
            return self.read(size)

    def client(self, *responses: object, **kwargs: object) -> HTTP.GitHubApi:
        api = HTTP.GitHubApi(token="test-only-token", **kwargs)
        api._no_redirect = mock.Mock()
        api._no_redirect.open.side_effect = responses
        return api

    def redirect(
        self,
        target: str | None,
        *,
        url: str = "https://api.github.com/test",
        code: int = 302,
    ) -> tuple[HTTPError, Response]:
        body = self.Response(b"redirect body must not be read")
        headers = Message()
        if target is not None:
            headers["Location"] = target
        return HTTPError(url, code, "redirect", headers, body), body

    def test_exact_limit_uses_bounded_reads_and_closes_response(self) -> None:
        response = self.Response(b"abcdefgh")
        with mock.patch.object(HTTP, "MAX_ARCHIVE_BYTES", 8):
            result = self.client(response).get_bytes("test")
        self.assertEqual(result.raw, b"abcdefgh")
        self.assertTrue(response.requests)
        self.assertTrue(all(0 < size <= 9 for size in response.requests))
        self.assertTrue(response.closed)

    def test_overflow_rejected_without_capturing_whole_body(self) -> None:
        response = self.Response(b"x" * 4096)
        with mock.patch.object(HTTP, "MAX_ARCHIVE_BYTES", 8):
            with self.assertRaisesRegex(COMMON.AggregateError, "byte bound"):
                self.client(response).get_bytes("test")
        self.assertEqual(response.requests, [9])
        self.assertTrue(response.closed)

    def test_oversized_content_length_rejected_before_read(self) -> None:
        response = self.Response(b"x", headers=(("Content-Length", "9000"),))
        with mock.patch.object(HTTP, "MAX_ARCHIVE_BYTES", 8):
            with self.assertRaisesRegex(COMMON.AggregateError, "byte bound"):
                self.client(response).get_bytes("test")
        self.assertEqual(response.requests, [])
        self.assertTrue(response.closed)

    def test_duplicate_and_malformed_lengths_are_rejected(self) -> None:
        variants = [
            (("Content-Length", value),)
            for value in ("-1", "+2", "1.0", "NaN", "1, 1")
        ]
        variants.append(
            (("Content-Length", "2"), ("content-length", "2"))
        )
        for headers in variants:
            response = self.Response(headers=headers)
            with self.subTest(headers=headers), self.assertRaises(
                COMMON.AggregateError
            ):
                self.client(response).get_bytes("test")
            self.assertEqual(response.requests, [])
            self.assertTrue(response.closed)

    def test_error_body_and_signed_url_are_not_leaked(self) -> None:
        error, body = self.redirect(None, code=403)
        with self.assertRaises(COMMON.AggregateError) as caught:
            self.client(error).get_bytes("test?sig=test-only-secret")
        self.assertEqual(body.requests, [])
        self.assertTrue(body.closed)
        self.assertNotIn("test-only-secret", str(caught.exception))
        self.assertNotIn("redirect body", str(caught.exception))

    def test_cross_origin_redirect_drops_token(self) -> None:
        target = "https://objects.example/artifact?sig=test-only-secret"
        error, body = self.redirect(target)
        final = self.Response(b"zip", url=target)
        api = self.client()

        def open_next(request: object, **_kwargs: object) -> object:
            if request.full_url == "https://api.github.com/test":
                self.assertEqual(
                    request.get_header("Authorization"),
                    "Bearer test-only-token",
                )
                raise error
            self.assertTrue(body.closed)
            self.assertIsNone(request.get_header("Authorization"))
            return final

        api._no_redirect.open.side_effect = open_next
        self.assertEqual(api.get_bytes("test").raw, b"zip")
        self.assertTrue(final.closed)

    def test_redirect_roundtrip_never_restores_token(self) -> None:
        first, first_body = self.redirect("https://objects.example/one")
        second, second_body = self.redirect(
            "https://api.github.com/final",
            url="https://objects.example/one",
        )
        final = self.Response(url="https://api.github.com/final")
        api = self.client(first, second, final)
        api.get_bytes("test")
        requests = [call.args[0] for call in api._no_redirect.open.call_args_list]
        self.assertIsNotNone(requests[0].get_header("Authorization"))
        self.assertTrue(
            all(
                request.get_header("Authorization") is None
                for request in requests[1:]
            )
        )
        self.assertTrue(first_body.closed and second_body.closed and final.closed)

    def test_insecure_credentialed_or_control_redirect_is_rejected(self) -> None:
        targets = (
            "http://objects.example/a",
            "https://user:secret@objects.example/a",
            "https://objects.example:0/a",
            "https://objects.example:99999/a",
            "https://objects.example/a#fragment",
            "https://objects.example/a\nInjected",
        )
        for target in targets:
            error, body = self.redirect(target)
            api = self.client(error, self.Response())
            with self.subTest(target=target), self.assertRaises(
                COMMON.AggregateError
            ):
                api.get_bytes("test")
            self.assertEqual(api._no_redirect.open.call_count, 1)
            self.assertTrue(body.closed)

    def test_json_cannot_leave_configured_api_origin(self) -> None:
        api = self.client(self.Response(url="https://objects.example/a"))
        with self.assertRaisesRegex(COMMON.AggregateError, "origin"):
            api.get_json("https://objects.example/a")
        api._no_redirect.open.assert_not_called()

    def test_malformed_url_and_invalid_timeout_rejected_before_network(self) -> None:
        urls = (
            "http://api.github.com/",
            "https://u:p@api.github.com/",
            "https://api.github.com/#fragment",
            "https://api.github.com:bad/",
            "https://api.github.com/\n",
        )
        for url in urls:
            with self.subTest(url=url), self.assertRaises(COMMON.AggregateError):
                HTTP.GitHubApi(base_url=url)
        for value in (True, 0, -1, float("nan"), float("inf"), "30", 301):
            with self.subTest(timeout=value), self.assertRaises(
                COMMON.AggregateError
            ):
                HTTP.GitHubApi(timeout=value)

    def test_deadline_is_shared_across_reads(self) -> None:
        response = self.Response(b"abc")
        clock = [0.0]
        original = response.read1

        def slow_read(size: int) -> bytes:
            clock[0] += 2.0
            return original(min(size, 1))

        response.read1 = slow_read
        api = self.client(response, timeout=1.0)
        with mock.patch.object(
            HTTP.time, "monotonic", side_effect=lambda: clock[0]
        ):
            with self.assertRaisesRegex(COMMON.AggregateError, "deadline"):
                api.get_bytes("test")
        self.assertTrue(response.closed)

    def test_transport_error_hides_signed_url_and_has_no_retry(self) -> None:
        api = self.client(URLError("test-only-secret"), self.Response())
        with self.assertRaises(COMMON.AggregateError) as caught:
            api.get_bytes(
                "https://objects.example/artifact?sig=test-only-secret"
            )
        self.assertNotIn("test-only-secret", str(caught.exception))
        self.assertEqual(api._no_redirect.open.call_count, 1)

    def test_protocol_failure_is_typed_and_closes_response(self) -> None:
        response = self.Response()
        response.read1 = mock.Mock(
            side_effect=HTTPException("test-only protocol failure")
        )
        response.read = response.read1
        with self.assertRaises(COMMON.AggregateError):
            self.client(response).get_bytes("test")
        self.assertTrue(response.closed)


if __name__ == "__main__":
    unittest.main()
