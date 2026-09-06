from __future__ import annotations

from copy import deepcopy
import hashlib
import io
import json
from email.message import Message
from http.client import HTTPException, HTTPResponse
from urllib.error import HTTPError, URLError
from unittest import mock

from tools import g1_pr_aggregate_api as HTTP
from tools import g1_pr_aggregate_archive as ARCHIVE
from tools import g1_pr_aggregate_common as COMMON
import unittest

from tools.tests.g1_pr_aggregate_fixture import AGG, NOW, FakeApi, AggregateFixture


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

    def _verify_complete_report(self):
        # Exercise the production four-family report without the legacy fixture's
        # three-family presentation adapter.
        return AGG.verify_pr_aggregate(
            repository=self.repo, pr_number=self.pr_number,
            expected_base_commit=self.base_commit, expected_head_commit=self.head_commit,
            repo_root=self.repo_root, api=FakeApi(self.values, self.blobs),
            timeout_seconds=0, poll_seconds=0, now=NOW,
        )

    def test_successful_report_does_not_publish_download_capabilities(self) -> None:
        original = FakeApi.get_bytes
        capabilities = (
            "https://objects.example/archive.zip?sig=test-only-query-capability",
            "https://objects.example/test-only-path-capability/archive.zip",
        )
        for final_url in capabilities:
            with self.subTest(final_url=final_url):
                def redirected(api, path):
                    response = original(api, path)
                    return AGG.ApiResponse(response.value, response.raw, final_url, {})

                with mock.patch.object(FakeApi, "get_bytes", redirected):
                    report = self._verify_complete_report()
                self.assertEqual(len(report["workflows"]), 4)
                output = self.repo_root.parent / "aggregate-report.json"
                AGG._write_json(output, report)
                self.assertEqual(json.loads(output.read_text()), report)
                serialized = AGG._canonical(report).decode()
                self.assertNotIn(final_url, serialized)
                self.assertNotIn("test-only-", serialized)
                for workflow in report["workflows"]:
                    for artifact in workflow["artifacts"]:
                        self.assertNotIn("download_url", artifact)
                        self.assertEqual(
                            artifact["archive_api_path"],
                            f"repos/{self.repo}/actions/artifacts/{artifact['id']}/zip",
                        )

    def test_report_hash_does_not_depend_on_transport_url_rotation(self) -> None:
        original = FakeApi.get_bytes
        reports = []
        for generation in range(2):
            def rotated(api, path):
                response = original(api, path)
                url = f"https://objects.example/rotated-{generation}?sig=test-only-{generation}"
                return AGG.ApiResponse(response.value, response.raw, url, {})

            with mock.patch.object(FakeApi, "get_bytes", rotated):
                reports.append(self._verify_complete_report())
        self.assertEqual(reports[0], reports[1])

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

    def test_synthetic_diagnostic_artifact_must_bind_exact_head(self) -> None:
        path = f"repos/{self.repo}/actions/runs/1001/artifacts?per_page=100"
        payload = deepcopy(self.values[path])
        assert isinstance(payload, dict)
        artifacts = payload["artifacts"]
        assert isinstance(artifacts, list) and len(artifacts) == 2
        diagnostic = artifacts[1]
        assert isinstance(diagnostic, dict)
        diagnostic["name"] = f"g1-merge-test-diagnostics-{'a' * 40}"
        self.values[path] = payload
        with self.assertRaisesRegex(AGG.AggregateError, "incomplete or ambiguous"):
            self.verify()

    def test_synthetic_artifact_set_rejects_a_third_artifact(self) -> None:
        path = f"repos/{self.repo}/actions/runs/1001/artifacts?per_page=100"
        payload = deepcopy(self.values[path])
        assert isinstance(payload, dict)
        artifacts = payload["artifacts"]
        assert isinstance(artifacts, list) and len(artifacts) == 2
        artifacts.append(
            self._artifact(
                2011,
                1001,
                "g1-unexpected-third-artifact",
                self._zip({"unexpected.json": {}}),
            )
        )
        self.values[path] = payload
        with self.assertRaisesRegex(AGG.AggregateError, "incomplete or ambiguous"):
            self.verify()

    def test_synthetic_artifact_set_rejects_a_second_semantic_receipt(self) -> None:
        path = f"repos/{self.repo}/actions/runs/1001/artifacts?per_page=100"
        payload = deepcopy(self.values[path])
        assert isinstance(payload, dict)
        artifacts = payload["artifacts"]
        assert isinstance(artifacts, list) and len(artifacts) == 2
        artifacts.append(
            self._artifact(
                2012,
                1001,
                f"g1-synthetic-merge-{'e' * 40}",
                self._zip({"not-consumed.json": {}}),
            )
        )
        self.values[path] = payload
        with self.assertRaisesRegex(
            AGG.AggregateError, "exactly one semantic merge artifact"
        ):
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

    def test_evidence_report_plan_gap_binding_is_mandatory_and_equal(self) -> None:
        for mode in ("missing", "mismatched"):
            with self.subTest(mode=mode):
                report, plan = self._evidence_report(), self._promotion_plan()
                if mode == "missing":
                    plan.pop("gap_specs_sha256")
                else:
                    plan["gap_specs_sha256"] = "8" * 64
                self._replace_artifact_blob(1003, 0, self._zip({
                    "g1-evidence-report.json": report, "g1-promotion-plan.json": plan,
                }))
                with self.assertRaisesRegex(AGG.AggregateError, "gap_specs_sha256|snapshot mismatch"):
                    self.verify()

    def test_evidence_report_plan_closure_claims_cannot_diverge(self) -> None:
        for mode in ("unresolved", "zero_gap"):
            with self.subTest(mode=mode):
                report, plan = self._evidence_report(), self._promotion_plan()
                if mode == "unresolved":
                    plan["unresolved_gaps"] = []
                else:
                    plan["zero_gap_after_plan"] = True
                self._replace_artifact_blob(1003, 0, self._zip({
                    "g1-evidence-report.json": report, "g1-promotion-plan.json": plan,
                }))
                with self.assertRaisesRegex(AGG.AggregateError, "unresolved gaps mismatch|closure flags contradict"):
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



class AggregateHttpBoundaryTest(unittest.TestCase):
    """In-memory transports test budgets and credentials, not live GitHub CI."""

    class Response(io.BytesIO):
        def __init__(self, raw=b"{}", *, url="https://api.github.com/test", headers=()):
            super().__init__(raw)
            self.url, self.status, self.requests = url, 200, []
            self.headers = Message()
            for name, value in headers:
                self.headers[name] = value

        def geturl(self):
            return self.url

        def getcode(self):
            return self.status

        def read(self, size=-1):
            self.requests.append(size)
            return super().read(size)

        def read1(self, size=-1):
            return self.read(size)

    def client(self, *responses, **kwargs):
        api = HTTP.GitHubApi(token="test-only-token", **kwargs)
        api._no_redirect = mock.Mock()
        api._no_redirect.open.side_effect = responses
        return api

    def redirect(self, target, *, url="https://api.github.com/test", code=302):
        body = self.Response(b"redirect body must not be read")
        headers = Message()
        if target is not None:
            headers['Location'] = target
        return HTTPError(url, code, 'redirect', headers, body), body

    def test_exact_limit_uses_bounded_reads_and_closes_response(self):
        response = self.Response(b"abcdefgh")
        api = self.client(response)
        with mock.patch.object(HTTP, 'MAX_ARCHIVE_BYTES', 8, create=True):
            result = api.get_bytes('test')
        self.assertEqual(result.raw, b"abcdefgh")
        self.assertTrue(response.requests)
        self.assertTrue(all(0 < size <= 9 for size in response.requests))
        self.assertTrue(response.closed)

    def test_overflow_is_rejected_during_read_without_capture_of_whole_body(self):
        response = self.Response(b'x' * 4096)
        api = self.client(response)
        with mock.patch.object(HTTP, 'MAX_ARCHIVE_BYTES', 8, create=True):
            with self.assertRaisesRegex(HTTP.AggregateError, 'byte bound'):
                api.get_bytes('test')
        self.assertEqual(response.requests, [9])
        self.assertTrue(response.closed)

    def test_json_has_separate_response_budget(self):
        response = self.Response(b'{"x":"too much"}')
        with mock.patch.object(HTTP, 'MAX_JSON_RESPONSE_BYTES', 8, create=True):
            with self.assertRaisesRegex(HTTP.AggregateError, 'byte bound'):
                self.client(response).get_json('test')
        self.assertTrue(response.closed)

    def test_positive_short_reads_complete_exact_bytes(self):
        response = self.Response(b'abcdef')
        original = response.read1
        response.read1 = lambda size: original(min(size, 2))
        self.assertEqual(self.client(response).get_bytes('test').raw, b'abcdef')
        self.assertTrue(response.closed)

    def test_oversized_content_length_rejected_before_body_read(self):
        response = self.Response(b'x', headers=[('Content-Length', '9000')])
        with mock.patch.object(HTTP, 'MAX_ARCHIVE_BYTES', 8, create=True):
            with self.assertRaisesRegex(HTTP.AggregateError, 'byte bound'):
                self.client(response).get_bytes('test')
        self.assertEqual(response.requests, [])
        self.assertTrue(response.closed)

    def test_malformed_or_duplicate_lengths_rejected(self):
        variants = [[('Content-Length', value)] for value in ('-1', '+2', '1.0', 'NaN', '1, 1', '9' * 40)]
        variants.append([('Content-Length', '2'), ('content-length', '2')])
        for headers in variants:
            response = self.Response(headers=headers)
            with self.subTest(headers=headers), self.assertRaises(HTTP.AggregateError):
                self.client(response).get_bytes('test')
            self.assertEqual(response.requests, [])
            self.assertTrue(response.closed)

    def test_truncated_content_length_is_not_accepted(self):
        response = self.Response(b'abc', headers=[('Content-Length', '4')])
        with self.assertRaisesRegex(HTTP.AggregateError, 'Content-Length'):
            self.client(response).get_bytes('test')
        self.assertTrue(response.closed)

    def test_framing_conflict_and_encoded_body_are_rejected(self):
        for headers in ([('Content-Length', '2'), ('Transfer-Encoding', 'chunked')],
                        [('Content-Encoding', 'gzip')], [('Transfer-Encoding', 'unknown')]):
            response = self.Response(headers=headers)
            with self.subTest(headers=headers), self.assertRaises(HTTP.AggregateError):
                self.client(response).get_bytes('test')
            self.assertEqual(response.requests, [])
            self.assertTrue(response.closed)

    def test_real_httpresponse_chunked_body_obeys_capture_bound(self):
        class Socket:
            def makefile(self, *args, **kwargs):
                return io.BytesIO(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n5\r\nefghi\r\n0\r\n\r\n')
        response = HTTPResponse(Socket(), url='https://api.github.com/test')
        response.begin()
        response.url = 'https://api.github.com/test'  # urllib attaches this after open.
        with mock.patch.object(HTTP, 'MAX_ARCHIVE_BYTES', 8, create=True):
            with self.assertRaisesRegex(HTTP.AggregateError, 'byte bound'):
                self.client(response).get_bytes('test')
        self.assertTrue(response.closed)

    def test_http_protocol_failure_is_typed_and_response_is_closed(self):
        response = self.Response()
        response.read1 = mock.Mock(side_effect=HTTPException('test-only protocol failure'))
        response.read = response.read1
        with self.assertRaises(HTTP.AggregateError):
            self.client(response).get_bytes('test')
        self.assertTrue(response.closed)

    def test_error_body_is_never_read_or_leaked(self):
        error, body = self.redirect(None, code=403)
        with self.assertRaises(HTTP.AggregateError) as caught:
            self.client(error).get_bytes('test?sig=test-only-secret')
        self.assertEqual(body.requests, [])
        self.assertTrue(body.closed)
        self.assertNotIn('test-only-secret', str(caught.exception))
        self.assertNotIn('redirect body', str(caught.exception))

    def test_redirect_response_closed_before_following_and_token_dropped(self):
        error, body = self.redirect('https://objects.example/artifact?sig=test-only-secret')
        final = self.Response(b'zip', url='https://objects.example/artifact?sig=test-only-secret')
        api = self.client()
        def open_next(request, **kwargs):
            if request.full_url == 'https://api.github.com/test':
                self.assertEqual(request.get_header('Authorization'), 'Bearer test-only-token')
                raise error
            self.assertTrue(body.closed)
            self.assertIsNone(request.get_header('Authorization'))
            return final
        api._no_redirect.open.side_effect = open_next
        self.assertEqual(api.get_bytes('test').raw, b'zip')
        self.assertEqual(body.requests, [])
        self.assertTrue(final.closed)

    def test_redirect_roundtrip_does_not_restore_token(self):
        one, b1 = self.redirect('https://objects.example/one')
        two, b2 = self.redirect('https://api.github.com/final', url='https://objects.example/one')
        final = self.Response(url='https://api.github.com/final')
        api = self.client(one, two, final)
        api.get_bytes('test')
        requests = [call.args[0] for call in api._no_redirect.open.call_args_list]
        self.assertIsNotNone(requests[0].get_header('Authorization'))
        self.assertTrue(all(r.get_header('Authorization') is None for r in requests[1:]))
        self.assertTrue(b1.closed and b2.closed and final.closed)

    def test_redirect_loop_stops_without_extra_request(self):
        error, body = self.redirect('/test')
        api = self.client(error, self.Response())
        with self.assertRaisesRegex(HTTP.AggregateError, 'redirect'):
            api.get_bytes('test')
        self.assertEqual(api._no_redirect.open.call_count, 1)
        self.assertTrue(body.closed)

    def test_redirect_hop_budget_is_finite(self):
        redirects = [self.redirect(f'/hop-{i}') for i in range(6)]
        api = self.client(*(item[0] for item in redirects), self.Response())
        with self.assertRaisesRegex(HTTP.AggregateError, 'redirect'):
            api.get_bytes('test')
        self.assertEqual(api._no_redirect.open.call_count, 6)
        self.assertTrue(all(body.closed for _error, body in redirects))

    def test_insecure_or_credentialed_redirect_rejected_before_next_open(self):
        for target in ('http://objects.example/a', 'https://user:secret@objects.example/a',
                       'https://objects.example:0/a', 'https://objects.example:99999/a',
                       'https://objects.example/a#fragment', 'https://objects.example/a\nInjected'):
            error, body = self.redirect(target)
            api = self.client(error, self.Response())
            with self.subTest(target=target), self.assertRaises(HTTP.AggregateError):
                api.get_bytes('test')
            self.assertEqual(api._no_redirect.open.call_count, 1)
            self.assertTrue(body.closed)

    def test_duplicate_redirect_location_rejected(self):
        error, body = self.redirect('/one')
        error.headers['Location'] = '/two'
        api = self.client(error, self.Response())
        with self.assertRaises(HTTP.AggregateError):
            api.get_bytes('test')
        self.assertEqual(api._no_redirect.open.call_count, 1)
        self.assertTrue(body.closed)

    def test_json_stays_on_configured_api_origin(self):
        api = self.client(self.Response(url='https://objects.example/a'))
        with self.assertRaisesRegex(HTTP.AggregateError, 'origin'):
            api.get_json('https://objects.example/a')
        api._no_redirect.open.assert_not_called()
        error, body = self.redirect('https://objects.example/a')
        api = self.client(error, self.Response(url='https://objects.example/a'))
        with self.assertRaisesRegex(HTTP.AggregateError, 'origin'):
            api.get_json('test')
        self.assertEqual(api._no_redirect.open.call_count, 1)
        self.assertTrue(body.closed)

    def test_direct_artifact_origin_receives_no_api_token(self):
        api = self.client(self.Response(url='https://objects.example/a'))
        api.get_bytes('https://objects.example/a')
        self.assertIsNone(api._no_redirect.open.call_args.args[0].get_header('Authorization'))

    def test_malformed_url_and_invalid_timeout_rejected_before_network(self):
        for url in ('http://api.github.com/', 'https://u:p@api.github.com/',
                    'https://api.github.com/#fragment', 'https://api.github.com:bad/',
                    'https://api.github.com/\n', 'https://api.github.com/' + 'a' * 9000):
            with self.subTest(url=url[:50]), self.assertRaises(HTTP.AggregateError):
                HTTP.GitHubApi(base_url=url)
        for value in (True, 0, -1, float('nan'), float('inf'), '30', 301):
            with self.subTest(timeout=value), self.assertRaises(HTTP.AggregateError):
                HTTP.GitHubApi(timeout=value)

    def test_deadline_shared_across_body_reads(self):
        response = self.Response(b'abc')
        clock = [0.0]
        original = response.read1
        def slow_read(size):
            clock[0] += 2.0
            return original(min(size, 1))
        response.read1 = slow_read
        api = self.client(response, timeout=1.0)
        with mock.patch.object(HTTP.time, 'monotonic', side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(HTTP.AggregateError, 'deadline'):
                api.get_bytes('test')
        self.assertEqual(len(response.requests), 1)
        self.assertTrue(response.closed)

    def test_redirects_do_not_reset_request_deadline(self):
        error, body = self.redirect('/next')
        clock = [0.0]
        api = self.client(timeout=1.0)
        def redirect_after_deadline(*args, **kwargs):
            clock[0] = 2.0
            raise error
        api._no_redirect.open.side_effect = redirect_after_deadline
        with mock.patch.object(HTTP.time, 'monotonic', side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(HTTP.AggregateError, 'deadline'):
                api.get_bytes('test')
        self.assertEqual(api._no_redirect.open.call_count, 1)
        self.assertTrue(body.closed)

    def test_transport_error_hides_signed_url_and_has_no_retry(self):
        api = self.client(URLError('test-only-secret'), self.Response())
        with self.assertRaises(HTTP.AggregateError) as caught:
            api.get_bytes('https://objects.example/artifact?sig=test-only-secret')
        self.assertNotIn('test-only-secret', str(caught.exception))
        self.assertEqual(api._no_redirect.open.call_count, 1)

    def test_download_receipt_omits_both_initial_and_redirect_capabilities(self):
        raw = b"test-only-archive-bytes"
        initial = "https://api.github.com/test-only-initial-path?sig=test-only-initial-query"
        final = "https://objects.example/test-only-final-path?sig=test-only-final-query"
        error, error_body = self.redirect(final, url=initial)
        response = self.Response(raw, url=final)
        client = self.client(error, response)
        artifact = dict(
            id=7, name="fixture", size_in_bytes=len(raw),
            digest="sha256:" + hashlib.sha256(raw).hexdigest(),
            archive_download_url=initial, expires_at="2026-09-08T00:00:00Z",
        )
        received, receipt = ARCHIVE._download_artifact(
            ARCHIVE._RepoApi(client, "example/repo"), artifact,
        )
        self.assertEqual(received, raw)
        self.assertEqual(receipt, {
            "id": 7, "name": "fixture", "size_in_bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "expires_at": artifact["expires_at"],
            "archive_api_path": "repos/example/repo/actions/artifacts/7/zip",
        })
        self.assertEqual(client._no_redirect.open.call_count, 2)
        requests = client._no_redirect.open.call_args_list
        self.assertEqual(requests[0].args[0].full_url, initial)
        self.assertEqual(requests[1].args[0].full_url, final)
        self.assertEqual(requests[0].args[0].get_header("Authorization"), "Bearer test-only-token")
        self.assertIsNone(requests[1].args[0].get_header("Authorization"))
        self.assertTrue(error_body.closed)
        self.assertTrue(response.closed)

    def test_metadata_archive_size_rejected_before_download(self):
        api = mock.Mock()
        artifact = dict(id=1, name='fixture', size_in_bytes=COMMON.MAX_ARCHIVE_BYTES + 1,
                        digest='sha256:' + '0' * 64, archive_download_url='https://api.github.com/test')
        with self.assertRaisesRegex(COMMON.AggregateError, 'archive byte bound'):
            ARCHIVE._download_artifact(api, artifact)
        api.get_bytes.assert_not_called()

    def test_parser_rejects_overflow_and_excessive_integer_literals(self):
        for raw in (b'{"x":1e9999}', b'{"x":-1e9999}', b'{"x":NaN}',
                    b'{"x":' + b'9' * 5000 + b'}'):
            with self.subTest(raw=raw[:25]), self.assertRaises(COMMON.AggregateError):
                COMMON._strict_json(raw, 'test-only')

    def test_json_depth_checked_before_recursive_decoder(self):
        with mock.patch.object(COMMON.json, 'loads') as loads:
            with self.assertRaisesRegex(COMMON.AggregateError, 'nesting'):
                COMMON._strict_json(b'[' * 65 + b'0' + b']' * 65, 'test-only')
        loads.assert_not_called()

    def test_json_size_checked_before_decoder(self):
        with mock.patch.object(COMMON, 'MAX_MEMBER_BYTES', 8), mock.patch.object(COMMON.json, 'loads') as loads:
            with self.assertRaisesRegex(COMMON.AggregateError, 'byte bound'):
                COMMON._strict_json(b'{"oversized":true}', 'test-only')
        loads.assert_not_called()

    def test_finite_json_and_escaped_string_brackets_are_preserved(self):
        value = {'x': '[' * 200 + '\\"' + ']' * 200, 'nested': {'n': 1.25}, 'list': [1, True]}
        self.assertEqual(COMMON._strict_json(json.dumps(value).encode(), 'test-only'), value)


    def test_five_redirects_are_allowed_without_credentials_after_first(self):
        redirects = [self.redirect(f'/hop-{i}') for i in range(5)]
        final = self.Response(url='https://api.github.com/hop-4')
        api = self.client(*(item[0] for item in redirects), final)
        self.assertEqual(api.get_bytes('test').raw, b'{}')
        self.assertEqual(api._no_redirect.open.call_count, 6)
        self.assertTrue(all(body.closed for _error, body in redirects))
        self.assertTrue(final.closed)

    def test_same_origin_json_redirect_is_valid_but_not_authenticated_again(self):
        error, body = self.redirect('/next')
        api = self.client(error, self.Response(b'{"ok":true}', url='https://api.github.com/next'))
        self.assertEqual(api.get_json('test').value, {'ok': True})
        self.assertIsNone(api._no_redirect.open.call_args.args[0].get_header('Authorization'))
        self.assertTrue(body.closed)

    def test_missing_redirect_location_closes_without_following(self):
        error, body = self.redirect(None)
        api = self.client(error)
        with self.assertRaisesRegex(HTTP.AggregateError, 'Location'):
            api.get_bytes('test')
        self.assertEqual(api._no_redirect.open.call_count, 1)
        self.assertTrue(body.closed)

    def test_partial_http_status_is_never_qualified(self):
        response = self.Response(b'partial')
        response.status = 206
        with self.assertRaisesRegex(HTTP.AggregateError, '200'):
            self.client(response).get_bytes('test')
        self.assertEqual(response.requests, [])
        self.assertTrue(response.closed)

    def test_nonbyte_or_oversized_reader_return_is_rejected(self):
        for chunk in (None, 'text', b'oversized' * 10):
            response = self.Response()
            response.read1 = mock.Mock(return_value=chunk)
            with self.subTest(chunk=repr(chunk)[:20]), mock.patch.object(HTTP, 'MAX_ARCHIVE_BYTES', 8):
                with self.assertRaisesRegex(HTTP.AggregateError, 'invalid HTTP body read'):
                    self.client(response).get_bytes('test')
            self.assertTrue(response.closed)

    def test_request_method_encoding_and_origin_are_explicit(self):
        api = self.client(self.Response())
        api.get_json('test')
        request = api._no_redirect.open.call_args.args[0]
        self.assertEqual(request.get_method(), 'GET')
        self.assertEqual(request.get_header('Accept-encoding'), 'identity')
        self.assertEqual(request.get_header('Authorization'), 'Bearer test-only-token')
        self.assertGreater(api._no_redirect.open.call_args.kwargs['timeout'], 0)

if __name__ == "__main__":
    unittest.main()
