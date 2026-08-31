from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "owner-open"))

from owner_open_broker_runtime import (
    BrokerError,
    Request,
    canonical_request_frame,
    correlation_matches,
    frame_correlation,
    response_envelope_matches,
    response_matches,
    validate_upstream_frame,
)


class BrokerCorrelationStrictTest(unittest.TestCase):
    @staticmethod
    def request() -> Request:
        frame = {
            "kind": "job.write",
            "seq": 7,
            "session_id": "session",
            "profile_id": "owner-open",
            "task_id": "task",
            "turn_id": "turn",
            "turn_stream_id": "turn-stream",
            "job_id": "job",
            "payload": {
                "session_id": "session",
                "profile_id": "owner-open",
                "task_id": "task",
                "turn_id": "turn",
                "turn_stream_id": "turn-stream",
                "job_id": "job",
                "operation_id": "write-new",
                "request_sha256": "a" * 64,
            },
        }
        return Request(
            owner_id="client",
            request_id="request",
            frame=frame,
            expected_kinds=frozenset({"job.control.result"}),
            expected_job_id="job",
            timeout_ms=1_000,
            client_seq=7,
            upstream_seq=11,
            request_sha256="b" * 64,
            correlation=frame_correlation(frame),
            audit_binding=None,
        )

    @staticmethod
    def response(operation_id: str | None) -> dict:
        payload = {
            "session_id": "session",
            "profile_id": "owner-open",
            "task_id": "task",
            "turn_id": "turn",
            "turn_stream_id": "turn-stream",
            "job_id": "job",
            "request_sha256": "a" * 64,
        }
        if operation_id is not None:
            payload["operation_id"] = operation_id
        return {
            "kind": "job.control.result",
            "seq": 23,
            "direction": "host_to_client",
            "broker_request_id": "request",
            "broker_request_upstream_seq": 11,
            "broker_request_sha256": "b" * 64,
            "session_id": "session",
            "profile_id": "owner-open",
            "task_id": "task",
            "turn_id": "turn",
            "turn_stream_id": "turn-stream",
            "job_id": "job",
            "payload": payload,
        }

    def test_exact_operation_and_lineage_match(self) -> None:
        self.assertTrue(response_matches(self.request(), self.response("write-new")))

    def test_response_requires_exact_broker_envelope(self) -> None:
        response = self.response("write-new")
        self.assertTrue(response_envelope_matches(self.request(), response))
        for field, value in (
            ("broker_request_id", "old-request"),
            ("broker_request_sha256", "c" * 64),
            ("broker_request_upstream_seq", 10),
            ("direction", "client_to_host"),
            ("seq", -1),
        ):
            candidate = self.response("write-new")
            candidate[field] = value
            self.assertFalse(
                response_matches(self.request(), candidate),
                msg=f"stale/malformed envelope field {field} was accepted",
            )

    def test_missing_broker_envelope_cannot_resolve_same_kind_frame(self) -> None:
        response = self.response("write-new")
        for field in (
            "broker_request_id",
            "broker_request_sha256",
            "broker_request_upstream_seq",
        ):
            candidate = self.response("write-new")
            candidate.pop(field)
            self.assertFalse(response_matches(self.request(), candidate))

    def test_conflicting_broker_envelope_mirror_fails_closed(self) -> None:
        response = self.response("write-new")
        response["payload"]["broker_request_id"] = "old-request"
        self.assertFalse(response_envelope_matches(self.request(), response))

    def test_delayed_old_operation_cannot_satisfy_new_request(self) -> None:
        self.assertFalse(response_matches(self.request(), self.response("write-old")))

    def test_missing_required_operation_cannot_satisfy_new_request(self) -> None:
        self.assertFalse(response_matches(self.request(), self.response(None)))

    def test_same_kind_and_job_but_wrong_turn_cannot_cross_deliver(self) -> None:
        response = self.response("write-new")
        response["turn_id"] = "old-turn"
        response["payload"]["turn_id"] = "old-turn"
        self.assertFalse(response_matches(self.request(), response))

    def test_exact_correlated_direct_error_is_eligible_for_active_request(self) -> None:
        response = self.response("write-new")
        response["kind"] = "job.error"
        self.assertTrue(correlation_matches(self.request(), response))
        self.assertTrue(response_envelope_matches(self.request(), response))

    def test_stale_direct_error_cannot_steal_active_request_ownership(self) -> None:
        response = self.response("write-old")
        response["kind"] = "job.error"
        self.assertFalse(correlation_matches(self.request(), response))

    def test_conflicting_top_level_and_payload_mirror_fails_closed(self) -> None:
        response = self.response("write-new")
        response["operation_id"] = "write-other"
        with self.assertRaisesRegex(
            BrokerError,
            "conflicting mirrored correlation field operation_id",
        ):
            frame_correlation(response)

    def test_conflicting_stream_aliases_fail_closed(self) -> None:
        frame = {
            "turn_stream_id": "stream-a",
            "stream_id": "stream-b",
            "payload": {},
        }
        with self.assertRaisesRegex(
            BrokerError,
            "conflicting mirrored correlation field turn_stream_id",
        ):
            frame_correlation(frame)

    def test_non_string_mirror_does_not_fall_back_to_payload(self) -> None:
        frame = {"job_id": 7, "payload": {"job_id": "job"}}
        with self.assertRaisesRegex(BrokerError, "frame.job_id must be a string"):
            frame_correlation(frame)

    def test_upstream_broadcast_requires_host_envelope(self) -> None:
        response = self.response("write-new")
        validate_upstream_frame(response)
        for field, value in (
            ("direction", "client_to_host"),
            ("broker_request_id", None),
            ("broker_request_sha256", "not-a-digest"),
            ("broker_request_upstream_seq", -1),
            ("seq", -1),
        ):
            candidate = self.response("write-new")
            if value is None:
                candidate.pop(field)
            else:
                candidate[field] = value
            with self.assertRaises(BrokerError, msg=f"invalid upstream field {field} accepted"):
                validate_upstream_frame(candidate)

    def test_upstream_payload_mirror_must_match(self) -> None:
        response = self.response("write-new")
        response["payload"]["seq"] = response["seq"] + 1
        with self.assertRaisesRegex(BrokerError, "payload mirror"):
            validate_upstream_frame(response)

    def test_request_digest_frame_is_stable_across_reconnect_transport_fields(self) -> None:
        first = {
            "kind": "job.inspect",
            "seq": 7,
            "client_seq": 7,
            "direction": "client_to_host",
            "connection_id": "connection-a",
            "event_id": "event-a",
            "request_sha256": "a" * 64,
            "turn_stream_id": "stream-a",
            "payload": {"job_id": "job-a", "turn_stream_id": "stream-a"},
        }
        replay = {
            "kind": "job.inspect",
            "seq": 0,
            "direction": "client_to_host",
            "connection_id": "connection-b",
            "server_request_id": "server-b",
            "turn_stream_id": "stream-a",
            "payload": {"job_id": "job-a", "stream_id": "stream-a"},
        }
        self.assertEqual(canonical_request_frame(first), canonical_request_frame(replay))

    def test_request_digest_rejects_conflicting_transport_mirror(self) -> None:
        with self.assertRaisesRegex(
            BrokerError, "conflicting mirrored transport field seq"
        ):
            canonical_request_frame(
                {
                    "kind": "job.inspect",
                    "seq": 1,
                    "direction": "client_to_host",
                    "payload": {"seq": 2, "job_id": "job"},
                }
            )


if __name__ == "__main__":
    unittest.main()
