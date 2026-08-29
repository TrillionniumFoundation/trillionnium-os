from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "owner-open"))

from owner_open_broker_runtime import (
    Request,
    correlation_matches,
    frame_correlation,
    response_matches,
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
        self.assertFalse(response_matches(self.request(), response))

    def test_stale_direct_error_cannot_steal_active_request_ownership(self) -> None:
        response = self.response("write-old")
        response["kind"] = "job.error"
        self.assertFalse(correlation_matches(self.request(), response))


if __name__ == "__main__":
    unittest.main()
