from __future__ import annotations

from pathlib import Path
import sys
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "owner-open"))

from owner_open_broker_runtime import Request, validate_upstream_frame  # noqa: E402
from owner_open_connection_broker import Broker  # noqa: E402


class BrokerUnknownEnvelopeTest(unittest.TestCase):
    """Unknown and retired Host envelopes are not broadcast observations."""

    @staticmethod
    def _request(
        *,
        request_id: str = "request",
        upstream_seq: int = 11,
        request_sha256: str = "b" * 64,
    ) -> Request:
        return Request(
            owner_id="client",
            request_id=request_id,
            frame={"kind": "job.inspect", "payload": {}},
            expected_kinds=frozenset({"job.inspect.result"}),
            expected_job_id=None,
            timeout_ms=1_000,
            client_seq=0,
            upstream_seq=upstream_seq,
            request_sha256=request_sha256,
            correlation={},
            audit_binding=None,
        )

    @staticmethod
    def _frame(
        *,
        request_id: str = "request",
        upstream_seq: int = 11,
        request_sha256: str = "b" * 64,
    ) -> dict:
        return {
            "kind": "job.inspect.result",
            "seq": 0,
            "direction": "host_to_client",
            "payload": {},
            "broker_request_id": request_id,
            "broker_request_upstream_seq": upstream_seq,
            "broker_request_sha256": request_sha256,
        }

    @classmethod
    def _broker(cls, *requests: Request):
        broker = object.__new__(Broker)
        broker.pending_requests_lock = threading.Lock()
        broker.pending_requests = {
            (request.owner_id, request.request_id): request for request in requests
        }
        broker.active_condition = threading.Condition(threading.RLock())
        broker.upstream_uncertain = threading.Event()
        return broker

    def test_exact_live_envelope_is_owned(self) -> None:
        request = self._request()
        frame = self._frame()
        validate_upstream_frame(frame)
        self.assertIs(
            Broker._request_for_upstream_frame(self._broker(request), frame),
            request,
        )

    def test_unknown_id_sha_and_sequence_are_unowned(self) -> None:
        request = self._request()
        broker = self._broker(request)
        for changed in (
            {"request_id": "old-request"},
            {"request_sha256": "c" * 64},
            {"upstream_seq": 12},
        ):
            frame = self._frame(**changed)
            validate_upstream_frame(frame)
            self.assertIsNone(Broker._request_for_upstream_frame(broker, frame))

    def test_terminalized_request_is_retired(self) -> None:
        request = self._request()
        request.terminalized = True
        frame = self._frame()
        validate_upstream_frame(frame)
        self.assertIsNone(Broker._request_for_upstream_frame(self._broker(request), frame))

    def test_ambiguous_envelope_fails_closed(self) -> None:
        first = self._request(request_id="first")
        second = self._request(request_id="second")
        # Deliberately give both requests the same immutable envelope to model
        # an in-memory invariant violation; selecting either owner would make
        # a stale line observable on the wrong connection.
        second.request_id = first.request_id
        frame = self._frame()
        validate_upstream_frame(frame)
        self.assertIsNone(Broker._request_for_upstream_frame(self._broker(first, second), frame))

    def test_uncertain_transition_suppresses_all_envelopes(self) -> None:
        request = self._request()
        broker = self._broker(request)
        broker.upstream_uncertain.set()
        frame = self._frame()
        validate_upstream_frame(frame)
        self.assertIsNone(Broker._request_for_upstream_frame(broker, frame))


if __name__ == "__main__":
    unittest.main()
