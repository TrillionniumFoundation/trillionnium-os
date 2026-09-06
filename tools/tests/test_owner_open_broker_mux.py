from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "owner-open"))

from owner_open_broker_mux import MuxError, WeightedFairMux, ordering_key_for_frame


@dataclass
class Request:
    owner_id: str
    request_id: str
    ordering_key: str
    upstream_seq: int
    deadline_monotonic: float = float("inf")


class OrderingKeyTest(unittest.TestCase):
    def test_mirrored_key_is_stable(self) -> None:
        scope = {
            "session_id": "session-a",
            "profile_id": "profile-a",
            "task_id": "task-a",
            "turn_id": "turn-a",
            "turn_stream_id": "stream-a",
        }
        key = ordering_key_for_frame(
            {
                "kind": "job.inspect",
                **scope,
                "job_id": "job-a",
                "payload": {**scope, "job_id": "job-a"},
            },
            "client-a",
        )
        self.assertTrue(key.startswith("effect:v1:"))
        # The key is a length-delimited tuple, not a first-present label or a
        # JSON insertion-order rendering.
        self.assertNotIn('"job-a"', key)

    def test_partial_or_inconsistent_lineage_fails_closed(self) -> None:
        with self.assertRaisesRegex(MuxError, "complete scope"):
            ordering_key_for_frame(
                {"kind": "job.inspect", "job_id": "job-a"},
                "client-a",
            )
        with self.assertRaises(MuxError):
            ordering_key_for_frame(
                {
                    "kind": "job.inspect",
                    "session_id": "session-a",
                    "profile_id": "profile-a",
                    "task_id": "task-a",
                    "turn_id": "turn-a",
                    "turn_stream_id": "stream-a",
                    "job_id": "job-a",
                    "payload": {"job_id": "job-b"},
                },
                "client-a",
            )

    def test_same_job_lineage_does_not_split_by_operation_id(self) -> None:
        scope = {
            "session_id": "session-a",
            "profile_id": "profile-a",
            "task_id": "task-a",
            "turn_id": "turn-a",
            "turn_stream_id": "stream-a",
            "job_id": "job-a",
        }
        first = ordering_key_for_frame(
            {"kind": "job.write", "payload": {**scope, "operation_id": "op-a"}},
            "client-a",
        )
        second = ordering_key_for_frame(
            {"kind": "job.write", "payload": {**scope, "operation_id": "op-b"}},
            "client-b",
        )
        self.assertEqual(first, second)

    def test_job_wait_uses_the_same_job_scope_as_inspect(self) -> None:
        # ``job.wait`` is a read-only job operation (the stdio client maps its
        # terminal to ``job.inspect.result``), so it must share the complete
        # job fence without requiring an operation_id.  Leaving it out of the
        # mux's known job family would fail closed as an unsupported partial
        # lineage and make the client mapping unusable.
        scope = {
            "session_id": "session-a",
            "profile_id": "profile-a",
            "task_id": "task-a",
            "turn_id": "turn-a",
            "turn_stream_id": "stream-a",
            "job_id": "job-a",
        }
        wait_key = ordering_key_for_frame(
            {"kind": "job.wait", "payload": scope},
            "client-a",
        )
        inspect_key = ordering_key_for_frame(
            {"kind": "job.inspect", "payload": scope},
            "client-b",
        )
        self.assertEqual(wait_key, inspect_key)

    def test_conflicting_mirror_fails_closed(self) -> None:
        with self.assertRaises(MuxError):
            ordering_key_for_frame(
                {"job_id": "job-a", "payload": {"job_id": "job-b"}},
                "client-a",
            )

    def test_unkeyed_request_is_serialized_per_owner(self) -> None:
        self.assertEqual(ordering_key_for_frame({"kind": "opaque"}, "client-a"), "client:client-a")


class WeightedFairMuxTest(unittest.TestCase):
    def test_cross_key_parallelism_and_per_key_serialization(self) -> None:
        mux = WeightedFairMux(max_pending=8, max_inflight=3, max_retired=8)
        first = Request("a", "a1", "job:one", 1)
        blocked = Request("b", "b1", "job:one", 2)
        parallel = Request("b", "b2", "job:two", 3)
        for request in (first, blocked, parallel):
            mux.enqueue(request)
        self.assertIs(mux.acquire(0), first)
        self.assertIs(mux.acquire(0), parallel)
        self.assertIsNone(mux.acquire(0.01))
        self.assertTrue(mux.complete(first, reason="terminal"))
        self.assertIs(mux.acquire(0), blocked)

    def test_weighted_round_robin_is_bounded_and_fair(self) -> None:
        mux = WeightedFairMux(
            max_pending=12,
            max_inflight=1,
            max_retired=16,
            owner_weights={"heavy": 2, "light": 1},
        )
        seq = 1
        for index in range(4):
            mux.enqueue(Request("heavy", f"h{index}", f"h:{index}", seq)); seq += 1
        for index in range(2):
            mux.enqueue(Request("light", f"l{index}", f"l:{index}", seq)); seq += 1
        owners = []
        for _ in range(6):
            request = mux.acquire(0)
            self.assertIsNotNone(request)
            owners.append(request.owner_id)
            mux.complete(request, reason="terminal")
        self.assertEqual(owners[:3], ["heavy", "heavy", "light"])
        self.assertEqual(owners[3:], ["heavy", "heavy", "light"])

    def test_retired_sequence_never_cross_delivers(self) -> None:
        mux = WeightedFairMux(max_pending=4, max_inflight=2, max_retired=4)
        old = Request("a", "same", "job:one", 7)
        new = Request("b", "same", "job:two", 8)
        mux.enqueue(old); mux.enqueue(new)
        self.assertIs(mux.acquire(0), old)
        self.assertIs(mux.acquire(0), new)
        self.assertTrue(mux.complete(old, reason="unknown_after_timeout"))
        self.assertIsNone(
            mux.match({"broker_request_upstream_seq": 7}, lambda _request, _frame: True)
        )
        self.assertIs(
            mux.match(
                {"broker_request_upstream_seq": 8}, lambda _request, _frame: True
            ),
            new,
        )

    def test_ambiguous_unsequenced_terminal_fails_closed(self) -> None:
        mux = WeightedFairMux(max_pending=4, max_inflight=2, max_retired=4)
        first = Request("a", "a", "job:one", 1)
        second = Request("b", "b", "job:two", 2)
        mux.enqueue(first); mux.enqueue(second)
        mux.acquire(0); mux.acquire(0)
        self.assertIsNone(mux.match({}, lambda _request, _frame: True))

    def test_sole_active_unsequenced_terminal_never_binds(self) -> None:
        mux = WeightedFairMux(max_pending=4, max_inflight=1, max_retired=4)
        request = Request("a", "a", "job:one", 1)
        mux.enqueue(request)
        self.assertIs(mux.acquire(0), request)
        # A delayed terminal can be semantically unique yet still has no
        # authenticated owner identity when the Host omitted its sequence.
        self.assertIsNone(mux.match({"kind": "job.result"}, lambda *_: True))
        self.assertTrue(mux.is_active(request))

    def test_unsequenced_duplicate_stays_unowned_after_tombstone_eviction(self) -> None:
        mux = WeightedFairMux(max_pending=8, max_inflight=1, max_retired=1)
        old = Request("a", "old", "job:same", 1)
        filler = Request("a", "filler", "job:filler", 2)
        current = Request("b", "current", "job:same", 3)
        mux.enqueue(old)
        self.assertIs(mux.acquire(0), old)
        self.assertTrue(mux.complete(old, reason="terminal"))
        mux.enqueue(filler)
        self.assertIs(mux.acquire(0), filler)
        self.assertTrue(mux.complete(filler, reason="terminal"))
        # Sequence 1's bounded tombstone has now been evicted.  Eviction must
        # not turn a missing sequence into permission for semantic guessing.
        mux.enqueue(current)
        self.assertIs(mux.acquire(0), current)
        self.assertIsNone(
            mux.match(
                {"kind": "job.result", "job_id": "same"},
                lambda _request, _frame: True,
            )
        )
        self.assertTrue(mux.is_active(current))

    def test_expiry_does_not_redispatch_or_reuse_sequence(self) -> None:
        now = time.monotonic()
        mux = WeightedFairMux(max_pending=4, max_inflight=1, max_retired=4)
        first = Request("a", "a", "job:one", 1, now - 1)
        second = Request("a", "b", "job:two", 2, now + 60)
        mux.enqueue(first); mux.enqueue(second)
        self.assertIs(mux.acquire(0), first)
        self.assertEqual(mux.expired_active(now), [first])
        self.assertTrue(mux.complete(first, reason="unknown_after_timeout"))
        self.assertIs(mux.acquire(0), second)
        self.assertEqual(second.upstream_seq, 2)

    def test_unknown_supplied_sequence_never_falls_back_to_semantic_match(self) -> None:
        mux = WeightedFairMux(max_pending=4, max_inflight=1, max_retired=1)
        current = Request("a", "current", "job:current", 11)
        mux.enqueue(current)
        self.assertIs(mux.acquire(0), current)
        self.assertIsNone(
            mux.match(
                {"seq": 999, "broker_request_upstream_seq": 999},
                lambda _request, _frame: True,
            )
        )

    def test_host_only_sequence_is_unsequenced_and_never_binds(self) -> None:
        mux = WeightedFairMux(max_pending=4, max_inflight=1, max_retired=4)
        current = Request("a", "current", "job:current", 11)
        mux.enqueue(current)
        self.assertIs(mux.acquire(0), current)
        self.assertEqual(mux.sequence_state({"seq": 11}), "unsequenced")
        self.assertIsNone(mux.match({"seq": 11}, lambda _request, _frame: True))

    def test_echoed_broker_binding_must_match_sequence_owner(self) -> None:
        mux = WeightedFairMux(max_pending=4, max_inflight=1, max_retired=4)
        current = Request("a", "current", "job:current", 11)
        # The lightweight test request has no digest attribute; an id mismatch
        # is still checked before the matcher is invoked.
        mux.enqueue(current)
        self.assertIs(mux.acquire(0), current)
        with self.assertRaisesRegex(MuxError, "broker_request_id"):
            mux.match(
                {
                    "seq": 11,
                    "broker_request_upstream_seq": 11,
                    "broker_request_id": "other",
                },
                lambda _request, _frame: True,
            )

    def test_broker_sequence_overrides_host_local_response_sequence(self) -> None:
        mux = WeightedFairMux(max_pending=4, max_inflight=1, max_retired=4)
        current = Request("a", "current", "job:current", 11)
        mux.enqueue(current)
        self.assertIs(mux.acquire(0), current)
        # Host response seq=0 is intentionally unrelated to the broker's
        # request sequence. Ownership follows the echoed broker field.
        self.assertIs(
            mux.match(
                {"seq": 0, "broker_request_upstream_seq": 11},
                lambda _request, _frame: True,
            ),
            current,
        )

    def test_malformed_broker_sequence_fails_closed(self) -> None:
        mux = WeightedFairMux(max_pending=4, max_inflight=1, max_retired=4)
        current = Request("a", "current", "job:current", 11)
        mux.enqueue(current)
        mux.acquire(0)
        with self.assertRaisesRegex(MuxError, "broker_request_upstream_seq"):
            mux.match(
                {"seq": 0, "broker_request_upstream_seq": "11"},
                lambda _request, _frame: True,
            )

    def test_uncertain_active_request_fences_key_and_retires_waiters(self) -> None:
        mux = WeightedFairMux(max_pending=6, max_inflight=2, max_retired=6)
        first = Request("a", "first", "job:one", 1)
        blocked = Request("b", "blocked", "job:one", 2)
        parallel = Request("b", "parallel", "job:two", 3)
        for request in (first, blocked, parallel):
            mux.enqueue(request)
        self.assertIs(mux.acquire(0), first)
        self.assertIs(mux.acquire(0), parallel)
        blocked_requests = mux.fence_active(first, reason="unknown_after_timeout")
        self.assertEqual(blocked_requests, [blocked])
        self.assertEqual(mux.fenced_reason("job:one"), "unknown_after_timeout")
        with self.assertRaisesRegex(MuxError, "ordering key is fenced"):
            mux.enqueue(Request("c", "later", "job:one", 4))
        self.assertTrue(mux.complete(parallel, reason="terminal"))
        self.assertIsNone(mux.acquire(0))

    def test_waiter_wakes_when_ordering_key_released(self) -> None:
        mux = WeightedFairMux(max_pending=4, max_inflight=2, max_retired=4)
        first = Request("a", "a", "job:one", 1)
        second = Request("b", "b", "job:one", 2)
        mux.enqueue(first); mux.enqueue(second)
        self.assertIs(mux.acquire(0), first)
        observed: list[Request | None] = []
        waiter = threading.Thread(target=lambda: observed.append(mux.acquire(1)))
        waiter.start()
        time.sleep(0.02)
        self.assertEqual(observed, [])
        mux.complete(first, reason="terminal")
        waiter.join(1)
        self.assertEqual(observed, [second])

    def test_pending_terminal_hold_blocks_only_its_exact_ordering_key(self) -> None:
        mux = WeightedFairMux(max_pending=4, max_inflight=2, max_retired=4)
        terminalizing = Request("a", "old", "job:one", 1)
        blocked = Request("b", "waiting", "job:one", 2)
        parallel = Request("b", "parallel", "job:two", 3)
        for request in (terminalizing, blocked, parallel):
            mux.enqueue(request)

        self.assertTrue(
            mux.hold_pending(terminalizing, reason="timeout_before_forward")
        )
        self.assertEqual(mux.held_count, 1)
        self.assertEqual(mux.pending_count, 2)
        self.assertIs(mux.acquire(0), parallel)
        self.assertIsNone(mux.acquire(0.01))

        self.assertTrue(mux.release_ordering_hold("job:one"))
        self.assertEqual(mux.held_count, 0)
        self.assertIs(mux.acquire(0), blocked)

    def test_counted_pending_holds_cannot_release_each_other(self) -> None:
        mux = WeightedFairMux(max_pending=4, max_inflight=1, max_retired=4)
        first = Request("a", "old-a", "job:one", 1)
        second = Request("b", "old-b", "job:one", 2)
        waiter = Request("c", "waiting", "job:one", 3)
        for request in (first, second, waiter):
            mux.enqueue(request)

        self.assertTrue(mux.hold_pending(first, reason="timeout"))
        self.assertTrue(mux.hold_pending(second, reason="timeout"))
        self.assertEqual(mux.held_count, 2)
        self.assertTrue(mux.release_ordering_hold("job:one"))
        self.assertEqual(mux.held_count, 1)
        self.assertIsNone(mux.acquire(0.01))
        self.assertTrue(mux.release_ordering_hold("job:one"))
        self.assertIs(mux.acquire(0), waiter)


if __name__ == "__main__":
    unittest.main()
