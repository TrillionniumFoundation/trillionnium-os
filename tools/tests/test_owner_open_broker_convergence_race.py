from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import socket
import sys
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "owner-open"))

from owner_open_broker_convergence_v2 import BrokerConvergenceMixin
from owner_open_broker_base_v2 import BrokerBase
from owner_open_broker_common import BrokerError
from owner_open_broker_mux import WeightedFairMux


class _ObservationBroker(BrokerConvergenceMixin):
    def __init__(self, request: SimpleNamespace) -> None:
        self.mux = WeightedFairMux(max_pending=4, max_inflight=1, max_retired=4)
        self.transition_lock = threading.RLock()
        self.unknown_lock = threading.Lock()
        self.upstream_uncertain = threading.Event()
        self.stopping = threading.Event()
        self.broadcast_entered = threading.Event()
        self.release_broadcast = threading.Event()
        self.events: list[str] = []
        self.request = request

    def _broadcast(self, _observation: dict) -> None:
        self.events.append("broadcast-entered")
        self.broadcast_entered.set()
        if not self.release_broadcast.wait(2.0):
            raise AssertionError("publication barrier was not released")
        self.events.append("broadcast-finished")


class _UnknownBoundaryBroker(BrokerConvergenceMixin):
    """Small shell for testing the uncertainty/byte-stream cut ordering."""

    def __init__(self) -> None:
        self.upstream_uncertain = threading.Event()
        self.stopping = threading.Event()
        self.unknown_lock = threading.Lock()
        self.upstream_write_lock = threading.Lock()
        self.transition_lock = threading.RLock()
        self.snapshot_started = threading.Event()
        self.snapshot_released = threading.Event()
        self.mux = SimpleNamespace(close_and_snapshot=self._snapshot)
        self.broker_epoch = "epoch"
        self.request_slots = SimpleNamespace(release=lambda: None)
        self.deliveries: list[tuple[str, dict]] = []
        self.statuses: list[dict] = []

    def _snapshot(self) -> list:
        self.snapshot_started.set()
        self.snapshot_released.set()
        return []

    def _terminalize_drained(self, requests, error, code):
        del requests, error, code
        return [], [], None

    def _owner(self, owner_id, message):
        self.deliveries.append((owner_id, message))

    def _broadcast(self, value):
        self.statuses.append(value)


def _lifecycle_request(
    *,
    request_id: str,
    upstream_seq: int,
    ordering_key: str = "effect:test",
) -> SimpleNamespace:
    """Build the smallest request shape consumed by convergence paths."""

    return SimpleNamespace(
        owner_id="owner",
        request_id=request_id,
        frame={"kind": "job.inspect"},
        expected_kinds=frozenset({"job.inspect.result"}),
        expected_job_id=None,
        timeout_ms=5_000,
        deadline_monotonic=time.monotonic() + 5.0,
        client_seq=upstream_seq - 1,
        upstream_seq=upstream_seq,
        request_sha256="a" * 64,
        correlation={},
        audit_binding=SimpleNamespace(stage="broker.forwarded"),
        ordering_key=ordering_key,
        transition_lock=threading.RLock(),
        effect_attempted=True,
    )


def _pending_lifecycle_request(
    *,
    request_id: str,
    upstream_seq: int,
    ordering_key: str = "effect:test",
) -> SimpleNamespace:
    request = _lifecycle_request(
        request_id=request_id,
        upstream_seq=upstream_seq,
        ordering_key=ordering_key,
    )
    request.audit_binding.stage = "broker.accepted"
    request.effect_attempted = False
    return request


class _FailingTerminalAudit:
    def terminal(self, _binding, *, owner_message, details=None):
        del owner_message, details
        raise BrokerError("injected terminal audit failure")


class _DelayedAuditFailureBroker(BrokerConvergenceMixin):
    """Broker shell that pauses exactly at global uncertainty publication."""

    _error = staticmethod(BrokerBase._error)
    _correlation_payload = BrokerBase._correlation_payload
    _request_error = BrokerBase._request_error

    def __init__(self) -> None:
        self.mux = WeightedFairMux(max_pending=4, max_inflight=2, max_retired=8)
        self.transition_lock = threading.RLock()
        self.unknown_lock = threading.Lock()
        self.upstream_write_lock = threading.Lock()
        self.upstream_uncertain = threading.Event()
        self.stopping = threading.Event()
        self.broker_epoch = "epoch"
        self.audit = _FailingTerminalAudit()
        self.request_slots = SimpleNamespace(release=lambda: None)
        self.mark_entered = threading.Event()
        self.release_mark = threading.Event()
        self.events: list[str] = []

    def _owner(self, _owner_id, _message) -> None:
        self.events.append("owner")

    def _broadcast(self, _value) -> None:
        self.events.append("status")

    def _mark_upstream_unknown(self, error, *, code="unknown_after_disconnect") -> None:
        self.events.append("mark-entered")
        self.mark_entered.set()
        if not self.release_mark.wait(2.0):
            raise AssertionError("uncertainty publication barrier was not released")
        super()._mark_upstream_unknown(error, code=code)


class _SuccessfulTerminalAudit:
    def terminal(self, binding, *, owner_message, details=None):
        del details
        binding.stage = "broker.terminal"
        binding.terminal_message = owner_message


class _DeliveryOrderingBroker(BrokerConvergenceMixin):
    """Broker shell whose terminal observation publication is controllable."""

    _error = staticmethod(BrokerBase._error)
    _correlation_payload = BrokerBase._correlation_payload
    _request_error = BrokerBase._request_error

    def __init__(self) -> None:
        self.mux = WeightedFairMux(max_pending=4, max_inflight=2, max_retired=8)
        self.transition_lock = threading.RLock()
        self.unknown_lock = threading.Lock()
        self.upstream_uncertain = threading.Event()
        self.stopping = threading.Event()
        self.broker_epoch = "epoch"
        self.audit = _SuccessfulTerminalAudit()
        self.request_slots = SimpleNamespace(release=lambda: None)
        self.broadcast_entered = threading.Event()
        self.release_broadcast = threading.Event()
        self.events: list[str] = []

    def _broadcast(self, value) -> None:
        if value.get("kind") == "observation":
            self.events.append("broadcast-entered")
            self.broadcast_entered.set()
            if not self.release_broadcast.wait(2.0):
                raise AssertionError("terminal observation barrier was not released")
            self.events.append("broadcast-finished")
        else:
            self.events.append("status")

    def _owner(self, _owner_id, _message) -> None:
        self.events.append("owner")


class _PendingDeliveryOrderingBroker(_DeliveryOrderingBroker):
    """Broker shell that stalls a pending terminal at owner publication."""

    def __init__(self) -> None:
        super().__init__()
        self.owner_entered = threading.Event()
        self.release_owner = threading.Event()

    def _owner(self, _owner_id, _message) -> None:
        self.events.append("owner-entered")
        self.owner_entered.set()
        if not self.release_owner.wait(2.0):
            raise AssertionError("pending owner-delivery barrier was not released")
        self.events.append("owner-finished")


class _ForwardedRuntimeErrorAudit:
    """Storage double that raises an ordinary exception after the write."""

    def forwarded(self, _binding, *, frame_sha256, frame_bytes):
        del frame_sha256, frame_bytes
        raise RuntimeError("injected forwarded-audit failure")


class _ForwardedRuntimeErrorBroker(BrokerConvergenceMixin):
    """Minimal dispatch shell for the generic forwarded-audit failure path."""

    def __init__(self) -> None:
        self.mux = WeightedFairMux(max_pending=2, max_inflight=1, max_retired=2)
        self.transition_lock = threading.RLock()
        self.unknown_lock = threading.Lock()
        self.upstream_write_lock = threading.Lock()
        self.upstream_uncertain = threading.Event()
        self.stopping = threading.Event()
        self.admission_fence = threading.Event()
        self.admission_fence_lock = threading.Lock()
        self.audit = _ForwardedRuntimeErrorAudit()
        self._upstream_reader, upstream_writer = socket.socketpair()
        self.upstream = SimpleNamespace(stdin=upstream_writer)
        self.marked: tuple[Exception, str] | None = None

    def _mark_upstream_unknown(self, error: Exception, *, code="unknown") -> None:
        self.marked = (error, code)
        self.upstream_uncertain.set()
        self.stopping.set()


class ConvergenceRaceTest(unittest.TestCase):
    def test_unexpected_forwarded_audit_exception_converges_instead_of_killing_worker(self) -> None:
        broker = _ForwardedRuntimeErrorBroker()
        request = _lifecycle_request(request_id="request", upstream_seq=1)
        broker.mux.enqueue(request)
        self.assertIs(broker.mux.acquire(0), request)

        # The write itself succeeds, but the durable forwarded transition
        # raises a generic RuntimeError.  The dispatcher must classify that
        # boundary as uncertain and return normally; an escaping exception
        # would leave the active mux entry orphaned in production.
        broker._forward_request(request)

        self.assertIsNotNone(broker.marked)
        assert broker.marked is not None
        error, code = broker.marked
        self.assertIsInstance(error, RuntimeError)
        self.assertEqual(str(error), "injected forwarded-audit failure")
        self.assertEqual(code, "unknown")
        self.assertTrue(broker.upstream_uncertain.is_set())
        self.assertTrue(broker.stopping.is_set())
        broker.upstream.stdin.close()
        broker._upstream_reader.close()

    def test_observation_publication_serializes_before_timeout_retirement(self) -> None:
        request = SimpleNamespace(
            owner_id="client",
            request_id="request",
            ordering_key="effect:test",
            upstream_seq=1,
            transition_lock=threading.RLock(),
        )
        broker = _ObservationBroker(request)
        broker.mux.enqueue(request)
        self.assertIs(broker.mux.acquire(0), request)

        publish_done = threading.Event()
        retire_done = threading.Event()

        def publish() -> None:
            broker._publish_active_observation(request, {"kind": "observation"})
            publish_done.set()

        def retire() -> None:
            # This is the lock order used by timeout/fence transitions.
            with request.transition_lock:
                with broker.transition_lock:
                    broker.events.append("retire-entered")
                    self.assertTrue(broker.mux.complete(request, reason="timeout"))
            retire_done.set()

        publisher = threading.Thread(target=publish)
        publisher.start()
        self.assertTrue(broker.broadcast_entered.wait(1.0))

        retier = threading.Thread(target=retire)
        retier.start()
        # The deterministic barrier proves the timeout cannot retire the
        # sequence while publication is in progress.
        self.assertFalse(retire_done.wait(0.05))
        broker.release_broadcast.set()
        publisher.join(2.0)
        retier.join(2.0)

        self.assertTrue(publish_done.is_set())
        self.assertTrue(retire_done.is_set())
        self.assertEqual(
            broker.events,
            ["broadcast-entered", "broadcast-finished", "retire-entered"],
        )
        self.assertFalse(broker.mux.is_active(request))

    def test_uncertainty_waits_for_shared_writer_before_snapshot(self) -> None:
        broker = _UnknownBoundaryBroker()
        # Model a worker that passed its final metadata check and still owns
        # the byte-stream gate.  The uncertainty marker may be published, but
        # it must not snapshot/retire accepted work until that writer exits.
        broker.upstream_write_lock.acquire()
        marked_done = threading.Event()

        def mark() -> None:
            broker._mark_upstream_unknown(RuntimeError("writer cut"), code="test_cut")
            marked_done.set()

        marker = threading.Thread(target=mark)
        marker.start()
        self.assertTrue(broker.upstream_uncertain.wait(1.0))
        self.assertTrue(broker.stopping.is_set())
        self.assertFalse(
            broker.snapshot_started.wait(0.05),
            "uncertainty snapshot overtook a writer already at the byte gate",
        )
        broker.upstream_write_lock.release()
        marker.join(2.0)
        self.assertTrue(marked_done.is_set())
        self.assertTrue(broker.snapshot_started.is_set())
        self.assertTrue(broker.snapshot_released.is_set())

    def test_terminal_audit_failure_keeps_ordering_key_active_until_fence(self) -> None:
        broker = _DelayedAuditFailureBroker()
        first = _lifecycle_request(request_id="first", upstream_seq=1)
        second = _lifecycle_request(request_id="second", upstream_seq=2)
        broker.mux.enqueue(first)
        broker.mux.enqueue(second)
        self.assertIs(broker.mux.acquire(0), first)

        second_acquired = threading.Event()

        def acquire_waiter() -> None:
            if broker.mux.acquire(1.0) is second:
                second_acquired.set()

        waiter = threading.Thread(target=acquire_waiter)
        waiter.start()
        finish_done = threading.Event()

        def finish() -> None:
            broker._finish_active(
                first,
                {"kind": "result"},
                details={"status": "host_terminal_observed"},
                retire_reason="terminal",
            )
            finish_done.set()

        finisher = threading.Thread(target=finish)
        finisher.start()
        self.assertTrue(broker.mark_entered.wait(1.0))
        # The failing terminal append must not free the key before the global
        # uncertainty boundary.  Under the old ordering, `mux.complete`
        # happened first and the waiter acquired `second` here.
        self.assertTrue(broker.mux.is_active(first))
        self.assertFalse(second_acquired.is_set())
        self.assertFalse(broker.upstream_uncertain.is_set())

        broker.release_mark.set()
        finisher.join(2.0)
        waiter.join(2.0)
        self.assertTrue(finish_done.is_set())
        self.assertTrue(broker.upstream_uncertain.is_set())
        self.assertFalse(second_acquired.is_set())
        self.assertTrue(broker.stopping.is_set())

    def test_pending_audit_failure_keeps_key_held_until_global_fence(self) -> None:
        broker = _DelayedAuditFailureBroker()
        first = _pending_lifecycle_request(request_id="first", upstream_seq=1)
        second = _pending_lifecycle_request(request_id="second", upstream_seq=2)
        broker.mux.enqueue(first)
        broker.mux.enqueue(second)

        finish_done = threading.Event()

        def finish() -> None:
            broker._finish_pending(
                first,
                {"kind": "error", "code": "timeout_before_forward"},
                details={
                    "status": "timeout_before_forward",
                    "effect_may_have_started": False,
                },
                retire_reason="timeout_before_forward",
            )
            finish_done.set()

        finisher = threading.Thread(target=finish)
        finisher.start()
        self.assertTrue(broker.mark_entered.wait(1.0))
        self.assertEqual(broker.mux.held_count, 1)
        self.assertEqual(broker.mux.pending_snapshot(), [second])

        second_acquired = threading.Event()

        def acquire_waiter() -> None:
            if broker.mux.acquire(1.0) is second:
                second_acquired.set()

        waiter = threading.Thread(target=acquire_waiter)
        waiter.start()
        self.assertFalse(second_acquired.wait(0.05))
        self.assertFalse(broker.upstream_uncertain.is_set())

        broker.release_mark.set()
        finisher.join(2.0)
        waiter.join(2.0)
        self.assertTrue(finish_done.is_set())
        self.assertTrue(broker.upstream_uncertain.is_set())
        self.assertTrue(broker.stopping.is_set())
        self.assertFalse(second_acquired.is_set())
        self.assertEqual(broker.mux.held_count, 0)

    def test_pending_terminal_delivery_precedes_same_key_release(self) -> None:
        broker = _PendingDeliveryOrderingBroker()
        first = _pending_lifecycle_request(request_id="first", upstream_seq=1)
        second = _pending_lifecycle_request(request_id="second", upstream_seq=2)
        broker.mux.enqueue(first)
        broker.mux.enqueue(second)

        finisher = threading.Thread(
            target=lambda: broker._finish_pending(
                first,
                {"kind": "error", "code": "timeout_before_forward"},
                details={
                    "status": "timeout_before_forward",
                    "effect_may_have_started": False,
                },
                retire_reason="timeout_before_forward",
            )
        )
        finisher.start()
        self.assertTrue(broker.owner_entered.wait(1.0))
        self.assertEqual(broker.mux.held_count, 1)

        acquired: list[object] = []
        waiter = threading.Thread(target=lambda: acquired.append(broker.mux.acquire(1.0)))
        waiter.start()
        self.assertEqual(acquired, [])
        self.assertEqual(broker.mux.pending_snapshot(), [second])

        broker.release_owner.set()
        finisher.join(2.0)
        waiter.join(2.0)
        self.assertEqual(broker.events, ["owner-entered", "owner-finished"])
        self.assertEqual(acquired, [second])
        self.assertEqual(broker.mux.held_count, 0)

    def test_terminal_observation_is_enqueued_before_same_key_can_activate(self) -> None:
        broker = _DeliveryOrderingBroker()
        first = _lifecycle_request(request_id="first", upstream_seq=1)
        second = _lifecycle_request(request_id="second", upstream_seq=2)
        broker.mux.enqueue(first)
        broker.mux.enqueue(second)
        self.assertIs(broker.mux.acquire(0), first)

        acquired: list[object] = []

        def acquire_waiter() -> None:
            request = broker.mux.acquire(1.0)
            if request is not None:
                acquired.append(request)

        waiter = threading.Thread(target=acquire_waiter)
        waiter.start()
        finisher = threading.Thread(
            target=lambda: broker._finish_active(
                first,
                {"kind": "result"},
                details={"status": "host_terminal_observed"},
                retire_reason="terminal",
                observation={"kind": "observation"},
            )
        )
        finisher.start()
        self.assertTrue(broker.broadcast_entered.wait(1.0))
        # Publication is intentionally stalled while the first request is
        # still active.  A same-key waiter must not be forwarded in front of
        # this terminal observation.
        self.assertEqual(acquired, [])
        self.assertTrue(broker.mux.is_active(first))

        broker.release_broadcast.set()
        finisher.join(2.0)
        waiter.join(2.0)
        self.assertEqual(acquired, [second])
        self.assertEqual(
            broker.events[:3],
            ["broadcast-entered", "broadcast-finished", "owner"],
        )


if __name__ == "__main__":
    unittest.main()
