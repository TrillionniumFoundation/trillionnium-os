from __future__ import annotations

from pathlib import Path
import threading
from types import SimpleNamespace
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "owner-open"))

from owner_open_broker_admission_v2 import BrokerAdmissionMixin
from owner_open_broker_base_v2 import BrokerBase
from owner_open_broker_common import BrokerError
from owner_open_broker_mux import MuxError, WeightedFairMux


class _Client:
    """Minimal authenticated client double for admission-only tests."""

    def __init__(self, client_id: str) -> None:
        self.client_id = client_id
        self.last_client_seq: int | None = None
        # The production Client owns this lock.  Keep the same per-client
        # namespace boundary in the test double so two clients can exercise
        # the admission path concurrently.
        self.admission_lock = threading.Lock()
        self.messages: list[dict] = []
        self.messages_lock = threading.Lock()

    def accept_sequence(self, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("invalid client sequence")
        if self.last_client_seq is not None and value != self.last_client_seq + 1:
            raise ValueError("client sequence is not contiguous")
        self.last_client_seq = value
        return value

    def enqueue(self, value: dict) -> bool:
        with self.messages_lock:
            self.messages.append(value)
        return True


def _binding(
    *,
    broker_epoch: str,
    client_id: str,
    request_id: str,
    request_sha256: str,
    client_seq: int,
    upstream_seq: int,
) -> SimpleNamespace:
    return SimpleNamespace(
        broker_epoch=broker_epoch,
        client_id=client_id,
        request_id=request_id,
        request_sha256=request_sha256,
        client_seq=client_seq,
        upstream_seq=upstream_seq,
        request_kind="job.inspect",
        correlation={"job_id": request_id},
        stage="broker.accepted",
        terminal_message=None,
    )


class _BlockingAudit:
    """Audit double whose first durable append is intentionally stalled."""

    def __init__(self) -> None:
        self.slow_entered = threading.Event()
        self.release_slow = threading.Event()
        self.bindings: dict[tuple[str, str], SimpleNamespace] = {}
        self.calls: list[str] = []
        self.lock = threading.Lock()

    def lookup(self, client_id: str, request_id: str):
        with self.lock:
            return self.bindings.get((client_id, request_id))

    def admit(self, **kwargs):
        request_id = kwargs["request_id"]
        with self.lock:
            self.calls.append(request_id)
        if request_id == "slow":
            self.slow_entered.set()
            if not self.release_slow.wait(2.0):
                raise AssertionError("slow audit was not released")
        binding = _binding(
            broker_epoch=kwargs["broker_epoch"],
            client_id=kwargs["client_id"],
            request_id=request_id,
            request_sha256=kwargs["request_sha256"],
            client_seq=kwargs["client_seq"],
            upstream_seq=kwargs["upstream_seq"],
        )
        with self.lock:
            key = kwargs["client_id"], request_id
            existing = self.bindings.get(key)
            if existing is not None:
                return SimpleNamespace(disposition="unresolved", binding=existing)
            self.bindings[key] = binding
        return SimpleNamespace(disposition="new", binding=binding)

    def terminal(self, binding, *, owner_message, details=None):
        binding.stage = "broker.terminal"
        binding.terminal_message = owner_message


class _MuxRejecting:
    def fenced_reason(self, _ordering_key: str):
        return None

    def enqueue(self, _request) -> None:
        raise MuxError("injected scheduler rejection")


class _FenceDuringEnqueueMux:
    """Publish an exact-key fence in the enqueue check-to-call window."""

    def __init__(self) -> None:
        self.fenced_key: str | None = None

    def fenced_reason(self, ordering_key: str):
        if ordering_key == self.fenced_key:
            return "unknown_after_timeout"
        return None

    def enqueue(self, request) -> None:
        # The admission preflight has already observed no fence.  Model the
        # timeout worker winning immediately before the scheduler's own
        # insertion, which is the production race that must preserve the
        # ordering-key-specific terminal code.
        self.fenced_key = request.ordering_key
        raise MuxError("ordering key is fenced after unresolved effect")


class _TerminalFailingAudit:
    """Existing binding whose restart terminal cannot be made durable."""

    def __init__(self, binding: SimpleNamespace) -> None:
        self.binding = binding

    def terminal(self, _binding, *, owner_message, details=None):
        del owner_message, details
        raise BrokerError("injected audit capacity failure")


class _BlockingRestartAudit:
    """Audit double that stalls an old-epoch terminal append."""

    def __init__(self, old_binding: SimpleNamespace, *, fail: bool = False) -> None:
        self.old_binding = old_binding
        self.fail = fail
        self.terminal_entered = threading.Event()
        self.release_terminal = threading.Event()
        self.admit_calls: list[str] = []
        self.bindings: dict[tuple[str, str], SimpleNamespace] = {
            (old_binding.client_id, old_binding.request_id): old_binding
        }
        self.lock = threading.Lock()

    def lookup(self, client_id: str, request_id: str):
        with self.lock:
            return self.bindings.get((client_id, request_id))

    def admit(self, **kwargs):
        request_id = kwargs["request_id"]
        with self.lock:
            self.admit_calls.append(request_id)
            binding = _binding(
                broker_epoch=kwargs["broker_epoch"],
                client_id=kwargs["client_id"],
                request_id=request_id,
                request_sha256=kwargs["request_sha256"],
                client_seq=kwargs["client_seq"],
                upstream_seq=kwargs["upstream_seq"],
            )
            self.bindings[(kwargs["client_id"], request_id)] = binding
        return SimpleNamespace(disposition="new", binding=binding)

    def terminal(self, binding, *, owner_message, details=None):
        if binding is self.old_binding:
            self.terminal_entered.set()
            if not self.release_terminal.wait(2.0):
                raise AssertionError("restart terminal append was not released")
            if self.fail:
                raise BrokerError("restart terminal append became uncertain")
        binding.stage = "broker.terminal"
        binding.terminal_message = owner_message


class _DispositionRestartAudit:
    """Return an older unresolved binding from the atomic admit race path."""

    def __init__(self, old_binding: SimpleNamespace) -> None:
        self.old_binding = old_binding
        self.admit_calls: list[str] = []
        self.lock = threading.Lock()
        self.admit_returned = threading.Event()

    def lookup(self, _client_id: str, _request_id: str):
        # Force the caller through ``audit.admit``'s disposition path.  This
        # models a reconnect on another Client object winning the journal
        # identity gate between lookup and append.
        return None

    def admit(self, **kwargs):
        with self.lock:
            self.admit_calls.append(kwargs["request_id"])
            # The request digest is only known once the racing caller has
            # canonicalized its frame; bind it to the old record so the helper
            # takes the restart-convergence branch rather than conflict.
            self.old_binding.request_sha256 = kwargs["request_sha256"]
        self.admit_returned.set()
        return SimpleNamespace(disposition="unresolved", binding=self.old_binding)

    def terminal(self, binding, *, owner_message, details=None):
        del details
        binding.stage = "broker.terminal"
        binding.terminal_message = owner_message


class _AdmissionFailingAudit(_BlockingAudit):
    """Admission append that fails at the durable boundary."""

    def admit(self, **kwargs):
        del kwargs
        raise BrokerError("append became uncertain")


class _FirstAdmissionFailingAudit(_BlockingAudit):
    """Fail the first admission while allowing a later one to proceed."""

    def __init__(self) -> None:
        super().__init__()
        self.failed = False

    def admit(self, **kwargs):
        with self.lock:
            if not self.failed:
                self.failed = True
                raise BrokerError("first append became uncertain")
        return super().admit(**kwargs)


class _AdmissionBroker(BrokerAdmissionMixin):
    """Small broker shell exposing only the admission dependencies."""

    _error = staticmethod(BrokerBase._error)
    _correlation_payload = BrokerBase._correlation_payload
    _request_error = BrokerBase._request_error

    def __init__(self, audit, *, mux=None, slots: int = 4) -> None:
        self.audit = audit
        self.broker_epoch = "epoch-current"
        self.sequence_lock = threading.Lock()
        self.upstream_write_lock = threading.Lock()
        self.next_upstream_seq = 1
        self.request_slots = threading.BoundedSemaphore(slots)
        self.mux = mux or WeightedFairMux(
            max_pending=slots,
            max_inflight=slots,
            max_retired=slots,
        )
        self.upstream_uncertain = threading.Event()
        self.stopping = threading.Event()
        self.unknown_errors: list[tuple[Exception, str]] = []

    def _mark_upstream_unknown(self, error: Exception, *, code: str = "unknown") -> None:
        self.unknown_errors.append((error, code))


class _FenceBlockingDispositionBroker(_AdmissionBroker):
    """Pause just before publishing the old-epoch transient fence."""

    def __init__(self, audit, *, slots: int = 1) -> None:
        super().__init__(audit, slots=slots)
        self.begin_entered = threading.Event()
        self.release_begin = threading.Event()

    def _begin_temporary_admission_fence(self) -> None:
        self.begin_entered.set()
        if not self.release_begin.wait(2.0):
            raise AssertionError("disposition fence barrier was not released")
        super()._begin_temporary_admission_fence()


class _FailClosedAdmissionBroker(_AdmissionBroker):
    """Model the production uncertainty publication without starting workers."""

    def _mark_upstream_unknown(self, error: Exception, *, code: str = "unknown") -> None:
        self.upstream_uncertain.set()
        self.stopping.set()
        super()._mark_upstream_unknown(error, code=code)


class _DelayedMarkAdmissionBroker(_AdmissionBroker):
    """Hold uncertainty publication to expose slot-release ordering."""

    def __init__(self, audit, *, slots: int = 1) -> None:
        super().__init__(audit, slots=slots)
        self.mark_entered = threading.Event()
        self.release_mark = threading.Event()

    def _mark_upstream_unknown(self, error: Exception, *, code: str = "unknown") -> None:
        self.mark_entered.set()
        if not self.release_mark.wait(2.0):
            raise AssertionError("admission uncertainty barrier was not released")
        self.upstream_uncertain.set()
        self.stopping.set()
        super()._mark_upstream_unknown(error, code=code)


def _frame(job_id: str, seq: int) -> dict:
    return {
        "kind": "job.inspect",
        "seq": seq,
        "direction": "client_to_host",
        "payload": {
            "session_id": "session-admission-test",
            "profile_id": "profile-admission-test",
            "task_id": "task-admission-test",
            "turn_id": "turn-admission-test",
            "turn_stream_id": "stream-admission-test",
            "job_id": job_id,
        },
    }


class BrokerAdmissionConcurrencyTest(unittest.TestCase):
    def test_admission_slow_path_has_no_broker_wide_audit_lock(self) -> None:
        admission = (ROOT / "owner-open" / "owner_open_broker_admission_v2.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("self.admission_lock", admission)
        gate_start = admission.index("        with client.admission_lock:")
        gate_end = admission.index(
            "        # Everything below this point is intentionally outside",
            gate_start,
        )
        gate_body = admission[gate_start:gate_end]
        self.assertNotIn("audit.admit", gate_body)
        self.assertNotIn("audit.terminal", gate_body)

    def test_blocked_audit_for_one_client_does_not_block_another_admission(self) -> None:
        audit = _BlockingAudit()
        broker = _AdmissionBroker(audit, slots=4)
        slow = _Client("client-slow")
        fast = _Client("client-fast")
        failures: list[BaseException] = []
        slow_done = threading.Event()
        fast_done = threading.Event()

        def admit(
            client: _Client,
            request_id: str,
            frame: dict,
            done: threading.Event,
        ) -> None:
            try:
                broker._admit_request(
                    client,
                    request_id,
                    frame,
                    frozenset({"job.inspect.result"}),
                    frame["payload"]["job_id"],
                    5_000,
                )
            except BaseException as error:  # report thread failures in the test
                failures.append(error)
            finally:
                done.set()

        first = threading.Thread(
            target=admit,
            args=(slow, "slow", _frame("job-slow", 0), slow_done),
        )
        first.start()
        self.assertTrue(audit.slow_entered.wait(1.0))

        second = threading.Thread(
            target=admit,
            args=(fast, "fast", _frame("job-fast", 0), fast_done),
        )
        second.start()
        try:
            # With the former broker-wide admission lock, this wait could not
            # complete until the slow audit/fsync returned.  The per-client
            # metadata gate must let the independent admission finish first.
            self.assertTrue(
                fast_done.wait(0.5),
                "a blocked audit for one client stalled another admission",
            )
        finally:
            audit.release_slow.set()
            first.join(2.0)
            second.join(2.0)

        self.assertFalse(failures)
        self.assertTrue(slow_done.is_set())
        self.assertEqual(audit.calls, ["slow", "fast"])
        self.assertCountEqual(
            [request.request_id for request in broker.mux.pending_snapshot()],
            ["slow", "fast"],
        )

    def test_mux_rejection_terminalizes_and_releases_reserved_slot(self) -> None:
        audit = _BlockingAudit()
        broker = _AdmissionBroker(audit, mux=_MuxRejecting(), slots=1)
        client = _Client("client")

        broker._admit_request(
            client,
            "request",
            _frame("job", 0),
            frozenset({"job.inspect.result"}),
            "job",
            5_000,
        )

        self.assertEqual(len(client.messages), 1)
        self.assertEqual(client.messages[0]["code"], "broker_acceptance_failed")
        self.assertEqual(client.messages[0]["request_id"], "request")
        self.assertEqual(len(audit.bindings), 1)
        binding = audit.bindings[("client", "request")]
        self.assertEqual(binding.stage, "broker.terminal")
        self.assertEqual(binding.terminal_message["code"], "broker_acceptance_failed")
        # A failed mux admission must not consume capacity permanently.
        self.assertTrue(broker.request_slots.acquire(blocking=False))
        broker.request_slots.release()

    def test_mux_fence_race_reports_ordering_key_uncertain(self) -> None:
        audit = _BlockingAudit()
        mux = _FenceDuringEnqueueMux()
        broker = _AdmissionBroker(audit, mux=mux, slots=1)
        client = _Client("client")

        broker._admit_request(
            client,
            "request",
            _frame("job", 0),
            frozenset({"job.inspect.result"}),
            "job",
            5_000,
        )

        self.assertEqual(len(client.messages), 1)
        self.assertEqual(client.messages[0]["code"], "ordering_key_uncertain")
        self.assertIn("unknown_after_timeout", client.messages[0]["message"])
        binding = audit.bindings[("client", "request")]
        self.assertEqual(binding.stage, "broker.terminal")
        self.assertEqual(binding.terminal_message["code"], "ordering_key_uncertain")
        self.assertTrue(broker.request_slots.acquire(blocking=False))
        broker.request_slots.release()

    def test_racing_audit_conflict_releases_speculative_slot_and_replies_conflict(self) -> None:
        audit = _BlockingAudit()
        client = _Client("client")
        frame = _frame("job", 0)
        # Seed a binding that the fast lookup intentionally does not observe;
        # ``admit`` will return it as the atomic race winner.
        seeded = _binding(
            broker_epoch="epoch-current",
            client_id="client",
            request_id="request",
            request_sha256="a" * 64,
            client_seq=0,
            upstream_seq=1,
        )

        class RacingAudit(_BlockingAudit):
            def lookup(self, _client_id: str, _request_id: str):
                return None

            def admit(self, **kwargs):
                self.bindings[("client", "request")] = seeded
                return SimpleNamespace(disposition="conflict", binding=seeded)

        broker = _AdmissionBroker(RacingAudit(), slots=1)
        broker._admit_request(
            client,
            "request",
            frame,
            frozenset({"job.inspect.result"}),
            "job",
            5_000,
        )

        self.assertEqual(client.messages[0]["code"], "request_id_conflict")
        self.assertTrue(broker.request_slots.acquire(blocking=False))
        broker.request_slots.release()

    def test_disposition_old_epoch_keeps_slot_until_restart_fence_is_published(self) -> None:
        binding = _binding(
            broker_epoch="epoch-previous",
            client_id="client-first",
            request_id="request",
            request_sha256="a" * 64,
            client_seq=0,
            upstream_seq=1,
        )
        audit = _DispositionRestartAudit(binding)
        broker = _FenceBlockingDispositionBroker(audit, slots=1)
        first = _Client("client-first")
        second = _Client("client-second")
        failures: list[BaseException] = []
        first_done = threading.Event()
        second_done = threading.Event()

        def admit_first() -> None:
            try:
                broker._admit_request(
                    first,
                    "request",
                    _frame("job-first", 0),
                    frozenset({"job.inspect.result"}),
                    "job-first",
                    5_000,
                )
            except BaseException as error:
                failures.append(error)
            finally:
                first_done.set()

        def admit_second() -> None:
            try:
                broker._admit_request(
                    second,
                    "request-second",
                    _frame("job-second", 0),
                    frozenset({"job.inspect.result"}),
                    "job-second",
                    5_000,
                )
            except BaseException as error:
                failures.append(error)
            finally:
                second_done.set()

        first_thread = threading.Thread(target=admit_first)
        first_thread.start()
        self.assertTrue(broker.begin_entered.wait(1.0))

        # The atomic audit disposition is old/unresolved, but the helper is
        # paused before it can set the transient fence.  The speculative slot
        # must still be held, otherwise this second client can cross the gap
        # and reach a healthy scheduler before restart convergence starts.
        second_thread = threading.Thread(target=admit_second)
        second_thread.start()
        self.assertTrue(second_done.wait(0.5))
        self.assertEqual(len(second.messages), 1)
        self.assertEqual(second.messages[0]["code"], "resource_exhausted")
        self.assertEqual(audit.admit_calls, ["request"])

        broker.release_begin.set()
        first_thread.join(2.0)
        second_thread.join(2.0)
        self.assertTrue(first_done.is_set())
        self.assertFalse(failures)
        self.assertFalse(broker._temporary_admission_fence_active())
        self.assertEqual(first.messages[0]["code"], "unknown_after_restart")

    def test_restart_fence_is_visible_while_writer_gate_is_busy(self) -> None:
        binding = _binding(
            broker_epoch="epoch-previous",
            client_id="client-first",
            request_id="request",
            request_sha256="a" * 64,
            client_seq=0,
            upstream_seq=1,
        )
        audit = _DispositionRestartAudit(binding)
        broker = _AdmissionBroker(audit, slots=2)
        first = _Client("client-first")
        second = _Client("client-second")
        failures: list[BaseException] = []
        done = threading.Event()

        # Hold the byte-stream gate to model a dispatcher already inside its
        # bounded write.  Fence publication must not wait for this gate: new
        # admissions need to stop immediately, while the old writer is allowed
        # to finish its pre-fence interval.
        broker.upstream_write_lock.acquire()

        def replay() -> None:
            try:
                broker._admit_request(
                    first,
                    "request",
                    _frame("job-first", 0),
                    frozenset({"job.inspect.result"}),
                    "job-first",
                    5_000,
                )
            except BaseException as error:
                failures.append(error)
            finally:
                done.set()

        thread = threading.Thread(target=replay)
        thread.start()
        self.assertTrue(audit.admit_returned.wait(1.0))
        self.assertTrue(
            broker._temporary_admission_fence_active(),
            "restart fence was not visible before the shared writer gate drained",
        )

        broker._admit_request(
            second,
            "request-second",
            _frame("job-second", 0),
            frozenset({"job.inspect.result"}),
            "job-second",
            5_000,
        )
        self.assertEqual(second.messages[0]["code"], "admission_fenced")
        self.assertEqual(audit.admit_calls, ["request"])

        broker.upstream_write_lock.release()
        thread.join(2.0)
        self.assertTrue(done.is_set())
        self.assertFalse(failures)
        self.assertFalse(broker._temporary_admission_fence_active())

    def test_existing_restart_admission_audit_failure_fences_without_false_terminal(self) -> None:
        binding = _binding(
            broker_epoch="epoch-previous",
            client_id="client",
            request_id="request",
            request_sha256="a" * 64,
            client_seq=0,
            upstream_seq=1,
        )
        broker = _FailClosedAdmissionBroker(_TerminalFailingAudit(binding), slots=1)
        client = _Client("client")

        # A restart convergence failure is an accepted-but-unresolved effect,
        # not a malformed client frame.  It must publish the global fence and
        # return an explicit audit failure while retaining the unresolved
        # binding for offline reconciliation.
        broker._handle_existing_admission(client, "request", "a" * 64, binding)

        self.assertTrue(broker.upstream_uncertain.is_set())
        self.assertTrue(broker.stopping.is_set())
        self.assertEqual(
            [(str(error), code) for error, code in broker.unknown_errors],
            [("injected audit capacity failure", "broker_terminal_audit_failed")],
        )
        self.assertEqual(len(client.messages), 1)
        self.assertEqual(client.messages[0]["code"], "broker_terminal_audit_failed")
        self.assertEqual(client.messages[0]["request_id"], "request")
        self.assertEqual(binding.stage, "broker.accepted")
        self.assertIsNone(binding.terminal_message)

    def test_old_epoch_terminal_replay_fences_new_admission_until_success(self) -> None:
        binding = _binding(
            broker_epoch="epoch-previous",
            client_id="old-client",
            request_id="old-request",
            request_sha256="a" * 64,
            client_seq=0,
            upstream_seq=1,
        )
        audit = _BlockingRestartAudit(binding)
        broker = _AdmissionBroker(audit, slots=1)
        old_client = _Client("old-client")
        new_client = _Client("new-client")
        failures: list[BaseException] = []

        def replay() -> None:
            try:
                broker._handle_existing_admission(
                    old_client,
                    "old-request",
                    "a" * 64,
                    binding,
                )
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=replay)
        thread.start()
        self.assertTrue(audit.terminal_entered.wait(1.0))
        self.assertTrue(broker._temporary_admission_fence_active())

        # The old binding is unresolved while its terminal append is stalled.
        # A genuinely new request must be rejected before it consumes a client
        # sequence, capacity slot, or audit identity.
        broker._admit_request(
            new_client,
            "new-request",
            _frame("job-new", 0),
            frozenset({"job.inspect.result"}),
            "job-new",
            5_000,
        )
        self.assertEqual(new_client.messages[0]["code"], "admission_fenced")
        self.assertEqual(audit.admit_calls, [])
        self.assertIsNone(new_client.last_client_seq)
        self.assertTrue(broker.request_slots.acquire(blocking=False))
        broker.request_slots.release()

        audit.release_terminal.set()
        thread.join(2.0)
        self.assertFalse(failures)
        self.assertFalse(broker._temporary_admission_fence_active())
        self.assertEqual(old_client.messages[0]["code"], "unknown_after_restart")
        self.assertEqual(binding.stage, "broker.terminal")

        # Success restores availability: the previously rejected sequence can
        # now be admitted normally and reaches the mux exactly once.
        broker._admit_request(
            new_client,
            "new-request",
            _frame("job-new", 0),
            frozenset({"job.inspect.result"}),
            "job-new",
            5_000,
        )
        self.assertEqual(audit.admit_calls, ["new-request"])
        self.assertEqual(
            [request.request_id for request in broker.mux.pending_snapshot()],
            ["new-request"],
        )

    def test_old_epoch_terminal_failure_keeps_fence_and_publishes_uncertainty(self) -> None:
        binding = _binding(
            broker_epoch="epoch-previous",
            client_id="old-client",
            request_id="old-request",
            request_sha256="a" * 64,
            client_seq=0,
            upstream_seq=1,
        )
        audit = _BlockingRestartAudit(binding, fail=True)
        broker = _FailClosedAdmissionBroker(audit, slots=1)
        old_client = _Client("old-client")
        new_client = _Client("new-client")
        failures: list[BaseException] = []

        def replay() -> None:
            try:
                broker._handle_existing_admission(
                    old_client,
                    "old-request",
                    "a" * 64,
                    binding,
                )
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=replay)
        thread.start()
        self.assertTrue(audit.terminal_entered.wait(1.0))
        broker._admit_request(
            new_client,
            "new-request",
            _frame("job-new", 0),
            frozenset({"job.inspect.result"}),
            "job-new",
            5_000,
        )
        self.assertEqual(new_client.messages[0]["code"], "admission_fenced")

        audit.release_terminal.set()
        thread.join(2.0)
        self.assertFalse(failures)
        self.assertTrue(broker.upstream_uncertain.is_set())
        self.assertTrue(broker.stopping.is_set())
        # The failed append leaves the transient fence set as a fail-closed
        # guard; global uncertainty is the lasting admission decision.
        self.assertTrue(broker._temporary_admission_fence_active())
        self.assertEqual(old_client.messages[0]["code"], "broker_terminal_audit_failed")
        self.assertEqual(binding.stage, "broker.accepted")
        self.assertEqual(audit.admit_calls, [])

    def test_fresh_admission_audit_failure_publishes_global_uncertainty(self) -> None:
        broker = _FailClosedAdmissionBroker(_AdmissionFailingAudit(), slots=1)
        client = _Client("client")

        broker._admit_request(
            client,
            "request",
            _frame("job", 0),
            frozenset({"job.inspect.result"}),
            "job",
            5_000,
        )

        self.assertTrue(broker.upstream_uncertain.is_set())
        self.assertTrue(broker.stopping.is_set())
        self.assertEqual(
            [(str(error), code) for error, code in broker.unknown_errors],
            [("append became uncertain", "broker_acceptance_audit_failed")],
        )
        self.assertEqual(client.messages[0]["code"], "broker_acceptance_failed")
        self.assertTrue(broker.request_slots.acquire(blocking=False))
        broker.request_slots.release()

    def test_failed_admission_keeps_slot_reserved_until_uncertainty_publication(self) -> None:
        audit = _FirstAdmissionFailingAudit()
        broker = _DelayedMarkAdmissionBroker(audit, slots=1)
        first = _Client("client-first")
        second = _Client("client-second")
        failures: list[BaseException] = []
        first_done = threading.Event()

        def admit_first() -> None:
            try:
                broker._admit_request(
                    first,
                    "first",
                    _frame("job-first", 0),
                    frozenset({"job.inspect.result"}),
                    "job-first",
                    5_000,
                )
            except BaseException as error:
                failures.append(error)
            finally:
                first_done.set()

        thread = threading.Thread(target=admit_first)
        thread.start()
        self.assertTrue(broker.mark_entered.wait(1.0))

        # The failed append still owns its speculative capacity reservation
        # until the global uncertainty bit is published.  A second client
        # therefore cannot sneak through the slot-release window.
        broker._admit_request(
            second,
            "second",
            _frame("job-second", 0),
            frozenset({"job.inspect.result"}),
            "job-second",
            5_000,
        )
        self.assertEqual(len(second.messages), 1)
        self.assertEqual(second.messages[0]["code"], "resource_exhausted")

        broker.release_mark.set()
        thread.join(2.0)
        self.assertTrue(first_done.is_set())
        self.assertFalse(failures)
        self.assertTrue(broker.upstream_uncertain.is_set())
        self.assertTrue(broker.stopping.is_set())


if __name__ == "__main__":
    unittest.main()
