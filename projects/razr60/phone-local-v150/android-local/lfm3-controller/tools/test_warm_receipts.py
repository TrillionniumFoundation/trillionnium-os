"""Synthetic receipt fixtures exercise rejection boundaries, not phone quality."""
import copy
import unittest
from warm_receipts import request_contract, session_contract, collection_verified

T, G, UID, PID = "1" * 32, "2" * 32, 10001, 456


def fixture():
    pairs = []
    for sequence in (1, 2):
        native = dict(schema="hepta.geniex-task-request.result.v1", task_id=T, worker_generation=G,
            request_id=str(sequence + 2) * 32, request_sequence=sequence, pid=PID, worker_retained=True,
            process_exit_observed=False, worker_exit_status_planned=None, request_status=0,
            model_hash_scope="task_generation", model_hash_count=1, sdk_init_count=1, model_create_count=1,
            model_hash_performed_this_request=sequence == 1, model_reset_count=sequence, model_reset_rc=0,
            model_metadata_unchanged=True, generation_complete=True)
        app = dict(schema="hepta.local-model.task-request.v1", task_id=T, worker_generation=G,
            run_id=native["request_id"], request_sequence=sequence, worker_pid=PID,
            process_started=True, worker_started_this_request=sequence == 1, process_exit_observed=False,
            exit_code=None, status="request_completed", request_committed=True, inference_completed=True,
            cancel_requested=False, timeout_observed=False, force_destroy_sent=False, native_receipt=copy.deepcopy(native),
            app_pid=123, app_uid=UID)
        pairs.append((app, native))
    native = dict(schema="hepta.geniex-task-session.result.v1", task_id=T, worker_generation=G, pid=PID,
        process_exit_observed=False, requests_received=2, requests_completed=2, model_reset_count=2,
        model_hash_count=1, model_create_count=1, sdk_init_count=1, model_metadata_unchanged_before_close=True,
        close_requested=True, signal_observed=0, last_request_status=0, sdk_destroy_rc=0, sdk_deinit_rc=0,
        sdk_destroy_attempted=True, sdk_deinit_attempted=True)
    app = dict(schema="hepta.local-model.task-session.v1", task_id=T, worker_generation=G, app_pid=123,
        app_uid=UID, process_started=True, process_exit_observed=True, exit_code=0, cleanup_known=True,
        native_session_binding_valid=True, force_destroy_sent=False, cancel_requested=False,
        automatic_restart=False, cross_task_reuse=False, native_session_receipt=copy.deepcopy(native),
        requests_sent=2, requests_accepted=2)
    final = dict(task_id=T, cleanup_known=True, model_session=dict(worker_generation=G, task_id=T,
        process_started=True, process_exit_observed=True, exit_code=0, receipt_valid=True, app_receipt_sha256="a" * 64))
    return app, native, "a" * 64, final, pairs, T, UID


class WarmReceiptTest(unittest.TestCase):
    def test_one_process_two_requests_valid(self):
        f = fixture()
        self.assertTrue(session_contract(*f))
        self.assertTrue(all(request_contract(a, n, T) for a, n in f[4]))

    def test_parent_timeline_is_additive_not_acceptance_evidence(self):
        f = fixture()
        f[0]["parent_process_timeline"] = dict(
            schema="hepta.parent-process-timeline.v1", task_id=T, worker_generation=G,
            clock="System.nanoTime", units="nanoseconds",
            origin="parent_warm_task_timeline_creation", clock_scope="same_parent_process_only",
            first_cancel_requested=None, first_destroy_invoked=None,
            first_destroy_forcibly_invoked=None,
            first_exit_observed=dict(elapsed_ns=10, sequence=1, source="graceful_close_wait", exit_code=0),
            snapshot_elapsed_ns=11, destroy_invocation_count=0, destroy_forcibly_invocation_count=0,
            signal_delivery_proven=False, exit_cause_inferred=False)
        self.assertTrue(session_contract(*f))
        for key, value in (("process_exit_observed", False), ("exit_code", 134),
                           ("cleanup_known", False), ("force_destroy_sent", True),
                           ("cancel_requested", True), ("native_session_binding_valid", False)):
            bad = copy.deepcopy(f)
            bad[0][key] = value
            self.assertFalse(session_contract(*bad), key)

    def test_request_exit_is_rejected_even_if_marked_success(self):
        for key, value in (("process_exit_observed", True), ("exit_code", 0), ("request_committed", False),
                           ("cancel_requested", True), ("timeout_observed", True)):
            f = fixture(); f[4][0][0][key] = value
            self.assertFalse(session_contract(*f), key)

    def test_no_terminal_or_unknown_actual_exit(self):
        f = fixture(); self.assertFalse(session_contract({}, *f[1:]))
        for key, value in (("process_exit_observed", False), ("exit_code", None), ("cleanup_known", False),
                           ("force_destroy_sent", True), ("native_session_binding_valid", False)):
            f = fixture(); f[0][key] = value
            self.assertFalse(session_contract(*f), key)

    def test_native_cannot_claim_own_exit(self):
        f = fixture(); f[1]["process_exit_observed"] = True; f[0]["native_session_receipt"] = copy.deepcopy(f[1])
        self.assertFalse(session_contract(*f))

    def test_stale_generation_pid_task_or_restarted_worker(self):
        for key, value in (("worker_generation", "f" * 32), ("worker_pid", PID + 1), ("task_id", "f" * 32),
                           ("worker_started_this_request", True), ("app_pid", 124)):
            f = fixture(); f[4][1][0][key] = value
            self.assertFalse(session_contract(*f), key)

    def test_missing_duplicate_and_out_of_order_sequences(self):
        f = fixture(); f[4].pop(); self.assertFalse(session_contract(*f))
        f = fixture(); f[4][1] = copy.deepcopy(f[4][0]); self.assertFalse(session_contract(*f))
        f = fixture(); f[4].reverse(); self.assertTrue(session_contract(*f))

    def test_reset_each_prompt_and_exact_create_hash_counts(self):
        for key, value in (("model_reset_count", 1), ("model_reset_rc", -1), ("model_create_count", 2),
                           ("model_hash_count", 2), ("model_hash_performed_this_request", True)):
            f = fixture(); f[4][1][1][key] = value; f[4][1][0]["native_receipt"] = copy.deepcopy(f[4][1][1])
            self.assertFalse(session_contract(*f), key)

    def test_terminal_identity_hash_or_destroy_failure(self):
        f = fixture(); f[3]["model_session"]["app_receipt_sha256"] = "b" * 64
        self.assertFalse(session_contract(*f))
        for key, value in (("sdk_destroy_attempted", False), ("sdk_destroy_rc", -1), ("close_requested", False),
                           ("requests_completed", 1), ("model_metadata_unchanged_before_close", False)):
            f = fixture(); f[1][key] = value; f[0]["native_session_receipt"] = copy.deepcopy(f[1])
            self.assertFalse(session_contract(*f), key)

    def test_boolean_counters_are_not_integers(self):
        f = fixture(); f[4][0][1]["model_create_count"] = True
        f[4][0][0]["native_receipt"] = copy.deepcopy(f[4][0][1])
        self.assertFalse(session_contract(*f))

    def test_old_exit_gate_remains_required_and_warm_must_have_terminal(self):
        row = dict.fromkeys(("app_receipt_available", "run_id_binding_valid", "inference_completed",
            "app_identity_and_runtime_valid", "native_output_binding_valid", "accelerator_runtime_valid",
            "accelerator_offload_observed", "controller_grammar_binding_valid"), True)
        row.update(process_exit_observed=True, exit_code=0)
        self.assertTrue(collection_verified(dict(associated_runs=[row])))
        row["process_exit_observed"] = False
        self.assertFalse(collection_verified(dict(associated_runs=[row])))
        row.update(app_receipt_schema="hepta.local-model.task-request.v1", task_request_binding_valid=True)
        self.assertFalse(collection_verified(dict(associated_runs=[row])))
        self.assertTrue(collection_verified(dict(associated_runs=[row], task_model_sessions_valid=True)))


if __name__ == "__main__":
    unittest.main()
