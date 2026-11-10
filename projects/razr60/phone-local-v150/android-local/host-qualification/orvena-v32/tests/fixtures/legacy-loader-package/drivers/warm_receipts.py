"""Offline binding checks for task-scoped workers; a request is never an exit.

These checks consume recorded evidence. Actual process ownership and waitFor
belong to the app; native code cannot assert that its own process has exited.
"""
import re

ID = re.compile(r"[0-9a-f]{32}\Z")
APP_REQUEST = "hepta.local-model.task-request.v1"
NATIVE_REQUEST = "hepta.geniex-task-request.result.v1"
APP_SESSION = "hepta.local-model.task-session.v1"
NATIVE_SESSION = "hepta.geniex-task-session.result.v1"


def identifier(value):
    return isinstance(value, str) and ID.fullmatch(value) is not None


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def request_contract(app, native, task_id):
    if not isinstance(app, dict) or not isinstance(native, dict):
        return False
    generation, request, sequence = app.get("worker_generation"), app.get("run_id"), app.get("request_sequence")
    if not (identifier(task_id) and identifier(generation) and identifier(request)
            and integer(sequence, 1) and sequence <= 64):
        return False
    return (app.get("schema") == APP_REQUEST and native.get("schema") == NATIVE_REQUEST
        and app.get("task_id") == task_id == native.get("task_id")
        and native.get("worker_generation") == generation and native.get("request_id") == request
        and native.get("request_sequence") == sequence and type(native.get("request_sequence")) is int
        and integer(app.get("worker_pid"), 1) and native.get("pid") == app["worker_pid"]
        and type(native.get("pid")) is int
        and app.get("process_started") is True
        and app.get("worker_started_this_request") is (sequence == 1)
        and app.get("process_exit_observed") is False and "exit_code" in app and app["exit_code"] is None
        and app.get("status") == "request_completed" and app.get("request_committed") is True
        and app.get("inference_completed") is True and app.get("cancel_requested") is False
        and app.get("timeout_observed") is False and app.get("force_destroy_sent") is False
        and app.get("native_receipt") == native
        and native.get("worker_retained") is True and native.get("process_exit_observed") is False
        and "worker_exit_status_planned" in native and native["worker_exit_status_planned"] is None
        and native.get("request_status") == 0 and type(native.get("request_status")) is int
        and native.get("model_hash_scope") == "task_generation"
        and all(type(native.get(key)) is int and native[key] == 1
                for key in ("model_hash_count", "sdk_init_count", "model_create_count"))
        and native.get("model_hash_performed_this_request") is (sequence == 1)
        and native.get("model_reset_count") == sequence and type(native.get("model_reset_count")) is int
        and native.get("model_reset_rc") == 0 and type(native.get("model_reset_rc")) is int
        and native.get("model_metadata_unchanged") is True and native.get("generation_complete") is True)


def session_contract(app, native, app_sha256, final, records, task_id, expected_uid):
    """Require all requests, one generation, and an independently recorded exit.

    records contains (app request, native request) pairs. The caller separately
    validates model/profile, prompt/grammar/output hashes, and accelerator logs.
    """
    if not (isinstance(app, dict) and isinstance(native, dict) and isinstance(final, dict)
            and isinstance(records, list) and records and identifier(task_id)):
        return False
    generation = app.get("worker_generation")
    if not identifier(generation) or not all(request_contract(a, n, task_id) for a, n in records):
        return False
    count = len(records)
    if sorted(a["request_sequence"] for a, _ in records) != list(range(1, count + 1)):
        return False
    if len({a["run_id"] for a, _ in records}) != count:
        return False
    summary = final.get("model_session")
    if not isinstance(summary, dict):
        return False
    pid, app_pid = native.get("pid"), app.get("app_pid")
    return (app.get("schema") == APP_SESSION and native.get("schema") == NATIVE_SESSION
        and app.get("task_id") == task_id == native.get("task_id") == final.get("task_id")
        and native.get("worker_generation") == generation
        and integer(pid, 1) and integer(app_pid, 1) and integer(expected_uid, 10000)
        and app.get("app_uid") == expected_uid
        and all(a["worker_generation"] == generation and a["worker_pid"] == pid
                and a.get("app_pid") == app_pid and a.get("app_uid") == expected_uid for a, _ in records)
        and app.get("process_started") is True and app.get("process_exit_observed") is True
        and type(app.get("exit_code")) is int and app["exit_code"] == 0
        and app.get("cleanup_known") is True and app.get("native_session_binding_valid") is True
        and app.get("force_destroy_sent") is False and app.get("cancel_requested") is False
        and app.get("automatic_restart") is False and app.get("cross_task_reuse") is False
        and app.get("native_session_receipt") == native and native.get("process_exit_observed") is False
        and all(type(app.get(key)) is int and app[key] == count
                for key in ("requests_sent", "requests_accepted"))
        and all(type(native.get(key)) is int and native[key] == count
                for key in ("requests_received", "requests_completed", "model_reset_count"))
        and all(type(native.get(key)) is int and native[key] == 1
                for key in ("model_hash_count", "model_create_count", "sdk_init_count"))
        and native.get("model_metadata_unchanged_before_close") is True and native.get("close_requested") is True
        and all(type(native.get(key)) is int and native[key] == 0
                for key in ("signal_observed", "last_request_status", "sdk_destroy_rc", "sdk_deinit_rc"))
        and native.get("sdk_destroy_attempted") is True and native.get("sdk_deinit_attempted") is True
        and summary.get("worker_generation") == generation and summary.get("task_id") == task_id
        and summary.get("process_started") is True and summary.get("process_exit_observed") is True
        and type(summary.get("exit_code")) is int and summary["exit_code"] == 0
        and summary.get("receipt_valid") is True and summary.get("app_receipt_sha256") == app_sha256
        and final.get("cleanup_known") is True)


def collection_verified(collection):
    rows = collection.get("associated_runs", [])
    if not rows:
        return False
    warm = any(row.get("app_receipt_schema") == APP_REQUEST for row in rows)
    if warm and not (all(row.get("app_receipt_schema") == APP_REQUEST for row in rows)
                     and collection.get("task_model_sessions_valid") is True):
        return False
    common = ("app_receipt_available", "run_id_binding_valid", "inference_completed",
              "app_identity_and_runtime_valid", "native_output_binding_valid", "accelerator_runtime_valid",
              "accelerator_offload_observed", "controller_grammar_binding_valid")
    return all(all(row.get(key) is True for key in common)
               and (row.get("task_request_binding_valid") is True if warm
                    else row.get("process_exit_observed") is True and type(row.get("exit_code")) is int
                    and row["exit_code"] == 0) for row in rows)
