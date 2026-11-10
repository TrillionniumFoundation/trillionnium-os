"""Recheck an entire collected task worker before qualifying any of its actions.

This module reads a completed case directory only. It never runs a process,
contacts a device, changes evidence, or supplies an action. Collector summaries
are required, but cannot substitute for the request/session artifacts below.
"""
from pathlib import Path
import json
import re

import phone_acceptance as acceptance
from model_profiles import DEFAULT_PROFILE, profile
from warm_receipts import (APP_REQUEST, NATIVE_REQUEST, collection_verified,
                           json_equivalent, request_contract, session_contract)


def need(value, message):
    if not value:
        raise acceptance.DriverError("warm action evidence: " + message)


class Snapshot:
    """A bounded, per-call byte snapshot; no cached approval survives a call."""
    def __init__(self, directory):
        self.directory = Path(directory)
        self.data, self.manifest = {}, {}

    def read(self, relative, pinned=True):
        path = Path(relative)
        need(not path.is_absolute() and path.parts and all(p not in (".", "..") for p in path.parts)
             and str(path) == relative, "unsafe evidence path")
        target = self.directory / path
        current = target
        while current != self.directory.parent:
            need(not current.is_symlink(), "symlink in " + relative)
            current = current.parent
        if relative not in self.data:
            need(target.is_file() and target.stat().st_size <= 16 * 1024 * 1024,
                 "missing or oversized " + relative)
            raw = target.read_bytes()
            need(len(raw) <= 16 * 1024 * 1024, "evidence grew beyond bound")
            self.data[relative] = raw
            need(sum(map(len, self.data.values())) <= 128 * 1024 * 1024, "case exceeds byte bound")
        raw = self.data[relative]
        if pinned:
            item = self.manifest.get(relative, {})
            need(type(item.get("bytes")) is int and item["bytes"] == len(raw)
                 and item.get("sha256") == acceptance.digest(raw), "manifest differs for " + relative)
        return raw

    def obj(self, relative, pinned=True):
        value = acceptance.strict_json(self.read(relative, pinned))
        need(isinstance(value, dict), "object required in " + relative)
        return value

    def add_files(self, files, scope):
        need(isinstance(files, list) and len(files) <= 2048, "invalid file inventory")
        for item in files:
            need(isinstance(item, dict) and isinstance(item.get("path"), str), "invalid inventory entry")
            relative = item["path"]
            path = Path(relative)
            need(str(path.parent) == scope and acceptance.SAFE_FILE.fullmatch(path.name)
                 and relative not in self.manifest, "duplicate or foreign inventory path")
            self.manifest[relative] = item
        folder = self.directory / scope
        need(folder.is_dir() and not folder.is_symlink(), "missing or linked inventory directory")
        observed = {str(p.relative_to(self.directory)) for p in folder.iterdir()}
        expected = {name for name in self.manifest if str(Path(name).parent) == scope}
        need(observed == expected, "unlisted or missing collected files in " + scope)


def requires_warm_binding(directory, run_id, native):
    """Recognize task mode independently of the selected result's schema."""
    if native.get("schema") == NATIVE_REQUEST or "worker_generation" in native:
        return True
    snapshot = Snapshot(directory)
    for relative in ("runs/" + run_id + "/app-receipt.json", "task/result.json", "collection.json"):
        path = Path(directory) / relative
        if not path.exists() and not path.is_symlink():
            continue
        value = snapshot.obj(relative, pinned=False)
        summary = value.get("model_session")
        if (value.get("schema") == APP_REQUEST or "worker_generation" in value
                or isinstance(summary, dict) and (summary.get("worker_generation") is not None
                                                   or summary.get("process_started") is True)
                or value.get("task_model_session_expected") is True
                or any(isinstance(row, dict) and row.get("app_receipt_schema") == APP_REQUEST
                       for row in value.get("associated_runs", []))):
            return True
    return False


def verify_warm_action(directory, action_path, receipt, before, model_path, model, native, raw, owner_sha,
                       action_identity):
    """Return evidence for one action only after the whole generation verifies."""
    snapshot = Snapshot(directory)
    collection = snapshot.obj("collection.json", pinned=False)
    report = snapshot.obj("acceptance.json", pinned=False)
    need(json_equivalent(report.get("collection"), collection)
         and collection_verified(collection) and report.get("native_receipts_verified") is True,
         "complete verified collection is unavailable")
    need(collection.get("task_model_session_expected") is True
         and collection.get("observed_terminal_binding_valid") is True,
         "task mode or observed terminal is unbound")
    rows, sessions = collection.get("associated_runs"), collection.get("task_model_sessions")
    need(isinstance(rows, list) and 1 <= len(rows) <= 64
         and isinstance(sessions, list) and len(sessions) == 1, "one complete generation required")
    generation = sessions[0].get("worker_generation")
    need(isinstance(generation, str) and acceptance.HEX32.fullmatch(generation), "invalid generation")
    by_run = {}
    snapshot.add_files(collection.get("files"), "task")
    for row in rows:
        need(isinstance(row, dict), "invalid request summary")
        run_id = row.get("run_id")
        need(isinstance(run_id, str) and acceptance.HEX32.fullmatch(run_id)
             and run_id not in by_run and run_id != generation, "duplicate or invalid request identity")
        by_run[run_id] = row
        snapshot.add_files(row.get("files"), "runs/" + run_id)
    snapshot.add_files(sessions[0].get("files"), "runs/" + generation)
    run_root = Path(directory) / "runs"
    need(not run_root.is_symlink() and {p.name for p in run_root.iterdir()} == set(by_run) | {generation},
         "unlisted or missing request directory")
    for relative in snapshot.manifest:
        snapshot.read(relative)

    owner, final = snapshot.obj("task/owner.json"), snapshot.obj("task/result.json")
    task_id, instruction = owner.get("task_id"), owner.get("instruction")
    need(isinstance(task_id, str) and acceptance.HEX32.fullmatch(task_id)
         and task_id == collection.get("task_id") == report.get("task_id") == final.get("task_id"),
         "task identity differs")
    need(isinstance(instruction, str) and acceptance.digest(instruction.encode("utf-8")) == owner_sha
         and owner.get("instruction_utf8_sha256") == report.get("instruction_sha256") == owner_sha
         and report.get("instruction") == instruction, "original instruction differs")
    need(json.dumps(final, sort_keys=True, allow_nan=False)
         == json.dumps(report.get("task_result"), sort_keys=True, allow_nan=False)
         and final.get("status") in acceptance.TERMINAL and final.get("external_model") is False
         and final.get("cleanup_known") is True and report.get("cleanup_unknown") is False,
         "collected terminal differs or cleanup is unresolved")
    expected_uid = report.get("app_uid")
    need(type(expected_uid) is int and expected_uid >= 10000, "application UID is unavailable")

    observations, steps = {}, []
    for relative in sorted(snapshot.manifest):
        if re.fullmatch(r"task/step-[0-9]{2}-(before|after)\.json", relative):
            observation = snapshot.obj(relative)
            identifier, package = observation.get("observation_id"), observation.get("package")
            need(isinstance(identifier, str) and acceptance.HEX32.fullmatch(identifier)
                 and isinstance(package, str) and package, "invalid collected observation")
            observations.setdefault(identifier, set()).add(package)
        match = re.fullmatch(r"task/step-([0-9]{2})-model-([01])\.json", relative)
        if match:
            steps.append((int(match[1]), int(match[2]), relative, snapshot.obj(relative)))
        elif re.fullmatch(r"task/step-.*-model-.*\.json", relative):
            need(False, "invalid model attempt filename")
    need(len(steps) == len(rows) and {m.get("run_id") for _, _, _, m in steps} == set(by_run),
         "request inventory and step-model inventory differ")
    need({step for step, _, _, _ in steps} == set(range(1, max(step for step, _, _, _ in steps) + 1)),
         "controller model steps are not contiguous")
    step_numbers = {step for step, _, _, _ in steps}
    for suffix in ("before", "action", "after"):
        actual = {name for name in snapshot.manifest
                  if re.fullmatch(r"task/step-.*-" + suffix + r"\.json", name)}
        expected = {"task/step-%02d-%s.json" % (step, suffix) for step in step_numbers}
        need(actual == expected, "controller step " + suffix + " inventory is incomplete")
    records, runtime = [], None
    last_models = {}
    for sequence, (step, attempt, relative, step_model) in enumerate(sorted(steps), 1):
        need(step >= 1 and (attempt == 0 or any(s == step and t == 0 for s, t, _, _ in steps)),
             "corrected request lacks its first attempt")
        run_id = step_model["run_id"]
        prefix = "runs/" + run_id + "/"
        app, request = snapshot.obj(prefix + "app-receipt.json"), snapshot.obj(prefix + "native-result.json")
        need(request_contract(app, request, task_id) and app["worker_generation"] == generation
             and app["run_id"] == run_id and app["request_sequence"] == sequence
             and by_run[run_id].get("worker_generation") == generation
             and type(by_run[run_id].get("request_sequence")) is int
             and by_run[run_id]["request_sequence"] == sequence, "request/step sequence or generation differs")
        output, prompt = snapshot.read(prefix + "raw-text.txt"), snapshot.read(prefix + "prompt.txt")
        observed = snapshot.obj("task/step-%02d-before.json" % step)
        need(step_model.get("observation_id") == observed.get("observation_id")
             and step_model.get("original_instruction_sha256") == owner_sha
             and isinstance(step_model.get("raw_text"), str)
             and step_model["raw_text"].encode("utf-8") == output, "step output or observation differs")
        inputs = request.get("input_sha256")
        system = prefix + "system.txt"
        system_sha = acceptance.digest(snapshot.read(system)) if system in snapshot.manifest else None
        need(isinstance(inputs, dict) and app.get("prompt_sha256") == inputs.get("prompt") == acceptance.digest(prompt)
             and "system" in inputs and inputs["system"] == system_sha
             and acceptance.prompt_binding(prompt.decode("utf-8"), instruction, {observed.get("observation_id")}),
             "prompt/system does not bind this exact step and owner")
        prompt_data = acceptance.strict_json(prompt[len(b"UNTRUSTED_DATA\n"):].split(b"\nOWNER\n", 1)[0])
        need(prompt_data.get("screen", {}).get("package") == observed.get("package")
             and app.get("grammar_observation_id") == observed.get("observation_id"), "prompt screen differs")
        need(0 < len(output) <= 16384 and request.get("raw_text_utf8") is True
             and request.get("raw_text_truncated") is False and type(request.get("raw_text_bytes")) is int
             and request["raw_text_bytes"] == len(output) and "error" in request and request["error"] is None
             and app.get("raw_text_sha256_read") == request.get("raw_text_sha256") == acceptance.digest(output),
             "native output is incomplete or changed")
        output.decode("utf-8", "strict")
        need(acceptance.controller_grammar_binding_valid(app, request, snapshot.read(prefix + "grammar.gbnf"),
                                                        observations, prompt, output), "controller grammar is unbound")
        compute, context = app.get("compute_requested"), app.get("context_tokens")
        model_profile = app.get("model_profile", DEFAULT_PROFILE)
        selected = profile(model_profile)
        current_runtime = (compute, context, model_profile, app.get("model_path"))
        need(runtime is None or runtime == current_runtime, "runtime changed inside one generation")
        runtime = current_runtime
        need(compute in ("npu", "gpu") and type(context) is int and context in (4096, 8192)
             and app.get("package_name") == acceptance.PACKAGE and app.get("app_uid") == expected_uid
             and app.get("runtime") == request.get("runtime") == "llama_cpp"
             and app.get("mode") == request.get("mode") == "llm"
             and app.get("model_sha256_verified") == selected["sha256"]
             and all(app.get(k) is True for k in ("native_context_budget_valid", "grammar_constraint_enabled",
                     "grammar_binding_valid", "native_result_binding_valid"))
             and app.get("image_sent_to_model") is False and app.get("fallback_allowed") is False
             and request.get("compute_requested") == compute
             and request.get("device_resolved") == ("HTP0" if compute == "npu" else "GPUOpenCL")
             and "device_warning" in request and request["device_warning"] is None
             and type(request.get("n_gpu_layers_create")) is int and request["n_gpu_layers_create"] != 0
             and type(request.get("n_ctx_create")) is int and request["n_ctx_create"] == context
             and isinstance(request.get("model_path"), str) and request["model_path"] == app.get("model_path")
             and Path(request["model_path"]).name == selected["file"]
             and acceptance.native_budget_valid(request, context, model_profile), "runtime/model/budget is invalid")
        records.append((app, request))
        last_models[step] = (run_id, output)
    decisions = {}
    for step in sorted(step_numbers):
        prefix = "task/step-%02d" % step
        step_before, step_after = snapshot.obj(prefix + "-before.json"), snapshot.obj(prefix + "-after.json")
        action_receipt = snapshot.obj(prefix + "-action.json")
        run_id, output = last_models[step]
        action = action_receipt.get("action")
        generated = acceptance.strict_json(output)
        need(action_identity(action) == action_identity(generated)
             and action_receipt.get("model_issued") is True
             and action_receipt.get("model_run_id") == run_id
             and action.get("observation_id") == step_before.get("observation_id"),
             "controller step action differs from its selected native output")
        kind = action.get("action")
        effects = {"open", "click", "type", "scroll", "back", "home"}
        need(kind in effects | {"done", "find_app", "wait"}
             and action_receipt.get("accepted") is True and action_receipt.get("stale") is False
             and action_receipt.get("dispatched") is (kind in effects)
             and (kind == "open" or action.get("package") == step_before.get("package")),
             "controller step has inconsistent action outcome")
        need(kind != "find_app" or action_receipt.get("read_only") is True
             and action_receipt.get("effect") == "launcher_catalogue_read", "discovery is not recorded as read-only")
        need(kind != "wait" or type(action.get("duration_ms")) is int
             and 100 <= action["duration_ms"] <= 2000, "wait duration is not an exact bounded integer")
        decisions[step] = (action, step_after)
    last_step = max(step_numbers)
    terminal_action, terminal_after = decisions[last_step]
    need(type(final.get("steps")) is int and final["steps"] == last_step
         and final.get("final_observation_id") == terminal_after.get("observation_id"),
         "task terminal does not identify the last complete controller step")
    need(report.get("verdict") != "pass" or final.get("status") == "model_reported_done",
         "base pass contradicts an unsuccessful task terminal")
    if final.get("status") == "model_reported_done":
        need(final.get("model_reported_success") is True and terminal_action.get("action") == "done"
             and terminal_action.get("status") == "success", "successful terminal lacks a native done success decision")
        terminal_before = snapshot.obj("task/step-%02d-before.json" % last_step)
        for observation in (terminal_before, terminal_after):
            need(isinstance(observation.get("package"), str) and observation["package"]
                 and type(observation.get("window_id")) is int
                 and type(observation.get("rotation")) is int and observation["rotation"] in (0, 1, 2, 3)
                 and isinstance(observation.get("observation_state_sha256"), str)
                 and re.fullmatch(r"[0-9a-f]{64}", observation["observation_state_sha256"]),
                 "successful terminal observation lacks complete producer state")
        need(all(terminal_before[key] == terminal_after[key]
                 for key in ("package", "window_id", "rotation", "observation_state_sha256")),
             "producer state changed across the successful done action")
    app_session = snapshot.obj("runs/" + generation + "/app-session-receipt.json")
    native_session = snapshot.obj("runs/" + generation + "/native-session-result.json")
    session_sha = acceptance.digest(snapshot.read("runs/" + generation + "/app-session-receipt.json"))
    need(session_contract(app_session, native_session, session_sha, final, records, task_id, expected_uid),
         "generation lacks a complete request sequence and independently observed exit")
    stderr = "runs/" + generation + "/stderr.log"
    need(acceptance.accelerator_log_evidence(snapshot.read(stderr).decode("utf-8", "replace"), runtime[0])
         ["accelerator_offload_observed"], "same-generation accelerator offload is unavailable")
    action_relative, model_relative = (str(Path(p).relative_to(directory)) for p in (action_path, model_path))
    step_prefix = action_relative.removesuffix("-action.json")
    need(json_equivalent(snapshot.obj(action_relative), receipt)
         and json_equivalent(snapshot.obj(step_prefix + "-before.json"), before)
         and json_equivalent(snapshot.obj(model_relative), model), "caller evidence differs from collected snapshot")
    run_id = model["run_id"]
    need(any(path == model_relative and item["run_id"] == run_id for _, _, path, item in steps)
         and json_equivalent(snapshot.obj("runs/" + run_id + "/native-result.json"), native)
         and snapshot.read("runs/" + run_id + "/raw-text.txt") == raw, "selected request differs from snapshot")
    return {"inference_mode": "task_worker", "task_id": task_id, "worker_generation": generation,
            "request_sequence": next(a["request_sequence"] for a, _ in records if a["run_id"] == run_id),
            "generation_requests_verified": len(records), "generation_process_exit_observed": True,
            "generation_exit_code": 0, "generation_app_receipt_sha256": session_sha,
            "generation_stderr_sha256": acceptance.digest(snapshot.read(stderr)),
            "controller_steps_verified": len(step_numbers), "terminal_action_run_id": last_models[last_step][0],
            "terminal_action_raw_sha256": acceptance.digest(last_models[last_step][1]),
            "terminal_observation_id": terminal_after["observation_id"],
            "collection_sha256": acceptance.digest(snapshot.read("collection.json", pinned=False))}
