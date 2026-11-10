#!/usr/bin/env python3
"""Run an explicitly frozen set of Hepta phone cases, once each, without retries.

This driver qualifies only the cases in its manifest. It does not claim full
phone, offline, vision, battery, or production acceptance from a navigation suite.
Validation is offline; only the explicit run subcommand contacts a phone.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys
import time
from types import SimpleNamespace

import phone_acceptance as acceptance
from model_profiles import profile as selected_profile, DEFAULT_PROFILE
from phone_inventory import require_existing_adb_server
from warm_receipts import APP_REQUEST, NATIVE_REQUEST, request_contract, session_contract, collection_verified

SCHEMA = "hepta.phone-suite.v1"
SHA = re.compile(r"[0-9a-f]{64}\Z")
PKG = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+\Z")
EFFECTS = {"open", "click", "type", "scroll", "back", "home"}
UNASSESSED = ["all_installed_apps", "vision", "locked_or_screen_off", "offline_device",
              "cancellation_and_timeout", "process_restart_no_replay", "sustained_thermal_and_power"]
INTERRUPTED_LATCH_PROBE = (
    "if [ ! -d files ] || [ ! -r files ] || [ ! -x files ] || [ -L files ]; then exit 41; fi; "
    "if [ -e files/control-session.interrupted.json ] || [ -L files/control-session.interrupted.json ]; "
    "then exit 0; else exit 40; fi"
)


def exact_keys(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= set(value) or set(value) - set(required) - set(optional):
        raise acceptance.DriverError("missing or unknown fields: " + ", ".join(sorted(required)))


def validate_plan(plan, require_runnable=False):
    exact_keys(plan, ("schema", "suite_id", "candidate", "cases"))
    if plan["schema"] != SCHEMA or not isinstance(plan["suite_id"], str) or not acceptance.CASE_ID.fullmatch(plan["suite_id"]):
        raise acceptance.DriverError("invalid suite identity")
    candidate = plan["candidate"]
    exact_keys(candidate, ("package", "apk_sha256", "version_code", "model_sha256", "compute", "context_tokens", "threads"),("model_profile",))
    try: model=selected_profile(candidate.get("model_profile",DEFAULT_PROFILE))
    except ValueError as error: raise acceptance.DriverError(str(error)) from error
    if candidate["package"] != acceptance.PACKAGE or candidate["model_sha256"] != model["sha256"]:
        raise acceptance.DriverError("this driver only qualifies its fixed package and model")
    if type(candidate["version_code"]) is not int or candidate["version_code"] < 1:
        raise acceptance.DriverError("positive exact version_code required")
    if candidate["compute"] not in ("npu", "gpu") or type(candidate["context_tokens"]) is not int or candidate["context_tokens"] not in (4096, 8192):
        raise acceptance.DriverError("unsupported runtime configuration")
    if type(candidate["threads"]) is not int or not 1 <= candidate["threads"] <= 8:
        raise acceptance.DriverError("threads must be 1..8")
    blockers = []
    if candidate["apk_sha256"] is None:
        blockers.append("candidate APK has not been built and SHA-bound")
    elif not isinstance(candidate["apk_sha256"], str) or not SHA.fullmatch(candidate["apk_sha256"]):
        raise acceptance.DriverError("apk_sha256 must be a real SHA256 or null for a non-runnable draft")
    if not isinstance(plan["cases"], list) or not 1 <= len(plan["cases"]) <= 100:
        raise acceptance.DriverError("suite requires 1..100 explicitly enumerated attempts")
    ids = set()
    for case in plan["cases"]:
        exact_keys(case, ("case_id", "instruction", "expected_package", "expected_visible_text", "text_match", "required_actions", "setup_home", "timeout_seconds"))
        case_id = case["case_id"]
        if not isinstance(case_id, str) or not acceptance.CASE_ID.fullmatch(case_id) or case_id in ids:
            raise acceptance.DriverError("case IDs must be safe and unique")
        ids.add(case_id)
        text = case["instruction"]
        if not isinstance(text, str) or not text.strip() or len(text.encode("utf-8")) > 1600 or any(s in text for s in ("\0", "<|", "<__image__>")):
            raise acceptance.DriverError("invalid original instruction")
        if not isinstance(case["expected_package"], str) or not PKG.fullmatch(case["expected_package"]):
            raise acceptance.DriverError("an independent final-package predicate is required")
        texts = case["expected_visible_text"]
        if not isinstance(texts, list) or len(texts) > 32 or any(not isinstance(s, str) or not s or len(s.encode("utf-8")) > 4096 for s in texts):
            raise acceptance.DriverError("invalid final visible-text predicates")
        if case["text_match"] not in ("exact", "contains") or type(case["setup_home"]) is not bool:
            raise acceptance.DriverError("invalid test preconditions or text mode")
        timeout = case["timeout_seconds"]
        if type(timeout) is not int or not 1 <= timeout <= 3600:
            raise acceptance.DriverError("invalid bounded timeout")
        actions = case["required_actions"]
        if not isinstance(actions, list) or not actions or len(actions) > 20:
            raise acceptance.DriverError("at least one real dispatched action must be required")
        for action in actions:
            exact_keys(action, ("action",), ("package",))
            if action["action"] not in EFFECTS:
                raise acceptance.DriverError("required action must be a supported phone effect")
            if "package" in action and (not isinstance(action["package"], str) or not PKG.fullmatch(action["package"])):
                raise acceptance.DriverError("invalid required action package")
    if require_runnable and blockers:
        raise acceptance.DriverError("; ".join(blockers))
    return {"schema": SCHEMA, "valid": True, "runnable": not blockers,
            "planned_attempts": len(plan["cases"]), "blockers": blockers,
            "phone_contacted": False, "full_phone_acceptance": "not_assessed"}


def preflight(adb, candidate):
    """Read actual installed binary identity and current config; no model request."""
    _, data = adb.command(["pm", "path", acceptance.PACKAGE], label="suite-apk-path")
    paths = [line.removeprefix("package:") for line in data.decode("utf-8").splitlines() if line.startswith("package:")]
    if len(paths) != 1 or not paths[0].startswith("/data/app/") or not paths[0].endswith("/base.apk") or "\0" in paths[0]:
        raise acceptance.DriverError("exactly one installed base.apk required")
    _, output = adb.command(["sha256sum", paths[0]], label="suite-installed-apk-sha256", timeout=30)
    actual_sha = output.decode("ascii").split()[0]
    if not SHA.fullmatch(actual_sha) or actual_sha != candidate["apk_sha256"]:
        raise acceptance.DriverError("installed APK differs from frozen candidate")
    _, package_data = adb.command(["dumpsys", "package", acceptance.PACKAGE], label="suite-package")
    package_text = package_data.decode("utf-8", "strict")
    versions = re.findall(r"\bversionCode=(\d+)\b", package_text)
    if not versions or set(versions) != {str(candidate["version_code"])}:
        raise acceptance.DriverError("installed versionCode differs from frozen candidate")
    # A denied INTERNET permission also means a differently built candidate;
    # this package's contract contains no declaration at all.
    if "android.permission.INTERNET" in package_text:
        raise acceptance.DriverError("INTERNET appears in actual package permissions")
    config = adb.app_json("files/model/runtime-config.json", optional=True)
    if config is None:
        config = {"schema": "hepta.local-runtime.v1", "compute": "npu", "context_tokens": 8192, "threads": 4}
        origin = "fixed_application_default"
    else:
        origin = "app_private_config"
    expected = {"schema": "hepta.local-runtime.v1", **{k: candidate[k] for k in ("compute", "context_tokens", "threads")}}
    if "model_profile" in candidate: expected.update(schema="hepta.local-runtime.v2",model_profile=candidate["model_profile"])
    if not isinstance(config, dict) or type(config.get("context_tokens")) is not int or type(config.get("threads")) is not int or config != expected:
        raise acceptance.DriverError("actual on-phone configuration differs; no automatic switch attempted")
    latch_code, latch_output = adb.command(
        ["run-as", acceptance.PACKAGE, "sh", "-c", INTERRUPTED_LATCH_PROBE],
        label="suite-interrupted-session-latch", allowed=(0, 40), raw=True)
    if latch_code == 0:
        raise acceptance.DriverError("interrupted-session latch exists; no task submitted or latch cleared")
    if latch_code != 40 or latch_output != b"":
        raise acceptance.DriverError("interrupted-session latch absence could not be established in readable app files")
    state = acceptance.current_status(adb)
    session = state["session"] or {}
    if session.get("pending") is True or session.get("running") is True or session.get("blocked") is True or session.get("cleanup_known") is False:
        raise acceptance.DriverError("existing application session is active or unresolved")
    return {"installed_apk_sha256": actual_sha, "installed_version_code": int(versions[0]),
            "runtime_config": config, "config_origin": origin, "internet_permission_declared": False,
            "interrupted_session_latch_present": False,
            "device_offline_proven": False, "inference_has_run": False}


def _evidence_object(path):
    if path.is_symlink():
        raise acceptance.DriverError("evidence file is a symlink")
    value = acceptance.strict_json(path.read_bytes())
    if not isinstance(value, dict):
        raise acceptance.DriverError("evidence JSON object required")
    return value


def _action_identity(value):
    """Compare decoded flat decisions, preserving exact strings and numeric types."""
    if not isinstance(value, dict) or any(type(v) not in (str, int) for v in value.values()):
        raise acceptance.DriverError("model/action evidence is not a flat decision object")
    if any(not isinstance(value.get(key), str) for key in ("action", "observation_id", "package")):
        raise acceptance.DriverError("model/action identity fields are missing")
    normalized = dict(value)
    if "reason" in normalized:
        if not isinstance(normalized["reason"], str):
            raise acceptance.DriverError("decision reason is not a string")
        # ActionDecision retains an empty default reason; answerJson omits it.
        # No action field, Unicode text or nonempty reason is otherwise changed.
        if normalized["reason"] == "": del normalized["reason"]
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _collected_bytes(directory, relative, entries):
    """Read exact collected bytes; a cached verified flag cannot mask a changed file."""
    path = directory / relative
    if any(parent.is_symlink() for parent in (path, *path.parents) if parent != directory.parent):
        raise acceptance.DriverError("warm evidence path is a symlink")
    selected = [entry for entry in entries if isinstance(entry, dict) and entry.get("path") == relative]
    if len(selected) != 1:
        raise acceptance.DriverError("warm evidence must have one exact collection hash: " + relative)
    data = path.read_bytes(); entry = selected[0]
    if type(entry.get("bytes")) is not int or len(data) != entry["bytes"] or acceptance.digest(data) != entry.get("sha256"):
        raise acceptance.DriverError("warm evidence changed after collection: " + relative)
    return data


def _warm_task_model_binding(directory, run_id, current_native, owner):
    """Revalidate the whole owned generation from actual files before counting an effect."""
    collection = _evidence_object(directory / "collection.json")
    task_id, uid = collection.get("task_id"), collection.get("app_uid_expected")
    rows = collection.get("associated_runs")
    if (not isinstance(task_id, str) or not acceptance.HEX32.fullmatch(task_id) or owner.get("task_id") != task_id
            or type(uid) is not int or uid < 10000 or not isinstance(rows, list)
            or not all(isinstance(row, dict) for row in rows) or not collection_verified(collection)):
        raise acceptance.DriverError("warm action has no complete task/UID-bound collection")
    if not 1 <= len(rows) <= 64 or len({row.get("run_id") for row in rows}) != len(rows):
        raise acceptance.DriverError("warm collection contains duplicate or invalid request membership")
    records = []; selected = None
    for row in rows:
        identity = row.get("run_id")
        if not isinstance(identity, str) or not acceptance.HEX32.fullmatch(identity):
            raise acceptance.DriverError("invalid warm request directory identity")
        prefix = "runs/" + identity + "/"
        files = row.get("files")
        if not isinstance(files, list):
            raise acceptance.DriverError("missing warm request collection hashes")
        app = acceptance.strict_json(_collected_bytes(directory, prefix + "app-receipt.json", files))
        native = acceptance.strict_json(_collected_bytes(directory, prefix + "native-result.json", files))
        raw = _collected_bytes(directory, prefix + "raw-text.txt", files)
        raw.decode("utf-8", "strict")
        for name in ("prompt.txt", "system.txt", "grammar.gbnf"):
            _collected_bytes(directory, prefix + name, files)
        if not (isinstance(app, dict) and isinstance(native, dict) and app.get("schema") == APP_REQUEST
                and app.get("run_id") == identity and app.get("package_name") == acceptance.PACKAGE
                and type(app.get("app_uid")) is int and app["app_uid"] == uid
                and type(app.get("app_pid")) is int and app["app_pid"] > 0
                and type(app.get("expected_parent_pid")) is int and app["expected_parent_pid"] == app["app_pid"]
                and app.get("parent_death_guard_requested") is True
                and app.get("parent_death_guard_is_cleanup_proof") is False
                and request_contract(app, native, task_id)
                and type(native.get("raw_text_bytes")) is int and native["raw_text_bytes"] == len(raw)
                and native.get("raw_text_sha256") == acceptance.digest(raw) == app.get("raw_text_sha256_read")
                and native.get("raw_text_utf8") is True and native.get("raw_text_truncated") is False
                and "error" in native and native["error"] is None):
            raise acceptance.DriverError("warm request, parent/UID or raw-output contract differs")
        records.append((app, native))
        if identity == run_id:
            if native != current_native:
                raise acceptance.DriverError("current action's native result changed during binding")
            selected = app
    if selected is None:
        raise acceptance.DriverError("current model run is not a member of the warm task")
    generation = selected["worker_generation"]
    sessions = collection.get("task_model_sessions")
    if (not isinstance(sessions, list) or len(sessions) != 1 or not isinstance(sessions[0], dict)
            or sessions[0].get("worker_generation") != generation):
        raise acceptance.DriverError("warm task has no unique collected worker generation")
    session_files = sessions[0].get("files")
    if not isinstance(session_files, list):
        raise acceptance.DriverError("warm task has no terminal file hashes")
    prefix = "runs/" + generation + "/"
    terminal_bytes = _collected_bytes(directory, prefix + "app-session-receipt.json", session_files)
    app_terminal = acceptance.strict_json(terminal_bytes)
    native_terminal = acceptance.strict_json(_collected_bytes(directory, prefix + "native-session-result.json", session_files))
    _collected_bytes(directory, prefix + "stderr.log", session_files)
    final = _evidence_object(directory / "task" / "result.json")
    digest = acceptance.digest(terminal_bytes)
    if not session_contract(app_terminal, native_terminal, digest, final, records, task_id, uid):
        raise acceptance.DriverError("warm action lacks actual complete task-session terminal binding")
    return {"task_session_binding_valid": True, "worker_generation": generation,
        "task_id": task_id, "worker_pid": selected["worker_pid"], "app_uid": uid,
        "app_session_receipt_sha256": digest}


def model_action_binding(directory, path, receipt, before, instruction_sha256=None):
    """Independently tie one dispatched action to its exact collected native output.

    Incomplete/contradictory evidence cannot qualify an effect. It does not prove
    a failed phone action or make an otherwise known submission count unknown.
    """
    result = {"verified": False, "action_receipt": str(path.relative_to(directory))}
    try:
        if receipt.get("model_issued") is not True:
            raise acceptance.DriverError("action lacks model_issued=true")
        run_id = receipt.get("model_run_id")
        if not isinstance(run_id, str) or not acceptance.HEX32.fullmatch(run_id):
            raise acceptance.DriverError("action has no exact model run identity")
        result["model_run_id"] = run_id
        match = re.fullmatch(r"(step-[0-9]{2})-action\.json", path.name)
        if not match:
            raise acceptance.DriverError("invalid action step filename")
        prefix = match.group(1)
        selected = []
        for model_path in sorted(path.parent.glob(prefix + "-model-*.json")):
            if not re.fullmatch(re.escape(prefix) + r"-model-[01]\.json", model_path.name):
                raise acceptance.DriverError("invalid model attempt filename for action step")
            model = _evidence_object(model_path)
            if model.get("run_id") == run_id: selected.append((model_path, model))
        if len(selected) != 1:
            raise acceptance.DriverError("action must match exactly one model attempt from the same step")
        model_path, model = selected[0]
        if model.get("observation_id") != before.get("observation_id"):
            raise acceptance.DriverError("step model receipt uses a different observation")
        owner = _evidence_object(directory / "task" / "owner.json")
        instruction = owner.get("instruction")
        if not isinstance(instruction, str):
            raise acceptance.DriverError("original task instruction evidence is missing")
        owner_sha = acceptance.digest(instruction.encode("utf-8"))
        if (owner.get("instruction_utf8_sha256") != owner_sha
                or model.get("original_instruction_sha256") != owner_sha
                or instruction_sha256 is not None and instruction_sha256 != owner_sha):
            raise acceptance.DriverError("model/action original instruction binding differs")
        run_directory = directory / "runs" / run_id
        raw_path = run_directory / "raw-text.txt"
        if raw_path.is_symlink(): raise acceptance.DriverError("native raw output is a symlink")
        raw = raw_path.read_bytes()
        if not 0 < len(raw) <= 16384:
            raise acceptance.DriverError("native action output exceeds controller bounds")
        raw.decode("utf-8", "strict")
        recorded_raw = model.get("raw_text")
        if not isinstance(recorded_raw, str) or recorded_raw.encode("utf-8") != raw:
            raise acceptance.DriverError("step model output differs from collected native raw bytes")
        native_path = run_directory / "native-result.json"
        native = _evidence_object(native_path)
        raw_sha = acceptance.digest(raw)
        if (native.get("request_id") != run_id
                or native.get("raw_text_sha256") != raw_sha
                or type(native.get("raw_text_bytes")) is not int or native["raw_text_bytes"] != len(raw)
                or native.get("generation_complete") is not True or native.get("raw_text_utf8") is not True
                or native.get("raw_text_truncated") is not False or "error" not in native or native["error"] is not None):
            raise acceptance.DriverError("native result does not bind this complete model output")
        if native.get("schema") == NATIVE_REQUEST:
            result.update(_warm_task_model_binding(directory, run_id, native, owner))
        elif native.get("schema") != "hepta.geniex-once.result.v1":
            raise acceptance.DriverError("unsupported native result schema for an effect")
        elif any(key in native for key in ("worker_generation", "task_id", "request_sequence")):
            raise acceptance.DriverError("task-worker evidence cannot use the one-shot schema")
        generated_action = acceptance.strict_json(raw)
        if _action_identity(generated_action) != _action_identity(receipt["action"]):
            raise acceptance.DriverError("dispatched action differs from the model's exact decoded decision")
        result.update(verified=True, step_model_receipt=str(model_path.relative_to(directory)),
                      native_raw_output=str(raw_path.relative_to(directory)),
                      native_result=str(native_path.relative_to(directory)), raw_text_sha256=raw_sha)
    except (acceptance.DriverError, OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        result["reason"] = str(error)
    return result


def action_sequence(directory, required, instruction_sha256=None):
    """Check dispatched effects bound to actual model output and UI observations."""
    actual, missing, bindings = [], [], []
    seen_runs = set()
    for path in sorted((directory / "task").glob("step-*-action.json")):
        try:
            value = _evidence_object(path)
        except (acceptance.DriverError, OSError, ValueError, TypeError, RecursionError) as error:
            missing.append(str(path.relative_to(directory)) + ": invalid action receipt: " + str(error))
            continue
        action = value.get("action")
        if value.get("accepted") is not True or value.get("dispatched") is not True or value.get("stale") is not False:
            continue
        if not isinstance(action, dict):
            missing.append(str(path.relative_to(directory)) + ": missing dispatched action object")
            continue
        if action.get("action") not in EFFECTS:
            missing.append(str(path.relative_to(directory)) + ": non-effect action claimed as dispatched")
            continue
        after_path = path.with_name(path.name.replace("-action.json", "-after.json"))
        before_path = path.with_name(path.name.replace("-action.json", "-before.json"))
        if not after_path.is_file() or not before_path.is_file():
            missing.append(str(path.relative_to(directory)) + ": missing before/after observation")
            continue
        try:
            before = _evidence_object(before_path)
            after = _evidence_object(after_path)
        except (acceptance.DriverError, OSError, ValueError, TypeError, RecursionError) as error:
            missing.append(str(path.relative_to(directory)) + ": invalid observation evidence: " + str(error))
            continue
        if action.get("observation_id") != before.get("observation_id") or not isinstance(before.get("observation_id"), str) or not acceptance.HEX32.fullmatch(before["observation_id"]):
            missing.append(str(path.relative_to(directory)) + ": invalid before observation binding")
            continue
        if not isinstance(after.get("observation_id"), str) or not acceptance.HEX32.fullmatch(after["observation_id"]):
            missing.append(str(path.relative_to(directory)) + ": invalid after observation")
            continue
        binding = model_action_binding(directory, path, value, before, instruction_sha256)
        if binding["verified"] and binding["model_run_id"] in seen_runs:
            binding.update(verified=False, reason="model run reused by multiple dispatched action steps")
        bindings.append(binding)
        if not binding["verified"]:
            missing.append(str(path.relative_to(directory)) + ": " + binding["reason"])
            continue
        seen_runs.add(binding["model_run_id"])
        if action.get("action") == "open" and after.get("package") != action.get("package"):
            continue
        actual.append({"action": action.get("action"), "package": action.get("package"),
                       "package_after": after.get("package"), "source": str(path.relative_to(directory)),
                       "model_run_id": binding["model_run_id"], "model_binding_verified": True,
                       "raw_text_sha256": binding["raw_text_sha256"]})
    matched = 0
    for action in actual:
        if matched < len(required) and all(action.get(k) == v for k, v in required[matched].items()):
            matched += 1
    return {"passed": matched == len(required), "evidence_complete": not missing, "missing_evidence": missing, "required": required,
            "matched_in_order": matched, "observed_dispatched_actions": actual, "model_action_bindings": bindings}


def case_args(args, case, candidate, root):
    return SimpleNamespace(adb=args.adb, adb_host=args.adb_host, adb_port=args.adb_port, serial=args.serial,
        command_timeout=args.command_timeout, case_id=case["case_id"], instruction=case["instruction"],
        evidence_root=root / "cases", expected_package=case["expected_package"],
        expected_visible_text=case["expected_visible_text"], expected_compute=candidate["compute"],
        expected_context=candidate["context_tokens"], expected_model_profile=candidate.get("model_profile",DEFAULT_PROFILE),text_match=case["text_match"],
        timeout=case["timeout_seconds"], poll=2, stop_grace=25, setup_home=case["setup_home"], include_screenshots=False)


def summarize(report):
    counts = Counter(row["verdict"] for row in report["cases"])
    known_launches = sum(row.get("launch_attempt_count", 0) for row in report["cases"] if type(row.get("launch_attempt_count")) is int)
    unknown_launches = sum(row.get("launch_attempt_count") is None for row in report["cases"])
    report["counts"] = {k: counts.get(k, 0) for k in ("pass", "fail", "unverified", "not_run", "unknown")}
    report["known_launch_attempts"] = known_launches
    report["unknown_submission_outcomes"] = unknown_launches
    report["actual_launches"] = None if unknown_launches else known_launches
    report["planned_attempts"] = len(report["cases"])
    report["completion_status"] = "incomplete" if counts.get("not_run") or counts.get("unknown") else "complete"
    report["suite_verdict"] = "fail" if counts.get("fail") else "pass" if counts.get("pass") == len(report["cases"]) else "incomplete" if report["completion_status"] == "incomplete" else "unverified"
    report["full_phone_acceptance"] = "not_assessed"
    report["unassessed_coverage"] = UNASSESSED
    return report


def run_suite(args, plan, plan_bytes):
    validate_plan(plan, require_runnable=True)  # Before mkdir or any phone command.
    root = args.output.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    acceptance.private_write(root / "plan.json", plan_bytes)
    report = {"schema": "hepta.phone-suite-result.v1", "suite_id": plan["suite_id"],
        "plan_sha256": acceptance.digest(plan_bytes), "candidate": plan["candidate"],
        "driver_sha256": acceptance.digest(Path(__file__).read_bytes()),
        "case_driver_sha256": acceptance.digest(Path(acceptance.__file__).read_bytes()),
        "automatic_retry": False, "device_serial": args.serial, "adb_port": args.adb_port,
        "cases": [{"case_id": c["case_id"], "verdict": "not_run", "launch_attempt_count": 0} for c in plan["cases"]],
        "errors": [], "started_host_wall_ms": int(time.time() * 1000)}
    candidate = plan["candidate"]
    try:
        report["existing_server"] = require_existing_adb_server(args, root)
        report["preflight"] = preflight(acceptance.Adb(args, root / "preflight"), candidate)
        acceptance.write_json(root / "suite-result.json", summarize(report))
        for index, case in enumerate(plan["cases"]):
            started = time.monotonic()
            row = report["cases"][index]
            # Recheck the frozen identity before each independent submission.
            # A lost server or changed package leaves this and later cases not_run.
            row["existing_server"] = require_existing_adb_server(args, root, phase="case-%03d" % index)
            row["preflight"] = preflight(acceptance.Adb(args, root / ("preflight-%03d" % index)), candidate)
            row["verdict"] = "unknown"  # Persist before submission; never assume a lost result means no action.
            row["launch_attempt_count"] = None
            acceptance.write_json(root / "suite-result.json", summarize(report))
            try:
                code = acceptance.run_task(case_args(args, case, candidate, root))
                directory = root / "cases" / case["case_id"]
                raw = (directory / "acceptance.json").read_bytes()
                evidence = acceptance.strict_json(raw)
                if evidence.get("case_id") != case["case_id"] or evidence.get("instruction_sha256") != acceptance.digest(case["instruction"].encode("utf-8")):
                    raise acceptance.DriverError("case receipt does not bind this planned instruction")
                if type(evidence.get("launch_attempt_count")) is not int or evidence["launch_attempt_count"] not in (0, 1):
                    raise acceptance.DriverError("invalid launch attempt count")
                sequence = action_sequence(directory, case["required_actions"], evidence["instruction_sha256"])
                verdict = evidence.get("verdict")
                if verdict not in ("pass", "fail", "unverified"):
                    raise acceptance.DriverError("invalid case verdict")
                if verdict == "pass" and not sequence["evidence_complete"]:
                    verdict = "unverified"
                elif verdict == "pass" and not sequence["passed"]:
                    verdict = "fail"
                row.update(verdict=verdict, driver_exit_code=code, task_id=evidence.get("task_id"),
                    launch_attempt_count=evidence.get("launch_attempt_count", 0),
                    acceptance_sha256=acceptance.digest(raw), original_case_verdict=evidence.get("verdict"),
                    action_sequence=sequence, cleanup_unknown=evidence.get("cleanup_unknown") is not False,
                    elapsed_host_s=time.monotonic()-started)
                if row["cleanup_unknown"]:
                    report["errors"].append("cleanup unknown: no following case submitted")
                    break
            except (Exception, KeyboardInterrupt) as error:
                row.update(verdict="unknown", error=str(error), elapsed_host_s=time.monotonic()-started)
                report["errors"].append("case outcome unresolved; no replay or following case")
                break
            finally:
                acceptance.write_json(root / "suite-result.json", summarize(report))
    except (Exception, KeyboardInterrupt) as error:
        report["errors"].append(str(error))
    finally:
        report["finished_host_wall_ms"] = int(time.time() * 1000)
        acceptance.write_json(root / "suite-result.json", summarize(report))
    print(json.dumps({k: report[k] for k in ("suite_id", "suite_verdict", "counts", "actual_launches", "full_phone_acceptance", "errors")}, ensure_ascii=False, indent=2))
    return 0 if report["suite_verdict"] == "pass" else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    validate = sub.add_parser("validate", help="validate a plan without contacting ADB")
    validate.add_argument("plan", type=Path)
    run = sub.add_parser("run", help="run each frozen case exactly once")
    run.add_argument("plan", type=Path)
    run.add_argument("--adb", required=True)
    run.add_argument("--adb-host", default="127.0.0.1")
    run.add_argument("--adb-port", required=True, type=int)
    run.add_argument("--serial", required=True)
    run.add_argument("--output", required=True, type=Path)
    run.add_argument("--command-timeout", type=float, default=20)
    args = parser.parse_args()
    raw = args.plan.read_bytes()
    plan = acceptance.strict_json(raw)
    validation = validate_plan(plan)
    if args.operation == "validate":
        print(json.dumps(validation, ensure_ascii=False, indent=2))
        return 0
    if not 1 <= args.adb_port <= 65535 or not 1 <= args.command_timeout <= 120 or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", args.serial):
        parser.error("invalid explicit device identity or command timeout")
    return run_suite(args, plan, raw)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (acceptance.DriverError, OSError, ValueError) as error:
        print(json.dumps({"error": str(error), "no_automatic_retry": True}), file=sys.stderr)
        sys.exit(2)
