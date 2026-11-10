#!/usr/bin/env python3
"""Prepared, not phone-qualified: one ordinary-APK background calculator task.

Run on Pocket4 only after exact APK installation and visible Hepta UI preparation.
The only optional input injection is one screenshot-bound tap on Hepta's existing
Start button. Calculator actions must all come from the phone's local model.
No shell/root broker client, nonce trigger, receiver, scope edits, grants or retries.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import time
from types import ModuleType

PACKAGE = "org.trillionnium.hepta.local"
BROKER_ENTRY = "org.trillionnium.hepta.background.BackgroundDisplayBroker"
BROKER_PROCESS_ARGV0 = frozenset(("app_process", "app_process32", "app_process64",
    "/system/bin/app_process", "/system/bin/app_process32", "/system/bin/app_process64"))
INSTRUCTION = "打开计算器，计算 23 乘以 19，确认屏幕显示计算结果后结束任务。"
EXPECTED_RESULT = "437"  # Expected oracle only; never sent to the phone or model.
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
PINS = {
    "v35_identity": "a4a751cf03956783e551f54b16dd37769f00d5b7cd2a0225b667becbc6e6d003",
    "warm_receipts": "d5ab468b1b3155195d24b771376581dd441fd59a20b71feda98af4074fcaa3d5",
    "model_profiles": "9ba9403bdf64c2d765b31ffbbed2e95ac846f50df6ecb4e21efd4ebc926a397a",
    "phone_acceptance": "baa43b0379c25a7f7f8e03afc41ac1e92b4e1483462726d7eadc9d5a40f60f7a",
}


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def bad(value):
        raise ValueError("nonfinite JSON: " + value)
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=bad)


def checked_file(path, maximum=8 << 20):
    path = Path(path)
    need(path.is_absolute() and all(not p.is_symlink() for p in (path, *path.parents)),
         "absolute non-symlink input required: " + str(path))
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum, "invalid input size/type")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    def key(s):
        return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(len(raw) == before.st_size and key(before) == key(after) == key(path.stat()), "input changed while read")
    return raw


def write_new(path, value, binary=False):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    need(all(not p.is_symlink() for p in (path, *path.parents)), "output symlink refused")
    raw = value if binary else (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def load_pinned(name, path):
    need(name not in sys.modules, "preloaded helper refused: " + name)
    raw = checked_file(path)
    need(digest(raw) == PINS[name], "helper differs from reviewed bytes: " + name)
    module = ModuleType(name)
    module.__file__, module.__package__ = str(path), ""
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def text(adb, words, label, timeout=8):
    _, raw = adb.command(words, label=label, timeout=timeout)
    need(len(raw) <= 8 << 20, "system observation exceeded bound")
    return raw.decode("utf-8", errors="strict")


def bounded_private_reader(adb):
    """Keep collection bounded before bytes cross ADB, with the same guarded command."""
    def app_bytes(relative, *, optional=False):
        need(re.fullmatch(r"files/[A-Za-z0-9_./-]+", relative) and ".." not in relative.split("/"),
             "unsafe private evidence path")
        parts = relative.split("/")
        paths = ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]
        links = " || ".join("[ -L " + shlex.quote(p) + " ]" for p in paths)
        quoted = shlex.quote(relative)
        script = ("if " + links + "; then exit 41; fi; "
            "if [ ! -e " + quoted + " ]; then exit 40; fi; "
            "if [ ! -f " + quoted + " ]; then exit 41; fi; "
            "n=$(wc -c < " + quoted + ") || exit 42; "
            "case $n in ''|*[!0-9]*) exit 42;; esac; "
            "if [ \"$n\" -gt 16777216 ]; then exit 42; fi; head -c 16777217 " + quoted)
        code, raw = adb.command(["run-as", PACKAGE, "sh", "-c", script], label="bounded-app-evidence",
            allowed=(0, 40) if optional else (0,), raw=True)
        need(len(raw) <= 16 << 20, "private evidence grew beyond bound")
        return None if code == 40 else raw
    adb.app_bytes = app_bytes


def package_identity(adb, package, label):
    raw = text(adb, ["cmd", "package", "list", "packages", "-U", package], label + "-uid")
    found = re.findall(r"^package:" + re.escape(package) + r" uid:(\d+)\s*$", raw, re.M)
    need(len(found) == 1, "exact package UID unavailable: " + package)
    paths = text(adb, ["pm", "path", package], label + "-paths").splitlines()
    need(paths and len(paths) <= 32 and all(p.startswith("package:/data/app/") or p.startswith("package:/system/")
         or p.startswith("package:/product/") or p.startswith("package:/system_ext/") for p in paths), "unrecognized APK path")
    apks = []
    for index, line in enumerate(paths):
        path = line[len("package:"):]
        need(path.endswith(".apk") and "\n" not in path, "invalid APK path")
        hashed = text(adb, ["sha256sum", path], label + "-apk-" + str(index)).strip()
        match = re.fullmatch(r"([0-9a-f]{64})\s+(.+)", hashed)
        need(match is not None and match.group(2) == path, "APK digest output differs")
        apks.append({"path": path, "sha256": match.group(1)})
    return {"package": package, "uid": int(found[0]), "apks": sorted(apks, key=lambda x: x["path"])}


def parse_displays(raw):
    rows = {}
    for match in re.finditer(r"^\s*Display id (\d+):\s*(.+)$", raw, re.M):
        number, description = int(match.group(1)), match.group(2)
        need(number not in rows, "duplicate display enumeration")
        name = re.search(r'DisplayInfo\{"([^"]+)"', description)
        need(name is not None, "display name unavailable")
        rows[number] = {"name": name.group(1), "description": description}
    need(0 in rows, "unsupported cmd display get-displays format; no empty-set fallback")
    return rows


def display_blocks(raw, pattern):
    headings = list(re.finditer(pattern, raw, re.M))
    need(headings, "system display headings unavailable")
    result = {}
    for index, heading in enumerate(headings):
        number = int(heading.group(1))
        need(number not in result, "ambiguous display heading")
        result[number] = raw[heading.end():headings[index + 1].start() if index + 1 < len(headings) else len(raw)]
    need(0 in result, "main display absent from system dump")
    return result


def system_snapshot(adb, directory, index, target):
    started = time.monotonic()
    displays_raw = text(adb, ["cmd", "display", "get-displays"], "displays")
    windows_raw = text(adb, ["dumpsys", "window", "displays"], "window-displays")
    inputs_raw = text(adb, ["dumpsys", "input"], "input-dispatcher")
    tasks_raw = text(adb, ["dumpsys", "activity", "activities"], "activity-displays")
    processes_raw = text(adb, ["ps", "-A", "-o", "UID,PID,PPID,ARGS"], "process-uid")
    row = {"index": index, "started_monotonic_s": started, "ended_monotonic_s": time.monotonic(), "errors": []}
    try:
        row["displays"] = parse_displays(displays_raw)
        windows = display_blocks(windows_raw, r"^\s*Display: mDisplayId=(\d+)\b[^\n]*$")
        focus = re.findall(r"^\s*mCurrentFocus=(.+)$", windows[0], re.M)
        focused_display = re.findall(r"^\s*FocusedDisplayId:\s*(\d+)\s*$", inputs_raw, re.M)
        need(len(focus) == 1 and len(focused_display) == 1, "focus observation unavailable/ambiguous")
        row.update(main_focus=focus[0].strip(), input_focused_display=int(focused_display[0]))
        tasks = display_blocks(tasks_raw, r"^\s*Display #(\d+)\b[^\n]*$")
        row["target_task_displays"] = sorted(number for number, body in tasks.items() if target + "/" in body)
        row["task_display_ids"] = sorted(tasks)
        processes = []
        for line in processes_raw.splitlines()[1:]:
            fields = line.split(None, 3)
            need(len(fields) == 4 and all(v.isdigit() for v in fields[:3]), "unsupported numeric ps format")
            processes.append({"uid": int(fields[0]), "pid": int(fields[1]), "ppid": int(fields[2]), "args": fields[3]})
        row["processes"] = processes
    except Exception as error:
        row["errors"].append(str(error))
    write_new(directory / "system" / ("sample-%04d.json" % index), row)
    return row


def state(adb):
    return adb.app_json("files/control-session.json") or {}


def active(value):
    return value.get("running") is True or value.get("pending") is True


def broker_process_identity(process, generation, owner_uid, target_package):
    """Classify only a broker's own argv; command text inside su/sh is not identity.

    ps ARGS is an observation of argv, not an executable-file attestation. Unknown
    vendor encodings fail closed. The source client supplies exactly six pairs;
    all session values below must match, including an exact --generation token.
    """
    if (not isinstance(process, dict) or type(process.get("pid")) is not int or process["pid"] <= 0
            or type(process.get("uid")) is not int or process["uid"] < 0
            or type(owner_uid) is not int or not 10000 <= owner_uid < 90000
            or not isinstance(generation, str) or UUID.fullmatch(generation) is None
            or not isinstance(target_package, str)):
        return None
    command = process.get("args")
    if not isinstance(command, str) or not 1 <= len(command) <= 16384:
        return None
    try:
        words = shlex.split(command)
    except ValueError:
        return None
    if not words:
        return None
    if words[0] in BROKER_PROCESS_ARGV0:
        if len(words) < 3 or words[1] != "/" or words[2] != BROKER_ENTRY:
            return None
        pairs = words[3:]
    elif words[0] == BROKER_ENTRY:
        # An explicitly named Java argv0 is accepted only with complete exact
        # session flags. A bare renamed/truncated argv0 does not prove generation.
        pairs = words[1:]
    else:
        # In particular, never select su, sh, bash, env, timeout or their paths
        # merely because an embedded -c argument names this broker.
        return None
    keys = {"--socket", "--owner-uid", "--generation", "--allowed-packages", "--ttl-ms", "--expires-elapsed-ms"}
    if len(pairs) != 2 * len(keys):
        return None
    options = {}
    for index in range(0, len(pairs), 2):
        key, value = pairs[index:index + 2]
        if key not in keys or key in options:
            return None
        options[key] = value
    if (set(options) != keys or options["--generation"] != generation
            or options["--socket"] != "hepta-bg-" + generation
            or options["--owner-uid"] != str(owner_uid)
            or options["--allowed-packages"] != target_package
            or options["--ttl-ms"] != "540000"
            or re.fullmatch(r"[1-9][0-9]{0,15}", options["--expires-elapsed-ms"]) is None):
        return None
    return {"pid": process["pid"], "uid": process["uid"], "argv0": words[0], "generation": generation}


def broker_process_summary(processes, generation, owner_uid, target_package):
    """Repeated samples of one PID are expected; launcher wrappers never count."""
    identities = [identity for process in processes
        if (identity := broker_process_identity(process, generation, owner_uid, target_package)) is not None]
    pids = sorted({identity["pid"] for identity in identities})
    rows = sorted({(identity["pid"], identity["uid"], identity["argv0"]) for identity in identities})
    return {"verified": len(pids) == 1 and bool(identities) and all(identity["uid"] in (0, 2000) for identity in identities),
        "pids": pids, "matched_sample_count": len(identities),
        "identities": [{"pid": pid, "uid": uid, "argv0": argv0} for pid, uid, argv0 in rows],
        "identity_scope": "system ps UID/PID and exact argv0/class/flag-value tokens; not an executable-byte attestation"}


def collect_and_assess(adb, acceptance, receipts, args, report, samples, session, baseline_runs, uid, config):
    task = session.get("task_id")
    need(isinstance(task, str) and HEX32.fullmatch(task), "no fresh bound task ID")
    collection = acceptance.collect_evidence(adb, args.out / "evidence", task, INSTRUCTION,
        baseline_runs, True, uid, config["compute"], config["context_tokens"], config["model_profile"])
    report["collection"] = collection
    directory = args.out / "evidence" / "task"
    def read(name):
        value = strict(checked_file(directory / name))
        need(isinstance(value, dict), "task evidence must be object")
        return value
    owner, result, bootstrap, cleanup = (read(name) for name in
        ("owner.json", "result.json", "background-bootstrap.json", "background-cleanup.json"))
    selection = {"mode": "background", "allowed_packages": [args.target_package],
        "bootstrap_package": args.target_package, "bootstrap_source": "owner_selected_initial_app",
        "bootstrap_model_issued": False, "main_display_fallback": False, "home_allowed": False}
    generation, display_id = bootstrap.get("generation"), bootstrap.get("display_id")
    need(isinstance(generation, str) and UUID.fullmatch(generation), "invalid generation")
    need(type(display_id) is int and display_id > 0, "background display missing")
    display_name = "hepta-bg-" + generation
    owner_bound = (owner.get("task_id") == task and owner.get("instruction") == INSTRUCTION
        and owner.get("instruction_utf8_sha256") == digest(INSTRUCTION.encode())
        and owner.get("background_request") == selection and owner.get("external_model") is False
        and owner.get("expected_scope_sha256") is None and owner.get("actual_scope_sha256") is None
        and session.get("origin") == "user_button" and session.get("debug_nonce_sha256") is None)
    bootstrap_bound = (bootstrap.get("task_id") == task and bootstrap.get("app_uid") == uid
        and bootstrap.get("owner_sha256") == digest(INSTRUCTION.encode())
        and bootstrap.get("selection") == selection and bootstrap.get("display_name") == display_name
        and bootstrap.get("bootstrap_dispatched") is True and bootstrap.get("bootstrap_model_issued") is False)
    observations, actions, invalid_actions, effect_count, open_count = {}, [], [], 0, 0
    result_transition = False
    def has_result(observation):
        return any(node.get("view_id") == args.result_view_id and node.get("text", "").strip() == EXPECTED_RESULT
            for node in observation.get("nodes", []))
    associated = {row["run_id"] for row in collection.get("associated_runs", [])}
    for path in sorted(directory.glob("step-*-before.json")) + sorted(directory.glob("step-*-after.json")):
        observation = read(path.name)
        observations[observation.get("observation_id")] = observation
    for path in sorted(directory.glob("step-*-action.json")):
        action = read(path.name)
        decision = action.get("action", {})
        run = action.get("model_run_id")
        bound = run in associated and action.get("model_issued") is True
        if bound:
            raw_action = strict(checked_file(args.out / "evidence" / "runs" / run / "raw-text.txt"))
            prompt = checked_file(args.out / "evidence" / "runs" / run / "prompt.txt").decode("utf-8")
            bound = (isinstance(raw_action, dict) and all(raw_action.get(k) == v for k, v in decision.items())
                and acceptance.prompt_binding(prompt, INSTRUCTION, {decision.get("observation_id")}))
        before = observations.get(decision.get("observation_id"), {})
        bg = before.get("background_session", {})
        bound = (bound and bg.get("generation") == generation and bg.get("display_id") == display_id
            and before.get("window", {}).get("display_id") == display_id and before.get("package") == args.target_package
            and decision.get("package") == args.target_package and decision.get("action") != "home"
            and action.get("background_session", {}).get("generation") == generation)
        if not bound:
            invalid_actions.append(path.name)
        if bound and action.get("accepted") is True and action.get("dispatched") is True:
            if decision.get("action") in ("click", "type", "scroll", "back"):
                effect_count += 1
                after_path = directory / path.name.replace("-action.json", "-after.json")
                if after_path.is_file():
                    after = read(after_path.name)
                    result_transition = result_transition or (not has_result(before) and has_result(after)
                        and after.get("package") == args.target_package
                        and after.get("window", {}).get("display_id") == display_id
                        and after.get("background_session", {}).get("generation") == generation)
            if decision.get("action") == "open":
                open_count += 1
        actions.append({"file": path.name, "action": decision.get("action"), "run_id": run,
            "accepted": action.get("accepted"), "dispatched": action.get("dispatched"), "model_binding_valid": bound})
    final = observations.get(result.get("final_observation_id"), {})
    result_nodes = [node for node in final.get("nodes", []) if node.get("view_id") == args.result_view_id
        and node.get("text", "").strip() == EXPECTED_RESULT]
    png = directory / (str(final.get("observation_id")) + ".png")
    screen_bound = png.is_file() and digest(checked_file(png, 16 << 20)) == final.get("screen_sha256")
    goal_bound = (final.get("package") == args.target_package and final.get("window", {}).get("display_id") == display_id
        and final.get("background_session", {}).get("generation") == generation and len(result_nodes) == 1
        and screen_bound and result_transition)
    clean_samples = [row for row in samples if not row["errors"]]
    active_samples = [row for row in clean_samples if row.get("displays", {}).get(display_id, {}).get("name") == display_name]
    focus_ok = (len(clean_samples) == len(samples) and len(samples) >= 3
        and all(row.get("main_focus") == samples[0].get("main_focus") and row.get("input_focused_display") == 0 for row in samples))
    isolated = (bool(active_samples) and any(row.get("target_task_displays") == [display_id] for row in active_samples)
        and all(set(row.get("target_task_displays", [])) <= {display_id} for row in clean_samples))
    final_system_absent = (len(samples) >= 2 and all(not row["errors"] and display_id not in row.get("displays", {})
        and all(display.get("name") != display_name for display in row.get("displays", {}).values())
        and display_id not in row.get("task_display_ids", []) for row in samples[-2:]))
    broker_processes = broker_process_summary([p for row in active_samples for p in row.get("processes", [])],
        generation, uid, args.target_package)
    broker_identity = broker_processes["verified"]
    display_policy_ok = (bool(active_samples)
        and all(all(flag in row["displays"][display_id]["description"] for flag in
            ("FLAG_TRUSTED", "FLAG_OWN_FOCUS", "FLAG_STEAL_TOP_FOCUS_DISABLED"))
            and not any(flag in row["displays"][display_id]["description"] for flag in ("FLAG_SECURE", "FLAG_ALWAYS_UNLOCKED"))
            for row in active_samples))
    bootstrap_response = bootstrap.get("last_broker_response", {})
    display_policy_ok = (display_policy_ok and bootstrap_response.get("state") == "ACTIVE"
        and bootstrap_response.get("generation") == generation and bootstrap_response.get("display_id") == display_id
        and bootstrap_response.get("width") == 720 and bootstrap_response.get("height") == 1280
        and bootstrap_response.get("density") == 240 and bootstrap_response.get("capture_secure") is False
        and bootstrap_response.get("always_unlocked") is False and bootstrap_response.get("ime_policy") == "hide")
    model_pids = set()
    model_owner_prompts_bound = bool(collection.get("associated_runs"))
    for row in collection.get("associated_runs", []):
        receipt = strict(checked_file(args.out / "evidence" / "runs" / row["run_id"] / "app-receipt.json"))
        prompt = checked_file(args.out / "evidence" / "runs" / row["run_id"] / "prompt.txt").decode("utf-8")
        model_owner_prompts_bound = model_owner_prompts_bound and acceptance.prompt_binding(prompt, INSTRUCTION, set(observations))
        if type(receipt.get("worker_pid")) is int:
            model_pids.add(receipt["worker_pid"])
    actual_model_processes = [p for row in samples for p in row.get("processes", []) if p["pid"] in model_pids]
    model_uid_ok = (bool(model_pids) and all(any(p["pid"] == pid and p["uid"] == uid
        and "libhepta_local_runner.so" in p["args"] for p in actual_model_processes) for pid in model_pids)
        and all(p["uid"] == uid for p in actual_model_processes))
    last = cleanup.get("last_broker_response", {})
    journal_absent = adb.app_bytes("files/background-session.active.json", optional=True) is None
    cleanup_ok = (cleanup.get("generation") == generation and cleanup.get("task_id") == task
        and cleanup.get("state") == "RELEASED" and cleanup.get("cleanup_known") is True
        and cleanup.get("retired") is True and last.get("generation") == generation
        and last.get("ok") is True and last.get("state") == "RELEASED"
        and cleanup.get("broker_process_exit_observed") is True and cleanup.get("broker_process_exit_code") == 0
        and journal_absent and final_system_absent and result.get("cleanup_known") is True
        and session.get("cleanup_known") is True and not active(session) and session.get("blocked") is False)
    report["acceptance"] = {
        "owner_and_visible_button_bound": owner_bound, "owner_selected_bootstrap_bound": bootstrap_bound,
        "bootstrap_model_issued": False, "model_issued_effect_count": effect_count,
        "model_issued_open_count": open_count, "model_issued_app_discovery_qualified": False,
        "actions": actions, "invalid_action_bindings": invalid_actions,
        "local_accelerator_inference_verified": not collection.get("errors") and receipts.collection_verified(collection),
        "all_model_owner_prompts_bound": model_owner_prompts_bound,
        "ordinary_uid_model_process_observed": model_uid_ok, "root_or_shell_broker_process_observed": broker_identity,
        "broker_process_identity": broker_processes,
        "calculator_result_node_verified": goal_bound, "expected_result": EXPECTED_RESULT,
        "model_action_result_transition_observed": result_transition,
        "result_view_id": args.result_view_id, "result_observation_id": final.get("observation_id"),
        "result_screenshot_hash_verified": screen_bound, "visual_screenshot_reviewed": False,
        "sampled_main_focus_unchanged": focus_ok, "target_task_only_on_owned_display": isolated,
        "display_policy_readback_verified": display_policy_ok, "broker_display_flags": bootstrap_response.get("flags"),
        "cleanup_confirmed_by_app_broker_and_system": cleanup_ok, "journal_absent": journal_absent,
        "broker_process_exit_observed": cleanup.get("broker_process_exit_observed"),
        "broker_process_exit_code": cleanup.get("broker_process_exit_code"),
        "generation": generation, "display_id": display_id, "display_name": display_name,
        "sample_count": len(samples), "active_display_samples": len(active_samples),
        "maximum_sample_start_gap_s": max((b["started_monotonic_s"] - a["started_monotonic_s"]
            for a, b in zip(samples, samples[1:])), default=None),
        "maximum_sample_duration_s": max((x["ended_monotonic_s"] - x["started_monotonic_s"] for x in samples), default=None),
        "focus_claim_scope": "sampled points only; sequential dumps are not atomic and do not prove zero transient interference",
        "controller_status": result.get("status"), "controller_model_reported_success": result.get("model_reported_success"),
    }
    report["qualified"] = all((owner_bound, bootstrap_bound, bool(actions), not invalid_actions, effect_count > 0,
        report["acceptance"]["local_accelerator_inference_verified"], model_owner_prompts_bound, model_uid_ok, broker_identity, goal_bound,
        focus_ok, isolated, display_policy_ok, cleanup_ok, result.get("status") == "model_reported_done",
        result.get("model_reported_success") is True, result.get("external_model") is False))


def execute(args, report):
    identity = load_pinned("v35_identity", args.identity_helper)
    receipts = load_pinned("warm_receipts", args.source_tools / "warm_receipts.py")
    profiles = load_pinned("model_profiles", args.source_tools / "model_profiles.py")
    acceptance = load_pinned("phone_acceptance", args.source_tools / "phone_acceptance.py")
    expected_config = checked_file(args.runtime_config, 4096)
    config = strict(expected_config)
    need(isinstance(config, dict) and config.get("compute") in ("gpu", "npu"), "GPU/NPU config required")
    selected = profiles.profile(config.get("model_profile"))
    need(type(config.get("context_tokens")) is int and config["context_tokens"] in (4096, 8192), "unsupported context")
    report.update(runtime_config_sha256=digest(expected_config), model_profile=config["model_profile"],
        expected_model_sha256=selected["sha256"], compute=config["compute"], helper_pins=PINS)
    with identity.operation_lock(report):
        adb = identity.guard_adb(acceptance.Adb(args, args.out))
        bounded_private_reader(adb)
        # All file reads and observations below pass the same still-held readonly lock fd.
        hepta_before = package_identity(adb, PACKAGE, "before-hepta")
        need(hepta_before["uid"] == args.expected_uid and 10000 <= args.expected_uid < 90000, "ordinary APK UID differs")
        need(len(hepta_before["apks"]) == 1 and hepta_before["apks"][0]["sha256"] == args.apk_sha256, "installed exact APK differs")
        need(text(adb, ["run-as", PACKAGE, "id", "-u"], "run-as-uid").strip() == str(args.expected_uid), "private reader UID differs")
        target_before = package_identity(adb, args.target_package, "before-calculator")
        report["installed_identity_before"] = {"hepta": hepta_before, "calculator": target_before}
        need(adb.app_bytes("files/model/runtime-config.json") == expected_config, "runtime config bytes differ")
        scope = adb.app_bytes("files/qualification-scope.json", optional=True)
        report["qualification_scope_present"] = scope is not None
        if scope is not None:
            report["qualification_scope_sha256"] = digest(scope)
            raise RuntimeError("existing qualification scope blocks background UI; preserved unchanged")
        need(text(adb, ["am", "get-current-user"], "current-android-user").strip() == "0", "only current Android user 0 is covered")
        enabled = text(adb, ["settings", "get", "secure", "enabled_accessibility_services"], "enabled-accessibility").strip().split(":")
        expected_service = PACKAGE + "/" + PACKAGE + ".HeptaAccessibilityService"
        expanded = [value.split("/", 1)[0] + "/" + (value.split("/", 1)[0] + value.split("/", 1)[1]
            if value.split("/", 1)[1].startswith(".") else value.split("/", 1)[1]) for value in enabled if "/" in value]
        report["formal_hepta_accessibility_enabled"] = expected_service in expanded
        need(report["formal_hepta_accessibility_enabled"], "formal Hepta accessibility service is disabled; no settings changed")
        accessibility = text(adb, ["dumpsys", "accessibility"], "accessibility-bound-state")
        bound_sections = re.findall(r"\bBound services:\{(.*?)\}\s*Enabled services:\{", accessibility, re.S)
        service_names = (expected_service, PACKAGE + "/.HeptaAccessibilityService")
        report["formal_hepta_accessibility_bound"] = any(re.search(re.escape(name) + r"(?=[,\]\s}])", block)
            for block in bound_sections for name in service_names)
        need(report["formal_hepta_accessibility_bound"], "formal Hepta service binding not independently readable; no UI trigger sent")
        need(adb.app_bytes("files/background-session.active.json", optional=True) is None, "unreleased background journal blocks new task")
        baseline = state(adb)
        need(not active(baseline) and baseline.get("blocked") is not True, "existing task/recovery is not idle")
        need(not baseline or baseline.get("cleanup_known") is True, "old cleanup state unknown")
        need(adb.app_bytes("files/control-session.interrupted.json", optional=True) is None, "interruption latch requires normal owner recovery")
        baseline_runs = set(adb.list_children("files/runs", directories=True))
        baseline_tasks = set(adb.list_children("files/control-tasks", directories=True))
        samples = [system_snapshot(adb, args.out, 0, args.target_package)]
        report["baseline_session"] = baseline
        need(not samples[0]["errors"], "system baseline could not be parsed; inspect retained raw commands")
        need(PACKAGE + "/" in samples[0].get("main_focus", "") and samples[0].get("input_focused_display") == 0,
             "Hepta must already be visible on main display")
        need(not samples[0].get("target_task_displays"), "calculator already has a task; close it normally before a new test")
        need(not any(x["name"].startswith("hepta-bg-") for x in samples[0]["displays"].values()), "existing Hepta display blocks new test")
        _, screen = adb.command(["screencap", "-p"], label="prepared-main-screen", raw=True, timeout=8)
        need(screen.startswith(b"\x89PNG\r\n\x1a\n") and len(screen) <= 16 << 20, "prepared screen capture invalid")
        write_new(args.out / "prepared-main.png", screen, binary=True)
        report["prepared_screen_sha256"] = digest(screen)
        if args.start_tap:
            need(digest(screen) == args.prepared_screen_sha256, "current screenshot differs from visually reviewed Start-button proof")
            x, y = args.start_tap
            # No calculator input, HOME, target launch, shell calculation or direct broker IPC.
            adb.command(["input", "-d", "0", "tap", str(x), str(y)], label="existing-visible-hepta-start-button", timeout=3)
            report["trigger"] = {"kind": "one_screenshot_bound_start_tap", "coordinates": [x, y], "auto_task": False}
        else:
            report["trigger"] = {"kind": "owner_taps_existing_visible_start_button", "auto_task": False}
            print("ARMED: tap Hepta's existing visible 开始任务 button once. Do not start another ADB operator or interact with Calculator.", flush=True)
        armed = time.monotonic()
        running_started = None
        task = None
        latest = baseline
        while time.monotonic() - (running_started or armed) < (args.timeout if task else args.start_window):
            samples.append(system_snapshot(adb, args.out, len(samples), args.target_package))
            latest = state(adb)
            candidate = latest.get("task_id")
            fresh = isinstance(candidate, str) and HEX32.fullmatch(candidate) and candidate not in baseline_tasks
            if fresh and task is None:
                need(latest.get("instruction_sha256") == digest(INSTRUCTION.encode()) and latest.get("origin") == "user_button"
                    and latest.get("debug_nonce_sha256") is None, "new task is not the exact visible-owner calculator request")
                task, running_started = candidate, time.monotonic()
                report["task_id"] = task
            if task:
                need(candidate == task, "task identity changed; no retry permitted")
                if not active(latest) and latest.get("status") in acceptance.TERMINAL:
                    break
            time.sleep(args.interval)
        report["last_session"] = latest
        need(task is not None, "no fresh background task started in armed window")
        if active(latest):
            report["manual_visible_stop_required"] = True
            raise RuntimeError("task deadline reached; no guessed Stop, PID kill or cleanup success claim; use existing visible Stop")
        # Two complete post-terminal system observations; app flags alone cannot prove display release.
        for _ in range(2):
            time.sleep(args.interval)
            samples.append(system_snapshot(adb, args.out, len(samples), args.target_package))
        hepta_after = package_identity(adb, PACKAGE, "after-hepta")
        target_after = package_identity(adb, args.target_package, "after-calculator")
        report["installed_identity_after"] = {"hepta": hepta_after, "calculator": target_after}
        need(hepta_after == hepta_before and target_after == target_before, "APK/UID identity changed during test")
        need(adb.app_bytes("files/model/runtime-config.json") == expected_config, "runtime config changed during test")
        need(adb.app_bytes("files/qualification-scope.json", optional=True) is None, "scope appeared during test")
        collect_and_assess(adb, acceptance, receipts, args, report, samples, latest, baseline_runs, args.expected_uid, config)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--identity-helper", type=Path, required=True)
    p.add_argument("--source-tools", type=Path, required=True)
    p.add_argument("--adb", required=True)
    p.add_argument("--adb-host", required=True)
    p.add_argument("--adb-port", type=int, required=True)
    p.add_argument("--serial", required=True)
    p.add_argument("--apk-sha256", required=True)
    p.add_argument("--expected-uid", type=int, required=True)
    p.add_argument("--runtime-config", type=Path, required=True)
    p.add_argument("--target-package", required=True)
    p.add_argument("--result-view-id", required=True, help="exact Calculator result node view_id, verified from genuine app observation")
    p.add_argument("--existing-su-authorized", action="store_true", required=True,
        help="operator confirms Hepta already has normal su authorization; this driver does not grant or probe it")
    p.add_argument("--start-tap", type=int, nargs=2, metavar=("X", "Y"))
    p.add_argument("--prepared-screen-sha256", help="exact visually reviewed current main screencap, required for optional one Start tap")
    p.add_argument("--start-window", type=int, default=90)
    p.add_argument("--timeout", type=int, default=560)
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--command-timeout", type=int, default=8)
    p.add_argument("--out", type=Path, required=True)
    return p


def main():
    args = parser().parse_args()
    need(HEX64.fullmatch(args.apk_sha256), "explicit exact candidate APK hash required")
    need(re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)+", args.target_package)
        and args.target_package != PACKAGE, "exact calculator package required")
    need(args.result_view_id.startswith(args.target_package + ":id/"), "result view ID must belong to Calculator")
    need(1 <= args.adb_port <= 65535 and 1 <= args.command_timeout <= 30 and 1 <= args.start_window <= 120 and 540 <= args.timeout <= 600
        and 0.25 <= args.interval <= 5, "invalid bounded timing/connection configuration")
    if args.start_tap:
        need(args.prepared_screen_sha256 is not None and HEX64.fullmatch(args.prepared_screen_sha256)
            and all(0 <= value <= 10000 for value in args.start_tap), "Start tap requires reviewed screenshot and bounded coordinates")
    need(args.out.is_absolute() and not args.out.exists() and all(not p.is_symlink() for p in args.out.parents), "new absolute output directory required")
    args.out.mkdir(parents=False, mode=0o700)
    report = {"schema": "hepta.background-calculator-acceptance.v1", "qualified": False,
        "instruction": INSTRUCTION, "instruction_sha256": digest(INSTRUCTION.encode()),
        "expected_apk_sha256": args.apk_sha256, "expected_app_uid": args.expected_uid,
        "target_package": args.target_package, "existing_su_authorization_operator_attested": True,
        "magisk_policy_modified": False, "qualification_scope_modified": False,
        "external_model_invoked_by_driver": False, "direct_broker_client_used": False,
        "shell_calculator_actions": False, "private_nonce_trigger_used": False,
        "uiautomator_or_UiAutomation_used": False, "started_wall_s": time.time()}
    try:
        execute(args, report)
    except BaseException as error:
        report["error"] = type(error).__name__ + ": " + str(error)
        report["qualified"] = False
        if report.get("task_id") and not report.get("acceptance", {}).get("cleanup_confirmed_by_app_broker_and_system"):
            report["cleanup_status"] = "UNKNOWN"
            report["manual_visible_stop_may_be_required"] = True
    finally:
        report["ended_wall_s"] = time.time()
        write_new(args.out / "RESULT.json", report)
    print(json.dumps({"qualified": report["qualified"], "error": report.get("error"), "result": str(args.out / "RESULT.json")}, ensure_ascii=False), flush=True)
    return 0 if report["qualified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
