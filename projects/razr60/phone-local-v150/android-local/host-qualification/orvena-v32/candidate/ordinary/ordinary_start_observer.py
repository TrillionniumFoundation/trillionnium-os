#!/usr/bin/env python3
"""Observe one manually started Hepta task. No phone write or UI action is implemented.

prepare freezes current helpers/candidate on the host. observe waits after a normal
prefill for Root's single Start click, collects receipts and fresh screenshots, and
leaves goal verification to an independent visual review. It never submits a nonce.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import struct
import sys
import time
from types import ModuleType

PACKAGE = "org.trillionnium.hepta.local"
HELPERS = ("phone_acceptance.py", "phone_inventory.py", "phone_suite.py", "model_profiles.py")
BUNDLE_HELPERS = HELPERS + ("warm_receipts.py", "qualification_scope.py")
WARM_BACKGROUND_SCOPE = "native_request_processing_between_reservation_and_publication"
JOURNALS = ("control-session.json", "mobi-probe-session.json", "ui-venus-probe-session.json")
LATCHES = ("control-session.interrupted.json", "mobi-probe-interrupted.json", "ui-venus-probe-interrupted.json")
PENDING = ("debug-task.json", "mobi-probe-request.json", "ui-venus-probe-request.json")
TERMINAL = {"model_reported_done", "partial", "failed", "cancelled", "blocked"}
CLEAN = {"not_started", "cancelled_before_start", "model_reported_done", "partial", "failed", "cancelled"}
SHA = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[0-9a-f]{32}\Z")
REL = re.compile(r"files/[A-Za-z0-9_./-]+\Z")
WORKER = re.compile(r"libhepta_[A-Za-z0-9_.-]*(?:runner|worker)[A-Za-z0-9_.-]*[.]so|hepta-mobimind-probe|hepta-geniex-once|geniex[-_]bench|llama-(?:bench|cli)")
PROC_FIELDS = {"pid", "ppid", "uid", "start_ticks", "cmdline_sha256", "argv"}


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict(data):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def read(path, limit=8 << 20):
    path = Path(path)
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= limit,
         "nonregular/linked/oversize host file: " + str(path))
    data = path.read_bytes()
    need(len(data) == st.st_size, "host file changed during read")
    return data


def write(path, data):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def save(path, value):
    write(path, (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode())


def load_helpers(directory):
    directory = Path(directory).resolve(strict=True)
    sys.path.insert(0, str(directory))
    for name in HELPERS:
        old = sys.modules.get(name[:-3])
        need(old is None or Path(old.__file__).resolve().parent == directory, "another host driver version already imported")
    # Rebind scope explicitly to this verified snapshot, not a preloaded module
    # from the top-level package. Load all local dependencies from source bytes.
    for name in ("model_profiles", "warm_receipts", "qualification_scope", "phone_acceptance", "phone_inventory", "phone_suite"):
        path = directory / (name + ".py"); raw = read(path)
        module = ModuleType(name); module.__file__ = str(path); sys.modules[name] = module
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
        module.__hepta_verified_source_sha256__ = hashlib.sha256(raw).hexdigest()
    return tuple(sys.modules[name[:-3]] for name in HELPERS)


def scope_module(directory):
    path = Path(directory) / "qualification_scope.py"
    raw = read(path)
    module = ModuleType("hepta_scoped_observer_contract"); module.__file__ = str(path)
    sys.modules[module.__name__] = module
    exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


PERMISSION_PROOF_METHOD = "aapt2 dump permissions + xmltree on full-SHA-bound host APK; pinned assembler rule"


def apk_permission_proof(raw, candidate):
    """Validate the original completed-upgrade receipt; never infer false from null."""
    result = strict(raw)
    need(isinstance(result, dict) and result.get("schema") == "hepta.upgrade-v32-once.v1"
         and result.get("status") == "upgrade_verified"
         and result.get("permission_free_host_apk_bound_to_installed_bytes") is True,
         "permission proof is not a verified upgrade result")
    host = result.get("host_apks")
    need(isinstance(host, dict), "host APK proof missing")
    proof, signed = host.get("new_permission_evidence"), host.get("new")
    identity = result.get("identity_after_main")
    need(isinstance(proof, dict) and isinstance(signed, dict) and isinstance(identity, dict),
         "permission proof/bound host APK/installed readback missing")
    expected = candidate.get("apk_sha256")
    need(isinstance(expected, str) and SHA.fullmatch(expected)
         and result.get("new_apk_sha256") == expected
         and proof.get("apk_sha256") == expected and signed.get("sha256") == expected
         and identity.get("apk_sha256") == expected and identity.get("package") == PACKAGE
         and identity.get("version_code") == candidate.get("version_code"),
         "permission proof is not bound to the exact candidate APK")
    need(type(proof.get("apk_bytes")) is int and proof["apk_bytes"] > 0
         and type(signed.get("bytes")) is int and signed["bytes"] == proof["apk_bytes"]
         and isinstance(proof.get("host_apk"), str) and Path(proof["host_apk"]).is_absolute()
         and proof["host_apk"] == signed.get("path"),
         "permission proof host APK identity incomplete")
    need(proof.get("method") == PERMISSION_PROOF_METHOD
         and proof.get("internet_permission_declared") is False
         and type(proof.get("requested_permissions")) is list and proof["requested_permissions"] == [],
         "permission proof lacks the exact permission-free AAPT2 method")
    for key in ("permissions_stdout_sha256", "manifest_stdout_sha256"):
        need(isinstance(proof.get(key), str) and SHA.fullmatch(proof[key]),
             "permission proof capture hash missing: " + key)
    return {"source": "completed_upgrade_exact_apk_aapt2", "source_sha256": sha(raw),
            "apk_sha256": expected, "apk_bytes": proof["apk_bytes"], "method": proof["method"],
            "internet_permission_declared": False, "requested_permissions": [],
            "permissions_stdout_sha256": proof["permissions_stdout_sha256"],
            "manifest_stdout_sha256": proof["manifest_stdout_sha256"]}


def permission_observation(details, package_raw, installed_apk_sha, proof):
    declared = details.get("internet_permission_declared")
    need(declared is False or declared is None or declared is True, "malformed permission observation")
    need(declared is not True and b"android.permission.INTERNET" not in package_raw,
         "installed package explicitly declares INTERNET")
    if declared is None:
        need(isinstance(proof, dict) and proof.get("source") == "completed_upgrade_exact_apk_aapt2"
             and proof.get("apk_sha256") == installed_apk_sha
             and proof.get("method") == PERMISSION_PROOF_METHOD
             and proof.get("internet_permission_declared") is False
             and type(proof.get("requested_permissions")) is list and proof["requested_permissions"] == []
             and isinstance(proof.get("source_sha256"), str) and SHA.fullmatch(proof["source_sha256"]),
             "missing exact-APK independent proof for unknown dumpsys permission declaration")
    return {"dumpsys_internet_permission_declared": declared,
            "dumpsys_requested_permissions": details.get("requested_permissions"),
            "decision_source": "dumpsys" if declared is False else "frozen_exact_apk_aapt2_proof",
            "installed_apk_sha256": installed_apk_sha,
            "host_proof_sha256": None if proof is None else proof["source_sha256"]}


def prepare(args):
    source = args.source_dir.resolve(strict=True)
    drivers = args.driver_dir.resolve(strict=True)
    scope = scope_module(drivers)
    qualification = scope.load_binding(args.qualification_binding, args.qualification_binding_sha256)
    candidate, config = strict(read(args.candidate)), strict(read(args.runtime_config))
    need(scope.equal(candidate, qualification["candidate"]) and scope.equal(config, qualification["runtime_config"]), "scope candidate/runtime differs")
    asset_bytes = qualification["raw_files"]["build-identity.json"]
    asset = strict(asset_bytes)
    entries = {entry["path"]: entry["sha256"] for entry in asset["source_inputs"]}
    need(source == Path(qualification["source_directory"]).resolve(strict=True), "actual source directory differs")
    need(len(entries) == len(asset["source_inputs"]), "duplicate actual source input")
    need(candidate.get("package") == PACKAGE and SHA.fullmatch(candidate.get("apk_sha256", "")), "candidate APK required")
    proof_path = getattr(args, "apk_permission_proof", None)
    proof_raw = None if proof_path is None else read(proof_path)
    proof = None if proof_raw is None else apk_permission_proof(proof_raw, candidate)
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    scope.snapshot(qualification, output / "qualification-binding")
    copied, host_drivers = {}, {}
    contract_names = ("SessionRecovery.java", "MobiMindSessionContract.java", "UiVenusSessionContract.java", "LocalTaskController.java",
                      "LocalModelEngine.java", "WarmProcessSession.java", "MainActivity.java", "LocalTaskSession.java",
                      "HeptaAccessibilityService.java", "QualificationScope.java", "QualificationScopeConfig.java",
                      "ActionDecision.java", "ActionPolicy.java", "DecisionGrammar.java", "ObservedAppLabels.java")
    native_contracts = ("worker-upstream.c", "publish-appuid.inc", "warm-protocol.inc", "generate_adapter.py", "warm_runtime_adapter.py", "sampler-profile.inc")
    for relative in (["src/org/trillionnium/hepta/local/" + name for name in contract_names]
                     + ["native/" + name for name in native_contracts]):
        data = read(source / relative)
        need(entries.get(relative) == sha(data), "actual build source input mismatch: " + relative)
        copied[relative] = {"sha256": sha(data), "bytes": len(data)}
        write(output / relative, data)
    # The reviewable host qualification delta is not disguised as APK compiler input.
    for name in BUNDLE_HELPERS:
        data = read(drivers / name)
        if name == "model_profiles.py":
            need(entries.get("tools/" + name) == sha(data), "host registry differs from actual APK profile source")
        host_drivers[name] = {"sha256": sha(data), "bytes": len(data)}
        write(output / "tools" / name, data)
    acceptance, _, _, profiles = load_helpers(output / "tools")
    profile = profiles.profile(candidate["model_profile"])
    need(profile["sha256"] == candidate["model_sha256"], "candidate model SHA mismatch")
    need(candidate["compute"] in ("npu", "gpu") and candidate["context_tokens"] in (4096, 8192)
         and type(candidate["threads"]) is int and 1 <= candidate["threads"] <= 8, "invalid runtime candidate")
    expected_config = {"schema": "hepta.local-runtime.v2", **{key: candidate[key] for key in ("model_profile", "compute", "context_tokens", "threads")}}
    need(config == expected_config, "exact explicit current runtime-config required")
    instruction_bytes = read(args.instruction_file, 1600)
    instruction = instruction_bytes.decode("utf-8", "strict")
    need(instruction and instruction == instruction.strip() and not any(x in instruction for x in ("\0", "<|", "<__image__>")),
         "instruction file must contain the exact UI text without a trailing newline")
    controller = read(source / "src/org/trillionnium/hepta/local/LocalTaskController.java").decode()
    match = re.search(r"MAX_TASK_MS=(\d+),\s*MODEL_TIMEOUT_MS=(\d+)", controller)
    need(match is not None, "controller deadline constants not understood")
    task_ms, model_ms = map(int, match.groups())
    need(0 < model_ms < task_ms <= 3_600_000, "invalid source deadline constants")
    plan = {"schema": "hepta.ordinary-current-plan.v1", "candidate": candidate,
            "runtime_config": config, "runtime_config_sha256": sha(read(args.runtime_config)),
            "instruction": instruction, "instruction_sha256": sha(instruction_bytes),
            "actual_build_identity_sha256": qualification["build_identity_sha256"], "source_files": copied,
            "host_driver_files": host_drivers, "qualification_binding_sha256": qualification["binding_sha256"],
            "expected_scope_sha256": qualification["scope_sha256"], "app_uid_expected": qualification["app_uid"],
            "apk_permission_proof": proof,
            "task_limit_ms": task_ms, "model_limit_ms": model_ms,
            "phone_contacted": False, "observer_phone_writes": 0,
            "app_task_origin_required": "user_button", "debug_nonce_required": None,
             "warm_background_scope": WARM_BACKGROUND_SCOPE,
             "exact_generate_interval_claimed": False,
            "new_idle_acknowledgement_qualification": "not_implemented_refused",
            "goal_verification": "separate_root_review_of_fresh_final_png"}
    if proof_raw is not None:
        write(output / "apk-permission-proof.json", proof_raw)
    write(output / "instruction.txt", instruction_bytes)
    write(output / "actual-build-identity.json", asset_bytes)
    write(output / "ordinary_start_observer.py", read(Path(__file__)))
    save(output / "PLAN.json", plan)
    pins = {str(p.relative_to(output)): {"sha256": sha(read(p)), "bytes": p.stat().st_size}
            for p in sorted(output.rglob("*")) if p.is_file() and "__pycache__" not in p.parts}
    save(output / "BUNDLE-MANIFEST.json", {"schema": "hepta.ordinary-current-bundle.v1", "files": pins})
    print(json.dumps({"bundle": str(output), "manifest_sha256": sha(read(output / "BUNDLE-MANIFEST.json")),
                      "phone_contacted": False}, ensure_ascii=False))


def bundle(path, expected_sha):
    raw = read(path / "BUNDLE-MANIFEST.json")
    need(SHA.fullmatch(expected_sha) and sha(raw) == expected_sha, "bundle manifest SHA mismatch")
    manifest = strict(raw)
    need(manifest.get("schema") == "hepta.ordinary-current-bundle.v1", "unknown bundle")
    for name, pin in manifest["files"].items():
        rel = Path(name)
        need(not rel.is_absolute() and ".." not in rel.parts, "unsafe bundle path")
        data = read(path / rel)
        need(sha(data) == pin["sha256"] and len(data) == pin["bytes"], "changed bundle member: " + name)
    need(sha(read(Path(__file__))) == manifest["files"]["ordinary_start_observer.py"]["sha256"], "observer differs from frozen bundle")
    plan = strict(read(path / "PLAN.json"))
    scope = scope_module(path / "tools")
    qualification = scope.load_binding(path / "qualification-binding/BINDING.json", plan.get("qualification_binding_sha256"))
    need(scope.equal(qualification["candidate"], plan.get("candidate"))
         and plan.get("expected_scope_sha256") == qualification["scope_sha256"]
         and plan.get("actual_build_identity_sha256") == qualification["build_identity_sha256"], "frozen qualification differs")
    if plan.get("apk_permission_proof") is not None:
        actual_proof = apk_permission_proof(read(path / "apk-permission-proof.json"), plan["candidate"])
        need(actual_proof == plan["apk_permission_proof"], "frozen permission proof differs from plan")
    plan["_qualification"] = qualification
    plan["_scope_module"] = scope
    return plan


def hex_value(value, pattern):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def clean_control(value, uid):
    if value is None:
        return True  # Absence must be observed with no sidecar, latch, or pending barrier.
    if not isinstance(value, dict) or value.get("schema") != "hepta.local-session.v1" or value.get("app_uid") != uid:
        return False
    if type(value.get("updated_wall_ms")) is not int or value["updated_wall_ms"] <= 0 or not isinstance(value.get("state"), str):
        return False
    if any(value.get(k) is not False for k in ("pending", "running", "blocked", "external_model", "automatic_resume")) or value.get("cleanup_known") is not True:
        return False
    if value.get("status") not in CLEAN or not hex_value(value.get("instruction_sha256"), SHA):
        return False
    if not isinstance(value.get("origin"), str) or not 0 < len(value["origin"]) <= 80:
        return False
    if "debug_nonce_sha256" not in value or value["debug_nonce_sha256"] is not None and not hex_value(value["debug_nonce_sha256"], SHA):
        return False
    if value["origin"] == "private_debug_nonce" and not hex_value(value["debug_nonce_sha256"], SHA):
        return False
    return ("task_id" in value and value["task_id"] is None if value["status"] in ("not_started", "cancelled_before_start")
            else hex_value(value.get("task_id"), ID))


def clean_diagnostic(value, uid, schema):
    if value is None:
        return True
    if not isinstance(value, dict) or value.get("schema") != schema or value.get("app_uid") != uid:
        return False
    if type(value.get("updated_wall_ms")) is not int or value["updated_wall_ms"] <= 0:
        return False
    if any(value.get(k) is not False for k in ("pending", "running", "actions_executed", "external_model_used", "automatic_resume")) or value.get("cleanup_known") is not True:
        return False
    if not all(hex_value(value.get(k), SHA) for k in ("nonce_sha256", "owner_sha256")) or not hex_value(value.get("request_id"), ID):
        return False
    no_start = {"preflight_failed", "cancelled_before_start", "submission_failed"}
    if value.get("status") not in no_start | {"completed", "native_failed", "cancelled", "cancel_race", "timed_out"}:
        return False
    if value.get("process_started") is True:
        code = value.get("exit_code")
        if value.get("process_exit_observed") is not True or type(code) is not int or not 0 <= code <= 255 or value["status"] in no_start:
            return False
        if value["status"] == "cancelled" and code == 0:
            return False
    elif value.get("process_started") is not False or value.get("process_exit_observed") is not False or "exit_code" not in value or value["exit_code"] is not None or value["status"] not in no_start:
        return False
    return (value.get("process_started") is True and value.get("exit_code") == 0 and value.get("native_binding_valid") is True
            if value["status"] == "completed" else value.get("native_binding_valid") is False)


def ordinary_session(value, uid, instruction_sha, baseline_tasks, expected_task=None):
    need(isinstance(value, dict) and value.get("schema") == "hepta.local-session.v1" and value.get("app_uid") == uid, "session identity differs")
    need(value.get("origin") == "user_button" and "debug_nonce_sha256" in value and value["debug_nonce_sha256"] is None,
         "ordinary user_button/null-nonce ownership not established")
    need(value.get("instruction_sha256") == instruction_sha and value.get("external_model") is False and value.get("automatic_resume") is False,
         "ordinary original instruction/local/no-resume binding differs")
    task = value.get("task_id")
    if task is None:
        need(value.get("status") == "pending" and value.get("pending") is True and expected_task is None, "ordinary task has no valid reservation")
        return None
    need(hex_value(task, ID) and task not in baseline_tasks and (expected_task is None or task == expected_task), "ordinary task is old, invalid, or replaced")
    return task


def parse_proc(stat_bytes, status_bytes, cmdline_bytes, pid):
    raw = stat_bytes.decode("ascii", "strict").strip()
    opening, closing = raw.find(" ("), raw.rfind(") ")
    need(opening > 0 and closing > opening and int(raw[:opening]) == pid, "proc stat PID differs")
    fields = raw[closing + 2:].split()
    need(len(fields) >= 20 and fields[0] not in ("Z", "X", "x"), "process dead or stat incomplete")
    status = status_bytes.decode("ascii", "strict")
    pids = re.findall(r"(?m)^Pid:\s*(\d+)\s*$", status)
    uids = re.findall(r"(?m)^Uid:\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", status)
    need(pids == [str(pid)] and len(uids) == 1 and len(set(uids[0])) == 1, "proc PID/UID identity ambiguous")
    need(cmdline_bytes and cmdline_bytes.endswith(b"\0"), "proc cmdline lacks terminator")
    ticks = int(fields[19])
    need(ticks > 0, "invalid process start ticks")
    argv = cmdline_bytes.rstrip(b"\0").split(b"\0")
    return {"pid": pid, "ppid": int(fields[1]), "uid": int(uids[0][0]), "start_ticks": ticks,
            "cmdline_sha256": sha(cmdline_bytes), "argv": [item.decode("utf-8", "strict") for item in argv]}


def file_script(relative):
    need(REL.fullmatch(relative) and ".." not in relative.split("/"), "unsafe app file")
    p = shlex.quote(relative)
    return "if [ -f {p} ] && [ ! -L {p} ]; then cat {p}; elif [ -e {p} ] || [ -L {p} ]; then exit 41; else exit 40; fi".format(p=p)


def list_script(relative, directories):
    need(REL.fullmatch(relative) and ".." not in relative.split("/"), "unsafe app directory")
    return "if [ -d {p} ] && [ ! -L {p} ]; then find {p} -mindepth 1 -maxdepth 1 -type {t}; elif [ -e {p} ] || [ -L {p} ]; then exit 41; else exit 40; fi".format(p=shlex.quote(relative), t="d" if directories else "f")


def pending_names(run_id):
    need(hex_value(run_id, ID), "invalid pending request identity")
    return ("native-result.json." + run_id + ".pending", "raw-text.txt." + run_id + ".pending",
            "native-result.json", "raw-text.txt")


def pending_probe_script(run_ids):
    """One closed presence-only read over at most 64 exact new request IDs."""
    need(isinstance(run_ids, (list, tuple)) and 1 <= len(run_ids) <= 64
         and all(hex_value(value, ID) for value in run_ids)
         and list(run_ids) == sorted(set(run_ids)), "pending probe needs unique sorted bounded request IDs")
    return ("for hepta_observer_run in " + " ".join(run_ids) + "; do "
        "hepta_observer_dir=files/runs/$hepta_observer_run; "
        "if [ ! -d \"$hepta_observer_dir\" ] || [ -L \"$hepta_observer_dir\" ]; then exit 41; fi; "
        "for hepta_observer_name in native-result.json.$hepta_observer_run.pending raw-text.txt.$hepta_observer_run.pending native-result.json raw-text.txt; do "
        "if [ -f \"$hepta_observer_dir/$hepta_observer_name\" ] && [ ! -L \"$hepta_observer_dir/$hepta_observer_name\" ]; then "
        "printf '%s/%s present\\n' \"$hepta_observer_run\" \"$hepta_observer_name\"; "
        "elif [ -e \"$hepta_observer_dir/$hepta_observer_name\" ] || [ -L \"$hepta_observer_dir/$hepta_observer_name\" ]; then exit 41; "
        "else printf '%s/%s absent\\n' \"$hepta_observer_run\" \"$hepta_observer_name\"; fi; done; done")


def parse_pending_probe(raw, run_ids):
    expected = {run + "/" + name: None for run in run_ids for name in pending_names(run)}
    rows = {}
    for line in raw.decode("ascii", "strict").splitlines():
        fields = line.split(" ")
        need(len(fields) == 2 and fields[0] in expected and fields[0] not in rows
             and fields[1] in ("present", "absent"), "ambiguous pending presence reply")
        rows[fields[0]] = fields[1] == "present"
    need(set(rows) == set(expected), "incomplete pending presence reply")
    return {run: {name: rows[run + "/" + name] for name in pending_names(run)} for run in run_ids}


def pending_request(probe):
    """No sample is counted across a partial reservation or request transition."""
    selected = []
    for run, values in probe["runs"].items():
        first, second, native, raw = pending_names(run)
        if values[first] is True and values[second] is True and values[native] is False and values[raw] is False:
            selected.append(run)
    return selected[0] if len(selected) == 1 else None


BARRIER_SCRIPT = (
    "if [ ! -d files ] || [ -L files ] || [ ! -r files ] || [ ! -x files ] || [ -L files/model ]; then exit 41; fi; "
    + " ".join("if [ -e files/{0} ] || [ -L files/{0} ]; then exit 41; fi;".format(name)
               for name in (*LATCHES, *PENDING, *(j + s for j in JOURNALS for s in (".bak", ".new"))))
    + " for p in files/control-session.recovery-pending-*.record; do if [ -e \"$p\" ] || [ -L \"$p\" ]; then exit 41; fi; done"
)


def read_command_limit(words):
    """Closed phone-read policy; there is no arbitrary shell registration."""
    words = tuple(words)
    fixed = {
        ("am", "get-current-user"): 4096,
        ("pm", "path", PACKAGE): 16384,
        ("dumpsys", "package", PACKAGE): 4 << 20,
        ("pidof", PACKAGE): 4096,
        ("dumpsys", "window"): 4 << 20,
        ("ps", "-A", "-o", "PID,PPID,UID,NAME,ARGS"): 2 << 20,
    }
    if words in fixed:
        return fixed[words]
    if len(words) == 2 and words[0] == "sha256sum" and re.fullmatch(r"/data/app/[A-Za-z0-9_./=+~-]+/base[.]apk", words[1]) and ".." not in words[1].split("/"):
        return 4096
    if len(words) == 4 and words[:3] == ("screencap", "-p", "-d") and re.fullmatch(r"\d{1,20}", words[3]):
        return 24 << 20
    if words[:4] != ("run-as", PACKAGE, "--user", "0"):
        return 0
    rest = words[4:]
    if rest == ("id", "-u"):
        return 4096
    if len(rest) == 2 and rest[0] == "cat" and re.fullmatch(r"/proc/[1-9][0-9]*/(?:stat|status|cmdline)", rest[1]):
        return 128 << 10
    if len(rest) != 3 or rest[:2] != ("sh", "-c"):
        return 0
    script = rest[2]
    if script == BARRIER_SCRIPT:
        return 4096
    match = re.match(r"for hepta_observer_run in ([0-9a-f ]+); do ", script)
    if match:
        try:
            if script == pending_probe_script(match[1].split(" ")):
                return 65536
        except ValueError:
            pass
        return 0
    match = re.match(r"if \[ -f (files/[A-Za-z0-9_./-]+) \]", script)
    if match and ".." not in match[1].split("/") and script == file_script(match[1]):
        return 4 << 20
    match = re.match(r"if \[ -d (files/[A-Za-z0-9_./-]+) \]", script)
    if match and ".." not in match[1].split("/") and any(script == list_script(match[1], flag) for flag in (False, True)):
        return 1 << 20
    return 0


# Reuse the frozen lifecycle guards (SHA 2b1a5ba2...cdf4292), unchanged.
def top_focused_display(raw):
    """Parse one successful windows dump; duplicate/malformed labels are unknown."""
    text = raw.decode("utf-8", "strict")
    lines = [line.strip() for line in text.splitlines()
             if line.strip().startswith("mTopFocusedDisplayId")]
    if len(lines) != 1:
        raise ValueError("window dump lacks a unique top focused display label")
    match = re.fullmatch(r"mTopFocusedDisplayId=(0|[1-9][0-9]{0,4})", lines[0])
    if match is None or int(match[1]) > 65535:
        raise ValueError("window top focused display label is malformed")
    return int(match[1])

def display_focus(raw, logical_display_id):
    """Bind current focus to an explicit display block, never the first global line."""
    if type(logical_display_id) is not int or not 0 <= logical_display_id <= 65535:
        raise ValueError("explicit logical display ID required")
    lines = raw.decode("utf-8", "strict").splitlines()
    headers = [line.strip() for line in lines if line.strip().startswith("WINDOW MANAGER DISPLAY CONTENTS")]
    if headers != ["WINDOW MANAGER DISPLAY CONTENTS (dumpsys window displays)"]:
        raise ValueError("unexpected display dump header")
    blocks = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("Display:"):
            match = re.fullmatch(r"Display: mDisplayId=(0|[1-9][0-9]{0,4})(?: \(organized\))?", stripped)
            if match is None or int(match[1]) > 65535:
                raise ValueError("display block header is malformed")
            blocks.append((int(match[1]), index))
    ids = [item[0] for item in blocks]
    if len(ids) != len(set(ids)) or logical_display_id not in ids:
        raise ValueError("requested display block is absent or duplicated")
    position = ids.index(logical_display_id)
    first = blocks[position][1] + 1
    last = blocks[position + 1][1] if position + 1 < len(blocks) else len(lines)
    focus = [line.strip() for line in lines[first:last] if line.strip().startswith("mCurrentFocus")]
    if len(focus) != 1:
        raise ValueError("requested display has missing or ambiguous current focus")
    if focus[0] == "mCurrentFocus=null":
        package = component = user = None
    else:
        match = re.fullmatch(r"mCurrentFocus=Window\{[0-9a-fA-F]+ u([0-9]+) "
                             r"([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)/([A-Za-z0-9_.$]+)\}", focus[0])
        if match is None:
            raise ValueError("requested display focus is not an exact app component")
        user, package, component = int(match[1]), match[2], match[3]
    return {"logical_display_id": logical_display_id, "focus_package": package,
            "focus_component": component, "focus_user": user, "focus_lines": focus,
            "observed_display_ids": ids}


def full_window_focus(raw, logical_display_id, input_width, input_height):
    """Bind one full raw dump to logical 0; screenshot and dump are not atomic."""
    need(type(logical_display_id) is int and logical_display_id == 0,
         "this observer requires explicit logical display 0")
    lines = raw.decode("utf-8", "strict").splitlines()
    headers = [(i, line.strip()) for i, line in enumerate(lines)
               if line.strip().startswith("WINDOW MANAGER ")]
    def section(expected):
        found = [position for position, (_, name) in enumerate(headers) if name == expected]
        need(len(found) == 1, "missing/duplicate full-window section: " + expected)
        position = found[0]
        start = headers[position][0]
        end = headers[position + 1][0] if position + 1 < len(headers) else len(lines)
        return ("\n".join(lines[start:end]) + "\n").encode()
    displays = section("WINDOW MANAGER DISPLAY CONTENTS (dumpsys window displays)")
    windows = section("WINDOW MANAGER WINDOWS (dumpsys window windows)")
    top = top_focused_display(windows)
    # The global check refuses a duplicate/contradictory top label in any section.
    need(top_focused_display(raw) == top == logical_display_id,
         "top focused display differs from explicit logical input display")
    observed = display_focus(displays, logical_display_id)
    need(observed["focus_user"] is None or observed["focus_user"] == 0,
         "focused component belongs to a different Android user")
    display_lines = displays.decode().splitlines()
    blocks = [(int(match[1]), i) for i, line in enumerate(display_lines)
              if (match := re.fullmatch(r"\s*Display: mDisplayId=(0|[1-9][0-9]{0,4})(?: \(organized\))?", line))]
    position = [x[0] for x in blocks].index(logical_display_id)
    start = blocks[position][1] + 1
    end = blocks[position + 1][1] if position + 1 < len(blocks) else len(display_lines)
    dimensions = re.findall(r"(?m)^\s+init=[^\r\n]*\bcur=(\d+)x(\d+)(?:\s|$)",
                            "\n".join(display_lines[start:end]))
    need(len(dimensions) == 1 and tuple(map(int, dimensions[0])) == (input_width, input_height),
         "logical display dimensions differ from screenshot/input mapping")
    return {"line": observed["focus_lines"][0].split("=", 1)[1],
            "package": observed["focus_package"], "component": observed["focus_component"],
            "focus_user": observed["focus_user"], "logical_display_id": logical_display_id,
            "top_focused_display_id": top, "observed_display_ids": observed["observed_display_ids"],
            "display_width": input_width, "display_height": input_height,
            "full_window_sha256": sha(raw), "atomic_snapshot_claimed": False}


class ObserverAdb:
    """Only internally registered read templates reach the existing smart socket."""
    def __init__(self, args, output, inventory):
        import qualification_scope
        binding = qualification_scope.from_args(args)
        qualification_scope.need(binding is not None, "private device binding required before observer ADB")
        qualification_scope.require_device_target(args, binding, display=True)
        self.args, self.output, self.inventory = args, output, inventory
        self.sequence, self.failed = 0, False
        self.allowed = {}
        self.deadline = time.monotonic() + args.arm_timeout + 3600 + 300

    def _read(self, words, label, limit=1 << 20, allowed=(0,), timeout=None):
        need(0 < limit <= read_command_limit(words), "phone command outside closed read-only policy")
        self.allowed[tuple(words)] = limit
        return self.command(words, label=label, allowed=allowed, timeout=timeout)

    def command(self, words, *, label="read", input_data=None, allowed=(0,), timeout=None, raw=False):
        words = tuple(words)
        need(input_data is None and words in self.allowed and not self.failed, "command outside read-only templates or transport closed")
        limit = self.allowed[words]
        budget = min(timeout or self.args.command_timeout, 30, self.deadline - time.monotonic())
        need(budget > 0 and self.sequence < 10000, "observer read deadline/budget exhausted")
        self.sequence += 1
        deadline = time.monotonic() + budget
        streams, code = {1: bytearray(), 2: bytearray()}, None
        record = {"command": list(words), "phone_stdin_bytes": 0, "started_wall_ms": int(time.time() * 1000)}
        try:
            with socket.create_connection((self.args.adb_host, self.args.adb_port), timeout=budget) as channel:
                self.inventory._send_smart_service(channel, "host:transport:" + self.args.serial, deadline)
                self.inventory._send_smart_service(channel, "shell,v2,raw:" + shlex.join(words), deadline)
                channel.sendall(b"\x04\x00\x00\x00\x00")
                while True:
                    header = self.inventory._socket_read_exact(channel, 5, deadline)
                    stream, count = header[0], int.from_bytes(header[1:], "little")
                    if stream == 3:
                        need(count == 1, "bad remote exit packet")
                        code = self.inventory._socket_read_exact(channel, 1, deadline)[0]
                        break
                    need(stream in streams and count <= limit - sum(map(len, streams.values())), "unexpected or oversized read response")
                    streams[stream].extend(self.inventory._socket_read_exact(channel, count, deadline))
            need(code in allowed, "read remote exit " + str(code))
        except Exception as error:
            self.failed = True
            record["error"] = type(error).__name__ + ": " + str(error)
            raise
        finally:
            record.update(exit_code=code, finished_wall_ms=int(time.time() * 1000), transport_closed_after_error=self.failed)
            stem = self.output / "commands" / ("%05d-%s" % (self.sequence, re.sub(r"[^A-Za-z0-9_-]", "_", label)))
            write(stem.with_suffix(".stdout.bin"), bytes(streams[1]))
            write(stem.with_suffix(".stderr.bin"), bytes(streams[2]))
            save(stem.with_suffix(".json"), record)
        return code, bytes(streams[1])

    def app_read(self, words, label, limit=1 << 20, allowed=(0,)):
        return self._read(["run-as", PACKAGE, "--user", "0", *words], label, limit, allowed)

    def app_bytes(self, relative, *, optional=False):
        code, data = self.app_read(["sh", "-c", file_script(relative)], "app-file", 4 << 20, (0, 40) if optional else (0,))
        return None if code == 40 else data

    def app_json(self, relative, *, optional=True):
        data = self.app_bytes(relative, optional=optional)
        if data is None:
            return None
        value = strict(data)
        need(isinstance(value, dict), "expected JSON object: " + relative)
        return value

    def pending_probe(self, run_ids):
        run_ids = sorted(run_ids)
        _, raw = self.app_read(["sh", "-c", pending_probe_script(run_ids)], "warm-pending-presence", 65536)
        return {"runs": parse_pending_probe(raw, run_ids), "command_sequence": self.sequence,
                "stdout_sha256": sha(raw), "atomic_snapshot_claimed": False}

    def list_children(self, relative, directories=False):
        code, raw = self.app_read(["sh", "-c", list_script(relative, directories)], "app-list", 1 << 20, (0, 40))
        if code == 40:
            return []
        names = []
        for line in raw.decode().splitlines():
            need(line.startswith(relative + "/"), "unexpected directory result")
            name = line[len(relative) + 1:]
            need(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,239}", name), "unsafe evidence filename")
            names.append(name)
        return sorted(names)

    def proc(self, pid, optional=False):
        need(type(pid) is int and pid > 1, "invalid process PID")
        values = []
        for name in ("stat", "status", "cmdline"):
            code, raw = self.app_read(["cat", "/proc/%d/%s" % (pid, name)], "proc-" + name,
                                      128 << 10, (0, 1) if optional else (0,))
            if code != 0:
                return None  # No identity claim from a missed live-process sample.
            values.append(raw)
        if optional and (not values[2] or re.search(rb"\) [ZXx] ", values[0])):
            return None  # Exiting/zombie workers supply no live-background proof.
        return parse_proc(*values, pid)

    def focus(self):
        _, raw = self._read(["dumpsys", "window"], "window", 4 << 20)
        value = full_window_focus(raw, self.args.logical_display_id,
                                  self.args.input_width, self.args.input_height)
        return {**value, "physical_display_id": self.args.physical_display_id}

    def ps(self):
        return self._read(["ps", "-A", "-o", "PID,PPID,UID,NAME,ARGS"], "processes", 2 << 20)[1].decode("utf-8", "strict")

    def png(self, label):
        _, data = self._read(["screencap", "-p", "-d", self.args.physical_display_id], label, 24 << 20)
        need(data.startswith(b"\x89PNG\r\n\x1a\n") and data[12:16] == b"IHDR", "invalid screencap PNG")
        width, height = struct.unpack(">II", data[16:24])
        need((width, height) == (self.args.input_width, self.args.input_height), "screenshot/display mapping differs")
        write(self.output / (label + ".png"), data)
        return {"path": label + ".png", "sha256": sha(data), "width": width, "height": height, "focus": self.focus()}


def no_workers(processes):
    need(not any(WORKER.search(line) for line in processes.splitlines()[1:]), "native worker present")


def independent_accelerator_log(raw, native, compute):
    """Supplement only: never replaces the frozen collector's result or gates."""
    device, buffer_name = ("HTP0", "HTP0") if compute == "npu" else ("GPUOpenCL", "OpenCL")
    ansi = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")
    lines, nonascii = [], 0
    for original in raw.splitlines():
        try:
            lines.append(ansi.sub(b"", original).decode("ascii", "strict"))
        except UnicodeError:
            nonascii += 1
    selected = [line for line in lines if re.search(r"Using\s+1\s+device\(s\):\s*" + re.escape(device) + r"(?:\s|$)", line)]
    layers = []
    buffers = []
    for line in lines:
        for match in re.finditer(r"\boffloaded\s+(\d+)(?:/(\d+))?\s+layers\b", line, re.I):
            layers.append({"offloaded_layers": int(match[1]), "total_layers_if_logged": int(match[2]) if match[2] else None, "line": line})
        if re.search(r"\b" + re.escape(buffer_name) + r"\s+model buffer\b", line, re.I):
            sizes = [{"value": float(match[1]), "unit": match[2]} for match in re.finditer(
                r"([0-9]+(?:\.[0-9]+)?)\s*(MiB|MB|GiB|bytes)\b", line)]
            buffers.append({"line": line, "reported_sizes": sizes})
    matched = (native.get("compute_requested") == compute and native.get("device_resolved") == device
               and type(native.get("n_gpu_layers_create")) is int and native["n_gpu_layers_create"] != 0)
    positive = bool(matched and selected and any(item["offloaded_layers"] > 0 for item in layers)
                    and any(size["value"] > 0 for item in buffers for size in item["reported_sizes"]))
    return {"schema": "hepta.ordinary-independent-accelerator-log.v1", "raw_stderr_sha256": sha(raw),
            "raw_stderr_bytes": len(raw), "compute": compute, "expected_device": device,
            "expected_buffer_log_name": buffer_name, "native_device_fields_match": matched,
            "selected_device_lines": selected, "offload_layer_records": layers,
            "model_buffer_records": buffers, "nonascii_lines_excluded_from_positive_proof": nonascii,
            "positive_tensor_offload_observed": positive, "replaces_collector_result": False,
            "used_for_technical_verdict": False, "full_operator_accelerator_coverage_proven": False,
            "fallback_or_unsupported_lines": [line for line in lines if "fallback" in line.lower() or "unsupported" in line.lower()]}


def idle_snapshot(adb, uid, plan):
    adb.app_read(["sh", "-c", BARRIER_SCRIPT], "no-barriers", 4096)
    values, hashes = {}, {}
    for name in JOURNALS:
        raw = adb.app_bytes("files/" + name, optional=True)
        hashes[name] = sha(raw) if raw is not None else None
        values[name] = strict(raw) if raw is not None else None
    need(clean_control(values[JOURNALS[0]], uid), "control journal is not a known clean terminal/absence")
    for name, schema in zip(JOURNALS[1:], ("hepta.mobimind.diagnostic-session.v1", "hepta.ui-venus.diagnostic-session.v1")):
        need(clean_diagnostic(values[name], uid, schema), "diagnostic journal is not clean: " + name)
    raw = adb.app_bytes("files/model/runtime-config.json")
    need(sha(raw) == plan["runtime_config_sha256"] and strict(raw) == plan["runtime_config"], "runtime config changed")
    hashes["runtime-config.json"] = sha(raw)
    if "_qualification" in plan:
        qualification = plan["_qualification"]
        plan["_scope_module"].fresh_files(adb, qualification)
        hashes["qualification-scope.json"] = qualification["scope_sha256"]
    no_workers(adb.ps())
    return {"hashes": hashes, "control": values[JOURNALS[0]]}


def parent_identity(adb, expected=None):
    _, raw = adb._read(["pidof", PACKAGE], "app-pid", 4096)
    pids = raw.split()
    need(len(pids) == 1, "app parent is not unique")
    process = adb.proc(int(pids[0]))
    need(process["argv"] == [PACKAGE], "app parent cmdline differs")
    if expected is not None:
        need(process == expected, "app parent PID/start/UID/cmdline changed")
    return process


def argv_value(argv, name):
    need(argv.count(name) == 1 and argv.index(name) + 1 < len(argv), "native argv lacks unique " + name)
    return argv[argv.index(name) + 1]


def observed_worker(adb, parent, run_ids, task_id=None):
    matches = [line for line in adb.ps().splitlines()[1:] if WORKER.search(line)]
    if not matches:
        return None
    need(len(matches) == 1, "more than one native worker observed")
    worker = adb.proc(int(matches[0].split()[0]), optional=True)
    if worker is None:
        return None
    need(worker["uid"] == parent["uid"] and worker["ppid"] == parent["pid"], "native worker belongs to a different parent/UID")
    argv = worker["argv"]
    need(Path(argv[0]).name == "libhepta_local_runner.so", "unexpected native worker kind")
    run_id = argv_value(argv, "--request-id")
    need(hex_value(run_id, ID) and run_id in run_ids, "worker does not name a new run")
    need(argv_value(argv, "--expected-parent-pid") == str(parent["pid"]), "worker expected parent differs")
    warm_flags = {value for value in argv if value.startswith("--warm-")}
    if warm_flags:
        need(warm_flags == {"--warm-generation", "--warm-task-id", "--warm-session-dir"}, "partial or unknown warm argv")
        generation = argv_value(argv, "--warm-generation")
        need(hex_value(task_id, ID) and argv_value(argv, "--warm-task-id") == task_id,
             "live warm worker belongs to a different task")
        need(hex_value(generation, ID) and generation in run_ids and generation != run_id,
             "live warm generation is not a unique new directory")
        directory = argv_value(argv, "--warm-session-dir")
        need(directory in ("/data/user/0/" + PACKAGE + "/files/runs/" + generation,
                           "/data/data/" + PACKAGE + "/files/runs/" + generation),
             "warm session directory is outside the exact App user-0 runs")
        return {**worker, "mode": "warm", "task_id": task_id, "worker_generation": generation,
                "launch_run_id": run_id, "session_directory": directory}
    return {**worker, "mode": "one_shot", "run_id": run_id}


def warm_probe(adb, worker, new_runs):
    generation = worker["worker_generation"]
    need(generation in new_runs and all(hex_value(value, ID) for value in new_runs), "warm run directories changed")
    requests = sorted(new_runs - {generation})
    need(1 <= len(requests) <= 64 and worker["launch_run_id"] in requests, "warm request membership is invalid")
    return adb.pending_probe(requests)


def background_bracket(adb, parent, worker, new_runs, baseline_runs, instruction):
    """Observe native request processing, never an exact SDK generate interval."""
    detail = {}
    warm = worker is not None and worker["mode"] == "warm"
    if warm:
        detail["pending_before"] = warm_probe(adb, worker, new_runs)
    focus = adb.focus()
    if worker is None or focus["package"] is None or focus["package"] == PACKAGE:
        return focus, None, detail
    again = adb.proc(worker["pid"], optional=True)
    detail["worker_after"] = again
    if again is None:
        return focus, None, detail
    need(isinstance(again, dict) and set(again) == PROC_FIELDS and all(again[key] == worker[key] for key in PROC_FIELDS),
         "native worker changed around focus observation")
    detail["parent_after"] = parent_identity(adb, parent)
    if warm:
        after_runs = set(adb.list_children("files/runs", directories=True)) - baseline_runs
        detail["pending_after"] = warm_probe(adb, worker, after_runs)
        run_id = pending_request(detail["pending_before"])
        if run_id is None or pending_request(detail["pending_after"]) != run_id:
            return focus, None, detail
    else:
        run_id = worker["run_id"]
    prompt = adb.app_bytes("files/runs/" + run_id + "/prompt.txt")
    need(prompt.decode("utf-8", "strict").endswith("\nOWNER\n" + instruction), "background native run has different owner")
    proof = {"mode": worker["mode"], "run_id": run_id, "pid": worker["pid"], "start_ticks": worker["start_ticks"],
             "cmdline_sha256": worker["cmdline_sha256"], "focus": focus, "prompt_sha256": sha(prompt),
             "scope": WARM_BACKGROUND_SCOPE if warm else "owned_one_shot_native_process_alive",
             "exact_generate_interval_claimed": False}
    if warm:
        proof.update(task_id=worker["task_id"], worker_generation=worker["worker_generation"],
                     launch_run_id=worker["launch_run_id"])
    return focus, proof, detail


def native_collection_binding(output, collection, parent, task_id, instruction, suite):
    """Use complete recorded files; cached positive collection flags cannot suffice."""
    warm_path = Path(suite.__file__).resolve().with_name("warm_receipts.py")
    warm_receipts = ModuleType("hepta_bound_warm_receipts"); warm_receipts.__file__ = str(warm_path)
    exec(compile(read(warm_path), str(warm_path), "exec", dont_inherit=True), warm_receipts.__dict__)
    need(strict(read(output / "collection.json")) == collection, "collection changed after recording")
    runs = collection.get("associated_runs")
    need(isinstance(runs, list) and 1 <= len(runs) <= 64 and all(isinstance(row, dict) for row in runs)
         and not collection.get("errors") and warm_receipts.collection_verified(collection),
         "native collection is incomplete or contains errors")
    identities = [row.get("run_id") for row in runs]
    need(all(hex_value(value, ID) for value in identities) and len(set(identities)) == len(identities),
         "duplicate or invalid collected request identities")
    warm = all(row.get("app_receipt_schema") == warm_receipts.APP_REQUEST for row in runs)
    need(warm or all(row.get("app_receipt_schema") == "hepta.local-model.receipt.v2" for row in runs),
         "mixed native process lifetimes in one ordinary task")
    owner = strict(read(output / "task" / "owner.json"))
    need(owner.get("schema") == "hepta.local-owner.v1" and owner.get("task_id") == task_id
         and owner.get("instruction") == instruction and owner.get("instruction_utf8_sha256") == sha(instruction.encode("utf-8"))
         and owner.get("external_model") is False and owner.get("automatic_resume") is False,
         "collected ordinary owner changed")
    result = {"mode": "warm" if warm else "one_shot", "run_ids": sorted(identities), "runs": {}}
    generations = set()
    for row in runs:
        run_id = row["run_id"]
        app = strict(read(output / "runs" / run_id / "app-receipt.json"))
        native = strict(read(output / "runs" / run_id / "native-result.json"))
        need(app.get("run_id") == run_id and app.get("schema") == row["app_receipt_schema"]
             and type(app.get("app_pid")) is int and app["app_pid"] == parent["pid"]
             and type(app.get("app_uid")) is int and app["app_uid"] == parent["uid"]
             and type(app.get("expected_parent_pid")) is int and app["expected_parent_pid"] == parent["pid"]
             and app.get("parent_death_guard_requested") is True and app.get("process_started") is True,
             "collected native receipt belongs to a different App parent")
        if warm:
            binding = suite._warm_task_model_binding(output, run_id, native, owner)
            need(binding.get("task_id") == task_id and binding.get("app_uid") == parent["uid"],
                 "warm terminal ownership differs")
            generations.add(binding["worker_generation"])
            result["runs"][run_id] = {**binding, "request_sequence": app["request_sequence"], "argv": app.get("argv")}
        else:
            need(app.get("schema") == "hepta.local-model.receipt.v2" and app.get("process_exit_observed") is True
                 and type(app.get("exit_code")) is int and app["exit_code"] == 0,
                 "one-shot native exit was not observed")
            result["runs"][run_id] = {"worker_pid": native.get("pid")}
    if warm:
        need(len(generations) == 1 and not generations.intersection(identities), "warm task has no unique extra generation")
        generation = next(iter(generations))
        terminal = strict(read(output / "runs" / generation / "app-session-receipt.json"))
        need(type(terminal.get("app_pid")) is int and terminal["app_pid"] == parent["pid"]
             and type(terminal.get("app_uid")) is int and terminal["app_uid"] == parent["uid"], "warm session parent changed")
        result["worker_generation"] = generation
    return result


def validate_pending_evidence(output, probe):
    """Reparse the original bounded read, including its closed command receipt."""
    need(isinstance(probe, dict) and isinstance(probe.get("runs"), dict)
         and type(probe.get("command_sequence")) is int and 1 <= probe["command_sequence"] <= 10000,
         "pending probe identity is missing")
    run_ids = sorted(probe["runs"])
    script = pending_probe_script(run_ids)
    stem = output / "commands" / ("%05d-warm-pending-presence" % probe["command_sequence"])
    raw = read(stem.with_suffix(".stdout.bin"), 65536)
    receipt = strict(read(stem.with_suffix(".json")))
    need(sha(raw) == probe.get("stdout_sha256") and parse_pending_probe(raw, run_ids) == probe["runs"],
         "pending sample differs from original raw probe")
    need(receipt.get("command") == ["run-as", PACKAGE, "--user", "0", "sh", "-c", script]
         and type(receipt.get("exit_code")) is int and receipt["exit_code"] == 0
         and type(receipt.get("phone_stdin_bytes")) is int and receipt["phone_stdin_bytes"] == 0
         and receipt.get("transport_closed_after_error") is False and "error" not in receipt
         and read(stem.with_suffix(".stderr.bin"), 65536) == b"", "pending read did not complete under the closed policy")
    return pending_request(probe)


def validate_background_samples(output, samples, native_binding, parent, warm_identity):
    for entry in samples:
        raw = read(output / "samples" / ("%04d.json" % entry["sample"]))
        need(sha(raw) == entry.get("sample_sha256"), "background sample file changed")
        sample = strict(raw)
        proof = sample.get("background_evidence")
        need(proof == {key: value for key, value in entry.items() if key not in ("sample", "sample_sha256")},
             "background summary differs from sampled evidence")
        worker, after = sample.get("worker"), sample.get("worker_after")
        need(isinstance(worker, dict) and isinstance(after, dict) and set(after) == PROC_FIELDS
             and PROC_FIELDS.issubset(worker) and all(after[key] == worker[key] for key in PROC_FIELDS)
             and sample.get("parent_after") == parent and worker["uid"] == parent["uid"] and worker["ppid"] == parent["pid"],
             "background process/parent bracket is incomplete")
        need(proof["mode"] == native_binding["mode"] and proof["run_id"] in native_binding["runs"]
             and proof["pid"] == worker["pid"] and proof["start_ticks"] == worker["start_ticks"]
             and proof["cmdline_sha256"] == worker["cmdline_sha256"] and proof["focus"] == sample.get("focus")
             and proof["focus"].get("package") not in (None, PACKAGE), "background request/process/focus differs")
        native = strict(read(output / "runs" / proof["run_id"] / "native-result.json"))
        prompt = read(output / "runs" / proof["run_id"] / "prompt.txt")
        need(type(native.get("pid")) is int and native["pid"] == proof["pid"] and sha(prompt) == proof["prompt_sha256"],
             "background native PID or prompt differs from actual collection")
        if proof["mode"] == "warm":
            need(worker == warm_identity and proof.get("scope") == WARM_BACKGROUND_SCOPE
                 and proof.get("exact_generate_interval_claimed") is False
                 and proof.get("worker_generation") == native_binding["worker_generation"]
                 and validate_pending_evidence(output, sample["pending_before"]) == proof["run_id"]
                 and validate_pending_evidence(output, sample["pending_after"]) == proof["run_id"]
                 and sample["pending_before"]["command_sequence"] < sample["pending_after"]["command_sequence"],
                 "warm request was not bracketed by two pending pairs")
            binding = native_binding["runs"][proof["run_id"]]
            launch = native_binding["runs"].get(proof["launch_run_id"], {})
            need(binding["task_id"] == proof["task_id"] == worker["task_id"]
                 and binding["worker_generation"] == worker["worker_generation"]
                 and binding["worker_pid"] == worker["pid"] and launch.get("request_sequence") == 1
                 and launch.get("argv") == worker["argv"], "warm live argv/session/request chain differs")
    return True


def final_run_directories(new_runs, native_binding):
    expected = set(native_binding["run_ids"])
    if native_binding["mode"] == "warm":
        expected.add(native_binding["worker_generation"])
    need(new_runs == expected, "unassociated native run or task generation appeared")


def observe(args):
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    plan = bundle(args.bundle.resolve(strict=True), args.bundle_sha256)
    acceptance, inventory, suite, _ = load_helpers(args.bundle.resolve() / "tools")
    report = {"schema": "hepta.ordinary-current-observation.v1", "candidate": plan["candidate"],
              "instruction_sha256": plan["instruction_sha256"], "phone_contacted": False,
              "observer_phone_writes": 0, "observer_launches": 0, "observer_taps": 0,
              "automatic_retry": False, "cleanup_known": None, "goal_verified": None,
               "exact_generate_interval_claimed": False,
              "goal_verdict": "requires_independent_final_ui_review", "background_samples": [],
              "errors": [], "technical_evidence_complete": False, "task_id": None,
              "scope_excludes": ["offline_device", "Stop", "restart_no_replay", "locked_screen"]}
    scope, qualification = plan["_scope_module"], plan["_qualification"]
    scope.require_device_target(args, qualification, display=True)
    args.qualification_binding = Path(qualification["binding_path"])
    args.qualification_binding_sha256 = qualification["binding_sha256"]
    report.update(qualification_binding_sha256=qualification["binding_sha256"], expected_scope_sha256=qualification["scope_sha256"])
    adb = ObserverAdb(args, output, inventory)
    baseline_runs, parent, task_id = set(), None, None
    warm_identity = None
    terminal = None
    try:
        report["server"] = inventory.require_existing_adb_server(args, output, "before")
        report["phone_contacted"] = True
        need(adb._read(["am", "get-current-user"], "current-user", 4096)[1].strip() == b"0", "expected Android user 0")
        path_raw = adb._read(["pm", "path", PACKAGE], "apk-path", 16384)[1]
        match = re.fullmatch(rb"package:(/data/app/[^\s]+/base[.]apk)\r?\n", path_raw)
        need(match is not None, "installed APK path ambiguous")
        apk_path = match.group(1).decode()
        installed_apk_sha = adb._read(["sha256sum", apk_path], "apk-sha", 4096, timeout=30)[1].decode().split()[0]
        need(installed_apk_sha == plan["candidate"]["apk_sha256"], "installed APK differs")
        package = adb._read(["dumpsys", "package", PACKAGE], "package", 4 << 20)[1]
        details = inventory.parse_package_dump(package, 0)
        uid = int(adb.app_read(["id", "-u"], "app-uid", 4096)[1])
        need(uid == qualification["app_uid"] and details["app_id"] == uid and details["current_user_installed"] is True
             and details["version_code"] == plan["candidate"]["version_code"],
             "installed package/version/UID/no-INTERNET identity differs")
        report["permission_evidence"] = permission_observation(
            details, package, installed_apk_sha, plan.get("apk_permission_proof"))
        report.update(app_uid=uid, installed_package=details, installed_apk_sha256=plan["candidate"]["apk_sha256"])
        parent = parent_identity(adb)
        need(parent["uid"] == uid, "app process UID mismatch")
        report["parent"] = parent
        first = idle_snapshot(adb, uid, plan)
        baseline_tasks = set(adb.list_children("files/control-tasks", directories=True))
        baseline_runs = set(adb.list_children("files/runs", directories=True))
        time.sleep(0.5)
        need(idle_snapshot(adb, uid, plan) == first, "initial journals did not remain stable")
        parent_identity(adb, parent)
        report["ready_ui"] = adb.png("ready")
        need(report["ready_ui"]["focus"]["package"] == PACKAGE, "normal prefill is not focused")
        need(idle_snapshot(adb, uid, plan) == first, "task started before observer armed")
        save(output / "READY.json", {"event": "ARMED_AWAITING_ROOT_START", "ready_ui": report["ready_ui"],
                                    "instruction": plan["instruction"], "parent": parent,
                                    "instruction_sha256": plan["instruction_sha256"], "expected_scope_sha256": qualification["scope_sha256"],
                                    "qualification_binding_sha256": qualification["binding_sha256"],
                                    "baseline_tasks": sorted(baseline_tasks), "baseline_runs": sorted(baseline_runs),
                                    "phone_actions_sent": 0, "wall_ms": int(time.time() * 1000)})
        print(json.dumps({"event": "ARMED_AWAITING_ROOT_START", "output": str(output), "image": str(output / "ready.png")}), flush=True)
        arm_deadline = time.monotonic() + args.arm_timeout
        last_idle = time.monotonic()
        first_active = None
        sample_index = 0
        while True:
            observed_at = time.monotonic()
            session = adb.app_json("files/control-session.json")
            if first_active is None and session == first["control"]:
                need(observed_at < arm_deadline, "no ordinary Start observed within arm window")
                last_idle = observed_at
                time.sleep(args.poll_seconds)
                continue
            if first_active is None:
                first_active = observed_at
                report["first_active_host_wall_ms"] = int(time.time() * 1000)
                report["task_start_bracket_monotonic"] = [last_idle, first_active]
            task_id = ordinary_session(session, uid, plan["instruction_sha256"], baseline_tasks, task_id)
            need(session.get("expected_scope_sha256") == qualification["scope_sha256"], "ordinary session scope binding differs")
            report["task_id"] = task_id
            sample_index += 1
            sample = {"index": sample_index, "elapsed_since_prior_idle_s": observed_at - last_idle, "session": session}
            if task_id is not None:
                owner = adb.app_json("files/control-tasks/" + task_id + "/owner.json")
                if owner is None:
                    # schedule() can persist the new task ID before the controller
                    # worker writes owner.json. Do not misclassify this ordinary
                    # publication window, and do not claim any worker ownership yet.
                    sample["owner_publication_pending"] = True
                    save(output / "samples" / ("%04d.json" % sample_index), sample)
                    need(time.monotonic() - first_active <= plan["task_limit_ms"] / 1000 + 60,
                         "owner publication/task observation deadline elapsed")
                    time.sleep(args.poll_seconds)
                    continue
                need(owner.get("schema") == "hepta.local-owner.v1" and owner.get("task_id") == task_id
                     and owner.get("instruction") == plan["instruction"] and owner.get("instruction_utf8_sha256") == plan["instruction_sha256"]
                     and owner.get("external_model") is False and owner.get("automatic_resume") is False, "ordinary owner differs")
                terminal = adb.app_json("files/control-tasks/" + task_id + "/result.json")
            if terminal is not None:
                need(terminal.get("task_id") == task_id and terminal.get("status") in TERMINAL, "invalid terminal result")
                sample["terminal"] = terminal
                save(output / "samples" / ("%04d.json" % sample_index), sample)
                break
            parent_identity(adb, parent)
            new_runs = set(adb.list_children("files/runs", directories=True)) - baseline_runs
            worker = observed_worker(adb, parent, new_runs, task_id)
            if worker is not None:
                mode = report.setdefault("native_process_mode_observed", worker["mode"])
                need(mode == worker["mode"], "native process lifetime mode changed during the task")
                if worker["mode"] == "warm":
                    if warm_identity is None:
                        warm_identity = worker
                        report["warm_worker_identity"] = worker
                    need(worker == warm_identity, "warm task worker generation or process identity changed")
            focus, background, detail = background_bracket(adb, parent, worker, new_runs, baseline_runs, plan["instruction"])
            sample.update(worker=worker, focus=focus, background_bracket_verified=background is not None,
                          background_evidence=background, **detail)
            sample_path = output / "samples" / ("%04d.json" % sample_index)
            save(sample_path, sample)
            if background is not None:
                report["background_samples"].append({"sample": sample_index, "sample_sha256": sha(read(sample_path)), **background})
            need(time.monotonic() - first_active <= plan["task_limit_ms"] / 1000 + 60,
                 "task plus cleanup observation deadline elapsed; observer sends no stop/kill")
            time.sleep(args.poll_seconds)
        report["task_result"] = terminal
        report["terminal_observed_latency_since_prior_idle_s"] = time.monotonic() - last_idle
        report["terminal_observed_within_conservative_task_limit"] = time.monotonic() - last_idle <= plan["task_limit_ms"] / 1000
        # Result file can precede the main-thread terminal session persist. Wait
        # for that same task, without dispatching any phone command that mutates it.
        settle = time.monotonic() + 10
        while True:
            final_session = adb.app_json("files/control-session.json", optional=False)
            ordinary_session(final_session, uid, plan["instruction_sha256"], baseline_tasks, task_id)
            if final_session.get("running") is False and final_session.get("pending") is False:
                break
            need(time.monotonic() < settle, "terminal session did not settle")
            time.sleep(0.25)
        need(terminal.get("cleanup_known") is True and terminal.get("external_model") is False
             and terminal.get("automatic_replay") is False and final_session.get("status") == terminal["status"], "terminal cleanup/local/no-replay differs")
        stable = idle_snapshot(adb, uid, plan)
        need(stable["control"] == final_session, "terminal session changed")
        for name in JOURNALS[1:]:
            need(stable["hashes"][name] == first["hashes"][name], "diagnostic session changed")
        parent_identity(adb, parent)
        report["final_ui"] = [adb.png("final-1")]
        time.sleep(0.5)
        need(idle_snapshot(adb, uid, plan) == stable, "terminal journals changed after first screenshot")
        report["final_ui"].append(adb.png("final-2"))
        parent_identity(adb, parent)
        report["cleanup_known"] = True
        collection = acceptance.collect_evidence(adb, output, task_id, plan["instruction"], baseline_runs,
                                                False, uid, plan["candidate"]["compute"],
                                                plan["candidate"]["context_tokens"], plan["candidate"]["model_profile"])
        report["collection"] = collection
        report["qualification_scope_review"] = scope.review(output, qualification, task_id, plan["instruction"], collection)
        try:
            scope.session_binding(final_session, qualification)
        except ValueError as error:
            report["qualification_scope_review"]["verified"] = False
            report["qualification_scope_review"]["errors"].append(str(error))
        report["actions"] = suite.action_sequence(output, [], plan["instruction_sha256"])
        runs = collection["associated_runs"]
        native_binding = native_collection_binding(output, collection, parent, task_id, plan["instruction"], suite)
        report["native_file_binding"] = native_binding
        need(report.get("native_process_mode_observed") == native_binding["mode"], "live process mode differs from collected evidence")
        report["all_native_bindings_verified"] = True
        report["independent_accelerator_log_evidence"] = []
        for run in runs:
            receipt = strict(read(output / "runs" / run["run_id"] / "app-receipt.json"))
            need(receipt.get("app_pid") == parent["pid"] and receipt.get("expected_parent_pid") == parent["pid"]
                 and receipt.get("parent_death_guard_requested") is True and receipt.get("process_started") is True,
                 "collected native receipt belongs to a different App parent")
            log_id = native_binding["worker_generation"] if native_binding["mode"] == "warm" else run["run_id"]
            log_path = output / "runs" / log_id / "stderr.log"
            native_path = output / "runs" / run["run_id"] / "native-result.json"
            if log_path.is_file() and native_path.is_file():
                report["independent_accelerator_log_evidence"].append({"run_id": run["run_id"],
                    "log_scope": "same_owned_task_generation" if native_binding["mode"] == "warm" else "one_shot_run",
                    "log_directory_id": log_id,
                    "collector_accelerator_offload_observed": run.get("accelerator_offload_observed"),
                    **independent_accelerator_log(read(log_path), strict(read(native_path)), plan["candidate"]["compute"])})
        associated = {run["run_id"] for run in runs}
        validate_background_samples(output, report["background_samples"], native_binding, parent, warm_identity)
        report["background_verified"] = len(report["background_samples"]) >= args.minimum_background_samples
        report["background_scope"] = WARM_BACKGROUND_SCOPE if native_binding["mode"] == "warm" else "owned_one_shot_native_process_alive"
        report["warm_native_request_processing_background_verified"] = report["background_verified"] if native_binding["mode"] == "warm" else None
        need(idle_snapshot(adb, uid, plan) == stable, "state changed during evidence collection")
        need(set(adb.list_children("files/control-tasks", directories=True)) - baseline_tasks == {task_id}, "another task started during ordinary observation")
        final_run_directories(set(adb.list_children("files/runs", directories=True)) - baseline_runs, native_binding)
        parent_identity(adb, parent)
        # The screenshots were taken before collection. Capture one more after it
        # so Root sees the current terminal UI, not only a historical app snapshot.
        report["final_ui"].append(adb.png("final-current"))
        need(idle_snapshot(adb, uid, plan) == stable, "state changed around current final screenshot")
        parent_identity(adb, parent)
        report["clean_terminal_last_observed_wall_ms"] = int(time.time() * 1000)
        report["technical_evidence_complete"] = bool(report["all_native_bindings_verified"] and report["actions"]["evidence_complete"]
            and report["background_verified"] and report["qualification_scope_review"]["verified"])
        report["observation_status"] = "complete" if report["technical_evidence_complete"] else "unverified"
        report["task_status"] = terminal["status"]
        report["model_reported_success"] = terminal.get("model_reported_success")
    except Exception as error:
        report["errors"].append(type(error).__name__ + ": " + str(error))
        report["observation_status"] = "unverified"
        if report.get("cleanup_known") is True:
            report["earlier_clean_terminal_observed"] = True
        report["cleanup_known"] = None
    finally:
        report.update(finished_wall_ms=int(time.time() * 1000), phone_read_commands=adb.sequence,
                      transport_closed_after_error=adb.failed)
        save(output / "RESULT.json", report)
    print(json.dumps({key: report.get(key) for key in ("observation_status", "task_id", "task_status", "cleanup_known", "technical_evidence_complete", "goal_verified", "errors")}, ensure_ascii=False), flush=True)
    return 0 if report["technical_evidence_complete"] else 3


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    p = sub.add_parser("prepare")
    for name in ("source-dir", "candidate", "runtime-config", "instruction-file", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--driver-dir", type=Path, required=True)
    p.add_argument("--qualification-binding", type=Path, required=True)
    p.add_argument("--qualification-binding-sha256", required=True)
    p.add_argument("--apk-permission-proof", type=Path,
                   help="optional completed upgrade RESULT; exact APK-bound AAPT2 declaration evidence")
    p = sub.add_parser("observe")
    p.add_argument("--bundle", type=Path, required=True)
    p.add_argument("--bundle-sha256", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--adb", required=True)
    p.add_argument("--adb-host", default="127.0.0.1")
    p.add_argument("--adb-port", type=int, required=True)
    p.add_argument("--serial", required=True)
    p.add_argument("--logical-display-id", type=int, choices=(0,), required=True)
    p.add_argument("--physical-display-id", required=True)
    p.add_argument("--input-width", type=int, required=True)
    p.add_argument("--input-height", type=int, required=True)
    p.add_argument("--command-timeout", type=float, default=15)
    p.add_argument("--arm-timeout", type=float, default=120)
    p.add_argument("--poll-seconds", type=float, default=1)
    p.add_argument("--minimum-background-samples", type=int, default=3)
    args = parser.parse_args()
    if args.mode == "prepare":
        return prepare(args) or 0
    need(args.adb_host in ("127.0.0.1", "::1") and 1 <= args.adb_port <= 65535, "existing local ADB socket required")
    need(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", args.serial) and re.fullmatch(r"\d{1,20}", args.physical_display_id), "invalid device/display identity")
    need(0.1 <= args.command_timeout <= 30 and 1 <= args.arm_timeout <= 600 and 0.2 <= args.poll_seconds <= 5
         and 1 <= args.minimum_background_samples <= 10 and 0 < args.input_width <= 8192 and 0 < args.input_height <= 8192, "invalid observation bounds")
    return observe(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({"error": type(error).__name__ + ": " + str(error), "automatic_retry": False}), file=sys.stderr)
        sys.exit(3)
