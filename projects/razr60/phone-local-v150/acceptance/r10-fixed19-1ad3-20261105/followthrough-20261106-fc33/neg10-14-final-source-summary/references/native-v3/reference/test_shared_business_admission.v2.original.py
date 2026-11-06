#!/usr/bin/env python3
"""Current full-source host checks for selected NEG-12/13 business/admission paths.

All owner requests and native/public receipts are explicitly synthetic fixtures.
The real pinned CodexAdapter, candidate PhoneTools, and task_postconditions execute.
No PhoneLocalAdapter is constructed; its executor gate is neither replaced nor bypassed.
No provider completion loop, model client, subprocess, socket, or native dispatch is used.
"""
import argparse
import base64
import copy
import errno
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import resource
import secrets
import signal
import stat
import sys
import threading
import time
import traceback
import types
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
PINS_SHA = "8c15ed8eabefe9c2587cd4bbadd2738461b592eb30b103bd0c52ac14de83114a"
PACKAGE = "org.example.hepta.synthetic"
EDITOR = PACKAGE + ":id/editor"
PUBLIC = PACKAGE + ":id/receipt"
APP = PACKAGE + "/.FixtureActivity"
OUT = None
DENIED = []
OBS = GUARDS = CONTRACT = CODEX = OPENAI = DAILY = PHONE = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def mkdir(path):
    path.mkdir(mode=0o700)
    return path


def write_new(path, value):
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    assert path.read_bytes() == raw
    return {"bytes": len(raw), "sha256": sha(raw)}


def audit(event, args):
    denied = event in {
        "socket.__new__", "socket.connect", "socket.bind", "socket.getaddrinfo",
        "subprocess.Popen", "os.system", "os.fork", "os.forkpty", "os.posix_spawn",
        "os.exec", "pty.spawn",
    }
    paths = []
    if event == "open" and len(args) > 2 and isinstance(args[0], (str, bytes, os.PathLike)):
        flags = args[2]
        if isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            paths = [args[0]]
    elif event in {"os.mkdir", "os.remove", "os.rmdir", "os.chmod", "os.rename"}:
        paths = args[:2] if event == "os.rename" else args[:1]
    for path in paths:
        if isinstance(path, (str, bytes, os.PathLike)):
            resolved = os.path.abspath(os.fsdecode(path))
            if not (resolved == str(OUT) or resolved.startswith(str(OUT) + os.sep)):
                denied = True
    if denied:
        DENIED.append({"event": event, "denied": True})
        raise PermissionError("host-only regression denied network/process/outside write: " + event)


def pinned(path, length, digest):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == length
        chunks = []
        count = 0
        while True:
            block = os.read(fd, min(65536, length + 1 - count))
            if not block:
                break
            chunks.append(block)
            count += len(block)
            assert count <= length
        raw = b"".join(chunks)
        after, named = os.fstat(fd), path.lstat()
        fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns")
        assert all(getattr(before, field) == getattr(after, field) == getattr(named, field) for field in fields)
        assert len(raw) == length and sha(raw) == digest
        return raw
    finally:
        os.close(fd)


def verify_sources(package):
    pins_raw = (package / "CANDIDATE-PINS.json").read_bytes()
    assert sha(pins_raw) == PINS_SHA
    pins = json.loads(pins_raw)
    assert pins["production_source_count"] == pins["candidate_source_count"] == 15
    assert pins["changed_source_files"] == ["daily_phone_local.py", "phone_local_tools.py", "phone_observation_tools.py"]
    assert pins["adopted"] is False and pins["whole_NEG12_qualified"] is False and pins["whole_NEG13_qualified"] is False
    files = {}
    for row in pins["files"]:
        files[row["path"]] = pinned(package / row["path"], row["bytes"], row["sha256"])
    originals = {Path(path).name: raw for path, raw in files.items() if path.startswith("reference/production/")}
    candidate = {Path(path).name: raw for path, raw in files.items() if path.startswith("candidate/source/")}
    assert len(originals) == len(candidate) == 15 and set(originals) == set(candidate)
    assert [name for name in sorted(originals) if originals[name] != candidate[name]] == pins["changed_source_files"]
    assert sha(candidate["phone_observation_tools.py"]) == "ec015260f64e2c61c8f9953f6abe0d8dc4a7a62ce86943ce3c9cfcd250c35162"
    assert sha(candidate["daily_phone_local.py"]) == "203862a29023c827804d4e2a7ccc0217f917f789f49272dc09f4ab64ec029027"
    comb = pins["current_combination"]
    pinned(package / comb["archived_path"], comb["bytes"], comb["sha256"])
    old = pins["reference_runner"]
    pinned(package / old["path"], old["bytes"], old["sha256"])
    return pins, files


def resources():
    root = "/proc/self/fd" if Path("/proc/self/fd").is_dir() else "/dev/fd"
    fds = {}
    for name in os.listdir(root):
        if not name.isdigit():
            continue
        try:
            info = os.fstat(int(name))
        except OSError as error:
            if error.errno == errno.EBADF:
                continue
            raise
        fds[name] = [info.st_dev, info.st_ino, info.st_mode]
    own = resource.getrusage(resource.RUSAGE_SELF)
    child = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {"fds": fds, "threads": sorted((t.name, t.ident, t.is_alive()) for t in threading.enumerate()),
            "child_user_seconds": child.ru_utime, "child_system_seconds": child.ru_stime,
            "maxrss_lifetime": own.ru_maxrss, "rss_return_to_baseline_claimed": False}


def identity():
    return {"session_id": "synthetic-session-" + secrets.token_hex(12), "profile_id": "synthetic-host-only",
            "task_id": "synthetic-task-" + secrets.token_hex(12), "turn_id": "synthetic-turn-" + secrets.token_hex(12),
            "turn_stream_id": "synthetic-stream-" + secrets.token_hex(12)}


def contracts_tree(path):
    mkdir(path)
    mkdir(path / "templates")
    mkdir(path / "bindings")
    return path


def template(who, request, nonce, conditions, coverage="entire_request"):
    owner_sha = CONTRACT.request_hash(request)
    return {"schema": "hepta.task-template.v150.3",
            "expected_scope": {name: who[name] for name in ("session_id", "profile_id")},
            "request_sha256": owner_sha, "nonce": nonce, "coverage": coverage, "postconditions": conditions,
            "app_scope": {"schema": "hepta.task-app-scope.v1", "owner_request_sha256": owner_sha,
                          "apps": [{"alias": "synthetic_fixture", "component": APP}]}}


def b64(value):
    return base64.b64encode(value if isinstance(value, bytes) else value.encode()).decode()


def page(component=APP):
    return ("Display: mDisplayId=0\nmTopFocusedDisplayId=0\n"
            "mCurrentFocus=Window{synthetic u0 " + component + "}\n"
            "mFocusedApp=ActivityRecord{synthetic u0 " + component + "}\n"
            "isKeyguardShowing=false\ntopResumedActivity=ActivityRecord{synthetic u0 " + component + "}\n")


def viewport():
    return ("DisplayViewport{type=INTERNAL, valid=true, isActive=true, displayId=0, uniqueId='local:"
            + OBS.PHYSICAL_DISPLAY
            + "', orientation=0, logicalFrame=Rect(0, 0 - 1224, 2992), physicalFrame=Rect(0, 0 - 1224, 2992)}")


def native(call_id, raw, tool):
    # Explicitly synthetic current-schema receipt, matching observed NEG01
    # event/terminal field sets. This does not attest a physical execution.
    terminal = {"kind": "exited", "exit_code": 0, "signal": None, "stdout_bytes": len(raw),
                "stderr_bytes": 0, "output_truncated": False, "elapsed_ms": 7, "error": None}
    events = [{"kind": "accepted"}, {"kind": "started", "pid": 12345},
              {"kind": "output", "stream": "stdout", "encoding": "base64",
               "data": b64(raw), "byte_count": len(raw)},
              {"kind": "terminal", "terminal": copy.deepcopy(terminal)}]
    return {"call_id": call_id, "status": "terminal", "terminal": terminal,
            "registry": {"call_id": call_id, "tool": tool, "target_id": None,
                         "request_sha256": "0" * 64, "binding_fingerprint": "1" * 64,
                         "state": "SYNTHETIC terminal fixture",
                         "cancellation_requested": False, "connection_lost": False,
                         "earliest_history_seq": 0, "next_event_seq": 4},
            "generation": 1, "observation_sha256": "2" * 64,
            "events": [{"call_id": call_id, "target_id": None, "tool": tool,
                        "seq": i, "elapsed_ms": i * 2, "event": event}
                       for i, event in enumerate(events)]}

def input_payload(call):
    requested = call["requested_text"].encode()
    return {"schema": "hepta.focused-unicode-input.v1", "status": "set_verified",
            "operation_id": call["call_id"], "display_id": 0, "package": call["package"], "view_id": call["view_id"],
            "requested_utf8_sha256": sha(requested), "before_utf8_sha256": sha(call["expected_text"].encode()),
            "after_utf8_sha256": sha(requested), "own_automation_disconnected": True,
            "action_attempted": True, "effect_state": "observed_exact_requested_text",
            "readback_text_b64": b64(requested)}


def public_payload(token, text):
    root = ET.Element("hierarchy", rotation="0")
    ET.SubElement(root, "node", {"resource-id": PUBLIC, "package": PACKAGE, "password": "false",
                              "enabled": "true", "visible-to-user": "true", "bounds": "[10,20][200,100]", "text": text})
    return {"schema": "hepta.public-text-receipt.v149.1", "operation_id": token, "package": PACKAGE,
            "page_before_b64": b64(page()), "page_after_b64": b64(page()),
            "viewport_before_b64": b64(viewport()), "viewport_after_b64": b64(viewport()),
            "xml_b64": b64(ET.tostring(root, encoding="unicode"))}


def return_payload(token):
    return {"schema": "hepta.return-receipt.v149.1", "operation_id": token, "launch_exit_code": 0,
            "launch_b64": b64("Status: ok\nActivity: " + GUARDS.HEPTA_COMPONENT + "\n"),
            "page_b64": b64(page(GUARDS.HEPTA_COMPONENT)), "viewport_b64": b64(viewport())}


def prepare_one(tools, call, value, round_number):
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    message = {"role": "tool", "tool_call_id": call["call_id"], "content": raw}
    return tools.prepare([message], [copy.deepcopy(message)], round_number)


def claim_snapshot(path):
    return {item.name: item.read_bytes() for item in path.iterdir()}


def rejected(operation, contains):
    try:
        operation()
    except OPENAI.ProviderError as error:
        assert contains in str(error), str(error)
        return {"error_type": type(error).__name__, "message": str(error), "rejected": True}
    raise AssertionError("real ProviderError rejection expected: " + contains)


def close_adapter(adapter, source, sink, writer):
    if adapter is not None:
        adapter.frames.close()
        adapter.inputs.close()
    if writer is not None:
        os.close(writer)
    if source is not None:
        source.close()
    if sink is not None:
        sink.close()


def business_case(label, results, donor):
    directory = mkdir(OUT / ("SYNTHETIC-NEG12-" + label))
    state = mkdir(directory / "state")
    evidence = mkdir(state / "evidence")
    mkdir(evidence / "claims")
    contracts = contracts_tree(state / "task-contracts")
    run = mkdir(evidence / "run")
    who = identity()
    nonce = secrets.token_hex(16)
    requested = "主机合成输入 中文😀\nHEPTA " + nonce
    owner = "SYNTHETIC HOST-ONLY REQUEST: " + requested
    public = "主机合成确认 " + requested
    conditions = [
        {"id": "input", "kind": "text_readback_exact", "package": PACKAGE, "view_id": EDITOR, "utf8_sha256": sha(requested.encode())},
        {"id": "public", "kind": "public_text_exact", "package": PACKAGE, "view_id": PUBLIC, "utf8_sha256": sha(public.encode())},
        {"id": "return", "kind": "foreground_hepta"},
    ]
    coverage = "declared_postconditions_only" if label == "partial_coverage" else "entire_request"
    templ = template(who, owner, nonce, conditions, coverage)
    template_path = contracts / "templates" / (CONTRACT.request_hash(owner) + ".json")
    CONTRACT.write_exclusive(template_path, templ)
    frame = {"protocol": OPENAI.PROTOCOL, "kind": "turn.start", "seq": 0, "turn": dict(who, user_input=owner)}
    fixture = {"synthetic": True, "owner_and_public_data_generated_by_host_test": True,
               "physical_observation": False, "model_status_is_test_input": True,
               "owner_frame": frame, "task_template": templ, "planned_mapping_and_receipts": []}
    rfd, writer = os.pipe()
    source = os.fdopen(rfd, "rb", buffering=0)
    sink = open(directory / "wire.jsonl", "x", encoding="utf-8")
    adapter = None
    try:
        wire_input = canonical(frame) + b"\n"
        assert len(wire_input) < 4096
        assert os.write(writer, wire_input) == len(wire_input)
        adapter = CODEX.CodexAdapter(types.SimpleNamespace(evidence=evidence, contracts=contracts), source, sink, run)
        received = adapter.receive("turn.start", timeout=1)
        assert received == frame and adapter.claimed and adapter.accepted_identity == who
        assert type(adapter.phone_tools) is OBS.PhoneTools
        assert adapter.task_contract["contract"]["schema"] == "hepta.task-contract.v150.3"
        adapter.model_task_status = "completed"
        decisions = [
            {"call_id": "input_" + secrets.token_hex(10), "tool": "phone.input_text", "command": requested, "argv": [PACKAGE, EDITOR, ""]},
            {"call_id": "public_" + secrets.token_hex(10), "tool": "phone.read_text", "command": "", "argv": [PACKAGE, PUBLIC]},
            {"call_id": "return_" + secrets.token_hex(10), "tool": "phone.return_hepta", "command": "", "argv": []},
        ]
        for number, decision in enumerate(decisions, 1):
            adapter.phone_tools.map(decision)
            call = adapter.phone_tools.calls[decision["call_id"]]
            kind = decision["tool"]
            omitted = ((label == "missing_confirmation" and kind == "phone.input_text")
                       or (label == "missing_public" and kind == "phone.read_text")
                       or (label == "missing_return" and kind == "phone.return_hepta"))
            entry = {"synthetic": True, "mapped_not_dispatched": True, "decision": decision, "mapped_call": call,
                     "receipt_omitted": omitted}
            if omitted:
                assert call["call_id"] not in adapter.phone_tools.verified_facts
                fixture["planned_mapping_and_receipts"].append(entry)
                continue
            if kind == "phone.input_text":
                payload = input_payload(call)
                if label == "invalid_confirmation":
                    del payload["readback_text_b64"]
            elif kind == "phone.read_text":
                payload = public_payload(call["capture_id"], public + " WRONG" if label == "wrong_public" else public)
            else:
                payload = return_payload(call["capture_id"])
                if label == "wrong_return":
                    payload["launch_b64"] = b64("Status: ok\nActivity: org.example.hepta.other/.ElseActivity\n")
            reply = native(call["call_id"], canonical(payload), call["wire_tool"])
            entry["synthetic_payload"] = payload
            entry["synthetic_native_result"] = reply
            if label == "invalid_confirmation" and kind == "phone.input_text":
                entry["actual_parser_rejection"] = rejected(
                    lambda: prepare_one(adapter.phone_tools, call, reply, number), "readback field is absent")
                assert call["call_id"] not in adapter.phone_tools.verified_facts
            elif label == "wrong_return" and kind == "phone.return_hepta":
                entry["actual_parser_rejection"] = rejected(
                    lambda: prepare_one(adapter.phone_tools, call, reply, number), "different target")
                assert call["call_id"] not in adapter.phone_tools.verified_facts
            else:
                prepare_one(adapter.phone_tools, call, reply, number)
                assert call["call_id"] in adapter.phone_tools.verified_facts
            fixture["planned_mapping_and_receipts"].append(entry)
        assert adapter.dispatched_calls == set() and adapter.tool_count == 0
        assert len(adapter.phone_tools.calls) == 3
        adapter.emit("turn.complete", summary="SYNTHETIC host fixture says completed; no model was invoked.")
        sink.flush()
        os.fsync(sink.fileno())
        outcome = json.loads((run / "business-outcome.json").read_bytes())
        terminal = json.loads((run / "terminal.json").read_bytes())
        raw_wire = (directory / "wire.jsonl").read_bytes()
        wire = [json.loads(line) for line in raw_wire.splitlines()]
        assert len(wire) == 1 and (run / "provider-out.jsonl").read_bytes() == raw_wire
        expected_missing = {
            "missing_confirmation": ["input"], "invalid_confirmation": ["input"],
            "missing_public": ["public"], "wrong_public": ["public"],
            "missing_return": ["return"], "wrong_return": ["return"],
            "partial_coverage": [], "complete_control": [],
        }[label]
        assert outcome["missing_postconditions"] == expected_missing
        expected_terminal = "turn.complete" if label == "complete_control" else "turn.fail"
        assert wire[0]["kind"] == terminal["kind"] == outcome["emitted_protocol_terminal"] == expected_terminal
        assert outcome["business_verified"] is (label == "complete_control")
        assert outcome["native_completed_is_business_success"] is False
        if expected_terminal == "turn.fail":
            assert "[business_not_verified]" in wire[0]["error"] and terminal["error"] == wire[0]["error"]
            for missing in expected_missing:
                assert missing in wire[0]["error"]
        else:
            assert "明确后条件" in wire[0]["summary"]
        if label == "partial_coverage":
            assert outcome["postconditions_verified"] is True and outcome["coverage"] == "declared_postconditions_only"
        claims, bindings = claim_snapshot(evidence / "claims"), claim_snapshot(contracts / "bindings")
        assert len(claims) == len(bindings) == 1
        protected = {name: (run / name).read_bytes() for name in ("business-outcome.json", "terminal.json", "provider-out.jsonl")}
        second_terminal = rejected(lambda: adapter.emit("turn.complete", summary="late synthetic completion"), "already persisted a terminal")
        assert all((run / name).read_bytes() == raw for name, raw in protected.items())
        fixture_pin = write_new(directory / "SYNTHETIC-INPUTS.json", fixture)
        row = {"name": label, "scope": "NEG12_SELECTED_SHARED_BUSINESS_GATE", "passed": True,
               "synthetic_inputs": True, "expected_terminal": expected_terminal,
               "actual_terminal": wire[0], "missing_postconditions": outcome["missing_postconditions"],
               "business_outcome": outcome, "persisted_terminal": terminal,
               "fixture_file": {"path": str((directory / "SYNTHETIC-INPUTS.json").relative_to(OUT)), **fixture_pin},
               "claims": [{"name": name, "sha256": sha(raw)} for name, raw in claims.items()],
               "bindings": [{"name": name, "sha256": sha(raw)} for name, raw in bindings.items()],
               "late_terminal_rejected_without_rewrite": second_terminal,
               "actual_native_dispatches": 0, "model_requests": 0, "phone_calls": 0}
        write_new(directory / "RESULT.json", row)
        results.append(row)
        if label == "missing_confirmation":
            donor.update(who=who, request=owner, evidence=evidence, contracts=contracts, claims=claims, bindings=bindings)
    finally:
        close_adapter(adapter, source, sink, writer)


def wrong_nonce_case(label, results):
    directory = mkdir(OUT / ("SYNTHETIC-NEG13-" + label))
    contracts = contracts_tree(directory / "contracts")
    who, nonce = identity(), secrets.token_hex(16)
    if label == "nonce_missing":
        request = "SYNTHETIC nonce absent request"
    elif label == "nonce_duplicate":
        request = "SYNTHETIC duplicate " + nonce + " and " + nonce
    else:
        request = "SYNTHETIC owner binding " + nonce
    value = template(who, request, nonce, [{"id": "return", "kind": "foreground_hepta"}])
    if label == "request_digest_mismatch":
        value["request_sha256"] = "0" * 64
    elif label == "app_scope_owner_mismatch":
        value["app_scope"]["owner_request_sha256"] = "0" * 64
    path = contracts / "templates" / (CONTRACT.request_hash(request) + ".json")
    CONTRACT.write_exclusive(path, value)
    before = path.read_bytes()
    error = rejected(lambda: CONTRACT.load_contract(contracts, who, request),
                     "scope" if label in {"request_digest_mismatch", "app_scope_owner_mismatch"} else "nonce")
    assert path.read_bytes() == before and list((contracts / "bindings").iterdir()) == []
    row = {"name": label, "scope": "NEG13_SELECTED_TEMPLATE_PRECONDITIONS", "passed": True,
           "synthetic_inputs": True, "identity": who, "request": request, "template": value,
           "template_sha256": sha(before), "actual_rejection": error,
           "binding_count": 0, "template_unchanged": True, "native_dispatches": 0}
    write_new(directory / "RESULT.json", row)
    results.append(row)


def template_race(results):
    directory = mkdir(OUT / "SYNTHETIC-NEG13-real-exclusive-binding-race")
    contracts = contracts_tree(directory / "contracts")
    who, nonce = identity(), secrets.token_hex(16)
    request = "SYNTHETIC one-use concurrent request " + nonce
    value = template(who, request, nonce, [{"id": "return", "kind": "foreground_hepta"}])
    path = contracts / "templates" / (CONTRACT.request_hash(request) + ".json")
    CONTRACT.write_exclusive(path, value)
    original_template = path.read_bytes()
    wrong_scopes = []
    for field in ("session_id", "profile_id"):
        wrong = dict(who)
        wrong[field] = "synthetic-wrong-" + secrets.token_hex(12)
        failure = rejected(lambda wrong=wrong: CONTRACT.load_contract(contracts, wrong, request), "known scope differs")
        assert list((contracts / "bindings").iterdir()) == [] and path.read_bytes() == original_template
        wrong_scopes.append({"field": field, "identity": wrong, "rejection": failure, "bindings_after": 0})
    barrier = threading.Barrier(2, timeout=2)
    lock = threading.Lock()
    outcomes = []
    def attempt(index):
        contender = dict(who, task_id="synthetic-task-" + secrets.token_hex(12),
                         turn_id="synthetic-turn-" + secrets.token_hex(12),
                         turn_stream_id="synthetic-stream-" + secrets.token_hex(12))
        try:
            barrier.wait()
            result = CONTRACT.load_contract(contracts, contender, request)
            row = {"index": index, "accepted": True, "identity": contender, "contract_result": result}
        except BaseException as error:
            row = {"index": index, "accepted": False, "identity": contender,
                   "error_type": type(error).__name__, "error": str(error)}
        with lock:
            outcomes.append(row)
    threads = [threading.Thread(target=attempt, args=(i,), name="host-template-race-" + str(i), daemon=True) for i in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(3)
    assert all(not thread.is_alive() for thread in threads)
    assert len(outcomes) == 2 and sum(row["accepted"] for row in outcomes) == 1
    loser = next(row for row in outcomes if not row["accepted"])
    assert loser["error_type"] == "ProviderError" and "already consumed" in loser["error"]
    winner = next(row for row in outcomes if row["accepted"])
    assert winner["contract_result"]["binding_kind"] == "one_time_request_template"
    assert winner["contract_result"]["contract"]["schema"] == "hepta.task-contract.v150.3"
    bindings = claim_snapshot(contracts / "bindings")
    assert len(bindings) == 1 and path.read_bytes() == original_template
    bound = json.loads(next(iter(bindings.values())))
    assert bound["state"] == "consumed_no_reuse"
    assert bound["identity"] == {key: winner["identity"][key] for key in CONTRACT.IDENTITY}
    assert bound["nonce"] == nonce
    assert bound["app_scope_sha256"] == CONTRACT.app_scope_hash(value["app_scope"])
    replay_inputs = [
        ("same_identity", winner["identity"]),
        ("replacement_stream", dict(winner["identity"], turn_stream_id="synthetic-replacement-" + secrets.token_hex(8))),
        ("new_turn_old_nonce", dict(who, task_id="synthetic-new-task-" + secrets.token_hex(8),
                                    turn_id="synthetic-new-turn-" + secrets.token_hex(8))),
    ]
    replays = []
    for name, replay in replay_inputs:
        failure = rejected(lambda replay=replay: CONTRACT.load_contract(contracts, replay, request), "already consumed")
        assert claim_snapshot(contracts / "bindings") == bindings and path.read_bytes() == original_template
        replays.append({"name": name, "identity": replay, "actual_rejection": failure})
    apps, scope = CONTRACT.resolve_task_apps(winner["contract_result"], CONTRACT.request_hash(request),
                                            {"synthetic_fixture": {"component": APP}})
    assert apps == {"synthetic_fixture": {"component": APP}}
    assert scope["mode"] == "request_bound_explicit_subset"
    row = {"name": "real_exclusive_binding_race", "scope": "NEG13_SELECTED_REAL_FILESYSTEM_CONCURRENCY",
           "passed": True, "synthetic_inputs": True, "template": value, "request": request,
           "wrong_scopes_before_race": wrong_scopes, "outcomes": sorted(outcomes, key=lambda r: r["index"]),
           "threads_joined": True, "real_binding_files": 1, "binding_original": bound,
           "binding_sha256": sha(next(iter(bindings.values()))), "replays": replays,
           "template_sha256": sha(original_template), "template_and_binding_unchanged_after_replays": True,
           "native_dispatches": 0}
    write_new(directory / "RESULT.json", row)
    results.append(row)


def old_identity_admission(results, donor):
    assert donor
    directory = mkdir(OUT / "SYNTHETIC-NEG13-old-identity-admission")
    attempts = []
    for label, who in [
        ("exact_old_identity", donor["who"]),
        ("replacement_stream", dict(donor["who"], turn_stream_id="synthetic-new-stream-" + secrets.token_hex(12))),
    ]:
        run = mkdir(directory / label)
        frame = {"protocol": OPENAI.PROTOCOL, "kind": "turn.start", "seq": 0,
                 "turn": dict(who, user_input=donor["request"])}
        rfd, writer = os.pipe()
        source = os.fdopen(rfd, "rb", buffering=0)
        sink = open(run / "wire.jsonl", "x", encoding="utf-8")
        adapter = None
        try:
            encoded = canonical(frame) + b"\n"
            assert os.write(writer, encoded) == len(encoded)
            adapter = CODEX.CodexAdapter(
                types.SimpleNamespace(evidence=donor["evidence"], contracts=donor["contracts"]), source, sink, run)
            error = rejected(lambda: adapter.receive("turn.start", timeout=1), "identity already accepted")
            assert not adapter.claimed and adapter.accepted_identity is None
            assert adapter.dispatched_calls == set() and adapter.tool_count == 0 and adapter.phone_tools.calls == {}
            sink.flush()
            assert (run / "wire.jsonl").read_bytes() == b"" and (run / "provider-out.jsonl").read_bytes() == b""
            assert claim_snapshot(donor["evidence"] / "claims") == donor["claims"]
            assert claim_snapshot(donor["contracts"] / "bindings") == donor["bindings"]
            attempts.append({"name": label, "synthetic_owner_frame": frame, "actual_rejection": error,
                             "outgoing_frames": 0, "mapped_calls": 0, "native_dispatches": 0})
        finally:
            close_adapter(adapter, source, sink, writer)
    row = {"name": "old_identity_real_pipe_admission", "scope": "NEG13_SELECTED_REAL_ADAPTER_ADMISSION",
           "passed": True, "synthetic_inputs": True, "attempts": attempts,
           "original_failed_turn_claim_and_binding_unchanged": True}
    write_new(directory / "RESULT.json", row)
    results.append(row)


def main():
    global OUT, OBS, GUARDS, CONTRACT, CODEX, OPENAI, DAILY, PHONE
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--package-root", type=Path, default=Path(__file__).resolve().parent)
    ap.add_argument("--out", type=Path, required=True, help="Fresh private output directory.")
    args = ap.parse_args()
    package = args.package_root.resolve()
    pins, initial = verify_sources(package)
    assert args.out.is_absolute() and args.out.parent.resolve() == args.out.parent
    os.umask(0o077)
    OUT = args.out
    mkdir(OUT)
    source = package / "candidate/source"
    sys.addaudithook(audit)
    sys.path.insert(0, str(source))
    imported = []
    for row in pins["files"]:
        if not row["path"].startswith("candidate/source/"):
            continue
        name = Path(row["path"]).stem
        assert name not in sys.modules or Path(sys.modules[name].__file__).resolve().parent == source
    # Import daily first: its unmodified PARENTS verifier checks all 14 dependencies.
    DAILY = importlib.import_module("daily_phone_local")
    for row in pins["files"]:
        if not row["path"].startswith("candidate/source/"):
            continue
        module = importlib.import_module(Path(row["path"]).stem)
        path = Path(module.__file__).resolve()
        assert path == package / row["path"]
        assert sha(path.read_bytes()) == row["sha256"]
        imported.append({"path": row["path"], "bytes": row["bytes"], "sha256": row["sha256"]})
    OBS = importlib.import_module("phone_observation_tools")
    GUARDS = importlib.import_module("phone_task_guards")
    CONTRACT = importlib.import_module("task_postconditions")
    CODEX = importlib.import_module("provider_codex_host")
    OPENAI = importlib.import_module("provider_openai_compatible")
    PHONE = importlib.import_module("provider_phone_local")
    assert len(imported) == 15 and issubclass(PHONE.PhoneLocalAdapter, CODEX.CodexAdapter)
    assert issubclass(DAILY.DailyAdapter, PHONE.PhoneLocalAdapter)
    write_new(OUT / "ACTUAL-IMPORTED-SOURCES.json", {"source_count": 15, "files": imported,
              "daily_parent_pin_verifier_executed": True, "PhoneLocalAdapter_constructed": False})
    write_new(OUT / "SYNTHETIC-SCOPE.json", {
        "schema": "razr60-shared-business-host-fixture-scope/v1",
        "all_owner_requests_and_native_public_receipts_are_synthetic": True,
        "actual_functions": ["CodexAdapter.receive", "CodexAdapter.emit", "PhoneTools.map", "PhoneTools.prepare",
                             "native_streams", "load_contract", "write_exclusive", "evaluate", "terminal_fields"],
        "real_filesystem_and_pipe_operations": True, "real_O_EXCL_thread_competition": True,
        "PhoneLocalAdapter_constructed": False, "validate_executor_bypassed_or_modified": False,
        "phone_calls": 0, "model_requests": 0, "native_dispatches": 0,
        "whole_NEG12_qualified": False, "whole_NEG13_qualified": False, "candidate_adopted": False,
    })
    before = resources()
    started = time.monotonic()
    previous = signal.getsignal(signal.SIGALRM)
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
    def timeout(_signal, _frame):
        raise TimeoutError("shared-source host regression 50-second deadline")
    signal.signal(signal.SIGALRM, timeout)
    signal.setitimer(signal.ITIMER_REAL, 50)
    rows, donor, fatal = [], {}, None
    try:
        for label in ("missing_confirmation", "invalid_confirmation", "missing_public", "wrong_public",
                      "missing_return", "wrong_return", "partial_coverage", "complete_control"):
            business_case(label, rows, donor)
        for label in ("nonce_missing", "nonce_duplicate", "request_digest_mismatch", "app_scope_owner_mismatch"):
            wrong_nonce_case(label, rows)
        template_race(rows)
        old_identity_admission(rows, donor)
        after_pins, final = verify_sources(package)
        assert pins == after_pins and initial == final
    except BaseException as error:
        fatal = {"error_type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    after = resources()
    restored = (before["fds"] == after["fds"] and before["threads"] == after["threads"]
                and before["child_user_seconds"] == after["child_user_seconds"]
                and before["child_system_seconds"] == after["child_system_seconds"])
    passed = fatal is None and len(rows) == 14 and restored and not DENIED and all(row["passed"] for row in rows)
    result = {
        "schema": "razr60-current-shared-neg12-neg13-host-regression/v1",
        "status": "SELECTED_HOST_CHECKS_PASSED" if passed else "FAILED",
        "whole_NEG12_qualified": False, "whole_NEG13_qualified": False,
        "candidate_adopted": False, "phone_business_qualified": False,
        "pins_sha256": PINS_SHA, "actual_imported_source_count": len(imported),
        "script": {"bytes": len(Path(__file__).read_bytes()), "sha256": sha(Path(__file__).read_bytes())},
        "host": {"system": platform.system(), "python": platform.python_version()},
        "scenario_count": len(rows), "expected_scenario_count": 14,
        "resources": {"before": before, "after": after, "fd_thread_child_cpu_baseline_restored": restored},
        "audit_denied_events": DENIED, "fatal_error": fatal, "cases": rows,
        "elapsed_seconds": time.monotonic() - started,
        "phone_calls": 0, "model_requests": 0, "native_dispatches": 0,
        "actual_network_or_process_operations": 0 if not DENIED else None,
        "all_owner_and_public_receipts_are_synthetic": True,
        "limits": [
            "Full15 native v2 candidate pinned/imported; observation parser and eight existing callsites change, with daily two dependency pins; other twelve sources remain exact.",
            "Tests execute real shared business/admission implementations against explicitly synthetic owner/native/public fixtures.",
            "Real pipes, durable files, fsync, O_EXCL and two actual competing threads are used.",
            "No PhoneLocalAdapter or DailyAdapter instance is constructed; the fixed executor client gate is not bypassed.",
            "No model, native tool frame, phone transport, public UI, installed runtime, or source adoption is exercised.",
            "The complete-control fixture may report business_verified inside the fixture; it is not phone business evidence.",
            "Historical SOURCE-SEAL, runtime, and accepted production identities are not altered.",
        ],
    }
    pin = write_new(OUT / "RESULT.json", result)
    print(json.dumps({"status": result["status"], "scenario_count": len(rows), "result": pin,
                      "out": str(OUT), "script": result["script"], "fatal_error": fatal,
                      "source_count": len(imported), "whole_NEG12_qualified": False,
                      "whole_NEG13_qualified": False, "phone_calls": 0, "model_requests": 0,
                      "native_dispatches": 0, "resources_restored": restored}, ensure_ascii=False, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
