#!/usr/bin/env python3
"""Offline host regressions for the exact current native_streams candidate.

Loads selected AST definitions from the archived originals and candidate.
Does not import or start provider main, workers, model clients, or device tools.
NEG-14 tests cover only the listed rename/I/O/resource checks.
"""
import argparse
import ast
import base64
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import shlex
import stat
import struct
import sys
import tempfile
import threading
import time

PINS = {
    "reference/phone_observation_tools.original.py": (43445, "2c5ebb75e34fcce4c14638939809dade1f6d129504270930c8f94e2c2ce15b66"),
    "source/phone_observation_tools.py": (43954, "22580b8aa22d5c0ab4040888872e642a5176042023dd7bcf50e67efe51248409"),
    "reference/daily_phone_local.original.py": (22059, "ca23c60bbb4114960c6a571492cacd9e0bdc3404191409ac78bcf0c34a06c1d0"),
    "source/daily_phone_local.py": (22059, "689db3908014940a1e39689b966d30ab16ac6f9c0d7892becf1718b9840c824f"),
}
OBS_CONSTANTS = {
    "SERIAL", "PHYSICAL_DISPLAY", "ORIGINAL_SIZE", "MAX_IMAGE_BYTES",
    "MAX_TURN_IMAGE_BYTES", "MIN_IMAGE_BUDGET", "SCREEN_JAR_SHA256",
    "SAFE_CALL", "SHA256",
}
CALL_ID = "offline-native-case"


class ProviderError(Exception):
    pass


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load_parts(raw, filename, functions, classes=(), constants=()):
    tree = ast.parse(raw.decode("utf-8"), filename)
    selected = []
    found = set()
    for node in tree.body:
        name = getattr(node, "name", None)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and name in functions:
            selected.append(node)
            found.add(name)
        elif isinstance(node, ast.ClassDef) and name in classes:
            selected.append(node)
            found.add(name)
        elif isinstance(node, ast.Assign):
            names = {n.id for n in node.targets if isinstance(n, ast.Name)}
            if names and names <= set(constants):
                selected.append(node)
                found.update(names)
    assert set(functions) | set(classes) | set(constants) == found
    namespace = {
        "__name__": "offline_selected_source",
        "ProviderError": ProviderError, "base64": base64, "hashlib": hashlib,
        "json": json, "os": os, "Path": Path, "re": re, "shlex": shlex,
        "stat": stat, "struct": struct, "time": time,
    }
    exec(compile(ast.Module(body=selected, type_ignores=[]), filename, "exec"), namespace)
    return namespace


def reply(chunks=(b"ok",), minimal=False):
    raw = b"".join(chunks)
    terminal = {
        "kind": "exited", "exit_code": 0, "signal": None,
        "stdout_bytes": len(raw), "stderr_bytes": 0,
        "output_truncated": False, "elapsed_ms": 7, "error": None,
    }
    if minimal:
        del terminal["signal"]
        del terminal["elapsed_ms"]
    events = [{"kind": "accepted"}, {"kind": "started", "pid": 1234}]
    for block in chunks:
        events.append({
            "kind": "output", "stream": "stdout", "encoding": "base64",
            "data": base64.b64encode(block).decode("ascii"), "byte_count": len(block),
        })
    events.append({"kind": "terminal", "terminal": copy.deepcopy(terminal)})
    return {
        "call_id": CALL_ID, "status": "terminal", "terminal": terminal,
        "events": [{"call_id": CALL_ID, "tool": "adb.exec", "seq": i, "event": event}
                   for i, event in enumerate(events)],
    }


def reseq(value):
    for i, event in enumerate(value["events"]):
        event["seq"] = i
    return value


def parse_outcome(namespace, value, expected_tool="adb.exec"):
    try:
        raw = namespace["native_streams"](copy.deepcopy(value), CALL_ID, expected_tool)
    except ProviderError as error:
        return {"accepted": False, "error_type": type(error).__name__, "message": str(error)}
    return {"accepted": True, "bytes": len(raw), "sha256": digest(raw), "utf8": raw.decode("utf-8")}


def parser_cases():
    cases = []
    def add(name, value, accepted, original_accepted=None, expected=None, tool="adb.exec"):
        cases.append((name, value, accepted, accepted if original_accepted is None else original_accepted, expected, tool))
    add("valid_full_terminal", reply(), True, expected=b"ok")
    add("valid_empty_stdout", reply(chunks=()), True, expected=b"")
    chunks = ["中文".encode(), "😀".encode(), b"\nHEPTA"]
    add("valid_multichunk_chinese_emoji_lf", reply(chunks), True, expected=b"".join(chunks))
    add("valid_historical_minimal_terminal", reply(minimal=True), True, expected=b"ok")
    v = reply()
    v["events"][1], v["events"][2] = v["events"][2], v["events"][1]
    add("output_before_started", reseq(v), False, True)
    v = reply()
    v["events"].insert(2, copy.deepcopy(v["events"][1]))
    add("duplicate_started", reseq(v), False)
    v = reply()
    del v["events"][1]
    add("missing_started", reseq(v), False)
    for label, kind in [("progress", "progress"), ("queued", "queued"), ("list", []), ("dict", {}), ("none", None)]:
        v = reply()
        v["events"].insert(2, {"call_id": CALL_ID, "tool": "adb.exec", "seq": -1, "event": {"kind": kind}})
        add("unknown_kind_" + label, reseq(v), False, True)
    for label, value in [("bool", False), ("float", 0.0)]:
        v = reply()
        v["terminal"]["exit_code"] = value
        v["events"][-1]["event"]["terminal"]["exit_code"] = value
        add("top_exit_code_" + label, v, False, True)
    for label, field, value in [
        ("exit_bool", "exit_code", False), ("exit_float", "exit_code", 0.0),
        ("stdout_float", "stdout_bytes", 2.0), ("stderr_bool", "stderr_bytes", False),
        ("truncated_int", "output_truncated", 0), ("elapsed_float", "elapsed_ms", 7.0),
    ]:
        v = reply()
        v["events"][-1]["event"]["terminal"][field] = value
        add("event_terminal_" + label, v, False, True)
    v = reply()
    v["call_id"] = "foreign-call"
    add("wrong_call_identity", v, False)
    v = reply()
    v["events"][2]["call_id"] = "foreign-call"
    add("wrong_event_identity", v, False)
    v = reply()
    v["events"][2]["seq"] = 99
    add("wrong_event_sequence", v, False)
    v = reply()
    v["events"][2]["event"]["byte_count"] = 3
    add("wrong_output_byte_count", v, False)
    v = reply()
    v["events"][2]["event"]["data"] = "%%%"
    add("invalid_base64", v, False)
    v = reply()
    v["terminal"]["exit_code"] = 1
    v["events"][-1]["event"]["terminal"]["exit_code"] = 1
    add("nonzero_exit", v, False)
    v = reply()
    v["terminal"]["output_truncated"] = True
    v["events"][-1]["event"]["terminal"]["output_truncated"] = True
    add("truncated_output", v, False)
    add("wrong_wire_tool", reply(), False, tool="shell.exec")
    assert len(cases) == 28
    return cases


def fd_snapshot():
    directory = "/proc/self/fd" if Path("/proc/self/fd").is_dir() else "/dev/fd"
    result = {}
    for name in os.listdir(directory):
        if not name.isdigit():
            continue
        try:
            info = os.fstat(int(name))
        except OSError as error:
            if error.errno == errno.EBADF:
                continue
            raise
        result[name] = [info.st_dev, info.st_ino, info.st_mode]
    return result


def thread_snapshot():
    return sorted((thread.name, thread.ident, thread.is_alive()) for thread in threading.enumerate())


def expect_error(kind, call, error_number=None):
    try:
        call()
    except kind as error:
        if error_number is not None:
            assert error.errno == error_number
        return {"error_type": type(error).__name__, "errno": getattr(error, "errno", None)}
    raise AssertionError("expected controlled rejection " + kind.__name__)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--package-root", type=Path, default=Path(__file__).resolve().parent)
    ap.add_argument("--result-json", type=Path, help="Create-only result file.")
    args = ap.parse_args()
    raw = {}
    for relative, (length, expected_sha) in PINS.items():
        data = (args.package_root / relative).read_bytes()
        assert len(data) == length and digest(data) == expected_sha, relative
        raw[relative] = data
    original = load_parts(raw["reference/phone_observation_tools.original.py"], "original-observation",
                          {"require", "sha", "native_streams"}, {"PhoneTools"}, OBS_CONSTANTS)
    candidate = load_parts(raw["source/phone_observation_tools.py"], "candidate-observation",
                           {"require", "sha", "native_streams"}, {"PhoneTools"}, OBS_CONSTANTS)
    daily = load_parts(raw["source/daily_phone_local.py"], "candidate-daily",
                       {"require", "evidence_item_size", "expected_evidence_temporary", "raise_evidence_scan_error"},
                       constants={"_EXPECTED_RUN_NAME", "_EXPECTED_EVIDENCE_TEMP"})
    rows = []
    def case(name, scope, operation):
        try:
            detail = operation()
        except Exception as error:
            rows.append({"name": name, "scope": scope, "passed": False,
                         "error_type": type(error).__name__, "message": str(error)})
        else:
            rows.append({"name": name, "scope": scope, "passed": True, "detail": detail})
    for name, value, accepted, original_accepted, expected, wire_tool in parser_cases():
        def check(value=value, accepted=accepted, original_accepted=original_accepted, expected=expected, wire_tool=wire_tool):
            before = parse_outcome(original, value, wire_tool)
            after = parse_outcome(candidate, value, wire_tool)
            assert before["accepted"] is original_accepted, before
            assert after["accepted"] is accepted, after
            if expected is not None:
                assert after["sha256"] == digest(expected) and after["bytes"] == len(expected)
                assert after["utf8"].encode() == expected
            return {"original": before, "candidate": after}
        case(name, "NEG-11_SELECTED_NATIVE_PARSER", check)
    before_fds, before_threads = fd_snapshot(), thread_snapshot()
    rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    temp_path = None
    with tempfile.TemporaryDirectory(prefix="razr60-native-streams-regression-") as temp:
        temp_path = Path(temp)
        for kind in ["budget", "expired", "foreign_image", "old_round"]:
            def check_guard(kind=kind):
                run = temp_path / ("guard-" + kind)
                run.mkdir(mode=0o700)
                writes = []
                tools = candidate["PhoneTools"](run, lambda *items: writes.append(items))
                tools.bind({"session_id": "offline-s", "profile_id": "offline-p",
                            "task_id": "offline-t", "turn_id": "offline-turn"})
                tools.round = 3
                if kind == "budget":
                    tools.encoded_bytes_used = candidate["MAX_TURN_IMAGE_BYTES"] - 65535
                    decision = {"call_id": "guard-budget", "tool": "phone.screenshot", "argv": ["0"], "command": ""}
                else:
                    tools.latest = {"call_id": "image-current", "attached_round": 3,
                                    "received_monotonic": time.monotonic()}
                    if kind == "expired":
                        tools.latest["received_monotonic"] -= 121
                    elif kind == "old_round":
                        tools.latest["attached_round"] = 2
                    image_id = "foreign-image" if kind == "foreign_image" else "image-current"
                    decision = {"call_id": "guard-" + kind, "tool": "phone.tap",
                                "argv": [image_id, "10", "10"], "command": ""}
                state = {key: copy.deepcopy(value) for key, value in tools.__dict__.items()
                         if key not in {"atomic_record", "run_dir"}}
                observed = expect_error(ProviderError, lambda: tools.map(decision))
                after = {key: copy.deepcopy(value) for key, value in tools.__dict__.items()
                         if key not in {"atomic_record", "run_dir"}}
                assert state == after and writes == [] and list(run.iterdir()) == []
                return dict(observed, state_unchanged=True, mapping_records=0, dispatched_calls=0)
            case("image_" + kind, "NEG-10_SELECTED_MAP_GUARDS", check_guard)
        evidence = temp_path / "evidence"
        evidence.mkdir(mode=0o700)
        run = evidence / ("20261106-000000-" + "a" * 32)
        run.mkdir(mode=0o700)
        item_size = daily["evidence_item_size"]
        for name in ["local-01.request.json.new", "health-outcome.json.new"]:
            def check_rename(name=name):
                temporary = run / name
                canonical = temporary.with_name(name[:-4])
                content = b'{"offline":"actual os.replace"}\n'
                temporary.write_bytes(content)
                assert item_size(temporary, evidence) == len(content)
                os.replace(temporary, canonical)
                assert not temporary.exists()
                assert item_size(temporary, evidence) is None
                assert item_size(canonical, evidence) == len(content)
                return {"real_os_replace": True, "canonical_bytes": len(content), "missing_known_temporary": "tolerated"}
            case("rename_" + name, "NEG-14_SELECTED_FILESYSTEM", check_rename)
        case("missing_canonical", "NEG-14_SELECTED_FILESYSTEM",
             lambda: expect_error(FileNotFoundError, lambda: item_size(run / "terminal.json", evidence), errno.ENOENT))
        case("unknown_temporary", "NEG-14_SELECTED_FILESYSTEM",
             lambda: expect_error(FileNotFoundError, lambda: item_size(run / "unqualified.tmp", evidence), errno.ENOENT))
        case("known_temporary_missing_parent", "NEG-14_SELECTED_FILESYSTEM",
             lambda: expect_error(FileNotFoundError, lambda: item_size(
                 evidence / ("20261106-000000-" + "b" * 32) / "local-01.request.json.new", evidence), errno.ENOENT))
        target = run / "target.json"
        target.write_bytes(b"{}")
        symlink = run / "symlink.json"
        symlink.symlink_to(target.name)
        case("symlink_rejected", "NEG-14_SELECTED_FILESYSTEM",
             lambda: expect_error(RuntimeError, lambda: item_size(symlink, evidence)))
        nondirectory = evidence / ("20261106-000000-" + "c" * 32)
        nondirectory.write_bytes(b"not a directory")
        case("actual_enotdir_propagated", "NEG-14_SELECTED_FILESYSTEM",
             lambda: expect_error(NotADirectoryError, lambda: item_size(
                 nondirectory / "local-01.request.json.new", evidence), errno.ENOTDIR))
        def check_scanner_callback():
            error = PermissionError(errno.EACCES, "synthetic scanner callback test")
            try:
                daily["raise_evidence_scan_error"](error)
            except PermissionError as caught:
                assert caught is error
                return {"same_exception_object": True, "injection": "direct callback; not physical filesystem EACCES"}
            raise AssertionError("scan error was suppressed")
        case("scanner_eacces_same_exception", "NEG-14_SELECTED_FILESYSTEM", check_scanner_callback)
    def check_resources():
        after_fds, after_threads = fd_snapshot(), thread_snapshot()
        assert before_fds == after_fds
        assert before_threads == after_threads
        assert temp_path is not None and not temp_path.exists()
        return {
            "fd_before": before_fds, "fd_after": after_fds,
            "threads_before": before_threads, "threads_after": after_threads,
            "owned_temporary_tree_removed": True,
            "rss_high_water_before": rss_before,
            "rss_high_water_after": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "rss_baseline_return_claimed": False,
        }
    case("fd_thread_and_owned_temp_tree_baseline", "NEG-14_SELECTED_RESOURCE_RETURN", check_resources)
    def check_source_preservation():
        old = raw["reference/phone_observation_tools.original.py"].decode()
        new = raw["source/phone_observation_tools.py"].decode()
        def parts(text):
            start = text.index("def native_streams(")
            end = text.index("\ndef ", start + 1)
            return text[:start], text[start:end], text[end:]
        op, np = parts(old), parts(new)
        assert op[0] == np[0] and op[2] == np[2] and op[1] != np[1]
        old_daily = raw["reference/daily_phone_local.original.py"].decode()
        new_daily = raw["source/daily_phone_local.py"].decode()
        old_sha = PINS["reference/phone_observation_tools.original.py"][1]
        new_sha = PINS["source/phone_observation_tools.py"][1]
        assert old_daily.count(old_sha) == 1 and new_daily.count(new_sha) == 1
        assert new_daily.replace(new_sha, old_sha, 1) == old_daily
        return {"only_observation_function_changed": "native_streams",
                "all_other_observation_bytes_exact": True,
                "daily_one_parent_hash_inverse_exact": True}
    case("exact_current_source_preservation", "SOURCE_PRESERVATION", check_source_preservation)
    assert len(rows) == 42
    counts = {}
    for row in rows:
        counts[row["scope"]] = counts.get(row["scope"], 0) + 1
    result = {
        "schema": "razr60-current-native-streams-offline-regression/v2",
        "state": "PASSED" if all(row["passed"] for row in rows) else "FAILED",
        "host": {"system": platform.system(), "python": platform.python_version()},
        "script": {"bytes": len(Path(__file__).read_bytes()), "sha256": digest(Path(__file__).read_bytes())},
        "sources": [{"path": relative, "bytes": len(data), "sha256": digest(data)} for relative, data in raw.items()],
        "total": len(rows), "passed": sum(row["passed"] for row in rows), "scope_counts": counts,
        "phone_calls": 0, "model_requests": 0, "dispatches": 0,
        "whole_neg10_qualified": False, "whole_neg11_qualified": False, "whole_neg14_qualified": False,
        "source_combination_or_business_qualification": False,
        "limitations": [
            "Selected real source definitions loaded via AST; no whole provider or installed runtime is run.",
            "Original rejection or acceptance is measured alongside the candidate for each parser case.",
            "NEG-10 covers four map preconditions only; no new phone screenshot or model input is claimed.",
            "NEG-14 covers two actual renames, the listed filesystem errors, a synthetic callback, and host FD/thread/temp cleanup.",
            "No full capacity exhaustion, process-group cleanup, whole-runtime memory return, or physical phone case is claimed.",
            "This is a newly reconstructed Mac script, not a claim to recover the inaccessible earlier Linux script bytes."
        ],
        "cases": rows,
    }
    encoded = (json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if args.result_json:
        with open(args.result_json, "xb") as f:
            f.write(encoded)
            f.flush()
            os.fsync(f.fileno())
        assert args.result_json.read_bytes() == encoded
    print(json.dumps({
        "state": result["state"], "total": result["total"], "passed": result["passed"],
        "scope_counts": counts, "script": result["script"],
        "result_bytes": len(encoded), "result_sha256": digest(encoded),
        "result_path": str(args.result_json) if args.result_json else None,
        "failed": [row for row in rows if not row["passed"]],
        "phone_calls": 0, "model_requests": 0, "dispatches": 0,
    }, ensure_ascii=False, sort_keys=True))
    return 0 if result["state"] == "PASSED" else 1


if __name__ == "__main__":
    sys.exit(main())
