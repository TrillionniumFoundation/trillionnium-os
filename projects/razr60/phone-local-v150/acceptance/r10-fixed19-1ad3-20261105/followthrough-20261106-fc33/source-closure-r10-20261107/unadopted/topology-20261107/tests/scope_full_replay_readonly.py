#!/usr/bin/env python3
"""Read pinned Mac archives and compare complete old/derived pure R8 scope.

No phone, network, subprocess, signal, lock, or admission operation is performed
by this script.  It emits one JSON result to stdout and does not write files.
Use the operator's durable process capture to retain that stdout separately.
"""

from __future__ import annotations

import argparse
import ast
import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import platform
import re
import stat
import statistics
import sys
import tarfile
import time
import types
import zlib


R8_READER_PIN = {"bytes": 96088,
                 "sha256": "614f44d6eb75f47b02e32b463f18534e2d0bc5a3e8fd928535e7da17909679ae"}
SCOPE_PIN = {"bytes": 21865,
             "sha256": "937a34f4ba752e14bb78b1566c672e89b2e26502392d8d2a3561a52ceb88af38"}
SCOPE_FUNCTION_PIN = {"bytes": 8083,
                      "sha256": "798ffcd349da388ba6985b0b5e9a34beb436656aed300d3980280cea100d64a6"}
DERIVED_FUNCTION_PIN = {"bytes": 8369,
                        "sha256": "51bd57dffe1a2beca21a3d01288477030f61988daa3d294fdf8d371ade6c9f89"}
DERIVED_FULL_PIN = {"bytes": 22151,
                    "sha256": "520f0f9a1eab1de60a165908536c03559f3bc49214a3e74b4c5d9036197619ed"}
READSET = {}


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False,
                       separators=(",", ":")) + "\n").encode()


def full9(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def read_original(path, expected):
    path = Path(path)
    before = full9(path.lstat())
    need(stat.S_ISREG(before[2]) and before[5] == 1, "ordinary single-link original required")
    raw = path.read_bytes()
    need(before == full9(path.lstat()) and pin(raw) == expected, "pinned unchanged original: " + str(path))
    READSET[str(path)] = {"path": str(path), "metadata": before, **expected}
    return raw


def module(raw, label):
    value = types.ModuleType(label)
    value.__file__ = "<offline-pure-" + label + ">"
    exec(compile(raw, value.__file__, "exec"), value.__dict__)
    return value


def function_source(raw, name):
    source = raw.decode()
    nodes = [n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == name]
    need(len(nodes) == 1, "one exact pure function")
    n = nodes[0]
    return ("\n".join(source.splitlines()[n.lineno - 1:n.end_lineno]) + "\n").encode()


def original_archive(reader, packed):
    need(pin(packed) == reader.ARCHIVE_PIN, "exact R8 original archive")
    decoder = zlib.decompressobj()
    raw_tar = decoder.decompress(packed, reader.MAX_ORIGINAL + 1)
    need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
         and pin(raw_tar) == reader.RAW_ARCHIVE_PIN, "complete bounded R8 raw archive")
    originals = {}
    offset = 0
    with tarfile.open(fileobj=io.BytesIO(raw_tar), mode="r:") as archive:
        members = archive.getmembers()
        need([row.name for row in members] == ["originals/" + key for key in sorted(reader.EXPECTED_PINS)],
             "complete canonical R8 member names")
        for row in members:
            key = row.name.split("/", 1)[1]
            need(row.type == tarfile.REGTYPE and row.linkname == "" and row.pax_headers == {}
                 and row.uid == row.gid == row.mtime == 0 and row.uname == row.gname == ""
                 and row.mode == 0o400 and row.size == reader.EXPECTED_PINS[key]["bytes"]
                 and row.offset == offset and row.offset_data == offset + 512,
                 "immutable ordinary original member")
            stream = archive.extractfile(row)
            need(stream is not None, "original member stream")
            data = stream.read(reader.MAX_ORIGINAL + 1)
            need(pin(data) == reader.EXPECTED_PINS[key], "full original member pin: " + key)
            originals[key] = data
            offset += 512 + ((row.size + 511) // 512) * 512
    need(len(raw_tar) == ((offset + 1024 + 10239) // 10240) * 10240
         and raw_tar[offset:] == bytes(len(raw_tar) - offset), "complete tar terminator")
    return originals


def build_case(root, derived_function):
    reader_raw = read_original(root / "retained-staged-r8-failed01-ast02/verify_retained_staged_r8.py",
                               R8_READER_PIN)
    reader = module(reader_raw, "original-r8-reader")
    packed = read_original(root / "retained-staged-r8-failed01-ast02/ORIGINALS.zlib", reader.ARCHIVE_PIN)
    originals = original_archive(reader, packed)
    r7_archive = read_original(root / "retained-preaccept-r7-failed01/ORIGINALS.zlib",
                               {k: reader.R7_ARCHIVE[k] for k in ("bytes", "sha256")})
    need(pin(originals["r7_reader"]) == {"bytes": 37404,
         "sha256": "5935f4d4b3f00d914c6e0f9aec4429cf424a0601685061fe9277de3df5403b21"},
         "exact old R7 proof reader")
    r7 = module(originals["r7_reader"], "original-r7-reader")
    def supplied(row):
        if row == reader.R7_PHONE:
            data = originals["r7_phone_manifest"]
        else:
            need(row == reader.R7_ARCHIVE, "only fixed actual R7 archive dependency")
            data = r7_archive
        need(pin(data) == {k: row[k] for k in ("bytes", "sha256")}, "exact R7 input bytes")
        return data
    prior = r7.verify_retained_preaccept_archive(reader.R7_PHONE, read_pinned=supplied)
    projector = reader.load_module("projector")
    files = projector.actual_stage_files(originals["stage_archive"])
    stage_operation = reader.strict(originals["stage_operation"])
    need(stage_operation["actor_rc"] == 0 and stage_operation["wrapper"]["phone"]["rc"] == 0
         and stage_operation["wrapper"]["phone"]["stderr"] == "", "actual original stage operation")
    stage_complete = stage_operation["wrapper"]["phone"]["stdout"].encode()
    common_raw = files[reader.HOME + "/package/source/component_common.py"]
    need(common_raw == originals["source_common"], "exact actual common source")
    common = module(common_raw, "original-common")
    late_raw = files[reader.HOME + "/package/source/late_boundary.py"]
    need(late_raw == originals["source_late"], "exact actual late source")
    inventory_source = function_source(late_raw, "inventory_value")
    inv = {"C": common, "Path": Path, "re": re, "stat": stat}
    exec(compile(inventory_source, "<original-pure-inventory>", "exec"), inv)
    inventory_reader = inv["inventory_value"]
    capture, _ = projector.reconstruct(originals["scope_projection"], reader.encoded(prior["inventory_value"]),
                                      originals["stage_archive"], stage_complete,
                                      validate_inventory=inventory_reader)
    row = reader.MODULES["scope"]
    packed_source = base64.b64decode(row["zlib_base64"], validate=True)
    decoder = zlib.decompressobj()
    scope_raw = decoder.decompress(packed_source, 262145)
    need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
         and pin(scope_raw) == SCOPE_PIN, "exact embedded historical R8 scope module")
    original_function = function_source(scope_raw, "verify_complete_scope")
    need(pin(original_function) == SCOPE_FUNCTION_PIN
         and pin(derived_function) == DERIVED_FUNCTION_PIN, "old and new function identities remain distinct")
    need(scope_raw.count(original_function) == 1, "one original scope function")
    derived_raw = scope_raw.replace(original_function, derived_function, 1)
    need(pin(derived_raw) == DERIVED_FULL_PIN
         and derived_raw.replace(derived_function, original_function, 1) == scope_raw,
         "declared derived source and exact whole-byte inverse")
    original_scope = module(scope_raw, "original-r8-scope")
    derived_scope = module(derived_raw, "UNADOPTED-derived-r8-scope")
    args = (capture, originals["scope_source"], files, stage_complete, prior, common, inventory_reader)
    return reader, original_scope, derived_scope, args, {
        "r8_reader": pin(reader_raw), "r8_archive": pin(packed), "r7_archive": pin(r7_archive),
        "original_scope_source": pin(scope_raw), "derived_scope_source": pin(derived_raw),
        "capture": pin(capture), "observer_source": pin(originals["scope_source"]),
        "original_inventory_function": pin(inventory_source),
        "prior_inventory": pin(reader.encoded(prior["inventory_value"])),
        "stage_complete": pin(stage_complete), "stage_files_count": len(files),
        "before_entries": len(reader.strict(capture)["full_inventory_before"]["entries"]),
        "after_entries": len(reader.strict(capture)["full_inventory_after"]["entries"]),
        "old_roots": len(prior["inventory_value"]["roots"]),
    }


def invoke(function, args):
    try:
        value = function(*args)
    except Exception as error:
        return {"accepted": False, "exception_type": type(error).__name__, "message": str(error)}
    return {"accepted": True, "value": value}


def sample(function, args):
    began = time.perf_counter_ns()
    cpu = time.process_time_ns()
    function(*args)
    return {"wall_seconds": (time.perf_counter_ns() - began) / 1e9,
            "cpu_seconds": (time.process_time_ns() - cpu) / 1e9}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--derived-function-base64", required=True)
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()
    need(1 <= args.rounds <= 7 and sys.getprofile() is None and sys.gettrace() is None,
         "bounded unprofiled offline benchmark")
    derived = base64.b64decode(args.derived_function_base64, validate=True)
    began = time.monotonic()
    reader, old, new, case_args, provenance = build_case(args.root, derived)
    old_result = invoke(old.verify_complete_scope, case_args)
    new_result = invoke(new.verify_complete_scope, case_args)
    need(old_result == new_result and old_result["accepted"], "complete real scope output equality")
    receipt = old_result["value"][3]
    need(receipt["native_case_credit"] == 0 and receipt["runtime_admission"] is False
         and receipt["global_unknown_effect_count"] is None, "historical unknowns and zero credit retained")
    cases = []
    mutations = [
        ("capture-byte-truncated", 0, lambda x: x[:-1]),
        ("observer-source-truncated", 1, lambda x: x[:-1]),
        ("stage-complete-extra-newline", 3, lambda x: x + b"\n"),
        ("prior-duplicate-root", 4, lambda x: {**x, "inventory_value": {
            **x["inventory_value"], "roots": x["inventory_value"]["roots"] + [x["inventory_value"]["roots"][0]]}}),
        ("prior-inventory-pin", 4, lambda x: {**x, "inventory": {**x["inventory"], "sha256": "0" * 64}}),
    ]
    for name, index, mutate in mutations:
        changed = list(case_args)
        changed[index] = mutate(copy.deepcopy(changed[index]))
        left = invoke(old.verify_complete_scope, tuple(changed))
        right = invoke(new.verify_complete_scope, tuple(changed))
        need(left == right and not left["accepted"], "same rejection and priority: " + name)
        cases.append({"case": name, **left})
    # Two bad inputs establish that the original first pin guard still wins.
    changed = list(case_args)
    changed[0] = changed[0][:-1]
    changed[4] = {**changed[4], "inventory": {"bytes": 0, "sha256": "0" * 64}}
    left = invoke(old.verify_complete_scope, tuple(changed))
    right = invoke(new.verify_complete_scope, tuple(changed))
    need(left == right and not left["accepted"], "same initial pin rejection priority")
    cases.append({"case": "capture-pin-before-invalid-prior", **left})
    samples = {"original": [], "derived": []}
    functions = {"original": old.verify_complete_scope, "derived": new.verify_complete_scope}
    for round_index in range(args.rounds):
        order = ("original", "derived") if round_index % 2 == 0 else ("derived", "original")
        for key in order:
            samples[key].append(sample(functions[key], case_args))
    medians = {key: {metric: statistics.median(row[metric] for row in rows)
                     for metric in ("wall_seconds", "cpu_seconds")}
               for key, rows in samples.items()}
    # File provenance is checked again; no original is rewritten by this test.
    for path, row in READSET.items():
        need(full9(Path(path).lstat()) == row["metadata"], "original source/archive metadata changed during test")
        need(pin(Path(path).read_bytes()) == {k: row[k] for k in ("bytes", "sha256")},
             "original source/archive bytes changed during test")
    result = {
        "schema": "hepta.offline.complete-r8-scope-differential.v1", "state": "PASS",
        "scope": "Complete original and derived verify_complete_scope on exact retained Mac archive inputs",
        "full_valid_result_equal": True, "valid_cases": 1, "rejected_cases": cases,
        "exception_type_and_message_equal": True, "receipt": receipt, "receipt_sha256": pin(encoded(receipt)),
        "provenance": provenance, "source_archive_bookends_equal": True, "readset": READSET,
        "same_original_inventory_reader_for_both": True,
        "measurement": {"rounds": args.rounds, "alternating_order": True,
            "samples": samples, "medians": medians,
            "median_wall_ratio_original_over_derived": medians["original"]["wall_seconds"] / medians["derived"]["wall_seconds"]},
        "python": sys.version, "platform": platform.platform(), "profiler_enabled": False,
        "trace_enabled": False, "test_elapsed_seconds": time.monotonic() - began,
        "phone_calls": 0, "runtime_admission": False, "native_case_credit": 0,
        "historical_source_files_changed": False, "historical_module_globals_reassigned": False,
        "validation_result_cache": False, "production_selector_implemented": False,
        "whole_stage_budget_verified": False,
    }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
