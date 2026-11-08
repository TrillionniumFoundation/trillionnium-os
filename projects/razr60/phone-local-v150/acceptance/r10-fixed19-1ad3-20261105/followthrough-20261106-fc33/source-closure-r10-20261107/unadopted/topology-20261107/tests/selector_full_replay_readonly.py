#!/usr/bin/env python3
"""Offline exact retained R9 -> R8 -> R7 reader composition differential.

Reads fixed Mac evidence only; no device/network/subprocess/lock/signal/dispatch.
Does not write files.  Durable process stdout owns the two JSON-lines originals.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import platform
import statistics
import sys
import tarfile
import time
import types
import zlib


SUPPORT_PIN = {"bytes": 14290, "sha256": "c11951766978bbb0345dbbf853bb8b73a145f7f0f6cfdb65d18dbc3e48a91c78"}
MAC_R8_MANIFEST_PIN = {"bytes": 422, "sha256": "b005ba692ea1f31e93858628eb9ae64c936c83193c632002eafa1dfb84f7f7f0"}


def need(value, message):
    if not value:
        raise ValueError(message)


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode()


def module(raw, name):
    result = types.ModuleType(name)
    result.__file__ = "<offline-" + name + ":" + pin(raw)["sha256"] + ">"
    exec(compile(raw, result.__file__, "exec"), result.__dict__)
    return result


def invoke(reader, archive, supplied):
    try:
        result = reader.verify_retained_transport_archive(archive, read_pinned=supplied)
    except Exception as error:
        return {"accepted": False, "exception_type": type(error).__name__, "message": str(error)}
    return {"accepted": True, "value": result}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--selector-source-base64", required=True)
    parser.add_argument("--support-source-base64", required=True)
    parser.add_argument("--inventory-function-base64", required=True)
    parser.add_argument("--scope-function-base64", required=True)
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()
    need(1 <= args.rounds <= 7 and sys.getprofile() is None and sys.gettrace() is None,
         "bounded unprofiled offline benchmark")
    started = time.monotonic()
    support_raw = base64.b64decode(args.support_source_base64, validate=True)
    need(pin(support_raw) == SUPPORT_PIN, "fixed exact independent read-only support source")
    support = module(support_raw, "support_scope_harness")
    selector_raw = base64.b64decode(args.selector_source_base64, validate=True)
    selector_module = module(selector_raw, "UNADOPTED_reader_selector")
    inventory_function = base64.b64decode(args.inventory_function_base64, validate=True)
    scope_function = base64.b64decode(args.scope_function_base64, validate=True)
    selector = selector_module.OfflineDerivedSelector(
        inventory_function=inventory_function, scope_function=scope_function,
        implementation_source=selector_raw)
    root = args.root
    old_raw = support.read_original(root / "retained-transport-r9-failed01/verify_retained_transport_r9.py",
                                    selector_module.PINS["r9-reader"])
    original = module(old_raw, "unchanged_reference_r9_reader")
    # Snapshot immutable retained evidence bytes, not verification results or live observations.
    paths = [
        (original.ARCHIVE, root / "retained-transport-r9-failed01/ORIGINALS.zlib"),
        (original.R8_READER, root / "retained-staged-r8-failed01-ast02/verify_retained_staged_r8.py"),
        (original.R8_ARCHIVE, root / "retained-staged-r8-failed01-ast02/ORIGINALS.zlib"),
        (original.R7_ARCHIVE, root / "retained-preaccept-r7-failed01/ORIGINALS.zlib"),
    ]
    snapshots = {}
    for descriptor, path in paths:
        snapshots[descriptor["path"]] = support.read_original(
            path, {key: descriptor[key] for key in ("bytes", "sha256")})
    mac_manifest = support.read_original(root / "retained-staged-r8-failed01-ast02/RETENTION-INPUTS.json",
                                         MAC_R8_MANIFEST_PIN)
    canonical_manifest = original.strict(mac_manifest)
    old_archive_path = canonical_manifest["archive"]["path"]
    canonical_manifest["archive"]["path"] = original.R8_ARCHIVE["path"]
    phone_manifest = original.enc(canonical_manifest)
    need(pin(phone_manifest) == {key: original.R8_MANIFEST[key] for key in ("bytes", "sha256")},
         "only documented Mac archive-path representation maps to exact historical phone manifest")
    snapshots[original.R8_MANIFEST["path"]] = phone_manifest
    manifest_projection = {"mac_source": MAC_R8_MANIFEST_PIN,
        "phone_representation": pin(phone_manifest),
        "changed_field": "archive.path", "source_archive_path": old_archive_path,
        "historical_phone_archive_path": original.R8_ARCHIVE["path"],
        "is_new_phone_observation": False}
    descriptors = {row["path"]: row for row in (original.ARCHIVE,) + original.EXTERNAL_INPUTS}

    # Export one exact pinned source, for portable constructor tests.  The full
    # reference verifier below independently checks every tar member and header.
    packed = snapshots[original.ARCHIVE["path"]]
    codec = zlib.decompressobj()
    archive = codec.decompress(packed, original.MAX_ORIGINAL + 1)
    need(codec.eof and not codec.unused_data and not codec.unconsumed_tail
         and pin(archive) == original.RAW_ARCHIVE, "exact bounded retained R9 raw archive")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as stream:
        source_stream = stream.extractfile("modules/scope.py")
        need(source_stream is not None, "fixed original scope member")
        r9_scope = source_stream.read(65537)
    need(pin(r9_scope) == selector_module.PINS["r9-scope"], "exact original R9 scope export")
    print(json.dumps({"kind": "pinned-original-source-export", "member": "modules/scope.py",
        "source": pin(r9_scope), "archive": pin(packed), "raw_archive": pin(archive),
        "zlib_base64": base64.b64encode(zlib.compress(r9_scope, 9)).decode()},
        sort_keys=True, separators=(",", ":")), flush=True)

    traces = {}
    def read_factory(label, mutations=None):
        traces[label] = []
        mutations = {} if mutations is None else mutations
        def read(row):
            need(type(row) is dict and row.get("path") in descriptors
                 and row == descriptors[row["path"]], "only fixed complete supplied input descriptors")
            traces[label].append(dict(row))
            data = snapshots[row["path"]]
            return mutations[row["path"]](data) if row["path"] in mutations else data
        return read

    reference_globals_before = dict(original.__dict__)
    derived = selector.r9_reader(old_raw)
    left = invoke(original, original.ARCHIVE, read_factory("valid_original"))
    right = invoke(derived, original.ARCHIVE, read_factory("valid_derived"))
    need(left == right and left["accepted"], "full original and derived R9 proof result equality")
    need(traces["valid_original"] == traces["valid_derived"], "same complete external original read order")
    value = left["value"]
    original.same_semantics(value)
    need(value["native_case_credit"] == 0 and value["global_unknown_effect_count"] is None
         and value["native_terminal"] is None and value["remote_cleanup_proven"] is False
         and value["retirement_accepted"] is False and value["new_nonce_authorized"] is False,
         "all historical unknown, zero-credit and non-admission semantics retained")
    initial_construction_receipt = copy.deepcopy(selector.receipt())
    need({row["kind"] for row in initial_construction_receipt["constructions"]}
         == {"r9-reader", "r9-scope", "r8-reader", "r8-scope", "r7-reader", "inventory-function"},
         "entire declared nested pure-reader selection was executed")
    need({row["context"] for row in initial_construction_receipt["constructions"]
          if row["kind"] == "inventory-function"} == {"r7-readers", "r8-payload", "r9-scope"},
         "all three original inventory source contexts verified before derivation")
    rejected = []
    for name, descriptor in [("r9-archive-byte", original.ARCHIVE),
                             ("r8-reader-byte", original.R8_READER),
                             ("r8-manifest-byte", original.R8_MANIFEST),
                             ("r8-archive-byte", original.R8_ARCHIVE),
                             ("r7-archive-byte", original.R7_ARCHIVE)]:
        mutation = {descriptor["path"]: lambda data: data[:-1]}
        a = invoke(original, original.ARCHIVE, read_factory(name + "_old", mutation))
        b = invoke(derived, original.ARCHIVE, read_factory(name + "_new", mutation))
        need(a == b and not a["accepted"]
             and traces[name + "_old"] == traces[name + "_new"], "same full rejection and read order: " + name)
        rejected.append({"case": name, **a, "external_read_count": len(traces[name + "_old"]),
                         "external_read_order_equal": True})
    mutations = {original.ARCHIVE["path"]: lambda data: data[:-1],
                 original.R8_READER["path"]: lambda data: data[:-1]}
    a = invoke(original, original.ARCHIVE, read_factory("priority_old", mutations))
    b = invoke(derived, original.ARCHIVE, read_factory("priority_new", mutations))
    need(a == b and not a["accepted"] and traces["priority_old"] == traces["priority_new"]
         == [original.ARCHIVE], "original first external read rejection retains priority")
    rejected.append({"case": "r9-archive-before-r8-reader", **a, "external_read_count": 1,
                     "external_read_order_equal": True})
    bad_descriptor = {**original.ARCHIVE, "sha256": "0" * 64}
    a = invoke(original, bad_descriptor, read_factory("descriptor_old"))
    b = invoke(derived, bad_descriptor, read_factory("descriptor_new"))
    need(a == b and not a["accepted"] and traces["descriptor_old"] == traces["descriptor_new"] == [],
         "bad entrypoint rejected before any read")
    rejected.append({"case": "entrypoint-pin-before-read", **a, "external_read_count": 0,
                     "external_read_order_equal": True})

    samples = {"original": [], "derived": []}
    expected_return_pin = pin(original.enc(value))
    implementations = {"original": original, "derived": derived}
    # Timed complete calls repeat actual archive decode, nested reader construction
    # and all validation.  No prior PASS or result object is supplied to them.
    for round_number in range(args.rounds):
        order = ("original", "derived") if round_number % 2 == 0 else ("derived", "original")
        for name in order:
            trace_label = "timed_" + name + "_" + str(round_number)
            read = read_factory(trace_label)
            wall = time.perf_counter_ns()
            cpu = time.process_time_ns()
            result = implementations[name].verify_retained_transport_archive(original.ARCHIVE, read_pinned=read)
            cpu_elapsed = (time.process_time_ns() - cpu) / 1e9
            wall_elapsed = (time.perf_counter_ns() - wall) / 1e9
            need(result == value and pin(original.enc(result)) == expected_return_pin
                 and traces[trace_label] == traces["valid_original"],
                 "every complete timed validation recomputes identical historical proof and read order")
            samples[name].append({"wall_seconds": wall_elapsed, "cpu_seconds": cpu_elapsed})
    medians = {name: {key: statistics.median(row[key] for row in rows)
                      for key in ("wall_seconds", "cpu_seconds")} for name, rows in samples.items()}
    need(set(original.__dict__) == set(reference_globals_before)
         and all(original.__dict__[key] is item for key, item in reference_globals_before.items()),
         "reference module globals not replaced or rebound")
    for path, row in support.READSET.items():
        need(support.full9(Path(path).lstat()) == row["metadata"], "source/archive metadata bookend equality")
        need(pin(Path(path).read_bytes()) == {key: row[key] for key in ("bytes", "sha256")},
             "source/archive exact bytes bookend equality")
    result = {"kind": "full-selector-differential-report",
        "schema": "hepta.offline.complete-retained-reader-selector-differential.v1", "state": "PASS",
        "full_valid_return_equal": True, "return_pin": expected_return_pin,
        "historical_failure_semantics": {key: value[key] for key in original.FAILURE_SEMANTICS},
        "historical_retirement_accepted": value["retirement_accepted"],
        "historical_phone_scope_verified": value["phone_scope_verified"],
        "historical_proof_is_not_current_phone_observation": True,
        "inventory": value["inventory"], "inventory_roots": len(value["inventory_value"]["roots"]),
        "inventory_entries": len(value["inventory_value"]["entries"]),
        "external_reads": traces["valid_original"], "external_read_order_equal": True,
        "rejected_cases": rejected, "exception_type_and_message_equal": True,
        "initial_derived_construction_receipt": initial_construction_receipt,
        "total_constructions": len(selector.constructions),
        "measurement": {"rounds": args.rounds, "alternating_order": True, "samples": samples,
            "medians": medians, "boundary": "complete verify_retained_transport_archive; preloaded immutable retained bytes; nested modules rebuilt each call",
            "median_wall_ratio_original_over_derived": medians["original"]["wall_seconds"] / medians["derived"]["wall_seconds"]},
        "manifest_representation": manifest_projection, "readset": support.READSET,
        "source_archive_bookends_equal": True, "reference_module_bindings_unchanged": True,
        "selector_source": pin(selector_raw), "support_source": pin(support_raw),
        "python": sys.version, "platform": platform.platform(), "profiler_enabled": False,
        "trace_enabled": False, "test_elapsed_seconds": time.monotonic() - started,
        "phone_calls": 0, "runtime_admission": False, "native_case_credit": 0,
        "validation_result_cache": False, "live_observation_cache": False,
        "historical_source_files_changed": False, "historical_module_globals_reassigned": False,
        "production_selector_adopted": False, "source_parent_full_boundary_composed": False,
        "production_policy_status": "HOLD", "whole_stage_budget_verified": False}
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
