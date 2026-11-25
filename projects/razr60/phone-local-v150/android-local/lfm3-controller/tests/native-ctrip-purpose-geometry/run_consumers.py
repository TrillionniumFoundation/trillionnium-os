#!/usr/bin/env python3
"""Actual purpose-limited form consumers and lossless pixel comparison transport."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
sys.dont_write_bytecode = True
EXPECTED_CASES = ['ax_receipt_recomputes_recorded_geometry_and_real_phone_copy_frame', 'actual_session_date_domain_guard_claim_uses_restricted_ax_source', 'actual_session_query_before_calendar_roundtrip_still_refused', 'actual_ax_receipt_changed_certificate_cannot_be_sealed', 'actual_ax_receipt_changed_original_node_cannot_borrow_comparison', 'ax_capture_exact_purpose_and_path_are_jointly_required', 'pixel_pre_encoding_actual_phone_metadata_decode_copy_session_guard', 'pixel_post_encoding_actual_phone_metadata_decode_copy', 'pixel_certificate_cannot_cross_observation_or_owner', 'pixel_frame_missing_exact_target_is_refused', 'pixel_frame_source_identity_distinguishes_certificate_removal', 'pixel_domain_rejects_trip_generic_back_and_calendar_authority', 'pixel_raw_certificate_cannot_replace_new_observation_binding', 'pixel_complete_original_nodes_hash_checked_before_comparator', 'lossless_purpose_bytes_hash_and_semantics_are_exact', 'lossless_strict_comparison_keeps_all_literal_facts_and_phone_8192_bound', 'transport_wrong_codec_refused', 'transport_wrong_schema_refused', 'transport_bad_hash_refused', 'transport_zero_length_refused', 'transport_oversize_length_refused', 'transport_fractional_length_refused', 'transport_string_length_refused', 'transport_unknown_field_refused', 'transport_bad_base64_refused', 'transport_nonstring_base64_refused', 'transport_missing_codec_field_refused', 'transport_dictionary_stream_refused', 'transport_wrong_actual_length_refused', 'transport_truncated_zlib_refused', 'transport_trailing_zlib_bytes_refused', 'transport_noncanonical_base64_refused', 'transport_bomb_over_declared_bound_refused', 'transport_invalid_utf8_refused_after_matching_hash', 'transport_valid_json_with_trailing_value_refused', 'transport_unknown_inner_proof_schema_refused', 'transport_inner_grant_claim_refused', 'pixel_capture_outer_8192_bound_is_unchanged']

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def record(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw), "mode": path.stat().st_mode & 0o777}

def tree(source):
    rows = []
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise RuntimeError("source symlink is not permitted")
        if path.is_file():
            row = record(path)
            row["relative_path"] = str(path.relative_to(source))
            rows.append(row)
    return rows

def dump(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return record(path)

def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "output", "java-home", "json-jar"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    source, out, jdk, jar = [p.resolve() for p in (args.source, args.output, args.java_home, args.json_jar)]
    if out.exists() or source in out.parents:
        raise RuntimeError("fresh separate output required")
    out.mkdir(mode=0o700, parents=True)
    before = tree(source)
    report = {
        "schema": "hepta.ctrip-purpose-consumer-focus.v1",
        "source": str(source), "all_pass": False, "phone_operations": 0,
        "started_host_wall_ms": int(time.time() * 1000),
        "source_before": dump(out / "SOURCE-BEFORE.json", before),
        "stages": [], "android_producer_tested": False, "platform_effect_tested": False,
        "model_executed": False, "business_verified": False,
        "boundary": "Full actual consumers and original Guard/comparator. The Android IO and complete census are explicit host fixtures. No Android BFS, service validate/dispatch or phone qualification."
    }
    tool_paths = [jdk / "bin/javac", jdk / "bin/java", jdk / "lib/modules", jar, Path(sys.executable).resolve()]
    tools_before = [record(p) for p in tool_paths]
    report["tools_before"] = tools_before
    original_paths = []
    original_before = []
    try:
        closure_path = source / "tests/native-search-planning/host_closure.py"
        closure = module(closure_path, "form_history_real_session_closure")
        if sha(jar.read_bytes()) != closure.JSON_SHA:
            raise RuntimeError("actual pinned JSON jar required")
        host = source / "tests/native-ctrip-purpose-geometry/CtripPurposeConsumersHost.java"
        support = source / "tests/native-form-history-consumers/NativeFormHistoryConsumersHostTest.java"
        fixture = source / "tests/native-ctrip-purpose-geometry/recorded-060c-pair.json"
        paths, provenance = closure.prepare(source, out / "closure", (host, support))
        comparator = source / "src/org/trillionnium/hepta/local/NativeCtripFormObservation.java"
        paths = list(dict.fromkeys([*paths, comparator.resolve()]))
        original_paths = list(dict.fromkeys([Path(row["path"]) for row in provenance["production_inputs"]] +
                                           [comparator, support, fixture, Path(__file__).resolve()]))
        original_before = [record(p) for p in original_paths]
        report["source_inputs_before"] = original_before
        provenance["compile_inputs"] = [record(p) for p in paths]
        provenance["form_history_actual_comparator"] = record(comparator)
        report["extraction"] = dump(out / "EXTRACTION.json", provenance)
        classes = out / "classes"
        classes.mkdir()
        env = dict(os.environ)
        env["PATH"] = str(jdk / "bin") + ":/usr/bin:/bin"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        for name in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"):
            env.pop(name, None)
        commands = [
            ("compile", [jdk / "bin/javac", "--release", "8", "-encoding", "UTF-8", "-proc:none",
                         "-Xlint:all,-options", "-Werror", "-classpath", jar, "-d", classes, *paths]),
            ("consumers", [jdk / "bin/java", "-cp", str(classes) + os.pathsep + str(jar),
                           "org.trillionnium.hepta.local.CtripPurposeConsumersHost", out / "CASES.json", out / "work", fixture])
        ]
        for name, argv in commands:
            started = time.monotonic()
            argv = list(map(str, argv))
            completed = subprocess.run(argv, cwd=out, env=env, capture_output=True, timeout=120, check=False)
            (out / (name + ".stdout")).write_bytes(completed.stdout)
            (out / (name + ".stderr")).write_bytes(completed.stderr)
            report["stages"].append({
                "name": name, "argv": argv, "cwd": str(out), "exit_code": completed.returncode,
                "elapsed_seconds": time.monotonic() - started,
                "stdout": record(out / (name + ".stdout")), "stderr": record(out / (name + ".stderr"))
            })
            if completed.returncode:
                raise RuntimeError("stage failed: " + name)
        cases = json.loads((out / "CASES.json").read_text())
        if not (cases["all_pass"] is True and cases["cases"] == len(EXPECTED_CASES) and
                cases["case_names"] == EXPECTED_CASES and len(set(cases["case_names"])) == len(EXPECTED_CASES)):
            raise RuntimeError("declared case matrix differs")
        report["all_pass"] = True
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        if (out / "CASES.json").is_file():
            actual = json.loads((out / "CASES.json").read_text())
            report["cases"] = actual
            report["cases_file"] = record(out / "CASES.json")
        report["source_inputs_after"] = [record(p) for p in original_paths]
        report["source_inputs_unchanged"] = report["source_inputs_after"] == original_before
        after = tree(source)
        report["source_after"] = dump(out / "SOURCE-AFTER.json", after)
        report["source_unchanged"] = after == before
        report["source_file_count"] = len(before)
        report["tools_after"] = [record(p) for p in tool_paths]
        report["tools_unchanged"] = report["tools_after"] == tools_before
        report["all_pass"] = bool(report["all_pass"] and report["source_unchanged"] and
                                  report["source_inputs_unchanged"] and report["tools_unchanged"])
        report["finished_host_wall_ms"] = int(time.time() * 1000)
        dump(out / "RESULT.json", report)
    print(json.dumps({"all_pass": report["all_pass"], "error": report.get("error"),
                      "cases": report.get("cases", {}).get("cases"),
                      "assertions": report.get("cases", {}).get("assertions"),
                      "failed": [{"name": r["name"], "error": r.get("error")} for r in report.get("cases", {}).get("results", []) if not r.get("passed")],
                      "result": str(out / "RESULT.json")}, ensure_ascii=False))
    return 0 if report["all_pass"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
