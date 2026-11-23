#!/usr/bin/env python3
"""Actual form-history consumers over explicit synthetic Android and census IO."""
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
EXPECTED_CASES = ["actual_history_phone_copy_frame_session_form_chain","history_retains_different_complete_trees_and_late_content_without_current_claim","history_publication_current_tree_claim_is_refused","history_publication_kind_alias_is_refused","history_original_capture_clock_cannot_be_refreshed","history_pixel_claim_is_refused","history_and_ordinary_ax_have_distinct_source_identity","history_receipt_cannot_be_passed_to_old_equal_ax_factory","history_frame_cannot_rebind_selection_or_task_identity","same_value_different_selection_authority_cannot_copy_history","history_domain_rejects_result_payload","history_domain_rejects_other_phase_and_back","history_domain_rejects_generic_click_purpose","history_domain_refuses_recommendation_target","history_session_rejects_calendar_or_results_projection_before_progress","history_never_readies_or_accepts_success","history_wait_uses_original_non_effect_null_guard","history_done_failure_uses_original_non_effect_null_guard","history_done_partial_uses_original_non_effect_null_guard","history_query_before_calendar_roundtrip_is_refused","history_real_date_guard_is_once_claimed_and_keeps_eight_second_budget","history_real_guard_expiry_refuses_claim","history_equal_pair_comparator_and_protected_change_refusal","history_guard_needs_same_model_run_action_and_single_reservation"]

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
        "schema": "hepta.native-form-history-consumer-focus.v1",
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
        host = source / "tests/native-form-history-consumers/NativeFormHistoryConsumersHostTest.java"
        paths, provenance = closure.prepare(source, out / "closure", (host,))
        comparator = source / "src/org/trillionnium/hepta/local/NativeCtripFormObservation.java"
        paths = list(dict.fromkeys([*paths, comparator.resolve()]))
        original_paths = list(dict.fromkeys([Path(row["path"]) for row in provenance["production_inputs"]] +
                                           [comparator, Path(__file__).resolve()]))
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
                           "org.trillionnium.hepta.local.NativeFormHistoryConsumersHostTest", out / "CASES.json", out / "work"])
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
