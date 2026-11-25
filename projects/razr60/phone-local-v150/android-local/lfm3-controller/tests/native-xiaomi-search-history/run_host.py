#!/usr/bin/env python3
"""Compile actual baseline/candidate classes against exact archived f5fb censuses.

Original records are external host inputs, never generated phone evidence. Each
counterfactual is named; no Phone, model, Android permission or device operation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
sys.dont_write_bytecode = True
PKG = Path("src/org/trillionnium/hepta/local")
TEST = Path("tests/native-xiaomi-search-history")
JAVA = "NativeXiaomiSearchHistoryHostTest.java"
JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
BASE_INPUT_SHA = "ecf6a9ccf173dc78c6c167435dc745b4080aa85a4fb77b22c3d442b7674254c3"
TASK = "f5fb4ae516044e3e9abb6141f9eb8e8c"
RECORDINGS = {
    "step-02-action.json": (447200, "4554c22389eb4004eac8bab563735105e99ec4e9cda69ef7080eb45b9ccd9dda"),
    "step-03-action.json": (448094, "93e617d4dfe57f19f5b759dfd039dff65c2fbc1716f2ceb94eb13972f3e4585e"),
    "step-04-action.json": (447176, "760793d0ead3a00167cd077ea1fb12f4e6dd38b965f2981c6d0e48427a6486f2"),
}
NAMES = (
    "ObservationCaptureEvidence", "NativeCtripFormObservation", "NativeActionSnapshotCheck",
    "NativeXiaomiSearchInputObservation", "ObservedChildText", "ObservedTargetLabels",
    "ObservedScrollActions", "ObservedImeEnter",
)
EXPECTED_CANDIDATE = [
  "original_six_complete_censuses_and_zero_effect_failures_preserved",
  "recorded_step_02_complete_pair_accepted",
  "recorded_step_02_original_action_values_accepted_without_dispatch_authority",
  "recorded_step_03_complete_pair_accepted",
  "recorded_step_03_original_action_values_accepted_without_dispatch_authority",
  "recorded_step_04_complete_pair_accepted",
  "recorded_step_04_original_action_values_accepted_without_dispatch_authority",
  "equal_tree_keeps_final_live_check_requirement",
  "prefix_never_becomes_variable_or_a_click_target",
  "history_heading_text_changed_refused",
  "history_heading_label_changed_refused",
  "history_item_label_changed_refused",
  "history_item_own_text_added_refused",
  "history_child_text_changed_refused",
  "history_child_label_changed_refused",
  "history_heading_click_capability_added_refused",
  "history_item_click_capability_removed_refused",
  "history_item_disabled_refused",
  "history_item_hidden_refused",
  "history_item_editable_refused",
  "history_item_selected_refused",
  "history_child_focused_refused",
  "history_item_description_added_refused",
  "history_item_view_id_changed_refused",
  "history_heading_reference_changed_refused",
  "history_item_reference_changed_refused",
  "history_child_reference_changed_refused",
  "history_item_over_query_toolbar_refused",
  "history_child_outside_item_refused",
  "history_title_overlaps_item_refused",
  "history_item_overlaps_recommendation_title_refused",
  "recommendation_title_is_still_protected_refused",
  "refresh_control_is_still_protected_refused",
  "history_child_missing_refused",
  "duplicate_history_node_refused",
  "second_history_item_instead_of_recommendation_title_refused",
  "query_text_altered_refused",
  "query_reference_altered_refused",
  "query_disabled_refused",
  "query_focused_refused",
  "normal_search_button_altered_refused",
  "recommendation_gains_editability_refused",
  "recommendation_capability_altered_refused",
  "recommendation_leaves_enclosure_refused",
  "later_fixed_carousel_changed_refused",
  "offscreen_fixed_branch_changed_refused",
  "membership_omission_refused",
  "truncated_census_refused",
  "incomplete_census_refused",
  "unknown_ime_refused",
  "incomplete_window_report_refused",
  "window_metadata_changed_refused",
  "additional_reported_window_refused",
  "cross_display_refused",
  "cross_owner_refused",
  "cross_profile_refused",
  "cross_installed_set_refused",
  "cross_authorization_refused",
  "cross_goal_refused",
  "unsupported_history_literal_on_both_sides_refused",
  "wrong_history_title_on_both_sides_refused",
  "history_input_capability_on_both_sides_refused",
  "history_overlap_on_both_sides_refused",
  "extra_search_label_on_both_sides_refused",
  "one_side_loses_history_prefix",
  "old_observation_age_not_renewed",
  "original_action_deadline_not_extended",
  "history_item_never_selected_for_set_query",
  "different_original_query_reference_refused",
  "recorded_json_not_mutated"
]

def need(value, reason):
    if not value:
        raise RuntimeError(reason)

def read(path):
    p = Path(path).absolute()
    need(p.resolve(strict=True) == p, "input path must be exact and symlink-free: " + str(p))
    a = p.lstat()
    need(stat.S_ISREG(a.st_mode) and a.st_nlink == 1, "plain regular single-link input required")
    raw = p.read_bytes()
    b = p.lstat()
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_nlink")
    need(all(getattr(a, f) == getattr(b, f) for f in fields), "input changed while read: " + str(p))
    return raw

def ref(path):
    p = Path(path).absolute()
    raw = read(p)
    return dict(path=str(p), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), mode=stat.S_IMODE(p.stat().st_mode))

def recorded_fixture(root):
    pairs, refs = [], []
    for name, (size, digest) in RECORDINGS.items():
        p = root / name
        raw = read(p)
        need(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest, "original action recording pin: " + name)
        action = json.loads(raw)
        e = action["action_execution"]
        r = e["native_action_rejection_census"]
        need(e["task_id"] == TASK and r["schema"] == "hepta.native-action-rejection-census.v1"
             and r["complete_two_censuses"] is True and r["nodes_truncated"] is False,
             "complete same-task original worker rejection required")
        need(action["accepted"] is False and action["dispatched"] is False
             and e["effect_entered"] is False and e["effect_returned"] is False
             and e["worker_drained"] is True
             and r["comparison_refusal"] == "actual recommendation section heading",
             "historical failed no-effect action must remain intact")
        need(action["action"]["action"] == "type" and action["action"]["text"] == "AX3000T"
             and r["purpose"] == "set_product_query" and r["target_path"] == "0/1"
             and r["original_node_id"] == "n1", "exact historical model action")
        pin = ref(p); refs.append(pin)
        pairs.append(dict(step=int(name[5:7]), before=r["before"], fresh=r["fresh"],
                          guard=e["native_action_guard"],
                          original_node_id=r["original_node_id"], original_action_sha256=r["original_action_sha256"],
                          compared_elapsed_ms=r["compared_elapsed_ms"], original_action_file=pin,
                          complete_two_censuses=r["complete_two_censuses"], nodes_truncated=r["nodes_truncated"],
                          effect_entered=e["effect_entered"], effect_returned=e["effect_returned"],
                          dispatched=action["dispatched"], worker_drained=e["worker_drained"],
                          original_refusal=r["comparison_refusal"]))
    return dict(schema="hepta.xiaomi-search-history-recorded-pairs.v1", task_id=TASK,
                pairs=pairs, original_node_fields_rewritten=False,
                original_android_action_replayed=False, phone_operations=0), refs

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("source", "base-source", "recorded-dir", "output", "java-home", "json-jar"):
        p.add_argument("--" + key, type=Path, required=True)
    a = p.parse_args()
    source, base, recordings, out, jdk, jar = [
        getattr(a, key).absolute() for key in ("source", "base_source", "recorded_dir", "output", "java_home", "json_jar")
    ]
    need(not out.exists() and source not in out.parents and base not in out.parents, "fresh output outside both source trees")
    out.mkdir(parents=True, mode=0o700)
    report = dict(schema="hepta.xiaomi-search-history-host-run.v1", all_pass=False,
                  source=str(source), base_source=str(base), stages=[], variants={},
                  actual_complete_production_classes=True, phone_operations=0,
                  android_execution=False, model_executed=False, business_completion_verified=False)
    before, tool_before = [], []
    tracked = list(dict.fromkeys([Path(__file__).absolute(), source / TEST / JAVA]
              + [root / PKG / (name + ".java") for root in (base, source) for name in NAMES]
              + [recordings / name for name in RECORDINGS]))
    tools = [jdk / "bin/java", jdk / "bin/javac", jdk / "lib/modules", jdk / "lib/ct.sym", jar]
    env = dict(os.environ, JAVA_HOME=str(jdk), PATH=str(jdk / "bin") + ":/usr/bin:/bin", PYTHONDONTWRITEBYTECODE="1")
    for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"):
        env.pop(key, None)
    def stage(label, argv):
        started = time.monotonic()
        run = subprocess.run(list(map(str, argv)), cwd=out, env=env, capture_output=True, timeout=180)
        stdout, stderr = out / (label + ".stdout"), out / (label + ".stderr")
        with stdout.open("xb") as f: f.write(run.stdout)
        with stderr.open("xb") as f: f.write(run.stderr)
        report["stages"].append(dict(name=label, argv=list(map(str, argv)), exit_code=run.returncode,
                                    elapsed_seconds=time.monotonic()-started, stdout=ref(stdout), stderr=ref(stderr)))
        need(run.returncode == 0, label + " failed; actual stdout and stderr preserved")
    try:
        before = [ref(x) for x in tracked]; tool_before = [ref(x) for x in tools]
        report["inputs_before"], report["tools_before"] = before, tool_before
        need(ref(jar)["sha256"] == JSON_SHA and ref(jar)["bytes"] == 78332, "original JSON runtime pin")
        need(ref(base / PKG / "NativeXiaomiSearchInputObservation.java")["sha256"] == BASE_INPUT_SHA, "exact installed baseline predicate")
        for name in NAMES:
            if name != "NativeXiaomiSearchInputObservation":
                need(read(base / PKG / (name + ".java")) == read(source / PKG / (name + ".java")),
                     "new gate only changes intended input predicate; integration may qualify other inputs separately: " + name)
        fixture, record_refs = recorded_fixture(recordings)
        fixture_path = out / "RECORDED-PAIRS.json"
        with fixture_path.open("x") as f: f.write(json.dumps(fixture, ensure_ascii=False, indent=2) + "\n")
        report["recorded_inputs"], report["recorded_fixture"] = record_refs, ref(fixture_path)
        stage("jdk-version", [jdk / "bin/javac", "-version"])
        need(((out / "jdk-version.stdout").read_bytes() + (out / "jdk-version.stderr").read_bytes()).decode().strip().startswith("javac 17."),
             "JDK 17 required")
        for variant, root in (("baseline", base), ("candidate", source)):
            classes = out / (variant + "-classes"); classes.mkdir()
            paths = [root / PKG / (name + ".java") for name in NAMES] + [source / TEST / JAVA]
            report["variants"][variant] = dict(compile_inputs=[ref(x) for x in paths])
            stage(variant + "-compile", [jdk / "bin/javac", "--release", "8", "-encoding", "UTF-8", "-proc:none",
                                        "-Xlint:all", "-Werror", "-cp", jar, "-d", classes, *paths])
            case_file = out / (variant + "-CASES.json")
            stage(variant + "-cases", [jdk / "bin/java", "-ea", "-cp", str(classes) + os.pathsep + str(jar),
                                       "org.trillionnium.hepta.local.NativeXiaomiSearchHistoryHostTest", fixture_path, case_file, variant])
            cases = json.loads(read(case_file))
            expected = ["baseline_actual_step_0%d_rejects_historical_prefix" % n for n in (2,3,4)] if variant == "baseline" else EXPECTED_CANDIDATE
            need(cases.get("all_pass") is True and cases["case_names"] == expected
                 and cases["cases"] == len(expected) == len(cases["results"]) == len(set(cases["case_names"]))
                 and [x["name"] for x in cases["results"]] == expected
                 and all(x.get("passed") is True for x in cases["results"]), "exact complete " + variant + " case set")
            report["variants"][variant].update(result=ref(case_file), cases=cases["cases"],
                                                assertions=cases["assertions"], case_names=cases["case_names"], all_pass=True)
        report["all_pass"] = True
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        report["inputs_after"] = [ref(x) for x in tracked]
        report["tools_after"] = [ref(x) for x in tools]
        report["inputs_unchanged"] = before == report["inputs_after"]
        report["tools_unchanged"] = tool_before == report["tools_after"]
        report["all_pass"] = report["all_pass"] and report["inputs_unchanged"] and report["tools_unchanged"]
        target = out / "RESULT.json"
        with target.open("x") as f: f.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps(dict(all_pass=report["all_pass"], error=report.get("error"), result=ref(target),
                              variants=report["variants"])))
    return 0 if report["all_pass"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
