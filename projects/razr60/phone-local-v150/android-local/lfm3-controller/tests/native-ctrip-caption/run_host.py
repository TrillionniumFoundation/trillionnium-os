#!/usr/bin/env python3
"""Pinned recorded facts and complete-AX-derived caption cases; no device IO."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

HERE = Path(__file__).resolve().parent
PKG = Path("src/org/trillionnium/hepta/local")
BASE_SHA = "c1df34cb7613f7b50e206b89140e1518556343f438fe43594ff27ca1c5db3346"
JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
RECORDED = {
    "step-02-action.json": (48100, "be395fbedb96824f14d89ab8077d7b1c1b465cf12c652f1bc2845c5f6813f1b5"),
    "step-03-action.json": (48437, "7a76136d2aef8d043555e132aa18812f002e825008844f665952faf2cafde024"),
    "step-04-action.json": (48100, "9f8ee85305a036d4da5f2005dd6199a30e337b2166ae4643af054c846f1c4fd7"),
    "4438ee67817a433aa8e1d88b1f48c994-native-ax.json": (371073, "14be4d5e23c295d05e3aeb082f69c1e74c78a8e4c17709ed6f6791a851b6d831"),
    "6afece2af5ce4717b68731456beeb64c-native-ax.json": (380494, "d449521e8b2e7fdbbb7cbb9c0467ce42204e64e3b7649db78cac1fed34c4d67d"),
    "a999b83d176145d9894501221f4b9c80-native-ax.json": (366438, "39810fc86275cae589875cccdeb43ce67e15a470636844b3201196d48df4278f"),
}
NAMES = [
    "ObservationCaptureEvidence.java", "NativeCtripFormObservation.java",
    "NativeXiaomiSearchInputObservation.java", "NativeActionSnapshotCheck.java",
    "ObservedChildText.java", "ObservedTargetLabels.java",
    "ObservedScrollActions.java", "ObservedImeEnter.java",
]


FIXED_PRODUCTION = {
  "ObservationCaptureEvidence.java": [
    32347,
    "e7306d40d576efda5541e139abfc7e07c794f538aee7522f8f1f466947935f4c"
  ],
  "NativeCtripFormObservation.java": [
    25935,
    "ff884b8cafe28330262e8ff27423eaf34553faed3556984a3d188876ccef02ad"
  ],
  "NativeXiaomiSearchInputObservation.java": [
    26082,
    "6802c799ab5308594b9f817a3f00439f95ec3a27d5be991e2c3ea6138638b074"
  ],
  "NativeActionSnapshotCheck.java": [
    88545,
    "46c6aed0dfb6279c5b56ec80095a5d2fead6c3c95335f70d5a47a98bef52e0f6"
  ],
  "ObservedChildText.java": [
    10858,
    "56433b62f9c4c895edac441160fcdc4aaee7365586daa4b86863448dc4dd54d5"
  ],
  "ObservedTargetLabels.java": [
    4685,
    "c4e1b1a7ae0223fc7cda90864c6a5c3759a2875bb435359464672bc79465c8ba"
  ],
  "ObservedScrollActions.java": [
    2303,
    "c31012cf776fbc4177d6c617341d006f4a45ed63df3cfc435f705e515ebbc188"
  ],
  "ObservedImeEnter.java": [
    4665,
    "e449d61e928dca5a72730b5394fa8f95a7db4dd4006440a95f839818e165acf1"
  ]
}
EXPECTED_CANDIDATE_NAMES = [
  "recorded_step_2_refusal_facts",
  "recorded_complete_ax_pair_step_2",
  "derived_visible_caption_step_2",
  "derived_hidden_caption_step_2",
  "derived_reverse_caption_step_2",
  "derived_mixed_three_pages_step_2",
  "derived_all_ad_captions_step_2",
  "recorded_step_3_refusal_facts",
  "recorded_complete_ax_pair_step_3",
  "derived_visible_caption_step_3",
  "derived_hidden_caption_step_3",
  "derived_reverse_caption_step_3",
  "derived_mixed_three_pages_step_3",
  "derived_all_ad_captions_step_3",
  "recorded_step_4_refusal_facts",
  "recorded_complete_ax_pair_step_4",
  "derived_visible_caption_step_4",
  "derived_hidden_caption_step_4",
  "derived_reverse_caption_step_4",
  "derived_mixed_three_pages_step_4",
  "derived_all_ad_captions_step_4",
  "unknown_caption_text",
  "unknown_caption_before",
  "unknown_caption_class",
  "unknown_caption_resource",
  "caption_unknown_description",
  "caption_with_complete_child",
  "caption_capability_clickable",
  "caption_capability_action_click",
  "caption_capability_editable",
  "caption_capability_scrollable",
  "caption_capability_focused",
  "caption_capability_password",
  "caption_capability_selected",
  "caption_capability_checkable",
  "caption_capability_checked",
  "caption_disabled",
  "caption_unknown_scroll_metadata",
  "caption_unknown_ime_metadata",
  "caption_input_body_hash",
  "caption_projected_label_disagrees",
  "caption_reference_disagrees",
  "hidden_caption_label_present",
  "hidden_caption_reference_present",
  "caption_new_unknown_field",
  "caption_vertical_motion",
  "banner_overlaps_form_body",
  "raw_image_overlaps_date_hit",
  "visible_sibling_overlaps_date_hit",
  "form_date_changed",
  "form_city_changed",
  "form_unselected_control_changed",
  "target_reference_changed",
  "actual_form_ancestor_changed",
  "owner_changed",
  "profile_leaf_changed",
  "ime_visible",
  "complete_census_has_omission",
  "original_eight_second_action_deadline",
  "original_twelve_second_history_bound",
  "combined_caption_and_horizontal_motion_with_current_references",
  "combined_caption_motion_hidden_to_visible_with_current_references",
  "combined_caption_motion_visible_to_hidden_with_current_references",
  "combined_caption_valid_reference_overlaps_date_refused",
  "combined_caption_valid_reference_overlaps_query_refused",
  "combined_caption_valid_reference_with_click_capability_refused",
  "caption_literal_on_protected_non_target_branch_refused"
]

def meta(path):
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def stage(name, argv, out):
    start = time.monotonic()
    stdout, stderr = out / (name + ".stdout"), out / (name + ".stderr")
    with stdout.open("xb") as stream, stderr.open("xb") as errors:
        env = dict(os.environ)
        for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"):
            env.pop(key, None)
        run = subprocess.run(argv, stdout=stream, stderr=errors, check=False, timeout=180, env=env)
    return {
        "name": name, "argv": argv, "exit_code": run.returncode,
        "elapsed_seconds": time.monotonic() - start,
        "stdout": meta(stdout), "stderr": meta(stderr),
    }


def main():
    parser = argparse.ArgumentParser()
    for name in ("source", "output", "java-home", "json-jar", "recorded-root", "baseline-comparator"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--candidate-only", action="store_true")
    args = parser.parse_args()
    source, recorded = args.source.resolve(), args.recorded_root.resolve()
    out = args.output.absolute()
    out.mkdir(parents=True, exist_ok=False)
    java, javac = args.java_home.resolve() / "bin/java", args.java_home.resolve() / "bin/javac"
    jar, baseline = args.json_jar.resolve(), args.baseline_comparator.resolve()
    production = [source / PKG / name for name in NAMES]
    test = HERE / "NativeCtripCaptionHostTest.java"
    inputs = production + [test, Path(__file__).resolve(), baseline] + [recorded / name for name in RECORDED]
    tools = [java, javac, args.java_home.resolve() / "lib/modules", args.java_home.resolve() / "lib/ct.sym", jar]
    result = {
        "schema": "hepta.ctrip-caption-independent-host.v1", "all_pass": False,
        "candidate_only": args.candidate_only, "prior_60_cases_preserved": True,
        "new_combination_cases_expected": 7,
        "base_head": "5b943de939a72d0e61fd912c6af3b3edc60ad0f5",
        "recorded_task": "a9e6127f97a04854ab908d664f533e63",
        "recorded_b3_sha256": "fcb570f2444deacf170d6796f8a15ebc5419fd5614eb2fbdafa78b3363f2c159",
        "stages": [], "source_root": str(source), "phone_operations": 0,
        "android_execution": False, "model_executed": False,
        "business_completion_verified": False, "platform_dispatch_executed": False,
        "missing_failed_fresh_censuses_replayed": False,
        "derived_variants_are_synthetic": True, "synthetic_action_intents": True,
    }
    before = []
    tool_before = []
    try:
        before = [meta(path) for path in inputs]
        tool_before = [meta(path) for path in tools]
        result["inputs_before"], result["tools_before"] = before, tool_before
        for path in production:
            fact = meta(path)
            if [fact["bytes"], fact["sha256"]] != FIXED_PRODUCTION[path.name]:
                raise RuntimeError("unchanged complete production required: " + path.name)
        if meta(jar)["sha256"] != JSON_SHA or jar.stat().st_size != 78332:
            raise RuntimeError("JSON library pin differs")
        if meta(baseline)["sha256"] != BASE_SHA:
            raise RuntimeError("exact installed-5b comparator baseline differs")
        for name, (size, digest) in RECORDED.items():
            fact = meta(recorded / name)
            if fact["bytes"] != size or fact["sha256"] != digest:
                raise RuntimeError("immutable recorded evidence differs: " + name)
        for mode in (("candidate",) if args.candidate_only else ("baseline", "candidate")):
            classes = out / (mode + "-classes")
            classes.mkdir()
            sources = list(production)
            if mode == "baseline":
                base_source = out / "baseline-source" / "NativeActionSnapshotCheck.java"
                base_source.parent.mkdir()
                shutil.copyfile(baseline, base_source)
                sources = [base_source if path.name == base_source.name else path for path in sources]
            compile_argv = [str(javac), "-J-Xmx512m", "--release", "8", "-encoding", "UTF-8", "-proc:none",
                            "-Xlint:all", "-Werror", "-cp", str(jar), "-d", str(classes)]
            compile_argv += [str(path) for path in sources + [test]]
            item = stage(mode + "-compile", compile_argv, out)
            result["stages"].append(item)
            if item["exit_code"]:
                raise RuntimeError(mode + " compilation failed")
            case_file = out / (mode.upper() + "-CASES.json")
            argv = [str(java), "-Xmx512m", "-ea", "-cp", str(classes) + os.pathsep + str(jar),
                    "org.trillionnium.hepta.local.NativeCtripCaptionHostTest",
                    str(recorded), str(case_file), mode]
            item = stage(mode + "-cases", argv, out)
            result["stages"].append(item)
            if item["exit_code"]:
                raise RuntimeError(mode + " cases failed")
            cases = json.loads(case_file.read_text())
            if (cases.get("all_pass") is not True or cases["cases"] != len(cases["case_names"])
                    or len(set(cases["case_names"])) != cases["cases"]
                    or cases.get("recorded_action_fact_cases") != 3
                    or cases.get("recorded_complete_ax_pair_cases") != 3
                    or cases.get("missing_failed_fresh_censuses_replayed") is not False
                    or cases.get("phone_operations") != 0):
                raise RuntimeError(mode + " case accounting or evidence scope differs")
            if mode == "candidate" and (cases["case_names"] != EXPECTED_CANDIDATE_NAMES
                    or len(cases.get("combination_evidence", [])) != 7):
                raise RuntimeError("all prior 60 and exactly seven combination cases required")
            result[mode] = {"result": meta(case_file), "cases": cases}
        result["all_pass"] = True
    except Exception as failure:
        result["error"] = {"type": type(failure).__name__, "message": str(failure)}
    finally:
        result["inputs_after"] = [meta(path) for path in inputs]
        result["tools_after"] = [meta(path) for path in tools]
        result["inputs_unchanged"] = before == result["inputs_after"]
        result["tools_unchanged"] = tool_before == result["tools_after"]
        result["all_pass"] &= result["inputs_unchanged"] and result["tools_unchanged"]
        (out / "RESULT.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"all_pass": result["all_pass"], "error": result.get("error"), "result": meta(out / "RESULT.json")}))
    return 0 if result["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
