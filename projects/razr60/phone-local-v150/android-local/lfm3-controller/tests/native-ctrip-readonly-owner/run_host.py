#!/usr/bin/env python3
"""Actual pure Ctrip OWNER, auto target and permission consumers; no phone.
Original auto-target compilation ports remain explicit Android/asset/IO fakes.
"""
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
GOAL = "src/org/trillionnium/hepta/local/NativeAppGoal.java"
AUTH = "src/org/trillionnium/hepta/local/TaskAuthorization.java"
RESOLVER = "src/org/trillionnium/hepta/local/BackgroundAutoTargetResolver.java"
TEST = "tests/native-ctrip-readonly-owner/ReadOnlyFlightOwnerHostTest.java"
BASE_GOAL_SHA = "9f823e54fee2862e390df6b86d7a2fc9a02d463c073159dc6f38d6c3a31cb5c4"
AUTH_SHA = "49dc8fe1fd39b03416c268d8ed61577b67d5add232a5f774c7f88307853d7d04"
JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
BASE_NAMES = ["baseline_actual_long_owner_is_unrecognized","baseline_actual_auto_resolution_has_no_match","baseline_enumeration_clause_does_not_remove_submit","baseline_comma_clause_does_remove_submit","baseline_existing_short_and_report_forms_unchanged"]
NAMES = ["actual_long_owner_literal_facts_and_utf16_spans","new_form_same_requested_facts_as_short_owner","actual_saved_auto_resolution_selects_same_ctrip_instance","actual_enumeration_permission_is_narrowed_only_at_selection","comma_separated_original_submit_deny_remains_denied","mixed_punctuation_keeps_original_permission_refusal", "new_purpose_ceiling_is_exact_and_immutable","old_short_report_and_product_ceilings_are_unchanged","iso_ascii_field_spaces_keep_full_owner_and_spans","supplementary_han_city_keeps_utf16_offsets","complete_owner_binding_cannot_drop_restrictions","recognition_never_claims_provider_execution_or_completion","explicit_original_click_deny_is_not_stripped_or_overridden","extra_booking_action_refused","extra_payment_action_refused","extra_order_action_refused","second_app_goal_refused","unknown_report_suffix_refused","unknown_report_phrase_refused","missing_report_phrase_refused","missing_no_order_clause_refused","positive_order_clause_refused","positive_booking_clause_refused","positive_payment_clause_refused","conditional_order_exception_refused","double_negation_refused","reordered_limits_refused","missing_year_refused","relative_date_refused","invalid_calendar_date_refused","zero_year_refused","two_adults_refused","additional_child_refused","return_trip_refused","same_city_refused","alternative_route_refused","multiple_route_refused","city_action_payload_refused","leading_space_not_trimmed","trailing_space_not_trimmed","newline_not_normalized","unpaired_surrogate_refused","extra_tool_clause_not_stripped","new_form_not_added_to_foreign_native_or_web_packages","unknown_complete_owner_does_not_resolve_saved_target"]
ORIGINAL_TESTS = [
    "tests/native-app-goal/run_host.py",
    "tests/native-app-goal/NativeAppGoalHostTest.java",
    "tests/native-app-goal/NativeAppGoalSpacingHostTest.java",
    "tests/native-auto-target/run_host.py",
    "tests/native-auto-target/AutomaticTargetHostTest.java",
    "tests/native-auto-target/host_ports.py",
]
def sha(raw): return hashlib.sha256(raw).hexdigest()
def need(ok, why):
    if not ok: raise RuntimeError(why)
def ref(p):
    p = Path(p)
    need(p.is_file() and not p.is_symlink(), "direct regular input required: " + str(p))
    raw = p.read_bytes()
    return {"path": str(p), "bytes": len(raw), "sha256": sha(raw)}
def write(p, raw):
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("xb") as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    need(p.read_bytes() == raw, "output readback differs")
def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
def snapshot(source):
    return {str(p.relative_to(source)): ref(p) for p in sorted(source.rglob("*"))
            if p.is_file() and "__pycache__" not in p.parts}
def check_cases(path, expected, baseline):
    result = json.loads(path.read_text())
    need(result.get("schema") == "hepta.ctrip-readonly-owner-cases.v1"
         and result.get("all_pass") is True and result.get("baseline") is baseline, "closed case receipt")
    need(result.get("case_names") == expected and result.get("cases") == len(expected)
         and len(set(expected)) == len(expected), "complete exact named cases required")
    need(type(result.get("assertions")) is int and result["assertions"] >= len(expected), "assertion receipt")
    need(result.get("phone_operations") == 0 and result.get("android_runtime") is False
         and result.get("business_verified") is False and result.get("action_dispatched") is False
         and result.get("profile_identity_is_host_fixture") is True, "host scope is not live qualification")
    return result

def main():
    p = argparse.ArgumentParser()
    for name in ("source", "base-source", "output", "java-home", "json-jar"):
        p.add_argument("--" + name, type=Path, required=True)
    a = p.parse_args()
    source = a.source.resolve(strict=True); base = a.base_source.resolve(strict=True)
    out = a.output.absolute(); jdk = a.java_home.resolve(strict=True); jar = a.json_jar.resolve(strict=True)
    need(source != base and source not in out.parents and base not in out.parents and not out.exists(),
         "isolated candidate and fresh output required")
    need(sha((base / GOAL).read_bytes()) == BASE_GOAL_SHA, "exact original whole Goal required")
    need(sha((source / AUTH).read_bytes()) == AUTH_SHA and (source / AUTH).read_bytes() == (base / AUTH).read_bytes(),
         "TaskAuthorization must remain whole-byte identical")
    auto_test_rel="tests/native-auto-target/AutomaticTargetHostTest.java"
    auto_test_helper=source / "tests/native-auto-target/protected_model_preferences.py"
    need(sha(auto_test_helper.read_bytes())=="49e99d5b04f0c35b1375f62710c0e0a5e07e545d24d01cc8eafdad94703a60dc","exact reviewed explicit-model test inverse helper")
    auto_test_predecessor=module(auto_test_helper,"readonly_owner_auto_test_proof").predecessor
    auto_test_inverse=None
    for rel in ORIGINAL_TESTS + [RESOLVER, "src/org/trillionnium/hepta/local/BackgroundTaskTarget.java"]:
        current=(source / rel).read_bytes()
        proof=auto_test_predecessor(current) if rel==auto_test_rel else current
        need(proof == (base / rel).read_bytes(), "original consumer/test or exact full-file predecessor changed: " + rel)
        if rel==auto_test_rel:
            auto_test_inverse={"current":ref(source / rel),"baseline":ref(base / rel),
                "predecessor_sha256":sha(proof),"helper":ref(auto_test_helper),"proof_copy_only":True,
                "actual_compilation_uses_current_46_case_test":sha(current)=="964a1dfa97d9bb582e3937c8d01976e836bdea26d64c7bde77930241bf673993"}
    need(sha(jar.read_bytes()) == JSON_SHA, "fixed original pure JSON dependency")
    out.mkdir(mode=0o700, parents=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
               PATH=str(jdk / "bin") + os.pathsep + os.environ.get("PATH", ""))
    for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"): env.pop(key, None)
    before = snapshot(source)
    record = {"schema": "hepta.ctrip-readonly-owner-host-gate.v1", "all_pass": False,
              "source": str(source), "baseline_source": str(base), "source_before": before,
              "baseline_goal": ref(base / GOAL), "authorization": ref(source / AUTH),
              "phone_operations": 0, "android_runtime": False, "business_verified": False,
              "model_inference": False, "stages": [], "host_ports_explicit": True,
              "explicit_model_test_predecessor":auto_test_inverse}
    record["tools"] = {n: ref(p) for n, p in
                       (("java", jdk / "bin/java"), ("javac", jdk / "bin/javac"), ("json_jar", jar))}
    def run(name, argv):
        start = time.monotonic()
        stdout = out / (name + ".stdout"); stderr = out / (name + ".stderr")
        with stdout.open("xb") as so, stderr.open("xb") as se:
            done = subprocess.run(list(map(str, argv)), cwd=out, env=env, stdin=subprocess.DEVNULL,
                                  stdout=so, stderr=se, timeout=100, check=False)
        stage = {"name": name, "argv": list(map(str, argv)), "exit_code": done.returncode,
                 "elapsed_seconds": time.monotonic() - start, "stdout": ref(stdout), "stderr": ref(stderr)}
        record["stages"].append(stage)
        need(done.returncode == 0, "actual stage failed: " + name)
    try:
        auto = module(source / "tests/native-auto-target/run_host.py", "readonly_owner_auto_closure")
        goal_gate = module(source / "tests/native-app-goal/run_host.py", "readonly_owner_old_goal_gate")
        inputs, extraction = auto.prepare(source, out)
        inputs += [source / TEST, source / "tests/native-app-goal/NativeAppGoalHostTest.java",
                   source / "tests/native-app-goal/NativeAppGoalSpacingHostTest.java",
                   source / "tests/native-auto-target/AutomaticTargetHostTest.java"]
        need(len(inputs) == len(set(inputs)), "duplicate compiler input")
        for rel in (GOAL, AUTH, RESOLVER, "src/org/trillionnium/hepta/local/BackgroundTaskTarget.java",auto_test_rel):
            need(inputs.count(source / rel) == 1, "actual complete consumer compiler input: " + rel)
        record["extraction"] = extraction
        record["compile_inputs_before"] = [ref(x) for x in inputs]
        classes = out / "classes"; classes.mkdir()
        original_classes = out / "baseline-goal-classes"; original_classes.mkdir()
        empty = out / "empty-sourcepath"; empty.mkdir()
        run("compile", [jdk / "bin/javac", "--release", "8", "-encoding", "UTF-8", "-proc:none",
                        "-Xlint:all,-options", "-Werror", "-sourcepath", empty, "-cp", jar, "-d", classes, *inputs])
        run("compile-baseline-goal", [jdk / "bin/javac", "--release", "8", "-encoding", "UTF-8",
                        "-proc:none", "-Xlint:all,-options", "-Werror", "-sourcepath", empty,
                        "-d", original_classes, base / GOAL])
        cp = str(classes) + os.pathsep + str(jar)
        run("baseline", [jdk / "bin/java", "-Xmx256m", "-cp", str(original_classes) + os.pathsep + cp,
                         "org.trillionnium.hepta.local.ReadOnlyFlightOwnerHostTest", "--baseline"])
        record["baseline_cases"] = check_cases(out / "baseline.stdout", BASE_NAMES, True)
        run("candidate", [jdk / "bin/java", "-Xmx256m", "-cp", cp,
                          "org.trillionnium.hepta.local.ReadOnlyFlightOwnerHostTest"])
        record["cases"] = check_cases(out / "candidate.stdout", NAMES, False)
        run("original-goals", [jdk / "bin/java", "-Xmx256m", "-cp", cp,
                              "org.trillionnium.hepta.local.NativeAppGoalHostTest"])
        run("original-spacing", [jdk / "bin/java", "-Xmx256m", "-cp", cp,
                                "org.trillionnium.hepta.local.NativeAppGoalSpacingHostTest"])
        for name, schema, expected in (
                ("original-goals", "hepta.native-app-goal-host.v1", goal_gate.EXPECTED_NAMES),
                ("original-spacing", "hepta.native-app-goal-spacing-host.v1", goal_gate.SPACING_EXPECTED_NAMES)):
            value = json.loads((out / (name + ".stdout")).read_text())
            need(value.get("schema") == schema and value.get("all_pass") is True
                 and value.get("case_names") == expected and value.get("cases") == len(expected)
                 and value.get("assertions", 0) >= len(expected), "original full case set changed")
            record[name] = value
        legacy = source / "tests/native-auto-target/fixtures/legacy-ctrip-gui.json"
        need(sha(legacy.read_bytes()) == "a81058189584615f52dea098d79ba7d78fef59f996e38456009a1e1eb36949d7",
             "original saved GUI preference fixture")
        record["original_auto_preference"] = ref(legacy)
        run("original-auto", [jdk / "bin/java", "-Xmx256m", "-Dhepta.fixture.host_uid=" + str(os.getuid()),
                             "-cp", cp, "org.trillionnium.hepta.local.AutomaticTargetHostTest", out / "auto-cases", legacy])
        auto_cases = json.loads((out / "auto-cases/RESULT.json").read_text())
        need(auto_cases.get("schema") == "hepta.automatic-target-cases.v1" and auto_cases.get("all_pass") is True
             and auto_cases.get("phone_operations") == 0, "original automatic target cases failed")
        if auto_test_inverse["actual_compilation_uses_current_46_case_test"]:
            need(auto_cases.get("cases")==46,"all original 34 plus 12 explicit-model cases must execute")
        record["original_auto_cases"] = auto_cases
        record["compile_inputs_after"] = [ref(x) for x in inputs]
        need(record["compile_inputs_before"] == record["compile_inputs_after"], "compiler input changed")
        record["all_pass"] = True
    except BaseException as error:
        record["error"] = type(error).__name__ + ": " + str(error)
    finally:
        record["source_after"] = snapshot(source)
        record["source_unchanged"] = record["source_before"] == record["source_after"]
        record["authorization_unchanged"] = (source / AUTH).read_bytes() == (base / AUTH).read_bytes()
        record["all_pass"] = record["all_pass"] and record["source_unchanged"] and record["authorization_unchanged"]
        write(out / "RESULT.json", (json.dumps(record, ensure_ascii=False, indent=2) + "\n").encode())
        print(json.dumps({"all_pass": record["all_pass"], "error": record.get("error"),
                          "result": ref(out / "RESULT.json")}, ensure_ascii=False))
    return 0 if record["all_pass"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
