#!/usr/bin/env python3
"""Exact same-read membership proof reuse. Pure host; never invokes Android/ADB."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
FIXTURE_SHA = "b3a758e849b621bac4b21c508fa330dce03df38329b82ea260f01b635d44b0c9"
NAMES = ["ProfileIdentity", "ProfileTarget", "WindowOwnership", "BrokerProtocol",
         "PublicPermissionControllerUi", "PublicOwnGroupPolicy", "FixedIntentTools",
         "BackgroundOwnedTaskPolicy", "BackgroundOwnedSingleTask", "ProfileTaskPolicy",
         "ProfileOwnedTask", "ProfilePermissionTransient", "ProfileDisplayCustody",
         "PublicOwnGroupPhysicalFence", "PublicProfileRecentHistory"]
EXPECTED = [
    "opaque_private_constructor_and_thread_local_lifetime",
    "full_foreign_profile_raw_census_exact",
    "owned_leaf_full_raw_census_exact",
    "complete_utf8_non_ascii_body_preserved",
    "decimal_uid_same_complete_proof",
    "omitted_visible_home_and_detached_hidden_preserved",
    "unknown_hidden_identity_not_filtered",
    "null_raw_refused",
    "empty_raw_refused",
    "truncated_record_refused",
    "appended_dump_timeout_refused",
    "duplicate_identity_refused",
    "duplicate_internal_task_refused",
    "visible_identity_mismatch_refused",
    "uid_user_disagreement_refused",
    "rich_identity_component_invalid_refused",
    "omitted_visible_foreign_nonhome_refused",
    "one_raw_two_full_parses_becomes_one_with_equal_complete_census",
    "opaque_proof_rejects_equal_bytes_new_read",
    "opaque_proof_rejects_changed_raw",
    "opaque_proof_rejects_truncated_raw",
    "opaque_proof_rejects_appended_raw",
    "opaque_proof_rejects_duplicate_rows",
    "one_scope_cannot_authorize_second_projection",
    "closed_scope_rejects_same_and_changed_next_phase",
    "wrong_thread_cannot_consume_or_close_owner_scope",
    "null_scope_refused",
    "mismatch_claim_cannot_be_retried_with_original",
    "full_ownership_lifecycle_fresh_reads_effects_and_history_equal",
    "coordinator_finally_invalidates_scope_on_observer_exception",
    "foreign_history_change_still_latches_before_any_retire_effect",
    "late_foreign_change_after_leaf_remove_still_blocks_root_delete",
]
def need(value, reason):
    if not value:
        raise AssertionError(reason)
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def meta(path):
    return dict(path=str(path), bytes=path.stat().st_size, sha256=sha(path),
                mode=oct(path.stat().st_mode & 0o777))
def inventory(root):
    return {str(p.relative_to(root)): dict(bytes=p.stat().st_size, sha256=sha(p), mode=oct(p.stat().st_mode & 0o777))
            for p in sorted(root.rglob("*")) if p.is_file()}
def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for key in ("source", "java-home", "json-jar", "output"):
        ap.add_argument("--" + key, type=Path, required=True)
    a = ap.parse_args()
    source, out = a.source.resolve(), a.output.resolve()
    need(not out.exists() and source != out and source not in out.parents, "new output outside source required")
    need(sha(a.json_jar) == JSON_SHA, "fixed JSON dependency changed")
    fixture = source / "tests/profile-cleanup-sampling/fixtures-synthetic/before-recents.txt"
    need(sha(fixture) == FIXTURE_SHA, "synthetic fixture changed")
    before = inventory(source)
    bg = source / "src/org/trillionnium/hepta/background"
    test = source / "tests/profile-recents-parse-reuse/ProfileRecentsParseReuseHostTest.java"
    private = source / "tests/profile-broker/ProfileBrokerHostTest.java"
    sampling = source / "tests/profile-cleanup-sampling/ProfileCleanupSamplingHostTest.java"
    files = [bg / (name + ".java") for name in NAMES] + [private, sampling, test]
    tracked = files + [fixture, Path(__file__).resolve()]
    out.mkdir(parents=True)
    result = dict(schema="hepta.profile-recents-parse-reuse-host.v1", all_pass=False,
                  source=str(source), phone_operations=0, android_runtime=False, model_executed=False,
                  phone_latency_improvement_claimed=False, causal_attribution_to_actual_6127=False,
                  original_cleanup_read_budget_ms=1400, fresh_dump_cadence_changed=False,
                  synthetic_framework_clock_and_recents=True, expected_case_count=len(EXPECTED),
                  input_before=[meta(p) for p in tracked], tools_before=[meta(a.java_home / "bin/java"),
                  meta(a.java_home / "bin/javac"), meta(a.json_jar)], stages=[], variants={})
    (out / "SOURCE-BEFORE.json").write_text(json.dumps(before, indent=2) + "\n")
    def run(label, argv):
        started = time.monotonic()
        proc = subprocess.run([str(x) for x in argv], cwd=out, capture_output=True, timeout=90)
        stdout, stderr = out / (label + ".stdout"), out / (label + ".stderr")
        stdout.write_bytes(proc.stdout); stderr.write_bytes(proc.stderr)
        result["stages"].append(dict(name=label, argv=[str(x) for x in argv], exit_code=proc.returncode,
                                    elapsed_seconds=time.monotonic() - started, stdout=meta(stdout), stderr=meta(stderr)))
        need(proc.returncode == 0, label + ": " + proc.stderr.decode("utf-8", "backslashreplace")[-6000:])
        if not label.endswith("-compile"):
            return json.loads(proc.stdout.decode("utf-8").splitlines()[0])
    try:
        jdk = a.java_home.resolve() / "bin"
        flags = ["--release", "8", "-proc:none", "-Xlint:all,-options", "-Werror", "-encoding", "UTF-8"]
        for variant in ("actual", "counted"):
            current = list(files)
            if variant == "counted":
                original = bg / "ProfileTaskPolicy.java"
                old = "        public static Recents parse(String text)throws Exception{"
                new = old + "\n            ProfileRecentsParseReuseHostTest.countParse();"
                text = original.read_text()
                need(text.count(old) == 1, "single actual complete parser entry required")
                derived = out / "counted-source" / "ProfileTaskPolicy.java"
                derived.parent.mkdir()
                derived.write_text(text.replace(old, new))
                need(derived.read_text().replace(new, old) == text, "instrumentation inverse differs")
                current = [derived if p == original else p for p in current]
                result["instrumentation"] = dict(original=meta(original), compile_input=meta(derived),
                                                exact_insertion=new[len(old):], whole_inverse_equal=True,
                                                original_parser_body_changed=False, output_only=True)
            classes = out / (variant + "-classes")
            classes.mkdir()
            run(variant + "-compile", [jdk / "javac", *flags, "-cp", a.json_jar, "-d", classes, *current])
            cp = str(classes) + os.pathsep + str(a.json_jar.resolve())
            if variant == "actual":
                adversary = out / "constructor-forgery" / "ConstructorForgery.java"
                adversary.parent.mkdir()
                adversary.write_text("package org.trillionnium.hepta.background;\n"
                    "final class ConstructorForgery {\n"
                    " static Object source(String raw,ProfileTaskPolicy.Recents value) {\n"
                    "  return new ProfileTaskPolicy.Recents.Observation(raw,value);\n }\n"
                    " static Object bridge(String raw,ProfileTaskPolicy.Recents value) {\n"
                    "  return new ProfileTaskPolicy.Recents.Observation(raw,value,null);\n }\n}\n")
                negative_classes = out / "constructor-forgery-classes"
                negative_classes.mkdir()
                argv = [jdk / "javac", *flags, "-cp", cp, "-d", negative_classes, adversary]
                began = time.monotonic()
                neg = subprocess.run([str(x) for x in argv], cwd=out, capture_output=True, timeout=30)
                stdout, stderr = out / "constructor-forgery.stdout", out / "constructor-forgery.stderr"
                stdout.write_bytes(neg.stdout); stderr.write_bytes(neg.stderr)
                error = neg.stderr.decode("utf-8")
                passed = (neg.returncode == 1 and "has private access" in error
                          and "actual and formal argument lists differ in length" in error
                          and "2 errors" in error and not list(negative_classes.rglob("*.class")))
                result["constructor_source_refusal"] = dict(passed=passed, expected_exit_code=1,
                    exit_code=neg.returncode, argv=[str(x) for x in argv], seconds=time.monotonic()-began,
                    source=meta(adversary), stdout=meta(stdout), stderr=meta(stderr),
                    private_constructor_refused=True if passed else False,
                    synthetic_java8_bridge_source_call_refused=True if passed else False)
                need(passed, "actual javac did not reject both source constructor attempts: " + error)
            actual = run(variant + "-cases", [jdk / "java", "-cp", cp,
                         "org.trillionnium.hepta.background.ProfileRecentsParseReuseHostTest", fixture, variant])
            need(actual.get("passed") is True and actual.get("cases") == EXPECTED
                 and actual.get("case_count") == len(EXPECTED)
                 and actual.get("instrumented") == (variant == "counted")
                 and actual.get("phone_operations") == 0
                 and actual.get("phone_latency_improvement_claimed") is False
                 and actual.get("original_cleanup_read_budget_ms") == 1400,
                 "same-read test identity or original boundary changed")
            rows = actual.get("actual_counted_full_parse_calls")
            if variant == "counted":
                need(len(rows) == 2 and [x["case"] for x in rows] == ["one_raw", "full_lifecycle"], "both actual count cases required")
                for row in rows:
                    need(row["legacy_full_parses"] == 2 * row["fresh_dumps_each"]
                         and row["candidate_full_parses"] == row["fresh_dumps_each"] > 0, "full actual parse count changed")
            else:
                need(rows == [], "uninstrumented source must not claim actual counts")
                private_result = run("original-private", [jdk / "java", "-cp", cp,
                                     "org.trillionnium.hepta.background.ProfileBrokerHostTest"])
                need(private_result.get("passed") is True, "original private-profile policy failed")
                result["original_private"] = private_result
                sampling_result = run("original-sampling", [jdk / "java", "-cp", cp,
                                      "org.trillionnium.hepta.background.ProfileCleanupSamplingHostTest", fixture.parent, "candidate"])
                need(sampling_result.get("passed") is True and sampling_result.get("assertions") == 55
                     and sampling_result.get("original_cleanup_read_budget_ms") == 1400
                     and len(sampling_result.get("cases", [])) == 9
                     and sampling_result.get("retirement_history_reads") == 3
                     and sampling_result.get("phone_qualification") is False, "original cleanup cadence/1400ms gate changed")
                result["original_sampling"] = sampling_result
            result["variants"][variant] = actual
        result["all_pass"] = True
    finally:
        after = inventory(source)
        (out / "SOURCE-AFTER.json").write_text(json.dumps(after, indent=2) + "\n")
        result["input_after"] = [meta(p) for p in tracked]
        result["tools_after"] = [meta(a.java_home / "bin/java"), meta(a.java_home / "bin/javac"), meta(a.json_jar)]
        result["source_inputs_unchanged"] = before == after and result["input_before"] == result["input_after"]
        result["tools_unchanged"] = result["tools_before"] == result["tools_after"]
        result["all_pass"] = result["all_pass"] and result["source_inputs_unchanged"] and result["tools_unchanged"]
        result["source_before"] = meta(out / "SOURCE-BEFORE.json")
        result["source_after"] = meta(out / "SOURCE-AFTER.json")
        (out / "RESULT.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps(dict(all_pass=result["all_pass"], report=meta(out / "RESULT.json"),
                             variants={k: dict(cases=v["case_count"], assertions=v["assertions"]) for k, v in result["variants"].items()},
                             phone_operations=0)))
    return 0 if result["all_pass"] else 1
if __name__ == "__main__":
    raise SystemExit(main())
