#!/usr/bin/env python3
"""Pure host diagnostics and unchanged retirement regression; never contact a phone."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time

BASE_OWNED = "4869a3f7c1e3a2b349ca413c5480f18ccbb1042bae61d790233f0003b45281e9"
JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
FIXTURE_SHA = "b3a758e849b621bac4b21c508fa330dce03df38329b82ea260f01b635d44b0c9"
EXPECTED = [
    "normal_original_calls_and_deadline_clock",
    "before_first_root_no_mutation",
    "pre_leaf_history_failure_is_distinct",
    "post_leaf_history_failure_is_distinct",
    "remove_throw_preserves_exception_and_no_root_delete",
    "delete_false_is_not_release",
    "delete_throw_is_not_false_return",
    "recents_linger_preserves_original_1400ms_stop",
    "accepted_root_delete_does_not_prove_absence",
    "bounded_prefix_keeps_late_root_mutation",
    "changed_owner_still_stops_before_mutation",
    "watchdog_can_read_inflight_without_retire_monitor",
]
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()
def need(v, why):
    if not v:
        raise AssertionError(why)
def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for k in ("source", "java-home", "json-jar", "output"):
        ap.add_argument("--" + k, type=Path, required=True)
    ap.add_argument("--baseline-source", type=Path)
    a = ap.parse_args()
    src, out = a.source.resolve(), a.output.resolve()
    need(not out.exists() and src not in out.parents and out != src, "new external output required")
    need(sha(a.json_jar) == JSON_SHA, "fixed JSON differs")
    shared = src / "tests/profile-cleanup-sampling/run_host.py"
    spec = importlib.util.spec_from_file_location("retirement_sampling_inputs", shared)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    bgrel = Path("src/org/trillionnium/hepta/background")
    production = [bgrel / (n + ".java") for n in mod.NAMES]
    test = src / "tests/profile-retirement-diagnostics/ProfileRetirementDiagnosticsHostTest.java"
    old = [Path("tests/profile-broker/ProfileBrokerHostTest.java"),
           Path("tests/profile-cleanup-sampling/ProfileCleanupSamplingHostTest.java")]
    fixture = src / "tests/profile-cleanup-sampling/fixtures-synthetic/before-recents.txt"
    need(sha(fixture) == FIXTURE_SHA, "synthetic history fixture changed")
    tracked = [src / p for p in production + old] + [src / bgrel / "BackgroundDisplayBroker.java",
               test, fixture, shared, Path(__file__).resolve(), a.json_jar.resolve()]
    pins = {str(p): sha(p) for p in tracked}
    out.mkdir(parents=True)
    result = dict(schema="hepta.profile-retirement-diagnostics-host.v1", all_pass=False,
                  android_runtime=False, phone_operations=0, synthetic_framework_and_timing=True,
                  original_deadline_ms=1400, duration_clock_independent=True,
                  source_inputs=pins, source_inputs_unchanged=False, stages=[],
                  private_phone_fixture_used=False, actual6127_cleanup_fixed_claim=False)
    flags = ["--release", "8", "-proc:none", "-Xlint:all,-options", "-Werror", "-encoding", "UTF-8"]
    jdk = a.java_home.resolve() / "bin"
    java_cp = str(a.json_jar.resolve())
    def run(label, argv, parse=False):
        t = time.monotonic()
        p = subprocess.run([str(x) for x in argv], cwd=out, capture_output=True, timeout=60)
        (out / (label + ".stdout")).write_bytes(p.stdout)
        (out / (label + ".stderr")).write_bytes(p.stderr)
        record = dict(name=label, exit_code=p.returncode, seconds=time.monotonic()-t,
                      argv=[str(x) for x in argv], stdout_sha256=hashlib.sha256(p.stdout).hexdigest(),
                      stderr_sha256=hashlib.sha256(p.stderr).hexdigest())
        result["stages"].append(record)
        need(p.returncode == 0, label + " failed: " + p.stderr.decode("utf-8", "replace")[-3000:])
        if parse:
            value = json.loads(p.stdout.decode("utf-8").splitlines()[0])
            need(value.get("passed") is True, label + " no passed result")
            (out / (label + "-CASES.json")).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
            return value
    try:
        classes = out / "candidate-classes"
        classes.mkdir()
        run("candidate-compile", [jdk/"javac", *flags, "-cp", java_cp, "-d", classes,
             *[src / p for p in production + old], test])
        cp = str(classes) + ":" + java_cp
        candidate = run("diagnostics", [jdk/"java", "-cp", cp,
            "org.trillionnium.hepta.background.ProfileRetirementDiagnosticsHostTest", "candidate"], True)
        need(candidate["cases"] == EXPECTED and len(candidate["functional"]) == 11,
             "complete diagnostic cases required")
        result["diagnostics"] = dict(cases=candidate["cases"], assertions=candidate["assertions"],
            report=str(out/"diagnostics-CASES.json"), sha256=sha(out/"diagnostics-CASES.json"),
            fixed_wire_bound_bytes=8192, record_limit=24)
        legacy = run("legacy-profile", [jdk/"java", "-cp", cp,
            "org.trillionnium.hepta.background.ProfileBrokerHostTest"], True)
        need(legacy.get("cases") == 47 and legacy.get("assertions") == 449,
             "original 47/449 private policy contract changed")
        result["legacy_profile"] = dict(summary=legacy, report=str(out/"legacy-profile-CASES.json"),
                                       sha256=sha(out/"legacy-profile-CASES.json"))
        sampling = run("legacy-sampling", [jdk/"java", "-cp", cp,
            "org.trillionnium.hepta.background.ProfileCleanupSamplingHostTest", fixture.parent, "candidate"], True)
        need(len(sampling["cases"]) == 9 and sampling["assertions"] == 55
             and sampling["original_cleanup_read_budget_ms"] == 1400
             and sampling["retirement_history_reads"] == 3, "original 9/55 public history contract changed")
        result["legacy_sampling"] = dict(summary=sampling, report=str(out/"legacy-sampling-CASES.json"),
                                        sha256=sha(out/"legacy-sampling-CASES.json"))
        if a.baseline_source:
            base = a.baseline_source.resolve()
            need(sha(base/bgrel/"ProfileOwnedTask.java") == BASE_OWNED, "exact signed93 predecessor required")
            for rel in production + old:
                if rel.name != "ProfileOwnedTask.java":
                    need((base/rel).read_bytes() == (src/rel).read_bytes(), "unrelated baseline input differs: " + str(rel))
            original_files = [base/p for p in production + old]
            original_pins = {str(p): sha(p) for p in original_files}
            baseline_classes = out/"baseline-classes"
            baseline_classes.mkdir()
            run("baseline-compile", [jdk/"javac", *flags, "-cp", java_cp, "-d", baseline_classes,
                                    *original_files, test])
            baseline = run("baseline", [jdk/"java", "-cp", str(baseline_classes)+":"+java_cp,
                "org.trillionnium.hepta.background.ProfileRetirementDiagnosticsHostTest", "baseline"], True)
            need(baseline["cases"] == EXPECTED[:-1], "incomplete baseline call comparison")
            need(baseline["functional"] == candidate["functional"],
                 "original call sequence, clock reads, mutations, deadline or result changed")
            need(original_pins == {p: sha(Path(p)) for p in original_pins}, "baseline inputs changed")
            result["baseline_equivalence"] = dict(identical=True, cases=11,
                compared=["ordered_platform_calls","Platform.now_read_count","elapsed_fake_clock",
                          "mutations","first_refusal","cleanup_and_absence_flags"],
                original_inputs=original_pins, original_inputs_unchanged=True,
                report=str(out/"baseline-CASES.json"), sha256=sha(out/"baseline-CASES.json"))
        else:
            result["baseline_equivalence"] = None
        result["all_pass"] = True
    except BaseException as failure:
        result["failure"] = str(failure)
        raise
    finally:
        result["source_inputs_unchanged"] = pins == {p: sha(Path(p)) for p in pins}
        result["all_pass"] = result["all_pass"] and result["source_inputs_unchanged"]
        (out/"RESULT.json").write_text(json.dumps(result, ensure_ascii=False, indent=2)+"\n")
        print(json.dumps(dict(all_pass=result["all_pass"], report=str(out/"RESULT.json"),
              phone_operations=0, failure=result.get("failure")), ensure_ascii=False))
    return 0 if result["all_pass"] else 1
if __name__ == "__main__":
    sys.exit(main())
