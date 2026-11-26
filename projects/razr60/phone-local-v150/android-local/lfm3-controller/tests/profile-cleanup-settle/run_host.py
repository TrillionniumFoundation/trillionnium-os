#!/usr/bin/env python3
"""Measured-277 timing projection, actual production cleanup methods and old regressions.
No Android/phone/model effects. The framework, Binder endpoints and clock are synthetic.
"""
import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
import time
from pathlib import Path

JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
RECENTS_SHA = "b3a758e849b621bac4b21c508fa330dce03df38329b82ea260f01b635d44b0c9"
BASELINE = {
    "ProfileOwnedTask.java": "c1c7cc2b3d8a3d43ec9b2ce8ddb6f23ceab7697ab4eafcf6e948f6630bbaef08",
    "BackgroundDisplayBroker.java": "abccc17b66df24056a75bb44d8b0f9c6c790727cf0ac2abd4067a0d27d60ea7c",
    "ProfileTaskPlatform.java": "ecdd2e0ee3153456042bc8c76dda9d122d8617ee432aaf551e1b0cdfb9f4ac84",
    "BackgroundTaskOrganizer.java": "70eeb8e550dc77638687d5fa224fc2cd014f20991a1df94a232685244d9904ec",
    "ProfileDisplayCustody.java": "245cb70d0ab59918e6bbc1fa032120bfbea18065a31d6172483d4768ae409b75",
}
ACTUAL = {
    "result.json": "a2765fc3dc74364461b7f426c1b80bb5d8f75e56e48d2f412d672428998c5e2b",
    "background-cleanup.json": "1b0ddc44649cae70a8a968d65ab84987ec7705770d7db1b276f01e36253c4d7c",
    "background-broker-0333ed0e-44d2-46ed-9e0c-3478745acf91.bin": "888839db16e9ea07b77c2ef2a853748b9d6c07c5e43ae3c92631d0c21ddca8db",
}
BG = "src/org/trillionnium/hepta/background"
NAMES = ["ProfileIdentity", "ProfileTarget", "WindowOwnership", "BrokerProtocol",
         "PublicPermissionControllerUi", "PublicOwnGroupPolicy", "FixedIntentTools",
         "BackgroundOwnedTaskPolicy", "BackgroundOwnedSingleTask", "ProfileTaskPolicy",
         "ProfileOwnedTask", "ProfilePermissionTransient", "ProfileDisplayCustody",
         "PublicOwnGroupPhysicalFence", "PublicProfileRecentHistory"]
PKG = "org.trillionnium.hepta.background."

def require(ok, message):
    if not ok:
        raise AssertionError(message)

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def ref(path):
    p = Path(path).resolve(strict=True)
    st = p.stat()
    require(stat.S_ISREG(st.st_mode), "regular input required: " + str(p))
    return {"path": str(p), "bytes": st.st_size, "sha256": sha(p), "mode": stat.S_IMODE(st.st_mode)}

def balanced_end(text, opening):
    require(text[opening] == "{", "opening brace required")
    depth = 0
    mode = "code"
    escaped = False
    i = opening
    while i < len(text):
        c, n = text[i], text[i + 1:i + 2]
        if mode in ("string", "char"):
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == ('"' if mode == "string" else "'"):
                mode = "code"
        elif mode == "line":
            if c == "\n":
                mode = "code"
        elif mode == "comment":
            if c == "*" and n == "/":
                mode = "code"
                i += 1
        elif c == "/" and n == "/":
            mode = "line"
            i += 1
        elif c == "/" and n == "*":
            mode = "comment"
            i += 1
        elif c == '"':
            mode = "string"
        elif c == "'":
            mode = "char"
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise AssertionError("incomplete Java block")

def extract(text, anchor):
    require(text.count(anchor) == 1, "unique complete production anchor required: " + anchor)
    start = text.index(anchor)
    opening = text.index("{", start)
    end = balanced_end(text, opening)
    return text[start:end], start, end

def generate(src, out, report):
    template = src / "tests/profile-cleanup-settle/ProfileCleanupBrokerHost.template"
    content = template.read_text()
    sources = {
        "broker": src / BG / "BackgroundDisplayBroker.java",
        "platform": src / BG / "ProfileTaskPlatform.java",
        "organizer": src / BG / "BackgroundTaskOrganizer.java",
    }
    ports = [
        ("ORGANIZER_REMOVE", "organizer", "    void removeOwnedLeaf(Object token,Check finalCheck) throws Exception {"),
        ("ORGANIZER_DELETE", "organizer", "    boolean deleteOwnedContainer(Object token,Check finalCheck) throws Exception {"),
        ("PLATFORM_REMOVE", "platform", "    @Override public void removeLeaf(Object token,ProfileOwnedTask.CleanupEffectCheck check)throws Exception{"),
        ("PLATFORM_DELETE", "platform", "    @Override public boolean deleteRoot(Object token,ProfileOwnedTask.CleanupEffectCheck check)throws Exception{"),
        ("CLOSE_BRANCH", "broker", '            if ("close".equals(r.operation)) {'),
        ("READ_DEADLINE", "broker", "    private long cleanupReadDeadline(){"),
        ("WATCHDOG_DEADLINE", "broker", "    private long cleanupWatchdogDeadline(){"),
        ("PROFILE_DEADLINE", "broker", "    private long profileDeadline(){"),
        ("CLOSE_REPLY_PENDING", "broker", "    private boolean profileCloseReplyPending(long now){"),
        ("CLOSE_REPLY_FLUSH", "broker", "    private boolean releasedProfileReplyMayFlush(long now){"),
        ("BEGIN_PROFILE_CLEANUP", "broker", "    private void beginProfileCleanup(){"),
        ("REFRESH_EVIDENCE", "broker", "    private void refreshProfileTaskEvidence("),
        ("EMPTY_EVIDENCE", "broker", "    private java.util.Map<String,Object> emptyProfileCleanup(boolean known){"),
        ("QUARANTINE", "broker", "    private void quarantineProfile(String reason){"),
        ("FAILURE_AUDIT", "broker", "    static final class ProfileCleanupFailureAudit {"),
    ]
    report["production_method_extraction"] = []
    for key, source, anchor in ports:
        t = sources[source].read_text()
        block, start, end = extract(t, anchor)
        marker = "@@" + key + "@@"
        require(content.count(marker) == 1, "unique template marker: " + key)
        content = content.replace(marker, block)
        report["production_method_extraction"].append({
            "slot": key, "source": ref(sources[source]),
            "anchor": anchor, "start_line": t[:start].count("\n") + 1,
            "bytes": len(block.encode()), "sha256": hashlib.sha256(block.encode()).hexdigest(),
            "production_method_bytes_unchanged": True,
        })
    require("@@" not in content, "unresolved production extraction marker")
    directory = out / "generated"
    directory.mkdir()
    expanded = directory / "complete-expanded-template.txt"
    expanded.write_text(content)
    header = content[:content.index("final class BackgroundTaskOrganizer {")]
    generated = []
    for name in ("BackgroundTaskOrganizer", "ProfileTaskPlatform", "SystemClock", "ProfileCleanupBrokerHost"):
        block, _, _ = extract(content, "final class " + name + (" extends ProfileCleanupSettleFixtures.Platform" if name == "ProfileTaskPlatform" else "") + " {")
        path = directory / (name + ".java")
        path.write_text(header + block + "\n")
        generated.append(path)
    report["generated_fixture"] = ref(expanded)
    report["generated_compilation_units"] = [ref(p) for p in generated]
    report["split_top_level_types_without_body_rewrite"] = True
    report["full_android_broker_compiled"] = False
    report["android_services_clock_binder_and_wait_io_synthetic"] = True
    return generated

def actual_evidence(a, report):
    for name, digest in ACTUAL.items():
        require(sha(a.actual_task / name) == digest, "actual 277 original differs: " + name)
    original = json.loads((a.actual_task / "result.json").read_bytes())
    require(original["task_id"] == "277631ac4db44fb5a7ca0e130e22fdb3", "actual task identity")
    require(original.get("model_reported_success") is True and original.get("steps") == 5, "actual model completion shape")
    lines = [json.loads(x) for x in (a.actual_task / next(n for n in ACTUAL if n.endswith(".bin"))).read_bytes().splitlines()]
    require(len(lines) == 2 and lines[0] == lines[1], "actual duplicate broker terminal differs")
    broker = lines[0]
    require(broker["state"] == "CLEANUP_UNKNOWN" and broker["reason"] == "client_close", "actual cleanup unknown shape")
    cleanup = broker["profile_cleanup"]
    hist = cleanup["public_foreign_recent_history"]
    diag = broker["profile_cleanup_diagnostics"]
    first = diag["first_failure"]
    require(first["phase"] == "TASK_RETIRE" and first["code"] == "PROFILE_LEAF_RETIRE_NOT_CONFIRMED", "actual first refusal")
    # Exact elapsed fields are also preserved in the full original refs. The test
    # does not invent unarchived WCT return or per-iteration global census facts.
    serialized = json.dumps(broker, sort_keys=True)
    for expected in (1039659911, 1039661311, 1039661319, 1039661294):
        require(str(expected) in serialized, "actual known clock value absent")
    require(hist["owned_target_absent"] is True and cleanup["identity_unknown"] is True, "actual absence/unknown distinction")
    report["actual_saved_shape"] = {
        "originals": [ref(a.actual_task / n) for n in ACTUAL],
        "task_id": original["task_id"], "model_reported_success": True, "steps": 5,
        "original_overall_business_accepted": False, "state": "CLEANUP_UNKNOWN",
        "cleanup_started_elapsed_ms": 1039659911, "task_reads_deadline_elapsed_ms": 1039661311,
        "first_failure_elapsed_ms": 1039661319, "latest_history_elapsed_ms": 1039661294,
        "first_failure_phase": "TASK_RETIRE", "first_failure_code": first["code"],
        "owned_target_absent_in_last_public_history": True,
        "actual_per_iteration_global_census_available": False,
        "unique_race_cause_proven": False,
        "test_mixed_global_recents_transition_is_synthetic_projection": True,
    }

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "baseline-source", "java-home", "json-jar", "actual-task", "output"):
        ap.add_argument("--" + name, type=Path, required=True)
    a = ap.parse_args()
    src, base, out = a.source.resolve(), a.baseline_source.resolve(), a.output.resolve()
    require(not out.exists() and src not in out.parents and base not in out.parents, "fresh output outside sources required")
    require(sha(a.json_jar) == JSON_SHA, "JSON dependency pin")
    require({n: sha(base / BG / n) for n in BASELINE} == BASELINE, "actual f4 baseline production differs")
    fixture = src / "tests/profile-cleanup-sampling/fixtures-synthetic/before-recents.txt"
    require(sha(fixture) == RECENTS_SHA, "explicit synthetic complete history fixture differs")
    oldtests = ["tests/profile-broker/ProfileBrokerHostTest.java",
                "tests/profile-cleanup-sampling/ProfileCleanupSamplingHostTest.java"]
    for name in oldtests:
        require((src / name).read_bytes() == (base / name).read_bytes(), "old regression changed: " + name)
    out.mkdir(parents=True)
    report = {
        "schema": "hepta.profile-cleanup-settle-host.v1", "all_pass": False,
        "phone_operations": 0, "android_runtime": False, "model_run": False, "device_qualified": False,
        "stages": [], "inputs_before": [],
        "original_close_request_max_ms": 3500, "normal_convergence_budget_ms": 3000,
        "original_first_leaf_effect_deadline_ms": 1400, "per_effect_fresh_census_max_ms": 1500,
        "old_failed_business_history_rewritten": False,
    }
    files = set([Path(__file__).resolve(), a.json_jar.resolve(), fixture,
                 a.java_home.resolve() / "bin/java", a.java_home.resolve() / "bin/javac",
                 a.java_home.resolve() / "lib/modules"])
    pure = {}
    tests = src / "tests/profile-cleanup-settle"
    common = tests / "ProfileCleanupSettleFixtures.java"
    redtest = tests / "ProfileCleanupSettleOldTimingHostTest.java"
    newtest = tests / "ProfileCleanupSettleHostTest.java"
    files.update([common, redtest, newtest, tests / "ProfileCleanupBrokerHost.template"])
    for mode, root in (("baseline", base), ("candidate", src)):
        pure[mode] = [root / BG / (n + ".java") for n in NAMES]
        files.update(pure[mode])
        files.update(root / BG / n for n in BASELINE)
        files.update(root / n for n in oldtests)
    files.update(a.actual_task / n for n in ACTUAL)
    report["inputs_before"] = [ref(p) for p in sorted(files)]
    report["unchanged_old_test_inputs"] = [ref(src / n) for n in oldtests]

    def run(label, argv, expected=0, result_key=None):
        started = time.monotonic()
        p = subprocess.run([str(x) for x in argv], cwd=out, capture_output=True, timeout=120)
        stdout, stderr = out / (label + ".stdout"), out / (label + ".stderr")
        stdout.write_bytes(p.stdout)
        stderr.write_bytes(p.stderr)
        report["stages"].append({"name": label, "argv": [str(x) for x in argv],
            "exit_code": p.returncode, "expected_exit_code": expected,
            "seconds": time.monotonic() - started, "stdout": ref(stdout), "stderr": ref(stderr)})
        require(p.returncode == expected, label + " failed: " + p.stderr.decode("utf-8", "replace")[-6000:])
        if result_key:
            report[result_key] = json.loads(p.stdout.decode().splitlines()[0])
        print(json.dumps({"stage": label, "exit_code": p.returncode, "expected": expected}), flush=True)

    def compile_stage(label, inputs):
        classes = out / (label + "-classes")
        classes.mkdir()
        run(label + "-compile", [a.java_home / "bin/javac", "--release", "8", "-proc:none",
            "-Xlint:all,-options", "-Werror", "-encoding", "UTF-8", "-cp", a.json_jar,
            "-d", classes, *inputs])
        return str(classes) + ":" + str(a.json_jar.resolve())

    try:
        actual_evidence(a, report)
        cp = compile_stage("baseline", pure["baseline"] + [base / oldtests[0], common, redtest])
        run("baseline-red", [a.java_home / "bin/java", "-cp", cp,
            PKG + "ProfileCleanupSettleOldTimingHostTest", fixture], 3, "baseline_red")
        require(report["baseline_red"]["expected_red"] is True, "old production did not reproduce the measured-boundary projection")
        generated = generate(src, out, report)
        cp = compile_stage("candidate", pure["candidate"] + [src / n for n in oldtests] +
                           [common, redtest, newtest, *generated])
        run("candidate-green", [a.java_home / "bin/java", "-cp", cp,
            PKG + "ProfileCleanupSettleHostTest", fixture], 0, "candidate_green")
        require(report["candidate_green"]["all_pass"] is True, "candidate cases failed")
        run("candidate-no-phase", [a.java_home / "bin/java", "-cp", cp,
            PKG + "ProfileCleanupSettleOldTimingHostTest", fixture], 3, "candidate_legacy_red")
        run("private-regression", [a.java_home / "bin/java", "-cp", cp,
            PKG + "ProfileBrokerHostTest"], 0, "private_regression")
        run("public-sampling-regression", [a.java_home / "bin/java", "-cp", cp,
            PKG + "ProfileCleanupSamplingHostTest", fixture.parent, "candidate"], 0, "public_sampling_regression")
        require(report["private_regression"]["passed"] is True, "private guard regression")
        previous = report["public_sampling_regression"]
        require(previous["passed"] is True and len(previous["cases"]) == 9 and previous["assertions"] == 55,
                "original 9/55 public sampling regression differs")
        require(previous["original_cleanup_read_budget_ms"] == 1400 and previous["retirement_history_reads"] == 3,
                "old no-phase sampling budget/history changed")
        report["all_pass"] = True
    except Exception as e:
        report["error"] = str(e)
        raise
    finally:
        report["inputs_after"] = [ref(p) for p in sorted(files)]
        report["source_inputs_unchanged"] = report["inputs_before"] == report["inputs_after"]
        report["all_pass"] = report["all_pass"] and report["source_inputs_unchanged"]
        result = out / "RESULT.json"
        result.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps({"all_pass": report["all_pass"], "result": ref(result),
                          "phone_operations": 0, "device_qualified": False}), flush=True)
    return 0 if report["all_pass"] else 1

if __name__ == "__main__":
    sys.exit(main())
