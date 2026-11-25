#!/usr/bin/env python3
"""Pure ownership/history regression and complete nested cleanup audit; no phone access."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
RECENTS_SHA = "bb1335844af98cf8a2a435ab8b10a6bf9930ccd96bc162bff38150c9a7d1ee6a"
RAW = "background-broker-ce4531f7-4a3e-456a-bff3-fbed6421625a.bin"
ACTUAL = {
    "result.json": "0184be6c6de1643edfc74097d1d68cedc821d61267dffb50a79af73a401251b9",
    RAW: "78b5a35c726b0cd22ee31cb5ea1a67b4e242c3c15a35362f82d2c210aaf7b67c",
}
NAMES = ["ProfileIdentity", "ProfileTarget", "WindowOwnership", "BrokerProtocol",
         "PublicPermissionControllerUi", "PublicOwnGroupPolicy", "FixedIntentTools",
         "BackgroundOwnedTaskPolicy", "BackgroundOwnedSingleTask", "ProfileTaskPolicy",
         "ProfileOwnedTask", "ProfilePermissionTransient", "ProfileDisplayCustody",
         "PublicOwnGroupPhysicalFence", "PublicProfileRecentHistory"]

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def require(ok, message):
    if not ok:
        raise AssertionError(message)

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "baseline-source", "java-home", "json-jar", "actual-recents", "actual-task", "output"):
        ap.add_argument("--" + name, type=Path, required=True)
    a = ap.parse_args()
    src, base, out = a.source.resolve(), a.baseline_source.resolve(), a.output.resolve()
    require(not out.exists() and src not in out.parents and base not in out.parents, "new output outside source required")
    require(sha(a.json_jar) == JSON_SHA, "fixed JSON dependency differs")
    require(sha(a.actual_recents / "before-recents.txt") == RECENTS_SHA, "actual archived history differs")
    require({n: sha(a.actual_task / n) for n in ACTUAL} == ACTUAL, "e7ef originals differ")
    out.mkdir(parents=True)
    report = {"schema": "hepta.profile-cleanup-sampling-host.v1", "all_pass": False,
              "phone_actions": 0, "android_runtime": False, "model_run": False,
              "framework_and_latency_fixtures_synthetic": True,
              "e7ef_unique_cause_proven": False, "e7ef_phone_fix_qualified": False,
              "original_cleanup_budget_changed": False, "stages": [], "inputs": {}}
    original = json.loads((a.actual_task / "result.json").read_bytes())
    lines = [json.loads(x) for x in (a.actual_task / RAW).read_bytes().splitlines()]
    require(len(lines) == 2 and all(x["state"] == "CLEANUP_UNKNOWN" and x["reason"] == "client_close" for x in lines),
            "actual first-failure diagnostic-loss shape differs")
    require(all("profile_cleanup_diagnostics" not in x for x in lines), "historical diagnostic was not actually absent")
    cleanup = original["background_cleanup"]["last_broker_response"]
    history = cleanup["profile_cleanup"]["public_foreign_recent_history"]
    report["actual_saved_shape"] = {
        "original_sha256": ACTUAL, "task_id": original.get("task_id"),
        "history_owned_target_absent": history["owned_target_absent"],
        "last_history_elapsed_ms": history["current_elapsed_ms"],
        "last_leaf_valid": cleanup["profile_last_leaf_validation"]["valid"],
        "original_state": cleanup["state"], "original_identity_unknown": cleanup["profile_cleanup"]["identity_unknown"],
        "first_refusal_unavailable": True,
    }

    def run(label, argv, expected=0):
        began = time.monotonic()
        p = subprocess.run(list(map(str, argv)), cwd=out, capture_output=True, timeout=60)
        (out / (label + ".stdout")).write_bytes(p.stdout)
        (out / (label + ".stderr")).write_bytes(p.stderr)
        report["stages"].append({"name": label, "argv": list(map(str, argv)), "exit_code": p.returncode,
                                 "expected_exit_code": expected, "seconds": time.monotonic() - began,
                                 "stdout_sha256": hashlib.sha256(p.stdout).hexdigest(),
                                 "stderr_sha256": hashlib.sha256(p.stderr).hexdigest()})
        require(p.returncode == expected, label + " failed: " + p.stderr.decode("utf-8", "replace")[-3000:])
        if label.endswith("-cases") or label in ("private-regression", "diagnostics"):
            report[label] = json.loads(p.stdout.decode("utf-8").splitlines()[0])

    try:
        for mode, root in (("baseline", base), ("candidate", src)):
            bg = root / "src/org/trillionnium/hepta/background"
            files = [bg / (name + ".java") for name in NAMES]
            files += [root / "tests/profile-broker/ProfileBrokerHostTest.java",
                      src / "tests/profile-cleanup-sampling/ProfileCleanupSamplingHostTest.java"]
            report["inputs"].update({str(p): sha(p) for p in files})
            classes = out / (mode + "-classes")
            classes.mkdir()
            run(mode + "-compile", [a.java_home / "bin/javac", "--release", "8", "-proc:none",
                "-Xlint:all,-options", "-Werror", "-encoding", "UTF-8", "-cp", a.json_jar, "-d", classes, *files])
            cp = str(classes) + ":" + str(a.json_jar.resolve())
            run(mode + "-cases", [a.java_home / "bin/java", "-cp", cp,
                "org.trillionnium.hepta.background.ProfileCleanupSamplingHostTest", a.actual_recents, mode],
                3 if mode == "baseline" else 0)
            if mode == "candidate":
                run("private-regression", [a.java_home / "bin/java", "-cp", cp,
                    "org.trillionnium.hepta.background.ProfileBrokerHostTest"])

        broker = src / "src/org/trillionnium/hepta/background/BackgroundDisplayBroker.java"
        text = broker.read_text()
        start = text.index("    static final class ProfileCleanupFailureAudit {")
        end = text.index("    /** First unexpected policy failure only.", start)
        block = text[start:end].rstrip()
        require(block.endswith("}"), "complete production audit extraction required")
        fixture = out / "audit-fixture"
        fixture.mkdir()
        wrapper = fixture / "BackgroundDisplayBroker.java"
        wrapper.write_text("package org.trillionnium.hepta.background;\npublic final class BackgroundDisplayBroker {\n"
                           + block + "\n}\n")
        diagnostic = src / "tests/profile-cleanup-sampling/ProfileCleanupDiagnosticsHostTest.java"
        report["audit_extraction"] = {"source": str(broker), "source_sha256": sha(broker),
            "complete_nested_block_sha256": hashlib.sha256(block.encode()).hexdigest(),
            "full_android_broker_compiled": False, "wrapper_sha256": sha(wrapper)}
        report["inputs"].update({str(broker): sha(broker), str(diagnostic): sha(diagnostic), str(Path(__file__).resolve()): sha(Path(__file__).resolve())})
        classes = out / "audit-classes"
        classes.mkdir()
        run("diagnostics-compile", [a.java_home / "bin/javac", "--release", "8", "-proc:none",
            "-Xlint:all,-options", "-Werror", "-encoding", "UTF-8", "-cp", a.json_jar, "-d", classes, wrapper, diagnostic])
        run("diagnostics", [a.java_home / "bin/java", "-cp", str(classes) + ":" + str(a.json_jar.resolve()),
            "org.trillionnium.hepta.background.ProfileCleanupDiagnosticsHostTest"])
        report["all_pass"] = True
    finally:
        report["source_inputs_unchanged"] = report["inputs"] == {p: sha(Path(p)) for p in report["inputs"]}
        report["originals_unchanged"] = ACTUAL == {n: sha(a.actual_task / n) for n in ACTUAL}
        report["all_pass"] = report["all_pass"] and report["source_inputs_unchanged"] and report["originals_unchanged"]
        (out / "RESULT.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps({"all_pass": report["all_pass"], "result": str(out / "RESULT.json"),
                          "sha256": sha(out / "RESULT.json"), "phone_actions": 0}))
    return 0 if report["all_pass"] else 1

if __name__ == "__main__":
    sys.exit(main())
