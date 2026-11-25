#!/usr/bin/env python3
"""CI host regression using explicit synthetic history; never contact a phone."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time

FIXTURE_SHA = "b3a758e849b621bac4b21c508fa330dce03df38329b82ea260f01b635d44b0c9"
EXPECTED_CASES = [
    "same_original_budget_with_full_pre_leaf_pre_root_and_post_root_history",
    "protected_history_change_during_child_read_vetoes_root_delete",
    "final_history_expiry_never_authorizes_root_delete",
    "fresh_identity_before_root_mutation_is_not_cached",
    "root_actual_token_change_still_refuses",
    "returned_owned_child_blocks_root_delete",
    "owned_recents_remains_until_original_deadline",
    "fresh_global_after_root_mutation_is_required",
    "root_absence_is_not_assumed_from_recents_absence",
]

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def need(value, reason):
    if not value:
        raise AssertionError(reason)

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for key in ("source", "java-home", "json-jar", "output"):
        ap.add_argument("--" + key, type=Path, required=True)
    a = ap.parse_args()
    src, out = a.source.resolve(), a.output.resolve()
    need(not out.exists() and src not in out.parents and out != src, "new output outside source required")
    shared = src / "tests/profile-cleanup-sampling/run_host.py"
    spec = importlib.util.spec_from_file_location("cleanup_archived_runner", shared)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    need(sha(a.json_jar) == mod.JSON_SHA, "fixed JSON dependency differs")
    fixture = src / "tests/profile-cleanup-sampling/fixtures-synthetic/before-recents.txt"
    need(sha(fixture) == FIXTURE_SHA, "explicit synthetic fixture changed")
    bg = src / "src/org/trillionnium/hepta/background"
    files = [bg / (name + ".java") for name in mod.NAMES]
    files += [src / "tests/profile-broker/ProfileBrokerHostTest.java",
              src / "tests/profile-cleanup-sampling/ProfileCleanupSamplingHostTest.java"]
    broker = bg / "BackgroundDisplayBroker.java"
    diagnostic = src / "tests/profile-cleanup-sampling/ProfileCleanupDiagnosticsHostTest.java"
    tracked = files + [broker, diagnostic, shared, fixture, Path(__file__).resolve()]
    pins = {str(p): sha(p) for p in tracked}
    out.mkdir(parents=True)
    result = dict(schema="hepta.profile-cleanup-candidate-host.v1", all_pass=False,
                  phone_operations=0, android_runtime=False, model_run=False,
                  fixture_kind="synthetic_complete_public_recents",
                  framework_and_latency_fixtures_synthetic=True, original_cleanup_budget_changed=False,
                  original_task_fixture_used=False, e7ef_phone_fix_qualified=False,
                  source_inputs=pins, fixture_sha256=FIXTURE_SHA, stages=[])

    def run(label, argv):
        started = time.monotonic()
        proc = subprocess.run([str(x) for x in argv], cwd=out, capture_output=True, timeout=60)
        (out / (label + ".stdout")).write_bytes(proc.stdout)
        (out / (label + ".stderr")).write_bytes(proc.stderr)
        result["stages"].append(dict(name=label, exit_code=proc.returncode,
            seconds=time.monotonic() - started, argv=[str(x) for x in argv],
            stdout_sha256=hashlib.sha256(proc.stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(proc.stderr).hexdigest()))
        need(proc.returncode == 0, label + " failed: " + proc.stderr.decode("utf-8", "replace")[-3000:])
        if label in ("sampling", "diagnostics"):
            result[label] = json.loads(proc.stdout.decode("utf-8").splitlines()[0])
    try:
        classes = out / "classes"
        classes.mkdir()
        jdk = a.java_home.resolve() / "bin"
        flags = ["--release", "8", "-proc:none", "-Xlint:all,-options", "-Werror", "-encoding", "UTF-8"]
        run("compile", [jdk / "javac", *flags, "-cp", a.json_jar, "-d", classes, *files])
        run("sampling", [jdk / "java", "-cp", str(classes) + ":" + str(a.json_jar.resolve()),
            "org.trillionnium.hepta.background.ProfileCleanupSamplingHostTest", fixture.parent, "candidate"])
        cases = result["sampling"]
        need(cases.get("passed") is True and cases.get("cases") == EXPECTED_CASES
             and cases.get("assertions") == 55 and cases.get("original_cleanup_read_budget_ms") == 1400
             and cases.get("phone_qualification") is False, "complete candidate case contract changed")

        text = broker.read_text()
        start = text.index("    static final class ProfileCleanupFailureAudit {")
        end = text.index("    /** First unexpected policy failure only.", start)
        block = text[start:end].rstrip()
        need(block.endswith("}"), "complete nested diagnostic block required")
        fixture_dir = out / "audit-fixture"
        fixture_dir.mkdir()
        wrapper = fixture_dir / "BackgroundDisplayBroker.java"
        wrapper.write_text("package org.trillionnium.hepta.background;\npublic final class BackgroundDisplayBroker {\n"
                           + block + "\n}\n")
        result["audit_extraction"] = dict(source=str(broker), source_sha256=sha(broker),
            complete_nested_block_sha256=hashlib.sha256(block.encode()).hexdigest(),
            full_android_broker_compiled=False, wrapper_sha256=sha(wrapper))
        audit_classes = out / "audit-classes"
        audit_classes.mkdir()
        run("diagnostics-compile", [jdk / "javac", *flags, "-cp", a.json_jar,
                                   "-d", audit_classes, wrapper, diagnostic])
        run("diagnostics", [jdk / "java", "-cp", str(audit_classes) + ":" + str(a.json_jar.resolve()),
            "org.trillionnium.hepta.background.ProfileCleanupDiagnosticsHostTest"])
        need(result["diagnostics"].get("passed") is True
             and result["diagnostics"].get("assertions") == 14
             and result["diagnostics"].get("original_close_reason_changed") is False,
             "complete diagnostic contract changed")
        result["all_pass"] = True
    finally:
        result["source_inputs_unchanged"] = pins == {p: sha(Path(p)) for p in pins}
        result["all_pass"] = result["all_pass"] and result["source_inputs_unchanged"]
        (out / "RESULT.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps(dict(all_pass=result["all_pass"], report=str(out / "RESULT.json"),
                             cases=9, sampling_assertions=55, diagnostic_assertions=14, phone_operations=0)))
    return 0 if result["all_pass"] else 1

if __name__ == "__main__":
    sys.exit(main())
