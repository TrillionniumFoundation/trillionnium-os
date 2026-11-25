#!/usr/bin/env python3
"""Replay three exact complete AX captures through full original/candidate pure production parser closures."""
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
OLD_PAGE_SHA = "831bae5f1181eacf2873167afe9f0add0ad72e974e36103651b6e5b83068319f"
NEW_PAGE_SHA = "5e1a70f5a3b5b394723df834f8567cfb2679cfb3506ef7107599a92e89e23a2c"
FIXTURE_MANIFEST_SHA = "78b3224557707d2645c0a6a0c50620475ea9ff3856f34d0c7423a07a66dbcc04"
JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
PAGE = "src/org/trillionnium/hepta/local/NativeXiaomiProductPage.java"
LOCAL = ("NativeAppGoal", "NativeAppEvidence", "ObservationCaptureEvidence", "NativeCtripFormObservation",
         "NativeActionSnapshotCheck", "NativeXiaomiSearchInputObservation", "ObservedChildText",
         "ObservedTargetLabels", "ObservedScrollActions", "ObservedImeEnter", "NativeXiaomiProductPage")
BACKGROUND = ("ProfileIdentity", "ProfileTarget", "WindowOwnership")
EXPECTED_CASES = 68


def raw(path):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RuntimeError("ordinary unlinked source file required: " + str(path))
    data = path.read_bytes()
    after = path.lstat()
    names = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, key) != getattr(after, key) for key in names):
        raise RuntimeError("input changed during read: " + str(path))
    return data


def ref(path):
    path = Path(path).absolute()
    data = raw(path)
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                mode=stat.S_IMODE(path.lstat().st_mode))


def snapshot(source):
    paths = sorted(source.rglob("*"))
    if any(path.is_symlink() for path in paths):
        raise RuntimeError("source symlinks prohibited")
    return [ref(path) for path in paths if path.is_file()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("source", "baseline-source", "output", "java-home", "json-jar"):
        parser.add_argument("--" + key, required=True, type=Path)
    args = parser.parse_args()
    source, baseline, out, jdk, jar = [getattr(args, key).absolute() for key in
                                      ("source", "baseline_source", "output", "java_home", "json_jar")]
    if out.exists() or source == out or source in out.parents or baseline == out or baseline in out.parents:
        raise RuntimeError("fresh output outside both source roots required")
    test = source / "tests/native-xiaomi-direct-card"
    fixture_manifest = test / "FIXTURE-MANIFEST.json"
    old_page, page = baseline / PAGE, source / PAGE
    if ref(old_page)["sha256"] != OLD_PAGE_SHA or ref(old_page)["bytes"] != 58258:
        raise RuntimeError("complete pinned W5 original parser required")
    if ref(page)["sha256"] != NEW_PAGE_SHA or ref(page)["bytes"] != 61156:
        raise RuntimeError("complete reviewed candidate parser required")
    if ref(fixture_manifest)["sha256"] != FIXTURE_MANIFEST_SHA:
        raise RuntimeError("exact three-capture provenance manifest required")
    if ref(jar)["sha256"] != JSON_SHA or ref(jar)["bytes"] != 78332:
        raise RuntimeError("original pinned JSON dependency required")
    provenance = json.loads(raw(fixture_manifest))
    if len(provenance["files"]) != 9 or len(provenance["observations"]) != 3:
        raise RuntimeError("all nine full original capture/frame/page files required")
    fixtures = []
    for row in provenance["files"]:
        actual = ref(test / "fixtures" / row["name"])
        if any(actual[key] != row["source"][key] for key in ("bytes", "sha256")):
            raise RuntimeError("actual frozen raw bytes differ: " + row["name"])
        fixtures.append(actual)
    inputs = [source / ("src/org/trillionnium/hepta/local/" + name + ".java") for name in LOCAL]
    inputs += [source / ("src/org/trillionnium/hepta/background/" + name + ".java") for name in BACKGROUND]
    inputs += [test / "NativeXiaomiDirectCardHostTest.java"]
    tools = [jdk / "bin/java", jdk / "bin/javac", jdk / "lib/modules", jdk / "lib/ct.sym", jar]
    source_before = snapshot(source)
    baseline_before = snapshot(baseline)
    out.mkdir(parents=True, mode=0o700)
    report = dict(schema="hepta.xiaomi-direct-card-complete-host-gate.v1", all_pass=False,
                  source=str(source), baseline_source=str(baseline),
                  scope="complete actual pure production classes; exact archived captures plus labelled parser counterfactuals",
                  stages=[], variants={}, input_before=source_before, baseline_before=baseline_before,
                  tools_before=[ref(path) for path in tools], fixture_provenance=ref(fixture_manifest),
                  exact_fixture_files=fixtures, original_parser=ref(old_page), candidate_parser=ref(page),
                  phone_operations=0, android_execution=False, model_executed=False,
                  business_completion_verified=False, final_detail_price_verified=False,
                  current_phone_frame_or_action_authority=False)
    env = dict(os.environ)
    env.update(JAVA_HOME=str(jdk), PATH=str(jdk / "bin") + ":/usr/bin:/bin", PYTHONDONTWRITEBYTECODE="1")
    for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"):
        env.pop(key, None)

    def stage(name, argv):
        started = time.monotonic()
        run = subprocess.run(list(map(str, argv)), cwd=out, env=env, capture_output=True, timeout=180)
        stdout, stderr = out / (name + ".stdout"), out / (name + ".stderr")
        stdout.write_bytes(run.stdout)
        stderr.write_bytes(run.stderr)
        report["stages"].append(dict(name=name, argv=list(map(str, argv)), exit_code=run.returncode,
                                     elapsed_seconds=time.monotonic() - started, stdout=ref(stdout), stderr=ref(stderr)))
        if run.returncode:
            raise RuntimeError(name + " failed; exact stdout/stderr retained")
        return run

    try:
        run = stage("java-version", [jdk / "bin/javac", "-version"])
        if not (run.stdout + run.stderr).decode().strip().startswith("javac 17."):
            raise RuntimeError("actual JDK 17 required")
        for variant in ("baseline", "candidate"):
            classes = out / (variant + "-classes")
            classes.mkdir()
            compile_inputs = [(old_page if path == page and variant == "baseline" else path) for path in inputs]
            report["variants"][variant] = dict(compile_inputs=[ref(path) for path in compile_inputs],
                                                complete_page_input=ref(old_page if variant == "baseline" else page))
            stage(variant + "-compile", [jdk / "bin/javac", "--release", "8", "-encoding", "UTF-8",
                  "-proc:none", "-Xlint:all", "-Werror", "-cp", jar, "-d", classes, *compile_inputs])
            cases_path = out / (variant + "-CASES.json")
            stage(variant + "-cases", [jdk / "bin/java", "-ea", "-cp", str(classes) + os.pathsep + str(jar),
                  "org.trillionnium.hepta.local.NativeXiaomiDirectCardHostTest", test / "fixtures", cases_path, variant])
            cases = json.loads(raw(cases_path))
            if (cases.get("all_pass") is not True or cases.get("cases") != EXPECTED_CASES
                    or len(cases["results"]) != EXPECTED_CASES or len(set(cases["case_names"])) != EXPECTED_CASES
                    or not all(row.get("passed") is True for row in cases["results"])
                    or cases["actual_recorded_captures"] != 3 or cases["business_completion_verified"] is not False):
                raise RuntimeError("complete positive/negative accounting required")
            report["variants"][variant].update(case_file=ref(cases_path), cases=cases)
        baseline_cases = report["variants"]["baseline"]["cases"]
        candidate_cases = report["variants"]["candidate"]["cases"]
        if baseline_cases["case_names"] != candidate_cases["case_names"]:
            raise RuntimeError("same exact case set on old and new full parser required")
        report["all_pass"] = True
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        report["input_after"] = snapshot(source)
        report["baseline_after"] = snapshot(baseline)
        report["tools_after"] = [ref(path) for path in tools]
        report["inputs_unchanged"] = report["input_before"] == report["input_after"]
        report["baseline_unchanged"] = report["baseline_before"] == report["baseline_after"]
        report["tools_unchanged"] = report["tools_before"] == report["tools_after"]
        report["all_pass"] &= report["inputs_unchanged"] and report["baseline_unchanged"] and report["tools_unchanged"]
        result = out / "RESULT.json"
        result.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps(dict(all_pass=report["all_pass"], error=report.get("error"), result=ref(result),
                              variants={key:dict(cases=value.get("cases",{}).get("cases"),
                                                 assertions=value.get("cases",{}).get("assertions"))
                                        for key,value in report["variants"].items()})))
    return 0 if report["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
