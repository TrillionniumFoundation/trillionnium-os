#!/usr/bin/env python3
"""Strict filled-query candidate gate over exact recorded node trees and labelled counterfactuals."""
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
JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
FIXTURE_SHA = "80da80631b77f606f93b412faafd2915a13d2d6dfeeeb57398db05e8cb2525ff"


def ref(path):
    path = Path(path).resolve()
    before = path.stat()
    data = path.read_bytes()
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise RuntimeError("input changed during read: " + str(path))
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), mode=stat.S_IMODE(before.st_mode))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("source", "output", "java-home", "json-jar"):
        parser.add_argument("--" + key, required=True, type=Path)
    args = parser.parse_args()
    source, out, jdk, jar = [getattr(args, key).resolve() for key in ("source", "output", "java_home", "json_jar")]
    if out.exists() or source == out or source in out.parents:
        raise RuntimeError("fresh output outside source required")
    out.mkdir(parents=True, mode=0o700)
    test = source / "tests/native-xiaomi-query-stability"
    fixture = test / "real-censuses.json"
    names = ("ObservationCaptureEvidence", "NativeCtripFormObservation", "NativeActionSnapshotCheck",
             "NativeXiaomiSearchInputObservation", "ObservedChildText", "ObservedTargetLabels",
             "ObservedScrollActions", "ObservedImeEnter")
    paths = [source / ("src/org/trillionnium/hepta/local/" + name + ".java") for name in names]
    paths += [test / "NativeXiaomiQueryStabilityHostTest.java"]
    inputs = paths + [fixture, Path(__file__).resolve()]
    tools = [jdk / "bin/java", jdk / "bin/javac", jdk / "lib/modules", jdk / "lib/ct.sym", jar]
    report = dict(schema="hepta.xiaomi-filled-query-pure-host-run.v1", all_pass=False,
                  source=str(source), scope="actual_complete_pure_classes_no_android_ports",
                  stages=[], input_before=[ref(p) for p in inputs], tools_before=[ref(p) for p in tools],
                  phone_operations=0, android_execution=False, model_executed=False,
                  business_completion_verified=False, actual_type_current_census_retained=False,
                  original_worker_fresh_census_available=False)
    try:
        if ref(jar)["sha256"] != JSON_SHA or ref(jar)["bytes"] != 78332:
            raise RuntimeError("original JSON dependency pin required")
        if ref(fixture)["sha256"] != FIXTURE_SHA:
            raise RuntimeError("hash-exact recorded fixture required")
        for p in (fixture, test / "NativeXiaomiQueryStabilityHostTest.java", Path(__file__).resolve()):
            if ref(p)["mode"] != 0o644:
                raise RuntimeError("canonical 0644 fixture source mode required")
        env = dict(os.environ)
        env.update(JAVA_HOME=str(jdk), PATH=str(jdk / "bin") + ":/usr/bin:/bin", PYTHONDONTWRITEBYTECODE="1")
        for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"):
            env.pop(key, None)
        classes = out / "classes"
        classes.mkdir()
        commands = [
            ("java-version", [jdk / "bin/javac", "-version"]),
            ("compile", [jdk / "bin/javac", "--release", "8", "-encoding", "UTF-8", "-proc:none", "-Xlint:all", "-Werror",
                         "-cp", jar, "-d", classes, *paths]),
            ("cases", [jdk / "bin/java", "-ea", "-cp", str(classes) + os.pathsep + str(jar),
                       "org.trillionnium.hepta.local.NativeXiaomiQueryStabilityHostTest", fixture, out / "CASES.json"])
        ]
        for name, argv in commands:
            started = time.monotonic()
            run = subprocess.run(list(map(str, argv)), cwd=out, env=env, capture_output=True, timeout=180)
            stdout, stderr = out / (name + ".stdout"), out / (name + ".stderr")
            stdout.write_bytes(run.stdout)
            stderr.write_bytes(run.stderr)
            report["stages"].append(dict(name=name, argv=list(map(str, argv)), exit_code=run.returncode,
                                         elapsed_seconds=time.monotonic() - started,
                                         stdout=ref(stdout), stderr=ref(stderr)))
            if run.returncode:
                raise RuntimeError(name + " failed; original stdout/stderr retained")
            if name == "java-version" and not (run.stdout + run.stderr).decode().strip().startswith("javac 17."):
                raise RuntimeError("strict Temurin/JDK 17 host toolchain required")
        cases = json.loads((out / "CASES.json").read_bytes())
        if (cases.get("all_pass") is not True or cases["cases"] != len(cases["results"])
                or cases["cases"] != len(cases["case_names"]) or len(set(cases["case_names"])) != cases["cases"]
                or not all(row.get("passed") is True for row in cases["results"])):
            raise RuntimeError("complete independent case accounting required")
        report["all_pass"] = True
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        if (out / "CASES.json").exists():
            report["cases"] = json.loads((out / "CASES.json").read_bytes())
            report["case_file"] = ref(out / "CASES.json")
        report["input_after"] = [ref(p) for p in inputs]
        report["tools_after"] = [ref(p) for p in tools]
        report["inputs_unchanged"] = report["input_before"] == report["input_after"]
        report["tools_unchanged"] = report["tools_before"] == report["tools_after"]
        report["all_pass"] &= report["inputs_unchanged"] and report["tools_unchanged"]
        result = out / "RESULT.json"
        result.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps(dict(all_pass=report["all_pass"], error=report.get("error"), result=ref(result),
                              cases=report.get("cases", {}).get("cases"), assertions=report.get("cases", {}).get("assertions"))))
    return 0 if report["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
