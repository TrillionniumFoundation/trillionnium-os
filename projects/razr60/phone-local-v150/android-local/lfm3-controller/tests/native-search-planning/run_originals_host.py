#!/usr/bin/env python3
"""Actual complete Role/Planning closure and retained two-pair original tests."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "output", "originals", "java-home", "json-jar"):
        parser.add_argument("--" + name, type=Path, required=True)
    a = parser.parse_args()
    source, output, originals, jdk, jar = [getattr(a, n).resolve() for n in ("source", "output", "originals", "java_home", "json_jar")]
    if output.exists():
        raise RuntimeError("fresh output required")
    output.mkdir(mode=0o700)
    helper = source / "tests/native-search-planning/host_closure.py"
    spec = importlib.util.spec_from_file_location("search_closure", helper)
    closure = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(closure)
    report = {"schema": "hepta.native-search-originals-host-run.v1", "all_pass": False,
              "source": str(source), "originals": str(originals), "stages": [], "phone_actions": 0}
    try:
        assert closure.sha(jar.read_bytes()) == closure.JSON_SHA
        paths, provenance = closure.prepare(source, output / "closure", [source / "tests/native-search-planning/NativeSearchRoleOriginalsHostTest.java"])
        report["closure"] = provenance
        tracked = [Path(x["path"]) for x in provenance["production_inputs"]] + [Path(__file__).resolve(),
            originals / "step-01-action.json", originals / "failed-native-census.json"]
        tracked = list(dict.fromkeys(tracked))
        report["inputs_before"] = [closure.record(p) for p in tracked]
        tools = [jdk / "bin/java", jdk / "bin/javac", jar]
        report["tools_before"] = [closure.record(p) for p in tools]
        env = dict(os.environ, PATH=str(jdk / "bin") + ":/usr/bin:/bin", PYTHONDONTWRITEBYTECODE="1")
        for name in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"):
            env.pop(name, None)
        classes = output / "classes"
        classes.mkdir()
        commands = [
            ("compile", [jdk / "bin/javac", "--release", "8", "-encoding", "UTF-8", "-proc:none", "-Xlint:all,-options", "-Werror", "-classpath", jar, "-d", classes, *paths]),
            ("original-pairs", [jdk / "bin/java", "-cp", str(classes) + os.pathsep + str(jar), "org.trillionnium.hepta.local.NativeSearchRoleOriginalsHostTest", originals, output / "ORIGINAL-PAIRS.json"]),
            ("retained-native-snapshot", [jdk / "bin/java", "-cp", str(classes) + os.pathsep + str(jar), "org.trillionnium.hepta.local.NativeActionSnapshotCheckHostTest", output / "RETAINED-SNAPSHOT.json"]),
            ("retained-profile-identity", [jdk / "bin/java", "-cp", str(classes) + os.pathsep + str(jar), "org.trillionnium.hepta.local.NativeProfileIdentityHostTest", output / "RETAINED-PROFILE.json", output / "profile-work"])]
        for name, argv in commands:
            started = time.monotonic()
            done = subprocess.run(list(map(str, argv)), cwd=output, env=env, capture_output=True, timeout=120)
            for suffix, raw in (("stdout", done.stdout), ("stderr", done.stderr)):
                (output / (name + "." + suffix)).write_bytes(raw)
            report["stages"].append({"name": name, "argv": list(map(str, argv)), "seconds": time.monotonic() - started,
                "exit_code": done.returncode, "stdout_sha256": closure.sha(done.stdout), "stderr_sha256": closure.sha(done.stderr)})
            if done.returncode:
                raise RuntimeError("stage failed: " + name)
        report["case_reports"] = {name: json.loads((output / filename).read_text()) for name, filename in (
            ("original_pairs", "ORIGINAL-PAIRS.json"), ("retained_snapshot", "RETAINED-SNAPSHOT.json"), ("retained_profile", "RETAINED-PROFILE.json"))}
        assert all(v["all_pass"] for v in report["case_reports"].values())
        assert report["case_reports"]["retained_profile"]["cases"] == 22
        report["all_pass"] = True
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        if "inputs_before" in report:
            report["inputs_after"] = [closure.record(p) for p in tracked]
            report["inputs_unchanged"] = report["inputs_before"] == report["inputs_after"]
            report["tools_after"] = [closure.record(p) for p in tools]
            report["tools_unchanged"] = report["tools_before"] == report["tools_after"]
            report["all_pass"] = report["all_pass"] and report["inputs_unchanged"] and report["tools_unchanged"]
        (output / "RESULT.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps({"all_pass": report["all_pass"], "error": report.get("error"), "result": str(output / "RESULT.json"),
                          "cases": {k: v.get("cases") for k, v in report.get("case_reports", {}).items()}}))
    return 0 if report["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
