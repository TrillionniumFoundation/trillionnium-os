#!/usr/bin/env python3
"""Original Ctrip cleanup gate plus a separate Xiaomi fixture; no phone IO."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def record(path):
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "output", "java-home", "json-jar"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    jdk, jar = args.java_home.resolve(), args.json_jar.resolve()
    assert not output.exists() and source not in output.parents
    assert sha(jar.read_bytes()) == "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
    original = source / "tests/public-profile-cleanup/PublicProfileCleanupHostTest.java"
    assert sha(original.read_bytes()) == "06538000c0deebc4d39be8317974eff6cd1abfc9e3493ff10d3ef2912882f546"
    output.mkdir(mode=0o700)
    own = Path(__file__).resolve().parent
    fixture = own / "XiaomiPublicProfileCleanupHostTest.java"
    pins = [record(p) for p in (original, fixture, Path(__file__).resolve(), jar)]
    report = {"schema": "hepta.xiaomi-profile-cleanup-host.v1", "all_pass": False,
              "source": str(source), "source_before": pins, "stages": [], "phone_actions": 0,
              "actual_background_session": True, "framework_io_synthetic": True,
              "device_qualified": False, "business_verified": False}
    env = dict(os.environ)
    env["PATH"] = str(jdk / "bin") + ":/usr/bin:/bin"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"):
        env.pop(key, None)

    def run(name, argv):
        start = time.monotonic()
        result = subprocess.run(list(map(str, argv)), cwd=output, env=env, capture_output=True, timeout=300)
        for suffix, data in (("stdout", result.stdout), ("stderr", result.stderr)):
            (output / (name + "." + suffix)).write_bytes(data)
        report["stages"].append({"name": name, "argv": list(map(str, argv)), "exit_code": result.returncode,
            "seconds": time.monotonic() - start, "stdout_sha256": sha(result.stdout), "stderr_sha256": sha(result.stderr)})
        if result.returncode:
            raise RuntimeError("stage failed: " + name)

    try:
        # The original complete gate runs unchanged first, including its existing
        # private-client regression. Nothing is spliced into the historical test.
        run("original-ctrip-cleanup", ["/usr/bin/python3", "-B", source / "tests/public-profile-cleanup/run_host.py",
            "--source", source, "--output", output / "ctrip", "--java-home", jdk, "--json-jar", jar])
        report["original_result"] = record(output / "ctrip/RESULT.json")
        original_result = json.loads((output / "ctrip/RESULT.json").read_text())
        assert original_result["all_pass"]
        baseline_classes = output / "ctrip/candidate-classes"
        compiled = sorted(baseline_classes.rglob("*.class"))
        assert compiled
        class_pins = [record(p) for p in compiled]
        report["fresh_original_class_inputs"] = class_pins
        classes = output / "xiaomi-classes"
        classes.mkdir()
        cp = str(baseline_classes) + os.pathsep + str(jar)
        run("xiaomi-fixture-compile", [jdk / "bin/javac", "--release", "8", "-encoding", "UTF-8", "-proc:none",
            "-Xlint:all,-options", "-Werror", "-classpath", cp, "-d", classes, fixture])
        run("xiaomi-cleanup", [jdk / "bin/java", "-cp", str(classes) + os.pathsep + cp,
            "org.trillionnium.hepta.local.XiaomiPublicProfileCleanupHostTest", output / "XIAOMI-CASES.json", "-", "-", "xiaomi"])
        report["xiaomi_cases"] = json.loads((output / "XIAOMI-CASES.json").read_text())
        report["fresh_original_classes_unchanged"] = class_pins == [record(p) for p in sorted(baseline_classes.rglob("*.class"))]
        assert report["xiaomi_cases"]["all_pass"] and report["xiaomi_cases"]["cases"] == 49 and report["xiaomi_cases"]["assertions"] == 71
        report["all_pass"] = report["fresh_original_classes_unchanged"]
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        report["source_after"] = [record(p) for p in (original, fixture, Path(__file__).resolve(), jar)]
        report["source_unchanged"] = pins == report["source_after"]
        report["all_pass"] = report["all_pass"] and report["source_unchanged"]
        (output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"all_pass": report["all_pass"], "error": report.get("error"),
            "xiaomi_cases": report.get("xiaomi_cases", {}).get("cases"), "result": str(output / "RESULT.json")}))
    return 0 if report["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
