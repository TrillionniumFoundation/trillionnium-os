#!/usr/bin/env python3
"""Public derived complete location-popup shape + unchanged provider regressions; host only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(p):
    raw = p.read_bytes()
    return {"path": str(p), "bytes": len(raw), "sha256": sha(raw)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "output", "java-home", "json-jar"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    jdk, jar = args.java_home.resolve(), args.json_jar.resolve()
    assert not output.exists() and source not in output.parents
    output.mkdir(mode=0o700)
    inputs = [p for p in source.rglob("*") if p.is_file()]
    before = {str(p.relative_to(source)): identity(p) for p in inputs}
    tools = {str(p): identity(p) for p in (jdk / "bin/java", jdk / "bin/javac", jdk / "lib/modules", jar)}
    assert sha(jar.read_bytes()) == "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
    env = dict(os.environ)
    for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"):
        env.pop(key, None)
    env["PATH"] = str(jdk / "bin") + ":/usr/bin:/bin"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    report = {"schema": "hepta.xiaomi-location-host-gate.v1", "all_pass": False,
              "source": str(source), "phone_operations": 0, "model_executed": False,
              "platform_dispatch_executed": False, "phone_runtime_qualified": False,
              "business_verified": False, "stages": []}

    def run(name, argv):
        argv = [str(x) for x in argv]
        started = time.monotonic()
        with (output / (name + ".stdout")).open("wb") as stdout, (output / (name + ".stderr")).open("wb") as stderr:
            result = subprocess.run(argv, env=env, cwd=str(source), stdout=stdout, stderr=stderr, timeout=300)
        row = {"name": name, "argv": argv, "exit_code": result.returncode,
               "elapsed_seconds": time.monotonic() - started,
               "stdout": identity(output / (name + ".stdout")), "stderr": identity(output / (name + ".stderr"))}
        report["stages"].append(row)
        assert result.returncode == 0, name + " failed; original logs retained"

    try:
        provenance = json.loads((source / "tests/native-xiaomi-location/fixtures/PROVENANCE.json").read_text())
        assert provenance["schema"] == "hepta.xiaomi-location-public-derived-fixtures.v1"
        assert provenance["public_derived_fixtures"] is True
        assert provenance["exact_original_capture"] is False
        for row in provenance["files"]:
            path = source / "tests/native-xiaomi-location/fixtures" / row["path"]
            actual = identity(path)
            assert actual["bytes"] == row["bytes"] and actual["sha256"] == row["sha256"]
            assert row["derived_fixture"] is True and row["exact_original_capture"] is False
        report["public_derived_fixture_provenance"] = provenance
        original = source / "tests/native-app-provider/run_host.py"
        original_bytes = original.read_bytes()
        assert sha(original_bytes) == '7f57be43bbbf43ae0cbaca63569c723b42199b98d6819f5707981dcc978e7a4f'
        helper_source_entry = b"'ObservationCaptureEvidence', "
        assert original_bytes.count(helper_source_entry) == 1
        assert sha(original_bytes.replace(helper_source_entry, b"", 1)) == "8f98d2f335f1a4b2dd659a9b0c5478a87e313247b261a1d32c8ce0535fa32064"
        report["retained_provider_original_bytes_restored_without_only_helper_source_entry"] = True
        retained = output / "retained-provider"
        run("retained-provider", [sys.executable, original, "--source", source, "--output", retained,
                                  "--java-home", jdk, "--json-jar", jar])
        previous = json.loads((retained / "RESULT.json").read_text())
        assert previous["all_pass"] is True and previous["inputs_unchanged"] is True and previous["tools_unchanged"] is True
        report["retained_provider_result"] = identity(retained / "RESULT.json")
        report["retained_provider_cases"] = previous["cases"]["cases"]
        report["retained_provider_assertions"] = previous["cases"]["assertions"]
        classes = output / "classes"
        classes.mkdir()
        test = source / "tests/native-xiaomi-location/NativeXiaomiLocationHostTest.java"
        cp = str(retained / "classes") + os.pathsep + str(jar)
        run("location-compile", [jdk / "bin/javac", "--release", "8", "-encoding", "UTF-8", "-proc:none",
                                 "-Xlint:all,-options", "-Werror", "-classpath", cp, "-d", classes, test])
        report["new_test_input"] = identity(test)
        run("location-cases", [jdk / "bin/java", "-cp", str(classes) + os.pathsep + cp,
                               "org.trillionnium.hepta.local.NativeXiaomiLocationHostTest", source, output / "CASES.json"])
        cases = json.loads((output / "CASES.json").read_text())
        assert cases["all_pass"] is True and cases["schema"] == "hepta.native-xiaomi-location-host.v1"
        assert cases["private_originals_modified"] is False and cases["public_fixture_is_exact_capture"] is False and cases["synthetic_record_identity"] is True and cases["phone_operations"] == 0
        assert cases["phone_runtime_qualified"] is False and cases["business_verified"] is False
        assert cases["model_executed"] is False and cases["platform_dispatch_executed"] is False
        assert cases["cases"] == len(cases["case_names"]) and len(set(cases["case_names"])) == cases["cases"]
        report["cases"] = cases
        report["all_pass"] = True
    except Exception as error:
        report["failure"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        after = {str(p.relative_to(source)): identity(p) for p in source.rglob("*") if p.is_file()}
        report["source_unchanged"] = before == after
        report["tools_unchanged"] = tools == {p: identity(Path(p)) for p in tools}
        report["all_pass"] = report["all_pass"] and report["source_unchanged"] and report["tools_unchanged"]
        report["production"] = [identity(source / "src/org/trillionnium/hepta/local" / name)
                                for name in ("NativeXiaomiProductPage.java", "NativeAppSession.java", "NativeAppDomain.java", "HeptaAccessibilityService.java")]
        raw = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode()
        (output / "RESULT.json").write_bytes(raw)
        print(json.dumps({"all_pass": report["all_pass"], "cases": report.get("cases", {}).get("cases"),
                          "assertions": report.get("cases", {}).get("assertions"), "failure": report.get("failure"),
                          "result": str(output / "RESULT.json"), "sha256": sha(raw)}))
    return 0 if report["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
