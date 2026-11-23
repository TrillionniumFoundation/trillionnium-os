#!/usr/bin/env python3
"""Supplemental exact-source Application/external/recovery test runner.

The regular tools/test_recovery_application.py remains the strict --release 8
gate. This runner never falls back from --release8 and never launches su or ADB.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--release8", action="store_true")
    args = parser.parse_args()
    source, out = args.source.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    classes = out / "classes"
    classes.mkdir()
    helper = source / "tests/recovery-application/prepare_engine_fixture.py"
    spec = importlib.util.spec_from_file_location("hepta_recovery_application_fixture", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sources = module.prepare(source, out / "fixture")
    pins = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources + [helper]}
    engine = source / "src/org/trillionnium/hepta/local/LocalModelEngine.java"
    pins[str(engine)] = hashlib.sha256(engine.read_bytes()).hexdigest()
    javac = shutil.which("javac")
    compiler = [javac] if javac else ["java", "-m", "jdk.compiler/com.sun.tools.javac.Main"]
    flags = ["--release", "8", "-Xlint:all"] if args.release8 else ["-source", "8", "-target", "8", "-Xlint:all,-options"]
    stages = [("compile", compiler + flags + ["-encoding", "UTF-8", "-Werror", "-d", str(classes)] + list(map(str, sources))),
              ("application", ["java", "-cp", str(classes), "org.trillionnium.hepta.local.RecoveryApplicationHostTest"])]
    report = {"schema": "hepta.recovery-application-host-validation.v2", "passed": False,
              "source_sha256": pins, "stages": [],
              "compiler_contract": "Java 8 API release" if args.release8 else "supplemental Java8 source/class target on available JDK",
              "actual_application": True, "exact_engine_external_and_recovery_members": True,
              "android_task_permission_session_diagnostic_fixtures": True,
              "production_permission_session_tested": False, "filesystem_durability_tested": False,
              "su_executed": False, "android_runtime": False, "phone_tested": False}
    for name, command in stages:
        try:
            run = subprocess.run(command, capture_output=True, text=True, timeout=45)
            (out / (name + ".stdout")).write_text(run.stdout)
            (out / (name + ".stderr")).write_text(run.stderr)
            report["stages"].append({"name": name, "exit_code": run.returncode, "argv": command})
            if run.returncode:
                print(run.stdout[-4000:]); print(run.stderr[-4000:])
                break
        except (OSError, subprocess.TimeoutExpired) as error:
            report["stages"].append({"name": name, "exit_code": None, "argv": command, "error": str(error)})
            break
    output = out / "application.stdout"
    if output.is_file():
        actual = output.read_text()
        legacy = re.search(r"^PASS cases=(\d+) assertions=(\d+)$", actual, re.M)
        permission = re.search(r"^PASS permission_cases=(\d+) assertions=(\d+)$", actual, re.M)
        report["cases"] = {"legacy": int(legacy[1]) if legacy else None,
                           "legacy_assertions": int(legacy[2]) if legacy else None,
                           "permission": int(permission[1]) if permission else None,
                           "permission_assertions": int(permission[2]) if permission else None}
    report["sources_unchanged"] = all(Path(path).is_file() and hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest for path, digest in pins.items())
    report["passed"] = (len(report["stages"]) == len(stages) and all(row["exit_code"] == 0 for row in report["stages"])
                        and report["sources_unchanged"] and report.get("cases", {}).get("legacy") == 18
                        and report.get("cases", {}).get("permission") == 12)
    (out / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("passed", "compiler_contract", "sources_unchanged", "su_executed", "phone_tested")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
