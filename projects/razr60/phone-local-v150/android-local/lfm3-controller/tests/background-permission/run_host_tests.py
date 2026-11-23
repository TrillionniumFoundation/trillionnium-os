#!/usr/bin/env python3
"""Compile/run the actual permission worker with controlled Process/Clock/Journal.

Supplemental host compilation is the default. --release8 keeps the strict Java 8
API gate and never falls back if the installed JDK cannot provide that release.
This runner never starts su, ADB, Android, a model or a phone operation.
"""
import argparse
import hashlib
import json
from pathlib import Path
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
    files = [source / "src/org/trillionnium/hepta/local/BackgroundPermissionPreparation.java",
             source / "tests/background-permission/BackgroundPermissionPreparationHostTest.java"]
    pins = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    javac = shutil.which("javac")
    compiler = [javac] if javac else ["java", "-m", "jdk.compiler/com.sun.tools.javac.Main"]
    flags = ["--release", "8", "-Xlint:all"] if args.release8 else ["-source", "8", "-target", "8", "-Xlint:all,-options"]
    stages = [("compile", compiler + flags + ["-encoding", "UTF-8", "-Werror", "-d", str(classes)] + list(map(str, files))),
              ("worker", ["java", "-cp", str(classes), "org.trillionnium.hepta.local.BackgroundPermissionPreparationHostTest", str(out / "CASES.json")])]
    report = {"schema": "hepta.background-permission-host-validation.v1", "passed": False,
        "source_sha256": pins, "stages": [],
        "compiler_contract": "Java 8 API release" if args.release8 else "supplemental Java8 source/class target on available JDK",
        "process_clock_lease_journal_fakes": True, "su_executed": False,
        "android_runtime": False, "phone_tested": False, "native_model_tested": False}
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
    case_file = out / "CASES.json"
    if case_file.is_file():
        report["cases"] = json.loads(case_file.read_text())
    report["sources_unchanged"] = all(Path(path).is_file() and hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest for path, digest in pins.items())
    report["passed"] = (len(report["stages"]) == len(stages) and all(row["exit_code"] == 0 for row in report["stages"])
        and report["sources_unchanged"] and report.get("cases", {}).get("failed") == 0)
    (out / "RESULT.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({key: report[key] for key in ("passed", "compiler_contract", "sources_unchanged", "su_executed", "phone_tested")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
