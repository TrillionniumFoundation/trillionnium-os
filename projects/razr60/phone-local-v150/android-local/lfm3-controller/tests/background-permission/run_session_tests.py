#!/usr/bin/env python3
"""Actual permission session and ExternalRunLease with explicit Android/process IO fixtures."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--release8", action="store_true")
    args = parser.parse_args()
    source, out = args.source.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    helper = Path(__file__).with_name("prepare_session_fixture.py")
    spec = importlib.util.spec_from_file_location("permission_session_fixture", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    files, extraction = module.prepare(source, out / "fixture")
    files.append(Path(__file__).with_name("BackgroundPermissionSessionHostTest.java"))
    pins = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    classes = out / "classes"
    classes.mkdir()
    compiler = [shutil.which("javac")] if shutil.which("javac") else ["java", "-m", "jdk.compiler/com.sun.tools.javac.Main"]
    flags = ["--release", "8", "-Xlint:all"] if args.release8 else ["-source", "8", "-target", "8", "-Xlint:all,-options"]
    stages = [("compile", compiler + flags + ["-Werror", "-encoding", "UTF-8", "-d", str(classes), *map(str, files)]),
              ("session-tests", ["java", "-cp", str(classes), "org.trillionnium.hepta.local.BackgroundPermissionSessionHostTest", str(out / "CASES.json")])]
    report = {"schema": "hepta.background-permission-session-host.v1", "stages": [], "source_sha256": pins, "extraction": extraction,
              "compiler_contract": "Java8 API release" if args.release8 else "supplemental Java8 syntax/class target", "su_executed": False, "phone_tested": False}
    for name, argv in stages:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        (out / (name + ".stdout")).write_text(result.stdout)
        (out / (name + ".stderr")).write_text(result.stderr)
        report["stages"].append({"name": name, "exit_code": result.returncode})
        if result.returncode:
            print(result.stdout[-3000:])
            print(result.stderr[-7000:])
            break
    report["sources_unchanged"] = all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest for path, digest in pins.items())
    report["passed"] = len(report["stages"]) == len(stages) and all(row["exit_code"] == 0 for row in report["stages"]) and report["sources_unchanged"]
    (out / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("passed", "compiler_contract", "sources_unchanged", "su_executed", "phone_tested")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
