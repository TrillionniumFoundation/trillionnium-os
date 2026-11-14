#!/usr/bin/env python3
"""Actual submit classes/dispatcher/controller with explicit Android IO fakes."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import types


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--release8", action="store_true")
    args = parser.parse_args()
    source, out = args.source.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    helper = source / "tests/qualification-scope/prepare_fixture.py"
    module = types.ModuleType("actual_submit_fixture")
    module.__file__ = str(helper)
    exec(compile(helper.read_bytes(), str(helper), "exec"), module.__dict__)
    files, extraction = module.prepare(source, out / "fixture")
    files += [source / "tests/ime-submit/ImeSubmitHostTest.java",
              source / "tests/ime-submit/ImeSubmitWiringHostTest.java"]
    pins = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    classes, grammars = out / "classes", out / "grammars"
    classes.mkdir(); grammars.mkdir()
    compiler = [shutil.which("javac")] if shutil.which("javac") else ["java", "-m", "jdk.compiler/com.sun.tools.javac.Main"]
    flags = ["--release", "8", "-Xlint:all"] if args.release8 else ["-source", "8", "-target", "8", "-Xlint:all,-options"]
    stages = [
        ("compile", compiler + flags + ["-encoding", "UTF-8", "-Werror", "-d", str(classes)] + list(map(str, files))),
        ("pure", ["java", "-cp", str(classes), "ImeSubmitHostTest", str(grammars)]),
        ("grammar", [sys.executable, "-B", str(source / "tests/ime-submit/test_submit_grammar.py"), str(grammars)]),
        ("wiring", ["java", "-cp", str(classes), "org.trillionnium.hepta.local.ImeSubmitWiringHostTest", str(out / "cases")]),
    ]
    report = {"schema": "hepta.ime-submit-host-validation.v1", "passed": False,
              "source_sha256": pins, "extraction": extraction, "stages": [],
              "compiler_contract": "Java 8 API release" if args.release8 else "supplemental Java8 source/class target on available JDK",
              "android_runtime": False, "phone_tested": False, "native_model_tested": False}
    for name, command in stages:
        run = subprocess.run(command, capture_output=True, text=True, timeout=90)
        (out / (name + ".stdout")).write_text(run.stdout)
        (out / (name + ".stderr")).write_text(run.stderr)
        report["stages"].append({"name": name, "exit_code": run.returncode, "argv": command})
        if run.returncode:
            print(run.stdout[-2500:]); print(run.stderr[-6000:]); break
    report["sources_unchanged"] = all(hashlib.sha256(Path(p).read_bytes()).hexdigest() == digest for p, digest in pins.items())
    report["passed"] = len(report["stages"]) == len(stages) and all(row["exit_code"] == 0 for row in report["stages"]) and report["sources_unchanged"]
    (out / "RESULT.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({k: report[k] for k in ("passed", "compiler_contract", "android_runtime", "phone_tested", "sources_unchanged")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
