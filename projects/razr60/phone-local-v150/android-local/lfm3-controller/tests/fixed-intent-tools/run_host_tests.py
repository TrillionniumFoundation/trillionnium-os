#!/usr/bin/env python3
"""Compile and run the pure fixed-tool contract; no device, model, or Android calls."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True, help="FixedIntentTools.java")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--release8", action="store_true", help="Require the Java 8 API release gate")
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    tests = Path(__file__).resolve().with_name("FixedIntentToolsHostTest.java")
    out = args.out.absolute()
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    classes = out / "classes"
    classes.mkdir(mode=0o700)
    java = shutil.which("java")
    javac = shutil.which("javac")
    if not java:
        raise RuntimeError("Existing JDK required; no dependency installation")
    compiler = [javac] if javac else [java, "-m", "jdk.compiler/com.sun.tools.javac.Main"]
    flags = ["--release", "8"] if args.release8 else ["-source", "8", "-target", "8"]
    compile_argv = compiler + flags + ["-encoding", "UTF-8", "-Xlint:all,-options", "-Werror",
                              "-d", str(classes), str(source), str(tests)]
    compiled = subprocess.run(compile_argv, capture_output=True, timeout=30)
    (out / "compile.stdout").write_bytes(compiled.stdout)
    (out / "compile.stderr").write_bytes(compiled.stderr)
    run = None
    summary = None
    major = None
    if compiled.returncode == 0:
        header = (classes / "org/trillionnium/hepta/background/FixedIntentTools.class").read_bytes()[:8]
        if len(header) != 8 or header[:4] != b"\xca\xfe\xba\xbe":
            raise RuntimeError("Invalid compiled class")
        major = struct.unpack(">H", header[6:8])[0]
        run = subprocess.run([java, "-cp", str(classes), "FixedIntentToolsHostTest"], capture_output=True, timeout=30)
        (out / "test.stdout").write_bytes(run.stdout)
        (out / "test.stderr").write_bytes(run.stderr)
        if run.returncode == 0:
            summary = json.loads(run.stdout)
    passed = compiled.returncode == 0 and run is not None and run.returncode == 0 and major == 52 and summary is not None and summary.get("all_pass") is True and summary.get("android_or_phone_tested") is False
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    report = {"schema": "hepta.fixed-intent-tools-host-evidence.v1", "all_pass": passed,
              "source_path": str(source), "source_sha256": digest(source), "test_source_sha256": digest(tests),
              "runner_sha256": digest(Path(__file__)), "compile_argv": compile_argv,
              "compile_exit": compiled.returncode, "test_exit": None if run is None else run.returncode,
              "compiler_contract": "Java8 API release" if args.release8 else "Java8 syntax/target only; not --release8 or Android compile proof",
              "class_major_version": major, "tests": summary, "android_or_phone_tested": False}
    (out / "HOST-RESULTS.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
