#!/usr/bin/env python3
"""Compile the pure-JDK parser for Java 8 and retain exact host evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_new(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    labels_source = source.with_name("ObservedTargetLabels.java").resolve(strict=True)
    app_labels_source = source.with_name("ObservedAppLabels.java").resolve(strict=True)
    tests = Path(__file__).resolve().with_name("ActionDecisionHostTest.java")
    out = args.out.absolute()
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    classes = out / "classes"
    classes.mkdir(mode=0o700)
    java = shutil.which("java")
    if not java:
        raise RuntimeError("Existing JDK java is required; no dependency is installed")
    javac = shutil.which("javac")
    compiler = [javac] if javac else [java, "-m", "jdk.compiler/com.sun.tools.javac.Main"]
    compile_argv = compiler + ["--release", "8", "-encoding", "UTF-8", "-Xlint:all",
                              "-Werror", "-d", str(classes), str(source), str(labels_source), str(app_labels_source), str(tests)]
    started = time.time()
    compiled = subprocess.run(compile_argv, capture_output=True, timeout=30)
    write_new(out / "compile.stdout", compiled.stdout)
    write_new(out / "compile.stderr", compiled.stderr)
    summary = None
    major = None
    run_argv = [java, "-cp", str(classes), "ActionDecisionHostTest"]
    if compiled.returncode == 0:
        class_file = classes / "org/trillionnium/hepta/local/ActionDecision.class"
        class_header = class_file.read_bytes()[:8]
        if len(class_header) != 8 or class_header[:4] != b"\xca\xfe\xba\xbe":
            raise RuntimeError("Invalid compiled class header")
        major = struct.unpack(">H", class_header[6:8])[0]
        run = subprocess.run(run_argv, capture_output=True, timeout=30)
        write_new(out / "test.stdout", run.stdout)
        write_new(out / "test.stderr", run.stderr)
        if run.returncode == 0:
            summary = json.loads(run.stdout)
    else:
        run = None
    version = subprocess.run([java, "-version"], capture_output=True, timeout=10)
    write_new(out / "java-version.txt", version.stdout + version.stderr)
    passed = (compiled.returncode == 0 and run is not None and run.returncode == 0
              and major == 52 and summary is not None and summary.get("all_pass") is True
              and summary.get("android_or_phone_tested") is False)
    report = {
        "schema": "hepta.action-decision-host-evidence.v1",
        "all_pass": passed,
        "source_path": str(source),
        "source_sha256": digest(source),
        "labels_source_sha256": digest(labels_source),
        "app_labels_source_sha256": digest(app_labels_source),
        "test_source_sha256": digest(tests),
        "runner_sha256": digest(Path(__file__)),
        "compile_argv": compile_argv,
        "compile_exit": compiled.returncode,
        "class_major_version": major,
        "run_argv": run_argv,
        "test_exit": None if run is None else run.returncode,
        "tests": summary,
        "android_or_phone_tested": False,
        "external_model_used": False,
        "started_unix": started,
        "finished_unix": time.time(),
    }
    write_new(out / "HOST-RESULTS.json",
              (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode())
    print(json.dumps(report, ensure_ascii=False))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
