#!/usr/bin/env python3
"""Exercise exact MainActivity.refresh and model configuration accessors.

Android views/session IO are explicit fixtures. This checks a real configuration
failure through production methods, without Android, a model, or phone effects.
--release8 preserves the strict Java 8 API gate without an automatic fallback.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


def method(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    # Ignore quoted literals/comments when finding the exact method boundary.
    tokens = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/|[{}]', re.S)
    depth = 0
    for token in tokens.finditer(source, brace):
        if token.group() == "{":
            depth += 1
        elif token.group() == "}":
            depth -= 1
            if depth == 0:
                return source[start:token.end()]
    raise ValueError("unclosed production method: " + signature)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--release8", action="store_true")
    args = parser.parse_args()
    source, out = args.source.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    classes = out / "classes"
    classes.mkdir()
    java_dir = source / "src/org/trillionnium/hepta/local"
    main_file, engine_file = java_dir / "MainActivity.java", java_dir / "LocalModelEngine.java"
    template_file = Path(__file__).resolve().with_name("RefreshFixture.template")
    inputs = (main_file, engine_file, template_file, Path(__file__).resolve())
    pins = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}
    ui, engine = main_file.read_text(), engine_file.read_text()
    methods = {
        "refresh": method(ui, "private void refresh()"),
        "refresh_impl": method(ui, "private void refresh(boolean inspectModelFile)"),
        "navigation_idle": method(ui, "private boolean rootManagerNavigationIdle()"),
        "choice_error": method(ui, "private String backgroundChoiceError()"),
        "model_directory": method(engine, "public File modelDirectory()"),
        "model_file": method(engine, "public File modelFile()"),
        "configuration": method(engine, "public LocalRuntimeConfig configuration()"),
    }
    # The original model-config fixture has no authorization-preview pane.
    # Retain the actual absent-pane guard; any attempt to use a present pane throws.
    preview = method(ui, "private void previewTaskAuthorization()")
    preview_guard = "private void previewTaskAuthorization(){\n        if(taskAuthorizationInfo==null)return;"
    if not preview.startswith(preview_guard):
        raise RuntimeError("exact production absent-preview guard changed")
    methods["preview_absent"] = preview_guard + '\n        throw new AssertionError("authorization preview is outside the model-config fixture");\n    }'
    generated = template_file.read_text()
    for name, body in methods.items():
        marker = "{{" + name + "}}"
        if generated.count(marker) != 1:
            raise ValueError("production method insertion must be unique: " + name)
        generated = generated.replace(marker, body)
    fixture = out / "RuntimeConfigUiHostTest.java"
    fixture.write_text(generated)
    javac = shutil.which("javac")
    compiler = [javac] if javac else ["java", "-m", "jdk.compiler/com.sun.tools.javac.Main"]
    flags = ["--release", "8", "-Xlint:all"] if args.release8 else ["-source", "8", "-target", "8", "-Xlint:all,-options"]
    stages = [("compile", compiler + flags + ["-encoding", "UTF-8", "-Werror", "-d", str(classes), str(fixture)]),
              ("refresh", ["java", "-cp", str(classes), "RuntimeConfigUiHostTest", str(out / "files")])]
    report = {"schema": "hepta.runtime-config-ui-host-validation.v1", "passed": False,
        "source_sha256": pins, "stages": [],
        "production_methods_sha256": {name: hashlib.sha256(body.encode()).hexdigest() for name, body in methods.items()},
        "compiler_contract": "Java 8 API release" if args.release8 else "supplemental Java8 source/class target on available JDK",
        "view_session_io_fixtures": True, "android_runtime": False, "phone_tested": False,
        "preview_boundary":"Actual absent-pane guard only, present pane throws; original configuration assertions do not qualify native authorization preview",
        "preview_absent_guard_sha256":hashlib.sha256(preview_guard.encode()).hexdigest(),
        "native_model_tested": False, "configuration_modified": False}
    for name, command in stages:
        try:
            run = subprocess.run(command, capture_output=True, text=True, timeout=45)
            (out / (name + ".stdout")).write_text(run.stdout)
            (out / (name + ".stderr")).write_text(run.stderr)
            report["stages"].append({"name": name, "exit_code": run.returncode, "argv": command})
            if run.returncode:
                print(run.stdout[-4000:]); print(run.stderr[-4000:])
                break
            if name == "refresh":
                report["cases"] = json.loads(run.stdout)
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
            report["stages"].append({"name": name, "exit_code": None, "argv": command, "error": str(error)})
            break
    report["sources_unchanged"] = all(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == pins[str(path)] for path in inputs)
    report["passed"] = (len(report["stages"]) == len(stages) and all(row["exit_code"] == 0 for row in report["stages"])
        and report["sources_unchanged"] and report.get("cases", {}).get("failed") == 0)
    (out / "RESULT.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({key: report[key] for key in ("passed", "compiler_contract", "sources_unchanged", "phone_tested")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
