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
    display_file = java_dir / "TaskDisplayText.java"
    metadata_files = tuple(java_dir / name for name in ("ModelProfile.java", "VlmResultContract.java", "VlmPins.java", "MobiMindContract.java", "MobiMindPins.java"))
    inputs = (main_file, engine_file, display_file, template_file, Path(__file__).resolve()) + metadata_files
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
        "model_directory_config": method(engine, "private File modelDirectory(LocalRuntimeConfig config)"),
        "model_file_config": method(engine, "private File modelFile(LocalRuntimeConfig config)"),
        "generation_configuration": method(engine, "LocalRuntimeConfig configuration(){"),
    }
    # Execute the exact ordinary button's model/background guard prefix.
    # Deliberately stop before scope authorization, UI input handling and task scheduling.
    begin_task = method(ui, "private boolean beginTask(String owner,String source,String nonceSha)")
    begin_header = "private boolean beginTask(String owner,String source,String nonceSha){\n        try{\n"
    scope_boundary = "            if(scopeLaunchError!=null)"
    if not begin_task.startswith(begin_header) or begin_task.count(scope_boundary) != 1:
        raise RuntimeError("ordinary task model preflight boundary changed")
    begin_preflight = begin_task[len(begin_header):begin_task.index(scope_boundary)]
    if not begin_preflight.endswith("            }\n"):
        raise RuntimeError("ordinary visual model preflight is not a complete block")
    methods["begin_task_model_preflight"] = ("private String beginTaskModelPreflightError(){\n        try{\n"
        + begin_preflight + "            return null;\n        }catch(Exception error){return error.getMessage();}\n    }")
    # The original model-config fixture has no authorization-preview pane.
    # Retain the actual absent-pane guard; any attempt to use a present pane throws.
    preview = method(ui, "private void previewTaskAuthorization()")
    preview_guard = "private void previewTaskAuthorization(){\n        if(taskAuthorizationInfo==null)return;"
    if not preview.startswith(preview_guard):
        raise RuntimeError("exact production absent-preview guard changed")
    methods["preview_absent"] = preview_guard + '\n        throw new AssertionError("authorization preview is outside the model-config fixture");\n    }'
    permission = method(ui, "private void refreshProfilePermission()")
    permission_guard = "private void refreshProfilePermission(){\n        if(profilePermissionCard==null)return;"
    if not permission.startswith(permission_guard):
        raise RuntimeError("exact production absent-permission-pane guard changed")
    methods["permission_absent"] = permission_guard + '\n        throw new AssertionError("profile permission UI is outside the model-config fixture");\n    }'
    generated = template_file.read_text()
    for name, body in methods.items():
        marker = "{{" + name + "}}"
        if generated.count(marker) != 1:
            raise ValueError("production method insertion must be unique: " + name)
        generated = generated.replace(marker, body)
    fixture = out / "RuntimeConfigUiHostTest.java"
    fixture.write_text(generated)
    # The legacy extracted UI fixture is in the default package. Compile the
    # exact production display helper with only its package declaration removed.
    display_source = display_file.read_text()
    declaration = "package org.trillionnium.hepta.local;\n"
    if not display_source.startswith(declaration):
        raise RuntimeError("production display helper package differs")
    display_fixture = out / "TaskDisplayText.java"
    display_fixture.write_text(display_source[len(declaration):])
    # Compile exact closed profile/artifact metadata; only the legacy fixture's package boundary is adapted.
    metadata_fixtures = []
    for dependency in metadata_files:
        body = dependency.read_text()
        if not body.startswith(declaration):
            raise RuntimeError("production metadata helper package differs: " + dependency.name)
        target = out / dependency.name
        target.write_text(body[len(declaration):])
        metadata_fixtures.append(target)
    entry_fixture = out / "RuntimeConfigEntryHostTest.java"
    entry_fixture.write_text('public final class RuntimeConfigEntryHostTest {public static void main(String[] args)throws Exception{'
        'int checks=RuntimeConfigUiHostTest.entryChecks(new java.io.File(args[0]));'
        'System.out.println("{\\"passed\\":"+checks+",\\"failed\\":0,\\"task_scheduling_executed\\":false}");}}\n')
    javac = shutil.which("javac")
    compiler = [javac] if javac else ["java", "-m", "jdk.compiler/com.sun.tools.javac.Main"]
    flags = ["--release", "8", "-Xlint:all"] if args.release8 else ["-source", "8", "-target", "8", "-Xlint:all,-options"]
    stages = [("compile", compiler + flags + ["-encoding", "UTF-8", "-Werror", "-d", str(classes), str(fixture), str(display_fixture), str(entry_fixture)] + [str(path) for path in metadata_fixtures]),
              ("refresh", ["java", "-cp", str(classes), "RuntimeConfigUiHostTest", str(out / "files")]),
              ("entry", ["java", "-cp", str(classes), "RuntimeConfigEntryHostTest", str(out / "entry-files")])]
    report = {"schema": "hepta.runtime-config-ui-host-validation.v1", "passed": False,
        "source_sha256": pins, "stages": [],
        "production_methods_sha256": {name: hashlib.sha256(body.encode()).hexdigest() for name, body in methods.items()},
        "compiler_contract": "Java 8 API release" if args.release8 else "supplemental Java8 source/class target on available JDK",
        "profile_metadata_boundary": "Exact complete ModelProfile, VlmResultContract, VlmPins and the contract parser dependencies MobiMindContract/MobiMindPins; package declaration removal only. Profile facade retains legacy mutable UI inputs and delegates directory selection to the actual closed mapping. Weight files exercise presence display, not hash admission or model inference.",
        "start_preflight_boundary": "Exact beginTask model/background guard prefix, ending before scopeLaunchError. No scope authorization, task scheduling, keyboard or other Android action is executed.",
        "begin_task_sha256": hashlib.sha256(begin_task.encode()).hexdigest(),
        "begin_task_model_preflight_sha256": hashlib.sha256(begin_preflight.encode()).hexdigest(),
        "view_session_io_fixtures": True, "android_runtime": False, "phone_tested": False,
        "preview_boundary":"Actual absent-pane guard only, present pane throws; original configuration assertions do not qualify native authorization preview",
        "preview_absent_guard_sha256":hashlib.sha256(preview_guard.encode()).hexdigest(),
        "permission_boundary":"Exact absent-pane guard only; a present pane throws. Permission worker and choice lifecycle have their separate gate; no rendered UI claim.",
        "permission_absent_guard_sha256":hashlib.sha256(permission_guard.encode()).hexdigest(),
        "generation_boundary":"Exact three dependency methods; the original seven UI/config subjects and assertions remain. Mutable configuration/error are view fixture inputs, not production settings or publication.",
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
            if name in ("refresh", "entry"):
                report["cases" if name == "refresh" else "entry_cases"] = json.loads(run.stdout)
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
            report["stages"].append({"name": name, "exit_code": None, "argv": command, "error": str(error)})
            break
    report["sources_unchanged"] = all(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == pins[str(path)] for path in inputs)
    report["passed"] = (len(report["stages"]) == len(stages) and all(row["exit_code"] == 0 for row in report["stages"])
        and report["sources_unchanged"] and report.get("cases", {}).get("failed") == 0
        and report.get("cases", {}).get("original_passed") == 38
        and report.get("cases", {}).get("visual_projector_passed") == 16
        and report.get("entry_cases", {}).get("passed") == 14
        and report.get("entry_cases", {}).get("failed") == 0
        and report.get("entry_cases", {}).get("task_scheduling_executed") is False)
    (out / "RESULT.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({key: report[key] for key in ("passed", "compiler_contract", "sources_unchanged", "phone_tested")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
