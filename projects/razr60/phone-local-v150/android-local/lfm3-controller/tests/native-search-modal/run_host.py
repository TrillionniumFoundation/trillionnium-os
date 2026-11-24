#!/usr/bin/env python3
"""Retained failed modal pair, actual providers/Session, strict Java 8 host gate."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
sys.dont_write_bytecode = True


def record(path):
    p = Path(path).resolve()
    raw = p.read_bytes()
    return {"path": str(p), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for key in ("source", "output", "java-home", "json-jar"):
        ap.add_argument("--" + key, type=Path, required=True)
    args = ap.parse_args()
    source, out, jdk, jar = (args.source.resolve(), args.output.resolve(), args.java_home.resolve(), args.json_jar.resolve())
    if out.exists() or source in out.parents:
        raise RuntimeError("new output outside source required")
    out.mkdir(parents=True, mode=0o700)
    closure_path = source / "tests/native-search-planning/host_closure.py"
    spec = importlib.util.spec_from_file_location("modal_actual_closure", closure_path)
    closure = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(closure)
    if record(jar)["sha256"] != closure.JSON_SHA:
        raise RuntimeError("pinned JSON dependency required")
    test = source / "tests/native-search-modal"
    extras = [test / "NativeSearchModalHostTest.java", source / "tests/native-search-session/NativeSearchSessionHostTest.java",
              source / "tests/native-search-grammar/NativeSearchGrammarHostTest.java",
              source / "tests/native-search-planning/NativeSearchPlanningContractHostTest.java"]
    paths, provenance = closure.prepare(source, out / "generated", extras)
    original_paths = list(dict.fromkeys([Path(v["path"]) for v in provenance["production_inputs"]]
                                       + extras + [closure_path, Path(__file__).resolve(), test / "recorded-5b8-modal-censuses.json"]))
    before = [record(p) for p in original_paths]
    tools = [jdk / "bin/javac", jdk / "bin/java", jdk / "lib/modules", jdk / "lib/ct.sym", jar]
    tool_before = [record(p) for p in tools]
    result = {"schema": "hepta.native-search-image-modal-gate.v1", "all_pass": False, "scope": "host_only",
              "source": str(source), "source_inputs_before": before, "tool_inputs_before": tool_before,
              "closure": provenance, "phone_operations": 0, "android_executed": False,
              "model_inference_tested": False, "business_verified": False, "stages": []}
    env = dict(os.environ)
    env.update({"JAVA_HOME": str(jdk), "PATH": str(jdk / "bin") + ":/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"})
    for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"):
        env.pop(key, None)
    classes = out / "classes"
    classes.mkdir()
    argfile = out / "javac.args"
    argfile.write_text("\n".join('"' + str(p) + '"' for p in paths) + "\n")
    commands = [("compile", [jdk / "bin/javac", "--release", "8", "-encoding", "UTF-8", "-proc:none", "-Xlint:all,-options", "-Werror",
                             "-classpath", jar, "-d", classes, "@" + str(argfile)]),
                ("cases", [jdk / "bin/java", "-ea", "-cp", str(classes) + os.pathsep + str(jar),
                           "org.trillionnium.hepta.local.NativeSearchModalHostTest", test / "recorded-5b8-modal-censuses.json",
                           out / "CASES.json", out / "work"])]
    try:
        for name, argv in commands:
            started = time.monotonic()
            completed = subprocess.run(list(map(str, argv)), cwd=out, env=env, capture_output=True, timeout=180)
            stdout, stderr = out / (name + ".stdout"), out / (name + ".stderr")
            stdout.write_bytes(completed.stdout)
            stderr.write_bytes(completed.stderr)
            result["stages"].append({"name": name, "argv": list(map(str, argv)), "exit_code": completed.returncode,
                                     "seconds": time.monotonic() - started, "stdout": record(stdout), "stderr": record(stderr)})
            if completed.returncode:
                raise RuntimeError(name + " failed; original output retained")
        cases = json.loads((out / "CASES.json").read_text())
        if cases["all_pass"] is not True or cases["cases"] != 12:
            raise RuntimeError("complete modal positive/negative matrix required")
        result["cases"] = cases
        result["all_pass"] = True
    except Exception as error:
        result["error"] = type(error).__name__ + ": " + str(error)
    finally:
        result["source_inputs_after"] = [record(p) for p in original_paths]
        result["tool_inputs_after"] = [record(p) for p in tools]
        result["sources_unchanged"] = result["source_inputs_after"] == before
        result["tools_unchanged"] = result["tool_inputs_after"] == tool_before
        result["all_pass"] &= result["sources_unchanged"] and result["tools_unchanged"]
        (out / "RESULT.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"all_pass": result["all_pass"], "error": result.get("error"), "result": record(out / "RESULT.json")}))
    return 0 if result["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
