#!/usr/bin/env python3
"""Pinned recorded facts and complete-AX-derived caption cases; no device IO."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

HERE = Path(__file__).resolve().parent
PKG = Path("src/org/trillionnium/hepta/local")
BASE_SHA = "c1df34cb7613f7b50e206b89140e1518556343f438fe43594ff27ca1c5db3346"
JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
RECORDED = {
    "step-02-action.json": (48100, "be395fbedb96824f14d89ab8077d7b1c1b465cf12c652f1bc2845c5f6813f1b5"),
    "step-03-action.json": (48437, "7a76136d2aef8d043555e132aa18812f002e825008844f665952faf2cafde024"),
    "step-04-action.json": (48100, "9f8ee85305a036d4da5f2005dd6199a30e337b2166ae4643af054c846f1c4fd7"),
    "4438ee67817a433aa8e1d88b1f48c994-native-ax.json": (371073, "14be4d5e23c295d05e3aeb082f69c1e74c78a8e4c17709ed6f6791a851b6d831"),
    "6afece2af5ce4717b68731456beeb64c-native-ax.json": (380494, "d449521e8b2e7fdbbb7cbb9c0467ce42204e64e3b7649db78cac1fed34c4d67d"),
    "a999b83d176145d9894501221f4b9c80-native-ax.json": (366438, "39810fc86275cae589875cccdeb43ce67e15a470636844b3201196d48df4278f"),
}
NAMES = [
    "ObservationCaptureEvidence.java", "NativeCtripFormObservation.java",
    "NativeXiaomiSearchInputObservation.java", "NativeActionSnapshotCheck.java",
    "ObservedChildText.java", "ObservedTargetLabels.java",
    "ObservedScrollActions.java", "ObservedImeEnter.java",
]


def meta(path):
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def stage(name, argv, out):
    start = time.monotonic()
    stdout, stderr = out / (name + ".stdout"), out / (name + ".stderr")
    with stdout.open("xb") as stream, stderr.open("xb") as errors:
        run = subprocess.run(argv, stdout=stream, stderr=errors, check=False, timeout=180)
    return {
        "name": name, "argv": argv, "exit_code": run.returncode,
        "elapsed_seconds": time.monotonic() - start,
        "stdout": meta(stdout), "stderr": meta(stderr),
    }


def main():
    parser = argparse.ArgumentParser()
    for name in ("source", "output", "java-home", "json-jar", "recorded-root", "baseline-comparator"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    source, recorded = args.source.resolve(), args.recorded_root.resolve()
    out = args.output.absolute()
    out.mkdir(parents=True, exist_ok=False)
    java, javac = args.java_home.resolve() / "bin/java", args.java_home.resolve() / "bin/javac"
    jar, baseline = args.json_jar.resolve(), args.baseline_comparator.resolve()
    production = [source / PKG / name for name in NAMES]
    test = HERE / "NativeCtripCaptionHostTest.java"
    inputs = production + [test, Path(__file__).resolve(), baseline] + [recorded / name for name in RECORDED]
    tools = [java, javac, jar]
    result = {
        "schema": "hepta.ctrip-caption-successor-host.v1", "all_pass": False,
        "base_head": "5b943de939a72d0e61fd912c6af3b3edc60ad0f5",
        "recorded_task": "a9e6127f97a04854ab908d664f533e63",
        "recorded_b3_sha256": "fcb570f2444deacf170d6796f8a15ebc5419fd5614eb2fbdafa78b3363f2c159",
        "stages": [], "source_root": str(source), "phone_operations": 0,
        "android_execution": False, "model_executed": False,
        "business_completion_verified": False, "platform_dispatch_executed": False,
        "missing_failed_fresh_censuses_replayed": False,
        "derived_variants_are_synthetic": True, "synthetic_action_intents": True,
    }
    before = []
    tool_before = []
    try:
        before = [meta(path) for path in inputs]
        tool_before = [meta(path) for path in tools]
        result["inputs_before"], result["tools_before"] = before, tool_before
        if meta(jar)["sha256"] != JSON_SHA or jar.stat().st_size != 78332:
            raise RuntimeError("JSON library pin differs")
        if meta(baseline)["sha256"] != BASE_SHA:
            raise RuntimeError("exact installed-5b comparator baseline differs")
        for name, (size, digest) in RECORDED.items():
            fact = meta(recorded / name)
            if fact["bytes"] != size or fact["sha256"] != digest:
                raise RuntimeError("immutable recorded evidence differs: " + name)
        for mode in ("baseline", "candidate"):
            classes = out / (mode + "-classes")
            classes.mkdir()
            sources = list(production)
            if mode == "baseline":
                base_source = out / "baseline-source" / "NativeActionSnapshotCheck.java"
                base_source.parent.mkdir()
                shutil.copyfile(baseline, base_source)
                sources = [base_source if path.name == base_source.name else path for path in sources]
            compile_argv = [str(javac), "--release", "8", "-encoding", "UTF-8", "-proc:none",
                            "-Xlint:all", "-Werror", "-cp", str(jar), "-d", str(classes)]
            compile_argv += [str(path) for path in sources + [test]]
            item = stage(mode + "-compile", compile_argv, out)
            result["stages"].append(item)
            if item["exit_code"]:
                raise RuntimeError(mode + " compilation failed")
            case_file = out / (mode.upper() + "-CASES.json")
            argv = [str(java), "-cp", str(classes) + os.pathsep + str(jar),
                    "org.trillionnium.hepta.local.NativeCtripCaptionHostTest",
                    str(recorded), str(case_file), mode]
            item = stage(mode + "-cases", argv, out)
            result["stages"].append(item)
            if item["exit_code"]:
                raise RuntimeError(mode + " cases failed")
            cases = json.loads(case_file.read_text())
            if (cases.get("all_pass") is not True or cases["cases"] != len(cases["case_names"])
                    or len(set(cases["case_names"])) != cases["cases"]
                    or cases.get("recorded_action_fact_cases") != 3
                    or cases.get("recorded_complete_ax_pair_cases") != 3
                    or cases.get("missing_failed_fresh_censuses_replayed") is not False
                    or cases.get("phone_operations") != 0):
                raise RuntimeError(mode + " case accounting or evidence scope differs")
            result[mode] = {"result": meta(case_file), "cases": cases}
        result["all_pass"] = True
    except Exception as failure:
        result["error"] = {"type": type(failure).__name__, "message": str(failure)}
    finally:
        result["inputs_after"] = [meta(path) for path in inputs]
        result["tools_after"] = [meta(path) for path in tools]
        result["inputs_unchanged"] = before == result["inputs_after"]
        result["tools_unchanged"] = tool_before == result["tools_after"]
        result["all_pass"] &= result["inputs_unchanged"] and result["tools_unchanged"]
        (out / "RESULT.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"all_pass": result["all_pass"], "error": result.get("error"), "result": meta(out / "RESULT.json")}))
    return 0 if result["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
