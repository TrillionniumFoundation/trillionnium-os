#!/usr/bin/env python3
"""Initialization-failure Notes recovery: real policy/client/lease plus explicit host-only IO.
Portable inputs are authored synthetic values. Optional --actual-originals points at a
private role/file/hash index; raw originals are read-only and are never repository fixtures.
"""
import argparse
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def info(path):
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": sha(path)}

def main():
    parser = argparse.ArgumentParser()
    for key in ("source", "java-home", "json-jar", "output"):
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--actual-originals", type=Path,
                        help="Private exact 11-role file/hash index; not a public fixture.")
    a = parser.parse_args()
    source, output = a.source.resolve(strict=True), a.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    if sha(a.json_jar) != JSON_SHA:
        raise RuntimeError("actual org.json hash differs")
    jdk, jar = a.java_home.resolve(strict=True) / "bin", a.json_jar.resolve(strict=True)
    tests = source / "tests/personal-notes-initialization-recovery"
    required = [tests / x for x in ("run_host.py", "PersonalNotesInitializationHostTest.java",
                                    "PersonalNotesInitializationActualHostTest.java",
                                    "PersonalNotesInitializationClientHostTest.java")]
    source_inputs = {str(p): sha(p) for p in required}
    result = {"schema": "hepta.personal-notes-initialization-host-gate.v1",
              "all_pass": False, "phone_operations": 0, "android_runtime": False,
              "strict_release8": True, "business_success_claimed": False,
              "framework_controller_and_clock_values_synthetic": True,
              "private_actual_originals": bool(a.actual_originals),
              "source_inputs": source_inputs, "stages": []}

    def run(label, argv):
        (output / (label + ".command.json")).write_text(json.dumps(argv, indent=2) + "\n")
        began = time.monotonic()
        completed = subprocess.run(argv, capture_output=True, timeout=180 if label == "legacy" else 60)
        stdout, stderr = output / (label + ".stdout"), output / (label + ".stderr")
        stdout.write_bytes(completed.stdout)
        stderr.write_bytes(completed.stderr)
        result["stages"].append({"stage": label, "exit_code": completed.returncode,
                                 "seconds": time.monotonic() - began,
                                 "stdout": info(stdout), "stderr": info(stderr)})
        print(json.dumps({"stage": label, "exit_code": completed.returncode}), flush=True)
        if completed.returncode:
            raise RuntimeError(label + " failed; see saved stderr")
        return completed.stdout

    failure = None
    try:
        legacy = output / "existing-absence"
        run("legacy", ["/usr/bin/python3", "-B", str(source / "tests/personal-notes-absence/run_host.py"),
                       "--source", str(source), "--java-home", str(a.java_home),
                       "--json-jar", str(jar), "--output", str(legacy)])
        legacy_report = json.loads((legacy / "RESULT.json").read_bytes())
        if not legacy_report["all_pass"] or not legacy_report["strict_release8"] or not legacy_report["inputs_unchanged"]:
            raise RuntimeError("unchanged real legacy gate did not pass")
        result["legacy_result"] = info(legacy / "RESULT.json")
        for name, digest in legacy_report["source_inputs"].items():
            if sha(Path(name)) != digest:
                raise RuntimeError("legacy input changed after compilation")
        flags = [str(jdk / "javac"), "--release", "8", "-proc:none", "-Xlint:all,-options",
                 "-Werror", "-encoding", "UTF-8"]
        pure = output / "policy-classes"
        client = output / "client-classes"
        pure.mkdir()
        client.mkdir()
        pure_cp = str(legacy / "policy-classes") + os.pathsep + str(jar)
        client_cp = str(legacy / "client-classes") + os.pathsep + str(jar)
        run("policy-compile", [*flags, "-cp", pure_cp, "-d", str(pure),
                              str(tests / "PersonalNotesInitializationHostTest.java"),
                              str(tests / "PersonalNotesInitializationActualHostTest.java")])
        run("client-compile", [*flags, "-cp", client_cp, "-d", str(client),
                              str(tests / "PersonalNotesInitializationClientHostTest.java")])
        pure_run = [str(jdk / "java"), "-cp", str(pure) + os.pathsep + pure_cp]
        client_run = [str(jdk / "java"), "-cp", str(client) + os.pathsep + client_cp]
        portable = output / "portable-originals"
        result["portable_policy"] = json.loads(run("portable-policy", [*pure_run,
            "org.trillionnium.hepta.background.PersonalNotesInitializationHostTest",
            "--synthetic-output", str(portable)]))
        result["portable_client"] = json.loads(run("portable-client", [*client_run,
            "org.trillionnium.hepta.local.PersonalNotesInitializationClientHostTest", str(portable / "INDEX.json")]))
        if a.actual_originals:
            original_index = a.actual_originals.resolve(strict=True)
            data = json.loads(original_index.read_bytes())
            rows = data["records"] if "records" in data else data
            expected = {"journal", "owner", "bootstrap", "cleanup", "result", "broker_receipt", "broker_output",
                        "initial_binding", "scope_binding", "completion_identity", "current_control"}
            if set(rows) != expected:
                raise RuntimeError("private actual index must contain exactly eleven bound roles")
            for row in rows.values():
                p = Path(row["path"]).resolve(strict=True)
                if p.stat().st_size != row["bytes"] or sha(p) != row["sha256"]:
                    raise RuntimeError("private original differs")
            result["actual_index"] = info(original_index)
            result["actual_original_roles"] = rows
            flat = output / "PRIVATE-ORIGINAL-INDEX.json"
            flat.write_text(json.dumps(rows, indent=2) + "\n")
            synthetic_controller = json.loads((portable / "INDEX.json").read_bytes())["controller"]
            journal = json.loads(Path(rows["journal"]["path"]).read_bytes())
            synthetic_controller["uid"] = journal["app_uid"]
            combined = output / "PRIVATE-CLIENT-INDEX.json"
            combined.write_text(json.dumps({"records": rows, "controller": synthetic_controller,
                                            "controller_is_explicit_synthetic_host_value": True}, indent=2) + "\n")
            result["actual_policy"] = json.loads(run("actual-policy", [*pure_run,
                "org.trillionnium.hepta.background.PersonalNotesInitializationHostTest", "--actual", str(flat)]))
            result["actual_original_replay"] = json.loads(run("actual-original-replay", [*pure_run,
                "org.trillionnium.hepta.background.PersonalNotesInitializationActualHostTest", str(flat)]))
            result["actual_client"] = json.loads(run("actual-client", [*client_run,
                "org.trillionnium.hepta.local.PersonalNotesInitializationClientHostTest", str(combined)]))
            for row in rows.values():
                p = Path(row["path"])
                if p.stat().st_size != row["bytes"] or sha(p) != row["sha256"]:
                    raise RuntimeError("private original changed during gate")
        result["source_inputs_unchanged"] = source_inputs == {str(p): sha(p) for p in required}
        if not result["source_inputs_unchanged"]:
            raise RuntimeError("new test input changed")
        result["all_pass"] = True
    except Exception as exc:
        failure = type(exc).__name__ + ": " + str(exc)
        result["error"] = failure
    path = output / "RESULT.json"
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"all_pass": result["all_pass"], "result": info(path), "error": failure}), flush=True)
    return 0 if result["all_pass"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
