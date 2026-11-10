#!/usr/bin/env python3
"""Synthetic pure-parser regression. No driver main/import, ADB, helper or phone.

Extracts only the reviewed constants and the two pure production functions from
the driver AST. Fixtures are not recorded device output and prove no phone pass.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shlex

BASE = Path(__file__).resolve().parent
DRIVER = BASE / "background_calculator_acceptance.py"
GENERATION = "12345678-1234-1234-1234-123456789abc"
OWNER_UID = 10481
TARGET = "com.example.calculator"
ENTRY = "org.trillionnium.hepta.background.BackgroundDisplayBroker"
FLAGS = ["--socket", "hepta-bg-" + GENERATION, "--owner-uid", str(OWNER_UID),
    "--generation", GENERATION, "--allowed-packages", TARGET,
    "--ttl-ms", "540000", "--expires-elapsed-ms", "999999999"]


def process(pid, uid, words):
    return {"pid": pid, "uid": uid, "ppid": 500, "args": shlex.join(words)}


def fixture(name, processes, verified, expected_pids):
    return {"name": name, "processes": processes, "expected_verified": verified, "expected_pids": expected_pids}


def main():
    raw = DRIVER.read_bytes()
    tree = ast.parse(raw, filename=str(DRIVER))
    constants = {"BROKER_ENTRY", "BROKER_PROCESS_ARGV0", "UUID"}
    functions = {"broker_process_identity", "broker_process_summary"}
    selected = []
    found = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in constants:
                selected.append(node)
                found.add(name)
        elif isinstance(node, ast.FunctionDef) and node.name in functions:
            selected.append(node)
            found.add(node.name)
    assert found == constants | functions, "exact production parser definitions unavailable"
    namespace = {"re": re, "shlex": shlex}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(DRIVER) + ":pure-parser-only", "exec"), namespace)
    assess = namespace["broker_process_summary"]
    root = process(601, 0, ["/system/bin/app_process", "/", ENTRY] + FLAGS)
    shell = process(602, 2000, ["/system/bin/app_process64", "/", ENTRY] + FLAGS)
    class_argv0 = process(603, 0, [ENTRY] + FLAGS)
    command = "CLASSPATH=/data/app/example/base.apk " + shlex.join(["/system/bin/app_process", "/", ENTRY] + FLAGS)
    su = process(604, OWNER_UID, ["su", "-c", command])
    sh = process(605, 0, ["/system/bin/sh", "-c", command])
    wrong_generation = FLAGS.copy()
    wrong_generation[wrong_generation.index("--generation") + 1] = GENERATION + "0"
    wrong_socket = FLAGS.copy()
    wrong_socket[wrong_socket.index("--socket") + 1] = "hepta-bg-00000000-0000-0000-0000-000000000000"
    wrong_owner = FLAGS.copy()
    wrong_owner[wrong_owner.index("--owner-uid") + 1] = "10482"
    cases = [
        fixture("root_app_process", [root], True, [601]),
        fixture("shell_uid_app_process64", [shell], True, [602]),
        fixture("exact_java_class_argv0", [class_argv0], True, [603]),
        fixture("repeated_samples_same_pid", [root, root], True, [601]),
        fixture("ordinary_uid_su_wrapper_and_real_root", [su, root], True, [601]),
        fixture("root_sh_wrapper_and_real_root", [sh, root], True, [601]),
        fixture("ordinary_uid_su_wrapper_only", [su], False, []),
        fixture("root_sh_wrapper_only", [sh], False, []),
        fixture("root_su_wrapper_only", [{**su, "uid": 0}], False, []),
        fixture("fake_class_substring", [process(606, 0, ["/system/bin/app_process", "/", ENTRY + "Fake"] + FLAGS)], False, []),
        fixture("fake_argv0_substring", [process(607, 0, ["/system/bin/app_process_fake", "/", ENTRY] + FLAGS)], False, []),
        fixture("fake_class_argv0_substring", [process(608, 0, [ENTRY + "Fake"] + FLAGS)], False, []),
        fixture("generation_substring_only", [process(609, 0, ["/system/bin/app_process", "/", ENTRY] + wrong_generation)], False, []),
        fixture("generation_absent", [process(610, 0, ["/system/bin/app_process", "/", ENTRY] + FLAGS[:4] + FLAGS[6:])], False, []),
        fixture("duplicate_generation_flag", [process(611, 0, ["/system/bin/app_process", "/", ENTRY] + FLAGS + ["--generation", GENERATION])], False, []),
        fixture("socket_generation_mismatch", [process(612, 0, ["/system/bin/app_process", "/", ENTRY] + wrong_socket)], False, []),
        fixture("owner_uid_mismatch", [process(613, 0, ["/system/bin/app_process", "/", ENTRY] + wrong_owner)], False, []),
        fixture("ordinary_uid_actual_app_process", [{**root, "uid": OWNER_UID}], False, [601]),
        fixture("two_distinct_actual_broker_pids", [root, shell], False, [601, 602]),
        fixture("truncated_named_process_no_flags", [process(614, 0, [ENTRY])], False, []),
        fixture("boolean_uid_is_not_root", [{**root, "uid": False}], False, []),
        fixture("unclosed_quote_argv", [{**root, "args": "'" + root["args"]}], False, []),
    ]
    results = []
    for case in cases:
        actual = assess(case["processes"], GENERATION, OWNER_UID, TARGET)
        passed = actual["verified"] is case["expected_verified"] and actual["pids"] == case["expected_pids"]
        results.append({**case, "actual": actual, "passed": passed})
    files = {}
    for name in ("background_calculator_acceptance.py", "README.md", "test_process_identity.py"):
        content = (BASE / name).read_bytes()
        files[name] = {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
    report = {"schema": "hepta.background-phone-test-preparation.v2", "revision": "r2",
        "status": "prepared_phone_not_executed", "python_ast_parse": True,
        "pure_parser_regression_executed": True, "fixture_origin": "synthetic_not_phone_observations",
        "cases": len(results), "passed": sum(item["passed"] for item in results), "results": results,
        "driver_entry_executed": False, "host_helper_executed": False, "phone_operations": False,
        "phone_test_passed": False, "files": files}
    path = BASE / "PREPARATION.json"
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({"cases": report["cases"], "passed": report["passed"], "phone_operations": False,
        "phone_test_passed": False, "preparation": str(path)}))
    return 0 if report["passed"] == report["cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
