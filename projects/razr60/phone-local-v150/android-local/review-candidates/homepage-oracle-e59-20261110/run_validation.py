#!/usr/bin/env python3
"""Apply the pinned host-only patch in isolation and replay synthetic evidence.

An explicit --external-fixtures option enables private retained-evidence replay.
No ADB, phone task, network request, upload or deployment is performed.
"""
from __future__ import annotations

import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

CAPSULE = Path(__file__).resolve().parent


def record(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def verify(root, rows):
    for row in rows:
        path = root / row["path"]
        if path.is_symlink() or record(path) != {"bytes": row["bytes"], "sha256": row["sha256"]}:
            raise ValueError("exact baseline required: " + row["path"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True, help="exact before core source files listed in BASELINE.json")
    parser.add_argument("--drivers", type=Path, required=True, help="exact retained driver files listed in BASELINE.json")
    parser.add_argument("--output", type=Path, required=True, help="new output directory outside this capsule")
    parser.add_argument("--external-fixtures", type=Path, help="private fixture directory; default is generated synthetic fixtures")
    parser.add_argument("--external-manifest", type=Path, help="private manifest; defaults to sibling EVIDENCE-SOURCES.json")
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    baseline = json.loads((CAPSULE / "BASELINE.json").read_text())
    source, drivers, output = args.source_dir.resolve(), args.drivers.resolve(), args.output.resolve()
    if output == CAPSULE or output.is_relative_to(CAPSULE):
        raise ValueError("validation output must remain outside the publication capsule")
    verify(source, baseline["source_files"])
    verify(drivers, baseline["driver_files"])
    if record(CAPSULE / "homepage-evidence.patch") != {k: baseline["logic_patch"][k] for k in ("bytes", "sha256")}:
        raise ValueError("published logic patch changed")
    if args.external_manifest and not args.external_fixtures:
        raise ValueError("--external-manifest requires --external-fixtures")
    fixtures = args.external_fixtures.resolve() if args.external_fixtures else None
    manifest_path = (args.external_manifest.resolve() if args.external_manifest else
                     fixtures.parent / "EVIDENCE-SOURCES.json" if fixtures else None)
    if manifest_path and record(manifest_path)["sha256"] != baseline["private_replay_manifest_sha256"]:
        raise ValueError("external fixture manifest differs from the retained replay snapshot")
    output.mkdir(parents=True, exist_ok=False)
    work = output / "isolated"
    code = work / "source"
    code.mkdir(parents=True)
    local_drivers = work / "drivers"
    local_drivers.mkdir()
    for row in baseline["source_files"]:
        shutil.copyfile(source / row["path"], code / row["path"])
    for row in baseline["driver_files"]:
        shutil.copyfile(drivers / row["path"], local_drivers / row["path"])
    for command in (("git", "init", "--quiet"), ("git", "apply", "--check", str(CAPSULE / "homepage-evidence.patch")),
                    ("git", "apply", str(CAPSULE / "homepage-evidence.patch"))):
        subprocess.run(command, cwd=code, check=True, capture_output=True)
    for name, expected in baseline["after_source_files"].items():
        if record(code / name) != expected:
            raise ValueError("applied candidate differs: " + name)
    for path in (CAPSULE / "tools").iterdir():
        if path.suffix == ".py":
            shutil.copyfile(path, code / path.name)
    (work / "tmp").mkdir()
    tempfile.tempdir = str(work / "tmp")
    os.environ["HEPTA_CORE_TEST_DRIVERS"] = str(local_drivers)
    sys.path[:0] = [str(code), str(local_drivers)]
    import phone_acceptance as acceptance
    import phone_suite as suite
    import core_assertions as checks

    class Result(unittest.TextTestResult):
        successful_subtests = 0
        def addSubTest(self, test, subtest, err):
            if err is None:
                self.successful_subtests += 1
            super().addSubTest(test, subtest, err)

    with contextlib.ExitStack() as stack:
        for owner, name in ((acceptance, "Adb"), (socket, "create_connection"),
                            (subprocess, "run"), (subprocess, "Popen")):
            stack.enter_context(mock.patch.object(owner, name,
                side_effect=AssertionError("phone/network/subprocess forbidden during evidence replay")))
        if fixtures is None:
            from synthetic_homepage_fixtures import generate
            fixtures = work / "fixtures"
            generate(fixtures)
            manifest_path = work / "EVIDENCE-SOURCES.json"
        os.environ["HEPTA_ORACLE_FIXTURE_ROOT"] = str(fixtures)
        os.environ["HEPTA_ORACLE_MANIFEST"] = str(manifest_path)
        import test_settings_homepage as replay_tests
        tests = unittest.defaultTestLoader.loadTestsFromNames(("test_settings_homepage", "test_core_assertions"))
        with (output / "host-tests.txt").open("w", encoding="utf-8") as log:
            result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=Result).run(tests)
        plan = json.loads((fixtures / "original-plan.json").read_text())
        replays = {}
        for name in (replay_tests.HOME, replay_tests.CROSS, replay_tests.SUBPAGE):
            case = next(c for c in plan["cases"] if c["case_id"] == name)
            value = checks.settings_homepage_evidence(fixtures / "cases" / name, case, suite, acceptance)
            # Deliberately exclude raw text, node labels, paths, task/run IDs and
            # underlying binding objects from the distributable summary.
            replays[name] = {"passed": value["passed"], "evidence_complete": value["evidence_complete"],
                             "error_count": len(value["errors"]), "checks": [
                                 {"kind": item["kind"], "passed": item["passed"]} for item in value["checks"]]}
        replay_tests.SettingsHomepageEvidence.verify_originals()
    expected = {replay_tests.HOME: True, replay_tests.CROSS: True, replay_tests.SUBPAGE: False}
    replay_passed = all(replays[name]["evidence_complete"] and replays[name]["passed"] is wanted
                        for name, wanted in expected.items())
    verify(source, baseline["source_files"])
    verify(drivers, baseline["driver_files"])
    report = {
        "schema": "hepta.homepage-oracle-public-validation.v1", "generated_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "external-private-replay" if args.external_fixtures else "synthetic-only",
        "passed": result.wasSuccessful() and replay_passed,
        "test_methods": result.testsRun, "successful_subtests": result.successful_subtests,
        "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped),
        "fixture_manifest": record(manifest_path),
        "fixture_files_verified_before_and_after": len(json.loads(manifest_path.read_text())["files"]),
        "logic_patch": record(CAPSULE / "homepage-evidence.patch"),
        "applied_candidate": {name: record(code / name) for name in baseline["after_source_files"]},
        "test_files": {path.name: record(path) for path in sorted((CAPSULE / "tools").glob("*.py"))},
        "runner": record(CAPSULE / "run_validation.py"), "host_log": record(output / "host-tests.txt"),
        "patch_check_and_apply_to_exact_baseline": True, "inputs_unchanged": True,
        "phone_contacted": False, "network_access_during_replay": False, "real_phone_files_included_in_capsule": False,
        "full_phone_or_current_apk_qualification_claimed": False,
        "historical_formal_suite_counts_unchanged": baseline["historical_full_suite_counts_unchanged"],
        "replays": replays
    }
    (output / "VALIDATION.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"mode": report["mode"], "passed": report["passed"], "tests": result.testsRun,
                      "successful_subtests": result.successful_subtests, "replay_expected_results": replay_passed}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
