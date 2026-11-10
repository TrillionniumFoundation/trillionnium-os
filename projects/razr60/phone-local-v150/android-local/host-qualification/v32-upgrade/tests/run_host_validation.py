#!/usr/bin/env python3
"""Run the self-contained synthetic v32 host suite; never start a process/socket."""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib
import io
import json
from pathlib import Path
import platform
import sys
import time
from types import ModuleType
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_PINS = {
    "package/v32_identity.py": "e00335dba12953431aedaf0eac0185d5b58a2e248b287431b08e747008113476",
    "package/upgrade_v32_once_r1.py": "b6619f7e9e15c1aa465c4af0a405667fe288a0579c6a2240cb9afaef4c6b02d4",
    "package/select_runtime_once_v32_r1.py": "3fb80f4bf8ebd153d2d448415f9f1512a29a209697f1468545df069532a40721",
}
BASELINE_SHA = "480154279eed6d941d1cb240d4faf071088d4646f36f5bd35b926e3001c98e34"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def input_hashes():
    files = sorted({*ROOT.glob("package/*.py"), *ROOT.glob("tests/fixtures/**/*"), Path(__file__).resolve()})
    return {p.relative_to(ROOT).as_posix(): sha(p.read_bytes()) for p in files if p.is_file()}


def verify_runtime_manifest():
    manifest_raw = (ROOT / "MANIFEST.json").read_bytes()
    manifest = json.loads(manifest_raw)
    transfer = json.loads((ROOT / "TRANSFER-MANIFEST.json").read_bytes())
    if transfer["manifest_sha256"] != sha(manifest_raw):
        raise RuntimeError("transfer manifest does not bind this runtime manifest")
    if {row["path"]: row["sha256"] for row in manifest["files"]} != RUNTIME_PINS:
        raise RuntimeError("runtime manifest differs from frozen production pins")
    for row in manifest["files"]:
        raw = (ROOT / row["path"]).read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if len(raw) != row["bytes"] or sha(raw) != row["sha256"] or blob != row["git_blob_sha"]:
            raise RuntimeError("frozen runtime file differs: " + row["path"])
    expected = [{**row, "destination_name": Path(row["path"]).name} for row in manifest["files"]]
    if transfer["files"] != expected:
        raise RuntimeError("transfer rows differ from the checked runtime manifest")


def reproduce_baseline():
    """Reverse the one-character correction and prove the exact old verifier fails."""
    current = (ROOT / "package/v32_identity.py").read_bytes()
    new, old = b"[A-Za-z0-9_.+-]+[.]so", b"[A-Za-z0-9_.-]+[.]so"
    if current.count(new) != 1:
        raise RuntimeError("one exact runtime-name correction is required")
    previous = current.replace(new, old)
    if sha(previous) != BASELINE_SHA:
        raise RuntimeError("reconstructed pre-fix verifier does not match its original SHA")
    baseline = ModuleType("pre_fix_v32_identity")
    baseline.__file__ = "pre_fix_v32_identity.py"
    exec(compile(previous, baseline.__file__, "exec"), baseline.__dict__)
    regression = importlib.import_module("test_v32_zip_runtime_names")
    case = regression.RuntimeLibraryNames("test_libcxx_standard_basename_passes_actual_zip_verifier")
    try:
        case.setUp()
        try:
            baseline.verify_zip(regression.zip_bytes(case.f.apk_members), case.f.asset,
                                case.f.build, case.f.static, case.f.out)
        except RuntimeError as error:
            if str(error) != "unexpected runtime library":
                raise
        else:
            raise RuntimeError("expected pre-fix libc++ counterexample did not fail")
    finally:
        case.doCleanups()
    return {"reproduced": True, "baseline_identity_sha256": BASELINE_SHA,
            "current_identity_sha256": sha(current), "failure": "unexpected runtime library",
            "input": "synthetic valid ZIP/compiler bytes containing libc++_shared.so",
            "verifier_guards_mocked": False, "phone_contacted": False}


class CountResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.methods = []
        self.subtests_observed = 0

    def startTest(self, test):
        self.methods.append(test.id())
        super().startTest(test)

    def addSubTest(self, test, subtest, err):
        self.subtests_observed += 1
        super().addSubTest(test, subtest, err)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new absolute directory outside this release")
    args = parser.parse_args()
    if not args.output.is_absolute() or ROOT == args.output.resolve() or ROOT in args.output.resolve().parents:
        parser.error("--output must be an absolute directory outside this release")
    args.output.mkdir(parents=True, exist_ok=False)
    verify_runtime_manifest()
    before = input_hashes()
    attempted_transports = []

    def deny_transport(event, audit_args):
        if event.startswith("socket.") or event in ("subprocess.Popen", "os.system", "os.posix_spawn", "os.posix_spawnp", "os.exec", "os.fork", "os.forkpty"):
            attempted_transports.append(event)
            raise RuntimeError("host validation forbids process/network transport: " + event)

    sys.dont_write_bytecode = True
    sys.addaudithook(deny_transport)
    sys.path.insert(0, str(ROOT / "package"))
    stdout, stderr = io.StringIO(), io.StringIO()
    started = time.monotonic()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        baseline = reproduce_baseline()
        suite = unittest.defaultTestLoader.discover(str(ROOT / "package"), pattern="test_v32*.py")
        result = unittest.TextTestRunner(stream=stderr, verbosity=2, resultclass=CountResult).run(suite)
    after = input_hashes()
    success = (result.wasSuccessful() and result.testsRun == 42 and result.subtests_observed == 58
               and not result.skipped and not attempted_transports and before == after)
    stdout_raw, stderr_raw = stdout.getvalue().encode(), stderr.getvalue().encode()
    (args.output / "host-tests.stdout").write_bytes(stdout_raw)
    (args.output / "host-tests.stderr").write_bytes(stderr_raw)
    report = {
        "schema": "hepta.public-v32-upgrade-host-run.v1", "scope": "host_only",
        "passed": success, "exit_code": 0 if success else 1,
        "methods": result.testsRun, "original_methods": 36, "libcxx_regression_methods": 6,
        "subtests_observed": result.subtests_observed, "failures": len(result.failures),
        "errors": len(result.errors), "skipped": len(result.skipped),
        "test_methods": result.methods, "baseline_counterexample": baseline,
        "test_input_sha256": before, "test_inputs_unchanged": before == after,
        "runtime_manifest_sha256": sha((ROOT / "MANIFEST.json").read_bytes()),
        "transfer_manifest_sha256": sha((ROOT / "TRANSFER-MANIFEST.json").read_bytes()),
        "stdout_sha256": sha(stdout_raw), "stderr_sha256": sha(stderr_raw),
        "transport_forbidden_by_audit_hook": True,
        "attempted_transport_events": attempted_transports,
        "phone_contacted": False, "real_android_or_apk_execution": False,
        "actual_signed_v32_bundle_plan_run": False, "external_model_used": False,
        "producer_fixture": "three byte-identical public source files; remainder of the 1194-file test tree is synthetic",
        "live_source_gate": "unchanged: actual complete 1194-file source plus all actual receipts and APK required",
        "python_version": platform.python_version(), "elapsed_seconds": time.monotonic() - started,
        "reproduction": "python -B tests/run_host_validation.py --output /absolute/new-output",
    }
    (args.output / "HOST-RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("passed", "methods", "subtests_observed", "failures", "errors", "phone_contacted")}))
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
