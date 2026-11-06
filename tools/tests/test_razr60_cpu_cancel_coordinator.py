"""Verify cancellation transport ownership and exact original phase contracts."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = ROOT / "projects/razr60/phone-local-v150/operators/r10-cpu-cancel-coordinator-r1"
SEAL_SHA256 = "b8030fa733b178e8dec99774a6ea3246101626a31f2a452b944b0de46fead763"


class Razr60CpuCancelCoordinator(unittest.TestCase):
    def test_original_capture_and_unbound_admission_regressions(self):
        seal_raw = (CANDIDATE / "SOURCE-SEAL.json").read_bytes()
        self.assertEqual(hashlib.sha256(seal_raw).hexdigest(), SEAL_SHA256)
        seal = json.loads(seal_raw)
        self.assertIsNone(seal["final_authority"])
        self.assertEqual(seal["acceptance_case_credit"], 0)
        before = {}
        for row in seal["files"]:
            raw = (CANDIDATE / row["path"]).read_bytes()
            self.assertEqual(len(raw), row["bytes"], row["path"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row["sha256"], row["path"])
            before[row["path"]] = raw
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        with tempfile.TemporaryDirectory(prefix="razr60-cpu-cancel-") as temporary:
            output = Path(temporary) / "report.json"
            completed = subprocess.run(
                [sys.executable, "-I", "-B", str(CANDIDATE / "tests/run_regressions.py"),
                 "--output", str(output)], cwd=temporary, env=environment,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                timeout=45, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout[-20000:])
            self.assertTrue(output.is_file(), completed.stdout[-20000:])
            report = json.loads(output.read_bytes())
        self.assertEqual(report["schema"], "hepta.cpu-cancel.coordinator-local-regressions.v1")
        self.assertEqual((report["state"], report["passed"], report["total"]), ("PASS", 25, 25))
        self.assertIs(report["authority_frozen"], False)
        self.assertIs(report["physical_case_pass"], False)
        self.assertEqual(report["phone_calls"], 0)
        self.assertEqual(report["native_cases_run"], 0)
        self.assertEqual(report["host_isolated_acceptance_case_credit"], 0)
        self.assertTrue(all(row["passed"] for row in report["tests"]))
        for path, raw in before.items():
            self.assertEqual((CANDIDATE / path).read_bytes(), raw, path)
        self.assertEqual((CANDIDATE / "SOURCE-SEAL.json").read_bytes(), seal_raw)


if __name__ == "__main__":
    unittest.main()
