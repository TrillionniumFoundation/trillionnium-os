"""Keep the owned audit-directory regression in ordinary G1 discovery."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = ROOT / "projects/razr60/phone-local-v150/operators/r10-owned-output-directory-r1"


class Razr60OwnedOutputDirectory(unittest.TestCase):
    def test_complete_auditor_owned_directory_regressions(self):
        runner = CANDIDATE / "tests/run_regressions.py"
        self.assertTrue(runner.is_file(), "the owned-directory regression entry point is required")
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        with tempfile.TemporaryDirectory(prefix="razr60-owned-directory-") as temporary:
            report_path = Path(temporary) / "report.json"
            completed = subprocess.run(
                [sys.executable, "-B", str(runner), "--output", str(report_path)],
                cwd=temporary,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout[-20000:])
            self.assertTrue(report_path.is_file(), completed.stdout[-20000:])
            report = json.loads(report_path.read_text())
            self.assertEqual(report["schema"], "hepta.owned-output-directory.guard-regression.v1")
            self.assertEqual((report["status"], report["passed"], report["failed"]), ("PASS", 17, 0))
            self.assertIs(report["source_unchanged"], True)
            self.assertIs(report["complete_auditor_imported"], True)
            self.assertIs(report["real_class_constructor_write_check_readback_exercised"], True)
            self.assertIs(report["production_main_called"], False)
            self.assertIs(report["historical_verifier_called"], False)
            self.assertIs(report["historical_output_modified"], False)
            self.assertEqual(report["phone_calls"], 0)


if __name__ == "__main__":
    unittest.main()
