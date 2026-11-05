"""Run the current RAZR60 parser/capacity regressions in an isolated process.

G1's normal tools/tests discovery includes this module. The subprocess imports
the complete pinned candidate and writes its evidence only below a temporary
directory, keeping the checked-out source tree clean.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = ROOT / "projects/razr60/phone-local-v150/provider/r10-native-result-capacity-r1"


class Razr60NativeResultCapacity(unittest.TestCase):
    def test_pinned_candidate_regressions(self):
        runner = CANDIDATE / "tests/run_regressions.py"
        self.assertTrue(runner.is_file(), "the RAZR60 regression entry point is required")
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        with tempfile.TemporaryDirectory(prefix="razr60-native-capacity-") as temporary:
            result = subprocess.run(
                [sys.executable, "-B", str(runner), "--output", str(Path(temporary) / "report.json")],
                cwd=temporary,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=120,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout[-20000:])
            self.assertTrue((Path(temporary) / "report.json").is_file(), result.stdout[-20000:])
            report = json.loads((Path(temporary) / "report.json").read_text())
            self.assertEqual(report["schema"], "hepta.native-result-capacity.regression.v1")
            self.assertEqual((report["status"], report["passed"], report["failed"]), ("PASS", 5, 0))
            self.assertIs(report["source_unchanged"], True)
            self.assertIs(report["strict_native_pipeline_audit_passed"], True)
            self.assertEqual(report["phone_calls"], 0)
            self.assertIs(report["fixed19_qualification"], False)


if __name__ == "__main__":
    unittest.main()
