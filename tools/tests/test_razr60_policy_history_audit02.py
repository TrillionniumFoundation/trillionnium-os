"""Exercise fixed audit preparation and create-only staging in ordinary G1."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = ROOT / "projects/razr60/phone-local-v150/operators/r10-policy-history-audit02-r1"


class Razr60PolicyHistoryAudit02(unittest.TestCase):
    def run_report(self, relative, schema, expected_count):
        runner = CANDIDATE / relative
        self.assertTrue(runner.is_file(), "the pinned local regression entry point is required")
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        with tempfile.TemporaryDirectory(prefix="razr60-audit02-") as temporary:
            output = Path(temporary) / "report.json"
            completed = subprocess.run(
                [sys.executable, "-B", str(runner), "--output", str(output)],
                cwd=temporary, env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, timeout=60, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout[-20000:])
            self.assertTrue(output.is_file(), completed.stdout[-20000:])
            report = json.loads(output.read_text())
        self.assertEqual(report["schema"], schema)
        self.assertEqual((report["status"], report["passed"], report["failed"]),
                         ("PASS", expected_count, 0))
        self.assertEqual(report["phone_calls"], 0)
        self.assertEqual(report["mac_jobs_started"], 0)
        self.assertIs(report["remote_staging_performed"], False)
        return report

    def test_prepared_auditor_and_source_cascade(self):
        report = self.run_report(
            "preparation/tests/verify_preparation.py",
            "hepta.policy-history-audit02-preparation-regressions.v1", 24,
        )
        self.assertIs(report["source_bytes_unchanged"], True)
        self.assertIs(report["real_prepared_auditor_class_exercised"], True)
        self.assertIs(report["historical_verifier_called"], False)
        self.assertIs(report["production_main_called"], False)

    def test_stager_including_interrupted_fd_ownership(self):
        report = self.run_report(
            "staging/tests/run_regressions.py",
            "hepta.create-only-source-stager.local-regressions.v1", 25,
        )
        self.assertIs(report["source_unchanged"], True)
        self.assertIs(report["complete_source_imported"], True)
        self.assertIs(report["actual_pinned_payload_verified"], True)
        self.assertIs(report["production_mac_main_called"], False)


if __name__ == "__main__":
    unittest.main()
