"""Check the fixed recipe data path before any reviewed runtime source executes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = ROOT / "projects/razr60/phone-local-v150/operators/r10-external-source-recipe-r1/candidate"


class Razr60ExternalSourceRecipe(unittest.TestCase):
    def test_complete_consumer_recipe_regressions(self):
        runner = CANDIDATE / "tests/run_regressions.py"
        self.assertTrue(runner.is_file())
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        with tempfile.TemporaryDirectory(prefix="razr60-external-recipe-") as temporary:
            output = Path(temporary) / "report.json"
            completed = subprocess.run(
                [sys.executable, "-B", str(runner), "--output", str(output)],
                cwd=temporary, env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, timeout=45, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout[-20000:])
            self.assertTrue(output.is_file(), completed.stdout[-20000:])
            report = json.loads(output.read_text())
        self.assertEqual(report["schema"], "hepta.external-recipe-local-regressions.v1")
        self.assertEqual((report["state"], report["passed"], report["failed"]), ("PASS", 19, 0))
        self.assertEqual((report["fixture_runtime_members"], report["fixture_shared_members"]), (32, 17))
        self.assertEqual(report["phone_calls"], 0)
        self.assertEqual(report["runtime_or_provider_source_executions"], 0)
        self.assertEqual(report["case_credit"], 0)
        self.assertIs(report["candidate_unchanged"], True)
        self.assertIs(report["ready_claim"], False)


if __name__ == "__main__":
    unittest.main()
