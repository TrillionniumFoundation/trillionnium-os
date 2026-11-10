"""Compile actual rejected-action branch bodies with deterministic IO boundaries."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class StaleObservationJournalTest(unittest.TestCase):
    def test_real_rejected_branches_record_only_returned_observations(self):
        root = Path(__file__).resolve().parents[1]
        source = Path(os.environ.get("HEPTA_STALE_JOURNAL_SOURCE", str(root)))
        helper = root / "tests/stale-observation-journal/prepare_fixture.py"
        spec = importlib.util.spec_from_file_location("hepta_stale_observation_fixture", helper)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        java = os.environ.get("HEPTA_TEST_JAVA") or shutil.which("java")
        self.assertIsNotNone(java, "Existing Java required; no installation attempted")
        javac = os.environ.get("HEPTA_TEST_JAVAC") or shutil.which("javac")
        compiler = [javac] if javac else [java, "-m", "jdk.compiler/com.sun.tools.javac.Main"]
        with tempfile.TemporaryDirectory(prefix="hepta-stale-journal-") as temporary:
            output = Path(temporary)
            classes = output / "classes"
            classes.mkdir()
            fixture, record = module.prepare(source, output / "fixture")
            test = root / "tests/stale-observation-journal/StaleObservationJournalHostTest.java"
            print(json.dumps(record, sort_keys=True))
            compiled = subprocess.run(compiler + ["--release", "8", "-encoding", "UTF-8", "-Xlint:all", "-Werror",
                                                 "-d", str(classes), str(fixture), str(test)],
                                      capture_output=True, text=True, timeout=45)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([java, "-cp", str(classes), "org.trillionnium.hepta.local.StaleObservationJournalHostTest"],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("PASS cases=15 ", result.stdout)
            print(result.stdout, end="")


if __name__ == "__main__":
    unittest.main()
