"""Regression of actual controller/engine source; no phone/model/remote service."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class ExactAdmissionTest(unittest.TestCase):
    def test_full_prompt_admission_and_native_boundaries(self):
        root = Path(__file__).resolve().parents[1]
        source = Path(os.environ.get("HEPTA_ADMISSION_SOURCE", str(root)))
        helper = root / "tests/exact-admission/prepare_fixture.py"
        spec = importlib.util.spec_from_file_location("hepta_admission_fixture", helper)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        java = os.environ.get("HEPTA_TEST_JAVA") or shutil.which("java")
        self.assertIsNotNone(java, "Existing Java required; no installation attempted")
        javac = os.environ.get("HEPTA_TEST_JAVAC") or shutil.which("javac")
        compiler = [javac] if javac else [java, "-m", "jdk.compiler/com.sun.tools.javac.Main"]
        with tempfile.TemporaryDirectory(prefix="hepta-exact-admission-") as temporary:
            output = Path(temporary)
            classes = output / "classes"
            classes.mkdir()
            sources, record = module.prepare(source, output / "fixture")
            sources += sorted((root / "tests/exact-admission").rglob("*.java"))
            print(json.dumps(record, sort_keys=True))
            compiled = subprocess.run(compiler + ["--release", "8", "-encoding", "UTF-8", "-Xlint:all", "-Werror",
                                                 "-d", str(classes)] + [str(path) for path in sources],
                                      capture_output=True, text=True, timeout=45)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([java, "-cp", str(classes), "org.trillionnium.hepta.local.PromptAdmissionHostTest"],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("PASS cases=6 ", result.stdout)
            print(result.stdout, end="")


if __name__ == "__main__":
    unittest.main()
