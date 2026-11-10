"""Strict Java8 compilation of actual prompt/answer/receipt code; host IO fixtures only."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

class AppLabelControllerTest(unittest.TestCase):
    def test_actual_prompt_answer_receipt_and_host_consumer(self):
        root = Path(__file__).resolve().parents[1]
        helper = root / "tests/app-label/prepare_fixture.py"
        spec = importlib.util.spec_from_file_location("app_label_controller_fixture", helper)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        java = os.environ.get("HEPTA_TEST_JAVA") or shutil.which("java")
        self.assertIsNotNone(java)
        javac = os.environ.get("HEPTA_TEST_JAVAC") or shutil.which("javac")
        compiler = [javac] if javac else [java, "-m", "jdk.compiler/com.sun.tools.javac.Main"]
        with tempfile.TemporaryDirectory(prefix="hepta-app-label-") as temporary:
            out = Path(temporary); classes = out / "classes"; classes.mkdir()
            sources, record = module.prepare(root, out / "fixture")
            sources += sorted((root / "tests/exact-admission/org").rglob("*.java"))
            sources += sorted((root / "tests/exact-admission/android").rglob("*.java"))
            sources.append(root / "tests/app-label/AppLabelControllerHostTest.java")
            compiled = subprocess.run(compiler + ["--release", "8", "-encoding", "UTF-8", "-Xlint:all", "-Werror", "-d", str(classes)] + [str(p) for p in sources], capture_output=True, text=True, timeout=45)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            artifacts = out / "artifacts"
            run = subprocess.run([java, "-cp", str(classes), "org.trillionnium.hepta.local.AppLabelControllerHostTest", str(artifacts)], capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            import phone_acceptance as a
            import phone_suite as suite
            prompt = (artifacts / "prompt.txt").read_bytes(); grammar = (artifacts / "grammar.gbnf").read_bytes()
            raw = (artifacts / "raw.json").read_bytes(); receipt = json.loads((artifacts / "app-receipt-fragment.json").read_bytes())
            receipt["prompt_sha256"] = a.digest(prompt)
            native = {"input_sha256": {"prompt": a.digest(prompt), "grammar": a.digest(grammar)}}
            observation, package = receipt["grammar_observation_id"], receipt["grammar_current_package"]
            self.assertTrue(a.controller_grammar_binding_valid(receipt, native, grammar, {observation: {package}}, prompt, raw))
            self.assertEqual(suite._action_identity(json.loads(raw)), suite._action_identity(json.loads((artifacts / "action.json").read_bytes())))
            print(json.dumps(record, sort_keys=True)); print(run.stdout, end="")

if __name__ == "__main__":
    unittest.main(verbosity=2)
