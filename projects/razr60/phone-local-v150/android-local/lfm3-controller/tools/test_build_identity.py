"""Host regressions for source binding of cached Android build outputs."""
from pathlib import Path
import tempfile
import unittest
from build_identity import source_inputs, verify_source_inputs


class BuildIdentityTests(unittest.TestCase):
    def source(self, root):
        for name in ("AndroidManifest.xml", "build_mac.py", "assemble_pocket4.py", "tools/build_identity.py",
                     "tools/verify_runtime.py", "tools/fetch_pinned_runtime.py", "tools/model_profiles.py", "tools/verify_mobimind_runtime.py",
                     "provenance/mobimind-worker-r4-build.json", "provenance/mobimind-worker-r4/SOURCE-MANIFEST.json",
                     "src/example/Controller.java", "native/publish-appuid.inc", "native/worker.c", "res/values/strings.xml"):
            path = root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture: " + name)

    def test_matching_inputs_are_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.source(root)
            verify_source_inputs(root, {"source_inputs":source_inputs(root)})

    def test_mutated_codegen_include_rejects_cached_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.source(root)
            receipt = {"source_inputs":source_inputs(root)}
            (root/"native/publish-appuid.inc").write_text("changed publication code")
            with self.assertRaises(RuntimeError): verify_source_inputs(root, receipt)

    def test_added_java_source_rejects_cached_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.source(root)
            receipt = {"source_inputs":source_inputs(root)}
            (root/"src/example/NewAction.java").write_text("new action")
            with self.assertRaises(RuntimeError): verify_source_inputs(root, receipt)

    def test_manifest_change_rejects_cached_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.source(root)
            receipt = {"source_inputs":source_inputs(root)}
            (root/"AndroidManifest.xml").write_text("different version")
            with self.assertRaises(RuntimeError): verify_source_inputs(root, receipt)

    def test_legacy_receipt_without_inputs_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.source(root)
            with self.assertRaises(RuntimeError): verify_source_inputs(root, {})

    def test_separate_runtime_verifier_change_rejects_cached_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.source(root)
            receipt = {"source_inputs":source_inputs(root)}
            (root/"tools/verify_mobimind_runtime.py").write_text("changed binary qualification")
            with self.assertRaises(RuntimeError): verify_source_inputs(root, receipt)


if __name__ == "__main__": unittest.main()
