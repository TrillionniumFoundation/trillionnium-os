"""Host regressions for source binding of cached Android build outputs."""
from pathlib import Path
import tempfile
import unittest
from build_identity import source_inputs, verify_source_inputs, build_configuration


class BuildIdentityTests(unittest.TestCase):
    def source(self, root):
        for name in ("AndroidManifest.xml", "build_mac.py", "assemble_pocket4.py", "tools/build_identity.py",
                     "tools/verify_runtime.py", "tools/fetch_pinned_runtime.py", "tools/model_profiles.py", "tools/verify_mobimind_runtime.py", "tools/verify_ui_venus_runtime.py",
                     "provenance/mobimind-worker-r4-build.json", "provenance/mobimind-worker-r4/SOURCE-MANIFEST.json",
                     "src/example/Controller.java", "native/publish-appuid.inc", "native/worker.c", "res/values/strings.xml"):
            path = root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture: " + name)
        (root/"AndroidManifest.xml").write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="66"><application android:debuggable="false"/></manifest>')

    def receipt(self, root):
        return {"source_inputs":source_inputs(root), "build_configuration":build_configuration(root,"release")}

    def test_matching_inputs_are_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.source(root)
            verify_source_inputs(root, self.receipt(root))

    def test_mutated_codegen_include_rejects_cached_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.source(root)
            receipt = self.receipt(root)
            (root/"native/publish-appuid.inc").write_text("changed publication code")
            with self.assertRaises(RuntimeError): verify_source_inputs(root, receipt)

    def test_added_java_source_rejects_cached_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.source(root)
            receipt = self.receipt(root)
            (root/"src/example/NewAction.java").write_text("new action")
            with self.assertRaises(RuntimeError): verify_source_inputs(root, receipt)

    def test_manifest_change_rejects_cached_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.source(root)
            receipt = self.receipt(root)
            (root/"AndroidManifest.xml").write_text("different version")
            with self.assertRaises(RuntimeError): verify_source_inputs(root, receipt)

    def test_legacy_receipt_without_inputs_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.source(root)
            with self.assertRaises(RuntimeError): verify_source_inputs(root, {})

    def test_separate_runtime_verifier_change_rejects_cached_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.source(root)
            receipt = self.receipt(root)
            (root/"tools/verify_mobimind_runtime.py").write_text("changed binary qualification")
            with self.assertRaises(RuntimeError): verify_source_inputs(root, receipt)

    def test_added_ui_venus_build_provenance_rejects_cached_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.source(root)
            receipt=self.receipt(root)
            target=root/"provenance/ui-venus-app-r1/NATIVE-BUILD-RECEIPT.json"
            target.parent.mkdir(parents=True);target.write_text('{"synthetic":true}')
            with self.assertRaises(RuntimeError):verify_source_inputs(root,receipt)


if __name__ == "__main__": unittest.main()
