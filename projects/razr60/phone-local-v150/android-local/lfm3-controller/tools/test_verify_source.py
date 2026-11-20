"""Nested provenance manifests are payloads of the outer source closure."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from verify_source import verify


class SourceProvenanceTests(unittest.TestCase):
    def fixture(self, root):
        path = root / "provenance/runtime/SOURCE-MANIFEST.json"
        path.parent.mkdir(parents=True)
        data = b'{"explicit":"host-only provenance fixture"}\n'
        path.write_bytes(data)
        (root / "SOURCE-MANIFEST.json").write_text(json.dumps({
            "schema": "hepta.local-source.v3", "files": [{
                "path": str(path.relative_to(root)), "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest()}]}))
        return path

    def test_nested_manifest_is_verified_as_regular_source_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            self.assertEqual(verify(root)["members"], 1)

    def test_changed_nested_manifest_cannot_avoid_hash_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root).write_text("changed provenance")
            with self.assertRaisesRegex(RuntimeError, "identity mismatch"):
                verify(root)

    def test_unlisted_nested_manifest_is_not_silently_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            (root / "extra/SOURCE-MANIFEST.json").parent.mkdir()
            (root / "extra/SOURCE-MANIFEST.json").write_text("{}")
            with self.assertRaisesRegex(RuntimeError, "unlisted or missing"):
                verify(root)


if __name__ == "__main__":
    unittest.main()
