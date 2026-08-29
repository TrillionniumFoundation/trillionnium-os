from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from tools.tests import test_verify_owner_open_codex_artifacts as base_suite
from tools.tests import test_verify_owner_open_codex_artifacts_v2 as v2_suite

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-codex-artifacts-v3.py"
spec = importlib.util.spec_from_file_location("verify_owner_open_codex_artifacts_v3", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class VerifyOwnerOpenCodexArtifactsV3Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fixture = v2_suite.PackageChecksumFixture(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def rewrite_sigstores(self, transform) -> None:
        contract = self.fixture.contract()
        metadata = json.loads(self.fixture.assets_json.read_text(encoding="utf-8"))
        metadata_by_name = {item["name"]: item for item in metadata}
        for archive in contract["archives"]:
            filename = archive["sigstore"]["filename"]
            path = self.fixture.base.assets / filename
            value = json.loads(path.read_text(encoding="utf-8"))
            transform(value)
            path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
            archive["sigstore"]["bytes"] = path.stat().st_size
            archive["sigstore"]["sha256"] = base_suite.sha(path)
            metadata_by_name[filename]["size"] = path.stat().st_size
            metadata_by_name[filename]["digest"] = f"sha256:{base_suite.sha(path)}"
        self.fixture.write_contract(contract)
        self.fixture.assets_json.write_text(
            json.dumps(metadata, sort_keys=True), encoding="utf-8"
        )

    def verify(self):
        return module.verify(
            self.root,
            asset_dir=self.fixture.base.assets,
            release_json=self.fixture.base.release_json,
            release_asset_json=[self.fixture.assets_json],
            probe=False,
        )

    def test_legacy_bundle_without_media_type_retains_digest_binding(self) -> None:
        self.rewrite_sigstores(lambda value: value.pop("mediaType", None))
        report = self.verify()
        self.assertEqual(report.errors, [])
        self.assertTrue(report.ok)
        self.assertTrue(report.facts["artifact_bytes_verified"])
        self.assertFalse(report.facts["cryptographic_sigstore_verification"])
        for archive in report.facts["archives"]:
            self.assertFalse(archive["sigstore"]["media_type_declared"])
            self.assertTrue(archive["sigstore"]["archive_digest_bound"])

    def test_missing_message_signature_is_not_accepted_as_legacy_shape(self) -> None:
        def transform(value):
            value.pop("mediaType", None)
            value.pop("messageSignature", None)

        self.rewrite_sigstores(transform)
        report = self.verify()
        self.assertFalse(report.ok)
        self.assertTrue(
            any("messageSignature" in error for error in report.errors),
            report.errors,
        )

    def test_declared_unsupported_media_type_fails_closed(self) -> None:
        self.rewrite_sigstores(lambda value: value.__setitem__("mediaType", "text/plain"))
        report = self.verify()
        self.assertFalse(report.ok)
        self.assertTrue(
            any("media type is unsupported" in error for error in report.errors),
            report.errors,
        )


if __name__ == "__main__":
    unittest.main()
