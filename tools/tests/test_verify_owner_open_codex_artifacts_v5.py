from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from tools.tests import test_verify_owner_open_codex_artifacts as base_suite
from tools.tests import test_verify_owner_open_codex_artifacts_v4 as v4_suite

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-codex-artifacts-v5.py"
spec = importlib.util.spec_from_file_location("verify_owner_open_codex_artifacts_v5", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


class VerifyOwnerOpenCodexArtifactsV5Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.legacy = v4_suite.LegacyCosignFixture(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def verify(self):
        return module.verify(
            self.root,
            asset_dir=self.legacy.fixture.base.assets,
            release_json=self.legacy.fixture.base.release_json,
            release_asset_json=[self.legacy.assets_json],
            probe=False,
        )

    def test_canonical_base64_pem_certificate_passes_cross_binding(self) -> None:
        contract = self.legacy.contract()
        for archive in contract["archives"]:
            role = archive["role"]
            self.legacy.mutate_bundle(
                role,
                lambda value: value.__setitem__(
                    "cert", b64(value["cert"].encode("utf-8"))
                ),
            )
        report = self.verify()
        self.assertEqual(report.errors, [])
        self.assertTrue(report.ok)
        contract = self.legacy.contract()
        for archive in contract["archives"]:
            facts = module.V4.verify_sigstore_bundle_v4(
                self.legacy.fixture.base.assets / archive["sigstore"]["filename"],
                archive["sigstore"],
                archive["sha256"],
            )
            self.assertTrue(facts["certificate_bytes_cross_bound"])

    def test_pem_text_remains_supported(self) -> None:
        report = self.verify()
        self.assertEqual(report.errors, [])
        self.assertTrue(report.ok)

    def test_base64_noncertificate_bytes_fail_closed(self) -> None:
        self.legacy.mutate_bundle(
            "target_root_linux_codex",
            lambda value: value.__setitem__("cert", b64(b"not-a-certificate" * 8)),
        )
        report = self.verify()
        self.assertFalse(report.ok)
        self.assertTrue(
            any("neither PEM text nor canonical base64 certificate" in error for error in report.errors),
            report.errors,
        )

    def test_base64_certificate_still_cannot_cross_splice_rekor_public_key(self) -> None:
        def mutate(value):
            value["cert"] = b64(value["cert"].encode("utf-8"))
            payload = value["rekorBundle"]["Payload"]
            body = json.loads(base64.b64decode(payload["body"], validate=True))
            body["spec"]["signature"]["publicKey"]["content"] = b64(b"X" * 96)
            payload["body"] = b64(
                json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            )

        self.legacy.mutate_bundle("qualification_host_codex", mutate)
        report = self.verify()
        self.assertFalse(report.ok)
        self.assertTrue(
            any("public key differs" in error for error in report.errors),
            report.errors,
        )


if __name__ == "__main__":
    unittest.main()
