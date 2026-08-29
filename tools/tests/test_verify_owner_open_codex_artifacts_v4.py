from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from tools.tests import test_verify_owner_open_codex_artifacts as base_suite
from tools.tests import test_verify_owner_open_codex_artifacts_v2 as v2_suite

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-codex-artifacts-v4.py"
spec = importlib.util.spec_from_file_location("verify_owner_open_codex_artifacts_v4", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


class LegacyCosignFixture:
    def __init__(self, root: Path) -> None:
        self.fixture = v2_suite.PackageChecksumFixture(root)
        self.root = root
        self.contract_path = self.fixture.contract_path
        self.assets_json = self.fixture.assets_json
        self.rewrite_all()

    def contract(self) -> dict:
        return json.loads(self.contract_path.read_text(encoding="utf-8"))

    def write_contract(self, value: dict) -> None:
        self.contract_path.write_text(
            json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )

    def archive(self, role: str) -> dict:
        return next(item for item in self.contract()["archives"] if item["role"] == role)

    def archive_member_sha256(self, role: str) -> str:
        archive = self.archive(role)
        path = self.fixture.base.assets / archive["filename"]
        with tarfile.open(path, "r:gz") as handle:
            members = [member for member in handle.getmembers() if member.isfile()]
            if len(members) != 1:
                raise AssertionError(f"fixture archive member count: {len(members)}")
            source = handle.extractfile(members[0])
            if source is None:
                raise AssertionError("fixture archive member cannot be read")
            digest = hashlib.sha256()
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    def rewrite_all(self) -> None:
        contract = self.contract()
        metadata = json.loads(self.assets_json.read_text(encoding="utf-8"))
        metadata_by_name = {item["name"]: item for item in metadata}
        for index, archive in enumerate(contract["archives"]):
            signature = bytes([0x41 + index]) * 72
            certificate = (
                "-----BEGIN CERTIFICATE-----\n"
                f"fixture-certificate-{index}\n"
                "-----END CERTIFICATE-----\n"
            ).encode("utf-8")
            body = {
                "apiVersion": "0.0.1",
                "kind": "hashedrekord",
                "spec": {
                    "data": {
                        "hash": {
                            "algorithm": "sha256",
                            "value": archive["sha256"],
                        }
                    },
                    "signature": {
                        "content": b64(signature),
                        "publicKey": {"content": b64(certificate)},
                    },
                },
            }
            bundle = {
                "base64Signature": b64(signature),
                "cert": certificate.decode("utf-8"),
                "rekorBundle": {
                    "Payload": {
                        "body": b64(
                            json.dumps(
                                body,
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8")
                        ),
                        "integratedTime": 1700000000 + index,
                        "logID": f"{index + 1:064x}",
                        "logIndex": index,
                    },
                    "SignedEntryTimestamp": b64(bytes([0x51 + index]) * 72),
                },
            }
            filename = archive["sigstore"]["filename"]
            path = self.fixture.base.assets / filename
            path.write_text(json.dumps(bundle, sort_keys=True), encoding="utf-8")
            archive["sigstore"]["bytes"] = path.stat().st_size
            archive["sigstore"]["sha256"] = base_suite.sha(path)
            metadata_by_name[filename]["size"] = path.stat().st_size
            metadata_by_name[filename]["digest"] = f"sha256:{base_suite.sha(path)}"
        self.write_contract(contract)
        self.assets_json.write_text(
            json.dumps(metadata, sort_keys=True), encoding="utf-8"
        )

    def mutate_bundle(self, role: str, mutator) -> None:
        contract = self.contract()
        metadata = json.loads(self.assets_json.read_text(encoding="utf-8"))
        metadata_by_name = {item["name"]: item for item in metadata}
        archive = next(item for item in contract["archives"] if item["role"] == role)
        filename = archive["sigstore"]["filename"]
        path = self.fixture.base.assets / filename
        value = json.loads(path.read_text(encoding="utf-8"))
        mutator(value)
        path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
        archive["sigstore"]["bytes"] = path.stat().st_size
        archive["sigstore"]["sha256"] = base_suite.sha(path)
        metadata_by_name[filename]["size"] = path.stat().st_size
        metadata_by_name[filename]["digest"] = f"sha256:{base_suite.sha(path)}"
        self.write_contract(contract)
        self.assets_json.write_text(
            json.dumps(metadata, sort_keys=True), encoding="utf-8"
        )

    def set_rekor_digest(self, role: str, digest: str) -> None:
        def mutate(value):
            payload = value["rekorBundle"]["Payload"]
            body = json.loads(base64.b64decode(payload["body"], validate=True))
            body["spec"]["data"]["hash"]["value"] = digest
            payload["body"] = b64(
                json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            )

        self.mutate_bundle(role, mutate)

    def verify(self):
        return module.verify(
            self.root,
            asset_dir=self.fixture.base.assets,
            release_json=self.fixture.base.release_json,
            release_asset_json=[self.assets_json],
            probe=False,
        )


class VerifyOwnerOpenCodexArtifactsV4Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.legacy = LegacyCosignFixture(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_complete_legacy_cosign_release_passes_structural_cross_binding(self) -> None:
        report = self.legacy.verify()
        self.assertEqual(report.errors, [])
        self.assertTrue(report.ok)
        self.assertTrue(report.facts["artifact_bytes_verified"])
        self.assertTrue(report.facts["package_checksum_list_cross_check_passed"])
        self.assertFalse(report.facts["cryptographic_sigstore_verification"])
        contract = self.legacy.contract()
        for archive in contract["archives"]:
            facts = module.verify_sigstore_bundle_v4(
                self.legacy.fixture.base.assets / archive["sigstore"]["filename"],
                archive["sigstore"],
                archive["sha256"],
            )
            self.assertEqual(facts["bundle_encoding"], "cosign_legacy_sign_blob_bundle")
            self.assertTrue(facts["archive_digest_bound"])
            self.assertFalse(facts["archive_member_digest_bound"])
            self.assertEqual(facts["signed_subject_kind"], "release_archive")
            self.assertTrue(facts["signature_bytes_cross_bound"])
            self.assertTrue(facts["certificate_bytes_cross_bound"])
            self.assertFalse(facts["cryptographic_signature_verified"])
            self.assertFalse(facts["cryptographic_rekor_set_verified"])

    def test_rekor_unique_archive_member_digest_binding_passes(self) -> None:
        role = "qualification_host_codex"
        member_digest = self.legacy.archive_member_sha256(role)
        self.legacy.set_rekor_digest(role, member_digest)
        report = self.legacy.verify()
        self.assertEqual(report.errors, [])
        self.assertTrue(report.ok)
        archive = self.legacy.archive(role)
        facts = module.verify_sigstore_bundle_v4(
            self.legacy.fixture.base.assets / archive["sigstore"]["filename"],
            archive["sigstore"],
            archive["sha256"],
            member_digest,
        )
        self.assertFalse(facts["archive_digest_bound"])
        self.assertTrue(facts["archive_member_digest_bound"])
        self.assertTrue(facts["signed_subject_digest_bound"])
        self.assertEqual(facts["signed_subject_kind"], "unique_archive_member")
        self.assertEqual(facts["signed_subject_sha256"], member_digest)

    def test_rekor_archive_digest_drift_fails_closed(self) -> None:
        self.legacy.set_rekor_digest("target_root_linux_codex", "0" * 64)
        report = self.legacy.verify()
        self.assertTrue(
            any("not bound to the selected archive digest" in error for error in report.errors),
            report.errors,
        )

    def test_signature_cross_splice_fails_closed(self) -> None:
        self.legacy.mutate_bundle(
            "qualification_host_codex",
            lambda value: value.__setitem__("base64Signature", b64(b"Z" * 72)),
        )
        report = self.legacy.verify()
        self.assertTrue(
            any("signature differs" in error for error in report.errors),
            report.errors,
        )

    def test_certificate_cross_splice_fails_closed(self) -> None:
        self.legacy.mutate_bundle(
            "qualification_host_codex",
            lambda value: value.__setitem__(
                "cert",
                "-----BEGIN CERTIFICATE-----\nother\n-----END CERTIFICATE-----\n",
            ),
        )
        report = self.legacy.verify()
        self.assertTrue(
            any("public key differs" in error for error in report.errors),
            report.errors,
        )

    def test_missing_signed_entry_timestamp_fails_closed(self) -> None:
        self.legacy.mutate_bundle(
            "target_root_linux_codex",
            lambda value: value["rekorBundle"].pop("SignedEntryTimestamp"),
        )
        report = self.legacy.verify()
        self.assertTrue(
            any("rekorBundle keys differ" in error for error in report.errors),
            report.errors,
        )

    def test_modern_bundle_fixture_remains_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = v2_suite.PackageChecksumFixture(root)
            report = module.verify(
                root,
                asset_dir=fixture.base.assets,
                release_json=fixture.base.release_json,
                release_asset_json=[fixture.assets_json],
                probe=False,
            )
            self.assertEqual(report.errors, [])
            self.assertTrue(report.ok)


if __name__ == "__main__":
    unittest.main()
