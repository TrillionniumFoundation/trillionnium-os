from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from tools.tests import test_verify_owner_open_codex_artifacts as base_suite

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-codex-artifacts-v2.py"
spec = importlib.util.spec_from_file_location("verify_owner_open_codex_artifacts_v2", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class PackageChecksumFixture:
    def __init__(self, root: Path) -> None:
        self.base = base_suite.CodexArtifactFixture(root)
        self.root = root
        self.contract_path = root / module.CONTRACT
        self.assets_json = self.base.release_assets_json
        contract = json.loads(self.contract_path.read_text(encoding="utf-8"))
        metadata = json.loads(self.assets_json.read_text(encoding="utf-8"))
        bindings: list[dict] = []
        checksum_lines: list[str] = []
        next_id = max(int(item["id"]) for item in metadata) + 1
        for archive in contract["archives"]:
            package_name = f"codex-package-{archive['architecture']}.tar.gz"
            package_bytes = (
                f"aggregate-package-fixture:{archive['role']}:{archive['filename']}"
            ).encode("utf-8")
            package_sha = sha_bytes(package_bytes)
            package_url = (
                f"https://github.com/openai/codex/releases/download/{base_suite.TAG}/"
                f"{package_name}"
            )
            bindings.append(
                {
                    "role": archive["role"],
                    "archive_filename": archive["filename"],
                    "checksum_filename": package_name,
                    "url": package_url,
                    "bytes": len(package_bytes),
                    "sha256": package_sha,
                }
            )
            checksum_lines.append(f"{package_sha}  {package_name}\n")
            metadata.append(
                {
                    "id": next_id,
                    "name": package_name,
                    "state": "uploaded",
                    "size": len(package_bytes),
                    "digest": f"sha256:{package_sha}",
                    "browser_download_url": package_url,
                }
            )
            next_id += 1
        checksum_path = self.base.assets / "codex-package_SHA256SUMS"
        checksum_path.write_text("".join(checksum_lines), encoding="utf-8")
        contract["checksum_list"]["bytes"] = checksum_path.stat().st_size
        contract["checksum_list"]["sha256"] = base_suite.sha(checksum_path)
        contract["checksum_bindings"] = bindings
        for item in metadata:
            if item["name"] == checksum_path.name:
                item["size"] = checksum_path.stat().st_size
                item["digest"] = f"sha256:{base_suite.sha(checksum_path)}"
        self.contract_path.write_text(
            json.dumps(contract, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        self.assets_json.write_text(
            json.dumps(metadata, sort_keys=True), encoding="utf-8"
        )

    def contract(self) -> dict:
        return json.loads(self.contract_path.read_text(encoding="utf-8"))

    def write_contract(self, value: dict) -> None:
        self.contract_path.write_text(
            json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )

    def verify(self):
        return module.verify(
            self.root,
            asset_dir=self.base.assets,
            release_json=self.base.release_json,
            release_asset_json=[self.assets_json],
            probe=False,
        )


class VerifyOwnerOpenCodexArtifactsV2Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fixture = PackageChecksumFixture(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_source_contract_explicitly_binds_package_and_execution_assets(self) -> None:
        report = module.verify(self.root)
        self.assertEqual(report.errors, [])
        self.assertTrue(report.facts["package_checksum_binding_contract_valid"])
        self.assertFalse(report.facts["package_checksum_list_cross_check_passed"])
        self.assertFalse(report.facts["artifact_bytes_verified"])

    def test_complete_synthetic_release_passes_dual_binding(self) -> None:
        report = self.fixture.verify()
        self.assertEqual(report.errors, [])
        self.assertTrue(report.facts["artifact_bytes_verified"])
        self.assertTrue(report.facts["package_checksum_list_cross_check_passed"])
        self.assertTrue(report.facts["package_release_metadata_cross_check_passed"])
        self.assertTrue(
            report.facts["release_metadata"]["package_checksum_metadata_match"]
        )

    def test_bare_archive_checksum_line_cannot_substitute_for_package_binding(self) -> None:
        contract = self.fixture.contract()
        checksum_path = self.fixture.base.assets / "codex-package_SHA256SUMS"
        checksum_path.write_text(
            "".join(
                f"{item['sha256']}  {item['filename']}\n"
                for item in contract["archives"]
            ),
            encoding="utf-8",
        )
        contract["checksum_list"]["bytes"] = checksum_path.stat().st_size
        contract["checksum_list"]["sha256"] = base_suite.sha(checksum_path)
        self.fixture.write_contract(contract)
        metadata = json.loads(self.fixture.assets_json.read_text(encoding="utf-8"))
        for item in metadata:
            if item["name"] == checksum_path.name:
                item["size"] = checksum_path.stat().st_size
                item["digest"] = f"sha256:{base_suite.sha(checksum_path)}"
        self.fixture.assets_json.write_text(
            json.dumps(metadata, sort_keys=True), encoding="utf-8"
        )
        report = self.fixture.verify()
        self.assertTrue(
            any("package archive digest" in error for error in report.errors),
            report.errors,
        )

    def test_package_release_digest_drift_is_rejected(self) -> None:
        contract = self.fixture.contract()
        package_name = contract["checksum_bindings"][0]["checksum_filename"]
        metadata = json.loads(self.fixture.assets_json.read_text(encoding="utf-8"))
        for item in metadata:
            if item["name"] == package_name:
                item["digest"] = "sha256:" + "0" * 64
        self.fixture.assets_json.write_text(
            json.dumps(metadata, sort_keys=True), encoding="utf-8"
        )
        report = self.fixture.verify()
        self.assertTrue(
            any("package checksum asset digest drifted" in error for error in report.errors),
            report.errors,
        )

    def test_binding_cannot_cross_splice_archive_roles(self) -> None:
        contract = self.fixture.contract()
        contract["checksum_bindings"][0]["archive_filename"] = contract["archives"][1][
            "filename"
        ]
        self.fixture.write_contract(contract)
        report = module.verify(self.root)
        self.assertTrue(
            any("archive filename differs" in error for error in report.errors),
            report.errors,
        )


if __name__ == "__main__":
    unittest.main()
