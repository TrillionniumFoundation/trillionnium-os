from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-codex-artifacts.py"
spec = importlib.util.spec_from_file_location("verify_owner_open_codex_artifacts", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

TAG = "rust-v9.8.7"
VERSION = "9.8.7"
PUBLISHED = "2026-08-29T00:00:00Z"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def minimal_elf(machine: int) -> bytes:
    ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    fields = struct.pack(
        "<HHIQQQIHHHHHH",
        3,
        machine,
        1,
        0,
        0,
        0,
        0,
        64,
        0,
        0,
        0,
        0,
        0,
    )
    return ident + fields + b"fixture-codex"


class CodexArtifactFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.assets = root / "assets"
        self.assets.mkdir(parents=True)
        (root / module.CONTRACT).parent.mkdir(parents=True)
        self.entries = [
            {
                "role": "target_root_linux_codex",
                "architecture": "aarch64-unknown-linux-musl",
                "machine": 183,
                "member": "codex-aarch64-unknown-linux-musl",
                "execute": False,
            },
            {
                "role": "qualification_host_codex",
                "architecture": "x86_64-unknown-linux-musl",
                "machine": 62,
                "member": "codex-x86_64-unknown-linux-musl",
                "execute": True,
            },
        ]
        self.release_json = root / "release.json"
        self.release_assets_json = root / "release-assets.json"
        for entry in self.entries:
            self.write_archive(entry)
        self.refresh_metadata()

    def archive_path(self, entry: dict) -> Path:
        return self.assets / f"{entry['member']}.tar.gz"

    def sigstore_path(self, entry: dict) -> Path:
        return self.assets / f"{entry['member']}.sigstore"

    def write_archive(
        self,
        entry: dict,
        *,
        member_name: str | None = None,
        machine: int | None = None,
        kind: str = "file",
        mode: int = 0o755,
    ) -> None:
        path = self.archive_path(entry)
        with tarfile.open(path, "w:gz") as archive:
            info = tarfile.TarInfo(member_name or entry["member"])
            info.mode = mode
            if kind == "file":
                payload = minimal_elf(machine if machine is not None else entry["machine"])
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "elsewhere"
                archive.addfile(info)
            else:
                raise AssertionError(kind)

    def refresh_metadata(self) -> None:
        archives: list[dict] = []
        asset_metadata: list[dict] = []
        checksum_lines: list[str] = []
        next_id = 10
        for entry in self.entries:
            archive_path = self.archive_path(entry)
            archive_sha = sha(archive_path)
            checksum_lines.append(f"{archive_sha}  {archive_path.name}\n")
            bundle = {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {"tlogEntries": [{"fixture": True}]},
                "messageSignature": {
                    "messageDigest": {
                        "algorithm": "SHA2_256",
                        "digest": base64.b64encode(bytes.fromhex(archive_sha)).decode(),
                    },
                    "signature": base64.b64encode(b"s" * 64).decode(),
                },
            }
            sigstore_path = self.sigstore_path(entry)
            sigstore_path.write_text(
                json.dumps(bundle, sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
            archive_url = (
                f"https://github.com/openai/codex/releases/download/{TAG}/"
                f"{archive_path.name}"
            )
            sigstore_url = (
                f"https://github.com/openai/codex/releases/download/{TAG}/"
                f"{sigstore_path.name}"
            )
            archives.append(
                {
                    "role": entry["role"],
                    "architecture": entry["architecture"],
                    "elf_machine": entry["machine"],
                    "filename": archive_path.name,
                    "archive_member": entry["member"],
                    "url": archive_url,
                    "bytes": archive_path.stat().st_size,
                    "sha256": archive_sha,
                    "sigstore": {
                        "filename": sigstore_path.name,
                        "url": sigstore_url,
                        "bytes": sigstore_path.stat().st_size,
                        "sha256": sha(sigstore_path),
                    },
                    "execute_on_github_host": entry["execute"],
                }
            )
            for name, path, url in (
                (archive_path.name, archive_path, archive_url),
                (sigstore_path.name, sigstore_path, sigstore_url),
            ):
                asset_metadata.append(
                    {
                        "id": next_id,
                        "name": name,
                        "state": "uploaded",
                        "size": path.stat().st_size,
                        "digest": f"sha256:{sha(path)}",
                        "browser_download_url": url,
                    }
                )
                next_id += 1
        checksum_path = self.assets / "codex-package_SHA256SUMS"
        checksum_path.write_text("".join(checksum_lines), encoding="utf-8")
        checksum_url = (
            f"https://github.com/openai/codex/releases/download/{TAG}/"
            "codex-package_SHA256SUMS"
        )
        asset_metadata.append(
            {
                "id": next_id,
                "name": checksum_path.name,
                "state": "uploaded",
                "size": checksum_path.stat().st_size,
                "digest": f"sha256:{sha(checksum_path)}",
                "browser_download_url": checksum_url,
            }
        )
        contract = {
            "schema": module.EXPECTED_SCHEMA,
            "revision": "fixture",
            "upstream": {
                "repository": module.OFFICIAL_REPOSITORY,
                "release_tag": TAG,
                "version": VERSION,
                "release_api": (
                    "https://api.github.com/repos/openai/codex/releases/tags/" + TAG
                ),
                "release_page": "https://github.com/openai/codex/releases/tag/" + TAG,
                "published_at": PUBLISHED,
            },
            "checksum_list": {
                "filename": checksum_path.name,
                "url": checksum_url,
                "bytes": checksum_path.stat().st_size,
                "sha256": sha(checksum_path),
            },
            "archives": archives,
            "verification": {
                "require_exact_release_tag": True,
                "require_github_asset_digest_match": True,
                "require_checksum_list_cross_check": True,
                "require_safe_single_file_archive": True,
                "require_exact_elf_machine": True,
                "require_sigstore_bundle_digest_binding": True,
                "cryptographic_sigstore_verification_required_for_release": True,
            },
            "claims": {
                "official_release_identity_bound": True,
                "artifact_bytes_present_in_repository": False,
                "target_root_linux_installed": False,
                "authenticated_codex_execution": False,
                "same_turn_mcp_qualification": False,
                "cryptographic_sigstore_verification": False,
                "public_release": False,
            },
            "claim_ceiling": (
                "OFFICIAL_RELEASE_ASSET_IDENTITY_AND_CHECKSUM_CONTRACT_ONLY"
            ),
        }
        (self.root / module.CONTRACT).write_text(
            json.dumps(contract, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        self.release_json.write_text(
            json.dumps(
                {
                    "id": 7,
                    "tag_name": TAG,
                    "published_at": PUBLISHED,
                    "draft": False,
                    "prerelease": False,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        self.release_assets_json.write_text(
            json.dumps(asset_metadata, sort_keys=True), encoding="utf-8"
        )

    def verify(self):
        return module.verify(
            self.root,
            asset_dir=self.assets,
            release_json=self.release_json,
            release_asset_json=[self.release_assets_json],
            probe=False,
        )


class VerifyOwnerOpenCodexArtifactsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fixture = CodexArtifactFixture(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_source_contract_passes_without_material(self) -> None:
        report = module.verify(self.root)
        self.assertEqual(report.errors, [])
        self.assertFalse(report.facts["artifact_bytes_verified"])
        self.assertTrue(report.warnings)

    def test_complete_synthetic_release_passes(self) -> None:
        report = self.fixture.verify()
        self.assertEqual(report.errors, [])
        self.assertTrue(report.facts["artifact_bytes_verified"])
        self.assertTrue(report.facts["release_metadata"]["github_asset_digest_match"])
        self.assertEqual(len(report.facts["artifacts"]), 2)
        self.assertTrue(
            all(item["sigstore"]["archive_digest_bound"] for item in report.facts["artifacts"])
        )

    def test_archive_hash_drift_is_rejected(self) -> None:
        path = self.fixture.archive_path(self.fixture.entries[0])
        path.write_bytes(path.read_bytes() + b"drift")
        report = self.fixture.verify()
        self.assertTrue(any("size mismatch" in error for error in report.errors))

    def test_path_traversal_member_is_rejected(self) -> None:
        entry = self.fixture.entries[0]
        self.fixture.write_archive(entry, member_name="../escape")
        self.fixture.refresh_metadata()
        report = self.fixture.verify()
        self.assertTrue(any("archive member" in error for error in report.errors))

    def test_symlink_member_is_rejected(self) -> None:
        entry = self.fixture.entries[0]
        self.fixture.write_archive(entry, kind="symlink")
        self.fixture.refresh_metadata()
        report = self.fixture.verify()
        self.assertTrue(any("link/device/special" in error for error in report.errors))

    def test_wrong_elf_machine_is_rejected(self) -> None:
        entry = self.fixture.entries[0]
        self.fixture.write_archive(entry, machine=62)
        self.fixture.refresh_metadata()
        report = self.fixture.verify()
        self.assertTrue(any("ELF machine mismatch" in error for error in report.errors))

    def test_non_executable_member_is_rejected(self) -> None:
        entry = self.fixture.entries[0]
        self.fixture.write_archive(entry, mode=0o644)
        self.fixture.refresh_metadata()
        report = self.fixture.verify()
        self.assertTrue(any("not executable" in error for error in report.errors))

    def test_sigstore_digest_not_bound_to_archive_is_rejected(self) -> None:
        path = self.fixture.sigstore_path(self.fixture.entries[0])
        bundle = json.loads(path.read_text(encoding="utf-8"))
        bundle["messageSignature"]["messageDigest"]["digest"] = base64.b64encode(
            b"x" * 32
        ).decode()
        path.write_text(json.dumps(bundle, sort_keys=True), encoding="utf-8")
        contract_path = self.root / module.CONTRACT
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        contract["archives"][0]["sigstore"]["bytes"] = path.stat().st_size
        contract["archives"][0]["sigstore"]["sha256"] = sha(path)
        contract_path.write_text(json.dumps(contract, sort_keys=True), encoding="utf-8")
        assets = json.loads(self.fixture.release_assets_json.read_text(encoding="utf-8"))
        for item in assets:
            if item["name"] == path.name:
                item["size"] = path.stat().st_size
                item["digest"] = f"sha256:{sha(path)}"
        self.fixture.release_assets_json.write_text(
            json.dumps(assets, sort_keys=True), encoding="utf-8"
        )
        report = self.fixture.verify()
        self.assertTrue(any("not bound" in error for error in report.errors))

    def test_release_api_digest_drift_is_rejected(self) -> None:
        assets = json.loads(self.fixture.release_assets_json.read_text(encoding="utf-8"))
        assets[0]["digest"] = "sha256:" + "0" * 64
        self.fixture.release_assets_json.write_text(
            json.dumps(assets, sort_keys=True), encoding="utf-8"
        )
        report = self.fixture.verify()
        self.assertTrue(any("release digest drifted" in error for error in report.errors))

    def test_duplicate_contract_member_is_rejected(self) -> None:
        path = self.root / module.CONTRACT
        path.write_text(
            '{"schema":"org.trillionnium.owner-open.codex-artifacts.v1",'
            '"schema":"org.trillionnium.owner-open.codex-artifacts.v1"}',
            encoding="utf-8",
        )
        report = module.verify(self.root)
        self.assertTrue(any("duplicate JSON member" in error for error in report.errors))

    def test_artifact_bytes_require_release_metadata(self) -> None:
        report = module.verify(self.root, asset_dir=self.fixture.assets)
        self.assertTrue(any("requires upstream release metadata" in error for error in report.errors))


if __name__ == "__main__":
    unittest.main()
