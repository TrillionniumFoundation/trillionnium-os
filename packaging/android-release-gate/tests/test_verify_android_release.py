#!/usr/bin/env python3
"""Bounded fixture tests for the source-only Android release gate."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile


PACKAGE = Path(__file__).resolve().parents[1]
SCRIPT = PACKAGE / "verify_android_release.py"
SPEC = importlib.util.spec_from_file_location("verify_android_release", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATE
SPEC.loader.exec_module(GATE)


class AndroidReleaseGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="android-release-gate.")
        self.root = Path(self.temporary.name)
        self.target = self.root / "target-files.zip"
        self.signed = self.root / "signed-metadata.json"
        self.rollback = self.root / "rollback-evidence.json"
        self.write_target()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_target(
        self,
        *,
        build_type: str = "userdebug",
        tags: str = "test-keys",
        ota_keys: bytes = b"\n",
        rollback_index: int = 28,
        include_rollback: bool = True,
    ) -> None:
        fingerprint = (
            "trillionnium/trillionnium_fogos/fogos:16/BP4A.251205.006/eng.builder:"
            f"{build_type}/{tags}"
        )
        misc = [
            "ab_update=true",
            "avb_enable=true",
            f"build_type={build_type}",
            "avb_vbmeta_algorithm=SHA256_RSA4096",
            f"avb_vbmeta_args=--padding_size 4096 --rollback_index {rollback_index}",
            "avb_vbmeta_system_algorithm=SHA256_RSA2048",
            f"avb_vbmeta_system_args=--padding_size 4096 --rollback_index {rollback_index}",
            "avb_vbmeta_system_rollback_index_location=2",
        ]
        if not include_rollback:
            misc = [line for line in misc if "rollback_index" not in line]
        build_prop = "\n".join(
            (
                "ro.product.device=fogos",
                f"ro.build.type={build_type}",
                f"ro.build.tags={tags}",
                f"ro.build.fingerprint={fingerprint}",
                f"ro.system.build.type={build_type}",
                f"ro.system.build.tags={tags}",
            )
        )
        with zipfile.ZipFile(self.target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("META/misc_info.txt", "\n".join(misc) + "\n")
            archive.writestr("META/otakeys.txt", ota_keys)
            archive.writestr("SYSTEM/build.prop", build_prop + "\n")

    def target_sha256(self) -> str:
        return hashlib.sha256(self.target.read_bytes()).hexdigest()

    def write_evidence(self, *, signed: bool = True, rollback: bool = True) -> None:
        digest = self.target_sha256()
        if signed:
            self.signed.write_bytes(
                GATE.canonical_json_bytes(
                    {
                        "schema": GATE.SIGNED_METADATA_SCHEMA,
                        "target_files_sha256": digest,
                        "signed": True,
                        "build_type": "user",
                        "build_tags": ["release-keys"],
                        "signing_key_id": "release-key-2026",
                        "signature": {
                            "algorithm": "external-attestation",
                            "value": "detached-signature-placeholder",
                        },
                    }
                )
            )
        if rollback:
            self.rollback.write_bytes(
                GATE.canonical_json_bytes(
                    {
                        "schema": GATE.ROLLBACK_EVIDENCE_SCHEMA,
                        "target_files_sha256": digest,
                        "hardware_antirollback_proven": True,
                        "evidence_id": "device-attestation-2026-08-22",
                        "indices": {
                            "vbmeta": {
                                "rollback_index": 28,
                                "rollback_index_location": 0,
                            },
                            "vbmeta_system": {
                                "rollback_index": 28,
                                "rollback_index_location": 2,
                            },
                        },
                    }
                )
            )

    def test_userdebug_test_keys_empty_ota_and_missing_evidence_are_hold(self) -> None:
        before = self.target.read_bytes()
        report = GATE.verify_target_files(self.target)
        self.assertFalse(report["eligible"])
        self.assertEqual("HOLD", report["decision"])
        for reason in (
            "target_build_type_not_user",
            "target_build_tags_contain_development_keys",
            "target_metadata_contains_userdebug_or_test_keys",
            "target_ota_keys_empty_or_missing",
            "signed_metadata_missing",
            "rollback_evidence_missing",
        ):
            self.assertIn(reason, report["holds"])
        self.assertEqual(before, self.target.read_bytes())
        self.assertFalse(report["effects"]["flash_performed"])
        self.assertFalse(report["effects"]["signing_performed"])
        self.assertFalse(report["effects"]["private_key_accessed"])
        self.assertFalse(report["effects"]["files_written"])

    def test_complete_user_release_requires_and_accepts_both_public_documents(self) -> None:
        self.write_target(build_type="user", tags="release-keys", ota_keys=b"CERT\n")
        self.write_evidence()
        report = GATE.verify_target_files(
            self.target,
            signed_metadata=self.signed,
            rollback_evidence=self.rollback,
        )
        self.assertTrue(report["eligible"], report)
        self.assertEqual("ELIGIBLE", report["decision"])
        self.assertTrue(report["signed_metadata"]["signature_present"])
        self.assertTrue(report["rollback_evidence"]["hardware_antirollback_proven"])
        self.assertEqual([], report["holds"])

    def test_digest_binding_accepts_hex_case_but_not_a_different_digest(self) -> None:
        self.write_target(build_type="user", tags="release-keys", ota_keys=b"CERT\n")
        self.write_evidence()
        signed_value = json.loads(self.signed.read_text(encoding="utf-8"))
        rollback_value = json.loads(self.rollback.read_text(encoding="utf-8"))
        signed_value["target_files_sha256"] = signed_value["target_files_sha256"].upper()
        rollback_value["target_files_sha256"] = rollback_value["target_files_sha256"].upper()
        self.signed.write_bytes(GATE.canonical_json_bytes(signed_value))
        self.rollback.write_bytes(GATE.canonical_json_bytes(rollback_value))
        report = GATE.verify_target_files(
            self.target,
            signed_metadata=self.signed,
            rollback_evidence=self.rollback,
        )
        self.assertTrue(report["eligible"], report)

    def test_signed_metadata_must_bind_digest_and_explicit_signature(self) -> None:
        self.write_target(build_type="user", tags="release-keys", ota_keys=b"CERT\n")
        self.write_evidence(signed=False)
        self.signed.write_bytes(
            GATE.canonical_json_bytes(
                {
                    "schema": GATE.SIGNED_METADATA_SCHEMA,
                    "target_files_sha256": "0" * 64,
                    "signed": False,
                    "build_type": "user",
                    "build_tags": ["release-keys"],
                }
            )
        )
        report = GATE.verify_target_files(
            self.target,
            signed_metadata=self.signed,
            rollback_evidence=self.rollback,
        )
        self.assertFalse(report["eligible"])
        for reason in (
            "signed_metadata_not_explicitly_signed",
            "signed_metadata_target_digest_mismatch",
            "signed_metadata_signature_missing",
            "signed_metadata_signing_key_id_missing",
        ):
            self.assertIn(reason, report["holds"])

    def test_target_tags_must_be_exactly_release_keys(self) -> None:
        self.write_target(
            build_type="user", tags="release-keys,internal-tag", ota_keys=b"CERT\n"
        )
        report = GATE.verify_target_files(self.target)
        self.assertFalse(report["eligible"])
        self.assertIn("target_build_tags_not_exact_release_keys", report["holds"])

    def test_conflicting_rollback_metadata_is_a_hold(self) -> None:
        self.write_target(build_type="user", tags="release-keys", ota_keys=b"CERT\n")
        with zipfile.ZipFile(self.target, "r") as source:
            misc = source.read("META/misc_info.txt")
            ota = source.read("META/otakeys.txt")
            build_prop = source.read("SYSTEM/build.prop")
        misc += b"avb_vbmeta_args=--rollback_index 28 --rollback_index 29\n"
        with zipfile.ZipFile(self.target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("META/misc_info.txt", misc)
            archive.writestr("META/otakeys.txt", ota)
            archive.writestr("SYSTEM/build.prop", build_prop)
        report = GATE.verify_target_files(self.target)
        self.assertFalse(report["eligible"])
        self.assertIn("misc_info_conflicting_duplicate_property", report["holds"])

    def test_rollback_evidence_must_cover_exact_target_indices(self) -> None:
        self.write_target(build_type="user", tags="release-keys", ota_keys=b"CERT\n")
        self.write_evidence()
        value = json.loads(self.rollback.read_text(encoding="utf-8"))
        value["indices"]["vbmeta"]["rollback_index"] = 27
        self.rollback.write_bytes(GATE.canonical_json_bytes(value))
        report = GATE.verify_target_files(
            self.target,
            signed_metadata=self.signed,
            rollback_evidence=self.rollback,
        )
        self.assertFalse(report["eligible"])
        self.assertIn("rollback_evidence_index_mismatch_vbmeta", report["holds"])

    def test_rollback_evidence_rejects_unexpected_partition_entries(self) -> None:
        self.write_target(build_type="user", tags="release-keys", ota_keys=b"CERT\n")
        self.write_evidence()
        value = json.loads(self.rollback.read_text(encoding="utf-8"))
        value["indices"]["stale_partition"] = {
            "rollback_index": 28,
            "rollback_index_location": 7,
        }
        self.rollback.write_bytes(GATE.canonical_json_bytes(value))
        report = GATE.verify_target_files(
            self.target,
            signed_metadata=self.signed,
            rollback_evidence=self.rollback,
        )
        self.assertFalse(report["eligible"])
        self.assertIn("rollback_evidence_unexpected_stale_partition", report["holds"])

    def test_avb_footer_without_rollback_index_is_a_hold(self) -> None:
        self.write_target(build_type="user", tags="release-keys", ota_keys=b"CERT\n")
        with zipfile.ZipFile(self.target, "r") as source:
            misc = source.read("META/misc_info.txt").decode("utf-8")
            ota = source.read("META/otakeys.txt")
            build_prop = source.read("SYSTEM/build.prop")
        misc = misc.replace(
            "avb_vbmeta_system_args=--padding_size 4096 --rollback_index 28",
            "avb_vbmeta_system_args=--padding_size 4096",
        )
        with zipfile.ZipFile(self.target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("META/misc_info.txt", misc)
            archive.writestr("META/otakeys.txt", ota)
            archive.writestr("SYSTEM/build.prop", build_prop)
        report = GATE.verify_target_files(self.target)
        self.assertFalse(report["eligible"])
        self.assertIn("avb_vbmeta_system_args_missing_rollback_index", report["holds"])

    def test_private_material_path_is_rejected_without_opening_it(self) -> None:
        self.write_target(build_type="user", tags="release-keys", ota_keys=b"CERT\n")
        self.write_evidence(signed=False)
        private_path = self.root / "not-a-private-key.pem"
        private_path.write_bytes(b"PRIVATE KEY SENTINEL")
        before = private_path.read_bytes()
        report = GATE.verify_target_files(
            self.target,
            signed_metadata=private_path,
            rollback_evidence=self.rollback,
        )
        self.assertFalse(report["eligible"])
        self.assertIn("signed_metadata_private_material_path", report["holds"])
        self.assertEqual(before, private_path.read_bytes())

    def test_symlinked_parent_is_rejected_before_evidence_read(self) -> None:
        self.write_target(build_type="user", tags="release-keys", ota_keys=b"CERT\n")
        self.write_evidence(signed=False)
        private_dir = self.root / "private-store"
        private_dir.mkdir()
        private_evidence = private_dir / "attestation.json"
        private_evidence.write_bytes(self.rollback.read_bytes())
        public_alias = self.root / "attestations"
        public_alias.symlink_to(private_dir, target_is_directory=True)
        report = GATE.verify_target_files(
            self.target,
            signed_metadata=public_alias / "attestation.json",
            rollback_evidence=self.rollback,
        )
        self.assertFalse(report["eligible"])
        self.assertIn("signed_metadata_unreadable", report["holds"])
        self.assertEqual(self.rollback.read_bytes(), private_evidence.read_bytes())

    def test_cli_returns_hold_code_and_never_creates_output(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(self.target)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(GATE.HOLD_EXIT, result.returncode)
        report = json.loads(result.stdout)
        self.assertFalse(report["eligible"])
        self.assertEqual(b"", result.stderr)

    def test_source_has_no_process_or_write_api_import(self) -> None:
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        imported = {
            node.names[0].name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import) and node.names
        }
        self.assertNotIn("subprocess", imported)
        self.assertNotIn("shutil", imported)
        source = SCRIPT.read_text(encoding="utf-8").lower()
        self.assertNotIn("fastboot flash", source)
        self.assertNotIn("adb install", source)


if __name__ == "__main__":
    unittest.main()
