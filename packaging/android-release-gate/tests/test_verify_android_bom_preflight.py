#!/usr/bin/env python3
"""Fixture tests for the read-only Android BOM preflight."""

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
SCRIPT = PACKAGE / "verify_android_bom_preflight.py"
SPEC = importlib.util.spec_from_file_location("verify_android_bom_preflight", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
PREFLIGHT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PREFLIGHT
SPEC.loader.exec_module(PREFLIGHT)
BINDING_SCRIPT = PACKAGE / "verify_source_bom_binding.py"
BINDING_SPEC = importlib.util.spec_from_file_location("verify_source_bom_binding_fixture", BINDING_SCRIPT)
assert BINDING_SPEC is not None and BINDING_SPEC.loader is not None
BINDING = importlib.util.module_from_spec(BINDING_SPEC)
sys.modules[BINDING_SPEC.name] = BINDING
BINDING_SPEC.loader.exec_module(BINDING)


class BomPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="android-bom-preflight.")
        self.root = Path(self.temporary.name)
        self.bom = self.root / "source-bom.json"
        self.target = self.root / "target-files.zip"
        self.signed = self.root / "signed-metadata.json"
        self.rollback = self.root / "rollback-evidence.json"
        self.write_bom()
        self.write_target()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_bom(self, *, dirty: bool = False) -> None:
        project = {
            "id": "control_plane",
            "requirements": {"clean": True, "no_ignored_paths": True},
            "git": {
                "clean_nonignored": not dirty,
                "ignored": {"count": 0},
            },
            "failures": [],
        }
        bom = {
            "schema": PREFLIGHT.BOM_SCHEMA,
            "blockers": [],
            "decision": PREFLIGHT.PASS_BOM,
            "posture": {
                "local_only": True,
                "network_access_performed": False,
                "signed": False,
                "release_pin_published": False,
                "build_authorized": False,
                "ota_authorized": False,
                "device_write_authorized": False,
                "observed_artifact_hashes_are_release_pins": False,
                "observed_tree_hashes_are_release_pins": False,
            },
            "projects": [project],
            "trees": [
                {
                    "id": "vendor_motorola_fogos_blobs",
                    "failures": [],
                    "inventory": {
                        "stable_remeasurement_passed": True,
                        "no_follow_path_walk_passed": True,
                    },
                }
            ],
            "source_set": {
                "schema": PREFLIGHT.BOM_SOURCE_SET_SCHEMA,
                "sha256": "a" * 64,
            },
            "resolved_manifest": {
                "all_revisions_exact": True,
                "declared_checkout_revision_drift_count": 0,
            },
            "receipt_id_scope": "sha256(canonical-json-utf8-without-receipt_id)",
        }
        bom["receipt_id"] = "sha256:" + hashlib.sha256(
            PREFLIGHT.canonical_json_bytes(bom)
        ).hexdigest()
        self.bom.write_bytes(PREFLIGHT.canonical_json_bytes(bom))

    def write_target(
        self,
        *,
        build_type: str = "userdebug",
        tags: str = "test-keys",
        ota: bytes = b"\n",
        test_key: bool = True,
        source_bom_binding: bytes | None = None,
    ) -> None:
        fingerprint = f"trillionnium/fogos:16/BUILD/{build_type}/{tags}"
        misc_lines = [
            "ab_update=true",
            "avb_enable=true",
            f"build_type={build_type}",
            "avb_vbmeta_args=--rollback_index 28",
            "avb_vbmeta_system_args=--rollback_index 28",
            "avb_vbmeta_system_rollback_index_location=2",
        ]
        if test_key:
            misc_lines.append("avb_vbmeta_key_path=external/avb/test/data/testkey_rsa4096.pem")
        misc = "\n".join(misc_lines) + "\n"
        build_prop = "\n".join(
            (
                f"ro.build.type={build_type}",
                f"ro.build.tags={tags}",
                f"ro.build.fingerprint={fingerprint}",
            )
        ) + "\n"
        with zipfile.ZipFile(self.target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("META/misc_info.txt", misc)
            archive.writestr("META/otakeys.txt", ota)
            archive.writestr("SYSTEM/build.prop", build_prop)
            if source_bom_binding is not None:
                archive.writestr(BINDING.BINDING_MEMBER, source_bom_binding)

    def source_bom_binding(self) -> bytes:
        bom = json.loads(self.bom.read_text(encoding="utf-8"))
        source_set = bom["source_set"]
        value: dict[str, object] = {
            "schema": BINDING.BINDING_SCHEMA,
            "authority": BINDING.BINDING_AUTHORITY,
            "source_bom": {
                "schema": BINDING.BOM_SCHEMA,
                "receipt_id": bom["receipt_id"],
                "bytes": self.bom.stat().st_size,
                "sha256": hashlib.sha256(self.bom.read_bytes()).hexdigest(),
                "source_set_sha256": source_set["sha256"],
                "resolved_manifest_sha256": "4" * 64,
            },
            "source_set": {
                "schema": BINDING.BOM_SOURCE_SET_SCHEMA,
                "bytes": 1,
                "sha256": source_set["sha256"],
            },
            "resolved_manifest": {
                "schema": "org.trillionnium.repo-manifest.v1",
                "bytes": 1,
                "sha256": "4" * 64,
            },
            "receipt_stage": {
                "schema": "org.trillionnium.android.receipt-stage.v1",
                "bytes": 1,
                "sha256": "5" * 64,
            },
        }
        value["binding_id"] = "sha256:" + hashlib.sha256(
            BINDING.canonical_json_bytes(value)
        ).hexdigest()
        return BINDING.canonical_json_bytes(value)

    def write_release_evidence(self) -> None:
        digest = hashlib.sha256(self.target.read_bytes()).hexdigest()
        self.signed.write_bytes(
            PREFLIGHT.canonical_json_bytes(
                {
                    "schema": "org.trillionnium.android-release-signed-metadata.v1",
                    "target_files_sha256": digest,
                    "signed": True,
                    "build_type": "user",
                    "build_tags": ["release-keys"],
                    "signing_key_id": "release-key-2026",
                    "signature": {"value": "detached-attestation"},
                }
            )
        )
        self.rollback.write_bytes(
            PREFLIGHT.canonical_json_bytes(
                {
                    "schema": "org.trillionnium.android-rollback-evidence.v1",
                    "target_files_sha256": digest,
                    "hardware_antirollback_proven": True,
                    "evidence_id": "rollback-attestation-2026",
                    "indices": {
                        "vbmeta": {"rollback_index": 28, "rollback_index_location": 0},
                        "vbmeta_system": {"rollback_index": 28, "rollback_index_location": 2},
                    },
                }
            )
        )

    def test_current_shape_reports_exact_clean_bom_but_release_holds(self) -> None:
        report = PREFLIGHT.preflight(self.bom, target_files=self.target)
        self.assertEqual("HOLD", report["decision"])
        self.assertIn("target_build_type_not_user", report["holds"])
        self.assertIn("target_avb_test_key_path", report["holds"])
        self.assertIn("target_ota_keys_empty_or_missing", report["holds"])
        self.assertIn("signed_metadata_missing", report["holds"])
        self.assertIn("rollback_evidence_missing", report["holds"])
        self.assertNotIn("bom_receipt_id_mismatch", report["holds"])
        self.assertFalse(report["effects"]["files_written"])

    def test_dirty_project_claim_is_not_exact_clean(self) -> None:
        self.write_bom(dirty=True)
        report = PREFLIGHT.preflight(self.bom, target_files=self.target)
        self.assertIn("bom_project_git_dirty:control_plane", report["holds"])

    def test_source_bom_binding_strict_flag_requires_member(self) -> None:
        report = PREFLIGHT.preflight(
            self.bom,
            target_files=self.target,
            require_source_bom_binding=True,
        )
        self.assertIn("target_files_source_bom_binding_missing", report["holds"])
        self.assertTrue(report["source_bom_binding"]["required"])

    def test_source_bom_binding_strict_flag_accepts_matching_member(self) -> None:
        self.write_target(source_bom_binding=self.source_bom_binding())
        report = PREFLIGHT.preflight(
            self.bom,
            target_files=self.target,
            require_source_bom_binding=True,
        )
        self.assertTrue(report["source_bom_binding"]["valid"], report)
        self.assertEqual([], report["source_bom_binding"]["holds"])

    def test_release_fixture_requires_explicit_target_digest_and_accepts_it(self) -> None:
        self.write_bom()
        self.write_target(
            build_type="user", tags="release-keys", ota=b"release-cert\n", test_key=False
        )
        self.write_release_evidence()
        digest = hashlib.sha256(self.target.read_bytes()).hexdigest()
        without_digest = PREFLIGHT.preflight(
            self.bom,
            target_files=self.target,
            signed_metadata=self.signed,
            rollback_evidence=self.rollback,
        )
        self.assertIn("target_files_digest_not_provided_for_evidence_binding", without_digest["holds"])
        report = PREFLIGHT.preflight(
            self.bom,
            target_files=self.target,
            signed_metadata=self.signed,
            rollback_evidence=self.rollback,
            target_sha256=digest,
        )
        self.assertTrue(report["eligible"], report)
        self.assertEqual([], report["holds"])

    def test_private_evidence_path_is_rejected_before_read(self) -> None:
        private = self.root / "release-key.pem"
        private.write_bytes(b"PRIVATE KEY SENTINEL")
        report = PREFLIGHT.preflight(
            self.bom,
            target_files=self.target,
            signed_metadata=private,
        )
        self.assertIn("signed_metadata_private_material_path", report["holds"])
        self.assertEqual(b"PRIVATE KEY SENTINEL", private.read_bytes())

    def test_symlinked_bom_parent_is_rejected(self) -> None:
        alias_parent = self.root / "alias"
        alias_parent.symlink_to(self.root, target_is_directory=True)
        report = PREFLIGHT.preflight(alias_parent / self.bom.name, target_files=self.target)
        self.assertIn("bom_unreadable", report["holds"])

    def test_cli_is_read_only_and_uses_hold_exit(self) -> None:
        before = self.bom.read_bytes()
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--bom", str(self.bom), "--target-files", str(self.target)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(PREFLIGHT.HOLD_EXIT, result.returncode)
        self.assertEqual(before, self.bom.read_bytes())
        self.assertEqual(b"", result.stderr)
        self.assertEqual("HOLD", json.loads(result.stdout)["decision"])

    def test_source_has_no_process_or_write_api(self) -> None:
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertNotIn("subprocess", imported)
        source = SCRIPT.read_text(encoding="utf-8").lower()
        self.assertNotIn("fastboot flash", source)
        self.assertNotIn("adb install", source)


if __name__ == "__main__":
    unittest.main()
