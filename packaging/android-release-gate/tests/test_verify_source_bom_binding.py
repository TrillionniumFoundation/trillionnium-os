#!/usr/bin/env python3
"""Fixtures for the target-files source-BOM binding contract."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile


PACKAGE = Path(__file__).resolve().parents[1]
SCRIPT = PACKAGE / "verify_source_bom_binding.py"
SPEC = importlib.util.spec_from_file_location("verify_source_bom_binding", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BINDING = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BINDING
SPEC.loader.exec_module(BINDING)


class SourceBomBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="source-bom-binding.")
        self.root = Path(self.temporary.name)
        self.target = self.root / "target-files.zip"
        self.bom, self.bom_raw = self.make_bom()
        self.binding, self.binding_raw = self.make_binding(self.bom, self.bom_raw)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_bom(self) -> tuple[dict[str, object], bytes]:
        value: dict[str, object] = {
            "schema": BINDING.BOM_SCHEMA,
            "decision": "PASS_LOCAL_EXACT_CLEAN_GRAPH",
            "source_set": {
                "schema": BINDING.BOM_SOURCE_SET_SCHEMA,
                "sha256": "1" * 64,
            },
            "resolved_manifest": {
                "sha256": "2" * 64,
                "all_revisions_exact": True,
                "declared_checkout_revision_drift_count": 0,
            },
        }
        value["receipt_id"] = "sha256:" + hashlib.sha256(
            BINDING.canonical_json_bytes(value)
        ).hexdigest()
        raw = BINDING.canonical_json_bytes(value)
        return value, raw

    def make_binding(
        self, bom: dict[str, object], bom_raw: bytes
    ) -> tuple[dict[str, object], bytes]:
        source_set = bom["source_set"]
        assert isinstance(source_set, dict)
        manifest = bom["resolved_manifest"]
        assert isinstance(manifest, dict)
        value: dict[str, object] = {
            "schema": BINDING.BINDING_SCHEMA,
            "authority": BINDING.BINDING_AUTHORITY,
            "source_bom": {
                "schema": BINDING.BOM_SCHEMA,
                "receipt_id": bom["receipt_id"],
                "bytes": len(bom_raw),
                "sha256": hashlib.sha256(bom_raw).hexdigest(),
                "source_set_sha256": source_set["sha256"],
                "resolved_manifest_sha256": manifest["sha256"],
            },
            "source_set": {
                "schema": BINDING.BOM_SOURCE_SET_SCHEMA,
                "bytes": 321,
                "sha256": source_set["sha256"],
            },
            "resolved_manifest": {
                "schema": "org.trillionnium.repo-manifest.v1",
                "bytes": 654,
                "sha256": manifest["sha256"],
            },
            "receipt_stage": {
                "schema": "org.trillionnium.android.receipt-stage.v1",
                "bytes": 987,
                "sha256": "3" * 64,
            },
        }
        value["binding_id"] = "sha256:" + hashlib.sha256(
            BINDING.canonical_json_bytes(value)
        ).hexdigest()
        return value, BINDING.canonical_json_bytes(value)

    def write_target(self, member: bytes | None = None) -> None:
        with zipfile.ZipFile(self.target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("META/misc_info.txt", "ab_update=true\n")
            if member is not None:
                archive.writestr(BINDING.BINDING_MEMBER, member)

    def test_valid_binding_is_accepted_and_cross_checked(self) -> None:
        report = BINDING.validate_source_bom_binding(
            self.binding,
            raw=self.binding_raw,
            expected_bom=self.bom,
            expected_bom_bytes=self.bom_raw,
        )
        self.assertTrue(report["valid"], report)
        self.assertEqual([], report["holds"])

        self.write_target(self.binding_raw)
        archive_report = BINDING.inspect_target_files_source_bom_binding(
            self.target,
            require_binding=True,
            expected_bom_bytes=self.bom_raw,
        )
        self.assertTrue(archive_report["valid"], archive_report)
        self.assertTrue(archive_report["present"])

    def test_missing_member_is_backward_compatible_unless_strict(self) -> None:
        self.write_target()
        optional = BINDING.inspect_target_files_source_bom_binding(self.target)
        self.assertTrue(optional["valid"], optional)
        self.assertFalse(optional["present"])
        self.assertEqual([], optional["holds"])

        strict = BINDING.inspect_target_files_source_bom_binding(
            self.target, require_binding=True
        )
        self.assertFalse(strict["valid"])
        self.assertEqual(
            ["target_files_source_bom_binding_missing"], strict["holds"]
        )

    def test_malformed_member_is_held(self) -> None:
        self.write_target(b"{not-json")
        report = BINDING.inspect_target_files_source_bom_binding(self.target)
        self.assertFalse(report["valid"])
        self.assertEqual(["source_bom_binding_invalid_json"], report["holds"])

    def test_mismatch_is_held_even_when_binding_id_is_recomputed(self) -> None:
        mismatched = json.loads(self.binding_raw.decode("utf-8"))
        assert isinstance(mismatched, dict)
        source_bom = mismatched["source_bom"]
        assert isinstance(source_bom, dict)
        source_bom["receipt_id"] = "sha256:" + "f" * 64
        mismatched.pop("binding_id")
        mismatched["binding_id"] = "sha256:" + hashlib.sha256(
            BINDING.canonical_json_bytes(mismatched)
        ).hexdigest()
        raw = BINDING.canonical_json_bytes(mismatched)
        self.write_target(raw)
        report = BINDING.inspect_target_files_source_bom_binding(
            self.target, require_binding=True, expected_bom_bytes=self.bom_raw
        )
        self.assertFalse(report["valid"])
        self.assertIn("source_bom_binding_bom_receipt_id_mismatch", report["holds"])

    def test_descriptor_schemas_are_not_arbitrary(self) -> None:
        invalid = json.loads(self.binding_raw.decode("utf-8"))
        assert isinstance(invalid, dict)
        manifest = invalid["resolved_manifest"]
        assert isinstance(manifest, dict)
        manifest["schema"] = "org.trillionnium.evil.v1"
        invalid.pop("binding_id")
        invalid["binding_id"] = "sha256:" + hashlib.sha256(
            BINDING.canonical_json_bytes(invalid)
        ).hexdigest()
        raw = BINDING.canonical_json_bytes(invalid)
        report = BINDING.validate_source_bom_binding(invalid, raw=raw)
        self.assertFalse(report["valid"])
        self.assertIn("source_bom_binding_resolved_manifest_schema_invalid", report["holds"])

        invalid = json.loads(self.binding_raw.decode("utf-8"))
        assert isinstance(invalid, dict)
        stage = invalid["receipt_stage"]
        assert isinstance(stage, dict)
        stage["schema"] = "org.trillionnium.evil-stage.v1"
        invalid.pop("binding_id")
        invalid["binding_id"] = "sha256:" + hashlib.sha256(
            BINDING.canonical_json_bytes(invalid)
        ).hexdigest()
        raw = BINDING.canonical_json_bytes(invalid)
        report = BINDING.validate_source_bom_binding(invalid, raw=raw)
        self.assertFalse(report["valid"])
        self.assertIn("source_bom_binding_receipt_stage_schema_invalid", report["holds"])


if __name__ == "__main__":
    unittest.main()
