from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).parents[1] / "materialize_android_source_bom_binding.py"
SPEC = importlib.util.spec_from_file_location("android_source_bom_binding", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BINDING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BINDING)


class MaterializeAndroidSourceBomBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="android-source-bom-binding.")
        self.root = Path(self.temp.name)
        self.source_set = {"schema": BINDING.SOURCE_SET_SCHEMA, "projects": [], "trees": [], "artifacts": []}
        self.source_set_raw = BINDING.canonical_json_bytes(self.source_set)
        self.manifest_raw = b"<?xml version='1.0'?><manifest/>\n"
        self.stage = {"schema": "org.trillionnium.android.receipt-stage.v1", "decision": "PASS_HOST_ONLY_ANDROID_USERDEBUG_RECEIPT_STAGE"}
        self.stage_raw = BINDING.canonical_json_bytes(self.stage)
        self.bom = self.make_bom()
        self.paths = {
            "bom": self.root / "source-bom.json",
            "set": self.root / "source-set.json",
            "manifest": self.root / "resolved-manifest.xml",
            "stage": self.root / "receipt-stage.json",
            "out": self.root / "binding.json",
        }
        self.paths["bom"].write_bytes(BINDING.canonical_json_bytes(self.bom))
        self.paths["set"].write_bytes(self.source_set_raw)
        self.paths["manifest"].write_bytes(self.manifest_raw)
        self.paths["stage"].write_bytes(self.stage_raw)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_bom(self) -> dict[str, object]:
        source_set_sha = hashlib.sha256(self.source_set_raw).hexdigest()
        manifest_sha = hashlib.sha256(self.manifest_raw).hexdigest()
        value: dict[str, object] = {
            "schema": BINDING.SOURCE_BOM_SCHEMA,
            "decision": BINDING.SOURCE_BOM_PASS,
            "posture": {
                "local_only": True,
                "signed": False,
                "build_authorized": False,
                "ota_authorized": False,
                "device_write_authorized": False,
            },
            "source_set": {"schema": BINDING.SOURCE_SET_SCHEMA, "bytes": len(self.source_set_raw), "sha256": source_set_sha},
            "resolved_manifest": {"producer": "test", "bytes": len(self.manifest_raw), "sha256": manifest_sha},
            "projects": [],
            "trees": [],
            "artifacts": [],
            "blockers": [],
            "receipt_id_scope": BINDING.SOURCE_BOM_RECEIPT_ID_SCOPE,
        }
        value["receipt_id"] = "sha256:" + hashlib.sha256(BINDING.canonical_json_bytes(value)).hexdigest()
        return value

    def test_materializes_and_binds_all_input_bytes(self) -> None:
        raw = BINDING.materialize(self.paths["bom"], self.paths["set"], self.paths["manifest"], self.paths["stage"])
        value = json.loads(raw)
        self.assertEqual(value["schema"], BINDING.BINDING_SCHEMA)
        self.assertEqual(value["source_bom"]["sha256"], hashlib.sha256(self.paths["bom"].read_bytes()).hexdigest())
        self.assertEqual(value["resolved_manifest"]["sha256"], hashlib.sha256(self.manifest_raw).hexdigest())
        self.assertEqual(value["binding_id"], "sha256:" + hashlib.sha256(BINDING.canonical_json_bytes({k: v for k, v in value.items() if k != "binding_id"})).hexdigest())

    def test_digest_mismatch_and_existing_output_are_holds(self) -> None:
        self.paths["manifest"].write_bytes(b"different\n")
        with self.assertRaisesRegex(BINDING.BindingError, "resolved_manifest_digest_mismatch"):
            BINDING.materialize(self.paths["bom"], self.paths["set"], self.paths["manifest"], self.paths["stage"])
        self.paths["manifest"].write_bytes(self.manifest_raw)
        self.paths["out"].write_bytes(b"old")
        with self.assertRaisesRegex(BINDING.BindingError, "output_must_be_new"):
            BINDING.publish_exclusive(self.paths["out"], b"new")
        self.assertEqual(self.paths["out"].read_bytes(), b"old")

    def test_symlink_input_is_rejected(self) -> None:
        link = self.root / "source-set-link.json"
        link.symlink_to(self.paths["set"])
        with self.assertRaisesRegex(BINDING.BindingError, "symlink_path"):
            BINDING.materialize(self.paths["bom"], link, self.paths["manifest"], self.paths["stage"])


if __name__ == "__main__":
    unittest.main()
