from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "owner-open"
    / "verify_owner_open_materialized_payload.py"
)
spec = importlib.util.spec_from_file_location(
    "verify_owner_open_materialized_payload", SCRIPT
)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class VerifyOwnerOpenMaterializedPayloadTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.inputs = self.root / "inputs"
        self.outputs = self.root / "outputs"
        self.inputs.mkdir(mode=0o700)
        self.outputs.mkdir(mode=0o700)
        self.image = self.inputs / module.IMAGE_NAME
        self.manifest = self.inputs / module.MANIFEST_NAME
        self.image_bytes = b"hsqs-owner-open-fixture\x00\xff" * 17
        self.image.write_bytes(self.image_bytes)
        self.image.chmod(0o400)
        digest = hashlib.sha256(self.image_bytes).hexdigest()
        self.value = {
            "schema": module.IMAGE_SCHEMA,
            "payload_id": "fixture",
            "staging_manifest_sha256": "0" * 64,
            "architecture": "aarch64",
            "libc": "glibc",
            "entry_count": 1,
            "mksquashfs": {"sha256": "1" * 64},
            "help_observation": {},
            "build_runs": [
                {"image_sha256": digest, "image_bytes": len(self.image_bytes)},
                {"image_sha256": digest, "image_bytes": len(self.image_bytes)},
            ],
            "reproducibility_runs": 2,
            "reproducible": True,
            "image_sha256": digest,
            "image_bytes": len(self.image_bytes),
            "image_path": "/build/owner-open-rootfs.squashfs",
            "claims": {
                "staging_revalidated": True,
                "deterministic_options_observed": True,
                "independent_builds_byte_identical": True,
                "rootfs_image_built": True,
                "android_module_bound": False,
                "target_files_built": False,
                "image_included": False,
                "physical_device_observed": False,
                "public_release": False,
            },
            "claim_ceiling": "ROOTFS_IMAGE_BUILT_NOT_ANDROID_INCLUDED",
        }
        self.write_manifest(self.value)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_manifest(self, value: dict) -> None:
        self.manifest.chmod(0o600) if self.manifest.exists() else None
        self.manifest.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        self.manifest.chmod(0o400)

    def inputs_list(self) -> list[Path]:
        return [self.inputs / "README.materialization-required", self.image, self.manifest]

    def test_image_manifest_and_digest_are_published_exactly(self) -> None:
        (self.inputs / "README.materialization-required").write_text(
            "external artifacts required\n", encoding="utf-8"
        )
        for kind, name in (
            ("image", "out.squashfs"),
            ("manifest", "out.json"),
            ("digest", "out.sha256"),
        ):
            output = self.outputs / name
            report = module.materialize(kind, output, self.inputs_list())
            self.assertEqual(report["kind"], kind)
            self.assertTrue(output.is_file())
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o644)
        self.assertEqual((self.outputs / "out.squashfs").read_bytes(), self.image_bytes)
        self.assertEqual((self.outputs / "out.json").read_bytes(), self.manifest.read_bytes())
        self.assertEqual(
            (self.outputs / "out.sha256").read_text(encoding="ascii"),
            hashlib.sha256(self.image_bytes).hexdigest() + "\n",
        )

    def test_missing_materialized_pair_is_a_hold(self) -> None:
        self.manifest.unlink()
        with self.assertRaisesRegex(module.MaterializationError, "exactly one image"):
            module.materialize("image", self.outputs / "out", [self.image])

    def test_digest_or_byte_drift_is_rejected(self) -> None:
        value = dict(self.value)
        value["image_sha256"] = "f" * 64
        self.write_manifest(value)
        with self.assertRaisesRegex(module.MaterializationError, "do not match"):
            module.materialize("image", self.outputs / "out", [self.image, self.manifest])

    def test_android_or_device_overclaim_is_rejected(self) -> None:
        value = json.loads(json.dumps(self.value))
        value["claims"]["android_module_bound"] = True
        value["claims"]["image_included"] = True
        self.write_manifest(value)
        with self.assertRaisesRegex(module.MaterializationError, "pre-Android"):
            module.materialize("manifest", self.outputs / "out", [self.image, self.manifest])

    def test_duplicate_json_member_is_rejected(self) -> None:
        self.manifest.chmod(0o600)
        self.manifest.write_text(
            '{"schema":"%s","schema":"%s"}\n'
            % (module.IMAGE_SCHEMA, module.IMAGE_SCHEMA),
            encoding="utf-8",
        )
        self.manifest.chmod(0o400)
        with self.assertRaisesRegex(module.MaterializationError, "duplicate key"):
            module.materialize("digest", self.outputs / "out", [self.image, self.manifest])

    def test_create_only_output_refuses_replacement(self) -> None:
        output = self.outputs / "existing"
        output.write_text("do not replace", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            module.materialize("digest", output, [self.image, self.manifest])
        self.assertEqual(output.read_text(encoding="utf-8"), "do not replace")


if __name__ == "__main__":
    unittest.main()
