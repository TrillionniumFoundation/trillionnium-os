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

ANDROID_SCRIPT = (
    Path(__file__).resolve().parents[1]
    / ".."
    / "android-integration/working-tree/vendor/trillionnium/owner-open/tools"
    / "verify_owner_open_materialized_payload.py"
).resolve()
android_spec = importlib.util.spec_from_file_location(
    "verify_owner_open_materialized_payload_android", ANDROID_SCRIPT
)
assert android_spec is not None and android_spec.loader is not None
android_module = importlib.util.module_from_spec(android_spec)
android_spec.loader.exec_module(android_module)


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
            "entries": [
                {
                    "role": "fixture",
                    "destination": "/etc/trillionnium/owner-open/config.json",
                    "mode": "0444",
                    "uid": 0,
                    "gid": 0,
                    "sha256": "0" * 64,
                    "bytes": 1,
                }
            ],
            "runtime_state_directory": "/var/lib/trillionnium/owner-open",
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

    def test_state_mountpoint_binding_is_required(self) -> None:
        value = json.loads(json.dumps(self.value))
        value["runtime_state_directory"] = "/var/lib/trillionnium/other"
        self.write_manifest(value)
        with self.assertRaisesRegex(module.MaterializationError, "canonical writable state"):
            module.materialize("manifest", self.outputs / "out", [self.image, self.manifest])

    def test_entry_inventory_is_required(self) -> None:
        value = json.loads(json.dumps(self.value))
        value.pop("entries")
        self.write_manifest(value)
        with self.assertRaisesRegex(module.MaterializationError, "entry inventory"):
            module.materialize("manifest", self.outputs / "out", [self.image, self.manifest])

    def test_entry_uid_and_gid_must_be_json_integers(self) -> None:
        for field in ("uid", "gid"):
            value = json.loads(json.dumps(self.value))
            value["entries"][0][field] = False
            self.write_manifest(value)
            with self.assertRaisesRegex(module.MaterializationError, "entry 0 is malformed"):
                module.materialize("manifest", self.outputs / f"bad-{field}", [self.image, self.manifest])

    def test_build_run_image_bytes_must_be_json_integer(self) -> None:
        value = json.loads(json.dumps(self.value))
        value["build_runs"][0]["image_bytes"] = True
        self.write_manifest(value)
        with self.assertRaisesRegex(module.MaterializationError, "build run 0"):
            module.materialize("manifest", self.outputs / "bad-run-bytes", [self.image, self.manifest])

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

    def test_sbox_relative_output_is_resolved_below_the_sandbox(self) -> None:
        sandbox = self.root / "sandbox"
        output_dir = sandbox / "out"
        output_dir.mkdir(parents=True, mode=0o700)
        previous = Path.cwd()
        try:
            os.chdir(sandbox)
            report = module.materialize(
                "digest", "./out/sbox-output.sha256", self.inputs_list()
            )
        finally:
            os.chdir(previous)
        output = output_dir / "sbox-output.sha256"
        self.assertEqual(report["output"], str(output))
        self.assertEqual(
            output.read_text(encoding="ascii"),
            hashlib.sha256(self.image_bytes).hexdigest() + "\n",
        )

    def test_relative_output_traversal_is_rejected(self) -> None:
        previous = Path.cwd()
        try:
            os.chdir(self.outputs)
            for raw in ("../escaped.sha256", "out/../escaped.sha256"):
                with self.subTest(raw=raw), self.assertRaisesRegex(
                    module.MaterializationError, "normalized|traversal"
                ):
                    module.materialize("digest", raw, self.inputs_list())
        finally:
            os.chdir(previous)

    def test_noncanonical_output_spellings_are_rejected(self) -> None:
        previous = Path.cwd()
        try:
            os.chdir(self.outputs)
            for raw in ("out//escaped.sha256", "out/./escaped.sha256", ".", ""):
                with self.subTest(raw=raw), self.assertRaisesRegex(
                    module.MaterializationError, "normalized|empty"
                ):
                    module.materialize("digest", raw, self.inputs_list())
        finally:
            os.chdir(previous)

    def test_output_parent_symlink_is_rejected(self) -> None:
        link = self.root / "output-link"
        link.symlink_to(self.outputs, target_is_directory=True)
        with self.assertRaisesRegex(module.MaterializationError, "symlink"):
            module.materialize("digest", link / "out.sha256", self.inputs_list())

    def test_android_copy_accepts_sbox_relative_output(self) -> None:
        sandbox = self.root / "android-sandbox"
        output_dir = sandbox / "out"
        output_dir.mkdir(parents=True, mode=0o700)
        previous = Path.cwd()
        try:
            os.chdir(sandbox)
            output = android_module.normalize_output_path("./out/result")
        finally:
            os.chdir(previous)
        self.assertEqual(output, output_dir / "result")


if __name__ == "__main__":
    unittest.main()
