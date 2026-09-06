#!/usr/bin/env python3
"""Tests for the owner-open Linux ARM64 adb artifact verifier."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
VERIFIER_PATH = ROOT / "packaging/owner-open-adb/verify_arm64_adb.py"
SPEC = importlib.util.spec_from_file_location("verify_owner_open_arm64_adb", VERIFIER_PATH)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFY
SPEC.loader.exec_module(VERIFY)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def minimal_aarch64_elf(machine: int = 183, elf_type: int = 3) -> bytes:
    value = bytearray(64)
    value[:4] = b"\x7fELF"
    value[4] = 2  # ELF64
    value[5] = 1  # little endian
    value[6] = 1  # current ELF version
    value[16:18] = elf_type.to_bytes(2, "little")
    value[18:20] = machine.to_bytes(2, "little")
    value[20:24] = (1).to_bytes(4, "little")
    return bytes(value)


class Arm64AdbVerifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.artifact = self.root / "adb"
        self.version = self.root / "adb-version.txt"
        self.metadata = self.root / "adb-artifact.json"
        self.write_artifact(minimal_aarch64_elf())
        self.version_bytes = (
            b"Android Debug Bridge version 1.0.41\n"
            b"Version 35.0.2-owner-open-test\n"
        )
        self.version.write_bytes(self.version_bytes)
        self.version.chmod(0o644)
        self.write_metadata()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_artifact(self, value: bytes) -> None:
        self.artifact.write_bytes(value)
        self.artifact.chmod(0o755)

    def document(self) -> dict[str, object]:
        artifact = self.artifact.read_bytes()
        return {
            "schema": VERIFY.SCHEMA,
            "artifact": {
                "sha256": sha256(artifact),
                "bytes": len(artifact),
                "architecture": "linux-arm64",
                "os": "linux",
                "format": "ELF64-AArch64",
                "install_path": "/usr/bin/adb",
                "install_mode": "0755",
            },
            "source": {
                "kind": "aosp-reproducible-build",
                "name": "AOSP platform-tools adb",
                "revision_or_version": "test-revision",
                "provenance": "pinned source fixture",
                "license": "Apache-2.0",
                "build_or_package_command": "fixture build command",
                "toolchain_or_repository": "fixture toolchain",
            },
            "runtime_observation": {
                "adb_version_output_sha256": sha256(self.version_bytes),
                "observed_on": "linux-arm64 Root Linux fixture",
            },
            "claims": {
                "ordinary_adb_client": True,
                "typed_trillionnium_adapter": False,
                "image_inclusion": False,
                "integrated_codex_turn": False,
                "physical_device_effect": False,
                "release_qualified": False,
            },
        }

    def write_metadata(self, mutate=None) -> None:
        document = self.document()
        if mutate:
            mutate(document)
        self.metadata.write_text(
            json.dumps(document, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        self.metadata.chmod(0o644)

    def verify(self):
        return VERIFY.verify(self.artifact, self.metadata, self.version)

    def test_accepts_only_a_source_qualified_arm64_adb_artifact(self) -> None:
        report = self.verify()
        self.assertTrue(report["accepted"])
        self.assertEqual(report["artifact"]["machine"], "AArch64")
        self.assertEqual(report["artifact"]["sha256"], sha256(self.artifact.read_bytes()))
        self.assertEqual(report["claim_ceiling"], "QUALIFIED_SOURCE_ARTIFACT_ONLY")
        self.assertFalse(report["image_inclusion"])
        self.assertFalse(report["integrated_codex_turn"])
        self.assertFalse(report["physical_device_effect"])
        self.assertFalse(report["release_qualified"])

    def test_rejects_wrong_machine_and_non_executable_elf(self) -> None:
        self.write_artifact(minimal_aarch64_elf(machine=62))  # x86_64
        self.write_metadata()
        with self.assertRaisesRegex(VERIFY.VerificationError, "expected AArch64"):
            self.verify()

        self.write_artifact(minimal_aarch64_elf())
        self.artifact.chmod(0o644)
        self.write_metadata()
        with self.assertRaisesRegex(VERIFY.VerificationError, "no executable bit"):
            self.verify()

    def test_rejects_digest_size_and_version_observation_drift(self) -> None:
        self.write_metadata(
            lambda value: value["artifact"].__setitem__("sha256", "0" * 64)
        )
        with self.assertRaisesRegex(VERIFY.VerificationError, "SHA-256"):
            self.verify()

        self.write_metadata(lambda value: value["artifact"].__setitem__("bytes", 65))
        with self.assertRaisesRegex(VERIFY.VerificationError, "byte size"):
            self.verify()

        self.write_metadata(
            lambda value: value["runtime_observation"].__setitem__(
                "adb_version_output_sha256", "1" * 64
            )
        )
        with self.assertRaisesRegex(VERIFY.VerificationError, "version output SHA-256"):
            self.verify()

    def test_rejects_typed_adapter_or_promoted_product_claims(self) -> None:
        for field, replacement in (
            ("ordinary_adb_client", False),
            ("typed_trillionnium_adapter", True),
            ("image_inclusion", True),
            ("integrated_codex_turn", True),
            ("physical_device_effect", True),
            ("release_qualified", True),
        ):
            self.write_metadata(
                lambda value, field=field, replacement=replacement: value[
                    "claims"
                ].__setitem__(field, replacement)
            )
            with self.assertRaisesRegex(VERIFY.VerificationError, "claims must identify"):
                self.verify()

    def test_rejects_symlink_writable_or_multiply_linked_inputs(self) -> None:
        real = self.root / "real-adb"
        real.write_bytes(minimal_aarch64_elf())
        real.chmod(0o755)
        self.artifact.unlink()
        self.artifact.symlink_to(real)
        self.write_metadata()
        with self.assertRaisesRegex(VERIFY.VerificationError, "not a symlink"):
            self.verify()

        self.artifact.unlink()
        self.write_artifact(minimal_aarch64_elf())
        self.artifact.chmod(0o775)
        self.write_metadata()
        with self.assertRaisesRegex(VERIFY.VerificationError, "group/world writable"):
            self.verify()

        self.artifact.chmod(0o755)
        hardlink = self.root / "adb-hardlink"
        os.link(self.artifact, hardlink)
        self.write_metadata()
        with self.assertRaisesRegex(VERIFY.VerificationError, "exactly one hard link"):
            self.verify()

    def test_rejects_non_adb_version_output_and_claim_schema_drift(self) -> None:
        self.version.write_text("not adb\n", encoding="utf-8")
        self.write_metadata()
        with self.assertRaisesRegex(VERIFY.VerificationError, "does not identify"):
            self.verify()

        self.version.write_bytes(self.version_bytes)
        self.write_metadata(lambda value: value.__setitem__("unexpected", True))
        with self.assertRaisesRegex(VERIFY.VerificationError, "unknown fields"):
            self.verify()

    def test_cli_failure_is_machine_readable_and_nonzero(self) -> None:
        self.write_artifact(minimal_aarch64_elf(machine=62))
        self.write_metadata()
        result = subprocess.run(
            [
                sys.executable,
                str(VERIFIER_PATH),
                "--artifact",
                str(self.artifact),
                "--metadata",
                str(self.metadata),
                "--version-output",
                str(self.version),
                "--json",
            ],
            text=True,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 1)
        response = json.loads(result.stdout)
        self.assertFalse(response["accepted"])
        self.assertIn("expected AArch64", response["error"])


if __name__ == "__main__":
    unittest.main()
