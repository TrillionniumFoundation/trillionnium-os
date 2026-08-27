#!/usr/bin/env python3
"""Fixture tests for the Android release target-files/OTA pipeline."""

from __future__ import annotations

from contextlib import redirect_stdout
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile


TOOLS = Path(__file__).resolve().parents[1]
SCRIPT = TOOLS / "android_release_ota.py"


def load_module():
    spec = importlib.util.spec_from_file_location("android_release_ota", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RELEASE = load_module()
TEST_CERT = b"-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n"


class AndroidReleaseOtaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="trillionnium-android-release-test."
        )
        self.root = Path(self.temporary.name)
        self.android = self.root / "android"
        self.android.mkdir()
        for relative in (
            "out/host/linux-x86/bin/sign_target_files_apks",
            "out/host/linux-x86/bin/ota_from_target_files",
            "out/host/linux-x86/bin/check_ota_package_signature",
            "out/host/linux-x86/bin/avbtool",
            "out/host/linux-x86/bin/apksigner",
        ):
            path = self.android / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            path.chmod(0o755)
        avbtool = self.android / "out/host/linux-x86/bin/avbtool"
        avbtool.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "if [ \"$1\" = extract_public_key ]; then\n"
            "  shift\n"
            "  key=\n"
            "  output=\n"
            "  while [ \"$#\" -gt 0 ]; do\n"
            "    case \"$1\" in\n"
            "      --key) key=$2; shift 2 ;;\n"
            "      --output) output=$2; shift 2 ;;\n"
            "      *) shift ;;\n"
            "    esac\n"
            "  done\n"
            "  test -n \"$key\"\n"
            "  test -n \"$output\"\n"
            "  printf '%s' \"$key\" > \"$output\"\n"
            "fi\n",
            encoding="utf-8",
        )
        avbtool.chmod(0o755)
        self.config_value = {
            "schema": RELEASE.CONFIG_SCHEMA,
            "product": {
                "device": "fogos",
                "allowed_build_types": ["user", "userdebug"],
                "require_ab_update": True,
            },
            "tools": {
                "sign_target_files_apks": "out/host/linux-x86/bin/sign_target_files_apks",
                "ota_from_target_files": "out/host/linux-x86/bin/ota_from_target_files",
                "check_ota_package_signature": (
                    "out/host/linux-x86/bin/check_ota_package_signature"
                ),
                "avbtool": "out/host/linux-x86/bin/avbtool",
                "apksigner": "out/host/linux-x86/bin/apksigner",
            },
            "signing": {
                "apk_key_mappings": {
                    "build/make/target/product/security/testkey": "releasekey",
                    "build/make/target/product/security/platform": "platform",
                },
                "ota_key_alias": "releasekey",
                "avb": {
                    "vbmeta": {
                        "algorithm": "SHA256_RSA4096",
                        "expected_flags": 0,
                        "key": "vbmeta.pem",
                        "rollback_index": 28,
                        "rollback_index_location": 0,
                    },
                    "vbmeta_system": {
                        "algorithm": "SHA256_RSA2048",
                        "expected_flags": 0,
                        "key": "vbmeta_system.pem",
                        "rollback_index": 28,
                        "rollback_index_location": 2,
                    },
                },
                "rollback_policy": dict(RELEASE.EXPECTED_ROLLBACK_POLICY),
                "apex_payload_keys": {
                    "com.android.runtime.apex": "apex_runtime.pem",
                    "com.android.wifi.apex": "apex_wifi.pem",
                },
            },
        }
        self.config = self.root / "config.json"
        self.write_config()
        self.target = self.root / "target-files.zip"
        self.write_target()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_config(self, value: dict[str, object] | None = None) -> None:
        self.config.write_bytes(
            RELEASE.canonical_json_bytes(value if value is not None else self.config_value)
        )

    def write_target(
        self,
        *,
        device: str = "fogos",
        build_type: str = "userdebug",
        tags: str = "test-keys",
        apex_lines: list[str] | None = None,
        vbmeta_flags: int | None = None,
        vbmeta_rollback_index: int = 28,
        vbmeta_system_rollback_index: int = 28,
        vbmeta_system_rollback_index_location: int = 2,
        source_bom_binding: bytes | None = None,
    ) -> None:
        if apex_lines is None:
            apex_lines = [
                'name="com.android.runtime.apex" public_key="runtime.avbpubkey" '
                'private_key="runtime.pem" container_certificate="runtime.x509.pem" '
                'container_private_key="runtime.pk8" partition="system"',
                'name="com.android.wifi.apex" public_key="wifi.avbpubkey" '
                'private_key="wifi.pem" container_certificate="wifi.x509.pem" '
                'container_private_key="wifi.pk8" partition="system"',
                'name="com.android.apex.cts.shim.apex" public_key="PRESIGNED" '
                'private_key="PRESIGNED" container_certificate="PRESIGNED" '
                'container_private_key="PRESIGNED" partition="system"',
            ]
        fingerprint = f"trillionnium/trillionnium_fogos/{device}:16/BUILD/1:{build_type}/{tags}"
        flags = "" if vbmeta_flags is None else f" --flags {vbmeta_flags}"
        misc = "\n".join(
            (
                "ab_update=true",
                "avb_enable=true",
                "avb_vbmeta_algorithm=SHA256_RSA4096",
                "avb_vbmeta_key_path=external/avb/testkey_rsa4096.pem",
                "avb_vbmeta_args=--padding_size 4096 "
                f"--rollback_index {vbmeta_rollback_index}{flags}",
                "avb_vbmeta_system_algorithm=SHA256_RSA2048",
                "avb_vbmeta_system_key_path=external/avb/testkey_rsa2048.pem",
                "avb_vbmeta_system_args=--padding_size 4096 "
                f"--rollback_index {vbmeta_system_rollback_index}",
                "avb_vbmeta_system_rollback_index_location="
                f"{vbmeta_system_rollback_index_location}",
            )
        )
        build_prop = "\n".join(
            (
                f"ro.product.device={device}",
                f"ro.build.type={build_type}",
                f"ro.build.tags={tags}",
                f"ro.build.fingerprint={fingerprint}",
            )
        )
        with zipfile.ZipFile(self.target, "w") as archive:
            archive.writestr("META/misc_info.txt", misc + "\n")
            archive.writestr("META/apexkeys.txt", "\n".join(apex_lines) + "\n")
            archive.writestr("SYSTEM/build.prop", build_prop + "\n")
            if source_bom_binding is not None:
                archive.writestr(
                    "META/trillionnium-source-bom-binding.json",
                    source_bom_binding,
                )

    def source_bom_binding_fixture(self) -> tuple[Path, bytes]:
        """Return a valid source BOM path and matching target-files member."""

        bom = {
            "schema": "org.trillionnium.local-cross-repo-source-bom.v2",
            "decision": "PASS_LOCAL_EXACT_CLEAN_GRAPH",
            "source_set": {
                "schema": "org.trillionnium.p0-cross-repo-source-set.v2",
                "sha256": "1" * 64,
            },
            "resolved_manifest": {
                "sha256": "2" * 64,
                "all_revisions_exact": True,
                "declared_checkout_revision_drift_count": 0,
            },
        }
        bom["receipt_id"] = "sha256:" + RELEASE.sha256_bytes(
            RELEASE.canonical_json_bytes(bom)
        )
        bom_raw = RELEASE.canonical_json_bytes(bom)
        source_set = bom["source_set"]
        manifest = bom["resolved_manifest"]
        assert isinstance(source_set, dict)
        assert isinstance(manifest, dict)
        binding = {
            "schema": "org.trillionnium.android-source-bom-binding.v1",
            "authority": "local_source_provenance_not_release_authority",
            "source_bom": {
                "schema": bom["schema"],
                "receipt_id": bom["receipt_id"],
                "bytes": len(bom_raw),
                "sha256": RELEASE.sha256_bytes(bom_raw),
                "source_set_sha256": source_set["sha256"],
                "resolved_manifest_sha256": manifest["sha256"],
            },
            "source_set": {
                "schema": source_set["schema"],
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
        binding["binding_id"] = "sha256:" + RELEASE.sha256_bytes(
            RELEASE.canonical_json_bytes(binding)
        )
        bom_path = self.root / "source-bom.json"
        bom_path.write_bytes(bom_raw)
        return bom_path, RELEASE.canonical_json_bytes(binding)

    def run_dry(self, *extra: str) -> tuple[int, dict[str, object]]:
        output = io.StringIO()
        with redirect_stdout(output):
            rc = RELEASE.main(
                [
                    "--android-root",
                    str(self.android),
                    "--target-files",
                    str(self.target),
                    "--config",
                    str(self.config),
                    "--dry-run",
                    *extra,
                ]
            )
        return rc, json.loads(output.getvalue())

    def execution_receipt(self, build_type: str) -> dict[str, object]:
        self.write_target(build_type=build_type)
        _, dry_receipt = self.run_dry()
        return {
            "schema": RELEASE.RECEIPT_SCHEMA,
            "decision": RELEASE.execution_decision(build_type, None),
            "build_type": build_type,
            "dry_run": False,
            "config_sha256": "a" * 64,
            "plan": dry_receipt["plan"],
            "release_boundaries": RELEASE.release_boundaries(build_type),
            "material": {},
            "signed_target_files": {"build_type": build_type},
            "signed_target_cryptography": {},
            "signed_full_ab_ota": {"build_type": build_type},
            "quarantined_partial_outputs": [],
            "commands": {},
            "secret_source_paths_recorded": False,
            "private_key_contents_recorded": False,
            "plaintext_passphrases_recorded": False,
            "transient_password_file_retained": False,
            "transient_material_retained": False,
            "device_write_performed": False,
            "public_upload_performed": False,
            "public_release_authorized": False,
            "error": None,
        }

    def run_execution(
        self, build_type: str, *, signed_build_type: str | None = None
    ) -> tuple[int, dict[str, object], dict[str, object]]:
        self.write_target(build_type=build_type)
        key_dir, apex_dir = self.material_directories()
        output_dir = self.root / "output"
        output_dir.mkdir(mode=0o700)
        scratch_dir = self.root / "scratch"
        scratch_dir.mkdir(mode=0o700)
        signed_build_type = signed_build_type or build_type
        signed_fingerprint = (
            "trillionnium/trillionnium_fogos/fogos:16/BUILD/1:"
            f"{signed_build_type}/release-keys"
        )
        original_inspect = RELEASE.inspect_target_files

        def fake_inspect(
            path: Path,
            config: dict[str, object],
            *,
            signed: bool,
            measurement: dict[str, object] | None = None,
        ) -> dict[str, object]:
            if not signed:
                return original_inspect(
                    path, config, signed=False, measurement=measurement
                )
            return {
                "build_type": signed_build_type,
                "fingerprint": signed_fingerprint,
            }

        def fake_run(command: list[str], **kwargs: object) -> tuple[int, float]:
            tool = Path(command[0]).name
            output_log = kwargs["output_log"]
            assert isinstance(output_log, Path)
            output_log.write_text("fixture host tool completed\n", encoding="utf-8")
            if tool == "sign_target_files_apks":
                Path(command[-1]).write_bytes(b"fixture signed target-files\n")
            elif tool == "ota_from_target_files":
                Path(command[-1]).write_bytes(b"fixture signed full OTA\n")
                metadata_index = command.index("--output_metadata_path") + 1
                Path(command[metadata_index]).write_text(
                    "fixture metadata\n", encoding="utf-8"
                )
            return 0, 0.001

        crypto_facts = {
            "apex": {},
            "apex_count": 2,
            "all_apex_payload_keys_exact": True,
            "all_apex_container_certificates_exact": True,
            "avb": {},
            "avb_partition_count": 2,
            "all_avb_images_verified": True,
        }
        ota_facts = {
            "build_type": signed_build_type,
            "post_build": signed_fingerprint,
        }
        output = io.StringIO()
        with (
            mock.patch.object(
                RELEASE, "inspect_target_files", side_effect=fake_inspect
            ),
            mock.patch.object(RELEASE, "run_sanitized", side_effect=fake_run),
            mock.patch.object(
                RELEASE,
                "verify_signed_payload_keys",
                return_value=crypto_facts,
            ),
            mock.patch.object(
                RELEASE, "verify_signed_ota", return_value=ota_facts
            ),
            redirect_stdout(output),
        ):
            rc = RELEASE.main(
                [
                    "--android-root",
                    str(self.android),
                    "--target-files",
                    str(self.target),
                    "--config",
                    str(self.config),
                    "--output-dir",
                    str(output_dir),
                    "--scratch-dir",
                    str(scratch_dir),
                    "--artifact-prefix",
                    "fixture",
                    "--key-dir",
                    str(key_dir),
                    "--apex-key-dir",
                    str(apex_dir),
                ]
            )
        summary = json.loads(output.getvalue())
        receipt_path = output_dir / "fixture-signing-receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        return rc, summary, receipt

    def material_directories(self) -> tuple[Path, Path]:
        key_dir = self.root / "private-apk-avb"
        apex_dir = self.root / "private-apex"
        key_dir.mkdir(mode=0o700)
        apex_dir.mkdir(mode=0o700)
        required = RELEASE.required_material(RELEASE.validate_config(self.config_value))
        for name in required["apk"]:
            content = TEST_CERT if name.endswith(".x509.pem") else b"private-fixture\n"
            if name.endswith(".passphrase"):
                content = b"fixture-passphrase\n"
            path = key_dir / name
            path.write_bytes(content)
            path.chmod(0o600)
        for name in required["apex"]:
            path = apex_dir / name
            path.write_bytes(b"private-apex-fixture\n")
            path.chmod(0o600)
        return key_dir, apex_dir

    def test_dry_run_is_non_secret_and_non_mutating(self) -> None:
        output_dir = self.root / "must-not-exist"
        rc, result = self.run_dry("--output-dir", str(output_dir))
        self.assertEqual(0, rc)
        self.assertEqual(RELEASE.DRY_RUN_USERDEBUG_PASS, result["decision"])
        self.assertEqual("userdebug", result["build_type"])
        self.assertFalse(result["private_material_read"])
        self.assertFalse(result["signing_performed"])
        self.assertFalse(result["device_write_performed"])
        self.assertFalse(result["public_release_authorized"])
        self.assertFalse(output_dir.exists())
        self.assertEqual("fogos", result["plan"]["device"])
        self.assertTrue(result["plan"]["apex_mapping_complete"])
        self.assertEqual(
            "USERDEBUG_NON_RELEASE_HOST_SIGNED_ARTIFACT",
            result["release_boundaries"]["build_classification"],
        )
        self.assertEqual(
            "DENY_USERDEBUG_NON_RELEASE",
            result["release_boundaries"]["release_eligibility"],
        )
        self.assertFalse(result["release_boundaries"]["release_ready"])
        self.assertFalse(result["release_boundaries"]["device_evidence_collected"])
        self.assertIs(result, RELEASE.validate_receipt(result))

    def test_source_bom_binding_is_opt_in_and_requires_bom_path(self) -> None:
        with self.assertRaisesRegex(
            RELEASE.ReleaseError, "--source-bom-binding-bom is required"
        ):
            self.run_dry("--require-source-bom-binding")

        bom_path, _ = self.source_bom_binding_fixture()
        with self.assertRaisesRegex(
            RELEASE.ReleaseError, "requires --require-source-bom-binding"
        ):
            self.run_dry("--source-bom-binding-bom", str(bom_path))

    def test_source_bom_binding_strict_mode_rejects_missing_member(self) -> None:
        bom_path, _ = self.source_bom_binding_fixture()
        with self.assertRaisesRegex(
            RELEASE.ReleaseError, "target_files_source_bom_binding_missing"
        ):
            self.run_dry(
                "--require-source-bom-binding",
                "--source-bom-binding-bom",
                str(bom_path),
            )

    def test_source_bom_binding_strict_mode_rejects_symlinked_bom_parent(self) -> None:
        bom_path, _ = self.source_bom_binding_fixture()
        alias_parent = self.root / "bom-alias"
        alias_parent.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(
            RELEASE.ReleaseError, "path contains a symlink"
        ):
            self.run_dry(
                "--require-source-bom-binding",
                "--source-bom-binding-bom",
                str(alias_parent / bom_path.name),
            )

    def test_source_bom_binding_strict_mode_cross_checks_target_member(self) -> None:
        bom_path, binding = self.source_bom_binding_fixture()
        self.write_target(source_bom_binding=binding)
        rc, result = self.run_dry(
            "--require-source-bom-binding",
            "--source-bom-binding-bom",
            str(bom_path),
        )
        self.assertEqual(0, rc)
        self.assertTrue(result["plan"]["source_bom_binding"]["required"])
        self.assertTrue(result["plan"]["source_bom_binding"]["valid"])
        self.assertIs(result, RELEASE.validate_receipt(result))
        self.assertEqual(
            RELEASE.sha256_bytes(bom_path.read_bytes()),
            result["plan"]["source_bom_binding"]["source_bom"]["sha256"],
        )

    def test_default_mode_does_not_require_source_bom_binding(self) -> None:
        rc, result = self.run_dry()
        self.assertEqual(0, rc)
        self.assertNotIn("source_bom_binding", result["plan"])

    def test_dry_run_can_validate_material_without_staging(self) -> None:
        key_dir, apex_dir = self.material_directories()
        scratch_dir = self.root / "scratch"
        scratch_dir.mkdir(mode=0o700)
        before = set(self.root.iterdir())
        rc, result = self.run_dry(
            "--validate-key-material",
            "--key-dir",
            str(key_dir),
            "--apex-key-dir",
            str(apex_dir),
            "--scratch-dir",
            str(scratch_dir),
        )
        self.assertEqual(0, rc)
        self.assertEqual(RELEASE.DRY_RUN_MATERIAL_USERDEBUG_PASS, result["decision"])
        self.assertTrue(result["private_material_read"])
        self.assertNotIn(str(key_dir), json.dumps(result))
        self.assertEqual(before, set(self.root.iterdir()))

    def test_user_dry_run_is_only_a_host_release_candidate_with_holds(self) -> None:
        self.write_target(build_type="user")
        rc, result = self.run_dry()
        self.assertEqual(0, rc)
        self.assertEqual(RELEASE.DRY_RUN_USER_PASS, result["decision"])
        self.assertNotEqual(RELEASE.DRY_RUN_USERDEBUG_PASS, result["decision"])
        self.assertEqual("user", result["build_type"])
        boundaries = result["release_boundaries"]
        self.assertEqual(
            "USER_RELEASE_CANDIDATE_HOST_ONLY", boundaries["build_classification"]
        )
        self.assertEqual(
            "HOLD_DEVICE_RELEASE_BOUNDARIES_NOT_PROVEN",
            boundaries["release_eligibility"],
        )
        self.assertEqual(
            "HOLD_NOT_PROVEN_BY_HOST_PIPELINE", boundaries["locked_green_device"]
        )
        self.assertEqual(
            "HOLD_NOT_PROVEN_BY_HOST_PIPELINE",
            boundaries["hardware_antirollback"],
        )
        self.assertEqual(
            "HOLD_NOT_PROVEN_BY_HOST_PIPELINE", boundaries["erofs_fsverity"]
        )
        self.assertEqual("HOLD_NOT_AUTHORIZED", boundaries["public_release"])
        self.assertFalse(boundaries["release_ready"])
        self.assertFalse(result["public_release_authorized"])
        self.assertIs(result, RELEASE.validate_receipt(result))

    def test_execution_success_decision_is_build_type_closed(self) -> None:
        self.assertEqual(
            RELEASE.EXECUTION_USER_PASS,
            RELEASE.execution_decision("user", None),
        )
        self.assertEqual(
            RELEASE.EXECUTION_USERDEBUG_PASS,
            RELEASE.execution_decision("userdebug", None),
        )
        self.assertNotEqual(
            RELEASE.execution_decision("user", None),
            RELEASE.execution_decision("userdebug", None),
        )
        self.assertIn("USERDEBUG_NON_RELEASE", RELEASE.EXECUTION_USERDEBUG_PASS)
        self.assertEqual(
            RELEASE.EXECUTION_DENY,
            RELEASE.execution_decision("userdebug", "fixture failure"),
        )
        with self.assertRaisesRegex(RELEASE.ReleaseError, "outside the closed set"):
            RELEASE.execution_decision("eng", None)

    def test_userdebug_host_pipeline_stays_non_release(self) -> None:
        rc, summary, receipt = self.run_execution("userdebug")
        self.assertEqual(0, rc)
        self.assertEqual(RELEASE.EXECUTION_USERDEBUG_PASS, summary["decision"])
        self.assertEqual(RELEASE.EXECUTION_USERDEBUG_PASS, receipt["decision"])
        self.assertEqual("userdebug", summary["build_type"])
        self.assertEqual(
            "DENY_USERDEBUG_NON_RELEASE",
            summary["release_boundaries"]["release_eligibility"],
        )
        self.assertFalse(summary["public_release_authorized"])
        self.assertIs(receipt, RELEASE.validate_receipt(receipt))

    def test_user_host_pipeline_stays_release_candidate_hold(self) -> None:
        rc, summary, receipt = self.run_execution("user")
        self.assertEqual(0, rc)
        self.assertEqual(RELEASE.EXECUTION_USER_PASS, summary["decision"])
        self.assertEqual(RELEASE.EXECUTION_USER_PASS, receipt["decision"])
        self.assertEqual(
            "HOLD_DEVICE_RELEASE_BOUNDARIES_NOT_PROVEN",
            summary["release_boundaries"]["release_eligibility"],
        )
        self.assertFalse(receipt["release_boundaries"]["release_ready"])
        self.assertFalse(receipt["release_boundaries"]["device_evidence_collected"])
        self.assertIs(receipt, RELEASE.validate_receipt(receipt))

    def test_host_pipeline_denies_signed_target_build_type_drift(self) -> None:
        rc, summary, receipt = self.run_execution(
            "user", signed_build_type="userdebug"
        )
        self.assertEqual(1, rc)
        self.assertEqual(RELEASE.EXECUTION_DENY, summary["decision"])
        self.assertEqual(RELEASE.EXECUTION_DENY, receipt["decision"])
        self.assertIn("changed the input build type", receipt["error"])
        self.assertFalse(receipt["public_release_authorized"])
        self.assertIs(receipt, RELEASE.validate_receipt(receipt))

    def test_receipt_schema_and_release_semantics_are_closed_sets(self) -> None:
        receipt = self.execution_receipt("userdebug")
        self.assertIs(receipt, RELEASE.validate_receipt(receipt))

        mutations = (
            (
                "legacy unscoped release decision",
                lambda value: value.__setitem__(
                    "decision", "PASS_RELEASE_SIGNED_FULL_AB_OTA"
                ),
                "execution decision",
            ),
            (
                "user decision on userdebug",
                lambda value: value.__setitem__(
                    "decision", RELEASE.EXECUTION_USER_PASS
                ),
                "execution decision",
            ),
            (
                "claimed locked-green evidence",
                lambda value: value["release_boundaries"].__setitem__(
                    "locked_green_device", "PASS_PROVEN"
                ),
                "release boundaries",
            ),
            (
                "claimed hardware rollback authority",
                lambda value: value["plan"]["rollback_policy"].__setitem__(
                    "hardware_programming_authorized", True
                ),
                "rollback or hardware authority",
            ),
            (
                "legacy receipt schema",
                lambda value: value.__setitem__(
                    "schema", "org.trillionnium.android-release-ota-receipt.v1"
                ),
                "receipt schema",
            ),
            (
                "unknown receipt field",
                lambda value: value.__setitem__("device_claim", True),
                "keys differ",
            ),
        )
        for label, mutate, expected_error in mutations:
            with self.subTest(label=label):
                candidate = copy.deepcopy(receipt)
                mutate(candidate)
                with self.assertRaisesRegex(RELEASE.ReleaseError, expected_error):
                    RELEASE.validate_receipt(candidate)

    def test_success_receipt_rejects_artifact_build_type_drift(self) -> None:
        receipt = self.execution_receipt("user")
        receipt["signed_full_ab_ota"]["build_type"] = "userdebug"
        with self.assertRaisesRegex(RELEASE.ReleaseError, "changed the build type"):
            RELEASE.validate_receipt(receipt)

    def test_staged_material_password_file_is_0600_and_removed(self) -> None:
        key_dir, apex_dir = self.material_directories()
        config = RELEASE.validate_config(self.config_value)
        with RELEASE.staged_material(config, key_dir, apex_dir) as staged:
            runtime = staged["runtime"]
            password_file = staged["password_file"]
            self.assertEqual(0o700, stat.S_IMODE(runtime.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(password_file.stat().st_mode))
            self.assertIn("fixture-passphrase", password_file.read_text())
            self.assertNotIn(str(key_dir), password_file.read_text())
        self.assertFalse(runtime.exists())

    def test_missing_private_apex_handle_fails_closed(self) -> None:
        key_dir, apex_dir = self.material_directories()
        (apex_dir / "apex_wifi.pem").unlink()
        with self.assertRaisesRegex(RELEASE.ReleaseError, "APEX handle apex_wifi.pem"):
            RELEASE.validate_material(
                RELEASE.validate_config(self.config_value), key_dir, apex_dir
            )

    def test_group_readable_private_material_fails_closed(self) -> None:
        key_dir, apex_dir = self.material_directories()
        (key_dir / "releasekey.pk8").chmod(0o640)
        with self.assertRaisesRegex(RELEASE.ReleaseError, "boundary is invalid"):
            RELEASE.validate_material(
                RELEASE.validate_config(self.config_value), key_dir, apex_dir
            )

    def test_incomplete_apex_map_fails_closed(self) -> None:
        broken = copy.deepcopy(self.config_value)
        del broken["signing"]["apex_payload_keys"]["com.android.wifi.apex"]
        self.write_config(broken)
        with self.assertRaisesRegex(RELEASE.ReleaseError, "APEX payload mapping"):
            self.run_dry()

    def test_unexpected_apex_map_fails_closed(self) -> None:
        broken = copy.deepcopy(self.config_value)
        broken["signing"]["apex_payload_keys"][
            "com.android.unexpected.apex"
        ] = "unexpected.pem"
        self.write_config(broken)
        with self.assertRaisesRegex(RELEASE.ReleaseError, "APEX payload mapping"):
            self.run_dry()

    def test_incomplete_avb_map_fails_closed(self) -> None:
        broken = copy.deepcopy(self.config_value)
        del broken["signing"]["avb"]["vbmeta_system"]
        self.write_config(broken)
        with self.assertRaisesRegex(RELEASE.ReleaseError, "AVB mapping"):
            self.run_dry()

    def test_disabled_avb_flags_fail_closed(self) -> None:
        for flags in (1, 2, 3):
            with self.subTest(flags=flags):
                self.write_target(vbmeta_flags=flags)
                with self.assertRaisesRegex(RELEASE.ReleaseError, "AVB flags mismatch"):
                    self.run_dry()

    def test_avb_rollback_policy_drift_fails_closed(self) -> None:
        cases = (
            ({"vbmeta_rollback_index": 27}, "rollback index mismatch for vbmeta"),
            (
                {"vbmeta_system_rollback_index": 29},
                "rollback index mismatch for vbmeta_system",
            ),
            (
                {"vbmeta_system_rollback_index_location": 3},
                "rollback index location mismatch for vbmeta_system",
            ),
        )
        for values, expected in cases:
            with self.subTest(values=values):
                self.write_target(**values)
                with self.assertRaisesRegex(RELEASE.ReleaseError, expected):
                    self.run_dry()

    def test_release_config_requires_zero_flags_and_unique_locations(self) -> None:
        flags = copy.deepcopy(self.config_value)
        flags["signing"]["avb"]["vbmeta"]["expected_flags"] = 3
        with self.assertRaisesRegex(RELEASE.ReleaseError, "flags must be exactly zero"):
            RELEASE.validate_config(flags)

        locations = copy.deepcopy(self.config_value)
        locations["signing"]["avb"]["vbmeta_system"][
            "rollback_index_location"
        ] = 0
        with self.assertRaisesRegex(RELEASE.ReleaseError, "unique and nonzero"):
            RELEASE.validate_config(locations)

        hardware = copy.deepcopy(self.config_value)
        hardware["signing"]["rollback_policy"][
            "hardware_programming_authorized"
        ] = True
        with self.assertRaisesRegex(RELEASE.ReleaseError, "hardware authority"):
            RELEASE.validate_config(hardware)

    def test_aosp_development_certificate_fails_closed(self) -> None:
        key_dir, apex_dir = self.material_directories()
        fixture_digest = RELEASE.cert_digest_from_pem(TEST_CERT)
        with mock.patch.object(
            RELEASE,
            "KNOWN_AOSP_DEVELOPMENT_CERTIFICATE_SHA256",
            frozenset({fixture_digest}),
        ):
            with self.assertRaisesRegex(
                RELEASE.ReleaseError, "AOSP development signing certificate"
            ):
                RELEASE.validate_material(
                    RELEASE.validate_config(self.config_value), key_dir, apex_dir
                )

    def test_aosp_development_avb_private_key_fails_closed(self) -> None:
        key_dir, apex_dir = self.material_directories()
        fixture_digest = RELEASE.sha256_bytes(b"private-fixture\n")
        with mock.patch.object(
            RELEASE,
            "KNOWN_AOSP_DEVELOPMENT_AVB_PRIVATE_KEY_SHA256",
            frozenset({fixture_digest}),
        ):
            with self.assertRaisesRegex(
                RELEASE.ReleaseError, "AOSP development AVB private key"
            ):
                RELEASE.validate_material(
                    RELEASE.validate_config(self.config_value), key_dir, apex_dir
                )

    def test_aosp_development_apk_private_key_fails_closed(self) -> None:
        key_dir, apex_dir = self.material_directories()
        fixture_digest = RELEASE.sha256_bytes(b"private-fixture\n")
        with mock.patch.object(
            RELEASE,
            "KNOWN_AOSP_DEVELOPMENT_APK_PRIVATE_KEY_SHA256",
            frozenset({fixture_digest}),
        ):
            with self.assertRaisesRegex(
                RELEASE.ReleaseError, "AOSP development APK private key"
            ):
                RELEASE.validate_material(
                    RELEASE.validate_config(self.config_value), key_dir, apex_dir
                )

    def test_real_aosp_development_material_matches_fixed_denylists(self) -> None:
        source_value = os.environ.get("TRILLIONNIUM_ANDROID_SOURCE_ROOT")
        if not source_value:
            self.skipTest("TRILLIONNIUM_ANDROID_SOURCE_ROOT is not set")
        source_root = Path(source_value)
        security = source_root / "build/make/target/product/security"
        certificate_digests = {
            "bluetooth.x509.pem": (
                "a6ccc500ff0e7421200eb66a7fe174ef1b00e52ca91727070cbedf061ff76c35"
            ),
            "cts_uicc_2021.x509.pem": (
                "ce7b2b47ae2b7552c8f92cc29124279883041fb623a5f194a82c9bf15d492aa0"
            ),
            "media.x509.pem": (
                "465983f7791f2abeb43ea2cbdc7f21a8260b72bc08a55c839fc1a43bc741a81e"
            ),
            "networkstack.x509.pem": (
                "e1dbadce60dc080d15b58a014b0dcf9400e24de23fa00b287a5a982bfebda2ee"
            ),
            "nfc.x509.pem": (
                "fae9122a8721d6e2a196d2224dffcf773c9127e2bb956cbddb40b009192ffdfd"
            ),
            "platform.x509.pem": (
                "c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8"
            ),
            "sdk_sandbox.x509.pem": (
                "abf21f9e2af1d881cc673fddcefa6ed9c269a437bd64b279cf45844cfd589126"
            ),
            "shared.x509.pem": (
                "28bbfe4a7b97e74681dc55c2fbb6ccb8d6c74963733f6af6ae74d8c3a6e879fd"
            ),
            "testkey.x509.pem": (
                "a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc"
            ),
        }
        observed_certificate_names = {path.name for path in security.glob("*.x509.pem")}
        self.assertEqual(set(certificate_digests), observed_certificate_names)
        production_config = RELEASE.validate_config(
            json.loads(RELEASE.DEFAULT_CONFIG.read_text(encoding="utf-8"))
        )
        configured_certificate_names = {
            f"{source.rsplit('/', 1)[-1]}.x509.pem"
            for source in production_config["signing"]["apk_key_mappings"]
        }
        self.assertLessEqual(configured_certificate_names, set(certificate_digests))
        for name, expected_digest in certificate_digests.items():
            certificate = (security / name).read_bytes()
            certificate_digest = RELEASE.cert_digest_from_pem(certificate)
            self.assertEqual(expected_digest, certificate_digest, name)
            self.assertIn(
                certificate_digest,
                RELEASE.KNOWN_AOSP_DEVELOPMENT_CERTIFICATE_SHA256,
                name,
            )
            with self.assertRaisesRegex(
                RELEASE.ReleaseError, "AOSP development signing certificate"
            ):
                RELEASE.require_non_development_certificate(certificate, name)

        apk_private_key_digests = {
            "bluetooth.pk8": (
                "a471fd99794def737b9f824032a78a80e59e0bd1a0333f1696fed1a117854a6f"
            ),
            "cts_uicc_2021.pk8": (
                "e32e232318d819932340f87efc5390eb2f1453b70093bebae9ec067be50ea39e"
            ),
            "media.pk8": (
                "ab578e1fcc9297cc33202dd1806bd33575c405a5daba34d096da7d7fe30752fc"
            ),
            "networkstack.pk8": (
                "b1b50ff711c9c137593d16b970540d27187fe569ff110da32062c5324ee7b007"
            ),
            "nfc.pk8": (
                "23a018823d64aabecf2c91da0cef7f7bedf06df67122f88e202bb9f4b3d62970"
            ),
            "platform.pk8": (
                "1ad8ef556870edb70f69a9d3c112544c07de5162ba440d84d33f8bb0c5962875"
            ),
            "sdk_sandbox.pk8": (
                "dbc66a830a79a95438016ca5dce12ae624f90d82ab32f5b8b84357b6cc40ba04"
            ),
            "shared.pk8": (
                "561dae618ceeb3b97fe92d71c7af8c30b05bfcda661dbb29dcb3883a772c4685"
            ),
            "testkey.pk8": (
                "495675d32e89a149d5abe191f4e9c0e218b9068714e9b53a7c91e164a0741a23"
            ),
        }
        observed_apk_private_key_names = {
            path.name for path in security.glob("*.pk8")
        }
        self.assertEqual(
            set(apk_private_key_digests), observed_apk_private_key_names
        )
        for name, expected_digest in apk_private_key_digests.items():
            private_bytes = (security / name).read_bytes()
            private_digest = RELEASE.sha256_bytes(private_bytes)
            self.assertEqual(expected_digest, private_digest, name)
            self.assertIn(
                private_digest,
                RELEASE.KNOWN_AOSP_DEVELOPMENT_APK_PRIVATE_KEY_SHA256,
                name,
            )
            with self.assertRaisesRegex(
                RELEASE.ReleaseError, "AOSP development APK private key"
            ):
                RELEASE.require_non_development_apk_private_key(
                    private_bytes, name
                )

        avbtool = source_root / "external/avb/avbtool.py"
        avb_data = source_root / "external/avb/test/data"
        avb_keys = {
            "testkey_rsa2048.pem": (
                "f1d5765a2bdfb92fb08aee021107c7ac1a7a3f590dafd853771c85375ef0fbd7",
                "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c",
            ),
            "testkey_rsa2048_2.pem": (
                "c7011836c52fdeb024f4b5865620133bb3e15df4452bf5bfe709150e289aa21c",
                "2bed47451bc698e9e82d92a6668bd03ab6cf8dd1a144341cb7f426f20b2879cf",
            ),
            "testkey_rsa4096.pem": (
                "6a224754880a57ab9cbd308267cd157d94cf05a1c8cb851aec4090e045d24121",
                "7728e30f50bfa5cea165f473175a08803f6a8346642b5aa10913e9d9e6defef6",
            ),
            "testkey_rsa8192.pem": (
                "a7a9b2eaa8a39867e6c0592b522f4e79210fad5bdfdb618eca1637b95d9983ec",
                "e15e2365469ce672a91d02cc8d9c2f29b787481e574d3b56ac774153d7ced614",
            ),
        }
        observed_private_key_names = {
            path.name
            for path in avb_data.glob("testkey_rsa*.pem")
            if not path.name.endswith("_pub.pem")
        }
        self.assertEqual(set(avb_keys), observed_private_key_names)
        for name, (expected_private_digest, expected_public_digest) in avb_keys.items():
            key = avb_data / name
            private_bytes = key.read_bytes()
            private_digest = RELEASE.sha256_bytes(private_bytes)
            self.assertEqual(expected_private_digest, private_digest, name)
            self.assertIn(
                private_digest,
                RELEASE.KNOWN_AOSP_DEVELOPMENT_AVB_PRIVATE_KEY_SHA256,
                name,
            )
            with self.assertRaisesRegex(
                RELEASE.ReleaseError, "AOSP development AVB private key"
            ):
                RELEASE.require_non_development_avb_private_key(
                    private_bytes, name
                )

            public_key = self.root / f"{name}.avbpubkey"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(avbtool),
                    "extract_public_key",
                    "--key",
                    str(key),
                    "--output",
                    str(public_key),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=120,
            )
            self.assertEqual(0, completed.returncode, completed.stdout)
            public_bytes = public_key.read_bytes()
            public_digest = RELEASE.sha256_bytes(public_bytes)
            self.assertEqual(expected_public_digest, public_digest, name)
            self.assertIn(
                public_digest,
                RELEASE.KNOWN_AOSP_DEVELOPMENT_AVB_PUBLIC_KEY_SHA256,
                name,
            )
            with self.assertRaisesRegex(
                RELEASE.ReleaseError, "AOSP development AVB key"
            ):
                RELEASE.require_non_development_avb_public_key(
                    public_bytes, name
                )

    def test_external_tool_root_is_supported(self) -> None:
        external = self.root / "external-tools"
        external.mkdir()
        (self.android / "out").rename(external / "out")
        rc, result = self.run_dry("--tool-root", str(external))
        self.assertEqual(0, rc)
        self.assertEqual(RELEASE.DRY_RUN_USERDEBUG_PASS, result["decision"])

    def test_exact_android_out_directory_is_supported(self) -> None:
        android_out = self.root / "data-build" / "out"
        android_out.parent.mkdir()
        (self.android / "out").rename(android_out)
        rc, result = self.run_dry("--android-out", str(android_out))
        self.assertEqual(0, rc)
        self.assertEqual(RELEASE.DRY_RUN_USERDEBUG_PASS, result["decision"])

    def test_android_out_and_tool_root_are_mutually_exclusive(self) -> None:
        with self.assertRaisesRegex(RELEASE.ReleaseError, "mutually exclusive"):
            self.run_dry(
                "--android-out",
                str(self.android / "out"),
                "--tool-root",
                str(self.android),
            )

    def test_release_output_and_scratch_directories_are_private_and_empty(self) -> None:
        output = self.root / "output-boundary"
        output.mkdir(mode=0o700)
        self.assertEqual(output, RELEASE.ensure_output_dir(output, ["artifact.zip"]))

        output.chmod(0o755)
        with self.assertRaisesRegex(
            RELEASE.ReleaseError, "group/world accessible|mode 0700"
        ):
            RELEASE.ensure_output_dir(output, ["artifact.zip"])

        scratch = self.root / "scratch-boundary"
        scratch.mkdir(mode=0o700)
        (scratch / "stale").write_text("stale\n", encoding="utf-8")
        with self.assertRaisesRegex(RELEASE.ReleaseError, "must be empty"):
            RELEASE.owned_private_directory(scratch, "scratch", empty=True)

    def test_config_build_types_are_a_typed_closed_set(self) -> None:
        for allowed in (["eng"], ["user", "user"], [True]):
            with self.subTest(allowed=allowed):
                broken = copy.deepcopy(self.config_value)
                broken["product"]["allowed_build_types"] = allowed
                with self.assertRaisesRegex(
                    RELEASE.ReleaseError, "allowed_build_types is invalid"
                ):
                    RELEASE.validate_config(broken)

    def test_wrong_device_fails_closed(self) -> None:
        self.write_target(device="other")
        with self.assertRaisesRegex(RELEASE.ReleaseError, "target device mismatch"):
            self.run_dry()

    def test_release_signed_input_is_not_resigned(self) -> None:
        self.write_target(tags="release-keys")
        with self.assertRaisesRegex(RELEASE.ReleaseError, "unsigned test/dev-key"):
            self.run_dry()

    def test_unknown_build_tags_fail_closed(self) -> None:
        self.write_target(tags="local-keys")
        with self.assertRaisesRegex(RELEASE.ReleaseError, "unsigned test/dev-key"):
            self.run_dry()

    def test_target_files_symlink_fails_closed(self) -> None:
        real = self.root / "real-target-files.zip"
        self.target.rename(real)
        self.target.symlink_to(real)
        with self.assertRaisesRegex(RELEASE.ReleaseError, "stable regular file"):
            self.run_dry()

    def test_config_symlink_fails_closed(self) -> None:
        real = self.root / "real-config.json"
        self.config.rename(real)
        self.config.symlink_to(real)
        with self.assertRaisesRegex(RELEASE.ReleaseError, "stable regular file"):
            self.run_dry()

    def test_host_tool_symlink_fails_closed(self) -> None:
        tool = self.android / "out/host/linux-x86/bin/sign_target_files_apks"
        real = tool.with_name("real-sign-target-files")
        tool.rename(real)
        tool.symlink_to(real.name)
        with self.assertRaisesRegex(RELEASE.ReleaseError, "host tool is unavailable"):
            self.run_dry()

    def test_duplicate_zip_member_fails_closed(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.target, "a") as archive:
                archive.writestr("SYSTEM/build.prop", "duplicate=true\n")
        with self.assertRaisesRegex(RELEASE.ReleaseError, "duplicate target-files ZIP member"):
            self.run_dry()

    def test_ota_certificate_and_metadata_are_exact(self) -> None:
        ota = self.root / "signed-ota.zip"
        metadata = self.root / "metadata.txt"
        with zipfile.ZipFile(ota, "w") as archive:
            archive.writestr("payload.bin", b"payload")
            archive.writestr("payload_properties.txt", "FILE_HASH=fixture\n")
            archive.writestr("META-INF/com/android/otacert", TEST_CERT)
        metadata.write_text(
            "ota-type=AB\n"
            "pre-device=fogos\n"
            "post-build=trillionnium/fogos/fogos:16/BUILD/1:user/release-keys\n",
            encoding="utf-8",
        )
        expected = RELEASE.cert_digest_from_pem(TEST_CERT)
        facts = RELEASE.verify_signed_ota(ota, metadata, "fogos", "user", expected)
        self.assertEqual(expected, facts["certificate_sha256"])
        self.assertEqual("user", facts["build_type"])
        self.assertFalse(facts["wipe"])
        with self.assertRaisesRegex(RELEASE.ReleaseError, "certificate does not match"):
            RELEASE.verify_signed_ota(ota, metadata, "fogos", "user", "0" * 64)
        with self.assertRaisesRegex(RELEASE.ReleaseError, "build-type/release-key"):
            RELEASE.verify_signed_ota(
                ota, metadata, "fogos", "userdebug", expected
            )
        with self.assertRaisesRegex(RELEASE.ReleaseError, "outside the closed set"):
            RELEASE.verify_signed_ota(ota, metadata, "fogos", "eng", expected)

    def test_signed_apex_and_avb_cryptography_is_verified(self) -> None:
        expected_cert = "a" * 64
        public_key = b"fixture-apex-public-key"
        avbtool = self.android / "out/host/linux-x86/bin/avbtool"
        avbtool.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib\n"
            "import sys\n"
            "args = sys.argv[1:]\n"
            "if args[0] == 'extract_public_key':\n"
            "    key = pathlib.Path(args[args.index('--key') + 1]).name\n"
            "    output = pathlib.Path(args[args.index('--output') + 1])\n"
            "    if key.startswith('apex_'):\n"
            "        value = b'fixture-apex-public-key'\n"
            "    elif 'vbmeta_system' in key:\n"
            "        value = b'fixture-vbmeta-system-public-key'\n"
            "    else:\n"
            "        value = b'fixture-vbmeta-public-key'\n"
            "    output.write_bytes(value)\n"
            "elif args[0] == 'verify_image':\n"
            "    image = pathlib.Path(args[args.index('--image') + 1])\n"
            "    if image.name == 'avb-0.img':\n"
            "        marker = args[args.index('--expected_chain_partition') + 1]\n"
            "        assert marker.startswith('vbmeta_system:2:')\n"
            "elif args[0] == 'info_image':\n"
            "    image = pathlib.Path(args[args.index('--image') + 1])\n"
            "    algorithm = 'SHA256_RSA4096' if image.name == 'avb-0.img' else 'SHA256_RSA2048'\n"
            "    print(f'Algorithm:                {algorithm}')\n"
            "    print('Rollback Index:           28')\n"
            "    print('Flags:                    0')\n",
            encoding="utf-8",
        )
        avbtool.chmod(0o755)
        apksigner = self.android / "out/host/linux-x86/bin/apksigner"
        apksigner.write_text(
            "#!/bin/sh\n"
            f"printf 'Signer #1 certificate SHA-256 digest: {expected_cert}\\n'\n",
            encoding="utf-8",
        )
        apksigner.chmod(0o755)
        signed = self.root / "signed-target.zip"
        apex_bytes: dict[str, bytes] = {}
        for package in ("com.android.runtime.apex", "com.android.wifi.apex"):
            nested = io.BytesIO()
            with zipfile.ZipFile(nested, "w") as apex:
                apex.writestr("apex_pubkey", public_key)
            apex_bytes[package] = nested.getvalue()
        with zipfile.ZipFile(signed, "w") as archive:
            archive.writestr(
                "SYSTEM/apex/com.android.runtime.apex",
                apex_bytes["com.android.runtime.apex"],
            )
            archive.writestr(
                "SYSTEM/apex/com.android.wifi.capex",
                apex_bytes["com.android.wifi.apex"],
            )
            archive.writestr("IMAGES/vbmeta.img", b"vbmeta")
            archive.writestr("IMAGES/vbmeta_system.img", b"vbmeta-system")
        material = self.root / "staged-material"
        runtime = self.root / "runtime"
        material.mkdir()
        runtime.mkdir()
        config = RELEASE.validate_config(self.config_value)
        for key in config["signing"]["apex_payload_keys"].values():
            (material / key).write_text("private\n", encoding="utf-8")
        for item in config["signing"]["avb"].values():
            (material / item["key"]).write_text("private\n", encoding="utf-8")
        tools = {
            name: self.android / relative for name, relative in config["tools"].items()
        }
        facts = RELEASE.verify_signed_payload_keys(
            signed, config, material, tools, runtime, expected_cert
        )
        self.assertTrue(facts["all_apex_payload_keys_exact"])
        self.assertTrue(facts["all_apex_container_certificates_exact"])
        self.assertTrue(facts["all_avb_images_verified"])
        self.assertEqual(2, facts["apex_count"])
        self.assertEqual(2, facts["avb_partition_count"])
        self.assertEqual(0, facts["avb"]["vbmeta"]["flags"])
        self.assertEqual(28, facts["avb"]["vbmeta"]["rollback_index"])
        self.assertEqual(0, facts["avb"]["vbmeta"]["rollback_index_location"])
        self.assertEqual(
            2, facts["avb"]["vbmeta_system"]["rollback_index_location"]
        )
        self.assertRegex(
            facts["avb"]["vbmeta_system"]["public_key_sha256"], r"^[0-9a-f]{64}$"
        )

    def test_avb_info_requires_nonempty_exact_fields(self) -> None:
        for raw in (
            "",
            "Algorithm: SHA256_RSA4096\nRollback Index: 28\n",
            "Algorithm: SHA256_RSA4096\nRollback Index: 28\nFlags: 0\nFlags: 0\n",
        ):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(RELEASE.ReleaseError, "AVB info"):
                    RELEASE.parse_avb_info(raw, "vbmeta")

    def test_sanitizer_removes_paths_passphrases_and_private_blocks(self) -> None:
        sanitizer = RELEASE.Sanitizer(
            [Path("/private/signing-material")], ["top-secret-passphrase"]
        )
        self.assertNotIn(
            "top-secret-passphrase",
            sanitizer.line("password top-secret-passphrase\n"),
        )
        self.assertNotIn(
            "/private/signing-material",
            sanitizer.line("path=/private/signing-material/key.pk8\n"),
        )
        self.assertEqual(
            "<redacted-private-key-material>\n",
            sanitizer.line("-----BEGIN PRIVATE KEY-----\n"),
        )
        retired_secret_path = "/home/fixture/." + "open" + "claw/secrets/token"
        self.assertNotIn(
            retired_secret_path,
            sanitizer.line(f"path={retired_secret_path}\n"),
        )
        self.assertEqual("", sanitizer.line("private bytes\n"))
        self.assertEqual("", sanitizer.line("-----END PRIVATE KEY-----\n"))

    def test_secret_evidence_guard_rejects_plaintext(self) -> None:
        evidence = self.root / "bad.log"
        evidence.write_text("fixture-passphrase\n", encoding="utf-8")
        with self.assertRaisesRegex(RELEASE.ReleaseError, "secret leak guard"):
            RELEASE.no_secret_evidence([evidence], ["fixture-passphrase"])


if __name__ == "__main__":
    unittest.main()
