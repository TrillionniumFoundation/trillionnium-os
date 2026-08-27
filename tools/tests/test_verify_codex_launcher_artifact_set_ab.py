from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/verify_codex_launcher_artifact_set_ab.py"
SPEC = importlib.util.spec_from_file_location("launcher_artifact_set_ab", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def fake_elf(seed: bytes) -> bytes:
    value = bytearray(512)
    value[:4] = b"\x7fELF"
    value[4] = 2
    value[5] = 1
    value[16:18] = (3).to_bytes(2, "little")
    value[18:20] = (183).to_bytes(2, "little")
    value[64 : 64 + len(seed)] = seed
    return bytes(value)


def mode(path: Path) -> int:
    return path.stat().st_mode & 0o7777


class Fixture:
    def __init__(self, root: Path, lane: str = "common") -> None:
        self.root = root
        self.lane = lane
        self.a = root / "launcher-a"
        self.b = root / "launcher-b"
        self.raw = root / "raw-ab"
        self.output = root / "output"
        self.tools = root / "tools"
        self.tool_lane_a = root / "tool-lane-a"
        self.tool_lane_b = root / "tool-lane-b"
        for directory in (self.a, self.b, self.raw, self.output, self.tools):
            directory.mkdir(mode=0o700)
        self.compiler_bytes = fake_elf(b"fixed-aarch64-gcc")
        self.archiver_bytes = fake_elf(b"ar")
        self.readelf_bytes = fake_elf(b"fixed-aarch64-readelf")
        self.write_target_toolchain(self.tool_lane_a)
        self.write_target_toolchain(self.tool_lane_b)
        self.compiler_a = (
            self.tool_lane_a
            / "toolchain/sysroot/usr/bin/aarch64-linux-gnu-gcc-12"
        )
        self.compiler_b = (
            self.tool_lane_b
            / "toolchain/sysroot/usr/bin/aarch64-linux-gnu-gcc-12"
        )
        self.readelf_a = (
            self.tool_lane_a
            / "toolchain/sysroot/usr/bin/aarch64-linux-gnu-readelf"
        )
        self.readelf_b = (
            self.tool_lane_b
            / "toolchain/sysroot/usr/bin/aarch64-linux-gnu-readelf"
        )
        self.artifacts = {
            role: fake_elf(role.encode("ascii"))
            for role in VERIFIER.LANES[lane]["artifacts"]
        }
        launcher_markers = [
            VERIFIER.CODEX_RUNTIME_SHA256,
            sha256(self.artifacts["system_api_tool"]),
        ]
        if lane == "common":
            launcher_markers.append(sha256(self.artifacts["accessibility_tool"]))
        self.artifacts["codex_launcher"] = fake_elf(b"codex-launcher") + "".join(
            launcher_markers
        ).encode("ascii")
        self.raw_receipt = self.make_raw_receipt()
        self.write_raw_receipt()
        self.a_receipt = self.make_launcher_receipt(self.compiler_a, self.readelf_a)
        self.b_receipt = self.make_launcher_receipt(self.compiler_b, self.readelf_b)
        self.write_launcher(self.a, self.a_receipt)
        self.write_launcher(self.b, self.b_receipt)

    def write_target_toolchain(self, lane_root: Path) -> None:
        compiler_bin = lane_root / "toolchain/sysroot/usr/bin"
        compiler_bin.mkdir(parents=True, mode=0o700)
        for filename, raw in (
            ("aarch64-linux-gnu-gcc-12", self.compiler_bytes),
            ("aarch64-linux-gnu-ar", self.archiver_bytes),
            ("aarch64-linux-gnu-readelf", self.readelf_bytes),
        ):
            path = compiler_bin / filename
            path.write_bytes(raw)
            path.chmod(0o555)

    def source_raw(self) -> dict[str, object]:
        return {
            "schema": VERIFIER.SOURCE_SCHEMA,
            "decision": VERIFIER.SOURCE_DECISION,
            "bytes": 123456,
            "sha256": "1" * 64,
            "receipt_id": "sha256:" + "2" * 64,
            "source_set_sha256": "3" * 64,
            "resolved_manifest_sha256": "4" * 64,
            "live_full_remeasurement_before_and_after_build": True,
            "byte_equal_to_each_live_remeasurement": True,
            "authority": "local_source_measurement_not_release_authority",
        }

    def source_launcher(self) -> dict[str, object]:
        raw = self.raw_receipt["source_bom"]
        return {
            "file_sha256": raw["sha256"],
            "bytes": raw["bytes"],
            "receipt_id": raw["receipt_id"],
            "control_head": "5" * 40,
            "source_set_sha256": raw["source_set_sha256"],
            "resolved_manifest_sha256": raw["resolved_manifest_sha256"],
            "authority": "local_exact_clean_graph_not_build_or_release_authority",
        }

    def tool_record(self, role: str) -> dict[str, object]:
        if role == "linker":
            raw = self.compiler_bytes
            version = "aarch64-linux-gnu-gcc fixed\nCopyright fixed"
            file_mode = "0555"
        elif role == "readelf":
            raw = self.readelf_bytes
            version = "GNU readelf fixed\nCopyright fixed"
            file_mode = "0555"
        elif role == "ar":
            raw = self.archiver_bytes
            version = "ar fixed"
            file_mode = "0555"
        else:
            raw = fake_elf(role.encode("ascii"))
            version = f"{role} fixed"
            file_mode = "0555"
        return {
            "bytes": len(raw),
            "sha256": sha256(raw),
            "mode": file_mode,
            "version": version,
        }

    @staticmethod
    def toolchain_snapshot() -> dict[str, object]:
        return {
            "schema": "org.trillionnium.packaging.mobian-toolchain-snapshot-binding.v1",
            "manifest_schema": "org.trillionnium.packaging.mobian-toolchain-snapshot-manifest.v1",
            "manifest_sha256": "735fab7c0ded3d37e53ac8295c32e7a3a1547ba54e603e74f25e83de2f8c541f",
            "manifest_bytes": 8_375_893,
            "manifest_id": "d3ef19017ab4499243936ff65db4d2b50fce1536a9127f2d7ea3e7468784ebb4",
            "tree_digest": "6335b8cb911852156b10eec32ba08d9730b51a8ca0b0b04abfefa0b6ef7a4367",
            "entry_count": 33_930,
            "regular_bytes": 1_952_702_440,
            "closed_world": True,
            "target_sysroot_relative_path": "toolchain/sysroot",
            "target_compiler_relative_path": "toolchain/sysroot/usr/bin/aarch64-linux-gnu-gcc-12",
            "target_compiler_bin_relative_path": "toolchain/sysroot/usr/bin",
            "target_gcc_libdir_relative_path": "toolchain/sysroot/usr/lib/gcc-cross/aarch64-linux-gnu/12",
            "target_binutils_relative_path": "toolchain/sysroot/usr/aarch64-linux-gnu/bin",
            "target_host_runtime_libdir_relative_path": "toolchain/sysroot/usr/lib/x86_64-linux-gnu",
        }

    @staticmethod
    def target_compiler_closure() -> dict[str, object]:
        return {
            "schema": "org.trillionnium.target-compiler-effective-closure.v1",
            "target": "aarch64-linux-gnu",
            "normalized_search_arguments": [
                "--sysroot=$TARGET_SYSROOT",
                "-B$TARGET_COMPILER_BIN",
                "-B$TARGET_GCC_LIBDIR",
                "-B$TARGET_BINUTILS_DIR",
            ],
            "reported_sysroot": "$TARGET_SYSROOT",
            "components": {
                role: dict(record)
                for role, record in VERIFIER.raw_ab_contract.EXPECTED_RESOLVED_COMPONENTS.items()
            },
            "snapshot_tree_fully_remeasured_before_and_after_build": True,
            "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed": False,
            "complete_host_execution_runtime_closure": False,
        }

    def make_raw_receipt(self) -> dict[str, object]:
        specification = VERIFIER.LANES[self.lane]
        receipt: dict[str, object] = {
            "schema": VERIFIER.RAW_SCHEMA,
            "decision": VERIFIER.RAW_DECISION,
            "release_status": VERIFIER.RAW_HOLD,
            "lane": specification["raw_lane"],
            "variant": specification["raw_variant"],
            "target": VERIFIER.TARGET,
            "source_bom": self.source_raw(),
            "build_semantics_sha256": "6" * 64,
            "normalized_receipt_semantics_sha256": "7" * 64,
            "selected_tool_identities": {
                role: self.tool_record(role)
                for role in (
                    "cargo",
                    "rustc",
                    "host_linker",
                    "linker",
                    "ar",
                    "readelf",
                )
            },
            "toolchain_snapshot": self.toolchain_snapshot(),
            "target_compiler_closure": self.target_compiler_closure(),
            "tool_paths_may_differ_and_are_excluded_from_identity": True,
            "inputs": {
                side: {
                    "receipt_file": specification["raw_receipt"],
                    "receipt_bytes": 1000,
                    "receipt_sha256": ("8" if side == "a" else "9") * 64,
                    "receipt_id": "sha256:" + ("a" if side == "a" else "b") * 64,
                }
                for side in ("a", "b")
            },
            "artifacts": {
                role: {
                    "file": specification["artifacts"][role],
                    "bytes": len(self.artifacts[role]),
                    "sha256": sha256(self.artifacts[role]),
                    "a_receipt_bound": True,
                    "b_receipt_bound": True,
                    "a_b_byte_equal": True,
                }
                for role in specification["raw_roles"]
            },
            "comparisons": {
                "same_lane": True,
                "same_upstream_source_bom_receipt_claim": True,
                "physical_source_bom_or_live_graph_remeasured_by_this_stage": False,
                "receipt_ids_are_content_identifiers_only": True,
                "receipt_ids_are_signatures_or_attestations": False,
                "same_build_semantics": True,
                "same_selected_tool_bytes_sha256_versions": True,
                "same_non_path_receipt_semantics": True,
                "exact_bidirectional_directory_receipt_binding": True,
                "physical_elf_bytes_equal_by_role": True,
                "physical_input_directories_distinct": True,
                "physical_input_artifact_inodes_distinct": True,
                "physical_target_toolchain_roots_distinct": True,
                "physical_target_sysroots_distinct": True,
                "physical_selected_target_tool_inodes_distinct": True,
                "stable_full_input_reread_passed": True,
            },
            "posture": {
                "host_only": True,
                "deterministic_raw_elf_ab_verified": True,
                "complete_toolchain_byte_closure": False,
                "launcher_built": False,
                "rootfs_built": False,
                "device_execution_verified": False,
                "avb_or_ota_verified": False,
                "release_allowed": False,
                "device_write_authorized": False,
            },
            "limitations": [
                "raw_elf_ab_does_not_prove_complete_toolchain_byte_closure",
                "raw_elf_ab_does_not_prove_launcher_rootfs_android_device_avb_or_ota",
                "source_bom_is_an_upstream_receipt_claim_not_physically_remeasured_by_this_stage",
                "receipt_ids_are_content_identifiers_not_signatures_or_attestations",
                "receipt_tool_paths_are_physical_custody_inputs_but_excluded_from_ab_semantic_identity",
            ],
            "receipt_id_scope": VERIFIER.RECEIPT_ID_SCOPE,
        }
        receipt["receipt_id"] = "sha256:" + sha256(
            VERIFIER.canonical_json_bytes(receipt)
        )
        return receipt

    def build_tool_custody(
        self, path: Path, role: str, raw: bytes, version: str
    ) -> dict[str, object]:
        metadata = path.stat()
        return {
            "schema": VERIFIER.LAUNCHER_BUILD_TOOL_SCHEMA,
            "role": role,
            "path": str(path),
            "bytes": len(raw),
            "sha256": sha256(raw),
            "mode": f"0{mode(path):o}",
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "link_count": metadata.st_nlink,
            "version": version,
            "target": VERIFIER.LAUNCHER_BUILD_TOOL_TARGET,
            "execution": {
                "mechanism": "retained_open_file_description_via_proc_self_fd",
                "measured_before_first_execution": True,
                "all_invocations_used_same_open_file_description": True,
                "descriptor_and_path_stable_after_last_execution": True,
                "ambient_environment_inherited": False,
                "environment_allowlist": VERIFIER.LAUNCHER_BUILD_ENVIRONMENT_ALLOWLIST,
            },
            "complete_recursive_toolchain_closure": False,
        }

    def make_launcher_receipt(
        self, compiler: Path, inspector: Path
    ) -> dict[str, object]:
        specification = VERIFIER.LANES[self.lane]
        artifact_records = {
            role: {
                "file": filename,
                "sha256": sha256(self.artifacts[role]),
                "bytes": len(self.artifacts[role]),
            }
            for role, filename in specification["artifacts"].items()
        }
        launcher_sha = artifact_records["codex_launcher"]["sha256"]
        inputs = {
            "codex_runtime_sha256": VERIFIER.CODEX_RUNTIME_SHA256,
            "codex_runtime_bytes": VERIFIER.CODEX_RUNTIME_BYTES,
            "codex_launcher_source_sha256": "d" * 64,
        }
        for role, input_field in specification["raw_roles"].items():
            inputs[input_field] = self.raw_receipt["artifacts"][role]["sha256"]
        stable_measurement = {
            "status": "host_measurement_only_avb_slot_admission_absent",
            "stable_principal_contract_sha256": (
                VERIFIER.STABLE_PRINCIPAL_CONTRACT_SHA256
            ),
            "stable_principal_canonical_sha256": (
                VERIFIER.STABLE_PRINCIPAL_CANONICAL_SHA256
            ),
            "launcher_executable_sha256": launcher_sha,
            "launcher_identity_source": "measured_after_closed_launcher_inputs",
            "executable_identity_is_stable_registry_input": False,
        }
        gate = {
            "status": "hold_identity_independence_evidence_unverified",
            "literal_digest_absence_verified": True,
            "digests": dict(VERIFIER.LEGACY_DESCRIPTOR_DIGESTS),
            "counterfactual_same_source_rebuild": {
                "required": True,
                "verified": False,
                "evidence_receipt": None,
            },
            "stable_principal_admission_split": {
                "required": True,
                "verified": False,
                "evidence_receipt": None,
            },
        }
        common = {
            "schema": specification["schema"],
            "receipt_role": "common_rootfs_complete_measured_build_input",
            "status": "host_built_device_evidence_hold",
            "product_variant": "common",
            "common_direct_tool_posture": "inert_no_default_features_fail_closed",
            "stable_principal_launcher_measurement": stable_measurement,
            "legacy_descriptor_contamination_hold_gate": gate,
            "accessibility_available": False,
            "dependency_graph": VERIFIER.COMMON_DEPENDENCY_GRAPH,
            "source_bom": self.source_launcher(),
            "compiler": self.build_tool_custody(
                compiler,
                "compiler_driver",
                self.compiler_bytes,
                "aarch64-linux-gnu-gcc fixed",
            ),
            "elf_inspector": self.build_tool_custody(
                inspector,
                "elf_inspector",
                self.readelf_bytes,
                "GNU readelf fixed",
            ),
            "toolchain_snapshot": self.toolchain_snapshot(),
            "target_compiler_closure": self.target_compiler_closure(),
            "inputs": inputs,
            "artifacts": artifact_records,
            "rootfs_build_required": True,
            "device_execution_verified": False,
            "release_allowed": False,
        }
        if self.lane == "common":
            return common
        daemon_build_binding = {
            "schema": "org.trillionnium.p01-userdebug-daemon-build-binding.v2",
            "sha256_scope": (
                "sha256(canonical-json-utf8-sort-keys-indent-2-lf-of-daemon_build_binding)"
            ),
            "product_variant": "userdebug",
            "feature_profile": {
                "cargo_package": "trillionniumd",
                "enabled_cargo_features": ["p0-launch-package-device-conformance"],
                "default_cargo_features": [],
                "conformance_build_variant": "userdebug",
            },
            "cargo_profile": {
                "name": "release",
                "opt_level": "3",
                "debug": 0,
                "debug_assertions": False,
                "incremental": False,
                "strip": "symbols",
            },
            "build_policy": {
                "cargo_incremental": "0",
                "normalized_rustflags": list(
                    VERIFIER.DAEMON_NORMALIZED_RUSTFLAGS
                ),
                "normalized_native_environment": {
                    "CC_aarch64_unknown_linux_gnu": "$RETAINED_TARGET_COMPILER",
                    "AR_aarch64_unknown_linux_gnu": "$RETAINED_TARGET_ARCHIVER",
                    "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER": "$RETAINED_TARGET_COMPILER",
                    "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_AR": "$RETAINED_TARGET_ARCHIVER",
                    "CFLAGS_aarch64_unknown_linux_gnu": "--sysroot=$TARGET_SYSROOT -B$TARGET_COMPILER_BIN -B$TARGET_GCC_LIBDIR -B$TARGET_BINUTILS_DIR",
                    "CXXFLAGS_aarch64_unknown_linux_gnu": "--sysroot=$TARGET_SYSROOT -B$TARGET_COMPILER_BIN -B$TARGET_GCC_LIBDIR -B$TARGET_BINUTILS_DIR",
                },
                "selected_native_tools": {
                    "compiler": {
                        "relative_path": "toolchain/sysroot/usr/bin/aarch64-linux-gnu-gcc-12",
                        "bytes": 1_315_296,
                        "sha256": "c7b8890354c8ddc0364addfeb8968597e197627bd1e338fb6ed705b578803846",
                        "mode": "0555",
                    },
                    "archiver": {
                        "relative_path": "toolchain/sysroot/usr/bin/aarch64-linux-gnu-ar",
                        "bytes": 68_920,
                        "sha256": "086da15d802a53c33c0aeccfb2de663f724edab8fdca7e10b242cfefe24673dc",
                        "mode": "0555",
                    },
                },
                "host_runtime_execution_boundary": {
                    "snapshot_usr_lib_relative_path": "toolchain/sysroot/usr/lib/x86_64-linux-gnu",
                    "cargo_target_dir_subpaths_may_be_prepended": True,
                    "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed": False,
                },
                "source_date_epoch": 1_785_110_400,
            },
            "target_profile": {
                "rust_target_triple": "aarch64-unknown-linux-gnu",
                "architecture": "aarch64",
                "operating_system": "linux",
                "libc_family": "glibc",
                "dynamic_interpreter": "/lib/ld-linux-aarch64.so.1",
                "maximum_glibc": "GLIBC_2.36",
                "runtime_base_contract": "debian-bookworm-arm64",
            },
            "runtime_artifact_sha256": {
                role: artifact_records[role]["sha256"]
                for role in (
                    "system_api_tool",
                    "replay_sync_helper",
                    "high_water_authority",
                    "codex_launcher",
                )
            },
            "stable_principal": {
                "authority": "stable_principal_registry_v2",
                "contract_sha256": VERIFIER.STABLE_PRINCIPAL_CONTRACT_SHA256,
                "canonical_sha256": VERIFIER.STABLE_PRINCIPAL_CANONICAL_SHA256,
            },
            "identity_independence_hold": {
                "schema": (
                    "org.trillionnium.p01-userdebug-identity-independence-hold.v1"
                ),
                "status": "hold_identity_independence_evidence_unverified",
                "profile_sha256": sha256(VERIFIER.canonical_json_bytes(gate)),
            },
            "toolchain_snapshot": self.toolchain_snapshot(),
            "target_compiler_closure": self.target_compiler_closure(),
        }
        return {
            "schema": specification["schema"],
            "receipt_role": "final_daemon_build_binding_envelope",
            "status": "host_built_device_evidence_hold",
            "product_variant": "userdebug",
            "selected_system_api_sha256": inputs["system_api_tool_input_sha256"],
            "principal_authority": "stable_principal_registry_v2",
            "legacy_descriptor_executable_identity_is_principal_authority": False,
            "runtime_policy_launcher_measurement_migration": (
                "active_launcher_separate_from_stable_principal"
            ),
            "product_effect_authority_available": False,
            "accessibility_available": False,
            "dependency_graph": VERIFIER.P01_DEPENDENCY_GRAPH,
            "source_bom": self.source_launcher(),
            "daemon_build_binding": daemon_build_binding,
            "stable_principal_launcher_measurement": stable_measurement,
            "legacy_descriptor_contamination_hold_gate": gate,
            "compiler": self.build_tool_custody(
                compiler,
                "compiler_driver",
                self.compiler_bytes,
                "aarch64-linux-gnu-gcc fixed",
            ),
            "elf_inspector": self.build_tool_custody(
                inspector,
                "elf_inspector",
                self.readelf_bytes,
                "GNU readelf fixed",
            ),
            "inputs": inputs,
            "artifacts": artifact_records,
            "daemon_build_required": True,
            "device_execution_verified": False,
            "release_allowed": False,
        }

    def write_raw_receipt(self) -> None:
        path = self.raw / "codex-only-raw-elf-ab.v3.json"
        path.write_bytes(VERIFIER.canonical_json_bytes(self.raw_receipt))
        path.chmod(0o444)

    def rewrite_raw_receipt(self) -> None:
        path = self.raw / "codex-only-raw-elf-ab.v3.json"
        path.chmod(0o600)
        self.raw_receipt.pop("receipt_id", None)
        self.raw_receipt["receipt_id"] = "sha256:" + sha256(
            VERIFIER.canonical_json_bytes(self.raw_receipt)
        )
        path.write_bytes(VERIFIER.canonical_json_bytes(self.raw_receipt))
        path.chmod(0o444)

    def write_launcher(self, directory: Path, receipt: dict[str, object]) -> None:
        for role, filename in VERIFIER.LANES[self.lane]["artifacts"].items():
            path = directory / filename
            path.write_bytes(self.artifacts[role])
            path.chmod(0o555)
        receipt_path = directory / VERIFIER.LANES[self.lane]["receipt"]
        receipt_path.write_bytes(VERIFIER.canonical_json_bytes(receipt))
        receipt_path.chmod(0o444)

    def rewrite_launcher(self, directory: Path, receipt: dict[str, object]) -> None:
        path = directory / VERIFIER.LANES[self.lane]["receipt"]
        path.chmod(0o600)
        path.write_bytes(VERIFIER.canonical_json_bytes(receipt))
        path.chmod(0o444)

    def args(self) -> argparse.Namespace:
        receipt = str(VERIFIER.LANES[self.lane]["receipt"])
        return argparse.Namespace(
            lane=self.lane,
            a_artifact_dir=self.a,
            a_receipt=self.a / receipt,
            b_artifact_dir=self.b,
            b_receipt=self.b / receipt,
            raw_ab_receipt=self.raw / "codex-only-raw-elf-ab.v3.json",
            output_dir=self.output,
        )


class LauncherArtifactSetAbTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._expected_target_tool_identities = copy.deepcopy(
            VERIFIER.raw_ab_contract.EXPECTED_TARGET_TOOL_IDENTITIES
        )
        compiler = fake_elf(b"fixed-aarch64-gcc")
        archiver = fake_elf(b"ar")
        readelf = fake_elf(b"fixed-aarch64-readelf")
        VERIFIER.raw_ab_contract.EXPECTED_TARGET_TOOL_IDENTITIES = {
            "linker": {
                "bytes": len(compiler),
                "sha256": sha256(compiler),
                "mode": "0555",
                "version": "aarch64-linux-gnu-gcc fixed\nCopyright fixed",
            },
            "ar": {
                "bytes": len(archiver),
                "sha256": sha256(archiver),
                "mode": "0555",
                "version": "ar fixed",
            },
            "readelf": {
                "bytes": len(readelf),
                "sha256": sha256(readelf),
                "mode": "0555",
                "version": "GNU readelf fixed\nCopyright fixed",
            },
        }

    @classmethod
    def tearDownClass(cls) -> None:
        VERIFIER.raw_ab_contract.EXPECTED_TARGET_TOOL_IDENTITIES = (
            cls._expected_target_tool_identities
        )

    def test_device_inode_uses_stat_device_not_sequence_mode_slot(self) -> None:
        metadata = os.stat(__file__)
        expected = (metadata.st_dev, metadata.st_ino)
        self.assertEqual(VERIFIER.device_inode(metadata), expected)
        self.assertEqual(
            VERIFIER.device_inode(VERIFIER.stable_identity(metadata)), expected
        )

    def test_valid_common_ab_is_canonical_host_only_hold(self) -> None:
        self.assertEqual(
            VERIFIER.RECEIPT_ID_SCOPE,
            "sha256(canonical-json-utf8-sort-keys-indent-2-lf-without-receipt_id)",
        )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            result = VERIFIER.verify(fixture.args())
            self.assertEqual(result["decision"], VERIFIER.OUTPUT_DECISION)
            self.assertEqual(result["status"], VERIFIER.OUTPUT_HOLD)
            self.assertFalse(result["release_allowed"])
            self.assertFalse(
                result["posture"]["identity_independence_counterfactual_verified"]
            )
            self.assertTrue(result["posture"]["build_time_compiler_bytes_bound"])
            self.assertTrue(
                result["posture"]["build_time_elf_inspector_bytes_bound"]
            )
            self.assertTrue(
                result["compiler"]["post_build_matches_raw_ab_selected_linker"]
            )
            self.assertTrue(
                result["elf_inspector"][
                    "post_build_matches_raw_ab_selected_readelf"
                ]
            )
            for field in (
                "physical_input_directories_distinct",
                "physical_input_artifact_inodes_distinct",
                "physical_target_toolchain_roots_distinct",
                "physical_target_sysroots_distinct",
                "physical_selected_target_tool_inodes_distinct",
            ):
                self.assertTrue(result["comparisons"][field])
            self.assertTrue(
                result["comparisons"]["same_upstream_source_bom_receipt_claim"]
            )
            self.assertFalse(
                result["comparisons"][
                    "physical_source_bom_or_live_graph_remeasured_by_this_stage"
                ]
            )
            self.assertTrue(
                result["comparisons"]["receipt_ids_are_content_identifiers_only"]
            )
            self.assertFalse(
                result["comparisons"][
                    "receipt_ids_are_signatures_or_attestations"
                ]
            )
            self.assertTrue(
                result["comparisons"][
                    "post_build_target_archiver_matches_raw_ab_selected_ar"
                ]
            )
            self.assertEqual(result["schema"], VERIFIER.OUTPUT_SCHEMA)
            output = fixture.output / VERIFIER.OUTPUT_NAME
            raw = output.read_bytes()
            self.assertEqual(raw, VERIFIER.canonical_json_bytes(json.loads(raw)))
            self.assertEqual(mode(output), 0o444)
            self.assertEqual(output.stat().st_nlink, 1)
            expected = dict(result)
            receipt_id = expected.pop("receipt_id")
            self.assertEqual(
                receipt_id,
                "sha256:" + sha256(VERIFIER.canonical_json_bytes(expected)),
            )

    def test_valid_p01_v8_ab_propagates_the_same_unresolved_hold(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary), "p01_userdebug_pre_daemon")
            result = VERIFIER.verify(fixture.args())
            self.assertEqual(result["lane"], "p01_userdebug_pre_daemon")
            self.assertEqual(result["status"], VERIFIER.OUTPUT_HOLD)
            self.assertFalse(result["release_allowed"])
            self.assertEqual(
                result["identity_independence_gate"],
                fixture.a_receipt["legacy_descriptor_contamination_hold_gate"],
            )
            self.assertNotIn("daemon", result["artifacts"])
            self.assertEqual(result["schema"], VERIFIER.P01_OUTPUT_SCHEMA)
            self.assertTrue((fixture.output / VERIFIER.P01_OUTPUT_NAME).is_file())

    def test_p01_target_abi_binding_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary), "p01_userdebug_pre_daemon")
            for directory, receipt in (
                (fixture.a, fixture.a_receipt),
                (fixture.b, fixture.b_receipt),
            ):
                receipt["daemon_build_binding"]["target_profile"][
                    "maximum_glibc"
                ] = "GLIBC_2.37"
                fixture.rewrite_launcher(directory, receipt)
            with self.assertRaisesRegex(
                VERIFIER.VerificationError, "target profile|binding profile"
            ):
                VERIFIER.verify(fixture.args())

    def test_p01_extra_normalized_rustflag_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary), "p01_userdebug_pre_daemon")
            for directory, receipt in (
                (fixture.a, fixture.a_receipt),
                (fixture.b, fixture.b_receipt),
            ):
                receipt["daemon_build_binding"]["build_policy"][
                    "normalized_rustflags"
                ].extend(["-C", "target-cpu=native"])
                fixture.rewrite_launcher(directory, receipt)
            with self.assertRaisesRegex(
                VERIFIER.VerificationError, "binding profile differs"
            ):
                VERIFIER.verify(fixture.args())

    def test_superseded_raw_ab_v1_receipt_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            fixture.raw_receipt["schema"] = (
                "org.trillionnium.codex-only-raw-elf-ab.v1"
            )
            fixture.rewrite_raw_receipt()
            with self.assertRaisesRegex(
                VERIFIER.VerificationError, "header or lane differs"
            ):
                VERIFIER.verify(fixture.args())

    def test_superseded_p01_v6_receipt_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary), "p01_userdebug_pre_daemon")
            v8_name = str(VERIFIER.LANES[fixture.lane]["receipt"])
            v6_name = "p01-userdebug-pre-daemon-artifact-set.v6.json"
            for directory, receipt in (
                (fixture.a, fixture.a_receipt),
                (fixture.b, fixture.b_receipt),
            ):
                path = directory / v8_name
                path.chmod(0o600)
                path.unlink()
                receipt["schema"] = (
                    "org.trillionnium.p01-userdebug-pre-daemon-artifact-set.v6"
                )
                receipt.pop("legacy_descriptor_contamination_hold_gate")
                old = directory / v6_name
                old.write_bytes(VERIFIER.canonical_json_bytes(receipt))
                old.chmod(0o444)
            args = fixture.args()
            args.a_receipt = fixture.a / v6_name
            args.b_receipt = fixture.b / v6_name
            with self.assertRaisesRegex(VERIFIER.VerificationError, "filename differs"):
                VERIFIER.verify(args)

    def test_physical_tamper_and_missing_artifact_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            path = fixture.a / "trillionnium-agent-system-api"
            path.chmod(0o600)
            path.write_bytes(fake_elf(b"tampered"))
            path.chmod(0o555)
            with self.assertRaisesRegex(VERIFIER.VerificationError, "differs from its receipt"):
                VERIFIER.verify(fixture.args())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            (fixture.a / "trillionnium-agent-system-api").unlink()
            with self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.verify(fixture.args())

    def test_ab_launcher_difference_is_rejected_even_when_b_receipt_is_rebound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            different = fake_elf(b"different-launcher") + b"".join(
                digest.encode("ascii")
                for digest in (
                    fixture.b_receipt["inputs"]["codex_runtime_sha256"],
                    fixture.b_receipt["inputs"]["system_api_tool_input_sha256"],
                    fixture.b_receipt["inputs"]["accessibility_tool_input_sha256"],
                )
            )
            filename = VERIFIER.LANES["common"]["artifacts"]["codex_launcher"]
            path = fixture.b / filename
            path.chmod(0o600)
            path.write_bytes(different)
            path.chmod(0o555)
            digest = sha256(different)
            fixture.b_receipt["artifacts"]["codex_launcher"].update(
                {"bytes": len(different), "sha256": digest}
            )
            fixture.b_receipt["stable_principal_launcher_measurement"][
                "launcher_executable_sha256"
            ] = digest
            fixture.rewrite_launcher(fixture.b, fixture.b_receipt)
            with self.assertRaisesRegex(VERIFIER.VerificationError, "receipts differ"):
                VERIFIER.verify(fixture.args())

    def test_raw_source_and_artifact_splices_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            fixture.raw_receipt["source_bom"]["sha256"] = "f" * 64
            fixture.rewrite_raw_receipt()
            with self.assertRaisesRegex(VERIFIER.VerificationError, "source BOM bindings differ"):
                VERIFIER.verify(fixture.args())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            fixture.raw_receipt["artifacts"]["system_api_tool"]["sha256"] = "f" * 64
            fixture.rewrite_raw_receipt()
            with self.assertRaisesRegex(VERIFIER.VerificationError, "not bidirectionally bound"):
                VERIFIER.verify(fixture.args())

    def test_p01_launcher_source_is_cross_bound_to_raw_ab(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary), "p01_userdebug_pre_daemon")
            for directory, receipt in (
                (fixture.a, fixture.a_receipt),
                (fixture.b, fixture.b_receipt),
            ):
                receipt["source_bom"]["file_sha256"] = "f" * 64
                fixture.rewrite_launcher(directory, receipt)
            with self.assertRaisesRegex(
                VERIFIER.VerificationError, "source BOM bindings differ"
            ):
                VERIFIER.verify(fixture.args())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary), "p01_userdebug_pre_daemon")
            for directory, receipt in (
                (fixture.a, fixture.a_receipt),
                (fixture.b, fixture.b_receipt),
            ):
                receipt["source_bom"]["unexpected"] = True
                fixture.rewrite_launcher(directory, receipt)
            with self.assertRaisesRegex(
                VERIFIER.VerificationError,
                "launcher source BOM schema is not closed",
            ):
                VERIFIER.verify(fixture.args())

    def test_compiler_path_swap_not_matching_raw_linker_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            replacement = fixture.tools / "other-gcc"
            replacement.write_bytes(fake_elf(b"other"))
            replacement.chmod(0o555)
            fixture.a_receipt["compiler"]["path"] = str(replacement)
            fixture.rewrite_launcher(fixture.a, fixture.a_receipt)
            with self.assertRaisesRegex(
                VERIFIER.VerificationError, "build-time custody or raw A/B"
            ):
                VERIFIER.verify(fixture.args())

    def test_elf_inspector_path_swap_not_matching_raw_readelf_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            replacement = fixture.tools / "other-readelf"
            replacement.write_bytes(fake_elf(b"other-readelf"))
            replacement.chmod(0o555)
            fixture.a_receipt["elf_inspector"]["path"] = str(replacement)
            fixture.rewrite_launcher(fixture.a, fixture.a_receipt)
            with self.assertRaisesRegex(
                VERIFIER.VerificationError, "build-time custody or raw A/B"
            ):
                VERIFIER.verify(fixture.args())

    def test_receipt_path_swap_and_schema_drift_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            args = fixture.args()
            args.a_receipt = fixture.b / VERIFIER.LANES["common"]["receipt"]
            with self.assertRaisesRegex(VERIFIER.VerificationError, "direct child"):
                VERIFIER.verify(args)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            fixture.a_receipt["schema"] = "org.trillionnium.wrong"
            fixture.rewrite_launcher(fixture.a, fixture.a_receipt)
            with self.assertRaisesRegex(VERIFIER.VerificationError, "header"):
                VERIFIER.verify(fixture.args())

    def test_symlink_and_hardlink_artifacts_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            filename = "trillionnium-agent-system-api"
            target = fixture.a / filename
            target.unlink()
            target.symlink_to(fixture.b / filename)
            with self.assertRaisesRegex(VERIFIER.VerificationError, "symlink"):
                VERIFIER.verify(fixture.args())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            target = fixture.a / "trillionnium-agent-system-api"
            alias = fixture.root / "artifact-hardlink"
            os.link(target, alias)
            with self.assertRaisesRegex(VERIFIER.VerificationError, "one link"):
                VERIFIER.verify(fixture.args())

    def test_physical_a_b_aliases_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            args = fixture.args()
            args.b_artifact_dir = fixture.a / ".." / "launcher-a"
            args.b_receipt = fixture.a / VERIFIER.LANES[fixture.lane]["receipt"]
            with self.assertRaisesRegex(
                VERIFIER.VerificationError,
                "same physical directory",
            ):
                VERIFIER.verify(args)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            args = fixture.args()
            args.raw_ab_receipt = fixture.a / "codex-only-raw-elf-ab.v3.json"
            with self.assertRaisesRegex(
                VERIFIER.VerificationError,
                "same physical directory",
            ):
                VERIFIER.verify(args)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            linked_input = fixture.root / "launcher-a-link"
            linked_input.symlink_to(fixture.a, target_is_directory=True)
            args = fixture.args()
            args.a_artifact_dir = linked_input
            args.a_receipt = linked_input / VERIFIER.LANES[fixture.lane]["receipt"]
            with self.assertRaisesRegex(
                VERIFIER.VerificationError,
                "symbolic link|symlink in its path",
            ):
                VERIFIER.verify(args)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            fixture.b_receipt["compiler"]["path"] = str(fixture.compiler_a)
            fixture.b_receipt["elf_inspector"]["path"] = str(fixture.readelf_a)
            fixture.rewrite_launcher(fixture.b, fixture.b_receipt)
            with self.assertRaisesRegex(
                VERIFIER.VerificationError,
                "toolchain roots are the same physical directory",
            ):
                VERIFIER.verify(fixture.args())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            b_sysroot = fixture.tool_lane_b / "toolchain/sysroot"
            shutil.rmtree(b_sysroot)
            b_sysroot.symlink_to(fixture.tool_lane_a / "toolchain/sysroot")
            with self.assertRaisesRegex(
                VERIFIER.VerificationError,
                "symbolic link|symlink in its path|target sysroot is unavailable or is a symlink|"
                "target sysroots are the same physical directory",
            ):
                VERIFIER.verify(fixture.args())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            b_bin = fixture.tool_lane_b / "toolchain/sysroot/usr/bin"
            shutil.rmtree(b_bin)
            b_bin.symlink_to(fixture.tool_lane_a / "toolchain/sysroot/usr/bin")
            with self.assertRaisesRegex(
                VERIFIER.VerificationError,
                "symbolic link|symlink in its path|selected target tools reuse",
            ):
                VERIFIER.verify(fixture.args())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            filename = VERIFIER.LANES[fixture.lane]["artifacts"]["system_api_tool"]
            b_artifact = fixture.b / filename
            b_artifact.unlink()
            os.link(fixture.a / filename, b_artifact)
            with self.assertRaisesRegex(
                VERIFIER.VerificationError,
                "one link|reuse one or more physical inodes",
            ):
                VERIFIER.verify(fixture.args())

    def test_target_archiver_and_fixed_tool_layout_are_physically_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            archiver = (
                fixture.tool_lane_b
                / "toolchain/sysroot/usr/bin/aarch64-linux-gnu-ar"
            )
            archiver.chmod(0o600)
            archiver.write_bytes(fake_elf(b"tampered-ar"))
            archiver.chmod(0o555)
            with self.assertRaisesRegex(
                VERIFIER.VerificationError,
                "target archiver differs from raw A/B selected ar",
            ):
                VERIFIER.verify(fixture.args())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            replacement = fixture.tools / "same-bytes-gcc"
            replacement.write_bytes(fixture.compiler_bytes)
            replacement.chmod(0o555)
            fixture.a_receipt["compiler"]["path"] = str(replacement)
            fixture.rewrite_launcher(fixture.a, fixture.a_receipt)
            with self.assertRaisesRegex(
                VERIFIER.VerificationError,
                "compiler is outside the fixed snapshot layout",
            ):
                VERIFIER.verify(fixture.args())

    def test_retained_tool_path_drift_before_publication_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            target = fixture.compiler_b
            original_finalize = VERIFIER.finalize_receipt

            def finalize_and_replace(value: dict[str, object]) -> bytes:
                result = original_finalize(value)
                replacement = target.with_name(target.name + ".replacement")
                replacement.write_bytes(target.read_bytes())
                replacement.chmod(0o555)
                os.replace(replacement, target)
                return result

            VERIFIER.finalize_receipt = finalize_and_replace
            try:
                with self.assertRaisesRegex(
                    VERIFIER.VerificationError,
                    "retained (?:pathname|directory) changed|"
                    "inputs changed before publication",
                ):
                    VERIFIER.verify(fixture.args())
            finally:
                VERIFIER.finalize_receipt = original_finalize
            output_name = VERIFIER.LANES[fixture.lane]["output_name"]
            self.assertFalse((fixture.output / output_name).exists())

    def test_retained_input_and_output_directory_path_swaps_are_rejected(self) -> None:
        for target_kind in ("input", "output"):
            with self.subTest(target_kind=target_kind), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                original_finalize = VERIFIER.finalize_receipt

                def finalize_and_swap(value: dict[str, object]) -> bytes:
                    result = original_finalize(value)
                    target = fixture.a if target_kind == "input" else fixture.output
                    held = target.with_name(target.name + ".held")
                    target.rename(held)
                    if target_kind == "input":
                        shutil.copytree(held, target)
                    else:
                        target.mkdir(mode=0o700)
                    os.chmod(target, 0o700)
                    return result

                VERIFIER.finalize_receipt = finalize_and_swap
                try:
                    with self.assertRaisesRegex(
                        VERIFIER.VerificationError,
                        "retained pathname changed|retained directory changed|"
                        "launcher directory changed while read",
                    ):
                        VERIFIER.verify(fixture.args())
                finally:
                    VERIFIER.finalize_receipt = original_finalize
                output_name = VERIFIER.LANES[fixture.lane]["output_name"]
                self.assertFalse((fixture.output / output_name).exists())

    def test_published_aggregate_path_and_bytes_are_revalidated(self) -> None:
        for mutation in ("replace", "in_place"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                original_write = VERIFIER.write_exclusive_at

                def mutate_after_write(
                    directory: int, name: str, value: bytes
                ) -> VERIFIER.RetainedPublishedFile:
                    retained = original_write(directory, name, value)
                    target = fixture.output / name
                    if mutation == "replace":
                        replacement = target.with_name(target.name + ".replacement")
                        replacement.write_bytes(value)
                        replacement.chmod(0o444)
                        os.replace(replacement, target)
                    else:
                        target.chmod(0o600)
                        target.write_bytes(b"corrupt-but-pass\n")
                        target.chmod(0o444)
                    return retained

                VERIFIER.write_exclusive_at = mutate_after_write
                try:
                    with self.assertRaisesRegex(
                        VERIFIER.VerificationError,
                        "descriptor, pathname, or bytes changed",
                    ):
                        VERIFIER.verify(fixture.args())
                finally:
                    VERIFIER.write_exclusive_at = original_write

    def test_input_artifact_in_place_mutation_during_publication_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            filename = str(
                VERIFIER.LANES[fixture.lane]["artifacts"]["system_api_tool"]
            )
            target = fixture.a / filename
            original_write = VERIFIER.write_exclusive_at

            def mutate_then_write(
                directory: int, name: str, value: bytes
            ) -> VERIFIER.RetainedPublishedFile:
                target.chmod(0o755)
                target.write_bytes(fake_elf(b"post-reread-in-place-tamper"))
                target.chmod(0o555)
                return original_write(directory, name, value)

            VERIFIER.write_exclusive_at = mutate_then_write
            try:
                with self.assertRaisesRegex(
                    VERIFIER.VerificationError,
                    "retained pathname or bytes changed",
                ):
                    VERIFIER.verify(fixture.args())
            finally:
                VERIFIER.write_exclusive_at = original_write
            output_name = str(VERIFIER.LANES[fixture.lane]["output_name"])
            self.assertFalse((fixture.output / output_name).exists())

    def test_counterfactual_false_claim_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            gate = fixture.a_receipt["legacy_descriptor_contamination_hold_gate"]
            gate["counterfactual_same_source_rebuild"].update(
                {"verified": True, "evidence_receipt": "sha256:" + "f" * 64}
            )
            fixture.rewrite_launcher(fixture.a, fixture.a_receipt)
            with self.assertRaisesRegex(VERIFIER.VerificationError, "must remain required"):
                VERIFIER.verify(fixture.args())

    def test_claimed_legacy_digest_absence_is_remeasured(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            role = "codex_launcher"
            filename = VERIFIER.LANES["common"]["artifacts"][role]
            contaminated = fixture.artifacts[role] + VERIFIER.LEGACY_DESCRIPTOR_DIGESTS[
                "launcher identity"
            ].encode("ascii")
            for directory, receipt in (
                (fixture.a, fixture.a_receipt),
                (fixture.b, fixture.b_receipt),
            ):
                path = directory / filename
                path.chmod(0o600)
                path.write_bytes(contaminated)
                path.chmod(0o555)
                digest = sha256(contaminated)
                receipt["artifacts"][role].update(
                    {"bytes": len(contaminated), "sha256": digest}
                )
                receipt["stable_principal_launcher_measurement"][
                    "launcher_executable_sha256"
                ] = digest
                fixture.rewrite_launcher(directory, receipt)
            with self.assertRaisesRegex(VERIFIER.VerificationError, "embeds legacy"):
                VERIFIER.verify(fixture.args())

    def test_output_must_be_empty_private_0700(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            fixture.output.chmod(0o750)
            with self.assertRaisesRegex(VERIFIER.VerificationError, "0700"):
                VERIFIER.verify(fixture.args())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            (fixture.output / "occupied").write_bytes(b"x")
            with self.assertRaisesRegex(VERIFIER.VerificationError, "must be empty"):
                VERIFIER.verify(fixture.args())


if __name__ == "__main__":
    unittest.main()
