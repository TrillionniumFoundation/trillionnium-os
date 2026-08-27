from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/materialize_p01_final_daemon_artifact.py"
SPEC = importlib.util.spec_from_file_location("p01_final_v5", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MATERIALIZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATERIALIZER)


def aarch64_elf(payload: bytes) -> bytes:
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", header, 16, 3)
    struct.pack_into("<H", header, 18, 183)
    return bytes(header) + payload


class P01FinalDaemonArtifactTests(unittest.TestCase):
    def test_import_disables_bytecode_before_loading_shared_primitives(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        assignment = source.index("sys.dont_write_bytecode = True")
        shared_import = source.index(
            "import build_p01_userdebug_agent_launchers as primitives"
        )
        self.assertLess(assignment, shared_import)

    def test_raw_receipt_scope_names_indented_lf_encoding(self) -> None:
        self.assertEqual(
            MATERIALIZER.RAW_RECEIPT_ID_SCOPE,
            "sha256(canonical-json-utf8-sort-keys-indent-2-lf-without-receipt_id)",
        )

    def test_launcher_build_environment_allowlist_matches_real_producer(self) -> None:
        self.assertEqual(
            MATERIALIZER.LAUNCHER_BUILD_ENVIRONMENT_ALLOWLIST,
            list(MATERIALIZER.primitives.LAUNCHER_BUILD_ENVIRONMENT_ALLOWLIST),
        )
        self.assertIn(
            "LD_LIBRARY_PATH",
            MATERIALIZER.LAUNCHER_BUILD_ENVIRONMENT_ALLOWLIST,
        )

    maxDiff = None

    def setUp(self) -> None:
        # Launcher and selected raw-build tools are traversed component by
        # component without following links.  Keep the fixture below an
        # owner-controlled parent rather than the world-writable /tmp tree.
        self.temporary = tempfile.TemporaryDirectory(
            prefix="p01-final-v5-test.", dir=Path.home()
        )
        self.root = Path(self.temporary.name)
        self.source_bom = self.root / "source-bom.json"
        self.source_bom_bytes = MATERIALIZER.canonical_json(
            {"fixture": "canonical-source-bom-v2"}
        )
        self.write(self.source_bom, self.source_bom_bytes, 0o444)
        self.source_binding = {
            "file_sha256": MATERIALIZER.sha256(self.source_bom_bytes),
            "bytes": len(self.source_bom_bytes),
            "receipt_id": "sha256:" + "1" * 64,
            "control_head": "2" * 40,
            "source_set_sha256": "3" * 64,
            "resolved_manifest_sha256": "4" * 64,
            "authority": "local_exact_clean_graph_not_build_or_release_authority",
        }
        control_head = MATERIALIZER.primitives.git_output(
            MATERIALIZER.CONTROL_REPOSITORY,
            ["rev-parse", "HEAD"],
            "test control head",
        ).decode("ascii").strip()
        control_tree = MATERIALIZER.primitives.git_output(
            MATERIALIZER.CONTROL_REPOSITORY,
            ["rev-parse", "HEAD^{tree}"],
            "test control tree",
        ).decode("ascii").strip()
        object_format = MATERIALIZER.primitives.git_output(
            MATERIALIZER.CONTROL_REPOSITORY,
            ["rev-parse", "--show-object-format"],
            "test control object format",
        ).decode("ascii").strip()
        self.authority_source_bom_bytes = MATERIALIZER.canonical_json(
            {
                "projects": [
                    {
                        "id": "control_plane",
                        "git": {
                            "head": control_head,
                            "head_tree": control_tree,
                            "object_format": object_format,
                        },
                    }
                ]
            }
        )
        self.raw_source_binding = {
            "schema": MATERIALIZER.primitives.SOURCE_BOM_SCHEMA,
            "decision": MATERIALIZER.primitives.SOURCE_BOM_PASS,
            "bytes": self.source_binding["bytes"],
            "sha256": self.source_binding["file_sha256"],
            "receipt_id": self.source_binding["receipt_id"],
            "source_set_sha256": self.source_binding["source_set_sha256"],
            "resolved_manifest_sha256": self.source_binding[
                "resolved_manifest_sha256"
            ],
            "live_full_remeasurement_before_and_after_build": True,
            "byte_equal_to_each_live_remeasurement": True,
            "authority": "local_source_measurement_not_release_authority",
        }
        self.stable_contract = self.root / "agent-principal-registry-v2.json"
        self.stable_contract_bytes = MATERIALIZER.STABLE_PRINCIPAL_CONTRACT.read_bytes()
        self.write(self.stable_contract, self.stable_contract_bytes, 0o444)
        stable_value = json.loads(self.stable_contract_bytes)
        self.stable_contract_sha = MATERIALIZER.sha256(self.stable_contract_bytes)
        self.stable_canonical_sha = MATERIALIZER.sha256(
            MATERIALIZER.stable_principal_projection(stable_value)
        )
        self.toolchain_manifest = self.root / "mobian-toolchain-snapshot.manifest.v1.json"
        self.toolchain_manifest_bytes = MATERIALIZER.canonical_json(
            {"fixture": "closed-world-mobian-toolchain-manifest"}
        )
        self.write(self.toolchain_manifest, self.toolchain_manifest_bytes, 0o444)
        self.toolchain_snapshot = {
            "schema": MATERIALIZER.primitives.TOOLCHAIN_SNAPSHOT_BINDING_SCHEMA,
            "manifest_schema": MATERIALIZER.primitives.TOOLCHAIN_MANIFEST_SCHEMA,
            "manifest_sha256": MATERIALIZER.primitives.FROZEN_TOOLCHAIN_MANIFEST_SHA256,
            "manifest_bytes": 8_375_893,
            "manifest_id": MATERIALIZER.primitives.FROZEN_TOOLCHAIN_MANIFEST_ID,
            "tree_digest": MATERIALIZER.primitives.FROZEN_TOOLCHAIN_TREE_DIGEST,
            "entry_count": MATERIALIZER.primitives.FROZEN_TOOLCHAIN_ENTRY_COUNT,
            "regular_bytes": MATERIALIZER.primitives.FROZEN_TOOLCHAIN_REGULAR_BYTES,
            "closed_world": True,
            "target_sysroot_relative_path": "toolchain/sysroot",
            "target_compiler_relative_path": (
                "toolchain/sysroot/usr/bin/aarch64-linux-gnu-gcc-12"
            ),
            "target_compiler_bin_relative_path": "toolchain/sysroot/usr/bin",
            "target_gcc_libdir_relative_path": (
                "toolchain/sysroot/usr/lib/gcc-cross/aarch64-linux-gnu/12"
            ),
            "target_binutils_relative_path": (
                "toolchain/sysroot/usr/aarch64-linux-gnu/bin"
            ),
            "target_host_runtime_libdir_relative_path": (
                "toolchain/sysroot/usr/lib/x86_64-linux-gnu"
            ),
        }
        self.target_compiler_closure = {
            "schema": MATERIALIZER.primitives.TARGET_COMPILER_CLOSURE_SCHEMA,
            "target": "aarch64-linux-gnu",
            "normalized_search_arguments": [
                "--sysroot=$TARGET_SYSROOT",
                "-B$TARGET_COMPILER_BIN",
                "-B$TARGET_GCC_LIBDIR",
                "-B$TARGET_BINUTILS_DIR",
            ],
            "reported_sysroot": "$TARGET_SYSROOT",
            "components": {
                role: dict(value)
                for role, value in MATERIALIZER.raw_ab_contract.EXPECTED_RESOLVED_COMPONENTS.items()
            },
            "snapshot_tree_fully_remeasured_before_and_after_build": True,
            "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed": False,
            "complete_host_execution_runtime_closure": False,
        }
        self.launcher_tool_root = self.root / "toolchain/sysroot/usr/bin"
        self.launcher_tool_root.mkdir(mode=0o700, parents=True)
        for directory in (
            self.root / "toolchain",
            self.root / "toolchain/sysroot",
            self.root / "toolchain/sysroot/usr",
            self.launcher_tool_root,
        ):
            directory.chmod(0o700)
        self.compiler_path = self.launcher_tool_root / "aarch64-linux-gnu-gcc-12"
        self.archiver_path = self.launcher_tool_root / "aarch64-linux-gnu-ar"
        self.inspector_path = self.launcher_tool_root / "aarch64-linux-gnu-readelf"
        self.compiler_bytes = aarch64_elf(b"fixture-launcher-compiler")
        self.archiver_bytes = aarch64_elf(b"fixture-target-archiver")
        self.inspector_bytes = aarch64_elf(b"fixture-launcher-elf-inspector")
        self.compiler_version = "fixture linker"
        self.archiver_version = "fixture archiver"
        self.inspector_version = "fixture readelf"
        self.write(self.compiler_path, self.compiler_bytes, 0o555)
        self.write(self.archiver_path, self.archiver_bytes, 0o555)
        self.write(self.inspector_path, self.inspector_bytes, 0o555)
        self._expected_target_tool_identities = copy.deepcopy(
            MATERIALIZER.raw_ab_contract.EXPECTED_TARGET_TOOL_IDENTITIES
        )
        MATERIALIZER.raw_ab_contract.EXPECTED_TARGET_TOOL_IDENTITIES = {
            "linker": {
                "bytes": len(self.compiler_bytes),
                "sha256": MATERIALIZER.sha256(self.compiler_bytes),
                "mode": "0555",
                "version": self.compiler_version,
            },
            "ar": {
                "bytes": len(self.archiver_bytes),
                "sha256": MATERIALIZER.sha256(self.archiver_bytes),
                "mode": "0555",
                "version": self.archiver_version,
            },
            "readelf": {
                "bytes": len(self.inspector_bytes),
                "sha256": MATERIALIZER.sha256(self.inspector_bytes),
                "mode": "0555",
                "version": self.inspector_version,
            },
        }
        self._daemon_build_policy = copy.deepcopy(
            MATERIALIZER.primitives.DAEMON_BUILD_POLICY
        )
        MATERIALIZER.primitives.DAEMON_BUILD_POLICY["selected_native_tools"] = {
            "compiler": {
                "relative_path": (
                    "toolchain/sysroot/usr/bin/aarch64-linux-gnu-gcc-12"
                ),
                **MATERIALIZER.raw_ab_contract.EXPECTED_TARGET_TOOL_IDENTITIES[
                    "linker"
                ],
            },
            "archiver": {
                "relative_path": "toolchain/sysroot/usr/bin/aarch64-linux-gnu-ar",
                **MATERIALIZER.raw_ab_contract.EXPECTED_TARGET_TOOL_IDENTITIES["ar"],
            },
        }
        for record in MATERIALIZER.primitives.DAEMON_BUILD_POLICY[
            "selected_native_tools"
        ].values():
            record.pop("version")
        self.pre_a = self.root / "pre-a"
        self.make_pre(self.pre_a)
        self._real_materialize = MATERIALIZER.materialize

        def materialize_with_fixture_manifest(*args, **kwargs):
            kwargs.setdefault("toolchain_manifest", self.toolchain_manifest)
            return self._real_materialize(*args, **kwargs)

        MATERIALIZER.materialize = materialize_with_fixture_manifest

    def tearDown(self) -> None:
        MATERIALIZER.materialize = self._real_materialize
        MATERIALIZER.raw_ab_contract.EXPECTED_TARGET_TOOL_IDENTITIES = (
            self._expected_target_tool_identities
        )
        MATERIALIZER.primitives.DAEMON_BUILD_POLICY.clear()
        MATERIALIZER.primitives.DAEMON_BUILD_POLICY.update(
            self._daemon_build_policy
        )
        self.temporary.cleanup()

    @staticmethod
    def write(path: Path, value: bytes, mode: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        path.chmod(mode)

    def make_toolchain_lane(
        self, label: str
    ) -> tuple[Path, Path, Path, Path, Path]:
        lane_root = self.root / label
        manifest = lane_root / "mobian-toolchain-snapshot.manifest.v1.json"
        self.write(manifest, self.toolchain_manifest_bytes, 0o444)
        tool_root = lane_root / "toolchain/sysroot/usr/bin"
        compiler = tool_root / "aarch64-linux-gnu-gcc-12"
        archiver = tool_root / "aarch64-linux-gnu-ar"
        inspector = tool_root / "aarch64-linux-gnu-readelf"
        self.write(compiler, self.compiler_bytes, 0o555)
        self.write(archiver, self.archiver_bytes, 0o555)
        self.write(inspector, self.inspector_bytes, 0o555)
        for directory in (
            lane_root,
            lane_root / "toolchain",
            lane_root / "toolchain/sysroot",
            lane_root / "toolchain/sysroot/usr",
            tool_root,
        ):
            directory.chmod(0o700)
        return lane_root, manifest, compiler, archiver, inspector

    def retarget_pre_to_toolchain_lane(
        self, pre_root: Path, compiler: Path, inspector: Path
    ) -> None:
        self.mutate_receipt(
            pre_root,
            lambda value: (
                value["compiler"].__setitem__("path", str(compiler)),
                value["elf_inspector"].__setitem__("path", str(inspector)),
            ),
        )

    def artifact_bytes(self) -> dict[str, bytes]:
        system = aarch64_elf(
            b"|".join(
                (
                    b"trillionnium.p0-device-conformance-activation-snapshot.v1",
                    b"com.android.settings",
                    b"trillionnium-agent-system-api-p0-1-device-conformance",
                    b"org.trillionnium.p01.conformance.compiled-variant.v1=userdebug",
                )
            )
        )
        replay = aarch64_elf(
            b"|".join(
                (
                    b"trillionnium.p0-replay-sync-ack-confirmation.v1",
                    b"non_product_userdebug_daemon_custody",
                    b"P0-2 sealed replay authority changed before ACTIVATE",
                    b"org.trillionnium.p01.conformance.compiled-variant.v1=userdebug",
                )
            )
        )
        high_water = aarch64_elf(
            b"trillionnium.direct-operation-custody-high-water-authority.v2"
        )
        runtime_sha = "5" * 64
        launcher = aarch64_elf(
            b"launcher|"
            + MATERIALIZER.sha256(system).encode("ascii")
            + b"|"
            + runtime_sha.encode("ascii")
        )
        return {
            "system_api_tool": system,
            "replay_sync_helper": replay,
            "high_water_authority": high_water,
            "codex_launcher": launcher,
        }

    def launcher_tool_record(
        self, path: Path, value: bytes, role: str, version: str
    ) -> dict[str, object]:
        metadata = path.stat()
        return {
            "schema": MATERIALIZER.LAUNCHER_BUILD_TOOL_SCHEMA,
            "role": role,
            "path": str(path),
            "bytes": len(value),
            "sha256": MATERIALIZER.sha256(value),
            "mode": f"0{stat.S_IMODE(metadata.st_mode):o}",
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "link_count": 1,
            "version": version,
            "target": "aarch64-linux-gnu",
            "execution": {
                "mechanism": "retained_open_file_description_via_proc_self_fd",
                "measured_before_first_execution": True,
                "all_invocations_used_same_open_file_description": True,
                "descriptor_and_path_stable_after_last_execution": True,
                "ambient_environment_inherited": False,
                "environment_allowlist": (
                    MATERIALIZER.LAUNCHER_BUILD_ENVIRONMENT_ALLOWLIST
                ),
            },
            "complete_recursive_toolchain_closure": False,
        }

    def pre_receipt(self, artifacts: dict[str, bytes]) -> dict[str, object]:
        launcher_sha = MATERIALIZER.sha256(artifacts["codex_launcher"])
        identity_gate = {
            "status": "hold_identity_independence_evidence_unverified",
            "literal_digest_absence_verified": True,
            "digests": MATERIALIZER.legacy_descriptor_digests(),
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
        return {
            "schema": MATERIALIZER.PRE_DAEMON_SCHEMA,
            "receipt_role": "final_daemon_build_binding_envelope",
            "status": "host_built_device_evidence_hold",
            "product_variant": "userdebug",
            "selected_system_api_sha256": MATERIALIZER.sha256(
                artifacts["system_api_tool"]
            ),
            "principal_authority": "stable_principal_registry_v2",
            "legacy_descriptor_executable_identity_is_principal_authority": False,
            "runtime_policy_launcher_measurement_migration": (
                "active_launcher_separate_from_stable_principal"
            ),
            "product_effect_authority_available": False,
            "accessibility_available": False,
            "dependency_graph": MATERIALIZER.primitives.DEPENDENCY_GRAPH,
            "source_bom": self.source_binding,
            "daemon_build_binding": MATERIALIZER.primitives.daemon_build_binding(
                artifacts,
                identity_gate,
                self.toolchain_snapshot,
                self.target_compiler_closure,
            ),
            "stable_principal_launcher_measurement": {
                "status": "host_measurement_only_avb_slot_admission_absent",
                "stable_principal_contract_sha256": self.stable_contract_sha,
                "stable_principal_canonical_sha256": self.stable_canonical_sha,
                "launcher_executable_sha256": launcher_sha,
                "launcher_identity_source": "measured_after_closed_launcher_inputs",
                "executable_identity_is_stable_registry_input": False,
            },
            "legacy_descriptor_contamination_hold_gate": identity_gate,
            "compiler": self.launcher_tool_record(
                self.compiler_path,
                self.compiler_bytes,
                "compiler_driver",
                self.compiler_version,
            ),
            "elf_inspector": self.launcher_tool_record(
                self.inspector_path,
                self.inspector_bytes,
                "elf_inspector",
                self.inspector_version,
            ),
            "inputs": {
                "codex_launcher_source_sha256": "6" * 64,
                "codex_runtime_bytes": 1234,
                "codex_runtime_sha256": "5" * 64,
                "high_water_authority_input_sha256": MATERIALIZER.sha256(
                    artifacts["high_water_authority"]
                ),
                "replay_sync_helper_input_sha256": MATERIALIZER.sha256(
                    artifacts["replay_sync_helper"]
                ),
                "system_api_tool_input_sha256": MATERIALIZER.sha256(
                    artifacts["system_api_tool"]
                ),
            },
            "artifacts": {
                role: {
                    "file": MATERIALIZER.PRE_ARTIFACTS[role],
                    "sha256": MATERIALIZER.sha256(value),
                    "bytes": len(value),
                }
                for role, value in artifacts.items()
            },
            "daemon_build_required": True,
            "device_execution_verified": False,
            "release_allowed": False,
        }

    def make_pre(self, root: Path) -> None:
        root.mkdir(mode=0o700)
        artifacts = self.artifact_bytes()
        for role, value in artifacts.items():
            self.write(root / MATERIALIZER.PRE_ARTIFACTS[role], value, 0o555)
        self.write(
            root / MATERIALIZER.PRE_DAEMON_RECEIPT_NAME,
            MATERIALIZER.canonical_json(self.pre_receipt(artifacts)),
            0o444,
        )

    def validate_pre(self, root: Path | None = None) -> dict[str, object]:
        with self.patch_source_bom():
            return MATERIALIZER.validate_pre_daemon_set(
                root or self.pre_a,
                self.source_bom,
                self.stable_contract,
            )

    def daemon_bytes(self, pre: dict[str, object]) -> bytes:
        artifacts = pre["artifacts"]
        measurement = (
            f"schema={MATERIALIZER.EMBEDDED_MEASUREMENT_SCHEMA}\n"
            "variant=userdebug\n"
            "daemon_build_binding_sha256="
            f"{pre['daemon_build_binding_sha256']}\n"
            f"launcher_sha256={pre['active_launcher_sha256']}\n"
            f"system_api_sha256={MATERIALIZER.sha256(artifacts['system_api_tool'])}\n"
        ).encode("ascii")
        legacy_digests = MATERIALIZER.legacy_descriptor_digests()
        hold = (
            f"schema={MATERIALIZER.IDENTITY_HOLD_SCHEMA}\n"
            "daemon_build_binding_sha256="
            f"{pre['daemon_build_binding_sha256']}\n"
            "status=hold_identity_independence_evidence_unverified\n"
            "literal_digest_absence_verified=true\n"
            "legacy_descriptor_canonical_sha256="
            f"{legacy_digests['canonical digest']}\n"
            "legacy_descriptor_contract_sha256="
            f"{legacy_digests['contract digest']}\n"
            "legacy_descriptor_launcher_identity_sha256="
            f"{legacy_digests['launcher identity']}\n"
            "counterfactual_same_source_rebuild="
            "required:true,verified:false,evidence_receipt:null\n"
            "stable_principal_admission_split="
            "required:true,verified:false,evidence_receipt:null\n"
        ).encode("ascii")
        variant = MATERIALIZER.VARIANT_MARKER.encode("ascii") + b"\0\0"
        names = (
            b"\0.shstrtab\0"
            + MATERIALIZER.MEASUREMENT_SECTION.encode("ascii")
            + b"\0"
            + MATERIALIZER.IDENTITY_HOLD_SECTION.encode("ascii")
            + b"\0"
            + MATERIALIZER.VARIANT_SECTION.encode("ascii")
            + b"\0"
        )
        shstr_name = names.index(b".shstrtab")
        measurement_name = names.index(MATERIALIZER.MEASUREMENT_SECTION.encode("ascii"))
        hold_name = names.index(MATERIALIZER.IDENTITY_HOLD_SECTION.encode("ascii"))
        variant_name = names.index(MATERIALIZER.VARIANT_SECTION.encode("ascii"))
        program_header_offset = 64
        program_header_size = 56
        interpreter = b"/lib/ld-linux-aarch64.so.1\0"
        interpreter_offset = program_header_offset + program_header_size
        shstr_offset = interpreter_offset + len(interpreter)
        measurement_offset = shstr_offset + len(names)
        hold_offset = measurement_offset + len(measurement)
        variant_offset = hold_offset + len(hold)
        marker_payload = (
            b"agent-codex-direct-v1|"
            b"TRILLIONNIUM_AGENTD_CAPABILITY_HARDENING_V1_ACTIVE|"
            + str(pre["active_launcher_sha256"]).encode("ascii")
            + b"|GLIBC_2.34|"
        )
        marker_offset = variant_offset + len(variant)
        section_offset = (marker_offset + len(marker_payload) + 7) & ~7
        data = bytearray(section_offset + 5 * 64)
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", data, 16, 3)
        struct.pack_into("<H", data, 18, 183)
        struct.pack_into("<Q", data, 32, program_header_offset)
        struct.pack_into("<H", data, 54, program_header_size)
        struct.pack_into("<H", data, 56, 1)
        struct.pack_into("<Q", data, 40, section_offset)
        struct.pack_into("<H", data, 58, 64)
        struct.pack_into("<H", data, 60, 5)
        struct.pack_into("<H", data, 62, 1)
        struct.pack_into(
            "<IIQQQQQQ",
            data,
            program_header_offset,
            3,
            4,
            interpreter_offset,
            0,
            0,
            len(interpreter),
            len(interpreter),
            1,
        )
        data[interpreter_offset : interpreter_offset + len(interpreter)] = interpreter
        data[shstr_offset : shstr_offset + len(names)] = names
        data[measurement_offset : measurement_offset + len(measurement)] = measurement
        data[hold_offset : hold_offset + len(hold)] = hold
        data[variant_offset : variant_offset + len(variant)] = variant
        data[marker_offset : marker_offset + len(marker_payload)] = marker_payload
        headers = (
            (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            (shstr_name, 3, 0, 0, shstr_offset, len(names), 0, 0, 1, 0),
            (
                measurement_name,
                1,
                0,
                0,
                measurement_offset,
                len(measurement),
                0,
                0,
                1,
                0,
            ),
            (hold_name, 1, 0, 0, hold_offset, len(hold), 0, 0, 1, 0),
            (variant_name, 1, 0, 0, variant_offset, len(variant), 0, 0, 1, 0),
        )
        for index, header in enumerate(headers):
            struct.pack_into("<IIQQQQIIQQ", data, section_offset + index * 64, *header)
        return bytes(data)

    @staticmethod
    def hardening() -> dict[str, object]:
        return {
            "elf_class": "ELF64",
            "endianness": "little",
            "machine": "AArch64",
            "type": "DYN_PIE",
            "interpreter": "/lib/ld-linux-aarch64.so.1",
            "gnu_relro": True,
            "bind_now": True,
            "gnu_stack_executable": False,
            "writable_executable_load_segment": False,
            "rpath_or_runpath": False,
            "text_relocations": False,
            "debug_sections": False,
            "needed": ["libgcc_s.so.1", "libc.so.6"],
            "aarch64_stack_protector_guard": {
                "loader_dt_needed": False,
                "undefined_dynamic_symbol": None,
                "version": None,
                "version_provider": None,
                "loader_bound_undefined_symbols": [],
            },
            "required_glibc_versions": ["GLIBC_2.17"],
            "maximum_glibc": "GLIBC_2.17",
            "gnu_build_id_sha1": "7" * 40,
        }

    def make_raw(
        self,
        root: Path,
        pre: dict[str, object],
        suffix: str,
        *,
        lane_root: Path | None = None,
    ) -> Path:
        root.mkdir(mode=0o700)
        artifacts = pre["artifacts"]
        for role, filename in MATERIALIZER.RAW_ARTIFACTS.items():
            self.write(root / filename, artifacts[role], 0o555)
        tool_root = self.root / f"toolchain-{suffix}"
        rust_root = tool_root / "rust"
        host_root = tool_root / "host"
        cargo_home = tool_root / "cargo-home"
        target_root = (self.root if lane_root is None else lane_root) / "toolchain"
        target_sysroot = target_root / "sysroot"
        for directory in (rust_root, host_root, cargo_home):
            directory.mkdir(mode=0o700, parents=True)
        for directory in (tool_root, rust_root, host_root, cargo_home):
            directory.chmod(0o700)
        for directory in (
            target_sysroot / "usr/lib/gcc-cross/aarch64-linux-gnu/12",
            target_sysroot / "usr/aarch64-linux-gnu/bin",
            target_sysroot / "usr/lib/x86_64-linux-gnu",
        ):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        executable_records: dict[str, object] = {}
        for role in (
            "cargo",
            "rustc",
            "host_linker",
            "linker",
            "ar",
            "readelf",
        ):
            if role == "linker":
                path = target_sysroot / "usr/bin/aarch64-linux-gnu-gcc-12"
                value = self.compiler_bytes
                version = self.compiler_version
            elif role == "ar":
                path = target_sysroot / "usr/bin/aarch64-linux-gnu-ar"
                value = self.archiver_bytes
                version = self.archiver_version
            elif role == "readelf":
                path = target_sysroot / "usr/bin/aarch64-linux-gnu-readelf"
                value = self.inspector_bytes
                version = self.inspector_version
            else:
                path = (
                    rust_root / role
                    if role in {"cargo", "rustc"}
                    else host_root / role
                )
                value = aarch64_elf(f"fixture-{role}".encode())
                version = f"fixture {role}"
                self.write(path, value, 0o555)
            metadata = path.stat()
            executable_records[role] = {
                "path": str(path),
                "bytes": len(value),
                "sha256": MATERIALIZER.sha256(value),
                "mode": f"0{stat.S_IMODE(metadata.st_mode):o}",
                "version": version,
            }
        receipt: dict[str, object] = {
            "schema": MATERIALIZER.RAW_RECEIPT_SCHEMA,
            "decision": MATERIALIZER.RAW_PASS,
            "release_status": MATERIALIZER.RAW_PRODUCT_HOLD,
            "lane": "p01_userdebug_pre_daemon",
            "variant": "non_product_userdebug_settings_only_pre_daemon",
            "target": "aarch64-unknown-linux-gnu",
            "profile": "release",
            "source_date_epoch": 1785110400,
            "source_bom": self.raw_source_binding,
            "build": {
                "commands": [
                    ["$CARGO", "build", "--bin", "fixture-system-api"],
                    ["$CARGO", "build", "--bin", "fixture-high-water"],
                ],
                "locked": True,
                "offline": True,
                "no_default_features": True,
                "jobs": 1,
                "incremental": False,
                "fresh_private_target_directory": True,
                "path_remapping": True,
                "p01_compile_variant": "userdebug",
                "target_native_compile_flags": [
                    "--sysroot=$TARGET_SYSROOT",
                    "-B$TARGET_COMPILER_BIN",
                    "-B$TARGET_GCC_LIBDIR",
                    "-B$TARGET_BINUTILS_DIR",
                ],
            },
            "toolchain": {
                "boundary": MATERIALIZER.raw_ab_contract.TOOLCHAIN_BOUNDARY,
                "cargo_home": str(cargo_home),
                "rust_toolchain_root": str(rust_root),
                "rust_target_libdir": str(rust_root),
                "target_toolchain_root": str(target_root),
                "host_toolchain_root": str(host_root),
                "target_sysroot": str(target_sysroot),
                "target_search_prefixes": {
                    "compiler_bin": str(target_sysroot / "usr/bin"),
                    "gcc_libdir": str(
                        target_sysroot
                        / "usr/lib/gcc-cross/aarch64-linux-gnu/12"
                    ),
                    "binutils_dir": str(
                        target_sysroot / "usr/aarch64-linux-gnu/bin"
                    ),
                    "host_runtime_libdir": str(
                        target_sysroot / "usr/lib/x86_64-linux-gnu"
                    ),
                },
                "snapshot_manifest": self.toolchain_snapshot,
                "resolved_components": {
                    role: dict(value)
                    for role, value in MATERIALIZER.raw_ab_contract.EXPECTED_RESOLVED_COMPONENTS.items()
                },
                "executables": executable_records,
                "input_remeasurement_after_build_required": True,
                "snapshot_tree_fully_remeasured_before_and_after_build": True,
                "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed": False,
                "complete_release_toolchain_closure": False,
            },
            "artifacts": {
                role: {
                    "file": filename,
                    "bytes": len(artifacts[role]),
                    "sha256": MATERIALIZER.sha256(artifacts[role]),
                    "mode": "0555",
                    "link_count": 1,
                    "hardening": self.hardening(),
                    "lane_markers_verified": True,
                    "unremapped_host_paths_absent": True,
                    "retired_agent_identity_absent": True,
                }
                for role, filename in MATERIALIZER.RAW_ARTIFACTS.items()
            },
            "posture": {
                "host_only": True,
                "source_graph_passed": True,
                "raw_elf_build_passed": True,
                "complete_toolchain_byte_closure": False,
                "launcher_built": False,
                "final_p01_daemon_built": False,
                "rootfs_built": False,
                "android_product_wired": False,
                "device_execution_verified": False,
                "avb_or_slot_admission_verified": False,
                "release_allowed": False,
                "device_write_authorized": False,
            },
            "limitations": list(MATERIALIZER.raw_ab_contract.LIMITATIONS),
            "receipt_id_scope": MATERIALIZER.RAW_RECEIPT_ID_SCOPE,
        }
        receipt["receipt_id"] = "sha256:" + MATERIALIZER.sha256(
            MATERIALIZER.canonical_json(receipt)
        )
        receipt_path = root / MATERIALIZER.RAW_RECEIPT_NAME
        self.write(receipt_path, MATERIALIZER.canonical_json(receipt), 0o444)
        return receipt_path

    def make_launcher_ab(
        self,
        root: Path,
        pre_a: dict[str, object],
        pre_b: dict[str, object] | None = None,
    ) -> Path:
        root.mkdir(mode=0o700)
        peer = pre_a if pre_b is None else pre_b
        compiler = MATERIALIZER.tool_without_path(pre_a["compiler"])
        compiler.update(
            {
                "build_time_bytes_bound_by_upstream_receipt": True,
                "post_build_matches_raw_ab_selected_linker": True,
                "a_b_byte_equal": True,
            }
        )
        inspector = MATERIALIZER.tool_without_path(pre_a["elf_inspector"])
        inspector.update(
            {
                "build_time_bytes_bound_by_upstream_receipt": True,
                "post_build_matches_raw_ab_selected_readelf": True,
                "a_b_byte_equal": True,
            }
        )
        artifacts = pre_a["artifacts"]
        receipt: dict[str, object] = {
            "schema": MATERIALIZER.LAUNCHER_AB_RECEIPT_SCHEMA,
            "decision": MATERIALIZER.LAUNCHER_AB_DECISION,
            "status": MATERIALIZER.LAUNCHER_AB_HOLD,
            "release_status": MATERIALIZER.LAUNCHER_AB_HOLD,
            "release_allowed": False,
            "lane": "p01_userdebug_pre_daemon",
            "product_variant": "userdebug",
            "target": "aarch64-unknown-linux-gnu",
            "source_bom": dict(pre_a["source_bom"]),
            "raw_elf_ab": {
                "file": "codex-only-raw-elf-ab.v3.json",
                "bytes": 1234,
                "sha256": "8" * 64,
                "receipt_id": "sha256:" + "9" * 64,
                "lane": "p01_userdebug_pre_daemon",
                "decision": "PASS_HOST_ONLY_DETERMINISTIC_CODEX_RAW_ELF_AB",
                "release_status": MATERIALIZER.RAW_PRODUCT_HOLD,
            },
            "launcher_inputs": {
                "a": {
                    "receipt_file": MATERIALIZER.PRE_DAEMON_RECEIPT_NAME,
                    "receipt_bytes": len(pre_a["receipt_bytes"]),
                    "receipt_sha256": MATERIALIZER.sha256(pre_a["receipt_bytes"]),
                },
                "b": {
                    "receipt_file": MATERIALIZER.PRE_DAEMON_RECEIPT_NAME,
                    "receipt_bytes": len(peer["receipt_bytes"]),
                    "receipt_sha256": MATERIALIZER.sha256(peer["receipt_bytes"]),
                },
            },
            "builder_inputs": pre_a["receipt"]["inputs"],
            "compiler": compiler,
            "elf_inspector": inspector,
            "toolchain_snapshot": pre_a["daemon_build_binding"][
                "toolchain_snapshot"
            ],
            "target_compiler_closure": pre_a["daemon_build_binding"][
                "target_compiler_closure"
            ],
            "stable_principal_launcher_measurement": pre_a["receipt"][
                "stable_principal_launcher_measurement"
            ],
            "identity_independence_gate": pre_a["receipt"][
                "legacy_descriptor_contamination_hold_gate"
            ],
            "daemon_build_binding": pre_a["daemon_build_binding"],
            "artifacts": {
                role: {
                    "file": MATERIALIZER.PRE_ARTIFACTS[role],
                    "bytes": len(value),
                    "sha256": MATERIALIZER.sha256(value),
                    "a_receipt_bound": True,
                    "b_receipt_bound": True,
                    "raw_ab_bound": role in MATERIALIZER.RAW_ARTIFACTS,
                    "a_b_byte_equal": True,
                }
                for role, value in artifacts.items()
            },
            "comparisons": {
                "same_upstream_source_bom_receipt_claim": True,
                "physical_source_bom_or_live_graph_remeasured_by_this_stage": False,
                "receipt_ids_are_content_identifiers_only": True,
                "receipt_ids_are_signatures_or_attestations": False,
                "same_non_path_launcher_receipt_semantics": True,
                "same_measured_launcher_compiler": True,
                "same_measured_launcher_elf_inspector": True,
                "post_build_compiler_matches_raw_ab_selected_linker": True,
                "post_build_elf_inspector_matches_raw_ab_selected_readelf": True,
                "post_build_target_archiver_matches_raw_ab_selected_ar": True,
                "build_time_compiler_bytes_bound_by_upstream_receipt": True,
                "build_time_elf_inspector_bytes_bound_by_upstream_receipt": True,
                "raw_inputs_bidirectionally_bound": True,
                "exact_bidirectional_launcher_directory_binding": True,
                "physical_launcher_artifacts_byte_equal": True,
                "physical_input_directories_distinct": True,
                "physical_input_artifact_inodes_distinct": True,
                "physical_target_toolchain_roots_distinct": True,
                "physical_target_sysroots_distinct": True,
                "physical_selected_target_tool_inodes_distinct": True,
                "stable_full_input_reread_passed": True,
            },
            "posture": {
                "host_only": True,
                "deterministic_launcher_artifact_set_ab_verified": True,
                "identity_independence_counterfactual_verified": False,
                "stable_principal_admission_split_verified": False,
                "build_time_compiler_bytes_bound": True,
                "build_time_elf_inspector_bytes_bound": True,
                "complete_toolchain_byte_closure": False,
                "rootfs_built": False,
                "android_product_wired": False,
                "device_execution_verified": False,
                "avb_or_ota_verified": False,
                "release_allowed": False,
                "device_write_authorized": False,
            },
            "limitations": [
                "same_source_counterfactual_identity_independence_is_unverified",
                "stable_principal_admission_split_is_unverified",
                "source_bom_is_an_upstream_receipt_claim_not_physically_remeasured_by_this_stage",
                "receipt_ids_are_content_identifiers_not_signatures_or_attestations",
                "launcher_compiler_elf_inspector_and_snapshot_archiver_bytes_are_bound_but_recursive_toolchain_closure_is_absent",
                "codex_runtime_is_receipt_bound_but_not_a_physical_input_to_this_verifier",
                "launcher_ab_does_not_prove_rootfs_android_device_avb_or_ota",
            ],
            "receipt_id_scope": MATERIALIZER.RAW_RECEIPT_ID_SCOPE,
        }
        receipt["receipt_id"] = "sha256:" + MATERIALIZER.sha256(
            MATERIALIZER.canonical_json(receipt)
        )
        path = root / MATERIALIZER.LAUNCHER_AB_RECEIPT_NAME
        self.write(path, MATERIALIZER.canonical_json(receipt), 0o444)
        return path

    @contextlib.contextmanager
    def patch_authority_source_bom(self, authority_opener=None):
        real_open_authority = (
            MATERIALIZER.RetainedSourceAuthorityClosure.open_from_bom
        )

        def open_authority(raw, retained_tools):
            if authority_opener is not None:
                return authority_opener(raw, retained_tools)
            return real_open_authority(
                self.authority_source_bom_bytes, retained_tools
            )

        with mock.patch.object(
            MATERIALIZER.RetainedSourceAuthorityClosure,
            "open_from_bom",
            side_effect=open_authority,
        ):
            yield

    @contextlib.contextmanager
    def patch_source_bom(self, authority_opener=None):
        with self.patch_authority_source_bom(authority_opener), mock.patch.object(
            MATERIALIZER.primitives,
            "validate_source_bom_bytes",
            return_value=self.source_binding,
        ), mock.patch.object(
            MATERIALIZER.primitives,
            "verify_current_control_checkout",
        ), mock.patch.object(
            MATERIALIZER.primitives,
            "verify_toolchain_snapshot_binding",
            return_value=(
                self.toolchain_snapshot,
                self.toolchain_manifest_bytes,
            ),
        ):
            yield

    @contextlib.contextmanager
    def projected_authority_closure(
        self,
        repository: Path,
        builtin: Path,
        contract: Path,
        generated: Path,
        capability_root: Path,
        direct_root: Path,
    ):
        candidates = sorted(capability_root.glob("capability_lease*.rs"))
        direct_candidates = sorted(direct_root.rglob("*.rs"))
        paths = {builtin, contract, *candidates, *direct_candidates}
        tree_entries: dict[str, dict[str, str]] = {}
        for path in paths:
            relative = path.relative_to(repository).as_posix()
            value = path.read_bytes()
            mode = "100755" if stat.S_IMODE(path.stat().st_mode) & 0o111 else "100644"
            tree_entries[relative] = {
                "mode": mode,
                "type": "blob",
                "oid": MATERIALIZER.git_blob_oid(value, "sha1"),
            }
        closure = MATERIALIZER.RetainedSourceAuthorityClosure.open_from_projection(
            control_head="1" * 40,
            control_head_tree="2" * 40,
            object_format="sha1",
            tree_entries=tree_entries,
            repository=repository,
            builtin_source=builtin,
            root_contract=contract,
            root_source=generated,
            capability_root=capability_root,
            direct_tools_root=direct_root,
        )
        try:
            yield closure
        finally:
            closure.close()

    def make_authority_fixture(
        self, name: str
    ) -> tuple[Path, Path, Path, Path, Path, Path]:
        repository = self.root / name
        repository.mkdir(mode=0o700)
        builtin = repository / "daemon" / "builtin_provider_identity.rs"
        contract = repository / "contracts" / "capability-root.json"
        capability_root = repository / "capability"
        generated = capability_root / "capability_lease_root_registration.rs"
        direct_root = repository / "direct-tools"
        self.write(
            builtin,
            MATERIALIZER.BUILTIN_IDENTITY_SOURCE.read_bytes(),
            0o644,
        )
        self.write(
            contract,
            MATERIALIZER.CAPABILITY_ROOT_CONTRACT.read_bytes(),
            0o644,
        )
        self.write(
            generated,
            MATERIALIZER.CAPABILITY_ROOT_SOURCE.read_bytes(),
            0o644,
        )
        self.write(
            capability_root / "capability_lease_fixture.rs",
            b"pub const FIXTURE_CAPABILITY_HOLD: bool = true;\n",
            0o644,
        )
        self.write(
            direct_root / "lib.rs",
            b"pub fn retained_direct_tools_fixture() {}\n",
            0o644,
        )
        for directory in (
            builtin.parent,
            contract.parent,
            capability_root,
            direct_root,
        ):
            directory.chmod(0o700)
        return (
            repository,
            builtin,
            contract,
            generated,
            capability_root,
            direct_root,
        )

    def expected_final_names(self, *, raw: bool = False) -> set[str]:
        names = set(MATERIALIZER.PRE_ARTIFACTS.values()) | {
            MATERIALIZER.PRE_DAEMON_RECEIPT_NAME,
            MATERIALIZER.DAEMON_NAME,
            MATERIALIZER.SOURCE_BOM_NAME,
            MATERIALIZER.STABLE_PRINCIPAL_CONTRACT_NAME,
            MATERIALIZER.LAUNCHER_AB_RECEIPT_NAME,
            MATERIALIZER.FINAL_RECEIPT_NAME,
        }
        if raw:
            names.add(MATERIALIZER.RAW_RECEIPT_NAME)
        return names

    def mutate_receipt(self, root: Path, mutate) -> None:
        path = root / MATERIALIZER.PRE_DAEMON_RECEIPT_NAME
        value = json.loads(path.read_bytes())
        mutate(value)
        path.chmod(0o600)
        path.write_bytes(MATERIALIZER.canonical_json(value))
        path.chmod(0o444)

    def test_checked_in_source_authority_boundaries_are_split_and_hold(self) -> None:
        with MATERIALIZER.RetainedLauncherBuildTools() as retained_tools:
            with MATERIALIZER.RetainedSourceAuthorityClosure.open_from_bom(
                self.authority_source_bom_bytes, retained_tools
            ) as closure:
                evidence = MATERIALIZER.validate_source_authority_boundaries(
                    closure
                )
                MATERIALIZER.validate_p01_identity_authority_source(closure)
                closure.assert_stable()
                retained_tools.assert_stable()
        self.assertTrue(evidence["stable_principal_is_only_static_principal_authority"])
        self.assertTrue(evidence["active_launcher_is_separate_runtime_custody"])
        self.assertFalse(
            evidence["legacy_descriptor_executable_identity_is_principal_authority"]
        )
        self.assertFalse(evidence["confers_effect_authority"])

    def test_authority_closure_ignores_unrelated_home_sibling_churn(self) -> None:
        with MATERIALIZER.RetainedLauncherBuildTools() as retained_tools:
            with MATERIALIZER.RetainedSourceAuthorityClosure.open_from_bom(
                self.authority_source_bom_bytes, retained_tools
            ) as closure:
                with tempfile.TemporaryDirectory(
                    prefix="p01-unrelated-home-sibling.",
                    dir=Path.home(),
                ) as unrelated:
                    Path(unrelated, "unrelated").write_bytes(b"unrelated\n")
                    closure.assert_stable()
                closure.assert_stable()
                retained_tools.assert_stable()

    def test_authority_source_rejects_tree_oid_masquerading_as_head(self) -> None:
        receipt = json.loads(self.authority_source_bom_bytes)
        control_git = receipt["projects"][0]["git"]
        control_git["head"] = control_git["head_tree"]
        with MATERIALIZER.RetainedLauncherBuildTools() as retained_tools:
            with self.assertRaisesRegex(
                MATERIALIZER.FinalArtifactError,
                "head is not exactly a Git commit",
            ):
                MATERIALIZER.RetainedSourceAuthorityClosure.open_from_bom(
                    MATERIALIZER.canonical_json(receipt), retained_tools
                )

    def test_authority_source_rejects_git_storage_object_format_mismatch(
        self,
    ) -> None:
        real_run = MATERIALIZER.run_retained_authority_git
        receipt = json.loads(self.authority_source_bom_bytes)
        expected_format = receipt["projects"][0]["git"]["object_format"]
        mismatched_format = "sha256" if expected_format == "sha1" else "sha1"

        def report_mismatched_storage_format(tool, arguments):
            if arguments == ["rev-parse", "--show-object-format=storage"]:
                return (mismatched_format + "\n").encode("ascii")
            return real_run(tool, arguments)

        with mock.patch.object(
            MATERIALIZER,
            "run_retained_authority_git",
            side_effect=report_mismatched_storage_format,
        ), MATERIALIZER.RetainedLauncherBuildTools() as retained_tools:
            with self.assertRaisesRegex(
                MATERIALIZER.FinalArtifactError,
                "storage object format differs",
            ):
                MATERIALIZER.RetainedSourceAuthorityClosure.open_from_bom(
                    self.authority_source_bom_bytes, retained_tools
                )

    def test_source_boundary_rejects_legacy_executable_principal_authority(self) -> None:
        fixture = self.root / "source-fixture"
        fixture.mkdir()
        builtin = fixture / "builtin.rs"
        builtin.write_bytes(MATERIALIZER.BUILTIN_IDENTITY_SOURCE.read_bytes())
        builtin.write_bytes(builtin.read_bytes() + b"\nuse agent_descriptor_registry::CODEX;\n")
        contract = fixture / "contract.json"
        contract.write_bytes(MATERIALIZER.CAPABILITY_ROOT_CONTRACT.read_bytes())
        capability_root = fixture / "capability"
        capability_root.mkdir()
        generated = capability_root / "capability_lease_root_registration.rs"
        generated.write_bytes(MATERIALIZER.CAPABILITY_ROOT_SOURCE.read_bytes())
        direct_root = fixture / "direct"
        direct_root.mkdir()
        (direct_root / "lib.rs").write_bytes(b"pub fn safe_fixture() {}\n")
        capability_root.chmod(0o700)
        direct_root.chmod(0o700)
        for source in (builtin, contract, generated, direct_root / "lib.rs"):
            source.chmod(0o644)
        with self.projected_authority_closure(
            fixture,
            builtin,
            contract,
            generated,
            capability_root,
            direct_root,
        ) as closure:
            with self.assertRaisesRegex(
                MATERIALIZER.FinalArtifactError,
                "legacy executable identity authority",
            ):
                MATERIALIZER.validate_source_authority_boundaries(closure)

    def test_v8_pre_receipt_and_stable_launcher_split_validate(self) -> None:
        pre = self.validate_pre()
        self.assertEqual(pre["stable_principal"]["canonical_sha256"], self.stable_canonical_sha)
        self.assertEqual(pre["compiler"]["sha256"], MATERIALIZER.sha256(self.compiler_bytes))
        self.assertEqual(
            pre["elf_inspector"]["sha256"], MATERIALIZER.sha256(self.inspector_bytes)
        )
        self.assertEqual(
            pre["receipt"]["legacy_descriptor_contamination_hold_gate"]
            ["counterfactual_same_source_rebuild"]["verified"],
            False,
        )

    def test_source_bom_binds_the_current_control_checkout(self) -> None:
        with mock.patch.object(
            MATERIALIZER.primitives,
            "validate_source_bom_bytes",
            return_value=self.source_binding,
        ), mock.patch.object(
            MATERIALIZER.primitives,
            "verify_current_control_checkout",
        ) as checkout:
            raw, binding = MATERIALIZER.validate_source_bom(
                self.source_bom, self.source_binding
            )
        self.assertEqual(raw, self.source_bom_bytes)
        self.assertEqual(binding, self.source_binding)
        checkout.assert_called_once_with(
            self.source_binding, MATERIALIZER.REPOSITORY
        )

        with mock.patch.object(
            MATERIALIZER.primitives,
            "validate_source_bom_bytes",
            return_value=self.source_binding,
        ), mock.patch.object(
            MATERIALIZER.primitives,
            "verify_current_control_checkout",
            side_effect=RuntimeError("dirty checkout"),
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "current control-plane checkout differs",
        ):
            MATERIALIZER.validate_source_bom(
                self.source_bom, self.source_binding
            )

    def test_peer_receipt_bytes_include_local_tool_paths(self) -> None:
        artifacts = self.artifact_bytes()
        selected = self.pre_receipt(artifacts)
        peer = copy.deepcopy(selected)
        peer["compiler"]["path"] = "/independent/lane-b/compiler"
        peer["elf_inspector"]["path"] = "/independent/lane-b/readelf"
        self.assertNotEqual(
            MATERIALIZER.canonical_json(selected),
            MATERIALIZER.canonical_json(peer),
        )

        peer["compiler"]["sha256"] = "f" * 64
        self.assertNotEqual(
            MATERIALIZER.canonical_json(selected),
            MATERIALIZER.canonical_json(peer),
        )

    def test_legacy_v6_old_identity_authority_and_missing_source_are_rejected(
        self,
    ) -> None:
        legacy = self.root / "legacy"
        shutil.copytree(self.pre_a, legacy)
        self.mutate_receipt(
            legacy,
            lambda value: value.__setitem__(
                "schema", "org.trillionnium.p01-userdebug-pre-daemon-artifact-set.v6"
            ),
        )
        with self.patch_source_bom(), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError, "authority boundary"
        ):
            MATERIALIZER.validate_pre_daemon_set(
                legacy, self.source_bom, self.stable_contract
            )

        old = self.root / "old-authority"
        shutil.copytree(self.pre_a, old)
        self.mutate_receipt(
            old,
            lambda value: value.__setitem__(
                "legacy_descriptor_executable_identity_is_principal_authority", True
            ),
        )
        with self.patch_source_bom(), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError, "authority boundary"
        ):
            MATERIALIZER.validate_pre_daemon_set(
                old, self.source_bom, self.stable_contract
            )

        source_missing = self.root / "source-missing"
        shutil.copytree(self.pre_a, source_missing)
        self.mutate_receipt(
            source_missing,
            lambda value: value.pop("source_bom"),
        )
        with self.patch_source_bom(), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError, "closed schema"
        ):
            MATERIALIZER.validate_pre_daemon_set(
                source_missing, self.source_bom, self.stable_contract
            )

    def test_digest_splice_and_source_bom_tamper_are_rejected(self) -> None:
        spliced = self.root / "spliced"
        shutil.copytree(self.pre_a, spliced)
        self.mutate_receipt(
            spliced,
            lambda value: value["inputs"].__setitem__(
                "system_api_tool_input_sha256", "8" * 64
            ),
        )
        with self.patch_source_bom(), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError, "spliced"
        ):
            MATERIALIZER.validate_pre_daemon_set(
                spliced, self.source_bom, self.stable_contract
            )

        source_spliced = self.root / "source-spliced"
        shutil.copytree(self.pre_a, source_spliced)
        self.mutate_receipt(
            source_spliced,
            lambda value: value["source_bom"].__setitem__(
                "file_sha256", "8" * 64
            ),
        )
        with self.patch_source_bom(), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError, "spliced from another source BOM"
        ):
            MATERIALIZER.validate_pre_daemon_set(
                source_spliced, self.source_bom, self.stable_contract
            )

        binding_spliced = self.root / "binding-spliced"
        shutil.copytree(self.pre_a, binding_spliced)
        self.mutate_receipt(
            binding_spliced,
            lambda value: value["daemon_build_binding"][
                "runtime_artifact_sha256"
            ].__setitem__("system_api_tool", "8" * 64),
        )
        with self.patch_source_bom(), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError, "build binding differs"
        ):
            MATERIALIZER.validate_pre_daemon_set(
                binding_spliced, self.source_bom, self.stable_contract
            )

        target_spliced = self.root / "target-binding-spliced"
        shutil.copytree(self.pre_a, target_spliced)
        self.mutate_receipt(
            target_spliced,
            lambda value: value["daemon_build_binding"]["target_profile"].__setitem__(
                "maximum_glibc", "GLIBC_2.37"
            ),
        )
        with self.patch_source_bom(), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError, "build binding differs"
        ):
            MATERIALIZER.validate_pre_daemon_set(
                target_spliced, self.source_bom, self.stable_contract
            )

        profile_spliced = self.root / "cargo-profile-binding-spliced"
        shutil.copytree(self.pre_a, profile_spliced)
        self.mutate_receipt(
            profile_spliced,
            lambda value: value["daemon_build_binding"]["cargo_profile"].__setitem__(
                "name", "dev"
            ),
        )
        with self.patch_source_bom(), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError, "build binding differs"
        ):
            MATERIALIZER.validate_pre_daemon_set(
                profile_spliced, self.source_bom, self.stable_contract
            )

        with mock.patch.object(
            MATERIALIZER.primitives,
            "validate_source_bom_bytes",
            side_effect=RuntimeError("invalid canonical BOM"),
        ), self.assertRaisesRegex(MATERIALIZER.FinalArtifactError, "failed v2 verification"):
            MATERIALIZER.validate_pre_daemon_set(
                self.pre_a, self.source_bom, self.stable_contract
            )

    def test_symlink_and_hardlink_inputs_fail_closed(self) -> None:
        symlinked = self.root / "symlinked"
        shutil.copytree(self.pre_a, symlinked)
        receipt = symlinked / MATERIALIZER.PRE_DAEMON_RECEIPT_NAME
        receipt.unlink()
        receipt.symlink_to(self.pre_a / MATERIALIZER.PRE_DAEMON_RECEIPT_NAME)
        with self.assertRaisesRegex(MATERIALIZER.FinalArtifactError, "without following links"):
            self.validate_pre(symlinked)

        linked = self.root / "hardlinked"
        shutil.copytree(self.pre_a, linked)
        artifact = linked / MATERIALIZER.PRE_ARTIFACTS["system_api_tool"]
        backup = self.root / "hardlink-source"
        artifact.rename(backup)
        os.link(backup, artifact)
        with self.assertRaisesRegex(MATERIALIZER.FinalArtifactError, "link count"):
            self.validate_pre(linked)

    def test_daemon_measurement_v4_separates_stable_principal_and_launcher(self) -> None:
        pre = self.validate_pre()
        daemon = self.daemon_bytes(pre)
        measurement = MATERIALIZER.validate_daemon(daemon, pre)
        self.assertEqual(measurement["schema"], MATERIALIZER.VERIFIED_MEASUREMENT_SCHEMA)
        self.assertEqual(
            measurement["stable_principal_canonical_sha256"], self.stable_canonical_sha
        )
        self.assertEqual(measurement["active_launcher_sha256"], pre["active_launcher_sha256"])
        self.assertTrue(measurement["active_launcher_separate_from_stable_principal"])
        self.assertEqual(
            measurement["embedded_identity_hold_schema"],
            MATERIALIZER.IDENTITY_HOLD_SCHEMA,
        )
        self.assertFalse(measurement["counterfactual_same_source_rebuild_verified"])
        self.assertEqual(
            measurement["daemon_build_binding_sha256"],
            pre["daemon_build_binding_sha256"],
        )
        self.assertEqual(
            measurement["dynamic_interpreter"],
            "/lib/ld-linux-aarch64.so.1",
        )

        wrong_interpreter = daemon.replace(
            b"/lib/ld-linux-aarch64.so.1\0",
            b"/lib/ld-linux-aarch64.so.2\0",
            1,
        )
        with self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError, "PT_INTERP differs"
        ):
            MATERIALIZER.validate_daemon(wrong_interpreter, pre)

        bookworm_ceiling = daemon.replace(b"GLIBC_2.34", b"GLIBC_2.36")
        ceiling_measurement = MATERIALIZER.validate_daemon(bookworm_ceiling, pre)
        self.assertEqual(ceiling_measurement["maximum_glibc"], "2.36")

        above_ceiling = daemon.replace(b"GLIBC_2.34", b"GLIBC_2.37")
        with self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError, "GLIBC 2.36 ABI ceiling"
        ):
            MATERIALIZER.validate_daemon(above_ceiling, pre)

        spliced = bytearray(daemon)
        needle = str(pre["active_launcher_sha256"]).encode("ascii")
        offset = spliced.find(needle)
        spliced[offset] = ord("0") if spliced[offset] != ord("0") else ord("1")
        with self.assertRaisesRegex(MATERIALIZER.FinalArtifactError, "spliced"):
            MATERIALIZER.validate_daemon(bytes(spliced), pre)

        hold_tampered = bytearray(daemon)
        hold_status = b"status=hold_identity_independence_evidence_unverified"
        hold_offset = hold_tampered.find(hold_status)
        self.assertGreaterEqual(hold_offset, 0)
        hold_tampered[hold_offset + len(b"status=")] = ord("x")
        with self.assertRaisesRegex(MATERIALIZER.FinalArtifactError, "HOLD"):
            MATERIALIZER.validate_daemon(bytes(hold_tampered), pre)

    def test_raw_receipt_remeasures_tools_and_bidirectionally_binds_artifacts(self) -> None:
        pre = self.validate_pre()
        raw_path = self.make_raw(self.root / "raw-a", pre, "a")
        raw = MATERIALIZER.validate_raw_receipt(raw_path, pre)
        self.assertFalse(raw["complete_toolchain_byte_closure"])
        self.assertFalse(raw["product_authority"])

        receipt = json.loads(raw_path.read_bytes())
        receipt["artifacts"]["system_api_tool"]["sha256"] = "a" * 64
        receipt.pop("receipt_id")
        receipt["receipt_id"] = "sha256:" + MATERIALIZER.sha256(
            MATERIALIZER.canonical_json(receipt)
        )
        raw_path.chmod(0o600)
        raw_path.write_bytes(MATERIALIZER.canonical_json(receipt))
        raw_path.chmod(0o444)
        with self.assertRaisesRegex(MATERIALIZER.FinalArtifactError, "bidirectionally bound"):
            MATERIALIZER.validate_raw_receipt(raw_path, pre)

        guard_path = self.make_raw(self.root / "raw-guard", pre, "guard")
        guard_receipt = json.loads(guard_path.read_bytes())
        guard_receipt["artifacts"]["system_api_tool"]["hardening"][
            "aarch64_stack_protector_guard"
        ]["unexpected"] = True
        guard_receipt.pop("receipt_id")
        guard_receipt["receipt_id"] = "sha256:" + MATERIALIZER.sha256(
            MATERIALIZER.canonical_json(guard_receipt)
        )
        guard_path.chmod(0o600)
        guard_path.write_bytes(MATERIALIZER.canonical_json(guard_receipt))
        guard_path.chmod(0o444)
        with self.assertRaisesRegex(MATERIALIZER.FinalArtifactError, "closed schema"):
            MATERIALIZER.validate_raw_receipt(guard_path, pre)

    def test_raw_receipt_accepts_real_builder_source_bom_binding_shape(self) -> None:
        pre = self.validate_pre()
        raw_path = self.make_raw(self.root / "raw-source-shape", pre, "source-shape")
        raw_receipt = json.loads(raw_path.read_bytes())

        self.assertEqual(raw_receipt["source_bom"], self.raw_source_binding)
        self.assertNotEqual(raw_receipt["source_bom"], pre["source_bom"])
        self.assertEqual(
            MATERIALIZER.canonical_source_bom_identity(
                raw_receipt["source_bom"], raw_build_binding=True
            ),
            MATERIALIZER.canonical_source_bom_identity(
                pre["source_bom"], raw_build_binding=False
            ),
        )
        MATERIALIZER.validate_raw_receipt(raw_path, pre)

    def test_raw_receipt_rejects_every_shared_source_bom_identity_splice(self) -> None:
        pre = self.validate_pre()
        mutations: dict[str, object] = {
            "sha256": "a" * 64,
            "bytes": self.raw_source_binding["bytes"] + 1,
            "receipt_id": "sha256:" + "b" * 64,
            "source_set_sha256": "c" * 64,
            "resolved_manifest_sha256": "d" * 64,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                raw_path = self.make_raw(
                    self.root / f"raw-source-splice-{field}",
                    pre,
                    f"source-splice-{field}",
                )
                receipt = json.loads(raw_path.read_bytes())
                receipt["source_bom"][field] = replacement
                receipt.pop("receipt_id")
                receipt["receipt_id"] = "sha256:" + MATERIALIZER.sha256(
                    MATERIALIZER.canonical_json(receipt)
                )
                raw_path.chmod(0o600)
                raw_path.write_bytes(MATERIALIZER.canonical_json(receipt))
                raw_path.chmod(0o444)
                with self.assertRaisesRegex(
                    MATERIALIZER.FinalArtifactError, "spliced from another source BOM"
                ):
                    MATERIALIZER.validate_raw_receipt(raw_path, pre)

    def test_raw_receipt_source_bom_authority_shape_remains_closed(self) -> None:
        pre = self.validate_pre()
        mutations: dict[str, object] = {
            "authority": "local_exact_clean_graph_not_build_or_release_authority",
            "schema": "org.trillionnium.local-cross-repo-source-bom.v1",
            "decision": "PASS_UNSCOPED",
            "live_full_remeasurement_before_and_after_build": False,
            "byte_equal_to_each_live_remeasurement": False,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                raw_path = self.make_raw(
                    self.root / f"raw-source-boundary-{field}",
                    pre,
                    f"source-boundary-{field}",
                )
                receipt = json.loads(raw_path.read_bytes())
                receipt["source_bom"][field] = replacement
                receipt.pop("receipt_id")
                receipt["receipt_id"] = "sha256:" + MATERIALIZER.sha256(
                    MATERIALIZER.canonical_json(receipt)
                )
                raw_path.chmod(0o600)
                raw_path.write_bytes(MATERIALIZER.canonical_json(receipt))
                raw_path.chmod(0o444)
                with self.assertRaisesRegex(
                    MATERIALIZER.FinalArtifactError,
                    "raw-build source BOM authority differs",
                ):
                    MATERIALIZER.validate_raw_receipt(raw_path, pre)

    def test_launcher_ab_is_required_and_rebinds_v8_artifacts_and_tools(self) -> None:
        pre = self.validate_pre()
        raw_path = self.make_raw(self.root / "raw-launcher", pre, "launcher")
        raw = MATERIALIZER.validate_raw_receipt(raw_path, pre)
        launcher_path = self.make_launcher_ab(self.root / "launcher-ab", pre)
        launcher_receipt = json.loads(launcher_path.read_bytes())
        self.assertEqual(launcher_receipt["source_bom"], pre["source_bom"])
        self.assertNotEqual(
            launcher_receipt["source_bom"], self.raw_source_binding
        )
        launcher = MATERIALIZER.validate_launcher_ab_receipt(
            launcher_path, pre, raw
        )
        self.assertTrue(launcher["selected_raw_entities_cross_bound"])

        raw_shape_path = self.make_launcher_ab(
            self.root / "launcher-ab-raw-source-shape", pre
        )
        raw_shape = json.loads(raw_shape_path.read_bytes())
        raw_shape["source_bom"] = dict(self.raw_source_binding)
        raw_shape.pop("receipt_id")
        raw_shape["receipt_id"] = "sha256:" + MATERIALIZER.sha256(
            MATERIALIZER.canonical_json(raw_shape)
        )
        raw_shape_path.chmod(0o600)
        raw_shape_path.write_bytes(MATERIALIZER.canonical_json(raw_shape))
        raw_shape_path.chmod(0o444)
        with self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError, "closed schema"
        ):
            MATERIALIZER.validate_launcher_ab_receipt(raw_shape_path, pre, raw)

        control_splice_path = self.make_launcher_ab(
            self.root / "launcher-ab-control-head-splice", pre
        )
        control_splice = json.loads(control_splice_path.read_bytes())
        control_splice["source_bom"]["control_head"] = "f" * 40
        control_splice.pop("receipt_id")
        control_splice["receipt_id"] = "sha256:" + MATERIALIZER.sha256(
            MATERIALIZER.canonical_json(control_splice)
        )
        control_splice_path.chmod(0o600)
        control_splice_path.write_bytes(
            MATERIALIZER.canonical_json(control_splice)
        )
        control_splice_path.chmod(0o444)
        with self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError, "source BOM differs"
        ):
            MATERIALIZER.validate_launcher_ab_receipt(
                control_splice_path, pre, raw
            )

        for field in ("toolchain_snapshot", "target_compiler_closure"):
            with self.subTest(field=field):
                drift_path = self.make_launcher_ab(
                    self.root / f"launcher-ab-{field}-drift", pre
                )
                drift = json.loads(drift_path.read_bytes())
                if field == "toolchain_snapshot":
                    drift[field]["manifest_id"] = "f" * 64
                else:
                    drift[field]["target"] = "x86_64-linux-gnu"
                drift.pop("receipt_id")
                drift["receipt_id"] = "sha256:" + MATERIALIZER.sha256(
                    MATERIALIZER.canonical_json(drift)
                )
                drift_path.chmod(0o600)
                drift_path.write_bytes(MATERIALIZER.canonical_json(drift))
                drift_path.chmod(0o444)
                with self.assertRaisesRegex(
                    MATERIALIZER.FinalArtifactError,
                    "authority boundary differs",
                ):
                    MATERIALIZER.validate_launcher_ab_receipt(
                        drift_path, pre, raw
                    )

        receipt = json.loads(launcher_path.read_bytes())
        receipt["compiler"]["sha256"] = "a" * 64
        receipt.pop("receipt_id")
        receipt["receipt_id"] = "sha256:" + MATERIALIZER.sha256(
            MATERIALIZER.canonical_json(receipt)
        )
        launcher_path.chmod(0o600)
        launcher_path.write_bytes(MATERIALIZER.canonical_json(receipt))
        launcher_path.chmod(0o444)
        with self.assertRaisesRegex(MATERIALIZER.FinalArtifactError, "custody differs"):
            MATERIALIZER.validate_launcher_ab_receipt(launcher_path, pre, raw)

    def test_missing_final_peer_materializes_explicit_hold_and_tamper_fails(self) -> None:
        pre = self.validate_pre()
        launcher_ab = self.make_launcher_ab(self.root / "launcher-ab-hold", pre)
        daemon_path = self.root / "daemon-a"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        output = self.root / "final-hold"
        output.mkdir(mode=0o700)
        with self.patch_source_bom():
            result = MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
            )
        self.assertEqual(result["decision"], MATERIALIZER.FINAL_HOST_HOLD)
        self.assertFalse(result["ab_evidence"]["provided"])
        for field in (
            "toolchain_snapshot_roots_physically_distinct",
            "target_sysroots_physically_distinct",
            "selected_target_tool_inodes_physically_distinct",
            "pre_daemon_input_directories_physically_distinct",
            "raw_input_directories_physically_distinct",
        ):
            self.assertFalse(result["ab_evidence"][field])
        self.assertFalse(result["release_allowed"])
        self.assertFalse(result["device_write_authorized"])
        self.assertTrue(result["launcher_ab_evidence"]["provided"])
        self.assertTrue(
            result["launcher_ab_evidence"][
                "closed_receipt_schema_and_id_revalidated"
            ]
        )
        self.assertFalse(
            result["launcher_ab_evidence"][
                "peer_launcher_directories_reopened_by_final_materializer"
            ]
        )
        self.assertFalse(
            result["launcher_ab_evidence"]["selected_raw_entities_cross_bound"]
        )
        self.assertIn(
            "independent_peer_lane_reverification_missing", result["blockers"]
        )

        final_receipt = output / MATERIALIZER.FINAL_RECEIPT_NAME
        tampered = json.loads(final_receipt.read_bytes())
        tampered["release_allowed"] = True
        final_receipt.chmod(0o600)
        final_receipt.write_bytes(MATERIALIZER.canonical_json(tampered))
        final_receipt.chmod(0o444)
        with self.patch_source_bom(), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError, "differs"
        ):
            MATERIALIZER.verify(output)

    def test_failed_retained_verification_fail_retains_committed_files(self) -> None:
        pre = self.validate_pre()
        launcher_ab = self.make_launcher_ab(self.root / "launcher-ab-rollback", pre)
        daemon_path = self.root / "daemon-rollback"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        output = self.root / "final-rollback"
        output.mkdir(mode=0o700)
        with self.patch_source_bom(), mock.patch.object(
            MATERIALIZER,
            "_verify_retained",
            side_effect=MATERIALIZER.FinalArtifactError(
                "forced retained verification failure"
            ),
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "forced retained verification failure",
        ):
            MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
            )
        self.assertEqual({path.name for path in output.iterdir()}, self.expected_final_names())

    def test_post_verify_in_place_output_mutation_is_detected_and_retained(self) -> None:
        pre = self.validate_pre()
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-post-verify-mutation", pre
        )
        daemon_path = self.root / "daemon-post-verify-mutation"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        output = self.root / "final-post-verify-mutation"
        output.mkdir(mode=0o700)
        target = output / MATERIALIZER.DAEMON_NAME
        real_verify = MATERIALIZER._verify_retained
        observed: dict[str, object] = {}

        def verify_then_mutate(descriptor: int) -> dict[str, object]:
            result = real_verify(descriptor)
            before = target.stat()
            original = target.read_bytes()
            replacement = (
                (b"X" if original[:1] != b"X" else b"Y") + original[1:]
            )
            target.chmod(0o700)
            target.write_bytes(replacement)
            target.chmod(stat.S_IMODE(before.st_mode))
            os.utime(
                target,
                ns=(before.st_atime_ns, before.st_mtime_ns),
                follow_symlinks=False,
            )
            after = target.stat()
            observed.update(
                before=before,
                after=after,
                replacement=replacement,
            )
            return result

        with self.patch_source_bom(), mock.patch.object(
            MATERIALIZER,
            "_verify_retained",
            side_effect=verify_then_mutate,
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "published output artifact trillionniumd changed after publication",
        ):
            MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
            )
        before = observed["before"]
        after = observed["after"]
        assert isinstance(before, os.stat_result)
        assert isinstance(after, os.stat_result)
        self.assertEqual(stat.S_IMODE(after.st_mode), stat.S_IMODE(before.st_mode))
        self.assertEqual(after.st_size, before.st_size)
        self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)
        self.assertNotEqual(after.st_ctime_ns, before.st_ctime_ns)
        self.assertEqual(target.read_bytes(), observed["replacement"])
        self.assertEqual(
            {path.name for path in output.iterdir()}, self.expected_final_names()
        )

    def test_post_verify_transient_output_mutation_is_detected_by_ctime(self) -> None:
        pre = self.validate_pre()
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-post-verify-transient", pre
        )
        daemon_path = self.root / "daemon-post-verify-transient"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        output = self.root / "final-post-verify-transient"
        output.mkdir(mode=0o700)
        target = output / MATERIALIZER.DAEMON_NAME
        real_verify = MATERIALIZER._verify_retained
        observed: dict[str, object] = {}

        def verify_then_mutate_and_restore(descriptor: int) -> dict[str, object]:
            result = real_verify(descriptor)
            before = target.stat()
            original = target.read_bytes()
            replacement = (
                (b"X" if original[:1] != b"X" else b"Y") + original[1:]
            )
            target.chmod(0o700)
            target.write_bytes(replacement)
            target.write_bytes(original)
            target.chmod(stat.S_IMODE(before.st_mode))
            os.utime(
                target,
                ns=(before.st_atime_ns, before.st_mtime_ns),
                follow_symlinks=False,
            )
            after = target.stat()
            observed.update(before=before, after=after, original=original)
            return result

        with self.patch_source_bom(), mock.patch.object(
            MATERIALIZER,
            "_verify_retained",
            side_effect=verify_then_mutate_and_restore,
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "published output artifact trillionniumd changed after publication",
        ):
            MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
            )
        before = observed["before"]
        after = observed["after"]
        assert isinstance(before, os.stat_result)
        assert isinstance(after, os.stat_result)
        self.assertEqual(stat.S_IMODE(after.st_mode), stat.S_IMODE(before.st_mode))
        self.assertEqual(after.st_size, before.st_size)
        self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)
        self.assertNotEqual(after.st_ctime_ns, before.st_ctime_ns)
        self.assertEqual(target.read_bytes(), observed["original"])
        self.assertEqual(
            {path.name for path in output.iterdir()}, self.expected_final_names()
        )

    def test_transient_output_path_swap_is_rejected_and_cleanup_stays_retained(self) -> None:
        pre = self.validate_pre()
        launcher_ab = self.make_launcher_ab(self.root / "launcher-ab-swap", pre)
        daemon_path = self.root / "daemon-swap"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        output = self.root / "final-swap"
        displaced = self.root / "final-swap-displaced"
        replacement = self.root / "final-swap-replacement"
        output.mkdir(mode=0o700)
        real_verify = MATERIALIZER._verify_retained

        def swap_path_and_verify(descriptor: int) -> dict[str, object]:
            output.rename(displaced)
            output.mkdir(mode=0o700)
            self.write(output / "replacement-marker", b"replacement", 0o444)
            output.rename(replacement)
            displaced.rename(output)
            return real_verify(descriptor)

        with self.patch_source_bom(), mock.patch.object(
            MATERIALIZER,
            "_verify_retained",
            side_effect=swap_path_and_verify,
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "pathname or retained directory changed",
        ):
            MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
            )
        self.assertEqual({path.name for path in output.iterdir()}, self.expected_final_names())
        self.assertEqual(
            (replacement / "replacement-marker").read_bytes(), b"replacement"
        )

    def test_transient_pre_path_component_swap_and_restore_is_rejected(self) -> None:
        pre_scope = self.root / "pre-component-scope"
        pre_scope.mkdir(mode=0o700)
        component = pre_scope / "lane-a"
        component.mkdir(mode=0o700)
        selected_pre = component / "pre"
        shutil.copytree(self.pre_a, selected_pre)
        pre = self.validate_pre(selected_pre)
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-component-swap", pre
        )
        daemon_path = self.root / "daemon-component-swap"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        output = self.root / "final-component-swap"
        output.mkdir(mode=0o700)
        displaced = pre_scope / "lane-a-displaced"
        replacement = pre_scope / "lane-a-replacement"
        real_verify = MATERIALIZER._verify_retained

        def swap_component_and_verify(descriptor: int) -> dict[str, object]:
            component.rename(displaced)
            component.mkdir(mode=0o700)
            component.rename(replacement)
            displaced.rename(component)
            return real_verify(descriptor)

        with self.patch_source_bom(), mock.patch.object(
            MATERIALIZER,
            "_verify_retained",
            side_effect=swap_component_and_verify,
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "selected P01 pre-daemon.*pathname or retained",
        ):
            MATERIALIZER.materialize(
                output,
                daemon_path,
                selected_pre,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
            )
        self.assertEqual({path.name for path in output.iterdir()}, self.expected_final_names())
        self.assertEqual(list(replacement.iterdir()), [])

    def test_anonymous_staging_write_failure_creates_no_public_inode(self) -> None:
        output = self.root / "partial-publication"
        output.mkdir(mode=0o700)
        descriptor = os.open(
            output,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
        )
        try:
            with mock.patch.object(
                MATERIALIZER.os,
                "write",
                side_effect=OSError("forced write failure"),
            ), self.assertRaisesRegex(
                MATERIALIZER.FinalArtifactError,
                "cannot stage output artifact",
            ):
                MATERIALIZER.publish_file(
                    descriptor, "partial", b"payload", 0o444
                )
        finally:
            os.close(descriptor)
        self.assertEqual(list(output.iterdir()), [])

    def test_anonymous_staging_failure_never_fsyncs_public_directory(self) -> None:
        output = self.root / "partial-publication-fsync-failure"
        output.mkdir(mode=0o700)
        descriptor = os.open(
            output,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
        )
        real_fsync = os.fsync

        def fail_directory_fsync(candidate: int) -> None:
            if stat.S_ISDIR(os.fstat(candidate).st_mode):
                raise OSError("forced directory fsync failure")
            real_fsync(candidate)

        try:
            with mock.patch.object(
                MATERIALIZER.os,
                "write",
                side_effect=OSError("forced write failure"),
            ), mock.patch.object(
                MATERIALIZER.os,
                "fsync",
                side_effect=fail_directory_fsync,
            ), self.assertRaisesRegex(
                MATERIALIZER.FinalArtifactError,
                "cannot stage output artifact",
            ):
                MATERIALIZER.publish_file(
                    descriptor, "partial", b"payload", 0o444
                )
        finally:
            os.close(descriptor)
        self.assertEqual(list(output.iterdir()), [])

    def test_final_extra_entry_is_rejected_and_committed_set_is_retained(self) -> None:
        pre = self.validate_pre()
        launcher_ab = self.make_launcher_ab(self.root / "launcher-ab-extra", pre)
        daemon_path = self.root / "daemon-extra"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        output = self.root / "final-extra"
        output.mkdir(mode=0o700)
        real_boundaries = MATERIALIZER.validate_source_authority_boundaries
        calls = 0

        def inject_extra(*args, **kwargs):
            nonlocal calls
            result = real_boundaries(*args, **kwargs)
            calls += 1
            if calls == 2:
                self.write(output / "foreign-extra", b"foreign", 0o444)
            return result

        with self.patch_source_bom(), mock.patch.object(
            MATERIALIZER,
            "validate_source_authority_boundaries",
            side_effect=inject_extra,
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "output closure has missing or unexpected entries",
        ):
            MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
            )
        self.assertEqual(
            {path.name for path in output.iterdir()},
            self.expected_final_names() | {"foreign-extra"},
        )

    def test_second_authority_measurement_parent_swap_is_committed_fail_retain(
        self,
    ) -> None:
        fixture = self.make_authority_fixture("authority-parent-swap")
        (
            repository,
            builtin,
            contract,
            generated,
            capability_root,
            direct_root,
        ) = fixture

        def authority_opener(_raw, _retained_tools):
            return self.projected_authority_closure(*fixture)

        pre = self.validate_pre()
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-authority-parent-swap", pre
        )
        daemon_path = self.root / "daemon-authority-parent-swap"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        output = self.root / "final-authority-parent-swap"
        output.mkdir(mode=0o700)
        displaced = repository / "capability-displaced"
        replacement = repository / "capability-replacement"
        generated_bytes = generated.read_bytes()
        real_boundaries = MATERIALIZER.validate_source_authority_boundaries
        calls = 0

        def validate_then_swap(closure):
            nonlocal calls
            result = real_boundaries(closure)
            calls += 1
            if calls == 2:
                capability_root.rename(displaced)
                capability_root.mkdir(mode=0o755)
                self.write(
                    capability_root / "capability_lease_root_registration.rs",
                    generated_bytes,
                    0o644,
                )
                capability_root.rename(replacement)
                displaced.rename(capability_root)
            return result

        with self.patch_source_bom(authority_opener), mock.patch.object(
            MATERIALIZER,
            "validate_source_authority_boundaries",
            side_effect=validate_then_swap,
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "ordered commit failed after creating retained public entries.*"
            "pathname or retained",
        ):
            MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
            )
        self.assertEqual(calls, 2)
        self.assertEqual(
            {path.name for path in output.iterdir()}, self.expected_final_names()
        )
        self.assertTrue(replacement.is_dir())

    def test_second_authority_measurement_candidate_add_remove_is_committed_fail_retain(
        self,
    ) -> None:
        fixture = self.make_authority_fixture("authority-candidate-transient")
        (
            _repository,
            _builtin,
            _contract,
            _generated,
            capability_root,
            _direct_root,
        ) = fixture

        def authority_opener(_raw, _retained_tools):
            return self.projected_authority_closure(*fixture)

        pre = self.validate_pre()
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-authority-candidate-transient", pre
        )
        daemon_path = self.root / "daemon-authority-candidate-transient"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        output = self.root / "final-authority-candidate-transient"
        output.mkdir(mode=0o700)
        transient = capability_root / "capability_lease_transient.rs"
        real_boundaries = MATERIALIZER.validate_source_authority_boundaries
        calls = 0

        def validate_then_add_remove(closure):
            nonlocal calls
            result = real_boundaries(closure)
            calls += 1
            if calls == 2:
                self.write(transient, b"transient candidate\n", 0o644)
                transient.unlink()
            return result

        with self.patch_source_bom(authority_opener), mock.patch.object(
            MATERIALIZER,
            "validate_source_authority_boundaries",
            side_effect=validate_then_add_remove,
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "ordered commit failed after creating retained public entries.*"
            "pathname or retained",
        ):
            MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
            )
        self.assertEqual(calls, 2)
        self.assertFalse(transient.exists())
        self.assertEqual(
            {path.name for path in output.iterdir()}, self.expected_final_names()
        )

    def test_second_authority_measurement_bytes_restore_is_committed_fail_retain(
        self,
    ) -> None:
        fixture = self.make_authority_fixture("authority-bytes-restore")
        (
            _repository,
            builtin,
            _contract,
            _generated,
            _capability_root,
            _direct_root,
        ) = fixture

        def authority_opener(_raw, _retained_tools):
            return self.projected_authority_closure(*fixture)

        pre = self.validate_pre()
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-authority-bytes-restore", pre
        )
        daemon_path = self.root / "daemon-authority-bytes-restore"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        output = self.root / "final-authority-bytes-restore"
        output.mkdir(mode=0o700)
        real_boundaries = MATERIALIZER.validate_source_authority_boundaries
        calls = 0
        original = builtin.read_bytes()

        def validate_then_restore_bytes(closure):
            nonlocal calls
            result = real_boundaries(closure)
            calls += 1
            if calls == 2:
                before = builtin.stat()
                builtin.write_bytes(b"X" + original[1:])
                builtin.write_bytes(original)
                builtin.chmod(stat.S_IMODE(before.st_mode))
                os.utime(
                    builtin,
                    ns=(before.st_atime_ns, before.st_mtime_ns),
                    follow_symlinks=False,
                )
            return result

        with self.patch_source_bom(authority_opener), mock.patch.object(
            MATERIALIZER,
            "validate_source_authority_boundaries",
            side_effect=validate_then_restore_bytes,
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "ordered commit failed after creating retained public entries.*"
            "retained input changed",
        ):
            MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
            )
        self.assertEqual(calls, 2)
        self.assertEqual(builtin.read_bytes(), original)
        self.assertEqual(
            {path.name for path in output.iterdir()}, self.expected_final_names()
        )

    def test_indeterminate_non_os_post_link_error_is_reported_and_never_unlinked(self) -> None:
        pre = self.validate_pre()
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-indeterminate-link", pre
        )
        daemon_path = self.root / "daemon-indeterminate-link"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        output = self.root / "final-indeterminate-link"
        output.mkdir(mode=0o700)
        real_link = os.link
        linked: list[str] = []

        def link_then_raise(source, destination, **kwargs) -> None:
            real_link(source, destination, **kwargs)
            linked.append(destination)
            raise RuntimeError("wrapper failed after link")

        with self.patch_source_bom(), mock.patch.object(
            MATERIALIZER.os,
            "link",
            side_effect=link_then_raise,
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "ATTEMPTING_OR_UNKNOWN.*wrapper failed after link",
        ):
            MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
            )
        self.assertEqual(len(linked), 1)
        self.assertEqual({path.name for path in output.iterdir()}, {linked[0]})

    def test_post_link_file_exists_error_remains_indeterminate_and_retained(self) -> None:
        pre = self.validate_pre()
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-indeterminate-eexist", pre
        )
        daemon_path = self.root / "daemon-indeterminate-eexist"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        output = self.root / "final-indeterminate-eexist"
        output.mkdir(mode=0o700)
        real_link = os.link
        linked: list[str] = []

        def link_then_raise(source, destination, **kwargs) -> None:
            real_link(source, destination, **kwargs)
            linked.append(destination)
            raise FileExistsError("wrapper reported EEXIST after link")

        with self.patch_source_bom(), mock.patch.object(
            MATERIALIZER.os,
            "link",
            side_effect=link_then_raise,
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "ATTEMPTING_OR_UNKNOWN.*EEXIST after link",
        ):
            MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
            )
        self.assertEqual(len(linked), 1)
        self.assertEqual({path.name for path in output.iterdir()}, {linked[0]})

    def test_selected_child_mutation_at_commit_boundary_is_precommit_failure(self) -> None:
        pre = self.validate_pre()
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-child-mutation", pre
        )
        daemon_path = self.root / "daemon-child-mutation"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        output = self.root / "final-child-mutation"
        output.mkdir(mode=0o700)
        target = self.pre_a / MATERIALIZER.PRE_ARTIFACTS["system_api_tool"]
        original = target.read_bytes()
        calls = 0
        real_publish = MATERIALIZER.publish_file

        def stage_then_mutate(*args, **kwargs):
            nonlocal calls
            result = real_publish(*args, **kwargs)
            calls += 1
            if calls == 1:
                target.chmod(0o755)
                target.write_bytes(b"X" + original[1:])
                target.chmod(0o555)
            return result

        with self.patch_source_bom(), mock.patch.object(
            MATERIALIZER,
            "publish_file",
            side_effect=stage_then_mutate,
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "retained input changed|retained input bytes changed",
        ):
            MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
            )
        self.assertEqual(list(output.iterdir()), [])

    def test_transient_launcher_tool_path_swap_after_validation_is_precommit_failure(
        self,
    ) -> None:
        pre = self.validate_pre()
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-tool-path-swap", pre
        )
        daemon_path = self.root / "daemon-tool-path-swap"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        output = self.root / "final-tool-path-swap"
        output.mkdir(mode=0o700)
        displaced = self.launcher_tool_root / "compiler-displaced"
        replacement = self.launcher_tool_root / "compiler-replacement"
        real_publish = MATERIALIZER.publish_file
        injected = False

        def stage_then_swap_and_restore(*args, **kwargs):
            nonlocal injected
            result = real_publish(*args, **kwargs)
            if not injected:
                injected = True
                self.compiler_path.rename(displaced)
                self.write(self.compiler_path, self.compiler_bytes, 0o755)
                self.compiler_path.rename(replacement)
                displaced.rename(self.compiler_path)
            return result

        with self.patch_source_bom(), mock.patch.object(
            MATERIALIZER,
            "publish_file",
            side_effect=stage_then_swap_and_restore,
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "P01 launcher compiler parent custody.*changed",
        ):
            MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
            )
        self.assertTrue(injected)
        self.assertEqual(list(output.iterdir()), [])

    def test_raw_build_tool_mutation_after_validation_is_precommit_failure(self) -> None:
        pre = self.validate_pre()
        raw = self.make_raw(self.root / "raw-tool-mutation", pre, "mutation")
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-raw-tool-mutation", pre
        )
        daemon_path = self.root / "daemon-raw-tool-mutation"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        output = self.root / "final-raw-tool-mutation"
        output.mkdir(mode=0o700)
        cargo = self.root / "toolchain-mutation" / "cargo"
        real_publish = MATERIALIZER.publish_file
        injected = False

        def stage_then_mutate(*args, **kwargs):
            nonlocal injected
            result = real_publish(*args, **kwargs)
            if not injected:
                injected = True
                cargo.write_bytes(aarch64_elf(b"mutated-cargo"))
            return result

        with self.patch_source_bom(), mock.patch.object(
            MATERIALIZER,
            "publish_file",
            side_effect=stage_then_mutate,
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "P01 raw-build cargo changed while retained|"
            "P01 raw-build cargo parent custody pathname or retained directory changed",
        ):
            MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
                raw_receipt=raw,
            )
        self.assertTrue(injected)
        self.assertEqual(list(output.iterdir()), [])

    def test_late_checkout_failure_is_committed_fail_retain(self) -> None:
        pre = self.validate_pre()
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-late-checkout", pre
        )
        daemon_path = self.root / "daemon-late-checkout"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        output = self.root / "final-late-checkout"
        output.mkdir(mode=0o700)
        boundary_calls = 0
        dirty = False
        real_boundaries = MATERIALIZER.validate_source_authority_boundaries

        def dirty_after_second_boundary(*args, **kwargs):
            nonlocal boundary_calls, dirty
            result = real_boundaries(*args, **kwargs)
            boundary_calls += 1
            if boundary_calls == 2:
                dirty = True
            return result

        def checkout(_binding, _repository) -> None:
            if dirty:
                raise RuntimeError("late dirty checkout")

        with self.patch_authority_source_bom(), mock.patch.object(
            MATERIALIZER,
            "validate_source_authority_boundaries",
            side_effect=dirty_after_second_boundary,
        ), mock.patch.object(
            MATERIALIZER.primitives,
            "validate_source_bom_bytes",
            return_value=self.source_binding,
        ), mock.patch.object(
            MATERIALIZER.primitives,
            "verify_current_control_checkout",
            side_effect=checkout,
        ), mock.patch.object(
            MATERIALIZER.primitives,
            "verify_toolchain_snapshot_binding",
            return_value=(
                self.toolchain_snapshot,
                self.toolchain_manifest_bytes,
            ),
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "final gate",
        ):
            MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
            )
        self.assertEqual(
            {path.name for path in output.iterdir()}, self.expected_final_names()
        )

    def test_final_checkout_output_swap_is_detected_and_committed_set_is_retained(self) -> None:
        pre = self.validate_pre()
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-final-checkout-swap", pre
        )
        daemon_path = self.root / "daemon-final-checkout-swap"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        output = self.root / "final-checkout-swap"
        displaced = self.root / "final-checkout-swap-displaced"
        output.mkdir(mode=0o700)
        real_checkout = MATERIALIZER.require_current_control_checkout
        checkout_calls = 0

        def swap_during_final_checkout(binding) -> None:
            nonlocal checkout_calls
            real_checkout(binding)
            checkout_calls += 1
            if checkout_calls == 2:
                output.rename(displaced)
                output.mkdir(mode=0o700)
                self.write(output / "attacker-marker", b"attacker", 0o444)

        with self.patch_source_bom(), mock.patch.object(
            MATERIALIZER,
            "require_current_control_checkout",
            side_effect=swap_during_final_checkout,
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "ordered commit failed after creating retained public entries.*pathname",
        ):
            MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
            )
        self.assertEqual(checkout_calls, 2)
        self.assertEqual(
            {path.name for path in displaced.iterdir()}, self.expected_final_names()
        )
        self.assertEqual((output / "attacker-marker").read_bytes(), b"attacker")

    def test_frozen_verify_does_not_require_live_checkout_and_allows_tmp(self) -> None:
        pre = self.validate_pre()
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-offline-verify", pre
        )
        daemon_path = self.root / "daemon-offline-verify"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        output = self.root / "final-offline-verify"
        output.mkdir(mode=0o700)
        with self.patch_source_bom():
            MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
            )

        with tempfile.TemporaryDirectory(
            prefix="p01-final-offline.", dir="/tmp"
        ) as temporary:
            copied = Path(temporary) / "artifact"
            shutil.copytree(output, copied)
            with self.patch_authority_source_bom(), mock.patch.object(
                MATERIALIZER.primitives,
                "validate_source_bom_bytes",
                return_value=self.source_binding,
            ), mock.patch.object(
                MATERIALIZER.primitives,
                "verify_current_control_checkout",
                side_effect=AssertionError("offline verifier called live checkout"),
            ) as checkout:
                result = MATERIALIZER.verify(copied)
            checkout.assert_not_called()
        self.assertEqual(result["schema"], MATERIALIZER.FINAL_RECEIPT_SCHEMA)

    def test_directory_close_attempts_every_descriptor_after_non_os_error(self) -> None:
        retained = MATERIALIZER.RetainedDirectoryPath.open(
            self.pre_a, "close-fault fixture"
        )
        descriptors = list(retained.descriptors)
        real_close = os.close
        calls: list[int] = []

        def close_then_fail_once(descriptor: int) -> None:
            calls.append(descriptor)
            real_close(descriptor)
            if len(calls) == 1:
                raise RuntimeError("forced close failure")

        with mock.patch.object(
            MATERIALIZER.os, "close", side_effect=close_then_fail_once
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError, "descriptor cleanup failed"
        ):
            retained.close()
        self.assertEqual(set(calls), set(descriptors))
        self.assertEqual(retained.descriptors, [])
        for descriptor in descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_retained_build_tool_accepts_root_owned_usr_bin_parent(self) -> None:
        candidates = (
            Path("/usr/bin/aarch64-linux-gnu-readelf"),
            Path("/usr/bin/readelf"),
            Path("/usr/bin/true"),
        )
        tool_path = next(
            (
                candidate
                for candidate in candidates
                if candidate.exists()
                and not candidate.is_symlink()
                and candidate.stat().st_uid == 0
                and candidate.stat().st_nlink == 1
            ),
            None,
        )
        if tool_path is None:
            self.skipTest("no stable root-owned /usr/bin executable is available")
        self.assertEqual(tool_path.parent.stat().st_uid, 0)
        self.assertEqual(stat.S_IMODE(tool_path.parent.stat().st_mode) & 0o022, 0)
        custody = MATERIALIZER.RetainedLauncherBuildTools()
        tool = MATERIALIZER.primitives.open_launcher_build_tool(
            tool_path, "elf_inspector"
        )
        try:
            custody.retain(tool, "root-owned ELF inspector")
            custody.assert_stable()
            self.assertEqual(custody.entries[0][2].leaf_metadata.st_uid, 0)
        finally:
            custody.close()

    def test_root_leaf_owner_permission_does_not_allow_group_writable_parent(
        self,
    ) -> None:
        parent = self.root / "group-writable-tool-parent"
        parent.mkdir(mode=0o700)
        parent.chmod(0o770)
        with self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "path component is not owner-controlled",
        ):
            MATERIALIZER.RetainedDirectoryPath.open(
                parent,
                "group-writable tool parent",
                allow_root_leaf_owner=True,
            )

    def test_retained_build_tool_close_drains_tool_and_path_descriptors(self) -> None:
        custody = MATERIALIZER.RetainedLauncherBuildTools()
        tool = MATERIALIZER.primitives.open_launcher_build_tool(
            self.compiler_path, "compiler_driver"
        )
        custody.retain(tool, "P01 launcher compiler")
        parent = custody.entries[0][2]
        descriptors = {
            tool.descriptor,
            tool.parent_descriptor,
            *parent.descriptors,
        }
        real_close = os.close
        calls: list[int] = []

        def close_then_report_once(descriptor: int) -> None:
            calls.append(descriptor)
            real_close(descriptor)
            if len(calls) == 1:
                raise RuntimeError("forced tool close failure")

        with mock.patch.object(
            MATERIALIZER.os, "close", side_effect=close_then_report_once
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "build-tool descriptor cleanup failed",
        ):
            custody.close()
        self.assertCountEqual(calls, descriptors)
        self.assertEqual(custody.entries, [])
        for descriptor in descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)
        custody.close()

    def test_successful_raw_materialization_drains_all_retained_tool_fds(self) -> None:
        pre = self.validate_pre()
        raw = self.make_raw(self.root / "raw-fd-drain", pre, "fd-drain")
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-fd-drain", pre
        )
        daemon_path = self.root / "daemon-fd-drain"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        output = self.root / "final-fd-drain"
        output.mkdir(mode=0o700)
        before = set(os.listdir("/proc/self/fd"))
        with self.patch_source_bom():
            MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
                raw_receipt=raw,
            )
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_regular_input_close_still_closes_parent_chain_after_non_os_error(self) -> None:
        retained = MATERIALIZER.RetainedRegularInput.open(
            self.source_bom,
            "close-fault regular input",
            16 * 1024 * 1024,
            modes={0o444},
        )
        file_descriptor = retained.descriptor
        parent_descriptors = list(retained.parent.descriptors)
        real_close = os.close
        calls: list[int] = []

        def close_and_fail_file(descriptor: int) -> None:
            calls.append(descriptor)
            real_close(descriptor)
            if descriptor == file_descriptor:
                raise RuntimeError("forced file close failure")

        with mock.patch.object(
            MATERIALIZER.os, "close", side_effect=close_and_fail_file
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError, "descriptor cleanup failed"
        ):
            retained.close()
        self.assertEqual(
            set(calls), {file_descriptor, *parent_descriptors}
        )
        self.assertEqual(retained.descriptor, -1)
        self.assertEqual(retained.parent.descriptors, [])
        for descriptor in [file_descriptor, *parent_descriptors]:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_regular_input_final_check_closes_fresh_parent_after_non_os_error(self) -> None:
        retained = MATERIALIZER.RetainedRegularInput.open(
            self.source_bom,
            "fresh-close-fault regular input",
            16 * 1024 * 1024,
            modes={0o444},
        )
        retained_descriptors = {
            retained.descriptor, *retained.parent.descriptors
        }
        before = set(os.listdir("/proc/self/fd"))
        real_close = os.close
        injected = False

        def close_fresh_file_then_fail(descriptor: int) -> None:
            nonlocal injected
            metadata = os.fstat(descriptor)
            real_close(descriptor)
            if (
                not injected
                and descriptor not in retained_descriptors
                and stat.S_ISREG(metadata.st_mode)
            ):
                injected = True
                raise RuntimeError("forced fresh file close failure")

        try:
            with mock.patch.object(
                MATERIALIZER.os,
                "close",
                side_effect=close_fresh_file_then_fail,
            ), self.assertRaisesRegex(
                MATERIALIZER.FinalArtifactError,
                "final custody cleanup failed",
            ):
                retained.assert_stable()
            self.assertTrue(injected)
            self.assertEqual(set(os.listdir("/proc/self/fd")), before)
        finally:
            retained.close()

    def test_private_sticky_ancestor_is_rejected_even_without_shared_write_bits(self) -> None:
        sticky = self.root / "private-sticky"
        sticky.mkdir(mode=0o700)
        sticky.chmod(0o1700)
        leaf = sticky / "leaf"
        leaf.mkdir(mode=0o700)
        candidate = leaf / "candidate.json"
        self.write(candidate, b"{}\n", 0o444)
        with self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "path component is not owner-controlled",
        ):
            MATERIALIZER.RetainedRegularInput.open(
                candidate,
                "private sticky candidate",
                1024,
                modes={0o444},
            )

    def test_peer_raw_child_mutation_at_commit_boundary_is_precommit_failure(self) -> None:
        pre = self.validate_pre()
        daemon = self.daemon_bytes(pre)
        daemon_a = self.root / "daemon-peer-raw-a"
        daemon_b = self.root / "daemon-peer-raw-b"
        self.write(daemon_a, daemon, 0o755)
        self.write(daemon_b, daemon, 0o755)
        pre_b = self.root / "pre-peer-raw-b"
        shutil.copytree(self.pre_a, pre_b)
        peer_lane_root, peer_manifest, peer_compiler, _, peer_inspector = (
            self.make_toolchain_lane("peer-toolchain-raw-mutation")
        )
        self.retarget_pre_to_toolchain_lane(
            pre_b, peer_compiler, peer_inspector
        )
        raw_a = self.make_raw(self.root / "raw-peer-raw-a", pre, "a")
        pre_peer = self.validate_pre(pre_b)
        raw_b = self.make_raw(
            self.root / "raw-peer-raw-b",
            pre_peer,
            "b",
            lane_root=peer_lane_root,
        )
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-peer-raw-mutation", pre, pre_peer
        )
        output = self.root / "final-peer-raw-mutation"
        output.mkdir(mode=0o700)
        target = raw_b.parent / MATERIALIZER.RAW_ARTIFACTS["system_api_tool"]
        original = target.read_bytes()
        calls = 0
        real_publish = MATERIALIZER.publish_file

        def stage_then_mutate(*args, **kwargs):
            nonlocal calls
            result = real_publish(*args, **kwargs)
            calls += 1
            if calls == 1:
                target.chmod(0o755)
                target.write_bytes(b"Y" + original[1:])
                target.chmod(0o555)
            return result

        with self.patch_source_bom(), mock.patch.object(
            MATERIALIZER,
            "publish_file",
            side_effect=stage_then_mutate,
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "peer P01 raw-build system_api_tool retained input changed|"
            "peer P01 raw-build system_api_tool retained input bytes changed",
        ):
            MATERIALIZER.materialize(
                output,
                daemon_a,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
                raw_receipt=raw_a,
                peer_pre_daemon_root=pre_b,
                peer_daemon_path=daemon_b,
                peer_raw_receipt=raw_b,
                peer_toolchain_manifest=peer_manifest,
            )
        self.assertEqual(list(output.iterdir()), [])

    def test_complete_peer_lane_rejects_inode_aliases(self) -> None:
        pre = self.validate_pre()
        daemon_path = self.root / "daemon-peer-alias"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        raw = self.make_raw(self.root / "raw-peer-alias", pre, "a")
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-peer-alias", pre, pre
        )
        output = self.root / "final-peer-alias"
        output.mkdir(mode=0o700)
        with self.patch_source_bom(), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "alias",
        ):
            MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
                raw_receipt=raw,
                peer_pre_daemon_root=self.pre_a,
                peer_daemon_path=daemon_path,
                peer_raw_receipt=raw,
                peer_toolchain_manifest=self.toolchain_manifest,
            )
        self.assertEqual(list(output.iterdir()), [])

    def test_physical_alias_gate_rejects_root_sysroot_leaf_and_input_aliases(
        self,
    ) -> None:
        metadata = os.stat(self.root / "toolchain", follow_symlinks=False)
        for label in (
            "P01 A/B physical toolchain roots",
            "P01 A/B physical target sysroots",
            "P01 A/B selected linker tool paths",
            "P01 A/B selected ar tool paths",
            "P01 A/B selected readelf tool paths",
            "P01 A/B pre-daemon input directories",
            "P01 A/B raw input directories",
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                MATERIALIZER.FinalArtifactError,
                "alias the same inode",
            ):
                MATERIALIZER.require_distinct_physical_identity(
                    metadata, metadata, label
                )

    def test_complete_distinct_peer_lane_reaches_host_only_determinism_pass(self) -> None:
        pre = self.validate_pre()
        daemon = self.daemon_bytes(pre)
        daemon_a = self.root / "daemon-a"
        daemon_b = self.root / "daemon-b"
        self.write(daemon_a, daemon, 0o755)
        self.write(daemon_b, daemon, 0o755)
        pre_b = self.root / "pre-b"
        shutil.copytree(self.pre_a, pre_b)
        peer_lane_root, peer_manifest, peer_compiler, _, peer_inspector = (
            self.make_toolchain_lane("peer-toolchain-pass")
        )
        self.retarget_pre_to_toolchain_lane(
            pre_b, peer_compiler, peer_inspector
        )
        raw_a = self.make_raw(self.root / "raw-a", pre, "a")
        pre_peer = self.validate_pre(pre_b)
        raw_b = self.make_raw(
            self.root / "raw-b", pre_peer, "b", lane_root=peer_lane_root
        )
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-pass", pre, pre_peer
        )
        output = self.root / "final-pass"
        output.mkdir(mode=0o700)
        with self.patch_source_bom():
            result = MATERIALIZER.materialize(
                output,
                daemon_a,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
                raw_receipt=raw_a,
                peer_pre_daemon_root=pre_b,
                peer_daemon_path=daemon_b,
                peer_raw_receipt=raw_b,
                peer_toolchain_manifest=peer_manifest,
            )
        self.assertEqual(result["decision"], MATERIALIZER.FINAL_HOST_PASS)
        self.assertEqual(
            json.loads((output / MATERIALIZER.FINAL_RECEIPT_NAME).read_bytes())["schema"],
            MATERIALIZER.FINAL_RECEIPT_SCHEMA,
        )
        self.assertTrue(result["ab_evidence"]["peer_lane_physically_reverified"])
        for field in (
            "toolchain_snapshot_roots_physically_distinct",
            "target_sysroots_physically_distinct",
            "selected_target_tool_inodes_physically_distinct",
            "pre_daemon_input_directories_physically_distinct",
            "raw_input_directories_physically_distinct",
        ):
            self.assertTrue(result["ab_evidence"][field])
        self.assertTrue(result["ab_evidence"]["final_daemon_byte_identical"])
        self.assertFalse(result["raw_build_evidence"]["complete_toolchain_byte_closure"])
        self.assertTrue(
            result["raw_build_evidence"]["launcher_compiler_matches_selected_linker"]
        )
        self.assertTrue(
            result["raw_build_evidence"][
                "launcher_elf_inspector_matches_selected_readelf"
            ]
        )
        self.assertTrue(
            result["launcher_ab_evidence"]["selected_raw_entities_cross_bound"]
        )
        self.assertEqual(result["release_status"], MATERIALIZER.FINAL_PRODUCT_HOLD)
        self.assertFalse(result["device_execution_verified"])
        self.assertFalse(result["product_effect_authority_available"])
        self.assertFalse(result["release_allowed"])

    def test_complete_peer_lane_accepts_path_only_tool_receipt_drift(self) -> None:
        pre = self.validate_pre()
        daemon = self.daemon_bytes(pre)
        daemon_a = self.root / "daemon-path-drift-a"
        daemon_b = self.root / "daemon-path-drift-b"
        self.write(daemon_a, daemon, 0o755)
        self.write(daemon_b, daemon, 0o755)

        peer_lane_root, peer_manifest, peer_compiler, _, peer_inspector = (
            self.make_toolchain_lane("peer-toolchain-path-drift")
        )
        pre_b = self.root / "pre-path-drift-b"
        shutil.copytree(self.pre_a, pre_b)
        self.retarget_pre_to_toolchain_lane(
            pre_b, peer_compiler, peer_inspector
        )
        pre_peer = self.validate_pre(pre_b)
        self.assertNotEqual(pre["receipt_bytes"], pre_peer["receipt_bytes"])

        raw_a = self.make_raw(self.root / "raw-path-drift-a", pre, "path-a")
        raw_b = self.make_raw(
            self.root / "raw-path-drift-b",
            pre_peer,
            "path-b",
            lane_root=peer_lane_root,
        )
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-path-drift", pre, pre_peer
        )
        output = self.root / "final-path-drift"
        output.mkdir(mode=0o700)
        with self.patch_source_bom():
            result = MATERIALIZER.materialize(
                output,
                daemon_a,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
                raw_receipt=raw_a,
                peer_pre_daemon_root=pre_b,
                peer_daemon_path=daemon_b,
                peer_raw_receipt=raw_b,
                peer_toolchain_manifest=peer_manifest,
            )
        self.assertEqual(result["decision"], MATERIALIZER.FINAL_HOST_PASS)
        self.assertFalse(
            result["ab_evidence"]["pre_daemon_receipt_byte_identical"]
        )
        self.assertTrue(
            result["ab_evidence"]["pre_daemon_non_path_semantics_equal"]
        )

    def test_peer_lane_requires_complete_inputs_and_rejects_aliases(self) -> None:
        pre = self.validate_pre()
        daemon_path = self.root / "daemon-a"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        raw = self.make_raw(self.root / "raw-incomplete-peer", pre, "incomplete")
        launcher_ab = self.make_launcher_ab(self.root / "launcher-ab-peer", pre)
        output = self.root / "incomplete-peer"
        output.mkdir(mode=0o700)
        with self.assertRaisesRegex(MATERIALIZER.FinalArtifactError, "requires"):
            MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
                peer_pre_daemon_root=self.pre_a,
            )

        with self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError, "toolchain-manifest"
        ):
            MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
                raw_receipt=raw,
                peer_pre_daemon_root=self.pre_a,
                peer_daemon_path=daemon_path,
                peer_raw_receipt=raw,
            )

    def test_peer_lane_rejects_selected_tool_path_splice(self) -> None:
        pre = self.validate_pre()
        daemon = self.daemon_bytes(pre)
        daemon_a = self.root / "daemon-tool-splice-a"
        daemon_b = self.root / "daemon-tool-splice-b"
        self.write(daemon_a, daemon, 0o755)
        self.write(daemon_b, daemon, 0o755)
        pre_b = self.root / "pre-tool-splice-b"
        shutil.copytree(self.pre_a, pre_b)
        peer_lane_root, peer_manifest, _, _, _ = self.make_toolchain_lane(
            "peer-toolchain-splice"
        )
        raw_a = self.make_raw(self.root / "raw-tool-splice-a", pre, "splice-a")
        pre_peer = self.validate_pre(pre_b)
        raw_b = self.make_raw(
            self.root / "raw-tool-splice-b",
            pre_peer,
            "splice-b",
            lane_root=peer_lane_root,
        )
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-tool-splice", pre, pre_peer
        )
        output = self.root / "final-tool-splice"
        output.mkdir(mode=0o700)
        with self.patch_source_bom(), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "P01 pre-daemon compiler differs from the verified snapshot leaf",
        ):
            MATERIALIZER.materialize(
                output,
                daemon_a,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
                raw_receipt=raw_a,
                peer_pre_daemon_root=pre_b,
                peer_daemon_path=daemon_b,
                peer_raw_receipt=raw_b,
                peer_toolchain_manifest=peer_manifest,
            )
        self.assertEqual(list(output.iterdir()), [])

    def test_peer_lane_rejects_semantic_snapshot_drift(self) -> None:
        pre = self.validate_pre()
        daemon_path = self.root / "daemon-peer-snapshot-drift"
        self.write(daemon_path, self.daemon_bytes(pre), 0o755)
        raw = self.make_raw(self.root / "raw-peer-snapshot-drift", pre, "drift")
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-peer-snapshot-drift", pre
        )
        _, peer_manifest, _, _, _ = self.make_toolchain_lane(
            "peer-toolchain-semantic-drift"
        )
        output = self.root / "final-peer-snapshot-drift"
        output.mkdir(mode=0o700)

        def verify_snapshot(path: Path):
            snapshot = copy.deepcopy(self.toolchain_snapshot)
            if path == peer_manifest:
                snapshot["tree_digest"] = "f" * 64
            return snapshot, path.read_bytes()

        with self.patch_source_bom(), mock.patch.object(
            MATERIALIZER.primitives,
            "verify_toolchain_snapshot_binding",
            side_effect=verify_snapshot,
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError, "not semantically equal"
        ):
            MATERIALIZER.materialize(
                output,
                daemon_path,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
                raw_receipt=raw,
                peer_pre_daemon_root=self.pre_a,
                peer_daemon_path=daemon_path,
                peer_raw_receipt=raw,
                peer_toolchain_manifest=peer_manifest,
            )
        self.assertEqual(list(output.iterdir()), [])

    def test_peer_lane_rejects_persistent_snapshot_drift(self) -> None:
        pre = self.validate_pre()
        daemon = self.daemon_bytes(pre)
        daemon_a = self.root / "daemon-peer-persistent-a"
        daemon_b = self.root / "daemon-peer-persistent-b"
        self.write(daemon_a, daemon, 0o755)
        self.write(daemon_b, daemon, 0o755)
        pre_b = self.root / "pre-peer-persistent-b"
        shutil.copytree(self.pre_a, pre_b)
        peer_lane_root, peer_manifest, peer_compiler, _, peer_inspector = (
            self.make_toolchain_lane("peer-toolchain-persistent-drift")
        )
        self.retarget_pre_to_toolchain_lane(
            pre_b, peer_compiler, peer_inspector
        )
        raw_a = self.make_raw(self.root / "raw-peer-persistent-a", pre, "persistent-a")
        pre_peer = self.validate_pre(pre_b)
        raw_b = self.make_raw(
            self.root / "raw-peer-persistent-b",
            pre_peer,
            "persistent-b",
            lane_root=peer_lane_root,
        )
        launcher_ab = self.make_launcher_ab(
            self.root / "launcher-ab-peer-persistent", pre, pre_peer
        )
        output = self.root / "final-peer-persistent"
        output.mkdir(mode=0o700)
        peer_verifications = 0

        def verify_snapshot(path: Path):
            nonlocal peer_verifications
            snapshot = copy.deepcopy(self.toolchain_snapshot)
            raw_manifest = path.read_bytes()
            if path == peer_manifest:
                peer_verifications += 1
                if peer_verifications == 2:
                    snapshot["tree_digest"] = "e" * 64
            return snapshot, raw_manifest

        with self.patch_source_bom(), mock.patch.object(
            MATERIALIZER.primitives,
            "verify_toolchain_snapshot_binding",
            side_effect=verify_snapshot,
        ), self.assertRaisesRegex(
            MATERIALIZER.FinalArtifactError,
            "peer closed-world toolchain snapshot changed",
        ):
            MATERIALIZER.materialize(
                output,
                daemon_a,
                self.pre_a,
                self.source_bom,
                launcher_ab_receipt=launcher_ab,
                stable_contract=self.stable_contract,
                raw_receipt=raw_a,
                peer_pre_daemon_root=pre_b,
                peer_daemon_path=daemon_b,
                peer_raw_receipt=raw_b,
                peer_toolchain_manifest=peer_manifest,
            )
        self.assertEqual(peer_verifications, 2)
        self.assertEqual(list(output.iterdir()), [])

    def test_parse_args_rejects_materialization_inputs_in_verify_mode(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            MATERIALIZER.parse_args(
                ["--verify-dir", "/tmp/final", "--daemon", "/tmp/daemon"]
            )

        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            MATERIALIZER.parse_args(
                [
                    "--output-dir",
                    "/tmp/final",
                    "--daemon",
                    "/tmp/daemon",
                    "--pre-daemon-artifact-set",
                    "/tmp/pre",
                    "--source-bom",
                    "/tmp/bom",
                ]
            )


if __name__ == "__main__":
    unittest.main()
