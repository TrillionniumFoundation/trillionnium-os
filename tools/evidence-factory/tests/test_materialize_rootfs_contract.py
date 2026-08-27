#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import py_compile
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock


EVIDENCE_FACTORY = Path(__file__).resolve().parents[1]
TOOLS = EVIDENCE_FACTORY.parent
TRILLIONNIUM_OS = TOOLS.parent
MATERIALIZER = EVIDENCE_FACTORY / "materialize_rootfs_contract.py"
COMMON_AGENT_MANIFEST_MATERIALIZER = (
    EVIDENCE_FACTORY / "materialize_common_codex_agent_manifest.py"
)
TEMPLATE = EVIDENCE_FACTORY / "rootfs-packager.contract.template.json"
PACKAGER = TOOLS / "package_current_rootfs.py"
REQUIRED_FORBIDDEN_CONTENT_MARKERS = [
    "TRILLIONNIUM_DO_NOT_PACKAGE_SECRET",
    "TRILLIONNIUM_DEVELOPMENT_RESPONSE_LOSS_FAULT_HOOK_V1",
    "/run/trillionnium/dev-conformance/fault-hook.json",
    "org.trillionnium.dev-conformance.gateway-response-loss.v1",
    "org.trillionnium.dev-conformance.gateway-response-loss-audit.v1",
]
SOURCE_SET_SHA256 = "b" * 64
RESOLVED_MANIFEST_SHA256 = "c" * 64
LAUNCHER_AB_HOLD = (
    "HOLD_IDENTITY_INDEPENDENCE_PRODUCT_DEVICE_AND_COMPLETE_TOOLCHAIN_ADMISSION"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fake_aarch64_elf(*, machine: int = 183, interpreter: bool = False) -> bytes:
    ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    phnum = 1 if interpreter else 0
    phoff = 64 if phnum else 0
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        2,
        machine,
        1,
        0,
        phoff,
        0,
        0,
        64,
        56,
        phnum,
        0,
        0,
        0,
    )
    if not interpreter:
        return header
    payload = b"/lib/ld-linux-aarch64.so.1\x00"
    offset = 64 + 56
    program_header = struct.pack(
        "<IIQQQQQQ", 3, 4, offset, 0, 0, len(payload), len(payload), 1
    )
    return header + program_header + payload


class RootfsContractMaterializerTests(unittest.TestCase):
    def setUp(self) -> None:
        # The materializer rejects shared sticky/world-writable path components.
        # Keep ordinary fixtures below the current user's private home instead
        # of inheriting tempfile's usual /tmp ancestry.
        self.temporary = tempfile.TemporaryDirectory(
            prefix="rootfs-contract-materializer-test-",
            dir=Path.home(),
        )
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.materializer = self.load_materializer("fixture_constants")
        self.template = self.root / "template.json"
        self.template.write_bytes(TEMPLATE.read_bytes())
        self.base = self.root / "base-rootfs.tar.zst"
        self.base.write_bytes(b"frozen base rootfs fixture\n")
        self.daemon = self.root / "trillionniumd"
        self.daemon.write_bytes(fake_aarch64_elf())
        self.codex = self.root / "trillionnium-codex-agent-2026.7.1"
        self.codex.write_bytes(fake_aarch64_elf())
        self.system_api_tool = self.root / "trillionnium-agent-system-api"
        self.system_api_tool.write_bytes(fake_aarch64_elf(interpreter=True))
        self.accessibility_tool = self.root / "trillionnium-agent-accessibility"
        self.accessibility_tool.write_bytes(fake_aarch64_elf(interpreter=True))
        self.system_api_replay_sync = (
            self.root / "trillionnium-system-api-replay-sync"
        )
        self.system_api_replay_sync.write_bytes(
            fake_aarch64_elf(interpreter=True)
        )
        self.zstd = self.root / "zstd"
        self.zstd.write_bytes(b"fixture pinned zstd executable\n")
        self.common_artifact_set_receipt = (
            self.root / "common-codex-rootfs-artifact-set.v5.json"
        )
        self.common_launcher_ab_receipt = (
            self.root / "codex-launcher-artifact-set-ab.v4.json"
        )
        self.manifest = self.root / "AgentManifest.json"
        self.generated_manifest = self.root / "generated-AgentManifest.json"
        self.output = self.root / "rootfs-contract.json"
        self.write_manifest()
        self.write_common_artifact_set_receipt()
        self.write_common_launcher_ab_receipt()
        self.freeze_inputs()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_template_codex_identity_matches_descriptor_registry(self) -> None:
        registry_contract = json.loads(
            (
                TRILLIONNIUM_OS
                / "crates"
                / "trillionnium-os-types"
                / "contracts"
                / "agent-descriptor-registry-v1.json"
            ).read_text(encoding="utf-8")
        )
        codex = next(
            descriptor
            for descriptor in registry_contract["descriptors"]
            if descriptor["symbol"] == "CODEX"
        )
        daemon_agent_id = codex["agent_id"]
        template = json.loads(TEMPLATE.read_text(encoding="utf-8"))
        manifest_contract = template["inputs"]["agent_manifest"]
        self.assertEqual(
            manifest_contract["required_fields"]["agent_id"], daemon_agent_id
        )
        self.assertEqual(
            Path(manifest_contract["install"]["path"]).name,
            f"{daemon_agent_id}.json",
        )
        self.assertFalse(manifest_contract["required_fields"]["enabled"])
        self.assertEqual(
            manifest_contract["required_fields"]["health"], "disabled"
        )
        replay = template["inputs"]["system_api_replay_sync"]
        self.assertEqual(
            replay["install"]["path"],
            "usr/local/bin/trillionnium-system-api-replay-sync",
        )
        self.assertFalse(replay["require_static"])

    def freeze_inputs(self) -> None:
        self.template.chmod(0o444)
        self.base.chmod(0o444)
        self.daemon.chmod(0o555)
        self.codex.chmod(0o555)
        self.system_api_tool.chmod(0o555)
        self.accessibility_tool.chmod(0o555)
        self.system_api_replay_sync.chmod(0o555)
        self.zstd.chmod(0o555)
        self.common_artifact_set_receipt.chmod(0o444)
        self.common_launcher_ab_receipt.chmod(0o444)
        self.manifest.chmod(0o444)

    def thaw(self, path: Path) -> None:
        path.chmod(0o600)

    def write_manifest(self, *, identity: str | None = None, version: str = "2026.7.1") -> None:
        value = {
            "adapter": "supervised-codex-cli",
            "adapter_version": version,
            "agent_id": "agent-codex-direct-v1",
            "api_version": "trillionnium.agent-api.v1",
            "enabled": False,
            "health": "disabled",
            "identity_key_sha256": identity or sha256(self.codex),
            "network_policy": "per_request",
            "peer_uid": 5901,
            "peer_gid": 5901,
            "registered_at_unix_ms": 1_700_000_000_000,
            "selinux_domain": "u:r:trillionnium_codex_agent:s0",
            "updated_at_unix_ms": 1_700_000_000_000,
        }
        self.manifest.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def build_tool(self, role: str, *, path: str) -> dict[str, object]:
        identity = self.materializer.EXPECTED_LAUNCHER_BUILD_TOOL_IDENTITIES[role]
        return {
            "schema": "org.trillionnium.launcher-build-tool-custody.v1",
            "role": role,
            "path": path,
            "bytes": identity["bytes"],
            "sha256": identity["sha256"],
            "mode": identity["mode"],
            "uid": 0,
            "gid": 0,
            "link_count": 1,
            "version": identity["version"],
            "target": identity["target"],
            "execution": {
                "mechanism": "retained_open_file_description_via_proc_self_fd",
                "measured_before_first_execution": True,
                "all_invocations_used_same_open_file_description": True,
                "descriptor_and_path_stable_after_last_execution": True,
                "ambient_environment_inherited": False,
                "environment_allowlist": self.materializer.LAUNCHER_BUILD_ENVIRONMENT_ALLOWLIST,
            },
            "complete_recursive_toolchain_closure": False,
        }

    def target_compiler_closure(self) -> dict[str, object]:
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
            "components": json.loads(
                json.dumps(self.materializer.EXPECTED_TARGET_COMPILER_COMPONENTS)
            ),
            "snapshot_tree_fully_remeasured_before_and_after_build": True,
            "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed": False,
            "complete_host_execution_runtime_closure": False,
        }

    def write_common_artifact_set_receipt(
        self, *, artifact_overrides: dict[str, dict[str, object]] | None = None
    ) -> None:
        physical = {
            "daemon": self.daemon,
            "codex_launcher": self.codex,
            "system_api_tool": self.system_api_tool,
            "accessibility_tool": self.accessibility_tool,
            "replay_sync_helper": self.system_api_replay_sync,
        }
        artifacts = {
            name: {"bytes": path.stat().st_size, "file": path.name, "sha256": sha256(path)}
            for name, path in physical.items()
        }
        for name, override in (artifact_overrides or {}).items():
            artifacts[name].update(override)
        value = {
            "accessibility_available": False,
            "artifacts": artifacts,
            "common_direct_tool_posture": "inert_no_default_features_fail_closed",
            "compiler": self.build_tool("compiler_driver", path="/fixture/gcc"),
            "elf_inspector": self.build_tool("elf_inspector", path="/fixture/readelf"),
            "dependency_graph": {
                "acyclic": True,
                "edge_semantics": "left artifact is a build input of the right artifact",
                "edges": [
                    "codex_runtime->codex_launcher",
                    "system_api_tool->codex_launcher",
                    "accessibility_tool->codex_launcher",
                    "daemon->rootfs_package",
                    "replay_sync_helper->rootfs_package",
                    "codex_launcher->rootfs_package",
                ],
                "forbidden_edges": [
                    "codex_launcher->system_api_tool",
                    "codex_launcher->accessibility_tool",
                    "rootfs_package->daemon",
                    "rootfs_package->replay_sync_helper",
                ],
            },
            "device_execution_verified": False,
            "inputs": {
                "accessibility_tool_input_sha256": artifacts["accessibility_tool"]["sha256"],
                "codex_launcher_source_sha256": "1" * 64,
                "codex_runtime_bytes": 1234,
                "codex_runtime_sha256": "2" * 64,
                "daemon_input_sha256": artifacts["daemon"]["sha256"],
                "replay_sync_helper_input_sha256": artifacts["replay_sync_helper"]["sha256"],
                "system_api_tool_input_sha256": artifacts["system_api_tool"]["sha256"],
            },
            "legacy_descriptor_contamination_hold_gate": {
                "counterfactual_same_source_rebuild": {
                    "evidence_receipt": None,
                    "required": True,
                    "verified": False,
                },
                "digests": {
                    "canonical digest": "bc6c64abbb893e6e75ed708f87cf864e6c8f7503381371dc394409bddc4009c2",
                    "contract digest": "5ecd89d3c9fedbbeb0ac1de32fba2b5e5e5d248048ddc9a9e0359a0a01903119",
                    "launcher identity": "edcf9d31da8b48d29575115a7242691c1337174edf42573b7274b652a4cd571c",
                },
                "literal_digest_absence_verified": True,
                "stable_principal_admission_split": {
                    "evidence_receipt": None,
                    "required": True,
                    "verified": False,
                },
                "status": "hold_identity_independence_evidence_unverified",
            },
            "product_variant": "common",
            "receipt_role": "common_rootfs_complete_measured_build_input",
            "release_allowed": False,
            "rootfs_build_required": True,
            "schema": "org.trillionnium.common-codex-rootfs-artifact-set.v5",
            "source_bom": {
                "authority": "local_exact_clean_graph_not_build_or_release_authority",
                "bytes": 4096,
                "control_head": "3" * 40,
                "file_sha256": "4" * 64,
                "receipt_id": "sha256:" + "5" * 64,
                "resolved_manifest_sha256": RESOLVED_MANIFEST_SHA256,
                "source_set_sha256": SOURCE_SET_SHA256,
            },
            "stable_principal_launcher_measurement": {
                "executable_identity_is_stable_registry_input": False,
                "launcher_executable_sha256": artifacts["codex_launcher"]["sha256"],
                "launcher_identity_source": "measured_after_closed_launcher_inputs",
                "stable_principal_canonical_sha256": "a9c224116123deb49908beda3ab047fc98d6917cfeb62d60364033858cc57153",
                "stable_principal_contract_sha256": "3e9bfcb04e48062c20bd7407635c1a27086a0de8c2fa5ca73963c946b984095b",
                "status": "host_measurement_only_avb_slot_admission_absent",
            },
            "status": "host_built_device_evidence_hold",
            "target_compiler_closure": self.target_compiler_closure(),
            "toolchain_snapshot": json.loads(
                json.dumps(self.materializer.EXPECTED_TOOLCHAIN_SNAPSHOT_BINDING)
            ),
        }
        self.common_artifact_set_receipt.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def write_common_launcher_ab_receipt(self) -> None:
        common = json.loads(
            self.common_artifact_set_receipt.read_text(encoding="utf-8")
        )
        compiler = dict(common["compiler"])
        compiler.pop("path")
        compiler.update(
            {
                "a_b_byte_equal": True,
                "build_time_bytes_bound_by_upstream_receipt": True,
                "post_build_matches_raw_ab_selected_linker": True,
            }
        )
        inspector = dict(common["elf_inspector"])
        inspector.pop("path")
        inspector.update(
            {
                "a_b_byte_equal": True,
                "build_time_bytes_bound_by_upstream_receipt": True,
                "post_build_matches_raw_ab_selected_readelf": True,
            }
        )
        common_raw = self.common_artifact_set_receipt.read_bytes()
        value = {
            "schema": "org.trillionnium.codex-launcher-artifact-set-ab.v4",
            "decision": "PASS_HOST_ONLY_DETERMINISTIC_CODEX_LAUNCHER_ARTIFACT_SET_AB",
            "status": LAUNCHER_AB_HOLD,
            "release_status": LAUNCHER_AB_HOLD,
            "release_allowed": False,
            "lane": "common",
            "product_variant": "common",
            "target": "aarch64-unknown-linux-gnu",
            "source_bom": common["source_bom"],
            "raw_elf_ab": {
                "file": "codex-only-raw-elf-ab.v3.json",
                "bytes": 8192,
                "sha256": "8" * 64,
                "receipt_id": "sha256:" + "9" * 64,
                "lane": "common",
                "decision": "PASS_HOST_ONLY_DETERMINISTIC_CODEX_RAW_ELF_AB",
                "release_status": "HOLD_PRODUCT_DEVICE_AND_COMPLETE_TOOLCHAIN_ADMISSION",
            },
            "launcher_inputs": {
                side: {
                    "receipt_file": self.common_artifact_set_receipt.name,
                    "receipt_bytes": len(common_raw),
                    "receipt_sha256": hashlib.sha256(common_raw).hexdigest(),
                }
                for side in ("a", "b")
            },
            "builder_inputs": common["inputs"],
            "compiler": compiler,
            "elf_inspector": inspector,
            "stable_principal_launcher_measurement": common[
                "stable_principal_launcher_measurement"
            ],
            "identity_independence_gate": common[
                "legacy_descriptor_contamination_hold_gate"
            ],
            "target_compiler_closure": common["target_compiler_closure"],
            "toolchain_snapshot": common["toolchain_snapshot"],
            "artifacts": {
                role: {
                    **artifact,
                    "a_receipt_bound": True,
                    "b_receipt_bound": True,
                    "raw_ab_bound": role != "codex_launcher",
                    "a_b_byte_equal": True,
                }
                for role, artifact in common["artifacts"].items()
            },
            "comparisons": {
                "build_time_compiler_bytes_bound_by_upstream_receipt": True,
                "build_time_elf_inspector_bytes_bound_by_upstream_receipt": True,
                "exact_bidirectional_launcher_directory_binding": True,
                "physical_input_artifact_inodes_distinct": True,
                "physical_input_directories_distinct": True,
                "physical_launcher_artifacts_byte_equal": True,
                "physical_selected_target_tool_inodes_distinct": True,
                "physical_source_bom_or_live_graph_remeasured_by_this_stage": False,
                "physical_target_sysroots_distinct": True,
                "physical_target_toolchain_roots_distinct": True,
                "post_build_compiler_matches_raw_ab_selected_linker": True,
                "post_build_elf_inspector_matches_raw_ab_selected_readelf": True,
                "post_build_target_archiver_matches_raw_ab_selected_ar": True,
                "raw_inputs_bidirectionally_bound": True,
                "receipt_ids_are_content_identifiers_only": True,
                "receipt_ids_are_signatures_or_attestations": False,
                "same_measured_launcher_compiler": True,
                "same_measured_launcher_elf_inspector": True,
                "same_non_path_launcher_receipt_semantics": True,
                "same_upstream_source_bom_receipt_claim": True,
                "stable_full_input_reread_passed": True,
            },
            "posture": {
                "android_product_wired": False,
                "avb_or_ota_verified": False,
                "build_time_compiler_bytes_bound": True,
                "build_time_elf_inspector_bytes_bound": True,
                "complete_toolchain_byte_closure": False,
                "deterministic_launcher_artifact_set_ab_verified": True,
                "device_execution_verified": False,
                "device_write_authorized": False,
                "host_only": True,
                "identity_independence_counterfactual_verified": False,
                "release_allowed": False,
                "rootfs_built": False,
                "stable_principal_admission_split_verified": False,
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
            "receipt_id_scope": (
                "sha256(canonical-json-utf8-sort-keys-indent-2-lf-without-receipt_id)"
            ),
        }
        pretty = lambda item: (
            json.dumps(
                item,
                ensure_ascii=False,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        value["receipt_id"] = "sha256:" + hashlib.sha256(pretty(value)).hexdigest()
        self.common_launcher_ab_receipt.write_bytes(pretty(value))

    def command(self, **overrides: Path | int) -> list[str]:
        values: dict[str, Path | int] = {
            "template": self.template,
            "base-rootfs": self.base,
            "common-artifact-set-receipt": self.common_artifact_set_receipt,
            "common-launcher-ab-receipt": self.common_launcher_ab_receipt,
            "daemon": self.daemon,
            "codex-binary": self.codex,
            "system-api-tool": self.system_api_tool,
            "accessibility-tool": self.accessibility_tool,
            "system-api-replay-sync": self.system_api_replay_sync,
            "agent-manifest": self.manifest,
            "zstd": self.zstd,
            "source-date-epoch": 1_700_000_000,
            "output": self.output,
        }
        values.update(overrides)
        command = [sys.executable, str(MATERIALIZER)]
        for key, value in values.items():
            command.extend([f"--{key}", str(value)])
        return command

    def run_materializer(
        self, *, expect_ok: bool = True, **overrides: Path | int
    ) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            self.command(**overrides),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if expect_ok and completed.returncode != 0:
            self.fail(completed.stderr)
        if not expect_ok and completed.returncode == 0:
            self.fail("materializer unexpectedly succeeded")
        return completed

    def common_agent_manifest_command(
        self,
        *,
        materializer: Path = COMMON_AGENT_MANIFEST_MATERIALIZER,
        **overrides: Path | int,
    ) -> list[str]:
        values: dict[str, Path | int] = {
            "template": self.template,
            "common-artifact-set-receipt": self.common_artifact_set_receipt,
            "common-launcher-ab-receipt": self.common_launcher_ab_receipt,
            "daemon": self.daemon,
            "codex-launcher": self.codex,
            "system-api-tool": self.system_api_tool,
            "accessibility-tool": self.accessibility_tool,
            "system-api-replay-sync": self.system_api_replay_sync,
            "source-date-epoch": 1_700_000_000,
            "output": self.generated_manifest,
        }
        values.update(overrides)
        command = [sys.executable, str(materializer)]
        for key, value in values.items():
            command.extend([f"--{key}", str(value)])
        return command

    def run_common_agent_manifest_materializer(
        self,
        *,
        expect_ok: bool = True,
        materializer: Path = COMMON_AGENT_MANIFEST_MATERIALIZER,
        **overrides: Path | int,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.pop("PYTHONDONTWRITEBYTECODE", None)
        completed = subprocess.run(
            self.common_agent_manifest_command(
                materializer=materializer,
                **overrides,
            ),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
        )
        if expect_ok and completed.returncode != 0:
            self.fail(completed.stderr)
        if not expect_ok and completed.returncode == 0:
            self.fail("common AgentManifest materializer unexpectedly succeeded")
        return completed

    def load_materializer(self, suffix: str) -> object:
        module_name = f"rootfs_contract_materializer_{suffix}_{id(self)}"
        spec = importlib.util.spec_from_file_location(module_name, MATERIALIZER)
        assert spec is not None and spec.loader is not None
        materializer = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = materializer
        spec.loader.exec_module(materializer)
        return materializer

    def test_common_agent_manifest_materializer_emits_exact_disabled_binding(
        self,
    ) -> None:
        self.run_common_agent_manifest_materializer()
        expected = {
            "adapter": "supervised-codex-cli",
            "adapter_version": "2026.7.1",
            "agent_id": "agent-codex-direct-v1",
            "api_version": "trillionnium.agent-api.v1",
            "enabled": False,
            "health": "disabled",
            "identity_key_sha256": sha256(self.codex),
            "network_policy": "per_request",
            "peer_gid": 5901,
            "peer_uid": 5901,
            "registered_at_unix_ms": 0,
            "selinux_domain": "u:r:trillionnium_codex_agent:s0",
            "updated_at_unix_ms": 0,
        }
        expected_raw = (
            json.dumps(
                expected,
                ensure_ascii=False,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        self.assertEqual(self.generated_manifest.read_bytes(), expected_raw)
        self.assertNotIn(
            b"edcf9d31da8b48d29575115a7242691c1337174edf42573b7274b652a4cd571c",
            expected_raw,
        )
        metadata = self.generated_manifest.stat()
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o444)
        self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual(metadata.st_uid, os.geteuid())
        self.assertEqual(metadata.st_mtime_ns, 1_700_000_000_000_000_000)
        self.assertEqual(
            list(self.root.glob(f".{self.generated_manifest.name}.tmp-*")), []
        )

    def test_common_agent_manifest_materializer_feeds_v9_contract(self) -> None:
        self.run_common_agent_manifest_materializer()
        self.run_materializer(
            **{"agent-manifest": self.generated_manifest},
        )
        contract = json.loads(self.output.read_text(encoding="utf-8"))
        descriptor = contract["inputs"]["agent_manifest"]
        self.assertEqual(descriptor["sha256"], sha256(self.generated_manifest))
        self.assertEqual(
            descriptor["required_fields"]["identity_key_sha256"],
            sha256(self.codex),
        )
        self.assertFalse(descriptor["required_fields"]["enabled"])
        self.assertEqual(descriptor["required_fields"]["health"], "disabled")

    def test_common_agent_manifest_materializer_is_byte_deterministic_across_lanes(
        self,
    ) -> None:
        self.run_common_agent_manifest_materializer()
        lane_b = self.root / "lane-b"
        lane_b.mkdir(mode=0o700)
        copied: dict[Path, Path] = {}
        for source in (
            self.common_artifact_set_receipt,
            self.daemon,
            self.codex,
            self.system_api_tool,
            self.accessibility_tool,
            self.system_api_replay_sync,
        ):
            target = lane_b / source.name
            shutil.copyfile(source, target)
            target.chmod(stat.S_IMODE(source.stat().st_mode))
            copied[source] = target
            self.assertNotEqual(source.stat().st_ino, target.stat().st_ino)
        lane_b_manifest = lane_b / "generated-AgentManifest.json"
        self.run_common_agent_manifest_materializer(
            **{
                "common-artifact-set-receipt": copied[
                    self.common_artifact_set_receipt
                ],
                "daemon": copied[self.daemon],
                "codex-launcher": copied[self.codex],
                "system-api-tool": copied[self.system_api_tool],
                "accessibility-tool": copied[self.accessibility_tool],
                "system-api-replay-sync": copied[self.system_api_replay_sync],
                "output": lane_b_manifest,
            }
        )
        self.assertEqual(
            self.generated_manifest.read_bytes(), lane_b_manifest.read_bytes()
        )
        self.assertNotEqual(
            self.generated_manifest.stat().st_ino, lane_b_manifest.stat().st_ino
        )

    def test_common_agent_manifest_materializer_rejects_receipt_launcher_drift(
        self,
    ) -> None:
        self.thaw(self.common_artifact_set_receipt)
        self.write_common_artifact_set_receipt(
            artifact_overrides={"codex_launcher": {"sha256": "a" * 64}}
        )
        self.common_artifact_set_receipt.chmod(0o444)
        completed = self.run_common_agent_manifest_materializer(expect_ok=False)
        self.assertIn(
            "does not match physical artifact: codex_launcher", completed.stderr
        )
        self.assertFalse(self.generated_manifest.exists())

    def test_common_agent_manifest_materializer_rejects_launcher_ab_drift(
        self,
    ) -> None:
        self.thaw(self.common_launcher_ab_receipt)
        value = json.loads(
            self.common_launcher_ab_receipt.read_text(encoding="utf-8")
        )
        value["artifacts"]["codex_launcher"]["sha256"] = "a" * 64
        value.pop("receipt_id")
        encoded = (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        value["receipt_id"] = "sha256:" + hashlib.sha256(encoded).hexdigest()
        self.common_launcher_ab_receipt.write_text(
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.common_launcher_ab_receipt.chmod(0o444)
        completed = self.run_common_agent_manifest_materializer(expect_ok=False)
        self.assertIn(
            "common launcher A/B artifact codex_launcher is not closed",
            completed.stderr,
        )
        self.assertFalse(self.generated_manifest.exists())

    def test_common_agent_manifest_materializer_rejects_template_field_drift(
        self,
    ) -> None:
        self.thaw(self.template)
        value = json.loads(self.template.read_text(encoding="utf-8"))
        value["inputs"]["agent_manifest"]["allowed_fields"].append(
            "caller_selected_identity"
        )
        self.template.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.template.chmod(0o444)
        completed = self.run_common_agent_manifest_materializer(expect_ok=False)
        self.assertIn(
            "field closure is not the common v9 set", completed.stderr
        )
        self.assertFalse(self.generated_manifest.exists())

    def test_common_agent_manifest_materializer_rejects_unsafe_inputs_and_output(
        self,
    ) -> None:
        alias = self.root / "launcher-alias"
        alias.symlink_to(self.codex)
        completed = self.run_common_agent_manifest_materializer(
            expect_ok=False,
            **{"codex-launcher": alias},
        )
        self.assertIn("symbolic link", completed.stderr)
        self.assertFalse(self.generated_manifest.exists())

        self.generated_manifest.write_text("existing\n", encoding="utf-8")
        self.generated_manifest.chmod(0o444)
        completed = self.run_common_agent_manifest_materializer(expect_ok=False)
        self.assertIn("overwrite is forbidden", completed.stderr)
        self.assertEqual(
            self.generated_manifest.read_text(encoding="utf-8"), "existing\n"
        )

    def test_common_agent_manifest_help_and_run_do_not_create_bytecode(self) -> None:
        cache = EVIDENCE_FACTORY / "__pycache__"

        def inventory() -> set[tuple[str, int, int]]:
            if not cache.exists():
                return set()
            return {
                (item.name, item.stat().st_size, item.stat().st_mtime_ns)
                for item in cache.iterdir()
            }

        before = inventory()
        environment = os.environ.copy()
        environment.pop("PYTHONDONTWRITEBYTECODE", None)
        completed = subprocess.run(
            [sys.executable, str(COMMON_AGENT_MANIFEST_MATERIALIZER), "--help"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("--codex-launcher", completed.stdout)
        self.run_common_agent_manifest_materializer()
        self.assertEqual(inventory(), before)

    def test_common_agent_manifest_ignores_valid_adjacent_poisoned_bytecode(
        self,
    ) -> None:
        tool_directory = self.root / "bytecode-poison-tool"
        tool_directory.mkdir(mode=0o700)
        copied_materializer = tool_directory / COMMON_AGENT_MANIFEST_MATERIALIZER.name
        copied_rootfs_source = tool_directory / MATERIALIZER.name
        shutil.copy2(COMMON_AGENT_MANIFEST_MATERIALIZER, copied_materializer)
        shutil.copy2(MATERIALIZER, copied_rootfs_source)
        copied_materializer.chmod(0o444)
        copied_rootfs_source.chmod(0o444)

        marker = self.root / "poisoned-bytecode-executed"
        poison_source = self.root / "poisoned-rootfs-source.py"
        prefix = (
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n"
            "raise RuntimeError('poisoned rootfs bytecode executed')\n"
            "#"
        ).encode("utf-8")
        rootfs_metadata = copied_rootfs_source.stat()
        remaining = rootfs_metadata.st_size - len(prefix)
        self.assertGreater(remaining, 1)
        poison_source.write_bytes(prefix + b"x" * (remaining - 1) + b"\n")
        os.utime(
            poison_source,
            ns=(rootfs_metadata.st_atime_ns, rootfs_metadata.st_mtime_ns),
        )

        cache_path = Path(importlib.util.cache_from_source(str(copied_rootfs_source)))
        cache_path.parent.mkdir(mode=0o700)
        py_compile.compile(
            str(poison_source),
            cfile=str(cache_path),
            dfile=str(copied_rootfs_source),
            doraise=True,
        )
        self.assertTrue(cache_path.is_file())

        self.run_common_agent_manifest_materializer(
            materializer=copied_materializer,
        )
        self.assertFalse(marker.exists())
        self.assertTrue(self.generated_manifest.is_file())

    def test_materializes_packager_valid_exact_contract(self) -> None:
        self.run_materializer()
        value = json.loads(self.output.read_text(encoding="utf-8"))
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], "org.trillionnium.rootfs-package.contract.v9")
        self.assertEqual(
            value["admission"]["decision"],
            "HOLD_IDENTITY_INDEPENDENCE_EVIDENCE_UNVERIFIED",
        )
        self.assertFalse(value["admission"]["release_allowed"])
        self.assertFalse(
            value["admission"]["identity_independence_gate"]
            ["counterfactual_same_source_rebuild"]["verified"]
        )
        self.assertEqual(
            value["common_build_evidence"]["upstream_source_bom_receipt_claim"][
                "receipt_id"
            ],
            "sha256:" + "5" * 64,
        )
        self.assertEqual(
            value["common_build_evidence"]["source_bom_claim_authority"],
            self.materializer.SOURCE_BOM_CLAIM_AUTHORITY,
        )
        self.assertEqual(
            value["common_build_evidence"]["toolchain_claim_authority"],
            self.materializer.TOOLCHAIN_CLAIM_AUTHORITY,
        )
        for field in ("source_bom_claim_authority", "toolchain_claim_authority"):
            self.assertEqual(
                value["common_build_evidence"][field]["source"],
                "content_hash_bound_common_and_self_hashed_launcher_receipt",
            )
        self.assertFalse(
            value["common_build_evidence"]["launcher_ab"][
                "physical_source_bom_or_live_graph_remeasured_by_this_stage"
            ]
        )
        self.assertTrue(
            value["common_build_evidence"]["launcher_ab"][
                "same_upstream_source_bom_receipt_claim"
            ]
        )
        self.assertEqual(
            value["common_build_evidence"]
            ["stable_principal_launcher_measurement"]
            ["launcher_executable_sha256"],
            sha256(self.codex),
        )
        self.assertTrue(
            value["common_build_evidence"]["launcher_ab"]
            ["deterministic_artifact_set_ab_verified"]
        )
        self.assertEqual(
            value["common_build_evidence"]["elf_inspector"]["role"],
            "elf_inspector",
        )
        self.assertEqual(
            value["common_build_evidence"][
                "upstream_receipt_toolchain_snapshot_claim"
            ],
            self.materializer.EXPECTED_TOOLCHAIN_SNAPSHOT_BINDING,
        )
        self.assertTrue(
            value["common_build_evidence"][
                "upstream_receipt_target_compiler_closure_claim"
            ]
            ["snapshot_tree_fully_remeasured_before_and_after_build"]
        )
        self.assertFalse(
            value["common_build_evidence"][
                "upstream_receipt_target_compiler_closure_claim"
            ]
            ["complete_host_execution_runtime_closure"]
        )
        self.assertEqual(value["source_date_epoch"], 1_700_000_000)
        self.assertEqual(
            value["tools"]["zstd"],
            {"bytes": self.zstd.stat().st_size, "sha256": sha256(self.zstd)},
        )
        for name, path in (
            ("base_rootfs", self.base),
            ("daemon", self.daemon),
            ("codex", self.codex),
            ("system_api_tool", self.system_api_tool),
            ("accessibility_tool", self.accessibility_tool),
            ("system_api_replay_sync", self.system_api_replay_sync),
            ("agent_manifest", self.manifest),
        ):
            self.assertEqual(value["inputs"][name]["bytes"], path.stat().st_size)
            self.assertEqual(value["inputs"][name]["sha256"], sha256(path))
        self.assertEqual(
            value["inputs"]["common_artifact_set_receipt"]["sha256"],
            sha256(self.common_artifact_set_receipt),
        )
        self.assertEqual(
            value["inputs"]["common_launcher_ab_receipt"]["sha256"],
            sha256(self.common_launcher_ab_receipt),
        )
        self.assertEqual(
            value["inputs"]["codex"]["install"]["path"],
            "usr/lib/trillionnium/agents/codex/2026.7.1/"
            "aarch64-unknown-linux-musl/bin/codex",
        )
        self.assertEqual(
            value["inputs"]["agent_manifest"]["required_fields"], manifest
        )
        self.assertEqual(
            value["inputs"]["agent_manifest"]["allowed_fields"], sorted(manifest)
        )
        self.assertEqual(
            value["inputs"]["agent_manifest"]["install"]["path"],
            "etc/trillionnium/agents/agent-codex-direct-v1.json",
        )
        for field in (
            "legacy_duplicate_directory_migrations",
            "legacy_prune_members",
            "legacy_raw_name_prune_members",
        ):
            self.assertEqual(value["security"][field], [])
        self.assertIsNone(
            value["security"]["legacy_absolute_symlink_migration"]
        )
        self.assertEqual(
            value["security"]["forbidden_content_markers"],
            REQUIRED_FORBIDDEN_CONTENT_MARKERS,
        )
        output_metadata = self.output.stat()
        self.assertEqual(stat.S_IMODE(output_metadata.st_mode), 0o444)
        self.assertEqual(output_metadata.st_nlink, 1)
        self.assertEqual(output_metadata.st_uid, os.geteuid())
        self.assertEqual(output_metadata.st_mtime_ns, 1_700_000_000_000_000_000)
        self.assertEqual(
            list(self.root.glob(f".{self.output.name}.tmp-*")), []
        )

        spec = importlib.util.spec_from_file_location("rootfs_packager_fixture", PACKAGER)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        normalized, raw = module.load_contract(self.output)
        self.assertEqual(raw["schema"], value["schema"])
        self.assertEqual(normalized["inputs"]["codex"]["sha256"], sha256(self.codex))
        self.assertEqual(
            module.ANDROID_STAGING_FILTER_SCHEMA,
            "org.trillionnium.rootfs-tar-staging-filter.v1",
        )
        self.assertEqual(
            module.ANDROID_STAGING_FILTER_SOURCE_SHA256,
            "dc48c9ce97f1e64a62e45d00350b44801adb7cc0f60f8666b1d5e87696ce6092",
        )

    def test_rejects_identity_mismatch_without_output(self) -> None:
        self.thaw(self.manifest)
        self.write_manifest(identity="a" * 64)
        self.manifest.chmod(0o444)
        completed = self.run_materializer(expect_ok=False)
        self.assertIn("does not equal the Codex SHA-256", completed.stderr)
        self.assertFalse(self.output.exists())

    def test_rejects_template_that_preactivates_agent(self) -> None:
        self.thaw(self.template)
        value = json.loads(self.template.read_text(encoding="utf-8"))
        required = value["inputs"]["agent_manifest"]["required_fields"]
        required["enabled"] = True
        required["health"] = "ready"
        self.template.write_text(json.dumps(value), encoding="utf-8")
        self.template.chmod(0o444)
        completed = self.run_materializer(expect_ok=False)
        self.assertIn("must remain disabled until product admission", completed.stderr)
        self.assertFalse(self.output.exists())

    def test_rejects_dynamic_codex_and_non_aarch64_daemon(self) -> None:
        self.thaw(self.codex)
        self.codex.write_bytes(fake_aarch64_elf(interpreter=True))
        self.codex.chmod(0o555)
        self.thaw(self.manifest)
        self.write_manifest()
        self.manifest.chmod(0o444)
        self.assertIn(
            "PT_INTERP",
            self.run_materializer(expect_ok=False).stderr,
        )
        self.codex.unlink()
        self.codex.write_bytes(fake_aarch64_elf())
        self.codex.chmod(0o555)
        self.thaw(self.daemon)
        self.daemon.write_bytes(fake_aarch64_elf(machine=62))
        self.daemon.chmod(0o555)
        self.thaw(self.manifest)
        self.write_manifest()
        self.manifest.chmod(0o444)
        self.assertIn("not an AArch64", self.run_materializer(expect_ok=False).stderr)

    def test_rejects_missing_or_non_aarch64_replay_sync(self) -> None:
        missing = self.root / "missing-replay-sync"
        completed = self.run_materializer(
            expect_ok=False,
            **{"system-api-replay-sync": missing},
        )
        self.assertIn("path component is missing", completed.stderr)
        self.thaw(self.system_api_replay_sync)
        self.system_api_replay_sync.write_bytes(fake_aarch64_elf(machine=62))
        self.system_api_replay_sync.chmod(0o555)
        completed = self.run_materializer(expect_ok=False)
        self.assertIn("not an AArch64", completed.stderr)

    def test_rejects_missing_swapped_or_internally_drifted_common_receipt(self) -> None:
        missing = self.root / "missing-common-codex-rootfs-artifact-set.v5.json"
        completed = self.run_materializer(
            expect_ok=False,
            **{"common-artifact-set-receipt": missing},
        )
        self.assertIn("path component is missing", completed.stderr)

        self.thaw(self.common_artifact_set_receipt)
        self.write_common_artifact_set_receipt(
            artifact_overrides={"system_api_tool": {"sha256": "e" * 64}}
        )
        self.common_artifact_set_receipt.chmod(0o444)
        completed = self.run_materializer(expect_ok=False)
        self.assertIn(
            "does not match physical artifact: system_api_tool", completed.stderr
        )

        self.thaw(self.common_artifact_set_receipt)
        self.write_common_artifact_set_receipt()
        value = json.loads(
            self.common_artifact_set_receipt.read_text(encoding="utf-8")
        )
        value["status"] = "swapped_unreviewed_receipt"
        self.common_artifact_set_receipt.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        self.common_artifact_set_receipt.chmod(0o444)
        completed = self.run_materializer(expect_ok=False)
        self.assertIn("decision or posture drifted", completed.stderr)

    def test_rejects_common_receipt_provenance_and_identity_split_drift(self) -> None:
        cases = (
            (
                ("source_bom", "receipt_id"),
                "5" * 64,
                "source BOM binding is malformed",
            ),
            (
                ("source_bom", "source_set_sha256"),
                "0" * 64,
                "source BOM binding is malformed",
            ),
            (
                ("source_bom", "resolved_manifest_sha256"),
                "0" * 64,
                "source BOM binding is malformed",
            ),
            (
                ("source_bom", "source_set_sha256"),
                "5" * 64,
                "common launcher A/B source BOM is cross-spliced",
            ),
            (
                ("source_bom", "resolved_manifest_sha256"),
                "5" * 64,
                "common launcher A/B source BOM is cross-spliced",
            ),
            (
                (
                    "stable_principal_launcher_measurement",
                    "stable_principal_contract_sha256",
                ),
                "0" * 64,
                "stable-principal launcher measurement drifted",
            ),
            (
                (
                    "stable_principal_launcher_measurement",
                    "launcher_executable_sha256",
                ),
                "f" * 64,
                "launcher measurement is not physically bound",
            ),
            (
                (
                    "legacy_descriptor_contamination_hold_gate",
                    "counterfactual_same_source_rebuild",
                    "verified",
                ),
                True,
                "must remain unverified HOLD",
            ),
            (
                (
                    "legacy_descriptor_contamination_hold_gate",
                    "digests",
                    "launcher identity",
                ),
                "0" * 64,
                "legacy descriptor contamination gate drifted",
            ),
            (
                ("compiler", "target"),
                "x86_64-linux-gnu",
                "compiler custody is malformed",
            ),
            (
                ("compiler", "sha256"),
                "a" * 64,
                "frozen Mobian snapshot leaf",
            ),
            (
                ("toolchain_snapshot", "manifest_sha256"),
                "a" * 64,
                "frozen Mobian snapshot",
            ),
            (
                ("target_compiler_closure", "components", "ld", "sha256"),
                "a" * 64,
                "components.ld differs from the frozen Mobian snapshot",
            ),
            (
                ("target_compiler_closure", "complete_host_execution_runtime_closure"),
                True,
                "posture differs",
            ),
        )
        for field_path, replacement, message in cases:
            with self.subTest(field_path=field_path, replacement=replacement):
                self.thaw(self.common_artifact_set_receipt)
                self.write_common_artifact_set_receipt()
                value = json.loads(
                    self.common_artifact_set_receipt.read_text(encoding="utf-8")
                )
                target = value
                for field in field_path[:-1]:
                    target = target[field]
                target[field_path[-1]] = replacement
                self.common_artifact_set_receipt.write_text(
                    json.dumps(value, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                self.common_artifact_set_receipt.chmod(0o444)
                completed = self.run_materializer(expect_ok=False)
                self.assertIn(message, completed.stderr)

    def test_materializes_consistent_supplied_source_bom_digests(self) -> None:
        self.thaw(self.common_artifact_set_receipt)
        self.thaw(self.common_launcher_ab_receipt)
        value = json.loads(
            self.common_artifact_set_receipt.read_text(encoding="utf-8")
        )
        value["source_bom"]["source_set_sha256"] = "d" * 64
        value["source_bom"]["resolved_manifest_sha256"] = "e" * 64
        self.common_artifact_set_receipt.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        self.write_common_launcher_ab_receipt()
        self.freeze_inputs()

        self.run_materializer()

        contract = json.loads(self.output.read_text(encoding="utf-8"))
        source_bom = contract["common_build_evidence"][
            "upstream_source_bom_receipt_claim"
        ]
        self.assertEqual(
            source_bom["source_set_sha256"],
            "d" * 64,
        )
        self.assertEqual(
            source_bom["resolved_manifest_sha256"],
            "e" * 64,
        )

    def test_rejects_common_receipt_when_physical_effect_tool_changes(self) -> None:
        self.thaw(self.system_api_tool)
        self.system_api_tool.write_bytes(
            fake_aarch64_elf(interpreter=True) + b"physical-drift"
        )
        self.system_api_tool.chmod(0o555)
        completed = self.run_materializer(expect_ok=False)
        self.assertIn(
            "does not match physical artifact: system_api_tool", completed.stderr
        )

    def test_requires_and_reverifies_common_launcher_ab_receipt(self) -> None:
        command = self.command()
        option = command.index("--common-launcher-ab-receipt")
        del command[option : option + 2]
        completed = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("--common-launcher-ab-receipt", completed.stderr)

        self.thaw(self.common_launcher_ab_receipt)
        value = json.loads(self.common_launcher_ab_receipt.read_bytes())
        value["artifacts"]["system_api_tool"]["sha256"] = "a" * 64
        value.pop("receipt_id")
        pretty = lambda item: (
            json.dumps(
                item,
                ensure_ascii=False,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        value["receipt_id"] = "sha256:" + hashlib.sha256(pretty(value)).hexdigest()
        self.common_launcher_ab_receipt.write_bytes(pretty(value))
        self.common_launcher_ab_receipt.chmod(0o444)
        completed = self.run_materializer(expect_ok=False)
        self.assertIn("artifact system_api_tool is not closed", completed.stderr)

    def test_rejects_launcher_ab_tool_or_canonical_encoding_drift(self) -> None:
        self.thaw(self.common_launcher_ab_receipt)
        value = json.loads(self.common_launcher_ab_receipt.read_bytes())
        value["compiler"]["uid"] = 1
        value.pop("receipt_id")
        pretty = lambda item: (
            json.dumps(
                item,
                ensure_ascii=False,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        value["receipt_id"] = "sha256:" + hashlib.sha256(pretty(value)).hexdigest()
        self.common_launcher_ab_receipt.write_bytes(pretty(value))
        self.common_launcher_ab_receipt.chmod(0o444)
        completed = self.run_materializer(expect_ok=False)
        self.assertIn("compiler custody differs from common v5", completed.stderr)

        self.thaw(self.common_launcher_ab_receipt)
        self.write_common_launcher_ab_receipt()
        value = json.loads(self.common_launcher_ab_receipt.read_bytes())
        self.common_launcher_ab_receipt.write_text(
            json.dumps(value, separators=(",", ":"), sort_keys=True),
            encoding="utf-8",
        )
        self.common_launcher_ab_receipt.chmod(0o444)
        completed = self.run_materializer(expect_ok=False)
        self.assertIn("not canonical indented JSON", completed.stderr)

    def test_rejects_replay_sync_template_path_or_static_policy_drift(self) -> None:
        self.thaw(self.template)
        value = json.loads(self.template.read_text(encoding="utf-8"))
        replay = value["inputs"]["system_api_replay_sync"]
        replay["install"]["path"] = "usr/local/bin/unreviewed-replay-sync"
        self.template.write_text(json.dumps(value), encoding="utf-8")
        self.template.chmod(0o444)
        completed = self.run_materializer(expect_ok=False)
        self.assertIn("install path drifted", completed.stderr)

        self.thaw(self.template)
        value = json.loads(TEMPLATE.read_text(encoding="utf-8"))
        value["inputs"]["system_api_replay_sync"]["require_static"] = True
        self.template.write_text(json.dumps(value), encoding="utf-8")
        self.template.chmod(0o444)
        completed = self.run_materializer(expect_ok=False)
        self.assertIn("weakens static policy", completed.stderr)

    def test_rejects_duplicate_or_nonfinite_json(self) -> None:
        self.thaw(self.manifest)
        value = json.loads(self.manifest.read_text(encoding="utf-8"))
        encoded = json.dumps(value)
        self.manifest.write_text(
            encoded[:-1] + ',"identity_key_sha256":"' + sha256(self.codex) + '"}',
            encoding="utf-8",
        )
        self.manifest.chmod(0o444)
        self.assertIn("duplicate", self.run_materializer(expect_ok=False).stderr)
        self.thaw(self.manifest)
        self.write_manifest()
        value = json.loads(self.manifest.read_text(encoding="utf-8"))
        value["registered_at_unix_ms"] = float("nan")
        self.manifest.write_text(json.dumps(value), encoding="utf-8")
        self.manifest.chmod(0o444)
        self.assertIn("non-finite", self.run_materializer(expect_ok=False).stderr)

    def test_rejects_nonempty_migration_arrays(self) -> None:
        self.thaw(self.template)
        value = json.loads(self.template.read_text(encoding="utf-8"))
        value["security"]["legacy_prune_members"] = [{"path": "forbidden"}]
        self.template.write_text(json.dumps(value), encoding="utf-8")
        self.template.chmod(0o444)
        completed = self.run_materializer(expect_ok=False)
        self.assertIn("legacy_prune_members must remain empty", completed.stderr)

        self.thaw(self.template)
        value["security"]["legacy_prune_members"] = []
        value["security"]["legacy_absolute_symlink_migration"] = {
            "rewrite": "root-absolute-to-relative-v1",
            "expected_count": 1,
            "inventory_sha256": "0" * 64,
        }
        self.template.write_text(json.dumps(value), encoding="utf-8")
        self.template.chmod(0o444)
        completed = self.run_materializer(expect_ok=False)
        self.assertIn(
            "legacy_absolute_symlink_migration must remain null",
            completed.stderr,
        )

    def test_rejects_drifted_forbidden_content_marker_closure(self) -> None:
        for index, marker in enumerate(REQUIRED_FORBIDDEN_CONTENT_MARKERS):
            with self.subTest(marker=marker):
                self.thaw(self.template)
                value = json.loads(TEMPLATE.read_text(encoding="utf-8"))
                value["security"]["forbidden_content_markers"].pop(index)
                self.template.write_text(json.dumps(value), encoding="utf-8")
                self.template.chmod(0o444)
                completed = self.run_materializer(expect_ok=False)
                self.assertIn(
                    "forbidden content marker closure mismatch", completed.stderr
                )
                self.assertFalse(self.output.exists())

    def test_rejects_writable_or_symlinked_inputs(self) -> None:
        self.template.chmod(0o644)
        self.assertIn("not a bounded frozen", self.run_materializer(expect_ok=False).stderr)
        self.template.chmod(0o444)
        alias = self.root / "codex-alias"
        alias.symlink_to(self.codex)
        self.assertIn(
            "symbolic link",
            self.run_materializer(expect_ok=False, **{"codex-binary": alias}).stderr,
        )

    def test_requires_frozen_explicit_zstd(self) -> None:
        command = self.command()
        zstd_index = command.index("--zstd")
        del command[zstd_index : zstd_index + 2]
        completed = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("--zstd", completed.stderr)
        self.assertFalse(self.output.exists())

        self.zstd.chmod(0o755)
        completed = self.run_materializer(expect_ok=False)
        self.assertIn("not a bounded frozen regular file", completed.stderr)
        self.assertFalse(self.output.exists())
        self.zstd.chmod(0o555)

        alias = self.root / "zstd-alias"
        alias.symlink_to(self.zstd)
        completed = self.run_materializer(
            expect_ok=False, **{"zstd": alias}
        )
        self.assertIn("symbolic link", completed.stderr)
        self.assertFalse(self.output.exists())

    def test_rejects_existing_output_and_symlinked_output_parent(self) -> None:
        self.output.write_text("existing", encoding="utf-8")
        self.output.chmod(0o444)
        completed = self.run_materializer(expect_ok=False)
        self.assertIn("overwrite is forbidden", completed.stderr)
        self.output.unlink()
        real_parent = self.root / "real-output"
        real_parent.mkdir(mode=0o700)
        linked_parent = self.root / "linked-output"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        linked_output = linked_parent / "contract.json"
        completed = self.run_materializer(expect_ok=False, output=linked_output)
        self.assertIn("symbolic link", completed.stderr)
        self.assertFalse((real_parent / "contract.json").exists())

    def test_anonymous_staging_never_exposes_or_unlinks_a_temp_name(self) -> None:
        materializer = self.load_materializer("anonymous_staging")
        callback_calls = 0

        def check_before_commit() -> None:
            nonlocal callback_calls
            callback_calls += 1
            self.assertFalse(self.output.exists())
            self.assertEqual(
                list(self.root.glob(f".{self.output.name}.tmp-*")),
                [],
            )

        with mock.patch.object(
            materializer.os,
            "unlink",
            side_effect=AssertionError("publication must not unlink pathnames"),
        ) as unlink:
            materializer.publish_new(
                self.output,
                b'{"fixture": "anonymous-staging"}\n',
                1_700_000_000,
                check_before_commit,
            )
        self.assertEqual(callback_calls, 2)
        unlink.assert_not_called()
        self.assertEqual(
            self.output.read_bytes(),
            b'{"fixture": "anonymous-staging"}\n',
        )
        self.assertEqual(list(self.root.glob(f".{self.output.name}.tmp-*")), [])

    def test_instant_final_name_swap_after_link_never_deletes_foreign_inode(self) -> None:
        materializer = self.load_materializer("link_then_instant_swap")
        real_link = os.link
        retained_created = self.root / "retained-created-output"
        foreign_bytes = b"foreign output replacement\n"
        foreign_inode: tuple[int, int] | None = None

        def link_then_swap_and_error(*args: object, **kwargs: object) -> None:
            nonlocal foreign_inode
            real_link(*args, **kwargs)
            self.output.rename(retained_created)
            self.output.write_bytes(foreign_bytes)
            self.output.chmod(0o444)
            metadata = self.output.stat()
            foreign_inode = (metadata.st_dev, metadata.st_ino)
            raise RuntimeError(
                "injected non-OS error after link and instantaneous name swap"
            )

        try:
            with (
                mock.patch.object(
                    materializer.os,
                    "link",
                    side_effect=link_then_swap_and_error,
                ),
                mock.patch.object(
                    materializer.os,
                    "unlink",
                    side_effect=AssertionError(
                        "an uncertain pathname must never be unlinked"
                    ),
                ) as unlink,
            ):
                with self.assertRaisesRegex(
                    materializer.MaterializerError,
                    "link outcome is uncertain.*no pathname was removed",
                ):
                    materializer.publish_new(
                        self.output,
                        b'{"fixture": "link-then-swap"}\n',
                        1_700_000_000,
                        lambda: None,
                    )
            unlink.assert_not_called()
            self.assertEqual(self.output.read_bytes(), foreign_bytes)
            self.assertIsNotNone(foreign_inode)
            metadata = self.output.stat()
            self.assertEqual((metadata.st_dev, metadata.st_ino), foreign_inode)
            self.assertEqual(
                retained_created.read_bytes(),
                b'{"fixture": "link-then-swap"}\n',
            )
        finally:
            self.output.unlink(missing_ok=True)
            retained_created.unlink(missing_ok=True)

    def test_second_precommit_check_failure_never_publishes(self) -> None:
        materializer = self.load_materializer("second_precommit_failure")
        calls = 0

        def fail_second_check() -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise materializer.MaterializerError(
                    "injected second pre-commit failure"
                )

        with (
            mock.patch.object(materializer.os, "link") as link,
            mock.patch.object(
                materializer.os,
                "unlink",
                side_effect=AssertionError("pre-commit failure must not unlink"),
            ) as unlink,
        ):
            with self.assertRaisesRegex(
                materializer.MaterializerError,
                "injected second pre-commit failure",
            ):
                materializer.publish_new(
                    self.output,
                    b'{"fixture": "second-precommit"}\n',
                    1_700_000_000,
                    fail_second_check,
                )
        self.assertEqual(calls, 2)
        link.assert_not_called()
        unlink.assert_not_called()
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(f".{self.output.name}.tmp-*")), [])

    def test_parent_rename_restore_is_detected_without_pathname_rollback(self) -> None:
        materializer = self.load_materializer("parent_rename_restore")
        real_link = os.link
        publish_parent = self.root / "publish-parent"
        publish_parent.mkdir(mode=0o700)
        output = publish_parent / "contract.json"
        detached_parent = self.root / "detached-publish-parent"
        alternate_parent = self.root / "alternate-publish-parent"
        alternate_parent.mkdir(mode=0o700)
        swapped = False

        def rename_restore_around_link(*args: object, **kwargs: object) -> None:
            nonlocal swapped
            publish_parent.rename(detached_parent)
            alternate_parent.rename(publish_parent)
            swapped = True
            try:
                real_link(*args, **kwargs)
            finally:
                publish_parent.rename(alternate_parent)
                detached_parent.rename(publish_parent)

        try:
            with mock.patch.object(
                materializer.os,
                "link",
                side_effect=rename_restore_around_link,
            ):
                with self.assertRaisesRegex(
                    materializer.MaterializerError,
                    "link committed.*output-parent custody became uncertain.*"
                    "remains visible.*not rolled back",
                ):
                    materializer.publish_new(
                        output,
                        b'{"fixture": "parent-rename-restore"}\n',
                        1_700_000_000,
                        lambda: None,
                    )
            self.assertTrue(swapped)
            self.assertEqual(
                output.read_bytes(),
                b'{"fixture": "parent-rename-restore"}\n',
            )
            self.assertEqual(list(alternate_parent.iterdir()), [])
        finally:
            output.unlink(missing_ok=True)

    def test_non_os_frozen_input_close_fault_still_closes_the_entire_chain(self) -> None:
        materializer = self.load_materializer("close_fault")
        frozen = materializer.FrozenInput.open(
            self.daemon,
            "daemon",
            materializer.MAX_BINARY_BYTES,
            require_executable=True,
        )
        descriptors = [
            frozen.fd,
            *[component.fd for component in frozen.parents],
        ]
        first_closed = descriptors[-1]
        real_close = os.close
        closed: list[int] = []

        def close_then_report_error(descriptor: int) -> None:
            closed.append(descriptor)
            real_close(descriptor)
            if descriptor == first_closed:
                raise RuntimeError("injected close status failure")

        with mock.patch.object(
            materializer.os,
            "close",
            side_effect=close_then_report_error,
        ):
            with self.assertRaisesRegex(
                materializer.MaterializerError,
                "descriptor close did not complete cleanly.*injected close status failure",
            ):
                frozen.close()

        self.assertEqual(set(closed), set(descriptors))
        for descriptor in descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_commit_fsync_failure_retains_output_and_reports_visibility(self) -> None:
        materializer = self.load_materializer("commit_fsync")
        real_fsync = os.fsync

        def fail_directory_fsync(file_descriptor: int) -> None:
            if stat.S_ISDIR(os.fstat(file_descriptor).st_mode):
                raise OSError("injected commit directory fsync failure")
            real_fsync(file_descriptor)

        try:
            with (
                mock.patch.object(
                    materializer.os,
                    "fsync",
                    side_effect=fail_directory_fsync,
                ),
                mock.patch.object(
                    materializer.os,
                    "unlink",
                    side_effect=AssertionError(
                        "a committed pathname must not be rolled back"
                    ),
                ) as unlink,
            ):
                with self.assertRaisesRegex(
                    materializer.MaterializerError,
                    "link committed.*durability is uncertain.*remains visible.*"
                    "not rolled back",
                ):
                    materializer.publish_new(
                        self.output,
                        b'{"fixture": "commit-fsync"}\n',
                        1_700_000_000,
                        lambda: None,
                    )
            unlink.assert_not_called()
            self.assertEqual(
                self.output.read_bytes(),
                b'{"fixture": "commit-fsync"}\n',
            )
        finally:
            self.output.unlink(missing_ok=True)

    def test_postcommit_close_error_is_composite_and_other_fds_close(self) -> None:
        materializer = self.load_materializer("postcommit_close_fault")
        real_guard_close = materializer.NamespaceMutationGuard.close
        baseline = len(os.listdir("/proc/self/fd"))

        def close_guard_then_report_error(guard: object) -> None:
            real_guard_close(guard)
            raise materializer.MaterializerError(
                "injected namespace guard close status failure"
            )

        try:
            with mock.patch.object(
                materializer.NamespaceMutationGuard,
                "close",
                side_effect=close_guard_then_report_error,
                autospec=True,
            ):
                with self.assertRaisesRegex(
                    materializer.MaterializerError,
                    "publication cleanup failed after the output link committed.*"
                    "output remains visible.*injected namespace guard close",
                ):
                    materializer.publish_new(
                        self.output,
                        b'{"fixture": "postcommit-close-fault"}\n',
                        1_700_000_000,
                        lambda: None,
                    )
            self.assertEqual(
                self.output.read_bytes(),
                b'{"fixture": "postcommit-close-fault"}\n',
            )
            self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)
        finally:
            self.output.unlink(missing_ok=True)

    def test_final_gate_rejects_permanent_in_place_post_link_mutation(self) -> None:
        materializer = self.load_materializer("post_link_permanent_mutation")
        real_assert_quiet = materializer.NamespaceMutationGuard.assert_quiet
        content = b'{"fixture": "post-link-original"}\n'
        altered = b'{"fixture": "post-link-altered!"}\n'
        self.assertEqual(len(content), len(altered))

        def final_assert_then_mutate(guard: object, phase: str) -> None:
            real_assert_quiet(guard, phase)
            if phase != "publication commit":
                return
            self.output.chmod(0o600)
            self.output.write_bytes(altered)
            self.output.chmod(0o444)
            os.utime(
                self.output,
                ns=(
                    1_700_000_000_000_000_000,
                    1_700_000_000_000_000_000,
                ),
            )

        try:
            with (
                mock.patch.object(
                    materializer.NamespaceMutationGuard,
                    "assert_quiet",
                    side_effect=final_assert_then_mutate,
                    autospec=True,
                ),
                mock.patch.object(
                    materializer.os,
                    "unlink",
                    side_effect=AssertionError(
                        "a committed pathname must never be rolled back"
                    ),
                ) as unlink,
            ):
                with self.assertRaisesRegex(
                    materializer.MaterializerError,
                    "link committed but final pathname/content custody failed.*"
                    "remains visible.*not rolled back",
                ):
                    materializer.publish_new(
                        self.output,
                        content,
                        1_700_000_000,
                        lambda: None,
                    )
            unlink.assert_not_called()
            self.assertEqual(self.output.read_bytes(), altered)
        finally:
            self.output.unlink(missing_ok=True)

    def test_final_gate_rejects_restored_in_place_mutation_by_ctime(self) -> None:
        materializer = self.load_materializer("post_link_restored_mutation")
        real_guard_close = materializer.NamespaceMutationGuard.close
        content = b'{"fixture": "post-link-original"}\n'
        transient = b'{"fixture": "post-link-altered!"}\n'
        self.assertEqual(len(content), len(transient))
        ctimes: list[int] = []

        def close_then_mutate_and_restore(guard: object) -> None:
            real_guard_close(guard)
            ctimes.append(self.output.stat().st_ctime_ns)
            self.output.chmod(0o600)
            self.output.write_bytes(transient)
            self.output.write_bytes(content)
            self.output.chmod(0o444)
            os.utime(
                self.output,
                ns=(
                    1_700_000_000_000_000_000,
                    1_700_000_000_000_000_000,
                ),
            )
            ctimes.append(self.output.stat().st_ctime_ns)

        try:
            with (
                mock.patch.object(
                    materializer.NamespaceMutationGuard,
                    "close",
                    side_effect=close_then_mutate_and_restore,
                    autospec=True,
                ),
                mock.patch.object(
                    materializer.os,
                    "unlink",
                    side_effect=AssertionError(
                        "a committed pathname must never be rolled back"
                    ),
                ) as unlink,
            ):
                with self.assertRaisesRegex(
                    materializer.MaterializerError,
                    "link committed but final pathname/content custody failed.*"
                    "retained inode changed after publication",
                ):
                    materializer.publish_new(
                        self.output,
                        content,
                        1_700_000_000,
                        lambda: None,
                    )
            unlink.assert_not_called()
            self.assertEqual(self.output.read_bytes(), content)
            metadata = self.output.stat()
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o444)
            self.assertEqual(metadata.st_mtime_ns, 1_700_000_000_000_000_000)
            self.assertEqual(len(ctimes), 2)
            self.assertNotEqual(ctimes[0], ctimes[1])
        finally:
            self.output.unlink(missing_ok=True)

    def test_final_gate_rejects_pathname_replace_during_guard_teardown(self) -> None:
        materializer = self.load_materializer("post_link_pathname_replace")
        real_guard_close = materializer.NamespaceMutationGuard.close
        content = b'{"fixture": "post-link-original"}\n'
        retained_original = self.root / "retained-original-contract"
        # Make the replacement byte-for-byte identical so inode/namespace
        # custody, rather than a convenient size or digest mismatch, rejects it.
        foreign = content

        def close_then_replace(guard: object) -> None:
            real_guard_close(guard)
            self.output.rename(retained_original)
            self.output.write_bytes(foreign)
            self.output.chmod(0o444)
            os.utime(
                self.output,
                ns=(
                    1_700_000_000_000_000_000,
                    1_700_000_000_000_000_000,
                ),
            )

        try:
            with (
                mock.patch.object(
                    materializer.NamespaceMutationGuard,
                    "close",
                    side_effect=close_then_replace,
                    autospec=True,
                ),
                mock.patch.object(
                    materializer.os,
                    "unlink",
                    side_effect=AssertionError(
                        "a replacement pathname must never be rolled back"
                    ),
                ) as unlink,
            ):
                with self.assertRaisesRegex(
                    materializer.MaterializerError,
                    "link committed but final pathname/content custody failed.*"
                    "remains visible.*not rolled back",
                ):
                    materializer.publish_new(
                        self.output,
                        content,
                        1_700_000_000,
                        lambda: None,
                    )
            unlink.assert_not_called()
            self.assertEqual(self.output.read_bytes(), foreign)
            self.assertEqual(retained_original.read_bytes(), content)
            self.assertNotEqual(
                (self.output.stat().st_dev, self.output.stat().st_ino),
                (
                    retained_original.stat().st_dev,
                    retained_original.stat().st_ino,
                ),
            )
        finally:
            self.output.unlink(missing_ok=True)
            retained_original.unlink(missing_ok=True)

    def test_run_final_gate_spans_every_retained_input_teardown(self) -> None:
        materializer = self.load_materializer("input_teardown_output_mutation")
        args = materializer.build_parser().parse_args(self.command()[2:])
        real_frozen_close = materializer.FrozenInput.close
        mutated_labels: list[str] = []
        expected_output: list[bytes] = []
        ctimes: list[int] = []

        def close_first_then_mutate_and_restore(frozen: object) -> None:
            real_frozen_close(frozen)
            if mutated_labels:
                return
            mutated_labels.append(frozen.label)
            original = self.output.read_bytes()
            expected_output.append(original)
            transient = bytearray(original)
            transient[0] ^= 1
            ctimes.append(self.output.stat().st_ctime_ns)
            self.output.chmod(0o600)
            self.output.write_bytes(transient)
            self.output.write_bytes(original)
            self.output.chmod(0o444)
            os.utime(
                self.output,
                ns=(
                    1_700_000_000_000_000_000,
                    1_700_000_000_000_000_000,
                ),
            )
            ctimes.append(self.output.stat().st_ctime_ns)

        try:
            with mock.patch.object(
                materializer.FrozenInput,
                "close",
                side_effect=close_first_then_mutate_and_restore,
                autospec=True,
            ), self.assertRaisesRegex(
                materializer.MaterializerError,
                "link committed but final pathname/content custody failed.*"
                "retained inode changed after publication",
            ):
                materializer.run(args)
            self.assertEqual(len(mutated_labels), 1)
            self.assertEqual(len(expected_output), 1)
            self.assertEqual(len(ctimes), 2)
            self.assertNotEqual(ctimes[0], ctimes[1])
            self.assertEqual(self.output.read_bytes(), expected_output[0])
            metadata = self.output.stat()
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o444)
            self.assertEqual(metadata.st_mtime_ns, 1_700_000_000_000_000_000)
        finally:
            self.output.unlink(missing_ok=True)

    def test_cli_reports_post_link_primary_and_cleanup_secondary(self) -> None:
        materializer = self.load_materializer("primary_cleanup_composite")
        real_fsync = os.fsync
        real_guard_close = materializer.NamespaceMutationGuard.close

        def fail_directory_fsync(file_descriptor: int) -> None:
            if stat.S_ISDIR(os.fstat(file_descriptor).st_mode):
                raise OSError("injected primary directory fsync failure")
            real_fsync(file_descriptor)

        def close_guard_then_report_error(guard: object) -> None:
            real_guard_close(guard)
            raise materializer.MaterializerError(
                "injected secondary namespace guard close failure"
            )

        stderr = io.StringIO()
        try:
            with (
                mock.patch.object(
                    materializer.os,
                    "fsync",
                    side_effect=fail_directory_fsync,
                ),
                mock.patch.object(
                    materializer.NamespaceMutationGuard,
                    "close",
                    side_effect=close_guard_then_report_error,
                    autospec=True,
                ),
                mock.patch.object(sys, "argv", self.command()[1:]),
                redirect_stderr(stderr),
            ):
                self.assertEqual(materializer.main(), 1)
            visible_error = stderr.getvalue()
            self.assertIn("injected primary directory fsync failure", visible_error)
            self.assertIn(
                "injected secondary namespace guard close failure",
                visible_error,
            )
            self.assertIn("primary:", visible_error)
            self.assertIn("cleanup:", visible_error)
            self.assertTrue(self.output.exists())
        finally:
            self.output.unlink(missing_ok=True)

    def test_outer_input_close_error_preserves_postcommit_visibility_error(self) -> None:
        materializer = self.load_materializer("outer_close_composite")
        args = materializer.build_parser().parse_args(self.command()[2:])
        real_fsync = os.fsync
        real_frozen_close = materializer.FrozenInput.close

        def fail_directory_fsync(file_descriptor: int) -> None:
            if stat.S_ISDIR(os.fstat(file_descriptor).st_mode):
                raise OSError("injected postcommit directory fsync failure")
            real_fsync(file_descriptor)

        def close_template_then_fail(frozen: object) -> None:
            real_frozen_close(frozen)
            if frozen.label == "template":
                raise RuntimeError("injected outer input close failure")

        try:
            with mock.patch.object(
                materializer.os,
                "fsync",
                side_effect=fail_directory_fsync,
            ), mock.patch.object(
                materializer.FrozenInput,
                "close",
                side_effect=close_template_then_fail,
                autospec=True,
            ), self.assertRaisesRegex(
                materializer.MaterializerError,
                "primary: materialized contract link committed.*"
                "output remains visible.*cleanup: injected outer input close failure",
            ):
                materializer.run(args)
            self.assertTrue(self.output.exists())
        finally:
            self.output.unlink(missing_ok=True)

    def test_second_precommit_gate_rejects_transient_input_swap(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "rootfs_contract_materializer_transient_swap_fixture", MATERIALIZER
        )
        assert spec is not None and spec.loader is not None
        materializer = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = materializer
        spec.loader.exec_module(materializer)

        alternate = self.root / "transient-alternate-trillionniumd"
        alternate.write_bytes(fake_aarch64_elf() + b"alternate-daemon")
        alternate.chmod(0o555)
        backup = self.root / "retained-original-trillionniumd"
        original_sha256 = sha256(self.daemon)
        real_publish = materializer.publish_new
        swapped = False
        callback_calls = 0

        def inject_swap_into_second_gate(
            path: Path,
            content: bytes,
            source_date_epoch: int,
            pre_commit_check: Callable[[], None],
            post_commit_teardown: Callable[[], None] | None = None,
        ) -> None:
            def checked() -> None:
                nonlocal callback_calls, swapped
                callback_calls += 1
                if callback_calls != 2:
                    pre_commit_check()
                    return
                swapped = True
                self.daemon.rename(backup)
                alternate.rename(self.daemon)
                try:
                    pre_commit_check()
                finally:
                    self.daemon.rename(alternate)
                    backup.rename(self.daemon)

            real_publish(
                path,
                content,
                source_date_epoch,
                checked,
                post_commit_teardown,
            )

        args = materializer.build_parser().parse_args(self.command()[2:])
        with mock.patch.object(
            materializer,
            "publish_new",
            side_effect=inject_swap_into_second_gate,
        ):
            with self.assertRaisesRegex(
                materializer.MaterializerError,
                "parent path component changed during final custody check",
            ):
                materializer.run(args)
        self.assertTrue(swapped)
        self.assertEqual(callback_calls, 2)
        self.assertEqual(sha256(self.daemon), original_sha256)
        self.assertFalse(self.output.exists())
        self.assertEqual(
            list(self.root.glob(f".{self.output.name}.tmp-*")), []
        )

    def test_rejects_shared_sticky_or_writable_ancestor_above_safe_leaf(self) -> None:
        materializer = self.load_materializer("shared_path_component")
        for mode in (0o1777, 0o1700, 0o0777, 0o0770):
            with self.subTest(mode=oct(mode)):
                shared = self.root / f"shared-{mode:o}"
                shared.mkdir(mode=0o700)
                shared.chmod(mode)
                safe_leaf = shared / "safe-leaf"
                safe_leaf.mkdir(mode=0o700)
                frozen_path = safe_leaf / "frozen-input"
                frozen_path.write_bytes(b"frozen shared-path fixture\n")
                frozen_path.chmod(0o444)
                with self.assertRaisesRegex(
                    materializer.MaterializerError,
                    "path component is shared, writable, or not owner-controlled",
                ):
                    materializer.FrozenInput.open(
                        frozen_path,
                        "shared input",
                        1024,
                    )

                output = safe_leaf / "contract.json"
                with self.assertRaisesRegex(
                    materializer.MaterializerError,
                    "path component is shared, writable, or not owner-controlled",
                ):
                    materializer.publish_new(
                        output,
                        b'{"fixture": "shared-path"}\n',
                        1_700_000_000,
                        lambda: None,
                    )
                self.assertFalse(output.exists())

    def test_publish_success_and_precommit_failure_do_not_leak_fds(self) -> None:
        materializer = self.load_materializer("fd_balance")
        baseline = len(os.listdir("/proc/self/fd"))

        for index in range(8):
            output = self.root / f"fd-success-{index}.json"
            materializer.publish_new(
                output,
                f'{{"fixture": "fd-success-{index}"}}\n'.encode(),
                1_700_000_000,
                lambda: None,
            )
            output.unlink()

        for index in range(8):
            output = self.root / f"fd-failure-{index}.json"

            def fail_before_commit() -> None:
                raise materializer.MaterializerError(
                    "injected fd-balance pre-commit failure"
                )

            with self.assertRaisesRegex(
                materializer.MaterializerError,
                "fd-balance pre-commit failure",
            ):
                materializer.publish_new(
                    output,
                    f'{{"fixture": "fd-failure-{index}"}}\n'.encode(),
                    1_700_000_000,
                    fail_before_commit,
                )
            self.assertFalse(output.exists())

        self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)

    def test_rejects_unsafe_adapter_version_path_segment(self) -> None:
        self.thaw(self.manifest)
        self.write_manifest(version="../../escape")
        self.manifest.chmod(0o444)
        completed = self.run_materializer(expect_ok=False)
        self.assertIn("safe install-path segment", completed.stderr)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
