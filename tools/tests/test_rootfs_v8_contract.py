#!/usr/bin/env python3

"""Rootfs package v9 and EROFS admission v4 HOLD contract tests."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parents[1]
REPOSITORY = TOOLS.parent


def load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, TOOLS / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PACKAGER = load_module("rootfs_v9_packager", "package_current_rootfs.py")
EROFS = load_module("rootfs_v9_erofs", "build_immutable_rootfs_erofs.py")
SOURCE_SET_SHA256 = "b" * 64
RESOLVED_MANIFEST_SHA256 = "c" * 64

IDENTITY_GATE = {
    "counterfactual_same_source_rebuild": {
        "evidence_receipt": None,
        "required": True,
        "verified": False,
    },
    "digests": dict(PACKAGER.EXPECTED_LEGACY_DESCRIPTOR_DIGESTS),
    "literal_digest_absence_verified": True,
    "stable_principal_admission_split": {
        "evidence_receipt": None,
        "required": True,
        "verified": False,
    },
    "status": PACKAGER.CONTRACT_STATUS,
}

def build_tool(role: str, path: str) -> dict[str, object]:
    identity = PACKAGER.EXPECTED_LAUNCHER_BUILD_TOOL_IDENTITIES[role]
    return {
        "schema": PACKAGER.LAUNCHER_BUILD_TOOL_SCHEMA,
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
            "environment_allowlist": list(
                PACKAGER.LAUNCHER_BUILD_ENVIRONMENT_ALLOWLIST
            ),
        },
        "complete_recursive_toolchain_closure": False,
}


TARGET_COMPILER_CLOSURE = {
    "schema": "org.trillionnium.target-compiler-effective-closure.v1",
    "target": "aarch64-linux-gnu",
    "normalized_search_arguments": [
        "--sysroot=$TARGET_SYSROOT",
        "-B$TARGET_COMPILER_BIN",
        "-B$TARGET_GCC_LIBDIR",
        "-B$TARGET_BINUTILS_DIR",
    ],
    "reported_sysroot": "$TARGET_SYSROOT",
    "components": copy.deepcopy(PACKAGER.EXPECTED_TARGET_COMPILER_COMPONENTS),
    "snapshot_tree_fully_remeasured_before_and_after_build": True,
    "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed": False,
    "complete_host_execution_runtime_closure": False,
}


COMMON_BUILD_EVIDENCE = {
    "compiler": build_tool("compiler_driver", "/fixture/aarch64-linux-gnu-gcc"),
    "elf_inspector": build_tool(
        "elf_inspector", "/fixture/aarch64-linux-gnu-readelf"
    ),
    "launcher_ab": {
        "bytes": 8192,
        "compiler_and_elf_inspector_build_time_bytes_bound": True,
        "decision": PACKAGER.COMMON_LAUNCHER_AB_DECISION,
        "deterministic_artifact_set_ab_verified": True,
        "lane": "common",
        "physical_source_bom_or_live_graph_remeasured_by_this_stage": False,
        "raw_elf_ab_receipt_id": "sha256:" + "6" * 64,
        "receipt_id": "sha256:" + "7" * 64,
        "release_status": PACKAGER.COMMON_LAUNCHER_AB_HOLD,
        "same_upstream_source_bom_receipt_claim": True,
        "schema": PACKAGER.COMMON_LAUNCHER_AB_SCHEMA,
        "sha256": "8" * 64,
        "status": PACKAGER.COMMON_LAUNCHER_AB_HOLD,
    },
    "source_bom_claim_authority": copy.deepcopy(PACKAGER.SOURCE_BOM_CLAIM_AUTHORITY),
    "upstream_source_bom_receipt_claim": {
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
        "launcher_executable_sha256": "a" * 64,
        "launcher_identity_source": "measured_after_closed_launcher_inputs",
        "stable_principal_canonical_sha256": PACKAGER.STABLE_PRINCIPAL_CANONICAL_SHA256,
        "stable_principal_contract_sha256": PACKAGER.STABLE_PRINCIPAL_CONTRACT_SHA256,
        "status": "host_measurement_only_avb_slot_admission_absent",
    },
    "toolchain_claim_authority": copy.deepcopy(PACKAGER.TOOLCHAIN_CLAIM_AUTHORITY),
    "upstream_receipt_target_compiler_closure_claim": copy.deepcopy(
        TARGET_COMPILER_CLOSURE
    ),
    "upstream_receipt_toolchain_snapshot_claim": copy.deepcopy(
        PACKAGER.EXPECTED_TOOLCHAIN_SNAPSHOT_BINDING
    ),
}


def binary(path: str, *, require_static: bool) -> dict[str, object]:
    return {
        "bytes": 64,
        "sha256": "a" * 64,
        "install": {"mode": "0755", "path": path},
        "require_static": require_static,
    }


def contract() -> dict[str, object]:
    manifest = {
        "adapter": "supervised-codex-cli",
        "adapter_version": "0.144.1",
        "agent_id": "agent-codex-direct-v1",
        "api_version": "trillionnium.agent-api.v1",
        "enabled": False,
        "health": "disabled",
        "identity_key_sha256": "a" * 64,
        "network_policy": "per_request",
        "peer_gid": 5901,
        "peer_uid": 5901,
        "selinux_domain": "u:r:trillionnium_codex_agent:s0",
    }
    return {
        "admission": {
            "decision": PACKAGER.CONTRACT_DECISION,
            "identity_independence_gate": copy.deepcopy(IDENTITY_GATE),
            "release_allowed": False,
            "status": PACKAGER.CONTRACT_STATUS,
        },
        "common_build_evidence": copy.deepcopy(COMMON_BUILD_EVIDENCE),
        "schema": "org.trillionnium.rootfs-package.contract.v9",
        "source_date_epoch": 1_785_110_400,
        "compression": {
            "algorithm": "zstd",
            "level": 19,
            "long_distance_matcher_log": 27,
            "threads": 1,
        },
        "limits": {
            "max_decompressed_tar_bytes": 1 << 30,
            "max_member_bytes": 1 << 29,
            "max_members": 4096,
            "max_path_bytes": 4096,
            "max_total_regular_bytes": 1 << 30,
        },
        "runtime": {"elf_machine": "AArch64", "max_glibc": "2.36"},
        "inputs": {
            "base_rootfs": {"bytes": 1, "sha256": "b" * 64},
            "common_artifact_set_receipt": {
                "bytes": 2797,
                "file": "common-codex-rootfs-artifact-set.v5.json",
                "schema": "org.trillionnium.common-codex-rootfs-artifact-set.v5",
                "sha256": "d" * 64,
                "status": "host_built_device_evidence_hold",
            },
            "common_launcher_ab_receipt": {
                "bytes": 8192,
                "decision": PACKAGER.COMMON_LAUNCHER_AB_DECISION,
                "file": PACKAGER.COMMON_LAUNCHER_AB_FILE,
                "schema": PACKAGER.COMMON_LAUNCHER_AB_SCHEMA,
                "sha256": "8" * 64,
                "status": PACKAGER.COMMON_LAUNCHER_AB_HOLD,
            },
            "daemon": binary("usr/bin/trillionniumd", require_static=False),
            "codex": binary(
                "usr/lib/trillionnium/agents/codex/0.144.1/"
                "aarch64-unknown-linux-musl/bin/codex",
                require_static=True,
            ),
            "system_api_tool": binary(
                "usr/local/bin/trillionnium-agent-system-api",
                require_static=False,
            ),
            "accessibility_tool": binary(
                "usr/local/bin/trillionnium-agent-accessibility",
                require_static=False,
            ),
            "system_api_replay_sync": binary(
                "usr/local/bin/trillionnium-system-api-replay-sync",
                require_static=False,
            ),
            "agent_manifest": {
                "allowed_fields": sorted(manifest),
                "bytes": 2,
                "install": {
                    "mode": "0644",
                    "path": "etc/trillionnium/agents/agent-codex-direct-v1.json",
                },
                "required_fields": manifest,
                "sha256": "c" * 64,
            },
        },
        "security": {
            "forbidden_content_markers": [],
            "forbidden_path_patterns": [],
            "legacy_absolute_symlink_migration": None,
            "legacy_duplicate_directory_migrations": [],
            "legacy_prune_members": [],
            "legacy_raw_name_prune_members": [],
            "replacement_hardlink_allowlist": [],
        },
        "tools": {"zstd": {"bytes": 1022760, "sha256": "e" * 64}},
    }


class RootfsContractV9Tests(unittest.TestCase):
    def test_v9_and_v4_receipt_id_scope_is_explicit_compact_no_lf(self) -> None:
        expected = (
            "sha256(canonical-json-utf8-sort-keys-compact-no-lf-"
            "without-receipt_id)"
        )
        self.assertEqual(PACKAGER.ROOTFS_RECEIPT_ID_SCOPE, expected)
        self.assertEqual(EROFS.ROOTFS_RECEIPT_ID_SCOPE, expected)

    def test_exact_replay_sync_closure_is_accepted(self) -> None:
        normalized = PACKAGER.validate_contract(contract())
        self.assertEqual(
            normalized["admission"]["decision"], PACKAGER.CONTRACT_DECISION
        )
        self.assertFalse(normalized["admission"]["release_allowed"])
        self.assertFalse(
            normalized["admission"]["identity_independence_gate"]
            ["counterfactual_same_source_rebuild"]["verified"]
        )
        replay = normalized["inputs"]["system_api_replay_sync"]
        self.assertEqual(
            replay["install"]["path"],
            "usr/local/bin/trillionnium-system-api-replay-sync",
        )
        self.assertFalse(replay["require_static"])
        self.assertEqual(
            normalized["inputs"]["system_api_tool"]["install"]["path"],
            "usr/local/bin/trillionnium-agent-system-api",
        )
        self.assertEqual(
            normalized["inputs"]["accessibility_tool"]["install"]["path"],
            "usr/local/bin/trillionnium-agent-accessibility",
        )
        self.assertEqual(
            normalized["common_build_evidence"][
                "upstream_receipt_toolchain_snapshot_claim"
            ],
            PACKAGER.EXPECTED_TOOLCHAIN_SNAPSHOT_BINDING,
        )
        self.assertFalse(
            normalized["common_build_evidence"][
                "upstream_receipt_target_compiler_closure_claim"
            ]
            ["complete_host_execution_runtime_closure"]
        )
        for field in ("source_bom_claim_authority", "toolchain_claim_authority"):
            self.assertEqual(
                normalized["common_build_evidence"][field]["source"],
                "content_hash_bound_common_and_self_hashed_launcher_receipt",
            )

    def test_missing_replay_sync_is_rejected(self) -> None:
        value = contract()
        value["inputs"].pop("system_api_replay_sync")
        with self.assertRaisesRegex(PACKAGER.PackagerError, "missing=.*replay_sync"):
            PACKAGER.validate_contract(value)

    def test_frozen_toolchain_snapshot_and_effective_closure_drift_is_rejected(
        self,
    ) -> None:
        cases = (
            (
                ("compiler", "sha256"),
                "a" * 64,
                "frozen Mobian snapshot leaf",
            ),
            (
                (
                    "source_bom_claim_authority",
                    "physical_source_bom_input_to_this_stage",
                ),
                True,
                "overclaims downstream authority",
            ),
            (
                (
                    "toolchain_claim_authority",
                    "physical_snapshot_remeasured_by_this_stage",
                ),
                True,
                "overclaims downstream authority",
            ),
            (
                ("upstream_receipt_toolchain_snapshot_claim", "tree_digest"),
                "a" * 64,
                "frozen Mobian snapshot",
            ),
            (
                (
                    "upstream_receipt_target_compiler_closure_claim",
                    "components",
                    "ld",
                    "sha256",
                ),
                "a" * 64,
                "components.ld differs from the frozen Mobian snapshot",
            ),
            (
                (
                    "upstream_receipt_target_compiler_closure_claim",
                    "complete_host_execution_runtime_closure",
                ),
                True,
                "posture differs",
            ),
        )
        for path, replacement, message in cases:
            with self.subTest(path=path):
                value = contract()
                target = value["common_build_evidence"]
                for field in path[:-1]:
                    target = target[field]
                target[path[-1]] = replacement
                with self.assertRaisesRegex(PACKAGER.PackagerError, message):
                    PACKAGER.validate_contract(value)

    def test_exact_zstd_tool_binding_is_required(self) -> None:
        normalized = PACKAGER.validate_contract(contract())
        self.assertEqual(
            normalized["tools"]["zstd"],
            {"bytes": 1022760, "sha256": "e" * 64},
        )

        value = contract()
        value.pop("tools")
        with self.assertRaisesRegex(PACKAGER.PackagerError, "missing=.*tools"):
            PACKAGER.validate_contract(value)

        value = contract()
        value["tools"]["zstd"].pop("bytes")
        with self.assertRaisesRegex(PACKAGER.PackagerError, "missing=.*bytes"):
            PACKAGER.validate_contract(value)

    def test_replay_sync_path_or_static_policy_drift_is_rejected(self) -> None:
        value = contract()
        value["inputs"]["system_api_replay_sync"]["install"]["path"] = (
            "usr/local/bin/unreviewed-replay-sync"
        )
        with self.assertRaisesRegex(PACKAGER.PackagerError, "reviewed Root-Linux"):
            PACKAGER.validate_contract(value)

        value = contract()
        value["inputs"]["system_api_replay_sync"]["require_static"] = True
        with self.assertRaisesRegex(PACKAGER.PackagerError, "must be false"):
            PACKAGER.validate_contract(value)

    def test_admission_manifest_requires_replay_sync_object_and_label(self) -> None:
        path = (
            REPOSITORY
            / "packaging/root-linux/rootfs-codex-erofs-admission.v4.json"
        )
        manifest = EROFS.validate_codex_admission_manifest(
            path, hashlib.sha256(path.read_bytes()).hexdigest()
        )
        self.assertEqual(
            manifest["layout"]["system_api_replay_sync_path"],
            "usr/local/bin/trillionnium-system-api-replay-sync",
        )
        self.assertIn(
            "usr/local/bin/trillionnium-system-api-replay-sync",
            {
                item.get("path")
                for item in manifest["selinux"]["critical_labels"]
                if isinstance(item, dict)
            },
        )
        self.assertEqual(
            manifest["layout"]["android_effect_tool_paths"],
            [
                "usr/local/bin/trillionnium-agent-accessibility",
                "usr/local/bin/trillionnium-agent-system-api",
            ],
        )
        self.assertEqual(
            manifest["archive_contract"]["contract_schema"],
            "org.trillionnium.rootfs-package.contract.v9",
        )
        self.assertEqual(
            manifest["archive_contract"]["decision"],
            EROFS.CODEX_PACKAGE_DECISION,
        )
        self.assertFalse(manifest["archive_contract"]["release_allowed"])
        self.assertEqual(
            manifest["archive_contract"]["required_identity_independence_gate"],
            IDENTITY_GATE,
        )

    def test_erofs_preflight_receipt_preserves_upstream_identity_hold(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rootfs = root / "rootfs.tar.zst"
            rootfs.write_bytes(b"rootfs")
            tar_path = root / "rootfs.tar"
            tar_path.write_bytes(b"tar")
            admission_path = root / "admission.json"
            admission_path.write_bytes(b"{}\n")
            contexts = root / "file_contexts.bin"
            contexts.write_bytes(b"contexts")
            package_facts = {
                "admission": {
                    "decision": EROFS.CODEX_PACKAGE_DECISION,
                    "identity_independence_gate": copy.deepcopy(IDENTITY_GATE),
                    "release_allowed": False,
                    "status": EROFS.CODEX_PACKAGE_STATUS,
                },
                "common_build_evidence": copy.deepcopy(COMMON_BUILD_EVIDENCE),
                "critical_selinux_objects": [],
            }
            receipt = EROFS.codex_preflight_receipt(
                args=argparse.Namespace(
                    admission_manifest=admission_path,
                    admission_manifest_sha256="1" * 64,
                    compiled_file_contexts=contexts,
                    compiled_file_contexts_sha256="2" * 64,
                    mount_point=EROFS.FINAL_MOUNT_POINT,
                    rootfs=rootfs,
                    source_date_epoch=1_785_110_400,
                ),
                rootfs_info=rootfs.stat(),
                rootfs_sha256=hashlib.sha256(rootfs.read_bytes()).hexdigest(),
                tar_path=tar_path,
                archive={"member_count": 1, "regular_bytes": 3},
                admission_manifest={
                    "schema": EROFS.CODEX_ADMISSION_MANIFEST_SCHEMA,
                    "admission": {"missing_gates": ["identity proof"]},
                },
                admission_manifest_info=admission_path.stat(),
                compiled_contexts_info=contexts.stat(),
                compiled_contexts_header={"magic": 0xF97CFF8A, "version": 5},
                package_facts=package_facts,
            )
            self.assertTrue(receipt["decision"].startswith("HOLD_"))
            self.assertNotIn("PASS", receipt["decision"])
            self.assertFalse(receipt["release_allowed"])
            self.assertEqual(
                receipt["receipt_id_scope"], EROFS.ROOTFS_RECEIPT_ID_SCOPE
            )
            unsigned = dict(receipt)
            receipt_id = unsigned.pop("receipt_id")
            self.assertEqual(
                receipt_id,
                "sha256:"
                + hashlib.sha256(EROFS.canonical_json_bytes(unsigned)).hexdigest(),
            )
            self.assertEqual(receipt["upstream_admission"], package_facts["admission"])
            self.assertEqual(receipt["limitations"], EROFS.PREFLIGHT_LIMITATIONS)
            self.assertFalse(
                receipt["upstream_admission"]["identity_independence_gate"]
                ["counterfactual_same_source_rebuild"]["verified"]
            )

    def test_effect_tool_or_common_receipt_contract_drift_is_rejected(self) -> None:
        value = contract()
        value["inputs"]["system_api_tool"]["install"]["path"] = (
            "usr/local/bin/unreviewed-system-api"
        )
        with self.assertRaisesRegex(PACKAGER.PackagerError, "install.path drifted"):
            PACKAGER.validate_contract(value)

        value = contract()
        value["inputs"]["common_artifact_set_receipt"]["status"] = "unreviewed"
        with self.assertRaisesRegex(
            PACKAGER.PackagerError, "receipt identity drifted"
        ):
            PACKAGER.validate_contract(value)

    def test_admission_manifest_replay_sync_path_drift_is_rejected(self) -> None:
        source = (
            REPOSITORY
            / "packaging/root-linux/rootfs-codex-erofs-admission.v4.json"
        )
        value = copy.deepcopy(json.loads(source.read_text(encoding="utf-8")))
        value["layout"]["system_api_replay_sync_path"] = (
            "usr/local/bin/unreviewed-replay-sync"
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "admission.json"
            path.write_text(
                json.dumps(value, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(EROFS.ImageError, "runtime layout drifted"):
                EROFS.validate_codex_admission_manifest(
                    path, hashlib.sha256(path.read_bytes()).hexdigest()
                )

    def test_admission_manifest_cannot_claim_identity_gate_verified(self) -> None:
        source = (
            REPOSITORY
            / "packaging/root-linux/rootfs-codex-erofs-admission.v4.json"
        )
        value = copy.deepcopy(json.loads(source.read_text(encoding="utf-8")))
        value["archive_contract"]["required_identity_independence_gate"][
            "counterfactual_same_source_rebuild"
        ]["verified"] = True
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "admission.json"
            path.write_text(
                json.dumps(value, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(EROFS.ImageError, "must remain unverified HOLD"):
                EROFS.validate_codex_admission_manifest(
                    path, hashlib.sha256(path.read_bytes()).hexdigest()
                )


if __name__ == "__main__":
    unittest.main()
