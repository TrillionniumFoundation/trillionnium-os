#!/usr/bin/env python3
"""Build the measured common-product Codex launcher and its input receipt.

This is the common-product counterpart to the P01 pre-daemon builder. It reuses
the same bounded/no-follow I/O and deterministic static-C compilation
primitives, closes over the two inert common direct-tool ABI stubs, and records
the exact daemon and replay-sync inputs consumed by the later rootfs packager.
It does not mutate Android sources, package a rootfs, sign anything, or claim
device evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile


# This script imports the shared P0.1 launcher primitives at module load time.
# Disable bytecode before that import so even metadata-only entry points such
# as ``--help`` cannot add an ignored ``tools/__pycache__`` entry and invalidate
# a just-frozen source BOM.
sys.dont_write_bytecode = True


TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import build_p01_userdebug_agent_launchers as primitives  # noqa: E402


FROZEN_CODEX_RUNTIME_SHA256 = primitives.FROZEN_CODEX_RUNTIME_SHA256
FROZEN_SYSTEM_API_SHA256 = (
    "3802e114fe6f479052015dddb0ee7e02a2c70f51dea847a98e60aaddfc1f0e1a"
)
FROZEN_ACCESSIBILITY_SHA256 = (
    "f79515414740b0d6c4a46f44c5b9dca0173db01cfef2dc4d9cb582ca05755064"
)
FROZEN_REPLAY_SYNC_SHA256 = (
    "6d25eedb5264be27da78f12393b0e1747706347aa11e3673cb881836e4d47268"
)
FROZEN_DAEMON_SHA256 = (
    "f3345817137c227926c943d0248e05cf97379014c857a78c2e9c23d46b1ff341"
)
LEGACY_DESCRIPTOR_CONTRACT = (
    primitives.REPOSITORY
    / "crates/trillionnium-os-types/contracts/agent-descriptor-registry-v1.json"
)
STABLE_PRINCIPAL_CONTRACT = (
    primitives.REPOSITORY
    / "crates/trillionnium-os-types/contracts/agent-principal-registry-v2.json"
)
REGISTRY_TOP_LEVEL_FIELDS = {
    "contract_schema",
    "registry_schema",
    "descriptor_schema",
    "endpoints",
    "descriptors",
}
REGISTRY_DESCRIPTOR_FIELDS = {
    "symbol",
    "provider_id",
    "agent_id",
    "identity_key_sha256",
    "replay_namespace",
    "uid",
    "gid",
    "agent_selinux_domain",
    "runtime_adapter",
}
STABLE_REGISTRY_TOP_LEVEL_FIELDS = {
    "contract_schema",
    "registry_schema",
    "principal_schema",
    "materialization_status",
    "same_crate_counterfactual_build_required",
    "endpoints",
    "principals",
}
STABLE_PRINCIPAL_FIELDS = {
    "symbol",
    "provider_id",
    "agent_id",
    "replay_namespace",
    "uid",
    "gid",
    "agent_selinux_domain",
    "runtime_adapter",
}
EXPECTED_REGISTRY_SCHEMAS = {
    "contract_schema": "org.trillionnium.agent-descriptor-registry.contract.v1",
    "registry_schema": "org.trillionnium.agent-descriptor-registry.v1",
    "descriptor_schema": "org.trillionnium.agent-descriptor.v1",
}
EXPECTED_REGISTRY_ENDPOINTS = [
    {
        "symbol": "SYSTEM_API",
        "tool_selinux_domain": "u:r:trillionnium_agent_system_api_tool:s0",
        "operation_replay_sync_selinux_domain": "u:r:trillionnium_agent_system_api_operation_replay_sync:s0",
    },
    {
        "symbol": "ACCESSIBILITY",
        "tool_selinux_domain": "u:r:trillionnium_agent_accessibility_tool:s0",
        "operation_replay_sync_selinux_domain": "u:r:trillionnium_agent_accessibility_operation_replay_sync:s0",
    },
]
EXPECTED_CODEX_STABLE_PRINCIPAL = {
    "symbol": "CODEX",
    "provider_id": "openai-codex",
    "agent_id": "agent-codex-direct-v1",
    "replay_namespace": "agent-codex-v1",
    "uid": 5901,
    "gid": 5901,
    "agent_selinux_domain": "u:r:trillionnium_codex_agent:s0",
    "runtime_adapter": "supervised-codex-cli",
}
EXPECTED_STABLE_REGISTRY_SCHEMAS = {
    "contract_schema": "org.trillionnium.agent-principal-registry.contract.v2",
    "registry_schema": "org.trillionnium.agent-principal-registry.v2",
    "principal_schema": "org.trillionnium.agent-stable-principal.v1",
}
OUTPUT_NAMES = {
    "system_api_tool": "trillionnium-agent-system-api",
    "accessibility_tool": "trillionnium-agent-accessibility",
    "replay_sync_helper": "trillionnium-system-api-replay-sync",
    "daemon": "trillionniumd",
    "codex_launcher": "trillionnium-codex-agent-0.144.1",
    "receipt": "common-codex-rootfs-artifact-set.v5.json",
}
DEPENDENCY_GRAPH = {
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
    "acyclic": True,
}


def reject_duplicate_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate registry field: {key}")
        value[key] = item
    return value


def reject_nonstandard_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def load_legacy_descriptor_registry_digests() -> tuple[str, str, str]:
    raw = primitives.read_bounded_regular(
        LEGACY_DESCRIPTOR_CONTRACT, "legacy AgentDescriptor registry contract", 128 * 1024
    )
    try:
        contract = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_object,
            parse_constant=reject_nonstandard_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeError("AgentDescriptor registry contract is invalid") from error
    if not isinstance(contract, dict) or set(contract) != REGISTRY_TOP_LEVEL_FIELDS:
        raise RuntimeError("AgentDescriptor registry contract schema is not closed")
    if any(contract.get(key) != value for key, value in EXPECTED_REGISTRY_SCHEMAS.items()):
        raise RuntimeError("AgentDescriptor registry schema values drifted")
    if contract.get("endpoints") != EXPECTED_REGISTRY_ENDPOINTS:
        raise RuntimeError("AgentDescriptor registry endpoint set drifted")
    descriptors = contract.get("descriptors")
    if not isinstance(descriptors, list) or len(descriptors) != 1:
        raise RuntimeError("AgentDescriptor registry is not the Codex-only set")
    descriptor = descriptors[0]
    if (
        not isinstance(descriptor, dict)
        or set(descriptor) != REGISTRY_DESCRIPTOR_FIELDS
        or any(
            descriptor.get(key) != value
            for key, value in EXPECTED_CODEX_STABLE_PRINCIPAL.items()
        )
    ):
        raise RuntimeError("AgentDescriptor registry Codex principal drifted")
    identity = descriptor.get("identity_key_sha256")
    if not isinstance(identity, str):
        raise RuntimeError("AgentDescriptor registry identity is missing")
    primitives.require_digest(identity, "AgentDescriptor registry identity")
    canonical_descriptor = {
        "schema": contract["descriptor_schema"],
        "provider_id": descriptor["provider_id"],
        "agent_id": descriptor["agent_id"],
        "identity_key_sha256": identity,
        "replay_namespace": descriptor["replay_namespace"],
        "uid": descriptor["uid"],
        "gid": descriptor["gid"],
        "agent_selinux_domain": descriptor["agent_selinux_domain"],
        "runtime_adapter": descriptor["runtime_adapter"],
    }
    canonical_registry = json.dumps(
        {
            "schema": contract["registry_schema"],
            "descriptors": [canonical_descriptor],
        },
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return (
        identity,
        hashlib.sha256(raw).hexdigest(),
        hashlib.sha256(canonical_registry).hexdigest(),
    )


def load_stable_principal_registry_digests() -> tuple[str, str]:
    raw = primitives.read_bounded_regular(
        STABLE_PRINCIPAL_CONTRACT, "stable Agent principal registry contract", 128 * 1024
    )
    try:
        contract = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_object,
            parse_constant=reject_nonstandard_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeError("stable Agent principal registry contract is invalid") from error
    if not isinstance(contract, dict) or set(contract) != STABLE_REGISTRY_TOP_LEVEL_FIELDS:
        raise RuntimeError("stable Agent principal registry contract schema is not closed")
    if any(
        contract.get(key) != value
        for key, value in EXPECTED_STABLE_REGISTRY_SCHEMAS.items()
    ):
        raise RuntimeError("stable Agent principal registry schema values drifted")
    if (
        contract.get("materialization_status")
        != "hold_same_crate_counterfactual_build_required"
        or contract.get("same_crate_counterfactual_build_required") is not True
    ):
        raise RuntimeError("stable Agent principal registry overclaims materialization")
    if contract.get("endpoints") != EXPECTED_REGISTRY_ENDPOINTS:
        raise RuntimeError("stable Agent principal endpoint set drifted")
    principals = contract.get("principals")
    if not isinstance(principals, list) or len(principals) != 1:
        raise RuntimeError("stable Agent principal registry is not the Codex-only set")
    principal = principals[0]
    if (
        not isinstance(principal, dict)
        or set(principal) != STABLE_PRINCIPAL_FIELDS
        or any(
            principal.get(key) != value
            for key, value in EXPECTED_CODEX_STABLE_PRINCIPAL.items()
        )
    ):
        raise RuntimeError("stable Codex principal drifted")
    canonical_registry = json.dumps(
        {
            "schema": contract["registry_schema"],
            "endpoints": [
                {
                    "symbol": endpoint["symbol"],
                    "tool_selinux_domain": endpoint["tool_selinux_domain"],
                    "operation_replay_sync_selinux_domain": endpoint[
                        "operation_replay_sync_selinux_domain"
                    ],
                }
                for endpoint in contract["endpoints"]
            ],
            "principals": [
                {
                    "schema": contract["principal_schema"],
                    "provider_id": principal["provider_id"],
                    "agent_id": principal["agent_id"],
                    "replay_namespace": principal["replay_namespace"],
                    "uid": principal["uid"],
                    "gid": principal["gid"],
                    "agent_selinux_domain": principal["agent_selinux_domain"],
                    "runtime_adapter": principal["runtime_adapter"],
                }
            ],
        },
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest(), hashlib.sha256(canonical_registry).hexdigest()


def validate_prelauncher_legacy_registry_digest_absence(
    artifacts: dict[str, bytes], registry_digests: dict[str, str]
) -> None:
    """Reject obvious v1-registry digest contamination in launcher inputs.

    This is deliberately a HOLD gate, not structural independence proof.  A
    release claim additionally requires a stable-principal/admission split and
    counterfactual rebuilds from the same source revision.
    """
    for role, value in artifacts.items():
        for label, digest in registry_digests.items():
            primitives.require_digest(digest, f"AgentDescriptor registry {label}")
            if digest.encode("ascii") in value:
                raise RuntimeError(
                    f"common launcher input {role} embeds the legacy registry {label}"
                )


def measure_launcher_identity(launcher: bytes) -> str:
    actual = primitives.sha256_bytes(launcher)
    return primitives.require_digest(actual, "measured common Codex launcher identity")


def validate_codex_only_elf(value: bytes, expected: str, label: str) -> None:
    primitives.require_aarch64_elf(value, label)
    primitives.require_frozen_digest(value, expected, label)
    primitives.validate_no_retired_identity(value, label)


def validate_inert_tool(
    value: bytes, expected: str, label: str, required_markers: tuple[bytes, ...]
) -> None:
    validate_codex_only_elf(value, expected, label)
    for forbidden in (
        b"current-invocation.json",
        b"/var/lib/trillionnium/agent-tools/inbox",
        b"trusted adapter inbox is corrupt:",
    ):
        if forbidden in value:
            raise RuntimeError(f"{label} retains the retired fixed-inbox lane")
    for required in required_markers:
        if required not in value:
            raise RuntimeError(f"{label} omits its held fail-closed ABI marker")


def build(args: argparse.Namespace) -> dict[str, object]:
    output = args.output_dir
    output_custody = primitives.open_empty_output_dir(output)
    try:
        return build_into(args, output, output_custody)
    finally:
        output_custody.close()


def build_into(
    args: argparse.Namespace,
    output: Path,
    output_custody: primitives.OutputDirectoryCustody,
) -> dict[str, object]:
    source_bom_binding = primitives.remeasure_live_source_bom_binding(
        args.source_bom,
        args.android_root,
        args.artifact_root,
        args.resolved_manifest,
    )
    toolchain_snapshot, toolchain_manifest_before = (
        primitives.verify_toolchain_snapshot_binding(args.toolchain_manifest)
    )
    manifest_path = primitives.absolute_without_symlink_resolution(
        args.toolchain_manifest
    )
    lane_root = manifest_path.parent
    expected_layout = {
        "target_sysroot": lane_root / "toolchain/sysroot",
        "target_compiler": (
            lane_root / "toolchain/sysroot/usr/bin/aarch64-linux-gnu-gcc-12"
        ),
        "target_readelf": (
            lane_root / "toolchain/sysroot/usr/bin/aarch64-linux-gnu-readelf"
        ),
        "target_compiler_bin": lane_root / "toolchain/sysroot/usr/bin",
        "target_gcc_libdir": (
            lane_root
            / "toolchain/sysroot/usr/lib/gcc-cross/aarch64-linux-gnu/12"
        ),
        "target_binutils_dir": (
            lane_root / "toolchain/sysroot/usr/aarch64-linux-gnu/bin"
        ),
        "target_host_runtime_libdir": (
            lane_root / "toolchain/sysroot/usr/lib/x86_64-linux-gnu"
        ),
    }
    supplied_layout = {
        "target_sysroot": primitives.absolute_without_symlink_resolution(
            args.target_sysroot
        ),
        "target_compiler": primitives.absolute_without_symlink_resolution(args.cc),
        "target_readelf": primitives.absolute_without_symlink_resolution(args.readelf),
        "target_compiler_bin": primitives.absolute_without_symlink_resolution(
            args.target_compiler_bin
        ),
        "target_gcc_libdir": primitives.absolute_without_symlink_resolution(
            args.target_gcc_libdir
        ),
        "target_binutils_dir": primitives.absolute_without_symlink_resolution(
            args.target_binutils_dir
        ),
        "target_host_runtime_libdir": primitives.absolute_without_symlink_resolution(
            args.target_host_runtime_libdir
        ),
    }
    if supplied_layout != expected_layout:
        raise RuntimeError(
            "common target compiler/sysroot layout differs from the bound lane snapshot"
        )
    target_link_arguments = [
        f"--sysroot={supplied_layout['target_sysroot']}",
        f"-B{supplied_layout['target_compiler_bin']}",
        f"-B{supplied_layout['target_gcc_libdir']}",
        f"-B{supplied_layout['target_binutils_dir']}",
    ]
    codex_runtime = primitives.absolute_without_symlink_resolution(args.codex_runtime)
    system_api_path = primitives.absolute_without_symlink_resolution(args.system_api_tool)
    accessibility_path = primitives.absolute_without_symlink_resolution(
        args.accessibility_tool
    )
    replay_sync_path = primitives.absolute_without_symlink_resolution(
        args.replay_sync_helper
    )
    daemon_path = primitives.absolute_without_symlink_resolution(args.daemon)
    system_api = primitives.read_bounded_regular(
        system_api_path, "common System API", 64 * 1024 * 1024
    )
    accessibility = primitives.read_bounded_regular(
        accessibility_path, "common Accessibility", 64 * 1024 * 1024
    )
    replay_sync = primitives.read_bounded_regular(
        replay_sync_path, "common replay-sync", 64 * 1024 * 1024
    )
    daemon = primitives.read_bounded_regular(
        daemon_path, "common daemon", 64 * 1024 * 1024
    )
    (
        legacy_registry_identity,
        legacy_registry_contract_sha256,
        legacy_canonical_registry_sha256,
    ) = load_legacy_descriptor_registry_digests()
    stable_contract_sha256, stable_canonical_sha256 = (
        load_stable_principal_registry_digests()
    )
    validate_inert_tool(
        system_api,
        FROZEN_SYSTEM_API_SHA256,
        "common System API",
        (b"System API effect lane is not compiled",),
    )
    validate_inert_tool(
        accessibility,
        FROZEN_ACCESSIBILITY_SHA256,
        "common Accessibility",
        (
            b"Accessibility effect lane is not compiled",
            b"org.trillionnium.agent-accessibility.v2",
            b"snapshot_mode",
        ),
    )
    validate_codex_only_elf(
        replay_sync, FROZEN_REPLAY_SYNC_SHA256, "common replay-sync"
    )
    validate_codex_only_elf(daemon, FROZEN_DAEMON_SHA256, "common daemon")
    for required in (
        b"agent-codex-direct-v1",
        b"TRILLIONNIUM_AGENTD_CAPABILITY_HARDENING_V1_ACTIVE",
    ):
        if required not in daemon:
            raise RuntimeError("common daemon omits a required Codex/capability marker")

    runtime = primitives.read_bounded_regular(
        codex_runtime, "Codex runtime", 512 * 1024 * 1024
    )
    runtime_sha256 = primitives.sha256_bytes(runtime)
    runtime_bytes = len(runtime)
    if runtime_sha256 != FROZEN_CODEX_RUNTIME_SHA256:
        raise RuntimeError("Codex runtime digest differs from the frozen product runtime")
    source_bytes = primitives.read_bounded_regular(
        primitives.CODEX_SOURCE, "Codex launcher source", 1024 * 1024
    )
    legacy_registry_digests = {
        "launcher identity": legacy_registry_identity,
        "contract digest": legacy_registry_contract_sha256,
        "canonical digest": legacy_canonical_registry_sha256,
    }
    validate_prelauncher_legacy_registry_digest_absence(
        {
            "codex_runtime": runtime,
            "system_api_tool": system_api,
            "accessibility_tool": accessibility,
            "replay_sync_helper": replay_sync,
            "daemon": daemon,
            "launcher_source": source_bytes,
        },
        legacy_registry_digests,
    )
    compiler = primitives.open_launcher_build_tool(args.cc, "compiler_driver")
    try:
        inspector = primitives.open_launcher_build_tool(args.readelf, "elf_inspector")
        try:
            with tempfile.TemporaryDirectory(
                prefix=".common-codex-launcher.", dir=output.parent
            ) as temporary:
                build_root = Path(temporary)
                environment = primitives.launcher_build_environment(
                    compiler,
                    inspector,
                    build_root,
                    supplied_layout["target_host_runtime_libdir"],
                )
                compiler_identity = primitives.launcher_build_tool_identity(
                    compiler,
                    environment=environment,
                    build_root=build_root,
                    require_target=True,
                )
                inspector_identity = primitives.launcher_build_tool_identity(
                    inspector,
                    environment=environment,
                    build_root=build_root,
                    require_target=False,
                )
                target_compiler_closure = primitives.validate_target_compiler_closure(
                    compiler,
                    environment=environment,
                    build_root=build_root,
                    target_sysroot=supplied_layout["target_sysroot"],
                    target_link_arguments=target_link_arguments,
                )
                source = build_root / "codex-integrity-launcher.c"
                primitives.write_exclusive(source, source_bytes, 0o444)
                launcher = primitives.reproducible_launcher(
                    compiler,
                    inspector,
                    source,
                    [
                        f'-DTRILLIONNIUM_CODEX_RUNTIME_SHA256="{runtime_sha256}"',
                        f'-DTRILLIONNIUM_SYSTEM_API_TOOL_SHA256="{FROZEN_SYSTEM_API_SHA256}"',
                        f'-DTRILLIONNIUM_ACCESSIBILITY_TOOL_SHA256="{FROZEN_ACCESSIBILITY_SHA256}"',
                        "-DTRILLIONNIUM_CODEX_REQUIRE_ACCESSIBILITY_TOOL=1",
                    ],
                    build_root,
                    environment,
                    target_link_arguments,
                )
                primitives.revalidate_launcher_build_tool(compiler)
                primitives.revalidate_launcher_build_tool(inspector)
        finally:
            inspector.close()
    finally:
        compiler.close()

    launcher_sha256 = measure_launcher_identity(launcher)
    for expected in (
        runtime_sha256,
        FROZEN_SYSTEM_API_SHA256,
        FROZEN_ACCESSIBILITY_SHA256,
    ):
        if expected.encode("ascii") not in launcher:
            raise RuntimeError("common Codex launcher omits a measured input pin")
    primitives.validate_no_retired_identity(launcher, "common Codex launcher")

    artifacts = {
        "system_api_tool": system_api,
        "accessibility_tool": accessibility,
        "replay_sync_helper": replay_sync,
        "daemon": daemon,
        "codex_launcher": launcher,
    }
    publication_contract: dict[str, tuple[bytes, int]] = {}
    for role, value in artifacts.items():
        primitives.write_exclusive_at(
            output_custody, OUTPUT_NAMES[role], value, 0o555
        )
        publication_contract[OUTPUT_NAMES[role]] = (value, 0o555)

    # The shared BOM gate remeasures tracked, untracked, and ignored state.
    # Re-run it after compilation so a same-HEAD worktree mutation cannot be
    # hidden behind the initial provenance check.
    if (
        primitives.remeasure_live_source_bom_binding(
            args.source_bom,
            args.android_root,
            args.artifact_root,
            args.resolved_manifest,
        )
        != source_bom_binding
    ):
        raise RuntimeError("source BOM binding changed during common launcher build")
    toolchain_snapshot_after, toolchain_manifest_after = (
        primitives.verify_toolchain_snapshot_binding(args.toolchain_manifest)
    )
    if (
        toolchain_snapshot_after != toolchain_snapshot
        or toolchain_manifest_after != toolchain_manifest_before
    ):
        raise RuntimeError("Mobian toolchain manifest changed during common launcher build")
    receipt: dict[str, object] = {
        "schema": "org.trillionnium.common-codex-rootfs-artifact-set.v5",
        "receipt_role": "common_rootfs_complete_measured_build_input",
        "status": "host_built_device_evidence_hold",
        "product_variant": "common",
        "common_direct_tool_posture": "inert_no_default_features_fail_closed",
        "stable_principal_launcher_measurement": {
            "status": "host_measurement_only_avb_slot_admission_absent",
            "stable_principal_contract_sha256": stable_contract_sha256,
            "stable_principal_canonical_sha256": stable_canonical_sha256,
            "launcher_executable_sha256": launcher_sha256,
            "launcher_identity_source": "measured_after_closed_launcher_inputs",
            "executable_identity_is_stable_registry_input": False,
        },
        "legacy_descriptor_contamination_hold_gate": {
            "status": "hold_identity_independence_evidence_unverified",
            "literal_digest_absence_verified": True,
            "digests": legacy_registry_digests,
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
        },
        "accessibility_available": False,
        "dependency_graph": DEPENDENCY_GRAPH,
        "source_bom": source_bom_binding,
        "compiler": compiler_identity,
        "elf_inspector": inspector_identity,
        "toolchain_snapshot": toolchain_snapshot,
        "target_compiler_closure": target_compiler_closure,
        "inputs": {
            "codex_runtime_sha256": runtime_sha256,
            "codex_runtime_bytes": runtime_bytes,
            "codex_launcher_source_sha256": hashlib.sha256(source_bytes).hexdigest(),
            "system_api_tool_input_sha256": FROZEN_SYSTEM_API_SHA256,
            "accessibility_tool_input_sha256": FROZEN_ACCESSIBILITY_SHA256,
            "replay_sync_helper_input_sha256": FROZEN_REPLAY_SYNC_SHA256,
            "daemon_input_sha256": FROZEN_DAEMON_SHA256,
        },
        "artifacts": {
            role: {
                "file": OUTPUT_NAMES[role],
                "sha256": primitives.sha256_bytes(value),
                "bytes": len(value),
            }
            for role, value in artifacts.items()
        },
        "rootfs_build_required": True,
        "device_execution_verified": False,
        "release_allowed": False,
    }
    receipt_bytes = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    primitives.write_exclusive_at(
        output_custody, OUTPUT_NAMES["receipt"], receipt_bytes, 0o444
    )
    publication_contract[OUTPUT_NAMES["receipt"]] = (receipt_bytes, 0o444)
    primitives.finalize_output_publication(
        output_custody, publication_contract
    )
    receipt["receipt_sha256"] = primitives.sha256_bytes(receipt_bytes)
    receipt["codex_launcher_sha256"] = launcher_sha256
    return receipt


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--source-bom", type=Path, required=True)
    parser.add_argument("--android-root", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--resolved-manifest", type=Path, required=True)
    parser.add_argument("--codex-runtime", type=Path, required=True)
    parser.add_argument("--system-api-tool", type=Path, required=True)
    parser.add_argument("--accessibility-tool", type=Path, required=True)
    parser.add_argument("--replay-sync-helper", type=Path, required=True)
    parser.add_argument("--daemon", type=Path, required=True)
    parser.add_argument("--cc", type=Path, required=True)
    parser.add_argument("--readelf", type=Path, required=True)
    parser.add_argument("--toolchain-manifest", type=Path, required=True)
    parser.add_argument("--target-sysroot", type=Path, required=True)
    parser.add_argument("--target-compiler-bin", type=Path, required=True)
    parser.add_argument("--target-gcc-libdir", type=Path, required=True)
    parser.add_argument("--target-binutils-dir", type=Path, required=True)
    parser.add_argument("--target-host-runtime-libdir", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    print(json.dumps(build(parse_args()), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
