#!/usr/bin/env python3
"""Build the deterministic P0 userdebug Codex measured launcher.

The dependency direction is deliberately one way:

    selected System API + Codex runtime -> Codex launcher -> daemon

This tool measures the actual frozen System API, replay-sync, and high-water
artifacts, copies that pre-daemon set beside the launchers, and emits the one
receipt consumed by the final daemon build.  It does not build the daemon,
mutate Android sources, sign artifacts, or claim device readiness. Production
launchers and the production descriptor registry are never inputs that this
command rewrites.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


sys.dont_write_bytecode = True
TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import mobian_toolchain_snapshot as toolchain_snapshot_verifier  # noqa: E402


REPOSITORY = Path(__file__).resolve().parents[1]
GIT = Path("/usr/bin/git")
CODEX_SOURCE = (
    REPOSITORY
    / "packaging/codex-android/launcher/codex-integrity-launcher.c"
)
SOURCE_SET_CONTRACT = REPOSITORY / "tools/p0-cross-repo-source-set.v2.json"
FROZEN_CODEX_RUNTIME_SHA256 = (
    "124867cc1c0b13f56539880f19d8c7b59f96e25fd47d068df91ea27c99d1ce78"
)
FROZEN_SYSTEM_API_SHA256 = (
    "5d5b92f9f190c40a3d84c82212fb1c81ef9bf3228ea7eb4ca42949af0b48cf55"
)
FROZEN_REPLAY_SYNC_HELPER_SHA256 = (
    "49e899b166472e3a663528c3a70f0db21644e5848a162aaab2f68ab1aa6dd927"
)
FROZEN_HIGH_WATER_AUTHORITY_SHA256 = (
    "e2339d5bd99747148f13b313d422450b9e20b6f4ade786cda829af6b883a4b5b"
)
STABLE_PRINCIPAL_CONTRACT = (
    REPOSITORY
    / "crates/trillionnium-os-types/contracts/agent-principal-registry-v2.json"
)
LEGACY_DESCRIPTOR_CONTRACT = (
    REPOSITORY
    / "crates/trillionnium-os-types/contracts/agent-descriptor-registry-v1.json"
)
FROZEN_STABLE_PRINCIPAL_CONTRACT_SHA256 = (
    "3e9bfcb04e48062c20bd7407635c1a27086a0de8c2fa5ca73963c946b984095b"
)
FROZEN_STABLE_PRINCIPAL_CANONICAL_SHA256 = (
    "a9c224116123deb49908beda3ab047fc98d6917cfeb62d60364033858cc57153"
)
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
P01_PRE_DAEMON_RECEIPT_SCHEMA = (
    "org.trillionnium.p01-userdebug-pre-daemon-artifact-set.v8"
)
P01_PRE_DAEMON_RECEIPT_FILE = (
    "p01-userdebug-pre-daemon-artifact-set.v8.json"
)
DAEMON_BUILD_BINDING_SCHEMA = (
    "org.trillionnium.p01-userdebug-daemon-build-binding.v2"
)
DAEMON_BUILD_BINDING_SHA256_SCOPE = (
    "sha256(canonical-json-utf8-sort-keys-indent-2-lf-of-daemon_build_binding)"
)
TOOLCHAIN_MANIFEST_SCHEMA = (
    "org.trillionnium.packaging.mobian-toolchain-snapshot-manifest.v1"
)
TOOLCHAIN_SNAPSHOT_BINDING_SCHEMA = (
    "org.trillionnium.packaging.mobian-toolchain-snapshot-binding.v1"
)
FROZEN_TOOLCHAIN_MANIFEST_SHA256 = (
    "735fab7c0ded3d37e53ac8295c32e7a3a1547ba54e603e74f25e83de2f8c541f"
)
FROZEN_TOOLCHAIN_TREE_DIGEST = (
    "6335b8cb911852156b10eec32ba08d9730b51a8ca0b0b04abfefa0b6ef7a4367"
)
FROZEN_TOOLCHAIN_MANIFEST_ID = (
    "d3ef19017ab4499243936ff65db4d2b50fce1536a9127f2d7ea3e7468784ebb4"
)
FROZEN_TOOLCHAIN_ENTRY_COUNT = 33_930
FROZEN_TOOLCHAIN_REGULAR_BYTES = 1_952_702_440
DAEMON_TARGET_PROFILE = {
    "rust_target_triple": "aarch64-unknown-linux-gnu",
    "architecture": "aarch64",
    "operating_system": "linux",
    "libc_family": "glibc",
    "dynamic_interpreter": "/lib/ld-linux-aarch64.so.1",
    "maximum_glibc": "GLIBC_2.36",
    "runtime_base_contract": "debian-bookworm-arm64",
}
DAEMON_CARGO_PROFILE = {
    "name": "release",
    "opt_level": "3",
    "debug": 0,
    "debug_assertions": False,
    "incremental": False,
    "strip": "symbols",
}
DAEMON_BUILD_POLICY = {
    "cargo_incremental": "0",
    "normalized_rustflags": [
        "-C",
        "debuginfo=0",
        "-C",
        "strip=symbols",
        "-C",
        "codegen-units=1",
        "-C",
        "relocation-model=pic",
        "-C",
        "linker=$RETAINED_LINKER",
        "-C",
        "link-arg=--sysroot=$TARGET_SYSROOT",
        "-C",
        "link-arg=-B$TARGET_COMPILER_BIN",
        "-C",
        "link-arg=-B$TARGET_GCC_LIBDIR",
        "-C",
        "link-arg=-B$TARGET_BINUTILS_DIR",
        "-C",
        "link-arg=-pie",
        "-C",
        "link-arg=-Wl,--as-needed,-z,relro,-z,now,-z,noexecstack,--build-id=sha1",
        "--remap-path-prefix",
        "$ABSOLUTE_SOURCE=/usr/src/trillionnium-os",
        "--remap-path-prefix",
        "$ABSOLUTE_SOURCE=/usr/src/trillionnium-target",
        "--remap-path-prefix",
        "$ABSOLUTE_SOURCE=/usr/src/trillionnium-cargo-home",
        "--remap-path-prefix",
        "$ABSOLUTE_SOURCE=/usr/src/trillionnium-rust-toolchain",
        "--remap-path-prefix",
        "$ABSOLUTE_SOURCE=/usr/src/trillionnium-android",
        "--remap-path-prefix",
        "$ABSOLUTE_SOURCE=/usr/src/trillionnium-empty-artifacts",
        "--remap-path-prefix",
        "$ABSOLUTE_SOURCE=/usr/src/trillionnium-manifest-parent",
        "--remap-path-prefix",
        "$ABSOLUTE_SOURCE=/usr/src/trillionnium-raw-elf-output",
    ],
    "normalized_native_environment": {
        "CC_aarch64_unknown_linux_gnu": "$RETAINED_TARGET_COMPILER",
        "AR_aarch64_unknown_linux_gnu": "$RETAINED_TARGET_ARCHIVER",
        "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER": "$RETAINED_TARGET_COMPILER",
        "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_AR": "$RETAINED_TARGET_ARCHIVER",
        "CFLAGS_aarch64_unknown_linux_gnu": (
            "--sysroot=$TARGET_SYSROOT -B$TARGET_COMPILER_BIN "
            "-B$TARGET_GCC_LIBDIR -B$TARGET_BINUTILS_DIR"
        ),
        "CXXFLAGS_aarch64_unknown_linux_gnu": (
            "--sysroot=$TARGET_SYSROOT -B$TARGET_COMPILER_BIN "
            "-B$TARGET_GCC_LIBDIR -B$TARGET_BINUTILS_DIR"
        ),
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
        "snapshot_usr_lib_relative_path": (
            "toolchain/sysroot/usr/lib/x86_64-linux-gnu"
        ),
        "cargo_target_dir_subpaths_may_be_prepended": True,
        "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed": False,
    },
    "source_date_epoch": 1_785_110_400,
}
IDENTITY_INDEPENDENCE_HOLD_STATUS = (
    "hold_identity_independence_evidence_unverified"
)
LEGACY_REGISTRY_TOP_LEVEL_FIELDS = {
    "contract_schema",
    "registry_schema",
    "descriptor_schema",
    "endpoints",
    "descriptors",
}
LEGACY_REGISTRY_DESCRIPTOR_FIELDS = {
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
EXPECTED_LEGACY_REGISTRY_SCHEMAS = {
    "contract_schema": "org.trillionnium.agent-descriptor-registry.contract.v1",
    "registry_schema": "org.trillionnium.agent-descriptor-registry.v1",
    "descriptor_schema": "org.trillionnium.agent-descriptor.v1",
}
EXPECTED_REGISTRY_ENDPOINTS = [
    {
        "symbol": "SYSTEM_API",
        "tool_selinux_domain": "u:r:trillionnium_agent_system_api_tool:s0",
        "operation_replay_sync_selinux_domain": (
            "u:r:trillionnium_agent_system_api_operation_replay_sync:s0"
        ),
    },
    {
        "symbol": "ACCESSIBILITY",
        "tool_selinux_domain": "u:r:trillionnium_agent_accessibility_tool:s0",
        "operation_replay_sync_selinux_domain": (
            "u:r:trillionnium_agent_accessibility_operation_replay_sync:s0"
        ),
    },
]
EXPECTED_CODEX_STABLE_FIELDS = {
    "symbol": "CODEX",
    "provider_id": "openai-codex",
    "agent_id": "agent-codex-direct-v1",
    "replay_namespace": "agent-codex-v1",
    "uid": 5901,
    "gid": 5901,
    "agent_selinux_domain": "u:r:trillionnium_codex_agent:s0",
    "runtime_adapter": "supervised-codex-cli",
}
P01_DIRECT_TOOLS_SOURCE_ROOT = (
    REPOSITORY / "crates/trillionnium-agent-direct-tools/src"
)
REGISTRY_IDENTITY_KEY_READ = re.compile(
    rb"\bCODEX\s*\.\s*identity_key_sha256\b"
)
OUTPUT_NAMES = {
    "system_api_tool": "trillionnium-agent-system-api-device-conformance",
    "replay_sync_helper": (
        "trillionnium-system-api-device-conformance-replay-sync"
    ),
    "high_water_authority": "trillionnium-direct-operation-custody-high-water",
    "codex_launcher": "trillionnium-codex-agent-0.144.1-p01-userdebug",
    "receipt": P01_PRE_DAEMON_RECEIPT_FILE,
}
DEPENDENCY_GRAPH = {
    "edge_semantics": "left artifact is a build input of the right artifact",
    "edges": [
        "selected_system_api->codex_userdebug_launcher",
        "codex_runtime->codex_userdebug_launcher",
        "daemon_build_binding->p01_daemon_final_build",
        "selected_system_api->p01_daemon_final_build",
        "replay_sync_helper->p01_daemon_final_build",
        "high_water_authority->p01_daemon_final_build",
        "codex_userdebug_launcher->p01_daemon_final_build",
    ],
    "forbidden_edges": [
        "p01_daemon_final_build->daemon_build_binding",
        "p01_daemon_final_build->selected_system_api",
        "p01_daemon_final_build->replay_sync_helper",
        "p01_daemon_final_build->codex_userdebug_launcher",
        "codex_userdebug_launcher->selected_system_api",
    ],
    "acyclic": True,
}
SOURCE_BOM_SCHEMA = "org.trillionnium.local-cross-repo-source-bom.v2"
SOURCE_BOM_PASS = "PASS_LOCAL_EXACT_CLEAN_GRAPH"
SOURCE_BOM_RECEIPT_ID_SCOPE = "sha256(canonical-json-utf8-without-receipt_id)"
SOURCE_BOM_MATERIALIZER = REPOSITORY / "tools/materialize_cross_repo_source_bom.py"
SOURCE_BOM_PYTHON = Path("/usr/bin/python3")
SOURCE_BOM_FIELDS = {
    "schema",
    "decision",
    "posture",
    "source_set",
    "resolved_manifest",
    "projects",
    "trees",
    "artifacts",
    "blockers",
    "receipt_id_scope",
    "receipt_id",
}
MAX_LAUNCHER_BUILD_TOOL_BYTES = 128 * 1024 * 1024
MAX_LAUNCHER_BUILD_TOOL_OUTPUT_BYTES = 4 * 1024 * 1024
LAUNCHER_BUILD_TOOL_SCHEMA = "org.trillionnium.launcher-build-tool-custody.v1"
TARGET_COMPILER_CLOSURE_SCHEMA = (
    "org.trillionnium.target-compiler-effective-closure.v1"
)
TARGET_COMPILER_COMPONENT_QUERIES = {
    "ld": "-print-prog-name=ld",
    "as": "-print-prog-name=as",
    "cc1": "-print-prog-name=cc1",
    "collect2": "-print-prog-name=collect2",
    "Scrt1.o": "-print-file-name=Scrt1.o",
    "crtbeginS.o": "-print-file-name=crtbeginS.o",
    "libc.so": "-print-file-name=libc.so",
    "libgcc_s.so.1": "-print-file-name=libgcc_s.so.1",
    "libgcc.a": "-print-file-name=libgcc.a",
}
LAUNCHER_BUILD_ENVIRONMENT_ALLOWLIST = (
    "LANG",
    "LC_ALL",
    "LD_LIBRARY_PATH",
    "PATH",
    "SOURCE_DATE_EPOCH",
    "TMPDIR",
    "TZ",
)


class LauncherBuildTool:
    def __init__(
        self,
        *,
        role: str,
        path: Path,
        parent_descriptor: int,
        leaf: str,
        descriptor: int,
        initial_metadata: os.stat_result,
        initial_bytes: bytes,
    ) -> None:
        self.role = role
        self.path = path
        self.parent_descriptor = parent_descriptor
        self.leaf = leaf
        self.descriptor = descriptor
        self.initial_metadata = initial_metadata
        self.initial_bytes = initial_bytes

    def close(self) -> None:
        descriptors = (
            ("executable", self.descriptor),
            ("parent directory", self.parent_descriptor),
        )
        self.descriptor = -1
        self.parent_descriptor = -1
        failures: list[str] = []
        for label, descriptor in descriptors:
            if descriptor < 0:
                continue
            try:
                os.close(descriptor)
            except BaseException as error:
                failures.append(f"{label} fd {descriptor}: {error}")
        if failures:
            raise RuntimeError(
                f"launcher {self.role} descriptor cleanup failed: "
                + "; ".join(failures)
            )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def reject_duplicate_json_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def reject_nonstandard_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def canonical_source_bom_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def require_digest(value: str, label: str) -> str:
    if LOWER_SHA256.fullmatch(value) is None or value == "0" * 64:
        raise RuntimeError(f"{label} is not a nonzero lowercase SHA-256")
    return value


def load_legacy_descriptor_registry_digests() -> dict[str, str]:
    """Validate the frozen v1 descriptor contract and derive its three digests."""
    raw = read_bounded_regular(
        LEGACY_DESCRIPTOR_CONTRACT,
        "legacy AgentDescriptor registry contract",
        128 * 1024,
    )
    try:
        contract = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_json_object,
            parse_constant=reject_nonstandard_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeError("AgentDescriptor registry contract is invalid") from error
    if (
        not isinstance(contract, dict)
        or set(contract) != LEGACY_REGISTRY_TOP_LEVEL_FIELDS
        or any(
            contract.get(key) != value
            for key, value in EXPECTED_LEGACY_REGISTRY_SCHEMAS.items()
        )
        or contract.get("endpoints") != EXPECTED_REGISTRY_ENDPOINTS
    ):
        raise RuntimeError("AgentDescriptor registry contract drifted")
    descriptors = contract.get("descriptors")
    if not isinstance(descriptors, list) or len(descriptors) != 1:
        raise RuntimeError("AgentDescriptor registry is not the Codex-only set")
    descriptor = descriptors[0]
    if (
        not isinstance(descriptor, dict)
        or set(descriptor) != LEGACY_REGISTRY_DESCRIPTOR_FIELDS
        or any(
            descriptor.get(key) != value
            for key, value in EXPECTED_CODEX_STABLE_FIELDS.items()
        )
    ):
        raise RuntimeError("AgentDescriptor registry Codex principal drifted")
    identity = descriptor.get("identity_key_sha256")
    if not isinstance(identity, str):
        raise RuntimeError("AgentDescriptor registry identity is missing")
    require_digest(identity, "AgentDescriptor registry identity")
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
    return {
        "launcher identity": identity,
        "contract digest": sha256_bytes(raw),
        "canonical digest": sha256_bytes(canonical_registry),
    }


def legacy_descriptor_contamination_hold_gate(
    legacy_registry_digests: dict[str, str],
) -> dict[str, object]:
    """Return the closed, deliberately unresolved identity-independence gate."""
    if set(legacy_registry_digests) != {
        "canonical digest",
        "contract digest",
        "launcher identity",
    }:
        raise RuntimeError("legacy AgentDescriptor digest set is not closed")
    for label, digest in legacy_registry_digests.items():
        require_digest(digest, f"legacy AgentDescriptor {label}")
    return {
        "status": IDENTITY_INDEPENDENCE_HOLD_STATUS,
        "literal_digest_absence_verified": True,
        "digests": dict(legacy_registry_digests),
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


def daemon_build_binding(
    artifacts: dict[str, bytes],
    identity_independence_gate: dict[str, object],
    toolchain_snapshot: dict[str, object],
    target_compiler_closure: dict[str, object],
) -> dict[str, object]:
    """Project only the stable semantic inputs that may affect daemon bytes.

    Source-BOM identity, checkout revisions, receipt bytes, tool paths, and
    compiler custody are deliberately excluded.  They remain external
    provenance/admission evidence, while this closed projection is the only
    pre-daemon receipt content embedded in the final daemon.
    """

    if set(artifacts) != {
        "system_api_tool",
        "replay_sync_helper",
        "high_water_authority",
        "codex_launcher",
    }:
        raise RuntimeError("daemon build artifact input set is not closed")
    gate_profile_sha256 = sha256_bytes(
        canonical_source_bom_bytes(identity_independence_gate)
    )
    return {
        "schema": DAEMON_BUILD_BINDING_SCHEMA,
        "sha256_scope": DAEMON_BUILD_BINDING_SHA256_SCOPE,
        "product_variant": "userdebug",
        "feature_profile": {
            "cargo_package": "trillionniumd",
            "enabled_cargo_features": [
                "p0-launch-package-device-conformance",
            ],
            "default_cargo_features": [],
            "conformance_build_variant": "userdebug",
        },
        "target_profile": dict(DAEMON_TARGET_PROFILE),
        "cargo_profile": dict(DAEMON_CARGO_PROFILE),
        "build_policy": dict(DAEMON_BUILD_POLICY),
        "toolchain_snapshot": dict(toolchain_snapshot),
        "target_compiler_closure": dict(target_compiler_closure),
        "runtime_artifact_sha256": {
            role: sha256_bytes(artifacts[role])
            for role in (
                "system_api_tool",
                "replay_sync_helper",
                "high_water_authority",
                "codex_launcher",
            )
        },
        "stable_principal": {
            "authority": "stable_principal_registry_v2",
            "contract_sha256": FROZEN_STABLE_PRINCIPAL_CONTRACT_SHA256,
            "canonical_sha256": FROZEN_STABLE_PRINCIPAL_CANONICAL_SHA256,
        },
        "identity_independence_hold": {
            "schema": (
                "org.trillionnium.p01-userdebug-identity-independence-hold.v1"
            ),
            "status": IDENTITY_INDEPENDENCE_HOLD_STATUS,
            "profile_sha256": gate_profile_sha256,
        },
    }


def validate_toolchain_manifest_bytes(raw: bytes) -> dict[str, object]:
    """Bind the audited closed-world A/B Mobian toolchain snapshot.

    The manifest's tree digest uses the historical snapshot producer's exact
    compact canonical-JSON encoding.  Do not substitute the pretty canonical
    encoding used by the surrounding release receipts.
    """

    if len(raw) == 0 or len(raw) > 64 * 1024 * 1024:
        raise RuntimeError("Mobian toolchain manifest is empty or oversized")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_json_object,
            parse_constant=reject_nonstandard_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeError("Mobian toolchain manifest is invalid JSON") from error
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "entries",
            "manifest_id",
            "schema",
            "source_date_epoch",
            "summary",
            "tree_digest",
        }
        or value.get("schema") != TOOLCHAIN_MANIFEST_SCHEMA
        or value.get("source_date_epoch") != 1_784_390_949
        or not isinstance(value.get("entries"), list)
        or not isinstance(value.get("summary"), dict)
    ):
        raise RuntimeError("Mobian toolchain manifest schema differs")
    entries = value["entries"]
    summary = value["summary"]
    compact_entries = json.dumps(
        entries, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    unsigned = dict(value)
    unsigned.pop("manifest_id")
    compact_unsigned = json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    if (
        sha256_bytes(raw) != FROZEN_TOOLCHAIN_MANIFEST_SHA256
        or value.get("tree_digest") != FROZEN_TOOLCHAIN_TREE_DIGEST
        or sha256_bytes(compact_entries) != FROZEN_TOOLCHAIN_TREE_DIGEST
        or value.get("manifest_id") != FROZEN_TOOLCHAIN_MANIFEST_ID
        or sha256_bytes(compact_unsigned) != FROZEN_TOOLCHAIN_MANIFEST_ID
        or summary.get("entry_count") != FROZEN_TOOLCHAIN_ENTRY_COUNT
        or len(entries) != FROZEN_TOOLCHAIN_ENTRY_COUNT
        or summary.get("regular_bytes") != FROZEN_TOOLCHAIN_REGULAR_BYTES
        or summary.get("closed_world") is not True
        or summary.get("current_user_owned") is not True
        or summary.get("directories_mode_0500") is not True
        or summary.get("regular_files_mode_0444_or_0555") is not True
        or summary.get("regular_files_single_link") is not True
        or summary.get("group_world_writable_entries") != 0
        or summary.get("symlink_targets_manifested") is not True
    ):
        raise RuntimeError("Mobian toolchain manifest closure differs")
    return {
        "schema": TOOLCHAIN_SNAPSHOT_BINDING_SCHEMA,
        "manifest_schema": TOOLCHAIN_MANIFEST_SCHEMA,
        "manifest_sha256": FROZEN_TOOLCHAIN_MANIFEST_SHA256,
        "manifest_bytes": len(raw),
        "manifest_id": FROZEN_TOOLCHAIN_MANIFEST_ID,
        "tree_digest": FROZEN_TOOLCHAIN_TREE_DIGEST,
        "entry_count": FROZEN_TOOLCHAIN_ENTRY_COUNT,
        "regular_bytes": FROZEN_TOOLCHAIN_REGULAR_BYTES,
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


def load_toolchain_manifest_binding(path: Path) -> tuple[dict[str, object], bytes]:
    absolute = absolute_without_symlink_resolution(path)
    raw = read_bounded_regular(
        absolute, "Mobian closed-world toolchain manifest", 64 * 1024 * 1024
    )
    return validate_toolchain_manifest_bytes(raw), raw


def verify_toolchain_snapshot_binding(
    path: Path,
) -> tuple[dict[str, object], bytes]:
    manifest = absolute_without_symlink_resolution(path)
    snapshot = manifest.parent / "toolchain"
    try:
        verification = toolchain_snapshot_verifier.verify(snapshot, manifest)
    except toolchain_snapshot_verifier.SnapshotError as error:
        raise RuntimeError("Mobian closed-world toolchain verification failed") from error
    binding, raw = load_toolchain_manifest_binding(manifest)
    if verification != {
        "schema": "org.trillionnium.packaging.mobian-toolchain-snapshot-verification.v1",
        "decision": "PASS_IMMUTABLE_MOBIAN_TOOLCHAIN_SNAPSHOT",
        "passed": True,
        "source_date_epoch": 1_784_390_949,
        "tree_digest": FROZEN_TOOLCHAIN_TREE_DIGEST,
        "manifest_id": FROZEN_TOOLCHAIN_MANIFEST_ID,
        "manifest_sha256": FROZEN_TOOLCHAIN_MANIFEST_SHA256,
        "entry_count": FROZEN_TOOLCHAIN_ENTRY_COUNT,
        "regular_files": 28_899,
        "symlinks": 781,
        "regular_bytes": FROZEN_TOOLCHAIN_REGULAR_BYTES,
    }:
        raise RuntimeError("Mobian toolchain verification projection differs")
    return binding, raw


def daemon_build_binding_sha256(value: object) -> str:
    return sha256_bytes(canonical_source_bom_bytes(value))


def validate_identity_digest_literal_absence(
    artifacts: dict[str, bytes], digests: dict[str, str]
) -> None:
    """Reject a pre-daemon artifact that embeds a legacy v1-registry digest."""
    for digest_label, digest in digests.items():
        encoded = require_digest(digest, digest_label).encode("ascii")
        for role, value in artifacts.items():
            if encoded in value:
                raise RuntimeError(
                    f"P01 artifact {role} embeds legacy registry {digest_label}"
                )


def require_frozen_digest(value: bytes, expected: str, label: str) -> str:
    actual = sha256_bytes(value)
    if actual != expected:
        raise RuntimeError(f"{label} digest differs from the frozen P0 artifact")
    return actual


def require_aarch64_elf(value: bytes, label: str) -> None:
    if (
        len(value) < 64
        or value[:4] != b"\x7fELF"
        or value[4] != 2
        or value[5] != 1
        or int.from_bytes(value[18:20], "little") != 183
    ):
        raise RuntimeError(f"{label} is not a little-endian AArch64 ELF64 artifact")


def retired_identity_tokens() -> tuple[bytes, ...]:
    return (
        b"open" + b"claw",
        b"open_" + b"claw",
        b"agent-open" + b"claw-direct-v1",
        b"59" + b"02",
    )


def validate_no_retired_identity(value: bytes, label: str) -> None:
    folded = value.lower()
    for forbidden in retired_identity_tokens():
        if forbidden in folded:
            raise RuntimeError(f"{label} retains a retired Agent identity")


def validate_p01_identity_authority_source(
    source_root: Path = P01_DIRECT_TOOLS_SOURCE_ROOT,
) -> None:
    """Keep the pre-daemon tools independent of the launcher identity key.

    The P0 tools intentionally use only the v2 stable Codex principal. That
    projection contains no executable digest. Reachable source must therefore
    never read the legacy ``CODEX.identity_key_sha256`` as principal or effect
    authority. The P0 launcher digest is measured later and is consumed only
    by the daemon/Android admission chain.
    """
    if not source_root.is_dir():
        raise RuntimeError("P0 direct-tools source root is unavailable")
    for path in sorted(source_root.rglob("*.rs")):
        value = path.read_bytes()
        if REGISTRY_IDENTITY_KEY_READ.search(value) is not None:
            relative = path.relative_to(source_root)
            raise RuntimeError(
                "P0 direct-tools source reads the legacy descriptor identity "
                f"key: {relative}"
            )


def validate_p01_activated_payloads(artifacts: dict[str, bytes]) -> None:
    system_api = artifacts["system_api_tool"]
    for required in (
        b"trillionnium.p0-device-conformance-activation-snapshot.v1",
        b"com.android.settings",
        b"trillionnium-agent-system-api-p0-1-device-conformance",
        b"org.trillionnium.p01.conformance.compiled-variant.v1=userdebug",
    ):
        if required not in system_api:
            raise RuntimeError(
                "frozen System API omits the activated P0 device-conformance ABI"
            )
    if b"System API effect lane is not compiled" in system_api:
        raise RuntimeError("inert System API is not a P0 build input")

    replay = artifacts["replay_sync_helper"]
    for required in (
        b"trillionnium.p0-replay-sync-ack-confirmation.v1",
        b"non_product_userdebug_daemon_custody",
        b"P0-2 sealed replay authority changed before ACTIVATE",
        b"org.trillionnium.p01.conformance.compiled-variant.v1=userdebug",
    ):
        if required not in replay:
            raise RuntimeError("frozen replay-sync helper omits the activated P0 ABI")
    if b"P0-2 external replay authority unavailable after fixed FD/context" in replay:
        raise RuntimeError("legacy HOLD replay-sync helper is not a P0 build input")


def validate_frozen_upstream_artifacts(artifacts: dict[str, bytes]) -> None:
    expectations = {
        "system_api_tool": FROZEN_SYSTEM_API_SHA256,
        "replay_sync_helper": FROZEN_REPLAY_SYNC_HELPER_SHA256,
        "high_water_authority": FROZEN_HIGH_WATER_AUTHORITY_SHA256,
    }
    for role, expected in expectations.items():
        value = artifacts[role]
        require_aarch64_elf(value, role)
        require_frozen_digest(value, expected, role)
        validate_no_retired_identity(value, role)
    validate_p01_activated_payloads(artifacts)


def stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def open_bounded_regular(path: Path, label: str, maximum: int) -> tuple[int, os.stat_result]:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > maximum
        ):
            raise RuntimeError(f"{label} is not a bounded regular file")
        return descriptor, metadata
    except BaseException:
        os.close(descriptor)
        raise


def read_bounded_regular(path: Path, label: str, maximum: int) -> bytes:
    descriptor, before = open_bounded_regular(path, label, maximum)
    try:
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, min(1024 * 1024, before.st_size - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > before.st_size:
                raise RuntimeError(f"{label} grew while it was being measured")
        after = os.fstat(descriptor)
        if total != before.st_size or stable_identity(before) != stable_identity(after):
            raise RuntimeError(f"{label} changed while it was being measured")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def load_checked_in_source_set_contract() -> tuple[dict[str, object], bytes]:
    raw = read_bounded_regular(
        SOURCE_SET_CONTRACT,
        "checked-in cross-repository source-set contract",
        256 * 1024,
    )
    try:
        contract = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_json_object,
            parse_constant=reject_nonstandard_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeError("checked-in source-set contract is invalid JSON") from error
    if (
        not isinstance(contract, dict)
        or set(contract) != {"schema", "projects", "trees", "artifacts"}
        or contract.get("schema") != "org.trillionnium.p0-cross-repo-source-set.v2"
        or contract.get("artifacts") != []
        or not isinstance(contract.get("projects"), list)
        or not isinstance(contract.get("trees"), list)
    ):
        raise RuntimeError("checked-in source-set contract shape drifted")
    project_ids = [
        project.get("id") if isinstance(project, dict) else None
        for project in contract["projects"]
    ]
    tree_ids = [
        tree.get("id") if isinstance(tree, dict) else None
        for tree in contract["trees"]
    ]
    if (
        len(project_ids) != 23
        or len(set(project_ids)) != len(project_ids)
        or any(not isinstance(value, str) for value in project_ids)
        or len(tree_ids) != 2
        or len(set(tree_ids)) != len(tree_ids)
        or any(not isinstance(value, str) for value in tree_ids)
    ):
        raise RuntimeError(
            "checked-in source-set contract is not the complete unique graph"
        )
    return contract, raw


def validate_complete_source_graph_receipt(
    receipt: dict[str, object], contract: dict[str, object], contract_raw: bytes
) -> dict[str, object]:
    source_set = receipt.get("source_set")
    expected_source_set = {
        "bytes": len(contract_raw),
        "schema": contract["schema"],
        "sha256": sha256_bytes(contract_raw),
    }
    if not isinstance(source_set, dict) or source_set != expected_source_set:
        raise RuntimeError("source BOM source-set descriptor is not exact")

    manifest = receipt.get("resolved_manifest")
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {
            "all_revisions_exact",
            "bytes",
            "declared_checkout_revision_drift_count",
            "declared_checkout_revision_drifts",
            "producer",
            "project_count",
            "sha256",
        }
        or not isinstance(manifest.get("sha256"), str)
        or LOWER_SHA256.fullmatch(manifest["sha256"]) is None
        or manifest["sha256"] == "0" * 64
        or manifest.get("all_revisions_exact") is not True
        or manifest.get("declared_checkout_revision_drift_count") != 0
        or manifest.get("declared_checkout_revision_drifts") != []
        or manifest.get("producer") != "supplied_regular_file"
        or not isinstance(manifest.get("bytes"), int)
        or isinstance(manifest.get("bytes"), bool)
        or manifest.get("bytes") <= 0
        or not isinstance(manifest.get("project_count"), int)
        or isinstance(manifest.get("project_count"), bool)
        or manifest.get("project_count") < len(contract["projects"])
    ):
        raise RuntimeError("source BOM resolved manifest descriptor is not exact")

    projects = receipt.get("projects")
    expected_projects = contract["projects"]
    if not isinstance(projects, list) or len(projects) != len(expected_projects):
        raise RuntimeError("source BOM project graph is truncated")
    observed_project_ids = [
        project.get("id") if isinstance(project, dict) else None for project in projects
    ]
    expected_project_ids = [project["id"] for project in expected_projects]
    if observed_project_ids != expected_project_ids or len(set(observed_project_ids)) != len(
        observed_project_ids
    ):
        raise RuntimeError("source BOM project graph is reordered or duplicated")

    control: dict[str, object] | None = None
    for observed, expected in zip(projects, expected_projects, strict=True):
        if not isinstance(observed, dict) or set(observed) != {
            "checkout",
            "failures",
            "git",
            "id",
            "manifest",
            "requirements",
        }:
            raise RuntimeError("source BOM project receipt shape drifted")
        expected_checkout = {
            "path": expected["checkout_path"],
            "root": expected["checkout_root"],
        }
        expected_requirements = {
            "clean": expected["require_clean"],
            "manifest_required": expected["manifest_required"],
            "no_ignored_paths": expected["require_no_ignored"],
        }
        git = observed.get("git")
        if (
            observed.get("checkout") != expected_checkout
            or observed.get("requirements") != expected_requirements
            or observed.get("failures") != []
            or not isinstance(git, dict)
            or git.get("clean_nonignored") is not True
            or git.get("exact_nonignored_state_captured") is not True
            or git.get("stable_revalidation_passed") is not True
            or git.get("object_format") not in {"sha1", "sha256"}
            or not isinstance(git.get("head"), str)
            or re.fullmatch(r"[0-9a-f]{40,64}", git["head"]) is None
            or not isinstance(git.get("head_tree"), str)
            or re.fullmatch(r"[0-9a-f]{40,64}", git["head_tree"]) is None
        ):
            raise RuntimeError("source BOM contains a non-clean or malformed project")
        for field, count_field, entries_field in (
            ("status", "bytes", "entries"),
            ("untracked", "count", "entries"),
            ("ignored", "count", "paths"),
        ):
            state = git.get(field)
            if (
                not isinstance(state, dict)
                or state.get(count_field) != 0
                or state.get(entries_field) != []
            ):
                raise RuntimeError("source BOM project state is not empty")
        tracked_diff = git.get("tracked_diff")
        if not isinstance(tracked_diff, dict) or tracked_diff.get("bytes") != 0:
            raise RuntimeError("source BOM project tracked diff is not empty")
        observed_manifest = observed.get("manifest")
        if expected["manifest_required"]:
            if (
                not isinstance(observed_manifest, dict)
                or observed_manifest.get("path") != expected["manifest_path"]
                or observed_manifest.get("name") != expected["expected_manifest_name"]
                or observed_manifest.get("revision") != git["head"]
                or observed_manifest.get("checkout_differs_from_declared_revision") is not False
            ):
                raise RuntimeError("source BOM project manifest binding drifted")
        elif observed_manifest is not None:
            raise RuntimeError("source BOM added a manifest binding to an unmanifested project")
        if observed["id"] == "control_plane":
            control = observed

    trees = receipt.get("trees")
    expected_trees = contract["trees"]
    if not isinstance(trees, list) or len(trees) != len(expected_trees):
        raise RuntimeError("source BOM non-Git tree graph is truncated")
    observed_tree_ids = [tree.get("id") if isinstance(tree, dict) else None for tree in trees]
    expected_tree_ids = [tree["id"] for tree in expected_trees]
    if observed_tree_ids != expected_tree_ids or len(set(observed_tree_ids)) != len(
        observed_tree_ids
    ):
        raise RuntimeError("source BOM non-Git tree graph is reordered or duplicated")
    for observed, expected in zip(trees, expected_trees, strict=True):
        if not isinstance(observed, dict) or set(observed) != {
            "authority",
            "failures",
            "id",
            "inventory",
            "requirements",
            "source",
        }:
            raise RuntimeError("source BOM non-Git tree receipt shape drifted")
        expected_requirements = {
            "byte_limit": expected["byte_limit"],
            "entry_limit": expected["entry_limit"],
            "mode_policy": expected["mode_policy"],
            "no_follow": True,
            "required": expected["required"],
            "stable_remeasurement": True,
        }
        inventory = observed.get("inventory")
        if (
            observed.get("authority") != "observed_local_non_git_source_tree_input"
            or observed.get("failures") != []
            or observed.get("source")
            != {"checkout_root": expected["checkout_root"], "path": expected["path"]}
            or observed.get("requirements") != expected_requirements
            or not isinstance(inventory, dict)
            or inventory.get("schema")
            != "org.trillionnium.stable-source-tree-inventory.v1"
            or inventory.get("digest_scope")
            != "sha256(canonical-json-utf8-of-schema-and-entries-with-lf)"
            or inventory.get("no_follow_path_walk_passed") is not True
            or inventory.get("safe_modes_and_types_passed") is not True
            or inventory.get("confined_link_addresses_passed") is not True
            or inventory.get("stable_remeasurement_passed") is not True
            or not isinstance(inventory.get("entries"), list)
            or inventory.get("entry_count") != len(inventory.get("entries", []))
            or inventory.get("entry_count", 0) <= 0
        ):
            raise RuntimeError("source BOM non-Git tree evidence is malformed")
        inventory_preimage = {
            "schema": inventory["schema"],
            "entries": inventory["entries"],
        }
        if inventory.get("sha256") != sha256_bytes(
            canonical_source_bom_bytes(inventory_preimage)
        ):
            raise RuntimeError("source BOM non-Git tree inventory self-hash is invalid")

    if control is None:
        raise RuntimeError("source BOM lacks the control-plane project")
    return control


def validate_source_bom_bytes(raw: bytes) -> dict[str, object]:
    try:
        receipt = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_json_object,
            parse_constant=reject_nonstandard_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeError("source BOM is invalid JSON") from error
    if not isinstance(receipt, dict) or set(receipt) != SOURCE_BOM_FIELDS:
        raise RuntimeError("source BOM does not use the closed v2 receipt schema")
    posture = receipt.get("posture")
    if (
        receipt.get("schema") != SOURCE_BOM_SCHEMA
        or receipt.get("decision") != SOURCE_BOM_PASS
        or receipt.get("blockers") != []
        or receipt.get("receipt_id_scope") != SOURCE_BOM_RECEIPT_ID_SCOPE
        or not isinstance(posture, dict)
        or posture.get("local_only") is not True
        or posture.get("signed") is not False
        or posture.get("build_authorized") is not False
        or posture.get("release_pin_published") is not False
        or posture.get("device_write_authorized") is not False
        or posture.get("ota_authorized") is not False
    ):
        raise RuntimeError("source BOM is not the exact local PASS posture")
    receipt_id = receipt.get("receipt_id")
    without_id = dict(receipt)
    without_id.pop("receipt_id")
    expected_id = "sha256:" + sha256_bytes(canonical_source_bom_bytes(without_id))
    if receipt_id != expected_id:
        raise RuntimeError("source BOM receipt_id is not canonical")
    source_set_contract, source_set_raw = load_checked_in_source_set_contract()
    control = validate_complete_source_graph_receipt(
        receipt, source_set_contract, source_set_raw
    )
    git = control.get("git")
    head = git.get("head") if isinstance(git, dict) else None
    requirements = control.get("requirements")
    if (
        not isinstance(head, str)
        or re.fullmatch(r"[0-9a-f]{40,64}", head) is None
        or requirements
        != {
            "clean": True,
            "manifest_required": False,
            "no_ignored_paths": True,
        }
        or not isinstance(git, dict)
        or git.get("clean_nonignored") is not True
        or git.get("exact_nonignored_state_captured") is not True
        or git.get("stable_revalidation_passed") is not True
    ):
        raise RuntimeError("source BOM control-plane head is invalid")
    if receipt.get("artifacts") != []:
        raise RuntimeError(
            "source BOM must not treat previously built ELF observations as source inputs"
        )
    bound_digests: dict[str, str] = {}
    for field in ("source_set", "resolved_manifest"):
        value = receipt.get(field)
        digest = value.get("sha256") if isinstance(value, dict) else None
        if (
            not isinstance(digest, str)
            or LOWER_SHA256.fullmatch(digest) is None
            or digest == "0" * 64
        ):
            raise RuntimeError(f"source BOM {field} digest is invalid")
        bound_digests[field] = digest
    return {
        "file_sha256": sha256_bytes(raw),
        "bytes": len(raw),
        "receipt_id": receipt_id,
        "control_head": head,
        "source_set_sha256": bound_digests["source_set"],
        "resolved_manifest_sha256": bound_digests["resolved_manifest"],
        "authority": "local_exact_clean_graph_not_build_or_release_authority",
    }


def git_output(repository: Path, arguments: list[str], label: str) -> bytes:
    completed = subprocess.run(
        [str(GIT), *arguments],
        cwd=repository,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"cannot verify current control-plane {label}")
    return completed.stdout


def current_control_checkout_root(repository: Path | None = None) -> Path:
    source_repository = REPOSITORY if repository is None else repository
    top_raw = git_output(
        source_repository, ["rev-parse", "--show-toplevel"], "worktree root"
    )
    try:
        top = Path(top_raw.decode("utf-8").strip()).resolve(strict=True)
        source_repository.resolve(strict=True).relative_to(top)
    except (UnicodeDecodeError, OSError, ValueError) as error:
        raise RuntimeError("current control-plane worktree root is invalid") from error
    return top


def verify_current_control_checkout(
    binding: dict[str, object], repository: Path | None = None
) -> None:
    top = current_control_checkout_root(repository)
    head = git_output(top, ["rev-parse", "HEAD"], "revision").decode("ascii").strip()
    if binding["control_head"] != head:
        raise RuntimeError("source BOM does not bind the current control-plane revision")
    dirty = git_output(
        top,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        "non-ignored state",
    )
    ignored = git_output(
        top,
        ["ls-files", "-z", "--others", "--ignored", "--exclude-standard"],
        "ignored state",
    )
    if dirty:
        raise RuntimeError("current control-plane worktree differs from the source BOM")
    if ignored:
        raise RuntimeError("current control-plane worktree contains ignored inputs")


def load_source_bom_binding(
    path: Path, repository: Path | None = None
) -> dict[str, object]:
    raw = read_bounded_regular(path, "canonical cross-repository source BOM", 8 * 1024 * 1024)
    binding = validate_source_bom_bytes(raw)
    verify_current_control_checkout(binding, repository)
    return binding


def remeasure_live_source_bom_binding(
    path: Path,
    android_root: Path,
    artifact_root: Path,
    resolved_manifest: Path,
    repository: Path | None = None,
) -> dict[str, object]:
    """Recreate the complete source BOM and require exact byte equality.

    Nested receipt self-hashes are useful corruption checks, but they are not
    evidence that the 23 Git projects and two non-Git vendor trees still match
    the supplied receipt.  The launcher builders therefore invoke the same
    canonical materializer against the live roots before and after compilation.
    """

    source_bom = absolute_without_symlink_resolution(path)
    supplied = read_bounded_regular(
        source_bom, "canonical cross-repository source BOM", 8 * 1024 * 1024
    )
    binding = validate_source_bom_bytes(supplied)
    control_root = current_control_checkout_root(repository)
    verify_current_control_checkout(binding, repository)
    android = absolute_without_symlink_resolution(android_root)
    artifacts = absolute_without_symlink_resolution(artifact_root)
    manifest = absolute_without_symlink_resolution(resolved_manifest)

    with tempfile.TemporaryDirectory(
        prefix=".source-bom-remeasurement.", dir=source_bom.parent
    ) as temporary:
        output = Path(temporary) / "live-source-bom.v2.json"
        environment = {
            "PATH": "/usr/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
        }
        try:
            completed = subprocess.run(
                [
                    str(SOURCE_BOM_PYTHON),
                    str(SOURCE_BOM_MATERIALIZER),
                    "--android-root",
                    str(android),
                    "--control-root",
                    str(control_root),
                    "--artifact-root",
                    str(artifacts),
                    "--contract",
                    str(SOURCE_SET_CONTRACT),
                    "--resolved-manifest",
                    str(manifest),
                    "--output",
                    str(output),
                ],
                cwd=control_root,
                env=environment,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=1800,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError("complete live source BOM remeasurement failed") from error
        if completed.returncode != 0:
            raise RuntimeError("complete live source BOM remeasurement returned HOLD")
        observed = read_bounded_regular(
            output, "remeasured cross-repository source BOM", 8 * 1024 * 1024
        )
    if observed != supplied:
        raise RuntimeError("live source graph differs from the supplied source BOM")
    verify_current_control_checkout(binding, repository)
    return binding


def sha256_bounded_regular(path: Path, label: str, maximum: int) -> tuple[str, int]:
    descriptor, before = open_bounded_regular(path, label, maximum)
    digest = hashlib.sha256()
    total = 0
    try:
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            total += len(chunk)
            if total > before.st_size:
                raise RuntimeError(f"{label} grew while it was being measured")
        after = os.fstat(descriptor)
        if total != before.st_size or stable_identity(before) != stable_identity(after):
            raise RuntimeError(f"{label} changed while it was being measured")
        return digest.hexdigest(), total
    finally:
        os.close(descriptor)


def stable_directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Directory identity fields that publication is not expected to mutate."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
    )


class RetainedPublishedOutput:
    """One output inode held open until the complete publication gate passes."""

    def __init__(
        self,
        *,
        directory_descriptor: int,
        name: str,
        descriptor: int,
        initial_metadata: os.stat_result,
        initial_bytes: bytes,
        mode: int,
    ) -> None:
        self.directory_descriptor = directory_descriptor
        self.name = name
        self.descriptor = descriptor
        self.initial_metadata = initial_metadata
        self.initial_bytes = initial_bytes
        self.mode = mode

    @staticmethod
    def _read_bounded(descriptor: int, expected_size: int) -> bytes:
        chunks: list[bytes] = []
        offset = 0
        maximum = expected_size + 1
        while offset < maximum:
            chunk = os.pread(
                descriptor,
                min(1024 * 1024, maximum - offset),
                offset,
            )
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
        return b"".join(chunks)

    def assert_stable(self) -> None:
        if self.descriptor < 0:
            raise RuntimeError(f"published output {self.name} is already closed")
        held_before = os.fstat(self.descriptor)
        held_bytes = self._read_bounded(
            self.descriptor, len(self.initial_bytes)
        )
        held_after = os.fstat(self.descriptor)
        reopened = -1
        try:
            pathname_metadata = os.stat(
                self.name,
                dir_fd=self.directory_descriptor,
                follow_symlinks=False,
            )
            reopened = os.open(
                self.name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=self.directory_descriptor,
            )
            reopened_before = os.fstat(reopened)
            reopened_bytes = self._read_bounded(
                reopened, len(self.initial_bytes)
            )
            reopened_after = os.fstat(reopened)
        except OSError as error:
            raise RuntimeError(
                f"published output {self.name} pathname changed"
            ) from error
        finally:
            if reopened >= 0:
                os.close(reopened)
        expected_identity = stable_identity(self.initial_metadata)
        if (
            stable_identity(held_before) != expected_identity
            or stable_identity(held_after) != expected_identity
            or stable_identity(pathname_metadata) != expected_identity
            or stable_identity(reopened_before) != expected_identity
            or stable_identity(reopened_after) != expected_identity
            or held_bytes != self.initial_bytes
            or reopened_bytes != self.initial_bytes
            or not stat.S_ISREG(pathname_metadata.st_mode)
            or pathname_metadata.st_nlink != 1
            or stat.S_IMODE(pathname_metadata.st_mode) != self.mode
        ):
            raise RuntimeError(
                f"published output {self.name} descriptor, pathname, or bytes changed"
            )

    def close(self) -> None:
        if self.descriptor >= 0:
            descriptor = self.descriptor
            self.descriptor = -1
            os.close(descriptor)


class OutputDirectoryCustody:
    """Retain every component of one absolute output directory and its files."""

    def __init__(
        self,
        *,
        path: Path,
        descriptors: list[int],
        metadata: list[os.stat_result],
        component_names: list[str],
    ) -> None:
        self.path = path
        self.descriptors = descriptors
        self.metadata = metadata
        self.component_names = component_names
        self.published: list[RetainedPublishedOutput] = []

    @property
    def descriptor(self) -> int:
        if not self.descriptors:
            raise RuntimeError("output directory custody is already closed")
        return self.descriptors[-1]

    def register(self, output: RetainedPublishedOutput) -> None:
        if output.directory_descriptor != self.descriptor:
            raise RuntimeError("published output is outside retained output custody")
        if any(item.name == output.name for item in self.published):
            raise RuntimeError(f"output artifact {output.name} was published twice")
        self.published.append(output)

    def assert_path_stable(self) -> None:
        if len(self.descriptors) != len(self.metadata):
            raise RuntimeError("output directory custody is incomplete")
        for index, (descriptor, expected) in enumerate(
            zip(self.descriptors, self.metadata, strict=True)
        ):
            held = os.fstat(descriptor)
            if stable_directory_identity(held) != stable_directory_identity(expected):
                raise RuntimeError("output directory retained descriptor changed")
            if index == 0:
                continue
            try:
                pathname_metadata = os.stat(
                    self.component_names[index - 1],
                    dir_fd=self.descriptors[index - 1],
                    follow_symlinks=False,
                )
            except OSError as error:
                raise RuntimeError(
                    "output directory retained pathname disappeared"
                ) from error
            if (
                not stat.S_ISDIR(pathname_metadata.st_mode)
                or stable_directory_identity(pathname_metadata)
                != stable_directory_identity(expected)
            ):
                raise RuntimeError("output directory retained pathname changed")

    def close(self) -> None:
        published = list(reversed(self.published))
        descriptors = list(reversed(self.descriptors))
        self.published.clear()
        self.descriptors.clear()
        failures: list[str] = []
        for output in published:
            try:
                output.close()
            except BaseException as error:
                failures.append(f"published {output.name}: {error}")
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except BaseException as error:
                failures.append(f"directory fd {descriptor}: {error}")
        if failures:
            raise RuntimeError(
                "output publication descriptor cleanup failed: "
                + "; ".join(failures)
            )


def open_empty_output_dir(path: Path) -> OutputDirectoryCustody:
    value = os.fspath(path)
    if (
        not path.is_absolute()
        or os.path.normpath(value) != value
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or len(path.parts) < 2
        or any(part in {"", ".", ".."} for part in path.parts[1:])
    ):
        raise RuntimeError(
            "output directory path must be canonical absolute component-wise no-follow syntax"
        )
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
    descriptors: list[int] = []
    metadata: list[os.stat_result] = []
    component_names: list[str] = []
    try:
        root_descriptor = os.open(path.anchor, flags)
        descriptors.append(root_descriptor)
        metadata.append(os.fstat(root_descriptor))
        for component in path.parts[1:]:
            lexical = os.stat(
                component,
                dir_fd=descriptors[-1],
                follow_symlinks=False,
            )
            if not stat.S_ISDIR(lexical.st_mode):
                raise RuntimeError(
                    "output directory path contains a link or non-directory component"
                )
            descriptor = os.open(
                component,
                flags,
                dir_fd=descriptors[-1],
            )
            descriptors.append(descriptor)
            opened = os.fstat(descriptor)
            if stable_directory_identity(opened) != stable_directory_identity(lexical):
                raise RuntimeError("output directory component changed while opened")
            metadata.append(opened)
            component_names.append(component)
        custody = OutputDirectoryCustody(
            path=path,
            descriptors=descriptors,
            metadata=metadata,
            component_names=component_names,
        )
        leaf = metadata[-1]
        if (
            not stat.S_ISDIR(leaf.st_mode)
            or leaf.st_uid != os.geteuid()
            or stat.S_IMODE(leaf.st_mode) & 0o077
        ):
            raise RuntimeError("output directory must be owner-controlled")
        if os.listdir(custody.descriptor):
            raise RuntimeError("output directory must be empty")
        custody.assert_path_stable()
        return custody
    except BaseException:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except BaseException:
                pass
        raise


def absolute_without_symlink_resolution(path: Path) -> Path:
    return path if path.is_absolute() else Path.cwd() / path


def _read_retained_tool_bytes(tool: LauncherBuildTool) -> bytes:
    before = os.fstat(tool.descriptor)
    chunks: list[bytes] = []
    offset = 0
    while offset < before.st_size:
        chunk = os.pread(
            tool.descriptor,
            min(1024 * 1024, before.st_size - offset),
            offset,
        )
        if not chunk:
            break
        chunks.append(chunk)
        offset += len(chunk)
    after = os.fstat(tool.descriptor)
    try:
        path_metadata = os.stat(
            tool.leaf,
            dir_fd=tool.parent_descriptor,
            follow_symlinks=False,
        )
    except OSError as error:
        raise RuntimeError(f"launcher {tool.role} pathname disappeared") from error
    if (
        offset != before.st_size
        or stable_identity(before) != stable_identity(after)
        or stable_identity(before) != stable_identity(path_metadata)
    ):
        raise RuntimeError(f"launcher {tool.role} changed while retained")
    return b"".join(chunks)


def open_launcher_build_tool(path: Path, role: str) -> LauncherBuildTool:
    if not path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts[1:]):
        raise RuntimeError(f"launcher {role} path must be canonical absolute syntax")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise RuntimeError("host lacks required no-follow descriptor support")
    components = path.parts[1:]
    if not components:
        raise RuntimeError(f"launcher {role} path has no executable leaf")
    directory = os.open(
        "/",
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        for component in components[:-1]:
            child = os.open(
                component,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory,
            )
            metadata = os.fstat(child)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid not in {0, os.geteuid()}
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                os.close(child)
                raise RuntimeError(
                    f"launcher {role} path traverses an untrusted directory"
                )
            os.close(directory)
            directory = child
        descriptor = os.open(
            components[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory,
        )
    except BaseException:
        os.close(directory)
        raise
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not 1 <= metadata.st_size <= MAX_LAUNCHER_BUILD_TOOL_BYTES
            or metadata.st_nlink != 1
            or metadata.st_uid not in {0, os.geteuid()}
            or mode & 0o022
            or not mode & 0o111
        ):
            raise RuntimeError(
                f"launcher {role} is not one bounded immutable executable"
            )
        tool = LauncherBuildTool(
            role=role,
            path=path,
            parent_descriptor=directory,
            leaf=components[-1],
            descriptor=descriptor,
            initial_metadata=metadata,
            initial_bytes=b"",
        )
        tool.initial_bytes = _read_retained_tool_bytes(tool)
        return tool
    except BaseException:
        os.close(descriptor)
        os.close(directory)
        raise


def revalidate_launcher_build_tool(tool: LauncherBuildTool) -> None:
    if (
        _read_retained_tool_bytes(tool) != tool.initial_bytes
        or stable_identity(os.fstat(tool.descriptor))
        != stable_identity(tool.initial_metadata)
    ):
        raise RuntimeError(f"launcher {tool.role} bytes changed during the build")
    reopened = open_launcher_build_tool(tool.path, tool.role)
    try:
        if (
            reopened.initial_bytes != tool.initial_bytes
            or stable_identity(reopened.initial_metadata)
            != stable_identity(tool.initial_metadata)
        ):
            raise RuntimeError(
                f"launcher {tool.role} absolute pathname changed during the build"
            )
    finally:
        reopened.close()


def launcher_build_environment(
    compiler: LauncherBuildTool,
    inspector: LauncherBuildTool,
    build_root: Path,
    target_host_runtime_libdir: Path,
) -> dict[str, str]:
    path_components: list[str] = []
    for component in (str(compiler.path.parent), str(inspector.path.parent)):
        if component not in path_components:
            path_components.append(component)
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "LD_LIBRARY_PATH": str(target_host_runtime_libdir),
        "PATH": os.pathsep.join(path_components),
        "SOURCE_DATE_EPOCH": "1783900800",
        "TMPDIR": str(build_root),
        "TZ": "UTC",
    }


def run_retained_tool(
    tool: LauncherBuildTool,
    arguments: list[str],
    *,
    environment: dict[str, str],
    cwd: Path,
    timeout: int,
) -> bytes:
    if set(environment) != set(LAUNCHER_BUILD_ENVIRONMENT_ALLOWLIST):
        raise RuntimeError("launcher build environment allowlist differs")
    _read_retained_tool_bytes(tool)
    try:
        completed = subprocess.run(
            [str(tool.path), *arguments],
            executable=f"/proc/self/fd/{tool.descriptor}",
            pass_fds=(tool.descriptor,),
            check=False,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"retained launcher {tool.role} execution failed") from error
    _read_retained_tool_bytes(tool)
    if (
        completed.returncode != 0
        or len(completed.stdout) + len(completed.stderr)
        > MAX_LAUNCHER_BUILD_TOOL_OUTPUT_BYTES
    ):
        raise RuntimeError(f"retained launcher {tool.role} returned failure")
    return completed.stdout


def launcher_build_tool_identity(
    tool: LauncherBuildTool,
    *,
    environment: dict[str, str],
    build_root: Path,
    require_target: bool,
) -> dict[str, object]:
    version_output = run_retained_tool(
        tool,
        ["--version"],
        environment=environment,
        cwd=build_root,
        timeout=30,
    )
    try:
        version = version_output.decode("utf-8").splitlines()[0]
    except (UnicodeDecodeError, IndexError) as error:
        raise RuntimeError(f"launcher {tool.role} version output is malformed") from error
    target = "aarch64-linux-gnu"
    if require_target:
        try:
            target = run_retained_tool(
                tool,
                ["-dumpmachine"],
                environment=environment,
                cwd=build_root,
                timeout=30,
            ).decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise RuntimeError("launcher compiler target output is malformed") from error
        if target != "aarch64-linux-gnu":
            raise RuntimeError("launcher compiler target is not aarch64-linux-gnu")
    metadata = tool.initial_metadata
    return {
        "schema": LAUNCHER_BUILD_TOOL_SCHEMA,
        "role": tool.role,
        "path": str(tool.path),
        "bytes": len(tool.initial_bytes),
        "sha256": sha256_bytes(tool.initial_bytes),
        "mode": f"0{stat.S_IMODE(metadata.st_mode):o}",
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "link_count": metadata.st_nlink,
        "version": version,
        "target": target,
        "execution": {
            "mechanism": "retained_open_file_description_via_proc_self_fd",
            "measured_before_first_execution": True,
            "all_invocations_used_same_open_file_description": True,
            "descriptor_and_path_stable_after_last_execution": True,
            "ambient_environment_inherited": False,
            "environment_allowlist": list(LAUNCHER_BUILD_ENVIRONMENT_ALLOWLIST),
        },
        "complete_recursive_toolchain_closure": False,
    }


def validate_target_compiler_closure(
    compiler: LauncherBuildTool,
    *,
    environment: dict[str, str],
    build_root: Path,
    target_sysroot: Path,
    target_link_arguments: list[str],
) -> dict[str, object]:
    """Bind the effective GCC12 programs/startfiles used by one launcher build."""

    expected_arguments = [
        f"--sysroot={target_sysroot}",
        f"-B{target_sysroot / 'usr/bin'}",
        f"-B{target_sysroot / 'usr/lib/gcc-cross/aarch64-linux-gnu/12'}",
        f"-B{target_sysroot / 'usr/aarch64-linux-gnu/bin'}",
    ]
    if target_link_arguments != expected_arguments:
        raise RuntimeError("target compiler search arguments differ from the snapshot layout")
    try:
        reported_sysroot = run_retained_tool(
            compiler,
            [*target_link_arguments, "-print-sysroot"],
            environment=environment,
            cwd=build_root,
            timeout=30,
        ).decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise RuntimeError("target compiler sysroot output is malformed") from error
    if Path(reported_sysroot).resolve(strict=True) != target_sysroot.resolve(strict=True):
        raise RuntimeError("target compiler effective sysroot differs")
    components: dict[str, object] = {}
    resolved_sysroot = target_sysroot.resolve(strict=True)
    for role, query in TARGET_COMPILER_COMPONENT_QUERIES.items():
        try:
            reported = run_retained_tool(
                compiler,
                [*target_link_arguments, query],
                environment=environment,
                cwd=build_root,
                timeout=30,
            ).decode("utf-8").strip()
            resolved = Path(reported).resolve(strict=True)
            relative = resolved.relative_to(resolved_sysroot)
        except (UnicodeDecodeError, OSError, ValueError) as error:
            raise RuntimeError(
                f"target compiler effective component {role} escapes the snapshot"
            ) from error
        value = read_bounded_regular(
            resolved,
            f"target compiler effective component {role}",
            MAX_LAUNCHER_BUILD_TOOL_BYTES,
        )
        metadata = os.stat(resolved, follow_symlinks=False)
        mode = stat.S_IMODE(metadata.st_mode)
        if metadata.st_nlink != 1 or mode & 0o022:
            raise RuntimeError(
                f"target compiler effective component {role} is not immutable"
            )
        components[role] = {
            "relative_path": relative.as_posix(),
            "bytes": len(value),
            "sha256": sha256_bytes(value),
            "mode": f"0{mode:o}",
        }
    return {
        "schema": TARGET_COMPILER_CLOSURE_SCHEMA,
        "target": "aarch64-linux-gnu",
        "normalized_search_arguments": [
            "--sysroot=$TARGET_SYSROOT",
            "-B$TARGET_COMPILER_BIN",
            "-B$TARGET_GCC_LIBDIR",
            "-B$TARGET_BINUTILS_DIR",
        ],
        "reported_sysroot": "$TARGET_SYSROOT",
        "components": components,
        "snapshot_tree_fully_remeasured_before_and_after_build": True,
        "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed": False,
        "complete_host_execution_runtime_closure": False,
    }


def compile_static(
    compiler: LauncherBuildTool,
    inspector: LauncherBuildTool,
    source: Path,
    output: Path,
    definitions: list[str],
    build_root: Path,
    environment: dict[str, str],
    target_link_arguments: list[str],
) -> None:
    command = [
        "-std=c17",
        "-Os",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-fno-ident",
        "-fno-record-gcc-switches",
        f"-ffile-prefix-map={REPOSITORY}=.",
        f"-ffile-prefix-map={build_root}=.",
        f"-fmacro-prefix-map={REPOSITORY}=.",
        f"-fmacro-prefix-map={build_root}=.",
        "-static",
        "-s",
        "-Wl,--build-id=none,-z,relro,-z,now,-z,noexecstack",
        *target_link_arguments,
        *definitions,
        str(source),
        "-o",
        str(output),
    ]
    run_retained_tool(
        compiler,
        command,
        environment=environment,
        cwd=REPOSITORY,
        timeout=300,
    )
    output.chmod(0o555)
    try:
        header = run_retained_tool(
            inspector,
            ["-h", str(output)],
            environment=environment,
            cwd=REPOSITORY,
            timeout=30,
        ).decode("utf-8")
        dynamic = run_retained_tool(
            inspector,
            ["-d", str(output)],
            environment=environment,
            cwd=REPOSITORY,
            timeout=30,
        ).decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError("launcher ELF inspection output is malformed") from error
    if "AArch64" not in header or "NEEDED" in dynamic:
        raise RuntimeError("launcher is not a static AArch64 ELF")


def reproducible_launcher(
    compiler: LauncherBuildTool,
    inspector: LauncherBuildTool,
    source: Path,
    definitions: list[str],
    build_root: Path,
    environment: dict[str, str],
    target_link_arguments: list[str],
) -> bytes:
    first = build_root / "first"
    second = build_root / "second"
    compile_static(
        compiler,
        inspector,
        source,
        first,
        definitions,
        build_root,
        environment,
        target_link_arguments,
    )
    compile_static(
        compiler,
        inspector,
        source,
        second,
        definitions,
        build_root,
        environment,
        target_link_arguments,
    )
    first_bytes = read_bounded_regular(first, "first launcher", 8 * 1024 * 1024)
    second_bytes = read_bounded_regular(second, "second launcher", 8 * 1024 * 1024)
    if first_bytes != second_bytes:
        raise RuntimeError(f"launcher build is not reproducible: {source}")
    return first_bytes


def write_exclusive(path: Path, value: bytes, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        view = memoryview(value)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise RuntimeError(f"short write while creating {path}")
            offset += written
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_exclusive_at(
    custody: OutputDirectoryCustody, name: str, value: bytes, mode: int
) -> RetainedPublishedOutput:
    if not name or "/" in name or name in {".", ".."}:
        raise RuntimeError("output artifact name is not a single path component")
    descriptor = os.open(
        name,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
        dir_fd=custody.descriptor,
    )
    completed = False
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError(f"output artifact {name} is not a single-link file")
        view = memoryview(value)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise RuntimeError(f"short write while creating {name}")
            offset += written
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or after.st_size != len(value)
            or stat.S_IMODE(after.st_mode) != mode
        ):
            raise RuntimeError(f"output artifact {name} changed during publication")
        output = RetainedPublishedOutput(
            directory_descriptor=custody.descriptor,
            name=name,
            descriptor=descriptor,
            initial_metadata=after,
            initial_bytes=value,
            mode=mode,
        )
        output.assert_stable()
        custody.register(output)
        completed = True
        return output
    finally:
        if not completed:
            os.close(descriptor)


def finalize_output_publication(
    custody: OutputDirectoryCustody,
    expected: dict[str, tuple[bytes, int]],
) -> None:
    expected_names = set(expected)
    custody.assert_path_stable()
    observed_names = os.listdir(custody.descriptor)
    if (
        len(observed_names) != len(expected_names)
        or set(observed_names) != expected_names
        or {output.name for output in custody.published} != expected_names
        or len(custody.published) != len(expected_names)
    ):
        raise RuntimeError("output directory inventory is not the exact published set")
    for output in custody.published:
        expected_bytes, expected_mode = expected[output.name]
        if output.initial_bytes != expected_bytes or output.mode != expected_mode:
            raise RuntimeError(
                f"retained output {output.name} differs from publication contract"
            )
        output.assert_stable()
    os.fsync(custody.descriptor)
    custody.assert_path_stable()
    observed_names = os.listdir(custody.descriptor)
    if (
        len(observed_names) != len(expected_names)
        or set(observed_names) != expected_names
    ):
        raise RuntimeError("output directory inventory changed during final sync")
    for output in custody.published:
        output.assert_stable()
    custody.assert_path_stable()


def build(args: argparse.Namespace) -> dict[str, object]:
    output = args.output_dir
    output_custody = open_empty_output_dir(output)
    try:
        return build_into(args, output, output_custody)
    finally:
        output_custody.close()


def build_into(
    args: argparse.Namespace,
    output: Path,
    output_custody: OutputDirectoryCustody,
) -> dict[str, object]:
    validate_p01_identity_authority_source()
    source_bom_binding = remeasure_live_source_bom_binding(
        args.source_bom,
        args.android_root,
        args.artifact_root,
        args.resolved_manifest,
    )
    stable_principal_contract = read_bounded_regular(
        STABLE_PRINCIPAL_CONTRACT,
        "stable Agent principal registry contract",
        128 * 1024,
    )
    if sha256_bytes(stable_principal_contract) != FROZEN_STABLE_PRINCIPAL_CONTRACT_SHA256:
        raise RuntimeError("stable Agent principal registry contract digest drifted")
    legacy_registry_digests = load_legacy_descriptor_registry_digests()
    toolchain_snapshot, toolchain_manifest_before = verify_toolchain_snapshot_binding(
        args.toolchain_manifest
    )
    manifest_path = absolute_without_symlink_resolution(args.toolchain_manifest)
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
        "target_sysroot": absolute_without_symlink_resolution(args.target_sysroot),
        "target_compiler": absolute_without_symlink_resolution(args.cc),
        "target_readelf": absolute_without_symlink_resolution(args.readelf),
        "target_compiler_bin": absolute_without_symlink_resolution(
            args.target_compiler_bin
        ),
        "target_gcc_libdir": absolute_without_symlink_resolution(
            args.target_gcc_libdir
        ),
        "target_binutils_dir": absolute_without_symlink_resolution(
            args.target_binutils_dir
        ),
        "target_host_runtime_libdir": absolute_without_symlink_resolution(
            args.target_host_runtime_libdir
        ),
    }
    if supplied_layout != expected_layout:
        raise RuntimeError(
            "P01 target compiler/sysroot layout differs from the bound lane snapshot"
        )
    target_link_arguments = [
        f"--sysroot={supplied_layout['target_sysroot']}",
        f"-B{supplied_layout['target_compiler_bin']}",
        f"-B{supplied_layout['target_gcc_libdir']}",
        f"-B{supplied_layout['target_binutils_dir']}",
    ]
    codex_runtime = absolute_without_symlink_resolution(args.codex_runtime)
    system_api_tool = absolute_without_symlink_resolution(args.system_api_tool)
    replay_sync_helper = absolute_without_symlink_resolution(args.replay_sync_helper)
    high_water_authority = absolute_without_symlink_resolution(
        args.high_water_authority
    )
    upstream_artifacts = {
        "system_api_tool": read_bounded_regular(
            system_api_tool, "selected P0 System API", 64 * 1024 * 1024
        ),
        "replay_sync_helper": read_bounded_regular(
            replay_sync_helper, "P0 replay-sync helper", 64 * 1024 * 1024
        ),
        "high_water_authority": read_bounded_regular(
            high_water_authority, "P0 high-water authority", 64 * 1024 * 1024
        ),
    }
    validate_frozen_upstream_artifacts(upstream_artifacts)
    system_api_sha256 = FROZEN_SYSTEM_API_SHA256
    codex_source_bytes = read_bounded_regular(
        CODEX_SOURCE, "Codex launcher source", 1024 * 1024
    )
    codex_runtime_sha256, codex_runtime_bytes = sha256_bounded_regular(
        codex_runtime, "Codex runtime", 512 * 1024 * 1024
    )
    if codex_runtime_sha256 != FROZEN_CODEX_RUNTIME_SHA256:
        raise RuntimeError("Codex runtime digest differs from the frozen product runtime")
    compiler = open_launcher_build_tool(args.cc, "compiler_driver")
    try:
        inspector = open_launcher_build_tool(args.readelf, "elf_inspector")
        try:
            with tempfile.TemporaryDirectory(
                prefix=".p01-agent-launchers.", dir=output.parent
            ) as temporary:
                build_root = Path(temporary)
                environment = launcher_build_environment(
                    compiler,
                    inspector,
                    build_root,
                    supplied_layout["target_host_runtime_libdir"],
                )
                compiler_identity = launcher_build_tool_identity(
                    compiler,
                    environment=environment,
                    build_root=build_root,
                    require_target=True,
                )
                inspector_identity = launcher_build_tool_identity(
                    inspector,
                    environment=environment,
                    build_root=build_root,
                    require_target=False,
                )
                target_compiler_closure = validate_target_compiler_closure(
                    compiler,
                    environment=environment,
                    build_root=build_root,
                    target_sysroot=supplied_layout["target_sysroot"],
                    target_link_arguments=target_link_arguments,
                )
                codex_source = build_root / "codex-integrity-launcher.c"
                write_exclusive(codex_source, codex_source_bytes, 0o444)
                codex_bytes = reproducible_launcher(
                    compiler,
                    inspector,
                    codex_source,
                    [
                        f'-DTRILLIONNIUM_CODEX_RUNTIME_SHA256="{codex_runtime_sha256}"',
                        f'-DTRILLIONNIUM_SYSTEM_API_TOOL_SHA256="{system_api_sha256}"',
                        "-DTRILLIONNIUM_CODEX_REQUIRE_ACCESSIBILITY_TOOL=0",
                    ],
                    build_root,
                    environment,
                    target_link_arguments,
                )
                revalidate_launcher_build_tool(compiler)
                revalidate_launcher_build_tool(inspector)
        finally:
            inspector.close()
    finally:
        compiler.close()

    codex_sha256 = sha256_bytes(codex_bytes)
    if system_api_sha256.encode("ascii") not in codex_bytes:
        raise RuntimeError("launcher omits the selected P0 System API pin")
    for forbidden in (
        b"trillionnium-agent-accessibility",
        b"TRILLIONNIUM_ACCESSIBILITY_TOOL_SHA256",
        b"trillionniumd",
    ):
        if forbidden in codex_bytes:
            raise RuntimeError("P0 launcher retains a reverse or dual-tool dependency")

    for role, value in upstream_artifacts.items():
        if codex_sha256.encode("ascii") in value:
            raise RuntimeError(
                f"upstream artifact {role} retains a reverse launcher dependency"
            )

    artifacts = {
        **upstream_artifacts,
        "codex_launcher": codex_bytes,
    }
    identity_independence_gate = legacy_descriptor_contamination_hold_gate(
        legacy_registry_digests
    )
    validate_identity_digest_literal_absence(artifacts, legacy_registry_digests)
    build_binding = daemon_build_binding(
        artifacts,
        identity_independence_gate,
        toolchain_snapshot,
        target_compiler_closure,
    )
    executable_roles = {
        "system_api_tool",
        "replay_sync_helper",
        "high_water_authority",
        "codex_launcher",
    }
    publication_contract: dict[str, tuple[bytes, int]] = {}
    for role, value in artifacts.items():
        mode = 0o555 if role in executable_roles else 0o444
        write_exclusive_at(
            output_custody,
            OUTPUT_NAMES[role],
            value,
            mode,
        )
        publication_contract[OUTPUT_NAMES[role]] = (value, mode)

    # Re-check the complete control worktree after compilation and before a
    # receipt can be published. The source BOM is invalid if tracked,
    # untracked, or ignored state changed without moving HEAD.
    if (
        remeasure_live_source_bom_binding(
            args.source_bom,
            args.android_root,
            args.artifact_root,
            args.resolved_manifest,
        )
        != source_bom_binding
    ):
        raise RuntimeError("source BOM binding changed during P01 launcher build")
    toolchain_snapshot_after, toolchain_manifest_after = (
        verify_toolchain_snapshot_binding(args.toolchain_manifest)
    )
    if (
        toolchain_snapshot_after != toolchain_snapshot
        or toolchain_manifest_after != toolchain_manifest_before
    ):
        raise RuntimeError("Mobian toolchain manifest changed during P01 launcher build")
    receipt: dict[str, object] = {
        "schema": P01_PRE_DAEMON_RECEIPT_SCHEMA,
        "receipt_role": "final_daemon_build_binding_envelope",
        "status": "host_built_device_evidence_hold",
        "product_variant": "userdebug",
        "selected_system_api_sha256": system_api_sha256,
        "principal_authority": "stable_principal_registry_v2",
        "legacy_descriptor_executable_identity_is_principal_authority": False,
        "runtime_policy_launcher_measurement_migration": (
            "active_launcher_separate_from_stable_principal"
        ),
        "product_effect_authority_available": False,
        "accessibility_available": False,
        "dependency_graph": DEPENDENCY_GRAPH,
        "source_bom": source_bom_binding,
        "daemon_build_binding": build_binding,
        "stable_principal_launcher_measurement": {
            "status": "host_measurement_only_avb_slot_admission_absent",
            "stable_principal_contract_sha256": FROZEN_STABLE_PRINCIPAL_CONTRACT_SHA256,
            "stable_principal_canonical_sha256": FROZEN_STABLE_PRINCIPAL_CANONICAL_SHA256,
            "launcher_executable_sha256": codex_sha256,
            "launcher_identity_source": "measured_after_closed_launcher_inputs",
            "executable_identity_is_stable_registry_input": False,
        },
        "legacy_descriptor_contamination_hold_gate": identity_independence_gate,
        "compiler": compiler_identity,
        "elf_inspector": inspector_identity,
        "inputs": {
            "codex_runtime_sha256": codex_runtime_sha256,
            "codex_runtime_bytes": codex_runtime_bytes,
            "system_api_tool_input_sha256": system_api_sha256,
            "replay_sync_helper_input_sha256": sha256_bytes(
                upstream_artifacts["replay_sync_helper"]
            ),
            "high_water_authority_input_sha256": sha256_bytes(
                upstream_artifacts["high_water_authority"]
            ),
            "codex_launcher_source_sha256": sha256_bytes(codex_source_bytes),
        },
        "artifacts": {
            role: {
                "file": OUTPUT_NAMES[role],
                "sha256": sha256_bytes(value),
                "bytes": len(value),
            }
            for role, value in artifacts.items()
        },
        "daemon_build_required": True,
        "device_execution_verified": False,
        "release_allowed": False,
    }
    receipt_bytes = (
        json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    write_exclusive_at(
        output_custody, OUTPUT_NAMES["receipt"], receipt_bytes, 0o444
    )
    publication_contract[OUTPUT_NAMES["receipt"]] = (receipt_bytes, 0o444)
    finalize_output_publication(output_custody, publication_contract)
    receipt["receipt_sha256"] = sha256_bytes(receipt_bytes)
    receipt["codex_launcher_sha256"] = codex_sha256
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
    parser.add_argument("--replay-sync-helper", type=Path, required=True)
    parser.add_argument("--high-water-authority", type=Path, required=True)
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
    receipt = build(parse_args())
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
