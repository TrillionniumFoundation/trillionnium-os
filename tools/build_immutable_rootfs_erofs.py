#!/usr/bin/env python3
"""Validate or convert one normalized Root-Linux tar.zst.

``host-base`` emits the historical non-authorizing deterministic EROFS image.
``codex-product-preflight`` instead validates the fresh-base, Codex-only
package receipt, runtime placeholders, admission manifest and compiled SELinux
database, then emits a truthful HOLD receipt.  It never emits an image because
the reviewed erofs-utils tar path does not apply file_contexts.  Product
admission remains impossible until a reviewed label-applying materializer and
pinned xattr verifier replace that HOLD.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
from typing import Mapping
import uuid


SCHEMA = "org.trillionnium.root-linux.immutable-erofs.v1"
CODEX_PREFLIGHT_SCHEMA = (
    "org.trillionnium.root-linux.codex-erofs-preflight-receipt.v4"
)
CODEX_ADMISSION_MANIFEST_SCHEMA = (
    "org.trillionnium.root-linux.codex-erofs-admission.v4"
)
CODEX_PACKAGE_RECEIPT_SCHEMA = "org.trillionnium.rootfs-package.receipt.v9"
CODEX_PACKAGE_CONTRACT_SCHEMA = "org.trillionnium.rootfs-package.contract.v9"
CODEX_PACKAGE_DECISION = "HOLD_IDENTITY_INDEPENDENCE_EVIDENCE_UNVERIFIED"
CODEX_PACKAGE_STATUS = "hold_identity_independence_evidence_unverified"
EXPECTED_LEGACY_DESCRIPTOR_DIGESTS = {
    "canonical digest": "bc6c64abbb893e6e75ed708f87cf864e6c8f7503381371dc394409bddc4009c2",
    "contract digest": "5ecd89d3c9fedbbeb0ac1de32fba2b5e5e5d248048ddc9a9e0359a0a01903119",
    "launcher identity": "edcf9d31da8b48d29575115a7242691c1337174edf42573b7274b652a4cd571c",
}
STABLE_PRINCIPAL_CONTRACT_SHA256 = (
    "3e9bfcb04e48062c20bd7407635c1a27086a0de8c2fa5ca73963c946b984095b"
)
STABLE_PRINCIPAL_CANONICAL_SHA256 = (
    "a9c224116123deb49908beda3ab047fc98d6917cfeb62d60364033858cc57153"
)
COMMON_ARTIFACT_SET_SCHEMA = (
    "org.trillionnium.common-codex-rootfs-artifact-set.v5"
)
COMMON_ARTIFACT_SET_FILE = "common-codex-rootfs-artifact-set.v5.json"
COMMON_ARTIFACT_SET_STATUS = "host_built_device_evidence_hold"
COMMON_LAUNCHER_AB_SCHEMA = "org.trillionnium.codex-launcher-artifact-set-ab.v4"
COMMON_LAUNCHER_AB_FILE = "codex-launcher-artifact-set-ab.v4.json"
COMMON_LAUNCHER_AB_DECISION = (
    "PASS_HOST_ONLY_DETERMINISTIC_CODEX_LAUNCHER_ARTIFACT_SET_AB"
)
COMMON_LAUNCHER_AB_HOLD = (
    "HOLD_IDENTITY_INDEPENDENCE_PRODUCT_DEVICE_AND_COMPLETE_TOOLCHAIN_ADMISSION"
)
ROOTFS_RECEIPT_ID_SCOPE = (
    "sha256(canonical-json-utf8-sort-keys-compact-no-lf-without-receipt_id)"
)
ANDROID_STAGING_FILTER_SCHEMA = (
    "org.trillionnium.rootfs-tar-staging-filter.v1"
)
ANDROID_STAGING_FILTER_SOURCE_SHA256 = (
    "dc48c9ce97f1e64a62e45d00350b44801adb7cc0f60f8666b1d5e87696ce6092"
)
ANDROID_STAGING_FILTER_EXPECTED_DIRECTORY_COUNT = 265
ANDROID_STAGING_FILTER_EXPECTED_GNU_LONGLINKS = (
    (
        "etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_"
        "CIF_A62634068.pem",
        "../../../usr/share/ca-certificates/mozilla/"
        "Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.crt",
    ),
    (
        "etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_"
        "CIF_A62634068_2.pem",
        "../../../usr/share/ca-certificates/mozilla/"
        "Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068_2.crt",
    ),
    (
        "etc/ssl/certs/Hellenic_Academic_and_Research_Institutions_"
        "ECC_RootCA_2015.pem",
        "../../../usr/share/ca-certificates/mozilla/"
        "Hellenic_Academic_and_Research_Institutions_ECC_RootCA_2015.crt",
    ),
    (
        "etc/ssl/certs/Hellenic_Academic_and_Research_Institutions_"
        "RootCA_2015.pem",
        "../../../usr/share/ca-certificates/mozilla/"
        "Hellenic_Academic_and_Research_Institutions_RootCA_2015.crt",
    ),
)
ANDROID_STAGING_FILTER_TAR_BLOCK_BYTES = 512
ANDROID_STAGING_FILTER_MAX_HEADER_COUNT = 10_000
ANDROID_STAGING_FILTER_MAX_GNU_LONGLINK_BYTES = 256
LAUNCHER_BUILD_TOOL_SCHEMA = "org.trillionnium.launcher-build-tool-custody.v1"
LAUNCHER_BUILD_ENVIRONMENT_ALLOWLIST = [
    "LANG",
    "LC_ALL",
    "LD_LIBRARY_PATH",
    "PATH",
    "SOURCE_DATE_EPOCH",
    "TMPDIR",
    "TZ",
]
EXPECTED_TOOLCHAIN_SNAPSHOT_BINDING = {
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
EXPECTED_TARGET_COMPILER_COMPONENTS = {
    "ld": {
        "relative_path": "usr/bin/aarch64-linux-gnu-ld.bfd",
        "bytes": 1_663_936,
        "sha256": "e09a889c78a75e73ed096c9fa28905599e6813298b9ac839d10b02ffa96e7b08",
        "mode": "0555",
    },
    "as": {
        "relative_path": "usr/bin/aarch64-linux-gnu-as",
        "bytes": 854_992,
        "sha256": "49b906db048bd4be400bc885e3aed84e778cffa48a426fe5b9716bd80ea88e47",
        "mode": "0555",
    },
    "cc1": {
        "relative_path": "usr/lib/gcc-cross/aarch64-linux-gnu/12/cc1",
        "bytes": 29_467_976,
        "sha256": "bd201647ea988ff6060fc73595a3f7edbe4aff485e18efa4afd02c432dfffb17",
        "mode": "0555",
    },
    "collect2": {
        "relative_path": "usr/lib/gcc-cross/aarch64-linux-gnu/12/collect2",
        "bytes": 639_192,
        "sha256": "3ee4c136b021dce4b1157cb64b5eaeda9f49d4aa580dc74aed2e29f422a09a70",
        "mode": "0555",
    },
    "Scrt1.o": {
        "relative_path": "usr/lib/aarch64-linux-gnu/Scrt1.o",
        "bytes": 1_704,
        "sha256": "d03fc7a1a0b7cdbc1fb0a5c25425d3e1d2971a193c52f0ccdc40049234b7daae",
        "mode": "0444",
    },
    "crtbeginS.o": {
        "relative_path": "usr/lib/gcc-cross/aarch64-linux-gnu/12/crtbeginS.o",
        "bytes": 3_472,
        "sha256": "1e819bf5f6d4785a0ba792e34853f1d42d64e58a4d49bf788c27cc537885a194",
        "mode": "0444",
    },
    "libc.so": {
        "relative_path": "usr/lib/aarch64-linux-gnu/libc.so",
        "bytes": 291,
        "sha256": "cf5d6c74565de8a3e39b94ca1da75acedbb1f0d44dfc1633969477ae058badc3",
        "mode": "0444",
    },
    "libgcc_s.so.1": {
        "relative_path": "usr/aarch64-linux-gnu/lib/libgcc_s.so.1",
        "bytes": 133_320,
        "sha256": "c39939ec474dd03d9a8aa657d85fa71a8f879a3159bf1a5d19dff3b4788dfba2",
        "mode": "0444",
    },
    "libgcc.a": {
        "relative_path": "usr/lib/gcc-cross/aarch64-linux-gnu/12/libgcc.a",
        "bytes": 334_174,
        "sha256": "5cde35acdc58ad84b548efe9bade4ed8151154db35d7fc3bca1240db77e68dff",
        "mode": "0444",
    },
}
EXPECTED_LAUNCHER_BUILD_TOOL_IDENTITIES = {
    "compiler_driver": {
        "bytes": 1_315_296,
        "sha256": "c7b8890354c8ddc0364addfeb8968597e197627bd1e338fb6ed705b578803846",
        "mode": "0555",
        "version": "aarch64-linux-gnu-gcc-12 (Debian 12.2.0-14) 12.2.0",
        "target": "aarch64-linux-gnu",
    },
    "elf_inspector": {
        "bytes": 802_144,
        "sha256": "716843c4034e24fa7d8e7d2a590dd1645aebf2b87ddc3a888144923174b2a562",
        "mode": "0555",
        "version": "GNU readelf (GNU Binutils for Debian) 2.40",
        "target": "aarch64-linux-gnu",
    },
}
TOOLCHAIN_CLAIM_AUTHORITY = {
    "schema": "org.trillionnium.upstream-toolchain-receipt-claim.v1",
    "source": "content_hash_bound_common_and_self_hashed_launcher_receipt",
    "upstream_receipts_cross_agree": True,
    "receipt_ids_are_content_identifiers_only": True,
    "receipt_ids_are_signatures_or_attestations": False,
    "physical_snapshot_input_to_this_stage": False,
    "physical_snapshot_remeasured_by_this_stage": False,
    "effective_components_requeried_by_this_stage": False,
}
SOURCE_BOM_CLAIM_AUTHORITY = {
    "schema": "org.trillionnium.upstream-source-bom-receipt-claim.v1",
    "source": "content_hash_bound_common_and_self_hashed_launcher_receipt",
    "upstream_receipts_cross_agree": True,
    "receipt_ids_are_content_identifiers_only": True,
    "receipt_ids_are_signatures_or_attestations": False,
    "physical_source_bom_input_to_this_stage": False,
    "live_source_graph_remeasured_by_this_stage": False,
}
PACKAGE_LIMITATIONS = [
    "upstream_receipt_ids_are_unsigned_content_identifiers_not_signatures_or_attestations",
    "physical_toolchain_snapshot_is_not_an_input_to_rootfs_packager",
    "physical_toolchain_snapshot_is_not_remeasured_by_rootfs_packager",
    "effective_target_compiler_components_are_not_requeried_by_rootfs_packager",
    "physical_source_bom_or_live_source_graph_is_not_remeasured_by_rootfs_packager",
]
PREFLIGHT_LIMITATIONS = [
    "upstream_receipt_ids_are_unsigned_content_identifiers_not_signatures_or_attestations",
    "physical_toolchain_snapshot_is_not_an_input_to_erofs_preflight",
    "physical_toolchain_snapshot_is_not_remeasured_by_erofs_preflight",
    "effective_target_compiler_components_are_not_requeried_by_erofs_preflight",
    "physical_source_bom_or_live_source_graph_is_not_remeasured_by_erofs_preflight",
]
CODEX_ADMISSION_MANIFEST_PATH = (
    Path(__file__).resolve().parents[1]
    / "packaging/root-linux/rootfs-codex-erofs-admission.v4.json"
)
FRESH_BASE_ALLOWLIST_PATH = (
    Path(__file__).resolve().parents[1]
    / "packaging/root-linux/rootfs-fresh-minimal-bookworm-arm64.allowlist.v1.json"
)
FINAL_MOUNT_POINT = "/data/trillionnium/root-linux/rootfs"
SELINUX_COMPILED_FILE_CONTEXTS_MAGIC = 0xF97CFF8A
SELINUX_COMPILED_FILE_CONTEXTS_VERSION = 5
CODEX_PRODUCT_HOLD_REASON = (
    "Codex product EROFS HOLD: upstream identity-independence and recursive "
    "toolchain admission remain incomplete, and pinned erofs-utils tar input "
    "does not apply compiled file_contexts; no image was emitted"
)
CODEX_PRODUCT_MISSING_GATES = [
    "counterfactual same-source rebuild proving executable identity independence",
    "verified stable-principal admission split evidence receipt",
    "complete recursive compiler and ELF-inspector toolchain byte closure",
    "independent Debian keyring-origin approval",
    (
        "Android product-wiring receipt binding the exact final v9 archive, "
        "AgentManifest and SELinux policy"
    ),
    (
        "reviewed static EROFS materializer that applies compiled "
        "file_contexts to tar input"
    ),
    (
        "pinned fsck.erofs and dump.erofs verification of every critical "
        "security.selinux xattr"
    ),
    "Android fs-verity enable and re-measure before first read-only mount",
]
SHA256_RE = re.compile(r"[0-9a-f]{64}")


class ImageError(RuntimeError):
    """A fail-closed input, tool, archive, or image error."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def json_bytes(value: object) -> bytes:
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


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def reject_duplicate_json_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ImageError(f"duplicate JSON key forbidden: {key}")
        result[key] = value
    return result


def reject_json_constant(value: str) -> object:
    raise ImageError(f"non-finite JSON number forbidden: {value}")


def strict_json_bytes(content: bytes, label: str) -> Mapping[str, object]:
    try:
        text = content.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_json_keys,
            parse_constant=reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ImageError(f"{label} is not strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ImageError(f"{label} must be a JSON object")
    try:
        canonical = json_bytes(value)
    except UnicodeEncodeError as error:
        raise ImageError(f"{label} contains a non-scalar JSON string") from error
    if canonical != content:
        raise ImageError(f"{label} must use canonical indented JSON bytes")
    return value


def strict_json_file(path: Path, label: str) -> Mapping[str, object]:
    return strict_json_bytes(path.read_bytes(), label)


def exact_mapping(
    value: object, keys: set[str], label: str
) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ImageError(f"{label} must be a JSON object")
    actual = set(value)
    if actual != keys:
        raise ImageError(
            f"{label} keys differ: missing={sorted(keys - actual)} "
            f"unknown={sorted(actual - keys)}"
        )
    return value


def lowercase_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ImageError(f"{label} is not a lowercase SHA-256")
    return value


def bounded_int(
    value: object, label: str, minimum: int, maximum: int
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ImageError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise ImageError(f"{label} is outside its supported range")
    return value


def validate_identity_independence_gate(
    value: object, label: str
) -> Mapping[str, object]:
    gate = exact_mapping(
        value,
        {
            "counterfactual_same_source_rebuild",
            "digests",
            "literal_digest_absence_verified",
            "stable_principal_admission_split",
            "status",
        },
        label,
    )
    digests = exact_mapping(
        gate["digests"],
        {"canonical digest", "contract digest", "launcher identity"},
        f"{label}.digests",
    )
    for field in (
        "counterfactual_same_source_rebuild",
        "stable_principal_admission_split",
    ):
        nested = exact_mapping(
            gate[field],
            {"evidence_receipt", "required", "verified"},
            f"{label}.{field}",
        )
        if (
            nested["required"] is not True
            or nested["verified"] is not False
            or nested["evidence_receipt"] is not None
        ):
            raise ImageError(f"{label}.{field} must remain unverified HOLD")
    if (
        gate["status"] != CODEX_PACKAGE_STATUS
        or gate["literal_digest_absence_verified"] is not True
        or digests != EXPECTED_LEGACY_DESCRIPTOR_DIGESTS
    ):
        raise ImageError(f"{label} drifted")
    return gate


def validate_launcher_build_tool(
    value: object,
    label: str,
    role: str,
) -> Mapping[str, object]:
    tool = exact_mapping(
        value,
        {
            "schema",
            "role",
            "path",
            "bytes",
            "sha256",
            "mode",
            "uid",
            "gid",
            "link_count",
            "version",
            "target",
            "execution",
            "complete_recursive_toolchain_closure",
        },
        label,
    )
    execution = exact_mapping(
        tool["execution"],
        {
            "mechanism",
            "measured_before_first_execution",
            "all_invocations_used_same_open_file_description",
            "descriptor_and_path_stable_after_last_execution",
            "ambient_environment_inherited",
            "environment_allowlist",
        },
        f"{label}.execution",
    )
    path = tool["path"]
    mode = tool["mode"]
    version = tool["version"]
    if (
        tool["schema"] != LAUNCHER_BUILD_TOOL_SCHEMA
        or tool["role"] != role
        or not isinstance(path, str)
        or not 1 <= len(path.encode("utf-8")) <= 4096
        or not path.startswith("/")
        or "\x00" in path
        or any(part in {"", ".", ".."} for part in path.split("/")[1:])
        or bounded_int(tool["bytes"], f"{label}.bytes", 1, 1 << 30)
        != tool["bytes"]
        or lowercase_sha256(tool["sha256"], f"{label}.sha256")
        != tool["sha256"]
        or not isinstance(mode, str)
        or re.fullmatch(r"0[0-7]{3}", mode) is None
        or int(mode, 8) & 0o022
        or not int(mode, 8) & 0o100
        or isinstance(tool["uid"], bool)
        or not isinstance(tool["uid"], int)
        or tool["uid"] < 0
        or isinstance(tool["gid"], bool)
        or not isinstance(tool["gid"], int)
        or tool["gid"] < 0
        or tool["link_count"] != 1
        or not isinstance(version, str)
        or not 1 <= len(version.encode("utf-8")) <= 4096
        or "\x00" in version
        or tool["target"] != "aarch64-linux-gnu"
        or tool["complete_recursive_toolchain_closure"] is not False
        or execution
        != {
            "mechanism": "retained_open_file_description_via_proc_self_fd",
            "measured_before_first_execution": True,
            "all_invocations_used_same_open_file_description": True,
            "descriptor_and_path_stable_after_last_execution": True,
            "ambient_environment_inherited": False,
            "environment_allowlist": LAUNCHER_BUILD_ENVIRONMENT_ALLOWLIST,
        }
    ):
        raise ImageError(f"{label} custody is malformed")
    expected_identity = EXPECTED_LAUNCHER_BUILD_TOOL_IDENTITIES[role]
    if any(tool[field] != expected for field, expected in expected_identity.items()):
        raise ImageError(f"{label} differs from the frozen Mobian snapshot leaf")
    return tool


def validate_toolchain_snapshot_binding(
    value: object, label: str
) -> Mapping[str, object]:
    snapshot = exact_mapping(value, set(EXPECTED_TOOLCHAIN_SNAPSHOT_BINDING), label)
    if snapshot != EXPECTED_TOOLCHAIN_SNAPSHOT_BINDING:
        raise ImageError(f"{label} differs from the frozen Mobian snapshot")
    return snapshot


def validate_target_compiler_closure(
    value: object, label: str
) -> Mapping[str, object]:
    closure = exact_mapping(
        value,
        {
            "schema",
            "target",
            "normalized_search_arguments",
            "reported_sysroot",
            "components",
            "snapshot_tree_fully_remeasured_before_and_after_build",
            "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed",
            "complete_host_execution_runtime_closure",
        },
        label,
    )
    components = exact_mapping(
        closure["components"],
        set(EXPECTED_TARGET_COMPILER_COMPONENTS),
        f"{label}.components",
    )
    for role, expected in EXPECTED_TARGET_COMPILER_COMPONENTS.items():
        record = exact_mapping(
            components[role],
            {"relative_path", "bytes", "sha256", "mode"},
            f"{label}.components.{role}",
        )
        if record != expected:
            raise ImageError(
                f"{label}.components.{role} differs from the frozen Mobian snapshot"
            )
    if (
        closure["schema"]
        != "org.trillionnium.target-compiler-effective-closure.v1"
        or closure["target"] != "aarch64-linux-gnu"
        or closure["normalized_search_arguments"]
        != [
            "--sysroot=$TARGET_SYSROOT",
            "-B$TARGET_COMPILER_BIN",
            "-B$TARGET_GCC_LIBDIR",
            "-B$TARGET_BINUTILS_DIR",
        ]
        or closure["reported_sysroot"] != "$TARGET_SYSROOT"
        or closure["snapshot_tree_fully_remeasured_before_and_after_build"] is not True
        or closure[
            "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed"
        ]
        is not False
        or closure["complete_host_execution_runtime_closure"] is not False
    ):
        raise ImageError(f"{label} posture differs")
    return closure


def validate_claim_authority(
    value: object,
    label: str,
    expected: Mapping[str, object],
) -> Mapping[str, object]:
    authority = exact_mapping(value, set(expected), label)
    if authority != expected:
        raise ImageError(f"{label} overclaims downstream authority")
    return authority


def validate_common_build_evidence(
    value: object, label: str
) -> Mapping[str, object]:
    evidence = exact_mapping(
        value,
        {
            "compiler",
            "elf_inspector",
            "launcher_ab",
            "source_bom_claim_authority",
            "stable_principal_launcher_measurement",
            "toolchain_claim_authority",
            "upstream_receipt_target_compiler_closure_claim",
            "upstream_receipt_toolchain_snapshot_claim",
            "upstream_source_bom_receipt_claim",
        },
        label,
    )
    validate_launcher_build_tool(
        evidence["compiler"], f"{label}.compiler", "compiler_driver"
    )
    validate_launcher_build_tool(
        evidence["elf_inspector"], f"{label}.elf_inspector", "elf_inspector"
    )
    validate_target_compiler_closure(
        evidence["upstream_receipt_target_compiler_closure_claim"],
        f"{label}.upstream_receipt_target_compiler_closure_claim",
    )
    validate_toolchain_snapshot_binding(
        evidence["upstream_receipt_toolchain_snapshot_claim"],
        f"{label}.upstream_receipt_toolchain_snapshot_claim",
    )
    validate_claim_authority(
        evidence["toolchain_claim_authority"],
        f"{label}.toolchain_claim_authority",
        TOOLCHAIN_CLAIM_AUTHORITY,
    )
    validate_claim_authority(
        evidence["source_bom_claim_authority"],
        f"{label}.source_bom_claim_authority",
        SOURCE_BOM_CLAIM_AUTHORITY,
    )
    launcher_ab = exact_mapping(
        evidence["launcher_ab"],
        {
            "bytes",
            "compiler_and_elf_inspector_build_time_bytes_bound",
            "decision",
            "deterministic_artifact_set_ab_verified",
            "lane",
            "physical_source_bom_or_live_graph_remeasured_by_this_stage",
            "raw_elf_ab_receipt_id",
            "receipt_id",
            "release_status",
            "same_upstream_source_bom_receipt_claim",
            "schema",
            "sha256",
            "status",
        },
        f"{label}.launcher_ab",
    )
    if (
        bounded_int(launcher_ab["bytes"], f"{label}.launcher_ab.bytes", 1, 16 << 20)
        != launcher_ab["bytes"]
        or launcher_ab["compiler_and_elf_inspector_build_time_bytes_bound"]
        is not True
        or launcher_ab["decision"] != COMMON_LAUNCHER_AB_DECISION
        or launcher_ab["deterministic_artifact_set_ab_verified"] is not True
        or launcher_ab["lane"] != "common"
        or launcher_ab[
            "physical_source_bom_or_live_graph_remeasured_by_this_stage"
        ]
        is not False
        or not isinstance(launcher_ab["raw_elf_ab_receipt_id"], str)
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}", launcher_ab["raw_elf_ab_receipt_id"]
        )
        is None
        or not isinstance(launcher_ab["receipt_id"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", launcher_ab["receipt_id"])
        is None
        or launcher_ab["release_status"] != COMMON_LAUNCHER_AB_HOLD
        or launcher_ab["same_upstream_source_bom_receipt_claim"] is not True
        or launcher_ab["schema"] != COMMON_LAUNCHER_AB_SCHEMA
        or lowercase_sha256(
            launcher_ab["sha256"], f"{label}.launcher_ab.sha256"
        )
        != launcher_ab["sha256"]
        or launcher_ab["status"] != COMMON_LAUNCHER_AB_HOLD
    ):
        raise ImageError(f"{label}.launcher_ab custody is malformed")
    source_bom = exact_mapping(
        evidence["upstream_source_bom_receipt_claim"],
        {
            "authority",
            "bytes",
            "control_head",
            "file_sha256",
            "receipt_id",
            "resolved_manifest_sha256",
            "source_set_sha256",
        },
        f"{label}.upstream_source_bom_receipt_claim",
    )
    if (
        source_bom["authority"]
        != "local_exact_clean_graph_not_build_or_release_authority"
        or not isinstance(source_bom["control_head"], str)
        or re.fullmatch(r"[0-9a-f]{40,64}", source_bom["control_head"]) is None
        or not isinstance(source_bom["receipt_id"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", source_bom["receipt_id"]) is None
        or bounded_int(
            source_bom["bytes"],
            f"{label}.upstream_source_bom_receipt_claim.bytes",
            1,
            8 << 20,
        )
        != source_bom["bytes"]
        or any(
            lowercase_sha256(
                source_bom[field],
                f"{label}.upstream_source_bom_receipt_claim.{field}",
            )
            != source_bom[field]
            for field in (
                "file_sha256",
                "resolved_manifest_sha256",
                "source_set_sha256",
            )
        )
        or source_bom["source_set_sha256"] == "0" * 64
        or source_bom["resolved_manifest_sha256"] == "0" * 64
    ):
        raise ImageError(f"{label}.upstream_source_bom_receipt_claim drifted")
    stable = exact_mapping(
        evidence["stable_principal_launcher_measurement"],
        {
            "executable_identity_is_stable_registry_input",
            "launcher_executable_sha256",
            "launcher_identity_source",
            "stable_principal_canonical_sha256",
            "stable_principal_contract_sha256",
            "status",
        },
        f"{label}.stable_principal_launcher_measurement",
    )
    if (
        stable["status"] != "host_measurement_only_avb_slot_admission_absent"
        or stable["launcher_identity_source"]
        != "measured_after_closed_launcher_inputs"
        or stable["executable_identity_is_stable_registry_input"] is not False
        or stable["stable_principal_contract_sha256"]
        != STABLE_PRINCIPAL_CONTRACT_SHA256
        or stable["stable_principal_canonical_sha256"]
        != STABLE_PRINCIPAL_CANONICAL_SHA256
        or lowercase_sha256(
            stable["launcher_executable_sha256"],
            f"{label}.stable_principal_launcher_measurement.launcher_executable_sha256",
        )
        != stable["launcher_executable_sha256"]
    ):
        raise ImageError(f"{label}.stable-principal launcher measurement drifted")
    return evidence


def validate_common_builder_inputs(
    value: object, label: str
) -> Mapping[str, object]:
    inputs = exact_mapping(
        value,
        {
            "accessibility_tool_input_sha256",
            "codex_launcher_source_sha256",
            "codex_runtime_bytes",
            "codex_runtime_sha256",
            "daemon_input_sha256",
            "replay_sync_helper_input_sha256",
            "system_api_tool_input_sha256",
        },
        label,
    )
    if (
        bounded_int(
            inputs["codex_runtime_bytes"],
            f"{label}.codex_runtime_bytes",
            1,
            16 << 30,
        )
        != inputs["codex_runtime_bytes"]
        or any(
            lowercase_sha256(inputs[field], f"{label}.{field}") != inputs[field]
            for field in (
                "accessibility_tool_input_sha256",
                "codex_launcher_source_sha256",
                "codex_runtime_sha256",
                "daemon_input_sha256",
                "replay_sync_helper_input_sha256",
                "system_api_tool_input_sha256",
            )
        )
    ):
        raise ImageError(f"{label} is malformed")
    return inputs


def validate_common_launcher_ab_projection(
    value: object,
    expected_summary: Mapping[str, object],
    label: str,
) -> Mapping[str, object]:
    projection = exact_mapping(
        value,
        {
            "filename",
            "bytes",
            "sha256",
            "mode",
            "compiler_and_elf_inspector_build_time_bytes_bound",
            "decision",
            "deterministic_artifact_set_ab_verified",
            "lane",
            "physical_source_bom_or_live_graph_remeasured_by_this_stage",
            "raw_elf_ab_receipt_id",
            "receipt_id",
            "release_status",
            "same_upstream_source_bom_receipt_claim",
            "schema",
            "status",
        },
        label,
    )
    summary = {
        field: projection[field]
        for field in (
            "bytes",
            "compiler_and_elf_inspector_build_time_bytes_bound",
            "decision",
            "deterministic_artifact_set_ab_verified",
            "lane",
            "physical_source_bom_or_live_graph_remeasured_by_this_stage",
            "raw_elf_ab_receipt_id",
            "receipt_id",
            "release_status",
            "same_upstream_source_bom_receipt_claim",
            "schema",
            "sha256",
            "status",
        )
    }
    if (
        projection["filename"] != COMMON_LAUNCHER_AB_FILE
        or projection["mode"] != "0444"
        or summary != expected_summary
    ):
        raise ImageError(f"{label} custody or build-evidence projection drifted")
    return projection


def strict_regular(path: Path, label: str, expected_sha256: str | None) -> os.stat_result:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current = current / component
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ImageError(f"{label} contains a symlink component: {current}")
    info = absolute.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ImageError(f"{label} must be a regular file")
    if expected_sha256 is not None:
        if SHA256_RE.fullmatch(expected_sha256) is None:
            raise ImageError(f"{label} expected SHA-256 is malformed")
        if sha256_file(path) != expected_sha256:
            raise ImageError(f"{label} SHA-256 mismatch")
    return info


def output_available(path: Path, label: str) -> None:
    parent = path.absolute().parent
    current = Path(parent.anchor)
    for component in parent.parts[1:]:
        current = current / component
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ImageError(f"{label} parent is unsafe: {current}")
    if path.exists() or path.is_symlink():
        raise ImageError(f"{label} already exists")


def run(command: list[str]) -> bytes:
    try:
        return subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except subprocess.CalledProcessError as error:
        raise ImageError(
            f"{command[0]} failed: "
            + error.stderr.decode("utf-8", "replace")[-4000:]
        ) from error


def decompress(zstd: Path, source: Path, output: Path, maximum_bytes: int) -> None:
    process = subprocess.Popen(
        [str(zstd), "-q", "-d", "-c", str(source)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    total = 0
    try:
        with output.open("xb") as sink:
            for chunk in iter(lambda: process.stdout.read(1024 * 1024), b""):
                total += len(chunk)
                if total > maximum_bytes:
                    process.kill()
                    raise ImageError("decompressed rootfs exceeds the configured limit")
                sink.write(chunk)
            sink.flush()
            os.fsync(sink.fileno())
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        process.stdout.close()
    stderr = process.stderr.read() if process.stderr is not None else b""
    if process.wait() != 0:
        raise ImageError(
            "zstd decompression failed: " + stderr.decode("utf-8", "replace")[-2000:]
        )


def canonical_path(raw: str) -> str:
    if not raw or raw.startswith("/") or "\x00" in raw or "\\" in raw:
        raise ImageError(f"non-canonical tar path: {raw!r}")
    value = raw
    while value.startswith("./"):
        value = value[2:]
    value = value.rstrip("/")
    if not value or value == ".":
        return "."
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ImageError(f"non-canonical tar path: {raw!r}")
    return "/".join(parts)


def validate_link(path: str, target: str) -> None:
    if not target or target.startswith("/") or "\x00" in target or "\\" in target:
        raise ImageError(f"unsafe tar link: {path} -> {target!r}")
    parent = PurePosixPath(path).parent
    resolved = PurePosixPath(os.path.normpath((parent / target).as_posix()))
    if resolved == PurePosixPath("..") or resolved.as_posix().startswith("../"):
        raise ImageError(f"tar link escapes rootfs: {path} -> {target}")


def _android_staging_filter_octal(
    field: bytes,
    label: str,
    *,
    allow_blank: bool = False,
) -> int:
    """Parse one tar octal field with the pinned C filter's exact grammar."""

    if not field:
        raise ImageError(f"Android staging-filter {label} is empty")
    if field == bytes(len(field)):
        if allow_blank:
            return 0
        raise ImageError(f"Android staging-filter {label} is blank")
    index = 0
    while index < len(field) and field[index] == ord(" "):
        index += 1
    value = 0
    have_digit = False
    terminated = False
    maximum_before_octal_digit = ((1 << 64) - 1 - 7) // 8
    for byte in field[index:]:
        if ord("0") <= byte <= ord("7"):
            if terminated or value > maximum_before_octal_digit:
                raise ImageError(
                    f"Android staging-filter {label} has digits after termination "
                    "or exceeds the C octal bound"
                )
            value = value * 8 + byte - ord("0")
            have_digit = True
        elif byte in {0, ord(" ")}:
            terminated = True
        else:
            raise ImageError(f"Android staging-filter {label} is not octal")
    if not have_digit:
        raise ImageError(f"Android staging-filter {label} has no digits")
    return value


def _android_staging_filter_field(field: bytes, label: str) -> bytes:
    nul = field.find(b"\0")
    if nul < 0:
        return field
    if any(field[nul:]):
        raise ImageError(f"Android staging-filter {label} has a non-zero tail")
    return field[:nul]


def _android_staging_filter_checksum_valid(header: bytes) -> bool:
    if len(header) != ANDROID_STAGING_FILTER_TAR_BLOCK_BYTES:
        return False
    try:
        stored = _android_staging_filter_octal(header[148:156], "checksum")
    except ImageError:
        return False
    return stored == sum(header[:148]) + 8 * ord(" ") + sum(header[156:])


def _android_staging_filter_common_header(
    header: bytes,
) -> dict[str, object]:
    """Validate every physical common-header constraint enforced by the C filter."""

    if not _android_staging_filter_checksum_valid(header):
        raise ImageError("Android staging-filter header checksum is invalid")
    gnu = header[257:263] == b"ustar " and header[263:265] == b" \0"
    posix = header[257:263] == b"ustar\0" and header[263:265] == b"00"
    if not (gnu or posix):
        raise ImageError("Android staging-filter tar header is unsupported")
    parsed: dict[str, object] = {
        "mode": _android_staging_filter_octal(header[100:108], "mode"),
        "uid": _android_staging_filter_octal(header[108:116], "uid"),
        "gid": _android_staging_filter_octal(header[116:124], "gid"),
        "size": _android_staging_filter_octal(header[124:136], "size"),
        "mtime": _android_staging_filter_octal(header[136:148], "mtime"),
        "devmajor": _android_staging_filter_octal(
            header[329:337], "devmajor", allow_blank=True
        ),
        "devminor": _android_staging_filter_octal(
            header[337:345], "devminor", allow_blank=True
        ),
        "typeflag": header[156],
        "gnu": gnu,
    }
    _android_staging_filter_field(header[265:297], "uname")
    _android_staging_filter_field(header[297:329], "gname")
    if any(header[500:512]):
        raise ImageError("Android staging-filter header trailer padding is non-zero")
    if (
        int(parsed["mode"]) > 0o7777
        or parsed["uid"] != 0
        or parsed["gid"] != 0
        or parsed["devmajor"] != 0
        or parsed["devminor"] != 0
    ):
        raise ImageError(
            "Android staging-filter header ownership, mode, or device fields drifted"
        )
    return parsed


def _android_staging_filter_path_is_canonical(path: bytes) -> bool:
    if not path or path.startswith(b"/") or path.endswith(b"/"):
        return False
    if path == b".":
        return True
    for component in path.split(b"/"):
        if component in {b"", b".", b".."}:
            return False
        if any(byte < 0x20 or byte == 0x7F for byte in component):
            return False
    return True


def _android_staging_filter_member_path(header: bytes, typeflag: int) -> bytes:
    name = _android_staging_filter_field(header[0:100], "name")
    prefix = _android_staging_filter_field(header[345:500], "prefix")
    if not name:
        raise ImageError("Android staging-filter member name is empty")
    path = (prefix + b"/" if prefix else b"") + name
    if typeflag == ord("5") and path.endswith(b"/"):
        path = path[:-1]
    if not _android_staging_filter_path_is_canonical(path):
        raise ImageError("Android staging-filter member path is not canonical")
    return path


def _android_staging_filter_relative_link_is_contained(
    member: bytes, target: bytes
) -> bool:
    if not target or target.startswith(b"/") or target.endswith(b"/"):
        return False
    depth = member.count(b"/")
    for component in target.split(b"/"):
        if component in {b"", b"."}:
            return False
        if any(byte < 0x20 or byte == 0x7F for byte in component):
            return False
        if component == b"..":
            if depth == 0:
                return False
            depth -= 1
        else:
            depth += 1
    return True


def _android_staging_filter_directory_header(header: bytes) -> bytes:
    transformed = bytearray(header)
    transformed[100:108] = b"0000755\0"
    transformed[148:156] = b" " * 8
    checksum = sum(transformed)
    if checksum > 0o777777:
        raise ImageError("Android staging-filter checksum overflowed")
    encoded = f"{checksum:06o}".encode("ascii")
    if len(encoded) != 6:
        raise ImageError("Android staging-filter checksum encoding drifted")
    transformed[148:156] = encoded + b"\0 "
    result = bytes(transformed)
    if not _android_staging_filter_checksum_valid(result):
        raise ImageError("Android staging-filter checksum reproduction failed")
    return result


def reproduce_android_staging_filter(tar_path: Path) -> dict[str, object]:
    """Independently model the pinned C filter's complete accepted grammar."""

    block_size = ANDROID_STAGING_FILTER_TAR_BLOCK_BYTES
    digest = hashlib.sha256()
    output_bytes = 0
    header_count = 0
    directory_count = 0
    longlink_count = 0
    zero_block_count = 0
    trailer_started = False
    pending_longlink: tuple[bytes, bytes] | None = None
    with tar_path.open("rb") as source:
        while True:
            header = source.read(block_size)
            if not header:
                break
            if len(header) != block_size:
                raise ImageError("Android staging-filter saw a short tar block")
            if header == bytes(block_size):
                if pending_longlink is not None:
                    raise ImageError("Android staging-filter longlink is unterminated")
                zero_block_count += 1
                if zero_block_count >= 2:
                    trailer_started = True
                digest.update(header)
                output_bytes += block_size
                continue
            if trailer_started or zero_block_count:
                raise ImageError("Android staging-filter saw data after the trailer")
            header_count += 1
            if header_count > ANDROID_STAGING_FILTER_MAX_HEADER_COUNT:
                raise ImageError("Android staging-filter header count exceeds 10000")
            parsed = _android_staging_filter_common_header(header)
            mode = int(parsed["mode"])
            size = int(parsed["size"])
            typeflag = int(parsed["typeflag"])

            if typeflag == ord("K"):
                if (
                    pending_longlink is not None
                    or longlink_count
                    >= len(ANDROID_STAGING_FILTER_EXPECTED_GNU_LONGLINKS)
                    or parsed["gnu"] is not True
                    or _android_staging_filter_field(
                        header[0:100], "GNU longlink name"
                    )
                    != b"././@LongLink"
                    or mode != 0
                    or parsed["uid"] != 0
                    or parsed["gid"] != 0
                    or parsed["mtime"] != 0
                    or size <= 1
                    or size > ANDROID_STAGING_FILTER_MAX_GNU_LONGLINK_BYTES
                    or any(header[157:257])
                    or any(header[265:500])
                ):
                    raise ImageError("Android staging-filter longlink header drifted")
                expected_member_text, expected_target_text = (
                    ANDROID_STAGING_FILTER_EXPECTED_GNU_LONGLINKS[longlink_count]
                )
                expected_member = expected_member_text.encode("ascii")
                expected_target = expected_target_text.encode("ascii")
                payload = source.read(block_size)
                if (
                    len(payload) != block_size
                    or size != len(expected_target) + 1
                    or payload[:size] != expected_target + b"\0"
                    or any(payload[size:])
                ):
                    raise ImageError("Android staging-filter longlink payload drifted")
                digest.update(header)
                digest.update(payload)
                output_bytes += 2 * block_size
                pending_longlink = (expected_member, expected_target)
                continue

            path = _android_staging_filter_member_path(header, typeflag)
            link = _android_staging_filter_field(header[157:257], "linkname")
            if typeflag in {0, ord("0")}:
                valid_member = not link
            elif typeflag == ord("1"):
                valid_member = (
                    size == 0
                    and bool(link)
                    and link != b"."
                    and _android_staging_filter_path_is_canonical(link)
                )
            elif typeflag == ord("2"):
                valid_member = size == 0 and bool(link)
            elif typeflag == ord("5"):
                valid_member = size == 0 and mode == 0o555 and not link
            else:
                valid_member = False
            if not valid_member:
                raise ImageError(
                    "Android staging-filter member header is unsupported or invalid"
                )
            if pending_longlink is not None:
                expected_member, expected_target = pending_longlink
                if (
                    typeflag != ord("2")
                    or path != expected_member
                    or len(expected_target) < 100
                    or header[157:257] != expected_target[:100]
                    or not _android_staging_filter_relative_link_is_contained(
                        path, expected_target
                    )
                ):
                    raise ImageError("Android staging-filter longlink pair drifted")
                pending_longlink = None
                longlink_count += 1
            elif typeflag == ord("2") and not (
                _android_staging_filter_relative_link_is_contained(path, link)
            ):
                raise ImageError("Android staging-filter symlink target is unsafe")

            if typeflag == ord("5"):
                directory_count += 1
                output_header = _android_staging_filter_directory_header(header)
            else:
                output_header = header
            digest.update(output_header)
            output_bytes += block_size
            data_blocks = (size + block_size - 1) // block_size
            final_payload_bytes = size % block_size
            for index in range(data_blocks):
                data = source.read(block_size)
                if len(data) != block_size:
                    raise ImageError("Android staging-filter member data is truncated")
                if (
                    index + 1 == data_blocks
                    and final_payload_bytes
                    and any(data[final_payload_bytes:])
                ):
                    raise ImageError("Android staging-filter data padding drifted")
                digest.update(data)
                output_bytes += block_size

    if pending_longlink is not None or zero_block_count < 2:
        raise ImageError("Android staging-filter tar stream is incomplete")
    if directory_count != ANDROID_STAGING_FILTER_EXPECTED_DIRECTORY_COUNT:
        raise ImageError("Android staging-filter directory count drifted")
    if longlink_count != len(ANDROID_STAGING_FILTER_EXPECTED_GNU_LONGLINKS):
        raise ImageError("Android staging-filter longlink count drifted")
    return {
        "schema": ANDROID_STAGING_FILTER_SCHEMA,
        "source_sha256": ANDROID_STAGING_FILTER_SOURCE_SHA256,
        "bytes": output_bytes,
        "sha256": digest.hexdigest(),
    }


def validate_android_staging_filter_receipt(
    value: object,
    tar_path: Path,
    raw_tar_bytes: int,
) -> Mapping[str, object]:
    closure = exact_mapping(
        value,
        {"schema", "source_sha256", "bytes", "sha256"},
        "Codex rootfs Android staging-filter closure",
    )
    if (
        closure["schema"] != ANDROID_STAGING_FILTER_SCHEMA
        or closure["source_sha256"] != ANDROID_STAGING_FILTER_SOURCE_SHA256
        or bounded_int(
            closure["bytes"],
            "Codex rootfs Android staging-filter bytes",
            1,
            1 << 44,
        )
        != raw_tar_bytes
    ):
        raise ImageError("Codex rootfs Android staging-filter identity drifted")
    lowercase_sha256(
        closure["sha256"], "Codex rootfs Android staging-filter SHA-256"
    )
    reproduced = reproduce_android_staging_filter(tar_path)
    if dict(closure) != reproduced:
        raise ImageError(
            "Codex rootfs Android staging-filter receipt does not reproduce"
        )
    return closure


def inspect_normalized_tar(path: Path, epoch: int) -> dict[str, int]:
    seen: set[str] = set()
    regular_members: set[str] = set()
    members = 0
    regular_bytes = 0
    previous_sort_key: tuple[bool, bytes] | None = None
    with tarfile.open(path, "r:") as archive:
        if archive.pax_headers:
            raise ImageError("global PAX headers are forbidden")
        for member in archive:
            members += 1
            if members > 200_000:
                raise ImageError("rootfs has too many tar members")
            canonical = canonical_path(member.name)
            if member.name != canonical:
                raise ImageError(f"non-normalized tar path spelling: {member.name!r}")
            sort_key = (canonical != ".", canonical.encode("utf-8"))
            if previous_sort_key is not None and sort_key <= previous_sort_key:
                raise ImageError(f"rootfs tar order is not canonical: {canonical}")
            previous_sort_key = sort_key
            if canonical in seen:
                raise ImageError(f"duplicate rootfs tar member: {canonical}")
            if member.pax_headers:
                raise ImageError(f"PAX member headers are forbidden: {canonical}")
            if member.uid != 0 or member.gid != 0:
                raise ImageError(f"rootfs ownership is not 0:0: {canonical}")
            if member.uname or member.gname:
                raise ImageError(f"rootfs owner names are not empty: {canonical}")
            if member.mtime != epoch:
                raise ImageError(f"rootfs timestamp drift: {canonical}")
            mode = member.mode & 0o7777
            if member.isdir():
                if mode != 0o555 or member.size != 0:
                    raise ImageError(f"directory is not normalized 0555: {canonical}")
            elif member.isreg():
                if mode not in {0o444, 0o555}:
                    raise ImageError(f"regular file is not normalized read-only: {canonical}")
                if member.sparse is not None or member.size < 0:
                    raise ImageError(f"sparse or invalid regular member: {canonical}")
                regular_bytes += member.size
                if regular_bytes > 32 * 1024 * 1024 * 1024:
                    raise ImageError("rootfs regular bytes exceed 32 GiB")
                regular_members.add(canonical)
            elif member.issym():
                if mode != 0o777 or member.size != 0:
                    raise ImageError(f"symlink is not normalized 0777/zero: {canonical}")
                validate_link(canonical, member.linkname)
            elif member.islnk():
                if mode not in {0o444, 0o555} or member.size != 0:
                    raise ImageError(
                        f"hardlink is not normalized read-only/zero: {canonical}"
                    )
                target = canonical_path(member.linkname)
                if member.linkname != target or target not in regular_members:
                    raise ImageError(
                        f"hardlink target is not an earlier regular member: "
                        f"{canonical} -> {member.linkname}"
                    )
            else:
                raise ImageError(f"special tar member is forbidden: {canonical}")
            seen.add(canonical)
    if "." not in seen:
        raise ImageError("normalized rootfs tar lacks its root directory")
    return {"members": members, "regular_bytes": regular_bytes}


def verify_compiled_file_contexts(path: Path) -> dict[str, int]:
    content = path.read_bytes()
    if len(content) < 16:
        raise ImageError("compiled file_contexts is too short")
    magic, version = struct.unpack_from("<II", content, 0)
    if magic != SELINUX_COMPILED_FILE_CONTEXTS_MAGIC:
        raise ImageError("compiled file_contexts magic is invalid")
    if version != SELINUX_COMPILED_FILE_CONTEXTS_VERSION:
        raise ImageError("compiled file_contexts is not the reviewed v5 format")
    return {"magic": magic, "version": version, "bytes": len(content)}


def validate_codex_admission_manifest(
    path: Path, expected_sha256: str
) -> Mapping[str, object]:
    strict_regular(path, "Codex EROFS admission manifest", expected_sha256)
    manifest = strict_json_file(path, "Codex EROFS admission manifest")
    exact_mapping(
        manifest,
        {
            "schema",
            "archive_contract",
            "layout",
            "required_absence",
            "selinux",
            "size_targets",
            "admission",
        },
        "Codex EROFS admission manifest",
    )
    if manifest["schema"] != CODEX_ADMISSION_MANIFEST_SCHEMA:
        raise ImageError("Codex EROFS admission manifest schema drifted")

    archive_contract = exact_mapping(
        manifest["archive_contract"],
        {
            "contract_schema",
            "receipt_schema",
            "decision",
            "status",
            "release_allowed",
            "single_agent",
            "fresh_base_allowlist",
            "required_agent_manifest",
            "required_identity_independence_gate",
        },
        "Codex EROFS admission manifest.archive_contract",
    )
    if (
        archive_contract["receipt_schema"] != CODEX_PACKAGE_RECEIPT_SCHEMA
        or archive_contract["contract_schema"] != CODEX_PACKAGE_CONTRACT_SCHEMA
        or archive_contract["decision"] != CODEX_PACKAGE_DECISION
        or archive_contract["status"] != CODEX_PACKAGE_STATUS
        or archive_contract["release_allowed"] is not False
        or archive_contract["single_agent"] != "codex"
    ):
        raise ImageError("Codex package receipt identity drifted")
    validate_identity_independence_gate(
        archive_contract["required_identity_independence_gate"],
        "Codex EROFS required identity-independence gate",
    )
    allowlist = exact_mapping(
        archive_contract["fresh_base_allowlist"],
        {"path", "sha256"},
        "Codex EROFS admission manifest fresh-base allowlist",
    )
    if (
        allowlist["path"]
        != "packaging/root-linux/rootfs-fresh-minimal-bookworm-arm64.allowlist.v1.json"
        or lowercase_sha256(allowlist["sha256"], "fresh-base allowlist SHA-256")
        != sha256_file(FRESH_BASE_ALLOWLIST_PATH)
    ):
        raise ImageError("Codex admission does not bind the current fresh-base allowlist")
    required_agent = exact_mapping(
        archive_contract["required_agent_manifest"],
        {"agent_id", "enabled", "health", "peer_gid", "peer_uid", "selinux_domain"},
        "Codex EROFS required AgentManifest",
    )
    if required_agent != {
        "agent_id": "agent-codex-direct-v1",
        "enabled": False,
        "health": "disabled",
        "peer_gid": 5901,
        "peer_uid": 5901,
        "selinux_domain": "u:r:trillionnium_codex_agent:s0",
    }:
        raise ImageError("Codex EROFS required AgentManifest identity drifted")

    layout = exact_mapping(
        manifest["layout"],
        {
            "mount_point",
            "daemon_path",
            "codex_launcher_path_source",
            "codex_runtime_bind_placeholder_suffix",
            "android_effect_tool_paths",
            "runtime_mount_directories",
            "system_api_replay_sync_path",
        },
        "Codex EROFS admission manifest.layout",
    )
    if (
        layout["mount_point"] != FINAL_MOUNT_POINT
        or layout["daemon_path"] != "usr/bin/trillionniumd"
        or layout["codex_launcher_path_source"]
        != "receipt.inputs.codex_launcher.install_path"
        or layout["codex_runtime_bind_placeholder_suffix"] != ".real"
        or layout["android_effect_tool_paths"]
        != [
            "usr/local/bin/trillionnium-agent-accessibility",
            "usr/local/bin/trillionnium-agent-system-api",
        ]
        or layout["runtime_mount_directories"]
        != ["run/trillionnium", "tmp", "var/lib/trillionnium"]
        or layout["system_api_replay_sync_path"]
        != "usr/local/bin/trillionnium-system-api-replay-sync"
    ):
        raise ImageError("Codex EROFS runtime layout drifted")

    absence = exact_mapping(
        manifest["required_absence"],
        {
            "forbidden_package_names",
            "forbidden_path_prefixes",
            "local_llm_payloads",
            "node_runtime",
            "second_agent_principal_or_runtime",
        },
        "Codex EROFS required absence",
    )
    if any(
        absence[field] is not True
        for field in (
            "local_llm_payloads",
            "node_runtime",
            "second_agent_principal_or_runtime",
        )
    ):
        raise ImageError("Codex EROFS absence policy polarity drifted")
    if not all(
        isinstance(absence[field], list)
        and absence[field]
        and all(isinstance(item, str) and item for item in absence[field])
        for field in ("forbidden_package_names", "forbidden_path_prefixes")
    ):
        raise ImageError("Codex EROFS absence inventories are malformed")

    selinux = exact_mapping(
        manifest["selinux"],
        {
            "compiled_file_contexts_format",
            "critical_labels",
            "current_tar_materializer_applies_labels",
            "unlabelled_image_admission_allowed",
        },
        "Codex EROFS admission manifest.selinux",
    )
    compiled = exact_mapping(
        selinux["compiled_file_contexts_format"],
        {"magic", "version"},
        "Codex EROFS compiled file_contexts format",
    )
    if (
        compiled != {"magic": "0xf97cff8a", "version": 5}
        or selinux["current_tar_materializer_applies_labels"] is not False
        or selinux["unlabelled_image_admission_allowed"] is not False
    ):
        raise ImageError("Codex EROFS SELinux admission polarity drifted")
    critical_labels = selinux["critical_labels"]
    expected_critical_labels = [
        {
            "kind": "directory",
            "label": "u:object_r:trillionnium_proc_mountpoint_dir:s0",
            "path": "proc",
        },
        {
            "kind": "file",
            "label": "u:object_r:trillionnium_agentd_mountpoint_file:s0",
            "path": "usr/bin/trillionniumd",
        },
        {
            "kind": "file",
            "label": "u:object_r:trillionnium_codex_payload_file:s0",
            "path_source": "receipt.inputs.codex_launcher.install_path",
        },
        {
            "kind": "file",
            "label": "u:object_r:trillionnium_codex_runtime_exec:s0",
            "path_source": (
                "receipt.runtime_layout.codex_runtime_bind_placeholder"
            ),
        },
        {
            "kind": "file",
            "label": (
                "u:object_r:trillionnium_agent_accessibility_mountpoint_file:s0"
            ),
            "path": "usr/local/bin/trillionnium-agent-accessibility",
        },
        {
            "kind": "file",
            "label": "u:object_r:trillionnium_agent_system_api_mountpoint_file:s0",
            "path": "usr/local/bin/trillionnium-agent-system-api",
        },
        {
            "kind": "file",
            "label": (
                "u:object_r:trillionnium_agent_system_api_replay_sync_"
                "mountpoint_file:s0"
            ),
            "path": "usr/local/bin/trillionnium-system-api-replay-sync",
        },
        {
            "kind": "file",
            "label": "u:object_r:trillionnium_rootfs_loader_exec:s0",
            "path": "lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
        },
    ]
    if critical_labels != expected_critical_labels:
        raise ImageError("Codex EROFS critical SELinux label set drifted")

    targets = exact_mapping(
        manifest["size_targets"],
        {
            "base_installed_package_count",
            "base_rootfs_tar_zst_bytes",
            "final_rootfs_tar_zst_max_bytes",
            "final_erofs_max_bytes",
            "final_member_count_max",
            "final_regular_bytes_max",
        },
        "Codex EROFS admission manifest.size_targets",
    )
    if (
        targets["base_installed_package_count"] != 35
        or targets["base_rootfs_tar_zst_bytes"] != 10_959_228
    ):
        raise ImageError("Codex EROFS fresh-base size target drifted")
    for field in (
        "final_rootfs_tar_zst_max_bytes",
        "final_erofs_max_bytes",
        "final_member_count_max",
        "final_regular_bytes_max",
    ):
        bounded_int(targets[field], f"size_targets.{field}", 1, 1 << 42)

    admission = exact_mapping(
        manifest["admission"],
        {
            "decision",
            "status",
            "missing_gates",
            "android_package_wiring_allowed",
            "product_pin_refresh_allowed",
            "fsverity_enable_allowed",
            "device_write_allowed",
            "ota_or_release_allowed",
        },
        "Codex EROFS admission manifest.admission",
    )
    if (
        admission["decision"]
        != "HOLD_IDENTITY_INDEPENDENCE_AND_SOURCE_PREFLIGHT_ONLY"
        or admission["status"] != CODEX_PACKAGE_STATUS
        or any(
        admission[field] is not False
        for field in (
            "android_package_wiring_allowed",
            "product_pin_refresh_allowed",
            "fsverity_enable_allowed",
            "device_write_allowed",
            "ota_or_release_allowed",
        )
        )
    ):
        raise ImageError("Codex EROFS admission manifest overclaims authority")
    if admission["missing_gates"] != CODEX_PRODUCT_MISSING_GATES:
        raise ImageError("Codex EROFS admission HOLD blocker set drifted")
    return manifest


def tar_member_json(path: Path, member_name: str, label: str) -> Mapping[str, object]:
    with tarfile.open(path, "r:") as archive:
        try:
            member = archive.getmember(member_name)
        except KeyError as error:
            raise ImageError(f"{label} member is absent") from error
        if not member.isreg():
            raise ImageError(f"{label} member is not a regular file")
        source = archive.extractfile(member)
        if source is None:
            raise ImageError(f"{label} member cannot be read")
        content = source.read(1024 * 1024 + 1)
    if len(content) > 1024 * 1024:
        raise ImageError(f"{label} member exceeds its size bound")
    return strict_json_bytes(content, label)


def validate_codex_package_receipt(
    *,
    receipt_path: Path,
    expected_receipt_sha256: str,
    rootfs_path: Path,
    rootfs_info: os.stat_result,
    rootfs_sha256: str,
    tar_path: Path,
    archive: Mapping[str, int],
    source_date_epoch: int,
    admission_manifest: Mapping[str, object],
) -> dict[str, object]:
    receipt_info = strict_regular(
        receipt_path, "Codex rootfs package receipt", expected_receipt_sha256
    )
    if rootfs_info.st_nlink != 1 or stat.S_IMODE(rootfs_info.st_mode) != 0o444:
        raise ImageError("Codex rootfs archive must be single-link 0444")
    if receipt_info.st_nlink != 1 or stat.S_IMODE(receipt_info.st_mode) != 0o444:
        raise ImageError("Codex rootfs package receipt must be single-link 0444")
    receipt_content = receipt_path.read_bytes()
    receipt = strict_json_bytes(receipt_content, "Codex rootfs package receipt")
    exact_mapping(
        receipt,
        {
            "schema",
            "decision",
            "status",
            "release_allowed",
            "source_date_epoch",
            "admission",
            "common_build_evidence",
            "posture",
            "packager",
            "contract",
            "tools",
            "inputs",
            "limitations",
            "runtime_layout",
            "normalization",
            "security",
            "reproducibility",
            "output_rootfs",
            "receipt_id_scope",
            "receipt_id",
        },
        "Codex rootfs package receipt",
    )
    archive_contract = admission_manifest["archive_contract"]
    assert isinstance(archive_contract, dict)
    if (
        receipt["schema"] != archive_contract["receipt_schema"]
        or receipt["decision"] != archive_contract["decision"]
        or receipt["status"] != archive_contract["status"]
        or receipt["release_allowed"] is not False
        or receipt["source_date_epoch"] != source_date_epoch
        or receipt["receipt_id_scope"]
        != ROOTFS_RECEIPT_ID_SCOPE
    ):
        raise ImageError("Codex rootfs package receipt identity drifted")
    receipt_id = receipt["receipt_id"]
    if not isinstance(receipt_id, str) or not receipt_id.startswith("sha256:"):
        raise ImageError("Codex rootfs package receipt ID is malformed")
    unsigned = dict(receipt)
    unsigned.pop("receipt_id")
    if receipt_id != "sha256:" + hashlib.sha256(
        canonical_json_bytes(unsigned)
    ).hexdigest():
        raise ImageError("Codex rootfs package receipt self-hash is invalid")
    admission = exact_mapping(
        receipt["admission"],
        {"decision", "identity_independence_gate", "release_allowed", "status"},
        "Codex rootfs package admission",
    )
    if (
        admission["decision"] != CODEX_PACKAGE_DECISION
        or admission["status"] != CODEX_PACKAGE_STATUS
        or admission["release_allowed"] is not False
    ):
        raise ImageError("Codex rootfs package admission is not explicit HOLD")
    identity_gate = validate_identity_independence_gate(
        admission["identity_independence_gate"],
        "Codex rootfs package identity-independence gate",
    )
    if identity_gate != archive_contract["required_identity_independence_gate"]:
        raise ImageError("Codex rootfs package identity-independence gate drifted")
    common_build_evidence = validate_common_build_evidence(
        receipt["common_build_evidence"], "Codex rootfs package common build evidence"
    )
    if receipt["limitations"] != PACKAGE_LIMITATIONS:
        raise ImageError("Codex rootfs package limitations drifted")
    contract = exact_mapping(
        receipt["contract"],
        {"filename", "bytes", "sha256", "mode", "schema"},
        "Codex rootfs package contract descriptor",
    )
    if contract["schema"] != CODEX_PACKAGE_CONTRACT_SCHEMA:
        raise ImageError("Codex rootfs package contract schema drifted")

    posture = exact_mapping(
        receipt["posture"],
        {
            "host_only",
            "base_rootfs_mutated",
            "fresh_base_only",
            "archive_subtraction_or_hot_replacement_performed",
            "aosp_vendor_archive_touched",
            "device_write_performed",
            "ota_signing_performed",
            "public_release_allowed",
        },
        "Codex rootfs package receipt posture",
    )
    if posture != {
        "host_only": True,
        "base_rootfs_mutated": False,
        "fresh_base_only": True,
        "archive_subtraction_or_hot_replacement_performed": False,
        "aosp_vendor_archive_touched": False,
        "device_write_performed": False,
        "ota_signing_performed": False,
        "public_release_allowed": False,
    }:
        raise ImageError("Codex rootfs package receipt overclaims authority")

    inputs = exact_mapping(
        receipt["inputs"],
        {
            "base_rootfs",
            "fresh_base_provenance",
            "common_artifact_set_receipt",
            "common_launcher_ab_receipt",
            "daemon",
            "codex_launcher",
            "system_api_tool",
            "accessibility_tool",
            "system_api_replay_sync",
            "agent_manifest",
        },
        "Codex rootfs package receipt inputs",
    )
    fresh = exact_mapping(
        inputs["fresh_base_provenance"],
        {
            "allowlist",
            "builder",
            "build_contract",
            "receipt",
            "sbom",
            "snapshot_timestamp",
            "source_date_epoch",
            "package_count",
            "fresh_archive_exact_match",
            "archive_subtraction_or_hot_replacement_performed",
            "product_admission_allowed",
        },
        "Codex rootfs fresh-base provenance",
    )
    fresh_allowlist = exact_mapping(
        fresh["allowlist"],
        {"filename", "bytes", "sha256", "mode", "schema"},
        "Codex rootfs fresh-base allowlist descriptor",
    )
    admitted_allowlist = archive_contract["fresh_base_allowlist"]
    assert isinstance(admitted_allowlist, dict)
    if (
        fresh_allowlist["sha256"] != admitted_allowlist["sha256"]
        or fresh["package_count"] != 35
        or fresh["source_date_epoch"] != source_date_epoch
        or fresh["fresh_archive_exact_match"] is not True
        or fresh["archive_subtraction_or_hot_replacement_performed"] is not False
        or fresh["product_admission_allowed"] is not False
    ):
        raise ImageError("Codex rootfs fresh-base provenance drifted")

    output = exact_mapping(
        receipt["output_rootfs"],
        {
            "filename",
            "bytes",
            "sha256",
            "decompressed_tar_bytes",
            "decompressed_tar_sha256",
            "android_staging_filter",
            "member_count",
            "total_regular_bytes",
            "members",
        },
        "Codex rootfs package output",
    )
    if (
        output["bytes"] != rootfs_info.st_size
        or output["sha256"] != rootfs_sha256
        or output["decompressed_tar_bytes"] != tar_path.stat().st_size
        or output["decompressed_tar_sha256"] != sha256_file(tar_path)
        or output["member_count"] != archive["members"]
        or output["total_regular_bytes"] != archive["regular_bytes"]
    ):
        raise ImageError("Codex rootfs receipt does not bind the exact archive")
    validate_android_staging_filter_receipt(
        output["android_staging_filter"],
        tar_path,
        tar_path.stat().st_size,
    )
    targets = admission_manifest["size_targets"]
    assert isinstance(targets, dict)
    if (
        rootfs_info.st_size > int(targets["final_rootfs_tar_zst_max_bytes"])
        or archive["members"] > int(targets["final_member_count_max"])
        or archive["regular_bytes"] > int(targets["final_regular_bytes_max"])
    ):
        raise ImageError("Codex rootfs exceeds the admission size target")

    members = output["members"]
    if not isinstance(members, list) or len(members) != archive["members"]:
        raise ImageError("Codex rootfs receipt member inventory is incomplete")
    by_path: dict[str, Mapping[str, object]] = {}
    for index, item in enumerate(members):
        member = exact_mapping(
            item,
            (
                {"path", "type", "mode", "bytes", "sha256", "digest_scope"}
                if not isinstance(item, dict) or "link_target" not in item
                else {
                    "path",
                    "type",
                    "mode",
                    "bytes",
                    "sha256",
                    "digest_scope",
                    "link_target",
                }
            ),
            f"Codex rootfs receipt member {index}",
        )
        member_path = member["path"]
        if not isinstance(member_path, str) or member_path in by_path:
            raise ImageError("Codex rootfs receipt member path is malformed or duplicate")
        by_path[member_path] = member

    daemon = exact_mapping(
        inputs["daemon"],
        {"filename", "bytes", "sha256", "mode", "role", "install_path", "elf"},
        "Codex rootfs daemon input",
    )
    launcher = exact_mapping(
        inputs["codex_launcher"],
        {
            "filename",
            "bytes",
            "sha256",
            "mode",
            "role",
            "install_path",
            "codex_runtime_payload_packaged",
            "elf",
        },
        "Codex rootfs launcher input",
    )
    replay_sync = exact_mapping(
        inputs["system_api_replay_sync"],
        {"filename", "bytes", "sha256", "mode", "role", "install_path", "elf"},
        "Codex rootfs System API replay-sync input",
    )
    system_api_tool = exact_mapping(
        inputs["system_api_tool"],
        {
            "filename",
            "bytes",
            "sha256",
            "mode",
            "role",
            "install_path",
            "packaged",
            "elf",
        },
        "Codex rootfs System API tool input",
    )
    accessibility_tool = exact_mapping(
        inputs["accessibility_tool"],
        {
            "filename",
            "bytes",
            "sha256",
            "mode",
            "role",
            "install_path",
            "packaged",
            "elf",
        },
        "Codex rootfs Accessibility tool input",
    )
    common_receipt = exact_mapping(
        inputs["common_artifact_set_receipt"],
        {
            "filename",
            "bytes",
            "sha256",
            "mode",
            "artifact_bindings",
            "builder_inputs",
            "compiler",
            "device_execution_verified",
            "elf_inspector",
            "identity_independence_gate",
            "product_variant",
            "receipt_role",
            "release_allowed",
            "schema",
            "source_bom",
            "stable_principal_launcher_measurement",
            "status",
            "target_compiler_closure",
            "toolchain_snapshot",
        },
        "Codex rootfs common artifact-set receipt input",
    )
    if (
        common_receipt["filename"]
        != COMMON_ARTIFACT_SET_FILE
        or bounded_int(
            common_receipt["bytes"],
            "Codex common artifact-set receipt bytes",
            1,
            1 << 20,
        )
        != common_receipt["bytes"]
        or lowercase_sha256(
            common_receipt["sha256"],
            "Codex common artifact-set receipt SHA-256",
        )
        != common_receipt["sha256"]
        or common_receipt["mode"] != "0444"
        or common_receipt["schema"] != COMMON_ARTIFACT_SET_SCHEMA
        or common_receipt["status"] != COMMON_ARTIFACT_SET_STATUS
        or common_receipt["product_variant"] != "common"
        or common_receipt["receipt_role"]
        != "common_rootfs_complete_measured_build_input"
        or common_receipt["release_allowed"] is not False
        or common_receipt["device_execution_verified"] is not False
    ):
        raise ImageError("Codex common artifact-set receipt posture drifted")
    nested_common_build_evidence = validate_common_build_evidence(
        {
            "compiler": common_receipt["compiler"],
            "elf_inspector": common_receipt["elf_inspector"],
            "launcher_ab": common_build_evidence["launcher_ab"],
            "source_bom_claim_authority": dict(SOURCE_BOM_CLAIM_AUTHORITY),
            "stable_principal_launcher_measurement": common_receipt[
                "stable_principal_launcher_measurement"
            ],
            "toolchain_claim_authority": dict(TOOLCHAIN_CLAIM_AUTHORITY),
            "upstream_receipt_target_compiler_closure_claim": common_receipt[
                "target_compiler_closure"
            ],
            "upstream_receipt_toolchain_snapshot_claim": common_receipt[
                "toolchain_snapshot"
            ],
            "upstream_source_bom_receipt_claim": common_receipt["source_bom"],
        },
        "Codex common artifact-set build evidence",
    )
    nested_identity_gate = validate_identity_independence_gate(
        common_receipt["identity_independence_gate"],
        "Codex common artifact-set identity-independence gate",
    )
    if nested_common_build_evidence != common_build_evidence:
        raise ImageError("Codex rootfs common build evidence projection drifted")
    if nested_identity_gate != identity_gate:
        raise ImageError("Codex rootfs identity-independence gate projection drifted")
    common_builder_inputs = validate_common_builder_inputs(
        common_receipt["builder_inputs"],
        "Codex common artifact-set builder inputs",
    )
    launcher_ab_summary = common_build_evidence["launcher_ab"]
    assert isinstance(launcher_ab_summary, dict)
    common_launcher_ab = validate_common_launcher_ab_projection(
        inputs["common_launcher_ab_receipt"],
        launcher_ab_summary,
        "Codex rootfs common launcher A/B receipt input",
    )
    common_bindings = exact_mapping(
        common_receipt["artifact_bindings"],
        {
            "daemon",
            "codex_launcher",
            "system_api_tool",
            "accessibility_tool",
            "replay_sync_helper",
        },
        "Codex common artifact-set bindings",
    )
    physical_inputs = {
        "daemon": daemon,
        "codex_launcher": launcher,
        "system_api_tool": system_api_tool,
        "accessibility_tool": accessibility_tool,
        "replay_sync_helper": replay_sync,
    }
    for name, physical in physical_inputs.items():
        binding = exact_mapping(
            common_bindings[name],
            {"bytes", "file", "sha256"},
            f"Codex common artifact-set binding {name}",
        )
        if (
            binding["bytes"] != physical["bytes"]
            or binding["file"] != physical["filename"]
            or binding["sha256"] != physical["sha256"]
        ):
            raise ImageError(
                f"Codex common artifact-set physical binding drifted: {name}"
            )
    for input_field, artifact_name in {
        "daemon_input_sha256": "daemon",
        "replay_sync_helper_input_sha256": "replay_sync_helper",
        "system_api_tool_input_sha256": "system_api_tool",
        "accessibility_tool_input_sha256": "accessibility_tool",
    }.items():
        binding = common_bindings[artifact_name]
        assert isinstance(binding, dict)
        if common_builder_inputs[input_field] != binding["sha256"]:
            raise ImageError(
                "Codex common artifact-set builder input-to-artifact binding drifted"
            )
    stable_launcher = common_build_evidence["stable_principal_launcher_measurement"]
    assert isinstance(stable_launcher, dict)
    if stable_launcher["launcher_executable_sha256"] != launcher["sha256"]:
        raise ImageError(
            "Codex stable-principal launcher measurement is not physically bound"
        )
    agent_input = exact_mapping(
        inputs["agent_manifest"],
        {
            "filename",
            "bytes",
            "sha256",
            "mode",
            "install_path",
            "schema_valid",
            "identity_bound_to_codex",
        },
        "Codex rootfs AgentManifest input",
    )
    layout = exact_mapping(
        receipt["runtime_layout"],
        {
            "codex_runtime_bind_placeholder",
            "android_effect_tool_paths",
            "runtime_mount_directories",
            "placeholder_mode",
            "placeholder_bytes",
            "placeholder_payloads_present",
        },
        "Codex rootfs runtime layout",
    )
    admitted_layout = admission_manifest["layout"]
    assert isinstance(admitted_layout, dict)
    launcher_path = launcher["install_path"]
    if (
        daemon["role"] != "codex_agent_host_daemon"
        or daemon["install_path"] != admitted_layout["daemon_path"]
        or launcher["role"] != "measured_codex_integrity_launcher"
        or launcher["codex_runtime_payload_packaged"] is not False
        or not isinstance(launcher_path, str)
        or not launcher_path.startswith("usr/lib/trillionnium/agents/codex/")
        or not launcher_path.endswith("/bin/codex")
        or layout["codex_runtime_bind_placeholder"] != launcher_path + ".real"
        or layout["android_effect_tool_paths"]
        != admitted_layout["android_effect_tool_paths"]
        or layout["android_effect_tool_paths"]
        != [
            accessibility_tool["install_path"],
            system_api_tool["install_path"],
        ]
        or system_api_tool["role"] != "android_system_api_effect_tool"
        or system_api_tool["packaged"] is not True
        or accessibility_tool["role"] != "android_accessibility_effect_tool"
        or accessibility_tool["packaged"] is not True
        or layout["runtime_mount_directories"]
        != admitted_layout["runtime_mount_directories"]
        or replay_sync["role"] != "android_system_api_replay_synchronizer"
        or replay_sync["install_path"]
        != admitted_layout["system_api_replay_sync_path"]
        or layout["placeholder_mode"] != "0555"
        or layout["placeholder_bytes"] != 0
        or layout["placeholder_payloads_present"] is not False
    ):
        raise ImageError("Codex launcher/runtime layout receipt drifted")

    required_files = {
        str(daemon["install_path"]): str(daemon["sha256"]),
        str(launcher_path): str(launcher["sha256"]),
        str(system_api_tool["install_path"]): str(system_api_tool["sha256"]),
        str(accessibility_tool["install_path"]): str(
            accessibility_tool["sha256"]
        ),
        str(replay_sync["install_path"]): str(replay_sync["sha256"]),
        str(agent_input["install_path"]): str(agent_input["sha256"]),
    }
    for path, expected_sha256 in required_files.items():
        member = by_path.get(path)
        if (
            member is None
            or member["type"] != "file"
            or member["sha256"] != expected_sha256
        ):
            raise ImageError(f"Codex rootfs required payload member drifted: {path}")
    placeholders = [str(layout["codex_runtime_bind_placeholder"])]
    for path in placeholders:
        member = by_path.get(path)
        if (
            member is None
            or member["type"] != "file"
            or member["mode"] != "0555"
            or member["bytes"] != 0
            or member["sha256"] != hashlib.sha256(b"").hexdigest()
        ):
            raise ImageError(f"Codex rootfs bind placeholder drifted: {path}")
    for path in layout["runtime_mount_directories"]:
        member = by_path.get(str(path))
        if member is None or member["type"] != "directory":
            raise ImageError(f"Codex rootfs runtime mount directory is absent: {path}")

    absence = admission_manifest["required_absence"]
    assert isinstance(absence, dict)
    forbidden_prefixes = tuple(str(item) for item in absence["forbidden_path_prefixes"])
    violating_paths = sorted(
        path for path in by_path if any(path.startswith(prefix) for prefix in forbidden_prefixes)
    )
    if violating_paths:
        raise ImageError(
            "Codex rootfs contains a forbidden GUI/user path: " + violating_paths[0]
        )
    manifest_paths = sorted(
        path
        for path in by_path
        if path.startswith("etc/trillionnium/agents/")
        and by_path[path]["type"] == "file"
    )
    if manifest_paths != [agent_input["install_path"]]:
        raise ImageError("Codex rootfs must contain exactly one AgentManifest")
    agent_manifest = tar_member_json(
        tar_path, str(agent_input["install_path"]), "Codex AgentManifest"
    )
    required_agent = archive_contract["required_agent_manifest"]
    assert isinstance(required_agent, dict)
    for key, expected in required_agent.items():
        if agent_manifest.get(key) != expected:
            raise ImageError(f"Codex AgentManifest required field drifted: {key}")
    if agent_manifest.get("identity_key_sha256") != launcher["sha256"]:
        raise ImageError("Codex AgentManifest is not bound to the launcher")

    critical_labels = admission_manifest["selinux"]["critical_labels"]
    assert isinstance(critical_labels, list)
    critical_paths: list[dict[str, str]] = []
    for index, item in enumerate(critical_labels):
        if not isinstance(item, dict):
            raise ImageError(f"critical SELinux label {index} is malformed")
        path_source = item.get("path_source")
        if path_source == "receipt.inputs.codex_launcher.install_path":
            path = str(launcher_path)
        elif path_source == "receipt.runtime_layout.codex_runtime_bind_placeholder":
            path = str(layout["codex_runtime_bind_placeholder"])
        elif path_source is None and isinstance(item.get("path"), str):
            path = str(item["path"])
        else:
            raise ImageError(f"critical SELinux label {index} path source drifted")
        member = by_path.get(path)
        if member is None or member["type"] != item.get("kind"):
            raise ImageError(f"critical SELinux object is absent or wrong kind: {path}")
        label = item.get("label")
        if not isinstance(label, str) or not label.startswith("u:object_r:"):
            raise ImageError(f"critical SELinux label is malformed: {path}")
        critical_paths.append({"path": path, "kind": str(item["kind"]), "label": label})

    return {
        "admission": {
            "decision": CODEX_PACKAGE_DECISION,
            "identity_independence_gate": dict(identity_gate),
            "release_allowed": False,
            "status": CODEX_PACKAGE_STATUS,
        },
        "common_build_evidence": dict(common_build_evidence),
        "limitations": list(PACKAGE_LIMITATIONS),
        "package_receipt": {
            "bytes": receipt_info.st_size,
            "sha256": expected_receipt_sha256,
            "schema": receipt["schema"],
            "receipt_id": receipt_id,
        },
        "fresh_base": {
            "allowlist_sha256": fresh_allowlist["sha256"],
            "package_count": fresh["package_count"],
            "snapshot_timestamp": fresh["snapshot_timestamp"],
        },
        "codex_closure": {
            "common_artifact_set_receipt_sha256": common_receipt["sha256"],
            "common_launcher_ab_receipt_id": common_launcher_ab["receipt_id"],
            "common_launcher_ab_receipt_sha256": common_launcher_ab["sha256"],
            "common_launcher_ab_raw_elf_receipt_id": common_launcher_ab[
                "raw_elf_ab_receipt_id"
            ],
            "daemon_path": daemon["install_path"],
            "daemon_sha256": daemon["sha256"],
            "launcher_path": launcher_path,
            "launcher_sha256": launcher["sha256"],
            "system_api_tool_path": system_api_tool["install_path"],
            "system_api_tool_sha256": system_api_tool["sha256"],
            "accessibility_tool_path": accessibility_tool["install_path"],
            "accessibility_tool_sha256": accessibility_tool["sha256"],
            "system_api_replay_sync_path": replay_sync["install_path"],
            "system_api_replay_sync_sha256": replay_sync["sha256"],
            "agent_manifest_path": agent_input["install_path"],
            "runtime_bind_placeholder": layout["codex_runtime_bind_placeholder"],
            "android_effect_tool_paths": layout["android_effect_tool_paths"],
        },
        "critical_selinux_objects": critical_paths,
    }


def fsverity_digest(fsverity: Path, image: Path) -> str:
    output = run(
        [str(fsverity), "digest", "--hash-alg", "sha256", str(image)]
    ).decode("utf-8", "strict").strip()
    first = output.split()[0] if output else ""
    if not first.startswith("sha256:"):
        raise ImageError("fsverity digest output is malformed")
    digest = first.removeprefix("sha256:")
    if SHA256_RE.fullmatch(digest) is None:
        raise ImageError("fsverity digest output is malformed")
    return digest


def publish_file(path: Path, source: Path) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as destination, source.open(
            "rb"
        ) as input_file:
            shutil.copyfileobj(input_file, destination, length=1024 * 1024)
            destination.flush()
            os.fsync(destination.fileno())
    finally:
        os.close(descriptor)


def publish_bytes(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as destination:
            destination.write(content)
            destination.flush()
            os.fsync(destination.fileno())
    finally:
        os.close(descriptor)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=("host-base", "codex-product-preflight"),
        default="host-base",
    )
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--rootfs-sha256", required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    parser.add_argument("--zstd", type=Path, default=Path("/usr/bin/zstd"))
    parser.add_argument("--zstd-sha256", required=True)
    parser.add_argument("--mkfs-erofs", type=Path)
    parser.add_argument("--mkfs-erofs-sha256")
    parser.add_argument("--fsverity", type=Path)
    parser.add_argument("--fsverity-sha256")
    parser.add_argument("--work-parent", type=Path, required=True)
    parser.add_argument("--output-image", type=Path)
    parser.add_argument("--output-descriptor", type=Path)
    parser.add_argument("--rootfs-receipt", type=Path)
    parser.add_argument("--rootfs-receipt-sha256")
    parser.add_argument("--admission-manifest", type=Path)
    parser.add_argument("--admission-manifest-sha256")
    parser.add_argument("--compiled-file-contexts", type=Path)
    parser.add_argument("--compiled-file-contexts-sha256")
    parser.add_argument("--mount-point")
    parser.add_argument("--output-preflight-receipt", type=Path)
    parser.add_argument(
        "--maximum-decompressed-bytes",
        type=int,
        default=64 * 1024 * 1024 * 1024,
    )
    return parser.parse_args()


def require_mode_arguments(args: argparse.Namespace) -> None:
    host_arguments = {
        "mkfs-erofs": args.mkfs_erofs,
        "mkfs-erofs-sha256": args.mkfs_erofs_sha256,
        "fsverity": args.fsverity,
        "fsverity-sha256": args.fsverity_sha256,
        "output-image": args.output_image,
        "output-descriptor": args.output_descriptor,
    }
    preflight_arguments = {
        "rootfs-receipt": args.rootfs_receipt,
        "rootfs-receipt-sha256": args.rootfs_receipt_sha256,
        "admission-manifest": args.admission_manifest,
        "admission-manifest-sha256": args.admission_manifest_sha256,
        "compiled-file-contexts": args.compiled_file_contexts,
        "compiled-file-contexts-sha256": args.compiled_file_contexts_sha256,
        "mount-point": args.mount_point,
        "output-preflight-receipt": args.output_preflight_receipt,
    }
    required = host_arguments if args.mode == "host-base" else preflight_arguments
    forbidden = preflight_arguments if args.mode == "host-base" else host_arguments
    missing = sorted(name for name, value in required.items() if value is None)
    supplied_forbidden = sorted(
        name for name, value in forbidden.items() if value is not None
    )
    if missing:
        raise ImageError(
            f"{args.mode} is missing required arguments: " + ", ".join(missing)
        )
    if supplied_forbidden:
        raise ImageError(
            f"{args.mode} forbids arguments: " + ", ".join(supplied_forbidden)
        )
    if args.mode == "codex-product-preflight":
        assert args.admission_manifest is not None
        if (
            args.admission_manifest.resolve()
            != CODEX_ADMISSION_MANIFEST_PATH.resolve()
        ):
            raise ImageError(
                "codex-product-preflight requires the repository admission manifest"
            )
        if args.mount_point != FINAL_MOUNT_POINT:
            raise ImageError("Codex product mount point drifted")


def codex_preflight_receipt(
    *,
    args: argparse.Namespace,
    rootfs_info: os.stat_result,
    rootfs_sha256: str,
    tar_path: Path,
    archive: Mapping[str, int],
    admission_manifest: Mapping[str, object],
    admission_manifest_info: os.stat_result,
    compiled_contexts_info: os.stat_result,
    compiled_contexts_header: Mapping[str, int],
    package_facts: Mapping[str, object],
) -> dict[str, object]:
    admission = admission_manifest["admission"]
    assert isinstance(admission, dict)
    receipt: dict[str, object] = {
        "schema": CODEX_PREFLIGHT_SCHEMA,
        "decision": "HOLD_IDENTITY_INDEPENDENCE_AND_SELINUX_MATERIALIZER_UNAVAILABLE",
        "status": CODEX_PACKAGE_STATUS,
        "release_allowed": False,
        "reason": CODEX_PRODUCT_HOLD_REASON,
        "source_date_epoch": args.source_date_epoch,
        "mount_point": args.mount_point,
        "limitations": list(PREFLIGHT_LIMITATIONS),
        "source_rootfs": {
            "filename": args.rootfs.name,
            "bytes": rootfs_info.st_size,
            "sha256": rootfs_sha256,
            "decompressed_tar_bytes": tar_path.stat().st_size,
            "decompressed_tar_sha256": sha256_file(tar_path),
            **archive,
        },
        "validated_package": dict(package_facts),
        "upstream_admission": dict(package_facts["admission"]),
        "common_build_evidence": dict(package_facts["common_build_evidence"]),
        "admission_manifest": {
            "filename": args.admission_manifest.name,
            "bytes": admission_manifest_info.st_size,
            "sha256": args.admission_manifest_sha256,
            "schema": admission_manifest["schema"],
        },
        "compiled_file_contexts": {
            "filename": args.compiled_file_contexts.name,
            "bytes": compiled_contexts_info.st_size,
            "sha256": args.compiled_file_contexts_sha256,
            "magic": f"0x{compiled_contexts_header['magic']:08x}",
            "version": compiled_contexts_header["version"],
            "header_validated": True,
            "critical_labels_planned": package_facts[
                "critical_selinux_objects"
            ],
            "labels_applied_to_image": False,
            "security_selinux_xattrs_verified": False,
        },
        "posture": {
            "host_only_preflight": True,
            "image_emitted": False,
            "selinux_labels_applied": False,
            "fsverity_digest_computed": False,
            "fsverity_enable_performed": False,
            "android_package_wiring_performed": False,
            "product_pin_refresh_performed": False,
            "device_write_performed": False,
            "ota_signing_performed": False,
            "release_promotion_performed": False,
        },
        "blockers": list(admission["missing_gates"]),
        "receipt_id_scope": ROOTFS_RECEIPT_ID_SCOPE,
    }
    receipt["receipt_id"] = "sha256:" + hashlib.sha256(
        canonical_json_bytes(receipt)
    ).hexdigest()
    return receipt


def main() -> int:
    args = parse_args()
    require_mode_arguments(args)
    if not 1 <= args.source_date_epoch <= 4_102_444_800:
        raise ImageError("source-date-epoch is outside the supported range")
    if not 1 <= args.maximum_decompressed_bytes <= 64 * 1024 * 1024 * 1024:
        raise ImageError("maximum-decompressed-bytes is outside the supported range")
    rootfs_info = strict_regular(args.rootfs, "rootfs", args.rootfs_sha256)
    tool_specs = {"zstd": (args.zstd, args.zstd_sha256)}
    if args.mode == "host-base":
        tool_specs.update(
            {
                "mkfs_erofs": (args.mkfs_erofs, args.mkfs_erofs_sha256),
                "fsverity": (args.fsverity, args.fsverity_sha256),
            }
        )
    for label, (path, digest) in tool_specs.items():
        assert path is not None and digest is not None
        strict_regular(path, label, digest)
    if args.mode == "host-base":
        assert args.output_image is not None and args.output_descriptor is not None
        output_available(args.output_image, "output image")
        output_available(args.output_descriptor, "output descriptor")
    else:
        assert args.output_preflight_receipt is not None
        output_available(args.output_preflight_receipt, "output preflight receipt")

    work_parent = args.work_parent.absolute()
    if work_parent.is_symlink() or not work_parent.is_dir():
        raise ImageError("work parent must be a real existing directory")
    work: Path | None = None
    try:
        work = Path(
            tempfile.mkdtemp(prefix="trillionnium-rootfs-erofs.", dir=work_parent)
        )
        if work_parent.resolve() not in work.resolve().parents:
            raise ImageError("temporary work directory escaped its parent")
        tar_path = work / "rootfs.tar"
        decompress(
            args.zstd,
            args.rootfs,
            tar_path,
            args.maximum_decompressed_bytes,
        )
        archive = inspect_normalized_tar(tar_path, args.source_date_epoch)
        rootfs_sha256 = sha256_file(args.rootfs)
        if args.mode == "codex-product-preflight":
            assert args.rootfs_receipt is not None
            assert args.rootfs_receipt_sha256 is not None
            assert args.admission_manifest is not None
            assert args.admission_manifest_sha256 is not None
            assert args.compiled_file_contexts is not None
            assert args.compiled_file_contexts_sha256 is not None
            assert args.output_preflight_receipt is not None
            admission_manifest_info = strict_regular(
                args.admission_manifest,
                "Codex EROFS admission manifest",
                args.admission_manifest_sha256,
            )
            admission_manifest = validate_codex_admission_manifest(
                args.admission_manifest,
                args.admission_manifest_sha256,
            )
            compiled_contexts_info = strict_regular(
                args.compiled_file_contexts,
                "compiled file_contexts",
                args.compiled_file_contexts_sha256,
            )
            compiled_contexts_header = verify_compiled_file_contexts(
                args.compiled_file_contexts
            )
            package_facts = validate_codex_package_receipt(
                receipt_path=args.rootfs_receipt,
                expected_receipt_sha256=args.rootfs_receipt_sha256,
                rootfs_path=args.rootfs,
                rootfs_info=rootfs_info,
                rootfs_sha256=rootfs_sha256,
                tar_path=tar_path,
                archive=archive,
                source_date_epoch=args.source_date_epoch,
                admission_manifest=admission_manifest,
            )
            receipt = codex_preflight_receipt(
                args=args,
                rootfs_info=rootfs_info,
                rootfs_sha256=rootfs_sha256,
                tar_path=tar_path,
                archive=archive,
                admission_manifest=admission_manifest,
                admission_manifest_info=admission_manifest_info,
                compiled_contexts_info=compiled_contexts_info,
                compiled_contexts_header=compiled_contexts_header,
                package_facts=package_facts,
            )
            publish_bytes(args.output_preflight_receipt, json_bytes(receipt))
            print(f"decision={receipt['decision']}")
            print(f"receipt_id={receipt['receipt_id']}")
            return 3

        assert args.mkfs_erofs is not None
        assert args.fsverity is not None
        assert args.output_image is not None
        assert args.output_descriptor is not None
        image_uuid = uuid.uuid5(
            uuid.UUID("8f454f75-9689-5964-9348-8977f2f6ac76"),
            rootfs_sha256,
        )
        image = work / "rootfs.erofs"
        run(
            [
                str(args.mkfs_erofs),
                "-d0",
                f"-T{args.source_date_epoch}",
                "--all-time",
                f"-U{image_uuid}",
                "--all-root",
                "-L",
                "TRILLIONNIUM",
                "-zlz4hc,level=9",
                "--tar=f",
                str(image),
                str(tar_path),
            ]
        )
        image.chmod(0o444)
        digest = fsverity_digest(args.fsverity, image)
        descriptor = {
            "schema": SCHEMA,
            "source_rootfs": {
                "bytes": rootfs_info.st_size,
                "sha256": rootfs_sha256,
                **archive,
            },
            "erofs": {
                "bytes": image.stat().st_size,
                "sha256": sha256_file(image),
                "uuid": str(image_uuid),
                "label": "TRILLIONNIUM",
                "compression": "lz4hc,level=9",
                "source_date_epoch": args.source_date_epoch,
                "all_root": True,
                "read_only_filesystem_format": True,
            },
            "fsverity": {
                "algorithm": "sha256",
                "digest": digest,
                "host_digest_computed": True,
                "host_enable_performed": False,
                "product_enable_and_measure_required": True,
                "mount_before_enable_forbidden": True,
            },
            "tools": {
                label: {
                    "sha256": expected,
                    "path_basename": path.name,
                }
                for label, (path, expected) in tool_specs.items()
            },
            "product": {
                "classification": "host-base-only",
                "selinux_labels_applied": False,
                "codex_package_receipt_validated": False,
                "android_admission_allowed": False,
                "product_pin_refresh_performed": False,
                "android_package_wiring_performed": False,
                "device_write_performed": False,
                "ota_signing_performed": False,
                "release_promotion_performed": False,
            },
        }
        content = json_bytes(descriptor)
        publish_file(args.output_image, image)
        publish_bytes(args.output_descriptor, content)
        print(f"erofs_sha256={descriptor['erofs']['sha256']}")
        print(f"fsverity_sha256={digest}")
        return 0
    finally:
        if work is not None:
            resolved_parent = work_parent.resolve()
            resolved_work = work.resolve(strict=False)
            if resolved_parent in resolved_work.parents and resolved_work != resolved_parent:
                shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ImageError as error:
        print(f"immutable Root-Linux image denied: {error}", file=os.sys.stderr)
        raise SystemExit(2)
