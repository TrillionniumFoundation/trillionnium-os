#!/usr/bin/env python3
"""Aggregate two independently built Codex raw-ELF lanes without modifying them.

Both inputs must be canonical raw-ELF v3 host PASS receipts.  Every receipt
artifact is re-opened through its retained directory descriptor, matched in
both directions to the exact directory inventory, and compared byte-for-byte
across A/B.  Local tool and toolchain paths may differ, but the selected tool
bytes, SHA-256 identities, versions, modes, and all non-path build semantics
must agree.  Inputs are fully re-read before the one canonical aggregate
receipt is published.

This verifier does not build, copy, chmod, rename, or otherwise mutate either
input.  Its PASS is host-only; product, device, complete-toolchain, AVB, and OTA
admission remain HOLD.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Mapping, Sequence


RAW_SCHEMA = "org.trillionnium.codex-only-raw-elf-set.v3"
RAW_PASS = "PASS_HOST_ONLY_CODEX_RAW_ELF_SET"
RELEASE_HOLD = "HOLD_PRODUCT_DEVICE_AND_COMPLETE_TOOLCHAIN_ADMISSION"
AGGREGATE_SCHEMA = "org.trillionnium.codex-only-raw-elf-ab.v3"
AGGREGATE_PASS = "PASS_HOST_ONLY_DETERMINISTIC_CODEX_RAW_ELF_AB"
RECEIPT_ID_SCOPE = (
    "sha256(canonical-json-utf8-sort-keys-indent-2-lf-without-receipt_id)"
)
OUTPUT_NAME = "codex-only-raw-elf-ab.v3.json"
TARGET = "aarch64-unknown-linux-gnu"
SOURCE_BOM_SCHEMA = "org.trillionnium.local-cross-repo-source-bom.v2"
SOURCE_BOM_PASS = "PASS_LOCAL_EXACT_CLEAN_GRAPH"
MAX_RECEIPT_BYTES = 16 * 1024 * 1024
MAX_ELF_BYTES = 128 * 1024 * 1024
MAX_TOOL_BYTES = 128 * 1024 * 1024
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
LOWER_SHA1 = re.compile(r"[0-9a-f]{40}")
GLIBC_RE = re.compile(r"GLIBC_([0-9]+)\.([0-9]+)")
MAX_GLIBC = (2, 36)
TOOL_ROLES = ("cargo", "rustc", "host_linker", "linker", "ar", "readelf")
BASE_NEEDED = {"libgcc_s.so.1", "libc.so.6"}
PT_INTERP_LOADER = "ld-linux-aarch64.so.1"
STACK_CHK_GUARD_SYMBOL = "__stack_chk_guard@GLIBC_2.17"

ROOT_FIELDS = {
    "schema",
    "decision",
    "release_status",
    "lane",
    "variant",
    "target",
    "profile",
    "source_date_epoch",
    "source_bom",
    "build",
    "toolchain",
    "artifacts",
    "posture",
    "limitations",
    "receipt_id_scope",
    "receipt_id",
}
SOURCE_BOM_FIELDS = {
    "schema",
    "decision",
    "bytes",
    "sha256",
    "receipt_id",
    "source_set_sha256",
    "resolved_manifest_sha256",
    "live_full_remeasurement_before_and_after_build",
    "byte_equal_to_each_live_remeasurement",
    "authority",
}
BUILD_FIELDS = {
    "commands",
    "locked",
    "offline",
    "no_default_features",
    "jobs",
    "incremental",
    "fresh_private_target_directory",
    "path_remapping",
    "p01_compile_variant",
    "target_native_compile_flags",
}
TOOLCHAIN_FIELDS = {
    "boundary",
    "cargo_home",
    "rust_toolchain_root",
    "rust_target_libdir",
    "target_toolchain_root",
    "host_toolchain_root",
    "target_sysroot",
    "target_search_prefixes",
    "snapshot_manifest",
    "resolved_components",
    "executables",
    "input_remeasurement_after_build_required",
    "snapshot_tree_fully_remeasured_before_and_after_build",
    "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed",
    "complete_release_toolchain_closure",
}
TARGET_SEARCH_PREFIX_FIELDS = {
    "compiler_bin",
    "gcc_libdir",
    "binutils_dir",
    "host_runtime_libdir",
}
SNAPSHOT_MANIFEST_FIELDS = {
    "schema",
    "manifest_schema",
    "manifest_sha256",
    "manifest_bytes",
    "manifest_id",
    "tree_digest",
    "entry_count",
    "regular_bytes",
    "closed_world",
    "target_sysroot_relative_path",
    "target_compiler_relative_path",
    "target_compiler_bin_relative_path",
    "target_gcc_libdir_relative_path",
    "target_binutils_relative_path",
    "target_host_runtime_libdir_relative_path",
}
RESOLVED_COMPONENTS = {
    "ld",
    "as",
    "cc1",
    "collect2",
    "Scrt1.o",
    "crtbeginS.o",
    "libc.so",
    "libgcc_s.so.1",
    "libgcc.a",
}
RESOLVED_COMPONENT_FIELDS = {"relative_path", "bytes", "sha256", "mode"}
EXPECTED_RESOLVED_COMPONENTS = {
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
TOOL_FIELDS = {"path", "bytes", "sha256", "mode", "version"}
ARTIFACT_FIELDS = {
    "file",
    "bytes",
    "sha256",
    "mode",
    "link_count",
    "hardening",
    "lane_markers_verified",
    "unremapped_host_paths_absent",
    "retired_agent_identity_absent",
}
HARDENING_FIELDS = {
    "elf_class",
    "endianness",
    "machine",
    "type",
    "interpreter",
    "gnu_relro",
    "bind_now",
    "gnu_stack_executable",
    "writable_executable_load_segment",
    "rpath_or_runpath",
    "text_relocations",
    "debug_sections",
    "needed",
    "aarch64_stack_protector_guard",
    "required_glibc_versions",
    "maximum_glibc",
    "gnu_build_id_sha1",
}
STACK_GUARD_FIELDS = {
    "loader_dt_needed",
    "undefined_dynamic_symbol",
    "version",
    "version_provider",
    "loader_bound_undefined_symbols",
}
POSTURE = {
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
}
TOOLCHAIN_BOUNDARY = (
    "exact_selected_executables_retained_from_initial_measurement_through_"
    "query_build_and_inspection_via_proc_self_fd_and_reported_sysroots; "
    "the_bound_Mobian_snapshot_is_manifest_closed_and_fully_remeasured_"
    "before_and_after_build; host_kernel_process_interpreter_fallback_"
    "glibc_libm_libz_and_Rust_Cargo_source_closure_are_not_fully_attested"
)
LIMITATIONS = [
    "cargo_home_and_rust_target_source_trees_are_explicit_but_not_recursively_byte_closed",
    "closed_world_mobian_toolchain_snapshot_is_manifest_bound_and_fully_remeasured_before_and_after_build",
    "host_process_interpreter_and_fallback_glibc_libm_libz_are_not_byte_closed",
    "host_kernel_and_filesystem_snapshot_are_not_attested",
    "source_measurement_python_and_git_runtime_dependencies_are_not_byte_closed",
    "shell_or_env_tool_wrappers_are_rejected_until_their_interpreter_utility_tcb_is_closed",
    "two_boundary_source_remeasurement_cannot_exclude_transient_between-boundary_mutation",
    "no_launcher_rootfs_android_device_avb_or_ota_evidence",
]
EXPECTED_SNAPSHOT_MANIFEST = {
    "schema": "org.trillionnium.packaging.mobian-toolchain-snapshot-binding.v1",
    "manifest_schema": (
        "org.trillionnium.packaging.mobian-toolchain-snapshot-manifest.v1"
    ),
    "manifest_sha256": (
        "735fab7c0ded3d37e53ac8295c32e7a3a1547ba54e603e74f25e83de2f8c541f"
    ),
    "manifest_bytes": 8_375_893,
    "manifest_id": (
        "d3ef19017ab4499243936ff65db4d2b50fce1536a9127f2d7ea3e7468784ebb4"
    ),
    "tree_digest": (
        "6335b8cb911852156b10eec32ba08d9730b51a8ca0b0b04abfefa0b6ef7a4367"
    ),
    "entry_count": 33_930,
    "regular_bytes": 1_952_702_440,
    "closed_world": True,
    "target_sysroot_relative_path": "toolchain/sysroot",
    "target_compiler_relative_path": (
        "toolchain/sysroot/usr/bin/aarch64-linux-gnu-gcc-12"
    ),
    "target_compiler_bin_relative_path": "toolchain/sysroot/usr/bin",
    "target_gcc_libdir_relative_path": (
        "toolchain/sysroot/usr/lib/gcc-cross/aarch64-linux-gnu/12"
    ),
    "target_binutils_relative_path": "toolchain/sysroot/usr/aarch64-linux-gnu/bin",
    "target_host_runtime_libdir_relative_path": (
        "toolchain/sysroot/usr/lib/x86_64-linux-gnu"
    ),
}
EXPECTED_TARGET_TOOL_IDENTITIES = {
    "linker": {
        "bytes": 1_315_296,
        "sha256": "c7b8890354c8ddc0364addfeb8968597e197627bd1e338fb6ed705b578803846",
        "mode": "0555",
        "version": (
            "aarch64-linux-gnu-gcc-12 (Debian 12.2.0-14) 12.2.0\n"
            "Copyright (C) 2022 Free Software Foundation, Inc.\n"
            "This is free software; see the source for copying conditions.  There is NO\n"
            "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."
        ),
    },
    "ar": {
        "bytes": 68_920,
        "sha256": "086da15d802a53c33c0aeccfb2de663f724edab8fdca7e10b242cfefe24673dc",
        "mode": "0555",
        "version": (
            "GNU ar (GNU Binutils for Debian) 2.40\n"
            "Copyright (C) 2023 Free Software Foundation, Inc.\n"
            "This program is free software; you may redistribute it under the terms of\n"
            "the GNU General Public License version 3 or (at your option) any later version.\n"
            "This program has absolutely no warranty."
        ),
    },
    "readelf": {
        "bytes": 802_144,
        "sha256": "716843c4034e24fa7d8e7d2a590dd1645aebf2b87ddc3a888144923174b2a562",
        "mode": "0555",
        "version": (
            "GNU readelf (GNU Binutils for Debian) 2.40\n"
            "Copyright (C) 2023 Free Software Foundation, Inc.\n"
            "This program is free software; you may redistribute it under the terms of\n"
            "the GNU General Public License version 3 or (at your option) any later version.\n"
            "This program has absolutely no warranty."
        ),
    },
}

LANES: Mapping[str, dict[str, object]] = {
    "common": {
        "variant": "common_inert_no_default_features",
        "receipt": "codex-only-raw-elf-set.common.v3.json",
        "artifacts": {
            "system_api_tool": "trillionnium-agent-system-api",
            "accessibility_tool": "trillionnium-agent-accessibility",
            "replay_sync_helper": "trillionnium-system-api-replay-sync",
            "daemon": "trillionniumd",
        },
        "commands": [
            [
                "$CARGO",
                "build",
                "--locked",
                "--offline",
                "--quiet",
                "--release",
                "--target",
                TARGET,
                "--no-default-features",
                "--package",
                "trillionnium-agent-direct-tools",
                "--bin",
                "trillionnium-agent-system-api",
                "--bin",
                "trillionnium-agent-accessibility",
                "--bin",
                "trillionnium-system-api-replay-sync",
            ],
            [
                "$CARGO",
                "build",
                "--locked",
                "--offline",
                "--quiet",
                "--release",
                "--target",
                TARGET,
                "--no-default-features",
                "--package",
                "trillionniumd",
                "--bin",
                "trillionniumd",
            ],
        ],
        "p01_compile_variant": None,
    },
    "p01_userdebug_pre_daemon": {
        "variant": "non_product_userdebug_settings_only_pre_daemon",
        "receipt": "codex-only-raw-elf-set.p01-userdebug-pre-daemon.v3.json",
        "artifacts": {
            "system_api_tool": "trillionnium-agent-system-api-device-conformance",
            "replay_sync_helper": (
                "trillionnium-system-api-device-conformance-replay-sync"
            ),
            "high_water_authority": (
                "trillionnium-direct-operation-custody-high-water"
            ),
        },
        "commands": [
            [
                "$CARGO",
                "build",
                "--locked",
                "--offline",
                "--quiet",
                "--release",
                "--target",
                TARGET,
                "--no-default-features",
                "--package",
                "trillionnium-agent-direct-tools",
                "--bin",
                "trillionnium-agent-system-api-device-conformance",
                "--bin",
                "trillionnium-system-api-device-conformance-replay-sync",
                "--features",
                "device-launch-package-conformance",
            ],
            [
                "$CARGO",
                "build",
                "--locked",
                "--offline",
                "--quiet",
                "--release",
                "--target",
                TARGET,
                "--no-default-features",
                "--package",
                "trillionnium-agent-privilege-broker",
                "--bin",
                "trillionnium-direct-operation-custody-high-water",
                "--features",
                "p0-launch-package-device-conformance",
            ],
        ],
        "p01_compile_variant": "userdebug",
    },
}


class AggregateError(RuntimeError):
    """An input receipt, physical artifact, or A/B invariant failed."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json_bytes(value: object) -> bytes:
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


def exact_object(value: object, fields: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise AggregateError(f"{label} schema is not closed")
    return value


def strict_json(raw: bytes, label: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise AggregateError(f"{label} contains duplicate key {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda item: (_ for _ in ()).throw(
                AggregateError(f"{label} contains non-finite number {item}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise AggregateError(f"{label} is not strict UTF-8 JSON") from error
    if type(value) is not dict:
        raise AggregateError(f"{label} must be an object")
    return value


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


def device_inode(identity: Sequence[int] | os.stat_result) -> tuple[int, int]:
    if isinstance(identity, os.stat_result):
        return (identity.st_dev, identity.st_ino)
    return (identity[0], identity[1])


def stable_directory_identity(
    metadata: os.stat_result, *, leaf: bool
) -> tuple[int, ...]:
    if leaf:
        return stable_identity(metadata)
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
    )


class RetainedAbsoluteDirectory:
    """Component-wise no-follow custody for one canonical absolute directory."""

    def __init__(
        self,
        path: Path,
        label: str,
        descriptors: list[int],
        metadata: list[os.stat_result],
        component_names: list[str],
        relax_leaf_content_changes: bool,
    ) -> None:
        self.path = path
        self.label = label
        self.descriptors = descriptors
        self.metadata = metadata
        self.component_names = component_names
        self.relax_leaf_content_changes = relax_leaf_content_changes

    @classmethod
    def open(
        cls,
        path: Path,
        label: str,
        *,
        relax_leaf_content_changes: bool = False,
    ) -> "RetainedAbsoluteDirectory":
        value = os.fspath(path)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if (
            not path.is_absolute()
            or os.path.normpath(value) != value
            or not nofollow
            or not hasattr(os, "O_DIRECTORY")
            or len(path.parts) < 2
            or any(part in {"", ".", ".."} for part in path.parts[1:])
        ):
            raise AggregateError(
                f"{label} path is not canonical or component-wise no-follow capable"
            )
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | nofollow
        descriptors: list[int] = []
        metadata: list[os.stat_result] = []
        component_names: list[str] = []
        try:
            descriptor = os.open(path.anchor, flags)
            descriptors.append(descriptor)
            metadata.append(os.fstat(descriptor))
            for component in path.parts[1:]:
                try:
                    lexical = os.stat(
                        component,
                        dir_fd=descriptors[-1],
                        follow_symlinks=False,
                    )
                except OSError as error:
                    raise AggregateError(
                        f"{label} component is unavailable"
                    ) from error
                if not stat.S_ISDIR(lexical.st_mode):
                    raise AggregateError(
                        f"{label} contains a symbolic link or non-directory component"
                    )
                try:
                    descriptor = os.open(component, flags, dir_fd=descriptors[-1])
                except OSError as error:
                    raise AggregateError(
                        f"{label} component cannot be opened without following links"
                    ) from error
                opened = os.fstat(descriptor)
                leaf = len(component_names) + 1 == len(path.parts) - 1
                strict_leaf = leaf and not relax_leaf_content_changes
                if stable_directory_identity(
                    opened, leaf=strict_leaf
                ) != stable_directory_identity(lexical, leaf=strict_leaf):
                    os.close(descriptor)
                    raise AggregateError(f"{label} component changed while opened")
                descriptors.append(descriptor)
                metadata.append(opened)
                component_names.append(component)
            result = cls(
                path,
                label,
                descriptors,
                metadata,
                component_names,
                relax_leaf_content_changes,
            )
            result.assert_stable()
            return result
        except Exception:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
            raise

    @property
    def descriptor(self) -> int:
        return self.descriptors[-1]

    @property
    def initial_metadata(self) -> os.stat_result:
        return self.metadata[-1]

    def assert_stable(self) -> None:
        for index, (descriptor, expected) in enumerate(
            zip(self.descriptors, self.metadata, strict=True)
        ):
            held = os.fstat(descriptor)
            leaf = index == len(self.descriptors) - 1
            strict_leaf = leaf and not self.relax_leaf_content_changes
            if stable_directory_identity(
                held, leaf=strict_leaf
            ) != stable_directory_identity(expected, leaf=strict_leaf):
                raise AggregateError(f"{self.label} retained directory changed")
            if index == 0:
                continue
            try:
                current = os.stat(
                    self.component_names[index - 1],
                    dir_fd=self.descriptors[index - 1],
                    follow_symlinks=False,
                )
            except OSError as error:
                raise AggregateError(
                    f"{self.label} retained pathname disappeared"
                ) from error
            if stable_directory_identity(
                current, leaf=strict_leaf
            ) != stable_directory_identity(expected, leaf=strict_leaf):
                raise AggregateError(f"{self.label} retained pathname changed")

    def close(self) -> None:
        for descriptor in reversed(self.descriptors):
            os.close(descriptor)
        self.descriptors.clear()


class RetainedAbsoluteTargetTool:
    """Retain a target tool and every directory used to reach it."""

    def __init__(
        self,
        path: Path,
        label: str,
        parent: RetainedAbsoluteDirectory,
        descriptor: int,
        metadata: os.stat_result,
        initial_bytes: bytes,
    ) -> None:
        self.path = path
        self.label = label
        self.parent = parent
        self.descriptor = descriptor
        self.initial_metadata = metadata
        self.initial_bytes = initial_bytes

    @classmethod
    def open(
        cls,
        path: Path,
        record: dict[str, object],
        label: str,
    ) -> "RetainedAbsoluteTargetTool":
        value = os.fspath(path)
        if (
            not path.is_absolute()
            or os.path.normpath(value) != value
            or path.name in {"", ".", ".."}
        ):
            raise AggregateError(f"{label} path is not canonical and absolute")
        parent = RetainedAbsoluteDirectory.open(path.parent, f"{label} parent")
        descriptor = -1
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent.descriptor,
            )
            before = os.fstat(descriptor)
            mode = stat.S_IMODE(before.st_mode)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or not 1 <= before.st_size <= MAX_TOOL_BYTES
                or mode & 0o022
                or not mode & 0o100
            ):
                raise AggregateError(
                    f"{label} must be one bounded non-writable executable regular file"
                )
            chunks: list[bytes] = []
            observed = 0
            while observed <= MAX_TOOL_BYTES:
                chunk = os.read(
                    descriptor,
                    min(1024 * 1024, MAX_TOOL_BYTES + 1 - observed),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                observed += len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
            if observed != before.st_size or stable_identity(before) != stable_identity(after):
                raise AggregateError(f"{label} changed while read")
            current = os.stat(
                path.name,
                dir_fd=parent.descriptor,
                follow_symlinks=False,
            )
            if stable_identity(current) != stable_identity(before):
                raise AggregateError(f"{label} pathname changed while read")
            if (
                len(raw) != record["bytes"]
                or sha256_bytes(raw) != record["sha256"]
                or f"{mode:04o}" != record["mode"]
            ):
                raise AggregateError(f"{label} differs from its receipt identity")
            result = cls(path, label, parent, descriptor, before, raw)
            result.assert_stable()
            return result
        except Exception:
            if descriptor >= 0:
                os.close(descriptor)
            parent.close()
            raise

    def assert_stable(self) -> None:
        self.parent.assert_stable()
        held = os.fstat(self.descriptor)
        try:
            current = os.stat(
                self.path.name,
                dir_fd=self.parent.descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise AggregateError(f"{self.label} retained pathname disappeared") from error
        if (
            stable_identity(held) != stable_identity(self.initial_metadata)
            or stable_identity(current) != stable_identity(self.initial_metadata)
        ):
            raise AggregateError(f"{self.label} retained pathname changed")

    def close(self) -> None:
        os.close(self.descriptor)
        self.parent.close()


class RetainedPublishedFile:
    """One aggregate receipt held through final pathname/content validation."""

    def __init__(
        self,
        directory: int,
        name: str,
        descriptor: int,
        metadata: os.stat_result,
        initial_bytes: bytes,
    ) -> None:
        self.directory = directory
        self.name = name
        self.descriptor = descriptor
        self.initial_metadata = metadata
        self.initial_bytes = initial_bytes

    @staticmethod
    def _read_exact(descriptor: int, maximum: int) -> bytes:
        chunks: list[bytes] = []
        offset = 0
        while offset <= maximum:
            chunk = os.pread(
                descriptor,
                min(1024 * 1024, maximum + 1 - offset),
                offset,
            )
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
        return b"".join(chunks)

    def assert_stable(self) -> None:
        if self.descriptor < 0:
            raise AggregateError("published aggregate receipt is already closed")
        held_before = os.fstat(self.descriptor)
        held_bytes = self._read_exact(self.descriptor, len(self.initial_bytes))
        held_after = os.fstat(self.descriptor)
        try:
            current = os.stat(
                self.name,
                dir_fd=self.directory,
                follow_symlinks=False,
            )
            reopened = os.open(
                self.name,
                os.O_RDONLY
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=self.directory,
            )
        except OSError as error:
            raise AggregateError("published aggregate receipt pathname changed") from error
        try:
            reopened_before = os.fstat(reopened)
            reopened_bytes = self._read_exact(reopened, len(self.initial_bytes))
            reopened_after = os.fstat(reopened)
        finally:
            os.close(reopened)
        expected = stable_identity(self.initial_metadata)
        if (
            stable_identity(held_before) != expected
            or stable_identity(held_after) != expected
            or stable_identity(current) != expected
            or stable_identity(reopened_before) != expected
            or stable_identity(reopened_after) != expected
            or held_bytes != self.initial_bytes
            or reopened_bytes != self.initial_bytes
            or stat.S_IMODE(current.st_mode) != 0o444
        ):
            raise AggregateError(
                "published aggregate receipt descriptor, pathname, or bytes changed"
            )

    def close(self) -> None:
        if self.descriptor >= 0:
            descriptor = self.descriptor
            self.descriptor = -1
            os.close(descriptor)

    def unlink_if_current(self) -> None:
        try:
            current = os.stat(
                self.name,
                dir_fd=self.directory,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        if (
            current.st_dev == self.initial_metadata.st_dev
            and current.st_ino == self.initial_metadata.st_ino
        ):
            os.unlink(self.name, dir_fd=self.directory)


class RetainedInputFile:
    """One receipt/artifact inode held from measurement through publication."""

    def __init__(
        self,
        directory: int,
        name: str,
        label: str,
        descriptor: int,
        metadata: os.stat_result,
        initial_bytes: bytes,
        mode: int,
    ) -> None:
        self.directory = directory
        self.name = name
        self.label = label
        self.descriptor = descriptor
        self.initial_metadata = metadata
        self.initial_bytes = initial_bytes
        self.mode = mode

    @classmethod
    def open(
        cls,
        directory: int,
        name: str,
        *,
        label: str,
        maximum: int,
        mode: int,
    ) -> "RetainedInputFile":
        if not name or "/" in name or name in {".", ".."}:
            raise AggregateError(f"{label} name is not one path component")
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory,
            )
        except OSError as error:
            raise AggregateError(f"{label} is unavailable or is a symlink") from error
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != mode
                or not 1 <= before.st_size <= maximum
            ):
                raise AggregateError(
                    f"{label} must be one {mode:04o} bounded regular file with one link"
                )
            raw = RetainedPublishedFile._read_exact(descriptor, maximum)
            after = os.fstat(descriptor)
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (
                len(raw) != before.st_size
                or stable_identity(before) != stable_identity(after)
                or stable_identity(current) != stable_identity(before)
            ):
                raise AggregateError(f"{label} changed while read")
            result = cls(directory, name, label, descriptor, before, raw, mode)
            result.assert_stable()
            return result
        except BaseException:
            os.close(descriptor)
            raise

    def assert_stable(self) -> None:
        if self.descriptor < 0:
            raise AggregateError(f"{self.label} retained descriptor is closed")
        held_before = os.fstat(self.descriptor)
        held_bytes = RetainedPublishedFile._read_exact(
            self.descriptor, len(self.initial_bytes)
        )
        held_after = os.fstat(self.descriptor)
        try:
            current = os.stat(
                self.name,
                dir_fd=self.directory,
                follow_symlinks=False,
            )
        except OSError as error:
            raise AggregateError(f"{self.label} retained pathname disappeared") from error
        expected = stable_identity(self.initial_metadata)
        if (
            stable_identity(held_before) != expected
            or stable_identity(held_after) != expected
            or stable_identity(current) != expected
            or held_bytes != self.initial_bytes
            or stat.S_IMODE(current.st_mode) != self.mode
        ):
            raise AggregateError(f"{self.label} retained pathname or bytes changed")

    def close(self) -> None:
        if self.descriptor >= 0:
            descriptor = self.descriptor
            self.descriptor = -1
            os.close(descriptor)


def open_directory(
    path: Path, label: str, *, output: bool
) -> tuple[Path, int, os.stat_result, RetainedAbsoluteDirectory]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        custody = RetainedAbsoluteDirectory.open(
            absolute,
            label,
            relax_leaf_content_changes=output,
        )
    except AggregateError:
        raise
    descriptor = custody.descriptor
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        custody.close()
        raise AggregateError(f"{label} must be an invoking-user-owned 0700 directory")
    if output and os.listdir(descriptor):
        custody.close()
        raise AggregateError("output directory must be empty")
    return absolute, descriptor, metadata, custody


def read_regular_at(
    directory: int,
    name: str,
    *,
    label: str,
    maximum: int,
    mode: int,
) -> tuple[bytes, tuple[int, ...]]:
    if not name or "/" in name or name in {".", ".."}:
        raise AggregateError(f"{label} name is not one path component")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | nofollow,
            dir_fd=directory,
        )
    except OSError as error:
        raise AggregateError(f"{label} is unavailable or is a symlink") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode
            or not 1 <= before.st_size <= maximum
        ):
            raise AggregateError(
                f"{label} must be one {mode:04o} bounded regular file with one link"
            )
        chunks: list[bytes] = []
        observed = 0
        while observed <= maximum:
            block = os.read(descriptor, min(1024 * 1024, maximum + 1 - observed))
            if not block:
                break
            chunks.append(block)
            observed += len(block)
        after = os.fstat(descriptor)
        if observed != before.st_size or stable_identity(before) != stable_identity(after):
            raise AggregateError(f"{label} changed while read")
    finally:
        os.close(descriptor)
    try:
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except OSError as error:
        raise AggregateError(f"{label} pathname disappeared") from error
    if stable_identity(current) != stable_identity(before):
        raise AggregateError(f"{label} pathname changed while read")
    return b"".join(chunks), stable_identity(before)


def canonical_absolute_path(value: object, label: str) -> Path:
    if type(value) is not str or not value or "\x00" in value:
        raise AggregateError(f"{label} is not an absolute path")
    candidate = Path(value)
    if not candidate.is_absolute() or os.path.normpath(value) != value:
        raise AggregateError(f"{label} is not a canonical absolute path")
    return candidate


def path_within(path: Path, root: Path, label: str) -> None:
    try:
        path.relative_to(root)
    except ValueError as error:
        raise AggregateError(f"{label} is outside its recorded toolchain root") from error


def validate_source_bom(value: object) -> dict[str, object]:
    source = exact_object(value, SOURCE_BOM_FIELDS, "raw receipt source BOM")
    if (
        source["schema"] != SOURCE_BOM_SCHEMA
        or source["decision"] != SOURCE_BOM_PASS
        or type(source["bytes"]) is not int
        or source["bytes"] <= 0
        or type(source["sha256"]) is not str
        or LOWER_SHA256.fullmatch(source["sha256"]) is None
        or type(source["receipt_id"]) is not str
        or not source["receipt_id"].startswith("sha256:")
        or LOWER_SHA256.fullmatch(source["receipt_id"][7:]) is None
        or type(source["source_set_sha256"]) is not str
        or LOWER_SHA256.fullmatch(source["source_set_sha256"]) is None
        or type(source["resolved_manifest_sha256"]) is not str
        or LOWER_SHA256.fullmatch(source["resolved_manifest_sha256"]) is None
        or source["live_full_remeasurement_before_and_after_build"] is not True
        or source["byte_equal_to_each_live_remeasurement"] is not True
        or source["authority"]
        != "local_source_measurement_not_release_authority"
    ):
        raise AggregateError("raw receipt source BOM binding is malformed")
    return source


def expected_build(lane: str) -> dict[str, object]:
    specification = LANES[lane]
    return {
        "commands": specification["commands"],
        "locked": True,
        "offline": True,
        "no_default_features": True,
        "jobs": 1,
        "incremental": False,
        "fresh_private_target_directory": True,
        "path_remapping": True,
        "p01_compile_variant": specification["p01_compile_variant"],
        "target_native_compile_flags": [
            "--sysroot=$TARGET_SYSROOT",
            "-B$TARGET_COMPILER_BIN",
            "-B$TARGET_GCC_LIBDIR",
            "-B$TARGET_BINUTILS_DIR",
        ],
    }


def validate_toolchain(value: object) -> tuple[dict[str, object], dict[str, object]]:
    toolchain = exact_object(value, TOOLCHAIN_FIELDS, "raw receipt toolchain")
    if (
        toolchain["boundary"] != TOOLCHAIN_BOUNDARY
        or toolchain["input_remeasurement_after_build_required"] is not True
        or toolchain["snapshot_tree_fully_remeasured_before_and_after_build"] is not True
        or toolchain[
            "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed"
        ]
        is not False
        or toolchain["complete_release_toolchain_closure"] is not False
    ):
        raise AggregateError("raw receipt toolchain posture is malformed")
    paths = {
        field: canonical_absolute_path(toolchain[field], f"toolchain {field}")
        for field in (
            "cargo_home",
            "rust_toolchain_root",
            "rust_target_libdir",
            "target_toolchain_root",
            "host_toolchain_root",
            "target_sysroot",
        )
    }
    path_within(
        paths["rust_target_libdir"],
        paths["rust_toolchain_root"],
        "Rust target libdir",
    )
    if paths["target_sysroot"].parent != paths["target_toolchain_root"]:
        raise AggregateError("target sysroot is outside the exact lane snapshot layout")
    search = exact_object(
        toolchain["target_search_prefixes"],
        TARGET_SEARCH_PREFIX_FIELDS,
        "target search prefixes",
    )
    search_paths = {
        field: canonical_absolute_path(value, f"target search prefix {field}")
        for field, value in search.items()
    }
    expected_search_paths = {
        "compiler_bin": paths["target_sysroot"] / "usr/bin",
        "gcc_libdir": (
            paths["target_sysroot"]
            / "usr/lib/gcc-cross/aarch64-linux-gnu/12"
        ),
        "binutils_dir": paths["target_sysroot"] / "usr/aarch64-linux-gnu/bin",
        "host_runtime_libdir": paths["target_sysroot"] / "usr/lib/x86_64-linux-gnu",
    }
    if search_paths != expected_search_paths:
        raise AggregateError("target search prefixes differ from the bound snapshot layout")

    snapshot = exact_object(
        toolchain["snapshot_manifest"],
        SNAPSHOT_MANIFEST_FIELDS,
        "toolchain snapshot manifest",
    )
    if (
        {key: snapshot[key] for key in EXPECTED_SNAPSHOT_MANIFEST}
        != EXPECTED_SNAPSHOT_MANIFEST
    ):
        raise AggregateError("toolchain snapshot manifest binding differs")

    components = exact_object(
        toolchain["resolved_components"],
        RESOLVED_COMPONENTS,
        "resolved target compiler components",
    )
    normalized_components: dict[str, object] = {}
    for name in sorted(RESOLVED_COMPONENTS):
        component = exact_object(
            components[name],
            RESOLVED_COMPONENT_FIELDS,
            f"resolved target compiler component {name}",
        )
        relative = component["relative_path"]
        if (
            type(relative) is not str
            or not relative
            or relative.startswith("/")
            or any(part in {"", ".", ".."} for part in relative.split("/"))
            or type(component["bytes"]) is not int
            or component["bytes"] <= 0
            or type(component["sha256"]) is not str
            or LOWER_SHA256.fullmatch(component["sha256"]) is None
            or type(component["mode"]) is not str
            or re.fullmatch(r"0[0-7]{3}", component["mode"]) is None
            or int(component["mode"], 8) & 0o022
        ):
            raise AggregateError(f"resolved target compiler component {name} is malformed")
        normalized_components[name] = dict(component)
    if normalized_components != EXPECTED_RESOLVED_COMPONENTS:
        raise AggregateError("resolved target compiler components differ from the fixed manifest")
    executables = exact_object(
        toolchain["executables"], set(TOOL_ROLES), "selected executable set"
    )
    normalized_tools: dict[str, object] = {}
    for role in TOOL_ROLES:
        record = exact_object(executables[role], TOOL_FIELDS, f"tool {role}")
        path = canonical_absolute_path(record["path"], f"tool {role} path")
        if role in {"cargo", "rustc"}:
            path_within(path, paths["rust_toolchain_root"], f"tool {role}")
        elif role == "host_linker":
            path_within(path, paths["host_toolchain_root"], f"tool {role}")
        else:
            path_within(path, paths["target_toolchain_root"], f"tool {role}")
        if (
            type(record["bytes"]) is not int
            or record["bytes"] <= 0
            or type(record["sha256"]) is not str
            or LOWER_SHA256.fullmatch(record["sha256"]) is None
            or type(record["mode"]) is not str
            or re.fullmatch(r"0[0-7]{3}", record["mode"]) is None
            or int(record["mode"], 8) & 0o022
            or not int(record["mode"], 8) & 0o100
            or type(record["version"]) is not str
            or not record["version"]
            or "\x00" in record["version"]
        ):
            raise AggregateError(f"selected tool identity {role} is malformed")
        normalized_tools[role] = {
            "bytes": record["bytes"],
            "sha256": record["sha256"],
            "mode": record["mode"],
            "version": record["version"],
        }
    expected_target_tools = {
        "linker": search_paths["compiler_bin"] / "aarch64-linux-gnu-gcc-12",
        "ar": search_paths["compiler_bin"] / "aarch64-linux-gnu-ar",
        "readelf": search_paths["compiler_bin"] / "aarch64-linux-gnu-readelf",
    }
    if any(
        canonical_absolute_path(executables[role]["path"], f"tool {role} path")
        != expected
        for role, expected in expected_target_tools.items()
    ):
        raise AggregateError("target tool leaf differs from the bound snapshot")
    for role, expected in EXPECTED_TARGET_TOOL_IDENTITIES.items():
        if normalized_tools[role] != expected:
            raise AggregateError(
                f"selected target tool identity {role} differs from the frozen snapshot leaf"
            )
    normalized = {
        "boundary": toolchain["boundary"],
        "snapshot_manifest": snapshot,
        "resolved_components": normalized_components,
        "executables": normalized_tools,
        "input_remeasurement_after_build_required": True,
        "snapshot_tree_fully_remeasured_before_and_after_build": True,
        "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed": False,
        "complete_release_toolchain_closure": False,
        "local_paths_excluded_from_ab_identity": True,
    }
    return toolchain, normalized


def validate_hardening(value: object, role: str) -> dict[str, object]:
    hardening = exact_object(value, HARDENING_FIELDS, f"artifact {role} hardening")
    expected_scalars = {
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
    }
    if any(hardening[field] != expected for field, expected in expected_scalars.items()):
        raise AggregateError(f"artifact {role} hardening posture differs")
    needed = hardening["needed"]
    if type(needed) is not list or any(type(item) is not str for item in needed):
        raise AggregateError(f"artifact {role} dependency closure is malformed")
    needed_set = set(needed)
    allowed = BASE_NEEDED | (
        {"libm.so.6", PT_INTERP_LOADER} if role == "daemon" else set()
    )
    if (
        len(needed) != len(needed_set)
        or not BASE_NEEDED <= needed_set
        or not needed_set <= allowed
    ):
        raise AggregateError(f"artifact {role} dependency closure differs")
    stack_guard = exact_object(
        hardening["aarch64_stack_protector_guard"],
        STACK_GUARD_FIELDS,
        f"artifact {role} AArch64 stack-protector guard",
    )
    if PT_INTERP_LOADER in needed_set:
        expected_stack_guard = {
            "loader_dt_needed": True,
            "undefined_dynamic_symbol": STACK_CHK_GUARD_SYMBOL,
            "version": "GLIBC_2.17",
            "version_provider": PT_INTERP_LOADER,
            "loader_bound_undefined_symbols": [STACK_CHK_GUARD_SYMBOL],
        }
    else:
        expected_stack_guard = {
            "loader_dt_needed": False,
            "undefined_dynamic_symbol": None,
            "version": None,
            "version_provider": None,
            "loader_bound_undefined_symbols": [],
        }
    if stack_guard != expected_stack_guard:
        raise AggregateError(
            f"artifact {role} AArch64 stack-protector guard evidence differs"
        )
    versions = hardening["required_glibc_versions"]
    if type(versions) is not list or not versions or any(type(item) is not str for item in versions):
        raise AggregateError(f"artifact {role} GLIBC closure is malformed")
    parsed: list[tuple[int, int]] = []
    for version in versions:
        match = GLIBC_RE.fullmatch(version)
        if match is None:
            raise AggregateError(f"artifact {role} GLIBC closure is malformed")
        parsed.append((int(match.group(1)), int(match.group(2))))
    if parsed != sorted(set(parsed)) or max(parsed) > MAX_GLIBC:
        raise AggregateError(f"artifact {role} exceeds the GLIBC_2.36 ceiling")
    maximum = f"GLIBC_{max(parsed)[0]}.{max(parsed)[1]}"
    if hardening["maximum_glibc"] != maximum:
        raise AggregateError(f"artifact {role} maximum GLIBC record differs")
    if (
        type(hardening["gnu_build_id_sha1"]) is not str
        or LOWER_SHA1.fullmatch(hardening["gnu_build_id_sha1"]) is None
    ):
        raise AggregateError(f"artifact {role} GNU build id is malformed")
    return hardening


def validate_artifact_record(
    value: object,
    role: str,
    expected_file: str,
) -> dict[str, object]:
    record = exact_object(value, ARTIFACT_FIELDS, f"artifact {role}")
    if (
        record["file"] != expected_file
        or type(record["bytes"]) is not int
        or not 1 <= record["bytes"] <= MAX_ELF_BYTES
        or type(record["sha256"]) is not str
        or LOWER_SHA256.fullmatch(record["sha256"]) is None
        or record["mode"] != "0555"
        or record["link_count"] != 1
        or record["lane_markers_verified"] is not True
        or record["unremapped_host_paths_absent"] is not True
        or record["retired_agent_identity_absent"] is not True
    ):
        raise AggregateError(f"artifact {role} receipt binding is malformed")
    validate_hardening(record["hardening"], role)
    return record


def validate_aarch64_pie(value: bytes, label: str) -> None:
    if (
        len(value) < 64
        or value[:4] != b"\x7fELF"
        or value[4] != 2
        or value[5] != 1
        or int.from_bytes(value[16:18], "little") != 3
        or int.from_bytes(value[18:20], "little") != 183
    ):
        raise AggregateError(f"{label} is not an AArch64 ELF64 PIE")


def validate_receipt(value: dict[str, object], raw: bytes) -> dict[str, object]:
    receipt = exact_object(value, ROOT_FIELDS, "raw ELF receipt")
    if (
        receipt["schema"] != RAW_SCHEMA
        or receipt["decision"] != RAW_PASS
        or receipt["release_status"] != RELEASE_HOLD
        or receipt["lane"] not in LANES
        or receipt["target"] != TARGET
        or receipt["profile"] != "release"
        or receipt["source_date_epoch"] != 1785110400
        or receipt["receipt_id_scope"] != RECEIPT_ID_SCOPE
    ):
        raise AggregateError("raw ELF receipt header differs")
    lane = str(receipt["lane"])
    specification = LANES[lane]
    if receipt["variant"] != specification["variant"]:
        raise AggregateError("raw ELF receipt variant differs")
    validate_source_bom(receipt["source_bom"])
    build = exact_object(receipt["build"], BUILD_FIELDS, "raw receipt build")
    if build != expected_build(lane):
        raise AggregateError("raw ELF receipt build semantics differ from the fixed lane")
    _toolchain, normalized_toolchain = validate_toolchain(receipt["toolchain"])
    artifacts_expected = specification["artifacts"]
    assert isinstance(artifacts_expected, dict)
    artifacts = exact_object(
        receipt["artifacts"], set(artifacts_expected), "raw receipt artifacts"
    )
    for role, filename in artifacts_expected.items():
        validate_artifact_record(artifacts[role], role, str(filename))
    if receipt["posture"] != POSTURE:
        raise AggregateError("raw ELF receipt host-only posture differs")
    limitations = receipt["limitations"]
    if limitations != LIMITATIONS:
        raise AggregateError("raw ELF receipt limitations are malformed")
    receipt_id = receipt["receipt_id"]
    preimage = dict(receipt)
    preimage.pop("receipt_id")
    if (
        type(receipt_id) is not str
        or receipt_id != "sha256:" + sha256_bytes(canonical_json_bytes(preimage))
        or raw != canonical_json_bytes(receipt)
    ):
        raise AggregateError("raw ELF receipt is not canonical or its id differs")
    return {
        "lane": lane,
        "specification": specification,
        "normalized_toolchain": normalized_toolchain,
    }


def normalized_receipt_semantics(receipt: dict[str, object]) -> dict[str, object]:
    _toolchain, normalized_toolchain = validate_toolchain(receipt["toolchain"])
    return {
        "schema": receipt["schema"],
        "decision": receipt["decision"],
        "release_status": receipt["release_status"],
        "lane": receipt["lane"],
        "variant": receipt["variant"],
        "target": receipt["target"],
        "profile": receipt["profile"],
        "source_date_epoch": receipt["source_date_epoch"],
        "source_bom": receipt["source_bom"],
        "build": receipt["build"],
        "toolchain": normalized_toolchain,
        "artifacts": receipt["artifacts"],
        "posture": receipt["posture"],
        "limitations": receipt["limitations"],
        "receipt_id_scope": receipt["receipt_id_scope"],
    }


def receipt_argument_name(receipt_path: Path, directory: Path, label: str) -> str:
    absolute = Path(os.path.abspath(os.fspath(receipt_path)))
    try:
        parent = absolute.parent.resolve(strict=True)
    except OSError as error:
        raise AggregateError(f"{label} receipt parent is unavailable") from error
    if parent != directory or absolute.name in {"", ".", ".."}:
        raise AggregateError(f"{label} receipt must be a direct child of its input directory")
    return absolute.name


def read_lane(
    directory_fd: int,
    directory_initial: os.stat_result,
    receipt_name: str,
    label: str,
) -> dict[str, object]:
    retained_custody: list[
        RetainedAbsoluteDirectory | RetainedAbsoluteTargetTool | RetainedInputFile
    ] = []
    completed = False
    try:
        result = _read_lane_with_retained_custody(
            directory_fd,
            directory_initial,
            receipt_name,
            label,
            retained_custody,
        )
        completed = True
        return result
    finally:
        if not completed:
            for retained in reversed(retained_custody):
                retained.close()


def _read_lane_with_retained_custody(
    directory_fd: int,
    directory_initial: os.stat_result,
    receipt_name: str,
    label: str,
    retained_custody: list[
        RetainedAbsoluteDirectory | RetainedAbsoluteTargetTool | RetainedInputFile
    ],
) -> dict[str, object]:
    receipt_file = RetainedInputFile.open(
        directory_fd,
        receipt_name,
        label=f"{label} raw receipt",
        maximum=MAX_RECEIPT_BYTES,
        mode=0o444,
    )
    retained_custody.append(receipt_file)
    receipt_raw = receipt_file.initial_bytes
    receipt_identity = stable_identity(receipt_file.initial_metadata)
    receipt = strict_json(receipt_raw, f"{label} raw receipt")
    validated = validate_receipt(receipt, receipt_raw)
    specification = validated["specification"]
    expected_receipt = str(specification["receipt"])
    if receipt_name != expected_receipt:
        raise AggregateError(f"{label} receipt filename differs from its lane")
    artifacts_expected = specification["artifacts"]
    assert isinstance(artifacts_expected, dict)
    expected_names = {expected_receipt, *map(str, artifacts_expected.values())}
    observed_names = set(os.listdir(directory_fd))
    if observed_names != expected_names:
        raise AggregateError(f"{label} directory and receipt artifact sets differ")

    artifacts: dict[str, bytes] = {}
    artifact_identities: dict[str, tuple[int, ...]] = {}
    identities: dict[str, tuple[int, ...]] = {expected_receipt: receipt_identity}
    for role, filename_object in artifacts_expected.items():
        filename = str(filename_object)
        artifact_file = RetainedInputFile.open(
            directory_fd,
            filename,
            label=f"{label} artifact {role}",
            maximum=MAX_ELF_BYTES,
            mode=0o555,
        )
        retained_custody.append(artifact_file)
        value = artifact_file.initial_bytes
        identity = stable_identity(artifact_file.initial_metadata)
        validate_aarch64_pie(value, f"{label} artifact {role}")
        record = receipt["artifacts"][role]
        if record["bytes"] != len(value) or record["sha256"] != sha256_bytes(value):
            raise AggregateError(f"{label} artifact {role} differs from its receipt")
        artifacts[role] = value
        artifact_identities[role] = identity
        identities[filename] = identity

    toolchain = receipt["toolchain"]
    assert isinstance(toolchain, dict)
    target_toolchain_root = canonical_absolute_path(
        toolchain["target_toolchain_root"],
        f"{label} target toolchain root",
    )
    target_sysroot = canonical_absolute_path(
        toolchain["target_sysroot"],
        f"{label} target sysroot",
    )
    target_toolchain_root_custody = RetainedAbsoluteDirectory.open(
        target_toolchain_root,
        f"{label} target toolchain root",
    )
    retained_custody.append(target_toolchain_root_custody)
    target_sysroot_custody = RetainedAbsoluteDirectory.open(
        target_sysroot,
        f"{label} target sysroot",
    )
    retained_custody.append(target_sysroot_custody)
    target_toolchain_root_identity = stable_identity(
        target_toolchain_root_custody.initial_metadata
    )
    target_sysroot_identity = stable_identity(target_sysroot_custody.initial_metadata)
    executable_records = toolchain["executables"]
    assert isinstance(executable_records, dict)
    selected_target_tool_identities: dict[str, tuple[int, ...]] = {}
    selected_target_tool_sha256: dict[str, str] = {}
    selected_target_tool_custody: dict[str, RetainedAbsoluteTargetTool] = {}
    for role in ("linker", "ar", "readelf"):
        record = executable_records[role]
        assert isinstance(record, dict)
        path = canonical_absolute_path(record["path"], f"{label} target tool {role}")
        tool_custody = RetainedAbsoluteTargetTool.open(
            path,
            record,
            f"{label} target tool {role}",
        )
        retained_custody.append(tool_custody)
        selected_target_tool_custody[role] = tool_custody
        raw_tool = tool_custody.initial_bytes
        identity = stable_identity(tool_custody.initial_metadata)
        selected_target_tool_identities[role] = identity
        selected_target_tool_sha256[role] = sha256_bytes(raw_tool)
    directory_after = os.fstat(directory_fd)
    if stable_identity(directory_after) != stable_identity(directory_initial):
        raise AggregateError(f"{label} input directory changed while read")
    token = sha256_bytes(
        canonical_json_bytes(
            {
                "receipt_sha256": sha256_bytes(receipt_raw),
                "files": {
                    name: {
                        "identity": list(identities[name]),
                        "sha256": sha256_bytes(
                            receipt_raw
                            if name == expected_receipt
                            else artifacts[
                                next(
                                    role
                                    for role, filename in artifacts_expected.items()
                                    if filename == name
                                )
                            ]
                        ),
                    }
                    for name in sorted(identities)
                },
                "target_toolchain_root_identity": list(
                    target_toolchain_root_identity
                ),
                "target_sysroot_identity": list(target_sysroot_identity),
                "selected_target_tools": {
                    role: {
                        "identity": list(selected_target_tool_identities[role]),
                        "sha256": selected_target_tool_sha256[role],
                    }
                    for role in sorted(selected_target_tool_identities)
                },
            }
        )
    )
    return {
        "receipt": receipt,
        "receipt_raw": receipt_raw,
        "artifacts": artifacts,
        "artifact_identities": artifact_identities,
        "target_toolchain_root_identity": target_toolchain_root_identity,
        "target_sysroot_identity": target_sysroot_identity,
        "selected_target_tool_identities": selected_target_tool_identities,
        "target_toolchain_root_custody": target_toolchain_root_custody,
        "target_sysroot_custody": target_sysroot_custody,
        "selected_target_tool_custody": selected_target_tool_custody,
        "retained_custody": retained_custody,
        "stable_token": token,
        "normalized_semantics": normalized_receipt_semantics(receipt),
    }


def assert_lane_custody_stable(lane: dict[str, object]) -> None:
    retained = lane.get("retained_custody")
    if not isinstance(retained, list):
        raise AggregateError("raw lane retained physical custody is missing")
    for item in retained:
        if not isinstance(
            item,
            (RetainedAbsoluteDirectory, RetainedAbsoluteTargetTool, RetainedInputFile),
        ):
            raise AggregateError("raw lane retained physical custody is malformed")
        item.assert_stable()


def close_lane_custody(lane: dict[str, object]) -> None:
    retained = lane.get("retained_custody")
    if not isinstance(retained, list):
        return
    for item in reversed(retained):
        item.close()
    retained.clear()


def ensure_directory_separation(output: Path, a: Path, b: Path) -> None:
    if len({output, a, b}) != 3:
        raise AggregateError("A, B, and output directories must be distinct")
    for parent, child in ((a, b), (b, a), (a, output), (b, output), (output, a), (output, b)):
        try:
            child.relative_to(parent)
        except ValueError:
            continue
        raise AggregateError("A, B, and output directories may not contain each other")


def write_exclusive_at(
    directory: int, name: str, value: bytes
) -> RetainedPublishedFile:
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
    )
    completed = False
    try:
        descriptor = os.open(name, flags, 0o444, dir_fd=directory)
    except OSError as error:
        raise AggregateError("aggregate receipt publication failed") from error
    try:
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise AggregateError("aggregate receipt publication short write")
            view = view[written:]
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o444
            or metadata.st_size != len(value)
        ):
            raise AggregateError("published aggregate receipt boundary differs")
        retained = RetainedPublishedFile(
            directory,
            name,
            descriptor,
            metadata,
            value,
        )
        retained.assert_stable()
        completed = True
        return retained
    finally:
        if not completed:
            os.close(descriptor)


def finalize_receipt(value: dict[str, object]) -> bytes:
    value["receipt_id_scope"] = RECEIPT_ID_SCOPE
    value["receipt_id"] = "sha256:" + sha256_bytes(canonical_json_bytes(value))
    return canonical_json_bytes(value)


def verify(args: argparse.Namespace) -> dict[str, object]:
    a_directory, a_fd, a_initial, a_directory_custody = open_directory(
        args.a_artifact_dir, "A input directory", output=False
    )
    try:
        b_directory, b_fd, b_initial, b_directory_custody = open_directory(
            args.b_artifact_dir, "B input directory", output=False
        )
        try:
            output_directory, output_fd, output_initial, output_directory_custody = open_directory(
                args.output_dir, "output directory", output=True
            )
            retained_lanes: list[dict[str, object]] = []
            published_output: RetainedPublishedFile | None = None
            publication_succeeded = False
            try:
                if device_inode(a_initial) == device_inode(b_initial):
                    raise AggregateError(
                        "A/B input artifact directories are the same physical directory"
                    )
                if device_inode(output_initial) in {
                    device_inode(a_initial),
                    device_inode(b_initial),
                }:
                    raise AggregateError(
                        "output directory physically aliases an A/B input directory"
                    )
                ensure_directory_separation(output_directory, a_directory, b_directory)
                a_receipt_name = receipt_argument_name(
                    args.a_receipt, a_directory, "A"
                )
                b_receipt_name = receipt_argument_name(
                    args.b_receipt, b_directory, "B"
                )
                a = read_lane(a_fd, a_initial, a_receipt_name, "A")
                retained_lanes.append(a)
                b = read_lane(b_fd, b_initial, b_receipt_name, "B")
                retained_lanes.append(b)
                if not {
                    device_inode(identity)
                    for identity in a["artifact_identities"].values()
                }.isdisjoint(
                    {
                        device_inode(identity)
                        for identity in b["artifact_identities"].values()
                    }
                ):
                    raise AggregateError(
                        "A/B input artifacts reuse one or more physical inodes"
                    )
                a_toolchain_custody = a["target_toolchain_root_custody"]
                b_toolchain_custody = b["target_toolchain_root_custody"]
                assert isinstance(a_toolchain_custody, RetainedAbsoluteDirectory)
                assert isinstance(b_toolchain_custody, RetainedAbsoluteDirectory)
                if device_inode(a_toolchain_custody.initial_metadata) == device_inode(
                    b_toolchain_custody.initial_metadata
                ):
                    raise AggregateError(
                        "A/B target toolchain roots are the same physical directory"
                    )
                a_sysroot_custody = a["target_sysroot_custody"]
                b_sysroot_custody = b["target_sysroot_custody"]
                assert isinstance(a_sysroot_custody, RetainedAbsoluteDirectory)
                assert isinstance(b_sysroot_custody, RetainedAbsoluteDirectory)
                if device_inode(a_sysroot_custody.initial_metadata) == device_inode(
                    b_sysroot_custody.initial_metadata
                ):
                    raise AggregateError(
                        "A/B target sysroots are the same physical directory"
                    )
                if not {
                    device_inode(custody.initial_metadata)
                    for custody in a["selected_target_tool_custody"].values()
                }.isdisjoint(
                    {
                        device_inode(custody.initial_metadata)
                        for custody in b["selected_target_tool_custody"].values()
                    }
                ):
                    raise AggregateError(
                        "A/B selected target tools reuse one or more physical inodes"
                    )
                if a["normalized_semantics"] != b["normalized_semantics"]:
                    raise AggregateError(
                        "A/B lane, source BOM, build, tool identity, or receipt semantics differ"
                    )
                a_receipt = a["receipt"]
                b_receipt = b["receipt"]
                assert isinstance(a_receipt, dict) and isinstance(b_receipt, dict)
                lane = str(a_receipt["lane"])
                roles = tuple(LANES[lane]["artifacts"])
                for role in roles:
                    if a["artifacts"][role] != b["artifacts"][role]:
                        raise AggregateError(f"A/B artifact bytes differ for role {role}")

                semantic_raw = canonical_json_bytes(a["normalized_semantics"])
                build_raw = canonical_json_bytes(a_receipt["build"])
                normalized_toolchain = a["normalized_semantics"]["toolchain"]
                target_compiler_closure = {
                    "schema": "org.trillionnium.target-compiler-effective-closure.v1",
                    "target": "aarch64-linux-gnu",
                    "normalized_search_arguments": [
                        "--sysroot=$TARGET_SYSROOT",
                        "-B$TARGET_COMPILER_BIN",
                        "-B$TARGET_GCC_LIBDIR",
                        "-B$TARGET_BINUTILS_DIR",
                    ],
                    "reported_sysroot": "$TARGET_SYSROOT",
                    "components": normalized_toolchain["resolved_components"],
                    "snapshot_tree_fully_remeasured_before_and_after_build": True,
                    "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed": False,
                    "complete_host_execution_runtime_closure": False,
                }
                receipt: dict[str, object] = {
                    "schema": AGGREGATE_SCHEMA,
                    "decision": AGGREGATE_PASS,
                    "release_status": RELEASE_HOLD,
                    "lane": lane,
                    "variant": a_receipt["variant"],
                    "target": TARGET,
                    "source_bom": a_receipt["source_bom"],
                    "build_semantics_sha256": sha256_bytes(build_raw),
                    "normalized_receipt_semantics_sha256": sha256_bytes(semantic_raw),
                    "selected_tool_identities": normalized_toolchain["executables"],
                    "toolchain_snapshot": normalized_toolchain["snapshot_manifest"],
                    "target_compiler_closure": target_compiler_closure,
                    "tool_paths_may_differ_and_are_excluded_from_identity": True,
                    "inputs": {
                        "a": {
                            "receipt_file": a_receipt_name,
                            "receipt_bytes": len(a["receipt_raw"]),
                            "receipt_sha256": sha256_bytes(a["receipt_raw"]),
                            "receipt_id": a_receipt["receipt_id"],
                        },
                        "b": {
                            "receipt_file": b_receipt_name,
                            "receipt_bytes": len(b["receipt_raw"]),
                            "receipt_sha256": sha256_bytes(b["receipt_raw"]),
                            "receipt_id": b_receipt["receipt_id"],
                        },
                    },
                    "artifacts": {
                        role: {
                            "file": a_receipt["artifacts"][role]["file"],
                            "bytes": len(a["artifacts"][role]),
                            "sha256": sha256_bytes(a["artifacts"][role]),
                            "a_receipt_bound": True,
                            "b_receipt_bound": True,
                            "a_b_byte_equal": True,
                        }
                        for role in roles
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
                }
                receipt_raw = finalize_receipt(receipt)

                # Re-read every input and compare inode/content tokens before
                # publication. No operation above writes to either input.
                a_second = read_lane(a_fd, a_initial, a_receipt_name, "A")
                retained_lanes.append(a_second)
                b_second = read_lane(b_fd, b_initial, b_receipt_name, "B")
                retained_lanes.append(b_second)
                a_directory_custody.assert_stable()
                b_directory_custody.assert_stable()
                output_directory_custody.assert_stable()
                for retained_lane in retained_lanes:
                    assert_lane_custody_stable(retained_lane)
                if (
                    a_second["stable_token"] != a["stable_token"]
                    or b_second["stable_token"] != b["stable_token"]
                    or a_second["normalized_semantics"] != a["normalized_semantics"]
                    or b_second["normalized_semantics"] != b["normalized_semantics"]
                ):
                    raise AggregateError("A/B inputs changed before aggregate publication")
                published_output = write_exclusive_at(
                    output_fd, OUTPUT_NAME, receipt_raw
                )
                os.fsync(output_fd)
                a_directory_custody.assert_stable()
                b_directory_custody.assert_stable()
                output_directory_custody.assert_stable()
                for retained_lane in retained_lanes:
                    assert_lane_custody_stable(retained_lane)
                if os.listdir(output_fd) != [OUTPUT_NAME]:
                    raise AggregateError(
                        "output directory inventory is not the exact aggregate receipt"
                    )
                published_output.assert_stable()
                output_directory_custody.assert_stable()
                publication_succeeded = True
                return receipt
            finally:
                try:
                    for retained_lane in reversed(retained_lanes):
                        close_lane_custody(retained_lane)
                finally:
                    try:
                        if published_output is not None:
                            try:
                                if not publication_succeeded:
                                    published_output.unlink_if_current()
                            finally:
                                published_output.close()
                    finally:
                        output_directory_custody.close()
        finally:
            b_directory_custody.close()
    finally:
        a_directory_custody.close()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--a-artifact-dir", type=Path, required=True)
    parser.add_argument("--a-receipt", type=Path, required=True)
    parser.add_argument("--b-artifact-dir", type=Path, required=True)
    parser.add_argument("--b-receipt", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        receipt = verify(parse_args(argv))
    except AggregateError as error:
        print(f"Codex raw ELF A/B verification error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, allow_nan=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
