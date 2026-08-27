#!/usr/bin/env python3
"""Close a launcher artifact-set A/B over one verified raw-ELF A/B receipt.

The verifier is deliberately downstream-only.  It neither rebuilds nor copies
launcher artifacts.  Each launcher directory is read through a retained
directory descriptor, its inventory must exactly match its receipt, every
artifact is checked in both directions, and A/B outputs must be byte-identical.
The launcher compiler and ELF inspector are byte-bound by each builder receipt,
post-build remeasured, and must match the exact linker/readelf identities
selected by the raw ELF A/B receipt.

Current common v5 and P01 pre v8 receipts must both carry the unresolved
stable-principal counterfactual gate.  Superseded schemas are rejected;
no absence is inferred from a contract digest.
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


sys.dont_write_bytecode = True
TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import verify_codex_only_raw_elf_ab as raw_ab_contract  # noqa: E402


OUTPUT_NAME = "codex-launcher-artifact-set-ab.v4.json"
OUTPUT_SCHEMA = "org.trillionnium.codex-launcher-artifact-set-ab.v4"
P01_OUTPUT_NAME = "codex-launcher-artifact-set-ab.v5.json"
P01_OUTPUT_SCHEMA = "org.trillionnium.codex-launcher-artifact-set-ab.v5"
OUTPUT_DECISION = (
    "PASS_HOST_ONLY_DETERMINISTIC_CODEX_LAUNCHER_ARTIFACT_SET_AB"
)
OUTPUT_HOLD = (
    "HOLD_IDENTITY_INDEPENDENCE_PRODUCT_DEVICE_AND_COMPLETE_TOOLCHAIN_ADMISSION"
)
RECEIPT_ID_SCOPE = (
    "sha256(canonical-json-utf8-sort-keys-indent-2-lf-without-receipt_id)"
)
RAW_SCHEMA = "org.trillionnium.codex-only-raw-elf-ab.v3"
RAW_DECISION = "PASS_HOST_ONLY_DETERMINISTIC_CODEX_RAW_ELF_AB"
RAW_HOLD = "HOLD_PRODUCT_DEVICE_AND_COMPLETE_TOOLCHAIN_ADMISSION"
SOURCE_SCHEMA = "org.trillionnium.local-cross-repo-source-bom.v2"
SOURCE_DECISION = "PASS_LOCAL_EXACT_CLEAN_GRAPH"
TARGET = "aarch64-unknown-linux-gnu"
LAUNCHER_BUILD_TOOL_TARGET = "aarch64-linux-gnu"
MAX_RECEIPT_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_COMPILER_BYTES = 128 * 1024 * 1024
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
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
STABLE_PRINCIPAL_CONTRACT_SHA256 = (
    "3e9bfcb04e48062c20bd7407635c1a27086a0de8c2fa5ca73963c946b984095b"
)
STABLE_PRINCIPAL_CANONICAL_SHA256 = (
    "a9c224116123deb49908beda3ab047fc98d6917cfeb62d60364033858cc57153"
)
CODEX_RUNTIME_SHA256 = (
    "124867cc1c0b13f56539880f19d8c7b59f96e25fd47d068df91ea27c99d1ce78"
)
CODEX_RUNTIME_BYTES = 259_126_424
LEGACY_DESCRIPTOR_DIGESTS = {
    "canonical digest": (
        "bc6c64abbb893e6e75ed708f87cf864e6c8f7503381371dc394409bddc4009c2"
    ),
    "contract digest": (
        "5ecd89d3c9fedbbeb0ac1de32fba2b5e5e5d248048ddc9a9e0359a0a01903119"
    ),
    "launcher identity": (
        "edcf9d31da8b48d29575115a7242691c1337174edf42573b7274b652a4cd571c"
    ),
}
COMMON_DEPENDENCY_GRAPH = {
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
P01_DEPENDENCY_GRAPH = {
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


LANES: Mapping[str, dict[str, object]] = {
    "common": {
        "schema": "org.trillionnium.common-codex-rootfs-artifact-set.v5",
        "receipt": "common-codex-rootfs-artifact-set.v5.json",
        "variant": "common",
        "raw_lane": "common",
        "raw_variant": "common_inert_no_default_features",
        "raw_receipt": "codex-only-raw-elf-set.common.v3.json",
        "raw_roles": {
            "system_api_tool": "system_api_tool_input_sha256",
            "accessibility_tool": "accessibility_tool_input_sha256",
            "replay_sync_helper": "replay_sync_helper_input_sha256",
            "daemon": "daemon_input_sha256",
        },
        "artifacts": {
            "system_api_tool": "trillionnium-agent-system-api",
            "accessibility_tool": "trillionnium-agent-accessibility",
            "replay_sync_helper": "trillionnium-system-api-replay-sync",
            "daemon": "trillionniumd",
            "codex_launcher": "trillionnium-codex-agent-0.144.1",
        },
    },
    "p01_userdebug_pre_daemon": {
        "schema": "org.trillionnium.p01-userdebug-pre-daemon-artifact-set.v8",
        "receipt": "p01-userdebug-pre-daemon-artifact-set.v8.json",
        "output_schema": P01_OUTPUT_SCHEMA,
        "output_name": P01_OUTPUT_NAME,
        "variant": "userdebug",
        "raw_lane": "p01_userdebug_pre_daemon",
        "raw_variant": "non_product_userdebug_settings_only_pre_daemon",
        "raw_receipt": (
            "codex-only-raw-elf-set.p01-userdebug-pre-daemon.v3.json"
        ),
        "raw_roles": {
            "system_api_tool": "system_api_tool_input_sha256",
            "replay_sync_helper": "replay_sync_helper_input_sha256",
            "high_water_authority": "high_water_authority_input_sha256",
        },
        "artifacts": {
            "system_api_tool": (
                "trillionnium-agent-system-api-device-conformance"
            ),
            "replay_sync_helper": (
                "trillionnium-system-api-device-conformance-replay-sync"
            ),
            "high_water_authority": (
                "trillionnium-direct-operation-custody-high-water"
            ),
            "codex_launcher": (
                "trillionnium-codex-agent-0.144.1-p01-userdebug"
            ),
        },
    },
}
LANES["common"].update({"output_schema": OUTPUT_SCHEMA, "output_name": OUTPUT_NAME})

SOURCE_FIELDS = {
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
LAUNCHER_SOURCE_FIELDS = {
    "file_sha256",
    "bytes",
    "receipt_id",
    "control_head",
    "source_set_sha256",
    "resolved_manifest_sha256",
    "authority",
}
RAW_ROOT_FIELDS = {
    "schema",
    "decision",
    "release_status",
    "lane",
    "variant",
    "target",
    "source_bom",
    "build_semantics_sha256",
    "normalized_receipt_semantics_sha256",
    "selected_tool_identities",
    "toolchain_snapshot",
    "target_compiler_closure",
    "tool_paths_may_differ_and_are_excluded_from_identity",
    "inputs",
    "artifacts",
    "comparisons",
    "posture",
    "limitations",
    "receipt_id_scope",
    "receipt_id",
}
RAW_TOOL_FIELDS = {"bytes", "sha256", "mode", "version"}
RAW_INPUT_FIELDS = {
    "receipt_file",
    "receipt_bytes",
    "receipt_sha256",
    "receipt_id",
}
RAW_ARTIFACT_FIELDS = {
    "file",
    "bytes",
    "sha256",
    "a_receipt_bound",
    "b_receipt_bound",
    "a_b_byte_equal",
}
LAUNCHER_ARTIFACT_FIELDS = {"file", "sha256", "bytes"}
BUILD_TOOL_FIELDS = {
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
}
BUILD_TOOL_EXECUTION_FIELDS = {
    "mechanism",
    "measured_before_first_execution",
    "all_invocations_used_same_open_file_description",
    "descriptor_and_path_stable_after_last_execution",
    "ambient_environment_inherited",
    "environment_allowlist",
}
STABLE_MEASUREMENT_FIELDS = {
    "status",
    "stable_principal_contract_sha256",
    "stable_principal_canonical_sha256",
    "launcher_executable_sha256",
    "launcher_identity_source",
    "executable_identity_is_stable_registry_input",
}
DAEMON_BUILD_BINDING_FIELDS = {
    "schema",
    "sha256_scope",
    "product_variant",
    "build_policy",
    "cargo_profile",
    "feature_profile",
    "runtime_artifact_sha256",
    "stable_principal",
    "identity_independence_hold",
    "target_profile",
    "toolchain_snapshot",
    "target_compiler_closure",
}
TARGET_COMPILER_CLOSURE_FIELDS = {
    "schema",
    "target",
    "normalized_search_arguments",
    "reported_sysroot",
    "components",
    "snapshot_tree_fully_remeasured_before_and_after_build",
    "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed",
    "complete_host_execution_runtime_closure",
}
TARGET_COMPILER_COMPONENT_FIELDS = {"relative_path", "bytes", "sha256", "mode"}
TARGET_COMPILER_COMPONENTS = {
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
GATE_FIELDS = {
    "status",
    "literal_digest_absence_verified",
    "digests",
    "counterfactual_same_source_rebuild",
    "stable_principal_admission_split",
}
GATE_SUBFIELDS = {"required", "verified", "evidence_receipt"}
DAEMON_NORMALIZED_RUSTFLAGS = (
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
)


class VerificationError(RuntimeError):
    """One receipt, physical input, or cross-receipt binding failed."""


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
        raise VerificationError(f"{label} schema is not closed")
    return value


def strict_json(raw: bytes, label: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError(f"{label} contains duplicate key {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda item: (_ for _ in ()).throw(
                VerificationError(f"{label} contains non-finite number {item}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{label} is not strict UTF-8 JSON") from error
    if type(value) is not dict:
        raise VerificationError(f"{label} must be an object")
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
    def __init__(
        self,
        path: Path,
        label: str,
        descriptors: list[int],
        metadata: list[os.stat_result],
        component_names: list[str],
        allow_leaf_content_changes: bool,
    ) -> None:
        self.path = path
        self.label = label
        self.descriptors = descriptors
        self.metadata = metadata
        self.component_names = component_names
        self.allow_leaf_content_changes = allow_leaf_content_changes

    @classmethod
    def open(
        cls,
        path: Path,
        label: str,
        *,
        allow_leaf_content_changes: bool = False,
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
            raise VerificationError(
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
                    raise VerificationError(
                        f"{label} component is unavailable"
                    ) from error
                if not stat.S_ISDIR(lexical.st_mode):
                    raise VerificationError(
                        f"{label} contains a symbolic link or non-directory component"
                    )
                try:
                    descriptor = os.open(component, flags, dir_fd=descriptors[-1])
                except OSError as error:
                    raise VerificationError(
                        f"{label} component cannot be opened without following links"
                    ) from error
                opened = os.fstat(descriptor)
                leaf = len(component_names) + 1 == len(path.parts) - 1
                if stable_directory_identity(
                    opened, leaf=leaf
                ) != stable_directory_identity(lexical, leaf=leaf):
                    os.close(descriptor)
                    raise VerificationError(f"{label} component changed while opened")
                descriptors.append(descriptor)
                metadata.append(opened)
                component_names.append(component)
            result = cls(
                path,
                label,
                descriptors,
                metadata,
                component_names,
                allow_leaf_content_changes,
            )
            result.assert_stable()
            return result
        except BaseException:
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
            leaf = (
                index == len(self.descriptors) - 1
                and not self.allow_leaf_content_changes
            )
            if stable_directory_identity(
                held, leaf=leaf
            ) != stable_directory_identity(expected, leaf=leaf):
                raise VerificationError(f"{self.label} retained directory changed")
            if index == 0:
                continue
            try:
                current = os.stat(
                    self.component_names[index - 1],
                    dir_fd=self.descriptors[index - 1],
                    follow_symlinks=False,
                )
            except OSError as error:
                raise VerificationError(
                    f"{self.label} retained pathname disappeared"
                ) from error
            if stable_directory_identity(
                current, leaf=leaf
            ) != stable_directory_identity(expected, leaf=leaf):
                raise VerificationError(f"{self.label} retained pathname changed")

    def close(self) -> None:
        for descriptor in reversed(self.descriptors):
            os.close(descriptor)
        self.descriptors.clear()


class RetainedAbsoluteRegular:
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
        cls, path: Path, label: str, maximum: int
    ) -> "RetainedAbsoluteRegular":
        value = os.fspath(path)
        if (
            not path.is_absolute()
            or os.path.normpath(value) != value
            or path.name in {"", ".", ".."}
        ):
            raise VerificationError(f"{label} path is not canonical and absolute")
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
                or not 1 <= before.st_size <= maximum
                or mode & 0o022
                or not mode & 0o100
            ):
                raise VerificationError(
                    f"{label} must be one bounded non-writable executable regular file"
                )
            chunks: list[bytes] = []
            observed = 0
            while observed <= maximum:
                chunk = os.read(
                    descriptor, min(1024 * 1024, maximum + 1 - observed)
                )
                if not chunk:
                    break
                chunks.append(chunk)
                observed += len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
            if observed != before.st_size or stable_identity(before) != stable_identity(after):
                raise VerificationError(f"{label} changed while read")
            result = cls(path, label, parent, descriptor, before, raw)
            result.assert_stable()
            return result
        except BaseException:
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
            raise VerificationError(f"{self.label} retained pathname disappeared") from error
        if (
            stable_identity(held) != stable_identity(self.initial_metadata)
            or stable_identity(current) != stable_identity(self.initial_metadata)
        ):
            raise VerificationError(f"{self.label} retained pathname changed")

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
            raise VerificationError("published launcher aggregate is already closed")
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
            raise VerificationError(
                "published launcher aggregate pathname changed"
            ) from error
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
            raise VerificationError(
                "published launcher aggregate descriptor, pathname, or bytes changed"
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


class RetainedRelativeInputFile:
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
    ) -> "RetainedRelativeInputFile":
        if not name or "/" in name or name in {".", ".."}:
            raise VerificationError(f"{label} name is not one path component")
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory,
            )
        except OSError as error:
            raise VerificationError(f"{label} is unavailable or is a symlink") from error
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != mode
                or not 1 <= before.st_size <= maximum
            ):
                raise VerificationError(
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
                raise VerificationError(f"{label} changed while read")
            result = cls(directory, name, label, descriptor, before, raw, mode)
            result.assert_stable()
            return result
        except BaseException:
            os.close(descriptor)
            raise

    def assert_stable(self) -> None:
        if self.descriptor < 0:
            raise VerificationError(f"{self.label} retained descriptor is closed")
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
            raise VerificationError(
                f"{self.label} retained pathname disappeared"
            ) from error
        expected = stable_identity(self.initial_metadata)
        if (
            stable_identity(held_before) != expected
            or stable_identity(held_after) != expected
            or stable_identity(current) != expected
            or held_bytes != self.initial_bytes
            or stat.S_IMODE(current.st_mode) != self.mode
        ):
            raise VerificationError(f"{self.label} retained pathname or bytes changed")

    def close(self) -> None:
        if self.descriptor >= 0:
            descriptor = self.descriptor
            self.descriptor = -1
            os.close(descriptor)


def read_absolute_directory_identity(
    path: Path, label: str
) -> tuple[tuple[int, ...], RetainedAbsoluteDirectory]:
    retained = RetainedAbsoluteDirectory.open(path, label)
    return stable_identity(retained.initial_metadata), retained


def open_directory(
    path: Path, label: str, *, empty: bool
) -> tuple[Path, int, os.stat_result, RetainedAbsoluteDirectory]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    retained = RetainedAbsoluteDirectory.open(
        absolute, label, allow_leaf_content_changes=empty
    )
    descriptor = retained.descriptor
    metadata = retained.initial_metadata
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        retained.close()
        raise VerificationError(f"{label} must be an invoking-user-owned 0700 directory")
    if empty and os.listdir(descriptor):
        retained.close()
        raise VerificationError(f"{label} must be empty")
    return absolute, descriptor, metadata, retained


def read_regular_at(
    directory: int,
    name: str,
    *,
    label: str,
    maximum: int,
    mode: int,
) -> tuple[bytes, tuple[int, ...]]:
    if not name or "/" in name or name in {".", ".."}:
        raise VerificationError(f"{label} name is not one path component")
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory,
        )
    except OSError as error:
        raise VerificationError(f"{label} is unavailable or is a symlink") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode
            or not 1 <= before.st_size <= maximum
        ):
            raise VerificationError(
                f"{label} must be one {mode:04o} bounded regular file with one link"
            )
        chunks: list[bytes] = []
        observed = 0
        while observed <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
        after = os.fstat(descriptor)
        if observed != before.st_size or stable_identity(before) != stable_identity(after):
            raise VerificationError(f"{label} changed while read")
    finally:
        os.close(descriptor)
    try:
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except OSError as error:
        raise VerificationError(f"{label} pathname disappeared") from error
    if stable_identity(current) != stable_identity(before):
        raise VerificationError(f"{label} pathname changed while read")
    return b"".join(chunks), stable_identity(before)


def read_absolute_regular(
    path: Path, *, label: str, maximum: int
) -> tuple[bytes, tuple[int, ...], str, RetainedAbsoluteRegular]:
    retained = RetainedAbsoluteRegular.open(path, label, maximum)
    mode = stat.S_IMODE(retained.initial_metadata.st_mode)
    return (
        retained.initial_bytes,
        stable_identity(retained.initial_metadata),
        f"{mode:04o}",
        retained,
    )


def direct_child_name(path: Path, parent: Path, label: str) -> str:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if absolute.parent != parent or absolute.name in {"", ".", ".."}:
        raise VerificationError(f"{label} must be a direct child of its artifact directory")
    return absolute.name


def validate_sha256(value: object, label: str) -> str:
    if type(value) is not str or LOWER_SHA256.fullmatch(value) is None:
        raise VerificationError(f"{label} is not a lowercase SHA-256")
    return value


def validate_receipt_id(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not value.startswith("sha256:")
        or LOWER_SHA256.fullmatch(value[7:]) is None
    ):
        raise VerificationError(f"{label} is malformed")
    return value


def validate_raw_source(value: object) -> dict[str, object]:
    source = exact_object(value, SOURCE_FIELDS, "raw A/B source BOM")
    if (
        source["schema"] != SOURCE_SCHEMA
        or source["decision"] != SOURCE_DECISION
        or type(source["bytes"]) is not int
        or source["bytes"] <= 0
        or source["live_full_remeasurement_before_and_after_build"] is not True
        or source["byte_equal_to_each_live_remeasurement"] is not True
        or source["authority"] != "local_source_measurement_not_release_authority"
    ):
        raise VerificationError("raw A/B source BOM posture is malformed")
    for field in ("sha256", "source_set_sha256", "resolved_manifest_sha256"):
        validate_sha256(source[field], f"raw A/B source BOM {field}")
    validate_receipt_id(source["receipt_id"], "raw A/B source BOM receipt id")
    return source


def validate_target_compiler_closure(value: object) -> dict[str, object]:
    closure = exact_object(
        value,
        TARGET_COMPILER_CLOSURE_FIELDS,
        "target compiler effective closure",
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
        raise VerificationError("target compiler effective closure posture differs")
    components = exact_object(
        closure["components"],
        TARGET_COMPILER_COMPONENTS,
        "target compiler effective components",
    )
    for role, value in components.items():
        record = exact_object(
            value,
            TARGET_COMPILER_COMPONENT_FIELDS,
            f"target compiler effective component {role}",
        )
        relative = record["relative_path"]
        if (
            type(relative) is not str
            or not relative
            or relative.startswith("/")
            or any(part in {"", ".", ".."} for part in relative.split("/"))
            or type(record["bytes"]) is not int
            or record["bytes"] <= 0
            or type(record["mode"]) is not str
            or re.fullmatch(r"0[0-7]{3,4}", record["mode"]) is None
            or int(record["mode"], 8) & 0o022
        ):
            raise VerificationError(
                f"target compiler effective component {role} is malformed"
            )
        validate_sha256(record["sha256"], f"target compiler component {role}")
    if components != raw_ab_contract.EXPECTED_RESOLVED_COMPONENTS:
        raise VerificationError(
            "target compiler effective components differ from the fixed manifest"
        )
    return closure


def validate_raw_aggregate(value: dict[str, object], raw: bytes, lane: str) -> None:
    receipt = exact_object(value, RAW_ROOT_FIELDS, "raw ELF A/B receipt")
    specification = LANES[lane]
    if (
        receipt["schema"] != RAW_SCHEMA
        or receipt["decision"] != RAW_DECISION
        or receipt["release_status"] != RAW_HOLD
        or receipt["lane"] != specification["raw_lane"]
        or receipt["variant"] != specification["raw_variant"]
        or receipt["target"] != TARGET
        or receipt["receipt_id_scope"] != RECEIPT_ID_SCOPE
        or receipt["tool_paths_may_differ_and_are_excluded_from_identity"] is not True
    ):
        raise VerificationError("raw ELF A/B receipt header or lane differs")
    validate_raw_source(receipt["source_bom"])
    validate_sha256(receipt["build_semantics_sha256"], "raw build semantics")
    validate_sha256(
        receipt["normalized_receipt_semantics_sha256"],
        "raw normalized semantics",
    )
    tools = exact_object(
        receipt["selected_tool_identities"],
        {"cargo", "rustc", "host_linker", "linker", "ar", "readelf"},
        "raw selected tool identities",
    )
    for role, candidate in tools.items():
        record = exact_object(candidate, RAW_TOOL_FIELDS, f"raw tool {role}")
        if (
            type(record["bytes"]) is not int
            or record["bytes"] <= 0
            or type(record["mode"]) is not str
            or re.fullmatch(r"0[0-7]{3}", record["mode"]) is None
            or int(record["mode"], 8) & 0o022
            or not int(record["mode"], 8) & 0o100
            or type(record["version"]) is not str
            or not record["version"]
            or "\x00" in record["version"]
        ):
            raise VerificationError(f"raw selected tool {role} is malformed")
        validate_sha256(record["sha256"], f"raw tool {role}")
    for role, expected in raw_ab_contract.EXPECTED_TARGET_TOOL_IDENTITIES.items():
        if tools[role] != expected:
            raise VerificationError(
                f"raw selected target tool {role} differs from the frozen snapshot leaf"
            )
    validate_toolchain_snapshot(receipt["toolchain_snapshot"])
    validate_target_compiler_closure(receipt["target_compiler_closure"])
    inputs = exact_object(receipt["inputs"], {"a", "b"}, "raw A/B inputs")
    for side in ("a", "b"):
        record = exact_object(inputs[side], RAW_INPUT_FIELDS, f"raw input {side}")
        if (
            record["receipt_file"] != specification["raw_receipt"]
            or type(record["receipt_bytes"]) is not int
            or record["receipt_bytes"] <= 0
        ):
            raise VerificationError(f"raw input {side} is malformed")
        validate_sha256(record["receipt_sha256"], f"raw input {side}")
        validate_receipt_id(record["receipt_id"], f"raw input {side} receipt id")
    expected_raw_roles = set(specification["raw_roles"])
    artifacts = exact_object(
        receipt["artifacts"], expected_raw_roles, "raw aggregate artifacts"
    )
    for role, candidate in artifacts.items():
        record = exact_object(candidate, RAW_ARTIFACT_FIELDS, f"raw artifact {role}")
        if (
            type(record["file"]) is not str
            or not record["file"]
            or "/" in record["file"]
            or type(record["bytes"]) is not int
            or record["bytes"] <= 0
            or record["a_receipt_bound"] is not True
            or record["b_receipt_bound"] is not True
            or record["a_b_byte_equal"] is not True
        ):
            raise VerificationError(f"raw artifact {role} binding is malformed")
        validate_sha256(record["sha256"], f"raw artifact {role}")
    expected_comparisons = {
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
    }
    if receipt["comparisons"] != expected_comparisons:
        raise VerificationError("raw A/B comparisons are not the closed PASS set")
    expected_posture = {
        "host_only": True,
        "deterministic_raw_elf_ab_verified": True,
        "complete_toolchain_byte_closure": False,
        "launcher_built": False,
        "rootfs_built": False,
        "device_execution_verified": False,
        "avb_or_ota_verified": False,
        "release_allowed": False,
        "device_write_authorized": False,
    }
    if receipt["posture"] != expected_posture:
        raise VerificationError("raw A/B host-only posture differs")
    if receipt["limitations"] != [
        "raw_elf_ab_does_not_prove_complete_toolchain_byte_closure",
        "raw_elf_ab_does_not_prove_launcher_rootfs_android_device_avb_or_ota",
        "source_bom_is_an_upstream_receipt_claim_not_physically_remeasured_by_this_stage",
        "receipt_ids_are_content_identifiers_not_signatures_or_attestations",
        "receipt_tool_paths_are_physical_custody_inputs_but_excluded_from_ab_semantic_identity",
    ]:
        raise VerificationError("raw A/B limitations are not the closed HOLD set")
    receipt_id = validate_receipt_id(receipt["receipt_id"], "raw A/B receipt id")
    preimage = dict(receipt)
    preimage.pop("receipt_id")
    if (
        receipt_id != "sha256:" + sha256_bytes(canonical_json_bytes(preimage))
        or raw != canonical_json_bytes(receipt)
    ):
        raise VerificationError("raw A/B receipt is not canonical or its id differs")


def validate_launcher_source(
    value: object, raw_source: dict[str, object]
) -> dict[str, object]:
    source = exact_object(value, LAUNCHER_SOURCE_FIELDS, "launcher source BOM")
    if (
        type(source["bytes"]) is not int
        or source["bytes"] <= 0
        or type(source["control_head"]) is not str
        or re.fullmatch(r"[0-9a-f]{40,64}", source["control_head"]) is None
        or source["authority"]
        != "local_exact_clean_graph_not_build_or_release_authority"
    ):
        raise VerificationError("launcher source BOM binding is malformed")
    validate_sha256(source["file_sha256"], "launcher source BOM file hash")
    validate_sha256(source["source_set_sha256"], "launcher source-set hash")
    validate_sha256(
        source["resolved_manifest_sha256"], "launcher resolved manifest hash"
    )
    validate_receipt_id(source["receipt_id"], "launcher source BOM receipt id")
    pairs = {
        "file_sha256": "sha256",
        "bytes": "bytes",
        "receipt_id": "receipt_id",
        "source_set_sha256": "source_set_sha256",
        "resolved_manifest_sha256": "resolved_manifest_sha256",
    }
    if any(source[left] != raw_source[right] for left, right in pairs.items()):
        raise VerificationError("launcher and raw A/B source BOM bindings differ")
    return source


def validate_stable_measurement(value: object, launcher_sha256: str) -> dict[str, object]:
    measurement = exact_object(
        value, STABLE_MEASUREMENT_FIELDS, "stable-principal launcher measurement"
    )
    if (
        measurement["status"]
        != "host_measurement_only_avb_slot_admission_absent"
        or measurement["launcher_executable_sha256"] != launcher_sha256
        or measurement["launcher_identity_source"]
        != "measured_after_closed_launcher_inputs"
        or measurement["executable_identity_is_stable_registry_input"] is not False
        or measurement["stable_principal_contract_sha256"]
        != STABLE_PRINCIPAL_CONTRACT_SHA256
        or measurement["stable_principal_canonical_sha256"]
        != STABLE_PRINCIPAL_CANONICAL_SHA256
    ):
        raise VerificationError("stable-principal launcher measurement is malformed")
    validate_sha256(
        measurement["stable_principal_contract_sha256"],
        "stable-principal contract hash",
    )
    validate_sha256(
        measurement["stable_principal_canonical_sha256"],
        "stable-principal canonical hash",
    )
    return measurement


def validate_unresolved_gate(value: object) -> dict[str, object]:
    gate = exact_object(value, GATE_FIELDS, "identity-independence HOLD gate")
    if (
        gate["status"] != "hold_identity_independence_evidence_unverified"
        or gate["literal_digest_absence_verified"] is not True
    ):
        raise VerificationError("identity-independence gate status is not the required HOLD")
    digests = gate["digests"]
    if digests != LEGACY_DESCRIPTOR_DIGESTS:
        raise VerificationError("identity-independence digest set is not closed")
    for field in (
        "counterfactual_same_source_rebuild",
        "stable_principal_admission_split",
    ):
        record = exact_object(gate[field], GATE_SUBFIELDS, f"gate {field}")
        if (
            record["required"] is not True
            or record["verified"] is not False
            or record["evidence_receipt"] is not None
        ):
            raise VerificationError(
                f"{field} must remain required, unresolved, and evidence-free"
            )
    return gate


def validate_daemon_build_binding(
    value: object,
    artifacts: dict[str, object],
    gate: dict[str, object],
) -> dict[str, object]:
    binding = exact_object(
        value, DAEMON_BUILD_BINDING_FIELDS, "P01 daemon build binding"
    )
    feature_profile = exact_object(
        binding["feature_profile"],
        {
            "cargo_package",
            "enabled_cargo_features",
            "default_cargo_features",
            "conformance_build_variant",
        },
        "P01 daemon feature profile",
    )
    cargo_profile = exact_object(
        binding["cargo_profile"],
        {
            "name",
            "opt_level",
            "debug",
            "debug_assertions",
            "incremental",
            "strip",
        },
        "P01 daemon Cargo profile",
    )
    build_policy = exact_object(
        binding["build_policy"],
        {
            "cargo_incremental",
            "normalized_rustflags",
            "normalized_native_environment",
            "selected_native_tools",
            "host_runtime_execution_boundary",
            "source_date_epoch",
        },
        "P01 daemon build policy",
    )
    runtime = exact_object(
        binding["runtime_artifact_sha256"],
        {
            "system_api_tool",
            "replay_sync_helper",
            "high_water_authority",
            "codex_launcher",
        },
        "P01 daemon runtime-artifact binding",
    )
    stable = exact_object(
        binding["stable_principal"],
        {"authority", "contract_sha256", "canonical_sha256"},
        "P01 daemon stable-principal binding",
    )
    identity_hold = exact_object(
        binding["identity_independence_hold"],
        {"schema", "status", "profile_sha256"},
        "P01 daemon identity-HOLD binding",
    )
    target_profile = exact_object(
        binding["target_profile"],
        {
            "rust_target_triple",
            "architecture",
            "operating_system",
            "libc_family",
            "dynamic_interpreter",
            "maximum_glibc",
            "runtime_base_contract",
        },
        "P01 daemon target profile",
    )
    toolchain_snapshot = exact_object(
        binding["toolchain_snapshot"],
        {
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
        },
        "P01 daemon toolchain snapshot",
    )
    target_compiler_closure = validate_target_compiler_closure(
        binding["target_compiler_closure"]
    )
    if (
        binding["schema"]
        != "org.trillionnium.p01-userdebug-daemon-build-binding.v2"
        or binding["sha256_scope"]
        != "sha256(canonical-json-utf8-sort-keys-indent-2-lf-of-daemon_build_binding)"
        or binding["product_variant"] != "userdebug"
        or feature_profile
        != {
            "cargo_package": "trillionniumd",
            "enabled_cargo_features": ["p0-launch-package-device-conformance"],
            "default_cargo_features": [],
            "conformance_build_variant": "userdebug",
        }
        or cargo_profile
        != {
            "name": "release",
            "opt_level": "3",
            "debug": 0,
            "debug_assertions": False,
            "incremental": False,
            "strip": "symbols",
        }
        or build_policy
        != {
            "cargo_incremental": "0",
            "normalized_rustflags": list(DAEMON_NORMALIZED_RUSTFLAGS),
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
        }
        or target_profile
        != {
            "rust_target_triple": "aarch64-unknown-linux-gnu",
            "architecture": "aarch64",
            "operating_system": "linux",
            "libc_family": "glibc",
            "dynamic_interpreter": "/lib/ld-linux-aarch64.so.1",
            "maximum_glibc": "GLIBC_2.36",
            "runtime_base_contract": "debian-bookworm-arm64",
        }
        or toolchain_snapshot
        != {
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
        or stable
        != {
            "authority": "stable_principal_registry_v2",
            "contract_sha256": STABLE_PRINCIPAL_CONTRACT_SHA256,
            "canonical_sha256": STABLE_PRINCIPAL_CANONICAL_SHA256,
        }
        or identity_hold
        != {
            "schema": "org.trillionnium.p01-userdebug-identity-independence-hold.v1",
            "status": "hold_identity_independence_evidence_unverified",
            "profile_sha256": sha256_bytes(canonical_json_bytes(gate)),
        }
    ):
        raise VerificationError("P01 daemon build binding profile differs")
    for role, record in artifacts.items():
        if role in runtime and runtime[role] != record["sha256"]:
            raise VerificationError(
                f"P01 daemon build binding {role} differs from its artifact"
            )
    return binding


def validate_artifact_record(
    value: object, role: str, expected_file: str
) -> dict[str, object]:
    record = exact_object(value, LAUNCHER_ARTIFACT_FIELDS, f"launcher artifact {role}")
    if (
        record["file"] != expected_file
        or type(record["bytes"]) is not int
        or not 1 <= record["bytes"] <= MAX_ARTIFACT_BYTES
    ):
        raise VerificationError(f"launcher artifact {role} binding is malformed")
    validate_sha256(record["sha256"], f"launcher artifact {role}")
    return record


def common_receipt_fields() -> set[str]:
    return {
        "schema",
        "receipt_role",
        "status",
        "product_variant",
        "common_direct_tool_posture",
        "stable_principal_launcher_measurement",
        "legacy_descriptor_contamination_hold_gate",
        "accessibility_available",
        "dependency_graph",
        "source_bom",
        "compiler",
        "elf_inspector",
        "toolchain_snapshot",
        "target_compiler_closure",
        "inputs",
        "artifacts",
        "rootfs_build_required",
        "device_execution_verified",
        "release_allowed",
    }


def p01_receipt_fields() -> set[str]:
    return {
        "schema",
        "receipt_role",
        "status",
        "product_variant",
        "selected_system_api_sha256",
        "principal_authority",
        "legacy_descriptor_executable_identity_is_principal_authority",
        "runtime_policy_launcher_measurement_migration",
        "product_effect_authority_available",
        "accessibility_available",
        "dependency_graph",
        "source_bom",
        "daemon_build_binding",
        "stable_principal_launcher_measurement",
        "legacy_descriptor_contamination_hold_gate",
        "compiler",
        "elf_inspector",
        "inputs",
        "artifacts",
        "daemon_build_required",
        "device_execution_verified",
        "release_allowed",
    }


def validate_launcher_build_tool(value: object, role: str) -> dict[str, object]:
    tool = exact_object(value, BUILD_TOOL_FIELDS, f"launcher {role}")
    execution = exact_object(
        tool["execution"], BUILD_TOOL_EXECUTION_FIELDS, f"launcher {role} execution"
    )
    path = tool["path"]
    if (
        tool["schema"] != LAUNCHER_BUILD_TOOL_SCHEMA
        or tool["role"] != role
        or type(path) is not str
        or not path.startswith("/")
        or os.path.normpath(path) != path
        or any(part in {"", ".", ".."} for part in path.split("/")[1:])
        or type(tool["bytes"]) is not int
        or not 1 <= tool["bytes"] <= MAX_COMPILER_BYTES
        or type(tool["mode"]) is not str
        or re.fullmatch(r"0[0-7]{3}", tool["mode"]) is None
        or int(tool["mode"], 8) & 0o022
        or not int(tool["mode"], 8) & 0o100
        or type(tool["uid"]) is not int
        or tool["uid"] < 0
        or type(tool["gid"]) is not int
        or tool["gid"] < 0
        or tool["link_count"] != 1
        or type(tool["version"]) is not str
        or not tool["version"]
        or "\x00" in tool["version"]
        or tool["target"] != LAUNCHER_BUILD_TOOL_TARGET
        or tool["complete_recursive_toolchain_closure"] is not False
    ):
        raise VerificationError(f"launcher {role} custody is malformed")
    validate_sha256(tool["sha256"], f"launcher {role}")
    if execution != {
        "mechanism": "retained_open_file_description_via_proc_self_fd",
        "measured_before_first_execution": True,
        "all_invocations_used_same_open_file_description": True,
        "descriptor_and_path_stable_after_last_execution": True,
        "ambient_environment_inherited": False,
        "environment_allowlist": LAUNCHER_BUILD_ENVIRONMENT_ALLOWLIST,
    }:
        raise VerificationError(f"launcher {role} execution custody differs")
    return tool


def validate_toolchain_snapshot(value: object) -> dict[str, object]:
    snapshot = exact_object(
        value,
        {
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
        },
        "launcher toolchain snapshot",
    )
    expected = {
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
    if snapshot != expected:
        raise VerificationError("launcher toolchain snapshot differs")
    return snapshot


def launcher_target_toolchain_layout(
    compiler: dict[str, object],
    elf_inspector: dict[str, object],
    snapshot: dict[str, object],
    label: str,
) -> dict[str, Path]:
    compiler_path = Path(str(compiler["path"]))
    compiler_relative = Path(str(snapshot["target_compiler_relative_path"]))
    if len(compiler_path.parents) < len(compiler_relative.parts):
        raise VerificationError(f"{label} compiler is outside the fixed snapshot layout")
    lane_root = compiler_path.parents[len(compiler_relative.parts) - 1]
    if compiler_path != lane_root / compiler_relative:
        raise VerificationError(f"{label} compiler is outside the fixed snapshot layout")
    target_toolchain_root = lane_root / "toolchain"
    target_sysroot = lane_root / str(snapshot["target_sysroot_relative_path"])
    expected_inspector = (
        target_sysroot / "usr/bin/aarch64-linux-gnu-readelf"
    )
    inspector_path = Path(str(elf_inspector["path"]))
    if inspector_path != expected_inspector:
        raise VerificationError(
            f"{label} ELF inspector is outside the fixed snapshot layout"
        )
    return {
        "target_toolchain_root": target_toolchain_root,
        "target_sysroot": target_sysroot,
        "compiler": compiler_path,
        "archiver": target_sysroot / "usr/bin/aarch64-linux-gnu-ar",
        "readelf": inspector_path,
    }


def validate_launcher_receipt(
    receipt: dict[str, object], raw: bytes, lane: str, raw_receipt: dict[str, object]
) -> dict[str, object]:
    specification = LANES[lane]
    expected_fields = common_receipt_fields() if lane == "common" else p01_receipt_fields()
    exact_object(receipt, expected_fields, "launcher builder receipt")
    if raw != canonical_json_bytes(receipt):
        raise VerificationError("launcher builder receipt is not canonical JSON")
    if (
        receipt["schema"] != specification["schema"]
        or receipt["status"] != "host_built_device_evidence_hold"
        or receipt["product_variant"] != specification["variant"]
        or receipt["device_execution_verified"] is not False
        or receipt["release_allowed"] is not False
        or receipt["accessibility_available"] is not False
    ):
        raise VerificationError("launcher builder receipt header or HOLD posture differs")
    if lane == "common":
        if (
            receipt["receipt_role"] != "common_rootfs_complete_measured_build_input"
            or receipt["common_direct_tool_posture"]
            != "inert_no_default_features_fail_closed"
            or receipt["rootfs_build_required"] is not True
            or receipt["dependency_graph"] != COMMON_DEPENDENCY_GRAPH
        ):
            raise VerificationError("common launcher receipt semantics differ")
    else:
        if (
            receipt["receipt_role"] != "final_daemon_build_binding_envelope"
            or receipt["principal_authority"] != "stable_principal_registry_v2"
            or receipt["legacy_descriptor_executable_identity_is_principal_authority"]
            is not False
            or receipt["runtime_policy_launcher_measurement_migration"]
            != "active_launcher_separate_from_stable_principal"
            or receipt["product_effect_authority_available"] is not False
            or receipt["daemon_build_required"] is not True
            or receipt["dependency_graph"] != P01_DEPENDENCY_GRAPH
        ):
            raise VerificationError("P01 launcher receipt semantics differ")
    source = validate_launcher_source(
        receipt["source_bom"], raw_receipt["source_bom"]
    )
    compiler = validate_launcher_build_tool(receipt["compiler"], "compiler_driver")
    elf_inspector = validate_launcher_build_tool(
        receipt["elf_inspector"], "elf_inspector"
    )
    toolchain_snapshot = (
        validate_toolchain_snapshot(receipt["toolchain_snapshot"])
        if lane == "common"
        else validate_toolchain_snapshot(
            receipt["daemon_build_binding"]["toolchain_snapshot"]
        )
    )
    target_compiler_closure = validate_target_compiler_closure(
        receipt["target_compiler_closure"]
        if lane == "common"
        else receipt["daemon_build_binding"]["target_compiler_closure"]
    )
    raw_target_compiler_closure = validate_target_compiler_closure(
        raw_receipt["target_compiler_closure"]
    )
    raw_toolchain_snapshot = validate_toolchain_snapshot(
        raw_receipt["toolchain_snapshot"]
    )
    if toolchain_snapshot != raw_toolchain_snapshot:
        raise VerificationError(
            "launcher toolchain snapshot differs from raw A/B evidence"
        )
    if target_compiler_closure != raw_target_compiler_closure:
        raise VerificationError(
            "launcher target compiler closure differs from raw A/B evidence"
        )
    input_fields = {
        "codex_runtime_sha256",
        "codex_runtime_bytes",
        "codex_launcher_source_sha256",
        *set(specification["raw_roles"].values()),
    }
    inputs = exact_object(receipt["inputs"], input_fields, "launcher inputs")
    for field, value in inputs.items():
        if field.endswith("_sha256"):
            validate_sha256(value, f"launcher input {field}")
    if (
        inputs["codex_runtime_sha256"] != CODEX_RUNTIME_SHA256
        or inputs["codex_runtime_bytes"] != CODEX_RUNTIME_BYTES
    ):
        raise VerificationError("launcher Codex runtime byte count is malformed")
    artifacts = exact_object(
        receipt["artifacts"], set(specification["artifacts"]), "launcher artifacts"
    )
    for role, filename in specification["artifacts"].items():
        validate_artifact_record(artifacts[role], role, str(filename))
    launcher_sha = artifacts["codex_launcher"]["sha256"]
    measurement = validate_stable_measurement(
        receipt["stable_principal_launcher_measurement"], launcher_sha
    )
    gate = validate_unresolved_gate(
        receipt["legacy_descriptor_contamination_hold_gate"]
    )
    daemon_binding = (
        validate_daemon_build_binding(receipt["daemon_build_binding"], artifacts, gate)
        if lane == "p01_userdebug_pre_daemon"
        else None
    )
    raw_artifacts = raw_receipt["artifacts"]
    for role, input_field in specification["raw_roles"].items():
        raw_record = raw_artifacts[role]
        launcher_record = artifacts[role]
        if (
            inputs[input_field] != raw_record["sha256"]
            or launcher_record["sha256"] != raw_record["sha256"]
            or launcher_record["bytes"] != raw_record["bytes"]
            or launcher_record["file"] != raw_record["file"]
        ):
            raise VerificationError(
                f"launcher input/artifact and raw A/B artifact {role} are not bidirectionally bound"
            )
    if (
        lane == "p01_userdebug_pre_daemon"
        and receipt["selected_system_api_sha256"]
        != inputs["system_api_tool_input_sha256"]
    ):
        raise VerificationError("P01 selected System API digest differs from its input")
    return {
        "source": source,
        "compiler": compiler,
        "elf_inspector": elf_inspector,
        "toolchain_snapshot": toolchain_snapshot,
        "target_compiler_closure": target_compiler_closure,
        "inputs": inputs,
        "artifacts": artifacts,
        "measurement": measurement,
        "gate": gate,
        "daemon_build_binding": daemon_binding,
    }


def validate_aarch64_elf(value: bytes, label: str) -> None:
    if (
        len(value) < 64
        or value[:4] != b"\x7fELF"
        or value[4] != 2
        or value[5] != 1
        or int.from_bytes(value[18:20], "little") != 183
    ):
        raise VerificationError(f"{label} is not an AArch64 ELF64 file")


def corroborate_launcher_build_tool(
    tool: dict[str, object],
    raw_tool: dict[str, object],
    *,
    label: str,
    raw_role: str,
) -> tuple[dict[str, object], tuple[int, ...], RetainedAbsoluteRegular]:
    value, identity, mode, retained = read_absolute_regular(
        Path(str(tool["path"])), label=label, maximum=MAX_COMPILER_BYTES
    )
    try:
        raw_version_first_line = str(raw_tool["version"]).splitlines()[0]
        if (
            len(value) != tool["bytes"]
            or sha256_bytes(value) != tool["sha256"]
            or mode != tool["mode"]
            or identity[2] != tool["uid"]
            or identity[3] != tool["gid"]
            or identity[5] != tool["link_count"]
            or len(value) != raw_tool["bytes"]
            or sha256_bytes(value) != raw_tool["sha256"]
            or mode != raw_tool["mode"]
            or tool["version"] != raw_version_first_line
        ):
            raise VerificationError(
                f"{label} differs from build-time custody or raw A/B tool identity"
            )
        result = {
            "schema": tool["schema"],
            "role": tool["role"],
            "bytes": len(value),
            "sha256": sha256_bytes(value),
            "mode": mode,
            "uid": identity[2],
            "gid": identity[3],
            "link_count": identity[5],
            "version": tool["version"],
            "target": tool["target"],
            "execution": tool["execution"],
            "build_time_bytes_bound_by_upstream_receipt": True,
            "complete_recursive_toolchain_closure": False,
        }
        result[f"post_build_matches_raw_ab_selected_{raw_role}"] = True
        return result, identity, retained
    except BaseException:
        retained.close()
        raise


def corroborate_target_archiver(
    path: Path,
    raw_tool: dict[str, object],
    *,
    label: str,
) -> tuple[dict[str, object], tuple[int, ...], RetainedAbsoluteRegular]:
    value, identity, mode, retained = read_absolute_regular(
        path,
        label=label,
        maximum=MAX_COMPILER_BYTES,
    )
    try:
        if (
            len(value) != raw_tool["bytes"]
            or sha256_bytes(value) != raw_tool["sha256"]
            or mode != raw_tool["mode"]
        ):
            raise VerificationError(f"{label} differs from raw A/B selected ar")
        return (
            {
                "bytes": len(value),
                "sha256": sha256_bytes(value),
                "mode": mode,
                "post_build_matches_raw_ab_selected_ar": True,
            },
            identity,
            retained,
        )
    except BaseException:
        retained.close()
        raise


def read_launcher_lane(
    directory_fd: int,
    directory_initial: os.stat_result,
    receipt_name: str,
    lane: str,
    raw_receipt: dict[str, object],
    label: str,
) -> dict[str, object]:
    retained_physical: list[
        tuple[
            RetainedAbsoluteDirectory
            | RetainedAbsoluteRegular
            | RetainedRelativeInputFile,
            tuple[int, ...],
            str,
        ]
    ] = []
    completed = False
    try:
        result = _read_launcher_lane_with_retained_custody(
            directory_fd,
            directory_initial,
            receipt_name,
            lane,
            raw_receipt,
            label,
            retained_physical,
        )
        completed = True
        return result
    finally:
        if not completed:
            for retained, _identity, _label in reversed(retained_physical):
                retained.close()


def _read_launcher_lane_with_retained_custody(
    directory_fd: int,
    directory_initial: os.stat_result,
    receipt_name: str,
    lane: str,
    raw_receipt: dict[str, object],
    label: str,
    retained_physical: list[
        tuple[
            RetainedAbsoluteDirectory
            | RetainedAbsoluteRegular
            | RetainedRelativeInputFile,
            tuple[int, ...],
            str,
        ]
    ],
) -> dict[str, object]:
    specification = LANES[lane]
    if receipt_name != specification["receipt"]:
        raise VerificationError(f"{label} launcher receipt filename differs from its lane")
    receipt_file = RetainedRelativeInputFile.open(
        directory_fd,
        receipt_name,
        label=f"{label} launcher receipt",
        maximum=MAX_RECEIPT_BYTES,
        mode=0o444,
    )
    receipt_raw = receipt_file.initial_bytes
    receipt_identity = stable_identity(receipt_file.initial_metadata)
    retained_physical.append(
        (receipt_file, receipt_identity, f"{label} launcher receipt")
    )
    receipt = strict_json(receipt_raw, f"{label} launcher receipt")
    validated = validate_launcher_receipt(receipt, receipt_raw, lane, raw_receipt)
    expected_names = {receipt_name, *map(str, specification["artifacts"].values())}
    if set(os.listdir(directory_fd)) != expected_names:
        raise VerificationError(f"{label} launcher directory and receipt inventory differ")
    artifacts: dict[str, bytes] = {}
    artifact_identities: dict[str, tuple[int, ...]] = {}
    identities: dict[str, tuple[int, ...]] = {receipt_name: receipt_identity}
    for role, filename_object in specification["artifacts"].items():
        filename = str(filename_object)
        artifact_file = RetainedRelativeInputFile.open(
            directory_fd,
            filename,
            label=f"{label} launcher artifact {role}",
            maximum=MAX_ARTIFACT_BYTES,
            mode=0o555,
        )
        artifact = artifact_file.initial_bytes
        identity = stable_identity(artifact_file.initial_metadata)
        retained_physical.append(
            (artifact_file, identity, f"{label} launcher artifact {role}")
        )
        validate_aarch64_elf(artifact, f"{label} launcher artifact {role}")
        record = validated["artifacts"][role]
        if record["bytes"] != len(artifact) or record["sha256"] != sha256_bytes(artifact):
            raise VerificationError(
                f"{label} launcher artifact {role} differs from its receipt"
            )
        artifacts[role] = artifact
        artifact_identities[role] = identity
        identities[filename] = identity
    launcher = artifacts["codex_launcher"]
    embedded_input_digests = [validated["inputs"]["codex_runtime_sha256"]]
    embedded_input_digests.append(
        validated["inputs"]["system_api_tool_input_sha256"]
    )
    if lane == "common":
        embedded_input_digests.append(
            validated["inputs"]["accessibility_tool_input_sha256"]
        )
    if any(str(digest).encode("ascii") not in launcher for digest in embedded_input_digests):
        raise VerificationError(
            f"{label} launcher omits a receipt-bound runtime/tool digest"
        )
    for digest_label, digest in validated["gate"]["digests"].items():
        encoded = str(digest).encode("ascii")
        for role, artifact in artifacts.items():
            if encoded in artifact:
                raise VerificationError(
                    f"{label} artifact {role} embeds legacy identity digest {digest_label}"
                )
    if stable_identity(os.fstat(directory_fd)) != stable_identity(directory_initial):
        raise VerificationError(f"{label} launcher directory changed while read")
    try:
        compiler, compiler_identity, compiler_custody = corroborate_launcher_build_tool(
            validated["compiler"],
            raw_receipt["selected_tool_identities"]["linker"],
            label=f"{label} launcher compiler",
            raw_role="linker",
        )
        retained_physical.append(
            (compiler_custody, compiler_identity, f"{label} launcher compiler")
        )
        elf_inspector, inspector_identity, inspector_custody = (
            corroborate_launcher_build_tool(
                validated["elf_inspector"],
                raw_receipt["selected_tool_identities"]["readelf"],
                label=f"{label} launcher ELF inspector",
                raw_role="readelf",
            )
        )
        retained_physical.append(
            (inspector_custody, inspector_identity, f"{label} launcher ELF inspector")
        )
        layout = launcher_target_toolchain_layout(
            validated["compiler"],
            validated["elf_inspector"],
            validated["toolchain_snapshot"],
            label,
        )
        target_toolchain_root_identity, target_toolchain_root_custody = (
            read_absolute_directory_identity(
                layout["target_toolchain_root"],
                f"{label} target toolchain root",
            )
        )
        retained_physical.append(
            (
                target_toolchain_root_custody,
                target_toolchain_root_identity,
                f"{label} target toolchain root",
            )
        )
        target_sysroot_identity, target_sysroot_custody = read_absolute_directory_identity(
            layout["target_sysroot"],
            f"{label} target sysroot",
        )
        retained_physical.append(
            (
                target_sysroot_custody,
                target_sysroot_identity,
                f"{label} target sysroot",
            )
        )
        target_archiver, archiver_identity, archiver_custody = (
            corroborate_target_archiver(
                layout["archiver"],
                raw_receipt["selected_tool_identities"]["ar"],
                label=f"{label} target archiver",
            )
        )
        retained_physical.append(
            (archiver_custody, archiver_identity, f"{label} target archiver")
        )
        selected_target_tool_identities = {
            "compiler": compiler_identity,
            "archiver": archiver_identity,
            "readelf": inspector_identity,
        }
        token = sha256_bytes(
            canonical_json_bytes(
                {
                    "receipt_sha256": sha256_bytes(receipt_raw),
                    "files": {
                        name: list(identity)
                        for name, identity in sorted(identities.items())
                    },
                    "compiler_identity": list(compiler_identity),
                    "compiler_sha256": compiler["sha256"],
                    "elf_inspector_identity": list(inspector_identity),
                    "elf_inspector_sha256": elf_inspector["sha256"],
                    "target_archiver_identity": list(archiver_identity),
                    "target_archiver_sha256": target_archiver["sha256"],
                    "target_toolchain_root_identity": list(
                        target_toolchain_root_identity
                    ),
                    "target_sysroot_identity": list(target_sysroot_identity),
                }
            )
        )
        normalized_receipt = json.loads(json.dumps(receipt))
        normalized_receipt["compiler"].pop("path")
        normalized_receipt["elf_inspector"].pop("path")
        return {
            "receipt": receipt,
            "receipt_raw": receipt_raw,
            "validated": validated,
            "artifacts": artifacts,
            "artifact_identities": artifact_identities,
            "compiler": compiler,
            "elf_inspector": elf_inspector,
            "target_archiver": target_archiver,
            "target_toolchain_root_identity": target_toolchain_root_identity,
            "target_sysroot_identity": target_sysroot_identity,
            "selected_target_tool_identities": selected_target_tool_identities,
            "normalized_receipt": normalized_receipt,
            "stable_token": token,
            "retained_physical": retained_physical,
        }
    except BaseException:
        for retained, _identity, _label in reversed(retained_physical):
            retained.close()
        retained_physical.clear()
        raise


def read_raw_aggregate(
    directory_fd: int,
    directory_initial: os.stat_result,
    name: str,
    lane: str,
) -> dict[str, object]:
    if name != "codex-only-raw-elf-ab.v3.json":
        raise VerificationError("raw A/B receipt filename differs")
    if set(os.listdir(directory_fd)) != {name}:
        raise VerificationError("raw A/B receipt directory inventory is not closed")
    retained = RetainedRelativeInputFile.open(
        directory_fd,
        name,
        label="raw ELF A/B aggregate receipt",
        maximum=MAX_RECEIPT_BYTES,
        mode=0o444,
    )
    try:
        raw = retained.initial_bytes
        identity = stable_identity(retained.initial_metadata)
        receipt = strict_json(raw, "raw ELF A/B aggregate receipt")
        validate_raw_aggregate(receipt, raw, lane)
        if stable_identity(os.fstat(directory_fd)) != stable_identity(directory_initial):
            raise VerificationError("raw A/B receipt directory changed while read")
        return {
            "receipt": receipt,
            "raw": raw,
            "identity": identity,
            "stable_token": sha256_bytes(
                canonical_json_bytes(
                    {
                        "identity": list(identity),
                        "sha256": sha256_bytes(raw),
                    }
                )
            ),
            "retained_physical": [
                (retained, identity, "raw ELF A/B aggregate receipt")
            ],
        }
    except BaseException:
        retained.close()
        raise


def assert_retained_physical_stable(lanes: Sequence[dict[str, object]]) -> None:
    for lane in lanes:
        retained = lane.get("retained_physical")
        if not isinstance(retained, list):
            raise VerificationError("launcher physical custody set is missing")
        for custody, identity, label in retained:
            custody.assert_stable()
            if stable_identity(custody.initial_metadata) != identity:
                raise VerificationError(f"{label} changed while retained")


def close_retained_physical(lanes: Sequence[dict[str, object]]) -> None:
    for lane in reversed(lanes):
        retained = lane.get("retained_physical")
        if isinstance(retained, list):
            for custody, _identity, _label in reversed(retained):
                custody.close()
            retained.clear()


def ensure_separate(paths: Sequence[Path]) -> None:
    if len(set(paths)) != len(paths):
        raise VerificationError("launcher A/B, raw receipt, and output directories must differ")
    for parent in paths:
        for child in paths:
            if parent == child:
                continue
            try:
                child.relative_to(parent)
            except ValueError:
                continue
            raise VerificationError("input and output directories may not contain each other")


def write_exclusive_at(
    directory: int, name: str, value: bytes
) -> RetainedPublishedFile:
    try:
        descriptor = os.open(
            name,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o444,
            dir_fd=directory,
        )
    except OSError as error:
        raise VerificationError("launcher aggregate receipt publication failed") from error
    completed = False
    try:
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise VerificationError("launcher aggregate receipt short write")
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
            raise VerificationError("published launcher aggregate receipt differs")
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


def finalize_receipt(receipt: dict[str, object]) -> bytes:
    receipt["receipt_id_scope"] = RECEIPT_ID_SCOPE
    receipt["receipt_id"] = "sha256:" + sha256_bytes(canonical_json_bytes(receipt))
    return canonical_json_bytes(receipt)


def verify(args: argparse.Namespace) -> dict[str, object]:
    lane = args.lane
    if lane not in LANES:
        raise VerificationError("launcher lane is unsupported")
    a_path, a_fd, a_initial, a_custody = open_directory(
        args.a_artifact_dir, "A launcher artifact directory", empty=False
    )
    try:
        b_path, b_fd, b_initial, b_custody = open_directory(
            args.b_artifact_dir, "B launcher artifact directory", empty=False
        )
        try:
            raw_parent_argument = Path(args.raw_ab_receipt).parent
            raw_path, raw_fd, raw_initial, raw_custody = open_directory(
                raw_parent_argument, "raw A/B receipt directory", empty=False
            )
            try:
                output_path, output_fd, output_initial, output_custody = open_directory(
                    args.output_dir, "output directory", empty=True
                )
                retained_lanes: list[dict[str, object]] = []
                published_output: RetainedPublishedFile | None = None
                publication_succeeded = False
                try:
                    if len(
                        {
                            device_inode(metadata)
                            for metadata in (
                                a_initial,
                                b_initial,
                                raw_initial,
                                output_initial,
                            )
                        }
                    ) != 4:
                        raise VerificationError(
                            "launcher A/B, raw receipt, or output directories reuse the "
                            "same physical directory"
                        )
                    ensure_separate((a_path, b_path, raw_path, output_path))
                    a_name = direct_child_name(args.a_receipt, a_path, "A receipt")
                    b_name = direct_child_name(args.b_receipt, b_path, "B receipt")
                    raw_name = direct_child_name(
                        args.raw_ab_receipt, raw_path, "raw A/B receipt"
                    )
                    raw_aggregate = read_raw_aggregate(
                        raw_fd, raw_initial, raw_name, lane
                    )
                    retained_lanes.append(raw_aggregate)
                    raw_receipt = raw_aggregate["receipt"]
                    a = read_launcher_lane(
                        a_fd, a_initial, a_name, lane, raw_receipt, "A"
                    )
                    retained_lanes.append(a)
                    b = read_launcher_lane(
                        b_fd, b_initial, b_name, lane, raw_receipt, "B"
                    )
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
                        raise VerificationError(
                            "A/B launcher input artifacts reuse one or more physical inodes"
                        )
                    if device_inode(
                        a["target_toolchain_root_identity"]
                    ) == device_inode(b["target_toolchain_root_identity"]):
                        raise VerificationError(
                            "A/B launcher target toolchain roots are the same physical directory"
                        )
                    if device_inode(a["target_sysroot_identity"]) == device_inode(
                        b["target_sysroot_identity"]
                    ):
                        raise VerificationError(
                            "A/B launcher target sysroots are the same physical directory"
                        )
                    if not {
                        device_inode(identity)
                        for identity in a["selected_target_tool_identities"].values()
                    }.isdisjoint(
                        {
                            device_inode(identity)
                            for identity in b["selected_target_tool_identities"].values()
                        }
                    ):
                        raise VerificationError(
                            "A/B launcher selected target tools reuse one or more "
                            "physical inodes"
                        )
                    if a["normalized_receipt"] != b["normalized_receipt"]:
                        raise VerificationError(
                            "A/B launcher receipts differ beyond compiler-local path"
                        )
                    if a["compiler"] != b["compiler"]:
                        raise VerificationError("A/B launcher compiler identities differ")
                    if a["elf_inspector"] != b["elf_inspector"]:
                        raise VerificationError(
                            "A/B launcher ELF inspector identities differ"
                        )
                    if a["target_archiver"] != b["target_archiver"]:
                        raise VerificationError(
                            "A/B launcher target archiver identities differ"
                        )
                    specification = LANES[lane]
                    for role in specification["artifacts"]:
                        if a["artifacts"][role] != b["artifacts"][role]:
                            raise VerificationError(
                                f"A/B launcher artifact bytes differ for role {role}"
                            )
                    receipt: dict[str, object] = {
                        "schema": specification["output_schema"],
                        "decision": OUTPUT_DECISION,
                        "status": OUTPUT_HOLD,
                        "release_status": OUTPUT_HOLD,
                        "release_allowed": False,
                        "lane": lane,
                        "product_variant": specification["variant"],
                        "target": TARGET,
                        "source_bom": a["validated"]["source"],
                        "raw_elf_ab": {
                            "file": raw_name,
                            "bytes": len(raw_aggregate["raw"]),
                            "sha256": sha256_bytes(raw_aggregate["raw"]),
                            "receipt_id": raw_receipt["receipt_id"],
                            "lane": raw_receipt["lane"],
                            "decision": raw_receipt["decision"],
                            "release_status": raw_receipt["release_status"],
                        },
                        "launcher_inputs": {
                            "a": {
                                "receipt_file": a_name,
                                "receipt_bytes": len(a["receipt_raw"]),
                                "receipt_sha256": sha256_bytes(a["receipt_raw"]),
                            },
                            "b": {
                                "receipt_file": b_name,
                                "receipt_bytes": len(b["receipt_raw"]),
                                "receipt_sha256": sha256_bytes(b["receipt_raw"]),
                            },
                        },
                        "builder_inputs": a["validated"]["inputs"],
                        "compiler": {
                            **a["compiler"],
                            "a_b_byte_equal": True,
                        },
                        "elf_inspector": {
                            **a["elf_inspector"],
                            "a_b_byte_equal": True,
                        },
                        "toolchain_snapshot": a["validated"]["toolchain_snapshot"],
                        "target_compiler_closure": a["validated"][
                            "target_compiler_closure"
                        ],
                        "stable_principal_launcher_measurement": a["validated"][
                            "measurement"
                        ],
                        "identity_independence_gate": a["validated"]["gate"],
                        "artifacts": {
                            role: {
                                "file": a["receipt"]["artifacts"][role]["file"],
                                "bytes": len(a["artifacts"][role]),
                                "sha256": sha256_bytes(a["artifacts"][role]),
                                "a_receipt_bound": True,
                                "b_receipt_bound": True,
                                "raw_ab_bound": role in specification["raw_roles"],
                                "a_b_byte_equal": True,
                            }
                            for role in specification["artifacts"]
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
                    }
                    if lane == "p01_userdebug_pre_daemon":
                        receipt["daemon_build_binding"] = a["validated"][
                            "daemon_build_binding"
                        ]
                    output_raw = finalize_receipt(receipt)
                    raw_second = read_raw_aggregate(raw_fd, raw_initial, raw_name, lane)
                    retained_lanes.append(raw_second)
                    a_second = read_launcher_lane(
                        a_fd, a_initial, a_name, lane, raw_receipt, "A"
                    )
                    retained_lanes.append(a_second)
                    b_second = read_launcher_lane(
                        b_fd, b_initial, b_name, lane, raw_receipt, "B"
                    )
                    retained_lanes.append(b_second)
                    if (
                        raw_second["stable_token"] != raw_aggregate["stable_token"]
                        or a_second["stable_token"] != a["stable_token"]
                        or b_second["stable_token"] != b["stable_token"]
                    ):
                        raise VerificationError(
                            "raw or launcher A/B inputs changed before publication"
                        )
                    for custody in (a_custody, b_custody, raw_custody):
                        custody.assert_stable()
                    output_custody.assert_stable()
                    assert_retained_physical_stable(retained_lanes)
                    published_output = write_exclusive_at(
                        output_fd, str(specification["output_name"]), output_raw
                    )
                    os.fsync(output_fd)
                    for custody in (a_custody, b_custody, raw_custody):
                        custody.assert_stable()
                    output_custody.assert_stable()
                    assert_retained_physical_stable(retained_lanes)
                    if stable_identity(os.fstat(output_fd))[:6] != stable_identity(
                        output_initial
                    )[:6]:
                        raise VerificationError("output directory identity changed")
                    if os.listdir(output_fd) != [str(specification["output_name"])]:
                        raise VerificationError(
                            "output directory inventory is not the exact launcher aggregate"
                        )
                    published_output.assert_stable()
                    output_custody.assert_stable()
                    publication_succeeded = True
                    return receipt
                finally:
                    try:
                        close_retained_physical(retained_lanes)
                    finally:
                        try:
                            if published_output is not None:
                                try:
                                    if not publication_succeeded:
                                        published_output.unlink_if_current()
                                finally:
                                    published_output.close()
                        finally:
                            output_custody.close()
            finally:
                raw_custody.close()
        finally:
            b_custody.close()
    finally:
        a_custody.close()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lane", choices=tuple(LANES), required=True)
    parser.add_argument("--a-artifact-dir", type=Path, required=True)
    parser.add_argument("--a-receipt", type=Path, required=True)
    parser.add_argument("--b-artifact-dir", type=Path, required=True)
    parser.add_argument("--b-receipt", type=Path, required=True)
    parser.add_argument("--raw-ab-receipt", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        receipt = verify(parse_args(argv))
    except VerificationError as error:
        print(f"Codex launcher A/B verification error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, allow_nan=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
