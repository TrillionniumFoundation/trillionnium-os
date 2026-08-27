#!/usr/bin/env python3
"""Materialize one frozen rootfs packager contract without touching artifacts."""

from __future__ import annotations

import argparse
import copy
import ctypes
import hashlib
import json
import os
import re
import stat
import struct
import sys
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, NoReturn


CONTRACT_SCHEMA = "org.trillionnium.rootfs-package.contract.v9"
CONTRACT_DECISION = "HOLD_IDENTITY_INDEPENDENCE_EVIDENCE_UNVERIFIED"
CONTRACT_STATUS = "hold_identity_independence_evidence_unverified"
COMMON_ARTIFACT_SET_SCHEMA = (
    "org.trillionnium.common-codex-rootfs-artifact-set.v5"
)
COMMON_ARTIFACT_SET_STATUS = "host_built_device_evidence_hold"
COMMON_ARTIFACT_SET_FILE = "common-codex-rootfs-artifact-set.v5.json"
COMMON_LAUNCHER_AB_SCHEMA = "org.trillionnium.codex-launcher-artifact-set-ab.v4"
COMMON_LAUNCHER_AB_FILE = "codex-launcher-artifact-set-ab.v4.json"
COMMON_LAUNCHER_AB_DECISION = (
    "PASS_HOST_ONLY_DETERMINISTIC_CODEX_LAUNCHER_ARTIFACT_SET_AB"
)
COMMON_LAUNCHER_AB_HOLD = (
    "HOLD_IDENTITY_INDEPENDENCE_PRODUCT_DEVICE_AND_COMPLETE_TOOLCHAIN_ADMISSION"
)
COMMON_LAUNCHER_AB_RECEIPT_ID_SCOPE = (
    "sha256(canonical-json-utf8-sort-keys-indent-2-lf-without-receipt_id)"
)
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
STABLE_PRINCIPAL_CONTRACT_SHA256 = (
    "3e9bfcb04e48062c20bd7407635c1a27086a0de8c2fa5ca73963c946b984095b"
)
STABLE_PRINCIPAL_CANONICAL_SHA256 = (
    "a9c224116123deb49908beda3ab047fc98d6917cfeb62d60364033858cc57153"
)
EXPECTED_LEGACY_DESCRIPTOR_DIGESTS = {
    "canonical digest": "bc6c64abbb893e6e75ed708f87cf864e6c8f7503381371dc394409bddc4009c2",
    "contract digest": "5ecd89d3c9fedbbeb0ac1de32fba2b5e5e5d248048ddc9a9e0359a0a01903119",
    "launcher identity": "edcf9d31da8b48d29575115a7242691c1337174edf42573b7274b652a4cd571c",
}
VERSION_MARKER = "REPLACE_WITH_VERSION"
ZERO_SHA256 = "0" * 64
SYSTEM_API_REPLAY_SYNC_INSTALL_PATH = (
    "usr/local/bin/trillionnium-system-api-replay-sync"
)
EXTERNAL_EFFECT_TOOLS = {
    "system_api_tool": {
        "artifact": "system_api_tool",
        "file": "trillionnium-agent-system-api",
        "install_path": "usr/local/bin/trillionnium-agent-system-api",
    },
    "accessibility_tool": {
        "artifact": "accessibility_tool",
        "file": "trillionnium-agent-accessibility",
        "install_path": "usr/local/bin/trillionnium-agent-accessibility",
    },
}
MIGRATION_FIELDS = (
    "legacy_duplicate_directory_migrations",
    "legacy_prune_members",
    "legacy_raw_name_prune_members",
)
NULLABLE_MIGRATION_FIELDS = ("legacy_absolute_symlink_migration",)
TOP_LEVEL_FIELDS = {
    "admission",
    "common_build_evidence",
    "schema",
    "source_date_epoch",
    "compression",
    "limits",
    "runtime",
    "inputs",
    "security",
    "tools",
}
INPUT_FIELDS = {
    "base_rootfs",
    "common_artifact_set_receipt",
    "common_launcher_ab_receipt",
    "daemon",
    "codex",
    "system_api_tool",
    "accessibility_tool",
    "system_api_replay_sync",
    "agent_manifest",
}
SECURITY_FIELDS = {
    "forbidden_path_patterns",
    "forbidden_content_markers",
    *MIGRATION_FIELDS,
    *NULLABLE_MIGRATION_FIELDS,
    "replacement_hardlink_allowlist",
}
MAX_TEMPLATE_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_COMMON_RECEIPT_BYTES = 1024 * 1024
MAX_LAUNCHER_AB_RECEIPT_BYTES = 16 * 1024 * 1024
MAX_BINARY_BYTES = 16 * 1024 * 1024 * 1024
MAX_HOST_TOOL_BYTES = 1024 * 1024 * 1024
MAX_BASE_BYTES = 4 * 1024 * 1024 * 1024 * 1024
MAX_SOURCE_DATE_EPOCH = 4_102_444_800
EM_AARCH64 = 183
PT_INTERP = 3
REQUIRED_FORBIDDEN_CONTENT_MARKERS = (
    "TRILLIONNIUM_DO_NOT_PACKAGE_SECRET",
    "TRILLIONNIUM_DEVELOPMENT_RESPONSE_LOSS_FAULT_HOOK_V1",
    "/run/trillionnium/dev-conformance/fault-hook.json",
    "org.trillionnium.dev-conformance.gateway-response-loss.v1",
    "org.trillionnium.dev-conformance.gateway-response-loss-audit.v1",
)


class MaterializerError(Exception):
    """A bounded fail-closed contract error."""


def deny(message: str) -> NoReturn:
    raise MaterializerError(message)


def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            deny("JSON contains duplicate object keys")
        value[key] = item
    return value


def reject_json_constant(_value: str) -> NoReturn:
    deny("JSON contains a non-finite number")


def reject_non_scalar_strings(value: object, label: str) -> None:
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise MaterializerError(f"{label} contains a non-scalar string") from error
    elif isinstance(value, list):
        for item in value:
            reject_non_scalar_strings(item, label)
    elif isinstance(value, dict):
        for key, item in value.items():
            reject_non_scalar_strings(key, label)
            reject_non_scalar_strings(item, label)


def strict_json_bytes(raw: bytes, label: str) -> object:
    try:
        encoded = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise MaterializerError(f"{label} is not strict UTF-8") from error
    try:
        value = json.loads(
            encoded,
            object_pairs_hook=strict_object,
            parse_constant=reject_json_constant,
        )
        reject_non_scalar_strings(value, label)
        return value
    except MaterializerError:
        raise
    except (ValueError, RecursionError) as error:
        raise MaterializerError(f"{label} is not strict JSON") from error


def require_mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        deny(f"{label} must be a JSON object")
    return value


def require_exact_keys(value: dict[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        deny(f"{label} has unknown or missing fields")


def require_int(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        deny(f"{label} is outside its integer boundary")
    return value


def lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def private_directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
    )


def directory_custody_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        *private_directory_identity(metadata),
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def validate_private_directory(metadata: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        deny(f"{label} path component is not a directory")
    if (
        metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & 0o022
        or metadata.st_mode & stat.S_ISVTX
    ):
        deny(
            f"{label} path component is shared, writable, or not owner-controlled"
        )


def published_regular_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def hash_open_descriptor(file_descriptor: int) -> tuple[int, str]:
    """Hash a retained file descriptor without changing its shared offset."""

    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(file_descriptor, 1024 * 1024, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    return offset, digest.hexdigest()


@dataclass
class FrozenDirectoryComponent:
    path: Path
    name: str | None
    fd: int
    initial: os.stat_result


def descriptor_close_errors(descriptors: list[int] | tuple[int, ...]) -> list[str]:
    """Close every descriptor once, even when an earlier close reports failure."""

    errors: list[str] = []
    for descriptor in reversed(descriptors):
        if descriptor < 0:
            continue
        try:
            os.close(descriptor)
        except BaseException as error:
            errors.append(f"fd {descriptor}: {error}")
    return errors


def close_descriptors(
    descriptors: list[int] | tuple[int, ...],
    label: str,
) -> None:
    errors = descriptor_close_errors(descriptors)
    if errors:
        raise MaterializerError(
            f"{label} descriptor close did not complete cleanly: "
            + "; ".join(errors)
        )


def open_directory_component(
    parent_fd: int | None,
    name: str,
    label: str,
) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        lexical = os.stat(
            name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        raise MaterializerError(
            f"{label} parent path component is missing"
        ) from None
    if stat.S_ISLNK(lexical.st_mode) or not stat.S_ISDIR(lexical.st_mode):
        deny(
            f"{label} parent path contains a symbolic link or "
            "non-directory component"
        )
    validate_private_directory(lexical, label)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        raise MaterializerError(
            f"{label} parent path component is missing"
        ) from None
    except OSError as error:
        raise MaterializerError(
            f"{label} parent path contains a symbolic link or "
            "non-directory component"
        ) from error
    try:
        opened = os.fstat(descriptor)
        validate_private_directory(opened, label)
        if directory_custody_fingerprint(opened) != (
            directory_custody_fingerprint(lexical)
        ):
            deny(f"{label} parent path component changed while opened")
        return descriptor, opened
    except Exception as primary_error:
        errors = descriptor_close_errors([descriptor])
        if errors:
            raise MaterializerError(
                f"{label} parent component open failed and descriptor cleanup "
                f"did not close cleanly: {'; '.join(errors)}"
            ) from primary_error
        raise


def open_private_directory_chain(
    path: Path,
    label: str,
) -> tuple[FrozenDirectoryComponent, ...]:
    """Retain every private, non-symlink component of one absolute directory."""

    absolute = lexical_absolute(path)
    components: list[FrozenDirectoryComponent] = []
    try:
        root_path = Path(absolute.anchor)
        root_fd, root_metadata = open_directory_component(
            None,
            os.fspath(root_path),
            label,
        )
        components.append(
            FrozenDirectoryComponent(root_path, None, root_fd, root_metadata)
        )
        current_path = root_path
        for component_name in absolute.parts[1:]:
            current_path /= component_name
            component_fd, component_metadata = open_directory_component(
                components[-1].fd,
                component_name,
                label,
            )
            components.append(
                FrozenDirectoryComponent(
                    current_path,
                    component_name,
                    component_fd,
                    component_metadata,
                )
            )
        return tuple(components)
    except Exception as primary_error:
        errors = descriptor_close_errors(
            [component.fd for component in components]
        )
        if errors:
            raise MaterializerError(
                f"{label} directory custody failed and descriptor cleanup did "
                f"not close cleanly: {'; '.join(errors)}"
            ) from primary_error
        raise


def directory_component_matches(
    component: FrozenDirectoryComponent,
    metadata: os.stat_result,
) -> bool:
    return (
        stat.S_ISDIR(metadata.st_mode)
        and directory_custody_fingerprint(metadata)
        == directory_custody_fingerprint(component.initial)
    )


def verify_private_directory_chain(
    components: tuple[FrozenDirectoryComponent, ...],
    label: str,
    phase: str,
) -> None:
    """Verify retained bindings and a fresh absolute re-open of the whole chain."""

    if not components:
        deny(f"{label} directory custody chain is incomplete")
    for index, component in enumerate(components):
        held = os.fstat(component.fd)
        if not directory_component_matches(component, held):
            deny(f"{label} parent path component changed during {phase}")
        if index == 0:
            continue
        assert component.name is not None
        try:
            lexical = os.stat(
                component.name,
                dir_fd=components[index - 1].fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            deny(f"{label} parent path component disappeared during {phase}")
        if not directory_component_matches(component, lexical):
            deny(f"{label} parent path component changed during {phase}")

    fresh = open_private_directory_chain(components[-1].path, label)
    try:
        if len(fresh) != len(components):
            deny(f"{label} directory custody chain changed during {phase}")
        for expected, observed in zip(components, fresh, strict=True):
            if not directory_component_matches(expected, observed.initial):
                deny(f"{label} parent path component changed during {phase}")
    finally:
        close_descriptors(
            [component.fd for component in fresh],
            f"{label} fresh directory custody",
        )


_IN_MOVE_SELF = 0x00000800
_IN_DELETE_SELF = 0x00000400
_IN_UNMOUNT = 0x00002000
_IN_Q_OVERFLOW = 0x00004000
_IN_IGNORED = 0x00008000
_INOTIFY_CUSTODY_MASK = (
    _IN_MOVE_SELF | _IN_DELETE_SELF | _IN_UNMOUNT | _IN_Q_OVERFLOW | _IN_IGNORED
)
_INOTIFY_EVENT = struct.Struct("iIII")


@dataclass
class NamespaceMutationGuard:
    """Detect a move/delete of any retained output-path directory component."""

    fd: int

    @classmethod
    def open(
        cls,
        components: tuple[FrozenDirectoryComponent, ...],
        label: str,
    ) -> "NamespaceMutationGuard":
        libc = ctypes.CDLL(None, use_errno=True)
        init = libc.inotify_init1
        init.argtypes = [ctypes.c_int]
        init.restype = ctypes.c_int
        add_watch = libc.inotify_add_watch
        add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        add_watch.restype = ctypes.c_int

        descriptor = init(os.O_CLOEXEC | os.O_NONBLOCK)
        if descriptor < 0:
            error_number = ctypes.get_errno()
            raise MaterializerError(
                f"{label} namespace mutation guard could not be opened: "
                f"{os.strerror(error_number)}"
            )
        try:
            for component in components:
                retained_path = os.fsencode(f"/proc/self/fd/{component.fd}")
                if add_watch(
                    descriptor,
                    retained_path,
                    _INOTIFY_CUSTODY_MASK,
                ) < 0:
                    error_number = ctypes.get_errno()
                    raise MaterializerError(
                        f"{label} namespace mutation guard could not retain "
                        f"{component.path}: {os.strerror(error_number)}"
                    )
            guard = cls(descriptor)
            guard.assert_quiet("guard initialization")
            return guard
        except Exception as primary_error:
            errors = descriptor_close_errors([descriptor])
            if errors:
                raise MaterializerError(
                    f"{label} namespace guard setup failed and descriptor "
                    f"cleanup did not close cleanly: {'; '.join(errors)}"
                ) from primary_error
            raise

    def assert_quiet(self, phase: str) -> None:
        observed_masks: list[str] = []
        while True:
            try:
                encoded = os.read(self.fd, 64 * 1024)
            except BlockingIOError:
                break
            except OSError as error:
                raise MaterializerError(
                    f"output namespace mutation guard failed during {phase}"
                ) from error
            if not encoded:
                deny(f"output namespace mutation guard closed during {phase}")
            offset = 0
            while offset < len(encoded):
                if len(encoded) - offset < _INOTIFY_EVENT.size:
                    deny(
                        f"output namespace mutation guard returned a truncated "
                        f"event during {phase}"
                    )
                _watch, mask, _cookie, name_bytes = _INOTIFY_EVENT.unpack_from(
                    encoded,
                    offset,
                )
                offset += _INOTIFY_EVENT.size + name_bytes
                if mask & _INOTIFY_CUSTODY_MASK:
                    observed_masks.append(f"0x{mask:08x}")
        if observed_masks:
            deny(
                f"output path component moved or became uncertain during {phase} "
                f"({', '.join(observed_masks)})"
            )

    def close(self) -> None:
        descriptor = self.fd
        self.fd = -1
        close_descriptors([descriptor], "output namespace mutation guard")


@dataclass
class FrozenInput:
    path: Path
    label: str
    fd: int
    initial: os.stat_result
    sha256: str
    parents: tuple[FrozenDirectoryComponent, ...]

    @staticmethod
    def _open_directory(
        parent_fd: int | None,
        name: str,
        label: str,
    ) -> tuple[int, os.stat_result]:
        return open_directory_component(parent_fd, name, label)

    def _directory_matches(
        self,
        component: FrozenDirectoryComponent,
        metadata: os.stat_result,
    ) -> bool:
        return directory_component_matches(component, metadata)

    def _verify_parent_descriptors(
        self,
        descriptors: tuple[int, ...],
        phase: str,
    ) -> None:
        if len(descriptors) != len(self.parents):
            deny(f"{self.label} parent custody chain is incomplete")
        for index, (component, descriptor) in enumerate(
            zip(self.parents, descriptors, strict=True)
        ):
            held = os.fstat(descriptor)
            if not self._directory_matches(component, held):
                deny(
                    f"{self.label} parent path component changed during {phase}"
                )
            if index == 0:
                continue
            assert component.name is not None
            try:
                lexical = os.stat(
                    component.name,
                    dir_fd=descriptors[index - 1],
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                deny(
                    f"{self.label} parent path component disappeared during {phase}"
                )
            if not self._directory_matches(
                component,
                lexical,
            ):
                deny(
                    f"{self.label} parent path component changed during {phase}"
                )

    def _open_fresh_leaf(
        self,
        phase: str,
    ) -> tuple[tuple[int, ...], int]:
        retained_descriptors = tuple(component.fd for component in self.parents)
        self._verify_parent_descriptors(
            retained_descriptors,
            phase,
        )

        fresh_descriptors: list[int] = []
        leaf_fd = -1
        try:
            root = self.parents[0]
            assert root.name is None
            root_fd, root_metadata = self._open_directory(
                None,
                os.fspath(root.path),
                self.label,
            )
            fresh_descriptors.append(root_fd)
            if not self._directory_matches(
                root,
                root_metadata,
            ):
                deny(
                    f"{self.label} parent path component changed during {phase}"
                )
            for component in self.parents[1:]:
                assert component.name is not None
                next_fd, metadata = self._open_directory(
                    fresh_descriptors[-1],
                    component.name,
                    self.label,
                )
                fresh_descriptors.append(next_fd)
                if not self._directory_matches(
                    component,
                    metadata,
                ):
                    deny(
                        f"{self.label} parent path component changed during {phase}"
                    )

            try:
                lexical = os.stat(
                    self.path.name,
                    dir_fd=fresh_descriptors[-1],
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                deny(f"{self.label} pathname disappeared during {phase}")
            if stat.S_ISLNK(lexical.st_mode):
                deny(f"{self.label} path contains a symbolic link")
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            try:
                leaf_fd = os.open(
                    self.path.name,
                    flags,
                    dir_fd=fresh_descriptors[-1],
                )
            except OSError as error:
                raise MaterializerError(
                    f"{self.label} pathname could not be reopened during {phase}"
                ) from error
            reopened = os.fstat(leaf_fd)
            expected = published_regular_fingerprint(self.initial)
            if (
                not stat.S_ISREG(lexical.st_mode)
                or not stat.S_ISREG(reopened.st_mode)
                or published_regular_fingerprint(lexical) != expected
                or published_regular_fingerprint(reopened) != expected
            ):
                deny(f"{self.label} changed during {phase}")
            return tuple(fresh_descriptors), leaf_fd
        except Exception as primary_error:
            errors = descriptor_close_errors([leaf_fd, *fresh_descriptors])
            if errors:
                raise MaterializerError(
                    f"{self.label} fresh leaf verification failed and descriptor "
                    f"cleanup did not close cleanly: {'; '.join(errors)}"
                ) from primary_error
            raise

    @classmethod
    def open(
        cls,
        path: Path,
        label: str,
        maximum_bytes: int,
        *,
        require_executable: bool = False,
    ) -> "FrozenInput":
        absolute = lexical_absolute(path)
        if absolute.name in {"", ".", ".."}:
            deny(f"{label} filename is invalid")
        parents: list[FrozenDirectoryComponent] = []
        fd = -1
        try:
            root_path = Path(absolute.anchor)
            root_fd, root_metadata = cls._open_directory(
                None,
                os.fspath(root_path),
                label,
            )
            parents.append(
                FrozenDirectoryComponent(root_path, None, root_fd, root_metadata)
            )
            current_path = root_path
            for component_name in absolute.parent.parts[1:]:
                current_path /= component_name
                component_fd, component_metadata = cls._open_directory(
                    parents[-1].fd,
                    component_name,
                    label,
                )
                parents.append(
                    FrozenDirectoryComponent(
                        current_path,
                        component_name,
                        component_fd,
                        component_metadata,
                    )
                )
            validate_private_directory(parents[-1].initial, label)
            try:
                lexical = os.stat(
                    absolute.name,
                    dir_fd=parents[-1].fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                raise MaterializerError(
                    f"{label} path component is missing"
                ) from None
            if stat.S_ISLNK(lexical.st_mode):
                deny(f"{label} path contains a symbolic link")
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            try:
                fd = os.open(absolute.name, flags, dir_fd=parents[-1].fd)
            except OSError as error:
                raise MaterializerError(f"cannot open frozen {label}") from error
            metadata = os.fstat(fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size <= 0
                or metadata.st_size > maximum_bytes
                or metadata.st_mode & 0o222
                or (require_executable and not metadata.st_mode & 0o111)
            ):
                deny(f"{label} is not a bounded frozen regular file")
            if (
                not stat.S_ISREG(lexical.st_mode)
                or published_regular_fingerprint(lexical)
                != published_regular_fingerprint(metadata)
            ):
                deny(f"{label} changed while opened")
            measured_bytes, measured_sha256 = hash_open_descriptor(fd)
            if measured_bytes != metadata.st_size:
                deny(f"{label} changed while being measured")
            item = cls(
                absolute,
                label,
                fd,
                metadata,
                measured_sha256,
                tuple(parents),
            )
            item.verify_unchanged()
            return item
        except Exception as primary_error:
            errors = descriptor_close_errors(
                [fd, *[component.fd for component in parents]]
            )
            if errors:
                raise MaterializerError(
                    f"{label} open failed and descriptor cleanup did not close "
                    f"cleanly: {'; '.join(errors)}"
                ) from primary_error
            raise

    @property
    def size(self) -> int:
        return self.initial.st_size

    def read_all(self) -> bytes:
        os.lseek(self.fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = self.initial.st_size
        while remaining:
            chunk = os.read(self.fd, min(remaining, 1024 * 1024))
            if not chunk:
                deny(f"{self.label} changed while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(self.fd, 1):
            deny(f"{self.label} grew while being read")
        self.verify_unchanged()
        return b"".join(chunks)

    def pread(self, count: int, offset: int) -> bytes:
        return os.pread(self.fd, count, offset)

    def verify_unchanged(self) -> None:
        current = os.fstat(self.fd)
        expected = published_regular_fingerprint(self.initial)
        if (
            published_regular_fingerprint(current) != expected
            or not stat.S_ISREG(current.st_mode)
        ):
            deny(f"{self.label} changed during materialization")
        fresh_descriptors, lexical_fd = self._open_fresh_leaf(
            "materialization",
        )
        try:
            lexical = os.fstat(lexical_fd)
            if (
                published_regular_fingerprint(lexical) != expected
                or not stat.S_ISREG(lexical.st_mode)
            ):
                deny(f"{self.label} changed during materialization")
        finally:
            close_descriptors(
                [lexical_fd, *fresh_descriptors],
                f"{self.label} unchanged verification",
            )

    def verify_final(self) -> None:
        """Reverify retained identity, pathname identity, and complete bytes."""

        expected = published_regular_fingerprint(self.initial)
        current = os.fstat(self.fd)
        if (
            published_regular_fingerprint(current) != expected
            or not stat.S_ISREG(current.st_mode)
        ):
            deny(f"{self.label} changed during final custody check")
        held_bytes, held_sha256 = hash_open_descriptor(self.fd)
        current_after = os.fstat(self.fd)
        if (
            held_bytes != self.initial.st_size
            or held_sha256 != self.sha256
            or published_regular_fingerprint(current_after) != expected
        ):
            deny(f"{self.label} bytes changed during final custody check")

        fresh_descriptors, lexical_fd = self._open_fresh_leaf(
            "final custody check",
        )
        try:
            reopened = os.fstat(lexical_fd)
            if (
                published_regular_fingerprint(reopened) != expected
                or not stat.S_ISREG(reopened.st_mode)
            ):
                deny(f"{self.label} pathname no longer names the retained input")
            reopened_bytes, reopened_sha256 = hash_open_descriptor(lexical_fd)
            reopened_after = os.fstat(lexical_fd)
            if (
                reopened_bytes != self.initial.st_size
                or reopened_sha256 != self.sha256
            ):
                deny(
                    f"{self.label} pathname bytes changed during final custody check"
                )
            retained_descriptors = tuple(
                component.fd for component in self.parents
            )
            self._verify_parent_descriptors(
                retained_descriptors,
                "final custody check",
            )
            self._verify_parent_descriptors(
                fresh_descriptors,
                "final custody check",
            )
            try:
                retained_lexical = os.stat(
                    self.path.name,
                    dir_fd=retained_descriptors[-1],
                    follow_symlinks=False,
                )
                lexical_after = os.stat(
                    self.path.name,
                    dir_fd=fresh_descriptors[-1],
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                deny(
                    f"{self.label} pathname disappeared during final custody check"
                )
            if (
                published_regular_fingerprint(reopened_after) != expected
                or published_regular_fingerprint(retained_lexical) != expected
                or published_regular_fingerprint(lexical_after) != expected
                or not stat.S_ISREG(retained_lexical.st_mode)
                or not stat.S_ISREG(lexical_after.st_mode)
            ):
                deny(f"{self.label} pathname changed during final custody check")
        finally:
            close_descriptors(
                [lexical_fd, *fresh_descriptors],
                f"{self.label} final custody verification",
            )

    def close(self) -> None:
        descriptors = [self.fd, *[component.fd for component in self.parents]]
        self.fd = -1
        for component in self.parents:
            component.fd = -1
        close_descriptors(descriptors, f"{self.label} frozen input")

    def __enter__(self) -> "FrozenInput":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class PublicationAwareExitStack(ExitStack):
    """Preserve a publication error when retained-input cleanup also fails."""

    def close_retained_inputs(self) -> None:
        """Drain all input contexts for an explicit post-commit custody gate.

        Calling the base implementation bypasses this class's contextual error
        wrapper.  The publication state machine can therefore compose the raw
        teardown failure with any already-active post-link failure and its own
        final output-custody result.
        """

        super().__exit__(None, None, None)

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        try:
            return super().__exit__(exc_type, exc, traceback)
        except BaseException as cleanup_error:
            if exc is not None:
                raise MaterializerError(
                    "rootfs contract materialization failed and retained-input "
                    f"cleanup also failed; primary: {exc}; cleanup: {cleanup_error}"
                ) from exc
            raise MaterializerError(
                "rootfs contract publication completed but retained-input cleanup "
                f"failed; the output remains visible: {cleanup_error}"
            ) from cleanup_error


def verify_aarch64_elf(binary: FrozenInput, *, require_static: bool) -> None:
    header = binary.pread(64, 0)
    if len(header) != 64 or header[:4] != b"\x7fELF":
        deny(f"{binary.label} is not ELF")
    if header[4:7] != b"\x02\x01\x01":
        deny(f"{binary.label} is not little-endian ELF64")
    try:
        values = struct.unpack("<16sHHIQQQIHHHHHH", header)
    except struct.error as error:
        raise MaterializerError(f"{binary.label} has an invalid ELF header") from error
    (_, elf_type, machine, version, _, phoff, _, _, ehsize, phentsize, phnum, _, _, _) = values
    if elf_type not in {2, 3} or machine != EM_AARCH64 or version != 1 or ehsize != 64:
        deny(f"{binary.label} is not an AArch64 executable")
    if phnum == 0xFFFF or phnum > 4096:
        deny(f"{binary.label} uses an unsupported program-header encoding")
    if phnum:
        if phentsize < 56 or phentsize > 4096:
            deny(f"{binary.label} has an invalid program-header size")
        end = phoff + phentsize * phnum
        if phoff < 64 or end > binary.size:
            deny(f"{binary.label} program headers exceed the frozen file")
    has_interpreter = False
    for index in range(phnum):
        entry = binary.pread(4, phoff + index * phentsize)
        if len(entry) != 4:
            deny(f"{binary.label} program header is truncated")
        if struct.unpack("<I", entry)[0] == PT_INTERP:
            has_interpreter = True
    if require_static and has_interpreter:
        deny(f"{binary.label} is not static: PT_INTERP is present")


def canonical_relative_path(value: object, label: str, max_path_bytes: int) -> str:
    if not isinstance(value, str):
        deny(f"{label} must be a string")
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or any(ord(character) < 32 for character in value)
        or len(value.encode("utf-8")) > max_path_bytes
    ):
        deny(f"{label} is not a canonical relative path")
    return value


def canonical_install(
    value: object, label: str, max_path_bytes: int
) -> dict[str, str]:
    mapping = require_mapping(value, label)
    require_exact_keys(mapping, {"path", "mode"}, label)
    mode = mapping["mode"]
    if not isinstance(mode, str):
        deny(f"{label}.mode must be a string")
    if (
        len(mode) != 4
        or mode[0] != "0"
        or any(character not in "01234567" for character in mode)
    ):
        deny(f"{label}.mode is not canonical octal")
    if int(mode, 8) & 0o022:
        deny(f"{label}.mode must not be group/world writable")
    path = canonical_relative_path(mapping["path"], f"{label}.path", max_path_bytes)
    return {"path": path, "mode": mode}


def validate_template(value: object) -> dict[str, object]:
    template = require_mapping(value, "template")
    require_exact_keys(template, TOP_LEVEL_FIELDS, "template")
    if template["schema"] != CONTRACT_SCHEMA or template["source_date_epoch"] != 0:
        deny("template is not an unmaterialized v9 contract")
    common_build_evidence = require_mapping(
        template["common_build_evidence"], "template.common_build_evidence"
    )
    require_exact_keys(
        common_build_evidence,
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
        "template.common_build_evidence",
    )
    if any(value is not None for value in common_build_evidence.values()):
        deny("template common build evidence is already materialized")
    admission = require_mapping(template["admission"], "template.admission")
    require_exact_keys(
        admission,
        {"decision", "identity_independence_gate", "release_allowed", "status"},
        "template.admission",
    )
    if (
        admission["decision"] != CONTRACT_DECISION
        or admission["status"] != CONTRACT_STATUS
        or admission["release_allowed"] is not False
        or admission["identity_independence_gate"] is not None
    ):
        deny("template admission HOLD is already materialized or drifted")
    compression = require_mapping(template["compression"], "template.compression")
    require_exact_keys(
        compression,
        {"algorithm", "level", "long_distance_matcher_log", "threads"},
        "template.compression",
    )
    if compression["algorithm"] != "zstd" or compression["threads"] != 1:
        deny("template compression boundary is unsupported")
    require_int(compression["level"], "template.compression.level", 1, 22)
    require_int(
        compression["long_distance_matcher_log"],
        "template.compression.long_distance_matcher_log",
        10,
        31,
    )
    limits = require_mapping(template["limits"], "template.limits")
    require_exact_keys(
        limits,
        {
            "max_members",
            "max_member_bytes",
            "max_total_regular_bytes",
            "max_decompressed_tar_bytes",
            "max_path_bytes",
        },
        "template.limits",
    )
    limit_boundaries = {
        "max_members": (1, 1_000_000),
        "max_member_bytes": (1, 1 << 40),
        "max_total_regular_bytes": (1, 1 << 44),
        "max_decompressed_tar_bytes": (1024, 1 << 44),
        "max_path_bytes": (16, 65535),
    }
    validated_limits = {
        key: require_int(limits[key], f"template.limits.{key}", minimum, maximum)
        for key, (minimum, maximum) in limit_boundaries.items()
    }
    max_path_bytes = validated_limits["max_path_bytes"]
    runtime = require_mapping(template["runtime"], "template.runtime")
    require_exact_keys(runtime, {"elf_machine", "max_glibc"}, "template.runtime")
    if (
        runtime["elf_machine"] != "AArch64"
        or not isinstance(runtime["max_glibc"], str)
        or re.fullmatch(r"\d+\.\d+", runtime["max_glibc"]) is None
    ):
        deny("template runtime is not AArch64")
    tools = require_mapping(template["tools"], "template.tools")
    require_exact_keys(tools, {"zstd"}, "template.tools")
    zstd = require_mapping(tools["zstd"], "template.tools.zstd")
    require_exact_keys(zstd, {"bytes", "sha256"}, "template.tools.zstd")
    if zstd != {"bytes": 0, "sha256": ZERO_SHA256}:
        deny("template zstd tool is already materialized")
    inputs = require_mapping(template["inputs"], "template.inputs")
    require_exact_keys(inputs, INPUT_FIELDS, "template.inputs")
    base = require_mapping(inputs["base_rootfs"], "template.inputs.base_rootfs")
    require_exact_keys(base, {"bytes", "sha256"}, "template.inputs.base_rootfs")
    if base != {"bytes": 0, "sha256": ZERO_SHA256}:
        deny("template base_rootfs is already materialized")
    common_receipt = require_mapping(
        inputs["common_artifact_set_receipt"],
        "template.inputs.common_artifact_set_receipt",
    )
    require_exact_keys(
        common_receipt,
        {"bytes", "file", "schema", "sha256", "status"},
        "template.inputs.common_artifact_set_receipt",
    )
    if common_receipt != {
        "bytes": 0,
        "file": COMMON_ARTIFACT_SET_FILE,
        "schema": COMMON_ARTIFACT_SET_SCHEMA,
        "sha256": ZERO_SHA256,
        "status": COMMON_ARTIFACT_SET_STATUS,
    }:
        deny("template common artifact-set receipt identity drifted")
    launcher_ab_receipt = require_mapping(
        inputs["common_launcher_ab_receipt"],
        "template.inputs.common_launcher_ab_receipt",
    )
    require_exact_keys(
        launcher_ab_receipt,
        {"bytes", "decision", "file", "schema", "sha256", "status"},
        "template.inputs.common_launcher_ab_receipt",
    )
    if launcher_ab_receipt != {
        "bytes": 0,
        "decision": COMMON_LAUNCHER_AB_DECISION,
        "file": COMMON_LAUNCHER_AB_FILE,
        "schema": COMMON_LAUNCHER_AB_SCHEMA,
        "sha256": ZERO_SHA256,
        "status": COMMON_LAUNCHER_AB_HOLD,
    }:
        deny("template common launcher A/B receipt identity drifted")
    install_paths: dict[str, str] = {}
    for name, require_static in (
        ("daemon", False),
        ("codex", True),
        ("system_api_tool", False),
        ("accessibility_tool", False),
        ("system_api_replay_sync", False),
    ):
        item = require_mapping(inputs[name], f"template.inputs.{name}")
        require_exact_keys(
            item,
            {"bytes", "sha256", "install", "require_static"},
            f"template.inputs.{name}",
        )
        if (
            item["bytes"] != 0
            or item["sha256"] != ZERO_SHA256
            or item["require_static"] is not require_static
        ):
            deny(f"template {name} is already materialized or weakens static policy")
        install = canonical_install(
            item["install"], f"template.inputs.{name}.install", max_path_bytes
        )
        if install["mode"] != "0755":
            deny(f"template {name} install mode must be 0755")
        marker_count = install["path"].count(VERSION_MARKER)
        if (name == "codex" and marker_count != 1) or (
            name != "codex" and marker_count != 0
        ):
            deny(f"template {name} install path has an invalid version marker")
        if (
            name == "system_api_replay_sync"
            and install["path"] != SYSTEM_API_REPLAY_SYNC_INSTALL_PATH
        ):
            deny("template system_api_replay_sync install path drifted")
        if name in EXTERNAL_EFFECT_TOOLS and (
            install["path"] != EXTERNAL_EFFECT_TOOLS[name]["install_path"]
        ):
            deny(f"template {name} install path drifted")
        install_paths[name] = install["path"]
    manifest = require_mapping(inputs["agent_manifest"], "template.inputs.agent_manifest")
    require_exact_keys(
        manifest,
        {"bytes", "sha256", "install", "required_fields", "allowed_fields"},
        "template.inputs.agent_manifest",
    )
    if manifest["bytes"] != 0 or manifest["sha256"] != ZERO_SHA256:
        deny("template AgentManifest is already materialized")
    manifest_install = canonical_install(
        manifest["install"],
        "template.inputs.agent_manifest.install",
        max_path_bytes,
    )
    if VERSION_MARKER in manifest_install["path"]:
        deny("template AgentManifest install path has an invalid version marker")
    install_paths["agent_manifest"] = manifest_install["path"]
    if len(set(install_paths.values())) != len(install_paths):
        deny("template replacement install paths must be distinct")
    required = require_mapping(
        manifest["required_fields"], "template.inputs.agent_manifest.required_fields"
    )
    allowed = manifest["allowed_fields"]
    if (
        not isinstance(allowed, list)
        or not allowed
        or any(not isinstance(item, str) or not item for item in allowed)
        or len(set(allowed)) != len(allowed)
        or not set(required).issubset(set(allowed))
    ):
        deny("template AgentManifest field policy is invalid")
    if required.get("adapter_version") != "REPLACE_WITH_CUSTODIED_VERSION":
        deny("template AgentManifest adapter version marker is missing")
    if required.get("identity_key_sha256") != ZERO_SHA256:
        deny("template AgentManifest identity marker is missing")
    if required.get("enabled") is not False or required.get("health") != "disabled":
        deny("template AgentManifest must remain disabled until product admission")
    security = require_mapping(template["security"], "template.security")
    require_exact_keys(security, SECURITY_FIELDS, "template.security")
    for field in MIGRATION_FIELDS:
        if security[field] != []:
            deny(f"template {field} must remain empty")
    for field in NULLABLE_MIGRATION_FIELDS:
        if security[field] is not None:
            deny(f"template {field} must remain null")
    path_patterns = security["forbidden_path_patterns"]
    if not isinstance(path_patterns, list):
        deny("template security.forbidden_path_patterns must be an array")
    for index, pattern in enumerate(path_patterns):
        if not isinstance(pattern, str) or not pattern or len(pattern) > 1024:
            deny(f"template forbidden path pattern {index} is invalid")
        try:
            re.compile(pattern, re.IGNORECASE)
        except re.error as error:
            raise MaterializerError(
                f"template forbidden path pattern {index} is invalid"
            ) from error
    content_markers = security["forbidden_content_markers"]
    if not isinstance(content_markers, list) or any(
        not isinstance(marker, str)
        or not marker
        or len(marker.encode("utf-8")) > 1024
        for marker in content_markers
    ):
        deny("template forbidden content markers are invalid")
    if tuple(content_markers) != REQUIRED_FORBIDDEN_CONTENT_MARKERS:
        deny("template forbidden content marker closure mismatch")
    hardlinks = security["replacement_hardlink_allowlist"]
    if not isinstance(hardlinks, list):
        deny("template security.replacement_hardlink_allowlist must be an array")
    normalized_hardlinks: list[tuple[str, str]] = []
    for index, item in enumerate(hardlinks):
        label = f"template security.replacement_hardlink_allowlist[{index}]"
        mapping = require_mapping(item, label)
        require_exact_keys(mapping, {"path", "target"}, label)
        path = canonical_relative_path(mapping["path"], f"{label}.path", max_path_bytes)
        target = canonical_relative_path(
            mapping["target"], f"{label}.target", max_path_bytes
        )
        if path == target or target not in set(install_paths.values()):
            deny(f"{label} does not bind a distinct replacement target")
        normalized_hardlinks.append((path, target))
    if len(set(normalized_hardlinks)) != len(normalized_hardlinks):
        deny("template replacement hardlink allowlist contains duplicates")
    return template


def validate_manifest(
    value: object,
    template_manifest: dict[str, object],
    codex_sha256: str,
) -> tuple[dict[str, object], str]:
    manifest = require_mapping(value, "AgentManifest")
    allowed = template_manifest["allowed_fields"]
    assert isinstance(allowed, list)
    unknown = set(manifest) - set(allowed)
    if unknown:
        deny("AgentManifest contains unknown fields")
    required_template = require_mapping(
        template_manifest["required_fields"], "template AgentManifest required_fields"
    )
    if not set(required_template).issubset(manifest):
        deny("AgentManifest is missing required fields")
    for key, expected in required_template.items():
        if key in {"adapter_version", "identity_key_sha256"}:
            continue
        if type(manifest[key]) is not type(expected) or manifest[key] != expected:
            deny(f"AgentManifest fixed field mismatch: {key}")
    adapter_version = manifest.get("adapter_version")
    if (
        not isinstance(adapter_version, str)
        or not 1 <= len(adapter_version.encode("utf-8")) <= 128
        or adapter_version in {".", ".."}
        or any(
            not (character.isascii() and (character.isalnum() or character in ".+_-"))
            for character in adapter_version
        )
    ):
        deny("AgentManifest adapter_version is not a safe install-path segment")
    if manifest.get("identity_key_sha256") != codex_sha256:
        deny("AgentManifest identity_key_sha256 does not equal the Codex SHA-256")
    if manifest.get("enabled") is not False or manifest.get("health") != "disabled":
        deny("AgentManifest must remain disabled until product admission")
    for timestamp in ("registered_at_unix_ms", "updated_at_unix_ms"):
        if timestamp in manifest:
            require_int(manifest[timestamp], f"AgentManifest.{timestamp}", 0, 1 << 63)
    return manifest, adapter_version


def validate_launcher_build_tool(
    value: object,
    label: str,
    role: str,
    *,
    include_path: bool,
    raw_match_field: str | None = None,
) -> dict[str, object]:
    tool = require_mapping(value, label)
    fields = {
        "schema",
        "role",
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
    if include_path:
        fields.add("path")
    else:
        fields.update(
            {
                "a_b_byte_equal",
                "build_time_bytes_bound_by_upstream_receipt",
            }
        )
        if raw_match_field is None:
            deny(f"{label} omitted its raw-tool match field")
        fields.add(raw_match_field)
    require_exact_keys(tool, fields, label)
    execution = require_mapping(tool["execution"], f"{label}.execution")
    require_exact_keys(
        execution,
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
    mode = tool["mode"]
    if (
        tool["schema"] != LAUNCHER_BUILD_TOOL_SCHEMA
        or tool["role"] != role
        or not isinstance(tool["bytes"], int)
        or isinstance(tool["bytes"], bool)
        or not 0 < tool["bytes"] <= MAX_HOST_TOOL_BYTES
        or not isinstance(tool["sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", tool["sha256"]) is None
        or not isinstance(mode, str)
        or re.fullmatch(r"0[0-7]{3}", mode) is None
        or int(mode, 8) & 0o022
        or not int(mode, 8) & 0o100
        or not isinstance(tool["uid"], int)
        or isinstance(tool["uid"], bool)
        or tool["uid"] < 0
        or not isinstance(tool["gid"], int)
        or isinstance(tool["gid"], bool)
        or tool["gid"] < 0
        or tool["link_count"] != 1
        or not isinstance(tool["version"], str)
        or not tool["version"]
        or len(tool["version"].encode("utf-8")) > 4096
        or "\x00" in tool["version"]
        or any(ord(character) < 32 for character in tool["version"])
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
        deny(f"{label} custody is malformed")
    if include_path:
        path = tool["path"]
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or len(path.encode("utf-8")) > 4096
            or "\x00" in path
            or any(part in {"", ".", ".."} for part in path.split("/")[1:])
        ):
            deny(f"{label}.path is not canonical absolute syntax")
    else:
        assert raw_match_field is not None
        if (
            tool["a_b_byte_equal"] is not True
            or tool["build_time_bytes_bound_by_upstream_receipt"] is not True
            or tool[raw_match_field] is not True
        ):
            deny(f"{label} A/B custody claims are incomplete")
    expected_identity = EXPECTED_LAUNCHER_BUILD_TOOL_IDENTITIES[role]
    if any(tool[field] != expected for field, expected in expected_identity.items()):
        deny(f"{label} differs from the frozen Mobian snapshot leaf")
    return copy.deepcopy(tool)


def validate_toolchain_snapshot_binding(
    value: object, label: str
) -> dict[str, object]:
    snapshot = require_mapping(value, label)
    require_exact_keys(snapshot, set(EXPECTED_TOOLCHAIN_SNAPSHOT_BINDING), label)
    if snapshot != EXPECTED_TOOLCHAIN_SNAPSHOT_BINDING:
        deny(f"{label} differs from the frozen Mobian snapshot")
    return copy.deepcopy(snapshot)


def validate_target_compiler_closure(
    value: object, label: str
) -> dict[str, object]:
    closure = require_mapping(value, label)
    require_exact_keys(
        closure,
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
    components = require_mapping(closure["components"], f"{label}.components")
    require_exact_keys(
        components,
        set(EXPECTED_TARGET_COMPILER_COMPONENTS),
        f"{label}.components",
    )
    for role, expected in EXPECTED_TARGET_COMPILER_COMPONENTS.items():
        record = require_mapping(components[role], f"{label}.components.{role}")
        require_exact_keys(
            record,
            {"relative_path", "bytes", "sha256", "mode"},
            f"{label}.components.{role}",
        )
        if record != expected:
            deny(f"{label}.components.{role} differs from the frozen Mobian snapshot")
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
        deny(f"{label} posture differs")
    return copy.deepcopy(closure)


def validate_claim_authority(
    value: object,
    label: str,
    expected: dict[str, object],
) -> dict[str, object]:
    authority = require_mapping(value, label)
    require_exact_keys(authority, set(expected), label)
    if authority != expected:
        deny(f"{label} overclaims downstream authority")
    return copy.deepcopy(authority)


def tool_without_local_path(value: dict[str, object]) -> dict[str, object]:
    result = copy.deepcopy(value)
    result.pop("path", None)
    return result


def validate_common_artifact_set(
    value: object,
    raw: bytes,
    receipt_input: FrozenInput,
    artifacts_on_disk: dict[str, FrozenInput],
) -> dict[str, object]:
    receipt = require_mapping(value, "common artifact-set receipt")
    require_exact_keys(
        receipt,
        {
            "accessibility_available",
            "artifacts",
            "common_direct_tool_posture",
            "compiler",
            "elf_inspector",
            "dependency_graph",
            "device_execution_verified",
            "inputs",
            "legacy_descriptor_contamination_hold_gate",
            "product_variant",
            "receipt_role",
            "release_allowed",
            "rootfs_build_required",
            "schema",
            "source_bom",
            "stable_principal_launcher_measurement",
            "status",
            "target_compiler_closure",
            "toolchain_snapshot",
        },
        "common artifact-set receipt",
    )
    if canonical_json(receipt) != raw:
        deny("common artifact-set receipt is not canonical indented JSON")
    if receipt_input.path.name != COMMON_ARTIFACT_SET_FILE:
        deny("common artifact-set receipt filename drifted")
    if stat.S_IMODE(receipt_input.initial.st_mode) != 0o444:
        deny("common artifact-set receipt mode must be 0444")
    if (
        receipt["schema"] != COMMON_ARTIFACT_SET_SCHEMA
        or receipt["status"] != COMMON_ARTIFACT_SET_STATUS
        or receipt["product_variant"] != "common"
        or receipt["receipt_role"]
        != "common_rootfs_complete_measured_build_input"
        or receipt["common_direct_tool_posture"]
        != "inert_no_default_features_fail_closed"
        or receipt["rootfs_build_required"] is not True
        or receipt["release_allowed"] is not False
        or receipt["device_execution_verified"] is not False
        or receipt["accessibility_available"] is not False
    ):
        deny("common artifact-set receipt decision or posture drifted")

    compiler = validate_launcher_build_tool(
        receipt["compiler"],
        "common artifact-set compiler",
        "compiler_driver",
        include_path=True,
    )
    elf_inspector = validate_launcher_build_tool(
        receipt["elf_inspector"],
        "common artifact-set ELF inspector",
        "elf_inspector",
        include_path=True,
    )
    toolchain_snapshot = validate_toolchain_snapshot_binding(
        receipt["toolchain_snapshot"], "common artifact-set toolchain snapshot"
    )
    target_compiler_closure = validate_target_compiler_closure(
        receipt["target_compiler_closure"],
        "common artifact-set target compiler closure",
    )

    source_bom = require_mapping(receipt["source_bom"], "common artifact-set source BOM")
    require_exact_keys(
        source_bom,
        {
            "authority",
            "bytes",
            "control_head",
            "file_sha256",
            "receipt_id",
            "resolved_manifest_sha256",
            "source_set_sha256",
        },
        "common artifact-set source BOM",
    )
    if (
        source_bom["authority"]
        != "local_exact_clean_graph_not_build_or_release_authority"
        or not isinstance(source_bom["bytes"], int)
        or isinstance(source_bom["bytes"], bool)
        or not 0 < source_bom["bytes"] <= 8 * 1024 * 1024
        or not isinstance(source_bom["control_head"], str)
        or re.fullmatch(r"[0-9a-f]{40,64}", source_bom["control_head"]) is None
        or not isinstance(source_bom["receipt_id"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", source_bom["receipt_id"]) is None
        or any(
            not isinstance(source_bom[field], str)
            or re.fullmatch(r"[0-9a-f]{64}", source_bom[field]) is None
            for field in (
                "file_sha256",
                "resolved_manifest_sha256",
                "source_set_sha256",
            )
        )
        or source_bom["source_set_sha256"] == "0" * 64
        or source_bom["resolved_manifest_sha256"] == "0" * 64
    ):
        deny("common artifact-set source BOM binding is malformed")

    stable_measurement = require_mapping(
        receipt["stable_principal_launcher_measurement"],
        "common stable-principal launcher measurement",
    )
    require_exact_keys(
        stable_measurement,
        {
            "executable_identity_is_stable_registry_input",
            "launcher_executable_sha256",
            "launcher_identity_source",
            "stable_principal_canonical_sha256",
            "stable_principal_contract_sha256",
            "status",
        },
        "common stable-principal launcher measurement",
    )
    if (
        stable_measurement["status"]
        != "host_measurement_only_avb_slot_admission_absent"
        or stable_measurement["launcher_identity_source"]
        != "measured_after_closed_launcher_inputs"
        or stable_measurement["executable_identity_is_stable_registry_input"] is not False
        or stable_measurement["stable_principal_contract_sha256"]
        != STABLE_PRINCIPAL_CONTRACT_SHA256
        or stable_measurement["stable_principal_canonical_sha256"]
        != STABLE_PRINCIPAL_CANONICAL_SHA256
        or not isinstance(stable_measurement["launcher_executable_sha256"], str)
        or re.fullmatch(
            r"[0-9a-f]{64}", stable_measurement["launcher_executable_sha256"]
        )
        is None
    ):
        deny("common stable-principal launcher measurement drifted")

    legacy_gate = require_mapping(
        receipt["legacy_descriptor_contamination_hold_gate"],
        "common legacy descriptor contamination gate",
    )
    require_exact_keys(
        legacy_gate,
        {
            "counterfactual_same_source_rebuild",
            "digests",
            "literal_digest_absence_verified",
            "stable_principal_admission_split",
            "status",
        },
        "common legacy descriptor contamination gate",
    )
    legacy_digests = require_mapping(
        legacy_gate["digests"], "common legacy descriptor digests"
    )
    require_exact_keys(
        legacy_digests,
        {"canonical digest", "contract digest", "launcher identity"},
        "common legacy descriptor digests",
    )
    counterfactual = require_mapping(
        legacy_gate["counterfactual_same_source_rebuild"],
        "common counterfactual same-source rebuild gate",
    )
    stable_split = require_mapping(
        legacy_gate["stable_principal_admission_split"],
        "common stable-principal admission split gate",
    )
    for label, gate in (
        ("counterfactual same-source rebuild", counterfactual),
        ("stable-principal admission split", stable_split),
    ):
        require_exact_keys(
            gate, {"evidence_receipt", "required", "verified"}, f"common {label} gate"
        )
        if (
            gate["required"] is not True
            or gate["verified"] is not False
            or gate["evidence_receipt"] is not None
        ):
            deny(f"common {label} gate must remain unverified HOLD")
    if (
        legacy_gate["status"] != CONTRACT_STATUS
        or legacy_gate["literal_digest_absence_verified"] is not True
        or legacy_digests != EXPECTED_LEGACY_DESCRIPTOR_DIGESTS
    ):
        deny("common legacy descriptor contamination gate drifted")

    dependency_graph = require_mapping(
        receipt["dependency_graph"], "common artifact-set dependency graph"
    )
    require_exact_keys(
        dependency_graph,
        {"acyclic", "edge_semantics", "edges", "forbidden_edges"},
        "common artifact-set dependency graph",
    )
    required_edges = {
        "codex_runtime->codex_launcher",
        "system_api_tool->codex_launcher",
        "accessibility_tool->codex_launcher",
        "daemon->rootfs_package",
        "replay_sync_helper->rootfs_package",
        "codex_launcher->rootfs_package",
    }
    required_forbidden_edges = {
        "codex_launcher->system_api_tool",
        "codex_launcher->accessibility_tool",
        "rootfs_package->daemon",
        "rootfs_package->replay_sync_helper",
    }
    if (
        dependency_graph["acyclic"] is not True
        or set(dependency_graph["edges"] if isinstance(dependency_graph["edges"], list) else ())
        != required_edges
        or set(
            dependency_graph["forbidden_edges"]
            if isinstance(dependency_graph["forbidden_edges"], list)
            else ()
        )
        != required_forbidden_edges
    ):
        deny("common artifact-set dependency graph drifted")

    artifacts = require_mapping(receipt["artifacts"], "common artifact-set artifacts")
    expected_artifact_names = {
        "daemon",
        "codex_launcher",
        "replay_sync_helper",
        "system_api_tool",
        "accessibility_tool",
    }
    require_exact_keys(
        artifacts, expected_artifact_names, "common artifact-set artifacts"
    )
    bindings: dict[str, dict[str, object]] = {}
    for artifact_name in sorted(expected_artifact_names):
        artifact = require_mapping(
            artifacts[artifact_name],
            f"common artifact-set artifacts.{artifact_name}",
        )
        require_exact_keys(
            artifact,
            {"bytes", "file", "sha256"},
            f"common artifact-set artifacts.{artifact_name}",
        )
        frozen = artifacts_on_disk[artifact_name]
        if (
            artifact["file"] != frozen.path.name
            or artifact["bytes"] != frozen.size
            or artifact["sha256"] != frozen.sha256
        ):
            deny(
                "common artifact-set receipt does not match physical artifact: "
                + artifact_name
            )
        bindings[artifact_name] = {
            "bytes": frozen.size,
            "file": frozen.path.name,
            "sha256": frozen.sha256,
        }

    receipt_inputs = require_mapping(
        receipt["inputs"], "common artifact-set receipt inputs"
    )
    require_exact_keys(
        receipt_inputs,
        {
            "accessibility_tool_input_sha256",
            "codex_launcher_source_sha256",
            "codex_runtime_bytes",
            "codex_runtime_sha256",
            "daemon_input_sha256",
            "replay_sync_helper_input_sha256",
            "system_api_tool_input_sha256",
        },
        "common artifact-set receipt inputs",
    )
    cross_links = {
        "daemon_input_sha256": "daemon",
        "replay_sync_helper_input_sha256": "replay_sync_helper",
        "system_api_tool_input_sha256": "system_api_tool",
        "accessibility_tool_input_sha256": "accessibility_tool",
    }
    if any(
        receipt_inputs[field] != bindings[artifact]["sha256"]
        for field, artifact in cross_links.items()
    ):
        deny("common artifact-set receipt input-to-artifact SHA binding drifted")
    if stable_measurement["launcher_executable_sha256"] != bindings["codex_launcher"]["sha256"]:
        deny("common stable-principal launcher measurement is not physically bound")
    if (
        not isinstance(receipt_inputs["codex_runtime_bytes"], int)
        or receipt_inputs["codex_runtime_bytes"] <= 0
        or any(
            not isinstance(receipt_inputs[field], str)
            or re.fullmatch(r"[0-9a-f]{64}", receipt_inputs[field]) is None
            for field in (
                "codex_launcher_source_sha256",
                "codex_runtime_sha256",
            )
        )
    ):
        deny("common artifact-set Codex source custody is malformed")
    return {
        "artifact_bindings": bindings,
        "builder_inputs": copy.deepcopy(receipt_inputs),
        "compiler": copy.deepcopy(compiler),
        "elf_inspector": copy.deepcopy(elf_inspector),
        "identity_independence_gate": copy.deepcopy(legacy_gate),
        "source_bom": copy.deepcopy(source_bom),
        "stable_principal_launcher_measurement": copy.deepcopy(stable_measurement),
        "target_compiler_closure": target_compiler_closure,
        "toolchain_snapshot": toolchain_snapshot,
    }


def validate_common_launcher_ab(
    value: object,
    raw: bytes,
    receipt_input: FrozenInput,
    common_receipt_raw: bytes,
    common_evidence: dict[str, object],
) -> dict[str, object]:
    receipt = require_mapping(value, "common launcher A/B receipt")
    require_exact_keys(
        receipt,
        {
            "artifacts",
            "builder_inputs",
            "comparisons",
            "compiler",
            "decision",
            "elf_inspector",
            "identity_independence_gate",
            "lane",
            "launcher_inputs",
            "limitations",
            "posture",
            "product_variant",
            "raw_elf_ab",
            "receipt_id",
            "receipt_id_scope",
            "release_allowed",
            "release_status",
            "schema",
            "source_bom",
            "stable_principal_launcher_measurement",
            "status",
            "target",
            "target_compiler_closure",
            "toolchain_snapshot",
        },
        "common launcher A/B receipt",
    )
    if canonical_json(receipt) != raw:
        deny("common launcher A/B receipt is not canonical indented JSON")
    if receipt_input.path.name != COMMON_LAUNCHER_AB_FILE:
        deny("common launcher A/B receipt filename drifted")
    if stat.S_IMODE(receipt_input.initial.st_mode) != 0o444:
        deny("common launcher A/B receipt mode must be 0444")
    if (
        receipt["schema"] != COMMON_LAUNCHER_AB_SCHEMA
        or receipt["decision"] != COMMON_LAUNCHER_AB_DECISION
        or receipt["status"] != COMMON_LAUNCHER_AB_HOLD
        or receipt["release_status"] != COMMON_LAUNCHER_AB_HOLD
        or receipt["release_allowed"] is not False
        or receipt["lane"] != "common"
        or receipt["product_variant"] != "common"
        or receipt["target"] != "aarch64-unknown-linux-gnu"
        or receipt["receipt_id_scope"]
        != COMMON_LAUNCHER_AB_RECEIPT_ID_SCOPE
    ):
        deny("common launcher A/B receipt header or HOLD posture drifted")
    receipt_id = receipt["receipt_id"]
    if (
        not isinstance(receipt_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", receipt_id) is None
    ):
        deny("common launcher A/B receipt id is malformed")
    preimage = copy.deepcopy(receipt)
    preimage.pop("receipt_id")
    if receipt_id != "sha256:" + hashlib.sha256(canonical_json(preimage)).hexdigest():
        deny("common launcher A/B receipt id does not bind its canonical preimage")

    if receipt["source_bom"] != common_evidence["source_bom"]:
        deny("common launcher A/B source BOM is cross-spliced")
    if receipt["builder_inputs"] != common_evidence["builder_inputs"]:
        deny("common launcher A/B builder inputs are cross-spliced")
    if (
        receipt["stable_principal_launcher_measurement"]
        != common_evidence["stable_principal_launcher_measurement"]
        or receipt["identity_independence_gate"]
        != common_evidence["identity_independence_gate"]
    ):
        deny("common launcher A/B identity evidence is cross-spliced")
    toolchain_snapshot = validate_toolchain_snapshot_binding(
        receipt["toolchain_snapshot"], "common launcher A/B toolchain snapshot"
    )
    target_compiler_closure = validate_target_compiler_closure(
        receipt["target_compiler_closure"],
        "common launcher A/B target compiler closure",
    )
    if (
        toolchain_snapshot != common_evidence["toolchain_snapshot"]
        or target_compiler_closure != common_evidence["target_compiler_closure"]
    ):
        deny("common launcher A/B toolchain evidence is cross-spliced")

    compiler = validate_launcher_build_tool(
        receipt["compiler"],
        "common launcher A/B compiler",
        "compiler_driver",
        include_path=False,
        raw_match_field="post_build_matches_raw_ab_selected_linker",
    )
    inspector = validate_launcher_build_tool(
        receipt["elf_inspector"],
        "common launcher A/B ELF inspector",
        "elf_inspector",
        include_path=False,
        raw_match_field="post_build_matches_raw_ab_selected_readelf",
    )
    for observed, expected, match_field, label in (
        (
            compiler,
            common_evidence["compiler"],
            "post_build_matches_raw_ab_selected_linker",
            "compiler",
        ),
        (
            inspector,
            common_evidence["elf_inspector"],
            "post_build_matches_raw_ab_selected_readelf",
            "ELF inspector",
        ),
    ):
        projected = copy.deepcopy(observed)
        for field in (
            "a_b_byte_equal",
            "build_time_bytes_bound_by_upstream_receipt",
            match_field,
        ):
            projected.pop(field)
        if projected != tool_without_local_path(expected):
            deny(f"common launcher A/B {label} custody differs from common v5")

    launcher_inputs = require_mapping(
        receipt["launcher_inputs"], "common launcher A/B inputs"
    )
    require_exact_keys(launcher_inputs, {"a", "b"}, "common launcher A/B inputs")
    matched_common_receipt = False
    for side in ("a", "b"):
        record = require_mapping(
            launcher_inputs[side], f"common launcher A/B inputs.{side}"
        )
        require_exact_keys(
            record,
            {"receipt_bytes", "receipt_file", "receipt_sha256"},
            f"common launcher A/B inputs.{side}",
        )
        if (
            record["receipt_file"] != COMMON_ARTIFACT_SET_FILE
            or not isinstance(record["receipt_bytes"], int)
            or isinstance(record["receipt_bytes"], bool)
            or record["receipt_bytes"] <= 0
            or not isinstance(record["receipt_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", record["receipt_sha256"]) is None
        ):
            deny(f"common launcher A/B inputs.{side} is malformed")
        if (
            record["receipt_bytes"] == len(common_receipt_raw)
            and record["receipt_sha256"] == hashlib.sha256(common_receipt_raw).hexdigest()
        ):
            matched_common_receipt = True
    if not matched_common_receipt:
        deny("common v5 receipt is not one launcher A/B lane input")

    artifacts = require_mapping(receipt["artifacts"], "common launcher A/B artifacts")
    bindings = common_evidence["artifact_bindings"]
    assert isinstance(bindings, dict)
    require_exact_keys(artifacts, set(bindings), "common launcher A/B artifacts")
    for role, binding in bindings.items():
        record = require_mapping(artifacts[role], f"common launcher A/B artifact {role}")
        require_exact_keys(
            record,
            {
                "a_b_byte_equal",
                "a_receipt_bound",
                "b_receipt_bound",
                "bytes",
                "file",
                "raw_ab_bound",
                "sha256",
            },
            f"common launcher A/B artifact {role}",
        )
        expected_raw_bound = role != "codex_launcher"
        if (
            record["file"] != binding["file"]
            or record["bytes"] != binding["bytes"]
            or record["sha256"] != binding["sha256"]
            or record["a_receipt_bound"] is not True
            or record["b_receipt_bound"] is not True
            or record["a_b_byte_equal"] is not True
            or record["raw_ab_bound"] is not expected_raw_bound
        ):
            deny(f"common launcher A/B artifact {role} is not closed")

    raw_ab = require_mapping(receipt["raw_elf_ab"], "common launcher raw ELF A/B")
    require_exact_keys(
        raw_ab,
        {"bytes", "decision", "file", "lane", "receipt_id", "release_status", "sha256"},
        "common launcher raw ELF A/B",
    )
    if (
        raw_ab["file"] != "codex-only-raw-elf-ab.v3.json"
        or raw_ab["lane"] != "common"
        or raw_ab["decision"] != "PASS_HOST_ONLY_DETERMINISTIC_CODEX_RAW_ELF_AB"
        or raw_ab["release_status"]
        != "HOLD_PRODUCT_DEVICE_AND_COMPLETE_TOOLCHAIN_ADMISSION"
        or not isinstance(raw_ab["bytes"], int)
        or isinstance(raw_ab["bytes"], bool)
        or raw_ab["bytes"] <= 0
        or not isinstance(raw_ab["sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", raw_ab["sha256"]) is None
        or not isinstance(raw_ab["receipt_id"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", raw_ab["receipt_id"]) is None
    ):
        deny("common launcher raw ELF A/B binding is malformed")

    if receipt["comparisons"] != {
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
    }:
        deny("common launcher A/B comparison set drifted")
    if receipt["posture"] != {
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
    }:
        deny("common launcher A/B posture drifted")
    if receipt["limitations"] != [
        "same_source_counterfactual_identity_independence_is_unverified",
        "stable_principal_admission_split_is_unverified",
        "source_bom_is_an_upstream_receipt_claim_not_physically_remeasured_by_this_stage",
        "receipt_ids_are_content_identifiers_not_signatures_or_attestations",
        "launcher_compiler_elf_inspector_and_snapshot_archiver_bytes_are_bound_but_recursive_toolchain_closure_is_absent",
        "codex_runtime_is_receipt_bound_but_not_a_physical_input_to_this_verifier",
        "launcher_ab_does_not_prove_rootfs_android_device_avb_or_ota",
    ]:
        deny("common launcher A/B limitations drifted")
    return {
        "bytes": len(raw),
        "compiler_and_elf_inspector_build_time_bytes_bound": True,
        "decision": receipt["decision"],
        "deterministic_artifact_set_ab_verified": True,
        "lane": "common",
        "physical_source_bom_or_live_graph_remeasured_by_this_stage": receipt[
            "comparisons"
        ]["physical_source_bom_or_live_graph_remeasured_by_this_stage"],
        "raw_elf_ab_receipt_id": raw_ab["receipt_id"],
        "receipt_id": receipt_id,
        "release_status": receipt["release_status"],
        "same_upstream_source_bom_receipt_claim": receipt["comparisons"][
            "same_upstream_source_bom_receipt_claim"
        ],
        "schema": receipt["schema"],
        "sha256": hashlib.sha256(raw).hexdigest(),
        "status": receipt["status"],
    }


def replace_version(
    path: str,
    version: str,
    max_path_bytes: int,
    label: str,
    *,
    require_marker: bool,
) -> str:
    count = path.count(VERSION_MARKER)
    if count > 1 or (require_marker and count != 1):
        deny(f"{label} contains an invalid version marker")
    materialized = path.replace(VERSION_MARKER, version)
    return canonical_relative_path(materialized, label, max_path_bytes)


def materialize(
    template: dict[str, object],
    common_evidence: dict[str, object],
    base: FrozenInput,
    common_artifact_set_receipt: FrozenInput,
    common_launcher_ab_receipt: FrozenInput,
    daemon: FrozenInput,
    codex: FrozenInput,
    system_api_tool: FrozenInput,
    accessibility_tool: FrozenInput,
    system_api_replay_sync: FrozenInput,
    zstd: FrozenInput,
    manifest_input: FrozenInput,
    manifest: dict[str, object],
    adapter_version: str,
    source_date_epoch: int,
) -> dict[str, object]:
    output = copy.deepcopy(template)
    output["source_date_epoch"] = source_date_epoch
    build_evidence = require_mapping(
        output["common_build_evidence"], "materialized.common_build_evidence"
    )
    for field in (
        "compiler",
        "elf_inspector",
        "launcher_ab",
        "stable_principal_launcher_measurement",
    ):
        build_evidence[field] = copy.deepcopy(common_evidence[field])
    build_evidence["source_bom_claim_authority"] = copy.deepcopy(
        SOURCE_BOM_CLAIM_AUTHORITY
    )
    build_evidence["toolchain_claim_authority"] = copy.deepcopy(
        TOOLCHAIN_CLAIM_AUTHORITY
    )
    build_evidence["upstream_receipt_target_compiler_closure_claim"] = (
        copy.deepcopy(common_evidence["target_compiler_closure"])
    )
    build_evidence["upstream_receipt_toolchain_snapshot_claim"] = copy.deepcopy(
        common_evidence["toolchain_snapshot"]
    )
    build_evidence["upstream_source_bom_receipt_claim"] = copy.deepcopy(
        common_evidence["source_bom"]
    )
    admission = require_mapping(output["admission"], "materialized.admission")
    admission["identity_independence_gate"] = copy.deepcopy(
        common_evidence["identity_independence_gate"]
    )
    limits = require_mapping(output["limits"], "materialized.limits")
    max_path_bytes = require_int(
        limits["max_path_bytes"], "materialized.limits.max_path_bytes", 16, 65535
    )
    inputs = require_mapping(output["inputs"], "materialized.inputs")
    tools = require_mapping(output["tools"], "materialized.tools")
    zstd_descriptor = require_mapping(tools["zstd"], "materialized.tools.zstd")
    zstd_descriptor["bytes"] = zstd.size
    zstd_descriptor["sha256"] = zstd.sha256
    inputs["base_rootfs"] = {"bytes": base.size, "sha256": base.sha256}
    for name, frozen in (
        ("common_artifact_set_receipt", common_artifact_set_receipt),
        ("common_launcher_ab_receipt", common_launcher_ab_receipt),
        ("daemon", daemon),
        ("codex", codex),
        ("system_api_tool", system_api_tool),
        ("accessibility_tool", accessibility_tool),
        ("system_api_replay_sync", system_api_replay_sync),
    ):
        descriptor = require_mapping(inputs[name], f"materialized.inputs.{name}")
        descriptor["bytes"] = frozen.size
        descriptor["sha256"] = frozen.sha256
    codex_descriptor = require_mapping(inputs["codex"], "materialized.inputs.codex")
    codex_install = canonical_install(
        codex_descriptor["install"], "Codex install", max_path_bytes
    )
    codex_install["path"] = replace_version(
        codex_install["path"],
        adapter_version,
        max_path_bytes,
        "Codex install path",
        require_marker=True,
    )
    codex_descriptor["install"] = codex_install
    manifest_descriptor = require_mapping(
        inputs["agent_manifest"], "materialized.inputs.agent_manifest"
    )
    manifest_descriptor["bytes"] = manifest_input.size
    manifest_descriptor["sha256"] = manifest_input.sha256
    manifest_descriptor["required_fields"] = copy.deepcopy(manifest)
    manifest_descriptor["allowed_fields"] = sorted(manifest_descriptor["allowed_fields"])
    daemon_descriptor = require_mapping(inputs["daemon"], "materialized.inputs.daemon")
    daemon_install = canonical_install(
        daemon_descriptor["install"], "daemon install", max_path_bytes
    )
    replay_sync_descriptor = require_mapping(
        inputs["system_api_replay_sync"],
        "materialized.inputs.system_api_replay_sync",
    )
    replay_sync_install = canonical_install(
        replay_sync_descriptor["install"],
        "system_api_replay_sync install",
        max_path_bytes,
    )
    system_api_tool_descriptor = require_mapping(
        inputs["system_api_tool"], "materialized.inputs.system_api_tool"
    )
    system_api_tool_install = canonical_install(
        system_api_tool_descriptor["install"],
        "system_api_tool install",
        max_path_bytes,
    )
    accessibility_tool_descriptor = require_mapping(
        inputs["accessibility_tool"],
        "materialized.inputs.accessibility_tool",
    )
    accessibility_tool_install = canonical_install(
        accessibility_tool_descriptor["install"],
        "accessibility_tool install",
        max_path_bytes,
    )
    manifest_install = canonical_install(
        manifest_descriptor["install"], "AgentManifest install", max_path_bytes
    )
    replacement_targets = {
        daemon_install["path"],
        codex_install["path"],
        system_api_tool_install["path"],
        accessibility_tool_install["path"],
        replay_sync_install["path"],
        manifest_install["path"],
    }
    if len(replacement_targets) != 6:
        deny("materialized replacement install paths must be distinct")
    security = require_mapping(output["security"], "materialized.security")
    for field in MIGRATION_FIELDS:
        if security[field] != []:
            deny(f"materialized {field} must remain empty")
    for field in NULLABLE_MIGRATION_FIELDS:
        if security[field] is not None:
            deny(f"materialized {field} must remain null")
    hardlinks = security["replacement_hardlink_allowlist"]
    assert isinstance(hardlinks, list)
    normalized_hardlinks: list[tuple[str, str]] = []
    for index, item in enumerate(hardlinks):
        mapping = require_mapping(item, f"materialized hardlink allowlist[{index}]")
        for field in ("path", "target"):
            mapping[field] = replace_version(
                mapping[field],
                adapter_version,
                max_path_bytes,
                f"materialized hardlink allowlist[{index}].{field}",
                require_marker=False,
            )
        path = mapping["path"]
        target = mapping["target"]
        assert isinstance(path, str) and isinstance(target, str)
        if path == target or target not in replacement_targets:
            deny("materialized hardlink does not bind a distinct replacement target")
        normalized_hardlinks.append((path, target))
    if len(set(normalized_hardlinks)) != len(normalized_hardlinks):
        deny("materialized replacement hardlink allowlist contains duplicates")
    if VERSION_MARKER in json.dumps(output, ensure_ascii=False):
        deny("materialized contract retains an unresolved version marker")
    return output


def canonical_json(value: object) -> bytes:
    try:
        return (
            json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise MaterializerError("materialized contract cannot be encoded canonically") from error


def verify_anonymous_staging(
    retained_fd: int,
    content: bytes,
    expected_mtime_ns: int,
) -> None:
    """Reverify the complete anonymous inode before it gains a pathname."""

    before = os.fstat(retained_fd)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 0
        or before.st_uid != os.geteuid()
        or before.st_size != len(content)
        or stat.S_IMODE(before.st_mode) != 0o444
        or before.st_mtime_ns != expected_mtime_ns
    ):
        deny("materialized contract anonymous staging boundary changed")
    actual_bytes, actual_sha256 = hash_open_descriptor(retained_fd)
    after = os.fstat(retained_fd)
    if published_regular_fingerprint(after) != published_regular_fingerprint(before):
        deny("materialized contract anonymous staging changed while verified")
    if (
        actual_bytes != len(content)
        or actual_sha256 != hashlib.sha256(content).hexdigest()
    ):
        deny("materialized contract bytes changed before publication")


def require_output_absent(
    parent_components: tuple[FrozenDirectoryComponent, ...],
    output_name: str,
    phase: str,
) -> None:
    verify_private_directory_chain(parent_components, "output", phase)
    try:
        os.stat(
            output_name,
            dir_fd=parent_components[-1].fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    except OSError as error:
        raise MaterializerError(
            f"output pathname could not be inspected during {phase}"
        ) from error
    deny("output already exists; overwrite is forbidden")


def verify_published_directory_chain(
    components: tuple[FrozenDirectoryComponent, ...],
    expected: tuple[os.stat_result, ...],
    phase: str,
) -> None:
    """Revalidate the retained and absolute bindings of the output parent.

    Publication necessarily changes the leaf directory's timestamps, so the
    ordinary pre-publication custody baseline cannot be reused after link(2).
    The caller records a new baseline immediately after the link and this gate
    compares every retained relationship, plus a fresh absolute reopen, to that
    exact post-link state.
    """

    if not components or len(components) != len(expected):
        deny("output post-link parent custody baseline is incomplete")
    for index, (component, baseline) in enumerate(
        zip(components, expected, strict=True)
    ):
        retained = os.fstat(component.fd)
        if (
            not stat.S_ISDIR(retained.st_mode)
            or directory_custody_fingerprint(retained)
            != directory_custody_fingerprint(baseline)
        ):
            deny(f"output parent path component changed during {phase}")
        if index == 0:
            continue
        assert component.name is not None
        try:
            lexical = os.stat(
                component.name,
                dir_fd=components[index - 1].fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            deny(f"output parent path component disappeared during {phase}")
        if (
            not stat.S_ISDIR(lexical.st_mode)
            or directory_custody_fingerprint(lexical)
            != directory_custody_fingerprint(baseline)
        ):
            deny(f"output parent path component changed during {phase}")

    fresh = open_private_directory_chain(components[-1].path, "output")
    try:
        if len(fresh) != len(expected):
            deny(f"output parent custody chain changed during {phase}")
        for component, baseline in zip(fresh, expected, strict=True):
            if (
                not stat.S_ISDIR(component.initial.st_mode)
                or directory_custody_fingerprint(component.initial)
                != directory_custody_fingerprint(baseline)
            ):
                deny(f"output parent path component changed during {phase}")
    finally:
        close_descriptors(
            [component.fd for component in fresh],
            "output final parent custody verification",
        )


def verify_committed_output(
    parent_components: tuple[FrozenDirectoryComponent, ...],
    parent_baseline: tuple[os.stat_result, ...],
    output_name: str,
    anonymous_fd: int,
    published_baseline: os.stat_result,
    content: bytes,
    expected_mtime_ns: int,
) -> None:
    """Perform the last post-link pathname, inode, metadata, and byte gate."""

    phase = "final post-link custody check"
    expected_fingerprint = published_regular_fingerprint(published_baseline)
    expected_sha256 = hashlib.sha256(content).hexdigest()
    if (
        not stat.S_ISREG(published_baseline.st_mode)
        or published_baseline.st_nlink != 1
        or published_baseline.st_uid != os.geteuid()
        or stat.S_IMODE(published_baseline.st_mode) != 0o444
        or published_baseline.st_size != len(content)
        or published_baseline.st_mtime_ns != expected_mtime_ns
    ):
        deny("materialized contract post-link inode baseline is invalid")

    verify_published_directory_chain(parent_components, parent_baseline, phase)
    retained_before = os.fstat(anonymous_fd)
    if (
        not stat.S_ISREG(retained_before.st_mode)
        or published_regular_fingerprint(retained_before) != expected_fingerprint
    ):
        deny("materialized contract retained inode changed after publication")

    pathname_fd = -1
    try:
        try:
            lexical_before = os.stat(
                output_name,
                dir_fd=parent_components[-1].fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            deny("materialized contract final pathname disappeared after publication")
        if (
            not stat.S_ISREG(lexical_before.st_mode)
            or published_regular_fingerprint(lexical_before)
            != expected_fingerprint
        ):
            deny("materialized contract final pathname was replaced after publication")
        try:
            pathname_fd = os.open(
                output_name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_components[-1].fd,
            )
        except OSError as error:
            raise MaterializerError(
                "materialized contract final pathname could not be reopened "
                "after publication"
            ) from error
        pathname_before = os.fstat(pathname_fd)
        if (
            not stat.S_ISREG(pathname_before.st_mode)
            or published_regular_fingerprint(pathname_before)
            != expected_fingerprint
        ):
            deny(
                "materialized contract final pathname no longer names the "
                "retained published inode"
            )

        retained_bytes, retained_sha256 = hash_open_descriptor(anonymous_fd)
        pathname_bytes, pathname_sha256 = hash_open_descriptor(pathname_fd)
        retained_after = os.fstat(anonymous_fd)
        pathname_after = os.fstat(pathname_fd)
        try:
            lexical_after = os.stat(
                output_name,
                dir_fd=parent_components[-1].fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            deny("materialized contract final pathname disappeared while verified")
        if (
            retained_bytes != len(content)
            or pathname_bytes != len(content)
            or retained_sha256 != expected_sha256
            or pathname_sha256 != expected_sha256
            or published_regular_fingerprint(retained_after)
            != expected_fingerprint
            or published_regular_fingerprint(pathname_after)
            != expected_fingerprint
            or published_regular_fingerprint(lexical_after)
            != expected_fingerprint
        ):
            deny(
                "materialized contract final pathname or retained bytes changed "
                "after publication"
            )
        verify_published_directory_chain(parent_components, parent_baseline, phase)
    finally:
        close_descriptors(
            [pathname_fd],
            "materialized contract final pathname verification",
        )


def publish_new(
    path: Path,
    content: bytes,
    source_date_epoch: int,
    pre_commit_check: Callable[[], None],
    post_commit_teardown: Callable[[], None] | None = None,
) -> None:
    """Publish a new contract at one explicit POSIX visibility boundary.

    The successful hard-link operation is the commit: another process may open
    the pathname before the following directory fsync returns.  Every fallible
    input check runs before that link; the post-link output custody gate runs
    after durability, explicit retained-input teardown, and guard teardown.
    Once link is attempted, this function never unlinks a pathname: an error
    from link, durability, final custody, the namespace-move guard, or descriptor
    cleanup may therefore leave an output visible.  Consumers must wait for a
    successful process exit before treating the pathname as authoritative, and
    operators must quarantine an uncertain result out of band rather than
    racing a pathname rollback.

    POSIX does not make the final input check and the output link one atomic
    operation, nor can it prevent the owning UID (or root) from changing a
    pathname immediately after return.  The private-component policy, retained
    descriptors, repeated pre-commit gates, output-chain move guard, and final
    retained-inode/pathname byte gate fail closed around the bounded commit
    window; callers must still exclude a concurrent same-UID namespace writer.
    """

    output = lexical_absolute(path)
    parent = output.parent
    if output.name in {"", ".", ".."}:
        deny("output filename is invalid")
    parent_components: tuple[FrozenDirectoryComponent, ...] = ()
    mutation_guard: NamespaceMutationGuard | None = None
    anonymous_fd = -1
    link_attempted = False
    committed = False
    expected_mtime_ns = source_date_epoch * 1_000_000_000
    published_baseline: os.stat_result | None = None
    parent_post_link_baseline: tuple[os.stat_result, ...] = ()
    try:
        parent_components = open_private_directory_chain(parent, "output")
        directory_fd = parent_components[-1].fd
        mutation_guard = NamespaceMutationGuard.open(parent_components, "output")
        require_output_absent(
            parent_components,
            output.name,
            "initial publication check",
        )
        mutation_guard.assert_quiet("initial publication check")
        anonymous_flag = getattr(os, "O_TMPFILE", 0)
        if not anonymous_flag:
            deny("output filesystem does not support anonymous staging")
        try:
            anonymous_fd = os.open(
                ".",
                os.O_RDWR | os.O_CLOEXEC | anonymous_flag,
                0o600,
                dir_fd=directory_fd,
            )
        except OSError as error:
            raise MaterializerError(
                "output filesystem cannot create anonymous staging; refusing "
                "a pathname cleanup race"
            ) from error
        view = memoryview(content)
        while view:
            written = os.write(anonymous_fd, view)
            if written <= 0:
                deny("short write while materializing contract")
            view = view[written:]
        os.fchmod(anonymous_fd, 0o444)
        os.utime(anonymous_fd, (source_date_epoch, source_date_epoch))
        os.fsync(anonymous_fd)
        # Two caller gates run while the output name is still absent and the
        # staged inode has no link.  Expensive staging rehashes and fresh path
        # reopens are completed before the second/final input callback.  After
        # that callback only the already-open namespace guard and the no-replace
        # link remain, minimizing the unavoidable input-check-to-link window.
        for check_index in range(2):
            phase = f"pre-commit check {check_index + 1}"
            verify_anonymous_staging(
                anonymous_fd,
                content,
                expected_mtime_ns,
            )
            require_output_absent(parent_components, output.name, phase)
            mutation_guard.assert_quiet(phase)
            pre_commit_check()
            if check_index == 0:
                verify_anonymous_staging(
                    anonymous_fd,
                    content,
                    expected_mtime_ns,
                )
                require_output_absent(parent_components, output.name, phase)
                mutation_guard.assert_quiet(phase)
        mutation_guard.assert_quiet("final pre-commit boundary")

        # This is the POSIX visibility commit.  There is intentionally no
        # pathname rollback after entry: stat(name)->unlink(name) cannot be made
        # conditional on inode identity and can delete a concurrent replacement.
        try:
            link_attempted = True
            os.link(
                f"/proc/self/fd/{anonymous_fd}",
                output.name,
                dst_dir_fd=directory_fd,
                follow_symlinks=True,
            )
        except BaseException as error:
            raise MaterializerError(
                "materialized contract link outcome is uncertain; no pathname "
                "was removed and an output may remain visible"
            ) from error
        committed = True
        published_baseline = os.fstat(anonymous_fd)
        parent_post_link_baseline = tuple(
            os.fstat(component.fd) for component in parent_components
        )
        try:
            os.fsync(directory_fd)
        except OSError as error:
            raise MaterializerError(
                "materialized contract link committed but directory durability "
                "is uncertain; the output remains visible and was not rolled "
                f"back: {error}"
            ) from error
        try:
            mutation_guard.assert_quiet("publication commit")
        except Exception as error:
            raise MaterializerError(
                "materialized contract link committed but output-parent custody "
                "became uncertain; the output remains visible and was not rolled back"
            ) from error
    finally:
        active_error = sys.exc_info()[1]
        retained_input_teardown_error: BaseException | None = None
        if committed and post_commit_teardown is not None:
            try:
                post_commit_teardown()
            except BaseException as error:
                retained_input_teardown_error = error
        cleanup_errors: list[str] = []
        if mutation_guard is not None:
            try:
                mutation_guard.close()
            except BaseException as error:
                cleanup_errors.append(str(error))
        final_verification_error: BaseException | None = None
        if committed:
            try:
                if published_baseline is None:
                    deny(
                        "materialized contract post-link inode baseline is "
                        "incomplete"
                    )
                verify_committed_output(
                    parent_components,
                    parent_post_link_baseline,
                    output.name,
                    anonymous_fd,
                    published_baseline,
                    content,
                    expected_mtime_ns,
                )
            except BaseException as error:
                final_verification_error = error
        cleanup_errors.extend(descriptor_close_errors([anonymous_fd]))
        cleanup_errors.extend(
            descriptor_close_errors(
                [component.fd for component in parent_components]
            )
        )
        if final_verification_error is not None:
            details = (
                "materialized contract link committed but final "
                "pathname/content custody failed; the output remains visible "
                "and was not rolled back"
            )
            if active_error is not None:
                details += f"; primary: {active_error}"
            if retained_input_teardown_error is not None:
                details += (
                    "; retained-input teardown: "
                    f"{retained_input_teardown_error}"
                )
            details += f"; final verification: {final_verification_error}"
            if cleanup_errors:
                details += "; cleanup: " + "; ".join(cleanup_errors)
            failure = MaterializerError(details)
            if active_error is not None:
                raise failure from active_error
            raise failure from final_verification_error
        if cleanup_errors:
            state = (
                "after the output link committed; the output remains visible"
                if committed
                else (
                    "after the output link was attempted; its outcome remains "
                    "uncertain and any output was retained"
                    if link_attempted
                    else "before an output link was attempted"
                )
            )
            details = f"materialized contract publication cleanup failed {state}"
            if active_error is not None:
                details += f"; primary: {active_error}"
            if retained_input_teardown_error is not None:
                details += (
                    "; retained-input teardown: "
                    f"{retained_input_teardown_error}"
                )
            details += "; cleanup: " + "; ".join(cleanup_errors)
            composite = MaterializerError(details)
            if active_error is not None:
                raise composite from active_error
            if retained_input_teardown_error is not None:
                raise composite from retained_input_teardown_error
            raise composite
        if retained_input_teardown_error is not None:
            details = (
                "materialized contract link committed but retained-input "
                "teardown failed; the output remains visible and was not "
                "rolled back"
            )
            if active_error is not None:
                details += f"; primary: {active_error}"
            details += f"; cleanup: {retained_input_teardown_error}"
            failure = MaterializerError(details)
            if active_error is not None:
                raise failure from active_error
            raise failure from retained_input_teardown_error


def parse_source_date_epoch(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a base-10 integer") from error
    if not 0 <= parsed <= MAX_SOURCE_DATE_EPOCH:
        raise argparse.ArgumentTypeError("is outside the supported epoch range")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--base-rootfs", type=Path, required=True)
    parser.add_argument("--common-artifact-set-receipt", type=Path, required=True)
    parser.add_argument("--common-launcher-ab-receipt", type=Path, required=True)
    parser.add_argument("--daemon", type=Path, required=True)
    parser.add_argument("--codex-binary", type=Path, required=True)
    parser.add_argument("--system-api-tool", type=Path, required=True)
    parser.add_argument("--accessibility-tool", type=Path, required=True)
    parser.add_argument("--system-api-replay-sync", type=Path, required=True)
    parser.add_argument("--agent-manifest", type=Path, required=True)
    parser.add_argument("--zstd", type=Path, required=True)
    parser.add_argument("--source-date-epoch", type=parse_source_date_epoch, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def run(args: argparse.Namespace) -> None:
    with PublicationAwareExitStack() as stack:
        template_input = stack.enter_context(
            FrozenInput.open(args.template, "template", MAX_TEMPLATE_BYTES)
        )
        base = stack.enter_context(
            FrozenInput.open(args.base_rootfs, "base_rootfs", MAX_BASE_BYTES)
        )
        common_artifact_set_receipt = stack.enter_context(
            FrozenInput.open(
                args.common_artifact_set_receipt,
                "common_artifact_set_receipt",
                MAX_COMMON_RECEIPT_BYTES,
            )
        )
        common_launcher_ab_receipt = stack.enter_context(
            FrozenInput.open(
                args.common_launcher_ab_receipt,
                "common_launcher_ab_receipt",
                MAX_LAUNCHER_AB_RECEIPT_BYTES,
            )
        )
        daemon = stack.enter_context(
            FrozenInput.open(
                args.daemon, "daemon", MAX_BINARY_BYTES, require_executable=True
            )
        )
        codex = stack.enter_context(
            FrozenInput.open(
                args.codex_binary,
                "codex_binary",
                MAX_BINARY_BYTES,
                require_executable=True,
            )
        )
        system_api_tool = stack.enter_context(
            FrozenInput.open(
                args.system_api_tool,
                "system_api_tool",
                MAX_BINARY_BYTES,
                require_executable=True,
            )
        )
        accessibility_tool = stack.enter_context(
            FrozenInput.open(
                args.accessibility_tool,
                "accessibility_tool",
                MAX_BINARY_BYTES,
                require_executable=True,
            )
        )
        system_api_replay_sync = stack.enter_context(
            FrozenInput.open(
                args.system_api_replay_sync,
                "system_api_replay_sync",
                MAX_BINARY_BYTES,
                require_executable=True,
            )
        )
        zstd = stack.enter_context(
            FrozenInput.open(
                args.zstd,
                "zstd",
                MAX_HOST_TOOL_BYTES,
                require_executable=True,
            )
        )
        manifest_input = stack.enter_context(
            FrozenInput.open(args.agent_manifest, "AgentManifest", MAX_MANIFEST_BYTES)
        )
        template = validate_template(
            strict_json_bytes(template_input.read_all(), "template")
        )
        verify_aarch64_elf(daemon, require_static=False)
        verify_aarch64_elf(codex, require_static=True)
        verify_aarch64_elf(system_api_tool, require_static=False)
        verify_aarch64_elf(accessibility_tool, require_static=False)
        verify_aarch64_elf(system_api_replay_sync, require_static=False)
        common_receipt_raw = common_artifact_set_receipt.read_all()
        common_evidence = validate_common_artifact_set(
            strict_json_bytes(
                common_receipt_raw, "common artifact-set receipt"
            ),
            common_receipt_raw,
            common_artifact_set_receipt,
            {
                "daemon": daemon,
                "codex_launcher": codex,
                "system_api_tool": system_api_tool,
                "accessibility_tool": accessibility_tool,
                "replay_sync_helper": system_api_replay_sync,
            },
        )
        launcher_ab_raw = common_launcher_ab_receipt.read_all()
        common_evidence["launcher_ab"] = validate_common_launcher_ab(
            strict_json_bytes(
                launcher_ab_raw, "common launcher A/B receipt"
            ),
            launcher_ab_raw,
            common_launcher_ab_receipt,
            common_receipt_raw,
            common_evidence,
        )
        template_inputs = require_mapping(template["inputs"], "template.inputs")
        template_manifest = require_mapping(
            template_inputs["agent_manifest"], "template.inputs.agent_manifest"
        )
        manifest, adapter_version = validate_manifest(
            strict_json_bytes(manifest_input.read_all(), "AgentManifest"),
            template_manifest,
            codex.sha256,
        )
        contract = materialize(
            template,
            common_evidence,
            base,
            common_artifact_set_receipt,
            common_launcher_ab_receipt,
            daemon,
            codex,
            system_api_tool,
            accessibility_tool,
            system_api_replay_sync,
            zstd,
            manifest_input,
            manifest,
            adapter_version,
            args.source_date_epoch,
        )
        content = canonical_json(contract)
        frozen_inputs = (
            template_input,
            base,
            common_artifact_set_receipt,
            common_launcher_ab_receipt,
            daemon,
            codex,
            system_api_tool,
            accessibility_tool,
            system_api_replay_sync,
            zstd,
            manifest_input,
        )
        for frozen in frozen_inputs:
            frozen.verify_unchanged()

        def verify_inputs_before_commit() -> None:
            for frozen in frozen_inputs:
                frozen.verify_final()

        publish_new(
            args.output,
            content,
            args.source_date_epoch,
            verify_inputs_before_commit,
            post_commit_teardown=stack.close_retained_inputs,
        )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        run(args)
    except (MaterializerError, OSError) as error:
        print(f"rootfs contract materialization denied: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
