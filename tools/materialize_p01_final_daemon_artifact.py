#!/usr/bin/env python3
"""Materialize one fail-closed P01 userdebug final-daemon evidence set.

The v5 materializer deliberately has no candidate ELF digests compiled into
it.  It re-measures the canonical v8 pre-daemon receipt, every physical input,
the canonical source BOM, the stable-principal contract, and the daemon's
linker-retained measurement.  A raw-build receipt is optional, but when it is
provided its physical ELF set is re-opened and must match the v8 set in both
directions.  A canonical P01 launcher A/B v5 receipt is required, its closed
schema and content bindings are revalidated, and its selected physical inputs
are remeasured.  A final-daemon A/B result is accepted only from a complete
peer lane that is re-verified by this process; a declaration-only final A/B
receipt is never an authority.

This remains a non-product, userdebug-only evidence producer.  Missing A/B
inputs produce an honest HOLD.  Complete byte-identical host A/B inputs may
produce a host-determinism PASS, but never device, effect, write, OTA, AVB, or
release authority.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
from typing import Iterable


sys.dont_write_bytecode = True


TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import build_p01_userdebug_agent_launchers as primitives  # noqa: E402
import verify_codex_only_raw_elf_ab as raw_ab_contract  # noqa: E402


REPOSITORY = Path(__file__).resolve().parents[1]
PRE_DAEMON_RECEIPT_NAME = "p01-userdebug-pre-daemon-artifact-set.v8.json"
PRE_DAEMON_SCHEMA = "org.trillionnium.p01-userdebug-pre-daemon-artifact-set.v8"
FINAL_RECEIPT_NAME = "p01-userdebug-final-daemon-artifact-set.v5.json"
FINAL_RECEIPT_SCHEMA = "org.trillionnium.p01-userdebug-final-daemon-artifact-set.v5"
DAEMON_NAME = "trillionniumd"
SOURCE_BOM_NAME = "p01-source-bom.v2.json"
STABLE_PRINCIPAL_CONTRACT_NAME = "agent-principal-registry-v2.json"
RAW_RECEIPT_NAME = "codex-only-raw-elf-set.p01-userdebug-pre-daemon.v3.json"
RAW_RECEIPT_SCHEMA = "org.trillionnium.codex-only-raw-elf-set.v3"
RAW_RECEIPT_ID_SCOPE = (
    "sha256(canonical-json-utf8-sort-keys-indent-2-lf-without-receipt_id)"
)
RAW_PASS = "PASS_HOST_ONLY_CODEX_RAW_ELF_SET"
RAW_PRODUCT_HOLD = "HOLD_PRODUCT_DEVICE_AND_COMPLETE_TOOLCHAIN_ADMISSION"
RAW_SOURCE_BOM_AUTHORITY = "local_source_measurement_not_release_authority"
PRE_SOURCE_BOM_AUTHORITY = (
    "local_exact_clean_graph_not_build_or_release_authority"
)
LAUNCHER_AB_RECEIPT_NAME = "codex-launcher-artifact-set-ab.v5.json"
LAUNCHER_AB_RECEIPT_SCHEMA = "org.trillionnium.codex-launcher-artifact-set-ab.v5"
LAUNCHER_AB_DECISION = "PASS_HOST_ONLY_DETERMINISTIC_CODEX_LAUNCHER_ARTIFACT_SET_AB"
LAUNCHER_AB_HOLD = (
    "HOLD_IDENTITY_INDEPENDENCE_PRODUCT_DEVICE_AND_COMPLETE_TOOLCHAIN_ADMISSION"
)
LAUNCHER_BUILD_TOOL_SCHEMA = "org.trillionnium.launcher-build-tool-custody.v1"
FINAL_HOST_PASS = "PASS_HOST_ONLY_DETERMINISTIC_P01_FINAL_DAEMON_A_B"
FINAL_HOST_HOLD = "HOLD_HOST_RAW_OR_A_B_EVIDENCE_INCOMPLETE"
FINAL_PRODUCT_HOLD = (
    "HOLD_PRODUCT_DEVICE_COMPLETE_TOOLCHAIN_AND_IDENTITY_ADMISSION"
)
VERIFIED_MEASUREMENT_SCHEMA = (
    "org.trillionnium.p01-userdebug-verified-daemon-measurement.v3"
)
EMBEDDED_MEASUREMENT_SCHEMA = (
    "org.trillionnium.p01-userdebug-daemon-measurement.v4"
)
MEASUREMENT_SECTION = ".trillionnium_p01_measurement_v4"
IDENTITY_HOLD_SECTION = ".trillionnium_p01_identity_hold_v2"
IDENTITY_HOLD_SCHEMA = (
    "org.trillionnium.p01-userdebug-identity-independence-hold.v2"
)
VARIANT_SECTION = ".trillionnium.p01.provider.variant"
VARIANT_MARKER = "org.trillionnium.p01.provider.compiled-variant.v1=userdebug"
MAX_GLIBC = (2, 36)
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
PRE_ARTIFACTS = {
    "system_api_tool": "trillionnium-agent-system-api-device-conformance",
    "replay_sync_helper": (
        "trillionnium-system-api-device-conformance-replay-sync"
    ),
    "high_water_authority": "trillionnium-direct-operation-custody-high-water",
    "codex_launcher": "trillionnium-codex-agent-0.144.1-p01-userdebug",
}
RAW_ARTIFACTS = {
    role: name for role, name in PRE_ARTIFACTS.items() if role != "codex_launcher"
}
STABLE_PRINCIPAL_CONTRACT = (
    REPOSITORY
    / "crates/trillionnium-os-types/contracts/agent-principal-registry-v2.json"
)
LEGACY_DESCRIPTOR_CONTRACT = (
    REPOSITORY
    / "crates/trillionnium-os-types/contracts/agent-descriptor-registry-v1.json"
)
BUILTIN_IDENTITY_SOURCE = REPOSITORY / "apps/trillionniumd/src/builtin_provider_identity.rs"
CAPABILITY_ROOT_CONTRACT = (
    REPOSITORY
    / "crates/trillionnium-os-types/contracts/capability-lease-root-registration-v1.json"
)
CAPABILITY_ROOT_SOURCE = (
    REPOSITORY / "crates/trillionnium-os-types/src/capability_lease_root_registration.rs"
)
CAPABILITY_SOURCE_ROOT = CAPABILITY_ROOT_SOURCE.parent
P01_DIRECT_TOOLS_SOURCE_ROOT = (
    REPOSITORY / "crates/trillionnium-agent-direct-tools/src"
)
CONTROL_REPOSITORY = REPOSITORY
AUTHORITY_SOURCE_GIT = Path("/usr/bin/git")
AUTHORITY_SOURCE_CLOSURE_SCHEMA = (
    "org.trillionnium.p01-authority-source-control-head-closure.v1"
)
CAPABILITY_ROOT_SOURCE_STATUS = (
    "source_only_no_transport_no_runtime_no_effect_authority_v1"
)


class FinalArtifactError(RuntimeError):
    """A physical artifact, receipt, or authority boundary failed closed."""


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json(value: object) -> bytes:
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


def reject_duplicate_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def reject_nonstandard_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def strict_json(raw: bytes, label: str, *, canonical: bool = True) -> dict[str, object]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_object,
            parse_constant=reject_nonstandard_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise FinalArtifactError(f"{label} is invalid JSON") from error
    if not isinstance(value, dict):
        raise FinalArtifactError(f"{label} is not a JSON object")
    if canonical and canonical_json(value) != raw:
        raise FinalArtifactError(f"{label} is not canonical JSON")
    return value


def exact_keys(value: object, expected: Iterable[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != set(expected):
        raise FinalArtifactError(f"{label} does not use the closed schema")
    return value


def require_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or LOWER_SHA256.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise FinalArtifactError(f"{label} is not a nonzero lowercase SHA-256")
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


def require_distinct_physical_identity(
    selected: os.stat_result, peer: os.stat_result, label: str
) -> None:
    if (selected.st_dev, selected.st_ino) == (peer.st_dev, peer.st_ino):
        raise FinalArtifactError(f"{label} alias the same inode")


def lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def controlled_path_component_metadata(
    descriptor: int,
    label: str,
    *,
    leaf: bool,
    strict_leaf_permissions: bool,
    allow_root_leaf_owner: bool = False,
    allow_shared_sticky_ancestor: bool = False,
) -> os.stat_result:
    metadata = os.fstat(descriptor)
    allowed_owners = (
        {os.geteuid()}
        if leaf and not allow_root_leaf_owner
        else {0, os.geteuid()}
    )
    mode = stat.S_IMODE(metadata.st_mode)
    shared_sticky_ancestor = (
        allow_shared_sticky_ancestor
        and not leaf
        and metadata.st_uid == 0
        and mode == 0o1777
    )
    unsafe_permissions = False if shared_sticky_ancestor else (
        bool(mode & 0o022)
        if (leaf and strict_leaf_permissions) or metadata.st_uid != os.geteuid()
        else bool(mode & 0o002)
    )
    if mode & stat.S_ISVTX and not shared_sticky_ancestor:
        unsafe_permissions = True
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in allowed_owners
        or unsafe_permissions
    ):
        raise FinalArtifactError(f"{label} path component is not owner-controlled")
    return metadata


class RetainedDirectoryPath:
    def __init__(
        self,
        path: Path,
        label: str,
        descriptors: list[int],
        metadata: list[os.stat_result],
        allow_leaf_content_changes: bool = False,
        strict_leaf_permissions: bool = True,
        allow_root_leaf_owner: bool = False,
        allow_shared_sticky_ancestors: bool = False,
        relax_ancestor_content_changes: bool = False,
    ) -> None:
        self.path = path
        self.label = label
        self.descriptors = descriptors
        self.metadata = metadata
        self.allow_leaf_content_changes = allow_leaf_content_changes
        self.strict_leaf_permissions = strict_leaf_permissions
        self.allow_root_leaf_owner = allow_root_leaf_owner
        self.allow_shared_sticky_ancestors = allow_shared_sticky_ancestors
        self.relax_ancestor_content_changes = relax_ancestor_content_changes

    @classmethod
    def open(
        cls,
        path: Path,
        label: str,
        *,
        allow_leaf_content_changes: bool = False,
        strict_leaf_permissions: bool = True,
        allow_root_leaf_owner: bool = False,
        allow_shared_sticky_ancestors: bool = False,
        relax_ancestor_content_changes: bool = False,
    ) -> "RetainedDirectoryPath":
        absolute = lexical_absolute(path)
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
        descriptors: list[int] = []
        metadata: list[os.stat_result] = []
        try:
            try:
                descriptor = os.open(absolute.anchor, flags)
            except OSError as error:
                raise FinalArtifactError(
                    f"cannot open {label} root without following links"
                ) from error
            descriptors.append(descriptor)
            metadata.append(
                controlled_path_component_metadata(
                    descriptor,
                    label,
                    leaf=len(absolute.parts) == 1,
                    strict_leaf_permissions=strict_leaf_permissions,
                    allow_root_leaf_owner=allow_root_leaf_owner,
                    allow_shared_sticky_ancestor=allow_shared_sticky_ancestors,
                )
            )
            for index, component in enumerate(absolute.parts[1:], start=1):
                parent = descriptors[-1]
                try:
                    lexical = os.stat(
                        component, dir_fd=parent, follow_symlinks=False
                    )
                except OSError as error:
                    raise FinalArtifactError(
                        f"cannot inspect {label} path component"
                    ) from error
                if not stat.S_ISDIR(lexical.st_mode):
                    raise FinalArtifactError(
                        f"{label} path contains a symbolic link or non-directory component"
                    )
                try:
                    descriptor = os.open(component, flags, dir_fd=parent)
                except OSError as error:
                    raise FinalArtifactError(
                        f"cannot open {label} path component without following links"
                    ) from error
                descriptors.append(descriptor)
                opened = controlled_path_component_metadata(
                    descriptor,
                    label,
                    leaf=index == len(absolute.parts) - 1,
                    strict_leaf_permissions=strict_leaf_permissions,
                    allow_root_leaf_owner=allow_root_leaf_owner,
                    allow_shared_sticky_ancestor=allow_shared_sticky_ancestors,
                )
                if stable_identity(opened) != stable_identity(lexical):
                    raise FinalArtifactError(
                        f"{label} path component changed while opened"
                    )
                metadata.append(opened)
            return cls(
                absolute,
                label,
                descriptors,
                metadata,
                allow_leaf_content_changes,
                strict_leaf_permissions,
                allow_root_leaf_owner,
                allow_shared_sticky_ancestors,
                relax_ancestor_content_changes,
            )
        except BaseException as primary:
            cleanup_failures: list[str] = []
            for descriptor in reversed(descriptors):
                try:
                    os.close(descriptor)
                except BaseException as error:
                    cleanup_failures.append(f"fd {descriptor}: {error}")
            if cleanup_failures:
                raise FinalArtifactError(
                    f"{label} open failed and descriptor cleanup was incomplete: "
                    + "; ".join(cleanup_failures)
                ) from primary
            raise

    @property
    def descriptor(self) -> int:
        return self.descriptors[-1]

    @property
    def leaf_metadata(self) -> os.stat_result:
        return self.metadata[-1]

    def assert_held_stable(self) -> None:
        for index, (descriptor, expected) in enumerate(
            zip(self.descriptors, self.metadata)
        ):
            current = os.fstat(descriptor)
            if self._component_identity(current, index) != self._component_identity(
                expected, index
            ):
                raise FinalArtifactError(
                    f"{self.label} pathname or retained directory changed"
                )

    def _component_identity(
        self, metadata: os.stat_result, index: int
    ) -> tuple[int, ...]:
        if self.allow_leaf_content_changes and index == len(self.metadata) - 1:
            return (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_uid,
                metadata.st_gid,
                metadata.st_mode,
                metadata.st_nlink,
            )
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            self.relax_ancestor_content_changes
            and index != len(self.metadata) - 1
        ):
            # Authority-source custody freezes each scanned namespace as the
            # leaf of its own retained path.  Shared ancestors still bind to
            # the same safe directory inode, but unrelated sibling churn must
            # not invalidate that namespace closure.
            return (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_uid,
                metadata.st_gid,
                metadata.st_mode,
            )
        if (
            self.allow_shared_sticky_ancestors
            and index != len(self.metadata) - 1
            and metadata.st_uid == 0
            and mode == 0o1777
        ):
            # Offline verification may traverse /tmp.  Bind the retained and
            # freshly reopened component to the same directory inode, while
            # ignoring unrelated namespace churn in that shared ancestor.
            return (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_uid,
                metadata.st_gid,
                metadata.st_mode,
            )
        return stable_identity(metadata)

    def assert_stable(self) -> None:
        self.assert_held_stable()
        fresh = type(self).open(
            self.path,
            self.label,
            allow_leaf_content_changes=self.allow_leaf_content_changes,
            strict_leaf_permissions=self.strict_leaf_permissions,
            allow_root_leaf_owner=self.allow_root_leaf_owner,
            allow_shared_sticky_ancestors=self.allow_shared_sticky_ancestors,
            relax_ancestor_content_changes=self.relax_ancestor_content_changes,
        )
        try:
            if len(fresh.metadata) != len(self.metadata) or any(
                self._component_identity(current, index)
                != self._component_identity(expected, index)
                for index, (current, expected) in enumerate(
                    zip(fresh.metadata, self.metadata)
                )
            ):
                raise FinalArtifactError(
                    f"{self.label} pathname or retained component changed"
                )
            fresh.assert_held_stable()
            self.assert_held_stable()
        finally:
            fresh.close()

    def close(self) -> None:
        descriptors = list(reversed(self.descriptors))
        self.descriptors.clear()
        failures: list[str] = []
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except BaseException as error:
                failures.append(f"fd {descriptor}: {error}")
        if failures:
            raise FinalArtifactError(
                f"{self.label} descriptor cleanup failed: " + "; ".join(failures)
            )

    def __enter__(self) -> "RetainedDirectoryPath":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def read_descriptor_bytes(
    descriptor: int,
    before: os.stat_result,
    label: str,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total < before.st_size:
        chunk = os.pread(
            descriptor,
            min(1024 * 1024, before.st_size - total),
            total,
        )
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    after = os.fstat(descriptor)
    if total != before.st_size or stable_identity(before) != stable_identity(after):
        raise FinalArtifactError(f"{label} changed while being measured")
    return b"".join(chunks)


def validate_regular_input_metadata(
    metadata: os.stat_result,
    label: str,
    maximum: int,
    *,
    modes: set[int] | None,
    require_invoking_user: bool,
) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or (require_invoking_user and metadata.st_uid != os.geteuid())
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > maximum
        or (modes is not None and mode not in modes)
    ):
        raise FinalArtifactError(
            f"{label} ownership, type, link count, size, or mode is not exact"
        )


class RetainedRegularInput:
    def __init__(
        self,
        path: Path,
        label: str,
        parent: RetainedDirectoryPath,
        descriptor: int,
        initial_metadata: os.stat_result,
        initial_bytes: bytes,
    ) -> None:
        self.path = path
        self.label = label
        self.parent = parent
        self.descriptor = descriptor
        self.initial_metadata = initial_metadata
        self.initial_bytes = initial_bytes

    @classmethod
    def open(
        cls,
        path: Path,
        label: str,
        maximum: int,
        *,
        modes: set[int] | None = None,
        require_invoking_user: bool = True,
        relax_ancestor_content_changes: bool = False,
    ) -> "RetainedRegularInput":
        absolute = lexical_absolute(path)
        if absolute.name in {"", ".", ".."}:
            raise FinalArtifactError(f"{label} filename is invalid")
        parent = RetainedDirectoryPath.open(
            absolute.parent,
            f"{label} parent",
            strict_leaf_permissions=False,
            relax_ancestor_content_changes=relax_ancestor_content_changes,
        )
        descriptor = -1
        try:
            try:
                lexical = os.stat(
                    absolute.name,
                    dir_fd=parent.descriptor,
                    follow_symlinks=False,
                )
                descriptor = os.open(
                    absolute.name,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=parent.descriptor,
                )
            except OSError as error:
                raise FinalArtifactError(
                    f"cannot open {label} without following links"
                ) from error
            metadata = os.fstat(descriptor)
            validate_regular_input_metadata(
                metadata,
                label,
                maximum,
                modes=modes,
                require_invoking_user=require_invoking_user,
            )
            if stable_identity(metadata) != stable_identity(lexical):
                raise FinalArtifactError(f"{label} changed while being opened")
            raw = read_descriptor_bytes(descriptor, metadata, label)
            retained = cls(absolute, label, parent, descriptor, metadata, raw)
            retained.assert_held_stable()
            return retained
        except BaseException as primary:
            cleanup_failures: list[str] = []
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except BaseException as error:
                    cleanup_failures.append(f"file fd {descriptor}: {error}")
            try:
                parent.close()
            except BaseException as error:
                cleanup_failures.append(str(error))
            if cleanup_failures:
                raise FinalArtifactError(
                    f"{label} open failed and descriptor cleanup was incomplete: "
                    + "; ".join(cleanup_failures)
                ) from primary
            raise

    def assert_held_stable(self) -> None:
        current = os.fstat(self.descriptor)
        if stable_identity(current) != stable_identity(self.initial_metadata):
            raise FinalArtifactError(f"{self.label} retained input changed")
        if read_descriptor_bytes(
            self.descriptor, self.initial_metadata, self.label
        ) != self.initial_bytes:
            raise FinalArtifactError(f"{self.label} retained input bytes changed")

    def assert_stable(self) -> None:
        self.assert_held_stable()
        self.parent.assert_stable()
        fresh_parent = RetainedDirectoryPath.open(
            self.path.parent,
            f"{self.label} parent",
            strict_leaf_permissions=False,
            relax_ancestor_content_changes=(
                self.parent.relax_ancestor_content_changes
            ),
        )
        fresh_descriptor = -1
        try:
            try:
                lexical = os.stat(
                    self.path.name,
                    dir_fd=fresh_parent.descriptor,
                    follow_symlinks=False,
                )
                fresh_descriptor = os.open(
                    self.path.name,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=fresh_parent.descriptor,
                )
            except OSError as error:
                raise FinalArtifactError(
                    f"cannot reopen {self.label} during final custody check"
                ) from error
            reopened = os.fstat(fresh_descriptor)
            if (
                stable_identity(lexical) != stable_identity(self.initial_metadata)
                or stable_identity(reopened) != stable_identity(self.initial_metadata)
                or read_descriptor_bytes(
                    fresh_descriptor, reopened, self.label
                )
                != self.initial_bytes
            ):
                raise FinalArtifactError(
                    f"{self.label} pathname changed during final custody check"
                )
            fresh_parent.assert_held_stable()
            self.parent.assert_held_stable()
            self.assert_held_stable()
        finally:
            active_error = sys.exc_info()[1]
            cleanup_failures: list[str] = []
            if fresh_descriptor >= 0:
                try:
                    os.close(fresh_descriptor)
                except BaseException as error:
                    cleanup_failures.append(
                        f"fresh file fd {fresh_descriptor}: {error}"
                    )
            try:
                fresh_parent.close()
            except BaseException as error:
                cleanup_failures.append(str(error))
            if cleanup_failures:
                cleanup_error = FinalArtifactError(
                    f"{self.label} final custody cleanup failed: "
                    + "; ".join(cleanup_failures)
                )
                if active_error is not None:
                    raise cleanup_error from active_error
                raise cleanup_error

    def close(self) -> None:
        failures: list[str] = []
        descriptor = self.descriptor
        self.descriptor = -1
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except BaseException as error:
                failures.append(f"file fd {descriptor}: {error}")
        try:
            self.parent.close()
        except BaseException as error:
            failures.append(str(error))
        if failures:
            raise FinalArtifactError(
                f"{self.label} descriptor cleanup failed: " + "; ".join(failures)
            )

    def __enter__(self) -> "RetainedRegularInput":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class RetainedLauncherBuildTools:
    """Hold launcher/raw build tools and their path custody to the final gate."""

    def __init__(self) -> None:
        self.entries: list[
            tuple[str, primitives.LauncherBuildTool, RetainedDirectoryPath]
        ] = []

    def retain(self, tool: primitives.LauncherBuildTool, label: str) -> None:
        parent: RetainedDirectoryPath | None = None
        try:
            parent = RetainedDirectoryPath.open(
                tool.path.parent,
                f"{label} parent custody",
                strict_leaf_permissions=False,
                allow_root_leaf_owner=True,
            )
            if stable_identity(os.fstat(tool.parent_descriptor)) != stable_identity(
                parent.leaf_metadata
            ):
                raise FinalArtifactError(
                    f"{label} retained parent differs from its absolute pathname"
                )
            self.entries.append((label, tool, parent))
        except BaseException as primary:
            cleanup_failures: list[str] = []
            try:
                tool.close()
            except BaseException as error:
                cleanup_failures.append(f"tool cleanup: {error}")
            if parent is not None:
                try:
                    parent.close()
                except BaseException as error:
                    cleanup_failures.append(f"parent cleanup: {error}")
            if cleanup_failures:
                raise FinalArtifactError(
                    f"{label} custody setup failed and cleanup was incomplete: "
                    + "; ".join(cleanup_failures)
                ) from primary
            raise

    def assert_stable(self) -> None:
        for label, tool, parent in self.entries:
            parent.assert_stable()
            if stable_identity(os.fstat(tool.parent_descriptor)) != stable_identity(
                parent.leaf_metadata
            ):
                raise FinalArtifactError(f"{label} retained parent custody changed")
            try:
                primitives.revalidate_launcher_build_tool(tool)
            except RuntimeError as error:
                raise FinalArtifactError(
                    f"{label} changed while retained through final publication"
                ) from error
            if stable_identity(os.fstat(tool.parent_descriptor)) != stable_identity(
                parent.leaf_metadata
            ):
                raise FinalArtifactError(f"{label} retained parent custody changed")
            parent.assert_stable()

    def close(self) -> None:
        entries = list(reversed(self.entries))
        self.entries.clear()
        failures: list[str] = []
        for label, tool, parent in entries:
            try:
                tool.close()
            except BaseException as error:
                failures.append(f"{label} tool: {error}")
            try:
                parent.close()
            except BaseException as error:
                failures.append(f"{label} parent: {error}")
        if failures:
            raise FinalArtifactError(
                "launcher/raw build-tool descriptor cleanup failed: "
                + "; ".join(failures)
            )

    def __enter__(self) -> "RetainedLauncherBuildTools":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def git_blob_oid(value: bytes, object_format: str) -> str:
    if object_format not in {"sha1", "sha256"}:
        raise FinalArtifactError("authority-source Git object format is unsupported")
    digest = hashlib.new(object_format)
    digest.update(f"blob {len(value)}\0".encode("ascii"))
    digest.update(value)
    return digest.hexdigest()


def authority_source_git_environment() -> dict[str, str]:
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "LD_LIBRARY_PATH": "",
        "PATH": str(AUTHORITY_SOURCE_GIT.parent),
        "SOURCE_DATE_EPOCH": "1785110400",
        "TMPDIR": "/tmp",
        "TZ": "UTC",
    }


def run_retained_authority_git(
    tool: primitives.LauncherBuildTool,
    arguments: list[str],
) -> bytes:
    try:
        return primitives.run_retained_tool(
            tool,
            [
                "--no-pager",
                "--no-replace-objects",
                "-c",
                "color.ui=false",
                *arguments,
            ],
            environment=authority_source_git_environment(),
            cwd=CONTROL_REPOSITORY,
            timeout=30,
        )
    except RuntimeError as error:
        raise FinalArtifactError(
            "cannot read the BOM-fixed authority-source Git tree"
        ) from error


def source_bom_control_git(raw: bytes) -> dict[str, str]:
    receipt = strict_json(raw, "canonical source BOM")
    projects = receipt.get("projects")
    if not isinstance(projects, list):
        raise FinalArtifactError("source BOM control-plane project set is malformed")
    controls = [
        project
        for project in projects
        if isinstance(project, dict) and project.get("id") == "control_plane"
    ]
    if len(controls) != 1:
        raise FinalArtifactError(
            "source BOM does not contain one control-plane project"
        )
    git = controls[0].get("git")
    if not isinstance(git, dict):
        raise FinalArtifactError("source BOM control-plane Git binding is malformed")
    head = git.get("head")
    head_tree = git.get("head_tree")
    object_format = git.get("object_format")
    expected_length = 40 if object_format == "sha1" else 64
    if (
        object_format not in {"sha1", "sha256"}
        or not isinstance(head, str)
        or not isinstance(head_tree, str)
        or re.fullmatch(rf"[0-9a-f]{{{expected_length}}}", head) is None
        or re.fullmatch(rf"[0-9a-f]{{{expected_length}}}", head_tree) is None
    ):
        raise FinalArtifactError(
            "source BOM control-plane revision/tree binding is malformed"
        )
    return {
        "head": head,
        "head_tree": head_tree,
        "object_format": object_format,
    }


def parse_git_tree_entries(raw: bytes, object_format: str) -> dict[str, dict[str, str]]:
    expected_oid_length = 40 if object_format == "sha1" else 64
    entries: dict[str, dict[str, str]] = {}
    records = raw.split(b"\0")
    if not records or records[-1] != b"":
        raise FinalArtifactError("authority-source Git tree output is not NUL closed")
    for record in records[:-1]:
        try:
            metadata, encoded_path = record.split(b"\t", 1)
            mode, object_type, oid = metadata.decode("ascii").split(" ")
            path = encoded_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise FinalArtifactError(
                "authority-source Git tree output is malformed"
            ) from error
        if (
            not path
            or path.startswith("/")
            or any(component in {"", ".", ".."} for component in path.split("/"))
            or path in entries
            or re.fullmatch(r"[0-7]{6}", mode) is None
            or re.fullmatch(rf"[0-9a-f]{{{expected_oid_length}}}", oid) is None
        ):
            raise FinalArtifactError(
                "authority-source Git tree contains an invalid or duplicate entry"
            )
        entries[path] = {"mode": mode, "type": object_type, "oid": oid}
    return entries


def control_relative_path(path: Path, repository: Path) -> str:
    absolute = lexical_absolute(path)
    root = lexical_absolute(repository)
    try:
        relative = absolute.relative_to(root)
    except ValueError as error:
        raise FinalArtifactError(
            "authority source is outside the control-plane repository"
        ) from error
    if relative == Path(".") or any(
        component in {"", ".", ".."} for component in relative.parts
    ):
        raise FinalArtifactError("authority source has an invalid repository path")
    return relative.as_posix()


def git_mode_live_modes(mode: str) -> set[int]:
    if mode == "100644":
        return {0o644}
    if mode == "100755":
        return {0o755}
    raise FinalArtifactError("authority source is not a regular Git blob mode")


def immediate_capability_candidate(name: str) -> bool:
    return name.startswith("capability_lease") and name.endswith(".rs")


class RetainedSourceAuthorityClosure:
    """Bind authority scanners to one BOM-fixed Git tree and held live files."""

    def __init__(
        self,
        *,
        custody: contextlib.ExitStack,
        control_head: str,
        control_head_tree: str,
        object_format: str,
        repository: Path,
        builtin_source: Path,
        root_contract: Path,
        root_source: Path,
        capability_root: Path,
        direct_tools_root: Path,
        capability_directories: dict[str, RetainedDirectoryPath],
        direct_directories: dict[str, RetainedDirectoryPath],
        inputs: dict[Path, RetainedRegularInput],
        capability_candidates: tuple[Path, ...],
        direct_candidates: tuple[Path, ...],
    ) -> None:
        self.custody = custody
        self.control_head = control_head
        self.control_head_tree = control_head_tree
        self.object_format = object_format
        self.repository = repository
        self.builtin_source = builtin_source
        self.root_contract = root_contract
        self.root_source = root_source
        self.capability_root = capability_root
        self.direct_tools_root = direct_tools_root
        self.capability_directories = capability_directories
        self.direct_directories = direct_directories
        self.inputs = inputs
        self.capability_candidates = capability_candidates
        self.direct_candidates = direct_candidates

    @staticmethod
    def _directory_names(directory: RetainedDirectoryPath, label: str) -> list[str]:
        try:
            names = os.listdir(directory.descriptor)
        except OSError as error:
            raise FinalArtifactError(f"cannot enumerate {label}") from error
        if len(names) != len(set(names)) or any(
            not isinstance(name, str)
            or name in {"", ".", ".."}
            or "/" in name
            or "\0" in name
            for name in names
        ):
            raise FinalArtifactError(f"{label} contains invalid directory entries")
        return sorted(names)

    @classmethod
    def _retain_recursive_directories(
        cls,
        stack: contextlib.ExitStack,
        root: Path,
        label: str,
    ) -> tuple[dict[str, RetainedDirectoryPath], tuple[Path, ...]]:
        retained_root = stack.enter_context(
            RetainedDirectoryPath.open(
                root,
                label,
                relax_ancestor_content_changes=True,
            )
        )
        directories = {"": retained_root}
        candidates: list[Path] = []

        def walk(relative: Path, directory: RetainedDirectoryPath) -> None:
            for name in cls._directory_names(directory, label):
                relative_child = relative / name
                try:
                    metadata = os.stat(
                        name,
                        dir_fd=directory.descriptor,
                        follow_symlinks=False,
                    )
                except OSError as error:
                    raise FinalArtifactError(
                        f"cannot inspect {label} entry"
                    ) from error
                if stat.S_ISDIR(metadata.st_mode):
                    key = relative_child.as_posix()
                    child = stack.enter_context(
                        RetainedDirectoryPath.open(
                            root / relative_child,
                            label,
                            relax_ancestor_content_changes=True,
                        )
                    )
                    if stable_identity(child.leaf_metadata) != stable_identity(metadata):
                        raise FinalArtifactError(
                            f"{label} directory changed while its closure was opened"
                        )
                    directories[key] = child
                    walk(relative_child, child)
                elif name.endswith(".rs"):
                    if not stat.S_ISREG(metadata.st_mode):
                        raise FinalArtifactError(
                            f"{label} Rust candidate is not a regular file"
                        )
                    candidates.append(lexical_absolute(root / relative_child))
            directory.assert_held_stable()

        walk(Path(), retained_root)
        return directories, tuple(sorted(candidates, key=os.fspath))

    @classmethod
    def open_from_bom(
        cls,
        source_bom_raw: bytes,
        retained_tools: RetainedLauncherBuildTools,
    ) -> "RetainedSourceAuthorityClosure":
        control = source_bom_control_git(source_bom_raw)
        try:
            git_tool = primitives.open_launcher_build_tool(
                AUTHORITY_SOURCE_GIT, "authority_source_git"
            )
        except RuntimeError as error:
            raise FinalArtifactError(
                "authority-source Git executable custody failed"
            ) from error
        retained_tools.retain(git_tool, "authority-source Git")
        head_type = run_retained_authority_git(
            git_tool,
            ["cat-file", "-t", control["head"]],
        )
        if head_type != b"commit\n":
            raise FinalArtifactError(
                "source BOM authority-source head is not exactly a Git commit"
            )
        storage_format = run_retained_authority_git(
            git_tool,
            ["rev-parse", "--show-object-format=storage"],
        )
        if storage_format != (control["object_format"] + "\n").encode("ascii"):
            raise FinalArtifactError(
                "authority-source Git storage object format differs from the source BOM"
            )
        tree = run_retained_authority_git(
            git_tool,
            ["rev-parse", "--verify", f"{control['head']}^{{tree}}"],
        )
        try:
            observed_tree = tree.decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise FinalArtifactError(
                "authority-source Git head tree output is malformed"
            ) from error
        if observed_tree != control["head_tree"]:
            raise FinalArtifactError(
                "authority-source Git tree differs from the source BOM"
            )
        tree_entries = parse_git_tree_entries(
            run_retained_authority_git(
                git_tool,
                ["ls-tree", "-r", "-z", "--full-tree", control["head"]],
            ),
            control["object_format"],
        )
        return cls.open_from_projection(
            control_head=control["head"],
            control_head_tree=control["head_tree"],
            object_format=control["object_format"],
            tree_entries=tree_entries,
        )

    @classmethod
    def open_from_projection(
        cls,
        *,
        control_head: str,
        control_head_tree: str,
        object_format: str,
        tree_entries: dict[str, dict[str, str]],
        repository: Path = CONTROL_REPOSITORY,
        builtin_source: Path = BUILTIN_IDENTITY_SOURCE,
        root_contract: Path = CAPABILITY_ROOT_CONTRACT,
        root_source: Path = CAPABILITY_ROOT_SOURCE,
        capability_root: Path = CAPABILITY_SOURCE_ROOT,
        direct_tools_root: Path = P01_DIRECT_TOOLS_SOURCE_ROOT,
    ) -> "RetainedSourceAuthorityClosure":
        repository = lexical_absolute(repository)
        builtin_source = lexical_absolute(builtin_source)
        root_contract = lexical_absolute(root_contract)
        root_source = lexical_absolute(root_source)
        capability_root = lexical_absolute(capability_root)
        direct_tools_root = lexical_absolute(direct_tools_root)
        capability_prefix = control_relative_path(capability_root, repository) + "/"
        direct_prefix = control_relative_path(direct_tools_root, repository) + "/"
        expected_capability_paths = tuple(
            sorted(
                (
                    lexical_absolute(repository / path)
                    for path in tree_entries
                    if path.startswith(capability_prefix)
                    and "/" not in path[len(capability_prefix) :]
                    and immediate_capability_candidate(
                        path[len(capability_prefix) :]
                    )
                ),
                key=os.fspath,
            )
        )
        expected_direct_paths = tuple(
            sorted(
                (
                    lexical_absolute(repository / path)
                    for path in tree_entries
                    if path.startswith(direct_prefix)
                    and path.endswith(".rs")
                ),
                key=os.fspath,
            )
        )
        if (
            not expected_capability_paths
            or root_source not in expected_capability_paths
            or not expected_direct_paths
        ):
            raise FinalArtifactError(
                "BOM-fixed authority-source candidate closure is incomplete"
            )

        stack = contextlib.ExitStack()
        try:
            capability_directory = stack.enter_context(
                RetainedDirectoryPath.open(
                    capability_root,
                    "generic capability-source namespace",
                    relax_ancestor_content_changes=True,
                )
            )
            capability_directories = {"": capability_directory}
            observed_capability_paths: list[Path] = []
            for name in cls._directory_names(
                capability_directory, "generic capability-source namespace"
            ):
                if not immediate_capability_candidate(name):
                    continue
                try:
                    metadata = os.stat(
                        name,
                        dir_fd=capability_directory.descriptor,
                        follow_symlinks=False,
                    )
                except OSError as error:
                    raise FinalArtifactError(
                        "cannot inspect generic capability-source candidate"
                    ) from error
                if not stat.S_ISREG(metadata.st_mode):
                    raise FinalArtifactError(
                        "generic capability-source candidate is not a regular file"
                    )
                observed_capability_paths.append(
                    lexical_absolute(capability_root / name)
                )
            if tuple(sorted(observed_capability_paths, key=os.fspath)) != (
                expected_capability_paths
            ):
                raise FinalArtifactError(
                    "live capability-source candidate namespace differs from control HEAD"
                )

            direct_directories, observed_direct_paths = (
                cls._retain_recursive_directories(
                    stack,
                    direct_tools_root,
                    "P01 direct-tools authority-source namespace",
                )
            )
            if observed_direct_paths != expected_direct_paths:
                raise FinalArtifactError(
                    "live direct-tools authority-source namespace differs from control HEAD"
                )

            all_paths = {
                builtin_source,
                root_contract,
                *expected_capability_paths,
                *expected_direct_paths,
            }
            if len(all_paths) != 2 + len(expected_capability_paths) + len(
                expected_direct_paths
            ):
                raise FinalArtifactError("authority-source closure aliases input paths")
            inputs: dict[Path, RetainedRegularInput] = {}
            for path in sorted(all_paths, key=os.fspath):
                relative = control_relative_path(path, repository)
                entry = tree_entries.get(relative)
                if (
                    not isinstance(entry, dict)
                    or set(entry) != {"mode", "type", "oid"}
                    or entry.get("type") != "blob"
                ):
                    raise FinalArtifactError(
                        "authority source is absent from the BOM-fixed Git tree"
                    )
                git_mode = entry.get("mode")
                git_oid = entry.get("oid")
                if not isinstance(git_mode, str) or not isinstance(git_oid, str):
                    raise FinalArtifactError(
                        "authority-source Git entry is malformed"
                    )
                maximum = (
                    256 * 1024
                    if path == root_contract
                    else 512 * 1024
                    if path == builtin_source
                    else 1024 * 1024
                    if path == root_source
                    else 2 * 1024 * 1024
                )
                retained = stack.enter_context(
                    RetainedRegularInput.open(
                        path,
                        f"authority source {relative}",
                        maximum,
                        modes=git_mode_live_modes(git_mode),
                        relax_ancestor_content_changes=True,
                    )
                )
                if git_blob_oid(retained.initial_bytes, object_format) != git_oid:
                    raise FinalArtifactError(
                        "authority-source bytes differ from the BOM-fixed Git blob"
                    )
                inputs[path] = retained

            custody = stack.pop_all()
            closure = cls(
                custody=custody,
                control_head=control_head,
                control_head_tree=control_head_tree,
                object_format=object_format,
                repository=repository,
                builtin_source=builtin_source,
                root_contract=root_contract,
                root_source=root_source,
                capability_root=capability_root,
                direct_tools_root=direct_tools_root,
                capability_directories=capability_directories,
                direct_directories=direct_directories,
                inputs=inputs,
                capability_candidates=expected_capability_paths,
                direct_candidates=expected_direct_paths,
            )
            try:
                closure.assert_held_stable()
            except BaseException:
                closure.close()
                raise
            return closure
        except BaseException:
            stack.close()
            raise

    def _current_capability_candidates(self) -> tuple[Path, ...]:
        directory = self.capability_directories[""]
        candidates: list[Path] = []
        for name in self._directory_names(
            directory, "generic capability-source namespace"
        ):
            if immediate_capability_candidate(name):
                candidates.append(lexical_absolute(self.capability_root / name))
        return tuple(sorted(candidates, key=os.fspath))

    def _current_direct_candidates(self) -> tuple[Path, ...]:
        candidates: list[Path] = []
        expected_directories = set(self.direct_directories)
        observed_directories: set[str] = {""}
        for relative, directory in sorted(self.direct_directories.items()):
            base = Path(relative) if relative else Path()
            for name in self._directory_names(
                directory, "P01 direct-tools authority-source namespace"
            ):
                try:
                    metadata = os.stat(
                        name,
                        dir_fd=directory.descriptor,
                        follow_symlinks=False,
                    )
                except OSError as error:
                    raise FinalArtifactError(
                        "cannot inspect retained direct-tools source entry"
                    ) from error
                child = base / name
                if stat.S_ISDIR(metadata.st_mode):
                    observed_directories.add(child.as_posix())
                elif name.endswith(".rs"):
                    if not stat.S_ISREG(metadata.st_mode):
                        raise FinalArtifactError(
                            "retained direct-tools Rust candidate is not regular"
                        )
                    candidates.append(
                        lexical_absolute(self.direct_tools_root / child)
                    )
        if observed_directories != expected_directories:
            raise FinalArtifactError(
                "retained direct-tools directory closure changed"
            )
        return tuple(sorted(candidates, key=os.fspath))

    def assert_held_stable(self) -> None:
        for directory in (
            *self.capability_directories.values(),
            *self.direct_directories.values(),
        ):
            directory.assert_held_stable()
        if self._current_capability_candidates() != self.capability_candidates:
            raise FinalArtifactError(
                "retained capability-source candidate closure changed"
            )
        if self._current_direct_candidates() != self.direct_candidates:
            raise FinalArtifactError(
                "retained direct-tools authority-source closure changed"
            )
        for retained in self.inputs.values():
            retained.assert_held_stable()

    def assert_stable(self) -> None:
        self.assert_held_stable()
        for retained in self.inputs.values():
            retained.assert_stable()
        for directory in (
            *self.capability_directories.values(),
            *self.direct_directories.values(),
        ):
            directory.assert_stable()
        self.assert_held_stable()

    def bytes_for(self, path: Path, label: str) -> bytes:
        retained = self.inputs.get(lexical_absolute(path))
        if retained is None:
            raise FinalArtifactError(f"{label} is absent from retained authority closure")
        retained.assert_held_stable()
        return retained.initial_bytes

    def close(self) -> None:
        self.custody.close()

    def __enter__(self) -> "RetainedSourceAuthorityClosure":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def read_exact_file(
    path: Path | RetainedRegularInput,
    label: str,
    maximum: int,
    *,
    modes: set[int] | None = None,
    require_invoking_user: bool = True,
    directory_fd: int | None = None,
) -> tuple[bytes, os.stat_result]:
    if isinstance(path, RetainedRegularInput):
        validate_regular_input_metadata(
            path.initial_metadata,
            label,
            maximum,
            modes=modes,
            require_invoking_user=require_invoking_user,
        )
        path.assert_held_stable()
        return path.initial_bytes, path.initial_metadata
    if directory_fd is None:
        retained = RetainedRegularInput.open(
            path,
            label,
            maximum,
            modes=modes,
            require_invoking_user=require_invoking_user,
        )
        try:
            retained.assert_stable()
            return retained.initial_bytes, retained.initial_metadata
        finally:
            retained.close()
    if os.fspath(path) != path.name or path.name in {"", ".", ".."}:
        raise FinalArtifactError(f"{label} is not a single directory entry")
    try:
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd,
        )
    except OSError as error:
        raise FinalArtifactError(f"cannot open {label} without following links") from error
    try:
        before = os.fstat(descriptor)
        validate_regular_input_metadata(
            before,
            label,
            maximum,
            modes=modes,
            require_invoking_user=require_invoking_user,
        )
        return read_descriptor_bytes(descriptor, before, label), before
    finally:
        os.close(descriptor)


def retained_input_path(path: Path | RetainedRegularInput) -> Path:
    return path.path if isinstance(path, RetainedRegularInput) else path


def controlled_directory_metadata(
    descriptor: int, label: str
) -> os.stat_result:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise FinalArtifactError(f"{label} is not owner-controlled")
    return metadata


def open_controlled_directory(path: Path, label: str) -> tuple[int, os.stat_result]:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
        )
    except OSError as error:
        raise FinalArtifactError(f"cannot open {label} without following links") from error
    try:
        metadata = controlled_directory_metadata(descriptor, label)
        return descriptor, metadata
    except BaseException:
        os.close(descriptor)
        raise


def directory_names(
    path: Path,
    expected: set[str],
    label: str,
    *,
    retained_descriptor: int | None = None,
) -> os.stat_result:
    if retained_descriptor is None:
        descriptor, metadata = open_controlled_directory(path, label)
    else:
        try:
            descriptor = os.dup(retained_descriptor)
        except OSError as error:
            raise FinalArtifactError(f"cannot retain {label} directory") from error
        try:
            metadata = controlled_directory_metadata(descriptor, label)
        except BaseException:
            os.close(descriptor)
            raise
    try:
        if set(os.listdir(descriptor)) != expected:
            raise FinalArtifactError(f"{label} file closure is not exact")
        return metadata
    finally:
        os.close(descriptor)


def artifact_record(value: object, role: str, expected_file: str) -> dict[str, object]:
    record = exact_keys(value, {"file", "sha256", "bytes"}, f"{role} record")
    if record.get("file") != expected_file:
        raise FinalArtifactError(f"{role} filename differs")
    require_sha256(record.get("sha256"), f"{role} digest")
    size = record.get("bytes")
    if type(size) is not int or size <= 0 or size > 512 * 1024 * 1024:
        raise FinalArtifactError(f"{role} byte length is invalid")
    return record


LAUNCHER_BUILD_TOOL_FIELDS = {
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
LAUNCHER_BUILD_TOOL_EXECUTION_FIELDS = {
    "mechanism",
    "measured_before_first_execution",
    "all_invocations_used_same_open_file_description",
    "descriptor_and_path_stable_after_last_execution",
    "ambient_environment_inherited",
    "environment_allowlist",
}
LAUNCHER_BUILD_ENVIRONMENT_ALLOWLIST = [
    "LANG",
    "LC_ALL",
    "LD_LIBRARY_PATH",
    "PATH",
    "SOURCE_DATE_EPOCH",
    "TMPDIR",
    "TZ",
]

RAW_SOURCE_BOM_FIELDS = {
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
PRE_SOURCE_BOM_FIELDS = {
    "file_sha256",
    "bytes",
    "receipt_id",
    "control_head",
    "source_set_sha256",
    "resolved_manifest_sha256",
    "authority",
}


def require_source_bom_receipt_id(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None
        or value == "sha256:" + "0" * 64
    ):
        raise FinalArtifactError(f"{label} is malformed")
    return value


def canonical_source_bom_identity(
    value: object,
    *,
    raw_build_binding: bool,
) -> dict[str, object]:
    """Validate one source-BOM binding shape and project its shared identity.

    The raw ELF builder records its independently remeasured source-BOM
    posture, while the launcher/pre-daemon materializer records the exact
    physical BOM and current control-plane revision.  Those authority records
    intentionally use different closed schemas.  They identify the same
    canonical BOM only when every shared byte/content binding agrees.
    """

    if raw_build_binding:
        source = exact_keys(
            value, RAW_SOURCE_BOM_FIELDS, "P01 raw-build source BOM binding"
        )
        if (
            source.get("schema") != primitives.SOURCE_BOM_SCHEMA
            or source.get("decision") != primitives.SOURCE_BOM_PASS
            or source.get("live_full_remeasurement_before_and_after_build")
            is not True
            or source.get("byte_equal_to_each_live_remeasurement") is not True
            or source.get("authority") != RAW_SOURCE_BOM_AUTHORITY
        ):
            raise FinalArtifactError("P01 raw-build source BOM authority differs")
        file_sha256 = require_sha256(
            source.get("sha256"), "P01 raw-build source BOM file digest"
        )
    else:
        source = exact_keys(
            value, PRE_SOURCE_BOM_FIELDS, "P01 pre-daemon source BOM binding"
        )
        control_head = source.get("control_head")
        if (
            source.get("authority") != PRE_SOURCE_BOM_AUTHORITY
            or not isinstance(control_head, str)
            or re.fullmatch(r"[0-9a-f]{40,64}", control_head) is None
        ):
            raise FinalArtifactError("P01 pre-daemon source BOM authority differs")
        file_sha256 = require_sha256(
            source.get("file_sha256"), "P01 pre-daemon source BOM file digest"
        )

    byte_length = source.get("bytes")
    if type(byte_length) is not int or not 1 <= byte_length <= 16 * 1024 * 1024:
        raise FinalArtifactError("P01 source BOM byte length is invalid")
    receipt_id = require_source_bom_receipt_id(
        source.get("receipt_id"), "P01 source BOM receipt id"
    )
    source_set_sha256 = require_sha256(
        source.get("source_set_sha256"), "P01 source-set digest"
    )
    resolved_manifest_sha256 = require_sha256(
        source.get("resolved_manifest_sha256"), "P01 resolved-manifest digest"
    )
    return {
        "schema": primitives.SOURCE_BOM_SCHEMA,
        "decision": primitives.SOURCE_BOM_PASS,
        "bytes": byte_length,
        "file_sha256": file_sha256,
        "receipt_id": receipt_id,
        "source_set_sha256": source_set_sha256,
        "resolved_manifest_sha256": resolved_manifest_sha256,
    }


def validate_launcher_build_tool(
    value: object,
    expected_role: str,
    label: str,
    *,
    retained_tools: RetainedLauncherBuildTools | None = None,
) -> tuple[dict[str, object], os.stat_result]:
    tool = exact_keys(value, LAUNCHER_BUILD_TOOL_FIELDS, label)
    execution = exact_keys(
        tool.get("execution"),
        LAUNCHER_BUILD_TOOL_EXECUTION_FIELDS,
        f"{label} execution custody",
    )
    path_value = tool.get("path")
    mode_value = tool.get("mode")
    if (
        tool.get("schema") != LAUNCHER_BUILD_TOOL_SCHEMA
        or tool.get("role") != expected_role
        or not isinstance(path_value, str)
        or not path_value.startswith("/")
        or os.path.normpath(path_value) != path_value
        or any(part in {"", ".", ".."} for part in path_value.split("/")[1:])
        or type(tool.get("bytes")) is not int
        or not 1 <= tool["bytes"] <= 128 * 1024 * 1024
        or not isinstance(mode_value, str)
        or re.fullmatch(r"0[0-7]{3}", mode_value) is None
        or int(mode_value, 8) & 0o022
        or not int(mode_value, 8) & stat.S_IXUSR
        or type(tool.get("uid")) is not int
        or tool["uid"] < 0
        or type(tool.get("gid")) is not int
        or tool["gid"] < 0
        or tool.get("link_count") != 1
        or not isinstance(tool.get("version"), str)
        or not tool["version"]
        or len(tool["version"]) > 512
        or any(character in tool["version"] for character in ("\x00", "\n", "\r"))
        or tool.get("target") != "aarch64-linux-gnu"
        or tool.get("complete_recursive_toolchain_closure") is not False
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
        raise FinalArtifactError(f"{label} custody is malformed")
    require_sha256(tool.get("sha256"), f"{label} digest")
    try:
        retained = primitives.open_launcher_build_tool(Path(path_value), expected_role)
    except RuntimeError as error:
        raise FinalArtifactError(f"{label} physical custody failed") from error
    retained_owned_locally = True
    try:
        metadata = retained.initial_metadata
        raw = retained.initial_bytes
        if (
            tool.get("bytes") != len(raw)
            or tool.get("sha256") != sha256(raw)
            or tool.get("mode") != f"0{stat.S_IMODE(metadata.st_mode):o}"
            or tool.get("uid") != metadata.st_uid
            or tool.get("gid") != metadata.st_gid
            or tool.get("link_count") != metadata.st_nlink
        ):
            raise FinalArtifactError(f"{label} differs from its physical executable")
        try:
            primitives.revalidate_launcher_build_tool(retained)
        except RuntimeError as error:
            raise FinalArtifactError(f"{label} changed while remeasured") from error
        if retained_tools is not None:
            retained_owned_locally = False
            retained_tools.retain(retained, label)
    finally:
        if retained_owned_locally:
            retained.close()
    return tool, metadata


def tool_without_path(tool: dict[str, object]) -> dict[str, object]:
    normalized = dict(tool)
    normalized.pop("path")
    return normalized


def require_pre_tools_match_snapshot(
    pre: dict[str, object], toolchain_manifest: Path
) -> None:
    """Bind the pre-daemon compiler/inspector to the verified snapshot leaves."""

    lane_root = Path(os.path.abspath(os.fspath(toolchain_manifest))).parent
    expected_paths = {
        "compiler": lane_root
        / "toolchain/sysroot/usr/bin/aarch64-linux-gnu-gcc-12",
        "elf_inspector": lane_root
        / "toolchain/sysroot/usr/bin/aarch64-linux-gnu-readelf",
    }
    expected_roles = {"compiler": "linker", "elf_inspector": "readelf"}
    for field, expected_path in expected_paths.items():
        tool = pre.get(field)
        if not isinstance(tool, dict):
            raise FinalArtifactError(f"P01 pre-daemon {field} custody is missing")
        expected = raw_ab_contract.EXPECTED_TARGET_TOOL_IDENTITIES[
            expected_roles[field]
        ]
        if (
            tool.get("path") != str(expected_path)
            or tool.get("bytes") != expected["bytes"]
            or tool.get("sha256") != expected["sha256"]
            or tool.get("mode") != expected["mode"]
            or tool.get("version") != str(expected["version"]).splitlines()[0]
            or tool.get("target") != "aarch64-linux-gnu"
        ):
            raise FinalArtifactError(
                f"P01 pre-daemon {field} differs from the verified snapshot leaf"
            )
    binding = pre.get("daemon_build_binding")
    build_policy = binding.get("build_policy") if isinstance(binding, dict) else None
    selected = (
        build_policy.get("selected_native_tools")
        if isinstance(build_policy, dict)
        else None
    )
    expected_selected = {
        "compiler": {
            "relative_path": (
                "toolchain/sysroot/usr/bin/aarch64-linux-gnu-gcc-12"
            ),
            **{
                key: raw_ab_contract.EXPECTED_TARGET_TOOL_IDENTITIES["linker"][key]
                for key in ("bytes", "sha256", "mode")
            },
        },
        "archiver": {
            "relative_path": "toolchain/sysroot/usr/bin/aarch64-linux-gnu-ar",
            **{
                key: raw_ab_contract.EXPECTED_TARGET_TOOL_IDENTITIES["ar"][key]
                for key in ("bytes", "sha256", "mode")
            },
        },
    }
    if selected != expected_selected:
        raise FinalArtifactError(
            "P01 daemon build policy native tools differ from the verified snapshot"
        )


def validate_source_bom(
    path: Path | RetainedRegularInput,
    expected: object | None = None,
    *,
    directory_fd: int | None = None,
    verify_current_checkout: bool = True,
) -> tuple[bytes, dict[str, object]]:
    raw, _ = read_exact_file(
        path,
        "canonical source BOM",
        16 * 1024 * 1024,
        modes={0o444},
        directory_fd=directory_fd,
    )
    try:
        binding = primitives.validate_source_bom_bytes(raw)
    except RuntimeError as error:
        raise FinalArtifactError("canonical source BOM failed v2 verification") from error
    if expected is not None and binding != expected:
        raise FinalArtifactError("source BOM physical bytes differ from the expected binding")
    if verify_current_checkout:
        try:
            primitives.verify_current_control_checkout(binding, REPOSITORY)
        except RuntimeError as error:
            raise FinalArtifactError(
                "current control-plane checkout differs from the source BOM"
            ) from error
    return raw, binding


def stable_principal_projection(contract: dict[str, object]) -> bytes:
    endpoints = contract.get("endpoints")
    principals = contract.get("principals")
    if not isinstance(endpoints, list) or not isinstance(principals, list):
        raise FinalArtifactError("stable-principal allowlists are malformed")
    projected_endpoints = []
    for endpoint in endpoints:
        item = exact_keys(
            endpoint,
            {
                "symbol",
                "tool_selinux_domain",
                "operation_replay_sync_selinux_domain",
            },
            "stable-principal endpoint",
        )
        projected_endpoints.append(
            {
                "symbol": item["symbol"],
                "tool_selinux_domain": item["tool_selinux_domain"],
                "operation_replay_sync_selinux_domain": item[
                    "operation_replay_sync_selinux_domain"
                ],
            }
        )
    projected_principals = []
    for principal in principals:
        item = exact_keys(
            principal,
            {
                "symbol",
                "provider_id",
                "agent_id",
                "replay_namespace",
                "uid",
                "gid",
                "agent_selinux_domain",
                "runtime_adapter",
            },
            "stable principal",
        )
        projected_principals.append(
            {
                "schema": contract["principal_schema"],
                "provider_id": item["provider_id"],
                "agent_id": item["agent_id"],
                "replay_namespace": item["replay_namespace"],
                "uid": item["uid"],
                "gid": item["gid"],
                "agent_selinux_domain": item["agent_selinux_domain"],
                "runtime_adapter": item["runtime_adapter"],
            }
        )
    return json.dumps(
        {
            "schema": contract["registry_schema"],
            "endpoints": projected_endpoints,
            "principals": projected_principals,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")


def validate_stable_principal_contract(
    path: Path | RetainedRegularInput,
    expected_measurement: object,
    *,
    directory_fd: int | None = None,
) -> tuple[bytes, dict[str, object]]:
    raw, _ = read_exact_file(
        path,
        "stable-principal contract",
        256 * 1024,
        directory_fd=directory_fd,
    )
    contract = strict_json(raw, "stable-principal contract", canonical=False)
    exact_keys(
        contract,
        {
            "contract_schema",
            "registry_schema",
            "principal_schema",
            "materialization_status",
            "same_crate_counterfactual_build_required",
            "endpoints",
            "principals",
        },
        "stable-principal contract",
    )
    if (
        contract.get("contract_schema")
        != "org.trillionnium.agent-principal-registry.contract.v2"
        or contract.get("registry_schema")
        != "org.trillionnium.agent-principal-registry.v2"
        or contract.get("principal_schema")
        != "org.trillionnium.agent-stable-principal.v1"
        or contract.get("materialization_status")
        != "hold_same_crate_counterfactual_build_required"
        or contract.get("same_crate_counterfactual_build_required") is not True
    ):
        raise FinalArtifactError("stable-principal contract is not the fail-closed v2 contract")
    canonical_sha = sha256(stable_principal_projection(contract))
    expected = exact_keys(
        expected_measurement,
        {
            "status",
            "stable_principal_contract_sha256",
            "stable_principal_canonical_sha256",
            "launcher_executable_sha256",
            "launcher_identity_source",
            "executable_identity_is_stable_registry_input",
        },
        "v8 stable-principal measurement",
    )
    if (
        expected.get("status") != "host_measurement_only_avb_slot_admission_absent"
        or expected.get("launcher_identity_source")
        != "measured_after_closed_launcher_inputs"
        or expected.get("executable_identity_is_stable_registry_input") is not False
        or expected.get("stable_principal_contract_sha256") != sha256(raw)
        or expected.get("stable_principal_canonical_sha256") != canonical_sha
    ):
        raise FinalArtifactError(
            "stable principal and active launcher are not independently bound"
        )
    return raw, {
        "contract_sha256": sha256(raw),
        "canonical_sha256": canonical_sha,
        "materialization_status": contract["materialization_status"],
        "same_crate_counterfactual_build_required": True,
    }


def legacy_descriptor_digests(
    path: Path = LEGACY_DESCRIPTOR_CONTRACT,
) -> dict[str, str]:
    """Recompute the three v1 digests used only by the contamination HOLD.

    These values are never admitted as the stable principal or active launcher.
    They exist solely so a v8 builder can prove literal absence while the real
    same-source counterfactual and admission-split evidence remains unresolved.
    """
    raw, _ = read_exact_file(
        path,
        "legacy AgentDescriptor contract",
        256 * 1024,
    )
    contract = strict_json(raw, "legacy AgentDescriptor contract", canonical=False)
    exact_keys(
        contract,
        {
            "contract_schema",
            "registry_schema",
            "descriptor_schema",
            "endpoints",
            "descriptors",
        },
        "legacy AgentDescriptor contract",
    )
    descriptors = contract.get("descriptors")
    if (
        contract.get("contract_schema")
        != "org.trillionnium.agent-descriptor-registry.contract.v1"
        or contract.get("registry_schema")
        != "org.trillionnium.agent-descriptor-registry.v1"
        or contract.get("descriptor_schema")
        != "org.trillionnium.agent-descriptor.v1"
        or not isinstance(contract.get("endpoints"), list)
        or not isinstance(descriptors, list)
        or len(descriptors) != 1
    ):
        raise FinalArtifactError("legacy AgentDescriptor contract is not the closed v1 set")
    descriptor = exact_keys(
        descriptors[0],
        {
            "symbol",
            "provider_id",
            "agent_id",
            "identity_key_sha256",
            "replay_namespace",
            "uid",
            "gid",
            "agent_selinux_domain",
            "runtime_adapter",
        },
        "legacy Codex descriptor",
    )
    if (
        descriptor.get("symbol") != "CODEX"
        or descriptor.get("provider_id") != "openai-codex"
        or descriptor.get("agent_id") != "agent-codex-direct-v1"
    ):
        raise FinalArtifactError("legacy AgentDescriptor contract is not Codex-only")
    launcher_identity = require_sha256(
        descriptor.get("identity_key_sha256"),
        "legacy AgentDescriptor launcher identity",
    )
    canonical_descriptor = {
        "schema": contract["descriptor_schema"],
        "provider_id": descriptor["provider_id"],
        "agent_id": descriptor["agent_id"],
        "identity_key_sha256": launcher_identity,
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
        "canonical digest": sha256(canonical_registry),
        "contract digest": sha256(raw),
        "launcher identity": launcher_identity,
    }


def validate_pre_daemon_set(
    root: Path,
    source_bom: Path | RetainedRegularInput,
    stable_contract: Path | RetainedRegularInput = STABLE_PRINCIPAL_CONTRACT,
    *,
    additional_names: set[str] | None = None,
    root_descriptor: int | None = None,
    external_inputs_directory_fd: int | None = None,
    verify_current_checkout: bool = True,
    retained_tools: RetainedLauncherBuildTools | None = None,
) -> dict[str, object]:
    if root_descriptor is None:
        retained_root = RetainedDirectoryPath.open(
            root, "P01 pre-daemon artifact set"
        )
        try:
            result = validate_pre_daemon_set(
                retained_root.path,
                source_bom,
                stable_contract,
                additional_names=additional_names,
                root_descriptor=retained_root.descriptor,
                external_inputs_directory_fd=external_inputs_directory_fd,
                verify_current_checkout=verify_current_checkout,
                retained_tools=retained_tools,
            )
            retained_root.assert_stable()
            return result
        finally:
            retained_root.close()
    expected_names = set(PRE_ARTIFACTS.values()) | {PRE_DAEMON_RECEIPT_NAME}
    expected_names |= additional_names or set()
    directory_metadata = directory_names(
        root,
        expected_names,
        "P01 pre-daemon artifact set",
        retained_descriptor=root_descriptor,
    )
    receipt_bytes, receipt_metadata = read_exact_file(
        Path(PRE_DAEMON_RECEIPT_NAME),
        "P01 v8 pre-daemon receipt",
        256 * 1024,
        modes={0o444},
        directory_fd=root_descriptor,
    )
    receipt = strict_json(receipt_bytes, "P01 v8 pre-daemon receipt")
    exact_keys(
        receipt,
        {
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
        },
        "P01 v8 pre-daemon receipt",
    )
    if (
        receipt.get("schema") != PRE_DAEMON_SCHEMA
        or receipt.get("receipt_role") != "final_daemon_build_binding_envelope"
        or receipt.get("status") != "host_built_device_evidence_hold"
        or receipt.get("product_variant") != "userdebug"
        or receipt.get("principal_authority") != "stable_principal_registry_v2"
        or receipt.get("legacy_descriptor_executable_identity_is_principal_authority")
        is not False
        or receipt.get("runtime_policy_launcher_measurement_migration")
        != "active_launcher_separate_from_stable_principal"
        or receipt.get("product_effect_authority_available") is not False
        or receipt.get("accessibility_available") is not False
        or receipt.get("daemon_build_required") is not True
        or receipt.get("device_execution_verified") is not False
        or receipt.get("release_allowed") is not False
        or receipt.get("dependency_graph") != primitives.DEPENDENCY_GRAPH
    ):
        raise FinalArtifactError("P01 v8 pre-daemon authority boundary differs")

    identity_gate = exact_keys(
        receipt.get("legacy_descriptor_contamination_hold_gate"),
        {
            "status",
            "literal_digest_absence_verified",
            "digests",
            "counterfactual_same_source_rebuild",
            "stable_principal_admission_split",
        },
        "P01 v8 identity-independence gate",
    )
    digests = exact_keys(
        identity_gate.get("digests"),
        {"canonical digest", "contract digest", "launcher identity"},
        "P01 v8 identity-independence digest set",
    )
    for label, digest in digests.items():
        if not isinstance(label, str) or not label:
            raise FinalArtifactError("P01 v8 legacy-registry digest label is invalid")
        require_sha256(digest, f"P01 v8 legacy-registry {label}")
    for field in (
        "counterfactual_same_source_rebuild",
        "stable_principal_admission_split",
    ):
        gate = exact_keys(
            identity_gate.get(field),
            {"required", "verified", "evidence_receipt"},
            f"P01 v8 {field}",
        )
        if (
            gate.get("required") is not True
            or gate.get("verified") is not False
            or gate.get("evidence_receipt") is not None
        ):
            raise FinalArtifactError(f"P01 v8 {field} overclaims evidence")
    if (
        identity_gate.get("status")
        != "hold_identity_independence_evidence_unverified"
        or identity_gate.get("literal_digest_absence_verified") is not True
    ):
        raise FinalArtifactError("P01 v8 identity-independence gate is not HOLD")

    source_raw, source_binding = validate_source_bom(
        source_bom,
        directory_fd=external_inputs_directory_fd,
        verify_current_checkout=verify_current_checkout,
    )
    if receipt.get("source_bom") != source_binding:
        raise FinalArtifactError(
            "P01 v8 pre-daemon receipt is spliced from another source BOM"
        )
    stable_raw, stable_binding = validate_stable_principal_contract(
        stable_contract,
        receipt.get("stable_principal_launcher_measurement"),
        directory_fd=external_inputs_directory_fd,
    )

    records = exact_keys(receipt.get("artifacts"), PRE_ARTIFACTS, "P01 v8 artifact map")
    values: dict[str, bytes] = {}
    metadata: dict[str, os.stat_result] = {}
    for role, filename in PRE_ARTIFACTS.items():
        record = artifact_record(records.get(role), role, filename)
        maximum = 16 * 1024 * 1024 if role == "codex_launcher" else 128 * 1024 * 1024
        value, file_metadata = read_exact_file(
            Path(filename),
            role,
            maximum,
            modes={0o555},
            directory_fd=root_descriptor,
        )
        if record.get("sha256") != sha256(value) or record.get("bytes") != len(value):
            raise FinalArtifactError(f"{role} physical bytes differ from the v8 receipt")
        primitives.require_aarch64_elf(value, role)
        values[role] = value
        metadata[role] = file_metadata

    inputs = exact_keys(
        receipt.get("inputs"),
        {
            "codex_launcher_source_sha256",
            "codex_runtime_bytes",
            "codex_runtime_sha256",
            "high_water_authority_input_sha256",
            "replay_sync_helper_input_sha256",
            "system_api_tool_input_sha256",
        },
        "P01 v8 input map",
    )
    input_to_role = {
        "system_api_tool_input_sha256": "system_api_tool",
        "replay_sync_helper_input_sha256": "replay_sync_helper",
        "high_water_authority_input_sha256": "high_water_authority",
    }
    for input_name, role in input_to_role.items():
        if inputs.get(input_name) != sha256(values[role]):
            raise FinalArtifactError(f"{input_name} is spliced from another artifact")
    runtime_sha = require_sha256(inputs.get("codex_runtime_sha256"), "Codex runtime digest")
    runtime_bytes = inputs.get("codex_runtime_bytes")
    if type(runtime_bytes) is not int or runtime_bytes <= 0 or runtime_bytes > 512 * 1024 * 1024:
        raise FinalArtifactError("Codex runtime byte length is invalid")
    launcher_sha = sha256(values["codex_launcher"])
    measurement = receipt["stable_principal_launcher_measurement"]
    assert isinstance(measurement, dict)
    if measurement.get("launcher_executable_sha256") != launcher_sha:
        raise FinalArtifactError("active launcher digest is spliced from another receipt")
    if digests != legacy_descriptor_digests():
        raise FinalArtifactError("P01 v8 legacy-descriptor digests are cross-spliced")
    daemon_build_binding = receipt.get("daemon_build_binding")
    toolchain_snapshot = (
        daemon_build_binding.get("toolchain_snapshot")
        if isinstance(daemon_build_binding, dict)
        else None
    )
    if not isinstance(toolchain_snapshot, dict):
        raise FinalArtifactError("P01 v8 daemon binding omits toolchain snapshot")
    target_compiler_closure = (
        daemon_build_binding.get("target_compiler_closure")
        if isinstance(daemon_build_binding, dict)
        else None
    )
    closure = exact_keys(
        target_compiler_closure,
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
        "P01 v8 target compiler closure",
    )
    if (
        closure.get("schema")
        != "org.trillionnium.target-compiler-effective-closure.v1"
        or closure.get("target") != "aarch64-linux-gnu"
        or closure.get("normalized_search_arguments")
        != [
            "--sysroot=$TARGET_SYSROOT",
            "-B$TARGET_COMPILER_BIN",
            "-B$TARGET_GCC_LIBDIR",
            "-B$TARGET_BINUTILS_DIR",
        ]
        or closure.get("reported_sysroot") != "$TARGET_SYSROOT"
        or closure.get("snapshot_tree_fully_remeasured_before_and_after_build")
        is not True
        or closure.get(
            "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed"
        )
        is not False
        or closure.get("complete_host_execution_runtime_closure") is not False
        or closure.get("components")
        != raw_ab_contract.EXPECTED_RESOLVED_COMPONENTS
    ):
        raise FinalArtifactError("P01 v8 target compiler closure differs")
    try:
        expected_daemon_build_binding = primitives.daemon_build_binding(
            values,
            identity_gate,
            toolchain_snapshot,
            closure,
        )
    except RuntimeError as error:
        raise FinalArtifactError("P01 v8 daemon build binding cannot be projected") from error
    if daemon_build_binding != expected_daemon_build_binding:
        raise FinalArtifactError(
            "P01 v8 daemon build binding differs from the closed semantic inputs"
        )
    daemon_build_binding_sha256 = primitives.daemon_build_binding_sha256(
        daemon_build_binding
    )
    for digest in digests.values():
        encoded = str(digest).encode("ascii")
        if any(encoded in value for value in values.values()):
            raise FinalArtifactError(
                "P01 v8 artifact embeds an identity-independence gate digest"
            )
    if receipt.get("selected_system_api_sha256") != sha256(values["system_api_tool"]):
        raise FinalArtifactError("selected System API digest differs from its physical file")
    if (
        sha256(values["system_api_tool"]).encode("ascii") not in values["codex_launcher"]
        or runtime_sha.encode("ascii") not in values["codex_launcher"]
    ):
        raise FinalArtifactError("Codex launcher omits its independently measured inputs")
    if any(
        launcher_sha.encode("ascii") in values[role]
        for role in RAW_ARTIFACTS
    ):
        raise FinalArtifactError("pre-daemon artifact retains a reverse launcher dependency")
    primitives.validate_p01_activated_payloads(values)

    compiler, compiler_metadata = validate_launcher_build_tool(
        receipt.get("compiler"),
        "compiler_driver",
        "P01 launcher compiler",
        retained_tools=retained_tools,
    )
    elf_inspector, elf_inspector_metadata = validate_launcher_build_tool(
        receipt.get("elf_inspector"),
        "elf_inspector",
        "P01 launcher ELF inspector",
        retained_tools=retained_tools,
    )

    directory_after = directory_names(
        root,
        expected_names,
        "P01 pre-daemon artifact set",
        retained_descriptor=root_descriptor,
    )
    if stable_identity(directory_metadata) != stable_identity(directory_after):
        raise FinalArtifactError("P01 pre-daemon directory changed while measured")

    return {
        "root": root,
        "directory_metadata": directory_metadata,
        "receipt": receipt,
        "receipt_bytes": receipt_bytes,
        "receipt_metadata": receipt_metadata,
        "artifacts": values,
        "artifact_metadata": metadata,
        "source_bom_bytes": source_raw,
        "source_bom": source_binding,
        "stable_contract_bytes": stable_raw,
        "stable_principal": stable_binding,
        "active_launcher_sha256": launcher_sha,
        "daemon_build_binding": daemon_build_binding,
        "daemon_build_binding_sha256": daemon_build_binding_sha256,
        "compiler": compiler,
        "elf_inspector": elf_inspector,
        "tool_metadata": {
            "compiler": compiler_metadata,
            "elf_inspector": elf_inspector_metadata,
        },
    }


def elf_sections(value: bytes) -> dict[str, bytes]:
    primitives.require_aarch64_elf(value, "P01 daemon")
    section_offset = struct.unpack_from("<Q", value, 40)[0]
    section_entry_size = struct.unpack_from("<H", value, 58)[0]
    section_count = struct.unpack_from("<H", value, 60)[0]
    names_index = struct.unpack_from("<H", value, 62)[0]
    if (
        section_entry_size != 64
        or section_count == 0
        or names_index >= section_count
        or section_offset + section_entry_size * section_count > len(value)
    ):
        raise FinalArtifactError("P01 daemon ELF section table is malformed")
    headers = [
        struct.unpack_from("<IIQQQQIIQQ", value, section_offset + index * 64)
        for index in range(section_count)
    ]
    names_header = headers[names_index]
    names_offset, names_size = names_header[4], names_header[5]
    if names_offset + names_size > len(value):
        raise FinalArtifactError("P01 daemon ELF section-name table is out of bounds")
    names = value[names_offset : names_offset + names_size]
    sections: dict[str, bytes] = {}
    for header in headers:
        name_offset = header[0]
        if name_offset >= len(names):
            raise FinalArtifactError("P01 daemon ELF section name is out of bounds")
        name_end = names.find(b"\0", name_offset)
        if name_end < 0:
            raise FinalArtifactError("P01 daemon ELF section name is unterminated")
        try:
            name = names[name_offset:name_end].decode("ascii")
        except UnicodeDecodeError as error:
            raise FinalArtifactError("P01 daemon ELF section name is not ASCII") from error
        section_type = header[1]
        payload_offset, payload_size = header[4], header[5]
        if section_type == 8:
            payload = b""
        elif payload_offset + payload_size > len(value):
            raise FinalArtifactError(f"P01 daemon ELF section is out of bounds: {name}")
        else:
            payload = value[payload_offset : payload_offset + payload_size]
        if name in sections:
            raise FinalArtifactError(f"P01 daemon ELF section name is duplicated: {name}")
        sections[name] = payload
    return sections


def parse_embedded_measurement(value: bytes) -> dict[str, str]:
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as error:
        raise FinalArtifactError("P01 daemon measurement is not ASCII") from error
    if not text.endswith("\n"):
        raise FinalArtifactError("P01 daemon measurement is not newline terminated")
    result: dict[str, str] = {}
    for line in text[:-1].split("\n"):
        if line.count("=") != 1:
            raise FinalArtifactError("P01 daemon measurement line is malformed")
        key, item = line.split("=", 1)
        if key in result:
            raise FinalArtifactError("P01 daemon measurement field is duplicated")
        result[key] = item
    if set(result) != {
        "schema",
        "variant",
        "daemon_build_binding_sha256",
        "launcher_sha256",
        "system_api_sha256",
    }:
        raise FinalArtifactError("P01 daemon measurement schema is not closed")
    for key in (
        "daemon_build_binding_sha256",
        "launcher_sha256",
        "system_api_sha256",
    ):
        require_sha256(result[key], f"embedded {key}")
    if (
        result["schema"] != EMBEDDED_MEASUREMENT_SCHEMA
        or result["variant"] != "userdebug"
    ):
        raise FinalArtifactError("P01 daemon embedded measurement variant differs")
    return result


def parse_embedded_identity_hold(value: bytes) -> dict[str, str]:
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as error:
        raise FinalArtifactError("P01 daemon identity HOLD record is not ASCII") from error
    if not text.endswith("\n"):
        raise FinalArtifactError("P01 daemon identity HOLD record lacks a final newline")
    result: dict[str, str] = {}
    for line in text[:-1].split("\n"):
        if line.count("=") != 1:
            raise FinalArtifactError("P01 daemon identity HOLD line is malformed")
        key, item = line.split("=", 1)
        if key in result:
            raise FinalArtifactError("P01 daemon identity HOLD field is duplicated")
        result[key] = item
    if set(result) != {
        "schema",
        "daemon_build_binding_sha256",
        "status",
        "literal_digest_absence_verified",
        "legacy_descriptor_canonical_sha256",
        "legacy_descriptor_contract_sha256",
        "legacy_descriptor_launcher_identity_sha256",
        "counterfactual_same_source_rebuild",
        "stable_principal_admission_split",
    }:
        raise FinalArtifactError("P01 daemon identity HOLD schema is not closed")
    for key in (
        "daemon_build_binding_sha256",
        "legacy_descriptor_canonical_sha256",
        "legacy_descriptor_contract_sha256",
        "legacy_descriptor_launcher_identity_sha256",
    ):
        require_sha256(result[key], f"embedded identity HOLD {key}")
    if result["schema"] != IDENTITY_HOLD_SCHEMA:
        raise FinalArtifactError("P01 daemon identity HOLD schema differs")
    return result


def elf_dynamic_interpreter(value: bytes) -> str:
    """Return the single bounded ELF64 PT_INTERP pathname."""
    if len(value) < 64 or int.from_bytes(value[16:18], "little") != 3:
        raise FinalArtifactError("P01 daemon is not an AArch64 ELF64 PIE")
    program_offset = struct.unpack_from("<Q", value, 32)[0]
    program_entry_size = struct.unpack_from("<H", value, 54)[0]
    program_count = struct.unpack_from("<H", value, 56)[0]
    if (
        program_entry_size != 56
        or program_count == 0
        or program_count > 1024
        or program_offset + program_entry_size * program_count > len(value)
    ):
        raise FinalArtifactError("P01 daemon ELF program-header table is malformed")
    interpreters: list[str] = []
    for index in range(program_count):
        header = struct.unpack_from(
            "<IIQQQQQQ", value, program_offset + index * program_entry_size
        )
        if header[0] != 3:  # PT_INTERP
            continue
        payload_offset = header[2]
        payload_size = header[5]
        memory_size = header[6]
        if (
            payload_size < 2
            or payload_size > 4096
            or memory_size < payload_size
            or payload_offset + payload_size > len(value)
        ):
            raise FinalArtifactError("P01 daemon PT_INTERP payload is malformed")
        payload = value[payload_offset : payload_offset + payload_size]
        if not payload.endswith(b"\0") or b"\0" in payload[:-1]:
            raise FinalArtifactError("P01 daemon PT_INTERP is not one pathname")
        try:
            interpreter = payload[:-1].decode("ascii")
        except UnicodeDecodeError as error:
            raise FinalArtifactError("P01 daemon PT_INTERP is not ASCII") from error
        if not interpreter.startswith("/") or os.path.normpath(interpreter) != interpreter:
            raise FinalArtifactError("P01 daemon PT_INTERP pathname is not canonical")
        interpreters.append(interpreter)
    if len(interpreters) != 1:
        raise FinalArtifactError("P01 daemon must contain exactly one PT_INTERP")
    return interpreters[0]


def validate_daemon(value: bytes, pre: dict[str, object]) -> dict[str, object]:
    sections = elf_sections(value)
    if any(
        name == ".symtab" or name == ".strtab" or name.startswith(".debug")
        for name in sections
    ):
        raise FinalArtifactError("P01 daemon is not stripped of symbol/debug sections")
    build_binding = pre.get("daemon_build_binding")
    if not isinstance(build_binding, dict):
        raise FinalArtifactError("P01 daemon build binding is missing")
    target_profile = build_binding.get("target_profile")
    if not isinstance(target_profile, dict):
        raise FinalArtifactError("P01 daemon target profile is missing")
    interpreter = elf_dynamic_interpreter(value)
    if interpreter != target_profile.get("dynamic_interpreter"):
        raise FinalArtifactError("P01 daemon PT_INTERP differs from its target profile")
    measurement_raw = sections.get(MEASUREMENT_SECTION)
    if measurement_raw is None:
        raise FinalArtifactError("P01 daemon omits its linker-retained measurement")
    embedded = parse_embedded_measurement(measurement_raw)
    artifacts = pre["artifacts"]
    assert isinstance(artifacts, dict)
    expected = {
        "daemon_build_binding_sha256": str(pre["daemon_build_binding_sha256"]),
        "launcher_sha256": str(pre["active_launcher_sha256"]),
        "system_api_sha256": sha256(artifacts["system_api_tool"]),
    }
    for field, digest in expected.items():
        if embedded[field] != digest:
            raise FinalArtifactError(f"P01 daemon {field} is spliced from another lane")
    hold_raw = sections.get(IDENTITY_HOLD_SECTION)
    if hold_raw is None:
        raise FinalArtifactError("P01 daemon omits its retained identity HOLD record")
    hold = parse_embedded_identity_hold(hold_raw)
    stable_principal = pre["stable_principal"]
    assert isinstance(stable_principal, dict)
    legacy_digests = legacy_descriptor_digests()
    expected_hold = {
        "schema": IDENTITY_HOLD_SCHEMA,
        "daemon_build_binding_sha256": expected["daemon_build_binding_sha256"],
        "status": "hold_identity_independence_evidence_unverified",
        "literal_digest_absence_verified": "true",
        "legacy_descriptor_canonical_sha256": legacy_digests["canonical digest"],
        "legacy_descriptor_contract_sha256": legacy_digests["contract digest"],
        "legacy_descriptor_launcher_identity_sha256": legacy_digests[
            "launcher identity"
        ],
        "counterfactual_same_source_rebuild": (
            "required:true,verified:false,evidence_receipt:null"
        ),
        "stable_principal_admission_split": (
            "required:true,verified:false,evidence_receipt:null"
        ),
    }
    if hold != expected_hold:
        raise FinalArtifactError(
            "P01 daemon retained identity HOLD is spliced or overclaims"
        )
    variant = sections.get(VARIANT_SECTION)
    if variant is None or variant.rstrip(b"\0") != VARIANT_MARKER.encode("ascii"):
        raise FinalArtifactError("P01 daemon compiled-variant section is not exact")
    if variant[len(VARIANT_MARKER) :] != b"\0" * (len(variant) - len(VARIANT_MARKER)):
        raise FinalArtifactError("P01 daemon compiled-variant section has nonzero padding")
    if value.count(expected["launcher_sha256"].encode("ascii")) < 2:
        raise FinalArtifactError(
            "P01 daemon does not retain measurement and runtime launcher pins"
        )
    for marker in (
        b"agent-codex-direct-v1",
        b"TRILLIONNIUM_AGENTD_CAPABILITY_HARDENING_V1_ACTIVE",
    ):
        if marker not in value:
            raise FinalArtifactError("P01 daemon omits a required Codex/capability marker")
    versions = {
        tuple(int(part) for part in match.split(b"_")[1].split(b"."))
        for match in re.findall(rb"GLIBC_[0-9]+(?:\.[0-9]+)+", value)
    }
    if not versions or max(versions) > MAX_GLIBC:
        raise FinalArtifactError("P01 daemon exceeds the frozen GLIBC 2.36 ABI ceiling")
    return {
        "schema": VERIFIED_MEASUREMENT_SCHEMA,
        "embedded_measurement_schema": EMBEDDED_MEASUREMENT_SCHEMA,
        "embedded_measurement_section": MEASUREMENT_SECTION,
        "embedded_identity_hold_schema": IDENTITY_HOLD_SCHEMA,
        "embedded_identity_hold_section": IDENTITY_HOLD_SECTION,
        "identity_independence_status": hold["status"],
        "legacy_descriptor_canonical_sha256": hold[
            "legacy_descriptor_canonical_sha256"
        ],
        "legacy_descriptor_contract_sha256": hold[
            "legacy_descriptor_contract_sha256"
        ],
        "legacy_descriptor_launcher_identity_sha256": hold[
            "legacy_descriptor_launcher_identity_sha256"
        ],
        "counterfactual_same_source_rebuild_verified": False,
        "stable_principal_admission_split_verified": False,
        "compiled_variant": "userdebug",
        "daemon_build_binding_sha256": expected["daemon_build_binding_sha256"],
        "stable_principal_contract_sha256": stable_principal["contract_sha256"],
        "stable_principal_canonical_sha256": stable_principal["canonical_sha256"],
        "active_launcher_sha256": expected["launcher_sha256"],
        "active_launcher_separate_from_stable_principal": True,
        "legacy_descriptor_executable_identity_is_principal_authority": False,
        "system_api_sha256": expected["system_api_sha256"],
        "daemon_sha256": sha256(value),
        "daemon_bytes": len(value),
        "dynamic_interpreter": interpreter,
        "maximum_glibc": ".".join(str(part) for part in max(versions)),
    }


def validate_source_authority_boundaries(
    closure: RetainedSourceAuthorityClosure,
) -> dict[str, object]:
    closure.assert_held_stable()
    builtin = closure.bytes_for(
        closure.builtin_source, "daemon stable-principal source"
    )
    required = (
        b"AgentStablePrincipal, CODEX_STABLE_PRINCIPAL",
        b"matches_stable_registration",
        b"measured_launcher_sha256",
        b"registration.identity_key_sha256 == measured_launcher_sha256",
        b"active_launcher_identity(principal)",
        b'P01_CODEX_LAUNCHER_SHA256: &str = env!("TRILLIONNIUM_P01_CODEX_LAUNCHER_SHA256")',
        b"fresh OS-held file-description",
    )
    forbidden = (
        b"agent_descriptor_registry",
        b"AgentDescriptor",
        b"CODEX.identity_key_sha256",
        b"registration(&CODEX, CODEX.identity_key_sha256)",
    )
    if any(marker not in builtin for marker in required):
        raise FinalArtifactError("daemon stable-principal/runtime-launcher boundary is incomplete")
    if any(marker in builtin for marker in forbidden):
        raise FinalArtifactError("daemon source restores legacy executable identity authority")

    contract_bytes = closure.bytes_for(
        closure.root_contract, "capability root contract"
    )
    contract = strict_json(
        contract_bytes, "capability root contract", canonical=False
    )
    if (
        contract.get("source_status") != CAPABILITY_ROOT_SOURCE_STATUS
        or contract.get("authority")
        != {
            "transport_available": False,
            "runtime_consumer_available": False,
            "confers_effect_authority": False,
        }
    ):
        raise FinalArtifactError("generic capability-lease root registration is not HOLD")
    generated = closure.bytes_for(
        closure.root_source, "generated capability root source"
    )
    if CAPABILITY_ROOT_SOURCE_STATUS.encode("ascii") not in generated:
        raise FinalArtifactError("generated root-registration source status differs")

    if not closure.capability_candidates:
        raise FinalArtifactError("generic capability-lease source set is unavailable")
    for path in closure.capability_candidates:
        value = closure.bytes_for(path, "generic capability source")
        if b"TRILLIONNIUM_P01_CODEX_LAUNCHER_SHA256" in value:
            raise FinalArtifactError("generic capability-lease path gains P01 launcher wiring")
    closure.assert_held_stable()
    return {
        "daemon_variant_source_sha256": sha256(builtin),
        "stable_principal_is_only_static_principal_authority": True,
        "active_launcher_is_separate_runtime_custody": True,
        "legacy_descriptor_executable_identity_is_principal_authority": False,
        "root_registration_contract_sha256": sha256(contract_bytes),
        "root_registration_generated_source_sha256": sha256(generated),
        "root_registration_source_status": CAPABILITY_ROOT_SOURCE_STATUS,
        "transport_available": False,
        "runtime_consumer_available": False,
        "confers_effect_authority": False,
    }


def validate_p01_identity_authority_source(
    closure: RetainedSourceAuthorityClosure,
) -> None:
    closure.assert_held_stable()
    if not closure.direct_candidates:
        raise FinalArtifactError("P01 direct-tools authority-source set is unavailable")
    for path in closure.direct_candidates:
        value = closure.bytes_for(path, "P01 direct-tools authority source")
        if primitives.REGISTRY_IDENTITY_KEY_READ.search(value) is not None:
            relative = path.relative_to(closure.direct_tools_root)
            raise FinalArtifactError(
                "P0 direct-tools source reads the legacy descriptor identity "
                f"key: {relative}"
            )
    closure.assert_held_stable()


def validate_frozen_source_authority(
    source_bom_raw: bytes,
) -> dict[str, object]:
    with contextlib.ExitStack() as stack:
        retained_tools = stack.enter_context(RetainedLauncherBuildTools())
        closure = stack.enter_context(
            RetainedSourceAuthorityClosure.open_from_bom(
                source_bom_raw, retained_tools
            )
        )
        boundaries = validate_source_authority_boundaries(closure)
        validate_p01_identity_authority_source(closure)
        closure.assert_stable()
        retained_tools.assert_stable()
        closure.assert_stable()
        return boundaries


def validate_raw_receipt(
    path: Path | RetainedRegularInput,
    pre: dict[str, object],
    *,
    toolchain_manifest: Path | None = None,
    require_directory_closure: bool = True,
    directory_fd: int | None = None,
    retained_tools: RetainedLauncherBuildTools | None = None,
) -> dict[str, object]:
    physical_path = retained_input_path(path)
    if physical_path.name != RAW_RECEIPT_NAME:
        raise FinalArtifactError("P01 raw receipt filename differs")
    if not isinstance(path, RetainedRegularInput) and directory_fd is None:
        retained = RetainedRegularInput.open(
            path,
            "P01 raw-build receipt",
            512 * 1024,
            modes={0o444},
        )
        try:
            result = validate_raw_receipt(
                retained,
                pre,
                toolchain_manifest=toolchain_manifest,
                require_directory_closure=require_directory_closure,
                retained_tools=retained_tools,
            )
            retained.assert_stable()
            return result
        finally:
            retained.close()
    root = physical_path.parent
    root_descriptor = (
        path.parent.descriptor
        if isinstance(path, RetainedRegularInput)
        else directory_fd
    )
    assert root_descriptor is not None
    raw_directory_metadata: os.stat_result | None = None
    if require_directory_closure:
        raw_directory_metadata = directory_names(
            root,
            set(RAW_ARTIFACTS.values()) | {RAW_RECEIPT_NAME},
            "P01 raw-build artifact set",
            retained_descriptor=root_descriptor,
        )
    raw, metadata = read_exact_file(
        path,
        "P01 raw-build receipt",
        512 * 1024,
        modes={0o444},
        directory_fd=(
            None if isinstance(path, RetainedRegularInput) else root_descriptor
        ),
    )
    receipt = strict_json(raw, "P01 raw-build receipt")
    exact_keys(
        receipt,
        {
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
        },
        "P01 raw-build receipt",
    )
    if (
        receipt.get("schema") != RAW_RECEIPT_SCHEMA
        or receipt.get("decision") != RAW_PASS
        or receipt.get("release_status") != RAW_PRODUCT_HOLD
        or receipt.get("lane") != "p01_userdebug_pre_daemon"
        or receipt.get("variant") != "non_product_userdebug_settings_only_pre_daemon"
        or receipt.get("target") != "aarch64-unknown-linux-gnu"
        or receipt.get("profile") != "release"
        or receipt.get("receipt_id_scope") != RAW_RECEIPT_ID_SCOPE
    ):
        raise FinalArtifactError("P01 raw-build receipt boundary differs")
    receipt_id = receipt.get("receipt_id")
    preimage = dict(receipt)
    preimage.pop("receipt_id")
    if receipt_id != "sha256:" + sha256(canonical_json(preimage)):
        raise FinalArtifactError("P01 raw-build receipt_id is not canonical")
    raw_source_identity = canonical_source_bom_identity(
        receipt.get("source_bom"), raw_build_binding=True
    )
    pre_source_identity = canonical_source_bom_identity(
        pre.get("source_bom"), raw_build_binding=False
    )
    if raw_source_identity != pre_source_identity:
        raise FinalArtifactError("P01 raw-build receipt is spliced from another source BOM")
    build = exact_keys(
        receipt.get("build"),
        {
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
        },
        "P01 raw-build semantics",
    )
    commands = build.get("commands")
    if (
        not isinstance(commands, list)
        or len(commands) != 2
        or any(
            not isinstance(command, list)
            or not command
            or command[0] != "$CARGO"
            or any(not isinstance(item, str) or not item for item in command)
            for command in commands
        )
        or build.get("locked") is not True
        or build.get("offline") is not True
        or build.get("no_default_features") is not True
        or build.get("jobs") != 1
        or build.get("incremental") is not False
        or build.get("fresh_private_target_directory") is not True
        or build.get("path_remapping") is not True
        or build.get("p01_compile_variant") != "userdebug"
        or build.get("target_native_compile_flags")
        != [
            "--sysroot=$TARGET_SYSROOT",
            "-B$TARGET_COMPILER_BIN",
            "-B$TARGET_GCC_LIBDIR",
            "-B$TARGET_BINUTILS_DIR",
        ]
    ):
        raise FinalArtifactError("P01 raw-build semantics differ from the v3 lane")
    posture = exact_keys(
        receipt.get("posture"),
        {
            "host_only",
            "source_graph_passed",
            "raw_elf_build_passed",
            "complete_toolchain_byte_closure",
            "launcher_built",
            "final_p01_daemon_built",
            "rootfs_built",
            "android_product_wired",
            "device_execution_verified",
            "avb_or_slot_admission_verified",
            "release_allowed",
            "device_write_authorized",
        },
        "P01 raw-build posture",
    )
    if (
        posture.get("host_only") is not True
        or posture.get("source_graph_passed") is not True
        or posture.get("raw_elf_build_passed") is not True
        or posture.get("complete_toolchain_byte_closure") is not False
        or posture.get("launcher_built") is not False
        or posture.get("final_p01_daemon_built") is not False
        or posture.get("rootfs_built") is not False
        or posture.get("android_product_wired") is not False
        or posture.get("device_execution_verified") is not False
        or posture.get("avb_or_slot_admission_verified") is not False
        or posture.get("release_allowed") is not False
        or posture.get("device_write_authorized") is not False
    ):
        raise FinalArtifactError("P01 raw-build posture overclaims authority")
    if receipt.get("limitations") != raw_ab_contract.LIMITATIONS:
        raise FinalArtifactError("P01 raw-build limitations are not the closed v3 HOLD set")
    toolchain = exact_keys(
        receipt.get("toolchain"),
        {
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
        },
        "P01 raw-build toolchain",
    )
    executables = toolchain.get("executables")
    if (
        toolchain.get("complete_release_toolchain_closure") is not False
        or toolchain.get("input_remeasurement_after_build_required") is not True
        or toolchain.get("snapshot_tree_fully_remeasured_before_and_after_build") is not True
        or toolchain.get(
            "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed"
        )
        is not False
        or toolchain.get("boundary") != raw_ab_contract.TOOLCHAIN_BOUNDARY
        or not isinstance(executables, dict)
        or set(executables)
        != {"cargo", "rustc", "host_linker", "linker", "ar", "readelf"}
    ):
        raise FinalArtifactError("P01 raw-build toolchain boundary is incomplete or malformed")
    root_paths: dict[str, Path] = {}
    for field in (
        "cargo_home",
        "rust_toolchain_root",
        "rust_target_libdir",
        "target_toolchain_root",
        "host_toolchain_root",
        "target_sysroot",
    ):
        field_value = toolchain.get(field)
        if not isinstance(field_value, str) or not Path(field_value).is_absolute():
            raise FinalArtifactError(f"P01 raw-build toolchain {field} is not absolute")
        root_paths[field] = Path(field_value)
    if toolchain_manifest is not None:
        lane_root = Path(os.path.abspath(os.fspath(toolchain_manifest))).parent
        if (
            root_paths["target_toolchain_root"] != lane_root / "toolchain"
            or root_paths["target_sysroot"] != lane_root / "toolchain/sysroot"
        ):
            raise FinalArtifactError(
                "P01 raw-build target toolchain is outside its verified lane snapshot"
            )
    selected_tools: dict[str, dict[str, object]] = {}
    selected_tool_metadata: dict[str, os.stat_result] = {}
    for role, record_value in executables.items():
        record = exact_keys(
            record_value,
            {"path", "bytes", "sha256", "mode", "version"},
            f"P01 raw-build {role} executable",
        )
        path_value = record.get("path")
        if not isinstance(path_value, str) or not Path(path_value).is_absolute():
            raise FinalArtifactError(f"P01 raw-build {role} path is not absolute")
        expected_mode = record.get("mode")
        if not isinstance(expected_mode, str) or re.fullmatch(r"0[0-7]{3}", expected_mode) is None:
            raise FinalArtifactError(f"P01 raw-build {role} mode is malformed")
        mode = int(expected_mode, 8)
        if not mode & stat.S_IXUSR or mode & 0o022:
            raise FinalArtifactError(f"P01 raw-build {role} mode is unsafe")
        try:
            retained = primitives.open_launcher_build_tool(
                Path(path_value), f"raw-build {role}"
            )
        except RuntimeError as error:
            raise FinalArtifactError(
                f"P01 raw-build {role} physical custody failed"
            ) from error
        retained_owned_locally = True
        try:
            tool_bytes = retained.initial_bytes
            tool_metadata = retained.initial_metadata
            if (
                record.get("bytes") != len(tool_bytes)
                or record.get("sha256") != sha256(tool_bytes)
                or not isinstance(record.get("version"), str)
                or not record["version"]
                or stat.S_IMODE(tool_metadata.st_mode) != mode
                or tool_bytes[:4] != b"\x7fELF"
            ):
                raise FinalArtifactError(
                    f"P01 raw-build {role} physical executable differs"
                )
            try:
                primitives.revalidate_launcher_build_tool(retained)
            except RuntimeError as error:
                raise FinalArtifactError(
                    f"P01 raw-build {role} changed while remeasured"
                ) from error
            if retained_tools is not None:
                retained_owned_locally = False
                retained_tools.retain(retained, f"P01 raw-build {role}")
        finally:
            if retained_owned_locally:
                retained.close()
        containing_root = (
            root_paths["rust_toolchain_root"]
            if role in {"cargo", "rustc"}
            else root_paths["host_toolchain_root"]
            if role == "host_linker"
            else root_paths["target_toolchain_root"]
        )
        try:
            Path(path_value).resolve(strict=True).relative_to(
                containing_root.resolve(strict=True)
            )
        except (OSError, ValueError) as error:
            raise FinalArtifactError(
                f"P01 raw-build {role} escapes its declared toolchain root"
            ) from error
        selected_tools[role] = record
        selected_tool_metadata[role] = tool_metadata
    snapshot_manifest = exact_keys(
        toolchain.get("snapshot_manifest"),
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
        "P01 raw-build snapshot manifest binding",
    )
    pre_binding = pre.get("daemon_build_binding")
    if (
        not isinstance(pre_binding, dict)
        or snapshot_manifest != pre_binding.get("toolchain_snapshot")
    ):
        raise FinalArtifactError("P01 raw-build snapshot binding differs from v8")
    prefixes = exact_keys(
        toolchain.get("target_search_prefixes"),
        {"compiler_bin", "gcc_libdir", "binutils_dir", "host_runtime_libdir"},
        "P01 raw-build target search prefixes",
    )
    target_sysroot = root_paths["target_sysroot"]
    if prefixes != {
        "compiler_bin": str(target_sysroot / "usr/bin"),
        "gcc_libdir": str(
            target_sysroot / "usr/lib/gcc-cross/aarch64-linux-gnu/12"
        ),
        "binutils_dir": str(target_sysroot / "usr/aarch64-linux-gnu/bin"),
        "host_runtime_libdir": str(
            target_sysroot / "usr/lib/x86_64-linux-gnu"
        ),
    }:
        raise FinalArtifactError("P01 raw-build target search prefixes differ")
    expected_target_tools = {
        "linker": target_sysroot / "usr/bin/aarch64-linux-gnu-gcc-12",
        "ar": target_sysroot / "usr/bin/aarch64-linux-gnu-ar",
        "readelf": target_sysroot / "usr/bin/aarch64-linux-gnu-readelf",
    }
    for role, expected_path in expected_target_tools.items():
        if Path(str(selected_tools[role]["path"])) != expected_path:
            raise FinalArtifactError(
                f"P01 raw-build selected {role} is not the exact snapshot leaf"
            )
        expected_identity = raw_ab_contract.EXPECTED_TARGET_TOOL_IDENTITIES[role]
        actual_identity = {
            key: selected_tools[role][key]
            for key in ("bytes", "sha256", "mode", "version")
        }
        if actual_identity != expected_identity:
            raise FinalArtifactError(
                f"P01 raw-build selected {role} identity differs from the snapshot leaf"
            )
    resolved_components = exact_keys(
        toolchain.get("resolved_components"),
        set(raw_ab_contract.EXPECTED_RESOLVED_COMPONENTS),
        "P01 raw-build resolved target compiler components",
    )
    for role, expected_component in raw_ab_contract.EXPECTED_RESOLVED_COMPONENTS.items():
        component = exact_keys(
            resolved_components.get(role),
            {"relative_path", "bytes", "sha256", "mode"},
            f"P01 raw-build resolved target compiler component {role}",
        )
        if component != expected_component:
            raise FinalArtifactError(
                f"P01 raw-build resolved target compiler component {role} differs"
            )
    for pre_role, raw_role, label in (
        ("compiler", "linker", "launcher compiler/raw linker"),
        ("elf_inspector", "readelf", "launcher inspector/raw readelf"),
    ):
        pre_tool = pre.get(pre_role)
        raw_tool = selected_tools[raw_role]
        assert isinstance(pre_tool, dict)
        raw_version = raw_tool.get("version")
        if (
            pre_tool.get("bytes") != raw_tool.get("bytes")
            or pre_tool.get("sha256") != raw_tool.get("sha256")
            or pre_tool.get("mode") != raw_tool.get("mode")
            or not isinstance(raw_version, str)
            or pre_tool.get("version") != raw_version.splitlines()[0]
        ):
            raise FinalArtifactError(f"P01 {label} physical identities differ")
    records = exact_keys(receipt.get("artifacts"), RAW_ARTIFACTS, "P01 raw artifact map")
    pre_artifacts = pre.get("artifacts")
    assert isinstance(pre_artifacts, dict)
    measured: dict[str, dict[str, object]] = {}
    for role, filename in RAW_ARTIFACTS.items():
        record = exact_keys(
            records.get(role),
            {
                "file",
                "bytes",
                "sha256",
                "mode",
                "link_count",
                "hardening",
                "lane_markers_verified",
                "unremapped_host_paths_absent",
                "retired_agent_identity_absent",
            },
            f"raw {role} record",
        )
        value, file_metadata = read_exact_file(
            Path(filename),
            f"raw {role}",
            128 * 1024 * 1024,
            modes={0o555},
            directory_fd=root_descriptor,
        )
        if (
            record.get("file") != filename
            or record.get("bytes") != len(value)
            or record.get("sha256") != sha256(value)
            or record.get("mode") != "0555"
            or record.get("link_count") != 1
            or record.get("lane_markers_verified") is not True
            or record.get("unremapped_host_paths_absent") is not True
            or record.get("retired_agent_identity_absent") is not True
            or value != pre_artifacts[role]
        ):
            raise FinalArtifactError(f"raw {role} is not bidirectionally bound to v8")
        hardening = exact_keys(
            record.get("hardening"),
            {
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
            },
            f"raw {role} hardening",
        )
        needed = hardening.get("needed")
        stack_guard = exact_keys(
            hardening.get("aarch64_stack_protector_guard"),
            {
                "loader_dt_needed",
                "undefined_dynamic_symbol",
                "version",
                "version_provider",
                "loader_bound_undefined_symbols",
            },
            f"raw {role} AArch64 stack-protector guard",
        )
        required_versions = hardening.get("required_glibc_versions")
        parsed_versions: list[tuple[int, int]] = []
        if isinstance(required_versions, list):
            for version in required_versions:
                match = (
                    re.fullmatch(r"GLIBC_([0-9]+)\.([0-9]+)", version)
                    if isinstance(version, str)
                    else None
                )
                if match is None:
                    raise FinalArtifactError(
                        f"raw {role} GLIBC version evidence is malformed"
                    )
                parsed_versions.append((int(match.group(1)), int(match.group(2))))
        if (
            hardening.get("elf_class") != "ELF64"
            or hardening.get("endianness") != "little"
            or hardening.get("machine") != "AArch64"
            or hardening.get("type") != "DYN_PIE"
            or hardening.get("interpreter") != "/lib/ld-linux-aarch64.so.1"
            or hardening.get("gnu_relro") is not True
            or hardening.get("bind_now") is not True
            or hardening.get("gnu_stack_executable") is not False
            or hardening.get("writable_executable_load_segment") is not False
            or hardening.get("rpath_or_runpath") is not False
            or hardening.get("text_relocations") is not False
            or hardening.get("debug_sections") is not False
            or not isinstance(needed, list)
            or set(needed) != {"libc.so.6", "libgcc_s.so.1"}
            or "ld-linux-aarch64.so.1" in needed
            or stack_guard
            != {
                "loader_dt_needed": False,
                "undefined_dynamic_symbol": None,
                "version": None,
                "version_provider": None,
                "loader_bound_undefined_symbols": [],
            }
            or not parsed_versions
            or max(parsed_versions) > (2, 36)
            or hardening.get("maximum_glibc")
            != f"GLIBC_{max(parsed_versions)[0]}.{max(parsed_versions)[1]}"
            or not isinstance(hardening.get("gnu_build_id_sha1"), str)
            or re.fullmatch(r"[0-9a-f]{40}", hardening["gnu_build_id_sha1"]) is None
        ):
            raise FinalArtifactError(f"raw {role} hardening posture differs")
        measured[role] = {
            "sha256": sha256(value),
            "bytes": len(value),
            "device": file_metadata.st_dev,
            "inode": file_metadata.st_ino,
        }
    if raw_directory_metadata is not None:
        raw_directory_after = directory_names(
            root,
            set(RAW_ARTIFACTS.values()) | {RAW_RECEIPT_NAME},
            "P01 raw-build artifact set",
            retained_descriptor=root_descriptor,
        )
        if stable_identity(raw_directory_metadata) != stable_identity(raw_directory_after):
            raise FinalArtifactError("P01 raw-build directory changed while measured")
    return {
        "receipt_bytes": raw,
        "receipt_sha256": sha256(raw),
        "receipt_metadata": metadata,
        "directory_metadata": raw_directory_metadata,
        "receipt_id": receipt_id,
        "artifacts": measured,
        "selected_tools": selected_tools,
        "selected_tool_metadata": selected_tool_metadata,
        "launcher_compiler_matches_selected_linker": True,
        "launcher_elf_inspector_matches_selected_readelf": True,
        "complete_toolchain_byte_closure": False,
        "product_authority": False,
    }
def validate_launcher_ab_receipt(
    path: Path | RetainedRegularInput,
    pre: dict[str, object],
    raw_selected: dict[str, object] | None = None,
    *,
    directory_fd: int | None = None,
) -> dict[str, object]:
    if retained_input_path(path).name != LAUNCHER_AB_RECEIPT_NAME:
        raise FinalArtifactError("P01 launcher A/B receipt filename differs")
    raw, metadata = read_exact_file(
        path,
        "P01 launcher A/B v5 receipt",
        2 * 1024 * 1024,
        modes={0o444},
        directory_fd=directory_fd,
    )
    receipt = strict_json(raw, "P01 launcher A/B v5 receipt")
    exact_keys(
        receipt,
        {
            "schema",
            "decision",
            "status",
            "release_status",
            "release_allowed",
            "lane",
            "product_variant",
            "target",
            "source_bom",
            "raw_elf_ab",
            "launcher_inputs",
            "builder_inputs",
            "compiler",
            "elf_inspector",
            "toolchain_snapshot",
            "target_compiler_closure",
            "stable_principal_launcher_measurement",
            "identity_independence_gate",
            "daemon_build_binding",
            "artifacts",
            "comparisons",
            "posture",
            "limitations",
            "receipt_id_scope",
            "receipt_id",
        },
        "P01 launcher A/B v5 receipt",
    )
    if (
        receipt.get("schema") != LAUNCHER_AB_RECEIPT_SCHEMA
        or receipt.get("decision") != LAUNCHER_AB_DECISION
        or receipt.get("status") != LAUNCHER_AB_HOLD
        or receipt.get("release_status") != LAUNCHER_AB_HOLD
        or receipt.get("release_allowed") is not False
        or receipt.get("lane") != "p01_userdebug_pre_daemon"
        or receipt.get("product_variant") != "userdebug"
        or receipt.get("target") != "aarch64-unknown-linux-gnu"
        or receipt.get("receipt_id_scope") != RAW_RECEIPT_ID_SCOPE
        or receipt.get("builder_inputs") != pre["receipt"].get("inputs")
        or receipt.get("stable_principal_launcher_measurement")
        != pre["receipt"].get("stable_principal_launcher_measurement")
        or receipt.get("identity_independence_gate")
        != pre["receipt"].get("legacy_descriptor_contamination_hold_gate")
        or receipt.get("daemon_build_binding") != pre.get("daemon_build_binding")
        or receipt.get("toolchain_snapshot")
        != pre.get("daemon_build_binding", {}).get("toolchain_snapshot")
        or receipt.get("target_compiler_closure")
        != pre.get("daemon_build_binding", {}).get("target_compiler_closure")
    ):
        raise FinalArtifactError("P01 launcher A/B v5 authority boundary differs")
    launcher_source_identity = canonical_source_bom_identity(
        receipt.get("source_bom"), raw_build_binding=False
    )
    pre_source_identity = canonical_source_bom_identity(
        pre.get("source_bom"), raw_build_binding=False
    )
    if (
        launcher_source_identity != pre_source_identity
        or receipt.get("source_bom") != pre.get("source_bom")
    ):
        raise FinalArtifactError("P01 launcher A/B receipt source BOM differs")
    receipt_id = receipt.get("receipt_id")
    preimage = dict(receipt)
    preimage.pop("receipt_id")
    if receipt_id != "sha256:" + sha256(canonical_json(preimage)):
        raise FinalArtifactError("P01 launcher A/B receipt_id is not canonical")

    raw_ab = exact_keys(
        receipt.get("raw_elf_ab"),
        {"file", "bytes", "sha256", "receipt_id", "lane", "decision", "release_status"},
        "P01 launcher raw A/B binding",
    )
    if (
        raw_ab.get("file") != "codex-only-raw-elf-ab.v3.json"
        or type(raw_ab.get("bytes")) is not int
        or raw_ab["bytes"] <= 0
        or require_sha256(raw_ab.get("sha256"), "P01 launcher raw A/B digest")
        != raw_ab.get("sha256")
        or not isinstance(raw_ab.get("receipt_id"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", raw_ab["receipt_id"]) is None
        or raw_ab.get("lane") != "p01_userdebug_pre_daemon"
        or raw_ab.get("decision") != "PASS_HOST_ONLY_DETERMINISTIC_CODEX_RAW_ELF_AB"
        or raw_ab.get("release_status") != RAW_PRODUCT_HOLD
    ):
        raise FinalArtifactError("P01 launcher raw A/B binding differs")

    launcher_inputs = exact_keys(
        receipt.get("launcher_inputs"), {"a", "b"}, "P01 launcher A/B inputs"
    )
    input_receipt_hashes: set[str] = set()
    for side in ("a", "b"):
        item = exact_keys(
            launcher_inputs.get(side),
            {"receipt_file", "receipt_bytes", "receipt_sha256"},
            f"P01 launcher {side} input",
        )
        if (
            item.get("receipt_file") != PRE_DAEMON_RECEIPT_NAME
            or type(item.get("receipt_bytes")) is not int
            or item["receipt_bytes"] <= 0
        ):
            raise FinalArtifactError(f"P01 launcher {side} input differs")
        input_receipt_hashes.add(
            require_sha256(
                item.get("receipt_sha256"), f"P01 launcher {side} receipt digest"
            )
        )
    if sha256(pre["receipt_bytes"]) not in input_receipt_hashes:
        raise FinalArtifactError("P01 selected pre-daemon receipt is absent from launcher A/B")

    for field_name, role, raw_role in (
        ("compiler", "compiler_driver", "linker"),
        ("elf_inspector", "elf_inspector", "readelf"),
    ):
        expected = tool_without_path(pre[field_name])
        expected["build_time_bytes_bound_by_upstream_receipt"] = True
        expected[f"post_build_matches_raw_ab_selected_{raw_role}"] = True
        expected["a_b_byte_equal"] = True
        if receipt.get(field_name) != expected or expected.get("role") != role:
            raise FinalArtifactError(f"P01 launcher A/B {field_name} custody differs")

    artifacts = exact_keys(
        receipt.get("artifacts"), PRE_ARTIFACTS, "P01 launcher A/B artifacts"
    )
    pre_artifacts = pre.get("artifacts")
    assert isinstance(pre_artifacts, dict)
    for role, filename in PRE_ARTIFACTS.items():
        record = exact_keys(
            artifacts.get(role),
            {
                "file",
                "bytes",
                "sha256",
                "a_receipt_bound",
                "b_receipt_bound",
                "raw_ab_bound",
                "a_b_byte_equal",
            },
            f"P01 launcher A/B {role}",
        )
        value = pre_artifacts[role]
        if (
            record.get("file") != filename
            or record.get("bytes") != len(value)
            or record.get("sha256") != sha256(value)
            or record.get("a_receipt_bound") is not True
            or record.get("b_receipt_bound") is not True
            or record.get("raw_ab_bound") != (role in RAW_ARTIFACTS)
            or record.get("a_b_byte_equal") is not True
        ):
            raise FinalArtifactError(f"P01 launcher A/B {role} binding differs")

    if raw_selected is not None:
        raw_artifacts = raw_selected.get("artifacts")
        raw_tools = raw_selected.get("selected_tools")
        assert isinstance(raw_artifacts, dict) and isinstance(raw_tools, dict)
        for role in RAW_ARTIFACTS:
            if (
                artifacts[role]["bytes"] != raw_artifacts[role]["bytes"]
                or artifacts[role]["sha256"] != raw_artifacts[role]["sha256"]
            ):
                raise FinalArtifactError(
                    f"P01 launcher A/B {role} differs from the selected raw receipt"
                )
        for field_name, raw_role in (
            ("compiler", "linker"),
            ("elf_inspector", "readelf"),
        ):
            launcher_tool = receipt[field_name]
            raw_tool = raw_tools[raw_role]
            assert isinstance(launcher_tool, dict) and isinstance(raw_tool, dict)
            if (
                launcher_tool.get("bytes") != raw_tool.get("bytes")
                or launcher_tool.get("sha256") != raw_tool.get("sha256")
                or launcher_tool.get("mode") != raw_tool.get("mode")
                or launcher_tool.get("version")
                != str(raw_tool.get("version")).splitlines()[0]
            ):
                raise FinalArtifactError(
                    f"P01 launcher A/B {field_name} differs from selected raw {raw_role}"
                )

    if receipt.get("comparisons") != {
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
    }:
        raise FinalArtifactError("P01 launcher A/B comparisons differ")
    if receipt.get("posture") != {
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
    }:
        raise FinalArtifactError("P01 launcher A/B posture differs")
    if receipt.get("limitations") != [
        "same_source_counterfactual_identity_independence_is_unverified",
        "stable_principal_admission_split_is_unverified",
        "source_bom_is_an_upstream_receipt_claim_not_physically_remeasured_by_this_stage",
        "receipt_ids_are_content_identifiers_not_signatures_or_attestations",
        "launcher_compiler_elf_inspector_and_snapshot_archiver_bytes_are_bound_but_recursive_toolchain_closure_is_absent",
        "codex_runtime_is_receipt_bound_but_not_a_physical_input_to_this_verifier",
        "launcher_ab_does_not_prove_rootfs_android_device_avb_or_ota",
    ]:
        raise FinalArtifactError("P01 launcher A/B HOLD limitations differ")
    return {
        "receipt": receipt,
        "receipt_bytes": raw,
        "receipt_sha256": sha256(raw),
        "receipt_id": receipt_id,
        "receipt_metadata": metadata,
        "input_receipt_hashes": input_receipt_hashes,
        "selected_raw_entities_cross_bound": raw_selected is not None,
        "product_authority": False,
    }


def verify_peer_lane(
    selected_pre: dict[str, object],
    selected_daemon: bytes,
    selected_raw: dict[str, object],
    launcher_ab: dict[str, object],
    peer_pre_root: Path,
    peer_daemon_path: Path | RetainedRegularInput,
    peer_raw_path: Path | RetainedRegularInput,
    source_bom: Path | RetainedRegularInput,
    stable_contract: Path | RetainedRegularInput,
    peer_toolchain_manifest: Path,
    peer_toolchain_snapshot: dict[str, object],
    *,
    peer_pre_descriptor: int | None = None,
    verify_current_checkout: bool = True,
    retained_tools: RetainedLauncherBuildTools | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    peer_pre = validate_pre_daemon_set(
        peer_pre_root,
        source_bom,
        stable_contract,
        root_descriptor=peer_pre_descriptor,
        verify_current_checkout=verify_current_checkout,
        retained_tools=retained_tools,
    )
    if peer_pre.get("daemon_build_binding", {}).get(
        "toolchain_snapshot"
    ) != peer_toolchain_snapshot:
        raise FinalArtifactError(
            "peer P01 daemon binding is spliced from another toolchain snapshot"
        )
    require_pre_tools_match_snapshot(peer_pre, peer_toolchain_manifest)
    peer_daemon, peer_daemon_metadata = read_exact_file(
        peer_daemon_path,
        "peer P01 daemon",
        128 * 1024 * 1024,
        modes={0o555, 0o755},
    )
    peer_measurement = validate_daemon(peer_daemon, peer_pre)
    peer_raw = validate_raw_receipt(
        peer_raw_path,
        peer_pre,
        toolchain_manifest=peer_toolchain_manifest,
        retained_tools=retained_tools,
    )

    input_receipt_hashes = launcher_ab.get("input_receipt_hashes")
    if (
        not isinstance(input_receipt_hashes, set)
        or sha256(selected_pre["receipt_bytes"]) not in input_receipt_hashes
        or sha256(peer_pre["receipt_bytes"]) not in input_receipt_hashes
    ):
        raise FinalArtifactError(
            "P01 final A/B lanes are not both bound by the launcher A/B receipt"
        )
    selected_normalized = copy.deepcopy(selected_pre["receipt"])
    peer_normalized = copy.deepcopy(peer_pre["receipt"])
    for normalized in (selected_normalized, peer_normalized):
        normalized["compiler"].pop("path")
        normalized["elf_inspector"].pop("path")
    if selected_normalized != peer_normalized:
        raise FinalArtifactError(
            "P01 A/B pre-daemon receipts differ beyond custody-local tool paths"
        )
    if peer_pre.get("daemon_build_binding") != selected_pre.get(
        "daemon_build_binding"
    ):
        raise FinalArtifactError("P01 A/B daemon build bindings differ")
    for label, selected_metadata, peer_metadata in (
        (
            "pre-daemon input directories",
            selected_pre.get("directory_metadata"),
            peer_pre.get("directory_metadata"),
        ),
        (
            "pre-daemon receipts",
            selected_pre.get("receipt_metadata"),
            peer_pre.get("receipt_metadata"),
        ),
        (
            "raw input directories",
            selected_raw.get("directory_metadata"),
            peer_raw.get("directory_metadata"),
        ),
        (
            "raw receipts",
            selected_raw.get("receipt_metadata"),
            peer_raw.get("receipt_metadata"),
        ),
    ):
        if not isinstance(selected_metadata, os.stat_result) or not isinstance(
            peer_metadata, os.stat_result
        ):
            raise FinalArtifactError(f"P01 A/B {label} custody metadata is missing")
        require_distinct_physical_identity(
            selected_metadata, peer_metadata, f"P01 A/B {label}"
        )

    selected_pre_tool_metadata = selected_pre.get("tool_metadata")
    peer_pre_tool_metadata = peer_pre.get("tool_metadata")
    selected_raw_tool_metadata = selected_raw.get("selected_tool_metadata")
    peer_raw_tool_metadata = peer_raw.get("selected_tool_metadata")
    if not all(
        isinstance(value, dict)
        for value in (
            selected_pre_tool_metadata,
            peer_pre_tool_metadata,
            selected_raw_tool_metadata,
            peer_raw_tool_metadata,
        )
    ):
        raise FinalArtifactError("P01 A/B target-tool custody metadata is missing")
    assert isinstance(selected_pre_tool_metadata, dict)
    assert isinstance(peer_pre_tool_metadata, dict)
    assert isinstance(selected_raw_tool_metadata, dict)
    assert isinstance(peer_raw_tool_metadata, dict)
    for pre_role, raw_role in (
        ("compiler", "linker"),
        ("elf_inspector", "readelf"),
    ):
        for lane, pre_metadata, raw_metadata in (
            (
                "selected",
                selected_pre_tool_metadata.get(pre_role),
                selected_raw_tool_metadata.get(raw_role),
            ),
            (
                "peer",
                peer_pre_tool_metadata.get(pre_role),
                peer_raw_tool_metadata.get(raw_role),
            ),
        ):
            if not isinstance(pre_metadata, os.stat_result) or not isinstance(
                raw_metadata, os.stat_result
            ):
                raise FinalArtifactError(
                    f"P01 A/B {lane} {pre_role} physical metadata is missing"
                )
            if (pre_metadata.st_dev, pre_metadata.st_ino) != (
                raw_metadata.st_dev,
                raw_metadata.st_ino,
            ):
                raise FinalArtifactError(
                    f"P01 A/B {lane} {pre_role} is not the exact raw snapshot leaf"
                )
    for role in ("linker", "ar", "readelf"):
        selected_metadata = selected_raw_tool_metadata.get(role)
        peer_metadata = peer_raw_tool_metadata.get(role)
        if not isinstance(selected_metadata, os.stat_result) or not isinstance(
            peer_metadata, os.stat_result
        ):
            raise FinalArtifactError(f"P01 A/B selected {role} metadata is missing")
        require_distinct_physical_identity(
            selected_metadata,
            peer_metadata,
            f"P01 A/B selected {role} tool paths",
        )
    selected_artifacts = selected_pre["artifacts"]
    peer_artifacts = peer_pre["artifacts"]
    assert isinstance(selected_artifacts, dict) and isinstance(peer_artifacts, dict)
    for role in PRE_ARTIFACTS:
        if peer_artifacts[role] != selected_artifacts[role]:
            raise FinalArtifactError(f"P01 A/B {role} artifacts are not byte-identical")
        selected_metadata = selected_pre["artifact_metadata"]
        peer_metadata = peer_pre["artifact_metadata"]
        assert isinstance(selected_metadata, dict) and isinstance(peer_metadata, dict)
        if (
            selected_metadata[role].st_dev,
            selected_metadata[role].st_ino,
        ) == (peer_metadata[role].st_dev, peer_metadata[role].st_ino):
            raise FinalArtifactError("P01 A/B artifact paths alias the same inode")
    if peer_daemon != selected_daemon:
        raise FinalArtifactError("P01 A/B final daemons are not byte-identical")
    selected_daemon_metadata = selected_pre.get("daemon_input_metadata")
    if not isinstance(selected_daemon_metadata, os.stat_result):
        raise FinalArtifactError("selected P01 daemon custody metadata is missing")
    if (
        selected_daemon_metadata.st_dev,
        selected_daemon_metadata.st_ino,
    ) == (peer_daemon_metadata.st_dev, peer_daemon_metadata.st_ino):
        raise FinalArtifactError("P01 A/B daemon paths alias the same inode")
    # Raw records include inode identity only to catch aliases; compare the
    # reproducible byte fields separately.
    for role in RAW_ARTIFACTS:
        peer_record = peer_raw["artifacts"][role]
        selected_record = selected_raw["artifacts"][role]
        if (
            peer_record["sha256"] != selected_record["sha256"]
            or peer_record["bytes"] != selected_record["bytes"]
        ):
            raise FinalArtifactError(f"P01 A/B raw {role} bytes differ")
        if (
            peer_record["device"],
            peer_record["inode"],
        ) == (selected_record["device"], selected_record["inode"]):
            raise FinalArtifactError("P01 A/B raw artifact paths alias the same inode")
    evidence = {
        "schema": "org.trillionnium.p01-userdebug-final-daemon-ab-observation.v2",
        "provided": True,
        "peer_lane_physically_reverified": True,
        "toolchain_snapshot_roots_physically_distinct": True,
        "target_sysroots_physically_distinct": True,
        "selected_target_tool_inodes_physically_distinct": True,
        "pre_daemon_input_directories_physically_distinct": True,
        "raw_input_directories_physically_distinct": True,
        "pre_daemon_receipt_byte_identical": (
            peer_pre["receipt_bytes"] == selected_pre["receipt_bytes"]
        ),
        "pre_daemon_non_path_semantics_equal": True,
        "daemon_build_binding_equal": True,
        "pre_daemon_artifacts_byte_identical": True,
        "raw_artifacts_byte_identical": True,
        "final_daemon_byte_identical": True,
        "selected_pre_daemon_receipt_sha256": sha256(selected_pre["receipt_bytes"]),
        "peer_pre_daemon_receipt_sha256": sha256(peer_pre["receipt_bytes"]),
        "selected_raw_receipt_sha256": selected_raw["receipt_sha256"],
        "peer_raw_receipt_sha256": peer_raw["receipt_sha256"],
        "selected_daemon_sha256": sha256(selected_daemon),
        "peer_daemon_sha256": peer_measurement["daemon_sha256"],
        "independent_build_process_externally_attested": False,
        "device_execution_verified": False,
        "product_authority": False,
    }
    return evidence, peer_pre


def absent_ab_evidence(selected_pre: dict[str, object], daemon: bytes) -> dict[str, object]:
    return {
        "schema": "org.trillionnium.p01-userdebug-final-daemon-ab-observation.v2",
        "provided": False,
        "peer_lane_physically_reverified": False,
        "toolchain_snapshot_roots_physically_distinct": False,
        "target_sysroots_physically_distinct": False,
        "selected_target_tool_inodes_physically_distinct": False,
        "pre_daemon_input_directories_physically_distinct": False,
        "raw_input_directories_physically_distinct": False,
        "pre_daemon_receipt_byte_identical": False,
        "pre_daemon_non_path_semantics_equal": False,
        "daemon_build_binding_equal": False,
        "pre_daemon_artifacts_byte_identical": False,
        "raw_artifacts_byte_identical": False,
        "final_daemon_byte_identical": False,
        "selected_pre_daemon_receipt_sha256": sha256(selected_pre["receipt_bytes"]),
        "peer_pre_daemon_receipt_sha256": None,
        "selected_raw_receipt_sha256": None,
        "peer_raw_receipt_sha256": None,
        "selected_daemon_sha256": sha256(daemon),
        "peer_daemon_sha256": None,
        "independent_build_process_externally_attested": False,
        "device_execution_verified": False,
        "product_authority": False,
    }


def validate_ab_evidence(
    value: object,
    pre: dict[str, object],
    daemon: bytes,
    raw: dict[str, object] | None,
) -> dict[str, object]:
    evidence = exact_keys(
        value,
        {
            "schema",
            "provided",
            "peer_lane_physically_reverified",
            "toolchain_snapshot_roots_physically_distinct",
            "target_sysroots_physically_distinct",
            "selected_target_tool_inodes_physically_distinct",
            "pre_daemon_input_directories_physically_distinct",
            "raw_input_directories_physically_distinct",
            "pre_daemon_receipt_byte_identical",
            "pre_daemon_non_path_semantics_equal",
            "daemon_build_binding_equal",
            "pre_daemon_artifacts_byte_identical",
            "raw_artifacts_byte_identical",
            "final_daemon_byte_identical",
            "selected_pre_daemon_receipt_sha256",
            "peer_pre_daemon_receipt_sha256",
            "selected_raw_receipt_sha256",
            "peer_raw_receipt_sha256",
            "selected_daemon_sha256",
            "peer_daemon_sha256",
            "independent_build_process_externally_attested",
            "device_execution_verified",
            "product_authority",
        },
        "P01 A/B observation",
    )
    if (
        evidence.get("schema")
        != "org.trillionnium.p01-userdebug-final-daemon-ab-observation.v2"
        or evidence.get("selected_pre_daemon_receipt_sha256")
        != sha256(pre["receipt_bytes"])
        or evidence.get("selected_daemon_sha256") != sha256(daemon)
        or evidence.get("independent_build_process_externally_attested") is not False
        or evidence.get("device_execution_verified") is not False
        or evidence.get("product_authority") is not False
    ):
        raise FinalArtifactError("P01 A/B observation overclaims or is spliced")
    provided = evidence.get("provided") is True
    truth_fields = (
        "peer_lane_physically_reverified",
        "toolchain_snapshot_roots_physically_distinct",
        "target_sysroots_physically_distinct",
        "selected_target_tool_inodes_physically_distinct",
        "pre_daemon_input_directories_physically_distinct",
        "raw_input_directories_physically_distinct",
        "pre_daemon_non_path_semantics_equal",
        "daemon_build_binding_equal",
        "pre_daemon_artifacts_byte_identical",
        "raw_artifacts_byte_identical",
        "final_daemon_byte_identical",
    )
    if any(evidence.get(field) is not provided for field in truth_fields):
        raise FinalArtifactError("P01 A/B observation truth fields are inconsistent")
    if provided:
        for field in (
            "peer_pre_daemon_receipt_sha256",
            "selected_raw_receipt_sha256",
            "peer_raw_receipt_sha256",
            "peer_daemon_sha256",
        ):
            require_sha256(evidence.get(field), f"P01 A/B {field}")
        if raw is None or evidence.get("selected_raw_receipt_sha256") != raw["receipt_sha256"]:
            raise FinalArtifactError("P01 A/B raw receipt binding differs")
        if (
            evidence.get("pre_daemon_receipt_byte_identical")
            is not (
                evidence.get("peer_pre_daemon_receipt_sha256")
                == evidence.get("selected_pre_daemon_receipt_sha256")
            )
            or evidence.get("peer_daemon_sha256")
            != evidence.get("selected_daemon_sha256")
        ):
            raise FinalArtifactError("P01 A/B byte identity digest bindings differ")
    else:
        if evidence.get("pre_daemon_receipt_byte_identical") is not False:
            raise FinalArtifactError("absent P01 A/B receipt identity is inconsistent")
        if any(
            evidence.get(field) is not None
            for field in (
                "peer_pre_daemon_receipt_sha256",
                "selected_raw_receipt_sha256",
                "peer_raw_receipt_sha256",
                "peer_daemon_sha256",
            )
        ):
            raise FinalArtifactError("absent P01 A/B observation contains peer claims")
    return evidence


def final_receipt(
    pre: dict[str, object],
    daemon: bytes,
    measurement: dict[str, object],
    boundaries: dict[str, object],
    launcher_ab: dict[str, object],
    raw: dict[str, object] | None,
    ab: dict[str, object],
) -> dict[str, object]:
    raw_provided = raw is not None
    host_ab_pass = raw_provided and ab["provided"] is True
    blockers = [
        "stable_principal_same_crate_counterfactual_build_evidence_missing",
        "complete_release_toolchain_byte_closure_missing",
        "android_variant_and_avb_slot_admission_missing",
        "physical_device_execution_and_effect_authority_missing",
        "reboot_power_loss_replay_and_ota_evidence_missing",
    ]
    if not raw_provided:
        blockers.append("selected_raw_build_receipt_and_physical_artifacts_missing")
    if ab["provided"] is not True:
        blockers.append("independent_peer_lane_reverification_missing")
    artifacts = pre["artifacts"]
    assert isinstance(artifacts, dict)
    records: dict[str, dict[str, object]] = {
        role: {
            "file": PRE_ARTIFACTS[role],
            "sha256": sha256(value),
            "bytes": len(value),
            "mode": "0555",
        }
        for role, value in artifacts.items()
    }
    records.update(
        {
            "pre_daemon_receipt": {
                "file": PRE_DAEMON_RECEIPT_NAME,
                "sha256": sha256(pre["receipt_bytes"]),
                "bytes": len(pre["receipt_bytes"]),
                "mode": "0444",
            },
            "daemon": {
                "file": DAEMON_NAME,
                "sha256": sha256(daemon),
                "bytes": len(daemon),
                "mode": "0555",
            },
            "source_bom": {
                "file": SOURCE_BOM_NAME,
                "sha256": sha256(pre["source_bom_bytes"]),
                "bytes": len(pre["source_bom_bytes"]),
                "mode": "0444",
            },
            "stable_principal_contract": {
                "file": STABLE_PRINCIPAL_CONTRACT_NAME,
                "sha256": sha256(pre["stable_contract_bytes"]),
                "bytes": len(pre["stable_contract_bytes"]),
                "mode": "0444",
            },
            "launcher_ab_receipt": {
                "file": LAUNCHER_AB_RECEIPT_NAME,
                "sha256": launcher_ab["receipt_sha256"],
                "bytes": len(launcher_ab["receipt_bytes"]),
                "mode": "0444",
            },
        }
    )
    if raw is not None:
        records["raw_build_receipt"] = {
            "file": RAW_RECEIPT_NAME,
            "sha256": raw["receipt_sha256"],
            "bytes": len(raw["receipt_bytes"]),
            "mode": "0444",
        }
    stable = pre["stable_principal"]
    assert isinstance(stable, dict)
    return {
        "schema": FINAL_RECEIPT_SCHEMA,
        "decision": FINAL_HOST_PASS if host_ab_pass else FINAL_HOST_HOLD,
        "release_status": FINAL_PRODUCT_HOLD,
        "product_variant": "userdebug",
        "non_product_conformance_only": True,
        "principal_and_launcher_authority": {
            "principal_authority": "stable_principal_registry_v2",
            "stable_principal_contract_sha256": stable["contract_sha256"],
            "stable_principal_canonical_sha256": stable["canonical_sha256"],
            "stable_principal_materialization_status": stable["materialization_status"],
            "active_launcher_sha256": pre["active_launcher_sha256"],
            "active_launcher_separate_from_stable_principal": True,
            "legacy_descriptor_executable_identity_is_principal_authority": False,
        },
        "identity_independence_hold_gate": pre["receipt"][
            "legacy_descriptor_contamination_hold_gate"
        ],
        "source_bom": pre["source_bom"],
        "daemon_build_binding": {
            "sha256": pre["daemon_build_binding_sha256"],
            "projection": pre["daemon_build_binding"],
        },
        "daemon_measurement": measurement,
        "source_authority_boundaries": boundaries,
        "launcher_ab_evidence": {
            "required": True,
            "provided": True,
            "receipt_file": LAUNCHER_AB_RECEIPT_NAME,
            "receipt_sha256": launcher_ab["receipt_sha256"],
            "receipt_id": launcher_ab["receipt_id"],
            "lane": "p01_userdebug_pre_daemon",
            "closed_receipt_schema_and_id_revalidated": True,
            "selected_pre_daemon_receipt_bound": True,
            "selected_physical_launcher_artifacts_bound": True,
            "launcher_build_tool_custody_bound": True,
            "peer_launcher_directories_reopened_by_final_materializer": False,
            "selected_raw_entities_cross_bound": launcher_ab[
                "selected_raw_entities_cross_bound"
            ],
            "identity_independence_counterfactual_verified": False,
            "complete_toolchain_byte_closure": False,
            "product_authority": False,
        },
        "raw_build_evidence": {
            "provided": raw_provided,
            "receipt_file": RAW_RECEIPT_NAME if raw_provided else None,
            "receipt_sha256": raw["receipt_sha256"] if raw_provided else None,
            "physical_artifacts_bidirectionally_bound": raw_provided,
            "launcher_compiler_matches_selected_linker": (
                raw["launcher_compiler_matches_selected_linker"]
                if raw_provided
                else False
            ),
            "launcher_elf_inspector_matches_selected_readelf": (
                raw["launcher_elf_inspector_matches_selected_readelf"]
                if raw_provided
                else False
            ),
            "complete_toolchain_byte_closure": False,
            "product_authority": False,
        },
        "ab_evidence": ab,
        "artifacts": records,
        "blockers": sorted(blockers),
        "limitations": [
            "host_process_interpreter_and_fallback_glibc_libm_libz_are_not_byte_closed",
            "final_daemon_build_same_uid_transient_source_mutation_and_restore_between_source_checks_cannot_be_excluded",
            "final_daemon_build_same_uid_transient_toolchain_snapshot_mutation_and_restore_between_build_rs_and_materializer_cannot_be_excluded",
            "complete_release_toolchain_execution_closure_is_not_attested",
        ],
        "product_effect_authority_available": False,
        "android_variant_binding_verified": False,
        "avb_slot_admission_verified": False,
        "device_execution_verified": False,
        "device_write_authorized": False,
        "ota_authorized": False,
        "release_allowed": False,
    }


def publish_file(
    directory: int, name: str, value: bytes, mode: int
) -> tuple[int, os.stat_result]:
    if not name or "/" in name or name in {".", ".."}:
        raise FinalArtifactError("output artifact name is not a single path component")
    descriptor: int | None = None
    try:
        if not hasattr(os, "O_TMPFILE"):
            raise FinalArtifactError(
                "anonymous O_TMPFILE staging is unavailable on this host"
            )
        descriptor = os.open(
            ".",
            os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC,
            0o600,
            dir_fd=directory,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 0
        ):
            raise FinalArtifactError(
                f"output artifact {name} is not an owned anonymous staging file"
            )
        view = memoryview(value)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise FinalArtifactError(f"short write while creating {name}")
            offset += written
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_uid != os.geteuid()
            or after.st_nlink != 0
            or after.st_size != len(value)
            or stat.S_IMODE(after.st_mode) != mode
            or read_descriptor_bytes(descriptor, after, name) != value
        ):
            raise FinalArtifactError(f"output artifact {name} changed during staging")
        return descriptor, after
    except BaseException as error:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException as cleanup_error:
                raise FinalArtifactError(
                    f"output artifact {name} staging cleanup failed: {cleanup_error}"
                ) from error
        if isinstance(error, (FinalArtifactError, KeyboardInterrupt, SystemExit)):
            raise
        raise FinalArtifactError(f"cannot stage output artifact {name}") from error


class PublishedArtifact:
    def __init__(
        self,
        *,
        name: str,
        descriptor: int,
        staged_metadata: os.stat_result,
        expected_bytes: bytes,
    ) -> None:
        self.name = name
        self.descriptor = descriptor
        self.staged_metadata = staged_metadata
        self.expected_bytes = expected_bytes
        self.committed_metadata: os.stat_result | None = None


def staged_content_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def published_content_identity(metadata: os.stat_result) -> tuple[int, ...]:
    # Link publication legitimately changes ctime and nlink once.  The
    # committed baseline is captured immediately after that link, after which
    # both fields are immutable parts of the success boundary.  In particular,
    # an owner cannot hide an in-place write by restoring mode/size/mtime.
    return stable_identity(metadata)


def capture_published_file_baseline(
    directory: int,
    artifact: PublishedArtifact,
) -> None:
    if artifact.committed_metadata is not None:
        raise FinalArtifactError(
            f"published output artifact {artifact.name} has multiple baselines"
        )
    retained = os.fstat(artifact.descriptor)
    try:
        current = os.stat(
            artifact.name,
            dir_fd=directory,
            follow_symlinks=False,
        )
    except OSError as error:
        raise FinalArtifactError(
            f"cannot establish published output artifact {artifact.name} baseline"
        ) from error
    if (
        not stat.S_ISREG(retained.st_mode)
        or not stat.S_ISREG(current.st_mode)
        or retained.st_nlink != 1
        or current.st_nlink != 1
        or staged_content_identity(retained)
        != staged_content_identity(artifact.staged_metadata)
        or published_content_identity(current)
        != published_content_identity(retained)
    ):
        raise FinalArtifactError(
            f"published output artifact {artifact.name} changed while committed"
        )
    try:
        retained_bytes = read_descriptor_bytes(
            artifact.descriptor,
            retained,
            f"published output artifact {artifact.name}",
        )
    except FinalArtifactError as error:
        raise FinalArtifactError(
            f"published output artifact {artifact.name} changed while committed"
        ) from error
    if retained_bytes != artifact.expected_bytes:
        raise FinalArtifactError(
            f"published output artifact {artifact.name} bytes changed while committed"
        )
    artifact.committed_metadata = retained


def require_published_files_stable(
    directory: int,
    published: list[PublishedArtifact],
) -> None:
    for artifact in published:
        expected = artifact.committed_metadata
        if expected is None:
            raise FinalArtifactError(
                f"published output artifact {artifact.name} has no committed baseline"
            )
        retained = os.fstat(artifact.descriptor)
        try:
            current = os.stat(
                artifact.name,
                dir_fd=directory,
                follow_symlinks=False,
            )
        except OSError as error:
            raise FinalArtifactError(
                f"cannot revalidate published output artifact {artifact.name}"
            ) from error
        try:
            retained_bytes = read_descriptor_bytes(
                artifact.descriptor,
                retained,
                f"published output artifact {artifact.name}",
            )
        except FinalArtifactError as error:
            raise FinalArtifactError(
                f"published output artifact {artifact.name} changed after publication"
            ) from error
        if (
            not stat.S_ISREG(retained.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or retained.st_nlink != 1
            or current.st_nlink != 1
            or published_content_identity(retained)
            != published_content_identity(expected)
            or published_content_identity(current)
            != published_content_identity(expected)
            or retained_bytes != artifact.expected_bytes
        ):
            raise FinalArtifactError(
                f"published output artifact {artifact.name} changed after publication"
            )


def require_exact_output_closure(
    directory: int,
    published: list[PublishedArtifact],
) -> None:
    expected = {artifact.name for artifact in published}
    try:
        actual = set(os.listdir(directory))
    except OSError as error:
        raise FinalArtifactError(
            "cannot enumerate the final P01 output closure"
        ) from error
    if actual != expected:
        raise FinalArtifactError(
            "P01 final output closure has missing or unexpected entries"
        )


def close_staged_output_descriptors(
    staged: list[PublishedArtifact],
) -> list[str]:
    entries = list(staged)
    staged.clear()
    failures: list[str] = []
    for artifact in reversed(entries):
        try:
            os.close(artifact.descriptor)
        except BaseException as error:
            failures.append(
                f"{artifact.name} fd {artifact.descriptor}: {error}"
            )
    return failures


def retain_expected_regular_input(
    stack: contextlib.ExitStack,
    path: Path,
    label: str,
    maximum: int,
    modes: set[int],
    expected: bytes,
) -> RetainedRegularInput:
    retained = stack.enter_context(
        RetainedRegularInput.open(path, label, maximum, modes=modes)
    )
    if retained.initial_bytes != expected:
        raise FinalArtifactError(f"{label} changed before retained custody opened")
    return retained


def retain_pre_daemon_closure(
    stack: contextlib.ExitStack,
    root: Path,
    pre: dict[str, object],
    label_prefix: str,
) -> list[RetainedRegularInput]:
    artifacts = pre.get("artifacts")
    receipt_bytes = pre.get("receipt_bytes")
    if not isinstance(artifacts, dict) or not isinstance(receipt_bytes, bytes):
        raise FinalArtifactError(f"{label_prefix} custody projection is malformed")
    retained: list[RetainedRegularInput] = []
    for role, filename in PRE_ARTIFACTS.items():
        value = artifacts.get(role)
        if not isinstance(value, bytes):
            raise FinalArtifactError(f"{label_prefix} {role} custody bytes are missing")
        retained.append(
            retain_expected_regular_input(
                stack,
                root / filename,
                f"{label_prefix} {role}",
                16 * 1024 * 1024 if role == "codex_launcher" else 128 * 1024 * 1024,
                {0o555},
                value,
            )
        )
    retained.append(
        retain_expected_regular_input(
            stack,
            root / PRE_DAEMON_RECEIPT_NAME,
            f"{label_prefix} receipt",
            256 * 1024,
            {0o444},
            receipt_bytes,
        )
    )
    return retained


def retain_raw_artifact_closure(
    stack: contextlib.ExitStack,
    root: Path,
    pre: dict[str, object],
    label_prefix: str,
) -> list[RetainedRegularInput]:
    artifacts = pre.get("artifacts")
    if not isinstance(artifacts, dict):
        raise FinalArtifactError(f"{label_prefix} custody projection is malformed")
    retained: list[RetainedRegularInput] = []
    for role, filename in RAW_ARTIFACTS.items():
        value = artifacts.get(role)
        if not isinstance(value, bytes):
            raise FinalArtifactError(f"{label_prefix} {role} custody bytes are missing")
        retained.append(
            retain_expected_regular_input(
                stack,
                root / filename,
                f"{label_prefix} {role}",
                128 * 1024 * 1024,
                {0o555},
                value,
            )
        )
    return retained


def require_current_control_checkout(binding: object) -> None:
    try:
        primitives.verify_current_control_checkout(binding, REPOSITORY)
    except RuntimeError as error:
        raise FinalArtifactError(
            "current control-plane checkout differs from the source BOM at final gate"
        ) from error


def require_retained_directory_path(
    path: Path,
    descriptor: int,
    expected: os.stat_result,
    label: str,
) -> None:
    held = controlled_directory_metadata(descriptor, label)
    try:
        current = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise FinalArtifactError(f"cannot revalidate {label} pathname") from error
    if (
        stable_identity(held) != stable_identity(expected)
        or stable_identity(current) != stable_identity(expected)
    ):
        raise FinalArtifactError(f"{label} pathname or retained directory changed")


def materialize(
    output: Path,
    daemon_path: Path,
    pre_daemon_root: Path,
    source_bom: Path,
    *,
    launcher_ab_receipt: Path,
    toolchain_manifest: Path,
    stable_contract: Path = STABLE_PRINCIPAL_CONTRACT,
    raw_receipt: Path | None = None,
    peer_pre_daemon_root: Path | None = None,
    peer_daemon_path: Path | None = None,
    peer_raw_receipt: Path | None = None,
    peer_toolchain_manifest: Path | None = None,
) -> dict[str, object]:
    peer_inputs = (
        peer_pre_daemon_root,
        peer_daemon_path,
        peer_raw_receipt,
        peer_toolchain_manifest,
    )
    if any(value is not None for value in peer_inputs) and not all(
        value is not None for value in peer_inputs
    ):
        raise FinalArtifactError(
            "peer lane requires pre-daemon, daemon, raw, and toolchain-manifest inputs together"
        )
    if all(value is not None for value in peer_inputs) and raw_receipt is None:
        raise FinalArtifactError("peer lane requires the selected raw receipt")

    with contextlib.ExitStack() as stack, contextlib.ExitStack() as output_stack:
        retained_build_tools = stack.enter_context(RetainedLauncherBuildTools())
        selected_pre_directory = stack.enter_context(
            RetainedDirectoryPath.open(
                pre_daemon_root, "selected P01 pre-daemon artifact set"
            )
        )
        retained_source_bom = stack.enter_context(
            RetainedRegularInput.open(
                source_bom,
                "canonical source BOM",
                16 * 1024 * 1024,
                modes={0o444},
            )
        )
        retained_source_authority = stack.enter_context(
            RetainedSourceAuthorityClosure.open_from_bom(
                retained_source_bom.initial_bytes,
                retained_build_tools,
            )
        )
        retained_stable_contract = stack.enter_context(
            RetainedRegularInput.open(
                stable_contract,
                "stable-principal contract",
                256 * 1024,
            )
        )
        retained_daemon = stack.enter_context(
            RetainedRegularInput.open(
                daemon_path,
                "P01 daemon build output",
                128 * 1024 * 1024,
                modes={0o555, 0o755},
            )
        )
        retained_launcher_ab = stack.enter_context(
            RetainedRegularInput.open(
                launcher_ab_receipt,
                "P01 launcher A/B v5 receipt",
                2 * 1024 * 1024,
                modes={0o444},
            )
        )
        retained_toolchain_manifest = stack.enter_context(
            RetainedRegularInput.open(
                toolchain_manifest,
                "closed-world Mobian toolchain manifest",
                64 * 1024 * 1024,
                modes={0o444},
            )
        )
        toolchain_snapshot, verified_toolchain_manifest_before = (
            primitives.verify_toolchain_snapshot_binding(toolchain_manifest)
        )
        if verified_toolchain_manifest_before != retained_toolchain_manifest.initial_bytes:
            raise FinalArtifactError(
                "retained toolchain manifest differs from full snapshot verification"
            )
        selected_lane_root = Path(
            os.path.abspath(os.fspath(toolchain_manifest))
        ).parent
        selected_toolchain_directory = stack.enter_context(
            RetainedDirectoryPath.open(
                selected_lane_root / "toolchain",
                "selected closed-world toolchain root",
                allow_root_leaf_owner=True,
            )
        )
        selected_sysroot_directory = stack.enter_context(
            RetainedDirectoryPath.open(
                selected_lane_root / "toolchain/sysroot",
                "selected target sysroot",
                allow_root_leaf_owner=True,
            )
        )
        retained_raw = (
            stack.enter_context(
                RetainedRegularInput.open(
                    raw_receipt,
                    "P01 raw-build receipt",
                    512 * 1024,
                    modes={0o444},
                )
            )
            if raw_receipt is not None
            else None
        )
        peer_pre_directory = (
            stack.enter_context(
                RetainedDirectoryPath.open(
                    peer_pre_daemon_root,
                    "peer P01 pre-daemon artifact set",
                )
            )
            if peer_pre_daemon_root is not None
            else None
        )
        retained_peer_daemon = (
            stack.enter_context(
                RetainedRegularInput.open(
                    peer_daemon_path,
                    "peer P01 daemon",
                    128 * 1024 * 1024,
                    modes={0o555, 0o755},
                )
            )
            if peer_daemon_path is not None
            else None
        )
        retained_peer_raw = (
            stack.enter_context(
                RetainedRegularInput.open(
                    peer_raw_receipt,
                    "peer P01 raw-build receipt",
                    512 * 1024,
                    modes={0o444},
                )
            )
            if peer_raw_receipt is not None
            else None
        )
        retained_peer_toolchain_manifest = (
            stack.enter_context(
                RetainedRegularInput.open(
                    peer_toolchain_manifest,
                    "peer closed-world Mobian toolchain manifest",
                    64 * 1024 * 1024,
                    modes={0o444},
                )
            )
            if peer_toolchain_manifest is not None
            else None
        )
        peer_toolchain_snapshot: dict[str, object] | None = None
        verified_peer_toolchain_manifest_before: bytes | None = None
        peer_toolchain_directory: RetainedDirectoryPath | None = None
        peer_sysroot_directory: RetainedDirectoryPath | None = None
        if retained_peer_toolchain_manifest is not None:
            assert peer_toolchain_manifest is not None
            peer_toolchain_snapshot, verified_peer_toolchain_manifest_before = (
                primitives.verify_toolchain_snapshot_binding(peer_toolchain_manifest)
            )
            if (
                verified_peer_toolchain_manifest_before
                != retained_peer_toolchain_manifest.initial_bytes
            ):
                raise FinalArtifactError(
                    "retained peer toolchain manifest differs from full snapshot verification"
                )
            if peer_toolchain_snapshot != toolchain_snapshot:
                raise FinalArtifactError(
                    "P01 A/B toolchain snapshot bindings are not semantically equal"
                )
            peer_lane_root = Path(
                os.path.abspath(os.fspath(peer_toolchain_manifest))
            ).parent
            peer_toolchain_directory = stack.enter_context(
                RetainedDirectoryPath.open(
                    peer_lane_root / "toolchain",
                    "peer closed-world toolchain root",
                    allow_root_leaf_owner=True,
                )
            )
            peer_sysroot_directory = stack.enter_context(
                RetainedDirectoryPath.open(
                    peer_lane_root / "toolchain/sysroot",
                    "peer target sysroot",
                    allow_root_leaf_owner=True,
                )
            )
            selected_root_metadata = retained_toolchain_manifest.parent.leaf_metadata
            peer_root_metadata = retained_peer_toolchain_manifest.parent.leaf_metadata
            selected_manifest_metadata = retained_toolchain_manifest.initial_metadata
            peer_manifest_metadata = retained_peer_toolchain_manifest.initial_metadata
            if (
                selected_lane_root == peer_lane_root
                or (selected_root_metadata.st_dev, selected_root_metadata.st_ino)
                == (peer_root_metadata.st_dev, peer_root_metadata.st_ino)
                or (selected_manifest_metadata.st_dev, selected_manifest_metadata.st_ino)
                == (peer_manifest_metadata.st_dev, peer_manifest_metadata.st_ino)
            ):
                raise FinalArtifactError(
                    "P01 A/B toolchain manifests or physical snapshot roots alias"
                )
            require_distinct_physical_identity(
                selected_toolchain_directory.leaf_metadata,
                peer_toolchain_directory.leaf_metadata,
                "P01 A/B physical toolchain roots",
            )
            require_distinct_physical_identity(
                selected_sysroot_directory.leaf_metadata,
                peer_sysroot_directory.leaf_metadata,
                "P01 A/B physical target sysroots",
            )
        output_directory = output_stack.enter_context(
            RetainedDirectoryPath.open(
                output,
                "P01 final artifact set",
                allow_leaf_content_changes=True,
            )
        )
        output_descriptor = output_directory.descriptor
        if os.listdir(output_descriptor):
            raise FinalArtifactError("P01 final artifact set is not empty")

        retained_inputs = [
            retained_source_bom,
            retained_source_authority,
            retained_stable_contract,
            retained_daemon,
            retained_launcher_ab,
            retained_toolchain_manifest,
        ]
        retained_inputs.extend(
            retained
            for retained in (
                retained_raw,
                retained_peer_daemon,
                retained_peer_raw,
                retained_peer_toolchain_manifest,
            )
            if retained is not None
        )
        retained_pre_directories = [selected_pre_directory]
        if peer_pre_directory is not None:
            retained_pre_directories.append(peer_pre_directory)
        retained_pre_directories.extend(
            [selected_toolchain_directory, selected_sysroot_directory]
        )
        if peer_toolchain_directory is not None:
            retained_pre_directories.append(peer_toolchain_directory)
        if peer_sysroot_directory is not None:
            retained_pre_directories.append(peer_sysroot_directory)

        published: list[PublishedArtifact] = []
        link_states: dict[str, str] = {}

        def publish(name: str, value: bytes, mode: int) -> None:
            retained_descriptor, metadata = publish_file(
                output_descriptor, name, value, mode
            )
            try:
                published.append(
                    PublishedArtifact(
                        name=name,
                        descriptor=retained_descriptor,
                        staged_metadata=metadata,
                        expected_bytes=bytes(value),
                    )
                )
            except BaseException as error:
                try:
                    os.close(retained_descriptor)
                except BaseException as cleanup_error:
                    raise FinalArtifactError(
                        "output artifact "
                        f"{name} staging descriptor cleanup failed: {cleanup_error}"
                    ) from error
                raise

        try:
            pre = validate_pre_daemon_set(
                selected_pre_directory.path,
                retained_source_bom,
                retained_stable_contract,
                root_descriptor=selected_pre_directory.descriptor,
                retained_tools=retained_build_tools,
            )
            if pre["daemon_build_binding"]["toolchain_snapshot"] != toolchain_snapshot:
                raise FinalArtifactError(
                    "P01 daemon binding is spliced from another toolchain snapshot"
                )
            require_pre_tools_match_snapshot(pre, toolchain_manifest)
            daemon, daemon_metadata = read_exact_file(
                retained_daemon,
                "P01 daemon build output",
                128 * 1024 * 1024,
                modes={0o555, 0o755},
            )
            pre["daemon_input_path"] = daemon_path
            pre["daemon_input_metadata"] = daemon_metadata
            measurement = validate_daemon(daemon, pre)
            boundaries = validate_source_authority_boundaries(
                retained_source_authority
            )
            validate_p01_identity_authority_source(retained_source_authority)
            raw = (
                validate_raw_receipt(
                    retained_raw,
                    pre,
                    toolchain_manifest=toolchain_manifest,
                    retained_tools=retained_build_tools,
                )
                if retained_raw is not None
                else None
            )
            launcher_ab = validate_launcher_ab_receipt(
                retained_launcher_ab, pre, raw
            )
            ab = absent_ab_evidence(pre, daemon)
            peer_pre: dict[str, object] | None = None
            if peer_pre_directory is not None:
                assert (
                    retained_peer_daemon is not None
                    and retained_peer_raw is not None
                    and peer_toolchain_manifest is not None
                    and peer_toolchain_snapshot is not None
                    and raw is not None
                )
                ab, peer_pre = verify_peer_lane(
                    pre,
                    daemon,
                    raw,
                    launcher_ab,
                    peer_pre_directory.path,
                    retained_peer_daemon,
                    retained_peer_raw,
                    retained_source_bom,
                    retained_stable_contract,
                    peer_toolchain_manifest,
                    peer_toolchain_snapshot,
                    peer_pre_descriptor=peer_pre_directory.descriptor,
                    retained_tools=retained_build_tools,
                )

            toolchain_snapshot_after, verified_toolchain_manifest_after = (
                primitives.verify_toolchain_snapshot_binding(toolchain_manifest)
            )
            if (
                toolchain_snapshot_after != toolchain_snapshot
                or verified_toolchain_manifest_after
                != verified_toolchain_manifest_before
            ):
                raise FinalArtifactError(
                    "closed-world toolchain snapshot changed during final materialization"
                )
            if peer_toolchain_manifest is not None:
                assert (
                    peer_toolchain_snapshot is not None
                    and verified_peer_toolchain_manifest_before is not None
                    and retained_peer_toolchain_manifest is not None
                )
                (
                    peer_toolchain_snapshot_after,
                    verified_peer_toolchain_manifest_after,
                ) = primitives.verify_toolchain_snapshot_binding(
                    peer_toolchain_manifest
                )
                if (
                    peer_toolchain_snapshot_after != peer_toolchain_snapshot
                    or verified_peer_toolchain_manifest_after
                    != verified_peer_toolchain_manifest_before
                    or verified_peer_toolchain_manifest_after
                    != retained_peer_toolchain_manifest.initial_bytes
                ):
                    raise FinalArtifactError(
                        "peer closed-world toolchain snapshot changed during final materialization"
                    )

            # The validators above intentionally operate on retained directory
            # descriptors, but their per-file reads are short-lived.  Reopen
            # every measured closure member, compare it to the validated byte
            # projection, and hold those descriptors through the final gate.
            retained_inputs.extend(
                retain_pre_daemon_closure(
                    stack,
                    selected_pre_directory.path,
                    pre,
                    "selected P01 pre-daemon",
                )
            )
            if retained_raw is not None:
                retained_inputs.extend(
                    retain_raw_artifact_closure(
                        stack,
                        retained_raw.path.parent,
                        pre,
                        "selected P01 raw-build",
                    )
                )
            if peer_pre_directory is not None:
                assert peer_pre is not None
                retained_inputs.extend(
                    retain_pre_daemon_closure(
                        stack,
                        peer_pre_directory.path,
                        peer_pre,
                        "peer P01 pre-daemon",
                    )
                )
            if retained_peer_raw is not None:
                assert peer_pre is not None
                retained_inputs.extend(
                    retain_raw_artifact_closure(
                        stack,
                        retained_peer_raw.path.parent,
                        peer_pre,
                        "peer P01 raw-build",
                    )
                )

            artifacts = pre["artifacts"]
            assert isinstance(artifacts, dict)
            for role, value in artifacts.items():
                publish(PRE_ARTIFACTS[role], value, 0o555)
            publish(PRE_DAEMON_RECEIPT_NAME, pre["receipt_bytes"], 0o444)
            publish(DAEMON_NAME, daemon, 0o555)
            publish(SOURCE_BOM_NAME, pre["source_bom_bytes"], 0o444)
            publish(
                STABLE_PRINCIPAL_CONTRACT_NAME,
                pre["stable_contract_bytes"],
                0o444,
            )
            publish(
                LAUNCHER_AB_RECEIPT_NAME,
                launcher_ab["receipt_bytes"],
                0o444,
            )
            if raw is not None:
                publish(RAW_RECEIPT_NAME, raw["receipt_bytes"], 0o444)
            receipt = final_receipt(
                pre, daemon, measurement, boundaries, launcher_ab, raw, ab
            )
            publish(FINAL_RECEIPT_NAME, canonical_json(receipt), 0o444)

            # This is the last pre-commit gate.  Up to this point every output
            # is an anonymous O_TMPFILE inode and no public artifact pathname
            # exists.  POSIX has neither multi-name atomic publication nor an
            # atomic compare-and-unlink primitive, so committed names are
            # retained and reported on any later failure rather than risking
            # deletion of a concurrently replaced pathname.
            for retained in retained_inputs:
                retained.assert_stable()
            for retained in retained_pre_directories:
                retained.assert_stable()
            retained_build_tools.assert_stable()
            output_directory.assert_stable()
            if os.listdir(output_descriptor):
                raise FinalArtifactError(
                    "P01 final artifact set changed before commit"
                )
            require_current_control_checkout(pre["source_bom"])
            for retained in retained_inputs:
                retained.assert_stable()
            for retained in retained_pre_directories:
                retained.assert_stable()
            retained_build_tools.assert_stable()
            output_directory.assert_stable()
            if os.listdir(output_descriptor):
                raise FinalArtifactError(
                    "P01 final artifact set changed at the commit boundary"
                )

            for artifact in published:
                link_states[artifact.name] = "ATTEMPTING_OR_UNKNOWN"
                try:
                    os.link(
                        f"/proc/self/fd/{artifact.descriptor}",
                        artifact.name,
                        dst_dir_fd=output_descriptor,
                        follow_symlinks=True,
                    )
                except BaseException as error:
                    raise FinalArtifactError(
                        "cannot determine whether anonymous output artifact "
                        f"{artifact.name} was committed: {error}"
                    ) from error
                link_states[artifact.name] = "CREATED_BY_TX"
                capture_published_file_baseline(output_descriptor, artifact)
            os.fsync(output_descriptor)
            result = _verify_retained(output_descriptor)
            require_published_files_stable(output_descriptor, published)
            require_exact_output_closure(output_descriptor, published)
            for retained in retained_inputs:
                retained.assert_stable()
            for retained in retained_pre_directories:
                retained.assert_stable()
            retained_build_tools.assert_stable()
            output_directory.assert_stable()
            # Repeat the inexpensive output namespace gate after every long
            # input/path check.  Staged and input descriptors are drained
            # before the final live-checkout/output-path pair so cleanup
            # callbacks cannot silently move either success boundary.
            require_published_files_stable(output_descriptor, published)
            require_exact_output_closure(output_descriptor, published)
            output_directory.assert_stable()
            retained_cleanup = stack.pop_all()
            try:
                retained_cleanup.close()
            except BaseException as cleanup_error:
                raise FinalArtifactError(
                    "committed P01 retained-input cleanup failed"
                ) from cleanup_error
            require_current_control_checkout(pre["source_bom"])
            require_published_files_stable(output_descriptor, published)
            require_exact_output_closure(output_descriptor, published)
            output_directory.assert_stable()
            descriptor_failures = close_staged_output_descriptors(published)
            if descriptor_failures:
                raise FinalArtifactError(
                    "committed P01 output descriptor cleanup failed: "
                    + "; ".join(descriptor_failures)
                )
            output_cleanup = output_stack.pop_all()
            try:
                output_cleanup.close()
            except BaseException as cleanup_error:
                raise FinalArtifactError(
                    "committed P01 output-path cleanup failed"
                ) from cleanup_error
            return result
        except BaseException as error:
            cleanup_failures = close_staged_output_descriptors(published)
            try:
                stack.pop_all().close()
            except BaseException as cleanup_error:
                cleanup_failures.append(f"retained-input cleanup: {cleanup_error}")
            try:
                output_stack.pop_all().close()
            except BaseException as cleanup_error:
                cleanup_failures.append(f"output-path cleanup: {cleanup_error}")
            cleanup_suffix = (
                "; cleanup failures: " + "; ".join(cleanup_failures)
                if cleanup_failures
                else ""
            )
            retained_or_unknown = [
                f"{name}:{state}"
                for name, state in link_states.items()
                if state in {"ATTEMPTING_OR_UNKNOWN", "CREATED_BY_TX"}
            ]
            if retained_or_unknown:
                raise FinalArtifactError(
                    "P01 ordered commit failed after creating retained public "
                    "entries or reaching an indeterminate link result ["
                    + ", ".join(retained_or_unknown)
                    + "]; no pathname rollback was attempted; cause: "
                    + str(error)
                    + cleanup_suffix
                ) from error
            if cleanup_failures:
                raise FinalArtifactError(
                    "P01 materialization failed before commit"
                    + cleanup_suffix
                ) from error
            raise


def _verify_retained(root_descriptor: int) -> dict[str, object]:
    root = Path(f"/proc/self/fd/{root_descriptor}")
    receipt_bytes, _ = read_exact_file(
        Path(FINAL_RECEIPT_NAME),
        "P01 final v5 receipt",
        512 * 1024,
        modes={0o444},
        directory_fd=root_descriptor,
    )
    receipt = strict_json(receipt_bytes, "P01 final v5 receipt")
    if receipt.get("schema") != FINAL_RECEIPT_SCHEMA:
        raise FinalArtifactError("P01 final receipt is not v5")
    raw_evidence = receipt.get("raw_build_evidence")
    if not isinstance(raw_evidence, dict):
        raise FinalArtifactError("P01 final raw-build evidence is malformed")
    raw_provided = raw_evidence.get("provided") is True
    extras = {
        DAEMON_NAME,
        SOURCE_BOM_NAME,
        STABLE_PRINCIPAL_CONTRACT_NAME,
        LAUNCHER_AB_RECEIPT_NAME,
        FINAL_RECEIPT_NAME,
    }
    if raw_provided:
        extras.add(RAW_RECEIPT_NAME)
    pre = validate_pre_daemon_set(
        root,
        Path(SOURCE_BOM_NAME),
        Path(STABLE_PRINCIPAL_CONTRACT_NAME),
        additional_names=extras,
        root_descriptor=root_descriptor,
        external_inputs_directory_fd=root_descriptor,
        verify_current_checkout=False,
    )
    daemon, _ = read_exact_file(
        Path(DAEMON_NAME),
        "frozen P01 daemon",
        128 * 1024 * 1024,
        modes={0o555},
        directory_fd=root_descriptor,
    )
    measurement = validate_daemon(daemon, pre)
    boundaries = validate_frozen_source_authority(pre["source_bom_bytes"])
    raw = (
        validate_raw_receipt(
            Path(RAW_RECEIPT_NAME),
            pre,
            require_directory_closure=False,
            directory_fd=root_descriptor,
        )
        if raw_provided
        else None
    )
    launcher_ab = validate_launcher_ab_receipt(
        Path(LAUNCHER_AB_RECEIPT_NAME),
        pre,
        raw,
        directory_fd=root_descriptor,
    )
    ab = validate_ab_evidence(receipt.get("ab_evidence"), pre, daemon, raw)
    expected = final_receipt(
        pre, daemon, measurement, boundaries, launcher_ab, raw, ab
    )
    if receipt != expected:
        raise FinalArtifactError("P01 final v5 receipt differs from verified artifacts")
    result = dict(expected)
    result["receipt_sha256"] = sha256(receipt_bytes)
    return result


def verify(root: Path) -> dict[str, object]:
    retained_root = RetainedDirectoryPath.open(
        root,
        "P01 final artifact set",
        allow_shared_sticky_ancestors=True,
    )
    try:
        result = _verify_retained(retained_root.descriptor)
        retained_root.assert_stable()
        return result
    finally:
        retained_root.close()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--daemon", type=Path)
    parser.add_argument("--pre-daemon-artifact-set", type=Path)
    parser.add_argument("--source-bom", type=Path)
    parser.add_argument("--launcher-ab-receipt", type=Path)
    parser.add_argument("--toolchain-manifest", type=Path)
    parser.add_argument(
        "--stable-principal-contract",
        type=Path,
        default=STABLE_PRINCIPAL_CONTRACT,
    )
    parser.add_argument("--raw-elf-receipt", type=Path)
    parser.add_argument("--peer-pre-daemon-artifact-set", type=Path)
    parser.add_argument("--peer-daemon", type=Path)
    parser.add_argument("--peer-raw-elf-receipt", type=Path)
    parser.add_argument("--peer-toolchain-manifest", type=Path)
    parser.add_argument("--verify-dir", type=Path)
    args = parser.parse_args(argv)
    materialize_args = (
        args.output_dir,
        args.daemon,
        args.pre_daemon_artifact_set,
        args.source_bom,
        args.launcher_ab_receipt,
        args.toolchain_manifest,
    )
    if args.verify_dir is not None:
        optional_materialize_args = (
            args.raw_elf_receipt,
            args.peer_pre_daemon_artifact_set,
            args.peer_daemon,
            args.peer_raw_elf_receipt,
            args.peer_toolchain_manifest,
        )
        if any(value is not None for value in materialize_args + optional_materialize_args):
            parser.error("--verify-dir cannot be combined with materialization inputs")
    elif any(value is None for value in materialize_args):
        parser.error(
            "materialization requires --output-dir, --daemon, "
            "--pre-daemon-artifact-set, --source-bom, --launcher-ab-receipt, "
            "and --toolchain-manifest"
        )
    return args


def main() -> int:
    args = parse_args()
    result = (
        verify(args.verify_dir)
        if args.verify_dir is not None
        else materialize(
            args.output_dir,
            args.daemon,
            args.pre_daemon_artifact_set,
            args.source_bom,
            launcher_ab_receipt=args.launcher_ab_receipt,
            toolchain_manifest=args.toolchain_manifest,
            stable_contract=args.stable_principal_contract,
            raw_receipt=args.raw_elf_receipt,
            peer_pre_daemon_root=args.peer_pre_daemon_artifact_set,
            peer_daemon_path=args.peer_daemon,
            peer_raw_receipt=args.peer_raw_elf_receipt,
            peer_toolchain_manifest=args.peer_toolchain_manifest,
        )
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
