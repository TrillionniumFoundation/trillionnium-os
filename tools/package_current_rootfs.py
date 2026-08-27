#!/usr/bin/env python3
"""Build a deterministic host-only Root-Linux archive from a locked contract.

The base archive is an immutable input.  This tool never installs to Android,
changes the AOSP vendor archive, signs an OTA, or performs device I/O.

Public output uses an ordered output-then-receipt hard-link protocol, not an
atomic multi-file transaction.  After any successful or outcome-unknown link,
errors are fail-retain: public pathnames are reported and never unlinked.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import posixpath
import re
import secrets
import stat
import struct
import subprocess
import sys
import tarfile
from typing import BinaryIO, Callable, Iterable, Mapping, Sequence


CONTRACT_SCHEMA = "org.trillionnium.rootfs-package.contract.v9"
RECEIPT_SCHEMA = "org.trillionnium.rootfs-package.receipt.v9"
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
FRESH_BASE_ALLOWLIST_SCHEMA = (
    "org.trillionnium.root-linux.fresh-base-allowlist.v1"
)
FRESH_BASE_RECEIPT_SCHEMA = (
    "org.trillionnium.root-linux.minimal-bookworm-receipt.v1"
)
FRESH_BASE_ALLOWLIST_PATH = (
    Path(__file__).resolve().parents[1]
    / "packaging/root-linux/rootfs-fresh-minimal-bookworm-arm64.allowlist.v1.json"
)
FRESH_BASE_BUILDER_PATH = Path(__file__).with_name(
    "build_minimal_bookworm_rootfs.py"
)
FRESH_BASE_BUILD_CONTRACT_PATH = Path(__file__).with_name(
    "evidence-factory"
) / "minimal-bookworm-rootfs.contract.v1.json"
CODEX_ONLY_RUNTIME_MOUNT_DIRECTORIES = (
    "run/trillionnium",
    "tmp",
    "var/lib/trillionnium",
)
CODEX_ONLY_ANDROID_EFFECT_TOOL_PATHS = (
    "usr/local/bin/trillionnium-agent-accessibility",
    "usr/local/bin/trillionnium-agent-system-api",
)
SHELL_EXEC_RUNTIME_BIND_PLACEHOLDER_PATH = (
    "usr/local/bin/trillionnium-agent-shell"
)
SHELL_EXEC_STANDARD_ALLOWLIST_PATH = (
    "etc/trillionnium/shell-exec-standard-allowlist.v1.json"
)
SHELL_EXEC_STANDARD_ALLOWLIST_SCHEMA = (
    "org.trillionnium.shell-exec.standard-executable-policy.v1"
)
SHELL_EXEC_STANDARD_ALLOWLIST_PROFILE = "standard"
SHELL_EXEC_STANDARD_ALLOWLIST_EXECUTABLES = (
    "/bin/echo",
    "/bin/false",
    "/bin/sleep",
    "/bin/true",
    "/bin/uname",
    "/usr/bin/id",
    "/usr/bin/printf",
)
SYSTEM_API_REPLAY_SYNC_INSTALL_PATH = (
    "usr/local/bin/trillionnium-system-api-replay-sync"
)
EXTERNAL_EFFECT_TOOLS = {
    "system_api_tool": {
        "file": "trillionnium-agent-system-api",
        "runtime_bind_path": "usr/local/bin/trillionnium-agent-system-api",
    },
    "accessibility_tool": {
        "file": "trillionnium-agent-accessibility",
        "runtime_bind_path": "usr/local/bin/trillionnium-agent-accessibility",
    },
}
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
SHA256_RE = re.compile(r"[0-9a-f]{64}")
GLIBC_RE = re.compile(rb"GLIBC_(\d+)\.(\d+)")
TOKEN_RE = re.compile(
    rb"(?<![A-Za-z0-9_-])sk-(?:proj-)?[A-Za-z0-9_-]{20,}"
)
RETIRED_PROVIDER_HOME_NAME = "open" + "claw"
STATIC_FORBIDDEN_PATHS = (
    re.compile(
        r"(^|/)(?:auth\.json|credentials?(?:\.json)?|\.env(?:\..*)?|"
        r"id_(?:rsa|dsa|ecdsa|ed25519)|[^/]*(?:private|passphrase)[^/]*\.(?:pem|pk8))$",
        re.IGNORECASE,
    ),
    re.compile(
        r"(^|/)(?:root|home/[^/]+)/(?:\.(?:codex|"
        + re.escape(RETIRED_PROVIDER_HOME_NAME)
        + r"|ssh|aws)(?:/|$)|"
        r"[^/]*(?:auth|credential|api[-_]?key|token)[^/]*)",
        re.IGNORECASE,
    ),
)
STATIC_FORBIDDEN_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)
STATIC_DEVELOPMENT_ONLY_MARKERS = (
    b"TRILLIONNIUM_DEVELOPMENT_RESPONSE_LOSS_FAULT_HOOK_V1",
    b"/run/trillionnium/dev-conformance/fault-hook.json",
    b"org.trillionnium.dev-conformance.gateway-response-loss.v1",
    b"org.trillionnium.dev-conformance.gateway-response-loss-audit.v1",
)
PEM_PRIVATE_KEY_RE = re.compile(
    rb"(?:^|[\r\n])-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\r?\n"
    rb"[A-Za-z0-9+/=]{16,}",
    re.MULTILINE,
)
SENSITIVE_JSON_KEY_RE = re.compile(
    r"(?:^|_)(?:password|passphrase|secret|credential|api_?key|access_?token|refresh_?token)(?:$|_)",
    re.IGNORECASE,
)


class PackagerError(RuntimeError):
    """A fail-closed contract or archive validation failure."""


class RetainedPublicationError(PackagerError):
    """Publication may have crossed the ordered commit boundary and was retained.

    POSIX does not provide an atomic compare-and-unlink operation.  Once a
    public hard link may have been created, this packager never guesses that a
    pathname is still its own and never deletes it during error handling.
    """


def raise_composite_failure(
    context: str,
    primary: BaseException | None,
    failures: Sequence[tuple[str, BaseException]],
) -> None:
    """Raise one explicit error without losing primary or cleanup failures."""

    if not failures:  # pragma: no cover - caller invariant
        raise AssertionError("composite failure requires at least one failure")
    details = "; ".join(
        f"{label}: {type(error).__name__}: {error}"
        for label, error in failures
    )
    if primary is None:
        message = f"{context}: {details}"
        cause: BaseException = failures[0][1]
    else:
        message = (
            f"{context}; primary failure: {type(primary).__name__}: {primary}; "
            f"additional failures: {details}"
        )
        cause = primary
    raise PackagerError(message) from cause


def raise_retained_publication_failure(
    primary: BaseException | None,
    failures: Sequence[tuple[str, BaseException]],
    targets: Sequence["PublicationTarget"],
) -> None:
    """Report a non-atomic ordered publication without deleting public paths."""

    details = "; ".join(
        f"{label}: {type(error).__name__}: {error}"
        for label, error in failures
    )
    primary_text = (
        "none"
        if primary is None
        else f"{type(primary).__name__}: {primary}"
    )
    message = (
        "ordered multi-file publication did not complete; public rollback is "
        "forbidden because POSIX has no atomic compare-and-unlink; "
        f"primary failure: {primary_text}; cleanup failures: {details or 'none'}; "
        f"retained-or-unknown targets: {retained_publication_summary(targets)}"
    )
    cause = (
        primary
        if primary is not None
        else (failures[0][1] if failures else None)
    )
    if cause is None:  # pragma: no cover - caller invariant
        raise AssertionError("retained publication failure needs a cause")
    raise RetainedPublicationError(message) from cause


def hash_open_descriptor(file_descriptor: int) -> tuple[int, str]:
    """Hash a regular-file fd without changing its shared file offset."""

    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(file_descriptor, 1024 * 1024, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    return offset, digest.hexdigest()


def stable_directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Return directory identity fields that publication must not change.

    Directory timestamps and link counts legitimately move when stage/output
    entries are added or removed, so custody is intentionally based on the
    held inode, type, permissions, and ownership instead.
    """

    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
    )


def require_controlled_directory_component(
    metadata: os.stat_result,
    label: str,
    component: str,
    *,
    is_leaf: bool,
) -> None:
    """Require a directory component whose namespace is not externally writable.

    The release-source checkout currently contains an euid-owned ``0775``
    ancestor, so group write is tolerated only for such non-leaf components.
    The directory that directly contains an input or publication target remains
    strict.  Root-owned group-writable ancestors are not equivalent: a
    non-root caller does not control their group membership or namespace.
    """

    mode = stat.S_IMODE(metadata.st_mode)
    effective_uid = os.geteuid()
    if metadata.st_uid not in {0, effective_uid}:
        raise PackagerError(
            f"{label} component is not root/euid-owned: {component}"
        )
    if mode & stat.S_ISVTX:
        raise PackagerError(
            f"{label} sticky directory component is forbidden: {component}"
        )
    if mode & 0o002:
        raise PackagerError(
            f"{label} world-writable directory component is forbidden: {component}"
        )
    if mode & 0o020 and (is_leaf or metadata.st_uid != effective_uid):
        location = "leaf" if is_leaf else "non-euid-owned ancestor"
        raise PackagerError(
            f"{label} {location} directory component must not be group-writable: "
            f"{component}"
        )


class RetainedDirectoryChain:
    """A component-by-component, no-symlink directory custody chain."""

    def __init__(
        self,
        path: Path,
        label: str,
        components: list[tuple[str, int, tuple[int, ...]]],
    ) -> None:
        self.path = path
        self.label = label
        self.components = components

    @classmethod
    def open(cls, path: Path, label: str) -> "RetainedDirectoryChain":
        absolute = Path(os.path.abspath(os.fspath(path)))
        if not absolute.is_absolute():  # pragma: no cover - abspath invariant
            raise PackagerError(f"{label} is not absolute")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        components: list[tuple[str, int, tuple[int, ...]]] = []
        current_fd = -1
        try:
            root = Path(absolute.anchor)
            current_fd = os.open(root, flags)
            root_metadata = os.fstat(current_fd)
            if not stat.S_ISDIR(root_metadata.st_mode):
                raise PackagerError(f"{label} root is not a directory")
            require_controlled_directory_component(
                root_metadata,
                label,
                absolute.anchor,
                is_leaf=len(absolute.parts) == 1,
            )
            components.append(
                (
                    absolute.anchor,
                    current_fd,
                    stable_directory_identity(root_metadata),
                )
            )
            current_fd = -1
            for index, component in enumerate(absolute.parts[1:], start=1):
                parent_fd = components[-1][1]
                try:
                    lexical = os.stat(
                        component,
                        dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError as error:
                    raise PackagerError(f"{label} component is missing") from error
                if stat.S_ISLNK(lexical.st_mode) or not stat.S_ISDIR(lexical.st_mode):
                    raise PackagerError(
                        f"{label} component is not a real directory: {component}"
                    )
                current_fd = os.open(component, flags, dir_fd=parent_fd)
                opened = os.fstat(current_fd)
                if stable_directory_identity(opened) != stable_directory_identity(lexical):
                    raise PackagerError(f"{label} changed while its component was opened")
                require_controlled_directory_component(
                    opened,
                    label,
                    component,
                    is_leaf=index == len(absolute.parts) - 1,
                )
                components.append(
                    (component, current_fd, stable_directory_identity(opened))
                )
                current_fd = -1
            retained = cls(absolute, label, components)
            retained.assert_stable()
            return retained
        except BaseException as primary:
            cleanup_failures: list[tuple[str, BaseException]] = []
            if current_fd >= 0:
                descriptor = current_fd
                current_fd = -1
                try:
                    os.close(descriptor)
                except BaseException as error:
                    cleanup_failures.append(
                        (f"{label} in-progress component fd close", error)
                    )
            retained_components = components
            components = []
            for name, descriptor, _identity in reversed(retained_components):
                try:
                    os.close(descriptor)
                except BaseException as error:
                    cleanup_failures.append(
                        (f"{label} component fd close ({name})", error)
                    )
            if cleanup_failures:
                raise_composite_failure(
                    f"{label} directory-chain retention failed",
                    primary,
                    cleanup_failures,
                )
            raise

    @property
    def directory_fd(self) -> int:
        return self.components[-1][1]

    @property
    def fd_path(self) -> Path:
        return Path(f"/proc/self/fd/{self.directory_fd}")

    def assert_stable(self) -> None:
        for index, (name, descriptor, identity) in enumerate(self.components):
            held = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(held.st_mode)
                or stable_directory_identity(held) != identity
            ):
                raise PackagerError(f"{self.label} held directory changed")
            if index == 0:
                lexical = os.lstat(name)
            else:
                lexical = os.stat(
                    name,
                    dir_fd=self.components[index - 1][1],
                    follow_symlinks=False,
                )
            if (
                stat.S_ISLNK(lexical.st_mode)
                or not stat.S_ISDIR(lexical.st_mode)
                or stable_directory_identity(lexical) != identity
            ):
                raise PackagerError(f"{self.label} pathname component changed")

    def close(self) -> None:
        components = self.components
        self.components = []
        failures: list[tuple[str, BaseException]] = []
        for name, descriptor, _identity in reversed(components):
            try:
                # A failed close has unspecified descriptor state.  Mark the
                # descriptor consumed before the one and only close attempt;
                # retrying could close a subsequently reused descriptor.
                os.close(descriptor)
            except BaseException as error:
                failures.append((f"{self.label} component fd close ({name})", error))
        if failures:
            raise_composite_failure(
                f"{self.label} directory-chain close failed",
                None,
                failures,
            )

    def __enter__(self) -> "RetainedDirectoryChain":
        return self

    def __exit__(
        self,
        _exc_type: object,
        exception: BaseException | None,
        _traceback: object,
    ) -> None:
        try:
            self.close()
        except BaseException as error:
            if exception is not None:
                raise_composite_failure(
                    f"{self.label} body and directory-chain close failed",
                    exception,
                    [(f"{self.label} directory-chain close", error)],
                )
            raise


def stable_staged_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
    )


def committed_publication_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Return the post-link metadata that must survive through final success.

    Creating the public hard link legitimately changes ``st_nlink`` and ctime,
    so this baseline is captured immediately after ``os.link`` returns rather
    than compared with the anonymous staging metadata.  Including ctime makes
    an in-place write detectable even if an actor restores the original bytes,
    mode, and mtime before the final digest recheck.
    """

    return (
        *stable_staged_identity(metadata),
        metadata.st_nlink,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def verify_committed_publication(
    directory_fd: int,
    name: str,
    label: str,
    expected_identity: tuple[int, ...],
    expected_sha256: str,
) -> None:
    """Reopen one public name without following links and verify full bytes."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    primary: BaseException | None = None
    try:
        lexical = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(lexical.st_mode)
            or committed_publication_identity(lexical) != expected_identity
        ):
            raise PackagerError(f"{label} committed pathname metadata changed")
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        opened_before = os.fstat(descriptor)
        actual_bytes, actual_sha256 = hash_open_descriptor(descriptor)
        opened_after = os.fstat(descriptor)
        lexical_after = os.stat(
            name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if (
            committed_publication_identity(opened_before) != expected_identity
            or committed_publication_identity(opened_after) != expected_identity
            or committed_publication_identity(lexical_after) != expected_identity
            or committed_publication_identity(opened_before)
            != committed_publication_identity(lexical)
            or committed_publication_identity(opened_after)
            != committed_publication_identity(lexical_after)
            or actual_bytes != opened_after.st_size
            or actual_sha256 != expected_sha256
        ):
            raise PackagerError(f"{label} committed pathname bytes changed")
    except FileNotFoundError as error:
        primary = PackagerError(f"{label} committed pathname disappeared")
        primary.__cause__ = error
    except BaseException as error:
        primary = error
    if descriptor >= 0:
        closing = descriptor
        descriptor = -1
        try:
            os.close(closing)
        except BaseException as error:
            raise_composite_failure(
                f"{label} committed pathname verification failed",
                primary,
                [(f"{label} verification fd close", error)],
            )
    if primary is not None:
        raise primary


class RetainedStagedFile:
    """One anonymous staged artifact retained by fd through publication."""

    def __init__(
        self,
        directory_fd: int,
        name: str | None,
        label: str,
        file_descriptor: int,
        initial: os.stat_result,
        sha256: str,
    ) -> None:
        self.directory_fd = directory_fd
        self.name = name
        self.label = label
        self.file_descriptor = file_descriptor
        self.initial = initial
        self.sha256 = sha256
        self.source_removed = name is None

    @classmethod
    def open_existing(
        cls,
        directory_fd: int,
        name: str,
        label: str,
    ) -> "RetainedStagedFile":
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        try:
            initial = os.fstat(descriptor)
            lexical = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(initial.st_mode)
                or stable_staged_identity(initial) != stable_staged_identity(lexical)
                or initial.st_nlink != 1
            ):
                raise PackagerError(f"{label} is not a private staged regular file")
            actual_bytes, actual_sha256 = hash_open_descriptor(descriptor)
            if actual_bytes != initial.st_size:
                raise PackagerError(f"{label} changed while it was retained")
            retained = cls(
                directory_fd,
                name,
                label,
                descriptor,
                initial,
                actual_sha256,
            )
            retained.assert_held_stable()
            return retained
        except BaseException as primary:
            try:
                os.close(descriptor)
            except BaseException as error:
                raise_composite_failure(
                    f"{label} retention failed",
                    primary,
                    [(f"{label} retained fd close", error)],
                )
            raise

    @classmethod
    def create_bytes(
        cls,
        directory_fd: int,
        label: str,
        content: bytes,
        mode: int,
    ) -> "RetainedStagedFile":
        """Create an unnamed inode so failed cleanup never unlinks a pathname."""

        temporary_flag = getattr(os, "O_TMPFILE", 0)
        if temporary_flag == 0:
            raise PackagerError("O_TMPFILE is required for safe staged publication")
        flags = (
            os.O_RDWR
            | temporary_flag
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = -1
        try:
            descriptor = os.open(".", flags, mode, dir_fd=directory_fd)
            initial = os.fstat(descriptor)
            if not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 0:
                raise PackagerError(f"{label} anonymous staging inode is invalid")
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise PackagerError(f"short write while staging {label}")
                view = view[written:]
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
            initial = os.fstat(descriptor)
            if initial.st_nlink != 0:
                raise PackagerError(f"{label} staged link count drifted")
            actual_bytes, actual_sha256 = hash_open_descriptor(descriptor)
            if actual_bytes != len(content) or actual_sha256 != sha256_bytes(content):
                raise PackagerError(f"{label} staged bytes changed")
            retained = cls(
                directory_fd,
                None,
                label,
                descriptor,
                initial,
                actual_sha256,
            )
            retained.assert_source_stable(expected_links=0)
            descriptor = -1
            return retained
        except BaseException as primary:
            cleanup_failures: list[tuple[str, BaseException]] = []
            if descriptor >= 0:
                closing = descriptor
                descriptor = -1
                try:
                    os.close(closing)
                except BaseException as error:
                    cleanup_failures.append((f"{label} retained fd close", error))
            if cleanup_failures:
                raise_composite_failure(
                    f"{label} staging failed and cleanup was incomplete",
                    primary,
                    cleanup_failures,
                )
            raise

    @classmethod
    def adopt_anonymous_scratch(
        cls,
        scratch: "RetainedScratchFile",
        label: str,
        mode: int,
    ) -> "RetainedStagedFile":
        """Seal an anonymous scratch inode and transfer its descriptor."""

        descriptor = scratch.file_descriptor
        if descriptor < 0:
            raise PackagerError(f"{label} scratch descriptor is unavailable")
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        initial = os.fstat(descriptor)
        if not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 0:
            raise PackagerError(f"{label} anonymous staged inode is invalid")
        actual_bytes, actual_sha256 = hash_open_descriptor(descriptor)
        if actual_bytes != initial.st_size:
            raise PackagerError(f"{label} changed while it was sealed")
        transferred = scratch.detach_descriptor()
        try:
            if transferred != descriptor:  # pragma: no cover - object invariant
                raise AssertionError("anonymous scratch descriptor transfer changed")
            retained = cls(
                scratch.directory_fd,
                None,
                label,
                transferred,
                initial,
                actual_sha256,
            )
            retained.assert_source_stable(expected_links=0)
            return retained
        except BaseException as primary:
            try:
                os.close(transferred)
            except BaseException as error:
                raise_composite_failure(
                    f"{label} anonymous scratch adoption failed",
                    primary,
                    [(f"{label} adopted fd close", error)],
                )
            raise

    def assert_held_stable(self) -> None:
        current = os.fstat(self.file_descriptor)
        actual_bytes, actual_sha256 = hash_open_descriptor(self.file_descriptor)
        if (
            not stat.S_ISREG(current.st_mode)
            or stable_staged_identity(current) != stable_staged_identity(self.initial)
            or actual_bytes != self.initial.st_size
            or actual_sha256 != self.sha256
        ):
            raise PackagerError(f"{self.label} held inode changed")

    def assert_source_stable(self, *, expected_links: int) -> None:
        self.assert_held_stable()
        if self.name is None:
            if os.fstat(self.file_descriptor).st_nlink != expected_links:
                raise PackagerError(f"{self.label} staged link count changed")
            return
        try:
            lexical = os.stat(
                self.name,
                dir_fd=self.directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError as error:
            raise PackagerError(
                f"{self.label} staged pathname disappeared"
            ) from error
        if (
            stable_staged_identity(lexical) != stable_staged_identity(self.initial)
            or lexical.st_nlink != expected_links
        ):
            raise PackagerError(f"{self.label} staged pathname changed")

    def destination_is_own_inode(self, directory_fd: int, name: str) -> bool:
        try:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        held = os.fstat(self.file_descriptor)
        return (
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_dev == held.st_dev
            and metadata.st_ino == held.st_ino
        )

    def verify_destination(
        self,
        directory_fd: int,
        name: str,
        *,
        expected_links: int,
    ) -> None:
        if not self.destination_is_own_inode(directory_fd, name):
            raise PackagerError(f"{self.label} published pathname changed")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        primary: BaseException | None = None
        try:
            metadata = os.fstat(descriptor)
            actual_bytes, actual_sha256 = hash_open_descriptor(descriptor)
            if (
                stable_staged_identity(metadata)
                != stable_staged_identity(self.initial)
                or metadata.st_nlink != expected_links
                or actual_bytes != self.initial.st_size
                or actual_sha256 != self.sha256
            ):
                raise PackagerError(f"{self.label} published bytes changed")
        except BaseException as error:
            primary = error
        try:
            os.close(descriptor)
        except BaseException as error:
            raise_composite_failure(
                f"{self.label} destination verification failed",
                primary,
                [(f"{self.label} verification fd close", error)],
            )
        if primary is not None:
            raise primary

    def unlink_source_if_own(self) -> bool:
        if self.source_removed:
            return False
        raise PackagerError(
            f"{self.label} named staged source retained: POSIX has no safe "
            "compare-and-unlink operation"
        )

    def close(self) -> None:
        descriptor = self.file_descriptor
        if descriptor < 0:
            return
        self.file_descriptor = -1
        os.close(descriptor)


class PublicationTarget:
    """One ordered, non-atomic public hard-link commit target."""

    NOT_ATTEMPTED = "not_attempted"
    ATTEMPTING_OR_UNKNOWN = "attempting_or_unknown"
    NOT_CREATED = "not_created"
    CREATED = "created_by_this_invocation"

    def __init__(
        self,
        staged: RetainedStagedFile,
        destination_parent: RetainedDirectoryChain,
        destination_name: str,
    ) -> None:
        self.staged = staged
        self.destination_parent = destination_parent
        self.destination_name = destination_name
        self.state = self.NOT_ATTEMPTED
        self.parent_fsynced = False
        self.destination_verified = False
        self.committed_identity: tuple[int, ...] | None = None

    @property
    def public_path(self) -> Path:
        return self.destination_parent.path / self.destination_name

    def link_once(self) -> None:
        """Record provenance immediately after the raw link returns.

        An exception whose syscall outcome is not definitive is deliberately
        left as ``attempting_or_unknown``.  Error handling never inspects a
        pathname and guesses that it is safe to remove.
        """

        self.state = self.ATTEMPTING_OR_UNKNOWN
        try:
            link_retained_file_descriptor(
                self.staged,
                self.destination_parent,
                self.destination_name,
            )
        except FileExistsError as error:
            if self.staged.destination_is_own_inode(
                self.destination_parent.directory_fd,
                self.destination_name,
            ):
                raise PackagerError(
                    f"{self.staged.label} link reported EEXIST after the staged "
                    "inode became public; publication outcome is unknown"
                ) from error
            self.state = self.NOT_CREATED
            raise PackagerError(
                f"{self.staged.label} appeared during publish; overwrite is forbidden"
            ) from error
        else:
            # This assignment must remain the first operation after os.link.
            self.state = self.CREATED
            # Link creation itself changes ctime/nlink.  Capture that legal
            # post-link state immediately so any later write-and-restore is
            # still visible at the final-success boundary.
            metadata_before = os.fstat(self.staged.file_descriptor)
            actual_bytes, actual_sha256 = hash_open_descriptor(
                self.staged.file_descriptor
            )
            metadata_after = os.fstat(self.staged.file_descriptor)
            if (
                not stat.S_ISREG(metadata_after.st_mode)
                or stable_staged_identity(metadata_after)
                != stable_staged_identity(self.staged.initial)
                or committed_publication_identity(metadata_before)
                != committed_publication_identity(metadata_after)
                or metadata_after.st_nlink != 1
                or actual_bytes != metadata_after.st_size
                or actual_sha256 != self.staged.sha256
            ):
                raise PackagerError(
                    f"{self.staged.label} changed while its committed baseline "
                    "was captured"
                )
            self.committed_identity = committed_publication_identity(
                metadata_after
            )

    def fsync_parent(self) -> None:
        os.fsync(self.destination_parent.directory_fd)
        self.parent_fsynced = True

    def verify(self) -> None:
        if self.committed_identity is None:
            raise PackagerError(
                f"{self.staged.label} has no committed publication baseline"
            )
        self.staged.verify_destination(
            self.destination_parent.directory_fd,
            self.destination_name,
            expected_links=1,
        )
        verify_committed_publication(
            self.destination_parent.directory_fd,
            self.destination_name,
            self.staged.label,
            self.committed_identity,
            self.staged.sha256,
        )
        self.destination_verified = True

    def verify_final(
        self,
        destination_parent: RetainedDirectoryChain,
    ) -> None:
        """Verify after staged-fd and ordinary-parent teardown.

        ``destination_parent`` is an independent custody chain retained before
        publication.  It keeps an ``openat(O_NOFOLLOW)`` route available even
        after the staged inode descriptor and the ordinary parent chain close.
        """

        if self.committed_identity is None:
            raise PackagerError(
                f"{self.staged.label} has no committed publication baseline"
            )
        destination_parent.assert_stable()
        verify_committed_publication(
            destination_parent.directory_fd,
            self.destination_name,
            self.staged.label,
            self.committed_identity,
            self.staged.sha256,
        )
        destination_parent.assert_stable()

    def status(self) -> dict[str, object]:
        return {
            "path": os.fspath(self.public_path),
            "link_state": self.state,
            "parent_fsynced": self.parent_fsynced,
            "destination_verified": self.destination_verified,
        }


def link_retained_file_descriptor(
    staged: RetainedStagedFile,
    destination_parent: RetainedDirectoryChain,
    destination_name: str,
) -> None:
    """Hard-link the held inode, never a re-resolved staging pathname."""

    proc_source = f"/proc/self/fd/{staged.file_descriptor}"
    os.link(
        proc_source,
        destination_name,
        dst_dir_fd=destination_parent.directory_fd,
        follow_symlinks=True,
    )


def retained_publication_summary(targets: Sequence[PublicationTarget]) -> str:
    return json.dumps([target.status() for target in targets], sort_keys=True)


class RetainedScratchFile:
    """A retained scratch inode; package flow uses anonymous instances."""

    def __init__(
        self,
        directory_fd: int,
        name: str | None,
        label: str,
        file_descriptor: int,
        initial: os.stat_result,
    ) -> None:
        self.directory_fd = directory_fd
        self.name = name
        self.label = label
        self.file_descriptor = file_descriptor
        self.initial = initial
        self.removed = name is None

    @property
    def path(self) -> Path:
        return Path(f"/proc/self/fd/{self.file_descriptor}")

    @classmethod
    def create_anonymous(
        cls,
        directory_fd: int,
        label: str,
    ) -> "RetainedScratchFile":
        temporary_flag = getattr(os, "O_TMPFILE", 0)
        if temporary_flag == 0:
            raise PackagerError("O_TMPFILE is required for safe scratch files")
        descriptor = -1
        try:
            descriptor = os.open(
                ".",
                os.O_RDWR | temporary_flag | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=directory_fd,
            )
            initial = os.fstat(descriptor)
            if not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 0:
                raise PackagerError(f"{label} anonymous scratch inode is invalid")
            retained = cls(directory_fd, None, label, descriptor, initial)
            descriptor = -1
            return retained
        except BaseException as primary:
            failures: list[tuple[str, BaseException]] = []
            if descriptor >= 0:
                closing = descriptor
                descriptor = -1
                try:
                    os.close(closing)
                except BaseException as error:
                    failures.append((f"{label} anonymous fd close", error))
            if failures:
                raise_composite_failure(
                    f"{label} anonymous scratch creation failed",
                    primary,
                    failures,
                )
            raise

    @classmethod
    def create(
        cls,
        directory_fd: int,
        name: str,
        label: str,
    ) -> "RetainedScratchFile":
        if name in {"", ".", ".."} or "/" in name or "\x00" in name:
            raise PackagerError(f"{label} staging filename is invalid")
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = -1
        created = False
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
            created = True
            initial = os.fstat(descriptor)
            lexical = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(initial.st_mode)
                or initial.st_dev != lexical.st_dev
                or initial.st_ino != lexical.st_ino
                or initial.st_nlink != 1
            ):
                raise PackagerError(f"{label} staging file changed while opened")
            retained = cls(directory_fd, name, label, descriptor, initial)
            descriptor = -1
            return retained
        except BaseException as primary:
            cleanup_failures: list[tuple[str, BaseException]] = []
            if created:
                cleanup_failures.append(
                    (
                        f"{label} named-path cleanup",
                        PackagerError(
                            f"{label} named staging path retained because POSIX "
                            "has no safe compare-and-unlink operation"
                        ),
                    )
                )
            if descriptor >= 0:
                closing = descriptor
                descriptor = -1
                try:
                    os.close(closing)
                except BaseException as error:
                    cleanup_failures.append(
                        (f"{label} failed-creation fd close", error)
                    )
            if cleanup_failures:
                raise_composite_failure(
                    f"{label} creation failed and cleanup was incomplete",
                    primary,
                    cleanup_failures,
                )
            raise

    def unlink_if_own(self) -> bool:
        if self.removed:
            return False
        raise PackagerError(
            f"{self.label} named scratch retained because POSIX has no safe "
            "compare-and-unlink operation"
        )

    def assert_pathname_own(self) -> None:
        if self.name is None:
            if os.fstat(self.file_descriptor).st_nlink != 0:
                raise PackagerError(f"{self.label} anonymous scratch gained a link")
            return
        try:
            lexical = os.stat(
                self.name,
                dir_fd=self.directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError as error:
            if self.removed:
                return
            raise PackagerError(
                f"{self.label} staging pathname disappeared during cleanup"
            ) from error
        if (
            not stat.S_ISREG(lexical.st_mode)
            or lexical.st_dev != self.initial.st_dev
            or lexical.st_ino != self.initial.st_ino
        ):
            raise PackagerError(
                f"{self.label} staging pathname changed; refusing foreign cleanup"
            )

    def mark_removed(self) -> None:
        self.removed = True

    def detach_descriptor(self) -> int:
        descriptor = self.file_descriptor
        if descriptor < 0:
            raise PackagerError(f"{self.label} scratch descriptor already consumed")
        self.file_descriptor = -1
        return descriptor

    def close(self) -> None:
        descriptor = self.file_descriptor
        if descriptor < 0:
            return
        self.file_descriptor = -1
        os.close(descriptor)


class RetainedStagingDirectory:
    """A retained private directory with an explicit owned-file inventory."""

    def __init__(
        self,
        parent: RetainedDirectoryChain,
        name: str,
        descriptor: int,
        initial: os.stat_result,
    ) -> None:
        self.parent = parent
        self.name = name
        self.descriptor = descriptor
        self.initial = initial
        self.path = Path(f"/proc/self/fd/{descriptor}")
        self.owned_files: list[RetainedScratchFile] = []
        self.cleaned = False

    def create_file(self, name: str, label: str) -> tuple[Path, RetainedScratchFile]:
        retained = RetainedScratchFile.create(self.descriptor, name, label)
        self.owned_files.append(retained)
        return self.path / name, retained

    def cleanup(self) -> list[tuple[str, BaseException]]:
        if self.cleaned:
            return []
        self.cleaned = True
        failures: list[tuple[str, BaseException]] = []
        for retained in reversed(self.owned_files):
            try:
                retained.unlink_if_own()
            except BaseException as error:
                failures.append((f"{retained.label} cleanup", error))
            try:
                retained.close()
            except BaseException as error:
                failures.append((f"{retained.label} fd close", error))

        if self.descriptor >= 0:
            try:
                os.fsync(self.descriptor)
            except BaseException as error:
                failures.append(("staging directory fsync", error))

        pathname_is_own = False
        try:
            self.parent.assert_stable()
            lexical = os.stat(
                self.name,
                dir_fd=self.parent.directory_fd,
                follow_symlinks=False,
            )
            pathname_is_own = (
                stat.S_ISDIR(lexical.st_mode)
                and lexical.st_dev == self.initial.st_dev
                and lexical.st_ino == self.initial.st_ino
            )
            if not pathname_is_own:
                raise PackagerError(
                    "staging directory pathname changed; refusing foreign cleanup"
                )
            held = os.fstat(self.descriptor)
            if stable_directory_identity(held) != stable_directory_identity(
                self.initial
            ):
                failures.append(
                    (
                        "staging directory custody",
                        PackagerError("retained staging directory inode changed"),
                    )
                )
        except FileNotFoundError as error:
            failures.append(
                (
                    "staging directory pathname cleanup",
                    PackagerError("staging directory pathname disappeared"),
                )
            )
        except BaseException as error:
            failures.append(("staging directory pathname cleanup", error))

        if pathname_is_own:
            failures.append(
                (
                    "staging directory removal",
                    PackagerError(
                        "named staging directory retained because POSIX has no "
                        "safe compare-and-rmdir operation"
                    ),
                )
            )
        descriptor = self.descriptor
        self.descriptor = -1
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except BaseException as error:
                failures.append(("staging directory fd close", error))
        return failures


@contextmanager
def retained_staging_directory(
    parent: RetainedDirectoryChain,
) -> Iterable[RetainedStagingDirectory]:
    """Create and retain one private stage directory below a held parent."""

    parent.assert_stable()
    name = f".rootfs-packager-{os.getpid()}-{secrets.token_hex(12)}"
    created = False
    descriptor = -1
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent.directory_fd)
        created = True
        created_metadata = os.stat(
            name,
            dir_fd=parent.directory_fd,
            follow_symlinks=False,
        )
        descriptor = os.open(name, flags, dir_fd=parent.directory_fd)
        initial = os.fstat(descriptor)
        lexical = os.stat(name, dir_fd=parent.directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(initial.st_mode)
            or stable_directory_identity(initial)
            != stable_directory_identity(created_metadata)
            or stable_directory_identity(initial)
            != stable_directory_identity(lexical)
        ):
            raise PackagerError("staging directory changed while it was opened")
    except BaseException as primary:
        cleanup_failures: list[tuple[str, BaseException]] = []
        if descriptor >= 0:
            closing = descriptor
            descriptor = -1
            try:
                os.close(closing)
            except BaseException as error:
                cleanup_failures.append(("unretained staging fd close", error))
        if created:
            cleanup_failures.append(
                (
                    "unretained staging directory cleanup",
                    PackagerError(
                        "named staging directory retained because POSIX has no "
                        "safe compare-and-rmdir operation"
                    ),
                )
            )
        if cleanup_failures:
            raise_composite_failure(
                "staging directory retention failed",
                primary,
                cleanup_failures,
            )
        raise
    retained = RetainedStagingDirectory(parent, name, descriptor, initial)
    try:
        yield retained
    finally:
        primary = sys.exc_info()[1]
        cleanup_failures = retained.cleanup()
        if cleanup_failures:
            raise_composite_failure(
                "retained staging cleanup failed",
                primary,
                cleanup_failures,
            )


def ensure_retained_output_available(
    parent: RetainedDirectoryChain,
    name: str,
    label: str,
) -> None:
    if name in {"", ".", ".."} or "/" in name or "\x00" in name:
        raise PackagerError(f"{label} filename is invalid")
    parent.assert_stable()
    try:
        os.stat(name, dir_fd=parent.directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise PackagerError(f"{label} already exists; overwrite is forbidden")


class RetainedRegularInput:
    """One input held open from its first measurement through publication.

    Content consumers use ``/proc/self/fd`` (or a duplicate opened through it),
    while the original pathname is retained solely for identity revalidation.
    This prevents a pathname replacement from changing the bytes consumed by
    JSON parsing, ELF inspection, tar construction, or zstd.
    """

    def __init__(
        self,
        path: Path,
        label: str,
        parent_chain: RetainedDirectoryChain,
        leaf_name: str,
        file_descriptor: int,
        initial: os.stat_result,
        descriptor: Mapping[str, object],
    ) -> None:
        self.original_path = path
        self.label = label
        self.parent_chain = parent_chain
        self.leaf_name = leaf_name
        self.file_descriptor = file_descriptor
        self.initial = initial
        self.descriptor = dict(descriptor)
        self.fd_path = Path(f"/proc/self/fd/{file_descriptor}")
        self.closed = False

    def __fspath__(self) -> str:
        return os.fspath(self.fd_path)

    def __str__(self) -> str:
        return os.fspath(self.fd_path)

    @property
    def name(self) -> str:
        return self.original_path.name

    def open(
        self,
        mode: str = "r",
        buffering: int = -1,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> BinaryIO:
        if any(flag in mode for flag in ("w", "a", "x", "+")):
            raise PackagerError(f"{self.label} retained input is read-only")
        return self.fd_path.open(
            mode,
            buffering=buffering,
            encoding=encoding,
            errors=errors,
            newline=newline,
        )

    def read_bytes(self) -> bytes:
        with self.open("rb") as source:
            return source.read()

    def read_text(
        self,
        encoding: str | None = None,
        errors: str | None = None,
    ) -> str:
        with self.open("r", encoding=encoding, errors=errors) as source:
            return source.read()

    def stat(self) -> os.stat_result:
        return os.fstat(self.file_descriptor)

    def lstat(self) -> os.stat_result:
        return os.fstat(self.file_descriptor)

    def resolve(self, strict: bool = False) -> Path:
        return self.original_path.resolve(strict=strict)

    def assert_stable(self) -> None:
        """Revalidate both the retained inode and the original pathname."""

        self.parent_chain.assert_stable()
        current = os.fstat(self.file_descriptor)
        if stable_regular_fingerprint(current) != stable_regular_fingerprint(
            self.initial
        ):
            raise PackagerError(
                f"{self.label} changed during retained input custody"
            )
        actual_bytes, actual_sha256 = hash_open_descriptor(self.file_descriptor)
        if (
            actual_bytes != self.descriptor["bytes"]
            or actual_sha256 != self.descriptor["sha256"]
        ):
            raise PackagerError(
                f"{self.label} bytes changed during retained input custody"
            )
        try:
            lexical = os.stat(
                self.leaf_name,
                dir_fd=self.parent_chain.directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError as error:
            raise PackagerError(
                f"{self.label} pathname disappeared during retained input custody"
            ) from error
        if stable_regular_fingerprint(lexical) != stable_regular_fingerprint(
            self.initial
        ):
            raise PackagerError(
                f"{self.label} pathname changed during retained input custody"
            )

        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            lexical_descriptor = os.open(
                self.leaf_name,
                flags,
                dir_fd=self.parent_chain.directory_fd,
            )
        except OSError as error:
            raise PackagerError(
                f"{self.label} pathname could not be reopened during final custody check"
            ) from error
        try:
            reopened = os.fstat(lexical_descriptor)
            if stable_regular_fingerprint(reopened) != stable_regular_fingerprint(
                self.initial
            ):
                raise PackagerError(
                    f"{self.label} pathname no longer names the retained input"
                )
            reopened_bytes, reopened_sha256 = hash_open_descriptor(
                lexical_descriptor
            )
            if (
                reopened_bytes != self.descriptor["bytes"]
                or reopened_sha256 != self.descriptor["sha256"]
            ):
                raise PackagerError(
                    f"{self.label} pathname bytes changed during retained input custody"
                )
            reopened_after = os.fstat(lexical_descriptor)
            lexical_after = self.original_path.lstat()
            if (
                stable_regular_fingerprint(reopened_after)
                != stable_regular_fingerprint(self.initial)
                or stable_regular_fingerprint(lexical_after)
                != stable_regular_fingerprint(self.initial)
            ):
                raise PackagerError(
                    f"{self.label} pathname changed during final custody check"
                )
        finally:
            os.close(lexical_descriptor)

        with RetainedDirectoryChain.open(
            self.original_path.parent,
            f"{self.label} fresh parent",
        ) as fresh_parent:
            if stable_directory_identity(
                os.fstat(fresh_parent.directory_fd)
            ) != stable_directory_identity(
                os.fstat(self.parent_chain.directory_fd)
            ):
                raise PackagerError(
                    f"{self.label} fresh parent rewalk changed identity"
                )
            fresh_descriptor = os.open(
                self.leaf_name,
                flags,
                dir_fd=fresh_parent.directory_fd,
            )
            try:
                fresh = os.fstat(fresh_descriptor)
                fresh_bytes, fresh_sha256 = hash_open_descriptor(fresh_descriptor)
                if (
                    stable_regular_fingerprint(fresh)
                    != stable_regular_fingerprint(self.initial)
                    or fresh_bytes != self.descriptor["bytes"]
                    or fresh_sha256 != self.descriptor["sha256"]
                ):
                    raise PackagerError(
                        f"{self.label} fresh pathname rewalk changed identity"
                    )
            finally:
                os.close(fresh_descriptor)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        failures: list[tuple[str, BaseException]] = []
        descriptor = self.file_descriptor
        self.file_descriptor = -1
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except BaseException as error:
                failures.append((f"{self.label} retained fd close", error))
        try:
            self.parent_chain.close()
        except BaseException as error:
            failures.append((f"{self.label} retained parent close", error))
        if failures:
            raise_composite_failure(
                f"{self.label} retained input close failed",
                None,
                failures,
            )


def open_retained_regular_input(path: Path, label: str) -> RetainedRegularInput:
    """Open and measure one input, returning explicit resource ownership."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    leaf_name = absolute.name
    if leaf_name in {"", ".", ".."} or "/" in leaf_name or "\x00" in leaf_name:
        raise PackagerError(f"{label} filename is invalid")
    parent_chain: RetainedDirectoryChain | None = None
    file_descriptor = -1
    try:
        parent_chain = RetainedDirectoryChain.open(
            absolute.parent,
            f"{label} parent",
        )
        try:
            before = os.stat(
                leaf_name,
                dir_fd=parent_chain.directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError as error:
            raise PackagerError(f"{label} input is missing") from error
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise PackagerError(f"{label} must be a regular, non-symlink file")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            file_descriptor = os.open(
                leaf_name,
                flags,
                dir_fd=parent_chain.directory_fd,
            )
        except OSError as error:
            raise PackagerError(
                f"{label} changed while its retained fd was opened"
            ) from error
        opened = os.fstat(file_descriptor)
        if stable_regular_fingerprint(opened) != stable_regular_fingerprint(before):
            raise PackagerError(f"{label} changed while its retained fd was opened")
        actual_bytes, actual_sha256 = hash_open_descriptor(file_descriptor)
        opened_after = os.fstat(file_descriptor)
        try:
            lexical_after = os.stat(
                leaf_name,
                dir_fd=parent_chain.directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError as error:
            raise PackagerError(
                f"{label} pathname disappeared during its first measurement"
            ) from error
        if (
            stable_regular_fingerprint(opened_after)
            != stable_regular_fingerprint(before)
            or stable_regular_fingerprint(lexical_after)
            != stable_regular_fingerprint(before)
            or actual_bytes != opened.st_size
        ):
            raise PackagerError(f"{label} changed during its first measurement")
        retained = RetainedRegularInput(
            absolute,
            label,
            parent_chain,
            leaf_name,
            file_descriptor,
            opened,
            {
                "filename": absolute.name,
                "bytes": actual_bytes,
                "sha256": actual_sha256,
                "mode": f"{stat.S_IMODE(opened.st_mode):04o}",
            },
        )
        retained.assert_stable()
        parent_chain = None
        file_descriptor = -1
        return retained
    except BaseException as primary:
        failures: list[tuple[str, BaseException]] = []
        if file_descriptor >= 0:
            closing = file_descriptor
            file_descriptor = -1
            try:
                os.close(closing)
            except BaseException as error:
                failures.append((f"{label} retained fd close", error))
        if parent_chain is not None:
            try:
                parent_chain.close()
            except BaseException as error:
                failures.append((f"{label} retained parent close", error))
        if failures:
            raise_composite_failure(
                f"{label} input retention failed",
                primary,
                failures,
            )
        raise


@contextmanager
def retained_regular_input(
    path: Path, label: str
) -> Iterable[RetainedRegularInput]:
    """Open and measure a regular input once, retaining the fd until exit."""

    retained = open_retained_regular_input(path, label)
    try:
        yield retained
    finally:
        primary = sys.exc_info()[1]
        try:
            retained.close()
        except BaseException as error:
            if primary is not None:
                raise_composite_failure(
                    f"{label} retained-input body and close failed",
                    primary,
                    [(f"{label} retained-input close", error)],
                )
            raise


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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
            raise PackagerError(f"duplicate JSON key forbidden: {key}")
        result[key] = value
    return result


def reject_json_constant(value: str) -> object:
    raise PackagerError(f"non-finite JSON number forbidden: {value}")


def load_strict_json(
    path: Path | RetainedRegularInput, label: str
) -> object:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise PackagerError(f"{label} is not valid UTF-8 JSON") from error
    try:
        return json.loads(
            text,
            object_pairs_hook=reject_duplicate_json_keys,
            parse_constant=reject_json_constant,
        )
    except json.JSONDecodeError as error:
        raise PackagerError(f"{label} is not valid UTF-8 JSON") from error


def require_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise PackagerError(f"{label} must be a JSON object")
    return value


def require_exact_keys(
    value: Mapping[str, object], keys: set[str], label: str
) -> None:
    actual = set(value)
    if actual != keys:
        raise PackagerError(
            f"{label} keys differ: missing={sorted(keys - actual)} "
            f"unknown={sorted(actual - keys)}"
        )


def require_int(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PackagerError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise PackagerError(f"{label} is outside [{minimum}, {maximum}]")
    return value


def require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise PackagerError(f"{label} must be a lowercase SHA-256")
    return value


def is_bounded_utf8_text(value: object, minimum: int, maximum: int) -> bool:
    if not isinstance(value, str):
        return False
    try:
        size = len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError:
        return False
    return minimum <= size <= maximum


def require_mode(value: object, label: str) -> int:
    if not isinstance(value, str) or re.fullmatch(r"0[0-7]{3}", value) is None:
        raise PackagerError(f"{label} must be a four-digit octal mode")
    mode = int(value, 8)
    if mode & 0o022:
        raise PackagerError(f"{label} must not be group/world writable")
    return mode


def glibc_tuple(value: object, label: str) -> tuple[int, int]:
    if not isinstance(value, str):
        raise PackagerError(f"{label} must be MAJOR.MINOR")
    match = re.fullmatch(r"(\d+)\.(\d+)", value)
    if match is None:
        raise PackagerError(f"{label} must be MAJOR.MINOR")
    return int(match.group(1)), int(match.group(2))


def canonical_member_path(raw_name: str, max_path_bytes: int) -> str:
    if not raw_name or "\x00" in raw_name or "\\" in raw_name:
        raise PackagerError("tar member has an empty, NUL, or backslash path")
    if raw_name.startswith("/"):
        raise PackagerError(f"absolute tar member forbidden: {raw_name!r}")
    name = raw_name
    while name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    if name in {"", "."}:
        return "."
    parts = name.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise PackagerError(f"non-canonical tar member forbidden: {raw_name!r}")
    if any(any(ord(character) < 32 for character in part) for part in parts):
        raise PackagerError(f"control character in tar member: {raw_name!r}")
    canonical = "/".join(parts)
    try:
        encoded = canonical.encode("utf-8")
    except UnicodeEncodeError as error:
        raise PackagerError(f"tar member is not valid UTF-8: {raw_name!r}") from error
    if len(encoded) > max_path_bytes:
        raise PackagerError(f"tar member path exceeds contract limit: {raw_name!r}")
    return canonical


def canonical_hardlink_target(raw_target: str, max_path_bytes: int) -> str:
    target = canonical_member_path(raw_target, max_path_bytes)
    if target == ".":
        raise PackagerError("hardlink target may not be archive root")
    return target


def resolved_symlink_target(path: str, target: str, max_path_bytes: int) -> str:
    if not target or "\x00" in target or "\\" in target:
        raise PackagerError(f"invalid symlink target for {path}")
    if target.startswith("/"):
        raise PackagerError(f"absolute symlink target forbidden: {path} -> {target}")
    if any(ord(character) < 32 for character in target):
        raise PackagerError(f"control character in symlink target: {path}")
    try:
        encoded_target = target.encode("utf-8")
    except UnicodeEncodeError as error:
        raise PackagerError(f"symlink target is not valid UTF-8: {path}") from error
    if len(encoded_target) > max_path_bytes:
        raise PackagerError(f"symlink target exceeds contract limit: {path}")
    parent = "." if path == "." else posixpath.dirname(path)
    resolved = posixpath.normpath(posixpath.join(parent, target))
    if resolved == ".." or resolved.startswith("../") or resolved.startswith("/"):
        raise PackagerError(f"escaping symlink target forbidden: {path} -> {target}")
    try:
        encoded = resolved.encode("utf-8")
    except UnicodeEncodeError as error:
        raise PackagerError(f"symlink target is not valid UTF-8: {path}") from error
    if len(encoded) > max_path_bytes:
        raise PackagerError(f"resolved symlink target exceeds contract limit: {path}")
    return resolved


def install_spec(value: object, label: str, max_path_bytes: int) -> dict[str, object]:
    mapping = require_mapping(value, label)
    require_exact_keys(mapping, {"path", "mode"}, label)
    raw_path = mapping["path"]
    if not isinstance(raw_path, str):
        raise PackagerError(f"{label}.path must be a string")
    path = canonical_member_path(raw_path, max_path_bytes)
    if path == ".":
        raise PackagerError(f"{label}.path may not be archive root")
    return {"path": path, "mode": require_mode(mapping["mode"], f"{label}.mode")}


def validate_common_source_bom(value: object, label: str) -> dict[str, object]:
    source_bom = require_mapping(value, label)
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
        label,
    )
    if (
        source_bom["authority"]
        != "local_exact_clean_graph_not_build_or_release_authority"
        or isinstance(source_bom["bytes"], bool)
        or not isinstance(source_bom["bytes"], int)
        or not 0 < source_bom["bytes"] <= 8 * 1024 * 1024
        or not isinstance(source_bom["control_head"], str)
        or re.fullmatch(r"[0-9a-f]{40,64}", source_bom["control_head"]) is None
        or not isinstance(source_bom["receipt_id"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", source_bom["receipt_id"]) is None
        or any(
            not isinstance(source_bom[field], str)
            or SHA256_RE.fullmatch(source_bom[field]) is None
            for field in (
                "file_sha256",
                "resolved_manifest_sha256",
                "source_set_sha256",
            )
        )
        or source_bom["source_set_sha256"] == "0" * 64
        or source_bom["resolved_manifest_sha256"] == "0" * 64
    ):
        raise PackagerError(f"{label} binding is malformed")
    return dict(source_bom)


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
            raise PackagerError(f"{label} omitted its raw-tool match field")
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
        or isinstance(tool["bytes"], bool)
        or not isinstance(tool["bytes"], int)
        or not 0 < tool["bytes"] <= 1 << 30
        or not isinstance(tool["sha256"], str)
        or SHA256_RE.fullmatch(tool["sha256"]) is None
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
        or not is_bounded_utf8_text(tool["version"], 1, 4096)
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
        raise PackagerError(f"{label} custody is malformed")
    if include_path:
        path = tool["path"]
        if (
            not is_bounded_utf8_text(path, 1, 4096)
            or not path.startswith("/")
            or "\x00" in path
            or any(part in {"", ".", ".."} for part in path.split("/")[1:])
        ):
            raise PackagerError(f"{label}.path is not canonical absolute syntax")
    else:
        assert raw_match_field is not None
        if (
            tool["a_b_byte_equal"] is not True
            or tool["build_time_bytes_bound_by_upstream_receipt"] is not True
            or tool[raw_match_field] is not True
        ):
            raise PackagerError(f"{label} A/B custody claims are incomplete")
    expected_identity = EXPECTED_LAUNCHER_BUILD_TOOL_IDENTITIES[role]
    if any(tool[field] != expected for field, expected in expected_identity.items()):
        raise PackagerError(f"{label} differs from the frozen Mobian snapshot leaf")
    return json.loads(json.dumps(tool))


def validate_toolchain_snapshot_binding(
    value: object, label: str
) -> dict[str, object]:
    snapshot = require_mapping(value, label)
    require_exact_keys(snapshot, set(EXPECTED_TOOLCHAIN_SNAPSHOT_BINDING), label)
    if snapshot != EXPECTED_TOOLCHAIN_SNAPSHOT_BINDING:
        raise PackagerError(f"{label} differs from the frozen Mobian snapshot")
    return json.loads(json.dumps(snapshot))


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
            raise PackagerError(
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
        raise PackagerError(f"{label} posture differs")
    return json.loads(json.dumps(closure))


def validate_claim_authority(
    value: object,
    label: str,
    expected: Mapping[str, object],
) -> dict[str, object]:
    authority = require_mapping(value, label)
    require_exact_keys(authority, set(expected), label)
    if authority != expected:
        raise PackagerError(f"{label} overclaims downstream authority")
    return json.loads(json.dumps(authority))


def tool_without_local_path(value: Mapping[str, object]) -> dict[str, object]:
    result = json.loads(json.dumps(value))
    result.pop("path", None)
    return result


def validate_common_launcher_ab_summary(
    value: object, label: str
) -> dict[str, object]:
    summary = require_mapping(value, label)
    require_exact_keys(
        summary,
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
        label,
    )
    if (
        isinstance(summary["bytes"], bool)
        or not isinstance(summary["bytes"], int)
        or not 0 < summary["bytes"] <= 16 * 1024 * 1024
        or summary["compiler_and_elf_inspector_build_time_bytes_bound"] is not True
        or summary["decision"] != COMMON_LAUNCHER_AB_DECISION
        or summary["deterministic_artifact_set_ab_verified"] is not True
        or summary["lane"] != "common"
        or summary[
            "physical_source_bom_or_live_graph_remeasured_by_this_stage"
        ]
        is not False
        or not isinstance(summary["raw_elf_ab_receipt_id"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", summary["raw_elf_ab_receipt_id"])
        is None
        or not isinstance(summary["receipt_id"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", summary["receipt_id"]) is None
        or summary["release_status"] != COMMON_LAUNCHER_AB_HOLD
        or summary["same_upstream_source_bom_receipt_claim"] is not True
        or summary["schema"] != COMMON_LAUNCHER_AB_SCHEMA
        or not isinstance(summary["sha256"], str)
        or SHA256_RE.fullmatch(summary["sha256"]) is None
        or summary["status"] != COMMON_LAUNCHER_AB_HOLD
    ):
        raise PackagerError(f"{label} is malformed or weakens HOLD")
    return dict(summary)


def validate_stable_principal_measurement(
    value: object, label: str
) -> dict[str, object]:
    measurement = require_mapping(value, label)
    require_exact_keys(
        measurement,
        {
            "executable_identity_is_stable_registry_input",
            "launcher_executable_sha256",
            "launcher_identity_source",
            "stable_principal_canonical_sha256",
            "stable_principal_contract_sha256",
            "status",
        },
        label,
    )
    if (
        measurement["status"]
        != "host_measurement_only_avb_slot_admission_absent"
        or measurement["launcher_identity_source"]
        != "measured_after_closed_launcher_inputs"
        or measurement["executable_identity_is_stable_registry_input"] is not False
        or measurement["stable_principal_contract_sha256"]
        != STABLE_PRINCIPAL_CONTRACT_SHA256
        or measurement["stable_principal_canonical_sha256"]
        != STABLE_PRINCIPAL_CANONICAL_SHA256
        or not isinstance(measurement["launcher_executable_sha256"], str)
        or SHA256_RE.fullmatch(measurement["launcher_executable_sha256"]) is None
    ):
        raise PackagerError(f"{label} drifted")
    return dict(measurement)


def validate_identity_independence_gate(
    value: object, label: str
) -> dict[str, object]:
    gate = require_mapping(value, label)
    require_exact_keys(
        gate,
        {
            "counterfactual_same_source_rebuild",
            "digests",
            "literal_digest_absence_verified",
            "stable_principal_admission_split",
            "status",
        },
        label,
    )
    digests = require_mapping(gate["digests"], f"{label}.digests")
    require_exact_keys(
        digests,
        {"canonical digest", "contract digest", "launcher identity"},
        f"{label}.digests",
    )
    for field in (
        "counterfactual_same_source_rebuild",
        "stable_principal_admission_split",
    ):
        nested = require_mapping(gate[field], f"{label}.{field}")
        require_exact_keys(
            nested,
            {"evidence_receipt", "required", "verified"},
            f"{label}.{field}",
        )
        if (
            nested["required"] is not True
            or nested["verified"] is not False
            or nested["evidence_receipt"] is not None
        ):
            raise PackagerError(f"{label}.{field} must remain unverified HOLD")
    if (
        gate["status"] != CONTRACT_STATUS
        or gate["literal_digest_absence_verified"] is not True
        or digests != EXPECTED_LEGACY_DESCRIPTOR_DIGESTS
    ):
        raise PackagerError(f"{label} drifted")
    return {
        "counterfactual_same_source_rebuild": dict(
            gate["counterfactual_same_source_rebuild"]
        ),
        "digests": dict(digests),
        "literal_digest_absence_verified": True,
        "stable_principal_admission_split": dict(
            gate["stable_principal_admission_split"]
        ),
        "status": CONTRACT_STATUS,
    }


def validate_contract(raw: object) -> dict[str, object]:
    contract = require_mapping(raw, "contract")
    require_exact_keys(
        contract,
        {
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
        },
        "contract",
    )
    if contract["schema"] != CONTRACT_SCHEMA:
        raise PackagerError("unsupported contract schema")
    common_build_evidence = require_mapping(
        contract["common_build_evidence"], "common_build_evidence"
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
        "common_build_evidence",
    )
    normalized_common_build_evidence = {
        "compiler": validate_launcher_build_tool(
            common_build_evidence["compiler"],
            "common_build_evidence.compiler",
            "compiler_driver",
            include_path=True,
        ),
        "elf_inspector": validate_launcher_build_tool(
            common_build_evidence["elf_inspector"],
            "common_build_evidence.elf_inspector",
            "elf_inspector",
            include_path=True,
        ),
        "launcher_ab": validate_common_launcher_ab_summary(
            common_build_evidence["launcher_ab"],
            "common_build_evidence.launcher_ab",
        ),
        "source_bom_claim_authority": validate_claim_authority(
            common_build_evidence["source_bom_claim_authority"],
            "common_build_evidence.source_bom_claim_authority",
            SOURCE_BOM_CLAIM_AUTHORITY,
        ),
        "stable_principal_launcher_measurement": validate_stable_principal_measurement(
            common_build_evidence["stable_principal_launcher_measurement"],
            "common_build_evidence.stable_principal_launcher_measurement",
        ),
        "toolchain_claim_authority": validate_claim_authority(
            common_build_evidence["toolchain_claim_authority"],
            "common_build_evidence.toolchain_claim_authority",
            TOOLCHAIN_CLAIM_AUTHORITY,
        ),
        "upstream_receipt_target_compiler_closure_claim": validate_target_compiler_closure(
            common_build_evidence[
                "upstream_receipt_target_compiler_closure_claim"
            ],
            "common_build_evidence.upstream_receipt_target_compiler_closure_claim",
        ),
        "upstream_receipt_toolchain_snapshot_claim": validate_toolchain_snapshot_binding(
            common_build_evidence["upstream_receipt_toolchain_snapshot_claim"],
            "common_build_evidence.upstream_receipt_toolchain_snapshot_claim",
        ),
        "upstream_source_bom_receipt_claim": validate_common_source_bom(
            common_build_evidence["upstream_source_bom_receipt_claim"],
            "common_build_evidence.upstream_source_bom_receipt_claim",
        ),
    }
    admission = require_mapping(contract["admission"], "admission")
    require_exact_keys(
        admission,
        {"decision", "identity_independence_gate", "release_allowed", "status"},
        "admission",
    )
    if (
        admission["decision"] != CONTRACT_DECISION
        or admission["status"] != CONTRACT_STATUS
        or admission["release_allowed"] is not False
    ):
        raise PackagerError("rootfs v9 admission must remain explicit HOLD")
    normalized_admission = {
        "decision": CONTRACT_DECISION,
        "identity_independence_gate": validate_identity_independence_gate(
            admission["identity_independence_gate"],
            "admission.identity_independence_gate",
        ),
        "release_allowed": False,
        "status": CONTRACT_STATUS,
    }
    source_date_epoch = require_int(
        contract["source_date_epoch"], "source_date_epoch", 0, 4_102_444_800
    )

    compression = require_mapping(contract["compression"], "compression")
    require_exact_keys(
        compression,
        {"algorithm", "level", "long_distance_matcher_log", "threads"},
        "compression",
    )
    if compression["algorithm"] != "zstd":
        raise PackagerError("compression.algorithm must be zstd")
    level = require_int(compression["level"], "compression.level", 1, 22)
    long_log = require_int(
        compression["long_distance_matcher_log"],
        "compression.long_distance_matcher_log",
        10,
        31,
    )
    threads = require_int(compression["threads"], "compression.threads", 1, 1)

    limits = require_mapping(contract["limits"], "limits")
    require_exact_keys(
        limits,
        {
            "max_members",
            "max_member_bytes",
            "max_total_regular_bytes",
            "max_decompressed_tar_bytes",
            "max_path_bytes",
        },
        "limits",
    )
    normalized_limits = {
        "max_members": require_int(limits["max_members"], "limits.max_members", 1, 1_000_000),
        "max_member_bytes": require_int(
            limits["max_member_bytes"], "limits.max_member_bytes", 1, 1 << 40
        ),
        "max_total_regular_bytes": require_int(
            limits["max_total_regular_bytes"],
            "limits.max_total_regular_bytes",
            1,
            1 << 44,
        ),
        "max_decompressed_tar_bytes": require_int(
            limits["max_decompressed_tar_bytes"],
            "limits.max_decompressed_tar_bytes",
            1024,
            1 << 44,
        ),
        "max_path_bytes": require_int(
            limits["max_path_bytes"], "limits.max_path_bytes", 16, 65535
        ),
    }

    runtime = require_mapping(contract["runtime"], "runtime")
    require_exact_keys(runtime, {"elf_machine", "max_glibc"}, "runtime")
    if runtime["elf_machine"] != "AArch64":
        raise PackagerError("runtime.elf_machine must be AArch64")
    max_glibc = glibc_tuple(runtime["max_glibc"], "runtime.max_glibc")

    inputs = require_mapping(contract["inputs"], "inputs")
    require_exact_keys(
        inputs,
        {
            "base_rootfs",
            "common_artifact_set_receipt",
            "common_launcher_ab_receipt",
            "daemon",
            "codex",
            "system_api_tool",
            "accessibility_tool",
            "system_api_replay_sync",
            "agent_manifest",
        },
        "inputs",
    )
    base = require_mapping(inputs["base_rootfs"], "inputs.base_rootfs")
    require_exact_keys(base, {"sha256", "bytes"}, "inputs.base_rootfs")
    normalized_base = {
        "sha256": require_sha256(base["sha256"], "inputs.base_rootfs.sha256"),
        "bytes": require_int(base["bytes"], "inputs.base_rootfs.bytes", 1, 1 << 42),
    }

    def binary_input(name: str) -> dict[str, object]:
        value = require_mapping(inputs[name], f"inputs.{name}")
        require_exact_keys(
            value, {"sha256", "bytes", "install", "require_static"}, f"inputs.{name}"
        )
        require_static = value["require_static"]
        if not isinstance(require_static, bool):
            raise PackagerError(f"inputs.{name}.require_static must be boolean")
        return {
            "sha256": require_sha256(value["sha256"], f"inputs.{name}.sha256"),
            "bytes": require_int(value["bytes"], f"inputs.{name}.bytes", 1, 1 << 34),
            "install": install_spec(
                value["install"], f"inputs.{name}.install", normalized_limits["max_path_bytes"]
            ),
            "require_static": require_static,
        }

    daemon = binary_input("daemon")
    codex = binary_input("codex")
    system_api_tool = binary_input("system_api_tool")
    accessibility_tool = binary_input("accessibility_tool")
    system_api_replay_sync = binary_input("system_api_replay_sync")
    if daemon["require_static"] is not False:
        raise PackagerError("inputs.daemon.require_static must be false")
    if codex["require_static"] is not True:
        raise PackagerError("inputs.codex.require_static must be true")
    for name, value in (
        ("daemon", daemon),
        ("system_api_tool", system_api_tool),
        ("accessibility_tool", accessibility_tool),
        ("system_api_replay_sync", system_api_replay_sync),
    ):
        if value["require_static"] is not False:
            raise PackagerError(f"inputs.{name}.require_static must be false")
    for name, value in (
        ("daemon", daemon),
        ("codex", codex),
        ("system_api_tool", system_api_tool),
        ("accessibility_tool", accessibility_tool),
        ("system_api_replay_sync", system_api_replay_sync),
    ):
        if value["install"]["mode"] != 0o755:
            raise PackagerError(
                f"inputs.{name}.install.mode must be 0755 before immutable "
                "output normalization"
            )
    if (
        system_api_replay_sync["install"]["path"]
        != SYSTEM_API_REPLAY_SYNC_INSTALL_PATH
    ):
        raise PackagerError(
            "inputs.system_api_replay_sync.install.path must be the reviewed "
            "Root-Linux replay-sync path"
        )
    for name, expected in EXTERNAL_EFFECT_TOOLS.items():
        value = system_api_tool if name == "system_api_tool" else accessibility_tool
        if value["install"]["path"] != expected["runtime_bind_path"]:
            raise PackagerError(f"inputs.{name}.install.path drifted")
    common_receipt = require_mapping(
        inputs["common_artifact_set_receipt"],
        "inputs.common_artifact_set_receipt",
    )
    require_exact_keys(
        common_receipt,
        {"bytes", "file", "schema", "sha256", "status"},
        "inputs.common_artifact_set_receipt",
    )
    if (
        common_receipt["file"] != COMMON_ARTIFACT_SET_FILE
        or common_receipt["schema"] != COMMON_ARTIFACT_SET_SCHEMA
        or common_receipt["status"] != COMMON_ARTIFACT_SET_STATUS
    ):
        raise PackagerError("common artifact-set receipt identity drifted")
    normalized_common_receipt = {
        "bytes": require_int(
            common_receipt["bytes"],
            "inputs.common_artifact_set_receipt.bytes",
            1,
            1 << 30,
        ),
        "file": COMMON_ARTIFACT_SET_FILE,
        "schema": COMMON_ARTIFACT_SET_SCHEMA,
        "sha256": require_sha256(
            common_receipt["sha256"],
            "inputs.common_artifact_set_receipt.sha256",
        ),
        "status": COMMON_ARTIFACT_SET_STATUS,
    }
    launcher_ab_receipt = require_mapping(
        inputs["common_launcher_ab_receipt"],
        "inputs.common_launcher_ab_receipt",
    )
    require_exact_keys(
        launcher_ab_receipt,
        {"bytes", "decision", "file", "schema", "sha256", "status"},
        "inputs.common_launcher_ab_receipt",
    )
    if (
        launcher_ab_receipt["decision"] != COMMON_LAUNCHER_AB_DECISION
        or launcher_ab_receipt["file"] != COMMON_LAUNCHER_AB_FILE
        or launcher_ab_receipt["schema"] != COMMON_LAUNCHER_AB_SCHEMA
        or launcher_ab_receipt["status"] != COMMON_LAUNCHER_AB_HOLD
    ):
        raise PackagerError("common launcher A/B receipt identity drifted")
    normalized_launcher_ab_receipt = {
        "bytes": require_int(
            launcher_ab_receipt["bytes"],
            "inputs.common_launcher_ab_receipt.bytes",
            1,
            16 * 1024 * 1024,
        ),
        "decision": COMMON_LAUNCHER_AB_DECISION,
        "file": COMMON_LAUNCHER_AB_FILE,
        "schema": COMMON_LAUNCHER_AB_SCHEMA,
        "sha256": require_sha256(
            launcher_ab_receipt["sha256"],
            "inputs.common_launcher_ab_receipt.sha256",
        ),
        "status": COMMON_LAUNCHER_AB_HOLD,
    }
    manifest = require_mapping(inputs["agent_manifest"], "inputs.agent_manifest")
    require_exact_keys(
        manifest,
        {"sha256", "bytes", "install", "required_fields", "allowed_fields"},
        "inputs.agent_manifest",
    )
    required_fields = require_mapping(
        manifest["required_fields"], "inputs.agent_manifest.required_fields"
    )
    allowed_fields_raw = manifest["allowed_fields"]
    if not isinstance(allowed_fields_raw, list) or not allowed_fields_raw:
        raise PackagerError("inputs.agent_manifest.allowed_fields must be a non-empty array")
    if any(not isinstance(item, str) or not item for item in allowed_fields_raw):
        raise PackagerError("agent manifest allowed field names must be non-empty strings")
    if len(set(allowed_fields_raw)) != len(allowed_fields_raw):
        raise PackagerError("agent manifest allowed fields contain duplicates")
    if not set(required_fields).issubset(set(allowed_fields_raw)):
        raise PackagerError("agent manifest required fields are not all allowed")
    if (
        required_fields.get("enabled") is not False
        or required_fields.get("health") != "disabled"
    ):
        raise PackagerError("AgentManifest must remain disabled until product admission")
    normalized_manifest = {
        "sha256": require_sha256(manifest["sha256"], "inputs.agent_manifest.sha256"),
        "bytes": require_int(manifest["bytes"], "inputs.agent_manifest.bytes", 2, 1 << 24),
        "install": install_spec(
            manifest["install"],
            "inputs.agent_manifest.install",
            normalized_limits["max_path_bytes"],
        ),
        "required_fields": dict(required_fields),
        "allowed_fields": sorted(set(allowed_fields_raw)),
    }
    if normalized_manifest["install"]["mode"] != 0o644:
        raise PackagerError(
            "inputs.agent_manifest.install.mode must be 0644 before immutable "
            "output normalization"
        )
    install_paths = {
        str(daemon["install"]["path"]),
        str(codex["install"]["path"]),
        str(system_api_tool["install"]["path"]),
        str(accessibility_tool["install"]["path"]),
        str(system_api_replay_sync["install"]["path"]),
        str(normalized_manifest["install"]["path"]),
    }
    if len(install_paths) != 6:
        raise PackagerError(
            "the five common artifacts and AgentManifest install paths must be distinct"
        )

    tools = require_mapping(contract["tools"], "tools")
    require_exact_keys(tools, {"zstd"}, "tools")
    zstd = require_mapping(tools["zstd"], "tools.zstd")
    require_exact_keys(zstd, {"bytes", "sha256"}, "tools.zstd")
    normalized_zstd = {
        "bytes": require_int(zstd["bytes"], "tools.zstd.bytes", 1, 1 << 30),
        "sha256": require_sha256(zstd["sha256"], "tools.zstd.sha256"),
    }

    security = require_mapping(contract["security"], "security")
    require_exact_keys(
        security,
        {
            "forbidden_path_patterns",
            "forbidden_content_markers",
            "legacy_duplicate_directory_migrations",
            "legacy_prune_members",
            "legacy_raw_name_prune_members",
            "legacy_absolute_symlink_migration",
            "replacement_hardlink_allowlist",
        },
        "security",
    )
    path_patterns = security["forbidden_path_patterns"]
    content_markers = security["forbidden_content_markers"]
    if not isinstance(path_patterns, list) or not isinstance(content_markers, list):
        raise PackagerError("security pattern and marker fields must be arrays")
    compiled_patterns: list[re.Pattern[str]] = []
    for index, pattern in enumerate(path_patterns):
        if not isinstance(pattern, str) or not pattern or len(pattern) > 1024:
            raise PackagerError(f"invalid security.forbidden_path_patterns[{index}]")
        try:
            compiled_patterns.append(re.compile(pattern, re.IGNORECASE))
        except re.error as error:
            raise PackagerError(f"invalid forbidden path regex at index {index}") from error
    marker_bytes: list[bytes] = []
    for index, marker in enumerate(content_markers):
        if not isinstance(marker, str) or not marker or len(marker.encode("utf-8")) > 1024:
            raise PackagerError(f"invalid security.forbidden_content_markers[{index}]")
        marker_bytes.append(marker.encode("utf-8"))

    legacy_defaults: dict[str, object] = {
        "legacy_duplicate_directory_migrations": [],
        "legacy_prune_members": [],
        "legacy_raw_name_prune_members": [],
        "legacy_absolute_symlink_migration": None,
        "replacement_hardlink_allowlist": [],
    }
    for field, expected in legacy_defaults.items():
        if security[field] != expected:
            raise PackagerError(
                "fresh-only contract forbids every legacy migration, prune, "
                f"and replacement-hardlink rule: {field}"
            )

    return {
        "admission": normalized_admission,
        "common_build_evidence": normalized_common_build_evidence,
        "schema": CONTRACT_SCHEMA,
        "source_date_epoch": source_date_epoch,
        "compression": {
            "algorithm": "zstd",
            "level": level,
            "long_distance_matcher_log": long_log,
            "threads": threads,
        },
        "limits": normalized_limits,
        "runtime": {"elf_machine": "AArch64", "max_glibc": max_glibc},
        "tools": {"zstd": normalized_zstd},
        "inputs": {
            "base_rootfs": normalized_base,
            "common_artifact_set_receipt": normalized_common_receipt,
            "common_launcher_ab_receipt": normalized_launcher_ab_receipt,
            "daemon": daemon,
            "codex": codex,
            "system_api_tool": system_api_tool,
            "accessibility_tool": accessibility_tool,
            "system_api_replay_sync": system_api_replay_sync,
            "agent_manifest": normalized_manifest,
        },
        "security": {
            "forbidden_path_patterns": compiled_patterns,
            "forbidden_content_markers": marker_bytes,
            **legacy_defaults,
        },
    }


def load_contract(
    path: Path | RetainedRegularInput,
) -> tuple[dict[str, object], dict[str, object]]:
    raw = load_strict_json(path, "contract")
    return validate_contract(raw), raw


def stat_fingerprint(
    path: Path | RetainedRegularInput,
) -> tuple[int, int, int, int, int]:
    metadata = path.lstat()
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        stat.S_IMODE(metadata.st_mode),
    )


def stable_regular_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
    )


def stable_regular_descriptor(
    path: Path | RetainedRegularInput,
    label: str,
    require_no_write_bits: bool = False,
    require_executable: bool = False,
    require_single_link: bool = False,
) -> dict[str, object]:
    if isinstance(path, RetainedRegularInput):
        path.assert_stable()
    try:
        before = path.lstat()
    except FileNotFoundError as error:
        raise PackagerError(f"{label} input is missing") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise PackagerError(f"{label} must be a regular, non-symlink file")
    mode = stat.S_IMODE(before.st_mode)
    if require_no_write_bits and mode & 0o222:
        raise PackagerError(f"{label} must have no owner/group/world write bits")
    if require_executable and not mode & 0o111:
        raise PackagerError(f"{label} must be executable")
    if require_single_link and before.st_nlink != 1:
        raise PackagerError(f"{label} must have exactly one hard link")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = (
        os.open(
            path.fd_path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
        )
        if isinstance(path, RetainedRegularInput)
        else os.open(path, flags)
    )
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise PackagerError(f"{label} must be a regular, non-symlink file")
        if stable_regular_fingerprint(opened) != stable_regular_fingerprint(before):
            raise PackagerError(f"{label} changed while it was being opened")
        digest = hashlib.sha256()
        actual_bytes = 0
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
                actual_bytes += len(chunk)
        opened_after = os.fstat(descriptor)
        after = path.lstat()
        if (
            stable_regular_fingerprint(opened_after)
            != stable_regular_fingerprint(before)
            or stable_regular_fingerprint(after)
            != stable_regular_fingerprint(before)
        ):
            raise PackagerError(f"{label} changed while it was being hashed")
        if actual_bytes != opened.st_size:
            raise PackagerError(f"{label} changed while it was being hashed")
    finally:
        os.close(descriptor)
    if isinstance(path, RetainedRegularInput):
        path.assert_stable()
    return {
        "filename": path.name,
        "bytes": actual_bytes,
        "sha256": digest.hexdigest(),
        "mode": f"{mode:04o}",
    }


def verify_regular_input(
    path: Path | RetainedRegularInput,
    expected: Mapping[str, object],
    label: str,
    require_no_write_bits: bool = False,
    require_executable: bool = False,
    require_single_link: bool = False,
) -> dict[str, object]:
    descriptor = stable_regular_descriptor(
        path,
        label,
        require_no_write_bits,
        require_executable,
        require_single_link,
    )
    actual_sha = descriptor["sha256"]
    actual_bytes = descriptor["bytes"]
    if actual_sha != expected["sha256"]:
        raise PackagerError(f"{label} SHA-256 mismatch")
    if actual_bytes != expected["bytes"]:
        raise PackagerError(f"{label} byte-size mismatch")
    for field in ("filename", "mode"):
        if field in expected and descriptor[field] != expected[field]:
            raise PackagerError(f"{label} {field} mismatch")
    return descriptor


def describe_regular_input(
    path: Path | RetainedRegularInput, label: str
) -> dict[str, object]:
    return stable_regular_descriptor(path, label)


@contextmanager
def pinned_executable(
    path: Path | RetainedRegularInput,
    expected: Mapping[str, object],
    label: str,
) -> Iterable[tuple[str, int, dict[str, object]]]:
    """Open, measure, and execute one immutable binary through its held fd."""

    if isinstance(path, RetainedRegularInput):
        path.assert_stable()
        initial = os.fstat(path.file_descriptor)
        mode = stat.S_IMODE(initial.st_mode)
        if mode & 0o222:
            raise PackagerError(
                f"{label} must have no owner/group/world write bits"
            )
        if not mode & 0o111:
            raise PackagerError(f"{label} must be executable")
        if initial.st_nlink != 1:
            raise PackagerError(f"{label} must have exactly one hard link")
        descriptor = dict(path.descriptor)
        if descriptor["sha256"] != expected["sha256"]:
            raise PackagerError(f"{label} SHA-256 mismatch")
        if descriptor["bytes"] != expected["bytes"]:
            raise PackagerError(f"{label} byte-size mismatch")
        try:
            yield os.fspath(path.fd_path), path.file_descriptor, descriptor
        finally:
            path.assert_stable()
        return

    require_no_symlink_components(path, label)
    require_private_input_parent(path.parent, label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_descriptor = os.open(path, flags)
    initial = os.fstat(file_descriptor)
    try:
        mode = stat.S_IMODE(initial.st_mode)
        if not stat.S_ISREG(initial.st_mode):
            raise PackagerError(f"{label} must be a regular, non-symlink file")
        if mode & 0o222:
            raise PackagerError(f"{label} must have no owner/group/world write bits")
        if not mode & 0o111:
            raise PackagerError(f"{label} must be executable")
        if initial.st_nlink != 1:
            raise PackagerError(f"{label} must have exactly one hard link")
        if stable_regular_fingerprint(initial) != stable_regular_fingerprint(path.lstat()):
            raise PackagerError(f"{label} changed while its execution fd was opened")
        digest = hashlib.sha256()
        actual_bytes = 0
        os.lseek(file_descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(file_descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            actual_bytes += len(chunk)
        current = os.fstat(file_descriptor)
        lexical = path.lstat()
        if (
            stable_regular_fingerprint(current) != stable_regular_fingerprint(initial)
            or stable_regular_fingerprint(lexical) != stable_regular_fingerprint(initial)
            or actual_bytes != initial.st_size
        ):
            raise PackagerError(f"{label} changed while it was being read")
        actual_sha256 = digest.hexdigest()
        if actual_sha256 != expected["sha256"]:
            raise PackagerError(f"{label} SHA-256 mismatch")
        if actual_bytes != expected["bytes"]:
            raise PackagerError(f"{label} byte-size mismatch")
        descriptor = {
            "filename": path.name,
            "bytes": actual_bytes,
            "sha256": actual_sha256,
            "mode": f"{mode:04o}",
        }
        fd_path = f"/proc/self/fd/{file_descriptor}"
        if not Path("/proc/self/fd").is_dir():
            raise PackagerError("/proc/self/fd is required for pinned tool execution")
        try:
            yield fd_path, file_descriptor, descriptor
        finally:
            current = os.fstat(file_descriptor)
            try:
                lexical = path.lstat()
            except FileNotFoundError as error:
                raise PackagerError(
                    f"{label} pathname disappeared during execution"
                ) from error
            if (
                stable_regular_fingerprint(current)
                != stable_regular_fingerprint(initial)
                or stable_regular_fingerprint(lexical)
                != stable_regular_fingerprint(initial)
            ):
                raise PackagerError(f"{label} changed during execution")
    finally:
        os.close(file_descriptor)


def require_canonical_json_file(
    path: Path | RetainedRegularInput, label: str
) -> tuple[Mapping[str, object], bytes]:
    raw = path.read_bytes()
    value = require_mapping(load_strict_json(path, label), label)
    if json_bytes(value) != raw:
        raise PackagerError(f"{label} must use canonical indented JSON bytes")
    return value, raw


def expected_file_descriptor(
    value: object, label: str, *, extra_keys: set[str] | None = None
) -> dict[str, object]:
    descriptor = require_mapping(value, label)
    keys = {"bytes", "sha256"} | (extra_keys or set())
    require_exact_keys(descriptor, keys, label)
    result = {
        "bytes": require_int(descriptor["bytes"], f"{label}.bytes", 1, 1 << 42),
        "sha256": require_sha256(descriptor["sha256"], f"{label}.sha256"),
    }
    for key in extra_keys or set():
        result[key] = descriptor[key]
    return result


def verify_fresh_base_provenance(
    base_rootfs: Path | RetainedRegularInput,
    base_descriptor: Mapping[str, object],
    receipt_path: Path | RetainedRegularInput,
    sbom_path: Path | RetainedRegularInput,
    *,
    allowlist_path: Path | RetainedRegularInput | None = None,
    builder_path: Path | RetainedRegularInput | None = None,
    build_contract_path: Path | RetainedRegularInput | None = None,
) -> dict[str, object]:
    """Require the one frozen fresh-build receipt/SBOM chain.

    A base SHA in a payload contract is not provenance: the retired workflow
    could point that field at any patched archive.  The current packager only
    accepts the independently reproducible mmdebstrap base pinned by the
    Mobian packaging allowlist, with its exact canonical receipt and SPDX
    document supplied as separate read-only inputs.
    """

    if allowlist_path is None:
        allowlist_path = FRESH_BASE_ALLOWLIST_PATH
    if builder_path is None:
        builder_path = FRESH_BASE_BUILDER_PATH
    if build_contract_path is None:
        build_contract_path = FRESH_BASE_BUILD_CONTRACT_PATH

    allowlist, _ = require_canonical_json_file(
        allowlist_path, "fresh base allowlist"
    )
    require_exact_keys(
        allowlist,
        {
            "schema",
            "builder",
            "build_contract",
            "snapshot",
            "package_allowlist",
            "artifacts",
            "forbidden_input_archives",
            "policy",
        },
        "fresh base allowlist",
    )
    if allowlist["schema"] != FRESH_BASE_ALLOWLIST_SCHEMA:
        raise PackagerError("fresh base allowlist schema drifted")

    builder = require_mapping(allowlist["builder"], "fresh base allowlist.builder")
    require_exact_keys(
        builder, {"path", "bytes", "sha256"}, "fresh base allowlist.builder"
    )
    if builder["path"] != "tools/build_minimal_bookworm_rootfs.py":
        raise PackagerError("fresh base builder path drifted")
    builder_expected = expected_file_descriptor(
        {"bytes": builder["bytes"], "sha256": builder["sha256"]},
        "fresh base allowlist.builder",
    )
    builder_descriptor = verify_regular_input(
        builder_path,
        builder_expected,
        "fresh base builder",
    )

    build_contract = require_mapping(
        allowlist["build_contract"], "fresh base allowlist.build_contract"
    )
    require_exact_keys(
        build_contract,
        {"path", "schema", "bytes", "sha256"},
        "fresh base allowlist.build_contract",
    )
    if (
        build_contract["path"]
        != "tools/evidence-factory/minimal-bookworm-rootfs.contract.v1.json"
        or build_contract["schema"]
        != "org.trillionnium.root-linux.minimal-bookworm-build.v1"
    ):
        raise PackagerError("fresh base build contract identity drifted")
    build_contract_expected = expected_file_descriptor(
        {
            "bytes": build_contract["bytes"],
            "sha256": build_contract["sha256"],
        },
        "fresh base allowlist.build_contract",
    )
    build_contract_descriptor = verify_regular_input(
        build_contract_path,
        build_contract_expected,
        "fresh base build contract",
    )

    artifacts = require_mapping(
        allowlist["artifacts"], "fresh base allowlist.artifacts"
    )
    require_exact_keys(
        artifacts, {"rootfs", "receipt", "sbom"}, "fresh base allowlist.artifacts"
    )
    rootfs_expected = expected_file_descriptor(
        artifacts["rootfs"],
        "fresh base allowlist.artifacts.rootfs",
        extra_keys={"members", "regular_bytes"},
    )
    for field in ("members", "regular_bytes"):
        rootfs_expected[field] = require_int(
            rootfs_expected[field],
            f"fresh base allowlist.artifacts.rootfs.{field}",
            1,
            1 << 42,
        )

    forbidden = allowlist["forbidden_input_archives"]
    if not isinstance(forbidden, list) or not forbidden:
        raise PackagerError("fresh base forbidden-input inventory is empty")
    rejected_digests: set[str] = set()
    for index, item in enumerate(forbidden):
        label = f"fresh base allowlist.forbidden_input_archives[{index}]"
        entry = require_mapping(item, label)
        require_exact_keys(
            entry,
            {"bytes", "sha256", "installed_package_count", "reason"},
            label,
        )
        rejected_digests.add(require_sha256(entry["sha256"], f"{label}.sha256"))
        require_int(entry["bytes"], f"{label}.bytes", 1, 1 << 42)
        require_int(
            entry["installed_package_count"],
            f"{label}.installed_package_count",
            1,
            1_000_000,
        )
        if not isinstance(entry["reason"], str) or not entry["reason"]:
            raise PackagerError(f"{label}.reason must be non-empty text")
    if base_descriptor["sha256"] in rejected_digests:
        raise PackagerError(
            "known historical GUI rootfs is forbidden; rebuild from the fresh allowlist"
        )
    if (
        base_descriptor["bytes"] != rootfs_expected["bytes"]
        or base_descriptor["sha256"] != rootfs_expected["sha256"]
    ):
        raise PackagerError(
            "base_rootfs is not the exact fresh minimal allowlisted archive"
        )

    receipt_expected = expected_file_descriptor(
        artifacts["receipt"],
        "fresh base allowlist.artifacts.receipt",
        extra_keys={"schema", "receipt_id"},
    )
    if receipt_expected["schema"] != FRESH_BASE_RECEIPT_SCHEMA:
        raise PackagerError("fresh base receipt schema pin drifted")
    if (
        not isinstance(receipt_expected["receipt_id"], str)
        or SHA256_RE.fullmatch(str(receipt_expected["receipt_id"])) is None
    ):
        raise PackagerError("fresh base receipt ID pin is malformed")
    receipt_descriptor = verify_regular_input(
        receipt_path,
        receipt_expected,
        "fresh base receipt",
        require_no_write_bits=True,
    )
    receipt, receipt_bytes = require_canonical_json_file(
        receipt_path, "fresh base receipt"
    )
    require_exact_keys(
        receipt,
        {
            "schema",
            "contract",
            "keyring_deb",
            "snapshot",
            "packages",
            "normalization",
            "rootfs",
            "sbom",
            "tools",
            "host_only",
            "product_pin_refresh_performed",
            "fsverity_enable_performed",
            "device_write_performed",
            "ota_signing_performed",
            "release_promotion_performed",
            "receipt_id",
        },
        "fresh base receipt",
    )
    if (
        receipt["schema"] != receipt_expected["schema"]
        or receipt["receipt_id"] != receipt_expected["receipt_id"]
    ):
        raise PackagerError("fresh base receipt identity drifted")
    unsigned_receipt = dict(receipt)
    unsigned_receipt.pop("receipt_id")
    if sha256_bytes(canonical_json_bytes(unsigned_receipt)) != receipt["receipt_id"]:
        raise PackagerError("fresh base receipt self-hash is invalid")
    if sha256_bytes(receipt_bytes) != receipt_expected["sha256"]:
        raise PackagerError("fresh base canonical receipt bytes drifted")
    if (
        receipt["host_only"] is not True
        or any(
            receipt[field] is not False
            for field in (
                "product_pin_refresh_performed",
                "fsverity_enable_performed",
                "device_write_performed",
                "ota_signing_performed",
                "release_promotion_performed",
            )
        )
    ):
        raise PackagerError("fresh base receipt overclaims product authority")

    receipt_contract = expected_file_descriptor(
        receipt["contract"], "fresh base receipt.contract"
    )
    if receipt_contract != build_contract_expected:
        raise PackagerError("fresh base receipt does not bind the frozen build contract")
    receipt_rootfs = require_mapping(receipt["rootfs"], "fresh base receipt.rootfs")
    require_exact_keys(
        receipt_rootfs,
        {"bytes", "sha256", "members", "regular_bytes"},
        "fresh base receipt.rootfs",
    )
    if dict(receipt_rootfs) != rootfs_expected:
        raise PackagerError("fresh base receipt rootfs facts drifted")

    package_allowlist = require_mapping(
        allowlist["package_allowlist"], "fresh base allowlist.package_allowlist"
    )
    require_exact_keys(
        package_allowlist,
        {"count", "names", "resolved_inventory_canonical_json_sha256"},
        "fresh base allowlist.package_allowlist",
    )
    package_count = require_int(
        package_allowlist["count"], "fresh base package count", 1, 10_000
    )
    package_names = package_allowlist["names"]
    if (
        not isinstance(package_names, list)
        or len(package_names) != package_count
        or len(set(package_names)) != package_count
        or any(not isinstance(name, str) or not name for name in package_names)
    ):
        raise PackagerError("fresh base package allowlist is malformed")
    require_sha256(
        package_allowlist["resolved_inventory_canonical_json_sha256"],
        "fresh base resolved inventory digest",
    )
    receipt_packages = require_mapping(
        receipt["packages"], "fresh base receipt.packages"
    )
    if receipt_packages != {
        "allowlist_exact_match": True,
        "count": package_count,
        "names": package_names,
    }:
        raise PackagerError("fresh base receipt package allowlist drifted")

    receipt_sbom = require_mapping(receipt["sbom"], "fresh base receipt.sbom")
    sbom_expected = expected_file_descriptor(
        artifacts["sbom"],
        "fresh base allowlist.artifacts.sbom",
        extra_keys={"schema"},
    )
    if dict(receipt_sbom) != sbom_expected:
        raise PackagerError("fresh base receipt SPDX binding drifted")
    sbom_descriptor = verify_regular_input(
        sbom_path,
        sbom_expected,
        "fresh base SPDX SBOM",
        require_no_write_bits=True,
    )
    sbom, _ = require_canonical_json_file(sbom_path, "fresh base SPDX SBOM")
    if (
        sbom.get("spdxVersion") != "SPDX-2.3"
        or sbom.get("SPDXID") != "SPDXRef-DOCUMENT"
        or sbom.get("name") != "trillionnium-root-linux-minimal-bookworm-arm64"
    ):
        raise PackagerError("fresh base SPDX document identity drifted")
    sbom_packages = sbom.get("packages")
    if not isinstance(sbom_packages, list):
        raise PackagerError("fresh base SPDX package inventory is absent")
    sbom_names = [
        item.get("name") if isinstance(item, dict) else None for item in sbom_packages
    ]
    if sbom_names != package_names:
        raise PackagerError("fresh base SPDX package inventory differs from allowlist")
    if any(
        not isinstance(item, dict)
        or not isinstance(item.get("versionInfo"), str)
        or not item["versionInfo"]
        for item in sbom_packages
    ):
        raise PackagerError("fresh base SPDX package version inventory is malformed")

    normalization = require_mapping(
        receipt["normalization"], "fresh base receipt.normalization"
    )
    if normalization != {
        "uid_gid": "0:0",
        "directories": "0555",
        "regular_files": "0444",
        "executables": "0555",
        "filesystem_write_bits_absent": True,
        "special_files_absent": True,
        "volatile_trees_empty": True,
        "home_and_root_empty": True,
        "absolute_symlinks_rewritten_relative": True,
    }:
        raise PackagerError("fresh base normalization receipt drifted")

    snapshot = require_mapping(allowlist["snapshot"], "fresh base allowlist.snapshot")
    require_exact_keys(
        snapshot,
        {
            "architecture",
            "suite",
            "timestamp",
            "source_date_epoch",
            "archive_signatures_required",
            "keyring_deb",
            "debian_inrelease",
            "security_inrelease",
        },
        "fresh base allowlist.snapshot",
    )
    if (
        snapshot["architecture"] != "arm64"
        or snapshot["suite"] != "bookworm"
        or snapshot["archive_signatures_required"] is not True
    ):
        raise PackagerError("fresh base snapshot platform or signature policy drifted")
    snapshot_epoch = require_int(
        snapshot["source_date_epoch"],
        "fresh base allowlist.snapshot.source_date_epoch",
        1,
        4_102_444_800,
    )
    receipt_snapshot = require_mapping(receipt["snapshot"], "fresh base receipt.snapshot")
    if (
        receipt_snapshot.get("timestamp") != snapshot.get("timestamp")
        or receipt_snapshot.get("archive_signatures_required") is not True
    ):
        raise PackagerError("fresh base authenticated snapshot identity drifted")
    inrelease = require_mapping(
        receipt_snapshot.get("inrelease"), "fresh base receipt.snapshot.inrelease"
    )
    if set(inrelease) != {"debian", "security"} or any(
        not isinstance(inrelease[name], dict)
        or inrelease[name].get("signature_verified") is not True
        for name in ("debian", "security")
    ):
        raise PackagerError("fresh base archive signature evidence is incomplete")

    policy = require_mapping(allowlist["policy"], "fresh base allowlist.policy")
    require_exact_keys(
        policy,
        {
            "fresh_mmdebstrap_build_required",
            "base_receipt_and_sbom_required",
            "archive_subtraction_or_hot_replacement_allowed",
            "independent_keyring_origin_approved",
            "product_admission_allowed",
            "reason_product_hold",
        },
        "fresh base allowlist.policy",
    )
    if (
        policy["fresh_mmdebstrap_build_required"] is not True
        or policy["base_receipt_and_sbom_required"] is not True
        or policy["archive_subtraction_or_hot_replacement_allowed"] is not False
        or policy["independent_keyring_origin_approved"] is not False
        or policy["product_admission_allowed"] is not False
    ):
        raise PackagerError("fresh base policy polarity drifted")

    return {
        "allowlist": {
            **describe_regular_input(allowlist_path, "fresh base allowlist"),
            "schema": FRESH_BASE_ALLOWLIST_SCHEMA,
        },
        "builder": builder_descriptor,
        "build_contract": {
            **build_contract_descriptor,
            "schema": build_contract["schema"],
        },
        "receipt": {
            **receipt_descriptor,
            "schema": receipt["schema"],
            "receipt_id": receipt["receipt_id"],
        },
        "sbom": {
            **sbom_descriptor,
            "schema": sbom_expected["schema"],
        },
        "snapshot_timestamp": snapshot["timestamp"],
        "source_date_epoch": snapshot_epoch,
        "package_count": package_count,
        "fresh_archive_exact_match": True,
        "archive_subtraction_or_hot_replacement_performed": False,
        "product_admission_allowed": False,
    }


def glibc_versions(path: Path) -> list[tuple[int, int]]:
    versions: set[tuple[int, int]] = set()
    carry = b""
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            data = carry + chunk
            versions.update(
                (int(major), int(minor)) for major, minor in GLIBC_RE.findall(data)
            )
            carry = data[-64:]
    return sorted(versions)


def inspect_elf(path: Path, require_static: bool, max_glibc: tuple[int, int], label: str) -> dict[str, object]:
    with path.open("rb") as source:
        header = source.read(64)
        if len(header) < 64 or header[:4] != b"\x7fELF":
            raise PackagerError(f"{label} is not an ELF64 binary")
        if header[4] != 2 or header[5] != 1:
            raise PackagerError(f"{label} must be little-endian ELF64")
        machine = struct.unpack_from("<H", header, 18)[0]
        if machine != 183:
            raise PackagerError(f"{label} wrong architecture: ELF machine {machine}")
        program_offset = struct.unpack_from("<Q", header, 32)[0]
        program_entry_size = struct.unpack_from("<H", header, 54)[0]
        program_count = struct.unpack_from("<H", header, 56)[0]
        has_interpreter = False
        if program_count:
            if program_entry_size < 56:
                raise PackagerError(f"{label} has malformed program headers")
            if program_offset + program_entry_size * program_count > path.stat().st_size:
                raise PackagerError(f"{label} program headers exceed file size")
            for index in range(program_count):
                source.seek(program_offset + index * program_entry_size)
                entry = source.read(program_entry_size)
                if len(entry) != program_entry_size:
                    raise PackagerError(f"{label} program header is truncated")
                if struct.unpack_from("<I", entry, 0)[0] == 3:  # PT_INTERP
                    has_interpreter = True
    if require_static and has_interpreter:
        raise PackagerError(f"{label} contract requires a static ELF")
    versions = glibc_versions(path)
    if versions and max(versions) > max_glibc:
        found = ".".join(map(str, max(versions)))
        allowed = ".".join(map(str, max_glibc))
        raise PackagerError(f"{label} requires GLIBC_{found}, newer than GLIBC_{allowed}")
    return {
        "format": "ELF64",
        "machine": "AArch64",
        "static": not has_interpreter,
        "glibc_versions": [".".join(map(str, version)) for version in versions],
        "max_glibc_compatible": True,
    }


def reject_sensitive_json(value: object, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise PackagerError("AgentManifest contains a non-string key")
            if SENSITIVE_JSON_KEY_RE.search(key):
                raise PackagerError(f"AgentManifest contains credential-like field {path}.{key}")
            reject_sensitive_json(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_sensitive_json(child, f"{path}[{index}]")


def validate_agent_manifest(
    path: Path, spec: Mapping[str, object], codex_sha256: str
) -> dict[str, object]:
    manifest = load_strict_json(path, "AgentManifest")
    mapping = require_mapping(manifest, "AgentManifest")
    required = spec["required_fields"]
    allowed = set(spec["allowed_fields"])
    unknown = set(mapping) - allowed
    if unknown:
        raise PackagerError(f"AgentManifest contains unknown fields: {sorted(unknown)}")
    for key, expected in required.items():
        if mapping.get(key) != expected:
            raise PackagerError(f"AgentManifest required field mismatch: {key}")
    if mapping.get("enabled") is not False or mapping.get("health") != "disabled":
        raise PackagerError("AgentManifest must remain disabled until product admission")
    if mapping.get("identity_key_sha256") != codex_sha256:
        raise PackagerError("AgentManifest identity_key_sha256 is not bound to Codex")
    reject_sensitive_json(mapping)
    return {"schema_valid": True, "identity_bound_to_codex": True}


def validate_common_artifact_set_receipt(
    path: Path,
    spec: Mapping[str, object],
    physical_artifacts: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    receipt, _ = require_canonical_json_file(path, "common artifact-set receipt")
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
    if path.name != spec["file"]:
        raise PackagerError("common artifact-set receipt filename drifted")
    if (
        receipt["schema"] != spec["schema"]
        or receipt["status"] != spec["status"]
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
        raise PackagerError("common artifact-set receipt decision or posture drifted")
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
    source_bom = validate_common_source_bom(
        receipt["source_bom"], "common artifact-set source BOM"
    )
    stable_measurement = validate_stable_principal_measurement(
        receipt["stable_principal_launcher_measurement"],
        "common stable-principal launcher measurement",
    )
    legacy_gate = validate_identity_independence_gate(
        receipt["legacy_descriptor_contamination_hold_gate"],
        "common legacy descriptor contamination gate",
    )
    dependency_graph = require_mapping(
        receipt["dependency_graph"], "common artifact-set dependency graph"
    )
    require_exact_keys(
        dependency_graph,
        {"acyclic", "edge_semantics", "edges", "forbidden_edges"},
        "common artifact-set dependency graph",
    )
    if (
        dependency_graph["acyclic"] is not True
        or set(dependency_graph["edges"] if isinstance(dependency_graph["edges"], list) else ())
        != {
            "codex_runtime->codex_launcher",
            "system_api_tool->codex_launcher",
            "accessibility_tool->codex_launcher",
            "daemon->rootfs_package",
            "replay_sync_helper->rootfs_package",
            "codex_launcher->rootfs_package",
        }
        or set(
            dependency_graph["forbidden_edges"]
            if isinstance(dependency_graph["forbidden_edges"], list)
            else ()
        )
        != {
            "codex_launcher->system_api_tool",
            "codex_launcher->accessibility_tool",
            "rootfs_package->daemon",
            "rootfs_package->replay_sync_helper",
        }
    ):
        raise PackagerError("common artifact-set dependency graph drifted")

    artifacts = require_mapping(receipt["artifacts"], "common artifact-set artifacts")
    artifact_names = {
        "daemon",
        "codex_launcher",
        "system_api_tool",
        "accessibility_tool",
        "replay_sync_helper",
    }
    require_exact_keys(artifacts, artifact_names, "common artifact-set artifacts")
    bindings: dict[str, dict[str, object]] = {}
    for artifact_name in sorted(artifact_names):
        artifact = require_mapping(
            artifacts[artifact_name],
            f"common artifact-set artifacts.{artifact_name}",
        )
        require_exact_keys(
            artifact,
            {"bytes", "file", "sha256"},
            f"common artifact-set artifacts.{artifact_name}",
        )
        physical = physical_artifacts[artifact_name]
        if (
            artifact["file"] != physical["filename"]
            or artifact["bytes"] != physical["bytes"]
            or artifact["sha256"] != physical["sha256"]
        ):
            raise PackagerError(
                "common artifact-set receipt does not match physical artifact: "
                + artifact_name
            )
        bindings[artifact_name] = dict(artifact)

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
    for field, artifact_name in {
        "daemon_input_sha256": "daemon",
        "replay_sync_helper_input_sha256": "replay_sync_helper",
        "system_api_tool_input_sha256": "system_api_tool",
        "accessibility_tool_input_sha256": "accessibility_tool",
    }.items():
        if receipt_inputs[field] != bindings[artifact_name]["sha256"]:
            raise PackagerError(
                "common artifact-set receipt input-to-artifact SHA binding drifted"
            )
    if stable_measurement["launcher_executable_sha256"] != bindings["codex_launcher"]["sha256"]:
        raise PackagerError(
            "common stable-principal launcher measurement is not physically bound"
        )
    if (
        isinstance(receipt_inputs["codex_runtime_bytes"], bool)
        or not isinstance(receipt_inputs["codex_runtime_bytes"], int)
        or receipt_inputs["codex_runtime_bytes"] <= 0
        or any(
            not isinstance(receipt_inputs[field], str)
            or SHA256_RE.fullmatch(receipt_inputs[field]) is None
            for field in ("codex_launcher_source_sha256", "codex_runtime_sha256")
        )
    ):
        raise PackagerError("common artifact-set Codex source custody is malformed")
    return {
        "artifact_bindings": bindings,
        "builder_inputs": dict(receipt_inputs),
        "compiler": compiler,
        "device_execution_verified": False,
        "elf_inspector": elf_inspector,
        "identity_independence_gate": legacy_gate,
        "product_variant": "common",
        "receipt_role": receipt["receipt_role"],
        "release_allowed": False,
        "schema": receipt["schema"],
        "source_bom": source_bom,
        "stable_principal_launcher_measurement": stable_measurement,
        "status": receipt["status"],
        "target_compiler_closure": target_compiler_closure,
        "toolchain_snapshot": toolchain_snapshot,
    }


def validate_common_launcher_ab_receipt(
    path: Path,
    spec: Mapping[str, object],
    common_receipt_descriptor: Mapping[str, object],
    common_evidence: Mapping[str, object],
) -> dict[str, object]:
    receipt, raw = require_canonical_json_file(path, "common launcher A/B receipt")
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
    if path.name != spec["file"]:
        raise PackagerError("common launcher A/B receipt filename drifted")
    if (
        receipt["schema"] != spec["schema"]
        or receipt["decision"] != spec["decision"]
        or receipt["status"] != spec["status"]
        or receipt["release_status"] != COMMON_LAUNCHER_AB_HOLD
        or receipt["release_allowed"] is not False
        or receipt["lane"] != "common"
        or receipt["product_variant"] != "common"
        or receipt["target"] != "aarch64-unknown-linux-gnu"
        or receipt["receipt_id_scope"]
        != COMMON_LAUNCHER_AB_RECEIPT_ID_SCOPE
    ):
        raise PackagerError("common launcher A/B receipt header or HOLD posture drifted")
    receipt_id = receipt["receipt_id"]
    if (
        not isinstance(receipt_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", receipt_id) is None
    ):
        raise PackagerError("common launcher A/B receipt id is malformed")
    preimage = json.loads(json.dumps(receipt))
    preimage.pop("receipt_id")
    if receipt_id != "sha256:" + sha256_bytes(json_bytes(preimage)):
        raise PackagerError(
            "common launcher A/B receipt id does not bind its canonical preimage"
        )

    if receipt["source_bom"] != common_evidence["source_bom"]:
        raise PackagerError("common launcher A/B source BOM is cross-spliced")
    if receipt["builder_inputs"] != common_evidence["builder_inputs"]:
        raise PackagerError("common launcher A/B builder inputs are cross-spliced")
    if (
        receipt["stable_principal_launcher_measurement"]
        != common_evidence["stable_principal_launcher_measurement"]
        or receipt["identity_independence_gate"]
        != common_evidence["identity_independence_gate"]
    ):
        raise PackagerError("common launcher A/B identity evidence is cross-spliced")
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
        raise PackagerError("common launcher A/B toolchain evidence is cross-spliced")

    compiler = validate_launcher_build_tool(
        receipt["compiler"],
        "common launcher A/B compiler",
        "compiler_driver",
        include_path=False,
        raw_match_field="post_build_matches_raw_ab_selected_linker",
    )
    elf_inspector = validate_launcher_build_tool(
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
            elf_inspector,
            common_evidence["elf_inspector"],
            "post_build_matches_raw_ab_selected_readelf",
            "ELF inspector",
        ),
    ):
        projected = json.loads(json.dumps(observed))
        for field in (
            "a_b_byte_equal",
            "build_time_bytes_bound_by_upstream_receipt",
            match_field,
        ):
            projected.pop(field)
        if projected != tool_without_local_path(expected):
            raise PackagerError(
                f"common launcher A/B {label} custody differs from common v5"
            )

    launcher_inputs = require_mapping(
        receipt["launcher_inputs"], "common launcher A/B inputs"
    )
    require_exact_keys(launcher_inputs, {"a", "b"}, "common launcher A/B inputs")
    common_receipt_matches = 0
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
            or isinstance(record["receipt_bytes"], bool)
            or not isinstance(record["receipt_bytes"], int)
            or record["receipt_bytes"] <= 0
            or not isinstance(record["receipt_sha256"], str)
            or SHA256_RE.fullmatch(record["receipt_sha256"]) is None
        ):
            raise PackagerError(f"common launcher A/B inputs.{side} is malformed")
        if (
            record["receipt_bytes"] == common_receipt_descriptor["bytes"]
            and record["receipt_sha256"] == common_receipt_descriptor["sha256"]
        ):
            common_receipt_matches += 1
    if common_receipt_matches == 0:
        raise PackagerError(
            "common v5 receipt must be at least one launcher A/B lane input"
        )

    artifacts = require_mapping(receipt["artifacts"], "common launcher A/B artifacts")
    bindings = require_mapping(
        common_evidence["artifact_bindings"], "common v5 artifact bindings"
    )
    require_exact_keys(artifacts, set(bindings), "common launcher A/B artifacts")
    for role, binding_value in bindings.items():
        binding = require_mapping(binding_value, f"common v5 artifact {role}")
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
            raise PackagerError(f"common launcher A/B artifact {role} is not closed")

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
        or isinstance(raw_ab["bytes"], bool)
        or not isinstance(raw_ab["bytes"], int)
        or raw_ab["bytes"] <= 0
        or not isinstance(raw_ab["sha256"], str)
        or SHA256_RE.fullmatch(raw_ab["sha256"]) is None
        or not isinstance(raw_ab["receipt_id"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", raw_ab["receipt_id"]) is None
    ):
        raise PackagerError("common launcher raw ELF A/B binding is malformed")
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
        raise PackagerError("common launcher A/B comparison set drifted")
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
        raise PackagerError("common launcher A/B posture drifted")
    if receipt["limitations"] != [
        "same_source_counterfactual_identity_independence_is_unverified",
        "stable_principal_admission_split_is_unverified",
        "source_bom_is_an_upstream_receipt_claim_not_physically_remeasured_by_this_stage",
        "receipt_ids_are_content_identifiers_not_signatures_or_attestations",
        "launcher_compiler_elf_inspector_and_snapshot_archiver_bytes_are_bound_but_recursive_toolchain_closure_is_absent",
        "codex_runtime_is_receipt_bound_but_not_a_physical_input_to_this_verifier",
        "launcher_ab_does_not_prove_rootfs_android_device_avb_or_ota",
    ]:
        raise PackagerError("common launcher A/B limitations drifted")
    summary = {
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
        "sha256": sha256_bytes(raw),
        "status": receipt["status"],
    }
    return validate_common_launcher_ab_summary(summary, "common launcher A/B summary")


def forbidden_path(path: str, contract: Mapping[str, object]) -> bool:
    patterns: Iterable[re.Pattern[str]] = (
        *STATIC_FORBIDDEN_PATHS,
        *contract["security"]["forbidden_path_patterns"],
    )
    encoded = path.encode("utf-8")
    markers = (
        *STATIC_FORBIDDEN_MARKERS,
        *STATIC_DEVELOPMENT_ONLY_MARKERS,
        *contract["security"]["forbidden_content_markers"],
    )
    return (
        any(pattern.search(path) for pattern in patterns)
        or TOKEN_RE.search(encoded) is not None
        or any(marker in encoded for marker in markers)
    )


def hash_and_scan_stream(
    source: BinaryIO, path: str, contract: Mapping[str, object]
) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0
    carry = b""
    contract_markers = tuple(contract["security"]["forbidden_content_markers"])
    markers = (*STATIC_DEVELOPMENT_ONLY_MARKERS, *contract_markers)
    overlap = max([1024, *(len(marker) + 8 for marker in markers)])
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
        total += len(chunk)
        data = carry + chunk
        if any(marker in data for marker in STATIC_DEVELOPMENT_ONLY_MARKERS):
            raise PackagerError(
                f"development-only content marker found in tar member: {path}"
            )
        if (
            any(marker in data for marker in contract_markers)
            or TOKEN_RE.search(data)
            or PEM_PRIVATE_KEY_RE.search(data)
        ):
            raise PackagerError(f"secret content marker found in tar member: {path}")
        carry = data[-overlap:]
    return total, digest.hexdigest()


def entry_digest(
    entry_type: str, sha256: str | None, link_target: str | None
) -> tuple[int, str, str]:
    if entry_type == "file":
        assert sha256 is not None
        return -1, sha256, "file-content"
    if entry_type == "directory":
        return 0, EMPTY_SHA256, "empty-directory"
    assert link_target is not None
    encoded = link_target.encode("utf-8")
    return len(encoded), sha256_bytes(encoded), "link-target"


def _android_filter_parse_octal(
    field: bytes,
    label: str,
    *,
    allow_blank: bool = False,
) -> int:
    """Parse one tar octal field with the Android C filter's exact grammar."""

    if not field:
        raise PackagerError(f"Android tar staging filter {label} is empty")
    if field == bytes(len(field)):
        if allow_blank:
            return 0
        raise PackagerError(
            f"Android tar staging filter {label} is an invalid blank octal field"
        )
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
                raise PackagerError(
                    f"Android tar staging filter {label} has digits after termination "
                    "or exceeds the C uint64 octal bound"
                )
            value = value * 8 + byte - ord("0")
            have_digit = True
        elif byte in {0, ord(" ")}:
            terminated = True
        else:
            raise PackagerError(
                f"Android tar staging filter {label} is not octal"
            )
    if not have_digit:
        raise PackagerError(
            f"Android tar staging filter {label} has no octal digits"
        )
    return value


def _android_filter_field_bytes(field: bytes, label: str) -> bytes:
    """Apply the C filter's fixed-field NUL and tail-zero requirements."""

    nul = field.find(b"\0")
    if nul < 0:
        return field
    if any(field[nul:]):
        raise PackagerError(
            f"Android tar staging filter {label} has bytes after its NUL"
        )
    return field[:nul]


def _android_filter_checksum_is_valid(header: bytes) -> bool:
    if len(header) != ANDROID_STAGING_FILTER_TAR_BLOCK_BYTES:
        return False
    try:
        stored = _android_filter_parse_octal(
            header[148:156], "checksum", allow_blank=False
        )
    except PackagerError:
        return False
    calculated = sum(header[:148]) + 8 * ord(" ") + sum(header[156:])
    return stored == calculated


def _android_filter_common_header(header: bytes) -> dict[str, object]:
    if not _android_filter_checksum_is_valid(header):
        raise PackagerError(
            "Android tar staging filter encountered an invalid header checksum"
        )
    posix = header[257:263] == b"ustar\0" and header[263:265] == b"00"
    gnu = header[257:263] == b"ustar " and header[263:265] == b" \0"
    if not (posix or gnu):
        raise PackagerError(
            "Android tar staging filter encountered an unsupported tar header"
        )
    parsed: dict[str, object] = {
        "mode": _android_filter_parse_octal(header[100:108], "mode"),
        "uid": _android_filter_parse_octal(header[108:116], "uid"),
        "gid": _android_filter_parse_octal(header[116:124], "gid"),
        "size": _android_filter_parse_octal(header[124:136], "size"),
        "mtime": _android_filter_parse_octal(header[136:148], "mtime"),
        "devmajor": _android_filter_parse_octal(
            header[329:337], "devmajor", allow_blank=True
        ),
        "devminor": _android_filter_parse_octal(
            header[337:345], "devminor", allow_blank=True
        ),
        "typeflag": header[156],
        "gnu": gnu,
    }
    _android_filter_field_bytes(header[265:297], "uname")
    _android_filter_field_bytes(header[297:329], "gname")
    if any(header[500:512]):
        raise PackagerError(
            "Android tar staging filter header trailer padding is non-zero"
        )
    if (
        int(parsed["mode"]) > 0o7777
        or parsed["uid"] != 0
        or parsed["gid"] != 0
        or parsed["devmajor"] != 0
        or parsed["devminor"] != 0
    ):
        raise PackagerError(
            "Android tar staging filter header ownership, mode, or device fields drifted"
        )
    return parsed


def _android_filter_path_is_canonical(path: bytes) -> bool:
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


def _android_filter_member_path(
    header: bytes, typeflag: int
) -> bytes:
    name = _android_filter_field_bytes(header[0:100], "name")
    prefix = _android_filter_field_bytes(header[345:500], "prefix")
    if not name:
        raise PackagerError("Android tar staging filter member name is empty")
    path = (prefix + b"/" if prefix else b"") + name
    if typeflag == ord("5") and path.endswith(b"/"):
        path = path[:-1]
    if not _android_filter_path_is_canonical(path):
        raise PackagerError(
            "Android tar staging filter member path is not canonical"
        )
    return path


def _android_filter_relative_link_is_contained(
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


def _android_filter_directory_header(header: bytes) -> bytes:
    transformed = bytearray(header)
    transformed[100:108] = b"0000755\0"
    transformed[148:156] = b" " * 8
    checksum = sum(transformed)
    if checksum > 0o777777:
        raise PackagerError(
            "Android tar staging filter directory checksum exceeds its field"
        )
    encoded = f"{checksum:06o}".encode("ascii")
    if len(encoded) != 6:
        raise PackagerError(
            "Android tar staging filter directory checksum encoding drifted"
        )
    transformed[148:156] = encoded + b"\0 "
    result = bytes(transformed)
    if not _android_filter_checksum_is_valid(result):
        raise PackagerError(
            "Android tar staging filter directory checksum reproduction failed"
        )
    return result


def android_staging_filter_closure(tar_path: Path) -> dict[str, object]:
    """Hash the exact stream emitted by the pinned Android tar filter.

    The already-normalized tar is never rewritten.  This is a byte-for-byte
    Python model of the pinned C filter's accepted physical-header grammar,
    fixed GNU longlink fixture and directory mode/checksum transformation.
    """

    block_size = ANDROID_STAGING_FILTER_TAR_BLOCK_BYTES
    digest = hashlib.sha256()
    output_bytes = 0
    header_count = 0
    directory_count = 0
    zero_block_count = 0
    trailer_started = False
    pending_longlink: tuple[bytes, bytes] | None = None
    longlink_count = 0

    with tar_path.open("rb") as source:
        while True:
            header = source.read(block_size)
            if not header:
                break
            if len(header) != block_size:
                raise PackagerError(
                    "Android tar staging filter encountered a short tar block"
                )
            if header == bytes(block_size):
                if pending_longlink is not None:
                    raise PackagerError(
                        "Android tar staging filter GNU longlink lacks its symlink"
                    )
                zero_block_count += 1
                if zero_block_count >= 2:
                    trailer_started = True
                digest.update(header)
                output_bytes += block_size
                continue
            if trailer_started or zero_block_count != 0:
                raise PackagerError(
                    "Android tar staging filter found non-zero data after the trailer"
                )
            header_count += 1
            if header_count > ANDROID_STAGING_FILTER_MAX_HEADER_COUNT:
                raise PackagerError(
                    "Android tar staging filter header count exceeds its fixed bound"
                )
            parsed = _android_filter_common_header(header)
            typeflag = int(parsed["typeflag"])
            size = int(parsed["size"])

            if typeflag == ord("K"):
                if (
                    pending_longlink is not None
                    or longlink_count
                    >= len(ANDROID_STAGING_FILTER_EXPECTED_GNU_LONGLINKS)
                    or parsed["gnu"] is not True
                    or _android_filter_field_bytes(header[0:100], "GNU longlink name")
                    != b"././@LongLink"
                    or parsed["mode"] != 0
                    or parsed["mtime"] != 0
                    or size <= 1
                    or size > ANDROID_STAGING_FILTER_MAX_GNU_LONGLINK_BYTES
                    or any(header[157:257])
                    or any(header[265:500])
                ):
                    raise PackagerError(
                        "Android tar staging filter GNU longlink header drifted"
                    )
                expected_member_text, expected_target_text = (
                    ANDROID_STAGING_FILTER_EXPECTED_GNU_LONGLINKS[longlink_count]
                )
                expected_member = expected_member_text.encode("ascii")
                expected_target = expected_target_text.encode("ascii")
                payload = source.read(block_size)
                if len(payload) != block_size:
                    raise PackagerError(
                        "Android tar staging filter GNU longlink payload is truncated"
                    )
                if (
                    size != len(expected_target) + 1
                    or payload[:size] != expected_target + b"\0"
                    or any(payload[size:])
                ):
                    raise PackagerError(
                        "Android tar staging filter GNU longlink payload drifted"
                    )
                digest.update(header)
                digest.update(payload)
                output_bytes += 2 * block_size
                pending_longlink = (expected_member, expected_target)
                continue

            path = _android_filter_member_path(header, typeflag)
            link = _android_filter_field_bytes(header[157:257], "linkname")
            if typeflag in {0, ord("0")}:
                valid_member = not link
            elif typeflag == ord("1"):
                valid_member = (
                    size == 0
                    and bool(link)
                    and link != b"."
                    and _android_filter_path_is_canonical(link)
                )
            elif typeflag == ord("2"):
                valid_member = size == 0 and bool(link)
            elif typeflag == ord("5"):
                valid_member = (
                    size == 0 and parsed["mode"] == 0o555 and not link
                )
            else:
                valid_member = False
            if not valid_member:
                raise PackagerError(
                    "Android tar staging filter encountered an unsupported or "
                    "invalid tar member header"
                )

            if pending_longlink is not None:
                expected_member, expected_target = pending_longlink
                if (
                    typeflag != ord("2")
                    or path != expected_member
                    or len(expected_target) < 100
                    or header[157:257] != expected_target[:100]
                    or not _android_filter_relative_link_is_contained(
                        path, expected_target
                    )
                ):
                    raise PackagerError(
                        "Android tar staging filter GNU longlink pair drifted"
                    )
                pending_longlink = None
                longlink_count += 1
            elif typeflag == ord("2") and not _android_filter_relative_link_is_contained(
                path, link
            ):
                raise PackagerError(
                    "Android tar staging filter encountered an unsafe symlink"
                )

            if typeflag == ord("5"):
                directory_count += 1
                output_header = _android_filter_directory_header(header)
            else:
                output_header = header
            digest.update(output_header)
            output_bytes += block_size

            data_blocks = (size + block_size - 1) // block_size
            final_payload_bytes = size % block_size
            for index in range(data_blocks):
                data = source.read(block_size)
                if len(data) != block_size:
                    raise PackagerError(
                        "Android tar staging filter member data is truncated"
                    )
                if (
                    index + 1 == data_blocks
                    and final_payload_bytes != 0
                    and any(data[final_payload_bytes:])
                ):
                    raise PackagerError(
                        "Android tar staging filter member padding is non-zero"
                    )
                digest.update(data)
                output_bytes += block_size

    if pending_longlink is not None:
        raise PackagerError(
            "Android tar staging filter GNU longlink is unterminated"
        )
    if zero_block_count < 2:
        raise PackagerError(
            "Android tar staging filter tar trailer is missing or truncated"
        )
    if directory_count != ANDROID_STAGING_FILTER_EXPECTED_DIRECTORY_COUNT:
        raise PackagerError(
            "Android tar staging filter directory count drifted: "
            f"expected {ANDROID_STAGING_FILTER_EXPECTED_DIRECTORY_COUNT}, "
            f"got {directory_count}"
        )
    if longlink_count != len(ANDROID_STAGING_FILTER_EXPECTED_GNU_LONGLINKS):
        raise PackagerError(
            "Android tar staging filter GNU longlink count drifted: "
            f"expected {len(ANDROID_STAGING_FILTER_EXPECTED_GNU_LONGLINKS)}, "
            f"got {longlink_count}"
        )
    return {
        "schema": ANDROID_STAGING_FILTER_SCHEMA,
        "source_sha256": ANDROID_STAGING_FILTER_SOURCE_SHA256,
        "bytes": output_bytes,
        "sha256": digest.hexdigest(),
    }


def inspect_tar(
    tar_path: Path,
    contract: Mapping[str, object],
) -> dict[str, object]:
    """Inspect one canonical, immutable, fresh-only rootfs tar."""

    limits = contract["limits"]
    epoch = int(contract["source_date_epoch"])
    entries: dict[str, dict[str, object]] = {}
    total_regular_bytes = 0
    previous_sort_key: tuple[bool, bytes] | None = None
    with tarfile.open(tar_path, "r:") as archive:
        if archive.pax_headers:
            raise PackagerError("global PAX headers are forbidden")
        for member_count, member in enumerate(archive, start=1):
            if member_count > limits["max_members"]:
                raise PackagerError("tar member count exceeds contract limit")
            path = canonical_member_path(member.name, limits["max_path_bytes"])
            if member.name != path:
                raise PackagerError(
                    f"tar member path spelling is not canonical: {member.name!r}"
                )
            sort_key = (path != ".", path.encode("utf-8"))
            if previous_sort_key is not None and sort_key <= previous_sort_key:
                raise PackagerError(f"tar member order is not canonical: {path}")
            previous_sort_key = sort_key
            if path in entries:
                raise PackagerError(f"duplicate canonical tar member: {path}")
            if member.pax_headers:
                raise PackagerError(f"PAX member headers are forbidden: {path}")
            if member.uid != 0 or member.gid != 0:
                raise PackagerError(f"tar member ownership is not 0:0: {path}")
            if member.uname or member.gname:
                raise PackagerError(f"tar member owner names are not empty: {path}")
            if member.mtime != epoch:
                raise PackagerError(f"tar member timestamp drifted: {path}")
            if forbidden_path(path, contract):
                raise PackagerError(f"forbidden secret path in archive: {path}")
            if path != ".":
                parent = posixpath.dirname(path) or "."
                parent_entry = entries.get(parent)
                if parent_entry is None or parent_entry["type"] != "directory":
                    raise PackagerError(
                        f"tar member parent is absent or not a directory: {path}"
                    )

            mode = member.mode & 0o7777
            entry: dict[str, object] = {
                "path": path,
                "mode": mode,
                "source": "base",
            }
            if member.isdir():
                if mode != 0o555 or member.size != 0:
                    raise PackagerError(
                        f"directory is not normalized 0555/zero: {path}"
                    )
                entry.update(
                    {
                        "type": "directory",
                        "bytes": 0,
                        "sha256": EMPTY_SHA256,
                        "digest_scope": "empty-directory",
                    }
                )
            elif member.isreg():
                if mode not in {0o444, 0o555}:
                    raise PackagerError(
                        f"regular file is not normalized read-only: {path}"
                    )
                if member.sparse is not None:
                    raise PackagerError(f"sparse tar member forbidden: {path}")
                if member.size < 0 or member.size > limits["max_member_bytes"]:
                    raise PackagerError(f"tar member exceeds size limit: {path}")
                total_regular_bytes += member.size
                if total_regular_bytes > limits["max_total_regular_bytes"]:
                    raise PackagerError(
                        "tar regular-file bytes exceed contract limit"
                    )
                stream = archive.extractfile(member)
                if stream is None:
                    raise PackagerError(f"cannot read tar member: {path}")
                with stream:
                    actual_size, digest = hash_and_scan_stream(
                        stream, path, contract
                    )
                if actual_size != member.size:
                    raise PackagerError(f"tar member size mismatch: {path}")
                entry.update(
                    {
                        "type": "file",
                        "bytes": actual_size,
                        "sha256": digest,
                        "digest_scope": "file-content",
                    }
                )
            elif member.issym():
                if mode != 0o777 or member.size != 0:
                    raise PackagerError(
                        f"symlink is not normalized 0777/zero: {path}"
                    )
                link_target = member.linkname
                resolved = resolved_symlink_target(
                    path, link_target, limits["max_path_bytes"]
                )
                if forbidden_path(resolved, contract):
                    raise PackagerError(
                        f"symlink resolves to forbidden path: {path}"
                    )
                size, digest, scope = entry_digest(
                    "symlink", None, link_target
                )
                entry.update(
                    {
                        "type": "symlink",
                        "link_target": link_target,
                        "resolved_target": resolved,
                        "bytes": size,
                        "sha256": digest,
                        "digest_scope": scope,
                    }
                )
            elif member.islnk():
                if mode not in {0o444, 0o555} or member.size != 0:
                    raise PackagerError(
                        f"hardlink is not normalized read-only/zero: {path}"
                    )
                target = canonical_hardlink_target(
                    member.linkname, limits["max_path_bytes"]
                )
                if member.linkname != target:
                    raise PackagerError(
                        f"hardlink target spelling is not canonical: {path}"
                    )
                if forbidden_path(target, contract):
                    raise PackagerError(
                        f"hardlink targets forbidden path: {path}"
                    )
                target_entry = entries.get(target)
                visited = {path}
                while target_entry is not None and target_entry["type"] == "hardlink":
                    if target in visited:
                        raise PackagerError(f"hardlink cycle detected at {path}")
                    visited.add(target)
                    target = str(target_entry["link_target"])
                    target_entry = entries.get(target)
                if target_entry is None or target_entry["type"] != "file":
                    raise PackagerError(
                        f"hardlink target is not an earlier regular file: {path}"
                    )
                size, digest, scope = entry_digest(
                    "hardlink", None, member.linkname
                )
                entry.update(
                    {
                        "type": "hardlink",
                        "link_target": member.linkname,
                        "bytes": size,
                        "sha256": digest,
                        "digest_scope": scope,
                    }
                )
            else:
                raise PackagerError(f"special tar member forbidden: {path}")
            entries[path] = entry

    if "." not in entries:
        raise PackagerError("canonical rootfs tar lacks its root directory")
    return {
        "entries": entries,
        "member_count": len(entries),
        "physical_member_count": len(entries),
        "total_regular_bytes": total_regular_bytes,
    }


def replacement_entry(path: Path, install: Mapping[str, object], contract: Mapping[str, object]) -> dict[str, object]:
    with path.open("rb") as source:
        size, digest = hash_and_scan_stream(source, str(install["path"]), contract)
    input_mode = int(install["mode"])
    output_mode = 0o555 if input_mode & 0o111 else 0o444
    return {
        "path": install["path"],
        "type": "file",
        "mode": output_mode,
        "bytes": size,
        "sha256": digest,
        "digest_scope": "file-content",
        "source": "replacement",
        "source_path": path,
    }


def codex_runtime_placeholder_path(contract: Mapping[str, object]) -> str:
    codex_path = str(contract["inputs"]["codex"]["install"]["path"])
    if posixpath.basename(codex_path) != "codex":
        raise PackagerError(
            "Codex launcher install path must end in /codex so its measured "
            "runtime bind target is unambiguous"
        )
    return canonical_member_path(
        codex_path + ".real", int(contract["limits"]["max_path_bytes"])
    )


def shell_exec_standard_allowlist_bytes(
    entries: Mapping[str, Mapping[str, object]],
) -> bytes:
    """Bind the fixed standard profile to this newly assembled rootfs.

    These are deliberately small, non-launcher utilities.  Every digest is
    taken from the normalized output plan being packaged; no digest is pinned
    from an older receipt.  Interpreters, shells, loaders, dispatchers,
    recursive discovery/launch tools, and destructive copy/move/remove tools
    are outside this closed profile.
    """

    executable_paths = SHELL_EXEC_STANDARD_ALLOWLIST_EXECUTABLES
    if executable_paths != tuple(
        sorted(executable_paths, key=lambda value: value.encode("utf-8"))
    ) or len(set(executable_paths)) != len(executable_paths):
        raise PackagerError("shell executable allowlist path closure is not canonical")
    policy_entries: list[dict[str, str]] = []
    for absolute_path in executable_paths:
        if (
            not absolute_path.startswith("/")
            or absolute_path == "/"
            or "//" in absolute_path
            or any(component in {"", ".", ".."} for component in absolute_path[1:].split("/"))
        ):
            raise PackagerError("shell executable allowlist path is not absolute canonical")
        member_path = absolute_path[1:]
        member = entries.get(member_path)
        digest = member.get("sha256") if isinstance(member, Mapping) else None
        if (
            not isinstance(member, Mapping)
            or member.get("path") != member_path
            or member.get("type") != "file"
            or member.get("mode") != 0o555
            or not isinstance(member.get("bytes"), int)
            or isinstance(member.get("bytes"), bool)
            or int(member["bytes"]) <= 0
            or member.get("digest_scope") != "file-content"
            or not isinstance(digest, str)
            or SHA256_RE.fullmatch(digest) is None
            or digest == "0" * 64
        ):
            raise PackagerError(
                "shell executable allowlist member is not a nonempty 0555 "
                f"regular file in the assembled rootfs: {absolute_path}"
            )
        policy_entries.append({"path": absolute_path, "sha256": digest})
    return canonical_json_bytes(
        {
            "schema": SHELL_EXEC_STANDARD_ALLOWLIST_SCHEMA,
            "profile": SHELL_EXEC_STANDARD_ALLOWLIST_PROFILE,
            "entries": policy_entries,
        }
    )


def build_output_entries(
    base_inspection: Mapping[str, object],
    daemon: Path,
    codex: Path,
    system_api_tool: Path,
    accessibility_tool: Path,
    system_api_replay_sync: Path,
    manifest: Path,
    contract: Mapping[str, object],
) -> tuple[dict[str, dict[str, object]], list[str]]:
    entries = {path: dict(entry) for path, entry in base_inspection["entries"].items()}
    inputs = contract["inputs"]
    replacements = {
        str(inputs["daemon"]["install"]["path"]): replacement_entry(
            daemon, inputs["daemon"]["install"], contract
        ),
        str(inputs["codex"]["install"]["path"]): replacement_entry(
            codex, inputs["codex"]["install"], contract
        ),
        str(inputs["system_api_tool"]["install"]["path"]): replacement_entry(
            system_api_tool, inputs["system_api_tool"]["install"], contract
        ),
        str(inputs["accessibility_tool"]["install"]["path"]): replacement_entry(
            accessibility_tool, inputs["accessibility_tool"]["install"], contract
        ),
        str(inputs["system_api_replay_sync"]["install"]["path"]): replacement_entry(
            system_api_replay_sync,
            inputs["system_api_replay_sync"]["install"],
            contract,
        ),
        str(inputs["agent_manifest"]["install"]["path"]): replacement_entry(
            manifest, inputs["agent_manifest"]["install"], contract
        ),
    }
    for path in sorted(replacements):
        parent = posixpath.dirname(path)
        ancestors: list[str] = []
        while parent not in {"", "."}:
            ancestors.append(parent)
            parent = posixpath.dirname(parent)
        for ancestor in reversed(ancestors):
            existing = entries.get(ancestor)
            if existing is not None and existing["type"] != "directory":
                raise PackagerError(
                    f"replacement ancestor is not a directory: {ancestor}"
                )
            if existing is None:
                entries[ancestor] = {
                    "path": ancestor,
                    "type": "directory",
                    "mode": 0o555,
                    "bytes": 0,
                    "sha256": EMPTY_SHA256,
                    "digest_scope": "empty-directory",
                    "source": "synthetic",
                }
        entries[path] = replacements[path]

    runtime_placeholder = codex_runtime_placeholder_path(contract)
    reserved_directories = set(CODEX_ONLY_RUNTIME_MOUNT_DIRECTORIES)
    # shell.exec.v1 is supplied by the measured Android /system_ext artifact at
    # boot and bind-mounted into Root Linux.  Package only the empty mount
    # target here: putting another executable payload in the rootfs would
    # create a second effect authority and widening the v9 input contract just
    # to carry a file that must never execute would be misleading.
    reserved_placeholders = {
        runtime_placeholder,
        SHELL_EXEC_RUNTIME_BIND_PLACEHOLDER_PATH,
    }
    for path in sorted(reserved_directories | reserved_placeholders):
        parent = path if path in reserved_directories else posixpath.dirname(path)
        ancestors: list[str] = []
        while parent not in {"", "."}:
            ancestors.append(parent)
            parent = posixpath.dirname(parent)
        for ancestor in reversed(ancestors):
            existing = entries.get(ancestor)
            if existing is not None and existing["type"] != "directory":
                raise PackagerError(
                    f"Codex runtime-layout ancestor is not a directory: {ancestor}"
                )
            if existing is None:
                entries[ancestor] = {
                    "path": ancestor,
                    "type": "directory",
                    "mode": 0o555,
                    "bytes": 0,
                    "sha256": EMPTY_SHA256,
                    "digest_scope": "empty-directory",
                    "source": "synthetic",
                }
    for path in sorted(reserved_placeholders):
        if path in entries:
            raise PackagerError(
                "fresh base or payload unexpectedly pre-populates a measured "
                f"bind placeholder: {path}"
            )
        entries[path] = {
            "path": path,
            "type": "file",
            "mode": 0o555,
            "bytes": 0,
            "sha256": EMPTY_SHA256,
            "digest_scope": "file-content",
            "source": "synthetic-empty",
        }

    allowlist_path = canonical_member_path(
        SHELL_EXEC_STANDARD_ALLOWLIST_PATH,
        int(contract["limits"]["max_path_bytes"]),
    )
    if allowlist_path in entries:
        raise PackagerError(
            "fresh base or payload unexpectedly pre-populates the measured "
            f"shell executable allowlist: {allowlist_path}"
        )
    allowlist_parent = posixpath.dirname(allowlist_path)
    ancestors: list[str] = []
    while allowlist_parent not in {"", "."}:
        ancestors.append(allowlist_parent)
        allowlist_parent = posixpath.dirname(allowlist_parent)
    for ancestor in reversed(ancestors):
        existing = entries.get(ancestor)
        if existing is not None and existing["type"] != "directory":
            raise PackagerError(
                f"shell executable allowlist ancestor is not a directory: {ancestor}"
            )
        if existing is None:
            entries[ancestor] = {
                "path": ancestor,
                "type": "directory",
                "mode": 0o555,
                "bytes": 0,
                "sha256": EMPTY_SHA256,
                "digest_scope": "empty-directory",
                "source": "synthetic",
            }
    allowlist_raw = shell_exec_standard_allowlist_bytes(entries)
    entries[allowlist_path] = {
        "path": allowlist_path,
        "type": "file",
        "mode": 0o444,
        "bytes": len(allowlist_raw),
        "sha256": sha256_bytes(allowlist_raw),
        "digest_scope": "file-content",
        "source": "synthetic-content",
        "content": allowlist_raw,
    }

    limits = contract["limits"]
    regular_entries = [entry for entry in entries.values() if entry["type"] == "file"]
    if len(entries) > limits["max_members"]:
        raise PackagerError("normalized tar member count exceeds contract limit")
    if any(int(entry["bytes"]) > limits["max_member_bytes"] for entry in regular_entries):
        raise PackagerError("normalized tar member exceeds contract size limit")
    if sum(int(entry["bytes"]) for entry in regular_entries) > limits["max_total_regular_bytes"]:
        raise PackagerError("normalized tar regular-file bytes exceed contract limit")
    return entries, sorted(replacements)


def normalized_tar_info(entry: Mapping[str, object], epoch: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(str(entry["path"]))
    info.mode = int(entry["mode"])
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = epoch
    info.pax_headers = {}
    info.devmajor = 0
    info.devminor = 0
    entry_type = entry["type"]
    if entry_type == "directory":
        info.type = tarfile.DIRTYPE
        info.size = 0
    elif entry_type == "file":
        info.type = tarfile.REGTYPE
        info.size = int(entry["bytes"])
    elif entry_type == "symlink":
        info.type = tarfile.SYMTYPE
        info.linkname = str(entry["link_target"])
        info.size = 0
    elif entry_type == "hardlink":
        info.type = tarfile.LNKTYPE
        info.linkname = str(entry["link_target"])
        info.size = 0
    else:  # pragma: no cover - internal invariant
        raise PackagerError(f"unsupported normalized member type: {entry_type}")
    return info


def write_normalized_tar(
    base_tar: Path,
    output_tar: Path,
    entries: Mapping[str, Mapping[str, object]],
    epoch: int,
    max_path_bytes: int,
    max_members: int,
) -> None:
    with tarfile.open(base_tar, "r:") as source, tarfile.open(
        output_tar, "w:", format=tarfile.GNU_FORMAT
    ) as destination:
        source_members: dict[str, tarfile.TarInfo] = {}
        for member_count, member in enumerate(source, start=1):
            if member_count > max_members:
                raise PackagerError("base tar changed to exceed the member limit")
            path = canonical_member_path(member.name, max_path_bytes)
            if member.name != path:
                raise PackagerError(
                    f"base tar changed to contain non-canonical member name: {member.name!r}"
                )
            if path in source_members:
                raise PackagerError(
                    f"base tar changed to contain duplicate member: {path}"
                )
            source_members[path] = member
        for path in sorted(entries, key=lambda item: (item != ".", item.encode("utf-8"))):
            entry = entries[path]
            info = normalized_tar_info(entry, epoch)
            if entry["type"] != "file":
                destination.addfile(info)
                continue
            if entry["source"] == "replacement":
                with Path(entry["source_path"]).open("rb") as content:
                    destination.addfile(info, content)
            elif entry["source"] == "synthetic-empty":
                if int(entry["bytes"]) != 0:
                    raise PackagerError(
                        f"synthetic bind placeholder is not empty: {path}"
                    )
                destination.addfile(info)
            elif entry["source"] == "synthetic-content":
                content = entry.get("content")
                if (
                    not isinstance(content, bytes)
                    or len(content) != int(entry["bytes"])
                    or sha256_bytes(content) != entry["sha256"]
                ):
                    raise PackagerError(
                        f"synthetic measured file content changed: {path}"
                    )
                destination.addfile(info, io.BytesIO(content))
            else:
                member = source_members.get(path)
                if member is None:
                    raise PackagerError(f"base tar member disappeared: {path}")
                content = source.extractfile(member)
                if content is None:
                    raise PackagerError(f"base tar member became unreadable: {path}")
                destination.addfile(info, content)


def run_zstd_decompress(
    zstd: Path | RetainedRegularInput,
    zstd_expected: Mapping[str, object],
    source: Path | RetainedRegularInput | RetainedStagedFile,
    destination: Path,
    maximum_bytes: int,
    retained_directory_fds: Sequence[int] = (),
) -> int:
    with pinned_executable(zstd, zstd_expected, "zstd") as (
        executable,
        file_descriptor,
        _,
    ):
        retained_source = isinstance(
            source,
            (RetainedRegularInput, RetainedStagedFile),
        )
        retained_source_fds = (source.file_descriptor,) if retained_source else ()
        command = [executable, "-q", "-d", "-c"]
        source_stdin: int | None = None
        if retained_source:
            # zstd intentionally rejects /proc/self/fd paths as symlinks, so
            # bind the held input fd to stdin instead of reopening a pathname.
            source_stdin = source.file_descriptor
        else:
            command.append(str(source))
        process = subprocess.Popen(
            command,
            stdin=source_stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=tuple(
                dict.fromkeys(
                    (
                        file_descriptor,
                        *retained_source_fds,
                        *retained_directory_fds,
                    )
                )
            ),
        )
        assert process.stdout is not None
        total = 0
        limit_exceeded = False
        try:
            with destination.open("wb") as sink:
                for chunk in iter(lambda: process.stdout.read(1024 * 1024), b""):
                    total += len(chunk)
                    if total > maximum_bytes:
                        process.kill()
                        limit_exceeded = True
                        break
                    sink.write(chunk)
                sink.flush()
                os.fsync(sink.fileno())
        except BaseException:
            process.kill()
            process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
            process.wait()
            raise
        finally:
            if not process.stdout.closed:
                process.stdout.close()
        stderr = b""
        if process.stderr is not None:
            stderr = process.stderr.read()
            process.stderr.close()
        return_code = process.wait()
        if limit_exceeded:
            raise PackagerError("decompressed tar exceeds contract limit")
        if return_code != 0:
            raise PackagerError(
                "zstd decompression failed: "
                + stderr.decode("utf-8", "replace")[-1024:]
            )
        return total


def run_zstd_compress(
    zstd: Path | RetainedRegularInput,
    zstd_expected: Mapping[str, object],
    source: Path,
    destination: Path,
    compression: Mapping[str, object],
    retained_source_fd: int | None = None,
) -> list[str]:
    flags = [
        "-q",
        "--no-progress",
        "-T1",
        f"-{compression['level']}",
        f"--long={compression['long_distance_matcher_log']}",
        "-c",
    ]
    with destination.open("wb") as sink:
        with pinned_executable(zstd, zstd_expected, "zstd") as (
            executable,
            file_descriptor,
            _,
        ):
            command = [executable, *flags]
            if retained_source_fd is None:
                command.append(str(source))
            completed = subprocess.run(
                command,
                stdin=retained_source_fd,
                stdout=sink,
                stderr=subprocess.PIPE,
                check=False,
                pass_fds=tuple(
                    dict.fromkeys(
                        (
                            file_descriptor,
                            *(() if retained_source_fd is None else (retained_source_fd,)),
                        )
                    )
                ),
            )
        sink.flush()
        os.fsync(sink.fileno())
    if completed.returncode != 0:
        raise PackagerError(
            "zstd compression failed: "
            + completed.stderr.decode("utf-8", "replace")[-1024:]
        )
    return flags


def identify_zstd(
    zstd: Path | RetainedRegularInput, expected: Mapping[str, object]
) -> tuple[dict[str, object], str]:
    with pinned_executable(zstd, expected, "zstd") as (
        executable,
        file_descriptor,
        descriptor,
    ):
        completed = subprocess.run(
            [executable, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            pass_fds=(file_descriptor,),
        )
    if completed.returncode != 0:
        raise PackagerError("unable to identify zstd")
    return descriptor, completed.stdout.strip()


def public_inventory(inspection: Mapping[str, object]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for path, entry in sorted(inspection["entries"].items()):
        item: dict[str, object] = {
            "path": path,
            "type": entry["type"],
            "mode": f"{int(entry['mode']):04o}",
            "bytes": entry["bytes"],
            "sha256": entry["sha256"],
            "digest_scope": entry["digest_scope"],
        }
        if "link_target" in entry:
            item["link_target"] = entry["link_target"]
        result.append(item)
    return result


def compare_inventory(
    expected: Mapping[str, Mapping[str, object]], actual: Mapping[str, object]
) -> None:
    actual_entries = actual["entries"]
    if set(expected) != set(actual_entries):
        raise PackagerError("output tar member set differs from normalized plan")
    fields = ("type", "mode", "bytes", "sha256", "digest_scope", "link_target")
    for path, expected_entry in expected.items():
        actual_entry = actual_entries[path]
        for field in fields:
            if expected_entry.get(field) != actual_entry.get(field):
                raise PackagerError(f"output tar member mismatch: {path}:{field}")


def ensure_distinct_outputs(
    inputs: Sequence[Path | RetainedRegularInput], output: Path, receipt: Path
) -> None:
    if output.exists() or output.is_symlink():
        raise PackagerError("output rootfs already exists; overwrite is forbidden")
    if receipt.exists() or receipt.is_symlink():
        raise PackagerError("receipt already exists; overwrite is forbidden")
    resolved_inputs = {path.resolve() for path in inputs}
    if output.resolve() in resolved_inputs or receipt.resolve() in resolved_inputs:
        raise PackagerError("output and receipt must not alias any input")
    if output.resolve() == receipt.resolve():
        raise PackagerError("output rootfs and receipt must be distinct")


def lexical_absolute(
    path: Path | RetainedRegularInput,
) -> Path | RetainedRegularInput:
    """Make a path absolute without dereferencing its final symlink."""

    if isinstance(path, RetainedRegularInput):
        return path
    return Path(os.path.abspath(os.fspath(path)))


def require_lexical_regular_input(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise PackagerError(f"{label} input is missing") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise PackagerError(f"{label} must be a regular, non-symlink file")


def require_no_symlink_components(path: Path, label: str) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError as error:
            raise PackagerError(f"{label} input is missing") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise PackagerError(f"{label} path contains a symbolic link")


def require_private_input_parent(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise PackagerError(f"{label} parent is missing") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise PackagerError(f"{label} parent is not a directory")
    if metadata.st_uid not in {0, os.geteuid()} or metadata.st_mode & 0o022:
        raise PackagerError(f"{label} parent is not owner-controlled")


def require_real_existing_parent(path: Path, label: str) -> None:
    parent = path.parent
    current = Path(parent.anchor)
    try:
        root_metadata = current.lstat()
    except FileNotFoundError as error:  # pragma: no cover - malformed host root
        raise PackagerError(f"{label} parent does not exist") from error
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise PackagerError(f"{label} parent root is not a real directory")
    for component in parent.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError as error:
            raise PackagerError(
                f"{label} parent must already exist without symlink components"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            raise PackagerError(f"{label} parent contains symlink: {current}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise PackagerError(f"{label} parent component is not a directory: {current}")


def _package_from_retained_inputs(
    args: argparse.Namespace,
    precommit_input_gate: Callable[[], None],
    *,
    packager_script: RetainedRegularInput,
    fresh_base_allowlist: RetainedRegularInput,
    fresh_base_builder: RetainedRegularInput,
    fresh_base_build_contract: RetainedRegularInput,
) -> dict[str, object]:
    contract_path = lexical_absolute(args.contract)
    base_rootfs = lexical_absolute(args.base_rootfs)
    fresh_base_receipt = lexical_absolute(args.fresh_base_receipt)
    fresh_base_sbom = lexical_absolute(args.fresh_base_sbom)
    common_artifact_set_receipt = lexical_absolute(
        args.common_artifact_set_receipt
    )
    common_launcher_ab_receipt = lexical_absolute(
        args.common_launcher_ab_receipt
    )
    daemon = lexical_absolute(args.daemon)
    codex = lexical_absolute(args.codex_binary)
    system_api_tool = lexical_absolute(args.system_api_tool)
    accessibility_tool = lexical_absolute(args.accessibility_tool)
    system_api_replay_sync = lexical_absolute(args.system_api_replay_sync)
    manifest = lexical_absolute(args.agent_manifest)
    zstd = lexical_absolute(args.zstd)
    output_rootfs = lexical_absolute(args.output_rootfs)
    receipt_path = lexical_absolute(args.receipt)
    lexical_inputs = (
        (contract_path, "contract"),
        (base_rootfs, "base_rootfs"),
        (fresh_base_receipt, "fresh_base_receipt"),
        (fresh_base_sbom, "fresh_base_sbom"),
        (common_artifact_set_receipt, "common_artifact_set_receipt"),
        (common_launcher_ab_receipt, "common_launcher_ab_receipt"),
        (daemon, "daemon"),
        (codex, "codex"),
        (system_api_tool, "system_api_tool"),
        (accessibility_tool, "accessibility_tool"),
        (system_api_replay_sync, "system_api_replay_sync"),
        (manifest, "agent_manifest"),
        (zstd, "zstd"),
    )
    for path, label in lexical_inputs:
        require_lexical_regular_input(path, label)
    inputs = (
        contract_path,
        base_rootfs,
        fresh_base_receipt,
        fresh_base_sbom,
        common_artifact_set_receipt,
        common_launcher_ab_receipt,
        daemon,
        codex,
        system_api_tool,
        accessibility_tool,
        system_api_replay_sync,
        manifest,
        zstd,
        packager_script,
        fresh_base_allowlist,
        fresh_base_builder,
        fresh_base_build_contract,
    )
    ensure_distinct_outputs(inputs, output_rootfs, receipt_path)
    require_real_existing_parent(output_rootfs, "output rootfs")
    require_real_existing_parent(receipt_path, "receipt")

    contract_descriptor = describe_regular_input(contract_path, "contract")
    contract, raw_contract = load_contract(contract_path)
    verify_regular_input(contract_path, contract_descriptor, "contract")
    script_descriptor = describe_regular_input(packager_script, "packager")
    input_specs = contract["inputs"]
    base_descriptor = verify_regular_input(
        base_rootfs,
        input_specs["base_rootfs"],
        "base_rootfs",
        require_no_write_bits=True,
    )
    fresh_base_provenance = verify_fresh_base_provenance(
        base_rootfs,
        base_descriptor,
        fresh_base_receipt,
        fresh_base_sbom,
        allowlist_path=fresh_base_allowlist,
        builder_path=fresh_base_builder,
        build_contract_path=fresh_base_build_contract,
    )
    if contract["source_date_epoch"] != fresh_base_provenance["source_date_epoch"]:
        raise PackagerError(
            "final package source_date_epoch must equal the frozen fresh-base epoch"
        )
    daemon_descriptor = verify_regular_input(daemon, input_specs["daemon"], "daemon")
    codex_descriptor = verify_regular_input(codex, input_specs["codex"], "codex")
    system_api_tool_descriptor = verify_regular_input(
        system_api_tool, input_specs["system_api_tool"], "system_api_tool"
    )
    accessibility_tool_descriptor = verify_regular_input(
        accessibility_tool,
        input_specs["accessibility_tool"],
        "accessibility_tool",
    )
    replay_sync_descriptor = verify_regular_input(
        system_api_replay_sync,
        input_specs["system_api_replay_sync"],
        "system_api_replay_sync",
    )
    manifest_descriptor = verify_regular_input(
        manifest, input_specs["agent_manifest"], "agent_manifest"
    )
    common_receipt_descriptor = verify_regular_input(
        common_artifact_set_receipt,
        input_specs["common_artifact_set_receipt"],
        "common artifact-set receipt",
        require_no_write_bits=True,
        require_single_link=True,
    )
    if common_receipt_descriptor["mode"] != "0444":
        raise PackagerError("common artifact-set receipt mode must be 0444")
    launcher_ab_receipt_descriptor = verify_regular_input(
        common_launcher_ab_receipt,
        input_specs["common_launcher_ab_receipt"],
        "common launcher A/B receipt",
        require_no_write_bits=True,
        require_single_link=True,
    )
    if launcher_ab_receipt_descriptor["mode"] != "0444":
        raise PackagerError("common launcher A/B receipt mode must be 0444")
    base_before = stat_fingerprint(base_rootfs)
    max_glibc = contract["runtime"]["max_glibc"]
    daemon_elf = inspect_elf(
        daemon, bool(input_specs["daemon"]["require_static"]), max_glibc, "daemon"
    )
    codex_elf = inspect_elf(
        codex, bool(input_specs["codex"]["require_static"]), max_glibc, "codex"
    )
    system_api_tool_elf = inspect_elf(
        system_api_tool,
        bool(input_specs["system_api_tool"]["require_static"]),
        max_glibc,
        "system_api_tool",
    )
    accessibility_tool_elf = inspect_elf(
        accessibility_tool,
        bool(input_specs["accessibility_tool"]["require_static"]),
        max_glibc,
        "accessibility_tool",
    )
    replay_sync_elf = inspect_elf(
        system_api_replay_sync,
        bool(input_specs["system_api_replay_sync"]["require_static"]),
        max_glibc,
        "system_api_replay_sync",
    )
    manifest_validation = validate_agent_manifest(
        manifest, input_specs["agent_manifest"], str(input_specs["codex"]["sha256"])
    )
    common_receipt_validation = validate_common_artifact_set_receipt(
        common_artifact_set_receipt,
        input_specs["common_artifact_set_receipt"],
        {
            "daemon": daemon_descriptor,
            "codex_launcher": codex_descriptor,
            "system_api_tool": system_api_tool_descriptor,
            "accessibility_tool": accessibility_tool_descriptor,
            "replay_sync_helper": replay_sync_descriptor,
        },
    )
    launcher_ab_validation = validate_common_launcher_ab_receipt(
        common_launcher_ab_receipt,
        input_specs["common_launcher_ab_receipt"],
        common_receipt_descriptor,
        common_receipt_validation,
    )
    receipt_build_evidence = {
        "compiler": common_receipt_validation["compiler"],
        "elf_inspector": common_receipt_validation["elf_inspector"],
        "launcher_ab": launcher_ab_validation,
        "source_bom_claim_authority": json.loads(
            json.dumps(SOURCE_BOM_CLAIM_AUTHORITY)
        ),
        "stable_principal_launcher_measurement": common_receipt_validation[
            "stable_principal_launcher_measurement"
        ],
        "toolchain_claim_authority": json.loads(
            json.dumps(TOOLCHAIN_CLAIM_AUTHORITY)
        ),
        "upstream_receipt_target_compiler_closure_claim": common_receipt_validation[
            "target_compiler_closure"
        ],
        "upstream_receipt_toolchain_snapshot_claim": common_receipt_validation[
            "toolchain_snapshot"
        ],
        "upstream_source_bom_receipt_claim": common_receipt_validation[
            "source_bom"
        ],
    }
    if receipt_build_evidence != contract["common_build_evidence"]:
        raise PackagerError(
            "rootfs v9 common build evidence is not the exact receipt projection"
        )
    if (
        common_receipt_validation["identity_independence_gate"]
        != contract["admission"]["identity_independence_gate"]
    ):
        raise PackagerError(
            "rootfs v9 identity-independence gate is not the exact receipt projection"
        )

    zstd_spec = contract["tools"]["zstd"]
    zstd_descriptor, zstd_version = identify_zstd(zstd, zstd_spec)

    output_parent: RetainedDirectoryChain | None = None
    receipt_parent: RetainedDirectoryChain | None = None
    final_output_parent: RetainedDirectoryChain | None = None
    final_receipt_parent: RetainedDirectoryChain | None = None
    scratch_files: list[RetainedScratchFile] = []
    staged_files: list[RetainedStagedFile] = []
    publication_targets: list[PublicationTarget] = []
    final_publication_checks: list[
        tuple[PublicationTarget, RetainedDirectoryChain]
    ] = []
    receipt: dict[str, object] | None = None
    primary: BaseException | None = None
    try:
        output_parent = RetainedDirectoryChain.open(
            output_rootfs.parent,
            "output rootfs parent",
        )
        receipt_parent = RetainedDirectoryChain.open(
            receipt_path.parent,
            "receipt parent",
        )
        ensure_retained_output_available(
            output_parent,
            output_rootfs.name,
            "output rootfs",
        )
        ensure_retained_output_available(
            receipt_parent,
            receipt_path.name,
            "receipt",
        )
        output_parent_identity = stable_directory_identity(
            os.fstat(output_parent.directory_fd)
        )
        receipt_parent_identity = stable_directory_identity(
            os.fstat(receipt_parent.directory_fd)
        )
        if (
            output_parent_identity == receipt_parent_identity
            and output_rootfs.name == receipt_path.name
        ):
            raise PackagerError("output rootfs and receipt must be distinct")
        # Retain independent parent chains before any public link.  The
        # ordinary chains can then be drained after publication (including
        # fault-injected close hooks) while these chains still provide a held
        # openat route for the final metadata-and-full-digest recheck.
        final_output_parent = RetainedDirectoryChain.open(
            output_rootfs.parent,
            "final-success output rootfs parent",
        )
        final_receipt_parent = RetainedDirectoryChain.open(
            receipt_path.parent,
            "final-success receipt parent",
        )
        if stable_directory_identity(
            os.fstat(final_output_parent.directory_fd)
        ) != output_parent_identity:
            raise PackagerError("output rootfs parent changed during final custody")
        if stable_directory_identity(
            os.fstat(final_receipt_parent.directory_fd)
        ) != receipt_parent_identity:
            raise PackagerError("receipt parent changed during final custody")
        base_tar_owner = RetainedScratchFile.create_anonymous(
            output_parent.directory_fd,
            "decompressed base tar",
        )
        scratch_files.append(base_tar_owner)
        normalized_tar_owner = RetainedScratchFile.create_anonymous(
            output_parent.directory_fd,
            "normalized tar",
        )
        scratch_files.append(normalized_tar_owner)
        staged_rootfs_owner = RetainedScratchFile.create_anonymous(
            output_parent.directory_fd,
            "output rootfs source",
        )
        scratch_files.append(staged_rootfs_owner)
        verify_tar_owner = RetainedScratchFile.create_anonymous(
            output_parent.directory_fd,
            "verification tar",
        )
        scratch_files.append(verify_tar_owner)
        base_tar = base_tar_owner.path
        normalized_tar = normalized_tar_owner.path
        staged_rootfs = staged_rootfs_owner.path
        verify_tar = verify_tar_owner.path
        decompressed_bytes = run_zstd_decompress(
            zstd,
            zstd_spec,
            base_rootfs,
            base_tar,
            int(contract["limits"]["max_decompressed_tar_bytes"]),
        )
        base_inspection = inspect_tar(base_tar, contract)
        payload_paths = {
            str(contract["inputs"][name]["install"]["path"])
            for name in (
                "daemon",
                "codex",
                "system_api_tool",
                "accessibility_tool",
                "system_api_replay_sync",
                "agent_manifest",
            )
        }
        preexisting_payload_paths = sorted(
            payload_paths & set(base_inspection["entries"])
        )
        if preexisting_payload_paths:
            raise PackagerError(
                "fresh base unexpectedly contains final payload paths; "
                "archive hot replacement is forbidden: "
                + ", ".join(preexisting_payload_paths)
            )
        entries, payload_members_added = build_output_entries(
            base_inspection,
            daemon,
            codex,
            system_api_tool,
            accessibility_tool,
            system_api_replay_sync,
            manifest,
            contract,
        )
        write_normalized_tar(
            base_tar,
            normalized_tar,
            entries,
            int(contract["source_date_epoch"]),
            int(contract["limits"]["max_path_bytes"]),
            int(contract["limits"]["max_members"]),
        )
        if normalized_tar.stat().st_size > contract["limits"]["max_decompressed_tar_bytes"]:
            raise PackagerError("normalized tar exceeds decompressed-size contract limit")
        normalized_inspection = inspect_tar(normalized_tar, contract)
        compare_inventory(entries, normalized_inspection)
        compression_flags = run_zstd_compress(
            zstd,
            zstd_spec,
            normalized_tar,
            staged_rootfs,
            contract["compression"],
            normalized_tar_owner.file_descriptor,
        )
        staged_rootfs_input = RetainedStagedFile.adopt_anonymous_scratch(
            staged_rootfs_owner,
            "output rootfs",
            0o444,
        )
        staged_files.append(staged_rootfs_input)
        output_decompressed_bytes = run_zstd_decompress(
            zstd,
            zstd_spec,
            staged_rootfs_input,
            verify_tar,
            int(contract["limits"]["max_decompressed_tar_bytes"]),
        )
        staged_rootfs_input.assert_source_stable(expected_links=0)
        final_inspection = inspect_tar(verify_tar, contract)
        compare_inventory(entries, final_inspection)
        output_decompressed_sha256 = sha256_file(verify_tar)
        if sha256_file(normalized_tar) != output_decompressed_sha256:
            raise PackagerError("compressed output does not round-trip byte-identically")
        android_staging_filter = android_staging_filter_closure(verify_tar)
        if android_staging_filter["bytes"] != output_decompressed_bytes:
            raise PackagerError(
                "Android tar staging filter reproduction changed tar stream length"
            )

        rechecks = (
            (contract_path, contract_descriptor, "contract"),
            (packager_script, script_descriptor, "packager"),
            (
                fresh_base_receipt,
                fresh_base_provenance["receipt"],
                "fresh base receipt",
            ),
            (
                fresh_base_sbom,
                fresh_base_provenance["sbom"],
                "fresh base SPDX SBOM",
            ),
            (daemon, daemon_descriptor, "daemon"),
            (codex, codex_descriptor, "codex"),
            (system_api_tool, system_api_tool_descriptor, "system_api_tool"),
            (
                accessibility_tool,
                accessibility_tool_descriptor,
                "accessibility_tool",
            ),
            (
                system_api_replay_sync,
                replay_sync_descriptor,
                "system_api_replay_sync",
            ),
            (manifest, manifest_descriptor, "agent_manifest"),
            (
                common_artifact_set_receipt,
                common_receipt_descriptor,
                "common artifact-set receipt",
            ),
            (
                common_launcher_ab_receipt,
                launcher_ab_receipt_descriptor,
                "common launcher A/B receipt",
            ),
        )
        for path, descriptor, label in rechecks:
            verify_regular_input(path, descriptor, label)
        verify_regular_input(
            common_artifact_set_receipt,
            common_receipt_descriptor,
            "common artifact-set receipt",
            require_no_write_bits=True,
            require_single_link=True,
        )
        verify_regular_input(
            common_launcher_ab_receipt,
            launcher_ab_receipt_descriptor,
            "common launcher A/B receipt",
            require_no_write_bits=True,
            require_single_link=True,
        )
        verify_regular_input(
            zstd,
            zstd_descriptor,
            "zstd",
            require_no_write_bits=True,
            require_executable=True,
            require_single_link=True,
        )
        verify_regular_input(
            base_rootfs,
            base_descriptor,
            "base_rootfs",
            require_no_write_bits=True,
        )
        if verify_fresh_base_provenance(
            base_rootfs,
            base_descriptor,
            fresh_base_receipt,
            fresh_base_sbom,
            allowlist_path=fresh_base_allowlist,
            builder_path=fresh_base_builder,
            build_contract_path=fresh_base_build_contract,
        ) != fresh_base_provenance:
            raise PackagerError("fresh base provenance changed while packaging")
        if stat_fingerprint(base_rootfs) != base_before:
            raise PackagerError("base_rootfs metadata changed while packaging")

        output_descriptor = {
            "filename": output_rootfs.name,
            "bytes": staged_rootfs_input.initial.st_size,
            "sha256": staged_rootfs_input.sha256,
            "decompressed_tar_bytes": output_decompressed_bytes,
            "decompressed_tar_sha256": output_decompressed_sha256,
            "android_staging_filter": android_staging_filter,
            "member_count": final_inspection["member_count"],
            "total_regular_bytes": final_inspection["total_regular_bytes"],
            "members": public_inventory(final_inspection),
        }
        receipt = {
            "schema": RECEIPT_SCHEMA,
            "decision": CONTRACT_DECISION,
            "status": CONTRACT_STATUS,
            "release_allowed": False,
            "source_date_epoch": contract["source_date_epoch"],
            "admission": contract["admission"],
            "common_build_evidence": contract["common_build_evidence"],
            "limitations": list(PACKAGE_LIMITATIONS),
            "posture": {
                "host_only": True,
                "base_rootfs_mutated": False,
                "fresh_base_only": True,
                "archive_subtraction_or_hot_replacement_performed": False,
                "aosp_vendor_archive_touched": False,
                "device_write_performed": False,
                "ota_signing_performed": False,
                "public_release_allowed": False,
            },
            "packager": script_descriptor,
            "contract": {
                **contract_descriptor,
                "schema": raw_contract["schema"],
            },
            "tools": {
                "zstd": {
                    **zstd_descriptor,
                    "version": zstd_version,
                    "compression_flags": compression_flags,
                    "threads": 1,
                }
            },
            "inputs": {
                "base_rootfs": {
                    **base_descriptor,
                    "decompressed_tar_bytes": decompressed_bytes,
                    "member_count": base_inspection["member_count"],
                    "physical_member_count": base_inspection["physical_member_count"],
                    "total_regular_bytes": base_inspection["total_regular_bytes"],
                    "read_only_input": True,
                    "opened_read_only": True,
                    "filesystem_write_bits_absent": True,
                    "unchanged_after_packaging": True,
                },
                "fresh_base_provenance": fresh_base_provenance,
                "common_artifact_set_receipt": {
                    **common_receipt_descriptor,
                    **common_receipt_validation,
                },
                "common_launcher_ab_receipt": {
                    **launcher_ab_receipt_descriptor,
                    **launcher_ab_validation,
                },
                "daemon": {
                    **daemon_descriptor,
                    "role": "codex_agent_host_daemon",
                    "install_path": input_specs["daemon"]["install"]["path"],
                    "elf": daemon_elf,
                },
                "codex_launcher": {
                    **codex_descriptor,
                    "role": "measured_codex_integrity_launcher",
                    "install_path": input_specs["codex"]["install"]["path"],
                    "codex_runtime_payload_packaged": False,
                    "elf": codex_elf,
                },
                "system_api_tool": {
                    **system_api_tool_descriptor,
                    "role": "android_system_api_effect_tool",
                    "install_path": input_specs["system_api_tool"]["install"][
                        "path"
                    ],
                    "packaged": True,
                    "elf": system_api_tool_elf,
                },
                "accessibility_tool": {
                    **accessibility_tool_descriptor,
                    "role": "android_accessibility_effect_tool",
                    "install_path": input_specs["accessibility_tool"]["install"][
                        "path"
                    ],
                    "packaged": True,
                    "elf": accessibility_tool_elf,
                },
                "system_api_replay_sync": {
                    **replay_sync_descriptor,
                    "role": "android_system_api_replay_synchronizer",
                    "install_path": input_specs["system_api_replay_sync"][
                        "install"
                    ]["path"],
                    "elf": replay_sync_elf,
                },
                "agent_manifest": {
                    **manifest_descriptor,
                    "install_path": input_specs["agent_manifest"]["install"][
                        "path"
                    ],
                    **manifest_validation,
                },
            },
            "runtime_layout": {
                "codex_runtime_bind_placeholder": codex_runtime_placeholder_path(
                    contract
                ),
                "android_effect_tool_paths": list(
                    CODEX_ONLY_ANDROID_EFFECT_TOOL_PATHS
                ),
                "runtime_mount_directories": list(
                    CODEX_ONLY_RUNTIME_MOUNT_DIRECTORIES
                ),
                "placeholder_mode": "0555",
                "placeholder_bytes": 0,
                "placeholder_payloads_present": False,
            },
            "normalization": {
                "member_order": "utf8-path-ascending",
                "uid": 0,
                "gid": 0,
                "uname": "",
                "gname": "",
                "mtime": contract["source_date_epoch"],
                "archive_format": "GNU tar",
                "pax_headers_allowed": False,
                "special_members_allowed": False,
                "fresh_base_member_set_preserved_before_payload_addition": True,
                "legacy_migration_or_prune_performed": False,
                "payload_paths_preexisting_in_base": False,
                "payload_install_write_bits_stripped": True,
                "payload_members_added": payload_members_added,
            },
            "security": {
                "path_escape_check": "PASS",
                "link_escape_check": "PASS",
                "duplicate_member_check": "PASS_NO_UNDECLARED_DUPLICATES",
                "fresh_base_receipt_check": "PASS_EXACT",
                "fresh_base_spdx_check": "PASS_EXACT",
                "legacy_archive_migration_check": "PASS_NOT_USED",
                "special_member_check": "PASS",
                "secret_name_and_content_check": "PASS",
            },
            "reproducibility": {
                "deterministic_tar_metadata": True,
                "single_thread_zstd": True,
                "compressed_round_trip_exact": True,
            },
            "publication": {
                "protocol": "ordered-hard-link-publication-v1",
                "order": ["output_rootfs", "receipt"],
                "atomic_multi_file": False,
                "public_rollback": "forbidden_fail_retain",
                "successful_return_boundary": (
                    "both ordered links created, destination parents fsynced, "
                    "destinations verified, and all retained resources drained"
                ),
                "observer_contract": (
                    "consumers must require both files and verify the receipt-bound "
                    "output digest; a failed invocation may retain a partial prefix"
                ),
            },
            "output_rootfs": output_descriptor,
            "receipt_id_scope": ROOTFS_RECEIPT_ID_SCOPE,
        }
        receipt["receipt_id"] = "sha256:" + sha256_bytes(canonical_json_bytes(receipt))
        staged_receipt_input = RetainedStagedFile.create_bytes(
            receipt_parent.directory_fd,
            "receipt",
            json_bytes(receipt),
            0o444,
        )
        staged_files.append(staged_receipt_input)
        output_target = PublicationTarget(
            staged_rootfs_input,
            output_parent,
            output_rootfs.name,
        )
        receipt_target = PublicationTarget(
            staged_receipt_input,
            receipt_parent,
            receipt_path.name,
        )
        publication_targets.extend((output_target, receipt_target))
        final_publication_checks.extend(
            (
                (output_target, final_output_parent),
                (receipt_target, final_receipt_parent),
            )
        )

        # All semantic output validation and all disposable scratch teardown
        # happen before the final input gate and before any public pathname.
        if not Path("/proc/self/fd").is_dir():
            raise PackagerError("/proc/self/fd is required for retained publication")
        staged_rootfs_input.assert_source_stable(expected_links=0)
        staged_receipt_input.assert_source_stable(expected_links=0)
        output_parent.assert_stable()
        receipt_parent.assert_stable()
        ensure_retained_output_available(
            output_parent,
            output_rootfs.name,
            "output rootfs",
        )
        ensure_retained_output_available(
            receipt_parent,
            receipt_path.name,
            "receipt",
        )
        precommit_cleanup_failures: list[tuple[str, BaseException]] = []
        for scratch in reversed(scratch_files):
            try:
                scratch.close()
            except BaseException as error:
                precommit_cleanup_failures.append(
                    (f"{scratch.label} precommit close", error)
                )
        if precommit_cleanup_failures:
            raise_composite_failure(
                "anonymous scratch precommit cleanup failed",
                None,
                precommit_cleanup_failures,
            )

        # This is the final precommit semantic gate.  The callback also closes
        # every retained input descriptor; a close failure aborts before link.
        precommit_input_gate()

        # Ordered hard links are not a multi-file atomic transaction.  State is
        # recorded immediately after each raw link returns.  Once any result is
        # CREATED or UNKNOWN, later failures are fail-retain and never unlink.
        for target in publication_targets:
            target.link_once()

        fsynced_parent_fds: set[int] = set()
        for target in publication_targets:
            parent_fd = target.destination_parent.directory_fd
            if parent_fd not in fsynced_parent_fds:
                os.fsync(parent_fd)
                fsynced_parent_fds.add(parent_fd)
            target.parent_fsynced = True
        for target in publication_targets:
            target.verify()
        output_parent.assert_stable()
        receipt_parent.assert_stable()
    except BaseException as error:
        primary = error

    cleanup_failures: list[tuple[str, BaseException]] = []
    for staged in reversed(staged_files):
        try:
            staged.close()
        except BaseException as error:
            cleanup_failures.append((f"{staged.label} staged fd close", error))
    for scratch in reversed(scratch_files):
        try:
            scratch.close()
        except BaseException as error:
            cleanup_failures.append((f"{scratch.label} scratch fd close", error))
    # Drain the ordinary parent chains before the final-success check.  An
    # actor synchronized with either staged-fd or parent-chain teardown is
    # therefore observed through the independent custody chains below.
    for label, parent in (
        ("receipt parent", receipt_parent),
        ("output rootfs parent", output_parent),
    ):
        if parent is None:
            continue
        try:
            parent.close()
        except BaseException as error:
            cleanup_failures.append((f"{label} close", error))

    if (
        len(final_publication_checks) == len(publication_targets) == 2
        and all(
            target.state == PublicationTarget.CREATED
            for target, _parent in final_publication_checks
        )
    ):
        for target, parent in final_publication_checks:
            try:
                target.verify_final(parent)
            except BaseException as error:
                cleanup_failures.append(
                    (f"{target.staged.label} final-success recheck", error)
                )

    # These are the last retained namespace resources.  A close failure after
    # publication is diagnostic and fail-retain; no public pathname is ever
    # guessed safe to unlink.
    for label, parent in (
        ("final-success receipt parent", final_receipt_parent),
        ("final-success output rootfs parent", final_output_parent),
    ):
        if parent is None:
            continue
        try:
            parent.close()
        except BaseException as error:
            cleanup_failures.append((f"{label} close", error))

    retained_or_unknown = [
        target
        for target in publication_targets
        if target.state
        in {PublicationTarget.ATTEMPTING_OR_UNKNOWN, PublicationTarget.CREATED}
    ]
    if primary is not None or cleanup_failures:
        if retained_or_unknown:
            raise_retained_publication_failure(
                primary,
                cleanup_failures,
                retained_or_unknown,
            )
        if cleanup_failures:
            raise_composite_failure(
                "rootfs preparation failed and cleanup was incomplete",
                primary,
                cleanup_failures,
            )
        assert primary is not None
        raise primary
    return receipt  # type: ignore[return-value]


RETAINED_PACKAGE_ARGUMENTS = (
    ("contract", "contract"),
    ("base_rootfs", "base_rootfs"),
    ("fresh_base_receipt", "fresh_base_receipt"),
    ("fresh_base_sbom", "fresh_base_sbom"),
    ("common_artifact_set_receipt", "common_artifact_set_receipt"),
    ("common_launcher_ab_receipt", "common_launcher_ab_receipt"),
    ("daemon", "daemon"),
    ("codex_binary", "codex"),
    ("system_api_tool", "system_api_tool"),
    ("accessibility_tool", "accessibility_tool"),
    ("system_api_replay_sync", "system_api_replay_sync"),
    ("agent_manifest", "agent_manifest"),
    ("zstd", "zstd"),
)


def package(args: argparse.Namespace) -> dict[str, object]:
    """Retain every caller-supplied input fd for the complete package run."""

    retained_args = argparse.Namespace(**vars(args))
    retained: list[RetainedRegularInput] = []
    retained_provenance: dict[str, RetainedRegularInput] = {}
    result: dict[str, object] | None = None
    primary: BaseException | None = None

    def close_retained_inputs() -> list[tuple[str, BaseException]]:
        failures: list[tuple[str, BaseException]] = []
        for pinned in reversed(retained):
            try:
                pinned.close()
            except BaseException as error:
                failures.append((f"{pinned.label} retained-input close", error))
        return failures

    try:
        for attribute, label in RETAINED_PACKAGE_ARGUMENTS:
            path = Path(
                os.path.abspath(os.fspath(getattr(args, attribute)))
            )
            require_lexical_regular_input(path, label)
            pinned = open_retained_regular_input(path, label)
            retained.append(pinned)
            setattr(retained_args, attribute, pinned)
        for name, path, label in (
            ("packager_script", Path(__file__).resolve(), "packager"),
            (
                "fresh_base_allowlist",
                FRESH_BASE_ALLOWLIST_PATH,
                "fresh base allowlist",
            ),
            (
                "fresh_base_builder",
                FRESH_BASE_BUILDER_PATH,
                "fresh base builder",
            ),
            (
                "fresh_base_build_contract",
                FRESH_BASE_BUILD_CONTRACT_PATH,
                "fresh base build contract",
            ),
        ):
            pinned = open_retained_regular_input(path, label)
            retained.append(pinned)
            retained_provenance[name] = pinned

        def final_input_gate_and_close() -> None:
            gate_primary: BaseException | None = None
            try:
                for pinned in retained:
                    pinned.assert_stable()
            except BaseException as error:
                gate_primary = error
            close_failures = close_retained_inputs()
            if close_failures:
                raise_composite_failure(
                    "final retained-input gate or teardown failed",
                    gate_primary,
                    close_failures,
                )
            if gate_primary is not None:
                raise gate_primary

        result = _package_from_retained_inputs(
            retained_args,
            final_input_gate_and_close,
            packager_script=retained_provenance["packager_script"],
            fresh_base_allowlist=retained_provenance[
                "fresh_base_allowlist"
            ],
            fresh_base_builder=retained_provenance["fresh_base_builder"],
            fresh_base_build_contract=retained_provenance[
                "fresh_base_build_contract"
            ],
        )
    except BaseException as error:
        primary = error

    cleanup_failures = close_retained_inputs()
    if cleanup_failures:
        if isinstance(primary, RetainedPublicationError):
            details = "; ".join(
                f"{label}: {type(error).__name__}: {error}"
                for label, error in cleanup_failures
            )
            raise RetainedPublicationError(
                f"{primary}; additional input cleanup failures: {details}"
            ) from primary
        raise_composite_failure(
            "rootfs package input cleanup failed",
            primary,
            cleanup_failures,
        )
    if primary is not None:
        raise primary
    return result  # type: ignore[return-value]


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--contract", type=Path, required=True)
    result.add_argument("--base-rootfs", type=Path, required=True)
    result.add_argument("--fresh-base-receipt", type=Path, required=True)
    result.add_argument("--fresh-base-sbom", type=Path, required=True)
    result.add_argument("--common-artifact-set-receipt", type=Path, required=True)
    result.add_argument("--common-launcher-ab-receipt", type=Path, required=True)
    result.add_argument("--daemon", type=Path, required=True)
    result.add_argument("--codex-binary", type=Path, required=True)
    result.add_argument("--system-api-tool", type=Path, required=True)
    result.add_argument("--accessibility-tool", type=Path, required=True)
    result.add_argument("--system-api-replay-sync", type=Path, required=True)
    result.add_argument("--agent-manifest", type=Path, required=True)
    result.add_argument("--zstd", type=Path, required=True)
    result.add_argument("--output-rootfs", type=Path, required=True)
    result.add_argument("--receipt", type=Path, required=True)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    try:
        receipt = package(parser().parse_args(argv))
        print(
            json.dumps(
                {"decision": receipt["decision"], "output": receipt["output_rootfs"]["filename"]},
                sort_keys=True,
            )
        )
        return 0
    except RetainedPublicationError as error:
        print(f"PUBLISH-RETAINED: {error}", file=os.sys.stderr)
        return 3
    except (PackagerError, OSError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(f"DENY: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
