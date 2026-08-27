#!/usr/bin/env python3
"""Build one fixed, host-only Codex ELF lane from a live frozen source graph.

This builder closes the previously loose Rust-ELF input boundary used by the
launcher materializers.  It has exactly two lanes:

* ``common``: inert common System API and Accessibility adapters, the common
  replay-sync helper, and the ordinary fail-closed daemon;
* ``p01_userdebug_pre_daemon``: the separately compiled Settings-only System
  API and replay-sync helpers plus the P0.1 high-water authority.  It never
  builds the final P0.1 daemon.

The supplied source BOM is re-created from the live Android/control/non-Git
trees both before and after compilation and must be byte-identical each time.
The command never mutates a source checkout, launcher input, Android product,
device, signing key, or release pin.  A successful receipt is therefore a
host-build PASS inside an explicit product/device/toolchain-admission HOLD.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Callable, Mapping, Sequence


# Importing the canonical source-BOM materializer must not create an ignored
# ``tools/__pycache__`` entry before the first live graph remeasurement.  Make
# the standalone builder self-contained instead of relying on a caller-owned
# PYTHONDONTWRITEBYTECODE environment variable.
sys.dont_write_bytecode = True


REPOSITORY = Path(__file__).resolve().parents[1]
TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import build_p01_userdebug_agent_launchers as launcher_primitives  # noqa: E402
GIT = Path("/usr/bin/git")
SOURCE_BOM_MATERIALIZER = REPOSITORY / "tools/materialize_cross_repo_source_bom.py"
SOURCE_SET_CONTRACT = REPOSITORY / "tools/p0-cross-repo-source-set.v2.json"
TARGET = "aarch64-unknown-linux-gnu"
HOST_TARGET = "x86_64-unknown-linux-gnu"
SOURCE_DATE_EPOCH = "1785110400"
RECEIPT_SCHEMA = "org.trillionnium.codex-only-raw-elf-set.v3"
RECEIPT_ID_SCOPE = (
    "sha256(canonical-json-utf8-sort-keys-indent-2-lf-without-receipt_id)"
)
SOURCE_BOM_SCHEMA = "org.trillionnium.local-cross-repo-source-bom.v2"
SOURCE_BOM_PASS = "PASS_LOCAL_EXACT_CLEAN_GRAPH"
PASS = "PASS_HOST_ONLY_CODEX_RAW_ELF_SET"
PRODUCT_HOLD = "HOLD_PRODUCT_DEVICE_AND_COMPLETE_TOOLCHAIN_ADMISSION"
MAX_TOOL_BYTES = 512 * 1024 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_TOOL_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_CARGO_OUTPUT_BYTES = 32 * 1024 * 1024
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
NEEDED_RE = re.compile(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]")
BUILD_ID_RE = re.compile(r"Build ID:\s*([0-9a-f]{40})")
GLIBC_VERSION_RE = re.compile(r"Name:\s+GLIBC_([0-9]+)\.([0-9]+)\b")
VERSION_NEED_FILE_RE = re.compile(
    r"Version:\s+1\s+File:\s+(\S+)\s+Cnt:\s+([0-9]+)\s*$"
)
VERSION_NEED_NAME_RE = re.compile(
    r"Name:\s+(\S+)\s+Flags:\s+\S+\s+Version:\s+([0-9]+)\s*$"
)
UNDEFINED_DYNSYM_RE = re.compile(
    r"^\s*[0-9]+:\s+[0-9a-fA-F]+\s+[0-9]+\s+\S+\s+\S+\s+\S+\s+"
    r"UND\s+(\S+)(?:\s+\(([0-9]+)\))?\s*$",
    re.MULTILINE,
)
MAX_GLIBC = (2, 36)
BASE_NEEDED = {"libc.so.6", "libgcc_s.so.1"}
PT_INTERP_LOADER = "ld-linux-aarch64.so.1"
STACK_CHK_GUARD_SYMBOL = "__stack_chk_guard@GLIBC_2.17"
STACK_CHK_GUARD_VERSION = "GLIBC_2.17"
ROLE_NEEDED = {
    "system_api_tool": BASE_NEEDED,
    "accessibility_tool": BASE_NEEDED,
    "replay_sync_helper": BASE_NEEDED,
    "high_water_authority": BASE_NEEDED,
    "daemon": BASE_NEEDED | {"libm.so.6", PT_INTERP_LOADER},
}


class RawElfBuildError(RuntimeError):
    """A closed build input, output, or verification boundary failed."""


@dataclass
class RetainedExecutable:
    """One measured executable held open for the complete build transaction."""

    role: str
    path: Path
    descriptor: int
    initial_metadata: os.stat_result
    initial_bytes: bytes

    @property
    def fd_path(self) -> str:
        if self.descriptor < 0:
            raise RawElfBuildError(f"retained {self.role} executable is already closed")
        return f"/proc/self/fd/{self.descriptor}"

    def close(self) -> None:
        if self.descriptor >= 0:
            descriptor = self.descriptor
            self.descriptor = -1
            os.close(descriptor)


@dataclass(frozen=True)
class CargoInvocation:
    package: str
    bins: tuple[str, ...]
    features: tuple[str, ...] = ()

    def arguments(self) -> tuple[str, ...]:
        result = [
            "build",
            "--locked",
            "--offline",
            "--quiet",
            "--release",
            "--target",
            TARGET,
            "--no-default-features",
            "--package",
            self.package,
        ]
        for binary in self.bins:
            result.extend(("--bin", binary))
        if self.features:
            result.extend(("--features", ",".join(self.features)))
        return tuple(result)


@dataclass(frozen=True)
class ArtifactSpec:
    role: str
    binary: str
    required_markers: tuple[bytes, ...]
    forbidden_markers: tuple[bytes, ...] = ()


@dataclass(frozen=True)
class LaneSpec:
    name: str
    variant: str
    invocations: tuple[CargoInvocation, ...]
    artifacts: tuple[ArtifactSpec, ...]
    receipt_name: str


P01_VARIANT_MARKER = b"org.trillionnium.p01.conformance.compiled-variant.v1=userdebug"
LANES: Mapping[str, LaneSpec] = {
    "common": LaneSpec(
        name="common",
        variant="common_inert_no_default_features",
        invocations=(
            CargoInvocation(
                package="trillionnium-agent-direct-tools",
                bins=(
                    "trillionnium-agent-system-api",
                    "trillionnium-agent-accessibility",
                    "trillionnium-system-api-replay-sync",
                ),
            ),
            CargoInvocation(package="trillionniumd", bins=("trillionniumd",)),
        ),
        artifacts=(
            ArtifactSpec(
                role="system_api_tool",
                binary="trillionnium-agent-system-api",
                required_markers=(b"System API effect lane is not compiled",),
                forbidden_markers=(P01_VARIANT_MARKER,),
            ),
            ArtifactSpec(
                role="accessibility_tool",
                binary="trillionnium-agent-accessibility",
                required_markers=(
                    b"Accessibility effect lane is not compiled",
                    b"org.trillionnium.agent-accessibility.v2",
                    b"snapshot_mode",
                ),
                forbidden_markers=(P01_VARIANT_MARKER,),
            ),
            ArtifactSpec(
                role="replay_sync_helper",
                binary="trillionnium-system-api-replay-sync",
                required_markers=(
                    b"root publication does not match the launched replay-sync identity",
                    b"root publisher requires no arguments and an empty environment",
                ),
                forbidden_markers=(P01_VARIANT_MARKER,),
            ),
            ArtifactSpec(
                role="daemon",
                binary="trillionniumd",
                required_markers=(b"trillionnium.agent-api.uds.v2",),
                forbidden_markers=(P01_VARIANT_MARKER,),
            ),
        ),
        receipt_name="codex-only-raw-elf-set.common.v3.json",
    ),
    "p01_userdebug_pre_daemon": LaneSpec(
        name="p01_userdebug_pre_daemon",
        variant="non_product_userdebug_settings_only_pre_daemon",
        invocations=(
            CargoInvocation(
                package="trillionnium-agent-direct-tools",
                bins=(
                    "trillionnium-agent-system-api-device-conformance",
                    "trillionnium-system-api-device-conformance-replay-sync",
                ),
                features=("device-launch-package-conformance",),
            ),
            CargoInvocation(
                package="trillionnium-agent-privilege-broker",
                bins=("trillionnium-direct-operation-custody-high-water",),
                features=("p0-launch-package-device-conformance",),
            ),
        ),
        artifacts=(
            ArtifactSpec(
                role="system_api_tool",
                binary="trillionnium-agent-system-api-device-conformance",
                required_markers=(
                    P01_VARIANT_MARKER,
                    b"trillionnium.p0-device-conformance-activation-snapshot.v1",
                    b"trillionnium-agent-system-api-p0-1-device-conformance",
                    b"com.android.settings",
                ),
                forbidden_markers=(b"System API effect lane is not compiled",),
            ),
            ArtifactSpec(
                role="replay_sync_helper",
                binary="trillionnium-system-api-device-conformance-replay-sync",
                required_markers=(
                    P01_VARIANT_MARKER,
                    b"trillionnium.p0-replay-sync-ack-confirmation.v1",
                    b"non_product_userdebug_daemon_custody",
                    b"P0-2 sealed replay authority changed before ACTIVATE",
                ),
                forbidden_markers=(
                    b"P0-2 external replay authority unavailable after fixed FD/context",
                ),
            ),
            ArtifactSpec(
                role="high_water_authority",
                binary="trillionnium-direct-operation-custody-high-water",
                required_markers=(
                    b"org.trillionnium.p01.high-water.compiled-variant.v1=userdebug",
                    b"trillionnium.direct-operation-custody-high-water-authority.v2",
                ),
            ),
        ),
        receipt_name="codex-only-raw-elf-set.p01-userdebug-pre-daemon.v3.json",
    ),
}


def _load_source_bom_materializer() -> object:
    specification = importlib.util.spec_from_file_location(
        "trillionnium_cross_repo_source_bom_for_raw_elf",
        SOURCE_BOM_MATERIALIZER,
    )
    if specification is None or specification.loader is None:
        raise RawElfBuildError("cross-repository source BOM materializer is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


SOURCE_BOM = _load_source_bom_materializer()


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


def stable_directory_identity(
    metadata: os.stat_result, *, strict_contents: bool
) -> tuple[int, ...]:
    if strict_contents:
        return stable_identity(metadata)
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
    )


class RetainedAbsoluteDirectory:
    """Hold every component of one absolute directory without following links."""

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
            raise RawElfBuildError(
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
                    raise RawElfBuildError(
                        f"{label} component is unavailable"
                    ) from error
                if not stat.S_ISDIR(lexical.st_mode):
                    raise RawElfBuildError(
                        f"{label} contains a symbolic link or non-directory component"
                    )
                try:
                    descriptor = os.open(component, flags, dir_fd=descriptors[-1])
                except OSError as error:
                    raise RawElfBuildError(
                        f"{label} component cannot be opened without following links"
                    ) from error
                opened = os.fstat(descriptor)
                leaf = len(component_names) + 1 == len(path.parts) - 1
                strict_contents = leaf and not allow_leaf_content_changes
                if stable_directory_identity(
                    opened, strict_contents=strict_contents
                ) != stable_directory_identity(
                    lexical, strict_contents=strict_contents
                ):
                    os.close(descriptor)
                    raise RawElfBuildError(f"{label} component changed while opened")
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
            leaf = index == len(self.descriptors) - 1
            strict_contents = leaf and not self.allow_leaf_content_changes
            held = os.fstat(descriptor)
            if stable_directory_identity(
                held, strict_contents=strict_contents
            ) != stable_directory_identity(
                expected, strict_contents=strict_contents
            ):
                raise RawElfBuildError(f"{self.label} retained directory changed")
            if index == 0:
                continue
            try:
                current = os.stat(
                    self.component_names[index - 1],
                    dir_fd=self.descriptors[index - 1],
                    follow_symlinks=False,
                )
            except OSError as error:
                raise RawElfBuildError(
                    f"{self.label} retained pathname disappeared"
                ) from error
            if stable_directory_identity(
                current, strict_contents=strict_contents
            ) != stable_directory_identity(
                expected, strict_contents=strict_contents
            ):
                raise RawElfBuildError(f"{self.label} retained pathname changed")

    def close(self) -> None:
        first_error: OSError | None = None
        for descriptor in reversed(self.descriptors):
            try:
                os.close(descriptor)
            except OSError as error:
                if first_error is None:
                    first_error = error
        self.descriptors.clear()
        if first_error is not None:
            raise first_error


class RetainedPublishedFile:
    """One exclusively-created output held through the final publication gate."""

    def __init__(
        self,
        directory: int,
        name: str,
        descriptor: int,
        metadata: os.stat_result,
        initial_bytes: bytes,
        mode: int,
    ) -> None:
        self.directory = directory
        self.name = name
        self.descriptor = descriptor
        self.initial_metadata = metadata
        self.initial_bytes = initial_bytes
        self.mode = mode

    @staticmethod
    def _read_exact(descriptor: int, maximum: int) -> bytes:
        chunks: list[bytes] = []
        offset = 0
        while offset <= maximum:
            block = os.pread(
                descriptor,
                min(1024 * 1024, maximum + 1 - offset),
                offset,
            )
            if not block:
                break
            chunks.append(block)
            offset += len(block)
        return b"".join(chunks)

    def assert_stable(self) -> None:
        if self.descriptor < 0:
            raise RawElfBuildError(f"published output {self.name} is already closed")
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
            raise RawElfBuildError(
                f"published output {self.name} pathname changed"
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
            or stat.S_IMODE(current.st_mode) != self.mode
        ):
            raise RawElfBuildError(
                f"published output {self.name} descriptor, pathname, or bytes changed"
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


def strict_regular_bytes(
    path: Path,
    label: str,
    maximum: int,
    *,
    require_single_link: bool = True,
) -> tuple[bytes, os.stat_result]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise RawElfBuildError("host lacks required O_NOFOLLOW support")
    try:
        descriptor = os.open(absolute, os.O_RDONLY | os.O_CLOEXEC | nofollow)
    except OSError as error:
        raise RawElfBuildError(f"{label} is unavailable or is a symlink") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink < 1
            or (require_single_link and before.st_nlink != 1)
            or not 1 <= before.st_size <= maximum
        ):
            raise RawElfBuildError(f"{label} is not one bounded regular file")
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
            raise RawElfBuildError(f"{label} changed while read")
    finally:
        os.close(descriptor)
    try:
        current = os.lstat(absolute)
    except OSError as error:
        raise RawElfBuildError(f"{label} pathname disappeared") from error
    if stat.S_ISLNK(current.st_mode) or stable_identity(current) != stable_identity(before):
        raise RawElfBuildError(f"{label} pathname changed while read")
    return b"".join(chunks), before


def strict_json_object(raw: bytes, label: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise RawElfBuildError(f"{label} contains duplicate key {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda item: (_ for _ in ()).throw(
                RawElfBuildError(f"{label} contains non-finite number {item}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RawElfBuildError(f"{label} is not strict UTF-8 JSON") from error
    if type(value) is not dict:
        raise RawElfBuildError(f"{label} must be a JSON object")
    return value


def absolute_existing_directory(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        metadata = os.lstat(absolute)
        resolved = absolute.resolve(strict=True)
    except OSError as error:
        raise RawElfBuildError(f"{label} is unavailable") from error
    if not stat.S_ISDIR(metadata.st_mode) or absolute.is_symlink():
        raise RawElfBuildError(f"{label} must be a real directory")
    return resolved


def open_private_empty_directory(
    path: Path, label: str
) -> tuple[Path, int, os.stat_result, RetainedAbsoluteDirectory]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    custody = RetainedAbsoluteDirectory.open(
        absolute,
        label,
        allow_leaf_content_changes=True,
    )
    descriptor = custody.descriptor
    metadata = custody.initial_metadata
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        custody.close()
        raise RawElfBuildError(f"{label} must be an invoking-user-owned 0700 directory")
    try:
        names = os.listdir(descriptor)
    except OSError:
        custody.close()
        raise
    if names:
        custody.close()
        raise RawElfBuildError(f"{label} must be empty")
    custody.assert_stable()
    return absolute, descriptor, metadata, custody


def require_empty_input_directory(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow or not hasattr(os, "O_DIRECTORY"):
        raise RawElfBuildError("host lacks required no-follow directory support")
    try:
        descriptor = os.open(
            absolute,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | nofollow,
        )
    except OSError as error:
        raise RawElfBuildError(f"{label} is unavailable or is a symlink") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or os.listdir(descriptor)
        ):
            raise RawElfBuildError(
                f"{label} must be invoking-user-owned, non-group-writable, and empty"
            )
    finally:
        os.close(descriptor)
    return absolute.resolve(strict=True)


def ensure_distinct_outside_inputs(
    output: Path,
    target: Path,
    roots: Sequence[Path],
) -> None:
    if output == target:
        raise RawElfBuildError("output and Cargo target directories must be distinct")
    for candidate, candidate_label in ((output, "output"), (target, "Cargo target")):
        for root in roots:
            try:
                candidate.relative_to(root)
            except ValueError:
                continue
            raise RawElfBuildError(
                f"{candidate_label} directory must be outside every measured input root"
            )
    for parent, child in ((output, target), (target, output)):
        try:
            child.relative_to(parent)
        except ValueError:
            continue
        raise RawElfBuildError("output and Cargo target directories may not contain each other")


def validate_source_bom_receipt(value: dict[str, object], raw: bytes) -> dict[str, object]:
    if value.get("schema") != SOURCE_BOM_SCHEMA or value.get("decision") != SOURCE_BOM_PASS:
        raise RawElfBuildError("source BOM is not the canonical v2 clean-graph PASS")
    if value.get("blockers") != [] or value.get("artifacts") != []:
        raise RawElfBuildError("source BOM contains blockers or previously built artifacts")
    posture = value.get("posture")
    if type(posture) is not dict or any(
        posture.get(field) is not expected
        for field, expected in {
            "local_only": True,
            "signed": False,
            "build_authorized": False,
            "release_pin_published": False,
            "device_write_authorized": False,
            "ota_authorized": False,
        }.items()
    ):
        raise RawElfBuildError("source BOM authority posture is invalid")
    receipt_id = value.get("receipt_id")
    if type(receipt_id) is not str or not receipt_id.startswith("sha256:"):
        raise RawElfBuildError("source BOM receipt id is malformed")
    preimage = dict(value)
    preimage.pop("receipt_id", None)
    expected = "sha256:" + sha256_bytes(canonical_json_bytes(preimage))
    if receipt_id != expected or canonical_json_bytes(value) != raw:
        raise RawElfBuildError("source BOM is not canonical or its receipt id differs")
    source_set = value.get("source_set")
    resolved_manifest = value.get("resolved_manifest")
    if type(source_set) is not dict or type(resolved_manifest) is not dict:
        raise RawElfBuildError("source BOM omits its source-set or manifest binding")
    source_set_sha256 = source_set.get("sha256")
    resolved_manifest_sha256 = resolved_manifest.get("sha256")
    if (
        type(source_set_sha256) is not str
        or LOWER_SHA256.fullmatch(source_set_sha256) is None
        or type(resolved_manifest_sha256) is not str
        or LOWER_SHA256.fullmatch(resolved_manifest_sha256) is None
    ):
        raise RawElfBuildError("source BOM source-set or manifest digest is malformed")
    return {
        "schema": SOURCE_BOM_SCHEMA,
        "decision": SOURCE_BOM_PASS,
        "bytes": len(raw),
        "sha256": sha256_bytes(raw),
        "receipt_id": receipt_id,
        "source_set_sha256": source_set_sha256,
        "resolved_manifest_sha256": resolved_manifest_sha256,
        "live_full_remeasurement_before_and_after_build": True,
        "byte_equal_to_each_live_remeasurement": True,
        "authority": "local_source_measurement_not_release_authority",
    }


def remeasure_source_bom(
    expected_raw: bytes,
    *,
    android_root: Path,
    control_root: Path,
    artifact_root: Path,
    resolved_manifest: Path,
    measure: Callable[..., dict[str, object]] | None = None,
) -> None:
    measure_function = measure if measure is not None else SOURCE_BOM.measure
    try:
        measured = measure_function(
            SOURCE_SET_CONTRACT,
            android_root,
            control_root,
            artifact_root,
            resolved_manifest,
        )
        measured_raw = SOURCE_BOM.canonical_json_bytes(measured)
    except Exception as error:
        raise RawElfBuildError("live cross-repository source BOM remeasurement failed") from error
    if measured_raw != expected_raw:
        raise RawElfBuildError("live source graph differs byte-for-byte from the supplied BOM")


def _retained_executable_bytes(tool: RetainedExecutable) -> bytes:
    try:
        before = os.fstat(tool.descriptor)
    except OSError as error:
        raise RawElfBuildError(f"retained {tool.role} executable is unavailable") from error
    chunks: list[bytes] = []
    offset = 0
    while offset < before.st_size:
        try:
            chunk = os.pread(
                tool.descriptor,
                min(1024 * 1024, before.st_size - offset),
                offset,
            )
        except OSError as error:
            raise RawElfBuildError(
                f"retained {tool.role} executable could not be read"
            ) from error
        if not chunk:
            break
        chunks.append(chunk)
        offset += len(chunk)
    try:
        after = os.fstat(tool.descriptor)
    except OSError as error:
        raise RawElfBuildError(f"retained {tool.role} executable disappeared") from error
    if (
        offset != before.st_size
        or stable_identity(before) != stable_identity(after)
        or stable_identity(after) != stable_identity(tool.initial_metadata)
    ):
        raise RawElfBuildError(f"retained {tool.role} executable changed while read")
    return b"".join(chunks)


def _require_original_executable_path(tool: RetainedExecutable) -> None:
    try:
        current = os.lstat(tool.path)
    except OSError as error:
        raise RawElfBuildError(
            f"{tool.role} original pathname disappeared during the build"
        ) from error
    if (
        stat.S_ISLNK(current.st_mode)
        or stable_identity(current) != stable_identity(tool.initial_metadata)
    ):
        raise RawElfBuildError(
            f"{tool.role} original pathname changed during the build"
        )


def open_retained_executable(path: Path, label: str) -> RetainedExecutable:
    absolute = Path(os.path.abspath(os.fspath(path)))
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow or not Path("/proc/self/fd").is_dir():
        raise RawElfBuildError(
            "host lacks required no-follow /proc/self/fd executable custody"
        )
    try:
        descriptor = os.open(absolute, os.O_RDONLY | os.O_CLOEXEC | nofollow)
    except OSError as error:
        raise RawElfBuildError(f"{label} is unavailable or is a symlink") from error
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= MAX_TOOL_BYTES
            or not mode & stat.S_IXUSR
            or mode & 0o022
        ):
            raise RawElfBuildError(
                f"{label} must be one bounded executable and not group/other writable"
            )
        tool = RetainedExecutable(
            role=label,
            path=absolute,
            descriptor=descriptor,
            initial_metadata=metadata,
            initial_bytes=b"",
        )
        raw = _retained_executable_bytes(tool)
        _require_original_executable_path(tool)
        if raw[:4] != b"\x7fELF":
            raise RawElfBuildError(
                f"{label} must be a direct measured ELF executable; shell/env wrappers "
                "require an independently closed interpreter and utility TCB"
            )
        tool.initial_bytes = raw
        return tool
    except BaseException:
        os.close(descriptor)
        raise


def retained_executable_record(tool: RetainedExecutable) -> dict[str, object]:
    return {
        "path": str(tool.path),
        "bytes": len(tool.initial_bytes),
        "sha256": sha256_bytes(tool.initial_bytes),
        "mode": f"{stat.S_IMODE(tool.initial_metadata.st_mode):04o}",
    }


def revalidate_retained_executable(tool: RetainedExecutable) -> None:
    if _retained_executable_bytes(tool) != tool.initial_bytes:
        raise RawElfBuildError(f"{tool.role} retained bytes changed during the build")
    _require_original_executable_path(tool)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        reopened = os.open(tool.path, os.O_RDONLY | os.O_CLOEXEC | nofollow)
    except OSError as error:
        raise RawElfBuildError(
            f"{tool.role} original pathname could not be reopened after the build"
        ) from error
    try:
        reopened_metadata = os.fstat(reopened)
        if stable_identity(reopened_metadata) != stable_identity(tool.initial_metadata):
            raise RawElfBuildError(
                f"{tool.role} original pathname no longer names the retained executable"
            )
    finally:
        os.close(reopened)
    _require_original_executable_path(tool)


def close_retained_executables(tools: Sequence[RetainedExecutable]) -> None:
    first_error: OSError | None = None
    for tool in reversed(tuple(tools)):
        try:
            tool.close()
        except OSError as error:
            if first_error is None:
                first_error = error
    if first_error is not None and sys.exc_info()[0] is None:
        raise RawElfBuildError("could not close every retained executable") from first_error


def validate_executable(path: Path, label: str) -> tuple[Path, dict[str, object], bytes]:
    """Compatibility helper for callers that only need one immediate measurement."""

    tool = open_retained_executable(path, label)
    try:
        return tool.path, retained_executable_record(tool), tool.initial_bytes
    finally:
        tool.close()


def run_bounded(
    command: Sequence[str],
    *,
    env: Mapping[str, str],
    cwd: Path | None,
    maximum: int,
    timeout: int,
    label: str,
    executable: str | None = None,
    pass_fds: Sequence[int] = (),
) -> bytes:
    try:
        result = subprocess.run(
            list(command),
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=timeout,
            executable=executable,
            pass_fds=tuple(pass_fds),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RawElfBuildError(f"{label} could not complete") from error
    if len(result.stdout) > maximum:
        raise RawElfBuildError(f"{label} output exceeds its bound")
    if result.returncode != 0:
        excerpt = result.stdout[-4096:].decode("utf-8", errors="replace")
        raise RawElfBuildError(f"{label} failed: {excerpt}")
    return result.stdout


def run_retained_bounded(
    tool: RetainedExecutable,
    arguments: Sequence[str],
    *,
    env: Mapping[str, str],
    cwd: Path | None,
    maximum: int,
    timeout: int,
    label: str,
    inherited_tools: Sequence[RetainedExecutable] = (),
) -> bytes:
    tools: list[RetainedExecutable] = []
    observed_descriptors: set[int] = set()
    for candidate in (tool, *inherited_tools):
        if candidate.descriptor in observed_descriptors:
            continue
        observed_descriptors.add(candidate.descriptor)
        tools.append(candidate)
    for candidate in tools:
        if (
            stable_identity(os.fstat(candidate.descriptor))
            != stable_identity(candidate.initial_metadata)
        ):
            raise RawElfBuildError(
                f"retained {candidate.role} metadata changed before {label}"
            )
        _require_original_executable_path(candidate)
    result = run_bounded(
        (str(tool.path), *arguments),
        env=env,
        cwd=cwd,
        maximum=maximum,
        timeout=timeout,
        label=label,
        executable=tool.fd_path,
        pass_fds=tuple(candidate.descriptor for candidate in tools),
    )
    for candidate in tools:
        if (
            stable_identity(os.fstat(candidate.descriptor))
            != stable_identity(candidate.initial_metadata)
        ):
            raise RawElfBuildError(
                f"retained {candidate.role} metadata changed during {label}"
            )
        _require_original_executable_path(candidate)
    return result


def derive_control_root() -> Path:
    raw = run_bounded(
        (str(GIT), "-C", str(REPOSITORY), "rev-parse", "--show-toplevel"),
        env={"LANG": "C", "LC_ALL": "C", "TZ": "UTC", "PATH": ""},
        cwd=None,
        maximum=4096,
        timeout=30,
        label="control Git top-level query",
    )
    top = normalized_tool_output(raw, "control Git top-level query")
    try:
        root = Path(top).resolve(strict=True)
        REPOSITORY.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as error:
        raise RawElfBuildError("control Git top level does not contain this source tree") from error
    return root


def normalized_tool_output(raw: bytes, label: str) -> str:
    try:
        value = raw.decode("utf-8")
    except UnicodeError as error:
        raise RawElfBuildError(f"{label} output is not UTF-8") from error
    value = value.replace("\r\n", "\n").rstrip("\n")
    if not value or "\x00" in value:
        raise RawElfBuildError(f"{label} output is empty or malformed")
    return value


def path_within(path: Path, root: Path, label: str) -> None:
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise RawElfBuildError(f"{label} is outside its explicit toolchain root") from error


def reject_ambient_cargo_configuration(control_root: Path, cargo_home: Path) -> None:
    candidates = [control_root, *control_root.parents]
    for root in candidates:
        for name in ("config", "config.toml"):
            candidate = root / ".cargo" / name
            if candidate.exists() or candidate.is_symlink():
                raise RawElfBuildError(
                    "ambient Cargo configuration outside the fixed command is forbidden"
                )
    for name in ("config", "config.toml"):
        candidate = cargo_home / name
        if candidate.exists() or candidate.is_symlink():
            raise RawElfBuildError("Cargo home configuration is forbidden in the closed lane")


def inspect_toolchain(
    args: argparse.Namespace,
    toolchain_snapshot: dict[str, object],
) -> tuple[dict[str, object], dict[str, RetainedExecutable]]:
    rust_root = absolute_existing_directory(args.rust_toolchain_root, "Rust toolchain root")
    target_root = absolute_existing_directory(args.target_toolchain_root, "target toolchain root")
    explicit_target_sysroot = absolute_existing_directory(
        args.target_sysroot, "target sysroot"
    )
    if explicit_target_sysroot.parent != target_root:
        raise RawElfBuildError(
            "target sysroot is outside the exact lane snapshot layout"
        )
    cargo_home = absolute_existing_directory(args.cargo_home, "Cargo home")
    cargo_home_metadata = os.stat(cargo_home, follow_symlinks=False)
    if cargo_home_metadata.st_uid != os.geteuid() or stat.S_IMODE(cargo_home_metadata.st_mode) & 0o022:
        raise RawElfBuildError("Cargo home must be invoking-user-owned and not group/other writable")
    records: dict[str, dict[str, object]] = {}
    tools: dict[str, RetainedExecutable] = {}
    try:
        for name, candidate in {
            "cargo": args.cargo,
            "rustc": args.rustc,
            "host_linker": args.host_linker,
            "linker": args.linker,
            "ar": args.ar,
            "readelf": args.readelf,
        }.items():
            tool = open_retained_executable(candidate, name)
            tools[name] = tool
            records[name] = retained_executable_record(tool)
        path_within(tools["cargo"].path, rust_root, "cargo")
        path_within(tools["rustc"].path, rust_root, "rustc")
        host_root = Path(args.host_toolchain_root).resolve(strict=True)
        path_within(tools["host_linker"].path, host_root, "host_linker")
        for name in ("linker", "ar", "readelf"):
            path_within(tools[name].path, target_root, name)

        target_host_runtime_libdir = Path(
            os.path.abspath(os.fspath(args.target_host_runtime_libdir))
        )
        host_tool_env = {
            "LC_ALL": "C",
            "LANG": "C",
            "TZ": "UTC",
            "PATH": "",
        }
        target_tool_env = {
            **host_tool_env,
            "LD_LIBRARY_PATH": str(target_host_runtime_libdir),
        }
        version_arguments = {
            "cargo": ("--version", "--verbose"),
            "rustc": ("-vV",),
            "host_linker": ("--version",),
            "linker": ("--version",),
            "ar": ("--version",),
            "readelf": ("--version",),
        }
        for name, arguments in version_arguments.items():
            output = run_retained_bounded(
                tools[name],
                arguments,
                env=(
                    target_tool_env
                    if name in {"linker", "ar", "readelf"}
                    else host_tool_env
                ),
                cwd=None,
                maximum=MAX_TOOL_OUTPUT_BYTES,
                timeout=30,
                label=f"{name} identity query",
            )
            records[name]["version"] = normalized_tool_output(
                output, f"{name} identity query"
            )

        rust_sysroot = normalized_tool_output(
            run_retained_bounded(
                tools["rustc"],
                ("--print", "sysroot"),
                env=host_tool_env,
                cwd=None,
                maximum=4096,
                timeout=30,
                label="rustc sysroot query",
            ),
            "rustc sysroot query",
        )
        try:
            observed_rust_root = Path(rust_sysroot).resolve(strict=True)
        except OSError as error:
            raise RawElfBuildError("rustc reported an unavailable sysroot") from error
        if observed_rust_root != rust_root:
            raise RawElfBuildError("rustc sysroot differs from the explicit Rust toolchain root")
        target_libdir = normalized_tool_output(
            run_retained_bounded(
                tools["rustc"],
                ("--target", TARGET, "--print", "target-libdir"),
                env=host_tool_env,
                cwd=None,
                maximum=4096,
                timeout=30,
                label="rustc target libdir query",
            ),
            "rustc target libdir query",
        )
        try:
            target_libdir_path = Path(target_libdir).resolve(strict=True)
            target_libdir_path.relative_to(rust_root)
        except (OSError, ValueError) as error:
            raise RawElfBuildError(
                "Rust target libdir is outside the explicit toolchain"
            ) from error

        compiler_bin = Path(os.path.abspath(os.fspath(args.target_compiler_bin)))
        gcc_libdir = Path(os.path.abspath(os.fspath(args.target_gcc_libdir)))
        binutils_dir = Path(os.path.abspath(os.fspath(args.target_binutils_dir)))
        host_runtime_libdir = target_host_runtime_libdir
        expected_layout = {
            "target_sysroot": Path(args.toolchain_manifest).absolute().parent
            / "toolchain/sysroot",
            "target_compiler_bin": Path(args.toolchain_manifest).absolute().parent
            / "toolchain/sysroot/usr/bin",
            "target_gcc_libdir": Path(args.toolchain_manifest).absolute().parent
            / "toolchain/sysroot/usr/lib/gcc-cross/aarch64-linux-gnu/12",
            "target_binutils_dir": Path(args.toolchain_manifest).absolute().parent
            / "toolchain/sysroot/usr/aarch64-linux-gnu/bin",
            "target_host_runtime_libdir": Path(args.toolchain_manifest).absolute().parent
            / "toolchain/sysroot/usr/lib/x86_64-linux-gnu",
        }
        if {
            "target_sysroot": explicit_target_sysroot,
            "target_compiler_bin": compiler_bin,
            "target_gcc_libdir": gcc_libdir,
            "target_binutils_dir": binutils_dir,
            "target_host_runtime_libdir": host_runtime_libdir,
        } != expected_layout:
            raise RawElfBuildError(
                "target compiler/sysroot layout differs from the bound lane snapshot"
            )
        expected_target_tools = {
            "linker": compiler_bin / "aarch64-linux-gnu-gcc-12",
            "ar": compiler_bin / "aarch64-linux-gnu-ar",
            "readelf": compiler_bin / "aarch64-linux-gnu-readelf",
        }
        for role, expected_path in expected_target_tools.items():
            if tools[role].path != expected_path:
                raise RawElfBuildError(
                    f"selected {role} is not the exact lane snapshot executable"
                )
        target_prefix_arguments = (
            f"--sysroot={explicit_target_sysroot}",
            f"-B{compiler_bin}",
            f"-B{gcc_libdir}",
            f"-B{binutils_dir}",
        )
        target_tool_env = {**host_tool_env, "LD_LIBRARY_PATH": str(host_runtime_libdir)}
        linker_sysroot = normalized_tool_output(
            run_retained_bounded(
                tools["linker"],
                (*target_prefix_arguments, "-print-sysroot"),
                env=target_tool_env,
                cwd=None,
                maximum=4096,
                timeout=30,
                label="target linker sysroot query",
            ),
            "target linker sysroot query",
        )
        try:
            if (
                Path(linker_sysroot).resolve(strict=True)
                != explicit_target_sysroot.resolve(strict=True)
            ):
                raise RawElfBuildError(
                    "target linker sysroot differs from the explicit target sysroot"
                )
        except OSError as error:
            raise RawElfBuildError("target sysroot is unavailable") from error

        resolved_components: dict[str, dict[str, object]] = {}
        for label, query in {
            "ld": "-print-prog-name=ld",
            "as": "-print-prog-name=as",
            "cc1": "-print-prog-name=cc1",
            "collect2": "-print-prog-name=collect2",
            "Scrt1.o": "-print-file-name=Scrt1.o",
            "crtbeginS.o": "-print-file-name=crtbeginS.o",
            "libc.so": "-print-file-name=libc.so",
            "libgcc_s.so.1": "-print-file-name=libgcc_s.so.1",
            "libgcc.a": "-print-file-name=libgcc.a",
        }.items():
            queried = normalized_tool_output(
                run_retained_bounded(
                    tools["linker"],
                    (*target_prefix_arguments, query),
                    env=target_tool_env,
                    cwd=None,
                    maximum=4096,
                    timeout=30,
                    label=f"target linker {label} query",
                ),
                f"target linker {label} query",
            )
            try:
                resolved = Path(queried).resolve(strict=True)
                relative = resolved.relative_to(explicit_target_sysroot.resolve(strict=True))
            except (OSError, ValueError) as error:
                raise RawElfBuildError(
                    f"target linker {label} escapes the closed-world snapshot"
                ) from error
            component, component_metadata = strict_regular_bytes(
                resolved, f"target linker {label}", MAX_TOOL_BYTES
            )
            resolved_components[label] = {
                "relative_path": relative.as_posix(),
                "bytes": len(component),
                "sha256": sha256_bytes(component),
                "mode": f"0{stat.S_IMODE(component_metadata.st_mode):o}",
            }

        return (
            {
                "boundary": (
                    "exact_selected_executables_retained_from_initial_measurement_through_"
                    "query_build_and_inspection_via_proc_self_fd_and_reported_sysroots; "
                    "the_bound_Mobian_snapshot_is_manifest_closed_and_fully_remeasured_"
                    "before_and_after_build; host_kernel_process_interpreter_fallback_"
                    "glibc_libm_libz_and_Rust_Cargo_source_closure_are_not_fully_attested"
                ),
                "cargo_home": str(cargo_home),
                "rust_toolchain_root": str(rust_root),
                "rust_target_libdir": str(target_libdir_path),
                "target_toolchain_root": str(target_root),
                "host_toolchain_root": str(host_root),
                "target_sysroot": str(explicit_target_sysroot.resolve(strict=True)),
                "target_search_prefixes": {
                    "compiler_bin": str(compiler_bin),
                    "gcc_libdir": str(gcc_libdir),
                    "binutils_dir": str(binutils_dir),
                    "host_runtime_libdir": str(host_runtime_libdir),
                },
                "snapshot_manifest": dict(toolchain_snapshot),
                "resolved_components": resolved_components,
                "executables": records,
                "input_remeasurement_after_build_required": True,
                "snapshot_tree_fully_remeasured_before_and_after_build": True,
                "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed": False,
                "complete_release_toolchain_closure": False,
            },
            tools,
        )
    except BaseException:
        close_retained_executables(tuple(tools.values()))
        raise


def build_environment(
    *,
    lane: LaneSpec,
    target_dir: Path,
    cargo_home: Path,
    rust_toolchain_root: Path,
    cargo: RetainedExecutable,
    rustc: RetainedExecutable,
    host_linker: RetainedExecutable,
    linker: RetainedExecutable,
    ar: RetainedExecutable,
    readelf: RetainedExecutable,
    android_root: Path,
    artifact_root: Path,
    resolved_manifest: Path,
    output_dir: Path,
    target_sysroot: Path,
    target_compiler_bin: Path,
    target_gcc_libdir: Path,
    target_binutils_dir: Path,
    target_host_runtime_libdir: Path,
) -> dict[str, str]:
    # Resolve every retained path while all six descriptors are live. Cargo
    # itself and readelf are invoked directly by run_retained_bounded; rustc,
    # the linker and ar are invoked by Cargo/rustc and therefore must be named
    # through inherited descriptor paths in the child environment.
    _direct_fd_paths = (cargo.fd_path, readelf.fd_path)
    rustc_fd_path = rustc.fd_path
    host_linker_fd_path = host_linker.fd_path
    linker_fd_path = linker.fd_path
    ar_fd_path = ar.fd_path
    remaps = (
        (REPOSITORY, "/usr/src/trillionnium-os"),
        (target_dir, "/usr/src/trillionnium-target"),
        (cargo_home, "/usr/src/trillionnium-cargo-home"),
        (rust_toolchain_root, "/usr/src/trillionnium-rust-toolchain"),
        (android_root, "/usr/src/trillionnium-android"),
        (artifact_root, "/usr/src/trillionnium-empty-artifacts"),
        (resolved_manifest.parent, "/usr/src/trillionnium-manifest-parent"),
        (output_dir, "/usr/src/trillionnium-raw-elf-output"),
    )
    rust_flags = [
        "-C",
        "debuginfo=0",
        "-C",
        "strip=symbols",
        "-C",
        "codegen-units=1",
        "-C",
        "relocation-model=pic",
        "-C",
        f"linker={linker_fd_path}",
        "-C",
        f"link-arg=--sysroot={target_sysroot}",
        "-C",
        f"link-arg=-B{target_compiler_bin}",
        "-C",
        f"link-arg=-B{target_gcc_libdir}",
        "-C",
        f"link-arg=-B{target_binutils_dir}",
        "-C",
        "link-arg=-pie",
        "-C",
        "link-arg=-Wl,--as-needed,-z,relro,-z,now,-z,noexecstack,--build-id=sha1",
    ]
    for source, replacement in remaps:
        rust_flags.extend(("--remap-path-prefix", f"{source}={replacement}"))
    environment = {
        "AR_aarch64_unknown_linux_gnu": ar_fd_path,
        "CARGO_BUILD_JOBS": "1",
        "CARGO_CACHE_RUSTC_INFO": "0",
        "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(rust_flags),
        "CARGO_HOME": str(cargo_home),
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": host_linker_fd_path,
        "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_AR": ar_fd_path,
        "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER": linker_fd_path,
        "CARGO_TARGET_DIR": str(target_dir),
        "CC_x86_64_unknown_linux_gnu": host_linker_fd_path,
        "CC_aarch64_unknown_linux_gnu": linker_fd_path,
        "CFLAGS_aarch64_unknown_linux_gnu": " ".join(
            (
                f"--sysroot={target_sysroot}",
                f"-B{target_compiler_bin}",
                f"-B{target_gcc_libdir}",
                f"-B{target_binutils_dir}",
            )
        ),
        "CXXFLAGS_aarch64_unknown_linux_gnu": " ".join(
            (
                f"--sysroot={target_sysroot}",
                f"-B{target_compiler_bin}",
                f"-B{target_gcc_libdir}",
                f"-B{target_binutils_dir}",
            )
        ),
        "LANG": "C",
        "LC_ALL": "C",
        "LD_LIBRARY_PATH": str(target_host_runtime_libdir),
        "NUM_JOBS": "1",
        "PATH": "",
        "RUSTC": rustc_fd_path,
        "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
        "TZ": "UTC",
    }
    if lane.name == "p01_userdebug_pre_daemon":
        environment["TRILLIONNIUM_P01_CONFORMANCE_BUILD_VARIANT"] = "userdebug"
    return environment


def validate_aarch64_elf_header(value: bytes, label: str) -> None:
    if (
        len(value) < 64
        or value[:4] != b"\x7fELF"
        or value[4] != 2
        or value[5] != 1
        or int.from_bytes(value[16:18], "little") != 3
        or int.from_bytes(value[18:20], "little") != 183
    ):
        raise RawElfBuildError(f"{label} is not an AArch64 little-endian ELF64 PIE")


def validate_artifact_markers(value: bytes, specification: ArtifactSpec) -> None:
    for marker in specification.required_markers:
        if marker not in value:
            raise RawElfBuildError(
                f"{specification.role} omits required lane marker {marker!r}"
            )
    for marker in specification.forbidden_markers:
        if marker in value:
            raise RawElfBuildError(
                f"{specification.role} retains forbidden lane marker {marker!r}"
            )
    folded = value.lower()
    for token in (
        b"open" + b"claw",
        b"open_" + b"claw",
        b"agent-open" + b"claw-direct-v1",
    ):
        if token in folded:
            raise RawElfBuildError(f"{specification.role} retains a retired Agent identity")


def validate_no_path_leaks(value: bytes, paths: Sequence[Path], label: str) -> None:
    for path in paths:
        encoded = os.fsencode(path)
        if encoded not in {b"", b"/"} and encoded in value:
            raise RawElfBuildError(f"{label} contains an unremapped host path")


def parse_version_need_providers(output: str, label: str) -> dict[int, tuple[str, str]]:
    providers: dict[int, tuple[str, str]] = {}
    current_file: str | None = None
    remaining = 0
    for line in output.splitlines():
        file_match = VERSION_NEED_FILE_RE.search(line)
        if file_match is not None:
            if remaining != 0:
                raise RawElfBuildError(f"{label} has malformed version-provider evidence")
            current_file = file_match.group(1)
            remaining = int(file_match.group(2))
            if remaining <= 0:
                raise RawElfBuildError(f"{label} has malformed version-provider evidence")
            continue
        name_match = VERSION_NEED_NAME_RE.search(line)
        if name_match is None or current_file is None:
            continue
        version_index = int(name_match.group(2))
        if version_index in providers:
            raise RawElfBuildError(f"{label} repeats one version-provider index")
        providers[version_index] = (current_file, name_match.group(1))
        remaining -= 1
        if remaining == 0:
            current_file = None
    if remaining != 0:
        raise RawElfBuildError(f"{label} has truncated version-provider evidence")
    return providers


def validate_stack_guard_loader_binding(
    output: str,
    label: str,
    *,
    loader_needed: bool,
    allow_loader_for_stack_guard: bool,
) -> dict[str, object]:
    absent: dict[str, object] = {
        "loader_dt_needed": False,
        "undefined_dynamic_symbol": None,
        "version": None,
        "version_provider": None,
        "loader_bound_undefined_symbols": [],
    }
    providers = parse_version_need_providers(output, label)
    undefined_symbols = [
        (symbol, int(index) if index else None)
        for symbol, index in UNDEFINED_DYNSYM_RE.findall(output)
    ]
    loader_versions = {
        index: version
        for index, (provider, version) in providers.items()
        if provider == PT_INTERP_LOADER
    }
    loader_bound = [
        symbol
        for symbol, index in undefined_symbols
        if index is not None
        and providers.get(index, (None, None))[0] == PT_INTERP_LOADER
    ]
    guard_symbols = [
        (symbol, index)
        for symbol, index in undefined_symbols
        if symbol == "__stack_chk_guard" or symbol.startswith("__stack_chk_guard@")
    ]

    if not loader_needed:
        if loader_versions or loader_bound or guard_symbols:
            raise RawElfBuildError(
                f"{label} has stack-guard loader evidence without loader DT_NEEDED"
            )
        return absent
    if not allow_loader_for_stack_guard:
        raise RawElfBuildError(
            f"{label} incorrectly retains the PT_INTERP loader as DT_NEEDED"
        )
    if (
        len(loader_versions) != 1
        or next(iter(loader_versions.values())) != STACK_CHK_GUARD_VERSION
        or len(guard_symbols) != 1
        or guard_symbols[0][0] != STACK_CHK_GUARD_SYMBOL
        or guard_symbols[0][1] not in loader_versions
        or loader_bound != [STACK_CHK_GUARD_SYMBOL]
    ):
        raise RawElfBuildError(
            f"{label} loader DT_NEEDED is not exclusively bound to "
            f"{STACK_CHK_GUARD_SYMBOL}"
        )
    return {
        "loader_dt_needed": True,
        "undefined_dynamic_symbol": STACK_CHK_GUARD_SYMBOL,
        "version": STACK_CHK_GUARD_VERSION,
        "version_provider": PT_INTERP_LOADER,
        "loader_bound_undefined_symbols": [STACK_CHK_GUARD_SYMBOL],
    }


def parse_and_validate_readelf(
    output: str,
    label: str,
    *,
    allowed_needed: frozenset[str] | set[str] = BASE_NEEDED,
    allow_loader_for_stack_guard: bool = False,
) -> dict[str, object]:
    required = (
        "Class:                             ELF64",
        "Data:                              2's complement, little endian",
        "Type:                              DYN",
        "Machine:                           AArch64",
        "Requesting program interpreter: /lib/ld-linux-aarch64.so.1",
        "GNU_RELRO",
    )
    for marker in required:
        if marker not in output:
            raise RawElfBuildError(f"{label} readelf evidence omits {marker!r}")
    stack_lines = [line for line in output.splitlines() if line.lstrip().startswith("GNU_STACK")]
    if len(stack_lines) != 1 or " E " in f" {stack_lines[0]} " or " RWE " in stack_lines[0]:
        raise RawElfBuildError(f"{label} does not have exactly one non-executable GNU stack")
    load_lines = [line for line in output.splitlines() if line.lstrip().startswith("LOAD")]
    if not load_lines or any("W" in line and "E" in line for line in load_lines):
        raise RawElfBuildError(f"{label} has an absent or writable-executable LOAD segment")
    if "BIND_NOW" not in output and "Flags: NOW" not in output:
        raise RawElfBuildError(f"{label} lacks immediate relocation binding")
    if any(token in output for token in ("(RPATH)", "(RUNPATH)", "(TEXTREL)")):
        raise RawElfBuildError(f"{label} retains RPATH, RUNPATH, or text relocations")
    if re.search(r"\]\s+\.debug(?:_|\s)", output) is not None:
        raise RawElfBuildError(f"{label} retains a debug section")
    needed = NEEDED_RE.findall(output)
    needed_set = set(needed)
    stack_guard = validate_stack_guard_loader_binding(
        output,
        label,
        loader_needed=PT_INTERP_LOADER in needed_set,
        allow_loader_for_stack_guard=allow_loader_for_stack_guard,
    )
    if (
        len(needed) != len(needed_set)
        or not BASE_NEEDED <= needed_set
        or not needed_set <= set(allowed_needed)
    ):
        raise RawElfBuildError(f"{label} has an unexpected shared-library dependency closure")
    build_ids = BUILD_ID_RE.findall(output)
    if len(build_ids) != 1:
        raise RawElfBuildError(f"{label} lacks one SHA-1 GNU build id")
    if "GLIBC_PRIVATE" in output:
        raise RawElfBuildError(f"{label} requires the private GLIBC ABI")
    glibc_versions = {
        (int(major), int(minor)) for major, minor in GLIBC_VERSION_RE.findall(output)
    }
    if not glibc_versions or max(glibc_versions) > MAX_GLIBC:
        raise RawElfBuildError(f"{label} exceeds the fixed GLIBC_2.36 ABI ceiling")
    return {
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
        "needed": needed,
        "aarch64_stack_protector_guard": stack_guard,
        "required_glibc_versions": [
            f"GLIBC_{major}.{minor}" for major, minor in sorted(glibc_versions)
        ],
        "maximum_glibc": f"GLIBC_{max(glibc_versions)[0]}.{max(glibc_versions)[1]}",
        "gnu_build_id_sha1": build_ids[0],
    }


def inspect_artifact(
    path: Path,
    specification: ArtifactSpec,
    *,
    readelf: RetainedExecutable,
    environment: Mapping[str, str],
    leaked_paths: Sequence[Path],
) -> tuple[bytes, dict[str, object]]:
    # Cargo publishes each top-level executable as a hardlink to its hashed
    # artifact under ``deps/``. Both names are created inside the fresh,
    # caller-owned 0700 target directory. Accept that native layout here while
    # retaining no-follow inode/ctime/mtime/size checks across both reads and
    # the external inspector. Every published output below is still a new
    # single-link 0555 file.
    value, _metadata = strict_regular_bytes(
        path,
        specification.role,
        MAX_ARTIFACT_BYTES,
        require_single_link=False,
    )
    validate_aarch64_elf_header(value, specification.role)
    validate_artifact_markers(value, specification)
    validate_no_path_leaks(value, leaked_paths, specification.role)
    readelf_raw = run_retained_bounded(
        readelf,
        (
            "--file-header",
            "--program-headers",
            "--dynamic",
            "--section-headers",
            "--notes",
            "--version-info",
            "--dyn-syms",
            "--wide",
            str(path),
        ),
        env=environment,
        cwd=None,
        maximum=MAX_TOOL_OUTPUT_BYTES,
        timeout=30,
        label=f"readelf inspection for {specification.role}",
    )
    readelf_text = normalized_tool_output(readelf_raw, f"readelf {specification.role}")
    # Close the path-to-bytes race across the external inspector.
    after, _ = strict_regular_bytes(
        path,
        specification.role,
        MAX_ARTIFACT_BYTES,
        require_single_link=False,
    )
    if after != value:
        raise RawElfBuildError(f"{specification.role} changed while inspected")
    hardening = parse_and_validate_readelf(
        readelf_text,
        specification.role,
        allowed_needed=ROLE_NEEDED[specification.role],
        allow_loader_for_stack_guard=specification.role == "daemon",
    )
    return value, {
        "file": specification.binary,
        "bytes": len(value),
        "sha256": sha256_bytes(value),
        "mode": "0555",
        "link_count": 1,
        "hardening": hardening,
        "lane_markers_verified": True,
        "unremapped_host_paths_absent": True,
        "retired_agent_identity_absent": True,
    }


def write_exclusive_at(
    directory: int, name: str, value: bytes, mode: int
) -> RetainedPublishedFile:
    if not name or "/" in name or name in {".", ".."}:
        raise RawElfBuildError("output name is not one fixed path component")
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
    )
    completed = False
    try:
        descriptor = os.open(name, flags, mode, dir_fd=directory)
    except OSError as error:
        raise RawElfBuildError(f"cannot publish output {name}") from error
    try:
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RawElfBuildError(f"short write while publishing {name}")
            view = view[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_size != len(value)
        ):
            raise RawElfBuildError(f"published output {name} boundary differs")
        retained = RetainedPublishedFile(
            directory,
            name,
            descriptor,
            metadata,
            value,
            mode,
        )
        retained.assert_stable()
        completed = True
        return retained
    finally:
        if not completed:
            os.close(descriptor)


def assert_closed_publication(
    directory: int,
    custody: RetainedAbsoluteDirectory,
    expected_names: set[str],
    published: Sequence[RetainedPublishedFile],
) -> None:
    custody.assert_stable()
    observed = os.listdir(directory)
    if len(observed) != len(expected_names) or set(observed) != expected_names:
        raise RawElfBuildError("output directory inventory is not the exact published set")
    if {item.name for item in published} != expected_names:
        raise RawElfBuildError("retained output set differs from the expected publication")
    for item in published:
        item.assert_stable()
    custody.assert_stable()


def close_published_files(published: Sequence[RetainedPublishedFile]) -> None:
    first_error: OSError | None = None
    for item in reversed(tuple(published)):
        try:
            item.close()
        except OSError as error:
            if first_error is None:
                first_error = error
    if first_error is not None and sys.exc_info()[0] is None:
        raise RawElfBuildError("could not close every retained published output") from first_error


def cleanup_published_files(published: Sequence[RetainedPublishedFile]) -> None:
    first_error: OSError | None = None
    for item in reversed(tuple(published)):
        try:
            item.unlink_if_current()
        except OSError as error:
            if first_error is None:
                first_error = error
    if first_error is not None and sys.exc_info()[0] is None:
        raise RawElfBuildError("could not clean failed published outputs") from first_error


def command_receipt(invocation: CargoInvocation) -> list[str]:
    return ["$CARGO", *invocation.arguments()]


def finalize_receipt(receipt: dict[str, object]) -> bytes:
    if "receipt_id" in receipt:
        raise RawElfBuildError("receipt preimage already contains receipt_id")
    receipt["receipt_id_scope"] = RECEIPT_ID_SCOPE
    receipt["receipt_id"] = "sha256:" + sha256_bytes(canonical_json_bytes(receipt))
    return canonical_json_bytes(receipt)


def build(args: argparse.Namespace) -> dict[str, object]:
    lane = LANES[args.lane]
    output, output_fd, _output_initial, output_custody = open_private_empty_directory(
        args.output_dir, "output directory"
    )
    try:
        target, target_fd, _target_initial, target_custody = open_private_empty_directory(
            args.target_dir, "Cargo target directory"
        )
        retained_tools: dict[str, RetainedExecutable] = {}
        published: list[RetainedPublishedFile] = []
        publication_succeeded = False
        try:
            android_root = absolute_existing_directory(args.android_root, "Android root")
            artifact_root = require_empty_input_directory(args.artifact_root, "artifact root")
            control_root = derive_control_root()
            resolved_manifest = Path(os.path.abspath(os.fspath(args.resolved_manifest)))
            source_bom_path = Path(os.path.abspath(os.fspath(args.source_bom)))
            resolved_manifest_raw, _ = strict_regular_bytes(
                resolved_manifest, "resolved manifest", 64 * 1024 * 1024
            )
            source_bom_raw, _ = strict_regular_bytes(
                source_bom_path, "source BOM", 512 * 1024 * 1024
            )
            source_bom_value = strict_json_object(source_bom_raw, "source BOM")
            source_bom_binding = validate_source_bom_receipt(source_bom_value, source_bom_raw)
            if source_bom_binding["resolved_manifest_sha256"] != sha256_bytes(
                resolved_manifest_raw
            ):
                raise RawElfBuildError(
                    "resolved manifest bytes differ from the supplied source BOM"
                )
            source_set_raw, _ = strict_regular_bytes(
                SOURCE_SET_CONTRACT, "source-set contract", 2 * 1024 * 1024
            )
            if source_bom_binding["source_set_sha256"] != sha256_bytes(source_set_raw):
                raise RawElfBuildError("source-set contract differs from the supplied BOM")
            ensure_distinct_outside_inputs(
                output,
                target,
                (android_root, artifact_root, control_root),
            )
            remeasure_source_bom(
                source_bom_raw,
                android_root=android_root,
                control_root=control_root,
                artifact_root=artifact_root,
                resolved_manifest=resolved_manifest,
            )

            toolchain_snapshot, toolchain_manifest_before = (
                launcher_primitives.verify_toolchain_snapshot_binding(
                    args.toolchain_manifest
                )
            )
            toolchain, retained_tools = inspect_toolchain(args, toolchain_snapshot)
            cargo_home = Path(str(toolchain["cargo_home"]))
            rust_toolchain_root = Path(str(toolchain["rust_toolchain_root"]))
            reject_ambient_cargo_configuration(REPOSITORY.resolve(strict=True), cargo_home)
            environment = build_environment(
                lane=lane,
                target_dir=target,
                cargo_home=cargo_home,
                rust_toolchain_root=rust_toolchain_root,
                cargo=retained_tools["cargo"],
                rustc=retained_tools["rustc"],
                host_linker=retained_tools["host_linker"],
                linker=retained_tools["linker"],
                ar=retained_tools["ar"],
                readelf=retained_tools["readelf"],
                android_root=android_root,
                artifact_root=artifact_root,
                resolved_manifest=resolved_manifest,
                output_dir=output,
                target_sysroot=Path(args.target_sysroot).absolute(),
                target_compiler_bin=Path(args.target_compiler_bin).absolute(),
                target_gcc_libdir=Path(args.target_gcc_libdir).absolute(),
                target_binutils_dir=Path(args.target_binutils_dir).absolute(),
                target_host_runtime_libdir=Path(
                    args.target_host_runtime_libdir
                ).absolute(),
            )

            old_umask = os.umask(0o077)
            try:
                for index, invocation in enumerate(lane.invocations):
                    run_retained_bounded(
                        retained_tools["cargo"],
                        invocation.arguments(),
                        env=environment,
                        cwd=REPOSITORY.resolve(strict=True),
                        maximum=MAX_CARGO_OUTPUT_BYTES,
                        timeout=args.timeout_seconds,
                        label=f"Cargo invocation {index + 1} for {lane.name}",
                        inherited_tools=(
                            retained_tools["rustc"],
                            retained_tools["host_linker"],
                            retained_tools["linker"],
                            retained_tools["ar"],
                        ),
                    )
            finally:
                os.umask(old_umask)

            leaked_paths = (
                control_root,
                target,
                output,
                cargo_home,
                rust_toolchain_root,
                android_root,
                artifact_root,
                resolved_manifest,
            )
            artifact_bytes: dict[str, bytes] = {}
            artifact_records: dict[str, object] = {}
            release_dir = target / TARGET / "release"
            for specification in lane.artifacts:
                artifact, record = inspect_artifact(
                    release_dir / specification.binary,
                    specification,
                    readelf=retained_tools["readelf"],
                    environment=environment,
                    leaked_paths=leaked_paths,
                )
                artifact_bytes[specification.role] = artifact
                artifact_records[specification.role] = record

            resolved_manifest_after, _ = strict_regular_bytes(
                resolved_manifest, "resolved manifest", 64 * 1024 * 1024
            )
            if resolved_manifest_after != resolved_manifest_raw:
                raise RawElfBuildError("resolved manifest changed during the build")
            source_bom_after, _ = strict_regular_bytes(
                source_bom_path, "source BOM", 512 * 1024 * 1024
            )
            if source_bom_after != source_bom_raw:
                raise RawElfBuildError("source BOM changed during the build")
            require_empty_input_directory(artifact_root, "artifact root")
            remeasure_source_bom(
                source_bom_raw,
                android_root=android_root,
                control_root=control_root,
                artifact_root=artifact_root,
                resolved_manifest=resolved_manifest,
            )
            toolchain_snapshot_after, toolchain_manifest_after = (
                launcher_primitives.verify_toolchain_snapshot_binding(
                    args.toolchain_manifest
                )
            )
            if (
                toolchain_snapshot_after != toolchain_snapshot
                or toolchain_manifest_after != toolchain_manifest_before
            ):
                raise RawElfBuildError("toolchain snapshot changed during the build")

            receipt: dict[str, object] = {
                "schema": RECEIPT_SCHEMA,
                "decision": PASS,
                "release_status": PRODUCT_HOLD,
                "lane": lane.name,
                "variant": lane.variant,
                "target": TARGET,
                "profile": "release",
                "source_date_epoch": int(SOURCE_DATE_EPOCH),
                "source_bom": source_bom_binding,
                "build": {
                    "commands": [command_receipt(item) for item in lane.invocations],
                    "locked": True,
                    "offline": True,
                    "no_default_features": True,
                    "jobs": 1,
                    "incremental": False,
                    "fresh_private_target_directory": True,
                    "path_remapping": True,
                    "p01_compile_variant": (
                        "userdebug" if lane.name == "p01_userdebug_pre_daemon" else None
                    ),
                    "target_native_compile_flags": [
                        "--sysroot=$TARGET_SYSROOT",
                        "-B$TARGET_COMPILER_BIN",
                        "-B$TARGET_GCC_LIBDIR",
                        "-B$TARGET_BINUTILS_DIR",
                    ],
                },
                "toolchain": toolchain,
                "artifacts": artifact_records,
                "posture": {
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
                },
                "limitations": [
                    "cargo_home_and_rust_target_source_trees_are_explicit_but_not_recursively_byte_closed",
                    "closed_world_mobian_toolchain_snapshot_is_manifest_bound_and_fully_remeasured_before_and_after_build",
                    "host_process_interpreter_and_fallback_glibc_libm_libz_are_not_byte_closed",
                    "host_kernel_and_filesystem_snapshot_are_not_attested",
                    "source_measurement_python_and_git_runtime_dependencies_are_not_byte_closed",
                    "shell_or_env_tool_wrappers_are_rejected_until_their_interpreter_utility_tcb_is_closed",
                    "two_boundary_source_remeasurement_cannot_exclude_transient_between-boundary_mutation",
                    "no_launcher_rootfs_android_device_avb_or_ota_evidence",
                ],
            }
            receipt_bytes = finalize_receipt(receipt)

            # The open file descriptions used for every direct query/build/
            # inspection and inherited Cargo child path must still contain the
            # initially measured bytes and metadata. Each original absolute
            # pathname must still name that same inode immediately before
            # publication. This closes selected-tool TOCTOU without claiming
            # recursive compiler/sysroot closure.
            for tool in retained_tools.values():
                revalidate_retained_executable(tool)
            target_custody.assert_stable()
            output_custody.assert_stable()

            # Publication occurs only after both complete live source-graph
            # measurements and every artifact/tool check have passed.
            for specification in lane.artifacts:
                published.append(
                    write_exclusive_at(
                        output_fd,
                        specification.binary,
                        artifact_bytes[specification.role],
                        0o555,
                    )
                )
            published.append(
                write_exclusive_at(output_fd, lane.receipt_name, receipt_bytes, 0o444)
            )
            expected_names = {
                lane.receipt_name,
                *(specification.binary for specification in lane.artifacts),
            }
            assert_closed_publication(
                output_fd,
                output_custody,
                expected_names,
                published,
            )
            os.fsync(output_fd)
            assert_closed_publication(
                output_fd,
                output_custody,
                expected_names,
                published,
            )
            target_custody.assert_stable()
            publication_succeeded = True
            return receipt
        finally:
            try:
                if not publication_succeeded:
                    cleanup_published_files(published)
            finally:
                try:
                    close_published_files(published)
                finally:
                    try:
                        close_retained_executables(tuple(retained_tools.values()))
                    finally:
                        target_custody.close()
    finally:
        output_custody.close()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lane", choices=tuple(LANES), required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--source-bom", type=Path, required=True)
    parser.add_argument("--android-root", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--resolved-manifest", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--host-linker", type=Path, required=True)
    parser.add_argument("--linker", type=Path, required=True)
    parser.add_argument("--ar", type=Path, required=True)
    parser.add_argument("--readelf", type=Path, required=True)
    parser.add_argument("--cargo-home", type=Path, required=True)
    parser.add_argument("--rust-toolchain-root", type=Path, required=True)
    parser.add_argument("--target-toolchain-root", type=Path, required=True)
    parser.add_argument("--host-toolchain-root", type=Path, required=True)
    parser.add_argument("--target-sysroot", type=Path, required=True)
    parser.add_argument("--toolchain-manifest", type=Path, required=True)
    parser.add_argument("--target-compiler-bin", type=Path, required=True)
    parser.add_argument("--target-gcc-libdir", type=Path, required=True)
    parser.add_argument("--target-binutils-dir", type=Path, required=True)
    parser.add_argument("--target-host-runtime-libdir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=3600)
    args = parser.parse_args(argv)
    if not 1 <= args.timeout_seconds <= 14_400:
        parser.error("--timeout-seconds must be in 1..=14400")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    try:
        receipt = build(parse_args(argv))
    except RawElfBuildError as error:
        print(f"Codex raw ELF build error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, allow_nan=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
