#!/usr/bin/env python3
"""Fail-closed target-files contract for the Root Linux tar staging filter.

The normal mode consumes a real target-files ZIP or directory.  It verifies the
installed AArch64 ELF against its generated identity receipt, verifies the
final fs_config ownership/modes, and parses both the installed text and the
compiled SELinux file-context databases.  Static source checks are available
only through the explicit ``--source-only`` HOLD mode.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tempfile
import unittest
import warnings
import zipfile


TEST_FILE = Path(__file__).resolve()
DEFAULT_VENDOR_ROOT = TEST_FILE.parents[3]

HELPER_BASENAME = "trillionnium_rootfs_tar_staging_filter"
HELPER_ARTIFACT = f"SYSTEM_EXT/bin/{HELPER_BASENAME}"
IDENTITY_BASENAME = "rootfs-tar-staging-filter.identity.v1"
IDENTITY_ARTIFACT = (
    f"SYSTEM_EXT/etc/trillionnium/linux/{IDENTITY_BASENAME}"
)
FILESYSTEM_CONFIG_ARTIFACT = "META/system_ext_filesystem_config.txt"
TEXT_FILE_CONTEXTS_ARTIFACT = (
    "SYSTEM_EXT/etc/selinux/system_ext_file_contexts"
)
COMPILED_FILE_CONTEXTS_ARTIFACT = "META/file_contexts.bin"

HELPER_FS_PATH = f"system_ext/bin/{HELPER_BASENAME}"
IDENTITY_FS_PATH = (
    f"system_ext/etc/trillionnium/linux/{IDENTITY_BASENAME}"
)
HELPER_DEVICE_PATH = f"/system_ext/bin/{HELPER_BASENAME}"
EXPECTED_CONTEXT_REGEX = (
    rf"/(system_ext|system/system_ext)/bin/{HELPER_BASENAME}"
)
EXPECTED_CONTEXT = "u:object_r:trillionnium_rootlinux_exec:s0"
EXPECTED_SOURCE_SHA256 = (
    "dc48c9ce97f1e64a62e45d00350b44801adb7cc0f60f8666b1d5e87696ce6092"
)
EXPECTED_IDENTITY_SCHEMA = (
    "org.trillionnium.rootfs-tar-staging-filter.identity.v1"
)
EXPECTED_BUILD_VARIANTS = "eng,user,userdebug"

IDENTITY_KEYS = (
    "schema",
    "path",
    "sha256",
    "size",
    "owner",
    "mode",
    "selinux_label",
    "source_sha256",
    "build_variants",
)

REQUIRED_ARTIFACT_LIMITS = {
    HELPER_ARTIFACT: 32 * 1024 * 1024,
    IDENTITY_ARTIFACT: 64 * 1024,
    FILESYSTEM_CONFIG_ARTIFACT: 64 * 1024 * 1024,
    TEXT_FILE_CONTEXTS_ARTIFACT: 64 * 1024 * 1024,
    COMPILED_FILE_CONTEXTS_ARTIFACT: 128 * 1024 * 1024,
}
MAX_ZIP_ENTRIES = 500_000
MAX_COMPILED_STEMS = 100_000
MAX_COMPILED_SPECS = 500_000
COMPILED_FCONTEXT_MAGIC = 0xF97CFF8A
COMPILED_FCONTEXT_VERSION = 5


class ContractError(RuntimeError):
    """A fail-closed contract violation."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_member_name(raw: str) -> str:
    if not raw or "\x00" in raw or "\\" in raw or raw.startswith("/"):
        raise ContractError(f"unsafe target-files member name: {raw!r}")
    parts = raw.split("/")
    if parts[-1] == "":
        parts.pop()
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ContractError(f"ambiguous target-files member name: {raw!r}")
    return "/".join(parts)


def _path_parts(path: Path) -> tuple[Path, tuple[str, ...]]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.is_absolute() or absolute.anchor != "/":
        raise ContractError(f"path is not an absolute POSIX path: {path}")
    parts = absolute.parts[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ContractError(f"unsafe input path: {absolute}")
    return absolute, parts


def _open_absolute_nofollow(path: Path, *, directory: bool) -> tuple[int, Path]:
    absolute, parts = _path_parts(path)
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    current_fd = os.open("/", directory_flags)
    try:
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            flags = os.O_RDONLY | os.O_CLOEXEC | nofollow
            if not final or directory:
                flags |= os.O_DIRECTORY
            next_fd = os.open(part, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd, absolute
    except OSError as error:
        os.close(current_fd)
        raise ContractError(
            f"cannot open without following links: {absolute}: {error}"
        ) from error


def _stable_file_tuple(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_fd_bounded(fd: int, limit: int, label: str) -> bytes:
    metadata_before = os.fstat(fd)
    if not stat.S_ISREG(metadata_before.st_mode):
        raise ContractError(f"{label} is not a regular file")
    if metadata_before.st_nlink != 1:
        raise ContractError(f"{label} is hard-linked")
    if metadata_before.st_size < 0 or metadata_before.st_size > limit:
        raise ContractError(
            f"{label} size {metadata_before.st_size} exceeds {limit} bytes"
        )
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        chunk = os.read(fd, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    metadata_after = os.fstat(fd)
    if len(data) > limit:
        raise ContractError(f"{label} exceeded its bounded read limit")
    if len(data) != metadata_before.st_size:
        raise ContractError(f"{label} changed size during verification")
    if _stable_file_tuple(metadata_before) != _stable_file_tuple(metadata_after):
        raise ContractError(f"{label} mutated during verification")
    return data


def read_regular_path(path: Path, limit: int, label: str) -> bytes:
    fd, absolute = _open_absolute_nofollow(path, directory=False)
    try:
        return _read_fd_bounded(fd, limit, f"{label} ({absolute})")
    finally:
        os.close(fd)


class DirectoryTargetFiles:
    def __init__(self, path: Path):
        self._root_fd, self.path = _open_absolute_nofollow(path, directory=True)
        self._observed: dict[tuple[int, int], tuple[int, tuple[int, ...], str]] = {}
        self._observe(self._root_fd, ".")

    def _observe(self, fd: int, label: str) -> None:
        metadata = os.fstat(fd)
        identity = (metadata.st_dev, metadata.st_ino)
        snapshot = _stable_file_tuple(metadata)
        previous = self._observed.get(identity)
        if previous is not None:
            if previous[1] != snapshot:
                raise ContractError(f"target-files directory mutated at {label}")
            return
        self._observed[identity] = (os.dup(fd), snapshot, label)

    def close(self) -> None:
        violation: ContractError | None = None
        for held_fd, snapshot, label in self._observed.values():
            try:
                if _stable_file_tuple(os.fstat(held_fd)) != snapshot:
                    violation = ContractError(
                        f"target-files directory tree mutated at {label}"
                    )
            finally:
                os.close(held_fd)
        self._observed.clear()
        if self._root_fd >= 0:
            os.close(self._root_fd)
            self._root_fd = -1
        if violation is not None:
            raise violation

    def __enter__(self) -> "DirectoryTargetFiles":
        return self

    def __exit__(self, *_unused: object) -> None:
        self.close()

    def read(self, name: str, limit: int) -> bytes:
        canonical = _canonical_member_name(name)
        if canonical != name:
            raise ContractError(f"non-canonical required artifact path: {name}")
        parts = canonical.split("/")
        directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        current_fd = os.dup(self._root_fd)
        try:
            self._observe(current_fd, ".")
            traversed: list[str] = []
            for part in parts[:-1]:
                traversed.append(part)
                next_fd = os.open(
                    part,
                    directory_flags | nofollow,
                    dir_fd=current_fd,
                )
                os.close(current_fd)
                current_fd = next_fd
                self._observe(current_fd, "/".join(traversed))
            file_fd = os.open(
                parts[-1],
                os.O_RDONLY | os.O_CLOEXEC | nofollow,
                dir_fd=current_fd,
            )
            try:
                data = _read_fd_bounded(file_fd, limit, canonical)
                self._observe(file_fd, canonical)
                return data
            finally:
                os.close(file_fd)
        except OSError as error:
            raise ContractError(
                f"missing or unsafe target-files artifact {canonical}: {error}"
            ) from error
        finally:
            os.close(current_fd)


class ZipTargetFiles:
    def __init__(self, path: Path):
        self._fd, self.path = _open_absolute_nofollow(path, directory=False)
        self._stream = None
        self._zip = None
        self._backing_metadata: tuple[int, ...] | None = None
        try:
            metadata = os.fstat(self._fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ContractError("target-files ZIP is not a unique regular file")
            self._backing_metadata = _stable_file_tuple(metadata)
            self._stream = os.fdopen(os.dup(self._fd), "rb")
            self._zip = zipfile.ZipFile(self._stream, "r")
            infos = self._zip.infolist()
            if not infos or len(infos) > MAX_ZIP_ENTRIES:
                raise ContractError(
                    f"target-files ZIP entry count is outside bounds: {len(infos)}"
                )
            required_casefold = {
                artifact.casefold(): artifact for artifact in REQUIRED_ARTIFACT_LIMITS
            }
            self._entries: dict[str, zipfile.ZipInfo] = {}
            for info in infos:
                canonical = _canonical_member_name(info.filename)
                if canonical in self._entries:
                    raise ContractError(
                        f"duplicate normalized ZIP member: {canonical}"
                    )
                casefolded = canonical.casefold()
                if (
                    casefolded in required_casefold
                    and canonical != required_casefold[casefolded]
                ):
                    raise ContractError(
                        "case-ambiguous alias for required artifact: "
                        f"{canonical}"
                    )
                self._entries[canonical] = info
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        if self._zip is not None:
            self._zip.close()
            self._zip = None
        if self._stream is not None:
            self._stream.close()
            self._stream = None
        if self._fd >= 0:
            metadata = os.fstat(self._fd)
            if (
                self._backing_metadata is not None
                and _stable_file_tuple(metadata) != self._backing_metadata
            ):
                os.close(self._fd)
                self._fd = -1
                raise ContractError("target-files ZIP mutated during verification")
            os.close(self._fd)
            self._fd = -1

    def __enter__(self) -> "ZipTargetFiles":
        return self

    def __exit__(self, *_unused: object) -> None:
        self.close()

    def read(self, name: str, limit: int) -> bytes:
        if self._zip is None:
            raise ContractError("target-files ZIP reader is closed")
        info = self._entries.get(name)
        if info is None:
            raise ContractError(f"missing target-files artifact: {name}")
        if info.is_dir():
            raise ContractError(f"required artifact is a directory: {name}")
        unix_mode = (info.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(unix_mode)
        if file_type not in (0, stat.S_IFREG):
            raise ContractError(f"required ZIP artifact is not regular: {name}")
        if info.flag_bits & 0x1:
            raise ContractError(f"required ZIP artifact is encrypted: {name}")
        if info.file_size < 0 or info.file_size > limit:
            raise ContractError(
                f"{name} size {info.file_size} exceeds {limit} bytes"
            )
        with self._zip.open(info, "r") as source:
            data = source.read(limit + 1)
            if source.read(1):
                raise ContractError(f"{name} exceeded its bounded read limit")
        if len(data) > limit or len(data) != info.file_size:
            raise ContractError(f"{name} size disagrees with the ZIP directory")
        return data


def open_target_files(path: Path) -> DirectoryTargetFiles | ZipTargetFiles:
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        metadata = os.lstat(absolute)
    except OSError as error:
        raise ContractError(f"target-files input is unavailable: {absolute}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise ContractError(f"target-files input is a symbolic link: {absolute}")
    if stat.S_ISDIR(metadata.st_mode):
        return DirectoryTargetFiles(absolute)
    if stat.S_ISREG(metadata.st_mode):
        try:
            return ZipTargetFiles(absolute)
        except zipfile.BadZipFile as error:
            raise ContractError(f"target-files input is not a valid ZIP: {error}") from error
    raise ContractError(f"target-files input is not a regular ZIP or directory: {absolute}")


def _decode_strict(data: bytes, label: str) -> str:
    if b"\x00" in data or b"\r" in data:
        raise ContractError(f"{label} contains NUL or CR bytes")
    try:
        return data.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ContractError(f"{label} is not strict UTF-8") from error


def parse_identity(data: bytes) -> dict[str, str]:
    text = _decode_strict(data, "tar-filter identity")
    if not text.endswith("\n") or text.endswith("\n\n"):
        raise ContractError("tar-filter identity must end in exactly one LF")
    lines = text[:-1].split("\n")
    if len(lines) != len(IDENTITY_KEYS):
        raise ContractError("tar-filter identity has an unexpected line count")
    values: dict[str, str] = {}
    order: list[str] = []
    for line in lines:
        if "=" not in line:
            raise ContractError("tar-filter identity contains a malformed line")
        key, value = line.split("=", 1)
        if not key or not value or key in values:
            raise ContractError("tar-filter identity contains an empty or duplicate key")
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key):
            raise ContractError(f"tar-filter identity key is invalid: {key!r}")
        order.append(key)
        values[key] = value
    if tuple(order) != IDENTITY_KEYS:
        raise ContractError("tar-filter identity key set/order differs")
    return values


def verify_elf(data: bytes) -> None:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ContractError("installed tar filter is not an ELF64 executable")
    if data[4:7] != b"\x02\x01\x01":
        raise ContractError("installed tar filter is not little-endian ELF64 v1")
    elf_type, machine = struct.unpack_from("<HH", data, 16)
    elf_version = struct.unpack_from("<I", data, 20)[0]
    header_size = struct.unpack_from("<H", data, 52)[0]
    if elf_type != 3 or machine != 183 or elf_version != 1 or header_size != 64:
        raise ContractError(
            "installed tar filter is not an AArch64 ET_DYN ELF64 executable"
        )


def verify_identity(values: dict[str, str], helper: bytes, source_sha: str) -> str:
    helper_sha = sha256_bytes(helper)
    expected = {
        "schema": EXPECTED_IDENTITY_SCHEMA,
        "path": HELPER_DEVICE_PATH,
        "sha256": helper_sha,
        "size": str(len(helper)),
        "owner": "0:2000",
        "mode": "0755",
        "selinux_label": EXPECTED_CONTEXT,
        "source_sha256": source_sha,
        "build_variants": EXPECTED_BUILD_VARIANTS,
    }
    if values != expected:
        mismatches = sorted(
            key for key in IDENTITY_KEYS if values.get(key) != expected[key]
        )
        raise ContractError(
            "tar-filter identity disagrees with installed material: "
            + ", ".join(mismatches)
        )
    if not re.fullmatch(r"[0-9a-f]{64}", values["sha256"]):
        raise ContractError("tar-filter identity ELF SHA-256 is not canonical")
    return helper_sha


def _parse_octal_mode(token: str, label: str) -> int:
    if not re.fullmatch(r"[0-7]{3,4}", token):
        raise ContractError(f"{label} mode is not canonical octal: {token!r}")
    value = int(token, 8)
    if value > 0o7777:
        raise ContractError(f"{label} mode exceeds permission bits")
    return value


def parse_filesystem_config(data: bytes) -> dict[str, tuple[int, int, int, dict[str, str]]]:
    text = _decode_strict(data, "system_ext filesystem_config")
    entries: dict[str, tuple[int, int, int, dict[str, str]]] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line:
            continue
        fields = line.split()
        if len(fields) < 4:
            raise ContractError(f"filesystem_config line {line_number} is malformed")
        # Android's fs_config emits the partition root with an empty path,
        # represented by leading whitespace (for example
        # `` 0 0 755 capabilities=0x0``).  It is a real, canonical record but
        # has no path key to retain.  Validate it with the same strict field
        # rules as every other record, then omit it from the path map.
        root_record = line[:1].isspace()
        if root_record:
            path = ""
            uid_token, gid_token, mode_token, *attribute_tokens = fields
        else:
            path, uid_token, gid_token, mode_token, *attribute_tokens = fields
        if path and path in entries:
            raise ContractError(f"filesystem_config path is duplicated: {path}")
        if path and not re.fullmatch(
            r"[A-Za-z0-9._+/@=-]+(?:/[A-Za-z0-9._+@=-]+)*", path
        ):
            raise ContractError(f"filesystem_config path is non-canonical: {path!r}")
        if not re.fullmatch(r"[0-9]+", uid_token) or not re.fullmatch(
            r"[0-9]+", gid_token
        ):
            raise ContractError(f"filesystem_config identity is malformed for {path}")
        attributes: dict[str, str] = {}
        for token in attribute_tokens:
            if token.count("=") != 1:
                raise ContractError(f"filesystem_config attribute is malformed: {token}")
            key, value = token.split("=", 1)
            if not key or not value or key in attributes:
                raise ContractError(f"filesystem_config attribute is duplicated: {token}")
            attributes[key] = value
        metadata = (
            int(uid_token, 10),
            int(gid_token, 10),
            _parse_octal_mode(mode_token, path or "<partition-root>"),
            attributes,
        )
        if path:
            entries[path] = metadata
    if not entries:
        raise ContractError("system_ext filesystem_config is empty")
    return entries


def verify_filesystem_config(data: bytes) -> None:
    entries = parse_filesystem_config(data)
    expected = {
        HELPER_FS_PATH: (0, 2000, 0o755, {"capabilities": "0x0"}),
        IDENTITY_FS_PATH: (0, 0, 0o644, {"capabilities": "0x0"}),
    }
    for path, metadata in expected.items():
        actual = entries.get(path)
        if actual is None:
            raise ContractError(f"filesystem_config omits {path}")
        if actual != metadata:
            raise ContractError(
                f"filesystem_config metadata differs for {path}: {actual!r}"
            )


def parse_text_file_contexts(data: bytes) -> list[tuple[str, str | None, str]]:
    text = _decode_strict(data, "installed system_ext_file_contexts")
    entries: list[tuple[str, str | None, str]] = []
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) == 2:
            regex_text, context = fields
            file_type = None
        elif len(fields) == 3 and re.fullmatch(r"-[bcdpls-]", fields[1]):
            regex_text, file_type, context = fields
        else:
            raise ContractError(f"file_contexts line {line_number} is malformed")
        entries.append((regex_text, file_type, context))
    if not entries:
        raise ContractError("installed system_ext_file_contexts is empty")
    return entries


def verify_text_file_contexts(data: bytes) -> None:
    entries = parse_text_file_contexts(data)
    helper_entries = [entry for entry in entries if HELPER_BASENAME in entry[0]]
    expected = (EXPECTED_CONTEXT_REGEX, None, EXPECTED_CONTEXT)
    if helper_entries != [expected]:
        raise ContractError(
            "installed system_ext_file_contexts lacks one exact tar-filter mapping"
        )


class _BinaryCursor:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, length: int, label: str) -> bytes:
        if length < 0 or length > len(self.data) - self.offset:
            raise ContractError(f"compiled file_contexts truncates {label}")
        start = self.offset
        self.offset += length
        return self.data[start : self.offset]

    def u32(self, label: str) -> int:
        return struct.unpack("<I", self.take(4, label))[0]

    def i32(self, label: str) -> int:
        return struct.unpack("<i", self.take(4, label))[0]

    def c_string(self, length: int, label: str, *, maximum: int) -> str:
        if length < 1 or length > maximum:
            raise ContractError(f"compiled file_contexts {label} length is invalid")
        raw = self.take(length, label)
        if raw[-1:] != b"\x00" or b"\x00" in raw[:-1]:
            raise ContractError(f"compiled file_contexts {label} is not one C string")
        try:
            return raw[:-1].decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            raise ContractError(
                f"compiled file_contexts {label} is not UTF-8"
            ) from error


def verify_compiled_file_contexts(data: bytes) -> int:
    if not data:
        raise ContractError("compiled file_contexts is empty")
    cursor = _BinaryCursor(data)
    magic = cursor.u32("magic")
    version = cursor.u32("version")
    if magic != COMPILED_FCONTEXT_MAGIC or version != COMPILED_FCONTEXT_VERSION:
        raise ContractError(
            "compiled file_contexts magic/version is unsupported or malformed"
        )
    regex_version_len = cursor.u32("regex backend version length")
    if regex_version_len < 1 or regex_version_len > 1024:
        raise ContractError("compiled file_contexts regex backend version is invalid")
    cursor.take(regex_version_len, "regex backend version")
    regex_arch_len = cursor.u32("regex architecture length")
    if regex_arch_len < 1 or regex_arch_len > 128:
        raise ContractError("compiled file_contexts regex architecture is invalid")
    cursor.take(regex_arch_len, "regex architecture")

    stem_count = cursor.u32("stem count")
    if stem_count > MAX_COMPILED_STEMS:
        raise ContractError("compiled file_contexts stem count exceeds bounds")
    for index in range(stem_count):
        stem_len = cursor.u32(f"stem {index} length")
        cursor.c_string(stem_len + 1, f"stem {index}", maximum=1024 * 1024)

    spec_count = cursor.u32("spec count")
    if spec_count < 1 or spec_count > MAX_COMPILED_SPECS:
        raise ContractError("compiled file_contexts spec count is outside bounds")
    exact_matches = 0
    for index in range(spec_count):
        context_len = cursor.u32(f"spec {index} context length")
        context = cursor.c_string(
            context_len, f"spec {index} context", maximum=64 * 1024
        )
        regex_len = cursor.u32(f"spec {index} regex length")
        regex_text = cursor.c_string(
            regex_len, f"spec {index} regex", maximum=4 * 1024 * 1024
        )
        mode = cursor.u32(f"spec {index} mode")
        cursor.i32(f"spec {index} stem id")
        has_meta = cursor.u32(f"spec {index} meta flag")
        cursor.u32(f"spec {index} prefix length")
        compiled_len = cursor.u32(f"spec {index} compiled regex length")
        cursor.take(compiled_len, f"spec {index} compiled regex")
        if HELPER_BASENAME in regex_text:
            if (
                regex_text != EXPECTED_CONTEXT_REGEX
                or context != EXPECTED_CONTEXT
                or mode != 0
                or has_meta == 0
            ):
                raise ContractError(
                    "compiled file_contexts contains a conflicting tar-filter mapping"
                )
            exact_matches += 1
    if cursor.offset != len(data):
        raise ContractError("compiled file_contexts has trailing bytes")
    if exact_matches != 1:
        raise ContractError(
            "compiled file_contexts does not contain exactly one tar-filter mapping"
        )
    return spec_count


def _require_once(text: str, token: str, label: str) -> None:
    count = text.count(token)
    if count != 1:
        raise ContractError(f"{label} expected one occurrence, found {count}: {token}")


def verify_source_contract(vendor_root: Path) -> str:
    vendor_root = Path(os.path.abspath(os.fspath(vendor_root)))
    if vendor_root.name != "trillionnium" or vendor_root.parent.name != "vendor":
        raise ContractError(
            "--source-root must identify the Android vendor/trillionnium directory"
        )
    with DirectoryTargetFiles(vendor_root) as source:
        c_source = source.read(
            "prebuilt/common/src/trillionnium_rootfs_tar_staging_filter.c",
            4 * 1024 * 1024,
        )
        android_bp = _decode_strict(
            source.read("prebuilt/common/Android.bp", 16 * 1024 * 1024),
            "Android.bp",
        )
        common_mk = _decode_strict(
            source.read("config/common.mk", 4 * 1024 * 1024), "config/common.mk"
        )
        bootstrap = _decode_strict(
            source.read(
                "prebuilt/common/bin/trillionnium-root-linux-bootstrap.sh",
                8 * 1024 * 1024,
            ),
            "Root Linux bootstrap",
        )
    source_sha = sha256_bytes(c_source)
    if source_sha != EXPECTED_SOURCE_SHA256:
        raise ContractError(
            f"tar-filter C source digest differs: {source_sha}"
        )

    if not re.search(
        rf'cc_binary\s*\{{.*?name:\s*"{HELPER_BASENAME}".*?'
        r'srcs:\s*\["src/trillionnium_rootfs_tar_staging_filter\.c"\].*?'
        r'system_ext_specific:\s*true,.*?c_std:\s*"c17"',
        android_bp,
        re.DOTALL,
    ):
        raise ContractError("Android.bp lacks the source-built C17 system_ext helper")
    identity_anchor = 'name: "trillionnium-rootfs-tar-staging-filter-identity-generated"'
    identity_start = android_bp.find(identity_anchor)
    identity_end = android_bp.find("\n}\n", identity_start)
    if identity_start < 0 or identity_end < 0:
        raise ContractError("Android.bp lacks the tar-filter identity genrule")
    identity_block = android_bp[identity_start:identity_end]
    for token in (
        '":trillionnium_rootfs_tar_staging_filter"',
        '"src/trillionnium_rootfs_tar_staging_filter.c"',
        "$(location :trillionnium_rootfs_tar_staging_filter)",
        "$(location src/trillionnium_rootfs_tar_staging_filter.c)",
        EXPECTED_SOURCE_SHA256,
        "'owner=0:2000'",
        "'mode=0755'",
        f"'selinux_label={EXPECTED_CONTEXT}'",
    ):
        if token not in identity_block:
            raise ContractError(f"identity genrule omits required binding: {token}")

    _require_once(
        common_mk,
        "    trillionnium_rootfs_tar_staging_filter \\",
        "product helper package",
    )
    _require_once(
        common_mk,
        "    trillionnium-rootfs-tar-staging-filter-identity \\",
        "product identity package",
    )
    for token in (
        '"0:0:644:1"',
        '"0:2000:755:${claimed_size}:1"',
        EXPECTED_CONTEXT,
        "verify_tar_staging_filter_identity",
    ):
        if token not in bootstrap:
            raise ContractError(f"bootstrap omits tar-filter check: {token}")

    android_root = vendor_root.parent.parent
    file_contexts = _decode_strict(
        read_regular_path(
            android_root
            / "device/trillionnium/sepolicy/common/private/file_contexts",
            8 * 1024 * 1024,
            "source file_contexts",
        ),
        "source file_contexts",
    )
    expected_line = f"{EXPECTED_CONTEXT_REGEX} {EXPECTED_CONTEXT}"
    helper_lines = [
        line.strip()
        for line in file_contexts.splitlines()
        if HELPER_BASENAME in line and not line.lstrip().startswith("#")
    ]
    if helper_lines != [expected_line]:
        raise ContractError("source file_contexts lacks one exact tar-filter mapping")
    return source_sha


def verify_target_files(
    target: DirectoryTargetFiles | ZipTargetFiles, source_sha: str
) -> tuple[str, int]:
    artifacts = {
        name: target.read(name, limit)
        for name, limit in REQUIRED_ARTIFACT_LIMITS.items()
    }
    helper = artifacts[HELPER_ARTIFACT]
    verify_elf(helper)
    identity = parse_identity(artifacts[IDENTITY_ARTIFACT])
    helper_sha = verify_identity(identity, helper, source_sha)
    verify_filesystem_config(artifacts[FILESYSTEM_CONFIG_ARTIFACT])
    verify_text_file_contexts(artifacts[TEXT_FILE_CONTEXTS_ARTIFACT])
    spec_count = verify_compiled_file_contexts(
        artifacts[COMPILED_FILE_CONTEXTS_ARTIFACT]
    )
    return helper_sha, spec_count


def _fixture_elf() -> bytes:
    data = bytearray(128)
    data[:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into("<HHI", data, 16, 3, 183, 1)
    struct.pack_into("<H", data, 52, 64)
    data[64:] = b"bounded-target-files-fixture" + b"\x00" * (
        len(data) - 64 - len(b"bounded-target-files-fixture")
    )
    return bytes(data)


def _fixture_identity(helper: bytes, **overrides: str) -> bytes:
    values = {
        "schema": EXPECTED_IDENTITY_SCHEMA,
        "path": HELPER_DEVICE_PATH,
        "sha256": sha256_bytes(helper),
        "size": str(len(helper)),
        "owner": "0:2000",
        "mode": "0755",
        "selinux_label": EXPECTED_CONTEXT,
        "source_sha256": EXPECTED_SOURCE_SHA256,
        "build_variants": EXPECTED_BUILD_VARIANTS,
    }
    values.update(overrides)
    return ("".join(f"{key}={values[key]}\n" for key in IDENTITY_KEYS)).encode()


def _fixture_fs_config(*, helper_gid: int = 2000, helper_mode: str = "755") -> bytes:
    return (
        " 0 0 755 capabilities=0x0\n"
        "system_ext 0 0 755 capabilities=0x0\n"
        f"{HELPER_FS_PATH} 0 {helper_gid} {helper_mode} capabilities=0x0\n"
        f"{IDENTITY_FS_PATH} 0 0 644 capabilities=0x0\n"
    ).encode()


def _fixture_text_contexts() -> bytes:
    return f"{EXPECTED_CONTEXT_REGEX} {EXPECTED_CONTEXT}\n".encode()


def _fixture_compiled_contexts(
    *, regex_text: str = EXPECTED_CONTEXT_REGEX, context: str = EXPECTED_CONTEXT
) -> bytes:
    chunks = [
        struct.pack("<II", COMPILED_FCONTEXT_MAGIC, COMPILED_FCONTEXT_VERSION),
    ]
    for value in (b"fixture-pcre2", b"8-8-el"):
        chunks.extend((struct.pack("<I", len(value)), value))
    chunks.append(struct.pack("<I", 0))  # stems
    chunks.append(struct.pack("<I", 1))  # specs
    context_bytes = context.encode() + b"\x00"
    regex_bytes = regex_text.encode() + b"\x00"
    chunks.extend(
        (
            struct.pack("<I", len(context_bytes)),
            context_bytes,
            struct.pack("<I", len(regex_bytes)),
            regex_bytes,
            struct.pack("<IiIII", 0, -1, 1, 1, 0),
        )
    )
    return b"".join(chunks)


def _fixture_artifacts(**overrides: bytes) -> dict[str, bytes]:
    helper = overrides.pop(HELPER_ARTIFACT, _fixture_elf())
    artifacts = {
        HELPER_ARTIFACT: helper,
        IDENTITY_ARTIFACT: _fixture_identity(helper),
        FILESYSTEM_CONFIG_ARTIFACT: _fixture_fs_config(),
        TEXT_FILE_CONTEXTS_ARTIFACT: _fixture_text_contexts(),
        COMPILED_FILE_CONTEXTS_ARTIFACT: _fixture_compiled_contexts(),
    }
    artifacts.update(overrides)
    return artifacts


def _write_directory_fixture(root: Path, artifacts: dict[str, bytes]) -> None:
    for name, data in artifacts.items():
        destination = root.joinpath(*name.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)


def _write_zip_fixture(path: Path, artifacts: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in artifacts.items():
            archive.writestr(name, data)


def run_self_tests(vendor_root: Path) -> bool:
    source_sha = verify_source_contract(vendor_root)

    class BoundedTargetFilesTests(unittest.TestCase):
        def verify_path(self, path: Path) -> tuple[str, int]:
            with open_target_files(path) as target:
                return verify_target_files(target, source_sha)

        def assert_contract_error(self, path: Path) -> None:
            with self.assertRaises(ContractError):
                self.verify_path(path)

        def test_directory_positive(self) -> None:
            with tempfile.TemporaryDirectory(
                prefix="trillionnium-target-files-dir-positive-"
            ) as temporary:
                root = Path(temporary)
                _write_directory_fixture(root, _fixture_artifacts())
                helper_sha, specs = self.verify_path(root)
                self.assertEqual(helper_sha, sha256_bytes(_fixture_elf()))
                self.assertEqual(specs, 1)

        def test_zip_positive(self) -> None:
            with tempfile.TemporaryDirectory(
                prefix="trillionnium-target-files-zip-positive-"
            ) as temporary:
                path = Path(temporary) / "target-files.zip"
                _write_zip_fixture(path, _fixture_artifacts())
                self.assertEqual(self.verify_path(path)[1], 1)

        def test_duplicate_zip_member_is_rejected(self) -> None:
            with tempfile.TemporaryDirectory(
                prefix="trillionnium-target-files-zip-duplicate-"
            ) as temporary:
                path = Path(temporary) / "target-files.zip"
                artifacts = _fixture_artifacts()
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    with zipfile.ZipFile(path, "w") as archive:
                        for name, data in artifacts.items():
                            archive.writestr(name, data)
                        archive.writestr(HELPER_ARTIFACT, artifacts[HELPER_ARTIFACT])
                self.assert_contract_error(path)

        def test_duplicate_identity_key_is_rejected(self) -> None:
            with tempfile.TemporaryDirectory(
                prefix="trillionnium-target-files-identity-duplicate-"
            ) as temporary:
                root = Path(temporary)
                artifacts = _fixture_artifacts()
                artifacts[IDENTITY_ARTIFACT] += b"mode=0755\n"
                _write_directory_fixture(root, artifacts)
                self.assert_contract_error(root)

        def test_helper_digest_mismatch_is_rejected(self) -> None:
            with tempfile.TemporaryDirectory(
                prefix="trillionnium-target-files-helper-mismatch-"
            ) as temporary:
                root = Path(temporary)
                artifacts = _fixture_artifacts()
                artifacts[HELPER_ARTIFACT] += b"drift"
                _write_directory_fixture(root, artifacts)
                self.assert_contract_error(root)

        def test_filesystem_config_identity_mismatch_is_rejected(self) -> None:
            with tempfile.TemporaryDirectory(
                prefix="trillionnium-target-files-fsconfig-mismatch-"
            ) as temporary:
                root = Path(temporary)
                artifacts = _fixture_artifacts(
                    **{FILESYSTEM_CONFIG_ARTIFACT: _fixture_fs_config(helper_gid=0)}
                )
                _write_directory_fixture(root, artifacts)
                self.assert_contract_error(root)

        def test_filesystem_config_mode_mismatch_is_rejected(self) -> None:
            with tempfile.TemporaryDirectory(
                prefix="trillionnium-target-files-mode-mismatch-"
            ) as temporary:
                root = Path(temporary)
                artifacts = _fixture_artifacts(
                    **{
                        FILESYSTEM_CONFIG_ARTIFACT: _fixture_fs_config(
                            helper_mode="750"
                        )
                    }
                )
                _write_directory_fixture(root, artifacts)
                self.assert_contract_error(root)

        def test_missing_compiled_contexts_is_rejected(self) -> None:
            with tempfile.TemporaryDirectory(
                prefix="trillionnium-target-files-context-missing-"
            ) as temporary:
                root = Path(temporary)
                artifacts = _fixture_artifacts()
                del artifacts[COMPILED_FILE_CONTEXTS_ARTIFACT]
                _write_directory_fixture(root, artifacts)
                self.assert_contract_error(root)

        def test_compiled_context_conflict_is_rejected(self) -> None:
            with tempfile.TemporaryDirectory(
                prefix="trillionnium-target-files-context-conflict-"
            ) as temporary:
                root = Path(temporary)
                artifacts = _fixture_artifacts(
                    **{
                        COMPILED_FILE_CONTEXTS_ARTIFACT: _fixture_compiled_contexts(
                            context="u:object_r:system_file:s0"
                        )
                    }
                )
                _write_directory_fixture(root, artifacts)
                self.assert_contract_error(root)

        def test_required_symlink_is_rejected(self) -> None:
            if not hasattr(os, "symlink"):
                self.skipTest("symlinks are unavailable")
            with tempfile.TemporaryDirectory(
                prefix="trillionnium-target-files-symlink-"
            ) as temporary:
                root = Path(temporary)
                artifacts = _fixture_artifacts()
                identity = artifacts.pop(IDENTITY_ARTIFACT)
                _write_directory_fixture(root, artifacts)
                outside = root / "outside-identity"
                outside.write_bytes(identity)
                destination = root.joinpath(*IDENTITY_ARTIFACT.split("/"))
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.symlink_to(outside)
                self.assert_contract_error(root)

        def test_directory_mutation_after_read_is_rejected(self) -> None:
            with tempfile.TemporaryDirectory(
                prefix="trillionnium-target-files-concurrent-mutation-"
            ) as temporary:
                root = Path(temporary)
                artifacts = _fixture_artifacts()
                _write_directory_fixture(root, artifacts)
                target = DirectoryTargetFiles(root)
                target.read(
                    HELPER_ARTIFACT, REQUIRED_ARTIFACT_LIMITS[HELPER_ARTIFACT]
                )
                root.joinpath(*HELPER_ARTIFACT.split("/")).write_bytes(b"drift")
                with self.assertRaises(ContractError):
                    target.close()

        def test_non_elf_helper_is_rejected(self) -> None:
            with tempfile.TemporaryDirectory(
                prefix="trillionnium-target-files-non-elf-"
            ) as temporary:
                root = Path(temporary)
                helper = b"not-an-elf"
                artifacts = _fixture_artifacts(
                    **{
                        HELPER_ARTIFACT: helper,
                        IDENTITY_ARTIFACT: _fixture_identity(helper),
                    }
                )
                _write_directory_fixture(root, artifacts)
                self.assert_contract_error(root)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(BoundedTargetFilesTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return result.wasSuccessful()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--target-files",
        type=Path,
        help="real target-files ZIP or unpacked target-files directory",
    )
    mode.add_argument(
        "--source-only",
        action="store_true",
        help="run static source checks and report HOLD/SOURCE_ONLY",
    )
    mode.add_argument(
        "--self-test",
        action="store_true",
        help="run bounded temporary positive and negative fixtures",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        default=DEFAULT_VENDOR_ROOT,
        help="Android vendor/trillionnium source root",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if not (args.target_files or args.source_only or args.self_test):
        print(
            "FAIL: --target-files is required unless --source-only or "
            "--self-test is explicit",
            file=sys.stderr,
        )
        return 2
    try:
        if args.self_test:
            if not run_self_tests(args.source_root):
                print("FAIL: bounded target-files verifier self-tests", file=sys.stderr)
                return 1
            print(
                "PASS: bounded target-files verifier self-tests "
                "(no physical materialization claim)"
            )
            return 0

        source_sha = verify_source_contract(args.source_root)
        if args.source_only:
            print(
                "HOLD/SOURCE_ONLY: tar-filter source/product contract verified; "
                "target-files physical materialization was not supplied and is not PASS"
            )
            return 0

        with open_target_files(args.target_files) as target:
            helper_sha, spec_count = verify_target_files(target, source_sha)
        print(
            "PASS: target-files tar-filter physical materialization verified; "
            f"helper_sha256={helper_sha}; compiled_file_context_specs={spec_count}"
        )
        return 0
    except (ContractError, OSError, zipfile.BadZipFile) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
