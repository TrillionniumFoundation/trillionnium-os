#!/usr/bin/env python3
"""Source-only contract for two measured operation replay-sync helpers.

This module deliberately has no product-install, Android, fs-verity, AVB,
launcher, or effect-authority path.  Its CLI requires an explicit subcommand;
the verification commands are read-only, while public candidate execution and
persistent reconciliation are fixed HOLDs.  The retained future build code
cannot currently issue a receipt or publish an output.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import platform
import selectors
import secrets
import signal
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable


RECIPE_SCHEMA = "trillionnium.operation-replay-sync-static-recipe.v1"
BUILD_SCHEMA = "trillionnium.operation-replay-sync-static-build-receipt.v1"
RECONCILE_SCHEMA = "trillionnium.operation-replay-sync-static-reconcile.v1"
TOOLCHAIN_SCHEMA = "trillionnium.operation-replay-sync-static-toolchain-receipt.v1"
IMAGE_SCHEMA = "trillionnium.operation-replay-sync-static-image-receipt.v1"
TARGET = "aarch64-unknown-linux-musl"
PROFILES = ("amd64-cross", "arm64-native")
ROLE_ORDER = ("system-api", "accessibility")
PAGE_SIZES = (4096, 16384, 65536)
MAX_ELF_BYTES = 512 * 1024 * 1024
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_TREE_FILES = 200_000
MAX_TREE_BYTES = 16 * 1024 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_BUILD_LOG_BYTES = 32 * 1024 * 1024
MAX_ABSOLUTE_PATH_BYTES = 4096
MAX_PATH_COMPONENTS = 256
MAX_PATH_COMPONENT_BYTES = 255
MAX_CRT_FILES = 128
MAX_CRT_TOTAL_BYTES = 512 * 1024 * 1024
MAX_CRT_FILE_BYTES = 256 * 1024 * 1024
MAX_CRT_RELATIVE_PATH_BYTES = 4096
MAX_CRT_COMPONENTS = 16
_PUBLIC_CANDIDATE_EXECUTION_ENABLED = False
AT_EMPTY_PATH = 0x1000

PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
PF_X = 1
PF_W = 2
PF_R = 4
SHT_NOBITS = 8
SHT_DYNAMIC = 6

AUTHORITY_FALSE = {
    "installable": False,
    "product_authority": False,
    "effect_authority": False,
    "release_authority": False,
}
CHECKPOINT_FALSE = {
    "formal_lane_started": False,
    "two_by_two_build_completed": False,
    "independent_builder_custody_verified": False,
    "signed_product_contract_verified": False,
    "fsverity_enable_performed": False,
    "avb_provenance_verified": False,
    "product_packaging_wired": False,
    "launcher_authority_constructible": False,
    "main_effect_route_wired": False,
}

# Fault-injection seams. Production uses the exact stdlib/syscall functions;
# tests replace one seam at a time and assert the real child/process group is
# gone before `_bounded_build` returns an error.
_SELECTOR_FACTORY = selectors.DefaultSelector
_READ_FD = os.read
_CLOSE_FD = os.close
_PROCESS_OBSERVER = lambda _process: None
_PUBLICATION_PRE_LINK_BARRIER = lambda _output, _parent_fd, _bundle_fd: None
_RECONCILE_PRE_FINAL_BARRIER = lambda _left, _right: None


class ContractError(RuntimeError):
    """Fail-closed contract rejection."""


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _exact_keys(value: Any, expected: Iterable[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    expected_set = set(expected)
    actual_set = set(value)
    if actual_set != expected_set:
        raise ContractError(
            f"{label} keys drifted: missing={sorted(expected_set - actual_set)} "
            f"extra={sorted(actual_set - expected_set)}"
        )
    return value


def read_regular(path: Path, limit: int, label: str) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ContractError(f"could not open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ContractError(f"{label} is not a single-link regular file")
        if before.st_size < 0 or before.st_size > limit:
            raise ContractError(f"{label} exceeds its byte limit")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise ContractError(f"{label} truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ContractError(f"{label} grew while reading")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after:
            raise ContractError(f"{label} changed while reading")
        return b"".join(chunks), after
    finally:
        os.close(descriptor)


def load_json(path: Path, label: str, limit: int = MAX_JSON_BYTES) -> tuple[dict[str, Any], str]:
    raw, _ = read_regular(path, limit, label)
    return _parse_canonical_json(raw, label), sha256_bytes(raw)


def _parse_canonical_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_pairs_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError(f"{label} is not canonical JSON: {error}") from error
    if not isinstance(value, dict):
        raise ContractError(f"{label} must contain one object")
    if canonical_json_bytes(value) != raw:
        raise ContractError(f"{label} is not canonical newline-terminated JSON")
    return value


def _checked_end(offset: int, size: int, total: int, label: str) -> int:
    if offset < 0 or size < 0 or offset > total or size > total - offset:
        raise ContractError(f"{label} is outside the ELF file")
    return offset + size


def _u64_end(start: int, size: int, label: str) -> int:
    end = start + size
    if end > 0xFFFFFFFFFFFFFFFF:
        raise ContractError(f"{label} overflows u64")
    return end


def _power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def inspect_elf_bytes(blob: bytes) -> dict[str, Any]:
    """Parse and enforce the complete static helper ELF boundary."""

    if len(blob) < 64 or len(blob) > MAX_ELF_BYTES:
        raise ContractError("ELF size is outside the accepted range")
    ident = blob[:16]
    if ident[:4] != b"\x7fELF":
        raise ContractError("artifact is not ELF")
    if ident[4] != 2 or ident[5] != 1 or ident[6] != 1:
        raise ContractError("artifact is not little-endian ELF64 version 1")
    if ident[7] not in (0, 3):
        raise ContractError("artifact has an unexpected ELF OS ABI")
    (
        elf_type,
        machine,
        version,
        entry,
        program_offset,
        section_offset,
        flags,
        header_size,
        program_entry_size,
        program_count,
        section_entry_size,
        section_count,
        section_name_index,
    ) = struct.unpack_from("<HHIQQQIHHHHHH", blob, 16)
    if elf_type != 2 or machine != 183 or version != 1:
        raise ContractError("artifact is not AArch64 ET_EXEC")
    if header_size != 64 or flags != 0:
        raise ContractError("ELF header size or AArch64 flags drifted")
    if program_entry_size != 56 or not 1 <= program_count <= 256:
        raise ContractError("program-header geometry is invalid")
    if section_entry_size != 64 or not 1 <= section_count <= 8192:
        raise ContractError("section-header geometry is invalid or extended")
    if not 0 < section_name_index < section_count:
        raise ContractError("section-name table index is invalid or extended")
    if program_offset < 64 or program_offset % 8 != 0:
        raise ContractError("program-header table offset is invalid")
    if section_offset < 64 or section_offset % 8 != 0:
        raise ContractError("section-header table offset is invalid")
    _checked_end(program_offset, program_entry_size * program_count, len(blob), "program headers")
    _checked_end(section_offset, section_entry_size * section_count, len(blob), "section headers")

    loads: list[dict[str, int]] = []
    stack_count = 0
    forbidden_program_headers: list[int] = []
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        (
            segment_type,
            segment_flags,
            file_offset,
            virtual_address,
            _physical_address,
            file_size,
            memory_size,
            alignment,
        ) = struct.unpack_from("<IIQQQQQQ", blob, offset)
        if segment_flags & ~(PF_R | PF_W | PF_X):
            raise ContractError(f"program header {index} has unknown permission flags")
        _checked_end(file_offset, file_size, len(blob), f"program header {index} payload")
        _u64_end(virtual_address, memory_size, f"program header {index} memory")
        if alignment not in (0, 1):
            if not _power_of_two(alignment):
                raise ContractError(f"program header {index} alignment is not a power of two")
            if virtual_address % alignment != file_offset % alignment:
                raise ContractError(f"program header {index} offset/address congruence failed")
        if segment_type in (PT_INTERP, PT_DYNAMIC):
            forbidden_program_headers.append(segment_type)
        if segment_type == PT_GNU_STACK:
            stack_count += 1
            if segment_flags & PF_X:
                raise ContractError("GNU_STACK is executable")
        if segment_type == PT_LOAD:
            if file_size > memory_size or memory_size == 0:
                raise ContractError(f"LOAD {index} has invalid file/memory sizes")
            if alignment < max(PAGE_SIZES):
                raise ContractError(
                    f"LOAD {index} alignment is below the largest supported page"
                )
            for page_size in PAGE_SIZES:
                if virtual_address % page_size != file_offset % page_size:
                    raise ContractError(
                        f"LOAD {index} offset/address congruence failed at {page_size}-byte pages"
                    )
            loads.append(
                {
                    "index": index,
                    "flags": segment_flags,
                    "offset": file_offset,
                    "vaddr": virtual_address,
                    "filesz": file_size,
                    "memsz": memory_size,
                    "align": alignment,
                }
            )
    if forbidden_program_headers:
        raise ContractError("PT_INTERP or PT_DYNAMIC is forbidden")
    if stack_count != 1:
        raise ContractError("artifact must contain exactly one GNU_STACK")
    if not 1 <= len(loads) <= 64:
        raise ContractError("LOAD segment count is invalid")
    executable_entries = [
        segment
        for segment in loads
        if segment["flags"] & PF_X
        and segment["vaddr"] <= entry < segment["vaddr"] + segment["memsz"]
    ]
    if len(executable_entries) != 1:
        raise ContractError("entry point is not in exactly one executable LOAD")

    for page_size in PAGE_SIZES:
        page_ranges: list[tuple[int, int, int, int]] = []
        for segment in loads:
            start = segment["vaddr"] & ~(page_size - 1)
            raw_end = _u64_end(segment["vaddr"], segment["memsz"], "LOAD page range")
            rounded_end = (raw_end + page_size - 1) & ~(page_size - 1)
            if rounded_end > 0xFFFFFFFFFFFFFFFF:
                raise ContractError("LOAD page range rounding overflowed")
            if segment["flags"] & PF_W and segment["flags"] & PF_X:
                raise ContractError(f"LOAD is W+X at {page_size}-byte pages")
            page_ranges.append((start, rounded_end, segment["flags"], segment["index"]))
        for left_index, left in enumerate(page_ranges):
            for right in page_ranges[left_index + 1 :]:
                if max(left[0], right[0]) >= min(left[1], right[1]):
                    continue
                combined = left[2] | right[2]
                if combined & PF_W and combined & PF_X:
                    raise ContractError(
                        f"LOADs {left[3]} and {right[3]} create combined W+X at "
                        f"{page_size}-byte pages"
                    )

    sections: list[dict[str, int]] = []
    for index in range(section_count):
        offset = section_offset + index * section_entry_size
        (
            name_offset,
            section_type,
            section_flags,
            address,
            file_offset,
            size,
            link,
            info,
            alignment,
            entry_size,
        ) = struct.unpack_from("<IIQQQQIIQQ", blob, offset)
        _u64_end(address, size, f"section {index} address range")
        if section_type != SHT_NOBITS:
            _checked_end(file_offset, size, len(blob), f"section {index} payload")
        if alignment not in (0, 1) and not _power_of_two(alignment):
            raise ContractError(f"section {index} alignment is not a power of two")
        if alignment not in (0, 1):
            if section_flags & 0x2 and address % alignment != 0:
                raise ContractError(f"section {index} address alignment failed")
            if section_type != SHT_NOBITS and size and file_offset % alignment != 0:
                raise ContractError(f"section {index} file-offset alignment failed")
        if entry_size and size % entry_size != 0:
            raise ContractError(f"section {index} size is not an entry-size multiple")
        if link >= section_count and link != 0:
            raise ContractError(f"section {index} link is out of range")
        sections.append(
            {
                "name_offset": name_offset,
                "type": section_type,
                "flags": section_flags,
                "addr": address,
                "offset": file_offset,
                "size": size,
                "link": link,
                "info": info,
                "align": alignment,
                "entsize": entry_size,
            }
        )
    name_section = sections[section_name_index]
    if any(sections[0].values()):
        raise ContractError("ELF null section is not canonical")
    if name_section["type"] != 3:
        raise ContractError("section-name table is not SHT_STRTAB")
    names = blob[
        name_section["offset"] : name_section["offset"] + name_section["size"]
    ]
    if not names or names[0] != 0 or names[-1] != 0:
        raise ContractError("section-name table is not NUL bounded")
    decoded_names: list[str] = []
    for index, section in enumerate(sections):
        name_offset = section["name_offset"]
        if name_offset >= len(names):
            raise ContractError(f"section {index} name offset is out of range")
        terminator = names.find(b"\0", name_offset)
        if terminator < 0:
            raise ContractError(f"section {index} name is unterminated")
        try:
            name = names[name_offset:terminator].decode("ascii")
        except UnicodeDecodeError as error:
            raise ContractError(f"section {index} name is not ASCII") from error
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in name):
            raise ContractError(f"section {index} name contains a control character")
        decoded_names.append(name)
        if section["type"] == SHT_DYNAMIC or name in (".dynamic", ".interp"):
            raise ContractError("dynamic/interpreter section is forbidden")

    return {
        "schema": "trillionnium.operation-replay-sync-static-elf.v1",
        "sha256": sha256_bytes(blob),
        "size": len(blob),
        "class": "ELF64",
        "endianness": "little",
        "machine": "AArch64",
        "type": "ET_EXEC",
        "entry": entry,
        "entry_load_index": executable_entries[0]["index"],
        "program_header_count": program_count,
        "section_header_count": section_count,
        "load_count": len(loads),
        "gnu_stack_count": stack_count,
        "gnu_stack_executable": False,
        "pt_interp_present": False,
        "pt_dynamic_present": False,
        "sht_dynamic_present": False,
        "combined_wx_safe_page_sizes": list(PAGE_SIZES),
        "load_congruence_page_sizes": list(PAGE_SIZES),
        "bounds_and_alignment_verified": True,
    }


def inspect_elf_path(path: Path) -> dict[str, Any]:
    blob, _ = read_regular(path, MAX_ELF_BYTES, "static helper ELF")
    return inspect_elf_bytes(blob)


def verify_recipe(recipe: dict[str, Any]) -> dict[str, Any]:
    _exact_keys(
        recipe,
        (
            "schema",
            "candidate_scope",
            "source_date_epoch",
            "target",
            "profiles",
            "cargo",
            "source_contract",
            "build_contract",
            "elf_contract",
            "roles",
            "reconcile_contract",
            "source_checkpoint",
            "authority",
        ),
        "recipe",
    )
    if recipe["schema"] != RECIPE_SCHEMA or recipe["candidate_scope"] != "source_only_unwired":
        raise ContractError("recipe schema or candidate scope drifted")
    if recipe["target"] != TARGET or not isinstance(recipe["source_date_epoch"], int):
        raise ContractError("recipe target or SOURCE_DATE_EPOCH drifted")
    if recipe["source_date_epoch"] <= 0:
        raise ContractError("SOURCE_DATE_EPOCH must be positive")
    profiles = _exact_keys(recipe["profiles"], PROFILES, "recipe profiles")
    expected_hosts = {"amd64-cross": "x86_64", "arm64-native": "aarch64"}
    for name in PROFILES:
        profile = _exact_keys(
            profiles[name],
            ("host_arch", "builder_image_receipt_required", "toolchain_receipt_required"),
            f"profile {name}",
        )
        if profile != {
            "host_arch": expected_hosts[name],
            "builder_image_receipt_required": True,
            "toolchain_receipt_required": True,
        }:
            raise ContractError(f"profile {name} drifted")
    cargo = _exact_keys(
        recipe["cargo"],
        ("package", "feature", "release", "locked", "offline", "no_default_features", "bins"),
        "cargo contract",
    )
    expected_bins = [
        "trillionnium-system-api-operation-replay-sync",
        "trillionnium-accessibility-operation-replay-sync",
    ]
    if cargo != {
        "package": "trillionnium-agent-direct-tools",
        "feature": "production-durable-hotpath",
        "release": True,
        "locked": True,
        "offline": True,
        "no_default_features": True,
        "bins": expected_bins,
    }:
        raise ContractError("Cargo contract drifted")
    if recipe["source_checkpoint"] != CHECKPOINT_FALSE:
        raise ContractError("source checkpoint must remain entirely false")
    if recipe["authority"] != AUTHORITY_FALSE:
        raise ContractError("recipe authority must remain entirely false")
    source = _exact_keys(
        recipe["source_contract"],
        (
            "cargo_lock_sha256",
            "fixed_files",
            "full_tree_receipt_required",
            "cargo_vendor_receipt_required",
            "compiler_read_set_bound",
            "hostile_same_uid_source_custody_proven",
        ),
        "source contract",
    )
    expected_source_paths = {
        "Cargo.toml",
        "crates/trillionnium-agent-direct-tools/Cargo.toml",
        "crates/trillionnium-agent-direct-tools/src/operation_replay_sync.rs",
        "crates/trillionnium-agent-direct-tools/src/bin/system_api_operation_replay_sync.rs",
        "crates/trillionnium-agent-direct-tools/src/bin/accessibility_operation_replay_sync.rs",
    }
    if (
        not _is_sha256(source["cargo_lock_sha256"])
        or not isinstance(source["fixed_files"], dict)
        or set(source["fixed_files"]) != expected_source_paths
        or not all(_is_sha256(value) for value in source["fixed_files"].values())
        or source["full_tree_receipt_required"] is not True
        or source["cargo_vendor_receipt_required"] is not True
        or source["compiler_read_set_bound"] is not False
        or source["hostile_same_uid_source_custody_proven"] is not False
    ):
        raise ContractError("source receipt contract drifted")
    build = _exact_keys(
        recipe["build_contract"],
        (
            "base_environment",
            "candidate_execution_enabled",
            "locale",
            "timezone",
            "path_remap_root",
            "cargo_net_offline",
            "network_namespace_verified_by_builder",
            "outer_cgroup_v2_zero_survivor_required",
            "durable_publication_journal_required",
            "fresh_target_directory_required",
            "toolchain_and_crt_receipt_required",
            "builder_image_receipt_required",
        ),
        "build contract",
    )
    if build != {
        "base_environment": "empty",
        "candidate_execution_enabled": False,
        "locale": "C",
        "timezone": "UTC",
        "path_remap_root": "/usr/src/trillionnium-os",
        "cargo_net_offline": True,
        "network_namespace_verified_by_builder": False,
        "outer_cgroup_v2_zero_survivor_required": True,
        "durable_publication_journal_required": True,
        "fresh_target_directory_required": True,
        "toolchain_and_crt_receipt_required": True,
        "builder_image_receipt_required": True,
    }:
        raise ContractError("build environment/receipt contract drifted")
    roles = _exact_keys(recipe["roles"], ROLE_ORDER, "roles")
    for role in ROLE_ORDER:
        value = _exact_keys(roles[role], ("cargo_bin", "filename", "entry_source"), f"role {role}")
        if value["cargo_bin"] != value["filename"] or value["cargo_bin"] not in expected_bins:
            raise ContractError(f"role {role} binary identity drifted")
        if value["entry_source"] not in source["fixed_files"]:
            raise ContractError(f"role {role} entry source is not source-fixed")
    elf = _exact_keys(
        recipe["elf_contract"],
        (
            "class",
            "endianness",
            "machine",
            "type",
            "pt_interp_forbidden",
            "pt_dynamic_forbidden",
            "sht_dynamic_forbidden",
            "entry_in_executable_load",
            "gnu_stack_count",
            "gnu_stack_executable",
            "combined_wx_page_sizes",
            "load_congruence_page_sizes",
            "program_and_section_bounds_required",
            "load_alignment_and_congruence_required",
        ),
        "ELF contract",
    )
    if (
        elf.get("class") != "ELF64"
        or elf.get("endianness") != "little"
        or elf.get("machine") != "AArch64"
        or elf.get("type") != "ET_EXEC"
        or elf.get("combined_wx_page_sizes") != list(PAGE_SIZES)
        or elf.get("load_congruence_page_sizes") != list(PAGE_SIZES)
        or elf.get("gnu_stack_count") != 1
        or elf.get("gnu_stack_executable") is not False
        or any(
            elf.get(key) is not True
            for key in (
                "pt_interp_forbidden",
                "pt_dynamic_forbidden",
                "sht_dynamic_forbidden",
                "entry_in_executable_load",
                "program_and_section_bounds_required",
                "load_alignment_and_congruence_required",
            )
        )
    ):
        raise ContractError("ELF contract drifted")
    reconcile = _exact_keys(
        recipe["reconcile_contract"],
        (
            "profiles",
            "same_role_byte_identical",
            "cross_role_byte_distinct",
            "role_exchange_forbidden",
            "source_cargo_lock_vendor_and_crt_equal",
            "durable_publication_enabled",
            "fixed_custody_journal_required",
        ),
        "reconcile contract",
    )
    if reconcile != {
        "profiles": list(PROFILES),
        "same_role_byte_identical": True,
        "cross_role_byte_distinct": True,
        "role_exchange_forbidden": True,
        "source_cargo_lock_vendor_and_crt_equal": True,
        "durable_publication_enabled": False,
        "fixed_custody_journal_required": True,
    }:
        raise ContractError("reconcile contract drifted")
    return recipe


def load_recipe(path: Path) -> tuple[dict[str, Any], str]:
    raw, _ = read_regular(path, MAX_JSON_BYTES, "operation helper recipe")
    try:
        recipe = json.loads(raw, object_pairs_hook=_pairs_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError(f"operation helper recipe is invalid JSON: {error}") from error
    if not isinstance(recipe, dict) or not raw.endswith(b"\n"):
        raise ContractError("operation helper recipe must be an object ending in one newline")
    digest = sha256_bytes(raw)
    verify_recipe(recipe)
    return recipe, digest


def _tree_manifest(root: Path, label: str, require_readonly: bool) -> dict[str, Any]:
    try:
        root_stat = root.lstat()
    except OSError as error:
        raise ContractError(f"could not stat {label}: {error}") from error
    if not stat.S_ISDIR(root_stat.st_mode) or root.is_symlink():
        raise ContractError(f"{label} must be a real directory")
    if require_readonly and root_stat.st_mode & 0o222:
        raise ContractError(f"{label} root is writable")
    digest = hashlib.sha256()
    digest.update(b"trillionnium.tree-manifest.v1\0")
    file_count = 0
    directory_count = 0
    total_bytes = 0
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        directories.sort()
        files.sort()
        current_path = Path(current)
        relative_directory = current_path.relative_to(root).as_posix()
        if relative_directory == ".":
            relative_directory = ""
        if any(name in (".git", "target") for name in directories):
            raise ContractError(f"{label} contains a forbidden mutable build directory")
        for name in directories:
            path = current_path / name
            metadata = path.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
                raise ContractError(f"{label} contains a symlink or non-directory: {path}")
            if require_readonly and metadata.st_mode & 0o222:
                raise ContractError(f"{label} directory is writable: {path}")
            relative = f"{relative_directory}/{name}".lstrip("/")
            digest.update(b"d\0" + relative.encode("utf-8") + b"\0")
            digest.update(f"{stat.S_IMODE(metadata.st_mode):04o}\0".encode("ascii"))
            directory_count += 1
        for name in files:
            path = current_path / name
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ContractError(f"{label} contains a non-regular or multiply-linked file: {path}")
            if require_readonly and metadata.st_mode & 0o222:
                raise ContractError(f"{label} file is writable: {path}")
            if metadata.st_size > MAX_FILE_BYTES:
                raise ContractError(f"{label} file exceeds its limit: {path}")
            raw, after = read_regular(path, MAX_FILE_BYTES, f"{label} file")
            if metadata.st_ino != after.st_ino or metadata.st_dev != after.st_dev:
                raise ContractError(f"{label} file identity changed: {path}")
            relative = f"{relative_directory}/{name}".lstrip("/")
            digest.update(b"f\0" + relative.encode("utf-8") + b"\0")
            digest.update(f"{stat.S_IMODE(metadata.st_mode):04o}\0".encode("ascii"))
            digest.update(str(len(raw)).encode("ascii") + b"\0" + bytes.fromhex(sha256_bytes(raw)))
            file_count += 1
            total_bytes += len(raw)
            if file_count > MAX_TREE_FILES or total_bytes > MAX_TREE_BYTES:
                raise ContractError(f"{label} exceeds its tree limits")
    return {
        "schema": "trillionnium.operation-replay-sync-static-tree.v1",
        "file_count": file_count,
        "directory_count": directory_count,
        "regular_bytes": total_bytes,
        "manifest_sha256": digest.hexdigest(),
        "readonly_mode_bits_verified": require_readonly,
        "symlinks_allowed": False,
        "compiler_read_set_bound": False,
        "hostile_same_uid_custody_proven": False,
    }


def _absolute_components(path: Path, label: str) -> tuple[str, ...]:
    if not path.is_absolute():
        raise ContractError(f"{label} path must be absolute")
    encoded = os.fsencode(path)
    if not encoded or len(encoded) > MAX_ABSOLUTE_PATH_BYTES or b"\0" in encoded:
        raise ContractError(f"{label} absolute path is outside its byte bound")
    parts = path.parts
    if not parts or parts[0] != os.sep:
        raise ContractError(f"{label} absolute path root is not canonical")
    components = parts[1:]
    if len(components) > MAX_PATH_COMPONENTS:
        raise ContractError(f"{label} absolute path is too deep")
    for component in components:
        raw = os.fsencode(component)
        if (
            component in ("", ".", "..")
            or not raw
            or len(raw) > MAX_PATH_COMPONENT_BYTES
            or b"/" in raw
            or b"\0" in raw
        ):
            raise ContractError(f"{label} absolute path component is invalid")
    return tuple(components)


def _canonical_crt_relative_components(value: Any) -> tuple[str, ...]:
    if not isinstance(value, str):
        raise ContractError("CRT file path is not a string")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ContractError("CRT file path is not canonical ASCII") from error
    components = value.split("/")
    if (
        not raw
        or len(raw) > MAX_CRT_RELATIVE_PATH_BYTES
        or len(components) > MAX_CRT_COMPONENTS
        or value.startswith("/")
        or "\\" in value
        or any(character < 0x21 or character > 0x7E for character in raw)
        or any(component in ("", ".", "..") for component in components)
        or any(len(component.encode("ascii")) > MAX_PATH_COMPONENT_BYTES for component in components)
    ):
        raise ContractError("CRT file path is not canonical and bounded")
    return tuple(components)


def _measure_tool(path_value: Any, expected_sha: Any, label: str) -> dict[str, Any]:
    if not isinstance(path_value, str) or not path_value.startswith("/") or not _is_sha256(expected_sha):
        raise ContractError(f"{label} path or SHA-256 is invalid")
    path = Path(path_value)
    descriptor, raw, metadata = _open_absolute_regular_retained(
        path, MAX_FILE_BYTES, label
    )
    try:
        digest = sha256_bytes(raw)
        if (
            digest != expected_sha
            or not metadata.st_mode & 0o111
            or metadata.st_mode & 0o222
        ):
            raise ContractError(
                f"{label} digest, executable mode, or read-only mode drifted"
            )
        return {"path": str(path), "sha256": digest, "size": len(raw)}
    finally:
        os.close(descriptor)


def _load_toolchain_receipt(path: Path, profile: str) -> tuple[dict[str, Any], str, dict[str, Any]]:
    receipt, receipt_sha = load_json(path, "toolchain receipt")
    _exact_keys(
        receipt,
        (
            "schema",
            "profile",
            "target",
            "claimed_target_spec_sha256",
            "tools",
            "crt",
            "authority",
        ),
        "toolchain receipt",
    )
    if (
        receipt["schema"] != TOOLCHAIN_SCHEMA
        or receipt["profile"] != profile
        or receipt["target"] != TARGET
        or not _is_sha256(receipt["claimed_target_spec_sha256"])
        or receipt["authority"] != AUTHORITY_FALSE
    ):
        raise ContractError("toolchain receipt identity or authority drifted")
    tools = _exact_keys(receipt["tools"], ("cargo", "rustc", "linker", "archiver"), "toolchain tools")
    measured_tools: dict[str, Any] = {}
    for name in ("cargo", "rustc", "linker", "archiver"):
        entry = _exact_keys(tools[name], ("path", "sha256"), f"tool {name}")
        measured_tools[name] = _measure_tool(entry["path"], entry["sha256"], f"tool {name}")
    crt = _exact_keys(receipt["crt"], ("root", "files", "manifest_sha256"), "CRT closure")
    if not isinstance(crt["root"], str) or not crt["root"].startswith("/") or not _is_sha256(crt["manifest_sha256"]):
        raise ContractError("CRT root or manifest digest is invalid")
    root = Path(crt["root"])
    if not isinstance(crt["files"], list) or not 1 <= len(crt["files"]) <= MAX_CRT_FILES:
        raise ContractError("CRT closure count is outside its bound")
    required = {"crt1.o", "crti.o", "crtbegin.o", "crtend.o", "crtn.o", "libc.a", "libunwind.a"}
    observed_names: set[str] = set()
    observed_paths: list[str] = []
    total_bytes = 0
    validated: list[tuple[dict[str, Any], tuple[str, ...]]] = []
    for entry in crt["files"]:
        item = _exact_keys(entry, ("path", "sha256", "size"), "CRT file")
        components = _canonical_crt_relative_components(item["path"])
        size = item["size"]
        if (
            not _is_sha256(item["sha256"])
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 < size <= MAX_CRT_FILE_BYTES
        ):
            raise ContractError("CRT file record is invalid")
        total_bytes += size
        if total_bytes > MAX_CRT_TOTAL_BYTES:
            raise ContractError("CRT closure exceeds its aggregate byte bound")
        observed_paths.append(item["path"])
        basename = components[-1]
        if basename in observed_names:
            raise ContractError("CRT closure contains a duplicate basename")
        observed_names.add(basename)
        validated.append((item, components))
    if observed_paths != sorted(observed_paths) or len(observed_paths) != len(set(observed_paths)):
        raise ContractError("CRT closure paths must be sorted and unique")
    if not required <= observed_names:
        raise ContractError("CRT closure is missing a required runtime object")

    root_fd, root_metadata = _open_directory_path_retained(root, "CRT root")
    if root_metadata.st_mode & 0o222:
        os.close(root_fd)
        raise ContractError("CRT root must be read-only")
    manifest = hashlib.sha256()
    manifest.update(b"trillionnium.operation-replay-sync-static-crt.v1\0")
    try:
        for item, components in validated:
            descriptor, raw, metadata = _open_relative_regular_retained(
                root_fd,
                components,
                item["size"],
                f"CRT file {item['path']}",
                require_readonly=True,
            )
            try:
                if len(raw) != item["size"] or sha256_bytes(raw) != item["sha256"]:
                    raise ContractError(f"CRT file drifted: {item['path']}")
            finally:
                os.close(descriptor)
            manifest.update(item["path"].encode("ascii") + b"\0")
            manifest.update(str(len(raw)).encode("ascii") + b"\0")
            manifest.update(bytes.fromhex(item["sha256"]))
        _revalidate_directory_path(root, root_fd, root_metadata, "CRT root")
    finally:
        os.close(root_fd)
    if manifest.hexdigest() != crt["manifest_sha256"]:
        raise ContractError("CRT closure manifest drifted")
    return receipt, receipt_sha, measured_tools


def _load_image_receipt(path: Path, profile: str, expected_arch: str) -> tuple[dict[str, Any], str]:
    receipt, receipt_sha = load_json(path, "builder image receipt")
    _exact_keys(
        receipt,
        (
            "schema",
            "profile",
            "host_arch",
            "claimed_image_id",
            "invocation_id",
            "network_mode",
            "rootfs_read_only",
            "authority",
        ),
        "builder image receipt",
    )
    image_id = receipt["claimed_image_id"]
    if (
        receipt["schema"] != IMAGE_SCHEMA
        or receipt["profile"] != profile
        or receipt["host_arch"] != expected_arch
        or not isinstance(image_id, str)
        or not image_id.startswith("sha256:")
        or not _is_sha256(image_id[7:])
        or not isinstance(receipt["invocation_id"], str)
        or not receipt["invocation_id"]
        or receipt["network_mode"] != "none"
        or receipt["rootfs_read_only"] is not True
        or receipt["authority"] != AUTHORITY_FALSE
    ):
        raise ContractError("builder image receipt is not an exact non-authorizing lane receipt")
    return receipt, receipt_sha


def _write_new(path: Path, data: bytes, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ContractError(f"short write: {path}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _inode_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _stable_directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
    )


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_retained_fd(descriptor: int, limit: int, label: str) -> tuple[bytes, os.stat_result]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink not in (0, 1):
        raise ContractError(f"{label} retained FD is not a regular candidate")
    if before.st_size < 0 or before.st_size > limit:
        raise ContractError(f"{label} retained FD exceeds its byte limit")
    chunks: list[bytes] = []
    offset = 0
    while offset < before.st_size:
        chunk = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
        if not chunk:
            raise ContractError(f"{label} retained FD truncated")
        chunks.append(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, offset):
        raise ContractError(f"{label} retained FD grew")
    after = os.fstat(descriptor)
    if _stable_file_identity(before) != _stable_file_identity(after):
        raise ContractError(f"{label} retained FD changed while reading")
    return b"".join(chunks), after


def _open_directory_path_retained(path: Path, label: str) -> tuple[int, os.stat_result]:
    components = _absolute_components(path, label)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(os.sep, flags)
    except OSError as error:
        raise ContractError(f"could not retain {label} root: {error}") from error
    try:
        for component in components:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as error:
                raise ContractError(
                    f"could not component-open {label}: {error}"
                ) from error
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ContractError(f"{label} is not a directory")
        named = os.stat(path, follow_symlinks=False)
        if _inode_identity(named) != _inode_identity(metadata):
            raise ContractError(f"{label} named inode does not match its retained FD")
        return descriptor, metadata
    except BaseException:
        os.close(descriptor)
        raise


def _revalidate_directory_path(
    path: Path, descriptor: int, expected: os.stat_result, label: str
) -> None:
    current_fd = os.fstat(descriptor)
    if _stable_directory_identity(current_fd) != _stable_directory_identity(expected):
        raise ContractError(f"{label} retained directory identity drifted")
    rebound, rebound_metadata = _open_directory_path_retained(path, label)
    try:
        if _stable_directory_identity(rebound_metadata) != _stable_directory_identity(
            expected
        ):
            raise ContractError(f"{label} absolute path rebound")
    finally:
        os.close(rebound)


def _create_retained_tmpfile(
    parent_fd: int, data: bytes, mode: int, label: str
) -> tuple[int, os.stat_result]:
    if not hasattr(os, "O_TMPFILE"):
        raise ContractError("O_TMPFILE is unavailable")
    try:
        descriptor = os.open(
            ".",
            os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC,
            mode,
            dir_fd=parent_fd,
        )
    except OSError as error:
        raise ContractError(f"could not create retained {label}: {error}") from error
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ContractError(f"{label} O_TMPFILE write was short")
            view = view[written:]
        os.fsync(descriptor)
        observed, metadata = _read_retained_fd(descriptor, len(data), label)
        if observed != data or stat.S_IMODE(metadata.st_mode) != mode or metadata.st_nlink != 0:
            raise ContractError(f"{label} O_TMPFILE bytes/mode/link count drifted")
        return descriptor, metadata
    except BaseException:
        os.close(descriptor)
        raise


def _linkat_empty_noreplace(source_fd: int, destination_fd: int, name: str) -> None:
    if not name or name in (".", "..") or "/" in name or "\0" in name:
        raise ContractError("publication leaf name is invalid")
    libc = ctypes.CDLL(None, use_errno=True)
    linkat = libc.linkat
    linkat.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
    ]
    linkat.restype = ctypes.c_int
    if linkat(source_fd, b"", destination_fd, os.fsencode(name), AT_EMPTY_PATH) != 0:
        error = ctypes.get_errno()
        raise ContractError(f"no-replace retained-file publication failed: {os.strerror(error)}")


def _open_regular_at_retained(
    directory_fd: int, name: str, limit: int, label: str
) -> tuple[int, bytes, os.stat_result]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as error:
        raise ContractError(f"could not open retained {label}: {error}") from error
    try:
        data, metadata = _read_retained_fd(descriptor, limit, label)
        return descriptor, data, metadata
    except BaseException:
        os.close(descriptor)
        raise


def _open_absolute_regular_retained(
    path: Path, limit: int, label: str
) -> tuple[int, bytes, os.stat_result]:
    _absolute_components(path, label)
    if path.name in ("", ".", ".."):
        raise ContractError(f"{label} leaf name is invalid")
    parent_fd, _ = _open_directory_path_retained(path.parent, f"{label} parent")
    try:
        descriptor, raw, metadata = _open_regular_at_retained(
            parent_fd, path.name, limit, label
        )
        named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if _stable_file_identity(named) != _stable_file_identity(metadata):
            os.close(descriptor)
            raise ContractError(f"{label} named inode changed while opening")
        return descriptor, raw, metadata
    finally:
        os.close(parent_fd)


def _open_relative_regular_retained(
    root_fd: int,
    components: tuple[str, ...],
    limit: int,
    label: str,
    *,
    require_readonly: bool,
) -> tuple[int, bytes, os.stat_result]:
    if not components:
        raise ContractError(f"{label} relative path is empty")
    directory_fd = os.dup(root_fd)
    directory_flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        for component in components[:-1]:
            try:
                child = os.open(component, directory_flags, dir_fd=directory_fd)
            except OSError as error:
                raise ContractError(
                    f"could not component-open {label}: {error}"
                ) from error
            os.close(directory_fd)
            directory_fd = child
            metadata = os.fstat(directory_fd)
            if require_readonly and metadata.st_mode & 0o222:
                raise ContractError(f"{label} parent directory is writable")
        descriptor, raw, metadata = _open_regular_at_retained(
            directory_fd, components[-1], limit, label
        )
        if require_readonly and metadata.st_mode & 0o222:
            os.close(descriptor)
            raise ContractError(f"{label} is writable")
        return descriptor, raw, metadata
    finally:
        os.close(directory_fd)


def _retain_absent_absolute_leaf(
    path: Path, label: str
) -> tuple[int, os.stat_result]:
    _absolute_components(path, label)
    if path.name in ("", ".", ".."):
        raise ContractError(f"{label} leaf name is invalid")
    parent_fd, parent_metadata = _open_directory_path_retained(
        path.parent, f"{label} parent"
    )
    try:
        try:
            os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return parent_fd, parent_metadata
        raise ContractError(f"{label} must not preexist")
    except BaseException:
        os.close(parent_fd)
        raise


def _mkdirat_private(directory_fd: int, name: str) -> None:
    """Create a private directory with an exact mode despite ambient umask.

    The builder is deliberately single-threaded and starts no helper thread;
    fixing and immediately restoring umask therefore cannot affect a
    concurrent in-process file creation.
    """

    previous = os.umask(0o077)
    try:
        os.mkdir(name, mode=0o700, dir_fd=directory_fd)
    finally:
        os.umask(previous)


def _require_exact_directory_entries(
    directory_fd: int, expected: Iterable[str], label: str
) -> None:
    expected_names = sorted(expected)
    try:
        observed = sorted(os.listdir(directory_fd))
    except OSError as error:
        raise ContractError(f"could not enumerate retained {label}: {error}") from error
    if observed != expected_names:
        raise ContractError(
            f"{label} entries drifted: expected={expected_names!r} observed={observed!r}"
        )


def _revalidate_linked_file(
    directory_fd: int,
    name: str,
    retained_fd: int,
    expected_data: bytes,
    expected_mode: int,
    label: str,
) -> None:
    named_fd, named_data, named_metadata = _open_regular_at_retained(
        directory_fd, name, max(len(expected_data), 1), label
    )
    try:
        retained_metadata = os.fstat(retained_fd)
        if (
            _inode_identity(named_metadata) != _inode_identity(retained_metadata)
            or named_metadata.st_nlink != 1
            or stat.S_IMODE(named_metadata.st_mode) != expected_mode
            or named_metadata.st_uid != os.geteuid()
            or named_metadata.st_gid != os.getegid()
            or named_data != expected_data
        ):
            raise ContractError(f"{label} named inode/bytes/mode drifted")
        os.fsync(named_fd)
    finally:
        os.close(named_fd)


def _publish_retained_bundle(
    output: Path,
    parent_fd: int,
    parent_identity: os.stat_result,
    files: list[tuple[str, bytes, int]],
) -> None:
    """Publish a no-replace directory from retained anonymous file inodes.

    The final directory is created directly with mkdirat. A crash after that
    point leaves a durable partial/commit-unknown directory which future runs
    refuse; no rollback or overwrite is attempted.
    """

    if (
        not output.name
        or output.name in (".", "..")
        or "/" in output.name
        or "\0" in output.name
    ):
        raise ContractError("output bundle leaf name is invalid")
    names = [name for name, _data, _mode in files]
    if not files or len(names) != len(set(names)):
        raise ContractError("bundle files must be non-empty with unique leaf names")
    for name, data, mode in files:
        if (
            not name
            or name in (".", "..")
            or "/" in name
            or "\0" in name
            or mode not in (0o444, 0o555)
            or not isinstance(data, bytes)
            or len(data) > MAX_ELF_BYTES
        ):
            raise ContractError(f"bundle candidate contract is invalid: {name!r}")
    _revalidate_directory_path(output.parent, parent_fd, parent_identity, "output parent")
    candidates: list[tuple[str, bytes, int, int]] = []
    bundle_fd: int | None = None
    primary_error: BaseException | None = None
    try:
        for name, data, mode in files:
            candidate_fd, _ = _create_retained_tmpfile(
                parent_fd, data, mode, f"bundle candidate {name}"
            )
            candidates.append((name, data, mode, candidate_fd))
        _mkdirat_private(parent_fd, output.name)
        bundle_fd = os.open(
            output.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        os.fchmod(bundle_fd, 0o700)
        bundle_identity = os.fstat(bundle_fd)
        named_bundle = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(named_bundle.st_mode)
            or _stable_directory_identity(named_bundle)
            != _stable_directory_identity(bundle_identity)
            or stat.S_IMODE(bundle_identity.st_mode) != 0o700
            or bundle_identity.st_uid != os.geteuid()
            or bundle_identity.st_gid != os.getegid()
        ):
            raise ContractError("published bundle directory identity/mode drifted")
        os.fsync(bundle_fd)
        os.fsync(parent_fd)
        _PUBLICATION_PRE_LINK_BARRIER(output, parent_fd, bundle_fd)
        for name, data, mode, candidate_fd in candidates:
            _linkat_empty_noreplace(candidate_fd, bundle_fd, name)
            _revalidate_linked_file(
                bundle_fd, name, candidate_fd, data, mode, f"published {name}"
            )
        _require_exact_directory_entries(bundle_fd, names, "published bundle")
        os.fsync(bundle_fd)
        os.fsync(parent_fd)
        _revalidate_directory_path(output.parent, parent_fd, parent_identity, "output parent")
        rebound_fd, rebound_identity = _open_directory_path_retained(
            output, "published bundle"
        )
        try:
            if _stable_directory_identity(rebound_identity) != _stable_directory_identity(
                bundle_identity
            ):
                raise ContractError("published bundle path rebound")
            _require_exact_directory_entries(rebound_fd, names, "final bundle")
            for name, data, mode, candidate_fd in candidates:
                _revalidate_linked_file(
                    rebound_fd, name, candidate_fd, data, mode, f"final {name}"
                )
            os.fsync(rebound_fd)
        finally:
            os.close(rebound_fd)
        os.fsync(parent_fd)
    except BaseException as error:
        primary_error = error
    cleanup_errors: list[BaseException] = []
    if bundle_fd is not None:
        try:
            os.close(bundle_fd)
        except BaseException as error:
            cleanup_errors.append(error)
    for _name, _data, _mode, candidate_fd in candidates:
        try:
            os.close(candidate_fd)
        except BaseException as error:
            cleanup_errors.append(error)
    if cleanup_errors:
        raise ContractError(
            "retained bundle publication close failed: "
            + "; ".join(str(error) for error in cleanup_errors)
        ) from primary_error
    if primary_error is not None:
        if isinstance(primary_error, ContractError):
            raise primary_error
        raise ContractError(
            f"retained bundle publication failed: {primary_error}"
        ) from primary_error


def _receipt_id(document: dict[str, Any], domain: bytes) -> str:
    copy = dict(document)
    copy.pop("receipt_id", None)
    digest = hashlib.sha256()
    digest.update(domain + b"\0")
    digest.update(canonical_json_bytes(copy))
    return digest.hexdigest()


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError as error:
        raise ContractError("cannot inspect the isolated build process group") from error
    return True


def _kill_group_and_reap(
    process: subprocess.Popen[bytes],
    process_group: int,
    pidfd: int | None,
    *,
    failure: bool,
) -> None:
    """Boundedly eliminate the child and every member of its new session."""

    group_was_live = _process_group_exists(process_group)
    if failure or process.returncode is None or group_was_live:
        if group_was_live:
            try:
                os.killpg(process_group, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if pidfd is not None and hasattr(signal, "pidfd_send_signal"):
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired as error:
            raise ContractError("isolated build child could not be reaped") from error
    else:
        # `poll` reaps on POSIX, but call wait to make that contract explicit.
        process.wait(timeout=1)
    deadline = time.monotonic() + 5
    while _process_group_exists(process_group):
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            break
        if time.monotonic() >= deadline:
            raise ContractError("isolated build descendants survived SIGKILL/reap")
        time.sleep(0.01)


def _bounded_build(command: list[str], cwd: Path, environment: dict[str, str], log_path: Path) -> dict[str, Any]:
    descriptor = os.open(
        log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
    )
    process: subprocess.Popen[bytes] | None = None
    process_group: int | None = None
    pidfd: int | None = None
    selector: selectors.BaseSelector | None = None
    return_code: int | None = None
    primary_error: BaseException | None = None
    cleanup_errors: list[BaseException] = []
    try:
        os.fchmod(descriptor, 0o600)
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            close_fds=True,
            start_new_session=True,
            umask=0o077,
        )
        # From the first instruction after Popen returns, every operation is
        # inside this try/finally. The child owns a stable new session/PGID;
        # pidfd additionally pins the leader identity when the host supports it.
        process_group = process.pid
        if os.getpgid(process.pid) != process_group:
            raise ContractError("build child did not enter its fixed process group")
        if hasattr(os, "pidfd_open"):
            pidfd = os.pidfd_open(process.pid, 0)
        _PROCESS_OBSERVER(process)
        if process.stdout is None:  # pragma: no cover - Popen contract.
            raise ContractError("Cargo build log pipe is absent")
        selector = _SELECTOR_FACTORY()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 3600
        log_bytes = 0
        pipe_open = True
        while pipe_open or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ContractError("offline Cargo build exceeded its deadline")
            events = selector.select(timeout=min(1.0, remaining)) if pipe_open else []
            for key, _ in events:
                chunk = _READ_FD(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    pipe_open = False
                    continue
                log_bytes += len(chunk)
                if log_bytes > MAX_BUILD_LOG_BYTES:
                    raise ContractError("offline Cargo build log exceeded its byte limit")
                view = memoryview(chunk)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise ContractError("Cargo build log write was short")
                    view = view[written:]
        return_code = process.wait(
            timeout=min(30.0, max(0.1, deadline - time.monotonic()))
        )
        os.fsync(descriptor)
    except BaseException as error:
        primary_error = error
    finally:
        if process is not None and process_group is not None:
            try:
                _kill_group_and_reap(
                    process,
                    process_group,
                    pidfd,
                    failure=primary_error is not None,
                )
            except BaseException as error:
                cleanup_errors.append(error)
        if selector is not None:
            try:
                selector.close()
            except BaseException as error:
                cleanup_errors.append(error)
        if process is not None and process.stdout is not None:
            try:
                process.stdout.close()
            except BaseException as error:
                cleanup_errors.append(error)
        if pidfd is not None:
            try:
                os.close(pidfd)
            except BaseException as error:
                cleanup_errors.append(error)
        try:
            _CLOSE_FD(descriptor)
        except BaseException as error:
            cleanup_errors.append(error)
    if cleanup_errors:
        details = "; ".join(str(error) for error in cleanup_errors)
        raise ContractError(f"isolated build cleanup/reap failed: {details}") from primary_error
    if primary_error is not None:
        if isinstance(primary_error, ContractError):
            raise primary_error
        raise ContractError(f"isolated build I/O failed: {primary_error}") from primary_error
    if return_code is None:
        raise ContractError("isolated build produced no exit status")
    raw, _ = read_regular(log_path, MAX_BUILD_LOG_BYTES, "Cargo build log")
    if return_code != 0:
        raise ContractError(f"offline Cargo build failed with exit code {return_code}")
    return {"sha256": sha256_bytes(raw), "size": len(raw), "exit_code": return_code}


def _normalize_host_arch(value: str) -> str:
    if value in ("x86_64", "amd64"):
        return "x86_64"
    if value in ("aarch64", "arm64"):
        return "aarch64"
    return value


def _reject_ancestor_cargo_configuration(source_root: Path) -> None:
    for ancestor in (source_root, *source_root.parents):
        for name in ("config", "config.toml"):
            candidate = ancestor / ".cargo" / name
            if candidate.exists() or candidate.is_symlink():
                raise ContractError(
                    f"source/cwd ancestry contains ambient Cargo configuration: {candidate}"
                )


def _role_binding(role: str, role_config: dict[str, Any], artifact_sha: str, source_sha: str) -> str:
    digest = hashlib.sha256()
    digest.update(b"trillionnium.operation-replay-sync-static-role-binding.v1\0")
    for value in (role, role_config["cargo_bin"], role_config["filename"], role_config["entry_source"], source_sha, artifact_sha):
        digest.update(value.encode("utf-8") + b"\0")
    return digest.hexdigest()


def build_candidate(args: argparse.Namespace) -> dict[str, Any]:
    if not args.acknowledge_non_authorizing_source_only:
        raise ContractError("candidate build requires the explicit non-authorizing acknowledgement")
    if not _PUBLIC_CANDIDATE_EXECUTION_ENABLED:
        raise ContractError(
            "candidate execution is fixed HOLD until an outer-owned cgroup-v2 "
            "zero-survivor boundary, fixed-custody durable publication journal, "
            "and external permanent-HOLD path exist"
        )
    recipe, recipe_sha = load_recipe(args.recipe)
    if recipe["build_contract"]["candidate_execution_enabled"] is not True:
        raise ContractError(
            "candidate execution is fixed HOLD until an outer-owned cgroup-v2 "
            "zero-survivor boundary and durable publication journal exist"
        )
    profile = args.profile
    expected_arch = recipe["profiles"][profile]["host_arch"]
    if _normalize_host_arch(platform.machine()) != expected_arch:
        raise ContractError("current host architecture does not match the selected profile")
    for candidate, label in (
        (args.source_root, "source root"),
        (args.vendor_dir, "Cargo vendor root"),
        (args.toolchain_receipt, "toolchain receipt"),
        (args.image_receipt, "image receipt"),
        (args.output, "output bundle"),
    ):
        if not candidate.is_absolute():
            raise ContractError(f"{label} path must be absolute")
    if args.source_root.is_symlink() or args.vendor_dir.is_symlink():
        raise ContractError("source and Cargo vendor roots cannot be symlinks")
    source_root = args.source_root.resolve(strict=True)
    vendor_root = args.vendor_dir.resolve(strict=True)
    output = args.output
    for root, label in ((source_root, "source snapshot"), (vendor_root, "Cargo vendor snapshot")):
        if not root.is_dir() or root.is_symlink():
            raise ContractError(f"{label} is not a real directory")
    if source_root == vendor_root or source_root in vendor_root.parents or vendor_root in source_root.parents:
        raise ContractError("source and vendor snapshots must be disjoint")
    if source_root in output.parents or vendor_root in output.parents:
        raise ContractError("output must not be within an input snapshot")
    _reject_ancestor_cargo_configuration(source_root)
    image, image_sha = _load_image_receipt(args.image_receipt, profile, expected_arch)
    toolchain, toolchain_sha, measured_tools = _load_toolchain_receipt(args.toolchain_receipt, profile)

    source_contract = recipe["source_contract"]
    for relative, expected in source_contract["fixed_files"].items():
        raw, _ = read_regular(source_root / relative, MAX_FILE_BYTES, f"fixed source {relative}")
        if sha256_bytes(raw) != expected:
            raise ContractError(f"fixed source drifted: {relative}")
    lock_raw, _ = read_regular(source_root / "Cargo.lock", MAX_FILE_BYTES, "Cargo.lock")
    if sha256_bytes(lock_raw) != source_contract["cargo_lock_sha256"]:
        raise ContractError("Cargo.lock drifted from the recipe")
    source_before = _tree_manifest(source_root, "source snapshot", require_readonly=True)
    vendor_before = _tree_manifest(vendor_root, "Cargo vendor snapshot", require_readonly=True)

    parent_fd, parent_identity = _retain_absent_absolute_leaf(
        output, "output bundle"
    )
    if (
        parent_identity.st_uid != os.geteuid()
        or parent_identity.st_gid != os.getegid()
        or stat.S_IMODE(parent_identity.st_mode) != 0o700
    ):
        os.close(parent_fd)
        raise ContractError(
            "output parent must be current-user/group-owned mode 0700"
        )
    work_fd: int | None = None
    work: Path | None = None
    work_identity: os.stat_result | None = None
    try:
        for _attempt in range(64):
            work_name = f".operation-replay-sync-static.{secrets.token_hex(16)}"
            try:
                _mkdirat_private(parent_fd, work_name)
            except FileExistsError:
                continue
            work = output.parent / work_name
            work_fd = os.open(
                work_name,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
            os.fchmod(work_fd, 0o700)
            work_identity = os.fstat(work_fd)
            named_work = os.stat(work_name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                _inode_identity(named_work) != _inode_identity(work_identity)
                or stat.S_IMODE(work_identity.st_mode) != 0o700
            ):
                raise ContractError("private work directory identity/mode drifted")
            os.fsync(work_fd)
            os.fsync(parent_fd)
            break
        else:
            raise ContractError("could not allocate a unique private work directory")
        assert work is not None and work_fd is not None and work_identity is not None
        cargo_home = work / "cargo-home"
        target_dir = work / "target"
        cargo_home.mkdir(mode=0o700)
        target_dir.mkdir(mode=0o700)
        os.chmod(cargo_home, 0o700)
        os.chmod(target_dir, 0o700)
        config_text = (
            "[source.crates-io]\nreplace-with = \"vendored-sources\"\n"
            "[source.vendored-sources]\ndirectory = "
            + json.dumps(str(vendor_root))
            + "\n[net]\noffline = true\n"
        ).encode("utf-8")
        _write_new(cargo_home / "config.toml", config_text)
        remap = recipe["build_contract"]["path_remap_root"]
        rustflags = [
            "-Ctarget-feature=+crt-static",
            "-Crelocation-model=static",
            "-Clink-arg=-static",
            "-Clink-arg=-no-pie",
            "-Clink-arg=-Wl,-z,max-page-size=65536",
            "-Clink-arg=-Wl,-z,noexecstack",
            "-Clink-arg=-Wl,-z,relro,-z,now",
            "-Clink-arg=-Wl,--build-id=sha1",
            f"--remap-path-prefix={source_root}={remap}",
            f"--remap-path-prefix={vendor_root}=/usr/src/cargo-vendor",
            f"--remap-path-prefix={work}=/usr/src/build",
        ]
        tool_paths = {name: value["path"] for name, value in measured_tools.items()}
        environment = {
            "HOME": str(cargo_home),
            "PATH": os.pathsep.join(sorted({str(Path(path).parent) for path in tool_paths.values()})),
            "LC_ALL": "C",
            "LANG": "C",
            "TZ": "UTC",
            "SOURCE_DATE_EPOCH": str(recipe["source_date_epoch"]),
            "CARGO_NET_OFFLINE": "true",
            "CARGO_HOME": str(cargo_home),
            "CARGO_TARGET_DIR": str(target_dir),
            "RUSTC": tool_paths["rustc"],
            "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(rustflags),
            "CARGO_PROFILE_RELEASE_OPT_LEVEL": "3",
            "CARGO_PROFILE_RELEASE_DEBUG": "0",
            "CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS": "false",
            "CARGO_PROFILE_RELEASE_INCREMENTAL": "false",
            "CARGO_PROFILE_RELEASE_STRIP": "symbols",
            "CARGO_PROFILE_RELEASE_PANIC": "abort",
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER": tool_paths["linker"],
            "CC_aarch64_unknown_linux_musl": tool_paths["linker"],
            "AR_aarch64_unknown_linux_musl": tool_paths["archiver"],
        }
        cargo = recipe["cargo"]
        command = [
            tool_paths["cargo"],
            "build",
            "--release",
            "--locked",
            "--offline",
            "--no-default-features",
            "--features",
            cargo["feature"],
            "--target",
            TARGET,
            "--package",
            cargo["package"],
        ]
        for binary in cargo["bins"]:
            command.extend(("--bin", binary))
        log = _bounded_build(command, source_root, environment, work / "cargo.log")
        source_after = _tree_manifest(source_root, "source snapshot", require_readonly=True)
        vendor_after = _tree_manifest(vendor_root, "Cargo vendor snapshot", require_readonly=True)
        if source_before != source_after or vendor_before != vendor_after:
            raise ContractError("source or Cargo vendor snapshot changed during the build")
        image_after, image_sha_after = _load_image_receipt(
            args.image_receipt, profile, expected_arch
        )
        toolchain_after, toolchain_sha_after, measured_tools_after = (
            _load_toolchain_receipt(args.toolchain_receipt, profile)
        )
        if (
            image_after != image
            or image_sha_after != image_sha
            or toolchain_after != toolchain
            or toolchain_sha_after != toolchain_sha
            or measured_tools_after != measured_tools
        ):
            raise ContractError(
                "image/toolchain receipt or measured tool closure drifted during the build"
            )

        artifacts: list[dict[str, Any]] = []
        artifact_bytes: dict[str, bytes] = {}
        artifact_hashes: set[str] = set()
        for role in ROLE_ORDER:
            role_config = recipe["roles"][role]
            built_path = target_dir / TARGET / "release" / role_config["filename"]
            raw, _ = read_regular(built_path, MAX_ELF_BYTES, f"built {role} helper")
            elf = inspect_elf_bytes(raw)
            artifact_bytes[role] = raw
            source_sha = source_contract["fixed_files"][role_config["entry_source"]]
            artifacts.append(
                {
                    "role": role,
                    "cargo_bin": role_config["cargo_bin"],
                    "filename": role_config["filename"],
                    "entry_source": role_config["entry_source"],
                    "entry_source_sha256": source_sha,
                    "sha256": elf["sha256"],
                    "size": elf["size"],
                    "mode": "0555",
                    "role_binding_sha256": _role_binding(role, role_config, elf["sha256"], source_sha),
                    "elf": elf,
                }
            )
            artifact_hashes.add(elf["sha256"])
        if len(artifact_hashes) != len(ROLE_ORDER):
            raise ContractError("the two fixed roles produced interchangeable bytes")
        inputs = {
            "recipe_sha256": recipe_sha,
            "source_tree": source_before,
            "cargo_lock_sha256": sha256_bytes(lock_raw),
            "vendor_tree": vendor_before,
            "toolchain_receipt_sha256": toolchain_sha,
            "claimed_target_spec_sha256": toolchain[
                "claimed_target_spec_sha256"
            ],
            "crt_manifest_sha256": toolchain["crt"]["manifest_sha256"],
            "image_receipt_sha256": image_sha,
            "claimed_image_id": image["claimed_image_id"],
        }
        receipt: dict[str, Any] = {
            "schema": BUILD_SCHEMA,
            "status": "SOURCE_ONLY_UNWIRED_CANDIDATE",
            "profile": profile,
            "target": TARGET,
            "inputs": inputs,
            "invocation": {
                "base_environment": "empty",
                "environment_keys": sorted(environment),
                "cargo_argv": command,
                "source_date_epoch": recipe["source_date_epoch"],
                "path_remap_root": remap,
                "cargo_locked": True,
                "cargo_offline": True,
                "cargo_release": True,
                "network_namespace_verified_by_builder": False,
                "compiler_read_set_bound": False,
                "hostile_same_uid_source_custody_proven": False,
                "toolchain_runtime_read_set_bound": False,
                "crt_link_read_set_bound": False,
                "builder_image_execution_bound": False,
                "outer_cgroup_v2_zero_survivor_verified": False,
                "durable_publication_journal_verified": False,
                "automatic_work_cleanup_performed": False,
                "work_retained_for_ephemeral_lane_cleanup": True,
                "log": log,
            },
            "artifacts": artifacts,
            "source_checkpoint": CHECKPOINT_FALSE,
            "authority": AUTHORITY_FALSE,
            "receipt_id": "",
        }
        receipt["receipt_id"] = _receipt_id(
            receipt, b"trillionnium.operation-replay-sync-static-build-receipt.v1"
        )
        receipt_bytes = canonical_json_bytes(receipt)
        publication_files = [
            (
                recipe["roles"][role]["filename"],
                artifact_bytes[role],
                0o555,
            )
            for role in ROLE_ORDER
        ]
        publication_files.append(("build-receipt.json", receipt_bytes, 0o444))
        _publish_retained_bundle(
            output, parent_fd, parent_identity, publication_files
        )
        _revalidate_directory_path(work, work_fd, work_identity, "private build work")
        return receipt
    finally:
        # Automatic recursive deletion is intentionally absent. POSIX has no
        # unlink-by-FD operation, so a hostile same-UID name race cannot be
        # made safe by pathname rmtree. The isolated/ephemeral lane owns final
        # cleanup after this process closes its retained work FD.
        finalization_errors: list[BaseException] = []
        if work_fd is not None:
            try:
                if work is None or work_identity is None:
                    raise ContractError("private build work custody is incomplete")
                _revalidate_directory_path(
                    work, work_fd, work_identity, "private build work"
                )
            except BaseException as error:
                finalization_errors.append(error)
            try:
                os.close(work_fd)
            except BaseException as error:
                finalization_errors.append(error)
        try:
            _revalidate_directory_path(
                output.parent, parent_fd, parent_identity, "output parent"
            )
        except BaseException as error:
            finalization_errors.append(error)
        try:
            os.close(parent_fd)
        except BaseException as error:
            finalization_errors.append(error)
        if finalization_errors:
            raise ContractError(
                "retained build directory finalization failed: "
                + "; ".join(str(error) for error in finalization_errors)
            )


def _validate_build_receipt_document(
    receipt: dict[str, Any],
    recipe: dict[str, Any],
    recipe_sha: str,
    artifact_loader: Any,
) -> dict[str, Any]:
    _exact_keys(
        receipt,
        (
            "schema",
            "status",
            "profile",
            "target",
            "inputs",
            "invocation",
            "artifacts",
            "source_checkpoint",
            "authority",
            "receipt_id",
        ),
        "build receipt",
    )
    if (
        receipt["schema"] != BUILD_SCHEMA
        or receipt["status"] != "SOURCE_ONLY_UNWIRED_CANDIDATE"
        or receipt["profile"] not in PROFILES
        or receipt["target"] != TARGET
        or receipt["source_checkpoint"] != CHECKPOINT_FALSE
        or receipt["authority"] != AUTHORITY_FALSE
        or receipt["receipt_id"]
        != _receipt_id(receipt, b"trillionnium.operation-replay-sync-static-build-receipt.v1")
    ):
        raise ContractError("build receipt identity, status, or authority drifted")
    inputs = _exact_keys(
        receipt["inputs"],
        (
            "recipe_sha256",
            "source_tree",
            "cargo_lock_sha256",
            "vendor_tree",
            "toolchain_receipt_sha256",
            "claimed_target_spec_sha256",
            "crt_manifest_sha256",
            "image_receipt_sha256",
            "claimed_image_id",
        ),
        "build inputs",
    )
    if inputs["recipe_sha256"] != recipe_sha:
        raise ContractError("build receipt recipe binding drifted")
    for key in (
        "cargo_lock_sha256",
        "toolchain_receipt_sha256",
        "claimed_target_spec_sha256",
        "crt_manifest_sha256",
        "image_receipt_sha256",
    ):
        if not _is_sha256(inputs[key]):
            raise ContractError(f"build input digest is invalid: {key}")
    if (
        inputs["cargo_lock_sha256"] != recipe["source_contract"]["cargo_lock_sha256"]
        or not isinstance(inputs["claimed_image_id"], str)
        or not inputs["claimed_image_id"].startswith("sha256:")
        or not _is_sha256(inputs["claimed_image_id"][7:])
    ):
        raise ContractError("Cargo.lock or image identity drifted")
    for tree_key in ("source_tree", "vendor_tree"):
        tree = _exact_keys(
            inputs[tree_key],
            (
                "schema",
                "file_count",
                "directory_count",
                "regular_bytes",
                "manifest_sha256",
                "readonly_mode_bits_verified",
                "symlinks_allowed",
                "compiler_read_set_bound",
                "hostile_same_uid_custody_proven",
            ),
            tree_key,
        )
        if (
            tree["schema"] != "trillionnium.operation-replay-sync-static-tree.v1"
            or any(
                not isinstance(tree[key], int) or isinstance(tree[key], bool) or tree[key] < 0
                for key in ("file_count", "directory_count", "regular_bytes")
            )
            or not _is_sha256(tree["manifest_sha256"])
            or tree["readonly_mode_bits_verified"] is not True
            or tree["symlinks_allowed"] is not False
            or tree["compiler_read_set_bound"] is not False
            or tree["hostile_same_uid_custody_proven"] is not False
        ):
            raise ContractError(f"{tree_key} facts drifted")
    invocation = _exact_keys(
        receipt["invocation"],
        (
            "base_environment",
            "environment_keys",
            "cargo_argv",
            "source_date_epoch",
            "path_remap_root",
            "cargo_locked",
            "cargo_offline",
            "cargo_release",
            "network_namespace_verified_by_builder",
            "compiler_read_set_bound",
            "hostile_same_uid_source_custody_proven",
            "toolchain_runtime_read_set_bound",
            "crt_link_read_set_bound",
            "builder_image_execution_bound",
            "outer_cgroup_v2_zero_survivor_verified",
            "durable_publication_journal_verified",
            "automatic_work_cleanup_performed",
            "work_retained_for_ephemeral_lane_cleanup",
            "log",
        ),
        "build invocation",
    )
    expected_environment_keys = sorted(
        {
            "HOME",
            "PATH",
            "LC_ALL",
            "LANG",
            "TZ",
            "SOURCE_DATE_EPOCH",
            "CARGO_NET_OFFLINE",
            "CARGO_HOME",
            "CARGO_TARGET_DIR",
            "RUSTC",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_PROFILE_RELEASE_OPT_LEVEL",
            "CARGO_PROFILE_RELEASE_DEBUG",
            "CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS",
            "CARGO_PROFILE_RELEASE_INCREMENTAL",
            "CARGO_PROFILE_RELEASE_STRIP",
            "CARGO_PROFILE_RELEASE_PANIC",
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER",
            "CC_aarch64_unknown_linux_musl",
            "AR_aarch64_unknown_linux_musl",
        }
    )
    expected_cargo_tail = [
        "build",
        "--release",
        "--locked",
        "--offline",
        "--no-default-features",
        "--features",
        recipe["cargo"]["feature"],
        "--target",
        TARGET,
        "--package",
        recipe["cargo"]["package"],
        "--bin",
        recipe["cargo"]["bins"][0],
        "--bin",
        recipe["cargo"]["bins"][1],
    ]
    if (
        invocation["base_environment"] != "empty"
        or invocation["environment_keys"] != expected_environment_keys
        or not isinstance(invocation["cargo_argv"], list)
        or len(invocation["cargo_argv"]) != len(expected_cargo_tail) + 1
        or not isinstance(invocation["cargo_argv"][0], str)
        or not invocation["cargo_argv"][0].startswith("/")
        or invocation["cargo_argv"][1:] != expected_cargo_tail
        or invocation["source_date_epoch"] != recipe["source_date_epoch"]
        or invocation["path_remap_root"] != recipe["build_contract"]["path_remap_root"]
        or invocation["cargo_locked"] is not True
        or invocation["cargo_offline"] is not True
        or invocation["cargo_release"] is not True
        or any(
            invocation[key] is not False
            for key in (
                "network_namespace_verified_by_builder",
                "compiler_read_set_bound",
                "hostile_same_uid_source_custody_proven",
                "toolchain_runtime_read_set_bound",
                "crt_link_read_set_bound",
                "builder_image_execution_bound",
                "outer_cgroup_v2_zero_survivor_verified",
                "durable_publication_journal_verified",
                "automatic_work_cleanup_performed",
            )
        )
        or invocation["work_retained_for_ephemeral_lane_cleanup"] is not True
    ):
        raise ContractError("build invocation posture drifted")
    log = _exact_keys(invocation["log"], ("sha256", "size", "exit_code"), "build log")
    if (
        not _is_sha256(log["sha256"])
        or not isinstance(log["size"], int)
        or isinstance(log["size"], bool)
        or not 0 <= log["size"] <= MAX_BUILD_LOG_BYTES
        or log["exit_code"] != 0
    ):
        raise ContractError("build log facts drifted")
    artifacts = receipt["artifacts"]
    if not isinstance(artifacts, list) or [item.get("role") for item in artifacts] != list(ROLE_ORDER):
        raise ContractError("build artifact role order drifted")
    hashes: set[str] = set()
    for item in artifacts:
        role = item["role"]
        role_config = recipe["roles"][role]
        expected_keys = {
            "role",
            "cargo_bin",
            "filename",
            "entry_source",
            "entry_source_sha256",
            "sha256",
            "size",
            "mode",
            "role_binding_sha256",
            "elf",
        }
        if not isinstance(item, dict) or set(item) != expected_keys:
            raise ContractError(f"artifact {role} fields drifted")
        source_sha = recipe["source_contract"]["fixed_files"][role_config["entry_source"]]
        if (
            item["cargo_bin"] != role_config["cargo_bin"]
            or item["filename"] != role_config["filename"]
            or item["entry_source"] != role_config["entry_source"]
            or item["entry_source_sha256"] != source_sha
        ):
            raise ContractError(f"artifact {role} source/bin binding drifted")
        artifact_raw, artifact_metadata = artifact_loader(
            role, item["filename"]
        )
        if stat.S_IMODE(artifact_metadata.st_mode) != 0o555 or item["mode"] != "0555":
            raise ContractError(f"artifact {role} mode drifted")
        elf = inspect_elf_bytes(artifact_raw)
        if elf != item["elf"] or elf["sha256"] != item["sha256"] or elf["size"] != item["size"]:
            raise ContractError(f"artifact {role} bytes or ELF receipt drifted")
        expected_binding = _role_binding(role, role_config, item["sha256"], source_sha)
        if item["role_binding_sha256"] != expected_binding:
            raise ContractError(f"artifact {role} role binding drifted")
        hashes.add(item["sha256"])
    if len(hashes) != len(ROLE_ORDER):
        raise ContractError("build roles are byte-interchangeable")
    return receipt


class _RetainedBuildBundle:
    """Hold a build receipt and both artifacts through the final barrier."""

    def __init__(self, receipt_path: Path, recipe: dict[str, Any], recipe_sha: str):
        self.receipt_path = receipt_path
        self.root_path = receipt_path.parent
        self.root_fd: int | None = None
        self.root_identity: os.stat_result | None = None
        self.receipt_fd: int | None = None
        self.receipt_raw: bytes | None = None
        self.receipt_metadata: os.stat_result | None = None
        self.artifact_files: dict[
            str, tuple[str, int, bytes, os.stat_result]
        ] = {}
        self.receipt: dict[str, Any] | None = None
        try:
            if not receipt_path.is_absolute() or receipt_path.name != "build-receipt.json":
                raise ContractError(
                    "build receipt must be the fixed absolute build-receipt.json path"
                )
            if self.root_path != self.root_path.resolve(strict=True):
                raise ContractError("build bundle root is not canonical")
            self.root_fd, self.root_identity = _open_directory_path_retained(
                self.root_path, "build bundle root"
            )
            if (
                self.root_identity.st_uid != os.geteuid()
                or self.root_identity.st_gid != os.getegid()
                or stat.S_IMODE(self.root_identity.st_mode) != 0o700
            ):
                raise ContractError(
                    "build bundle root must be current-user/group-owned mode 0700"
                )
            (
                self.receipt_fd,
                self.receipt_raw,
                self.receipt_metadata,
            ) = _open_regular_at_retained(
                self.root_fd,
                "build-receipt.json",
                MAX_JSON_BYTES,
                "static helper build receipt",
            )
            self._require_file_metadata(
                self.receipt_metadata, 0o444, "static helper build receipt"
            )
            parsed = _parse_canonical_json(
                self.receipt_raw, "static helper build receipt"
            )
            self.receipt = _validate_build_receipt_document(
                parsed, recipe, recipe_sha, self._load_artifact
            )
            _require_exact_directory_entries(
                self.root_fd,
                ("build-receipt.json",)
                + tuple(value[0] for value in self.artifact_files.values()),
                "build bundle root",
            )
        except BaseException:
            self._close_silent()
            raise

    @staticmethod
    def _require_file_metadata(
        metadata: os.stat_result, expected_mode: int, label: str
    ) -> None:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or stat.S_IMODE(metadata.st_mode) != expected_mode
        ):
            raise ContractError(
                f"{label} must be a current-user/group-owned single-link "
                f"mode-{expected_mode:04o} regular file"
            )

    def _load_artifact(
        self, role: str, filename: str
    ) -> tuple[bytes, os.stat_result]:
        if role in self.artifact_files:
            raise ContractError(f"artifact role was opened twice: {role}")
        if (
            not filename
            or filename in (".", "..")
            or "/" in filename
            or "\0" in filename
        ):
            raise ContractError(f"artifact {role} filename is invalid")
        assert self.root_fd is not None
        descriptor, raw, metadata = _open_regular_at_retained(
            self.root_fd, filename, MAX_ELF_BYTES, f"artifact {role}"
        )
        try:
            self._require_file_metadata(metadata, 0o555, f"artifact {role}")
        except BaseException:
            os.close(descriptor)
            raise
        self.artifact_files[role] = (filename, descriptor, raw, metadata)
        return raw, metadata

    def final_barrier(self) -> None:
        if (
            self.root_fd is None
            or self.root_identity is None
            or self.receipt_fd is None
            or self.receipt_raw is None
            or self.receipt_metadata is None
            or self.receipt is None
        ):
            raise ContractError("retained build bundle is incomplete")
        _revalidate_directory_path(
            self.root_path, self.root_fd, self.root_identity, "build bundle root"
        )
        expected_entries = ("build-receipt.json",) + tuple(
            value[0] for value in self.artifact_files.values()
        )
        _require_exact_directory_entries(
            self.root_fd, expected_entries, "build bundle root"
        )
        retained_receipt, retained_receipt_metadata = _read_retained_fd(
            self.receipt_fd, MAX_JSON_BYTES, "retained build receipt"
        )
        if (
            retained_receipt != self.receipt_raw
            or _stable_file_identity(retained_receipt_metadata)
            != _stable_file_identity(self.receipt_metadata)
        ):
            raise ContractError("retained build receipt changed before final barrier")
        _revalidate_linked_file(
            self.root_fd,
            "build-receipt.json",
            self.receipt_fd,
            self.receipt_raw,
            0o444,
            "final build receipt",
        )
        for role in ROLE_ORDER:
            if role not in self.artifact_files:
                raise ContractError(f"retained artifact is missing: {role}")
            filename, descriptor, expected_raw, expected_metadata = self.artifact_files[
                role
            ]
            retained_raw, retained_metadata = _read_retained_fd(
                descriptor, MAX_ELF_BYTES, f"retained artifact {role}"
            )
            if (
                retained_raw != expected_raw
                or _stable_file_identity(retained_metadata)
                != _stable_file_identity(expected_metadata)
            ):
                raise ContractError(f"retained artifact changed: {role}")
            _revalidate_linked_file(
                self.root_fd,
                filename,
                descriptor,
                expected_raw,
                0o555,
                f"final artifact {role}",
            )
        _revalidate_directory_path(
            self.root_path, self.root_fd, self.root_identity, "build bundle root"
        )
        _require_exact_directory_entries(
            self.root_fd, expected_entries, "final build bundle root"
        )

    def _close_silent(self) -> None:
        descriptors = [
            value[1] for value in self.artifact_files.values()
        ]
        if self.receipt_fd is not None:
            descriptors.append(self.receipt_fd)
        if self.root_fd is not None:
            descriptors.append(self.root_fd)
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        self.artifact_files.clear()
        self.receipt_fd = None
        self.root_fd = None

    def close(self) -> None:
        errors: list[BaseException] = []
        descriptors = [value[1] for value in self.artifact_files.values()]
        if self.receipt_fd is not None:
            descriptors.append(self.receipt_fd)
        if self.root_fd is not None:
            descriptors.append(self.root_fd)
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except BaseException as error:
                errors.append(error)
        self.artifact_files.clear()
        self.receipt_fd = None
        self.root_fd = None
        if errors:
            raise ContractError(
                "retained build bundle close failed: "
                + "; ".join(str(error) for error in errors)
            )


def _verify_build_receipt(
    path: Path, recipe: dict[str, Any], recipe_sha: str
) -> dict[str, Any]:
    bundle: _RetainedBuildBundle | None = None
    primary_error: BaseException | None = None
    result: dict[str, Any] | None = None
    try:
        bundle = _RetainedBuildBundle(path, recipe, recipe_sha)
        bundle.final_barrier()
        result = bundle.receipt
    except BaseException as error:
        primary_error = error
    close_error: BaseException | None = None
    if bundle is not None:
        try:
            bundle.close()
        except BaseException as error:
            close_error = error
    if close_error is not None:
        raise ContractError(f"build bundle close failed: {close_error}") from primary_error
    if primary_error is not None:
        if isinstance(primary_error, ContractError):
            raise primary_error
        raise ContractError(f"build bundle verification failed: {primary_error}") from primary_error
    assert result is not None
    return result


def reconcile_receipts(
    recipe_path: Path, amd64_path: Path, arm64_path: Path
) -> dict[str, Any]:
    recipe, recipe_sha = load_recipe(recipe_path)
    left_bundle: _RetainedBuildBundle | None = None
    right_bundle: _RetainedBuildBundle | None = None
    document: dict[str, Any] | None = None
    primary_error: BaseException | None = None
    try:
        left_bundle = _RetainedBuildBundle(amd64_path, recipe, recipe_sha)
        right_bundle = _RetainedBuildBundle(arm64_path, recipe, recipe_sha)
        left = left_bundle.receipt
        right = right_bundle.receipt
        assert left is not None and right is not None
        if left["profile"] != "amd64-cross" or right["profile"] != "arm64-native":
            raise ContractError(
                "reconcile receipt profiles are missing, duplicated, or reversed"
            )
        equal_input_keys = (
            "recipe_sha256",
            "source_tree",
            "cargo_lock_sha256",
            "vendor_tree",
            "claimed_target_spec_sha256",
            "crt_manifest_sha256",
        )
        for key in equal_input_keys:
            if left["inputs"].get(key) != right["inputs"].get(key):
                raise ContractError(f"cross-profile input drifted: {key}")
        artifact_pairs: list[dict[str, Any]] = []
        left_by_role = {item["role"]: item for item in left["artifacts"]}
        right_by_role = {item["role"]: item for item in right["artifacts"]}
        for role in ROLE_ORDER:
            left_item = left_by_role[role]
            right_item = right_by_role[role]
            left_raw = left_bundle.artifact_files[role][2]
            right_raw = right_bundle.artifact_files[role][2]
            if (
                left_raw != right_raw
                or left_item["sha256"] != right_item["sha256"]
                or left_item["size"] != right_item["size"]
            ):
                raise ContractError(
                    f"role {role} is not byte-identical across profiles"
                )
            artifact_pairs.append(
                {
                    "role": role,
                    "sha256": left_item["sha256"],
                    "size": left_item["size"],
                    "amd64_role_binding_sha256": left_item[
                        "role_binding_sha256"
                    ],
                    "arm64_role_binding_sha256": right_item[
                        "role_binding_sha256"
                    ],
                    "byte_identical": True,
                }
            )
        if (
            left_by_role["system-api"]["sha256"]
            == left_by_role["accessibility"]["sha256"]
        ):
            raise ContractError("fixed roles are interchangeable")
        if (
            left_by_role["system-api"]["sha256"]
            == right_by_role["accessibility"]["sha256"]
        ):
            raise ContractError("cross-profile role exchange was detected")
        if (
            left_by_role["accessibility"]["sha256"]
            == right_by_role["system-api"]["sha256"]
        ):
            raise ContractError("cross-profile role exchange was detected")

        # Both roots, both receipt FDs and all four artifact FDs remain open
        # through this final barrier. A same-UID name swap after semantic
        # verification therefore cannot create an A/B split-view result.
        _RECONCILE_PRE_FINAL_BARRIER(left_bundle, right_bundle)
        left_bundle.final_barrier()
        right_bundle.final_barrier()
        document = {
            "schema": RECONCILE_SCHEMA,
            "status": "PREVIEW_SOURCE_ONLY_UNWIRED_BYTE_RECONCILIATION",
            "profiles": ["amd64-cross", "arm64-native"],
            "recipe_sha256": recipe_sha,
            "build_receipt_ids": [left["receipt_id"], right["receipt_id"]],
            "input_equivalence_keys": list(equal_input_keys),
            "artifacts": artifact_pairs,
            "same_role_byte_identical": True,
            "cross_role_byte_distinct": True,
            "role_exchange_forbidden": True,
            "durable_publication": False,
            "fixed_custody_journal_verified": False,
            "source_checkpoint": CHECKPOINT_FALSE,
            "authority": AUTHORITY_FALSE,
            "receipt_id": "",
        }
        document["receipt_id"] = _receipt_id(
            document, b"trillionnium.operation-replay-sync-static-reconcile.v1"
        )
    except BaseException as error:
        primary_error = error

    close_errors: list[BaseException] = []
    for bundle in (right_bundle, left_bundle):
        if bundle is not None:
            try:
                bundle.close()
            except BaseException as error:
                close_errors.append(error)
    if close_errors:
        raise ContractError(
            "reconcile retained-bundle close failed: "
            + "; ".join(str(error) for error in close_errors)
        ) from primary_error
    if primary_error is not None:
        if isinstance(primary_error, ContractError):
            raise primary_error
        raise ContractError(f"reconcile verification failed: {primary_error}") from primary_error
    assert document is not None
    return document


def _write_optional_output(path: Path | None, document: dict[str, Any]) -> None:
    raw = canonical_json_bytes(document)
    if path is not None:
        raise ContractError(
            "persistent reconcile publication is fixed HOLD until the fixed "
            "custody journal and external permanent-HOLD path exist"
        )
    sys.stdout.buffer.write(raw)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--recipe",
        type=Path,
        default=Path(__file__).with_name("operation-replay-sync-static-recipe-v1.json"),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("verify-recipe")
    inspect_parser = subparsers.add_parser("inspect-elf")
    inspect_parser.add_argument("artifact", type=Path)
    build_parser = subparsers.add_parser("build-candidate")
    build_parser.add_argument("--profile", choices=PROFILES, required=True)
    build_parser.add_argument("--source-root", type=Path, required=True)
    build_parser.add_argument("--vendor-dir", type=Path, required=True)
    build_parser.add_argument("--toolchain-receipt", type=Path, required=True)
    build_parser.add_argument("--image-receipt", type=Path, required=True)
    build_parser.add_argument("--output", type=Path, required=True)
    build_parser.add_argument("--acknowledge-non-authorizing-source-only", action="store_true")
    verify_parser = subparsers.add_parser("verify-build")
    verify_parser.add_argument("receipt", type=Path)
    reconcile_parser = subparsers.add_parser("reconcile")
    reconcile_parser.add_argument("--amd64-receipt", type=Path, required=True)
    reconcile_parser.add_argument("--arm64-receipt", type=Path, required=True)
    reconcile_parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "verify-recipe":
            recipe, digest = load_recipe(args.recipe)
            print(
                "PASS_SOURCE_ONLY_NOT_PRODUCT_ACTIVE "
                f"schema={recipe['schema']} sha256={digest}"
            )
        elif args.command == "inspect-elf":
            sys.stdout.buffer.write(canonical_json_bytes(inspect_elf_path(args.artifact)))
        elif args.command == "build-candidate":
            receipt = build_candidate(args)
            sys.stdout.buffer.write(canonical_json_bytes(receipt))
        elif args.command == "verify-build":
            recipe, recipe_sha = load_recipe(args.recipe)
            receipt = _verify_build_receipt(args.receipt, recipe, recipe_sha)
            sys.stdout.buffer.write(canonical_json_bytes(receipt))
        elif args.command == "reconcile":
            if args.output is not None:
                raise ContractError(
                    "persistent reconcile publication is fixed HOLD until the "
                    "fixed custody journal and external permanent-HOLD path exist"
                )
            document = reconcile_receipts(
                args.recipe, args.amd64_receipt, args.arm64_receipt
            )
            _write_optional_output(None, document)
        else:  # pragma: no cover - argparse owns this boundary.
            raise ContractError("unsupported command")
    except ContractError as error:
        print(f"HOLD: {error}", file=sys.stderr)
        return 78
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
