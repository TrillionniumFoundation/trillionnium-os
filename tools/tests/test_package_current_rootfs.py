#!/usr/bin/env python3
"""Strict fresh-only v9 HOLD tests for the host Root-Linux packager."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tarfile
import tempfile
from typing import Callable
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "package_current_rootfs.py"
SPEC = importlib.util.spec_from_file_location("package_current_rootfs_tested", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
packager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packager)

EPOCH = 1_785_110_400
REPLAY_PATH = "usr/local/bin/trillionnium-system-api-replay-sync"
SOURCE_SET_SHA256 = "b" * 64
RESOLVED_MANIFEST_SHA256 = "c" * 64
ANDROID_FILTER_FIXTURE_RAW_BYTES = 144_384
ANDROID_FILTER_FIXTURE_RAW_SHA256 = (
    "ef72f8d888b7f306e836041e0781c5df2ca14c1f7d93443a51b399be196ae3de"
)
ANDROID_FILTER_FIXTURE_FILTERED_SHA256 = (
    "0cf6b4d51902257cd6875c18be5120c888b17964867608bb02c8906646dd7822"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def compact_json_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def write_read_only(path: Path, content: bytes) -> None:
    if path.exists() or path.is_symlink():
        path.chmod(0o600)
        path.unlink()
    path.write_bytes(content)
    path.chmod(0o444)


def write_json(path: Path, value: object) -> None:
    write_read_only(path, canonical_json_bytes(value))


def fake_elf(
    *, machine: int = 183, dynamic: bool = False, suffix: bytes = b""
) -> bytes:
    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\x00" * 8
    program_offset = 64 if dynamic else 0
    program_entry_size = 56 if dynamic else 0
    program_count = 1 if dynamic else 0
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        2,
        machine,
        1,
        0,
        program_offset,
        0,
        0,
        64,
        program_entry_size,
        program_count,
        0,
        0,
        0,
    )
    if not dynamic:
        return header + suffix
    interpreter = b"/lib/ld-linux-aarch64.so.1\x00"
    program_header = struct.pack(
        "<IIQQQQQQ",
        3,
        4,
        120,
        0,
        0,
        len(interpreter),
        len(interpreter),
        1,
    )
    return header + program_header + interpreter + suffix


def default_base_entries() -> list[dict[str, object]]:
    entries: list[dict[str, object]] = [
        {"path": ".", "type": "directory", "mode": 0o555},
        {"path": "bin", "type": "directory", "mode": 0o555},
        {"path": "etc", "type": "directory", "mode": 0o555},
        {
            "path": "etc/os-release",
            "type": "file",
            "mode": 0o444,
            "content": b"NAME=Fixture\n",
        },
        {"path": "usr", "type": "directory", "mode": 0o555},
        {"path": "usr/bin", "type": "directory", "mode": 0o555},
        {
            "path": "usr/bin/base-tool",
            "type": "file",
            "mode": 0o555,
            "content": b"fixture-tool\n",
        },
    ]
    entries.extend(
        {
            "path": absolute_path[1:],
            "type": "file",
            "mode": 0o555,
            "content": ("fixture:" + absolute_path).encode("utf-8"),
        }
        for absolute_path in packager.SHELL_EXEC_STANDARD_ALLOWLIST_EXECUTABLES
    )
    entries.extend(
        {"path": f"d{index:03d}", "type": "directory", "mode": 0o555}
        for index in range(242)
    )
    entries.extend(
        (
            {"path": "etc/ssl", "type": "directory", "mode": 0o555},
            {"path": "etc/ssl/certs", "type": "directory", "mode": 0o555},
        )
    )
    entries.extend(
        {
            "path": member,
            "type": "symlink",
            "mode": 0o777,
            "target": target,
        }
        for member, target in packager.ANDROID_STAGING_FILTER_EXPECTED_GNU_LONGLINKS
    )
    return sorted(
        entries,
        key=lambda entry: (
            entry["path"] != ".",
            str(entry["path"]).encode("utf-8"),
        ),
    )


def android_filter_fixture_octal(value: int, width: int) -> bytes:
    encoded = f"{value:0{width - 1}o}".encode("ascii") + b"\0"
    if len(encoded) != width:
        raise AssertionError("Android filter fixture octal field overflowed")
    return encoded


def android_filter_fixture_header(
    name: str,
    typeflag: bytes,
    mode: int,
    size: int = 0,
    linkname: bytes = b"",
    *,
    gnu_metadata: bool = False,
) -> bytes:
    name_bytes = name.encode("utf-8")
    if len(name_bytes) > 100 or len(typeflag) != 1 or len(linkname) > 100:
        raise AssertionError("Android filter fixture field overflowed")
    header = bytearray(packager.ANDROID_STAGING_FILTER_TAR_BLOCK_BYTES)
    header[0 : len(name_bytes)] = name_bytes
    header[100:108] = android_filter_fixture_octal(mode, 8)
    header[108:116] = android_filter_fixture_octal(0, 8)
    header[116:124] = android_filter_fixture_octal(0, 8)
    header[124:136] = android_filter_fixture_octal(size, 12)
    header[136:148] = android_filter_fixture_octal(0, 12)
    header[148:156] = b" " * 8
    header[156:157] = typeflag
    header[157 : 157 + len(linkname)] = linkname
    header[257:263] = b"ustar "
    header[263:265] = b" \0"
    if not gnu_metadata:
        header[265:269] = b"root"
        header[297:301] = b"root"
    checksum = sum(header)
    header[148:156] = f"{checksum:06o}".encode("ascii") + b"\0 "
    return bytes(header)


def android_filter_fixture_padded(data: bytes) -> bytes:
    block = packager.ANDROID_STAGING_FILTER_TAR_BLOCK_BYTES
    return data + bytes((-len(data)) % block)


def android_filter_fixture_tar() -> bytes:
    block = packager.ANDROID_STAGING_FILTER_TAR_BLOCK_BYTES
    chunks: list[bytes] = []
    directory_names = ["./", "etc/", "etc/ssl/", "etc/ssl/certs/"]
    directory_names.extend(f"d{index:03d}/" for index in range(261))
    if len(directory_names) != packager.ANDROID_STAGING_FILTER_EXPECTED_DIRECTORY_COUNT:
        raise AssertionError("Android filter directory fixture drifted")
    chunks.extend(
        android_filter_fixture_header(name, b"5", 0o555)
        for name in directory_names
    )
    for member, target in packager.ANDROID_STAGING_FILTER_EXPECTED_GNU_LONGLINKS:
        payload = target.encode("ascii") + b"\0"
        chunks.extend(
            (
                android_filter_fixture_header(
                    "././@LongLink",
                    b"K",
                    0,
                    len(payload),
                    gnu_metadata=True,
                ),
                android_filter_fixture_padded(payload),
                android_filter_fixture_header(
                    member,
                    b"2",
                    0o777,
                    linkname=target.encode("ascii")[:100],
                ),
            )
        )
    payload = b"rootfs-filter-fixture\n"
    chunks.extend(
        (
            android_filter_fixture_header(
                "fixture", b"0", 0o444, len(payload)
            ),
            android_filter_fixture_padded(payload),
            bytes(3 * block),
        )
    )
    return b"".join(chunks)


def android_filter_fixture_entries(
    data: bytes,
) -> tuple[list[tuple[int, bytes, int]], int]:
    block = packager.ANDROID_STAGING_FILTER_TAR_BLOCK_BYTES
    entries: list[tuple[int, bytes, int]] = []
    offset = 0
    while offset + block <= len(data):
        header = data[offset : offset + block]
        if header == bytes(block):
            return entries, offset
        size_text = header[124:136].rstrip(b"\0 ").lstrip(b" ")
        size = int(size_text or b"0", 8)
        entries.append((offset, header[156:157], size))
        offset += block + ((size + block - 1) // block) * block
    raise AssertionError("Android filter fixture trailer is absent")


def update_android_filter_fixture_checksum(buffer: bytearray, offset: int) -> None:
    block = packager.ANDROID_STAGING_FILTER_TAR_BLOCK_BYTES
    header = bytearray(buffer[offset : offset + block])
    header[148:156] = b" " * 8
    header[148:156] = f"{sum(header):06o}".encode("ascii") + b"\0 "
    buffer[offset : offset + block] = header


def mutate_android_filter_fixture_header(
    raw: bytes,
    offset: int,
    updates: tuple[tuple[int, bytes], ...],
) -> bytes:
    """Apply fixed-header byte mutations and restore the tar checksum."""

    block = packager.ANDROID_STAGING_FILTER_TAR_BLOCK_BYTES
    buffer = bytearray(raw)
    for relative_offset, content in updates:
        if relative_offset < 0 or relative_offset + len(content) > block:
            raise AssertionError("Android filter header mutation escaped its block")
        start = offset + relative_offset
        buffer[start : start + len(content)] = content
    update_android_filter_fixture_checksum(buffer, offset)
    return bytes(buffer)


def insert_android_filter_fixture_member(raw: bytes, header: bytes) -> bytes:
    if len(header) != packager.ANDROID_STAGING_FILTER_TAR_BLOCK_BYTES:
        raise AssertionError("Android filter inserted header has the wrong size")
    _, trailer = android_filter_fixture_entries(raw)
    return raw[:trailer] + header + raw[trailer:]


def android_filter_differential_corpus() -> tuple[tuple[str, bytes, bool], ...]:
    """Physical-header corpus shared by the C, packager and EROFS models."""

    raw = android_filter_fixture_tar()
    entries, _ = android_filter_fixture_entries(raw)
    directory_offset = next(offset for offset, kind, _ in entries if kind == b"5")
    regular_offset = next(offset for offset, kind, _ in entries if kind == b"0")

    contained_symlink = android_filter_fixture_header(
        "top/link", b"2", 0o777, linkname=b"../fixture"
    )
    escaping_symlink = android_filter_fixture_header(
        "top/link", b"2", 0o777, linkname=b"../../escape"
    )
    nul_tail_symlink = android_filter_fixture_header(
        "top/link", b"2", 0o777, linkname=b"../fixture\0x"
    )

    return (
        ("baseline", raw, True),
        (
            "posix-regular-header",
            mutate_android_filter_fixture_header(
                raw,
                regular_offset,
                ((257, b"ustar\0"), (263, b"00")),
            ),
            True,
        ),
        (
            "nonzero-canonical-mtime",
            mutate_android_filter_fixture_header(
                raw, regular_offset, ((136, b"00000000001\0"),)
            ),
            True,
        ),
        (
            "contained-short-symlink",
            insert_android_filter_fixture_member(raw, contained_symlink),
            True,
        ),
        (
            "regular-linkname",
            mutate_android_filter_fixture_header(
                raw, regular_offset, ((157, b"unexpected"),)
            ),
            False,
        ),
        (
            "directory-linkname",
            mutate_android_filter_fixture_header(
                raw, directory_offset, ((157, b"unexpected"),)
            ),
            False,
        ),
        (
            "mode-above-07777",
            mutate_android_filter_fixture_header(
                raw, regular_offset, ((100, b"0010000\0"),)
            ),
            False,
        ),
        (
            "uid-base256",
            mutate_android_filter_fixture_header(
                raw, regular_offset, ((108, b"\x80" + bytes(7)),)
            ),
            False,
        ),
        (
            "uid-blank",
            mutate_android_filter_fixture_header(
                raw, regular_offset, ((108, bytes(8)),)
            ),
            False,
        ),
        (
            "gid-non-octal",
            mutate_android_filter_fixture_header(
                raw, regular_offset, ((116, b"0000008\0"),)
            ),
            False,
        ),
        (
            "size-base256",
            mutate_android_filter_fixture_header(
                raw, regular_offset, ((124, b"\x80" + bytes(11)),)
            ),
            False,
        ),
        (
            "mtime-digit-after-terminator",
            mutate_android_filter_fixture_header(
                raw, regular_offset, ((136, b"0000000000\01"),)
            ),
            False,
        ),
        (
            "devmajor-nonzero",
            mutate_android_filter_fixture_header(
                raw, regular_offset, ((329, b"0000001\0"),)
            ),
            False,
        ),
        (
            "devminor-nonzero",
            mutate_android_filter_fixture_header(
                raw, regular_offset, ((337, b"0000001\0"),)
            ),
            False,
        ),
        (
            "name-nul-tail",
            mutate_android_filter_fixture_header(
                raw, regular_offset, ((8, b"x"),)
            ),
            False,
        ),
        (
            "uname-nul-tail",
            mutate_android_filter_fixture_header(
                raw, regular_offset, ((270, b"x"),)
            ),
            False,
        ),
        (
            "gname-nul-tail",
            mutate_android_filter_fixture_header(
                raw, regular_offset, ((302, b"x"),)
            ),
            False,
        ),
        (
            "prefix-nul-tail",
            mutate_android_filter_fixture_header(
                raw, regular_offset, ((346, b"x"),)
            ),
            False,
        ),
        (
            "header-trailer-padding",
            mutate_android_filter_fixture_header(
                raw, regular_offset, ((500, b"x"),)
            ),
            False,
        ),
        (
            "noncanonical-name",
            mutate_android_filter_fixture_header(
                raw,
                regular_offset,
                ((0, b"bad//path\0" + bytes(90)),),
            ),
            False,
        ),
        (
            "noncanonical-prefix",
            mutate_android_filter_fixture_header(
                raw,
                regular_offset,
                ((345, b"bad/../prefix\0" + bytes(141)),),
            ),
            False,
        ),
        (
            "escaping-short-symlink",
            insert_android_filter_fixture_member(raw, escaping_symlink),
            False,
        ),
        (
            "short-symlink-linkname-nul-tail",
            insert_android_filter_fixture_member(raw, nul_tail_symlink),
            False,
        ),
    )


def add_tar_entry(archive: tarfile.TarFile, entry: dict[str, object]) -> None:
    info = tarfile.TarInfo(str(entry["path"]))
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = EPOCH
    info.mode = int(entry["mode"])
    entry_type = entry["type"]
    if entry_type == "directory":
        info.type = tarfile.DIRTYPE
        archive.addfile(info)
    elif entry_type == "file":
        content = bytes(entry.get("content", b""))
        info.type = tarfile.REGTYPE
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    elif entry_type == "symlink":
        info.type = tarfile.SYMTYPE
        info.linkname = str(entry["target"])
        archive.addfile(info)
    elif entry_type == "hardlink":
        info.type = tarfile.LNKTYPE
        info.linkname = str(entry["target"])
        archive.addfile(info)
    elif entry_type == "fifo":
        info.type = tarfile.FIFOTYPE
        archive.addfile(info)
    else:  # pragma: no cover - fixture invariant
        raise AssertionError(entry_type)


class CurrentRootfsPackagerV9Tests(unittest.TestCase):
    def setUp(self) -> None:
        original_umask = os.umask(0o077)
        self.addCleanup(os.umask, original_umask)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="rootfs-v9-packager-test-",
            dir=Path.home(),
        )
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.builder = self.root / "build_minimal_bookworm_rootfs.py"
        self.build_contract = self.root / "minimal-bookworm-rootfs.contract.v1.json"
        self.allowlist = self.root / "rootfs-fresh-allowlist.json"
        self.base_receipt = self.root / "minimal-bookworm-receipt.json"
        self.sbom = self.root / "minimal-bookworm.spdx.json"
        self.common_receipt = self.root / "common-codex-rootfs-artifact-set.v5.json"
        self.launcher_ab_receipt = self.root / "codex-launcher-artifact-set-ab.v4.json"
        self.daemon = self.root / "trillionniumd"
        self.codex = self.root / "codex"
        self.system_api_tool = self.root / "trillionnium-agent-system-api"
        self.accessibility_tool = self.root / "trillionnium-agent-accessibility"
        self.replay = self.root / "trillionnium-system-api-replay-sync"
        self.manifest = self.root / "AgentManifest.json"
        self.contract = self.root / "rootfs-contract.v9.json"
        self.zstd = self.root / "zstd"

        write_read_only(self.builder, b"#!/usr/bin/env python3\n")
        write_json(
            self.build_contract,
            {"schema": "org.trillionnium.root-linux.minimal-bookworm-build.v1"},
        )
        write_read_only(
            self.daemon,
            fake_elf(dynamic=True, suffix=b"GLIBC_2.17\x00GLIBC_2.36\x00"),
        )
        self.daemon.chmod(0o555)
        write_read_only(self.codex, fake_elf(suffix=b"codex-integrity-launcher"))
        self.codex.chmod(0o555)
        write_read_only(self.zstd, Path("/usr/bin/zstd").read_bytes())
        self.zstd.chmod(0o555)
        write_read_only(
            self.system_api_tool,
            fake_elf(dynamic=True, suffix=b"GLIBC_2.17\x00system-api"),
        )
        self.system_api_tool.chmod(0o555)
        write_read_only(
            self.accessibility_tool,
            fake_elf(dynamic=True, suffix=b"GLIBC_2.17\x00accessibility"),
        )
        self.accessibility_tool.chmod(0o555)
        write_read_only(
            self.replay,
            fake_elf(dynamic=True, suffix=b"GLIBC_2.17\x00replay-sync"),
        )
        self.replay.chmod(0o555)
        self.write_manifest()
        self.write_common_receipt()
        self.write_launcher_ab_receipt()

        self.original_paths = (
            packager.FRESH_BASE_ALLOWLIST_PATH,
            packager.FRESH_BASE_BUILDER_PATH,
            packager.FRESH_BASE_BUILD_CONTRACT_PATH,
        )
        packager.FRESH_BASE_ALLOWLIST_PATH = self.allowlist
        packager.FRESH_BASE_BUILDER_PATH = self.builder
        packager.FRESH_BASE_BUILD_CONTRACT_PATH = self.build_contract

        self.base_entries = default_base_entries()
        self.base = self.build_base(self.base_entries, "base")
        self.refresh_frozen_chain(self.base, self.base_entries)
        self.write_contract()

    def tearDown(self) -> None:
        (
            packager.FRESH_BASE_ALLOWLIST_PATH,
            packager.FRESH_BASE_BUILDER_PATH,
            packager.FRESH_BASE_BUILD_CONTRACT_PATH,
        ) = self.original_paths
        self.temporary.cleanup()

    def write_manifest(self) -> None:
        value = {
            "adapter": "supervised-codex-cli",
            "agent_id": "agent-codex-direct-v1",
            "api_version": "trillionnium.agent-api.v1",
            "enabled": False,
            "health": "disabled",
            "identity_key_sha256": sha256(self.codex),
            "network_policy": "per_request",
            "peer_gid": 5901,
            "peer_uid": 5901,
            "selinux_domain": "u:r:trillionnium_codex_agent:s0",
        }
        write_json(self.manifest, value)

    def write_common_receipt(
        self, *, artifact_overrides: dict[str, dict[str, object]] | None = None
    ) -> None:
        physical = {
            "daemon": self.daemon,
            "codex_launcher": self.codex,
            "system_api_tool": self.system_api_tool,
            "accessibility_tool": self.accessibility_tool,
            "replay_sync_helper": self.replay,
        }
        artifacts = {
            name: {
                "bytes": path.stat().st_size,
                "file": path.name,
                "sha256": sha256(path),
            }
            for name, path in physical.items()
        }
        for name, override in (artifact_overrides or {}).items():
            artifacts[name].update(override)
        value = {
            "accessibility_available": False,
            "artifacts": artifacts,
            "common_direct_tool_posture": "inert_no_default_features_fail_closed",
            "compiler": self.build_tool("compiler_driver", "/fixture/aarch64-gcc"),
            "elf_inspector": self.build_tool("elf_inspector", "/fixture/readelf"),
            "dependency_graph": {
                "acyclic": True,
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
            },
            "device_execution_verified": False,
            "inputs": {
                "accessibility_tool_input_sha256": artifacts["accessibility_tool"]["sha256"],
                "codex_launcher_source_sha256": "1" * 64,
                "codex_runtime_bytes": 1234,
                "codex_runtime_sha256": "2" * 64,
                "daemon_input_sha256": artifacts["daemon"]["sha256"],
                "replay_sync_helper_input_sha256": artifacts["replay_sync_helper"]["sha256"],
                "system_api_tool_input_sha256": artifacts["system_api_tool"]["sha256"],
            },
            "legacy_descriptor_contamination_hold_gate": {
                "counterfactual_same_source_rebuild": {
                    "evidence_receipt": None,
                    "required": True,
                    "verified": False,
                },
                "digests": {
                    "canonical digest": "bc6c64abbb893e6e75ed708f87cf864e6c8f7503381371dc394409bddc4009c2",
                    "contract digest": "5ecd89d3c9fedbbeb0ac1de32fba2b5e5e5d248048ddc9a9e0359a0a01903119",
                    "launcher identity": "edcf9d31da8b48d29575115a7242691c1337174edf42573b7274b652a4cd571c",
                },
                "literal_digest_absence_verified": True,
                "stable_principal_admission_split": {
                    "evidence_receipt": None,
                    "required": True,
                    "verified": False,
                },
                "status": packager.CONTRACT_STATUS,
            },
            "product_variant": "common",
            "receipt_role": "common_rootfs_complete_measured_build_input",
            "release_allowed": False,
            "rootfs_build_required": True,
            "schema": packager.COMMON_ARTIFACT_SET_SCHEMA,
            "source_bom": {
                "authority": "local_exact_clean_graph_not_build_or_release_authority",
                "bytes": 4096,
                "control_head": "3" * 40,
                "file_sha256": "4" * 64,
                "receipt_id": "sha256:" + "5" * 64,
                "resolved_manifest_sha256": RESOLVED_MANIFEST_SHA256,
                "source_set_sha256": SOURCE_SET_SHA256,
            },
            "stable_principal_launcher_measurement": {
                "executable_identity_is_stable_registry_input": False,
                "launcher_executable_sha256": artifacts["codex_launcher"]["sha256"],
                "launcher_identity_source": "measured_after_closed_launcher_inputs",
                "stable_principal_canonical_sha256": packager.STABLE_PRINCIPAL_CANONICAL_SHA256,
                "stable_principal_contract_sha256": packager.STABLE_PRINCIPAL_CONTRACT_SHA256,
                "status": "host_measurement_only_avb_slot_admission_absent",
            },
            "status": packager.COMMON_ARTIFACT_SET_STATUS,
            "target_compiler_closure": self.target_compiler_closure(),
            "toolchain_snapshot": json.loads(
                json.dumps(packager.EXPECTED_TOOLCHAIN_SNAPSHOT_BINDING)
            ),
        }
        write_json(self.common_receipt, value)

    def build_tool(self, role: str, path: str) -> dict[str, object]:
        identity = packager.EXPECTED_LAUNCHER_BUILD_TOOL_IDENTITIES[role]
        return {
            "schema": packager.LAUNCHER_BUILD_TOOL_SCHEMA,
            "role": role,
            "path": path,
            "bytes": identity["bytes"],
            "sha256": identity["sha256"],
            "mode": identity["mode"],
            "uid": 0,
            "gid": 0,
            "link_count": 1,
            "version": identity["version"],
            "target": identity["target"],
            "execution": {
                "mechanism": "retained_open_file_description_via_proc_self_fd",
                "measured_before_first_execution": True,
                "all_invocations_used_same_open_file_description": True,
                "descriptor_and_path_stable_after_last_execution": True,
                "ambient_environment_inherited": False,
                "environment_allowlist": packager.LAUNCHER_BUILD_ENVIRONMENT_ALLOWLIST,
            },
            "complete_recursive_toolchain_closure": False,
        }

    def target_compiler_closure(self) -> dict[str, object]:
        return {
            "schema": "org.trillionnium.target-compiler-effective-closure.v1",
            "target": "aarch64-linux-gnu",
            "normalized_search_arguments": [
                "--sysroot=$TARGET_SYSROOT",
                "-B$TARGET_COMPILER_BIN",
                "-B$TARGET_GCC_LIBDIR",
                "-B$TARGET_BINUTILS_DIR",
            ],
            "reported_sysroot": "$TARGET_SYSROOT",
            "components": json.loads(
                json.dumps(packager.EXPECTED_TARGET_COMPILER_COMPONENTS)
            ),
            "snapshot_tree_fully_remeasured_before_and_after_build": True,
            "host_process_interpreter_and_fallback_glibc_libm_libz_byte_closed": False,
            "complete_host_execution_runtime_closure": False,
        }

    def write_launcher_ab_receipt(self) -> None:
        common = json.loads(self.common_receipt.read_text(encoding="utf-8"))
        compiler = dict(common["compiler"])
        compiler.pop("path")
        compiler.update(
            {
                "a_b_byte_equal": True,
                "build_time_bytes_bound_by_upstream_receipt": True,
                "post_build_matches_raw_ab_selected_linker": True,
            }
        )
        inspector = dict(common["elf_inspector"])
        inspector.pop("path")
        inspector.update(
            {
                "a_b_byte_equal": True,
                "build_time_bytes_bound_by_upstream_receipt": True,
                "post_build_matches_raw_ab_selected_readelf": True,
            }
        )
        common_raw = self.common_receipt.read_bytes()
        value: dict[str, object] = {
            "schema": packager.COMMON_LAUNCHER_AB_SCHEMA,
            "decision": packager.COMMON_LAUNCHER_AB_DECISION,
            "status": packager.COMMON_LAUNCHER_AB_HOLD,
            "release_status": packager.COMMON_LAUNCHER_AB_HOLD,
            "release_allowed": False,
            "lane": "common",
            "product_variant": "common",
            "target": "aarch64-unknown-linux-gnu",
            "source_bom": common["source_bom"],
            "raw_elf_ab": {
                "file": "codex-only-raw-elf-ab.v3.json",
                "bytes": 8192,
                "sha256": "8" * 64,
                "receipt_id": "sha256:" + "9" * 64,
                "lane": "common",
                "decision": "PASS_HOST_ONLY_DETERMINISTIC_CODEX_RAW_ELF_AB",
                "release_status": "HOLD_PRODUCT_DEVICE_AND_COMPLETE_TOOLCHAIN_ADMISSION",
            },
            "launcher_inputs": {
                side: {
                    "receipt_file": self.common_receipt.name,
                    "receipt_bytes": len(common_raw),
                    "receipt_sha256": hashlib.sha256(common_raw).hexdigest(),
                }
                for side in ("a", "b")
            },
            "builder_inputs": common["inputs"],
            "compiler": compiler,
            "elf_inspector": inspector,
            "stable_principal_launcher_measurement": common[
                "stable_principal_launcher_measurement"
            ],
            "identity_independence_gate": common[
                "legacy_descriptor_contamination_hold_gate"
            ],
            "target_compiler_closure": common["target_compiler_closure"],
            "toolchain_snapshot": common["toolchain_snapshot"],
            "artifacts": {
                role: {
                    **artifact,
                    "a_receipt_bound": True,
                    "b_receipt_bound": True,
                    "raw_ab_bound": role != "codex_launcher",
                    "a_b_byte_equal": True,
                }
                for role, artifact in common["artifacts"].items()
            },
            "comparisons": {
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
            },
            "posture": {
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
            "receipt_id_scope": packager.COMMON_LAUNCHER_AB_RECEIPT_ID_SCOPE,
        }
        value["receipt_id"] = "sha256:" + hashlib.sha256(
            canonical_json_bytes(value)
        ).hexdigest()
        write_read_only(self.launcher_ab_receipt, canonical_json_bytes(value))

    def build_base(
        self, entries: list[dict[str, object]], stem: str
    ) -> Path:
        raw = self.root / f"{stem}.tar"
        compressed = self.root / f"{stem}.tar.zst"
        with tarfile.open(raw, "w:", format=tarfile.GNU_FORMAT) as archive:
            for entry in entries:
                add_tar_entry(archive, entry)
        with compressed.open("wb") as sink:
            completed = subprocess.run(
                [
                    str(self.zstd),
                    "-q",
                    "--no-progress",
                    "-T1",
                    "-3",
                    "--long=20",
                    "-c",
                    str(raw),
                ],
                stdout=sink,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        raw.unlink()
        compressed.chmod(0o444)
        return compressed

    def refresh_frozen_chain(
        self,
        base: Path,
        entries: list[dict[str, object]],
        *,
        forbidden_sha256: str = "f" * 64,
    ) -> None:
        package_names = ["base-files"]
        sbom = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "trillionnium-root-linux-minimal-bookworm-arm64",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-base-files",
                    "name": "base-files",
                    "versionInfo": "12.4+deb12u12",
                }
            ],
            "spdxVersion": "SPDX-2.3",
        }
        write_json(self.sbom, sbom)
        rootfs_facts = {
            "bytes": base.stat().st_size,
            "members": len(entries),
            "regular_bytes": sum(
                len(bytes(entry.get("content", b"")))
                for entry in entries
                if entry["type"] == "file"
            ),
            "sha256": sha256(base),
        }
        sbom_binding = {
            "bytes": self.sbom.stat().st_size,
            "schema": "SPDX-2.3",
            "sha256": sha256(self.sbom),
        }
        contract_binding = {
            "bytes": self.build_contract.stat().st_size,
            "sha256": sha256(self.build_contract),
        }
        receipt: dict[str, object] = {
            "contract": contract_binding,
            "device_write_performed": False,
            "fsverity_enable_performed": False,
            "host_only": True,
            "keyring_deb": {},
            "normalization": {
                "absolute_symlinks_rewritten_relative": True,
                "directories": "0555",
                "executables": "0555",
                "filesystem_write_bits_absent": True,
                "home_and_root_empty": True,
                "regular_files": "0444",
                "special_files_absent": True,
                "uid_gid": "0:0",
                "volatile_trees_empty": True,
            },
            "ota_signing_performed": False,
            "packages": {
                "allowlist_exact_match": True,
                "count": len(package_names),
                "names": package_names,
            },
            "product_pin_refresh_performed": False,
            "release_promotion_performed": False,
            "rootfs": rootfs_facts,
            "sbom": sbom_binding,
            "schema": packager.FRESH_BASE_RECEIPT_SCHEMA,
            "snapshot": {
                "archive_signatures_required": True,
                "inrelease": {
                    "debian": {"signature_verified": True},
                    "security": {"signature_verified": True},
                },
                "timestamp": "20260727T000000Z",
            },
            "tools": {},
        }
        receipt["receipt_id"] = compact_json_sha256(receipt)
        write_json(self.base_receipt, receipt)
        allowlist = {
            "artifacts": {
                "receipt": {
                    "bytes": self.base_receipt.stat().st_size,
                    "receipt_id": receipt["receipt_id"],
                    "schema": packager.FRESH_BASE_RECEIPT_SCHEMA,
                    "sha256": sha256(self.base_receipt),
                },
                "rootfs": rootfs_facts,
                "sbom": sbom_binding,
            },
            "build_contract": {
                "bytes": self.build_contract.stat().st_size,
                "path": "tools/evidence-factory/minimal-bookworm-rootfs.contract.v1.json",
                "schema": "org.trillionnium.root-linux.minimal-bookworm-build.v1",
                "sha256": sha256(self.build_contract),
            },
            "builder": {
                "bytes": self.builder.stat().st_size,
                "path": "tools/build_minimal_bookworm_rootfs.py",
                "sha256": sha256(self.builder),
            },
            "forbidden_input_archives": [
                {
                    "bytes": 378_118_207,
                    "installed_package_count": 512,
                    "reason": "historical mutable GUI rootfs is never admissible",
                    "sha256": forbidden_sha256,
                }
            ],
            "package_allowlist": {
                "count": len(package_names),
                "names": package_names,
                "resolved_inventory_canonical_json_sha256": compact_json_sha256(
                    package_names
                ),
            },
            "policy": {
                "archive_subtraction_or_hot_replacement_allowed": False,
                "base_receipt_and_sbom_required": True,
                "fresh_mmdebstrap_build_required": True,
                "independent_keyring_origin_approved": False,
                "product_admission_allowed": False,
                "reason_product_hold": "fixture remains host-only",
            },
            "schema": packager.FRESH_BASE_ALLOWLIST_SCHEMA,
            "snapshot": {
                "architecture": "arm64",
                "archive_signatures_required": True,
                "debian_inrelease": {},
                "keyring_deb": {},
                "security_inrelease": {},
                "source_date_epoch": EPOCH,
                "suite": "bookworm",
                "timestamp": "20260727T000000Z",
            },
        }
        write_json(self.allowlist, allowlist)

    def contract_value(self) -> dict[str, object]:
        manifest_value = json.loads(self.manifest.read_text(encoding="utf-8"))
        common_receipt = json.loads(self.common_receipt.read_text(encoding="utf-8"))
        launcher_ab = json.loads(self.launcher_ab_receipt.read_bytes())
        launcher_ab_summary = {
            "bytes": self.launcher_ab_receipt.stat().st_size,
            "compiler_and_elf_inspector_build_time_bytes_bound": True,
            "decision": launcher_ab["decision"],
            "deterministic_artifact_set_ab_verified": True,
            "lane": "common",
            "physical_source_bom_or_live_graph_remeasured_by_this_stage": launcher_ab[
                "comparisons"
            ]["physical_source_bom_or_live_graph_remeasured_by_this_stage"],
            "raw_elf_ab_receipt_id": launcher_ab["raw_elf_ab"]["receipt_id"],
            "receipt_id": launcher_ab["receipt_id"],
            "release_status": launcher_ab["release_status"],
            "same_upstream_source_bom_receipt_claim": launcher_ab["comparisons"][
                "same_upstream_source_bom_receipt_claim"
            ],
            "schema": launcher_ab["schema"],
            "sha256": sha256(self.launcher_ab_receipt),
            "status": launcher_ab["status"],
        }
        return {
            "admission": {
                "decision": packager.CONTRACT_DECISION,
                "identity_independence_gate": common_receipt[
                    "legacy_descriptor_contamination_hold_gate"
                ],
                "release_allowed": False,
                "status": packager.CONTRACT_STATUS,
            },
            "common_build_evidence": {
                "compiler": common_receipt["compiler"],
                "elf_inspector": common_receipt["elf_inspector"],
                "launcher_ab": launcher_ab_summary,
                "source_bom_claim_authority": json.loads(
                    json.dumps(packager.SOURCE_BOM_CLAIM_AUTHORITY)
                ),
                "stable_principal_launcher_measurement": common_receipt[
                    "stable_principal_launcher_measurement"
                ],
                "toolchain_claim_authority": json.loads(
                    json.dumps(packager.TOOLCHAIN_CLAIM_AUTHORITY)
                ),
                "upstream_receipt_target_compiler_closure_claim": common_receipt[
                    "target_compiler_closure"
                ],
                "upstream_receipt_toolchain_snapshot_claim": common_receipt[
                    "toolchain_snapshot"
                ],
                "upstream_source_bom_receipt_claim": common_receipt["source_bom"],
            },
            "compression": {
                "algorithm": "zstd",
                "level": 3,
                "long_distance_matcher_log": 20,
                "threads": 1,
            },
            "inputs": {
                "accessibility_tool": {
                    "bytes": self.accessibility_tool.stat().st_size,
                    "install": {
                        "mode": "0755",
                        "path": "usr/local/bin/trillionnium-agent-accessibility",
                    },
                    "require_static": False,
                    "sha256": sha256(self.accessibility_tool),
                },
                "agent_manifest": {
                    "allowed_fields": sorted(manifest_value),
                    "bytes": self.manifest.stat().st_size,
                    "install": {
                        "mode": "0644",
                        "path": "etc/trillionnium/agents/agent-codex-direct-v1.json",
                    },
                    "required_fields": manifest_value,
                    "sha256": sha256(self.manifest),
                },
                "base_rootfs": {
                    "bytes": self.base.stat().st_size,
                    "sha256": sha256(self.base),
                },
                "common_artifact_set_receipt": {
                    "bytes": self.common_receipt.stat().st_size,
                    "file": self.common_receipt.name,
                    "schema": packager.COMMON_ARTIFACT_SET_SCHEMA,
                    "sha256": sha256(self.common_receipt),
                    "status": packager.COMMON_ARTIFACT_SET_STATUS,
                },
                "common_launcher_ab_receipt": {
                    "bytes": self.launcher_ab_receipt.stat().st_size,
                    "decision": packager.COMMON_LAUNCHER_AB_DECISION,
                    "file": self.launcher_ab_receipt.name,
                    "schema": packager.COMMON_LAUNCHER_AB_SCHEMA,
                    "sha256": sha256(self.launcher_ab_receipt),
                    "status": packager.COMMON_LAUNCHER_AB_HOLD,
                },
                "codex": {
                    "bytes": self.codex.stat().st_size,
                    "install": {
                        "mode": "0755",
                        "path": "usr/lib/trillionnium/agents/codex/current/bin/codex",
                    },
                    "require_static": True,
                    "sha256": sha256(self.codex),
                },
                "daemon": {
                    "bytes": self.daemon.stat().st_size,
                    "install": {"mode": "0755", "path": "usr/bin/trillionniumd"},
                    "require_static": False,
                    "sha256": sha256(self.daemon),
                },
                "system_api_replay_sync": {
                    "bytes": self.replay.stat().st_size,
                    "install": {"mode": "0755", "path": REPLAY_PATH},
                    "require_static": False,
                    "sha256": sha256(self.replay),
                },
                "system_api_tool": {
                    "bytes": self.system_api_tool.stat().st_size,
                    "install": {
                        "mode": "0755",
                        "path": "usr/local/bin/trillionnium-agent-system-api",
                    },
                    "require_static": False,
                    "sha256": sha256(self.system_api_tool),
                },
            },
            "limits": {
                "max_decompressed_tar_bytes": 1_048_576,
                "max_member_bytes": 262_144,
                "max_members": 512,
                "max_path_bytes": 512,
                "max_total_regular_bytes": 524_288,
            },
            "runtime": {"elf_machine": "AArch64", "max_glibc": "2.36"},
            "schema": packager.CONTRACT_SCHEMA,
            "security": {
                "forbidden_content_markers": ["FIXTURE_PRIVATE_TOKEN"],
                "forbidden_path_patterns": ["(^|/)fixture-secret($|/)"],
                "legacy_absolute_symlink_migration": None,
                "legacy_duplicate_directory_migrations": [],
                "legacy_prune_members": [],
                "legacy_raw_name_prune_members": [],
                "replacement_hardlink_allowlist": [],
            },
            "source_date_epoch": EPOCH,
            "tools": {
                "zstd": {
                    "bytes": self.zstd.stat().st_size,
                    "sha256": sha256(self.zstd),
                }
            },
        }

    def write_contract(self, value: dict[str, object] | None = None) -> None:
        if value is None:
            self.write_launcher_ab_receipt()
            value = self.contract_value()
        write_json(self.contract, value)

    def select_base(
        self, entries: list[dict[str, object]], stem: str = "alternate-base"
    ) -> None:
        self.base_entries = entries
        self.base = self.build_base(entries, stem)
        self.refresh_frozen_chain(self.base, entries)
        self.write_contract()

    def package_args(self, run_name: str) -> tuple[argparse.Namespace, Path, Path]:
        destination = self.root / run_name
        destination.mkdir()
        output = destination / "rootfs.tar.zst"
        receipt = destination / "rootfs.receipt.json"
        return (
            argparse.Namespace(
                agent_manifest=self.manifest,
                accessibility_tool=self.accessibility_tool,
                base_rootfs=self.base,
                codex_binary=self.codex,
                common_artifact_set_receipt=self.common_receipt,
                common_launcher_ab_receipt=self.launcher_ab_receipt,
                contract=self.contract,
                daemon=self.daemon,
                fresh_base_receipt=self.base_receipt,
                fresh_base_sbom=self.sbom,
                output_rootfs=output,
                receipt=receipt,
                system_api_replay_sync=self.replay,
                system_api_tool=self.system_api_tool,
                zstd=self.zstd,
            ),
            output,
            receipt,
        )

    def test_same_inputs_are_byte_identical_and_normalized(self) -> None:
        before = (
            sha256(self.base),
            self.base.stat().st_size,
            self.base.stat().st_mtime_ns,
            stat.S_IMODE(self.base.stat().st_mode),
        )
        first_args, first_output, first_receipt = self.package_args("run-a")
        second_args, second_output, second_receipt = self.package_args("run-b")
        with mock.patch.dict(os.environ, {"PATH": ""}):
            first = packager.package(first_args)
            second = packager.package(second_args)
        after = (
            sha256(self.base),
            self.base.stat().st_size,
            self.base.stat().st_mtime_ns,
            stat.S_IMODE(self.base.stat().st_mode),
        )
        self.assertEqual(before, after)
        self.assertEqual(first_output.read_bytes(), second_output.read_bytes())
        self.assertEqual(first_receipt.read_bytes(), second_receipt.read_bytes())
        self.assertEqual(first, second)
        self.assertEqual(stat.S_IMODE(first_output.stat().st_mode), 0o444)
        self.assertEqual(stat.S_IMODE(first_receipt.stat().st_mode), 0o444)
        self.assertEqual(first["schema"], packager.RECEIPT_SCHEMA)
        self.assertEqual(
            first["receipt_id_scope"], packager.ROOTFS_RECEIPT_ID_SCOPE
        )
        self.assertEqual(first["decision"], packager.CONTRACT_DECISION)
        self.assertEqual(first["status"], packager.CONTRACT_STATUS)
        self.assertFalse(first["release_allowed"])
        self.assertEqual(
            first["publication"],
            {
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
        )
        self.assertEqual(first["admission"], self.contract_value()["admission"])
        self.assertEqual(
            first["common_build_evidence"],
            self.contract_value()["common_build_evidence"],
        )
        for field in ("source_bom_claim_authority", "toolchain_claim_authority"):
            self.assertEqual(
                first["common_build_evidence"][field]["source"],
                "content_hash_bound_common_and_self_hashed_launcher_receipt",
            )
        self.assertEqual(first["limitations"], packager.PACKAGE_LIMITATIONS)
        self.assertFalse(
            first["admission"]["identity_independence_gate"]
            ["counterfactual_same_source_rebuild"]["verified"]
        )
        self.assertEqual(first["tools"]["zstd"]["sha256"], sha256(self.zstd))
        self.assertEqual(
            first["tools"]["zstd"]["bytes"], self.zstd.stat().st_size
        )
        staging_filter = first["output_rootfs"]["android_staging_filter"]
        self.assertEqual(
            set(staging_filter), {"schema", "source_sha256", "bytes", "sha256"}
        )
        self.assertEqual(
            staging_filter["schema"], packager.ANDROID_STAGING_FILTER_SCHEMA
        )
        self.assertEqual(
            staging_filter["source_sha256"],
            packager.ANDROID_STAGING_FILTER_SOURCE_SHA256,
        )
        self.assertEqual(
            staging_filter["bytes"],
            first["output_rootfs"]["decompressed_tar_bytes"],
        )
        self.assertRegex(staging_filter["sha256"], r"^[0-9a-f]{64}$")
        self.assertNotEqual(
            staging_filter["sha256"],
            first["output_rootfs"]["decompressed_tar_sha256"],
        )
        self.assertEqual(
            first["inputs"]["system_api_replay_sync"]["install_path"], REPLAY_PATH
        )
        self.assertEqual(
            first["inputs"]["system_api_replay_sync"]["role"],
            "android_system_api_replay_synchronizer",
        )
        output_members = first["output_rootfs"]["members"]
        self.assertEqual(
            sum(item["type"] == "directory" for item in output_members),
            packager.ANDROID_STAGING_FILTER_EXPECTED_DIRECTORY_COUNT,
        )
        longlinks = {
            item["path"]: item.get("link_target")
            for item in output_members
            if item["path"]
            in {
                member
                for member, _ in packager.ANDROID_STAGING_FILTER_EXPECTED_GNU_LONGLINKS
            }
        }
        self.assertEqual(
            longlinks,
            dict(packager.ANDROID_STAGING_FILTER_EXPECTED_GNU_LONGLINKS),
        )
        modes = {item["path"]: item["mode"] for item in output_members}
        self.assertEqual(modes["usr/bin/trillionniumd"], "0555")
        self.assertEqual(
            modes["usr/lib/trillionnium/agents/codex/current/bin/codex"], "0555"
        )
        self.assertEqual(modes[REPLAY_PATH], "0555")
        self.assertEqual(
            modes["usr/local/bin/trillionnium-agent-system-api"], "0555"
        )
        self.assertEqual(
            modes["usr/local/bin/trillionnium-agent-accessibility"], "0555"
        )
        shell_placeholder = next(
            item
            for item in output_members
            if item["path"]
            == packager.SHELL_EXEC_RUNTIME_BIND_PLACEHOLDER_PATH
        )
        self.assertEqual(shell_placeholder["type"], "file")
        self.assertEqual(shell_placeholder["mode"], "0555")
        self.assertEqual(shell_placeholder["bytes"], 0)
        self.assertEqual(shell_placeholder["sha256"], packager.EMPTY_SHA256)
        allowlist_member = next(
            item
            for item in output_members
            if item["path"] == packager.SHELL_EXEC_STANDARD_ALLOWLIST_PATH
        )
        self.assertEqual(allowlist_member["type"], "file")
        self.assertEqual(allowlist_member["mode"], "0444")
        self.assertGreater(allowlist_member["bytes"], 0)
        decompressed = subprocess.run(
            [str(self.zstd), "-q", "-d", "-c", str(first_output)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout
        with tarfile.open(fileobj=io.BytesIO(decompressed), mode="r:") as archive:
            stream = archive.extractfile(packager.SHELL_EXEC_STANDARD_ALLOWLIST_PATH)
            self.assertIsNotNone(stream)
            assert stream is not None
            allowlist_raw = stream.read()
        self.assertFalse(allowlist_raw.endswith(b"\n"))
        self.assertTrue(allowlist_raw.startswith(b'{"entries":['))
        self.assertTrue(
            allowlist_raw.endswith(
                b'],"profile":"standard","schema":"org.trillionnium.shell-exec.'
                b'standard-executable-policy.v1"}'
            )
        )
        self.assertEqual(
            hashlib.sha256(allowlist_raw).hexdigest(), allowlist_member["sha256"]
        )
        self.assertEqual(len(allowlist_raw), allowlist_member["bytes"])
        allowlist = json.loads(allowlist_raw)
        self.assertEqual(
            set(allowlist), {"schema", "profile", "entries"}
        )
        self.assertEqual(
            allowlist["schema"], packager.SHELL_EXEC_STANDARD_ALLOWLIST_SCHEMA
        )
        self.assertEqual(
            allowlist["profile"], packager.SHELL_EXEC_STANDARD_ALLOWLIST_PROFILE
        )
        self.assertEqual(
            [entry["path"] for entry in allowlist["entries"]],
            list(packager.SHELL_EXEC_STANDARD_ALLOWLIST_EXECUTABLES),
        )
        self.assertNotIn(
            "/bin/mkdir", packager.SHELL_EXEC_STANDARD_ALLOWLIST_EXECUTABLES
        )
        self.assertNotIn(
            "/bin/touch", packager.SHELL_EXEC_STANDARD_ALLOWLIST_EXECUTABLES
        )
        self.assertNotIn(
            "/bin/pwd", packager.SHELL_EXEC_STANDARD_ALLOWLIST_EXECUTABLES
        )
        self.assertNotIn(
            "/usr/bin/whoami",
            packager.SHELL_EXEC_STANDARD_ALLOWLIST_EXECUTABLES,
        )
        self.assertTrue(
            all(set(entry) == {"path", "sha256"} for entry in allowlist["entries"])
        )
        member_by_path = {"/" + item["path"]: item for item in output_members}
        self.assertEqual(
            allowlist["entries"],
            [
                {
                    "path": path,
                    "sha256": member_by_path[path]["sha256"],
                }
                for path in packager.SHELL_EXEC_STANDARD_ALLOWLIST_EXECUTABLES
            ],
        )
        self.assertEqual(
            allowlist_raw, packager.canonical_json_bytes(allowlist)
        )
        self.assertEqual(
            set(first["runtime_layout"]),
            {
                "codex_runtime_bind_placeholder",
                "android_effect_tool_paths",
                "runtime_mount_directories",
                "placeholder_mode",
                "placeholder_bytes",
                "placeholder_payloads_present",
            },
        )
        self.assertEqual(
            modes["etc/trillionnium/agents/agent-codex-direct-v1.json"], "0444"
        )
        common = first["inputs"]["common_artifact_set_receipt"]
        self.assertEqual(common["sha256"], sha256(self.common_receipt))
        self.assertEqual(common["schema"], packager.COMMON_ARTIFACT_SET_SCHEMA)
        self.assertEqual(
            set(common["artifact_bindings"]),
            {
                "daemon",
                "codex_launcher",
                "system_api_tool",
                "accessibility_tool",
                "replay_sync_helper",
            },
        )
        launcher_ab = first["inputs"]["common_launcher_ab_receipt"]
        self.assertEqual(launcher_ab["sha256"], sha256(self.launcher_ab_receipt))
        self.assertTrue(launcher_ab["deterministic_artifact_set_ab_verified"])
        self.assertTrue(
            launcher_ab["compiler_and_elf_inspector_build_time_bytes_bound"]
        )
        unsigned = dict(first)
        receipt_id = unsigned.pop("receipt_id")
        self.assertEqual(receipt_id, "sha256:" + compact_json_sha256(unsigned))

    def test_shell_allowlist_rejects_non_regular_or_digestless_member(self) -> None:
        entries = {
            path[1:]: {
                "path": path[1:],
                "type": "file",
                "mode": 0o555,
                "bytes": index + 1,
                "sha256": f"{index + 1:064x}",
                "digest_scope": "file-content",
            }
            for index, path in enumerate(
                packager.SHELL_EXEC_STANDARD_ALLOWLIST_EXECUTABLES
            )
        }
        first = packager.shell_exec_standard_allowlist_bytes(entries)
        golden = (
            '{"entries":['
            + ",".join(
                '{"path":"'
                + path
                + '","sha256":"'
                + f"{index + 1:064x}"
                + '"}'
                for index, path in enumerate(
                    packager.SHELL_EXEC_STANDARD_ALLOWLIST_EXECUTABLES
                )
            )
            + '],"profile":"standard","schema":"'
            + packager.SHELL_EXEC_STANDARD_ALLOWLIST_SCHEMA
            + '"}'
        ).encode("utf-8")
        self.assertEqual(first, golden)
        self.assertEqual(len(first), 793)
        self.assertEqual(
            hashlib.sha256(first).hexdigest(),
            "1fc833c037c732038e177fc516a8484f1d1120742809b5a0568e111eac56989e",
        )
        entries["bin/echo"]["sha256"] = "f" * 64
        second = packager.shell_exec_standard_allowlist_bytes(entries)
        self.assertNotEqual(first, second)
        entries["bin/echo"]["type"] = "symlink"
        with self.assertRaisesRegex(
            packager.PackagerError, "not a nonempty 0555 regular file"
        ):
            packager.shell_exec_standard_allowlist_bytes(entries)

    def test_shell_runtime_bind_placeholder_must_be_created_empty_0555(self) -> None:
        parents = [
            {"path": "usr/local", "type": "directory", "mode": 0o555},
            {"path": "usr/local/bin", "type": "directory", "mode": 0o555},
        ]
        variants = (
            {
                "path": packager.SHELL_EXEC_RUNTIME_BIND_PLACEHOLDER_PATH,
                "type": "symlink",
                "mode": 0o777,
                "target": "../../../bin/true",
            },
            {
                "path": packager.SHELL_EXEC_RUNTIME_BIND_PLACEHOLDER_PATH,
                "type": "file",
                "mode": 0o555,
                "content": b"not-empty",
            },
            {
                "path": packager.SHELL_EXEC_RUNTIME_BIND_PLACEHOLDER_PATH,
                "type": "file",
                "mode": 0o444,
                "content": b"",
            },
        )
        for index, variant in enumerate(variants):
            with self.subTest(index=index, kind=variant["type"], mode=variant["mode"]):
                entries = sorted(
                    [*default_base_entries(), *parents, variant],
                    key=lambda entry: (
                        entry["path"] != ".",
                        str(entry["path"]).encode("utf-8"),
                    ),
                )
                self.select_base(entries, f"prepopulated-shell-placeholder-{index}")
                args, output, receipt = self.package_args(
                    f"prepopulated-shell-placeholder-{index}"
                )
                with self.assertRaisesRegex(
                    packager.PackagerError,
                    "unexpectedly pre-populates.*bind placeholder",
                ):
                    packager.package(args)
                self.assertFalse(output.exists())
                self.assertFalse(receipt.exists())

    def test_android_staging_filter_matches_frozen_fixture_digest(self) -> None:
        raw = android_filter_fixture_tar()
        self.assertEqual(len(raw), ANDROID_FILTER_FIXTURE_RAW_BYTES)
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(), ANDROID_FILTER_FIXTURE_RAW_SHA256
        )
        fixture = self.root / "android-filter-fixture.tar"
        write_read_only(fixture, raw)

        first = packager.android_staging_filter_closure(fixture)
        second = packager.android_staging_filter_closure(fixture)

        self.assertEqual(first, second)
        self.assertEqual(
            first,
            {
                "schema": packager.ANDROID_STAGING_FILTER_SCHEMA,
                "source_sha256": packager.ANDROID_STAGING_FILTER_SOURCE_SHA256,
                "bytes": ANDROID_FILTER_FIXTURE_RAW_BYTES,
                "sha256": ANDROID_FILTER_FIXTURE_FILTERED_SHA256,
            },
        )
        self.assertEqual(fixture.read_bytes(), raw)

    def test_android_staging_filter_rejects_header_checksum_and_mode_drift(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            packager.PackagerError, "C uint64 octal bound"
        ):
            packager._android_filter_parse_octal(
                b"2000000000000000000000", "oversized fixture field"
            )
        raw = android_filter_fixture_tar()
        entries, _ = android_filter_fixture_entries(raw)
        directory_offset = next(
            offset for offset, kind, _ in entries if kind == b"5"
        )
        regular_offset = next(
            offset for offset, kind, _ in entries if kind == b"0"
        )
        variants: list[tuple[str, bytes, str]] = []

        bad_checksum = bytearray(raw)
        bad_checksum[directory_offset] ^= 1
        variants.append(("checksum", bytes(bad_checksum), "header checksum"))

        bad_mode = bytearray(raw)
        bad_mode[directory_offset + 100 : directory_offset + 108] = b"0000755\0"
        update_android_filter_fixture_checksum(bad_mode, directory_offset)
        variants.append(("mode", bytes(bad_mode), "invalid tar member header"))

        bad_header = bytearray(raw)
        bad_header[regular_offset + 156 : regular_offset + 157] = b"x"
        update_android_filter_fixture_checksum(bad_header, regular_offset)
        variants.append(("header", bytes(bad_header), "invalid tar member header"))

        for label, content, message in variants:
            with self.subTest(label=label):
                fixture = self.root / f"android-filter-{label}.tar"
                fixture.write_bytes(content)
                with self.assertRaisesRegex(packager.PackagerError, message):
                    packager.android_staging_filter_closure(fixture)

    def test_android_staging_filter_rejects_trailer_count_and_allowlist_drift(
        self,
    ) -> None:
        block = packager.ANDROID_STAGING_FILTER_TAR_BLOCK_BYTES
        raw = android_filter_fixture_tar()
        entries, trailer = android_filter_fixture_entries(raw)
        first_longlink = next(
            offset for offset, kind, _ in entries if kind == b"K"
        )
        variants: list[tuple[str, bytes, str]] = []

        nonzero_trailer = bytearray(raw)
        nonzero_trailer[trailer + 2 * block] = 1
        variants.append(
            ("trailer-data", bytes(nonzero_trailer), "data after the trailer")
        )
        variants.append(("short-block", raw[:-1], "short tar block"))
        variants.append(
            (
                "directory-count",
                raw[block:],
                "directory count drifted: expected 265, got 264",
            )
        )

        longlink_drift = bytearray(raw)
        longlink_drift[first_longlink + block + 10] ^= 1
        variants.append(
            ("longlink-allowlist", bytes(longlink_drift), "payload drifted")
        )

        for label, content, message in variants:
            with self.subTest(label=label):
                fixture = self.root / f"android-filter-{label}.tar"
                fixture.write_bytes(content)
                with self.assertRaisesRegex(packager.PackagerError, message):
                    packager.android_staging_filter_closure(fixture)

    def test_contract_requires_exact_v9_replay_and_hold_shape(self) -> None:
        cases = (
            ("schema", "org.trillionnium.rootfs-package.contract.v6", "unsupported contract schema"),
            ("path", "usr/bin/replay-sync", "reviewed Root-Linux replay-sync path"),
            ("static", True, "require_static must be false"),
        )
        for field, replacement, message in cases:
            with self.subTest(field=field):
                value = self.contract_value()
                if field == "schema":
                    value["schema"] = replacement
                elif field == "path":
                    value["inputs"]["system_api_replay_sync"]["install"]["path"] = replacement
                else:
                    value["inputs"]["system_api_replay_sync"]["require_static"] = replacement
                with self.assertRaisesRegex(packager.PackagerError, message):
                    packager.validate_contract(value)

        value = self.contract_value()
        value["admission"]["release_allowed"] = True
        with self.assertRaisesRegex(packager.PackagerError, "must remain explicit HOLD"):
            packager.validate_contract(value)

    def test_contract_evidence_must_equal_common_receipt_projection(self) -> None:
        value = self.contract_value()
        value["common_build_evidence"]["upstream_source_bom_receipt_claim"][
            "file_sha256"
        ] = "6" * 64
        self.write_contract(value)
        args, _, _ = self.package_args("contract-evidence-projection-drift")
        with self.assertRaisesRegex(
            packager.PackagerError, "not the exact receipt projection"
        ):
            packager.package(args)

    def test_zstd_is_explicit_exact_and_frozen(self) -> None:
        value = self.contract_value()
        value.pop("tools")
        with self.assertRaisesRegex(packager.PackagerError, "missing=.*tools"):
            packager.validate_contract(value)

        value = self.contract_value()
        value["tools"].pop("zstd")
        with self.assertRaisesRegex(packager.PackagerError, "missing=.*zstd"):
            packager.validate_contract(value)

        zstd_action = next(
            action
            for action in packager.parser()._actions
            if action.dest == "zstd"
        )
        self.assertTrue(zstd_action.required)

        for index, (field, replacement, message) in enumerate(
            (
                ("sha256", "0" * 64, "zstd SHA-256 mismatch"),
                ("bytes", self.zstd.stat().st_size + 1, "zstd byte-size mismatch"),
            )
        ):
            with self.subTest(field=field):
                value = self.contract_value()
                value["tools"]["zstd"][field] = replacement
                self.write_contract(value)
                args, _, _ = self.package_args(f"zstd-contract-drift-{index}")
                with self.assertRaisesRegex(packager.PackagerError, message):
                    packager.package(args)

        self.write_contract()
        missing_args, _, _ = self.package_args("zstd-missing")
        missing_args.zstd = self.root / "missing-zstd"
        with self.assertRaisesRegex(packager.PackagerError, "zstd input is missing"):
            packager.package(missing_args)

        alias = self.root / "zstd-alias"
        alias.symlink_to(self.zstd)
        alias_args, _, _ = self.package_args("zstd-symlink")
        alias_args.zstd = alias
        with self.assertRaisesRegex(packager.PackagerError, "non-symlink"):
            packager.package(alias_args)

        self.zstd.chmod(0o755)
        try:
            writable_args, _, _ = self.package_args("zstd-writable")
            with self.assertRaisesRegex(
                packager.PackagerError, "no owner/group/world write bits"
            ):
                packager.package(writable_args)
        finally:
            self.zstd.chmod(0o555)

    def test_zstd_change_during_read_fails_closed(self) -> None:
        expected = self.contract_value()["tools"]["zstd"]
        real_read = packager.os.read
        mutated = False

        def mutating_read(file_descriptor: int, count: int) -> bytes:
            nonlocal mutated
            chunk = real_read(file_descriptor, count)
            if chunk and not mutated:
                self.zstd.chmod(0o755)
                mutated = True
            return chunk

        try:
            with mock.patch.object(packager.os, "read", side_effect=mutating_read):
                with self.assertRaisesRegex(
                    packager.PackagerError, "changed while it was being read"
                ):
                    with packager.pinned_executable(self.zstd, expected, "zstd"):
                        self.fail("mutated zstd must not become executable")
        finally:
            self.zstd.chmod(0o555)

    def test_missing_and_tampered_replay_fail_closed(self) -> None:
        self.replay.unlink()
        args, _, _ = self.package_args("missing-replay")
        with self.assertRaisesRegex(packager.PackagerError, "system_api_replay_sync input is missing"):
            packager.package(args)

        write_read_only(
            self.replay,
            fake_elf(dynamic=True, suffix=b"GLIBC_2.17\x00tampered"),
        )
        self.replay.chmod(0o555)
        args, _, _ = self.package_args("tampered-replay")
        with self.assertRaisesRegex(packager.PackagerError, "system_api_replay_sync SHA-256 mismatch"):
            packager.package(args)

    def test_replay_elf_architecture_and_glibc_are_gated(self) -> None:
        cases = (
            (fake_elf(machine=62, dynamic=True), "wrong architecture"),
            (
                fake_elf(dynamic=True, suffix=b"GLIBC_2.40\x00"),
                "newer than GLIBC_2.36",
            ),
        )
        for index, (payload, message) in enumerate(cases):
            with self.subTest(message=message):
                write_read_only(self.replay, payload)
                self.replay.chmod(0o555)
                self.write_common_receipt()
                self.write_contract()
                args, _, _ = self.package_args(f"replay-elf-{index}")
                with self.assertRaisesRegex(packager.PackagerError, message):
                    packager.package(args)

    def test_common_receipt_and_all_five_physical_inputs_fail_closed(self) -> None:
        self.common_receipt.unlink()
        args, _, _ = self.package_args("missing-common-receipt")
        with self.assertRaisesRegex(
            packager.PackagerError,
            "common_artifact_set_receipt input is missing",
        ):
            packager.package(args)

        self.write_common_receipt()
        original = self.common_receipt.read_bytes()
        write_read_only(self.common_receipt, original + b" \n")
        args, _, _ = self.package_args("changed-common-receipt")
        with self.assertRaisesRegex(
            packager.PackagerError, "common artifact-set receipt SHA-256 mismatch"
        ):
            packager.package(args)

        self.write_common_receipt(
            artifact_overrides={"system_api_tool": {"sha256": "e" * 64}}
        )
        self.write_contract()
        args, _, _ = self.package_args("common-internal-sha-drift")
        with self.assertRaisesRegex(
            packager.PackagerError,
            "does not match physical artifact: system_api_tool",
        ):
            packager.package(args)

        self.write_common_receipt()
        self.system_api_tool.unlink()
        args, _, _ = self.package_args("missing-system-api-tool")
        with self.assertRaisesRegex(
            packager.PackagerError, "system_api_tool input is missing"
        ):
            packager.package(args)

    def test_launcher_ab_receipt_is_required_and_reverified(self) -> None:
        self.launcher_ab_receipt.unlink()
        args, _, _ = self.package_args("missing-launcher-ab")
        with self.assertRaisesRegex(
            packager.PackagerError,
            "common_launcher_ab_receipt input is missing",
        ):
            packager.package(args)

        self.write_launcher_ab_receipt()
        value = json.loads(self.launcher_ab_receipt.read_bytes())
        value["compiler"]["uid"] = 1
        value.pop("receipt_id")
        value["receipt_id"] = "sha256:" + hashlib.sha256(
            canonical_json_bytes(value)
        ).hexdigest()
        write_read_only(self.launcher_ab_receipt, canonical_json_bytes(value))
        self.write_contract(self.contract_value())
        args, _, _ = self.package_args("launcher-ab-tool-splice")
        with self.assertRaisesRegex(
            packager.PackagerError,
            "compiler custody differs from common v5",
        ):
            packager.package(args)

    def test_launcher_ab_artifact_cross_splice_fails_closed(self) -> None:
        value = json.loads(self.launcher_ab_receipt.read_bytes())
        value["artifacts"]["system_api_tool"]["sha256"] = "a" * 64
        value.pop("receipt_id")
        value["receipt_id"] = "sha256:" + hashlib.sha256(
            canonical_json_bytes(value)
        ).hexdigest()
        write_read_only(self.launcher_ab_receipt, canonical_json_bytes(value))
        self.write_contract(self.contract_value())
        args, _, _ = self.package_args("launcher-ab-artifact-splice")
        with self.assertRaisesRegex(
            packager.PackagerError,
            "artifact system_api_tool is not closed",
        ):
            packager.package(args)

    def test_common_receipt_provenance_and_identity_split_fail_closed(self) -> None:
        cases = (
            (
                ("source_bom", "receipt_id"),
                "5" * 64,
                "upstream_source_bom_receipt_claim binding is malformed",
            ),
            (
                ("source_bom", "source_set_sha256"),
                "0" * 64,
                "upstream_source_bom_receipt_claim binding is malformed",
            ),
            (
                ("source_bom", "resolved_manifest_sha256"),
                "0" * 64,
                "upstream_source_bom_receipt_claim binding is malformed",
            ),
            (
                (
                    "stable_principal_launcher_measurement",
                    "stable_principal_contract_sha256",
                ),
                "0" * 64,
                "stable_principal_launcher_measurement drifted",
            ),
            (
                (
                    "stable_principal_launcher_measurement",
                    "launcher_executable_sha256",
                ),
                "f" * 64,
                "launcher measurement is not physically bound",
            ),
            (
                (
                    "legacy_descriptor_contamination_hold_gate",
                    "counterfactual_same_source_rebuild",
                    "verified",
                ),
                True,
                "must remain unverified HOLD",
            ),
            (
                (
                    "legacy_descriptor_contamination_hold_gate",
                    "digests",
                    "contract digest",
                ),
                "0" * 64,
                "identity_independence_gate drifted",
            ),
            (
                ("compiler", "sha256"),
                "a" * 64,
                "frozen Mobian snapshot leaf",
            ),
            (
                ("toolchain_snapshot", "manifest_sha256"),
                "a" * 64,
                "frozen Mobian snapshot",
            ),
            (
                ("target_compiler_closure", "components", "ld", "sha256"),
                "a" * 64,
                "components.ld differs from the frozen Mobian snapshot",
            ),
            (
                ("target_compiler_closure", "complete_host_execution_runtime_closure"),
                True,
                "posture differs",
            ),
        )
        for index, (field_path, replacement, message) in enumerate(cases):
            with self.subTest(field_path=field_path):
                self.write_common_receipt()
                value = json.loads(self.common_receipt.read_text(encoding="utf-8"))
                target = value
                for field in field_path[:-1]:
                    target = target[field]
                target[field_path[-1]] = replacement
                write_json(self.common_receipt, value)
                self.write_contract()
                args, _, _ = self.package_args(f"common-identity-split-{index}")
                with self.assertRaisesRegex(packager.PackagerError, message):
                    packager.package(args)

    def test_source_bom_digest_cross_splice_fails_closed(self) -> None:
        for index, field in enumerate(
            ("source_set_sha256", "resolved_manifest_sha256")
        ):
            with self.subTest(field=field):
                self.write_common_receipt()
                value = json.loads(self.common_receipt.read_text(encoding="utf-8"))
                value["source_bom"][field] = "5" * 64
                write_json(self.common_receipt, value)
                self.write_contract(self.contract_value())
                args, _, _ = self.package_args(f"source-bom-cross-splice-{index}")
                with self.assertRaisesRegex(
                    packager.PackagerError,
                    "common launcher A/B source BOM is cross-spliced",
                ):
                    packager.package(args)

    def test_consistent_supplied_source_bom_digests_are_propagated(self) -> None:
        value = json.loads(self.common_receipt.read_text(encoding="utf-8"))
        value["source_bom"]["source_set_sha256"] = "d" * 64
        value["source_bom"]["resolved_manifest_sha256"] = "e" * 64
        write_json(self.common_receipt, value)
        self.write_contract()
        args, _, _ = self.package_args("supplied-source-bom-digests")

        receipt = packager.package(args)

        source_bom = receipt["common_build_evidence"][
            "upstream_source_bom_receipt_claim"
        ]
        self.assertEqual(
            source_bom["source_set_sha256"],
            "d" * 64,
        )
        self.assertEqual(
            source_bom["resolved_manifest_sha256"],
            "e" * 64,
        )

    def test_preexisting_replay_path_is_not_hot_replaced(self) -> None:
        entries = default_base_entries() + [
            {"path": "usr/local", "type": "directory", "mode": 0o555},
            {"path": "usr/local/bin", "type": "directory", "mode": 0o555},
            {
                "path": REPLAY_PATH,
                "type": "file",
                "mode": 0o555,
                "content": b"stale replay",
            },
        ]
        self.select_base(entries, "base-with-replay")
        args, _, _ = self.package_args("hot-replay")
        with self.assertRaisesRegex(packager.PackagerError, "hot replacement is forbidden"):
            packager.package(args)

    def test_every_legacy_migration_field_must_remain_empty(self) -> None:
        replacements = {
            "legacy_duplicate_directory_migrations": [{}],
            "legacy_prune_members": [{}],
            "legacy_raw_name_prune_members": [{}],
            "legacy_absolute_symlink_migration": {},
            "replacement_hardlink_allowlist": [{}],
        }
        for field, replacement in replacements.items():
            with self.subTest(field=field):
                value = self.contract_value()
                value["security"][field] = replacement
                with self.assertRaisesRegex(packager.PackagerError, field):
                    packager.validate_contract(value)

    def test_known_historical_archive_is_rejected_before_packaging(self) -> None:
        self.refresh_frozen_chain(
            self.base, self.base_entries, forbidden_sha256=sha256(self.base)
        )
        args, _, _ = self.package_args("known-old-archive")
        with self.assertRaisesRegex(packager.PackagerError, "known historical GUI rootfs is forbidden"):
            packager.package(args)

    def test_frozen_receipt_and_sbom_tampering_fail_closed(self) -> None:
        for index, (path, message) in enumerate(
            (
                (self.base_receipt, "fresh base receipt SHA-256 mismatch"),
                (self.sbom, "fresh base SPDX SBOM SHA-256 mismatch"),
            )
        ):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                write_read_only(path, original + b" \n")
                args, _, _ = self.package_args(f"provenance-tamper-{index}")
                with self.assertRaisesRegex(packager.PackagerError, message):
                    packager.package(args)
                write_read_only(path, original)

    def test_end_to_end_rejects_transient_provenance_parent_swaps(self) -> None:
        def relocate(path: Path, parent_name: str) -> Path:
            parent = self.root / parent_name
            parent.mkdir(mode=0o700)
            relocated = parent / path.name
            path.rename(relocated)
            return relocated

        self.allowlist = relocate(self.allowlist, "retained-allowlist-parent")
        self.builder = relocate(self.builder, "retained-builder-parent")
        self.build_contract = relocate(
            self.build_contract,
            "retained-build-contract-parent",
        )
        packager.FRESH_BASE_ALLOWLIST_PATH = self.allowlist
        packager.FRESH_BASE_BUILDER_PATH = self.builder
        packager.FRESH_BASE_BUILD_CONTRACT_PATH = self.build_contract
        self.refresh_frozen_chain(self.base, self.base_entries)

        script_parent = self.root / "retained-packager-parent"
        script_parent.mkdir(mode=0o700)
        packager_script = script_parent / SCRIPT.name
        write_read_only(packager_script, SCRIPT.read_bytes())

        cases = (
            ("packager", packager_script, "packager_script"),
            ("allowlist", self.allowlist, "allowlist_path"),
            ("builder", self.builder, "builder_path"),
            (
                "build-contract",
                self.build_contract,
                "build_contract_path",
            ),
        )
        for case, target, provenance_argument in cases:
            with self.subTest(case=case):
                alternate_parent = self.root / f"transient-{case}-parent"
                alternate_parent.mkdir(mode=0o700)
                alternate_target = alternate_parent / target.name
                write_read_only(alternate_target, target.read_bytes())
                alternate_target.chmod(stat.S_IMODE(target.stat().st_mode))
                retained_parent = self.root / f"held-{case}-parent"
                swapped = False
                consumer_received_retained_input = False

                def call_during_parent_swap(
                    callback: Callable[[], dict[str, object]],
                ) -> dict[str, object]:
                    nonlocal swapped
                    swapped = True
                    target.parent.rename(retained_parent)
                    alternate_parent.rename(target.parent)
                    try:
                        return callback()
                    finally:
                        target.parent.rename(alternate_parent)
                        retained_parent.rename(target.parent)

                args, output, receipt = self.package_args(
                    f"transient-{case}-parent-swap"
                )
                if case == "packager":
                    real_describe = packager.describe_regular_input

                    def describe_during_swap(
                        path: object, label: str
                    ) -> dict[str, object]:
                        nonlocal consumer_received_retained_input
                        if label != "packager":
                            return real_describe(path, label)
                        consumer_received_retained_input = isinstance(
                            path, packager.RetainedRegularInput
                        )
                        return call_during_parent_swap(
                            lambda: real_describe(path, label)
                        )

                    consumer_patch = mock.patch.object(
                        packager,
                        "describe_regular_input",
                        side_effect=describe_during_swap,
                    )
                else:
                    real_provenance = packager.verify_fresh_base_provenance

                    def provenance_during_swap(
                        *call_args: object, **call_kwargs: object
                    ) -> dict[str, object]:
                        nonlocal consumer_received_retained_input
                        candidate = call_kwargs.get(provenance_argument)
                        consumer_received_retained_input = isinstance(
                            candidate, packager.RetainedRegularInput
                        )
                        return call_during_parent_swap(
                            lambda: real_provenance(
                                *call_args,
                                **call_kwargs,
                            )
                        )

                    consumer_patch = mock.patch.object(
                        packager,
                        "verify_fresh_base_provenance",
                        side_effect=provenance_during_swap,
                    )

                with (
                    mock.patch.object(packager, "__file__", str(packager_script)),
                    consumer_patch,
                ):
                    with self.assertRaisesRegex(
                        packager.PackagerError,
                        "parent pathname component changed",
                    ):
                        packager.package(args)
                self.assertTrue(swapped)
                self.assertTrue(consumer_received_retained_input)
                self.assertFalse(output.exists())
                self.assertFalse(receipt.exists())

    def test_writable_base_archive_fails_closed(self) -> None:
        self.base.chmod(0o644)
        args, _, _ = self.package_args("writable-base")
        with self.assertRaisesRegex(packager.PackagerError, "must have no owner/group/world write bits"):
            packager.package(args)

    def test_end_to_end_rejects_transient_base_path_swap(self) -> None:
        alternate_entries = default_base_entries() + [
            {
                "path": "etc/alternate-release",
                "type": "file",
                "mode": 0o444,
                "content": b"transient alternate base\n",
            }
        ]
        alternate = self.build_base(alternate_entries, "transient-base")
        backup = self.root / "retained-original-base.tar.zst"
        real_decompress = packager.run_zstd_decompress
        swapped = False

        def swap_around_decompress(
            *call_args: object, **call_kwargs: object
        ) -> int:
            nonlocal swapped
            source = call_args[2]
            if (
                not swapped
                and isinstance(source, packager.RetainedRegularInput)
                and source.original_path == self.base
            ):
                swapped = True
                self.base.rename(backup)
                alternate.rename(self.base)
                try:
                    return real_decompress(*call_args, **call_kwargs)
                finally:
                    self.base.rename(alternate)
                    backup.rename(self.base)
            return real_decompress(*call_args, **call_kwargs)

        args, output, receipt = self.package_args("transient-base-swap")
        with mock.patch.object(
            packager,
            "run_zstd_decompress",
            side_effect=swap_around_decompress,
        ):
            with self.assertRaisesRegex(
                packager.PackagerError,
                "base_rootfs (?:changed|pathname changed) during retained "
                "input custody",
            ):
                packager.package(args)
        self.assertTrue(swapped)
        self.assertFalse(output.exists())
        self.assertFalse(receipt.exists())

    def test_end_to_end_rejects_transient_payload_path_swap(self) -> None:
        alternate = self.root / "transient-trillionniumd"
        write_read_only(
            alternate,
            fake_elf(dynamic=True, suffix=b"GLIBC_2.17\x00alternate-daemon"),
        )
        alternate.chmod(0o555)
        backup = self.root / "retained-original-trillionniumd"
        real_build_entries = packager.build_output_entries
        swapped = False

        def swap_around_tar_plan(
            *call_args: object, **call_kwargs: object
        ) -> tuple[dict[str, dict[str, object]], list[str]]:
            nonlocal swapped
            if not swapped:
                swapped = True
                self.daemon.rename(backup)
                alternate.rename(self.daemon)
                try:
                    return real_build_entries(*call_args, **call_kwargs)
                finally:
                    self.daemon.rename(alternate)
                    backup.rename(self.daemon)
            return real_build_entries(*call_args, **call_kwargs)

        args, output, receipt = self.package_args("transient-payload-swap")
        with mock.patch.object(
            packager,
            "build_output_entries",
            side_effect=swap_around_tar_plan,
        ):
            with self.assertRaisesRegex(
                packager.PackagerError,
                "daemon (?:changed|pathname changed) during retained input custody",
            ):
                packager.package(args)
        self.assertTrue(swapped)
        self.assertFalse(output.exists())
        self.assertFalse(receipt.exists())

    def test_late_daemon_swap_is_caught_by_final_precommit_gate(self) -> None:
        args, output, receipt = self.package_args("late-daemon-swap")
        alternate = self.root / "late-foreign-daemon"
        backup = self.root / "late-original-daemon"
        write_read_only(
            alternate,
            fake_elf(dynamic=True, suffix=b"GLIBC_2.17\x00late-foreign"),
        )
        alternate.chmod(0o555)
        real_canonical = packager.canonical_json_bytes
        swapped = False

        def swap_after_receipt_semantics(value: object) -> bytes:
            nonlocal swapped
            encoded = real_canonical(value)
            if (
                not swapped
                and isinstance(value, dict)
                and value.get("schema") == packager.RECEIPT_SCHEMA
                and "output_rootfs" in value
            ):
                swapped = True
                self.daemon.rename(backup)
                alternate.rename(self.daemon)
            return encoded

        try:
            with mock.patch.object(
                packager,
                "canonical_json_bytes",
                side_effect=swap_after_receipt_semantics,
            ):
                with self.assertRaisesRegex(
                    packager.PackagerError,
                    "daemon (?:changed|pathname changed) during retained input custody",
                ):
                    packager.package(args)
        finally:
            if backup.exists():
                self.daemon.rename(alternate)
                backup.rename(self.daemon)
        self.assertTrue(swapped)
        self.assertFalse(output.exists())
        self.assertFalse(receipt.exists())

    def test_input_parent_symlink_rewalk_fails_before_publication(self) -> None:
        daemon_parent = self.root / "daemon-custody-parent"
        daemon_parent.mkdir()
        nested_daemon = daemon_parent / self.daemon.name
        self.daemon.rename(nested_daemon)
        self.daemon = nested_daemon
        self.write_common_receipt()
        self.write_launcher_ab_receipt()
        self.write_contract()
        args, output, receipt = self.package_args("input-parent-symlink")
        backup_parent = self.root / "daemon-custody-parent-retained"
        real_canonical = packager.canonical_json_bytes
        swapped = False

        def symlink_parent_after_output_validation(value: object) -> bytes:
            nonlocal swapped
            encoded = real_canonical(value)
            if (
                not swapped
                and isinstance(value, dict)
                and value.get("schema") == packager.RECEIPT_SCHEMA
                and "output_rootfs" in value
            ):
                swapped = True
                daemon_parent.rename(backup_parent)
                daemon_parent.symlink_to(backup_parent, target_is_directory=True)
            return encoded

        try:
            with mock.patch.object(
                packager,
                "canonical_json_bytes",
                side_effect=symlink_parent_after_output_validation,
            ):
                with self.assertRaisesRegex(
                    packager.PackagerError,
                    "daemon parent pathname component changed",
                ):
                    packager.package(args)
        finally:
            if daemon_parent.is_symlink():
                daemon_parent.unlink()
                backup_parent.rename(daemon_parent)
        self.assertTrue(swapped)
        self.assertFalse(output.exists())
        self.assertFalse(receipt.exists())

    def test_preexisting_same_inode_hardlink_is_never_rolled_back(self) -> None:
        args, output, receipt = self.package_args("same-inode-prelink")
        real_link = packager.os.link
        injected = False

        def prelink_then_report_exists(
            source: object,
            destination: object,
            *call_args: object,
            **call_kwargs: object,
        ) -> None:
            nonlocal injected
            if not injected and Path(os.fspath(destination)).name == output.name:
                injected = True
                real_link(source, destination, *call_args, **call_kwargs)
                real_link(source, destination, *call_args, **call_kwargs)
                return
            real_link(source, destination, *call_args, **call_kwargs)

        with mock.patch.object(packager.os, "link", side_effect=prelink_then_report_exists):
            with self.assertRaisesRegex(
                packager.PackagerError,
                "link reported EEXIST after the staged inode became public; "
                "publication outcome is unknown",
            ):
                packager.package(args)
        self.assertTrue(injected)
        self.assertTrue(output.is_file())
        self.assertFalse(receipt.exists())

    def test_foreign_replacement_after_link_is_fail_retained_without_unlink(self) -> None:
        args, output, receipt = self.package_args("foreign-after-link")
        real_link = packager.os.link
        real_unlink = packager.os.unlink
        calls = 0
        published_inode = -1
        foreign_inode = -1
        foreign_content = b"foreign replacement after identity observation\n"

        def replace_before_second_link(
            source: object,
            destination: object,
            *call_args: object,
            **call_kwargs: object,
        ) -> None:
            nonlocal calls, published_inode, foreign_inode
            calls += 1
            if calls == 1:
                real_link(source, destination, *call_args, **call_kwargs)
                published_inode = output.stat().st_ino
                return
            content = output.read_bytes()
            self.assertTrue(content)
            real_unlink(output)
            write_read_only(output, foreign_content)
            foreign_inode = output.stat().st_ino
            raise OSError("injected second-link failure after foreign replacement")

        with (
            mock.patch.object(packager.os, "link", side_effect=replace_before_second_link),
            mock.patch.object(packager.os, "unlink") as forbidden_unlink,
            mock.patch.object(packager.os, "rmdir") as forbidden_rmdir,
        ):
            with self.assertRaisesRegex(
                packager.RetainedPublicationError,
                "public rollback is forbidden.*second-link failure",
            ):
                packager.package(args)
        forbidden_unlink.assert_not_called()
        forbidden_rmdir.assert_not_called()
        self.assertNotEqual(published_inode, foreign_inode)
        self.assertEqual(output.read_bytes(), foreign_content)
        self.assertEqual(output.stat().st_ino, foreign_inode)
        self.assertFalse(receipt.exists())

    def test_os_link_success_then_exception_is_unknown_and_fail_retained(self) -> None:
        args, output, receipt = self.package_args("link-success-then-error")
        real_link = packager.os.link
        injected = False

        def link_then_raise(
            source: object,
            destination: object,
            *call_args: object,
            **call_kwargs: object,
        ) -> None:
            nonlocal injected
            real_link(source, destination, *call_args, **call_kwargs)
            if not injected:
                injected = True
                raise OSError("injected exception after successful os.link")

        with mock.patch.object(packager.os, "link", side_effect=link_then_raise):
            with self.assertRaisesRegex(
                packager.RetainedPublicationError,
                "exception after successful os.link.*attempting_or_unknown",
            ):
                packager.package(args)
        self.assertTrue(injected)
        self.assertTrue(output.is_file())
        self.assertFalse(receipt.exists())

    def test_postcommit_close_failure_is_committed_diagnostic(self) -> None:
        args, output, receipt = self.package_args("postcommit-close-error")
        real_close = packager.os.close
        before_fds = len(os.listdir("/proc/self/fd"))
        injected = False

        def fail_one_close_after_both_links(descriptor: int) -> None:
            nonlocal injected
            real_close(descriptor)
            if output.exists() and receipt.exists() and not injected:
                injected = True
                raise OSError("injected postcommit close failure")

        with mock.patch.object(
            packager.os,
            "close",
            side_effect=fail_one_close_after_both_links,
        ):
            with self.assertRaisesRegex(
                packager.RetainedPublicationError,
                "postcommit close failure.*retained-or-unknown targets",
            ):
                packager.package(args)
        self.assertTrue(injected)
        self.assertTrue(output.is_file())
        self.assertTrue(receipt.is_file())
        self.assertEqual(len(os.listdir("/proc/self/fd")), before_fds)

    def test_final_success_recheck_rejects_restored_in_place_writes(self) -> None:
        for target_kind in ("output", "receipt"):
            with self.subTest(target=target_kind):
                args, output, receipt = self.package_args(
                    f"postcommit-restored-write-{target_kind}"
                )
                target = output if target_kind == "output" else receipt
                staged_label = "output rootfs" if target_kind == "output" else "receipt"
                real_close = packager.RetainedStagedFile.close
                injected = False
                ctime_changed = False

                def mutate_and_restore_after_staged_close(
                    staged: packager.RetainedStagedFile,
                ) -> None:
                    nonlocal injected, ctime_changed
                    real_close(staged)
                    if (
                        not injected
                        and staged.label == staged_label
                        and output.exists()
                        and receipt.exists()
                    ):
                        injected = True
                        original = target.read_bytes()
                        before = target.stat()
                        replacement = bytes((original[0] ^ 0x01,)) + original[1:]
                        target.chmod(0o644)
                        descriptor = os.open(target, os.O_WRONLY)
                        try:
                            os.pwrite(descriptor, replacement, 0)
                            os.ftruncate(descriptor, len(replacement))
                            os.fsync(descriptor)
                            os.pwrite(descriptor, original, 0)
                            os.ftruncate(descriptor, len(original))
                            os.fsync(descriptor)
                        finally:
                            os.close(descriptor)
                        target.chmod(stat.S_IMODE(before.st_mode))
                        os.utime(
                            target,
                            ns=(before.st_atime_ns, before.st_mtime_ns),
                            follow_symlinks=False,
                        )
                        after = target.stat()
                        ctime_changed = after.st_ctime_ns != before.st_ctime_ns
                        self.assertEqual(target.read_bytes(), original)
                        self.assertEqual(
                            stat.S_IMODE(after.st_mode),
                            stat.S_IMODE(before.st_mode),
                        )
                        self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)

                with (
                    mock.patch.object(
                        packager.RetainedStagedFile,
                        "close",
                        new=mutate_and_restore_after_staged_close,
                    ),
                    mock.patch.object(packager.os, "unlink") as forbidden_unlink,
                    mock.patch.object(packager.os, "rmdir") as forbidden_rmdir,
                ):
                    with self.assertRaisesRegex(
                        packager.RetainedPublicationError,
                        "final-success recheck.*committed pathname metadata changed",
                    ):
                        packager.package(args)
                self.assertTrue(injected)
                self.assertTrue(ctime_changed)
                forbidden_unlink.assert_not_called()
                forbidden_rmdir.assert_not_called()
                self.assertTrue(output.is_file())
                self.assertTrue(receipt.is_file())

    def test_final_success_recheck_rejects_parent_close_replacement(self) -> None:
        for target_kind in ("output", "receipt"):
            with self.subTest(target=target_kind):
                args, output, receipt = self.package_args(
                    f"postcommit-parent-replace-{target_kind}"
                )
                target = output if target_kind == "output" else receipt
                parent_label = (
                    "output rootfs parent"
                    if target_kind == "output"
                    else "receipt parent"
                )
                foreign_content = (
                    f"foreign {target_kind} replacement during parent close\n".encode()
                )
                real_close = packager.RetainedDirectoryChain.close
                injected = False

                def replace_before_parent_close(
                    parent: packager.RetainedDirectoryChain,
                ) -> None:
                    nonlocal injected
                    if (
                        not injected
                        and parent.label == parent_label
                        and output.exists()
                        and receipt.exists()
                    ):
                        injected = True
                        foreign = target.parent / f".{target.name}.foreign"
                        write_read_only(foreign, foreign_content)
                        os.replace(foreign, target)
                    real_close(parent)

                with (
                    mock.patch.object(
                        packager.RetainedDirectoryChain,
                        "close",
                        new=replace_before_parent_close,
                    ),
                    mock.patch.object(packager.os, "unlink") as forbidden_unlink,
                    mock.patch.object(packager.os, "rmdir") as forbidden_rmdir,
                ):
                    with self.assertRaisesRegex(
                        packager.RetainedPublicationError,
                        "final-success recheck.*committed pathname metadata changed",
                    ):
                        packager.package(args)
                self.assertTrue(injected)
                forbidden_unlink.assert_not_called()
                forbidden_rmdir.assert_not_called()
                self.assertTrue(output.is_file())
                self.assertTrue(receipt.is_file())
                self.assertEqual(target.read_bytes(), foreign_content)

    def test_precommit_scratch_close_failure_publishes_nothing(self) -> None:
        args, output, receipt = self.package_args("precommit-close-error")
        real_open = packager.os.open
        real_close = packager.os.close
        before_fds = len(os.listdir("/proc/self/fd"))
        anonymous_fds: set[int] = set()
        injected = False

        def remember_anonymous_fd(
            path: object,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            if flags & getattr(os, "O_TMPFILE", 0):
                anonymous_fds.add(descriptor)
            return descriptor

        def fail_one_anonymous_close(descriptor: int) -> None:
            nonlocal injected
            real_close(descriptor)
            if descriptor in anonymous_fds and not injected:
                injected = True
                raise OSError("injected precommit scratch close failure")

        with (
            mock.patch.object(packager.os, "open", side_effect=remember_anonymous_fd),
            mock.patch.object(packager.os, "close", side_effect=fail_one_anonymous_close),
        ):
            with self.assertRaisesRegex(
                packager.PackagerError,
                "precommit scratch close failure",
            ):
                packager.package(args)
        self.assertTrue(injected)
        self.assertFalse(output.exists())
        self.assertFalse(receipt.exists())
        self.assertEqual(len(os.listdir("/proc/self/fd")), before_fds)

    def test_postlink_primary_and_cleanup_close_errors_are_composed(self) -> None:
        args, output, receipt = self.package_args("postlink-composite-error")
        real_link = packager.os.link
        real_close = packager.os.close
        link_calls = 0
        close_failed = False

        def fail_second_link(
            source: object,
            destination: object,
            *call_args: object,
            **call_kwargs: object,
        ) -> None:
            nonlocal link_calls
            link_calls += 1
            if link_calls == 2:
                raise OSError("injected primary second-link error")
            real_link(source, destination, *call_args, **call_kwargs)

        def fail_first_cleanup_close(descriptor: int) -> None:
            nonlocal close_failed
            real_close(descriptor)
            if link_calls == 2 and not close_failed:
                close_failed = True
                raise OSError("injected cleanup close error")

        with (
            mock.patch.object(packager.os, "link", side_effect=fail_second_link),
            mock.patch.object(packager.os, "close", side_effect=fail_first_cleanup_close),
        ):
            with self.assertRaisesRegex(
                packager.RetainedPublicationError,
                "primary second-link error.*cleanup close error",
            ):
                packager.package(args)
        self.assertEqual(link_calls, 2)
        self.assertTrue(close_failed)
        self.assertTrue(output.is_file())
        self.assertFalse(receipt.exists())

    def test_anonymous_fstat_failure_closes_fd_and_publishes_nothing(self) -> None:
        args, output, receipt = self.package_args("anonymous-fstat-error")
        real_open = packager.os.open
        real_fstat = packager.os.fstat
        before_fds = len(os.listdir("/proc/self/fd"))
        anonymous_fd = -1
        injected = False

        def remember_anonymous_fd(
            path: object,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal anonymous_fd
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            if anonymous_fd < 0 and flags & getattr(os, "O_TMPFILE", 0):
                anonymous_fd = descriptor
            return descriptor

        def fail_first_anonymous_fstat(descriptor: int) -> os.stat_result:
            nonlocal injected
            if descriptor == anonymous_fd and not injected:
                injected = True
                raise OSError("injected anonymous fstat failure")
            return real_fstat(descriptor)

        with (
            mock.patch.object(packager.os, "open", side_effect=remember_anonymous_fd),
            mock.patch.object(packager.os, "fstat", side_effect=fail_first_anonymous_fstat),
        ):
            with self.assertRaisesRegex(OSError, "anonymous fstat failure"):
                packager.package(args)
        self.assertTrue(injected)
        self.assertFalse(output.exists())
        self.assertFalse(receipt.exists())
        self.assertEqual(len(os.listdir("/proc/self/fd")), before_fds)

    def test_directory_chain_close_drains_all_fds_once(self) -> None:
        nested = self.root / "close-chain" / "a" / "b"
        nested.mkdir(parents=True)
        before_fds = len(os.listdir("/proc/self/fd"))
        chain = packager.RetainedDirectoryChain.open(nested, "close chain")
        descriptors = [item[1] for item in chain.components]
        real_close = packager.os.close
        calls: list[int] = []
        injected = False

        def close_all_but_report_one(descriptor: int) -> None:
            nonlocal injected
            calls.append(descriptor)
            real_close(descriptor)
            if descriptor == descriptors[-1] and not injected:
                injected = True
                raise OSError("injected directory close failure")

        with mock.patch.object(
            packager.os,
            "close",
            side_effect=close_all_but_report_one,
        ):
            with self.assertRaisesRegex(
                packager.PackagerError,
                "directory-chain close failed.*directory close failure",
            ):
                chain.close()
            calls_after_first_close = list(calls)
            chain.close()
        self.assertTrue(injected)
        self.assertCountEqual(calls_after_first_close, descriptors)
        self.assertEqual(calls, calls_after_first_close)
        for descriptor in descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before_fds)

    def test_non_normalized_member_fails_closed(self) -> None:
        entries = default_base_entries()
        entries[-1] = {**entries[-1], "mode": 0o755}
        self.select_base(entries, "writable-member-base")
        args, _, _ = self.package_args("writable-member")
        with self.assertRaisesRegex(packager.PackagerError, "not normalized read-only"):
            packager.package(args)

    def test_path_secret_special_and_link_safety(self) -> None:
        variants = (
            (
                [
                    {"path": ".", "type": "directory", "mode": 0o555},
                    {"path": "../escape", "type": "file", "mode": 0o444, "content": b"bad"},
                ],
                "non-canonical tar member",
            ),
            (
                default_base_entries()
                + [
                    {"path": "usr/fixture-secret", "type": "directory", "mode": 0o555},
                    {"path": "usr/fixture-secret/token", "type": "file", "mode": 0o444, "content": b"bad"},
                ],
                "forbidden secret path",
            ),
            (
                sorted(
                    default_base_entries()
                    + [{"path": "usr/bin/fifo", "type": "fifo", "mode": 0o444}],
                    key=lambda entry: (
                        entry["path"] != ".",
                        str(entry["path"]).encode("utf-8"),
                    ),
                ),
                "special tar member forbidden",
            ),
            (
                sorted(
                    default_base_entries()
                    + [
                        {
                            "path": "usr/bin/escape-link",
                            "type": "symlink",
                            "mode": 0o777,
                            "target": "/etc/passwd",
                        }
                    ],
                    key=lambda entry: (
                        entry["path"] != ".",
                        str(entry["path"]).encode("utf-8"),
                    ),
                ),
                "absolute symlink target forbidden",
            ),
        )
        for index, (entries, message) in enumerate(variants):
            with self.subTest(message=message):
                self.select_base(entries, f"unsafe-base-{index}")
                args, _, _ = self.package_args(f"unsafe-run-{index}")
                with self.assertRaisesRegex(packager.PackagerError, message):
                    packager.package(args)


if __name__ == "__main__":
    unittest.main()
