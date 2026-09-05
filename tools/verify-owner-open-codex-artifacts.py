#!/usr/bin/env python3
"""Verify pinned official Codex release artifacts without promoting live execution.

The verifier binds the upstream GitHub release metadata, checksum manifest,
archive bytes, safe single-file archive shape, ELF architecture and the digest
embedded in each Sigstore bundle. Cryptographic Sigstore certificate-chain
verification remains a separate release gate and is deliberately not claimed
here.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, BinaryIO

CONTRACT = Path("docs/contracts/owner-open-r5-codex-artifacts-v1.json")
EXPECTED_SCHEMA = "org.trillionnium.owner-open.codex-artifacts.v1"
OFFICIAL_REPOSITORY = "openai/codex"
OFFICIAL_API_PREFIX = "https://api.github.com/repos/openai/codex/"
OFFICIAL_WEB_PREFIX = "https://github.com/openai/codex/"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_CHECKSUM_BYTES = 64 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_EXPANDED_BYTES = 768 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 32
MAX_SIGSTORE_BYTES = 256 * 1024
MAX_PROBE_OUTPUT = 1024 * 1024
MAX_PROGRAM_HEADERS = 256
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


class DuplicateMember(ValueError):
    pass


class VerificationError(ValueError):
    pass


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.errors

    def value(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "errors": self.errors,
            "warnings": self.warnings,
            "facts": self.facts,
        }


def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise DuplicateMember(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def bounded_real_file(path: Path, maximum: int, label: str) -> tuple[bytes, os.stat_result]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise VerificationError(f"{label} is not a regular non-symlink file: {path}")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        raise VerificationError(
            f"{label} size is outside 1..{maximum}: {metadata.st_size}"
        )
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        raise VerificationError(f"{label} changed while read: {path}")
    return raw, metadata


def strict_json_bytes(raw: bytes, label: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateMember) as error:
        raise VerificationError(f"invalid {label}: {error}") from error


def strict_json_file(path: Path, maximum: int, label: str) -> Any:
    raw, _metadata = bounded_real_file(path, maximum, label)
    return strict_json_bytes(raw, label)


def sha256_file(path: Path, maximum: int, label: str) -> tuple[str, int]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise VerificationError(f"{label} is not a regular non-symlink file: {path}")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        raise VerificationError(
            f"{label} size is outside 1..{maximum}: {metadata.st_size}"
        )
    digest = hashlib.sha256()
    observed = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            observed += len(chunk)
            if observed > maximum:
                raise VerificationError(f"{label} exceeded its byte ceiling while read")
            digest.update(chunk)
    after = path.lstat()
    if after.st_size != metadata.st_size or observed != metadata.st_size:
        raise VerificationError(f"{label} changed while hashed: {path}")
    return digest.hexdigest(), observed


def require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{label} must be an object")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise VerificationError(f"{label} must be a nonempty string")
    return value


def require_filename(value: Any, label: str) -> str:
    name = require_string(value, label)
    if not SAFE_NAME.fullmatch(name) or Path(name).name != name:
        raise VerificationError(f"{label} is not a safe basename: {name!r}")
    return name


def require_sha(value: Any, label: str) -> str:
    digest = require_string(value, label)
    if HEX64.fullmatch(digest) is None:
        raise VerificationError(f"{label} must be lowercase SHA-256 hex")
    return digest


def require_size(value: Any, maximum: int, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= maximum:
        raise VerificationError(f"{label} must be an integer in 1..{maximum}")
    return value


def load_contract(path: Path) -> dict[str, Any]:
    value = strict_json_file(path, MAX_JSON_BYTES, "Codex artifact contract")
    contract = require_dict(value, "Codex artifact contract")
    if contract.get("schema") != EXPECTED_SCHEMA:
        raise VerificationError(f"contract schema must be {EXPECTED_SCHEMA}")
    return contract


def validate_contract(contract: dict[str, Any]) -> list[dict[str, Any]]:
    upstream = require_dict(contract.get("upstream"), "upstream")
    if upstream.get("repository") != OFFICIAL_REPOSITORY:
        raise VerificationError(f"upstream.repository must be {OFFICIAL_REPOSITORY}")
    tag = require_string(upstream.get("release_tag"), "upstream.release_tag")
    version = require_string(upstream.get("version"), "upstream.version")
    if tag != f"rust-v{version}":
        raise VerificationError("release tag and version are inconsistent")
    api = require_string(upstream.get("release_api"), "upstream.release_api")
    page = require_string(upstream.get("release_page"), "upstream.release_page")
    if api != f"{OFFICIAL_API_PREFIX}releases/tags/{tag}":
        raise VerificationError("release_api is not the exact official tag endpoint")
    if page != f"{OFFICIAL_WEB_PREFIX}releases/tag/{tag}":
        raise VerificationError("release_page is not the exact official tag page")
    require_string(upstream.get("published_at"), "upstream.published_at")

    checksum = require_dict(contract.get("checksum_list"), "checksum_list")
    checksum_name = require_filename(checksum.get("filename"), "checksum_list.filename")
    require_size(checksum.get("bytes"), MAX_CHECKSUM_BYTES, "checksum_list.bytes")
    require_sha(checksum.get("sha256"), "checksum_list.sha256")
    expected_checksum_url = f"{OFFICIAL_WEB_PREFIX}releases/download/{tag}/{checksum_name}"
    if checksum.get("url") != expected_checksum_url:
        raise VerificationError("checksum_list.url is not the exact official asset URL")

    archives_value = contract.get("archives")
    if not isinstance(archives_value, list) or len(archives_value) != 2:
        raise VerificationError("archives must contain exactly target and host artifacts")
    archives: list[dict[str, Any]] = []
    roles: set[str] = set()
    architectures: set[str] = set()
    filenames: set[str] = {checksum_name}
    executable_count = 0
    for index, raw in enumerate(archives_value):
        item = require_dict(raw, f"archives[{index}]")
        role = require_string(item.get("role"), f"archives[{index}].role")
        architecture = require_string(
            item.get("architecture"), f"archives[{index}].architecture"
        )
        if role in roles or architecture in architectures:
            raise VerificationError("archive role or architecture is duplicated")
        roles.add(role)
        architectures.add(architecture)
        machine = item.get("elf_machine")
        if machine not in {62, 183}:
            raise VerificationError(f"archive {role} has unsupported ELF machine")
        filename = require_filename(item.get("filename"), f"archive {role} filename")
        member = require_filename(item.get("archive_member"), f"archive {role} member")
        if filename != f"{member}.tar.gz":
            raise VerificationError(f"archive {role} filename/member mismatch")
        if filename in filenames:
            raise VerificationError(f"duplicate asset filename: {filename}")
        filenames.add(filename)
        require_size(item.get("bytes"), MAX_ARCHIVE_BYTES, f"archive {role} bytes")
        require_sha(item.get("sha256"), f"archive {role} sha256")
        expected_url = f"{OFFICIAL_WEB_PREFIX}releases/download/{tag}/{filename}"
        if item.get("url") != expected_url:
            raise VerificationError(f"archive {role} URL is not exact official URL")
        execute = item.get("execute_on_github_host")
        if not isinstance(execute, bool):
            raise VerificationError(f"archive {role} execute flag must be boolean")
        executable_count += int(execute)
        sigstore = require_dict(item.get("sigstore"), f"archive {role} sigstore")
        sig_name = require_filename(
            sigstore.get("filename"), f"archive {role} sigstore filename"
        )
        if sig_name in filenames:
            raise VerificationError(f"duplicate asset filename: {sig_name}")
        filenames.add(sig_name)
        require_size(
            sigstore.get("bytes"), MAX_SIGSTORE_BYTES, f"archive {role} sigstore bytes"
        )
        require_sha(sigstore.get("sha256"), f"archive {role} sigstore sha256")
        expected_sig_url = f"{OFFICIAL_WEB_PREFIX}releases/download/{tag}/{sig_name}"
        if sigstore.get("url") != expected_sig_url:
            raise VerificationError(
                f"archive {role} Sigstore URL is not exact official URL"
            )
        archives.append(item)
    if roles != {"target_root_linux_codex", "qualification_host_codex"}:
        raise VerificationError("archive roles are not the exact selected pair")
    if executable_count != 1:
        raise VerificationError("exactly one host-compatible artifact must be probed")

    verification = require_dict(contract.get("verification"), "verification")
    required_flags = {
        "require_exact_release_tag",
        "require_github_asset_digest_match",
        "require_checksum_list_cross_check",
        "require_safe_single_file_archive",
        "require_exact_elf_machine",
        "require_sigstore_bundle_digest_binding",
        "cryptographic_sigstore_verification_required_for_release",
    }
    for key in required_flags:
        if verification.get(key) is not True:
            raise VerificationError(f"verification flag must remain true: {key}")

    claims = require_dict(contract.get("claims"), "claims")
    if claims.get("official_release_identity_bound") is not True:
        raise VerificationError("official release identity contract must remain bound")
    for key in (
        "artifact_bytes_present_in_repository",
        "target_root_linux_installed",
        "authenticated_codex_execution",
        "same_turn_mcp_qualification",
        "cryptographic_sigstore_verification",
        "public_release",
    ):
        if claims.get(key) is not False:
            raise VerificationError(f"source contract must not claim {key}")
    if contract.get("claim_ceiling") != (
        "OFFICIAL_RELEASE_ASSET_IDENTITY_AND_CHECKSUM_CONTRACT_ONLY"
    ):
        raise VerificationError("unexpected source-contract claim ceiling")
    return archives


def parse_checksum_list(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError(f"checksum list is not UTF-8: {error}") from error
    result: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64})[ \t]+\*?([^\s]+)", line)
        if match is None:
            raise VerificationError(f"malformed checksum line {line_number}")
        digest, name = match.groups()
        require_filename(name, f"checksum line {line_number} filename")
        if name in result:
            raise VerificationError(f"duplicate checksum filename: {name}")
        result[name] = digest
    if not result:
        raise VerificationError("checksum list is empty")
    return result


def verify_checksum_list(
    path: Path, specification: dict[str, Any], archives: list[dict[str, Any]]
) -> dict[str, Any]:
    expected_size = int(specification["bytes"])
    expected_digest = str(specification["sha256"])
    observed_digest, observed_size = sha256_file(
        path, MAX_CHECKSUM_BYTES, "Codex checksum list"
    )
    if observed_size != expected_size:
        raise VerificationError(
            f"checksum list size mismatch: {observed_size} != {expected_size}"
        )
    if observed_digest != expected_digest:
        raise VerificationError("checksum list SHA-256 mismatch")
    raw, _metadata = bounded_real_file(path, MAX_CHECKSUM_BYTES, "Codex checksum list")
    entries = parse_checksum_list(raw)
    for item in archives:
        filename = str(item["filename"])
        if entries.get(filename) != item["sha256"]:
            raise VerificationError(
                f"checksum list does not bind exact archive digest: {filename}"
            )
    return {
        "filename": path.name,
        "bytes": observed_size,
        "sha256": observed_digest,
        "entry_count": len(entries),
        "selected_archives_bound": True,
    }


def release_asset_map(asset_documents: list[Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for document in asset_documents:
        if not isinstance(document, list):
            raise VerificationError("release assets JSON must be an array")
        for raw in document:
            item = require_dict(raw, "release asset")
            name = require_filename(item.get("name"), "release asset name")
            if name in result:
                raise VerificationError(f"release metadata duplicates asset: {name}")
            result[name] = item
    return result


def verify_release_metadata(
    contract: dict[str, Any],
    release_document: Any,
    asset_documents: list[Any],
) -> dict[str, Any]:
    release = require_dict(release_document, "upstream release metadata")
    upstream = require_dict(contract["upstream"], "upstream")
    tag = str(upstream["release_tag"])
    if release.get("tag_name") != tag:
        raise VerificationError("upstream release tag metadata drifted")
    if release.get("published_at") != upstream["published_at"]:
        raise VerificationError("upstream release publication timestamp drifted")
    if release.get("draft") is not False or release.get("prerelease") is not False:
        raise VerificationError("selected upstream release is draft or prerelease")
    release_id = release.get("id")
    if not isinstance(release_id, int) or isinstance(release_id, bool) or release_id <= 0:
        raise VerificationError("upstream release ID is malformed")
    assets = release_asset_map(asset_documents)
    selected: list[dict[str, Any]] = [contract["checksum_list"]]
    for archive in contract["archives"]:
        selected.extend((archive, archive["sigstore"]))
    bound: dict[str, Any] = {}
    for specification in selected:
        filename = str(specification["filename"])
        metadata = assets.get(filename)
        if metadata is None:
            raise VerificationError(f"upstream release metadata misses {filename}")
        if metadata.get("state") != "uploaded":
            raise VerificationError(f"upstream release asset is not uploaded: {filename}")
        if metadata.get("size") != specification["bytes"]:
            raise VerificationError(f"upstream release size drifted: {filename}")
        if metadata.get("digest") != f"sha256:{specification['sha256']}":
            raise VerificationError(f"upstream release digest drifted: {filename}")
        if metadata.get("browser_download_url") != specification["url"]:
            raise VerificationError(f"upstream release URL drifted: {filename}")
        asset_id = metadata.get("id")
        if not isinstance(asset_id, int) or isinstance(asset_id, bool) or asset_id <= 0:
            raise VerificationError(f"upstream release asset ID malformed: {filename}")
        bound[filename] = {
            "asset_id": asset_id,
            "bytes": metadata["size"],
            "digest": metadata["digest"],
        }
    return {
        "release_id": release_id,
        "tag": tag,
        "published_at": release["published_at"],
        "selected_assets": bound,
        "github_asset_digest_match": True,
    }


def safe_member_name(name: str) -> PurePosixPath:
    if not name or "\x00" in name or name.startswith("/"):
        raise VerificationError(f"unsafe archive member name: {name!r}")
    value = PurePosixPath(name)
    if ".." in value.parts or str(value) != name:
        raise VerificationError(f"non-canonical archive member name: {name!r}")
    return value


def copy_member(source: BinaryIO, destination: Path, expected_size: int) -> str:
    digest = hashlib.sha256()
    observed = 0
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                observed += len(chunk)
                if observed > expected_size or observed > MAX_EXPANDED_BYTES:
                    raise VerificationError("archive member expanded beyond declared size")
                output.write(chunk)
                digest.update(chunk)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    if observed != expected_size:
        destination.unlink(missing_ok=True)
        raise VerificationError(
            f"archive member size mismatch: {observed} != {expected_size}"
        )
    return digest.hexdigest()


def parse_elf(path: Path, expected_machine: int) -> dict[str, Any]:
    size = path.stat().st_size
    with path.open("rb") as handle:
        header = handle.read(64)
        if len(header) != 64 or header[:4] != b"\x7fELF":
            raise VerificationError("selected archive member is not ELF")
        if header[4] != 2 or header[5] != 1 or header[6] != 1:
            raise VerificationError("selected Codex ELF must be ELF64 little-endian v1")
        fields = struct.unpack("<HHIQQQIHHHHHH", header[16:64])
        (
            elf_type,
            machine,
            version,
            _entry,
            program_offset,
            _section_offset,
            _flags,
            header_size,
            program_entry_size,
            program_count,
            _section_entry_size,
            _section_count,
            _section_names,
        ) = fields
        if elf_type not in {2, 3} or version != 1 or header_size != 64:
            raise VerificationError("selected Codex ELF header is incompatible")
        if machine != expected_machine:
            raise VerificationError(
                f"selected Codex ELF machine mismatch: {machine} != {expected_machine}"
            )
        if program_count > MAX_PROGRAM_HEADERS:
            raise VerificationError("selected Codex ELF has too many program headers")
        if program_count and program_entry_size < 56:
            raise VerificationError("selected Codex ELF program header size is invalid")
        if program_offset + program_entry_size * program_count > size:
            raise VerificationError("selected Codex ELF program headers exceed file")
        interpreter: str | None = None
        for index in range(program_count):
            handle.seek(program_offset + index * program_entry_size)
            raw = handle.read(56)
            if len(raw) != 56:
                raise VerificationError("selected Codex ELF program header truncated")
            (
                program_type,
                _program_flags,
                file_offset,
                _virtual,
                _physical,
                file_size,
                _memory_size,
                _alignment,
            ) = struct.unpack("<IIQQQQQQ", raw)
            if program_type == 3:
                if interpreter is not None or not 0 < file_size <= 4096:
                    raise VerificationError("selected Codex ELF PT_INTERP is malformed")
                if file_offset + file_size > size:
                    raise VerificationError("selected Codex ELF PT_INTERP exceeds file")
                handle.seek(file_offset)
                encoded = handle.read(file_size)
                if not encoded.endswith(b"\x00") or b"\x00" in encoded[:-1]:
                    raise VerificationError("selected Codex ELF interpreter is malformed")
                try:
                    interpreter = encoded[:-1].decode("utf-8")
                except UnicodeDecodeError as error:
                    raise VerificationError(
                        "selected Codex ELF interpreter is not UTF-8"
                    ) from error
    return {
        "elf64": True,
        "little_endian": True,
        "elf_type": elf_type,
        "elf_machine": machine,
        "program_header_count": program_count,
        "interpreter": interpreter,
        "static_or_self_contained_candidate": interpreter is None,
    }


def verify_sigstore_bundle(
    path: Path, specification: dict[str, Any], archive_digest: str
) -> dict[str, Any]:
    expected_size = int(specification["bytes"])
    expected_sha = str(specification["sha256"])
    observed_sha, observed_size = sha256_file(
        path, MAX_SIGSTORE_BYTES, "Codex Sigstore bundle"
    )
    if observed_size != expected_size:
        raise VerificationError("Codex Sigstore bundle size mismatch")
    if observed_sha != expected_sha:
        raise VerificationError("Codex Sigstore bundle SHA-256 mismatch")
    document = require_dict(
        strict_json_file(path, MAX_SIGSTORE_BYTES, "Codex Sigstore bundle"),
        "Codex Sigstore bundle",
    )
    media_type = require_string(document.get("mediaType"), "Sigstore mediaType")
    if not media_type.startswith("application/vnd.dev.sigstore.bundle.v"):
        raise VerificationError("Codex Sigstore bundle media type is unsupported")
    material = require_dict(
        document.get("verificationMaterial"), "Sigstore verificationMaterial"
    )
    signature = require_dict(document.get("messageSignature"), "Sigstore messageSignature")
    digest = require_dict(signature.get("messageDigest"), "Sigstore messageDigest")
    algorithm = digest.get("algorithm")
    if algorithm not in {"SHA2_256", "SHA2_256_UNSPECIFIED", "SHA256"}:
        raise VerificationError(f"Sigstore digest algorithm is not SHA-256: {algorithm!r}")
    encoded_digest = require_string(digest.get("digest"), "Sigstore digest")
    try:
        signed_digest = base64.b64decode(encoded_digest, validate=True)
    except ValueError as error:
        raise VerificationError("Sigstore digest is not canonical base64") from error
    if signed_digest != bytes.fromhex(archive_digest):
        raise VerificationError("Sigstore bundle is not bound to the selected archive digest")
    encoded_signature = require_string(signature.get("signature"), "Sigstore signature")
    try:
        signature_bytes = base64.b64decode(encoded_signature, validate=True)
    except ValueError as error:
        raise VerificationError("Sigstore signature is not canonical base64") from error
    if len(signature_bytes) < 64:
        raise VerificationError("Sigstore signature is unexpectedly short")
    if not material:
        raise VerificationError("Sigstore verification material is empty")
    tlog_entries = material.get("tlogEntries")
    if not isinstance(tlog_entries, list) or not tlog_entries:
        raise VerificationError("Sigstore bundle has no transparency-log entry")
    return {
        "filename": path.name,
        "bytes": observed_size,
        "sha256": observed_sha,
        "media_type": media_type,
        "archive_digest_bound": True,
        "transparency_log_entries": len(tlog_entries),
        "cryptographic_signature_verified": False,
    }


def verify_archive(
    archive_path: Path,
    specification: dict[str, Any],
    destination: Path,
) -> tuple[dict[str, Any], Path]:
    role = str(specification["role"])
    observed_sha, observed_size = sha256_file(
        archive_path, MAX_ARCHIVE_BYTES, f"Codex archive {role}"
    )
    if observed_size != specification["bytes"]:
        raise VerificationError(f"Codex archive size mismatch for {role}")
    if observed_sha != specification["sha256"]:
        raise VerificationError(f"Codex archive SHA-256 mismatch for {role}")
    expected_member = str(specification["archive_member"])
    selected = None
    regular_files = 0
    expanded = 0
    names: set[str] = set()
    try:
        archive = tarfile.open(archive_path, mode="r:gz")
    except (tarfile.TarError, OSError) as error:
        raise VerificationError(f"cannot open Codex archive {role}: {error}") from error
    with archive:
        members = archive.getmembers()
        if not members or len(members) > MAX_ARCHIVE_MEMBERS:
            raise VerificationError(f"Codex archive {role} member count is invalid")
        for member in members:
            safe_member_name(member.name)
            if member.name in names:
                raise VerificationError(f"Codex archive {role} duplicates a member")
            names.add(member.name)
            if member.isdir():
                continue
            if not member.isfile():
                raise VerificationError(
                    f"Codex archive {role} contains a link/device/special member"
                )
            regular_files += 1
            expanded += member.size
            if expanded > MAX_EXPANDED_BYTES:
                raise VerificationError(f"Codex archive {role} expands beyond its ceiling")
            if member.name == expected_member:
                selected = member
        if regular_files != 1 or selected is None:
            raise VerificationError(
                f"Codex archive {role} must contain exactly {expected_member!r}"
            )
        if selected.mode & 0o111 == 0:
            raise VerificationError(f"Codex archive {role} member is not executable")
        source = archive.extractfile(selected)
        if source is None:
            raise VerificationError(f"Codex archive {role} member cannot be read")
        output = destination / expected_member
        with source:
            binary_sha = copy_member(source, output, selected.size)
    elf = parse_elf(output, int(specification["elf_machine"]))
    return (
        {
            "role": role,
            "filename": archive_path.name,
            "archive_bytes": observed_size,
            "archive_sha256": observed_sha,
            "archive_member": expected_member,
            "archive_member_bytes": selected.size,
            "archive_member_sha256": binary_sha,
            "archive_member_mode": format(selected.mode & 0o7777, "04o"),
            "safe_single_file_archive": True,
            "elf": elf,
        },
        output,
    )


def terminate_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    process.wait(timeout=2)


def bounded_command(command: list[str], cwd: Path, environment: dict[str, str]) -> dict[str, Any]:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=20)
    except subprocess.TimeoutExpired as error:
        terminate_group(process)
        raise VerificationError(f"Codex probe timed out: {command[-1]}") from error
    finally:
        if process.poll() is None:
            terminate_group(process)
    if len(stdout) + len(stderr) > MAX_PROBE_OUTPUT:
        raise VerificationError(f"Codex probe output exceeded its ceiling: {command[-1]}")
    if process.returncode != 0:
        raise VerificationError(
            f"Codex probe failed rc={process.returncode}: {command[-1]}"
        )
    return {
        "argv_tail": command[-1],
        "returncode": process.returncode,
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "stdout_text": stdout.decode("utf-8", errors="replace")[:4096],
        "stderr_text": stderr.decode("utf-8", errors="replace")[:4096],
    }


def probe_codex(binary: Path, version: str, root: Path) -> dict[str, Any]:
    home = root / "probe-home"
    codex_home = root / "probe-codex-home"
    home.mkdir(mode=0o700)
    codex_home.mkdir(mode=0o700)
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "CODEX_HOME": str(codex_home),
        "NO_COLOR": "1",
        "TERM": "dumb",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    version_result = bounded_command([str(binary), "--version"], root, environment)
    help_result = bounded_command([str(binary), "--help"], root, environment)
    combined_version = version_result["stdout_text"] + version_result["stderr_text"]
    if version not in combined_version:
        raise VerificationError("Codex --version does not identify the selected version")
    combined_help = help_result["stdout_text"] + help_result["stderr_text"]
    if "Usage" not in combined_help and "usage" not in combined_help:
        raise VerificationError("Codex --help has no usage marker")
    return {
        "executed": True,
        "network_or_model_contact_claimed": False,
        "authentication_claimed": False,
        "version": version_result,
        "help": help_result,
    }


def verify(
    root: Path,
    *,
    asset_dir: Path | None = None,
    release_json: Path | None = None,
    release_asset_json: list[Path] | None = None,
    probe: bool = False,
) -> Report:
    report = Report()
    release_asset_json = release_asset_json or []
    try:
        contract = load_contract(root / CONTRACT)
        archives = validate_contract(contract)
        report.facts.update(
            revision=contract.get("revision"),
            upstream=contract.get("upstream"),
            contract_path=str(CONTRACT),
            source_contract_valid=True,
            claim_ceiling=contract.get("claim_ceiling"),
            authenticated_codex_execution=False,
            same_turn_mcp_qualification=False,
            target_root_linux_installed=False,
            cryptographic_sigstore_verification=False,
            public_release=False,
        )
        if (release_json is None) != (not release_asset_json):
            raise VerificationError(
                "release metadata requires both release JSON and asset JSON pages"
            )
        if release_json is not None:
            release_document = strict_json_file(
                release_json, MAX_JSON_BYTES, "upstream release JSON"
            )
            asset_documents = [
                strict_json_file(path, MAX_JSON_BYTES, "upstream release assets JSON")
                for path in release_asset_json
            ]
            report.facts["release_metadata"] = verify_release_metadata(
                contract, release_document, asset_documents
            )
        elif asset_dir is not None:
            raise VerificationError(
                "artifact-byte verification requires upstream release metadata"
            )
        else:
            report.warnings.append(
                "artifact bytes and upstream release metadata were not supplied"
            )

        if asset_dir is not None:
            asset_root = asset_dir.resolve(strict=True)
            checksum_spec = require_dict(contract["checksum_list"], "checksum_list")
            checksum_path = asset_root / str(checksum_spec["filename"])
            report.facts["checksum_list"] = verify_checksum_list(
                checksum_path, checksum_spec, archives
            )
            artifact_facts: list[dict[str, Any]] = []
            for item in archives:
                archive_path = asset_root / str(item["filename"])
                sigstore_spec = require_dict(item["sigstore"], "sigstore")
                sigstore_path = asset_root / str(sigstore_spec["filename"])
                with tempfile.TemporaryDirectory(prefix="owner-open-codex-") as temporary:
                    temporary_path = Path(temporary)
                    archive_facts, binary = verify_archive(
                        archive_path, item, temporary_path
                    )
                    archive_facts["sigstore"] = verify_sigstore_bundle(
                        sigstore_path, sigstore_spec, str(item["sha256"])
                    )
                    if probe and item["execute_on_github_host"] is True:
                        archive_facts["cli_probe"] = probe_codex(
                            binary, str(contract["upstream"]["version"]), temporary_path
                        )
                    else:
                        archive_facts["cli_probe"] = {
                            "executed": False,
                            "reason": (
                                "probe disabled"
                                if not probe
                                else "target architecture is not the GitHub host"
                            ),
                        }
                    artifact_facts.append(archive_facts)
            report.facts["artifacts"] = artifact_facts
            report.facts["artifact_bytes_verified"] = True
            report.facts["host_cli_identity_probe_passed"] = bool(
                probe
                and any(
                    item.get("cli_probe", {}).get("executed") is True
                    for item in artifact_facts
                )
            )
            report.facts["claim_ceiling"] = (
                "OFFICIAL_RELEASE_BYTES_ELF_AND_LOCAL_CLI_IDENTITY_PROBED_"
                "NOT_AUTHENTICATED_NOT_INSTALLED"
            )
        else:
            report.facts["artifact_bytes_verified"] = False
            report.facts["host_cli_identity_probe_passed"] = False
    except (OSError, VerificationError, tarfile.TarError) as error:
        report.errors.append(str(error))
    return report


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--asset-dir", type=Path)
    parser.add_argument("--release-json", type=Path)
    parser.add_argument("--release-assets-json", type=Path, action="append", default=[])
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = verify(
        args.root,
        asset_dir=args.asset_dir,
        release_json=args.release_json,
        release_asset_json=args.release_assets_json,
        probe=args.probe,
    )
    if args.json:
        print(json.dumps(report.value(), ensure_ascii=False, sort_keys=True, indent=2))
    elif report.ok:
        for warning in report.warnings:
            print(f"WARNING: {warning}")
        print(
            "PASS_OWNER_OPEN_CODEX_ARTIFACTS "
            f"bytes_verified={str(report.facts['artifact_bytes_verified']).lower()} "
            f"probe={str(report.facts['host_cli_identity_probe_passed']).lower()}"
        )
    else:
        for error in report.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        for warning in report.warnings:
            print(f"WARNING: {warning}", file=sys.stderr)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
