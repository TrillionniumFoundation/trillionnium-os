#!/usr/bin/env python3
"""Verify one ordinary Linux ARM64 adb client artifact and its source BOM.

This tool is read-only. It never downloads, builds, installs, signs, starts an
adb server, opens a key path or contacts a device. Acceptance is source/artifact
qualification only and does not imply image inclusion or a physical effect.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any


SCHEMA = "org.trillionnium.owner-open.adb-arm64-artifact.v1"
REPORT_SCHEMA = "org.trillionnium.owner-open.adb-arm64-artifact-report.v1"
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_METADATA_BYTES = 256 * 1024
MAX_VERSION_OUTPUT_BYTES = 64 * 1024
EM_AARCH64 = 183
ET_EXEC = 2
ET_DYN = 3


class VerificationError(ValueError):
    pass


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def strict_object(
    value: Any,
    *,
    label: str,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{label} must be an object")
    optional = optional or set()
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        raise VerificationError(f"{label} missing fields: {sorted(missing)}")
    if unknown:
        raise VerificationError(f"{label} has unknown fields: {sorted(unknown)}")
    return value


def required_string(value: Any, label: str, max_bytes: int = 16_384) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > max_bytes
        or "\x00" in value
        or any(ord(character) < 0x20 and character not in "\n\t" for character in value)
    ):
        raise VerificationError(f"{label} must be a non-empty bounded string")
    return value


def required_sha256(value: Any, label: str) -> str:
    value = required_string(value, label, 64)
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise VerificationError(f"{label} must be a lowercase SHA-256")
    return value


def load_metadata(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size == 0
        or metadata.st_size > MAX_METADATA_BYTES
        or metadata.st_mode & 0o022
    ):
        raise VerificationError("metadata must be one bounded non-writable regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"invalid metadata JSON: {error}") from error
    return strict_object(
        value,
        label="metadata",
        required={"schema", "artifact", "source", "runtime_observation", "claims"},
    )


def inspect_artifact(path: Path) -> tuple[dict[str, Any], bytes]:
    metadata = path.lstat()
    mode = stat.S_IMODE(metadata.st_mode)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise VerificationError("artifact must be a real regular file, not a symlink")
    if metadata.st_nlink != 1:
        raise VerificationError("artifact must have exactly one hard link")
    if metadata.st_size == 0 or metadata.st_size > MAX_ARTIFACT_BYTES:
        raise VerificationError("artifact is empty or exceeds the byte bound")
    if mode & 0o111 == 0:
        raise VerificationError("artifact has no executable bit")
    if mode & 0o022:
        raise VerificationError("artifact is group/world writable")

    before = (
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
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_ARTIFACT_BYTES + 1)
            after_stat = os.fstat(handle.fileno())
    except OSError as error:
        raise VerificationError(f"cannot read artifact: {error}") from error
    after = (
        after_stat.st_dev,
        after_stat.st_ino,
        after_stat.st_uid,
        after_stat.st_gid,
        after_stat.st_mode,
        after_stat.st_nlink,
        after_stat.st_size,
        after_stat.st_mtime_ns,
        after_stat.st_ctime_ns,
    )
    if before != after or len(raw) != metadata.st_size:
        raise VerificationError("artifact changed while being read")
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise VerificationError("artifact exceeds the byte bound")
    if len(raw) < 64 or raw[:4] != b"\x7fELF":
        raise VerificationError("artifact is not an ELF file")
    if raw[4] != 2:
        raise VerificationError("artifact is not ELF64")
    if raw[5] != 1:
        raise VerificationError("artifact is not little-endian ELF")
    if raw[6] != 1:
        raise VerificationError("artifact has an unsupported ELF version")
    elf_type = int.from_bytes(raw[16:18], "little")
    machine = int.from_bytes(raw[18:20], "little")
    if elf_type not in {ET_EXEC, ET_DYN}:
        raise VerificationError("artifact is not an executable/PIE ELF")
    if machine != EM_AARCH64:
        raise VerificationError(f"artifact machine is {machine}, expected AArch64 ({EM_AARCH64})")

    result = {
        "bytes": len(raw),
        "sha256": sha256_bytes(raw),
        "mode": f"{mode:04o}",
        "elf_class": "ELF64",
        "endianness": "little",
        "elf_type": elf_type,
        "machine": "AArch64",
        "machine_id": machine,
    }
    return result, raw


def load_version_output(path: Path) -> tuple[dict[str, Any], bytes]:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size == 0
        or metadata.st_size > MAX_VERSION_OUTPUT_BYTES
        or metadata.st_mode & 0o022
    ):
        raise VerificationError("version output must be one bounded non-writable regular file")
    raw = path.read_bytes()
    if len(raw) != metadata.st_size or b"\x00" in raw:
        raise VerificationError("version output changed or contains NUL")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError("version output is not UTF-8") from error
    if "Android Debug Bridge version" not in text:
        raise VerificationError("version output does not identify Android Debug Bridge")
    return {"bytes": len(raw), "sha256": sha256_bytes(raw), "raw": text}, raw


def verify(
    artifact_path: Path,
    metadata_path: Path,
    version_output_path: Path,
) -> dict[str, Any]:
    document = load_metadata(metadata_path)
    if document["schema"] != SCHEMA:
        raise VerificationError(f"metadata schema must be {SCHEMA}")

    artifact_meta = strict_object(
        document["artifact"],
        label="artifact metadata",
        required={
            "sha256",
            "bytes",
            "architecture",
            "os",
            "format",
            "install_path",
            "install_mode",
        },
    )
    source_meta = strict_object(
        document["source"],
        label="source metadata",
        required={
            "kind",
            "name",
            "revision_or_version",
            "provenance",
            "license",
            "build_or_package_command",
            "toolchain_or_repository",
        },
    )
    runtime_meta = strict_object(
        document["runtime_observation"],
        label="runtime observation metadata",
        required={"adb_version_output_sha256", "observed_on"},
    )
    claims = strict_object(
        document["claims"],
        label="claims",
        required={
            "ordinary_adb_client",
            "typed_trillionnium_adapter",
            "image_inclusion",
            "integrated_codex_turn",
            "physical_device_effect",
            "release_qualified",
        },
    )

    observed_artifact, _ = inspect_artifact(artifact_path)
    observed_version, _ = load_version_output(version_output_path)

    expected_sha = required_sha256(artifact_meta["sha256"], "artifact.sha256")
    if observed_artifact["sha256"] != expected_sha:
        raise VerificationError("artifact SHA-256 does not match metadata")
    if not isinstance(artifact_meta["bytes"], int) or artifact_meta["bytes"] <= 0:
        raise VerificationError("artifact.bytes must be a positive integer")
    if observed_artifact["bytes"] != artifact_meta["bytes"]:
        raise VerificationError("artifact byte size does not match metadata")
    if artifact_meta["architecture"] != "linux-arm64":
        raise VerificationError("artifact architecture must be linux-arm64")
    if artifact_meta["os"] != "linux":
        raise VerificationError("artifact os must be linux")
    if artifact_meta["format"] != "ELF64-AArch64":
        raise VerificationError("artifact format must be ELF64-AArch64")
    if artifact_meta["install_path"] != "/usr/bin/adb":
        raise VerificationError("owner-open Root Linux adb install path must be /usr/bin/adb")
    if artifact_meta["install_mode"] != "0755":
        raise VerificationError("adb install mode must be 0755")

    source_kind = required_string(source_meta["kind"], "source.kind", 64)
    if source_kind not in {"aosp-reproducible-build", "distribution-package"}:
        raise VerificationError("source.kind is not an accepted recorded source form")
    for field in (
        "name",
        "revision_or_version",
        "provenance",
        "license",
        "build_or_package_command",
        "toolchain_or_repository",
    ):
        required_string(source_meta[field], f"source.{field}")

    expected_version_sha = required_sha256(
        runtime_meta["adb_version_output_sha256"],
        "runtime_observation.adb_version_output_sha256",
    )
    if observed_version["sha256"] != expected_version_sha:
        raise VerificationError("adb version output SHA-256 does not match metadata")
    required_string(runtime_meta["observed_on"], "runtime_observation.observed_on", 256)

    expected_claims = {
        "ordinary_adb_client": True,
        "typed_trillionnium_adapter": False,
        "image_inclusion": False,
        "integrated_codex_turn": False,
        "physical_device_effect": False,
        "release_qualified": False,
    }
    if claims != expected_claims:
        raise VerificationError(
            "claims must identify an ordinary client while keeping image/turn/device/release false"
        )

    return {
        "schema": REPORT_SCHEMA,
        "accepted": True,
        "artifact": observed_artifact,
        "source": source_meta,
        "runtime_observation": observed_version,
        "claim_ceiling": "QUALIFIED_SOURCE_ARTIFACT_ONLY",
        "image_inclusion": False,
        "integrated_codex_turn": False,
        "physical_device_effect": False,
        "release_qualified": False,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--version-output", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    arguments = parse_args(argv)
    try:
        report = verify(arguments.artifact, arguments.metadata, arguments.version_output)
    except (OSError, VerificationError) as error:
        if arguments.json:
            print(
                json.dumps(
                    {
                        "schema": REPORT_SCHEMA,
                        "accepted": False,
                        "error": str(error),
                    },
                    sort_keys=True,
                )
            )
        else:
            print(f"HOLD: {error}", file=sys.stderr)
        return 1
    if arguments.json:
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print(
            "PASS_SOURCE_ARTIFACT_ONLY "
            f"sha256={report['artifact']['sha256']} bytes={report['artifact']['bytes']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
