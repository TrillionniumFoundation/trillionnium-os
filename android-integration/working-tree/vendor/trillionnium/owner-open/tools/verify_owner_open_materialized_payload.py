#!/usr/bin/env python3
"""Fail-closed admission for externally materialized owner-open Root Linux images.

The Android build may consume only an image/manifest pair produced by the
selected reproducible image builder. This tool never downloads, rebuilds or
substitutes an artifact. It validates exact bytes and emits one requested Soong
output (image, manifest, or digest) using create-only publication.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any, Iterable

IMAGE_NAME = "owner-open-rootfs.squashfs"
MANIFEST_NAME = "owner-open-rootfs.image-manifest.json"
IMAGE_SCHEMA = "org.trillionnium.owner-open.rootfs-image-manifest.v1"
RUNTIME_STATE_DIRECTORY = "/var/lib/trillionnium/owner-open"
MAX_IMAGE_BYTES = 8 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_ENTRY_BYTES = 512 * 1024 * 1024
MAX_ENTRIES = 4096
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class MaterializationError(RuntimeError):
    pass


class DuplicateMember(ValueError):
    pass


def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise DuplicateMember(f"duplicate key {key}")
        result[key] = value
    return result


def stable_regular(path: Path, label: str, maximum: int) -> os.stat_result:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > maximum
        or metadata.st_mode & 0o022
    ):
        raise MaterializationError(f"{label} is not one stable bounded read-only file")
    return metadata


def hash_file(path: Path, maximum: int) -> tuple[str, int]:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_CLOEXEC)
    digest = hashlib.sha256()
    count = 0
    try:
        before = os.fstat(descriptor)
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            count += len(chunk)
            if count > maximum:
                raise MaterializationError(f"input exceeds byte bound: {path}")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after or count != before.st_size:
            raise MaterializationError(f"input changed while read: {path}")
    finally:
        os.close(descriptor)
    return digest.hexdigest(), count


def load_manifest(path: Path) -> tuple[dict[str, Any], bytes]:
    metadata = stable_regular(path, "image manifest", MAX_MANIFEST_BYTES)
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        raise MaterializationError("image manifest changed while read")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateMember) as error:
        raise MaterializationError(f"invalid image manifest: {error}") from error
    if not isinstance(value, dict) or value.get("schema") != IMAGE_SCHEMA:
        raise MaterializationError(f"image manifest schema must be {IMAGE_SCHEMA}")
    return value, raw


def locate(inputs: Iterable[Path]) -> tuple[Path, Path]:
    images: list[Path] = []
    manifests: list[Path] = []
    for path in inputs:
        if path.name == IMAGE_NAME:
            images.append(path)
        elif path.name == MANIFEST_NAME:
            manifests.append(path)
    if len(images) != 1 or len(manifests) != 1:
        raise MaterializationError(
            "materialized payload must contain exactly one image and one image manifest"
        )
    if images[0].resolve() == manifests[0].resolve():
        raise MaterializationError("image and manifest paths alias")
    return images[0], manifests[0]


def validate_entries(manifest: dict[str, Any]) -> None:
    entries = manifest.get("entries")
    entry_count = manifest.get("entry_count")
    if (
        not isinstance(entry_count, int)
        or isinstance(entry_count, bool)
        or not 1 <= entry_count <= MAX_ENTRIES
        or not isinstance(entries, list)
        or len(entries) != entry_count
    ):
        raise MaterializationError("image manifest entry inventory is incomplete")
    roles: set[str] = set()
    destinations: set[str] = set()
    allowed_prefixes = (
        "/bin/",
        "/lib/",
        "/lib64/",
        "/usr/bin/",
        "/usr/lib/",
        "/usr/lib64/",
        "/usr/libexec/trillionnium/",
        "/etc/trillionnium/",
    )
    for index, item in enumerate(entries):
        if not isinstance(item, dict):
            raise MaterializationError(f"image manifest entry {index} is malformed")
        role = item.get("role")
        destination = item.get("destination")
        mode = item.get("mode")
        uid = item.get("uid")
        gid = item.get("gid")
        bytes_value = item.get("bytes")
        digest_value = item.get("sha256")
        if (
            not isinstance(role, str)
            or not role
            or role in roles
            or not isinstance(destination, str)
            or not destination.startswith("/")
            or destination.endswith("/")
            or "\x00" in destination
            or ".." in PurePosixPath(destination).parts
            or str(PurePosixPath(destination)) != destination
            or not any(destination.startswith(prefix) for prefix in allowed_prefixes)
            or destination in destinations
            or not isinstance(mode, str)
            or re.fullmatch(r"0[0-7]{3}", mode) is None
            or int(mode, 8) & 0o022
            or not isinstance(uid, int)
            or isinstance(uid, bool)
            or uid != 0
            or not isinstance(gid, int)
            or isinstance(gid, bool)
            or gid != 0
            or not isinstance(bytes_value, int)
            or isinstance(bytes_value, bool)
            or not 1 <= bytes_value <= MAX_ENTRY_BYTES
            or not isinstance(digest_value, str)
            or SHA256.fullmatch(digest_value) is None
        ):
            raise MaterializationError(f"image manifest entry {index} is malformed")
        roles.add(role)
        destinations.add(destination)


def validate(image: Path, manifest_path: Path) -> tuple[dict[str, Any], bytes, str, int]:
    stable_regular(image, "rootfs image", MAX_IMAGE_BYTES)
    manifest, raw = load_manifest(manifest_path)
    digest, count = hash_file(image, MAX_IMAGE_BYTES)
    if manifest.get("runtime_state_directory") != RUNTIME_STATE_DIRECTORY:
        raise MaterializationError(
            "image manifest does not bind the canonical writable state mountpoint"
        )
    validate_entries(manifest)
    expected_digest = manifest.get("image_sha256")
    expected_bytes = manifest.get("image_bytes")
    if not isinstance(expected_digest, str) or SHA256.fullmatch(expected_digest) is None:
        raise MaterializationError("image manifest image_sha256 is malformed")
    if not isinstance(expected_bytes, int) or isinstance(expected_bytes, bool) or expected_bytes <= 0:
        raise MaterializationError("image manifest image_bytes is malformed")
    if digest != expected_digest or count != expected_bytes:
        raise MaterializationError("rootfs image bytes do not match the image manifest")
    if manifest.get("reproducible") is not True:
        raise MaterializationError("image manifest does not claim byte-identical reproduction")
    runs = manifest.get("reproducibility_runs")
    if not isinstance(runs, int) or isinstance(runs, bool) or not 2 <= runs <= 4:
        raise MaterializationError("image manifest reproducibility run count is invalid")
    build_runs = manifest.get("build_runs")
    if not isinstance(build_runs, list) or len(build_runs) != runs:
        raise MaterializationError("image manifest build run inventory is incomplete")
    for index, item in enumerate(build_runs):
        if not isinstance(item, dict):
            raise MaterializationError(f"image manifest build run {index} is malformed")
        run_bytes = item.get("image_bytes")
        if (
            item.get("image_sha256") != digest
            or not isinstance(run_bytes, int)
            or isinstance(run_bytes, bool)
            or run_bytes != count
        ):
            raise MaterializationError(f"image manifest build run {index} does not bind selected bytes")
    claims = manifest.get("claims")
    expected_claims = {
        "staging_revalidated": True,
        "deterministic_options_observed": True,
        "independent_builds_byte_identical": True,
        "rootfs_image_built": True,
        "android_module_bound": False,
        "target_files_built": False,
        "image_included": False,
        "physical_device_observed": False,
        "public_release": False,
    }
    if claims != expected_claims:
        raise MaterializationError(
            "image manifest claims must remain pre-Android and pre-device at materialization"
        )
    if manifest.get("claim_ceiling") != "ROOTFS_IMAGE_BUILT_NOT_ANDROID_INCLUDED":
        raise MaterializationError("image manifest claim ceiling drifted")
    return manifest, raw, digest, count


def open_output(path: Path) -> int:
    if not path.is_absolute() or path.parent.is_symlink() or not path.parent.is_dir():
        raise MaterializationError("Soong output must be an absolute path below a real directory")
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | os.O_CLOEXEC,
        0o644,
    )
    try:
        # open(2) applies the process umask.  The materialization contract
        # is an exact 0644 output, so normalize the descriptor before any
        # bytes are published and make the mode independent of the caller's
        # umask.
        os.fchmod(descriptor, 0o644)
        return descriptor
    except Exception:
        os.close(descriptor)
        path.unlink(missing_ok=True)
        raise


def publish_bytes(path: Path, value: bytes) -> None:
    descriptor = open_output(path)
    try:
        offset = 0
        while offset < len(value):
            written = os.write(descriptor, value[offset:])
            if written <= 0:
                raise MaterializationError("short write while publishing Soong output")
            offset += written
        os.fsync(descriptor)
    except Exception:
        try:
            os.close(descriptor)
        finally:
            path.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)


def publish_image(source: Path, output: Path, expected_digest: str, expected_bytes: int) -> None:
    source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_CLOEXEC)
    output_fd = open_output(output)
    digest = hashlib.sha256()
    count = 0
    try:
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            count += len(chunk)
            if count > MAX_IMAGE_BYTES:
                raise MaterializationError("rootfs image exceeds byte bound during publication")
            offset = 0
            while offset < len(chunk):
                written = os.write(output_fd, chunk[offset:])
                if written <= 0:
                    raise MaterializationError("short write while publishing rootfs image")
                offset += written
        os.fsync(output_fd)
        if digest.hexdigest() != expected_digest or count != expected_bytes:
            raise MaterializationError("rootfs image changed during Soong publication")
    except Exception:
        try:
            os.close(source_fd)
        finally:
            try:
                os.close(output_fd)
            finally:
                output.unlink(missing_ok=True)
        raise
    else:
        os.close(source_fd)
        os.close(output_fd)


def materialize(kind: str, output: Path, inputs: list[Path]) -> dict[str, Any]:
    image, manifest_path = locate(inputs)
    _manifest, manifest_raw, digest, count = validate(image, manifest_path)
    if kind == "image":
        publish_image(image, output, digest, count)
    elif kind == "manifest":
        publish_bytes(output, manifest_raw)
    elif kind == "digest":
        publish_bytes(output, f"{digest}\n".encode("ascii"))
    else:
        raise MaterializationError(f"unsupported materialization kind: {kind}")
    return {
        "schema": "org.trillionnium.owner-open.android-payload-materialization.v1",
        "kind": kind,
        "image_sha256": digest,
        "image_bytes": count,
        "output": str(output),
        "claim_ceiling": "SOONG_INPUT_MATERIALIZED_NOT_TARGET_FILES",
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", choices=("image", "manifest", "digest"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("inputs", nargs="+", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        report = materialize(args.kind, args.output, args.inputs)
    except (OSError, MaterializationError) as error:
        print(f"HOLD: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
