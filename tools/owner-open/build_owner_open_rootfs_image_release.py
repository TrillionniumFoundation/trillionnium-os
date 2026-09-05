#!/usr/bin/env python3
"""Build and reproducibility-check an owner-open Root Linux squashfs payload.

The builder accepts only a staging tree produced by the release stager, measures
one exact mksquashfs executable, verifies required deterministic options, builds
from independent normalized copies and requires byte-identical image hashes.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
from typing import Any

STAGING_SCHEMA = "org.trillionnium.owner-open.rootfs-payload-manifest.v1"
IMAGE_SCHEMA = "org.trillionnium.owner-open.rootfs-image-manifest.v1"
RUNTIME_STATE_DIRECTORY = "/var/lib/trillionnium/owner-open"
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_IMAGE_BYTES = 8 * 1024 * 1024 * 1024
MAX_TOOL_BYTES = 512 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
REQUIRED_HELP_TOKENS = (
    "-noappend",
    "-all-root",
    "-no-xattrs",
    "-no-exports",
    "-no-progress",
    "-comp",
    "-b",
    "-mkfs-time",
    "-all-time",
    "-sort",
)
IMAGE_OPTIONS = (
    "-noappend",
    "-all-root",
    "-no-xattrs",
    "-no-exports",
    "-no-progress",
    "-comp",
    "zstd",
    "-b",
    "131072",
    "-mkfs-time",
    "0",
    "-all-time",
    "0",
)


class ImageError(RuntimeError):
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


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_path(path: Path, maximum: int) -> tuple[str, int]:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256()
    count = 0
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            count += len(chunk)
            if count > maximum:
                raise ImageError(f"file exceeds byte bound: {path}")
    finally:
        os.close(descriptor)
    return digest.hexdigest(), count


def stable_file(path: Path, label: str, maximum: int, *, executable: bool = False) -> os.stat_result:
    if not path.is_absolute():
        raise ImageError(f"{label} must be absolute")
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > maximum
        or metadata.st_mode & 0o022
        or (executable and (metadata.st_mode & 0o111 == 0 or not os.access(path, os.X_OK)))
    ):
        raise ImageError(f"{label} is not a stable bounded file")
    return metadata


def load_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    metadata = stable_file(path, label, MAX_MANIFEST_BYTES)
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        raise ImageError(f"{label} changed while read")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateMember) as error:
        raise ImageError(f"invalid {label}: {error}") from error
    if not isinstance(value, dict):
        raise ImageError(f"{label} must contain an object")
    return value, raw


def private_directory(path: Path, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise ImageError(f"{label} must be an absolute real directory")
    metadata = path.lstat()
    if metadata.st_uid not in {0, os.geteuid()} or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ImageError(f"{label} must be owner controlled and non-writable by group/world")
    return path


def new_output(path: Path) -> None:
    if not path.is_absolute() or not path.parent.is_dir() or path.parent.is_symlink():
        raise ImageError("image output must be an absolute new directory")
    private_directory(path.parent, "image output parent")
    if path.exists() or path.is_symlink():
        raise ImageError("image output already exists")


def manifest_entries(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    values = manifest.get("entries")
    if not isinstance(values, list) or not values:
        raise ImageError("staging manifest entries are empty")
    result: dict[str, dict[str, Any]] = {}
    roles: set[str] = set()
    for value in values:
        if not isinstance(value, dict):
            raise ImageError("staging manifest entry is not an object")
        role, destination = value.get("role"), value.get("destination")
        if not isinstance(role, str) or not role or role in roles:
            raise ImageError("staging manifest role is malformed or duplicated")
        roles.add(role)
        if not isinstance(destination, str) or not destination.startswith("/"):
            raise ImageError("staging manifest destination is malformed")
        path = PurePosixPath(destination)
        if ".." in path.parts or str(path) != destination or destination in result:
            raise ImageError("staging manifest destination is noncanonical or duplicated")
        result[destination] = value
    return result


def validate_staging(staging: Path) -> tuple[dict[str, Any], bytes, Path, list[str]]:
    private_directory(staging, "staging output")
    root = staging / "root"
    if root.is_symlink() or not root.is_dir():
        raise ImageError("staging root is missing or not a real directory")
    manifest_path = staging / "owner-open-rootfs.manifest.json"
    manifest, manifest_raw = load_json(manifest_path, "staging manifest")
    if manifest.get("schema") != STAGING_SCHEMA:
        raise ImageError(f"staging manifest schema must be {STAGING_SCHEMA}")
    claims = manifest.get("claims")
    if (
        not isinstance(claims, dict)
        or claims.get("staging_tree_complete") is not True
        or claims.get("rootfs_image_built") is not False
    ):
        raise ImageError("staging manifest claims are incompatible")
    if manifest.get("runtime_state_directory") != RUNTIME_STATE_DIRECTORY:
        raise ImageError(
            "staging manifest does not reserve the canonical writable state mountpoint"
        )
    observed = validate_root_snapshot(root, manifest, manifest_raw)
    return manifest, manifest_raw, root, observed


def validate_root_snapshot(root: Path, manifest: dict[str, Any], manifest_raw: bytes) -> list[str]:
    """Bind each observed build tree to the original validated manifest bytes.

    Reproducibility is not provenance. Never replace this snapshot by a freshly
    loaded manifest after executing a tool or copying mutable staging inputs.
    This is interval validation, not isolation from a malicious build tool.
    """
    if root.is_symlink() or not root.is_dir():
        raise ImageError("normalized staging copy root is not a real directory")
    entries = manifest_entries(manifest)
    embedded = root / "etc/trillionnium/owner-open/rootfs.manifest.json"
    stable_file(embedded, "embedded staging manifest", MAX_MANIFEST_BYTES)
    if embedded.read_bytes() != manifest_raw:
        raise ImageError("embedded and external staging manifests differ")
    expected_files = {
        destination.removeprefix("/"): value for destination, value in entries.items()
    }
    expected_files["etc/trillionnium/owner-open/rootfs.manifest.json"] = {
        "sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "bytes": len(manifest_raw),
        "mode": "0444",
    }
    state_directory = root / RUNTIME_STATE_DIRECTORY.removeprefix("/")
    if state_directory.is_symlink() or not state_directory.is_dir():
        raise ImageError("staging tree is missing the canonical writable state mountpoint")
    state_metadata = state_directory.lstat()
    if stat.S_IMODE(state_metadata.st_mode) != 0o755:
        raise ImageError("canonical writable state mountpoint mode is not 0755")
    observed: list[str] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ImageError(f"staging tree contains a symlink: {relative}")
        if stat.S_ISDIR(metadata.st_mode):
            if stat.S_IMODE(metadata.st_mode) != 0o755:
                raise ImageError(f"staging directory mode is not 0755: {relative}")
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ImageError(f"staging tree contains a non-regular file: {relative}")
        expected = expected_files.get(relative)
        if expected is None:
            raise ImageError(f"staging tree contains an undeclared file: {relative}")
        digest, count = sha256_path(path, MAX_FILE_BYTES)
        if digest != expected.get("sha256") or count != expected.get("bytes"):
            raise ImageError(f"staging file digest or byte count drifted: {relative}")
        expected_mode = expected.get("mode")
        if not isinstance(expected_mode, str) or stat.S_IMODE(metadata.st_mode) != int(expected_mode, 8):
            raise ImageError(f"staging file mode drifted: {relative}")
        observed.append(relative)
    if set(observed) != set(expected_files):
        missing = sorted(set(expected_files) - set(observed))
        raise ImageError(f"staging tree is missing manifest files: {missing}")
    return sorted(observed)


def measure_tool(path: Path, expected: str) -> dict[str, Any]:
    metadata = stable_file(path, "mksquashfs", MAX_TOOL_BYTES, executable=True)
    actual, count = sha256_path(path, MAX_TOOL_BYTES)
    if re.fullmatch(r"[0-9a-f]{64}", expected) is None or actual != expected:
        raise ImageError("mksquashfs does not match the expected SHA-256")
    return {
        "path": str(path),
        "sha256": actual,
        "bytes": count,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }


def bounded_command(argv: list[str], timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            start_new_session=True,
            check=False,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "TZ": "UTC"},
        )
    except subprocess.TimeoutExpired as error:
        raise ImageError(f"command timed out: {argv[0]}") from error
    if len(completed.stdout) + len(completed.stderr) > MAX_OUTPUT_BYTES:
        raise ImageError(f"command output exceeds byte bound: {argv[0]}")
    return {
        "returncode": completed.returncode,
        "elapsed_ms": max(0, int((time.monotonic() - started) * 1000)),
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
    }


def probe_tool(path: Path, timeout: float) -> dict[str, Any]:
    result = bounded_command([str(path), "-help"], timeout)
    text = (result["stdout"] + b"\n" + result["stderr"]).decode(
        "utf-8", errors="replace"
    )
    if result["returncode"] != 0:
        raise ImageError("mksquashfs help probe failed")
    missing = [token for token in REQUIRED_HELP_TOKENS if token not in text]
    if missing:
        raise ImageError(f"mksquashfs lacks required deterministic options: {missing}")
    return {
        "stdout_sha256": result["stdout_sha256"],
        "stderr_sha256": result["stderr_sha256"],
        "output_bytes": len(result["stdout"]) + len(result["stderr"]),
        "required_options_observed": list(REQUIRED_HELP_TOKENS),
    }


def normalize_copy(source_root: Path, destination_root: Path) -> list[str]:
    destination_root.mkdir(mode=0o755)
    paths: list[str] = []
    for source in sorted(source_root.rglob("*")):
        relative = source.relative_to(source_root)
        target = destination_root / relative
        metadata = source.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            target.mkdir(mode=0o755, parents=True, exist_ok=True)
            os.chmod(target, 0o755)
            os.utime(target, ns=(0, 0), follow_symlinks=False)
            paths.append(relative.as_posix())
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ImageError(f"staging copy encountered non-regular file: {relative}")
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        shutil.copyfile(source, target, follow_symlinks=False)
        os.chmod(target, stat.S_IMODE(metadata.st_mode))
        os.utime(target, ns=(0, 0), follow_symlinks=False)
        paths.append(relative.as_posix())
    # Normalize directory times after all children have been created.
    directories = [path for path in destination_root.rglob("*") if path.is_dir()]
    for directory in sorted(directories, reverse=True):
        os.utime(directory, ns=(0, 0), follow_symlinks=False)
    os.utime(destination_root, ns=(0, 0), follow_symlinks=False)
    return sorted(paths)


def sort_file(path: Path, relative_paths: list[str]) -> None:
    if len(relative_paths) > 32768:
        raise ImageError("staging path count exceeds sort priority range")
    lines = [f"{relative} {32767 - index}" for index, relative in enumerate(relative_paths)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)


def build_once(
    tool: Path,
    source_root: Path,
    image: Path,
    sort_path: Path,
    timeout: float,
) -> dict[str, Any]:
    argv = [
        str(tool),
        str(source_root),
        str(image),
        *IMAGE_OPTIONS,
        "-sort",
        str(sort_path),
    ]
    result = bounded_command(argv, timeout)
    if result["returncode"] != 0:
        raise ImageError(
            "mksquashfs failed: "
            + result["stderr"][-2048:].decode("utf-8", errors="replace")
        )
    metadata = stable_file(image, "built rootfs image", MAX_IMAGE_BYTES)
    digest, count = sha256_path(image, MAX_IMAGE_BYTES)
    return {
        "argv_options": list(IMAGE_OPTIONS) + ["-sort", "<generated-sort-file>"],
        "returncode": result["returncode"],
        "elapsed_ms": result["elapsed_ms"],
        "stdout_sha256": result["stdout_sha256"],
        "stderr_sha256": result["stderr_sha256"],
        "image_sha256": digest,
        "image_bytes": count,
        "image_mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
    }


def atomic_json(path: Path, value: Any, mode: int) -> None:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise ImageError("image manifest write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    os.chmod(path, mode)


def build(args: argparse.Namespace) -> dict[str, Any]:
    staging = private_directory(args.staging, "staging output")
    manifest, manifest_raw, staging_root, observed = validate_staging(staging)
    tool = Path(args.mksquashfs)
    measurement = measure_tool(tool, args.expected_mksquashfs_sha256)
    help_observation = probe_tool(tool, args.probe_timeout)
    new_output(args.output)
    args.output.mkdir(mode=0o700)
    runs: list[dict[str, Any]] = []
    try:
        for index in range(args.runs):
            run_root = args.output / f"run-{index + 1}-root"
            paths = normalize_copy(staging_root, run_root)
            validate_root_snapshot(run_root, manifest, manifest_raw)
            if paths != observed:
                raise ImageError("normalized staging copy path set drifted")
            sort_path = args.output / f"run-{index + 1}.sort"
            sort_file(sort_path, paths)
            image = args.output / f"run-{index + 1}.squashfs"
            # A changed tool or source must not acquire an old identity receipt.
            measure_tool(tool, args.expected_mksquashfs_sha256)
            runs.append(
                build_once(tool, run_root, image, sort_path, args.build_timeout)
            )
            validate_root_snapshot(run_root, manifest, manifest_raw)
        measure_tool(tool, args.expected_mksquashfs_sha256)
        digests = {item["image_sha256"] for item in runs}
        sizes = {item["image_bytes"] for item in runs}
        if len(digests) != 1 or len(sizes) != 1:
            raise ImageError("independent rootfs image builds are not byte-identical")
        selected_image = args.output / "owner-open-rootfs.squashfs"
        os.replace(args.output / "run-1.squashfs", selected_image)
        os.chmod(selected_image, 0o444)
        for index in range(args.runs):
            shutil.rmtree(args.output / f"run-{index + 1}-root", ignore_errors=True)
            (args.output / f"run-{index + 1}.sort").unlink(missing_ok=True)
            (args.output / f"run-{index + 1}.squashfs").unlink(missing_ok=True)
        image_manifest = {
            "schema": IMAGE_SCHEMA,
            "payload_id": manifest.get("payload_id"),
            "staging_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "staging_plan_sha256": manifest.get("plan_sha256"),
            "architecture": manifest.get("architecture"),
            "libc": manifest.get("libc"),
            "entry_count": manifest.get("entry_count"),
            # Carry the complete per-entry contract into the Android-facing
            # manifest. The native bootstrap validates these records against
            # the mounted image before it starts the Root Linux supervisor.
            "entries": manifest.get("entries"),
            "runtime_state_directory": manifest.get("runtime_state_directory"),
            "mksquashfs": measurement,
            "help_observation": help_observation,
            "build_runs": runs,
            "reproducibility_runs": args.runs,
            "reproducible": True,
            "image_sha256": runs[0]["image_sha256"],
            "image_bytes": runs[0]["image_bytes"],
            "image_path": str(selected_image),
            "claims": {
                "staging_revalidated": True,
                "deterministic_options_observed": True,
                "independent_builds_byte_identical": True,
                "rootfs_image_built": True,
                "android_module_bound": False,
                "target_files_built": False,
                "image_included": False,
                "physical_device_observed": False,
                "public_release": False,
            },
            "claim_ceiling": "ROOTFS_IMAGE_BUILT_NOT_ANDROID_INCLUDED",
        }
        atomic_json(
            args.output / "owner-open-rootfs.image-manifest.json",
            image_manifest,
            0o600,
        )
        return image_manifest
    except Exception:
        shutil.rmtree(args.output, ignore_errors=True)
        raise


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--staging", required=True, type=Path)
    parser.add_argument("--mksquashfs", required=True, type=Path)
    parser.add_argument("--expected-mksquashfs-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--probe-timeout", type=float, default=10.0)
    parser.add_argument("--build-timeout", type=float, default=300.0)
    parser.add_argument("--json", action="store_true")
    result = parser.parse_args(argv)
    if not result.execute:
        parser.error("--execute is required to build a rootfs image")
    if not 2 <= result.runs <= 4:
        parser.error("--runs must be between 2 and 4")
    if not 0.1 <= result.probe_timeout <= 120 or not 1 <= result.build_timeout <= 1800:
        parser.error("probe or build timeout is outside the finite bound")
    return result


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        result = build(args)
    except (OSError, ImageError, subprocess.SubprocessError) as error:
        print(f"HOLD: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print(
            "PASS_ROOTFS_IMAGE_BUILT_NOT_ANDROID_INCLUDED "
            f"sha256={result['image_sha256']} runs={result['reproducibility_runs']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
