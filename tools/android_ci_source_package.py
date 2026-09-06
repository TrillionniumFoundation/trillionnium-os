#!/usr/bin/env python3
"""Create and verify the small, exact source package used by Android CI.

The repository is an integration/control repository, not a flattened Android
checkout.  This tool therefore packages *tracked files in this repository*
only and says so explicitly in the manifest.  It never pretends that a
LineageOS/repo-manifest checkout, an APK, a target-files archive, or a device
image is present.

The manifest is intentionally strict and content-addressed.  A consumer must
verify the repository, commit, tree, archive size, archive digest, and archive
member safety before it extracts or executes anything from the package.
"""
from __future__ import annotations

import argparse
from collections.abc import Iterable
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
from typing import Any


SCHEMA = "org.trillionnium.android-ci.source-package.v1"
TOOL_VERSION = "1.0.0"
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$"
)
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
MAX_MEMBER_NAME_BYTES = 4096
MAX_MANIFEST_BYTES = 256 * 1024
MAX_UNCOMPRESSED_BYTES = 512 * 1024 * 1024


class PackageError(RuntimeError):
    """Raised for an invalid or ambiguous package."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _json_load(path: Path) -> Any:
    metadata = _regular_path(path, "manifest")
    if metadata.st_size <= 0 or metadata.st_size > MAX_MANIFEST_BYTES:
        raise PackageError("manifest size is outside the permitted bound")
    try:
        with path.open("rb") as stream:
            encoded = stream.read(MAX_MANIFEST_BYTES + 1)
        if len(encoded) != metadata.st_size:
            raise PackageError("manifest changed while being read")
        return json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=_reject_nonfinite,
        )
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise PackageError(f"invalid JSON {path}: {error}") from error


def _run_git(repo_root: Path, *arguments: str) -> str:
    command = ["git", "-C", str(repo_root), "--no-replace-objects", *arguments]
    try:
        completed = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", "") or str(error)
        raise PackageError(f"git command failed: {' '.join(command)}: {detail.strip()}") from error
    return completed.stdout


def _regular_path(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise PackageError(f"{label} is unavailable: {path}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise PackageError(f"{label} must not be a symlink: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise PackageError(f"{label} must be a regular file: {path}")
    return metadata


def _directory(path: Path, label: str) -> Path:
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_dir():
            raise PackageError(f"{label} must be a real directory: {path}")
    else:
        try:
            path.mkdir(parents=True)
        except OSError as error:
            raise PackageError(f"cannot create {label} {path}: {error}") from error
    return path


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _sha256(path: Path) -> tuple[int, str]:
    metadata = _regular_path(path, "archive")
    if metadata.st_size <= 0 or metadata.st_size > MAX_ARCHIVE_BYTES:
        raise PackageError(
            f"archive size {metadata.st_size} is outside the 1..{MAX_ARCHIVE_BYTES} byte bound"
        )
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as stream:
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                digest.update(block)
    except OSError as error:
        raise PackageError(f"cannot hash archive {path}: {error}") from error
    if total != metadata.st_size:
        raise PackageError(f"archive changed while being hashed: {path}")
    return total, digest.hexdigest()


def _write_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
    if path.exists() or path.is_symlink():
        raise PackageError(f"refusing to overwrite existing path: {path}")
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            mode,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise PackageError(f"cannot write {path}: {error}") from error


def _validate_sha(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise PackageError(f"{label} is not a lowercase hexadecimal digest")
    return value


def _validate_repository(value: Any, label: str = "repository") -> str:
    if not isinstance(value, str) or REPOSITORY_RE.fullmatch(value) is None:
        raise PackageError(f"{label} must be OWNER/REPOSITORY")
    return value


def _validate_member_name(name: str) -> None:
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as error:
        raise PackageError("archive member name is not valid UTF-8") from error
    if not name or len(encoded) > MAX_MEMBER_NAME_BYTES:
        raise PackageError("archive member name is empty or too long")
    path = PurePosixPath(name)
    if path.is_absolute() or "\\" in name:
        raise PackageError(f"archive member has an unsafe name: {name!r}")
    parts = name.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise PackageError(f"archive member has an unsafe path: {name!r}")


def _inspect_archive(path: Path) -> int:
    """Validate a gzip tar without extracting it and return file count."""
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
    except (OSError, tarfile.TarError) as error:
        raise PackageError(f"cannot inspect source archive {path}: {error}") from error
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise PackageError(f"archive has too many members: {len(members)}")
    file_count = 0
    uncompressed_bytes = 0
    names: set[str] = set()
    for member in members:
        _validate_member_name(member.name)
        if member.name in names:
            raise PackageError(f"archive contains a duplicate member: {member.name!r}")
        names.add(member.name)
        # A source package must be safe to materialize in a future build
        # workspace.  Git links, symlinks and device nodes are not needed here
        # and would create an avoidable extraction ambiguity.
        if member.isdir():
            continue
        if not member.isfile():
            raise PackageError(
                f"archive member {member.name!r} is not a regular file or directory"
            )
        if member.size < 0:
            raise PackageError(f"archive member {member.name!r} has a negative size")
        uncompressed_bytes += member.size
        if uncompressed_bytes > MAX_UNCOMPRESSED_BYTES:
            raise PackageError("archive uncompressed content exceeds size ceiling")
        file_count += 1
    return file_count


def _create(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo_root).resolve(strict=True)
    if not repo_root.is_dir():
        raise PackageError(f"repo root is not a directory: {repo_root}")
    output_dir = _directory(Path(args.output_dir).resolve(), "output directory")
    if _is_within(output_dir, repo_root):
        raise PackageError("output directory must be outside the repository checkout")

    source_commit = _run_git(repo_root, "rev-parse", "HEAD").strip()
    source_tree = _run_git(repo_root, "rev-parse", "HEAD^{tree}").strip()
    if SHA1_RE.fullmatch(source_commit) is None or SHA1_RE.fullmatch(source_tree) is None:
        raise PackageError("git did not return full lowercase commit/tree IDs")
    if source_commit == "0" * 40 or source_tree == "0" * 40:
        raise PackageError("git returned an all-zero commit/tree ID")
    if args.expected_commit and source_commit != args.expected_commit:
        raise PackageError(
            f"checkout commit {source_commit} does not match expected {args.expected_commit}"
        )
    status = _run_git(repo_root, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise PackageError("repository checkout is dirty; refusing to package it")

    tracked_names = [
        line
        for line in _run_git(repo_root, "ls-tree", "-r", "--name-only", "HEAD").splitlines()
        if line
    ]
    if not tracked_names:
        raise PackageError("repository has no tracked files")
    if len(tracked_names) > MAX_ARCHIVE_MEMBERS:
        raise PackageError("repository has too many tracked files")

    archive_name = args.archive_name
    manifest_name = args.manifest_name
    if Path(archive_name).name != archive_name or not archive_name.endswith(".tar.gz"):
        raise PackageError("archive name must be a simple .tar.gz filename")
    if Path(manifest_name).name != manifest_name or not manifest_name.endswith(".json"):
        raise PackageError("manifest name must be a simple .json filename")
    archive_path = output_dir / archive_name
    manifest_path = output_dir / manifest_name
    if archive_path.exists() or archive_path.is_symlink() or manifest_path.exists() or manifest_path.is_symlink():
        raise PackageError("output archive or manifest already exists")

    command = [
        "git",
        "-C",
        str(repo_root),
        "--no-replace-objects",
        "archive",
        "--format=tar.gz",
        "--output",
        str(archive_path),
        "HEAD",
    ]
    try:
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", "") or str(error)
        raise PackageError(f"git archive failed: {detail.strip()}") from error

    archive_bytes, archive_sha256 = _sha256(archive_path)
    archive_member_count = _inspect_archive(archive_path)
    if archive_member_count != len(tracked_names):
        raise PackageError(
            "archive member count does not match tracked file count: "
            f"{archive_member_count} != {len(tracked_names)}"
        )
    repository = _validate_repository(args.repository)
    manifest = {
        "schema": SCHEMA,
        "version": 1,
        "tool_version": TOOL_VERSION,
        "repository": repository,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "archive": {
            "name": archive_name,
            "format": "tar.gz",
            "bytes": archive_bytes,
            "sha256": archive_sha256,
            "member_count": archive_member_count,
        },
        "package_kind": "tracked-control-repository-source",
        "claims": {
            "full_android_checkout_included": False,
            "android_build_performed": False,
            "apk_or_target_files_included": False,
            "device_mutation_performed": False,
        },
        # A stable timestamp is deliberately omitted: the package identity is
        # the exact source/tree/archive digest, not wall-clock metadata.
    }
    manifest_bytes = _canonical_json(manifest) + b"\n"
    _write_exclusive(manifest_path, manifest_bytes)
    sidecar = f"{archive_sha256}  {archive_name}\n".encode("ascii")
    _write_exclusive(output_dir / f"{archive_name}.sha256", sidecar)
    print(json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


def _verify_manifest_shape(manifest: Any) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise PackageError("manifest root must be an object")
    expected = {
        "schema",
        "version",
        "tool_version",
        "repository",
        "source_commit",
        "source_tree",
        "archive",
        "package_kind",
        "claims",
    }
    if set(manifest) != expected:
        raise PackageError(
            f"manifest keys drifted; expected {sorted(expected)}, got {sorted(manifest)}"
        )
    if manifest["schema"] != SCHEMA or manifest["version"] != 1:
        raise PackageError("unsupported source-package schema/version")
    if manifest["tool_version"] != TOOL_VERSION:
        raise PackageError("manifest tool_version is unsupported")
    _validate_repository(manifest["repository"])
    _validate_sha(manifest["source_commit"], SHA1_RE, "source_commit")
    _validate_sha(manifest["source_tree"], SHA1_RE, "source_tree")
    if manifest["package_kind"] != "tracked-control-repository-source":
        raise PackageError("manifest package_kind is unsupported")
    claims = manifest["claims"]
    expected_claims = {
        "full_android_checkout_included",
        "android_build_performed",
        "apk_or_target_files_included",
        "device_mutation_performed",
    }
    if not isinstance(claims, dict) or set(claims) != expected_claims or any(
        value is not False for value in claims.values()
    ):
        raise PackageError("source package claims must explicitly remain false")
    archive = manifest["archive"]
    expected_archive = {"name", "format", "bytes", "sha256", "member_count"}
    if not isinstance(archive, dict) or set(archive) != expected_archive:
        raise PackageError("manifest archive object keys drifted")
    name = archive["name"]
    if not isinstance(name, str) or Path(name).name != name or not name.endswith(".tar.gz"):
        raise PackageError("manifest archive name is unsafe")
    if archive["format"] != "tar.gz":
        raise PackageError("manifest archive format is unsupported")
    if not isinstance(archive["bytes"], int) or isinstance(archive["bytes"], bool) or archive["bytes"] <= 0:
        raise PackageError("manifest archive byte count is invalid")
    if archive["bytes"] > MAX_ARCHIVE_BYTES:
        raise PackageError("manifest archive exceeds size ceiling")
    _validate_sha(archive["sha256"], SHA256_RE, "archive.sha256")
    if not isinstance(archive["member_count"], int) or isinstance(archive["member_count"], bool) or archive["member_count"] <= 0:
        raise PackageError("manifest archive member_count is invalid")
    if archive["member_count"] > MAX_ARCHIVE_MEMBERS:
        raise PackageError("manifest archive member_count exceeds ceiling")
    return manifest


def _verify(args: argparse.Namespace) -> int:
    manifest_input = Path(args.manifest)
    _regular_path(manifest_input, "manifest")
    manifest_path = manifest_input.resolve(strict=True)
    manifest = _verify_manifest_shape(_json_load(manifest_path))
    if args.expected_repository:
        expected_repository = _validate_repository(args.expected_repository, "expected_repository")
        if manifest["repository"] != expected_repository:
            raise PackageError("manifest repository does not match expected repository")
    if args.expected_commit:
        _validate_sha(args.expected_commit, SHA1_RE, "expected_commit")
        if manifest["source_commit"] != args.expected_commit:
            raise PackageError("manifest source_commit does not match expected commit")
    if args.expected_tree:
        _validate_sha(args.expected_tree, SHA1_RE, "expected_tree")
        if manifest["source_tree"] != args.expected_tree:
            raise PackageError("manifest source_tree does not match expected tree")
    archive_name = manifest["archive"]["name"]
    if args.archive:
        archive_input = Path(args.archive)
        _regular_path(archive_input, "archive")
        archive_path = archive_input.resolve(strict=True)
    else:
        archive_input = manifest_path.parent / archive_name
        _regular_path(archive_input, "archive")
        archive_path = archive_input.resolve(strict=True)
    if archive_path.name != archive_name:
        raise PackageError("archive filename does not match manifest")
    archive_bytes, archive_sha256 = _sha256(archive_path)
    expected_archive = manifest["archive"]
    if archive_bytes != expected_archive["bytes"] or archive_sha256 != expected_archive["sha256"]:
        raise PackageError("archive size or SHA-256 does not match manifest")
    sidecar_path = archive_path.with_name(f"{archive_path.name}.sha256")
    _regular_path(sidecar_path, "archive SHA-256 sidecar")
    try:
        sidecar = sidecar_path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as error:
        raise PackageError(f"cannot read archive SHA-256 sidecar: {error}") from error
    expected_sidecar = f"{archive_sha256}  {archive_name}\n"
    if sidecar != expected_sidecar:
        raise PackageError("archive SHA-256 sidecar does not match manifest/archive")
    member_count = _inspect_archive(archive_path)
    if member_count != expected_archive["member_count"]:
        raise PackageError("archive member count does not match manifest")
    print(json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="create an exact tracked-source package")
    create.add_argument("--repo-root", required=True, type=Path)
    create.add_argument("--output-dir", required=True, type=Path)
    create.add_argument("--repository", required=True)
    create.add_argument("--expected-commit")
    create.add_argument("--archive-name", default="trillionnium-os-source.tar.gz")
    create.add_argument("--manifest-name", default="trillionnium-os-source.json")
    create.set_defaults(handler=_create)

    verify = subparsers.add_parser("verify", help="verify a package before consumption")
    verify.add_argument("--manifest", required=True, type=Path)
    verify.add_argument("--archive", type=Path)
    verify.add_argument("--expected-repository")
    verify.add_argument("--expected-commit")
    verify.add_argument("--expected-tree")
    verify.set_defaults(handler=_verify)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.handler(args))
    except PackageError as error:
        print(f"android-ci-source-package: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
