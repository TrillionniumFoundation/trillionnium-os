#!/usr/bin/env python3
"""Resolve a statically pinned repo manifest without walking worktrees.

``repo manifest -r`` asks repo/Git to inspect every project and can become
unbounded on a sick external disk.  This resolver is deliberately narrower:
it accepts only a regular checked-out manifest with no dynamic composition
elements, reads each worktree's Git ``HEAD`` metadata directly, and publishes
the original manifest bytes only when every checked-out HEAD equals the
manifest's exact SHA revision.  The accompanying receipt is provenance
evidence, never release authority.

The resolver never cleans or mutates a checkout, contacts a remote, invokes
Git, or writes a device.  A mismatch, unsafe path, unstable file, missing
project, or I/O error fails closed and no resolved-manifest bytes are
published.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import xml.etree.ElementTree as ET


SCHEMA = "org.trillionnium.local-repo-manifest-resolution-receipt.v1"
PASS = "PASS_LOCAL_PINNED_MANIFEST_HEADS"
HOLD = "HOLD_LOCAL_PINNED_MANIFEST_HEADS"
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_RECEIPT_BYTES = 256 * 1024 * 1024
SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
REF_RE = re.compile(r"^refs/(?:heads|remotes)/[A-Za-z0-9._/-]+$")
PATH_COMPONENT_RE = re.compile(r"[A-Za-z0-9._+-]+")
FORBIDDEN_TAGS = {"include", "submanifest", "remove-project", "extend-project", "repo-hooks"}


class ResolverError(RuntimeError):
    """A malformed or unstable local source measurement."""


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, allow_nan=False, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def identity(item: os.stat_result) -> tuple[int, int, int, int, int, int, int, int, int]:
    return (
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
        item.st_mode,
        item.st_uid,
        item.st_gid,
        item.st_nlink,
    )


def reject_symlink_parents(path: Path) -> None:
    absolute = Path(os.path.abspath(os.fspath(path)))
    current = Path(absolute.anchor or os.sep)
    for component in absolute.parts[1:]:
        current /= component
        try:
            mode = os.lstat(current).st_mode
        except OSError as error:
            raise ResolverError(f"unavailable path component: {current}") from error
        if stat.S_ISLNK(mode):
            raise ResolverError(f"symlinked path component: {current}")


def read_regular(path: Path, label: str, maximum: int) -> bytes:
    absolute = Path(os.path.abspath(os.fspath(path)))
    reject_symlink_parents(absolute)
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(absolute, flags)
    except OSError as error:
        raise ResolverError(f"{label} unavailable") from error
    before: os.stat_result
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 1 <= before.st_size <= maximum:
            raise ResolverError(f"{label} boundary invalid")
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            block = os.read(fd, min(1024 * 1024, maximum + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
        after = os.fstat(fd)
        if total != before.st_size or identity(before) != identity(after):
            raise ResolverError(f"{label} changed while read")
    finally:
        os.close(fd)
    try:
        current = os.lstat(absolute)
    except OSError as error:
        raise ResolverError(f"{label} disappeared after read") from error
    if stat.S_ISLNK(current.st_mode) or identity(current) != identity(before):
        raise ResolverError(f"{label} pathname changed while read")
    return b"".join(chunks)


def canonical_relative(value: str, label: str) -> str:
    if not value or value.startswith("/") or value.endswith("/") or "\\" in value:
        raise ResolverError(f"{label} is not a relative path")
    parts = value.split("/")
    if any(
        part in {".", ".."} or not PATH_COMPONENT_RE.fullmatch(part)
        for part in parts
    ):
        raise ResolverError(f"{label} is not canonical")
    return value


def parse_manifest(raw: bytes) -> list[dict[str, str]]:
    if not raw or b"\x00" in raw or re.search(br"<!\s*(?:DOCTYPE|ENTITY)\b", raw, re.I):
        raise ResolverError("manifest contains forbidden declaration")
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, RecursionError) as error:
        raise ResolverError("manifest XML is invalid") from error
    if root.tag != "manifest":
        raise ResolverError("manifest root is not <manifest>")
    if any(element.tag in FORBIDDEN_TAGS for element in root.iter()):
        raise ResolverError("manifest uses dynamic composition")
    projects = root.findall("project")
    if len(projects) != sum(1 for element in root.iter() if element.tag == "project"):
        raise ResolverError("manifest contains nested project")
    seen: set[str] = set()
    result: list[dict[str, str]] = []
    for project in projects:
        name = project.get("name", "")
        path = project.get("path", name)
        revision = project.get("revision", "")
        canonical_relative(path, "project path")
        canonical_relative(name, "project name")
        if path in seen:
            raise ResolverError(f"duplicate project path: {path}")
        if not SHA_RE.fullmatch(revision):
            raise ResolverError(f"project revision is not an exact SHA: {path}")
        seen.add(path)
        result.append({"name": name, "path": path, "revision": revision})
    if not result:
        raise ResolverError("manifest project set is empty")
    return result


def resolve_gitdir(worktree: Path, root: Path) -> Path:
    dotgit = worktree / ".git"
    # repo uses a final ``.git`` symlink into ``.repo/projects``.  Reject
    # symlinked parents, but inspect and constrain that final link explicitly
    # instead of treating the normal repo layout as an unsafe escape.
    reject_symlink_parents(dotgit.parent)
    try:
        mode = os.lstat(dotgit).st_mode
    except OSError as error:
        raise ResolverError(f"missing .git for {worktree}") from error
    if stat.S_ISDIR(mode):
        gitdir = dotgit
    elif stat.S_ISLNK(mode):
        target = os.readlink(dotgit)
        candidate = Path(target)
        gitdir = candidate if candidate.is_absolute() else dotgit.parent / candidate
    elif stat.S_ISREG(mode):
        raw = read_regular(dotgit, f"{worktree}/.git pointer", 16 * 1024)
        try:
            text = raw.decode("utf-8")
        except UnicodeError as error:
            raise ResolverError(f"invalid .git pointer: {worktree}") from error
        if not text.startswith("gitdir:"):
            raise ResolverError(f"invalid .git pointer: {worktree}")
        target = text.split(":", 1)[1].strip()
        if not target or "\x00" in target:
            raise ResolverError(f"invalid .git pointer target: {worktree}")
        candidate = Path(target)
        gitdir = candidate if candidate.is_absolute() else dotgit.parent / candidate
    else:
        raise ResolverError(f".git is not a directory or pointer: {worktree}")
    gitdir = Path(os.path.abspath(os.fspath(gitdir)))
    reject_symlink_parents(gitdir.parent)
    try:
        target_mode = os.lstat(gitdir).st_mode
    except OSError as error:
        raise ResolverError(f"resolved .git target is unavailable: {worktree}") from error
    if not stat.S_ISDIR(target_mode) or stat.S_ISLNK(target_mode):
        raise ResolverError(f"resolved .git target is not a directory: {worktree}")
    try:
        gitdir.relative_to(root / ".repo")
    except ValueError:
        # A normal standalone project may keep .git in its worktree.  Repo
        # projects are expected under .repo; permit the former only when the
        # resolved path is exactly the worktree .git directory.
        if gitdir != Path(os.path.abspath(os.fspath(dotgit))):
            raise ResolverError(f".git escapes checkout metadata root: {worktree}")
    return gitdir


def packed_ref(gitdir: Path, ref: str) -> str | None:
    packed = gitdir / "packed-refs"
    try:
        raw = read_regular(packed, f"packed refs for {gitdir}", 64 * 1024 * 1024)
    except ResolverError:
        return None
    try:
        text = raw.decode("ascii")
    except UnicodeError as error:
        raise ResolverError(f"packed refs are not ASCII: {gitdir}") from error
    for line in text.splitlines():
        if not line or line.startswith("#") or line.startswith("^"):
            continue
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[1] == ref and SHA_RE.fullmatch(parts[0]):
            return parts[0]
    return None


def resolve_head(gitdir: Path) -> tuple[str, str]:
    raw = read_regular(gitdir / "HEAD", f"HEAD for {gitdir}", 1024).strip()
    try:
        text = raw.decode("ascii")
    except UnicodeError as error:
        raise ResolverError(f"HEAD is not ASCII: {gitdir}") from error
    if SHA_RE.fullmatch(text):
        return text, "detached"
    if not text.startswith("ref: "):
        raise ResolverError(f"HEAD is neither SHA nor symbolic ref: {gitdir}")
    ref = text[5:]
    if not REF_RE.fullmatch(ref) or any(
        part in {".", ".."} for part in ref.split("/")
    ):
        raise ResolverError(f"unsafe HEAD ref: {gitdir}")
    ref_path = gitdir / ref
    try:
        value = read_regular(ref_path, f"HEAD ref {ref} for {gitdir}", 1024).strip().decode("ascii")
    except ResolverError:
        value = packed_ref(gitdir, ref) or ""
    if not SHA_RE.fullmatch(value):
        raise ResolverError(f"HEAD ref does not resolve to exact SHA: {gitdir} {ref}")
    return value, "symbolic"


def publish(path: Path, raw: bytes, label: str) -> None:
    absolute = Path(os.path.abspath(os.fspath(path)))
    reject_symlink_parents(absolute.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(absolute, flags, 0o444)
    except OSError as error:
        raise ResolverError(f"{label} publication failed") from error
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise ResolverError(f"{label} short write")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        parent_fd = os.open(absolute.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except OSError as error:
        raise ResolverError(f"{label} parent durability failed") from error


def resolve(android_root: Path, manifest_path: Path) -> tuple[bytes, dict[str, object]]:
    root = Path(os.path.abspath(os.fspath(android_root)))
    if not root.is_dir() or root.is_symlink():
        raise ResolverError("Android checkout root is unavailable")
    manifest = Path(os.path.abspath(os.fspath(manifest_path)))
    try:
        manifest.relative_to(root / ".repo")
    except ValueError as error:
        raise ResolverError("manifest must reside below checkout .repo") from error
    raw = read_regular(manifest, "manifest", MAX_MANIFEST_BYTES)
    projects = parse_manifest(raw)
    observations: list[dict[str, str]] = []
    for project in projects:
        worktree = root / project["path"]
        if not worktree.is_dir() or worktree.is_symlink():
            raise ResolverError(f"project worktree unavailable: {project['path']}")
        gitdir = resolve_gitdir(worktree, root)
        resolved, kind = resolve_head(gitdir)
        if resolved != project["revision"]:
            raise ResolverError(
                f"checked-out HEAD differs from manifest revision: {project['path']}"
            )
        observations.append(
            {
                "path": project["path"],
                "name": project["name"],
                "declared_revision": project["revision"],
                "resolved_revision": resolved,
                "head_kind": kind,
            }
        )
    # Re-read the manifest after all metadata reads so a concurrent manifest
    # replacement cannot be promoted as a resolved snapshot.
    reread = read_regular(manifest, "manifest", MAX_MANIFEST_BYTES)
    if reread != raw:
        raise ResolverError("manifest changed during resolution")
    receipt: dict[str, object] = {
        "schema": SCHEMA,
        "decision": PASS,
        "authority": "local_source_provenance_not_release_authority",
        "release_allowed": False,
        "producer": "local_repo_manifest_direct_pinned",
        "resolution_mode": "static_manifest_all_project_heads_exact",
        "android_root": str(root),
        "manifest_path": str(manifest),
        "manifest_bytes": len(raw),
        "manifest_sha256": sha256(raw),
        "project_count": len(observations),
        "projects": observations,
    }
    receipt["receipt_id"] = "sha256:" + sha256(canonical_json(receipt))
    return raw, receipt


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--android-root", type=Path, required=True)
    result.add_argument("--manifest", type=Path)
    result.add_argument("--resolved-manifest", type=Path, required=True)
    result.add_argument("--receipt", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    root = Path(os.path.abspath(os.fspath(args.android_root)))
    manifest = args.manifest or root / ".repo/manifests/trillionnium-fogos.xml"
    try:
        raw, receipt = resolve(root, manifest)
        for output, content, label in (
            (args.resolved_manifest, raw, "resolved manifest"),
            (args.receipt, canonical_json(receipt), "resolution receipt"),
        ):
            absolute = Path(os.path.abspath(os.fspath(output)))
            try:
                absolute.relative_to(root)
            except ValueError:
                pass
            else:
                raise ResolverError(f"{label} output must be outside checkout")
            publish(absolute, content, label)
        print(json.dumps(receipt, sort_keys=True))
        return 0
    except ResolverError as error:
        print(f"low-I/O manifest resolver HOLD: {error}", file=sys.stderr)
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
