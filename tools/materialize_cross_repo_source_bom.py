#!/usr/bin/env python3
"""Materialize a deterministic, non-authorizing local cross-repository BOM.

The BOM binds one resolved ``repo manifest -r`` plus the exact Git and
non-ignored dirty state of a reviewed critical project set.  The v2 contract
also binds reviewed non-Git source trees by canonical path, type, mode, file
bytes, and confined link address.  It records required non-product conformance
artifacts from a distinct, out-of-tree build root as *observed bytes*, never as
release pins.  Missing manifest membership, revision drift, dirty or ignored
source, an unsafe or unstable tree, a missing artifact, an invalid ELF closure,
or ambiguous compile-time variant evidence produces a HOLD receipt.

This host-only tool does not clean a checkout, create or rewrite a manifest,
copy an artifact into Android, sign a BOM, authorize a build, publish a pin,
write a device, or perform network access.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time
from typing import Iterable, Mapping, Sequence
import unicodedata
import xml.etree.ElementTree as ET


CONTRACT_SCHEMA_V1 = "org.trillionnium.p0-cross-repo-source-set.v1"
CONTRACT_SCHEMA_V2 = "org.trillionnium.p0-cross-repo-source-set.v2"
CONTRACT_SCHEMA = CONTRACT_SCHEMA_V2
RECEIPT_SCHEMA_V1 = "org.trillionnium.local-cross-repo-source-bom.v1"
RECEIPT_SCHEMA_V2 = "org.trillionnium.local-cross-repo-source-bom.v2"
RECEIPT_SCHEMA = RECEIPT_SCHEMA_V2
TREE_INVENTORY_SCHEMA = "org.trillionnium.stable-source-tree-inventory.v1"
PASS = "PASS_LOCAL_EXACT_CLEAN_GRAPH"
HOLD = "HOLD_LOCAL_SOURCE_GRAPH"
RECEIPT_ID_SCOPE = "sha256(canonical-json-utf8-without-receipt_id)"
TREE_DIGEST_SCOPE = "sha256(canonical-json-utf8-of-schema-and-entries-with-lf)"
MANIFEST_RESOLUTION_RECEIPT_SCHEMA = (
    "org.trillionnium.local-repo-manifest-resolution-receipt.v1"
)
MANIFEST_RESOLUTION_PASS = "PASS_LOCAL_PINNED_MANIFEST_HEADS"
MANIFEST_RESOLUTION_PRODUCERS = {
    "local_repo_manifest_r",
    "local_repo_manifest_direct_pinned",
}
DEFAULT_CONTRACT = Path(__file__).with_name("p0-cross-repo-source-set.v2.json")
GIT = Path("/usr/bin/git")
MAX_CONTRACT_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_GIT_OUTPUT_BYTES = 512 * 1024 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_PROMPT_SOURCE_BYTES = 1024 * 1024
MAX_TREE_ENTRIES = 250_000
MAX_TREE_BYTES = 16 * 1024 * 1024 * 1024
MAX_TREE_PATH_BYTES = 4096
MAX_TREE_LINK_BYTES = 4096
TREE_MODE_POLICY = "owner-readable-no-special-or-group-other-write-v1"
REQUIRED_V2_TREES = {
    "vendor_motorola_fogos_blobs": "vendor/motorola/fogos",
    "vendor_motorola_sm6375_common_blobs": "vendor/motorola/sm6375-common",
}
SHA_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
IDENTIFIER_RE = re.compile(r"[a-z][a-z0-9_-]{0,127}")
PORTABLE_COMPONENT_RE = re.compile(r"[A-Za-z0-9._+-]+")
PROMPT_TUPLE_BLOCKER = "cross_repo_prompt_contract_tuple_invalid"
CANONICAL_PROMPT_CONTRACT = (
    "trillionnium.codex-p0-system-api-shell-exec-prompt.v3"
)
CANONICAL_PROMPT_CONTRACT_VERSION = 3
PROMPT_ROLE_SPECS = {
    "control_plane": {
        "checkout_root": "control",
        "checkout_path": ".",
        "source_path": (
            "trillionnium-os/crates/trillionnium-tool-runtime/src/"
            "supervised_codex.rs"
        ),
        "language": "rust",
        "contract_symbol": "DIRECT_EXECUTION_PROMPT_CONTRACT",
        "version_symbol": "DIRECT_EXECUTION_PROMPT_CONTRACT_VERSION",
    },
    "ai_shell": {
        "checkout_root": "android",
        "checkout_path": "packages/apps/TrillionniumAiShell",
        "source_path": "src/org/trillionnium/aishell/AiShellActivity.java",
        "language": "java",
        "contract_symbol": "CODEX_PROMPT_CONTRACT",
        "version_symbol": "PROMPT_CONTRACT_VERSION",
    },
    "ai_authority": {
        "checkout_root": "android",
        "checkout_path": "packages/apps/TrillionniumAiAuthority",
        "source_path": (
            "src/org/trillionnium/aiauthority/EgressConsentActivity.java"
        ),
        "language": "java",
        "contract_symbol": "CODEX_PROMPT_CONTRACT",
        "version_symbol": "PROMPT_CONTRACT_VERSION",
    },
}


class BomError(RuntimeError):
    """A malformed contract, unstable input, or local measurement error."""


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


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


def exact_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict:
        raise BomError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        raise BomError(
            f"{label} keys differ: missing={sorted(expected - actual)} "
            f"unknown={sorted(actual - expected)}"
        )
    return value


def portable_path(value: object, label: str, *, dot_allowed: bool = False) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > 1024:
        raise BomError(f"{label} must be a bounded portable path")
    if dot_allowed and value == ".":
        return value
    if value.startswith("/") or value.endswith("/") or "\\" in value:
        raise BomError(f"{label} must be relative and canonical")
    if not all(
        part not in {"", ".", ".."} and PORTABLE_COMPONENT_RE.fullmatch(part)
        for part in value.split("/")
    ):
        raise BomError(f"{label} must be relative and canonical")
    return value


def git_relative_path(value: str, label: str) -> str:
    if (
        not value
        or len(value.encode("utf-8")) > 4096
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or any(ord(character) < 32 for character in value)
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise BomError(f"{label} must be a canonical UTF-8 relative path")
    return value


def path_is_prefix(parent: str, child: str) -> bool:
    """Return whether one canonical relative path contains another."""

    return parent == "." or child == parent or child.startswith(parent + "/")


def _path_components_are_not_symlinks(path: Path) -> None:
    """Reject symlinked parents before opening a measured source file."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    current = Path(absolute.anchor or os.sep)
    for component in absolute.parts[1:]:
        current /= component
        try:
            mode = os.lstat(current).st_mode
        except OSError as error:
            raise BomError(f"source path component is unavailable: {current}") from error
        if stat.S_ISLNK(mode):
            raise BomError(f"source path component is a symlink: {current}")


def strict_regular_bytes(
    path: Path,
    label: str,
    maximum: int,
    *,
    allow_hardlinks: bool = False,
) -> bytes:
    absolute = Path(os.path.abspath(os.fspath(path)))
    _path_components_are_not_symlinks(absolute)
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise BomError(f"{label} is unavailable") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink < 1
            or (before.st_nlink != 1 and not allow_hardlinks)
            or not 1 <= before.st_size <= maximum
        ):
            raise BomError(f"{label} boundary is invalid")
        chunks: list[bytes] = []
        observed = 0
        while observed <= maximum:
            block = os.read(descriptor, min(1024 * 1024, maximum + 1 - observed))
            if not block:
                break
            chunks.append(block)
            observed += len(block)
        after = os.fstat(descriptor)
        identity = lambda item: (
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
        if observed != before.st_size or identity(before) != identity(after):
            raise BomError(f"{label} changed while measured")
    finally:
        os.close(descriptor)
    current = os.lstat(absolute)
    if stat.S_ISLNK(current.st_mode) or identity(current) != identity(before):
        raise BomError(f"{label} pathname changed while measured")
    return b"".join(chunks)


def strict_json(path: Path, label: str, maximum: int) -> tuple[dict[str, object], bytes]:
    raw = strict_regular_bytes(path, label, maximum)
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                BomError(f"{label} contains non-finite JSON number {value}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise BomError(f"{label} is not strict UTF-8 JSON") from error
    if type(value) is not dict:
        raise BomError(f"{label} must be a JSON object")
    return value, raw


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BomError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def validate_contract(value: dict[str, object]) -> dict[str, object]:
    if type(value) is not dict:
        raise BomError("contract must be an object")
    schema = value.get("schema")
    if schema == CONTRACT_SCHEMA_V1:
        raw = exact_keys(value, {"schema", "projects", "artifacts"}, "contract")
        trees_raw: object = []
    elif schema == CONTRACT_SCHEMA_V2:
        raw = exact_keys(
            value, {"schema", "projects", "trees", "artifacts"}, "contract"
        )
        trees_raw = raw["trees"]
    else:
        raise BomError("unsupported cross-repository source-set schema")
    projects_raw = raw["projects"]
    artifacts_raw = raw["artifacts"]
    if type(projects_raw) is not list or not projects_raw:
        raise BomError("contract.projects must be a non-empty array")
    if type(artifacts_raw) is not list:
        raise BomError("contract.artifacts must be an array")
    if type(trees_raw) is not list:
        raise BomError("contract.trees must be an array")

    projects: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    seen_checkouts: set[tuple[str, str]] = set()
    seen_manifest_paths: set[str] = set()
    for index, candidate in enumerate(projects_raw):
        label = f"contract.projects[{index}]"
        item = exact_keys(
            candidate,
            {
                "id",
                "checkout_root",
                "checkout_path",
                "manifest_required",
                "manifest_path",
                "expected_manifest_name",
                "require_clean",
                "require_no_ignored",
            },
            label,
        )
        project_id = item["id"]
        checkout_root = item["checkout_root"]
        if type(project_id) is not str or IDENTIFIER_RE.fullmatch(project_id) is None:
            raise BomError(f"{label}.id is invalid")
        if checkout_root not in {"android", "control"}:
            raise BomError(f"{label}.checkout_root is invalid")
        checkout_path = portable_path(
            item["checkout_path"], f"{label}.checkout_path", dot_allowed=True
        )
        for flag in ("manifest_required", "require_clean", "require_no_ignored"):
            if type(item[flag]) is not bool:
                raise BomError(f"{label}.{flag} must be a boolean")
        manifest_path = item["manifest_path"]
        expected_name = item["expected_manifest_name"]
        if item["manifest_required"]:
            manifest_path = portable_path(manifest_path, f"{label}.manifest_path")
            expected_name = portable_path(
                expected_name, f"{label}.expected_manifest_name"
            )
        elif manifest_path is not None or expected_name is not None:
            raise BomError(
                f"{label} non-manifest project must use null manifest identity"
            )
        key = (str(checkout_root), checkout_path)
        if project_id in seen_ids or key in seen_checkouts:
            raise BomError("contract contains duplicate project identity")
        if isinstance(manifest_path, str) and manifest_path in seen_manifest_paths:
            raise BomError("contract contains duplicate required manifest path")
        seen_ids.add(project_id)
        seen_checkouts.add(key)
        if isinstance(manifest_path, str):
            seen_manifest_paths.add(manifest_path)
        projects.append(
            {
                "id": project_id,
                "checkout_root": checkout_root,
                "checkout_path": checkout_path,
                "manifest_required": item["manifest_required"],
                "manifest_path": manifest_path,
                "expected_manifest_name": expected_name,
                "require_clean": item["require_clean"],
                "require_no_ignored": item["require_no_ignored"],
            }
        )

    trees: list[dict[str, object]] = []
    seen_tree_ids: set[str] = set()
    seen_tree_paths: list[tuple[str, str]] = []
    for index, candidate in enumerate(trees_raw):
        label = f"contract.trees[{index}]"
        item = exact_keys(
            candidate,
            {
                "id",
                "checkout_root",
                "path",
                "required",
                "entry_limit",
                "byte_limit",
                "mode_policy",
            },
            label,
        )
        tree_id = item["id"]
        if type(tree_id) is not str or IDENTIFIER_RE.fullmatch(tree_id) is None:
            raise BomError(f"{label}.id is invalid")
        if tree_id in seen_ids or tree_id in seen_tree_ids:
            raise BomError("contract contains duplicate source identity")
        if item["checkout_root"] != "android":
            raise BomError(f"{label}.checkout_root must be android")
        path = portable_path(item["path"], f"{label}.path")
        if item["required"] is not True:
            raise BomError(f"{label}.required must be true")
        entry_limit = item["entry_limit"]
        byte_limit = item["byte_limit"]
        if type(entry_limit) is not int or not 1 <= entry_limit <= MAX_TREE_ENTRIES:
            raise BomError(f"{label}.entry_limit is invalid")
        if type(byte_limit) is not int or not 1 <= byte_limit <= MAX_TREE_BYTES:
            raise BomError(f"{label}.byte_limit is invalid")
        if item["mode_policy"] != TREE_MODE_POLICY:
            raise BomError(f"{label}.mode_policy is unsupported")
        for other_root, other_path in seen_tree_paths:
            if other_root == "android" and (
                path_is_prefix(path, other_path) or path_is_prefix(other_path, path)
            ):
                raise BomError("contract contains duplicate or nested tree roots")
        for project in projects:
            if project["checkout_root"] == "android" and (
                path_is_prefix(path, str(project["checkout_path"]))
                or path_is_prefix(str(project["checkout_path"]), path)
            ):
                raise BomError("contract contains an ambiguous project/tree prefix")
        seen_tree_ids.add(tree_id)
        seen_tree_paths.append(("android", path))
        trees.append(
            {
                "id": tree_id,
                "checkout_root": "android",
                "path": path,
                "required": True,
                "entry_limit": entry_limit,
                "byte_limit": byte_limit,
                "mode_policy": TREE_MODE_POLICY,
            }
        )
    if schema == CONTRACT_SCHEMA_V2 and {
        str(item["id"]): str(item["path"]) for item in trees
    } != REQUIRED_V2_TREES:
        raise BomError("v2 contract must bind the exact Motorola vendor blob trees")

    artifacts: list[dict[str, object]] = []
    seen_artifact_ids: set[str] = set()
    for index, candidate in enumerate(artifacts_raw):
        label = f"contract.artifacts[{index}]"
        item = exact_keys(
            candidate,
            {
                "id",
                "checkout_root",
                "path",
                "required",
                "lane",
                "embedded_variant",
                "variant_section",
                "release_pin",
            },
            label,
        )
        artifact_id = item["id"]
        if type(artifact_id) is not str or IDENTIFIER_RE.fullmatch(artifact_id) is None:
            raise BomError(f"{label}.id is invalid")
        if artifact_id in seen_artifact_ids:
            raise BomError("contract contains duplicate artifact id")
        if item["checkout_root"] != "artifacts":
            raise BomError(
                f"{label}.checkout_root must select the out-of-tree artifact root"
            )
        if item["required"] is not True or item["release_pin"] is not False:
            raise BomError(
                f"{label} must be required observed evidence, never a release pin"
            )
        path = portable_path(item["path"], f"{label}.path")
        variant_section = item["variant_section"]
        if variant_section != ".trillionnium.p01.variant":
            raise BomError(f"{label}.variant_section is not the frozen section")
        lane = item["lane"]
        variant = item["embedded_variant"]
        if lane != "non_product_userdebug_only" or variant != "userdebug":
            raise BomError(f"{label} may describe only the userdebug-only conformance lane")
        seen_artifact_ids.add(artifact_id)
        artifacts.append(
            {
                "id": artifact_id,
                "checkout_root": item["checkout_root"],
                "path": path,
                "required": True,
                "lane": lane,
                "embedded_variant": variant,
                "variant_section": variant_section,
                "release_pin": False,
            }
        )
    return {
        "schema": schema,
        "projects": projects,
        "trees": trees,
        "artifacts": artifacts,
    }


def bounded_command(
    command: Sequence[str],
    cwd: Path,
    label: str,
    maximum: int,
    timeout: int = 120,
    *,
    allowed_returncodes: Sequence[int] = (0,),
) -> bytes:
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "PATH": "/usr/bin:/bin",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        # repo's launcher defaults tracing on unless this is explicitly
        # disabled.  A source measurement must not append to .repo/TRACE_FILE
        # (or otherwise mutate a checkout) while resolving the manifest.
        "REPO_TRACE": "0",
    }
    if timeout <= 0 or maximum <= 0 or not allowed_returncodes:
        raise BomError(f"{label} bounds are invalid")
    try:
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
        )
    except OSError as error:
        raise BomError(f"{label} failed") from error

    assert process.stdout is not None
    assert process.stderr is not None
    stdout_descriptor = process.stdout.fileno()
    selector = selectors.DefaultSelector()
    streams = (process.stdout, process.stderr)
    buffers: dict[int, bytearray] = {
        stream.fileno(): bytearray() for stream in streams
    }
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)

    def terminate_group() -> None:
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        except OSError:
            try:
                process.kill()
            except OSError:
                pass

    def reap_briefly() -> None:
        if process.poll() is not None:
            return
        try:
            process.wait(timeout=0.2)
        except (subprocess.TimeoutExpired, OSError):
            # A process stuck in uninterruptible storage I/O cannot be
            # reaped synchronously.  The caller still gets a bounded HOLD;
            # never turn cleanup into another unbounded wait.
            pass

    deadline = time.monotonic() + float(timeout)
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                terminate_group()
                raise BomError(f"{label} failed")
            events = selector.select(min(remaining, 0.1))
            if not events and process.poll() is not None:
                events = [
                    (key, selectors.EVENT_READ)
                    for key in selector.get_map().values()
                ]
            for key, _ in events:
                stream = key.fileobj
                descriptor = stream.fileno()
                try:
                    chunk = os.read(descriptor, 1024 * 1024)
                except BlockingIOError:
                    continue
                except OSError as error:
                    terminate_group()
                    raise BomError(f"{label} failed") from error
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                buffers[descriptor].extend(chunk)
                if len(buffers[descriptor]) > maximum:
                    terminate_group()
                    raise BomError(f"{label} exceeds output bound")

        if process.poll() is None:
            # Pipes can reach EOF just before the leader's wait status is
            # observable.  Give the normal case a short bounded reap window;
            # never turn this into the unbounded subprocess.run cleanup that
            # originally made external-disk I/O hangs sticky.
            try:
                process.wait(timeout=0.2)
            except (subprocess.TimeoutExpired, OSError):
                terminate_group()
                raise BomError(f"{label} failed")
        if process.returncode not in allowed_returncodes:
            raise BomError(f"{label} failed")
        return bytes(buffers[stdout_descriptor])
    finally:
        terminate_group()
        reap_briefly()
        selector.close()
        for stream in streams:
            try:
                stream.close()
            except OSError:
                pass


def git(
    checkout: Path,
    arguments: Sequence[str],
    label: str,
    maximum: int = MAX_GIT_OUTPUT_BYTES,
) -> bytes:
    return bounded_command(
        [
            str(GIT),
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "core.quotepath=true",
            "-c",
            "diff.external=",
            *arguments,
        ],
        checkout,
        label,
        maximum,
    )


def git_head_blob_text(checkout: Path, head: str, path: str, label: str) -> str:
    """Read one bounded UTF-8 blob from a previously captured Git HEAD."""

    if SHA_RE.fullmatch(head) is None:
        raise BomError(f"{label} captured HEAD is invalid")
    canonical_path = git_relative_path(path, f"{label} blob path")
    object_name = f"{head}:{canonical_path}"
    size_raw = git(
        checkout,
        ["cat-file", "-s", object_name],
        f"{label} blob size",
        128,
    )
    if re.fullmatch(rb"[0-9]+\n?", size_raw) is None:
        raise BomError(f"{label} blob size is malformed")
    size = int(size_raw)
    if not 1 <= size <= MAX_PROMPT_SOURCE_BYTES:
        raise BomError(f"{label} blob exceeds source bound")
    raw = git(
        checkout,
        ["cat-file", "blob", object_name],
        f"{label} blob",
        MAX_PROMPT_SOURCE_BYTES,
    )
    if len(raw) != size:
        raise BomError(f"{label} blob size changed while read")
    if b"\x00" in raw:
        raise BomError(f"{label} blob contains NUL")
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise BomError(f"{label} blob is not strict UTF-8") from error


def _rust_raw_string_end(source: str, start: int) -> int | None:
    """Return the end of a Rust raw string beginning at ``start``, if any."""

    prefix_length = 0
    if source.startswith("br", start):
        prefix_length = 2
    elif source.startswith("r", start):
        prefix_length = 1
    else:
        return None
    if start and (source[start - 1].isalnum() or source[start - 1] == "_"):
        return None
    cursor = start + prefix_length
    hashes = 0
    while cursor < len(source) and source[cursor] == "#":
        hashes += 1
        cursor += 1
    if cursor >= len(source) or source[cursor] != '"':
        return None
    terminator = '"' + "#" * hashes
    end = source.find(terminator, cursor + 1)
    if end < 0:
        raise BomError("Rust source contains an unterminated raw string")
    return end + len(terminator)


def _char_literal_end(source: str, start: int) -> int | None:
    """Recognize a Java/Rust character literal without confusing Rust lifetimes."""

    cursor = start + 1
    if cursor >= len(source) or source[cursor] in {"\r", "\n", "'"}:
        return None
    if source[cursor] == "\\":
        cursor += 1
        if cursor >= len(source) or source[cursor] in {"\r", "\n"}:
            return None
        if source[cursor] == "u" and cursor + 1 < len(source) and source[cursor + 1] == "{":
            closing = source.find("}", cursor + 2)
            if closing < 0:
                return None
            cursor = closing + 1
        else:
            cursor += 1
    else:
        cursor += 1
    return cursor + 1 if cursor < len(source) and source[cursor] == "'" else None


def comment_filtered_source(source: str, language: str) -> tuple[str, list[bool]]:
    """Mask comments while retaining literals and their source positions."""

    if language not in {"rust", "java"}:
        raise BomError("prompt source language is unsupported")
    filtered = list(source)
    live = [True] * len(source)

    def mask(start: int, end: int, *, erase: bool) -> None:
        for offset in range(start, end):
            live[offset] = False
            if erase and filtered[offset] not in {"\r", "\n"}:
                filtered[offset] = " "

    cursor = 0
    while cursor < len(source):
        if source.startswith("//", cursor):
            end = source.find("\n", cursor + 2)
            if end < 0:
                end = len(source)
            mask(cursor, end, erase=True)
            cursor = end
            continue
        if source.startswith("/*", cursor):
            depth = 1
            end = cursor + 2
            while end < len(source) and depth:
                if language == "rust" and source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                raise BomError("prompt source contains an unterminated block comment")
            mask(cursor, end, erase=True)
            cursor = end
            continue
        if language == "rust":
            raw_end = _rust_raw_string_end(source, cursor)
            if raw_end is not None:
                mask(cursor, raw_end, erase=False)
                cursor = raw_end
                continue
        if source[cursor] == '"':
            if language == "java" and source.startswith('\"\"\"', cursor):
                end = source.find('\"\"\"', cursor + 3)
                if end < 0:
                    raise BomError("Java source contains an unterminated text block")
                end += 3
            else:
                end = cursor + 1
                escaped = False
                while end < len(source):
                    character = source[end]
                    if character in {"\r", "\n"} and not escaped:
                        raise BomError("prompt source contains an unterminated string")
                    if character == '"' and not escaped:
                        end += 1
                        break
                    if character == "\\" and not escaped:
                        escaped = True
                    else:
                        escaped = False
                    end += 1
                else:
                    raise BomError("prompt source contains an unterminated string")
            mask(cursor, end, erase=False)
            cursor = end
            continue
        if source[cursor] == "'":
            char_end = _char_literal_end(source, cursor)
            if char_end is not None:
                mask(cursor, char_end, erase=False)
                cursor = char_end
                continue
        cursor += 1
    return "".join(filtered), live


def parse_prompt_tuple(
    source: str,
    language: str,
    contract_symbol: str,
    version_symbol: str,
) -> tuple[str, int]:
    """Extract exactly one live, literal prompt contract declaration pair."""

    filtered, live = comment_filtered_source(source, language)
    if language == "rust":
        contract_pattern = re.compile(
            r"(?P<declaration>\b(?:pub(?:\s*\([^()\r\n]*\))?\s+)?const\s+"
            + re.escape(contract_symbol)
            + r"\b)\s*:\s*&\s*str\s*=\s*\"(?P<value>[A-Za-z0-9._-]+)\"\s*;",
            re.MULTILINE,
        )
        version_pattern = re.compile(
            r"(?P<declaration>\b(?:pub(?:\s*\([^()\r\n]*\))?\s+)?const\s+"
            + re.escape(version_symbol)
            + r"\b)\s*:\s*u64\s*=\s*(?P<value>[0-9]+)\s*;",
            re.MULTILINE,
        )
    else:
        contract_pattern = re.compile(
            r"(?P<declaration>\b(?:public|protected|private)\s+static\s+final\s+String\s+"
            + re.escape(contract_symbol)
            + r"\b)\s*=\s*\"(?P<value>[A-Za-z0-9._-]+)\"\s*;",
            re.MULTILINE,
        )
        version_pattern = re.compile(
            r"(?P<declaration>\b(?:public|protected|private)\s+static\s+final\s+long\s+"
            + re.escape(version_symbol)
            + r"\b)\s*=\s*(?P<value>[0-9]+)L\s*;",
            re.MULTILINE,
        )

    def live_matches(pattern: re.Pattern[str]) -> list[re.Match[str]]:
        return [
            match
            for match in pattern.finditer(filtered)
            if live[match.start("declaration")]
        ]

    contracts = live_matches(contract_pattern)
    versions = live_matches(version_pattern)
    if len(contracts) != 1 or len(versions) != 1:
        raise BomError("prompt source declarations are missing or ambiguous")
    return contracts[0].group("value"), int(versions[0].group("value"))


def prompt_tuple_gate(
    contract: Mapping[str, object],
    projects: Sequence[Mapping[str, object]],
    roots: Mapping[str, Path],
) -> bool:
    """Validate the three prompt tuples from immutable, captured HEAD blobs."""

    project_contracts = {
        str(item["id"]): item
        for item in contract["projects"]  # type: ignore[index]
        if isinstance(item, Mapping)
    }
    observations = {
        str(item["id"]): item for item in projects if isinstance(item, Mapping)
    }
    tuples: list[tuple[str, int]] = []
    for role, spec in PROMPT_ROLE_SPECS.items():
        item = project_contracts.get(role)
        observed = observations.get(role)
        if item is None or observed is None:
            raise BomError(f"prompt role {role} is unavailable")
        checkout_root = str(spec["checkout_root"])
        checkout_path = str(spec["checkout_path"])
        if (
            item.get("checkout_root") != checkout_root
            or item.get("checkout_path") != checkout_path
        ):
            raise BomError(f"prompt role {role} checkout differs")
        git_state = observed.get("git")
        if not isinstance(git_state, Mapping) or type(git_state.get("head")) is not str:
            raise BomError(f"prompt role {role} captured HEAD is unavailable")
        checkout = roots[checkout_root] / checkout_path
        source = git_head_blob_text(
            checkout,
            str(git_state["head"]),
            str(spec["source_path"]),
            f"prompt role {role}",
        )
        tuples.append(
            parse_prompt_tuple(
                source,
                str(spec["language"]),
                str(spec["contract_symbol"]),
                str(spec["version_symbol"]),
            )
        )
    if len(set(tuples)) != 1:
        return False
    contract_name, contract_version = tuples[0]
    suffix = re.search(r"\.v([0-9]+)\Z", contract_name)
    return bool(
        suffix
        and int(suffix.group(1)) == contract_version
        and contract_name == CANONICAL_PROMPT_CONTRACT
        and contract_version == CANONICAL_PROMPT_CONTRACT_VERSION
    )


def validate_manifest_resolution_receipt(
    receipt_path: Path,
    manifest_raw: bytes,
    android_root: Path,
) -> dict[str, object]:
    """Validate a resolver receipt before accepting supplied manifest bytes.

    A regular XML file by itself is not evidence that ``repo manifest -r``
    completed.  The optional receipt closes that host-tool provenance gap for
    the low-I/O pinned-manifest resolver.  It deliberately carries
    ``release_allowed=false`` and a non-authorizing authority label; this is
    source freshness evidence only, never a signing or device-write grant.
    """

    receipt, receipt_raw = strict_json(
        receipt_path,
        "resolved-manifest provenance receipt",
        MAX_MANIFEST_BYTES,
    )
    required = {
        "schema",
        "decision",
        "authority",
        "release_allowed",
        "producer",
        "resolution_mode",
        "android_root",
        "manifest_path",
        "manifest_bytes",
        "manifest_sha256",
        "project_count",
        "projects",
        "receipt_id",
    }
    if set(receipt) != required:
        raise BomError("resolved-manifest provenance receipt keys differ")
    if receipt["schema"] != MANIFEST_RESOLUTION_RECEIPT_SCHEMA:
        raise BomError("resolved-manifest provenance receipt schema is invalid")
    if receipt["decision"] != MANIFEST_RESOLUTION_PASS:
        raise BomError("resolved-manifest provenance receipt is not a pass")
    if receipt["authority"] != "local_source_provenance_not_release_authority":
        raise BomError("resolved-manifest provenance authority is invalid")
    if receipt["release_allowed"] is not False:
        raise BomError("resolved-manifest provenance cannot authorize release")
    producer = receipt["producer"]
    if producer not in MANIFEST_RESOLUTION_PRODUCERS:
        raise BomError("resolved-manifest provenance producer is invalid")
    if receipt["resolution_mode"] not in {
        "static_manifest_all_project_heads_exact",
        "repo_manifest_r_output",
    }:
        raise BomError("resolved-manifest provenance resolution mode is invalid")
    if type(receipt["manifest_bytes"]) is not int or receipt["manifest_bytes"] != len(manifest_raw):
        raise BomError("resolved-manifest provenance byte count differs")
    manifest_digest = receipt["manifest_sha256"]
    if type(manifest_digest) is not str or re.fullmatch(r"[0-9a-f]{64}", manifest_digest) is None:
        raise BomError("resolved-manifest provenance digest is invalid")
    if manifest_digest != sha256_bytes(manifest_raw):
        raise BomError("resolved-manifest provenance digest differs")
    root = Path(os.path.abspath(os.fspath(android_root)))
    receipt_root = receipt["android_root"]
    if type(receipt_root) is not str or Path(os.path.abspath(receipt_root)) != root:
        raise BomError("resolved-manifest provenance checkout differs")
    manifest_path = receipt["manifest_path"]
    if type(manifest_path) is not str:
        raise BomError("resolved-manifest provenance path is invalid")
    try:
        Path(os.path.abspath(manifest_path)).relative_to(root / ".repo")
    except ValueError as error:
        raise BomError("resolved-manifest provenance path escapes .repo") from error
    if type(receipt["project_count"]) is not int or receipt["project_count"] <= 0:
        raise BomError("resolved-manifest provenance project count is invalid")
    projects = receipt["projects"]
    if type(projects) is not list or len(projects) != receipt["project_count"]:
        raise BomError("resolved-manifest provenance project observations are invalid")
    # Bind the receipt's per-project observations to the exact manifest bytes,
    # rather than trusting only the top-level digest/count.  This prevents a
    # stale or hand-edited observation list from being presented as the result
    # of the resolver.
    manifest_projects, _revisions_exact, _drifts = parse_manifest(manifest_raw)
    if len(manifest_projects) != len(projects):
        raise BomError("resolved-manifest provenance project count differs")
    observed_by_path: dict[str, dict[str, object]] = {}
    for observation in projects:
        if type(observation) is not dict or set(observation) != {
            "path",
            "name",
            "declared_revision",
            "resolved_revision",
            "head_kind",
        }:
            raise BomError("resolved-manifest provenance project observation is invalid")
        path = observation["path"]
        if type(path) is not str or path in observed_by_path:
            raise BomError("resolved-manifest provenance project path is invalid")
        if observation["head_kind"] not in {"detached", "symbolic"}:
            raise BomError("resolved-manifest provenance HEAD kind is invalid")
        observed_by_path[path] = observation
    for path, manifest_entry in manifest_projects.items():
        observation = observed_by_path.get(path)
        if observation is None:
            raise BomError("resolved-manifest provenance project is missing")
        if (
            observation["name"] != manifest_entry["name"]
            or observation["declared_revision"] != manifest_entry["revision"]
            or observation["resolved_revision"] != manifest_entry["revision"]
        ):
            raise BomError("resolved-manifest provenance project differs")
    # Verify the receipt identity after all semantic fields.  Reusing the
    # materializer's canonical JSON scope keeps this check byte deterministic.
    receipt_id = receipt["receipt_id"]
    if type(receipt_id) is not str or not receipt_id.startswith("sha256:"):
        raise BomError("resolved-manifest provenance receipt id is invalid")
    unsigned = dict(receipt)
    del unsigned["receipt_id"]
    expected_id = "sha256:" + sha256_bytes(canonical_json_bytes(unsigned))
    if receipt_id != expected_id:
        raise BomError("resolved-manifest provenance receipt id differs")
    # Keep the raw bytes in the local variable intentionally: strict_json's
    # duplicate-key and file-stability checks are part of the receipt proof.
    _ = receipt_raw
    return receipt


def acquire_manifest(
    android_root: Path,
    supplied: Path | None,
    provenance_receipt: Path | None = None,
    require_provenance: bool = False,
) -> tuple[bytes, str]:
    if supplied is not None:
        raw = strict_regular_bytes(supplied, "resolved manifest", MAX_MANIFEST_BYTES)
        if provenance_receipt is None:
            if require_provenance:
                raise BomError(
                    "resolved manifest provenance receipt is required for this lane"
                )
            return raw, "supplied_regular_file"
        receipt = validate_manifest_resolution_receipt(
            provenance_receipt, raw, android_root
        )
        return raw, str(receipt["producer"])
    if provenance_receipt is not None:
        raise BomError(
            "resolved-manifest provenance receipt requires --resolved-manifest"
        )
    if require_provenance:
        # The local repo invocation below is itself the provenance producer;
        # do not require a sidecar for the direct repo path.
        pass
    repo = android_root / ".repo/repo/repo"
    raw = strict_regular_bytes(repo, "local repo launcher", 4 * 1024 * 1024)
    if not raw.startswith(b"#!/usr/bin/env python") and not raw.startswith(b"#!/usr/bin/python"):
        raise BomError("local repo launcher identity is invalid")
    return (
        bounded_command(
            [sys.executable, str(repo), "manifest", "-r", "-o", "-"],
            android_root,
            "repo manifest -r",
            MAX_MANIFEST_BYTES,
            timeout=300,
        ),
        "local_repo_manifest_r",
    )


def parse_manifest(
    raw: bytes,
) -> tuple[dict[str, dict[str, object]], bool, list[dict[str, str]]]:
    if not raw or b"\x00" in raw or re.search(
        br"<!\s*(?:DOCTYPE|ENTITY)\b", raw, flags=re.IGNORECASE
    ):
        raise BomError("resolved manifest contains a forbidden declaration")
    try:
        document = ET.fromstring(raw)
    except (ET.ParseError, RecursionError) as error:
        raise BomError("resolved manifest is invalid XML") from error
    if document.tag != "manifest":
        raise BomError("resolved manifest root is invalid")
    remotes = {
        str(item.get("name")): str(item.get("fetch"))
        for item in document.findall("remote")
        if item.get("name") and item.get("fetch")
    }
    defaults = document.findall("default")
    if len(defaults) > 1:
        raise BomError("resolved manifest contains multiple defaults")
    default_remote = defaults[0].get("remote", "") if defaults else ""
    projects: dict[str, dict[str, object]] = {}
    revisions_exact = True
    revision_drifts: list[dict[str, str]] = []
    direct = document.findall("project")
    if len(direct) != sum(1 for item in document.iter() if item.tag == "project"):
        raise BomError("resolved manifest contains nested project elements")
    for item in direct:
        name = item.get("name", "")
        path = item.get("path", name)
        revision = item.get("revision", "")
        upstream = item.get("upstream", "")
        destination_branch = item.get("dest-branch", "")
        remote = item.get("remote", default_remote)
        portable_path(path, "manifest project path")
        portable_path(name, "manifest project name")
        if path in projects:
            raise BomError("resolved manifest contains duplicate project path")
        if SHA_RE.fullmatch(revision) is None:
            revisions_exact = False
        declared_revision = upstream if upstream else revision
        if SHA_RE.fullmatch(declared_revision) is None:
            revisions_exact = False
        checkout_differs = revision != declared_revision
        if checkout_differs:
            revision_drifts.append(
                {
                    "path": path,
                    "declared_revision": declared_revision,
                    "checkout_revision": revision,
                }
            )
        projects[path] = {
            "path": path,
            "name": name,
            "revision": revision,
            "declared_revision": declared_revision,
            "declared_revision_source": "upstream" if upstream else "revision",
            "checkout_differs_from_declared_revision": checkout_differs,
            "upstream": upstream or None,
            "destination_branch": destination_branch or None,
            "remote": remote,
            "fetch": remotes.get(remote, ""),
        }
    if not projects:
        raise BomError("resolved manifest project set is empty")
    return projects, revisions_exact, revision_drifts


def decode_nul_paths(raw: bytes, label: str) -> list[str]:
    if raw and not raw.endswith(b"\x00"):
        raise BomError(f"{label} is not NUL terminated")
    result: list[str] = []
    for item in raw.split(b"\x00")[:-1]:
        try:
            path = item.decode("utf-8")
        except UnicodeError as error:
            raise BomError(f"{label} contains a non-UTF-8 path") from error
        git_relative_path(path.rstrip("/"), label)
        result.append(path)
    return result


def status_entries(raw: bytes) -> list[dict[str, object]]:
    if raw and not raw.endswith(b"\x00"):
        raise BomError("Git status is not NUL terminated")
    records = raw.split(b"\x00")[:-1]
    result: list[dict[str, object]] = []
    index = 0
    while index < len(records):
        record = records[index]
        if len(record) < 4 or record[2:3] != b" ":
            raise BomError("Git porcelain status is malformed")
        try:
            code = record[:2].decode("ascii")
            path = record[3:].decode("utf-8")
        except UnicodeError as error:
            raise BomError("Git status contains invalid path bytes") from error
        git_relative_path(path, "Git status path")
        entry: dict[str, object] = {"status": code, "path": path}
        if code[0] in {"R", "C"} or code[1] in {"R", "C"}:
            index += 1
            if index >= len(records):
                raise BomError("Git rename status lacks its source path")
            try:
                original = records[index].decode("utf-8")
            except UnicodeError as error:
                raise BomError("Git rename contains invalid path bytes") from error
            git_relative_path(original, "Git rename source path")
            entry["original_path"] = original
        result.append(entry)
        index += 1
    return result


def describe_untracked(checkout: Path, paths: Sequence[str]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    total = 0
    for path in paths:
        absolute = checkout / path
        metadata = os.lstat(absolute)
        if stat.S_ISREG(metadata.st_mode):
            raw = strict_regular_bytes(absolute, f"untracked file {path}", MAX_ARTIFACT_BYTES)
            total += len(raw)
            item = {
                "path": path,
                "type": "file",
                "git_mode": "100755" if metadata.st_mode & 0o111 else "100644",
                "bytes": len(raw),
                "sha256": sha256_bytes(raw),
                "digest_scope": "file-content",
            }
        elif stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(absolute)
            encoded = target.encode("utf-8")
            total += len(encoded)
            item = {
                "path": path,
                "type": "symlink",
                "git_mode": "120000",
                "bytes": len(encoded),
                "sha256": sha256_bytes(encoded),
                "digest_scope": "link-target",
            }
        else:
            raise BomError(f"untracked path is not a regular file or symlink: {path}")
        if total > MAX_GIT_OUTPUT_BYTES:
            raise BomError("untracked source inventory exceeds byte bound")
        result.append(item)
    return result


def _tree_utf8(value: str, label: str, maximum: int) -> bytes:
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as error:
        raise BomError(f"{label} is not valid UTF-8") from error
    if not encoded or len(encoded) > maximum or b"\x00" in encoded:
        raise BomError(f"{label} is outside the UTF-8 byte bound")
    return encoded


def _validate_tree_name(value: str, label: str) -> bytes:
    encoded = _tree_utf8(value, label, 255)
    if (
        value in {".", ".."}
        or "/" in value
        or "\\" in value
        or value != unicodedata.normalize("NFC", value)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise BomError(f"{label} is unsafe")
    return encoded


def _validate_tree_relative_path(value: str, label: str) -> bytes:
    encoded = _tree_utf8(value, label, MAX_TREE_PATH_BYTES)
    if value == ".":
        return encoded
    if value.startswith("/") or value.endswith("/"):
        raise BomError(f"{label} is not canonical")
    for index, component in enumerate(value.split("/")):
        _validate_tree_name(component, f"{label} component {index}")
    return encoded


def _validate_tree_link_target(target: str, link_path: str, label: str) -> str:
    _tree_utf8(target, label, MAX_TREE_LINK_BYTES)
    if (
        target.startswith("/")
        or target.endswith("/")
        or "\\" in target
        or any(ord(character) < 32 or ord(character) == 127 for character in target)
    ):
        raise BomError(f"{label} is absolute or unsafe")
    stack = [] if "/" not in link_path else link_path.split("/")[:-1]
    for index, component in enumerate(target.split("/")):
        if component == "":
            raise BomError(f"{label} is not canonical")
        if component == ".":
            continue
        if component == "..":
            if not stack:
                raise BomError(f"{label} escapes the measured tree")
            stack.pop()
            continue
        _validate_tree_name(component, f"{label} component {index}")
        stack.append(component)
    resolved = "/".join(stack) or "."
    _validate_tree_relative_path(resolved, f"{label} resolved path")
    return resolved


def _tree_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
    )


def _safe_tree_mode(metadata: os.stat_result, entry_type: str, label: str) -> str:
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & 0o7000 or mode & 0o022:
        raise BomError(f"{label} has an unsafe mode")
    if entry_type == "directory" and mode & 0o500 != 0o500:
        raise BomError(f"{label} directory is not owner-readable/searchable")
    if entry_type == "file" and mode & 0o400 == 0:
        raise BomError(f"{label} file is not owner-readable")
    return f"{mode:04o}"


def _append_tree_entry(
    state: dict[str, object], entry: dict[str, object], *, addressed_bytes: int
) -> None:
    entries = state["entries"]
    assert isinstance(entries, list)
    entry_limit = int(state["entry_limit"])
    byte_limit = int(state["byte_limit"])
    if len(entries) >= entry_limit:
        raise BomError("source tree exceeds its entry bound")
    new_total = int(state["addressed_bytes"]) + addressed_bytes
    if addressed_bytes < 0 or new_total > byte_limit:
        raise BomError("source tree exceeds its byte bound")
    entries.append(entry)
    state["addressed_bytes"] = new_total


def _hash_tree_file_at(
    parent_fd: int,
    name: str,
    initial: os.stat_result,
    label: str,
    maximum: int,
) -> tuple[int, str, os.stat_result]:
    if initial.st_size < 0 or initial.st_size > maximum:
        raise BomError(f"{label} exceeds the remaining byte bound")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise BomError("host lacks required O_NOFOLLOW support")
    flags = os.O_RDONLY | os.O_CLOEXEC | nofollow | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as error:
        raise BomError(f"{label} is unavailable") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or _tree_identity(before) != _tree_identity(initial):
            raise BomError(f"{label} pathname changed before measurement")
        digest = hashlib.sha256()
        observed = 0
        while observed <= maximum:
            block = os.read(descriptor, min(1024 * 1024, maximum + 1 - observed))
            if not block:
                break
            digest.update(block)
            observed += len(block)
        after = os.fstat(descriptor)
        if observed != before.st_size or _tree_identity(before) != _tree_identity(after):
            raise BomError(f"{label} changed while measured")
    finally:
        os.close(descriptor)
    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if _tree_identity(current) != _tree_identity(before):
        raise BomError(f"{label} pathname changed while measured")
    return observed, digest.hexdigest(), before


def _walk_tree_directory(
    descriptor: int,
    relative: str,
    state: dict[str, object],
    label: str,
) -> None:
    before = os.fstat(descriptor)
    if not stat.S_ISDIR(before.st_mode):
        raise BomError(f"{label} is not a directory")
    mode = _safe_tree_mode(before, "directory", label)
    _validate_tree_relative_path(relative, f"{label} path")
    _append_tree_entry(
        state,
        {"path": relative, "type": "directory", "mode": mode},
        addressed_bytes=0,
    )
    try:
        names = os.listdir(descriptor)
    except OSError as error:
        raise BomError(f"{label} cannot be enumerated") from error
    encoded_names: list[tuple[bytes, str]] = []
    seen_names: set[bytes] = set()
    for name in names:
        encoded = _validate_tree_name(name, f"{label} entry name")
        if encoded in seen_names:
            raise BomError(f"{label} contains a duplicate entry name")
        seen_names.add(encoded)
        encoded_names.append((encoded, name))
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise BomError("host lacks required O_NOFOLLOW support")
    for _encoded, name in sorted(encoded_names):
        child = name if relative == "." else relative + "/" + name
        _validate_tree_relative_path(child, f"{label} child path")
        try:
            initial = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError as error:
            raise BomError(f"{label} child is unavailable") from error
        child_label = f"source tree entry {child}"
        if stat.S_ISDIR(initial.st_mode):
            flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | nofollow
            try:
                child_fd = os.open(name, flags, dir_fd=descriptor)
            except OSError as error:
                raise BomError(f"{child_label} is unavailable") from error
            try:
                if _tree_identity(os.fstat(child_fd)) != _tree_identity(initial):
                    raise BomError(f"{child_label} pathname changed before traversal")
                _walk_tree_directory(child_fd, child, state, child_label)
            finally:
                os.close(child_fd)
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if _tree_identity(current) != _tree_identity(initial):
                raise BomError(f"{child_label} pathname changed while traversed")
        elif stat.S_ISREG(initial.st_mode):
            mode = _safe_tree_mode(initial, "file", child_label)
            remaining = int(state["byte_limit"]) - int(state["addressed_bytes"])
            size, digest, measured = _hash_tree_file_at(
                descriptor, name, initial, child_label, remaining
            )
            _append_tree_entry(
                state,
                {
                    "path": child,
                    "type": "file",
                    "mode": mode,
                    "bytes": size,
                    "sha256": digest,
                    "_device": measured.st_dev,
                    "_inode": measured.st_ino,
                    "_links": measured.st_nlink,
                },
                addressed_bytes=size,
            )
        elif stat.S_ISLNK(initial.st_mode):
            try:
                target = os.readlink(name, dir_fd=descriptor)
            except OSError as error:
                raise BomError(f"{child_label} link address is unavailable") from error
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if _tree_identity(current) != _tree_identity(initial):
                raise BomError(f"{child_label} link changed while measured")
            resolved = _validate_tree_link_target(
                target, child, f"{child_label} link target"
            )
            encoded_target = target.encode("utf-8")
            _append_tree_entry(
                state,
                {
                    "path": child,
                    "type": "symlink",
                    "mode": f"{stat.S_IMODE(initial.st_mode):04o}",
                    "target": target,
                    "resolved_path": resolved,
                    "bytes": len(encoded_target),
                    "sha256": sha256_bytes(encoded_target),
                },
                addressed_bytes=len(encoded_target),
            )
        else:
            raise BomError(
                f"{child_label} is a forbidden device, FIFO, socket, or special file"
            )
    after = os.fstat(descriptor)
    if _tree_identity(before) != _tree_identity(after):
        raise BomError(f"{label} changed while enumerated")


def _open_tree_root(root: Path, relative: str, label: str) -> tuple[int, int, str]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow or not hasattr(os, "O_DIRECTORY"):
        raise BomError("host lacks required no-follow directory support")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | nofollow
    try:
        current = os.open(root, flags)
    except OSError as error:
        raise BomError(f"{label} checkout root is unavailable") from error
    components = relative.split("/")
    try:
        for component in components[:-1]:
            try:
                following = os.open(component, flags, dir_fd=current)
            except OSError as error:
                raise BomError(f"{label} contains a symlink or unavailable component") from error
            os.close(current)
            current = following
        leaf = components[-1]
        try:
            target = os.open(leaf, flags, dir_fd=current)
        except OSError as error:
            raise BomError(f"{label} is unavailable or is a symlink") from error
        return target, current, leaf
    except Exception:
        os.close(current)
        raise


def _normalize_tree_entries(entries: list[dict[str, object]]) -> list[dict[str, object]]:
    ordered = sorted(entries, key=lambda item: str(item["path"]).encode("utf-8"))
    by_path: dict[str, dict[str, object]] = {}
    regular_groups: dict[tuple[int, int], list[dict[str, object]]] = {}
    for entry in ordered:
        path = str(entry["path"])
        if path in by_path:
            raise BomError("source tree inventory contains a duplicate path")
        by_path[path] = entry
        if entry["type"] == "file":
            key = (int(entry["_device"]), int(entry["_inode"]))
            regular_groups.setdefault(key, []).append(entry)
    for path, entry in by_path.items():
        if path == ".":
            continue
        parts = path.split("/")
        for end in range(1, len(parts)):
            prefix = "/".join(parts[:end])
            parent = by_path.get(prefix)
            if parent is not None and parent["type"] != "directory":
                raise BomError("source tree inventory contains a non-directory prefix")
    for group in regular_groups.values():
        links = int(group[0]["_links"])
        if links != len(group) or any(int(item["_links"]) != links for item in group):
            raise BomError("source tree hardlink reaches outside the measured root")
        first = str(group[0]["path"])
        for entry in group[1:]:
            entry["type"] = "hardlink"
            entry["target"] = first
    result: list[dict[str, object]] = []
    for entry in ordered:
        result.append(
            {key: value for key, value in entry.items() if not key.startswith("_")}
        )
    return result


def _measure_source_tree_once(root: Path, item: Mapping[str, object]) -> dict[str, object]:
    tree_id = str(item["id"])
    relative = str(item["path"])
    label = f"source tree {tree_id}"
    target_fd, parent_fd, leaf = _open_tree_root(root, relative, label)
    try:
        initial = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if _tree_identity(os.fstat(target_fd)) != _tree_identity(initial):
            raise BomError(f"{label} pathname changed before traversal")
        state: dict[str, object] = {
            "entries": [],
            "entry_limit": item["entry_limit"],
            "byte_limit": item["byte_limit"],
            "addressed_bytes": 0,
        }
        _walk_tree_directory(target_fd, ".", state, label)
        current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if _tree_identity(current) != _tree_identity(initial):
            raise BomError(f"{label} pathname changed while traversed")
    finally:
        os.close(target_fd)
        os.close(parent_fd)
    raw_entries = state["entries"]
    assert isinstance(raw_entries, list)
    entries = _normalize_tree_entries(raw_entries)
    digest_document = {"schema": TREE_INVENTORY_SCHEMA, "entries": entries}
    type_counts = {
        entry_type: sum(1 for entry in entries if entry["type"] == entry_type)
        for entry_type in ("directory", "file", "hardlink", "symlink")
    }
    regular_file_bytes = sum(
        int(entry["bytes"])
        for entry in entries
        if entry["type"] in {"file", "hardlink"}
    )
    unique_file_bytes = sum(
        int(entry["bytes"]) for entry in entries if entry["type"] == "file"
    )
    symlink_target_bytes = sum(
        int(entry["bytes"]) for entry in entries if entry["type"] == "symlink"
    )
    return {
        "schema": TREE_INVENTORY_SCHEMA,
        "digest_scope": TREE_DIGEST_SCOPE,
        "sha256": sha256_bytes(canonical_json_bytes(digest_document)),
        "entry_count": len(entries),
        "addressed_bytes": int(state["addressed_bytes"]),
        "regular_file_logical_bytes": regular_file_bytes,
        "regular_file_unique_bytes": unique_file_bytes,
        "symlink_target_bytes": symlink_target_bytes,
        "type_counts": type_counts,
        "entries": entries,
    }


def inspect_source_tree(root: Path, item: Mapping[str, object]) -> dict[str, object]:
    first = _measure_source_tree_once(root, item)
    second = _measure_source_tree_once(root, item)
    if canonical_json_bytes(first) != canonical_json_bytes(second):
        raise BomError(f"source tree {item['id']} changed between stable measurements")
    result = dict(first)
    result.update(
        {
            "stable_remeasurement_passed": True,
            "no_follow_path_walk_passed": True,
            "confined_link_addresses_passed": True,
            "safe_modes_and_types_passed": True,
        }
    )
    return result


def inspect_tree_input(
    item: Mapping[str, object], roots: Mapping[str, Path]
) -> tuple[dict[str, object], list[str]]:
    tree_id = str(item["id"])
    try:
        inventory = inspect_source_tree(
            roots[str(item["checkout_root"])], item
        )
    except (BomError, OSError):
        return (
            {
                "id": tree_id,
                "source": {
                    "checkout_root": item["checkout_root"],
                    "path": item["path"],
                },
                "requirements": {
                    "required": True,
                    "entry_limit": item["entry_limit"],
                    "byte_limit": item["byte_limit"],
                    "mode_policy": item["mode_policy"],
                    "no_follow": True,
                    "stable_remeasurement": True,
                },
                "authority": "observed_local_non_git_source_tree_input",
                "inventory": None,
                "failures": ["tree_unavailable_unsafe_or_unstable"],
            },
            [f"tree_unavailable_unsafe_or_unstable:{tree_id}"],
        )
    return (
        {
            "id": tree_id,
            "source": {
                "checkout_root": item["checkout_root"],
                "path": item["path"],
            },
            "requirements": {
                "required": True,
                "entry_limit": item["entry_limit"],
                "byte_limit": item["byte_limit"],
                "mode_policy": item["mode_policy"],
                "no_follow": True,
                "stable_remeasurement": True,
            },
            "authority": "observed_local_non_git_source_tree_input",
            "inventory": inventory,
            "failures": [],
        },
        [],
    )


def inspect_git_project(checkout: Path, label: str) -> dict[str, object]:
    if not checkout.is_dir() or checkout.is_symlink():
        raise BomError(f"{label} checkout directory is unavailable")
    top = git(checkout, ["rev-parse", "--show-toplevel"], f"{label} git top")
    try:
        top_path = Path(top.decode("utf-8").strip()).resolve(strict=True)
    except (UnicodeError, OSError, RuntimeError) as error:
        raise BomError(f"{label} Git top is invalid") from error
    if top_path != checkout.resolve(strict=True):
        raise BomError(f"{label} is not an independent Git checkout")

    status_before = git(
        checkout,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"],
        f"{label} status",
    )
    head = git(checkout, ["rev-parse", "--verify", "HEAD^{commit}"], f"{label} head")
    tree = git(checkout, ["rev-parse", "--verify", "HEAD^{tree}"], f"{label} tree")
    object_format = git(checkout, ["rev-parse", "--show-object-format"], f"{label} object format")
    branch = git(checkout, ["symbolic-ref", "--quiet", "--short", "HEAD"], f"{label} branch") if _has_symbolic_head(checkout) else b""
    index = git(checkout, ["ls-files", "--stage", "-z"], f"{label} index")
    tracked_diff = git(
        checkout,
        [
            "diff",
            "--binary",
            "--full-index",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "HEAD",
            "--",
        ],
        f"{label} tracked diff",
    )
    untracked_raw = git(
        checkout,
        ["ls-files", "--others", "--exclude-standard", "-z"],
        f"{label} untracked listing",
    )
    ignored_raw = git(
        checkout,
        ["ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z"],
        f"{label} ignored listing",
    )
    status_after = git(
        checkout,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"],
        f"{label} status revalidation",
    )
    head_after = git(checkout, ["rev-parse", "--verify", "HEAD^{commit}"], f"{label} head revalidation")
    index_after = git(checkout, ["ls-files", "--stage", "-z"], f"{label} index revalidation")
    if status_before != status_after or head != head_after or index != index_after:
        raise BomError(f"{label} changed while measured")

    try:
        head_text = head.decode("ascii").strip()
        tree_text = tree.decode("ascii").strip()
        object_format_text = object_format.decode("ascii").strip()
        branch_text = branch.decode("utf-8").strip()
    except UnicodeError as error:
        raise BomError(f"{label} Git identity is malformed") from error
    if SHA_RE.fullmatch(head_text) is None or SHA_RE.fullmatch(tree_text) is None:
        raise BomError(f"{label} Git identity is malformed")
    if object_format_text not in {"sha1", "sha256"}:
        raise BomError(f"{label} Git object format is unsupported")
    untracked_paths = decode_nul_paths(untracked_raw, f"{label} untracked path")
    ignored_paths = decode_nul_paths(ignored_raw, f"{label} ignored path")
    return {
        "object_format": object_format_text,
        "head": head_text,
        "head_tree": tree_text,
        "branch": branch_text or None,
        "detached_head": not bool(branch_text),
        "clean_nonignored": not bool(status_before),
        "status": {
            "bytes": len(status_before),
            "sha256": sha256_bytes(status_before),
            "entries": status_entries(status_before),
        },
        "index": {"bytes": len(index), "sha256": sha256_bytes(index)},
        "tracked_diff": {
            "bytes": len(tracked_diff),
            "sha256": sha256_bytes(tracked_diff),
        },
        "untracked": {
            "count": len(untracked_paths),
            "listing_sha256": sha256_bytes(untracked_raw),
            "entries": describe_untracked(checkout, untracked_paths),
        },
        "ignored": {
            "count": len(ignored_paths),
            "listing_sha256": sha256_bytes(ignored_raw),
            "paths": ignored_paths,
        },
        "stable_revalidation_passed": True,
        "exact_nonignored_state_captured": True,
    }


def _has_symbolic_head(checkout: Path) -> bool:
    output = bounded_command(
        [str(GIT), "symbolic-ref", "--quiet", "HEAD"],
        checkout,
        "Git symbolic HEAD inspection",
        4096,
        timeout=30,
        allowed_returncodes=(0, 1),
    )
    # Git returns 1, with no stdout, for a detached HEAD.  Any successful
    # symbolic-ref lookup returns the short ref on stdout.
    return bool(output)


def inspect_elf(
    path: Path,
    label: str,
    *,
    variant_section_name: str,
    expected_variant: str,
) -> dict[str, object]:
    raw = strict_regular_bytes(
        path,
        label,
        MAX_ARTIFACT_BYTES,
        allow_hardlinks=True,
    )
    metadata = os.lstat(path)
    if metadata.st_mode & 0o111 == 0 or len(raw) < 64 or raw[:4] != b"\x7fELF":
        raise BomError(f"{label} is not an executable ELF64")
    if raw[4] != 2 or raw[5] != 1 or raw[6] != 1:
        raise BomError(f"{label} is not a little-endian ELF64 v1 artifact")
    elf_type, machine = struct.unpack_from("<HH", raw, 16)
    phoff = struct.unpack_from("<Q", raw, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", raw, 54)
    if elf_type != 2 or machine != 183 or phentsize < 56 or phnum == 0:
        raise BomError(f"{label} is not one AArch64 ET_EXEC artifact")
    if phoff > len(raw) or phnum > 4096 or phoff + phentsize * phnum > len(raw):
        raise BomError(f"{label} program header table is invalid")
    program_types = {
        struct.unpack_from("<I", raw, phoff + index * phentsize)[0]
        for index in range(phnum)
    }
    if 2 in program_types or 3 in program_types:
        raise BomError(f"{label} is dynamically linked")
    shoff = struct.unpack_from("<Q", raw, 40)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", raw, 58)
    if (
        shoff > len(raw)
        or shentsize < 64
        or not 1 <= shnum <= 65534
        or not 1 <= shstrndx < shnum
        or shoff + shentsize * shnum > len(raw)
    ):
        raise BomError(f"{label} section header table is invalid")

    def section_header(index: int) -> tuple[int, int, int, int, int]:
        offset = shoff + index * shentsize
        name_offset, section_type = struct.unpack_from("<II", raw, offset)
        flags = struct.unpack_from("<Q", raw, offset + 8)[0]
        content_offset, content_size = struct.unpack_from("<QQ", raw, offset + 24)
        if section_type != 8 and (
            content_offset > len(raw) or content_size > len(raw) - content_offset
        ):
            raise BomError(f"{label} section range is invalid")
        return name_offset, section_type, flags, content_offset, content_size

    _names_name, names_type, _names_flags, names_offset, names_size = section_header(
        shstrndx
    )
    if names_type != 3:
        raise BomError(f"{label} section-name table is invalid")
    names = raw[names_offset : names_offset + names_size]

    def section_name(offset: int) -> str:
        if offset >= len(names):
            raise BomError(f"{label} section-name offset is invalid")
        end = names.find(b"\x00", offset)
        if end < 0:
            raise BomError(f"{label} section name is unterminated")
        try:
            return names[offset:end].decode("ascii")
        except UnicodeError as error:
            raise BomError(f"{label} section name is non-ASCII") from error

    matches: list[tuple[int, int, int, int]] = []
    for index in range(shnum):
        name_offset, section_type, flags, content_offset, content_size = section_header(
            index
        )
        if section_name(name_offset) == variant_section_name:
            matches.append((section_type, flags, content_offset, content_size))
    if len(matches) != 1:
        raise BomError(f"{label} lacks one unique compiled-variant ELF section")
    section_type, section_flags, section_offset, section_size = matches[0]
    section_content = raw[section_offset : section_offset + section_size]
    marker = (
        "org.trillionnium.p01.conformance.compiled-variant.v1="
        + expected_variant
    ).encode("ascii")
    if (
        section_type != 1
        or len(section_content) != 96
        or not section_content.startswith(marker)
        or any(section_content[len(marker) :])
    ):
        raise BomError(f"{label} compiled-variant ELF section is invalid")
    return {
        "bytes": len(raw),
        "sha256": sha256_bytes(raw),
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "format": "ELF64",
        "endianness": "little",
        "type": "ET_EXEC",
        "machine": "AArch64",
        "pt_interp_present": False,
        "pt_dynamic_present": False,
        "static": True,
        "compiled_variant_section": {
            "name": variant_section_name,
            "type": "SHT_PROGBITS",
            "flags": section_flags,
            "offset": section_offset,
            "bytes": section_size,
            "sha256": sha256_bytes(section_content),
            "marker": marker.decode("ascii"),
            "zero_padded": True,
        },
    }


def inspect_artifact(
    item: Mapping[str, object], roots: Mapping[str, Path]
) -> tuple[dict[str, object], list[str]]:
    artifact_id = str(item["id"])
    root = roots[str(item["checkout_root"])]
    path = root / str(item["path"])
    failures: list[str] = []
    try:
        elf = inspect_elf(
            path,
            f"artifact {artifact_id}",
            variant_section_name=str(item["variant_section"]),
            expected_variant=str(item["embedded_variant"]),
        )
    except (BomError, OSError) as error:
        return (
            {
                "id": artifact_id,
                "source": {
                    "checkout_root": item["checkout_root"],
                    "path": item["path"],
                },
                "lane": item["lane"],
                "embedded_variant": item["embedded_variant"],
                "release_pin": False,
                "authority": "observed_local_dirty_source_artifact_only",
                "elf": None,
                "failures": ["artifact_unavailable_or_invalid"],
            },
            [f"artifact_invalid:{artifact_id}"],
        )

    observed = {
        "id": artifact_id,
        "source": {
            "checkout_root": item["checkout_root"],
            "path": item["path"],
        },
        "lane": item["lane"],
        "embedded_variant": item["embedded_variant"],
        "release_pin": False,
        "authority": "observed_local_dirty_source_artifact_only",
        "elf": elf,
        "failures": failures,
    }
    blockers = [f"artifact_{failure}:{artifact_id}" for failure in failures]
    return observed, blockers


def measure(
    contract_path: Path,
    android_root: Path,
    control_root: Path,
    artifact_root: Path,
    resolved_manifest: Path | None,
    manifest_provenance_receipt: Path | None = None,
    require_manifest_provenance: bool = False,
) -> dict[str, object]:
    contract_value, contract_raw = strict_json(
        contract_path, "source-set contract", MAX_CONTRACT_BYTES
    )
    contract = validate_contract(contract_value)
    roots = {
        "android": Path(os.path.abspath(os.fspath(android_root))),
        "control": Path(os.path.abspath(os.fspath(control_root))),
        "artifacts": Path(os.path.abspath(os.fspath(artifact_root))),
    }
    for name, root in roots.items():
        if not root.is_dir() or root.is_symlink():
            raise BomError(f"{name} measurement root is unavailable")
    manifest_raw, manifest_producer = acquire_manifest(
        roots["android"],
        resolved_manifest,
        manifest_provenance_receipt,
        require_manifest_provenance,
    )
    manifest_projects, revisions_exact, revision_drifts = parse_manifest(manifest_raw)

    blockers: list[str] = []
    projects: list[dict[str, object]] = []
    for item in contract["projects"]:
        assert isinstance(item, dict)
        project_id = str(item["id"])
        checkout = roots[str(item["checkout_root"])] / str(item["checkout_path"])
        manifest_entry = (
            manifest_projects.get(str(item["manifest_path"]))
            if item["manifest_required"]
            else None
        )
        failures: list[str] = []
        if item["manifest_required"]:
            if manifest_entry is None:
                failures.append("required_manifest_project_missing")
            elif manifest_entry["name"] != item["expected_manifest_name"]:
                failures.append("manifest_project_name_mismatch")
            elif SHA_RE.fullmatch(manifest_entry["revision"]) is None:
                failures.append("manifest_revision_not_exact")
            elif SHA_RE.fullmatch(str(manifest_entry["declared_revision"])) is None:
                failures.append("manifest_declared_revision_not_exact")
            elif manifest_entry["checkout_differs_from_declared_revision"]:
                failures.append("manifest_checkout_revision_drift")
        git_state: dict[str, object] | None
        try:
            git_state = inspect_git_project(checkout, f"project {project_id}")
        except (BomError, OSError):
            git_state = None
            failures.append("git_checkout_unavailable_or_unstable")
        if git_state is not None:
            if item["require_clean"] and not git_state["clean_nonignored"]:
                failures.append("nonignored_worktree_dirty")
            ignored = git_state["ignored"]
            assert isinstance(ignored, dict)
            if item["require_no_ignored"] and int(ignored["count"]) != 0:
                failures.append("ignored_paths_present")
            if manifest_entry is not None and git_state["head"] != manifest_entry["revision"]:
                failures.append("head_differs_from_manifest_revision")
            if (
                manifest_entry is not None
                and git_state["head"] != manifest_entry["declared_revision"]
                and "manifest_checkout_revision_drift" not in failures
            ):
                failures.append("head_differs_from_manifest_declared_revision")
        blockers.extend(f"project_{failure}:{project_id}" for failure in failures)
        projects.append(
            {
                "id": project_id,
                "checkout": {
                    "root": item["checkout_root"],
                    "path": item["checkout_path"],
                },
                "requirements": {
                    "manifest_required": item["manifest_required"],
                    "clean": item["require_clean"],
                    "no_ignored_paths": item["require_no_ignored"],
                },
                "manifest": manifest_entry,
                "git": git_state,
                "failures": failures,
            }
        )

    trees: list[dict[str, object]] = []
    for item in contract["trees"]:
        assert isinstance(item, dict)
        observed, tree_blockers = inspect_tree_input(item, roots)
        trees.append(observed)
        blockers.extend(tree_blockers)

    artifacts: list[dict[str, object]] = []
    for item in contract["artifacts"]:
        assert isinstance(item, dict)
        observed, artifact_blockers = inspect_artifact(item, roots)
        artifacts.append(observed)
        blockers.extend(artifact_blockers)
    if not revisions_exact:
        blockers.append("resolved_manifest_contains_floating_revisions")
    if revision_drifts:
        blockers.append("resolved_manifest_checkout_differs_from_declared_revisions")
    if contract["schema"] == CONTRACT_SCHEMA_V2:
        try:
            prompt_tuple_valid = prompt_tuple_gate(contract, projects, roots)
        except (BomError, OSError, ValueError):
            prompt_tuple_valid = False
        if not prompt_tuple_valid:
            blockers.append(PROMPT_TUPLE_BLOCKER)
    blockers = sorted(set(blockers))
    contract_schema = str(contract["schema"])
    receipt_schema = (
        RECEIPT_SCHEMA_V1
        if contract_schema == CONTRACT_SCHEMA_V1
        else RECEIPT_SCHEMA_V2
    )
    posture: dict[str, object] = {
        "local_only": True,
        "network_access_performed": False,
        "signed": False,
        "release_pin_published": False,
        "build_authorized": False,
        "ota_authorized": False,
        "device_write_authorized": False,
        "observed_artifact_hashes_are_release_pins": False,
    }
    if contract_schema == CONTRACT_SCHEMA_V2:
        posture["observed_tree_hashes_are_release_pins"] = False
    receipt: dict[str, object] = {
        "schema": receipt_schema,
        "decision": PASS if not blockers else HOLD,
        "posture": posture,
        "source_set": {
            "schema": contract_schema,
            "bytes": len(contract_raw),
            "sha256": sha256_bytes(contract_raw),
        },
        "resolved_manifest": {
            "producer": manifest_producer,
            "bytes": len(manifest_raw),
            "sha256": sha256_bytes(manifest_raw),
            "project_count": len(manifest_projects),
            "all_revisions_exact": revisions_exact,
            "declared_checkout_revision_drift_count": len(revision_drifts),
            "declared_checkout_revision_drifts": revision_drifts,
        },
        "projects": projects,
        "artifacts": artifacts,
        "blockers": blockers,
        "receipt_id_scope": RECEIPT_ID_SCOPE,
    }
    if contract_schema == CONTRACT_SCHEMA_V2:
        receipt["trees"] = trees
    receipt["receipt_id"] = "sha256:" + sha256_bytes(canonical_json_bytes(receipt))
    return receipt


def ensure_output_outside_checkouts(
    output: Path, android_root: Path, control_root: Path, artifact_root: Path
) -> None:
    try:
        parent = output.parent.resolve(strict=True)
        roots = (
            android_root.resolve(strict=True),
            control_root.resolve(strict=True),
            artifact_root.resolve(strict=True),
        )
    except (OSError, RuntimeError) as error:
        raise BomError("BOM output or source-root boundary is unavailable") from error
    candidate = parent / output.name
    for root in roots:
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        raise BomError("BOM output must be outside every measured checkout")


def publish(path: Path, content: bytes) -> None:
    absolute = Path(os.path.abspath(os.fspath(path)))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags, 0o444)
    except OSError as error:
        raise BomError("BOM output publication failed") from error
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise BomError("BOM output short write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        parent_fd = os.open(
            absolute.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
    except OSError as error:
        raise BomError("BOM output parent durability failed") from error
    try:
        try:
            os.fsync(parent_fd)
        except OSError as error:
            raise BomError("BOM output parent durability failed") from error
    finally:
        os.close(parent_fd)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--android-root", type=Path, required=True)
    result.add_argument("--control-root", type=Path, required=True)
    result.add_argument("--artifact-root", type=Path, required=True)
    result.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    result.add_argument("--resolved-manifest", type=Path)
    result.add_argument(
        "--resolved-manifest-receipt",
        type=Path,
        help=(
            "provenance receipt produced by a bounded resolver for a supplied "
            "resolved manifest"
        ),
    )
    result.add_argument(
        "--require-resolved-manifest-provenance",
        action="store_true",
        help="reject a supplied manifest without an explicit resolver receipt",
    )
    result.add_argument("--output", type=Path)
    return result


def main(argv: Iterable[str] | None = None) -> int:
    args = parser().parse_args(list(argv) if argv is not None else None)
    try:
        if args.output is not None:
            ensure_output_outside_checkouts(
                Path(os.path.abspath(os.fspath(args.output))),
                Path(os.path.abspath(os.fspath(args.android_root))),
                Path(os.path.abspath(os.fspath(args.control_root))),
                Path(os.path.abspath(os.fspath(args.artifact_root))),
            )
        receipt = measure(
            args.contract,
            args.android_root,
            args.control_root,
            args.artifact_root,
            args.resolved_manifest,
            args.resolved_manifest_receipt,
            args.require_resolved_manifest_provenance,
        )
        content = canonical_json_bytes(receipt)
        if args.output is None:
            sys.stdout.buffer.write(content)
        else:
            publish(args.output, content)
        return 0 if receipt["decision"] == PASS else 2
    except BomError as error:
        print(f"cross-repo source BOM error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
