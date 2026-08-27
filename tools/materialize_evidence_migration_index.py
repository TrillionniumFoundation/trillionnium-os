#!/usr/bin/env python3
"""Materialize the deterministic source-evidence migration index.

The index measures only Git-tracked files under the two frozen historical
evidence roots. It neither creates an archive nor deletes source files.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
from typing import Sequence


REPOSITORY = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = REPOSITORY / "docs/archive/evidence-migration-v1/index-v1.json"
INDEX_SCHEMA = "org.trillionnium.source-evidence-migration-index.v1"
SOURCE_SETS: tuple[tuple[str, str], ...] = (
    ("mobile-smoke-2026-05", "docs/mobile-smoke"),
    ("historical-v1", "docs/archive/historical-v1"),
)
GIT = Path("/usr/bin/git")
MAX_SOURCE_FILE_BYTES = 16 * 1024 * 1024


class IndexError(RuntimeError):
    """The tracked evidence set cannot be measured deterministically."""


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


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) < 32 for character in value)
    ):
        raise IndexError(f"noncanonical tracked path: {value!r}")
    return value


def tracked_paths(repository: Path, root: str) -> list[str]:
    completed = subprocess.run(
        [os.fspath(GIT), "ls-files", "-z", "--", root],
        cwd=repository,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise IndexError(
            f"git ls-files failed for {root}: "
            f"{completed.stderr.decode('utf-8', errors='replace').strip()}"
        )
    try:
        values = [
            canonical_relative_path(item.decode("utf-8"))
            for item in completed.stdout.split(b"\0")
            if item
        ]
    except UnicodeDecodeError as error:
        raise IndexError(f"tracked path below {root} is not UTF-8") from error
    if not values or values != sorted(values) or len(values) != len(set(values)):
        raise IndexError(f"tracked set below {root} is empty, unsorted, or duplicated")
    prefix = root.rstrip("/") + "/"
    if any(not value.startswith(prefix) for value in values):
        raise IndexError(f"git returned a path outside {root}")
    return values


def read_stable_regular(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise IndexError(f"cannot open tracked evidence {path}") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink < 1
            or before.st_size < 0
            or before.st_size > MAX_SOURCE_FILE_BYTES
        ):
            raise IndexError(f"tracked evidence boundary is invalid: {path}")
        chunks: list[bytes] = []
        observed = 0
        while observed <= MAX_SOURCE_FILE_BYTES:
            block = os.read(
                descriptor,
                min(1024 * 1024, MAX_SOURCE_FILE_BYTES + 1 - observed),
            )
            if not block:
                break
            chunks.append(block)
            observed += len(block)
        after = os.fstat(descriptor)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_uid,
            value.st_gid,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if observed != before.st_size or identity(before) != identity(after):
            raise IndexError(f"tracked evidence changed while read: {path}")
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def media_type(path: str) -> str:
    return {
        ".json": "application/json",
        ".md": "text/markdown; charset=utf-8",
        ".sha256": "text/plain; charset=us-ascii",
        ".txt": "text/plain; charset=utf-8",
    }.get(PurePosixPath(path).suffix.lower(), "application/octet-stream")


def entries_digest(entries: list[dict[str, object]]) -> str:
    digest = hashlib.sha256()
    for entry in entries:
        digest.update(str(entry["path"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(entry["bytes"]).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(entry["sha256"]).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def build_index(
    repository: Path = REPOSITORY,
    source_sets: Sequence[tuple[str, str]] = SOURCE_SETS,
) -> dict[str, object]:
    repository = repository.resolve()
    all_entries: list[dict[str, object]] = []
    summaries: list[dict[str, object]] = []
    seen_paths: set[str] = set()
    seen_ids: set[str] = set()
    for source_set_id, root in source_sets:
        if source_set_id in seen_ids:
            raise IndexError(f"duplicate source-set id: {source_set_id}")
        seen_ids.add(source_set_id)
        entries: list[dict[str, object]] = []
        extensions: Counter[str] = Counter()
        for relative in tracked_paths(repository, root):
            if relative in seen_paths:
                raise IndexError(f"tracked evidence appears in two source sets: {relative}")
            seen_paths.add(relative)
            content = read_stable_regular(repository / relative)
            suffix = PurePosixPath(relative).suffix.lower() or "<none>"
            extensions[suffix] += 1
            entries.append(
                {
                    "bytes": len(content),
                    "media_type": media_type(relative),
                    "path": relative,
                    "sha256": sha256_bytes(content),
                    "source_set_id": source_set_id,
                }
            )
        set_digest = entries_digest(entries)
        summaries.append(
            {
                "archive_status": "not_materialized_plan_only",
                "entry_count": len(entries),
                "entries_sha256": set_digest,
                "extension_counts": dict(sorted(extensions.items())),
                "proposed_object_key": (
                    "trillionnium-os/source-evidence/v1/"
                    f"{source_set_id}/{set_digest}.tar.zst"
                ),
                "root": root,
                "source_set_id": source_set_id,
                "total_bytes": sum(int(entry["bytes"]) for entry in entries),
            }
        )
        all_entries.extend(entries)

    return {
        "archive_contract": {
            "archive_format": "deterministic_posix_tar_plus_zstd",
            "archive_sha256": "unavailable_until_materialized",
            "deletion_authorized": False,
            "entry_digest_algorithm": "sha256(path_utf8 NUL decimal_bytes NUL sha256 LF)",
            "required_before_source_deletion": [
                "archive_sha256_recorded_in_signed_release_manifest",
                "two_independently_verified_archive_replicas",
                "clean-room_restore_matches_every_index_entry",
                "selected_golden_fixtures_retained_in_source",
                "explicit_release-owner_approval",
            ],
            "tar_normalization": {
                "entry_order": "bytewise_path_ascending",
                "gid": 0,
                "gname": "",
                "mtime_unix": 0,
                "regular_file_mode": "0644",
                "uid": 0,
                "uname": "",
            },
            "zstd_profile": "level_19_no_dictionary_single_thread",
        },
        "entries": all_entries,
        "schema": INDEX_SCHEMA,
        "source_sets": summaries,
        "status": "migration_plan_only_source_files_retained",
        "totals": {
            "bytes": sum(int(entry["bytes"]) for entry in all_entries),
            "entries": len(all_entries),
            "source_sets": len(summaries),
        },
    }


def parse_args(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the index differs")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    options = parse_args(sys.argv[1:] if arguments is None else arguments)
    expected = canonical_json_bytes(build_index())
    output = options.output.resolve()
    if options.check:
        try:
            actual = output.read_bytes()
        except OSError as error:
            raise IndexError(f"cannot read migration index {output}") from error
        if actual != expected:
            raise IndexError("source-evidence migration index is stale")
        print(f"PASS: source-evidence migration index is current ({output})")
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(expected)
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except IndexError as error:
        print(f"HOLD: {error}", file=sys.stderr)
        raise SystemExit(1) from error
