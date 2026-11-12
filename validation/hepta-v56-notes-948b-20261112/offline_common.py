"""Strict, read-only inputs and create-only results for the v56 host preparation.

This module has no subprocess, socket, ADB, lock, or phone entry point.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
TASK = re.compile(r"[0-9a-f]{32}\Z")
GENERATION = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def exact_keys(obj, keys, label):
    need(type(obj) is dict and set(obj) == set(keys), label + ": exact object fields required")


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError("nonfinite JSON: " + value)

    return json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs,
                      parse_constant=invalid_constant)


def require_sha(value, label):
    need(type(value) is str and SHA256.fullmatch(value), label + ": exact SHA-256 required")


def checked_path(path):
    path = Path(path)
    need(path.is_absolute(), "absolute input path required")
    need(all(not p.is_symlink() for p in (path, *path.parents)), "input symlink refused")
    return path


def _key(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def checked_read(path, expected_sha, maximum=16 << 20):
    require_sha(expected_sha, "input hash")
    path = checked_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum, "input size/type refused")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    need(len(raw) == before.st_size and _key(before) == _key(after) == _key(path.stat()),
         "input changed during read")
    need(sha256(raw) == expected_sha, "input SHA-256 mismatch: " + str(path))
    return raw


def checked_file_hash(path, expected_sha, maximum=1 << 30):
    require_sha(expected_sha, "file hash")
    path = checked_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    total, digest = 0, hashlib.sha256()
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum, "file size/type refused")
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            total += len(chunk)
            need(total <= maximum, "file grew beyond bound")
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    need(total == before.st_size and _key(before) == _key(after) == _key(path.stat()),
         "file changed during hashing")
    need(digest.hexdigest() == expected_sha, "file SHA-256 mismatch: " + str(path))
    return {"path": str(path), "bytes": total, "sha256": digest.hexdigest()}


def write_new_json(path, value):
    path = Path(path)
    need(path.is_absolute() and path.parent.is_dir(), "existing absolute output parent required")
    need(all(not p.is_symlink() for p in (path, *path.parents)), "output symlink refused")
    raw = (json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode("utf-8")
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"path": str(path), "bytes": len(raw), "sha256": sha256(raw)}
