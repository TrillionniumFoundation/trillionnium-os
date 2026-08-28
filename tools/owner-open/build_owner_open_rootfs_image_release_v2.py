#!/usr/bin/env python3
"""Selected Root Linux squashfs image builder with bounded process groups."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

import build_owner_open_rootfs_image_release as base

POLL_SECONDS = 0.02
TERM_GRACE = 1.0
KILL_GRACE = 2.0


def terminate_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + TERM_GRACE
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(POLL_SECONDS)
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=KILL_GRACE)
    except subprocess.TimeoutExpired as error:
        raise base.ImageError("image tool process group could not be reaped") from error


def bounded_command(argv: list[str], timeout: float):
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LC_ALL": "C",
            "TZ": "UTC",
        },
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        terminate_group(process)
        stdout, stderr = process.communicate(timeout=KILL_GRACE)
    if len(stdout) + len(stderr) > base.MAX_OUTPUT_BYTES:
        raise base.ImageError(f"command output exceeds byte bound: {argv[0]}")
    if timed_out:
        raise base.ImageError(f"command timed out and was reaped: {argv[0]}")
    return {
        "returncode": process.returncode,
        "elapsed_ms": max(0, int((time.monotonic() - started) * 1000)),
        "stdout": stdout,
        "stderr": stderr,
        "stdout_sha256": base.hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": base.hashlib.sha256(stderr).hexdigest(),
    }


def normalize_copy(source_root: Path, destination_root: Path) -> list[str]:
    destination_root.mkdir(mode=0o755)
    files: list[str] = []
    for source in sorted(source_root.rglob("*")):
        relative = source.relative_to(source_root)
        target = destination_root / relative
        metadata = source.lstat()
        if base.stat.S_ISLNK(metadata.st_mode):
            raise base.ImageError(f"staging copy encountered symlink: {relative}")
        if base.stat.S_ISDIR(metadata.st_mode):
            target.mkdir(mode=0o755, parents=True, exist_ok=True)
            os.chmod(target, 0o755)
            continue
        if not base.stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise base.ImageError(f"staging copy encountered non-regular file: {relative}")
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        shutil.copyfile(source, target, follow_symlinks=False)
        os.chmod(target, base.stat.S_IMODE(metadata.st_mode))
        source_digest, source_bytes = base.sha256_path(source, base.MAX_FILE_BYTES)
        target_digest, target_bytes = base.sha256_path(target, base.MAX_FILE_BYTES)
        if source_digest != target_digest or source_bytes != target_bytes:
            raise base.ImageError(f"normalized staging copy drifted: {relative}")
        files.append(relative.as_posix())
    for path in sorted(destination_root.rglob("*"), reverse=True):
        os.utime(path, ns=(0, 0), follow_symlinks=False)
    os.utime(destination_root, ns=(0, 0), follow_symlinks=False)
    return sorted(files)


base.bounded_command = bounded_command
base.normalize_copy = normalize_copy


def main(argv: list[str]) -> int:
    return base.main(argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
