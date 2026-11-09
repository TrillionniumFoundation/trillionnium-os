#!/usr/bin/env python3
"""Derive shared Android configuration before deferred product inheritance.

common.mk remains the sealed compatibility input. The owner-open product
inherits this generated common base, which never selects its old runtime.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import os
from pathlib import Path
import secrets
import stat
import sys

COMMON = Path("android-integration/working-tree/vendor/trillionnium/config/common.mk")
OUTPUT = COMMON.with_name("common_owner_open_base.mk")
MAX_BYTES = 1024 * 1024
START = "# Built-in headless Trillionnium root Linux payload."
END = "\n".join((
    "PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += " + chr(92),
    "    system/bin/curl " + chr(92),
    "",
))
LEGACY_INIT = "\n".join((
    "# Trillionnium-specific init rc file",
    "PRODUCT_PACKAGES += " + chr(92),
    "    init.trillionnium-system_ext.rc",
    "",
))


class GenerationError(ValueError):
    pass


def identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
            metadata.st_gid, metadata.st_nlink, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


class DirectoryHandle:
    """One raw close attempt; interruption ends this standalone observer.

    Linux close(EINTR) may already release and recycle the descriptor. Never
    retry its number. Arbitrary asynchronous interruption of os.open ownership
    transfer cannot be made exception-safe in pure Python; the CLI must abort
    and kernel process-exit cleanup owns any unknown directory descriptor.
    """
    def __init__(self, path: Path):
        self.path = path
        self.fd: int | None = None
        before = path.lstat()
        if not stat.S_ISDIR(before.st_mode):
            raise GenerationError(f"ordinary parent directory required: {path}")
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        self.expected = self.directory_identity(before)
        try:
            self.require_identity()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
        # Creating a temporary file intentionally changes directory timestamps.
        return (metadata.st_dev, metadata.st_ino, metadata.st_mode,
                metadata.st_uid, metadata.st_gid)

    def require_identity(self) -> None:
        assert self.fd is not None
        if (self.directory_identity(os.fstat(self.fd)) != self.expected or
                self.directory_identity(self.path.lstat()) != self.expected):
            raise GenerationError(f"parent directory changed: {self.path}")

    def close(self) -> None:
        if self.fd is not None:
            closing, self.fd = self.fd, None
            os.close(closing)


def close_owned_file(stream: io.FileIO) -> None:
    try:
        stream.close()
    except BaseException:
        # The C-layer object retains ownership/closed state; retrying that
        # object is safe even if the first close released and recycled its fd.
        if not stream.closed:
            try:
                stream.close()
            except BaseException:
                pass
        raise


def open_owned_file(parent: DirectoryHandle, name: str, flags: int, mode: int = 0o600) -> io.FileIO:
    assert parent.fd is not None
    # Let FileIO own construction and closure. Its opener returns the raw fd
    # straight to the C-layer owner, without a second Python raw-close path.
    def opener(open_name: str, open_flags: int) -> int:
        return os.open(open_name, open_flags | flags | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                       mode, dir_fd=parent.fd)
    stream = io.FileIO(name, "wb" if flags & os.O_WRONLY else "rb", opener=opener)
    try:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise GenerationError(f"ordinary file required: {name}")
        return stream
    except BaseException:
        close_owned_file(stream)
        raise


def bounded_text(path: Path) -> str:
    parent = DirectoryHandle(path.parent)
    stream = None
    try:
        assert parent.fd is not None
        metadata = os.stat(path.name, dir_fd=parent.fd, follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_BYTES:
            raise GenerationError(f"bounded ordinary input required: {path}")
        stream = open_owned_file(parent, path.name, os.O_RDONLY)
        expected = identity(metadata)
        if identity(os.fstat(stream.fileno())) != expected:
            raise GenerationError(f"input changed before read: {path}")
        raw = bytearray()
        # Read exactly the initial bounded size. Growth is rejected by fstat;
        # detecting EOF never requires an extra byte beyond the 1 MiB cap.
        while len(raw) < metadata.st_size:
            if identity(os.fstat(stream.fileno())) != expected:
                raise GenerationError(f"input changed while read: {path}")
            chunk = stream.read(min(4096, metadata.st_size - len(raw)))
            if not chunk:
                raise GenerationError(f"input shortened while read: {path}")
            raw.extend(chunk)
        if (identity(os.fstat(stream.fileno())) != expected or
                identity(os.stat(path.name, dir_fd=parent.fd, follow_symlinks=False)) != expected):
            raise GenerationError(f"input changed while read: {path}")
        parent.require_identity()
        return raw.decode("utf-8")
    finally:
        try:
            if stream is not None:
                close_owned_file(stream)
        finally:
            parent.close()


def output_identity(parent: DirectoryHandle, name: str) -> tuple[int, ...] | None:
    assert parent.fd is not None
    try:
        metadata = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode):
        raise GenerationError(f"ordinary output required: {name}")
    return identity(metadata)


def publish_generated(path: Path, source: str) -> None:
    raw = source.encode("utf-8")
    if not 0 < len(raw) <= MAX_BYTES:
        raise GenerationError("generated output exceeds the ordinary-file bound")
    parent = DirectoryHandle(path.parent)
    stream = None
    temporary = ".owner-open-common-base-" + secrets.token_hex(16)
    owned_inode = None
    published = False
    try:
        assert parent.fd is not None
        expected_output = output_identity(parent, path.name)
        stream = open_owned_file(parent, temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        owned_inode = os.fstat(stream.fileno())
        offset = 0
        while offset < len(raw):
            written = stream.write(memoryview(raw)[offset:offset + 4096])
            if written is None or written <= 0:
                raise GenerationError("generated output write made no progress")
            offset += written
        os.fchmod(stream.fileno(), 0o644)
        os.fsync(stream.fileno())
        completed = os.fstat(stream.fileno())
        if completed.st_size != len(raw) or completed.st_nlink != 1:
            raise GenerationError("generated temporary inode changed")
        parent.require_identity()
        if output_identity(parent, path.name) != expected_output:
            raise GenerationError("output changed during generation")
        # replace acts on the directory entry and never follows a last-moment
        # output symlink. It is not a compare-and-swap against hostile writers.
        os.replace(temporary, path.name, src_dir_fd=parent.fd, dst_dir_fd=parent.fd)
        published = True
        os.fsync(parent.fd)
        if output_identity(parent, path.name) != identity(os.fstat(stream.fileno())):
            raise GenerationError("published output changed")
        parent.require_identity()
    finally:
        try:
            if not published and owned_inode is not None:
                try:
                    actual = os.stat(temporary, dir_fd=parent.fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    if (actual.st_dev, actual.st_ino) == (owned_inode.st_dev, owned_inode.st_ino):
                        os.unlink(temporary, dir_fd=parent.fd)
        finally:
            try:
                if stream is not None:
                    close_owned_file(stream)
            finally:
                parent.close()
    # Late publication/close errors may leave the complete new output visible;
    # only a successful standalone CLI exit and subsequent --check admit it.


def render(source: str) -> str:
    if source.count(START) != 1 or source.count(END) != 1:
        raise GenerationError("shared/retained runtime source boundaries are ambiguous")
    start, end = source.index(START), source.index(END)
    if end <= start:
        raise GenerationError("retained runtime boundaries are reversed")
    # Remove the complete legacy runtime, RootFS, P01 and debug-ADB section,
    # including its variant conditions, before Android expands inherit tags.
    # The rest of common.mk is copied byte-for-byte and bound by its digest.
    shared = source[:start] + source[end:]
    if shared.count(LEGACY_INIT) != 1:
        raise GenerationError("legacy init selection boundary is ambiguous")
    shared = shared.replace(LEGACY_INIT, "", 1)
    return (
        "# AUTO-GENERATED by tools/generate-owner-open-common-base.py.\n"
        "# Shared Android configuration only; sealed runtime stays in common.mk.\n"
        "# common.mk sha256: " + hashlib.sha256(source.encode()).hexdigest() + "\n\n"
        + shared
    )


def verify(root: Path) -> None:
    if bounded_text(root / OUTPUT) != render(bounded_text(root / COMMON)):
        raise GenerationError("owner-open common base drifted from its shared source")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.check:
            verify(args.root)
        else:
            output = args.root / OUTPUT
            publish_generated(output, render(bounded_text(args.root / COMMON)))
        print("PASS_OWNER_OPEN_COMMON_BASE_GENERATED source_only=true")
        return 0
    except (OSError, UnicodeError, GenerationError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
