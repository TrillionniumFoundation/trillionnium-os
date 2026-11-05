"""Read one pinned completed P4 host audit receipt; emit a lossless envelope only."""
import base64
import hashlib
import json
import lzma
import os
from pathlib import Path
import stat
import sys

TARGET = Path('/home/alex/codex-hepta-external902-independent-closure-audit-1ad3-01/BYTE-EQUALITY.json')
EXPECTED_BYTES = 52142
EXPECTED_SHA256 = '6bb0cb5179850cce2adc53982796bde4dd6bb2f0269968df33e91ff4b4dc8461'
EXPECTED_VERSION = '66306:37116535:52142:1793888235526283464:1793888235526283464'
META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def metadata(value):
    return [getattr(value, name) for name in META]


def version(value):
    return ':'.join(str(getattr(value, name)) for name in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def parent_fd():
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in TARGET.parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def main():
    source_sha = globals().get('PINNED_STDIN_SOURCE_SHA256')
    need(type(source_sha) is str and len(source_sha) == 64 and all(c in '0123456789abcdef' for c in source_sha), 'pinned stdin source identity required')
    need(TARGET.is_absolute() and TARGET.resolve(strict=True) == TARGET, 'canonical fixed original required')
    parent = parent_fd()
    fd = None
    try:
        parent_before = metadata(os.fstat(parent))
        before = os.stat(TARGET.name, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == before.st_gid == 1000 and stat.S_IMODE(before.st_mode) == 0o600, 'original regular owner/mode differs')
        need(before.st_size == EXPECTED_BYTES and version(before) == EXPECTED_VERSION, 'original immutable-read version differs')
        fd = os.open(TARGET.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        need(metadata(os.fstat(fd)) == metadata(before), 'original changed at open')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(EXPECTED_BYTES + 1)
        need(len(raw) == EXPECTED_BYTES and sha(raw) == EXPECTED_SHA256, 'whole original bytes differ')
        packed = lzma.compress(raw, format=lzma.FORMAT_XZ, preset=6)
        need(lzma.decompress(packed) == raw, 'lossless packing differs')
        need(metadata(before) == metadata(os.fstat(fd)) == metadata(os.stat(TARGET.name, dir_fd=parent, follow_symlinks=False)), 'original full9 changed during read/packing')
        need(parent_before == metadata(os.fstat(parent)), 'original parent changed during read/packing')
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)
    fresh_parent = parent_fd()
    try:
        need(metadata(os.fstat(fresh_parent)) == parent_before and metadata(os.stat(TARGET.name, dir_fd=fresh_parent, follow_symlinks=False)) == metadata(before), 'canonical original/parent changed')
    finally:
        os.close(fresh_parent)
    result = {
        'schema': 'hepta.p4.pinned-original-packed-read.v1',
        'state': 'PINNED_ORIGINAL_READ_AND_LOSSLESSLY_PACKED',
        'source_execution_mode': 'pinned_stdin_no_source_file_published',
        'source_sha256': source_sha,
        'original': {'path': str(TARGET), 'bytes': len(raw), 'sha256': sha(raw), 'version': version(before), 'metadata': metadata(before)},
        'packed': {'format': 'xz', 'bytes': len(packed), 'sha256': sha(packed), 'data_base64': base64.b64encode(packed).decode('ascii')},
        'whole_original_and_parent_bookends_complete': True,
        'phone_calls': 0, 'subprocesses': 0, 'source_or_original_writes': 0,
        'original_close_calls': 0, 'boundary_publications': 0, 'component_qualified': False,
    }
    encoded = (json.dumps(result, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode('utf-8')
    need(len(encoded) <= 65536, 'complete packed envelope exceeds stdout bound')
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


if __name__ == '__main__':
    main()
