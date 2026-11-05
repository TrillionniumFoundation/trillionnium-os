#!/usr/bin/env python3
"""Stage only the fixed reviewed source archive; no source imports or execution."""
import base64
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import time
import zlib
from pathlib import Path, PurePosixPath

B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
R = B / 'root-fixed19-1ad3-20261105-r1'
AUDIT = R / 'source-stage09'
TARGET = B / 'fixed19-physical-faults-r10-r1-candidate01-1ad3'
KEY = 'root-1ad3-physical-fault-final01-source-stage09-20261105'
ARCHIVE_NAME = 'physical-fault-neg04-neg05-neg07-source-stage-final01.tar.gz'
ARCHIVE_PIN = (306125, '833533c5b4c1bc90a17d92885e277b4c48c3811d3308f55a4e9cc01dababcca3')
TAR_PIN = (1208320, 'df847ed82b876e88a4f8e72e0fdb9e1b7fa06db0c73e16627f8e7655170b1926')
MANIFEST_PIN = (8432, 'e9a4489cd0c01c7f36c9cf597d71f4fd5d6dfe034c802140e9e41edeea7e0654')
PAYLOAD_B64 = '__EXACT_REVIEWED_ARCHIVE_BASE64__'
META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
DIR_META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid')
DIRS = {}
CREATED = []


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def desc(path, raw):
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')


def strict(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def values(st, names=META):
    return tuple(getattr(st, name) for name in names)


def hold_directory(path, created=False):
    need(path.is_absolute() and path.resolve(strict=True) == path, 'canonical directory required: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    st = os.fstat(fd)
    need(stat.S_ISDIR(st.st_mode) and values(st, DIR_META) == values(path.lstat(), DIR_META),
         'directory inode/path identity differs')
    if created:
        need(st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o700,
             'new private directory ownership/mode differs')
    DIRS[str(path)] = (fd, values(st, DIR_META))


def directory_fd(path):
    fd, identity = DIRS[str(path)]
    need(path.resolve(strict=True) == path and identity == values(os.fstat(fd), DIR_META)
         == values(path.lstat(), DIR_META), 'held directory replaced: ' + str(path))
    return fd


def new_directory(path):
    parent_fd = directory_fd(path.parent)
    os.mkdir(path.name, mode=0o700, dir_fd=parent_fd)
    hold_directory(path, created=True)
    os.fsync(parent_fd)


def put(path, raw):
    need(type(raw) is bytes and len(raw) <= 2 * 1024 * 1024, 'bounded staged file required')
    parent_fd = directory_fd(path.parent)
    fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=parent_fd)
    try:
        first = os.fstat(fd)
        need(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and first.st_size == 0
             and first.st_uid == os.geteuid() and stat.S_IMODE(first.st_mode) == 0o600,
             'new private single-link regular inode required')
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            need(count > 0, 'staged file short write')
            offset += count
        os.fsync(fd)
        after = os.fstat(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        body = bytearray()
        while len(body) <= len(raw):
            block = os.read(fd, min(65536, len(raw) + 1 - len(body)))
            if not block:
                break
            body.extend(block)
        need(bytes(body) == raw and after.st_size == len(raw)
             and values(after) == values(os.fstat(fd)) == values(path.lstat()),
             'staged file byte/metadata readback differs')
        need(values(first, DIR_META) == values(after, DIR_META), 'created inode ownership changed')
        directory_fd(path.parent)
        os.fsync(parent_fd)
        row = desc(path, raw)
        CREATED.append((path, row, values(after)))
        return row
    finally:
        os.close(fd)


def check_file(path, row, identity):
    parent_fd = directory_fd(path.parent)
    fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    try:
        initial = os.fstat(fd)
        need(stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1
             and values(initial) == identity, 'retained output identity changed')
        data = bytearray()
        while len(data) <= row['bytes']:
            block = os.read(fd, min(65536, row['bytes'] + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        need(desc(path, bytes(data)) == row and values(os.fstat(fd)) == identity == values(path.lstat()),
             'retained output readbookend differs')
    finally:
        os.close(fd)


def relative(name):
    need(type(name) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*', name),
         'strict relative member name required')
    path = PurePosixPath(name)
    need(not path.is_absolute() and str(path) == name and all(x not in ('.', '..') for x in path.parts),
         'canonical relative regular member required')
    return path


def archive_files():
    packed = base64.b64decode(PAYLOAD_B64, validate=True)
    need(base64.b64encode(packed).decode('ascii') == PAYLOAD_B64
         and (len(packed), sha(packed)) == ARCHIVE_PIN, 'exact archive differs')
    inflater = zlib.decompressobj(31)
    tar_raw = inflater.decompress(packed, TAR_PIN[0] + 1)
    need(inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail
         and (len(tar_raw), sha(tar_raw)) == TAR_PIN, 'exact bounded one-member gzip/tar differs')
    result = {}
    with tarfile.open(fileobj=io.BytesIO(tar_raw), mode='r:') as archive:
        members = archive.getmembers()
        need(len(members) == 48 and sum(m.size for m in members) == 1162604, 'exact archive inventory budget differs')
        for member in members:
            relative(member.name)
            need(member.type == tarfile.REGTYPE and member.isfile() and not member.linkname
                 and not member.pax_headers and not member.sparse and 0 <= member.size <= 2 * 1024 * 1024
                 and member.name not in result, 'regular-only unique tar entries required')
            handle = archive.extractfile(member)
            need(handle is not None, 'regular member unavailable')
            with handle:
                raw = handle.read(member.size + 1)
            need(len(raw) == member.size, 'archive member size differs')
            result[member.name] = raw
    mf = result['SOURCE-MANIFEST.json']
    need((len(mf), sha(mf)) == MANIFEST_PIN, 'reviewed manifest original differs')
    value = strict(mf)
    rows = value['files']
    need(value['schema'] == 'hepta.physical-fault.root-source-package.v1'
         and type(rows) is list and len(rows) == 47, 'reviewed source manifest shape differs')
    names = set()
    for row in rows:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}, 'exact manifest member descriptor required')
        relative(row['path'])
        need(row['path'] not in names and type(row['bytes']) is int and row['bytes'] >= 0
             and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'unique exact manifest member required')
        names.add(row['path'])
        raw = result[row['path']]
        need((len(raw), sha(raw)) == (row['bytes'], row['sha256']), 'declared member bytes differ')
    need(set(result) == names | {'SOURCE-MANIFEST.json'}, 'tar is not the manifest closed regular-file set')
    need(sum(map(len, result.values())) == 1162604, 'exact uncompressed source bytes differ')
    return packed, result


def main():
    started = time.monotonic_ns()
    packed, files = archive_files()
    os.umask(0o077)
    hold_directory(B)
    hold_directory(R)
    need(not os.path.lexists(AUDIT) and not os.path.lexists(TARGET), 'fresh target and audit required; old attempts retained')
    new_directory(AUDIT)
    try:
        archive_row = put(AUDIT / ARCHIVE_NAME, packed)
        put(AUDIT / 'STAGE-CONTROL.json', encoded({
            'schema': 'hepta.physical-fault.source-stage-control.v1', 'idempotency_key': KEY,
            'archive': archive_row, 'target': str(TARGET), 'source_manifest_pin': list(MANIFEST_PIN),
            'regular_files': 48, 'uncompressed_file_bytes': 1162604,
            'phone_calls': 0, 'p4_calls': 0, 'case_runs': 0, 'runtime_freezes': 0, 'plan_preparations': 0,
            'automatic_retry': False, 'existing_outputs_overwritten': False,
        }))
        new_directory(TARGET)
        staged = []
        for name, raw in sorted(files.items()):
            relative_path = relative(name)
            parent = TARGET
            for part in relative_path.parts[:-1]:
                parent = parent / part
                if str(parent) not in DIRS:
                    new_directory(parent)
            staged.append(put(TARGET.joinpath(*relative_path.parts), raw))
        entries = list(TARGET.rglob('*'))
        expected_dirs = {str(parent) for name in files for parent in PurePosixPath(name).parents
                         if str(parent) != '.'}
        actual_files, actual_dirs = [], []
        for path in entries:
            st = path.lstat()
            name = str(path.relative_to(TARGET))
            if stat.S_ISREG(st.st_mode):
                need(st.st_nlink == 1, 'unexpected staged hard link')
                actual_files.append(name)
            else:
                need(stat.S_ISDIR(st.st_mode) and not path.is_symlink(), 'unexpected staged special file or symlink')
                actual_dirs.append(name)
        need(sorted(actual_files) == sorted(files) and set(actual_dirs) == expected_dirs,
             'actual staged closed file/directory inventory differs')
        for path, row, identity in CREATED:
            check_file(path, row, identity)
        for path in sorted(DIRS):
            directory_fd(Path(path))
        staged_row = put(AUDIT / 'STAGED-FILES.json', encoded({
            'schema': 'hepta.physical-fault.staged-source-files.v1', 'files': staged,
            'all_created_single_link_regular_inodes': True, 'file_and_directory_fsync': True,
            'all_raw_bytes_and_full9_metadata_bookended': True,
        }))
        result = {
            'schema': 'hepta.physical-fault.source-stage-result.v1',
            'state': 'REVIEWED_SOURCE_PACKAGE_STAGED_NO_ENTRYPOINT_EXECUTED',
            'idempotency_key': KEY, 'target': str(TARGET), 'audit': str(AUDIT),
            'archive': archive_row, 'source_manifest': desc(TARGET / 'SOURCE-MANIFEST.json', files['SOURCE-MANIFEST.json']),
            'staged_files': staged_row, 'regular_files': len(staged), 'declared_source_members': 47,
            'uncompressed_file_bytes': sum(map(len, files.values())),
            'exact_original_manifest_preserved': True, 'created_inode_readback_complete': True,
            'closed_regular_inventory_verified': True, 'elapsed_monotonic_ns': time.monotonic_ns() - started,
            'phone_calls': 0, 'p4_calls': 0, 'case_runs': 0, 'runtime_freezes': 0, 'plan_preparations': 0,
            'source_imports': 0, 'source_entrypoint_executions': 0, 'automatic_retry': False,
            'existing_outputs_overwritten': False, 'physical_cases_passed': 0, 'whole_cases_passed': 0,
        }
        result_row = put(AUDIT / 'RESULT.json', encoded(result))
        for path, row, identity in CREATED:
            check_file(path, row, identity)
        print(json.dumps({'state': result['state'], 'result': result_row,
            'source_manifest': result['source_manifest'], 'regular_files': len(staged),
            'phone_calls': 0, 'case_runs': 0, 'runtime_freezes': 0, 'plan_preparations': 0}, sort_keys=True))
        return 0
    except BaseException as error:
        failure = {'state': 'SOURCE_STAGE_FAILED_OR_UNKNOWN_ORIGINALS_RETAINED',
            'idempotency_key': KEY, 'target': str(TARGET), 'error_type': type(error).__name__,
            'detail': str(error)[:2000], 'created_file_count': len(CREATED),
            'automatic_retry': False, 'cleanup_or_overwrite_performed': False,
            'phone_calls': 0, 'p4_calls': 0, 'case_runs': 0, 'runtime_freezes': 0, 'plan_preparations': 0}
        try:
            put(AUDIT / 'FAILED-OR-UNKNOWN.json', encoded(failure))
        except BaseException:
            pass
        raise
    finally:
        for fd, _ in DIRS.values():
            os.close(fd)


if __name__ == '__main__':
    raise SystemExit(main())
