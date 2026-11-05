#!/usr/bin/env python3
"""Read only one ended Root prefix; create a separate, non-atomic evidence copy."""
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import time

B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
R = B / 'root-fixed19-1ad3-20261105-r1'
SOURCE = B / 'native-guard-root-chains-r10-r1/root-r10-neg01-1ad3-02'
OUT = R / 'neg01-1ad3-02-root-evidence01'
LABEL = 'root-r10-neg01-1ad3-02'
NONCE = 'bc0573ad459cecae9884d6a46568621b'
FAILURE_PIN = (6664, 'e057408165ccca775f8fcc196dc7fdc69fe0aaba72b18f1da0cf5e0f4c8ae471')
PLAN_PIN = (4772, 'e3b9d77a317f6c7ac7ea6bae9a3276c9f8a689563084a54d82d7417e2a17a3e7')
PHONE_STDOUT_PIN = (3130, '049f43bb4c3a700b95ffd2de37a346499c2b0a6bb87822f9d9b27d9c22c9c15c')
PHASES = ('prepare-material', 'host-stage-material', 'phone-push-material',
          'phone-copy-material', 'phone-push-stage-source', 'phone-copy-stage-source', 'phone-stage')
META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns')
MAX_FILES = 2048
MAX_DIRECTORIES = 512
MAX_BYTES = 64 * 1024 * 1024
MAX_SECONDS = 100


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + '\n').encode('utf-8')


def strict(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))


def metadata(value):
    return [getattr(value, key) for key in META]


def descriptor(path, raw):
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def relative(value):
    need(type(value) is str and '\0' not in value, 'plain relative path required')
    path = PurePosixPath(value)
    need(value and not path.is_absolute() and str(path) == value
         and all(p not in ('', '.', '..') for p in path.parts), 'canonical relative path required')
    return path


def check_time(started):
    # Cooperative only: filesystem/compression syscalls are not preempted.
    need(time.monotonic() - started < MAX_SECONDS, 'collector observation budget exhausted')


def open_directory(path, parent=None, leaf=None):
    need(path.is_absolute() and path.resolve(strict=True) == path, 'canonical directory required')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path if parent is None else leaf, flags, dir_fd=parent)
    try:
        value = os.fstat(fd)
        need(stat.S_ISDIR(value.st_mode) and metadata(value) == metadata(path.lstat()),
             'directory path/held identity differs')
        return fd, metadata(value)
    except BaseException:
        os.close(fd)
        raise


def check_directory(path, fd, expected, full=True):
    need(path.resolve(strict=True) == path, 'held directory path became noncanonical')
    held, named = metadata(os.fstat(fd)), metadata(path.lstat())
    need(held == named, 'held directory path identity differs')
    need(held == expected if full else held[:5] == expected[:5], 'directory changed across observation')


def read_file(path, parent_fd, leaf, expected=None):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(leaf, flags, dir_fd=parent_fd)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= MAX_BYTES, 'bounded single-link original file required')
        if expected is not None:
            need(metadata(before) == expected, 'original file identity changed before re-read')
        chunks = []
        total = 0
        while total <= before.st_size:
            part = os.read(fd, min(65536, before.st_size + 1 - total))
            if not part:
                break
            chunks.append(part)
            total += len(part)
        raw = b''.join(chunks)
        need(len(raw) == before.st_size and metadata(before) == metadata(os.fstat(fd))
             == metadata(os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False))
             == metadata(path.lstat()), 'original file bytes/identity raced')
        return raw, metadata(before)
    finally:
        os.close(fd)


def collect_tree(started, handles):
    files, directories = {}, {}
    total = 0

    def visit(path, name, parent_fd=None, leaf=None):
        nonlocal total
        check_time(started)
        need(len(handles) < MAX_DIRECTORIES, 'directory count budget exceeded')
        fd, first = open_directory(path, parent_fd, leaf)
        handles[name] = (path, fd, first)
        names = sorted(os.listdir(fd))
        need(len(names) <= MAX_FILES + MAX_DIRECTORIES, 'directory child count exceeded')
        directories[name] = {'path': str(path), 'relative_path': name,
                             'metadata': first, 'names': names}
        for child in names:
            need(child not in ('', '.', '..') and '/' not in child and '\0' not in child,
                 'single direct child name required')
            child_name = child if not name else name + '/' + child
            relative(child_name)
            info = os.stat(child, dir_fd=fd, follow_symlinks=False)
            child_path = path / child
            if stat.S_ISDIR(info.st_mode):
                visit(child_path, child_name, fd, child)
            else:
                need(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                     'special file or symlink in original case tree')
                need(len(files) < MAX_FILES, 'original file count budget exceeded')
                raw, original_metadata = read_file(child_path, fd, child, metadata(info))
                total += len(raw)
                need(total <= MAX_BYTES, 'complete original byte budget exceeded')
                files[child_name] = {'raw': raw, 'metadata': original_metadata,
                                    'parent': name, 'leaf': child,
                                    'descriptor': descriptor(child_path, raw)}
            check_time(started)
        need(sorted(os.listdir(fd)) == names, 'directory child set changed during scan')
        check_directory(path, fd, first)

    visit(SOURCE, '')
    return files, directories


def recheck_tree(files, directories, handles, started):
    check_time(started)
    for name, row in sorted(files.items()):
        path = SOURCE.joinpath(*relative(name).parts)
        parent_path, parent_fd, parent_metadata = handles[row['parent']]
        check_directory(parent_path, parent_fd, parent_metadata)
        raw, current_metadata = read_file(path, parent_fd, row['leaf'], row['metadata'])
        need(raw == row['raw'] and current_metadata == row['metadata'],
             'original file changed across full-tree bookend')
        check_time(started)
    for name, row in directories.items():
        path, fd, first = handles[name]
        check_directory(path, fd, first)
        need(sorted(os.listdir(fd)) == row['names'], 'complete original child set changed')
    return {'checked_file_count': len(files), 'checked_directory_count': len(directories),
            'completed_unix_ns': time.time_ns(), 'completed_monotonic_ns': time.monotonic_ns()}


def verify_ended_failure(files):
    def raw(name):
        need(name in files, 'required original absent: ' + name)
        return files[name]['raw']
    def value(name):
        return strict(raw(name))
    def fixed(name, expected):
        body = raw(name)
        need((len(body), sha(body)) == expected, 'fixed case original differs: ' + name)
        return strict(body)
    failure = fixed('ROOT-FAILURE.json', FAILURE_PIN)
    plan = fixed('ROOT-PLAN.original.json', PLAN_PIN)
    need(plan['label'] == LABEL and plan['nonce'] == NONCE and plan['case_id'] == 'NEG-01'
         and plan['out'] == str(SOURCE), 'fixed case identity differs')
    need(failure['state'] == 'FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED_NO_AUTOMATIC_CONTINUATION'
         and failure['host_cleanup'] == {'host_children': [], 'stream_cleanup_errors': []}
         and failure['root_fixture_attempts'] == [] and failure['signals_sent_by_coordinator'] == 0
         and failure['send_again'] is False and failure['automatic_retry'] is False,
         'retained failure ownership state differs')
    need([r['phase'] for r in failure['steps']] == list(PHASES), 'exact seven ended host phases required')
    phase_proofs = []
    for step in failure['steps']:
        name = step['phase']
        result = value(name + '/RESULT.json')
        intent_raw = raw(name + '/INTENT.json')
        intent = strict(intent_raw)
        child = value(name + '/CHILD.json')
        capture = value(name + '/OUTPUT-CAPTURE.json')
        need(result == step and set(result) == {'state', 'phase', 'pid', 'returncode',
             'stdout', 'stderr', 'automatic_retry'} and result['state'] == 'ORIGINAL_HOST_CHILD_JOINED'
             and result['returncode'] == 0 and type(result['pid']) is int and result['pid'] > 0
             and result['automatic_retry'] is False, 'actual joined host result differs')
        digest = sha(intent_raw)
        need(intent['phase'] == name and intent['maximum_starts'] == 1
             and intent['automatic_retry'] is False and intent['signals_on_timeout'] is False
             and child['source_intent_sha256'] == capture['source_intent_sha256'] == digest
             and child['pid'] == capture['pid'] == result['pid'], 'host intent/child/capture binding differs')
        need(capture['schema'] == 'hepta.native-guard.host-output-capture.v1'
             and capture['phase'] == name and capture['worker_started'] is True
             and capture['worker_joined'] is True and capture['child_wait_returned'] is True
             and capture['child_returncode'] == 0 and capture['stdout_eof'] is True
             and capture['stderr_eof'] is True and capture['prefix_only_or_unknown'] is False
             and capture['pipe_reader_owner'] == 'closed_by_worker' and capture['error'] is None
             and capture['persist_errors'] == [] and capture['pipe_close_errors'] == [],
             'complete original joined capture required')
        for stream in ('stdout', 'stderr'):
            key = name + '/' + stream + '.original'
            body = raw(key)
            exact = descriptor(SOURCE / key, body)
            held = capture['files'][stream]
            need(result[stream] == exact and {k: held[k] for k in exact} == exact
                 and held['original_created_inode_bound'] is True
                 and [held['metadata'][k] for k in META] == files[key]['metadata']
                 and capture['captured'][stream] == {'bytes': len(body), 'sha256': sha(body)},
                 'original capture output bytes/full9 identity differs')
        if intent['stdin_sha256'] is not None:
            need(sha(raw(name + '/stdin.original')) == intent['stdin_sha256'], 'retained stdin differs')
        phase_proofs.append({'phase': name, 'pid': result['pid'], 'returncode': 0,
            'result': files[name + '/RESULT.json']['descriptor'],
            'capture': files[name + '/OUTPUT-CAPTURE.json']['descriptor'],
            'original_host_child_joined': True, 'both_original_output_eofs': True})
    wrapped = fixed('phone-stage/stdout.original', PHONE_STDOUT_PIN)
    need(wrapped['actor_rc'] == 0 and wrapped['wrapper']['phone']['rc'] == 1
         and wrapped['wrapper']['label'] == 'ng-' + NONCE + '-stage'
         and 'current complete cumulative originals differ; no new component admission'
             in wrapped['wrapper']['phone']['stderr'], 'actual phone-stage refusal differs')
    forbidden = ('sender-preview/', 'sender-execute/', 'sender-prepared/', 'phone-launch/', 'ROOT-FIXTURE-')
    need('ROOT-RESULT.json' not in files and not any(n.startswith(forbidden) for n in files),
         'later coordinator phase appears in this retained failed prefix')
    return phase_proofs


def put_new(directory_fd, path, raw):
    need(type(raw) is bytes and len(raw) <= MAX_BYTES + 4 * 1024 * 1024, 'bounded new evidence output required')
    fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=directory_fd)
    try:
        first = os.fstat(fd)
        need(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and first.st_size == 0
             and first.st_uid == os.geteuid() and stat.S_IMODE(first.st_mode) == 0o600,
             'new private regular evidence inode required')
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:offset + 65536])
            need(count > 0, 'new evidence short write')
            offset += count
        os.fsync(fd)
        final = metadata(os.fstat(fd))
        need(final[:5] == metadata(first)[:5] and final == metadata(path.lstat()),
             'created evidence inode replaced')
        os.lseek(fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        count = 0
        while count <= len(raw):
            block = os.read(fd, min(65536, len(raw) + 1 - count))
            if not block:
                break
            digest.update(block)
            count += len(block)
        need(count == len(raw) and digest.hexdigest() == sha(raw)
             and final == metadata(os.fstat(fd)) == metadata(path.lstat()),
             'new evidence readback differs')
        os.fsync(directory_fd)
        return {**descriptor(path, raw), 'metadata': final}
    finally:
        os.close(fd)


def main():
    started = time.monotonic()
    start_unix_ns = time.time_ns()
    handles = {}
    parent_fd = out_fd = None
    out_identity = None
    try:
        need(type(COLLECTOR_SOURCE) is bytes and len(COLLECTOR_SOURCE) <= 65536,
             'exact controller-retained collector source required')
        files, directories = collect_tree(started, handles)
        proofs = verify_ended_failure(files)
        before_write = recheck_tree(files, directories, handles, started)
        # The archive is a byte copy of this one case tree. No code inside it is run.
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, row in sorted(files.items()):
                member = tarfile.TarInfo('root-originals/' + str(relative(name)))
                member.size = len(row['raw'])
                member.mode = 0o600
                member.uid = member.gid = 0
                member.mtime = 0
                archive.addfile(member, io.BytesIO(row['raw']))
        tar_raw = buffer.getvalue()
        need(len(tar_raw) <= MAX_BYTES + 4 * 1024 * 1024, 'archive framing budget exceeded')
        packed = lzma.compress(tar_raw, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64, preset=6)
        need(lzma.decompress(packed) == tar_raw, 'lossless original archive mirror differs')
        check_time(started)
        parent_fd, parent_identity = open_directory(R)
        need(not os.path.lexists(OUT), 'new independent evidence directory required; no retry or overwrite')
        os.mkdir(OUT.name, mode=0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
        out_fd, out_identity = open_directory(OUT, parent_fd, OUT.name)
        need(out_identity[3] == os.geteuid() and stat.S_IMODE(out_identity[2]) == 0o700,
             'new private evidence directory required')
        collector_row = put_new(out_fd, OUT / 'COLLECTOR.original.py', COLLECTOR_SOURCE)
        archive_row = put_new(out_fd, OUT / 'ROOT-ORIGINALS.tar.xz', packed)
        manifest = {
            'schema': 'hepta.root.failed-case-originals-manifest.v1',
            'state': 'EXACT_ENDED_FAILED_PREFIX_READ_ONLY_BYTE_COPY',
            'source_root': str(SOURCE), 'label': LABEL, 'nonce': NONCE,
            'started_unix_ns': start_unix_ns, 'first_full_recheck': before_write,
            'files': [{**row['descriptor'], 'relative_path': name, 'metadata': row['metadata']}
                      for name, row in sorted(files.items())],
            'directories': [row for _, row in sorted(directories.items())],
            'source_files': len(files), 'source_directories': len(directories),
            'source_file_bytes': sum(len(row['raw']) for row in files.values()),
            'archive': archive_row, 'tar_plaintext': {'bytes': len(tar_raw), 'sha256': sha(tar_raw)},
            'archive_regular_members': len(files), 'collector_source': collector_row,
            'original_host_phase_receipts': proofs,
            'same_instant_as_failure': False, 'atomic_filesystem_snapshot': False,
            'observation_scope': 'Later complete file/dir read with full9/contents/child-set bookends',
            'originals_modified': False, 'phone_calls': 0, 'p4_calls': 0,
            'subprocesses': 0, 'signals_sent': 0, 'case_pass': False,
        }
        manifest_row = put_new(out_fd, OUT / 'ORIGINALS-MANIFEST.json', enc(manifest))
        after_copy = recheck_tree(files, directories, handles, started)
        check_directory(R, parent_fd, parent_identity, full=False)
        check_directory(OUT, out_fd, out_identity, full=False)
        result = {'schema': 'hepta.root.failed-case-originals-collection.v1',
            'state': 'FAILED_CASE_ORIGINALS_ARCHIVED_WITH_FULL9_BOOKENDS',
            'label': LABEL, 'nonce': NONCE, 'source_root': str(SOURCE), 'out': str(OUT),
            'root_failure': {'path': str(SOURCE / 'ROOT-FAILURE.json'),
                'bytes': FAILURE_PIN[0], 'sha256': FAILURE_PIN[1]},
            'root_plan': {'path': str(SOURCE / 'ROOT-PLAN.original.json'),
                'bytes': PLAN_PIN[0], 'sha256': PLAN_PIN[1]},
            'archive': archive_row, 'manifest': manifest_row, 'collector_source': collector_row,
            'source_files': len(files), 'source_directories': len(directories),
            'source_file_bytes': manifest['source_file_bytes'], 'after_copy_full_recheck': after_copy,
            'joined_host_phase_count': len(proofs), 'original_host_outputs_complete': True,
            'same_instant_as_failure': False, 'atomic_filesystem_snapshot': False,
            'originals_modified': False, 'phone_calls': 0, 'p4_calls': 0,
            'subprocesses': 0, 'signals_sent': 0, 'case_pass': False, 'automatic_retry': False,
            'filesystem_or_compression_hard_deadline': False}
        result_row = put_new(out_fd, OUT / 'RESULT.json', enc(result))
        final_check = recheck_tree(files, directories, handles, started)
        check_directory(R, parent_fd, parent_identity, full=False)
        check_directory(OUT, out_fd, out_identity, full=False)
        need(sorted(os.listdir(out_fd)) == ['COLLECTOR.original.py', 'ORIGINALS-MANIFEST.json',
            'RESULT.json', 'ROOT-ORIGINALS.tar.xz'], 'new evidence output inventory differs')
        print(enc({'state': result['state'], 'result': result_row, 'archive': archive_row,
            'manifest': manifest_row, 'source_files': len(files),
            'source_file_bytes': manifest['source_file_bytes'], 'last_full_recheck': final_check,
            'case_pass': False, 'phone_calls': 0, 'p4_calls': 0,
            'same_instant_as_failure': False, 'atomic_filesystem_snapshot': False}).decode(), end='')
        return 0
    except BaseException as error:
        if out_fd is not None:
            try:
                put_new(out_fd, OUT / 'FAILED-OR-UNKNOWN.json', enc({
                    'state': 'EVIDENCE_COLLECTION_FAILED_OR_UNKNOWN_RETAIN_EXISTING_OUTPUTS',
                    'error_type': type(error).__name__, 'detail': str(error)[:2000],
                    'source_root': str(SOURCE), 'out': str(OUT), 'case_pass': False,
                    'automatic_retry': False, 'originals_modified': False,
                    'phone_calls': 0, 'p4_calls': 0, 'signals_sent': 0}))
            except BaseException:
                pass
        raise
    finally:
        if out_fd is not None:
            os.close(out_fd)
        if parent_fd is not None:
            os.close(parent_fd)
        for _, fd, _ in handles.values():
            os.close(fd)


if __name__ == '__main__':
    raise SystemExit(main())
