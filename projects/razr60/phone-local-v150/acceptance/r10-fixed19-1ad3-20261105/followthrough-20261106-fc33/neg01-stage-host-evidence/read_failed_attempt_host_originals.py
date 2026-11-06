"""Read only the exact failed fc33 attempt's host artifacts; never touch phone.

All file bodies are withheld except named public phase records. In particular,
stdin.original, preserved_draft, archives and material members only yield
outer path/bytes/SHA256/full9 descriptors. No project module is imported.
"""
import errno
import hashlib
import json
import os
import stat
import sys
import time
from pathlib import Path

B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
LABEL = 'root-r10-neg01-fc33-bound01'
NONCE = 'e2fdaccd43cec9da1df4d77783db8fdb'
ROOTOUT = B / 'native-guard-root-chains-r10-r1' / LABEL
FROZEN = B / 'native-guard-r10-r1-operator-fc33-native-v3-r5'
P4_CHAIN = Path('/home/alex/codex-native-guard-chain-r10-r1') / NONCE
P4_SENDER = Path('/home/alex/codex-hepta-natural-' + LABEL + '-root-v150')
META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns')
PUBLIC_PHASE_MEMBERS = {'INTENT.json', 'RESULT.json', 'JOINED.json', 'stdout.original', 'stderr.original'}
PUBLIC_ROOT_MEMBERS = {'ROOT-FAILURE.json', 'CHAIN-INTENT.json'}
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_ENTRIES = 2048
MAX_PUBLIC = 1024 * 1024
TOTAL = 0
ENTRY_COUNT = 0
PUBLIC_TOTAL = 0

def need(value, why):
    if not value:
        raise ValueError(why)

def metadata(value):
    return {key: getattr(value, key) for key in META}

def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

def exact_file(path, *, public=False):
    global TOTAL, ENTRY_COUNT, PUBLIC_TOTAL
    need(path.is_absolute() and path.resolve(strict=True) == path, 'canonical regular original path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= MAX_FILE, 'bounded single-link regular original')
        need(TOTAL + before.st_size <= MAX_TOTAL and ENTRY_COUNT < MAX_ENTRIES, 'bounded host evidence pool')
        digest, count, chunks = hashlib.sha256(), 0, []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            count += len(chunk)
            need(count <= before.st_size, 'original grew while reading')
            digest.update(chunk)
            if public:
                chunks.append(chunk)
        after = os.fstat(fd)
        need(count == before.st_size and metadata(before) == metadata(after) == metadata(path.lstat()),
             'complete original EOF and full9 bookends')
        need(path.resolve(strict=True) == path, 'original parent identity remains canonical')
        TOTAL += count
        ENTRY_COUNT += 1
        row = {'path': str(path), 'bytes': count, 'sha256': digest.hexdigest(),
               'metadata': metadata(before), 'eof': True, 'full9_bookended': True}
        if public:
            raw = b''.join(chunks)
            PUBLIC_TOTAL += len(raw)
            need(PUBLIC_TOTAL <= MAX_PUBLIC, 'bounded public original output')
            row['text'] = raw.decode('utf-8')
        return row
    finally:
        os.close(fd)

def public_member(relative):
    p = Path(relative)
    if 'stdin.original' in p.parts or any('preserved_draft' in part for part in p.parts):
        return False
    return (len(p.parts) == 1 and p.name in PUBLIC_ROOT_MEMBERS
            or len(p.parts) == 2 and p.name in PUBLIC_PHASE_MEMBERS
            and p.parts[0] not in {'material', 'inputs'})

def read_tree(root):
    directories, files, originals = [], [], []
    def walk(path):
        need(path.resolve(strict=True) == path, 'canonical original directory')
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            names = sorted(os.listdir(fd))
            need(len(directories) + len(files) + len(names) < MAX_ENTRIES, 'bounded complete directory tree')
            for name in names:
                need(name not in ('.', '..') and '/' not in name and '\0' not in name, 'plain child name')
                child = path / name
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    walk(child)
                else:
                    need(stat.S_ISREG(info.st_mode), 'unexpected non-regular host tree member')
                    relative = str(child.relative_to(root))
                    row = exact_file(child, public=public_member(relative))
                    files.append({'relative_path': relative, **{k: v for k, v in row.items() if k != 'text'}})
                    if 'text' in row:
                        originals.append({'relative_path': relative, **row})
            need(names == sorted(os.listdir(fd)) and metadata(before) == metadata(os.fstat(fd))
                 == metadata(path.lstat()), 'complete original directory names and full9 bookends')
            directories.append({'path': str(path), 'relative_path': str(path.relative_to(root)),
                                'names': names, 'metadata': metadata(before), 'full9_bookended': True})
        finally:
            os.close(fd)
    walk(root)
    return {'root': str(root), 'directories': sorted(directories, key=lambda r: r['path']),
            'files': sorted(files, key=lambda r: r['path']),
            'public_originals': sorted(originals, key=lambda r: r['path']),
            'file_count': len(files), 'file_bytes': sum(r['bytes'] for r in files),
            'complete_tree_bookended': True}

def presence(path):
    row = {'path': str(path), 'observed_unix_ns': time.time_ns()}
    try:
        info = path.lstat()
    except OSError as error:
        if error.errno != errno.ENOENT:
            raise
        row.update(state='ENOENT', errno=error.errno)
        # State which existing ancestor was observed; missing ancestors stay
        # explicit instead of implying an independently queried leaf directory.
        ancestor = path.parent
        missing = []
        while True:
            try:
                a = ancestor.lstat()
                break
            except OSError as parent_error:
                if parent_error.errno != errno.ENOENT:
                    raise
                missing.append(str(ancestor))
                ancestor = ancestor.parent
        need(stat.S_ISDIR(a.st_mode) and ancestor.resolve(strict=True) == ancestor,
             'absence under a real canonical host directory')
        row.update(existing_ancestor={'path': str(ancestor), 'metadata': metadata(a)},
                   missing_ancestor_paths=missing)
        return row
    row['metadata'] = metadata(info)
    if stat.S_ISDIR(info.st_mode):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            names = sorted(os.listdir(fd))
            need(metadata(before) == metadata(os.fstat(fd)) == metadata(path.lstat()),
                 'existing exact directory stable during name read')
            row.update(state='DIRECTORY_PRESENT', names=names, metadata=metadata(before))
        finally:
            os.close(fd)
    elif stat.S_ISREG(info.st_mode):
        row.update(state='FILE_PRESENT', descriptor=exact_file(path))
    else:
        row.update(state='NONREGULAR_PRESENT')
    return row

def main():
    need(len(sys.argv) == 2 and sys.argv[1] in ('mac', 'pocket4'), 'one explicit host evidence scope')
    mode = sys.argv[1]
    started = time.time_ns()
    if mode == 'mac':
        tree = read_tree(ROOTOUT)
        paths = [ROOTOUT / name for name in ('sender-preview', 'sender-execute', 'sender-prepared')]
        paths += [B / (LABEL + suffix) for suffix in ('.actor.py', '.local-once.json', '.send-result.json')]
        sources = {}
        for key, relative, expected in [
            ('root', 'root-chain/source/run_component_root_once.py',
             (78566, '2af78597f211b8b7de32d5f40591e46c4ea5ff7caa3c4a2547ac4325666c2032')),
            ('sender', 'runtime/source/send_new_native_guard_task_r10_r4.py',
             (41080, '53a6e9149cf768211c3c8ba74d3c422f95d78f14efdb8751af1ac55d1a9225d5')),
        ]:
            sources[key] = exact_file(FROZEN / relative)
            need((sources[key]['bytes'], sources[key]['sha256']) == expected, 'same actual reviewed control flow source')
        # JOINED is expected only for the later asynchronous sender; synchronous
        # phases use RESULT. Observe both names explicitly for every actual phase.
        phase_names = [r['relative_path'] for r in tree['directories']
                       if r['relative_path'] != '.' and '/' not in r['relative_path']
                       and r['relative_path'] != 'material']
        paths += [ROOTOUT / phase / member for phase in phase_names
                  for member in ('INTENT.json', 'RESULT.json', 'JOINED.json', 'stdout.original', 'stderr.original')]
    else:
        tree, sources = None, {}
        paths = [P4_CHAIN, P4_CHAIN / 'phone-stage', P4_SENDER]
        paths += [P4_SENDER / name for name in (
            'COMPONENT-PREPARED-NO-SEND.json', 'SEND.once.json', 'SEND.MONOTONIC-INTENT.json',
            'SEND.result.json', 'SEND.unknown.json', 'SEND.MONOTONIC-WINDOW.json', 'SEND-NATIVE-LATENCY.json')]
    observed = [presence(path) for path in paths]
    if mode == 'mac':
        for row in tree['files']:
            need(metadata(Path(row['path']).lstat()) == row['metadata'], 'host original changed before audit return')
        for row in tree['directories']:
            need(metadata(Path(row['path']).lstat()) == row['metadata']
                 and sorted(os.listdir(row['path'])) == row['names'], 'host directory changed before audit return')
    print(json.dumps({
        'schema': 'hepta.fc33.failed-neg01-host-original-observation.v1',
        'state': 'COMPLETE_HOST_READ_ONLY_OBSERVATION', 'host': mode,
        'label': LABEL, 'nonce': NONCE, 'started_unix_ns': started, 'finished_unix_ns': time.time_ns(),
        'tree': tree, 'source_originals': sources, 'presence': observed,
        'hashed_file_bytes': TOTAL, 'hashed_file_count': ENTRY_COUNT, 'public_original_bytes': PUBLIC_TOTAL,
        'private_bodies_exported': False, 'phone_calls': 0, 'project_modules_executed': 0,
        'cleanup_actions': 0, 'sender_executions': 0, 'new_qualification': False,
        'scope': 'Exact attempt host originals and current existence only; no claim of global no effects or phone cleanup.',
    }, ensure_ascii=False, sort_keys=True))

if __name__ == '__main__':
    main()
