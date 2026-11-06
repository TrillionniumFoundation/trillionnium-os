"""Read and losslessly transfer the exact 8+21 published host source originals."""
import base64
import hashlib
import json
import os
import stat
import time
import zlib
from pathlib import Path

B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
SPECS = (
    ('binding', B / 'followthrough-fc33-release-source-binding-r5-01',
     ('', 'source', 'reference'), 8,
     {'bytes': 2548, 'sha256': '5699b0817fd6d4de93eafdc5ff9bb444620f0b097a18c3fcd6a7c2d9f2f1710c'}),
    ('derived', B / 'followthrough-fc33-release-source-chain-r5-derived01',
     ('', 'source', 'contracts', 'preview-module'), 21,
     {'bytes': 44922, 'sha256': '09ea015625df33e992160a2b58569079586a2b501087a6c23e51e3f869b1ca37'}),
)
META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns')
ALL = []

def need(value, why):
    if not value:
        raise ValueError(why)

def meta(value):
    return {key: getattr(value, key) for key in META}

def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

def strict(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))

def read_group(tag, root, layouts, count, terminal_pin):
    need(root.resolve(strict=True) == root, 'canonical exact published source namespace')
    handles, directories, files = {}, {}, {}
    context = {'tag': tag, 'root': root, 'handles': handles, 'directories': directories, 'files': files}
    ALL.append(context)
    for rel in layouts:
        if rel == '':
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        else:
            fd = os.open(rel, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=handles[''])
        handles[rel] = fd
        info = os.fstat(fd)
        need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
             and meta(info) == meta((root / rel).lstat()), 'exact private published directory full9')
        directories[rel] = {'path': str(root / rel), 'metadata': meta(info), 'names': sorted(os.listdir(fd))}
    def read_one(name, expected):
        p = Path(name)
        parent = '' if str(p.parent) == '.' else str(p.parent)
        need(not p.is_absolute() and '..' not in p.parts and str(p) == name and parent in handles,
             'one member of the exact published layout')
        need(set(expected) == {'bytes', 'sha256'} and type(expected['bytes']) is int
             and 0 < expected['bytes'] <= 2 * 1024 * 1024, 'typed bounded exact published file')
        fd = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=handles[parent])
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600
                 and before.st_nlink == 1 and before.st_size == expected['bytes'],
                 'exact single-link private published source file')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(expected['bytes'] + 1)
                need(stream.read(1) == b'', 'original complete EOF')
            need(pin(raw) == expected and meta(before) == meta(os.fstat(fd))
                 == meta(os.stat(p.name, dir_fd=handles[parent], follow_symlinks=False)),
                 'complete original pin and nine-field bookend')
            files[name] = {'path': str(root / name), 'relative_path': name, **pin(raw),
                           'metadata': meta(before), 'eof': True, 'text': raw.decode('utf-8')}
            return raw
        finally:
            os.close(fd)
    terminal_raw = read_one('DERIVATION.json', terminal_pin)
    terminal = strict(terminal_raw)
    rows = terminal['files']
    need(type(rows) is list and len(rows) == count - 1 and len({row['path'] for row in rows}) == count - 1,
         'complete exact declared source members')
    expected_names = {'DERIVATION.json'}
    for row in rows:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}, 'published exact three-field descriptor')
        path = Path(row['path'])
        relative = str(path.relative_to(root))
        need(str(root / relative) == row['path'] and relative not in expected_names,
             'each declared source has one exact published path')
        expected_names.add(relative)
        read_one(relative, {key: row[key] for key in ('bytes', 'sha256')})
    need(len(files) == count and sum(row['bytes'] for row in files.values()) <= 4 * 1024 * 1024,
         'complete bounded source group')
    for rel, row in directories.items():
        expected = set()
        if rel == '':
            expected.update(layouts[1:])
        for name in expected_names:
            p = Path(name)
            owner = '' if str(p.parent) == '.' else str(p.parent)
            if owner == rel:
                expected.add(p.name)
        need(sorted(expected) == row['names'], 'no omitted or extra published member')
    return {'tag': tag, 'root': str(root), 'terminal': {'path': str(root / 'DERIVATION.json'), **terminal_pin},
            'file_count': count, 'file_bytes': sum(row['bytes'] for row in files.values()),
            'directories': [dict(relative_path=rel, **row) for rel, row in directories.items()],
            'files': [files[name] for name in sorted(files)]}

def bookend():
    for context in ALL:
        root = context['root']
        for name, row in context['files'].items():
            p = Path(name)
            parent = '' if str(p.parent) == '.' else str(p.parent)
            need(meta(os.stat(p.name, dir_fd=context['handles'][parent], follow_symlinks=False)) == row['metadata'],
                 'published original unchanged before complete return')
        for rel, row in context['directories'].items():
            fd = context['handles'][rel]
            need(meta(os.fstat(fd)) == meta((root / rel).lstat()) == row['metadata']
                 and sorted(os.listdir(fd)) == row['names'], 'complete directory bookend before return')

def main():
    started = time.time_ns()
    try:
        groups = [read_group(*spec) for spec in SPECS]
        bookend()
        result = {
            'schema': 'hepta.fc33.actual-published-source-originals.v1',
            'state': 'COMPLETE_29_PUBLISHED_HOST_SOURCE_ORIGINALS_READ',
            'publication_job_id': '1a1b1ff0f2e-fc05-7bef',
            'started_unix_ns': started, 'finished_unix_ns': time.time_ns(),
            'groups': groups, 'file_count': 29, 'file_bytes': sum(group['file_bytes'] for group in groups),
            'all_original_files_read_to_EOF': True, 'all_directory_and_file_full9_bookended': True,
            'phone_calls': 0, 'project_modules_executed': 0, 'host_file_writes': 0,
            'current_case_qualified': False, 'actual_BUILD': None, 'actual_install': None, 'actual_READY': None,
        }
        raw = (json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
    finally:
        errors = []
        for context in reversed(ALL):
            for fd in reversed(list(context['handles'].values())):
                try:
                    os.close(fd)
                except BaseException as error:
                    errors.append(error)
        if errors:
            raise errors[0]
    print(json.dumps({'schema': 'hepta.fc33.published-source-original-transfer.v1',
        'uncompressed': pin(raw), 'compression': 'zlib',
        'raw_zlib_base64': base64.b64encode(zlib.compress(raw, 9)).decode(),
        'all_observation_fds_closed': True, 'phone_calls': 0}, sort_keys=True))

if __name__ == '__main__':
    main()
