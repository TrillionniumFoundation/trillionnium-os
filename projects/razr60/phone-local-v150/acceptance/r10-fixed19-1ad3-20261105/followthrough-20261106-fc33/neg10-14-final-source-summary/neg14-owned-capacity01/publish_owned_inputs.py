#!/usr/bin/env python3
"""Create-only publication of this one reviewed host control source tree."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import zlib

ROOT = Path('/home/alex/razr60-local-model-v150/fc33-neg14-capacity-native-v3-01')
def sha(raw): return hashlib.sha256(raw).hexdigest()
def need(value, why):
    if not value: raise ValueError(why)
request = json.load(sys.stdin)
need(set(request) == {'archive_base64', 'archive_sha256', 'decoded_sha256'}, 'closed publication input')
packed = base64.b64decode(request['archive_base64'], validate=True)
need(len(packed) <= 524288 and sha(packed) == request['archive_sha256'], 'bounded exact archive')
d = zlib.decompressobj()
raw = d.decompress(packed, 1048577)
need(d.eof and not d.unused_data and not d.unconsumed_tail and len(raw) <= 1048576
     and sha(raw) == request['decoded_sha256'], 'complete single reviewed archive')
value = json.loads(raw)
need(set(value) == {'files'} and len(value['files']) == 19, 'exact nineteen source originals')
files = {}
for row in value['files']:
    need(set(row) == {'path', 'bytes', 'sha256', 'base64'} and type(row['path']) is str
         and re.fullmatch(r'[A-Za-z0-9_./-]+', row['path'])
         and all(p not in ('', '.', '..') for p in row['path'].split('/')), 'closed source member')
    body = base64.b64decode(row['base64'], validate=True)
    need(len(body) == row['bytes'] and sha(body) == row['sha256'] and row['path'] not in files,
         'complete unique source bytes')
    files[row['path']] = (body, {k: row[k] for k in ('path', 'bytes', 'sha256')})
need(ROOT.parent.resolve(strict=True) == ROOT.parent and not os.path.lexists(ROOT), 'fresh owned source root')
os.umask(0o077)
ROOT.mkdir(mode=0o700)
handles = {}
try:
    handles[''] = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    parents = {''}
    for name in files:
        parts = name.split('/')[:-1]
        for i in range(1, len(parts) + 1): parents.add('/'.join(parts[:i]))
    for name in sorted(parents - {''}, key=lambda n: (n.count('/'), n)):
        parent, unused, leaf = name.rpartition('/')
        os.mkdir(leaf, 0o700, dir_fd=handles[parent])
        handles[name] = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=handles[parent])
    for name, (body, row) in sorted(files.items()):
        parent, unused, leaf = name.rpartition('/')
        fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=handles[parent])
        with os.fdopen(fd, 'wb') as handle:
            handle.write(body); handle.flush(); os.fsync(handle.fileno())
        need((ROOT / name).read_bytes() == body, 'published source complete byte readback')
    for name, fd in handles.items():
        expected = {p.split('/')[len(name.split('/')) if name else 0] for p in files
                    if not name or p.startswith(name + '/')}
        need(set(os.listdir(fd)) == expected, 'closed complete source directory membership')
        need(os.fstat(fd).st_ino == (ROOT / name).stat().st_ino, 'held source directory identity')
        os.fsync(fd)
    result = {'schema': 'fc33.neg14.owned-host-source-publication.v1',
              'root': str(ROOT), 'files': [v[1] for k, v in sorted(files.items())],
              'complete_byte_readback': True, 'host_test_executed': False,
              'phone_calls': 0, 'model_requests': 0, 'production_changes': 0}
    result_raw = (json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open('PUBLICATION.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=handles[''])
    with os.fdopen(fd, 'wb') as handle:
        handle.write(result_raw); handle.flush(); os.fsync(handle.fileno())
    os.fsync(handles[''])
    need((ROOT / 'PUBLICATION.json').read_bytes() == result_raw, 'terminal publication readback')
    print(json.dumps({'root': str(ROOT), 'files': len(files), 'publication': {
          'path': str(ROOT / 'PUBLICATION.json'), 'bytes': len(result_raw), 'sha256': sha(result_raw)},
          'phone_calls': 0, 'model_requests': 0}, sort_keys=True))
finally:
    for fd in reversed(list(handles.values())): os.close(fd)
