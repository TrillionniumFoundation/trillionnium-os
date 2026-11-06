#!/usr/bin/env python3
"""P4 host files only: prepare one request or retain its original actor files.

This source cannot call adb, a socket, an HTTP endpoint, or the actor. Preparation
creates only the exact already reviewed request; observation only reads files.
The caller separately dispatches the original actor with the derived request.
"""
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time
import zlib

FROZEN_SPEC = None
P4 = '/home/alex/razr60-local-model-v150'
ACTOR_PIN = {'bytes': 5652, 'sha256': '179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'}
META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False,
                       separators=(',', ':'), allow_nan=False) + '\n').encode()


def strict(raw):
    def pairs(rows):
        value = {}
        for key, child in rows:
            need(key not in value, 'duplicate JSON key')
            value[key] = child
        return value
    need(type(raw) is bytes and len(raw) <= 131072, 'bounded whole host observation specification')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite JSON'))


def path(value):
    need(type(value) is str and value and not any(c in value for c in '\0\r\n\t'), 'plain private P4 pathname')
    p = PurePosixPath(value)
    need(p.is_absolute() and str(p) == value and '..' not in p.parts
         and PurePosixPath(P4) in p.parents, 'exact established P4 namespace')
    return p


def validate_spec(value):
    need(type(value) is dict and set(value) == {'schema', 'phase', 'mode', 'actor', 'request_path',
         'request_base64', 'request_pin', 'actor_operation_dir'}
         and value['schema'] == 'hepta.fc33.p4-install-phase-file-observation.v1'
         and value['phase'] in ('stage', 'start', 'ready')
         and value['mode'] in ('prepare', 'collect'), 'closed host-only observation specification')
    actor = value['actor']
    need(type(actor) is dict and set(actor) == {'path', 'bytes', 'sha256'}
         and type(actor['bytes']) is int and {k: actor[k] for k in ('bytes', 'sha256')} == ACTOR_PIN,
         'exact original P4 actor source pin')
    path(actor['path']); path(value['request_path'])
    root = path(value['actor_operation_dir'])
    need(root.parent == PurePosixPath(P4) / 'operations'
         and re.fullmatch('[A-Za-z0-9_-]{1,100}', root.name), 'one selected actor operation directory')
    raw = base64.b64decode(value['request_base64'], validate=True)
    need(type(value['request_pin']) is dict and set(value['request_pin']) == {'bytes', 'sha256'}
         and type(value['request_pin']['bytes']) is int and type(value['request_pin']['sha256']) is str
         and base64.b64encode(raw).decode() == value['request_base64']
         and len(raw) <= 65536 and pin(raw) == value['request_pin'], 'complete exact original request bytes')
    request = strict(raw)
    need(type(request) is dict and set(request) == {'kind', 'root', 'timeout_seconds', 'command'}
         and request['kind'] == 'shell' and request['root'] is True
         and type(request['timeout_seconds']) is int and 1 <= request['timeout_seconds'] <= 300
         and type(request['command']) is str, 'original finite request body, never executed here')
    return raw


def metadata(info):
    return [getattr(info, key) for key in META]


def read_file(name, maximum):
    p = Path(name)
    path(name)
    need(p.resolve(strict=True) == p, 'canonical P4 original without symlink ancestors')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and type(maximum) is int and 0 <= before.st_size <= maximum, 'bounded single-link P4 original')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
            need(stream.read(1) == b'', 'complete P4 original EOF')
        need(len(raw) == before.st_size and metadata(before) == metadata(os.fstat(fd))
             == metadata(p.lstat()), 'complete P4 file full9 bookends')
        return raw, dict(path=name, metadata=metadata(before), **pin(raw))
    finally:
        os.close(fd)


def create_request(name, raw):
    """One create-only regular file under a held existing private parent."""
    p = Path(name); path(name)
    need(p.parent.resolve(strict=True) == p.parent, 'canonical original request parent')
    parent = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        first = os.fstat(parent)
        need(stat.S_ISDIR(first.st_mode) and stat.S_IMODE(first.st_mode) & 0o022 == 0,
             'original request parent is not group/other writable')
        identity = metadata(first)[:5]
        fd = os.open(p.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            created = metadata(os.fstat(stream.fileno()))
        need(created == metadata(os.stat(p.name, dir_fd=parent, follow_symlinks=False)),
             'same freshly created request inode')
        need(metadata(os.fstat(parent))[:5] == metadata(p.parent.lstat())[:5] == identity,
             'same held original request parent')
        observed, row = read_file(name, 65536)
        need(observed == raw and row['metadata'] == created
             and stat.S_IMODE(created[2]) == 0o600, 'complete newly saved request identity and bytes')
        os.fsync(parent)
        return row
    finally:
        os.close(parent)


def run_bound(spec_raw):
    need(FROZEN_SPEC is not None, 'UNBOUND_P4_PHASE_FILE_OBSERVATION_NO_IO')
    need(type(FROZEN_SPEC) is dict and set(FROZEN_SPEC) == {'path', 'bytes', 'sha256'}
         and type(FROZEN_SPEC['bytes']) is int and type(spec_raw) is bytes
         and pin(spec_raw) == {k: FROZEN_SPEC[k] for k in ('bytes', 'sha256')},
         'exact separately bound complete observation specification')
    value = strict(spec_raw); request_raw = validate_spec(value)
    started = time.time_ns(); files = []
    def save(role, name, maximum, expected=None):
        raw, row = read_file(name, maximum)
        if expected is not None:
            need(pin(raw) == expected, 'exact original ' + role + ' source/bytes')
        files.append(dict(role=role, original=row, raw_base64=base64.b64encode(raw).decode(), eof=True))
        return raw, row
    save('actor', value['actor']['path'], 65536, ACTOR_PIN)
    if value['mode'] == 'prepare':
        create_request(value['request_path'], request_raw)
    save('request', value['request_path'], 65536, value['request_pin'])
    if value['mode'] == 'collect':
        for role, maximum in (('intent', 131072), ('baseline', 131072), ('result', 4 * 1024 * 1024)):
            save(role, value['actor_operation_dir'] + '/' + role + '.json', maximum)
    for item in files:
        body, row = read_file(item['original']['path'], item['original']['bytes'])
        need(row == item['original'] and base64.b64encode(body).decode() == item['raw_base64'],
             'all original P4 file bodies and full9 unchanged before return')
    report = dict(schema='hepta.fc33.p4-install-phase-original-files.v1', phase=value['phase'], mode=value['mode'],
        specification=FROZEN_SPEC, started_unix_ns=started, finished_unix_ns=time.time_ns(), files=files,
        phone_calls=0, actor_executed=False, source_full9_bookended=True,
        request_created_here=value['mode'] == 'prepare', qualified=False)
    raw = encoded(report)
    print(json.dumps(dict(schema='hepta.fc33.p4-install-phase-original-transfer.v1',
        original=pin(raw), raw_zlib_base64=base64.b64encode(zlib.compress(raw, 9)).decode(),
        phone_calls=0, actor_executed=False), sort_keys=True))


if __name__ == '__main__':
    raise SystemExit('UNBOUND_P4_PHASE_FILE_OBSERVATION_API_ONLY_NO_IO')
