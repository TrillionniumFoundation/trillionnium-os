#!/usr/bin/env python3
"""Independent read-only complete-byte and full9 observation of fixed sources."""
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time

SOURCE = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/'
              'stock16-hepta-local-model-Root-v150-r1/'
              'epoch-policy-history-audit-source-1ad3-02-dirguard-4b572de398a74ce0')
EXPECTED = {
    'SOURCE-MANIFEST.json': (608, 'd23837daefb96368544889a4a4c1a87fd4cada74c3edb7b092ea74f6cc75b57f'),
    'audit_policy_history_once.py': (30525, '4cc7bdf1aac2325518724a973c74b89f5788ccb84932b82beacac4b2aad78b86'),
    'run_policy_history_owned_once.py': (54516, '9f5c8555c781bde2950bd44b7659225ebc6889027f6bc26c64a72c9d9b25235c')}

def need(value, message):
    if not value:
        raise ValueError(message)

def meta(value):
    return [getattr(value, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
        'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')]

def timeout(signum, frame):
    raise TimeoutError('independent source readback exceeded 10 seconds')

def main():
    started = time.monotonic_ns()
    result = {'schema': 'hepta.fixed-audit02-independent-source-readback.v1',
        'source_root': str(SOURCE), 'state': 'FAILED', 'source_bodies': [],
        'metadata_fields': ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns', 'ctime_ns'],
        'no_sources_executed': True, 'namespace_writes': 0, 'phone_calls': 0,
        'subprocesses': 0, 'case_credit': 0, 'automatic_retry': False,
        'started_utc_epoch_ns': time.time_ns(), 'physical_read_bytes': 0}
    fds = []
    leaves = []
    parents = []
    before = []
    close_errors = []
    signal.signal(signal.SIGALRM, timeout)
    signal.setitimer(signal.ITIMER_REAL, 10)
    try:
        need(sys.platform == 'darwin' and os.geteuid() == 501, 'fixed Mac owner required')
        need(SOURCE.is_absolute() and len(SOURCE.parts) <= 24 and '..' not in SOURCE.parts, 'fixed source path required')
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open('/', flags)
        fds.append(fd)
        parents.append(('/', fd, None, None))
        at = Path('/')
        for name in SOURCE.parts[1:]:
            parent_fd = fd
            at = at/name
            fd = os.open(name, flags, dir_fd=parent_fd)
            fds.append(fd)
            parents.append((str(at), fd, parent_fd, name))
        for path, held, parent, name in parents:
            actual = os.fstat(held)
            named = os.stat(name if parent is not None else '/', dir_fd=parent, follow_symlinks=False)
            need(stat.S_ISDIR(actual.st_mode) and meta(actual) == meta(named), 'held/named parent differs')
            before.append({'path': path, 'full9': meta(actual)})
        source_fd = parents[-1][1]
        source_stat = os.fstat(source_fd)
        need(source_stat.st_uid == 501 and stat.S_IMODE(source_stat.st_mode) == 0o700, 'fixed owned source directory required')
        names = []
        with os.scandir(source_fd) as entries:
            for entry in entries:
                need(len(names) < 3, 'unexpected fourth source member')
                names.append(entry.name)
        result['members_before'] = sorted(names)
        need(sorted(names) == sorted(EXPECTED), 'closed three-source member set required')
        for name, (size, digest) in sorted(EXPECTED.items()):
            leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=source_fd)
            fds.append(leaf)
            initial = os.fstat(leaf)
            named = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            need(stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1 and initial.st_uid == 501
                 and stat.S_IMODE(initial.st_mode) == 0o600 and initial.st_size == size
                 and meta(initial) == meta(named), 'fixed regular single-link source required')
            leaves.append((name, leaf, meta(initial)))
            body = bytearray()
            while len(body) <= size:
                chunk = os.read(leaf, min(16384, size + 1 - len(body)))
                result['physical_read_bytes'] += len(chunk)
                need(result['physical_read_bytes'] <= 85652, 'fixed read byte ceiling exceeded')
                if not chunk:
                    break
                body.extend(chunk)
            raw = bytes(body)
            need(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest, 'complete source body or SHA differs')
            need(meta(os.fstat(leaf)) == meta(initial)
                 == meta(os.stat(name, dir_fd=source_fd, follow_symlinks=False)), 'source full9 changed during read')
            result['source_bodies'].append({'name': name, 'bytes': len(raw), 'sha256': digest,
                'full9': meta(initial), 'body_base64': base64.b64encode(raw).decode('ascii')})
        names_after = []
        with os.scandir(source_fd) as entries:
            for entry in entries:
                need(len(names_after) < 3, 'unexpected fourth source member after read')
                names_after.append(entry.name)
        result['members_after'] = sorted(names_after)
        need(sorted(names_after) == sorted(names), 'source member set changed')
        for name, leaf, initial_full9 in leaves:
            need(meta(os.fstat(leaf)) == initial_full9
                 == meta(os.stat(name, dir_fd=source_fd, follow_symlinks=False)),
                 'source full9 changed after reading the other source members')
        after = []
        for path, held, parent, name in parents:
            actual = meta(os.fstat(held))
            named = meta(os.stat(name if parent is not None else '/', dir_fd=parent, follow_symlinks=False))
            need(actual == named, 'parent held/named differs after read')
            after.append({'path': path, 'full9': actual})
        result['parent_chain_before'] = before
        result['parent_chain_after'] = after
        need(before == after, 'parent full9 bookends differ')
        result['state'] = 'VERIFIED_COMPLETE_SOURCE_BYTES_AND_FULL9'
    except BaseException as error:
        result['error'] = {'type': type(error).__name__, 'message': str(error)[:1024]}
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for fd in reversed(fds):
            try:
                os.close(fd)
            except BaseException as error:
                close_errors.append({'fd': fd, 'type': type(error).__name__, 'message': str(error)[:256]})
        result['close_errors'] = close_errors
        if close_errors:
            result['state'] = 'FAILED_CLOSE_ERRORS'
        result['ended_utc_epoch_ns'] = time.time_ns()
        result['duration_ns'] = time.monotonic_ns() - started
    encoded = (json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode('ascii')
    need(len(encoded) <= 196608, 'complete observation output exceeds bound')
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    return 0 if result['state'] == 'VERIFIED_COMPLETE_SOURCE_BYTES_AND_FULL9' else 1

if __name__ == '__main__':
    raise SystemExit(main())
