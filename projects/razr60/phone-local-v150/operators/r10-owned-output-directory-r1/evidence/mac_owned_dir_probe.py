#!/usr/bin/env python3
"""One isolated Mac directory-metadata observation; never run the audit or phone."""
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import stat
import sys
import time

KEY = 'hepta-cp09-owned-dir-probe-acceptanceaudit-01-4b572de398a74ce0'
NAME = 'hepta-cp09-owned-dir-probe-4b572de398a74ce0'
PARENT = Path('/private/tmp')
REFERENCE = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/'
                 'stock16-hepta-local-model-Root-v150-r1')
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')


def full9(value):
    return [getattr(value, key) for key in FIELDS]


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def timeout(_number, _frame):
    raise TimeoutError('single directory probe exceeded 8 seconds')


def main():
    need(sys.platform == 'darwin' and os.geteuid() == 501, 'actual configured Mac uid 501 required')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16384, 16384))
    signal.signal(signal.SIGALRM, timeout)
    signal.setitimer(signal.ITIMER_REAL, 8)
    started = time.monotonic()
    parent_fd = owned_fd = leaf_fd = None
    observed = None
    try:
        reference = REFERENCE.lstat()
        need(stat.S_ISDIR(reference.st_mode), 'reference evidence root is not an ordinary directory')
        parent_fd = os.open(PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        parent = os.fstat(parent_fd)
        need(parent.st_dev == reference.st_dev, 'temporary parent is not on the reference filesystem')
        # An existing name is a hard failure; no deletion, suffix or retry.
        os.mkdir(NAME, 0o700, dir_fd=parent_fd)
        named_initial = os.stat(NAME, dir_fd=parent_fd, follow_symlinks=False)
        need(stat.S_ISDIR(named_initial.st_mode) and named_initial.st_uid == os.geteuid()
             and stat.S_IMODE(named_initial.st_mode) == 0o700, 'new private directory differs')
        owned_fd = os.open(NAME, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=parent_fd)
        before_held = full9(os.fstat(owned_fd))
        before_named = full9(os.stat(NAME, dir_fd=parent_fd, follow_symlinks=False))
        need(before_held == before_named == full9(named_initial) and os.listdir(owned_fd) == [],
             'initial named/held directory binding differs')
        raw = (json.dumps({'schema': 'hepta.synthetic-owned-directory-intent.v1',
                           'probe_key': KEY, 'phone_calls': 0, 'history_audit_calls': 0},
                          sort_keys=True, separators=(',', ':'))+'\n').encode()
        leaf_fd = os.open('INTENT.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                          0o600, dir_fd=owned_fd)
        offset = 0
        while offset < len(raw):
            count = os.write(leaf_fd, raw[offset:])
            need(count > 0, 'probe intent write made no progress')
            offset += count
        os.fsync(leaf_fd)
        leaf_held = full9(os.fstat(leaf_fd))
        leaf_named = full9(os.stat('INTENT.json', dir_fd=owned_fd, follow_symlinks=False))
        need(leaf_held == leaf_named and stat.S_ISREG(leaf_held[2]) and leaf_held[5] == 1
             and leaf_held[6] == len(raw), 'probe intent leaf identity differs')
        os.close(leaf_fd)
        leaf_fd = None
        os.fsync(owned_fd)
        after_held = full9(os.fstat(owned_fd))
        after_named = full9(os.stat(NAME, dir_fd=parent_fd, follow_symlinks=False))
        members = sorted(os.listdir(owned_fd))
        need(after_held == after_named and after_held[:5] == before_held[:5]
             and members == ['INTENT.json'], 'directory identity, permissions or exact membership changed')
        observed = {'schema': 'hepta.actual-mac-owned-directory-observation.v1',
                    'probe_key': KEY, 'path': str(PARENT/NAME), 'field_order': list(FIELDS),
                    'platform': sys.platform, 'uid': os.geteuid(),
                    'reference_path_read_only': str(REFERENCE), 'reference_full9': full9(reference),
                    'same_filesystem_as_reference': parent.st_dev == reference.st_dev,
                    'before': {'held': before_held, 'named': before_named, 'members': []},
                    'after': {'held': after_held, 'named': after_named, 'members': members},
                    'changed_directory_fields': [key for i, key in enumerate(FIELDS) if before_held[i] != after_held[i]],
                    'intent': {'held': leaf_held, 'named': leaf_named, 'bytes': len(raw),
                               'sha256': hashlib.sha256(raw).hexdigest()},
                    'original_prefix6_predicate': after_held == after_named and after_held[:6] == before_held[:6] and members == ['INTENT.json'],
                    'stable_prefix5_predicate': after_held == after_named and after_held[:5] == before_held[:5] and members == ['INTENT.json'],
                    'phone_calls': 0, 'history_audit_calls': 0, 'historical_output_modified': False,
                    'created_directory_count': 1, 'created_file_count': 1, 'evidence_retained': True,
                    'historical_failure_cause_proven': False, 'elapsed_seconds': time.monotonic()-started}
    finally:
        for fd in (leaf_fd, owned_fd, parent_fd):
            if fd is not None:
                os.close(fd)
        signal.setitimer(signal.ITIMER_REAL, 0)
    observed['owned_fds_closed'] = True
    print(json.dumps(observed, ensure_ascii=False, sort_keys=True))


if __name__ == '__main__':
    main()
