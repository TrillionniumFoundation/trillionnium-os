#!/usr/bin/env python3
"""One fixed readonly observation of retained failed-attempt footprint.

The exact134 retained rows,12 fixed transport leaves and65 fixed absences are
observed now. Historical data specifies expectations, never current absence.
No runtime is imported, no epoch is initialized, and no case permission results.
"""
import sys
sys.dont_write_bytecode = True
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import zlib

BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
ANDROID = Path('/proc/1/root')
META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
OUTPUT_LIMIT = 8*1024*1024
MAX_PACKET_RAW = 16*1024*1024
ENTRIES = {}
RAW_FILES = {}
PARENTS = {}
ANCESTORS = {}
ABSENCES = {}
READ_BOOKENDS = {}
ALIAS_CHECKS = None
PROC_BRIDGE = {'first': None, 'final': None}
BOOT_ORIGINALS = {'first': None, 'final': None}
LAST_METADATA_BYTES = 0
FOOTPRINT_PIN = {'bytes': 176976, 'sha256': '6bb6a8466bd8bcb2d7bb2aa6e376113d481dab27ca919a5f419fa19c07d0d40f'}
FOOTPRINT_PACKET = {'codec': 'zlib+base64', 'packed': {'bytes': 14981, 'sha256': 'a8c353cc3c13ff1b4aec2a398a6497a9571bc2c9384ce3fa021463d4b26ef2bd'}, 'raw': {'bytes': 176976, 'sha256': '6bb6a8466bd8bcb2d7bb2aa6e376113d481dab27ca919a5f419fa19c07d0d40f'}, 'data': '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'}

def need(ok,why):
    if not ok:raise ValueError(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(rows):
        value={}
        for k,v in rows:
            need(k not in value,'duplicate JSON key');value[k]=v
        return value
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))


def metadata(s):
    return [getattr(s,k) for k in META]


def parent_fd(path):
    path=Path(path)
    need(path.is_absolute() and '..' not in path.parts and 2<=len(path.parts)<=64,'bounded absolute path')
    if path.parts[:4]==('/','proc','1','root'):
        fd=os.open(ANDROID,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);parts=path.parts[4:]
    else:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);parts=path.parts[1:]
    need(parts,'original leaf required')
    try:
        for name in parts[:-1]:
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=child
        return fd,parts[-1]
    except BaseException:
        os.close(fd);raise


def boot():
    with open('/proc/sys/kernel/random/boot_id','rb') as stream:raw=stream.read(128)
    need(raw.strip().decode()==BOOT,'actual boot changed');return raw


def own_fds():
    names=os.listdir('/proc/self/fd');need(len(names)<=256,'own FD census bound')
    value={}
    for name in names:
        need(name.isdigit(),'own FD name shape');fd=int(name)
        try:s=os.fstat(fd)
        except OSError as error:
            need(error.errno in (errno.EBADF,errno.ENOENT),'own FD observation unknown');continue
        value[fd]=(s.st_dev,s.st_ino,s.st_mode)
    return value


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
        separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def descriptor(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}


def strict_unpack(packet, maximum):
    need(type(packet) is dict and set(packet) == {'codec', 'packed', 'raw', 'data'},
        'exact lossless packet required')
    need(packet['codec'] == 'zlib+base64' and type(packet['data']) is str,
        'fixed packet codec required')
    for key in ('packed', 'raw'):
        row = packet[key]
        need(type(row) is dict and set(row) == {'bytes', 'sha256'}
            and type(row['bytes']) is int and 0 < row['bytes'] <= maximum
            and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
            'bounded exact packet descriptor required')
    need(len(packet['data']) <= 4 * ((maximum + 2) // 3), 'bounded base64 packet required')
    packed = base64.b64decode(packet['data'], validate=True)
    need(descriptor(packed) == packet['packed'], 'lossless packed bytes differ')
    decompressor = zlib.decompressobj()
    raw = decompressor.decompress(packed, packet['raw']['bytes'] + 1)
    need(decompressor.eof and not decompressor.unused_data and not decompressor.unconsumed_tail
        and decompressor.flush() == b'' and descriptor(raw) == packet['raw'],
        'lossless complete bounded packet required')
    return raw


def pack_original(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_PACKET_RAW, 'bounded whole observation required')
    packed = zlib.compress(raw, 9)
    packet = {'codec': 'zlib+base64', 'packed': descriptor(packed), 'raw': descriptor(raw),
        'data': base64.b64encode(packed).decode('ascii')}
    need(strict_unpack(packet, MAX_PACKET_RAW) == raw, 'whole observation lossless roundtrip differs')
    return packet


class ReadBudget:
    """One cooperative clock and physical byte pool for the entire observation."""
    def __init__(self):
        self.started = time.monotonic()
        self.bytes_read = 0
        self.file_reads = 0
        self.operations = 0

    def check(self):
        need(time.monotonic()-self.started < 30, 'fixed footprint shared30second observation deadline')
        need(self.bytes_read <= 16*1024*1024 and self.operations <= 4096,
             'fixed footprint whole physical-read or operation budget')

    def operation(self):
        self.operations += 1
        self.check()

    def charge(self, amount):
        need(type(amount) is int and amount >= 0, 'nonnegative actual read charge required')
        self.bytes_read += amount
        self.check()


def fixed_footprint():
    raw = strict_unpack(FOOTPRINT_PACKET, 262144)
    need(descriptor(raw) == FOOTPRINT_PIN, 'fixed retained footprint original differs')
    value = strict(raw)
    need(value['schema'] == 'hepta.source-only.epoch-retained-footprint.v1'
         and value['state'] == 'EXACT_PATH_REQUEST_HISTORICAL_IDENTITIES_FRESH_OBSERVATION_REQUIRED'
         and value['epoch_initialized'] is False, 'fixed footprint scope is not a new epoch permission')
    roots = [row['path'] for row in value['retained_directory_roots']]
    entries = value['retained_directory_member_originals']
    leaves = value['fixed_control_leaves']
    absences = [row['path'] for row in value['absence_checks']]
    absences += [row['path'] for row in value['new_control_roots']]
    need(len(roots) == len(set(roots)) == 4 and len(entries) == 134
         and sum(row['kind'] == 'file' for row in entries) == 114
         and sum(row['kind'] == 'directory' for row in entries) == 20
         and len(leaves) == 12 and len(absences) == len(set(absences)) == 65,
         'fixed complete134/12/65 scope differs')
    need(roots == value['explicit_fresh_read_request']['complete_trees']
         and [row['path'] for row in leaves] == value['explicit_fresh_read_request']['fixed_leaves']
         and set(absences) == set(value['explicit_fresh_read_request']['positive_absence_paths']),
         'footprint exact request differs from its fixed rows')
    paths = [row['path'] for row in entries]
    need(len(paths) == len(set(paths)) and len({row['path'] for row in leaves}) == 12,
         'fixed source paths repeat')
    all_paths = paths + [row['path'] for row in leaves] + absences
    need(len(all_paths) == len(set(all_paths)), 'fixed present and absent scopes overlap')
    for path in all_paths:
        p = Path(path)
        need(p.is_absolute() and str(p) == path and '..' not in p.parts and len(p.parts) <= 64,
             'canonical bounded fixed footprint path required')
    root_paths = [Path(path) for path in roots]
    table = {row['path']: row for row in entries}
    children = {}
    for path in paths:
        p = Path(path)
        need(sum(p == root or root in p.parents for root in root_paths) == 1,
             'retained tree member leaves its unique complete root')
        if path not in roots:
            children.setdefault(str(p.parent), []).append(p.name)
    for path, row in table.items():
        need(type(row['metadata']) is list and len(row['metadata']) == 9
             and all(type(n) is int for n in row['metadata']), 'historical full9 required')
        if row['kind'] == 'directory':
            need(row['names'] == sorted(children.get(path, [])),
                 'historical complete tree did not enumerate every directory member')
        else:
            need(row['bytes'] == row['metadata'][6] and 0 <= row['bytes'] <= 16*1024*1024
                 and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'fixed historical file descriptor differs')
    for row in leaves:
        need(type(row['expected_bytes']) is int and 0 <= row['expected_bytes'] <= 16*1024*1024
             and type(row['expected_sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['expected_sha256']),
             'fixed transport leaf body pin differs')
    need(sum(row['bytes'] for row in entries if row['kind'] == 'file')
         + sum(row['expected_bytes'] for row in leaves) == 7114062,
         'complete physical body bytes differ from the exact fixed footprint')
    return value, roots, entries, leaves, sorted(absences)


def names_from_fd(fd, budget):
    names = []
    with os.scandir(fd) as scan:
        for item in scan:
            budget.check()
            need(len(names) < 20000 and item.name not in ('', '.', '..')
                 and '/' not in item.name and '\0' not in item.name,
                 'bounded literal directory membership required')
            names.append(item.name)
    need(len(names) == len(set(names)), 'directory repeats a name')
    return sorted(names)


def selinux_from_fd(fd, budget):
    raw = os.getxattr(fd, 'security.selinux')
    need(0 < len(raw) <= 4096, 'bounded actual SELinux label required')
    budget.charge(len(raw))
    return raw.hex()


def metadata_budget():
    global LAST_METADATA_BYTES
    value = {'entries': list(ENTRIES.values()), 'immediate_parent_observations': list(PARENTS.values()),
             'canonical_ancestor_observations': list(ANCESTORS.values()),
             'positive_absence_observations': list(ABSENCES.values()),
             'read_bookends': READ_BOOKENDS, 'actual_alias_checks': ALIAS_CHECKS,
             'fixed_proc_root_bridge': PROC_BRIDGE, 'boot_originals': BOOT_ORIGINALS,
             'file_originals': [{'bytes': ENTRIES[path]['bytes'], 'sha256': ENTRIES[path]['sha256'],
                                'path': path, 'encoding': 'base64', 'data_base64': ''} for path in RAW_FILES]}
    LAST_METADATA_BYTES = len(encoded(value))
    need(LAST_METADATA_BYTES <= 512*1024, 'whole footprint metadata observation bound')


def parent_observation_reference(row):
    path = row['path']; paths = list(PARENTS)
    need(path in PARENTS and encoded(PARENTS[path]) == encoded(row), 'actual parent observation changed')
    return {'table': 'immediate_parent_observations', 'index': paths.index(path),
            'serialized_observation': descriptor(encoded(row))}


def expand_parent_observation_reference(ref):
    rows = list(PARENTS.values())
    need(type(ref) is dict and set(ref) == {'table', 'index', 'serialized_observation'}
         and ref['table'] == 'immediate_parent_observations' and type(ref['index']) is int
         and 0 <= ref['index'] < len(rows), 'parent observation reference is malformed')
    row = rows[ref['index']]
    need(encoded(ref['serialized_observation']) == encoded(descriptor(encoded(row))),
         'serialized parent observation identity differs')
    return row


def pid1_generation(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 8192 and raw.startswith(b'1 (')
         and raw.endswith(b'\n'), 'bounded complete actual PID1 stat required')
    closing = raw.rfind(b') ')
    need(closing > 2, 'actual PID1 stat comm delimiter absent')
    fields = raw[closing+2:].split()
    need(len(fields) >= 20 and len(fields[0]) == 1
         and all(re.fullmatch(rb'[0-9]+', fields[i]) for i in (2, 3, 19)),
         'actual PID1 group/session/start fields malformed')
    value = [1, int(fields[2]), int(fields[3]), int(fields[19])]
    need(value[3] == 0, 'actual PID1 start ticks differ from the fixed native init profile')
    return value


def observe_proc_bridge(budget, *, final=False):
    """Only /proc/1/root is followed; ordinary components remain NOFOLLOW."""
    budget.operation(); began = time.monotonic_ns()
    parent = pidfd = statfd = androidfd = gnufd = reopened = None
    try:
        parent, leaf = parent_fd(Path('/proc/1/stat'))
        need(leaf == 'stat', 'fixed PID1 stat path differs')
        pidfd = parent; parent = None
        pid_meta = metadata(os.fstat(pidfd))
        need(stat.S_ISDIR(pid_meta[2]), 'actual PID1 directory type differs')
        named_stat = os.stat('stat', dir_fd=pidfd, follow_symlinks=False)
        need(stat.S_ISREG(named_stat.st_mode), 'actual PID1 stat is not regular')
        statfd = os.open('stat', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=pidfd)
        stat_meta = metadata(os.fstat(statfd))
        need(stat_meta == metadata(named_stat), 'actual PID1 stat changed before open')
        chunks = []; size = 0
        while True:
            budget.check(); block = os.read(statfd, min(4096, 8193-size))
            if not block: break
            chunks.append(block); size += len(block); budget.charge(len(block))
            need(size <= 8192, 'actual PID1 stat whole-body bound')
        raw = b''.join(chunks); generation = pid1_generation(raw)
        need(stat_meta == metadata(os.fstat(statfd))
             == metadata(os.stat('stat', dir_fd=pidfd, follow_symlinks=False)),
             'actual PID1 stat named/held metadata changed')
        root_meta = metadata(os.stat('root', dir_fd=pidfd, follow_symlinks=False))
        need(stat.S_ISLNK(root_meta[2]), 'fixed PID1 root is not the observed magic link')
        root_text = os.fsencode(os.readlink('root', dir_fd=pidfd))
        need(0 < len(root_text) <= 4096, 'fixed PID1 root link text bound')
        budget.charge(len(root_text))
        androidfd = os.open('root', os.O_RDONLY | os.O_DIRECTORY | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=pidfd)
        gnufd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        android_meta = metadata(os.fstat(androidfd)); gnu_meta = metadata(os.fstat(gnufd))
        need(stat.S_ISDIR(android_meta[2]) and stat.S_ISDIR(gnu_meta[2])
             and android_meta[:2] != gnu_meta[:2], 'actual Android and GNU roots must be distinct directories')
        need(metadata(os.stat('root', dir_fd=pidfd, follow_symlinks=True)) == android_meta
             and metadata(os.fstat(androidfd)) == android_meta
             and metadata(os.fstat(gnufd)) == gnu_meta
             and metadata(os.stat('/', follow_symlinks=False)) == gnu_meta,
             'fixed root target changed during observation')
        reopened, canonical_leaf = parent_fd(Path('/proc/1/stat'))
        need(canonical_leaf == 'stat' and metadata(os.fstat(reopened)) == pid_meta
             == metadata(os.fstat(pidfd)), 'actual PID1 canonical directory changed')
        need(metadata(os.stat('root', dir_fd=reopened, follow_symlinks=False)) == root_meta
             == metadata(os.stat('root', dir_fd=pidfd, follow_symlinks=False))
             and os.fsencode(os.readlink('root', dir_fd=reopened)) == root_text
             == os.fsencode(os.readlink('root', dir_fd=pidfd))
             and metadata(os.stat('root', dir_fd=reopened, follow_symlinks=True)) == android_meta,
             'fixed PID1 root link or canonical target changed')
        stable = {'pid1_directory_path': '/proc/1', 'pid1_directory_metadata': pid_meta,
                  'pid1_stat_metadata': stat_meta, 'generation_fields': ['pid', 'pgrp', 'session', 'start_ticks'],
                  'pid1_generation': generation, 'magic_link_path': '/proc/1/root',
                  'magic_link_lstat_metadata': root_meta, 'magic_link_text': {
                      **descriptor(root_text), 'encoding': 'base64', 'data_base64': base64.b64encode(root_text).decode('ascii')},
                  'followed_android_root': {'path': '/proc/1/root', 'dev_ino_mode': android_meta[:3], 'metadata': android_meta},
                  'gnu_root': {'path': '/', 'dev_ino_mode': gnu_meta[:3], 'metadata': gnu_meta},
                  'only_magic_link_exception': '/proc/1/root', 'other_path_components_nofollow': True}
        row = {'identity': stable, 'pid1_stat_original': {'path': '/proc/1/stat', **descriptor(raw),
                       'encoding': 'base64', 'data_base64': base64.b64encode(raw).decode('ascii')},
               'started_monotonic_ns': began, 'finished_monotonic_ns': time.monotonic_ns()}
    finally:
        for fd in (reopened, gnufd, androidfd, statfd, pidfd, parent):
            if fd is not None: os.close(fd)
    if final:
        need(PROC_BRIDGE['first'] is not None and PROC_BRIDGE['final'] is None
             and encoded(PROC_BRIDGE['first']['identity']) == encoded(stable),
             'fixed PID1 generation or /proc/1/root bridge changed between rounds')
        PROC_BRIDGE['final'] = row
    else:
        need(PROC_BRIDGE['first'] is None, 'fixed proc bridge repeated')
        PROC_BRIDGE['first'] = row
    metadata_budget(); budget.check()


def retain_parent(path, fd, budget):
    budget.operation()
    before = metadata(os.fstat(fd))
    need(stat.S_ISDIR(before[2]), 'held parent is not a directory')
    names = names_from_fd(fd, budget); label = selinux_from_fd(fd, budget)
    need(metadata(os.fstat(fd)) == before and names_from_fd(fd, budget) == names,
         'held immediate parent changed during observation')
    row = {'path': str(path), 'metadata': before, 'names': names, 'selinux_raw_hex': label,
           'scope': 'IMMEDIATE_PARENT_NAMES_METADATA_ONLY_NOT_COMPLETE_SUBTREE'}
    if str(path) in PARENTS:
        need(encoded(PARENTS[str(path)]) == encoded(row), 'immediate parent changed across observation')
    else:
        PARENTS[str(path)] = row
        metadata_budget()
    return row


def read_fixed_node(expected, scope, budget, *, final=False):
    """Regular-file reads are nonblocking; only exact listed Android leaves relax private mode."""
    path = Path(expected['path']); budget.operation(); began = time.monotonic_ns()
    parent, leaf = parent_fd(path); fd = None
    raw = None; row = None
    try:
        parent_row = retain_parent(path.parent, parent, budget)
        before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        actual = metadata(before)
        kind = expected['kind'] if scope == 'retained_tree' else 'file'
        need((kind == 'directory' and stat.S_ISDIR(before.st_mode))
             or (kind == 'file' and stat.S_ISREG(before.st_mode) and before.st_nlink == 1),
             'fixed footprint object has an unexpected type or link count')
        maximum = expected.get('bytes', expected.get('expected_bytes', 0))
        if kind == 'file':
            need(before.st_size == maximum and 0 <= maximum <= 16*1024*1024,
                 'fixed file size differs; unknown body is not followed')
        # Incoming Android copies are observed as they really are, including
        # their UID2000/mode0666 when present. This does not admit that mode for
        # any future generation, private original or different path.
        android_incoming = scope == 'fixed_control_leaf' and expected['private_uid_mode_must_not_be_assumed_for_android'] is True
        if not android_incoming:
            need(before.st_uid == before.st_gid == 0
                 and stat.S_IMODE(before.st_mode) == (0o700 if kind == 'directory' else 0o600),
                 'fixed retained/private original ownership or mode differs')
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        if kind == 'directory':
            flags |= os.O_DIRECTORY
        fd = os.open(leaf, flags, dir_fd=parent)
        need(metadata(os.fstat(fd)) == actual, 'fixed path changed before open')
        label = selinux_from_fd(fd, budget)
        row = {'path': str(path), 'kind': kind, 'metadata': actual,
               'selinux_raw_hex': label, 'scope': scope,
               'android_incoming_permissions_observed_not_approved': android_incoming}
        if kind == 'directory':
            row['names'] = names_from_fd(fd, budget)
        else:
            pieces = []; size = 0
            while True:
                budget.check()
                block = os.read(fd, min(65536, maximum+1-size))
                if not block:
                    break
                size += len(block); budget.charge(len(block)); pieces.append(block)
                need(size <= maximum, 'fixed file grew during whole read')
            raw = b''.join(pieces)
            need(len(raw) == maximum, 'fixed file truncated during whole read')
            row.update(descriptor(raw)); budget.file_reads += 1
        named = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        need(actual == metadata(os.fstat(fd)) == metadata(named), 'fixed full9 changed during whole read')
        need(label == selinux_from_fd(fd, budget), 'fixed SELinux label changed during read')
        if kind == 'directory':
            need(row['names'] == names_from_fd(fd, budget), 'fixed directory names changed during read')
        need(retain_parent(path.parent, parent, budget) == parent_row, 'fixed held parent changed during read')
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)
    canonical, canonical_leaf = parent_fd(path)
    try:
        need(canonical_leaf == leaf and retain_parent(path.parent, canonical, budget) == parent_row
             and metadata(os.stat(leaf, dir_fd=canonical, follow_symlinks=False)) == actual,
             'fixed canonical path or parent changed after read')
    finally:
        os.close(canonical)
    finished = time.monotonic_ns()
    if final:
        need(str(path) in ENTRIES and encoded(ENTRIES[str(path)]) == encoded(row),
             'fixed object changed at the final whole-body/full9 bookend')
        if raw is not None:
            need(RAW_FILES[str(path)] == raw, 'fixed original bytes changed at final whole-body bookend')
        READ_BOOKENDS[str(path)]['final'] = {'started_monotonic_ns': began, 'finished_monotonic_ns': finished}
    else:
        need(str(path) not in ENTRIES, 'fixed present path repeated')
        ENTRIES[str(path)] = row
        if raw is not None:
            RAW_FILES[str(path)] = raw
        READ_BOOKENDS[str(path)] = {'first': {'started_monotonic_ns': began, 'finished_monotonic_ns': finished},
                                   'final': None, 'both_reads_are_whole_bodies': kind == 'file'}
        metadata_budget()
    wanted_metadata = expected.get('metadata', expected.get('historical_metadata'))
    need(wanted_metadata is None or actual == wanted_metadata, 'actual original full9 differs from fixed historical identity')
    wanted_label = expected.get('selinux_raw_hex')
    need(wanted_label is None or label == wanted_label, 'actual SELinux differs from fixed historical label')
    if kind == 'directory':
        need(row['names'] == expected['names'], 'unexpected original directory membership; no new child is followed')
    else:
        wanted = expected.get('sha256', expected.get('expected_sha256'))
        need(row['sha256'] == wanted, 'actual whole original bytes differ from fixed source pin')
    budget.check()
    return row


def read_fixed_absence(path, budget, *, final=False):
    path = Path(path); budget.operation(); began = time.monotonic_ns()
    parent, leaf = parent_fd(path)
    try:
        parent_row = retain_parent(path.parent, parent, budget)
        for _ in range(2):
            try:
                actual = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            except OSError as error:
                need(error.errno == errno.ENOENT, 'fixed absence lookup is unknown')
            else:
                ABSENCES[str(path)] = {'path': str(path), 'state': 'UNEXPECTED_PRESENT_NOT_FOLLOWED',
                    'metadata': metadata(actual), 'parent_observation': parent_observation_reference(parent_row),
                    'observed_monotonic_ns': time.monotonic_ns()}
                metadata_budget()
                raise ValueError('fixed expected absence is present; no adoption or cleanup')
        second, second_leaf = parent_fd(path)
        try:
            need(second_leaf == leaf and retain_parent(path.parent, second, budget) == parent_row,
                 'fixed absence canonical parent changed')
            try:
                os.stat(second_leaf, dir_fd=second, follow_symlinks=False)
            except OSError as error:
                need(error.errno == errno.ENOENT, 'canonical fixed absence unknown')
            else:
                raise ValueError('fixed absent object appeared at canonical bookend')
        finally:
            os.close(second)
        need(retain_parent(path.parent, parent, budget) == parent_row,
             'fixed absence held parent changed')
    finally:
        os.close(parent)
    observation = {'started_monotonic_ns': began, 'finished_monotonic_ns': time.monotonic_ns(),
                   'held_parent_enoent_observations': 2, 'reopened_parent_enoent_observations': 1,
                   'canonical_parent_observation': parent_observation_reference(parent_row)}
    need(encoded(expand_parent_observation_reference(observation['canonical_parent_observation']))
         == encoded(parent_row), 'actual absence parent reference cannot be expanded exactly')
    if final:
        previous = ABSENCES[str(path)]
        need(previous['state'] == 'POSITIVELY_OBSERVED_ENOENT' and previous['final'] is None,
             'fixed absence has no unique first actual observation')
        need(encoded(previous['first']['canonical_parent_observation'])
             == encoded(observation['canonical_parent_observation']),
             'fixed absence parent differs between complete observation rounds')
        previous['final'] = observation
    else:
        need(str(path) not in ABSENCES, 'fixed absence path repeated')
        ABSENCES[str(path)] = {'path': str(path), 'state': 'POSITIVELY_OBSERVED_ENOENT',
                              'first': observation, 'final': None, 'absence_is_new_permission': False}
    metadata_budget(); budget.check()


def fixed_ancestor_paths(paths):
    result = set()
    for value in paths:
        path = Path(value)
        android = path.parts[:4] == ('/', 'proc', '1', 'root')
        for parent in path.parents:
            if android and len(parent.parts) < 4:
                continue
            result.add(str(parent))
    need(len(result) <= 128, 'fixed canonical ancestor count bound')
    return sorted(result, key=lambda value: (len(Path(value).parts), value))


def observe_ancestor(path, budget, *, final=False):
    path = Path(path); budget.operation(); parent = fd = None
    try:
        if str(path) in ('/', str(ANDROID)):
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        else:
            parent, leaf = parent_fd(path)
            before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode), 'fixed canonical ancestor is not a directory')
            fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=parent)
            need(metadata(os.fstat(fd)) == metadata(before), 'fixed ancestor changed before open')
        row = {'path': str(path), 'metadata': metadata(os.fstat(fd)),
               'selinux_raw_hex': selinux_from_fd(fd, budget),
               'scope': 'CANONICAL_ANCESTOR_METADATA_ONLY_NO_DIRECTORY_ENUMERATION'}
        need(stat.S_ISDIR(row['metadata'][2]) and metadata(os.fstat(fd)) == row['metadata'],
             'fixed canonical ancestor full9 changed')
        if parent is not None:
            need(metadata(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) == row['metadata'],
                 'fixed canonical ancestor named path changed')
    finally:
        if fd is not None:
            os.close(fd)
        if parent is not None:
            os.close(parent)
    if final:
        need(encoded(ANCESTORS[str(path)]) == encoded(row), 'canonical ancestor changed between full rounds')
    else:
        need(str(path) not in ANCESTORS, 'canonical ancestor repeated')
        ANCESTORS[str(path)] = row
    metadata_budget(); budget.check()


def final_parent_bookends(budget):
    for path, expected in list(PARENTS.items()):
        budget.check()
        parent, _leaf = parent_fd(Path(path)/'.fixed-footprint-parent-observation')
        try:
            need(retain_parent(path, parent, budget) == expected, 'final immediate parent changed')
        finally:
            os.close(parent)


def verify_actual_aliases(footprint):
    checks = []
    for pair in footprint['extra_alias_pairs']:
        need(type(pair) is list and len(pair) == 2, 'fixed alias pair differs')
        left, right = (ENTRIES[path] for path in pair)
        need(left['kind'] == right['kind'] == 'directory'
             and left['metadata'] == right['metadata'] and left['names'] == right['names']
             and left['selinux_raw_hex'] == right['selinux_raw_hex'],
             'failed-case GNU/Android executor aliases differ')
        checks.append({'paths': pair, 'metadata': left['metadata'], 'names': left['names'],
                       'selinux_raw_hex': left['selinux_raw_hex'], 'both_views_observed_and_charged': True})
    return checks


def main():
    global ALIAS_CHECKS
    budget = ReadBudget(); began_unix_ns = time.time_ns()
    phase = 'fixed_scope'; failure = None; complete = False; before = None; cleanup = None
    footprint = roots = entries = leaves = absences = None; alias_checks = None; boot_raw = None
    try:
        need(len(sys.argv) == 1, 'fixed retained-footprint observer takes no alternate paths or inputs')
        footprint, roots, entries, leaves, absences = fixed_footprint(); budget.check()
        need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
             'actual Root credentials required')
        before = own_fds(); boot_raw = boot(); budget.charge(len(boot_raw))
        BOOT_ORIGINALS['first'] = {'path': '/proc/sys/kernel/random/boot_id', **descriptor(boot_raw),
            'encoding': 'base64', 'data_base64': base64.b64encode(boot_raw).decode('ascii')}
        phase = 'fixed_proc_root_bridge'; observe_proc_bridge(budget)
        all_paths = [row['path'] for row in entries] + [row['path'] for row in leaves] + absences
        ancestor_paths = fixed_ancestor_paths(all_paths)
        phase = 'canonical_ancestor_metadata_only'
        for path in ancestor_paths:
            observe_ancestor(path, budget)
        phase = 'complete_fixed_tree_originals'
        for row in sorted(entries, key=lambda value: (len(Path(value['path']).parts), value['path'])):
            read_fixed_node(row, 'retained_tree', budget)
        phase = 'twelve_fixed_transport_originals'
        for row in leaves:
            read_fixed_node(row, 'fixed_control_leaf', budget)
        phase = 'sixtyfive_fixed_positive_absence_observations'
        for path in absences:
            read_fixed_absence(path, budget)
        alias_checks = verify_actual_aliases(footprint); ALIAS_CHECKS = alias_checks
        phase = 'whole_body_full9_names_label_and_absence_bookends'
        for row in entries:
            read_fixed_node(row, 'retained_tree', budget, final=True)
        for row in leaves:
            read_fixed_node(row, 'fixed_control_leaf', budget, final=True)
        for path in absences:
            read_fixed_absence(path, budget, final=True)
        for path in ancestor_paths:
            observe_ancestor(path, budget, final=True)
        final_parent_bookends(budget)
        observe_proc_bridge(budget, final=True)
        final_boot = boot(); budget.charge(len(final_boot))
        BOOT_ORIGINALS['final'] = {'path': '/proc/sys/kernel/random/boot_id', **descriptor(final_boot),
            'encoding': 'base64', 'data_base64': base64.b64encode(final_boot).decode('ascii')}
        need(final_boot == boot_raw, 'boot changed across retained-footprint observation')
        need(len(ENTRIES) == 146 and len(RAW_FILES) == 126 and len(ABSENCES) == 65
             and sum(len(raw) for raw in RAW_FILES.values()) == 7114062
             and budget.file_reads == 252
             and all(row['final'] is not None for row in READ_BOOKENDS.values())
             and all(row['final'] is not None for row in ABSENCES.values()),
             'fixed full original/body/absence read accounting is incomplete')
        budget.check(); complete = True; phase = 'complete'
    except BaseException as error:
        failure = {'phase': phase, 'type': type(error).__name__, 'detail': str(error)[:2048]}
    finally:
        if before is not None:
            try:
                after = own_fds()
                remaining = [{'fd': fd, 'identity': list(identity)} for fd, identity in after.items()
                             if fd >= 3 and before.get(fd) != identity]
                cleanup = {'complete': not remaining, 'new_read_FDs_remaining': remaining,
                           'unknown_or_foreign_FDs_closed': False, 'locks_acquired': 0}
                if remaining:
                    complete = False
                    if failure is None:
                        failure = {'phase': 'owned_fd_bookend', 'type': 'ValueError', 'detail': 'new read FD remains'}
            except BaseException as error:
                complete = False
                cleanup = {'complete': False, 'type': type(error).__name__, 'detail': str(error)[:1024]}
        else:
            cleanup = {'complete': True, 'owned_read_stage_entered': False, 'new_read_FDs_remaining': []}
    observations = {'entries': list(ENTRIES.values()), 'immediate_parent_observations': list(PARENTS.values()),
                    'canonical_ancestor_observations': list(ANCESTORS.values()),
                    'positive_absence_observations': list(ABSENCES.values()),
                    'read_bookends': READ_BOOKENDS, 'actual_alias_checks': alias_checks,
                    'fixed_proc_root_bridge': PROC_BRIDGE, 'boot_originals': BOOT_ORIGINALS,
                    'file_originals': [{**descriptor(raw), 'path': path, 'encoding': 'base64',
                                        'data_base64': base64.b64encode(raw).decode('ascii')}
                                       for path, raw in RAW_FILES.items()]}
    progress = {'present_rows': len(ENTRIES), 'full_file_bodies': len(RAW_FILES),
        'parent_observations': len(PARENTS), 'ancestor_observations': len(ANCESTORS),
        'absence_rows': len(ABSENCES), 'whole_file_reads': budget.file_reads,
        'physical_read_bytes': budget.bytes_read, 'last_metadata_bytes': LAST_METADATA_BYTES}
    result = {'schema': 'hepta.native-guard.fixed-epoch-retained-footprint-observation.v2',
              'state': 'EXACT_FIXED_RETAINED_ORIGINALS_AND_CURRENT_ABSENCES_OBSERVED' if complete
                       else 'FIXED_RETAINED_FOOTPRINT_FAILED_OR_PARTIAL',
              'observation_complete': complete, 'failure': failure, 'boot_id': BOOT,
              'footprint_original': FOOTPRINT_PIN, 'historical_inputs_are_expectations_not_current_observations': True,
              'observation_started_unix_ns': began_unix_ns, 'observation_ended_unix_ns': time.time_ns(),
              'fixed_tree_roots': roots, 'present_rows_observed': len(ENTRIES),
              'full_file_bodies_retained': len(RAW_FILES), 'raw_file_bytes_retained': sum(map(len, RAW_FILES.values())),
              'physical_read_bytes_charged': budget.bytes_read, 'whole_file_reads': budget.file_reads,
              'object_operations': budget.operations, 'owned_read_fd_observation': cleanup,
              'observation_progress': progress,
              'observations': None, 'complete_raw_observation_retained': False,
              'limits': {'cooperative_seconds': 30, 'physical_read_bytes': 16*1024*1024,
                         'object_operations': 4096, 'directory_names': 20000,
                         'metadata_bytes': 512*1024, 'packet_raw_bytes': MAX_PACKET_RAW,
                         'phone_report_bytes': OUTPUT_LIMIT},
              'hard_preemptive_deadline_claimed': False, 'atomic_global_snapshot_claimed': False,
              'global_clearance_proof': False, 'epoch_initialized': False, 'future_input_authorization': False,
              'native_case_qualified': False, 'case_pass': False, 'new_nonce_or_lease': False,
              'runtime_modules_loaded': 0, 'runtime_function_calls': 0, 'process_launches': 0,
              'phone_content_writes': 0, 'endpoint_connections': 0, 'signals': 0, 'locks_acquired': 0,
              'model_requests': 0, 'native_sends': 0, 'boundary_publications': 0, 'automatic_retry': False}
    try:
        metadata_budget()
        result['observations'] = pack_original(encoded(observations))
        result['complete_raw_observation_retained'] = True
        result['total_wall_seconds'] = time.monotonic()-budget.started
        if complete:
            budget.check()
        raw = encoded(result)
        need(len(raw) <= OUTPUT_LIMIT, 'whole lossless footprint report exceeds existing eight-MiB phone budget')
        if complete:
            budget.check()
    except BaseException as error:
        complete = False
        raw = encoded({'schema': result['schema'], 'state': 'FIXED_FOOTPRINT_SERIALIZATION_REFUSED',
            'observation_complete': False, 'complete_raw_observation_retained': False,
            'type': type(error).__name__, 'detail': str(error)[:1024], 'owned_read_fd_observation': cleanup,
            'original_failure': failure, 'observation_phase': phase, 'observation_progress': progress,
            'last_metadata_bytes': LAST_METADATA_BYTES,
            'footprint_original': FOOTPRINT_PIN, 'global_clearance_proof': False, 'future_input_authorization': False,
            'epoch_initialized': False, 'new_nonce_or_lease': False, 'phone_content_writes': 0,
            'case_pass': False, 'automatic_retry': False})
        need(len(raw) <= OUTPUT_LIMIT, 'fixed footprint failure report exceeded its output bound')
    sys.stdout.write(raw.decode('ascii'))
    return 0 if complete else 1


if __name__ == '__main__':
    raise SystemExit(main())
