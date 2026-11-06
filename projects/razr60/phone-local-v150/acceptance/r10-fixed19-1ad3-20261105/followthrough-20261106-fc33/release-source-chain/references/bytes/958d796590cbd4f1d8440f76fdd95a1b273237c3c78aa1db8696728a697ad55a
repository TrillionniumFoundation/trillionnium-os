#!/usr/bin/env python3
"""Bounded evidence helper for a service-owned child wait.

This program never starts a role, signals a role, waits for another process,
deletes a claim, or rewrites an original. Only the real service shell performs
the three builtin waits. The production CLI requires that shell as its parent.
"""
import argparse
import base64
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time

sys.dont_write_bytecode = True
ROLES = ('model', 'sidecar', 'provider')
META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns')
HISTORY = '/data/adb/trillionnium-hepta-phone-local-v150-r10-r1'
EXECUTOR_HISTORY = '/data/trillionnium/owner-open/state/phone-local-v150/executor-r6/module-history-r10-r1'
MODULE = '/data/adb/modules/trillionnium_hepta_phone_local_v150_r10_r1'
EXECUTOR_LABEL = b'u:object_r:trillionnium_owner_open_phone_executor_data_file:s0'
MAX_ORIGINAL = 262144
PHASE_SECONDS = 2.0
SUPERVISOR_LOG_ROOT = '/var/lib/trillionnium/owner-open/phone-local-v150/root-install-v150-r10-r1'

def need(value, message):
    if not value:
        raise ValueError(message)

def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2,
                       allow_nan=False) + '\n').encode()

def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: need(False, 'nonfinite JSON'))

def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

def metadata(info):
    return [getattr(info, key) for key in META]

def parse_identity(text):
    need(type(text) is str and re.fullmatch(r'[1-9][0-9]*(?::[1-9][0-9]*){3}', text),
         'exact PID:pgrp:session:start_ticks')
    value = list(map(int, text.split(':')))
    need(value[0] > 1 and value[0] == value[1] == value[2],
         'dedicated original group and session')
    return value

def identity_text(value):
    return ':'.join(map(str, value))

def parse_stat(raw, expected_pid):
    need(type(raw) is bytes and 0 < len(raw) <= 4096 and raw.endswith(b'\n'),
         'complete bounded proc stat')
    first = raw.find(b' (')
    end = raw.rfind(b') ')
    need(first > 0 and end > first and raw[:first] == str(expected_pid).encode(),
         'proc stat PID framing')
    fields = raw[end + 2:].split()
    need(len(fields) >= 20 and len(fields[0]) == 1 and
         fields[0] in (b'R', b'S', b'D', b'Z', b'T', b't', b'X', b'x', b'K', b'W', b'P', b'I'),
         'proc stat state and fields')
    numbers = []
    for index in (1, 2, 3, 19):
        need(re.fullmatch(b'[0-9]+', fields[index]) is not None,
             'proc stat unsigned identity field')
        numbers.append(int(fields[index]))
    parent, group, session, ticks = numbers
    need(expected_pid > 0 and group > 0 and session > 0 and ticks > 0,
         'positive proc generation')
    return {'pid': expected_pid, 'parent_pid': parent, 'state': fields[0].decode(),
            'identity': [expected_pid, group, session, ticks]}

def read_proc(pid):
    need(type(pid) is int and pid > 1, 'selected process PID only')
    path = '/proc/' + str(pid) + '/stat'
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as error:
        if error.errno == errno.ENOENT:
            return {'path': path, 'errno': errno.ENOENT, 'raw_b64': None, 'value': None}
        raise
    try:
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(4097)
        value = parse_stat(raw, pid)
        return {'path': path, 'errno': None,
                'raw_b64': base64.b64encode(raw).decode(), 'value': value}
    finally:
        os.close(fd)

def terminal_observation(observation, original):
    """Only monotonic loss of this exact generation can authorize a wait."""
    if observation['errno'] == errno.ENOENT:
        need(observation['value'] is None and observation['raw_b64'] is None,
             'ENOENT observation shape')
        return 'ORIGINAL_PID_ABSENT'
    need(observation['errno'] is None and observation['value'] is not None,
         'unknown errno is not absence')
    value = observation['value']
    need(value['pid'] == original[0], 'selected PID differs')
    if value['identity'][3] != original[3]:
        return 'ORIGINAL_GENERATION_REPLACED'
    need(value['identity'] == original, 'same start time but changed group/session')
    if value['state'] == 'Z':
        return 'ORIGINAL_CHILD_ZOMBIE'
    return None

def open_parent(path):
    path = Path(path)
    need(path.is_absolute() and str(path) == str(Path(str(path))) and '..' not in path.parts,
         'absolute path without traversal')
    parts = path.parts
    if parts[:4] == ('/', 'proc', '1', 'root'):
        fd = os.open('/proc/1/root', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        names = parts[4:]
    else:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        names = parts[1:]
    need(names and all(name not in ('', '.', '..') for name in names), 'file leaf required')
    try:
        for name in names[:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        return fd, names[-1]
    except BaseException:
        os.close(fd)
        raise

def read_regular(path, maximum=MAX_ORIGINAL, owner=None):
    parent, name = open_parent(path)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=parent)
    except BaseException:
        os.close(parent)
        raise
    try:
        before = metadata(os.fstat(fd))
        need(stat.S_ISREG(before[2]) and before[5] == 1 and 0 <= before[6] <= maximum,
             'bounded single-link regular original')
        if owner is not None:
            need(before[3:5] == list(owner) and stat.S_IMODE(before[2]) == 0o600,
                 'private original permissions')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        need(len(raw) == before[6] and before == metadata(os.fstat(fd)) ==
             metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)),
             'regular original full9 changed')
        return raw, {'path': str(path), **pin(raw), 'metadata': before}
    finally:
        os.close(fd)
        os.close(parent)

def publish(path, value, owner):
    raw = encoded(value)
    need(len(raw) <= MAX_ORIGINAL, 'bounded new owner receipt')
    parent, name = open_parent(path)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        try:
            need((os.fstat(fd).st_uid, os.fstat(fd).st_gid) == tuple(owner),
                 'new receipt ownership')
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)
    observed, row = read_regular(path, owner=owner)
    need(observed == raw, 'new receipt exact readback')
    return row

def helper_observation(env, parent):
    own = env.proc_reader(os.getpid())
    need(own['value'] is not None and own['value']['parent_pid'] == parent[0],
         'actual bounded helper parent relation')
    return own

def validate_probe(probe, original, parent, role, binding, sources, boot_id):
    need(probe['schema'] == 'hepta.resident-owner.pre-wait-observation.v1' and
         probe['boot_id'] == boot_id and probe['role'] == role and
         probe['pid'] == original[0] and probe['child_identity'] == original and
         probe['parent_identity'] == parent and probe['binding'] == binding and
         probe['sources'] == sources and probe['wait_called_by_helper'] is False and
         probe['signals_sent'] == 0, 'complete original pre-wait binding')
    first = terminal_observation(probe['before'], original)
    second = terminal_observation(probe['after'], original)
    need(probe['before_kind'] == first and probe['after_kind'] == second and
         probe['builtin_wait_permitted'] is (first is not None and second is not None),
         'pre-wait permission must be reconstructed from original proc observations')
    return probe['builtin_wait_permitted']

def descriptor(row):
    return {key: row[key] for key in ('path', 'bytes', 'sha256')}

class Environment:
    """Inputs supplied by the fixed phone CLI; host controls call this core directly."""
    def __init__(self, claim, logdir, service, helper, boot_id, owner=(0, 0),
                 proc_reader=read_proc, qualification='PHONE_SOURCE_UNQUALIFIED',
                 supervisor_output_paths=None):
        self.claim = Path(claim)
        self.logdir = Path(logdir)
        self.service = Path(service)
        self.helper = Path(helper)
        self.boot_id = boot_id
        self.owner = tuple(owner)
        self.proc_reader = proc_reader
        self.qualification = qualification
        self.originals = {}
        self.stop_deadline = None
        self.supervisor_output_paths = (dict(supervisor_output_paths) if supervisor_output_paths is not None
            else {stream: str(Path(SUPERVISOR_LOG_ROOT) / ('service.' + stream))
                  for stream in ('stdout', 'stderr')})
        need(set(self.supervisor_output_paths) == {'stdout', 'stderr'},
             'exact named supervisor output paths')

    def read(self, path, maximum=MAX_ORIGINAL, private=True):
        raw, row = read_regular(path, maximum, self.owner if private else None)
        previous = self.originals.get(str(path))
        need(previous is None or previous == row, 'receipt changed across one helper phase')
        self.originals[str(path)] = row
        return raw, row

    def source(self):
        result = {}
        for name, path in (('service', self.service), ('helper', self.helper)):
            raw, row = self.read(path, private=False)
            need(row['metadata'][3:5] == list(self.owner), 'selected source owner differs')
            result[name] = descriptor(row)
        return result

    def parent(self, expected):
        need(os.getppid() == expected[0], 'helper must be direct child of original service')
        before = self.proc_reader(expected[0])
        need(before['value'] is not None and before['value']['identity'] == expected and
             before['value']['state'] not in ('Z', 'X', 'x'), 'original service parent generation')
        return before

    def stop_window(self):
        now = time.clock_gettime(time.CLOCK_BOOTTIME)
        need(type(self.stop_deadline) in (int, float) and math.isfinite(self.stop_deadline)
             and 0 < self.stop_deadline - now <= 36.01,
             'remaining new observer window within original role cleanup')
        return {'deadline_boottime': self.stop_deadline, 'observed_boottime': now,
                'new_finalizer_total_ceiling_seconds': 36,
                'original_role_poll_count_ceiling_each': 12,
                'helper_phase_ceiling_seconds': PHASE_SECONDS}

    def file(self, role, suffix):
        need(role in ROLES and suffix in ('bind', 'probe', 'wait-intent', 'wait'),
             'fixed owner receipt name')
        return self.claim / ('owner-' + role + '.' + suffix + '.json')

    def recheck(self):
        for old in list(self.originals.values()):
            raw, row = read_regular(old['path'], max(MAX_ORIGINAL, old['bytes']))
            need(row == old, 'owner helper original bookend changed')

def binding_value(env, role, child, original, parent, expected_bind=None):
    raw, row = env.read(env.file(role, 'bind'))
    if expected_bind is not None:
        need(pin(raw)['sha256'] == expected_bind, 'service memory binding hash differs')
    value = strict(raw)
    need(value['schema'] == 'hepta.resident-owner.child-binding.v1' and
         value['boot_id'] == env.boot_id and value['role'] == role and
         value['pid'] == child and value['child_identity'] == original and
         value['parent_identity'] == parent and value['sources'] == env.source(),
         'exact original child binding')
    return value, descriptor(row)

def parent_fdinfo(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 4096 and raw.endswith(b'\n'),
         'complete bounded parent FD info')
    rows = [line.split(b':', 1) for line in raw.splitlines() if line.startswith(b'flags:')]
    need(len(rows) == 1 and re.fullmatch(b'[0-7]+', rows[0][1].strip()),
         'one original parent FD flags field')
    return int(rows[0][1].strip(), 8)

def read_parent_fdinfo(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(4097)
        parent_fdinfo(raw)
        return raw
    finally:
        os.close(fd)

def private_output_metadata(path, owner):
    parent, leaf = open_parent(path)
    fd = None
    try:
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=parent)
        value = metadata(os.fstat(fd))
        need(stat.S_ISREG(value[2]) and value[3:5] == list(owner) and
             stat.S_IMODE(value[2]) == 0o600 and value[5] == 1 and
             0 <= value[6] <= 16 * 1024 * 1024 and
             value == metadata(os.stat(leaf, dir_fd=parent, follow_symlinks=False)),
             'exact private named supervisor regular output')
        return value
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)

def observe_parent_outputs_at_bind(env, parent):
    began = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    rows = {}
    for number, stream in ((1, 'stdout'), (2, 'stderr')):
        first_at = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        path = '/proc/' + str(parent[0]) + '/fd/' + str(number)
        info_path = '/proc/' + str(parent[0]) + '/fdinfo/' + str(number)
        before = metadata(os.stat(path))
        raw_before = read_parent_fdinfo(info_path)
        flags = parent_fdinfo(raw_before)
        if stat.S_ISREG(before[2]):
            kind = 'regular_file'
            named = env.supervisor_output_paths[stream]
            named_before = private_output_metadata(named, env.owner)
            need(before == named_before,
                 'bind-time parent regular FD must be the specified service log inode')
        else:
            kind = ('pipe' if stat.S_ISFIFO(before[2]) else
                    'character_device' if stat.S_ISCHR(before[2]) else
                    'socket' if stat.S_ISSOCK(before[2]) else 'other_nonregular')
            named = None
            named_before = None
        raw_after = read_parent_fdinfo(info_path)
        after = metadata(os.stat(path))
        named_after = None if named is None else private_output_metadata(named, env.owner)
        need(before == after and raw_before == raw_after and
             parent_fdinfo(raw_after) == flags and named_before == named_after and
             (named_after is None or named_after == after),
             'parent FD/type/flags/full9 or named regular path changed during binding')
        rows[stream] = {'fd': number, 'kind': kind, 'proc_fd_path': path,
                        'before_full9': before, 'after_full9': after,
                        'fdinfo_before_b64': base64.b64encode(raw_before).decode(),
                        'fdinfo_after_b64': base64.b64encode(raw_after).decode(),
                        'flags': flags, 'specified_regular_path': named,
                        'path_before_full9': named_before, 'path_after_full9': named_after,
                        'observed_start_boottime_ns': first_at,
                        'observed_end_boottime_ns': time.clock_gettime_ns(time.CLOCK_BOOTTIME),
                        'pipe_eof_observed': None, 'regular_contents_read': False}
    return {'schema': 'hepta.resident-owner.parent-output-bind-observation.v1',
            'scope': 'DIRECT_PARENT_FD_AT_CHILD_BIND_ONLY',
            'parent_identity': parent, 'observed_start_boottime_ns': began,
            'observed_end_boottime_ns': time.clock_gettime_ns(time.CLOCK_BOOTTIME),
            'outputs': rows, 'installer_start_fd_identity_proven': False,
            'supervisor_original_parent_wait': 'NOT_RETAINED',
            'nonregular_outputs_remain_explicit_not_regular_log_credit': True,
            'complete_output_closure_qualified': False}

def bind_child(env, role, child, original, parent):
    need(role in ROLES and child == original[0] and child > 1, 'one original role PID')
    bind_began = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    parent_before = env.parent(parent)
    parent_outputs = observe_parent_outputs_at_bind(env, parent)
    first = env.proc_reader(child)
    need(first['value'] is not None and first['value']['identity'] == original and
         first['value']['parent_pid'] == parent[0] and first['value']['state'] not in ('Z', 'X', 'x'),
         'live direct original child required before admission')
    spawn_raw, spawn = env.read(env.claim / (role + '.spawn-pid'), 128)
    identity_raw, identity = env.read(env.claim / (role + '.identity'), 128)
    need(spawn_raw == (str(child) + '\n').encode() and
         identity_raw == (identity_text(original) + '\n').encode(),
         'original spawn and guard identity differ from service memory')
    log_rows = {}
    for fd_number, stream in ((1, 'stdout'), (2, 'stderr')):
        log = (env.logdir if role == 'sidecar' else env.claim) / (role + '.' + stream)
        raw, row = env.read(log, 0)
        need(raw == b'', 'new guarded role logs must be empty before admission')
        target = os.stat('/proc/' + str(child) + '/fd/' + str(fd_number))
        need(stat.S_ISREG(target.st_mode) and [target.st_dev, target.st_ino] == row['metadata'][:2],
             'original child output descriptor is not selected log inode')
        log_rows[stream] = row
    second = env.proc_reader(child)
    need(second['value'] is not None and second['value']['identity'] == original and
         second['value']['parent_pid'] == parent[0] and second['value']['state'] not in ('Z', 'X', 'x'),
         'original child changed during binding')
    parent_after = env.parent(parent)
    value = {'schema': 'hepta.resident-owner.child-binding.v1', 'role': role,
             'boot_id': env.boot_id, 'pid': child, 'child_identity': original,
             'parent_identity': parent, 'helper_observation': helper_observation(env, parent),
             'parent_output_bind_observation': parent_outputs,
             'bind_observation_interval_boottime_ns': [bind_began, time.clock_gettime_ns(time.CLOCK_BOOTTIME)],
             'spawn_original': spawn, 'identity_original': identity,
             'child_before': first, 'child_after': second, 'parent_before': parent_before,
             'parent_after': parent_after, 'regular_logs_initial': log_rows,
             'sources': env.source(), 'qualification': env.qualification,
             'task_qualification': False, 'signals_sent': 0, 'wait_called_by_helper': False}
    env.recheck()
    return publish(env.file(role, 'bind'), value, env.owner)

def probe_child(env, role, child, original, parent, expected_bind):
    stop_window = env.stop_window()
    parent_before = env.parent(parent)
    binding, binding_row = binding_value(env, role, child, original, parent, expected_bind)
    first = env.proc_reader(child)
    kind = terminal_observation(first, original)
    second = env.proc_reader(child)
    second_kind = terminal_observation(second, original)
    permitted = kind is not None and second_kind is not None
    value = {'schema': 'hepta.resident-owner.pre-wait-observation.v1',
             'boot_id': env.boot_id, 'role': role, 'pid': child,
             'child_identity': original, 'parent_identity': parent, 'binding': binding_row,
             'before': first, 'after': second, 'before_kind': kind, 'after_kind': second_kind,
             'parent_before': parent_before, 'parent_after': env.parent(parent),
             'helper_observation': helper_observation(env, parent),
             'builtin_wait_permitted': permitted, 'stop_window': stop_window,
             'wait_called_by_helper': False,
             'signals_sent': 0, 'sources': env.source()}
    env.recheck()
    probe_row = publish(env.file(role, 'probe'), value, env.owner)
    if permitted:
        intent = {'schema': 'hepta.resident-owner.original-wait-intent.v1',
                  'boot_id': env.boot_id, 'role': role, 'pid': child,
                  'child_identity': original, 'parent_identity': parent,
                  'binding': binding_row, 'terminal_probe': descriptor(probe_row),
                  'maximum_builtin_wait_calls': 1, 'parent_owned_memory_required': True,
                  'sources': env.source()}
        publish(env.file(role, 'wait-intent'), intent, env.owner)
    return descriptor(probe_row), permitted

def record_wait(env, role, child, original, parent, expected_bind, status):
    stop_window = env.stop_window()
    need(type(status) is int and 0 <= status <= 255, 'literal shell wait status')
    parent_before = env.parent(parent)
    binding, binding_row = binding_value(env, role, child, original, parent, expected_bind)
    intent_raw, intent_row = env.read(env.file(role, 'wait-intent'))
    intent = strict(intent_raw)
    probe_raw, probe_row = env.read(env.file(role, 'probe'))
    probe = strict(probe_raw)
    need(intent['schema'] == 'hepta.resident-owner.original-wait-intent.v1' and
         intent['binding'] == binding_row and intent['terminal_probe'] == descriptor(probe_row) and
         intent['pid'] == child and intent['child_identity'] == original and
         intent['parent_identity'] == parent and intent['maximum_builtin_wait_calls'] == 1 and
         probe['builtin_wait_permitted'] is True and probe['binding'] == binding_row,
         'original wait intent and terminal probe')
    need(validate_probe(probe, original, parent, role, binding_row, env.source(), env.boot_id),
         'original probe did not permit this wait')
    observed = env.proc_reader(child)
    kind = terminal_observation(observed, original)
    reaped = kind in ('ORIGINAL_PID_ABSENT', 'ORIGINAL_GENERATION_REPLACED')
    qualified = reaped and status != 127
    value = {'schema': 'hepta.resident-owner.original-child-wait.v1',
             'state': 'ORIGINAL_CHILD_WAIT_STATUS_RETAINED' if qualified else 'ORIGINAL_WAIT_UNQUALIFIED',
             'boot_id': env.boot_id, 'role': role, 'pid': child,
             'child_identity': original, 'parent_identity': parent, 'binding': binding_row,
             'wait_intent': descriptor(intent_row), 'terminal_probe': descriptor(probe_row),
             'shell_builtin_wait_status': status, 'stop_window': stop_window,
             'original_parent_builtin_wait_returned': True,
             'status_127_is_ambiguous': status == 127, 'old_generation_reaped_observed': reaped,
             'after_wait': observed, 'after_wait_kind': kind,
             'helper_observation': helper_observation(env, parent), 'parent_before': parent_before,
             'parent_after': env.parent(parent), 'source_controlled_parent_record': True,
             'stdout_pipe_eof_observed': None, 'stderr_pipe_eof_observed': None,
             'output_kind': 'regular_files', 'complete_log_writer_closure': False,
             'independent_fresh_absence_required': True, 'signals_sent_by_helper': 0,
             'sources': env.source(), 'qualification': env.qualification}
    env.recheck()
    return publish(env.file(role, 'wait'), value, env.owner)

def parse_memories(text):
    need(type(text) is str and len(text) <= 1024, 'bounded original service memory')
    rows = text.split(';')
    need(len(rows) == 3, 'exact three role memory rows')
    result = {}
    for role, row in zip(ROLES, rows):
        pieces = row.split(',')
        need(len(pieces) == 4 and pieces[0] == role, 'fixed memory role order')
        pid, identity, digest = pieces[1:]
        if not pid:
            need(identity == digest == '', 'unspawned role memory')
            result[role] = None
        else:
            need(re.fullmatch(r'[1-9][0-9]*', pid) and int(pid) > 1, 'memory child PID')
            if identity:
                parsed = parse_identity(identity)
                need(parsed[0] == int(pid), 'memory identity PID')
            else:
                parsed = None
            need(not digest or re.fullmatch(r'[0-9a-f]{64}', digest), 'memory binding SHA')
            result[role] = {'pid': int(pid), 'identity': parsed, 'binding_sha256': digest or None}
    return result

def record_supervisor(env, parent, memories, exit_status):
    stop_window = env.stop_window()
    need(type(exit_status) is int and 0 <= exit_status <= 255, 'original finish shell status')
    before = env.parent(parent)
    records = {}
    for role in ROLES:
        memory = memories[role]
        row = {'original_memory': memory, 'state': 'NOT_SPAWNED' if memory is None else 'UNKNOWN'}
        if memory is not None and memory['identity'] is not None and memory['binding_sha256']:
            try:
                binding, binding_row = binding_value(env, role, memory['pid'], memory['identity'],
                                                     parent, memory['binding_sha256'])
                wait_raw, wait_row = env.read(env.file(role, 'wait'))
                waited = strict(wait_raw)
                need(waited['binding'] == binding_row and waited['pid'] == memory['pid'] and
                     waited['child_identity'] == memory['identity'] and
                     waited['parent_identity'] == parent, 'terminal original wait generation')
                row.update(state=waited['state'], wait=descriptor(wait_row), binding=binding_row)
            except FileNotFoundError:
                row['state'] = 'UNKNOWN_MISSING_ORIGINAL_WAIT'
        records[role] = row
    value = {'schema': 'hepta.resident-owner.supervisor-self-terminal.v1',
             'state': 'SUPERVISOR_SELF_TERMINAL_INDEPENDENT_ABSENCE_REQUIRED',
             'boot_id': env.boot_id, 'parent_identity': parent, 'original_exit_status': exit_status,
             'stop_window': stop_window,
             'role_records': records, 'parent_before': before, 'parent_after': env.parent(parent),
             'helper_observation': helper_observation(env, parent),
             'original_parent_wait': 'NOT_RETAINED',
             'supervisor_absence_observed': False, 'regular_log_writer_closure': False,
             'full_effect_quiescence': False, 'pipe_eof_claimed': False,
             'sources': env.source(), 'qualification': env.qualification,
             'signals_sent_by_helper': 0}
    env.recheck()
    return publish(env.claim / 'owner-supervisor.terminal.json', value, env.owner)

def production_environment():
    need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
         'existing Root service only')
    need(Path('/proc/self/attr/current').read_text().strip('\0\n') == 'u:r:magisk:s0',
         'existing service domain')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot),
         'actual boot identity')
    root = Path('/proc/1/root')
    claim = root / HISTORY.lstrip('/') / boot
    logdir = root / EXECUTOR_HISTORY.lstrip('/') / boot
    module = root / MODULE.lstrip('/')
    for path in (claim, logdir, module):
        parent, name = open_parent(path)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=parent)
            try:
                info = os.fstat(fd)
                need(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                     'existing private service directory')
                if path == logdir:
                    need(os.getxattr(fd, 'security.selinux').rstrip(b'\0') == EXECUTOR_LABEL,
                         'existing sidecar log label')
            finally:
                os.close(fd)
        finally:
            os.close(parent)
    need(os.path.samefile(Path(__file__), module / 'resident_owner_terminal.py'),
         'helper must be the selected module file')
    return Environment(claim, logdir, module / 'service.sh', module / 'resident_owner_terminal.py', boot)

def expired(signum, frame):
    raise TimeoutError('bounded owner evidence phase')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('bind', 'probe', 'record-wait', 'terminal'))
    parser.add_argument('--parent-identity', required=True)
    parser.add_argument('--role', choices=ROLES)
    parser.add_argument('--pid', type=int)
    parser.add_argument('--identity')
    parser.add_argument('--binding-sha256')
    parser.add_argument('--wait-status', type=int)
    parser.add_argument('--memories')
    parser.add_argument('--exit-status', type=int)
    parser.add_argument('--stop-deadline', type=float)
    args = parser.parse_args()
    signal.signal(signal.SIGALRM, expired)
    # The absolute observer deadline is enforced before any production I/O.
    # Expiry never signals a role or supplies a synthetic wait status.
    try:
        if args.phase == 'bind':
            need(args.stop_deadline is None, 'startup binding has no stop deadline')
            budget = PHASE_SECONDS
        else:
            now = time.clock_gettime(time.CLOCK_BOOTTIME)
            need(args.stop_deadline is not None and math.isfinite(args.stop_deadline)
                 and 0 < args.stop_deadline - now <= 36.01,
                 'absolute observer window exhausted or invalid')
            budget = min(PHASE_SECONDS, args.stop_deadline - now)
        signal.setitimer(signal.ITIMER_REAL, budget)
        env = production_environment()
        if args.phase == 'bind':
            need(args.stop_deadline is None, 'startup binding has no stop deadline')
        else:
            env.stop_deadline = args.stop_deadline
            window = env.stop_window()
            remaining = window['deadline_boottime'] - time.clock_gettime(time.CLOCK_BOOTTIME)
            need(remaining > 0, 'stop window already exhausted')
            # Keep the first phase timer; do not grant another two seconds.
        parent = parse_identity(args.parent_identity)
        if args.phase == 'terminal':
            need(args.memories is not None and args.exit_status is not None,
                 'original terminal memory and status required')
            record_supervisor(env, parent, parse_memories(args.memories), args.exit_status)
            return 0
        need(args.role is not None and args.pid is not None and args.identity is not None,
             'original role memory required')
        original = parse_identity(args.identity)
        need(args.pid == original[0], 'original memory child PID')
        if args.phase == 'bind':
            bind_child(env, args.role, args.pid, original, parent)
            return 0
        need(args.binding_sha256 is not None and re.fullmatch(r'[0-9a-f]{64}', args.binding_sha256),
             'original parent memory binding SHA required')
        if args.phase == 'probe':
            row, permitted = probe_child(env, args.role, args.pid, original, parent, args.binding_sha256)
            return 0 if permitted else 4
        need(args.wait_status is not None, 'actual builtin wait status required')
        record_wait(env, args.role, args.pid, original, parent, args.binding_sha256, args.wait_status)
        return 0
    except BaseException as error:
        # No arbitrary exception message, user input or credentials are emitted.
        sys.stderr.write(json.dumps({'state': 'OWNER_EVIDENCE_UNKNOWN',
                                     'error_type': type(error).__name__,
                                     'role_or_supervisor_wait_replaced': False,
                                     'signals_sent_to_roles': 0}, sort_keys=True) + '\n')
        return 4
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)

if __name__ == '__main__':
    raise SystemExit(main())
