#!/usr/bin/env python3
"""Read-only original observer for selected resident log inodes.

Regular files are never labelled as pipe EOF. A complete result requires two
whole PID/FD censuses, absent selected groups, no matching writable descriptor,
and identical full file bytes/full9 at both ends. Permission/coverage/deadline
errors retain UNKNOWN. Production execution is unbound until an exact release
and original role/log inventory have been supplied and reviewed.
"""
import base64
import ctypes
import fcntl
import struct
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time
import types

sys.dont_write_bytecode = True
EXECUTION_BINDING = None
HELPER_PIN = {'bytes': 32701, 'sha256': '958d796590cbd4f1d8440f76fdd95a1b273237c3c78aa1db8696728a697ad55a'}
MAX_PIDS = 4096
MAX_FDS_PER_PID = 4096
MAX_FDS_TOTAL = 131072
MAX_LOG_BYTES = 16 * 1024 * 1024
MAX_LOG_TOTAL = 128 * 1024 * 1024
MAX_OBSERVATION_BYTES = 16 * 1024 * 1024
OBSERVATION_SECONDS = 30.0

def need(value, message):
    if not value:
        raise ValueError(message)

def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False,
                       separators=(',', ':'), allow_nan=False) + '\n').encode()

def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

def load_helper(raw, path):
    need(pin(raw) == HELPER_PIN, 'exact bounded evidence helper source')
    module = types.ModuleType('resident_owner_original_helpers')
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module

def census_stat(raw, pid):
    need(type(raw) is bytes and 0 < len(raw) <= 4096 and raw.endswith(b'\n'),
         'complete proc census stat')
    first, end = raw.find(b' ('), raw.rfind(b') ')
    need(first > 0 and end > first and raw[:first] == str(pid).encode(),
         'census PID framing')
    fields = raw[end + 2:].split()
    need(len(fields) >= 20 and fields[0] in
         (b'R', b'S', b'D', b'Z', b'T', b't', b'X', b'x', b'K', b'W', b'P', b'I'),
         'census state')
    values = []
    for index in (1, 2, 3, 19):
        need(re.fullmatch(b'[0-9]+', fields[index]), 'census unsigned field')
        values.append(int(fields[index]))
    # Kernel/init rows may legitimately have pgrp/session/start=0. The selected
    # resident identities are separately required positive and dedicated.
    return {'pid': pid, 'parent_pid': values[0], 'state': fields[0].decode(),
            'identity': [pid, values[1], values[2], values[3]]}

def fd_flags(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 4096 and raw.endswith(b'\n'),
         'bounded original fdinfo')
    rows = [line.split(b':', 1) for line in raw.splitlines() if line.startswith(b'flags:')]
    need(len(rows) == 1 and len(rows[0]) == 2 and re.fullmatch(b'[0-7]+', rows[0][1].strip()),
         'one original octal descriptor flags field')
    return int(rows[0][1].strip(), 8)

def proc_bytes(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(4097)
        need(0 < len(raw) <= 4096, 'bounded proc original')
        return raw
    finally:
        os.close(fd)

def numeric_entries(path, maximum):
    names = os.listdir(path)
    values = sorted(int(name) for name in names if name.isascii() and name.isdigit())
    need(len(values) == len(set(values)) <= maximum, 'complete bounded numeric inventory')
    return values

def directory_names(entries):
    need(type(entries) is list and len(entries) <= MAX_FDS_PER_PID + 2,
         'complete bounded directory entries')
    names = []
    for row in entries:
        need(set(row) == {'inode', 'offset', 'record_length', 'type', 'name'} and
             type(row['inode']) is int and 0 <= row['inode'] < 2**64 and
             type(row['offset']) is int and -(2**63) <= row['offset'] < 2**63 and
             type(row['record_length']) is int and 20 <= row['record_length'] <= 4096 and
             type(row['type']) is int and 0 <= row['type'] <= 255 and
             type(row['name']) is str and row['name'].isascii() and
             0 < len(row['name']) <= 255, 'original Linux LP64 dirent fields')
        name = row['name']
        need(name in ('.', '..') or re.fullmatch(r'0|[1-9][0-9]*', name),
             'only exact proc FD names')
        names.append(name)
    need(len(names) == len(set(names)), 'duplicate directory names')
    values = sorted(int(name) for name in names if name not in ('.', '..'))
    need(len(values) <= MAX_FDS_PER_PID, 'complete bounded FD inventory')
    return values

class HeldDirectory:
    """Keep the exact read-only directory stream open through both FD lists.

    CPython listdir(fd) duplicates and closes an enumeration FD. This explicit
    libc stream avoids that disappearing self slot. The supported production
    interpreter is GNU/Linux LP64 little-endian; unsupported ABIs fail closed.
    """
    def __init__(self, path):
        need(sys.platform == 'linux' and struct.calcsize('P') == 8 and
             struct.calcsize('l') == 8 and sys.byteorder == 'little',
             'reviewed Linux LP64 little-endian directory ABI')
        self.path = str(path)
        self.lib = ctypes.CDLL(None, use_errno=True)
        self.lib.fdopendir.argtypes = [ctypes.c_int]
        self.lib.fdopendir.restype = ctypes.c_void_p
        self.lib.readdir.argtypes = [ctypes.c_void_p]
        self.lib.readdir.restype = ctypes.c_void_p
        self.lib.rewinddir.argtypes = [ctypes.c_void_p]
        self.lib.rewinddir.restype = None
        self.lib.closedir.argtypes = [ctypes.c_void_p]
        self.lib.closedir.restype = ctypes.c_int
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            self.metadata = self.meta()
            self.flags = fcntl.fcntl(self.fd, fcntl.F_GETFL)
            need(stat.S_ISDIR(self.metadata[2]) and self.flags & os.O_ACCMODE == os.O_RDONLY,
                 'held enumeration descriptor is a read-only directory')
        except BaseException:
            os.close(self.fd)
            raise
        self.stream = self.lib.fdopendir(self.fd)
        if not self.stream:
            error = ctypes.get_errno()
            os.close(self.fd)
            raise OSError(error, 'fdopendir failed')
        self.closed = False

    def meta(self):
        value = os.fstat(self.fd)
        return [getattr(value, key) for key in
                ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                 'st_size', 'st_mtime_ns', 'st_ctime_ns')]

    def list(self, tick):
        need(not self.closed, 'held directory remains open')
        self.lib.rewinddir(self.stream)
        entries = []
        while True:
            tick()
            ctypes.set_errno(0)
            address = self.lib.readdir(self.stream)
            if not address:
                error = ctypes.get_errno()
                if error:
                    raise OSError(error, 'readdir failed')
                break
            inode, offset, length, kind = struct.unpack('<QqHB', ctypes.string_at(address, 19))
            need(20 <= length <= 4096, 'bounded actual directory record')
            raw = ctypes.string_at(address + 19, min(length - 19, 256))
            need(b'\0' in raw, 'complete directory name')
            name = raw.split(b'\0', 1)[0].decode('ascii')
            entries.append({'inode': inode, 'offset': offset, 'record_length': length,
                            'type': kind, 'name': name})
            need(len(entries) <= MAX_FDS_PER_PID + 2, 'bounded whole directory')
        return directory_names(entries), entries

    def close(self):
        if not self.closed:
            self.closed = True
            need(self.lib.closedir(self.stream) == 0, 'held directory close result')


def census_pass(proc_root, watched, selected, deadline):
    def tick():
        need(time.monotonic() <= deadline, 'original output census deadline')
    observer_pid = os.getpid()
    partial = {'pids_before': None, 'pids_after': None, 'processes': [],
               'fd_count': 0, 'writers': [], 'selected_group_members': [],
               'observer_pid': observer_pid, 'complete': False}
    try:
        tick()
        before = numeric_entries(proc_root, MAX_PIDS)
        need(observer_pid in before, 'observer belongs to this proc namespace')
        partial['pids_before'] = before
        rows = partial['processes']
        writers = partial['writers']
        group_members = partial['selected_group_members']
        total_fds = 0
        for pid in before:
            tick()
            entry = {'pid': pid, 'error_errno': None}
            rows.append(entry)
            directory = proc_root / str(pid)
            stream = None
            try:
                raw_before = proc_bytes(directory / 'stat')
                value_before = census_stat(raw_before, pid)
                entry['stat_before_b64'] = base64.b64encode(raw_before).decode()
                entry['stat_before'] = value_before
                if set(value_before['identity'][:3]) & selected:
                    group_members.append(value_before)
                stream = HeldDirectory(directory / 'fd')
                info_before = proc_bytes(proc_root / str(observer_pid) / 'fdinfo' / str(stream.fd))
                need(fd_flags(info_before) & os.O_ACCMODE == os.O_RDONLY,
                     'held directory raw flags are read-only')
                entry['census_directory'] = {
                    'path': stream.path, 'observer_pid': observer_pid, 'fd': stream.fd,
                    'metadata_before': stream.metadata, 'flags': stream.flags,
                    'fdinfo_before_b64': base64.b64encode(info_before).decode()}
                fds_before, entries_before = stream.list(tick)
                entry['fds_before'] = fds_before
                entry['directory_entries_before'] = entries_before
                observations = []
                entry['fds'] = observations
                for number in fds_before:
                    tick()
                    total_fds += 1
                    partial['fd_count'] = total_fds
                    need(total_fds <= MAX_FDS_TOTAL, 'total FD census bound')
                    fdrow = {'fd': number, 'errno': None}
                    observations.append(fdrow)
                    try:
                        target = os.stat(directory / 'fd' / str(number))
                        key = (target.st_dev, target.st_ino)
                        fdrow.update(dev=target.st_dev, ino=target.st_ino, mode=target.st_mode)
                        if key in watched:
                            info = proc_bytes(directory / 'fdinfo' / str(number))
                            flags = fd_flags(info)
                            after = os.stat(directory / 'fd' / str(number))
                            fdrow['after_target'] = {'dev': after.st_dev, 'ino': after.st_ino, 'mode': after.st_mode}
                            need((after.st_dev, after.st_ino, after.st_mode) ==
                                 (target.st_dev, target.st_ino, target.st_mode),
                                 'matching output FD changed during observation')
                            fdrow.update(log=watched[key], fdinfo_b64=base64.b64encode(info).decode(),
                                         flags=flags)
                            if flags & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR):
                                writers.append({'pid': pid, 'fd': number, 'log': watched[key],
                                                'dev': key[0], 'ino': key[1], 'flags': flags})
                        if pid == observer_pid and number == stream.fd:
                            need(stat.S_ISDIR(target.st_mode) and
                                 [target.st_dev, target.st_ino, target.st_mode] == stream.metadata[:3],
                                 'self enumeration FD is the retained read-only directory')
                            fdrow['held_self_directory'] = True
                    except OSError as error:
                        # No missing slot is converted into complete coverage.
                        # A number can close and be reused despite equal number lists.
                        fdrow['errno'] = error.errno
                        raise
                entry['fds_after'], entry['directory_entries_after'] = stream.list(tick)
                raw_after = proc_bytes(directory / 'stat')
                value_after = census_stat(raw_after, pid)
                entry['stat_after_b64'] = base64.b64encode(raw_after).decode()
                entry['stat_after'] = value_after
                info_after = proc_bytes(proc_root / str(observer_pid) / 'fdinfo' / str(stream.fd))
                entry['census_directory']['fdinfo_after_b64'] = base64.b64encode(info_after).decode()
                entry['census_directory']['metadata_after'] = stream.meta()
                need(stream.metadata == stream.meta() and
                     fd_flags(info_after) & os.O_ACCMODE == os.O_RDONLY,
                     'held enumeration directory identity and access unchanged')
                need(value_before['identity'] == value_after['identity'],
                     'process generation changed across FD census')
                need(entry['fds_before'] == entry['fds_after'], 'FD inventory changed across census')
                if pid == observer_pid:
                    need(sum(row.get('held_self_directory') is True for row in observations) == 1,
                         'complete observed self directory slot')
            except OSError as error:
                entry['error_errno'] = error.errno
                raise
            finally:
                if stream is not None:
                    stream.close()
        tick()
        after = numeric_entries(proc_root, MAX_PIDS)
        partial['pids_after'] = after
        need(before == after, 'PID inventory changed across full census')
        result = {'pids_before': before, 'pids_after': after, 'processes': rows,
                  'fd_count': total_fds, 'writers': writers, 'selected_group_members': group_members,
                  'observer_pid': observer_pid, 'complete': True}
        need(len(encoded(result)) <= MAX_OBSERVATION_BYTES, 'census original byte budget')
        return result
    except BaseException as error:
        partial.update(error_type=type(error).__name__, error_errno=getattr(error, 'errno', None))
        while len(encoded(partial)) > MAX_OBSERVATION_BYTES and partial['processes']:
            partial['processes'].pop()
            partial['partial_originals_truncated_to_bound'] = True
        return partial


def validate_selection(logs, identities):
    need(type(identities) is dict and set(identities) ==
         {'supervisor', 'model', 'sidecar', 'provider'},
         'exact four independently bound resident role identities')
    groups = set()
    for row in identities.values():
        need(type(row) is list and len(row) == 4 and
             all(type(n) is int and 0 < n < 2**64 for n in row) and
             row[0] == row[1] == row[2] and row[0] > 1,
             'positive exact PID/group/session/start identity')
        groups.add(row[0])
    need(len(groups) == 4, 'four distinct dedicated resident groups')
    need(type(logs) is list and 1 <= len(logs) <= 8, 'one to eight selected regular logs')
    names, paths, inodes = set(), set(), set()
    for row in logs:
        need(type(row) is dict and set(row) == {'name', 'path', 'initial_metadata'},
             'exact expected regular log descriptor')
        name, path, meta = row['name'], row['path'], row['initial_metadata']
        need(type(name) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}', name),
             'bounded unique log name')
        need(type(path) is str and path.startswith('/') and not path.startswith('//') and
             all(c not in path for c in ('\0', '\r', '\n', '\t')) and
             '..' not in PurePosixPath(path).parts and bool(PurePosixPath(path).name) and
             str(PurePosixPath(path)) == path,
             'canonical absolute exact log path')
        need(type(meta) is list and len(meta) == 9 and
             all(type(n) is int and 0 <= n < 2**64 for n in meta) and
             meta[1] > 0 and stat.S_ISREG(meta[2]) and meta[5] == 1 and meta[6] <= MAX_LOG_BYTES,
             'complete integer full9 of one regular single-link file')
        inode = tuple(meta[:2])
        need(name not in names and path not in paths and inode not in inodes,
             'no repeated log name, path or inode')
        names.add(name); paths.add(path); inodes.add(inode)
    return groups

def observe_regular_outputs(helper, logs, role_identities, *, proc_root=Path('/proc')):
    """Pure orchestration of read-only syscalls; caller supplies exact originals.

    The production entry remains UNBOUND. Host controls may use a private PID
    namespace and only their newly created log files; no current phone process
    or global phone state is used by those controls.
    """
    selected = validate_selection(logs, role_identities)
    began = time.monotonic()
    deadline = began + OBSERVATION_SECONDS
    originals = []
    watched = {}
    raw_logs = {}
    total_bytes = 0
    for row in logs:
        need(set(row) == {'name', 'path', 'initial_metadata'} and
             len(row['initial_metadata']) == 9, 'exact original log inode descriptor')
        raw, observed = helper.read_regular(row['path'], MAX_LOG_BYTES)
        need(observed['metadata'][:6] == row['initial_metadata'][:6],
             'selected original log inode or permissions changed')
        key = tuple(observed['metadata'][:2])
        need(key not in watched, 'distinct original log inodes')
        watched[key] = row['name']
        total_bytes += len(raw)
        need(total_bytes <= MAX_LOG_TOTAL, 'complete final log byte budget')
        originals.append({'name': row['name'], 'original': observed})
        raw_logs[row['name']] = raw
    result = {'schema': 'hepta.resident-owner.regular-output-observation.v1',
              'state': 'OUTPUT_PROOF_UNKNOWN', 'complete': False,
              'role_identities': role_identities, 'regular_logs': originals, 'regular_logs_final': [], 'passes': [],
              'stdout_pipe_eof_observed': None, 'stderr_pipe_eof_observed': None,
              'output_kind': 'regular_files', 'signals_sent': 0, 'processes_started': 0,
              'phone_qualification': False, 'whole_rollback_qualified': False}
    try:
        for _ in range(2):
            sweep = census_pass(proc_root, watched, selected, deadline)
            result['passes'].append(sweep)
            need(sweep['complete'] is True, 'partial original census is not closure')
        for row in originals:
            raw, observed = helper.read_regular(row['original']['path'], MAX_LOG_BYTES)
            result['regular_logs_final'].append({'name': row['name'], 'original': observed})
            need(raw == raw_logs[row['name']] and observed == row['original'],
                 'final regular log bytes or full9 changed across both censuses')
        need(time.monotonic() <= deadline, 'complete output observation deadline')
        no_writers = all(not sweep['writers'] for sweep in result['passes'])
        groups_absent = all(not sweep['selected_group_members'] for sweep in result['passes'])
        result.update(complete=True, no_matching_writable_fds=no_writers,
                      selected_groups_and_sessions_absent=groups_absent,
                      full_regular_bytes_and_full9_stable=True,
                      state='REGULAR_WRITERS_CLOSED_OBSERVED' if no_writers and groups_absent
                            else 'REGULAR_WRITER_OR_SELECTED_GROUP_PRESENT')
    except BaseException as error:
        result.update(error_type=type(error).__name__, error_errno=getattr(error, 'errno', None),
                      state='OUTPUT_PROOF_UNKNOWN', complete=False,
                      no_matching_writable_fds=False, selected_groups_and_sessions_absent=False,
                      full_regular_bytes_and_full9_stable=False)
    result['elapsed_seconds'] = time.monotonic() - began
    result['regular_log_total_bytes'] = total_bytes
    need(len(encoded(result)) <= MAX_OBSERVATION_BYTES, 'full output observation budget')
    return result, raw_logs

def verify_observation(helper, value, logs, identities, *, read_pinned):
    validate_selection(logs, identities)
    need(value['schema'] == 'hepta.resident-owner.regular-output-observation.v1' and
         value['state'] == 'REGULAR_WRITERS_CLOSED_OBSERVED' and value['complete'] is True and
         value['role_identities'] == identities and value['output_kind'] == 'regular_files' and
         value['stdout_pipe_eof_observed'] is None and value['stderr_pipe_eof_observed'] is None and
         value['signals_sent'] == value['processes_started'] == 0 and
         value['phone_qualification'] is False and value['whole_rollback_qualified'] is False,
         'complete typed regular-file observation only')
    need(type(value['elapsed_seconds']) in (int, float) and
         0 <= value['elapsed_seconds'] <= OBSERVATION_SECONDS, 'bounded full observation')
    expected = {row['name']: row for row in logs}
    need(len(value['regular_logs']) == len(expected) and
         {row['name'] for row in value['regular_logs']} == set(expected),
         'complete selected log set')
    need(type(value['regular_logs_final']) is list and
         value['regular_logs_final'] == value['regular_logs'],
         'actual final whole-file descriptors/full9 must equal the first originals')
    watched = {}
    total = 0
    for entry in value['regular_logs']:
        row = entry['original']
        wanted = expected[entry['name']]
        need(type(row['metadata']) is list and len(row['metadata']) == 9 and
             all(type(n) is int and 0 <= n < 2**64 for n in row['metadata']) and
             type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_LOG_BYTES,
             'actual regular-log descriptor has exact integer full9 and byte count')
        need(row['path'] == wanted['path'] and row['metadata'][:6] == wanted['initial_metadata'][:6],
             'original regular log inode binding')
        raw = read_pinned({key: row[key] for key in ('path', 'bytes', 'sha256')})
        need(type(raw) is bytes and pin(raw) == {key: row[key] for key in ('bytes', 'sha256')}
             and len(raw) <= MAX_LOG_BYTES and row['metadata'][6] == len(raw),
             'complete regular log original bytes')
        watched[tuple(row['metadata'][:2])] = entry['name']
        total += len(raw)
    need(len(watched) == len(expected) and total == value['regular_log_total_bytes'] <= MAX_LOG_TOTAL,
         'regular log total and distinct inodes')
    selected = {identity[0] for identity in identities.values()}
    need(len(value['passes']) == 2, 'two complete independent census passes')
    for sweep in value['passes']:
        pids = sweep['pids_before']
        need(pids == sweep['pids_after'] == sorted(set(pids)) and len(pids) <= MAX_PIDS and
             len(sweep['processes']) == len(pids) and sweep['complete'] is True,
             'complete full PID census')
        need(type(sweep['observer_pid']) is int and sweep['observer_pid'] in pids,
             'actual observer PID in the complete namespace')
        count = 0
        for pid, process in zip(pids, sweep['processes']):
            need(type(pid) is int and pid > 0 and process['pid'] == pid and process['error_errno'] is None,
                 'complete process observation')
            before = census_stat(base64.b64decode(process['stat_before_b64'], validate=True), pid)
            after = census_stat(base64.b64decode(process['stat_after_b64'], validate=True), pid)
            need(process['stat_before'] == before and process['stat_after'] == after and
                 before['identity'] == after['identity'] and
                 not (set(before['identity'][:3]) & selected) and
                 not (set(after['identity'][:3]) & selected), 'original selected groups/sessions absent')
            held = process['census_directory']
            need(held['observer_pid'] == sweep['observer_pid'] and
                 held['path'] == '/proc/' + str(pid) + '/fd' and
                 type(held['fd']) is int and held['fd'] >= 0 and
                 len(held['metadata_before']) == 9 and
                 held['metadata_before'] == held['metadata_after'] and
                 stat.S_ISDIR(held['metadata_before'][2]) and
                 type(held['flags']) is int and held['flags'] & os.O_ACCMODE == os.O_RDONLY and
                 fd_flags(base64.b64decode(held['fdinfo_before_b64'], validate=True)) & os.O_ACCMODE == os.O_RDONLY and
                 fd_flags(base64.b64decode(held['fdinfo_after_b64'], validate=True)) & os.O_ACCMODE == os.O_RDONLY,
                 'retained read-only enumeration directory original')
            fds = process['fds_before']
            need(directory_names(process['directory_entries_before']) == fds and
                 directory_names(process['directory_entries_after']) == process['fds_after'],
                 'whole FD inventories reconstructed from held directory entries')
            need(fds == process['fds_after'] == sorted(set(fds)) and len(fds) <= MAX_FDS_PER_PID and
                 len(process['fds']) == len(fds), 'complete descriptor census')
            for number, observed in zip(fds, process['fds']):
                count += 1
                need(type(number) is int and number >= 0 and observed['fd'] == number,
                     'exact FD inventory')
                need(observed['errno'] is None, 'every FD slot must be observed; ENOENT is not coverage')
                need(all(type(observed[key]) is int and 0 <= observed[key] < 2**64
                         for key in ('dev', 'ino', 'mode')), 'kernel FD metadata types')
                key = (observed['dev'], observed['ino'])
                if key in watched:
                    need(observed['log'] == watched[key] and stat.S_ISREG(observed['mode']),
                         'selected regular inode observation')
                    after = observed['after_target']
                    need(type(after) is dict and set(after) == {'dev', 'ino', 'mode'} and
                         all(type(after[k]) is int for k in after) and
                         [after['dev'], after['ino'], after['mode']] ==
                         [observed['dev'], observed['ino'], observed['mode']],
                         'actual second watched-FD stat must equal its original target')
                    flags = fd_flags(base64.b64decode(observed['fdinfo_b64'], validate=True))
                    need(type(observed['flags']) is int and observed['flags'] == flags and
                         flags & os.O_ACCMODE == os.O_RDONLY,
                         'matching writable FD still present')
            if pid == sweep['observer_pid']:
                own = [row for row in process['fds'] if row['fd'] == held['fd']]
                need(len(own) == 1 and own[0].get('held_self_directory') is True and
                     [own[0]['dev'], own[0]['ino'], own[0]['mode']] == held['metadata_before'][:3] and
                     stat.S_ISDIR(own[0]['mode']),
                     'self enumeration slot observed as the retained directory')
        need(count == sweep['fd_count'] <= MAX_FDS_TOTAL and sweep['writers'] == [] and
             sweep['selected_group_members'] == [], 'reconstructed complete empty writer/group sets')
    need(value['no_matching_writable_fds'] is True and value['selected_groups_and_sessions_absent'] is True and
         value['full_regular_bytes_and_full9_stable'] is True, 'full typed observation flags')
    return {'state': 'VERIFIED_REGULAR_WRITERS_CLOSED_OBSERVATION',
            'log_count': len(expected), 'log_bytes': total,
            'pipe_eof_claimed': False, 'whole_rollback_qualified': False,
            'complete_eight_resident_stream_bindings_required_from_caller': True,
            'this_verdict_covers_only_exact_regular_log_selector': True}

def main():
    need(EXECUTION_BINDING is not None, 'UNBOUND_PRODUCTION_OUTPUT_OBSERVER_NO_IO')
    raise RuntimeError('Actual production binding and one-use wrapper remain required')

if __name__ == '__main__':
    main()
