#!/usr/bin/env python3
"""Create three pinned source files in one new fixed Mac directory, once.

This stages data only. It does not import or execute the staged sources, invoke
the auditor, start a subprocess, access the network, or call the phone. Partial
outputs are retained. Independent external whole-body readback is still needed.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time

BASE = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/'
            'stock16-hepta-local-model-Root-v150-r1')
DEST = BASE/'epoch-policy-history-audit-source-1ad3-02-dirguard-4b572de398a74ce0'
AUDIT_OUT = BASE/'epoch-policy-history-audit-1ad3-02-dirguard-4b572de398a74ce0'
CALLER_OUT = BASE/'epoch-policy-history-audit-owned-1ad3-02-dirguard-4b572de398a74ce0'
OWNER_UID = 501
STAGE_KEY = 'hepta-cp09-audit02-source-stage-dirguard-4b572de398a74ce0'
EXPECTED = {
    'SOURCE-MANIFEST.json': (608, 'd23837daefb96368544889a4a4c1a87fd4cada74c3edb7b092ea74f6cc75b57f'),
    'audit_policy_history_once.py': (30525, '4cc7bdf1aac2325518724a973c74b89f5788ccb84932b82beacac4b2aad78b86'),
    'run_policy_history_owned_once.py': (54516, '9f5c8555c781bde2950bd44b7659225ebc6889027f6bc26c64a72c9d9b25235c')}
PAYLOAD_PIN = {'bytes': 114386, 'sha256': '75213e221fe5366946f16894f69354e70c9a205e5f1679429f9308875615e71e'}
LIMITS = {'seconds': 18, 'terminal_seconds': 1, 'stdin_bytes': 262144, 'source_body_bytes': 65536,
          'source_pool_bytes': 131072, 'source_write_bytes': 85649,
          'physical_source_read_bytes': 171304, 'parent_depth': 24,
          'owned_fds': 64, 'base_names_per_snapshot': 4096,
          'name_utf8_bytes': 1024, 'directory_entries_observed': 8256,
          'names_and_receipt_bytes': 524288, 'stdout_bytes': 262144}


def need(value, message):
    if not value:
        raise ValueError(message)


class StageAlarm(BaseException):
    """A terminal alarm must not be swallowed by an OSError cleanup handler."""


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}


def meta(value):
    return [getattr(value, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
            'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')]


def wire(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(',', ':'), allow_nan=False)+'\n').encode('utf-8', 'strict')


def strict(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate JSON field')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: need(False, 'nonfinite JSON value'))


def parent_names_wire(value):
    return (json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode('utf-8','strict')


def parent_names_decode(value):
    need(type(value) is dict and set(value)=={'schema','encoding','count','decoded','rows'}
        and value['schema']=='hepta.directory-name-prefix-table.v1'
        and value['encoding']=='unicode-prefix-length-and-suffix',
        'fixed parent name data encoding required')
    need(type(value['count']) is int and 0<=value['count']<=4096
        and type(value['rows']) is list and len(value['rows'])==value['count'],
        'original name count bound exceeded')
    descriptor=value['decoded']
    need(type(descriptor) is dict and set(descriptor)=={'bytes','sha256'} and type(descriptor['bytes']) is int
        and 3<=descriptor['bytes']<=524288 and type(descriptor['sha256']) is str
        and re.fullmatch('[0-9a-f]{64}',descriptor['sha256']),
        'bounded full decoded name descriptor required')
    need(len(parent_names_wire(value))<=65536,'prefix data exceeds original serialized field bound')
    names=[];previous='';decoded_charge=3
    for row in value['rows']:
        need(type(row) is list and len(row)==2 and type(row[0]) is int
            and 0<=row[0]<=len(previous) and type(row[1]) is str,
            'typed bounded prefix/suffix row required')
        name=previous[:row[0]]+row[1]
        need(name and '/' not in name and '\x00' not in name and name not in ('.','..')
            and (not names or previous<name),'complete names must be strict sorted unique basenames')
        common=0
        while common<min(len(previous),len(name)) and previous[common]==name[common]:common+=1
        need(row[0]==common,'prefix length must be canonical maximal common prefix')
        decoded_charge+=len(parent_names_wire(name))-1+(1 if names else 0)
        need(decoded_charge<=descriptor['bytes']<=524288,'decoded names exceed bounded original bytes')
        names.append(name);previous=name
    raw=parent_names_wire(names)
    need(len(raw)==descriptor['bytes'] and sha(raw)==descriptor['sha256'],'complete decoded names bytes/SHA differ')
    return names


def parent_names_encode(names):
    need(type(names) is list and len(names)<=4096 and all(type(x) is str for x in names)
        and names==sorted(set(names)),'original complete name count/order differs')
    raw=parent_names_wire(names)
    need(len(raw)<=524288,'complete decoded parent names exceed the shared metadata pool')
    rows=[];previous=''
    for name in names:
        common=0
        while common<min(len(previous),len(name)) and previous[common]==name[common]:common+=1
        rows.append([common,name[common:]]);previous=name
    value={'schema':'hepta.directory-name-prefix-table.v1','encoding':'unicode-prefix-length-and-suffix',
        'count':len(names),'decoded':{'bytes':len(raw),'sha256':sha(raw)},'rows':rows}
    need(len(parent_names_wire(value))<=65536 and parent_names_decode(value)==names,
        'lossless complete prefix data exceeds original serialized field bound')
    return value


def verify_body_pins(bodies):
    need(type(bodies) is dict and set(bodies) == set(EXPECTED), 'exact three source bodies required')
    for name, (size, digest) in EXPECTED.items():
        need(type(bodies[name]) is bytes and pin(bodies[name]) == {'bytes': size, 'sha256': digest},
             'fixed complete source body differs')
    need(sum(map(len, bodies.values())) <= LIMITS['source_pool_bytes'], 'source byte pool exceeded')


def decode_payload(raw):
    need(type(raw) is bytes and len(raw) <= LIMITS['stdin_bytes'] and pin(raw) == PAYLOAD_PIN,
         'independently pinned complete transport differs')
    value = strict(raw)
    need(type(value) is dict and set(value) == {'schema', 'files'}
         and value['schema'] == 'hepta.fixed-policy-source-stage.v1'
         and type(value['files']) is dict and set(value['files']) == set(EXPECTED),
         'fixed source transport closure differs')
    bodies = {}
    for name, (size, digest) in EXPECTED.items():
        encoded = value['files'][name]
        need(type(encoded) is str and len(encoded) <= 4*((LIMITS['source_body_bytes']+2)//3),
             'bounded source base64 required')
        raw_body = base64.b64decode(encoded, validate=True)
        need(base64.b64encode(raw_body).decode('ascii') == encoded, 'noncanonical source base64')
        raw_body.decode('utf-8', 'strict')
        bodies[name] = raw_body
    verify_body_pins(bodies)
    expected_manifest = {'schema': 'hepta.native-guard.policy-history-owned-source.v1',
        'target_root': str(DEST), 'files': [{'path': name, 'bytes': EXPECTED[name][0],
        'sha256': EXPECTED[name][1]} for name in sorted(EXPECTED) if name.endswith('.py')]}
    need(strict(bodies['SOURCE-MANIFEST.json']) == expected_manifest, 'actual three-member source closure differs')
    return bodies


class Budget:
    def __init__(self):
        self.started = time.monotonic()
        self.physical_read_bytes = 0
        self.source_write_bytes = 0
        self.directory_entries = 0
        self.names_decoded_bytes = 0
        self.names_encoded_bytes = 0
        self.peak_owned_fds = 0

    def check(self):
        need(time.monotonic()-self.started < LIMITS['seconds'], 'single source staging deadline exceeded')

    def reserve_names(self, data, *, charge):
        decoded = data['decoded']['bytes']
        encoded = len(parent_names_wire(data))
        need(self.names_decoded_bytes+self.names_encoded_bytes+decoded+encoded+LIMITS['stdout_bytes']
             <= LIMITS['names_and_receipt_bytes'], 'complete names and receipt reservation exceeded')
        if charge:
            self.names_decoded_bytes += decoded
            self.names_encoded_bytes += encoded


class Stager:
    def __init__(self, bodies, budget):
        verify_body_pins(bodies)
        self.bodies = bodies
        self.budget = budget
        self.fds = []
        self.fd_operations = []
        self.fd_operation_sequence = 0
        self.phase = 'three-target-absence'
        self.created = False
        self.created_files = []
        self.files = {}
        self.members = set()
        self.parent_fds = []
        self.parents_before = None
        self.parents_after = None
        self.names_before_data = None
        self.names_after_data = None
        self.source_fd = None
        self.source_identity = None
        self.cleanup_errors = []

    def reserve_fd(self, extra=1):
        need(len(self.fds)+extra <= LIMITS['owned_fds'], 'owned source-stage FD bound exceeded')
        self.budget.peak_owned_fds = max(self.budget.peak_owned_fds, len(self.fds)+extra)

    def begin_fd_operation(self, operation, *, fd=None, path=None):
        self.fd_operation_sequence += 1
        marker = {'sequence': self.fd_operation_sequence, 'operation': operation,
                  'state': 'IN_FLIGHT_OR_COMPLETION_UNCERTAIN'}
        if fd is not None:
            marker['fd'] = fd
        if path is not None:
            marker['path'] = os.fspath(path)[:4096]
        # This marker exists before acquiring, removing or closing ownership.
        # An asynchronous exception cannot turn an empty registry into proof
        # that the kernel never returned a descriptor or certainly closed it.
        self.fd_operations.append(marker)
        return marker

    def finish_fd_operation(self, marker):
        self.fd_operations.remove(marker)

    def uncertain_fd_operation(self, marker, error):
        marker['error_type'] = type(error).__name__
        marker['message'] = str(error)[:128]

    def open(self, path, flags, mode=0o777, *, dir_fd=None):
        self.budget.check()
        self.reserve_fd()
        marker = self.begin_fd_operation('open-and-register', path=path)
        try:
            fd = os.open(path, flags, mode, dir_fd=dir_fd)
            self.fds.append(fd)
        except BaseException as error:
            self.uncertain_fd_operation(marker, error)
            raise
        self.finish_fd_operation(marker)
        return fd

    def close_fd(self, fd):
        need(fd in self.fds, 'unowned source-stage descriptor close')
        marker = self.begin_fd_operation('remove-and-close', fd=fd)
        try:
            self.fds.remove(fd)
            os.close(fd)
        except BaseException as error:
            self.uncertain_fd_operation(marker, error)
            self.cleanup_errors.append({'fd': fd, 'type': type(error).__name__, 'message': str(error)[:128]})
            raise
        self.finish_fd_operation(marker)

    def close(self):
        while self.fds:
            try:
                self.close_fd(self.fds[-1])
            except OSError:
                # The failed FD was removed before its ambiguous close. Never
                # retry that numeric FD; retain its unresolved marker instead.
                continue

    def open_chain(self):
        need(BASE.is_absolute() and '..' not in BASE.parts and len(BASE.parts) <= LIMITS['parent_depth'],
             'fixed bounded source parent chain required')
        fds = [self.open('/', os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)]
        rows = [{'path': '/', 'metadata': meta(os.fstat(fds[0]))}]
        at = Path('/')
        for part in BASE.parts[1:]:
            self.budget.check()
            named = os.stat(part, dir_fd=fds[-1], follow_symlinks=False)
            need(stat.S_ISDIR(named.st_mode), 'ordinary no-follow parent required')
            fd = self.open(part, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=fds[-1])
            need(meta(os.fstat(fd)) == meta(named)
                 == meta(os.stat(part, dir_fd=fds[-1], follow_symlinks=False)), 'parent changed at open')
            fds.append(fd)
            at /= part
            rows.append({'path': str(at), 'metadata': meta(named)})
        need(rows[-1]['metadata'][3] == OWNER_UID
             and stat.S_IMODE(rows[-1]['metadata'][2]) == 0o700, 'private owned BASE required')
        return fds, rows

    def check_chain(self, fds, reference, *, base_may_change):
        self.budget.check()
        need(len(fds) == len(reference), 'parent descriptor sequence differs')
        for index, (fd, row) in enumerate(zip(fds, reference)):
            current = meta(os.fstat(fd))
            if index == 0:
                named = meta(os.stat('/', follow_symlinks=False))
            else:
                named = meta(os.stat(Path(row['path']).name, dir_fd=fds[index-1], follow_symlinks=False))
            need(current == named, 'current parent held/named full9 differs')
            expected = row['metadata']
            if base_may_change and row['path'] == str(BASE):
                need(current[:5] == expected[:5], 'BASE identity or permissions changed')
            else:
                need(current == expected, 'ordinary parent full9 changed')

    def bounded_names(self, fd, *, maximum, base_snapshot=False):
        self.budget.check()
        self.reserve_fd()  # scandir may hold one duplicate of the supplied FD.
        before = meta(os.fstat(fd))
        names = []
        decoded_charge = 3
        marker = self.begin_fd_operation('scandir-context-acquire-use-close', fd=fd)
        try:
            with os.scandir(fd) as iterator:
                for entry in iterator:
                    self.budget.check()
                    self.budget.directory_entries += 1
                    need(self.budget.directory_entries <= LIMITS['directory_entries_observed']
                         and len(names) < maximum, 'directory enumeration entry bound exceeded')
                    name = entry.name
                    need(type(name) is str and name and '/' not in name and '\0' not in name
                         and name not in ('.', '..') and len(name.encode('utf-8', 'strict')) <= LIMITS['name_utf8_bytes'],
                         'bounded reversible directory basename required')
                    decoded_charge += len(parent_names_wire(name))-1+(1 if names else 0)
                    remaining = (LIMITS['names_and_receipt_bytes']-LIMITS['stdout_bytes']
                                 -self.budget.names_decoded_bytes-self.budget.names_encoded_bytes)
                    need(decoded_charge <= (remaining if base_snapshot else 2048),
                         'directory name bytes exceed remaining bounded pool')
                    names.append(name)
        except BaseException as error:
            self.uncertain_fd_operation(marker, error)
            raise
        self.finish_fd_operation(marker)
        need(meta(os.fstat(fd)) == before, 'directory changed during complete enumeration')
        names.sort()
        need(len(names) == len(set(names)) and len(parent_names_wire(names)) == decoded_charge,
             'complete unique name encoding differs')
        if base_snapshot:
            data = parent_names_encode(names)
            self.budget.reserve_names(data, charge=True)
            return names, data
        return names

    def absent(self, base_fd, targets):
        for path in targets:
            self.budget.check()
            need(path.parent == BASE, 'only fixed direct target names allowed')
            try:
                os.stat(path.name, dir_fd=base_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError('fixed target already exists; no dispatch, cleanup, retry or suffix: '+path.name)

    def source_check(self, *, directory_full9=None):
        self.budget.check()
        self.check_chain(self.parent_fds, self.parents_before, base_may_change=True)
        held = meta(os.fstat(self.source_fd))
        named = meta(os.stat(DEST.name, dir_fd=self.parent_fds[-1], follow_symlinks=False))
        need(held == named and held[:5] == self.source_identity[:5], 'owned source directory identity changed')
        if directory_full9 is not None:
            need(held == directory_full9, 'completed source directory full9 changed')
        need(self.bounded_names(self.source_fd, maximum=3) == sorted(self.members),
             'owned source directory member closure differs')
        for name, row in self.files.items():
            need(meta(os.stat(name, dir_fd=self.source_fd, follow_symlinks=False)) == row['metadata'],
                 'completed source file full9 changed')

    def read_file(self, directory_fd, name, expected_metadata):
        self.budget.check()
        body = self.bodies[name]
        first = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        identity = meta(first)
        need(identity == expected_metadata and stat.S_ISREG(first.st_mode) and first.st_uid == OWNER_UID
             and stat.S_IMODE(first.st_mode) == 0o600 and first.st_nlink == 1 and first.st_size == len(body),
             'staged source regular single-link full9 differs')
        fd = self.open(name, os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=directory_fd)
        try:
            need(meta(os.fstat(fd)) == identity, 'staged source changed at independent read open')
            pieces = []
            total = 0
            while True:
                self.budget.check()
                room = LIMITS['physical_source_read_bytes']-self.budget.physical_read_bytes
                need(room > 0, 'stager physical read pool exhausted before read')
                part = os.read(fd, min(65536, len(body)+1-total, room))
                self.budget.physical_read_bytes += len(part)
                if not part:
                    break
                total += len(part)
                need(total <= len(body), 'staged source grew during readback')
                pieces.append(part)
            need(b''.join(pieces) == body and meta(os.fstat(fd)) == identity
                 == meta(os.stat(name, dir_fd=directory_fd, follow_symlinks=False)),
                 'staged complete source body/full9 readback differs')
            return {'path': str(DEST/name), **pin(body), 'metadata': identity}
        finally:
            self.close_fd(fd)

    def write_file(self, name, body):
        self.source_check()
        self.phase = 'create-and-write:'+name
        fd = self.open(name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
                       0o600, dir_fd=self.source_fd)
        self.created_files.append(name)
        self.members.add(name)
        try:
            first = os.fstat(fd)
            need(stat.S_ISREG(first.st_mode) and first.st_uid == OWNER_UID and first.st_nlink == 1
                 and stat.S_IMODE(first.st_mode) == 0o600 and first.st_size == 0
                 and meta(first) == meta(os.stat(name, dir_fd=self.source_fd, follow_symlinks=False)),
                 'new private single-link source leaf differs')
            count = 0
            while count < len(body):
                self.budget.check()
                room = LIMITS['source_write_bytes']-self.budget.source_write_bytes
                need(room > 0, 'source write pool exhausted before write')
                portion = body[count:count+min(65536, room)]
                written = os.write(fd, portion)
                need(0 < written <= len(portion), 'source write made no bounded progress')
                count += written
                self.budget.source_write_bytes += written
            os.fsync(fd)
            final = os.fstat(fd)
            need(meta(final)[:6] == meta(first)[:6] and final.st_size == len(body)
                 and meta(final) == meta(os.stat(name, dir_fd=self.source_fd, follow_symlinks=False)),
                 'created source changed identity during write')
            expected_metadata = meta(final)
        finally:
            self.close_fd(fd)
        os.fsync(self.source_fd)
        self.phase = 'first-independent-read:'+name
        self.files[name] = self.read_file(self.source_fd, name, expected_metadata)

    def run(self):
        try:
            result = self._run()
        finally:
            self.close()
        need(not self.cleanup_errors and not self.fd_operations, 'owned staging descriptor cleanup failed or uncertain')
        self.budget.check()
        result['owned_fds_closed'] = True
        result['cleanup_errors'] = self.cleanup_errors
        result['descriptor_operations_unresolved'] = self.fd_operations
        return result

    def _run(self):
        self.parent_fds, self.parents_before = self.open_chain()
        self.check_chain(self.parent_fds, self.parents_before, base_may_change=False)
        targets = (DEST, AUDIT_OUT, CALLER_OUT)
        self.absent(self.parent_fds[-1], targets)
        names_before, self.names_before_data = self.bounded_names(self.parent_fds[-1],
            maximum=LIMITS['base_names_per_snapshot'], base_snapshot=True)
        need(not any(path.name in names_before for path in targets), 'fixed target appeared in initial complete names')
        need(len(names_before)+1 <= LIMITS['base_names_per_snapshot'], 'new source would exceed complete name count bound')
        projected_names = parent_names_encode(sorted(names_before+[DEST.name]))
        self.budget.reserve_names(projected_names, charge=False)
        self.check_chain(self.parent_fds, self.parents_before, base_may_change=False)
        self.absent(self.parent_fds[-1], targets)
        self.phase = 'create-only-source-directory'
        os.mkdir(DEST.name, 0o700, dir_fd=self.parent_fds[-1])
        self.created = True
        os.fsync(self.parent_fds[-1])
        self.source_fd = self.open(DEST.name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
                                   dir_fd=self.parent_fds[-1])
        self.source_identity = meta(os.fstat(self.source_fd))
        need(self.source_identity[3] == OWNER_UID and stat.S_IMODE(self.source_identity[2]) == 0o700
             and self.source_identity == meta(os.stat(DEST.name, dir_fd=self.parent_fds[-1], follow_symlinks=False)),
             'new private source directory binding differs')
        self.source_check()
        for name, body in sorted(self.bodies.items()):
            self.write_file(name, body)
        self.phase = 'canonical-second-complete-read'
        self.source_check()
        directory_full9 = meta(os.fstat(self.source_fd))
        other, self.parents_after = self.open_chain()
        need([row['path'] for row in self.parents_before] == [row['path'] for row in self.parents_after],
             'canonical parent sequence changed')
        self.check_chain(other, self.parents_before, base_may_change=True)
        names_after, self.names_after_data = self.bounded_names(other[-1],
            maximum=LIMITS['base_names_per_snapshot'], base_snapshot=True)
        need(names_after == sorted(names_before+[DEST.name]), 'BASE complete names changed beyond sole source addition')
        self.absent(other[-1], (AUDIT_OUT, CALLER_OUT))
        self.check_chain(other, self.parents_after, base_may_change=False)
        second = self.open(DEST.name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=other[-1])
        need(meta(os.fstat(second)) == directory_full9
             == meta(os.stat(DEST.name, dir_fd=other[-1], follow_symlinks=False))
             and self.bounded_names(second, maximum=3) == sorted(EXPECTED), 'canonical reopened source directory differs')
        final_files = {name: self.read_file(second, name, self.files[name]['metadata']) for name in sorted(EXPECTED)}
        need(final_files == self.files, 'staged files changed between complete independent reads')
        need(meta(os.fstat(second)) == directory_full9, 'second source directory full9 changed')
        self.source_check(directory_full9=directory_full9)
        self.check_chain(self.parent_fds, self.parents_after, base_may_change=False)
        self.check_chain(other, self.parents_after, base_may_change=False)
        self.absent(other[-1], (AUDIT_OUT, CALLER_OUT))
        self.check_chain(other, self.parents_after, base_may_change=False)
        self.phase = 'complete'
        return {'schema': 'hepta.fixed-policy-source-stage-result.v2',
            'state': 'FIXED_THREE_SOURCES_CREATED_AND_FULLY_READ_TWICE',
            'source_root': str(DEST), 'source_directory_metadata': directory_full9,
            'files': [final_files[name] for name in sorted(final_files)],
            'parents_before': self.parents_before, 'parents_after': self.parents_after,
            'parent_names_before': self.names_before_data, 'parent_names_after': self.names_after_data,
            'only_declared_directory_added': True, 'all_three_targets_observed_absent_before_create': True,
            'audit_and_caller_outputs_still_absent': True, 'base_all_time_full9_stable_claim': False,
            'created': self.created, 'created_files': self.created_files, **self.accounting(),
            'limits': LIMITS, 'staged_source_execution': False, 'subprocesses_started': 0,
            'phone_calls': 0, 'case_credit': 0, 'automatic_retry': False,
            'external_complete_readback_required': True, 'self_report_is_not_source_authority': True}

    def accounting(self):
        return {'physical_source_read_bytes': self.budget.physical_read_bytes,
            'source_write_bytes': self.budget.source_write_bytes,
            'directory_entries_observed': self.budget.directory_entries,
            'peak_owned_fds': self.budget.peak_owned_fds,
            'parent_names_decoded_bytes': self.budget.names_decoded_bytes,
            'parent_names_encoded_bytes': self.budget.names_encoded_bytes,
            'parent_names_charge_is_canonical_expanded_data_not_kernel_dirent_bytes': True}

    def failure(self, error):
        return {'schema': 'hepta.fixed-policy-source-stage-failure.v1',
            'state': 'STAGING_FAILED_OR_UNKNOWN_RETAIN_PARTIAL_NO_RETRY', 'phase': self.phase,
            'error_type': type(error).__name__, 'message': str(error)[:512],
            'source_root': str(DEST), 'created': self.created, 'created_files': self.created_files,
            'completed_files': [self.files[name] for name in sorted(self.files)],
            'parents_before': self.parents_before, 'parents_after': self.parents_after,
            'parent_names_before': self.names_before_data, 'parent_names_after': self.names_after_data,
            'cleanup_errors': self.cleanup_errors,
            'descriptor_operations_unresolved': self.fd_operations,
            'owned_fds_closed': not self.fds and not self.cleanup_errors and not self.fd_operations,
            'partial_outputs_removed': False, 'retry_or_alternate_suffix': False, **self.accounting(),
            'staged_source_execution': False, 'phone_calls': 0, 'case_credit': 0,
            'external_complete_readback_required': True, 'self_report_is_not_source_authority': True}


def main():
    budget = Budget()
    stager = None
    result = None
    code = 1
    previous_handler = None
    timer_installed = False
    try:
        try:
            need(sys.platform == 'darwin' and os.geteuid() == OWNER_UID and sys.argv == ['-c'],
                 'fixed actual Mac -I -B -c staging entry required')
            os.umask(0o077)
            previous_handler = signal.getsignal(signal.SIGALRM)
            def alarm(_signum, _frame):
                raise StageAlarm('fixed source staging or terminal-receipt alarm expired')
            signal.signal(signal.SIGALRM, alarm)
            signal.setitimer(signal.ITIMER_REAL, LIMITS['seconds'])
            timer_installed = True
            raw = sys.stdin.buffer.read(LIMITS['stdin_bytes']+1)
            budget.check()
            bodies = decode_payload(raw)
            stager = Stager(bodies, budget)
            result = stager.run()
            result['input_bytes'] = len(raw)
            result['input_sha256'] = sha(raw)
            code = 0
        except BaseException as error:
            # At most one extra second is reserved for terminal cleanup and its
            # receipt. There is no retry of staging, mkdir, writes or readback.
            if timer_installed:
                signal.setitimer(signal.ITIMER_REAL, LIMITS['terminal_seconds'])
            if stager is not None:
                stager.close()
                result = stager.failure(error)
            else:
                result = {'schema': 'hepta.fixed-policy-source-stage-failure.v1',
                    'state': 'REJECTED_BEFORE_STAGE', 'error_type': type(error).__name__, 'message': str(error)[:512],
                    'created': False, 'created_files': [], 'partial_outputs_removed': False,
                    'retry_or_alternate_suffix': False, 'staged_source_execution': False, 'phone_calls': 0}
        result['elapsed_seconds'] = time.monotonic()-budget.started
        encoded = wire(result)
        need(len(encoded) <= LIMITS['stdout_bytes']
             and len(encoded)+budget.names_decoded_bytes+budget.names_encoded_bytes <= LIMITS['names_and_receipt_bytes'],
             'bounded full staging receipt exceeded')
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()
        return code
    finally:
        if timer_installed:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)


if __name__ == '__main__':
    raise SystemExit(main())
