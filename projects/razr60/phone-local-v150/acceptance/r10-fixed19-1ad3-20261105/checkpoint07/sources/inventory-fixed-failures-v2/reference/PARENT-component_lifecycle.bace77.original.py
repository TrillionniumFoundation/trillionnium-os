#!/usr/bin/env python3
"""Explicit one-use component lifecycle, independent of every production module.

The only launched roles are a new r6 sidecar and the component listener. No
model process, production restart, policy change, old helper write or native
task submission exists here. Importing this module performs no work.
"""
import argparse
import base64
import errno
import fcntl
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import time
import types

sys.path.insert(0, str(Path(__file__).resolve().parent))
import native_proc_profile
from component_common import (need, sha, encoded, strict, read, pinned, put,
    private_dir, metadata, descriptor, scope, parent_fd, verify_package, load_combination,
    verify_external, import_pinned, target_identity, proc_stat, generation,
    absent_groups, BASE, ANDROID, ANDROID_BASE, COMPONENT_EVIDENCE,
    PRODUCTION_EVIDENCE, CLIENT, CLIENT_SHA, SIDECAR, PARENT_DOMAIN, MAGISK, EXECUTOR_LABEL)


# This boot's generated classpath is observed original data, never a shell
# program.  Its complete file descriptor is populated only by the host source
# derivation from the pinned Root read-only observation.
REVIEWED_PLATFORM_CLASSPATH = {'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'file': {'bytes': 5259, 'metadata': [65086, 136045, 33152, 1000, 1000, 1, 5259, 2313515747999998, 2313515747999998], 'path': '/proc/1/root/data/system/environ/classpath', 'sha256': '16a13f546a20ead8d4a4b100cc58527c26ffe59008729cb9cdaccafbf14db7c5'}, 'selinux_label': 'u:object_r:environ_system_data_file:s0'}


def _reviewed_classpath_values(raw):
    """Parse the four fixed export records; expose only the two boot values."""
    need(type(raw) is bytes and raw.endswith(b'\n'), 'classpath must be original LF-terminated bytes')
    text = raw.decode('ascii')
    lines = text[:-1].split('\n')
    keys = ('BOOTCLASSPATH', 'DEX2OATBOOTCLASSPATH',
            'SYSTEMSERVERCLASSPATH', 'STANDALONE_SYSTEMSERVER_JARS')
    need(len(lines) == len(keys), 'classpath export count differs')
    values = {}; entries = {}
    for key, line in zip(keys, lines):
        tokens = line.split(' ')
        need(len(tokens) == 3 and tokens[:2] == ['export', key]
             and tokens[2], 'classpath export order or three-token grammar differs')
        paths = tokens[2].split(':')
        need(all(re.fullmatch(r'/(?:[A-Za-z0-9_+.-]+/)*[A-Za-z0-9_+.-]+\.jar', p)
                 and all(part not in ('.', '..') for part in p.split('/')[1:])
                 for p in paths), 'classpath entry is not one literal absolute jar path')
        values[key] = tokens[2]; entries[key] = paths
    dex = entries['DEX2OATBOOTCLASSPATH']; boot = entries['BOOTCLASSPATH']
    need(0 < len(dex) < len(boot) and boot[:len(dex)] == dex,
         'DEX2OATBOOTCLASSPATH is not the strict whole-entry boot prefix')
    return {key: values[key] for key in keys[:2]}


def reviewed_android_sidecar_environment(boot_id):
    """Read this exact boot's generated file without executing or sourcing it."""
    record = REVIEWED_PLATFORM_CLASSPATH
    need(isinstance(record, dict) and set(record) == {'boot_id', 'file', 'selinux_label'}
         and boot_id == record['boot_id']
         and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot_id,
         'reviewed Android classpath boot differs')
    row = record['file']; path = Path(row['path'])
    need(set(row) == {'path', 'bytes', 'sha256', 'metadata'}
         and str(path) == '/proc/1/root/data/system/environ/classpath'
         and row['bytes'] == 5259
         and row['sha256'] == '16a13f546a20ead8d4a4b100cc58527c26ffe59008729cb9cdaccafbf14db7c5',
         'reviewed Android classpath file differs')
    parent, name = parent_fd(path)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=parent)
    except BaseException:
        os.close(parent); raise
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and metadata(before) == row['metadata'],
             'reviewed Android classpath identity or metadata differs')
        label = os.getxattr(fd, 'security.selinux')
        canonical_label = record['selinux_label'].encode('ascii')
        need(label in (canonical_label, canonical_label+b'\0'),
             'reviewed Android classpath label differs')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(row['bytes']+1)
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256']
             and metadata(os.fstat(fd)) == row['metadata']
             == metadata(os.stat(name, dir_fd=parent, follow_symlinks=False))
             and os.getxattr(fd, 'security.selinux') == label,
             'reviewed Android classpath bytes or bookends differ')
        values = _reviewed_classpath_values(raw)
        second, leaf = parent_fd(path)
        try:
            need(leaf == name and metadata(os.stat(leaf, dir_fd=second, follow_symlinks=False))
                 == row['metadata'], 'reviewed Android classpath canonical path changed')
        finally:
            os.close(second)
    finally:
        os.close(fd); os.close(parent)
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot_id,
         'Android boot changed during classpath read')
    return {'PATH': '/system/bin:/vendor/bin', 'TMPDIR': '/data/local/tmp',
            'ANDROID_ART_ROOT': '/apex/com.android.art',
            'ANDROID_I18N_ROOT': '/apex/com.android.i18n',
            'ANDROID_TZDATA_ROOT': '/apex/com.android.tzdata', **values}


def load_lease(home, pin, *, require_live=True):
    home = private_dir(Path(home)); raw = read(home / 'LEASE.json', 262144)
    need(sha(raw) == pin, 'exact Root lease pin differs')
    q = strict(raw)
    need(set(q) == {'schema', 'label', 'boot_id', 'case_id', 'nonce', 'owner_request_sha256',
        'selected_session_id', 'selected_profile_id', 'expires_unix_ms', 'combination',
        'retirement', 'prior_boundary', 'android_journal', 'package_sha256'}
        and q['schema'] == 'hepta.native-guard.lease.v1'
        and q['case_id'] in ('NEG-01', 'NEG-02') and re.fullmatch('[a-z0-9][a-z0-9-]{5,55}', q['label'])
        and home == BASE / 'native-guard-r10-r1' / q['label'], 'explicit one-use component lease differs')
    need(re.fullmatch('[0-9a-f]{32}', q['nonce']) and re.fullmatch('[0-9a-f-]{36}', q['boot_id']), 'nonce/boot shape')
    need(q['android_journal'] == str(ANDROID_BASE / 'native-guard-r10-r1' / q['label'] / 'executor'),
         'new isolated executor journal required')
    owner = read(home / 'owner-request.txt', 16000)
    need(20 <= len(owner) <= 16000 and sha(owner) == q['owner_request_sha256']
         and b'\0' not in owner and owner.decode().count(q['nonce']) == 1, 'explicit exact owner request differs')
    prior = q['prior_boundary']
    need(prior is not None, 'r4 must retain the one actually published failed ancestor')
    need(prior is None or (isinstance(prior,dict) and set(prior)=={'path','bytes','sha256','metadata'}
         and re.fullmatch(r'/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/[0-9a-f]{32}\.json',prior['path'])
         and type(prior['bytes']) is int and 0<prior['bytes']<=16*1024*1024
         and re.fullmatch('[0-9a-f]{64}',prior['sha256'])
         and isinstance(prior['metadata'],list) and len(prior['metadata'])==9),
         'explicit original late-boundary descriptor required')
    need(type(q['expires_unix_ms']) is int and q['expires_unix_ms']>0, 'lease expiry type differs')
    if require_live:
        need(0 < q['expires_unix_ms']-int(time.time()*1000) <= 600000,
             'component lease expired or exceeds 600 seconds; no automatic extension')
    return q, raw


def native_root(boot_id):
    need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0, 'native Root credentials required')
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot_id, 'boot changed')
    # This exact platform profile has CONFIG_PID_NS absent. The original
    # reviewed native_view requires native procfs/init, self PID/PGID/SID,
    # exact namespace inventories and exactly ENOENT for both pid entries.
    # Any other read failure or newly present pid namespace is rejected.
    view=native_proc_profile.ProcView().native_view()
    own = target_identity(os.getpid())
    need(own['identity']==[view[k] for k in ('pid','pgrp','session','start_ticks')]
         and own['ppid']==view['ppid'],'actual process differs from versioned native proc profile')
    need(own['domain'] == MAGISK and own['uid'] == own['gid'] == [0]*4 and own['nnp'] == 0,
         'ordinary Root magisk NNP0 required, never bootstrap impersonation')
    need(generation(proc_stat(1))[3] == 0
         and (os.stat(ANDROID).st_dev,os.stat(ANDROID).st_ino) != (os.stat('/').st_dev,os.stat('/').st_ino),
         'GNU chroot/Android root anchors differ')
    return own


def verify_retired(lease, *, late_boundary_module=None):
    need(lease['prior_boundary'] is not None, 'r4 cannot omit the actual failed predecessor')
    r = lease['retirement']
    need(set(r) == {'proof', 'preflight', 'probe', 'bound_inputs', 'disabled_flag'}, 'retirement original set differs')
    code = BASE / 'module-r10-r1-retirement-code-r1'
    out = BASE / 'module-retire-r9-r2-for-r10-r1-01'
    expected = {'proof': out/'RETIREMENT.json', 'preflight': out/'PREFLIGHT.json',
        'probe': code/'retirement_probe.py', 'bound_inputs': code/'BOUND-INPUTS.json',
        'disabled_flag': ANDROID/'data/adb/modules/trillionnium_hepta_phone_local_v150_r9_r2/disable'}
    originals = {}
    for key, path in expected.items():
        row = r[key]
        need(set(row) == {'path', 'bytes', 'sha256', 'metadata'} and row['path'] == str(path),
             'retirement is not the original phone path: ' + key)
        originals[key] = pinned(path, {k: row[k] for k in ('bytes', 'sha256')}, 16*1024*1024)
        need(metadata(path.lstat()) == row['metadata'], 'original retirement file identity changed')
    proof, before, bound = (strict(originals[k]) for k in ('proof', 'preflight', 'bound_inputs'))
    need(proof.get('schema') == 'hepta.r9-r2-retirement-observation.v1'
         and proof.get('state') == 'ORIGINAL_FOUR_GROUPS_ABSENT_STATE_PRESERVED'
         and proof.get('boot_id') == lease['boot_id'] and proof.get('server_lock_now_unheld') is True
         and proof.get('global_pending_clear') is True and proof.get('old_claims_deleted') is False
         and proof.get('old_task_terminal_rewritten') is False
         and proof.get('automatic_restart') is False and proof.get('automatic_replay') is False,
         'actual entire four-role retirement is not established')
    need(before.get('schema') == 'hepta.r9-r2-retirement-preflight.v1'
         and before.get('state') == 'READY_FOR_DISABLE_AND_ONE_SUPERVISOR_TERM'
         and before['groups'] == proof['original_role_identities']
         and set(before['groups']) == {'supervisor', 'provider', 'model', 'sidecar'}
         and before['preserved_state'] == proof['preserved_state']
         and bound.get('complete_current_accepted_case_union_verified') is True,
         'actual retirement/preservation/complete accepted-case union differs')
    need(originals['disabled_flag'] == b'', 'current production module disable flag differs')
    probe = types.ModuleType('pinned_original_r9_r2_retirement'); probe.__file__ = str(expected['probe'])
    exec(compile(originals['probe'], str(expected['probe']), 'exec'), probe.__dict__)
    need(probe.BOUND == bound and {k:list(v) for k,v in probe.GROUPS.items()} == before['groups'],
         'retirement generated source does not bind original inputs')
    # Only the retained_state read path is called. No preflight/retire/stop,
    # old PID-based worker census, HTTP endpoint or model request is invoked.
    late = None
    if lease['prior_boundary'] is None:
        need(probe.retained_state() == proof['preserved_state'], 'retired baseline changed before component lifecycle')
    else:
        # A later component cannot claim equality with the earlier retirement.
        # The reviewed adapter owns a distinct, explicitly pinned later boundary.
        if late_boundary_module is None:
            import late_boundary as late_boundary_module
        late = late_boundary_module.verify_current(lease,
            combination_sha256=lease['combination']['sha256'], package_sha256=lease['package_sha256'])
    identities = list(before['groups'].values())
    observations = [absent_groups(identities), absent_groups(identities)]
    lock_path = BASE/'executor-r6/server.lock'
    lock = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(lock); raise
    # Hold the old journal lock for this whole isolated lifecycle. The new
    # sidecar owns another fresh journal and never uses the retired lease.
    return lock, {'retirement_sha256': sha(originals['proof']),
        'retirement_originals': {k: descriptor(v) for k,v in originals.items()},
        'old_group_absence': observations, 'old_journal_lock_held_without_writing': True,
        'old_preserved_state_equal_before_new_actions': lease['prior_boundary'] is None,
        'explicit_late_boundary_verification': late,
        'equality_is_not_claimed_after_component_actions': True}


def fixture_absence(path):
    """Only a bound fixture root may have a positively observed ENOENT state."""
    path=Path(path)
    need(re.fullmatch(r'/proc/1/root/data/local/tmp/hepta-native-guard-[0-9a-f]{32}',str(path)),
         'fixture absence path outside the explicit namespace')
    parent,name=parent_fd(path)
    try:
        before=os.fstat(parent)
        need(stat.S_ISDIR(before.st_mode),'fixture parent is not a directory')
        for _ in range(2):
            try:os.stat(name,dir_fd=parent,follow_symlinks=False)
            except OSError as error:need(error.errno==errno.ENOENT,'fixture absence unknown')
            else:need(False,'fixture root is now present')
        after=os.fstat(parent)
        need((before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_gid)==
             (after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_gid),'fixture parent identity changed')
        # Re-open the exact canonical parent walk; a renamed/replaced ancestor
        # cannot turn an unrelated held-directory ENOENT into valid absence.
        second,leaf=parent_fd(path)
        try:
            current=os.fstat(second)
            need(leaf==name and (current.st_dev,current.st_ino)==(before.st_dev,before.st_ino),
                 'fixture absence parent path was replaced')
            try:os.stat(leaf,dir_fd=second,follow_symlinks=False)
            except OSError as error:need(error.errno==errno.ENOENT,'fixture absence final read unknown')
            else:need(False,'fixture root appeared during absence observation')
        finally:os.close(second)
        return {'schema':'hepta.native-guard.fixture-absence.v1','path':str(path),'absence':'ENOENT',
                'canonical_parent_identity':[before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_gid],
                'observed_monotonic_ns':time.monotonic_ns(),'ui_actions':0}
    finally:os.close(parent)


def inventory(roots, *, fixture_root=None, fixture_roots=()):
    """Complete metadata/content inventory; errors or limits never mean absence."""
    result = {}; total = 0; started = time.monotonic(); visited = set()
    need(fixture_root is None or not fixture_roots,'single/multiple fixture root forms are exclusive')
    fixture_roots = tuple(map(Path,fixture_roots)) if fixture_root is None else (Path(fixture_root),)
    paths = list(map(Path,roots))
    need(all(a==b or not (a in b.parents or b in a.parents) for a in paths for b in paths),
         'overlapping inventory roots')
    need(len(fixture_roots)==len(set(fixture_roots)) and len(fixture_roots)<=8,
         'bounded unique cumulative fixture roots required')
    for fixture_root in fixture_roots:
        need(fixture_root in paths and re.fullmatch(
             r'/proc/1/root/data/local/tmp/hepta-native-guard-[0-9a-f]{32}',str(fixture_root)),
             'only explicit UID2000 fixture tree may use shell-owned originals')
    for root in roots:
        root = Path(root)
        need(str(root) not in visited, 'duplicate inventory root'); visited.add(str(root))
        if root in fixture_roots:
            try:root.lstat()
            except OSError as error:
                need(error.errno==errno.ENOENT,'fixture root existence unknown')
                fixture_absence(root)
                result[str(root)]={'kind':'absent','absence':'ENOENT'}
                continue
        stack = [root]
        while stack:
            need(time.monotonic()-started < 30 and len(result) < 30000, 'full inventory time/count bound')
            path = stack.pop(); s = path.lstat()
            need(not stat.S_ISLNK(s.st_mode), 'symlink in retained private inventory')
            fixture = any(path==p or p in path.parents for p in fixture_roots)
            if fixture:
                need(s.st_uid==s.st_gid==2000 and stat.S_IMODE(s.st_mode) in (0o700,0o600,0o400),
                     'fixture original ownership/mode differs')
            item = {'metadata': metadata(s)}
            if stat.S_ISDIR(s.st_mode):
                children = sorted(path.iterdir()); need(len(children) <= 20000, 'inventory directory entry bound')
                item.update(kind='directory', names=[p.name for p in children]); stack.extend(reversed(children))
            else:
                need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'non-regular/hardlinked inventory original')
                raw = read(path, 64*1024*1024, private=not fixture); total += len(raw)
                need(total <= 512*1024*1024, 'full inventory byte bound')
                item.update(kind='file', **descriptor(raw))
            need(metadata(s) == metadata(path.lstat()), 'inventory original raced')
            result[str(path)] = item
    return {'schema': 'hepta.native-guard.complete-inventory.v1', 'roots': list(map(str,roots)),
        'entries': result, 'file_bytes_hashed': total, 'elapsed_seconds': time.monotonic()-started,
        'inventory_is_closure_or_retirement': False}


# Explicit two-epoch observation, preserving the original single-domain API.
EPOCH_INVENTORY_LEGACY_ANCHOR = {'bytes': 9686, 'metadata': [65086, 156280, 33152, 0, 0, 1, 9686, 1793882486435914270, 1793882486435914270], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/902e851c3ca1f90deab3d880ab993774.json', 'sha256': '6e1d4a343fface7ebf36392e129a0f08ad91c8fc0d9216816502f90074b98831'}
EPOCH_INVENTORY_LEGACY_ROOTS = ('/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/evidence', '/var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6/evidence', '/var/lib/trillionnium/owner-open/phone-local-v150/client-receipts', '/var/lib/trillionnium/owner-open/phone-local-v150/executor-r6', '/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/health-contracts/bindings', '/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/task-contracts/bindings', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03', '/proc/1/root/data/local/tmp/hepta-native-guard-88d68d88130d3c74e6c950a6346357c1', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04', '/proc/1/root/data/local/tmp/hepta-native-guard-c705647dd4ebb5d421be1041a9c41ca6', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05', '/proc/1/root/data/local/tmp/hepta-native-guard-e4c3ccb0b2d706be3b7bf105ae772405', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06', '/proc/1/root/data/local/tmp/hepta-native-guard-154588e3a15591a21ec18950d18e3ecd', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07', '/proc/1/root/data/local/tmp/hepta-native-guard-16805e43f9787c44c262d5b6c6d8ed95', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08', '/proc/1/root/data/local/tmp/hepta-native-guard-2b0b103ee6de7a422064b9571266bf5d', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01', '/proc/1/root/data/local/tmp/hepta-native-guard-902e851c3ca1f90deab3d880ab993774')
EPOCH_INVENTORY_LEGACY_FIXTURES = ('/proc/1/root/data/local/tmp/hepta-native-guard-88d68d88130d3c74e6c950a6346357c1', '/proc/1/root/data/local/tmp/hepta-native-guard-c705647dd4ebb5d421be1041a9c41ca6', '/proc/1/root/data/local/tmp/hepta-native-guard-e4c3ccb0b2d706be3b7bf105ae772405', '/proc/1/root/data/local/tmp/hepta-native-guard-154588e3a15591a21ec18950d18e3ecd', '/proc/1/root/data/local/tmp/hepta-native-guard-16805e43f9787c44c262d5b6c6d8ed95', '/proc/1/root/data/local/tmp/hepta-native-guard-2b0b103ee6de7a422064b9571266bf5d', '/proc/1/root/data/local/tmp/hepta-native-guard-902e851c3ca1f90deab3d880ab993774')
EPOCH_INVENTORY_LEGACY_ALIAS_PAIRS = (('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03/executor'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03/executor/actions', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03/executor/actions'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03/executor/server.lock', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03/executor/server.lock'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03/executor/sidecar.stderr', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03/executor/sidecar.stderr'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03/executor/sidecar.stdout', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03/executor/sidecar.stdout'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor/actions', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor/actions'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor/actions/6ae95b55331656002d7dd82e9662224e', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor/actions/6ae95b55331656002d7dd82e9662224e'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor/actions/6ae95b55331656002d7dd82e9662224e/intent.json', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor/actions/6ae95b55331656002d7dd82e9662224e/intent.json'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor/actions/6ae95b55331656002d7dd82e9662224e/receipt.json', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor/actions/6ae95b55331656002d7dd82e9662224e/receipt.json'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor/actions/6ae95b55331656002d7dd82e9662224e/stderr.bin', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor/actions/6ae95b55331656002d7dd82e9662224e/stderr.bin'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor/actions/6ae95b55331656002d7dd82e9662224e/stdout.bin', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor/actions/6ae95b55331656002d7dd82e9662224e/stdout.bin'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor/server.lock', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor/server.lock'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor/sidecar.stderr', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor/sidecar.stderr'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor/sidecar.stdout', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor/sidecar.stdout'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05/executor'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05/executor/actions', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05/executor/actions'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05/executor/server.lock', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05/executor/server.lock'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05/executor/sidecar.stderr', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05/executor/sidecar.stderr'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05/executor/sidecar.stdout', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05/executor/sidecar.stdout'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor/actions', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor/actions'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor/actions/ff66f499606bccd37a388a8663d19ddf', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor/actions/ff66f499606bccd37a388a8663d19ddf'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor/actions/ff66f499606bccd37a388a8663d19ddf/intent.json', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor/actions/ff66f499606bccd37a388a8663d19ddf/intent.json'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor/actions/ff66f499606bccd37a388a8663d19ddf/receipt.json', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor/actions/ff66f499606bccd37a388a8663d19ddf/receipt.json'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor/actions/ff66f499606bccd37a388a8663d19ddf/stderr.bin', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor/actions/ff66f499606bccd37a388a8663d19ddf/stderr.bin'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor/actions/ff66f499606bccd37a388a8663d19ddf/stdout.bin', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor/actions/ff66f499606bccd37a388a8663d19ddf/stdout.bin'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor/server.lock', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor/server.lock'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor/sidecar.stderr', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor/sidecar.stderr'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor/sidecar.stdout', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor/sidecar.stdout'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07/executor'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07/executor/actions', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07/executor/actions'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07/executor/server.lock', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07/executor/server.lock'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07/executor/sidecar.stderr', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07/executor/sidecar.stderr'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07/executor/sidecar.stdout', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07/executor/sidecar.stdout'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor/actions', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor/actions'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor/actions/9e8c0fd0cd26f29ecfd80d0364e55225', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor/actions/9e8c0fd0cd26f29ecfd80d0364e55225'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor/actions/9e8c0fd0cd26f29ecfd80d0364e55225/intent.json', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor/actions/9e8c0fd0cd26f29ecfd80d0364e55225/intent.json'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor/actions/9e8c0fd0cd26f29ecfd80d0364e55225/receipt.json', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor/actions/9e8c0fd0cd26f29ecfd80d0364e55225/receipt.json'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor/actions/9e8c0fd0cd26f29ecfd80d0364e55225/stderr.bin', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor/actions/9e8c0fd0cd26f29ecfd80d0364e55225/stderr.bin'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor/actions/9e8c0fd0cd26f29ecfd80d0364e55225/stdout.bin', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor/actions/9e8c0fd0cd26f29ecfd80d0364e55225/stdout.bin'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor/server.lock', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor/server.lock'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor/sidecar.stderr', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor/sidecar.stderr'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor/sidecar.stdout', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor/sidecar.stdout'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/actions', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/actions'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/actions/5a952602788122f47ff1370cfa38dffe', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/actions/5a952602788122f47ff1370cfa38dffe'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/actions/5a952602788122f47ff1370cfa38dffe/intent.json', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/actions/5a952602788122f47ff1370cfa38dffe/intent.json'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/actions/5a952602788122f47ff1370cfa38dffe/receipt.json', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/actions/5a952602788122f47ff1370cfa38dffe/receipt.json'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/actions/5a952602788122f47ff1370cfa38dffe/stderr.bin', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/actions/5a952602788122f47ff1370cfa38dffe/stderr.bin'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/actions/5a952602788122f47ff1370cfa38dffe/stdout.bin', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/actions/5a952602788122f47ff1370cfa38dffe/stdout.bin'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/server.lock', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/server.lock'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/sidecar.stderr', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/sidecar.stderr'), ('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/sidecar.stdout', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor/sidecar.stdout'))
# Required exact retained/control/absence/alias binding is owned by epoch admission.
# None is a deliberate production refusal, never an implicit empty inventory.
EPOCH_INVENTORY_EXTRA_ROOTS = None

# This fragment is inserted after the unchanged single-domain inventory().
# The public two-epoch entrypoint is observation only, never an admission,
# allocation, preservation waiver, source-generation grant or case result.


def _epoch_inventory_path(value):
    need(type(value) is str and 0 < len(value.encode('utf-8')) <= 4096,
         'bounded exact epoch inventory path required')
    path = Path(value)
    need(path.is_absolute() and str(path) == value and '..' not in path.parts
         and 2 <= len(path.parts) <= 64 and '\0' not in value,
         'canonical bounded epoch inventory path required')
    return path


def _epoch_inventory_extra_rows(value, expected, absence_roots):
    need(type(value) is list and len(value) == len(expected),
         'complete explicit retained/control root list required')
    paths = []; absent = []
    for row, wanted in zip(value, expected):
        need(type(row) is dict and set(row) == {'path', 'presence'}
             and row['path'] == wanted and row['presence'] in ('present', 'absent'),
             'retained/control root or explicit presence differs')
        _epoch_inventory_path(row['path']); paths.append(row['path'])
        if row['presence'] == 'absent':
            need(row['path'] in absence_roots, 'unreviewed extra-root absence')
            absent.append(row['path'])
    return paths, absent


def inventory_epoch_spec_value(spec):
    """Validate the structural union, not the truth of a reservation registry.

    The late-boundary layer independently derives this exact value from real
    anchor, ordinal, identity, acceptance and phase originals. No caller may
    choose a smaller root subset, redefine a historical fixture as generic,
    replace the fixed failed/control set, or infer authorization from this API.
    """
    need(type(spec) is dict and set(spec) == {
        'schema', 'legacy_anchor', 'active_reservations', 'retained_roots',
        'control_roots', 'control_leaves', 'alias_pairs'} and spec['schema'] ==
        'hepta.native-guard.two-epoch-inventory-spec.v1', 'epoch inventory spec differs')
    need(encoded(spec['legacy_anchor']) == encoded(EPOCH_INVENTORY_LEGACY_ANCHOR),
         'only the fixed complete actual902 legacy anchor is supported')
    extra = EPOCH_INVENTORY_EXTRA_ROOTS
    need(type(extra) is dict and set(extra) == {
        'retained_roots', 'control_roots', 'control_leaves', 'absence_roots', 'alias_pairs'},
         'exact failed-attempt/control inventory roots remain unbound')
    for key in ('retained_roots', 'control_roots', 'absence_roots'):
        need(type(extra[key]) is list and len(extra[key]) <= 64
             and len(extra[key]) == len(set(extra[key])), 'extra-root binding shape differs')
        for path in extra[key]: _epoch_inventory_path(path)
    leaf_pins = extra['control_leaves']
    need(type(leaf_pins) is list and len(leaf_pins) <= 64, 'fixed exact control-leaf pins required')
    leaf_map = {}
    for pin in leaf_pins:
        need(type(pin) is dict and set(pin) == {'path', 'bytes', 'sha256', 'metadata'},
             'control leaf must bind the complete retained original identity')
        path = str(_epoch_inventory_path(pin['path'])); m = pin['metadata']
        need(path not in leaf_map and type(pin['bytes']) is int and 0 <= pin['bytes'] <= 64*1024*1024
             and type(pin['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', pin['sha256'])
             and type(m) is list and len(m) == 9 and all(type(n) is int for n in m)
             and m[0] >= 0 and m[1] > 0 and stat.S_ISREG(m[2]) and m[5] == 1
             and m[6] == pin['bytes'] and all(n >= 0 for n in m[3:])
             and (m[3], m[4], stat.S_IMODE(m[2])) in ((0, 0, 0o600), (2000, 2000, 0o666)),
             'only exact original private/ADB transport leaf metadata is admitted')
        leaf_map[path] = pin
    leaf_paths = list(leaf_map)
    extra_paths = extra['retained_roots'] + extra['control_roots'] + leaf_paths
    need(len(extra_paths) == len(set(extra_paths))
         and set(extra['absence_roots']) <= set(extra_paths),
         'extra roots repeat or absence is not an explicit extra root')
    retained, absent_retained = _epoch_inventory_extra_rows(
        spec['retained_roots'], extra['retained_roots'], extra['absence_roots'])
    control, absent_control = _epoch_inventory_extra_rows(
        spec['control_roots'], extra['control_roots'], extra['absence_roots'])
    control_leaves, absent_leaves = _epoch_inventory_extra_rows(
        spec['control_leaves'], leaf_paths, extra['absence_roots'])
    active = spec['active_reservations']
    need(type(active) is list and len(active) <= 8,
         'at most eight consumed active reservations are supported')
    roots = list(EPOCH_INVENTORY_LEGACY_ROOTS)
    fixtures = list(EPOCH_INVENTORY_LEGACY_FIXTURES)
    active_domains = []; identities = []; nonces = set(); labels = set()
    old_nonces = {p.rsplit('-', 1)[-1] for p in EPOCH_INVENTORY_LEGACY_FIXTURES}
    for ordinal, row in enumerate(active, 1):
        need(type(row) is dict and set(row) == {'ordinal', 'identity', 'inventory_roots'}
             and type(row['ordinal']) is int and row['ordinal'] == ordinal
             and type(row['inventory_roots']) is list,
             'active reservations must retain every unique consecutive consumed ordinal')
        identity = row['identity']; selected = row['inventory_roots']
        if identity is None:
            need(selected == [], 'pre-identity reservation cannot invent native roots')
        else:
            need(type(identity) is dict and set(identity) == {'label', 'nonce'}
                 and type(identity['label']) is str and re.fullmatch(
                     r'[a-z0-9][a-z0-9-]{5,69}', identity['label'])
                 and type(identity['nonce']) is str and re.fullmatch(
                     r'[0-9a-f]{32}', identity['nonce']), 'exact active identity differs')
            label, nonce = identity['label'], identity['nonce']
            need(nonce not in nonces and nonce not in old_nonces and label not in labels,
                 'active identity reuses a historical or active identity')
            nonces.add(nonce); labels.add(label)
            home = str(BASE / 'native-guard-r10-r1' / label)
            journal = str(ANDROID / str(ANDROID_BASE / 'native-guard-r10-r1'
                                      / label / 'executor').lstrip('/'))
            fixture = str(ANDROID / 'data/local/tmp' / ('hepta-native-guard-' + nonce))
            triple = [journal, home, fixture]
            need(all(type(p) is str for p in selected)
                 and selected == [p for p in triple if p in selected],
                 'active roots must be an exact ordered subset of this identity triple')
            need(not any(p in EPOCH_INVENTORY_LEGACY_ROOTS for p in triple),
                 'active identity collides with fixed historical roots')
            for path in selected: _epoch_inventory_path(path)
            if fixture in selected: fixtures.append(fixture)
            identities.append((home, journal))
        roots.extend(selected)
        active_domains.append({'ordinal': ordinal, 'roots': list(selected)})
    roots.extend(retained); roots.extend(control); roots.extend(control_leaves)
    need(0 < len(roots) <= 64 and len(roots) == len(set(roots)),
         'one complete unique union must fit the original 64-root bound')
    paths = [_epoch_inventory_path(p) for p in roots]
    parts = [p.parts for p in paths]
    need(all(not (a != b and (a[:len(b)] == b or b[:len(a)] == a))
             for a in parts for b in parts), 'overlapping epoch inventory roots')
    need(len(fixtures) <= 15 and len(fixtures) == len(set(fixtures))
         and fixtures[:7] == list(EPOCH_INVENTORY_LEGACY_FIXTURES),
         'fixed seven legacy plus at most eight active fixtures required')
    for path in paths:
        for ancestor in (path,) + tuple(path.parents):
            if re.fullmatch(r'/proc/1/root/data/local/tmp/hepta-native-guard-[0-9a-f]{32}', str(ancestor)):
                need(str(ancestor) in fixtures and path == ancestor,
                     'undeclared fixture cannot be hidden as a generic root')
    pairs = spec['alias_pairs']
    need(type(pairs) is list and len(pairs) <= 15000,
         'bounded explicit inventory alias pairs required')
    legacy = [list(pair) for pair in EPOCH_INVENTORY_LEGACY_ALIAS_PAIRS]
    extra_pairs = extra['alias_pairs']
    need(type(extra_pairs) is list and len(extra_pairs) <= 15000,
         'explicit retained alias binding differs')
    fixed_pairs = legacy + extra_pairs
    fixed = {tuple(pair) for pair in fixed_pairs
             if type(pair) is list and len(pair) == 2 and all(type(p) is str for p in pair)}
    need(len(fixed) == len(fixed_pairs), 'duplicate or malformed fixed alias pair')
    seen = set(); pair_tuples = []
    def covered(path):
        pp = Path(path).parts
        return sum(pp[:len(root)] == root for root in parts) == 1
    for pair in pairs:
        need(type(pair) is list and len(pair) == 2
             and all(type(p) is str for p in pair) and pair[0] < pair[1],
             'alias pair must contain two sorted exact paths')
        for path in pair:
            _epoch_inventory_path(path)
            need(path not in seen and covered(path),
                 'alias path repeats, is a third view, or leaves the exact root union')
            seen.add(path)
        key = tuple(pair); pair_tuples.append(key)
        if key not in fixed:
            matched = False
            for home, journal in identities:
                android_path, gnu_path = pair
                gp, jp = Path(home) / 'executor', Path(journal)
                gparts, aparts = Path(gnu_path).parts, Path(android_path).parts
                if gparts[:len(gp.parts)] == gp.parts and aparts[:len(jp.parts)] == jp.parts:
                    matched = gparts[len(gp.parts):] == aparts[len(jp.parts):]
                    if matched: break
            need(matched, 'only this active identity exact same-relative executor views may alias')
    need(pair_tuples == sorted(pair_tuples) and len(pair_tuples) == len(set(pair_tuples))
         and fixed <= set(pair_tuples), 'fixed legacy/retained aliases were omitted or reordered')
    business_roots = [p for p in roots if p not in control and p not in control_leaves and p not in absent_retained]
    control_roots = [p for p in control if p not in absent_control]
    for a, b in pairs:
        in_control = [p in control_leaves or any(Path(p).parts[:len(Path(r).parts)] == Path(r).parts
                                                for r in control_roots) for p in (a, b)]
        need(in_control[0] == in_control[1], 'an alias cannot cross business/control accounting domains')
    raw = encoded(spec)
    need(len(raw) <= 16 * 1024 * 1024, 'epoch inventory spec exceeds the original bounded input pool')
    return {'roots': roots, 'fixture_roots': fixtures,
            'required_absence_roots': absent_retained + absent_control + absent_leaves,
            'alias_pairs': [list(pair) for pair in pairs], 'active_reservation_count': len(active),
            'active_fixture_count': len(fixtures) - 7,
            'business_inventory_roots': business_roots,
            'control_inventory_roots': control_roots,
            'control_leaf_paths': control_leaves,
            'control_leaf_pins': leaf_map,
            'domain_roots': {'legacy': list(EPOCH_INVENTORY_LEGACY_ROOTS),
                             'active': active_domains, 'retained': retained, 'control': control,
                             'control_leaves': control_leaves},
            'spec_sha256': sha(raw)}


class _EpochInventoryBudget:
    """One operation-owned clock and resource pool, never supplied by callers."""
    def __init__(self):
        self.started = time.monotonic()
        self.entries = 0
        self.bytes_read = 0
        self.file_reads = 0

    def check(self):
        need(0 <= time.monotonic() - self.started < 30,
             'shared full inventory time bound')
        need(self.entries <= 30000 and self.bytes_read <= 512 * 1024 * 1024,
             'shared full inventory count/byte bound')

    def entry(self):
        self.check(); self.entries += 1
        need(self.entries <= 30000, 'shared full inventory entry bound')

    def chunk(self, count):
        need(type(count) is int and count >= 0, 'actual read byte count required')
        self.bytes_read += count; self.check()


def _epoch_inventory_names(fd, budget):
    names = []
    with os.scandir(fd) as iterator:
        for row in iterator:
            budget.check()
            need(len(names) < 20000, 'inventory directory entry bound')
            name = row.name
            need(type(name) is str and name not in ('', '.', '..')
                 and '/' not in name and '\0' not in name,
                 'literal inventory child name required')
            names.append(name)
    need(len(names) == len(set(names)), 'inventory directory repeats a child')
    return sorted(names)


def _epoch_inventory_fixture(path, fixtures):
    parts = Path(path).parts
    matched = [root for root in fixtures if parts[:len(Path(root).parts)] == Path(root).parts]
    need(len(matched) <= 1, 'ambiguous inventory fixture membership')
    for ancestor in (Path(path),) + tuple(Path(path).parents):
        if re.fullmatch(r'/proc/1/root/data/local/tmp/hepta-native-guard-[0-9a-f]{32}', str(ancestor)):
            need(str(ancestor) in fixtures, 'unlisted fixture path in generic inventory tree')
    return bool(matched)


def _epoch_inventory_observe_roots(value, budget):
    """Private walker: only inventory_epoch passes its fully checked union."""
    import hashlib as epoch_hashlib
    roots = value['roots']; fixtures = value['fixture_roots']
    required_absent = set(value['required_absence_roots'])
    aliases = {a: b for pair in value['alias_pairs'] for a, b in (pair, pair[::-1])}
    result = {}; identities = {}; root_parents = {}; absences = {}; leaf_parents = {}
    leaf_pins = value['control_leaf_pins']
    def guard_type(path, s):
        need(not stat.S_ISLNK(s.st_mode), 'symlink in retained private inventory')
        fixture = _epoch_inventory_fixture(str(path), fixtures)
        if str(path) in leaf_pins:
            pin = leaf_pins[str(path)]
            need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1
                 and metadata(s) == pin['metadata'], 'fixed control leaf identity or type changed')
            return False
        if fixture:
            need(s.st_uid == s.st_gid == 2000 and stat.S_IMODE(s.st_mode) in (0o700, 0o600, 0o400),
                 'fixture original ownership/mode differs')
        if stat.S_ISDIR(s.st_mode): return True
        need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and 0 <= s.st_size <= 64 * 1024 * 1024,
             'non-regular/hardlinked/oversized inventory original')
        if not fixture:
            need(s.st_uid == s.st_gid == 0 and stat.S_IMODE(s.st_mode) == 0o600,
                 'private original ownership/mode differs')
        return False
    def observe(path, parent, name, root=False):
        budget.entry()
        need(str(path) not in result and len(path.parts) <= 64,
             'duplicate or too-deep inventory path')
        try: before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except OSError as error:
            need(root and (str(path) in fixtures or str(path) in required_absent)
                 and error.errno == errno.ENOENT, 'inventory root existence unknown or required original absent')
            initial_parent = metadata(os.fstat(parent))
            # A held parent alone is insufficient after an ancestor rename.
            second, leaf = parent_fd(path)
            try:
                need(leaf == name and metadata(os.fstat(second)) == metadata(os.fstat(parent)) == initial_parent,
                     'absence canonical parent was replaced')
                for fd in (parent, second):
                    try: os.stat(name, dir_fd=fd, follow_symlinks=False)
                    except OSError as again: need(again.errno == errno.ENOENT, 'inventory absence unknown')
                    else: need(False, 'inventory root appeared during absence read')
            finally: os.close(second)
            result[str(path)] = {'kind': 'absent', 'absence': 'ENOENT'}
            need(metadata(os.fstat(parent)) == initial_parent, 'absence parent changed during initial observation')
            absences[str(path)] = {
                'schema': 'hepta.native-guard.epoch-positive-root-absence.v1',
                'path': str(path), 'absence': 'ENOENT', 'parent_path': str(path.parent),
                'initial_parent_metadata': initial_parent,
                'initial_held_enoent_checks': 2, 'initial_reopened_enoent_checks': 1,
                'first_elapsed_seconds': time.monotonic() - budget.started}
            budget.check(); return
        need(str(path) not in required_absent, 'an explicitly absent retained/control root appeared')
        directory = guard_type(path, before)
        if root:
            need(directory == (str(path) not in leaf_pins),
                 'complete inventory roots must be directories; control leaves are separate exact files')
        identity = (before.st_dev, before.st_ino)
        other = identities.get(identity)
        if other is not None:
            need(aliases.get(str(path)) == other, 'unlisted inode alias or third inventory view')
        else: identities[identity] = str(path)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        if directory: flags |= os.O_DIRECTORY
        fd = os.open(name, flags, dir_fd=parent)
        try:
            need(metadata(os.fstat(fd)) == metadata(before), 'inventory path replaced before open')
            row = {'metadata': metadata(before)}
            if directory:
                names = _epoch_inventory_names(fd, budget)
                row.update(kind='directory', names=names)
                result[str(path)] = row
                for child in names: observe(path / child, fd, child)
                need(_epoch_inventory_names(fd, budget) == names, 'inventory directory membership changed')
            else:
                need(before.st_size <= 512 * 1024 * 1024 - budget.bytes_read,
                     'shared remaining inventory byte bound')
                digest = epoch_hashlib.sha256(); size = 0
                while True:
                    budget.check()
                    block = os.read(fd, min(65536, before.st_size + 1 - size))
                    if not block: break
                    size += len(block); budget.chunk(len(block)); digest.update(block)
                    need(size <= before.st_size, 'inventory original grew during read')
                need(size == before.st_size, 'inventory original length changed')
                budget.file_reads += 1
                row.update(kind='file', bytes=size, sha256=digest.hexdigest())
                if str(path) in leaf_pins:
                    need(size == leaf_pins[str(path)]['bytes']
                         and row['sha256'] == leaf_pins[str(path)]['sha256'],
                         'fixed control leaf content changed')
                result[str(path)] = row
            need(metadata(before) == metadata(os.fstat(fd))
                 == metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                 'inventory original raced')
            if other is not None: need(result[other] == row, 'declared alias rows differ')
        finally: os.close(fd)
        budget.check()
    for root in roots:
        budget.check(); path = Path(root); parent, leaf = parent_fd(path)
        try:
            pkey = str(path.parent); initial = metadata(os.fstat(parent))
            if pkey in root_parents: need(root_parents[pkey] == initial, 'inventory root parent changed')
            else: root_parents[pkey] = initial
            if root in leaf_pins:
                names = _epoch_inventory_names(parent, budget)
                if pkey in leaf_parents:
                    need(leaf_parents[pkey]['initial_names'] == names,
                         'fixed control-leaf parent names changed')
                else:
                    leaf_parents[pkey] = {'path': pkey, 'initial_metadata': initial,
                        'initial_names': names, 'first_elapsed_seconds': time.monotonic() - budget.started}
            observe(path, parent, leaf, True)
            need(metadata(os.fstat(parent)) == initial, 'inventory root parent changed during walk')
        finally: os.close(parent)
    # Global bookends include objects visited early in any domain. Canonical
    # parents are re-opened from the real anchor, never from a stale held FD.
    for path, row in result.items():
        budget.check(); p = Path(path); parent, leaf = parent_fd(p)
        try:
            if row['kind'] == 'absent':
                parent_meta = metadata(os.fstat(parent))
                need(parent_meta == absences[path]['initial_parent_metadata'],
                     'absence canonical parent changed before global bookend')
                try: os.stat(leaf, dir_fd=parent, follow_symlinks=False)
                except OSError as error: need(error.errno == errno.ENOENT, 'inventory final absence unknown')
                else: need(False, 'absent inventory root appeared at global bookend')
                need(metadata(os.fstat(parent)) == parent_meta,
                     'absence canonical parent raced during global bookend')
                absences[path].update(final_parent_metadata=parent_meta,
                    final_reopened_enoent_checks=1, canonical_parent_reopened=True,
                    last_elapsed_seconds=time.monotonic() - budget.started)
                continue
            before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            need(metadata(before) == row['metadata'], 'inventory original changed before global bookend')
            directory = guard_type(p, before)
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            if directory: flags |= os.O_DIRECTORY
            fd = os.open(leaf, flags, dir_fd=parent)
            try:
                need(metadata(os.fstat(fd)) == row['metadata'], 'inventory global bookend inode replaced')
                if directory:
                    need(_epoch_inventory_names(fd, budget) == row['names'],
                         'inventory global directory membership changed')
                need(metadata(os.fstat(fd)) == metadata(os.stat(leaf, dir_fd=parent, follow_symlinks=False))
                     == row['metadata'], 'inventory global bookend raced')
            finally: os.close(fd)
        finally: os.close(parent)
    for path, wanted in root_parents.items():
        budget.check(); parent, leaf = parent_fd(Path(path) / '.epoch-inventory-parent-probe')
        try:
            need(metadata(os.fstat(parent)) == wanted, 'inventory canonical root parent was renamed or changed')
            if path in leaf_parents:
                names = _epoch_inventory_names(parent, budget)
                need(names == leaf_parents[path]['initial_names']
                     and metadata(os.fstat(parent)) == wanted,
                     'control-leaf parent directory names or full identity changed')
                leaf_parents[path].update(final_metadata=wanted, final_names=names,
                    last_elapsed_seconds=time.monotonic() - budget.started,
                    metadata_and_names_only=True, subtree_inventory_claimed=False)
        finally: os.close(parent)
    for a, b in value['alias_pairs']:
        need(a in result and b in result and result[a] == result[b]
             and result[a]['kind'] != 'absent', 'declared alias omitted or differs')
    budget.check()
    inventory = {'schema': 'hepta.native-guard.complete-inventory.v1', 'roots': list(roots),
            'entries': result, 'file_bytes_hashed': budget.bytes_read,
            'elapsed_seconds': time.monotonic() - budget.started,
            'inventory_is_closure_or_retirement': False}
    return inventory, [absences[p] for p in roots if p in absences], [leaf_parents[p] for p in sorted(leaf_parents)]


def _epoch_inventory_split_views(value, inventory):
    def project(roots):
        if not roots: return None
        parts = [Path(p).parts for p in roots]
        entries = {p: row for p, row in inventory['entries'].items()
                   if any(Path(p).parts[:len(r)] == r for r in parts)}
        return {'schema': 'hepta.native-guard.complete-inventory.v1',
                'roots': list(roots), 'entries': entries,
                'file_bytes_hashed': sum(row['bytes'] for row in entries.values() if row['kind'] == 'file'),
                'elapsed_seconds': inventory['elapsed_seconds'],
                'inventory_is_closure_or_retirement': False}
    return project(value['business_inventory_roots']), project(value['control_inventory_roots'])


def _epoch_inventory_join_views(value, business, control, control_leaves):
    """Reconstruct the observed union without inventing file or directory rows."""
    rows = {}; total = 0; elapsed = None
    for view, roots in ((business, value['business_inventory_roots']),
                        (control, value['control_inventory_roots'])):
        if not roots:
            need(view is None, 'no present control roots require an explicit null control inventory')
            continue
        need(type(view) is dict and set(view) == {
            'schema', 'roots', 'entries', 'file_bytes_hashed', 'elapsed_seconds',
            'inventory_is_closure_or_retirement'}
             and view['schema'] == 'hepta.native-guard.complete-inventory.v1'
             and view['roots'] == roots and view['inventory_is_closure_or_retirement'] is False
             and type(view['entries']) is dict and type(view['file_bytes_hashed']) is int,
             'business/control inventory view differs')
        if elapsed is None: elapsed = view['elapsed_seconds']
        else: need(encoded(view['elapsed_seconds']) == encoded(elapsed),
                   'views must report the same shared operation clock')
        root_parts = [Path(p).parts for p in roots]; size = 0
        for p, row in view['entries'].items():
            path = _epoch_inventory_path(p)
            need(type(row) is dict and p not in rows
                 and sum(path.parts[:len(r)] == r for r in root_parts) == 1,
                 'inventory view moved, repeated or omitted a domain path')
            if row.get('kind') == 'file':
                need(type(row.get('bytes')) is int and row['bytes'] >= 0,
                     'view file byte count differs')
                size += row['bytes']
            rows[p] = row
        need(size == view['file_bytes_hashed'], 'inventory view byte accounting differs')
        total += size
    need(type(control_leaves) is list and len(control_leaves) == len(value['control_leaf_paths']),
         'every declared control leaf requires its independent original row')
    for item, p in zip(control_leaves, value['control_leaf_paths']):
        need(type(item) is dict and set(item) == {'path', 'entry'} and item['path'] == p
             and type(item['entry']) is dict and p not in rows,
             'control leaf omitted, duplicated or leaked into a v1 inventory')
        rows[p] = item['entry']
        if item['entry'].get('kind') == 'file':
            need(type(item['entry'].get('bytes')) is int and item['entry']['bytes'] >= 0,
                 'control leaf byte count differs')
            total += item['entry']['bytes']
    for p in value['required_absence_roots']:
        if p in value['control_leaf_paths']:
            need(rows[p] == {'kind': 'absent', 'absence': 'ENOENT'}, 'explicit absent control leaf is present')
        else:
            need(p not in rows, 'nonfixture absence leaked into a v1 inventory view')
            rows[p] = {'kind': 'absent', 'absence': 'ENOENT'}
    return {'schema': 'hepta.native-guard.complete-inventory.v1', 'roots': value['roots'],
            'entries': rows, 'file_bytes_hashed': total, 'elapsed_seconds': elapsed,
            'inventory_is_closure_or_retirement': False}


def _epoch_inventory_observation_value(value, inventory, absence_observations, business, control, leaf_parents):
    entries = inventory['entries']; pairs = value['alias_pairs']
    return {
        'schema': 'hepta.native-guard.two-epoch-inventory-observation.v1',
        'state': 'COMPLETE_UNION_OBSERVED_ONE_SHARED_BUDGET',
        'spec_sha256': value['spec_sha256'], 'legacy_anchor': EPOCH_INVENTORY_LEGACY_ANCHOR,
        'domain_roots': value['domain_roots'],
        'business_inventory_roots': value['business_inventory_roots'],
        'control_inventory_roots': value['control_inventory_roots'],
        'inventory_descriptors': {'business': descriptor(encoded(business)),
                                  'control': descriptor(encoded(control)) if control is not None else None},
        'control_leaves': [{'path': p, 'entry': entries[p]} for p in value['control_leaf_paths']],
        'control_leaf_parent_observations': leaf_parents,
        'active_reservation_count': value['active_reservation_count'],
        'legacy_fixture_count': 7, 'active_fixture_count': value['active_fixture_count'],
        'shared_budget': {'root_limit': 64, 'entry_limit': 30000,
                         'byte_limit': 512 * 1024 * 1024, 'seconds_limit': 30,
                         'file_byte_limit': 64 * 1024 * 1024, 'directory_child_limit': 20000,
                         'roots_observed': len(inventory['roots']), 'entries_observed': len(entries),
                         'file_bytes_hashed': inventory['file_bytes_hashed'],
                         'elapsed_seconds': inventory['elapsed_seconds'],
                         'file_body_reads': sum(row['kind'] == 'file' for row in entries.values()),
                         'monotonic_clock_initializations': 1, 'full_union_traversals': 1,
                         'counter_or_clock_resets': 0, 'aliases_deduplicated': False},
        'aliases': {'pairs': pairs, 'pair_count': len(pairs), 'path_rows_charged': 2 * len(pairs),
                    'file_bytes_charged_for_both_views': sum(entries[p]['bytes']
                        for pair in pairs for p in pair if entries[p]['kind'] == 'file')},
        'positive_absence_roots': [p for p in inventory['roots'] if entries[p]['kind'] == 'absent'],
        'absence_observations': absence_observations,
        'complete_path_bookends': True, 'native_boundary_created': False,
        'inventory_is_closure_or_retirement': False, 'case_or_lease_authorized': False}


def verify_epoch_inventory_observation(spec, inventory, control_inventory, observation):
    """Pure structural proof; provenance and preservation remain separate gates."""
    value = inventory_epoch_spec_value(spec)
    need(type(observation) is dict, 'explicit epoch observation object required')
    business = inventory
    inventory = _epoch_inventory_join_views(value, business, control_inventory, observation.get('control_leaves'))
    need(type(inventory) is dict and set(inventory) == {
        'schema', 'roots', 'entries', 'file_bytes_hashed', 'elapsed_seconds',
        'inventory_is_closure_or_retirement'}
         and inventory['schema'] == 'hepta.native-guard.complete-inventory.v1'
         and inventory['roots'] == value['roots']
         and inventory['inventory_is_closure_or_retirement'] is False,
         'complete epoch inventory envelope differs')
    elapsed = inventory['elapsed_seconds']
    need(type(elapsed) in (int, float) and 0 <= elapsed < 30,
         'shared epoch inventory deadline exhausted or malformed')
    rows = inventory['entries']
    need(type(rows) is dict and 0 < len(rows) <= 30000, 'shared epoch inventory entry bound')
    roots = [Path(p).parts for p in value['roots']]
    fixtures = value['fixture_roots']; aliases = {a: b for pair in value['alias_pairs'] for a, b in (pair, pair[::-1])}
    required_absent = set(value['required_absence_roots'])
    children = {}; inode_paths = {}; total = 0
    for path, row in rows.items():
        p = _epoch_inventory_path(path)
        need(sum(p.parts[:len(root)] == root for root in roots) == 1
             and type(row) is dict, 'inventory entry leaves or overlaps the exact root union')
        if path not in value['roots']:
            children.setdefault(str(p.parent), []).append(p.name)
        if row.get('kind') == 'absent':
            need(set(row) == {'kind', 'absence'} and row['absence'] == 'ENOENT'
                 and path in value['roots'] and (path in fixtures or path in required_absent),
                 'only a declared fixture/explicit absence root may be absent')
            continue
        need(path not in required_absent and 'metadata' in row,
             'explicit absent root is present or metadata omitted')
        m = row['metadata']
        need(type(m) is list and len(m) == 9 and all(type(n) is int for n in m)
             and m[0] >= 0 and m[1] > 0 and all(n >= 0 for n in m[3:]),
             'complete nonnegative nine-field metadata required')
        fixture = _epoch_inventory_fixture(path, fixtures)
        if fixture:
            need(m[3] == m[4] == 2000 and stat.S_IMODE(m[2]) in (0o700, 0o600, 0o400),
                 'fixture inventory ownership/mode differs')
        if row.get('kind') == 'directory':
            need(set(row) == {'kind', 'metadata', 'names'} and stat.S_ISDIR(m[2])
                 and type(row['names']) is list and len(row['names']) <= 20000
                 and all(type(n) is str and n not in ('', '.', '..')
                         and '/' not in n and '\0' not in n for n in row['names'])
                 and row['names'] == sorted(set(row['names'])), 'complete inventory directory differs')
        else:
            need(row.get('kind') == 'file' and set(row) == {'kind', 'metadata', 'bytes', 'sha256'}
                 and stat.S_ISREG(m[2]) and m[5] == 1 and type(row['bytes']) is int
                 and 0 <= row['bytes'] == m[6] <= 64 * 1024 * 1024
                 and type(row['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', row['sha256']),
                 'complete inventory file differs')
            if path in value['control_leaf_pins']:
                pin = value['control_leaf_pins'][path]
                need(encoded(m) == encoded(pin['metadata']) and row['bytes'] == pin['bytes']
                     and row['sha256'] == pin['sha256'], 'fixed original control leaf identity/content changed')
            elif not fixture:
                need(m[3] == m[4] == 0 and stat.S_IMODE(m[2]) == 0o600,
                     'private inventory file ownership/mode differs')
            total += row['bytes']; need(total <= 512 * 1024 * 1024, 'shared inventory byte bound')
        key = tuple(m[:2]); other = inode_paths.get(key)
        if other is not None:
            need(aliases.get(path) == other and rows[other] == row,
                 'unlisted/third inventory alias or unequal paired rows')
        else: inode_paths[key] = path
    need(set(value['roots']) <= set(rows), 'complete union omitted a root')
    for path in value['roots']:
        need(rows[path]['kind'] in (('file', 'absent') if path in value['control_leaf_paths']
                                    else ('directory', 'absent')),
             'only explicitly fixed control leaves may be file roots')
    for path, row in rows.items():
        actual = sorted(children.get(path, []))
        need((row['kind'] == 'directory' and row['names'] == actual)
             or (row['kind'] != 'directory' and not actual),
             'inventory child set is incomplete or non-directory has children')
        if path not in value['roots']:
            need(str(Path(path).parent) in rows and rows[str(Path(path).parent)]['kind'] == 'directory',
                 'inventory entry has no complete directory parent')
    for a, b in value['alias_pairs']:
        need(a in rows and b in rows and rows[a] == rows[b] and rows[a]['kind'] != 'absent',
             'fixed declared alias views are incomplete or changed')
    need(type(inventory['file_bytes_hashed']) is int and inventory['file_bytes_hashed'] == total,
         'union byte accounting omitted or deduplicated a path')
    need(type(observation) is dict, 'explicit epoch observation object required')
    absences = observation.get('absence_observations')
    absent_paths = [p for p in inventory['roots'] if rows[p]['kind'] == 'absent']
    need(type(absences) is list and len(absences) == len(absent_paths),
         'every positive absence needs its complete independent parent observation')
    for item, path in zip(absences, absent_paths):
        need(type(item) is dict and set(item) == {
            'schema', 'path', 'absence', 'parent_path', 'initial_parent_metadata',
            'initial_held_enoent_checks', 'initial_reopened_enoent_checks',
            'first_elapsed_seconds', 'final_parent_metadata', 'final_reopened_enoent_checks',
            'canonical_parent_reopened', 'last_elapsed_seconds'}
             and item['schema'] == 'hepta.native-guard.epoch-positive-root-absence.v1'
             and item['path'] == path and item['absence'] == 'ENOENT'
             and item['parent_path'] == str(Path(path).parent), 'positive absence original shape/path differs')
        m = item['initial_parent_metadata']
        need(type(m) is list and len(m) == 9 and all(type(n) is int for n in m)
             and m[0] >= 0 and m[1] > 0 and stat.S_ISDIR(m[2]) and all(n >= 0 for n in m[3:])
             and encoded(item['final_parent_metadata']) == encoded(m),
             'absence canonical parent full identity changed or incomplete')
        for key, expected_count in (('initial_held_enoent_checks', 2),
                ('initial_reopened_enoent_checks', 1), ('final_reopened_enoent_checks', 1)):
            need(type(item[key]) is int and item[key] == expected_count,
                 'positive absence held/reopened check count differs')
        first, last = item['first_elapsed_seconds'], item['last_elapsed_seconds']
        need(type(first) in (int, float) and type(last) in (int, float)
             and 0 <= first <= last <= elapsed and item['canonical_parent_reopened'] is True,
             'positive absence observation leaves the one shared operation clock')
    parents = observation.get('control_leaf_parent_observations')
    expected_parents = sorted({str(Path(p).parent) for p in value['control_leaf_paths']})
    need(type(parents) is list and len(parents) == len(expected_parents),
         'complete control-leaf parent observation list required')
    for item, path in zip(parents, expected_parents):
        need(type(item) is dict and set(item) == {
            'path', 'initial_metadata', 'initial_names', 'first_elapsed_seconds',
            'final_metadata', 'final_names', 'last_elapsed_seconds',
            'metadata_and_names_only', 'subtree_inventory_claimed'} and item['path'] == path
             and item['metadata_and_names_only'] is True and item['subtree_inventory_claimed'] is False,
             'control-leaf parent scope differs')
        m = item['initial_metadata']; names = item['initial_names']
        need(type(m) is list and len(m) == 9 and all(type(n) is int for n in m)
             and m[0] >= 0 and m[1] > 0 and stat.S_ISDIR(m[2]) and all(n >= 0 for n in m[3:])
             and encoded(m) == encoded(item['final_metadata'])
             and type(names) is list and len(names) <= 20000
             and all(type(n) is str and n not in ('', '.', '..') and '/' not in n and '\0' not in n for n in names)
             and names == sorted(set(names)) and encoded(names) == encoded(item['final_names']),
             'control-leaf parent full identity or names changed')
        first, last = item['first_elapsed_seconds'], item['last_elapsed_seconds']
        need(type(first) in (int, float) and type(last) in (int, float) and 0 <= first <= last <= elapsed,
             'control-leaf parent observation left the shared clock')
        for p in value['control_leaf_paths']:
            if str(Path(p).parent) == path:
                need((Path(p).name in names) == (rows[p]['kind'] == 'file'),
                     'control-leaf parent name set contradicts explicit leaf observation')
    expected = _epoch_inventory_observation_value(value, inventory, absences, business, control_inventory, parents)
    need(type(observation) is dict and encoded(observation) == encoded(expected),
         'explicit shared-budget/alias observation differs')
    return {'schema': 'hepta.native-guard.two-epoch-inventory-verification.v1',
            'spec_sha256': value['spec_sha256'], 'roots': len(value['roots']),
            'entries': len(rows), 'file_bytes_hashed': total, 'alias_pairs': len(value['alias_pairs']),
            'active_reservation_count': value['active_reservation_count'],
            'whole_union_structurally_verified': True, 'case_or_lease_authorized': False,
            'original_provenance_verified_by_this_function': False,
            'cross_operation_preservation_verified_by_this_function': False}


def inventory_epoch(spec):
    """Observe one explicitly admitted two-domain union under one original pool.

    This is a cooperative Python/I/O observation deadline, not a hard interrupt
    of a blocked kernel call. No signals, process creation or target writes are
    performed. There is no public clock/budget override or per-domain restart.
    """
    budget = _EpochInventoryBudget()
    value = inventory_epoch_spec_value(spec); budget.check()
    observed, absences, leaf_parents = _epoch_inventory_observe_roots(value, budget)
    budget.check()
    # Pure recomputation is charged to this same clock before any result exists.
    business, control = _epoch_inventory_split_views(value, observed)
    proof = _epoch_inventory_observation_value(value, observed, absences, business, control, leaf_parents)
    verify_epoch_inventory_observation(spec, business, control, proof)
    budget.check()
    observed['elapsed_seconds'] = time.monotonic() - budget.started
    need(observed['elapsed_seconds'] < 30, 'shared epoch final deadline exhausted')
    business['elapsed_seconds'] = observed['elapsed_seconds']
    if control is not None: control['elapsed_seconds'] = observed['elapsed_seconds']
    proof = _epoch_inventory_observation_value(value, observed, absences, business, control, leaf_parents)
    need(budget.entries == len(observed['entries'])
         and budget.bytes_read == observed['file_bytes_hashed']
         and budget.file_reads == proof['shared_budget']['file_body_reads'],
         'shared physical traversal accounting differs')
    need(sha(encoded(spec)) == value['spec_sha256'], 'epoch inventory spec changed during observation')
    budget.check()
    return {'inventory': business, 'control_inventory': control, 'epoch_observation': proof}


def baseline_roots(home, lease):
    return [PRODUCTION_EVIDENCE, COMPONENT_EVIDENCE, BASE/'client-receipts', BASE/'executor-r6',
            BASE/'provider-state/health-contracts/bindings', BASE/'provider-state/task-contracts/bindings',
            ANDROID/lease['android_journal'].lstrip('/'), home/'inputs', home/'package',home/'claims',home/'operator']


def stop_owned(child, identity, home, role):
    """One exact owned leader pidfd TERM, wait/join, no signal fallback/retry."""
    row = {'role': role, 'identity': identity, 'signals': [], 'child_wait_returned': False,
           'dedicated_process_group_absent': False, 'automatic_retry': False}
    if child.poll() is None:
        current = proc_stat(child.pid)
        need(current is not None and generation(current) == identity and identity[:3] == [child.pid]*3,
             'owned child identity changed; no signal sent')
        fd = os.pidfd_open(child.pid, 0)
        try:
            current = proc_stat(child.pid)
            need(current is not None and generation(current) == identity, 'owned child changed after pidfd open')
            put(home / (role+'.TERM-INTENT.json'), {'target_identity': identity,
                'signal': 'SIGTERM', 'via': 'pidfd', 'maximum_signal_attempts': 1, 'automatic_retry': False})
            try:
                signal.pidfd_send_signal(fd, signal.SIGTERM, None, 0)
                row['signals'].append('SIGTERM_SYSCALL_RETURNED')
            except OSError as error:
                need(error.errno == errno.ESRCH, 'one owned pidfd signal failed')
                row['signals'].append('ESRCH_AFTER_ONE_SIGNAL_ATTEMPT')
        finally:
            os.close(fd)
    try:
        row['child_exit_code'] = child.wait(timeout=12)
        row['child_wait_returned'] = True
        row['absence'] = [absent_groups([identity]), absent_groups([identity])]
        row['dedicated_process_group_absent'] = True
    except BaseException as error:
        row['error'] = type(error).__name__ + ':' + str(error)[:512]
    put(home / (role+'.JOINED.json'), row)
    return row


def child_role(args, home, lease, combo):
    need(args.role in ('sidecar', 'provider'), 'only two component roles allowed')
    own = native_root(lease['boot_id']); ident = own['identity']
    need(ident[:3] == [os.getpid()]*3, 'dedicated child PID/PGID/SID required before admission')
    parent = strict(read(home/'SUPERVISOR.json', 16384))['identity']
    need(own['ppid'] == parent[0] and target_identity(parent[0], parent)['domain'] == MAGISK,
         'owned supervisor generation differs')
    put(home / (args.role+'.barrier.json'), {'identity': ident, 'parent_identity': parent,
        'domain': own['domain'], 'application_not_executed': True})
    deadline = time.monotonic()+5
    while time.monotonic() < deadline:
        need(target_identity(parent[0], parent)['domain'] == MAGISK, 'supervisor changed during barrier')
        try:
            admit = strict(read(home/(args.role+'.ADMIT.json'), 16384))
        except FileNotFoundError:
            time.sleep(.05); continue
        need(admit == {'identity': ident, 'parent_identity': parent,
                      'lease_sha256': args.lease_sha256, 'role': args.role}, 'one-use child admission differs')
        verify_external(combo)
        if args.role == 'sidecar':
            command = [str(ANDROID/'data/adb/magisk/busybox'), 'chroot', str(ANDROID),
                       SIDECAR, '--state-dir', lease['android_journal']]
            env = reviewed_android_sidecar_environment(lease['boot_id'])
        else:
            need(args.listener_fd is not None, 'exclusive listener fd missing')
            os.set_inheritable(args.listener_fd, True)
            command = [sys.executable, '-I', '-B', str(home/'package/source/component_listener.py'),
                '--package', str(home/'package/MANIFEST.json'), '--package-sha256', lease['package_sha256'],
                '--lease', str(home), '--lease-sha256', args.lease_sha256,
                '--listener-fd', str(args.listener_fd), '--execute-native-listener-once']
            env = {'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'}
        os.execve(command[0], command, env)
    need(False, 'component child admission expired; no automatic restart')


def launch_role(role, home, lease, lease_sha, combo, listener, children):
    journal = ANDROID/lease['android_journal'].lstrip('/')
    logs = journal if role == 'sidecar' else home
    put(home/(role+'.SPAWN-INTENT.json'), {'role': role, 'lease_sha256': lease_sha,
        'new_owned_session': True, 'no_model_role': True, 'automatic_restart': False})
    outputs = [open(logs/(role+'.'+name), 'xb', buffering=0) for name in ('stdout','stderr')]
    fds = () if role == 'sidecar' else (listener.fileno(),)
    argv = [sys.executable, '-I', '-B', str(home/'package/source/component_lifecycle.py'),
        '--lease', str(home), '--lease-sha256', lease_sha,
        '--package', str(home/'package/MANIFEST.json'), '--package-sha256', lease['package_sha256'],
        '--role', role, '--execute-child-role-once']
    if fds:
        argv += ['--listener-fd', str(fds[0])]
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=outputs[0], stderr=outputs[1],
        start_new_session=True, close_fds=True, pass_fds=fds,
        env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'})
    for stream in outputs:
        stream.close()
    row = proc_stat(child.pid); need(row is not None, 'spawned child disappeared before identity binding')
    ident = generation(row); need(ident[:3] == [child.pid]*3, 'spawned group/session differs')
    children[role] = (child, ident)
    put(home/(role+'.SPAWNED.json'), {'pid':child.pid,'identity':ident,'argv':argv,'automatic_retry':False})
    deadline = time.monotonic()+5
    while time.monotonic() < deadline:
        need(child.poll() is None and generation(proc_stat(child.pid)) == ident, 'child exited at admission barrier')
        try:
            barrier = strict(read(home/(role+'.barrier.json'), 16384))
        except FileNotFoundError:
            time.sleep(.05); continue
        parent = strict(read(home/'SUPERVISOR.json', 16384))['identity']
        need(barrier['identity'] == ident and barrier['parent_identity'] == parent
             and barrier['application_not_executed'] is True and barrier['domain'] == MAGISK,
             'child barrier original differs')
        put(home/(role+'.ADMIT.json'), {'identity':ident,'parent_identity':parent,
                                      'lease_sha256':lease_sha,'role':role})
        break
    else:
        need(False, 'child barrier not observed; no restart')
    return child, ident


def await_init_parent(boot_id, own):
    """Fix supervisor identity only after its one launcher has exited."""
    expected={k:v for k,v in own.items() if k!='ppid'}
    deadline=time.monotonic()+3
    while time.monotonic()<deadline:
        observed=target_identity(own['identity'][0],own['identity'])
        need({k:v for k,v in observed.items() if k!='ppid'}==expected,
             'supervisor changed while waiting for launcher exit')
        if observed['ppid']==1:
            final=native_root(boot_id)
            need(final==observed and final['ppid']==1,
                 'supervisor native init parent is not stable')
            return final
        time.sleep(.02)
    need(False,'launcher parent did not exit within 3 seconds; no retry or role launch')


def detached_launch(args):
    """One explicit fork/session/exec; parent returns no readiness claim."""
    home=private_dir(Path(args.lease));lease,lease_raw=load_lease(home,args.lease_sha256)
    verify_package(Path(args.package),args.package_sha256)
    need(args.package_sha256==lease['package_sha256']
         and Path(args.package)==home/'package/MANIFEST.json','launcher lease package differs')
    combo_raw=pinned(home/'inputs/COMBINATION.json',lease['combination'])
    reviewed=strict(read(home/'package/reference/REVIEWED-PRODUCTION-PINS.json'))
    combo,_cfg=load_combination(home/'inputs',combo_raw,reviewed)
    own=native_root(lease['boot_id']);verify_external(combo)
    need(sys.executable==combo['artifacts']['python']['path']==own['exe'],
         'launcher must use the exact reviewed GNU Python entry')
    for name in ('SUPERVISOR.json','LIFECYCLE-ATTEMPT.json','LIFECYCLE-ENDED.json'):
        try:(home/name).lstat()
        except FileNotFoundError:pass
        else:need(False,'component lifecycle already attempted; no fork')
    old_lock=None;outputs=[]
    argv=[combo['artifacts']['python']['path'],'-I','-B',str(home/'package/source/component_lifecycle.py'),
        '--lease',str(home),'--lease-sha256',args.lease_sha256,
        '--package',str(home/'package/MANIFEST.json'),'--package-sha256',lease['package_sha256'],
        '--execute-component-lifecycle-once']
    try:
        old_lock,retired=verify_retired(lease)
        put(home/'DETACHED-LAUNCH-INTENT.json',{'schema':'hepta.native-guard.detached-launch-intent.v1',
            'lease_sha256':sha(lease_raw),'launcher_identity':own,'supervisor_argv':argv,
            'retirement_sha256':retired['retirement_sha256'],'maximum_forks':1,'maximum_execs':1,
            'supervisor_parent_required_before_admission':1,'automatic_retry':False,
            'readiness_asserted':False,'model_requests':0,'native_task_submissions':0})
        for name in ('stdout','stderr'):
            outputs.append(os.open(home/('supervisor.'+name),
                os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600))
        need(time.time_ns()//1000000<lease['expires_unix_ms'],'lease expired before the sole fork')
        child=os.fork()
        if child==0:
            try:
                os.setsid()
                devnull=os.open('/dev/null',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
                need(stat.S_ISCHR(os.fstat(devnull).st_mode),'stdin null device differs')
                os.dup2(devnull,0);os.dup2(outputs[0],1);os.dup2(outputs[1],2)
                os.close(devnull)
                for fd in outputs:os.close(fd)
                os.close(old_lock)
                os.execve(argv[0],argv,{'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
                    'PYTHONDONTWRITEBYTECODE':'1'})
            except BaseException as error:
                os.write(2,encoded({'state':'DETACHED_CHILD_EXEC_FAILED_NO_RETRY',
                    'type':type(error).__name__,'detail':str(error)[:512]}))
            os._exit(70)
        result={'schema':'hepta.native-guard.detached-launch-observation.v1',
            'state':'ONE_FORK_RETURNED_SUPERVISOR_NOT_YET_ADMITTED','lease_sha256':sha(lease_raw),
            'fork_returned_pid':child,'launcher_identity':own['identity'],
            'readiness_asserted':False,'child_generation_not_inferred':True,
            'automatic_retry':False,'model_requests':0,'native_task_submissions':0}
        put(home/'DETACHED-LAUNCH-RESULT.json',result)
        print(encoded(result).decode(),end='')
        return 0
    finally:
        for fd in outputs:os.close(fd)
        if old_lock is not None:os.close(old_lock)


def supervise(args):
    home = private_dir(Path(args.lease)); lease, lease_raw = load_lease(home, args.lease_sha256)
    verify_package(Path(args.package), args.package_sha256)
    need(args.package_sha256 == lease['package_sha256']
         and Path(args.package) == home/'package/MANIFEST.json', 'lease package differs')
    combo_raw = pinned(home/'inputs/COMBINATION.json', lease['combination'])
    reviewed = strict(read(home/'package/reference/REVIEWED-PRODUCTION-PINS.json'))
    combo, _cfg = load_combination(home/'inputs', combo_raw, reviewed)
    own = native_root(lease['boot_id']); verify_external(combo)
    need(own['identity'][:3] == [os.getpid()]*3, 'Root must launch one dedicated supervisor session')
    own = await_init_parent(lease['boot_id'],own)
    launch_raw=read(home/'DETACHED-LAUNCH-INTENT.json',65536)
    launch_result_raw=read(home/'DETACHED-LAUNCH-RESULT.json',16384)
    launch=strict(launch_raw);launch_result=strict(launch_result_raw)
    need(launch.get('schema')=='hepta.native-guard.detached-launch-intent.v1'
         and launch.get('lease_sha256')==sha(lease_raw)
         and launch.get('retirement_sha256')==lease['retirement']['proof']['sha256']
         and launch.get('maximum_forks')==launch.get('maximum_execs')==1
         and launch.get('supervisor_parent_required_before_admission')==1
         and launch.get('automatic_retry') is False and launch.get('readiness_asserted') is False
         and base64.b64decode(own['argv_b64'],validate=True)==b'\0'.join(
             part.encode() for part in launch['supervisor_argv'])+b'\0',
         'actual supervisor argv is not the one original detached launch')
    need(launch_result=={'schema':'hepta.native-guard.detached-launch-observation.v1',
         'state':'ONE_FORK_RETURNED_SUPERVISOR_NOT_YET_ADMITTED','lease_sha256':sha(lease_raw),
         'fork_returned_pid':own['identity'][0],'launcher_identity':launch['launcher_identity']['identity'],
         'readiness_asserted':False,'child_generation_not_inferred':True,'automatic_retry':False,
         'model_requests':0,'native_task_submissions':0},'actual detached fork original differs')
    need(time.time_ns()//1000000<lease['expires_unix_ms'],'lease expired before supervisor admission')
    need(hasattr(os,'pidfd_open') and hasattr(signal,'pidfd_send_signal'), 'owned pidfd termination required')
    put(home/'LIFECYCLE-ATTEMPT.json', {'lease_sha256':sha(lease_raw),'identity':own['identity'],
        'native_proc_profile':native_proc_profile.PROFILE,
        'detached_launch_intent_sha256':sha(launch_raw),'detached_launch_result_sha256':sha(launch_result_raw),
        'automatic_restart':False,'model_requests':0,'native_task_submissions':0})
    put(home/'SUPERVISOR.json', own)
    old_lock = None; listener = None; children = {}; cleanup = {}; success = False; error = None
    stopped = [False]
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):
        signal.signal(sig, lambda _s,_f:stopped.__setitem__(0,True))
    try:
        old_lock, retired = verify_retired(lease); put(home/'RETIRED-BASELINE-VERIFIED.json',retired)
        baseline = inventory(baseline_roots(home,lease)); put(home/'BASELINE-INVENTORY.json',baseline)
        listener = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        # No SO_REUSEPORT/REUSEADDR, reverse, alternate port or reconnect path.
        listener.bind(('127.0.0.1',18080))
        put(home/'PORT-RESERVED.json',{'address':['127.0.0.1',18080],'exclusive_bind':True,
            'listening':False,'no_production_provider_takeover':True})
        sidecar,ident = launch_role('sidecar',home,lease,args.lease_sha256,combo,listener,children)
        deadline = time.monotonic()+8; observed = None
        while time.monotonic()<deadline and not stopped[0]:
            need(sidecar.poll() is None,'new sidecar exited; no restart')
            row = target_identity(sidecar.pid,ident)
            if row['domain']==PARENT_DOMAIN and row['exe']==SIDECAR:
                observed=row;break
            time.sleep(.05)
        need(observed is not None and observed['uid']==observed['gid']==[0]*4 and observed['nnp']==0,
             'new sidecar actual credentials/domain/exe unknown')
        need(base64.b64decode(observed['argv_b64']) == b'\0'.join(
            x.encode() for x in [SIDECAR,'--state-dir',lease['android_journal']])+b'\0', 'new sidecar argv differs')
        client_raw=read(CLIENT);need(sha(client_raw)==CLIENT_SHA,'client changed')
        client=types.ModuleType('component_root_readonly_client');client.__file__=str(CLIENT)
        exec(compile(client_raw,str(CLIENT),'exec'),client.__dict__)
        # Wait only for the pinned sidecar's original one-line startup output;
        # no health/execute request is replayed to discover readiness.
        journal=ANDROID/lease['android_journal'].lstrip('/')
        startup=None
        while time.monotonic()<deadline and not stopped[0]:
            need(sidecar.poll() is None,'sidecar exited before ready')
            raw=read(journal/'sidecar.stdout',16384)
            if raw.endswith(b'\n'):
                startup=strict(raw);break
            time.sleep(.05)
        need(startup is not None and startup.get('state')=='ready','sidecar startup readiness absent')
        health=client.request({'version':1,'op':'health'},timeout_s=3)
        need(health.get('version')==1 and health.get('protocol')=='hepta_phone_local_v150'
             and health.get('state')=='ready' and health.get('executor_revision')==6
             and health.get('server_instance')==startup['server_instance']
             and re.fullmatch('[0-9a-f]{32}',health['server_instance'])
             and health.get('executor_context')==PARENT_DOMAIN and health.get('peer_context')==MAGISK
             and health.get('execute_authorized') is False and health.get('inference_endpoint') is False,
             'new component sidecar read-only admission differs')
        need(target_identity(sidecar.pid,ident)==observed,'sidecar changed across readiness')
        put(home/'SIDECAR-HEALTH.original.json',health)
        contract={k:lease[k] for k in ('case_id','nonce','owner_request_sha256','selected_session_id','selected_profile_id')}
        contract.update(schema='hepta.native-guard-component.contract.v150.r10.1',
            source_seal_sha256=combo['source_seal']['sha256'],configuration_sha256=combo['configuration']['sha256'],
            executor_server_instance=health['server_instance'])
        bound={'schema':'hepta.native-guard.bound-contract.v1','contract':contract,'lease_sha256':sha(lease_raw),
            'sidecar_identity':observed,'sidecar_health':health,'run_basename':time.strftime('%Y%m%d-%H%M%S')+'-'+lease['nonce'],
            'provider_source_sha256':sha(read(home/'package/source/component_listener.py'))}
        put(home/'BOUND-CONTRACT.json',bound)
        provider,pident=launch_role('provider',home,lease,args.lease_sha256,combo,listener,children)
        listener.close();listener=None
        deadline=min(time.monotonic()+435, time.monotonic()+(lease['expires_unix_ms']/1000-time.time()))
        while not stopped[0] and time.monotonic()<deadline:
            need(sidecar.poll() is None,'component sidecar exited while provider active')
            need(target_identity(sidecar.pid,ident)==observed,'component sidecar generation changed')
            code=provider.poll()
            if code is not None:
                success=code==0;break
            time.sleep(.1)
        else:
            need(False,'component lifecycle deadline/stop; original scope cleanup required')
    except BaseException as exc:
        error={'type':type(exc).__name__,'detail':str(exc)[:1024]}
        put(home/'LIFECYCLE-FAILURE.json',error)
    finally:
        if listener is not None:listener.close()
        for role in ('provider','sidecar'):
            if role in children:
                try:cleanup[role]=stop_owned(*children[role],home,role)
                except BaseException as exc:
                    cleanup[role]={'error':type(exc).__name__+':'+str(exc)[:512],
                                   'owned_cleanup_unknown':True,'automatic_retry':False}
        if old_lock is not None:os.close(old_lock)
        put(home/'LIFECYCLE-ENDED.json',{'schema':'hepta.native-guard.lifecycle-ended.v1',
            'provider_observation_exit_zero':success,'failure':error,'roles':cleanup,
            'roles_joined_and_groups_absent':set(cleanup)=={'provider','sidecar'} and all(
                v.get('child_wait_returned') is True and v.get('dedicated_process_group_absent') is True for v in cleanup.values()),
            'supervisor_exit_not_yet_independently_observed':True,'native_turn_terminal_verified':False,
            'component_qualified':False,'business_qualified':False,'model_requests':0,
            'automatic_restart':False,'late_full_inventory_required':True})
    return 0 if success and error is None and all(v.get('dedicated_process_group_absent') is True for v in cleanup.values()) else 70


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser()
    p.add_argument('--lease',required=True);p.add_argument('--lease-sha256',required=True)
    p.add_argument('--package',required=True);p.add_argument('--package-sha256',required=True)
    p.add_argument('--role',choices=('provider','sidecar'));p.add_argument('--listener-fd',type=int)
    p.add_argument('--execute-component-lifecycle-once',action='store_true')
    p.add_argument('--execute-child-role-once',action='store_true')
    p.add_argument('--execute-detached-launch-once',action='store_true')
    a=p.parse_args()
    need(sum((a.execute_component_lifecycle_once,a.execute_child_role_once,a.execute_detached_launch_once))==1,
         'one explicit operation required')
    if a.execute_child_role_once:
        home=private_dir(Path(a.lease));lease,_=load_lease(home,a.lease_sha256)
        verify_package(Path(a.package),a.package_sha256)
        need(a.package_sha256==lease['package_sha256'],'child package differs')
        raw=pinned(home/'inputs/COMBINATION.json',lease['combination'])
        reviewed=strict(read(home/'package/reference/REVIEWED-PRODUCTION-PINS.json'))
        combo,_=load_combination(home/'inputs',raw,reviewed)
        child_role(a,home,lease,combo)
    else:
        need(a.role is None and a.listener_fd is None,'supervisor may not borrow another role/listener')
        return detached_launch(a) if a.execute_detached_launch_once else supervise(a)


if __name__=='__main__':
    raise SystemExit(main())
