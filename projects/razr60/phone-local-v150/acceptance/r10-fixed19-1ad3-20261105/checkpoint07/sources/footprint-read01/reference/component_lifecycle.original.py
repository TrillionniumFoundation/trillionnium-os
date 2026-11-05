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
