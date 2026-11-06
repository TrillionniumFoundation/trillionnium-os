#!/usr/bin/env python3
"""Pinned input and process primitives for an explicitly separate component lease.

No import-time phone access, listener, execution or nonce generation.  These
functions deliberately do not grant business, model or four-role qualification.
"""
import ast
import base64
import errno
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import types

BASE = Path('/var/lib/trillionnium/owner-open/phone-local-v150')
ANDROID = Path('/proc/1/root')
ANDROID_BASE = Path('/data/trillionnium/owner-open/state/phone-local-v150')
PRODUCTION_EVIDENCE = BASE / 'provider-state/evidence'
COMPONENT_EVIDENCE = BASE / 'component-probe-r6/evidence'
SOCKET_NAME = 'hepta_phone_executor_v150_r6'
CLIENT = BASE / 'tool_client_r6.py'
CLIENT_SHA = '500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f'
SIDECAR = '/data/local/tmp/hepta-phone-executor-v150-r6/bin/phone-tool-sidecar-r6'
SIDECAR_SHA = '8595f99cf8d0f39ec2a45f85f1250745c158ea504d2d0520cd83791f28bdb976'
WORKER = '/data/local/tmp/hepta-phone-executor-v150-r6/bin/phone-tool-worker-r6'
WORKER_SHA = '49fb74f8798194c63d5e510c0ed81604d64a55e1df84822d9457ae4110cab6da'
KERNEL_SHA = '77dacc52468de95b68f30baafbb1cbf7dd7452c3d9ce652980dbb4af0ca62d8b'
MAGISK = 'u:r:magisk:s0'
PARENT_DOMAIN = 'u:r:trillionnium_owner_open_phone_executor:s0'
WORKER_DOMAIN = 'u:r:trillionnium_owner_open_phone_worker:s0'
EXECUTOR_LABEL = 'u:object_r:trillionnium_owner_open_phone_executor_data_file:s0'
SCOPE = ('session_id', 'profile_id', 'task_id', 'turn_id', 'turn_stream_id')
MAX_FRAME = 1024 * 1024
MAX_TURN_SECONDS = 300
MAX_LEASE_SECONDS = 600
HASH = re.compile('[0-9a-f]{64}\\Z')


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode()


def strict(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))


def metadata(s):
    return [getattr(s, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
        'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')]


def parent_fd(path):
    """Walk directory FDs without links; only /proc/1/root is an explicit anchor.

    The GNU chroot cannot resolve that Android magic link lexically. Runtime
    startup separately binds the init PID namespace and the anchor inode.
    """
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and 2 <= len(path.parts) <= 64,
         'bounded absolute path required')
    if path.parts[:4] == ('/', 'proc', '1', 'root'):
        fd = os.open(ANDROID, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        parts = path.parts[4:]
    else:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        parts = path.parts[1:]
    need(parts, 'file path required')
    try:
        for name in parts[:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = child
        return fd, parts[-1]
    except BaseException:
        os.close(fd); raise


def read(path, maximum=8 * 1024 * 1024, *, private=True):
    path = Path(path)
    parent, name = parent_fd(path)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    except BaseException:
        os.close(parent); raise
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= maximum, 'original type/link/size differs')
        if private:
            need(before.st_uid == before.st_gid == 0 and stat.S_IMODE(before.st_mode) == 0o600,
                 'private original ownership/mode differs')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        need(len(raw) == before.st_size and metadata(before) == metadata(os.fstat(fd))
             == metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'original changed during read')
        return raw
    finally:
        os.close(fd); os.close(parent)


def descriptor(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}


def pinned(path, pin, maximum=8 * 1024 * 1024, *, private=True):
    need(isinstance(pin, dict) and set(pin) == {'bytes', 'sha256'}
         and type(pin['bytes']) is int and pin['bytes'] >= 0
         and isinstance(pin['sha256'], str) and HASH.fullmatch(pin['sha256']), 'exact file pin required')
    raw = read(path, maximum, private=private)
    need(descriptor(raw) == pin, 'original byte pin differs: ' + str(path))
    return raw


def private_dir(path, *, create=False):
    path = Path(path)
    parent, name = parent_fd(path)
    try:
        if create:
            os.mkdir(name, mode=0o700, dir_fd=parent); os.fsync(parent)
        s = os.stat(name, dir_fd=parent, follow_symlinks=False)
    finally:
        os.close(parent)
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == s.st_gid == 0
         and stat.S_IMODE(s.st_mode) == 0o700 and not path.is_symlink(), 'private directory differs')
    return path


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def put(path, value):
    path = Path(path); private_dir(path.parent)
    raw = value if isinstance(value, bytes) else encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw); out.flush(); os.fsync(out.fileno())
    sync(path.parent)
    return descriptor(raw)


def relative(name):
    p = Path(name)
    need(isinstance(name, str) and str(p) == name and p.parts and not p.is_absolute()
         and '..' not in p.parts, 'canonical package-relative input required')
    return p


def scope(value):
    need(isinstance(value, dict) and set(value) == set(SCOPE)
         and all(isinstance(value[k], str) and 0 < len(value[k].encode()) <= 256
                 and '\0' not in value[k] for k in SCOPE), 'actual native five-scope required')
    return value


def root_operation_id(scope_value, contract_sha256, phase):
    """Derive an original-scope token; this never creates a new task nonce."""
    scope(scope_value)
    need(HASH.fullmatch(contract_sha256) and phase in ('setup','before-guard','after-guard'),
         'actual Root phase token binding differs')
    return sha(encoded({'scope':scope_value,'contract_sha256':contract_sha256,'phase':phase}))[:32]


def verify_package(package, pin):
    package = Path(package)
    raw = read(package, 262144); need(sha(raw) == pin, 'adapter package pin differs')
    m = strict(raw)
    need(m.get('schema') == 'hepta.native-guard.adapter-package.v1'
         and m.get('state') == 'HOST_REVIEWED_NOT_PHONE_QUALIFIED', 'explicit adapter package required')
    files = m['files']; names = [x['path'] for x in files]
    need(len(names) == len(set(names)) and 5 <= len(names) <= 32, 'package inventory bound')
    for row in files:
        data = pinned(package.parent / relative(row['path']),
                      {k: row[k] for k in ('bytes', 'sha256')}, private=False)
        if row['path'] == 'reference/native_guard_session.py':
            need(sha(data) == KERNEL_SHA, 'frozen two-call kernel differs')
    need({'reference/native_guard_session.py', 'reference/REVIEWED-PRODUCTION-PINS.json',
          'source/native_guard_session_r2.py', 'source/component_common.py', 'source/component_listener.py',
          'source/component_lifecycle.py'} <= set(names), 'adapter package incomplete')
    return m


def load_combination(root, raw, reviewed_pins, *, private_inputs=True):
    """Read-only source/config/service pin validation; no model or role readiness."""
    root = Path(root); c = strict(raw)
    need(set(c) == {'schema', 'state', 'source_seal', 'configuration', 'service_inputs',
                   'production_files', 'artifacts', 'live_policy_sha256'}
         and c['schema'] == 'hepta.native-guard.component-combination.v150.r10.1'
         and c['state'] == 'REVIEWED_COMPONENT_BYTES_NOT_FOUR_ROLE_READY', 'explicit component combination required')
    need(isinstance(reviewed_pins, dict) and len(reviewed_pins) == 15, 'reviewed 15-source pins required')
    files = c['production_files']
    need(len(files) == 15 and {r['path'] for r in files} == {'production/' + n for n in reviewed_pins},
         'full reviewed production inventory differs')
    for row in files:
        name = Path(row['path']).name
        need(row['sha256'] == reviewed_pins[name], 'unreviewed production revision: ' + name)
        pinned(root / relative(row['path']), {k: row[k] for k in ('bytes', 'sha256')}, private=private_inputs)
    values = {}
    for key, filename in [('source_seal', 'SOURCE-SEAL.original.json'),
                          ('configuration', 'configuration.original.json'),
                          ('service_inputs', 'service-inputs.original.json')]:
        values[key] = strict(pinned(root / filename, c[key], private=private_inputs))
    s, cfg = values['source_seal'], values['configuration']
    need(set(s) == {'schema', 'state', 'intended_module_release', 'configuration',
                   'phone_service_inputs_sha256', 'production_files'}
         and s.get('schema') == 'hepta.native-guard.component-source-seal.v150.r10.1'
         and s.get('state') == 'REVIEWED_COMPONENT_BYTES_NOT_FINAL_RELEASE'
         and s.get('intended_module_release') == 'v150-r10-r1'
         and s.get('configuration') == c['configuration']
         and s.get('phone_service_inputs_sha256') == c['service_inputs']['sha256']
         and cfg.get('service_manifest_sha256') == c['service_inputs']['sha256'],
         'original source/config/service byte bindings differ')
    need(s['production_files'] == [dict(path='source/' + Path(x['path']).name,
             bytes=x['bytes'], sha256=x['sha256']) for x in files], 'source seal row order or bytes differ')
    need(isinstance(c['live_policy_sha256'], str) and HASH.fullmatch(c['live_policy_sha256']),
         'reviewed exact live policy pin required')
    artifacts = c['artifacts']
    need(set(artifacts) == {'client', 'sidecar', 'worker', 'screen_helper', 'focus_helper', 'unicode_helper',
                          'busybox', 'python'},
         'component external artifact set differs')
    for name, expected_path, expected_sha in [('client', str(CLIENT), CLIENT_SHA),
            ('sidecar', SIDECAR, SIDECAR_SHA), ('worker', WORKER, WORKER_SHA)]:
        need(artifacts[name]['path'] == expected_path and artifacts[name]['sha256'] == expected_sha,
             'native admission artifact differs: ' + name)
    need(artifacts['busybox']['path'] == '/data/adb/magisk/busybox'
         and artifacts['python']['path'] == '/usr/bin/python3',
         'exact reviewed launcher executable paths required')
    tree = ast.parse(read(root / 'production/phone_observation_tools.py', private=private_inputs))
    constants = {n.targets[0].id: ast.literal_eval(n.value) for n in tree.body
        if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
        and n.targets[0].id in {'SCREEN_JAR', 'SCREEN_JAR_SHA256', 'FOCUS_INPUT_JAR',
                               'FOCUS_INPUT_JAR_SHA256', 'INPUT_JAR', 'INPUT_JAR_SHA256'}}
    for artifact, stem in [('screen_helper', 'SCREEN_JAR'), ('focus_helper', 'FOCUS_INPUT_JAR'),
                           ('unicode_helper', 'INPUT_JAR')]:
        need(artifacts[artifact]['path'] == constants[stem]
             and artifacts[artifact]['sha256'] == constants[stem + '_SHA256'],
             'typed production helper byte pin differs: ' + artifact)
    return c, cfg


def verify_external(c):
    """Runtime only: exact existing files/labels; never relabel or chmod them."""
    result = {}
    for name, row in c['artifacts'].items():
        need(set(row) == {'path', 'bytes', 'sha256', 'uid', 'gid', 'mode', 'selinux'},
             'external artifact metadata descriptor differs')
        p = Path(row['path']) if name in ('client', 'python') else ANDROID / row['path'].lstrip('/')
        if name == 'python':
            need(str(p) == os.path.realpath(sys.executable), 'actual GNU Python executable differs')
        raw = pinned(p, {k: row[k] for k in ('bytes', 'sha256')}, 32*1024*1024, private=False)
        s = p.lstat(); label = os.getxattr(p, 'security.selinux', follow_symlinks=False).rstrip(b'\0').decode()
        need((s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode), label)
             == (row['uid'], row['gid'], row['mode'], row['selinux']), 'external artifact metadata changed')
        result[name] = {**row, 'observed_metadata': metadata(s)}
    enforce = (ANDROID / 'sys/fs/selinux/enforce').read_bytes()
    need(enforce in (b'1', b'1\n'), 'SELinux must remain enforcing')
    # Kernel policy is a pseudo-file with st_size=0; use its bounded byte stream.
    with (ANDROID / 'sys/fs/selinux/policy').open('rb') as stream:
        raw = stream.read(64*1024*1024+1)
    need(0 < len(raw) <= 64*1024*1024 and sha(raw) == c['live_policy_sha256'], 'live policy differs')
    return result


def stat_identity(raw, pid, *, census=False):
    need(type(census) is bool, 'explicit proc census mode required')
    head, tail = raw.rsplit(b') ', 1); fields = tail.split()
    need(head.startswith(str(pid).encode() + b' (') and len(fields) >= 20, 'proc stat shape')
    row = {'pid': pid, 'state': fields[0].decode(), 'ppid': int(fields[1]),
           'pgid': int(fields[2]), 'sid': int(fields[3]), 'start_ticks': int(fields[19])}
    if census:
        # A valid early process can start in tick zero. It still participates in
        # exact generation and PGID/SID membership checks; zero is not absence.
        need(row['start_ticks'] >= 0, 'proc census start ticks negative')
    else:
        need(row['start_ticks'] > 0 or (pid == 1 and row['start_ticks'] == 0), 'proc generation absent')
    return row


def proc_stat(pid, *, census=False):
    need(type(census) is bool, 'explicit proc census mode required')
    need(type(pid) is int and pid > 0, 'proc PID required')
    try:
        raw = Path('/proc/%d/stat' % pid).read_bytes()
    except FileNotFoundError:
        return None
    need(len(raw) <= 8192, 'proc stat bound')
    return stat_identity(raw, pid, census=census)


def generation(row):
    return [row[k] for k in ('pid', 'pgid', 'sid', 'start_ticks')]


def target_identity(pid, expected=None):
    a = proc_stat(pid); need(a is not None and a['state'] not in ('Z', 'X', 'x'), 'target generation not live')
    if expected is not None:
        need(generation(a) == expected, 'target process generation changed')
    p = Path('/proc/%d' % pid)
    status = (p / 'status').read_text()
    fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
    domain = (p / 'attr/current').read_bytes().rstrip(b'\0\n').decode()
    argv = (p / 'cmdline').read_bytes(); need(0 < len(argv) <= 65536 and argv.endswith(b'\0'), 'bounded target argv')
    exe = os.readlink(p / 'exe'); b = proc_stat(pid)
    need(b is not None and generation(a) == generation(b) and a['ppid'] == b['ppid'], 'target identity raced')
    return {'identity': generation(b), 'ppid': b['ppid'], 'domain': domain,
            'uid': list(map(int, fields['Uid'].split())), 'gid': list(map(int, fields['Gid'].split())),
            'nnp': int(fields['NoNewPrivs']), 'exe': exe,
            'argv_b64': base64.b64encode(argv).decode(), 'argv_sha256': sha(argv)}


def absent_groups(identities):
    """Only original generation and nonzero group/session identifiers count.

    A reused numeric PID with different ticks and PGID/SID=0 is not the retired
    group.  Enumeration errors other than a disappearing PID fail closed.
    """
    need(1 <= len(identities) <= 64 and all(len(x) == 4 and all(type(n) is int and n > 1
         for n in x) and x[0] == x[1] == x[2] for x in identities), 'owned-session identities required')
    ids = {x[0] for x in identities}; expected = {x[0]: x for x in identities}
    names = [n for n in os.listdir('/proc') if n.isdecimal()]
    need(len(names) <= 4096, 'proc census PID bound')
    members = []; deadline = time.monotonic() + 2
    for name in names:
        need(time.monotonic() < deadline, 'proc census deadline exceeded; absence unknown')
        row = proc_stat(int(name), census=True)
        if row is None:
            continue
        if ((row['pid'] in expected and generation(row) == expected[row['pid']])
             or row['pgid'] in ids or row['sid'] in ids):
            members.append(row)
    need(not members, 'owned group/session still observed')
    for pid in ids:
        try:
            os.kill(-pid, 0)
        except OSError as error:
            need(error.errno == errno.ESRCH, 'group absence unknown')
        else:
            need(False, 'kernel still observes owned group')
    return {'numeric_pids': len(names), 'members': [], 'kernel_group_absence': True,
            'observed_monotonic_ns': time.monotonic_ns()}


def import_pinned(path, pin, module_name):
    raw = pinned(path, pin, 16*1024*1024)
    m = types.ModuleType(module_name); m.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), m.__dict__)
    return m


def import_production(path):
    path = Path(path); sys.path.insert(0, str(path))
    result = {}
    for name in ('phone_local_tools', 'phone_observation_tools', 'phone_task_guards', 'action_ledger'):
        if name in sys.modules:
            need(Path(sys.modules[name].__file__).resolve() == path / (name + '.py'), 'foreign production module already imported')
        result[name] = importlib.import_module(name)
    return result
