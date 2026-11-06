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
CLIENT = BASE / 'tool_client_r6_output600000_1ad3_01.py'
CLIENT_SHA = '21020cc22e6a20a2827acc0bcf777cfea67591bc6f1e0d5b29c45bf4d90b03c9'
SIDECAR = '/data/local/tmp/hepta-phone-executor-v150-r6/bin/phone-tool-sidecar-r6-output600000-1ad3-01'
SIDECAR_SHA = '21b59e78c19f992d605ba9346febeeeb4161a8044580bf67441a04e785d9c2b2'
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


def load_combination(root, raw, reviewed_pins, *, private_inputs=True, actual_context=None):
    """Read-only source/config/service pin validation; no model or role readiness."""
    context=epoch_actual_context(globals())
    if actual_context is not None:need(actual_context==context,'actual combination context differs')
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


def open_live_policy(path):
    """Retry only a failed policy open reporting EBUSY, never an acquired fd.

    The retry window is one monotonic second, at most 21 open attempts, with
    each pause capped at 50ms. Existing caller deadlines remain unchanged.
    """
    deadline = time.monotonic() + 1.0
    last_busy = None
    for attempt in range(21):
        if attempt and time.monotonic() >= deadline:
            raise last_busy
        try:
            return os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        except OSError as error:
            if error.errno != errno.EBUSY:
                raise
            last_busy = error
            remaining = deadline - time.monotonic()
            if attempt == 20 or remaining <= 0:
                raise
            time.sleep(min(0.05, remaining))
    raise AssertionError('bounded policy-open loop exhausted unexpectedly')


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
    policy_fd = open_live_policy(ANDROID / 'sys/fs/selinux/policy')
    try:
        with os.fdopen(policy_fd, 'rb', closefd=False) as stream:
            raw = stream.read(64*1024*1024+1)
    finally:
        os.close(policy_fd)
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


def import_production(path, *, actual_context=None):
    context=epoch_actual_context(globals())
    if actual_context is not None:need(actual_context==context,'actual production context differs')
    path = Path(path); sys.path.insert(0, str(path))
    result = {}
    for name in ('phone_local_tools', 'phone_observation_tools', 'phone_task_guards', 'action_ledger'):
        if name in sys.modules:
            need(Path(sys.modules[name].__file__).resolve() == path / (name + '.py'), 'foreign production module already imported')
        result[name] = importlib.import_module(name)
    return result


import fcntl

# New current-generation epoch primitives. This fragment is intended to be
# appended to the existing component_common.py; it is not a 33rd runtime member.
# It provides no CLI and performs no action at import time. Binding and the full
# late/history/inventory admission remain required before any caller can write.
import errno as _ep_errno
import hashlib as _ep_hashlib
import json as _ep_json
import math as _ep_math
import os as _ep_os
from pathlib import Path as _EpPath
import re as _ep_re
import stat as _ep_stat
import time as _ep_time

EPOCH_PROTOCOL_BINDING = None
EPOCH_ID = 'legacy902-active01'
EPOCH_REGISTRY_ROOT = '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-epoch-legacy902-r10-r1'
EPOCH_ANDROID_TRANSPORT_ROOT = '/proc/1/root/data/local/tmp/hepta-phone-local-v150-r1/native-guard-epoch-legacy902-r10-r1'
EPOCH_MAX_SLOTS = 8
EPOCH_MAX_INPUT_FILES = 8192
EPOCH_MAX_INPUT_BYTES = 64 * 1024 * 1024
EPOCH_MAX_INPUT_FILE = 16 * 1024 * 1024
EPOCH_HASH = _ep_re.compile(r'[0-9a-f]{64}')
EPOCH_NONCE = _ep_re.compile(r'[0-9a-f]{32}')
EPOCH_LABEL = _ep_re.compile(r'[a-z0-9][a-z0-9-]{5,55}')
EPOCH_SCOPE_KEYS = ('session_id', 'profile_id', 'task_id', 'turn_id', 'turn_stream_id')


def _ep_need(condition, message):
    if not condition:
        raise ValueError(message)


def _ep_encoded(value):
    return (_ep_json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8', 'strict')


def _ep_strict(raw):
    _ep_need(type(raw) is bytes and 0 < len(raw) <= EPOCH_MAX_INPUT_FILE,
             'bounded epoch JSON original required')
    def pairs(items):
        result = {}
        for key, value in items:
            _ep_need(type(key) is str and key not in result, 'duplicate epoch JSON field')
            result[key] = value
        return result
    return _ep_json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs,
        parse_constant=lambda _: _ep_need(False, 'nonfinite epoch JSON value'))


def _ep_same(left, right):
    # JSON encodings retain the bool/int distinction that Python equality loses.
    return _ep_encoded(left) == _ep_encoded(right)


def _ep_exact(value, fields, message):
    _ep_need(type(value) is dict and set(value) == set(fields), message)
    return value


def _ep_sha(raw):
    _ep_need(type(raw) is bytes, 'original epoch bytes required')
    return _ep_hashlib.sha256(raw).hexdigest()


def _ep_bare(raw):
    return {'bytes': len(raw), 'sha256': _ep_sha(raw)}


def _ep_path(value):
    _ep_need(type(value) is str and '\0' not in value and len(value.encode()) <= 4096,
             'bounded exact epoch path required')
    path = _EpPath(value)
    _ep_need(path.is_absolute() and str(path) == value and '..' not in path.parts
             and '//' not in value and value != '/', 'canonical lexical epoch path required')
    return path


def _ep_full9(value, *, kind=None):
    _ep_need(type(value) is list and len(value) == 9
             and all(type(n) is int and n >= 0 for n in value), 'full9 epoch identity required')
    if kind == 'file':
        _ep_need(_ep_stat.S_ISREG(value[2]) and value[5] == 1,
                 'single-link epoch regular file required')
    elif kind == 'directory':
        _ep_need(_ep_stat.S_ISDIR(value[2]) and value[5] >= 1,
                 'epoch directory identity required')
    return value


def _ep_metadata(status):
    return [getattr(status, key) for key in ('st_dev', 'st_ino', 'st_mode',
        'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')]


def _ep_pin(value, *, original=False, maximum=EPOCH_MAX_INPUT_FILE):
    keys = {'path', 'bytes', 'sha256'} | ({'metadata'} if original else set())
    _ep_exact(value, keys, 'exact epoch file descriptor fields required')
    _ep_path(value['path'])
    _ep_need(type(value['bytes']) is int and 0 <= value['bytes'] <= maximum
             and type(value['sha256']) is str and EPOCH_HASH.fullmatch(value['sha256']),
             'bounded epoch file bytes and digest required')
    if original:
        _ep_full9(value['metadata'], kind='file')
        _ep_need(value['metadata'][6] == value['bytes'], 'epoch original size/full9 mismatch')
    return value


def _ep_scope(value):
    _ep_exact(value, EPOCH_SCOPE_KEYS, 'complete actual accepted native scope required')
    _ep_need(all(type(value[key]) is str and 0 < len(value[key].encode()) <= 256
                 and '\0' not in value[key] for key in EPOCH_SCOPE_KEYS),
             'bounded actual scope values required')
    return tuple(value[key] for key in EPOCH_SCOPE_KEYS)


def epoch_actual_context(namespace):
    # The caller supplies its actual module dictionary. A runtime=False flag is
    # never interpreted as Mac, and no path or platform heuristic is used.
    _ep_need(type(namespace) is dict and '__actual_context__' in namespace,
             'actual context must be injected explicitly before module execution')
    context = namespace['__actual_context__']
    _ep_need(type(context) is str and context in ('phone', 'mac', 'p4'),
             'actual context enum differs')
    return context


def epoch_binding_value(binding=None):
    selected = EPOCH_PROTOCOL_BINDING if binding is None else binding
    _ep_need(selected is not None, 'epoch protocol binding is not frozen')
    _ep_exact(selected, {'schema', 'epoch_id', 'boot_id', 'anchor', 'fixed_inputs',
        'retained_roots', 'control_roots', 'control_leaves', 'absence_roots',
        'alias_pairs', 'legacy_nonces', 'failed_nonces', 'retained_failed_fixture_absences',
        'retained_failed_native_nonces', 'additional_retained_prelaunch_nonces',
        'footprint_origin', 'prior_generations',
        'resource_profiles', 'source_contexts', 'proc_root'}, 'complete explicit epoch binding required')
    _ep_need(selected['schema'] == 'hepta.native-guard.epoch-protocol-binding.v3'
             and selected['epoch_id'] == EPOCH_ID
             and type(selected['boot_id']) is str and _ep_re.fullmatch(
                 r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', selected['boot_id']),
             'epoch identity and actual boot differ')
    _ep_pin(selected['anchor'])
    _ep_need(selected['anchor']['path'] == EPOCH_REGISTRY_ROOT + '/ANCHOR.json',
             'epoch anchor must have the one reviewed control path')
    _ep_need(type(selected['fixed_inputs']) is list and selected['fixed_inputs'],
             'complete anchor and failed-attempt original inputs required')
    for row in selected['fixed_inputs']:
        _ep_pin(row, original=True)
    _ep_need(len({r['path'] for r in selected['fixed_inputs']}) == len(selected['fixed_inputs']),
             'epoch fixed originals repeat a path')
    for name, count in (('legacy_nonces', 7), ('failed_nonces', 3),
            ('retained_failed_native_nonces', 1), ('additional_retained_prelaunch_nonces', 1)):
        values = selected[name]
        _ep_need(type(values) is list and len(values) == count
                 and all(type(n) is str and EPOCH_NONCE.fullmatch(n) for n in values)
                 and len(set(values)) == count, 'complete fixed historical nonce set required')
    domains=[selected[name] for name in ('legacy_nonces','failed_nonces',
        'retained_failed_native_nonces','additional_retained_prelaunch_nonces')]
    _ep_need(len(set(n for values in domains for n in values))==sum(map(len,domains)),
             'fixed historical nonce domains overlap')
    _ep_need(selected['retained_failed_native_nonces']==['6077fc8f045572edc4acfb13ed7e09a8']
             and selected['additional_retained_prelaunch_nonces']==['13ed8d3d16807322fb50923a8c1e8b42'],
             'the two additional retained domains must name their actual original nonces')
    failures=selected['retained_failed_fixture_absences']
    _ep_need(type(failures) is list and len(failures)==3
             and [r.get('nonce') for r in failures]==selected['failed_nonces'],
             'three exact failed fixture absences and forbidden nonces are mandatory')
    for row in failures:
        _ep_exact(row,{'label','nonce','path','presence','chain_intent'},
                  'fixed failed fixture identity fields differ')
        _ep_need(type(row['label']) is str and EPOCH_LABEL.fullmatch(row['label'])
                 and row['presence']=='absent'
                 and row['path']=='/proc/1/root/data/local/tmp/hepta-native-guard-'+row['nonce'],
                 'a retained failed fixture may only be its exact positive ENOENT namespace')
        _ep_exact(row['chain_intent'],{'bytes','sha256'},'actual failed chain intent pin required')
        _ep_need(type(row['chain_intent']['bytes']) is int and 0<row['chain_intent']['bytes']<=262144
                 and type(row['chain_intent']['sha256']) is str
                 and EPOCH_HASH.fullmatch(row['chain_intent']['sha256']),
                 'fixed failed chain original pin differs')
    _ep_origin(selected['footprint_origin'])
    for name in ('retained_roots', 'control_roots', 'absence_roots'):
        values = selected[name]
        _ep_need(type(values) is list and values and len(values) == len(set(values)),
                 'explicit nonempty fixed footprint list required: ' + name)
        for path in values:
            _ep_path(path)
    _ep_need(selected['control_roots'] == [EPOCH_REGISTRY_ROOT, EPOCH_ANDROID_TRANSPORT_ROOT],
             'both exact complete epoch control trees are required')
    _ep_need(not {r['path'] for r in failures}&set(selected['retained_roots']+selected['control_roots']+selected['absence_roots']),
             'the three failed fixture absences cannot be hidden as generic roots')
    leaves = selected['control_leaves']
    _ep_need(type(leaves) is list and len(leaves) == 12
             and len({r['path'] for r in leaves}) == 12, 'all twelve old transport leaves required')
    for row in leaves:
        _ep_pin(row, original=True)
    _ep_need(type(selected['alias_pairs']) is list, 'exact extra alias pairs required')
    used = set()
    for pair in selected['alias_pairs']:
        _ep_need(type(pair) is list and len(pair) == 2 and pair == sorted(set(pair)),
                 'exact two-view alias pair required')
        for path in pair:
            _ep_path(path)
            _ep_need(path not in used, 'a third or repeated alias is forbidden')
            used.add(path)
    generations = selected['prior_generations']
    _ep_need(type(generations) is list and len(generations) < EPOCH_MAX_SLOTS,
             'finite prior source-generation identities are required')
    for ordinal, generation in enumerate(generations, 1):
        _ep_exact(generation, {'original', 'value'}, 'complete prior catalog original required')
        _ep_pin(generation['original'], original=True)
        epoch_generation_value(generation['value'])
        _ep_need(generation['value']['ordinal'] == ordinal
                 and _ep_bare(_ep_encoded(generation['value'])) == {
                     k:generation['original'][k] for k in ('bytes','sha256')},
                 'prior catalog raw identity or order differs')
    _ep_need(len({g['value']['runtime']['sha256'] for g in generations}) == len(generations),
             'source generation repeats')
    _ep_need(type(selected['resource_profiles']) is list and selected['resource_profiles'],
             'explicit measured plus bounded copy/resource profiles are required')
    contexts = selected['source_contexts']
    _ep_exact(contexts, {'phone', 'mac', 'p4'}, 'all actual source contexts required')
    for path in contexts.values():
        _ep_path(path)
    epoch_proc_root_binding_value(selected['proc_root'], selected['boot_id'])
    return _ep_strict(_ep_encoded(selected))


def epoch_generation_value(value):
    _ep_exact(value, {'schema', 'epoch_id', 'ordinal', 'runtime', 'combination',
        'pure_verifier', 'derivation', 'predecessor_generation', 'closed_failure_input'},
        'explicit finite source-generation record required')
    _ep_need(value['schema'] == 'hepta.native-guard.epoch-generation-catalog.v1'
             and value['epoch_id'] == EPOCH_ID
             and type(value['ordinal']) is int and 1 <= value['ordinal'] <= EPOCH_MAX_SLOTS,
             'source-generation ordinal bound differs')
    for key in ('runtime', 'combination', 'pure_verifier', 'derivation'):
        _ep_pin(value[key])
    if value['ordinal'] == 1:
        _ep_need(value['predecessor_generation'] is None
                 and value['closed_failure_input'] is None,
                 'initial generation cannot invent a future closed failure')
    else:
        _ep_pin(value['predecessor_generation'])
        _ep_pin(value['closed_failure_input'])
    # This is an exact record shape, not a claim that its derivation is verified.
    # The caller must match the entire row to the frozen source catalog and run
    # its pinned source verifier before admission.
    return value


def epoch_current_catalog_value(raw, original_descriptor, *, binding,
        runtime_raw, combination_raw, verifier_descriptor, derivation_descriptor):
    """Acyclic current catalog identity; the full source verifier is separate.

    The source-bound policy names only actual prior catalogs. This current
    catalog is produced after the final runtime and pure verifier, and the Root
    coordinator pins it. It never contains that later Root package's hash.
    Actual ROOT-AUTHORIZATION may subsequently bind both immutable objects.
    """
    _ep_pin(original_descriptor, original=True)
    _ep_need(_ep_bare(raw) == {k:original_descriptor[k] for k in ('bytes','sha256')},
             'current catalog original bytes differ')
    value = epoch_generation_value(_ep_strict(raw))
    ordinal = len(binding['prior_generations']) + 1
    _ep_need(_ep_encoded(value) == raw and value['ordinal'] == ordinal
             and original_descriptor['path'] == EPOCH_REGISTRY_ROOT + '/generations/%02d.json' % ordinal,
             'current catalog canonical encoding, path or ordinal differs')
    for name, body in (('runtime', runtime_raw), ('combination', combination_raw)):
        _ep_need(_ep_bare(body) == {k:value[name][k] for k in ('bytes','sha256')},
                 'catalog does not bind the actual current ' + name)
    _ep_need(_ep_same(value['pure_verifier'], verifier_descriptor)
             and _ep_same(value['derivation'], derivation_descriptor),
             'current catalog changes the independently reviewed source proof')
    if ordinal > 1:
        prior = binding['prior_generations'][-1]['original']
        _ep_need(_ep_same(value['predecessor_generation'],
                         {k:prior[k] for k in ('path','bytes','sha256')}),
                 'source revision does not retain the exact previous catalog')
    return value


def epoch_manifest_value(manifest, originals_by_path, *, binding):
    fixed = epoch_binding_value(binding)
    _ep_exact(manifest, {'schema', 'files', 'directories'}, 'epoch input manifest fields differ')
    _ep_need(manifest['schema'] == 'hepta.native-guard.epoch-capture-inputs.v1',
             'epoch input manifest schema differs')
    files, directories = manifest['files'], manifest['directories']
    _ep_need(type(files) is list and 1 <= len(files) <= EPOCH_MAX_INPUT_FILES
             and type(directories) is list and 1 <= len(directories) <= 30000,
             'bounded nonempty complete epoch input sets required')
    _ep_need(type(originals_by_path) is dict
             and set(originals_by_path) == {r['path'] for r in files}
             and len(originals_by_path) == len(files), 'epoch original byte map is not exact')
    total = 0
    paths = set()
    public = {r['path']: r for r in fixed['control_leaves']}
    for row in files:
        _ep_pin(row, original=True)
        _ep_need(row['path'] not in paths, 'epoch input path repeats')
        paths.add(row['path'])
        raw = originals_by_path[row['path']]
        _ep_need(type(raw) is bytes and _ep_bare(raw) == {k:row[k] for k in ('bytes', 'sha256')},
                 'epoch original bytes differ from their exact pin')
        metadata = row['metadata']
        if row['path'] in public:
            _ep_need(_ep_same(row, public[row['path']]), 'old public transport leaf identity changed')
        elif _epoch_stage_api().epoch_installed_artifact_path(row['path']):
            _epoch_stage_api().epoch_installed_original_value(row,raw)
        else:
            _ep_need(metadata[3:6] == [0, 0, 1]
                     and _ep_stat.S_IMODE(metadata[2]) == 0o600,
                     'epoch input is not its exact private original')
        total += len(raw)
        _ep_need(total <= EPOCH_MAX_INPUT_BYTES, 'epoch captured input bytes exceed the shared pool')
    for row in directories:
        _ep_exact(row, {'path', 'metadata', 'names'}, 'epoch directory original fields differ')
        _ep_path(row['path']); _ep_full9(row['metadata'], kind='directory')
        _ep_need(row['path'] not in paths, 'epoch file/directory path repeats')
        paths.add(row['path'])
        names = row['names']
        _ep_need(type(names) is list and names == sorted(set(names)) and len(names) <= 20000
                 and all(type(n) is str and n not in ('', '.', '..') and '/' not in n
                         and '\0' not in n for n in names), 'epoch directory names are not closed and bounded')
    file_map = {r['path']:r for r in files}
    for expected in fixed['fixed_inputs']:
        _ep_need(expected['path'] in file_map
                 and _ep_same(file_map[expected['path']], expected),
                 'fixed historical or failed original is omitted or changed')
    return {'files': file_map, 'directories': {r['path']:r for r in directories},
            'file_count': len(files), 'retained_bytes': total}


def _ep_record(path, manifest_index, originals_by_path, fields, schema):
    _ep_need(path in manifest_index['files'], 'required epoch record was not captured: ' + path)
    raw = originals_by_path[path]
    value = _ep_strict(raw)
    _ep_exact(value, fields, 'epoch record fields differ: ' + path)
    _ep_need(value['schema'] == schema and _ep_encoded(value) == raw,
             'epoch record schema or canonical original encoding differs')
    return value, manifest_index['files'][path]


def epoch_reservation_value(value, *, binding, ordinal, previous_terminal):
    _ep_exact(value, {'schema', 'epoch_id', 'ordinal', 'boot_id', 'anchor',
        'generation', 'authorization_request', 'resource_reservation',
        'predecessor_terminal', 'nonce_generated', 'native_scope_assigned'},
        'epoch reservation fields differ')
    _ep_need(value['schema'] == 'hepta.native-guard.epoch-reservation.v2'
             and value['epoch_id'] == EPOCH_ID and type(value['ordinal']) is int
             and value['ordinal'] == ordinal and 1 <= ordinal <= EPOCH_MAX_SLOTS
             and value['boot_id'] == binding['boot_id']
             and _ep_same(value['anchor'], binding['anchor'])
             and _ep_same(value['predecessor_terminal'], previous_terminal)
             and value['nonce_generated'] is False and value['native_scope_assigned'] is False,
             'reservation changes known identity, predecessor or pre-acceptance semantics')
    _ep_pin(value['generation'],original=True)
    _ep_exact(value['authorization_request'],{'origin','utf8'},'complete preclaim authorization required')
    request=value['authorization_request'];_ep_origin(request['origin'])
    _ep_need(type(request['utf8']) is str and request['utf8'].count('{{EPOCH_NONCE}}')==1
        and 20<=len(request['utf8'].encode('utf-8'))<=16000
        and _ep_bare(request['utf8'].encode('utf-8'))=={k:request['origin'][k] for k in ('bytes','sha256')},
        'preclaim authorization original differs')
    _epoch_stage_api().epoch_resource_reservation_value(value['resource_reservation'])
    return value


def epoch_identity_value(value, reservation, reservation_pin, *, forbidden_nonces):
    _ep_exact(value, {'schema', 'epoch_id', 'ordinal', 'reservation', 'boot_id',
        'label', 'nonce', 'case_id', 'owner_request', 'selected_session_id',
        'selected_profile_id', 'source_generation', 'predecessor_terminal',
        'prior_boundary'}, 'epoch identity fields differ')
    _ep_need(value['schema'] == 'hepta.native-guard.epoch-identity.v1'
             and value['epoch_id'] == EPOCH_ID
             and type(value['ordinal']) is int and value['ordinal'] == reservation['ordinal']
             and _ep_same(value['reservation'], reservation_pin)
             and value['boot_id'] == reservation['boot_id']
             and _ep_same(value['source_generation'], reservation['generation'])
             and _ep_same(value['predecessor_terminal'], reservation['predecessor_terminal'])
             and type(value['nonce']) is str and EPOCH_NONCE.fullmatch(value['nonce'])
             and value['nonce'] not in forbidden_nonces
             and type(value['label']) is str and EPOCH_LABEL.fullmatch(value['label'])
             and value['case_id'] in ('NEG-01', 'NEG-02'), 'epoch identity binding or reuse differs')
    for name in ('selected_session_id', 'selected_profile_id'):
        _ep_need(type(value[name]) is str and 0 < len(value[name].encode()) <= 256
                 and '\0' not in value[name], 'actual selected session/profile required')
    _ep_pin(value['owner_request'], original=True, maximum=16000)
    _ep_pin(value['prior_boundary'], original=True)
    return value


def epoch_scope_binding_value(value, identity, identity_pin, accepted, accepted_pin):
    _ep_exact(value, {'schema', 'epoch_id', 'ordinal', 'identity', 'accepted',
        'scope', 'owner_request_sha256', 'boot_id'}, 'epoch scope binding fields differ')
    _ep_need(value['schema'] == 'hepta.native-guard.epoch-scope-binding.v1'
             and value['epoch_id'] == EPOCH_ID and type(value['ordinal']) is int
             and value['ordinal'] == identity['ordinal']
             and _ep_same(value['identity'], identity_pin)
             and _ep_same(value['accepted'], accepted_pin)
             and value['boot_id'] == identity['boot_id']
             and value['owner_request_sha256'] == identity['owner_request']['sha256'],
             'native scope is not bound to this durable identity and accepted original')
    _ep_scope(value['scope'])
    _ep_need(type(accepted) is dict and _ep_same(accepted.get('scope'), value['scope'])
             and value['scope']['session_id'] == identity['selected_session_id']
             and value['scope']['profile_id'] == identity['selected_profile_id'],
             'scope differs from actual accepted session/profile')
    return value


def epoch_resource_forecast(current, reservations, *, additional_profile_copies,
                            remaining_qualification_cases):
    """Pure arithmetic over explicit bounded profiles; no capacity qualification.

    Callers must derive current from the one complete inventory and authenticate
    every profile against source-level producers and exact capture/bundle copy
    plans. A supplied boolean, byte maximum per file, or serialized summary is
    not such evidence. No wall-time feasibility is inferred from byte counts.
    """
    limits = {'root_objects':64, 'inventory_entries':30000,
        'inventory_file_bytes':512*1024*1024, 'capture_files':8192,
        'capture_bytes':64*1024*1024, 'consumer_decoded_bytes':32*1024*1024}
    _ep_exact(current, limits, 'complete resource footprint counters required')
    _ep_need(type(remaining_qualification_cases) is list
             and remaining_qualification_cases in (['NEG-01','NEG-02'], ['NEG-01'], ['NEG-02'])
             and type(reservations) is list
             and len(remaining_qualification_cases) <= len(reservations) <= EPOCH_MAX_SLOTS,
             'the exact remaining actual qualification set and bounded profiles are required')
    _ep_need(type(additional_profile_copies) is dict
             and set(additional_profile_copies) == set(limits),
             'exact retained proof and repeated-copy overhead required')
    totals = {}
    for key, limit in limits.items():
        values = [current[key], additional_profile_copies[key]]
        for row in reservations:
            _ep_exact(row, set(limits) | {'producer_proof', 'copy_plan'},
                      'resource profile must identify its producer and copy evidence')
            _ep_pin(row['producer_proof']); _ep_pin(row['copy_plan'])
            values.append(row[key])
        _ep_need(all(type(n) is int and n >= 0 for n in values),
                 'resource counts must be exact nonnegative integers')
        totals[key] = sum(values)
        _ep_need(totals[key] <= limit, 'epoch shared resource reservation exceeds ' + key)
    return {'schema':'hepta.native-guard.epoch-resource-arithmetic.v1',
        'current':current, 'profiles':reservations, 'copy_overhead':additional_profile_copies,
        'remaining_qualification_cases':remaining_qualification_cases,
        'totals':totals, 'limits':limits, 'producer_bounds_verified_here':False,
        'time_budget_increased':False, 'admission_authorized':False}


def epoch_proc_root_binding_value(value, boot_id):
    _ep_exact(value, {'path','boot_id','init_identity','init_ppid','init_comm',
        'android_root_identity','gnu_root_identity','root_link_target'},
        'explicit actual proc-root bridge binding required')
    _ep_need(value['path'] == '/proc/1/root' and value['boot_id'] == boot_id
             and type(value['init_identity']) is list and len(value['init_identity']) == 4
             and all(type(n) is int and n >= 0 for n in value['init_identity'])
             and value['init_identity'][0] == 1 and value['init_identity'][3] == 0
             and type(value['init_ppid']) is int and value['init_ppid'] == 0
             and type(value['init_comm']) is str and 0 < len(value['init_comm'].encode()) <= 256,
             'actual native PID1 bridge identity differs')
    for name in ('android_root_identity','gnu_root_identity'):
        row=value[name]
        _ep_need(type(row) is list and len(row) == 5
                 and all(type(n) is int and n >= 0 for n in row)
                 and _ep_stat.S_ISDIR(row[2]), 'exact real root identity required')
    _ep_need(value['android_root_identity'][:2] != value['gnu_root_identity'][:2]
             and type(value['root_link_target']) is str
             and '\0' not in value['root_link_target']
             and len(value['root_link_target'].encode()) <= 4096,
             'GNU and Android root anchors must remain distinct')
    return value


def _ep_proc_small(fd, name, limit):
    child=_ep_os.open(name, _ep_os.O_RDONLY | _ep_os.O_NONBLOCK
        | _ep_os.O_NOFOLLOW | _ep_os.O_CLOEXEC, dir_fd=fd)
    try:
        before=_ep_metadata(_ep_os.fstat(child))
        _ep_need(_ep_stat.S_ISREG(before[2]), 'bounded native proc original required')
        pieces=[]; remaining=limit+1
        while remaining:
            part=_ep_os.read(child,min(4096,remaining))
            if not part:break
            pieces.append(part);remaining-=len(part)
        raw=b''.join(pieces)
        _ep_need(len(raw)<=limit and before == _ep_metadata(_ep_os.fstat(child))
                 == _ep_metadata(_ep_os.stat(name,dir_fd=fd,follow_symlinks=False)),
                 'native proc object changed or exceeds its read bound')
        return raw
    finally:_ep_os.close(child)


def _ep_boot_at(proc_fd):
    opened=[];fd=proc_fd
    try:
        for name in ('sys','kernel','random'):
            fd=_ep_os.open(name,_ep_os.O_RDONLY|_ep_os.O_DIRECTORY
                |_ep_os.O_NOFOLLOW|_ep_os.O_CLOEXEC,dir_fd=fd)
            opened.append(fd)
        return _ep_proc_small(fd,'boot_id',128).strip().decode('ascii','strict')
    finally:
        for fd in reversed(opened):_ep_os.close(fd)


def _ep_init_identity(raw):
    text=raw.decode('ascii','strict'); end=text.rfind(')')
    _ep_need(end>2 and text.startswith('1 ('), 'native PID1 stat original differs')
    fields=text[end+2:].split()
    _ep_need(len(fields)>=20, 'native PID1 stat fields incomplete')
    return {'identity':[1,int(fields[2]),int(fields[3]),int(fields[19])],
            'ppid':int(fields[1]),'comm':text[3:end]}


class _EpochParentChain(list):
    def __init__(self):
        super().__init__()
        self.proc_bridge = None


def _ep_proc_bridge_check(chain):
    bridge=chain.proc_bridge
    if bridge is None:return
    fixed=bridge['binding'];proc_fd=bridge['proc_fd'];init_fd=bridge['init_fd']
    current=_ep_init_identity(_ep_proc_small(init_fd,'stat',65536))
    _ep_need(_ep_boot_at(proc_fd) == fixed['boot_id']
             and current == {k:fixed['init_'+k] for k in ('identity','ppid','comm')},
             'native boot or PID1 generation changed across the proc-root bridge')
    link=_ep_metadata(_ep_os.stat('root',dir_fd=init_fd,follow_symlinks=False))
    _ep_need(link == bridge['link_metadata'] and _ep_stat.S_ISLNK(link[2])
             and _ep_os.readlink('root',dir_fd=init_fd) == fixed['root_link_target'],
             'the one authorized proc-root magic link changed')
    held=_ep_metadata(_ep_os.fstat(bridge['root_fd']))
    _ep_need(held == _ep_metadata(_ep_os.stat('root',dir_fd=init_fd,follow_symlinks=True))
             == _ep_metadata(_ep_os.stat('/proc/1/root',follow_symlinks=True))
             and held[:5] == fixed['android_root_identity']
             and _ep_metadata(_ep_os.fstat(chain[0][0]))[:5] == fixed['gnu_root_identity'],
             'held Android root and canonical kernel bridge target differ')


def _ep_parent_chain(path):
    """Hold every real ancestor so a parent rename cannot redirect ownership."""
    path = _ep_path(str(path))
    opened = _EpochParentChain()
    try:
        fd = _ep_os.open('/', _ep_os.O_RDONLY | _ep_os.O_DIRECTORY | _ep_os.O_CLOEXEC)
        opened.append((fd, None, None, _ep_metadata(_ep_os.fstat(fd))))
        parent_parts=path.parent.parts[1:]
        android=path.parts[:4] == ('/','proc','1','root')
        if android:
            _ep_need(epoch_actual_context(globals()) == 'phone'
                     and type(EPOCH_PROTOCOL_BINDING) is dict,
                     'proc-root access requires explicit phone context and actual binding')
            fixed=epoch_proc_root_binding_value(EPOCH_PROTOCOL_BINDING.get('proc_root'),
                                                EPOCH_PROTOCOL_BINDING.get('boot_id'))
        for index,name in enumerate(parent_parts):
            is_bridge = android and index == 2
            if is_bridge:
                _ep_need(name == 'root' and parent_parts[:2] == ('proc','1'),
                         'only the fixed native init root bridge may follow a link')
                init_fd=fd;proc_fd=opened[-2][0]
                link=_ep_metadata(_ep_os.stat(name,dir_fd=fd,follow_symlinks=False))
                _ep_need(_ep_stat.S_ISLNK(link[2])
                         and _ep_os.readlink(name,dir_fd=fd) == fixed['root_link_target'],
                         'native init root is not the fixed kernel magic link')
                child=_ep_os.open(name,_ep_os.O_RDONLY|_ep_os.O_DIRECTORY|_ep_os.O_CLOEXEC,dir_fd=fd)
                status=_ep_os.fstat(child)
                opened.append((child,fd,name,_ep_metadata(status)))
                opened.proc_bridge={'binding':fixed,'proc_fd':proc_fd,'init_fd':init_fd,
                    'root_fd':child,'link_metadata':link}
                _ep_proc_bridge_check(opened)
                fd=child
                continue
            child = _ep_os.open(name, _ep_os.O_RDONLY | _ep_os.O_DIRECTORY
                | _ep_os.O_NOFOLLOW | _ep_os.O_CLOEXEC, dir_fd=fd)
            status = _ep_os.fstat(child)
            _ep_need(_ep_stat.S_ISDIR(status.st_mode), 'epoch ancestor is not a directory')
            opened.append((child, fd, name, _ep_metadata(status)))
            fd = child
        return opened, path.name
    except BaseException:
        for row in reversed(opened):
            _ep_os.close(row[0])
        raise


def _ep_chain_check(chain, *, metadata_unchanged=False):
    _ep_proc_bridge_check(chain)
    for fd, parent_fd, name, before in chain:
        now = _ep_metadata(_ep_os.fstat(fd))
        # Directory times/size may legitimately change for our exclusive child
        # operation. Identity/owner/mode must never change. Read-only callers
        # request full9 equality separately.
        keys = range(9) if metadata_unchanged else (0, 1, 2, 3, 4)
        _ep_need(all(now[i] == before[i] for i in keys), 'owned epoch ancestor changed')
        if parent_fd is not None:
            bridge=chain.proc_bridge
            follow = bridge is not None and fd == bridge['root_fd']
            named = _ep_metadata(_ep_os.stat(name, dir_fd=parent_fd, follow_symlinks=follow))
            _ep_need(now == named, 'owned epoch ancestor was renamed or substituted')


def epoch_read_original(row, *, public_exact=None):
    _ep_pin(row, original=True)
    private = public_exact is None
    if not private:
        _ep_need(_ep_same(row, public_exact), 'public epoch leaf requires its exact fixed full9 pin')
    chain, name = _ep_parent_chain(row['path'])
    fd = None
    try:
        fd = _ep_os.open(name, _ep_os.O_RDONLY | _ep_os.O_NONBLOCK
            | _ep_os.O_NOFOLLOW | _ep_os.O_CLOEXEC, dir_fd=chain[-1][0])
        before = _ep_metadata(_ep_os.fstat(fd))
        _ep_need(before == row['metadata'] and _ep_stat.S_ISREG(before[2])
                 and before[5] == 1 and before[6] == row['bytes'],
                 'epoch original held identity differs before read')
        if private:
            _ep_need(before[3:6] == [0,0,1] and _ep_stat.S_IMODE(before[2]) == 0o600,
                     'epoch private file ownership/mode differs')
        chunks=[]; remaining=row['bytes'] + 1
        while remaining:
            chunk = _ep_os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk); remaining -= len(chunk)
        raw=b''.join(chunks)
        _ep_need(_ep_bare(raw) == {k:row[k] for k in ('bytes','sha256')}
                 and before == _ep_metadata(_ep_os.fstat(fd))
                 == _ep_metadata(_ep_os.stat(name, dir_fd=chain[-1][0], follow_symlinks=False))
                 == _ep_metadata(_EpPath(row['path']).lstat()),
                 'epoch original bytes or held/named/canonical identity changed')
        _ep_chain_check(chain)
        return raw
    finally:
        if fd is not None:
            _ep_os.close(fd)
        for item in reversed(chain):
            _ep_os.close(item[0])


def epoch_read_directory(path):
    chain, name = _ep_parent_chain(path)
    fd = None
    try:
        fd = _ep_os.open(name, _ep_os.O_RDONLY | _ep_os.O_DIRECTORY
            | _ep_os.O_NOFOLLOW | _ep_os.O_CLOEXEC, dir_fd=chain[-1][0])
        before = _ep_metadata(_ep_os.fstat(fd))
        _ep_need(_ep_stat.S_ISDIR(before[2]), 'epoch directory type differs')
        names = sorted(_ep_os.listdir(fd))
        _ep_need(len(names) <= 20000 and before == _ep_metadata(_ep_os.fstat(fd))
                 == _ep_metadata(_ep_os.stat(name, dir_fd=chain[-1][0], follow_symlinks=False))
                 == _ep_metadata(_EpPath(path).lstat()), 'epoch directory membership or full9 changed')
        _ep_chain_check(chain)
        return {'path':str(path), 'metadata':before, 'names':names}
    finally:
        if fd is not None:
            _ep_os.close(fd)
        for item in reversed(chain):
            _ep_os.close(item[0])


def epoch_recheck_manifest(manifest, *, binding):
    fixed = epoch_binding_value(binding)
    _ep_exact(manifest, {'schema','files','directories'}, 'epoch recheck manifest fields differ')
    _ep_need(manifest['schema'] == 'hepta.native-guard.epoch-capture-inputs.v1'
             and type(manifest['files']) is list and len(manifest['files']) <= EPOCH_MAX_INPUT_FILES
             and type(manifest['directories']) is list and len(manifest['directories']) <= 30000,
             'epoch recheck inputs exceed fixed bounds')
    public={r['path']:r for r in fixed['control_leaves']}
    count=0
    for row in manifest['files']:
        _ep_pin(row, original=True)
        count += row['bytes']
        _ep_need(count <= EPOCH_MAX_INPUT_BYTES, 'epoch recheck input bytes exceed shared bound')
        epoch_read_original(row, public_exact=public.get(row['path']))
    for row in manifest['directories']:
        _ep_need(_ep_same(epoch_read_directory(row['path']), row),
                 'epoch captured directory original changed at final bookend')
    return _ep_strict(_ep_encoded(manifest))


class EpochOwnedDirectory:
    """A bounded exclusive-write primitive, not an admission or allocator CLI.

    Ownership starts with an exact already observed parent. No replacement,
    overwrite, deletion, retry, mkdir-parents, or nonce generation exists here.
    On any failure the original created object remains evidence. A returned
    object means only this process owns this exact inode, never a case PASS.
    """
    def __init__(self, path, *, expected_parent, expected_names):
        self.path = str(_ep_path(path))
        self.chain, self.name = _ep_parent_chain(self.path)
        self.fd = None
        self.closed = False
        self.created = False
        self.failed = False
        try:
            _ep_exact(expected_parent, {'path','metadata','names'}, 'exact reservation parent observation required')
            _ep_need(expected_parent['path'] == str(_EpPath(self.path).parent)
                     and expected_parent['metadata'] == _ep_metadata(_ep_os.fstat(self.chain[-1][0]))
                     and expected_parent['metadata'][3:5] == [0,0]
                     and _ep_stat.S_IMODE(expected_parent['metadata'][2]) == 0o700
                     and expected_parent['names'] == sorted(_ep_os.listdir(self.chain[-1][0]))
                     and type(expected_names) is list and expected_names == sorted(set(expected_names))
                     and self.name not in expected_parent['names'],
                     'reservation parent or create-only namespace changed')
            self.allowed_names = tuple(expected_names)
            _ep_chain_check(self.chain)
            _ep_os.mkdir(self.name, 0o700, dir_fd=self.chain[-1][0])
            self.created = True
            _ep_os.fsync(self.chain[-1][0])
            self.fd = _ep_os.open(self.name, _ep_os.O_RDONLY | _ep_os.O_DIRECTORY
                | _ep_os.O_NOFOLLOW | _ep_os.O_CLOEXEC, dir_fd=self.chain[-1][0])
            identity = _ep_metadata(_ep_os.fstat(self.fd))
            _ep_need(identity[3:5] == [0,0] and _ep_stat.S_IMODE(identity[2]) == 0o700
                     and not _ep_os.listdir(self.fd), 'new reservation directory ownership or emptiness differs')
            self.identity = identity
            self.created_members = {}
            self._check()
        except BaseException:
            self.close()
            raise

    def _check(self, *, owned_partial_name=None):
        _ep_need(not self.closed and not self.failed and self.fd is not None,
                 'owned epoch directory is closed or has an unreconciled write failure')
        _ep_chain_check(self.chain)
        current = _ep_metadata(_ep_os.fstat(self.fd))
        named = _ep_metadata(_ep_os.stat(self.name, dir_fd=self.chain[-1][0], follow_symlinks=False))
        _ep_need(current == named and current[:5] == self.identity[:5]
                 and current == _ep_metadata(_EpPath(self.path).lstat()),
                 'owned epoch directory was renamed or replaced')
        _ep_need(sorted(_ep_os.listdir(self.fd)) == sorted(self.created_members),
                 'unowned file appeared in the claimed epoch directory')
        for name,record in self.created_members.items():
            if record['complete']:
                epoch_read_original(record['descriptor'])
            else:
                _ep_need(name == owned_partial_name,
                         'a partial prior epoch record cannot authorize a subsequent phase')
        return current

    def create_bytes(self, name, raw):
        _ep_need(type(name) is str and name in self.allowed_names
                 and name not in self.created_members and '/' not in name
                 and name not in ('','.','..') and '\0' not in name
                 and type(raw) is bytes and len(raw) <= EPOCH_MAX_INPUT_FILE,
                 'unreviewed name, repeated write or oversized epoch record')
        self._check()
        fd = None
        completed = False
        try:
            fd = _ep_os.open(name, _ep_os.O_WRONLY | _ep_os.O_CREAT | _ep_os.O_EXCL
                | _ep_os.O_NOFOLLOW | _ep_os.O_CLOEXEC, 0o600, dir_fd=self.fd)
            # Register immediately. Even an interrupted partial write remains
            # owned evidence, never an absent record that may be retried.
            initial = _ep_metadata(_ep_os.fstat(fd))
            self.created_members[name] = {'initial_metadata':initial, 'complete':False}
            _ep_need(_ep_stat.S_ISREG(initial[2]) and initial[3:6] == [0,0,1]
                     and _ep_stat.S_IMODE(initial[2]) == 0o600,
                     'new epoch record owner/type/mode differs')
            offset=0
            while offset < len(raw):
                wrote=_ep_os.write(fd, raw[offset:offset+65536])
                _ep_need(wrote > 0, 'short epoch write')
                offset += wrote
            _ep_os.fsync(fd)
            observed=_ep_metadata(_ep_os.fstat(fd))
            _ep_need(observed == _ep_metadata(_ep_os.stat(name, dir_fd=self.fd, follow_symlinks=False))
                     and observed[:6] == initial[:6] and observed[6] == len(raw),
                     'owned epoch record was renamed or substituted')
            _ep_os.fsync(self.fd)
            self._check(owned_partial_name=name)
            pin={'path':self.path+'/'+name, **_ep_bare(raw), 'metadata':observed}
            _ep_need(epoch_read_original(pin) == raw, 'created epoch record readback differs')
            self.created_members[name]={'complete':True, 'descriptor':pin}
            self._check()
            completed = True
            return pin
        finally:
            if not completed:
                self.failed = True
            if fd is not None:
                _ep_os.close(fd)

    def close(self):
        if getattr(self, 'closed', True):
            return
        self.closed=True
        if self.fd is not None:
            _ep_os.close(self.fd); self.fd=None
        for item in reversed(self.chain):
            _ep_os.close(item[0])
        self.chain=[]

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        self.close()


class _EpochOrdinalClaim:
    """Internal O_EXCL claim primitive; complete admission precedes its caller.

    The held CLAIM file, rather than mkdir's pathname result, owns the ordinal.
    The directory is explicitly first observed after mkdir/open and associated
    with that claim. We do not claim an atomic observation of mkdir's inode.
    An interrupted or partial claim consumes the name and is never retried here.
    """
    def __init__(self, slots_path, ordinal, reservation_raw, *, expected_parent,
                 allowed_slot_names):
        self.closed=False; self.failed=False; self.claim_fd=None; self.directory=None
        self.chain=None; self.pin=None; self.raw=reservation_raw
        _ep_need(type(ordinal) is int and 1<=ordinal<=EPOCH_MAX_SLOTS,
                 'bounded explicit ordinal required; no next-slot search is allowed')
        value=_ep_strict(reservation_raw)
        _ep_need(type(value) is dict
                 and value.get('schema')=='hepta.native-guard.epoch-reservation.v2'
                 and type(value.get('ordinal')) is int and value['ordinal']==ordinal
                 and value.get('nonce_generated') is False
                 and value.get('native_scope_assigned') is False
                 and _ep_encoded(value)==reservation_raw,
                 'claim must retain canonical pre-identity reservation bytes')
        self.slots_path=str(_ep_path(slots_path))
        self.ordinal=ordinal; self.claim_name='%02d.CLAIM.json'%ordinal
        self.directory_name='%02d'%ordinal
        self.claim_path=self.slots_path+'/'+self.claim_name
        try:
            self.chain,_leaf=_ep_parent_chain(self.claim_path)
            _ep_exact(expected_parent,{'path','metadata','names'},'exact slot parent original required')
            _ep_need(expected_parent['path']==self.slots_path
                     and expected_parent['metadata']==_ep_metadata(_ep_os.fstat(self.chain[-1][0]))
                     and expected_parent['metadata'][3:5]==[0,0]
                     and _ep_stat.S_IMODE(expected_parent['metadata'][2])==0o700
                     and expected_parent['names']==sorted(_ep_os.listdir(self.chain[-1][0]))
                     and self.claim_name not in expected_parent['names']
                     and self.directory_name not in expected_parent['names'],
                     'slot parent changed or this ordinal already has an object')
            _ep_chain_check(self.chain)
            self.claim_fd=_ep_os.open(self.claim_name,_ep_os.O_RDWR|_ep_os.O_CREAT|_ep_os.O_EXCL
                |_ep_os.O_NOFOLLOW|_ep_os.O_CLOEXEC,0o600,dir_fd=self.chain[-1][0])
            initial=_ep_metadata(_ep_os.fstat(self.claim_fd))
            _ep_need(_ep_stat.S_ISREG(initial[2]) and initial[3:6]==[0,0,1]
                     and _ep_stat.S_IMODE(initial[2])==0o600,'claim owner/type/mode differs')
            offset=0
            while offset<len(reservation_raw):
                wrote=_ep_os.write(self.claim_fd,reservation_raw[offset:offset+65536])
                _ep_need(wrote>0,'short ordinal claim write');offset+=wrote
            _ep_os.fsync(self.claim_fd);_ep_os.fsync(self.chain[-1][0])
            after=_ep_metadata(_ep_os.fstat(self.claim_fd))
            _ep_need(after[:6]==initial[:6] and after[6]==len(reservation_raw),
                     'held ordinal claim identity changed')
            self.pin={'path':self.claim_path,**_ep_bare(reservation_raw),'metadata':after}
            self._check_claim()
            observed=epoch_read_directory(self.slots_path)
            _ep_need(observed['names']==sorted(expected_parent['names']+[self.claim_name]),
                     'another control object appeared during ordinal allocation')
            _ep_need(type(allowed_slot_names) is list and 'DIRECTORY-BINDING.json' in allowed_slot_names,
                     'claim-to-directory original binding must be retained')
            self.directory=EpochOwnedDirectory(self.slots_path+'/'+self.directory_name,
                expected_parent=observed,expected_names=allowed_slot_names)
            linked={'schema':'hepta.native-guard.epoch-claimed-directory.v1',
                'ordinal':ordinal,'claim':self.pin,
                'directory':{'path':self.directory.path,'first_observed_metadata':self.directory.identity},
                'directory_inode_observed_atomically_at_mkdir':False,
                'ordinal_owned_by_held_exclusive_claim':True,
                'nonce_generated':False,'native_scope_assigned':False}
            self._check_claim()
            self.directory_binding=self.directory.create_bytes('DIRECTORY-BINDING.json',_ep_encoded(linked))
            self._check_claim()
        except BaseException:
            self.failed=True;self.close();raise

    def _check_claim(self):
        _ep_need(not self.closed and not self.failed and self.claim_fd is not None and self.pin is not None,
                 'ordinal claim is incomplete, failed, or closed')
        _ep_chain_check(self.chain)
        _ep_need(_ep_metadata(_ep_os.fstat(self.claim_fd))==self.pin['metadata']
                 ==_ep_metadata(_ep_os.stat(self.claim_name,dir_fd=self.chain[-1][0],follow_symlinks=False)),
                 'held ordinal claim was replaced or renamed')
        _ep_need(epoch_read_original(self.pin)==self.raw,'ordinal claim original changed')

    def create_record(self,name,raw):
        self._check_claim()
        try:
            result=self.directory.create_bytes(name,raw)
            self._check_claim()
            return result
        except BaseException:
            self.failed=True;raise

    def close(self):
        if self.closed:return
        self.closed=True
        if self.directory is not None:self.directory.close()
        if self.claim_fd is not None:_ep_os.close(self.claim_fd);self.claim_fd=None
        if self.chain is not None:
            for item in reversed(self.chain):_ep_os.close(item[0])
            self.chain=None

    def __enter__(self):return self

    def __exit__(self,kind,value,traceback):self.close()


# Explicit current epoch protocol replay. Appended to component_common.py
# after epoch_protocol.fragment.py. This module performs no import-time I/O.

EPOCH_ANCHOR_FIELDS = ('schema','epoch_id','boot_id','legacy','host_origins',
    'legacy_source_contexts','historical_originals_rewritten','native_boundary_created',
    'component_qualified','business_qualified')
EPOCH_INITIALIZATION_FIELDS = ('schema','epoch_id','boot_id','anchor','generation',
    'carriers','baseline_business_inventory','baseline_control_inventory',
    'baseline_inventory_spec','baseline_inventory_observation','root_authorization',
    'registry_lock','code_receipt','installed_artifacts','history_carriers',
    'retained_failed_native_branches','new_native_boundary','component_qualified','business_qualified')
EPOCH_SLOT_FILES = ('DIRECTORY-BINDING.json','IDENTITY.json','ALLOCATION-ADMISSION.json',
    'ROLE-LAUNCH-INTENT.json','ADMISSION.json',
    'STAGE.json','SCOPE-BINDING.json','LAUNCH.json','CLOSURE.json',
    'AFTER-INVENTORY.json','BOUNDARY.json','COMMIT.json')
EPOCH_TRANSPORT_FILES = ('inputs.tar.gz','stage.py','setup.witness.tar.gz',
    'before-guard.witness.tar.gz','after-guard.witness.tar.gz','CLOSURE.json','INVENTORY.json',
    'closure-authority.tar.gz')
EPOCH_HOST_ORIGIN_ROLES = ('legacy_failed_prelaunch_verifier','legacy_failed_prelaunch_admission',
    'root02_prelaunch_verifier','root02_prelaunch_admission','original_host_audit_source',
    'original_host_audit_result','original_host_audit_caller','original_host_audit_caller_result',
    'current_head_source','current_head_caller','current_head_phone_output','current_head_observations')


def _ep_origin(value):
    _ep_need(type(value) is dict and set(value) in (
        {'path','bytes','sha256'}, {'path','bytes','sha256','metadata'}),
        'complete historical origin descriptor required')
    return _ep_pin(value, original='metadata' in value)


def _ep_manifest_raw(pin, index, originals):
    _ep_pin(pin, original=True)
    _ep_need(pin['path'] in index['files'] and _ep_same(index['files'][pin['path']], pin),
             'protocol original is not present with its exact original metadata')
    raw=originals[pin['path']]
    _ep_need(_ep_bare(raw)=={k:pin[k] for k in ('bytes','sha256')},
             'protocol original body differs')
    return raw


def _ep_json_original(pin, index, originals):
    raw=_ep_manifest_raw(pin,index,originals)
    value=_ep_strict(raw)
    _ep_need(_ep_encoded(value)==raw,'canonical newly written epoch JSON required')
    return value


def _ep_under(path, root):
    p=_ep_path(path).parts;r=_ep_path(root).parts
    return p[:len(r)]==r


def epoch_anchor_value(raw, descriptor, *, binding):
    _ep_pin(descriptor,original=True)
    _ep_need({k:descriptor[k] for k in ('path','bytes','sha256')}==binding['anchor']
             and _ep_bare(raw)=={k:descriptor[k] for k in ('bytes','sha256')},
             'only the source-bound immutable historical anchor is accepted')
    value=_ep_strict(raw);_ep_exact(value,EPOCH_ANCHOR_FIELDS,'epoch anchor fields differ')
    _ep_need(_ep_encoded(value)==raw and value['schema']=='hepta.native-guard.epoch-anchor.v1'
             and value['epoch_id']==EPOCH_ID and value['boot_id']==binding['boot_id']
             and value['historical_originals_rewritten'] is False
             and value['native_boundary_created'] is False
             and value['component_qualified'] is False and value['business_qualified'] is False,
             'historical anchor cannot invent a current boundary or qualification')
    legacy=value['legacy']
    _ep_exact(legacy,{'schema','boot_id','native_chain','retirement','non_native_sidebranch',
        'native_components','fixture_roots'},'complete fixed legacy domain required')
    _ep_need(legacy['schema']=='hepta.native-guard.epoch-legacy-domain.v1'
             and legacy['boot_id']==binding['boot_id']
             and type(legacy['native_components']) is int and legacy['native_components']==6
             and type(legacy['fixture_roots']) is int and legacy['fixture_roots']==7
             and type(legacy['native_chain']) is list and len(legacy['native_chain'])==6,
             'historical domains must retain actual six native / seven fixture identities')
    required=[]
    for row in legacy['native_chain']:
        _ep_exact(row,{'boundary','inventory','closure'},'complete legacy original triple required')
        for name in ('boundary','inventory','closure'):
            _ep_pin(row[name],original=True);required.append(row[name])
    _ep_exact(legacy['retirement'],{'proof','preflight','probe','bound_inputs','disabled_flag'},
              'all original retirement inputs required')
    _ep_exact(legacy['non_native_sidebranch'],{'proof','closure','inventory'},
              'separate exact attempt05 originals required')
    for group in (legacy['retirement'],legacy['non_native_sidebranch']):
        for row in group.values():_ep_pin(row,original=True);required.append(row)
    _ep_need(len(required)==26 and len({r['path'] for r in required})==26
             and _ep_same(sorted(required,key=lambda r:r['path']),
                          sorted(binding['fixed_inputs'],key=lambda r:r['path'])),
             'anchor omits, substitutes, or adds a fixed historical phone original')
    origins=value['host_origins']
    _ep_need(type(origins) is list and [r.get('role') for r in origins]==list(EPOCH_HOST_ORIGIN_ROLES),
             'all reviewed host-proof origins must be declared once in fixed role order')
    for row in origins:
        _ep_exact(row,{'role','original'},'origin identity must remain distinct from a carrier')
        _ep_origin(row['original'])
    _ep_need(_ep_same(value['legacy_source_contexts'],binding['source_contexts']),
             'historical source locations cannot be inferred or substituted')
    return value


def epoch_carriers_value(rows, *, anchor, binding, index, originals):
    expected=list(anchor['host_origins'])+[{'role':'fixed_footprint','original':binding['footprint_origin']}]
    _ep_need(type(rows) is list and len(rows)==len(expected),
             'every historical origin needs one separately observed actual phone carrier')
    out={}
    for row,origin in zip(rows,expected):
        _ep_exact(row,{'role','origin','carrier'},'exact origin/carrier crosslink required')
        role=origin['role']
        _ep_need(row['role']==role and _ep_same(row['origin'],origin['original']),
                 'carrier changed an original host identity or its role')
        carrier=row['carrier'];_ep_pin(carrier,original=True)
        _ep_need(carrier['path']==EPOCH_REGISTRY_ROOT+'/initialization/carriers/'+role+'.original'
                 and {k:carrier[k] for k in ('bytes','sha256')}==
                     {k:origin['original'][k] for k in ('bytes','sha256')},
                 'new carrier must retain every exact byte without borrowing origin metadata')
        _ep_manifest_raw(carrier,index,originals)
        out[role]={'origin':origin['original'],'carrier':carrier}
    return out


def epoch_footprint_binding_value(raw, *, binding):
    _ep_need(_ep_bare(raw)=={k:binding['footprint_origin'][k] for k in ('bytes','sha256')},
             'source-bound actual footprint proof differs')
    value=_ep_strict(raw)
    _ep_exact(value,{'schema','boot_id','observation_origin','verification_origin',
        'retained_roots','retained_inventory_entries','control_leaves','absence_roots',
        'retained_failed_fixture_absences','alias_pairs','proc_root','namespace_parents',
        'canonical_ancestors','positive_absence_observations','source_original_entries',
        'unknown_namespace_members','namespace_coverage_complete','current_admission'},
        'complete explicit actual footprint binding required')
    _ep_need(value['schema']=='hepta.native-guard.epoch-fixed-footprint.v2'
             and value['boot_id']==binding['boot_id'] and _ep_encoded(value)==raw
             and value['current_admission'] is False,
             'actual fixed footprint schema, boot or canonical bytes differ')
    for name in ('observation_origin','verification_origin'):_ep_origin(value[name])
    _ep_need(type(value['retained_roots']) is list
             and [r.get('path') for r in value['retained_roots']]==binding['retained_roots'],
             'fixed retained roots differ')
    present=[]
    for row in value['retained_roots']:
        _ep_exact(row,{'path','presence'},'retained root presence must be explicit')
        _ep_need(row['presence'] in ('present','absent'),'retained root presence differs')
        if row['presence']=='absent':
            _ep_need(row['path'] in binding['absence_roots'],'unreviewed absent retained root')
        else:present.append(row['path'])
    entries=value['retained_inventory_entries']
    _ep_need(type(entries) is dict and all(sum(_ep_under(p,r) for r in present)==1 for p in entries)
             and all(p in entries for p in present), 'complete retained business rows required')
    # The original inventory validator and independent epoch observer validate
    # every row/topology/budget. This binding is a fixed actual proof identity,
    # not an alternative relaxed inventory parser.
    for name in ('control_leaves','absence_roots','retained_failed_fixture_absences','alias_pairs','proc_root'):
        _ep_need(_ep_same(value[name],binding[name]),'actual footprint source binding changed: '+name)
    parents=value['namespace_parents']
    _ep_need(type(parents) is list and 0<len(parents)<=64
             and len({p['path'] for p in parents})==len(parents),
             'complete source-bound namespace parent observations required')
    for parent in parents:
        _ep_path(parent['path']);_ep_full9(parent['metadata'],kind='directory')
        names=parent['names']
        _ep_need(type(names) is list and names==sorted(set(names)) and len(names)<=20000,
                 'fixed namespace parent has an unbounded or incomplete names view')
    witnesses=value['positive_absence_observations']
    _ep_need(type(witnesses) is list and len({r['path'] for r in witnesses})==len(witnesses),
             'fixed absence witness set repeats or is incomplete')
    for witness in witnesses:
        _ep_path(witness['path'])
        _ep_need(witness['state']=='POSITIVELY_OBSERVED_ENOENT'
                 and witness['absence_is_new_permission'] is False,
                 'historical absence cannot grant a future namespace permission')
        for phase in ('first','final'):
            ref=witness[phase]['canonical_parent_observation']
            _ep_exact(ref,{'table','index','serialized_observation'},'exact source parent reference required')
            _ep_need(ref['table']=='immediate_parent_observations'
                     and type(ref['index']) is int and 0<=ref['index']<len(parents),
                     'fixed absence parent table reference is invalid')
            parent=parents[ref['index']]
            _ep_need(_ep_bare(_ep_encoded(parent))==ref['serialized_observation']
                     and str(_EpPath(witness['path']).parent)==parent['path']
                     and _EpPath(witness['path']).name not in parent['names'],
                     'fixed absence witness does not retain its actual complete parent view')
    _ep_need(type(value['unknown_namespace_members']) is list
             and type(value['namespace_coverage_complete']) is bool
             and value['namespace_coverage_complete']==(len(value['unknown_namespace_members'])==0),
             'unknown namespace coverage cannot be silently promoted')
    return value


def epoch_initialization_value(value, *, original, anchor, binding, index, originals,
                               inventory_validator, observation_verifier):
    _ep_exact(value,EPOCH_INITIALIZATION_FIELDS,'complete actual initialization required')
    _ep_need(value['schema']=='hepta.native-guard.epoch-registry-initialization.v2'
             and value['epoch_id']==EPOCH_ID and value['boot_id']==binding['boot_id']
             and original['path']==EPOCH_REGISTRY_ROOT+'/INITIALIZATION.json'
             and value['new_native_boundary'] is False
             and value['component_qualified'] is False and value['business_qualified'] is False,
             'bootstrap initialization is not a native component or qualification')
    _ep_need(value['anchor']==index['files'][binding['anchor']['path']],
             'initialization does not name the actual anchor carrier identity')
    carriers=epoch_carriers_value(value['carriers'],anchor=anchor,binding=binding,index=index,originals=originals)
    footprint=epoch_footprint_binding_value(
        originals[carriers['fixed_footprint']['carrier']['path']],binding=binding)
    _ep_need(footprint['namespace_coverage_complete'] is True
             and footprint['unknown_namespace_members']==[],
             'unclosed additional native namespace members forbid epoch initialization and admission')
    _ep_pin(value['generation'],original=True);_ep_pin(value['root_authorization'],original=True)
    _ep_manifest_raw(value['generation'],index,originals)
    _ep_manifest_raw(value['root_authorization'],index,originals)
    _ep_pin(value['registry_lock'],original=True)
    _ep_need(value['registry_lock']['path']==EPOCH_REGISTRY_ROOT+'/REGISTRY.lock'
             and _ep_manifest_raw(value['registry_lock'],index,originals)==b'',
             'the one immutable empty registry-lock original is required')
    names={'baseline_business_inventory':'BASELINE-BUSINESS.json',
           'baseline_control_inventory':'BASELINE-CONTROL.json',
           'baseline_inventory_spec':'INVENTORY-SPEC.json',
           'baseline_inventory_observation':'INVENTORY-OBSERVATION.json'}
    parsed={}
    for key,name in names.items():
        _ep_pin(value[key],original=True)
        _ep_need(value[key]['path']==EPOCH_REGISTRY_ROOT+'/initialization/'+name,
                 'bootstrap observation uses an unreviewed path')
        parsed[key]=_ep_json_original(value[key],index,originals)
    baseline=parsed['baseline_business_inventory'];inventory_validator(baseline)
    headpin=anchor['legacy']['native_chain'][0]['inventory']
    historical=_ep_strict(_ep_manifest_raw(headpin,index,originals));inventory_validator(historical)
    retained=[r['path'] for r in footprint['retained_roots'] if r['presence']=='present']
    _ep_need(not set(historical['entries'])&set(footprint['retained_inventory_entries']),
             'retained failed trees overlap the immutable legacy business inventory')
    expected_entries=dict(historical['entries']);expected_entries.update(footprint['retained_inventory_entries'])
    _ep_need(baseline['roots']==historical['roots']+retained
             and _ep_same(baseline['entries'],expected_entries),
             'bootstrap must preserve every actual902 and fresh fixed failed-tree row')
    spec=parsed['baseline_inventory_spec']
    _ep_need(spec.get('active_reservations')==[]
             and _ep_same(spec.get('legacy_anchor'),anchor['legacy']['native_chain'][0]['boundary'])
             and _ep_same(spec.get('retained_roots'),footprint['retained_roots'])
             and _ep_same(spec.get('retained_failed_fixture_absences'),binding['retained_failed_fixture_absences']),
             'bootstrap inventory cannot allocate a slot or omit a separate retained domain')
    proof=observation_verifier(spec,baseline,parsed['baseline_control_inventory'],
                                parsed['baseline_inventory_observation'])
    _epoch_stage_api().epoch_initialization_extra_value(value,index,originals)
    return {'value':value,'original':original,'carriers':carriers,'footprint':footprint,
        'preservation_inventory':baseline,'preservation_inventory_original':value['baseline_business_inventory'],
        'baseline_inventory_verification':proof}


def epoch_lease_protocol_value(lease):
    _ep_need(type(lease) is dict and lease.get('schema')=='hepta.native-guard.epoch-lease.v1',
             'an explicit new epoch lease is required; legacy leases do not implicitly roll over')
    value=lease.get('epoch')
    _ep_exact(value,{'schema','epoch_id','anchor','initialization','ordinal',
        'reservation','identity','generation'},'lease must bind all actual immutable epoch identities')
    _ep_need(value['schema']=='hepta.native-guard.epoch-lease-binding.v1'
             and value['epoch_id']==EPOCH_ID and type(value['ordinal']) is int
             and 1<=value['ordinal']<=EPOCH_MAX_SLOTS,'epoch lease ordinal differs')
    for name in ('anchor','initialization','reservation','identity','generation'):
        _ep_pin(value[name],original=True)
    return value


def _ep_slot_original(index, originals, ordinal, name):
    path=EPOCH_REGISTRY_ROOT+'/slots/%02d/'%ordinal+name
    pin=index['files'].get(path)
    if pin is None:return None,None
    return _ep_json_original(pin,index,originals),pin


def epoch_directory_claim_value(value, *, ordinal, claim, directory):
    _ep_exact(value,{'schema','ordinal','claim','directory','directory_inode_observed_atomically_at_mkdir',
        'ordinal_owned_by_held_exclusive_claim','nonce_generated','native_scope_assigned'},
        'exclusive claim-to-directory original fields differ')
    _ep_need(value['schema']=='hepta.native-guard.epoch-claimed-directory.v1'
             and type(value['ordinal']) is int and value['ordinal']==ordinal
             and _ep_same(value['claim'],claim)
             and value['directory_inode_observed_atomically_at_mkdir'] is False
             and value['ordinal_owned_by_held_exclusive_claim'] is True
             and value['nonce_generated'] is False and value['native_scope_assigned'] is False,
             'a directory observation cannot masquerade as the original exclusive ordinal claim')
    linked=value['directory'];_ep_exact(linked,{'path','first_observed_metadata'},'claimed directory identity required')
    _ep_full9(linked['first_observed_metadata'],kind='directory')
    _ep_need(linked['path']==directory['path']
             and linked['first_observed_metadata'][:5]==directory['metadata'][:5],
             'claimed directory inode was renamed or substituted')
    return value


def epoch_stage_binding_value(value, *, identity, identity_pin, generation_value, index, originals):
    _ep_exact(value,{'schema','epoch_id','ordinal','identity','lease','stage_original',
        'package_manifest','phase_source','inventory_roots'},'actual stage phase binding fields differ')
    _ep_need(value['schema']=='hepta.native-guard.epoch-stage-binding.v1'
             and value['epoch_id']==EPOCH_ID and type(value['ordinal']) is int
             and value['ordinal']==identity['ordinal'] and _ep_same(value['identity'],identity_pin),
             'stage record is not bound to this actual claimed identity')
    for key in ('lease','stage_original','package_manifest','phase_source'):_ep_pin(value[key],original=True)
    lease=_ep_strict(_ep_manifest_raw(value['lease'],index,originals))
    epoch_lease_protocol_value(lease)
    _ep_need(lease['nonce']==identity['nonce'] and lease['label']==identity['label']
             and lease['case_id']==identity['case_id']
             and lease['package_sha256']==generation_value['runtime']['sha256']
             and lease['combination']=={k:generation_value['combination'][k] for k in ('bytes','sha256')}
             and lease['owner_request_sha256']==identity['owner_request']['sha256']
             and _ep_same(lease['epoch']['identity'],identity_pin),
             'actual staged lease changed its reserved identity')
    home='/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/'+identity['label']
    journal='/proc/1/root/'+lease['android_journal'].lstrip('/')
    android_home='/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/'+identity['label']
    fixture='/proc/1/root/data/local/tmp/hepta-native-guard-'+identity['nonce']
    _ep_need(value['lease']['path']==home+'/LEASE.json'
             and value['stage_original']['path']==home+'/STAGE-COMPLETE.json'
             and value['package_manifest']['path']==home+'/package/MANIFEST.json'
             and value['phase_source']['path']==home+'/package/source/stage_component.py'
             and journal==android_home+'/executor'
             and value['inventory_roots']==[android_home,home,fixture],
             'stage must retain its complete exact three-root domain')
    stage=_ep_strict(_ep_manifest_raw(value['stage_original'],index,originals))
    _ep_manifest_raw(value['phase_source'],index,originals)
    package_raw=_ep_manifest_raw(value['package_manifest'],index,originals)
    _ep_need(_ep_bare(package_raw)=={k:generation_value['runtime'][k] for k in ('bytes','sha256')},
             'stage package is not the exact source generation in the immutable catalog')
    package=_ep_strict(package_raw)
    _ep_need(package.get('schema')=='hepta.native-guard.adapter-package.v1'
             and type(package.get('files')) is list and len(package['files'])==32,
             'the stage catalog must bind the exact32 reviewed runtime')
    source_rows=[r for r in package['files'] if r.get('path')=='source/stage_component.py']
    _ep_need(len(source_rows)==1 and {k:source_rows[0][k] for k in ('bytes','sha256')}
             =={k:value['phase_source'][k] for k in ('bytes','sha256')},
             'stage completion reader source is not the exact runtime member')
    _ep_need(stage.get('schema')=='hepta.native-guard.private-stage.v1'
             and stage.get('state')=='PRIVATE_COMPONENT_INPUTS_STAGED_NO_ROLES'
             and stage.get('lease_sha256')==value['lease']['sha256']
             and stage.get('package_sha256')==lease['package_sha256']
             and stage.get('component_qualified') is False and stage.get('automatic_retry') is False
             and all(type(stage.get(k)) is int and stage[k]==0 for k in (
                 'existing_files_overwritten','service_launches','model_requests','native_tasks',
                 'existing_helper_or_policy_changes')),
             'stage original does not prove the exact create-only no-role completion')
    return {'binding':value,'lease':lease,'stage':stage,'inventory_roots':value['inventory_roots']}


def epoch_terminal_value(value, *, original, identity, identity_pin, scope_binding,
                         scope_pin, generation, predecessor_terminal, index, originals):
    # This current implementation supports native close only. An interrupted
    # prelaunch reservation cannot receive a generic synthetic terminal. A
    # future explicit reviewed source may add one fixed failure reconciler.
    _ep_exact(value,{'schema','epoch_id','ordinal','identity','scope_binding','generation',
        'predecessor_terminal','state','boundary','closure','inventory','source_verifier',
        'component_qualified','business_qualified'},'complete native terminal commit required')
    _ep_need(value['schema']=='hepta.native-guard.epoch-terminal-commit.v1'
             and value['epoch_id']==EPOCH_ID and type(value['ordinal']) is int
             and value['ordinal']==identity['ordinal']
             and original['path']==EPOCH_REGISTRY_ROOT+'/slots/%02d/COMMIT.json'%identity['ordinal']
             and _ep_same(value['identity'],identity_pin) and scope_binding is not None
             and _ep_same(value['scope_binding'],scope_pin)
             and _ep_same(value['generation'],generation)
             and _ep_same(value['predecessor_terminal'],predecessor_terminal)
             and value['state'] in ('NATIVE_COMPONENT_FAILED_CLOSED','NATIVE_COMPONENT_QUALIFIED_CLOSED')
             and type(value['component_qualified']) is bool
             and value['component_qualified']==(value['state']=='NATIVE_COMPONENT_QUALIFIED_CLOSED')
             and value['business_qualified'] is False,
             'terminal changed identity, actual scope, source generation or failure semantics')
    root=EPOCH_REGISTRY_ROOT+'/slots/%02d/'%identity['ordinal']
    for key,name in (('boundary','BOUNDARY.json'),('closure','CLOSURE.json'),('inventory','AFTER-INVENTORY.json')):
        _ep_pin(value[key],original=True)
        _ep_need(value[key]['path']==root+name,'terminal original path differs')
        _ep_manifest_raw(value[key],index,originals)
    _ep_pin(value['source_verifier'])
    # Full active closure semantics and phase originals are a mandatory late
    # gate. Merely passing this exact protocol graph never grants qualification.
    return value


class _EpochHeldRegistryLock:
    """Serialize only this reviewed epoch's writers; never claim old writers obey.

    The actual pre-existing empty inode is pinned before and after nonblocking
    flock. Its bytes are never written. Releasing the lock does not remove a
    partial claim or authorize another ordinal. Unknown originals remain hard
    blockers in the separate complete registry replay.
    """
    def __init__(self, original):
        import fcntl
        self._fcntl=fcntl;self.fd=None;self.chain=None;self.closed=False;self.locked=False
        self.pin=_ep_strict(_ep_encoded(_ep_pin(original,original=True)))
        self.pid=_ep_os.getpid()
        _ep_need(self.pin['bytes']==0 and self.pin['sha256']==_ep_sha(b'')
                 and self.pin['metadata'][3:6]==[0,0,1]
                 and _ep_stat.S_IMODE(self.pin['metadata'][2])==0o600,
                 'registry-lock must be the exact private empty original')
        try:
            self.chain,self.name=_ep_parent_chain(self.pin['path'])
            self.fd=_ep_os.open(self.name,_ep_os.O_RDONLY|_ep_os.O_NONBLOCK
                |_ep_os.O_NOFOLLOW|_ep_os.O_CLOEXEC,dir_fd=self.chain[-1][0])
            self._identity()
            fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.locked=True
            self.check()
        except BaseException:
            self.close();raise

    def _identity(self):
        _ep_need(not self.closed and self.fd is not None and self.pid==_ep_os.getpid(),
                 'registry lock is closed or belongs to another process')
        _ep_chain_check(self.chain)
        _ep_need(_ep_metadata(_ep_os.fstat(self.fd))==self.pin['metadata']
                 ==_ep_metadata(_ep_os.stat(self.name,dir_fd=self.chain[-1][0],follow_symlinks=False))
                 ==_ep_metadata(_EpPath(self.pin['path']).lstat()),
                 'registry lock was renamed or replaced')
        _ep_need(epoch_read_original(self.pin)==b'','registry-lock body changed')

    def check(self):
        _ep_need(self.locked,'exclusive registry lock is not held')
        self._identity()
        return self.pin

    def close(self):
        if self.closed:return
        self.closed=True
        if self.fd is not None:
            try:
                if self.locked:self._fcntl.flock(self.fd,self._fcntl.LOCK_UN)
            finally:_ep_os.close(self.fd);self.fd=None;self.locked=False
        if self.chain is not None:
            for item in reversed(self.chain):_ep_os.close(item[0])
            self.chain=None

    def __enter__(self):return self
    def __exit__(self,kind,value,traceback):self.close()


def epoch_acquire_registry_lock(initialization):
    _ep_need(epoch_actual_context(globals())=='phone',
             'only the actual phone Root context can own this registry')
    fixed=epoch_binding_value()
    _ep_exact(initialization,EPOCH_INITIALIZATION_FIELDS,'complete initialization required for registry lock')
    _ep_need(initialization['epoch_id']==EPOCH_ID and initialization['boot_id']==fixed['boot_id']
             and initialization['registry_lock']['path']==EPOCH_REGISTRY_ROOT+'/REGISTRY.lock',
             'registry-lock namespace/epoch identity differs')
    return _EpochHeldRegistryLock(initialization['registry_lock'])


# Pure carrier packet reader. Appended to current component_common.py. Raw
# bodies are separate originals, not repeated base64 members of this packet.
EPOCH_PUBLICATION_ACTION_ROLES = ('root_plan','root_source_manifest','host_intent','host_stdin',
    'host_child','host_result','host_joined','host_output_capture','host_stdout',
    'host_stderr','phone_wrapper')


def publication_inputs_from_original(raw, *, original_from):
    """Decode the full publication input set without executing target code.

    original_from is the enclosing consumer's exact original lookup: it must
    precharge its one decoded/original pool and refuse omitted, duplicate-key,
    over-budget, or different body identities. This reader performs no live I/O
    and grants no action or source-authority qualification. The consumer must
    additionally verify all returned source_action_originals with its actual
    Root source/plan/child/native-operation gates before accepting the state.
    """
    _ep_need(callable(original_from),'one exact enclosing original lookup is required')
    packet=_ep_strict(raw)
    _ep_exact(packet,{'schema','epoch_id','boot_id','publication_observation',
        'manifest','carriers','source_action_originals'},'publication carrier packet fields differ')
    _ep_need(packet['schema']=='hepta.native-guard.epoch-publication-inputs.v2'
             and packet['epoch_id']==EPOCH_ID and _ep_encoded(packet)==raw,
             'canonical explicit publication input schema required')
    fixed=epoch_binding_value()
    _ep_need(packet['boot_id']==fixed['boot_id'],'publication input boot differs')
    fetched={}
    def get(descriptor):
        _ep_pin(descriptor)
        path=descriptor['path']
        if path in fetched:
            pin,body=fetched[path]
            _ep_need(_ep_same(pin,descriptor),'a host carrier path changes its exact byte identity')
            return body
        body=original_from(descriptor)
        _ep_need(type(body) is bytes and _ep_bare(body)=={k:descriptor[k] for k in ('bytes','sha256')},
                 'consumer original lookup returned different publication bytes')
        fetched[path]=(descriptor,body)
        return body
    manifest_raw=get(packet['manifest']);manifest=_ep_strict(manifest_raw)
    _ep_exact(manifest,{'schema','files','directories'},'complete publication manifest fields differ')
    _ep_need(manifest.get('schema')=='hepta.native-guard.epoch-capture-inputs.v1'
             and _ep_encoded(manifest)==manifest_raw
             and type(manifest['files']) is list and 1<=len(manifest['files'])<=EPOCH_MAX_INPUT_FILES,
             'publication manifest must retain canonical exact original identities')
    carriers=packet['carriers'];_ep_need(type(carriers) is list and len(carriers)==len(manifest['files']),
                                       'publication carriers do not cover every original')
    expected={r['path']:r for r in manifest['files']}
    _ep_need(len(expected)==len(manifest['files']),'publication original paths repeat')
    originals={};carrier_paths=set()
    for row in carriers:
        _ep_exact(row,{'original','carrier'},'original/carrier separation is mandatory')
        original=row['original'];carrier=row['carrier']
        _ep_pin(original,original=True);_ep_pin(carrier)
        _ep_need(original['path'] in expected and _ep_same(original,expected[original['path']])
                 and original['path'] not in originals and carrier['path'] not in carrier_paths
                 and {k:carrier[k] for k in ('bytes','sha256')}==
                     {k:original[k] for k in ('bytes','sha256')},
                 'publication carrier omits, duplicates or changes a phone original')
        originals[original['path']]=get(carrier);carrier_paths.add(carrier['path'])
    _ep_need([r['original']['path'] for r in carriers]==[r['path'] for r in manifest['files']],
             'publication carrier order differs from its actual manifest')
    epoch_manifest_value(manifest,originals,binding=fixed)
    observed_raw=get(packet['publication_observation']);observed=_ep_strict(observed_raw)
    _ep_exact(observed,{'schema','state','epoch_id','boot_id','manifest','generation','terminal',
        'initial_manifest_sha256','final_manifest_sha256','file_count','retained_bytes',
        'source_reader_binding','rechecked_files','rechecked_directories','effects'},
        'actual publication observer report fields differ')
    _ep_need(observed['schema']=='hepta.native-guard.epoch-publication-observation.v1'
             and observed['state']=='ACTUAL_COMPLETE_PUBLISHED_REGISTRY_READ'
             and observed['epoch_id']==EPOCH_ID and observed['boot_id']==fixed['boot_id']
             and _ep_same(observed['manifest'],manifest)
             and observed['initial_manifest_sha256']==_ep_sha(manifest_raw)
                 ==observed['final_manifest_sha256']
             and type(observed['file_count']) is int and observed['file_count']==len(originals)
             and type(observed['retained_bytes']) is int
             and observed['retained_bytes']==sum(len(body) for body in originals.values())
             and type(observed['rechecked_files']) is int and observed['rechecked_files']==len(originals)
             and type(observed['rechecked_directories']) is int
             and observed['rechecked_directories']==len(manifest['directories']),
             'publication complete original set or initial/final bookends differ')
    for key in ('generation','terminal'):
        _ep_pin(observed[key],original=True)
        _ep_need(observed[key]['path'] in expected and _ep_same(observed[key],expected[observed[key]['path']]),
                 'actual publication generation/terminal is absent from complete originals')
    _ep_exact(observed['source_reader_binding'],{'root_source_manifest','bridge_source','operation'},
              'publication source is bound by its actual pinned Root caller, not a claimed self hash')
    for key in ('root_source_manifest','bridge_source'):_ep_pin(observed['source_reader_binding'][key])
    _ep_need(observed['source_reader_binding']['operation']=='epoch-publication-read',
             'wrong Root source operation for publication originals')
    expected_effects={'ui_actions':0,'phone_native_dispatches':0,'model_requests':0,
        'signals_sent':0,'source_original_writes':0,'nonces_generated':0,
        'leases_created':0,'boundaries_published':0,'component_qualified':False,'business_qualified':False}
    _ep_need(_ep_same(observed['effects'],expected_effects),
             'publication observation cannot claim task execution, writes or qualification')
    action=packet['source_action_originals']
    _ep_exact(action,EPOCH_PUBLICATION_ACTION_ROLES,'all actual Root action receipt originals required')
    for role in EPOCH_PUBLICATION_ACTION_ROLES:_ep_pin(action[role])
    _ep_need(_ep_same(action['host_joined'],action['host_result']),
             'synchronous joined role must alias the same actual RESULT original')
    _ep_need(len({action[role]['path'] for role in EPOCH_PUBLICATION_ACTION_ROLES
                  if role!='host_joined'})==10,
             'all other Root action roles require distinct original paths')
    action_raw={role:get(action[role]) for role in EPOCH_PUBLICATION_ACTION_ROLES}
    _ep_need(_ep_same(action['root_source_manifest'],observed['source_reader_binding']['root_source_manifest']),
             'publication output is not bound to the same actual Root source manifest')
    return {'manifest':manifest,'originals_by_path':originals,
        'publication_observation':observed,'source_action_originals':action,
        'source_action_original_bytes':action_raw,
        'action_verification_required':True,'source_or_action_authority_verified_here':False}


def _owned_output_read(path, maximum, expected_metadata=None):
    """Only a bounded private regular file; a replaced FIFO is never waited on."""
    path = Path(path)
    need(type(maximum) is int and 0 <= maximum <= 131072, 'owned output read bound differs')
    if expected_metadata is not None:
        need(type(expected_metadata) is list and len(expected_metadata) == 9
             and all(type(v) is int for v in expected_metadata), 'owned output expected identity differs')
    parent, name = parent_fd(path)
    fd = None
    try:
        parent_before = metadata(os.fstat(parent))
        named_before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISREG(named_before.st_mode), 'owned output named path is not regular')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd); identity = metadata(before)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_uid == before.st_gid == 0 and stat.S_IMODE(before.st_mode) == 0o600
             and 0 <= before.st_size <= maximum and identity == metadata(named_before)
             and (expected_metadata is None or identity == expected_metadata),
             'owned output held file type, mode, size, or identity differs')
        chunks = []; size = 0
        while size <= before.st_size:
            chunk = os.read(fd, min(65536, before.st_size + 1 - size))
            if not chunk: break
            chunks.append(chunk); size += len(chunk)
        raw = b''.join(chunks)
        need(len(raw) == before.st_size and identity == metadata(os.fstat(fd))
             == metadata(os.stat(name, dir_fd=parent, follow_symlinks=False))
             and parent_before == metadata(os.fstat(parent)), 'owned output read bookend differs')
        reopened, leaf = parent_fd(path)
        try:
            need(leaf == name and parent_before == metadata(os.fstat(reopened))
                 and identity == metadata(os.stat(leaf, dir_fd=reopened, follow_symlinks=False)),
                 'owned output canonical path changed during read')
        finally:
            os.close(reopened)
        return raw
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)

def _owned_output_error(error):
    return {'type': type(error).__name__[:80], 'detail': str(error)[:256]}

def _owned_output_put(path, value, limit):
    raw = encoded(value)
    need(len(raw) <= limit, 'owned output original exceeds its pre-write bound')
    result = put(path, raw)
    identity = metadata(Path(path).lstat())
    observed = _owned_output_read(path, limit, identity)
    need(observed == raw and metadata(Path(path).lstat()) == identity,
         'owned output original readback differs')
    return dict(path=str(path), metadata=identity, **result)

def _owned_output_fd_identity(fd):
    value = os.fstat(fd)
    return {'metadata': metadata(value), 'access': fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE}

def _owned_output_fd_equal(fd, original, *, regular=False):
    now = _owned_output_fd_identity(fd)
    need(now['access'] == original['access'] and now['metadata'][:6] == original['metadata'][:6],
         'owned output FD identity/access changed')
    need((stat.S_ISREG(now['metadata'][2]) if regular else stat.S_ISFIFO(now['metadata'][2])),
         'owned output descriptor type changed')
    return now

def _owned_output_close(record, slot, *, regular=False):
    """Close only this identity; an interrupted close is never retried blindly."""
    fd = record.get(slot)
    if fd is None:
        return
    record[slot] = None
    record[slot + '_close_attempted'] = False
    record[slot + '_close_returned'] = False
    try:
        _owned_output_fd_equal(fd, record[slot + '_identity'], regular=regular)
        record[slot + '_close_attempted'] = True
        os.close(fd)
        record[slot + '_close_returned'] = True
    except BaseException as error:
        record['ownership_unknown'] = True
        if len(record['errors']) < 4:
            record['errors'].append(_owned_output_error(error))

def _owned_output_capability(record):
    return {key: record[key] for key in (
        'role', 'stream', 'path', 'created_metadata', 'parent_birth_identity',
        'sink_fd', 'read_fd', 'write_fd', 'sink_fd_identity', 'read_fd_identity', 'write_fd_identity')}

def _owned_output_close_unclaimed(records):
    for record in records:
        need(record['reader_claimed'] is False, 'cannot close an active reader-owned FD')
        for slot in ('write_fd', 'read_fd', 'sink_fd'):
            _owned_output_close(record, slot, regular=slot == 'sink_fd')


# Exact public result contracts. This fragment defines shapes only; it never
# manufactures a semantic, live-preservation, publisher, or Root success value.
# An implementation must finish every mandatory original-source/action gate
# before calling a shape checker with its independently recomputed expectation.

EPOCH_ACTIVE_PROOF_FIELDS = ('schema', 'actual_context', 'source_observation', 'semantic')
EPOCH_ACTIVE_SEMANTIC_FIELDS = (
    'schema', 'epoch_id', 'boot_id', 'epoch_anchor', 'current_ordinal',
    'current_identity', 'current_scope_binding', 'current_generation',
    'closed_records', 'previous_native_components', 'consumed_slots_before_current',
    'native_nonces', 'native_scopes', 'native_call_counts',
    'retired_active_role_identities', 'qualified_case_ids',
    'preservation_inventory_original', 'previous_active_boundary',
    'predecessor_terminal', 'source_generations',
    'all_previous_native_records_verified', 'legacy_domains_flattened',
    'legacy_semantics_verified_here', 'live_inventory_verified_here',
    'role_absence_verified_here', 'endpoints_verified_here',
    'component_qualified', 'business_qualified', 'native_boundary_created')
EPOCH_ACTIVE_SOURCE_OBSERVATION_FIELDS = (
    'schema', 'context', 'current_generation', 'generation_records',
    'reviewed_source_bindings', 'physical_full9_observation_claimed')
EPOCH_CURRENT_PRESERVATION_FIELDS = (
    'schema', 'state', 'epoch_id', 'boot_id', 'publication_manifest',
    'latest_boundary', 'epoch_seal', 'source_generation',
    'inventory_spec', 'business_inventory', 'control_inventory',
    'inventory_observation', 'role_absence', 'endpoints', 'external_artifacts',
    'immutable_original_rechecks', 'original_retirement_current_equality_claimed',
    'component_qualified', 'business_qualified', 'native_boundary_created')
EPOCH_PUBLISH_RESULT_FIELDS = (
    'schema', 'state', 'epoch_id', 'ordinal', 'nonce', 'case_id',
    'boundary', 'inventory', 'closure', 'terminal', 'initialization',
    'generation', 'scope_binding', 'predecessor_terminal',
    'component_qualified', 'business_qualified', 'native_boundary_created',
    'automatic_replay')
EPOCH_ROOT_RESULT_FIELDS = (
    'schema', 'state', 'source_package', 'epoch', 'epoch_publication_inputs',
    'component_qualified', 'business_qualified', 'model_requests',
    'four_role_qualification', 'native_status', 'scope', 'late_boundary',
    'previous', 'automatic_retry', 'steps')
EPOCH_ROOT_RESULT_BINDING_FIELDS = (
    'schema', 'epoch_id', 'ordinal', 'nonce', 'label', 'runtime',
    'combination', 'generation', 'initialization', 'reservation', 'identity',
    'scope_binding', 'predecessor_terminal', 'terminal',
    'publication_observation')


def epoch_active_proof_contract(value, *, expected_semantic, expected_source_observation,
                                actual_context):
    """Check a completed proof against separately computed values, without I/O."""
    _ep_need(actual_context in ('phone', 'mac', 'p4'), 'explicit actual context required')
    _ep_exact(value, EPOCH_ACTIVE_PROOF_FIELDS, 'active proof result fields differ')
    _ep_exact(value['semantic'], EPOCH_ACTIVE_SEMANTIC_FIELDS, 'active semantic result fields differ')
    _ep_exact(value['source_observation'], EPOCH_ACTIVE_SOURCE_OBSERVATION_FIELDS,
              'active reviewed-source result fields differ')
    _ep_need(value['schema']=='hepta.native-guard.epoch-active-semantic-proof.v1'
             and value['actual_context']==actual_context
             and value['semantic']['schema']=='hepta.native-guard.epoch-active-semantics.v1'
             and value['semantic']['epoch_id']==EPOCH_ID
             and value['source_observation']['schema']=='hepta.native-guard.epoch-active-source-binding.v1'
             and value['source_observation']['context']==actual_context
             and value['source_observation']['physical_full9_observation_claimed'] is False,
             'active proof schema/context or source-provenance claim differs')
    _ep_need(_ep_same(value['semantic'], expected_semantic)
             and _ep_same(value['source_observation'], expected_source_observation),
             'active result differs from independently verified original inputs')
    return value


def epoch_current_preservation_contract(value, *, expected):
    """No live check is performed here; expected must be the full actual result."""
    _ep_exact(value, EPOCH_CURRENT_PRESERVATION_FIELDS, 'current epoch proof fields differ')
    _ep_need(value['schema']=='hepta.native-guard.epoch-current-preservation.v1'
             and value['state']=='SEALED_EPOCH_CURRENT_ORIGINALS_INVENTORY_ROLES_ENDPOINTS_VERIFIED'
             and value['epoch_id']==EPOCH_ID
             and value['original_retirement_current_equality_claimed'] is False
             and value['component_qualified'] is False
             and value['business_qualified'] is False
             and value['native_boundary_created'] is False
             and _ep_same(value,expected), 'actual current preservation proof differs')
    return value


def epoch_publish_result_contract(value, *, expected):
    """The expectation comes from complete post-COMMIT replay, never this state."""
    _ep_exact(value,EPOCH_PUBLISH_RESULT_FIELDS,'epoch publisher result fields differ')
    _ep_need(value['schema']=='hepta.native-guard.epoch-boundary-publish-result.v1'
             and value['state']=='ORIGINAL_EPOCH_NATIVE_BOUNDARY_AND_TERMINAL_PUBLISHED'
             and value['epoch_id']==EPOCH_ID
             and type(value['ordinal']) is int and 1<=value['ordinal']<=EPOCH_MAX_SLOTS
             and type(value['component_qualified']) is bool
             and value['business_qualified'] is False
             and value['native_boundary_created'] is True
             and value['automatic_replay'] is False
             and _ep_same(value,expected),'actual epoch publication differs from originals')
    return value


def epoch_root_result_contract(value, *, expected):
    """Expected requires original host action, publication packet and closure gates."""
    _ep_exact(value,EPOCH_ROOT_RESULT_FIELDS,'epoch Root result fields differ')
    _ep_exact(value['epoch'],EPOCH_ROOT_RESULT_BINDING_FIELDS,'Root epoch binding fields differ')
    _ep_need(value['schema']=='hepta.native-guard.epoch-root-result.v1'
             and value['state']=='ORIGINAL_EPOCH_COMPONENT_CLOSED_AND_TERMINAL_PUBLISHED'
             and value['epoch']['schema']=='hepta.native-guard.epoch-root-result-binding.v1'
             and value['epoch']['epoch_id']==EPOCH_ID
             and type(value['component_qualified']) is bool
             and value['business_qualified'] is False
             and value['four_role_qualification'] is False
             and type(value['model_requests']) is int and value['model_requests']==0
             and value['automatic_retry'] is False
             and _ep_same(value,expected),'Root result is not the complete independently verified result')
    return value



def epoch_forbidden_nonces(binding=None):
    """All four distinct fixed historical domains permanently deny reuse.

    This set never establishes closure, role absence, current preservation or
    eligibility. Those actual retained-branch gates remain mandatory.
    """
    fixed=epoch_binding_value(binding)
    return tuple(n for name in ('legacy_nonces','failed_nonces',
        'retained_failed_native_nonces','additional_retained_prelaunch_nonces')
        for n in fixed[name])


# The operation member is selected only from the already whole32-verified map.
def _epoch_stage_api():
    module=sys.modules.get('stage_component')
    _ep_need(module is not None,'the verified stage module must already be loaded')
    bodies=globals().get('__reviewed_package_sources__');raw=globals().get('__reviewed_package_manifest_raw__')
    _ep_need(type(bodies) is dict and type(raw) is bytes
        and module.__dict__.get('__reviewed_package_sources__') is bodies
        and module.__dict__.get('__reviewed_package_manifest_raw__')==raw
        and epoch_actual_context(module.__dict__)==epoch_actual_context(globals())
        and module.__dict__.get('__reviewed_source_sha256__')==_ep_sha(bodies['source/stage_component.py']),
        'stage source, source map, manifest or explicit context differs')
    return module

def epoch_lifecycle_bootstrap(package,actual_context,package_sha256,operation):
    return _epoch_stage_api().epoch_lifecycle_bootstrap(package,actual_context,package_sha256,operation)

def epoch_lifecycle_child_argv(package,package_sha256,operation,arguments):
    return _epoch_stage_api().epoch_lifecycle_child_argv(package,package_sha256,operation,arguments)

def epoch_record_lifecycle_admission(lease,retired_path,*,budget_check):
    return _epoch_stage_api().epoch_record_lifecycle_admission(lease,retired_path,budget_check=budget_check)

def epoch_fixture_bootstrap(tree,actual_context):
    return _epoch_stage_api().epoch_fixture_bootstrap(tree,actual_context)

def epoch_fixture_writer_admission(lease,plan,profile):
    return _epoch_stage_api().epoch_fixture_writer_admission(lease,plan,profile)

def epoch_fixture_copy_admission(lease,plan,profile,admission):
    return _epoch_stage_api().epoch_fixture_copy_admission(lease,plan,profile,admission)

def epoch_actual_source_location(namespace,package,member,package_sha256):
    return _epoch_stage_api().epoch_source_location(namespace,package,member,package_sha256)
