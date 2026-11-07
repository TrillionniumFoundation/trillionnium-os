"""Read-only independent audit of every parent-owned Root fixture attempt.

The fixed P4 nonce directory is enumerated independently of the submitted
attempt list. An original child wait and two group-absence observations do
not imply UI success: all actual command/wire/UID originals are rechecked.
No subprocess, socket, signal, device access or command execution occurs here.
"""
import ast
import base64
import errno
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import types

import component_common as C
import component_listener as L
import native_guard_session_r2 as K
import root_fixture_once as X
import witness_bundle as W

FIXTURE_PARENTS = Path('/home/alex/codex-hepta-native-guard-fixtures-r10-r1')
PHASES = ('setup', 'before-guard', 'after-guard')
ARGUMENTS = ('material', 'lease-sha256', 'package-sha256', 'plan', 'plan-sha256',
             'bound-contract', 'bound-contract-sha256', 'accepted', 'accepted-sha256')
BINDING = {'scope', 'phase', 'phase_plan_sha256', 'contract_sha256', 'lease_sha256',
           'package_sha256', 'child_entry', 'actor_out', 'argv'}
FINAL_ACTOR_FILES = {'ACTOR-ORIGINALS.json', 'ORIGINAL-INDEX.json', 'RESULT.json'}


def integer(value, minimum=0, maximum=None):
    C.need(type(value) is int and value >= minimum
           and (maximum is None or value <= maximum), 'original integer bound differs')
    return value


def directory_snapshot(path):
    """Canonical held-FD directory census, or the first real ENOENT edge."""
    path = Path(path)
    C.need(path.is_absolute() and '..' not in path.parts and 2 <= len(path.parts) <= 64,
           'canonical bounded host directory required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    current = Path('/')
    try:
        for part in path.parts[1:]:
            before = os.fstat(fd)
            try:
                following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            except OSError as error:
                C.need(error.errno == errno.ENOENT, 'host directory absence is unknown')
                try: os.stat(part, dir_fd=fd, follow_symlinks=False)
                except OSError as again: C.need(again.errno == errno.ENOENT, 'host absence second read unknown')
                else: C.need(False, 'host directory appeared during census')
                C.need(current.resolve(strict=True) == current, 'host absence ancestor changed')
                now = current.lstat()
                ident = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid]
                C.need(ident(before) == ident(os.fstat(fd)) == ident(now), 'host absence parent changed')
                try: (current/part).lstat()
                except OSError as again: C.need(again.errno == errno.ENOENT, 'host absence final read unknown')
                else: C.need(False, 'host absence path now exists')
                return {'path': str(path), 'kind': 'absent', 'absence': 'ENOENT',
                        'missing_path': str(current/part), 'parent_path': str(current),
                        'canonical_parent_identity': ident(before)}
            os.close(fd); fd = following; current /= part
        before = os.fstat(fd)
        C.need(stat.S_ISDIR(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o700,
               'private Root fixture host directory mode differs')
        names = sorted(os.listdir(fd)); C.need(len(names) <= 512, 'Root fixture directory count bound')
        C.need(names == sorted(os.listdir(fd)) and path.resolve(strict=True) == path
               and C.metadata(before) == C.metadata(os.fstat(fd)) == C.metadata(path.lstat()),
               'Root fixture directory changed during census')
        return {'path': str(path), 'kind': 'directory', 'metadata': C.metadata(before), 'names': names}
    finally:
        os.close(fd)


def remember_directory(originals, path):
    row = directory_snapshot(path)
    key = 'root_fixture_absences' if row['kind'] == 'absent' else 'root_fixture_directories'
    cache = getattr(originals, key, None)
    if cache is None: cache = {}; setattr(originals, key, cache)
    C.need(str(path) not in cache or cache[str(path)] == row, 'Root fixture directory changed between audit phases')
    cache[str(path)] = row
    return row


def recheck_directories(originals):
    """Call after Originals.recheck(), immediately before closing evidence."""
    for key in ('root_fixture_directories', 'root_fixture_absences'):
        for path, expected in getattr(originals, key, {}).items():
            C.need(directory_snapshot(path) == expected, 'Root fixture census changed after original audit')


def phone_fixture_absent(files, lease, scope):
    C.need(not any(name.startswith('fixture/') for name in files), 'actual phone fixture contains effects')
    raw = files.get('observation/FIXTURE-ABSENCE.json')
    C.need(raw is not None, 'actual original phone fixture ENOENT observation required')
    value = C.strict(raw)
    C.need(set(value) == {'schema', 'scope', 'observations', 'absence_does_not_qualify_component'}
           and value['schema'] == 'hepta.native-guard.fixture-absence-set.v1'
           and value['scope'] == scope and value['absence_does_not_qualify_component'] is True,
           'original phone fixture absence identity differs')
    path = '/proc/1/root/data/local/tmp/hepta-native-guard-' + lease['nonce']
    rows = [row for row in value['observations'] if row.get('path') == path]
    C.need(len(rows) == 1, 'one bound phone fixture absence required')
    row = rows[0]
    C.need(set(row) == {'schema', 'path', 'absence', 'canonical_parent_identity', 'observed_monotonic_ns', 'ui_actions'}
           and row['schema'] == 'hepta.native-guard.fixture-absence.v1' and row['absence'] == 'ENOENT'
           and type(row['ui_actions']) is int and row['ui_actions'] == 0,
           'phone fixture absence is not original ENOENT')
    meta = row['canonical_parent_identity']
    C.need(isinstance(meta, list) and len(meta) == 5 and all(type(x) is int for x in meta)
           and stat.S_ISDIR(meta[2]), 'phone fixture canonical parent identity absent')
    integer(row['observed_monotonic_ns'], 1)
    inventory = C.strict(files['after/AFTER-INVENTORY.json'])
    C.need(path in inventory['roots'] and inventory['entries'].get(path) == {'kind': 'absent', 'absence': 'ENOENT'},
           'full actual phone inventory does not retain the same absence')
    return row


def source_modules(originals, files, package_sha):
    package_raw = files['home/package/MANIFEST.json']
    C.need(C.sha(package_raw) == package_sha, 'explicit actual package pin differs')
    package = C.strict(package_raw)
    C.need(package['schema'] == 'hepta.native-guard.adapter-package.v1'
           and package['state'] == 'HOST_REVIEWED_NOT_PHONE_QUALIFIED', 'actual source package state differs')
    rows = {row['path']: row for row in package['files']}
    C.need(5 <= len(rows) == len(package['files']) <= 32, 'package file census differs')
    for module, filename in [(C, 'component_common.py'), (L, 'component_listener.py'),
            (K, 'native_guard_session_r2.py'), (W, 'witness_bundle.py'), (X, 'root_fixture_once.py')]:
        raw = originals.read(Path(module.__file__), 1048576)
        C.need(raw == files['home/package/source/'+filename]
               and C.descriptor(raw) == {k:rows['source/'+filename][k] for k in ('bytes', 'sha256')},
               'Root fixture verifier dependency differs from actual package: '+filename)
    C.need(originals.read(Path(__file__), 1048576) == files['home/package/source/root_fixture_originals.py'],
           'Root fixture verifier itself differs from actual package')
    runner = files['home/package/source/run_root_fixture_phase.py']
    assignments = {n.targets[0].id: n.value for n in ast.parse(runner).body
                   if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)}
    node = assignments['FIXTURE_PARENTS']
    C.need(ast.literal_eval(assignments['ARGUMENTS']) == ARGUMENTS
           and isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'Path'
           and len(node.args) == 1 and not node.keywords and ast.literal_eval(node.args[0]) == str(FIXTURE_PARENTS),
           'actual parent source namespace or argv interface changed')
    modules = {}
    for name in ('phone_observation_tools', 'phone_task_guards', 'phone_local_tools'):
        module = sys.modules.get(name)
        C.need(module is not None and originals.read(Path(module.__file__), 1048576)
               == files['home/inputs/production/'+name+'.py'], 'actual reviewed production pure mapper is not loaded')
        modules[name] = module
    return modules


def phase_context(files, lease, scope, modules):
    bound = C.strict(files['home/BOUND-CONTRACT.json']); contract = bound['contract']
    C.need(contract['nonce'] == lease['nonce'] and contract['case_id'] == lease['case_id']
           and bound['lease_sha256'] == C.sha(files['home/LEASE.json']), 'Root contract/lease mismatch')
    cfg = C.strict(files['home/inputs/configuration.original.json'])
    phone, guards, local = (modules[n] for n in ('phone_observation_tools', 'phone_task_guards', 'phone_local_tools'))
    mapper = types.SimpleNamespace(apps=cfg['approved_apps'],
        _serial_guard=lambda: phone.PhoneTools._serial_guard(None),
        _focus_input_precondition=local.current_viewport_guard)
    context = types.SimpleNamespace(contract=contract, contract_sha=C.sha(C.encoded(contract)), scope=scope, mapper=mapper)
    if 'run/capture-phase.json' in files: context.capture = C.strict(files['run/capture-phase.json'])['capture']
    return context, phone, guards


def actual_plan(raw, phase, context, guards):
    plan, commands = W.validate_plan(raw)
    token = C.root_operation_id(context.scope, context.contract_sha, phase)
    expected = L.root_commands(context, phase, guards, token)
    C.need(plan['scope'] == context.scope and plan['contract_sha256'] == context.contract_sha
           and plan['phase'] == phase and plan['operation_id'] == token and commands == expected,
           'Root phase plan differs from actual reviewed command builders')
    order = ['disturbance', 'public', 'png'] if phase == 'before-guard' else list(expected)
    C.need(plan['execution_order'] == order, 'Root phase command order differs')
    return plan, commands


def actual_argv(originals, value, files, lease, package_sha, phase, plan_raw, out):
    argv = value['argv']
    C.need(isinstance(argv, list) and len(argv) == 4 + 2*len(ARGUMENTS) + 3
           and all(isinstance(x, str) and '\0' not in x for x in argv)
           and argv[:3] == ['/usr/bin/python3', '-I', '-B']
           and argv[-3:] == ['--out', str(out/'actor'), '--execute-root-fixture-phase-once'],
           'actual single child argv differs')
    supplied = {}
    for pos, name in enumerate(ARGUMENTS):
        C.need(argv[4+2*pos] == '--'+name, 'actual child argv option order differs')
        supplied[name] = argv[5+2*pos]
    tree = Path(supplied['material'])
    C.need(tree.is_absolute() and tree.resolve(strict=True) == tree
           and argv[3] == str(tree/'package/source/root_fixture_once.py')
           and supplied['lease-sha256'] == C.sha(files['home/LEASE.json'])
           and supplied['package-sha256'] == package_sha
           and supplied['plan-sha256'] == C.sha(plan_raw)
           and supplied['bound-contract-sha256'] == C.sha(files['home/BOUND-CONTRACT.json'])
           and supplied['accepted-sha256'] == C.sha(files['home/ACCEPTED.json']),
           'child material/lease/plan/scope pins differ')
    for name, raw in [('plan', plan_raw), ('bound-contract', files['home/BOUND-CONTRACT.json']),
                      ('accepted', files['home/ACCEPTED.json'])]:
        C.need(originals.pinned({'path': supplied[name], **C.descriptor(raw)}) == raw,
               'actual host child input bytes differ')
    for name, raw in files.items():
        if name == 'home/LEASE.json' or name.startswith(('home/package/', 'home/inputs/')):
            C.need(originals.pinned({'path': str(tree/name[len('home/'):]), **C.descriptor(raw)}) == raw,
                   'actual Root material differs from captured combination/source')
    child = files['home/package/source/root_fixture_once.py']
    C.need(value['child_entry'] == {'path': argv[3], **C.descriptor(child)}, 'actual child source descriptor differs')
    return supplied


def raw_stat(row, pid):
    C.need(set(row) == {'raw_b64', 'bytes', 'sha256'}, 'original P4 proc stat descriptor differs')
    raw = base64.b64decode(row['raw_b64'], validate=True)
    C.need(0 < len(raw) <= 8192 and base64.b64encode(raw).decode() == row['raw_b64']
           and C.descriptor(raw) == {k:row[k] for k in ('bytes', 'sha256')}, 'original P4 proc stat bytes differ')
    return C.stat_identity(raw, pid)


def parent_terminal(originals, terminal_row, phase, files, lease, scope, package_sha, plan_raw, context):
    out = FIXTURE_PARENTS/lease['nonce']/phase
    C.need(terminal_row['path'] == str(out/'HOST-TERMINAL.json'), 'parent terminal is outside exact nonce/phase')
    terminal = C.strict(originals.pinned(terminal_row))
    intent = C.strict(originals.read(out/'HOST-INTENT.json', 262144))
    child = C.strict(originals.read(out/'HOST-CHILD.json', 262144))
    expected = {'scope': scope, 'phase': phase, 'phase_plan_sha256': C.sha(plan_raw),
        'contract_sha256': context.contract_sha, 'lease_sha256': C.sha(files['home/LEASE.json']),
        'package_sha256': package_sha, 'actor_out': str(out/'actor')}
    for value, schema in [(intent, 'intent'), (child, 'child'), (terminal, 'terminal')]:
        C.need(value['schema'] == 'hepta.native-guard.root-fixture-host-'+schema+'.v1'
               and all(value[k] == want for k, want in expected.items()), 'parent original binding differs')
        C.need({k:value[k] for k in BINDING} == {k:terminal[k] for k in BINDING}, 'parent/child original argv binding differs')
    actual_argv(originals, terminal, files, lease, package_sha, phase, plan_raw, out)
    parent_sha = C.sha(files['home/package/source/run_root_fixture_phase.py'])
    C.need(set(intent) == BINDING | {'schema', 'maximum_child_starts', 'automatic_retry',
           'maximum_wait_seconds', 'parent_source_sha256', 'phone_actions_owned_by_child_only'}
           and intent['maximum_child_starts'] == 1 and type(intent['maximum_child_starts']) is int
           and intent['maximum_wait_seconds'] == 240 and type(intent['maximum_wait_seconds']) is int
           and intent['automatic_retry'] is False and intent['phone_actions_owned_by_child_only'] is True
           and intent['parent_source_sha256'] == terminal['parent_source_sha256'] == parent_sha,
           'original parent bounded one-child source differs')
    C.need(set(terminal) == BINDING | {'schema', 'state', 'child_pid', 'child_identity', 'child_wait_returned',
        'child_returncode', 'failure', 'group_absence_observations', 'actor_directory', 'actor_files',
        'p4_started_monotonic_ns', 'p4_observed_monotonic_ns', 'automatic_retry', 'signals_sent',
        'model_requests', 'native_task_submissions', 'parent_source_sha256', 'component_qualified', 'stdout', 'stderr'}
        and terminal['state'] == 'OWNED_ROOT_FIXTURE_CHILD_JOINED' and terminal['child_wait_returned'] is True
        and type(terminal['child_returncode']) is int and terminal['failure'] is None
        and terminal['automatic_retry'] is False and terminal['component_qualified'] is False
        and all(type(terminal[k]) is int and terminal[k] == 0 for k in ('signals_sent', 'model_requests', 'native_task_submissions')),
        'Root child still unknown, unjoined or not the original one-attempt lifecycle')
    observed = terminal['child_identity']; pid = integer(terminal['child_pid'], 2)
    C.need(set(observed) == {'identity', 'ppid', 'proc_self_pid_matches_host', 'stat_before', 'stat_after'}
           and observed['proc_self_pid_matches_host'] is True and observed['identity'][:3] == [pid]*3,
           'original owned child session identity absent')
    before = raw_stat(observed['stat_before'], pid); after = raw_stat(observed['stat_after'], pid)
    C.need(C.generation(before) == C.generation(after) == observed['identity']
           and before['ppid'] == after['ppid'] == observed['ppid'] == child['parent_pid']
           and integer(observed['ppid'], 2) != pid and child['spawned_pid'] == pid,
           'P4 child generation or original parent differs')
    C.need(set(child) == BINDING | {'schema', 'identity', 'ppid', 'proc_self_pid_matches_host',
        'stat_before', 'stat_after', 'spawned_pid', 'parent_pid', 'p4_monotonic_observed_ns'}
        and all(child[k] == v for k, v in observed.items()), 'original HOST-CHILD and terminal identity differ')
    started = integer(terminal['p4_started_monotonic_ns'], 1)
    observed_ns = integer(child['p4_monotonic_observed_ns'], started)
    finished = integer(terminal['p4_observed_monotonic_ns'], observed_ns)
    absence = terminal['group_absence_observations']
    C.need(isinstance(absence, list) and len(absence) == 2, 'two original P4 group absence observations required')
    last = observed_ns
    for row in absence:
        C.need(set(row) == {'numeric_pids', 'members', 'kernel_group_absence', 'observed_monotonic_ns'}
               and row['members'] == [] and row['kernel_group_absence'] is True, 'P4 group/session absence unknown')
        integer(row['numeric_pids'], 1, 4096); last = integer(row['observed_monotonic_ns'], last, finished)
    directory = remember_directory(originals, out)
    C.need(directory['kind'] == 'directory', 'actual parent originals directory absent')
    expected_names = {'HOST-INTENT.json', 'HOST-CHILD.json', 'HOST-TERMINAL.json', 'child.stdout', 'child.stderr'}
    actor = terminal['actor_directory']
    if actor['kind'] == 'directory': expected_names.add('actor')
    C.need(set(directory['names']) == expected_names, 'unlisted or incomplete Root parent original set')
    for key in ('stdout', 'stderr'):
        C.need(terminal[key]['path'] == str(out/('child.'+key)), 'actual child stream path differs')
        originals.pinned(terminal[key])
    return terminal


def actor_files(originals, terminal):
    path = Path(terminal['actor_out']); current = remember_directory(originals, path)
    expected = terminal['actor_directory']
    if current['kind'] == 'absent':
        C.need(current['missing_path'] == str(path) and expected == {'path': str(path), 'kind': 'absent',
               'absence': 'ENOENT', 'canonical_parent_identity': current['canonical_parent_identity']}
               and terminal['actor_files'] == {}, 'actual actor output absence differs')
        return None
    C.need(current == expected and set(current['names']) == set(terminal['actor_files']),
           'actual complete Actor directory inventory differs')
    result = {}; total = 0
    for name, row in terminal['actor_files'].items():
        C.need(set(row) == {'path', 'metadata', 'bytes', 'sha256'} and row['path'] == str(path/name)
               and Path(name).name == name and name not in ('.', '..'), 'actor original descriptor/path differs')
        raw = originals.pinned({k:row[k] for k in ('path', 'bytes', 'sha256')}); total += len(raw)
        C.need(len(raw) <= 16*1024*1024 and total <= 64*1024*1024
               and originals.files[row['path']]['metadata'] == row['metadata'], 'actor original metadata/size differs')
        result[name] = raw
    return result


def named_originals(paths, expected_keys, actor_path, actual):
    C.need(isinstance(paths, dict) and set(paths) == set(expected_keys), 'eight-file Root execution set differs')
    result = {}
    for key, raw_path in paths.items():
        path = Path(raw_path)
        C.need(path.parent == actor_path and path.name in actual, 'Root execution original left actor directory')
        result[key] = actual[path.name]
    C.need(len(set(paths.values())) == len(paths), 'Root execution original path was duplicated')
    return result


def prelude_commands(q, plan, lease, mapper, phone, guards, actual, actor_path):
    prelude = q['fixture_prelude']
    if plan['phase'] != 'setup' or lease['case_id'] != 'NEG-02':
        C.need(prelude is None, 'unexpected Root setup prelude'); return []
    C.need(isinstance(prelude, dict) and set(prelude) == {'schema', 'scope', 'contract_sha256', 'operation_id',
        'records', 'initial_public_state', 'expected_final_input_text', 'focus_point_source', 'maximum_focus_taps',
        'maximum_append_commands', 'native_worker_qualification', 'model_requests', 'business_qualified', 'automatic_retry'},
        'complete explicit NEG02 prelude required')
    records = prelude['records']; C.need(isinstance(records, list) and len(records) in (3, 5), 'prelude command count differs')
    answer = []; index = 0
    def token(name): return C.sha((plan['operation_id']+':fixture:'+name).encode())[:32]
    def take(name, command):
        nonlocal index
        C.need(index < len(records), 'missing actual prelude command')
        row = records[index]; index += 1; prefix = 'prelude-'+name
        C.need(set(row) == {'name', 'command_sha256', 'files'} and row['name'] == name
               and row['command_sha256'] == C.sha(command), 'prelude command order or actual bytes differ')
        raw = named_originals(row['files'], [prefix+s for s in W.SUFFIXES], actor_path, actual)
        L.verify_operator_execution(raw, prefix, raw[prefix], command, phase='setup', nonce=lease['nonce'], boot=lease['boot_id'])
        answer.append((prefix, command, raw)); return raw[prefix]
    serial = mapper._serial_guard(); target = mapper.apps['Unicode验证']['component']
    C.need(guards.component(target) == K.TEXT, 'actual TextEntry setup component differs')
    opened = take('open', guards.app_open_command(serial, target, token('open'), mapper._focus_input_precondition()).encode())
    guards.verify_app_open(C.strict(opened), token('open'), target)
    def observe(name):
        path = '/data/local/tmp/hepta-native-guard-'+lease['nonce']+'/prelude-'+name+'.xml'
        command = guards.public_text_command(serial, token(name), K.PACKAGE, path).encode()
        return K.public_state(take(name, command), token(name), phone, guards)
    initial, page, viewport = observe('initial'); focused = initial; old = initial[K.INPUT]['text']
    C.need(initial[K.RECEIPT]['text'] == '等待输入', 'original setup receipt was already submitted')
    if initial[K.INPUT]['focused'] != 'true':
        x, y = X.fixture_input_point(initial)
        take('focus', (serial+guards.page_equality_guard(page)
            +'[ "$(dumpsys display | grep \'mViewports=\')" = '+shlex.quote(viewport)+' ] || exit 68; '
            +'exec /system/bin/input tap '+str(x)+' '+str(y)).encode())
        focused, page, viewport = observe('focused')
    C.need(focused[K.INPUT]['focused'] == 'true' and focused[K.INPUT]['text'] == old
           and focused[K.RECEIPT] == initial[K.RECEIPT] and focused[K.READBACK] == initial[K.READBACK],
           'Root prelude focus changed original text/receipt or was not confirmed')
    marker = '-fixture-'+lease['nonce'][:12]; C.need(len((old+marker).encode()) <= 4096, 'Root setup text bound')
    take('append', (serial+guards.page_equality_guard(page)
        +'[ "$(dumpsys display | grep \'mViewports=\')" = '+shlex.quote(viewport)+' ] || exit 68; '
        +'/system/bin/input keyevent KEYCODE_MOVE_END || exit 78; '
        +'exec /system/bin/input text '+shlex.quote(marker)).encode())
    C.need(index == len(records) and prelude == {'schema':'hepta.native-guard.root-text-fixture-prelude.v1',
        'scope': plan['scope'], 'contract_sha256': plan['contract_sha256'], 'operation_id': plan['operation_id'],
        'records': records, 'initial_public_state': initial, 'expected_final_input_text': old+marker,
        'focus_point_source':'center of the single visible original public EditText bounds', 'maximum_focus_taps':1,
        'maximum_append_commands':1, 'native_worker_qualification':False, 'model_requests':0,
        'business_qualified':False, 'automatic_retry':False}, 'Root setup summary does not reconstruct from originals')
    return answer


def verify_wire_census(actual, actor_path, executions, q, plan, lease, files, terminal):
    """Rebuild the entire frozen Actor wire sequence, including readonly fences."""
    basic = ('[ "$(id -u)" = 2000 ] || exit 78; [ "$(getprop ro.serialno)" = ZY22LS7WZT ] || exit 78; '
             '[ "$(cat /proc/sys/kernel/random/boot_id)" = '+shlex.quote(lease['boot_id'])+' ] || exit 78; ')
    stage = '/data/local/tmp/hepta-native-guard-'+lease['nonce']; phase = plan['phase']; sequence = []
    def add(tag, command, kind='empty', data=None): sequence.append((tag, command, kind, data))
    fence_count = 0
    def fence():
        nonlocal fence_count
        fence_count += 1; home = C.BASE/'native-guard-r10-r1'/lease['label']
        argv = ['/usr/bin/python3', '-I', '-B', str(home/'package/source/witness_bundle.py'), 'fence',
            '--lease', str(home), '--lease-sha256', C.sha(files['home/LEASE.json']), '--phase', phase,
            '--phase-plan-sha256', C.sha(files['home/ROOT-'+phase.upper()+'-PLAN.json']), '--execute-read-only-fence']
        command = '/data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root '+shlex.join(argv)
        add('live-scope-fence-'+str(fence_count), basic+'/debug_ramdisk/su -c '+shlex.quote(command), 'fence')
    fence()
    if phase == 'setup': add('reserve-fixture-stage', basic+'umask 077; mkdir '+shlex.quote(stage)+' && [ "$(stat -c %u:%a '+shlex.quote(stage)+')" = 2000:700 ]')
    else: add('verify-fixture-stage', basic+'test -d '+shlex.quote(stage)+' && test ! -L '+shlex.quote(stage)+' && [ "$(stat -c %u:%a '+shlex.quote(stage)+')" = 2000:700 ]')
    apks = q['installed_probe_before']
    def probe(tag):
        add(tag+'-paths', basic+'pm path '+shlex.quote(K.PACKAGE), 'paths', apks)
        for index, apk in enumerate(apks):
            path = apk['path']; add(tag+'-apk-'+str(index), basic+'stat -c %s '+shlex.quote(path)+' && sha256sum '+shlex.quote(path), 'apk', apk)
        C.need(C.strict(actual[tag+'.json']) == {'installed_public_package':K.PACKAGE, 'apks':apks, 'source_equals_apk_not_asserted':True}, 'actual probe identity summary differs')
    probe('probe-before')
    expected_names = {'ACTOR-ATTEMPT.json', 'probe-before.json', 'probe-after.json'} | FINAL_ACTOR_FILES
    fixtures = {}; last_command_end = 0
    for name, command, originals in executions:
        fence(); tag = phase+'-'+name; destination = stage+'/'+tag+'.sh'; uid = stage+'/'+tag+'.uid'
        add(tag+'-stage-absent', basic+'test ! -e '+shlex.quote(destination)+' && test ! -L '+shlex.quote(destination))
        wire, uid_wire = L.operator_wire(C.sha(command), destination, uid, lease['boot_id'])
        add(tag+'-execute', wire, 'execution', originals[name]); add(tag+'-actual-uid', uid_wire, 'uid', b'2000\n')
        expected_names |= {tag+suffix for suffix in ('.command.sh', '.DISPATCH-INTENT.json', '.SYNC.json', '.EXECUTION.json')}
        for suffix, key in [('.command.sh', name+'_command'), ('.DISPATCH-INTENT.json', name+'_intent'), ('.EXECUTION.json', name+'_execution')]:
            C.need(actual[tag+suffix] == originals[key], 'Root eight-file key points at another command')
        C.need(C.strict(actual[tag+'.SYNC.json']) == {'state':'ORIGINAL_SYNC_SEND_OKAY', 'path':destination,
               'source_sha256':C.sha(command), 'bytes':len(command), 'automatic_retry':False}, 'actual original sync bytes differ')
        fixtures[tag+'.sh'] = command; fixtures[tag+'.uid'] = b'2000\n'
        wire_value = C.strict(originals[name+'_wire']); uid_value = C.strict(originals[name+'_uid_wire'])
        C.need(wire_value['p4_monotonic_started_ns'] >= last_command_end, 'prelude/planned effect order differs')
        last_command_end = uid_value['p4_monotonic_finished_ns']
    probe('probe-after'); last = terminal['p4_started_monotonic_ns']; route = None
    bound = C.strict(files['home/BOUND-CONTRACT.json']); ready = C.strict(files['home/READY.json'])
    roles = {'provider':ready['identity'], 'sidecar':bound['sidecar_identity'], 'supervisor':C.strict(files['home/SUPERVISOR.json'])}
    for index, (tag, command, kind, data) in enumerate(sequence, 1):
        prefix = 'wire-%03d-%s' % (index, tag)
        expected_names |= {prefix+suffix for suffix in ('.INTENT.json', '.wire.json', '.stdout.bin', '.stderr.bin')}
        wire = C.strict(actual[prefix+'.wire.json']); intent = C.strict(actual[prefix+'.INTENT.json'])
        stdout = actual[prefix+'.stdout.bin']; stderr = actual[prefix+'.stderr.bin']
        C.need(wire['command'] == command and not stderr and set(intent) == {'command','wire_request_bytes','p4_monotonic_ns','automatic_retry'}
               and intent['command'] == command and intent['wire_request_bytes'] == len(('shell,v2,raw:'+command).encode())
               and intent['automatic_retry'] is False, 'unexpected, failed or unlisted actual Root wire')
        L.verify_shell_wire(wire, stdout, stderr)
        integer(intent['p4_monotonic_ns'], last, wire['p4_monotonic_started_ns'])
        last = integer(wire['p4_monotonic_finished_ns'], wire['p4_monotonic_started_ns'], terminal['p4_observed_monotonic_ns'])
        for key, raw in [('stdout', stdout), ('stderr', stderr)]:
            C.need(wire[key] == {'path':str(actor_path/(prefix+'.'+key+'.bin')), **C.descriptor(raw)}, 'wire stream source path differs')
        current_route = (wire['address'], wire['transport_id'])
        C.need(isinstance(current_route[0], list) and len(current_route[0]) == 2 and current_route[0][0] == '127.0.0.1'
               and type(current_route[0][1]) is int and 1 <= current_route[0][1] <= 65535
               and isinstance(current_route[1], str) and current_route[1].isdigit()
               and (route is None or route == current_route), 'actual original transport route changed')
        route = current_route
        if kind == 'empty': C.need(stdout == b'', 'unexpected Root staging output')
        elif kind in ('execution', 'uid'): C.need(stdout == data, 'actual Root effect stream differs')
        elif kind == 'paths': C.need(sorted(stdout.decode().splitlines()) == sorted('package:'+x['path'] for x in data), 'actual probe package paths differ')
        elif kind == 'apk': C.need(stdout.decode().splitlines() == [str(data['bytes']), data['sha256']+'  '+data['path']], 'actual probe APK bytes differ')
        else:
            value = C.strict(stdout)
            C.need(set(value) == {'schema','state','phase','phase_plan_sha256','scope','contract_sha256','lease_sha256',
                'package_sha256','boot_id','roles','phone_unix_ms','phone_writes','ui_actions','socket_connections','signals_sent','model_requests'}
                and value['schema'] == 'hepta.native-guard.root-fixture-live-fence.v1' and value['state'] == 'ACTUAL_ACCEPTED_PHASE_STILL_LIVE'
                and value['roles'] == roles and value['phase_plan_sha256'] == C.sha(files['home/ROOT-'+phase.upper()+'-PLAN.json'])
                and all(value[k] == plan[k] for k in ('phase','scope','contract_sha256'))
                and value['lease_sha256'] == C.sha(files['home/LEASE.json']) and value['package_sha256'] == lease['package_sha256']
                and value['boot_id'] == lease['boot_id'] and type(value['phone_unix_ms']) is int
                and 0 < value['phone_unix_ms'] < lease['expires_unix_ms']
                and all(type(value[k]) is int and value[k] == 0 for k in ('phone_writes','ui_actions','socket_connections','signals_sent','model_requests')),
                'actual pre-effect live-scope fence differs')
    C.need(set(actual) == expected_names, 'omitted, partial, extra or unknown original Actor operation')
    return fixtures, len(sequence)


def complete_actor(originals, terminal, actual, files, lease, scope, plan_raw, plan, commands, context, phone, guards):
    path = Path(terminal['actor_out'])
    attempt = C.strict(actual['ACTOR-ATTEMPT.json'])
    C.need(attempt == {'phase_plan_sha256':C.sha(plan_raw), 'lease_sha256':C.sha(files['home/LEASE.json']),
        'scope':scope, 'phase':plan['phase'], 'state':'RESERVED_NO_AUTOMATIC_RETRY',
        'automatic_retry':False, 'native_task_claim':False, 'model_requests':0}, 'actual child attempt reservation differs')
    index = C.strict(actual['ORIGINAL-INDEX.json'])
    C.need(set(index) == {'schema','phase_plan_sha256','files','actor_originals_file','frozen_actor_source_sha256','frozen_transport_source_sha256'}
        and index['schema'] == 'hepta.native-guard.root-original-index.v1' and index['phase_plan_sha256'] == C.sha(plan_raw)
        and index['actor_originals_file'] == str(path/'ACTOR-ORIGINALS.json')
        and index['frozen_actor_source_sha256'] == X.ACTOR_SHA and index['frozen_transport_source_sha256'] == X.TRANSPORT_SHA,
        'original frozen Actor index binding differs')
    planned = named_originals(index['files'], [name+s for name in commands for s in W.SUFFIXES], path, actual)
    W.validate_files(plan, commands, planned, lease['nonce'], lease['boot_id'])
    q = L.verify_root_actor_originals(actual['ACTOR-ORIGINALS.json'], plan_raw, planned)
    C.need(set(q['files']) == set(actual)-FINAL_ACTOR_FILES, 'Actor envelope omitted original directory entries')
    for name, row in q['files'].items():
        original = terminal['actor_files'][name]
        data = planned[row['planned_file_key']] if 'planned_file_key' in row else base64.b64decode(row['raw_b64'], validate=True)
        C.need(data == actual[name] and row['source_path'] == original['path']
               and row['source_metadata'] == original['metadata'], 'Actor envelope is detached from actual original bytes/metadata')
    executions = prelude_commands(q, plan, lease, context.mapper, phone, guards, actual, path)
    executions += [(name, commands[name], planned) for name in plan['execution_order']]
    if plan['phase'] == 'setup' and lease['case_id'] == 'NEG-02':
        final, _, _ = K.public_state(planned['public'], plan['operation_id'], phone, guards)
        prelude = q['fixture_prelude']
        C.need(final[K.INPUT]['focused'] == 'true' and final[K.INPUT]['text'] == prelude['expected_final_input_text']
               and final[K.RECEIPT]['text'] == '等待输入' and final[K.READBACK] == prelude['initial_public_state'][K.READBACK],
               'independent original NEG02 final setup readback differs')
    if plan['phase'] == 'setup' and lease['case_id'] == 'NEG-01':
        guards.verify_app_open(C.strict(planned['open']), plan['operation_id'], context.mapper.apps['视觉挑战']['component'])
    if plan['phase'] == 'before-guard' and lease['case_id'] == 'NEG-01':
        guards.verify_app_open(C.strict(planned['disturbance']), C.sha((plan['operation_id']+':open').encode())[:32], context.mapper.apps['Unicode验证']['component'])
    fixtures, wires = verify_wire_census(actual, path, executions, q, plan, lease, files, terminal)
    result = {'state':'ROOT_FIXTURE_ORIGINALS_RETAINED_NOT_PUBLISHED', 'phase':plan['phase'],
        'original_index':{'path':str(path/'ORIGINAL-INDEX.json'), **C.descriptor(actual['ORIGINAL-INDEX.json'])},
        'component_qualified':False, 'native_worker_qualification':False, 'model_requests':0,
        'automatic_retry':False, 'phone_stage_retained':'/data/local/tmp/hepta-native-guard-'+lease['nonce']}
    C.need(C.strict(actual['RESULT.json']) == result
           and originals.pinned(terminal['stdout']) == actual['RESULT.json']
           and originals.pinned(terminal['stderr']) == b'', 'original child return/output does not establish complete fixture originals')
    return {'status':'complete', 'plan_raw':plan_raw, 'planned_files':planned,
        'actor_originals_raw':actual['ACTOR-ORIGINALS.json'], 'fixture_originals':fixtures,
        'evidence_summary':{'phase':plan['phase'], 'parent_wait_returncode':0, 'actor_files':len(actual),
            'actual_command_count':len(executions), 'actual_wire_count':wires,
            'original_scope_fences_verified':True, 'native_worker_qualification':False, 'business_qualified':False}}


def verify_attempts(originals, attempts, files, lease, scope, *, expected_package_sha256):
    C.scope(scope)
    C.need(isinstance(lease['nonce'], str) and re.fullmatch('[0-9a-f]{32}', lease['nonce'])
           and lease['case_id'] in ('NEG-01','NEG-02') and lease['package_sha256'] == expected_package_sha256,
           'actual Root attempt lease identity differs')
    C.need(isinstance(attempts, list) and len(attempts) <= 3 and all(isinstance(row, dict)
           and set(row) == {'phase','terminal'} and row['phase'] in PHASES for row in attempts),
           'explicit bounded actual Root attempts required')
    phases = [row['phase'] for row in attempts]
    C.need(phases == sorted(set(phases), key=PHASES.index), 'Root attempts repeat or are out of order')
    root = remember_directory(originals, FIXTURE_PARENTS/lease['nonce'])
    if root['kind'] == 'absent':
        C.need(not attempts, 'declared parent attempts have no actual namespace')
        phone_fixture_absent(files, lease, scope); return {}
    C.need(set(root['names']) == set(phases), 'actual Root parent attempt census differs; omitted/inflight attempt')
    if not attempts:
        phone_fixture_absent(files, lease, scope); return {}
    modules = source_modules(originals, files, expected_package_sha256)
    context, phone, guards = phase_context(files, lease, scope, modules); result = {}
    for attempt in attempts:
        phase = attempt['phase']; plan_raw = files['home/ROOT-'+phase.upper()+'-PLAN.json']
        plan, commands = actual_plan(plan_raw, phase, context, guards)
        terminal = parent_terminal(originals, attempt['terminal'], phase, files, lease, scope,
                                   expected_package_sha256, plan_raw, context)
        actual = actor_files(originals, terminal)
        if terminal['child_returncode'] != 0:
            C.need(actual is None, 'failed child left Actor originals; Root effects remain unknown')
            phone_fixture_absent(files, lease, scope)
            result[phase] = {'status':'joined_no_ui_effect', 'plan_raw':plan_raw, 'planned_files':{},
                'actor_originals_raw':None, 'fixture_originals':{}, 'evidence_summary':{
                    'phase':phase, 'parent_wait_returncode':terminal['child_returncode'], 'actor_output_absent':True,
                    'phone_fixture_absent':True, 'native_worker_qualification':False, 'business_qualified':False}}
        else:
            C.need(actual is not None, 'child zero exit lacks actual complete Actor originals')
            result[phase] = complete_actor(originals, terminal, actual, files, lease, scope,
                                          plan_raw, plan, commands, context, phone, guards)
    recheck_directories(originals)
    return result
