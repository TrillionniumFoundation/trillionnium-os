#!/usr/bin/env python3
"""Exact final-15 NEG14 host controls in a fresh bwrap namespace.

No production source is changed.  The actual daily CLI and its normal config,
client-byte and fourteen-parent checks run.  No connection is admitted and no
model/phone request is made.  Every spawned process belongs to this invocation.
"""
import argparse
import errno
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import resource
import secrets
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import traceback

sys.dont_write_bytecode = True
PINS_SHA = 'f79991e29ddf5aa5c282a73b3b4a34b50a741f2e7c590b8e6db72d877002bb26'
CLIENT = '/var/lib/trillionnium/owner-open/phone-local-v150/tool_client_r6.py'
OWNED = []


def need(value, message):
    if not value:
        raise AssertionError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + '\n').encode()


def write(path, value):
    raw = encode(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    need(path.read_bytes() == raw, 'complete host evidence readback')
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def full9(info):
    return [getattr(info, name) for name in (
        'st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
        'st_size', 'st_mtime_ns', 'st_ctime_ns')]


def original(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_size <= 4 * 1024 * 1024, 'bounded regular host original')
        chunks = []
        while True:
            raw = os.read(fd, 65536)
            if not raw:
                break
            chunks.append(raw)
        raw = b''.join(chunks)
        need(full9(before) == full9(os.fstat(fd)) == full9(path.lstat())
             and len(raw) == before.st_size, 'host original changed while read')
        return raw, {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw),
                     'full9': full9(before)}
    finally:
        os.close(fd)


def inputs(root):
    raw, unused = original(root / 'PINS.json')
    need(sha(raw) == PINS_SHA, 'exact final source input manifest')
    pins = json.loads(raw)
    rows = []
    for row in pins['files']:
        raw, observed = original(root / row['path'])
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'final source bytes differ')
        rows.append({'path': row['path'], 'bytes': len(raw), 'sha256': sha(raw)})
    need(len(rows) == 17 and sum(r['path'].startswith('provider/source/') for r in rows) == 15,
         'complete production fifteen plus config and exact client')
    return rows


def proc(pid):
    path = Path('/proc') / str(pid)
    try:
        raw = (path / 'stat').read_bytes()
    except (FileNotFoundError, ProcessLookupError):
        return None
    tail = raw[raw.rfind(b')') + 2:].split()
    return {'pid': pid, 'ppid': int(tail[1]), 'pgid': int(tail[2]),
            'sid': int(tail[3]), 'start_ticks': int(tail[19]), 'raw_stat': raw.decode()}


def identity(value):
    return None if value is None else {k: value[k] for k in ('pid', 'ppid', 'pgid', 'sid', 'start_ticks')}


def group(group_id):
    members = []
    for item in Path('/proc').iterdir():
        if item.name.isdigit():
            observed = proc(int(item.name))
            if observed and (observed['pgid'] == group_id or observed['sid'] == group_id):
                members.append(observed)
    try:
        os.killpg(group_id, 0)
        kernel = 'exists'
    except ProcessLookupError:
        kernel = 'ESRCH'
    return {'pgid': group_id, 'members': members, 'kernel': kernel}


def resources():
    fds = {}
    for name in os.listdir('/proc/self/fd'):
        try:
            info = os.fstat(int(name))
            fds[name] = [info.st_dev, info.st_ino, info.st_mode, os.readlink('/proc/self/fd/' + name)]
        except FileNotFoundError:
            continue
        except OSError as error:
            if error.errno == errno.EBADF:
                continue
            raise
    child = resource.getrusage(resource.RUSAGE_CHILDREN)
    self_usage = resource.getrusage(resource.RUSAGE_SELF)
    return {'fds': fds, 'threads': [(t.name, t.ident, t.is_alive()) for t in threading.enumerate()],
            'child_user_seconds': child.ru_utime, 'child_system_seconds': child.ru_stime,
            'maxrss_lifetime_KiB': self_usage.ru_maxrss,
            'raw_proc_status': Path('/proc/self/status').read_text(),
            'rss_return_to_baseline_claimed': False}


class Owned:
    def __init__(self, label, argv, output):
        self.output, self.label, self.argv = output, label, argv
        self.stdout = (output / (label + '.stdout')).open('xb')
        self.stderr = (output / (label + '.stderr')).open('xb')
        self.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=self.stdout,
                                        stderr=self.stderr, start_new_session=True)
        self.pidfd = os.pidfd_open(self.process.pid, 0)
        self.initial = proc(self.process.pid)
        need(self.initial is not None and self.initial['pid'] == self.initial['pgid'] == self.initial['sid'],
             'new owned direct child exact session identity')
        self.signals, self.joined = [], False
        OWNED.append(self)
        write(output / (label + '-SPAWN.json'), {'argv': argv, 'original': self.initial,
              'pidfd_acquired': True, 'monotonic': time.monotonic(), 'this_invocation_owned': True})

    def sample(self, name):
        observed = proc(self.process.pid)
        need(identity(observed) == identity(self.initial), 'owned process identity changed')
        write(self.output / (self.label + '-' + name + '.json'), {'original': observed,
              'raw_status': (Path('/proc') / str(self.process.pid) / 'status').read_text(),
              'monotonic': time.monotonic()})

    def signal_owned(self, number):
        if self.process.poll() is not None:
            return
        need(identity(proc(self.process.pid)) == identity(self.initial), 'no signal after identity change')
        need(not select.select([self.pidfd], [], [], 0)[0], 'no signal after owned pidfd terminal')
        signal.pidfd_send_signal(self.pidfd, number)
        self.signals.append({'signal': number, 'identity': identity(self.initial),
                             'via': 'pidfd_send_signal', 'monotonic': time.monotonic()})

    def join(self, timeout=8):
        if self.joined:
            return self.result
        timed_out = False
        try:
            rc = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self.signal_owned(signal.SIGTERM)
            try:
                rc = self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.signal_owned(signal.SIGKILL)
                rc = self.process.wait(timeout=2)
        need(bool(select.select([self.pidfd], [], [], 0)[0]), 'original pidfd confirms termination')
        os.close(self.pidfd)
        self.stdout.close()
        self.stderr.close()
        self.joined = True
        remaining = group(self.process.pid)
        need(remaining['members'] == [] and remaining['kernel'] == 'ESRCH', 'owned child group not absent')
        self.result = {'returncode': rc, 'original_identity': self.initial, 'actual_direct_child_wait': True,
                       'pidfd_terminal': True, 'timed_out': timed_out, 'signals': self.signals,
                       'group_after': remaining, 'monotonic': time.monotonic()}
        write(self.output / (self.label + '-JOIN.json'), self.result)
        return self.result


def mkdir(path):
    path.mkdir(mode=0o700)
    return path


def waits(predicate, child, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        need(child.process.poll() is None, 'owned daily exited before required observation')
        time.sleep(.01)
    raise TimeoutError('bounded owned observation expired')


def fixture(root, label, DAILY):
    case = mkdir(root / label)
    state = mkdir(case / 'state')
    evidence = mkdir(state / 'evidence')
    mkdir(evidence / 'claims')
    config = json.loads((Path('/suite') / 'production-config.original.json').read_bytes())
    key = case / 'synthetic-only-api.key'
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as handle:
        handle.write(secrets.token_hex(24) + '\n')
    config.update(endpoint='http://127.0.0.1:18099/v1/chat/completions', api_key_file=str(key),
                  model='synthetic-capacity-no-real-inference')
    write(case / 'config.json', config)
    ident = {n: 'synthetic-neg14-' + secrets.token_hex(12) for n in DAILY.IDENTITY}
    seed = [{'identity': ident, 'origin_receipt_sha256': sha(encode({'synthetic': True, 'identity': ident}))}]
    seed_row = write(case / 'retained.json', seed)
    args = argparse.Namespace(evidence=evidence, retained_claims=case / 'retained.json',
                              retained_claims_sha256=seed_row['sha256'])
    DAILY.seed_retained_claims(args)
    claims = {p.name: original(p) for p in (evidence / 'claims').iterdir()}
    need(len(claims) == 1, 'exact one synthetic retained claim')
    write(case / 'FIXTURE-DECLARATION.json', {
        'all_request_and_owner_identities_synthetic': True, 'actual_inference_location': 'no inference',
        'phone_literal_in_config_is_schema_compatibility_only': True,
        'changed_config_fields': ['endpoint', 'api_key_file', 'model'],
        'no_original_config_or_source_changes': True, 'validate_executor_called_normally': True,
        'synthetic_key_content_and_digest_omitted': True, 'model_requests': 0, 'phone_calls': 0})
    return case, state, evidence, seed_row, claims


def child_argv(case, state, seed, port, maximum):
    return ['/usr/bin/python3', '-I', '-B', '/suite/provider/source/daily_phone_local.py',
            '--state', str(state), '--config', str(case / 'config.json'), '--port', str(port),
            '--workers', '1', '--timeout', '1', '--retained-claims', str(case / 'retained.json'),
            '--retained-claims-sha256', seed['sha256'], '--max-evidence-bytes', str(maximum)]


def no_consumption(state, evidence, claims):
    after = {p.name: original(p) for p in (evidence / 'claims').iterdir()}
    need(after == claims, 'retained claim bytes/full9 changed or extra claim consumed')
    forbidden = []
    for pattern in ('dispatch-*.json', 'semantic-*.json', 'local-*.spawned.json',
                    'codex-*.spawned.json', 'provider-out.jsonl', 'provider-in.jsonl', 'terminal.json'):
        forbidden += list(state.rglob(pattern))
    need(not forbidden, 'no accepted connection, worker or typed dispatch expected')
    bindings = state / 'task-contracts' / 'bindings'
    need(not bindings.exists() or not list(bindings.iterdir()), 'no task template consumed')
    return {'retained_claim_count': len(claims), 'retained_claim_bytes_and_full9_unchanged': True,
            'extra_claims': 0, 'task_template_bindings': 0, 'dispatch_records': 0,
            'worker_spawned_records': 0, 'provider_connections': 0, 'model_requests': 0, 'phone_calls': 0}


def lock_released(state):
    fd = os.open(state / 'daemon.lock', os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def archive_owned(root, output):
    archive = mkdir(output / 'originals')
    rows, excluded = [], []
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        rel = str(path.relative_to(root))
        if path.name == 'synthetic-only-api.key':
            excluded.append({'path': rel, 'reason': 'synthetic credential; no content or digest retained'})
            continue
        if path.name == 'capacity.logical-budget':
            excluded.append({'path': rel, 'reason': 'logical byte-budget input is ftruncate size, not file contents',
                             'full9': full9(info), 'allocated_bytes': info.st_blocks * 512})
            continue
        raw, observed = original(path)
        dest = archive / rel
        dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with dest.open('xb') as handle:
            handle.write(raw)
        need(dest.read_bytes() == raw, 'complete case original preservation')
        rows.append({'archive': 'originals/' + rel, 'source': observed})
    write(output / 'ORIGINALS.json', {'files': rows, 'excluded': excluded})
    return rows


def inside():
    output = Path('/work')
    outer = json.loads((output / 'OUTER-ENV.json').read_bytes())
    namespaces = {n: os.readlink('/proc/self/ns/' + n) for n in ('net', 'mnt', 'pid')}
    need(all(namespaces[n] != outer['namespaces'][n] for n in namespaces), 'all original unshare boundaries required')
    need(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'owned host pidfd support required')
    source_before = inputs(Path('/suite'))
    sys.path.insert(0, '/suite/provider/source')
    DAILY = importlib.import_module('daily_phone_local')
    imported = []
    for row in source_before:
        if row['path'].startswith('provider/source/'):
            module = importlib.import_module(Path(row['path']).stem)
            need(Path(module.__file__) == Path('/suite') / row['path'], 'full current source module location')
            need(sha(Path(module.__file__).read_bytes()) == row['sha256'], 'full imported source byte pin')
            imported.append(row)
    need(len(imported) == 15 and len(DAILY.PARENTS) == 14, 'full fifteen plus daily fourteen pins')
    before = resources()
    work = mkdir(output / 'owned-tests')
    work_identity = full9(work.lstat())[:2]
    checks, fatal, blocked = [], None, None
    started = time.monotonic()
    try:
        blocked = mkdir(work / 'unreadable')
        secret = blocked / 'evidence.json'
        write(secret, {'synthetic': True, 'kernel_permission_fixture': True})
        raw_before, stat_before = original(secret)
        os.chmod(blocked, 0)
        errors = []
        for name, call in [
            ('actual_lstat_EACCES', lambda: DAILY.evidence_item_size(secret, work)),
            ('actual_scandir_EACCES', lambda: list(os.walk(blocked, onerror=DAILY.raise_evidence_scan_error)))]:
            try:
                call()
            except PermissionError as error:
                need(error.errno == errno.EACCES, 'actual kernel EACCES required')
                errors.append({'name': name, 'errno': error.errno, 'type': type(error).__name__,
                               'message': str(error), 'filename': error.filename})
            else:
                raise AssertionError(name + ' did not reject')
        os.chmod(blocked, 0o700)
        need(original(secret) == (raw_before, stat_before), 'unreadable original retained unchanged')
        checks.append({'name': 'real_kernel_EACCES_through_lstat_and_scanner', 'passed': True,
                       'errors': errors, 'synthetic_exception_injection': False})

        maximum = 1024 * DAILY.MAX_LINE
        reserve = 128 * DAILY.MAX_LINE
        threshold = maximum - reserve
        case, state, evidence, seed, claims = fixture(work, 'capacity', DAILY)
        run = mkdir(evidence / ('20261106-000000-' + secrets.token_hex(16)))
        sparse = run / 'capacity.logical-budget'
        retained_bytes = sum(len(v[0]) for v in claims.values())
        fd = os.open(sparse, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.ftruncate(fd, threshold - retained_bytes - 1)
            os.fsync(fd)
        finally:
            os.close(fd)
        initial_sparse = full9(sparse.lstat())
        write(case / 'PUBLIC-LIMIT.json', {'entry': 'daily_phone_local.main -> serve.capacity',
              'public_CLI_argument': '--max-evidence-bytes', 'selected_maximum': maximum,
              'minimum_allowed_by_original_CLI': maximum, 'MAX_LINE': DAILY.MAX_LINE,
              'workers': 1, 'reserved_bytes': reserve, 'first_rejected_total_bytes': threshold,
              'total_before': sparse.stat().st_size + retained_bytes,
              'sparse_allocated_bytes': sparse.stat().st_blocks * 512,
              'logical_budget_exhaustion': True, 'disk_ENOSPC_test': False,
              'production_evidence_filled': False, 'source_constants_modified': False})
        child = Owned('daily-capacity', child_argv(case, state, seed, 18103, maximum), case)
        waits(lambda: (state / 'ready.json').exists(), child)
        ready_before = json.loads((state / 'ready.json').read_bytes())
        need(ready_before.get('accepting') is True and ready_before['source_sha256'] == DAILY.sha(Path(DAILY.__file__)),
             'same actual daily source transport ready')
        # No socket connects.  Surviving multiple original accept timeouts proves
        # the below-limit capacity path did not immediately reject after ready.
        time.sleep(1.2)
        child.sample('BELOW-LIMIT')
        need(child.process.poll() is None and sparse.stat().st_size + retained_bytes == threshold - 1,
             'strictly below capacity remains live without a task')
        before_consumption = no_consumption(state, evidence, claims)
        write(case / 'BEFORE-BOUNDARY.json', {'ready': ready_before, 'consumption': before_consumption,
                                            'sparse_full9': initial_sparse, 'monotonic': time.monotonic()})
        fd = os.open(sparse, os.O_WRONLY | os.O_NOFOLLOW)
        try:
            need(full9(os.fstat(fd)) == initial_sparse, 'only exact owned sparse capacity input may change')
            os.ftruncate(fd, threshold - retained_bytes)
            os.fsync(fd)
        finally:
            os.close(fd)
        crossed = full9(sparse.lstat())
        write(case / 'BOUNDARY-EXHAUSTED.json', {'total_bytes': crossed[6] + retained_bytes,
              'first_rejected_total_bytes': threshold, 'sparse_full9': crossed,
              'sparse_allocated_bytes': sparse.stat().st_blocks * 512, 'monotonic': time.monotonic()})
        result = child.join()
        stderr = (case / 'daily-capacity.stderr').read_text()
        need(result['returncode'] != 0 and not result['timed_out'] and not result['signals']
             and sum(line.endswith('evidence capacity reached; retain claims and archive evidence manually')
                     for line in stderr.splitlines()) == 1,
             'first actual capacity rejection, no retry or helper stop')
        ready_after = json.loads((state / 'ready.json').read_bytes())
        need(ready_after['accepting'] is False and full9(sparse.lstat()) == crossed,
             'daemon stopped accepting and preserved exact capacity input')
        after_consumption = no_consumption(state, evidence, claims)
        lock_released(state)
        checks.append({'name': 'public_daily_logical_capacity_first_boundary_refusal', 'passed': True,
                       'below_limit': threshold - 1, 'first_rejected_total': threshold,
                       'maximum': maximum, 'retained_claims': after_consumption,
                       'direct_child_wait_and_group_absence': result, 'ownership_lock_reacquired': True,
                       'validate_executor_bypassed': False, 'no_client_or_model_started': True})

        case, state, evidence, seed, claims = fixture(work, 'orphan', DAILY)
        run = mkdir(evidence / ('20261106-000001-' + secrets.token_hex(16)))
        intent = run / 'local-01.spawn-intent.json'
        write(intent, {'synthetic': True, 'state': 'reserved_without_joined', 'no_actual_worker_exists': True})
        intent_before = original(intent)
        child = Owned('daily-orphan', child_argv(case, state, seed, 18102, maximum), case)
        result = child.join()
        stderr = (case / 'daily-orphan.stderr').read_text()
        need(result['returncode'] != 0 and not result['timed_out'] and not result['signals']
             and sum(line.endswith('unjoined prior inference-client round; inspect exact receipts before service restart')
                     for line in stderr.splitlines()) == 1,
             'retained orphan intent causes actual public startup refusal')
        need(original(intent) == intent_before and not (run / 'local-01.joined.json').exists()
             and not (state / 'ready.json').exists(), 'orphan original preserved, no forged join or ready')
        consumption = no_consumption(state, evidence, claims)
        lock_released(state)
        checks.append({'name': 'public_daily_orphan_spawn_receipt_refusal', 'passed': True,
                       'intent_bytes_and_full9_unchanged': True, 'consumption': consumption,
                       'direct_child_wait_and_group_absence': result, 'ownership_lock_reacquired': True,
                       'actual_worker_spawned_for_orphan_fixture': False})
    except BaseException as error:
        fatal = {'type': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()}
    finally:
        if blocked is not None and blocked.exists():
            os.chmod(blocked, 0o700)
        for child in OWNED:
            if not child.joined:
                child.signal_owned(signal.SIGTERM)
                child.join(timeout=3)
    archive_owned(work, output)
    need(full9(work.lstat())[:2] == work_identity, 'owned test root identity changed')
    shutil.rmtree(work)
    after = resources()
    restored = before['fds'] == after['fds'] and before['threads'] == after['threads']
    need(not work.exists(), 'owned temporary test tree removed')
    if restored:
        checks.append({'name': 'owned_child_groups_files_and_fd_thread_baseline', 'passed': True,
                       'children_waited': len(OWNED), 'all_owned_groups_ESRCH': True,
                       'owned_test_tree_removed': True, 'FD_and_thread_baseline_restored': True,
                       'RSS_return_claimed': False, 'child_CPU_return_claimed': False})
    need(inputs(Path('/suite')) == source_before, 'final fifteen input bytes changed')
    passed = fatal is None and len(checks) == 4 and restored
    result = {'schema': 'fc33.neg14.final15.actual-owned-host-controls.v1',
              'status': 'PASS_SELECTED_HOST_SCOPE' if passed else 'FAILED',
              'checks': checks, 'control_count': len(checks), 'fatal_error': fatal,
              'namespaces': namespaces, 'production_sources': imported, 'source_count': 15,
              'PINS_sha256': PINS_SHA, 'script_sha256': sha(Path(__file__).read_bytes()),
              'resources': {'before': before, 'after': after}, 'elapsed_seconds': time.monotonic() - started,
              'model_requests': 0, 'phone_calls': 0, 'native_dispatches': 0,
              'actual_BUILD': None, 'installed_tuple': None, 'whole_NEG14_qualified': False,
              'prior_selected13_count_not_added': True,
              'limits': ['Logical evidence byte budget is exhausted at the original public minimum; disk ENOSPC and 200000-file bounds are not forced.',
                         'Two actual isolated daily processes are waited and absent. No existing model/service/phone process is targeted.',
                         'Orphan input is an explicit synthetic retained spawn-intent with no real old worker.',
                         'FD/thread/owned process and directory cleanup are measured. Full installed runtime RSS/slot cleanup remain separate.',
                         'No private credential content or digest is preserved. Sparse capacity input is preserved as complete metadata, not 896 MiB of zeros.']}
    row = write(output / 'RESULT.json', result)
    print(json.dumps({'status': result['status'], 'controls': len(checks), 'result': row,
                      'phone_calls': 0, 'model_requests': 0}, sort_keys=True))
    return 0 if passed else 1


def outer(args):
    base = Path(__file__).resolve().parent
    need(sha(Path(__file__).read_bytes()) == args.self_sha256, 'exact reviewed host control source')
    initial = inputs(base / 'inputs')
    output = base / 'RUN01'
    output.mkdir(mode=0o700)
    write(output / 'OUTER-ENV.json', {'namespaces': {n: os.readlink('/proc/self/ns/' + n) for n in ('net', 'mnt', 'pid')},
          'pid': os.getpid(), 'uid': os.getuid(), 'gid': os.getgid(),
          'phone_calls': 0, 'model_requests': 0, 'production_changes': 0})
    argv = ['/usr/bin/bwrap', '--unshare-user', '--uid', '0', '--gid', '0', '--unshare-pid',
            '--unshare-net', '--unshare-ipc', '--unshare-uts', '--die-with-parent', '--new-session',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
            '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/sbin', '/sbin', '--proc', '/proc', '--dev', '/dev',
            '--tmpfs', '/tmp', '--dir', '/var/lib/trillionnium/owner-open/phone-local-v150',
            '--ro-bind', str(base / 'inputs'), '/suite', '--dir', '/harness',
            '--ro-bind', str(Path(__file__).resolve()), '/harness/run_owned_neg14.py',
            '--bind', str(output), '/work', '--ro-bind', str(base / 'inputs/client/tool_client_r6.py'), CLIENT,
            '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
            '--setenv', 'PYTHONDONTWRITEBYTECODE', '1', '--chdir', '/work', '--cap-drop', 'ALL', '--',
            '/usr/bin/python3', '-I', '-B', '/harness/run_owned_neg14.py', '--inside']
    write(output / 'EXECUTION-INTENT.json', {'argv': argv, 'source_sha256': args.self_sha256,
          'inputs_sha256': PINS_SHA, 'phone_calls': 0, 'model_requests': 0, 'namespace_free_fallback': False})
    before = resources()
    child = Owned('namespace', argv, output)
    result = child.join(timeout=35)
    after = resources()
    need(inputs(base / 'inputs') == initial, 'outer complete source originals changed')
    inner = json.loads((output / 'RESULT.json').read_bytes()) if (output / 'RESULT.json').is_file() else None
    restored = before['fds'] == after['fds'] and before['threads'] == after['threads']
    passed = result['returncode'] == 0 and not result['timed_out'] and not result['signals'] and restored
    passed = passed and inner is not None and inner['status'] == 'PASS_SELECTED_HOST_SCOPE'
    row = write(output / 'OUTER-RESULT.json', {'schema': 'fc33.neg14.final15.owned-namespace-result.v1',
          'status': 'PASS_SELECTED_HOST_SCOPE' if passed else 'FAILED', 'original_child': result,
          'original_namespace_argv': argv, 'resources': {'before': before, 'after': after},
          'FD_and_thread_baseline_restored': restored, 'complete_input_bytes_unchanged': True,
          'inner_result': None if inner is None else original(output / 'RESULT.json')[1],
          'phone_calls': 0, 'model_requests': 0, 'installed_tuple': None, 'actual_BUILD': None,
          'whole_NEG14_qualified': False, 'source_bodies_modified': False})
    print(json.dumps({'status': 'PASS_SELECTED_HOST_SCOPE' if passed else 'FAILED', 'result': row,
                      'inner_controls': None if inner is None else inner['control_count'],
                      'phone_calls': 0, 'model_requests': 0}, sort_keys=True))
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--execute-once', action='store_true')
    parser.add_argument('--self-sha256')
    args = parser.parse_args()
    os.umask(0o077)
    if args.inside:
        need(not args.execute_once and args.self_sha256 is None, 'exact inner mode')
        return inside()
    if not args.execute_once:
        print('review-only; no host child or namespace launched')
        return 0
    return outer(args)


if __name__ == '__main__':
    raise SystemExit(main())
