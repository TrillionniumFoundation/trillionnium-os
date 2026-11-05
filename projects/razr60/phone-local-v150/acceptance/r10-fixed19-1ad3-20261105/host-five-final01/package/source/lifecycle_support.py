#!/usr/bin/env python3
"""Owned local fixture processes and exact current R10 source inputs, inside bwrap.

Only the five formal host lifecycle cases use this module. No phone transport,
native task, service policy, real credential or inference process is reachable.
"""
import hashlib
import base64
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import threading
import time
import types

sys.dont_write_bytecode = True
SUITE = Path('/suite')
SOURCE = SUITE/'provider/source'
WORK = Path('/work')
HARNESS = Path('/harness')
CLIENT = Path('/var/lib/trillionnium/owner-open/phone-local-v150/tool_client_r6.py')
CLIENT_SHA = '500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f'
CONFIG_SHA = '780754928709871d3e70f432acb6a021c6c97ab822aaf7c32c887c132cac8c34'
SERVICE_SHA = '2739a0af53650363e065bb71a448481998c68fc8b8632e61262c319dae6b586a'
PROTOCOL_SHA = 'c573959e59fd9fbe7a850d6d2d6d747e3135718493f15de4a8acde850bad93b0'
CAPTURE_SHA = '0374a8858a26114a6184e2e40949e33dbb9b0014117ce4637b55b72e7629a5bd'
IDS = ('NEG-04', 'NEG-05', 'NEG-07', 'NEG-08', 'NEG-09')
SEAL_SHA = COMBO_SHA = COMBO_CANONICAL = INPUT_SHA = None
DAILY = OPENAI = SERVER_SHA = None
OWNED = []
CAPTURE = None
SUITE_DEADLINE = None
PRODUCTION_PINS = {'action_ledger.py': '50620b2e27334b7cf311bd6b1c743d71c19c32887e5ed31a07fdf54dac0e7907', 'daily_phone_local.py': 'f42fa1f3268d2a2c00e49610d356b440d1e32722fbe2af877580fb6eb180f712', 'health_contracts.py': '00adea791c00eaac52f65716cb158ee73f38bdded96f1718578ec92f5091d32d', 'ledger_round_evidence.py': '87d2b8731883dd06806a45851867332c568fe02deb2b9b8952094b86822e678d', 'model_health.py': '105b401fbab1c151e890a3e6e4774322eb62a9e7799744b4d3cef01b6e1c0f80', 'model_slot_cleanup.py': '9144bc864e245d63186f6b37760562e3b42554fdcc42ed792c9081761f315183', 'phone_local_http_worker.py': 'a1f1c94f2e78ced93cbde2113f508d756507249133f71c6dbe9a82a58a232d4d', 'phone_local_tools.py': '0302a8bac9dac18234c9493aa512e1efcf43d7cc5eaab884882dad42c2182c54', 'phone_observation_tools.py': 'f16c77c1b4509babcea5fc2e8d0a7ae8ab43b3cd58e6640441b44ecd4bccb6df', 'phone_task_guards.py': '87d88e0e9f93b31cf69bf0e4cdb9c62fd20e03c2192a0ffec621eb84c26bba86', 'provider_codex_host.py': 'cbdeaaf819ef2fa2d67d3d9707dae86eac6303d6caa4bf194b37cd0816177039', 'provider_openai_compatible.py': '337c83284fece94c0dd477a30029c63017b7eb00aab55a747b89b193823820bc', 'provider_phone_local.py': '082b02a473dc4d75d46a895895b64b96cf25ae24fc61795cb292fc70fd8d9ad6', 'retirement_recovery.py': 'c1f5a77e32264f5f638f62f005f57c66fffeb60cf288ad036848ac4fceb74827', 'task_postconditions.py': 'd4984cce3e25609d0bc3ef97475edfe74d4795244722e654eb654df3b6e6ceb3'}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def strict(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def bounded(path, limit=4*1024*1024):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, 'canonical original required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
            'bounded regular original required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(limit+1)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(len(raw) == before.st_size and all(getattr(before, key) == getattr(os.fstat(fd), key)
            == getattr(path.lstat(), key) for key in fields), 'original changed during read')
        return raw
    finally:
        os.close(fd)


def raw_write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    need(bounded(path) == raw, 'new retained original differs')
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def write(path, value):
    return raw_write(path, (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)+'\n').encode())


def read(path):
    return strict(bounded(path))


def pinned(path, digest):
    raw = bounded(path)
    need(sha(raw) == digest, 'original pin differs: '+str(path))
    return raw


def mkdir(path):
    path.mkdir(mode=0o700)
    return path


def proc(pid):
    try:
        raw = (Path('/proc')/str(pid)/'stat').read_bytes()
    except (FileNotFoundError, ProcessLookupError):
        return None
    pos = raw.rfind(b')')
    need(pos > 0, 'malformed proc identity')
    tail = raw[pos+2:].split()
    need(len(tail) > 19, 'short proc identity')
    return {'pid': int(raw.split(b' ', 1)[0]), 'ppid': int(tail[1]), 'pgid': int(tail[2]),
        'sid': int(tail[3]), 'start_ticks': int(tail[19])}


def census(group):
    need(type(group) is int and group > 1 and group != os.getpgrp(), 'owned foreign group required')
    members = []
    for path in Path('/proc').iterdir():
        if path.name.isdigit():
            row = proc(int(path.name))
            if row and (row['pgid'] == group or row['sid'] == group):
                members.append(row)
    try:
        os.killpg(group, 0)
        kernel = 'exists'
    except ProcessLookupError:
        kernel = 'ESRCH'
    return {'group': group, 'members': members, 'kernel': kernel}


def proc_original(pid):
    need(type(pid) is int and pid > 1, 'live original process required')
    raw = (Path('/proc')/str(pid)/'stat').read_bytes()
    need(0 < len(raw) <= 4096, 'proc stat bound')
    tail = raw[raw.rfind(b')')+2:].split()
    observed = {'pid': int(raw.split(b' ', 1)[0]), 'ppid': int(tail[1]),
        'pgid': int(tail[2]), 'sid': int(tail[3]), 'start_ticks': int(tail[19])}
    need(observed == proc(pid), 'original process changed at phase fence')
    return {'identity': observed, 'stat_base64': base64.b64encode(raw).decode(),
        'stat_sha256': sha(raw), 'observed_monotonic': time.monotonic()}


def resources():
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {'monotonic': time.monotonic(), 'fd_count': len(list(Path('/proc/self/fd').iterdir())),
        'thread_count': threading.active_count(), 'cpu_user': own.ru_utime, 'cpu_system': own.ru_stime,
        'children_cpu_user': children.ru_utime, 'children_cpu_system': children.ru_stime,
        'maxrss_lifetime_KiB': own.ru_maxrss, 'maxrss_is_case_peak': False,
        'available_bytes': os.statvfs(WORK).f_bavail*os.statvfs(WORK).f_frsize}


def wait_file(path, deadline, process=None):
    while time.monotonic() < deadline:
        if path.is_file():
            try:
                return read(path)
            except json.JSONDecodeError:
                pass
        if process is not None and process.p.poll() is not None:
            raise RuntimeError('original process exited before '+str(path))
        time.sleep(.01)
    raise TimeoutError('original file deadline '+str(path))


def load_capture():
    global CAPTURE
    if CAPTURE is None:
        raw = pinned(HARNESS/'host_capture_transport.py', CAPTURE_SHA)
        module = types.ModuleType('exact_reviewed_host_capture_transport')
        module.__file__ = str(HARNESS/'host_capture_transport.py')
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
        CAPTURE = module
    return CAPTURE


class Owned:
    """Original child handle plus exact 0374 capture; signals only a verified owned group."""
    def __init__(self, label, argv, root):
        self.label, self.root, self.argv = label, root, argv
        self.signals = []
        self.joined = False
        self.result = None
        self.p = self.identity = None
        capture = load_capture()
        self.capture = capture.Chain.__new__(capture.Chain)
        self.capture.out, self.capture.steps = root, []
        OWNED.append(self)
        remaining = 90 if SUITE_DEADLINE is None else SUITE_DEADLINE-time.monotonic()
        need(remaining > 0, 'suite deadline exhausted before spawn')
        try:
            self.p, self.phase, self.stdout, self.stderr = self.capture.execute_process(
                label, argv, remaining, async_start=True)
            self.identity = proc(self.p.pid)
            need(self.identity is not None and self.identity['pid'] == self.identity['pgid']
                == self.identity['sid'] == self.p.pid and self.identity['ppid'] == os.getpid()
                and self.p.pid > 1 and self.p.pid != os.getpgrp(), 'owned spawn identity unavailable')
            write(root/(label+'-SPAWN.json'), {'argv': argv, 'pid': self.p.pid,
                'observed_identity': self.identity, 'monotonic': time.monotonic(),
                'synthetic_host_namespace': True, 'capture_transport_sha256': CAPTURE_SHA})
        except BaseException:
            if self.p is None:
                self.p = self.capture.__dict__.get('_owned_host_children', {}).get(label)
            self.capture.close_owned_host_outputs()
            raise

    def signal(self, number):
        if self.p is None or self.p.poll() is not None:
            return
        current = proc(self.p.pid)
        need(number in (signal.SIGTERM, signal.SIGKILL) and self.identity is not None
            and current == self.identity and current['pid'] == current['pgid'] == current['sid']
            and current['ppid'] == os.getpid() and current['pid'] > 1
            and current['pid'] != os.getpgrp(), 'owned identity lost; no signal')
        row = {'signal': number, 'identity': current, 'monotonic': time.monotonic()}
        write(self.root/(self.label+'-SIGNAL-'+str(len(self.signals)+1)+'.json'), row)
        os.killpg(self.p.pid, number)
        self.signals.append(row)

    def join(self, timeout=5, stop=False):
        if self.joined:
            return self.result
        need(self.p is not None, 'spawn never produced an owned handle')
        if stop:
            self.signal(signal.SIGTERM)
        try:
            rc = self.capture.join_host_capture(self.label, self.p, maximum_wait=timeout)
        except BaseException as error:
            # Bounded owned cleanup is separate from capture/phase qualification.
            if isinstance(error, subprocess.TimeoutExpired) and self.p.poll() is None:
                self.signal(signal.SIGKILL)
                self.p.wait(timeout=2)
            self.capture.close_owned_host_outputs()
            raise
        self.stdout.close()
        self.stderr.close()
        self.capture.verify_host_capture_outputs(self.label)
        outputs = {}
        for name in ('stdout', 'stderr'):
            original = self.phase/(name+'.original')
            body = bounded(original)
            outputs[name] = {'captured_original': {'path': str(original), 'bytes': len(body), 'sha256': sha(body)},
                'compatibility_copy': raw_write(self.root/(self.label+'.'+name), body)}
        for name in ('_owned_host_streams', '_owned_host_children', '_owned_host_deadlines', '_owned_host_captures'):
            self.capture.__dict__[name].pop(self.label, None)
        self.result = {'pid': self.p.pid, 'original_identity': self.identity, 'returncode': rc,
            'actual_direct_child_wait_returned': True, 'signals': self.signals,
            'group_after': census(self.p.pid), 'monotonic': time.monotonic(),
            'both_output_eof_and_capture_worker_joined': True, 'outputs': outputs,
            'capture_transport_sha256': CAPTURE_SHA}
        write(self.root/(self.label+'-JOIN.json'), self.result)
        self.joined = True
        return self.result


class Evidence:
    def __init__(self, case_id):
        self.path = mkdir(WORK/case_id)
        self.checks, self.observations = [], []

    def check(self, name, value):
        self.checks.append({'name': name, 'passed': value is True})
        if value is not True:
            raise AssertionError(name)


def no_members(evidence, label, result):
    evidence.check(label+' actual wait and group absence', result['actual_direct_child_wait_returned'] is True
        and result['group_after']['members'] == [] and result['group_after']['kernel'] == 'ESRCH'
        and result['both_output_eof_and_capture_worker_joined'] is True)


def verify():
    global SEAL_SHA, COMBO_SHA, COMBO_CANONICAL, INPUT_SHA
    envelope = read(WORK/'OUTER-ENV.json')
    raw = pinned(SUITE/'INPUT-MANIFEST.json', envelope['input_manifest_sha256'])
    manifest = strict(raw)
    need(manifest['schema'] == 'hepta.fixed19.r10.host-lifecycle-inputs.v1'
        and manifest['state'] == 'EXACT_CURRENT_SOURCE_MATERIAL_FOR_ISOLATED_HOST_ONLY'
        and manifest['phone_calls'] == 0 and manifest['physical_case_pass'] is False
        and manifest['deployment_source_seal_sha256'] is None,
        'explicit host-only current material input manifest required')
    need(PRODUCTION_PINS is not None and len(PRODUCTION_PINS) == 15, 'fixed current production15 required')
    source_rows = read(SUITE/'SOURCE-PINS.json')
    need(set(source_rows) == set(PRODUCTION_PINS)
        and all(row['sha256'] == PRODUCTION_PINS[name] for name, row in source_rows.items()),
        'current production source inventory differs')
    for name, row in source_rows.items():
        body = pinned(SOURCE/name, row['sha256'])
        need(len(body) == row['bytes'], 'current source size differs')
    names = set()
    for row in manifest['files']:
        path = Path(row['path'])
        need(not path.is_absolute() and str(path) == row['path'] and '..' not in path.parts
            and row['path'] not in names, 'input inventory member differs')
        names.add(row['path'])
        need(len(pinned(SUITE/path, row['sha256'])) == row['bytes'], 'input original size differs')
    observed = {str(path.relative_to(SUITE)) for path in SUITE.rglob('*') if path.is_file()}
    need(observed == names | {'INPUT-MANIFEST.json'}, 'extra or missing input original')
    for path in SUITE.rglob('*'):
        need(not path.is_symlink(), 'input symlink rejected')
    pinned(SUITE/'production-config.json', CONFIG_SHA)
    pinned(SUITE/'production-service.json', SERVICE_SHA)
    pinned(CLIENT, CLIENT_SHA)
    pinned(HARNESS/'fixture_server.py', SERVER_SHA)
    protocol = strict(pinned(SUITE/'original-protocol.json', PROTOCOL_SHA))
    cases = [case for case in protocol['cases'] if case['id'] in IDS]
    need(protocol['case_count'] == 19 and len(cases) == 5
        and all(case['layer'] == 'host_isolated' and case['required_qualification_layers']
            == ['host_isolated', 'physical_native_task'] for case in cases), 'original five two-layer contracts differ')
    generation = manifest['host_material_generation']
    SEAL_SHA = generation['host_source_seal_sha256']
    COMBO_SHA = generation['host_material_combination_sha256']
    pinned(SUITE/'provider/SOURCE-SEAL.json', SEAL_SHA)
    combo = strict(pinned(SUITE/'combination.json', COMBO_SHA))
    COMBO_CANONICAL = sha(canonical(combo))
    INPUT_SHA = sha(raw)
    need(generation['host_material_combination_canonical_sha256'] == COMBO_CANONICAL,
        'host material combination canonical identity differs')
    return protocol
