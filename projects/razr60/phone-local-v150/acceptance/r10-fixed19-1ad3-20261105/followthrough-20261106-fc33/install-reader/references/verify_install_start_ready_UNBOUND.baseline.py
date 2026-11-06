"""Read-only installation/start/READY execution-originals gate.

This module dispatches nothing. An actual BUILD, the exact three original actor
invocations, and their original outputs must all exist. Supervisor wait,
task closure, footprint closure, and rollback remain independent gates.
"""
import base64
import datetime
import hashlib
import json
import math
from pathlib import PurePosixPath
import re
import stat
import types

FROZEN_INPUTS = None
FROZEN_EXECUTION_PLAN = None
B = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
SOURCES = {
    'protocol': {'path': B + '/production-install-ready-source-a1055-20261106-01/source/install_ready_execution_protocol.py',
                 'bytes': 12331, 'sha256': '49d94d28156621358cd1a17844a16eb026a2f44b43a20f63336394e7b4895e35'},
    'release': {'path': B + '/production-release-owner-finalizer-a1055-r1/source/verify_final_release_inputs_v3.py',
                'bytes': 28483, 'sha256': 'e947a3b2de75a0820fcc3cb5cfe758f874cd85625cb11bac793b38256a670c43'},
    'exact8': {'path': B + '/fivefault-source-reconstruction-a1055-r2/source/verify_resident_output_bindings_bound02.py',
               'bytes': 29027, 'sha256': '24db28bee38671322b11ce4c2afd5dd47425381101dd85f887141f567811b490'},
}
SCHEMA = 'hepta.production.install-start-ready.original-inputs.v1'
BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
FINGERPRINT = 'motorola/leap_cn/leap:16/W1VL36H.59-53-11/643c83-3ed541:user/release-keys'
GNU = '/var/lib/trillionnium/owner-open/phone-local-v150'
OUT = GNU + '/root-install-v150-r10-r1'
PHASES = ('stage', 'start', 'ready')
HASH = re.compile('[0-9a-f]{64}')
MAX_INPUT = 4 * 1024 * 1024
MAX_ORIGINALS = 4096
MAX_TOTAL = 512 * 1024 * 1024
MAX_RESULT = 4 * 1024 * 1024
METADATA_FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                   'st_size', 'st_mtime_ns', 'st_ctime_ns')

def need(ok, message):
    if not ok:
        raise ValueError(message)

def exact(value, fields, message):
    need(type(value) is dict and set(value) == set(fields), message)
    return value

def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def strict(raw, maximum=MAX_INPUT):
    need(type(raw) is bytes and 0 < len(raw) <= maximum, 'bounded complete JSON original')
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate original JSON key')
            value[key] = item
        return value
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False) + '\n').encode()

def original_file_json(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()

def original_entry_stdout(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode()

def original_actor_json(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode()

def canonical_path(value):
    need(type(value) is str and value and not any(c in value for c in '\0\r\n\t'), 'plain original path')
    path = PurePosixPath(value)
    need(path.is_absolute() and str(path) == value and '..' not in path.parts, 'canonical absolute original path')
    return path

def descriptor(row, maximum=64 * 1024 * 1024, metadata=None):
    need(type(row) is dict and set(row) in ({'path', 'bytes', 'sha256'},
                                          {'path', 'bytes', 'sha256', 'metadata'}), 'exact3 or exact4 descriptor')
    canonical_path(row['path'])
    need(type(row['bytes']) is int and 0 <= row['bytes'] <= maximum
         and type(row['sha256']) is str and HASH.fullmatch(row['sha256']), 'finite complete original pin')
    if metadata is True:
        need('metadata' in row, 'original full9 required')
    if metadata is False:
        need('metadata' not in row, 'exact3 source descriptor required')
    if 'metadata' in row:
        check_metadata(row['metadata'], row['bytes'])
    return row

def check_metadata(value, size=None, *, root=False, mode=None):
    need(type(value) is list and len(value) == 9 and all(type(x) is int and x >= 0 for x in value),
         'complete typed full9 metadata')
    dev, ino, bits, uid, gid, links, length, mtime, ctime = value
    need(ino > 0 and links == 1 and stat.S_ISREG(bits), 'single-link regular original')
    if size is not None:
        need(length == size, 'full9 original byte count')
    if root:
        need(uid == gid == 0, 'phone original root ownership')
    if mode is not None:
        need(stat.S_IMODE(bits) == mode, 'phone original permission bits')
    return value

class Originals:
    """Explicit original namespace -> actual retained host full9, never a guessed alias."""
    def __init__(self, rows, read_pinned):
        need(type(rows) is list and 1 <= len(rows) <= MAX_ORIGINALS, 'finite complete explicit original map')
        self.callback = read_pinned
        self.mapping = {}
        self.observed = {}
        self.total = 0
        retained_paths = {}
        for row in rows:
            exact(row, ('namespace', 'original', 'retained'), 'explicit original/retained namespace mapping')
            need(row['namespace'] in ('host', 'pocket4', 'phone_gnu', 'phone_android'),
                 'declared original namespace')
            origin = descriptor(row['original'])
            retained = descriptor(row['retained'], metadata=True)
            need({k: origin[k] for k in ('bytes', 'sha256')} ==
                 {k: retained[k] for k in ('bytes', 'sha256')}, 'complete copied bytes must match original')
            key = encoded(origin)
            need(key not in self.mapping, 'duplicate original map row')
            if retained['path'] in retained_paths:
                need(retained_paths[retained['path']] == retained, 'conflicting retained inode/bytes')
            retained_paths[retained['path']] = retained
            self.mapping[key] = row
        need(sum(row['retained']['bytes'] for row in self.mapping.values()) <= MAX_TOTAL,
             'explicit original-map byte envelope; do not drop files to fit')

    def read(self, row, maximum=64 * 1024 * 1024):
        descriptor(row, maximum)
        key = encoded(row)
        need(key in self.mapping, 'undeclared original namespace or metadata')
        item = self.mapping[key]
        raw = self.callback(dict(item['retained']))
        need(type(raw) is bytes and pin(raw) == {k: row[k] for k in ('bytes', 'sha256')},
             'actual retained complete bytes differ')
        if key in self.observed:
            need(self.observed[key][1] == raw, 'original bytes changed across repeated read')
        else:
            self.total += len(raw)
            need(self.total <= MAX_TOTAL, 'complete read pool envelope')
            self.observed[key] = (item, raw)
        return raw

    def phone(self, row, expected_path, maximum=MAX_RESULT, mode=0o600):
        descriptor(row, maximum, metadata=True)
        need(row['path'] == expected_path, 'exact original phone output path')
        check_metadata(row['metadata'], row['bytes'], root=True, mode=mode)
        item = self.mapping.get(encoded(row))
        need(item and item['namespace'] == 'phone_gnu', 'GNU phone original is not a host pathname')
        return self.read(row, maximum)

    def p4(self, row, expected_path, maximum=MAX_RESULT, request=False):
        descriptor(row, maximum, metadata=True)
        need(row['path'] == expected_path, 'exact original P4 actor pathname')
        item = self.mapping.get(encoded(row))
        need(item and item['namespace'] == 'pocket4', 'P4 original is not a host pathname')
        if request:
            check_metadata(row['metadata'], row['bytes'], mode=0o600)
        return self.read(row, maximum)

    def recheck(self):
        for item, raw in list(self.observed.values()):
            again = self.callback(dict(item['retained']))
            need(type(again) is bytes and again == raw, 'complete retained full9/byte bookend differs')

def reviewed(raw, row, name):
    need(pin(raw) == {k: row[k] for k in ('bytes', 'sha256')}, 'reviewed complete source pin')
    module = types.ModuleType(name)
    module.__file__ = row['path']
    exec(compile(raw, row['path'], 'exec'), module.__dict__)
    return module

def tool_value(raw):
    value = strict(raw, MAX_RESULT)
    need(type(value) is dict and value.get('isError') is False, 'original controller tool envelope required')
    texts = [x['text'] for x in value.get('content', []) if type(x) is dict and x.get('type') == 'text']
    need(len(texts) == 1, 'one exact original tool payload')
    return strict(texts[0].encode(), MAX_RESULT)

def original_stream(row, name, status):
    exact(row, ('bytes_hex', 'eof', 'next_offset', 'offset', 'size', 'text'), 'complete original process stream')
    need(type(row['bytes_hex']) is str and len(row['bytes_hex']) <= 32768, 'single original actor summary page')
    raw = bytes.fromhex(row['bytes_hex'])
    need(row['offset'] == 0 and row['eof'] is True and type(row['size']) is int
         and row['next_offset'] == row['size'] == len(raw) and type(row['text']) is str
         and row['text'].encode() == raw, 'actual original output full bytes and EOF')
    need(status['log_bytes'][name] == {'seen': len(raw), 'stored': len(raw)}
         and status['log_synced'][name] is True, 'controller original durable stream counts')
    return raw

def verify_process(records, expected, pool):
    exact(records, ('dispatch', 'start', 'status', 'read'), 'original dispatch and three controller receipts')
    dispatch = strict(pool.read(records['dispatch'], 65536), 65536)
    need(dispatch == expected['dispatch'], 'actual submitted argv/cwd/key differ from independently derived command')
    started = tool_value(pool.read(records['start'], MAX_RESULT))
    status = tool_value(pool.read(records['status'], MAX_RESULT))
    outputs = tool_value(pool.read(records['read'], MAX_RESULT))
    job = started['job']
    for key in ('host', 'executable', 'args', 'cwd', 'idempotency_key'):
        need(job[key] == dispatch[key], 'original controller invocation differs: ' + key)
    need(job['launch_state'] == 'launched' and job['launch_error'] is None
         and started['reused'] is False and started.get('retried_launch', False) is False
         and job.get('env_keys', []) == [], 'single original actor launch without extra environment')
    need(type(job['id']) is str and job['id'] and type(job['created_unix_ms']) is int
         and status['job_id'] == job['id'] == outputs['job_id'], 'original job identity')
    need(status['state'] == 'succeeded' and type(status['exit_code']) is int and status['exit_code'] == 0
         and status['output_complete'] is True and status['output_durable'] is True
         and status['terminal_publication_confirmed'] is True
         and status['timed_out'] is False and status['cancelled'] is False
         and status['log_errors'] == {'stdout': None, 'stderr': None}
         and status['log_truncated'] == {'stdout': False, 'stderr': False}
         and type(status['at_unix_ms']) is int and job['created_unix_ms'] <= status['at_unix_ms'],
         'actual actor original wait/output is not complete success')
    streams = {name: original_stream(outputs[name], name, status) for name in ('stdout', 'stderr')}
    need(streams['stderr'] == b'', 'original actor process stderr is not empty')
    summary = strict(streams['stdout'], 16384)
    exact(summary, ('run', 'status', 'sha256', 'elapsed_seconds', 'http_status', 'phone_rc', 'error'),
          'original actor CLI summary')
    need(summary['run'] == expected['actor_operation_dir'] and summary['status'] == 'command_exited'
         and type(summary['phone_rc']) is int and summary['phone_rc'] == 0
         and summary['http_status'] is None and summary['error'] is None,
         'actor zero alone is insufficient: original phone must also exit zero')
    return dict(job_id=job['id'], created_unix_ms=job['created_unix_ms'],
                terminal_unix_ms=status['at_unix_ms'], exit_code=0,
                stdout=pin(streams['stdout']), stderr=pin(streams['stderr']),
                original_actor_terminal_and_dual_output_eof_verified=True), summary

def proc_identity(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 4096, 'bounded original source-entry proc stat')
    left, separator, right = raw.rpartition(b') ')
    fields = right.split()
    need(separator and b' (' in left and len(fields) >= 20, 'complete raw proc identity')
    result = [int(left.split(b' ', 1)[0]), int(fields[1]), int(fields[2]), int(fields[3]), int(fields[19])]
    need(all(type(x) is int and x > 0 for x in result), 'positive original entry identity')
    return result

def verify_guard(stderr_raw, expected, protocol, pool):
    need(stderr_raw.startswith(protocol.RECEIPT_PREFIX), 'actual selected-source execution receipt required')
    line, separator, remainder = stderr_raw[len(protocol.RECEIPT_PREFIX):].partition(b'\n')
    need(separator and not remainder and len(stderr_raw) <= 8192,
         'one complete original guard receipt and unchanged empty entry stderr')
    value = strict(line, 8192)
    exact(value, ('schema', 'boot_id', 'phase', 'source', 'argv', 'identity', 'proc_before_base64',
                  'proc_after_base64', 'started_monotonic_ns', 'observed_monotonic_ns',
                  'source_bytes_verified', 'exec_started_here', 'independent_parent_wait_claimed'),
          'exact source-entry receipt')
    need(value['schema'] == 'hepta.production.install-ready.entry-original.v1'
         and value['boot_id'] == BOOT and value['phase'] == expected['spec']['phase']
         and value['argv'] == expected['spec']['argv']
         and value['source_bytes_verified'] is True and value['exec_started_here'] is False
         and value['independent_parent_wait_claimed'] is False, 'actual source guard and exact original argv')
    source = descriptor(value['source'], 262144, metadata=True)
    need({k: source[k] for k in ('path', 'bytes', 'sha256')} == expected['spec']['source'],
         'source guard selected another file')
    pool.phone(source, source['path'], 262144)
    for name in ('proc_before_base64', 'proc_after_base64'):
        need(type(value[name]) is str, 'raw original proc representation')
        raw = base64.b64decode(value[name], validate=True)
        need(base64.b64encode(raw).decode() == value[name]
             and proc_identity(raw) == value['identity'], 'two actual same-view source-entry identities')
    need(type(value['started_monotonic_ns']) is int and type(value['observed_monotonic_ns']) is int
         and 0 <= value['started_monotonic_ns'] <= value['observed_monotonic_ns']
         and value['observed_monotonic_ns'] - value['started_monotonic_ns'] <= 10_000_000_000,
         'one bounded pre-exec source observation')
    return value

def verify_phase(name, value, plan, release, release_inputs, retirement_sha256, protocol, pool):
    exact(value, ('process', 'actor_source_before', 'actor_source_after', 'request',
                  'intent', 'baseline', 'result', 'phone_stdout', 'phone_stderr'), 'complete original phase')
    expected = protocol.expected_phase(plan, name, release, release_inputs, retirement_sha256)
    for key in ('actor_source_before', 'actor_source_after'):
        row = value[key]
        need({k: row[k] for k in ('path', 'bytes', 'sha256')} == plan['actor'],
             'original on-disk actor source differs from reviewed179a')
        pool.p4(row, plan['actor']['path'], 65536)
    need(value['actor_source_before'] == value['actor_source_after'],
         'original actor full9 changed across invocation')
    request_raw = pool.p4(value['request'], plan['phases'][name]['request_path'], 65536, request=True)
    need(request_raw == expected['request_raw'], 'all original request bytes must equal derived command')
    authority, cli = verify_process(value['process'], expected, pool)
    actor_root = expected['actor_operation_dir']
    intent_raw = pool.p4(value['intent'], actor_root + '/intent.json', 131072, request=True)
    baseline_raw = pool.p4(value['baseline'], actor_root + '/baseline.json', 131072, request=True)
    result_raw = pool.p4(value['result'], actor_root + '/result.json', MAX_RESULT, request=True)
    intent, baseline, result = strict(intent_raw, 131072), strict(baseline_raw, 131072), strict(result_raw, MAX_RESULT)
    need(intent_raw == original_actor_json(intent) and baseline_raw == original_actor_json(baseline)
         and result_raw == original_actor_json(result), 'actual actor saved JSON bytes differ')
    exact(intent, ('schema', 'label', 'utc', 'request_sha256', 'request', 'automatic_replay'), 'original one-use intent')
    need(intent['schema'] == 'hepta.phone-local.operator-intent.v150.1'
         and intent['label'] == plan['phases'][name]['label']
         and intent['request_sha256'] == pin(request_raw)['sha256']
         and intent['request'] == expected['request'] and intent['automatic_replay'] is False,
         'original request, label or replay policy differs')
    stamp = datetime.datetime.fromisoformat(intent['utc'])
    need(stamp.tzinfo is not None, 'original actor intent has a timezone')
    intent_ms = int(stamp.timestamp() * 1000)
    need(authority['created_unix_ms'] <= intent_ms <= authority['terminal_unix_ms'],
         'original intent outside original actor process lifetime')
    need(type(baseline.get('rc')) is int and baseline['rc'] == 0 and baseline.get('stderr') == ''
         and baseline['stdout'].splitlines() == [BOOT, FINGERPRINT, 'adb', 'Enforcing', '3021'],
         'actual original actor device baseline differs')
    need(result.get('schema') == 'hepta.phone-local.operator-result.v150.1'
         and result.get('label') == intent['label'] and result.get('status') == 'command_exited'
         and result.get('model_decision') is False and result.get('native_task_result') is False
         and pin(result_raw)['sha256'] == cli['sha256'], 'CLI must bind complete original actor result')
    elapsed = result.get('elapsed_seconds')
    need(type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0
         and cli['elapsed_seconds'] == elapsed, 'actual elapsed duration preserved')
    phone = result.get('phone')
    need(type(phone) is dict and type(phone.get('rc')) is int and phone['rc'] == 0
         and phone.get('command') == expected['wrapped_command']
         and phone.get('route') == baseline.get('route'), 'actual phone exit, command and same route')
    need(type(phone.get('stdout')) is str and type(phone.get('stderr')) is str,
         'original complete phone streams')
    stdout, stderr = phone['stdout'].encode(), phone['stderr'].encode()
    need(len(stdout) + len(stderr) <= 8 * 1024 * 1024, 'unchanged original combined shell output limit')
    need(pool.read(value['phone_stdout'], MAX_RESULT) == stdout
         and pool.read(value['phone_stderr'], 8192) == stderr, 'separate retained raw phone streams')
    guard = verify_guard(stderr, expected, protocol, pool)
    return dict(authority=authority, intent_unix_ms=intent_ms, request=pin(request_raw),
                phone_stdout=stdout, source_receipt=guard,
                actual_actor_result_sha256=pin(result_raw)['sha256'],
                wire_bytes=expected['wire_bytes'], phone_exit_code=0)

def verify_install_originals(rows, release, release_inputs, projected, phases, pool):
    exact(rows, ('install_intent', 'staged', 'preservation', 'start_intent', 'started'),
          'five original installation JSON files')
    names = {'install_intent': 'INSTALL-INTENT.json', 'staged': 'STAGED.json',
             'preservation': 'STAGED-PRESERVATION.original.json',
             'start_intent': 'START-INTENT.json', 'started': 'STARTED.json'}
    originals = {}
    for key, name in names.items():
        maximum = 32 * 1024 * 1024 if key == 'preservation' else 65536
        raw = pool.phone(rows[key], OUT + '/' + name, maximum)
        value = strict(raw, maximum)
        need(raw == original_file_json(value), 'exact original installer file serialization')
        originals[key] = (raw, value)
    intent = originals['install_intent'][1]
    exact(intent, ('release_id', 'retirement_sha256', 'write_count', 'automatic_replay'), 'original install intent')
    manifest, blobs = projected
    boundary = manifest['_boundary']
    need(intent == {'release_id': 'v150-r10-r1', 'retirement_sha256': boundary['retirement_sha256'],
                    'write_count': len(manifest['writes']), 'automatic_replay': False},
         'actual one-use stage write inventory differs')
    staged = originals['staged'][1]
    exact(staged, ('state', 'release_id', 'archive_sha256', 'manifest_sha256', 'writes_verified',
                   'disable_identity', 'retirement_sha256', 'closed_component_originals_preserved',
                   'old_retirement_current_equality_claimed', 'stage_preservation',
                   'policy_adoption_inputs_sha256', 'component_boundary_inputs_sha256',
                   'model_requests', 'task_submissions', 'service_starts'), 'complete original stage result')
    preservation_raw, preservation = originals['preservation']
    need(type(staged['writes_verified']) is int
         and staged['state'] == 'STAGED_DISABLED_NOT_STARTED' and staged['release_id'] == 'v150-r10-r1'
         and staged['archive_sha256'] == manifest['_archive_sha256']
         and staged['manifest_sha256'] == manifest['_manifest_sha256']
         and staged['writes_verified'] == len(manifest['writes'])
         and staged['retirement_sha256'] == boundary['retirement_sha256']
         and staged['stage_preservation'] == pin(preservation_raw)
         and staged['closed_component_originals_preserved'] is True
         and staged['old_retirement_current_equality_claimed'] is False
         and staged['policy_adoption_inputs_sha256'] == boundary['policy_adoption_sha256']
         and staged['component_boundary_inputs_sha256'] == boundary['component_input_sha256']
         and all(type(staged[k]) is int and staged[k] == 0 for k in ('model_requests', 'task_submissions', 'service_starts')),
         'original stage must be exact disabled/not-started actual BUILD')
    disable = staged['disable_identity']
    need(type(disable) is list and len(disable) == 5 and all(type(x) is int and x >= 0 for x in disable)
         and disable[1] > 0 and disable[2] == 0, 'actual new empty disable marker identity')
    exact(preservation, ('schema', 'state', 'release_id', 'boot_id', 'archive_sha256', 'manifest_sha256',
                         'component_boundary_inputs_sha256', 'policy_adoption_inputs_sha256',
                         'component_boundary_sha256', 'release_boundary_bundle_sha256', 'retirement_sha256',
                         'before_inventory', 'after_inventory', 'install_delta', 'new_directory_selinux',
                         'before_observation', 'after_observation', 'original_retirement_rewritten',
                         'old_retirement_current_equality_claimed'), 'complete stage preservation original')
    need(preservation['schema'] == 'hepta.r10.install-preservation-boundary.v1'
         and preservation['state'] == 'EXACT_COMPONENT_ORIGINALS_PLUS_ONE_INSTALL_OWNED_EMPTY_DIRECTORY'
         and preservation['release_id'] == 'v150-r10-r1' and preservation['boot_id'] == BOOT
         and preservation['archive_sha256'] == manifest['_archive_sha256']
         and preservation['manifest_sha256'] == manifest['_manifest_sha256']
         and preservation['retirement_sha256'] == boundary['retirement_sha256']
         and preservation['component_boundary_inputs_sha256'] == boundary['component_input_sha256']
         and preservation['policy_adoption_inputs_sha256'] == boundary['policy_adoption_sha256']
         and preservation['component_boundary_sha256'] == boundary['component_boundary_sha256']
         and preservation['release_boundary_bundle_sha256'] == boundary['bundle_sha256']
         and preservation['original_retirement_rewritten'] is False
         and preservation['old_retirement_current_equality_claimed'] is False, 'exact stage/current boundary linkage')
    consumer = manifest['_consumer']
    before = consumer['inventory_value'](boundary, preservation['before_inventory'])
    after = consumer['inventory_value'](boundary, preservation['after_inventory'])
    need(before == consumer['inventory_value'](boundary, boundary['current_inventory']),
         'stage before inventory must be the actual closed two-case native head')
    delta = consumer['validate_install_delta'](preservation['before_inventory'], preservation['after_inventory'])
    need(delta == preservation['install_delta']
         and preservation['new_directory_selinux'] == 'u:object_r:trillionnium_owner_open_phone_executor_data_file:s0',
         'unchanged exact one-directory installation delta')
    for name in ('before_observation', 'after_observation'):
        observed = preservation[name]
        need(type(observed) is dict and observed.get('component_boundary_sha256') == boundary['component_boundary_sha256']
             and observed.get('retirement_sha256') == boundary['retirement_sha256']
             and observed.get('old_retirement_current_equality_claimed') is False,
             'stage observation must preserve the actual current component boundary')
    start_intent = originals['start_intent'][1]
    need(type(start_intent.get('maximum_start_attempts')) is int
         and start_intent == {'release_id': 'v150-r10-r1', 'maximum_start_attempts': 1,
                          'old_release_remains_disabled': True}, 'original single-start intent')
    started = originals['started'][1]
    exact(started, ('state', 'pid', 'process_identity', 'boot_id', 'release_id', 'one_start_attempt',
                    'model_requests', 'task_submissions'), 'complete original STARTED record')
    identity = started['process_identity']
    need(type(identity) is list and len(identity) == 4 and all(type(x) is int and x > 0 for x in identity)
         and type(started['pid']) is int and identity[:3] == [started['pid']] * 3
         and started['state'] == 'SERVICE_SPAWNED_READINESS_NOT_YET_ESTABLISHED'
         and started['boot_id'] == BOOT and started['release_id'] == 'v150-r10-r1'
         and started['one_start_attempt'] is True
         and type(started['model_requests']) is int and started['model_requests'] == 0
         and type(started['task_submissions']) is int and started['task_submissions'] == 0,
         'actual new detached startup generation, never a wait receipt')
    need(phases['stage']['phone_stdout'] == original_entry_stdout(staged)
         and phases['start']['phone_stdout'] == original_entry_stdout(started),
         'actual CLI output must equal actual file value under its different source-defined serialization')
    return dict(supervisor_identity=identity, before_inventory_value=before, after_inventory_value=after,
                install_delta=delta, preservation_sha256=pin(preservation_raw)['sha256'])

def verify_install_start_ready_originals(inputs_raw, *, read_pinned):
    # No parsing, import, callback, or filesystem access before all actual slots exist.
    need(FROZEN_INPUTS is not None and FROZEN_EXECUTION_PLAN is not None,
         'UNBOUND_ACTUAL_INSTALL_START_READY_INPUTS_NO_IO')
    descriptor(FROZEN_INPUTS, MAX_INPUT, metadata=False)
    descriptor(FROZEN_EXECUTION_PLAN, 65536, metadata=False)
    need(type(inputs_raw) is bytes and pin(inputs_raw) ==
         {k: FROZEN_INPUTS[k] for k in ('bytes', 'sha256')}, 'exact frozen actual input bytes')
    value = exact(strict(inputs_raw), ('schema', 'release_inputs', 'eight_stream_inputs',
                                      'execution_plan', 'phases', 'install_originals', 'original_map'),
                  'exact install/start/READY input contract')
    need(value['schema'] == SCHEMA and value['execution_plan'] == FROZEN_EXECUTION_PLAN,
         'selected actual plan family')
    pool = Originals(value['original_map'], read_pinned)
    protocol = reviewed(pool.read(SOURCES['protocol'], 262144), SOURCES['protocol'], 'install_ready_protocol')
    release_api = reviewed(pool.read(SOURCES['release'], 262144), SOURCES['release'], 'actual_release_install_gate')
    exact8_api = reviewed(pool.read(SOURCES['exact8'], 262144), SOURCES['exact8'], 'actual_eight_stream_install_gate')
    release_raw = pool.read(value['release_inputs'], 1024 * 1024)
    release_inputs = strict(release_raw, 1024 * 1024)
    release = release_api.verify_final_release_inputs(release_raw, read_pinned=pool.read)
    need(release['state'] == 'ACTUAL_HOST_RELEASE_ORIGINALS_VERIFIED_PHONE_READINESS_SEPARATE'
         and release['all_17_shared_bytes_equal'] is True and release['all_originals_bookended'] is True,
         'actual complete BUILD originals required')
    eight_raw = pool.read(value['eight_stream_inputs'], 1024 * 1024)
    eight_inputs = strict(eight_raw, 1024 * 1024)
    need(eight_inputs['release_inputs'] == value['release_inputs'], 'same actual release in the four-role origin chain')
    eight = exact8_api.verify_resident_output_bindings(eight_raw, read_pinned=pool.read)
    need(eight['actual_build_originals_reverified'] is True
         and eight['actual_build_result_sha256'] == release['actual_build_result_sha256']
         and eight['release_pins'] == release['release_pins']
         and eight['complete_stream_origin_count'] == 8
         and eight['all_selected_originals_bookended'] is True
         and eight['actual_release_binding_qualified'] is False
         and eight['whole_resident_output_qualified'] is False
         and eight['whole_rollback_qualified'] is False
         and eight['supervisor_original_parent_wait'] == 'NOT_RETAINED',
         'complete exact8 origins remain separate from execution authority and closure')
    plan_raw = pool.read(value['execution_plan'], 65536)
    plan = strict(plan_raw, 65536)
    protocol.validate_plan(plan, release, release_inputs)
    need(plan['release_inputs_sha256'] == pin(release_raw)['sha256'], 'execution plan actual BUILD input binding')
    archive_raw = pool.read(release_inputs['release_archive'], 64 * 1024 * 1024)
    installer_raw = pool.read(release_inputs['installer_source'], 262144)
    projected = release_api.project_installer(installer_raw, release_inputs['release_archive'], archive_raw)
    manifest, blobs = projected['load_release'](
        PurePosixPath(release_inputs['release_archive']['path']), release_inputs['release_archive']['sha256'],
        release['release_pins']['component_boundary_inputs_sha256'], release['release_pins']['policy_adoption_inputs_sha256'])
    retirement_sha256 = manifest['_boundary']['retirement_sha256']
    exact(value['phases'], PHASES, 'three phases only; no implied replay or later health/model request')
    phases = {name: verify_phase(name, value['phases'][name], plan, release, release_inputs,
                                retirement_sha256, protocol, pool) for name in PHASES}
    for first, second in (('stage', 'start'), ('start', 'ready')):
        need(phases[first]['authority']['terminal_unix_ms'] <= phases[second]['authority']['created_unix_ms'],
             'next phase started before the previous original actor was joined and its output retained')
    installation = verify_install_originals(value['install_originals'], release, release_inputs,
                                             (manifest, blobs), phases, pool)
    ready_raw = pool.read(eight['ready_originals']['original'], 1024 * 1024)
    ready = strict(ready_raw, 1024 * 1024)
    need(ready_raw == phases['ready']['phone_stdout'] == original_entry_stdout(ready),
         'exact8 READY must be the full stdout of this original actual READY invocation')
    need(eight['role_identities']['supervisor'] == installation['supervisor_identity']
         and ready['roles']['supervisor']['identity'] == installation['supervisor_identity'],
         'STARTED original supervisor generation differs from original READY and exact8')
    pool.recheck()
    return {
        'schema': 'hepta.production.install-start-ready.original-verdict.v1',
        'state': 'VERIFIED_ACTUAL_INSTALL_START_READY_EXECUTION_ORIGINALS',
        'boot_id': BOOT, 'release_id': 'v150-r10-r1',
        'actual_build_result_sha256': release['actual_build_result_sha256'],
        'runtime_combination_sha256': release['runtime_combination_sha256'],
        'production_combination_sha256': release['production_combination_sha256'],
        'production_combination_manifest_sha256': release['production_combination_manifest_sha256'],
        'release_pins': release['release_pins'],
        'actual_execution_plan': value['execution_plan'],
        'actual_ready_original': eight['ready_originals']['original'],
        'role_identities': eight['role_identities'],
        'phase_authorities': {name: phases[name]['authority'] for name in PHASES},
        'phase_source_receipts': {name: phases[name]['source_receipt'] for name in PHASES},
        'installation_preservation_sha256': installation['preservation_sha256'],
        'original_installer_delta_recomputed': True,
        'three_original_actor_terminals_and_outputs_verified': True,
        'actual_installer_and_READY_execution_qualified': True,
        'READY_qualification_scope': 'TRANSPORT_ONLY_AT_ORIGINAL_OBSERVATION',
        'supervisor_original_parent_wait': 'NOT_RETAINED',
        'supervisor_regular_output_eof_claimed': False,
        'installation_scope_census_qualified': False,
        'task_lifecycle_qualified': False, 'resident_terminal_qualified': False,
        'resident_output_closure_qualified': False,
        'production_footprint_qualified': False, 'production_fresh_admission_qualified': False,
        'whole_production_scope_qualified': False, 'whole_rollback_qualified': False,
        'business_qualified': False, 'fixed19_credit': 0, 'cold_boot_qualified': False,
        'all_retained_originals_bookended': True,
        'original_count': len(pool.observed), 'original_raw_bytes': pool.total,
        'phone_calls': 0, 'processes_started': 0, 'model_requests': 0, 'new_nonces': 0,
    }
