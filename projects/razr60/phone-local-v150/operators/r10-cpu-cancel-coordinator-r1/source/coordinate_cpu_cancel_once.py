#!/usr/bin/env python3
"""One existing NEG-08/09 identity: sender, actual Cancel Actor, originals, CPU closer.

Preview is source-only. Execution remains closed until a separately reviewed
source revision freezes FINAL_AUTHORITY to the actual current release and policy.
This entry creates no nonce, registers no task, changes no model/policy/runtime,
and never replays an uncertain phase. The original Root capture module is loaded
whole and its transport methods remain byte-for-byte unchanged.
"""
import argparse
import ast
import base64
import contextlib
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import time
import types

FINAL_AUTHORITY = None
B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
P4 = '/home/alex/razr60-local-model-v150'
PHONE = '/var/lib/trillionnium/owner-open/phone-local-v150'
SCOPE = ('session_id', 'profile_id', 'task_id', 'turn_id', 'turn_stream_id')
META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
OPERATOR_NAMES = {'active_runtime_r10.py', 'cancel_native_once_r10.py', 'cancel_phase.py',
    'decode_client_state.py', 'native_journal_audit.py', 'observe_cancel_phase_r10.py',
    'production-pins.json', 'reviewed_page_projection.py'}
PHASE_KEYS = {'intent', 'child', 'result', 'stdout', 'stderr', 'stdin', 'output_capture'}
PHASE_LEAVES = {'intent':'INTENT.json', 'child':'CHILD.json', 'result':'RESULT.json',
    'stdout':'stdout.original', 'stderr':'stderr.original', 'stdin':'stdin.original',
    'output_capture':'OUTPUT-CAPTURE.json'}
MAX_ARCHIVE = 64 * 1024 * 1024  # Existing CPU closer archive bound, unchanged.
CHUNK = 512 * 1024  # Existing Root snapshot transport unit, unchanged.


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode()


def canonical_json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def strict(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def byte_pin(raw):
    return {'bytes':len(raw), 'sha256':sha(raw)}


def descriptor(path, raw):
    return {'path':str(path), **byte_pin(raw)}


def digest(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'exact SHA256 required')
    return value


def absolute(value):
    need(type(value) is str and value.startswith('/') and '\0' not in value and
        str(Path(value)) == value and all(x not in ('', '.', '..') for x in value[1:].split('/')),
        'canonical absolute path required')
    return Path(value)


def exact3(row, limit=MAX_ARCHIVE):
    need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}, 'exact original descriptor required')
    absolute(row['path']); digest(row['sha256'])
    need(type(row['bytes']) is int and 0 <= row['bytes'] <= limit, 'bounded exact byte count required')
    return row


def metadata(value):
    return tuple(getattr(value, key) for key in META)


def read_regular(path, maximum=MAX_ARCHIVE):
    path = absolute(str(path))
    need(path.resolve(strict=True) == path, 'original path contains a symlink')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
            'bounded single regular original required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        need(len(raw) == before.st_size and metadata(before) == metadata(os.fstat(fd)) == metadata(path.lstat()),
            'original changed during complete read')
        return raw, metadata(before)
    finally:
        os.close(fd)


class ReadSet:
    def __init__(self):
        self.rows = {}

    def read(self, row):
        exact3(row)
        raw, meta = read_regular(row['path'], row['bytes'])
        need(byte_pin(raw) == {k:row[k] for k in ('bytes', 'sha256')}, 'original byte pin differs')
        old = self.rows.get(row['path'])
        value = (dict(row), meta)
        need(old is None or old == value, 'input generation changed between reads')
        self.rows[row['path']] = value
        return raw

    def recheck(self):
        for row, _ in tuple(self.rows.values()):
            self.read(row)


def sync(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_parent(path):
    path = absolute(str(path))
    need(path.resolve(strict=True) == path, 'private parent canonical path')
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.geteuid(),
        'pre-existing private parent required')


def create_directory(path):
    private_parent(path.parent)
    path.mkdir(mode=0o700)
    sync(path); sync(path.parent)


def put(path, raw):
    need(type(raw) is bytes, 'exact bytes required')
    private_parent(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    sync(path.parent)
    actual, _ = read_regular(path, len(raw))
    need(actual == raw, 'new output complete independent readback')
    return descriptor(path, raw)


def absent(path):
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    raise ValueError('one-use namespace or marker already exists: ' + str(path))


def module_from_raw(name, raw, path):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec', optimize=0), module.__dict__)
    return module


def require_authority():
    value = FINAL_AUTHORITY
    need(type(value) is dict and set(value) == {'schema', 'sources', 'operator_manifest', 'operator_sources',
        'closure_sources', 'final_dependencies', 'derivation_evidence'},
        'actual final source authority remains unfrozen; no case input or remote action is admitted')
    need(value['schema'] == 'hepta.cpu-cancel.coordinator-final-authority.v1', 'final authority schema')
    need(set(value['operator_sources']) == OPERATOR_NAMES, 'all eight operator source pins required')
    need(set(value['closure_sources']) == {'root_cpu_negative', 'negative_originals', 'close_cpu_negative', 'ledger_prefix_negative'},
        'complete actual CPU closer source set required')
    for row in [value['operator_manifest'], *value['sources'].values(), *value['operator_sources'].values(),
                *value['closure_sources'].values(), *value['derivation_evidence']]:
        exact3(row)
    need(value['derivation_evidence'], 'actual source generation derivation must be preserved')
    return value


def load_authority(authority, reads):
    closure_raw = {name:reads.read(row) for name, row in authority['closure_sources'].items()}
    O = module_from_raw('reviewed_cpu_cancel_assembly', closure_raw['negative_originals'],
        authority['closure_sources']['negative_originals']['path'])
    final = O.final_dependencies()
    need(final == authority['final_dependencies'], 'actual closer final literals differ from authority')
    closer_parent = Path(authority['closure_sources']['root_cpu_negative']['path']).parent
    for name in ('negative_originals', 'close_cpu_negative'):
        need(authority['closure_sources'][name]['path'] == str(closer_parent / (name + '.py')),
            'actual closer imports its exact sibling source')
    need(O.literal(closure_raw['root_cpu_negative'], 'PURE_MODULES') ==
        {name:byte_pin(closure_raw[name]) for name in ('negative_originals', 'close_cpu_negative')},
        'actual closer source-pin cascade must close before any case dispatch')
    originals = O.Originals(reads.read)
    sources = O.load_sources({'sources':authority['sources']}, originals, final)
    need(sources['ledger_negative'] == closure_raw['ledger_prefix_negative'], 'same actual ledger closer bytes')
    root = module_from_raw('reviewed_root_capture_transport', sources['root_transport'],
        authority['sources']['root_transport']['path'])
    operator = {'source/' + name:reads.read(row) for name, row in authority['operator_sources'].items()}
    manifest_raw = reads.read(authority['operator_manifest']); manifest = strict(manifest_raw)
    expected = {'source/' + name:{'path':'source/' + name, **byte_pin(raw)}
        for name, raw in ((name, operator['source/' + name]) for name in OPERATOR_NAMES)}
    need(sha(manifest_raw) == final['ui_package_sha256'] and
        manifest.get('schema') == 'hepta.r10.native-cancel-operator-package.v1' and
        len(manifest['files']) == 8 and {r['path']:r for r in manifest['files']} == expected,
        'actual complete eight-source operator package')
    need(manifest['reviewed_production_source_pins'] == strict(operator['source/production-pins.json']),
        'actual production 15-source map must equal manifest')
    actor = module_from_raw('reviewed_cancel_actor_for_pure_plan', operator['source/cancel_native_once_r10.py'],
        authority['operator_sources']['cancel_native_once_r10.py']['path'])
    names = ('active_runtime_r10', 'cancel_phase', 'decode_client_state', 'reviewed_page_projection')
    saved = {name:sys.modules.get(name) for name in names}
    try:
        modules = actor.load_reviewed_helpers(operator)
        actor.require_final_execution_dependencies(manifest, modules)
    finally:
        for name in names:
            if saved[name] is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = saved[name]
    for row in authority['derivation_evidence']:
        reads.read(row)
    reads.recheck()
    return {'assembly':O, 'root':root, 'final':final, 'sources':sources, 'operator':operator,
        'manifest_raw':manifest_raw, 'actor':actor, 'modules':modules, 'closure_raw':closure_raw}


def validate_case_plan(plan, authority):
    fields = {'schema', 'state', 'case_id', 'nonce', 'out', 'actor_label', 'sender_label', 'capture_label',
        'expected_boot', 'wait_seconds', 'require_image_cancel', 'probe_component', 'runtime_binding',
        'sender_inputs', 'registration_template', 'qualify_physical_case'}
    need(type(plan) is dict and set(plan) == fields and
        plan['schema'] == 'hepta.cpu-cancel.coordinator-plan.v1' and
        plan['state'] == 'ROOT_REVIEWED_REGISTERED_UNCONSUMED_CASE_ONCE', 'exact coordinator plan')
    need(plan['case_id'] in ('NEG-08', 'NEG-09') and type(plan['nonce']) is str and
        re.fullmatch('[0-9a-f]{32}', plan['nonce']), 'one explicit existing negative nonce')
    need(plan['out'] == str(B / 'cpu-cancel-negative-coordinators-r1' / plan['nonce']), 'fixed one-use local output')
    for key in ('actor_label', 'sender_label', 'capture_label'):
        need(type(plan[key]) is str and re.fullmatch('[a-z0-9][a-z0-9-]{5,69}', plan[key]), 'explicit original label')
    need(type(plan['wait_seconds']) is int and 1 <= plan['wait_seconds'] <= 300, 'original closer wait contract')
    need(type(plan['require_image_cancel']) is bool and type(plan['qualify_physical_case']) is bool,
        'exact boolean qualification/image flags')
    need(set(plan['sender_inputs']) == {'request', 'previous', 'preserved_draft', 'retirement_resolution'},
        'four original sender inputs required')
    for row in [*plan['sender_inputs'].values(), plan['registration_template']]:
        exact3(row)
    pins = plan['runtime_binding']['release_pins']
    final = authority['final_dependencies']
    need(pins['configuration_sha256'] == final['configuration_sha256'] and
        pins['service_inputs_sha256'] == final['service_inputs_sha256'] and
        pins['policy_adoption_inputs_sha256'] == final['policy_adoption_sha256'], 'same actual source/policy generation')
    return plan


def make_actor_plan(plan, raw_inputs, modules):
    owner = raw_inputs['request']; previous = strict(raw_inputs['previous'])
    draft = strict(raw_inputs['preserved_draft']); template = strict(raw_inputs['registration_template'])
    need(previous['terminal']['status'] in ('completed', 'provider_failed', 'cancelled'), 'original previous task terminal')
    need(template['schema'] == 'hepta.task-template.v150.3' and template['request_sha256'] == sha(owner) and
        template['nonce'] == plan['nonce'] and template['expected_scope'] ==
        {k:previous['identity'][k] for k in ('session_id', 'profile_id')}, 'actual registered template/previous binding')
    need(owner.decode('utf-8').count(plan['nonce']) == 1, 'nonce occurs once in unchanged owner request')
    preserved = base64.b64decode(draft['exact_utf8_b64'], validate=True)
    need(preserved and preserved.decode('utf-8') and sha(preserved) == draft['utf8_sha256'] and preserved != owner,
        'exact preserved draft input')
    pins = plan['runtime_binding']['release_pins']
    actor = {'schema':'hepta.r10.native-cancel-once-plan.v1', 'label':plan['actor_label'],
        'sender_label':plan['sender_label'], 'case_id':plan['case_id'], 'nonce':plan['nonce'],
        'expected_boot':plan['expected_boot'], 'request_b64':base64.b64encode(owner).decode(),
        'owner_request_sha256':sha(owner), 'previous_scope':previous['identity'],
        'source_seal_sha256':pins['source_seal_sha256'], 'configuration_sha256':pins['configuration_sha256'],
        'service_inputs_sha256':pins['service_inputs_sha256'], 'require_image_cancel':plan['require_image_cancel'],
        'probe_component':plan['probe_component'], 'wait_seconds':plan['wait_seconds'],
        'app_scope':template['app_scope'], 'task_template_sha256':sha(raw_inputs['registration_template']),
        'runtime_binding':plan['runtime_binding']}
    need(modules['cancel_phase'].validate_plan(actor) == owner, 'actual original Actor validator')
    return actor


def sender_argv(plan, authority):
    v = plan['sender_inputs']
    return ['/usr/bin/python3', '-I', '-B', authority['sources']['sender']['path'], plan['sender_label'],
        v['request']['path'], v['previous']['path'], '--preserved-draft', v['preserved_draft']['path'],
        '--retirement-resolution', v['retirement_resolution']['path'], '--evidence-root', 'production', '--execute-once']


def actor_argv(plan, final):
    root = P4 + '/cpu-negative-case-inputs-r1/' + plan['nonce']
    return ['/usr/bin/python3', '-I', '-B', root + '/operator/source/cancel_native_once_r10.py',
        '--plan', root + '/ACTOR-PLAN.json', '--package', root + '/operator/MANIFEST.json',
        '--package-sha256', final['ui_package_sha256'], '--out', P4 + '/cancel-native-r10/' + plan['actor_label'],
        '--execute-once']


def phase_records(root, directory, *, stdin):
    rows = {key:root.filedesc(directory / leaf) for key, leaf in PHASE_LEAVES.items() if key != 'stdin'}
    rows['stdin'] = root.filedesc(directory / 'stdin.original') if stdin else None
    need(set(rows) == PHASE_KEYS, 'exact seven original phase descriptors')
    return rows


def finish_async_phase(chain, root, name, handle):
    """Use the actual Root join/EOF/created-inode verifier; publish its exact seven RESULT fields."""
    child, directory, stdout, stderr = handle
    errors = []
    try:
        rc = chain.join_host_capture(name, child)  # Never extend its original deadline.
    finally:
        errors += chain.stop_host_capture(name, request_stop=False)
        errors += chain.persist_host_capture(name)
        errors += root.close_streams_owned([(name + ':stdout', stdout), (name + ':stderr', stderr)])
        chain._owned_host_streams.pop(name, None)
    need(not errors, 'async phase original capture cleanup failed: ' + repr(errors))
    chain.verify_host_capture_outputs(name)
    result = {'state':'ORIGINAL_HOST_CHILD_JOINED', 'phase':name, 'pid':child.pid, 'returncode':rc,
        'stdout':root.filedesc(directory / 'stdout.original'), 'stderr':root.filedesc(directory / 'stderr.original'),
        'automatic_retry':False}
    root.put(directory / 'RESULT.json', root.enc(result)); chain.steps.append(result)
    chain._owned_host_children.pop(name, None)
    chain._owned_host_deadlines.pop(name, None)
    chain._owned_host_captures.pop(name, None)
    need(type(rc) is int and rc == 0, 'actual async sender failed; retain originals without replay')
    return result


def make_phone_plan(plan, actor_plan, actor_raw, result, final):
    need(result['schema'] == 'hepta.r10.native-cancel-once-result.v1' and
        result['state'] == 'ORIGINAL_CANCEL_AND_DRAIN_OBSERVED' and
        result['case_id'] == plan['case_id'] and result['owner_request_sha256'] == actor_plan['owner_request_sha256'],
        'actual same-case Actor result required')
    need(type(result['cancel_tap_attempts']) is int and result['cancel_tap_attempts'] == 1 and
        all(result[k] is True for k in ('cancel_acceptance_observed', 'native_cancelled_observed',
            'original_model_terminal_release_idle_observed', 'dispatch_prefix_unchanged')) and
        result['automatic_retry'] is False, 'single original Cancel and drain must be observed')
    observation = result['last_original_observation']
    scope = result['scope']
    need(type(scope) is dict and set(scope) == set(SCOPE) and scope == observation['scope'] and
        scope != actor_plan['previous_scope'] and observation['state'] == 'BOUND_ORIGINAL_PHASE_OBSERVED',
        'scope comes only from matching actual original Actor observations')
    need(observation['owner_request_sha256'] == actor_plan['owner_request_sha256'] and
        observation['boot_id'] == plan['expected_boot'] and
        observation['native_terminal']['payload']['status'] == 'cancelled', 'original scope boot and cancellation')
    digest(observation['native_request_sha256'])
    need(re.fullmatch('[0-9]{8}-[0-9]{6}-[0-9a-f]{32}', observation['run']), 'actual provider run basename')
    ready = strict(base64.b64decode(actor_plan['runtime_binding']['readiness']['raw_b64'], validate=True))
    identity = ready['roles']['model']['identity']
    need(type(identity) is list and len(identity) == 4 and all(type(v) is int and v > 0 for v in identity),
        'actual READY model identity')
    server = dict(zip(('pid', 'pgid', 'sid', 'start_ticks'), identity))
    server.update(schema='hepta.llama-server-identity.v1', boot_id=plan['expected_boot'])
    return {'schema':'hepta.cpu-cancel.phone-capture-plan.v1',
        'state':'ROOT_REVIEWED_EXISTING_NEGATIVE_ORIGINAL_CAPTURE', 'nonce':plan['nonce'], 'case_id':plan['case_id'],
        'owner_request_sha256':actor_plan['owner_request_sha256'], 'request_b64':actor_plan['request_b64'],
        'combination_sha256':final['combination_sha256'], 'sender_scope':scope,
        'native_request_sha256':observation['native_request_sha256'], 'sender_run':observation['run'],
        'sender_label':plan['sender_label'], 'operator_label':plan['actor_label'],
        'operator_plan_sha256':sha(actor_raw), 'operator_package_sha256':final['ui_package_sha256'],
        'release_pins':actor_plan['runtime_binding']['release_pins'], 'runtime_binding':actor_plan['runtime_binding'],
        'runtime':{'boot_id':plan['expected_boot'], 'server_identity':server,
            'binding_sha256':ready['actual_binding']['sha256']},
        'task_template_sha256':actor_plan['task_template_sha256'],
        'app_scope_sha256':sha(canonical_json(actor_plan['app_scope']))}


# The following code runs only through the already pinned Root transport. It
# reads/copies bounded existing originals, or creates this case's exact new host
# input directory. No source restored from an evidence archive is executed.
STAGE_SOURCE = r'''
import base64,hashlib,json,os,stat
from pathlib import Path
def need(x,m):
 if not x:raise ValueError(m)
def sync(p):
 d=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:os.fsync(d)
 finally:os.close(d)
def private(p):
 need(p.resolve(strict=True)==p,'canonical private parent')
 s=p.lstat();need(stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode)==0o700 and s.st_uid==os.geteuid(),'private owner')
private(root.parent)
for p in forbidden:
 try:os.lstat(p)
 except FileNotFoundError:pass
 else:raise ValueError('one-use case marker exists')
root.mkdir(mode=0o700);sync(root.parent)
created=[]
try:
 for name,value in sorted(files.items()):
  rel=Path(name);need(not rel.is_absolute() and all(x not in ('','.','..') for x in name.split('/')),'relative member')
  raw=base64.b64decode(value['base64'],validate=True)
  need(len(raw)==value['bytes'] and hashlib.sha256(raw).hexdigest()==value['sha256'],'member pin')
  parent=root
  for part in rel.parts[:-1]:
   parent=parent/part
   try:parent.mkdir(mode=0o700);sync(parent.parent)
   except FileExistsError:pass
   private(parent)
  path=root/rel;fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
  sync(parent);need(path.read_bytes()==raw,'new member readback');created.append(name)
 print(json.dumps({'state':'EXACT_NEW_INPUTS_CREATED','root':str(root),'files':{n:{k:v[k] for k in ('bytes','sha256')} for n,v in files.items()},'automatic_retry':False},sort_keys=True))
except BaseException as e:
 print(json.dumps({'state':'PARTIAL_NEW_INPUTS_RETAINED_NO_RETRY','root':str(root),'created':created,'error':type(e).__name__,'automatic_retry':False},sort_keys=True));raise
'''


def stage_code(root, files, forbidden=()):
    need(root.startswith(P4 + '/cpu-negative-case-inputs-r1/') or root.startswith(P4 + '/cpu-cancel-p4-capture-inputs-r1/'),
        'fixed new case input namespace')
    packet = {name:{**byte_pin(raw), 'base64':base64.b64encode(raw).decode()} for name, raw in files.items()}
    return 'from pathlib import Path\nroot=Path(' + repr(root) + ')\nfiles=' + repr(packet) + '\nforbidden=' + repr(list(forbidden)) + '\n' + STAGE_SOURCE


READ_CHUNK_SOURCE = r'''
import base64,hashlib,json,os,stat
from pathlib import Path
M=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
meta=lambda s:[getattr(s,k) for k in M]
def need(v,m):
 if not v:raise ValueError(m)
p=Path(path);need(p.is_absolute() and p.resolve(strict=True)==p,'fixed canonical original')
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
try:
 a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==size,'same bounded regular original')
 need(expected is None or meta(a)==expected,'same original across chunks')
 os.lseek(fd,offset,os.SEEK_SET);left=min(524288,size-offset);chunks=[]
 while left:
  chunk=os.read(fd,left);need(bool(chunk),'short original chunk');chunks.append(chunk);left-=len(chunk)
 raw=b''.join(chunks);need(meta(a)==meta(os.fstat(fd))==meta(p.lstat()),'full9 changed during chunk')
 if offset+len(raw)==size:need(os.read(fd,1)==b'','complete EOF')
finally:os.close(fd)
print(json.dumps({'path':path,'total_bytes':size,'offset':offset,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'metadata':meta(a),'base64':base64.b64encode(raw).decode(),'eof':offset+len(raw)==size},sort_keys=True))
'''


def chunk_code(row, offset, expected):
    exact3(row)
    need(type(offset) is int and 0 <= offset < max(1, row['bytes']), 'original chunk offset')
    return ('path=' + repr(row['path']) + '\nsize=' + repr(row['bytes']) + '\noffset=' + repr(offset) +
        '\nexpected=' + repr(expected) + '\n' + READ_CHUNK_SOURCE)


def check_chunk(value, row, offset, expected):
    raw = base64.b64decode(value['base64'], validate=True)
    need(value['path'] == row['path'] and value['total_bytes'] == row['bytes'] and value['offset'] == offset and
        byte_pin(raw) == {k:value[k] for k in ('bytes', 'sha256')} and
        len(raw) == min(CHUNK, row['bytes'] - offset), 'complete fixed original chunk')
    need(type(value['metadata']) is list and len(value['metadata']) == 9 and
        all(type(x) is int for x in value['metadata']) and
        (expected is None or value['metadata'] == expected), 'same exact full9 original generation')
    need(type(value['eof']) is bool and value['eof'] == (offset + len(raw) == row['bytes']), 'exact chunk EOF')
    return raw, value['metadata']


PREFLIGHT_SOURCE = r'''
import base64,hashlib,json,os,stat,sys,types
from pathlib import Path
def need(v,m):
 if not v:raise ValueError(m)
pins=json.loads(sources['production-pins.json'])
a=types.ModuleType('active_runtime_r10');a.__file__='<reviewed-active>';a._REVIEWED_PRODUCTION_PINS=pins;sys.modules[a.__name__]=a
exec(compile(sources['active_runtime_r10.py'],a.__file__,'exec'),a.__dict__)
g=types.ModuleType('cancel_phase');g.__file__='<reviewed-cancel-phase>';sys.modules[g.__name__]=g
exec(compile(sources['cancel_phase.py'],g.__file__,'exec'),g.__dict__)
d=types.ModuleType('reviewed_decoder');exec(compile(sources['decode_client_state.py'],'reviewed_decoder','exec'),d.__dict__)
o={'__name__':'reviewed_observer','_REVIEWED_NATIVE_AUDIT_SOURCE':sources['native_journal_audit.py'].encode(),'_REVIEWED_PRODUCTION_PINS':pins}
exec(compile(sources['observe_cancel_phase_r10.py'],'reviewed_observer','exec'),o)
observation=o['observe'](plan,None)
need(observation['state']=='NO_MATCHING_ACCEPTED_TASK','request already admitted; no Send')
base=Path('/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/task-contracts')
template=base/'templates'/(plan['owner_request_sha256']+'.json');binding=base/'bindings'/(plan['owner_request_sha256']+'.json')
selected=Path('/proc/1/root/data/user/0/org.trillionnium.owneropen/files/owner-client-session-v1.bin');pending=selected.with_suffix('.pending')
def missing(p):
 need(p.parent.resolve(strict=False)==p.parent,'absence parent must not redirect')
 try:os.lstat(p)
 except FileNotFoundError:return
 raise ValueError('existing pending/consumed marker')
missing(binding);missing(pending)
meta=lambda p:[getattr(p.lstat(),k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
before={str(p):meta(p) for p in (template,selected)}
raw=o['stable'](template,65536);need(hashlib.sha256(raw).hexdigest()==plan['task_template_sha256'],'actual registration template pin')
t=json.loads(raw);need(t['request_sha256']==plan['owner_request_sha256'] and t['nonce']==plan['nonce'] and t['app_scope']==plan['app_scope'],'registration owner/nonce/app scope')
selected_raw=o['stable'](selected,65536);v=d.decode_client_state(selected_raw)
need(v['checksum_valid'] is True and all(v[k]==previous['identity'][k] for k in ('session_id','task_id','turn_id')) and v['turn_request_sha256']==previous['request_sha256'],'actual previous selected CAS')
missing(binding);missing(pending)
need(before=={str(p):meta(p) for p in (template,selected)},'preflight original generation changed')
need(o['stable'](template,65536)==raw and o['stable'](selected,65536)==selected_raw,'preflight complete raw bookends')
print(json.dumps({'state':'CURRENT_RUNTIME_REGISTERED_UNCONSUMED_PREVIOUS_SELECTED','observation':observation,'template':{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'base64':base64.b64encode(raw).decode()},'selected':{'bytes':len(selected_raw),'sha256':hashlib.sha256(selected_raw).hexdigest(),'base64':base64.b64encode(selected_raw).decode()},'metadata':before,'binding_lookup_errno':2,'pending_lookup_errno':2,'task_submissions':0,'ui_actions':0,'model_requests':0,'policy_writes':0,'automatic_retry':False},sort_keys=True))
'''


def preflight_request(actor_plan, previous, operator):
    names = {'active_runtime_r10.py', 'cancel_phase.py', 'decode_client_state.py', 'native_journal_audit.py',
        'observe_cancel_phase_r10.py', 'production-pins.json'}
    packet = encode({'plan':actor_plan, 'previous':previous,
        'sources':{name:operator['source/' + name].decode() for name in names}})
    need(len(packet) <= 262144, 'same existing observer payload limit')
    body = base64.b64encode(gzip.compress(packet, mtime=0)).decode()
    code = ('import base64,zlib,json\nd=zlib.decompressobj(31)\nb=d.decompress(base64.b64decode(' + repr(body) +
        ',validate=True),262145)\nassert len(b)<=262144 and d.eof and not d.unused_data and not d.unconsumed_tail\n'
        'import hashlib\nassert hashlib.sha256(b).hexdigest()==' + repr(sha(packet)) +
        '\nv=json.loads(b)\nplan=v["plan"];previous=v["previous"];sources=v["sources"]\n' + PREFLIGHT_SOURCE)
    command = '/data/adb/magisk/busybox timeout -s TERM -k 1 8 /data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -I -B -c ' + shlex.quote(code)
    need(len(('shell,v2,raw:/debug_ramdisk/su -c ' + shlex.quote(command)).encode()) < 65536, 'original phone wire bound')
    return {'kind':'shell', 'root':True, 'timeout_seconds':12, 'command':command}


class Coordinator:
    def __init__(self, plan, plan_raw, authority, loaded, reads):
        self.plan, self.authority, self.loaded, self.reads = plan, authority, loaded, reads
        self.root, self.O, self.final = loaded['root'], loaded['assembly'], loaded['final']
        self.out = Path(plan['out']); self.created = False; self.tickets = []
        self.chain = None; self.sender_handle = None
        create_directory(self.out); self.created = True
        put(self.out / 'PLAN.original.json', plan_raw)
        put(self.out / 'FINAL-AUTHORITY.original.json', encode(authority))
        self.chain = self.root.Chain.__new__(self.root.Chain)
        self.chain.p = {'nonce':plan['nonce']}; self.chain.out = self.out; self.chain.steps = []
        self.chain.remote_root = P4 + '/cpu-negative-controls-r1/' + plan['nonce']

    def once(self, phase, call, *, async_start=False):
        need(not any(t['phase'] == phase for t in self.tickets), 'phase already attempted; no automatic replay')
        ticket = {'phase':phase, 'call_entered':False, 'call_returned':False, 'async_registered':False}
        self.tickets.append(ticket)
        put(self.out / ('CALL-' + phase + '.json'), encode({'phase':phase, 'maximum_starts':1, 'automatic_retry':False}))
        ticket['call_entered'] = True
        value = call()
        if async_start:
            ticket['async_registered'] = True
        ticket['call_returned'] = True
        return value

    def remote(self, name, code, timeout=60):
        return self.once(name, lambda:self.chain.remote(name, code, timeout))

    def remote_program(self, name, argv, timeout):
        return self.once(name, lambda:self.chain.remote_program(name, argv, timeout))

    def phone(self, tag, request):
        return self.once('phone-' + tag, lambda:self.chain.phone(tag, request))

    def save(self, name, value):
        return put(self.out / name, value if type(value) is bytes else encode(value))

    def remote_originals(self, tag, paths):
        response = self.once(tag, lambda:self.chain.remote_read(tag, paths))
        need(response['state'] == 'ORIGINAL_HOST_FILES_READ' and set(response['files']) == set(paths),
            'complete original remote read set')
        rows, raws = {}, {}
        for key, value in response['files'].items():
            raw = base64.b64decode(value['base64'], validate=True)
            need(value['path'] == paths[key] and byte_pin(raw) == {k:value[k] for k in ('bytes', 'sha256')},
                'actual complete remote original')
            rows[key] = self.save(tag + '--' + key + '.original', raw); raws[key] = raw
        return rows, raws

    def remote_execution(self, phase):
        root = self.chain.remote_root + '/' + phase
        rows, _ = self.remote_originals('read-' + phase,
            {'terminal':root + '/RESULT.json', 'argv':root + '/ARGV.json',
             'stdout':root + '/stdout.original', 'stderr':root + '/stderr.original'})
        return {'host':phase_records(self.root, self.out / phase, stdin=True),
            'p4_terminal':rows['terminal'], 'p4_argv':rows['argv'], 'p4_stdout':rows['stdout'], 'p4_stderr':rows['stderr']}

    def archive(self, tag, row, *, phone=False):
        exact3({k:row[k] for k in ('path', 'bytes', 'sha256')})
        need(0 < row['bytes'] <= MAX_ARCHIVE, 'original full archive bound')
        identity = None; pieces = []
        for number, offset in enumerate(range(0, row['bytes'], CHUNK)):
            code = chunk_code({k:row[k] for k in ('path', 'bytes', 'sha256')}, offset, identity)
            name = tag + '-' + str(number).zfill(3)
            if phone:
                command = '/data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -I -B -c ' + shlex.quote(code)
                value = self.phone(name, {'kind':'shell', 'root':True, 'timeout_seconds':20, 'command':command})
            else:
                value = self.remote(name, code, 30)
            raw, identity = check_chunk(value, row, offset, identity); pieces.append(raw)
        complete = b''.join(pieces)
        need(byte_pin(complete) == {k:row[k] for k in ('bytes', 'sha256')}, 'complete reconstructed archive hash')
        self.O.unpack_archive(complete)  # Full single-gzip regular-only validation; no extraction/execution.
        return self.save(tag + '.tar.gz', complete)

    def run(self):
        p, source, final = self.plan, self.loaded['sources'], self.final
        # Late closure must have its exact writable namespace available before
        # the first Send. Existing case outputs are never adopted or retried.
        for family in ('cpu-cancel-negative-inputs-r1', 'cpu-cancel-negative-closures-r1'):
            private_parent(B / family)
            absent(B / family / p['nonce'])
        raw_inputs = {k:self.reads.read(v) for k, v in p['sender_inputs'].items()}
        raw_inputs['registration_template'] = self.reads.read(p['registration_template'])
        actor = make_actor_plan(p, raw_inputs, self.loaded['modules']); actor_raw = encode(actor)
        self.save('ACTOR-PLAN.original.json', actor_raw)
        for suffix in ('.local-once.json', '.send-result.json', '.actor.py'):
            absent(B / (p['sender_label'] + suffix))
        # These six fixed host-only family directories are preparation inputs.
        # Creating a missing family never creates a task or changes an existing
        # member; every actual case leaf is still create-only below.
        parents = [P4 + '/' + family for family in ('cpu-negative-controls-r1', 'cpu-negative-case-inputs-r1',
            'cancel-native-r10', 'native-cancel-intents-r10', 'cpu-cancel-p4-capture-inputs-r1',
            'cpu-cancel-p4-original-captures-r1')]
        prepare = self.root.REMOTE_IO + 'paths=' + repr(parents) + '\nfor p in paths:private_dir(Path(p),True)\nprint(json.dumps({"state":"FIXED_PRIVATE_HOST_PARENTS_READY","paths":paths},sort_keys=True))\n'
        prepared = self.remote('prepare-host-parents', prepare, 30)
        need(prepared == {'state':'FIXED_PRIVATE_HOST_PARENTS_READY', 'paths':parents}, 'exact host family preparation')
        # All previous/default plan assumptions are checked by the original pure
        # Actor validator above, including its stricter current 15..180s range.
        control_files = {'COORDINATOR-INPUT.json':encode({'nonce':p['nonce'], 'case_id':p['case_id'],
            'owner_request_sha256':sha(raw_inputs['request']), 'automatic_retry':False})}
        self.once('create-control', lambda:self.chain.remote_files('create-control', control_files, create_root=True))
        stage = {'ACTOR-PLAN.json':actor_raw, 'operator/MANIFEST.json':self.loaded['manifest_raw']}
        stage.update({'operator/' + name:raw for name, raw in self.loaded['operator'].items()})
        root = P4 + '/cpu-negative-case-inputs-r1/' + p['nonce']
        forbidden = [P4 + '/cancel-native-r10/' + p['actor_label'],
            '/home/alex/codex-hepta-natural-' + p['sender_label'] + '-root-v150',
            P4 + '/native-cancel-intents-r10/' + actor['owner_request_sha256'] + '.json']
        staged = self.remote('stage-actor', stage_code(root, stage, forbidden), 90)
        need(staged['state'] == 'EXACT_NEW_INPUTS_CREATED' and staged['files'] == {n:byte_pin(v) for n, v in stage.items()},
            'complete exact actor input readback')
        argv = actor_argv(p, final)
        preview = self.remote_program('actor-preview', argv[:-1], 30)
        pv = strict(preview['stdout'])
        need(pv['state'] == 'VALIDATED_NO_PHONE' and pv['plan_sha256'] == sha(actor_raw) and
            pv['package_sha256'] == final['ui_package_sha256'] and pv['phone_calls'] == 0, 'actual Actor preview')
        preflight = self.phone('negative-preflight', preflight_request(actor, strict(raw_inputs['previous']), self.loaded['operator']))
        need(preflight['state'] == 'CURRENT_RUNTIME_REGISTERED_UNCONSUMED_PREVIOUS_SELECTED' and
            base64.b64decode(preflight['template']['base64'], validate=True) == raw_inputs['registration_template'],
            'actual unconsumed registered template readback differs')
        self.save('PREFLIGHT.original.json', preflight)
        self.reads.recheck()
        # Only these two original programs may submit/cancel. Their own request,
        # selected/UI/viewport CAS, phase guard and once files remain unchanged.
        self.sender_handle = self.once('negative-sender', lambda:self.chain.execute_process(
            'negative-sender', sender_argv(p, self.authority), 660, None, async_start=True), async_start=True)
        actor_remote = self.remote_program('negative-cancel-actor', argv, actor['wait_seconds'] + 240)
        actor_execution = self.remote_execution('negative-cancel-actor')
        finish_async_phase(self.chain, self.root, 'negative-sender', self.sender_handle)
        sender_host = phase_records(self.root, self.out / 'negative-sender', stdin=False)
        sender_stdout = self.reads.read(sender_host['stdout'])
        sender_send = self.root.filedesc(B / (p['sender_label'] + '.send-result.json'))
        need(self.reads.read(sender_send) == sender_stdout, 'fixed sender stdout equals complete actual send result')
        actor_rows, actor_originals = self.remote_originals('read-actor-result',
            {'result':P4 + '/cancel-native-r10/' + p['actor_label'] + '/RESULT.json'})
        actual_actor = strict(actor_originals['result'])
        need(strict(actor_remote['stdout']) == {k:v for k, v in actual_actor.items() if k != 'last_original_observation'},
            'remote Actor terminal equals actual retained result')
        phone_plan = make_phone_plan(p, actor, actor_raw, actual_actor, final)
        phone_raw = self.O.encoded(phone_plan)
        phone_plan_row = self.save('PHONE-CAPTURE-PLAN.json', phone_raw)
        request = self.O.phone_request(source['phone'], phone_raw)
        phone_request_row = self.save('PHONE-CAPTURE-REQUEST.json', self.O.encoded(request))
        captured = self.phone('negative-capture', request)
        phone_host = phase_records(self.root, self.out / 'phone-negative-capture', stdin=True)
        operation_raw = self.reads.read(phone_host['stdout']); operation = strict(operation_raw)
        label = 'ng-' + p['nonce'] + '-negative-capture'
        wrapper_rows, wrapper_raws = self.remote_originals('read-phone-wrapper',
            {'wrapper':P4 + '/operations/' + label + '/result.json'})
        need(sha(wrapper_raws['wrapper']) == operation['wrapper_sha256'] and
            strict(wrapper_raws['wrapper']) == operation['wrapper'], 'actual phone wrapper complete raw pin')
        need(captured['export_complete'] is True and captured['issues'] == [] and
            captured['archive']['path'] == PHONE + '/negative-original-captures-r10-r1/' + p['nonce'] + '/originals.tar.gz',
            'phone complete fixed original archive')
        phone_archive = self.archive('phone-originals', captured['archive'], phone=True)
        # Copy original Root transport bytes to P4 with their original Mac
        # descriptors. The P4 collector explicitly disclaims original metadata
        # for these copied bytes; it preserves the mapping rather than relabeling.
        p4root = P4 + '/cpu-cancel-p4-capture-inputs-r1/' + p['capture_label']
        files = {'capture_p4_cancel_originals.py':source['p4'], 'ACTOR-PLAN.original.json':actor_raw,
            'operator/MANIFEST.json':self.loaded['manifest_raw'], 'cpu_cancel_originals.py':source['cpu']}
        files.update({'operator/' + name:raw for name, raw in self.loaded['operator'].items()})
        transport = {}
        for role, host in (('sender', sender_host), ('actor', actor_execution['host'])):
            transport[role] = {}
            for name, key in (('launch_request', 'intent'), ('terminal_operation', 'result'), ('stdout', 'stdout'), ('stderr', 'stderr')):
                relative = 'transport/' + role + '-' + name + '.original'; raw = self.reads.read(host[key]); files[relative] = raw
                transport[role][name] = {'original':host[key], 'retained_on_p4':descriptor(p4root + '/' + relative, raw)}
        p4plan = {'schema':'hepta.cpu-cancel.p4-original-capture-plan.v1', 'case_id':p['case_id'],
            'capture_label':p['capture_label'], 'actor_label':p['actor_label'], 'sender_label':p['sender_label'],
            'owner_request_sha256':actor['owner_request_sha256'], 'expected_scope':phone_plan['sender_scope'],
            'actor_plan':descriptor(p4root + '/ACTOR-PLAN.original.json', actor_raw),
            'operator_package':descriptor(p4root + '/operator/MANIFEST.json', self.loaded['manifest_raw']),
            'operator_sources':{n:descriptor(p4root + '/operator/source/' + n, self.loaded['operator']['source/' + n]) for n in OPERATOR_NAMES},
            'cpu_verifier_source':descriptor(p4root + '/cpu_cancel_originals.py', source['cpu']),
            'transport_originals':transport, 'out':P4 + '/cpu-cancel-p4-original-captures-r1/' + p['capture_label']}
        p4raw = self.O.encoded(p4plan); files['PLAN.json'] = p4raw
        p4plan_row = self.save('P4-CAPTURE-PLAN.json', p4raw)
        staged = self.remote('stage-p4-capture', stage_code(p4root, files, [p4plan['out']]), 90)
        need(staged['state'] == 'EXACT_NEW_INPUTS_CREATED' and staged['files'] == {n:byte_pin(v) for n, v in files.items()},
            'complete P4 capture input readback')
        p4argv = ['/usr/bin/python3', '-I', '-B', p4root + '/capture_p4_cancel_originals.py',
            '--plan', p4root + '/PLAN.json', '--plan-sha256', sha(p4raw), '--reviewed-source-sha256', sha(source['p4']), '--execute-host-only']
        p4run = self.remote_program('negative-p4-capture', p4argv, 90)
        p4summary = strict(p4run['stdout']); p4execution = self.remote_execution('negative-p4-capture')
        p4rows, p4raws = self.remote_originals('read-p4-result', {'result':p4summary['result']['path']})
        need(byte_pin(p4raws['result']) == {k:p4summary['result'][k] for k in ('bytes', 'sha256')}, 'actual P4 result pin')
        p4result = strict(p4raws['result'])
        need(p4result['archive'] == p4summary['archive'] and p4result['archive']['path'] == p4plan['out'] + '/ORIGINALS.tar.gz',
            'actual P4 archive and fixed namespace')
        p4archive = self.archive('p4-originals', p4result['archive'])
        closure = {'schema':self.O.SCHEMA, 'state':'ROOT_REVIEWED_EXISTING_NEGATIVE_ORIGINALS_ONLY',
            'case_id':p['case_id'], 'nonce':p['nonce'], 'scope':phone_plan['sender_scope'],
            'owner_request_sha256':actor['owner_request_sha256'], 'native_request_sha256':phone_plan['native_request_sha256'],
            'combination_sha256':final['combination_sha256'], 'sources':self.authority['sources'],
            'phone':{'plan':phone_plan_row, 'request':phone_request_row, 'operation':phone_host['stdout'],
                'wrapper':wrapper_rows['wrapper'], 'execution':phone_host, 'archive':phone_archive},
            'p4':{'plan':p4plan_row, 'execution':p4execution, 'result':p4rows['result'], 'archive':p4archive},
            'actor_execution':actor_execution,
            'sender':{**p['sender_inputs'], 'execution':sender_host,
                'generated_actor':self.root.filedesc(B / (p['sender_label'] + '.actor.py')),
                'local_once':self.root.filedesc(B / (p['sender_label'] + '.local-once.json')), 'send_result':sender_send},
            'out':str(B / 'cpu-cancel-negative-closures-r1' / p['nonce'])}
        self.O.validate_plan(closure)
        closure_input = B / 'cpu-cancel-negative-inputs-r1' / p['nonce']
        create_directory(closure_input); closure_raw = self.O.encoded(closure)
        closure_row = put(closure_input / 'PLAN.json', closure_raw)
        self.reads.recheck()
        closer = self.authority['closure_sources']['root_cpu_negative']
        mode = '--qualify-original-case-once' if p['qualify_physical_case'] else '--close-originals-once'
        close_argv = ['/usr/bin/python3', '-I', '-B', closer['path'], '--plan', closure_row['path'],
            '--plan-sha256', closure_row['sha256'], '--reviewed-source-sha256', closer['sha256'], mode]
        closed_raw = self.once('negative-host-close', lambda:self.chain.execute_process('negative-host-close', close_argv, 180))
        closed = strict(closed_raw)
        need(closed['case_id'] == p['case_id'] and closed['nonce'] == p['nonce'] and closed['phone_calls'] == 0 and
            closed['new_nonces'] == 0 and closed['automatic_retry'] is False, 'actual original CPU closure identity')
        need(not p['qualify_physical_case'] or closed['physical_case_pass'] is True, 'CPU safe-point physical qualification not established')
        result = {'schema':'hepta.cpu-cancel.coordinator-result.v1', 'state':'ORIGINAL_CANCEL_CAPTURE_AND_CPU_CLOSURE_RETURNED',
            'case_id':p['case_id'], 'nonce':p['nonce'], 'scope':phone_plan['sender_scope'],
            'closure_plan':closure_row, 'closure_result':closed,
            'four_original_phases':{'sender.execution':sender_host, 'actor_execution.host':actor_execution['host'],
                'phone.execution':phone_host, 'p4.execution.host':p4execution['host']},
            'physical_case_pass':closed['physical_case_pass'], 'host_isolated_qualification':None,
            'business_qualified':False, 'policy_changes':0, 'new_native_nonces':0,
            'automatic_retry':False, 'identity_release_permitted':False, 'steps':self.chain.steps}
        self.save('RESULT.json', result)
        return result

    def failure(self, error):
        cleanup = self.chain.close_owned_host_outputs() if self.chain is not None else None
        unresolved = [t for t in self.tickets if t['call_entered'] and not t['call_returned']]
        failure = {'schema':'hepta.cpu-cancel.coordinator-failure.v1', 'state':'UNKNOWN_OR_FAILED_SAME_IDENTITY_ORIGINALS_RETAINED',
            'case_id':self.plan['case_id'], 'nonce':self.plan['nonce'], 'error_type':type(error).__name__,
            'detail':str(error)[:2048], 'attempts':self.tickets, 'unresolved_call_ownership':unresolved,
            'host_output_cleanup':cleanup, 'remote_terminal_or_cleanup_proven':False,
            'same_identity_replay_permitted':False, 'new_identity_retry':False, 'automatic_retry':False,
            'signals_sent_by_coordinator':0, 'policy_changes':0, 'physical_case_pass':False,
            'host_isolated_qualification':None, 'business_qualified':False, 'identity_release_permitted':False}
        if self.created:
            try:
                self.save('FAILURE.json', failure)
            except BaseException as record_error:
                failure['failure_record_error'] = type(record_error).__name__ + ':' + str(record_error)[:512]
        return failure


def preview():
    return {'schema':'hepta.cpu-cancel.coordinator-preview.v1', 'state':'SOURCE_ONLY_NO_PRIVATE_CASE_READ',
        'allowed_cases':['NEG-08', 'NEG-09'], 'actual_authority_frozen':FINAL_AUTHORITY is not None,
        'new_native_nonces':0, 'phone_calls':0, 'sender_starts':0, 'cancel_starts':0,
        'case_credit':0, 'automatic_retry':False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan'); parser.add_argument('--plan-sha256'); parser.add_argument('--reviewed-source-sha256')
    parser.add_argument('--execute-once', action='store_true')
    args = parser.parse_args(argv)
    if not args.execute_once:
        print(encode(preview()).decode(), end=''); return 0
    authority = require_authority()  # Before a private case read, output creation or remote dispatch.
    need(args.plan and args.plan_sha256 and args.reviewed_source_sha256, 'three explicit source/plan bindings required')
    source_raw, _ = read_regular(Path(__file__).resolve(), 131072)
    need(sha(source_raw) == digest(args.reviewed_source_sha256), 'actual compiled coordinator source SHA')
    reads = ReadSet(); loaded = load_authority(authority, reads)
    plan_raw, _ = read_regular(args.plan, 262144)
    need(sha(plan_raw) == digest(args.plan_sha256), 'actual complete coordinator plan pin')
    plan = validate_case_plan(strict(plan_raw), authority)
    need(args.plan == str(B / 'cpu-cancel-negative-coordinator-inputs-r1' / plan['nonce'] / 'PLAN.json'),
        'fixed explicit existing coordinator plan namespace')
    os.umask(0o077); coordinator = None
    try:
        # Retain the object before its first create-only mkdir: partial setup
        # still has an owner and never becomes permission to choose a suffix.
        coordinator = Coordinator.__new__(Coordinator)
        Coordinator.__init__(coordinator, plan, plan_raw, authority, loaded, reads)
        coordinator.save('EXECUTED-SOURCE.original.py', source_raw)
        result = coordinator.run(); print(encode(result).decode(), end=''); return 0
    except BaseException as error:
        if coordinator is not None:
            failure = coordinator.failure(error); print(encode(failure).decode(), end='')
        raise


if __name__ == '__main__':
    raise SystemExit(main())
