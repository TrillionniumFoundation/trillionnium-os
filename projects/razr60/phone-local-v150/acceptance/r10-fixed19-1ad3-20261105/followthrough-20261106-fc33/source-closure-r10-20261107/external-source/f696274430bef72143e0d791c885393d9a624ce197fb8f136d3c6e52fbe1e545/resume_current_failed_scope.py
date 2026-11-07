#!/usr/bin/env python3
"""Resume only the exact normal closure tail of the current failed native scope.

Default: complete original host validation only. Explicit execution consumes one
create-only recovery intent before any ps, SSH or phone call. No sender, native
task, UI fixture, lifecycle launch, nonce, role, lease or runtime is recreated.
The original stopped sender capture remains unknown. The frozen closer alone
computes native call counts and unknown effects from complete retained originals.
"""
import argparse
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import textwrap
import types

sys.dont_write_bytecode=True
DATA=None
ANCHORS=None
META_FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
FORBIDDEN_TAIL_METHODS={'run','__init__','remaining','execute_process'}
ALLOWED_TAIL_METHODS={'bridge_call','frozen_phone','remote_files','remote_program','remote_read','push_copy'}
TAIL_OUTPUTS=('RECOVERY-INTENT.json', 'RECOVERY-RESULT.json', 'RECOVERY-FAILURE.json', 'phone-role-end', 'phone-snapshot', 'ORIGINALS.tar.gz', 'stage-closure-inputs', 'stage-closure-plan', 'close', 'closed-originals', 'CLOSURE.json', 'INVENTORY.json', 'phone-push-closed-closure', 'phone-copy-closed-closure', 'phone-push-closed-inventory', 'phone-copy-closed-inventory', 'phone-late-publish', 'phone-boundary-read', 'LATE-BOUNDARY.original.json', 'LATE-BOUNDARY-DESCRIPTOR.json', 'latest-previous-original', 'ACTUAL-PREVIOUS-INPUT.json', 'ROOT-RESULT.json', 'RECOVERY-ADMISSION.json', 'recovery-sender-pid-observation', 'recovery-p4-originals', 'phone-recovery-originals')
INPUTS_BYTES=147263
INPUTS_SHA256='9427cd70e67b2f3c35cdba0b59086978116d97134310631027e66391e93f752c'

def need(value,message):
    if not value:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()


def strict(raw):
    def pairs(items):
        value={}
        for key,item in items:
            need(key not in value,'duplicate JSON key');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))


def descriptor(path,raw):
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}


def metadata(value):return [getattr(value,key) for key in META_FIELDS]


class Originals:
    def __init__(self):self.rows={}
    def read(self,path,expected=None,limit=64*1024*1024):
        path=Path(path)
        need(path.is_absolute() and path.resolve(strict=True)==path,'canonical original path required')
        fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
        try:
            before=os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink==1
                 and 0<=before.st_size<=limit,'bounded regular original required')
            with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(limit+1)
            need(metadata(before)==metadata(os.fstat(fd))==metadata(path.lstat())
                 and len(raw)==before.st_size,'original changed during read')
        finally:os.close(fd)
        row=descriptor(path,raw)
        if expected is not None:
            need(isinstance(expected,dict) and set(expected)=={'path','bytes','sha256'}
                 and type(expected['bytes']) is int and expected['bytes']>=0
                 and re.fullmatch('[0-9a-f]{64}',expected['sha256'])
                 and row==expected,'exact original descriptor differs')
        full={**row,'metadata':metadata(before)}
        if str(path) in self.rows:need(self.rows[str(path)]==full,'original metadata or bytes changed')
        self.rows[str(path)]=full
        return raw
    def pin(self,row):return self.read(row['path'],row)
    def recheck(self):
        rows=list(self.rows.values())
        for row in rows:
            self.read(row['path'],{key:row[key] for key in ('path','bytes','sha256')})
        return len(rows)


def absent(path):
    try:Path(path).lstat()
    except FileNotFoundError as error:
        need(error.errno==2,'absence must be ENOENT');return
    raise ValueError('recovery output or original sender wait already exists: '+str(path))


def tail_source(coordinator_raw):
    text=coordinator_raw.decode('utf-8');tree=ast.parse(text)
    classes=[node for node in tree.body if isinstance(node,ast.ClassDef) and node.name=='Chain']
    need(len(classes)==1,'one frozen Chain class required')
    runs=[node for node in classes[0].body if isinstance(node,ast.FunctionDef) and node.name=='run']
    need(len(runs)==1,'one frozen Chain.run required');run=runs[0]
    matches=[]
    for index,node in enumerate(run.body):
        if (isinstance(node,ast.Expr) and isinstance(node.value,ast.Call)
            and isinstance(node.value.func,ast.Attribute)
            and isinstance(node.value.func.value,ast.Name) and node.value.func.value.id=='self'
            and node.value.func.attr=='bridge_call'
            and [arg.value for arg in node.value.args if isinstance(arg,ast.Constant)]==['role-end','role-end']):
            matches.append(index)
    need(len(matches)==1,'one exact normal role-end tail required')
    statements=run.body[matches[0]:]
    need(isinstance(statements[-1],ast.Return),'complete original return tail required')
    lines=text.splitlines(keepends=True)
    original=''.join(lines[statements[0].lineno-1:run.end_lineno])
    body=textwrap.dedent(original)
    candidate='def resume_original_tail(self,p,home,staging,entry,sender_dir):\n'+textwrap.indent(body,'    ')
    compiled_tree=ast.parse(candidate);function=compiled_tree.body[0]
    need([ast.dump(node,include_attributes=False) for node in function.body]
         ==[ast.dump(node,include_attributes=False) for node in statements],
         'tail AST differs from frozen original')
    need(textwrap.indent(body,'        ')==original,'tail whole-byte inverse differs')
    calls=set()
    for node in ast.walk(function):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute):
            if isinstance(node.func.value,ast.Name) and node.func.value.id=='self':calls.add(node.func.attr)
    need(not (calls & FORBIDDEN_TAIL_METHODS) and calls==ALLOWED_TAIL_METHODS,
         'recovery tail gained a sender, launch, fixture or generic entry')
    for node in ast.walk(function):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='frozen_phone':
            need(isinstance(node.args[0],ast.Constant) and node.args[0].value in ('snapshot','late-publish'),
                 'only original snapshot and late publish phone programs allowed')
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='remote_program':
            need(isinstance(node.args[0],ast.Constant) and node.args[0].value=='close',
                 'only original host closure program allowed')
    proof={'coordinator':ANCHORS['coordinator'],'tail_original_bytes':len(original.encode()),
           'tail_original_sha256':sha(original.encode()),'tail_function_bytes':len(candidate.encode()),
           'tail_function_sha256':sha(candidate.encode()),'original_first_line':statements[0].lineno,
           'original_last_line':run.end_lineno,'ast_statement_count':len(statements),
           'whole_byte_inverse_equal':True,'all_original_tail_statements_equal':True,
           'self_methods':sorted(calls),'new_send':False,'new_launch':False,'new_fixture':False,
           'lease_extension':False,'sender_wait_fabricated':False}
    return candidate,original,proof


def original_record(row, *, metadata_required):
    required = {'path','bytes','sha256','base64'} | ({'metadata'} if metadata_required else set())
    need(set(row) == required and type(row['bytes']) is int and row['bytes'] >= 0,
         'complete original envelope required')
    raw = base64.b64decode(row['base64'], validate=True)
    need(base64.b64encode(raw).decode() == row['base64'] and len(raw) == row['bytes']
         and sha(raw) == row['sha256'], 'original envelope bytes differ')
    if metadata_required:
        need(len(row['metadata']) == 9 and all(type(v) is int for v in row['metadata'])
             and row['metadata'][6] == len(raw), 'original full9 differs')
    return raw

def phone_value(raw):
    value = strict(raw)
    need(type(value['actor_rc']) is int and value['actor_rc'] == 0
         and value['wrapper']['status'] == 'command_exited', 'original phone actor terminal differs')
    phone = value['wrapper']['phone']
    need(type(phone['rc']) is int and phone['rc'] == 0 and phone['stderr'] == '',
         'original phone read was not terminal zero')
    return strict(phone['stdout'].encode())

def validate_sender_terminal(raw, plan):
    sent = strict(raw)
    need(type(sent.get('rc')) is int and sent['rc'] == 0 and sent.get('stderr') == ''
         and isinstance(sent.get('stdout'), str), 'actual P4 sender failed/unknown; retain originals')
    actor = strict(sent['stdout'].strip().splitlines()[-1].encode())
    need(actor['state'] == 'ORIGINAL_NATIVE_TERMINAL_OBSERVED'
         and actor['draft_restore']['state'] == 'ORIGINAL_DRAFT_RESTORED',
         'native terminal/draft restoration not proven')
    need(actor['out'] == DATA['identity']['sender_dir']
         and actor['prompt_sha256'] == plan['request']['sha256']
         and actor['retirement_resolution_sha256'] == plan['sender_retirement_resolution']['sha256']
         and actor['send_attempt_count'] == 1 and actor['automatic_replay'] is False
         and actor['business_success_verified'] is False
         and actor['independent_collector_required'] is True
         and actor['draft_restore'] == {'state':'ORIGINAL_DRAFT_RESTORED',
              'restore_attempts':1, 'original_draft_submitted':False},
         'actual one-Send/restoration original identity differs')
    return actor

def validate_host_records(data, blobs, sender_raw):
    """Pure checks over exact retained original bytes; no path access or target call."""
    need(set(blobs) == {row['relative'] for row in data['host_originals']}
         and len(blobs) == 209, 'complete 209 retained original set required')
    for row in data['host_originals']:
        raw = blobs[row['relative']]
        need(len(raw) == row['original']['bytes'] and sha(raw) == row['original']['sha256'],
             'retained host original pin differs: ' + row['relative'])
    def raw(name):
        return blobs['scope/' + name]
    def value(name):
        return strict(raw(name))
    plan = value('ROOT-PLAN.original.json')
    need(raw('ROOT-PLAN.original.json') == blobs['selected-host-plan/ROOT-PLAN.json']
         and descriptor(ANCHORS['root_plan']['path'], raw('ROOT-PLAN.original.json')) == ANCHORS['root_plan'],
         'original selected plan changed')
    identity = data['identity']
    need(plan['label'] == identity['label'] and plan['nonce'] == identity['nonce']
         and plan['case_id'] == 'NEG-01' and plan['out'] == identity['host_out']
         and plan['package'] == data['runtime_manifest']
         and plan['source_package'] == data['root_source_manifest'], 'current original identity differs')
    failed = value('ROOT-FAILURE.json')
    need(failed['state'] == 'FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED_NO_AUTOMATIC_CONTINUATION'
         and failed['error_type'] == 'ValueError'
         and failed['detail'] == 'component ended before phase; preserve, no additional Root UI'
         and failed['automatic_retry'] is False and failed['send_again'] is False
         and failed['new_identity_retry'] is False
         and [row['phase'] for row in failed['steps']] == data['original_phases'],
         'actual launch/setup then before-guard failure differs')
    for result in failed['steps']:
        phase = result['phase']
        need(value(phase+'/RESULT.json') == result and result['state'] == 'ORIGINAL_HOST_CHILD_JOINED'
             and type(result['returncode']) is int and result['returncode'] == 0
             and result['automatic_retry'] is False, 'original joined host phase differs')
        intent = value(phase+'/INTENT.json'); child = value(phase+'/CHILD.json')
        capture = value(phase+'/OUTPUT-CAPTURE.json')
        need(intent['schema'] == 'hepta.native-guard.root-host-command.v1'
             and intent['phase'] == phase and intent['maximum_starts'] == 1
             and intent['automatic_retry'] is False and intent['signals_on_timeout'] is False
             and child['pid'] == result['pid'] and child['maximum_starts'] == 1
             and child['source_intent_sha256'] == sha(raw(phase+'/INTENT.json')),
             'original phase child/intent binding differs')
        for stream in ('stdout','stderr'):
            expected = descriptor(identity['host_out']+'/'+phase+'/'+stream+'.original',
                                  raw(phase+'/'+stream+'.original'))
            need(expected == result[stream], 'original phase output differs')
        need(raw(phase+'/stderr.original') == b'' and capture['child_wait_returned'] is True
             and capture['child_returncode'] == 0 and capture['stdout_eof'] is True
             and capture['stderr_eof'] is True and capture['prefix_only_or_unknown'] is False,
             'original completed phase capture is incomplete')
        if intent['stdin_sha256'] is not None:
            need(sha(raw(phase+'/stdin.original')) == intent['stdin_sha256'], 'original retained stdin differs')
    prepared = value('material/PREPARED.json'); lease = value('material/tree/LEASE.json')
    intent = value('CHAIN-INTENT.json')
    need(prepared['phone_home'] == identity['phone_home']
         and prepared['label'] == lease['label'] == plan['label']
         and prepared['nonce'] == lease['nonce'] == plan['nonce']
         and prepared['package_sha256'] == lease['package_sha256'] == plan['package']['sha256']
         and prepared['combination']['sha256'] == lease['combination']['sha256'] == data['combination_sha256']
         and prepared['lease'] == {k:ANCHORS['lease'][k] for k in ('bytes','sha256')}
         and lease['expires_unix_ms'] == intent['lease_expires_unix_ms'] == data['original_expiry_unix_ms']
         and intent['automatic_lease_extension'] is False and intent['maximum_native_sends'] == 1
         and intent['maximum_detached_launches'] == 1,
         'original fixed 600-second lease or prepared identity changed')
    args = value('prepare-material/INTENT.json')['argv']
    need(args[args.index('--expires-unix-ms')+1] == str(lease['expires_unix_ms'])
         and raw('prepare-material/stdout.original') == raw('material/PREPARED.json'),
         'original preparation invocation differs')
    archive = raw('material/component-inputs.tar.gz')
    need({'bytes':len(archive),'sha256':sha(archive)} == prepared['archive'], 'original staged archive differs')
    manifest_raw = raw('material/tree/package/MANIFEST.json')
    need(len(manifest_raw) == plan['package']['bytes'] and sha(manifest_raw) == plan['package']['sha256'],
         'actual staged runtime manifest differs')
    manifest = strict(manifest_raw)
    need(manifest['schema'] == 'hepta.native-guard.adapter-package.v1' and len(manifest['files']) == 32
         and len({row['path'] for row in manifest['files']}) == 32, 'exact frozen 32 runtime members required')
    for row in manifest['files']:
        member = raw('material/tree/package/'+row['path'])
        need(len(member) == row['bytes'] and sha(member) == row['sha256'], 'actual 32-member original differs')
    sender_child = value('sender-execute/CHILD.json'); sender_capture = value('sender-execute/OUTPUT-CAPTURE.json')
    need(sender_child['pid'] == sender_child['pgid'] == sender_child['sid'] == data['original_sender_pid']
         and sender_child['source_intent_sha256'] == sha(raw('sender-execute/INTENT.json'))
         and sender_child['maximum_starts'] == 1 and sender_capture['child_wait_returned'] is False
         and sender_capture['child_returncode'] is None
         and sender_capture['stdout_eof'] is False and sender_capture['stderr_eof'] is False
         and sender_capture['prefix_only_or_unknown'] is True
         and sender_capture['remote_terminal_or_cleanup_proven'] is False,
         'original sender capture unknown must remain original')
    setup = phone_value(raw('phone-plan-setup/stdout.original'))
    need(setup['state'] == 'ACTUAL_PHASE_ORIGINALS_READ' and setup['phase'] == 'setup'
         and set(setup['files']) == {'ACCEPTED.json','BOUND-CONTRACT.json','ROOT-SETUP-PLAN.json'},
         'actual setup original envelope differs')
    setup_raw = {k:original_record(v,metadata_required=True) for k,v in setup['files'].items()}
    for key, value_row in setup['files'].items():
        need({k:value_row[k] for k in ('path','bytes','sha256','metadata')} == data['setup_phone'][key],
             'actual retained phone original identity differs')
    accepted = strict(setup_raw['ACCEPTED.json']); bound = strict(setup_raw['BOUND-CONTRACT.json'])
    phase_plan = strict(setup_raw['ROOT-SETUP-PLAN.json'])
    need(accepted['run_dir'] == identity['run_dir'] and accepted['scope'] == data['native_scope']
         and setup['scope'] == phase_plan['scope'] == accepted['scope']
         and phase_plan['phase'] == 'setup' and bound['lease_sha256'] == ANCHORS['lease']['sha256']
         and phase_plan['contract_sha256'] == accepted['contract_sha256'], 'actual setup scope differs')
    p4 = value('fixture-originals-setup/stdout.original')
    need(p4['state'] == 'ORIGINAL_HOST_FILES_READ' and set(p4['files']) == {'terminal','index'},
         'actual setup P4 originals missing')
    p4_raw = {key:original_record(row,metadata_required=False) for key,row in p4['files'].items()}
    for key,row in p4['files'].items():
        need({k:row[k] for k in ('path','bytes','sha256')} == data['setup_p4'][key],
             'setup P4 byte identity differs; historical full9 is unavailable')
    terminal = strict(p4_raw['terminal'])
    need(terminal['state'] == 'OWNED_ROOT_FIXTURE_CHILD_JOINED' and terminal['child_wait_returned'] is True
         and terminal['child_returncode'] == 0 and len(terminal['group_absence_observations']) == 2
         and failed['root_fixture_attempts'] == [{'phase':'setup','terminal':data['setup_p4']['terminal']}],
         'actual complete setup parent attempt must be preserved')
    fixture = value('ROOT-FIXTURE-setup.INTENT.json')
    need(fixture['expected_terminal_path'] == data['setup_p4']['terminal']['path']
         and fixture['maximum_child_starts'] == 1 and fixture['automatic_retry'] is False,
         'original sole Root fixture intent differs')
    for option,key in (('--plan-sha256','ROOT-SETUP-PLAN.json'),
                       ('--bound-contract-sha256','BOUND-CONTRACT.json'),('--accepted-sha256','ACCEPTED.json')):
        need(fixture['argv'][fixture['argv'].index(option)+1] == sha(setup_raw[key]),
             'Root fixture original argv identity differs')
    packed_outer = value('pack-setup/stdout.original')
    need(packed_outer['returncode'] == 0 and packed_outer['stderr'] == '', 'actual original witness pack failed')
    packed = strict(packed_outer['stdout'].encode())
    published = phone_value(raw('phone-publish-setup/stdout.original'))
    need(packed['scope'] == accepted['scope'] and packed['phase_plan_sha256'] == sha(setup_raw['ROOT-SETUP-PLAN.json'])
         and published == {'component_qualified':False,'mailbox_sha256':packed['mailbox']['sha256'],
             'native_dispatches_by_publisher':0,'phase':'setup','state':'ORIGINAL_ROOT_WITNESS_BYTES_PUBLISHED_ONCE'},
         'actual setup witness publication differs')
    ended = phone_value(raw('phone-plan-before-guard/stdout.original'))
    need(ended['state'] == 'ORIGINAL_COMPONENT_ENDED_BEFORE_PHASE' and ended['phase'] == 'before-guard'
         and ended['effects'] == 0, 'original before-guard stop differs')
    end_raw = original_record(ended['original'],metadata_required=True)
    need({k:ended['original'][k] for k in ('path','bytes','sha256','metadata')} == data['provider_ended'],
         'actual provider end marker differs')
    marker = strict(end_raw)
    need(marker['original_cleanup_and_late_inventory_required'] is True
         and marker['native_turn_verified'] is False and marker['kernel_observation_completed'] is False,
         'provider marker must not be treated as native or cleanup proof')
    need(descriptor(ANCHORS['sender_result']['path'],sender_raw) == ANCHORS['sender_result'],
         'actual later Mac sender result differs')
    actor = validate_sender_terminal(sender_raw,plan)
    return {'plan':plan,'manifest':manifest,'failed':failed,'prepared':prepared,'lease':lease,
        'actor':actor,'accepted':accepted,'setup_phone_raw':setup_raw,'setup_p4_raw':p4_raw,
        'proof':{'host_original_count':209,'original_joined_phase_count':19,'runtime_file_count':32,
            'setup_attempt_count':1,'setup_phone_full9_count':3,'historical_setup_p4_full9_available':False,
            'original_sender_parent_join_observed':False,'original_sender_pipe_eof_observed':False,
            'sender_terminal_original':ANCHORS['sender_result'], 'native_hash_chain_verified':False,
            'actual_native_calls':None,'unknown_effects':None,'complete_closure_still_required':True}}

def load_coordinator(originals):
    raw = originals.pin(ANCHORS['coordinator'])
    tail, original, proof = tail_source(raw)
    need(len(original.encode()) == 5662
         and sha(original.encode()) == '776474bbc6816f24e5ca8f8d21b6a4e59a362d13553b861c9ba5ed4825623050',
         'exact current normal tail differs')
    module = types.ModuleType('reviewed_current_same_scope_coordinator')
    module.__file__ = ANCHORS['coordinator']['path']
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    exec(compile(tail,module.__file__+':exact-original-tail','exec'),module.__dict__)
    need(module.PKG == DATA['runtime_manifest']['sha256']
         and module.COMBINATION == DATA['combination_sha256'], 'actual current source generation differs')
    return module,proof

def not_consumed():
    out = Path(DATA['identity']['host_out'])
    for name in TAIL_OUTPUTS:
        absent(out/name)
    absent(out/'sender-execute/JOINED.json')
    need(not any(p.name.startswith('phone-chunk-') for p in out.iterdir()), 'original snapshot chunk already exists')
    for phase in ('before-guard','after-guard'):
        for name in ('ROOT-FIXTURE-'+phase+'.INTENT.json','store-plan-'+phase,'fixture-'+phase,
            'fixture-originals-'+phase,'pack-'+phase,'phone-push-witness-'+phase,
            'phone-copy-witness-'+phase,'phone-publish-'+phase):
            absent(out/name)

def preflight(source_sha256):
    global DATA, ANCHORS
    originals = Originals()
    source_path = Path(__file__).resolve(strict=True)
    self_raw = originals.read(source_path,limit=131072)
    need(sha(self_raw) == source_sha256, 'explicit reviewed recovery source SHA required')
    input_path = source_path.parent.parent/'INPUTS.json'
    input_raw = originals.read(input_path,limit=2*1024*1024)
    need(len(input_raw) == INPUTS_BYTES and sha(input_raw) == INPUTS_SHA256, 'reviewed recovery inputs differ')
    DATA = strict(input_raw); ANCHORS = DATA['anchors']
    need(DATA['schema'] == 'hepta.native-current.same-scope-recovery-inputs.v1', 'fixed recovery input schema')
    blobs = {}
    for row in DATA['host_originals']:
        expected = row['original']
        raw = originals.pin({k:expected[k] for k in ('path','bytes','sha256')})
        need(originals.rows[expected['path']]['metadata'] == expected['metadata'],
             'retained historical host full9 changed: '+row['relative'])
        blobs[row['relative']] = raw
    sender_raw = originals.pin(ANCHORS['sender_result'])
    current = validate_host_records(DATA,blobs,sender_raw)
    module,tailproof = load_coordinator(originals)
    tracked_read = lambda path,n=64*1024*1024: originals.read(path,limit=n)
    module.read = tracked_read
    plan,manifest = module.validate_plan(blobs['scope/ROOT-PLAN.original.json'])
    need(plan == current['plan'] and manifest == current['manifest'], 'complete unchanged Root plan validator differs')
    bridge = originals.pin(ANCHORS['bridge'])
    reader_path = source_path.parent/'read_existing_originals.py'
    reader_raw = originals.read(reader_path,limit=32768)
    need(len(reader_raw) == DATA['reader_template']['bytes']
         and sha(reader_raw) == DATA['reader_template']['sha256'], 'reviewed read-only program template differs')
    out = Path(plan['out'])
    need(out.resolve(strict=True) == out and stat.S_ISDIR(out.lstat().st_mode)
         and stat.S_IMODE(out.lstat().st_mode) == 0o700, 'original private output directory differs')
    not_consumed()
    originals.recheck()
    chain = object.__new__(module.Chain)
    chain.p=plan; chain.out=out; chain.steps=list(current['failed']['steps'])
    chain.sender=None; chain.sender_files=None
    chain.remote_root=DATA['identity']['remote_root']; chain.material=out/'material'
    chain.prepared=current['prepared']; chain.lease=current['lease']
    chain.root_attempts=current['failed']['root_fixture_attempts']; chain.bridge=bridge
    summary={'schema':'hepta.native-current.same-scope-recovery-admission.v1',
        'state':'HOST_ORIGINALS_VALIDATED_REMOTE_RECOVERY_ADMISSION_PENDING',
        'source':descriptor(source_path,self_raw),'inputs':descriptor(input_path,input_raw),
        'original_root_failure':ANCHORS['root_failure'],'original_plan':ANCHORS['root_plan'],
        'original_expiry_unix_ms':current['lease']['expires_unix_ms'],'original_lease_duration_seconds':600,
        'lease_extended':False,'tail':tailproof,'host_proof':current['proof'],
        'host_originals':list(originals.rows.values()),'host_originals_count':len(originals.rows),
        'original_sender_wait_fabricated':False,'new_nonce':False,'new_send':False,
        'new_fixture':False,'new_launch':False,'automatic_retry':False,
        'phone_calls_by_preflight':0,'remote_calls_by_preflight':0,
        'native_effects_classified':False,'unknown_effects':None,'component_qualified':False}
    return module,chain,originals,current,summary,reader_raw

def reader_config(kind):
    identity=DATA['identity']; home=identity['phone_home']; remote=identity['remote_root']
    files={}; optional={}
    def add(key,path,expected=None):
        files[key]={'path':path,'expected':expected}
    if kind == 'phone':
        add('home/LEASE.json',home+'/LEASE.json',
            {**{k:ANCHORS['lease'][k] for k in ('bytes','sha256')},'path':home+'/LEASE.json'})
        for name,row in DATA['setup_phone'].items():
            add('home/'+name,row['path'],row)
        add('home/PROVIDER-ENDED.json',DATA['provider_ended']['path'],DATA['provider_ended'])
        for name in ('SUPERVISOR.json','provider.SPAWNED.json','provider.JOINED.json',
            'sidecar.SPAWNED.json','sidecar.JOINED.json','LIFECYCLE-ENDED.json'):
            add('home/'+name,home+'/'+name)
        for name in ('accepted.json','terminal.json'):
            add('run/'+name,identity['run_dir']+'/'+name)
        optional={'run/listener-failure.json':identity['run_dir']+'/listener-failure.json'}
        package={**DATA['runtime_manifest'],'path':home+'/package/MANIFEST.json'}
        absent_paths=[DATA['phone_capture_out'],DATA['phone_boundary_out'],DATA['phone_boundary_out']+'.json']
    else:
        for key,row in DATA['setup_p4'].items():
            add('setup/'+key,row['path'],row)
        for name in ('SEND-NATIVE-LATENCY.json','DRAFT-RESTORE-RESULT.json'):
            add('sender/'+name,identity['sender_dir']+'/'+name)
        add('material/LEASE.json',remote+'/material/tree/LEASE.json',
            {**{k:ANCHORS['lease'][k] for k in ('bytes','sha256')},'path':remote+'/material/tree/LEASE.json'})
        package={**DATA['runtime_manifest'],'path':remote+'/material/tree/package/MANIFEST.json'}
        absent_paths=[remote+'/'+name for name in ('closure','close','closure-inputs','CLOSURE-PLAN.json')]
        for tag in DATA['tail_phone_tags']:
            label='ng-'+identity['nonce']+'-'+tag
            absent_paths += ['/home/alex/razr60-local-model-v150/requests/'+label+'.json',
                '/home/alex/razr60-local-model-v150/operations/'+label,remote+'/phone-'+tag]
        for tag in ('chunk-'+str(i) for i in range(128)):
            absent_paths.append('/home/alex/razr60-local-model-v150/requests/ng-'+identity['nonce']+'-'+tag+'.json')
    return {'schema':'hepta.native-current.recovery-read-config.v1','kind':kind,'files':files,
        'optional':optional,'absent':absent_paths,'package':package,
        'boot_id':DATA['identity']['boot_id'],'template_sha256':DATA['reader_template']['sha256']}

def reader_program(template,config):
    marker=b'CONFIG = None\n'
    need(template.count(marker) == 1, 'single inert reader configuration required')
    program=template.replace(marker,('CONFIG = '+repr(config)+'\n').encode())
    compile(program,'reviewed_existing_originals_'+config['kind'],'exec')
    return program

def validate_remote_read(report,config):
    need(report['state'] == 'EXISTING_ORIGINALS_READ_ONLY_BOOKENDS_EQUAL'
         and report['kind'] == config['kind'] and report['bookend_equal'] is True
         and report['template_sha256'] == config['template_sha256']
         and report['absent'] == config['absent']
         and set(report['files']) == set(config['files'])|set(config['optional'])
         and len(report['runtime']) == 33 and report['file_writes'] == 0
         and report['child_processes_started'] == 0 and report['network_calls'] == 0
         and report['signals_sent'] == 0 and report['global_unknown_effect_count'] is None,
         'complete read-only original receipt required')
    raws={}
    for key,row in report['files'].items():
        if not row['exists']:
            need(key in config['optional'] and row == {'path':config['optional'][key],
                'exists':False,'reason':'ENOENT'}, 'required original missing')
            continue
        need(set(row) == {'path','exists','bytes','sha256','metadata','base64'}, 'complete fresh full9 original required')
        expected=config['files'][key]['expected'] if key in config['files'] else None
        path=config['files'][key]['path'] if key in config['files'] else config['optional'][key]
        need(row['path'] == path, 'fresh original path differs')
        if expected is not None:
            need({k:row[k] for k in expected} == expected, 'fresh original pin differs')
        raws[key]=original_record({k:v for k,v in row.items() if k!='exists'},metadata_required=True)
    expected_runtime={'MANIFEST.json':config['package']}
    for item in DATA['runtime_files']:
        expected_runtime[item['path']]={'path':str(Path(config['package']['path']).parent/item['path']),
            'bytes':item['bytes'],'sha256':item['sha256']}
    need(set(report['runtime'])==set(expected_runtime), 'fresh complete runtime set differs')
    for key,row in report['runtime'].items():
        need(set(row)=={'path','exists','bytes','sha256','metadata'} and row['exists'] is True
             and {k:row[k] for k in ('path','bytes','sha256')}==expected_runtime[key]
             and len(row['metadata'])==9 and all(type(v) is int for v in row['metadata'])
             and row['metadata'][5]==1 and row['metadata'][6]==row['bytes'],
             'fresh runtime original full9 or exact bytes differ')
    return raws

def observe_original_sender_absence(module,chain,originals):
    tag='recovery-sender-pid-observation'
    # The frozen transport retains the actual ps rc=1 as a joined read-only
    # observation. A present/reused PID, read error or timeout is rejected.
    error=None
    try:
        chain.execute_process(tag,['/bin/ps','-p',str(DATA['original_sender_pid']),'-o','pid='],10)
    except BaseException as exc:
        error=exc
    path=chain.out/tag
    result=strict(originals.read(path/'RESULT.json'))
    capture=strict(originals.read(path/'OUTPUT-CAPTURE.json'))
    need(isinstance(error,ValueError) and str(error)=='original phase failed; no replay: '+tag
         and result['state']=='ORIGINAL_HOST_CHILD_JOINED' and type(result['returncode']) is int
         and result['returncode']==1 and originals.pin(result['stdout'])==originals.pin(result['stderr'])==b''
         and capture['child_wait_returned'] is True and capture['child_returncode']==1
         and capture['stdout_eof'] is True and capture['stderr_eof'] is True,
         'original sender PID absence not established; no signal or retry')
    return {'pid':DATA['original_sender_pid'],'observation':module.filedesc(path/'RESULT.json'),
        'observed_pid_absent':True,'parent_wait_not_claimed':True,'original_sender_joined':False,
        'process_group_absence_proven':False,'pid_reuse_if_present_is_not_admitted':True,'signals_sent':0}

def fresh_admission(module,chain,originals,current,template):
    pid=observe_original_sender_absence(module,chain,originals)
    p4_config=reader_config('p4'); p4_program=reader_program(template,p4_config)
    p4=chain.remote('recovery-p4-originals',p4_program.decode(),45)
    p4_raw=validate_remote_read(p4,p4_config)
    latency=strict(p4_raw['sender/SEND-NATIVE-LATENCY.json'])
    need(latency['state']=='ORIGINAL_NATIVE_TERMINAL_OBSERVED'
         and latency['scope']==DATA['native_scope']
         and latency['owner_request_utf8_sha256']==chain.p['request']['sha256']
         and latency['native_status']==current['actor']['native_status']
         and latency['send_attempt_count']==1 and latency['automatic_send_retry'] is False,
         'actual P4 terminal latency does not bind this original native scope')
    restored=strict(p4_raw['sender/DRAFT-RESTORE-RESULT.json'])
    draft=strict(originals.pin(chain.p['preserved_draft']))
    need(restored.get('state')=='ORIGINAL_DRAFT_RESTORED' and restored.get('restore_attempts')==1
         and restored.get('utf8_sha256')==draft['utf8_sha256']
         and restored.get('original_draft_submitted') is False and restored.get('model_business_credit') is False,
         'original draft restoration remains incomplete or belongs to another input')
    phone_config=reader_config('phone'); phone_program=reader_program(template,phone_config)
    command=module.ENV+'/usr/bin/python3 -I -B -S -c '+shlex.quote(phone_program.decode())
    wire=('shell,v2,raw:/debug_ramdisk/su -c '+shlex.quote(command)).encode()
    need(len(wire)<65536,'actual original-read wire exceeds fixed limit')
    phone=chain.phone('recovery-originals',{'kind':'shell','root':True,'timeout_seconds':40,'command':command})
    phone_raw=validate_remote_read(phone,phone_config)
    need(phone['boot_id']==chain.p['boot_id'], 'original boot changed')
    accepted=strict(phone_raw['home/ACCEPTED.json'])
    need(accepted==current['accepted'], 'fresh accepted scope differs')
    ended=strict(phone_raw['home/LIFECYCLE-ENDED.json'])
    need(ended['schema']=='hepta.native-guard.lifecycle-ended.v1'
         and ended['roles_joined_and_groups_absent'] is True and ended['model_requests']==0
         and ended['automatic_restart'] is False,'actual lifecycle end/join required before normal snapshot')
    for role in ('provider','sidecar'):
        joined=strict(phone_raw['home/'+role+'.JOINED.json'])
        spawned=strict(phone_raw['home/'+role+'.SPAWNED.json'])
        need(joined==ended['roles'][role] and joined['child_wait_returned'] is True
             and joined['dedicated_process_group_absent'] is True
             and joined['identity']==spawned['identity'], 'original role join differs')
    originals.recheck()
    return {'original_sender_absence_observation':pid,
        'p4_receipt':module.filedesc(chain.out/'recovery-p4-originals/stdout.original'),
        'phone_receipt':module.filedesc(chain.out/'phone-recovery-originals/stdout.original'),
        'phone_wire_bytes':len(wire),'p4_fresh_full9_count':len(p4['files'])+len(p4['runtime']),
        'phone_fresh_full9_count':sum(row['exists'] for row in phone['files'].values())+len(phone['runtime']),
        'native_status_observed_in_original_sender':current['actor']['native_status'],
        'native_hash_chain_still_required_by_snapshot_and_closer':True,
        'new_send':False,'new_fixture':False,'new_launch':False,'signals_sent':0,
        'unknown_effects':None,'native_call_count':None,'original_parent_wait_claimed':False}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-sha256',required=True)
    parser.add_argument('--execute-original-tail-once',action='store_true')
    args=parser.parse_args()
    need(re.fullmatch('[0-9a-f]{64}',args.source_sha256),'explicit reviewed source SHA required')
    module,chain,originals,current,summary,reader=preflight(args.source_sha256)
    if not args.execute_original_tail_once:
        print(json.dumps({key:value for key,value in summary.items() if key!='host_originals'},sort_keys=True))
        return 0
    # The existing namespace is consumed before ps, SSH, phone or any tail call.
    # Half-written intent and all later failures remain spent; no auto release.
    not_consumed(); originals.recheck()
    intent={**summary,'state':'EXPLICIT_SAME_SCOPE_ORIGINAL_TAIL_INTENT',
        'maximum_tail_starts':1,'maximum_new_native_sends':0,'maximum_new_fixtures':0,
        'maximum_new_component_launches':0,'reservation_scope':'this reviewed cooperative recovery entry',
        'global_device_mutex_claimed':False,'original_sender_joined_receipt_will_be_written':False}
    module.put(chain.out/'RECOVERY-INTENT.json',encoded(intent))
    try:
        admission=fresh_admission(module,chain,originals,current,reader)
        module.put(chain.out/'RECOVERY-ADMISSION.json',encoded(admission))
        rc=module.resume_original_tail(chain,chain.p,DATA['identity']['phone_home'],
            module.G+'/native-guard-staging-r10-r1/',chain.remote_root+'/material/tree/package/source/',
            DATA['identity']['sender_dir'])
        need(rc==0,'exact normal tail did not return zero')
        closed=strict(module.read(chain.out/'CLOSURE.json'))
        need(closed['schema']=='hepta.native-guard.original-closure.v1'
             and closed['closed'] is True and closed['nonce']==chain.p['nonce']
             and closed['scope']==DATA['native_scope'] and closed['package_sha256']==module.PKG
             and closed['lease_sha256']==ANCHORS['lease']['sha256']
             and closed['native_status']==current['actor']['native_status']
             and type(closed['actual_native_calls']) is int and 0<=closed['actual_native_calls']<=2
             and type(closed['unknown_effects']) is int and closed['unknown_effects']==0
             and closed['closure_source_sha256']==DATA['closure_source_sha256'],
             'actual frozen closure identity differs')
        originals.recheck()
        result={'schema':'hepta.native-current.same-scope-recovery-result.v1',
            'state':'ORIGINAL_NORMAL_TAIL_CLOSED_AND_PUBLISHED',
            'source':summary['source'],'original_root_failure':ANCHORS['root_failure'],
            'original_sender_result':ANCHORS['sender_result'],
            'recovery_intent':module.filedesc(chain.out/'RECOVERY-INTENT.json'),
            'recovery_admission':module.filedesc(chain.out/'RECOVERY-ADMISSION.json'),
            'root_result':module.filedesc(chain.out/'ROOT-RESULT.json'),
            'closure':module.filedesc(chain.out/'CLOSURE.json'),
            'boundary':module.filedesc(chain.out/'LATE-BOUNDARY.original.json'),
            'previous':module.filedesc(chain.out/'ACTUAL-PREVIOUS-INPUT.json'),
            'native_status':closed['native_status'],'actual_native_calls':closed['actual_native_calls'],
            'unknown_effects':closed['unknown_effects'],'component_qualified':closed['component_qualified'],
            'business_qualified':False,'model_requests':0,'original_sender_wait_fabricated':False,
            'new_nonce':False,'new_send':False,'new_fixture':False,'new_launch':False,
            'original_lease_expiry_unchanged':True,'automatic_retry':False}
        module.put(chain.out/'RECOVERY-RESULT.json',encoded(result))
        print(json.dumps(result,sort_keys=True)); return 0
    except BaseException as error:
        cleanup=chain.close_owned_host_outputs()
        failure={'schema':'hepta.native-current.same-scope-recovery-failure.v1',
            'state':'RECOVERY_FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED',
            'error_type':type(error).__name__,'detail':str(error)[:2048],
            'source':summary['source'],'original_root_failure':ANCHORS['root_failure'],
            'steps':chain.steps,'root_fixture_attempts':chain.root_attempts,'host_cleanup':cleanup,
            'original_sender_wait_fabricated':False,'global_unknown_effect_count':None,
            'automatic_retry':False,'new_nonce':False,'new_send':False,'new_fixture':False,
            'new_launch':False,'lease_extension':False,'signals_sent':0,
            'note':'Only reconcile retained original identities. Missing or failed receipts do not prove no effect.'}
        module.put(chain.out/'RECOVERY-FAILURE.json',encoded(failure))
        raise

if __name__=='__main__':
    raise SystemExit(main())
