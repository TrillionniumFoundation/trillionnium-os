#!/usr/bin/env python3
"""Recover only the unexecuted normal closure tail of actual failed attempt07.

Default is a read-only Mac preflight. Execution requires the explicit flag.
The original coordinator, failed case, lease, unconsumed setup plan and
original failed phase receipts remain unchanged. This program never calls Chain.run or creates a
native nonce, Send, fixture, service launch, lease extension or sender JOINED.
"""
import argparse
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import textwrap
import types

sys.dont_write_bytecode=True
ANCHORS=json.loads(r'''{"coordinator":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r7/root-chain/source/run_component_root_once.py","bytes":45915,"sha256":"7bdfa017e676e8a2c3813346ee4efc6b81f8e24229ae13f05e34f2e57e221c09"},"root_plan":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07/ROOT-PLAN.original.json","bytes":4738,"sha256":"1e9a0d9bb7243d3343a7cd6fb6efdb0d0f079254d15da525926c65686f13f524"},"root_failure":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07/ROOT-FAILURE.json","bytes":10055,"sha256":"a7a3ca03472a435ce3595c3a688ff339b7786a08c1bfbd5c1bd8552f369683f0"},"host_diagnostic":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07/terminal-originals-01/SUMMARY.json","bytes":19294,"sha256":"5b39c714799b3d62c064761561f1222ea998a1317185a139a8314074c1fb4d66"},"phone_diagnostic":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07/terminal-originals-01/PHONE-RESULT.original.json","bytes":36202,"sha256":"fe85bc5321a52d8b4b74bb182696836e4451a02ca19957b4fda633f27fdcefe9"},"prepared":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07/material/PREPARED.json","bytes":2873,"sha256":"3be6c656ca1330dcecab7bd5926ac96565c4ece043cc2cee507f7ea1f75fa700"},"lease":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07/material/tree/LEASE.json","bytes":2496,"sha256":"2b1ddf41dc09cc13d53a132bede6be5a6ff0e38f0eb186f8dba7b6dc207bee7a"},"original_intent":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07/CHAIN-INTENT.json","bytes":363,"sha256":"c85c9c97f47a28d2898372b8f75e870ec87be3ed388847a5aa1afd914e7f0dbb"},"sender_child":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07/sender-execute/CHILD.json","bytes":231,"sha256":"6e7ff7b6fd1df561f1cb4ef9c1d2966fc95b0cd880a174f36dae01e15931a895"}}''')
B=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
LABEL='root-r10-neg01-20261105-07'
NONCE='16805e43f9787c44c262d5b6c6d8ed95'
F=B/'native-guard-root-chains-r10-r1'/LABEL
G='/var/lib/trillionnium/owner-open/phone-local-v150'
HOME=G+'/native-guard-r10-r1/'+LABEL
SENDER_DIR='/home/alex/codex-hepta-natural-'+LABEL+'-root-v150'
REMOTE_ROOT='/home/alex/codex-native-guard-chain-r10-r1/'+NONCE
PACKAGE='683481bdb653bd7cb97bd6171d6b14f6ecaf4f9948ed2691c7b7c420fea5fe3c'
BRIDGE='d6ade88d49e7c6eff16f164b1e99f7369d98ba799750b690545799195bd6f02d'
COMBINATION='ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837'
FIXTURE_ABSENCE_ORIGINAL={'path':"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07/terminal-originals-01/root-fixture-absence-read/RESULT.json",'bytes':864,'sha256':"f7b4e7c92f0c26575221c8d563f0e53f678d14a2aed55037885555efd8a61f50"}
META_FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
ORIGINAL_PHASES=(
    'prepare-material','host-stage-material','phone-push-material','phone-copy-material',
    'phone-push-stage-source','phone-copy-stage-source','phone-stage','sender-preview',
    'sender-prepared','phone-launch','phone-plan-setup')
TAIL_OUTPUTS=(
    'RECOVERY-INTENT.json','RECOVERY-RESULT.json','RECOVERY-FAILURE.json',
    'phone-role-end','phone-snapshot','ORIGINALS.tar.gz',
    'stage-closure-inputs','stage-closure-plan','close','closed-originals',
    'CLOSURE.json','INVENTORY.json','phone-push-closed-closure','phone-copy-closed-closure',
    'phone-push-closed-inventory','phone-copy-closed-inventory','phone-late-publish',
    'phone-boundary-read','LATE-BOUNDARY.original.json','LATE-BOUNDARY-DESCRIPTOR.json',
    'latest-previous-original','ACTUAL-PREVIOUS-INPUT.json','ROOT-RESULT.json')
FORBIDDEN_TAIL_METHODS={'run','__init__','remaining','execute_process'}
ALLOWED_TAIL_METHODS={'bridge_call','frozen_phone','remote_files','remote_program','remote_read','push_copy'}

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

def load_coordinator(originals):
    raw=originals.pin(ANCHORS['coordinator']);tail,original_tail,proof=tail_source(raw)
    module=types.ModuleType('reviewed_attempt07_coordinator')
    module.__file__=ANCHORS['coordinator']['path']
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    exec(compile(tail,module.__file__+':exact-original-tail','exec'),module.__dict__)
    need(module.PKG==PACKAGE and module.COMBINATION==COMBINATION,'current generation differs')
    return module,proof

def validate_diagnostics(originals,host,phone,plan,failed,prepared,lease):
    need(host['schema']=='hepta.native-guard.attempt07-terminal-original-observation.v1'
         and host['state']==phone['state']=='READ_ONLY_ATTEMPT07_TERMINAL_ORIGINALS'
         and host['phone_effects']==phone['phone_effects']==0
         and host['native_sends']==phone['native_sends']==0
         and host['signals']==phone['signals']==0
         and host['new_fixture'] is False and host['new_send'] is False
         and host['root_fixture_attempts']==failed['root_fixture_attempts']==[]
         and host['sender_wait_fabricated'] is False
         and host['phase_continuation_no_output_created'] is True,
         'fixed original terminal observation differs')
    need(host['phone_original']==ANCHORS['phone_diagnostic']
         and host['full_phone_record_count']==len(phone['records'])==18,
         'full original phone observation missing')
    for key in ('scope','roles','role_absence','lifecycle','provider','listener_failure',
                'home_names','run_names','run_path','absent'):
        need(host[key]==phone[key],'summary differs from original phone observation: '+key)
    phone_keys={'home/ACCEPTED.json','home/BOUND-CONTRACT.json','home/CONNECTION-ACCEPTED.json',
        'home/LEASE.json','home/LIFECYCLE-ENDED.json','home/PROVIDER-ENDED.json','home/READY.json',
        'home/ROOT-SETUP-PLAN.json','home/SUPERVISOR.json','home/provider.JOINED.json',
        'home/provider.SPAWNED.json','home/provider.stderr','home/sidecar.JOINED.json',
        'home/sidecar.SPAWNED.json','home/supervisor.stderr','run/accepted.json',
        'run/listener-failure.json','run/terminal.json'}
    host_keys={'host/root_failure','host/sender_child','host/sender_result',
        'host/sender_stdout','host/sender_stderr','p4/native_latency',
        'p4/draft_restore_result','p4/preserved_draft'}
    need(set(phone['records'])==phone_keys and set(host['records'])==phone_keys|host_keys,
         'fixed complete terminal original set differs')
    # The private draft is deliberately not read here. Root executes the frozen
    # admission/closure, which independently compares the original private bytes.
    raws={key:originals.pin(row) for key,row in host['records'].items()
          if key!='p4/preserved_draft'}
    root=Path(ANCHORS['host_diagnostic']['path']).parent/'originals'
    for key in phone_keys:
        row=phone['records'][key];raw=base64.b64decode(row['base64'],validate=True)
        need(set(row)=={'path','bytes','sha256','metadata','base64'}
             and base64.b64encode(raw).decode()==row['base64']
             and len(raw)==row['bytes'] and sha(raw)==row['sha256']
             and raw==raws[key] and len(row['metadata'])==9
             and all(type(v) is int for v in row['metadata']),
             'original phone record bytes or metadata differ')
        area,name=key.split('/',1)
        expected=(HOME if area=='home' else phone['run_path'])+'/'+name
        need(row['path']==expected and host['records'][key]['path']==str(root/key.replace('/','__')),
             'original phone namespace or retained copy differs')
    need(raws['host/root_failure']==originals.pin(ANCHORS['root_failure'])
         and raws['host/sender_child']==originals.pin(ANCHORS['sender_child']),
         'original host failure or sender identity differs')
    child=strict(raws['host/sender_child'])
    need(child['pid']==child['pgid']==child['sid']==7359
         and child['maximum_starts']==1
         and child['identity_missing_only_if_actual_child_already_joined'] is False,
         'original sender generation differs')
    child_intent=originals.read(F/'sender-execute/INTENT.json')
    need(sha(child_intent)==child['source_intent_sha256'],'original sender intent differs')
    absent(F/'sender-execute/JOINED.json')
    ps=host['sender_ps']
    need(ps['pid']==7359 and ps['returncode']==1 and ps['parent_wait_not_claimed'] is True
         and originals.pin(ps['stdout'])==originals.pin(ps['stderr'])==b'',
         'actual original sender PID absence differs')
    sent=strict(raws['host/sender_result'])
    need(sent['rc']==0 and sent['stderr']=='' and raws['host/sender_stderr']==b'',
         'original SSH sender result is not terminal zero')
    need(raws['host/sender_stdout']==raws['host/sender_result']
         and originals.read(F/'sender-execute/stdout.original')==raws['host/sender_stdout']
         and originals.read(F/'sender-execute/stderr.original')==b''
         and originals.read(B/(LABEL+'.send-result.json'))==raws['host/sender_result'],
         'actual outer sender receipt raw bytes differ')
    actor=strict(sent['stdout'].strip().splitlines()[-1])
    restored={'state':'ORIGINAL_DRAFT_RESTORED','restore_attempts':1,
              'original_draft_submitted':False}
    need(actor['state']=='ORIGINAL_NATIVE_TERMINAL_OBSERVED'
         and actor['native_status']=='provider_failed' and actor['send_attempt_count']==1
         and actor['out']==SENDER_DIR and actor['automatic_replay'] is False
         and actor['draft_restore']==host['draft_restore']==restored,
         'original one-Send failed terminal or restoration receipt differs')
    restore=strict(raws['p4/draft_restore_result'])
    need(all(restore[key]==value for key,value in restored.items())
         and host['preserved_draft_utf8_exact_privately_verified'] is True,
         'original draft restoration state differs')
    latency=strict(raws['p4/native_latency']);scope=phone['scope']
    need(latency['state']=='ORIGINAL_NATIVE_TERMINAL_OBSERVED'
         and latency['native_status']==host['actual_native_status']=='provider_failed'
         and latency['scope']==scope and latency['send_attempt_count']==host['send_attempt_count']==1
         and latency['automatic_send_retry'] is False
         and latency['native_hash_chain_verified'] is False,
         'original latency observation or unverified-chain status differs')
    observation=latency['original_observation'];terminal=observation['native_terminal']
    frame=terminal['frame'];record=terminal['record']
    line=base64.b64decode(terminal['raw_line_b64'],validate=True)
    need(len(line)==terminal['raw_line_bytes'] and sha(line)==terminal['raw_line_sha256']
         and base64.b64encode(line).decode()==terminal['raw_line_b64']
         and strict(line)==record and record['payload']['frame']==frame
         and record['scope']==scope and record['kind']==frame['kind']=='turn.end'
         and frame['payload']['status']=='provider_failed'
         and record['payload']['request_sha256']==frame['payload']['turn_request_sha256']
             ==observation['native_request_sha256']
         and frame['payload']['error']=='owner-open provider exceeded its turn deadline',
         'actual terminal original line binding differs')
    need(observation['native_record_count']==2 and len(observation['native_records'])==2
         and [row['kind'] for row in observation['native_records']]==['turn.accepted','turn.end']
         and [row['turn_seq'] for row in observation['native_records']]==[0,1],
         'original no-tool terminal observation differs')
    accepted=strict(raws['home/ACCEPTED.json'])
    need(accepted['scope']==scope and scope['session_id']==plan['session_id']
         and scope['profile_id']==plan['profile_id']
         and accepted['run_dir']==phone['run_path']
         and accepted['native_tools_dispatched']==0
         and raws['home/LEASE.json']==originals.pin(ANCHORS['lease']),
         'actual accepted scope or original lease differs')
    setup=strict(raws['home/ROOT-SETUP-PLAN.json'])
    need(setup['schema']=='hepta.native-guard.root-phase-plan.v1' and setup['phase']=='setup'
         and setup['scope']==scope and setup['contract_sha256']==accepted['contract_sha256']
         and setup['automatic_retry'] is False,'unconsumed original setup plan differs')
    roles=[[10727,10727,10727,19174885],[11558,11558,11558,19177418],
           [11579,11579,11579,19177456]]
    need(phone['roles']==roles and len(phone['role_absence'])==2
         and all(row['kernel_group_absence'] is True and row['members']==[]
                 and type(row['numeric_pids']) is int and row['numeric_pids']>0
                 for row in phone['role_absence']),
         'actual three-role independent absence differs')
    supervisor=strict(raws['home/SUPERVISOR.json'])
    need(supervisor['identity']==roles[0] and supervisor['ppid']==1,
         'actual original supervisor identity differs')
    ended=strict(raws['home/LIFECYCLE-ENDED.json'])
    need(ended==phone['lifecycle'] and ended['schema']=='hepta.native-guard.lifecycle-ended.v1'
         and ended['roles_joined_and_groups_absent'] is True and ended['failure'] is None
         and ended['roles']['provider']['child_exit_code']==70
         and ended['roles']['sidecar']['child_exit_code']==0,
         'original role terminal differs')
    for role,identity in (('sidecar',roles[1]),('provider',roles[2])):
        value=ended['roles'][role]
        need(value['identity']==identity and value['child_wait_returned'] is True
             and value['dedicated_process_group_absent'] is True
             and len(value['absence'])==2 and all(row['kernel_group_absence'] is True
                  and row['members']==[] for row in value['absence'])
             and strict(raws['home/'+role+'.JOINED.json'])==value,
             'original role was not joined and absent')
    failure=strict(raws['run/listener-failure.json'])
    need(failure==phone['listener_failure'] and failure['phase'] is None
         and failure['kernel_state']=='BOUND'
         and failure['error']=='ValueError:native EOF; no reconnect'
         and failure['native_calls_may_have_been_sent']==[]
         and failure['automatic_retry'] is False and failure['component_qualified'] is False,
         'reviewed original no-dispatch listener failure differs')
    fixture_result=strict(originals.pin(FIXTURE_ABSENCE_ORIGINAL))
    fixture_root=Path(FIXTURE_ABSENCE_ORIGINAL['path']).parent
    fixture_intent_raw=originals.read(fixture_root/'INTENT.json')
    fixture_intent=strict(fixture_intent_raw)
    fixture_child=strict(originals.read(fixture_root/'CHILD.json'))
    fixture_source=originals.read(fixture_root/'stdin.original')
    need(sha(fixture_intent_raw)=='0b99c49c3d256a4e44b32f1f4c303daafb7c87cbcd7f3ae72aab60b7c5cb7740'
         and fixture_child['source_intent_sha256']==sha(fixture_intent_raw)
         and len(fixture_source)==1137 and sha(fixture_source)==fixture_intent['stdin_sha256']
             =='8b8f0d785bee3767e7124d97d164c8bd34a3a6a748fdde086e6ccb9392032cce'
         and fixture_result['state']=='ORIGINAL_HOST_CHILD_JOINED'
         and fixture_result['phase']=='root-fixture-absence-read'
         and fixture_result['pid']==fixture_child['pid']==17039
         and fixture_result['returncode']==0 and fixture_result['automatic_retry'] is False
         and originals.pin(fixture_result['stderr'])==b'',
         'actual P4 fixture absence observation terminal differs')
    fixture=strict(originals.pin(fixture_result['stdout']))
    paths={'/home/alex/codex-hepta-native-guard-fixtures-r10-r1/'+NONCE}
    paths.update(REMOTE_ROOT+'/fixture-'+phase for phase in ('setup','before-guard','after-guard'))
    need(fixture==host['root_fixture_absences']
         and fixture['state']=='ALL_ORIGINAL_FIXTURE_PARENT_PATHS_ABSENT'
         and fixture['phone_actions']==0 and len(fixture['records'])==4
         and {row['path'] for row in fixture['records']}==paths,
         'original complete fixture absence set differs')
    for row in fixture['records']:
        need(row['canonical_parent']==str(Path(row['path']).parent)
             and len(row['parent_metadata'])==9
             and all(type(v) is int for v in row['parent_metadata'])
             and row['observations']==[{'errno':2},{'errno':2}],
             'original fixture canonical ENOENT differs')
    for phase in ('setup','before-guard','after-guard'):
        for name in ('ROOT-FIXTURE-'+phase+'.INTENT.json','store-plan-'+phase,
                     'fixture-'+phase,'fixture-originals-'+phase,'pack-'+phase,
                     'phone-push-witness-'+phase,'phone-copy-witness-'+phase,'phone-publish-'+phase):
            absent(F/name)
    return {'actual_native_scope':scope,'actual_native_status':'provider_failed',
            'actual_observed_send_attempt_count':1,'original_native_call_metadata_count':0,
            'native_hash_chain_verified_by_admission':False,
            'complete_native_chain_still_required_by_normal_closer':True,
            'original_unconsumed_setup_plan':host['records']['home/ROOT-SETUP-PLAN.json'],
            'original_root_fixture_attempts':[],
            'original_p4_fixture_absence_terminal':FIXTURE_ABSENCE_ORIGINAL,
            'original_sender_pid':7359,'original_sender_pid_observed_absent':True,
            'sender_process_group_absence_proven':False,'original_sender_parent_wait_available':False,
            'sender_joined_receipt_will_be_created':False,
            'actual_role_identities':roles,'independent_two_role_absences_observed':True,
            'private_draft_recomparison_deferred_to_frozen_closer':True,
            'phone_fixture_absence_and_p4_census_still_required_by_normal_closer':True,
            'component_qualified':False,'new_native_calls':0}

def preflight(source_sha256):
    originals=Originals()
    self_raw=originals.read(Path(__file__).absolute(),limit=131072)
    need(sha(self_raw)==source_sha256,'explicit reviewed recovery source SHA required')
    M,tailproof=load_coordinator(originals)
    raw=originals.pin(ANCHORS['root_plan']);plan,manifest=M.validate_plan(raw)
    need(plan['label']==LABEL and plan['nonce']==NONCE and plan['case_id']=='NEG-01'
         and plan['out']==str(F) and plan['package']['sha256']==PACKAGE,
         'only the original failed attempt07 is admitted')
    need(F.resolve(strict=True)==F and stat.S_IMODE(F.stat().st_mode)==0o700,'original private case directory')
    failed=strict(originals.pin(ANCHORS['root_failure']))
    need(failed['state']=='FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED_NO_AUTOMATIC_CONTINUATION'
         and failed['error_type']=='ValueError'
         and failed['detail']=='actual phone command failed; no new key retry'
         and [row['phase'] for row in failed['steps']]==list(ORIGINAL_PHASES)
         and failed['root_fixture_attempts']==[],'fixed original failed phase differs')
    for row in failed['steps']:
        need(row['state']=='ORIGINAL_HOST_CHILD_JOINED' and row['returncode']==0
             and row['automatic_retry'] is False,'prior original host phase not joined')
        need(strict(originals.read(F/row['phase']/'RESULT.json'))==row,'original phase receipt differs')
        originals.pin(row['stdout']);need(originals.pin(row['stderr'])==b'','prior phase stderr differs')
    prepared=strict(originals.pin(ANCHORS['prepared']));lease=strict(originals.pin(ANCHORS['lease']))
    intent=strict(originals.pin(ANCHORS['original_intent']))
    need(prepared['phone_home']==HOME and prepared['nonce']==lease['nonce']==NONCE
         and prepared['label']==lease['label']==LABEL
         and prepared['package_sha256']==lease['package_sha256']==PACKAGE
         and prepared['combination']['sha256']==lease['combination']['sha256']==COMBINATION
         and prepared['lease']=={key:ANCHORS['lease'][key] for key in ('bytes','sha256')}
         and lease['expires_unix_ms']==intent['lease_expires_unix_ms']
         and intent['automatic_lease_extension'] is False,'original lease or material changed')
    need(originals.read(F/'prepare-material/stdout.original')==originals.pin(ANCHORS['prepared']),
         'actual prepare stdout differs')
    archive=originals.read(F/'material/component-inputs.tar.gz')
    need(len(archive)==prepared['archive']['bytes'] and sha(archive)==prepared['archive']['sha256'],
         'original material archive differs')
    need(originals.read(F/'material/tree/package/MANIFEST.json')==M.pin(plan['package']),
         'original staged package manifest differs')
    runtime=Path(plan['package']['path']).parent
    for row in manifest['files']:
        for base in (runtime,F/'material/tree/package'):
            originals.pin({'path':str(base/row['path']),'bytes':row['bytes'],'sha256':row['sha256']})
    original_bridge=Path(ANCHORS['coordinator']['path']).parent/'phone_chain_bridge.py'
    bridge=originals.read(original_bridge,limit=65536)
    need(len(bridge)==8068 and sha(bridge)==BRIDGE,'original bridge differs')
    last=strict(originals.pin(failed['steps'][-1]['stdout']))
    argv=['phone_chain_bridge.py','phase-originals','--label',LABEL,'--lease-sha256',
          prepared['lease']['sha256'],'--phase','setup','--execute-root-bridge-once']
    code='import sys\nsys.argv='+repr(argv)+'\n'+bridge.decode()
    command=M.ENV+'/usr/bin/python3 -I -B -c '+M.shlex.quote(code)
    need(last['actor_rc']==0 and last['wrapper']['phone']['rc']==1
         and last['wrapper']['phone']['stdout']==''
         and last['wrapper']['phone']['command']=='/debug_ramdisk/su -c '+M.shlex.quote(command)
         and last['wrapper']['phone']['stderr'].endswith(
             'ValueError: one bounded original phase wait expired\n'),
         'actual original setup wait failed on a different operation')
    host=strict(originals.pin(ANCHORS['host_diagnostic']))
    phone=strict(originals.pin(ANCHORS['phone_diagnostic']))
    diagnosis=validate_diagnostics(originals,host,phone,plan,failed,prepared,lease)
    for name in TAIL_OUTPUTS:absent(F/name)
    need(not any(path.name.startswith('phone-chunk-') for path in F.iterdir()),
         'a prior original snapshot chunk phase exists')
    originals.recheck()
    c=object.__new__(M.Chain)
    c.p=plan;c.out=F;c.steps=list(failed['steps']);c.sender=None;c.sender_files=None
    c.remote_root=REMOTE_ROOT;c.material=F/'material';c.prepared=prepared;c.lease=lease
    c.root_attempts=failed['root_fixture_attempts'];c.bridge=bridge
    summary={'schema':'hepta.native-guard.attempt07-recovery-admission.v1',
             'state':'EXISTING_FAILED_ATTEMPT07_NORMAL_TAIL_ADMITTED',
             'source':descriptor(Path(__file__).absolute(),self_raw),'anchors':ANCHORS,
             'original_expiry_unix_ms':lease['expires_unix_ms'],'lease_renewed':False,
             'tail':tailproof,'diagnostic':diagnosis,
             'originals':list(originals.rows.values()),'originals_count':len(originals.rows),
             'new_nonce':False,'new_send':False,'new_fixture':False,'new_launch':False,
             'phone_operations_executed_by_preflight':0,'automatic_retry':False}
    return M,c,originals,summary

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-sha256',required=True)
    parser.add_argument('--execute-original-tail-once',action='store_true')
    args=parser.parse_args()
    need(re.fullmatch('[0-9a-f]{64}',args.source_sha256),'reviewed source SHA format')
    os.umask(0o077)
    M,c,originals,summary=preflight(args.source_sha256)
    if not args.execute_original_tail_once:
        print(json.dumps({key:value for key,value in summary.items() if key!='originals'},sort_keys=True))
        return 0
    originals.recheck()
    intent={**summary,'state':'EXPLICIT_ORIGINAL_TAIL_EXECUTION_INTENT',
            'maximum_tail_starts':1,'maximum_native_sends':0,'maximum_fixture_starts':0,
            'maximum_service_launches':0,'phase_output_namespace':str(F)}
    M.put(F/'RECOVERY-INTENT.json',encoded(intent))
    try:
        rc=M.resume_original_tail(c,c.p,HOME,G+'/native-guard-staging-r10-r1/',
                                  REMOTE_ROOT+'/material/tree/package/source/',SENDER_DIR)
        need(rc==0,'original tail did not return zero')
        closed=strict(M.read(F/'CLOSURE.json'))
        need(closed['state']=='ORIGINAL_NATIVE_COMPONENT_FAILED_CLOSED'
             and closed['component_qualified'] is False and closed['native_status']=='provider_failed'
             and type(closed['unknown_effects']) is int and closed['unknown_effects']==0
             and closed['actual_native_calls']==0,'normal closure did not retain the expected failed zero-call case')
        originals.recheck()
        result={'schema':'hepta.native-guard.attempt07-recovery-result.v1',
                'state':'ORIGINAL_FAILED_COMPONENT_NORMAL_TAIL_CLOSED_AND_PUBLISHED',
                'source':summary['source'],'original_root_failure':ANCHORS['root_failure'],
                'recovery_intent':M.filedesc(F/'RECOVERY-INTENT.json'),
                'root_result':M.filedesc(F/'ROOT-RESULT.json'),
                'closure':M.filedesc(F/'CLOSURE.json'),
                'boundary':M.filedesc(F/'LATE-BOUNDARY.original.json'),
                'previous':M.filedesc(F/'ACTUAL-PREVIOUS-INPUT.json'),
                'original_setup_wait_failure_and_unconsumed_plan_preserved':True,'original_sender_wait_fabricated':False,
                'component_qualified':False,'business_qualified':False,'model_requests':0,
                'new_nonce':False,'new_send':False,'new_fixture':False,'new_launch':False,
                'original_lease_expiry_unchanged':True,'automatic_retry':False}
        M.put(F/'RECOVERY-RESULT.json',encoded(result));print(json.dumps(result,sort_keys=True));return 0
    except BaseException as error:
        failure={'schema':'hepta.native-guard.attempt07-recovery-failure.v1',
                 'state':'RECOVERY_FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED',
                 'error_type':type(error).__name__,'detail':str(error)[:1024],
                 'source':summary['source'],'original_root_failure':ANCHORS['root_failure'],
                 'steps':c.steps,'root_fixture_attempts':c.root_attempts,
                 'automatic_retry':False,'new_nonce':False,'new_send':False,'new_fixture':False,
                 'new_launch':False,'lease_extension':False,'signals_sent':0,
                 'note':'Only reconcile existing operations. No absent receipt proves no effect.'}
        M.put(F/'RECOVERY-FAILURE.json',encoded(failure));raise

if __name__=='__main__':raise SystemExit(main())
