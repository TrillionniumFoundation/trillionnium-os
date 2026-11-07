#!/usr/bin/env python3
"""Recover only the unexecuted normal closure tail of actual failed attempt08.

Default is a read-only Mac preflight for Root. Execution requires the explicit flag.
The original launch timeout, same-scope continuation, one setup child and one
completed-nonzero capture remain original evidence. This program never calls
Chain.run or creates a nonce, Send, fixture, launch, lease extension or sender JOINED.
The frozen closer alone determines native effect closure; no source-level PASS is claimed.
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
ANCHORS=json.loads(r'''{"coordinator":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-root-setup-budget01/source/run_component_root_once.py","bytes":45952,"sha256":"95c66358e4dc8edd065f19451f72e8a2e1dac761e7b355b7a7a2d35053ae2260"},"root_plan":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/ROOT-PLAN.original.json","bytes":4735,"sha256":"7bdbfbcdf676e186a7669925f6c1de5fb384e27bf10087bd92b6ce164a12ed82"},"root_failure":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/ROOT-FAILURE.json","bytes":9217,"sha256":"eb6cd1bc8cb41987a4f8aee655217dfb57a18592788f1f7bd15276f44225a411"},"host_diagnostic":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/terminal-originals-01/SUMMARY.json","bytes":18474,"sha256":"4e796d52b8d20778da24a6a99c699b94ca369b894698d74f34027a7fe3b275fa"},"phone_diagnostic":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/terminal-originals-01/PHONE-RESULT.original.json","bytes":41759,"sha256":"d670e2324d5036643f3e1d200a395ed159912d987f6c895512158476f421fe97"},"prepared":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/material/PREPARED.json","bytes":2873,"sha256":"395817339415620d26497b2e576751f492db8df8d4929a163dcadb0209aab3f2"},"lease":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/material/tree/LEASE.json","bytes":2496,"sha256":"db3a64d1d5dc3c61b92195ef7add765917274298902c187bbdffde1935cfd6e4"},"original_intent":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/CHAIN-INTENT.json","bytes":363,"sha256":"9cbf00a4cc55400268692f409487c830e3d660eb9817107780fa17571f1211e5"},"sender_child":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/sender-execute/CHILD.json","bytes":234,"sha256":"7131dc1d257bbe0094073f68606b79aa88e26b97cb4606d97683792308747a33"},"continuation_intent":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/phase-continuation-01/INTENT.json","bytes":1640,"sha256":"6fb0facbc6a926b52af102255a197c3f7aef98f8119aa8ba4440eabb1ebdde65"},"continuation_failure":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/phase-continuation-01/FAILURE.json","bytes":8876,"sha256":"80230e449a68dec9cac8842b8cd7bcb2a589fc0c8d22ed86018915e5e9c8e2b6"},"continuation_source":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/phase-continuation-01/PHASE-CONTINUATION.py","bytes":3639,"sha256":"8bc8b5d99b7b3381f357e264e7cc64e90335f814ab9118f5b515f0bd63592517"},"original_phase_loop":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/phase-continuation-01/PHASE-LOOP.original.py","bytes":3645,"sha256":"f9102dd599288f8627fc6ffb9d31ece6b302cfd7f05a57d6616f8955e74af3ae"},"fixture_intent":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/phase-continuation-01/ROOT-FIXTURE-setup.INTENT.json","bytes":1730,"sha256":"ba53f343141bb390f72516b4a092195ffea2e3e71212eb25085f9fe77e1aa31c"},"capture_diagnostic":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/capture-originals-01/SUMMARY.json","bytes":35850,"sha256":"58abff5d3f9812628f67eb73c7ea1cd38dfc08d059ffed2e11af1fa3de0e7547"},"capture_phone_diagnostic":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/capture-originals-01/PHONE-RESULT.original.json","bytes":130554,"sha256":"63a8c8d8a3bd5f1cd983e0b42022c919bbd5e109b9aceb5fd311ed45c9ab5d53"}}''')
B=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
LABEL='root-r10-neg01-20261105-08'
NONCE='2b0b103ee6de7a422064b9571266bf5d'
F=B/'native-guard-root-chains-r10-r1'/LABEL
G='/var/lib/trillionnium/owner-open/phone-local-v150'
HOME=G+'/native-guard-r10-r1/'+LABEL
SENDER_DIR='/home/alex/codex-hepta-natural-'+LABEL+'-root-v150'
REMOTE_ROOT='/home/alex/codex-native-guard-chain-r10-r1/'+NONCE
PACKAGE='683481bdb653bd7cb97bd6171d6b14f6ecaf4f9948ed2691c7b7c420fea5fe3c'
BRIDGE='50562d7869823080e31739c415503a5cf7366b5c82b5b1602b1a822c89197a8b'
COMBINATION='ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837'
CAPTURE_RECORDS=json.loads(r'''["capture-originals/ORIGINS.json","capture-originals/client-inspection.observation.json","capture-originals/client_claim.original","capture-originals/client_result.original","capture-originals/intent.original","capture-originals/receipt.original","capture-originals/stderr.original","capture-originals/stdout.original","capture-originals/transport-00-claim_durable_before_transport.json","capture-originals/transport-01-socket_create_attempt.json","capture-originals/transport-02-socket_created.json","capture-originals/transport-03-connect_attempt.json","capture-originals/transport-04-connected.json","capture-originals/transport-05-peer_identity_query.json","capture-originals/transport-06-peer_verified.json","capture-originals/transport-07-request_send_begin.json","capture-originals/transport-08-request_sent.json","capture-originals/transport-09-response_header_begin.json","capture-originals/transport-10-response_header_received.json","capture-originals/transport-11-response_body_begin.json","capture-originals/transport-12-response_received.json","capture-originals/transport-13-response_validated.json","capture-originals/transport-14-transport_complete.json","run/actual-wire-00.intent.json","run/actual-wire-00.sent.json","run/actual-wire-01.intent.json","run/actual-wire-01.sent.json","run/capture-ledger-wire-binding.json","run/capture.dispatch-intent.json","run/capture.native-command.sh","run/capture.original-command.sh","run/capture.reservation.json","run/provider-in-01.jsonl","run/provider-in.jsonl","run/provider-out.jsonl"]''')
CONTINUATION_PHASES=('phone-resume-plan-setup','store-plan-setup','fixture-setup',
    'fixture-originals-setup','pack-setup','phone-push-witness-setup',
    'phone-copy-witness-setup','phone-publish-setup','phone-resume-plan-before-guard')
META_FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
ORIGINAL_PHASES=(
    'prepare-material','host-stage-material','phone-push-material','phone-copy-material',
    'phone-push-stage-source','phone-copy-stage-source','phone-stage','sender-preview',
    'sender-prepared','phone-launch')
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
    module=types.ModuleType('reviewed_attempt08_coordinator')
    module.__file__=ANCHORS['coordinator']['path']
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    exec(compile(tail,module.__file__+':exact-original-tail','exec'),module.__dict__)
    need(module.PKG==PACKAGE and module.COMBINATION==COMBINATION,'current generation differs')
    return module,proof

def validate_diagnostics(originals,host,phone,plan,failed,prepared,lease):
    need(host['schema']=='hepta.native-guard.attempt08-terminal-original-observation.v1'
         and host['state']==phone['state']=='READ_ONLY_ATTEMPT08_TERMINAL_ORIGINALS'
         and host['phone_effects']==phone['phone_effects']==0
         and host['native_sends']==phone['native_sends']==0
         and host['signals']==phone['signals']==0
         and host['new_fixture'] is False and host['new_send'] is False
         and failed['root_fixture_attempts']==[]
         and host['sender_wait_fabricated'] is False,
         'fixed original terminal observation differs')
    need(host['phone_original']==ANCHORS['phone_diagnostic']
         and host['full_phone_record_count']==len(phone['records'])==21,
         'full original phone observation missing')
    for key in ('scope','roles','role_absence','lifecycle','provider','listener_failure',
                'home_names','run_names','run_path','absent'):
        need(host[key]==phone[key],'summary differs from original phone observation: '+key)
    phone_keys={'home/ACCEPTED.json','home/BOUND-CONTRACT.json','home/CONNECTION-ACCEPTED.json',
        'home/DETACHED-LAUNCH-INTENT.json','home/DETACHED-LAUNCH-RESULT.json',
        'home/LIFECYCLE-ATTEMPT.json','home/LEASE.json','home/LIFECYCLE-ENDED.json','home/PROVIDER-ENDED.json','home/READY.json',
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
    need(child['pid']==child['pgid']==child['sid']==24991
         and child['maximum_starts']==1
         and child['identity_missing_only_if_actual_child_already_joined'] is False,
         'original sender generation differs')
    child_intent=originals.read(F/'sender-execute/INTENT.json')
    need(sha(child_intent)==child['source_intent_sha256'],'original sender intent differs')
    absent(F/'sender-execute/JOINED.json')
    ps=host['sender_ps']
    need(ps['pid']==24991 and ps['returncode']==1 and ps['parent_wait_not_claimed'] is True
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
         and frame['payload']['error']=='owner-open provider exited before a terminal frame: Native component stopped; original state retained, no retry and no qualification.',
         'actual terminal original line binding differs')
    need(observation['native_record_count']==6 and len(observation['native_records'])==6
         and [row['kind'] for row in observation['native_records']]
             ==['turn.accepted','tool.accepted','tool.started','tool.stderr','tool.result','turn.end']
         and [row['turn_seq'] for row in observation['native_records']]==list(range(6)),
         'original single-tool failed terminal observation differs')
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
         and setup['automatic_retry'] is False,'actual original setup plan differs')
    roles=[[4923,4923,4923,19358240],[7150,7150,7150,19360616],
           [7209,7209,7209,19360649]]
    need(phone['roles']==roles and len(phone['role_absence'])==2
         and all(row['kernel_group_absence'] is True and row['members']==[]
                 and type(row['numeric_pids']) is int and row['numeric_pids']>0
                 for row in phone['role_absence']),
         'actual three-role independent absence differs')
    supervisor=strict(raws['home/SUPERVISOR.json'])
    need(supervisor['identity']==roles[0] and supervisor['ppid']==1,
         'actual original supervisor identity differs')
    launch_intent=strict(raws['home/DETACHED-LAUNCH-INTENT.json'])
    launch_result=strict(raws['home/DETACHED-LAUNCH-RESULT.json'])
    life_attempt=strict(raws['home/LIFECYCLE-ATTEMPT.json'])
    need(launch_intent['schema']=='hepta.native-guard.detached-launch-intent.v1'
         and launch_intent['maximum_execs']==launch_intent['maximum_forks']==1
         and launch_intent['automatic_retry'] is False
         and launch_result['schema']=='hepta.native-guard.detached-launch-observation.v1'
         and launch_result['state']=='ONE_FORK_RETURNED_SUPERVISOR_NOT_YET_ADMITTED'
         and launch_result['fork_returned_pid']==roles[0][0]
         and launch_result['child_generation_not_inferred'] is True
         and launch_result['automatic_retry'] is False
         and life_attempt['identity']==roles[0] and life_attempt['automatic_restart'] is False
         and life_attempt['detached_launch_intent_sha256']==sha(raws['home/DETACHED-LAUNCH-INTENT.json'])
         and life_attempt['detached_launch_result_sha256']==sha(raws['home/DETACHED-LAUNCH-RESULT.json'])
         and launch_intent['lease_sha256']==launch_result['lease_sha256']
             ==life_attempt['lease_sha256']==ANCHORS['lease']['sha256'],
         'original timed-out launch lacks its actual admitted supervisor evidence')
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
    need(failure==phone['listener_failure'] and failure['phase']=='capture'
         and failure['kernel_state']=='CAPTURE_RESULT_CONSUMED_UNKNOWN'
         and failure['error']=='ValueError:capture native failure retained'
         and failure['native_calls_may_have_been_sent']==['guard_'+NONCE+'_capture']
         and failure['automatic_retry'] is False and failure['component_qualified'] is False
         and failure['native_turn_terminal_verified'] is False,
         'reviewed original capture failure differs')
    return {'actual_native_scope':scope,'actual_native_status':'provider_failed',
            'actual_observed_send_attempt_count':1,'original_native_call_metadata_count':1,
            'native_hash_chain_verified_by_admission':False,
            'complete_native_chain_still_required_by_normal_closer':True,
            'original_setup_plan':host['records']['home/ROOT-SETUP-PLAN.json'],
            'actual_launch_observed_despite_original_actor_timeout':True,
            'original_sender_pid':24991,'original_sender_pid_observed_absent':True,
            'sender_process_group_absence_proven':False,'original_sender_parent_wait_available':False,
            'sender_joined_receipt_will_be_created':False,
            'actual_role_identities':roles,'independent_two_role_absences_observed':True,
            'private_draft_recomparison_deferred_to_frozen_closer':True,
            'complete_parent_actor_and_phone_fixture_proof_still_required_by_normal_closer':True,
            'listener_unknown_state_not_overridden':True,
            'native_effect_classification_deferred_to_normal_closer':True,
            'component_qualified':False,'new_native_calls':0}


def verify_host_phases(originals,base,steps,expected):
    need(isinstance(steps,list) and [row['phase'] for row in steps]==list(expected),
         'complete original host phase sequence differs')
    for row in steps:
        need(row['state']=='ORIGINAL_HOST_CHILD_JOINED' and type(row['returncode']) is int
             and row['returncode']==0 and row['automatic_retry'] is False
             and type(row['pid']) is int and row['pid']>1,
             'original host phase not joined')
        d=base/row['phase']
        need(strict(originals.read(d/'RESULT.json'))==row,
             'original phase receipt differs')
        need(row['stdout']['path']==str(d/'stdout.original')
             and row['stderr']['path']==str(d/'stderr.original'),
             'original phase stream path differs')
        originals.pin(row['stdout'])
        need(originals.pin(row['stderr'])==b'','prior phase stderr differs')
        intent_raw=originals.read(d/'INTENT.json');intent=strict(intent_raw)
        child=strict(originals.read(d/'CHILD.json'))
        need(intent['schema']=='hepta.native-guard.root-host-command.v1'
             and intent['phase']==row['phase'] and intent['maximum_starts']==1
             and intent['automatic_retry'] is False and intent['signals_on_timeout'] is False
             and child['pid']==row['pid'] and child['maximum_starts']==1
             and child['source_intent_sha256']==sha(intent_raw),
             'original phase child and intent differ')
        if intent['stdin_sha256'] is not None:
            need(sha(originals.read(d/'stdin.original'))==intent['stdin_sha256'],
                 'original phase stdin differs')
    return {row['phase']:row for row in steps}

def verify_continuation(originals,M,continuation,phone,prepared,lease,bridge,manifest):
    T=F/'phase-continuation-01'
    need(continuation['state']=='ORIGINAL_FIRST_FIXTURE_CONTINUATION_FAILED_NO_RETRY'
         and continuation['error_type']=='ValueError'
         and continuation['detail']=='component ended before phase; preserve, no additional Root UI'
         and continuation['automatic_retry'] is False
         and continuation['component_restarts']==continuation['native_sends']==0,
         'original continuation failure differs')
    rows=verify_host_phases(originals,T,continuation['steps'],CONTINUATION_PHASES)
    intent=strict(originals.pin(ANCHORS['continuation_intent']))
    need(intent['schema']=='hepta.native-guard.existing-scope-first-fixture-continuation.v1'
         and intent['state']=='EXISTING_ORIGINAL_SCOPE_ONLY_NO_SEND_OR_COMPONENT_RESTART'
         and intent['original_root_source']==ANCHORS['coordinator']
         and intent['plan']==ANCHORS['root_plan'] and intent['root_failure']==ANCHORS['root_failure']
         and intent['maximum_first_fixture_starts_per_phase']==1
         and intent['automatic_retry'] is False and intent['lease_extension'] is False
         and intent['component_restarts']==intent['native_sends']==0
         and intent['read_only_bridge_tag_delta_only'] is True
         and intent['original_native_turn_deadline_not_extended'] is True
         and intent['original_lease_expires_unix_ms']==lease['expires_unix_ms'],
         'same original scope continuation intent differs')
    source=originals.pin(ANCHORS['coordinator']);text=source.decode();tree=ast.parse(text)
    chain=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Chain')
    run=next(n for n in chain.body if isinstance(n,ast.FunctionDef) and n.name=='run')
    loops=[n for n in run.body if isinstance(n,ast.For) and isinstance(n.target,ast.Name)
           and n.target.id=='phase' and isinstance(n.iter,ast.Tuple)
           and [ast.literal_eval(x) for x in n.iter.elts]==['setup','before-guard','after-guard']]
    need(len(loops)==1,'one original first-fixture loop required')
    loop=loops[0];original=''.join(text.splitlines(keepends=True)[loop.lineno-1:loop.end_lineno])
    need(original.encode()==originals.pin(ANCHORS['original_phase_loop']),
         'retained loop differs from actual original coordinator')
    header=("def continue_first_fixtures(self):\n    p=self.p\n"
            "    home=self.prepared['phone_home']\n"
            "    staging=G+'/native-guard-staging-r10-r1/'\n")
    body=textwrap.indent(textwrap.dedent(original),'    ')
    need(body.count("'plan-'+phase")==1,'original plan tag is not unique')
    actual=originals.pin(ANCHORS['continuation_source'])
    need(actual==(header+body.replace("'plan-'+phase","'resume-plan-'+phase",1)).encode(),
         'continuation gained a change beyond its read-only bridge label')
    # The continuation source is inspected, never compiled or executed here.
    def phone_result(phase,tag,command):
        raw=originals.pin(rows[phase]['stdout']);value=strict(raw)
        need(value['actor_rc']==0 and re.fullmatch('[0-9a-f]{64}',value['wrapper_sha256']),
             'original continuation Actor did not return zero')
        wrapper=value['wrapper'];ph=wrapper['phone']
        need(wrapper['label']=='ng-'+NONCE+'-'+tag
             and wrapper['model_decision'] is False and wrapper['native_task_result'] is False
             and type(ph['rc']) is int and ph['rc']==0 and ph['stderr']==''
             and ph['command']=='/debug_ramdisk/su -c '+M.shlex.quote(command),
             'original continuation phone command differs')
        return strict(ph['stdout'])
    def bridge_command(phase):
        argv=['phone_chain_bridge.py','phase-originals','--label',LABEL,
              '--lease-sha256',prepared['lease']['sha256'],'--phase',phase,
              '--execute-root-bridge-once']
        code='import sys\nsys.argv='+repr(argv)+'\n'+bridge.decode()
        return M.ENV+'/usr/bin/python3 -I -B -c '+M.shlex.quote(code)
    phase=phone_result('phone-resume-plan-setup','resume-plan-setup',bridge_command('setup'))
    need(phase['state']=='ACTUAL_PHASE_ORIGINALS_READ' and phase['effects']==0
         and phase['phase']=='setup' and phase['scope']==phone['scope']
         and set(phase['files'])=={'ACCEPTED.json','BOUND-CONTRACT.json','ROOT-SETUP-PLAN.json'},
         'actual original setup phase differs')
    phase_raw={}
    for name,row in phase['files'].items():
        need(row==phone['records']['home/'+name],
             'setup phase originals differ from retained phone terminal originals')
        raw=base64.b64decode(row['base64'],validate=True)
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],
             'actual original setup bytes differ')
        phase_raw[name]=raw
    stored=strict(originals.pin(rows['store-plan-setup']['stdout']))
    need(stored=={'state':'EXACT_NEW_HOST_FILES_WRITTEN',
        'files':{'plans/setup/'+k:[len(v),sha(v)] for k,v in phase_raw.items()}},
        'original stored phase input set differs')
    accepted=strict(phase_raw['ACCEPTED.json']);setup=strict(phase_raw['ROOT-SETUP-PLAN.json'])
    parent='/home/alex/codex-hepta-native-guard-fixtures-r10-r1/'+NONCE+'/setup'
    entry=REMOTE_ROOT+'/material/tree/package/source/';directory=REMOTE_ROOT+'/plans/setup/'
    argv=['/usr/bin/python3','-I','-B',entry+'run_root_fixture_phase.py',
          '--material',REMOTE_ROOT+'/material/tree','--lease-sha256',prepared['lease']['sha256'],
          '--package-sha256',PACKAGE,'--plan',directory+'ROOT-SETUP-PLAN.json',
          '--plan-sha256',sha(phase_raw['ROOT-SETUP-PLAN.json']),
          '--bound-contract',directory+'BOUND-CONTRACT.json',
          '--bound-contract-sha256',sha(phase_raw['BOUND-CONTRACT.json']),
          '--accepted',directory+'ACCEPTED.json','--accepted-sha256',sha(phase_raw['ACCEPTED.json']),
          '--out',parent,'--execute-root-fixture-phase-once']
    fixture_intent=strict(originals.pin(ANCHORS['fixture_intent']))
    need(fixture_intent=={'phase':'setup','parent_out':parent,
        'expected_terminal_path':parent+'/HOST-TERMINAL.json','argv':argv,'maximum_child_starts':1,
        'terminal_unknown_until_actual_original_read':True,'automatic_retry':False},
        'original setup fixture intent differs')
    original_read=strict(originals.pin(rows['fixture-originals-setup']['stdout']))
    need(original_read['state']=='ORIGINAL_HOST_FILES_READ'
         and set(original_read['files'])=={'terminal','index'},
         'actual fixture original read set differs')
    tr=original_read['files']['terminal'];index=original_read['files']['index']
    for row,path in ((tr,parent+'/HOST-TERMINAL.json'),(index,parent+'/actor/ORIGINAL-INDEX.json')):
        data=base64.b64decode(row['base64'],validate=True)
        need(set(row)=={'path','bytes','sha256','base64'} and row['path']==path
             and len(data)==row['bytes'] and sha(data)==row['sha256']
             and base64.b64encode(data).decode()==row['base64'],
             'actual fixture original bytes differ')
    terminal_raw=base64.b64decode(tr['base64'],validate=True);terminal=strict(terminal_raw)
    need(tr['bytes']==24511 and tr['sha256']=='871c048f0d2e8b118d1c1e1953d148bc9dc6d37da158db72fa5e0394f22d5f58',
         'fixed actual setup terminal differs')
    attempt={'phase':'setup','terminal':{k:tr[k] for k in ('path','bytes','sha256')}}
    need(continuation['root_fixture_attempts']==[attempt],
         'actual continuation setup attempt must not be omitted or replaced')
    command_result=strict(originals.pin(rows['fixture-setup']['stdout']))
    need(command_result['returncode']==0 and command_result['automatic_retry'] is False
         and command_result['stderr']=='' and command_result['stdout'].encode()==terminal_raw,
         'original fixture command result and original terminal differ')
    package_rows={row['path']:row for row in manifest['files']}
    child_argv=list(argv);child_argv[3]=entry+'root_fixture_once.py'
    child_argv[child_argv.index('--out')+1]=parent+'/actor'
    need(terminal['schema']=='hepta.native-guard.root-fixture-host-terminal.v1'
         and terminal['state']=='OWNED_ROOT_FIXTURE_CHILD_JOINED'
         and terminal['phase']=='setup' and terminal['scope']==phone['scope']
         and terminal['argv']==child_argv and terminal['child_pid']==1173867
         and terminal['child_identity']['identity']==[1173867,1173867,1173867,87727269]
         and terminal['child_wait_returned'] is True and terminal['child_returncode']==0
         and terminal['failure'] is None and terminal['automatic_retry'] is False
         and terminal['phase_plan_sha256']==sha(phase_raw['ROOT-SETUP-PLAN.json'])
         and terminal['contract_sha256']==accepted['contract_sha256']==setup['contract_sha256']
         and terminal['lease_sha256']==prepared['lease']['sha256']
         and terminal['package_sha256']==PACKAGE and terminal['actor_out']==parent+'/actor'
         and terminal['parent_source_sha256']==package_rows['source/run_root_fixture_phase.py']['sha256']
         and terminal['child_entry']['sha256']==package_rows['source/root_fixture_once.py']['sha256']
         and terminal['signals_sent']==terminal['model_requests']==terminal['native_task_submissions']==0
         and terminal['component_qualified'] is False
         and len(terminal['group_absence_observations'])==2
         and all(r['kernel_group_absence'] is True and r['members']==[]
                 and type(r['numeric_pids']) is int and r['numeric_pids']>0
                 for r in terminal['group_absence_observations']),
         'actual joined setup child source or scope differs')
    packed_result=strict(originals.pin(rows['pack-setup']['stdout']))
    need(packed_result['returncode']==0 and packed_result['stderr']==''
         and packed_result['automatic_retry'] is False,'original witness pack did not succeed')
    packed=strict(packed_result['stdout'])
    need(packed['state']=='ORIGINAL_BYTES_PACKED_NOT_PUBLISHED'
         and packed['schema']=='hepta.native-guard.host-witness-bundle.v1'
         and packed['scope']==phone['scope'] and packed['phase']=='setup'
         and packed['phase_plan_sha256']==terminal['phase_plan_sha256']
         and packed['contract_sha256']==terminal['contract_sha256']
         and packed['archive']=={'bytes':18822,'sha256':'b57b8401a7642e095070ec7c76f7e7f061b1ba91a9a138abce560be973127552'}
         and packed['mailbox']=={'bytes':1751,'sha256':'173c2b3ee7c6c1a6e16006c5d110448ffadbf968b43727e1bc09cbc7e15c4d71'}
         and packed['component_qualified'] is False and packed['business_qualified'] is False
         and packed['native_calls']==packed['model_requests']==packed['phone_calls']==0,
         'original setup witness packing differs')
    pubargv=['/usr/bin/python3','-I','-B',HOME+'/package/source/witness_bundle.py','publish',
             '--lease',HOME,'--lease-sha256',prepared['lease']['sha256'],
             '--archive',G+'/native-guard-staging-r10-r1/'+LABEL+'-setup.witness.tar.gz',
             '--archive-sha256',packed['archive']['sha256'],'--execute-publish-original-bytes-once']
    published=phone_result('phone-publish-setup','publish-setup',M.ENV+M.shlex.join(pubargv))
    need(published=={'component_qualified':False,'mailbox_sha256':packed['mailbox']['sha256'],
        'native_dispatches_by_publisher':0,'phase':'setup',
        'state':'ORIGINAL_ROOT_WITNESS_BYTES_PUBLISHED_ONCE'},
        'actual original setup publication differs')
    ended=phone_result('phone-resume-plan-before-guard','resume-plan-before-guard',
                      bridge_command('before-guard'))
    need(ended=={'effects':0,'original':phone['records']['home/PROVIDER-ENDED.json'],
                 'phase':'before-guard','state':'ORIGINAL_COMPONENT_ENDED_BEFORE_PHASE'},
         'actual before-guard read did not observe the retained provider terminal')
    for p in ('setup','before-guard','after-guard'):
        for name in ('ROOT-FIXTURE-'+p+'.INTENT.json','store-plan-'+p,'fixture-'+p,
                     'fixture-originals-'+p,'pack-'+p,'phone-push-witness-'+p,
                     'phone-copy-witness-'+p,'phone-publish-'+p):
            absent(F/name)
            if p!='setup':absent(T/name)
    absent(T/'phone-resume-plan-after-guard')
    return {'original_continuation_failure':ANCHORS['continuation_failure'],
        'original_continuation_intent':ANCHORS['continuation_intent'],
        'original_continuation_source':ANCHORS['continuation_source'],
        'original_phase_loop':ANCHORS['original_phase_loop'],
        'continuation_whole_byte_delta_is_read_only_tag_only':True,
        'original_fixture_attempts':[attempt],'original_setup_terminal':attempt['terminal'],
        'original_setup_parent_child_wait_returned':True,'original_setup_witness_published':True,
        'before_guard_original_read_observed_provider_ended':True,
        'before_and_after_fixture_starts_not_replayed':True,
        'complete_parent_actor_and_phone_fixture_proof_still_required_by_normal_closer':True}

def verify_capture_failure_originals(originals,phone):
    host=strict(originals.pin(ANCHORS['capture_diagnostic']))
    raw=strict(originals.pin(ANCHORS['capture_phone_diagnostic']))
    need(host['phone_original']==ANCHORS['capture_phone_diagnostic']
         and host['state']==raw['state']=='ATTEMPT08_CAPTURE_FAILURE_ORIGINALS_READ_ONLY'
         and host['phone_effects']==raw['phone_effects']==0
         and host['new_calls']==raw['new_calls']==0
         and host['signals']==raw['signals']==0
         and host['skipped_large']==raw['skipped_large']==[]
         and host['total_bytes']==raw['total_bytes']==85788
         and host['directories']==raw['directories']
         and set(host['records'])==set(raw['records'])==set(CAPTURE_RECORDS),
         'fixed complete capture failure observation differs')
    copied={};base=Path(ANCHORS['capture_diagnostic']['path']).parent/'originals'
    for key,row in raw['records'].items():
        need(set(row)=={'path','bytes','sha256','metadata','base64'}
             and len(row['metadata'])==9 and all(type(x) is int for x in row['metadata']),
             'capture original full metadata differs')
        data=base64.b64decode(row['base64'],validate=True)
        need(len(data)==row['bytes'] and sha(data)==row['sha256']
             and base64.b64encode(data).decode()==row['base64'],
             'capture original raw bytes differ')
        hr=host['records'][key]
        need(set(hr)=={'host','original'} and hr['original']=={k:row[k] for k in ('path','bytes','sha256','metadata')}
             and hr['host']['path']==str(base/key.replace('/','__')),
             'capture host copy is not the original descriptor projection')
        need(originals.pin(hr['host'])==data,'capture retained raw original differs')
        source=(phone['run_path']+'/'+key if key.startswith('capture-originals/')
                else phone['run_path']+'/'+key.removeprefix('run/'))
        need(row['path']==source,'capture source namespace differs')
        copied[key]=data
    need(set(raw['directories'])=={'capture-originals'},'capture directory set differs')
    directory=raw['directories']['capture-originals']
    need(directory['path']==phone['run_path']+'/capture-originals'
         and len(directory['metadata'])==9 and all(type(x) is int for x in directory['metadata'])
         and directory['names']==sorted(k.split('/',1)[1] for k in CAPTURE_RECORDS if k.startswith('capture-originals/')),
         'complete original capture directory census differs')
    receipt=strict(copied['capture-originals/receipt.original'])
    need(len(copied['capture-originals/receipt.original'])==1515
         and sha(copied['capture-originals/receipt.original'])=='5b467ac979fba6b0b20d94713d4d8af0a073b4c68d79d655b5529bd88abf2b22'
         and receipt['action_id']=='9e8c0fd0cd26f29ecfd80d0364e55225'
         and receipt['command_sha256']=='10c2e7459a4eff49b02a3326a931566600d1e1c29fef5cf9aba30ceebf579b8f'
         and receipt['state']=='completed' and receipt['terminal'] is True
         and receipt['effect_started'] is True and receipt['dispatch_count']==1
         and receipt['can_redispatch'] is False and receipt['waitpid_joined'] is True
         and receipt['waitpid_identity_lost'] is False and receipt['process_group_absent'] is True
         and receipt['process_group_established'] is True and receipt['worker_domain_verified'] is True
         and receipt['pid']==receipt['pgid']==14515 and receipt['exit_code']==72
         and receipt['term_signal'] is None and receipt['error']==''
         and receipt['execution_context']=='u:r:trillionnium_owner_open_phone_worker:s0'
         and receipt['executor_context']=='u:r:trillionnium_owner_open_phone_executor:s0'
         and receipt['execution_uid']==receipt['execution_gid']==receipt['execution_euid']==receipt['execution_egid']==2000
         and receipt['execution_credentials_verified'] is True
         and receipt['execution_supplementary_group_count']==0 and receipt['elapsed_ms']==1553,
         'actual single capture completed-nonzero worker receipt differs')
    for stream in ('stdout','stderr'):
        data=copied['capture-originals/'+stream+'.original']
        need(len(data)==receipt[stream+'_bytes'] and sha(data)==receipt[stream+'_sha256'],
             'capture original stream differs')
    need(copied['capture-originals/stdout.original']==b''
         and len(copied['capture-originals/stderr.original'])==5547
         and sha(copied['capture-originals/stderr.original'])=='9dedb056222c6f42359a0c30359d4163ca52e687b4d086c033ce720b81d8690f',
         'fixed actual capture failure streams differ')
    return {'original_capture_observation':ANCHORS['capture_diagnostic'],
        'original_phone_capture_observation':ANCHORS['capture_phone_diagnostic'],
        'actual_receipt':host['records']['capture-originals/receipt.original'],
        'actual_retained_record_count':len(copied),'actual_capture_exit_code':72,
        'actual_capture_waitpid_joined':True,'actual_capture_group_absent':True,
        'actual_capture_dispatch_count':1,'actual_capture_can_redispatch':False,
        'listener_unknown_state_not_overridden':True,
        'native_effect_classification_deferred_to_normal_closer':True,
        'new_native_calls':0,'qualification_claimed':False}

def preflight(source_sha256):
    originals=Originals()
    self_raw=originals.read(Path(__file__).absolute(),limit=131072)
    need(sha(self_raw)==source_sha256,'explicit reviewed recovery source SHA required')
    M,tailproof=load_coordinator(originals)
    raw=originals.pin(ANCHORS['root_plan']);plan,manifest=M.validate_plan(raw)
    need(plan['label']==LABEL and plan['nonce']==NONCE and plan['case_id']=='NEG-01'
         and plan['out']==str(F) and plan['package']['sha256']==PACKAGE,
         'only the original failed attempt08 is admitted')
    need(F.resolve(strict=True)==F and stat.S_IMODE(F.stat().st_mode)==0o700,'original private case directory')
    failed=strict(originals.pin(ANCHORS['root_failure']))
    need(failed['state']=='FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED_NO_AUTOMATIC_CONTINUATION'
         and failed['error_type']=='ValueError'
         and failed['detail']=='phone actor unknown/nonzero; inspect original without replay'
         and [row['phase'] for row in failed['steps']]==list(ORIGINAL_PHASES)
         and failed['root_fixture_attempts']==[],'fixed original failed phase differs')
    verify_host_phases(originals,F,failed['steps'],ORIGINAL_PHASES)
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
    need(len(bridge)==8098 and sha(bridge)==BRIDGE,'original bridge differs')
    last=strict(originals.pin(failed['steps'][-1]['stdout']))
    need(last['actor_rc']==1
         and last['wrapper_sha256']=='7f790de54520ef8764e9e1addf89800d847965fba675e094176b2e5d4735806f'
         and last['wrapper']=={'automatic_replay':False,'detail':'timed out',
             'elapsed_seconds':35.32458250108175,'error':'TimeoutError',
             'label':'ng-'+NONCE+'-launch','model_decision':False,'native_task_result':False,
             'schema':'hepta.phone-local.operator-result.v150.1','status':'failed_or_unknown_no_retry'},
         'actual original launch timeout must remain failed or unknown')
    host=strict(originals.pin(ANCHORS['host_diagnostic']))
    phone=strict(originals.pin(ANCHORS['phone_diagnostic']))
    diagnosis=validate_diagnostics(originals,host,phone,plan,failed,prepared,lease)
    continuation=strict(originals.pin(ANCHORS['continuation_failure']))
    continuation_proof=verify_continuation(originals,M,continuation,phone,prepared,lease,bridge,manifest)
    capture_proof=verify_capture_failure_originals(originals,phone)
    for name in TAIL_OUTPUTS:absent(F/name)
    need(not any(path.name.startswith('phone-chunk-') for path in F.iterdir()),
         'a prior original snapshot chunk phase exists')
    originals.recheck()
    c=object.__new__(M.Chain)
    c.p=plan;c.out=F;c.steps=list(failed['steps'])+list(continuation['steps']);c.sender=None;c.sender_files=None
    c.remote_root=REMOTE_ROOT;c.material=F/'material';c.prepared=prepared;c.lease=lease
    c.root_attempts=continuation['root_fixture_attempts'];c.bridge=bridge
    summary={'schema':'hepta.native-guard.attempt08-recovery-admission.v1',
             'state':'EXISTING_FAILED_ATTEMPT08_NORMAL_TAIL_ADMITTED',
             'source':descriptor(Path(__file__).absolute(),self_raw),'anchors':ANCHORS,
             'original_expiry_unix_ms':lease['expires_unix_ms'],'lease_renewed':False,
             'tail':tailproof,'diagnostic':diagnosis,'continuation':continuation_proof,
             'capture_failure':capture_proof,'original_joined_host_steps':len(c.steps),
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
             and closed['actual_native_calls']==1,'normal closure did not retain the expected failed one-call case')
        originals.recheck()
        result={'schema':'hepta.native-guard.attempt08-recovery-result.v1',
                'state':'ORIGINAL_FAILED_COMPONENT_NORMAL_TAIL_CLOSED_AND_PUBLISHED',
                'source':summary['source'],'original_root_failure':ANCHORS['root_failure'],
                'recovery_intent':M.filedesc(F/'RECOVERY-INTENT.json'),
                'root_result':M.filedesc(F/'ROOT-RESULT.json'),
                'closure':M.filedesc(F/'CLOSURE.json'),
                'boundary':M.filedesc(F/'LATE-BOUNDARY.original.json'),
                'previous':M.filedesc(F/'ACTUAL-PREVIOUS-INPUT.json'),
                'original_launch_timeout_and_continuation_failure_preserved':True,
                 'original_continuation_failure':ANCHORS['continuation_failure'],
                 'original_capture_failure_observation':ANCHORS['capture_diagnostic'],
                 'original_setup_attempt_count':1,'original_capture_call_count':1,
                 'original_sender_wait_fabricated':False,
                'component_qualified':False,'business_qualified':False,'model_requests':0,
                'new_nonce':False,'new_send':False,'new_fixture':False,'new_launch':False,
                'original_lease_expiry_unchanged':True,'automatic_retry':False}
        M.put(F/'RECOVERY-RESULT.json',encoded(result));print(json.dumps(result,sort_keys=True));return 0
    except BaseException as error:
        failure={'schema':'hepta.native-guard.attempt08-recovery-failure.v1',
                 'state':'RECOVERY_FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED',
                 'error_type':type(error).__name__,'detail':str(error)[:1024],
                 'source':summary['source'],'original_root_failure':ANCHORS['root_failure'],
                 'steps':c.steps,'root_fixture_attempts':c.root_attempts,
                 'automatic_retry':False,'new_nonce':False,'new_send':False,'new_fixture':False,
                 'new_launch':False,'lease_extension':False,'signals_sent':0,
                 'note':'Only reconcile existing operations. No absent receipt proves no effect.'}
        M.put(F/'RECOVERY-FAILURE.json',encoded(failure));raise

if __name__=='__main__':raise SystemExit(main())
