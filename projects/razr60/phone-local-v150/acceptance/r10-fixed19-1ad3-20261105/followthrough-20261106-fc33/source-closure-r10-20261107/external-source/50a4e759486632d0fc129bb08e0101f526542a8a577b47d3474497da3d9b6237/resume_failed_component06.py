#!/usr/bin/env python3
"""Recover only the unexecuted normal closure tail of actual failed attempt06.

Default is a read-only Mac preflight. Execution requires the explicit flag.
The original coordinator, failed case, lease, malformed capture and setup
terminal remain unchanged. This program never calls Chain.run or creates a
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
ANCHORS=json.loads(r'''{"coordinator":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r6/root-chain/source/run_component_root_once.py","bytes":45756,"sha256":"9d610a226da1c57f8e6178351dbe813a568b05a9538e3e81f850f56a4a3f083d"},"root_plan":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-06/ROOT-PLAN.original.json","bytes":4738,"sha256":"31c2750ec4e63fc44ea6c240304046655fc5949f666cd3fef68ce8b42712641f"},"root_failure":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-06/ROOT-FAILURE.json","bytes":17357,"sha256":"4db667e2036cfcfee95f48ee3a58ed7f930cd0807402433afc7ad220da83fc7d"},"host_diagnostic":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-attempt06-diagnostics-r1/host-existing-01/SUMMARY.json","bytes":3885,"sha256":"b01fcc50850dd79ada6418c877b34b24f434a0b2630f879caa2322dd659cb6b5"},"phone_diagnostic":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-attempt06-diagnostics-r1/phone-originals-01/SUMMARY.json","bytes":13070,"sha256":"518748a8624f8e3f6e7f7f62c22c87e5cc8a43cfe0c552926ca11198d8adeeb9"},"prepared":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-06/material/PREPARED.json","bytes":2873,"sha256":"c6c2f748437eaf547f43cfda9ebd163f2872eeca2dd5dae61fde6fdc94e0a282"},"lease":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-06/material/tree/LEASE.json","bytes":2496,"sha256":"2d20b567d29399383100eb9cc4d647a0c5f1e306c2bd4a309d99b714cd0ee346"},"original_intent":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-06/CHAIN-INTENT.json","bytes":363,"sha256":"fd988088dfe572e8ca1c574659578a9a76625eb39749ede89ea35ca1296f3bf0"},"sender_child":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-06/sender-execute/CHILD.json","bytes":234,"sha256":"104d2c94fa27666201b5c0497b1503bb8a82cb4f3a05a5193dd6a1166dbf6150"},"fixture_originals":{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-06/fixture-originals-setup/stdout.original","bytes":35282,"sha256":"92eba568a36024ec6fbc6d8ed839eb0ebc32602e21002d6b2217c71ce69cdaf9"}}''')
B=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
LABEL='root-r10-neg01-20261105-06'
NONCE='154588e3a15591a21ec18950d18e3ecd'
F=B/'native-guard-root-chains-r10-r1'/LABEL
G='/var/lib/trillionnium/owner-open/phone-local-v150'
HOME=G+'/native-guard-r10-r1/'+LABEL
SENDER_DIR='/home/alex/codex-hepta-natural-'+LABEL+'-root-v150'
REMOTE_ROOT='/home/alex/codex-native-guard-chain-r10-r1/'+NONCE
PACKAGE='4dd75caa1d77f4698fba5084689b84c99a91c388219fd546d84906d869f23f8e'
BRIDGE='9516cc133257abcc989ace06548c6854c49c6e7ff66e0480d0711c1fdd87fe70'
COMBINATION='ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837'
SETUP_TERMINAL='17572f25185b1d87288254d9005af06d9ae04d591a80618e8b33cafe79db376a'
MALFORMED_CAPTURE='e426970460d921e83b1a0aa4fffca8c447a7fa0b536d4f784356a5de8bdcfa6c'
META_FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
ORIGINAL_PHASES=(
    'prepare-material','host-stage-material','phone-push-material','phone-copy-material',
    'phone-push-stage-source','phone-copy-stage-source','phone-stage','sender-preview',
    'sender-prepared','phone-launch','phone-plan-setup','store-plan-setup','fixture-setup',
    'fixture-originals-setup','pack-setup','phone-push-witness-setup',
    'phone-copy-witness-setup','phone-publish-setup','phone-plan-before-guard')
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
    module=types.ModuleType('reviewed_attempt06_coordinator')
    module.__file__=ANCHORS['coordinator']['path']
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    exec(compile(tail,module.__file__+':exact-original-tail','exec'),module.__dict__)
    need(module.PKG==PACKAGE and module.COMBINATION==COMBINATION,'current generation differs')
    return module,proof

def validate_diagnostics(originals,host,phone,plan,failed,prepared,lease):
    host_raws={key:originals.pin(row) for key,row in host['records'].items()}
    phone_raws={key:originals.pin(row) for key,row in phone['records'].items()}
    need(host['state']=='EXISTING_ATTEMPT06_ORIGINALS_RECONCILED' and host['rc']==0
         and host['phone_actions']==0 and host['native_replays']==0
         and host['before_guard_state']=='ORIGINAL_COMPONENT_ENDED_BEFORE_PHASE','host diagnostic state')
    need(phone['state']=='READ_ONLY_ATTEMPT06_ORIGINAL_DIAGNOSTIC' and phone['phone_effects']==0
         and phone['draft_exact_original_verified_privately'] is True,'phone diagnostic state')
    need(host_raws['root_failure']==originals.pin(ANCHORS['root_failure']),'failure diagnostic origin differs')
    need(host['sender_ps_returncode']==1 and host['sender_ps_stdout']==''
         and host_raws['sender_ps']==b'','original sender PID observation differs')
    child=strict(originals.pin(ANCHORS['sender_child']))
    need(child['pid']==child['pgid']==child['sid']==79126 and child['maximum_starts']==1,
         'original sender child identity differs')
    child_intent=originals.read(F/'sender-execute/INTENT.json')
    need(sha(child_intent)==child['source_intent_sha256'],'original sender intent differs')
    absent(F/'sender-execute/JOINED.json')
    sent=strict(host_raws['sender_result'])
    need(sent['rc']==0 and sent['stderr']=='' and host_raws['sender_stderr']==b'',
         'original sender result not terminal zero')
    actor=strict(sent['stdout'].strip().splitlines()[-1])
    need(actor['state']=='ORIGINAL_NATIVE_TERMINAL_OBSERVED' and actor['native_status']=='provider_failed'
         and actor['send_attempt_count']==1 and actor['out']==SENDER_DIR
         and actor['automatic_replay'] is False
         and actor['draft_restore']=={'state':'ORIGINAL_DRAFT_RESTORED','restore_attempts':1,
                                    'original_draft_submitted':False},
         'actual one-Send failed terminal or draft restoration differs')
    need(sent['stdout'].encode()==host_raws['sender_stdout'],'sender stdout original differs')
    need(originals.read(B/(LABEL+'.send-result.json'))==host_raws['sender_result'],
         'canonical sender result differs from observed original')
    originals.read(B/(LABEL+'.local-once.json'));originals.read(B/(LABEL+'.actor.py'))
    need(phone_raws['home/LEASE.json']==originals.pin(ANCHORS['lease']),'phone original lease differs')
    ended=strict(phone_raws['home/LIFECYCLE-ENDED.json'])
    need(ended['schema']=='hepta.native-guard.lifecycle-ended.v1'
         and ended['roles_joined_and_groups_absent'] is True and ended['failure'] is None
         and ended['roles']['provider']['child_exit_code']==70
         and ended['roles']['sidecar']['child_exit_code']==0,
         'actual lifecycle failure is not the reviewed ended generation')
    for role in ('provider','sidecar'):
        value=ended['roles'][role]
        need(value['child_wait_returned'] is True and value['dedicated_process_group_absent'] is True
             and len(value['absence'])==2 and all(row['kernel_group_absence'] is True
             and row['members']==[] for row in value['absence']),'original role was not joined and absent')
        need(strict(phone_raws['home/'+role+'.JOINED.json'])==value,'original joined role differs')
    failure=strict(phone_raws['run/listener-failure.json'])
    need(failure['phase']=='capture' and failure['kernel_state']=='CAPTURE_RESULT_CONSUMED_UNKNOWN'
         and failure['error']=='JSONDecodeError:Expecting value: line 1 column 1622 (char 1621)'
         and failure['automatic_retry'] is False and failure['component_qualified'] is False
         and failure['native_calls_may_have_been_sent']==['guard_'+NONCE+'_capture'],
         'reviewed actual capture parse failure differs')
    malformed=phone_raws['run/capture-originals/stdout.original']
    need(len(malformed)==1623 and sha(malformed)==MALFORMED_CAPTURE
         and malformed.endswith(b',"screenshot":}\n'),'original malformed capture bytes differ')
    try:strict(malformed)
    except json.JSONDecodeError as error:
        need(error.pos==1621,'original malformed JSON rejection differs')
    else:raise ValueError('malformed original was reinterpreted as valid')
    need(phone_raws['run/capture-originals/stderr.original']==b'','original capture stderr differs')
    scope=phone['native_latency_summary']['scope']
    accepted=strict(phone_raws['home/ACCEPTED.json'])
    need(accepted['scope']==scope and scope['session_id']==plan['session_id']
         and scope['profile_id']==plan['profile_id']
         and phone['native_latency_summary']['native_status']=='provider_failed'
         and phone['native_latency_summary']['send_attempt_count']==1,'actual accepted scope differs')
    fixture=strict(originals.pin(ANCHORS['fixture_originals']))
    need(fixture['state']=='ORIGINAL_HOST_FILES_READ' and set(fixture['files'])=={'terminal','index'},
         'actual Root fixture originals missing')
    terminal=fixture['files']['terminal']
    traw=base64.b64decode(terminal['base64'],validate=True)
    need(descriptor(terminal['path'],traw)==failed['root_fixture_attempts'][0]['terminal']
         and len(traw)==24390 and sha(traw)==SETUP_TERMINAL,'actual setup terminal pin differs')
    t=strict(traw)
    need(t['state']=='OWNED_ROOT_FIXTURE_CHILD_JOINED' and t['child_wait_returned'] is True
         and t['child_returncode']==0 and len(t['group_absence_observations'])==2,
         'actual setup fixture not joined')
    return {'actual_native_scope':scope,'actual_native_status':'provider_failed',
            'malformed_capture':phone['records']['run/capture-originals/stdout.original'],
            'original_setup_terminal':failed['root_fixture_attempts'][0]['terminal'],
            'original_sender_pid':79126,'original_sender_pid_observed_absent':True,
            'sender_process_group_absence_proven':False,'original_sender_parent_wait_available':False,
            'sender_joined_receipt_will_be_created':False,
            'supervisor_absence_still_required_by_normal_snapshot':True,
            'typed_rejection_still_required_by_normal_closer':True,
            'component_qualified':False,'new_native_calls':0}

def preflight(source_sha256):
    originals=Originals()
    self_raw=originals.read(Path(__file__).absolute(),limit=131072)
    need(sha(self_raw)==source_sha256,'explicit reviewed recovery source SHA required')
    M,tailproof=load_coordinator(originals)
    raw=originals.pin(ANCHORS['root_plan']);plan,manifest=M.validate_plan(raw)
    need(plan['label']==LABEL and plan['nonce']==NONCE and plan['case_id']=='NEG-01'
         and plan['out']==str(F) and plan['package']['sha256']==PACKAGE,
         'only the original failed attempt06 is admitted')
    need(F.resolve(strict=True)==F and stat.S_IMODE(F.stat().st_mode)==0o700,'original private case directory')
    failed=strict(originals.pin(ANCHORS['root_failure']))
    need(failed['state']=='FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED_NO_AUTOMATIC_CONTINUATION'
         and failed['error_type']=='ValueError'
         and failed['detail']=='component ended before phase; preserve, no additional Root UI'
         and [row['phase'] for row in failed['steps']]==list(ORIGINAL_PHASES)
         and len(failed['root_fixture_attempts'])==1
         and failed['root_fixture_attempts'][0]['phase']=='setup','fixed original failed phase differs')
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
    summary={'schema':'hepta.native-guard.attempt06-recovery-admission.v1',
             'state':'EXISTING_FAILED_ATTEMPT06_NORMAL_TAIL_ADMITTED',
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
             and closed['actual_native_calls']==1,'normal closure did not retain the expected failed one-call case')
        originals.recheck()
        result={'schema':'hepta.native-guard.attempt06-recovery-result.v1',
                'state':'ORIGINAL_FAILED_COMPONENT_NORMAL_TAIL_CLOSED_AND_PUBLISHED',
                'source':summary['source'],'original_root_failure':ANCHORS['root_failure'],
                'recovery_intent':M.filedesc(F/'RECOVERY-INTENT.json'),
                'root_result':M.filedesc(F/'ROOT-RESULT.json'),
                'closure':M.filedesc(F/'CLOSURE.json'),
                'boundary':M.filedesc(F/'LATE-BOUNDARY.original.json'),
                'previous':M.filedesc(F/'ACTUAL-PREVIOUS-INPUT.json'),
                'malformed_original_preserved':True,'original_sender_wait_fabricated':False,
                'component_qualified':False,'business_qualified':False,'model_requests':0,
                'new_nonce':False,'new_send':False,'new_fixture':False,'new_launch':False,
                'original_lease_expiry_unchanged':True,'automatic_retry':False}
        M.put(F/'RECOVERY-RESULT.json',encoded(result));print(json.dumps(result,sort_keys=True));return 0
    except BaseException as error:
        failure={'schema':'hepta.native-guard.attempt06-recovery-failure.v1',
                 'state':'RECOVERY_FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED',
                 'error_type':type(error).__name__,'detail':str(error)[:1024],
                 'source':summary['source'],'original_root_failure':ANCHORS['root_failure'],
                 'steps':c.steps,'root_fixture_attempts':c.root_attempts,
                 'automatic_retry':False,'new_nonce':False,'new_send':False,'new_fixture':False,
                 'new_launch':False,'lease_extension':False,'signals_sent':0,
                 'note':'Only reconcile existing operations. No absent receipt proves no effect.'}
        M.put(F/'RECOVERY-FAILURE.json',encoded(failure));raise

if __name__=='__main__':raise SystemExit(main())
