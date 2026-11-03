#!/usr/bin/env python3
"""Focused host receipt/argv compatibility checks only. No phone, nonce or task generation."""
from pathlib import Path
import base64,copy,hashlib,importlib.util,json,os,sys
sys.dont_write_bytecode=True
D=Path(__file__).resolve().parent
sys.path.insert(0,str(D))
spec=importlib.util.spec_from_file_location('r5_business_collector_fixture',D/'collect_business_evidence.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
sha=lambda b:hashlib.sha256(b).hexdigest()
scope=dict(zip(m.SCOPE_FIELDS,('host-session','host-profile','host-task','host-turn','host-stream')))
token='ab'*16
command=b'printf synthetic_fixture_never_executed'
digest=sha(command)
run=Path('/synthetic/run');state=Path('/synthetic/state')
sidecar=Path('/synthetic/executor-r6');client=Path('/synthetic/client-receipts')
action=sidecar/'actions'/token
key=sha(b'host-call')
common={'version':1,'executor_revision':6,'action_id':token,'command_sha256':digest,'timeout_ms':60000,
 'executor_context':m.R6_PARENT,'peer_context':m.R6_BOOTSTRAP,'peer_uid':0,
 'server_instance':'cd'*16,'created_unix_ms':1,'can_redispatch':False}
receipt=dict(common,state='completed',terminal=True,dispatch_count=1,
 effect_started=True,process_group_established=True,waitpid_joined=True,process_group_absent=True,
 waitpid_identity_lost=False,execution_credentials_scope='android_shell_uid2000',
 handshake_stage='worker_entry_after_exec_transition',execution_context='u:r:trillionnium_owner_open_phone_worker:s0',
 required_execution_uid=2000,required_execution_gid=2000,execution_uid=2000,execution_euid=2000,
 execution_gid=2000,execution_egid=2000,execution_supplementary_group_count=0,
 supplementary_groups_cleared=True,worker_domain_verified=True,execution_credentials_verified=True,
 pid=123,pgid=123,intent_parent_sync_complete=True,exit_code=0,term_signal=None,
 stdout_bytes=0,stderr_bytes=0,stdout_sha256=sha(b''),stderr_sha256=sha(b''))
intent=dict(common,state='intent',terminal=False,dispatch_count=0,effect_started=False)
claim={'version':1,'action_id':token,'command_sha256':digest,'client_revision':6,
 'client_source_sha256':m.R6_CLIENT_SOURCE_SHA256,'endpoint':m.R6_ENDPOINT,'timeout_ms':60000,'state':'intent'}
def fixture(overrides=None,old_path=False,claim_overrides=None,missing_intent=False,pending=False,instance_mismatch=False):
 r=copy.deepcopy(receipt);r.update(overrides or {})
 i=copy.deepcopy(intent)
 if instance_mismatch:i['server_instance']='ef'*16
 c=copy.deepcopy(claim);c.update(claim_overrides or {})
 path='/var/lib/trillionnium/owner-open/phone-local-v150/'+('tool_client.py' if old_path else 'tool_client_r6.py')
 call={'call_id':'host-call','tool':'shell.exec','argv':['/usr/bin/python3',path,'execute',
  '--action-id',token,'--command-b64',base64.b64encode(command).decode(),'--timeout-ms','60000']}
 semantic={'call_id':'host-call','turn':scope,'wire_call':call,'wire_tool':'shell.exec','capture_id':token,'semantic_tool':'phone.observe'}
 values={run/('semantic-'+key+'.json'):semantic,run/('result-'+key+'.json'):None,
  action/'intent.json':None if missing_intent else i,action/'receipt.json':r,
  client/(token+'.claim.json'):c,
  client/(token+'.result.json'):{'version':1,'protocol':'hepta_phone_local_v150','duplicate':False,'receipt':r}}
 raw={action/'receipt.pending':b'uncommitted' if pending else None,action/'stdout.bin':b'',action/'stderr.bin':b''}
 class Snapshot:
  def json(self,path,required=True):return copy.deepcopy(values.get(path))
  def read(self,path,required=True,**kw):return raw.get(path)
 return m.inspect_tool(Snapshot(),run,state,sidecar,client,scope,call,None,[])
checks=[]
def passed(name,ok):assert ok,name;checks.append({'name':name,'passed':True})
r=fixture()
passed('exact_r6_receipt_is_safe_but_missing_native_result_never_full_success',
 r['safe_original_execution_terminal'] is True and r['successful_original_execution'] is False and r['native_raw_streams_equal'] is False)
r=fixture({'exit_code':127})
passed('completed_nonzero_is_known_terminal_not_business_success',
 r['safe_original_execution_terminal'] is True and r['successful_original_execution'] is False)
for name,kwargs in [
 ('wrong_worker_domain',{'overrides':{'execution_context':'u:r:magisk:s0'}}),
 ('root_effect_uid',{'overrides':{'execution_uid':0}}),
 ('supplementary_group_present',{'overrides':{'execution_supplementary_group_count':1}}),
 ('pre_exec_handshake',{'overrides':{'handshake_stage':'before_exec'}}),
 ('lost_wait_identity',{'overrides':{'waitpid_identity_lost':True}}),
 ('boolean_dispatch_count',{'overrides':{'dispatch_count':True}}),
 ('wrong_owned_group',{'overrides':{'pgid':124}}),
 ('uncommitted_pending_receipt',{'pending':True}),
 ('missing_original_intent',{'missing_intent':True}),
 ('different_original_server_instance',{'instance_mismatch':True})]:
 r=fixture(**kwargs)
 passed(name+'_does_not_prove_r6_terminal',r['safe_original_execution_terminal'] is False and r['successful_original_execution'] is False)
for name,kwargs in [
 ('legacy_client_path',{'old_path':True}),
 ('foreign_client_endpoint',{'claim_overrides':{'endpoint':'hepta_phone_local_v150'}}),
 ('unbound_client_source',{'claim_overrides':{'client_source_sha256':'00'*32}})]:
 try:fixture(**kwargs)
 except ValueError:passed(name+'_rejected',True)
 else:raise AssertionError(name+'_must_reject')
rev=json.loads((D/'SOURCE-REVISION-CHECK.json').read_bytes())
passed('old_noncompatibility_gates_preserved_by_reverse_source_and_predicate_ast',
 rev['reverse_text_exact'] is True and rev['reverse_ast_exact'] is True and rev['frozen_r6_terminal_predicate_ast_equal'] is True)
r={'schema':'hepta.business-r5-collector-focused-host-checks.v1','state':'PASS',
 'checks':checks,'passed':len(checks),'total':len(checks),
 'collector_source_sha256':sha((D/'collect_business_evidence.py').read_bytes()),
 'test_source_sha256':sha(Path(__file__).read_bytes()),
 'scope':'Synthetic receipt and actual inspect_tool argv boundaries only; no full business PASS or physical qualification.',
 'phone_operations':0,'model_requests':0,'new_nonce_generation':False,'task_submissions':0,'runtime_source_changes':0}
raw=(json.dumps(r,sort_keys=True,indent=2)+'\n').encode()
fd=os.open(D/'HOST-COMPAT-CHECKS.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
print(json.dumps({'state':'PASS','passed':len(checks),'total':len(checks),'report_sha256':sha(raw),'report_bytes':len(raw),'phone_operations':0,'model_requests':0},indent=2))
