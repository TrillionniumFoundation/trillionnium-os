#!/usr/bin/env python3
"""Offline phase/no-replay tests. Fake local sockets; no phone, network or shell."""
import ast, base64, hashlib, json, os, secrets, struct, tempfile, types
from pathlib import Path
HERE=Path(__file__).resolve().parent
source=(HERE/'tool_client_r6.py').read_text()
ast.parse(source,feature_version=(3,12))
m=types.ModuleType('client_r6_offline_fixture');m.__file__=str(HERE/'tool_client_r6.py')
exec(compile(source,m.__file__,'exec'),m.__dict__)
checks=['python312_syntax','module_import_no_connection']
def check(name,ok):
 assert ok,name;checks.append(name)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def response(action,command,**changes):
 out=b'fixture-only stdout\n';err=b''
 r={'version':1,'action_id':action,'command_sha256':sha(command.encode()),'terminal':True,
    'state':'completed','effect_started':True,'dispatch_count':1,'pid':1234,'pgid':1234,
    'process_group_established':True,'waitpid_joined':True,'process_group_absent':True,
    'waitpid_identity_lost':False,'exit_code':0,
    'executor_revision':6,'executor_context':m.EXPECTED_SERVER_CONTEXT,
    'peer_context':m.EXPECTED_EXECUTE_CALLER_CONTEXT,
    'execution_credentials_scope':'android_shell_uid2000',
    'required_execution_uid':2000,'required_execution_gid':2000,
    'execution_credentials_verified':True,'execution_uid':2000,'execution_euid':2000,
    'execution_gid':2000,'execution_egid':2000,
    'supplementary_groups_cleared':True,'execution_supplementary_group_count':0,
    'worker_domain_verified':True,'execution_context':m.EXPECTED_WORKER_CONTEXT,
    'handshake_stage':'worker_entry_after_exec_transition',
    'stdout_bytes':len(out),'stderr_bytes':0,'stdout_sha256':sha(out),'stderr_sha256':sha(err)}
 r.update(changes)
 return {'version':1,'protocol':m.PROTOCOL,'duplicate':False,'receipt':r,
     'stdout_b64':base64.b64encode(out).decode(),'stderr_b64':''}
class FakeSocket:
 def __init__(self,factory):
  self.factory=factory;self.sent=bytearray();self.closed=False;self.read_calls=0
  raw=m._json_bytes(factory.response)
  self.incoming=bytearray(struct.pack('>I',len(raw))+raw)
 def __enter__(self):return self
 def __exit__(self,*_):
  self.closed=True
  if len(self.sent)>=4:
   size=struct.unpack('>I',self.sent[:4])[0]
   if len(self.sent)==size+4:self.factory.operations.append(json.loads(self.sent[4:])['op'])
  return False
 def settimeout(self,_t):pass
 def connect(self,address):
  self.factory.connects.append(address)
  if self.factory.failure=='connect':raise PermissionError(13,'synthetic connect denied')
 def getsockopt(self,level,opt,size):
  if self.factory.failure=='peer_query':raise PermissionError(13,'synthetic peer query denied')
  if opt==17:return struct.pack('3i',777,self.factory.uid,self.factory.gid)
  assert opt==31 and size==256
  return self.factory.context.encode()
 def send(self,data):
  if self.factory.failure=='send_first':raise PermissionError(13,'synthetic send denial')
  if self.factory.failure=='send_partial' and self.sent:raise PermissionError(13,'synthetic partial send denial')
  count=min(len(data),7 if self.factory.failure=='send_partial' else len(data))
  self.sent.extend(bytes(data[:count]));return count
 def recv(self,size):
  self.read_calls+=1
  if self.factory.failure=='receive_header':raise PermissionError(13,'synthetic receive denied after full request')
  if self.factory.failure=='receive_body' and self.read_calls>1:return b''
  count=min(size,3,len(self.incoming));raw=bytes(self.incoming[:count]);del self.incoming[:count];return raw
class Factory:
 def __init__(self,value,*,failure=None,uid=0,gid=0,context=None):
  self.response=value;self.failure=failure;self.uid=uid;self.gid=gid
  self.context=context or m.EXPECTED_SERVER_CONTEXT
  self.instances=[];self.connects=[];self.operations=[]
 def socket(self,*_a,**_k):
  sock=FakeSocket(self);self.instances.append(sock);return sock
def install(factory):
 m.socket=types.SimpleNamespace(AF_UNIX=1,SOCK_STREAM=1,SOL_SOCKET=1,SO_PEERCRED=17,SO_PEERSEC=31,socket=factory.socket)
def read_json(path):return json.loads(path.read_bytes())
def phase_records(directory):
 items=[]
 for path in sorted(directory.glob('*.json')):items.append((path,read_json(path)))
 return items
def validate_chain(directory,action):
 records=phase_records(directory);previous=None
 for index,(path,value) in enumerate(records):
  assert value['action_id']==action and value['sequence']==index and value['previous_event_sha256']==previous
  previous=sha(path.read_bytes())
 return records
with tempfile.TemporaryDirectory(prefix='hepta-client-r6-host-') as tmp:
 root=Path(tmp).resolve();command='synthetic command NEVER executed '+secrets.token_hex(16)
 captured=[];m._emit_raw=lambda fd,data:captured.append((fd,bytes(data)))
 for name,failure,expected_phase,definitely_not_sent in [
   ('connect','connect','connect_attempt',True),
   ('peer_query','peer_query','peer_identity_query',True),
   ('first_send','send_first','request_send_begin',False),
   ('partial_send','send_partial','request_send_begin',False),
   ('receive_header','receive_header','response_header_begin',False),
   ('receive_body','receive_body','response_header_begin',False)]:
  action=secrets.token_hex(16);directory=root/name;factory=Factory(response(action,command),failure=failure);install(factory)
  code=m.execute(command,action,1000,receipt_dir=directory)
  result=read_json(directory/(action+'.result.json'));progress=result['client_transport']['transport']
  check(name+'_exit71_retained_unknown',code==71 and result['state']=='indeterminate' and result['can_redispatch'] is False)
  check(name+'_precise_phase_and_send_boundary',progress['failed_phase']==expected_phase and progress['request_definitely_not_sent']==definitely_not_sent)
  check(name+'_durable_phase_chain',len(validate_chain(directory/(action+'.transport-r6'),action))>=3)
  check(name+'_socket_closed',all(s.closed for s in factory.instances))
  if failure=='send_partial':check('partial_positive_byte_count_preserved',progress['confirmed_send_bytes']==7)
  if failure=='receive_header':check('full_request_precedes_recv_error',progress['request_frame_complete'] is True and progress['confirmed_send_bytes']==progress['request_frame_bytes'])
  claimraw=(directory/(action+'.claim.json')).read_bytes()
  check(name+'_one_claim_preserved',read_json(directory/(action+'.claim.json'))['state']=='intent' and bool(claimraw))
 for name,kw in [('foreign_uid',{'uid':2000}),('foreign_gid',{'gid':2000}),('foreign_server_domain',{'context':'u:r:magisk:s0'})]:
  action=secrets.token_hex(16);factory=Factory(response(action,command),**kw);install(factory);directory=root/name
  code=m.execute(command,action,1000,receipt_dir=directory)
  progress=read_json(directory/(action+'.result.json'))['client_transport']['transport']
  check(name+'_denied_before_send',code==71 and not progress['send_attempted'] and all(not s.sent for s in factory.instances))
 action=secrets.token_hex(16);directory=root/'success';factory=Factory(response(action,command));install(factory);captured.clear()
 check('full_r6_receipt_returns0',m.execute(command,action,1000,receipt_dir=directory)==0)
 check('raw_stdout_preserved_exact',b''.join(data for fd,data in captured if fd==1)==b'fixture-only stdout\n')
 record=read_json(directory/(action+'.result.json'))
 check('complete_transport_and_exact_byte_counts',record['client_transport']['transport']['phase']=='transport_complete'
   and record['client_transport']['transport']['response_frame_complete'] is True)
 events=validate_chain(directory/(action+'.transport-r6'),action)
 names=[value['phase'] for _p,value in events]
 check('writeahead_send_phase_precedes_request_sent',names.index('request_send_begin')<names.index('request_sent'))
 check('trace_does_not_duplicate_command_or_user_output',all(command.encode() not in p.read_bytes() and b'fixture-only stdout' not in p.read_bytes() for p,_v in events))
 claim_before=(directory/(action+'.claim.json')).read_bytes();events_before=[(p.name,sha(p.read_bytes())) for p,_v in events]
 duplicate=Factory(response(action,command));install(duplicate)
 check('duplicate_current_action_only_inspects',m.execute(command,action,1000,receipt_dir=directory)==76 and duplicate.operations==['inspect'])
 check('duplicate_claim_and_original_phases_unchanged',(directory/(action+'.claim.json')).read_bytes()==claim_before
   and [(p.name,sha(p.read_bytes())) for p,_v in validate_chain(directory/(action+'.transport-r6'),action)]==events_before)
 action=secrets.token_hex(16);directory=root/'legacy';directory.mkdir()
 legacy={'version':1,'action_id':action,'command_sha256':sha(command.encode()),'state':'intent','timeout_ms':1000}
 raw=m._json_bytes(legacy);(directory/(action+'.claim.json')).write_bytes(raw)
 unused=Factory(response(action,command));install(unused)
 check('legacy_claim_never_retargets_to_new_executor',m.execute(command,action,1000,receipt_dir=directory)==76 and unused.instances==[])
 check('legacy_claim_bytes_unchanged',(directory/(action+'.claim.json')).read_bytes()==raw and not (directory/(action+'.transport-r6')).exists())
 for name,changes in [
  ('terminal_truthy',{'terminal':'true'}),('boolean_exit',{'exit_code':False}),
  ('wrong_worker_domain',{'execution_context':m.EXPECTED_SERVER_CONTEXT}),
  ('lost_wait_identity',{'waitpid_identity_lost':True}),('missing_handshake',{'handshake_stage':'legacy'}),
  ('wrong_execute_peer',{'peer_context':'u:r:magisk:s0'}),('multiple_dispatch',{'dispatch_count':2}),
  ('bad_group',{'pgid':9999}),('root_effect_identity',{'execution_uid':0}),
  ('missing_worker_validation',{'worker_domain_verified':False}),('old_revision',{'executor_revision':5})]:
  action=secrets.token_hex(16);factory=Factory(response(action,command,**changes));install(factory)
  check(name+'_never_client0',m.execute(command,action,1000,receipt_dir=root/name)!=0)
 factory=Factory({'version':1,'protocol':m.PROTOCOL,'state':'ready','executor_revision':6,
    'executor_context':m.EXPECTED_SERVER_CONTEXT,'peer_context':'u:r:magisk:s0','execute_authorized':False});install(factory)
 value=m.request({'version':1,'op':'health'},timeout_s=1)
 check('readonly_health_reports_actual_nonexecute_authority',value['execute_authorized'] is False and factory.operations==['health'])
 factory=Factory({});install(factory)
 try:m.request({'version':1,'op':'health'},socket_name='legacy-endpoint')
 except ValueError:check('no_endpoint_fallback',not factory.instances)
 else:raise AssertionError('wrong endpoint used')
 before=list(root.iterdir())
 factory=Factory({});install(factory)
 try:m.request({'version':1,'op':'health'},timeout_s=0)
 except TimeoutError as exc:
  check('global_transport_deadline_before_connect',not factory.connects and exc.hepta_transport['request_definitely_not_sent'] is True)
 else:raise AssertionError('zero transport budget accepted')
 check('readonly_requests_do_not_create_claims',list(root.iterdir())==before)
report={'schema':'hepta.client-r6-host-validation.v150.1','source_sha256':sha((HERE/'tool_client_r6.py').read_bytes()),
   'host_only':True,'phone_calls':0,'model_calls':0,'actual_socket_connections':0,'actual_shell_commands':0,
   'checks_passed':len(checks),'checks':checks,'fixture_limit':'Socket syscall outcomes are injected; physical IPC/domain/worker qualification remains separate.'}
with (HERE/'HOST-CHECKS-01.json').open('x') as out:json.dump(report,out,indent=2);out.write('\n');out.flush();os.fsync(out.fileno())
print(json.dumps(report,indent=2))
