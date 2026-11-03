#!/usr/bin/env python3
"""Read-only verification of one frozen r3 native executor component's exported originals.

No phone, socket, subprocess, model or task action. This is not the daily/model
collector. Supplied native records do not attest unseen global WAL predecessors.
"""
import argparse,base64,hashlib,json,os,re,stat,struct,sys,types
from pathlib import Path
AUDIT_SHA='da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf'
PROVIDER_SHA='83e867936e6db85e5187a6e8853c40b7bdd9804a27cdd09591c1a8274a950295'
CLIENT_SHA='500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f'
RULE_SHA='b83280ba8be66d532e94a66fb5f03c586478deb62f33bc89649d3298cb08cb2f'
POLICY_SHA='3983cdba0e46e826fcf9d1cd67821c998849af7cc45fc863f2ce950897dde613'
STATE='/var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6'
CLIENT='/var/lib/trillionnium/owner-open/phone-local-v150/tool_client_r6.py'
PARENT='u:r:trillionnium_owner_open_phone_executor:s0'
WORKER='u:r:trillionnium_owner_open_phone_worker:s0'
BOOTSTRAP='u:r:trillionnium_owner_open_bootstrap:s0'
MAGISK='u:r:magisk:s0'
ENDPOINT='hepta_phone_executor_v150_r6'
PROTOCOL='trillionnium.owner-open.provider-jsonl.v1'
EXECUTOR_PROTOCOL='hepta_phone_local_v150'
KEYS=('session_id','profile_id','task_id','turn_id','turn_stream_id')
SCOPE='native executor component only; zero model requests and zero business UI effects; HEPTA task-entry UI counted separately'
SUMMARY='本地执行器组件探针通过；仅固定 stdout 标记，未进行模型或 App 业务验收。'
PHASES=['claim_durable_before_transport','socket_create_attempt','socket_created','connect_attempt',
'connected','peer_identity_query','peer_verified','request_send_begin','request_sent',
'response_header_begin','response_header_received','response_body_begin','response_received',
'response_validated','transport_complete']
def need(ok,label):
 if not ok:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value,sort=True,newline=False):
 return (json.dumps(value,sort_keys=sort,ensure_ascii=False,separators=(',',':'),allow_nan=False)+('\n' if newline else '')).encode()
def strict(raw):
 def pairs(items):
  value={}
  for k,v in items:
   need(k not in value,'duplicate_json_key');value[k]=v
  return value
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite_json')))
def exact(obj,expected,label):
 need(isinstance(obj,dict) and all(k in obj and type(obj[k]) is type(v) and obj[k]==v for k,v in expected.items()),label)
def positive_int(value):return type(value) is int and value>0
def decoded(value):
 need(isinstance(value,str),'base64_string_required')
 return base64.b64decode(value,validate=True)
class Snapshot:
 def __init__(self):self.rows={};self.total=0
 def read(self,path,limit=262144):
  path=Path(path).absolute()
  need(path.parent.resolve(strict=True)==path.parent,'noncanonical_input_parent')
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
  try:
   before=os.fstat(fd)
   need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=limit,'input_file_bound_or_type')
   with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(limit+1)
   after=os.fstat(fd);named=path.lstat()
   fields=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
   need(len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k)==getattr(named,k) for k in fields),'input_changed_or_short')
  finally:os.close(fd)
  row={'path':str(path),'bytes':len(raw),'sha256':sha(raw),'identity':[getattr(before,k) for k in fields]}
  if str(path) in self.rows:need(self.rows[str(path)]==row,'input_changed_between_reads')
  else:self.total+=len(raw)
  need(self.total<=32*1024*1024,'input_total_bound');self.rows[str(path)]=row
  return raw
 def json(self,path,limit=262144):return strict(self.read(path,limit))
 def absent(self,path):
  path=Path(path).absolute();need(path.parent.resolve(strict=True)==path.parent,'absence_parent_unverified')
  try:path.lstat()
  except FileNotFoundError:return True
  return False
 def unchanged(self):
  for row in self.rows.values():
   st=Path(row['path']).lstat()
   need([getattr(st,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')]==row['identity'],'input_changed_after_snapshot')
def jsonl(snap,path):
 raw=snap.read(path,4*1024*1024)
 need(raw and raw.endswith(b'\n'),'incomplete_jsonl_boundary')
 lines=raw.splitlines();need(len(lines)<=64 and all(lines),'jsonl_count_or_blank')
 return [strict(line) for line in lines]
def verify_contract(c,request,scope):
 expected={'schema':'hepta.native-component-probe.contract.v150.r6.1','executor_journal':'/data/trillionnium/owner-open/state/phone-local-v150/executor-r6-component-01',
 'endpoint':ENDPOINT,'client_sha256':CLIENT_SHA,'parent_sha256':'8595f99cf8d0f39ec2a45f85f1250745c158ea504d2d0520cd83791f28bdb976',
 'worker_sha256':'49fb74f8798194c63d5e510c0ed81604d64a55e1df84822d9457ae4110cab6da',
 'policy_rule_sha256':RULE_SHA,'patched_policy_sha256':POLICY_SHA,
 'retirement_proof_sha256':'2bdd6c33c42359f1b27567b99627f7223d40a0c37f6af0158b8dc010e899943e',
 'retirement_resolution_sha256':'7e06216823c49ec8b3949efa334e61b6731ca3f9bd4a039edbea771fb849a433',
 'provider_source_sha256':PROVIDER_SHA,'scope':SCOPE}
 names=set(expected)|{'nonce','owner_request_sha256','selected_session_id','selected_profile_id','executor_server_instance','expires_unix_ms'}
 need(isinstance(c,dict) and set(c)==names,'contract_exact_fields');exact(c,expected,'contract_frozen_inputs')
 for k in ('nonce','executor_server_instance'):need(isinstance(c[k],str) and re.fullmatch('[0-9a-f]{32}',c[k]) is not None,'contract_nonce_or_instance')
 need(set(scope)==set(KEYS) and all(isinstance(scope[k],str) and 0<len(scope[k].encode())<=256 and '\0' not in scope[k] for k in KEYS),'exact_five_field_scope')
 need(c['selected_session_id']==scope['session_id'] and c['selected_profile_id']==scope['profile_id'],'contract_selected_scope')
 owner=('执行一次手机本地执行器组件资格探针，标记 '+c['nonce']+'。只通过原生工具通道输出该新标记一次；不调用模型，不操作任何 App，不重放旧动作。').encode()
 need(request==owner and c['owner_request_sha256']==sha(request),'exact_component_owner_bytes')
 need(positive_int(c['expires_unix_ms']),'contract_expiry_type')
 action=sha(encoded({'scope':scope,'nonce':c['nonce'],'owner_request_sha256':sha(request)},newline=True))[:32]
 command="printf '%s\\n' 'hepta_executor_component_"+c['nonce']+"'"
 expected_stdout=('hepta_executor_component_'+c['nonce']+'\n').encode('ascii')
 return action,command,expected_stdout
def verify_receipt(intent,receipt,c,action,command,stdout,stderr):
 common={'version':1,'executor_revision':6,'action_id':action,'command_sha256':sha(command.encode()),'timeout_ms':3000,
 'server_instance':c['executor_server_instance'],'peer_uid':0,'peer_context':BOOTSTRAP,'executor_context':PARENT,
 'handshake_stage':'worker_entry_after_exec_transition','execution_credentials_scope':'android_shell_uid2000',
 'required_execution_uid':2000,'required_execution_gid':2000,'can_redispatch':False}
 exact(intent,common,'immutable_intent_binding');exact(receipt,common,'original_receipt_binding')
 exact(intent,{'state':'intent','terminal':False,'effect_started':False,'dispatch_count':0,
 'worker_domain_verified':False,'execution_context':None,'execution_credentials_verified':False,
 'execution_uid':None,'execution_euid':None,'execution_gid':None,'execution_egid':None,
 'execution_supplementary_group_count':None,'supplementary_groups_cleared':None},'immutable_pre_effect_intent')
 need('intent_parent_sync_complete' not in intent,'intent_must_not_be_rewritten_as_post_sync_receipt')
 need(positive_int(intent.get('created_unix_ms')) and receipt.get('created_unix_ms')==intent['created_unix_ms'],'intent_receipt_original_creation')
 exact(receipt,{'state':'completed','terminal':True,'intent_parent_sync_complete':True,'dispatch_count':1,'exit_code':0,'term_signal':None,
 'effect_started':True,'process_group_established':True,'waitpid_joined':True,'process_group_absent':True,
 'waitpid_identity_lost':False,'execution_credentials_verified':True,'execution_uid':2000,'execution_euid':2000,
 'execution_gid':2000,'execution_egid':2000,'supplementary_groups_cleared':True,'execution_supplementary_group_count':0,
 'worker_domain_verified':True,'execution_context':WORKER,'client_disconnected':False,'error':'',
 'stdout_bytes':len(stdout),'stderr_bytes':len(stderr),'stdout_sha256':sha(stdout),'stderr_sha256':sha(stderr)},'strict_r6_complete_terminal')
 need(type(receipt.get('pid')) is int and receipt['pid']>1 and type(receipt.get('pgid')) is int and receipt['pid']==receipt['pgid'],'owned_effect_pid_group')
 need(type(receipt.get('elapsed_ms')) is int and receipt['elapsed_ms']>=0 and positive_int(receipt.get('completed_unix_ms')),'receipt_completion_clock_fields')
def provider_streams(result,call):
 exact(result,{'protocol':PROTOCOL,'seq':1,'kind':'tool.result','call_id':call['call_id'],'status':'terminal'},'provider_native_result_header')
 terminal=result.get('terminal')
 exact(terminal,{'kind':'exited','exit_code':0,'signal':None,'error':None,'output_truncated':False},'provider_native_success_terminal')
 rows=result.get('events');need(isinstance(rows,list) and 3<=len(rows)<=32,'native_provider_event_bound')
 streams={'stdout':bytearray(),'stderr':bytearray()};kinds=[];started=None
 for i,row in enumerate(rows):
  exact(row,{'call_id':call['call_id'],'tool':'shell.exec','seq':i},'native_provider_event_identity')
  event=row.get('event',{});kind=event.get('kind');kinds.append(kind)
  if kind=='output':
   need(event.get('stream') in streams and event.get('encoding')=='base64','native_provider_stream')
   raw=decoded(event['data']);need(type(event.get('byte_count')) is int and event['byte_count']==len(raw),'native_provider_chunk_bytes')
   streams[event['stream']].extend(raw);need(sum(map(len,streams.values()))<=4096,'native_provider_output_bound')
  elif kind=='started':need(type(event.get('pid')) is int and event['pid']>1,'native_client_started_pid');started=event['pid']
  elif kind=='terminal':need(i==len(rows)-1 and event.get('terminal')==terminal,'native_provider_terminal_event')
  else:need(kind=='accepted','unexpected_native_provider_event')
 need(kinds[:2]==['accepted','started'] and kinds[-1]=='terminal' and all(kinds.count(k)==1 for k in ('accepted','started','terminal')),'native_provider_lifecycle_once')
 for k,v in streams.items():need(type(terminal.get(k+'_bytes')) is int and terminal[k+'_bytes']==len(v),'native_provider_terminal_length')
 registry=result.get('registry',{})
 exact(registry,{'call_id':call['call_id'],'tool':'shell.exec','cancellation_requested':False,'connection_lost':False},'native_registry_identity')
 need(isinstance(registry.get('state'),str) and registry['state'].startswith('Terminal {'),'native_registry_terminal')
 return {k:bytes(v) for k,v in streams.items()},started
def verify_transport(snap,root,action,command,receipt,stdout,stderr,client_pid,ready):
 claim=snap.json(root/(action+'.claim.json'));saved=snap.json(root/(action+'.result.json'))
 exact(claim,{'version':1,'action_id':action,'command_sha256':sha(command.encode()),'timeout_ms':3000,'state':'intent',
 'client_revision':6,'endpoint':ENDPOINT,'client_source_sha256':CLIENT_SHA},'original_client_one_use_claim')
 need(positive_int(claim.get('created_unix_ms')),'client_claim_clock')
 need(snap.absent(root/(action+'.last-inspect.json')),'duplicate_execute_inspection_present')
 exact(saved,{'version':1,'protocol':EXECUTOR_PROTOCOL,'duplicate':False},'client_original_response_envelope')
 need(set(saved)=={'version','protocol','duplicate','receipt','client_transport'} and saved['receipt']==receipt,'client_original_receipt_equal')
 trace=saved['client_transport'];directory=root/(action+'.transport-r6')
 exact(trace,{'schema':'hepta.client-transport-trace.v150.r6','directory':STATE+'/client-receipts/'+action+'.transport-r6','automatic_replay':False},'client_transport_summary_binding')
 paths=sorted(directory.iterdir());need([p.name for p in paths]==['%02d-%s.json'%(i,p) for i,p in enumerate(PHASES)],'client_exact_single_success_phase_chain')
 previous=None;rows=[];phase_values=[];last_clock=None;last=None
 for i,path in enumerate(paths):
  raw=snap.read(path,32768);row=strict(raw)
  exact(row,{'schema':'hepta.client-transport-event.v150.r6','client_revision':6,'action_id':action,
   'command_sha256':sha(command.encode()),'client_pid':client_pid,'client_source_sha256':CLIENT_SHA,
   'endpoint':ENDPOINT,'automatic_replay':False,'sequence':i,'phase':PHASES[i],'previous_event_sha256':previous},'client_phase_identity_or_chain')
  need(positive_int(row.get('monotonic_ns')) and positive_int(row.get('created_unix_ms')),'client_phase_clocks')
  need(last_clock is None or row['monotonic_ns']>=last_clock,'client_phase_time_order')
  last_clock=row['monotonic_ns'];previous=sha(raw);rows.append({'name':path.name,'sha256':previous,'bytes':len(raw)});phase_values.append(row);last=row
 need(trace.get('events')==rows and trace.get('last_event_sha256')==previous and trace.get('transport')==last['transport'],'client_phase_summary_matches_originals')
 need(ready['ready_monotonic_ns']<=last_clock<=ready['service_deadline_monotonic_ns']+1000,'client_transport_inside_original_service_window')
 payload={'version':1,'op':'execute','action_id':action,'command_sha256':sha(command.encode()),'command':command,'timeout_ms':3000}
 request=encoded(payload,sort=False);request_wire=struct.pack('>I',len(request))+request
 response={'version':1,'protocol':EXECUTOR_PROTOCOL,'duplicate':False,'receipt':receipt,
 'stdout_b64':base64.b64encode(stdout).decode(),'stderr_b64':base64.b64encode(stderr).decode()}
 # Pinned nlohmann json::dump orders map keys and has no trailing LF.
 response_raw=encoded(response)
 need(phase_values[0].get('transport')=={},'claim_phase_must_precede_transport')
 for i,row in enumerate(phase_values[1:],1):
  phase=row['transport']
  exact(phase,{'phase':PHASES[i],'operation':'execute','endpoint':ENDPOINT,
   'payload_sha256':sha(request),'request_frame_sha256':sha(request_wire),'request_frame_bytes':len(request_wire),
   'connected':i>=4,'peer_identity_verified':i>=6,'send_attempted':i>=7,
   'request_frame_complete':i>=8,'response_frame_complete':i>=12,'automatic_replay':False},'client_phase_transport_fence')
  need(type(phase.get('confirmed_send_bytes')) is int and phase['confirmed_send_bytes']==(0 if i<8 else len(request_wire)),'client_phase_send_count')
  need(type(phase.get('confirmed_receive_bytes')) is int and phase['confirmed_receive_bytes']==(0 if i<10 else 4 if i<12 else 4+len(response_raw)),'client_phase_receive_count')
  if i>=6:exact(phase,{'peer_uid':0,'peer_gid':0,'peer_context':PARENT},'client_peer_verified_before_send')
 p=last['transport']
 exact(p,{'operation':'execute','phase':'transport_complete','endpoint':ENDPOINT,'payload_sha256':sha(request),
 'request_frame_sha256':sha(request_wire),'request_frame_bytes':len(request_wire),'confirmed_send_bytes':len(request_wire),
 'confirmed_receive_bytes':4+len(response_raw),'response_body_bytes':len(response_raw),'response_body_sha256':sha(response_raw),
 'connected':True,'peer_identity_verified':True,'send_attempted':True,'request_frame_complete':True,
 'response_frame_complete':True,'automatic_replay':False,'peer_uid':0,'peer_gid':0,'peer_context':PARENT,
 'request_may_have_reached_executor':True},'client_complete_transport_and_peer_identity')
 need(type(p.get('peer_pid')) is int and p['peer_pid']>1,'executor_peer_pid')
 return {'client_pid':client_pid,'executor_peer_pid':p['peer_pid'],'phase_count':len(rows),
 'phase_chain_last_raw_sha256':previous,'original_response_body_sha256':sha(response_raw)}
def verify(args,snap,report):
 check=lambda name:report['checks_passed'].append(name)
 source=snap.read(args.provider_source,65536);client=snap.read(args.client_source,32768)
 need(sha(source)==PROVIDER_SHA and sha(client)==CLIENT_SHA,'frozen_provider_client_source_pins');check('actual_exported_provider_client_source_pins')
 audit_raw=snap.read(Path(__file__).with_name('native_journal_audit.py'),16384)
 need(sha(audit_raw)==AUDIT_SHA,'frozen_native_auditor_pin')
 auditor=types.ModuleType('pinned_native_auditor');exec(compile(audit_raw,'pinned_native_auditor','exec'),auditor.__dict__)
 request=snap.read(args.request_file,16384);contract_raw=snap.read(args.contract_file,16384);c=strict(contract_raw)
 need(sha(contract_raw)==args.contract_sha256,'operator_selected_contract_raw_sha256')
 scope=snap.json(args.scope_file,16384)
 action,command,expected=verify_contract(c,request,scope)
 report.update(identity=scope,owner_request_utf8_sha256=sha(request),contract_raw_sha256=sha(contract_raw),
  nonce=c['nonce'],action_id=action,command_sha256=sha(command.encode()),executor_server_instance=c['executor_server_instance'])
 check('exact_new_owner_contract_and_five_scope_binding')
 root=Path(args.component_root).absolute();nonce=c['nonce']
 need(snap.read(root/'contracts'/(nonce+'.json'),16384)==contract_raw,'retained_registered_contract_bytes')
 claim=snap.json(root/'claims'/(nonce+'.json'),16384)
 exact(claim,{'scope':scope,'owner_request_sha256':sha(request),'action_id':action,'call_id':'component-'+nonce,
 'executor_server_instance':c['executor_server_instance'],'state':'accepted_never_replay'},'component_nonce_one_use_claim')
 original_run=claim.get('run_dir','');run_name=original_run.removeprefix(STATE+'/evidence/')
 need(original_run==STATE+'/evidence/'+run_name and re.fullmatch('[0-9]{8}-[0-9]{6}-[0-9a-f]{32}',run_name) is not None,'actual_component_run_directory')
 run=root/'evidence'/run_name
 ready=snap.json(root/('ready-'+nonce+'.json'),16384)
 exact(ready,{'nonce':nonce,'owner_request_sha256':sha(request),'provider_source_sha256':PROVIDER_SHA,
 'contract_sha256':sha(contract_raw),'executor_server_instance':c['executor_server_instance'],
 'port':18080,'scope':SCOPE,'accepting_one_session':True,'clock':'phone CLOCK_MONOTONIC',
 'readiness_scope':'transport_and_readonly_parent_identity_only'},'original_ready_identity')
 need(type(ready.get('pid')) is int and ready['pid']>1 and positive_int(ready.get('pid_start_ticks')) and isinstance(ready.get('instance'),str) and re.fullmatch('[0-9a-f]{32}',ready['instance']) is not None,'original_ready_process_identity')
 times=[ready.get(k) for k in ('ready_monotonic_ns','accept_deadline_monotonic_ns','service_deadline_monotonic_ns')]
 need(all(positive_int(v) for v in times) and 0<times[1]-times[0]<=40000001000 and abs(times[2]-times[1]-30000000000)<=1000,'original_service_window_unextended')
 attempt=snap.json(root/('service-attempt-'+nonce+'.json'),16384)
 need(attempt=={'contract_sha256':sha(contract_raw),'automatic_restart':False,'pid':ready['pid']},'original_one_service_attempt')
 health=snap.json(root/('health-before-'+nonce+'.json'),16384)
 exact(health,{'version':1,'protocol':EXECUTOR_PROTOCOL,'server_instance':c['executor_server_instance'],
 'state':'ready','inference_endpoint':False,'executor_revision':6,'executor_context':PARENT,'peer_context':MAGISK,
 'execute_authorized':False,'required_worker_context':WORKER},'original_readonly_parent_health')
 check('retained_nonce_claim_and_original_service_identity')
 incoming=jsonl(snap,run/'provider-in.jsonl');outgoing=jsonl(snap,run/'provider-out.jsonl')
 need(len(incoming)==2 and len(outgoing)==2,'one_start_result_and_one_call_complete_only')
 need(incoming[0]=={'protocol':PROTOCOL,'seq':0,'kind':'turn.start','turn':dict(scope,user_input=request.decode('utf-8'))},'original_turn_start_owner_scope')
 call_id='component-'+nonce
 call={'call_id':call_id,'tool':'shell.exec',
 'argv':['/usr/bin/python3',CLIENT,'execute','--action-id',action,'--command-b64',base64.b64encode(command.encode()).decode(),
 '--timeout-ms','3000','--receipt-dir',STATE+'/client-receipts'],'timeout_ms':15000,**scope}
 need(outgoing[0]=={'protocol':PROTOCOL,'seq':0,'kind':'tool.call','call':call},'exact_only_fixed_native_tool_call')
 need(outgoing[1]=={'protocol':PROTOCOL,'seq':1,'kind':'turn.complete','summary':SUMMARY},'provider_successful_terminal')
 accepted=snap.json(run/'accepted.json');need(accepted=={'scope':scope,'action_id':action,'owner_request_sha256':sha(request),'contract':c},'original_accepted_binding')
 dispatch=snap.json(run/'dispatch-intent.json')
 need(dispatch=={'state':'reserved_before_wire_result_may_be_unknown','scope':scope,'action_id':action,'call':call,
 'command_sha256':sha(command.encode()),'executor_instance':c['executor_server_instance'],'automatic_replay':False},'original_single_dispatch_intent')
 need(snap.json(run/'native-tool-result.json')==incoming[1],'saved_native_result_equals_original_transcript')
 streams,client_pid=provider_streams(incoming[1],call)
 need(streams=={'stdout':expected,'stderr':b''},'original_native_marker_exact')
 for name in ('component-failure.json','original-executor-inspection-error.json'):
  need(snap.absent(run/name),'component_original_failure_present')
 need(not list(run.glob('local-*')) and not list(run.glob('*http*')),'model_evidence_present_in_fixed_no_model_component')
 check('one_native_call_original_result_and_zero_model_provider_path')
 action_dir=Path(args.executor_root).absolute()/'actions'/action
 need(snap.absent(action_dir/'receipt.pending'),'uncommitted_executor_pending_receipt')
 intent_raw=snap.read(action_dir/'intent.json');receipt_raw=snap.read(action_dir/'receipt.json')
 intent,receipt=strict(intent_raw),strict(receipt_raw)
 stdout=snap.read(action_dir/'stdout.bin',4096);stderr=snap.read(action_dir/'stderr.bin',4096)
 need(stdout==expected and stderr==b'' and streams=={'stdout':stdout,'stderr':stderr},'sidecar_native_raw_bytes_equal')
 verify_receipt(intent,receipt,c,action,command,stdout,stderr)
 report['executor_effect_verified']={'state':'completed','exit_code':0,'dispatch_count':1,'safe_join_and_group_absence':True,
 'worker_uid_gid':2000,'worker_context':WORKER,'handshake_stage':'worker_entry_after_exec_transition',
 'intent_original_raw_sha256':sha(intent_raw),'receipt_original_raw_sha256':sha(receipt_raw),
 'receipt_canonical_with_newline_sha256':sha(encoded(receipt,newline=True)),
 'stdout_bytes':len(stdout),'stdout_sha256':sha(stdout),'stderr_bytes':0,'stderr_sha256':sha(stderr)}
 check('strict_r6_intent_receipt_credentials_domain_and_cleanup')
 inspected=snap.json(run/'original-executor-inspection.json')
 need(inspected=={'version':1,'protocol':EXECUTOR_PROTOCOL,'duplicate':False,'receipt':receipt},'original_readonly_inspection_equals_immutable_terminal')
 report['client_transport']=verify_transport(snap,root/'client-receipts',action,command,receipt,stdout,stderr,client_pid,ready)
 check('client_original_claim_response_peer_and_durable_phase_chain')
 records=snap.json(args.native_records,8*1024*1024)
 need(isinstance(records,list) and 1<=len(records)<=128 and all(isinstance(r,dict) and r.get('scope')==scope for r in records),'selected_original_native_records_scope')
 audit=auditor.verify_records(records,scope)
 report['native_audit']={k:v for k,v in audit.items() if k not in ('selected_records','frames')}
 need(audit['status']=='PASS','native_hash_or_sequence_failed')
 frames=audit['frames'];native_request=records[0]['payload']['request_sha256']
 report['native_turn_request_sha256']=native_request
 need(sum(f['kind']=='turn.accepted' for f in frames)==1 and sum(f['kind']=='turn.end' for f in frames)==1,'native_single_turn_boundaries')
 ending=frames[-1]['payload'];exact(ending,{'status':'completed','error':None,'summary':SUMMARY,'runtime_ready':True,'event_log_status':'durable','event_log_error':None},'actual_native_turn_end_not_completed')
 tf=[f for f in frames if f['kind'].startswith('tool.')]
 need(tf and all(f.get('call_id')==call_id and f.get('tool')=='shell.exec' for f in tf),'native_has_other_tool_or_call')
 need([f['kind'] for f in tf[:2]]==['tool.accepted','tool.started'] and tf[-1]['kind']=='tool.result','native_tool_lifecycle_order')
 need(all(sum(f['kind']==kind for f in tf)==1 for kind in ('tool.accepted','tool.started','tool.result')),'native_tool_lifecycle_once')
 native_streams={'stdout':bytearray(),'stderr':bytearray()}
 for i,f in enumerate(tf):
  p=f['payload'];exact(p,{'runtime_seq':i,'event_log_status':'durable','event_log_error':None},'native_runtime_sequence_or_durability')
  if f['kind'] in ('tool.stdout','tool.stderr'):
   need(p.get('encoding')=='base64','native_output_encoding')
   data=decoded(p['data']);need(type(p.get('byte_count')) is int and p['byte_count']==len(data),'native_output_length')
   native_streams[f['kind'].split('.')[1]].extend(data)
  else:need(f['kind'] in ('tool.accepted','tool.started','tool.result'),'native_unexpected_tool_frame')
 need(tf[1]['payload'].get('pid')==client_pid,'native_started_client_transport_pid')
 terminal=incoming[1]['terminal'];native_terminal=tf[-1]['payload']
 exact(native_terminal,{'status':'terminal','terminal_kind':'exited','exit_code':0,'signal':None,
 'error':None,'output_truncated':False,'stdout_bytes':len(expected),'stderr_bytes':0},'native_actual_tool_exit0')
 need({k:bytes(v) for k,v in native_streams.items()}==streams,'native_wal_provider_and_sidecar_raw_streams')
 need(all(f['kind'] in {'turn.accepted','turn.end','model.message','tool.accepted','tool.started','tool.stdout','tool.stderr','tool.result'} for f in frames),'unexpected_native_frame')
 messages=[f for f in frames if f['kind']=='model.message']
 need(len(messages)<=1 and all(f['payload'].get('text')==SUMMARY for f in messages),'native_summary_message_differs')
 check('independent_native_hashes_raw_streams_lifecycle_and_completed_turn')
 outcome=snap.json(run/'component-outcome.json')
 exact(outcome,{'state':'component_postconditions_pass','scope':SCOPE,'identity':scope,'action_id':action,
 'original_receipt_canonical_json_sha256':sha(encoded(receipt,newline=True)),'model_requests':0,'ui_business_actions':0,
 'native_turn_end_verified':False,'business_qualified':False},'provider_outcome_is_original_scoped_claim')
 need(outcome['native_tool']=={'stdout_sha256':sha(expected),'stdout_bytes':len(expected),'stderr_sha256':sha(b''),'stderr_bytes':0,'native_exit_code':0},'provider_outcome_original_stream_digest')
 need(snap.json(run/'provider-terminal-intent.json')=={'kind':'turn.complete','fields':{'summary':SUMMARY},'native_terminal_independently_verified':False},'provider_terminal_intent')
 ended=snap.json(root/('service-ended-'+nonce+'.json'),16384)
 need(ended=={'accepted_connection':True,'exit_code':0,'automatic_restart':False,'native_terminal_verified':False,'operator_must_retire_component_executor':True},'original_service_end_not_confirmed')
 check('original_scoped_outcome_and_service_end_preserved')
 report['scope_boundaries']={'owner_request':'exact pinned request UTF8 bytes','native_task':scope,
 'ready_scope':SCOPE,'effect':{'action_id':action,'command_sha256':sha(command.encode()),'server_instance':c['executor_server_instance']},
 'model_zero_claim':'This pinned component provider and its only fixed printf tool call; not whole-device traffic',
 'ui_business_zero_claim':'Fixed stdout-only command; separate operator HEPTA task entry/draft restoration not counted'}
 report['component_pass']=True;report['state']='VERIFIED_NATIVE_EXECUTOR_COMPONENT'
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('request-file','contract-file','scope-file','component-root','executor-root','native-records','provider-source','client-source','out'):
  p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--contract-sha256',required=True)
 a=p.parse_args()
 out=a.out.absolute();need(out.parent.resolve(strict=True)==out.parent,'output_parent_noncanonical')
 need(not out.exists(),'new_output_file_required')
 snap=Snapshot();report={'schema':'hepta.native-component-original-verification.v150.r6.1',
 'state':'INCOMPLETE_OR_FAILED_INDEPENDENT_VERIFICATION','component_pass':False,'checks_passed':[],'issues':[],
 'phone_calls':0,'model_calls':0,'socket_connections':0,'service_changes':0,'task_submissions':0,
 'business_qualified':False,'daily_use_qualified':False,'fixed19_case_credit':False,
 'live_policy_byte_identity_verified_by_this_checker':False,
 'external_policy_boundary':'Contract declares pinned offline rules/patched inputs; Root live policy audit remains separate.',
 'process_retirement_boundary':'Receipt proves the effect group cleanup; parent/provider retirement remains separate.',
 'no_missing_SID_or_NNP_receipt_fields_invented':True}
 try:verify(a,snap,report);snap.unchanged()
 except (OSError,ValueError,TypeError,KeyError,UnicodeError,AttributeError,IndexError) as e:
  report['component_pass']=False;report['state']='INCOMPLETE_OR_FAILED_INDEPENDENT_VERIFICATION'
  report['issues'].append({'type':type(e).__name__,'message':str(e)})
 report['inputs']=list(snap.rows.values());report['input_bytes']=snap.total
 report['snapshot_scope']='Stable individual original files plus final identity recheck; no filesystem-wide atomic snapshot claim.'
 raw=(json.dumps(report,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
 fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 print(json.dumps({'state':report['state'],'component_pass':report['component_pass'],'report':str(out),'report_sha256':sha(raw),
 'checks_passed':len(report['checks_passed']),'issues':report['issues'],'phone_calls':0,'model_calls':0,'task_submissions':0},sort_keys=True))
 return 0 if report['component_pass'] else 2
if __name__=='__main__':sys.exit(main())
