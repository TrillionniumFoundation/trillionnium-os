"""One synthetic complete original bundle plus focused corruption checks; no external calls."""
import ast,base64,copy,hashlib,importlib.util,json,os,struct,tempfile
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
spec=importlib.util.spec_from_file_location('readonly_component_verifier',ROOT/'verify_component_originals.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
aspec=importlib.util.spec_from_file_location('fixture_native_hashes',ROOT/'native_journal_audit.py')
audit=importlib.util.module_from_spec(aspec);aspec.loader.exec_module(audit)
CHECKS=[]
def check(name,truth):
 if not truth:raise AssertionError(name)
 CHECKS.append(name)
def put(path,data):
 path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
def pj(path,value,newline=True):put(path,m.encoded(value,newline=newline))
def build(root,phase_fence_bad=False,native_failed=False,duplicate_started=False):
 component=root/'component';executor=root/'executor';n='12'*16;instance='34'*16
 scope={'session_id':'session-synthetic-component','profile_id':'owner-open','task_id':'task-synthetic-component','turn_id':'turn-synthetic-component','turn_stream_id':'stream-synthetic-component'}
 request=('执行一次手机本地执行器组件资格探针，标记 '+n+'。只通过原生工具通道输出该新标记一次；不调用模型，不操作任何 App，不重放旧动作。').encode()
 c={'schema':'hepta.native-component-probe.contract.v150.r6.1','nonce':n,'owner_request_sha256':m.sha(request),
 'selected_session_id':scope['session_id'],'selected_profile_id':scope['profile_id'],'executor_server_instance':instance,
 'executor_journal':'/data/trillionnium/owner-open/state/phone-local-v150/executor-r6-component-01','endpoint':m.ENDPOINT,
 'client_sha256':m.CLIENT_SHA,'parent_sha256':'8595f99cf8d0f39ec2a45f85f1250745c158ea504d2d0520cd83791f28bdb976',
 'worker_sha256':'49fb74f8798194c63d5e510c0ed81604d64a55e1df84822d9457ae4110cab6da',
 'policy_rule_sha256':m.RULE_SHA,'patched_policy_sha256':m.POLICY_SHA,
 'retirement_proof_sha256':'2bdd6c33c42359f1b27567b99627f7223d40a0c37f6af0158b8dc010e899943e',
 'retirement_resolution_sha256':'7e06216823c49ec8b3949efa334e61b6731ca3f9bd4a039edbea771fb849a433',
 'provider_source_sha256':m.PROVIDER_SHA,'expires_unix_ms':1793736900000,'scope':m.SCOPE}
 action,command,stdout=m.verify_contract(c,request,scope);stderr=b''
 craw=m.encoded(c,newline=True);csha=m.sha(craw)
 put(root/'request.txt',request);put(root/'contract.json',craw);pj(root/'scope.json',scope);put(component/'contracts'/(n+'.json'),craw)
 runname='20261103-200000-'+'ab'*16;run=component/'evidence'/runname;cid='component-'+n
 pj(component/'claims'/(n+'.json'),{'scope':scope,'owner_request_sha256':m.sha(request),'action_id':action,'call_id':cid,'executor_server_instance':instance,'run_dir':m.STATE+'/evidence/'+runname,'state':'accepted_never_replay'})
 now=1000000000000
 ready={'pid':4240,'pid_start_ticks':123456,'instance':'56'*16,'port':18080,'scope':m.SCOPE,
 'nonce':n,'owner_request_sha256':m.sha(request),'provider_source_sha256':m.PROVIDER_SHA,'contract_sha256':csha,
 'accepting_one_session':True,'executor_server_instance':instance,'clock':'phone CLOCK_MONOTONIC',
 'ready_monotonic_ns':now,'accept_deadline_monotonic_ns':now+40000000000,'service_deadline_monotonic_ns':now+70000000000,
 'readiness_scope':'transport_and_readonly_parent_identity_only'}
 pj(component/('ready-'+n+'.json'),ready)
 pj(component/('service-attempt-'+n+'.json'),{'contract_sha256':csha,'automatic_restart':False,'pid':4240})
 pj(component/('health-before-'+n+'.json'),{'version':1,'protocol':m.EXECUTOR_PROTOCOL,'server_instance':instance,'state':'ready',
 'inference_endpoint':False,'executor_revision':6,'executor_context':m.PARENT,'peer_context':m.MAGISK,'execute_authorized':False,'required_worker_context':m.WORKER})
 pj(component/('service-ended-'+n+'.json'),{'accepted_connection':True,'exit_code':0,'automatic_restart':False,'native_terminal_verified':False,'operator_must_retire_component_executor':True})
 call={'call_id':cid,'tool':'shell.exec','argv':['/usr/bin/python3',m.CLIENT,'execute','--action-id',action,'--command-b64',base64.b64encode(command.encode()).decode(),'--timeout-ms','3000','--receipt-dir',m.STATE+'/client-receipts'],'timeout_ms':15000,**scope}
 terminal={'kind':'exited','exit_code':0,'signal':None,'error':None,'output_truncated':False,'stdout_bytes':len(stdout),'stderr_bytes':0}
 events=[{'kind':'accepted'},{'kind':'started','pid':4241},{'kind':'output','stream':'stdout','encoding':'base64','data':base64.b64encode(stdout).decode(),'byte_count':len(stdout)},{'kind':'terminal','terminal':terminal}]
 result={'protocol':m.PROTOCOL,'seq':1,'kind':'tool.result','call_id':cid,'status':'terminal','terminal':terminal,
 'events':[{'call_id':cid,'tool':'shell.exec','seq':i,'event':event} for i,event in enumerate(events)],
 'registry':{'call_id':cid,'tool':'shell.exec','state':'Terminal { fixture: true }','cancellation_requested':False,'connection_lost':False}}
 incoming=[{'protocol':m.PROTOCOL,'seq':0,'kind':'turn.start','turn':dict(scope,user_input=request.decode())},result]
 outgoing=[{'protocol':m.PROTOCOL,'seq':0,'kind':'tool.call','call':call},{'protocol':m.PROTOCOL,'seq':1,'kind':'turn.complete','summary':m.SUMMARY}]
 put(run/'provider-in.jsonl',b''.join(m.encoded(v,newline=True) for v in incoming))
 put(run/'provider-out.jsonl',b''.join(m.encoded(v,newline=True) for v in outgoing))
 pj(run/'accepted.json',{'scope':scope,'action_id':action,'owner_request_sha256':m.sha(request),'contract':c})
 pj(run/'dispatch-intent.json',{'state':'reserved_before_wire_result_may_be_unknown','scope':scope,'action_id':action,'call':call,'command_sha256':m.sha(command.encode()),'executor_instance':instance,'automatic_replay':False})
 pj(run/'native-tool-result.json',result)
 intent={'version':1,'executor_revision':6,'action_id':action,'command_sha256':m.sha(command.encode()),'timeout_ms':3000,
 'server_instance':instance,'peer_uid':0,'peer_context':m.BOOTSTRAP,'executor_context':m.PARENT,
 'worker_domain_verified':False,'execution_context':None,'handshake_stage':'worker_entry_after_exec_transition',
 'created_unix_ms':1793736000000,'state':'intent','terminal':False,'effect_started':False,'dispatch_count':0,'can_redispatch':False,
 'execution_credentials_scope':'android_shell_uid2000','required_execution_uid':2000,'required_execution_gid':2000,
 'execution_credentials_verified':False,'execution_uid':None,'execution_euid':None,'execution_gid':None,'execution_egid':None,
 'execution_supplementary_group_count':None,'supplementary_groups_cleared':None}
 receipt=dict(intent,state='completed',terminal=True,intent_parent_sync_complete=True,dispatch_count=1,exit_code=0,term_signal=None,
 effect_started=True,process_group_established=True,waitpid_joined=True,process_group_absent=True,waitpid_identity_lost=False,
 execution_credentials_verified=True,execution_uid=2000,execution_euid=2000,execution_gid=2000,execution_egid=2000,
 supplementary_groups_cleared=True,execution_supplementary_group_count=0,worker_domain_verified=True,execution_context=m.WORKER,
 client_disconnected=False,error='',stdout_bytes=len(stdout),stderr_bytes=0,stdout_sha256=m.sha(stdout),stderr_sha256=m.sha(stderr),
 pid=4242,pgid=4242,elapsed_ms=5,completed_unix_ms=1793736000005)
 actiondir=executor/'actions'/action
 pj(actiondir/'intent.json',intent,newline=False);pj(actiondir/'receipt.json',receipt,newline=False)
 put(actiondir/'stdout.bin',stdout);put(actiondir/'stderr.bin',stderr)
 inspected={'version':1,'protocol':m.EXECUTOR_PROTOCOL,'duplicate':False,'receipt':receipt}
 pj(run/'original-executor-inspection.json',inspected)
 native_info={'stdout_sha256':m.sha(stdout),'stdout_bytes':len(stdout),'stderr_sha256':m.sha(b''),'stderr_bytes':0,'native_exit_code':0}
 pj(run/'component-outcome.json',{'state':'component_postconditions_pass','scope':m.SCOPE,'identity':scope,'action_id':action,'native_tool':native_info,'original_receipt_canonical_json_sha256':m.sha(m.encoded(receipt,newline=True)),'model_requests':0,'ui_business_actions':0,'native_turn_end_verified':False,'business_qualified':False})
 pj(run/'provider-terminal-intent.json',{'kind':'turn.complete','fields':{'summary':m.SUMMARY},'native_terminal_independently_verified':False})
 clientdir=component/'client-receipts'
 claim={'version':1,'action_id':action,'command_sha256':m.sha(command.encode()),'timeout_ms':3000,'state':'intent','created_unix_ms':1793735999999,'client_revision':6,'endpoint':m.ENDPOINT,'client_source_sha256':m.CLIENT_SHA}
 pj(clientdir/(action+'.claim.json'),claim,newline=False)
 payload={'version':1,'op':'execute','action_id':action,'command_sha256':m.sha(command.encode()),'command':command,'timeout_ms':3000}
 request_body=m.encoded(payload,sort=False);wire=struct.pack('>I',len(request_body))+request_body
 response=dict(inspected,stdout_b64=base64.b64encode(stdout).decode(),stderr_b64='')
 response_raw=m.encoded(response)
 event_refs=[];previous=None;last_progress=None
 for i,phase in enumerate(m.PHASES):
  progress={} if i==0 else {'operation':'execute','phase':phase,'endpoint':m.ENDPOINT,'payload_sha256':m.sha(request_body),
  'request_frame_sha256':m.sha(wire),'request_frame_bytes':len(wire),'confirmed_send_bytes':0 if i<8 else len(wire),
  'confirmed_receive_bytes':0 if i<10 else 4 if i<12 else 4+len(response_raw),
  'response_body_bytes':None if i<10 else len(response_raw),'connected':i>=4,'peer_identity_verified':i>=6,
  'send_attempted':i>=7,'request_frame_complete':i>=8,'response_frame_complete':i>=12,'automatic_replay':False}
  if i>=6:progress.update(peer_pid=4239,peer_uid=0,peer_gid=0,peer_context=m.PARENT)
  if i>=12:progress['response_body_sha256']=m.sha(response_raw)
  if i==14:progress['request_may_have_reached_executor']=True
  if phase_fence_bad and i==7:progress['send_attempted']=False
  event={'schema':'hepta.client-transport-event.v150.r6','client_revision':6,'action_id':action,'command_sha256':m.sha(command.encode()),
  'client_pid':4241,'client_source_sha256':m.CLIENT_SHA,'endpoint':m.ENDPOINT,'automatic_replay':False,
  'sequence':i,'phase':phase,'created_unix_ms':1793736000000+i,'monotonic_ns':now+1000000*(i+1),
  'previous_event_sha256':previous,'transport':progress}
  raw=m.encoded(event,sort=False);name='%02d-%s.json'%(i,phase);put(clientdir/(action+'.transport-r6')/name,raw)
  previous=m.sha(raw);event_refs.append({'name':name,'sha256':previous,'bytes':len(raw)});last_progress=progress
 trace={'schema':'hepta.client-transport-trace.v150.r6','directory':m.STATE+'/client-receipts/'+action+'.transport-r6','events':event_refs,
 'last_event_sha256':previous,'transport':last_progress,'automatic_replay':False}
 pj(clientdir/(action+'.result.json'),dict(inspected,client_transport=trace),newline=False)
 native_hash='ef'*32
 kinds=['turn.accepted','tool.accepted','tool.started','tool.stdout','tool.result','model.message','turn.end']
 if duplicate_started:kinds.insert(3,'tool.started')
 frames=[];runtime_seq=0
 for i,kind in enumerate(kinds):
  payload={'turn_request_sha256':native_hash,'event_log_status':'durable','event_log_error':None}
  if kind=='turn.accepted':payload['status']='accepted'
  if kind.startswith('tool.'):
   payload['runtime_seq']=runtime_seq;runtime_seq+=1
   if kind=='tool.accepted':payload['status']='accepted'
   if kind=='tool.started':payload.update(status='started',pid=4241)
   if kind=='tool.stdout':payload.update(encoding='base64',data=base64.b64encode(stdout).decode(),byte_count=len(stdout))
   if kind=='tool.result':payload.update(status='terminal',terminal_kind='exited',exit_code=0,signal=None,error=None,output_truncated=False,stdout_bytes=len(stdout),stderr_bytes=0)
  if kind=='model.message':payload['text']=m.SUMMARY
  if kind=='turn.end':payload.update(status='provider_failed' if native_failed else 'completed',error='synthetic_failure' if native_failed else None,summary=None if native_failed else m.SUMMARY,runtime_ready=True)
  frame={**scope,'kind':kind,'event_id':'fixture-event-'+str(i),'host_seq':i,'payload':payload}
  if kind.startswith('tool.'):frame.update(call_id=cid,tool='shell.exec')
  frames.append(frame)
 records=[];previous_hash='00'*32
 for i,frame in enumerate(frames):
  row={'schema':'trillionnium.owner-open.event-record.v1','store_seq':100+i,'turn_seq':i,'scope':scope,'event_id':frame['event_id'],
  'kind':frame['kind'],'payload':{'request_sha256':native_hash,'frame':frame},'payload_sha256':'','previous_record_sha256':previous_hash,'record_sha256':''}
  row['payload_sha256']=m.sha(m.encoded(audit.canonical_value(row['payload'])))
  row['record_sha256']=audit.record_hashes(row)[1]
  previous_hash=row['record_sha256'];records.append(row)
 pj(root/'native-records.json',records)
 args=SimpleNamespace(request_file=root/'request.txt',contract_file=root/'contract.json',contract_sha256=csha,scope_file=root/'scope.json',
 component_root=component,executor_root=executor,native_records=root/'native-records.json',
 provider_source=BASE/'component-probe-r6-r3/component_probe_provider.py',client_source=BASE/'client-r6/tool_client_r6.py')
 return args,actiondir
def verify(args):
 snap=m.Snapshot();report={'checks_passed':[],'component_pass':False}
 m.verify(args,snap,report);snap.unchanged();return report
def reject(name,args):
 try:verify(args)
 except (OSError,ValueError,KeyError,TypeError):check(name,True)
 else:raise AssertionError(name+' accepted')
with tempfile.TemporaryDirectory(prefix='synthetic-originals-',dir=str(ROOT)) as tmp:
 root=Path(tmp).resolve()
 args,actiondir=build(root/'valid')
 result=verify(args)
 check('complete_synthetic_original_bundle_all_layers_pass',result['component_pass'] is True and result['native_audit']['status']=='PASS' and result['client_transport']['phase_count']==15)
 check('native_digest_domain_separate_from_owner_utf8',result['native_turn_request_sha256']!=result['owner_request_utf8_sha256'])
 check('original_receipt_raw_and_canonical_hash_domains_separate',result['executor_effect_verified']['receipt_original_raw_sha256']!=result['executor_effect_verified']['receipt_canonical_with_newline_sha256'])
 raw=args.request_file.read_bytes();args.request_file.write_bytes(raw+b'\n');reject('owner_byte_change_rejected',args);args.request_file.write_bytes(raw)
 p=actiondir/'receipt.json';raw=p.read_bytes();v=m.strict(raw);v['pid']=v['pgid']=1;p.write_bytes(m.encoded(v));reject('effect_pid1_rejected',args);p.write_bytes(raw)
 p=actiondir/'stdout.bin';raw=p.read_bytes();p.write_bytes(b'wrong marker\n');reject('original_raw_stream_corruption_rejected',args);p.write_bytes(raw)
 p=actiondir/'receipt.pending';put(p,b'{}\n');reject('uncommitted_receipt_pending_rejected',args);p.unlink()
 bad,_=build(root/'bad-phase',phase_fence_bad=True);reject('hash_consistent_send_fence_false_rejected',bad)
 bad,_=build(root/'native-failed',native_failed=True);reject('effect_success_not_promoted_over_native_failed',bad)
 bad,_=build(root/'duplicate-started',duplicate_started=True);reject('hash_valid_duplicate_native_started_rejected',bad)
 tree=ast.parse((ROOT/'verify_component_originals.py').read_bytes(),feature_version=(3,12))
 imports=[a.name for n in ast.walk(tree) if isinstance(n,ast.Import) for a in n.names]
 check('no_socket_subprocess_http_or_phone_library_import',not set(imports)&{'socket','subprocess','requests','urllib','http','paramiko'})
 report={'schema':'hepta.native-component-original-verifier.host-checks.v1','status':'PASS','host_checks_passed':len(CHECKS),'checks':CHECKS,
 'synthetic_host_fixture_only':True,'phone_calls':0,'model_calls':0,'socket_connections':0,'native_actions':0,
 'physical_component_qualification':False,'fixed19_credit':False,
 'sources':{name:{'bytes':(ROOT/name).stat().st_size,'sha256':m.sha((ROOT/name).read_bytes())} for name in ('verify_component_originals.py','native_journal_audit.py','test_component_originals.py')}}
 raw=m.encoded(report,newline=True);put(ROOT/'HOST-CHECKS-01.json',raw);print(json.dumps(report,indent=2))
