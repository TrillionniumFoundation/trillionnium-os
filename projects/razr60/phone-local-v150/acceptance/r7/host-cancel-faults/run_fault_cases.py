#!/usr/bin/env python3
"""Five original fixed-protocol host fault cases through frozen daily JSONL/HTTP.
No phone transport, model weights, Android shell, native Host or SELinux claim.
"""
import argparse,base64,hashlib,importlib,json,os,re,secrets,select,signal,socket,sys,time,traceback
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,'/harness')
import frozen_fixture_support as H
IDS=('NEG-04','NEG-05','NEG-07','NEG-08','NEG-09')
KEYS=('session_id','profile_id','task_id','turn_id','turn_stream_id')
HOST_MODEL_TIMEOUT=10
SUPPORT_SHA='2a02578bc0793cb8f883a964f04c80573315c8967e89c022c709678de4277e12'
def raw_write(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 return {'path':str(path),'bytes':len(raw),'sha256':H.sha(raw)}
def wait_until(fn,seconds,label):
 deadline=time.monotonic()+seconds
 while time.monotonic()<deadline:
  value=fn()
  if value:return value
  time.sleep(.01)
 raise TimeoutError(label)
def config_tree(root):
 d=H.mkdir(root/'config');state=H.mkdir(d/'state')
 cfg=H.read(H.SUITE/'production-config.json')
 key=d/'synthetic-only-api.key'
 fd=os.open(key,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f:f.write(secrets.token_hex(24)+'\n');f.flush();os.fsync(f.fileno())
 cfg.update(endpoint='http://127.0.0.1:18099/v1/chat/completions',api_key_file=str(key),model='synthetic-fixture-no-real-inference')
 H.write(d/'config.json',cfg)
 identity={k:'seed-'+secrets.token_hex(16) for k in KEYS[:-1]}
 seed=[{'identity':identity,'origin_receipt_sha256':H.sha(H.canonical({'synthetic':True,'identity':identity}))}]
 record=H.write(d/'retained.json',seed)
 H.write(d/'FIXTURE-DECLARATION.json',{'layer':'host_isolated','source_schema_requires_phone_literal':True,
  'actual_inference_location':'isolated HTTP fixture; no model inference','actual_executor':'disposable host counter subprocess',
  'changed_fixture_config_fields':['endpoint','api_key_file','model'],'model_worker_deadline_seconds':HOST_MODEL_TIMEOUT,
  'original_max_rounds':8,'original_max_tool_calls':7,'source_max_turn_seconds':300,
  'original_production_configuration_unchanged':True,'phone_calls':0,'real_model_requests':0,
  'model_token_usage':None,'model_cost':None,'absence_of_cost_is_not_zero_cost':True})
 return d,state,record
def daily_args(d,state,seed):
 return ['/usr/bin/python3','-I','-B',str(H.SOURCE/'daily_phone_local.py'),'--state',str(state),
  '--config',str(d/'config.json'),'--port','18101','--workers','1','--timeout',str(HOST_MODEL_TIMEOUT),
  '--retained-claims',str(d/'retained.json'),'--retained-claims-sha256',seed['sha256']]
class Wire:
 def __init__(self,root,label):
  self.label=label;self.socket=socket.create_connection(('127.0.0.1',18101),timeout=2)
  self.socket.setblocking(False);self.buffer=bytearray();self.frames=[];self.sent=[];self.closed=False
  self.tx=open(root/(label+'.tx.jsonl'),'xb');self.rx=open(root/(label+'.rx.jsonl'),'xb')
 def send(self,value):
  raw=H.canonical(value)+b'\n';assert len(raw)<=H.OPENAI.MAX_LINE
  self.socket.settimeout(2)
  try:self.socket.sendall(raw)
  finally:self.socket.setblocking(False)
  self.tx.write(raw);self.tx.flush();os.fsync(self.tx.fileno())
  self.sent.append({'kind':value['kind'],'seq':value['seq'],'raw_sha256':H.sha(raw),'monotonic':time.monotonic()})
 def receive(self,seconds):
  deadline=time.monotonic()+seconds
  while time.monotonic()<deadline:
   if b'\n' in self.buffer:
    p=self.buffer.index(10)+1;raw=bytes(self.buffer[:p]);del self.buffer[:p]
    assert len(raw)<=H.OPENAI.MAX_LINE
    value=H.OPENAI.decode(raw);self.rx.write(raw);self.rx.flush();os.fsync(self.rx.fileno());self.frames.append(value)
    return value
   if select.select([self.socket],[],[],min(.05,max(0,deadline-time.monotonic())))[0]:
    raw=self.socket.recv(65536)
    if not raw:
     if self.buffer:raise RuntimeError('provider EOF with partial original frame')
     return None
    self.buffer.extend(raw);assert len(self.buffer)<=H.OPENAI.MAX_LINE
  raise TimeoutError('owned original JSONL read deadline')
 def until(self,kind,seconds=5):
  deadline=time.monotonic()+seconds
  while time.monotonic()<deadline:
   value=self.receive(max(.01,deadline-time.monotonic()))
   if value is None:raise RuntimeError('original EOF before '+kind)
   if value.get('kind')==kind:return value
   if value.get('kind') in ('turn.complete','turn.cancelled','turn.fail'):return value
  raise TimeoutError(kind)
 def close(self):
  if self.closed:return
  try:self.socket.shutdown(socket.SHUT_RDWR)
  except OSError:pass
  self.socket.close();self.tx.close();self.rx.close();self.closed=True
def claim_path(state,identity):
 return state/'evidence/claims'/H.sha(json.dumps([identity[k] for k in KEYS[:-1]],separators=(',',':')).encode())
def accepted_run(e,state,identity):
 path=claim_path(state,identity);claim=H.wait_file(path,time.monotonic()+4)
 run=Path(claim['run_dir']);e.check('durable original scope and consumed claim',claim['identity']==identity and claim['state']=='accepted_no_redispatch')
 e.check('actual normal business-channel marker',H.wait_file(run/'health-contract.json',time.monotonic()+3)=={'status':'no_health_contract'})
 return run,path,claim
def current_claim_hashes(state):
 return {p.name:H.sha(p.read_bytes()) for p in (state/'evidence/claims').iterdir()}
def worker_cleanup(e,run):
 spawned=H.wait_file(run/'local-01.spawned.json',time.monotonic()+4)
 joined=H.wait_file(run/'local-01.joined.json',time.monotonic()+5)
 slot=H.wait_file(run/'local-01.slot-after.json',time.monotonic()+4)
 result=H.wait_file(run/'local-01.worker-result.json',time.monotonic()+4)
 e.check('actual HTTP worker admission and direct wait',spawned['actual_spawn'] is True and spawned['pid']==spawned['process_group']==joined['pid'] and joined['child_wait_returned'] is True and joined['dedicated_process_group_absent'] is True)
 observed=H.census(spawned['process_group']);H.write(e.path/'HTTP-WORKER-CENSUS.json',observed)
 e.check('original HTTP worker group independently absent',observed['members']==[] and observed['kernel']=='ESRCH')
 e.check('original slot GET really observed idle',slot.get('observed') is True and slot.get('idle') is True)
 e.check('original HTTP worker terminal has no retry',type(result.get('returncode')) is int and result['automatic_retry'] is False)
 return {'spawned':spawned,'joined':joined,'slot_after':slot,'worker_result':result,'group_after':observed}
def duplicate_attempt(e,state,identity,owner,claim_sha):
 replacement=dict(identity,turn_stream_id='replacement-host-'+secrets.token_hex(16))
 wire=Wire(e.path,'explicit-duplicate-stream')
 frame={'protocol':H.OPENAI.PROTOCOL,'seq':0,'kind':'turn.start','turn':dict(replacement,user_input=owner)}
 H.write(e.path/'EXPLICIT-NEGATIVE-READMISSION-INTENT.json',{'synthetic_host_negative_test_only':True,
  'reason':'Required fixed-protocol assertion: same semantic identity with replacement stream must be rejected before any new request/effect',
  'original_semantic_scope':{k:identity[k] for k in KEYS[:-1]},'replacement':replacement,
  'automatic_retry':False,'phone_task_replay':False})
 try:
  wire.send(frame);reply=wire.until('turn.fail',4)
  e.check('replacement stream rejected by original consumed-identity gate',reply['kind']=='turn.fail' and 'turn identity already accepted' in reply.get('error',''))
  e.check('replacement stream emitted zero tools',not any(x['kind']=='tool.call' for x in wire.frames))
 finally:wire.close()
 e.check('original consumed claim bytes retained after negative readmission',H.sha(claim_path(state,identity).read_bytes())==claim_sha)
 return {'replacement_stream':replacement['turn_stream_id'],'frames':wire.frames,'sent':wire.sent,'automatic_retry':False}
def begin_counter(e,call,delay_ms):
 e.check('one real frozen typed shell dispatch',call['tool']=='shell.exec' and call['argv'][:3]==['/usr/bin/python3',str(H.CLIENT),'execute'])
 args=call['argv'];e.check('exact r6 guarded client argv shape',len(args)==9 and args[3]=='--action-id' and args[5]=='--command-b64' and args[7]=='--timeout-ms' and args[8]=='60000')
 action=args[4];command=base64.b64decode(args[6],validate=True)
 e.check('original mapped command recorded but never executed',re.fullmatch('[0-9a-f]{32}',action) is not None and bool(command))
 intent={'schema':'hepta.synthetic-host-counter-intent.v1','action_id':action,'command_sha256':H.sha(command),
  'original_call':call,'original_android_command_b64':args[6],'phone_command_executed':False,'fresh_disposable_host_counter':True}
 H.write(e.path/'COUNTER-INTENT.json',intent)
 child=H.Owned('counter-effect',['/usr/bin/python3','-I','-B','/harness/counter_effect.py','--intent',str(e.path/'COUNTER-INTENT.json'),'--delay-ms',str(delay_ms)],e.path)
 counter=H.wait_file(e.path/'COUNTER.json',time.monotonic()+3,child)
 e.check('one counter really committed under original dispatch binding',counter['action_id']==action and counter['command_sha256']==intent['command_sha256'] and counter['value']==1)
 return child,intent,counter
def finish_counter(e,child,intent):
 receipt=H.wait_file(e.path/'COUNTER-RECEIPT.json',time.monotonic()+4,child)
 joined=child.join(timeout=4)
 H.no_members(e,'disposable counter child',joined)
 e.check('original counter completed once with actual output and original receipt',joined['returncode']==0 and receipt['value']==1 and receipt['action_id']==intent['action_id'] and receipt['command_sha256']==intent['command_sha256'] and receipt['intent_sha256']==H.sha((e.path/'COUNTER-INTENT.json').read_bytes()) and receipt['counter_sha256']==H.sha((e.path/'COUNTER.json').read_bytes()) and (e.path/'counter-effect.stdout').read_bytes()==b'HOST-ONLY-COUNTER=1\n' and (e.path/'counter-effect.stderr').stat().st_size==0)
 return receipt,joined
def run_case(e,cid):
 mode='hold' if cid in ('NEG-04','NEG-08') else 'open'
 server=H.Owned('fixture-server',['/usr/bin/python3','-I','-B','/harness/fixture_server.py','--out',str(e.path/'fixture'),'--mode',mode],e.path)
 H.wait_file(e.path/'fixture/READY.json',time.monotonic()+3,server)
 d,state,seed=config_tree(e.path);daemon=H.Owned('daily-provider',daily_args(d,state,seed),e.path)
 ready=H.wait_file(state/'ready.json',time.monotonic()+4,daemon)
 e.check('unchanged daily entry really started with frozen source pin',ready['source_sha256']=='92122fcc8bf01511971075fce2ad94b628dadf2c0c342f0fb940e8b00c636ec3' and ready['accepting'] is True and ready['workers']==1)
 identity={k:'host-'+secrets.token_hex(16) for k in KEYS};identity['profile_id']='host-synthetic'
 owner='Fresh isolated '+cid+' fixture '+secrets.token_hex(16)+'; no physical phone or real model.'
 frame={'protocol':H.OPENAI.PROTOCOL,'kind':'turn.start','seq':0,'turn':dict(identity,user_input=owner)}
 H.write(e.path/'ORIGINAL-TURN.json',{'synthetic_host_fixture':True,'frame':frame})
 wire=Wire(e.path,'original-transport');counter_child=None;counter_data=None;late=None;intervention=None
 try:
  wire.send(frame);run,claim,cv=accepted_run(e,state,identity)
  original_claim_sha=H.sha(claim.read_bytes())
  post=H.wait_file(e.path/'fixture/POST-001.json',time.monotonic()+4,server)
  spawn=H.wait_file(run/'local-01.spawned.json',time.monotonic()+2,daemon)
  if mode=='hold':
   e.check('actual worker live at original before-dispatch intervention',H.proc(spawn['pid']) is not None and not (run/'local-01.joined.json').exists())
   e.check('no original tool mapping before intervention',not list(run.glob('dispatch-*.json')) and not list(run.glob('semantic-*.json')))
   intervention={'phase':'admitted_HTTP_worker_live_before_first_tool','kind':'transport_close' if cid=='NEG-04' else 'turn.cancel','monotonic':time.monotonic(),'worker_pid':spawn['pid'],'read_claim_sha256':original_claim_sha}
   H.write(e.path/'INTERVENTION.json',intervention)
   if cid=='NEG-04':wire.close()
   else:
    wire.send({'protocol':H.OPENAI.PROTOCOL,'kind':'turn.cancel','seq':1})
    reply=wire.until('turn.cancelled',5)
    e.check('original before-effect cancel wire observed',reply['kind']=='turn.cancelled')
  else:
   call_frame=wire.until('tool.call',5);e.check('deterministic fixture reaches actual frozen dispatch',call_frame['kind']=='tool.call')
   call=call_frame['call'];worker_cleanup(e,run)
   model_action=H.read(run/'local-01.model-action.json');mapping=H.read(run/'local-01.mapping.json');decision=H.read(run/'local-01.decision.json')
   fixture_content=H.read(e.path/'fixture/RESPONSE.json')['body']['choices'][0]['message']['content']
   e.check('actual r7 named model action and original projection bind the one native call',
    model_action==json.loads(fixture_content) and model_action['name']=='mobile_use' and model_action['arguments']['action']=='open'
    and decision['tool']=='phone.open_app' and decision['argv']==[model_action['arguments']['text']]
    and decision['call_id']==call['call_id']==mapping['allowed_call_id'] and mapping['request_id']==post['request_id']
    and mapping['original_model_content_sha256']==H.sha(fixture_content.encode())
    and mapping['original_model_action_canonical_sha256']==H.sha(H.canonical(model_action))
    and mapping['mapped_legacy_decision_canonical_sha256']==H.sha(H.canonical(decision))
    and mapping['native_dispatch_in_mapping'] is False and mapping['additional_model_requests']==0)
   delay=1200 if cid=='NEG-07' else 500 if cid=='NEG-05' else 0
   counter_child,intent,counter=begin_counter(e,call,delay)
   if cid=='NEG-05':
    e.check('effect visible before original result and before transport close',not (e.path/'COUNTER-RECEIPT.json').exists() and counter_child.p.poll() is None)
    intervention={'phase':'one_local_counter_committed_original_result_not_delivered','kind':'transport_close','monotonic':time.monotonic(),'counter_sha256':H.sha((e.path/'COUNTER.json').read_bytes())}
    H.write(e.path/'INTERVENTION.json',intervention);wire.close()
    receipt,join=finish_counter(e,counter_child,intent);counter_data={'receipt':receipt,'actual_join':join}
   elif cid=='NEG-09':
    receipt,join=finish_counter(e,counter_child,intent);counter_data={'receipt':receipt,'actual_join':join}
    intervention={'phase':'one_local_effect_independently_confirmed_and_joined_before_next_action','kind':'turn.cancel','monotonic':time.monotonic(),'receipt_sha256':H.sha((e.path/'COUNTER-RECEIPT.json').read_bytes()),'result_delivered_to_provider':False}
    H.write(e.path/'INTERVENTION.json',intervention)
    wire.send({'protocol':H.OPENAI.PROTOCOL,'kind':'turn.cancel','seq':1})
    reply=wire.until('turn.cancelled',5);e.check('original after-effect cancel wire observed',reply['kind']=='turn.cancelled')
   else:
    deadline=time.monotonic()+.20
    while time.monotonic()<deadline:time.sleep(min(.01,deadline-time.monotonic()))
    e.check('real executor-result deadline expires while original counter still in flight',counter_child.p.poll() is None and not (e.path/'COUNTER-RECEIPT.json').exists())
    intervention={'phase':'counter_committed_result_visibility_deadline_expired','kind':'unknown_tool_result','monotonic':time.monotonic(),'deadline_seconds':.20,'actual_child_live':True}
    H.write(e.path/'INTERVENTION.json',intervention)
    wire.send({'protocol':H.OPENAI.PROTOCOL,'kind':'tool.result','seq':1,'call_id':call['call_id'],'status':'unknown','error':'synthetic_host_executor_result_deadline','fixture_only':True})
    reply=wire.until('turn.fail',5)
    e.check('unknown original result is rejected without semantic retry',reply['kind']=='turn.fail' and 'not confirmed completed' in reply.get('error',''))
    terminal_before=H.wait_file(run/'terminal.json',time.monotonic()+2)
    fence={p.name:H.sha(p.read_bytes()) for p in [run/'terminal.json',run/'provider-in.jsonl',run/'provider-out.jsonl',claim]}
    receipt,join=finish_counter(e,counter_child,intent);counter_data={'receipt':receipt,'actual_join':join}
    late={'original_call_id':call['call_id'],'original_counter_receipt_sha256':H.sha((e.path/'COUNTER-RECEIPT.json').read_bytes()),
     'observed_after_original_provider_terminal':True,'actual_child_joined':True,'automatic_redispatch':False}
    try:
     wire.send({'protocol':H.OPENAI.PROTOCOL,'kind':'tool.result','seq':2,'call_id':call['call_id'],'status':'completed','fixture_only':True,'synthetic_counter_receipt':receipt})
     late['local_sendall_returned']=True
     try:late['subsequent_original_socket_read']=wire.receive(.3)
     except (OSError,TimeoutError) as ex:late['read_error']={'type':type(ex).__name__,'errno':getattr(ex,'errno',None)}
    except OSError as ex:late['local_sendall_returned']=False;late['send_error']={'type':type(ex).__name__,'errno':ex.errno}
    late['kernel_send_return_does_not_prove_provider_consumption']=True
    H.write(e.path/'LATE-ORIGINAL-RESULT-OBSERVATION.json',late)
    time.sleep(.05)
    e.check('late original result cannot rewrite accepted terminal or original provider streams',fence=={p.name:H.sha(p.read_bytes()) for p in [run/'terminal.json',run/'provider-in.jsonl',run/'provider-out.jsonl',claim]})
  terminal=H.wait_file(run/'terminal.json',time.monotonic()+5,daemon)
  business=H.wait_file(run/'business-outcome.json',time.monotonic()+3)
  if mode=='hold':cleanup=worker_cleanup(e,run)
  else:
   cleanup={'spawned':H.read(run/'local-01.spawned.json'),'joined':H.read(run/'local-01.joined.json'),'slot_after':H.read(run/'local-01.slot-after.json')}
  expected_terminal='turn.cancelled' if cid in ('NEG-08','NEG-09') else 'turn.fail'
  e.check('original persisted terminal retained without business success',terminal['kind']==expected_terminal and business.get('business_verified') is False)
  if cid in ('NEG-04','NEG-05'):e.check('closed-transport outcome remains explicit unknown', 'accepted outcome unknown' in terminal.get('error','') and not any(f['kind'] in ('turn.complete','turn.cancelled','turn.fail') for f in wire.frames))
  dispatches=list(run.glob('dispatch-*.json'));semantics=list(run.glob('semantic-*.json'));intents=list((state/'evidence/action-ledger').glob('*.intent.json'))
  count=0 if mode=='hold' else 1
  e.check('exactly expected dispatches and semantic intents; no navigation follow-up',len(dispatches)==len(semantics)==len(intents)==count)
  e.check('one actual HTTP request only',len(list(e.path.glob('fixture/POST-[0-9][0-9][0-9].json')))==1 and len(list(run.glob('local-*.spawned.json')))==1)
  if count:
   item=H.read(intents[0]);e.check('unconfirmed original action remains unresolved; no fabricated phone receipt',item['action_id']==intent['action_id'] and item['command_sha256']==intent['command_sha256'] and not list((state/'evidence/action-ledger').glob('*.resolution.json')) and not list(state.rglob('*.result.json')))
   e.check('disposable counter stays exactly one',H.read(e.path/'COUNTER.json')['value']==1 and len(list(e.path.glob('COUNTER-CLAIM.json')))==1)
  else:e.check('zero effect counter and zero phone actions',not (e.path/'COUNTER.json').exists())
  e.check('original owner claim is retained unchanged',H.sha(claim.read_bytes())==original_claim_sha and len(list((state/'evidence/claims').iterdir()))==2)
  wire.close()
  readmission=duplicate_attempt(e,state,identity,owner,original_claim_sha)
  terminal_snapshot=H.sha((run/'terminal.json').read_bytes());claims_before=current_claim_hashes(state)
  daemon_join=daemon.join(timeout=4,stop=True);H.no_members(e,'frozen daily provider',daemon_join)
  server_join=server.join(timeout=3,stop=True);H.no_members(e,'deterministic HTTP fixture',server_join)
  exited=H.read(e.path/'fixture/EXIT.json')
  e.check('HTTP fixture single original POST and true idle at exit',exited['post_count']==1 and exited['active'] is False)
  e.check('all accepted claim bytes and original terminal survive service cleanup',claims_before==current_claim_hashes(state) and H.sha((run/'terminal.json').read_bytes())==terminal_snapshot)
  e.check('no second dispatched effect across replacement stream',len(list(state.rglob('dispatch-*.json')))==count and len(list(state.rglob('local-*.spawned.json')))==1)
  H.write(e.path/'ORIGINAL-TERMINAL-EVIDENCE.json',{'scope':identity,'run':str(run),'original_claim_sha256':original_claim_sha,
   'original_owner_utf8_sha256':H.sha(owner.encode()),'terminal':terminal,'business':business,'worker_cleanup':cleanup,
   'intervention':intervention,'counter':counter_data,'late_result':late,'explicit_negative_readmission':readmission,
   'original_wire_frames':wire.frames,'original_wire_sends':wire.sent,'original_wire_terminal_observed':cid not in ('NEG-04','NEG-05'),
   'fixture_http_request':post,'fixture_exit':exited,'phone_calls':0,'real_model_requests':0,
   'native_host_scope_or_receipts':None,'phone_executor_receipt':None,'counter_is_not_phone_effect_proof':True})
 finally:
  wire.close()
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--execute-once',action='store_true');parser.add_argument('--server-sha256',required=True);parser.add_argument('--counter-sha256',required=True);args=parser.parse_args()
 if not args.execute_once:print('review-only');return 0
 os.umask(0o077)
 H.SERVER_SHA=args.server_sha256
 H.pinned(Path('/harness/frozen_fixture_support.py'),SUPPORT_SHA);H.pinned(Path('/harness/counter_effect.py'),args.counter_sha256)
 outer=H.read(H.WORK/'OUTER-ENV.json')
 current={'uid':os.getuid(),'gid':os.getgid(),'netns':os.readlink('/proc/self/ns/net'),'mntns':os.readlink('/proc/self/ns/mnt'),'pidns':os.readlink('/proc/self/ns/pid')}
 assert current['uid']==0 and current['netns']!=outer['host_netns'] and current['mntns']!=outer['host_mntns'] and current['pidns']!=outer['host_pidns']
 assert os.statvfs(H.SUITE).f_flag&1 and os.statvfs(H.CLIENT).f_flag&1
 protocol=H.verify();sys.path.insert(0,str(H.SOURCE));H.DAILY=importlib.import_module('daily_phone_local');H.OPENAI=importlib.import_module('provider_openai_compatible')
 H.write(H.WORK/'SUITE-INTENT.json',{'schema':'hepta.host-fault-suite-intent.v150.r7.1','cases':IDS,'current_namespace':current,
  'source_seal_sha256':H.SEAL_SHA,'combination_manifest_sha256':H.COMBO_SHA,'phone_calls':0,'real_model_requests':0,'native_host_calls':0,
  'counter_fixture_scope':'Real disposable host subprocess after actual frozen typed dispatch; Android command never executed',
  'physical_followup':'Required separately for all five cases; no host result closes physical lifecycle gate'})
 H.write(H.WORK/'SOURCE-ENTRY-PREFLIGHT.json',{'daily_path':str(H.DAILY.__file__),'daily_sha256':H.sha(Path(H.DAILY.__file__).read_bytes()),
  'all_13_source_pins_verified':True,'case_objects':[x for x in protocol['cases'] if x['id'] in IDS],'limits':protocol['limits'],'geometry':protocol['qualified_geometry']})
 deadline_expired=False
 def bound(n,f):
  nonlocal deadline_expired
  deadline_expired=True
  raise TimeoutError('absolute host fault suite 90s deadline')
 signal.signal(signal.SIGALRM,bound);signal.alarm(90)
 started=time.monotonic();rows=[]
 try:
  for cid in IDS:
   e=H.Evidence(cid);before=H.resources();first=len(H.OWNED);error=None
   try:run_case(e,cid)
   except BaseException as ex:error={'type':type(ex).__name__,'error':str(ex),'traceback':traceback.format_exc()}
   finally:
    for child in reversed(H.OWNED[first:]):
     if not child.joined:
      try:child.join(timeout=3,stop=True)
      except BaseException as ex:error=error or {'type':type(ex).__name__,'error':'owned cleanup unconfirmed: '+str(ex)}
   after=H.resources()
   for label,ok in [('actual runner FD baseline restored',before['fd_count']==after['fd_count']),('actual thread baseline restored',before['thread_count']==after['thread_count']),('all owned direct children waited and groups absent',all(x.joined and x.result['group_after']['members']==[] and x.result['group_after']['kernel']=='ESRCH' for x in H.OWNED[first:]))]:
    e.checks.append({'name':label,'passed':bool(ok)})
   passed=error is None and all(x['passed'] for x in e.checks)
   row={'schema':'hepta.host-fault-case.v150.r7.1','case_id':cid,'layer':'host_isolated','status':'PASS' if passed else 'FAIL',
    'source_seal_sha256':H.SEAL_SHA,'combination_manifest_sha256':H.COMBO_SHA,'combination_sha256':H.COMBO_CANONICAL,
    'checks':e.checks,'error':error,'resources':{'before':before,'after':after,'elapsed_seconds':after['monotonic']-before['monotonic']},
    'owned_processes':[x.result for x in H.OWNED[first:]],'phone_calls':0,'real_model_requests':0,'real_native_host_calls':0,
    'model_usage':None,'model_cost':None,'model_usage_reason':'Deterministic fixture executes no model; not evidence of zero model cost.',
    'physical_qualification':'NOT_ESTABLISHED_BY_THIS_HOST_SAMPLE','fixed19_whole_case_closed':False,
    'phone_draft_or_ui_touched':False,'restoration':'Private namespace only; exact source/input pins and FD/child ownership audited.'}
   rec=H.write(e.path/'RESULT.json',row);rows.append({'case_id':cid,'status':row['status'],'result':rec,'checks':len(e.checks),'elapsed_seconds':after['monotonic']-before['monotonic']})
   if deadline_expired:break
  H.verify();signal.alarm(0)
  result={'schema':'hepta.host-fault-suite.v150.r7.1','status':'PASS' if len(rows)==len(IDS) and all(x['status']=='PASS' for x in rows) else 'FAIL','cases':rows,
   'elapsed_seconds':time.monotonic()-started,'source_seal_sha256':H.SEAL_SHA,'combination_manifest_sha256':H.COMBO_SHA,'combination_sha256':H.COMBO_CANONICAL,
   'actual_namespace':current,'phone_calls':0,'real_model_requests':0,'native_host_calls':0,'frozen_sources_unchanged':True,'absolute_deadline_expired':deadline_expired,'unstarted_cases':[cid for cid in IDS if cid not in {x['case_id'] for x in rows}],
   'physical_qualification_not_inferred':True,'scope':'Original fixed NEG04/05/07/08/09 host_isolated requirements; actual provider/HTTP subprocess and local counter, no Android execution.'}
  rec=H.write(H.WORK/'RESULT.json',result);print(json.dumps({'result':rec,'status':result['status'],'cases':rows,'phone_calls':0,'real_model_requests':0}))
  return 0 if result['status']=='PASS' else 1
 finally:
  signal.alarm(0)
  for child in reversed(H.OWNED):
   if not child.joined:
    try:child.join(timeout=2,stop=True)
    except BaseException:pass
if __name__=='__main__':raise SystemExit(main())
