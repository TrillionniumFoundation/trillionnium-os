"""Offline actual-certificate and generated actor checks. Never executes phone code."""
import ast,base64,contextlib,copy,hashlib,importlib.util,io,json,os,runpy,secrets,subprocess,sys,tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(BASE))
import sender_retirement_guard_r4 as guard
CHECKS=[]
def check(name,truth):
 if not truth:raise AssertionError(name)
 CHECKS.append(name)
def rejected(name,fn):
 try:fn()
 except (AssertionError,ValueError,FileNotFoundError,PermissionError,RuntimeError):check(name,True)
 else:raise AssertionError(name+' was admitted')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def private_put(path,raw):
 path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as out:out.write(raw);out.flush();os.fsync(out.fileno())
resolution_path=BASE/'ondevice-contract-review-v150/retirement-resolution-r4-01/pocket4/RESOLUTION.json'
bound=guard.binding(resolution_path)
check('actual_root_resolution_exact_pin',bound['resolution_sha256']=='7e06216823c49ec8b3949efa334e61b6731ca3f9bd4a039edbea771fb849a433')
proof=json.loads((BASE/'retirement-recovery-r2/FINAL-PROOF-01.json').read_bytes())
check('actual_final_proof_exact_pin',bound['proof_sha256']=='2bdd6c33c42359f1b27567b99627f7223d40a0c37f6af0158b8dc010e899943e')
previous={'identity':bound['scope'],'request_sha256':bound['native_request_sha256'],'terminal':{'status':'provider_failed'}}
check('only_original_failed_scope_has_retirement_admission',guard.prior_is_exact_retired(previous,bound))
check('unrelated_failed_scope_not_admitted',not guard.prior_is_exact_retired(dict(previous,identity=dict(bound['scope'],turn_id='unrelated-failed-turn')),bound))
rejected('original_scope_wrong_native_digest_rejected',lambda:guard.prior_is_exact_retired(dict(previous,request_sha256='0'*64),bound))
rejected('original_failure_cannot_be_relabelled_success',lambda:guard.prior_is_exact_retired(dict(previous,terminal={'status':'completed'}),bound))
for key,value in [('action_id','0'*32),('state','not_found'),('business_verified',True),('automatic_replay',True),('old_effect_replay_forbidden',False)]:
 obj=copy.deepcopy(bound['resolution']);obj[key]=value
 rejected('malformed_resolution_'+key,lambda obj=obj:guard.validate_resolution(obj,proof))
obj=copy.deepcopy(bound['resolution']);obj['future_executor_binding']['endpoint']='hepta_phone_local_v150'
rejected('old_executor_fallback_rejected',lambda:guard.validate_resolution(obj,proof))
with tempfile.TemporaryDirectory(prefix='hepta-sender-r4-host-',dir=str(BASE/'sender-r4-validation')) as temp:
 root=Path(temp).resolve()
 changed=root/'changed-resolution.json';private_put(changed,resolution_path.read_bytes()+b' ')
 rejected('same_JSON_different_resolution_bytes_rejected',lambda:guard.binding(changed))
 phone_source=guard.phone_guard(bound)
 ast.parse(phone_source,feature_version=(3,12))
 check('full_embedded_native_auditor_compiles',True)
 before=json.loads((BASE/'retirement-recovery-r2/original/before.json').read_bytes())
 records=json.loads((BASE/'retirement-recovery-r2/original/selected-native-records.json').read_bytes())
 state=root/'state';ledger=state/'provider-state/evidence/action-ledger'
 ledger.mkdir(mode=0o700,parents=True)
 private_put(ledger/'ledger.lock',b'')
 private_put(ledger/(guard.ACTION+'.intent.json'),base64.b64decode(before['original_provider_ledger_intent']['raw_b64']))
 private_put(ledger/(guard.ACTION+'.retirement-proof.json'),(BASE/'retirement-recovery-r2/FINAL-PROOF-01.json').read_bytes())
 private_put(ledger/(guard.ACTION+'.resolution.json'),resolution_path.read_bytes())
 for suffix,key in [('claim','original_client_claim'),('result','original_client_result')]:
  private_put(state/'client-receipts'/(guard.ACTION+'.'+suffix+'.json'),base64.b64decode(before[key]['raw_b64']))
 journal=root/'journal';journal.mkdir()
 journal_path=journal/'original.jsonl'
 private_put(journal_path,b''.join((json.dumps(row,separators=(',',':'))+'\n').encode() for row in records))
 boot=root/'boot-id';private_put(boot,(bound['boot_id']+'\n').encode())
 fixture=phone_source.replace("BASE=Path('/var/lib/trillionnium/owner-open/phone-local-v150')",'BASE=Path('+repr(str(state))+')').replace("J=Path('/var/lib/trillionnium/owner-open/turn-events.jsonl.segments')",'J=Path('+repr(str(journal))+')').replace("Path('/proc/sys/kernel/random/boot_id')",'Path('+repr(str(boot))+')')
 def run_guard():
  output=io.StringIO()
  with contextlib.redirect_stdout(output):exec(compile(fixture,'HOST_ONLY_ORIGINAL_COPY_FIXTURE','exec'),{})
  return json.loads(output.getvalue())
 result=run_guard()
 check('read_only_guard_validates_actual_certificate_copies',result['global_action_gate_clear'] is True and result['native_record_hashes_verified']==7 and result['original_native_status']=='provider_failed')
 check('guard_does_not_reclassify_original_success',result['old_request_replay_authorized'] is False and result['phone_writes']==0 and result['effects_dispatched']==0)
 original_resolution=(ledger/(guard.ACTION+'.resolution.json')).read_bytes()
 (ledger/(guard.ACTION+'.resolution.json')).write_bytes(original_resolution+b' ')
 rejected('live_resolution_tamper_blocks_send_gate',run_guard)
 (ledger/(guard.ACTION+'.resolution.json')).write_bytes(original_resolution)
 extra=json.loads((ledger/(guard.ACTION+'.intent.json')).read_bytes());extra['action_id']='f'*32
 extra_path=ledger/('f'*32+'.intent.json');private_put(extra_path,(json.dumps(extra)+'\n').encode())
 rejected('any_new_unknown_effect_blocks_send_gate',run_guard);extra_path.unlink()
 original_native=journal_path.read_bytes()
 broken=copy.deepcopy(records);broken[1]['record_sha256']='0'*64
 journal_path.write_bytes(b''.join((json.dumps(row)+'\n').encode() for row in broken))
 rejected('original_native_hash_corruption_blocks_send_gate',run_guard);journal_path.write_bytes(original_native)
 # Default build executes only host parsing and actor compilation. Even a bug
 # falling through to the SSH branch is trapped before any external call.
 label='host-sender-r4-'+secrets.token_hex(6)
 request=root/'request.txt';private_put(request,('HOST_ONLY_NEW_REQUEST_'+secrets.token_hex(16)).encode())
 draft='SYNTHETIC_PRIVATE_DRAFT_'+secrets.token_hex(6)+'\n原稿 🧪'
 draft_file=root/'preserved.json';private_put(draft_file,json.dumps({'exact_utf8_b64':base64.b64encode(draft.encode()).decode(),'utf8_sha256':sha(draft.encode())}).encode())
 previous_file=root/'previous.json';private_put(previous_file,json.dumps(previous).encode())
 argv=[str(BASE/'send_new_native_task_r4.py'),label,str(request),str(previous_file),'--preserved-draft',str(draft_file),'--retirement-resolution',str(resolution_path)]
 external=[]
 def no_external(*args,**kwargs):
  external.append(True);raise AssertionError('HOST FIXTURE FORBIDS ALL EXTERNAL EXECUTION')
 output=io.StringIO()
 with patch.object(sys,'argv',argv),patch.object(subprocess,'run',no_external),contextlib.redirect_stdout(output):
  try:runpy.run_path(str(BASE/'send_new_native_task_r4.py'),run_name='__main__')
  except SystemExit as exit:assert exit.code==0
 built=json.loads(output.getvalue())
 check('default_is_build_only_and_zero_external_calls',built['state']=='BUILT_ONLY_NO_PHONE' and built['send_attempts']==0 and not external)
 actor_path=Path(built['actor_path']);actor=actor_path.read_text();tree=ast.parse(actor,feature_version=(3,12))
 check('generated_actor_private_mode',actor_path.stat().st_mode&0o777==0o600)
 check('generated_actor_has_exactly_one_Send_call',sum(isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='tap' and len(node.args)==1 and isinstance(node.args[0],ast.Name) and node.args[0].id=='send' for node in ast.walk(tree))==1)
 check('pre_Send_has_absolute_150s_deadline','pre_send_deadline_ns=time.monotonic_ns()+150_000_000_000' in actor and "assert time.monotonic_ns()<=pre_send_deadline_ns" in actor)
 check('retirement_gate_is_double_checked',"read_retirement_gate('PRE-MUTATION-RETIREMENT')" in actor and "read_retirement_gate('FINAL-PRE-SEND-RETIREMENT')" in actor)
 defs={node.name:node for node in tree.body if isinstance(node,ast.FunctionDef)}
 restore_ast=ast.Module(body=[defs['restore_preserved_draft']],type_ignores=[])
 class Node:
  def __init__(self,text):self.attrib={'text':text,'resource-id':'org.trillionnium.owneropen:id/ui_prompt'}
 def restoration_fixture(actual,visible=None,timing=True,changed_scope=False,pending=False):
  actuals=[actual];calls=[];saved={};visible=actual if visible is None else visible
  identity=dict(bound['scope'],turn_id='synthetic-completed-turn')
  timing_value={'state':'ORIGINAL_NATIVE_TERMINAL_OBSERVED','scope':identity,
                'original_observation':{'native_request_sha256':'d'*64}} if timing else None
  def selection(*_args):
   if changed_scope:raise RuntimeError('synthetic selected scope changed')
   return {}
  def gate(_tag):
   if pending:raise RuntimeError('synthetic new unresolved action')
   return {'global_action_gate_clear':True}
  def shell(command):
   calls.append(command)
   if command.startswith('am start'):return {'rc':0,'stdout':'fixture'}
   import shlex
   words=shlex.split(command);want=words[words.index('--expected-text-b64')+1];new=words[words.index('--text-b64')+1]
   want='' if want=='-' else base64.b64decode(want).decode();new='' if new=='-' else base64.b64decode(new).decode()
   if actuals[0]!=want:raise RuntimeError('synthetic effectiveText CAS rejected')
   actuals[0]=new
   return {'rc':0,'stdout':json.dumps({'status':'set_verified','own_automation_disconnected':True,
                       'readback_text_b64':base64.b64encode(actuals[0].encode()).decode()})}
  import shlex
  env={'preserved_draft':draft,'expected':'SYNTHETIC_NEW_REQUEST','previous_identity':bound['scope'],'previous_digest':bound['native_request_sha256'],
       'read_retirement_gate':gate,'read_selected_identity':selection,
       'save':lambda name,value:saved.setdefault(name,value),'f':SimpleNamespace(shell=lambda *a,**kw:{'rc':0,'stdout':'synthetic original foreground'}),
       'c':{},'t':'SYNTHETIC_ROUTE','sh':shell,'dump':lambda _tag:[Node(visible)],'node':lambda nodes,_rid:nodes[0],
       'tap':lambda _node:calls.append('focus-only'),'shlex':shlex,'base64':base64,'json':json,
       'label':'synthetic-restore','hashlib':hashlib}
  exec(compile(restore_ast,'HOST_ONLY_RESTORE_FIXTURE','exec'),env)
  try:outcome=env['restore_preserved_draft'](timing_value,True,True)
  except RuntimeError as error:return {'error':str(error),'actual':actuals[0],'calls':calls,'saved':saved}
  return {'outcome':outcome,'actual':actuals[0],'calls':calls,'saved':saved}
 empty=restoration_fixture('',visible='发消息或交代任务…')
 check('empty_hint_effectiveText_CAS_restores_exact_unicode',empty['actual']==draft and empty['outcome']['state']=='ORIGINAL_DRAFT_RESTORED')
 changed=restoration_fixture('a new user draft')
 check('changed_user_draft_not_overwritten',changed['actual']=='a new user draft' and 'error' in changed and not any('set-text' in c for c in changed['calls']))
 literal_hint=restoration_fixture('发消息或交代任务…')
 check('literal_user_hint_not_mistaken_for_empty_CAS',literal_hint['actual']=='发消息或交代任务…' and 'error' in literal_hint)
 unknown=restoration_fixture('',timing=False)
 check('unknown_native_task_has_no_restore_actions',unknown['outcome']['state']=='RESTORE_DEFERRED_ORIGINAL_TASK_NOT_TERMINAL' and unknown['calls']==[])
 moved=restoration_fixture('',changed_scope=True)
 check('changed_scope_prevents_restore_actions',moved['calls']==[] and 'error' in moved)
 pending=restoration_fixture('',pending=True)
 check('new_unknown_effect_prevents_restore_actions',pending['calls']==[] and 'error' in pending)
 check('restore_never_submits_original_draft',not any('ui_send' in c for c in empty['calls']) and empty['outcome']['original_draft_submitted'] is False)
 check('restore_not_credited_as_model_business_result',empty['outcome']['model_business_credit'] is False)
 check('original_draft_hash_stays_private',empty['saved']['DRAFT-RESTORE-RESULT.json']['utf8_sha256']==sha(draft.encode()))
 check('frozen_r3_sender_unchanged',sha((BASE/'send_new_native_task_r3.py').read_bytes())=='d1d3339bbfeacfc7d429f58e733d0130a36b2f8593f0efd590e427e7e7a937e5')
 report={'schema':'hepta.sender-r4-host-validation.v150.1','checks_passed':len(CHECKS),'checks':CHECKS,
 'phone_calls':0,'model_calls':0,'external_process_requests':len(external),'physical_qualification':False,
 'actual_certificate_checked_readonly':True,'actual_originals_copied_only_into_private_host_fixture':True,
 'draft_fixture_synthetic_not_user_draft':True,'actor_preview':{'path':str(actor_path),'sha256':sha(actor.encode())},
 'sources':{p.name:{'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())} for p in [BASE/'send_new_native_task_r4.py',BASE/'sender_retirement_guard_r4.py']}}
 out=BASE/'sender-r4-validation/HOST-CHECKS-02.json'
 with out.open('x') as stream:json.dump(report,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
 print(json.dumps(report,indent=2))
