"""Host-only fixed component-r3 rendezvous tests; no phone, model or external process."""
import ast,base64,contextlib,copy,hashlib,importlib.util,io,json,os,runpy,secrets,sys,tempfile,time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(BASE))
import sender_component_ready_r5 as ready
import sender_retirement_guard_r4 as retired
CHECKS=[]
def check(name,ok):
 if not ok:raise AssertionError(name)
 CHECKS.append(name)
def rejected(name,fn):
 try:fn()
 except (AssertionError,ValueError,RuntimeError,FileNotFoundError,TimeoutError):check(name,True)
 else:raise AssertionError(name+' was accepted')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def put(path,raw):
 path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as out:out.write(raw);out.flush();os.fsync(out.fileno())
def jbytes(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
provider_path=BASE/'component-probe-r6-r3/component_probe_provider.py'
check('frozen_component_r3_source_pin',sha(provider_path.read_bytes())==ready.SOURCE_SHA)
spec=importlib.util.spec_from_file_location('host_frozen_component_r3',provider_path)
provider=importlib.util.module_from_spec(spec);spec.loader.exec_module(provider)
resolution=BASE/'ondevice-contract-review-v150/retirement-resolution-r4-01/pocket4/RESOLUTION.json'
retirement=retired.binding(resolution)
previous={'identity':retirement['scope'],'request_sha256':retirement['native_request_sha256'],'terminal':{'status':'provider_failed'}}
nonce='a7'*16
request=provider.owner_request(nonce).encode()
c=dict(ready.PINS,nonce=nonce,executor_server_instance='b6'*16,owner_request_sha256=sha(request),
       selected_session_id=previous['identity']['session_id'],selected_profile_id=previous['identity']['profile_id'],
       expires_unix_ms=time.time_ns()//1000000+600000)
check('contract_owner_matches_frozen_provider_bytes',ready.validate_contract(c)==request and provider.validate_contract(c)==c)
with tempfile.TemporaryDirectory(prefix='hepta-ready-r4-host-',dir=str(BASE/'sender-r5-validation')) as temp:
 root=Path(temp).resolve();contract=root/'contract.json';put(contract,jbytes(c))
 binding=ready.binding(contract,request,previous['identity'])
 check('fixed_contract_binding_has_no_generic_command_or_path',binding['phone_source_path']==str(ready.SOURCE) and binding['phone_ready_path']==str(ready.STATE/('ready-'+nonce+'.json')))
 rejected('different_owner_request_rejected',lambda:ready.binding(contract,request+b'\n',previous['identity']))
 for field,old_pin in [('provider_source_sha256','ff65efc41c30027d0066ddd6fdf3120278c83ccdbe56d7e24922ed96782d2118'),('policy_rule_sha256','7011fc8b0e4629a05bdd9739d168cdcba9b43044e54e0cdadb6da5f5bb876381'),('patched_policy_sha256','67ee1d75606e42e8b95c91faa57f7a22a5070e177cd6cc82552308f3de2b25d0')]:
  prior=copy.deepcopy(c);prior[field]=old_pin
  rejected('old_r2_binding_rejected_'+field,lambda prior=prior:ready.validate_contract(prior))
 wrong=copy.deepcopy(c);wrong['provider_source_sha256']='0'*64
 rejected('old_or_unpinned_component_source_rejected',lambda:ready.validate_contract(wrong))
 state=root/'state';proc=root/'proc';state.mkdir(mode=0o700);(state/'claims').mkdir(mode=0o700)
 put(state/'contracts'/(nonce+'.json'),jbytes(c))
 probe=ready.phone_probe(binding).replace("STATE=Path('/var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6')",'STATE=Path('+repr(str(state))+')').replace("PROC=Path('/proc')",'PROC=Path('+repr(str(proc))+')').replace('st_uid==0','st_uid==os.getuid()')
 ast.parse(probe,feature_version=(3,12))
 check('generated_probe_is_python312_compatible',True)
 now=1000000000000;wall=time.time_ns()//1000000
 def run_probe():
  output=io.StringIO()
  with patch('time.monotonic_ns',return_value=now),patch('time.time_ns',return_value=wall*1000000),contextlib.redirect_stdout(output):
   try:exec(compile(probe,'HOST_ONLY_READY_COPY_FIXTURE','exec'),{})
   except SystemExit as error:
    assert error.code==0
  return json.loads(output.getvalue())
 waiting=run_probe()
 check('absent_ready_is_readonly_waiting_not_success',waiting['state']=='waiting_for_ready' and waiting['socket_connections']==0 and waiting['phone_writes'] is False)
 pid=4242;start=123456
 record={'pid':pid,'pid_start_ticks':start,'instance':'c5'*16,'port':18080,'scope':ready.SCOPE,
  'nonce':nonce,'owner_request_sha256':c['owner_request_sha256'],'provider_source_sha256':ready.SOURCE_SHA,
  'contract_sha256':binding['contract_sha256'],'accepting_one_session':True,
  'executor_server_instance':c['executor_server_instance'],'clock':'phone CLOCK_MONOTONIC',
  'ready_monotonic_ns':now-1000000000,'accept_deadline_monotonic_ns':now+35000000000,
  'service_deadline_monotonic_ns':now+65000000000,'readiness_scope':'transport_and_readonly_parent_identity_only'}
 put(state/('ready-'+nonce+'.json'),jbytes(record))
 put(state/('service-attempt-'+nonce+'.json'),jbytes({'contract_sha256':binding['contract_sha256'],'automatic_restart':False,'pid':pid}))
 put(state/'source-r3/component_probe_provider.py',provider_path.read_bytes())
 fields=['S']+['0']*18+[str(start)]+['0']*5
 put(proc/str(pid)/'stat',(str(pid)+' (python3) '+' '.join(fields)+'\n').encode())
 wanted=[b'/usr/bin/python3',b'-B',str(state/'source-r3/component_probe_provider.py').encode(),b'--contract',str(state/'contracts'/(nonce+'.json')).encode(),b'--contract-sha256',binding['contract_sha256'].encode()]
 put(proc/str(pid)/'cmdline',b'\0'.join(wanted)+b'\0')
 observed=run_probe()
 check('real_probe_logic_binds_ready_contract_process_source',observed['state']=='ready_observed' and observed['process_identity_bound'] is True and observed['provider_source_sha256']==ready.SOURCE_SHA)
 check('same_phone_clock_used_for_accept_remaining',observed['remaining_accept_ns']==35000000000 and ready.validate_ready_observation(observed,binding) is observed)
 for key,value in [('nonce','d4'*16),('owner_request_sha256','0'*64),('provider_source_sha256','0'*64),('contract_sha256','0'*64),('executor_server_instance','d4'*16),('scope',{}),('clock','Pocket4 clock')]:
  bad=copy.deepcopy(observed);bad['ready'][key]=value
  rejected('ready_rejects_wrong_'+key,lambda bad=bad:ready.validate_ready_observation(bad,binding))
 for key in ('claim_absent','ended_absent','attempt_bound','process_identity_bound'):
  bad=copy.deepcopy(observed);bad[key]=False
  rejected('ready_rejects_'+key+'_false',lambda bad=bad:ready.validate_ready_observation(bad,binding))
 late=copy.deepcopy(observed);late['phone_monotonic_ns']=record['accept_deadline_monotonic_ns']-14000000000;late['remaining_accept_ns']=14000000000
 rejected('under_15_seconds_never_admitted',lambda:ready.validate_ready_observation(late,binding))
 extended=copy.deepcopy(observed);extended['ready']['service_deadline_monotonic_ns']+=1000000000
 rejected('extended_service_window_rejected',lambda:ready.validate_ready_observation(extended,binding))
 changed=copy.deepcopy(observed);changed['ready']['instance']='d4'*16
 rejected('ready_instance_cannot_change_between_checks',lambda:ready.validate_ready_observation(changed,binding,observed))
 claim=state/'claims'/(nonce+'.json');put(claim,b'{}\n')
 rejected('actual_claim_file_blocks_probe',run_probe);claim.unlink()
 ended=state/('service-ended-'+nonce+'.json');put(ended,b'{}\n')
 rejected('actual_ended_file_blocks_probe',run_probe);ended.unlink()
 stat_path=proc/str(pid)/'stat';stat_raw=stat_path.read_bytes()
 stat_path.write_bytes(stat_raw.replace(str(start).encode(),str(start+1).encode()))
 rejected('actual_pid_reuse_blocks_probe',run_probe);stat_path.write_bytes(stat_raw)
 cmd=proc/str(pid)/'cmdline';cmd_raw=cmd.read_bytes();cmd.write_bytes(cmd_raw.replace(b'source-r3',b'source-r2'))
 rejected('actual_wrong_process_command_blocks_probe',run_probe);cmd.write_bytes(cmd_raw)
 # Generate the real final actor without running its body or any external command.
 req=root/'request.txt';put(req,request);prev=root/'previous.json';put(prev,jbytes(previous))
 draft='HOST ONLY original nonempty draft 保留🙂'
 preserve=root/'preserved.json';put(preserve,jbytes({'exact_utf8_b64':base64.b64encode(draft.encode()).decode(),'utf8_sha256':sha(draft.encode())}))
 label='host-ready-r5-'+secrets.token_hex(6);external=[];output=io.StringIO()
 def forbidden(*a,**k):external.append(True);raise AssertionError('external execution forbidden in host fixture')
 argv=['send_new_native_task_r5.py',label,str(req),str(prev),'--preserved-draft',str(preserve),'--retirement-resolution',str(resolution),'--evidence-root','component','--component-contract',str(contract)]
 with patch.object(sys,'argv',argv),patch('subprocess.run',side_effect=forbidden),contextlib.redirect_stdout(output):
  try:runpy.run_path(str(BASE/'send_new_native_task_r5.py'),run_name='__main__')
  except SystemExit as error:assert error.code==0
 built=json.loads(output.getvalue());actor=Path(built['actor_path']).read_text();tree=ast.parse(actor,feature_version=(3,12))
 check('component_default_build_has_zero_external_calls',not external and built['state']=='BUILT_ONLY_NO_PHONE')
 check('component_actor_still_exactly_one_Send',len([n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='tap' and len(n.args)==1 and isinstance(n.args[0],ast.Name) and n.args[0].id=='send'])==1)
 check('component_actor_binds_source_r3_only',str(ready.SOURCE) in actor and ready.SOURCE_SHA in actor)
 nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('wait_component_rendezvous','component_send_margin','read_component_ready')]
 module=ast.Module(body=nodes,type_ignores=[]);ast.fix_missing_locations(module)
 class Clock:
  def __init__(self):self.ns=1000000000
  def monotonic_ns(self):return self.ns
  def sleep(self,seconds):self.ns+=int(seconds*1000000000)
 clock=Clock();saved={};sent=[]
 env={'component_binding':binding,'evidence_mode':'component','time':clock,'pre_send_deadline_ns':clock.ns+150000000000,
      'save':lambda name,value:saved.__setitem__(name,value)}
 exec(compile(module,'HOST_ONLY_EXTRACTED_RENDEZVOUS','exec'),env)
 actual_read=env['read_component_ready']
 def no_ready(*args,**kwargs):
  clock.ns+=2000000000
  return {'observation':dict(waiting)}
 env['read_component_ready']=no_ready
 def timeout_then_send():
  env['wait_component_rendezvous']();sent.append(True)
 rejected('ready_timeout_has_zero_Send',timeout_then_send)
 check('timeout_keeps_original_absolute_deadline',not sent and clock.ns<=env['pre_send_deadline_ns'] and saved['COMPONENT-PREPARED-NO-SEND.json']['pre_send_deadline_monotonic_ns']==151000000000)
 check('prepared_marker_has_no_user_draft_or_hash',draft not in json.dumps(saved) and sha(draft.encode()) not in json.dumps(saved))
 clock.ns=1000000000;env['pre_send_deadline_ns']=151000000000
 def valid_ready(*args,**kwargs):return {'observation':observed,'read_start_monotonic_ns':clock.ns}
 env['read_component_ready']=valid_ready
 check('ready_rendezvous_returns_without_any_Send_or_launch',env['wait_component_rendezvous']()['observation']==observed and not sent)
 clock.ns=25000000000
 rejected('transport_and_post_read_delay_consumes_margin',lambda:env['component_send_margin']({'observation':observed,'read_start_monotonic_ns':1000000000}))
 report={'schema':'hepta.sender-r5-component-host-validation.v150.1','status':'PASS','checks_passed':len(CHECKS),'checks':CHECKS,
   'phone_calls':0,'model_calls':0,'socket_connections':0,'external_process_requests':len(external),
   'physical_qualification':False,'draft_fixture_synthetic_not_user_draft':True,
   'sources':{p.name:{'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())} for p in (BASE/'send_new_native_task_r5.py',BASE/'sender_component_ready_r5.py',provider_path)}}
 output_path=BASE/'sender-r5-validation/HOST-READY-CHECKS-01.json';put(output_path,jbytes(report))
 print(json.dumps(report,indent=2))
