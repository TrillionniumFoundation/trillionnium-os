"""Offline candidate controls; no phone, installer, service, or role is executed."""
import base64,contextlib,copy,hashlib,io,json,os,runpy,shlex,signal,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=Path(sys.argv[1]);OUT.mkdir(mode=0o700)
sys.argv=[str(ROOT/'validation/run_install_ready_source_controls.py'),str(OUT/'original43')]
capture=io.TextIOWrapper(io.BytesIO())
with contextlib.redirect_stdout(capture):ns=runpy.run_path(sys.argv[0])
R,P=ns['R'],ns['P'];cases=list(ns['cases'])
def check(value):
 if not value:raise AssertionError('offline candidate control assertion')
def test(name,fn):
 fn();cases.append({'name':name,'passed':True})
def rejects(name,fn,message):
 try:fn()
 except ValueError as e:
  check(message in str(e));cases.append({'name':name,'passed':True,'rejection':str(e)})
 else:raise AssertionError('accepted negative: '+name)
fixture,modify=ns['process_fixture'],ns['modify_tool']
test('unchanged_valid_process_shape',lambda:fixture())
for name,key,change,message in (
 ('stream_offset_false','read',lambda x:x['stdout'].update(offset=False),'full bytes and EOF'),
 ('stream_offset_float_zero','read',lambda x:x['stdout'].update(offset=0.0),'full bytes and EOF'),
 ('empty_next_offset_false','read',lambda x:x['stderr'].update(next_offset=False),'full bytes and EOF'),
 ('nonempty_next_offset_float','read',lambda x:x['stdout'].update(next_offset=float(x['stdout']['size'])),'full bytes and EOF'),
 ('empty_durable_counts_false','status',lambda x:x['log_bytes']['stderr'].update(seen=False,stored=False),'durable stream counts'),
 ('nonempty_durable_counts_float','status',lambda x:x['log_bytes']['stdout'].update(seen=float(x['log_bytes']['stdout']['seen']),stored=float(x['log_bytes']['stdout']['stored'])),'durable stream counts'),
 ('truncated_integer_zero','status',lambda x:x['log_truncated'].update(stdout=0,stderr=0),'complete success'),
 ('truncated_float_zero','status',lambda x:x['log_truncated'].update(stdout=0.0,stderr=0.0),'complete success'),
 ('synced_integer_one_still_rejected','status',lambda x:x['log_synced'].update(stdout=1),'durable stream counts')):
 rejects(name,lambda k=key,c=change:fixture(modify(k,c)),message)
def parse_guard(value):return R.verify_guard(ns['guard_bytes'](value),ns['expect']['stage'],P,ns['source_pool'])
test('unchanged_valid_integer_guard_identity',lambda:parse_guard(ns['receipt']))
bad=copy.deepcopy(ns['receipt']);bad['identity']=[123,True,123,123,999]
proc=b'123 (synthetic control) R 1 123 123 '+b'0 '*15+b'999 0\n'
bad['proc_before_base64']=bad['proc_after_base64']=base64.b64encode(proc).decode()
rejects('guard_bool_parent_aliases_one',lambda:parse_guard(bad),'positive integer')
bad=copy.deepcopy(ns['receipt']);bad['identity']=[123.0,122.0,123.0,123.0,999.0]
rejects('guard_float_identity_aliases_integers',lambda:parse_guard(bad),'positive integer')
sample={'text':'中文😀\nsecond line','number':1}
for name,serializer in [('canonical',P.canonical),('request',P.request_bytes),('file',R.original_file_json),('stdout',R.original_entry_stdout),('actor',R.original_actor_json)]:
 def serialization(serializer=serializer,name=name):
  raw=serializer(sample)
  check(raw.endswith(b'\n')and not raw.endswith(b'\\n')and json.loads(raw)==sample and b'\\nsecond line'in raw)
  check(('中文😀'.encode()in raw)==(name not in ('file','stdout')))
 test(name+'_real_LF_and_exact_multiline_unicode',serialization)
def bootstrap():
 expected=ns['expect']['stage'];parts=shlex.split(expected['request']['command']);check(parts[-2]=='-c')
 head,guard=parts[-1].split('\n',1);check(guard==P.GUARD)
 scope={};exec(compile(head,'<synthetic-spec>','exec'),scope)
 check(base64.b64decode(scope['SPEC'],validate=True)==P.canonical(expected['spec']))
 check(expected['request_raw']==P.request_bytes(expected['request']))
 compile(parts[-1],'<unexecuted-wire-bootstrap>','exec')
test('derived_request_bootstrap_real_LF',bootstrap)
calls=[]
rejects('unbound_before_parse_import_callback',lambda:R.verify_install_start_ready_originals(b'not-json',read_pinned=lambda x:calls.append(x)),'UNBOUND_ACTUAL_INSTALL_START_READY_INPUTS_NO_IO')
test('frozen_slots_still_none_zero_callbacks',lambda:check(not calls and R.FROZEN_INPUTS is None and R.FROZEN_EXECUTION_PLAN is None))
pure_count=len(cases)
CHILD=r'''
import base64,hashlib,json,os,signal,sys,tempfile,time,types
from pathlib import Path
protocol_path,mode=sys.argv[1:]
p=types.ModuleType('offline_protocol');exec(compile(Path(protocol_path).read_bytes(),protocol_path,'exec'),p.__dict__)
realos=os
class StatView:
 def __init__(self,value):self.value=value
 def __getattr__(self,key):return 0 if key in ('st_uid','st_gid')else getattr(self.value,key)
shim=types.ModuleType('os')
for key in dir(os):setattr(shim,key,getattr(os,key))
if mode!='unmodified_nonroot_rejection':
 for key in ('getuid','geteuid','getgid','getegid'):setattr(shim,key,lambda:0)
 shim.lstat=lambda *a,**k:StatView(realos.lstat(*a,**k))
 shim.fstat=lambda *a,**k:StatView(realos.fstat(*a,**k))
sys.modules['os']=shim
begun=time.monotonic();pipe=None
with tempfile.TemporaryDirectory(prefix='hepta-host-guard-source-')as tmp:
 target=Path(tmp)/'harmless.py';marker=Path(tmp)/'executed.json'
 body=("import json,os,signal\nfrom pathlib import Path\nPath("+repr(str(marker))+").write_text(json.dumps({'pid':os.getpid(),'pgid':os.getpgrp(),'sid':os.getsid(0),'timer':signal.getitimer(signal.ITIMER_REAL),'handler':getattr(signal.getsignal(signal.SIGALRM),'__name__',None),'stderr_blocking':os.get_blocking(2)}))\n").encode()
 target.write_bytes(body);target.chmod(0o600)
 def audit_prior_handler(*unused):pass
 signal.signal(signal.SIGALRM,audit_prior_handler)
 spec={'schema':'hepta.production.install-ready.entry-spec.v1','boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'phase':'stage','source':{'path':str(target),'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()},'argv':[str(target)]}
 if mode=='bad_hash_cleanup':spec['source']['sha256']='0'*64
 if mode=='blocked_receipt_deadline':
  readfd,writefd=os.pipe();pipe=(readfd,writefd);os.set_blocking(writefd,False)
  while True:
   try:os.write(writefd,b'x'*4096)
   except BlockingIOError:break
  os.dup2(writefd,2);os.set_blocking(2,True)
 before=(os.getpid(),os.getpgrp(),os.getsid(0));error=None
 try:exec(compile('SPEC='+repr(base64.b64encode(p.canonical(spec)).decode())+'\n'+p.GUARD,'<unchanged-offline-source-guard>','exec'),{'__name__':'__main__'})
 except BaseException as e:error={'class':type(e).__name__,'message':str(e)}
 report={'mode':mode,'same_process':before==(os.getpid(),os.getpgrp(),os.getsid(0)),'identity':before,'elapsed':time.monotonic()-begun,'executed':marker.exists(),'body_observation':json.loads(marker.read_text())if marker.exists()else None,'error':error,'timer':signal.getitimer(signal.ITIMER_REAL),'prior_handler_restored':signal.getsignal(signal.SIGALRM)is audit_prior_handler,'stderr_blocking':os.get_blocking(2),'synthetic_root_metadata':mode!='unmodified_nonroot_rejection'}
 if pipe:
  os.close(pipe[0]);os.close(pipe[1])
 print(json.dumps(report))
'''
guard_runs=[]
def run_guard(mode):
 p=subprocess.Popen([sys.executable,'-I','-B',str(OUT/'host_guard_child.py'),str(ROOT/'source/install_ready_execution_protocol.py'),mode],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
 try:stdout,stderr=p.communicate(timeout=15)
 except BaseException:
  try:os.killpg(p.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  p.communicate();raise
 check(p.returncode==0)
 result=json.loads(stdout);check(result['same_process']and result['timer']==[0.0,0.0]and result['prior_handler_restored']and result['stderr_blocking'])
 try:os.killpg(p.pid,0)
 except ProcessLookupError:pass
 else:raise AssertionError('offline child process group remained')
 (OUT/(mode+'.stdout')).write_bytes(stdout);(OUT/(mode+'.stderr')).write_bytes(stderr)
 if mode=='success':
  check(result['error']is None and result['executed'])
  b=result['body_observation'];check([b['pid'],b['pgid'],b['sid']]==result['identity']and b['timer']==[0.0,0.0]and b['handler']=='audit_prior_handler'and b['stderr_blocking'])
  check(stderr.startswith(P.RECEIPT_PREFIX)and stderr.count(b'\n')==1)
  receipt=json.loads(stderr[len(P.RECEIPT_PREFIX):]);check(receipt['identity'][0]==b['pid']and receipt['identity'][2:4]==[b['pgid'],b['sid']])
 else:
  check(not result['executed']and result['error']is not None)
  if mode=='blocked_receipt_deadline':check(result['error']['class']=='TimeoutError'and 8<=result['elapsed']<=13)
  elif mode=='bad_hash_cleanup':check(result['error']=={'class':'ValueError','message':'complete selected entry bytes'})
  else:check(result['error']['message']=='root entry guard')
 guard_runs.append(result)
guard_skip=None
if sys.platform.startswith('linux'):
 (OUT/'host_guard_child.py').write_text(CHILD)
 for mode in ('success','bad_hash_cleanup','blocked_receipt_deadline'):
  test('unchanged_guard_host_'+mode,lambda mode=mode:run_guard(mode))
 if os.getuid()!=0:test('unchanged_guard_nonroot_refuses',lambda:run_guard('unmodified_nonroot_rejection'))
else:guard_skip='Linux procfs required; four guard execution controls not executed on this host'
report={'schema':'hepta.install-ready.candidate.offline-controls.v1','state':'PASS_SOURCE_ONLY','passed':len(cases),'original_source_controls':43,'additional_type_lf_controls':pure_count-43,'host_guard_controls_count':len(guard_runs),'host_guard_execution_skip':guard_skip,'tests':cases,'host_guard_controls':guard_runs,'source_pins':{n:R.pin((ROOT/'source'/n).read_bytes())for n in ('verify_install_start_ready_UNBOUND.py','install_ready_execution_protocol.py')},'original43_result':R.pin((OUT/'original43/RESULT.json').read_bytes()),'synthetic_parser_fixtures':True,'guard_execution_uses_simulated_root_metadata_and_harmless_body':True,'actual_phone_operations':0,'actual_installs':0,'actual_READY':0,'formal_role_identities_generated':0,'fixed19_credit':0,'whole_qualification':False}
raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
with(OUT/'RESULT.json').open('xb')as f:f.write(raw)
sys.stdout.buffer.write(raw)
