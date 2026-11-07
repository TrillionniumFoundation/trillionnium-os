#!/usr/bin/env python3
"""Public projected-source host tests; synthetic inputs, no main, SSH, device or signals."""
import ast,errno,hashlib,json,os,stat,subprocess,sys,tempfile,time,types
from pathlib import Path
ROOT=Path(__file__).resolve().parent
EVIDENCE=Path(os.environ.get('RAZR_TRANSPORT_TEST_OUTPUT', str(Path(tempfile.gettempdir())/'razr60-public-transport'/('run-'+str(time.time_ns()))))).resolve()
EVIDENCE.mkdir(parents=True,exist_ok=False)
HELPERS={'need','sha','enc','desc','read','put','syncdir','newdir','original_stream','finish_stream','close_streams_owned'}
BIND=json.loads((ROOT/'CANDIDATE-BINDING.PUBLIC.json').read_text())
assert BIND['schema']=='razr60.r8-transport-public-source-binding.v1' and BIND['projected'] is True
RESULTS=[]

def fd_directory():
 # macOS exposes /dev/fd rather than Linux's /proc/self/fd. Refuse an
 # unsupported host before launching tests; never silently skip leak checks.
 errors=[]
 for path in ('/proc/self/fd','/dev/fd'):
  if not Path(path).is_dir():continue
  try:os.listdir(path)
  except OSError as error:errors.append({'path':path,'error_type':type(error).__name__})
  else:return path
 raise RuntimeError('readable /proc/self/fd or /dev/fd required for fd assertions: '+repr(errors))

FD_DIRECTORY=fd_directory()

def open_fds():
 # listdir's own temporary directory descriptor may appear in either listing.
 # fstat removes that already-closed descriptor from the observed live set.
 live=set()
 for entry in os.listdir(FD_DIRECTORY):
  if not entry.isdecimal():continue
  fd=int(entry)
  try:os.fstat(fd)
  except OSError as error:
   if error.errno!=errno.EBADF:raise
  else:live.add(fd)
 return live

def assigned_names(node):
 if not isinstance(node,ast.Assign) or len(node.targets)!=1:return None
 target=node.targets[0]
 if isinstance(target,ast.Name):return (target.id,)
 if isinstance(target,ast.Tuple) and all(isinstance(item,ast.Name) for item in target.elts):
  return tuple(item.id for item in target.elts)
 return None

def named_call(node,name):
 return isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id==name

def sender_assignment(node):
 return (assigned_names(node)==('child','d','so','se')
  and isinstance(node.value,ast.Attribute) and node.value.attr=='sender'
  and isinstance(node.value.value,ast.Name) and node.value.value.id=='self')

def sender_result_assignment(node):
 return (assigned_names(node)==('sent',) and named_call(node.value,'strict')
  and len(node.value.args)==1 and named_call(node.value.args[0],'read'))

def extract(path,expected):
 raw=Path(path).read_bytes();assert hashlib.sha256(raw).hexdigest()==expected
 tree=ast.parse(raw);chain=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Chain')
 helpers=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in HELPERS]
 methods=[n for n in chain.body if isinstance(n,ast.FunctionDef) and n.name in ('execute_process','close_owned_host_outputs')]
 run=next(n for n in chain.body if isinstance(n,ast.FunctionDef) and n.name=='run')
 nodes=run.body
 start=next(i for i,n in enumerate(nodes) if sender_assignment(n))
 end=next(i for i,n in enumerate(nodes) if sender_result_assignment(n))
 join=ast.FunctionDef(name='join_sender_only',args=ast.arguments(posonlyargs=[],args=[ast.arg(arg='self')],kwonlyargs=[],kw_defaults=[],defaults=[]),body=nodes[start:end]+[ast.Return(value=ast.Name(id='rc',ctx=ast.Load()))],decorator_list=[])
 cls=ast.ClassDef(name='Chain',bases=[],keywords=[],body=methods+[join],decorator_list=[])
 isolated=ast.fix_missing_locations(ast.Module(body=helpers+[cls],type_ignores=[]))
 ns=dict(hashlib=hashlib,json=json,os=os,Path=Path,re=__import__('re'),stat=stat,subprocess=subprocess,time=time)
 exec(compile(isolated,str(path),'exec'),ns)
 assert 'main' not in ns and 'SSH' not in ns
 return ns

HASH_READER="import sys,json,hashlib,os,stat; b=sys.stdin.buffer.read(); print(json.dumps({'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'regular':stat.S_ISREG(os.fstat(0).st_mode)}))"

def case(name,code='pass',timeout=1.0,payload=b'x'*(2*1024*1024),fault=None,async_start=False,original=False,join_sender=False,outer_cleanup=False):
 src=ROOT/'base/run_component_root_once.py' if original else ROOT/'candidate/run_component_root_once.py'
 expected=BIND['base_sha256'] if original else BIND['candidate_sha256']
 ns=extract(src,expected)
 out=EVIDENCE/'cases'/name;out.mkdir(parents=True,exist_ok=False)
 obj=ns['Chain']();obj.out=out;obj.steps=[]
 calls=[];children=[];streams=[];waits=[];fds=[];errors=[];phase_name='sender-execute' if async_start else 'phase'
 original_stream=ns['original_stream'];original_put=ns['put'];original_os=ns['os'];active={'yes':True};fired={'v':False};input_path=out/phase_name/'stdin.original'
 def tracked_stream(path):
  if fault=='stderr-open' and Path(path).name=='stderr.original':raise OSError(errno.EIO,'injected stderr open')
  f=original_stream(path);streams.append(f);return f
 ns['original_stream']=tracked_stream
 class OS:
  def __getattr__(self,k):return getattr(original_os,k)
  def getpgid(self,pid):
   if fault=='identity':raise OSError(errno.EIO,'injected identity read')
   return os.getpgid(pid)
  def open(self,p,flags,*a,**kw):
   fd=os.open(p,flags,*a,**kw)
   if fault=='stdin-replace' and Path(p).name=='stdin.original' and not (flags & os.O_CREAT):
    fds.append(fd);q=Path(p).with_name('replacement');q.write_bytes(Path(p).read_bytes());q.chmod(0o600);os.replace(q,p)
   if fault=='stream-create-fsync' and Path(p).name=='stdout.original':fds.append(fd)
   return fd
  def fsync(self,fd):
   if fault=='stream-create-fsync' and fd in fds and not fired['v']:
    fired['v']=True;raise OSError(errno.EIO,'injected output creation fsync')
   if fault in ('stdout-fsync','async-join-fsync','async-timeout-fsync','outer-fsync') and children and streams and not streams[0].closed and fd==streams[0].fileno() and not fired['v']:
    fired['v']=True;raise OSError(errno.EIO,'injected stdout fsync')
   return os.fsync(fd)
 ns['os']=OS()
 def put(path,data):
  if Path(path).name=='CHILD.json':
   if fault in ('child-record','child-unknown-record'):raise OSError(errno.EIO,'injected CHILD persistence')
   if fault=='record-delay':time.sleep(timeout*2)
  if Path(path).name=='UNKNOWN.json' and fault=='child-unknown-record':raise OSError(errno.ENOSPC,'injected UNKNOWN persistence')
  v=original_put(path,data)
  if Path(path).name=='stdin.original':
   if fault=='stdin-mutate':
    with Path(path).open('r+b') as f:f.write(b'z'*len(data));f.flush();os.fsync(f.fileno())
   if fault=='stdin-mode':Path(path).chmod(0o644)
  return v
 ns['put']=put
 def popen(*a,**kw):
  calls.append({'argv':a[0],'stdin_type':type(kw.get('stdin')).__name__})
  if fault=='popen':raise FileNotFoundError(errno.ENOENT,'injected absent local executable')
  p=subprocess.Popen(*a,**kw);children.append(p);actual_wait=p.wait
  def wait(*a,**kw):
   t=time.monotonic();w={'timeout':kw.get('timeout')}
   try:rc=actual_wait(*a,**kw)
   except BaseException as ex:w['outcome']=type(ex).__name__;raise
   else:
    w.update(outcome='joined',returncode=rc)
    if fault in ('late-join','async-late-join') and active['yes']:time.sleep(timeout*2)
    if fault=='postjoin-mutate' and active['yes']:
     with input_path.open('r+b') as f:f.write(b'z'*len(payload));f.flush();os.fsync(f.fileno())
    return rc
   finally:
    w['elapsed']=time.monotonic()-t
    if active['yes']:waits.append(w)
  p.wait=wait;return p
 ns['subprocess']=types.SimpleNamespace(Popen=popen,DEVNULL=subprocess.DEVNULL,PIPE=subprocess.PIPE,TimeoutExpired=subprocess.TimeoutExpired)
 before_fds=open_fds()
 t=time.monotonic();value=None;error=None;join_error=None;cleanup=None
 try:value=obj.execute_process(phase_name,[sys.executable,'-I','-B','-c',code],timeout,input_raw=payload,async_start=async_start)
 except BaseException as ex:error=ex
 elapsed=time.monotonic()-t
 records={n:(out/phase_name/n).exists() for n in ('INTENT.json','CHILD.json','UNKNOWN.json','RESULT.json','JOINED.json','OWNED-CHILD-FAILURE.json')}
 at_return=[{'pid':p.pid,'returncode':p.returncode} for p in children]
 at_return_closed=all(f.closed for f in streams)
 owned_at_return=list(getattr(obj,'_owned_host_children',{}))
 if join_sender and error is None:
  obj.sender=value
  try:value=obj.join_sender_only()
  except BaseException as ex:join_error=ex
 if outer_cleanup and error is None:
  cleanup=obj.close_owned_host_outputs()
 if original:
  assert isinstance(error,BrokenPipeError),(name,error)
  assert not records['CHILD.json'] and not records['UNKNOWN.json'] and not records['RESULT.json']
  assert not at_return_closed
 elif fault in ('stdin-mutate','stdin-replace','stdin-mode','stderr-open','stream-create-fsync'):
  assert error is not None and not children and not records['RESULT.json'],(name,error)
  assert at_return_closed
 elif fault=='popen':
  assert isinstance(error,FileNotFoundError) and not children and at_return_closed
 elif fault in ('identity','child-record','child-unknown-record'):
  assert isinstance(error,OSError) and len(children)==1 and at_return_closed and owned_at_return==[phase_name]
  assert obj.steps[-1]['pid']==children[0].pid and not records['RESULT.json']
  assert records['UNKNOWN.json']==(fault!='child-unknown-record')
  if fault=='child-unknown-record':assert obj.steps[-1]['unknown_record_error_type']=='OSError'
 elif fault in ('record-delay','late-join','postjoin-mutate','stdout-fsync'):
  assert error is not None and records['CHILD.json'] and records['UNKNOWN.json'] and not records['RESULT.json']
  assert at_return_closed
  if fault=='record-delay':assert waits[0]['timeout']==0.0
  if fault=='late-join':assert obj.steps[-1]['child_wait_returned'] is True
 elif async_start:
  assert error is None and len(children)==1 and records['CHILD.json'] and not records['RESULT.json']
  assert isinstance(value,(tuple,int)) or join_error is not None
  if join_sender:
   assert all(f.closed for f in streams)
   if fault=='async-late-join':
    assert isinstance(join_error,ValueError) and obj._owned_host_children[phase_name] is children[0]
    assert children[0].returncode is not None and not (out/phase_name/'JOINED.json').exists()
    cleanup=obj.close_owned_host_outputs();assert cleanup['host_children'][0]['returncode']==0
   elif fault=='async-join-fsync':
    assert isinstance(join_error,ValueError) and obj.steps[-1]['cleanup_errors']
   elif fault=='async-timeout-fsync':
    assert isinstance(join_error,RuntimeError) and 'still running' in str(join_error)
    assert obj.steps[-1]['cleanup_errors']
   else:assert join_error is None and value==0
  elif outer_cleanup:
   assert all(f.closed for f in streams) and len(cleanup['host_children'])==1
   assert (out/phase_name/'OWNED-CHILD-FAILURE.json').exists()
   if fault=='outer-fsync':assert cleanup['stream_cleanup_errors']
  else:
   assert len(value)==4 and value[0] is children[0] and value[1]==out/phase_name and owned_at_return==[phase_name]
 elif name=='fixed-nonreader-2m':
  assert isinstance(error,RuntimeError) and records['CHILD.json'] and records['UNKNOWN.json']
  assert at_return[0]['returncode'] is None and owned_at_return==[phase_name] and at_return_closed
  assert 0<=waits[0]['timeout']<=timeout and elapsed<0.5
 else:
  assert error is None and at_return_closed and records['CHILD.json'] and records['RESULT.json'] and not records['UNKNOWN.json'],(name,error)
  if name in ('fixed-readback','fixed-empty-input'):
   v=json.loads(value);assert v['bytes']==len(payload) and v['sha256']==hashlib.sha256(payload).hexdigest() and v['regular']
 active['yes']=False
 for child in children:
  child.wait(timeout=3)
  if child.stdin is not None:
   try:child.stdin.close()
   except BrokenPipeError:pass
 for f in streams:
  if not f.closed:f.close()
 for fd in fds:
  try:os.fstat(fd)
  except OSError as ex:assert ex.errno==errno.EBADF
  else:raise AssertionError('fd leaked')
 after_fds=open_fds()
 if not original:assert after_fds==before_fds,(name,'fd leak',sorted(before_fds),sorted(after_fds))
 if async_start and code==HASH_READER:
  response=json.loads((out/phase_name/'stdout.original').read_bytes());assert response['bytes']==len(payload) and response['sha256']==hashlib.sha256(payload).hexdigest()
 item={'case':name,'pass':True,'fd_check':{'directory':FD_DIRECTORY,'before':sorted(before_fds),'after':sorted(after_fds),'leak_assertion_applied':not original},'source_sha256':expected,'input_bytes':None if payload is None else len(payload),'budget_seconds':timeout,'elapsed_to_return_seconds':elapsed,'method_waits':waits,'start_calls':len(calls),'actual_children':at_return,'at_return_outputs_closed':at_return_closed,'at_return_owned':owned_at_return,'error_type':type(error).__name__ if error else None,'error_message':str(error) if error else None,'join_error_type':type(join_error).__name__ if join_error else None,'join_error_message':str(join_error) if join_error else None,'records_at_execute_return':records,'steps':obj.steps,'outer_cleanup':cleanup,'natural_local_children_joined':True,'signals_sent':0,'automatic_replay':False}
 RESULTS.append(item)
 (out/'TEST-RESULT.json').write_text(json.dumps(item,indent=2)+'\n')
 print(json.dumps({'case':name,'pass':True,'elapsed':round(elapsed,4),'error':item['error_type'],'join_error':item['join_error_type']}),flush=True)

case('original-nonreader-2m','import time; time.sleep(1.5)',timeout=.05,original=True)
case('original-earlyexit-2m','raise SystemExit(0)',timeout=.05,original=True)
case('fixed-nonreader-2m','import time; time.sleep(1.5)',timeout=.05)
case('fixed-earlyexit-2m','raise SystemExit(0)',timeout=.05)
case('fixed-readback',HASH_READER)
case('fixed-empty-input',HASH_READER,payload=b'')
case('fixed-no-input','pass',payload=None)
case('fixed-earlyclose','import os,time; os.close(0); time.sleep(.1)')
for fault in ['popen','stderr-open','stream-create-fsync','identity','child-record','child-unknown-record','stdin-mutate','stdin-replace','stdin-mode','postjoin-mutate','stdout-fsync']:
 case('fault-'+fault,'import time; time.sleep(.15)' if fault in ('identity','child-record','child-unknown-record') else HASH_READER,fault=fault)
case('fault-record-delay','import time; time.sleep(.3)',timeout=.05,fault='record-delay')
case('fault-late-join','pass',timeout=.1,fault='late-join')
case('async-abi-exact-readback',HASH_READER,async_start=True)
case('async-real-caller-readback',HASH_READER,async_start=True,join_sender=True)
case('async-real-caller-fsync-failure',HASH_READER,async_start=True,join_sender=True,fault='async-join-fsync')
case('async-real-caller-timeout-and-fsync','import time; time.sleep(.5)',timeout=.1,async_start=True,join_sender=True,fault='async-timeout-fsync')
case('async-late-join-known-child','pass',timeout=.1,async_start=True,join_sender=True,fault='async-late-join')
case('async-outer-failure-cleanup',HASH_READER,async_start=True,outer_cleanup=True)
case('async-outer-fsync-failure',HASH_READER,async_start=True,outer_cleanup=True,fault='outer-fsync')
ns=extract(ROOT/'candidate/run_component_root_once.py',BIND['candidate_sha256'])
for label,timeout in [('nan',float('nan')),('inf',float('inf')),('zero',0),('bool',True),('negative',-1)]:
 obj=ns['Chain']();obj.out=EVIDENCE/('invalid-'+label);obj.out.mkdir();obj.steps=[]
 try:obj.execute_process('invalid',[sys.executable,'-c','pass'],timeout)
 except ValueError:assert not list(obj.out.iterdir())
 else:raise AssertionError('invalid timeout started')
 RESULTS.append({'case':'invalid-budget-'+label,'pass':True,'start_calls':0})
summary={'schema':'razr60.r8-transport-public-projection-local-raw-tests.v1','candidate':BIND,'passed':len(RESULTS),'failed':0,'cases':RESULTS,'host_platform':sys.platform,'python_version':sys.version,'harness_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'fd_check':{'directory':FD_DIRECTORY,'inventory_method':'numeric entries verified live using os.fstat; transient directory fd excluded','closed_stream_assertions':True,'raw_fd_ebadf_assertions':True,'candidate_live_fd_set_equality':True,'unsupported_inventory':'fail before first child, no skipped checks'},'scope':'AST-extracted exact helpers, execute_process, close_owned_host_outputs and actual sender join segment; real OS subprocesses/files; no main/SSH/device/API or signals','phone_calls':0,'production_mutations':0,'all_local_children_naturally_joined':True}
(EVIDENCE/'TEST-RESULT.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps({'passed':len(RESULTS),'failed':0,'candidate_sha256':BIND['candidate_sha256'],'harness_sha256':summary['harness_sha256'],'fd_directory':FD_DIRECTORY,'raw_results_excluded_from_publication':True},indent=2))
