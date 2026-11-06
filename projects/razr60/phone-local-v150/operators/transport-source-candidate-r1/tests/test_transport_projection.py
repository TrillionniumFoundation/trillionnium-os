#!/usr/bin/env python3
"""Reproduce the transport defects and repair on synthetic local Unix children.

Only exact helper/method ASTs are executed. No operational constants, main,
phone/SSH/model/policy source, private plan, or real task is loaded. Temporary
fixtures are deleted only after every locally started test child is joined.
"""
import ast, errno, hashlib, json, os, re, stat, subprocess, sys, tempfile, time, types
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SOURCES={
 'reference/run_component_root_once.r4.BASELINE.PUBLIC.py':'3359e542d1335bd786c7938197c1aaba007ad8c3ad8c141083bd7febc52ef604',
 'source/run_component_root_once.r4.transport_fixed.PUBLIC.py':'cd1b372cb5ccd058d32fa870fe418b05f2c138ba41ca23de6f7f4a45fa853478',
 'reference/run_runtime_properties_policy_once.BASELINE.PUBLIC.py':'7b8c32c8092b34528b44dd15e214703a52cdf47a82b18546b2ed9e3946961c27',
 'source/run_runtime_properties_policy_once.PUBLIC.py':'358c5541b4717c6cc02d2f500b4c274c0a4d3cae647ccdbf7a780636160229fb'}
HELPERS={'need','sha','enc','desc','read','put','syncdir','newdir','original_stream','finish_stream','close_streams_owned'}
RESULTS=[]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def source(name):
 raw=(ROOT/name).read_bytes();assert sha(raw)==SOURCES[name],name
 return raw

def extract(name):
 tree=ast.parse(source(name));cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Chain')
 helpers=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in HELPERS]
 methods=[n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name in ('execute_process','close_owned_host_outputs')]
 unit=ast.fix_missing_locations(ast.Module(body=helpers+[ast.ClassDef(name='Chain',bases=[],keywords=[],body=methods,decorator_list=[])],type_ignores=[]))
 ns={'hashlib':hashlib,'json':json,'os':os,'Path':Path,'re':re,'stat':stat,'subprocess':subprocess,'time':time}
 exec(compile(unit,name,'exec'),ns)
 assert 'main' not in ns and 'SSH' not in ns
 return ns

def fd_count():
 return len(os.listdir('/proc/self/fd')) if Path('/proc/self/fd').is_dir() else None

def process_case(name,code,original=False,timeout=.08,fault=None):
 rel='reference/run_component_root_once.r4.BASELINE.PUBLIC.py' if original else 'source/run_component_root_once.r4.transport_fixed.PUBLIC.py'
 ns=extract(rel);children=[];streams=[];start_count=0
 real_stream=ns['original_stream'];real_put=ns['put']
 with tempfile.TemporaryDirectory(prefix='transport-public-fixture-') as temp:
  out=Path(temp).resolve();obj=ns['Chain'].__new__(ns['Chain']);obj.out=out;obj.steps=[]
  def spawn(*args,**kw):
   nonlocal start_count
   start_count+=1;child=subprocess.Popen(*args,**kw);children.append(child);return child
  ns['subprocess']=types.SimpleNamespace(Popen=spawn,PIPE=subprocess.PIPE,DEVNULL=subprocess.DEVNULL,TimeoutExpired=subprocess.TimeoutExpired)
  def stream(path):
   result=real_stream(path);streams.append(result);return result
  ns['original_stream']=stream
  def put(path,raw):
   if fault=='child-record' and path.name=='CHILD.json':raise OSError(errno.EIO,'synthetic child-record failure')
   return real_put(path,raw)
  ns['put']=put
  before=fd_count();started=time.monotonic();error=None;value=None;payload=b'x'*(2*1024*1024)
  try:value=obj.execute_process('fixture',[sys.executable,'-I','-B','-c',code],timeout,payload)
  except BaseException as err:error=err
  elapsed=time.monotonic()-started
  phase=out/'fixture';records={n:(phase/n).exists() for n in ['CHILD.json','UNKNOWN.json','RESULT.json']}
  closed_before_harness_cleanup=all(s.closed for s in streams)
  # Retain the original failing observations before cleaning only test children.
  if original:
   assert isinstance(error,BrokenPipeError) and not records['CHILD.json'] and not records['UNKNOWN.json']
   if name=='original-nonreader':assert elapsed>=.5
  elif name=='fixed-nonreader':
   assert isinstance(error,RuntimeError) and records['CHILD.json'] and records['UNKNOWN.json'] and not records['RESULT.json']
   assert elapsed<.5 and obj._owned_host_children['fixture'] is children[0] and closed_before_harness_cleanup
  elif fault=='child-record':
   assert isinstance(error,OSError) and records['UNKNOWN.json'] and not records['RESULT.json'] and closed_before_harness_cleanup
   cleanup=obj.close_owned_host_outputs();assert len(cleanup['host_children'])==1
  else:
   assert error is None and records['CHILD.json'] and records['RESULT.json'] and closed_before_harness_cleanup,(name,error)
   if name=='fixed-readback':assert value.strip()==str(len(payload)).encode()
  assert start_count==1
  for child in children:
   child.wait(timeout=3)
   if child.stdin is not None:
    try:child.stdin.close()
    except BrokenPipeError:pass
  for stream in streams:
   if not stream.closed:stream.close()
  after=fd_count()
  if before is not None:assert before==after
  RESULTS.append({'case':name,'pass':True,'classification':'original_defect_reproduced' if original else 'candidate_local_regression',
   'source_sha256':SOURCES[rel],'input_bytes':len(payload),'budget_seconds':timeout,
   'elapsed_seconds':round(elapsed,6),'exception_type':type(error).__name__ if error else None,
   'records_at_return':records,'parent_streams_closed_before_harness_cleanup':closed_before_harness_cleanup,
   'process_starts':start_count,'all_test_children_naturally_joined':True,
   'fd_baseline_restored':None if before is None else before==after,'signals':0,'automatic_replays':0})

process_case('original-nonreader','import time; time.sleep(.6)',original=True)
process_case('original-earlyexit','raise SystemExit(0)',original=True)
process_case('fixed-nonreader','import time; time.sleep(.6)')
process_case('fixed-earlyexit','raise SystemExit(0)',timeout=.25)
process_case('fixed-readback','import sys; print(len(sys.stdin.buffer.read()))',timeout=1)
process_case('fixed-child-record-error','import time; time.sleep(.2)',timeout=1,fault='child-record')

# Delta artifacts reconstruct exactly the public projections, not the private
# originals. Each application occurs only in a disposable local fixture.
for baseline,target,patch,filename in [
 ('reference/run_component_root_once.r4.BASELINE.PUBLIC.py','source/run_component_root_once.r4.transport_fixed.PUBLIC.py','changes/r4-transport.PUBLIC.patch','run_component_root_once.py'),
 ('reference/run_runtime_properties_policy_once.BASELINE.PUBLIC.py','source/run_runtime_properties_policy_once.PUBLIC.py','changes/policy-driver.PUBLIC.patch','run_runtime_properties_policy_once.py')]:
 with tempfile.TemporaryDirectory(prefix='transport-public-delta-') as temp:
  directory=Path(temp).resolve();(directory/filename).write_bytes(source(baseline))
  for extra in [['--check'],[]]:
   process=subprocess.run(['git','apply','--no-index',*extra,str(ROOT/patch)],cwd=directory,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   assert process.returncode==0,process.stderr.decode()
  assert (directory/filename).read_bytes()==source(target)
 RESULTS.append({'case':'public-delta-'+filename,'pass':True,'classification':'public_projection_delta','target_sha256':SOURCES[target]})

for rel in SOURCES:
 process=subprocess.run([sys.executable,'-I','-B',str(ROOT/rel)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
 assert process.returncode!=0 and process.stdout==b'' and b'PUBLIC_SOURCE_PROJECTION_REVIEW_ONLY_NOT_INSTALLABLE' in process.stderr
 RESULTS.append({'case':'direct-entry-refuses-'+Path(rel).name,'pass':True,'classification':'noninstallable_public_projection'})
print(json.dumps({'schema':'hepta.transport-public-local-fixture-results.v1','passed':len(RESULTS),'failed':0,
 'cases':RESULTS,'original_defects_reproduced':2,'fixed_transport_process_cases':4,'public_patch_roundtrips':2,'direct_entry_refusals':4,
 'scope':'synthetic local Unix children and public source projections only','phone_calls':0,'model_requests':0,'policy_operations':0,
 'native_task_sends':0,'business_qualification':False,'fixed19_qualification':False},indent=2,sort_keys=True))
