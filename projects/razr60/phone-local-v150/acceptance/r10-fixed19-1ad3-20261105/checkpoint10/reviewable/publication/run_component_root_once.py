"""Root-only one-identity orchestration of the frozen native-guard package.

Default is a host preview. No nonce is generated. The 600-second lease is
fixed only after explicit execution starts. Any unknown/failure stops without
replay, extension, second Send, or signalling an unknown process.
"""
import argparse
import ast
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import selectors
import threading
import stat
import subprocess
import sys
import tarfile
import time
import types
B=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
G='/var/lib/trillionnium/owner-open/phone-local-v150'
N='/data/trillionnium/owner-open/state/phone-local-v150'
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
PKG='a33474b4479b8bb47acb6407525e30e82151e9f4b83dc0081851051003b144d7'  
COMBINATION='54b1d9aef4c16ebc0989b3e13345238bfbd4e400e5bfc9a97e27648a2385057e'
VERIFIER_SHA='74f4c89b32b36b074971b247de1951962b45384ef821330b94656d144e512152'
VERIFIER_BYTES=126796
POLICY_SHA='f8219f9c3ad2e1d16a95fda8d5f0bc7612a31e00c0a661e53bf9a6e921c49d70'
ADOPTION_SHA='527374778e62717d837d546cfa56bd144c8415b52006a9be4a33935c8592d08a'
ROOT_SCOPE_SHA='5a08041da77eeec9168c869ae76adae0a117a5e34872aa07a1a096bc06a36132'
SENDER='aafd40345c6dc35b7b7d34ab8b04c860ebf17d326d842ed733d0404cd0a051ad'
READY_HELPER='f3b83e55a07edd370946c40cec8694f310c9713082604646d264b625e7314d99'
ACTOR='179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'
RET='e3c8411f3d85440018392597d4f9f8795cfd7a60c44fc1680068a60949d20999'
SHARED='121416839ffdac15485270cda0e95445e376b0a24801fa283659a3da084ae45f'
CONFIG='780754928709871d3e70f432acb6a021c6c97ab822aaf7c32c887c132cac8c34'
SERVICE='2739a0af53650363e065bb71a448481998c68fc8b8632e61262c319dae6b586a'
MATERIAL_ROOT=B/'r10-boundary-consumers-material-r1/actual-material-01'
SSH=['ssh','-J','ai395-usb4','-o','HostName=10.77.0.4','-p','22','-o','BatchMode=yes',
'-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','pocket4-usb4-fast','/usr/bin/python3','-I','-B','-']
ENV='/data/adb/magisk/busybox env -i PATH=/usr/bin:/bin:/usr/libexec/trillionnium PYTHONHOME=/usr PYTHONDONTWRITEBYTECODE=1 LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu LANG=C.UTF-8 LC_ALL=C.UTF-8 TMPDIR=/var/lib/trillionnium/owner-open/tmp NO_COLOR=1 TERM=dumb /data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root '
HERE=Path(__file__).resolve().parent
def need(v,s):
 if not v:raise ValueError(s)
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def strict(b):
 def pairs(v):
  d={}
  for k,x in v:need(k not in d,'duplicate JSON key');d[k]=x
  return d
 return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def desc(p,b):return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
def read(p,n=64*1024*1024):
 p=Path(p);need(p.is_absolute() and p.resolve(strict=True)==p,'canonical original')
 fd=os.open(p,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=n,'bounded regular original')
  with os.fdopen(fd,'rb',closefd=False) as f:b=f.read(n+1)
  z=os.fstat(fd);s=p.lstat();keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
  need(len(b)==a.st_size and all(getattr(a,k)==getattr(z,k)==getattr(s,k) for k in keys),'changed original')
 finally:os.close(fd)
 return b
def pin(row):
 need(isinstance(row,dict) and set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int
 and row['bytes']>=0 and re.fullmatch('[0-9a-f]{64}',row['sha256']),'exact original descriptor')
 b=read(row['path']);need(len(b)==row['bytes'] and sha(b)==row['sha256'],'original pin');return b
def put(p,b):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 syncdir(p.parent)
def syncdir(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:os.fsync(fd)
 finally:os.close(fd)
def newdir(p):
 p.mkdir(mode=0o700);syncdir(p);syncdir(p.parent)
def original_stream(p):
 fd=os.open(p,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  os.fsync(fd);syncdir(p.parent);return os.fdopen(fd,'w+b')
 except BaseException:
  os.close(fd);raise
def close_streams_owned(streams):
 errors=[]
 for label,stream in streams:
  if stream is None or stream.closed:continue
  try:stream.flush();os.fsync(stream.fileno())
  except BaseException as error:
   errors.append({'stream':label,'operation':'flush_fsync','error_type':type(error).__name__})
  finally:
   try:stream.close()
   except BaseException as error:
    errors.append({'stream':label,'operation':'close','error_type':type(error).__name__})
 return errors
def finish_stream(stream):
 errors=close_streams_owned([('output',stream)])
 need(not errors,'stream finalization failed: '+repr(errors))
def filedesc(p):return desc(p,read(p))
HOST_OUTPUT_LIMIT=64*1024*1024
HOST_CAPTURE_POLL=0.025
HOST_CAPTURE_STOP_WAIT=1.0
def capture_stat(value):
 return {key:getattr(value,key) for key in ('st_dev','st_ino','st_mode','st_uid','st_gid',
 'st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
def close_unclaimed_capture_readers(capture):
 with capture['reader_lock']:
  if capture['reader_owner']!='caller':return False
  capture['reader_owner']='closed_by_caller'
  for reader in capture['readers'].values():
   try:
    if not reader.closed:reader.close()
   except BaseException as error:capture['pipe_close_errors'].append(type(error).__name__)
 return True
def capture_output_worker(capture):
 selector=None;owns_readers=False
 try:
  capture['worker_started']=True
  with capture['reader_lock']:
   if capture['reader_owner']!='caller':
    capture['error']={'code':'CAPTURE_STOP_REQUESTED','error_type':'InterruptedError'};return
   capture['reader_owner']='worker';owns_readers=True
  if capture['stop'].is_set():
   capture['error']={'code':'CAPTURE_STOP_REQUESTED','error_type':'InterruptedError'};return
  selector=selectors.DefaultSelector()
  for label,reader in capture['readers'].items():
   os.set_blocking(reader.fileno(),False)
   selector.register(reader,selectors.EVENT_READ,label)
  while selector.get_map():
   if capture['stop'].is_set():
    capture['error']={'code':'CAPTURE_STOP_REQUESTED','error_type':'InterruptedError'};break
   remaining=capture['deadline']-time.monotonic()
   if remaining<=0:
    capture['error']={'code':'OUTPUT_EOF_DEADLINE_EXCEEDED','error_type':'TimeoutError'};break
   events=selector.select(min(HOST_CAPTURE_POLL,remaining))
   for key,_events in events:
    if capture['stop'].is_set():break
    label=key.data;room=HOST_OUTPUT_LIMIT-capture['bytes'][label]
    try:chunk=os.read(key.fd,min(65536,room+1))
    except BlockingIOError:continue
    if not chunk:
     capture['eof'][label]=True;capture['eof_at'][label]=time.monotonic()
     selector.unregister(key.fileobj);key.fileobj.close();continue
    accepted=chunk[:room]
    if accepted:
     capture['chunks'][label].append(accepted)
     capture['digests'][label].update(accepted);capture['bytes'][label]+=len(accepted)
    if len(chunk)>room:
     capture['error']={'code':'OUTPUT_LIMIT_EXCEEDED','stream':label,
     'limit_bytes':HOST_OUTPUT_LIMIT,'error_type':'ValueError'};break
   if capture['error'] is not None:break
  if all(capture['eof'].values()) and time.monotonic()>capture['deadline']:
   capture['error']={'code':'OUTPUT_EOF_DEADLINE_EXCEEDED','error_type':'TimeoutError'}
 except BaseException as error:
  capture['error']={'code':'OUTPUT_CAPTURE_FAILED','error_type':type(error).__name__,
  'detail':str(error)[:256]}
 finally:
  if selector is not None:
   try:selector.close()
   except BaseException as error:capture['pipe_close_errors'].append(type(error).__name__)
  if owns_readers:
   for reader in capture['readers'].values():
    try:
     if not reader.closed:reader.close()
    except BaseException as error:capture['pipe_close_errors'].append(type(error).__name__)
   with capture['reader_lock']:capture['reader_owner']='closed_by_worker'
  capture['done'].set()
def write_captured_output(stream,path,initial,chunks,count,expected_sha256):
 fd=stream.fileno();held=os.fstat(fd)
 need(stat.S_ISREG(held.st_mode) and held.st_uid==os.geteuid()
 and stat.S_IMODE(held.st_mode)==0o600 and held.st_nlink==1,'private held capture output required')
 need(capture_stat(held)==initial==capture_stat(Path(path).lstat()),'original output inode or content changed')
 os.lseek(fd,0,os.SEEK_SET)
 for chunk in chunks:
  pending=memoryview(chunk)
  while pending:
   wrote=os.write(fd,pending);need(wrote>0,'capture output write made no progress');pending=pending[wrote:]
 stream.flush();os.fsync(fd)
 before=capture_stat(os.fstat(fd));need(before['st_size']==count,'capture output size differs')
 need(before==capture_stat(Path(path).lstat()),'capture output path replaced during write')
 os.lseek(fd,0,os.SEEK_SET);digest=hashlib.sha256();total=0
 while total<=count:
  data=os.read(fd,min(65536,count+1-total))
  if not data:break
  total+=len(data);digest.update(data)
 need(total==count and digest.hexdigest()==expected_sha256,'held output bytes differ from captured pipe')
 need(before==capture_stat(os.fstat(fd))==capture_stat(Path(path).lstat()),
 'held output or path changed during verification')
 return {'path':str(path),'bytes':count,'sha256':expected_sha256,'metadata':before}
def capture_observation(capture):
 joined=capture['worker_joined']
 return {'schema':'hepta.native-guard.host-output-capture.v1','phase':capture['phase'],
 'pid':capture['child'].pid,'source_intent_sha256':capture['source_intent_sha256'],
 'output_limit_bytes_per_stream':HOST_OUTPUT_LIMIT,
 'worker_started':capture['worker_started'],'worker_joined':joined,'pipe_reader_owner':capture['reader_owner'],
 'child_wait_returned':capture['child_wait_returned'],'child_returncode':capture['child'].returncode,
 'child_join_observed_monotonic':capture['child_join_at'],
 'execution_deadline_monotonic':capture['deadline'],'deadline_validity':'this_running_coordinator_only',
 'stdout_eof':capture['eof']['stdout'],'stderr_eof':capture['eof']['stderr'],
 'eof_observed_monotonic':dict(capture['eof_at']),
 'prefix_only_or_unknown':not capture['qualified_capture'],
 'captured':{label:{'bytes':capture['bytes'][label],
 'sha256':capture['digests'][label].hexdigest() if joined else None} for label in ('stdout','stderr')},
 'files':capture['files'],'error':capture['error'],'persist_errors':capture['persist_errors'],
 'pipe_close_errors':capture['pipe_close_errors'],'automatic_retry':False,'signals_sent':0,
 'remote_terminal_or_cleanup_proven':False}
REMOTE_IO='''from pathlib import Path
import base64,hashlib,json,os,stat,subprocess
os.umask(0o077)
def enc(v):return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\\n').encode()
def syncdir(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:os.fsync(fd)
 finally:os.close(fd)
def newdir(p):
 p.mkdir(mode=0o700);syncdir(p);syncdir(p.parent)
def put(p,b):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 syncdir(p.parent)
def stream(p):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 os.fsync(fd);syncdir(p.parent);return os.fdopen(fd,'wb')
def finish(f):f.flush();os.fsync(f.fileno());f.close()
def private_dir(p,create=False):
 if create:
  try:newdir(p)
  except FileExistsError:pass
 s=p.lstat();assert p.resolve(strict=True)==p and stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700
def parents(root,relative):
 p=root;private_dir(p)
 for part in relative.parts:
  assert part not in ('','..','.');p=p/part;private_dir(p,True)
 return p
'''
def validate_adoption(adoption,expected_live_sha256,adoption_raw):
 need(isinstance(VERIFIER_SHA,str) and re.fullmatch('[0-9a-f]{64}',VERIFIER_SHA)
 and type(VERIFIER_BYTES) is int and 0<VERIFIER_BYTES<=131072
 and all(isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value)
 for value in (POLICY_SHA,ADOPTION_SHA,ROOT_SCOPE_SHA)),
 'new policy adoption verifier is not frozen')
 need(expected_live_sha256==POLICY_SHA
 and isinstance(expected_live_sha256,str) and re.fullmatch('[0-9a-f]{64}',expected_live_sha256)
 and expected_live_sha256 not in ('bfe7acc92ba8c5b7a3a1c2360d6faf53f804a19c3e25e20aad336e3220fa0e38',
 '296b09d9c844d2916b0dbdb0765c71cbcb8411790b58f5823798aa872205b659',
 '50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7','0'*64),
 'explicit adopted property-policy hash required')
 need(strict(adoption_raw)==adoption,'new adoption must be its exact supplied original')
 path=HERE.parent/'reference/policy_native5_verifier.py';raw=read(path,131072)
 need(len(raw)==VERIFIER_BYTES and sha(raw)==VERIFIER_SHA,'new policy verifier source differs')
 module=types.ModuleType('exact_root_native5_policy_verifier');module.__file__=str(path)
 module.__reviewed_source_sha256__=sha(raw)
 exec(compile(raw,str(path),'exec'),module.__dict__)
 state=module.verify_adoption(adoption_raw,read_pinned=pin)
 need(state['current_adoption_sha256']==sha(adoption_raw)==ADOPTION_SHA
 and state['parent_adoption_sha256']=='a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5'
 and state['root_scope_decision_sha256']==ROOT_SCOPE_SHA
 and state['prior_boundary_sha256']=='eca941303197228ebe03561e612bfe41eb0518c590ff21253444db25a11adc10',
 'new adoption original, parent, scope or actual08 transition differs')
 actual=pin(adoption['actual_export'])
 need(state['runtime_policy']=={'bytes':len(actual),'sha256':sha(actual)}
 and sha(actual)==expected_live_sha256,'complete explicit property-policy adoption recheck differs')
 return state['runtime_policy']
def validate_sender_marker(marker,contract_raw,prepared,owner_sha,nonce,provider_sha):
 need(marker['schema']=='hepta.native-guard.sender-prepared.v1' and marker['state']=='PREPARED_NO_SEND'
 and type(marker['send_attempt_count']) is int and marker['send_attempt_count']==0 and marker['provider_started_by_sender'] is False,
 'only the actual no-Send rendezvous admits one launch')
 need(marker['nonce']==nonce and marker['owner_request_sha256']==owner_sha
 and marker['contract_sha256']==sha(contract_raw)==prepared['sender_contract_sha256']
 and marker['provider_source_sha256']==provider_sha,'original sender prepared identity differs')
def prior_reader(runtime,manifest):
 package_sources={}
 for row in manifest['files']:
  raw=read(runtime/row['path'])
  need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'prior reader complete package pin')
  need(row['path'] not in package_sources,'duplicate prior reader package member')
  package_sources[row['path']]=raw
 saved=sys.modules.get('component_common');old_path=list(sys.path);old_dwb=sys.dont_write_bytecode
 try:
  sys.dont_write_bytecode=True
  loaded={}
  for name in ('component_common','late_boundary'):
   rel='source/'+name+'.py';rows=[r for r in manifest['files'] if r['path']==rel]
   need(len(rows)==1,'single reviewed prior-reader source required')
   raw=package_sources[rel];row=rows[0]
   need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'reviewed prior-reader bytes changed')
   mod=types.ModuleType(name);mod.__file__=str(runtime/rel)
   if name=='component_common':sys.modules[name]=mod
   else:
    mod.__reviewed_source_sha256__=sha(raw)
    mod.__reviewed_package_sources__=package_sources
   exec(compile(raw,mod.__file__,'exec'),mod.__dict__);loaded[name]=mod
  return loaded['late_boundary']
 finally:
  if saved is None:sys.modules.pop('component_common',None)
  else:sys.modules['component_common']=saved
  sys.path[:]=old_path;sys.dont_write_bytecode=old_dwb
def validate_current_prior(p,previous,runtime,manifest):
 need(p['prior_boundary_descriptor'] is not None and p['prior_boundary_original'] is not None,
 'current policy generation must retain its actual closed predecessor')
 prior=strict(pin(p['prior_boundary_descriptor']));original=pin(p['prior_boundary_original'])
 need(sha(original)==prior['sha256'] and len(original)==prior['bytes'],'explicit prior boundary original')
 reader=prior_reader(runtime,manifest)
 boundary=reader.boundary_from_original(original,original_descriptor=prior,
 combination_sha256=COMBINATION,package_sha256=PKG)
 need(boundary['nonce']!=p['nonce'] and boundary['scope']==previous['identity']
 and previous.get('known_all_dispatched_tools_confirmed_terminal') is True,
 'new component must use its actual terminal predecessor native scope')
 need(boundary['schema']==reader.SCHEMA,
 'historical03/04 cannot replace the already published actual08 predecessor')
 need(not reader.is_pre_policy_ancestor(boundary)
 and not reader.is_environment_parent_ancestor(boundary),
 'R8 cannot bypass the exact closed actual08 property-policy predecessor')
 parent=reader.is_property_parent_ancestor(boundary)
 if parent:
  need(p['case_id']=='NEG-01' and prior==reader.reviewed_property_parent_ancestors()[0]['boundary']
  and p['previous']['bytes']==1428
  and p['previous']['sha256']=='9133e2511a66a809be647cb8bb49e3afb351825db5e465f75b1f2f0b6d9d88f4',
  'the new generation must enter through the exact closed actual08 native predecessor; actual07 cannot substitute')
 else:
  need(boundary['package_sha256']==PKG and boundary['combination_sha256']==COMBINATION,
  'current predecessor has a different package or policy generation')
 closed_row=previous.get('closed_component')
 need(isinstance(closed_row,dict) and type(closed_row.get('bytes')) is int
 and 0<closed_row['bytes']<=16*1024*1024,
 'predecessor needs its bounded original host closure')
 home=Path(p['prior_boundary_original']['path']).parent
 need(Path(p['prior_boundary_original']['path'])==home/'LATE-BOUNDARY.original.json'
 and Path(closed_row.get('path',''))==home/'CLOSURE.json',
 'predecessor closure and boundary must be the same standard closed case')
 if parent:
  need(home==B/'native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08',
  'actual08 originals must retain their original Root namespace')
 closed_raw=pin(closed_row);inventory_row=boundary['inventory']
 need(type(inventory_row['bytes']) is int and 0<inventory_row['bytes']<=16*1024*1024,
 'predecessor needs its bounded cumulative inventory')
 inventory_raw=read(home/'INVENTORY.json',inventory_row['bytes'])
 verified,_inventory,closed=reader.closed_boundary_originals(
 original,inventory_raw,closed_raw,original_descriptor=prior,
 combination_sha256=COMBINATION,package_sha256=PKG)
 need(verified==boundary and boundary['prior_boundary'] is not None,
 'predecessor must retain the exact complete prior chain')
 closers=[row for row in manifest['files'] if row['path']=='source/close_component.py']
 need(len(closers)==1 and re.fullmatch('[0-9a-f]{64}',closers[0]['sha256']),
 'current package must contain one explicit closure source')
 expected_closer=reader.PROPERTY_PARENT_CLOSURE_SHA256 if parent else closers[0]['sha256']
 need(closed.get('closure_source_sha256')==expected_closer,
 'predecessor closure origin differs from its executed generation')
 need(previous.get('late_boundary')==prior
 and previous.get('component_qualified') is boundary['component_qualified']
 and isinstance(previous.get('terminal'),dict)
 and previous['terminal'].get('status')==boundary['native_status'],
 'previous native terminal or qualification differs from the published closure')
 failed=(closed['state']=='ORIGINAL_NATIVE_COMPONENT_FAILED_CLOSED'
 and closed['component_qualified'] is False
 and closed['native_status'] in ('provider_failed','cancelled')
 and type(closed['unknown_effects']) is int and closed['unknown_effects']==0)
 passed=(closed['state']=='ORIGINAL_NATIVE_COMPONENT_CLOSED'
 and closed['component_qualified'] is True and closed['native_status']=='completed')
 need((p['case_id']==boundary['case_id'] and failed)
 or (not parent and boundary['case_id']=='NEG-01' and p['case_id']=='NEG-02' and passed),
 'only a closed unqualified same-case failure or current qualified NEG01-to-NEG02 progression is allowed')
 need(pin(closed_row)==closed_raw
 and read(home/'INVENTORY.json',inventory_row['bytes'])==inventory_raw
 and pin(p['prior_boundary_original'])==original
 and strict(pin(p['prior_boundary_descriptor']))==prior,
 'predecessor originals changed during host admission')
 need(boundary['boot_id']==p['boot_id']
 and boundary['retirement']==strict(pin(p['retirement_descriptor']))['files'],
 'component predecessor boot or actual retirement differs')
def validate_plan(raw):
 need(isinstance(PKG,str) and re.fullmatch('[0-9a-f]{64}',PKG)
 and isinstance(COMBINATION,str) and re.fullmatch('[0-9a-f]{64}',COMBINATION)
 and all(isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value)
 for value in (POLICY_SHA,ADOPTION_SHA,ROOT_SCOPE_SHA,VERIFIER_SHA))
 and type(VERIFIER_BYTES) is int and 0<VERIFIER_BYTES<=131072,
 'new policy runtime and current combination are not frozen')
 p=strict(raw)
 required={'schema','label','case_id','nonce','boot_id','session_id','profile_id','request','previous','preserved_draft',
 'sender_retirement_resolution','package','shared_materials','shared_root','artifacts','policy_adoption','live_policy_sha256',
 'retirement_descriptor','retirement_originals','prior_boundary_descriptor','prior_boundary_original','source_package','out'}
 need(set(p)==required and p['schema']=='hepta.native-guard.root-chain-plan.v1','exact Root orchestration plan')
 need(re.fullmatch('[a-z0-9][a-z0-9-]{5,35}',p['label']) and p['case_id'] in ('NEG-01','NEG-02')
 and re.fullmatch('[0-9a-f]{32}',p['nonce']) and p['boot_id']==BOOT,'explicit new Root identity')
 need(p['package']['sha256']==PKG and p['retirement_descriptor']['sha256']==RET,'frozen package/actual retirement')
 source_package=strict(pin(p['source_package']))
 need(source_package['schema']=='hepta.native-guard.root-chain-source-package.v1'
 and Path(p['source_package']['path']).parent==HERE.parent
 and {r['path'] for r in source_package['files']}=={'source/phone_chain_bridge.py','source/run_component_root_once.py',
 'reference/policy_native5_verifier.py'}
 and len(source_package['files'])==3,'explicit reviewed coordinator source package required')
 for row in source_package['files']:
  b=read(HERE.parent/row['path']);need(len(b)==row['bytes'] and sha(b)==row['sha256'],'coordinator source pin')
 owner=pin(p['request']);need(20<=len(owner)<=16000 and owner.decode().count(p['nonce'])==1 and b'\0' not in owner,'exact owner nonce binding')
 previous=strict(pin(p['previous']));need(previous['identity']['session_id']==p['session_id']
 and previous['identity']['profile_id']==p['profile_id'],'actual selected previous session/profile')
 draft=strict(pin(p['preserved_draft']));d=base64.b64decode(draft['exact_utf8_b64'],validate=True)
 need(d and sha(d)==draft['utf8_sha256'] and d!=owner,'nonempty preserved draft')
 manifest=strict(pin(p['package']));need(manifest['schema']=='hepta.native-guard.adapter-package.v1','package schema')
 runtime=Path(p['package']['path']).parent
 for row in manifest['files']:
  b=read(runtime/row['path']);need(len(b)==row['bytes'] and sha(b)==row['sha256'],'frozen package bytes')
 validate_current_prior(p,previous,runtime,manifest)
 for name,h in (('send_new_native_guard_task_r10_r4.py',SENDER),('sender_native_guard_ready_r10_r4.py',READY_HELPER)):
  need(sha(read(B/name))==h,'original B-root sender helper pin')
 pin(p['sender_retirement_resolution']);pin(p['artifacts']);pin(p['retirement_descriptor'])
 need(p['shared_materials']['sha256']==SHARED and p['shared_materials']['bytes']==3519
 and Path(p['shared_root'])==MATERIAL_ROOT,'actual same-builder shared production material required')
 shared=strict(pin(p['shared_materials']));rows=shared['files'];root=Path(p['shared_root'])
 need(shared['schema']=='hepta.r10.shared-production-materials.v1'
 and shared['state']=='HOST_SHARED_PRODUCTION_BYTES_NOT_INSTALLABLE'
 and shared['release_id']=='v150-r10-r1' and shared['production_source_count']==15
 and shared['phone_calls']==0 and shared['phone_qualification'] is False
 and shared['policy_adoption_inferred'] is False,'actual shared material state differs')
 reviewed=strict(read(runtime/'reference/REVIEWED-PRODUCTION-PINS.json'))
 expected={'provider/source/'+name for name in reviewed}|{'local-config-r10-r1.json','PHONE-SERVICE-INPUTS-v150-r10-r1.json'}
 need(len(rows)==17 and {r['path'] for r in rows}==expected,'complete same-builder shared material set')
 for row in rows:
  b=read(root/row['path']);need(len(b)==row['bytes'] and sha(b)==row['sha256'],'shared material exact bytes')
  if row['path'].startswith('provider/source/'):need(row['sha256']==reviewed[Path(row['path']).name],'actual 15 production source pins')
 need(sha(read(root/'local-config-r10-r1.json'))==CONFIG and sha(read(root/'PHONE-SERVICE-INPUTS-v150-r10-r1.json'))==SERVICE,
 'actual shared configuration/service bytes differ')
 adoption_raw=pin(p['policy_adoption']);validate_adoption(strict(adoption_raw),p['live_policy_sha256'],adoption_raw)
 out=Path(p['out']);need(out.parent==B/'native-guard-root-chains-r10-r1' and out.name==p['label'],'fixed new Root output namespace')
 return p,manifest
class Chain:
    def __init__(self,plan,raw):
        self.p=plan;self.out=Path(plan['out']);newdir(self.out)
        put(self.out/'ROOT-PLAN.original.json',raw)
        self.steps=[];self.sender=None;self.sender_files=None
        self.remote_root='/home/alex/codex-native-guard-chain-r10-r1/'+plan['nonce']
        self.material=None;self.lease=None;self.prepared=None;self.root_attempts=[]
        self.bridge=read(HERE/'phone_chain_bridge.py',65536)
        source_manifest=strict(pin(plan['source_package']))
        bridge_row=next(r for r in source_manifest['files'] if r['path']=='source/phone_chain_bridge.py')
        need(len(self.bridge)==bridge_row['bytes'] and sha(self.bridge)==bridge_row['sha256'],'reviewed bridge bytes changed')
        compile(self.bridge,'phone_chain_bridge.py','exec')
    def stop_host_capture(self,name,request_stop=True):
        capture=self.__dict__.setdefault('_owned_host_captures',{}).get(name)
        if capture is None:return []
        if request_stop:capture['stop'].set()
        worker=capture['thread'];errors=[]
        if worker is not None and capture['worker_start_requested'] and not capture['worker_start_failed_no_thread']:
            try:worker.join(timeout=HOST_CAPTURE_STOP_WAIT)
            except BaseException as error:
                # Close only readers the worker has never claimed. The entry
                # handshake makes a late-starting worker skip them safely.
                # A claimed reader remains worker-owned until a proven join.
                close_unclaimed_capture_readers(capture)
                return [{'phase':name,'operation':'capture_worker_join','error_type':type(error).__name__}]
            capture['worker_joined']=capture['done'].is_set() and not worker.is_alive()
            if not capture['worker_joined']:
                # Leave ownership and fds intact: closing/reusing a reader here
                # would race the still-owned worker. No success can follow.
                return [{'phase':name,'operation':'capture_worker_join','error_type':'TimeoutError'}]
        else:
            close_unclaimed_capture_readers(capture)
            capture['worker_joined']=True;capture['done'].set()
            if capture['error'] is None:capture['error']={'code':'CAPTURE_NOT_STARTED','error_type':'RuntimeError'}
        return errors

    def persist_host_capture(self,name):
        capture=self.__dict__.setdefault('_owned_host_captures',{}).get(name)
        if capture is None:return []
        if capture['persist_attempted']:return list(capture['persist_errors'])
        if not capture['worker_joined']:
            return [{'phase':name,'operation':'persist_unjoined_capture_refused','error_type':'RuntimeError'}]
        capture['persist_attempted']=True;errors=capture['persist_errors'];d=capture['directory']
        for label in ('stdout','stderr'):
            stream=capture['outputs'][label];path=d/(label+'.original')
            digest=capture['digests'][label].hexdigest()
            try:
                proof=write_captured_output(stream,path,capture['initial_outputs'][label],
                    capture['chunks'][label],capture['bytes'][label],digest)
                proof['original_created_inode_bound']=True;capture['files'][label]=proof
            except BaseException as error:
                errors.append({'stream':label,'operation':'persist_or_bind_output','error_type':type(error).__name__,
                    'detail':str(error)[:256]})
                # Keep actual captured bytes in a create-only evidence file even
                # when the original path was replaced or unlinked. It cannot be
                # consumed as a successful stdout/stderr descriptor.
                fallback=None
                try:
                    other=d/(label+'.captured-prefix.original');fallback=original_stream(other)
                    proof=write_captured_output(fallback,other,capture_stat(os.fstat(fallback.fileno())),
                        capture['chunks'][label],capture['bytes'][label],digest)
                    proof['original_created_inode_bound']=False;capture['files'][label]=proof
                except BaseException as other_error:
                    errors.append({'stream':label,'operation':'preserve_captured_prefix','error_type':type(other_error).__name__})
                finally:
                    if fallback is not None:errors.extend(close_streams_owned([(label+':captured-prefix',fallback)]))
        if capture['qualified_capture'] and time.monotonic()>capture['join_deadline']:
            errors.append({'phase':name,'operation':'output_persistence_after_deadline','error_type':'TimeoutError'})
        if errors:capture['qualified_capture']=False
        try:
            put(d/'OUTPUT-CAPTURE.json',enc(capture_observation(capture)))
            capture['receipt']=filedesc(d/'OUTPUT-CAPTURE.json')
        except BaseException as error:
            errors.append({'phase':name,'operation':'capture_record','error_type':type(error).__name__})
            capture['qualified_capture']=False
        return list(errors)

    def verify_host_capture_outputs(self,name):
        capture=self._owned_host_captures[name]
        need(capture['worker_joined'] and capture['qualified_capture'] and not capture['persist_errors'],
            'complete joined capture required')
        for label in ('stdout','stderr'):
            proof=capture['files'][label]
            need(proof['original_created_inode_bound'] is True
                and capture_stat(Path(proof['path']).lstat())==proof['metadata'],
                'original captured output path changed before result publication')
        need(time.monotonic()<=capture['join_deadline'],'host capture finalized after execution deadline')

    def join_host_capture(self,name,child,maximum_wait=None):
        capture=self._owned_host_captures[name]
        need(self._owned_host_children[name] is child and capture['child'] is child,
            'original host child handle differs')
        deadline=self._owned_host_deadlines[name]
        if maximum_wait is not None:
            need(type(maximum_wait) in (int,float) and 0<maximum_wait<float('inf'),'finite join wait required')
            deadline=min(deadline,time.monotonic()+maximum_wait)
        capture['join_deadline']=deadline
        while True:
            remaining=max(0.0,deadline-time.monotonic())
            try:rc=child.wait(timeout=min(0.05,remaining))
            except subprocess.TimeoutExpired:
                if time.monotonic()>=deadline:raise
                error=capture['error']
                if error is not None:
                    need(error['code']!='OUTPUT_EOF_DEADLINE_EXCEEDED','output capture deadline exhausted')
                    raise ValueError('host output capture failed: '+repr(error))
                continue
            capture['child_wait_returned']=True;capture['child_join_at']=time.monotonic();break
        need(time.monotonic()<=deadline,'host child joined after execution deadline')
        if not capture['done'].wait(timeout=max(0.0,deadline-time.monotonic())):
            raise subprocess.TimeoutExpired(child.args,max(0.0,deadline-capture['started']))
        cleanup=self.stop_host_capture(name,request_stop=False)
        need(not cleanup,'capture worker did not join: '+repr(cleanup))
        error=capture['error']
        if error is not None and error['code']=='OUTPUT_EOF_DEADLINE_EXCEEDED':
            raise subprocess.TimeoutExpired(child.args,max(0.0,deadline-capture['started']))
        need(error is None and all(capture['eof'].values()) and not capture['pipe_close_errors'],
            'host output capture incomplete: '+repr(error))
        need(time.monotonic()<=deadline,'host output EOF observed after execution deadline')
        capture['qualified_capture']=True
        errors=self.persist_host_capture(name)
        need(not errors,'host output persistence or identity failed: '+repr(errors))
        self.verify_host_capture_outputs(name)
        return rc

    def execute_process(self,name,argv,timeout,input_raw=None,async_start=False):
        need(re.fullmatch('[a-z0-9-]{1,55}',name),'phase name')
        need(type(timeout) in (int,float) and 0<timeout<float('inf'),'finite positive host execution budget')
        d=self.out/name;newdir(d)
        intent={'schema':'hepta.native-guard.root-host-command.v1','phase':name,'argv':argv,
            'stdin_sha256':None if input_raw is None else sha(input_raw),'maximum_starts':1,
            'maximum_wait_seconds':timeout,'automatic_retry':False,'signals_on_timeout':False,
            'deadline_scope':'popen_start_through_child_join_pipe_eof_and_output_verification',
            'input_transport':'retained_readonly_regular_fd_child_reads_within_execution_budget',
            'output_transport':'owned_nonblocking_pipe_capture_worker_bounded_memory_main_thread_persistence',
            'output_limit_bytes_per_stream':HOST_OUTPUT_LIMIT,'hard_bound_on_filesystem_spawn_or_cleanup':False}
        put(d/'INTENT.json',enc(intent))
        if input_raw is not None:put(d/'stdin.original',input_raw)
        stdin_file=stdout=stderr=child=capture=None
        group=session=None;wait_returned=False;result_recorded=False;cleanup_errors=[]
        stdin_metadata=None
        owners=self.__dict__.setdefault('_owned_host_children',{})
        deadlines=self.__dict__.setdefault('_owned_host_deadlines',{})
        streams=self.__dict__.setdefault('_owned_host_streams',{})
        captures=self.__dict__.setdefault('_owned_host_captures',{})

        def input_metadata(value):
            return tuple(getattr(value,key) for key in ('st_dev','st_ino','st_mode','st_uid','st_gid',
                'st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

        def pin_retained_input(fd,expected_metadata):
            held=os.fstat(fd)
            need(stat.S_ISREG(held.st_mode) and held.st_nlink==1 and held.st_size==len(input_raw)
                and held.st_uid==os.geteuid() and stat.S_IMODE(held.st_mode)==0o600,
                'retained stdin must be the private exact-size regular input')
            need(input_metadata(held)==expected_metadata==input_metadata((d/'stdin.original').lstat()),
                'retained stdin file identity changed')
            os.lseek(fd,0,os.SEEK_SET)
            digest=hashlib.sha256();total=0;remaining=len(input_raw)+1
            while remaining:
                chunk=os.read(fd,min(65536,remaining))
                if not chunk:break
                total+=len(chunk);remaining-=len(chunk);digest.update(chunk)
            need(total==len(input_raw) and digest.hexdigest()==intent['stdin_sha256'],
                'retained stdin content differs from original input')
            need(input_metadata(os.fstat(fd))==expected_metadata==input_metadata((d/'stdin.original').lstat()),
                'retained stdin changed during content pin')
            os.lseek(fd,0,os.SEEK_SET)

        def close_owned_streams():
            errors=[]
            if stdin_file is not None and not stdin_file.closed:
                try:stdin_file.close()
                except BaseException as error:errors.append({'stream':'stdin','operation':'close','error_type':type(error).__name__})
            errors.extend(close_streams_owned([('stdout',stdout),('stderr',stderr)]))
            return errors

        try:
            if input_raw is not None:
                stdin_metadata=input_metadata((d/'stdin.original').lstat())
                fd=os.open(d/'stdin.original',os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
                try:
                    pin_retained_input(fd,stdin_metadata);stdin_file=os.fdopen(fd,'rb')
                except BaseException:os.close(fd);raise
            stdout=original_stream(d/'stdout.original');stderr=original_stream(d/'stderr.original')
            initial_outputs={label:capture_stat(os.fstat(stream.fileno())) for label,stream in (('stdout',stdout),('stderr',stderr))}
            started=time.monotonic();deadline=started+float(timeout)
            child=subprocess.Popen(argv,stdin=stdin_file if stdin_file is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0,start_new_session=True,close_fds=True)
            owners[name]=child;deadlines[name]=deadline;streams[name]=(stdout,stderr)
            capture={'phase':name,'directory':d,'child':child,'source_intent_sha256':sha(enc(intent)),'started':started,'deadline':deadline,'join_deadline':deadline,
                'readers':{'stdout':child.stdout,'stderr':child.stderr},'outputs':{'stdout':stdout,'stderr':stderr},
                'initial_outputs':initial_outputs,'stop':threading.Event(),'done':threading.Event(),
                'reader_lock':threading.Lock(),'reader_owner':'caller',
                'thread':None,'worker_started':False,'worker_start_requested':False,
                'worker_start_failed_no_thread':False,'worker_joined':False,
                'chunks':{'stdout':[],'stderr':[]},'bytes':{'stdout':0,'stderr':0},
                'digests':{'stdout':hashlib.sha256(),'stderr':hashlib.sha256()},
                'eof':{'stdout':False,'stderr':False},'eof_at':{'stdout':None,'stderr':None},
                'child_wait_returned':False,'child_join_at':None,'error':None,'pipe_close_errors':[],
                'persist_attempted':False,'persist_errors':[],'files':{},'receipt':None,'qualified_capture':False}
            captures[name]=capture
            try:group,session=os.getpgid(child.pid),os.getsid(child.pid)
            except ProcessLookupError:
                need(child.poll() is not None,'host child identity unknown before wait');group=session=None
            put(d/'CHILD.json',enc({'pid':child.pid,'pgid':group,'sid':session,
                'source_intent_sha256':sha(enc(intent)),'maximum_starts':1,
                'execution_deadline_monotonic':deadline,'deadline_validity':'this_running_coordinator_only',
                'original_output_identities':initial_outputs,
                'identity_missing_only_if_actual_child_already_joined':group is None}))
            worker=threading.Thread(target=capture_output_worker,args=(capture,),
                name='hepta-host-capture-'+name+'-'+str(child.pid),daemon=False)
            capture['thread']=worker;capture['worker_start_requested']=True
            try:worker.start()
            except RuntimeError:
                # A newly constructed Thread can fail to create an OS thread.
                # No worker will later acquire these pipe readers in that case.
                if worker.ident is None:capture['worker_start_failed_no_thread']=True
                raise
            if async_start:
                need(time.monotonic()<deadline,'host async launch exceeded execution deadline')
                if stdin_file is not None:stdin_file.close()
                return child,d,stdout,stderr
            rc=self.join_host_capture(name,child);wait_returned=True
            if stdin_file is not None:pin_retained_input(stdin_file.fileno(),stdin_metadata)
            o=b''.join(capture['chunks']['stdout']);e=b''.join(capture['chunks']['stderr'])
            cleanup_errors+=close_owned_streams();streams.pop(name,None)
            need(not cleanup_errors,'owned host stream finalization failed: '+repr(cleanup_errors))
            self.verify_host_capture_outputs(name)
            result={'state':'ORIGINAL_HOST_CHILD_JOINED','phase':name,'pid':child.pid,'returncode':rc,
                'stdout':desc(d/'stdout.original',o),'stderr':desc(d/'stderr.original',e),'automatic_retry':False}
            put(d/'RESULT.json',enc(result));self.steps.append(result);result_recorded=True
            owners.pop(name,None);deadlines.pop(name,None);captures.pop(name,None)
            need(rc==0,'original phase failed; no replay: '+name)
            return o
        except BaseException as error:
            # Popen may have succeeded before capture construction/registration
            # failed. With no worker created, these are still caller-owned.
            if child is not None and (capture is None or capture['thread'] is None):
                for label,reader in (('stdout-pipe',child.stdout),('stderr-pipe',child.stderr)):
                    try:
                        if reader is not None and not reader.closed:reader.close()
                    except BaseException as close_error:
                        cleanup_errors.append({'stream':label,'operation':'close','error_type':type(close_error).__name__})
            cleanup_errors+=self.stop_host_capture(name)
            if capture is not None:
                capture['qualified_capture']=False
                cleanup_errors+=self.persist_host_capture(name)
                wait_returned=wait_returned or capture['child_wait_returned']
            cleanup_errors+=close_owned_streams();streams.pop(name,None)
            if child is not None and not result_recorded:
                failure={'state':'OWNED_HOST_CHILD_JOINED_PHASE_RECORD_FAILED' if child.returncode is not None
                    else 'OWNED_HOST_CHILD_NOT_JOINED_NO_SIGNAL_OR_RETRY',
                    'phase':name,'pid':child.pid,'pgid':group,'sid':session,
                    'source_intent_sha256':sha(enc(intent)),'child_wait_returned':wait_returned,
                    'child_returncode':child.returncode,'error_type':type(error).__name__,
                    'cleanup_errors':cleanup_errors,'automatic_retry':False,'signals_sent':0,
                    'output_capture':None if capture is None else capture_observation(capture)}
                self.steps.append(failure)
                try:put(d/'UNKNOWN.json',enc(failure))
                except BaseException as record_error:failure['unknown_record_error_type']=type(record_error).__name__
            if isinstance(error,subprocess.TimeoutExpired):raise RuntimeError('unknown original phase '+name) from error
            raise

    def close_owned_host_outputs(self):
        # Stopping our readers never establishes child/remote terminal cleanup.
        # Every worker is held until joined; captured prefixes remain unknown.
        errors=[]
        captures=self.__dict__.setdefault('_owned_host_captures',{})
        streams=self.__dict__.setdefault('_owned_host_streams',{})
        owners=self.__dict__.setdefault('_owned_host_children',{})
        for name,capture in list(captures.items()):
            capture['qualified_capture']=False
            errors.extend(self.stop_host_capture(name));errors.extend(self.persist_host_capture(name))
        for name,(stdout,stderr) in list(streams.items()):
            errors.extend(close_streams_owned([(name+':stdout',stdout),(name+':stderr',stderr)]));streams.pop(name,None)
        rows=[]
        for name,child in list(owners.items()):
            row={'phase':name,'pid':child.pid,'returncode':child.returncode,
                'state':'OWNED_HOST_CHILD_NOT_JOINED_NO_SIGNAL_OR_RETRY' if child.returncode is None
                    else 'OWNED_HOST_CHILD_JOINED_NO_BUSINESS_QUALIFICATION',
                'automatic_retry':False,'signals_sent':0,
                'output_capture':capture_observation(captures[name]) if name in captures else None}
            rows.append(row)
            try:put(self.out/name/'OWNED-CHILD-FAILURE.json',enc(row))
            except BaseException as error:row['record_error_type']=type(error).__name__
        return {'stream_cleanup_errors':errors,'host_children':rows}

    def remote(self,name,code,timeout=60):
        compile(code,'root_p4_'+name,'exec')
        raw=self.execute_process(name,SSH,timeout,code.encode())
        return strict(raw)
    def remote_files(self,name,files,create_root=False):
        payload={path:base64.b64encode(raw).decode() for path,raw in files.items()}
        pins={path:[len(raw),sha(raw)] for path,raw in files.items()}
        code=REMOTE_IO+"R=Path("+repr(self.remote_root)+")\n"
        if create_root:code+="private_dir(R.parent,True)\nnewdir(R)\n"
        code+="private_dir(R)\nfiles="+repr(payload)+"\npins="+repr(pins)+"\n"
        code+="for rel,data in files.items():\n p=Path(rel);assert not p.is_absolute() and '..' not in p.parts\n b=base64.b64decode(data,validate=True);assert [len(b),hashlib.sha256(b).hexdigest()]==pins[rel]\n parents(R,p.parent);q=R/p;put(q,b)\n assert q.read_bytes()==b\nprint(json.dumps({'state':'EXACT_NEW_HOST_FILES_WRITTEN','files':pins},sort_keys=True))\n"
        return self.remote(name,code,90)
    def remote_read(self,name,paths,wait_path=None,wait_seconds=0,prepared=False):
        code="from pathlib import Path\nimport base64,hashlib,json,os,stat,time\npaths="+repr(paths)+"\n"
        if wait_path:
            code+="p=Path("+repr(wait_path)+");deadline=time.monotonic()+"+repr(wait_seconds)+"\nwhile not p.exists():\n assert time.monotonic()<deadline,'one original wait expired'\n time.sleep(.1)\n"
        code+="rows={}\nfor key,path in paths.items():\n p=Path(path);assert p.resolve(strict=True)==p\n fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)\n with os.fdopen(fd,'rb') as f:\n  a=os.fstat(f.fileno());assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=16777216\n  b=f.read(16777217);z=os.fstat(f.fileno())\n assert len(b)==a.st_size and (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)\n rows[key]={'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'base64':base64.b64encode(b).decode()}\n"
        if prepared:
            code+="v=json.loads(base64.b64decode(rows['prepared']['base64']));assert v['state']=='PREPARED_NO_SEND' and v['send_attempt_count']==0 and v['provider_started_by_sender'] is False\nassert v['pre_send_deadline_monotonic_ns']-time.monotonic_ns()>40_000_000_000,'insufficient original sender margin'\n"
        code+="print(json.dumps({'state':'ORIGINAL_HOST_FILES_READ','files':rows},sort_keys=True))\n"
        return self.remote(name,code,wait_seconds+30)
    def remote_program(self,name,argv,timeout):
        code=REMOTE_IO+"R=Path("+repr(self.remote_root)+")\nD=R/"+repr(name)+"\nnewdir(D)\nargv="+repr(argv)+"\n"
        code+="put(D/'ARGV.json',enc(argv))\no=stream(D/'stdout.original');e=stream(D/'stderr.original');p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=o,stderr=e,start_new_session=True)\n"
        code+="try:rc=p.wait(timeout="+repr(timeout)+")\nexcept subprocess.TimeoutExpired:\n put(D/'UNKNOWN.json',enc({'pid':p.pid,'automatic_retry':False,'signals_sent':0}));raise\nfinally:finish(o);finish(e)\nr={'returncode':rc,'stdout':(D/'stdout.original').read_text(),'stderr':(D/'stderr.original').read_text(),'automatic_retry':False}\nput(D/'RESULT.json',enc(r))\nprint(json.dumps(r,sort_keys=True))\n"
        value=self.remote(name,code,timeout+30)
        need(value['returncode']==0,'actual P4 child failed; no replay: '+name)
        return value
    def phone(self,tag,req):
        need(req['kind'] in ('shell','push') and type(req['timeout_seconds']) is int and 0<req['timeout_seconds']<=300,'fixed phone actor bound')
        if req['kind']=='shell':
            need(req.get('root') is True,'explicit reviewed root shell request required')
            wire=('shell,v2,raw:/debug_ramdisk/su -c '+shlex.quote(req['command'])).encode()
            need(len(wire)<65536,'fixed ADB wire bound')
        label='ng-'+self.p['nonce']+'-'+tag
        need(re.fullmatch('[a-z0-9-]{1,70}',label),'fixed one-use phone label')
        code=REMOTE_IO+"B=Path('/home/alex/razr60-local-model-v150');a=B/'ops/phone_once.py'\nassert hashlib.sha256(a.read_bytes()).hexdigest()=="+repr(ACTOR)+"\nlabel="+repr(label)+"\nreq="+repr(req)+"\np=B/'requests'/(label+'.json')\nput(p,enc(req))\n"
        code+="D=Path("+repr(self.remote_root)+")/"+repr('phone-'+tag)+"\nnewdir(D)\no=stream(D/'actor.stdout');e=stream(D/'actor.stderr')\np=subprocess.Popen(['/usr/bin/python3','-I','-B',str(a),label,str(B/'requests'/(label+'.json'))],stdout=o,stderr=e,start_new_session=True)\n"
        code+="try:rc=p.wait(timeout="+repr(req['timeout_seconds']+20)+")\nexcept subprocess.TimeoutExpired:\n put(D/'UNKNOWN.json',enc({'pid':p.pid,'automatic_retry':False,'signals_sent':0}));raise\nfinally:finish(o);finish(e)\nraw=(B/'operations'/label/'result.json').read_bytes();v={'actor_rc':rc,'wrapper_sha256':hashlib.sha256(raw).hexdigest(),'wrapper':json.loads(raw)}\nput(D/'ORIGINAL-OPERATION.json',enc(v))\nprint(json.dumps(v,sort_keys=True))\n"
        result=self.remote('phone-'+tag,code,req['timeout_seconds']+55)
        need(result['actor_rc']==0,'phone actor unknown/nonzero; inspect original without replay')
        w=result['wrapper']
        if req['kind']=='push':
            need(w['status']=='pushed_and_hash_verified' and w['sha256']==req['sha256'] and w['readback']['rc']==0,'actual push not confirmed')
            return w
        ph=w['phone'];need(type(ph['rc']) is int and ph['rc']==0,'actual phone command failed; no new key retry');return strict(ph['stdout'])
    def bridge_call(self,tag,operation,extra=(),timeout=40):
        argv=['phone_chain_bridge.py',operation,'--label',self.p['label']]
        if self.lease:argv+=['--lease-sha256',self.prepared['lease']['sha256']]
        argv+=list(extra)+['--execute-root-bridge-once']
        code='import sys\nsys.argv='+repr(argv)+'\n'+self.bridge.decode()
        command=ENV+'/usr/bin/python3 -I -B -c '+shlex.quote(code)
        return self.phone(tag,{'kind':'shell','root':True,'timeout_seconds':timeout,'command':command})
    def push_copy(self,tag,remote_path,name,byte_size,digest):
        self.phone('push-'+tag,{'kind':'push','source':remote_path,'destination':'/data/local/tmp/hepta-phone-local-v150-r1/hepta-native-guard-'+name,
            'sha256':digest,'timeout_seconds':90})
        return self.bridge_call('copy-'+tag,'copy-input',['--name',name,'--bytes',str(byte_size),'--sha256',digest])
    def frozen_phone(self,tag,argv,timeout=90):
        return self.phone(tag,{'kind':'shell','root':True,'timeout_seconds':timeout,'command':ENV+shlex.join(argv)})
    def remaining(self,minimum=1):
        left=(self.lease['expires_unix_ms']-time.time_ns()//1000000)/1000
        need(left>minimum,'same lease exhausted; no extension/restart');return left

    def run(self):
        p=self.p;runtime=Path(p['package']['path']).parent;shared=Path(p['shared_root'])
        expiry=time.time_ns()//1000000+600000
        put(self.out/'CHAIN-INTENT.json',enc({'schema':'hepta.native-guard.root-chain-intent.v1','nonce':p['nonce'],
            'label':p['label'],'case_id':p['case_id'],'lease_expires_unix_ms':expiry,'maximum_native_sends':1,
            'maximum_detached_launches':1,'automatic_retry':False,'automatic_lease_extension':False,'model_requests':0}))
        args=['/usr/bin/python3','-I','-B',str(runtime/'source/prepare_component.py')]
        values={'label':p['label'],'case-id':p['case_id'],'nonce':p['nonce'],'boot-id':BOOT,'session-id':p['session_id'],
            'profile-id':p['profile_id'],'package':p['package']['path'],'package-sha256':PKG,
            'production-source':str(shared/'provider/source'),'config-file':str(shared/'local-config-r10-r1.json'),
            'config-sha256':sha(read(shared/'local-config-r10-r1.json')),
            'service-file':str(shared/'PHONE-SERVICE-INPUTS-v150-r10-r1.json'),'service-sha256':sha(read(shared/'PHONE-SERVICE-INPUTS-v150-r10-r1.json')),
            'artifacts-file':p['artifacts']['path'],'artifacts-sha256':p['artifacts']['sha256'],'live-policy-sha256':p['live_policy_sha256'],
            'retirement-descriptor':p['retirement_descriptor']['path'],'retirement-descriptor-sha256':RET,
            'retirement-originals':p['retirement_originals'],'owner-request-file':p['request']['path'],
            'owner-request-sha256':p['request']['sha256'],'expires-unix-ms':expiry,'out':str(self.out/'material')}
        if p['prior_boundary_descriptor']:
            values.update({'prior-boundary-descriptor':p['prior_boundary_descriptor']['path'],
                'prior-boundary-descriptor-sha256':p['prior_boundary_descriptor']['sha256'],'prior-boundary-original':p['prior_boundary_original']['path']})
        for k,v in values.items():args+=['--'+k,str(v)]
        self.execute_process('prepare-material',args,30)
        self.material=self.out/'material';self.prepared=strict(read(self.material/'PREPARED.json'))
        self.lease=strict(read(self.material/'tree/LEASE.json'));self.remaining(480)
        files={}
        for file in (self.material/'tree').rglob('*'):
            if file.is_file():files['material/tree/'+str(file.relative_to(self.material/'tree'))]=read(file)
        archive=read(self.material/'component-inputs.tar.gz');files['inputs/component-inputs.tar.gz']=archive
        files['inputs/stage_component.py']=read(runtime/'source/stage_component.py')
        for k in ('request','previous','preserved_draft'):files['inputs/'+k+'.original']=pin(p[k])
        self.remote_files('host-stage-material',files,True)
        for tag,name,rel in [('material',p['label']+'.tar.gz','inputs/component-inputs.tar.gz'),('stage-source',p['label']+'.stage.py','inputs/stage_component.py')]:
            b=files[rel];self.push_copy(tag,self.remote_root+'/'+rel,name,len(b),sha(b))
        home=self.prepared['phone_home'];staging=G+'/native-guard-staging-r10-r1/'
        self.frozen_phone('stage',['/usr/bin/python3','-I','-B',staging+p['label']+'.stage.py',
            '--archive',staging+p['label']+'.tar.gz','--archive-sha256',sha(archive),
            '--lease-sha256',self.prepared['lease']['sha256'],'--package-sha256',PKG,'--execute-private-stage-once'],90)
        self.remaining(465)
        sender=['/usr/bin/python3','-I','-B',str(B/'send_new_native_guard_task_r10_r4.py'),p['label'],p['request']['path'],p['previous']['path'],
            '--preserved-draft',p['preserved_draft']['path'],'--retirement-resolution',p['sender_retirement_resolution']['path'],
            '--evidence-root','component','--component-contract',str(self.material/'tree/sender-contract.json'),
            '--component-package',p['package']['path'],'--component-package-sha256',PKG]
        self.execute_process('sender-preview',sender,20)
        self.sender=self.execute_process('sender-execute',sender+['--execute-once'],600,async_start=True)
        sender_dir='/home/alex/codex-hepta-natural-'+p['label']+'-root-v150'
        marker=self.remote_read('sender-prepared',{'prepared':sender_dir+'/COMPONENT-PREPARED-NO-SEND.json'},
            sender_dir+'/COMPONENT-PREPARED-NO-SEND.json',90,True)
        mr=strict(base64.b64decode(marker['files']['prepared']['base64'],validate=True))
        contract_raw=read(self.material/'tree/sender-contract.json')
        provider_sha=next(r['sha256'] for r in strict(pin(p['package']))['files'] if r['path']=='source/component_listener.py')
        validate_sender_marker(mr,contract_raw,self.prepared,p['request']['sha256'],p['nonce'],provider_sha)
        # Frozen listener requires more than 420 seconds before its sole listen.
        # Leave a small launch margin; never extend the original 600-second lease.
        self.remaining(510)
        self.frozen_phone('launch',self.prepared['root_detached_launcher_argv'],60)
        for phase in ('setup','before-guard','after-guard'):
            self.remaining(25)
            value=self.bridge_call('plan-'+phase,'phase-originals',['--phase',phase],timeout=75 if phase=='setup' else 40)
            need(value['state']=='ACTUAL_PHASE_ORIGINALS_READ','component ended before phase; preserve, no additional Root UI')
            phasefiles={}
            for name,row in value['files'].items():
                raw=base64.b64decode(row['base64'],validate=True);need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'original phase file')
                phasefiles['plans/'+phase+'/'+name]=raw
            self.remote_files('store-plan-'+phase,phasefiles)
            directory=self.remote_root+'/plans/'+phase+'/';planrow=value['files']['ROOT-'+phase.upper()+'-PLAN.json']
            parent='/home/alex/codex-hepta-native-guard-fixtures-r10-r1/'+p['nonce']+'/'+phase
            entry=self.remote_root+'/material/tree/package/source/'
            argv=['/usr/bin/python3','-I','-B',entry+'run_root_fixture_phase.py','--material',self.remote_root+'/material/tree',
                '--lease-sha256',self.prepared['lease']['sha256'],'--package-sha256',PKG,
                '--plan',directory+'ROOT-'+phase.upper()+'-PLAN.json','--plan-sha256',planrow['sha256'],
                '--bound-contract',directory+'BOUND-CONTRACT.json','--bound-contract-sha256',value['files']['BOUND-CONTRACT.json']['sha256'],
                '--accepted',directory+'ACCEPTED.json','--accepted-sha256',value['files']['ACCEPTED.json']['sha256'],
                '--out',parent,'--execute-root-fixture-phase-once']
            put(self.out/('ROOT-FIXTURE-'+phase+'.INTENT.json'),enc({'phase':phase,'parent_out':parent,
                'expected_terminal_path':parent+'/HOST-TERMINAL.json','argv':argv,'maximum_child_starts':1,
                'terminal_unknown_until_actual_original_read':True,'automatic_retry':False}))
            self.remote_program('fixture-'+phase,argv,min(250,max(1,int(self.remaining())-5)))
            terminal=self.remote_read('fixture-originals-'+phase,{'terminal':parent+'/HOST-TERMINAL.json','index':parent+'/actor/ORIGINAL-INDEX.json'})
            tr=terminal['files']['terminal'];tv=strict(base64.b64decode(tr['base64'],validate=True))
            need(tv['state']=='OWNED_ROOT_FIXTURE_CHILD_JOINED' and tv['child_wait_returned'] is True
                and tv['child_returncode']==0 and len(tv['group_absence_observations'])==2,'actual Root actor unknown')
            self.root_attempts.append({'phase':phase,'terminal':{k:tr[k] for k in ('path','bytes','sha256')}})
            packout=self.remote_root+'/witness-'+phase
            packargv=['/usr/bin/python3','-I','-B',entry+'witness_bundle.py','pack','--plan',directory+'ROOT-'+phase.upper()+'-PLAN.json',
                '--plan-sha256',planrow['sha256'],'--original-index',parent+'/actor/ORIGINAL-INDEX.json',
                '--original-index-sha256',terminal['files']['index']['sha256'],'--nonce',p['nonce'],'--boot-id',BOOT,'--out',packout]
            packed=strict(self.remote_program('pack-'+phase,packargv,30)['stdout'])
            row=packed['archive'];self.push_copy('witness-'+phase,packout+'/witness.tar.gz',p['label']+'-'+phase+'.witness.tar.gz',row['bytes'],row['sha256'])
            self.frozen_phone('publish-'+phase,['/usr/bin/python3','-I','-B',home+'/package/source/witness_bundle.py','publish',
                '--lease',home,'--lease-sha256',self.prepared['lease']['sha256'],'--archive',staging+p['label']+'-'+phase+'.witness.tar.gz',
                '--archive-sha256',row['sha256'],'--execute-publish-original-bytes-once'],35)
        child,d,so,se=self.sender
        try:rc=self.join_host_capture('sender-execute',child,maximum_wait=380)
        except subprocess.TimeoutExpired:raise RuntimeError('original sender still running or output incomplete; no signal/replay')
        finally:
            cleanup_errors=self.stop_host_capture('sender-execute')
            cleanup_errors+=self.persist_host_capture('sender-execute')
            cleanup_errors+=close_streams_owned([('sender:stdout',so),('sender:stderr',se)])
            self._owned_host_streams.pop('sender-execute',None)
            if cleanup_errors:
                self.steps.append({'state':'HOST_OUTPUT_FINALIZATION_FAILED','phase':'sender-execute',
                    'cleanup_errors':cleanup_errors,'automatic_retry':False,'signals_sent':0})
        need(not cleanup_errors,'sender output finalization failed: '+repr(cleanup_errors))
        self.verify_host_capture_outputs('sender-execute')
        put(d/'JOINED.json',enc({'pid':child.pid,'returncode':rc,'wait_returned':True,'automatic_retry':False}))
        self._owned_host_children.pop('sender-execute',None)
        self._owned_host_deadlines.pop('sender-execute',None)
        self._owned_host_captures.pop('sender-execute',None)
        need(rc==0,'original sender child failed')
        sent=strict(read(B/(p['label']+'.send-result.json')))
        need(sent.get('rc')==0 and sent.get('stderr')=='','actual P4 sender failed/unknown; retain originals')
        actor_result=strict(sent['stdout'].strip().splitlines()[-1])
        need(actor_result['state']=='ORIGINAL_NATIVE_TERMINAL_OBSERVED' and actor_result['draft_restore']['state']=='ORIGINAL_DRAFT_RESTORED',
            'native terminal/draft restoration not proven')
        self.bridge_call('role-end','role-end')
        capture_out=G+'/native-guard-snapshots-r10-r1/'+p['label']+'-capture-01'
        snap=self.frozen_phone('snapshot',['/usr/bin/python3','-I','-B',home+'/package/source/component_snapshot.py',
            '--lease',home,'--lease-sha256',self.prepared['lease']['sha256'],'--package-sha256',PKG,'--out',capture_out,
            '--execute-original-snapshot-once'],100)
        archive=snap['archive'];need(0<archive['bytes']<=64*1024*1024,'actual snapshot archive bound')
        chunks=[]
        for index in range((archive['bytes']+524287)//524288):
            row=self.bridge_call('chunk-'+str(index),'snapshot-chunk',['--sha256',archive['sha256'],'--bytes',str(archive['bytes']),'--index',str(index)],35)
            b=base64.b64decode(row['base64'],validate=True);need(len(b)==row['bytes'] and sha(b)==row['sha256'] and row['offset']==index*524288,'actual snapshot chunk')
            chunks.append(b)
        body=b''.join(chunks);need(len(body)==archive['bytes'] and sha(body)==archive['sha256'],'full actual snapshot hash')
        put(self.out/'ORIGINALS.tar.gz',body)
        hostfiles={'closure-inputs/ORIGINALS.tar.gz':body}
        for source,key in ((B/(p['label']+'.send-result.json'),'sender_host_result'),(B/(p['label']+'.local-once.json'),'sender_local_once'),
            (B/(p['label']+'.actor.py'),'sender_actor')):hostfiles['closure-inputs/'+key+'.original']=read(source)
        self.remote_files('stage-closure-inputs',hostfiles)
        def remote_desc(relative,raw):return desc(self.remote_root+'/'+relative,raw)
        closure={'schema':'hepta.native-guard.closure-plan.v1','label':p['label'],
            'archive':remote_desc('closure-inputs/ORIGINALS.tar.gz',body),'capture_sha256':snap['capture']['sha256'],
            'package':remote_desc('material/tree/package/MANIFEST.json',pin(p['package'])),'sender_dir':sender_dir,
            'request':remote_desc('inputs/request.original',pin(p['request'])),
            'previous':remote_desc('inputs/previous.original',pin(p['previous'])),
            'preserved_draft':remote_desc('inputs/preserved_draft.original',pin(p['preserved_draft'])),
            'root_fixture_attempts':self.root_attempts}
        for key in ('sender_host_result','sender_local_once','sender_actor'):
            closure[key]=remote_desc('closure-inputs/'+key+'.original',hostfiles['closure-inputs/'+key+'.original'])
        cr=enc(closure);self.remote_files('stage-closure-plan',{'CLOSURE-PLAN.json':cr});closeout=self.remote_root+'/closure'
        self.remote_program('close',['/usr/bin/python3','-I','-B',entry+'close_component.py','--plan',self.remote_root+'/CLOSURE-PLAN.json',
            '--plan-sha256',sha(cr),'--out',closeout,'--execute-host-closure-once'],150)
        closed=self.remote_read('closed-originals',{'closure':closeout+'/CLOSURE.original.json','inventory':closeout+'/AFTER-INVENTORY.original.json'})
        for key,extension in (('closure','CLOSURE.json'),('inventory','INVENTORY.json')):
            row=closed['files'][key];put(self.out/extension,base64.b64decode(row['base64'],validate=True))
            self.push_copy('closed-'+key,row['path'],p['label']+'.'+extension,row['bytes'],row['sha256'])
        published=self.frozen_phone('late-publish',['/usr/bin/python3','-I','-B',home+'/package/source/late_boundary.py',
            '--lease',home,'--lease-sha256',self.prepared['lease']['sha256'],'--closure',staging+p['label']+'.CLOSURE.json',
            '--closure-sha256',closed['files']['closure']['sha256'],'--inventory',staging+p['label']+'.INVENTORY.json',
            '--inventory-sha256',closed['files']['inventory']['sha256'],'--execute-publish-once'],100)
        boundary=self.bridge_call('boundary-read','boundary-original')['file']
        need({k:boundary[k] for k in ('path','bytes','sha256','metadata')}==published['boundary'],'actual published boundary')
        put(self.out/'LATE-BOUNDARY.original.json',base64.b64decode(boundary['base64'],validate=True))
        put(self.out/'LATE-BOUNDARY-DESCRIPTOR.json',enc({k:boundary[k] for k in ('path','bytes','sha256','metadata')}))
        value=strict(read(self.out/'CLOSURE.json'))
        latency=self.remote_read('latest-previous-original',{'latency':sender_dir+'/SEND-NATIVE-LATENCY.json'})
        lat=strict(base64.b64decode(latency['files']['latency']['base64'],validate=True));need(lat['scope']==value['scope'],'closed previous scope')
        previous={'schema':'hepta.native-guard.closed-previous.v1','identity':value['scope'],
            'request_sha256':lat['original_observation']['native_request_sha256'],'terminal':{'status':value['native_status']},
            'known_all_dispatched_tools_confirmed_terminal':True,'complete_business_success':False,
            'component_qualified':value['component_qualified'],'closed_component':filedesc(self.out/'CLOSURE.json'),
            'late_boundary':{k:boundary[k] for k in ('path','bytes','sha256','metadata')},'automatic_replay':False}
        put(self.out/'ACTUAL-PREVIOUS-INPUT.json',enc(previous))
        final={'state':'ORIGINAL_COMPONENT_CLOSED_AND_LATE_BOUNDARY_PUBLISHED','component_qualified':value['component_qualified'],
            'business_qualified':False,'model_requests':0,'four_role_qualification':False,'native_status':value['native_status'],
            'scope':value['scope'],'late_boundary':published['boundary'],'previous':filedesc(self.out/'ACTUAL-PREVIOUS-INPUT.json'),
            'automatic_retry':False,'steps':self.steps}
        put(self.out/'ROOT-RESULT.json',enc(final));print(json.dumps({k:v for k,v in final.items() if k!='steps'},sort_keys=True));return 0
def main():
 a=argparse.ArgumentParser(description=__doc__);a.add_argument('--plan',type=Path,required=True);a.add_argument('--plan-sha256',required=True)
 a.add_argument('--execute-root-chain-once',action='store_true');v=a.parse_args()
 raw=read(v.plan,262144);need(sha(raw)==v.plan_sha256,'Root plan pin')
 if not v.execute_root_chain_once:
  print(json.dumps({'state':'HOST_PREVIEW_NO_PHONE_NO_NONCE_NO_LEASE','plan_sha256':sha(raw),
  'phone_calls':0,'native_sends':0,'lease_fixed':False,'requires':'All explicit actual original descriptors, Root policy adoption, and execute flag.'},sort_keys=True));return 0
 p,_=validate_plan(raw);os.umask(0o077)
 parent=Path(p['out']).parent
 try:newdir(parent)
 except FileExistsError:pass
 need(parent.resolve(strict=True)==parent and stat.S_IMODE(parent.stat().st_mode)==0o700,'private Root output parent')
 c=Chain(p,raw)
 try:return c.run()
 except BaseException as error:
  host_cleanup=c.close_owned_host_outputs()
  value={'state':'FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED_NO_AUTOMATIC_CONTINUATION',
  'host_cleanup':host_cleanup,
  'error_type':type(error).__name__,'detail':str(error)[:1024],'steps':c.steps,'root_fixture_attempts':c.root_attempts,
  'automatic_retry':False,'new_identity_retry':False,'send_again':False,'signals_sent_by_coordinator':0,
  'policy_changes':0,'model_requests':0,'component_qualified':False,'business_qualified':False,
  'note':'Inspect existing process/actor/phone receipts. No missing record is treated as no effect.'}
  put(c.out/'ROOT-FAILURE.json',enc(value));raise
EPOCH_ROOT_BINDING = None
EPOCH_ENTRY_BOOTSTRAP = r'''import hashlib,importlib.abc,importlib.util,json,os,stat,sys,time,types
from pathlib import Path
def require(v,s):
 if not v:raise ValueError(s)
def digest(b):return hashlib.sha256(b).hexdigest()
def strict_json(b):
 def pairs(items):
  d={}
  for k,v in items:require(k not in d,'duplicate package key');d[k]=v
  return d
 return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite package')))
def meta(s):return [getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
require(len(sys.argv)>=7,'exact reviewed entry parameters required')
package=Path(sys.argv[1]);expected_size=int(sys.argv[2]);expected_sha=sys.argv[3];entry=sys.argv[4];context=sys.argv[5];seconds=int(sys.argv[6])
require(str(package)==sys.argv[1] and package.is_absolute() and '..' not in package.parts and context in ('phone','p4','mac') and 0<seconds<=300,'fixed actual context/path/clock required')
deadline=time.monotonic()+seconds
def check():require(time.monotonic()<deadline,'same full entry clock exhausted')
held=[];directories={};bodies={};originals={}
def read_original(path,size,wanted):
 check();require(type(size) is int and 0<=size<=16777216 and len(wanted)==64 and all(c in '0123456789abcdef' for c in wanted),'exact original bound required')
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);parents=[(fd,None,None,meta(os.fstat(fd)))];filefd=None
 try:
  for name in path.parts[1:-1]:
   child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
   parents.append((child,fd,name,meta(os.fstat(child))));fd=child
  named=meta(os.stat(path.name,dir_fd=fd,follow_symlinks=False))
  require(stat.S_ISREG(named[2]) and named[5]==1 and named[6]==size,'exact regular original required before open')
  filefd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
  require(meta(os.fstat(filefd))==named,'original changed during open')
  raw=bytearray()
  while len(raw)<=size:
   check();part=os.read(filefd,min(65536,size+1-len(raw)))
   if not part:break
   raw.extend(part)
  raw=bytes(raw);require(len(raw)==size and digest(raw)==wanted,'complete original hash differs')
  require(meta(os.fstat(filefd))==named==meta(os.stat(path.name,dir_fd=fd,follow_symlinks=False))==meta(path.lstat()),'original full9 changed')
  for pf,pp,pn,pm in parents:
   require(meta(os.fstat(pf))==pm and (pp is None or meta(os.stat(pn,dir_fd=pp,follow_symlinks=False))==pm),'canonical parent changed')
  held.append((filefd,parents,path,named,raw));filefd=None;parents=[]
  return raw,{'path':str(path),'bytes':size,'sha256':wanted,'metadata':named}
 finally:
  if filefd is not None:os.close(filefd)
  for row in reversed(parents):os.close(row[0])
def recheck():
 for fd,parents,path,before,raw in held:
  check();require(meta(os.fstat(fd))==before==meta(os.stat(path.name,dir_fd=parents[-1][0],follow_symlinks=False))==meta(path.lstat()),'held original renamed or changed')
  os.lseek(fd,0,os.SEEK_SET);h=hashlib.sha256();total=0
  while total<=len(raw):
   check();part=os.read(fd,min(65536,len(raw)+1-total))
   if not part:break
   h.update(part);total+=len(part)
  require(total==len(raw) and h.hexdigest()==digest(raw),'held original bytes changed')
  for pf,pp,pn,pm in parents:
   now=meta(os.fstat(pf));require(now[:5]==pm[:5] and (pp is None or meta(os.stat(pn,dir_fd=pp,follow_symlinks=False))==now),'source ancestor identity or canonical binding changed')
 for path,(fd,before,names) in directories.items():require(meta(os.fstat(fd))==before==meta(Path(path).lstat()) and sorted(os.listdir(fd))==names,'complete package directory changed')
class SourceLoader(importlib.abc.MetaPathFinder,importlib.abc.Loader):
 def find_spec(self,name,path=None,target=None):
  if name in names:return importlib.util.spec_from_loader(name,self,origin=str(package/names[name]))
  return None
 def create_module(self,spec):return None
 def exec_module(self,module):
  rel=names[module.__name__];raw=bodies[rel]
  module.__dict__.update({'__file__':str(package/rel),'__actual_context__':context,
   '__reviewed_package_manifest_raw__':manifest_raw,'__reviewed_package_sources__':bodies,
   '__reviewed_source_sha256__':digest(raw),'__epoch_budget_check__':check,
   '__reviewed_package_physical_observation__':originals})
  check();exec(compile(raw,str(package/rel),'exec'),module.__dict__);check()
try:
 require(0<expected_size<=262144,'manifest input limit')
 manifest_raw,manifest_original=read_original(package/'MANIFEST.json',expected_size,expected_sha)
 value=strict_json(manifest_raw);rows=value.get('files')
 require(value.get('schema')=='hepta.native-guard.adapter-package.v1' and value.get('state')=='HOST_REVIEWED_NOT_PHONE_QUALIFIED' and type(rows) is list and len(rows)==32,'actual32 package required')
 total=len(manifest_raw)
 for row in rows:
  require(type(row) is dict and set(row)=={'path','bytes','sha256'},'complete row required')
  rel=row['path'];size=row['bytes']
  require(type(rel) is str and rel.startswith(('source/','reference/')) and len(rel.split('/'))==2 and rel.split('/')[1] not in ('','.','..') and chr(0) not in rel and rel not in bodies and type(size) is int and 0<size and ((rel.endswith('.py') and size<=131072) or (rel.endswith('.json') and size<=16777216)),'member name/type/size differs')
  total+=size;require(total<=33554432,'same complete source pool exceeded')
  raw,pin=read_original(package/rel,size,row['sha256']);bodies[rel]=raw;originals[rel]=pin
 for rel in ('','source','reference'):
  path=package/rel;fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  before=meta(os.fstat(fd));actual=sorted(os.listdir(fd))
  wanted=['MANIFEST.json','reference','source'] if not rel else sorted(p.split('/')[1] for p in bodies if p.startswith(rel+'/'))
  require(actual==wanted and before==meta(path.lstat()),'package tree contains undeclared files')
  directories[str(path)]=(fd,before,actual)
 names={}
 for rel in bodies:
  if rel.endswith('.py'):
   name=Path(rel).stem;require(name not in names,'ambiguous reviewed import name');names[name]=rel
 require(entry in names and names[entry].startswith('source/'),'fixed current entry member required')
 require(all(name not in sys.modules for name in names),'foreign target module was imported before complete gate')
 recheck();sys.dont_write_bytecode=True;finder=SourceLoader();sys.meta_path.insert(0,finder)
 # All current imports are served from the already checked immutable byte map.
 # The direct entry is registered under its true source name before execution.
 entry_module=types.ModuleType(entry);entry_module.__file__=str(package/names[entry]);sys.modules[entry]=entry_module
 for name in ('component_common','native_proc_profile','component_lifecycle','prepare_component','late_boundary','component_snapshot'):
  if name!=entry:__import__(name)
 entry_module.__dict__.update({'__name__':'__main__','__file__':str(package/names[entry]),
  '__actual_context__':context,'__reviewed_package_manifest_raw__':manifest_raw,
  '__reviewed_package_sources__':bodies,'__reviewed_source_sha256__':digest(bodies[names[entry]]),
  '__epoch_budget_check__':check,'__reviewed_package_physical_observation__':originals})
 sys.argv=[str(package/names[entry])]+sys.argv[7:]
 sys.modules['__main__']=entry_module
 check();exec(compile(bodies[names[entry]],str(package/names[entry]),'exec'),entry_module.__dict__)
finally:
 try:
  if held:recheck()
 finally:
  for fd,parents,_path,_before,_raw in reversed(held):
   os.close(fd)
   for row in reversed(parents):os.close(row[0])
  for fd,_before,_names in directories.values():os.close(fd)
'''
def epoch_root_binding_value():
 value=EPOCH_ROOT_BINDING
 need(type(value) is dict and set(value)=={'schema','runtime','combination','shared_materials',
 'pure_verifier','source_derivation','generation','root_plan_schema','root_template_slots','template'},
 'final exact epoch Root source binding is unavailable')
 need(value['schema']=='hepta.native-guard.epoch-root-source-binding.v1'
 and value['root_plan_schema']=='hepta.native-guard.epoch-root-plan.v1'
 and value['root_template_slots']==['EPOCH_ROOT_BINDING'],
 'only the one reviewed Root literal slot may bind the actual generation')
 for name in ('runtime','combination','shared_materials','pure_verifier','source_derivation','generation'):
  row=value[name]
  need(type(row) is dict and set(row)=={'path','bytes','sha256'}
  and type(row['path']) is str and Path(row['path']).is_absolute()
  and str(Path(row['path']))==row['path'] and '..' not in Path(row['path']).parts
  and type(row['bytes']) is int and 0<row['bytes']<=16*1024*1024
  and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),
  'actual source-generation descriptor differs')
 row=value['template']
 need(type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int
 and 0<row['bytes']<=131072 and type(row['sha256']) is str
 and re.fullmatch('[0-9a-f]{64}',row['sha256']),'reviewed unbound whole Root template required')
 return value
def epoch_root_template_view(raw):
 binding=epoch_root_binding_value();tree=ast.parse(raw)
 rows=[n for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1
 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='EPOCH_ROOT_BINDING']
 need(len(rows)==1,'Root template must contain exactly one literal binding slot')
 node=rows[0].value;value=ast.literal_eval(node)
 need(enc(value)==enc(binding),'executing Root binding differs from its actual source original')
 lines=raw.splitlines(keepends=True)
 start=sum(map(len,lines[:node.lineno-1]))+node.col_offset
 end=sum(map(len,lines[:node.end_lineno-1]))+node.end_col_offset
 parent=raw[:start]+b'None'+raw[end:]
 need({'bytes':len(parent),'sha256':sha(parent)}==binding['template'],
 'whole Root source differs outside its single reviewed literal slot')
 return parent
def epoch_root_original_sources(plan):
 binding=epoch_root_binding_value();pinrow=plan.get('source_package')
 raw=pin(pinrow);value=strict(raw)
 need(Path(pinrow['path']).parent==HERE.parent
 and value.get('schema')=='hepta.native-guard.root-chain-source-package.v1'
 and value.get('frozen_component_package_sha256')==binding['runtime']['sha256']
 and value.get('current_combination_sha256')==binding['combination']['sha256']
 and type(value.get('files')) is list and len(value['files'])==3,
 'actual unique Root3 manifest/source-generation binding differs')
 expected={'source/run_component_root_once.py','source/phone_chain_bridge.py',
 'reference/policy_native5_verifier.py'}
 names={r.get('path') for r in value['files']}
 need(names==expected,
 'Root source package is not the fixed three regular source members')
 originals={}
 for row in value['files']:
  need(type(row) is dict and set(row)=={'path','bytes','sha256'}
  and type(row['bytes']) is int and 0<row['bytes']<=131072,'Root source member bound differs')
  actual=dict(row,path=str(HERE.parent/row['path']));body=pin(actual)
  if row['path']=='reference/policy_native5_verifier.py':
   need(row['bytes']==VERIFIER_BYTES and row['sha256']==VERIFIER_SHA,
   'historical policy adoption verifier source changed')
  originals[row['path']]={'origin':actual,'raw':body}
 source=originals['source/run_component_root_once.py']['raw'];epoch_root_template_view(source)
 need(Path(__file__)==HERE/'run_component_root_once.py','actual Root coordinator path differs')
 return {'manifest':{'origin':pinrow,'raw':raw},'sources':originals}
def epoch_entry_argv(package,manifest,entry,arguments,*,actual_context,seconds):
 binding=epoch_root_binding_value()
 need({k:manifest[k] for k in ('bytes','sha256')}
 =={k:binding['runtime'][k] for k in ('bytes','sha256')}
 and entry in ('close_component','component_snapshot','stage_component','component_lifecycle',
 'run_root_fixture_phase','root_fixture_once','witness_bundle','late_boundary'),
 'one reviewed actual current entry and full runtime pin required')
 limits={'close_component':150,'component_snapshot':75,'stage_component':90,'component_lifecycle':60,
 'run_root_fixture_phase':250,'root_fixture_once':180,'witness_bundle':35,'late_boundary':100}
 need(actual_context in ('phone','p4') and type(seconds) is int and 0<seconds<=limits[entry]
 and type(arguments) is list and all(type(v) is str and '\0' not in v for v in arguments),
 'actual entry context, single operation bound or argv differs')
 return ['/usr/bin/python3','-I','-B','-c',EPOCH_ENTRY_BOOTSTRAP,
 str(package),str(manifest['bytes']),manifest['sha256'],entry,actual_context,str(seconds),*arguments]
def epoch_owned_source_sections(coordinator_raw):
 tree=ast.parse(coordinator_raw);lines=coordinator_raw.splitlines(keepends=True)
 functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
 chain=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Chain')
 methods={n.name:n for n in chain.body if isinstance(n,ast.FunctionDef)}
 chosen=('need','sha','enc','strict','desc','read','put','syncdir','newdir','original_stream',
 'close_streams_owned','filedesc','capture_stat','close_unclaimed_capture_readers','capture_output_worker',
 'write_captured_output','capture_observation')
 operations=('stop_host_capture','persist_host_capture','verify_host_capture_outputs',
 'join_host_capture','execute_process','close_owned_host_outputs')
 def source(node):return b''.join(lines[node.lineno-1:node.end_lineno]).decode()
 raw='import hashlib,json,os,re,selectors,stat,subprocess,threading,time\nfrom pathlib import Path\n'
 raw+='HOST_OUTPUT_LIMIT=65536\nHOST_CAPTURE_POLL=0.025\nHOST_CAPTURE_STOP_WAIT=1.0\n'
 raw+='\n\n'.join(source(functions[name]) for name in chosen)+'\n\n'
 raw+='class EpochOwnedHostPhase:\n    def __init__(self,out):\n        self.out=Path(out);self.steps=[]\n'
 raw+='\n'.join(source(methods[name]) for name in operations)+'\n'
 return raw
def epoch_render_close_program(coordinator_raw,plan_raw,closure_plan_raw):
 binding=epoch_root_binding_value();plan=strict(plan_raw);closure=strict(closure_plan_raw)
 need(type(plan) is dict and plan.get('schema')==binding['root_plan_schema']
 and plan.get('package')==binding['runtime'] and plan.get('combination')==binding['combination']
 and plan.get('shared_materials')==binding['shared_materials']
 and type(plan.get('nonce')) is str and re.fullmatch('[0-9a-f]{32}',plan['nonce'])
 and type(plan.get('label')) is str and re.fullmatch('[a-z0-9][a-z0-9-]{5,55}',plan['label']),
 'actual epoch plan changed its complete current source generation or identity')
 epoch=plan.get('epoch')
 need(type(epoch) is dict and set(epoch)=={'schema','epoch_id','anchor','initialization',
 'ordinal','reservation','identity','generation'}
 and epoch['schema']=='hepta.native-guard.epoch-lease-binding.v1'
 and type(epoch['ordinal']) is int and 1<=epoch['ordinal']<=8
 and epoch['epoch_id']=='legacy902-active01',
 'actual complete bounded epoch identity links are required')
 for name in ('anchor','initialization','reservation','identity','generation'):
  original=epoch[name]
  need(type(original) is dict and set(original)=={'path','bytes','sha256','metadata'}
  and type(original['path']) is str and Path(original['path']).is_absolute()
  and str(Path(original['path']))==original['path'] and '..' not in Path(original['path']).parts
  and type(original['bytes']) is int and 0<original['bytes']<=16777216
  and type(original['sha256']) is str and re.fullmatch('[0-9a-f]{64}',original['sha256'])
  and type(original['metadata']) is list and len(original['metadata'])==9
  and all(type(n) is int for n in original['metadata'])
  and stat.S_ISREG(original['metadata'][2]) and original['metadata'][5]==1
  and original['metadata'][6]==original['bytes'],
  'actual phone original must retain its own complete full9: '+name)
 need({k:epoch['generation'][k] for k in ('path','bytes','sha256')}==binding['generation'],
 'actual bounded claimed generation is required')
 root='/home/alex/codex-native-guard-chain-r10-r1/'+plan['nonce']
 need(Path(plan['out'])==B/'native-guard-root-chains-r10-r1'/plan['label']
 and type(closure) is dict and set(closure)=={'schema','label','archive','capture_sha256','package',
 'sender_dir','sender_host_result','sender_local_once','sender_actor','request','previous',
 'preserved_draft','root_fixture_attempts'}
 and closure['schema']=='hepta.native-guard.closure-plan.v1' and closure['label']==plan['label'],
 'original finite closure plan fields or fixed Root namespace differ')
 manifest=dict(binding['runtime'],path=root+'/material/tree/package/MANIFEST.json')
 need(closure['package']==manifest and closure['archive']['path']==root+'/closure-inputs/ORIGINALS.tar.gz'
 and closure['sender_dir']=='/home/alex/codex-hepta-natural-'+plan['label']+'-root-v150',
 'closer input escaped the actual single case material/sender namespaces')
 for name in ('request','previous','preserved_draft'):
  need(closure[name]==dict(plan[name],path=root+'/inputs/'+name+'.original'),
  'closer actual original input differs from its Root plan: '+name)
 plan_path=root+'/CLOSURE-PLAN.json';out=root+'/closure'
 argv=epoch_entry_argv(root+'/material/tree/package',manifest,'close_component',
 ['--plan',plan_path,'--plan-sha256',sha(closure_plan_raw),'--out',out,
 '--execute-host-closure-once'],actual_context='p4',seconds=150)
 code=epoch_owned_source_sections(coordinator_raw)
 code+='\nROOT_PLAN='+repr(plan)+'\nCLOSURE_PLAN_RAW='+repr(closure_plan_raw)+'\n'
 code+='ROOT='+repr(root)+'\nPLAN_PATH='+repr(plan_path)+'\nARGV='+repr(argv)+'\n'
 code+='''need(read(PLAN_PATH,len(CLOSURE_PLAN_RAW))==CLOSURE_PLAN_RAW,'actual closure plan changed')
need(Path(ROOT).resolve(strict=True)==Path(ROOT),'exact existing P4 case namespace required')
runner=EpochOwnedHostPhase(ROOT)
try:
    runner.execute_process('epoch-close',ARGV,150,input_raw=None,async_start=False)
except BaseException:
    runner.close_owned_host_outputs()
    raise
phase=Path(ROOT)/'epoch-close';out=Path(ROOT)/'closure'
rows={}
for role,path in [('p4_intent',phase/'INTENT.json'),('p4_child',phase/'CHILD.json'),
    ('p4_result',phase/'RESULT.json'),('p4_output_capture',phase/'OUTPUT-CAPTURE.json'),
    ('p4_stdout',phase/'stdout.original'),('p4_stderr',phase/'stderr.original'),
    ('closure_plan',Path(PLAN_PATH)),('closure_result',out/'RESULT.json'),
    ('closed_original',out/'CLOSURE.original.json'),('inventory_original',out/'AFTER-INVENTORY.original.json')]:
    body=read(path,16777216)
    rows[role]={'origin':desc(path,body)}
rows['p4_joined']=dict(rows['p4_result'])
value={'schema':'hepta.native-guard.epoch-owned-host-closure-output.v2',
    'state':'ORIGINAL_INNER_CLOSER_JOINED_AND_OUTPUTS_RETAINED',
    'root_plan_sha256':sha(enc(ROOT_PLAN)),'inner_stdin':None,'originals':rows,
    'phone_calls':0,'signals_sent':0,'automatic_retry':False}
encoded=enc(value);need(len(encoded)<=65536,'complete descriptor-only closure envelope exceeds fixed output pool')
print(encoded.decode(),end='')
'''
 compile(code,'reviewed_epoch_inner_closer_producer','exec')
 return {'code':code,'phase':'epoch-close','p4_root':root,'p4_directory':root+'/epoch-close',
 'p4_argv':argv,'p4_wait_seconds':150,'p4_output_limit_bytes_per_stream':65536,
 'closure_plan_path':plan_path,'closure_out':out,'mac_wait_seconds':180,
 'mac_directory':str(Path(plan['out'])/'epoch-close')}
def epoch_close_owned(chain,closure_plan_raw):
 binding=epoch_root_binding_value()
 plan_raw=read(chain.out/'ROOT-PLAN.original.json',262144)
 need(type(chain.p) is dict and chain.p.get('schema')==binding['root_plan_schema']
 and strict(plan_raw)==chain.p and plan_raw==enc(chain.p),
 'complete retained actual Root plan required')
 identity_raw=read(chain.out/'epoch'/'IDENTITY.original.json',131072)
 identity=strict(identity_raw);original=chain.p['epoch']['identity']
 need({'bytes':len(identity_raw),'sha256':sha(identity_raw)}
 =={k:original[k] for k in ('bytes','sha256')}
 and (json.dumps(identity,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()==identity_raw
 and identity.get('schema')=='hepta.native-guard.epoch-identity.v1'
 and type(identity.get('ordinal')) is int and identity['ordinal']==chain.p['epoch']['ordinal']
 and identity.get('label')==chain.p['label'] and identity.get('nonce')==chain.p['nonce']
 and identity.get('case_id')==chain.p['case_id'] and identity.get('boot_id')==chain.p['boot_id']
 and identity.get('reservation')==chain.p['epoch']['reservation']
 and identity.get('source_generation')==chain.p['epoch']['generation'],
 'actual phone IDENTITY original does not belong to this Root closure plan')
 root_sources=epoch_root_original_sources(chain.p)
 source=root_sources['sources']['source/run_component_root_once.py']['raw']
 rendered=epoch_render_close_program(source,plan_raw,closure_plan_raw)
 close_deadline=time.monotonic()+rendered['mac_wait_seconds']
 raw=chain.execute_process('epoch-close',SSH,rendered['mac_wait_seconds'],
 rendered['code'].encode(),async_start=False)
 value=strict(raw)
 need(type(value) is dict and set(value)=={'schema','state','root_plan_sha256','inner_stdin',
 'originals','phone_calls','signals_sent','automatic_retry'}
 and value['schema']=='hepta.native-guard.epoch-owned-host-closure-output.v2'
 and value['state']=='ORIGINAL_INNER_CLOSER_JOINED_AND_OUTPUTS_RETAINED'
 and value['root_plan_sha256']==sha(enc(chain.p)) and value['inner_stdin'] is None
 and type(value['phone_calls']) is int and value['phone_calls']==0
 and type(value['signals_sent']) is int and value['signals_sent']==0
 and value['automatic_retry'] is False,
 'actual inner owned closure envelope differs')
 rows=value['originals'];need(type(rows) is dict and set(rows)=={'p4_intent','p4_child','p4_result',
 'p4_joined','p4_output_capture','p4_stdout','p4_stderr','closure_plan','closure_result',
 'closed_original','inventory_original'},'actual inner original set is incomplete')
 origins={};total=0
 for role,row in rows.items():
  need(type(row) is dict and set(row)=={'origin'},'descriptor-only actual inner output required')
  origin=row['origin']
  need(type(origin) is dict and set(origin)=={'path','bytes','sha256'}
  and type(origin['bytes']) is int and 0<=origin['bytes']<=16777216
  and type(origin['sha256']) is str and re.fullmatch('[0-9a-f]{64}',origin['sha256']),
  'complete bounded actual P4 original descriptor required')
  if role!='p4_joined':total+=origin['bytes']
  need(total<=8*1024*1024,'actual closure action bodies exceed original carrier bound')
  origins[role]=origin
 need(rows['p4_joined']==rows['p4_result'],'synchronous joined alias changed its real RESULT')
 retained=epoch_read_closed_output_bodies(chain,rendered,origins,deadline=close_deadline)
 return {'rendered':rendered,'inner':retained,'mac_stdout_original':raw,'root_sources':root_sources,
 'action_authority_verified_here':False,'component_qualified_here':False}
def epoch_read_closed_output_bodies(chain,rendered,origins,*,deadline):
 def actual_metadata(status):
  return [getattr(status,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid',
  'st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
 def remaining():
  left=deadline-time.monotonic();need(left>0,'original whole closure/retention clock exhausted')
  return min(30.0,left)
 remaining()
 phase=rendered['p4_directory'];out=rendered['closure_out']
 paths={'p4_intent':phase+'/INTENT.json','p4_child':phase+'/CHILD.json',
 'p4_result':phase+'/RESULT.json','p4_joined':phase+'/RESULT.json',
 'p4_output_capture':phase+'/OUTPUT-CAPTURE.json','p4_stdout':phase+'/stdout.original',
 'p4_stderr':phase+'/stderr.original','closure_plan':rendered['closure_plan_path'],
 'closure_result':out+'/RESULT.json','closed_original':out+'/CLOSURE.original.json',
 'inventory_original':out+'/AFTER-INVENTORY.original.json'}
 need(type(origins) is dict and set(origins)==set(paths)
 and all(origins[k]['path']==v for k,v in paths.items())
 and origins['p4_joined']==origins['p4_result'],
 'original close output set escaped its exact actual slot/nonce/phase')
 directory=chain.out/'epoch-close-carriers';newdir(directory)
 parentfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 parent_identity=actual_metadata(os.fstat(parentfd));created={};retained={}
 try:
  need(directory.resolve(strict=True)==directory
  and parent_identity==actual_metadata(directory.lstat())
  and stat.S_IMODE(parent_identity[2])==0o700
  and parent_identity[3]==os.geteuid() and parent_identity[4]==os.getegid()
  and os.listdir(parentfd)==[],'new actual Mac carrier directory identity differs')
  for role in paths:
   if role=='p4_joined':retained[role]=retained['p4_result'];continue
   origin=origins[role]
   program="""import base64,hashlib,json,os,stat
from pathlib import Path
def need(v,s):
 if not v:raise ValueError(s)
def meta(v):return [getattr(v,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
"""+'pin='+repr(origin)+'\n'+"""path=Path(pin['path']);need(path.is_absolute() and str(path)==pin['path'] and '..' not in path.parts,'canonical exact original required')
fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);parents=[(fd,None,None,meta(os.fstat(fd)))];source=None
try:
 for name in path.parts[1:-1]:
  child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);parents.append((child,fd,name,meta(os.fstat(child))));fd=child
 before=meta(os.stat(path.name,dir_fd=fd,follow_symlinks=False))
 need(stat.S_ISREG(before[2]) and before[5]==1 and before[6]==pin['bytes'] and 0<=pin['bytes']<=16777216,'exact bounded original required before open')
 source=os.open(path.name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
 need(meta(os.fstat(source))==before,'original replaced at open')
 raw=bytearray()
 while len(raw)<=pin['bytes']:
  part=os.read(source,min(65536,pin['bytes']+1-len(raw)))
  if not part:break
  raw.extend(part)
 body=bytes(raw);need(len(body)==pin['bytes'] and hashlib.sha256(body).hexdigest()==pin['sha256'],'complete original body does not match actual closer descriptor')
 need(before==meta(os.fstat(source))==meta(os.stat(path.name,dir_fd=fd,follow_symlinks=False))==meta(path.lstat()),'full held/named original changed')
 for p,parent,name,old in parents:need(meta(os.fstat(p))==old and (parent is None or meta(os.stat(name,dir_fd=parent,follow_symlinks=False))==old),'original canonical parent changed')
 result={'schema':'hepta.native-guard.epoch-closed-output-body-read.v1','origin':pin,'source_metadata':before,'body_base64':base64.b64encode(body).decode('ascii')}
 encoded=(json.dumps(result,sort_keys=True,separators=(',',':'))+'\n').encode()
 need(len(encoded)<=24*1024*1024,'complete body carrier exceeds original transport output pool')
 print(encoded.decode(),end='')
finally:
 if source is not None:os.close(source)
 for item in reversed(parents):os.close(item[0])
"""
   wire=chain.execute_process('epoch-close-read-'+role.replace('_','-'),SSH,remaining(),
   program.encode(),async_start=False)
   value=strict(wire)
   need(type(value) is dict and set(value)=={'schema','origin','source_metadata','body_base64'}
   and value['schema']=='hepta.native-guard.epoch-closed-output-body-read.v1'
   and enc(value['origin'])==enc(origin),'actual readback changed its original path or byte pin')
   text=value['body_base64']
   need(type(text) is str and len(text)<=4*((origin['bytes']+2)//3),
   'readback base64 exceeds exact original bound')
   body=base64.b64decode(text,validate=True);source_metadata=value['source_metadata']
   need(base64.b64encode(body).decode()==text and len(body)==origin['bytes']
   and sha(body)==origin['sha256'] and type(source_metadata) is list
   and len(source_metadata)==9 and all(type(v) is int for v in source_metadata)
   and stat.S_ISREG(source_metadata[2]) and source_metadata[5]==1
   and source_metadata[6]==len(body),'full actual P4 original readback differs')
   remaining()
   name=role+'.original'
   held=actual_metadata(os.fstat(parentfd))
   need(held[:5]==parent_identity[:5] and held[5]==parent_identity[5]+len(created) and held==actual_metadata(directory.lstat())
   and sorted(os.listdir(parentfd))==sorted(created),'Mac carrier parent replaced or gained an unknown member')
   filefd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
   0o600,dir_fd=parentfd)
   try:
    initial=actual_metadata(os.fstat(filefd));need(stat.S_ISREG(initial[2])
    and initial[5]==1 and initial[3:5]==[os.geteuid(),os.getegid()]
    and stat.S_IMODE(initial[2])==0o600,'new Mac carrier owner/type differs')
    at=0
    while at<len(body):
     size=os.write(filefd,body[at:at+65536]);need(size>0,'short new carrier write');at+=size
    os.fsync(filefd);os.fsync(parentfd)
    metadata=actual_metadata(os.fstat(filefd))
    need(metadata[:6]==initial[:6] and metadata[6]==len(body)
    and metadata==actual_metadata(os.stat(name,dir_fd=parentfd,follow_symlinks=False)),
    'new actual Mac carrier was replaced')
    os.lseek(filefd,0,os.SEEK_SET);readback=bytearray()
    while len(readback)<=len(body):
     part=os.read(filefd,min(65536,len(body)+1-len(readback)))
     if not part:break
     readback.extend(part)
    need(bytes(readback)==body and actual_metadata(os.fstat(filefd))==metadata,
    'new actual Mac carrier complete bytes changed')
   finally:os.close(filefd)
   pin=desc(directory/name,body);created[name]=(pin,metadata)
   retained[role]={'origin':origin,'raw':body,'origin_readback_metadata':source_metadata,
   'carrier':pin,'carrier_metadata':metadata}
  for name,(pin,metadata) in created.items():
   remaining()
   need(actual_metadata(os.stat(name,dir_fd=parentfd,follow_symlinks=False))==metadata
   and read(directory/name,pin['bytes'])==retained[name[:-9]]['raw'],
   'completed Mac carrier changed during the full readback set')
  held=actual_metadata(os.fstat(parentfd))
  need(held[:5]==parent_identity[:5] and held[5]==parent_identity[5]+len(created) and held==actual_metadata(directory.lstat())
  and sorted(os.listdir(parentfd))==sorted(created),
  'complete actual Mac carrier directory changed at final bookend')
  remaining()
  return retained
 finally:os.close(parentfd)
EPOCH_PUBLICATION_ACTOR = {'path':'/home/alex/codex-hepta-epoch-publication-actor-1ad3-source01/phone_once_stdin.py','bytes':64802,'sha256':'1f8c56efaee0c91250b88029116504d09a08395d630b4aabf3e0ba39bf1e524c'}
EPOCH_PUBLICATION_SDK = {'path':'/home/alex/codex-hepta-epoch-publication-actor-1ad3-source01/preserved_ui_package_phase_r7_stdin.py','bytes':40759,'sha256':'6da82bcb744fdc7d3757478f1182fedbf448bc024e39e0c0b428adb0212fe696'}
EPOCH_PUBLICATION_BRIDGE_TEMPLATE = {'bytes':36164,'sha256':'6952e0414ceeb0ecf9f8adce0aff731e3471e56efafddc0f4bf685df667a8060'}
def _epub_need(value, message):
 if not value:
  raise ValueError(message)
def _epub_compact(value):
 return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
 allow_nan=False)+'\n').encode('utf-8')
def _epub_strict(raw):
 def pairs(items):
  result = {}
  for key, value in items:
   _epub_need(key not in result, 'duplicate publication producer JSON key')
   result[key] = value
  return result
 return json.loads(raw, object_pairs_hook=pairs,
 parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite publication JSON')))
def _epub_sha(raw):
 return hashlib.sha256(raw).hexdigest()
def _epub_pin(value, *, full=False, maximum=16777216):
 fields = {'path', 'bytes', 'sha256'} | ({'metadata'} if full else set())
 _epub_need(type(value) is dict and set(value) == fields
 and type(value['path']) is str and Path(value['path']).is_absolute()
 and str(Path(value['path'])) == value['path'] and '..' not in Path(value['path']).parts
 and type(value['bytes']) is int and 0 <= value['bytes'] <= maximum
 and type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['sha256']),
 'complete bounded canonical publication original required')
 if full:
  meta = value['metadata']
  _epub_need(type(meta) is list and len(meta) == 9 and all(type(n) is int for n in meta)
  and stat.S_ISREG(meta[2]) and meta[5] == 1 and meta[6] == value['bytes'],
  'publication original must retain its own regular full9')
 return value
def epoch_publication_paths(nonce, actor_label):
 _epub_need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}', nonce)
 and actor_label == 'ng-'+nonce+'-epoch-publication-read',
 'publication identity or single-use actor label differs')
 root = '/home/alex/codex-native-guard-chain-r10-r1/'+nonce
 phase = root+'/epoch-publication-read'
 run = '/home/alex/razr60-local-model-v150/operations/'+actor_label
 paths = {'p4_intent':phase+'/INTENT.json', 'p4_child':phase+'/CHILD.json',
 'p4_result':phase+'/RESULT.json', 'p4_joined':phase+'/RESULT.json',
 'p4_output_capture':phase+'/OUTPUT-CAPTURE.json', 'p4_stdout':phase+'/stdout.original',
 'p4_stderr':phase+'/stderr.original', 'phone_wrapper':run+'/result.json',
 'publication_observation':run+'/PUBLICATION-OBSERVATION.original.json',
 'actor_request':root+'/epoch-publication-inputs/request.original.json'}
 for prefix, key in (('baseline-', 'sdk_baseline_'), ('', 'sdk_publication_')):
  for role, name in (('stdout','stdout.original'),('stderr','stderr.original'),
  ('incoming_wire','incoming-shell-wire.original'),
  ('smart_socket','smart-socket-responses.original')):
   paths[key+role] = run+'/'+prefix+name
 _epub_need(len(paths) == 18 and len(set(paths.values())) == 17,
 'publication original role closure changed')
 return {'root':root, 'phase':phase, 'run':run, 'paths':paths}
def epoch_publication_render_inputs(coordinator_raw, bridge_raw, plan_raw, lease_raw,
terminal_original, *, binding, actor, sdk, bridge_template, base, env):
 _epub_need(type(coordinator_raw) is bytes and type(bridge_raw) is bytes
 and len(coordinator_raw) <= 131072 and len(bridge_raw) <= 131072,
 'whole bounded actual producer and bridge source bytes required')
 plan = _epub_strict(plan_raw); lease = _epub_strict(lease_raw)
 pretty = (json.dumps(plan, sort_keys=True, indent=2, ensure_ascii=False,
 allow_nan=False)+'\n').encode()
 _epub_need(type(plan) is dict and pretty == plan_raw
 and plan.get('schema') == 'hepta.native-guard.epoch-root-plan.v1'
 and type(binding) is dict and _epub_compact(plan.get('package')) == _epub_compact(binding['runtime'])
 and _epub_compact(plan.get('combination')) == _epub_compact(binding['combination'])
 and _epub_compact(plan.get('shared_materials')) == _epub_compact(binding['shared_materials'])
 and type(plan.get('label')) is str and re.fullmatch('[a-z0-9][a-z0-9-]{5,55}', plan['label'])
 and type(plan.get('nonce')) is str and re.fullmatch('[0-9a-f]{32}', plan['nonce'])
 and plan.get('boot_id') == 'f8019f83-20a7-4f18-bea1-51c980621e4d'
 and plan.get('out') == str(Path(base)/'native-guard-root-chains-r10-r1'/plan['label']),
 'actual canonical Root publication plan/source/identity differs')
 epoch = plan.get('epoch')
 _epub_need(type(epoch) is dict and set(epoch) == {'schema','epoch_id','anchor','initialization',
 'ordinal','reservation','identity','generation'}
 and epoch['schema'] == 'hepta.native-guard.epoch-lease-binding.v1'
 and epoch['epoch_id'] == 'legacy902-active01' and type(epoch['ordinal']) is int
 and 1 <= epoch['ordinal'] <= 8, 'complete actual epoch lease-binding required')
 for name in ('anchor','initialization','reservation','identity','generation'):
  _epub_pin(epoch[name], full=True)
 _epub_need(type(lease) is dict and _epub_compact(lease) == lease_raw
 and lease.get('schema') == 'hepta.native-guard.epoch-lease.v1'
 and all(lease.get(name) == plan[name] for name in ('label','nonce','boot_id','case_id'))
 and _epub_compact(lease.get('epoch')) == _epub_compact(epoch)
 and lease.get('package_sha256') == binding['runtime']['sha256']
 and _epub_compact({k:epoch['generation'][k] for k in ('path','bytes','sha256')})
 == _epub_compact(binding['generation']), 'actual complete lease differs from Root plan')
 registry = '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-epoch-legacy902-r10-r1'
 slot = registry+'/slots/%02d' % epoch['ordinal']
 _epub_pin(terminal_original, full=True)
 _epub_need(terminal_original['path'] == slot+'/COMMIT.json'
 and epoch['identity']['path'] == slot+'/IDENTITY.json'
 and epoch['reservation']['path'] == registry+'/slots/%02d.CLAIM.json' % epoch['ordinal']
 and epoch['generation']['path'] == registry+'/generations/01.json',
 'publication must read the exact current actual COMMIT/IDENTITY/CLAIM/catalog')
 _epub_pin(actor, maximum=131072); _epub_pin(sdk, maximum=131072)
 _epub_need(Path(sdk['path']).parent == Path(actor['path']).parent
 and Path(actor['path']).name == 'phone_once_stdin.py'
 and Path(sdk['path']).name == 'preserved_ui_package_phase_r7_stdin.py',
 'actual separately reviewed actor and sibling SDK namespace differs')
 package = _epub_pin(plan['source_package'], maximum=262144)
 bridge = {'path':str(Path(package['path']).parent/'source/phone_chain_bridge.py'),
 'bytes':len(bridge_raw), 'sha256':_epub_sha(bridge_raw)}
 tree = ast.parse(bridge_raw); assignments = [n for n in tree.body if isinstance(n, ast.Assign)
 and len(n.targets)==1 and isinstance(n.targets[0], ast.Name)
 and n.targets[0].id=='EPOCH_BRIDGE_BINDING']
 _epub_need(len(assignments)==1, 'actual bridge has no unique binding literal')
 node = assignments[0].value; actual = ast.literal_eval(node)
 expected = {'schema':'hepta.native-guard.epoch-bridge-source-binding.v1',
 **{k:binding[k] for k in ('runtime','combination','shared_materials','pure_verifier',
 'source_derivation','generation')},
 'bridge_template_slots':['EPOCH_BRIDGE_BINDING'], 'template':bridge_template}
 _epub_need(_epub_compact(actual)==_epub_compact(expected),
 'actual bridge binding must derive from the same current generation')
 lines = bridge_raw.splitlines(keepends=True)
 start=sum(map(len,lines[:node.lineno-1]))+node.col_offset
 end=sum(map(len,lines[:node.end_lineno-1]))+node.end_col_offset
 unbound=bridge_raw[:start]+b'None'+bridge_raw[end:]
 _epub_need({'bytes':len(unbound),'sha256':_epub_sha(unbound)} == bridge_template,
 'whole actual bridge differs outside its reviewed one literal slot')
 observation = {'epoch_id':epoch['epoch_id'], 'boot_id':plan['boot_id'],
 'generation':epoch['generation'], 'terminal':terminal_original,
 'root_source_manifest':package, 'bridge_source':bridge}
 encoded = base64.b64encode(_epub_compact(observation)).decode('ascii')
 argv = ['phone_chain_bridge.py','epoch-publication-read','--label',plan['label'],
 '--lease-bytes',str(len(lease_raw)),'--lease-sha256',_epub_sha(lease_raw),
 '--observation-context-base64',encoded,'--execute-root-bridge-once']
 inline = 'import sys\nsys.argv='+repr(argv)+'\n'+bridge_raw.decode('utf-8','strict')
 command = env+'/usr/bin/python3 -I -B -c '+shlex.quote(inline)
 wire = ('shell,v2,raw:/debug_ramdisk/su -c '+shlex.quote(command)).encode('utf-8')
 _epub_need(len(wire) < 65536, 'complete actual publication command exceeds old shell wire bound')
 request = {'schema':'hepta.phone-local.epoch-publication-request.v1',
 'kind':'epoch_publication_read','root':True,'command':command,
 'timeout_seconds':120,'payload_budget_bytes':8388608,'expected_observation':observation}
 request_raw = _epub_compact(request)
 _epub_need(len(request_raw) <= 131072, 'whole publication request source bound')
 label = 'ng-'+plan['nonce']+'-epoch-publication-read'
 value = epoch_publication_paths(plan['nonce'], label)
 value.update(phase_name='epoch-publication-read', actor_label=label,
 actor=actor, sdk=sdk, request=request, request_raw=request_raw,
 request_path=value['paths']['actor_request'], expected_observation=observation,
 actor_argv=['/usr/bin/python3','-I','-B',actor['path'],label,value['paths']['actor_request']],
 inner_wait_seconds=150, host_wait_seconds=180, inner_stdin=None,
 root_plan_sha256=_epub_sha(plan_raw), command_wire_bytes=len(wire))
 return value
def _epub_meta(status):
 return [getattr(status, key) for key in ('st_dev','st_ino','st_mode','st_uid','st_gid',
 'st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def _epub_close_fds(fds):
 errors=[]
 for fd in reversed(fds):
  try: os.close(fd)
  except BaseException as error: errors.append(type(error).__name__)
 _epub_need(not errors, 'owned publication file close failed: '+repr(errors))
def _epub_parent_chain(path):
 _epub_need(type(path) is str and Path(path).is_absolute() and str(Path(path))==path
 and '..' not in Path(path).parts, 'canonical fixed publication host path required')
 opened=[]; rows=[]
 try:
  fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
  try: opened.append(fd)
  except BaseException: os.close(fd); raise
  current=Path('/');rows.append((fd,str(current),_epub_meta(os.fstat(fd))))
  for name in Path(path).parts[1:-1]:
   _epub_need(len(opened)<32, 'publication original ancestor descriptor bound')
   child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
   try: opened.append(child)
   except BaseException: os.close(child); raise
   current=current/name;fd=child
   rows.append((fd,str(current),_epub_meta(os.fstat(fd))))
  _epub_parent_check(rows)
  return opened,rows
 except BaseException:
  _epub_close_fds(opened);raise
def _epub_parent_check(rows):
 for fd,path,initial in rows:
  _epub_need(_epub_meta(os.fstat(fd))==initial
  and _epub_meta(os.stat(path,follow_symlinks=False))==initial
  and Path(path).resolve(strict=True)==Path(path),
  'publication original ancestor changed or became an alias')
class EpochPublicationReadSet:
 def __init__(self,deadline):
  self.deadline=deadline;self.physical_bytes=0;self.read_count=0;self.records={}
 def check(self):
  _epub_need(time.monotonic()<self.deadline,'one publication producer deadline exhausted')
 def read(self,path,maximum,expected=None,*,remember=True):
  self.check();opened,parents=_epub_parent_chain(path)
  try:
   first=_epub_meta(os.stat(Path(path).name,dir_fd=opened[-1],follow_symlinks=False))
   _epub_need(stat.S_ISREG(first[2]) and stat.S_IMODE(first[2])==0o600
   and first[3:5]==[os.geteuid(),os.getegid()] and first[5]==1
   and 0<=first[6]<=maximum and self.physical_bytes+first[6]+1<=16777216,
   'publication private regular original or shared physical read pool differs')
   _epub_need(len(opened)<32,'publication source leaf FD reservation')
   fd=os.open(Path(path).name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,
   dir_fd=opened[-1])
   try: opened.append(fd)
   except BaseException: os.close(fd);raise
   _epub_need(_epub_meta(os.fstat(fd))==first,'held publication source inode changed')
   raw=bytearray()
   while len(raw)<=first[6]:
    self.check();chunk=os.read(fd,min(65536,first[6]+1-len(raw)))
    self.physical_bytes+=len(chunk)
    _epub_need(self.physical_bytes<=16777216,'shared publication physical read pool exceeded')
    if not chunk:break
    raw.extend(chunk)
   body=bytes(raw);self.read_count+=1
   _epub_need(len(body)==first[6] and _epub_meta(os.fstat(fd))==first
   and _epub_meta(os.stat(Path(path).name,dir_fd=parents[-1][0],follow_symlinks=False))==first
   and _epub_meta(os.stat(path,follow_symlinks=False))==first
   and Path(path).resolve(strict=True)==Path(path),
   'complete publication original bytes/held/named/canonical full9 changed')
   _epub_parent_check(parents);self.check()
   value={'path':path,'bytes':len(body),'sha256':_epub_sha(body),'metadata':first}
   if expected is not None:
    _epub_pin(expected,full=('metadata' in expected),maximum=maximum)
    _epub_need(_epub_compact({k:value[k] for k in expected})==_epub_compact(expected),
    'actual publication original differs from fixed complete pin')
   parent_rows=[{'path':p,'metadata':m} for _,p,m in parents]
   if remember:
    _epub_need(path not in self.records,'publication original path was registered twice')
    self.records[path]=(value,maximum,parent_rows)
   return body,value,parent_rows
  finally:_epub_close_fds(opened)
 def recheck(self):
  for path,(pin,maximum,parents) in tuple(self.records.items()):
   _,again,again_parents=self.read(path,maximum,pin,remember=False)
   _epub_need(again==pin and again_parents==parents,
   'complete publication first/final original or ancestor full9 differs')
  self.check()
def epoch_publication_write_request(path,raw,reader):
 _epub_need(type(raw) is bytes and 0<len(raw)<=131072
 and Path(path).name=='request.original.json'
 and Path(path).parent.name=='epoch-publication-inputs', 'fixed publication request destination differs')
 directory=Path(path).parent;opened,parents=_epub_parent_chain(str(directory))
 try:
  reader.check()
  _epub_need(len(opened)+2<=32,'publication request directory/file FD reservation')
  parentfd=opened[-1];before=_epub_meta(os.fstat(parentfd))
  os.mkdir(directory.name,mode=0o700,dir_fd=parentfd)
  fd=os.open(directory.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd)
  try:opened.append(fd)
  except BaseException:os.close(fd);raise
  created=_epub_meta(os.fstat(fd));now=_epub_meta(os.fstat(parentfd))
  _epub_need(created[3:5]==[os.geteuid(),os.getegid()] and stat.S_IMODE(created[2])==0o700
  and now[:5]==before[:5] and now[5] in (before[5],before[5]+1)
  and now==_epub_meta(os.stat(directory.parent,follow_symlinks=False))
  and created==_epub_meta(os.stat(directory.name,dir_fd=parentfd,follow_symlinks=False))
  and directory.resolve(strict=True)==directory and os.listdir(fd)==[],
  'new private publication request directory identity differs')
  parents[-1]=(parentfd,parents[-1][1],now)
  _epub_parent_check(parents)
  filefd=os.open('request.original.json',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
  0o600,dir_fd=fd)
  try:opened.append(filefd)
  except BaseException:os.close(filefd);raise
  initial=_epub_meta(os.fstat(filefd));at=0
  _epub_need(initial[3:5]==[os.geteuid(),os.getegid()] and initial[5]==1
  and stat.S_ISREG(initial[2]) and stat.S_IMODE(initial[2])==0o600,
  'new publication request is not the owned private regular inode')
  while at<len(raw):
   reader.check()
   count=os.write(filefd,raw[at:at+65536]);_epub_need(count>0,'short new publication request write');at+=count
  os.fsync(filefd);os.fsync(fd);os.fsync(parentfd)
  final=_epub_meta(os.fstat(filefd));os.lseek(filefd,0,os.SEEK_SET);body=bytearray()
  _epub_need(reader.physical_bytes+len(raw)+1<=16777216,
  'request readback must fit the same producer read pool before reading')
  while len(body)<=len(raw):
   reader.check()
   part=os.read(filefd,min(65536,len(raw)+1-len(body)))
   if not part:break
   reader.physical_bytes+=len(part)
   _epub_need(reader.physical_bytes<=16777216,'request readback exceeds shared physical pool')
   body.extend(part)
  _epub_need(bytes(body)==raw and final[:6]==initial[:6]
  and final==_epub_meta(os.fstat(filefd))
  and final==_epub_meta(os.stat('request.original.json',dir_fd=fd,follow_symlinks=False))
  and final==_epub_meta(os.stat(path,follow_symlinks=False))
  and os.listdir(fd)==['request.original.json']
  and Path(path).resolve(strict=True)==Path(path),'owned whole publication request readback differs')
  directory_after=_epub_meta(os.fstat(fd))
  _epub_need(directory_after[:6]==created[:6]
  and directory_after==_epub_meta(os.stat(directory.name,dir_fd=parentfd,follow_symlinks=False))
  and directory_after==_epub_meta(os.stat(directory,follow_symlinks=False)),
  'created request directory no longer names the owned inode')
  _epub_parent_check(parents);reader.check()
  return {'path':path,'bytes':len(raw),'sha256':_epub_sha(raw),'metadata':final}
 finally:_epub_close_fds(opened)
def epoch_publication_source_sections(coordinator_raw):
 tree=ast.parse(coordinator_raw);lines=coordinator_raw.splitlines(keepends=True)
 nodes={n.name:n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
 selected=('_epub_need','_epub_compact','_epub_strict','_epub_sha','_epub_pin',
 '_epub_meta','_epub_close_fds','_epub_parent_chain','_epub_parent_check',
 'EpochPublicationReadSet','epoch_publication_write_request')
 return '\n\n'.join(b''.join(lines[nodes[name].lineno-1:nodes[name].end_lineno]).decode()
 for name in selected)+'\n'
def epoch_render_publication_program(coordinator_raw,bridge_raw,plan_raw,lease_raw,
terminal_original,*,binding,actor,sdk,bridge_template,base,env):
 value=epoch_publication_render_inputs(coordinator_raw,bridge_raw,plan_raw,lease_raw,
 terminal_original,binding=binding,actor=actor,sdk=sdk,bridge_template=bridge_template,
 base=base,env=env)
 code=epoch_owned_source_sections(coordinator_raw)+'\n'
 code+=epoch_publication_source_sections(coordinator_raw)
 code+='ACTOR='+repr(actor)+'\nSDK='+repr(sdk)+'\n'
 program_inputs={k:value[k] for k in ('root','request_path','request_raw','actor_argv',
 'paths','actor_label','run','root_plan_sha256')}
 code+='INPUTS='+repr(program_inputs)+'\n'
 code+='''deadline=time.monotonic()+175.0
reader=EpochPublicationReadSet(deadline)
actor_raw,actor_pin,_=reader.read(ACTOR['path'],131072,ACTOR)
sdk_raw,sdk_pin,_=reader.read(SDK['path'],131072,SDK)
request_pin=epoch_publication_write_request(INPUTS['request_path'],INPUTS['request_raw'],reader)
runner=EpochOwnedHostPhase(INPUTS['root'])
reader.check()
_epub_need(deadline-time.monotonic()>150,'insufficient same producer clock for the original owned actor wait')
try:
    runner.execute_process('epoch-publication-read',INPUTS['actor_argv'],150,input_raw=None,async_start=False)
except BaseException:
    runner.close_owned_host_outputs()
    raise
rows={};bodies={}
for role,path in INPUTS['paths'].items():
    if role=='p4_joined':
        rows[role]=dict(rows['p4_result']);bodies[role]=bodies['p4_result'];continue
    maximum=(2097152 if role=='publication_observation' else 131072 if role=='actor_request'
             else 70657 if role.endswith('_incoming_wire') else 8 if role.endswith('_smart_socket') else 65536)
    raw,original,_=reader.read(path,maximum,request_pin if role=='actor_request' else None)
    rows[role]={'origin':{k:original[k] for k in ('path','bytes','sha256')},'metadata':original['metadata']}
    bodies[role]=raw
final=_epub_strict(bodies['p4_stdout']);pending=_epub_strict(bodies['phone_wrapper'])
_epub_need(type(final) is dict and final.get('schema')=='hepta.phone-local.epoch-publication-summary.v1'
    and final.get('status')=='PUBLICATION_ORIGINALS_RETAINED_AND_OWNED_HOST_FDS_CLOSED'
    and final.get('label')==INPUTS['actor_label'] and final.get('run')==INPUTS['run']
    and bodies['p4_stderr']==b'' and _epub_compact(final)==bodies['p4_stdout'],
    'actual actor final complete output is absent or unsuccessful')
_epub_need(_epub_compact(final['result'])==_epub_compact(dict(rows['phone_wrapper']['origin'],
    metadata=rows['phone_wrapper']['metadata'])) and pending.get('state')==
    'PUBLICATION_WIRE_ORIGINALS_VERIFIED_PENDING_ACTOR_FD_CLOSE',
    'actor final output does not bind its exact pending original')
for prefix,key in (('baseline_transport','sdk_baseline_'),('transport','sdk_publication_')):
    for field,suffix in (('stdout_original','stdout'),('stderr_original','stderr'),
                         ('incoming_wire_original','incoming_wire'),('smart_socket_response_original','smart_socket')):
        item=rows[key+suffix]
        _epub_need(_epub_compact(pending[prefix][field])==_epub_compact(dict(item['origin'],metadata=item['metadata'])),
                   'actor pending receipt names a different actual SDK original')
item=rows['publication_observation']
_epub_need(_epub_compact(pending['publication_observation_original'])==_epub_compact(
    dict(item['origin'],metadata=item['metadata'])),'actual decoded observation source differs')
reader.recheck()
output={'schema':'hepta.native-guard.epoch-owned-publication-output.v1',
    'state':'ACTUAL_PUBLICATION_ACTOR_JOINED_AND_ORIGINALS_RETAINED',
    'root_plan_sha256':INPUTS['root_plan_sha256'],'actor_label':INPUTS['actor_label'],
    'request_sha256':_epub_sha(INPUTS['request_raw']),'inner_stdin':None,'originals':rows,
    'source_originals':{'actor':actor_pin,'sdk':sdk_pin},
    'physical_original_reads':{'bytes':reader.physical_bytes,'count':reader.read_count,
        'maximum_bytes':16777216,'first_and_final_complete':True,
        'scope':'new_source_body_readset_plus_request_readback',
        'request_readback_bytes':len(INPUTS['request_raw']),
        'owned_capture_IO_counted_here':False},
    'source_or_action_authority_verified_here':False,'automatic_retry':False,
    'new_explicit_process_signal_calls':0,'component_qualified':False}
encoded=enc(output);_epub_need(len(encoded)<=65536,'complete descriptor-only publication output exceeds owned stream bound')
reader.check()
print(encoded.decode(),end='')
'''
 _epub_need(len(code.encode('utf-8'))<=131072,
 'complete generated publication program exceeds its explicit source transport bound')
 compile(code,'reviewed_epoch_publication_producer','exec')
 value['code']=code
 return value
def epoch_publication_owned(chain,terminal_original):
 binding=epoch_root_binding_value()
 plan_raw=read(chain.out/'ROOT-PLAN.original.json',262144)
 _epub_need(enc(chain.p)==plan_raw,'actual Root publication plan original differs')
 root_sources=epoch_root_original_sources(chain.p)
 source=root_sources['sources']['source/run_component_root_once.py']['raw']
 bridge=root_sources['sources']['source/phone_chain_bridge.py']['raw']
 lease_raw=read(chain.out/'material/tree/LEASE.json',262144)
 _epub_need(type(chain.prepared) is dict and {'bytes':len(lease_raw),'sha256':sha(lease_raw)}
 =={k:chain.prepared['lease'][k] for k in ('bytes','sha256')},
 'publication must use its actual prepared complete lease')
 identity_raw=read(chain.out/'epoch/IDENTITY.original.json',131072)
 identity=_epub_strict(identity_raw);original=chain.p['epoch']['identity']
 _epub_need(_epub_compact(identity)==identity_raw
 and {'bytes':len(identity_raw),'sha256':sha(identity_raw)}=={k:original[k] for k in ('bytes','sha256')}
 and identity.get('schema')=='hepta.native-guard.epoch-identity.v1'
 and all(identity.get(k)==chain.p[k] for k in ('label','nonce','case_id','boot_id'))
 and type(identity.get('ordinal')) is int and identity['ordinal']==chain.p['epoch']['ordinal']
 and _epub_compact(identity.get('reservation'))==_epub_compact(chain.p['epoch']['reservation'])
 and _epub_compact(identity.get('source_generation'))==_epub_compact(chain.p['epoch']['generation']),
 'actual phone identity original does not belong to this single publication read')
 value=epoch_render_publication_program(source,bridge,plan_raw,lease_raw,terminal_original,
 binding=binding,actor=EPOCH_PUBLICATION_ACTOR,sdk=EPOCH_PUBLICATION_SDK,
 bridge_template=EPOCH_PUBLICATION_BRIDGE_TEMPLATE,base=B,env=ENV)
 raw=chain.execute_process('epoch-publication-read',SSH,180,value['code'].encode(),async_start=False)
 result=strict(raw)
 _epub_need(type(result) is dict and result.get('schema')=='hepta.native-guard.epoch-owned-publication-output.v1'
 and result.get('state')=='ACTUAL_PUBLICATION_ACTOR_JOINED_AND_ORIGINALS_RETAINED'
 and result.get('root_plan_sha256')==sha(plan_raw)
 and result.get('request_sha256')==sha(value['request_raw'])
 and result.get('actor_label')==value['actor_label'] and result.get('inner_stdin') is None
 and result.get('source_or_action_authority_verified_here') is False,
 'actual publication producer has not returned its source-bound complete envelope')
 rows=result.get('originals')
 _epub_need(type(rows) is dict and set(rows)==set(value['paths']),
 'actual publication original descriptor set is incomplete')
 for role,path in value['paths'].items():
  row=rows[role]
  _epub_need(type(row) is dict and set(row)=={'origin','metadata'},
  'publication origin and actual P4 metadata must remain separate')
  _epub_pin(dict(row['origin'],metadata=row['metadata']),full=True)
  _epub_need(row['origin']['path']==path,'publication original escaped its fixed phase/nonce namespace')
 _epub_need(_epub_compact(rows['p4_joined'])==_epub_compact(rows['p4_result']),
 'synchronous inner JOINED must alias its actual RESULT original')
 return {'rendered':value,'actual_producer_stdout':raw,'originals':rows,
 'root_sources':root_sources,'complete_original_body_acquisition_required':True,
 'source_or_action_authority_verified_here':False,'component_qualified':False}
if __name__=='__main__':raise SystemExit(main())
