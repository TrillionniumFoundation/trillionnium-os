"""Root-only one-identity orchestration of the frozen native-guard package.

Default is a host preview. No nonce is generated. The 600-second lease is
fixed only after explicit execution starts. Any unknown/failure stops without
replay, extension, second Send, or signalling an unknown process.
"""
import argparse
import importlib.abc,importlib.util,fcntl,select
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
VERIFIER_SHA='74f4c89b32b36b074971b247de1951962b45384ef821330b94656d144e512152'
VERIFIER_BYTES=126796
SENDER='aafd40345c6dc35b7b7d34ab8b04c860ebf17d326d842ed733d0404cd0a051ad'
READY_HELPER='f3b83e55a07edd370946c40cec8694f310c9713082604646d264b625e7314d99'
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
def validate_sender_marker(marker,contract_raw,prepared,owner_sha,nonce,provider_sha):
 need(marker['schema']=='hepta.native-guard.sender-prepared.v1' and marker['state']=='PREPARED_NO_SEND'
 and type(marker['send_attempt_count']) is int and marker['send_attempt_count']==0 and marker['provider_started_by_sender'] is False,
 'only the actual no-Send rendezvous admits one launch')
 need(marker['nonce']==nonce and marker['owner_request_sha256']==owner_sha
 and marker['contract_sha256']==sha(contract_raw)==prepared['sender_contract_sha256']
 and marker['provider_source_sha256']==provider_sha,'original sender prepared identity differs')
class Chain:
 def stop_host_capture(self,name,request_stop=True):
  capture=self.__dict__.setdefault('_owned_host_captures',{}).get(name)
  if capture is None:return []
  if request_stop:capture['stop'].set()
  worker=capture['thread'];errors=[]
  if worker is not None and capture['worker_start_requested'] and not capture['worker_start_failed_no_thread']:
   try:worker.join(timeout=HOST_CAPTURE_STOP_WAIT)
   except BaseException as error:
    close_unclaimed_capture_readers(capture)
    return [{'phase':name,'operation':'capture_worker_join','error_type':type(error).__name__}]
   capture['worker_joined']=capture['done'].is_set() and not worker.is_alive()
   if not capture['worker_joined']:
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
 indent=' '*methods[operations[0]].col_offset
 raw+='class EpochOwnedHostPhase:\n'+indent+'def __init__(self,out):\n'+indent*2+'self.out=Path(out);self.steps=[]\n'
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
EPOCH_PUBLICATION_BRIDGE_TEMPLATE = {'bytes': 90444, 'sha256': 'e9a9f860af8375a54d7b723ac8bdca76f3e52c8fd7513561aba644d3c541b2ed'}
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
def channel_flags(fd):
 mode = os.fstat(fd).st_mode
 need(stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode), 'actual shell pipe/socket required')
 return fcntl.fcntl(fd, fcntl.F_GETFL)
def read_stdin(size, owner):
 flags = channel_flags(0)
 fcntl.fcntl(0, fcntl.F_SETFL, flags | os.O_NONBLOCK)
 result = bytearray()
 try:
  while len(result) <= size:
   owner.check()
   left = owner.deadline - time.monotonic()
   readable, _, _ = select.select([0], [], [], max(0, min(.05, left)))
   if not readable:
    continue
   maximum = min(65536, size + 1 - len(result)); owner.reserve(maximum)
   try:
    part = os.read(0, maximum)
   except BlockingIOError:
    continue
   owner.read_bytes += len(part)
   if not part:
    return bytes(result)
   result.extend(part)
  raise ValueError('stdin exceeds exact whole input')
 finally:
  fcntl.fcntl(0, fcntl.F_SETFL, flags)
def write_channel(fd, raw, deadline, *, failure=False):
 flags = channel_flags(fd)
 fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
 position = 0
 try:
  while position < len(raw):
   left = deadline - time.monotonic()
   if left <= 0 and not failure:
    return False
   _, writable, _ = select.select([], [fd], [], max(0, min(.05, left)))
   if not writable:
    if left <= 0:
     return False
    continue
   try:
    count = os.write(fd, raw[position:position+65536])
   except BlockingIOError:
    if left <= 0:
     return False
    continue
   need(0 < count <= min(65536, len(raw)-position), 'incomplete original channel write')
   position += count
  return True
 finally:
  fcntl.fcntl(fd, fcntl.F_SETFL, flags)
EPOCH_OPERATION_ACTOR = {'bytes':86459,'sha256':'a1b0909939f0f5a5c3f7d5c33e3c2c03e8668d268c8f4f5ad46e8a3cb5cb9511'}
EPOCH_OPERATION_SDK = {'bytes': 40759, 'sha256': '6da82bcb744fdc7d3757478f1182fedbf448bc024e39e0c0b428adb0212fe696'}
EPOCH_OPERATION_LOADER = {'bytes':34083,'sha256':'6a0cdf579df10ad46f078ffc49ed240b62fe23a018c2aec913320770dc519f3e'}
EPOCH_OPERATION_NAMES = ('bootstrap-runtime','initialize','allocate','stage','scope-bind',
'launch','witness-publish','role-end','snapshot','publish','seal')
EPOCH_OPERATION_SOURCE_ROOT = '/home/alex/codex-hepta-epoch-operation-actor-1ad3-source01'
EPOCH_OPERATION_CONTROL_ROOT = '/home/alex/codex-native-guard-epoch-legacy902-1ad3-01'
def epoch_operation_paths(root, phase, actor_label):
 _epub_need(type(root) is str and (root == EPOCH_OPERATION_CONTROL_ROOT or
 re.fullmatch('/home/alex/codex-native-guard-chain-r10-r1/[0-9a-f]{32}',root))
 and type(phase) is str and re.fullmatch('[a-z0-9-]{1,55}',phase)
 and type(actor_label) is str and re.fullmatch('[a-z0-9-]{1,100}',actor_label),
 'finite actual operation namespace differs')
 directory=root+'/'+phase;inputs=root+'/'+phase+'-inputs'
 run='/home/alex/razr60-local-model-v150/operations/'+actor_label
 paths={'p4_intent':directory+'/INTENT.json','p4_child':directory+'/CHILD.json',
 'p4_result':directory+'/RESULT.json','p4_joined':directory+'/RESULT.json',
 'p4_output_capture':directory+'/OUTPUT-CAPTURE.json','p4_stdout':directory+'/stdout.original',
 'p4_stderr':directory+'/stderr.original','actor_request':root+'/'+phase+'-request/request.original.json',
 'payload_original':inputs+'/payload.original.json','phone_wrapper':run+'/result.json',
 'operation_result':run+'/OPERATION-RESULT.original.json'}
 for prefix,key in (('baseline-','sdk_baseline_'),('','sdk_operation_')):
  for role,name in (('stdout','stdout.original'),('stderr','stderr.original'),
  ('incoming_wire','incoming-shell-wire.original'),('smart_socket','smart-socket-responses.original')):
   paths[key+role]=run+'/'+prefix+name
 _epub_need(len(paths)==19 and len(set(paths.values()))==18,'finite operation role set differs')
 return {'root':root,'phase':phase,'run':run,'inputs':inputs,
 'request_directory':root+'/'+phase+'-request','paths':paths,'actor_label':actor_label}
def _eop_private_host_directory(path, reader, *, create):
 directory=Path(path);opened,parents=_epub_parent_chain(path)
 try:
  reader.check();parent=opened[-1];before=_epub_meta(os.fstat(parent))
  before_names=sorted(os.listdir(parent))
  _epub_need(len(before_names)<=8192,'bounded complete host parent names required')
  if create:
   _epub_need(directory.name not in before_names and len(opened)<32,
   'new private host directory already exists or has no FD reservation')
   os.mkdir(directory.name,mode=0o700,dir_fd=parent)
  fd=os.open(directory.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,
  dir_fd=parent)
  try:opened.append(fd)
  except BaseException:os.close(fd);raise
  actual=_epub_meta(os.fstat(fd));current=_epub_meta(os.fstat(parent))
  _epub_need(actual[3:5]==[os.geteuid(),os.getegid()] and stat.S_IMODE(actual[2])==0o700
  and actual==_epub_meta(os.stat(directory.name,dir_fd=parent,follow_symlinks=False))
  ==_epub_meta(os.lstat(directory)) and directory.resolve(strict=True)==directory,
  'actual private host directory identity differs')
  if create:
   _epub_need(current[:5]==before[:5] and sorted(os.listdir(parent))==sorted(before_names+[directory.name])
   and not os.listdir(fd),'owned new directory parent transition differs')
   parents[-1]=(parent,parents[-1][1],current);os.fsync(parent);os.fsync(fd)
  else:
   _epub_need(current==before and sorted(os.listdir(parent))==before_names,
   'existing host directory parent changed')
  _epub_parent_check(parents);reader.check()
  return {'path':path,'metadata':actual,'names':sorted(os.listdir(fd)),
  'mkdir_to_open_same_inode_proven':False if create else None}
 finally:_epub_close_fds(opened)
def _eop_write_host_original(path, raw, reader, maximum, *, members_bound=4):
 _epub_need(type(raw) is bytes and len(raw)<=maximum,'finite complete host original bound')
 opened,parents=_epub_parent_chain(path)
 try:
  reader.check();parent=opened[-1];before=_epub_meta(os.fstat(parent));names=sorted(os.listdir(parent))
  _epub_need(type(members_bound) is int and 4<=members_bound<=1024
  and Path(path).name not in names and len(names)<=members_bound and len(opened)<32,
  'bounded private input member already exists or FD bound differs')
  fd=os.open(Path(path).name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,
  0o600,dir_fd=parent)
  try:opened.append(fd)
  except BaseException:os.close(fd);raise
  initial=_epub_meta(os.fstat(fd));position=0
  _epub_need(stat.S_ISREG(initial[2]) and initial[3:6]==[os.geteuid(),os.getegid(),1]
  and stat.S_IMODE(initial[2])==0o600,'actual new private input inode differs')
  while position<len(raw):
   reader.check();count=os.write(fd,raw[position:position+65536])
   _epub_need(0<count<=min(65536,len(raw)-position),'incomplete retained input write')
   position+=count
  os.fsync(fd);os.fsync(parent);final=_epub_meta(os.fstat(fd));os.lseek(fd,0,os.SEEK_SET)
  _epub_need(reader.physical_bytes+len(raw)+1<=16777216,'same actual readback pool exhausted')
  body=bytearray()
  while len(body)<=len(raw):
   reader.check();part=os.read(fd,min(65536,len(raw)+1-len(body)));reader.physical_bytes+=len(part)
   if not part:break
   body.extend(part)
  _epub_need(bytes(body)==raw and final[:6]==initial[:6] and final==_epub_meta(os.fstat(fd))
  ==_epub_meta(os.stat(Path(path).name,dir_fd=parent,follow_symlinks=False))
  ==_epub_meta(os.lstat(path)),'actual retained stdin readback/full9 differs')
  current=_epub_meta(os.fstat(parent))
  _epub_need(current[:5]==before[:5] and sorted(os.listdir(parent))==sorted(names+[Path(path).name]),
  'owned input member changed another directory name')
  parents[-1]=(parent,parents[-1][1],current);_epub_parent_check(parents);reader.check()
  return {'path':path,'bytes':len(raw),'sha256':_epub_sha(raw),'metadata':final}
 finally:_epub_close_fds(opened)
class _EpochOperationChannel:
 def __init__(self, reader, maximum):
  self.reader=reader;self.deadline=reader.deadline;self.maximum=maximum;self.read_bytes=0
 def check(self):self.reader.check()
 def reserve(self, amount):
  self.check();_epub_need(type(amount) is int and amount>=0
  and self.read_bytes+amount<=self.maximum,'finite transport input reservation exceeded')
def epoch_render_operation_program(coordinator_raw, operation_raw, *, root, phase, actor_label,
root_plan_sha256, bridge_raw, create_root=False):
 epoch_root_template_view(coordinator_raw)
 request=_epub_strict(operation_raw)
 _epub_need(type(request) is dict and set(request)=={'schema','epoch_id','operation','boot_id','runtime','context','payload'}
 and request['schema']=='hepta.native-guard.epoch-operation-request.v1'
 and request['epoch_id']=='legacy902-active01' and request['boot_id']==BOOT
 and request['operation'] in EPOCH_OPERATION_NAMES and _epub_compact(request)==operation_raw
 and len(operation_raw)<=8388608,'complete finite operation input differs')
 _epub_need(_epub_compact(request['runtime'])==_epub_compact(epoch_root_binding_value()['runtime']),
 'operation cannot select a different runtime source generation')
 _epub_need(type(EPOCH_OPERATION_ACTOR) is dict and type(EPOCH_OPERATION_LOADER) is dict,
 'actual finite actor/loader source binding is missing')
 sources={'actor':dict(EPOCH_OPERATION_ACTOR,path=EPOCH_OPERATION_SOURCE_ROOT+'/phone_once_stdin.py'),
 'sdk':dict(EPOCH_OPERATION_SDK,path=EPOCH_OPERATION_SOURCE_ROOT+'/preserved_ui_package_phase_r7_stdin.py'),
 'loader':dict(EPOCH_OPERATION_LOADER,path=EPOCH_OPERATION_SOURCE_ROOT+'/epoch_phone_operation_loader.py')}
 for row in sources.values():_epub_pin(row,maximum=131072)
 value=epoch_operation_paths(root,phase,actor_label)
 _epub_need(type(create_root) is bool and (not create_root or request['operation'] in ('bootstrap-runtime','stage')),
 'only first code/case phase may create its fixed host root')
 value.update(operation=request['operation'],payload={'bytes':len(operation_raw),'sha256':sha(operation_raw)},
 sources=sources,root_plan_sha256=root_plan_sha256,create_root=create_root)
 tree=ast.parse(coordinator_raw);lines=coordinator_raw.splitlines(keepends=True)
 nodes={n.name:n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
 selected=('channel_flags','read_stdin','write_channel','_eop_private_host_directory',
 '_eop_write_host_original','_EpochOperationChannel')
 code=epoch_owned_source_sections(coordinator_raw)+'\nimport fcntl,select\n'+epoch_publication_source_sections(coordinator_raw)
 code+='\n\n'.join(b''.join(lines[nodes[name].lineno-1:nodes[name].end_lineno]).decode() for name in selected)+'\n'
 code+=epoch_bridge_host_worker_source(bridge_raw,'_eop_actual_worker')
 code+='INPUTS='+repr(value)+'''\nEOP_DEADLINE=time.monotonic()+175.0
try:
    _eop_actual_worker(INPUTS,EOP_DEADLINE)
except BaseException as error:
    failure=enc({'schema':'hepta.native-guard.epoch-owned-operation-failure.v1',
        'phase':INPUTS['phase'],'operation':INPUTS['operation'],
        'type':type(error).__name__,'detail':str(error)[:2048],
        'automatic_retry':False,'partial_originals_preserved':True})
    try:write_channel(2,failure,EOP_DEADLINE,failure=True)
    except BaseException:pass
    raise SystemExit(1)
'''
 _epub_need(len(code.encode())<=131072,'finite owned producer executable source bound')
 compile(code,'reviewed_epoch_operation_producer','exec')
 value['code']=code
 value['argv']=SSH[:-4]+[shlex.join(['/usr/bin/python3','-I','-B','-c',code])]
 _epub_need(len(value['argv'][-1].encode())<65536,'complete fixed SSH operation command exceeds its wire bound')
 return value
def epoch_host_deadline(seconds):
 need(type(seconds) is int and 0<seconds<=180,'fixed host operation budget required')
 end=time.monotonic()+seconds
 def check():need(time.monotonic()<end,'same original host operation budget exhausted')
 return check
EPOCH_INITIALIZE_RESULT_KEYS = ('schema','state','epoch_id','boot_id','code_receipt','anchor',
'initialization','generation','root_authorization','baseline_business_inventory',
'baseline_control_inventory','inventory_spec','inventory_observation','resource_admission',
'artifact_installation','nonces_generated','native_calls','component_qualified','business_qualified','automatic_retry')
EPOCH_ALLOCATION_RESULT_KEYS = ('schema','state','epoch_id','boot_id','ordinal','claim','directory_binding',
'identity','owner_request','allocation_admission','nonce','label','case_id','selected_session_id',
'selected_profile_id','initialization','generation','prior_boundary','predecessor_terminal',
'owner_request_utf8','scope','lease','automatic_retry','component_qualified','business_qualified')
def _epoch_local_actual(path, raw, maximum=8388608):
 need(type(raw) is bytes and len(raw)<=maximum,'new complete host original bound')
 put(Path(path),raw);held=read(Path(path),maximum)
 need(held==raw,'complete new host original changed after exclusive write')
 return dict(desc(path,raw),metadata=_epub_meta(os.lstat(path)))
def _epoch_carrier(original, raw):
 _epub_pin(original,full=('metadata' in original),maximum=64*1024*1024)
 need(type(raw) is bytes and len(raw)==original['bytes'] and sha(raw)==original['sha256'],
 'complete body differs from its actual origin')
 return {'original':{k:original[k] for k in ('path','bytes','sha256')},
 'body_base64':base64.b64encode(raw).decode()}
class EpochChain(Chain):
 def __init__(self,plan,raw,source):
  self.plan=plan;self.plan_raw=raw;self.source=source;self.sources=source['root_sources']
  self.initialize=plan['schema'].endswith('code-initialize-plan.v1')
  name='initialize' if self.initialize else 'allocate-'+plan['case_id'].lower()
  self.out=Path(plan['host_out'])/name
  parent=self.out.parent;need(parent.resolve(strict=True)==parent and stat.S_ISDIR(parent.lstat().st_mode),
  'fixed existing host control parent required')
  newdir(self.out);_epoch_local_actual(self.out/'INPUT-PLAN.original.json',raw,262144)
  self.steps=[];self.root_attempts=[];self.sender=None;self.lease=None;self.prepared=None
  self.claim_observed=False;self.identity_observed=False;self.operation_number=0;self.phone_context={}
  self.remote_root=EPOCH_OPERATION_CONTROL_ROOT;self.p=None;self.allocation=None
 def operation(self,operation,phase,payload,*,context=None,create_root=False):
  if self.p is not None and self.remote_root==EPOCH_OPERATION_CONTROL_ROOT:
   phase=self.plan['case_id'].lower()+'-'+phase
  need(operation in EPOCH_OPERATION_NAMES and re.fullmatch('[a-z0-9-]{1,55}',phase),'finite fixed operation required')
  context=self.phone_context if context is None else context
  value={'schema':'hepta.native-guard.epoch-operation-request.v1','epoch_id':'legacy902-active01',
  'operation':operation,'boot_id':BOOT,'runtime':self.plan['runtime'],'context':context,'payload':payload}
  raw=_epub_compact(value)
  label=('ng-epoch-initialize-'+phase if self.initialize else
  'ng-epoch-'+self.plan['case_id'].lower()+'-'+phase if self.p is None else 'ng-'+self.p['nonce']+'-'+phase)
  rendered=epoch_render_operation_program(self.sources['sources']['source/run_component_root_once.py']['raw'],raw,
  root=self.remote_root,phase=phase,actor_label=label,root_plan_sha256=sha(self.plan_raw),
  bridge_raw=self.sources['sources']['source/phone_chain_bridge.py']['raw'],create_root=create_root)
  self.operation_number+=1
  result=strict(self.execute_process(phase,rendered['argv'],180,input_raw=raw))
  need(result.get('schema')=='hepta.native-guard.epoch-owned-operation-output.v1'
  and result.get('state')=='ACTUAL_OPERATION_ACTOR_JOINED_AND_ORIGINALS_RETAINED'
  and result.get('operation')==operation and result.get('phase')==phase
  and result.get('actor_label')==label and result.get('root_plan_sha256')==sha(self.plan_raw)
  and result.get('payload')=={'bytes':len(raw),'sha256':sha(raw)} and result.get('automatic_retry') is False,
  'actual owned finite operation source/action chain differs')
  rows=result['originals'];need(set(rows)==set(rendered['paths']),'actual finite operation original set differs')
  for role,path in rendered['paths'].items():
   item=rows[role];_epub_pin(dict(item['origin'],metadata=item['metadata']),full=True)
   need(item['origin']['path']==path,'actual operation body escaped its fixed path')
  need(rows['p4_joined']==rows['p4_result'],'actual synchronous result alias changed')
  for role,pinrow in rendered['sources'].items():
   actual=result['source_originals'][role];_epub_pin(actual,full=True,maximum=131072)
   need(all(actual[k]==v for k,v in pinrow.items()),'operation executed a different source member')
  wire=result['operation_wire']
  need(type(wire) is dict and set(wire)=={'schema','state','epoch_id','operation','boot_id','request','result','automatic_retry'}
  and wire['schema']=='hepta.native-guard.epoch-operation-result.v1'
  and wire['state']=='OPERATION_RETURNED_COMPLETE_ORIGINAL_RESULT'
  and all(wire[k]==value[k] for k in ('epoch_id','operation','boot_id'))
  and wire['request']==result['payload'] and wire['automatic_retry'] is False,'actual complete operation wire differs')
  encoded=_epub_compact(wire);observed=rows['operation_result']['origin']
  need(len(encoded)==observed['bytes'] and sha(encoded)==observed['sha256'],
  'lossless actual phone wire differs from the retained complete body')
  _epoch_local_actual(self.out/phase/'PHONE-WIRE.original.json',encoded,65536)
  self.last_operation_request=value
  return wire['result']
 def read_phone(self,operation,name,pinrow,phase,*,context=None,maximum=8388608):
  _epub_pin(pinrow,full=True,maximum=maximum);pieces=[];offset=0
  count=max(1,(pinrow['bytes']+32767)//32768)
  for index in range(count):
   payload={'schema':'hepta.native-guard.epoch-read-original-payload.v1',
   'action':'read-chunk' if operation=='snapshot' else 'read-result' if operation=='role-end' else 'read-original',
   'name':name,'offset':offset,'limit':32768,'expected':pinrow}
   item=self.operation(operation,phase+'-%04d'%index,payload,context=context)
   need(type(item) is dict and set(item)=={'schema','state','original','offset','bytes','sha256','base64','eof'}
   and item['schema']=='hepta.native-guard.epoch-read-original-result.v1'
   and item['state']=='ACTUAL_FIXED_ORIGINAL_CHUNK_READ' and item['original']==pinrow
   and type(item['offset']) is int and item['offset']==offset and type(item['bytes']) is int
   and item['bytes']==min(32768,pinrow['bytes']-offset) and type(item['eof']) is bool,
   'actual fixed original fragment or full9 differs')
   body=base64.b64decode(item['base64'],validate=True)
   need(base64.b64encode(body).decode()==item['base64'] and len(body)==item['bytes']
   and sha(body)==item['sha256'] and item['eof']==(index==count-1),
   'actual fragment complete bytes/SHA/EOF differs')
   offset+=len(body);pieces.append(body)
  raw=b''.join(pieces);need(len(raw)==pinrow['bytes'] and sha(raw)==pinrow['sha256'],
  'complete actual original final hash differs; no reread or second operation key')
  return raw
 def result_value(self,operation,value,request=None):
  actual=self.last_operation_request
  need(actual['operation']==operation and (request is None or actual['payload']==request),
  'result validator must consume this actual complete dispatched request')
  check=epoch_host_deadline(90)
  with EpochRootHostRuntime(self.plan,budget_check=check) as runtime:
   gate=getattr(runtime.modules['stage_component'],'epoch_operation_result_value',None)
   need(callable(gate),'current source has no complete pure operation-result validator')
   check();checked=gate(operation,value,actual);check()
   need(_epub_compact(checked)==_epub_compact(value),'actual operation result interpretation changed')
  return value
 def initialize_code(self):
  roots=self.sources
  payload={'schema':'hepta.native-guard.epoch-code-bootstrap-payload.v1',
  'runtime_manifest':base64.b64encode(self.source['runtime_raw']).decode(),
  'runtime_sources':[{'path':name,'bytes':len(body),'sha256':sha(body),'body_base64':base64.b64encode(body).decode()}
  for name,body in sorted(self.source['runtime_sources'].items())],
  'root_source_manifest':_epoch_carrier(roots['manifest']['origin'],roots['manifest']['raw']),
  'root_sources':[{'path':name,'bytes':len(row['raw']),'sha256':sha(row['raw']),
  'body_base64':base64.b64encode(row['raw']).decode()} for name,row in sorted(roots['sources'].items())]}
  boot=self.operation('bootstrap-runtime','bootstrap-runtime',payload,context={
  'bootstrap_plan':self.plan['bootstrap_plan'],'root_authority':self.plan['root_authorization']},create_root=True)
  need(boot.get('schema')=='hepta.native-guard.epoch-code-bootstrap-result.v1'
  and boot.get('state')=='NEW_PRIVATE_CODE_FULLY_RETAINED','actual exclusive code installation is incomplete')
  receipt=boot['code_receipt'];_epub_pin(receipt,full=True)
  need(receipt['path']==G+'/native-guard-epoch-legacy902-r10-r1/code/01/BOOTSTRAP-CODE.json',
  'actual installed code receipt path differs')
  self.phone_context={'code_receipt':receipt}
  payload={'schema':'hepta.native-guard.epoch-initialize-payload.v1',
  'plan':_epoch_carrier(filedesc(self.out/'INPUT-PLAN.original.json'),self.plan_raw),
  'inputs':_epoch_carrier(self.plan['initialization_inputs'],pin(self.plan['initialization_inputs']))}
  initialized=self.operation('initialize','initialize',payload)
  need(set(initialized)==set(EPOCH_INITIALIZE_RESULT_KEYS)
  and initialized['schema']=='hepta.native-guard.epoch-initialization-result.v1'
  and initialized['state']=='REGISTRY_BASELINE_CREATED_NO_CASE_OR_LEASE'
  and initialized['code_receipt']==receipt and initialized['automatic_retry'] is False
  and initialized['component_qualified'] is False and initialized['business_qualified'] is False
  and type(initialized['nonces_generated']) is int and initialized['nonces_generated']==0
  and type(initialized['native_calls']) is int and initialized['native_calls']==0,
  'actual initialization must not allocate or start a native case')
  self.result_value('initialize',initialized)
  return self.finish('CODE_AND_REGISTRY_INITIALIZED_NO_CASE_OR_LEASE',{'initialization':initialized})
 def allocate(self):
  for row in self.plan['sender_inputs'].values():pin(row)
  authorization=self.plan['authorization_request'];need(pin(authorization['origin'])==authorization['utf8'].encode(),
  'actual complete preclaim authorization template differs')
  self.phone_context={k:self.plan[k] for k in ('code_receipt','initialization','generation')}
  result=self.operation('allocate','allocate-'+self.plan['case_id'].lower(),{
  'schema':'hepta.native-guard.epoch-allocate-payload.v1','action':'claim',
  'plan':_epoch_carrier(filedesc(self.out/'INPUT-PLAN.original.json'),self.plan_raw)})
  self.claim_observed=True
  need(set(result)==set(EPOCH_ALLOCATION_RESULT_KEYS)
  and result['schema']=='hepta.native-guard.epoch-allocation-result.v1'
  and result['state']=='EXCLUSIVE_CLAIM_AND_IDENTITY_CREATED_NO_SCOPE_OR_LEASE'
  and type(result['ordinal']) is int and 1<=result['ordinal']<=8
  and result['scope'] is None and result['lease'] is None and result['automatic_retry'] is False
  and result['component_qualified'] is False and result['business_qualified'] is False
  and re.fullmatch('[0-9a-f]{32}',result['nonce']) and re.fullmatch('[a-z0-9][a-z0-9-]{5,55}',result['label'])
  and all(result[k]==self.plan[k] for k in ('case_id','boot_id','selected_session_id','selected_profile_id','initialization','generation')),
  'actual durable claim/identity result differs; occupied slot is not reusable')
  self.result_value('allocate',result);self.allocation=result;self.identity_observed=True
  self.phone_context.update(reservation=result['claim'],identity=result['identity'])
  self.control_out=self.out;self.out=B/'native-guard-root-chains-r10-r1'/result['label'];newdir(self.out)
  self.p={'nonce':result['nonce'],'label':result['label']};self.remote_root=EPOCH_OPERATION_CONTROL_ROOT
  directory=self.out/'epoch';newdir(directory);members={}
  names={'claim':('CLAIM.json','CLAIM.original.json'),'directory_binding':('DIRECTORY-BINDING.json','DIRECTORY-BINDING.original.json'),
  'identity':('IDENTITY.json','IDENTITY.original.json'),'owner_request':('owner-request.original.txt','OWNER-REQUEST.original.txt'),
  'allocation_admission':('ALLOCATION-ADMISSION.json','ALLOCATION-ADMISSION.original.json')}
  for role,(name,filename) in names.items():
   raw=self.read_phone('allocate',name,result[role],'allocation-'+role.replace('_','-'),context=self.phone_context)
   carrier=_epoch_local_actual(directory/filename,raw)
   members[role]={'phone_original':result[role],'carrier':carrier}
  result_raw=_epub_compact(result);_epoch_local_actual(directory/'ALLOCATION-RESULT.original.json',result_raw)
  _epoch_local_actual(directory/'ALLOCATION-ORIGINALS.json',_epub_compact({
  'schema':'hepta.native-guard.epoch-allocation-originals.v1',
  'allocation':{'bytes':len(result_raw),'sha256':sha(result_raw)},'files':members}))
  prior=result['prior_boundary'];_epub_pin(prior,full=True)
  prior_raw=self.read_phone('allocate','PRIOR-BOUNDARY.json',prior,'allocation-prior-boundary',context=self.phone_context)
  _epoch_local_actual(directory/'PRIOR-BOUNDARY.original.json',prior_raw)
  check=epoch_host_deadline(90)
  with EpochRootHostRuntime(self.plan,budget_check=check) as runtime:
   function=getattr(runtime.modules['stage_component'],'epoch_prepare_material',None)
   need(callable(function),'actual epoch materializer is missing; old prepare/lease main is forbidden')
   _epoch_local_actual(directory/'MATERIAL-FUNCTION-INTENT.json',enc({'function':'stage_component.epoch_prepare_material',
   'source':runtime.physical['source/stage_component.py'],'plan':filedesc(self.control_out/'INPUT-PLAN.original.json'),
   'allocation':filedesc(directory/'ALLOCATION-RESULT.original.json'),'OS_child_created':False}))
   material=function(self.plan_raw,result,budget_check=check)
   need(type(material) is dict and set(material)=={'schema','state','prepared','lease','archive','root_plan','sender_inputs'}
   and material['schema']=='hepta.native-guard.epoch-material-result.v1'
   and material['state']=='ACTUAL_CLAIM_BOUND_HOST_MATERIAL_PREPARED_NOT_DEPLOYED',
   'actual epoch materializer did not return complete originals')
   _epoch_local_actual(directory/'MATERIAL-FUNCTION-RESULT.json',enc(material))
  self.p=material['root_plan']
  need(self.p.get('schema')=='hepta.native-guard.epoch-root-plan.v1'
  and self.p.get('out')==str(self.out) and all(self.p.get(k)==result[k] for k in ('nonce','label','case_id','boot_id'))
  and self.p.get('package')==self.plan['runtime'] and self.p.get('combination')==self.plan['combination']
  and self.p.get('shared_materials')==self.plan['shared_materials']
  and self.p.get('source_package')==self.plan['root_source_manifest'],
  'postclaim actual Root plan changed its source/identity/namespace')
  _epoch_local_actual(self.out/'ROOT-PLAN.original.json',enc(self.p),262144)
  self.material=self.out/'material';self.prepared=strict(pin(material['prepared']));self.lease=strict(pin(material['lease']))
  need(material['prepared']['path']==str(self.material/'PREPARED.json')
  and self.prepared['schema']=='hepta.native-guard.epoch-host-preparation.v1'
  and self.prepared['state']=='HOST_MATERIAL_ONLY_NOT_DEPLOYED'
  and self.prepared['root_detached_launcher_argv'] is None and self.prepared['root_shell_launch_fragment'] is None
  and self.prepared['finite_operation_required']=='launch'
  and material['lease']['path']==str(self.material/'tree/LEASE.json')
  and material['archive']['path']==str(self.material/'component-inputs.tar.gz')
  and self.lease['schema']=='hepta.native-guard.epoch-lease.v1'
  and self.lease['epoch']==self.p['epoch'] and self.lease['nonce']==result['nonce']
  and self.lease['label']==result['label'],'actual immutable epoch material/lease linkage differs')
  sender=material['sender_inputs'];need(set(sender)=={'request','previous','preserved_draft','retirement_resolution'},
  'complete actual sender originals required')
  need(pin(sender['request'])==result['owner_request_utf8'].encode()
  and all(sender[k]==self.plan['sender_inputs'][k] for k in ('previous','preserved_draft','retirement_resolution')),
  'materializer changed an existing sender original')
  self.sender_inputs=sender;self.material_result=material;self.remote_root='/home/alex/codex-native-guard-chain-r10-r1/'+result['nonce']
 def remaining(self,minimum=1):
  need(type(self.lease) is dict and type(self.lease['expires_unix_ms']) is int,'actual immutable epoch lease required')
  value=(self.lease['expires_unix_ms']-time.time_ns()//1000000)/1000
  need(value>minimum,'same original lease exhausted; no extension or second allocation');return value
 def host_files(self,phase,files,create=False):
  pending={};amount=0;part=0;allrows={}
  archives={k:v for k,v in files.items() if k in ('inputs/component-inputs.tar.gz','closure-inputs/ORIGINALS.tar.gz')}
  ordinary={k:v for k,v in files.items() if k not in archives}
  need(not create or ordinary,'first actual case root requires its ordinary material members')
  for name,body in sorted(ordinary.items()):
   need(len(body)<=3*1024*1024,'one complete host member exceeds this declared copy profile')
   if pending and amount+len(body)>3*1024*1024:
    allrows.update(epoch_host_io(self,phase+'-%03d'%part,files=pending,create_root=create and part==0));part+=1;pending={};amount=0
   pending[name]=body;amount+=len(body)
  if pending:allrows.update(epoch_host_io(self,phase+'-%03d'%part,files=pending,create_root=create and part==0))
  for index,(name,body) in enumerate(sorted(archives.items())):
   original=self.material_result['archive'] if name.startswith('inputs/') else desc(self.out/'ORIGINALS.tar.gz',body)
   allrows.update(epoch_host_archive(self,phase+'-archive-%d'%index,name,body,original))
  return allrows
 def host_originals(self,phase,paths,wait=None):
  rows=[{'path':p,'maximum':maximum} for p,maximum in paths.items()]
  return epoch_host_io(self,phase,originals=rows,wait_path=wait)
 def stage_material(self):
  self.remaining(480);archive=pin(self.material_result['archive']);files={}
  with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as tar:
   members=tar.getmembers();need(len(members)<=8192,'complete material archive count')
   seen=set()
   for member in members:
    name=Path(member.name);need(member.name not in seen and not name.is_absolute() and '..' not in name.parts,
    'material archive duplicate or escaped member');seen.add(member.name)
    if member.isdir():continue
    need(member.isfile() and member.size<=16777216,'material archive ordinary bounded file required')
    stream=tar.extractfile(member);body=stream.read(member.size+1);stream.close()
    need(len(body)==member.size and read(self.material/'tree'/name,16777216)==body,
    'actual material tree and complete archive member differ')
    files['material/tree/'+member.name]=body
  files['inputs/component-inputs.tar.gz']=archive
  for name in ('request','previous','preserved_draft'):files['inputs/'+name+'.original']=pin(self.sender_inputs[name])
  self.host_files('host-stage-material',files,True)
  payload={'schema':'hepta.native-guard.epoch-stage-inputs-payload.v1','action':'publish-inputs',
  'members':{'inputs.tar.gz':_epoch_carrier(self.material_result['archive'],archive),
  'stage.py':_epoch_carrier(dict(next(r for r in strict(self.source['runtime_raw'])['files']
  if r['path']=='source/stage_component.py'),path=str(Path(self.plan['runtime']['path']).parent/'source/stage_component.py')),
  self.source['runtime_sources']['source/stage_component.py'])}}
  inputs=self.operation('stage','stage-inputs',payload)
  self.result_value('stage',inputs,request=payload)
  staged=self.operation('stage','stage',{'schema':'hepta.native-guard.epoch-stage-payload.v1',
  'action':'stage','inputs':inputs})
  self.result_value('stage',staged)
  lease=staged['lease'];_epub_pin(lease,full=True)
  need({k:lease[k] for k in ('bytes','sha256')}=={k:self.material_result['lease'][k] for k in ('bytes','sha256')}
  and lease['path']==G+'/native-guard-r10-r1/'+self.p['label']+'/LEASE.json','actual staged lease differs')
  self.phone_context['lease']=lease;self.remaining(465)
 def run_sender_and_fixtures(self):
  p=self.p;sender=['/usr/bin/python3','-I','-B',str(B/'send_new_native_guard_task_r10_r4.py'),p['label'],
  self.sender_inputs['request']['path'],self.sender_inputs['previous']['path'],'--preserved-draft',
  self.sender_inputs['preserved_draft']['path'],'--retirement-resolution',self.sender_inputs['retirement_resolution']['path'],
  '--evidence-root','component','--component-contract',str(self.material/'tree/sender-contract.json'),
  '--component-package',self.plan['runtime']['path'],'--component-package-sha256',self.plan['runtime']['sha256']]
  need(sha(read(B/'send_new_native_guard_task_r10_r4.py',131072))==SENDER,'original sender source changed')
  self.execute_process('sender-preview',sender,20)
  self.sender=self.execute_process('sender-execute',sender+['--execute-once'],600,async_start=True)
  self.sender_dir='/home/alex/codex-hepta-natural-'+p['label']+'-root-v150';marker_path=self.sender_dir+'/COMPONENT-PREPARED-NO-SEND.json'
  original=self.host_originals('sender-prepared',{marker_path:65536},marker_path)[marker_path]
  marker=strict(original['raw']);provider=next(r['sha256'] for r in strict(self.source['runtime_raw'])['files']
  if r['path']=='source/component_listener.py')
  validate_sender_marker(marker,read(self.material/'tree/sender-contract.json'),self.prepared,
  self.sender_inputs['request']['sha256'],p['nonce'],provider)
  self.remaining(450)
  launched=self.operation('launch','launch',{'schema':'hepta.native-guard.epoch-launch-payload.v1','action':'start',
  'sender_prepared':_epoch_carrier(original['original'],original['raw'])})
  self.result_value('launch',launched)
  for phase in ('setup','before-guard','after-guard'):
   self.remaining(25)
   observed=self.operation('witness-publish','observe-'+phase,{
   'schema':'hepta.native-guard.epoch-observe-phase-payload.v1','action':'observe-phase','phase':phase})
   need(set(observed)=={'schema','state','phase','lease','originals','automatic_retry','component_qualified'}
   and observed['schema']=='hepta.native-guard.epoch-observe-phase-result.v1'
   and observed['state']=='ACTUAL_FIXED_PHASE_ORIGINALS_OBSERVED' and observed['phase']==phase
   and observed['lease']==self.phone_context['lease'] and observed['automatic_retry'] is False
   and observed['component_qualified'] is False,'actual fixed phase observation differs')
   names=('ACCEPTED.json','BOUND-CONTRACT.json','ROOT-'+phase.upper()+'-PLAN.json')
   need(set(observed['originals'])==set(names),'complete actual phase three-original set required')
   rawfiles={}
   for name in names:
    rawfiles[name]=self.read_phone('witness-publish',name,observed['originals'][name],
    phase+'-'+name.lower().replace('.','-'),maximum=65536)
   if phase=='setup':
    scoped=self.operation('scope-bind','scope-bind',{'schema':'hepta.native-guard.epoch-scope-bind-payload.v1',
    'action':'bind','accepted':observed['originals']['ACCEPTED.json'],
    'bound_contract':observed['originals']['BOUND-CONTRACT.json']})
    self.result_value('scope-bind',scoped)
   self.host_files('store-plan-'+phase,{'plans/'+phase+'/'+k:v for k,v in rawfiles.items()})
   directory=self.remote_root+'/plans/'+phase+'/';parent='/home/alex/codex-hepta-native-guard-fixtures-r10-r1/'+p['nonce']+'/'+phase
   argv=['--material',self.remote_root+'/material/tree','--lease-sha256',self.material_result['lease']['sha256'],
   '--package-sha256',self.plan['runtime']['sha256'],'--plan',directory+names[-1],'--plan-sha256',sha(rawfiles[names[-1]]),
   '--bound-contract',directory+'BOUND-CONTRACT.json','--bound-contract-sha256',sha(rawfiles['BOUND-CONTRACT.json']),
   '--accepted',directory+'ACCEPTED.json','--accepted-sha256',sha(rawfiles['ACCEPTED.json']),
   '--out',parent,'--execute-root-fixture-phase-once']
   phase_seconds=min(250,max(1,int(self.remaining())-5))
   _epoch_local_actual(self.out/('ROOT-FIXTURE-'+phase+'.INTENT.json'),enc({'phase':phase,'parent_out':parent,
   'expected_terminal_path':parent+'/HOST-TERMINAL.json','argv':epoch_entry_argv(self.remote_root+'/material/tree/package',
   dict(self.plan['runtime'],path=self.remote_root+'/material/tree/package/MANIFEST.json'),
   'run_root_fixture_phase',argv,actual_context='p4',seconds=phase_seconds),
   'maximum_child_starts':1,'terminal_unknown_until_actual_original_read':True,'automatic_retry':False}))
   epoch_host_entry(self,'fixture-'+phase,'run_root_fixture_phase',argv,phase_seconds)
   paths={parent+'/HOST-TERMINAL.json':65536,parent+'/actor/ORIGINAL-INDEX.json':1048576}
   retained=self.host_originals('fixture-originals-'+phase,paths);terminal=retained[parent+'/HOST-TERMINAL.json']
   value=strict(terminal['raw']);need(value['state']=='OWNED_ROOT_FIXTURE_CHILD_JOINED'
   and value['child_wait_returned'] is True and value['child_returncode']==0
   and len(value['group_absence_observations'])==2,'actual owned fixture terminal is incomplete')
   self.root_attempts.append({'phase':phase,'terminal':{k:terminal['original'][k] for k in ('path','bytes','sha256')}})
   index=retained[parent+'/actor/ORIGINAL-INDEX.json']['original'];out=self.remote_root+'/witness-'+phase
   _v,packed,_err=epoch_host_entry(self,'pack-'+phase,'witness_bundle',['pack','--plan',directory+names[-1],
   '--plan-sha256',sha(rawfiles[names[-1]]),'--original-index',index['path'],'--original-index-sha256',index['sha256'],
   '--nonce',p['nonce'],'--boot-id',BOOT,'--out',out],30)
   witness=strict(packed)['archive'];body=epoch_host_io(self,'read-witness-'+phase,originals=[witness])[witness['path']]['raw']
   published=self.operation('witness-publish','witness-'+phase,{
   'schema':'hepta.native-guard.epoch-witness-publish-payload.v1','action':'publish','phase':phase,
   'archive':_epoch_carrier(witness,body)})
   self.result_value('witness-publish',published)
  self.join_sender()
 def join_sender(self):
  child,d,so,se=self.sender
  try:rc=self.join_host_capture('sender-execute',child,maximum_wait=380)
  finally:
   errors=self.stop_host_capture('sender-execute')+self.persist_host_capture('sender-execute')
   errors+=close_streams_owned([('sender:stdout',so),('sender:stderr',se)])
   self._owned_host_streams.pop('sender-execute',None)
  need(not errors,'owned sender stream finalization failed')
  self.verify_host_capture_outputs('sender-execute')
  _epoch_local_actual(d/'JOINED.json',enc({'pid':child.pid,'returncode':rc,'wait_returned':True,'automatic_retry':False}))
  for key in ('_owned_host_children','_owned_host_deadlines','_owned_host_captures'):getattr(self,key).pop('sender-execute',None)
  need(type(rc) is int and rc==0,'original sender failed or remains unknown')
  sent=strict(read(B/(self.p['label']+'.send-result.json')))
  need(sent.get('rc')==0 and sent.get('stderr')=='','actual remote sender did not return complete success')
  original=strict(sent['stdout'].strip().splitlines()[-1])
  need(original['state']=='ORIGINAL_NATIVE_TERMINAL_OBSERVED'
  and original['draft_restore']['state']=='ORIGINAL_DRAFT_RESTORED','actual terminal/draft restoration missing')
 def close_case(self):
  ended=self.operation('role-end','role-end',{'schema':'hepta.native-guard.epoch-role-end-payload.v1','action':'request'})
  self.result_value('role-end',ended)
  snapshot=self.operation('snapshot','snapshot',{'schema':'hepta.native-guard.epoch-snapshot-payload.v1','action':'capture'})
  self.result_value('snapshot',snapshot)
  archive=snapshot['archive'];body=self.read_phone('snapshot','ORIGINALS.tar.gz',archive,'snapshot-originals',maximum=64*1024*1024)
  _epoch_local_actual(self.out/'ORIGINALS.tar.gz',body,64*1024*1024)
  hostfiles={'closure-inputs/ORIGINALS.tar.gz':body}
  for key,suffix in (('sender_host_result','.send-result.json'),('sender_local_once','.local-once.json'),('sender_actor','.actor.py')):
   hostfiles['closure-inputs/'+key+'.original']=read(B/(self.p['label']+suffix))
  self.host_files('stage-closure-inputs',hostfiles)
  closure={'schema':'hepta.native-guard.closure-plan.v1','label':self.p['label'],
  'archive':desc(self.remote_root+'/closure-inputs/ORIGINALS.tar.gz',body),
  'capture_sha256':snapshot['capture']['sha256'],
  'package':dict(self.plan['runtime'],path=self.remote_root+'/material/tree/package/MANIFEST.json'),
  'sender_dir':self.sender_dir,'root_fixture_attempts':self.root_attempts}
  for key in ('request','previous','preserved_draft'):
   closure[key]=dict(self.sender_inputs[key],path=self.remote_root+'/inputs/'+key+'.original')
  for key in ('sender_host_result','sender_local_once','sender_actor'):
   closure[key]=desc(self.remote_root+'/closure-inputs/'+key+'.original',hostfiles['closure-inputs/'+key+'.original'])
  raw=enc(closure);self.host_files('stage-closure-plan',{'CLOSURE-PLAN.json':raw})
  closed=epoch_close_owned(self,raw);authority,authority_raw=epoch_closure_authority_archive(self,closed)
  originals=closed['inner'];closed_raw=originals['closed_original']['raw'];inventory_raw=originals['inventory_original']['raw']
  _epoch_local_actual(self.out/'CLOSURE.json',closed_raw,16777216)
  _epoch_local_actual(self.out/'INVENTORY.json',inventory_raw,16777216)
  published=self.operation('publish','publish',{'schema':'hepta.native-guard.epoch-publish-payload.v1','action':'publish',
  'closure':_epoch_carrier(originals['closed_original']['origin'],closed_raw),
  'inventory':_epoch_carrier(originals['inventory_original']['origin'],inventory_raw),
  'authority':_epoch_carrier(authority,authority_raw)})
  self.result_value('publish',published)
  terminal=published['terminal'];boundary=published['boundary']
  _epub_pin(terminal,full=True);_epub_pin(boundary,full=True)
  boundary_raw=self.read_phone('publish','BOUNDARY.json',boundary,'published-boundary')
  _epoch_local_actual(self.out/'LATE-BOUNDARY.original.json',boundary_raw)
  _epoch_local_actual(self.out/'LATE-BOUNDARY-DESCRIPTOR.json',enc(boundary))
  publication=epoch_publication_owned(self,terminal)
  pins=[dict(row['origin'],metadata=row['metadata']) for role,row in publication['originals'].items() if role!='p4_joined']
  retained=epoch_host_io(self,'publication-originals',originals=pins)
  directory=self.out/'publication-originals';newdir(directory);records=[]
  for index,(path,item) in enumerate(sorted(retained.items())):
   carrier=_epoch_local_actual(directory/('%02d.original'%index),item['raw'])
   records.append({'origin':item['original'],'carrier':carrier})
  _epoch_local_actual(directory/'ORIGINALS.json',enc(records))
  value=strict(closed_raw)
  return self.finish('ACTUAL_EPOCH_COMPONENT_CLOSED_AND_PUBLISHED',{'closure':filedesc(self.out/'CLOSURE.json'),
  'boundary':boundary,'terminal':terminal,'publication_originals':filedesc(directory/'ORIGINALS.json'),
  'native_status':value['native_status'],'component_qualification_requires_consumer_action_and_current_state_gates':True})
 def finish(self,state,extra):
  value={'schema':'hepta.native-guard.epoch-root-result.v1','state':state,'epoch_id':'legacy902-active01',
  'automatic_retry':False,'new_identity_retry':False,'lease_extension':False,'component_qualified':False,
  'business_qualified':False,'claim_observed':self.claim_observed,'identity_observed':self.identity_observed,
  'steps':self.steps,**extra}
  _epoch_local_actual(self.out/'ROOT-RESULT.json',enc(value),16777216)
  print(json.dumps({k:v for k,v in value.items() if k!='steps'},sort_keys=True));return 0
 def run(self):
  if self.initialize:return self.initialize_code()
  self.allocate();self.stage_material();self.run_sender_and_fixtures();return self.close_case()
def main():
 parser=argparse.ArgumentParser(description='Explicit epoch initialization or one actual allocated native case; no legacy fallback.')
 parser.add_argument('--plan',type=Path,required=True);parser.add_argument('--plan-sha256',required=True)
 parser.add_argument('--execute-epoch-root-once',action='store_true');args=parser.parse_args()
 raw=read(args.plan,262144);need(sha(raw)==args.plan_sha256,'actual complete Root input plan pin differs')
 plan,source=epoch_preflight_plan(raw)
 if not args.execute_epoch_root_once:
  print(json.dumps({'state':'EXACT_EPOCH_SOURCE_AND_PLAN_PREVIEW_NO_ACTION','phone_calls':0,'nonces_generated':0,
  'lease_fixed':False,'actual_sources_checked':True,'plan_sha256':sha(raw)},sort_keys=True));return 0
 os.umask(0o077);chain=EpochChain(plan,raw,source)
 try:return chain.run()
 except BaseException as error:
  cleanup=chain.close_owned_host_outputs()
  value={'schema':'hepta.native-guard.epoch-root-failure.v1',
  'state':'FAILED_OR_UNKNOWN_ORIGINALS_RETAINED_NO_AUTOMATIC_CONTINUATION',
  'error_type':type(error).__name__,'detail':str(error)[:2048],'steps':chain.steps,'host_cleanup':cleanup,
  'claim_observed':chain.claim_observed,'identity_observed':chain.identity_observed,
  'occupied_or_unknown_slot_reusable':False,'rollback_attempted':False,'new_nonce_attempted_after_failure':False,
  'root_fixture_attempts':chain.root_attempts,'automatic_retry':False,'new_identity_retry':False,
  'send_again':False,'lease_extension':False,'new_explicit_process_signal_calls':0,
  'component_qualified':False,'business_qualified':False}
  _epoch_local_actual(chain.out/'ROOT-FAILURE.json',enc(value),16777216)
  raise
@contextlib.contextmanager
def epoch_root_host_support(plan, *, budget_check):
 need(callable(budget_check),'same enclosing host helper clock required');budget_check()
 originals=epoch_root_original_sources({'source_package':plan['root_source_manifest']})
 reader=EpochHostSourceReadSet(budget_check)
 entries=[originals['manifest'],*originals['sources'].values()]
 for row in entries:
  raw,_,_=reader.read(row['origin']['path'],262144,row['origin'])
  need(raw==row['raw'],'actual whole Root3 source changed before host bridge exec')
 row=originals['sources']['source/phone_chain_bridge.py']
 module=types.ModuleType('reviewed_actual_root_host_bridge')
 module.__dict__.update({'__file__':row['origin']['path'],'__actual_context__':'mac',
 '__reviewed_source_sha256__':sha(row['raw']),
 '__reviewed_root_source_manifest_raw__':originals['manifest']['raw']})
 budget_check();exec(compile(row['raw'],row['origin']['path'],'exec'),module.__dict__);budget_check()
 factory=getattr(module,'epoch_root_host_support',None)
 need(callable(factory),'actual reviewed bridge lacks its explicit host support entry')
 support=factory(sys.modules[__name__],actual_context='mac')
 try:yield support
 finally:reader.recheck();budget_check()
class EpochHostSourceReadSet(EpochPublicationReadSet):
 def __init__(self,budget_check):
  need(callable(budget_check),'same enclosing source clock required')
  self.outer_check=budget_check;self.physical_bytes=0;self.read_count=0;self.records={}
 def check(self):self.outer_check()
@contextlib.contextmanager
def EpochRootHostRuntime(plan, *, budget_check):
 with epoch_root_host_support(plan,budget_check=budget_check) as support:
  with support.EpochRootHostRuntime(plan,budget_check=budget_check) as runtime:yield runtime
def epoch_preflight_plan(raw):
 plan=strict(raw);need(type(plan) is dict and 'root_source_manifest' in plan,'explicit actual Root3 package required')
 check=epoch_host_deadline(90)
 with epoch_root_host_support(plan,budget_check=check) as support:return support.epoch_preflight_plan(raw)
def epoch_host_io(chain,phase,**kwargs):
 seconds=120 if kwargs.get('wait_path') is not None else 90
 end=time.monotonic()+seconds
 def check():need(time.monotonic()<end,'same host original transfer deadline expired')
 with epoch_root_host_support(chain.plan,budget_check=check) as support:
  return support.epoch_host_io(chain,phase,**kwargs)
def epoch_host_entry(chain,phase,entry,arguments,seconds):
 end=time.monotonic()+seconds+30
 def check():need(time.monotonic()<end,'same owned fixture entry deadline expired')
 with epoch_root_host_support(chain.plan,budget_check=check) as support:
  return support.epoch_host_entry(chain,phase,entry,arguments,seconds)
def epoch_host_archive(chain,phase,relative,raw,source_original):
 deadline=time.monotonic()+180
 def check():need(time.monotonic()<deadline,'same complete archive transfer180s clock expired')
 with epoch_root_host_support(chain.plan,budget_check=check) as support:
  return support.epoch_host_archive(chain,phase,relative,raw,source_original,deadline=deadline)
def epoch_closure_authority_archive(chain,closed):
 check=epoch_host_deadline(90)
 with epoch_root_host_support(chain.plan,budget_check=check) as support:
  return support.epoch_closure_authority_archive(chain,closed)
def epoch_publication_render_inputs(coordinator_raw,bridge_raw,plan_raw,lease_raw,terminal_original,
*,binding,actor,sdk,bridge_template,base,env):
 plan=strict(plan_raw);check=epoch_host_deadline(90)
 with epoch_root_host_support({'root_source_manifest':plan['source_package']},budget_check=check) as support:
  return support.epoch_publication_render_inputs(coordinator_raw,bridge_raw,plan_raw,lease_raw,
  terminal_original,binding=binding,actor=actor,sdk=sdk,bridge_template=bridge_template,base=base,env=env)
def epoch_bridge_host_worker_source(bridge_raw, name):
 need(type(bridge_raw) is bytes and len(bridge_raw)<=131072
 and name in ('_epoch_host_io_worker','_eop_actual_worker','_epoch_archive_host_worker'),
 'one fixed plain host worker from the actual Root bridge required')
 tree=ast.parse(bridge_raw);lines=bridge_raw.splitlines(keepends=True)
 factories=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='epoch_root_host_support']
 need(len(factories)==1,'one actual host support factory required')
 matches=[n for n in factories[0].body if isinstance(n,ast.FunctionDef) and n.name==name]
 need(len(matches)==1,'one actual host worker declaration required')
 node=matches[0];source=b''.join(lines[node.lineno-1:node.end_lineno]).decode()
 import textwrap
 source=textwrap.dedent(source)
 namespace=('need','sha','enc','strict','desc','read','put','newdir','filedesc',
 'EpochPublicationReadSet','_epub_need','_epub_strict','_epub_compact','_epub_sha','_epub_pin',
 '_epub_meta','_epub_parent_chain','_epub_parent_check','_epub_close_fds',
 '_eop_private_host_directory','_eop_write_host_original','_EpochOperationChannel',
 'EpochOwnedHostPhase','channel_flags','read_stdin','write_channel')
 needed=sorted({n.attr for n in ast.walk(node) if isinstance(n,ast.Attribute)
 and isinstance(n.value,ast.Name) and n.value.id=='api'})
 need(set(needed)<=set(namespace),'fixed bridge worker refers to an undeclared Root helper')
 return '\nimport types\napi=types.SimpleNamespace(**{k:globals()[k] for k in '+repr(tuple(needed))+'})\n'+source+'\n'
if __name__=='__main__':raise SystemExit(main())
