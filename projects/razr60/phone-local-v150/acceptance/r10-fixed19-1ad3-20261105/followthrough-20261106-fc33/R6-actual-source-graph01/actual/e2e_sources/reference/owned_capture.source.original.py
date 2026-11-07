#!/usr/bin/env python3
"""E2E-only owned capture with exact reviewed Root exception finalization."""
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
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
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
    # Transfer the still-unclaimed readers to the caller under the same lock
    # used by the worker's entry handshake. A late-starting worker then exits
    # without touching closed/reused fds.
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
        # No other thread closes or reuses fds after the worker claimed them.
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

class OwnedCapture:
    def __init__(self,out):
        out=Path(out)
        need(out.is_absolute() and out.parent.resolve(strict=True)==out.parent,
             'canonical owned host capture parent required')
        need(not out.exists() and not out.is_symlink(),'owned capture directory already exists')
        newdir(out)
        self.out=out
        self.steps=[]

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
            try:rc=child.wait(timeout=min(0.005,remaining))
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

    def execute_process(self,name,argv,timeout,input_raw=None,async_start=False,command_binding=None):
        need(re.fullmatch('[a-z0-9-]{1,55}',name),'phase name')
        need(type(timeout) in (int,float) and 0<timeout<float('inf'),'finite positive host execution budget')
        need(isinstance(command_binding,dict)
            and command_binding.get('schema')=='hepta.fixed19.e2e.phase-command.v1',
            'reviewed phase command binding required before launch')
        need(set(command_binding)=={'schema','case_id','phase_kind','context_sha256',
            'owner_request_sha256','source','plan','manifest','input_originals','expected_result_state'},
            'phase command binding fields')
        need(command_binding['case_id'] in ('E2E-01','E2E-02','E2E-03','E2E-04')
            and re.fullmatch('[a-z_]{1,40}',command_binding['phase_kind'])
            and re.fullmatch('[0-9a-f]{64}',command_binding['context_sha256'])
            and re.fullmatch('[0-9a-f]{64}',command_binding['owner_request_sha256']),
            'phase subject identity')
        need(isinstance(command_binding['input_originals'],list)
            and len(command_binding['input_originals'])<=32,'bounded phase originals')
        for row in [command_binding['source'],command_binding['plan'],
                    command_binding['manifest']]+command_binding['input_originals']:
            if row is not None:pin(row)
        need(command_binding['source'] is not None and
            isinstance(command_binding['expected_result_state'],str)
            and re.fullmatch('[A-Z][A-Z0-9_]{1,119}',command_binding['expected_result_state']),
            'phase source and expected owned result state')
        need(isinstance(argv,list) and 1<=len(argv)<=96
            and all(isinstance(x,str) and '\x00' not in x and len(x)<=65536 for x in argv),
            'bounded explicit phase argv')
        d=self.out/name;newdir(d)
        intent={'schema':'hepta.native-guard.root-host-command.v1','phase':name,'argv':argv,
            'stdin_sha256':None if input_raw is None else sha(input_raw),'maximum_starts':1,
            'maximum_wait_seconds':timeout,'automatic_retry':False,'signals_on_timeout':False,
            'deadline_scope':'popen_start_through_child_join_pipe_eof_and_output_verification',
            'input_transport':'retained_readonly_regular_fd_child_reads_within_execution_budget',
            'output_transport':'owned_nonblocking_pipe_capture_worker_bounded_memory_main_thread_persistence',
            'output_limit_bytes_per_stream':HOST_OUTPUT_LIMIT,'hard_bound_on_filesystem_spawn_or_cleanup':False,
            'execution_binding':command_binding,'argv_sha256':sha((json.dumps(argv,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()),
            'stdin_original':None if input_raw is None else desc(d/'stdin.original',input_raw)}
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
                fd=os.open(d/'stdin.original',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
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
        # An orchestration failure does not release our original Popen handles.
        # Let each owned child and its existing pipe readers finish within the
        # already-recorded deadline before closing them. This never sends or
        # signals, changes a lease, or establishes remote/business qualification.
        errors=[];rows=[]
        captures=self.__dict__.setdefault('_owned_host_captures',{})
        streams=self.__dict__.setdefault('_owned_host_streams',{})
        owners=self.__dict__.setdefault('_owned_host_children',{})
        deadlines=self.__dict__.setdefault('_owned_host_deadlines',{})
        for name,child in list(owners.items()):
            capture=captures.get(name);phase_errors=[];wait_returned=False
            wait_at=None;deadline=None
            try:
                deadline=deadlines[name]
                need(type(deadline) in (int,float) and 0<deadline<float('inf'),
                    'original owned host deadline required')
                if capture is not None:
                    need(capture['child'] is child,'original failure capture child differs')
                    previous=capture['join_deadline']
                    need(type(previous) in (int,float) and 0<previous<float('inf'),
                        'original capture join deadline required')
                    deadline=min(deadline,previous)
                    capture['join_deadline']=deadline
                    wait_returned=capture['child_wait_returned']
                    wait_at=capture['child_join_at']
                if not wait_returned:
                    while True:
                        remaining=deadline-time.monotonic()
                        if remaining<=0:
                            raise subprocess.TimeoutExpired(child.args,0)
                        try:child.wait(timeout=min(0.005,remaining))
                        except subprocess.TimeoutExpired:continue
                        wait_returned=True;wait_at=time.monotonic()
                        if capture is not None:
                            capture['child_wait_returned']=True
                            capture['child_join_at']=wait_at
                        break
                need(wait_at is not None and wait_at<=deadline,
                    'original failure child wait exceeded deadline')
                if capture is not None and not capture['persist_attempted']:
                    if not capture['done'].wait(timeout=max(0.0,deadline-time.monotonic())):
                        raise subprocess.TimeoutExpired(child.args,0)
            except BaseException as error:
                phase_errors.append({'phase':name,'operation':'original_failure_join',
                    'error_type':type(error).__name__})
            if capture is not None:
                try:
                    phase_errors.extend(self.stop_host_capture(name,
                        request_stop=not capture['done'].is_set()))
                    # Completed stdout/stderr may be retained even when the
                    # child returned nonzero. This is only transport evidence.
                    if not capture['persist_attempted']:
                        capture['qualified_capture']=bool(
                            not phase_errors and wait_returned and wait_at is not None
                            and deadline is not None and wait_at<=deadline
                            and time.monotonic()<=deadline
                            and capture['worker_joined'] and capture['error'] is None
                            and all(capture['eof'].values())
                            and all(type(v) in (int,float) and v<=deadline
                                for v in capture['eof_at'].values())
                            and not capture['pipe_close_errors'])
                    phase_errors.extend(self.persist_host_capture(name))
                except BaseException as error:
                    capture['qualified_capture']=False
                    phase_errors.append({'phase':name,'operation':'failure_output_finalization',
                        'error_type':type(error).__name__})
            if name in streams:
                stdout,stderr=streams.pop(name)
                phase_errors.extend(close_streams_owned([(name+':stdout',stdout),(name+':stderr',stderr)]))
            row={'phase':name,'pid':child.pid,'returncode':child.returncode,
                'child_wait_returned':wait_returned,'child_join_observed_monotonic':wait_at,
                'execution_deadline_monotonic':deadline,
                'state':'OWNED_HOST_CHILD_JOINED_NO_BUSINESS_QUALIFICATION' if wait_returned
                    else 'OWNED_HOST_CHILD_NOT_JOINED_NO_SIGNAL_OR_RETRY',
                'automatic_retry':False,'signals_sent':0,'business_qualified':False,
                'remote_terminal_or_cleanup_proven':False,'cleanup_errors':phase_errors,
                'output_capture':capture_observation(capture) if capture is not None else None}
            rows.append(row);errors.extend(phase_errors)
            try:put(self.out/name/'OWNED-CHILD-FAILURE.json',enc(row))
            except BaseException as error:row['record_error_type']=type(error).__name__
        # A failure before Popen ownership registration may leave only local
        # readers/files. They have no child to wait and retain the old cleanup.
        for name,capture in list(captures.items()):
            if name in owners:continue
            capture['qualified_capture']=False
            errors.extend(self.stop_host_capture(name));errors.extend(self.persist_host_capture(name))
        for name,(stdout,stderr) in list(streams.items()):
            errors.extend(close_streams_owned([(name+':stdout',stdout),(name+':stderr',stderr)]));streams.pop(name,None)
        return {'stream_cleanup_errors':errors,'host_children':rows}

    def finish_async_original(self,name,child):
        """Join exactly the existing Popen and return its actual exit, including nonzero."""
        need(name in self._owned_host_captures and self._owned_host_children[name] is child,
             'original asynchronous child ownership required')
        capture=self._owned_host_captures[name];d=capture['directory']
        try:
            rc=self.join_host_capture(name,child)
            stdout,stderr=self._owned_host_streams[name]
            errors=close_streams_owned([('stdout',stdout),('stderr',stderr)])
            self._owned_host_streams.pop(name,None)
            need(not errors,'original async stream finalization failed')
            self.verify_host_capture_outputs(name)
            result={'state':'ORIGINAL_HOST_CHILD_JOINED','phase':name,'pid':child.pid,
                'returncode':rc,'stdout':filedesc(d/'stdout.original'),
                'stderr':filedesc(d/'stderr.original'),'automatic_retry':False}
            put(d/'RESULT.json',enc(result));self.steps.append(result)
            self._owned_host_children.pop(name,None)
            self._owned_host_deadlines.pop(name,None)
            self._owned_host_captures.pop(name,None)
            return result
        except BaseException as error:
            errors=self.stop_host_capture(name)
            capture['qualified_capture']=False
            errors+=self.persist_host_capture(name)
            streams=self._owned_host_streams.pop(name,None)
            if streams is not None:errors+=close_streams_owned(list(zip(('stdout','stderr'),streams)))
            row={'state':'OWNED_HOST_CHILD_NOT_QUALIFIED_NO_SIGNAL_OR_RETRY',
                'phase':name,'pid':child.pid,'child_wait_returned':capture['child_wait_returned'],
                'child_returncode':child.returncode,'error_type':type(error).__name__,
                'cleanup_errors':errors,'automatic_retry':False,'signals_sent':0,
                'output_capture':capture_observation(capture)}
            self.steps.append(row)
            try:put(d/'ASYNC-UNKNOWN.json',enc(row))
            except BaseException as e:row['record_error_type']=type(e).__name__
            raise

    def run_phase_original(self,name,argv,timeout,input_raw=None,command_binding=None):
        child,_d,_o,_e=self.execute_process(name,argv,timeout,input_raw,True,command_binding)
        return self.finish_async_original(name,child)
