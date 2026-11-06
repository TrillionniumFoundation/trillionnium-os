#!/usr/bin/env python3
"""One P4 parent-owned fixture process; default host preview, no automatic retry.

The actual reviewed fixture source performs the authorized UI phase. This
parent retains a genuine child wait result so an unfinished host actor cannot
be mistaken for a closed phone lifecycle. Timeout leaves an explicit unknown;
it never signals or re-launches the child and cannot qualify safe closure.
"""
import argparse
import base64
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import component_common as C
import root_fixture_once as X
from prepare_component import host_read,write_new

ARGUMENTS=('material','lease-sha256','package-sha256','plan','plan-sha256',
           'bound-contract','bound-contract-sha256','accepted','accepted-sha256')
FIXTURE_PARENTS=Path('/home/alex/codex-hepta-native-guard-fixtures-r10-r1')


def prepare_parent_directory(nonce,phase,out):
    C.need(out==FIXTURE_PARENTS/nonce/phase,'Root fixture parent output left its exact nonce/phase namespace')
    C.need(FIXTURE_PARENTS.parent.resolve(strict=True)==FIXTURE_PARENTS.parent,
           'P4 parent namespace anchor differs')
    for path in (FIXTURE_PARENTS,FIXTURE_PARENTS/nonce):
        try:path.mkdir(mode=0o700)
        except FileExistsError:pass
        st=path.lstat()
        C.need(stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode)==0o700
               and st.st_uid==os.getuid() and st.st_gid==os.getgid()
               and path.resolve(strict=True)==path,'actual private P4 parent namespace differs')
    out.mkdir(mode=0o700)


def proc_stat_original(pid):
    fd=os.open('/proc/%d/stat'%pid,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        C.need(stat.S_ISREG(os.fstat(fd).st_mode),'P4 proc stat type differs')
        raw=os.read(fd,8193);C.need(0<len(raw)<=8192,'P4 proc stat bound')
        return raw
    finally:os.close(fd)


def host_child_identity(child):
    # This is the real P4 host child, never a phone /proc identity. Reading an
    # ancestor-mounted procfs with different local PIDs is a hard refusal.
    C.need(os.readlink('/proc/self')==str(os.getpid()),'P4 native proc self differs')
    first=proc_stat_original(child.pid);before=C.stat_identity(first,child.pid)
    group,session=os.getpgid(child.pid),os.getsid(child.pid)
    second=proc_stat_original(child.pid);after=C.stat_identity(second,child.pid)
    fields=('pid','ppid','pgid','sid','start_ticks')
    C.need(all(before[k]==after[k] for k in fields)
           and after['ppid']==os.getpid() and group==session==child.pid
           and after['pid']==after['pgid']==after['sid']==child.pid,
           'P4 owned fixture child generation or parent differs')
    return {'identity':C.generation(after),'ppid':after['ppid'],
        'proc_self_pid_matches_host':True,'stat_before':{'raw_b64':base64.b64encode(first).decode(),**C.descriptor(first)},
        'stat_after':{'raw_b64':base64.b64encode(second).decode(),**C.descriptor(second)}}


def actor_inventory(path):
    path=Path(path);parent=path.parent
    C.need(parent.resolve(strict=True)==parent,'canonical P4 output parent required')
    parent_fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(parent_fd)
        try:directory=os.stat(path.name,dir_fd=parent_fd,follow_symlinks=False)
        except FileNotFoundError:
            try:os.stat(path.name,dir_fd=parent_fd,follow_symlinks=False)
            except FileNotFoundError:pass
            else:C.need(False,'actor output appeared during absence observation')
            current=parent.lstat()
            C.need((before.st_dev,before.st_ino)==(current.st_dev,current.st_ino),
                   'P4 output parent changed')
            return {'path':str(path),'kind':'absent','absence':'ENOENT',
                'canonical_parent_identity':[before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_gid]},{}
        C.need(stat.S_ISDIR(directory.st_mode) and path.resolve(strict=True)==path,
               'actual actor output directory differs')
        names=sorted(path.iterdir());C.need(len(names)<=512,'actual actor original count bound')
        files={};total=0
        for item in names:
            before_item=item.lstat();raw=host_read(item,16*1024*1024);total+=len(raw)
            C.need(total<=64*1024*1024 and C.metadata(before_item)==C.metadata(item.lstat()),
                   'actual actor output bytes changed or exceeded bound')
            files[item.name]={'path':str(item),'metadata':C.metadata(before_item),**C.descriptor(raw)}
        C.need(C.metadata(directory)==C.metadata(path.lstat())
               and [p.name for p in names]==sorted(p.name for p in path.iterdir()),
               'actual actor original inventory changed')
        return {'path':str(path),'kind':'directory','metadata':C.metadata(directory),
                'names':[p.name for p in names]},files
    finally:os.close(parent_fd)


def run(a):
    os.umask(0o077)
    tree,lease,_combo,_cfg,plan,_commands=X.inputs(a)
    manifest=C.strict(host_read(tree/'package/MANIFEST.json'))
    rows={row['path']:row for row in manifest['files']}
    own='source/run_root_fixture_phase.py';source='source/root_fixture_once.py'
    C.need(rows[own]['sha256']==C.sha(host_read(Path(__file__))),
           'Root phase parent is not this reviewed package source')
    child_entry=tree/'package'/source;child_raw=host_read(child_entry)
    C.need(C.descriptor(child_raw)=={k:rows[source][k] for k in ('bytes','sha256')},
           'actual Root fixture child source differs')
    if not a.execute_root_fixture_phase_once:
        print(C.encoded({'schema':'hepta.native-guard.root-fixture-host-preview.v1',
            'state':'HOST_ONLY_NO_CHILD_OR_PHONE','scope':plan['scope'],'phase':plan['phase'],
            'phase_plan_sha256':a.plan_sha256,'phone_calls':0,'model_requests':0,
            'child_processes_started':0,'automatic_retry':False}).decode(),end='')
        return 0
    out=Path(a.out).absolute();prepare_parent_directory(lease['nonce'],plan['phase'],out)
    child_out=out/'actor'
    argv=['/usr/bin/python3','-I','-B',str(child_entry)]
    for key in ARGUMENTS:argv.extend(['--'+key,str(getattr(a,key.replace('-','_')))])
    argv.extend(['--out',str(child_out),'--execute-root-fixture-phase-once'])
    binding={'scope':plan['scope'],'phase':plan['phase'],'phase_plan_sha256':a.plan_sha256,
        'contract_sha256':plan['contract_sha256'],'lease_sha256':a.lease_sha256,'package_sha256':a.package_sha256,
        'child_entry':{'path':str(child_entry),**C.descriptor(child_raw)},'actor_out':str(child_out),'argv':argv}
    intent={'schema':'hepta.native-guard.root-fixture-host-intent.v1',**binding,
        'maximum_child_starts':1,'automatic_retry':False,'maximum_wait_seconds':240,
        'parent_source_sha256':C.sha(host_read(Path(__file__))), 'phone_actions_owned_by_child_only':True}
    write_new(out/'HOST-INTENT.json',C.encoded(intent))
    stdout=(out/'child.stdout').open('xb');stderr=(out/'child.stderr').open('xb')
    child=None;observed=None;failure=None;started=time.monotonic_ns();rc=None
    try:
        child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,
            start_new_session=True,close_fds=True,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8',
                'LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'})
        try:
            observed=host_child_identity(child)
            write_new(out/'HOST-CHILD.json',C.encoded({'schema':'hepta.native-guard.root-fixture-host-child.v1',
                **binding,**observed,'spawned_pid':child.pid,'parent_pid':os.getpid(),
                'p4_monotonic_observed_ns':time.monotonic_ns()}))
        except BaseException as error:
            failure={'phase':'child_identity','type':type(error).__name__,'detail':str(error)[:512]}
        try:rc=child.wait(timeout=max(.01,240-(time.monotonic_ns()-started)/1e9))
        except subprocess.TimeoutExpired:
            failure={'phase':'wait','type':'TimeoutExpired','detail':'Original actor may still be running; no signal or retry'}
    except BaseException as error:
        failure=failure or {'phase':'spawn_or_observe','type':type(error).__name__,'detail':str(error)[:512]}
    finally:
        stdout.close();stderr.close()
    # A pending actor can keep writing. Do not read those streams or make a
    # completed-file assertion when the original wait has not returned.
    joined=child is not None and type(rc) is int
    group_absence=[];directory=None;actor_files={}
    if joined and observed is not None:
        try:
            group_absence=[C.absent_groups([observed['identity']]),C.absent_groups([observed['identity']])]
            directory,actor_files=actor_inventory(child_out)
        except BaseException as error:
            failure=failure or {'phase':'original_absence_or_inventory','type':type(error).__name__,'detail':str(error)[:512]}
    result={'schema':'hepta.native-guard.root-fixture-host-terminal.v1',**binding,
        'state':'OWNED_ROOT_FIXTURE_CHILD_JOINED' if joined and observed is not None and failure is None else 'ROOT_FIXTURE_HOST_UNKNOWN',
        'child_pid':None if child is None else child.pid,'child_identity':observed,
        'child_wait_returned':joined,'child_returncode':rc,'failure':failure,
        'group_absence_observations':group_absence,'actor_directory':directory,'actor_files':actor_files,
        'p4_started_monotonic_ns':started,'p4_observed_monotonic_ns':time.monotonic_ns(),
        'automatic_retry':False,'signals_sent':0,'model_requests':0,'native_task_submissions':0,
        'parent_source_sha256':C.sha(host_read(Path(__file__))), 'component_qualified':False}
    if joined:
        for key in ('stdout','stderr'):
            path=out/('child.'+key);body=host_read(path,16*1024*1024)
            result[key]={'path':str(path),**C.descriptor(body)}
    write_new(out/'HOST-TERMINAL.json',C.encoded(result))
    print(C.encoded(result).decode(),end='')
    return 0 if joined and observed is not None and failure is None and rc==0 else 70




#!/usr/bin/env python3
"""Owned host child capture; exact 0374 function/method bodies, independent constructor."""
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

def read(p,n=65536):
    need(type(n) is int and 0 <= n <= 65536, 'bounded epoch capture receipt read')
    return X.epoch_fixture_read(p,n)

def pin(row):
    need(isinstance(row,dict) and set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int
        and row['bytes']>=0 and re.fullmatch('[0-9a-f]{64}',row['sha256']),'exact original descriptor')
    b=read(row['path']);need(len(b)==row['bytes'] and sha(b)==row['sha256'],'original pin');return b

def put(p,b):
    return epoch_parent_metadata_put(Path(p),b)

def syncdir(p):
    fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)

def newdir(p):
    return epoch_parent_capture_newdir(Path(p))

def original_stream(p):
    return epoch_parent_original_stream(Path(p))

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

HOST_OUTPUT_LIMIT=65536

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
    epoch_parent_reserve_captured_output(path,chunks,count)
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

    def execute_process(self,name,argv,timeout,input_raw=None,async_start=False,env=None):
        need(input_raw is None and env==EPOCH_PARENT_ENV and name=='fixture-child',
            'explicit one bounded epoch child environment with no stdin required')
        need(re.fullmatch('[a-z0-9-]{1,55}',name),'phase name')
        need(type(timeout) in (int,float) and 0<timeout<float('inf'),'finite positive host execution budget')
        d=self.out/name;newdir(d)
        intent={'schema':'hepta.native-guard.root-host-command.v1','phase':name,'argv':argv,
            'stdin_sha256':None if input_raw is None else sha(input_raw),'maximum_starts':1,
            'maximum_wait_seconds':timeout,'automatic_retry':False,'signals_on_timeout':False,
            'deadline_scope':'popen_start_through_child_join_pipe_eof_and_output_verification',
            'input_transport':'retained_readonly_regular_fd_child_reads_within_execution_budget',
            'output_transport':'owned_nonblocking_pipe_capture_worker_bounded_memory_main_thread_persistence',
            'output_limit_bytes_per_stream':HOST_OUTPUT_LIMIT,'hard_bound_on_filesystem_spawn_or_cleanup':False,
            'environment':dict(env)}
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
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0,start_new_session=True,close_fds=True,env=env)
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


EPOCH_PARENT_OUTPUT = None
EPOCH_PARENT_ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
                    'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}


def epoch_parent_output_start(out, profile):
    global EPOCH_PARENT_OUTPUT
    C.need(EPOCH_PARENT_OUTPUT is None and type(profile) is dict,
           'one actual parent output pool required')
    parent, name = X.epoch_fixture_parent_fd(out)
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        before = C.metadata(os.fstat(fd))
        C.need(before == C.metadata(os.stat(name, dir_fd=parent, follow_symlinks=False))
               and before[3:5] == [os.getuid(), os.getgid()] and stat.S_IMODE(before[2]) == 0o700
               and os.listdir(fd) == [], 'new private parent output directory differs')
        EPOCH_PARENT_OUTPUT = {'path': Path(out), 'fd': fd, 'identity': before[:5],
            'profile': profile, 'metadata_charged': 0, 'raw_charged': 0,
            'metadata_files': 0, 'raw_files': set(), 'put_paths': set(), 'events': [],
            'directories': {'': before[:5]},
            'maximum_metadata_files': profile['parent_metadata_files']}
        fd = None
    finally:
        if fd is not None and (EPOCH_PARENT_OUTPUT is None or EPOCH_PARENT_OUTPUT.get('fd') != fd):
            os.close(fd)
        os.close(parent)


def epoch_parent_output_check(path):
    state = EPOCH_PARENT_OUTPUT
    C.need(type(state) is dict and state['fd'] is not None, 'parent output pool is not active')
    path = Path(path)
    root = state['path']
    C.need(path.is_absolute() and '..' not in path.parts and path != root and root in path.parents,
           'parent writer left its one actual output root')
    parent, name = X.epoch_fixture_parent_fd(root)
    try:
        C.need(C.metadata(os.fstat(state['fd']))[:5] == state['identity']
               == C.metadata(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5],
               'actual parent output root was renamed or replaced')
    finally:
        os.close(parent)
    return state, path.relative_to(root).as_posix()


def epoch_parent_target_parent(path):
    state, rel = epoch_parent_output_check(path)
    parts = Path(rel).parts
    fd = os.dup(state['fd'])
    prefix = []
    try:
        for name in parts[:-1]:
            prefix.append(name); key = '/'.join(prefix)
            C.need(key in state['directories'], 'parent output ancestor was not created by this writer')
            named = C.metadata(os.stat(name, dir_fd=fd, follow_symlinks=False))
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                C.need(C.metadata(os.fstat(child)) == named
                       and named[:5] == state['directories'][key], 'owned parent output subdirectory changed')
            except BaseException:
                os.close(child); raise
            os.close(fd); fd = child
        return fd, parts[-1]
    except BaseException:
        os.close(fd); raise


def epoch_parent_metadata_put(path, body):
    C.need(type(body) is bytes, 'parent metadata must already be exactly serialized')
    state, rel = epoch_parent_output_check(path)
    allowed = {'HOST-INTENT.json', 'HOST-CHILD.json', 'HOST-TERMINAL.json', 'HOST-CLEANUP.original.json',
        'host-capture/fixture-child/INTENT.json', 'host-capture/fixture-child/CHILD.json',
        'host-capture/fixture-child/OUTPUT-CAPTURE.json', 'host-capture/fixture-child/UNKNOWN.json',
        'host-capture/fixture-child/OWNED-CHILD-FAILURE.json', 'host-capture/fixture-child/RESULT.json'}
    maximum = state['profile']['parent_terminal_bytes'] if rel == 'HOST-TERMINAL.json' else 65536
    C.need(rel in allowed and rel not in state['put_paths']
           and len(body) <= maximum and state['metadata_charged']+len(body) <= state['profile']['parent_metadata_pool_bytes']
           and state['metadata_files'] < state['maximum_metadata_files'],
           'serialized parent output exceeds fixed names/count/shared metadata pool')
    state['metadata_charged'] += len(body)
    state['metadata_files'] += 1
    state['put_paths'].add(rel)
    parent, name = epoch_parent_target_parent(path)
    fd = None
    try:
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        before = C.metadata(os.fstat(fd))
        C.need(stat.S_ISREG(before[2]) and stat.S_IMODE(before[2]) == 0o600
               and before[3:7] == [os.getuid(), os.getgid(), 1, 0]
               and before == C.metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)),
               'new parent metadata inode differs')
        pending = memoryview(body)
        while pending:
            count = os.write(fd, pending)
            C.need(count > 0, 'parent metadata write made no progress')
            pending = pending[count:]
        os.fsync(fd)
        after = C.metadata(os.fstat(fd))
        C.need(after[:6] == before[:6] and after[6] == len(body)
               and after == C.metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)),
               'new parent metadata changed during write')
        os.fsync(parent)
        epoch_parent_output_check(path)
        C.need(X.epoch_fixture_read(path, maximum) == body
               and C.metadata(os.fstat(fd)) == after,
               'actual serialized parent output readback differs')
        return {'path': str(path), 'metadata': after, **C.descriptor(body)}
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)


def epoch_parent_capture_newdir(path):
    state, rel = epoch_parent_output_check(path)
    C.need(rel in ('host-capture', 'host-capture/fixture-child'),
           'fixed parent capture subdirectory required')
    parent, name = epoch_parent_target_parent(path)
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = C.metadata(os.fstat(child))
            C.need(before[3:5] == [os.getuid(), os.getgid()] and stat.S_IMODE(before[2]) == 0o700
                   and before == C.metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                   'actual new capture directory differs')
            state['directories'][rel] = before[:5]
            os.fsync(child)
        finally:
            os.close(child)
        os.fsync(parent)
        epoch_parent_output_check(path)
    finally:
        os.close(parent)


def epoch_parent_original_stream(path):
    state, rel = epoch_parent_output_check(path)
    C.need(rel in {'host-capture/fixture-child/'+label+suffix
                   for label in ('stdout', 'stderr')
                   for suffix in ('.original', '.captured-prefix.original')}
           and rel not in state['raw_files'] and len(state['raw_files']) < 4,
           'fixed actual parent raw stream path/count required')
    state['raw_files'].add(rel)
    parent, name = epoch_parent_target_parent(path)
    fd = None
    try:
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        before = C.metadata(os.fstat(fd))
        C.need(stat.S_ISREG(before[2]) and stat.S_IMODE(before[2]) == 0o600
               and before[3:7] == [os.getuid(), os.getgid(), 1, 0]
               and before == C.metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)),
               'new original stream inode differs')
        os.fsync(fd); os.fsync(parent)
        result = os.fdopen(fd, 'w+b')
        fd = None
        return result
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)


def epoch_parent_reserve_captured_output(path, chunks, count):
    state, rel = epoch_parent_output_check(path)
    C.need(rel in state['raw_files'] and type(count) is int and 0 <= count <= 65536
           and type(chunks) is list and all(type(b) is bytes for b in chunks)
           and sum(len(b) for b in chunks) == count
           and state['raw_charged']+count <= state['profile']['parent_raw_stream_pool_bytes'],
           'parent captured bytes exceed the one actual raw pool before write')
    state['raw_charged'] += count
    state['events'].append({'path': rel, 'reserved_bytes': count})


def epoch_parent_output_close():
    state = EPOCH_PARENT_OUTPUT
    if state is None: return {'state': 'PARENT_OUTPUT_POOL_NOT_OPENED'}
    errors = []
    if state['fd'] is not None:
        fd = state['fd']; state['fd'] = None
        try:
            C.need(C.metadata(os.fstat(fd))[:5] == state['identity'], 'held parent output identity changed')
            os.fsync(fd)
        except BaseException as error:
            errors.append({'type': type(error).__name__, 'detail': str(error)[:256]})
        finally:
            try: os.close(fd)
            except BaseException as error: errors.append({'type': type(error).__name__, 'operation': 'close'})
    return {'state': 'PARENT_WRITER_OWNED_FD_CLOSED' if not errors else 'PARENT_WRITER_CLOSE_UNKNOWN',
        'errors': errors, 'metadata_bytes_reserved': state['metadata_charged'],
        'raw_bytes_reserved': state['raw_charged'], 'reservations_not_refunded': True,
        'raw_files_created_or_creation_attempted': sorted(state['raw_files'])}


def epoch_parent_actor_inventory(path, profile):
    parent, name = X.epoch_fixture_parent_fd(path)
    directory = None
    try:
        before_parent = C.metadata(os.fstat(parent))
        try: before = C.metadata(os.stat(name, dir_fd=parent, follow_symlinks=False))
        except FileNotFoundError:
            try: os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError: pass
            else: C.need(False, 'epoch actor directory appeared during absence observation')
            C.need(C.metadata(os.fstat(parent)) == before_parent, 'actor absence parent changed')
            return {'path': str(path), 'kind': 'absent', 'absence': 'ENOENT',
                    'canonical_parent_metadata': before_parent}, {}, {}
        C.need(stat.S_ISDIR(before[2]) and stat.S_IMODE(before[2]) == 0o700
               and before[3:5] == [os.getuid(), os.getgid()], 'actual private epoch actor directory differs')
        directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        C.need(C.metadata(os.fstat(directory)) == before, 'epoch actor directory changed before open')
        names = sorted(os.listdir(directory))
        C.need(len(names) <= profile['phase_files'], 'actual epoch actor output count exceeded')
        files, bodies, total, inodes = {}, {}, 0, set()
        for leaf in names:
            info = C.metadata(os.stat(leaf, dir_fd=directory, follow_symlinks=False))
            C.need(stat.S_ISREG(info[2]) and stat.S_IMODE(info[2]) == 0o600
                   and info[3:6] == [os.getuid(), os.getgid(), 1]
                   and tuple(info[:2]) not in inodes and 0 <= info[6] <= profile['phase_limits']['total']-total,
                   'actor output type/alias or shared physical byte pool differs')
            raw = X.epoch_fixture_read(path/leaf, info[6]); total += len(raw)
            C.need(C.metadata(os.stat(leaf, dir_fd=directory, follow_symlinks=False)) == info,
                   'actual epoch actor original changed')
            files[leaf] = {'path': str(path/leaf), 'metadata': info, **C.descriptor(raw)}
            bodies[leaf] = raw; inodes.add(tuple(info[:2]))
        C.need(names == sorted(os.listdir(directory)) and C.metadata(os.fstat(directory)) == before
               == C.metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)),
               'actual epoch actor closed set or full9 changed')
        fresh, leaf = X.epoch_fixture_parent_fd(path)
        try:
            C.need(C.metadata(os.fstat(fresh)) == before_parent
                   and C.metadata(os.stat(leaf, dir_fd=fresh, follow_symlinks=False)) == before,
                   'actor directory canonical path changed')
        finally: os.close(fresh)
        for leaf, raw in bodies.items():
            C.need(X.epoch_fixture_read(path/leaf, len(raw)) == raw
                   and C.metadata(os.stat(leaf, dir_fd=directory, follow_symlinks=False)) == files[leaf]['metadata'],
                   'actor original final bookend changed')
        return {'path': str(path), 'kind': 'directory', 'metadata': before, 'names': names,
                'actual_file_bytes': total}, files, bodies
    finally:
        if directory is not None: os.close(directory)
        os.close(parent)


def _run_epoch_parent(a):
    os.umask(0o077)
    tree, lease, _combo, _cfg, plan, _commands = X.epoch_inputs(a)
    manifest_raw = X.epoch_fixture_read(tree/'package/MANIFEST.json', 65536)
    rows = {row['path']: row for row in C.strict(manifest_raw)['files']}
    own_raw = X.epoch_fixture_read(Path(__file__), 131072)
    child_entry = tree/'package/source/root_fixture_once.py'
    child_raw = X.epoch_fixture_read(child_entry, 131072)
    C.need(C.descriptor(own_raw) == {k: rows['source/run_root_fixture_phase.py'][k] for k in ('bytes', 'sha256')}
           and C.descriptor(child_raw) == {k: rows['source/root_fixture_once.py'][k] for k in ('bytes', 'sha256')},
           'actual epoch parent/child source differs from all-32 package')
    profile = X.epoch_fixture_profile(plan['phase'])
    if not a.execute_root_fixture_phase_once:
        raw = C.encoded({'schema': 'hepta.epoch.root-fixture-host-preview.v1',
            'state': 'HOST_ONLY_NO_CHILD_OR_PHONE', 'phase': plan['phase'],
            'writer_profile': profile, 'writer_admission': C.descriptor(C.encoded(a._epoch_writer_admission)),
            'phone_calls': 0, 'child_processes_started': 0, 'automatic_retry': False})
        C.need(len(raw) <= 4096, 'bounded parent preview required'); print(raw.decode(), end=''); return 0
    out = Path(a.out).absolute()
    prepare_parent_directory(lease['nonce'], plan['phase'], out)
    epoch_parent_output_start(out, profile)
    child_out = out/'actor'
    argv = ['/usr/bin/python3', '-I', '-B', str(child_entry)]
    for key in ARGUMENTS: argv.extend(['--'+key, str(getattr(a, key.replace('-', '_')))])
    argv.extend(['--out', str(child_out), '--execute-root-fixture-phase-once'])
    binding = {'scope': plan['scope'], 'phase': plan['phase'], 'phase_plan_sha256': a.plan_sha256,
        'contract_sha256': plan['contract_sha256'], 'lease_sha256': a.lease_sha256,
        'package_sha256': a.package_sha256, 'child_entry': {'path': str(child_entry), **C.descriptor(child_raw)},
        'actor_out': str(child_out), 'argv': argv, 'parent_source': C.descriptor(own_raw),
        'writer_profile': profile, 'writer_admission': C.descriptor(C.encoded(a._epoch_writer_admission))}
    capture = child = observed = rc = failure = capture_receipt = None
    child_attempted = False
    started = time.monotonic_ns()
    group_absence = []; actor_directory = None; actor_files = {}; actor_bodies = {}; actor_verification = None
    cleanup = {'stream_cleanup_errors': [], 'host_children': []}
    try:
        epoch_parent_metadata_put(out/'HOST-INTENT.json', C.encoded({
            'schema': 'hepta.epoch.root-fixture-host-intent.v1', **binding,
            'maximum_child_starts': 1, 'maximum_wait_seconds': 240,
            'automatic_retry': False, 'explicit_nonzero_signal_calls': 0,
            'phone_actions_owned_by_child_only': True,
            'closing_owned_output_pipes_may_affect_child': True}))
        capture = OwnedCapture(out/'host-capture')
        child_attempted = True
        child, captured_out, stdout, stderr = capture.execute_process('fixture-child', argv, 240,
            async_start=True, env=EPOCH_PARENT_ENV)
        try:
            observed = host_child_identity(child)
            epoch_parent_metadata_put(out/'HOST-CHILD.json', C.encoded({
                'schema': 'hepta.epoch.root-fixture-host-child.v1', **binding, **observed,
                'spawned_pid': child.pid, 'parent_pid': os.getpid(),
                'p4_monotonic_observed_ns': time.monotonic_ns()}))
        except BaseException as error:
            failure = {'phase': 'child_identity', 'type': type(error).__name__, 'detail': str(error)[:512]}
        rc = capture.join_host_capture('fixture-child', child)
        close_errors = close_streams_owned([('stdout', stdout), ('stderr', stderr)])
        capture._owned_host_streams.pop('fixture-child', None)
        C.need(not close_errors, 'actual parent output close failed: '+repr(close_errors))
        capture.verify_host_capture_outputs('fixture-child')
        capture_receipt = C.strict(X.epoch_fixture_read(captured_out/'OUTPUT-CAPTURE.json', 65536))
        capture._owned_host_children.pop('fixture-child', None)
        capture._owned_host_deadlines.pop('fixture-child', None)
        capture._owned_host_captures.pop('fixture-child', None)
        if observed is not None:
            group_absence.append(C.absent_groups([observed['identity']]))
            group_absence.append(C.absent_groups([observed['identity']]))
            actor_directory, actor_files, actor_bodies = epoch_parent_actor_inventory(child_out, profile)
            if rc == 0:
                index_raw = actor_bodies['ORIGINAL-INDEX.json']; index = C.strict(index_raw)
                originals = {key: actor_bodies[Path(path).name] for key, path in index['files'].items()}
                X.W.validate_epoch_files(plan, _commands, originals, lease['nonce'], lease['boot_id'])
                actor_verification = X.LISTENER.verify_epoch_root_actor_originals(
                    actor_bodies['ACTOR-ORIGINALS.json'], X.epoch_fixture_read(a.plan, 65536), originals,
                    writer_raw=actor_bodies['OUTPUT-WRITER.original.json'], index_raw=index_raw,
                    result_raw=actor_bodies['RESULT.json'])
                proof = C.strict(actor_bodies['OUTPUT-WRITER.original.json'])
                C.need(set(actor_files) == set(proof['prefix_files']) | {'OUTPUT-WRITER.original.json'},
                       'actual actor directory contains an unaccounted writer original')
    except BaseException as error:
        failure = failure or {'phase': 'owned_capture_or_original_validation',
                              'type': type(error).__name__, 'detail': str(error)[:512]}
    finally:
        if capture is not None:
            if child is None:
                child = capture.__dict__.get('_owned_host_children', {}).get('fixture-child')
            try:
                cleanup = capture.close_owned_host_outputs()
            except BaseException as error:
                failure = failure or {'phase': 'owned_output_cleanup', 'type': type(error).__name__,
                                      'detail': str(error)[:512]}
                cleanup = {'complete': False, 'error_type': type(error).__name__,
                           'host_children_or_readers_remaining_unknown': True}
    try:
        joined = child is not None and type(child.returncode) is int
        if rc is None and joined: rc = child.returncode
        capture_complete = (capture_receipt is not None
            and capture_receipt.get('child_wait_returned') is True
            and capture_receipt.get('worker_joined') is True
            and capture_receipt.get('stdout_eof') is True and capture_receipt.get('stderr_eof') is True
            and capture_receipt.get('prefix_only_or_unknown') is False
            and capture_receipt.get('error') is None and capture_receipt.get('persist_errors') == []
            and capture_receipt.get('pipe_close_errors') == [])
        okay = (joined and observed is not None and failure is None and capture_complete and rc == 0
                and cleanup.get('stream_cleanup_errors') == [] and cleanup.get('host_children') == [])
        C.need(not okay or (len(group_absence) == 2 and actor_verification is not None),
               'complete epoch parent lacks actual group/original proof')
        epoch_parent_metadata_put(out/'HOST-CLEANUP.original.json', C.encoded(cleanup))
        result = {'schema': 'hepta.epoch.root-fixture-host-terminal.v1', **binding,
            'state': 'OWNED_EPOCH_ROOT_FIXTURE_CHILD_JOINED' if okay else 'EPOCH_ROOT_FIXTURE_HOST_FAILED_OR_UNKNOWN',
            'child_start_attempted': child_attempted, 'child_pid': None if child is None else child.pid,
            'child_identity': observed, 'child_wait_returned': joined, 'child_returncode': rc,
            'spawn_return_or_child_identity_unknown': child_attempted and child is None,
            'failure': failure, 'output_capture': capture_receipt, 'output_cleanup': cleanup,
            'group_absence_observations': group_absence, 'actor_directory': actor_directory,
            'actor_files': actor_files, 'actor_writer_verification': actor_verification,
            'p4_started_monotonic_ns': started, 'p4_observed_monotonic_ns': time.monotonic_ns(),
            'parent_metadata_bytes_reserved_before_terminal': EPOCH_PARENT_OUTPUT['metadata_charged'],
            'parent_raw_bytes_reserved': EPOCH_PARENT_OUTPUT['raw_charged'],
            'parent_raw_reservations': list(EPOCH_PARENT_OUTPUT['events']),
            'automatic_retry': False, 'explicit_nonzero_signal_calls': 0,
            'original_group_signal_zero_queries_preserved': True,
            'pipe_close_may_affect_owned_child': True, 'model_requests': 0,
            'native_task_submissions': 0, 'component_qualified': False}
        desc = epoch_parent_metadata_put(out/'HOST-TERMINAL.json', C.encoded(result))
        summary = C.encoded({'schema': 'hepta.epoch.root-fixture-host-summary.v1',
            'state': result['state'], 'terminal': {key: desc[key] for key in ('path', 'bytes', 'sha256')},
            'component_qualified': False, 'automatic_retry': False})
        C.need(len(summary) <= 4096, 'actual parent summary exceeds its writer bound')
        print(summary.decode(), end='')
        return 0 if okay else 70
    finally:
        closed = epoch_parent_output_close()
        C.need(closed.get('state') == 'PARENT_WRITER_OWNED_FD_CLOSED',
               'actual parent writer own FD cleanup is incomplete')


def run_epoch_parent(a):
    try:
        return _run_epoch_parent(a)
    finally:
        # Covers failures before capture construction and before terminal
        # serialization too. Repeating this helper never repeats an FD close.
        if EPOCH_PARENT_OUTPUT is not None and EPOCH_PARENT_OUTPUT['fd'] is not None:
            closed = epoch_parent_output_close()
            C.need(closed.get('state') == 'PARENT_WRITER_OWNED_FD_CLOSED',
                   'actual parent writer final FD cleanup is incomplete')


def main():
    parser=argparse.ArgumentParser()
    for name in (*ARGUMENTS,'out'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--execute-root-fixture-phase-once',action='store_true')
    a=parser.parse_args()
    observed=C.strict(X.epoch_fixture_pin(Path(a.material).absolute()/'LEASE.json',a.lease_sha256))
    if observed.get('schema')=='hepta.native-guard.epoch-lease.v1':return run_epoch_parent(a)
    return run(a)


if __name__=='__main__':raise SystemExit(main())
