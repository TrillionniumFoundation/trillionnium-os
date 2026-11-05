#!/usr/bin/env python3
"""Fixed Mac policy-history auditor, one owned child, complete bounded evidence.

Only the new auditor is dispatched. The retained 0374 capture methods neither
retry nor signal a child. A joined result is not external controller authority.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import threading
import time

BASE=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
SOURCE_ROOT=BASE/'epoch-policy-history-audit-source-1ad3-01'
SOURCE=SOURCE_ROOT/'run_policy_history_owned_once.py'
MANIFEST=SOURCE_ROOT/'SOURCE-MANIFEST.json'
AUDITOR={'path':str(SOURCE_ROOT/'audit_policy_history_once.py'),'bytes':30233,
    'sha256':'039f442f855ce27dc8c6f517785a4ca763b7729f1a5f17151f6a3deb2a99ef21'}
AUDIT_OUT=BASE/'epoch-policy-history-audit-1ad3-01'
OUT=BASE/'epoch-policy-history-audit-owned-1ad3-01'
PHASE='policy-history-audit'
ARGV=['/usr/bin/python3','-I','-B',AUDITOR['path'],'--execute-fixed-history-audit-once']
HOST_OUTPUT_LIMIT=65536
HOST_CAPTURE_POLL=0.025
HOST_CAPTURE_STOP_WAIT=1.0
CHILD_SECONDS=100
CALLER_SECONDS=120
READ_LIMIT=16*1024*1024
METADATA_LIMIT=512*1024
METADATA_FILE_LIMIT=65536
STREAM_POOL_LIMIT=4*HOST_OUTPUT_LIMIT
CAPTURE_READ_RESERVATION_LIMIT=4*(HOST_OUTPUT_LIMIT+1)
SOURCE_LIMIT=131072
READSET_LIMIT=1024*1024
STARTED=None
READ_BYTES=0
PARENT_NAMES_DECODED_BYTES=0
CAPTURE_READ_RESERVED=0
READ_OBSERVATIONS={}
STORE=None

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



def check_time():
    need(STARTED is not None and time.monotonic()-STARTED<=CALLER_SECONDS,
         'single caller time budget exceeded')


def full9(st):
    return [getattr(st,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid',
        'st_nlink','st_size','st_mtime_ns','st_ctime_ns')]


def close_fds(fds):
    errors=[]
    while fds:
        try:os.close(fds.pop())
        except OSError as error:errors.append(type(error).__name__)
    need(not errors,'owned directory FD close failed: '+repr(errors))


def parents(p):
    p=Path(p)
    need(p.is_absolute() and str(p)==os.fspath(p) and '..' not in p.parts
        and p.is_relative_to(BASE) and len(p.parts)<=24,'fixed bounded Mac namespace required')
    fds=[];rows=[];current=Path('/')
    try:
        fds.append(os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC))
        rows.append({'path':'/','metadata':full9(os.fstat(fds[-1]))})
        for part in p.parent.parts[1:]:
            check_time()
            before=os.stat(part,dir_fd=fds[-1],follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode),'ordinary canonical parent required')
            # Two simultaneous source-parent chains plus the two held output
            # directory FDs and at most seven capture/temporary FDs fit 64.
            need(2*(len(p.parts)-1)+9<=64,'fixed owned FD forecast exceeds 64')
            fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fds[-1])
            fds.append(fd);current/=part
            need(full9(os.fstat(fd))==full9(before),'parent changed at open')
            rows.append({'path':str(current),'metadata':full9(before)})
        return fds,rows
    except BaseException:
        close_fds(fds);raise


def read(p,n=16*1024*1024):
    global READ_BYTES
    p=Path(p);check_time()
    need(type(n) is int and 0<=n<=16*1024*1024,'bounded caller read required')
    pf,chain=parents(p);fd=None;other=[]
    try:
        first=os.stat(p.name,dir_fd=pf[-1],follow_symlinks=False)
        identity=full9(first)
        need(stat.S_ISREG(first.st_mode) and first.st_nlink==1 and 0<=first.st_size<=n
            and first.st_uid==os.geteuid() and not stat.S_IMODE(first.st_mode)&0o022,
            'private exact-size regular caller original required')
        fd=os.open(p.name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=pf[-1])
        need(full9(os.fstat(fd))==identity,'caller original changed at open')
        pieces=[];total=0
        while True:
            check_time()
            room=READ_LIMIT-READ_BYTES-CAPTURE_READ_RESERVED-PARENT_NAMES_DECODED_BYTES
            need(room>0,'caller physical read pool exhausted before read')
            part=os.read(fd,min(65536,first.st_size-total+1,room))
            READ_BYTES+=len(part)
            if not part:break
            total+=len(part);need(total<=first.st_size,'caller original grew');pieces.append(part)
        raw=b''.join(pieces)
        need(len(raw)==first.st_size and full9(os.fstat(fd))==identity
            and full9(os.stat(p.name,dir_fd=pf[-1],follow_symlinks=False))==identity,
            'caller original full9/whole-body bookend differs')
        other,reopened=parents(p)
        need(reopened==chain and all(full9(os.fstat(f))==r['metadata'] for f,r in zip(pf,chain))
            and full9(os.stat(p.name,dir_fd=other[-1],follow_symlinks=False))==identity,
            'caller original canonical parent bookend differs')
        READ_OBSERVATIONS[str(p)]={'path':str(p),'bytes':len(raw),'sha256':sha(raw),'metadata':identity,
            'parents':chain}
        return raw
    finally:
        close_fds(other)
        close_fds(pf+([fd] if fd is not None else []))


def pin(row):
    need(type(row) is dict and set(row)=={'path','bytes','sha256'}
        and type(row['bytes']) is int and 0<=row['bytes']<=16*1024*1024
        and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),
        'typed exact3 original descriptor required')
    raw=read(row['path'],row['bytes'])
    need(desc(row['path'],raw)==row,'whole fixed caller original differs')
    return raw


class OwnedStore:
    """Own the two fixed directory FDs and every create-only output leaf.

    Ancestors are canonical-identity observations. BASE has one independently
    checked child-output addition; no all-time full9 stability is claimed there.
    """
    def __init__(self):
        self.dirs={};self.members={};self.metadata_bytes=0;self.stream_reserved=0;self.names_decoded_bytes=0

    def check(self):
        check_time()
        for path,row in self.dirs.items():
            fd=row['fd'];current=full9(os.fstat(fd));pf,chain=parents(path)
            try:
                need(current==full9(os.stat(path.name,dir_fd=pf[-1],follow_symlinks=False))
                    and current[:5]==row['identity'][:5]
                    and sorted(os.listdir(fd))==sorted(row['members']),
                    'owned output directory renamed, replaced or has unknown members')
            finally:close_fds(pf)
        for path,row in self.members.items():
            info=full9(os.stat(path.name,dir_fd=self.dirs[path.parent]['fd'],follow_symlinks=False))
            if row['complete']:
                need(info==row['metadata'],'completed output member changed full9')
            else:
                need(info[:6]==row['metadata'][:6] and stat.S_ISREG(info[2]),
                    'owned stream inode or permissions changed')

    def mkdir(self,p):
        p=Path(p);check_time()
        need(p in (OUT,OUT/PHASE) and p not in self.dirs,'fixed once-only caller directory required')
        if self.dirs:self.check()
        pf,chain=parents(p);fd=None
        try:
            try:os.stat(p.name,dir_fd=pf[-1],follow_symlinks=False)
            except FileNotFoundError:pass
            else:raise ValueError('owned caller output already exists; no retry or suffix')
            os.mkdir(p.name,0o700,dir_fd=pf[-1]);os.fsync(pf[-1])
            fd=os.open(p.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=pf[-1])
            info=full9(os.fstat(fd))
            need(info==full9(os.stat(p.name,dir_fd=pf[-1],follow_symlinks=False))
                and info[3]==os.geteuid() and stat.S_IMODE(info[2])==0o700 and not os.listdir(fd),
                'new caller directory binding differs')
            self.dirs[p]={'fd':fd,'identity':info,'members':set()};fd=None
            if p.parent in self.dirs:self.dirs[p.parent]['members'].add(p.name)
        finally:close_fds(pf+([fd] if fd is not None else []))
        self.check()

    def create(self,p,*,stream=False):
        p=Path(p);self.check()
        root_names={'SOURCE-OBSERVATIONS.json','CALLER-RESULT.json','CALLER-FAILURE.json'}
        phase_names={'INTENT.json','CHILD.json','OUTPUT-CAPTURE.json','RESULT.json','UNKNOWN.json',
            'OWNED-CHILD-FAILURE.json','stdout.original','stderr.original',
            'stdout.captured-prefix.original','stderr.captured-prefix.original'}
        need(p.parent in self.dirs and p.name in (root_names if p.parent==OUT else phase_names)
            and p not in self.members,'fixed create-only caller output leaf required')
        if stream:
            need(p.name.endswith('.original'),'owned stream suffix differs')
            need(self.stream_reserved+HOST_OUTPUT_LIMIT<=STREAM_POOL_LIMIT,'owned stream pool exhausted before create')
            self.stream_reserved+=HOST_OUTPUT_LIMIT
        fd=os.open(p.name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,
                   dir_fd=self.dirs[p.parent]['fd'])
        try:
            info=full9(os.fstat(fd))
            need(info==full9(os.stat(p.name,dir_fd=self.dirs[p.parent]['fd'],follow_symlinks=False))
                and stat.S_ISREG(info[2]) and info[3]==os.geteuid()
                and stat.S_IMODE(info[2])==0o600 and info[5]==1 and info[6]==0,
                'new output held inode binding differs')
            self.members[p]={'metadata':info,'complete':False}
            self.dirs[p.parent]['members'].add(p.name)
            os.fsync(fd);os.fsync(self.dirs[p.parent]['fd'])
            self.check();return fd
        except BaseException:os.close(fd);raise

    def finish(self,p,raw,fd):
        p=Path(p);info=full9(os.fstat(fd));row=self.members[p]
        need(info[:6]==row['metadata'][:6] and info[6]==len(raw)
            and info==full9(os.stat(p.name,dir_fd=self.dirs[p.parent]['fd'],follow_symlinks=False)),
            'finished output held/named identity differs')
        row.update(metadata=info,complete=True,original=desc(p,raw))
        self.check()

    def close(self):
        fds=[r['fd'] for r in self.dirs.values()]
        self.dirs={}
        close_fds(fds)


def newdir(p):
    need(STORE is not None,'owned output store required');STORE.mkdir(p)


def syncdir(p):
    need(STORE is not None and Path(p) in STORE.dirs,'owned directory required for sync')
    os.fsync(STORE.dirs[Path(p)]['fd'])


def put(p,b):
    maximum=262144 if Path(p)==OUT/'SOURCE-OBSERVATIONS.json' else METADATA_FILE_LIMIT
    need(type(b) is bytes and len(b)<=maximum,'caller metadata file exceeds source bound before write')
    need(STORE.metadata_bytes+STORE.names_decoded_bytes+len(b)<=METADATA_LIMIT,'caller metadata pool exhausted before write')
    STORE.metadata_bytes+=len(b)
    fd=STORE.create(p)
    try:
        pending=memoryview(b)
        while pending:
            check_time();count=os.write(fd,pending);need(count>0,'output write made no progress');pending=pending[count:]
        os.fsync(fd);STORE.finish(p,b,fd)
    finally:os.close(fd)
    syncdir(Path(p).parent)
    need(read(p,len(b))==b,'complete caller output readback differs')


def original_stream(p):
    fd=STORE.create(p,stream=True)
    try:return os.fdopen(fd,'w+b')
    except BaseException:os.close(fd);raise


# Lossless directory-name data only. It neither authorizes nor reads a path.
def parent_names_wire(value):
    return (json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode('utf-8','strict')


def parent_names_decode(value):
    need(type(value) is dict and set(value)=={'schema','encoding','count','decoded','rows'}
        and value['schema']=='hepta.directory-name-prefix-table.v1'
        and value['encoding']=='unicode-prefix-length-and-suffix',
        'fixed parent name data encoding required')
    need(type(value['count']) is int and 0<=value['count']<=4096
        and type(value['rows']) is list and len(value['rows'])==value['count'],
        'original name count bound exceeded')
    pin=value['decoded']
    need(type(pin) is dict and set(pin)=={'bytes','sha256'} and type(pin['bytes']) is int
        and 3<=pin['bytes']<=524288 and type(pin['sha256']) is str
        and re.fullmatch('[0-9a-f]{64}',pin['sha256']),
        'bounded full decoded name descriptor required')
    need(len(parent_names_wire(value))<=65536,'prefix data exceeds original serialized field bound')
    names=[];previous='';decoded_charge=3
    for row in value['rows']:
        need(type(row) is list and len(row)==2 and type(row[0]) is int
            and 0<=row[0]<=len(previous) and type(row[1]) is str,
            'typed bounded prefix/suffix row required')
        name=previous[:row[0]]+row[1]
        need(name and '/' not in name and '\x00' not in name and name not in ('.','..')
            and (not names or previous<name),'complete names must be strict sorted unique basenames')
        common=0
        while common<min(len(previous),len(name)) and previous[common]==name[common]:common+=1
        need(row[0]==common,'prefix length must be canonical maximal common prefix')
        decoded_charge+=len(parent_names_wire(name))-1+(1 if names else 0)
        need(decoded_charge<=pin['bytes']<=524288,'decoded names exceed bounded original bytes')
        names.append(name);previous=name
    raw=parent_names_wire(names)
    need(len(raw)==pin['bytes'] and sha(raw)==pin['sha256'],'complete decoded names bytes/SHA differ')
    return names


def parent_names_encode(names):
    need(type(names) is list and len(names)<=4096 and all(type(x) is str for x in names)
        and names==sorted(set(names)),'original complete name count/order differs')
    raw=parent_names_wire(names)
    need(len(raw)<=524288,'complete decoded parent names exceed the shared metadata pool')
    rows=[];previous=''
    for name in names:
        common=0
        while common<min(len(previous),len(name)) and previous[common]==name[common]:common+=1
        rows.append([common,name[common:]]);previous=name
    value={'schema':'hepta.directory-name-prefix-table.v1','encoding':'unicode-prefix-length-and-suffix',
        'count':len(names),'decoded':{'bytes':len(raw),'sha256':sha(raw)},'rows':rows}
    need(len(parent_names_wire(value))<=65536 and parent_names_decode(value)==names,
        'lossless complete prefix data exceeds original serialized field bound')
    return value


def ancestor_observation():
    global PARENT_NAMES_DECODED_BYTES
    pf,chain=parents(SOURCE)
    try:
        index=next(i for i,r in enumerate(chain) if r['path']==str(BASE))
        names=sorted(os.listdir(pf[index]));value=parent_names_encode(names)
        expanded=value['decoded']['bytes']
        need(STORE.metadata_bytes+STORE.names_decoded_bytes+expanded<=METADATA_LIMIT,
             'complete expanded names exceed the single caller metadata pool')
        need(READ_BYTES+CAPTURE_READ_RESERVED+PARENT_NAMES_DECODED_BYTES+expanded<=READ_LIMIT,
             'complete expanded names exceed the single caller read budget')
        STORE.names_decoded_bytes+=expanded;PARENT_NAMES_DECODED_BYTES+=expanded
        return {'parents':chain,'base_names':value}
    finally:close_fds(pf)


def verify_ancestor_transition(before,after):
    need([r['path'] for r in before['parents']]==[r['path'] for r in after['parents']],
         'source parent path sequence changed')
    for left,right in zip(before['parents'],after['parents']):
        if left['path']==str(BASE):
            need(left['metadata'][:5]==right['metadata'][:5],
                 'BASE identity changed across the one known child mkdir')
        else:need(left==right,'source ancestor full9 changed across child')
    before_names=parent_names_decode(before['base_names']);after_names=parent_names_decode(after['base_names'])
    need(AUDIT_OUT.name not in before_names
        and after_names==sorted(before_names+[AUDIT_OUT.name]),
        'BASE additions differ from the sole fixed auditor evidence directory')
    return {'schema':'hepta.native-guard.policy-history-caller-parent-transition.v1',
        'before':before,'after':after,'allowed_created_directory':str(AUDIT_OUT),
        'ordinary_ancestors_full9_equal':True,'base_first5_equal':True,
        'base_all_time_full9_stable_claim':False,'only_declared_name_added':True}

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


def write_captured_output(stream,path,initial,chunks,count,expected_sha256):
    global CAPTURE_READ_RESERVED
    need(type(count) is int and 0<=count<=HOST_OUTPUT_LIMIT,'bounded owned pipe prefix required')
    need(CAPTURE_READ_RESERVED+count+1<=CAPTURE_READ_RESERVATION_LIMIT
        and READ_BYTES+CAPTURE_READ_RESERVED+PARENT_NAMES_DECODED_BYTES+count+1<=READ_LIMIT,
        'capture verification read reservation exhausted before read')
    CAPTURE_READ_RESERVED+=count+1
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
    STORE.finish(path,b''.join(chunks),fd)
    return {'path':str(path),'bytes':count,'sha256':expected_sha256,'metadata':before}


class Chain:
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



def main():
    global STARTED,STORE
    parser=argparse.ArgumentParser()
    parser.add_argument('--source-manifest-sha256',required=True)
    parser.add_argument('--execute-fixed-owned-history-once',action='store_true',required=True)
    args=parser.parse_args()
    need(args.execute_fixed_owned_history_once and re.fullmatch('[0-9a-f]{64}',args.source_manifest_sha256)
        and Path(__file__)==SOURCE and sys.platform=='darwin' and os.geteuid()==501,
        'fixed real Mac owned caller entry required')
    os.umask(0o077);STARTED=time.monotonic()
    completed=False;chain=None;final=None;STORE=OwnedStore()
    try:
        manifest_raw=read(MANIFEST,65536)
        need(sha(manifest_raw)==args.source_manifest_sha256,'actual requested source manifest differs')
        manifest=strict(manifest_raw)
        need(type(manifest) is dict and set(manifest)=={'schema','target_root','files'}
            and manifest['schema']=='hepta.native-guard.policy-history-owned-source.v1'
            and manifest['target_root']==str(SOURCE_ROOT) and type(manifest['files']) is list
            and len(manifest['files'])==2,'fixed source manifest shape differs')
        pins={}
        for row in manifest['files']:
            need(type(row) is dict and set(row)=={'path','bytes','sha256'}
                and row['path'] in ('audit_policy_history_once.py','run_policy_history_owned_once.py')
                and row['path'] not in pins and type(row['bytes']) is int and 0<row['bytes']<=SOURCE_LIMIT,
                'fixed two-source manifest closure differs')
            pins[row['path']]={**row,'path':str(SOURCE_ROOT/row['path'])}
        need(pins['audit_policy_history_once.py']==AUDITOR,'independent auditor literal pin differs')
        source_raw={name:pin(row) for name,row in pins.items()}
        source_before={name:READ_OBSERVATIONS[row['path']] for name,row in pins.items()}
        manifest_before=READ_OBSERVATIONS[str(MANIFEST)]
        need(sorted(os.listdir(SOURCE_ROOT))==sorted([*pins,'SOURCE-MANIFEST.json']),
             'actual source directory is not the closed three-file set')
        try:AUDIT_OUT.lstat()
        except FileNotFoundError:pass
        else:raise ValueError('fixed audit output already exists; no dispatch or retry')
        newdir(OUT)
        before=ancestor_observation()
        chain=Chain();chain.out=OUT;chain.steps=[]
        stdout=chain.execute_process(PHASE,ARGV,CHILD_SECONDS,input_raw=None,async_start=False)
        captured=strict(stdout)
        need(type(captured) is dict and captured.get('schema')=='hepta.native-guard.policy-history-host-audit-summary.v1'
            and captured.get('state')=='ORIGINAL_POLICY_HISTORY_RETAINED_AND_OWNED_HOST_FDS_CLOSED',
            'fixed auditor final output state differs')
        result_raw=read(OUT/PHASE/'RESULT.json',65536);result=strict(result_raw)
        capture_raw=read(OUT/PHASE/'OUTPUT-CAPTURE.json',65536);capture=strict(capture_raw)
        child_raw=read(OUT/PHASE/'CHILD.json',65536);child=strict(child_raw)
        need(result['returncode']==0 and capture['child_wait_returned'] is True
            and capture['worker_joined'] is True and capture['stdout_eof'] is True
            and capture['stderr_eof'] is True and capture['prefix_only_or_unknown'] is False
            and capture['error'] is None and capture['persist_errors']==[] and capture['pipe_close_errors']==[]
            and child['pgid']==child['pid']==child['sid']
            and child['identity_missing_only_if_actual_child_already_joined'] is False,
            'complete actual owned generation, join, output and EOF proof required')
        after=ancestor_observation();transition=verify_ancestor_transition(before,after)
        for name,row in pins.items():
            need(pin(row)==source_raw[name]
                and READ_OBSERVATIONS[row['path']]['metadata']==source_before[name]['metadata'],
                'caller/auditor source complete body or full9 changed across execution')
        need(read(MANIFEST,65536)==manifest_raw
            and READ_OBSERVATIONS[str(MANIFEST)]['metadata']==manifest_before['metadata'],
            'source manifest complete body/full9 changed across execution')
        need(sorted(os.listdir(SOURCE_ROOT))==sorted([*pins,'SOURCE-MANIFEST.json']),
             'source directory closure changed across execution')
        expected_audit={'INTENT.json':32768,'READSET.json':READSET_LIMIT,
            'POLICY-SUMMARY.json':65536,'RESULT.json':32768}
        need(sorted(os.listdir(AUDIT_OUT))==sorted(expected_audit),'fixed audit output closed set differs')
        actual_audit={}
        for name,maximum in expected_audit.items():
            raw=read(AUDIT_OUT/name,maximum);actual_audit[name]=dict(READ_OBSERVATIONS[str(AUDIT_OUT/name)])
        audit_result=strict(pin({k:actual_audit['RESULT.json'][k] for k in ('path','bytes','sha256')}))
        need(audit_result['schema']=='hepta.native-guard.policy-history-host-reconciliation.v1'
            and audit_result['state']=='ORIGINAL_POLICY_ADOPTION_FUNCTION_RETURNED_AND_ALL_INPUTS_RECHECKED',
            'actual complete audit result differs')
        for key,name in (('result','RESULT.json'),('readset','READSET.json'),('policy_summary','POLICY-SUMMARY.json')):
            actual={k:actual_audit[name][k] for k in ('path','bytes','sha256','metadata')}
            need(enc(captured[key])==enc(actual),'auditor final stdout does not bind the actual output original')
            if key!='result':
                need(enc(audit_result[key])==enc(actual),'auditor result does not bind its complete output original')
        need(enc(audit_result['intent'])==enc({k:actual_audit['INTENT.json'][k]
            for k in ('path','bytes','sha256','metadata')}),'auditor result intent binding differs')
        cleanup=chain.close_owned_host_outputs()
        need(cleanup=={'stream_cleanup_errors':[],'host_children':[]},'caller owned cleanup incomplete')
        put(OUT/'SOURCE-OBSERVATIONS.json',parent_names_wire({'schema':'hepta.native-guard.policy-history-caller-sources.v1',
            'source_manifest':manifest_before,'sources':source_before,
            'parent_transition':transition,'audit_outputs':actual_audit,
            'self_report_is_not_source_authority':True}))
        caller={'schema':'hepta.native-guard.policy-history-owned-caller.v1',
            'state':'FIXED_AUDITOR_CHILD_JOINED_AND_COMPLETE_OUTPUTS_RECHECKED',
            'source_manifest':desc(MANIFEST,manifest_raw),'sources':pins,'argv':ARGV,
            'phase':PHASE,'child':desc(OUT/PHASE/'CHILD.json',child_raw),
            'result':desc(OUT/PHASE/'RESULT.json',result_raw),
            'joined':desc(OUT/PHASE/'RESULT.json',result_raw),
            'output_capture':desc(OUT/PHASE/'OUTPUT-CAPTURE.json',capture_raw),
            'stdout':result['stdout'],'stderr':result['stderr'],
            'audit_outputs':{k:{a:v[a] for a in ('path','bytes','sha256')} for k,v in actual_audit.items()},
            'cleanup':cleanup,'source_observations':filedesc(OUT/'SOURCE-OBSERVATIONS.json'),
            'read_bytes_before_caller_result':READ_BYTES,'capture_read_bytes_reserved':CAPTURE_READ_RESERVED,
            'physical_read_limit':READ_LIMIT,'metadata_limit':METADATA_LIMIT,'stream_pool_limit':STREAM_POOL_LIMIT,
            'parent_names_decoded_bytes':PARENT_NAMES_DECODED_BYTES,
            'parent_names_byte_charge_is_canonical_expanded_data_not_kernel_dirent_bytes':True,
            'no_parent_all_time_full9_stability_claim':True,'controller_authority_still_required':True,
            'phone_calls':0,'new_nonce_or_lease':False,'component_qualified':False,'business_qualified':False,
            'automatic_retry':False,'signals_sent':0}
        put(OUT/'CALLER-RESULT.json',enc(caller))
        STORE.check()
        final_members=[]
        for path,record in sorted(STORE.members.items(),key=lambda item:str(item[0])):
            need(record['complete'],'caller member has incomplete output binding')
            need(pin(record['original']) is not None,'complete caller body recheck required')
            need(READ_OBSERVATIONS[str(path)]['metadata']==record['metadata'],'caller full9 changed at final read')
            final_members.append(record['original'])
        need(len(final_members)==8 and sorted(os.listdir(OUT/PHASE))==
            ['CHILD.json','INTENT.json','OUTPUT-CAPTURE.json','RESULT.json','stderr.original','stdout.original'],
            'successful caller exact eight-file closure differs')
        for name,row in actual_audit.items():
            need(pin({k:row[k] for k in ('path','bytes','sha256')}) is not None
                and READ_OBSERVATIONS[row['path']]['metadata']==row['metadata'],
                'audit output changed at final caller bookend')
        STORE.check()
        final={'schema':'hepta.native-guard.policy-history-owned-caller-summary.v1',
            'state':'OWNED_AUDITOR_JOINED_ALL_ORIGINALS_RETAINED_AND_CALLER_FDS_CLOSED',
            'caller_result':filedesc(OUT/'CALLER-RESULT.json'),'originals':final_members,
            'auditor_originals':caller['audit_outputs'],'actual_child_starts':1,
            'read_bytes':READ_BYTES,'capture_read_bytes_reserved':CAPTURE_READ_RESERVED,
            'physical_read_total_upper':READ_BYTES+CAPTURE_READ_RESERVED+PARENT_NAMES_DECODED_BYTES,
            'metadata_bytes':STORE.metadata_bytes,'parent_names_decoded_bytes':PARENT_NAMES_DECODED_BYTES,
            'metadata_total_charged_bytes':STORE.metadata_bytes+STORE.names_decoded_bytes,
            'parent_names_byte_charge_is_canonical_expanded_data_not_kernel_dirent_bytes':True,
            'stream_write_bytes_reserved':STORE.stream_reserved,
            'owned_host_cleanup':cleanup,'automatic_retry':False,'signals_sent':0,
            'phone_calls':0,'case_pass':False,'external_controller_originals_still_required':True}
        need(len(enc(final))<=65536,'bounded final caller stdout required')
        completed=True
    except BaseException as error:
        cleanup=None
        if chain is not None:
            try:cleanup=chain.close_owned_host_outputs()
            except BaseException as cleanup_error:cleanup={'error_type':type(cleanup_error).__name__}
        if OUT in STORE.dirs:
            try:put(OUT/'CALLER-FAILURE.json',enc({'schema':'hepta.native-guard.policy-history-caller-failure.v1',
                'state':'FIXED_ATTEMPT_FAILED_OR_UNKNOWN_NO_RETRY','error_type':type(error).__name__,
                'message':str(error)[:512],'owned_cleanup':cleanup,'automatic_retry':False,'signals_sent':0,
                'evidence_removed':False,'phone_calls':0,'case_pass':False}))
            except BaseException:pass
        raise
    finally:
        STORE.close()
    need(completed,'owned caller did not complete')
    sys.stdout.buffer.write(enc(final));sys.stdout.buffer.flush()


if __name__=='__main__':
    main()
