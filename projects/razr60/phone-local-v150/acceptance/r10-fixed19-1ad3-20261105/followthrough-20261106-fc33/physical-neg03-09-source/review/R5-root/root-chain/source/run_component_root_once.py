#!/usr/bin/env python3
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
PKG = '990c726a1fff139761494cc19cf091deb269201f27ea947dda4a5833e3a72f2a'
COMBINATION = '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'
VERIFIER_SHA = '6a3a9f8278ccf4b29724d9d034b4a349127a77d0adfd4daa8066ef6aa8d6c35b'
VERIFIER_BYTES = 65591
POLICY_SHA = '69aa6433a11ac4cffb2f1d349cc9f36ec2349a601911c173ebe7d92fff9e0c5b'
ADOPTION_SHA = '98b5db3d2c9680fff13e50bf64b18ddf9822689641427d204fded84f690d04c7'
ROOT_SCOPE_SHA = 'b9d163938dca91171a8eeb8d9ddd6b394580effd2987f34a661d3687c1ee4ba9'
SENDER = '53a6e9149cf768211c3c8ba74d3c422f95d78f14efdb8751af1ac55d1a9225d5'
READY_HELPER = '97b28afd910280bbdb7a1061218f4d72fc4b9024669b1aba10b0bfdb6caf13b2'
ACTOR='179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'
RET='e3c8411f3d85440018392597d4f9f8795cfd7a60c44fc1680068a60949d20999'
SHARED = 'cc7eb624333216e510b540c3af8277e948aa689a108950fa78e8d01c2177e5b1'
CONFIG = '5ff00467e8432d7119ba72a700ce07cb20f16555d3dc0c90de7cbfc388103f48'
SERVICE = '273db17098e5de6c67ded208e120e3910531ab1c7a778faa76824d453ddddd58'
MATERIAL_ROOT = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-fc33-native-v3-r5/shared')
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

# Each stream retains the same 64 MiB bound already enforced by read().
# The worker owns pipe readers only. All filesystem writes stay on the caller.
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

def validate_adoption(adoption, expected_live_sha256, adoption_raw):
    need(type(VERIFIER_BYTES) is int and 0<VERIFIER_BYTES<=131072
         and all(type(value) is str and re.fullmatch('[0-9a-f]{64}',value)
                 for value in (VERIFIER_SHA,POLICY_SHA,ADOPTION_SHA,ROOT_SCOPE_SHA)),
         'actual independently reviewed policy verifier must be frozen')
    need(expected_live_sha256==POLICY_SHA and POLICY_SHA=='69aa6433a11ac4cffb2f1d349cc9f36ec2349a601911c173ebe7d92fff9e0c5b',
         'this final tuple requires its exact actual exported policy')
    need(strict(adoption_raw)==adoption,'adoption must be its exact supplied original')
    path=HERE.parent/'reference/actual_policy_adoption.py';raw=read(path,131072)
    need(len(raw)==VERIFIER_BYTES and sha(raw)==VERIFIER_SHA,'actual adoption verifier source differs')
    module=types.ModuleType('exact_root_parent_dir_adoption');module.__file__=str(path)
    module.__reviewed_source_sha256__=sha(raw)
    exec(compile(raw,str(path),'exec'),module.__dict__)
    state=module.verify_adoption(adoption_raw,read_pinned=pin)
    need(state['current_adoption_sha256']==sha(adoption_raw)==ADOPTION_SHA
         and state['parent_adoption_sha256']=='527374778e62717d837d546cfa56bd144c8415b52006a9be4a33935c8592d08a'
         and state['root_scope_decision_sha256']==ROOT_SCOPE_SHA
         and state['prior_boundary_sha256']=='fd7766538b0ff88bea73ce66e0de4728caf3771f88c8441bb4d2844fb13b6c66'
         and state['actual_live_binding_sha256']=='c9053279b561296e67de6ed0acc8b233fcc64ae8600ab21a58b772cddfe6eeed',
         'actual adoption, f821 parent, actual v3 head or live binding differs')
    actual=pin(adoption['actual_export'])
    need(state['runtime_policy']=={'bytes':len(actual),'sha256':sha(actual)}
         and len(actual)==2667752 and sha(actual)==expected_live_sha256,
         'complete independently adopted actual policy bytes differ')
    return state['runtime_policy']


def validate_sender_marker(marker,contract_raw,prepared,owner_sha,nonce,provider_sha):
    need(marker['schema']=='hepta.native-guard.sender-prepared.v1' and marker['state']=='PREPARED_NO_SEND'
        and type(marker['send_attempt_count']) is int and marker['send_attempt_count']==0 and marker['provider_started_by_sender'] is False,
        'only the actual no-Send rendezvous admits one launch')
    need(marker['nonce']==nonce and marker['owner_request_sha256']==owner_sha
        and marker['contract_sha256']==sha(contract_raw)==prepared['sender_contract_sha256']
        and marker['provider_source_sha256']==provider_sha,'original sender prepared identity differs')

def prior_reader(runtime,manifest):
    # Pin every package byte before injecting the exact historical reference.
    # No ordinary import may substitute an unindexed bytecode file.
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
        late=loaded['late_boundary']
        expected=late.reviewed_v3_runtime_diagnostic_ancestor()['inventory']
        def retained_old39(row):
            need(row==expected,'host retained-stage callback may only read exact old39 descriptor')
            raw=read(runtime.parent/'retained-history/native-00/inventory.original.json',row['bytes'])
            need(len(raw)==row['bytes']and sha(raw)==row['sha256'],'host complete old39 raw copy differs')
            return raw
        late.__retained_stage_read_pinned__=retained_old39
        return late
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
    reader.validate_current_package_manifest(manifest)
    branches=reader.non_native_sidebranches()
    need(manifest.get('non_native_sidebranches')==[s['binding'] for s in branches],
         'current package omitted either actual typed non-native sidebranch')
    retained=reader.retained_unstarted_stage()
    need(manifest.get('retained_unstarted_stage')==retained['binding']
         and p['nonce']!=retained['binding']['nonce'],'current package omitted or reused expired unstarted stage')
    boundary=reader.boundary_from_original(original,original_descriptor=prior,
        combination_sha256=COMBINATION,package_sha256=PKG)
    need(boundary['nonce']!=p['nonce'] and boundary['scope']==previous['identity']
         and previous.get('known_all_dispatched_tools_confirmed_terminal') is True,
         'new component must use its actual terminal predecessor native scope')
    need(boundary['schema']==reader.SCHEMA,
         'historical03/04 cannot replace the already published actual_v3_diagnostic predecessor')
    need(not reader.is_pre_policy_ancestor(boundary)
         and not reader.is_environment_parent_ancestor(boundary)
         and not reader.is_property_parent_ancestor(boundary)
         and not reader.is_diagnostic_parent_ancestor(boundary)
         and not reader.is_v3_runtime_diagnostic_ancestor(boundary),
         'new source tuple must retain its exact closed source-parent head')
    parent=reader.is_source_parent_ancestor(boundary)
    source_parent=reader.reviewed_source_parent_records()[0]
    if parent:
        need(p['case_id']=='NEG-01' and prior==source_parent['boundary']
             and p['previous']==source_parent['closed_previous'],
             'the new source tuple must enter through its exact actual closed source-parent head')
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
        need(home==Path(source_parent['closed_previous']['path']).parent,
             'source-parent originals must retain their actual original Root namespace')
    closed_raw=pin(closed_row);inventory_row=boundary['inventory']
    need(type(inventory_row['bytes']) is int and 0<inventory_row['bytes']<=16*1024*1024,
         'predecessor needs its bounded cumulative inventory')
    inventory_raw=read(home/'INVENTORY.json',inventory_row['bytes'])
    verified,_inventory,closed=reader.closed_boundary_originals(
        original,inventory_raw,closed_raw,original_descriptor=prior,
        combination_sha256=COMBINATION,package_sha256=PKG)
    selected,selected_pin,selection=reader.effective_current_prior_inventory(boundary,_inventory,branches,retained=retained)
    expected_roots=reader.SOURCE_PARENT_INVENTORY_ROOT_COUNT+(0 if parent else 3)
    need(len(selected['roots'])==expected_roots
         and expected_roots<reader.MAX_CURRENT_INVENTORY_ROOTS,
         'current roots must retain the actual source parent and exact new component growth')
    need(verified==boundary and boundary['prior_boundary'] is not None,
         'predecessor must retain the exact complete prior chain')
    closers=[row for row in manifest['files'] if row['path']=='source/close_component.py']
    need(len(closers)==1 and re.fullmatch('[0-9a-f]{64}',closers[0]['sha256']),
         'current package must contain one explicit closure source')
    expected_closer=source_parent['closure_source_sha256'] if parent else closers[0]['sha256']
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
    need((parent and p['case_id']=='NEG-01' and passed)
         or (not parent and p['case_id']==boundary['case_id'] and failed)
         or (not parent and boundary['case_id']=='NEG-01' and p['case_id']=='NEG-02' and passed),
         'only the exact source-parent entry or current closed NEG01-to-NEG02 progression is allowed')
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
        and re.fullmatch('[0-9a-f]{32}',p['nonce']) and p['boot_id']==BOOT
        and p['nonce']!='d11e31c9ac94920d47998ca88a97e98f',
        'explicit new Root identity; consumed failed stage nonce cannot be reused')
    need(p['package']['sha256']==PKG and p['retirement_descriptor']['sha256']==RET,'frozen package/actual retirement')
    source_package=strict(pin(p['source_package']))
    need(source_package['schema']=='hepta.native-guard.root-chain-source-package.v1'
        and Path(p['source_package']['path']).parent==HERE.parent
        and {r['path'] for r in source_package['files']}=={'reference/actual_policy_adoption.py', 'source/phone_chain_bridge.py', 'source/run_component_root_once.py'}
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
        need(sha(read(runtime/'source'/name))==h,'selected current package sender/helper pin')
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
        sender=['/usr/bin/python3','-I','-B',str(runtime/'source/send_new_native_guard_task_r10_r4.py'),p['label'],p['request']['path'],p['previous']['path'],
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
        try:host_cleanup=c.close_owned_host_outputs()
        except BaseException as cleanup_error:
            host_cleanup={'state':'HOST_EXCEPTION_CLEANUP_FAILED_OR_UNKNOWN',
                'error_type':type(cleanup_error).__name__,'automatic_retry':False,
                'signals_sent':0,'remote_terminal_or_cleanup_proven':False}
        value={'state':'FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED_NO_AUTOMATIC_CONTINUATION',
            'host_cleanup':host_cleanup,
            'error_type':type(error).__name__,'detail':str(error)[:1024],'steps':c.steps,'root_fixture_attempts':c.root_attempts,
            'automatic_retry':False,'new_identity_retry':False,'send_again':False,'signals_sent_by_coordinator':0,
            'policy_changes':0,'model_requests':0,'component_qualified':False,'business_qualified':False,
            'note':'Inspect existing process/actor/phone receipts. No missing record is treated as no effect.'}
        try:put(c.out/'ROOT-FAILURE.json',enc(value))
        except BaseException:
            # Evidence write failure must not replace the original exception.
            pass
        raise
if __name__=='__main__':raise SystemExit(main())
