#!/usr/bin/env python3
"""One fixed expired-lease original read-only verification, without profiling."""
import sys
sys.dont_write_bytecode = True
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import types

LABEL='root-r10-neg01-1ad3-01'
NONCE='7c74b84aefb177d15f746fa7eae29d54'
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
CASE_HOME=Path('/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1')/LABEL
ANDROID=Path('/proc/1/root')
LEASE_PIN=(2488,'2f47f823ef1484852c5dc1b91f27020d6f56685b3024dc320d5925a3dac92d59')
PACKAGE_PIN=(16808,'67dc40470b8ecb1e10cb57f8953a3d0b6db309b45079216eb24cd65f0760107c')
COMBINATION_PIN=(4702,'54b1d9aef4c16ebc0989b3e13345238bfbd4e400e5bfc9a97e27648a2385057e')
LEASE_EXPIRES_UNIX_MS=1793872564534
ACTUAL08={'bytes':9373,'metadata':[65086,153711,33152,0,0,1,9373,1793853757339925229,1793853757339925229],
 'path':'/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/2b0b103ee6de7a422064b9571266bf5d.json',
 'sha256':'eca941303197228ebe03561e612bfe41eb0518c590ff21253444db25a11adc10'}
RETIREMENT_PROBE_PIN=(766658,'d1fe1478ee9699b5a1199aa4c2b96a2a405f7cafd0b5707071cfd2238dbe5df4')
OBSERVED_CALL_SECONDS=180
OUTPUT_LIMIT=1024*1024
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
READSET={}
DIRECTORIES={}
READ_BYTES=0

def need(ok,why):
    if not ok:raise ValueError(why)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def strict(raw):
    def pairs(rows):
        value={}
        for k,v in rows:
            need(k not in value,'duplicate JSON key');value[k]=v
        return value
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))

def metadata(s):
    return [getattr(s,k) for k in META]

def parent_fd(path):
    path=Path(path)
    need(path.is_absolute() and '..' not in path.parts and 2<=len(path.parts)<=64,'bounded absolute path')
    if path.parts[:4]==('/','proc','1','root'):
        fd=os.open(ANDROID,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);parts=path.parts[4:]
    else:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);parts=path.parts[1:]
    need(parts,'original leaf required')
    try:
        for name in parts[:-1]:
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=child
        return fd,parts[-1]
    except BaseException:
        os.close(fd);raise

def read_original(path,maximum=16*1024*1024,expected=None,expected_metadata=None):
    global READ_BYTES
    path=Path(path);parent,leaf=parent_fd(path)
    try:
        fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        try:
            before=os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==before.st_gid==0
                 and stat.S_IMODE(before.st_mode)==0o600 and 0<=before.st_size<=maximum,
                 'bounded private original shape')
            with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(before.st_size+1)
            named=os.stat(leaf,dir_fd=parent,follow_symlinks=False)
            need(len(raw)==before.st_size and metadata(before)==metadata(os.fstat(fd))==metadata(named),
                 'original full9 read changed')
        finally:os.close(fd)
    finally:os.close(parent)
    row={'path':str(path),'bytes':len(raw),'sha256':sha(raw),'metadata':metadata(before)}
    if expected is not None:need((len(raw),row['sha256'])==expected,'exact original pin differs')
    if expected_metadata is not None:need(row['metadata']==expected_metadata,'fixed original metadata differs')
    if str(path) in READSET:need(row==READSET[str(path)],'bootstrap original changed across verification')
    else:
        READ_BYTES+=len(raw);need(READ_BYTES<=16*1024*1024,'bootstrap original readset bound')
        READSET[str(path)]=row
    return raw

def read_directory(path):
    path=Path(path);parent,leaf=parent_fd(path)
    try:
        fd=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        try:
            before=os.fstat(fd);names=sorted(os.listdir(fd))
            need(stat.S_ISDIR(before.st_mode) and before.st_uid==before.st_gid==0
                 and stat.S_IMODE(before.st_mode)==0o700 and len(names)<=128,'private bounded source directory')
            need(metadata(before)==metadata(os.fstat(fd))==metadata(os.stat(leaf,dir_fd=parent,follow_symlinks=False)),
                 'source directory changed')
        finally:os.close(fd)
    finally:os.close(parent)
    row={'path':str(path),'metadata':metadata(before),'names':names}
    if str(path) in DIRECTORIES:need(row==DIRECTORIES[str(path)],'source directory changed across verification')
    else:DIRECTORIES[str(path)]=row
    return row

def source_package():
    root=CASE_HOME/'package'
    manifest_raw=read_original(root/'MANIFEST.json',262144,PACKAGE_PIN);manifest=strict(manifest_raw)
    need(manifest['schema']=='hepta.native-guard.adapter-package.v1'
         and manifest['state']=='HOST_REVIEWED_NOT_PHONE_QUALIFIED','exact actual runtime manifest shape')
    rows=manifest['files'];need(type(rows) is list and len(rows)==32,'exact runtime32')
    files={};dirs={'.'}
    for row in rows:
        need(type(row) is dict and set(row)=={'path','bytes','sha256'},'exact runtime member descriptor')
        name=row['path'];p=Path(name)
        need(type(name) is str and str(p)==name and not p.is_absolute() and '..' not in p.parts
             and name not in files and type(row['bytes']) is int and 0<row['bytes']<=16*1024*1024,
             'canonical unique bounded runtime member')
        files[name]=read_original(root/p,16*1024*1024,(row['bytes'],row['sha256']))
        dirs.update(str(d) for d in p.parents)
    expected=set(files)|{'MANIFEST.json'};observed=set();observed_dirs=set();stack=[Path('.')]
    while stack:
        rel=stack.pop();directory=read_directory(root/rel);observed_dirs.add(str(rel))
        need(str(rel) in dirs,'extra source directory')
        for name in directory['names']:
            relative=rel/name;full=root/relative;s=full.lstat()
            if stat.S_ISDIR(s.st_mode):stack.append(relative)
            else:
                need(stat.S_ISREG(s.st_mode) and str(relative) in expected,'extra or non-regular source member')
                observed.add(str(relative))
    need(observed==expected and observed_dirs==dirs,'actual source closed set changed')
    return root,files

def load_module(name,root,files):
    need(name not in sys.modules,'fresh exact runtime module required: '+name)
    relative='source/'+name+'.py';raw=files[relative];module=types.ModuleType(name)
    module.__file__=str(root/relative);sys.modules[name]=module
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    return module

def boot():
    with open('/proc/sys/kernel/random/boot_id','rb') as stream:raw=stream.read(128)
    need(raw.strip().decode()==BOOT,'actual boot changed');return raw

def recheck_bootstrap():
    for row in list(READSET.values()):
        read_original(row['path'],max(1,row['bytes']),(row['bytes'],row['sha256']),row['metadata'])
    for row in list(DIRECTORIES.values()):read_directory(row['path'])

def own_fds():
    names=os.listdir('/proc/self/fd');need(len(names)<=256,'own FD census bound')
    value={}
    for name in names:
        need(name.isdigit(),'own FD name shape');fd=int(name)
        try:s=os.fstat(fd)
        except OSError as error:
            need(error.errno in (errno.EBADF,errno.ENOENT),'own FD observation unknown');continue
        value[fd]=(s.st_dev,s.st_ino,s.st_mode)
    return value

def release_owned_verifier_lock(before,lock_identity,returned_fd):
    after=own_fds();closed=[];errors=[];targets=set()
    for fd,identity in after.items():
        if fd>=3 and identity==lock_identity and fd not in before:targets.add(fd)
    if returned_fd is not None:
        if type(returned_fd) is not int or returned_fd<3 or returned_fd in before:
            errors.append('returned FD is not an observed new owned FD')
        elif returned_fd not in after:
            errors.append('returned owned FD is already absent; release is not established')
        else:
            # A returned FD is our original verifier's new resource.  Even an
            # inode/flag mismatch must close it before reporting a rejection.
            targets.add(returned_fd)
    for fd in sorted(targets):
        identity=after[fd];row={'fd':fd,'identity':list(identity),
            'returned_by_verifier':fd==returned_fd,'matches_bootstrap_lock':identity==lock_identity}
        if identity!=lock_identity:errors.append('returned lock differs from bootstrap inode')
        try:
            row['readonly']=(fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE)==os.O_RDONLY
            if not row['readonly']:errors.append('original verifier lock FD is not read-only')
        except BaseException as exc:
            errors.append('owned FD flags unknown: '+type(exc).__name__)
        finally:
            try:os.close(fd);row['close_returned']=True
            except BaseException as exc:
                row['close_returned']=False;errors.append('owned FD close failed: '+type(exc).__name__)
        try:os.fstat(fd)
        except OSError as exc:
            row['observed_EBADF']=exc.errno==errno.EBADF
            if exc.errno!=errno.EBADF:errors.append('owned FD close observation unknown')
        else:row['observed_EBADF']=False;errors.append('owned FD remains after close')
        closed.append(row)
    final=own_fds()
    remaining=[{'fd':fd,'identity':list(identity)} for fd,identity in final.items()
               if fd>=3 and before.get(fd)!=identity]
    if remaining:errors.append('unexpected new own FDs remain; no complete cleanup claim')
    if returned_fd is not None and not any(row['fd']==returned_fd for row in closed):
        errors.append('returned verifier lock was not closed by this diagnostic')
    return {'only_returned_own_or_new_exact_existing_lock_FDs_closed':True,'closed':closed,
        'new_FDs_remaining':remaining,'errors':errors,'complete':not errors}

def main():
    started=time.monotonic();retired=None;error=None;cleanup=None
    global_verified=False;original_call_wall=None;original_call_cpu=None
    lock_fd=None;entered=0;returned=0;native_context=None
    try:
        need(len(sys.argv)==1,'fixed single expired-case diagnostic has no alternate inputs')
        need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'actual Root credentials')
        boot_raw=boot();root,files=source_package()
        C=load_module('component_common',root,files)
        load_module('native_proc_profile',root,files)
        L=load_module('component_lifecycle',root,files)
        late=load_module('late_boundary',root,files)
        load_module('component_snapshot',root,files)
        native_context=L.native_root(BOOT)
        lease_raw=read_original(CASE_HOME/'LEASE.json',262144,LEASE_PIN)
        lease,second=L.load_lease(CASE_HOME,LEASE_PIN[1],require_live=False)
        need(second==lease_raw and lease['label']==LABEL and lease['nonce']==NONCE
             and lease['boot_id']==BOOT and lease['case_id']=='NEG-01'
             and lease['expires_unix_ms']==LEASE_EXPIRES_UNIX_MS
             and time.time_ns()//1000000>=LEASE_EXPIRES_UNIX_MS,'exact expired failed-case lease')
        need(lease['package_sha256']==PACKAGE_PIN[1]
             and (lease['combination']['bytes'],lease['combination']['sha256'])==COMBINATION_PIN
             and lease['prior_boundary']==ACTUAL08,'actual runtime/combination/last-native08 binding')
        read_original(CASE_HOME/'inputs/COMBINATION.json',16384,COMBINATION_PIN)
        read_original(ACTUAL08['path'],16384,(ACTUAL08['bytes'],ACTUAL08['sha256']),ACTUAL08['metadata'])
        need((lease['retirement']['probe']['bytes'],lease['retirement']['probe']['sha256'])==RETIREMENT_PROBE_PIN,
             'original retirement probe identity changed')
        for row in lease['retirement'].values():
            read_original(row['path'],16*1024*1024,(row['bytes'],row['sha256']),row['metadata'])
        lock_path=C.BASE/'executor-r6/server.lock';read_original(lock_path,65536)
        s=lock_path.lstat();need(metadata(s)==READSET[str(lock_path)]['metadata'],'bootstrap lock path changed')
        lock_identity=(s.st_dev,s.st_ino,s.st_mode)
        before=own_fds();need(lock_identity not in before.values(),'no preexisting inherited verifier lock FD')
        need(time.monotonic()-started<=25,'bounded exact source bootstrap exceeded')
        wall_start=time.monotonic();cpu_start=time.process_time()
        try:
            entered+=1
            lock_fd,retired=L.verify_retired(lease,late_boundary_module=late)
            returned+=1
        finally:
            original_call_wall=time.monotonic()-wall_start
            original_call_cpu=time.process_time()-cpu_start
            cleanup=release_owned_verifier_lock(before,lock_identity,lock_fd)
        need(cleanup['complete'],'original owned lock cleanup did not complete')
        need(entered==returned==1,'exactly one original callsite entry and return required')
        need(original_call_wall<OBSERVED_CALL_SECONDS,
             'original verifier returned after the 180-second post-return observation limit')
        need(retired['old_journal_lock_held_without_writing'] is True
             and retired['explicit_late_boundary_verification']['state']=='EXACT_CLOSED_CUMULATIVE_ORIGINALS_UNCHANGED'
             and retired['explicit_late_boundary_verification']['previous_boundary']==ACTUAL08,
             'original full actual08 verification did not return its native result')
        recheck_bootstrap();need(boot()==boot_raw,'boot changed across original verification')
        global_verified=True
    except BaseException as exc:
        error={'type':type(exc).__name__,'detail':str(exc)[:1024]}
    result={'schema':'hepta.native-guard.expired-lease-readonly-verification.v1',
        'state':'ACTUAL08_ORIGINAL_GLOBAL_VERIFICATION_RETURNED_AND_LOCK_RELEASED' if global_verified
                else 'READONLY_VERIFICATION_FAILED_OR_PARTIAL_RETAIN_ORIGINALS',
        'label':LABEL,'nonce':NONCE,'boot_id':BOOT,'lease':dict(bytes=LEASE_PIN[0],sha256=LEASE_PIN[1]),
        'package':dict(bytes=PACKAGE_PIN[0],sha256=PACKAGE_PIN[1]),'actual_last_native_boundary':ACTUAL08,
        'lease_expiry_unchanged':LEASE_EXPIRES_UNIX_MS,
        'post_return_elapsed_limit_seconds':OBSERVED_CALL_SECONDS,
        'elapsed_limit_kind':'post_return_observation_only_not_a_hard_deadline',
        'blocked_C_or_IO_is_not_preemptible':True,'self_deadline_installed':False,
        'production_lease_or_510_420_gates_changed':False,
        'original_verify_retired_callsite_entered':entered,'original_verify_retired_returned':returned,
        'original_verifier_returned':returned==1,'original_verification_complete':global_verified,
        'original_result':retired,'failure':error,'owned_verifier_lock_cleanup':cleanup,
        'original_call_wall_seconds':original_call_wall,'original_call_cpu_seconds':original_call_cpu,
        'total_wall_seconds':time.monotonic()-started,
        'profiling_enabled':False,'tracing_enabled':False,'runtime_functions_rebound':False,
        'bootstrap_originals':list(READSET.values()),'bootstrap_source_directories':list(DIRECTORIES.values()),
        'actual_diagnostic_native_context':native_context,
        'phone_case_or_source_writes':0,'runtime_main_calls':0,'process_launches':0,
        'signals_delivered_to_other_processes':0,'self_signals':0,
        'original_signal_zero_absence_queries_retained':True,'model_requests':0,
        'native_sends':0,'boundary_publications':0,'fixture_attempts':0,
        'failed_prelaunch_predecessor_closed_here':False,'component_qualified':False,
        'automatic_retry':False}
    try:
        raw=(json.dumps(result,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
        need(len(raw)<=OUTPUT_LIMIT,'complete verification exceeds one-MiB output bound')
    except BaseException as exc:
        raw=(json.dumps({'schema':result['schema'],'state':'VERIFICATION_SERIALIZATION_REJECTED_RETAIN_ORIGINALS',
            'label':LABEL,'nonce':NONCE,'error_type':type(exc).__name__,'detail':str(exc)[:1024],
            'original_verify_retired_callsite_entered':entered,'original_verify_retired_returned':returned,
            'original_verification_complete':False,'owned_verifier_lock_cleanup':cleanup,
            'failed_prelaunch_predecessor_closed_here':False,'component_qualified':False,
            'phone_case_or_source_writes':0,'automatic_retry':False},sort_keys=True,separators=(',',':'))+'\n').encode()
        global_verified=False
    sys.stdout.write(raw.decode())
    return 0 if global_verified else 1

if __name__=='__main__':raise SystemExit(main())
