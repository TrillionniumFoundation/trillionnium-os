#!/usr/bin/env python3
"""Fixed explicit in-memory147cf read-only diagnostic; staged67dc/c50a stays unchanged.

This is a timing and equality diagnostic, never original-global clearance or a
phone case. All original lifecycle/live checks run once with the explicitly
supplied current reader. No trace, profiler, memoization, launch, or source write.
"""
import sys
sys.dont_write_bytecode = True
import base64
import zlib
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
STAGED_LATE_PIN=(66996,'c50a219efd992ce1353494ace2656af20c932cbc32530b0085e38a79975d8add')
EXECUTED_LATE_PIN=(67005,'147cf49e91fb4bcbddeba6591d48c8782efe20452db2b2d6179e7addd68c27e4')
CANDIDATE_COMPILE_FILENAME='<explicit-in-memory-inventory-prefix147cf-readonly-diagnostic>'
CANDIDATE_ZLIB_PIN=(16766, 'e95dffcf7b524a80c74fadd183fb63306e85e890f7dfdcbfa1a789d58257d90c')
CANDIDATE_ZLIB_B64='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'
OLD_INVENTORY_EXPRESSION=b'sum(p == q or q in p.parents for q in paths) == 1'
NEW_INVENTORY_EXPRESSION=b'sum(p.parts[:len(q.parts)] == q.parts for q in paths) == 1'
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

def explicit_candidate_source(files):
    """Only decode/verify bytes; all original runtime32 files remain untouched."""
    staged=files['source/late_boundary.py']
    need(type(staged) is bytes and (len(staged),sha(staged))==STAGED_LATE_PIN,
         'the original stagedc50a reader must remain byte exact')
    need(type(CANDIDATE_ZLIB_B64) is str and len(CANDIDATE_ZLIB_B64)<=131072,
         'bounded fixed candidate encoding')
    packed=base64.b64decode(CANDIDATE_ZLIB_B64,validate=True)
    need(base64.b64encode(packed).decode('ascii')==CANDIDATE_ZLIB_B64
         and (len(packed),sha(packed))==CANDIDATE_ZLIB_PIN,
         'fixed canonical compressed candidate bytes differ')
    decoder=zlib.decompressobj()
    body=decoder.decompress(packed,EXECUTED_LATE_PIN[0]+1)
    need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
         and (len(body),sha(body))==EXECUTED_LATE_PIN,
         'one complete bounded explicit147cf source required')
    need(body.count(NEW_INVENTORY_EXPRESSION)==1
         and body.replace(NEW_INVENTORY_EXPRESSION,OLD_INVENTORY_EXPRESSION,1)==staged
         and staged.count(OLD_INVENTORY_EXPRESSION)==1,
         'complete source inverse does not equal original stagedc50a')
    return body,{'schema':'hepta.native-guard.explicit-reader-diagnostic-source.v1',
        'staged_runtime_manifest':dict(bytes=PACKAGE_PIN[0],sha256=PACKAGE_PIN[1]),
        'staged_late':dict(bytes=STAGED_LATE_PIN[0],sha256=STAGED_LATE_PIN[1]),
        'executed_late':dict(bytes=EXECUTED_LATE_PIN[0],sha256=EXECUTED_LATE_PIN[1]),
        'compressed_supplied_source':dict(bytes=CANDIDATE_ZLIB_PIN[0],sha256=CANDIDATE_ZLIB_PIN[1]),
        'whole_source_inverse_matches_actual_staged_bytes':True,
        'compile_filename':CANDIDATE_COMPILE_FILENAME,
        'execution_origin':'fixed_source_bytes_supplied_by_diagnostic_stdin_only',
        'original_package_or_lease_rewritten':False,'successor_runtime_claimed_staged':False,
        'reference_file_reads_redirected_to_memory':False,'memoization_added':False}


def load_explicit_candidate_late(root,files):
    body,proof=explicit_candidate_source(files)
    # __file__ keeps the original package path ONLY for unchanged reference-file
    # reads. The code filename and retained source proof label execution origin.
    module=types.ModuleType('explicit_inventory_prefix_late_diagnostic')
    module.__file__=str(root/'source/late_boundary.py')
    need(module.__name__ not in sys.modules and 'late_boundary' not in sys.modules,
         'candidate diagnostic must not replace an existing runtime module')
    exec(compile(body,CANDIDATE_COMPILE_FILENAME,'exec'),module.__dict__)
    need(module.verify_current.__code__.co_filename==CANDIDATE_COMPILE_FILENAME
         and module.inventory_value.__code__.co_filename==CANDIDATE_COMPILE_FILENAME
         and '__reviewed_package_sources__' not in module.__dict__
         and '__reviewed_source_sha256__' not in module.__dict__,
         'explicit candidate execution origin or original file-read path differs')
    anchor=READSET.get(module.__file__)
    need(type(anchor) is dict and anchor['path']==module.__file__
         and (anchor['bytes'],anchor['sha256'])==STAGED_LATE_PIN,
         'resource anchor must be the actual full9-read stagedc50a original')
    proof['resource_anchor']=dict(anchor)
    proof['resource_anchor_used_for']=['unchanged reference lookup','unchanged self-source read semantics']
    proof['self_source_function_modified']=False
    proof['self_source_function_is_executed_code_identity']=False
    proof['self_source_read_semantics']='unchanged reviewed_source_sha256 reads stagedc50a if called; it is never reported as executed147cf identity'
    proof['registered_as_staged_late_module']=False
    return module,proof


def main():
    started=time.monotonic();retired=None;error=None;cleanup=None
    diagnostic_verified=False;original_call_wall=None;original_call_cpu=None
    lock_fd=None;entered=0;returned=0;native_context=None;explicit_source=None
    try:
        need(len(sys.argv)==1,'fixed single expired-case diagnostic has no alternate inputs')
        need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'actual Root credentials')
        boot_raw=boot();root,files=source_package()
        C=load_module('component_common',root,files)
        load_module('native_proc_profile',root,files)
        L=load_module('component_lifecycle',root,files)
        late,explicit_source=load_explicit_candidate_late(root,files)
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
        diagnostic_verified=True
    except BaseException as exc:
        error={'type':type(exc).__name__,'detail':str(exc)[:1024]}
    result={'schema':'hepta.native-guard.expired-lease-explicit-reader-diagnostic.v1',
        'state':'EXPLICIT_147CF_READONLY_DIAGNOSTIC_RETURNED_AND_LOCK_RELEASED' if diagnostic_verified
                else 'EXPLICIT_READER_DIAGNOSTIC_FAILED_OR_PARTIAL_RETAIN_ORIGINALS',
        'label':LABEL,'nonce':NONCE,'boot_id':BOOT,'lease':dict(bytes=LEASE_PIN[0],sha256=LEASE_PIN[1]),
        'package':dict(bytes=PACKAGE_PIN[0],sha256=PACKAGE_PIN[1]),'actual_last_native_boundary':ACTUAL08,
        'lease_expiry_unchanged':LEASE_EXPIRES_UNIX_MS,
        'post_return_elapsed_limit_seconds':OBSERVED_CALL_SECONDS,
        'elapsed_limit_kind':'post_return_observation_only_not_a_hard_deadline',
        'blocked_C_or_IO_is_not_preemptible':True,'self_deadline_installed':False,
        'production_lease_or_510_420_gates_changed':False,
        'original_verify_retired_callsite_entered':entered,'original_verify_retired_returned':returned,
        'original_lifecycle_returned':returned==1,'original_verification_complete':False,
        'diagnostic_verification_complete':diagnostic_verified,'original_global_clearance_evidence':False,
        'diagnostic_result':retired,'explicit_reader_source':explicit_source,
        'failure':error,'owned_verifier_lock_cleanup':cleanup,
        'original_call_wall_seconds':original_call_wall,'original_call_cpu_seconds':original_call_cpu,
        'total_wall_seconds':time.monotonic()-started,
        'profiling_enabled':False,'tracing_enabled':False,'runtime_functions_rebound':False,
        'candidate_late_module_compiled':explicit_source is not None,
        'candidate_late_argument_entered_callsite':entered==1 and explicit_source is not None,
        'candidate_late_verification_returned':diagnostic_verified,
        'expected_staged_late_reader_pin':dict(bytes=STAGED_LATE_PIN[0],sha256=STAGED_LATE_PIN[1]),
        'configured_executed_late_reader':dict(bytes=EXECUTED_LATE_PIN[0],sha256=EXECUTED_LATE_PIN[1]),
        'successor_runtime_claimed_staged':False,'memoization_added':False,
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
        raw=(json.dumps({'schema':result['schema'],'state':'EXPLICIT_READER_DIAGNOSTIC_SERIALIZATION_REJECTED_RETAIN_ORIGINALS',
            'label':LABEL,'nonce':NONCE,'error_type':type(exc).__name__,'detail':str(exc)[:1024],
            'original_verify_retired_callsite_entered':entered,'original_verify_retired_returned':returned,
            'original_verification_complete':False,'diagnostic_verification_complete':False,
            'original_global_clearance_evidence':False,'explicit_reader_source':explicit_source,
            'owned_verifier_lock_cleanup':cleanup,
            'failed_prelaunch_predecessor_closed_here':False,'component_qualified':False,
            'phone_case_or_source_writes':0,'automatic_retry':False},sort_keys=True,separators=(',',':'))+'\n').encode()
        diagnostic_verified=False
    sys.stdout.write(raw.decode())
    return 0 if diagnostic_verified else 1

if __name__=='__main__':raise SystemExit(main())
