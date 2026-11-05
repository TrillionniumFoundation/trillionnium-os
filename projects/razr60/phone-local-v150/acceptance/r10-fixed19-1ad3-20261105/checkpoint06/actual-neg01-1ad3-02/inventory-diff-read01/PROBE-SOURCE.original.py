#!/usr/bin/env python3
"""One fixed later actual08 inventory observation and complete field diff only."""
import sys
sys.dont_write_bytecode=True
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import types

LABEL='root-r10-neg01-1ad3-01'
CASE_HOME=Path('/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1')/LABEL
ANDROID=Path('/proc/1/root')
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
PACKAGE_PIN=(16808,'67dc40470b8ecb1e10cb57f8953a3d0b6db309b45079216eb24cd65f0760107c')
OUTPUT_LIMIT=8*1024*1024
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
READSET={}
DIRECTORIES={}
READ_BYTES=0

FAILED_LABEL='root-r10-neg01-1ad3-02'
FAILED_NONCE='bc0573ad459cecae9884d6a46568621b'
ACTUAL08={'bytes': 9373, 'metadata': [65086, 153711, 33152, 0, 0, 1, 9373, 1793853757339925229, 1793853757339925229], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/2b0b103ee6de7a422064b9571266bf5d.json', 'sha256': 'eca941303197228ebe03561e612bfe41eb0518c590ff21253444db25a11adc10'}
EXPECTED_INVENTORY={'bytes': 849854, 'metadata': [65086, 156653, 33152, 0, 0, 1, 849854, 1793853752103925231, 1793853752103925231], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/2b0b103ee6de7a422064b9571266bf5d/AFTER-INVENTORY.original.json', 'sha256': '80b8a56ee78055c19caf3b342af5bc5e479180843b0f3bc223751649188b7fc4'}
EXPECTED_ROOTS=['/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/evidence', '/var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6/evidence', '/var/lib/trillionnium/owner-open/phone-local-v150/client-receipts', '/var/lib/trillionnium/owner-open/phone-local-v150/executor-r6', '/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/health-contracts/bindings', '/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/task-contracts/bindings', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03', '/proc/1/root/data/local/tmp/hepta-native-guard-88d68d88130d3c74e6c950a6346357c1', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04', '/proc/1/root/data/local/tmp/hepta-native-guard-c705647dd4ebb5d421be1041a9c41ca6', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05', '/proc/1/root/data/local/tmp/hepta-native-guard-e4c3ccb0b2d706be3b7bf105ae772405', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06', '/proc/1/root/data/local/tmp/hepta-native-guard-154588e3a15591a21ec18950d18e3ecd', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07', '/proc/1/root/data/local/tmp/hepta-native-guard-16805e43f9787c44c262d5b6c6d8ed95', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08', '/proc/1/root/data/local/tmp/hepta-native-guard-2b0b103ee6de7a422064b9571266bf5d']
FIXTURE_ROOTS=['/proc/1/root/data/local/tmp/hepta-native-guard-88d68d88130d3c74e6c950a6346357c1', '/proc/1/root/data/local/tmp/hepta-native-guard-c705647dd4ebb5d421be1041a9c41ca6', '/proc/1/root/data/local/tmp/hepta-native-guard-e4c3ccb0b2d706be3b7bf105ae772405', '/proc/1/root/data/local/tmp/hepta-native-guard-154588e3a15591a21ec18950d18e3ecd', '/proc/1/root/data/local/tmp/hepta-native-guard-16805e43f9787c44c262d5b6c6d8ed95', '/proc/1/root/data/local/tmp/hepta-native-guard-2b0b103ee6de7a422064b9571266bf5d']
COMMON_PIN=(19138, '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab')
LIFECYCLE_PIN=(40261, '144836347482b8871703b882283ffac63d5df480e3333a9bd631409f890fc1c2')
FAILED_STAGE_ORIGINAL={'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-1ad3-02/phone-stage/stdout.original', 'bytes': 3130, 'sha256': '049f43bb4c3a700b95ffd2de37a346499c2b0a6bb87822f9d9b27d9c22c9c15c'}
FAILED_PLAN={'path': '/workspace/scratch/1ad3d6f55439/actual_neg01_1ad3_02/ROOT-PLAN.json', 'bytes': 4772, 'sha256': 'e3b9d77a317f6c7ac7ea6bae9a3276c9f8a689563084a54d82d7417e2a17a3e7'}


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

def encoded(value):
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode('utf-8')

def complete_diff(expected,observed):
    """Complete before/after values; no ignored metadata, row cap or truncation."""
    left={k:v for k,v in expected.items() if k!='elapsed_seconds'}
    right={k:v for k,v in observed.items() if k!='elapsed_seconds'}
    old=left['entries'];new=right['entries']
    top=[]
    for key in sorted((set(left)|set(right))-{'entries'}):
        if key not in left or key not in right or left[key]!=right[key]:
            top.append({'field':key,'expected_present':key in left,'observed_present':key in right,
                        'expected':left.get(key),'observed':right.get(key)})
    added=[{'path':path,'observed':new[path]} for path in sorted(set(new)-set(old))]
    removed=[{'path':path,'expected':old[path]} for path in sorted(set(old)-set(new))]
    changed=[]
    for path in sorted(set(old)&set(new)):
        if old[path]==new[path]:continue
        before=old[path];after=new[path]
        fields=[key for key in sorted(set(before)|set(after))
                if key not in before or key not in after or before[key]!=after[key]]
        metadata_changes=[]
        if type(before.get('metadata')) is list and type(after.get('metadata')) is list:
            need(len(before['metadata'])==len(after['metadata'])==9,'complete full9 diff required')
            metadata_changes=[{'field':name,'expected':before['metadata'][index],
                               'observed':after['metadata'][index]}
                              for index,name in enumerate(META)
                              if before['metadata'][index]!=after['metadata'][index]]
        changed.append({'path':path,'expected':before,'observed':after,
                        'changed_fields':fields,'metadata_fields_changed':metadata_changes})
    equal=left==right
    need(equal==(not top and not added and not removed and not changed),'complete diff equality mismatch')
    return {'excluded_top_level_fields':['elapsed_seconds'],'comparison_is_original_object_equality':True,
            'root_order_preserved':True,'full9_fields_preserved':list(META),
            'normalized_equal':equal,'top_level_changes':top,'added_entries':added,
            'removed_entries':removed,'changed_entries':changed,
            'added_count':len(added),'removed_count':len(removed),'changed_count':len(changed),
            'truncated':False}

def main():
    started=time.monotonic();started_unix_ns=time.time_ns()
    phase='bootstrap';error=None;complete=False;entered=0;returned=0
    observed=None;observed_raw=None;difference=None;inventory_wall=None;inventory_cpu=None
    expected_valid=False;observed_valid=False;source_info=None;fd_cleanup=None
    try:
        need(len(sys.argv)==1,'fixed diagnostic has no alternate input or output paths')
        need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'actual Root credentials')
        boot_raw=boot();root,files=source_package()
        need((len(files['source/component_common.py']),sha(files['source/component_common.py']))==COMMON_PIN
             and (len(files['source/component_lifecycle.py']),sha(files['source/component_lifecycle.py']))==LIFECYCLE_PIN,
             'exact original inventory and read primitives required')
        C=load_module('component_common',root,files)
        load_module('native_proc_profile',root,files)
        L=load_module('component_lifecycle',root,files)
        late=load_module('late_boundary',root,files)
        source_info={'source_case':LABEL,'runtime_manifest':dict(bytes=PACKAGE_PIN[0],sha256=PACKAGE_PIN[1]),
            'inventory_module':dict(path=L.__file__,bytes=LIFECYCLE_PIN[0],sha256=LIFECYCLE_PIN[1]),
            'common_module':dict(path=C.__file__,bytes=COMMON_PIN[0],sha256=COMMON_PIN[1]),
            'inventory_source_identical_in_failed_a334_generation':True,
            'runtime_functions_rebound':False,'runtime_package_rewritten':False}
        boundary_raw=read_original(ACTUAL08['path'],16384,(ACTUAL08['bytes'],ACTUAL08['sha256']),ACTUAL08['metadata'])
        boundary=strict(boundary_raw)
        need(boundary['inventory']==EXPECTED_INVENTORY and boundary['boot_id']==BOOT,
             'actual08 exact inventory descriptor or boot differs')
        expected_raw=read_original(EXPECTED_INVENTORY['path'],16*1024*1024,
            (EXPECTED_INVENTORY['bytes'],EXPECTED_INVENTORY['sha256']),EXPECTED_INVENTORY['metadata'])
        expected=strict(expected_raw)
        need(expected['roots']==EXPECTED_ROOTS==boundary['roots'] and len(expected['entries'])==2413
             and expected['file_bytes_hashed']==16401835,'fixed actual08 complete expected inventory differs')
        fixtures=[path for path in expected['roots'] if re.fullmatch(
            r'/proc/1/root/data/local/tmp/hepta-native-guard-[0-9a-f]{32}',path)]
        need(fixtures==FIXTURE_ROOTS and len(fixtures)==6,'exact six original fixture roots required')
        expected_value=late.inventory_value(expected);expected_valid=True
        before=own_fds();phase='one_original_inventory_call'
        call_start=time.monotonic();cpu_start=time.process_time()
        try:
            entered+=1
            observed=L.inventory(expected['roots'],fixture_roots=fixtures)
            returned+=1
        finally:
            inventory_wall=time.monotonic()-call_start;inventory_cpu=time.process_time()-cpu_start
            after=own_fds()
            remaining=[{'fd':fd,'identity':list(identity)} for fd,identity in after.items()
                       if fd>=3 and before.get(fd)!=identity]
            fd_cleanup={'new_FDs_remaining':remaining,'complete':not remaining,
                        'diagnostic_closed_unknown_or_foreign_FDs':False,'lock_acquisitions':0}
        need(entered==returned==1 and fd_cleanup['complete'],'one inventory return with all read FDs closed required')
        observed_raw=encoded(observed)
        need(len(observed_raw)<=OUTPUT_LIMIT,'complete observed inventory exceeds diagnostic output bound')
        phase='full_field_comparison'
        observed_value=late.inventory_value(observed);observed_valid=True
        difference=complete_diff(expected,observed)
        need(difference['normalized_equal']==(expected_value==observed_value),
             'diff does not exactly reproduce original inventory_value equality')
        phase='original_read_bookends'
        recheck_bootstrap();need(boot()==boot_raw,'boot changed across fixed later observation')
        complete=True;phase='complete'
    except BaseException as exc:
        error={'type':type(exc).__name__,'detail':str(exc)[:2048],'phase':phase}
    state='LATER_INVENTORY_OBSERVATION_FAILED_OR_PARTIAL_RETAIN_ORIGINALS'
    if complete:
        state='LATER_INVENTORY_FULL_DIFF_RETAINED' if not difference['normalized_equal'] else 'LATER_INVENTORY_EQUALITY_OBSERVED_NO_ADMISSION'
    result={'schema':'hepta.native-guard.actual08-inventory-difference-observation.v1','state':state,
        'failed_case_label':FAILED_LABEL,'failed_case_nonce':FAILED_NONCE,
        'failed_stage_original_reference':FAILED_STAGE_ORIGINAL,'failed_plan_reference':FAILED_PLAN,
        'actual_last_native_boundary':ACTUAL08,'expected_inventory_original':EXPECTED_INVENTORY,
        'boot_id':BOOT,'source_binding':source_info,'fixture_roots':FIXTURE_ROOTS,
        'observation_started_unix_ns':started_unix_ns,'observation_ended_unix_ns':time.time_ns(),
        'inventory_call_entered':entered,'inventory_call_returned':returned,
        'inventory_wall_seconds':inventory_wall,'inventory_cpu_seconds':inventory_cpu,
        'total_wall_seconds':time.monotonic()-started,'expected_inventory_schema_valid':expected_valid,
        'observed_inventory_schema_valid':observed_valid,'observation_complete':complete,
        'observed_inventory_original':None if observed_raw is None else {
            'encoding':'utf-8','serialization':'sorted compact JSON with LF; exact text bytes retained',
            'bytes':len(observed_raw),'sha256':sha(observed_raw),'text':observed_raw.decode('utf-8')},
        'complete_difference':difference,'failure':error,'owned_read_fd_observation':fd_cleanup,
        'bootstrap_originals':list(READSET.values()),'bootstrap_source_directories':list(DIRECTORIES.values()),
        'fresh_later_observation_not_original_failed_stage_snapshot':True,
        'original_failed_stage_observed_inventory_available':False,'failure_cause_attributed':False,
        'whole_verifier_or_chain_executed':False,'verify_retired_calls':0,'current_inventory_wrapper_calls':0,
        'original_scan_limits_unchanged':{'seconds':30,'entries':30000,'total_file_bytes':512*1024*1024},
        'elapsed_limit_is_original_cooperative_scan_check_not_preemptible_IO_deadline':True,
        'output_limit_bytes':OUTPUT_LIMIT,'profiling_enabled':False,'tracing_enabled':False,
        'runtime_functions_rebound':False,'lease_changes':0,'new_nonces':0,
        'phone_case_or_source_writes':0,'runtime_main_calls':0,'process_launches':0,'signals':0,
        'model_requests':0,'native_sends':0,'boundary_publications':0,'fixture_attempts':0,
        'global_clearance_proof':False,'admission_granted':False,'component_qualified':False,'automatic_retry':False}
    try:
        raw=encoded(result);need(len(raw)<=OUTPUT_LIMIT,'complete diff exceeds eight-MiB output bound')
    except BaseException as exc:
        raw=encoded({'schema':result['schema'],'state':'COMPLETE_DIFF_SERIALIZATION_REFUSED_RETAIN_ORIGINALS',
            'failed_case_label':FAILED_LABEL,'failed_case_nonce':FAILED_NONCE,
            'error_type':type(exc).__name__,'detail':str(exc)[:1024],
            'inventory_call_entered':entered,'inventory_call_returned':returned,
            'observed_inventory_pin':None if observed_raw is None else {'bytes':len(observed_raw),'sha256':sha(observed_raw)},
            'observation_complete':False,'full_observed_retained':False,'global_clearance_proof':False,
            'admission_granted':False,'component_qualified':False,'phone_case_or_source_writes':0,'automatic_retry':False})
        complete=False
    sys.stdout.write(raw.decode('utf-8'))
    return 0 if complete else 1

if __name__=='__main__':raise SystemExit(main())
