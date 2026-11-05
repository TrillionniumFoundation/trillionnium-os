#!/usr/bin/env python3
"""Root-only host receipt entry for existing actual NEG-08/09 originals.
No phone/UI/model command is started. Preview never reads a case plan.
Actual execution requires separately frozen source dependencies, complete
original operations and complete two-host archives. An existing output refuses
replay; failures retain the original read set without a PASS claim.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import traceback
import types

sys.dont_write_bytecode=True
B=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
PURE_MODULES = {'negative_originals': {'bytes': 37253, 'sha256': '939674588f6229e27b71581a45bbf5b92e53c7b71edf2dab836e1f83158ec8b2'}, 'close_cpu_negative': {'bytes': 43958, 'sha256': '5c4314195c84c30352c21e381957a922676ea16eadd8a86450da59012f949ce5'}}
SELF_LIMIT=65536
MAX_ORIGINAL=64*1024*1024
MAX_POOL=192*1024*1024
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')

class HostUnverified(ValueError):
    pass

def need(ok,message):
    if not ok:raise HostUnverified(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encoded(value):
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()

def strict(raw):
    def pairs(items):
        result={}
        for key,value in items:
            need(key not in result,'duplicate_JSON_key')
            result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(HostUnverified('nonfinite_JSON')))

def metadata(info):
    return {key:getattr(info,key) for key in META}

def canonical(path):
    need(type(path) is str and '\0' not in path and str(Path(path))==path and
         Path(path).is_absolute() and '..' not in Path(path).parts and Path(path).is_relative_to(B),
         'explicit_canonical_project_original')
    return Path(path)

def parent_fd(path):
    path=canonical(str(path))
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=new
        return fd,path.name
    except BaseException:
        os.close(fd);raise

def read_regular(path,maximum):
    parent,leaf=parent_fd(path);fd=None
    try:
        fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=maximum,
             'original_regular_single_link_bound')
        blocks=[];size=0
        while True:
            block=os.read(fd,min(65536,maximum+1-size))
            if not block:break
            size+=len(block);need(size<=maximum,'original_stream_bound');blocks.append(block)
        raw=b''.join(blocks);after=os.fstat(fd)
        named=os.stat(leaf,dir_fd=parent,follow_symlinks=False);absolute=os.lstat(path)
        need(metadata(before)==metadata(after)==metadata(named)==metadata(absolute) and len(raw)==before.st_size,
             'original_full9_bookends')
        return raw,metadata(before)
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)

def read_pin(row,maximum=MAX_ORIGINAL):
    need(type(row) is dict and set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int and
         0<=row['bytes']<=maximum and re.fullmatch('[0-9a-f]{64}',row['sha256']),
         'explicit_exact_original_descriptor')
    raw,meta=read_regular(canonical(row['path']),maximum)
    need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'original_bytes_and_SHA')
    return raw,meta

class OriginalReadSet:
    def __init__(self):
        self.rows={};self.total=0
    def read(self,row):
        raw,meta=read_pin(row)
        old=self.rows.get(row['path'])
        if old is None:
            self.total+=len(raw);need(self.total<=MAX_POOL,'bounded_host_original_pool')
            self.rows[row['path']]={'descriptor':dict(row),'source_metadata':meta,'raw':raw}
        else:
            need(old['descriptor']==row and old['source_metadata']==meta and old['raw']==raw,
                 'original_read_set_changed')
        return raw
    def recheck(self):
        for row in list(self.rows.values()):
            raw,meta=read_pin(row['descriptor'])
            need(raw==row['raw'] and meta==row['source_metadata'],'final_original_read_set_changed')

def fsync_directory(path):
    parent,leaf=parent_fd(path)
    fd=None
    try:
        fd=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        os.fsync(fd)
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)

def new_directory(path):
    parent,leaf=parent_fd(path)
    try:
        os.mkdir(leaf,0o700,dir_fd=parent)
        fd=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        try:
            meta=os.fstat(fd)
            need(stat.S_IMODE(meta.st_mode)==0o700 and meta.st_uid==os.geteuid(),'new_private_directory')
            os.fsync(fd)
        finally:os.close(fd)
        os.fsync(parent)
    finally:os.close(parent)

def put(path,raw):
    need(type(raw) is bytes,'raw_output_bytes')
    parent,leaf=parent_fd(path);fd=None
    try:
        fd=os.open(leaf,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
        data=memoryview(raw)
        while data:
            count=os.write(fd,data);need(count>0,'short_output_write');data=data[count:]
        os.fsync(fd);os.fsync(parent)
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)
    observed,_=read_regular(path,max(MAX_ORIGINAL,len(raw)))
    need(observed==raw,'create_only_output_readback')
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}

def load_pure():
    need(type(PURE_MODULES) is dict and set(PURE_MODULES)=={'negative_originals','close_cpu_negative'},
         'reviewed_source_module_pins_unfrozen')
    here=canonical(os.path.abspath(__file__)).parent;loaded={};saved={}
    try:
        for name in ('negative_originals','close_cpu_negative'):
            row=PURE_MODULES[name]
            need(type(row) is dict and set(row)=={'bytes','sha256'} and 0<row['bytes']<=131072,
                 'reviewed_pure_module_descriptor')
            raw,meta=read_regular(here/(name+'.py'),131072)
            need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'reviewed_pure_module_bytes')
            mod=types.ModuleType(name);mod.__file__=str(here/(name+'.py'))
            saved[name]=sys.modules.get(name);sys.modules[name]=mod
            exec(compile(raw,mod.__file__,'exec'),mod.__dict__)
            loaded[name]={'module':mod,'raw':raw,'metadata':meta}
        return loaded
    finally:
        for name,value in saved.items():
            if value is None:sys.modules.pop(name,None)
            else:sys.modules[name]=value

def persist_inputs(out,readset):
    root=out/'input-originals';new_directory(root);seen={};index=[]
    for path,row in sorted(readset.rows.items()):
        raw=row['raw'];digest=sha(raw)
        if digest not in seen:
            seen[digest]=put(root/(digest+'.original'),raw)
        index.append({'source':path,'bytes':len(raw),'sha256':digest,
                      'source_metadata':row['source_metadata'],'retained':seen[digest],
                      'copy_metadata_is_not_source_metadata':True})
    return put(out/'INPUT-ORIGINALS.json',encoded({'schema':'hepta.cpu-negative.original-read-set.v1',
            'rows':index,'all_readback_checked':True,'private_original_bodies_are_not_stdout':True}))

def persist_archive_members(out,context):
    root=out/'originals';new_directory(root);dirs={str(root)}
    for path,raw in sorted(context['retained'].items()):
        target=canonical(path)
        need(target.is_relative_to(root),'retained_path_outside_private_originals')
        relative=target.relative_to(root);current=root
        for component in relative.parts[:-1]:
            current=current/component
            if str(current) not in dirs:new_directory(current);dirs.add(str(current))
        put(target,raw)
    for path in sorted(dirs,key=lambda p:len(Path(p).parts),reverse=True):fsync_directory(Path(path))

def preview():
    return {'schema':'hepta.r10.cpu-negative-host-preview.v1','state':'SOURCE_ONLY_NO_CASE_READ',
      'future_release_dependencies_must_be_frozen':True,'product_case_main_executed':False,
      'required_plan_schema':'hepta.r10.cpu-negative-closure-plan.v1',
      'allowed_cases':['NEG-08','NEG-09'],'qualification_layer':'physical_native_task',
      'finalization_calls_phone':False,'host_isolated_qualification':None,
      'model_business_qualification':False,'physical_case_pass':False,
      'new_native_nonces':0,'phone_calls':0,'model_requests':0,'automatic_retry':False}

def execute(args):
    loaded=load_pure();assembly=loaded['negative_originals']['module'];closer=loaded['close_cpu_negative']['module']
    final=assembly.final_dependencies()  # Before opening a case plan/private original or creating output.
    need(args.plan and args.plan_sha256 and args.reviewed_source_sha256,'explicit_root_reviewed_inputs')
    self_raw,_=read_regular(canonical(os.path.abspath(__file__)),SELF_LIMIT)
    need(sha(self_raw)==args.reviewed_source_sha256,'actual_compiled_Root_source_pin')
    need(re.fullmatch('[0-9a-f]{64}',args.plan_sha256),'plan_SHA')
    plan_raw,_=read_regular(canonical(args.plan),4*1024*1024)
    need(sha(plan_raw)==args.plan_sha256,'actual_closure_plan_raw_pin')
    plan=assembly.validate_plan(strict(plan_raw));nonce=plan['nonce']
    need(args.plan==str(B/'cpu-cancel-negative-inputs-r1'/nonce/'PLAN.json'),
         'explicit_existing_case_plan_namespace')
    out=canonical(plan['out']);parent=B/'cpu-cancel-negative-closures-r1'
    need(out.parent==parent,'fixed_output_namespace')
    # The Root operator prepares this private evidence parent once. This entry
    # creates only its new nonce directory and descendants, never another case.
    parent_meta=os.lstat(parent)
    need(stat.S_ISDIR(parent_meta.st_mode) and stat.S_IMODE(parent_meta.st_mode)==0o700 and
         parent_meta.st_uid==os.geteuid(),'reviewed_private_closure_parent')
    new_directory(out)
    put(out/'PLAN.original.json',plan_raw)
    for name,row in loaded.items():put(out/(name+'.SOURCE.original.py'),row['raw'])
    put(out/'ROOT.SOURCE.original.py',self_raw)
    put(out/'INTENT.json',encoded({'schema':'hepta.r10.cpu-negative-host-intent.v1','case_id':plan['case_id'],
       'nonce':nonce,'scope':plan['scope'],'plan_sha256':sha(plan_raw),'Root_source_sha256':sha(self_raw),
       'maximum_closure_attempts':1,'qualification_requested':args.qualify_original_case_once,
       'phone_calls':0,'new_native_nonces':0,'automatic_retry':False}))
    reads=OriginalReadSet();context=None;input_index=None
    need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'preexisting_host_alarm')
    previous=signal.getsignal(signal.SIGALRM)
    def expired(_signal,_frame):raise TimeoutError('bounded_pure_host_verification')
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,120)
    try:
        closure,context=closer.close_originals(plan_raw,read_pinned=reads.read)
        reads.recheck()
        signal.setitimer(signal.ITIMER_REAL,0);signal.setitimer(signal.ITIMER_REAL,30)
        persist_archive_members(out,context)
        input_index=persist_inputs(out,reads)
        reads.recheck()
        put(out/'ASSEMBLY.json',assembly.encoded(context['assembly_summary']))
        put(out/'CPU-INPUTS.private.json',context['cpu_inputs_raw'])
        put(out/'CPU-RESULT.json',assembly.encoded(closure['CPU_result']))
        closure['Root_original_input_index']=input_index
        closure['Root_closer_source_sha256']=sha(loaded['close_cpu_negative']['raw'])
        closure['Root_assembler_source_sha256']=sha(loaded['negative_originals']['raw'])
        closure['Root_entry_source_sha256']=sha(self_raw)
        closure_raw=assembly.encoded(closure)
        desc=put(out/'CLOSURE.original.json',closure_raw)
        receipt=None
        if args.qualify_original_case_once and closure['CPU_case_eligible'] is True:
            receipt=closer.qualification_receipt(closure,desc)
            put(out/'PHYSICAL-NEGATIVE-RECEIPT.json',assembly.encoded(receipt))
        result={'schema':'hepta.r10.cpu-negative-host-result.v1','state':closure['state'],
            'case_id':plan['case_id'],'nonce':nonce,'closure':desc,
            'ordinary_cancellation_verified':closure['ordinary_cancellation_verified'],
            'CPU_case_eligible':closure['CPU_case_eligible'],'physical_case_pass':receipt is not None,
            'qualification_layer':'physical_native_task' if receipt is not None else None,
            'host_isolated_qualification':None,'model_business_qualification':False,
            'input_original_index':input_index,'phone_calls':0,'new_nonces':0,'automatic_retry':False}
        put(out/'RESULT.json',encoded(result));fsync_directory(out)
        print(encoded(result).decode(),end='')
        return 0 if not args.qualify_original_case_once or receipt is not None else 3
    except BaseException as error:
        signal.setitimer(signal.ITIMER_REAL,0)
        archive_error=None
        try:
            if input_index is None and not (out/'input-originals').exists():
                input_index=persist_inputs(out,reads)
        except BaseException as inner:archive_error=type(inner).__name__
        failure={'schema':'hepta.r10.cpu-negative-host-failure.v1','state':'UNVERIFIED_OR_UNKNOWN_ORIGINALS_RETAINED',
            'case_id':plan['case_id'],'nonce':nonce,'error_class':type(error).__name__,
            'input_original_index':input_index,'retention_error_class':archive_error,
            'original_read_count':len(reads.rows),'closed':False,'physical_case_pass':False,
            'CPU_case_eligible':False,'identity_release_permitted':False,'same_identity_replay_permitted':False,
            'phone_calls':0,'new_nonces':0,'automatic_retry':False}
        put(out/'FAILURE.json',encoded(failure))
        put(out/'ERROR.private.txt',traceback.format_exc().encode('utf-8'))
        fsync_directory(out);print(encoded(failure).decode(),end='');return 2
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--plan');p.add_argument('--plan-sha256');p.add_argument('--reviewed-source-sha256')
    modes=p.add_mutually_exclusive_group()
    modes.add_argument('--close-originals-once',action='store_true')
    modes.add_argument('--qualify-original-case-once',action='store_true')
    args=p.parse_args()
    if not args.close_originals_once and not args.qualify_original_case_once:
        print(encoded(preview()).decode(),end='');return 0
    os.umask(0o077)
    return execute(args)

if __name__=='__main__':raise SystemExit(main())
