#!/usr/bin/env python3
"""Execute the reviewed runtime-property post-live comparison once on retained host files.

No capture, phone, policy setter, service control, or automatic retry exists here.
The actual plan and its hash are supplied explicitly after Root captures the
single transaction. Default preview reads no plan and starts no child process.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

POST_SHA='85f325f9525c3470b2fbfe1bf7167f80a54febcffd87d08d2e6cbcdde4597471'
POST_BYTES=65251
C_SHA='da60ee90209a26216f053064a7ca47ebcb73c4730b4e00378886b5d653de09aa'
C_BYTES=22838
PARENT_SHA='50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'
OUT_ROOT=Path('/home/alex/razr60-local-model-v150/policy-runtime-properties-r10-r1')

def need(ok,message):
    if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def strict(raw):
    def pairs(rows):
        value={}
        for key,item in rows:
            need(key not in value,'duplicate JSON key');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def meta(s):return [getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def syncdir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def put(path,raw):
    if not isinstance(raw,bytes):raw=encoded(raw)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    syncdir(path.parent);need(path.read_bytes()==raw,'original output readback')
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}

class Inputs:
    def __init__(self):self.rows={}
    def read(self,row):
        need(type(row) is dict and set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int
             and 0<=row['bytes']<=64*1024*1024 and re.fullmatch('[0-9a-f]{64}',row['sha256']),
             'exact bounded original descriptor')
        path=Path(row['path']);need(path.is_absolute() and path.resolve(strict=True)==path,'canonical original')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==row['bytes'],'regular original')
            with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(row['bytes']+1)
            need(meta(a)==meta(os.fstat(fd))==meta(path.lstat()),'original metadata changed')
        finally:os.close(fd)
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'original bytes changed')
        record={'descriptor':row,'metadata':meta(a)}
        need(str(path) not in self.rows or self.rows[str(path)]==record,'original changed between reads')
        self.rows[str(path)]=record;return raw
    def known(self,path,pin=None,size=None):
        need(path.is_absolute() and path.resolve(strict=True)==path,'canonical discovered original')
        a=path.lstat();need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=64*1024*1024,'bounded original')
        raw=path.read_bytes();row={'path':str(path),'bytes':len(raw),'sha256':sha(raw)}
        need(pin is None or row['sha256']==pin,'known original hash');need(size is None or row['bytes']==size,'known original size')
        self.read(row);return row
    def bookend(self):
        for item in list(self.rows.values()):self.read(item['descriptor'])
        return {path:row for path,row in sorted(self.rows.items())}

def require_finalized_sources():
    need(isinstance(POST_SHA,str) and re.fullmatch('[0-9a-f]{64}',POST_SHA)
         and type(POST_BYTES) is int and POST_BYTES>0
         and isinstance(C_SHA,str) and re.fullmatch('[0-9a-f]{64}',C_SHA)
         and type(C_BYTES) is int and C_BYTES>0,'reviewed post/image source pins remain unpublished')

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan',type=Path,required=True)
    parser.add_argument('--plan-sha256',required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--execute-host-only',action='store_true')
    a=parser.parse_args(argv)
    if not a.execute_host_only:
        print(json.dumps({'state':'PREVIEW_NO_ORIGINAL_READ_NO_CHILD','phone_operations':0,'active_policy_writes':0}));return 0
    require_finalized_sources()
    os.umask(0o077);sys.dont_write_bytecode=True
    need(re.fullmatch('[0-9a-f]{64}',a.plan_sha256),'explicit plan SHA')
    need(not os.environ.get('LD_PRELOAD') and not os.environ.get('LD_LIBRARY_PATH'),'injected library environment')
    inputs=Inputs();source=inputs.known(Path(__file__).resolve())
    comparator=inputs.known(Path(__file__).resolve().parent/'post_live_compare_runtime_properties.py',POST_SHA,POST_BYTES)
    inputs.known(Path(__file__).resolve().parent/'policy_runtime_properties_image.c',C_SHA,C_BYTES)
    plan_desc=inputs.known(a.plan,a.plan_sha256);plan=strict(inputs.read(plan_desc))
    need(plan['schema']=='hepta.runtime-properties-r10.post-live-complete-policy-comparison-plan.v2','actual post plan schema')
    need(plan['parent']['sha256']==PARENT_SHA and plan['parent']['bytes']==2667608,'actual adopted parent required')
    for key in ('parent','candidate','image_build_result','live_provenance_inputs','live_verifier_source'):
        inputs.read(plan[key])
    out=a.out
    need(out.is_absolute() and out.is_relative_to(OUT_ROOT) and out!=OUT_ROOT
         and out.parent.resolve(strict=True)==out.parent and not out.exists() and not out.is_symlink(),
         'new explicit project post-comparison output')
    out.mkdir(mode=0o700);syncdir(out.parent)
    argv=['/usr/bin/python3','-I','-B',comparator['path'],'--plan',str(a.plan),
          '--plan-sha256',a.plan_sha256,'--out',str(out/'comparison'),'--execute-host-only']
    before=inputs.bookend();start=time.time_ns();begin=time.monotonic()
    put(out/'INTENT.json',{'schema':'hepta.runtime-properties.host-execution-intent.v1','source':source,
        'plan':plan_desc,'comparator':comparator,'argv':argv,'maximum_comparison_seconds':780,
        'automatic_retry':False,'phone_operations':0,'active_policy_writes':0})
    try:
        done=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            check=False,timeout=780,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'})
    except subprocess.TimeoutExpired as exc:
        stdout=put(out/'full-comparison.stdout.original',exc.stdout or b'')
        stderr=put(out/'full-comparison.stderr.original',exc.stderr or b'')
        put(out/'full-comparison.PROCESS.json',{'argv':argv,'returncode':None,'timed_out':True,
            'captured_streams_complete':False,'stdout':stdout,'stderr':stderr,'automatic_retry':False,
            'started_epoch_ns':start,'ended_epoch_ns':time.time_ns(),'elapsed_seconds':time.monotonic()-begin,
            'input_originals_before':before,'input_originals_after':inputs.bookend(),
            'phone_operations':0,'active_policy_writes':0})
        raise
    stdout=put(out/'full-comparison.stdout.original',done.stdout);stderr=put(out/'full-comparison.stderr.original',done.stderr)
    process=put(out/'full-comparison.PROCESS.json',{'argv':argv,'returncode':done.returncode,'timed_out':False,
        'captured_streams_complete':True,'stdout':stdout,'stderr':stderr,'automatic_retry':False,
        'started_epoch_ns':start,'ended_epoch_ns':time.time_ns(),'elapsed_seconds':time.monotonic()-begin,
        'input_originals_before':before,'input_originals_after':inputs.bookend(),
        'phone_operations':0,'active_policy_writes':0})
    need(done.returncode==0 and done.stderr==b'','actual post comparison failed; original terminal retained')
    report_desc=inputs.known(out/'comparison/RESULT.json');report=strict(inputs.read(report_desc))
    need(report['schema']=='hepta.runtime-properties-r10.complete-policy-comparison.v1'
        and report['state']=='EXACT_APPROVED_RUNTIME_PROPERTY_READ_DELTA_VERIFIED'
        and report['comparison_kind']=='post_live_export'
        and report['parent']==plan['parent'] and report['candidate']==plan['candidate']
        and report['check_count']==report['passed_count']==16 and len(report['checks'])==16
        and all(x['passed'] is True for x in report['checks']),'actual sixteen post-comparison gates did not pass')
    inputs.bookend()
    execution=put(out/'EXECUTION.RESULT.json',{'schema':'hepta.runtime-properties.actual-host-execution.v1',
        'state':'ACTUAL_HOST_POST_LIVE_COMPLETE_COMPARISON_FINISHED','source':source,
        'root_scope_decision':plan['root_scope_decision'],'parent':plan['parent'],'candidate':plan['candidate'],
        'plan':plan_desc,'build':plan['image_build_result'],'comparison_process':process,'report':report_desc,
        'returncode':0,'timed_out':False,'captured_streams_complete':True,
        'automatic_retry':False,'all_originals_rechecked':True,'check_count':16,'passed_count':16,
        'phone_operations':0,'active_policy_writes':0,'live_policy_adoption_authorized':False,'business_qualified':False})
    print(json.dumps({'state':'ACTUAL_HOST_POST_LIVE_COMPLETE','execution':execution,'report':report_desc,
        'candidate':plan['candidate'],'checks':16,'phone_operations':0,'active_policy_writes':0},sort_keys=True));return 0

if __name__=='__main__':raise SystemExit(main())
