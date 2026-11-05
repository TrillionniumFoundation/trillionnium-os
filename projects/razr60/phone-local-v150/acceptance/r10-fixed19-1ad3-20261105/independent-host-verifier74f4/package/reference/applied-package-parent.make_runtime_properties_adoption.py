#!/usr/bin/env python3
"""Verify actual policy originals; only an explicit Root flag creates adoption."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import types

HOST_SUPPORT_SHA256='d1a3b84875fe1b02867b904463621fff5a602160cdebe300db5a89dd40b43593'

def support():
    path=Path(__file__).resolve().parent/'runtime_properties_host_originals.py'
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd)
        if not(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<a.st_size<=32768):raise ValueError('bounded host support source required')
        with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(32769)
        keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        if not(len(raw)==a.st_size and all(getattr(a,k)==getattr(os.fstat(fd),k)==getattr(path.lstat(),k) for k in keys)
            and hashlib.sha256(raw).hexdigest()==HOST_SUPPORT_SHA256):raise ValueError('reviewed host support source differs')
    finally:os.close(fd)
    m=types.ModuleType('raw_runtime_properties_host_support');m.__file__=str(path);exec(compile(raw,str(path),'exec'),m.__dict__);return m

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--inputs',type=Path,required=True)
    p.add_argument('--inputs-sha256',required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--expected-actual-policy-sha256');p.add_argument('--execute-root-adoption',action='store_true');a=p.parse_args(argv)
    H=support();o=H.Originals();V=H.verifier(o);raw=o.read(a.inputs,a.inputs_sha256);value=V.strict(raw)
    H.need(value['schema']=='hepta.runtime-properties-r10.policy-adoption-inputs.v1','explicit new adoption input schema')
    value=dict(value);value['schema']='hepta.runtime-properties-r10.policy-adoption.v1'
    summary=V.validate_adoption_value(value,read_pinned=o.pinned,require_root_decision=False);o.recheck()
    if not a.execute_root_adoption:
        print(json.dumps({'state':'VERIFIED_PREVIEW_NO_ADOPTION_WRITE','summary':summary,
            'actual_policy':summary['runtime_policy'],'phone_calls':0,'policy_writes':0},sort_keys=True));return 0
    H.need(a.expected_actual_policy_sha256==summary['runtime_policy']['sha256'],
        'Root must explicitly name the independently verified actual exported policy hash')
    value['root_decision']=summary['root_decision'];adopted=V.encoded(value)
    V.verify_adoption(adopted,read_pinned=o.pinned);o.recheck();os.umask(0o077)
    result=H.put_new(a.out,adopted);o.recheck()
    print(json.dumps({'state':'EXPLICIT_ACTUAL_POLICY_ADOPTION_CREATED','adoption':result,
        'actual_policy':summary['runtime_policy'],'phone_calls':0,'policy_writes':0,
        'service_start_admitted':False,'component_qualified':False},sort_keys=True));return 0

if __name__=='__main__':raise SystemExit(main())
