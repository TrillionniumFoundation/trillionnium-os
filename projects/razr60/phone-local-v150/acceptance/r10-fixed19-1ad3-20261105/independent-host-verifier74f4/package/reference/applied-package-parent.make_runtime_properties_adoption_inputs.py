#!/usr/bin/env python3
"""Collect exact actual originals for a host-only adoption preview; never adopt policy."""
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

def assemble(H,o,V,plan):
    H.need(set(plan)=={'schema','live_provenance','offline_proof_inputs','post_live_proof_inputs'}
        and plan['schema']=='hepta.runtime-properties-r10.adoption-input-collection-plan.v1','exact original collection plan')
    pool={}
    def add(row):
        V.file_descriptor(row);old=pool.get(row['path']);H.need(old is None or old==row,'original path changed')
        raw=o.pinned(row);pool[row['path']]=row;return raw
    live_raw=add(plan['live_provenance']);live=V.strict(live_raw)
    H.need(live['schema']=='hepta.runtime-properties-r10.live-provenance-inputs.v1','actual original live provenance required')
    for key,row in live.items():
        if key not in ('schema','originals'):add(row)
    for row in live['originals'].values():add(row)
    files=live['originals']
    expectation=V.strict(add(live['pre_live_expectation']))
    for key in ('binding','root_scope_decision','offline_comparison'):add(expectation[key])
    prepared=V.strict(add(live['prepared']))
    for key in ('stage_requests','stage_request_provenance','apply_request'):add(prepared[key])
    for row in V.strict(add(prepared['stage_request_provenance'])):
        add(row['source']);add(row['request'])
    root=V.strict(add(live['root_plan']))
    V.verify_prior_failed_transaction(add(root['prior_failed_transaction']),read_pinned=add)
    for key in ('driver_source','source_package','capture_source','transport_root_plan'):
        add(root[key])
    package=V.strict(add(root['source_package']));parent=Path(root['source_package']['path']).parent
    for row in package['files']:add({'path':str(parent/row['path']),'bytes':row['bytes'],'sha256':row['sha256']})
    execution=V.strict(add(live['root_execution']))
    for step in execution['steps']:add(step['stdout']);add(step['stderr'])
    indices={}
    for kind in ('offline','post_live'):
        desc=plan[kind+'_proof_inputs'];value=V.strict(add(desc));indices[kind]=value
        for row in value['files']:add(row)
    binding=V.strict(add(files['BINDING.original.json']))
    value={'schema':'hepta.runtime-properties-r10.policy-adoption.v1','release_id':'v150-r10-r1','boot_id':V.BOOT,
        'root_scope_decision':files['ROOT-SCOPE-DECISION.original.json'],
        'parent_adoption_history':files['PARENT-ADOPTION-HISTORY.original.json'],
        'parent_policy':V.PARENT,'actual_export':files['live-policy-after.bin'],
        'offline_candidate':binding['offline_candidate'],'delta_rule':files['runtime-properties.delta.rule'],
        'parent_rule':files['parent-candidate.rule'],'full_rule':files['full-candidate.rule'],
        'retirement_descriptor':files['ACTUAL-RETIREMENT-INPUTS.original.json'],
        'retirement_host_closure':files['RETIREMENT-HOST-CLOSURE.original.json'],
        'pre_policy_boundary_descriptor':files['LATEST-BOUNDARY-DESCRIPTOR.original.json'],
        'pre_policy_boundary':V.BOUNDARY,'offline_comparison':indices['offline']['report'],
        'post_live_comparison':indices['post_live']['report'],
        'offline_proof_inputs':plan['offline_proof_inputs'],'post_live_proof_inputs':plan['post_live_proof_inputs'],
        'live_provenance':plan['live_provenance'],'pre_live_expectation':live['pre_live_expectation'],
        'verification_originals':list(pool.values()),'root_decision':None}
    summary=V.validate_adoption_value(value,read_pinned=o.pinned,require_root_decision=False)
    H.need(len([r for r in value['verification_originals'] if r['sha256']==V.reviewed_source_sha256()])==1,
        'one unique captured verifier original required; proof map must retain that same host copy')
    value['schema']='hepta.runtime-properties-r10.policy-adoption-inputs.v1';return value,summary


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--plan',type=Path,required=True)
    p.add_argument('--plan-sha256',required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--execute-host-inputs',action='store_true');a=p.parse_args(argv)
    if not a.execute_host_inputs:
        print(json.dumps({'state':'PREVIEW_NO_ORIGINAL_READ_NO_ADOPTION','phone_calls':0,'policy_writes':0}));return 0
    os.umask(0o077);H=support();o=H.Originals();V=H.verifier(o)
    plan=V.strict(o.read(a.plan,a.plan_sha256));value,summary=assemble(H,o,V,plan);o.recheck()
    row=H.put_new(a.out,V.encoded(value));o.recheck()
    print(json.dumps({'state':'ACTUAL_ADOPTION_INPUTS_CREATED_NOT_ADOPTED','inputs':row,
        'actual_policy':summary['runtime_policy'],'verification_original_count':summary['verification_original_count'],
        'verification_original_bytes':summary['verification_original_bytes'],
        'phone_calls':0,'policy_writes':0,'automatic_adoption':False},sort_keys=True));return 0

if __name__=='__main__':raise SystemExit(main())
