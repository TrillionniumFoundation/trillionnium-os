#!/usr/bin/env python3
"""Pure host fresh-input builder; no nonce, original replay or remote action.

Loads the actual six admission modules from the exact R10 FREEZE closure.
The unchanged existing host helper supplies reads, audit and create-only
publication. Default is a read-only preview; --publish-input-once writes one
independent admission-input directory, never the component request/output.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types

sys.dont_write_bytecode = True
B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
R10 = B/'native-guard-r10-r1-operator-fc33-native-v3-r10'
RETAINED_FAILED_TRANSPORT = {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/retained-transport-r9-failed01/RETENTION-INPUTS.json', 'bytes': 431, 'sha256': 'a49f04c7e6be09e9d46b00176b9a0baf4489b12d764abbfe4482f5c839fee01d'}
HELPER = {'path': str(B/'library-checkpoint02-resume-a1055-r1/restored/integration-review/diagnostic-root-plan-candidate01/source/prepare_diagnostic_root_plan_once.py'),
          'bytes': 35690, 'sha256': '4708d037d58fd5b40e2a15210887ce58d9e7d0857ef27057855031591ee7faf9'}
STAT_KEYS = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')


def need(v, text):
    if not v:
        raise ValueError(text)


def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def initial_helper():
    p = Path(HELPER['path'])
    need(p.is_absolute() and p.resolve(strict=True) == p, 'canonical exact existing host helper')
    fd = os.open(p, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == HELPER['bytes'], 'exact helper inode/type/size')
        with os.fdopen(fd,'rb',closefd=False) as stream:
            raw=stream.read(HELPER['bytes']+1)
        stamp=lambda s:tuple(getattr(s,k)for k in STAT_KEYS)
        need(stamp(before)==stamp(os.fstat(fd))==stamp(p.lstat()) and pin(raw)=={k:HELPER[k]for k in ('bytes','sha256')}, 'exact helper full9/hash bookends')
    finally:
        os.close(fd)
    h=types.ModuleType('actual_pure_host_admission_helper');h.__file__=str(p)
    exec(compile(raw,str(p),'exec'),h.__dict__)
    return h


def selected(h, o, freeze_desc, previous_desc, case):
    need(type(RETAINED_FAILED_TRANSPORT)is dict,
         'UNBOUND_ACTUAL_RETAINED_R9_TRANSPORT_PROOF_NO_ORIGINAL_READ_OR_CREATION')
    f=h.strict(o.read(freeze_desc))
    need(freeze_desc['path']==str(R10/'FREEZE-RESULT.json') and f.get('schema')=='hepta.fc33.native-bound.actual-host-freeze.v1'
         and f.get('state')=='FROZEN_FOR_NEW_NEG01_THEN_NEG02_NOT_QUALIFIED' and f.get('output')==str(R10), 'actual whole R10 FREEZE required')
    for key in ('phone_calls','native_submissions','new_nonces'):
        need(type(f.get(key)) is int and f[key]==0,'host freeze cannot confer phone/case credit')
    need(f.get('automatic_retry') is False and f.get('all_inputs_bookended_before_publication') is True
         and f.get('all_output_files_read_back') is True, 'actual freeze bookends required')
    members=f['files']
    need(type(members) is dict and 1<=len(members)<=2048,'bounded complete freeze member census')
    for name,row in members.items():
        path=Path(name)
        need(not path.is_absolute() and str(path)==name and '..'not in path.parts and row['path']==str(R10/name), 'exact full freeze member path')
        o.read(row)
    for name in ('build_fence_plan','verify_retained_preaccept','verify_retained_staged_r8','verify_retained_transport_r9','bound02_disposition','admission_entry'):
        row=members['dependencies/admission/'+name+'.py']
        raw=o.read(row);module=h.pure_module(raw,name,row['path']);sys.modules[name]=module
    D=sys.modules['bound02_disposition'];E=sys.modules['admission_entry']
    need(type(E.RESOLUTION)is dict and type(E.RETAINED_PREACCEPT)is dict and type(E.RETAINED_FAILED_STAGED)is dict and type(E.RETAINED_FAILED_TRANSPORT)is dict,
         'all four exact original dispositions must already be bound in frozen admission source')
    D.require_retained_transport_binding()
    need(D.same(E.RETAINED_FAILED_TRANSPORT, RETAINED_FAILED_TRANSPORT)
         and D.same(E.RETAINED_FAILED_TRANSPORT, D.RETAINED_FAILED_TRANSPORT_MANIFEST),
         'fresh builder, entry and original reader bind the same accepted R9 manifest')
    previous=h.strict(o.read(previous_desc));home=Path(previous_desc['path']).parent
    need(previous_desc['path']==str(home/'ACTUAL-PREVIOUS-INPUT.json'),'actual closed previous filename')
    parent_raw=o.raw(home/'ROOT-PLAN.original.json',1048576);parent=h.strict(parent_raw)
    need(parent.get('case_id')=='NEG-01' and previous['identity']['session_id']==parent['session_id']
         and previous['identity']['profile_id']==parent['profile_id']=='owner-open','actual predecessor Root plan identity')
    boundary_raw=o.raw(home/'LATE-BOUNDARY.original.json',16*1024*1024)
    descriptor_raw=o.raw(home/'LATE-BOUNDARY-DESCRIPTOR.json',1048576)
    label=D.CURRENT_LABELS[case]
    directory,out=h.require_unused(label)
    candidate={
        'package':f['runtime_manifest'],'source_package':f['root_chain_manifest'],'shared_materials':f['shared_materials'],
        'artifacts':members['ARTIFACTS.json'],'policy_adoption':f['actual_adoption'],'live_policy_sha256':f['actual_policy']['sha256']}
    if case=='NEG-02':
        need(home.name==D.CURRENT_LABELS['NEG-01'] and parent['package']==f['runtime_manifest']
             and parent['source_package']==f['root_chain_manifest'] and parent['policy_adoption']==f['actual_adoption'],
             'NEG02 input must follow this exact R10 NEG01 Root plan')
    context={'schema':D.CONTEXT_SCHEMA,'stage':'prepare-before-create','candidate':candidate,
        'case_id':case,'label':label,'nonce':None,'request':None,'out':str(out),'request_directory':str(directory),
        'previous':previous_desc,'prior_boundary_descriptor':{'path':str(home/'LATE-BOUNDARY-DESCRIPTOR.json'),**pin(descriptor_raw)},
        'prior_boundary_original':{'path':str(home/'LATE-BOUNDARY.original.json'),**pin(boundary_raw)},
        'boot_id':parent['boot_id'],'session_id':parent['session_id'],'profile_id':parent['profile_id']}
    output=Path(E.RESOLUTION['path']).parent/('admission-r10-'+case.lower().replace('-','')+'-01')
    need(output.parent.resolve(strict=True)==output.parent and not os.path.lexists(output),'new admission-input directory only; no resume/replay')
    fresh={'schema':D.FRESH_SCHEMA,'original':D.ORIGINAL,'resolution_sha256':E.RESOLUTION['sha256'],
        'retained_preaccept':E.RETAINED_PREACCEPT,'retained_failed_staged':E.RETAINED_FAILED_STAGED,
        'retained_failed_transport':E.RETAINED_FAILED_TRANSPORT,
        **{k:context[k]for k in ('candidate','case_id','label','previous','prior_boundary_descriptor','prior_boundary_original','boot_id','session_id','profile_id')},
        'reservation':{'label':label,'case_id':case,'request_directory':str(directory),'out':str(out),'maximum_nonce_generations':1}}
    raw=D.canonical(fresh);fresh_desc={'path':str(output/'FRESH-INPUT.json'),**pin(raw)}
    def preview_read(row):
        if row==fresh_desc:
            return raw
        return o.read(row)
    receipt=D.fresh_admission(context,E.RESOLUTION,fresh_desc,retained_preaccept_descriptor=E.RETAINED_PREACCEPT,
                              retained_failed_staged_descriptor=E.RETAINED_FAILED_STAGED,
                              retained_failed_transport_descriptor=E.RETAINED_FAILED_TRANSPORT,
                              read_pinned=preview_read,read_live_fence=E.read_live_fence)
    need(receipt['standalone_execution_authorized']is False and receipt['native_case_credit']is False,'additional disposition gate only')
    operator={'schema':D.OPERATOR_SCHEMA,'resolution':E.RESOLUTION,'retained_preaccept':E.RETAINED_PREACCEPT,'retained_failed_staged':E.RETAINED_FAILED_STAGED,'retained_failed_transport':E.RETAINED_FAILED_TRANSPORT,'fresh_observation':fresh_desc}
    return D,E,context,output,raw,operator,receipt


def main():
    p=argparse.ArgumentParser()
    for key in ('freeze','previous'):
        p.add_argument('--'+key,required=True);p.add_argument('--'+key+'-bytes',type=int,required=True);p.add_argument('--'+key+'-sha256',required=True)
    p.add_argument('--case',choices=('NEG-01','NEG-02'),required=True)
    p.add_argument('--publish-input-once',action='store_true')
    a=p.parse_args()
    need(type(RETAINED_FAILED_TRANSPORT)is dict,
         'UNBOUND_ACTUAL_RETAINED_R9_TRANSPORT_PROOF_NO_ORIGINAL_READ_OR_CREATION')
    h=initial_helper();sys.addaudithook(h.audit);o=h.Originals()
    row=lambda name:{'path':getattr(a,name),'bytes':getattr(a,name+'_bytes'),'sha256':getattr(a,name+'_sha256')}
    D,E,context,output,fresh_raw,operator,receipt=selected(h,o,row('freeze'),row('previous'),a.case)
    o.recheck();h.require_unused(context['label'])
    if not a.publish_input_once:
        print(json.dumps({'state':'EXACT_FRESH_INPUT_PREVIEW_ONLY','case_id':a.case,'label':context['label'],
            'planned_admission_directory':str(output),'nonce_generations':0,'phone_calls':0,'files_written':0,
            'standalone_execution_authorized':False},sort_keys=True));return
    h.reserve(output)
    fresh_desc=h.put(output/'FRESH-INPUT.json',fresh_raw)
    need(fresh_desc==operator['fresh_observation'],'published fresh input differs')
    operator_desc=h.put(output/'ORIGINAL-ATTEMPT-ADMISSION.json',D.canonical(operator))
    actual=D.fresh_admission(context,E.RESOLUTION,fresh_desc,retained_preaccept_descriptor=E.RETAINED_PREACCEPT,
                              retained_failed_staged_descriptor=E.RETAINED_FAILED_STAGED,
                              retained_failed_transport_descriptor=E.RETAINED_FAILED_TRANSPORT,
                             read_pinned=o.read,read_live_fence=E.read_live_fence)
    o.recheck();h.require_unused(context['label'])
    result={'schema':'hepta.r10.original-dispositions.actual-fresh-input-preparation.v1','state':'ONE_ADMISSION_INPUT_PREPARED_NO_COMPONENT_PLAN',
        'actual_freeze':row('freeze'),'actual_previous':row('previous'),'case_id':a.case,'label':context['label'],
        'original_attempt_admission':operator_desc,'fresh_input':fresh_desc,'additional_gate':actual,
        'nonce_generations':0,'component_plans_created':0,'component_outputs_created':0,'phone_calls':0,
        'native_submissions':0,'automatic_retry':False,'original_terminal':None,'current_case_credit':0}
    result_desc=h.put(output/'RESULT.json',D.canonical(result))
    print(json.dumps({'state':result['state'],'result':result_desc,'original_attempt_admission':operator_desc,
                      'fresh_input':fresh_desc,'nonce_generations':0,'phone_calls':0,'standalone_execution_authorized':False},sort_keys=True))


if __name__=='__main__':
    main()
