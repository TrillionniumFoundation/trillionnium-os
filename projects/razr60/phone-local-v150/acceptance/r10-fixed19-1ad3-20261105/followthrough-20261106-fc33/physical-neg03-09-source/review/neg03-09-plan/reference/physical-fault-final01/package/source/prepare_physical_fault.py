#!/usr/bin/env python3
"""Prepare one registered physical-fault plan from actual originals; no phone or task."""
import argparse,ast,base64,hashlib,json,os,re,sys,types
from pathlib import Path
CAPTURE_SHA='f12a251542894d0e8c0dedc9d62eb96d4f39e2b1d563f849c2f60e6ee02580e3'

def bootstrap(manifest_sha):
    root=Path(__file__).resolve().parent.parent
    path=root/'SOURCE-MANIFEST.json'
    if path.resolve(strict=True)!=path:
        raise ValueError('canonical source manifest required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        if not 0<st.st_size<=262144:
            raise ValueError('bounded manifest required')
        raw=os.read(fd,st.st_size+1)
    finally:
        os.close(fd)
    if len(raw)!=st.st_size or hashlib.sha256(raw).hexdigest()!=manifest_sha:
        raise ValueError('explicit source manifest pin differs')
    value=json.loads(raw)
    rows=[r for r in value['files'] if r['path']=='source/physical_fault_common.py']
    if len(rows)!=1:
        raise ValueError('one pinned common source required')
    p=root/rows[0]['path']
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        body=os.read(fd,rows[0]['bytes']+1)
    finally:
        os.close(fd)
    if len(body)!=rows[0]['bytes'] or hashlib.sha256(body).hexdigest()!=rows[0]['sha256']:
        raise ValueError('common source pin differs')
    S=types.ModuleType('physical_fault_common')
    S.__file__=str(p)
    exec(compile(body,str(p),'exec'),S.__dict__)
    originals=S.Originals()
    manifest_row=S.desc(path,raw)
    mf,files=S.load_members(originals,manifest_row)
    S.need(mf['schema']=='hepta.physical-fault.root-source-package.v1'
        and files['source/'+Path(__file__).name]==originals.known(Path(__file__).resolve(),131072)[1]
        and S.sha(files['source/owned_capture.py'])==CAPTURE_SHA,'reviewed complete physical source package required')
    capture=S.module(files['source/owned_capture.py'],root/'source/owned_capture.py','physical_owned_capture')
    return root,S,originals,manifest_row,files,capture


def prepare(S,C,root,originals,mf,files,value,raw):
    final=S.final_dependencies()
    fields={'schema','case_id','label','operation_id','sender_inputs','task_template','actual_ready',
            'expected_probe_component','configuration','service'}
    S.need(type(value) is dict and set(value)==fields and value['schema']=='hepta.physical-fault.prepare-inputs.v1' and
        value['case_id'] in S.CASE_IDS and all(re.fullmatch('[a-z0-9][a-z0-9-]{5,69}',value[k])
        for k in ('label','operation_id')),'explicit_registered_actual_case_material')
    dependency=S.strict(files['FREEZE-INPUT.original.json'])
    S.need(dependency['schema']=='hepta.physical-fault.freeze-inputs.v1','frozen_actual_source_package_required')
    inputs=value['sender_inputs']
    S.need(type(inputs) is dict and set(inputs)=={'request','previous','preserved_draft','retirement_resolution','registration_result'},
           'exact_existing_sender_inputs')
    owner=originals.read(inputs['request'],16000)
    previous=S.strict(originals.read(inputs['previous'],262144))
    template_raw=originals.read(value['task_template'],131072);template=S.strict(template_raw)
    ready_raw=originals.read(value['actual_ready'],32768);ready=S.strict(ready_raw)
    nonce=template['nonce'];S.need(re.fullmatch('[0-9a-f]{32}',nonce) and owner.decode('utf-8').count(nonce)==1 and
        template['schema']=='hepta.task-template.v150.3' and template['request_sha256']==S.sha(owner),
        'one_existing_registered_owner_nonce_template')
    S.need(template['expected_scope']=={k:previous['identity'][k] for k in ('session_id','profile_id')},
           'existing_registered_session_profile')
    sys.modules['physical_fault_common']=S
    O=S.module(files['source/fault_originals.py'],'fault_originals.py','fault_originals');sys.modules['fault_originals']=O
    P=S.module(files['source/fault_projections.py'],'fault_projections.py','fault_projections')
    post=P.projected(files['reference/task_postconditions.py'],
        {'require','app_scope_hash','validate_app_scope','resolve_task_apps','validate_conditions','validate_template'},
        {'SHA','ID','PACKAGE','VIEW','APP_COMPONENT','TASK_VERSIONS','APP_SCOPE_SCHEMA'},
        dict(hashlib=hashlib,json=json,re=re,ProviderError=ValueError))
    post.validate_template(template)
    configuration=S.strict(originals.read(value['configuration'],262144))
    post.validate_app_scope(template['app_scope'],S.sha(owner),configuration['approved_apps'])
    six=('source_seal_sha256','configuration_sha256','service_inputs_sha256','module_manifest_sha256',
         'component_boundary_inputs_sha256','policy_adoption_inputs_sha256')
    pins={k:ready[k] for k in six}
    binding={'schema':'hepta.r10.active-runtime-binding.v1','release_pins':pins,
             'readiness':{'bytes':len(ready_raw),'sha256':S.sha(ready_raw),'raw_b64':S.b64(ready_raw)}}
    fault,fb=S.load_members(originals,dependency['fault_package'],'runtime_sources')
    bundle={'manifest_b64':S.b64(originals.read(dependency['fault_package'],262144)),
            'sources':{name:S.b64(body) for name,body in fb.items()}}
    W=S.module(files['source/watch_physical_fault_once.py'],'watch_physical_fault_once.py','fault_plan_watch')
    actor,unused=W.load_actor(bundle,W.final_dependencies())
    actor.active.validate_runtime_binding(binding,S.BOOT)
    case=value['case_id'];probe=value['expected_probe_component']
    if case=='NEG-04':S.need(probe is None,'predispatch_case_has_no_probe_or_helper')
    else:S.need(probe in actor.PROBES and any(actor.projection.component(r['component'])==probe for r in template['app_scope']['apps']),
        'only_registered_disposable_probe_component')
    watch={'schema':'hepta.physical-fault.watch-plan.v1','case_id':case,'operation_id':value['operation_id'],
        'sender_label':value['label'],'nonce':nonce,'expected_boot':S.BOOT,
        'owner_request_b64':S.b64(owner),'owner_request_sha256':S.sha(owner),
        'previous_scope':previous['identity'],'roles':actor.active.role_rows(ready),'release_pins':pins,
        'expected_probe_component':probe,'android_shell_exe':None,'android_shell_sha256':None,'busybox_sha256':None,
        'app_scope':template['app_scope'],'task_template_sha256':S.sha(template_raw),'runtime_binding':binding,
        'fault_package_sha256':dependency['fault_package']['sha256']}
    if case in ('NEG-05','NEG-07'):
        watch.update(android_shell_exe=actor.STOCK_SHELL,android_shell_sha256=actor.STOCK_SHELL_SHA)
    if case=='NEG-05':watch['busybox_sha256']=actor.STOCK_BUSYBOX_SHA
    W.validate_plan(watch);actor.active.validate_task_expectations(watch,owner)
    out=S.B/'physical-fault-plans-r10-r1'/value['label']
    S.need(not out.exists() and not out.is_symlink(),'existing_plan_namespace_is_not_reusable')
    originals.recheck();os.umask(0o077)
    if not out.parent.exists():C.newdir(out.parent)
    C.newdir(out)
    C.put(out/'PREPARE-INPUT.original.json',raw)
    watch_raw=S.enc(watch);C.put(out/'WATCH-PLAN.json',watch_raw)
    plan={'schema':'hepta.physical-fault.root-plan.v1','case_id':case,'label':value['label'],'nonce':nonce,
        'out':str(S.B/'physical-faults-r10-r1'/value['label']),'watch_plan':S.desc(out/'WATCH-PLAN.json',watch_raw),
        'sender_source':originals.known(S.B/'send_new_native_task_r5.py',65536)[0],
        'sender_inputs':inputs,'configuration':value['configuration'],'service':value['service']}
    for key in ('runtime_package','fault_package','consumer','readiness','policy_adoption','actual_policy','combination_sha256'):
        plan[key]=dependency[key]
    S.admit(plan,originals,files)
    # Compile the exact future wire recipes now. Failure preserves this plan
    # namespace and occurs before any phone actor or native Send is started.
    stage,ref=S.operator_stage_request(bundle,nonce)
    request=S.source_request(files['source/watch_physical_fault_once.py'],watch_raw,'watch',ref)
    wire=lambda r:len(('shell,v2,raw:/debug_ramdisk/su -c '+__import__('shlex').quote(r['command'])).encode())
    packet={'schema':'hepta.physical-fault.p4-phase.v1','case_sha256':'0'*64,'nonce':nonce,'case_id':case,
            'phase':'watch','request':request}
    S.need(len(S.enc(packet))<=131072,'existing_P4_watch_envelope_budget')
    body=S.enc(plan);C.put(out/'ROOT-PLAN.json',body);originals.recheck()
    argv=['/usr/bin/python3','-I','-B',str(root/'source/run_physical_fault_once.py'),
        '--source-manifest-sha256',mf['sha256'],'--plan',str(out/'ROOT-PLAN.json'),
        '--plan-sha256',S.sha(body),'--execute-once']
    result={'schema':'hepta.physical-fault.prepared-plan.v1','state':'REGISTERED_ACTUAL_PLAN_PREPARED_NO_PHONE',
        'case_id':case,'nonce':nonce,'source_package':mf,'root_plan':S.desc(out/'ROOT-PLAN.json',body),
        'watch_plan':plan['watch_plan'],'execute_argv':argv,
        'phone_wire_bytes':{'operator_stage':wire(stage),'watch':wire(request)},
        'retained_task_template':value['task_template'],'retained_actual_READY':value['actual_ready'],
        'phone_calls':0,'new_send':0,'new_signal':0,'physical_case_pass':False,'whole_case_pass':False,
        'existing_sender_restoration_and_native_300s_gates_unchanged':True,'automatic_retry':False}
    C.put(out/'PREPARE-RESULT.json',S.enc(result));return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-manifest-sha256');p.add_argument('--inputs',type=Path);p.add_argument('--inputs-sha256')
    p.add_argument('--prepare-host-only',action='store_true');args=p.parse_args()
    if not args.prepare_host_only:
        print(json.dumps({'state':'SOURCE_PREVIEW_NO_INPUT_READ_NO_PHONE','phone_calls':0,'new_send':0,
            'physical_case_pass':False},sort_keys=True));return 0
    root,S,originals,mf,files,C=bootstrap(args.source_manifest_sha256);S.final_dependencies()
    row,raw=originals.known(args.inputs,65536);S.need(row['sha256']==args.inputs_sha256,'exact_explicit_prepare_input')
    result=prepare(S,C,root,originals,mf,files,S.strict(raw),raw)
    print(json.dumps(result,ensure_ascii=False,sort_keys=True));return 0


if __name__=='__main__':raise SystemExit(main())

