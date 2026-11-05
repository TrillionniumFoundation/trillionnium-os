#!/usr/bin/env python3
"""Create a separate final physical-fault package from exact actual dependencies; no effects."""
import argparse,ast,copy,hashlib,json,os,re,stat,sys,time,types
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


def rewrite(raw,values):
    tree=ast.parse(raw);lines=raw.splitlines(keepends=True);starts=[0]
    for line in lines:starts.append(starts[-1]+len(line))
    spans={}
    for node in tree.body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            key=node.targets[0].id
            if key in values:
                if key in spans:raise ValueError('duplicate pin assignment')
                v=node.value;spans[key]=(starts[v.lineno-1]+v.col_offset,starts[v.end_lineno-1]+v.end_col_offset)
    if set(spans)!=set(values):raise ValueError('exact pin slots required')
    result=raw
    for name,(a,b) in sorted(spans.items(),key=lambda x:x[1][0],reverse=True):
        result=result[:a]+repr(values[name]).encode('utf-8')+result[b:]
    compile(result,'<only-reviewed-pin-slots>','exec')
    return result


def created(S,path,raw):
    S.need(path.parent.resolve(strict=True)==path.parent,'canonical_new_output_parent')
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        before=os.fstat(fd);S.need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==0,
            'new_single_link_output_inode')
        with os.fdopen(fd,'wb',closefd=False) as stream:stream.write(raw);stream.flush();os.fsync(fd)
        after=os.fstat(fd);os.lseek(fd,0,0)
        with os.fdopen(fd,'rb',closefd=False) as stream:body=stream.read(len(raw)+1)
        S.need(body==raw and tuple(getattr(after,k) for k in S.META)==tuple(getattr(os.fstat(fd),k) for k in S.META)
            ==tuple(getattr(path.lstat(),k) for k in S.META) and
            all(getattr(before,k)==getattr(after,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink')),
            'new_output_inode_or_bytes_replaced')
    finally:os.close(fd)
    parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(parent)
    finally:os.close(parent)
    return S.desc(path,raw)


def derive(S,files,plan,originals):
    fields={'schema','out','runtime_package','fault_package','consumer','readiness','policy_adoption',
            'actual_policy','combination_sha256'}
    S.need(type(plan) is dict and set(plan)==fields and plan['schema']=='hepta.physical-fault.freeze-inputs.v1',
           'explicit_actual_freeze_inputs')
    S.need(re.fullmatch('[0-9a-f]{64}',plan['combination_sha256']),'actual_combination_pin')
    S.generation_inputs(plan,originals)
    fault,bodies=S.load_members(originals,plan['fault_package'],'runtime_sources')
    baseline=S.strict(files['reference/fault-package.original.json'])
    fixed={r['path']:r for r in baseline['runtime_sources']}
    S.need(fault.get('schema')=='hepta.r10.signal-fault-package.v1' and set(bodies)==set(fixed) and len(bodies)==8,
           'exact_original_fault_operator_inventory')
    for name,raw in bodies.items():
        if name!='source/active_runtime_r10.py':
            S.need(S.desc(name,raw)==fixed[name],'unchanged_fault_operator_member_'+name)
    active=bodies['source/active_runtime_r10.py'];old=files['reference/active_runtime_r10.original.py']
    slot_keys=('CONSUMER_SHA','READINESS_SHA','POLICY_SHA','ADOPTION_SHA')
    oldvalues={k:S.literal(old,k) for k in slot_keys}
    S.need(rewrite(active,oldvalues)==old,'only_four_original_shared_active_pin_slots_changed')
    wanted=dict(zip(slot_keys,[plan['consumer']['sha256'],plan['readiness']['sha256'],
                              plan['actual_policy']['sha256'],plan['policy_adoption']['sha256']]))
    S.need(all(S.literal(active,k)==v for k,v in wanted.items()),'actual_shared_active_pin_values')
    final={'fault_package_sha256':plan['fault_package']['sha256'],'active_source_sha256':S.sha(active),
        'runtime_package_sha256':plan['runtime_package']['sha256'],'consumer_sha256':plan['consumer']['sha256'],
        'readiness_sha256':plan['readiness']['sha256'],'policy_adoption_sha256':plan['policy_adoption']['sha256'],
        'combination_sha256':plan['combination_sha256'],'live_policy':{k:plan['actual_policy'][k] for k in ('bytes','sha256')}}
    watch={k:v for k,v in final.items() if k not in ('combination_sha256','live_policy')}
    watch['live_policy_sha256']=final['live_policy']['sha256']
    phone={k:v for k,v in final.items() if k!='combination_sha256'}
    phone.update(fault_verifier_sha256=S.sha(files['source/verify_physical_fault.py']),
        configuration_sha256='780754928709871d3e70f432acb6a021c6c97ab822aaf7c32c887c132cac8c34',
        service_inputs_sha256='2739a0af53650363e065bb71a448481998c68fc8b8632e61262c319dae6b586a')
    pins={'source/physical_fault_common.py':final,'source/watch_physical_fault_once.py':watch,
        'source/capture_fault_phone.py':phone,'source/capture_fault_p4.py':{'sender_sha256':S.SENDER_PIN[1]}}
    outputs=dict(files);rows=[]
    for name,value in pins.items():
        oldbody=files[name];S.need(S.literal(oldbody,'FINAL_DEPENDENCIES') is None,'candidate_must_be_unfrozen_'+name)
        new=rewrite(oldbody,{'FINAL_DEPENDENCIES':value})
        S.need(rewrite(new,{'FINAL_DEPENDENCIES':None})==oldbody,'whole_byte_pin_inverse_'+name)
        outputs[name]=new;rows.append({'path':name,'candidate':S.desc(name,oldbody),'final':S.desc(name,new),
                                      'whole_byte_inverse_after_one_RHS':True})
    S.need(sum(map(len,outputs.values()))<=32*1024*1024,'existing_32MiB_package_capacity')
    return outputs,final,rows


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-manifest-sha256');p.add_argument('--inputs',type=Path);p.add_argument('--inputs-sha256')
    p.add_argument('--freeze-source-only',action='store_true');args=p.parse_args()
    if not args.freeze_source_only:
        print(json.dumps({'state':'SOURCE_PREVIEW_NO_INPUT_READ_NO_PHONE','phone_calls':0,'task_submissions':0,
            'physical_case_pass':False},sort_keys=True));return 0
    root,S,originals,mf,files,C=bootstrap(args.source_manifest_sha256)
    row,raw=originals.known(args.inputs,65536);S.need(row['sha256']==args.inputs_sha256,'exact_explicit_freeze_input')
    plan=S.strict(raw);outputs,final,derivation=derive(S,files,plan,originals)
    out=Path(plan['out']);S.need(out.parent==S.B and re.fullmatch('physical-fault-r10-r1-final-[a-z0-9-]{6,60}',out.name),
        'new_exact_host_package_namespace')
    S.need(not out.exists() and not out.is_symlink(),'existing_source_package_cannot_be_replaced')
    originals.recheck();os.umask(0o077);C.newdir(out)
    outputs['FREEZE-INPUT.original.json']=raw
    outputs['CANDIDATE-SOURCE-MANIFEST.original.json']=originals.read(mf)
    outputs['FINALIZATION.json']=S.enc({'schema':'hepta.physical-fault.source-finalization.v1',
        'state':'EXACT_ACTUAL_DEPENDENCIES_BOUND_SOURCE_ONLY','candidate_source_package':mf,
        'freeze_input':row,'final_dependencies':final,'changed_sources':derivation,
        'independent_actual_adoption_is_prerequisite_not_awarded_here':True,
        'phone_calls':0,'new_send':0,'new_signal':0,'physical_case_pass':False,'whole_case_pass':False})
    S.need(len(outputs)<=128 and sum(map(len,outputs.values()))<=32*1024*1024,'bounded_complete_final_package')
    made=set();rows=[]
    for name,body in sorted(outputs.items()):
        relative=S.relative(name);parent=out
        for part in relative.parts[:-1]:
            parent/=part
            if str(parent) not in made:C.newdir(parent);made.add(str(parent))
        original=created(S,out/relative,body);rows.append(S.desc(name,body))
        originals.read(original)
    manifest={'schema':'hepta.physical-fault.root-source-package.v1','state':'ACTUAL_DEPENDENCIES_FROZEN_NO_CASE_EXECUTED',
        'candidate_source_package':mf,'final_dependencies':final,'files':rows,
        'phone_calls':0,'physical_case_pass':False}
    descriptor=created(S,out/'SOURCE-MANIFEST.json',S.enc(manifest));originals.recheck()
    print(json.dumps({'state':manifest['state'],'source_package':descriptor,'phone_calls':0,'new_send':0,
        'physical_case_pass':False,'next':'prepare_physical_fault.py --prepare-host-only'},sort_keys=True));return 0


if __name__=='__main__':raise SystemExit(main())

