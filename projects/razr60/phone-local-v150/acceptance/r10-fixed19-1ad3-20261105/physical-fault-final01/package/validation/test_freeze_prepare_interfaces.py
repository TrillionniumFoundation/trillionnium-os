#!/usr/bin/env python3
"""Local source-only freezer/preparer fixtures. Creates no actual adoption or phone proof."""
import argparse,ast,base64,copy,hashlib,json,os,sys,types
from pathlib import Path


def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
def need(v,s):
    if not v:raise AssertionError(s)
def module(body,path,name):
    m=types.ModuleType(name);m.__file__=str(path);sys.modules[name]=m
    exec(compile(body,str(path),'exec'),m.__dict__);return m


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package',type=Path,required=True);parser.add_argument('--manifest-sha256',required=True)
    parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    root=args.package.resolve();out=args.out.resolve();out.mkdir(mode=0o700)
    raw=(root/'SOURCE-MANIFEST.json').read_bytes();need(sha(raw)==args.manifest_sha256,'candidate manifest pin')
    mf=json.loads(raw);files={}
    for row in mf['files']:
        b=(root/row['path']).read_bytes();need(len(b)==row['bytes'] and sha(b)==row['sha256'],'member pin')
        files[row['path']]=b
    S=module(files['source/physical_fault_common.py'],root/'source/physical_fault_common.py','physical_fault_common')
    F=module(files['source/freeze_physical_fault.py'],root/'source/freeze_physical_fault.py','fixture_freezer')
    C=module(files['source/owned_capture.py'],root/'source/owned_capture.py','fixture_capture')
    fixture=out/'SYNTHETIC-SOURCE-INPUTS-NOT-ACTUAL';fixture.mkdir(mode=0o700)
    def put(name,value):
        b=value if type(value) is bytes else enc(value);p=fixture/name;p.parent.mkdir(parents=True,exist_ok=True)
        with p.open('xb') as stream:stream.write(b)
        return S.desc(p,b)
    policy=put('SYNTHETIC.policy',b'SYNTHETIC SOURCE RELATIONSHIP FIXTURE; NOT AN SELINUX POLICY\n')
    links={name:put('originals/'+name+'.json',{'source_only_fixture':True,'name':name})
           for name in ('root_scope_decision','post_live_comparison','pre_live_expectation')}
    decision={'schema':'hepta.root.runtime-properties-policy-adoption-decision.v1',
        'decision':'ADOPT_INDEPENDENTLY_VERIFIED_ACTUAL_EXPORTED_POLICY','actual_policy_sha256':policy['sha256'],
        'automatic_adoption':False,'service_start_admitted':False,'component_qualified':False,
        'root_scope_decision_sha256':links['root_scope_decision']['sha256'],
        'post_live_comparison_sha256':links['post_live_comparison']['sha256'],
        'pre_live_expectation_sha256':links['pre_live_expectation']['sha256'],
        'prior_boundary_sha256':'9'*64,'actual_live_binding_sha256':'8'*64,
        'permission_atoms':[['SYNTHETIC','NOT_ACTUAL','CLASS','PERMISSION',str(i)] for i in range(44)]}
    adoption=put('SYNTHETIC.adoption.json',{'schema':'hepta.runtime-properties-r10.policy-adoption.v1',
        'release_id':'v150-r10-r1','boot_id':S.BOOT,'actual_export':policy,'root_decision':decision,
        'pre_policy_boundary':{'sha256':'9'*64},**links})
    runtime=[]
    for index in range(32):
        row=put('runtime/source/member-%02d.py'%index,('# synthetic unused runtime fixture %d\n'%index).encode())
        runtime.append(dict(row,path='source/member-%02d.py'%index))
    runtime_row=put('runtime/MANIFEST.json',{'revision':'r10-r1-operator-r8','files':runtime,
        'actual_combination_generated':True,'current_policy_sha256':policy['sha256'],
        'current_combination_sha256':'7'*64,'explicit_policy_adoption_sha256':adoption['sha256']})
    consumer=put('consumer.py',('PACKAGE_SHA='+repr(runtime_row['sha256'])+'\nCURRENT_POLICY_SHA='+repr(policy['sha256'])+
        '\nCURRENT_POLICY_ADOPTION_SHA='+repr(adoption['sha256'])+'\n').encode())
    readiness=put('readiness.py',('BOUNDARY_CONSUMER_SHA256='+repr(consumer['sha256'])+'\n').encode())
    original=json.loads(files['reference/fault-package.original.json']);fault_sources={}
    for row in original['runtime_sources']:
        name=row['path'];body=files['validation/operator-source-fixture/'+name]
        if name=='source/active_runtime_r10.py':body=F.rewrite(body,{
            'CONSUMER_SHA':consumer['sha256'],'READINESS_SHA':readiness['sha256'],
            'POLICY_SHA':policy['sha256'],'ADOPTION_SHA':adoption['sha256']})
        put('fault/'+name,body);fault_sources[name]=body
    fault=copy.deepcopy(original);fault['runtime_sources']=[S.desc(name,b) for name,b in sorted(fault_sources.items())]
    fault_row=put('fault/MANIFEST.json',fault)
    plan={'schema':'hepta.physical-fault.freeze-inputs.v1','out':str(S.B/'physical-fault-r10-r1-final-fixture-only'),
        'runtime_package':runtime_row,'fault_package':fault_row,'consumer':consumer,'readiness':readiness,
        'policy_adoption':adoption,'actual_policy':policy,'combination_sha256':'7'*64}
    results=[]
    def check(name,fn):
        try:detail=fn();results.append({'name':name,'passed':True,'detail':detail})
        except BaseException as e:results.append({'name':name,'passed':False,'error_type':type(e).__name__,'detail':str(e)})
    def rejected(fn,contains):
        try:fn()
        except ValueError as e:
            need(contains in str(e),'wrong rejection: '+str(e));return str(e)
        raise AssertionError('invalid source relationship accepted')
    state={}
    def derive():
        outputs,final,changed=F.derive(S,files,plan,S.Originals())
        need(len(changed)==4 and all(r['whole_byte_inverse_after_one_RHS'] for r in changed),'four source RHS inverse')
        state.update(outputs=outputs,final=final);return {'changed_source_count':4,'actual_adoption_awarded':False}
    check('freezer binds four source pin slots using explicit synthetic relationships',derive)
    def stale():
        bad=copy.deepcopy(plan);bad['readiness']=put('bad-readiness.py',b"BOUNDARY_CONSUMER_SHA256='0000000000000000000000000000000000000000000000000000000000000000'\n")
        return rejected(lambda:F.derive(S,files,bad,S.Originals()),'actual_consumer_and_readiness_source_relationships')
    check('stale readiness-to-consumer reference rejected',stale)
    def drift():
        bad=copy.deepcopy(plan);bodies=dict(fault_sources);bodies['source/active_runtime_r10.py']+=b'\n# unrelated drift\n'
        for name,body in bodies.items():put('bad-fault/'+name,body)
        changed=copy.deepcopy(fault);changed['runtime_sources']=[S.desc(n,b) for n,b in sorted(bodies.items())]
        bad['fault_package']=put('bad-fault/MANIFEST.json',changed)
        return rejected(lambda:F.derive(S,files,bad,S.Originals()),'only_four_original_shared_active_pin_slots_changed')
    check('active source changes outside four reviewed slots rejected',drift)
    if 'outputs' in state:
        outputs=state['outputs'];frozen=fixture/'FROZEN-SYNTHETIC-SOURCE-NOT-ACTUAL';frozen.mkdir()
        outputs=dict(outputs);outputs['FREEZE-INPUT.original.json']=enc(plan)
        for name,body in outputs.items():
            p=frozen/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(body)
        frozen_mf={'schema':'hepta.physical-fault.root-source-package.v1','source_only_fixture':True,
            'files':[S.desc(n,b) for n,b in sorted(outputs.items())]}
        frozen_mfraw=enc(frozen_mf);(frozen/'SOURCE-MANIFEST.json').write_bytes(frozen_mfraw)
        source_mf=S.desc(frozen/'SOURCE-MANIFEST.json',frozen_mfraw)
        FS=module(outputs['source/physical_fault_common.py'],frozen/'source/physical_fault_common.py','physical_fault_common')
        # This process-local path substitution only permits writing local
        # synthetic preparation artifacts. It is never written into source;
        # the generated plans consequently cannot pass the real Root entry.
        FS.B=fixture/'SYNTHETIC-MAC-NAMESPACE';FS.B.mkdir()
        (FS.B/'send_new_native_task_r5.py').write_bytes(files['reference/send_new_native_task_r5.py'])
        T=module(outputs['source/prepare_physical_fault.py'],frozen/'source/prepare_physical_fault.py','fixture_prepare')
        A=module(fault_sources['source/active_runtime_r10.py'],'<synthetic-active-source>','fixture_active')
        config=put('local-config.json',files['reference/local-config-r10-r1.json'])
        service=put('service.json',files['reference/PHONE-SERVICE-INPUTS-v150-r10-r1.json'])
        pins={'source_seal_sha256':'1'*64,'configuration_sha256':A.CONFIG_SHA,'service_inputs_sha256':A.SERVICE_SHA,
              'module_manifest_sha256':'2'*64,'component_boundary_inputs_sha256':'3'*64,'policy_adoption_inputs_sha256':adoption['sha256']}
        ready={k:None for k in A.READY_FIELDS}
        ready.update(schema='hepta.r10.actual-readiness.v1',state='EXACT_COMBINATION_READY_TRANSPORT_ONLY',boot_id=FS.BOOT,
            policy_sha256=policy['sha256'],parent_policy_sha256=A.PARENT_POLICY_SHA,
            component_boundary_sha256='4'*64,release_boundary_bundle_sha256='5'*64,
            model_requests=0,task_submissions=0,ui_actions=0,signals_sent=0,
            health_qualified=False,business19_qualified=False,cold_boot_qualified=False,
            slot_observation={'is_processing':False},slot_get_receipt={'complete':True,'http_status':200,'error':None},
            actual_binding={'sha256':'6'*64},component_external_artifacts={k:None for k in
                ('client','sidecar','worker','screen_helper','focus_helper','unicode_helper','busybox','python')},**pins)
        ready['roles']={}
        for index,name in enumerate(('supervisor','provider','sidecar','model'),1):
            pid=40000+index;exe={'supervisor':'/usr/bin/python3','provider':'/usr/bin/python3','model':A.MODEL_EXE,'sidecar':A.SIDECAR_EXE}[name]
            ready['roles'][name]={'identity':[pid,pid,pid,80000+index],'state':'S','domain':
                'u:r:trillionnium_owner_open_phone_executor:s0' if name=='sidecar' else 'u:r:magisk:s0',
                'uid':[0]*4,'gid':[0]*4,'no_new_privs':0,'exe':exe}
        ready_row=put('SYNTHETIC-READY-NOT-ACTUAL.json',ready)
        for index,case in enumerate(('NEG-04','NEG-05','NEG-07'),1):
            def prepared(index=index,case=case):
                nonce=('%032x'%index);owner=('Source-only fixture 中文🙂\nNonce '+nonce+'\n').encode();owner_sha=sha(owner)
                scope=dict(session_id='synthetic-session',profile_id='synthetic-profile',task_id='old-task',turn_id='old-turn',turn_stream_id='old-stream')
                app={'schema':'hepta.task-app-scope.v1','owner_request_sha256':owner_sha,
                    'apps':[{'alias':'视觉挑战','component':'org.trillionnium.hepta.controlprobe/.VisualChallengeActivity'}]}
                template={'schema':'hepta.task-template.v150.3','request_sha256':owner_sha,'nonce':nonce,
                    'expected_scope':{k:scope[k] for k in ('session_id','profile_id')},'coverage':'entire_request',
                    'postconditions':[{'id':'return','kind':'foreground_hepta'}],'app_scope':app}
                prefix=case+'/'
                inputs={'request':put(prefix+'REQUEST.txt',owner),
                    'previous':put(prefix+'previous.json',{'identity':scope,'request_sha256':'a'*64,'terminal':{'status':'completed'}}),
                    'preserved_draft':put(prefix+'draft.json',{'exact_utf8_b64':base64.b64encode(b'synthetic saved draft').decode(),'utf8_sha256':sha(b'synthetic saved draft')}),
                    'retirement_resolution':put(prefix+'retirement.json',{'source_only_fixture':True}),
                    'registration_result':put(prefix+'registration.json',{'rc':0,'unconsumed_template_read_back':True,'request_sha256':owner_sha})}
                value={'schema':'hepta.physical-fault.prepare-inputs.v1','case_id':case,'label':'source-fixture-'+case.lower(),
                    'operation_id':'source-operator-'+case.lower(),'sender_inputs':inputs,'task_template':put(prefix+'template.json',template),
                    'actual_ready':ready_row,'expected_probe_component':None if case=='NEG-04' else
                        'org.trillionnium.hepta.controlprobe/org.trillionnium.hepta.controlprobe.VisualChallengeActivity',
                    'configuration':config,'service':service}
                result=T.prepare(FS,C,frozen,FS.Originals(),source_mf,outputs,value,enc(value))
                need(result['phone_calls']==result['new_send']==result['new_signal']==0 and result['physical_case_pass'] is False,
                     'source preparation awarded or executed a physical case')
                watch=json.loads(Path(result['watch_plan']['path']).read_bytes())
                need(base64.b64decode(watch['owner_request_b64'])==owner and watch['app_scope']==app,
                    'registered Unicode owner or app scope changed')
                need(watch['expected_probe_component']==value['expected_probe_component'],'case probe fields differ')
                return {'source_only_fixture':True,'case_id':case,'phone_calls':0,
                    'wire_bytes':result['phone_wire_bytes'],'registry_abbreviated_component_preserved':True}
            check('prepare '+case+' exact owner/template and original actor helper fields',prepared)
    passed=all(v['passed'] for v in results)
    report={'schema':'hepta.physical-fault.freeze-prepare-source-checks.v1','state':'PASS' if passed else 'FAIL',
        'source_manifest':{'path':str(root/'SOURCE-MANIFEST.json'),'bytes':len(raw),'sha256':sha(raw)},
        'checks':results,'passed':sum(v['passed'] for v in results),'total':len(results),
        'all_dependency_inputs_are_explicit_synthetic_fixtures':True,'actual_adoptions_created':0,
        'phone_calls':0,'native_tasks':0,'fault_actor_invocations':0,'actual_physical_cases_passed':0,
        'source_gate_semantics_only':True}
    (out/'RESULT.json').write_bytes(enc(report));print(json.dumps({'state':report['state'],'passed':report['passed'],
        'total':report['total'],'report':str(out/'RESULT.json'),'physical_cases_passed':0},sort_keys=True))
    return 0 if passed else 1


if __name__=='__main__':raise SystemExit(main())
