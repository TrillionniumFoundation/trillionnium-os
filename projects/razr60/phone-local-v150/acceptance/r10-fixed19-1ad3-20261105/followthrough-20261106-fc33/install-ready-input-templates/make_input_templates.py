#!/usr/bin/env python3
"""Create schema-shaped null templates only; never bind, build or dispatch."""
from pathlib import Path
import ast
import copy
import hashlib
import json

HERE=Path(__file__).resolve().parent
REVIEW=HERE.parent
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
RELEASE='v150-r10-r1'
B='/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
P4='/home/alex/razr60-local-model-v150'
GNU='/var/lib/trillionnium/owner-open/phone-local-v150'
OUT=GNU+'/root-install-v150-r10-r1'
CREATED=[]


def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def literal(raw,name):
    nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.Assign) and len(n.targets)==1
           and isinstance(n.targets[0],ast.Name) and n.targets[0].id==name]
    assert len(nodes)==1,name
    return ast.literal_eval(nodes[0].value)


def write(name,value):
    raw=(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
    path=HERE/name;path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb')as f:f.write(raw)
    CREATED.append({'path':name,**pin(raw)})


def d3(path=None):return {'path':path,'bytes':None,'sha256':None}
def d4(path=None):return {**d3(path),'metadata':None}
def process():return {key:None for key in ('dispatch','start','status','read')}


def phase():
    return {'process':process(),'actor_source_before':None,'actor_source_after':None,
            'request':None,'intent':None,'baseline':None,'result':None,
            'phone_stdout':None,'phone_stderr':None}


def main():
    transfer_raw=(REVIEW/'shared-v3-original-transfer.json').read_bytes()
    transfer=json.loads(transfer_raw)
    known={Path(row['path']).name:row for row in transfer}
    for row in transfer:assert pin(row['text'].encode())=={k:row[k]for k in ('bytes','sha256')}
    source_raw=(HERE/'references/MATERIAL-SOURCE-INPUTS.original.json').read_bytes()
    assert pin(source_raw)=={'bytes':2730,'sha256':'f02822b6ae8393738e563f61b73a646ddf0ccdf799d94e662fb5a88a43f16bcc'}
    source=json.loads(source_raw);producer=source['builder']
    assert pin((HERE/'references/material_producer.original.py').read_bytes())=={k:producer[k]for k in ('bytes','sha256')}
    material={key:{k:known[name][k]for k in ('path','bytes','sha256')}for key,name in
              (('combination','COMBINATION.json'),('source_seal','SOURCE-SEAL.json'),
               ('configuration','local-config-r10-r1.json'),('service','PHONE-SERVICE-INPUTS-v150-r10-r1.json'),
               ('shared','SHARED-MATERIALS.json'),('derivation','DERIVATION.json'))}
    material['source_inputs']={'path':str(Path(material['combination']['path']).parent/'SOURCE-INPUTS.json'),**pin(source_raw)}
    material['producer']=producer
    constructor_raw=(REVIEW/'install-source-chain43/source/derive_reviewed_release_sources_UNBOUND.py').read_bytes()
    assert pin(constructor_raw)=={'bytes':33827,'sha256':'4c8f32d518c4cf17308f561587eeaf12702b8b9addf0bd8e5ad335a33e941835'}
    consumer_raw=(REVIEW/'R5-release-consumer/source/release_boundaries.py').read_bytes()
    assert pin(consumer_raw)=={'bytes':249798,'sha256':'016d25b5467c96f96f25f7b2d9d606e40ea18a72421e549d0ab630a01f9c2349'}
    assert literal(consumer_raw,'PACKAGE_SHA')is None
    release_raw=(HERE/'references/release_reader.original.py').read_bytes()
    exact8_raw=(HERE/'references/exact8.original.py').read_bytes()
    protocol_raw=(HERE/'references/protocol.original.py').read_bytes()
    refs=json.loads(next(n.value.args[0].value for n in ast.parse(constructor_raw).body
        if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='REFS'for t in n.targets)))
    for name in ('builder','release_reader','installer','readiness','exact8','protocol','install_reader','retention','retention_protocol'):
        assert pin((HERE/('references/'+name+'.original.py')).read_bytes())=={k:refs[name][k]for k in ('bytes','sha256')}
    for name,slots in (('install_reader',('FROZEN_INPUTS','FROZEN_EXECUTION_PLAN')),
                       ('retention',('FROZEN_PHASE_AUTHORITY','FROZEN_RETENTION_INPUTS')),
                       ('retention_protocol',('FROZEN_SCOPE',))):
        assert all(literal((HERE/('references/'+name+'.original.py')).read_bytes(),k)is None for k in slots)
    bindings={
        'schema':'hepta.fc33.install-ready-preparation-slots.v1',
        'actual_runtime_freeze':None,'actual_freeze_controller':None,'actual_independent_freeze_admission':None,
        'bound_consumer_source':None,'source_chain_inputs':None,'source_chain_constructor_binding':None,
        'source_output_root':None,'published_source_chain':None,'formal_source_binding':None,
        'new_NEG01_closed_originals':None,'new_NEG01_lease_original':None,
        'new_NEG02_closed_originals':None,'new_NEG02_lease_original':None,
        'actual_component_boundary_inputs':None,'actual_retirement_inputs':None,
        'actual_build_output_root':None,'actual_build_controller':None,'actual_build_result':None,
        'actual_release_original_inputs':None,'actual_execution_plan':None,
        'actual_stage_phase':None,'actual_stage_retention_authority':None,'actual_stage_retention':None,
        'actual_start_phase':None,'actual_start_retention_authority':None,'actual_start_retention':None,
        'actual_ready_phase':None,'actual_ready_original':None,'actual_four_role_identity_originals':None,
        'actual_eight_stream_inputs':None,'actual_install_reader_inputs':None,'actual_install_ready_verdict':None}
    write('templates/00-ACTUAL-BINDINGS-UNBOUND.json',bindings)
    write('templates/01-SOURCE-CHAIN-INPUTS.template.json',{
        'schema':'hepta.reviewed-release-source-chain-inputs.v1','material':material,
        'consumer':{'source':None,'runtime_package':None},'output_root':None})
    write('templates/02-CONSUMER-BINDING.template.json',{
        'schema':'hepta.fc33.consumer-single-literal-binding-plan.v1',
        'template':{'path':B+'/followthrough-fc33-release-consumer-r5-source01/source/release_boundaries.py',**pin(consumer_raw)},
        'actual_runtime_package':None,'actual_freeze_originals':None,'actual_freeze_controller':None,
        'actual_independent_admission':None,'assignment':'PACKAGE_SHA','current_literal':None,
        'replacement_literal':None,'bound_output':None,'full_source_inverse':None})
    component={key:None for key in literal(consumer_raw,'COMPONENT_FIELDS')}
    component.update(schema='hepta.r10.component-boundary-inputs.v10',release_id=RELEASE,boot_id=BOOT,
                     component_combination=material['combination'])
    write('templates/03-COMPONENT-BOUNDARY-INPUTS.template.json',component)
    write('templates/04-RETIREMENT-INPUTS.template.json',{
        'report':None,'operator':None,'ancestor_retirement':None,'failed_predecessor':None,
        'original_operation_evidence':None})
    build_args=['-I','-B',None,'--inputs',None,'--inputs-sha256',None,'--output',None,
        '--retirement-inputs',None,'--retirement-inputs-sha256',None,
        '--component-boundary-inputs',None,'--component-boundary-inputs-sha256',None,
        '--policy-adoption-inputs',None,'--policy-adoption-inputs-sha256',None,
        '--shared-materials',None,'--shared-materials-sha256',None]
    write('templates/05-BUILD-PROCESS-START.template.json',{
        'host':'mac','executable':'/usr/bin/python3','args':build_args,'idempotency_key':None,
        'timeout_seconds':None})
    release={key:None for key in literal(release_raw,'FIELDS')}
    release.update(schema=literal(release_raw,'SCHEMA'),boot_id=BOOT,release_id=RELEASE,
        combination=material['combination'],shared_materials=material['shared'],
        policy_adoption=literal(release_raw,'FIXED')['ADOPTION'],
        build_process={'start':None,'status':None,'read':None})
    shared=json.loads(known['SHARED-MATERIALS.json']['text'])
    shared_root=Path(material['shared']['path']).parent
    release['shared_originals']=[{'name':row['path'],'copy':{'path':str(shared_root/row['path']),
        'bytes':row['bytes'],'sha256':row['sha256']}}for row in shared['files']]
    assert len(release['shared_originals'])==17
    write('templates/06-ACTUAL-RELEASE-ORIGINAL-INPUTS.template.json',release)
    plan={'schema':literal(protocol_raw,'PLAN_SCHEMA'),'boot_id':BOOT,'release_id':RELEASE,
        'release_inputs_sha256':None,'actor':{'path':None,**literal(protocol_raw,'ACTOR_PIN')},
        'actor_python':'/usr/bin/python3','actor_cwd':P4,'archive':None,'installer':None,
        'phases':{name:{key:None for key in ('label','request_path','idempotency_key','timeout_seconds')}
                  for name in ('stage','start','ready')}}
    write('templates/07-EXECUTION-PLAN.template.json',plan)
    write('templates/08-PHASE-ORIGINALS.fragment.json',phase())
    for number,name in ((9,'stage'),(10,'start')):
        write('templates/%02d-%s-PHASE-AUTHORITY.template.json'%(number,name.upper()),{
            'schema':'hepta.install-original-retention.phase-authority-inputs.v1','phase':name,
            'release_inputs':None,'execution_plan':None,
            'phases':{key:phase()for key in (('stage',)if name=='stage'else('stage','start'))},
            'original_map':None})
        write('derived-shapes/'+name.upper()+'-SCOPE.output-shape.json',{
            'schema':'hepta.install-original-retention.scope.v1','boot_id':BOOT,'release_id':RELEASE,'phase':name,
            **{key:None for key in ('authority_inputs','release_inputs','execution_plan',
                'actual_build_result_sha256','archive_sha256','release_manifest_sha256','retirement_sha256',
                'component_boundary_inputs_sha256','policy_adoption_inputs_sha256','phase_result_sha256',
                'phase_stdout_sha256','phase_source_identity','installation_generation','files')}})
    write('templates/11-CAPTURE-OPERATION.fragment.json',{
        'identity':{key:None for key in ('label','request_path','idempotency_key')},'originals':phase()})
    for number,name in ((12,'stage'),(13,'start')):
        write('templates/%02d-%s-RETENTION-INPUTS.template.json'%(number,name.upper()),{
            'schema':'hepta.install-original-retention.original-inputs.v1',
            'phase_authority':None,'scope':None,'operations':None,'original_map':None})
    eight={key:None for key in literal(exact8_raw,'FIELDS')}
    eight.update(schema=literal(exact8_raw,'SCHEMA'),ready={'source':None,'original':None},
        module_originals={key:None for key in ('manifest','binding','service','helper')},
        role_identity_originals={key:None for key in ('supervisor','model','sidecar','provider')},
        child_bindings={key:None for key in ('model','sidecar','provider')})
    write('templates/14-EIGHT-STREAM-INPUTS.template.json',eight)
    write('templates/15-INSTALL-START-READY-INPUTS.template.json',{
        'schema':'hepta.production.install-start-ready.original-inputs.v1','release_inputs':None,
        'eight_stream_inputs':None,'execution_plan':None,
        'phases':{key:phase()for key in ('stage','start','ready')},
        'install_originals':{key:d4(OUT+'/'+name)for key,name in
            (('install_intent','INSTALL-INTENT.json'),('staged','STAGED.json'),
             ('preservation','STAGED-PRESERVATION.original.json'),('start_intent','START-INTENT.json'),
             ('started','STARTED.json'))},'original_map':None})
    write('templates/16-ORIGINAL-MAP.fragment.json',{'namespace':None,'original':None,'retained':d4()})
    write('templates/17-NEW-COMPONENT-LEASE-COPY.fragment.json',{'phone':d4(),'copy':d3()})
    write('DESCRIPTOR-SHAPES.json',{'host3':d3(),'exact_original4':d4(),
        'full9_order':['st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'],
        'resident_identity4_order':['pid','pgrp','session','start_ticks'],
        'source_guard_identity5_order':['pid','ppid','pgrp','session','start_ticks'],
        'actual_identity4':None,'actual_identity5':None})
    outputs=['source/collect_r10_readiness.py','source/install_phone_release_r10.py',
        'contracts/FINAL-INTEGRATION-INPUTS.json','source/component_activation_gate.fragment.py',
        'source/build_release_r10.py','source/release_boundaries.py','preview-module/service.sh',
        'preview-module/RESIDENT-OWNER-FINALIZER.json','source/verify_final_release_inputs.py',
        'source/verify_resident_output_bindings.py','source/install_ready_execution_protocol.py',
        'source/verify_install_start_ready_UNBOUND.py','source/install_retention_protocol_UNBOUND.py',
        'source/verify_install_retention_UNBOUND.py']
    write('SOURCE-CHAIN-RETURN-CONTRACT.json',{
        'entrypoint':'derive_reviewed_source_chain(inputs_raw, read_pinned=...)',
        'report_schema':'hepta.reviewed-release-source-chain-construction.v1',
        'report_state':'SOURCE_CANDIDATES_ONLY_ACTUAL_EXECUTION_UNBOUND',
        'result_keys':['files','changes','source_binding','consumer_runtime','report'],
        'files_names':outputs,
        'source_binding_keys':['formal_parent','formal','readiness','production_replacements','configuration',
            'service','material_parent_configuration_sha256','material_parent_service_sha256','material_source_input'],
        'consumer_runtime_keys':['runtime_sha256','package_file_count','chain_length','role_budget'],
        'change_entry_keys':['parent','candidate','changes','complete_inverse'],
        'change_item_keys':['before','after'],
        'actual_published_report':None,'actual_source_binding_file':None,'actual_readiness_descriptor':None,
        'actual_consumer_descriptor':None})
    write('KNOWN-SOURCE-REFERENCES.json',{
        'schema':'hepta.fc33.install-ready-source-reference-catalog.v1',
        'source_constructor':{'path':str(Path(B).parent/'followthrough-20261106-fc33-release-source-chain01/source/derive_reviewed_release_sources_UNBOUND.py'),**pin(constructor_raw)},
        'unbound_consumer_template':{'path':B+'/followthrough-fc33-release-consumer-r5-source01/source/release_boundaries.py',**pin(consumer_raw)},
        'material':material,'original_references':refs,
        'runtime_freeze_is_bound':False,'actual_runtime_freeze':None,
        'actual_build_reader':None,'actual_install_reader':None,'actual_retention_reader':None})
    nulls=[]
    def walk(value,pointer,filename):
        if value is None:nulls.append({'file':filename,'pointer':pointer})
        elif isinstance(value,dict):
            for key,item in value.items():walk(item,pointer+'/'+key,filename)
        elif isinstance(value,list):
            for i,item in enumerate(value):walk(item,pointer+'/'+str(i),filename)
    for row in list(CREATED):
        if row['path'].startswith(('templates/','derived-shapes/')):
            walk(json.loads((HERE/row['path']).read_bytes()),'',row['path'])
    write('UNBOUND-SLOTS.json',{'schema':'hepta.fc33.null-input-slot-index.v1','slots':nulls})
    write('PREPARATION.json',{'schema':'hepta.fc33.install-ready-template-preparation.v1',
        'state':'EXACT_INPUT_SHAPES_ONLY_ACTUAL_BINDINGS_NONE','files':list(CREATED),
        'actual_freeze_controller_bound':False,'consumer_literal_changed':False,'source_chain_executed':False,
        'actual_cases_created':0,'actual_BUILD':False,'actual_install':False,'actual_READY':False,
        'new_control_scenarios':0,'phone_calls':0,'dispatch_calls':0})
    print(json.dumps({'templates_and_contracts':len(CREATED),'null_slots':len(nulls),
        'actual_bindings_none':True,'new_control_scenarios':0,'phone_calls':0},sort_keys=True))


if __name__=='__main__':main()
