#!/usr/bin/env python3
"""Exercise unchanged pure validators and the new replay wiring in synthetic context."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys
import types

HERE=Path(__file__).parent
rows=[]


def test(name, call):
    try:
        detail=call()
        if detail is False:
            raise AssertionError('check returned false')
        rows.append({'name':name,'passed':True,'detail':detail})
    except BaseException as error:
        rows.append({'name':name,'passed':False,'error':type(error).__name__+': '+str(error)})


def rejects(call):
    try:call()
    except ValueError:return True
    raise AssertionError('invalid input was accepted')


def parsed_functions(raw, names=None):
    tree=ast.parse(raw)
    return ast.Module(body=[node for node in tree.body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))
        and (names is None or node.name in names)],type_ignores=[])


common_raw=(HERE/'reference/component_common.py').read_bytes()
common=types.ModuleType('component_common');common.__file__=str(HERE/'reference/component_common.py')
exec(compile(common_raw,common.__file__,'exec'),common.__dict__)
original_binding=common.epoch_binding_value
test('actual unbound protocol remains closed before fixture injection',lambda:rejects(lambda:original_binding()))
stage=types.ModuleType('stage_component')
admission=(HERE/'reference/epoch_admission_values.fragment.py').read_bytes()
stage_raw=(HERE/'reference/epoch_stage_operations.fragment.py').read_bytes()
st=ast.parse(stage_raw)
for node in st.body:
    if isinstance(node,ast.Assign) and isinstance(node.targets[0],ast.Name) and node.targets[0].id in (
        'EPOCH_RESOURCE_KEYS','EPOCH_ALLOCATION_ADMISSION_FIELDS'):
        setattr(stage,node.targets[0].id,ast.literal_eval(node.value))
exec(compile(admission,'actual_epoch_admission_values.fragment.py','exec'),stage.__dict__)
exec(compile(parsed_functions(stage_raw,{'_est_host3'}),'actual_stage_host_pin.py','exec'),stage.__dict__)
prep_raw=(HERE/'source/prepare_component.py').read_bytes()
prep=types.ModuleType('reviewed_prepare_pure_replay')
prep.__dict__.update({key:value for key,value in common.__dict__.items() if key!='__name__'})
exec(compile(parsed_functions(prep_raw),'actual_prepare_component.py','exec'),prep.__dict__)
saved_common=sys.modules.get('component_common');sys.modules['component_common']=common
calls=[]


def fixture(*, identity=False, allocation=False, stage_record=False, role=False):
    epoch=common.EPOCH_ID;root=common.EPOCH_REGISTRY_ROOT;boot='11111111-2222-3333-4444-555555555555'
    files={};originals={};dirs={};serial=[1]
    def pin(path,raw):
        serial[0]+=1
        return {'path':path,**common._ep_bare(raw),'metadata':[17,serial[0],0o100600,0,0,1,len(raw),1,1]}
    def add(path,value,raw=None):
        body=common._ep_encoded(value) if raw is None else raw
        row=pin(path,body);files[path]=row;originals[path]=body
        return {'value':value,'original':row}
    def directory(path,names):
        serial[0]+=1;dirs[path]={'path':path,'metadata':[17,serial[0],0o40700,0,0,2,0,1,1],'names':sorted(names)}
    bare=lambda row:{k:row[k] for k in ('path','bytes','sha256')}
    prior=add('/fixture/prior.json',{'fixture':'prior'})['original']
    anchor_record=add(root+'/ANCHOR.json',{'fixture':'anchor'})
    generation=add(root+'/generations/01.json',{'ordinal':1,'fixture':'generation'})
    auth='只执行此授权测试。中文🙂\n本次唯一 nonce：{{EPOCH_NONCE}}\n'
    authpin={'path':'/fixture/authorization/NEG-01.txt',**common._ep_bare(auth.encode())}
    proof={'path':'/fixture/producer-proof.json',**common._ep_bare(b'fixture proof')}
    keys=stage.EPOCH_RESOURCE_KEYS
    profiles={case:{**{key:1 for key in keys},'producer_proof':proof,'copy_plan':proof} for case in ('NEG-01','NEG-02')}
    model={'schema':'hepta.native-guard.epoch-source-resource-model.v1','profiles':profiles,
        'copy_overhead':{key:0 for key in keys},
        'producer_limits':{'fixture':{'synthetic_fixture':True},
            'owned_role_output':{'per_stream_bytes':65536,'roles':3,'streams_per_role':2},
            'native_output':{'per_action_combined_bytes':600000,'maximum_actions_per_case':2},
            'snapshot':{},'closure_outputs':{},'operation_transport':{},'case_protocol':{}},
        'copy_ledger':[{'name':'synthetic-body','producer':'fixture','maximum_body_bytes':1,
            'maximum_count':1,'copies':1,'pool':'consumer'}],
        'historical_consumer_originals':[proof],'historical_consumer_proof':proof}
    mf=b'{"synthetic_manifest_context":true}\n'
    observation={'schema':'hepta.native-guard.epoch-preclaim-observation.v1','epoch_id':epoch,'boot_id':boot}
    resource={'schema':'hepta.native-guard.epoch-resource-reservation.v1','epoch_id':epoch,'boot_id':boot,
        'case_id':'NEG-01','generation':generation['original'],'observation':common._ep_bare(common._ep_encoded(observation)),
        'source_model':common._ep_bare(common._ep_encoded(model)),'runtime_manifest':common._ep_bare(mf),
        'remaining_qualification_cases':['NEG-01','NEG-02'],'measured':{key:1 for key in keys},
        'profiles':[profiles['NEG-01'],profiles['NEG-02']], 'copy_overhead':model['copy_overhead'],
        'producer_limits':model['producer_limits'],'copy_ledger':model['copy_ledger'],
        'native_calls_authorized':0,'component_qualified':False,'business_qualified':False,'automatic_retry':False}
    resource['arithmetic']=common.epoch_resource_forecast(resource['measured'],resource['profiles'],
        additional_profile_copies=resource['copy_overhead'],remaining_qualification_cases=resource['remaining_qualification_cases'])
    binding={'boot_id':boot,'anchor':bare(anchor_record['original']),'legacy_nonces':[f'{n:032x}' for n in range(1,8)],
        'failed_nonces':[f'{n:032x}' for n in range(8,11)],'retained_failed_native_nonces':['b'*32],
        'additional_retained_prelaunch_nonces':['c'*32],'retained_failed_fixture_absences':[],'control_roots':[]}
    fixed={'boot_id':boot,'resource_model':model,'authorization_requests':{'NEG-01':authpin,'NEG-02':dict(authpin,path='/fixture/authorization/NEG-02.txt')}}
    claim={'schema':'hepta.native-guard.epoch-reservation.v2','epoch_id':epoch,'ordinal':1,'boot_id':boot,
        'anchor':binding['anchor'],'generation':generation['original'],
        'authorization_request':{'origin':authpin,'utf8':auth},'resource_reservation':resource,
        'predecessor_terminal':None,'nonce_generated':False,'native_scope_assigned':False}
    claim_record=add(root+'/slots/01.CLAIM.json',claim)
    init_value={'generation':generation['original'],'anchor':anchor_record['original'],'carriers':[],
        'root_authorization':add(root+'/ROOT-AUTHORIZATION.json',{'fixture':'authorization'})['original']}
    initial_record=add(root+'/INITIALIZATION.json',init_value)
    initialization={**initial_record,'carriers':{},'footprint':{'unknown_namespace_members':[],'retained_roots':[]}}
    prefix=root+'/slots/01/';names={'DIRECTORY-BINDING.json'}
    directory(prefix[:-1],names)
    dclaim={'schema':'hepta.native-guard.epoch-claimed-directory.v1','ordinal':1,'claim':claim_record['original'],
        'directory':{'path':prefix[:-1],'first_observed_metadata':dirs[prefix[:-1]]['metadata']},
        'directory_inode_observed_atomically_at_mkdir':False,'ordinal_owned_by_held_exclusive_claim':True,
        'nonce_generated':False,'native_scope_assigned':False}
    add(prefix+'DIRECTORY-BINDING.json',dclaim)
    nonce='a'*32;label='fixture-neg01-root'
    owner=auth.replace('{{EPOCH_NONCE}}',nonce).encode()
    owner_pin=pin(prefix+'owner-request.original.txt',owner)
    iv={'schema':'hepta.native-guard.epoch-identity.v1','epoch_id':epoch,'ordinal':1,
        'reservation':claim_record['original'],'boot_id':boot,'label':label,'nonce':nonce,'case_id':'NEG-01',
        'owner_request':owner_pin,'selected_session_id':'fixture-session','selected_profile_id':'fixture-profile',
        'source_generation':generation['original'],'predecessor_terminal':None,'prior_boundary':prior}
    identity_record={'value':iv,'original':pin(prefix+'IDENTITY.json',common._ep_encoded(iv))}
    if identity:
        identity_record=add(prefix+'IDENTITY.json',iv);files[owner_pin['path']]=owner_pin;originals[owner_pin['path']]=owner
        names.update(('IDENTITY.json','owner-request.original.txt'))
    lease={'schema':'hepta.native-guard.epoch-lease.v1','nonce':nonce,'label':label,
        'epoch':{'schema':'hepta.native-guard.epoch-lease-binding.v1','epoch_id':epoch,'ordinal':1,
            'anchor':anchor_record['original'],'initialization':initial_record['original'],
            'reservation':claim_record['original'],'identity':identity_record['original'],'generation':generation['original']}}
    lease_pin=add('/fixture/home/LEASE.json',lease)['original']
    allocation_value={'schema':'hepta.native-guard.epoch-allocation-admission.v1',
        'state':'PRECLAIM_OBSERVATION_AND_CAPACITY_BOUND_TO_EXCLUSIVE_IDENTITY','epoch_id':epoch,'ordinal':1,'boot_id':boot,
        'anchor':anchor_record['original'],'initialization':initial_record['original'],'generation':generation['original'],
        'claim':claim_record['original'],'identity':identity_record['original'],'predecessor_terminal':None,'prior_boundary':prior,
        'preclaim_observation':observation,'resource_reservation':resource,'authorization_original':authpin,
        'nonce_generated_after_exclusive_claim':True,'native_scope_assigned':False,
        'component_qualified':False,'business_qualified':False,'automatic_retry':False}
    if allocation:add(prefix+'ALLOCATION-ADMISSION.json',allocation_value);names.add('ALLOCATION-ADMISSION.json')
    if stage_record:add(prefix+'STAGE.json',{'lease':lease_pin});names.add('STAGE.json')
    role_value={'schema':'hepta.native-guard.epoch-role-launch-intent.v1','epoch_id':epoch,'ordinal':1,
        'identity':identity_record['original'],'lease':lease_pin,'generation':generation['original'],'scope':None,
        'maximum_forks':1,'automatic_retry':False,'component_qualified':False,'business_qualified':False}
    if role:add(prefix+'ROLE-LAUNCH-INTENT.json',role_value);names.add('ROLE-LAUNCH-INTENT.json')
    dirs[prefix[:-1]]['names']=sorted(names)
    directory(root,{'ANCHOR.json','INITIALIZATION.json','REGISTRY.lock','ROOT-AUTHORIZATION.json','generations','initialization','slots'})
    directory(root+'/initialization',{'BASELINE-BUSINESS.json','BASELINE-CONTROL.json','INVENTORY-SPEC.json','INVENTORY-OBSERVATION.json','carriers'})
    directory(root+'/initialization/carriers',[]);directory(root+'/slots',{'01.CLAIM.json','01'})
    return locals()


def configure(f):
    common.epoch_binding_value=lambda binding=None:f['binding'] if binding is None else binding
    common._epoch_stage_api=lambda:stage
    stage._est_binding=lambda c:f['fixed']
    stage._est_modules=lambda:(common,{'component_lifecycle':types.SimpleNamespace(OWNED_OUTPUT_LIMIT=65536)},None,f['mf'],{})
    def preclaim(value, resource, **kw):
        assert value==f['observation'] and resource==f['resource']
        assert kw['initialization']==f['initialization'] and kw['originals'] is f['originals']
        calls.append('preclaim-observation-dependency')
    stage.epoch_preclaim_observation_value=preclaim
    prep.epoch_binding_value=common.epoch_binding_value
    prep.epoch_manifest_value=lambda manifest, originals, binding:manifest
    prep.epoch_anchor_value=lambda *a,**k:{'legacy':{'native_chain':[{'boundary':f['prior']}]},'host_origins':[]}
    prep.epoch_initialization_value=lambda *a,**k:f['initialization']
    prep._ep_generation_records=lambda *a,**k:[f['generation']]
    def stage_dependency(value,**kw):
        assert value=={'lease':f['lease_pin']}
        assert kw['identity_pin']==f['identity_record']['original'] and kw['originals'] is f['originals']
        calls.append('existing-stage-binding-dependency')
    prep.epoch_stage_binding_value=stage_dependency


def rewrite(f,path,value):
    raw=common._ep_encoded(value);old=f['files'][path]
    pin=copy.deepcopy(old);pin.update(common._ep_bare(raw));pin['metadata'][6]=len(raw)
    f['files'][path]=pin;f['originals'][path]=raw
    return pin


def replay(f):
    configure(f)
    return prep.epoch_registry_replay(f['lease'],{'files':f['files'],'directories':f['dirs']},f['originals'],
        mode='preclose',inventory_validator=lambda x:None,observation_verifier=lambda *a:None)


def reservation_test(mutate=None):
    f=fixture();configure(f);value=copy.deepcopy(f['claim'])
    if mutate:mutate(value,f)
    return common.epoch_reservation_value(value,binding=f['binding'],ordinal=1,previous_terminal=None)


try:
    test('v2 structured reservation passes actual unchanged common and resource validators',lambda:reservation_test()['schema'])
    test('old preparer descriptor loop demonstrably rejects the valid v2 value',lambda:rejects(lambda:common._ep_manifest_raw(fixture()['claim']['authorization_request'],{},{})))
    test('new replay accepts v2 claim without inventing native identity',lambda:replay(fixture())['active']['current_identity'] is None)
    for name,mutation in [
        ('old v1 schema',lambda v,f:v.update(schema='hepta.native-guard.epoch-reservation.v1')),
        ('authorization digest mismatch',lambda v,f:v['authorization_request'].update(utf8=v['authorization_request']['utf8']+'x')),
        ('duplicate nonce substitution',lambda v,f:v['authorization_request'].update(utf8=v['authorization_request']['utf8']+'{{EPOCH_NONCE}}')),
        ('boolean native-call count',lambda v,f:v['resource_reservation'].update(native_calls_authorized=True)),
        ('unknown resource field',lambda v,f:v['resource_reservation'].update(unreviewed=True)),
        ('changed runtime source manifest',lambda v,f:v['resource_reservation']['runtime_manifest'].update(sha256='f'*64)),
        ('changed producer bound',lambda v,f:v['resource_reservation']['producer_limits']['native_output'].update(maximum_actions_per_case=3)),
        ('changed source profile',lambda v,f:v['resource_reservation']['profiles'][0].update(capture_bytes=2)),
        ('changed repeated copy charge',lambda v,f:v['resource_reservation']['copy_overhead'].update(capture_bytes=1)),
        ('stale arithmetic',lambda v,f:v['resource_reservation']['arithmetic']['totals'].update(root_objects=1)),
        ('over-capacity measurement',lambda v,f:v['resource_reservation']['measured'].update(root_objects=65)),
    ]:
        test('actual validators reject '+name,lambda mutation=mutation:rejects(lambda:reservation_test(mutation)))
    def altered_claim(kind):
        f=fixture();value=copy.deepcopy(f['claim'])
        if kind=='origin':value['authorization_request']['origin']['path']='/fixture/unapproved.txt'
        elif kind=='generation':value['resource_reservation']['generation']['path']='/fixture/other-generation.json'
        elif kind=='nul':
            text=value['authorization_request']['utf8']+'\0';value['authorization_request']['utf8']=text
            value['authorization_request']['origin'].update(common._ep_bare(text.encode()))
            f['fixed']['authorization_requests']['NEG-01']=value['authorization_request']['origin']
        pin=rewrite(f,f['claim_record']['original']['path'],value)
        f['claim_record']={'value':value,'original':pin}
        d=copy.deepcopy(f['dclaim']);d['claim']=pin;rewrite(f,f['prefix']+'DIRECTORY-BINDING.json',d)
        f['lease']['epoch']['reservation']=pin
        return rejects(lambda:replay(f))
    for kind in ('origin','generation','nul'):test('replay rejects changed '+kind,lambda kind=kind:altered_claim(kind))
    test('actual identity replay preserves exact Chinese emoji newline authorization',lambda:replay(fixture(identity=True))['active']['current_identity'] is not None)
    def wrong_owner():
        f=fixture(identity=True);raw=f['owner']+b'changed';p=f['owner_pin']['path'];new=copy.deepcopy(f['files'][p])
        new.update(common._ep_bare(raw));new['metadata'][6]=len(raw);f['files'][p]=new;f['originals'][p]=raw
        iv=copy.deepcopy(f['iv']);iv['owner_request']=new;idpin=rewrite(f,f['prefix']+'IDENTITY.json',iv)
        f['lease']['epoch']['identity']=idpin
        return rejects(lambda:replay(f))
    test('replay rejects rehashed owner bytes outside authorization',wrong_owner)
    def wrong_identity(field,value):
        f=fixture(identity=True);iv=copy.deepcopy(f['iv']);iv[field]=value
        idpin=rewrite(f,f['prefix']+'IDENTITY.json',iv);f['lease']['epoch']['identity']=idpin
        return rejects(lambda:replay(f))
    test('replay rejects identity/resource case mismatch',lambda:wrong_identity('case_id','NEG-02'))
    test('replay rejects retained failed native nonce from the third domain',lambda:wrong_identity('nonce','b'*32))
    test('replay rejects retained prelaunch nonce from the fourth domain',lambda:wrong_identity('nonce','c'*32))
    test('preidentity allocation record is rejected',lambda:rejects(lambda:replay(fixture(allocation=True))))
    test('stage without allocation admission is rejected',lambda:rejects(lambda:replay(fixture(identity=True,stage_record=True))))
    test('role launch without completed stage is rejected',lambda:rejects(lambda:replay(fixture(identity=True,allocation=True,role=True))))
    def positive_admission():
        f=fixture(identity=True,allocation=True,stage_record=True,role=True);calls.clear();result=replay(f)
        assert result['registry']['slots'][0]['allocation']['value']==f['allocation_value']
        assert result['registry']['slots'][0]['role_launch']['value']==f['role_value']
        assert calls==['preclaim-observation-dependency','existing-stage-binding-dependency']
        return {'allocation_validator_executed':True,'role_validator_executed':True,
            'independent_dependency_boundaries':calls.copy(),'native_scope':result['active']['current_scope_binding']}
    test('both new records call actual validators and preserve original fields',positive_admission)
    for name,edit in [('multiple forks',lambda v:v.update(maximum_forks=2)),('boolean fork count',lambda v:v.update(maximum_forks=True)),
        ('invented scope',lambda v:v.update(scope={})),('wrong actual identity',lambda v:v['identity'].update(sha256='f'*64)),
        ('missing original',None)]:
        def role_case(edit=edit):
            f=fixture(identity=True);configure(f);v=copy.deepcopy(f['role_value'])
            if edit:edit(v)
            else:del f['originals'][f['lease_pin']['path']];del f['files'][f['lease_pin']['path']]
            return rejects(lambda:stage.epoch_role_launch_intent_value(v,identity=f['iv'],identity_pin=f['identity_record']['original'],
                lease_pin=f['lease_pin'],generation=f['generation']['original'],index={'files':f['files']},originals=f['originals']))
        test('actual launch validator rejects '+name,role_case)
    def later_without_role():
        f=fixture(identity=True,allocation=True,stage_record=True)
        f['add'](f['prefix']+'ADMISSION.json',{'fixture':'must not be reached'})
        f['dirs'][f['prefix'][:-1]]['names'].append('ADMISSION.json');f['dirs'][f['prefix'][:-1]]['names'].sort()
        return rejects(lambda:replay(f))
    test('lifecycle admission cannot precede original role intent',later_without_role)
    def unknown_member():
        f=fixture();f['dirs'][f['prefix'][:-1]]['names'].append('unknown.json');f['dirs'][f['prefix'][:-1]]['names'].sort()
        return rejects(lambda:replay(f))
    test('slot closed-set still rejects unknown members',unknown_member)
    def inverse():
        derivation=json.loads((HERE/'validation/SOURCE-DERIVATION.json').read_bytes());value=prep_raw.decode()
        for edit in reversed(derivation['edits']):
            assert value.count(edit['after'])==1;value=value.replace(edit['after'],edit['before'])
        assert value.encode()==(HERE/'reference/prepare_component.parent.py').read_bytes()
        return {'whole_original_bytes':len(value.encode()),'candidate_bytes':len(prep_raw),'source_limit':131072}
    test('complete derivation reverses to fixed parent bytes under unchanged source cap',inverse)
finally:
    if saved_common is None:sys.modules.pop('component_common',None)
    else:sys.modules['component_common']=saved_common

report={'schema':'hepta.prepare-epoch-v2.local-regressions.v1','state':'PASS' if all(r['passed'] for r in rows) else 'FAIL',
    'passed':sum(r['passed'] for r in rows),'total':len(rows),'tests':rows,
    'source':{'bytes':len(prep_raw),'sha256':hashlib.sha256(prep_raw).hexdigest()},
    'scope':'Actual unchanged common/resource/allocation/launch pure validators plus actual preparer replay control flow in explicitly synthetic upstream context.',
    'not_verified_here':['actual whole32 runtime load','historical anchor/initialization/source catalog proof',
        'preclaim observation semantic proof','existing stage binding semantic proof','installed runtime','native or physical case'],
    'context_injection_only':['common binding and verified stage selection','stage source context and fixed source binding',
        'already-verified manifest/anchor/initialization/generation inputs','preclaim observation dependency','existing stage binding dependency'],
    'phone_calls':0,'new_native_nonces':0,'current_authority_bound':False,'case_credit':0}
(HERE/'validation/LOCAL-REGRESSIONS.json').write_text(json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k not in ('tests','not_verified_here','context_injection_only')},ensure_ascii=False))
for row in rows:
    if not row['passed']:print(json.dumps(row,ensure_ascii=False))
raise SystemExit(0 if report['state']=='PASS' else 1)
