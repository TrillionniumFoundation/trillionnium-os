#!/usr/bin/env python3
"""Pure consumer-prefix controls, with explicitly synthetic new closed cases.

The actual source-parent boundary and complete reviewed source graph are read
unchanged. New-case inventory/closure validity is a caller precondition tested
by the existing LATE reader, not replaced by these isolated predicate fixtures.
No fixture is a published boundary, BUILD input, install identity or READY.
"""
from pathlib import Path
import ast
import copy
import hashlib
import json
import sys
import types

HERE=Path(__file__).resolve().parent
REVIEW=HERE.parent
CHECKS=[]


def deny_effects(event,args):
    if event in ('subprocess.Popen','os.system','os.exec','os.kill','os.killpg','socket.connect'):
        raise AssertionError('source control attempted external effect: '+event)


sys.addaudithook(deny_effects)


def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def enc(value):
    return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()


def read(path,expected=None):
    raw=path.read_bytes()
    if expected is not None:
        assert pin(raw)=={key:expected[key] for key in ('bytes','sha256')},str(path)
    return raw


def checked(name,function):
    function()
    CHECKS.append({'name':name,'state':'PASS'})


def reject(name,function,reason):
    try:
        function()
    except (ValueError,KeyError) as error:
        assert reason in str(error),(name,str(error),reason)
        CHECKS.append({'name':name,'state':'REJECTED','reason':str(error)})
    else:
        raise AssertionError('negative control accepted: '+name)


def main():
    derivation=json.loads(read(HERE/'DERIVATION.json'))
    original=read(HERE/'references/release_boundaries.original.py',derivation['original'])
    source=read(HERE/'source/release_boundaries.py',derivation['outputs'][0])
    module=types.ModuleType('unbound_consumer_current_prefix_control')
    module.__file__=str(HERE/'source/release_boundaries.py')
    exec(compile(source,module.__file__,'exec'),module.__dict__)
    assert module.PACKAGE_SHA is None
    reject('unbound_rejects_before_any_component_input',
           lambda:module.validate_component(None,None),'has not been frozen and reviewed')
    def unchanged_scope():
        old={node.name:ast.dump(node,include_attributes=False) for node in ast.parse(original).body
             if isinstance(node,(ast.FunctionDef,ast.ClassDef))}
        new={node.name:ast.dump(node,include_attributes=False) for node in ast.parse(source).body
             if isinstance(node,(ast.FunctionDef,ast.ClassDef))}
        assert set(new)-set(old)=={'current_closed_lease_roots'}
        assert not(set(old)-set(new))
        changed={name for name in old if old[name]!=new[name]}
        assert changed=={'validate_component','validate_final_component_prefix'}
        assert derivation['full_source_inverse_verified'] is True
    checked('all_unrelated_policy_retirement_history_functions_unchanged',unchanged_scope)
    package_raw=read(REVIEW/'R5-root/runtime/MANIFEST.json',derivation['observed_runtime_source_candidate'])
    manifest=json.loads(package_raw)
    sources={row['path']:read(REVIEW/'R5-root/runtime'/row['path'],row) for row in manifest['files']}
    assert len(sources)==module.PACKAGE_FILE_COUNT==38
    with module.component_modules({'package_sources':sources}) as actual:
        late=actual['late_boundary']
        late.validate_current_package_manifest(manifest)
        records=late.reviewed_source_parent_records()
        assert module.CURRENT_COMPONENT_CHAIN_LENGTH==late.MAX_CHAIN==9+len(records)+2
        assert module.COMPONENT_ROLE_BUDGET==late.COMPONENT_ROLE_CAP==3*(late.MAX_CHAIN+2)
        CHECKS.append({'name':'actual_source_graph_manifest_records_counts_match','state':'PASS'})
        head_raw=read(REVIEW/'R5-agent-late/history-inputs/NEG01-BOUNDARY.original.json',records[0]['boundary'])
        head=json.loads(head_raw)
        assert late.is_source_parent_ancestor(head)
        assert head['component_qualified'] is True and head['actual_native_calls']==2
        checked('actual_old_qualified_NEG01_classifies_only_as_exact_source_parent',lambda:
            assert_equal(late.boundary_from_original(head_raw,original_descriptor=records[0]['boundary'],
                combination_sha256=module.CURRENT_COMBINATION_SHA,
                package_sha256=hashlib.sha256(b'HOST_ONLY_CONSUMER_CONTEXT').hexdigest()),head))
        unit_package=hashlib.sha256(b'PURE_PREFIX_UNIT_FIXTURE_NOT_AN_ACTUAL_RUNTIME').hexdigest()
        module.PACKAGE_SHA=unit_package
        combination_descriptor=derivation['actual_shared_combination']
        retained={'unit_fixture_precondition_only':True}

        class PrefixLate:
            # These three preconditions are independently verified before the
            # new predicate in production. Unit fixtures intentionally isolate
            # the new prefix and lease checks, and cannot pass validate_component.
            def __getattr__(self,name):return getattr(late,name)
            def current_retained_stage_binding(self,value):return None
            def preserve_retained_unstarted_stage(self,inventory,*,retained):return None
            def validate_retained_stage_parent_profiles(self,retained,profiles,inventory):return None
        prefix_late=PrefixLate()

        class Fixture:
            def __init__(self):
                self.originals={}
                self.root_list=list(head['roots'])
                self.rows=[]
                self.prior=copy.deepcopy(records[0]['boundary'])
                for i,case in enumerate(('NEG-01','NEG-02'),1):
                    label='consumer-unit-control-0'+str(i)
                    nonce=str(i)*32
                    home=module.BASE+'/native-guard-r10-r1/'+label
                    journal=module.ANDROID_BASE+'/native-guard-r10-r1/'+label+'/executor'
                    roots=['/proc/1/root'+journal,home,
                           '/proc/1/root/data/local/tmp/hepta-native-guard-'+nonce]
                    self.root_list+=roots
                    scope={key:'unit-fixture-'+str(i)+'-'+key for key in
                           ('session_id','profile_id','task_id','turn_id','turn_stream_id')}
                    shared={'boot_id':module.BOOT,'nonce':nonce,'case_id':case,'scope':scope,
                        'owner_request_sha256':hashlib.sha256(('unit-owner-'+str(i)).encode()).hexdigest(),
                        'package_sha256':unit_package,'retirement':{'unit_fixture_only':True},
                        'prior_boundary':copy.deepcopy(self.prior),'component_qualified':True,
                        'native_status':'completed','retained_stage_parent_profiles':{}}
                    boundary={'schema':late.SCHEMA,'combination_sha256':module.CURRENT_COMBINATION_SHA,
                              'roots':list(self.root_list),**copy.deepcopy(shared)}
                    closure={**copy.deepcopy(shared),'unknown_effects':0,'lease_source_path':home+'/LEASE.json'}
                    lease={'schema':'hepta.native-guard.lease.v1','label':label,
                        **{key:shared[key] for key in ('boot_id','nonce','case_id','owner_request_sha256',
                                                      'package_sha256','retirement','prior_boundary')},
                        'selected_session_id':scope['session_id'],'selected_profile_id':scope['profile_id'],
                        'expires_unix_ms':1,'combination':copy.deepcopy(combination_descriptor),
                        'android_journal':journal}
                    inventory={'roots':list(self.root_list),'entries':{}}
                    row=(boundary,inventory,closure)
                    self.rows.append(row)
                    self.install_lease(row,lease)
                    self.prior={'path':str(late.ROOT/(nonce+'.json')),'bytes':99,
                                'sha256':hashlib.sha256(('unit-boundary-'+str(i)).encode()).hexdigest(),
                                'metadata':[1,10+i,33152,0,0,1,99,100+i,100+i]}
                parents=[(copy.deepcopy(head),{'roots':list(head['roots'])},{})]
                tail=[({'component_qualified':False,'native_status':'provider_failed'},{},{}) for _ in range(9)]
                self.chain=list(reversed(self.rows))+parents+tail
                self.reads=[]
            def install_lease(self,row,lease):
                _b,inventory,closure=row
                path=closure['lease_source_path']
                raw=enc(lease)
                metadata=[1,100+len(self.rows),33152,0,0,1,len(raw),1793980000000000001,1793980000000000001]
                entry={'kind':'file',**pin(raw),'metadata':metadata}
                inventory['entries'][path]=entry
                closure['lease_sha256']=pin(raw)['sha256']
                self.originals[path]=({'path':path,**pin(raw),'metadata':metadata[:]},raw)
            def change_lease(self,index,key,value):
                row=self.rows[index];raw=self.originals[row[2]['lease_source_path']][1]
                lease=json.loads(raw);lease[key]=value
                self.install_lease(row,lease)
            def read_original(self,row):
                if row['path'] not in self.originals:raise KeyError('unit original missing')
                expected,raw=self.originals[row['path']]
                module.need(enc(row)==enc(expected),'unit exact original full descriptor differs')
                self.reads.append(row['path'])
                return raw
            def run(self,custom_late=None):
                module.validate_final_component_prefix(self.chain,custom_late or prefix_late,retained,
                    read_pinned=self.read_original,combination_descriptor=combination_descriptor)

        def control(name,mutation,reason):
            fixture=Fixture();mutation(fixture)
            reject(name,fixture.run,reason)
        def positive():
            fixture=Fixture();fixture.run()
            assert len(fixture.reads)==2 and len(set(fixture.reads))==2
            assert fixture.chain[2][0]['component_qualified'] is True
            assert fixture.rows[0][1]['roots']==head['roots']+fixture.rows[0][1]['roots'][-3:]
            assert fixture.rows[1][1]['roots']==fixture.rows[0][1]['roots']+fixture.rows[1][1]['roots'][-3:]
        checked('synthetic_new_pair_accepts_only_exact_ordered_lease_roots_preserving_qualified_history',positive)
        control('missing_new_case_rejected',lambda f:f.chain.pop(0),'requires two new current cases')
        control('missing_source_parent_rejected',lambda f:f.chain.pop(2),'requires two new current cases')
        control('reordered_new_cases_rejected',lambda f:f.chain.__setitem__(slice(0,2),list(reversed(f.chain[:2]))),
                'latest-first after actual new NEG01 then NEG02')
        control('old_qualified_NEG01_cannot_supply_new_tuple_credit',
                lambda f:f.chain.__setitem__(1,(copy.deepcopy(head),f.rows[0][1],f.rows[0][2])),
                'both exact new current NEG component cases')
        control('source_parent_qualification_cannot_be_rewritten',
                lambda f:f.chain[2][0].__setitem__('component_qualified',False),'exact preceding-source originals')
        control('fixed_failed_tail_cannot_be_promoted',
                lambda f:f.chain[-1][0].__setitem__('component_qualified',True),'fixed historical failures')
        for key,value in (('package_sha256','f'*64),('combination_sha256','e'*64),
                          ('component_qualified',1),('native_status','provider_failed')):
            control('new_boundary_'+key+'_rejected',lambda f,k=key,v=value:f.rows[0][0].__setitem__(k,v),
                    'both exact new current NEG component cases')
        for value in (False,0.0,1):
            control('unknown_effects_'+repr(value)+'_rejected',
                    lambda f,v=value:f.rows[0][2].__setitem__('unknown_effects',v),
                    'both exact new current NEG component cases')
        for constant,value in (('CURRENT_COMPONENT_CHAIN_LENGTH',11),('CURRENT_COMPONENT_CHAIN_LENGTH',True),
                               ('COMPONENT_ROLE_BUDGET',41),('COMPONENT_ROLE_BUDGET',42.0)):
            before=getattr(module,constant);setattr(module,constant,value)
            try:reject('stale_or_untyped_'+constant+'_'+repr(value),Fixture().run,'requires two new current cases')
            finally:setattr(module,constant,before)
        control('same_count_foreign_root_rejected',
                lambda f:(f.rows[0][0]['roots'].__setitem__(-1,'/unit-foreign-root'),
                          f.rows[0][1]['roots'].__setitem__(-1,'/unit-foreign-root')),
                'preserve exact ordered baseline roots')
        control('root_order_change_rejected',
                lambda f:(f.rows[0][0]['roots'].reverse(),f.rows[0][1]['roots'].reverse()),
                'preserve exact ordered baseline roots')
        control('original_lease_missing_rejected',lambda f:f.originals.pop(f.rows[0][2]['lease_source_path']),
                'unit original missing')
        control('inventory_lease_entry_missing_rejected',
                lambda f:f.rows[0][1]['entries'].clear(),'inventory omitted the bounded original lease')
        control('closure_lease_digest_mismatch_rejected',
                lambda f:f.rows[0][2].__setitem__('lease_sha256','f'*64),'differs from the complete inventory or closure')
        control('closure_lease_path_outside_home_rejected',
                lambda f:f.rows[0][2].__setitem__('lease_source_path','/tmp/LEASE.json'),'exact component home namespace')
        def entry(f):return f.rows[0][1]['entries'][f.rows[0][2]['lease_source_path']]
        control('lease_descriptor_float_size_rejected',lambda f:entry(f).__setitem__('bytes',float(entry(f)['bytes'])),
                'bounded original lease file')
        control('lease_descriptor_boolean_metadata_rejected',lambda f:entry(f)['metadata'].__setitem__(0,True),
                'original private file metadata differs')
        control('lease_descriptor_symlink_mode_rejected',lambda f:entry(f)['metadata'].__setitem__(2,41472),
                'original private file metadata differs')
        control('lease_descriptor_hard_link_rejected',lambda f:entry(f)['metadata'].__setitem__(5,2),
                'original private file metadata differs')
        control('lease_original_full9_mismatch_rejected',lambda f:entry(f)['metadata'].__setitem__(7,1793980000000000002),
                'unit exact original full descriptor differs')
        for key,value in (('boot_id','0'*36),('nonce','f'*32),('case_id','NEG-02'),
                          ('owner_request_sha256','f'*64),('package_sha256','e'*64),
                          ('retirement',{'unit_fixture_only':False}),('prior_boundary',None)):
            control('self_consistent_lease_'+key+'_mismatch_rejected',
                    lambda f,k=key,v=value:f.change_lease(0,k,v),'lease/closed binding differs: '+key)
        for key in ('session_id','profile_id'):
            control('self_consistent_lease_selected_'+key+'_mismatch_rejected',
                    lambda f,k=key:f.change_lease(0,'selected_'+k,'other-unit-selection'),
                    'lease selected scope differs: '+key)
        for key,value in (('label','../escape'),('schema','other-schema'),('unknown_key',1)):
            control('self_consistent_lease_'+key+'_shape_rejected',
                    lambda f,k=key,v=value:f.change_lease(0,k,v),'lease schema or label differs')
        control('self_consistent_lease_label_home_mismatch_rejected',
                lambda f:f.change_lease(0,'label','other-unit-home'),'lease home, journal or historical expiry differs')
        control('self_consistent_lease_journal_mismatch_rejected',
                lambda f:f.change_lease(0,'android_journal','/data/local/tmp/other'),
                'lease home, journal or historical expiry differs')
        for value in (True,1.0,0,-1):
            control('self_consistent_lease_expiry_'+repr(value)+'_rejected',
                    lambda f,v=value:f.change_lease(0,'expires_unix_ms',v),'historical expiry differs')
        for value in ({'bytes':combination_descriptor['bytes']+1,'sha256':combination_descriptor['sha256']},
                      {'bytes':float(combination_descriptor['bytes']),'sha256':combination_descriptor['sha256']},
                      {'bytes':combination_descriptor['bytes'],'sha256':'f'*64}):
            control('self_consistent_lease_combination_'+repr(value['bytes'])+'_'+value['sha256'][:8]+'_rejected',
                    lambda f,v=value:f.change_lease(0,'combination',v),'actual complete current combination')
        module.PACKAGE_SHA=None
        reject('unbound_restored_after_all_memory_fixtures',
               lambda:module.validate_component(None,None),'has not been frozen and reviewed')
    result={'schema':'hepta.fc33.release-consumer-source-controls.v1',
        'state':'PURE_SOURCE_AND_PREFIX_CONTROLS_PASSED_NOT_COMPONENT_QUALIFICATION',
        'source':pin(source),'original':pin(original),'source_parent_boundary':records[0]['boundary'],
        'source_graph_candidate':pin(package_raw),'checks':CHECKS,'count':len(CHECKS),
        'fixture_scope':'new prefix predicate only; retained-stage functions are explicit caller-precondition stubs',
        'actual_source_parent_boundary_classification_verified':True,
        'historical_qualification_grants_current_tuple_credit':False,
        'synthetic_new_cases_only_in_memory':True,'current_package_fixture_only_in_memory':True,
        'actual_closed_new_cases':0,'actual_BUILD':False,'actual_install':False,'actual_READY':False,
        'phone_calls':0,'whole_case_qualified':False,'unbound_source_unchanged':True}
    assert read(HERE/'source/release_boundaries.py')==source
    out=HERE/'validation/RESULT.json';out.parent.mkdir(parents=True,exist_ok=True)
    with out.open('xb') as f:f.write(enc(result))
    print(json.dumps({'state':result['state'],'source':pin(source),'checks':len(CHECKS),
                      'result':pin(out.read_bytes()),'phone_calls':0},sort_keys=True))


def assert_equal(a,b):
    assert a==b


if __name__=='__main__':main()
