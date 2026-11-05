#!/usr/bin/env python3
"""Local synthetic checks; never an actual preparation or phone qualification."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import types

HERE = Path(__file__).resolve().parents[1]
ROOT = HERE.parent
SOURCE = HERE/'source/prepare_native_guard_root_plan.py'
raw = SOURCE.read_bytes()
M = types.ModuleType('reviewed_prepare_only_test')
M.__file__ = str(SOURCE)
exec(compile(raw,str(SOURCE),'exec'),M.__dict__)
checks = []


def check(name, action):
    action()
    checks.append({'name':name,'passed':True})


def rejects(action, text):
    try:
        action()
    except ValueError as error:
        assert text in str(error),(text,str(error))
    else:
        raise AssertionError('expected closed rejection: '+text)


class FixtureOriginals:
    def __init__(self):
        self.data = {}
    def add(self,path,value):
        body = value if isinstance(value,bytes) else M.encoded(value)
        row = M.descriptor(path,body)
        self.data[str(path)] = (row,body)
        return row
    def read(self,row):
        saved,body = self.data[row['path']]
        assert saved==row
        return body
    def discovered(self,path,maximum=262144):
        row,body = self.data[str(path)]
        assert len(body)<=maximum
        return row,body


def inversion():
    rows = [
        (ROOT/'transport_fix/native-guard-property-r8-freeze-transport-candidate02-1ad3/source/freeze_property_runtime.py',
         {'FINALIZATION':{'synthetic_fixture':'中文😀'}},M.FREEZER_TEMPLATE_SHA),
        (ROOT/'transport_fix/native-guard-property-root-r8-transport-candidate03-1ad3/source/run_component_root_once.py',
         {'PKG':'1'*64,'COMBINATION':'2'*64,'VERIFIER_SHA':'3'*64,'VERIFIER_BYTES':107666,
          'POLICY_SHA':'4'*64,'ADOPTION_SHA':'5'*64,'ROOT_SCOPE_SHA':'6'*64},M.ROOT_TEMPLATE_SHA),
        (ROOT/'transport_fix/native-guard-property-root-r8-transport-candidate03-1ad3/source/phone_chain_bridge.py',
         {'PKG':'1'*64},M.BRIDGE_TEMPLATE_SHA),
    ]
    for path,values,digest in rows:
        old = path.read_bytes()
        assert M.sha(old)==digest
        new = old
        for name,value in values.items():
            new = M.set_literal(new,name,None,value)
        for name,value in values.items():
            new = M.set_literal(new,name,value,None)
        assert new==old


O = FixtureOriginals()
nonces = {'new':'a'*32,'historical':'b'*32,'qualified_neg01':'c'*32}
scope = {'session_id':'fixture-session','profile_id':'fixture-profile','task_id':'fixture-task',
    'turn_id':'fixture-turn','turn_stream_id':'fixture-stream'}
base = {key:None for key in M.PLAN_KEYS}
base.update(schema='hepta.native-guard.root-chain-plan.v1',case_id='NEG-01',nonce=M.OLD08_NONCE,
    out=str(M.OLD08),boot_id=M.BOOT,label=M.OLD08.name)
for key in M.STABLE_PLAN_KEYS-{'shared_root','retirement_originals'}:
    base[key] = O.add(M.B/('fixture-'+key+'.json'),{'synthetic_fixture':key})
base['shared_root'] = str(M.B/'fixture-shared')
base['retirement_originals'] = str(M.B/'fixture-retirement')
base['request'] = O.add(M.B/'fixture-old-request.txt',('OLD FIXTURE '+M.OLD08_NONCE).encode())
base_row = O.add(M.OLD08/'ROOT-PLAN.original.json',base)
prev = O.add(M.OLD08/'ACTUAL-PREVIOUS-INPUT.json',{'identity':scope})
boundary = O.add(M.OLD08/'LATE-BOUNDARY.original.json',{'nonce':M.OLD08_NONCE})
boundary_desc = O.add(M.OLD08/'LATE-BOUNDARY-DESCRIPTOR.json',{'synthetic_fixture':'descriptor'})
historical = O.add(M.B/'fixture-history03.json',{'nonce':nonces['historical']})
freeze_inputs = {'history08_previous':prev,'history08_boundary':boundary,
    'history08_descriptor':boundary_desc,'history03_boundary':historical,'shared_materials':base['shared_materials']}
freeze = {'runtime_manifest':{'path':str(M.R8/'runtime/MANIFEST.json'),'bytes':1,'sha256':'1'*64},
    'root_chain_manifest':{'path':str(M.R8/'root-chain/SOURCE-MANIFEST.json'),'bytes':1,'sha256':'2'*64},
    'policy_adoption':{'path':str(M.B/'fixture-adoption.json'),'bytes':1,'sha256':'3'*64},
    'actual_adopted_policy_sha256':'4'*64}
request = O.add(M.B/'fixture-new-request.txt',('HOST FIXTURE ONLY NEG-01 nonce '+nonces['new']).encode())
first = M.choose_prior(O,freeze_inputs,freeze,'NEG-01',None)


def first_assembly():
    plan = M.assemble(O,freeze_inputs,freeze,base_row,'NEG-01','host-fixture-neg01-review',
        nonces['new'],request,first)
    assert set(plan)==M.PLAN_KEYS
    assert plan['previous']==prev and plan['prior_boundary_original']==boundary
    assert plan['package']==freeze['runtime_manifest'] and plan['source_package']==freeze['root_chain_manifest']
    assert plan['policy_adoption']==freeze['policy_adoption'] and plan['session_id']==scope['session_id']
    assert all(plan[key]==base[key] for key in M.STABLE_PLAN_KEYS)
    assert base['nonce']==M.OLD08_NONCE and plan['nonce']==nonces['new']


def nonce_rejection():
    historical_request = O.add(M.B/'fixture-historical-request.txt',
        ('HOST FIXTURE ONLY '+nonces['historical']).encode())
    rejects(lambda:M.assemble(O,freeze_inputs,freeze,base_row,'NEG-01','host-fixture-neg01-review',
        nonces['historical'],historical_request,first),'historical native nonce')
    contaminated = O.add(M.B/'fixture-contaminated-request.txt',
        ('HOST FIXTURE '+nonces['new']+' old '+M.OLD08_NONCE).encode())
    rejects(lambda:M.assemble(O,freeze_inputs,freeze,base_row,'NEG-01','host-fixture-neg01-review',
        nonces['new'],contaminated,first),'historical native nonce')
    rejects(lambda:M.assemble(O,freeze_inputs,freeze,base_row,'NEG-01','host-fixture-neg01-review',
        'd'*32,request,first),'supplied nonce exactly once')


current_home = M.CHAINS/'host-fixture-qualified-neg01'
current_boundary = {'nonce':nonces['qualified_neg01'],'case_id':'NEG-01',
    'component_qualified':True,'native_status':'completed'}
current_boundary_row = O.add(current_home/'LATE-BOUNDARY.original.json',current_boundary)
published = {'path':'/synthetic/phone/boundary.json','bytes':current_boundary_row['bytes'],
    'sha256':current_boundary_row['sha256'],'metadata':{'synthetic_fixture':True}}
current_previous = {'identity':scope,'component_qualified':True,'terminal':{'status':'completed'},
    'late_boundary':published}
current_previous_row = O.add(current_home/'ACTUAL-PREVIOUS-INPUT.json',current_previous)
current_desc_row = O.add(current_home/'LATE-BOUNDARY-DESCRIPTOR.json',published)
current_plan = copy.deepcopy(base)
current_plan.update(out=str(current_home),label=current_home.name,nonce=nonces['qualified_neg01'],
    package=freeze['runtime_manifest'],source_package=freeze['root_chain_manifest'],
    policy_adoption=freeze['policy_adoption'],live_policy_sha256=freeze['actual_adopted_policy_sha256'])
O.add(current_home/'ROOT-PLAN.original.json',current_plan)
current_result = {'state':'ORIGINAL_COMPONENT_CLOSED_AND_LATE_BOUNDARY_PUBLISHED',
    'component_qualified':True,'native_status':'completed','automatic_retry':False,
    'previous':current_previous_row,'scope':scope,'late_boundary':published}
current_result_row = O.add(current_home/'ROOT-RESULT.json',current_result)


def progression():
    prior = M.choose_prior(O,freeze_inputs,freeze,'NEG-02',current_result_row)
    assert prior=={'previous':current_previous_row,'prior_boundary_original':current_boundary_row,
        'prior_boundary_descriptor':current_desc_row}
    plan = M.assemble(O,freeze_inputs,freeze,base_row,'NEG-02','host-fixture-neg02-review',
        nonces['new'],request,prior)
    assert plan['case_id']=='NEG-02' and plan['previous']==current_previous_row
    rejects(lambda:M.choose_prior(O,freeze_inputs,freeze,'NEG-01',current_result_row),'exact frozen actual08')
    rejects(lambda:M.choose_prior(O,freeze_inputs,freeze,'NEG-02',None),'requires its actual qualified')


def failed_or_foreign_progression():
    failed = copy.deepcopy(current_result)
    failed['component_qualified'] = False
    failed_row = O.add(current_home/'ROOT-RESULT.json',failed)
    rejects(lambda:M.choose_prior(O,freeze_inputs,freeze,'NEG-02',failed_row),'qualified current NEG01 Root result')
    O.add(current_home/'ROOT-RESULT.json',current_result)
    foreign = copy.deepcopy(current_plan)
    foreign['package'] = {'path':str(M.R8/'runtime/MANIFEST.json'),'bytes':1,'sha256':'9'*64}
    O.add(current_home/'ROOT-PLAN.original.json',foreign)
    rejects(lambda:M.choose_prior(O,freeze_inputs,freeze,'NEG-02',current_result_row),'another runtime/policy generation')
    O.add(current_home/'ROOT-PLAN.original.json',current_plan)


def no_execution_endpoint():
    tree = ast.parse(raw)
    imports = [alias.name for node in ast.walk(tree) if isinstance(node,(ast.Import,ast.ImportFrom))
        for alias in node.names]
    assert not set(imports)&{'subprocess','secrets','uuid','random','socket'}
    calls = [node for node in ast.walk(tree) if isinstance(node,ast.Call)]
    assert not any(isinstance(node.func,ast.Attribute) and node.func.attr in
        {'Chain','run','phone','execute_process','remote_program','remote_files','main'} for node in calls)
    assert sum(isinstance(node.func,ast.Attribute) and node.func.attr=='validate_plan' for node in calls)==1


check('reviewed_freezer_root_bridge_literal_roundtrip_exact',inversion)
check('NEG01_uses08_and_current_generation_preserves_stable_materials',first_assembly)
check('historical_nonce_replay_and_wrong_request_nonce_rejected',nonce_rejection)
check('NEG02_uses_only_qualified_current_NEG01_result',progression)
check('failed_or_foreign_generation_NEG01_rejected_for_NEG02',failed_or_foreign_progression)
check('helper_has_no_process_phone_identity_generation_endpoint',no_execution_endpoint)
report = {'schema':'hepta.native-guard.r8-root-plan-helper-local-review.v1',
    'state':'SIX_LOCAL_SYNTHETIC_SOURCE_CHECKS_PASSED_NOT_ACTUAL_PLAN_VALIDATION',
    'source':M.descriptor(SOURCE,raw),'checks':checks,'actual_freeze_read':False,
    'actual_validate_plan_called':False,'actual_plan_created':False,'phone_calls':0,
    'remote_operations':0,'new_random_identities_generated':0,'component_qualified':False}
out = HERE/'validation/HOST-RESULT.json'
assert not out.exists()
out.write_bytes(M.encoded(report))
print(M.encoded(report).decode(),end='')
