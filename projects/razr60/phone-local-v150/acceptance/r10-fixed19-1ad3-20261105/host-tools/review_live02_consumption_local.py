"""Local source and interface checks only. Never load a transport or phone path."""
from pathlib import Path
import ast
import hashlib
import json
import types

ROOT=Path(__file__).resolve().parent.parent
P=ROOT/'property_diagnostic'
R=ROOT/'recovery_source_cache'
PACKAGE=ROOT/'transport_fix/root-runtime-properties-live02-capture-r6-1ad3-candidate02'

def sha(raw):return hashlib.sha256(raw).hexdigest()
def descriptor(path):
    raw=path.read_bytes();return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}
def literal(raw,name):
    return next(ast.literal_eval(n.value) for n in ast.parse(raw).body
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)
        and n.targets[0].id==name)
def module(path):
    m=types.ModuleType('local_source_interface_review');m.__file__=str(path)
    exec(compile(path.read_bytes(),str(path),'exec'),m.__dict__);return m

old_helper=P/'prepare_runtime_properties_post.py'
assert descriptor(old_helper)['sha256']=='8fbbf6a0da8d12dcef7ae911654efbb2f09bb5d379dc41c18f36bba05c4a75b7'
new_helper=P/'prepare_runtime_properties_post_v2.py'
post=module(new_helper)
fragment=(R/'prior_failed_transaction.fragment.py').read_bytes()
assert post.PRIOR_FAILED_TRANSACTION==literal(fragment,'PRIOR_FAILED_TRANSACTION')
prior=post.PRIOR_FAILED_TRANSACTION
actor=literal(fragment,'PRIOR_FAILURE_EVIDENCE')['actor_wrapper']
checks=[]

# These minimal root objects are interface fixtures, not actual transactions.
def check_fixture(which):
    values={};reads=[]
    def put(name,value):
        raw=post.enc(value);row={'path':'/LOCAL-INTERFACE-FIXTURE-NOT-ACTUAL/'+name,
            'bytes':len(raw),'sha256':post.sha(raw)};values[post.key(row)]=raw;return row
    plan={'schema':'hepta.root.runtime-properties-live-plan.v2','prior_failed_transaction':dict(prior)}
    if which=='plan_other_prior':plan['prior_failed_transaction']['path']+='.different'
    plan_row=put('plan.json',plan)
    intent={'schema':'hepta.root.runtime-properties-live-intent.v2','prior_failed_transaction':dict(prior),
        'plan_sha256':plan_row['sha256']}
    if which=='intent_other_prior':intent['prior_failed_transaction']['sha256']='0'*64
    intent_row=put('intent.json',intent)
    execution={'schema':'hepta.root.runtime-properties-live-execution.v2','prior_failed_transaction':dict(prior),
        'root_plan':plan_row,'root_intent':intent_row,
        'state':'ORIGINAL_POLICY_APPLY_CAPTURED_PENDING_INDEPENDENT_COMPARISON',
        'policy_apply_calls':1,'known_apply_error':None}
    if which=='execution_v1':execution['schema']='hepta.root.runtime-properties-live-execution.v1'
    execution_row=put('execution.json',execution)
    live={'root_plan':plan_row,'root_intent':intent_row,'root_execution':execution_row}
    values[post.key(prior)]=(R/'RESULT.json').read_bytes()
    values[post.key(actor)]=(R/'FAILED-ACTOR-WRAPPER.original.json').read_bytes()
    def get(row):
        reads.append(post.key(row));return values[post.key(row)]
    class VerifierInterfaceFixture:
        PRIOR_FAILED_TRANSACTION=prior
        calls=0
        @classmethod
        def verify_prior_failed_transaction(cls,raw,read_pinned):
            cls.calls+=1
            assert raw==values[post.key(prior)]
            assert read_pinned(actor)==values[post.key(actor)]
            return {'schema':'hepta.runtime-properties-r10.failed-predecessor-verification.v1',
                'state':'ACTUAL_LIVE01_FAILED_BEFORE_POLICY_INVOCATION','actual_magiskpolicy_invocations':0,
                'old_stage_preserved':True,'old_output_absent':True,'automatic_retry':False,'replayed_apply':False}
    if which=='verifier_other_prior':VerifierInterfaceFixture.PRIOR_FAILED_TRANSACTION={}
    if which=='valid_transitive':
        post.verify_v2_prior_inputs(VerifierInterfaceFixture,live,get)
        assert VerifierInterfaceFixture.calls==1 and post.key(actor) in reads and post.key(prior) in reads
    else:
        try:post.verify_v2_prior_inputs(VerifierInterfaceFixture,live,get)
        except ValueError:pass
        else:raise AssertionError('unqualified prior fixture accepted: '+which)
        assert VerifierInterfaceFixture.calls==0
    return {'name':which,'passed':True,'fixture_only_not_actual_qualification':True}
for which in ('valid_transitive','execution_v1','plan_other_prior','intent_other_prior','verifier_other_prior'):
    checks.append(check_fixture(which))
tree=ast.parse(new_helper.read_bytes())
for name in ('mac_stage','p4_plan'):
    node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name)
    calls=[n for n in ast.walk(node) if isinstance(n,ast.Call)]
    assert sum(isinstance(n.func,ast.Name) and n.func.id=='verify_v2_prior_inputs' for n in calls)==1
assert new_helper.read_text().count('prepare_runtime_properties_post_v2.py')==3
checks.append({'name':'both_Mac_and_P4_routes_require_v2_prior_and_stage_the_new_helper','passed':True})

increment=module(P/'adoption_inputs_prior_v2_increment.py')
base=(P/'retained_operator_sources/make_runtime_properties_adoption_inputs.py').read_text()
assert sha(base.encode())==increment.BASE_SHA256
for source in (base,base.replace('HOST_SUPPORT_SHA256=None',"HOST_SUPPORT_SHA256='"+'a'*64+"'")):
    result=increment.apply(source)
    assert result.replace(increment.AFTER,increment.BEFORE,1)==source
    call=next(n for n in ast.walk(ast.parse(result)) if isinstance(n,ast.Call)
        and isinstance(n.func,ast.Attribute) and n.func.attr=='verify_prior_failed_transaction')
    assert len(call.keywords)==1 and call.keywords[0].arg=='read_pinned'
    assert isinstance(call.keywords[0].value,ast.Name) and call.keywords[0].value.id=='add'
    try:increment.apply(result)
    except ValueError:pass
    else:raise AssertionError('double source increment admitted')
try:increment.apply(base+'# unrelated source increment\n')
except ValueError:pass
else:raise AssertionError('unreviewed source increment admitted')
checks.append({'name':'adoption_transitive_callback_exact_inverse_and_filled_pin_only_admission','passed':True})

mf=json.loads((PACKAGE/'SOURCE-MANIFEST.json').read_bytes())
assert descriptor(PACKAGE/'SOURCE-MANIFEST.json')['sha256']=='9cb8f7bc7ea82de7cd20f744c7112746f0d11086821eba54409ec7ef0e3de904'
assert len(mf['files'])==3
expected={'source/run_runtime_properties_policy_once.py':(20913,'4b1ae865a7266c26c3f2a862e202ec0d09fc6fb94b0831e53e807a6f0c90addd'),
 'source/run_component_root_once.py':(68481,'0374a8858a26114a6184e2e40949e33dbb9b0014117ce4637b55b72e7629a5bd'),
 'reference/run_component_root_once.r4.original.py':(43438,'860aaf747e89411efa993783b950f709b1d8ac5d7b606575065bdff74ef98e22')}
for row in mf['files']:
    body=(PACKAGE/row['path']).read_bytes()
    assert (len(body),sha(body))==expected[row['path']]==(row['bytes'],row['sha256'])
    compile(body,row['path'],'exec')
old=(R/'r2-run_runtime_properties_policy_once.py').read_bytes()
new=(PACKAGE/'source/run_runtime_properties_policy_once.py').read_bytes()
assert sha(old)=='574e639f52a3b99dc2ea6d6f82a7455d445fdb4d758bc486cf877df316921ebb'
def functions(raw):return {n.name:n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
old_f,new_f=functions(old),functions(new)
changed=[name for name in old_f if ast.dump(old_f[name],include_attributes=False)!=ast.dump(new_f[name],include_attributes=False)]
assert set(changed)=={'load_transport','validate','main'}
def prior_calls(raw):
    return [ast.dump(n,include_attributes=False) for n in ast.walk(ast.parse(raw)) if isinstance(n,ast.Call)
        and isinstance(n.func,ast.Attribute) and n.func.attr=='verify_prior_failed_transaction']
assert len(prior_calls(new))==3 and prior_calls(new)==prior_calls(old)
assert literal(new,'PRIOR_FAILURE')==prior==literal(old,'PRIOR_FAILURE')
handlers=[n for n in ast.walk(new_f['main']) if isinstance(n,ast.ExceptHandler)
    and isinstance(n.type,ast.Name) and n.type.id=='BaseException']
assert len(handlers)==1
handler=handlers[0]
assert isinstance(handler.body[0],ast.Assign)
assert ast.unparse(handler.body[0])=='host_cleanup = c.close_owned_host_outputs()'
assert 'host_cleanup' in ast.unparse(handler.body[1])
assert "'prior_failed_transaction': p['prior_failed_transaction']" in ast.unparse(handler.body[1])
assert 'hepta.root.runtime-properties-live-failure.v2' in ast.unparse(handler.body[1])
validate_source=ast.get_source_segment(new.decode(),new_f['validate'])
assert 'original_validator.validate_plan(original)' in validate_source and 'm.validate_plan(' not in validate_source
assert 'len(sources[\'files\'])==3' in validate_source
loader=ast.get_source_segment(new.decode(),new_f['load_transport'])
assert 'module.__file__=str(TRANSPORT_SOURCE)' in loader
assert 'original_validator.__file__=str(ORIGINAL_VALIDATOR_SOURCE)' in loader
checks.append({'name':'exact3_transport_originals_and_unchanged_three_prior_calls','passed':True})
checks.append({'name':'separate_true_source_loaders_and_outer_owner_cleanup_before_v2_failure','passed':True})

report={'schema':'hepta.runtime-properties.live02-consumption-independent-review.v1',
    'state':'LOCAL_SOURCE_AND_INTERFACE_REVIEW_PASSED_PENDING_ACTUAL_LIVE02_OPERATOR_BINDINGS',
    'artifacts':[descriptor(path) for path in (new_helper,P/'adoption_inputs_prior_v2_increment.py',
        P/'POST-V2-CONSUMPTION.patch',P/'ADOPTION-INPUTS-PRIOR-V2.patch',PACKAGE/'SOURCE-MANIFEST.json',
        PACKAGE/'source/run_runtime_properties_policy_once.py')],
    'unchanged_staged_helper':descriptor(old_helper),
    'reviewed_original_r2_driver':descriptor(R/'r2-run_runtime_properties_policy_once.py'),
    'reviewed_failed_predecessor_fragment':descriptor(R/'prior_failed_transaction.fragment.py'),
    'checks':checks,'findings':[],
    'fixed_capture_source_0374_suite_reexecuted':False,'transport_loaders_executed_by_this_review':False,
    'actual_live_capture_verified':False,'actual_post_stage_created':False,'actual_adoption_inputs_created':False,
    'remaining_required_integration':[
      'The final captured verifier must itself enforce v2 and the exact fixed failed predecessor inside verify_root_transaction.',
      'Apply the independent adoption-input source increment inside the final nine-source generation and rebind its support/source hashes.',
      'Freeze actual final live02 source pins and retain the unchanged stage/verifier resource caps; do not reuse live01 staging as live02 evidence.',
      'Root remains the single device owner and must reconcile the other existing chain before any phone operation.'],
    'mac_calls':0,'phone_calls':0,'policy_writes':0,'policy_parser_calls':0,'main_calls':0}
destination=P/'LIVE02-CONSUMPTION-INDEPENDENT-REVIEW.json'
with destination.open('x') as stream:stream.write(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps({'report':descriptor(destination),'checks':len(checks),'state':report['state']},sort_keys=True))
