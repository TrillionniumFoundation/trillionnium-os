#!/usr/bin/env python3
"""Pure local wiring checks. Every runtime loader and policy/case continuation is fenced."""
import ast
import base64
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import types

ROOT=Path('/workspace/scratch/1ad3d6f55439')
HERE=Path(__file__).resolve().parent
PKG=HERE/'package'
RUNTIME=ROOT/'runtime_prefix_successor_candidate01/delivery-final01/package/runtime'
PARENT_RUNTIME=ROOT/'runtime_prefix_successor_candidate01/reference/runtime32'
OUT=HERE/'validation/wiring-run01'
OUT.mkdir(parents=True,exist_ok=False)
results=[]


def enc(v):
    return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()


def pin(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def load(path):
    raw=path.read_bytes();m=types.ModuleType('test_'+path.stem)
    m.__file__=str(path);exec(compile(raw,str(path),'exec'),m.__dict__)
    return m,raw


def check(name,fn):
    try:
        detail=fn()
        results.append(dict(name=name,status='PASS',detail=detail))
    except BaseException as exc:
        results.append(dict(name=name,status='FAIL',error_type=type(exc).__name__,detail=str(exc)))


class ReachedFence(Exception):
    pass


def expect_error(fn,substring):
    try:
        fn()
    except ValueError as exc:
        assert substring in str(exc),(substring,str(exc))
        return str(exc)
    raise AssertionError('expected refusal: '+substring)


manifest_raw=(RUNTIME/'MANIFEST.json').read_bytes()
manifest=json.loads(manifest_raw)
runtime_files={r['path']:(RUNTIME/r['path']).read_bytes() for r in manifest['files']}
parent_raw=(PARENT_RUNTIME/'MANIFEST.json').read_bytes()
parent_files={r['path']:(PARENT_RUNTIME/r['path']).read_bytes() for r in json.loads(parent_raw)['files']}
assert pin(manifest_raw)==dict(bytes=19020,sha256='a33474b4479b8bb47acb6407525e30e82151e9f4b83dc0081851051003b144d7')
consumer,craw=load(PKG/'templates/release_boundaries.py')
constructor,conraw=load(PKG/'templates/make_component_boundary_inputs.py')
derive,draw=load(PKG/'source/derive_final_cascade_property_r8.py')
interface,iraw=load(PKG/'source/write_final_seal_interface_property_r8.py')
preparer,praw=load(PKG/'preparer/prepare_final_cascade.py')
pure,pureraw=load(PKG/'source/runtime_source_increment.py')
frozen=json.loads((ROOT/'actual_external_r8_cascade_and_09/r10-boundary-consumers-final-r8/DELIVERY-RESULT.json').read_bytes())['reviewed_finalization']
frozen=copy.deepcopy(frozen)
frozen['runtime_manifest']=dict(path=str(derive.B/'native-guard-r10-r1-operator-r8-inventory-prefix-1ad3-01/runtime/MANIFEST.json'),**pin(manifest_raw))
consumer.PACKAGE_SHA=pin(manifest_raw)['sha256']
consumer.CURRENT_COMBINATION_SHA=frozen['component_combination']['sha256']
constructor.PACKAGE_SHA=consumer.PACKAGE_SHA


def source_inverse():
    ref=(ROOT/'lossless_bundle_source_cache/templates/release_boundaries.py').read_bytes()
    block=pureraw[pureraw.index(b'RUNTIME_SOURCE_INCREMENT = '):]
    x=craw.replace(b'\n'+block+b'\n\ndef validate_component',b'\ndef validate_component',1)
    x=x.replace(b'    # Validate every new runtime byte before any component source is executed.\n'
                b'    verify_runtime_source_increment(manifest_raw, source)\n',b'',1)
    assert x==ref
    ref=(ROOT/'lossless_bundle_source_cache/templates/make_component_boundary_inputs.py').read_bytes()
    x=conraw.replace(b'    # The constructor must pass the same complete-byte gate before any runtime loader.\n'
        b'    h.verify_runtime_source_increment(manifest_raw,\n'
        b"        {item['path']: bodies[item['sha256']] for item in manifest['files']})\n",b'',1)
    assert x==ref
    assert consumer.MAX_BUNDLE==32*1024*1024
    assert len(craw)<131072 and consumer.PACKAGE_FILE_COUNT==32
    return 'Both complete template inverses match6195/ed12; codec and32MiB unchanged.'


check('complete_consumer_constructor_inverse_and_budget',source_inverse)


def pure_identity():
    def spans(raw):
        lines=raw.splitlines(keepends=True);out={}
        for n in ast.parse(raw).body:
            if isinstance(n,ast.FunctionDef) and n.name=='verify_runtime_source_increment' or (
                isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)
                and n.targets[0].id=='RUNTIME_SOURCE_INCREMENT'):
                lo=sum(map(len,lines[:n.lineno-1]))+n.col_offset
                hi=sum(map(len,lines[:n.end_lineno-1]))+n.end_col_offset
                out[getattr(n,'name','RUNTIME_SOURCE_INCREMENT')]=raw[lo:hi]
        return out
    wanted=spans(pureraw)
    assert len(wanted)==2
    assert all(spans(x)==wanted for x in (craw,draw,iraw))
    proofs=[m.verify_runtime_source_increment(manifest_raw,runtime_files) for m in (consumer,derive,interface,pure)]
    assert all(x==proofs[0] for x in proofs)
    return 'All three executable copies are byte-identical6282; same actual32 proof.'


check('pure_gate_whole_byte_copies_and_actual32',pure_identity)


def component_value(mraw,files):
    value={k:None for k in consumer.COMPONENT_FIELDS}
    value.update(schema='hepta.r10.component-boundary-inputs.v5',release_id=consumer.RELEASE,boot_id=consumer.BOOT)
    pool={}
    def add(name,raw):
        row=dict(path='/SYNTHETIC-WIRING-NOT-PHONE/'+name,**pin(raw))
        pool[row['sha256']]=consumer.pack_original(raw)
        return row
    value['component_package_manifest']=add('MANIFEST.json',mraw)
    value['component_package_files']=[dict(name=name,copy=add(name,raw)) for name,raw in files.items()]
    # The next combination read is an explicit fence; no runtime source is loaded.
    value['component_combination']={'path':'/SYNTHETIC-WIRING-NOT-PHONE/NEXT-COMBINATION', 'bytes':1,'sha256':'0'*64}
    return {'originals':pool},value


def consumer_reaches_next(mraw,files):
    bundle,value=component_value(mraw,files)
    real=consumer.original_from;calls=[]
    def bounded(bundle,row):
        if row['path'].endswith('/NEXT-COMBINATION'):
            calls.append('next_combination_read');raise ReachedFence('after complete runtime gate')
        return real(bundle,row)
    consumer.original_from=bounded
    consumer.PACKAGE_SHA=pin(mraw)['sha256'] # Test-only outerpin allows exercising the independent inverse gate.
    try:
        try:consumer.validate_component(bundle,value)
        except ReachedFence:pass
        else:raise AssertionError('continuation fence not reached')
        assert calls==['next_combination_read']
    finally:
        consumer.original_from=real;consumer.PACKAGE_SHA=pin(manifest_raw)['sha256']
    return 'All32 exact originals passed; stopped before combination or runtime execution.'


check('consumer_real_validation_path_reaches_only_next_fence',lambda:consumer_reaches_next(manifest_raw,runtime_files))


def consumer_rejects(mraw,files,substring):
    bundle,value=component_value(mraw,files)
    consumer.PACKAGE_SHA=pin(mraw)['sha256']
    try:return expect_error(lambda:consumer.validate_component(bundle,value),substring)
    finally:consumer.PACKAGE_SHA=pin(manifest_raw)['sha256']


check('consumer_original67dc_cannot_be_relabelled_successor',lambda:consumer_rejects(parent_raw,parent_files,'fixed reviewed runtime increment'))
typed=copy.deepcopy(manifest);typed['runtime_source_increment']['successor_actions']['phone_operations']=False
check('consumer_dropped_increment_bool_type_substitution_refused',lambda:consumer_rejects(enc(typed),runtime_files,'exact-typed'))
altered_files=dict(runtime_files);altered_files['source/late_boundary.py']+=b'\n# unrelated source drift\n'
altered_manifest=copy.deepcopy(manifest)
for row in altered_manifest['files']:
    if row['path']=='source/late_boundary.py':row.update(pin(altered_files[row['path']]))
check('consumer_hash_consistent_extra_source_drift_refused',lambda:consumer_rejects(enc(altered_manifest),altered_files,'only the exact reviewed'))


def constructor_path(mraw,files,refusal=None):
    constructor.PACKAGE_SHA=consumer.PACKAGE_SHA=pin(mraw)['sha256']
    root=OUT/'SYNTHETIC-READ-MAP-NOT-PHONE'
    data={str(root/'MANIFEST.json'):mraw,**{str(root/n):b for n,b in files.items()}}
    gate_calls=[];real_read=consumer.read_pinned;real_gate=consumer.verify_runtime_source_increment
    def read(row):
        if row['path']=='/SYNTHETIC-NEXT-RETIREMENT':
            raise ReachedFence('after constructor runtime gate')
        raw=data[row['path']];assert pin(raw)=={k:row[k] for k in ('bytes','sha256')}
        return raw,('synthetic-read-map',row['path'])
    def gate(raw,source):
        gate_calls.append((pin(raw),len(source)))
        return real_gate(raw,source)
    consumer.read_pinned=read;consumer.verify_runtime_source_increment=gate
    plan={k:None for k in ['schema','package_manifest','retirement_descriptor','retirement_originals',
        'shared_materials','policy_adoption','cases','legacy_ancestor','pre_policy_ancestor',
        'environment_parent_ancestor','property_parent_ancestors']}
    plan.update(schema=constructor.SCHEMA,package_manifest=dict(path=str(root/'MANIFEST.json'),**pin(mraw)),
        cases=[{'synthetic_fence_only':True}],retirement_descriptor={'path':'/SYNTHETIC-NEXT-RETIREMENT'})
    try:
        if refusal:
            detail=expect_error(lambda:constructor.build(consumer,plan,OUT/'NEVER-CREATED'),refusal)
        else:
            try:constructor.build(consumer,plan,OUT/'NEVER-CREATED')
            except ReachedFence:detail='Stopped at retirement input after one real all32 constructor gate.'
            else:raise AssertionError('retirement fence not reached')
        assert len(gate_calls)==1 and not (OUT/'NEVER-CREATED').exists()
        return detail
    finally:
        consumer.read_pinned=real_read;consumer.verify_runtime_source_increment=real_gate
        constructor.PACKAGE_SHA=consumer.PACKAGE_SHA=pin(manifest_raw)['sha256']


check('constructor_real_build_all32_gate_before_retirement_case_or_runtime',lambda:constructor_path(manifest_raw,runtime_files))
check('constructor_refuses_original67dc_before_retirement',lambda:constructor_path(parent_raw,parent_files,'fixed reviewed runtime increment'))


def normalization():
    before_raw=manifest_raw;before_files=dict(runtime_files)
    raw,value,files,proof=derive.runtime_parent_proof_view(manifest_raw,runtime_files)
    assert raw==parent_raw and files==parent_files
    assert manifest_raw==before_raw and runtime_files==before_files
    assert files is not runtime_files and value is not manifest
    assert proof['runtime_manifest']==pin(manifest_raw)
    return 'Normalized view is whole-byte actual67dc/c50a, inputs unchanged; proof bindsa334.'


check('parent_proof_view_is_exact_copy_no_original_mutation',normalization)


def reviewed_runtime_continuation(wrong_policy=False):
    r7files=dict(parent_files)
    r7files['source/late_boundary.py']=r7files.pop('reference/property_parent_late_boundary_r7.py')
    # This is an explicitly derived31-row test view, not an actual read-back R7 manifest.
    r7={'files':[dict(path=n,**pin(b)) for n,b in sorted(r7files.items())]}
    names={'policy_parent_late_boundary_r4.py':'reference/policy_parent_late_boundary_r4.py',
        'environment_parent_late_boundary_r6.py':'reference/environment_parent_late_boundary_r6.py',
        'property_parent_late_boundary_r7.py':'reference/property_parent_late_boundary_r7.py',
        'component_common_r5.py':'reference/component_common_r5.py',
        'non_native_attempt05.py':'reference/non_native_attempt05.py'}
    templates={name:parent_files[path] for name,path in names.items()}
    for name in ('stage_component.py','component_common.py','component_lifecycle.py','component_snapshot.py','close_component.py'):
        templates[name]=parent_files['source/'+name]
    late=parent_files['source/late_boundary.py']
    for n in ('REVIEWED_CURRENT_COMBINATION_SHA256','REVIEWED_CURRENT_POLICY_SHA256','REVIEWED_CURRENT_POLICY_ADOPTION_SHA256'):
        line=next(x for x in late.splitlines(keepends=True) if x.startswith((n+'=').encode()))
        late=late.replace(line,(n+'=None\n').encode(),1)
    assert pin(late)==derive.TEMPLATE_PINS['late_boundary.py']
    templates['late_boundary.py']=late
    real=derive.package
    def package(root,digest,size):
        assert digest==pin(manifest_raw)['sha256'] and size==len(manifest_raw)
        return manifest_raw,copy.deepcopy(manifest),dict(runtime_files)
    derive.package=package
    selected=copy.deepcopy(frozen)
    if wrong_policy:selected['actual_policy']['sha256']='0'*64
    try:
        if wrong_policy:return expect_error(lambda:derive.reviewed_runtime(selected,templates,r7,r7files),'three-literal output')
        raw,value,files=derive.reviewed_runtime(selected,templates,r7,r7files)
        assert raw==manifest_raw and value==manifest and files==runtime_files
        assert raw!=parent_raw and files['source/late_boundary.py']!=parent_files['source/late_boundary.py']
        return 'Actual reviewed_runtime retained all old31-to32 and literal/history checks, then returneda334/147cf, never normalized bytes.'
    finally:derive.package=real


check('original_runtime_proof_continues_and_returns_actual_successor',reviewed_runtime_continuation)
check('old_three_policy_literal_gate_still_refuses_wrong_policy',lambda:reviewed_runtime_continuation(True))


def source_manifest_gate():
    gen=(PKG/'GENERATOR-SOURCE-MANIFEST.json').read_bytes()
    tm=(ROOT/'lossless_bundle_source_cache/SOURCE-MANIFEST.json').read_bytes()
    mapping={preparer.GENERATOR_MANIFEST['path']:gen,preparer.TEMPLATE_MANIFEST['path']:tm}
    for n,change in preparer.TEMPLATE_OVERRIDES.items():mapping[change['successor']['path']]=(PKG/'templates'/n).read_bytes()
    seen=[]
    class Originals:
        def read(self,row):
            raw=mapping[row['path']];assert pin(raw)=={k:row[k] for k in ('bytes','sha256')}
            seen.append(row['path']);return raw
    preparer.validate_source_manifests(Originals(),derive)
    assert len(seen)==4 and len(derive.TEMPLATE_PINS)==19
    return 'Exact81663 nineteen-row source set with only two independently pinned overrides accepted.'


check('preparer_nineteen_original_templates_and_two_overrides',source_manifest_gate)


def no_finalization():
    assert derive.FINALIZATION is None and interface.DELIVERY is None and interface.OUT is None
    return expect_error(lambda:derive.finalization(),'not frozen')


check('future_finalization_and_delivery_remain_unfilled',no_finalization)


def namespace_and_parent_retention():
    assert str(derive.FC).endswith('r10-boundary-consumers-final-r8-inventory-prefix-1ad3-01')
    assert str(derive.AC).endswith('scoped-acceptance-v150-r10-r1-readiness-r9-inventory-prefix-1ad3-01')
    assert str(derive.CC).endswith('r10-component-boundary-input-entry-r8-inventory-prefix-1ad3-01')
    assert derive.FC!=derive.FC_PARENT and derive.AC!=derive.AC_PARENT and derive.CC!=derive.CC_PARENT
    old={'changed.py':b'old','retained.json':b'same'};new={'changed.py':b'new','retained.json':b'same'}
    derive.retain_overwritten_parent_files(old,new,'reference/parent')
    assert new['reference/parent/changed.py']==b'old' and old=={'changed.py':b'old','retained.json':b'same'}
    assert 'reference/parent/retained.json' not in new
    return 'Create-only suffixes differ from actual parents; replaced parent bytes retained.'


check('independent_namespaces_and_complete_replaced_parent_retention',namespace_and_parent_retention)

report={
 'schema':'hepta.inventory-prefix.consumer-cascade-wiring-checks.v1',
 'state':'PASS_LOCAL_SOURCE_WIRING_ONLY' if all(r['status']=='PASS' for r in results) else 'FAIL_RETAIN_ORIGINALS',
 'checks':results,'passed':sum(r['status']=='PASS' for r in results),'total':len(results),
 'sources':{n:pin((PKG/n).read_bytes()) for n in ['templates/release_boundaries.py',
     'templates/make_component_boundary_inputs.py','source/derive_final_cascade_property_r8.py',
     'source/write_final_seal_interface_property_r8.py','preparer/prepare_final_cascade.py','source/runtime_source_increment.py']},
 'runtime':pin(manifest_raw),'runtime_sources':32,
 'scope':{'no_target_runtime_module_executed':True,'no_policy_verifier_executed':True,
  'no_full_cascade_or_interface_main_executed':True,'constructor_stopped_before_retirement_and_cases':True,
  'host_source_only':True,'actual_parent_R7_manifest_read_here':False,
  'derived_R7_test_view_labelled_synthetic':True,'case_or_nonce_generated':False,
  'actual_phone_or_P4_operations':0,'physical_case_passed':False}}
raw=enc(report);(OUT/'RESULT.json').write_bytes(raw)
print(json.dumps(dict(path=str(OUT/'RESULT.json'),**pin(raw),state=report['state'],passed=report['passed'],total=report['total']),sort_keys=True))
if report['passed']!=report['total']:raise SystemExit(1)
