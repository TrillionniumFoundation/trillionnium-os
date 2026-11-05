#!/usr/bin/env python3
"""Source and interface checks using explicitly synthetic bindings; no remote/phone/case."""
import argparse,ast,contextlib,copy,hashlib,io,json,sys,types
from pathlib import Path

def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(raw,path,name):
    m=types.ModuleType(name);m.__file__=str(path);exec(compile(raw,str(path),'exec'),m.__dict__);return m
def enc(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,indent=2)+'\n').encode()
def run(package,out):
    rows=[]
    def check(name,fn):
        try:detail=fn();rows.append({'name':name,'passed':True,'detail':detail})
        except BaseException as e:rows.append({'name':name,'passed':False,'error':type(e).__name__+':'+str(e)})
    def reject(fn,contains):
        try:fn()
        except ValueError as error:
            assert contains in str(error),(contains,str(error));return str(error)
        raise AssertionError('unexpected acceptance')
    source=(package/'source/derive_negative_operator_sources.py').read_bytes()
    prep_raw=(package/'source/prepare_negative_source_generation.py').read_bytes()
    old_raw=(package/'reference/derive_negative_operator_sources.6adb.original.py').read_bytes()
    G=load(source,package/'source/derive_negative_operator_sources.py','capture_generator_test')
    old=load(old_raw,package/'reference/derive_negative_operator_sources.6adb.original.py','unchanged_parent_generator_test')
    P=load(prep_raw,package/'source/prepare_negative_source_generation.py','capture_binding_test')
    root_template=(package/'reference/root-capture-r8-50a5.original.py').read_bytes()
    fixture=package/'validation/parent-source-fixtures'
    parents={}
    for kind in ('ui','fault','component'):
        raw=(fixture/kind/'MANIFEST.json').read_bytes();value=G.strict(raw)
        assert G.pin(raw)=={k:G.PARENT_MANIFESTS[kind][k] for k in ('bytes','sha256')}
        files={}
        for row in value.get('files',value.get('runtime_sources',[])):
            body=(fixture/kind/row['path']).read_bytes();assert G.pin(body)=={k:row[k] for k in ('bytes','sha256')};files[row['path']]=body
        parents[kind]={'raw':raw,'value':value,'files':files}
    for kind in ('cpu','phone','p4'):
        raw=(fixture/kind/'source.original.py').read_bytes()
        assert G.pin(raw)=={k:G.DIRECT_PARENTS[kind][k] for k in ('bytes','sha256')};parents[kind]={'raw':raw}
    def p(label):return {'bytes':len(label.encode()),'sha256':sha(label.encode())}
    binding={k:p('SYNTHETIC-NOT-ACTUAL-'+k) for k in
        ('consumer','readiness','runtime','combination','policy','adoption','verifier','scope','full_rule')}
    binding.update(consumer_manifest={'path':str(G.FC/'MANIFEST.json'),**p('SYNTHETIC-FC')},
        acceptance_manifest={'path':str(G.AC/'MANIFEST.json'),**p('SYNTHETIC-AC')})
    expected={'PKG':binding['runtime']['sha256'],'COMBINATION':binding['combination']['sha256'],
        'VERIFIER_SHA':binding['verifier']['sha256'],'VERIFIER_BYTES':binding['verifier']['bytes'],
        'POLICY_SHA':binding['policy']['sha256'],'ADOPTION_SHA':binding['adoption']['sha256'],
        'ROOT_SCOPE_SHA':binding['scope']['sha256']}
    actual_root,unused=G.changed_source(root_template,[(n,None,repr(v)) for n,v in expected.items()])
    # Exact reviewed bridge source is a fixed reference copied solely for this source fixture.
    bridge_parent=(package/'reference/phone_chain_bridge.6694.original.py').read_bytes()
    bridge,unused=G.changed_source(bridge_parent,[('PKG',None,repr(binding['runtime']['sha256']))])
    verifier=b'SYNTHETIC-NOT-ACTUAL-verifier'
    assert G.pin(verifier)==binding['verifier']
    root_directory=G.B/'native-guard-property-root-r8-capture-successor01-1ad3'
    root_bodies={'source/run_component_root_once.py':actual_root,'source/phone_chain_bridge.py':bridge,
        'reference/policy_native5_verifier.py':verifier}
    root_mf={'schema':'hepta.native-guard.root-chain-source-package.v1',
        'state':'ACTUAL_R8_ROOT_CAPTURE_SUCCESSOR_SOURCE_ONLY','frozen_component_package_sha256':binding['runtime']['sha256'],
        'current_combination_sha256':binding['combination']['sha256'],
        'explicit_policy_adoption_sha256':binding['adoption']['sha256'],'files':G.rowset(root_bodies)}
    root_mf_raw=G.encoded(root_mf);root_desc={'path':str(root_directory/'SOURCE-MANIFEST.json'),**G.pin(root_mf_raw)}
    originals={str(root_directory/name):body for name,body in root_bodies.items()}
    originals[root_desc['path']]=root_mf_raw
    for name,(leaf,size,digest) in G.CLOSURE_REFERENCES.items():
        body=(package/'reference'/leaf).read_bytes();assert (len(body),sha(body))==(size,digest)
        originals[str(G.CLOSURE_REFERENCE_ROOT/leaf)]=body
    sender=(package/'reference/send_new_native_task_r5.5ab040.original.py').read_bytes()
    originals[G.SENDER_SOURCE['path']]=sender
    class SourceReader:
        def __init__(self,values):self.values=values;self.reads=[]
        def read(self,row,maximum):
            G.descriptor(row,maximum);raw=self.values[row['path']]
            assert G.pin(raw)=={k:row[k] for k in ('bytes','sha256')};self.reads.append(row);return raw
    def parse_sources():
        for body in (source,prep_raw,old_raw):ast.parse(body,feature_version=(3,9))
        return {'three_sources_python39':True}
    check('new generator and preparer retain Python 3.9 grammar',parse_sources)
    def inverse():
        value=G.strict((package/'validation/EXACT-REPLACEMENTS.json').read_bytes());b=source
        for e in reversed(value['replacements']):
            assert b.count(e['new'].encode())==1;b=b.replace(e['new'].encode(),e['old'].encode(),1)
        assert b==old_raw
        for name in ('derive_packages','actual_dependencies','parent_packages','changed_source','finalization','put','write_tree'):
            assert G.functions(source)[name]==G.functions(old_raw)[name],name
        return {'whole_source_inverse_to_6adb':True,'seven_original_functions_byte_identical':True}
    check('whole increment inverse and original six-package functions are exact',inverse)
    def preview():
        oldargv=sys.argv;sys.argv=[G.__file__]
        try:
            with contextlib.redirect_stdout(io.StringIO()) as stream:rc=G.main()
            v=json.loads(stream.getvalue());assert rc==0 and v['originals_read']==0 and v['future_dependencies_bound'] is False
            with contextlib.redirect_stdout(io.StringIO()) as stream:rc=P.main([])
            assert rc==0 and json.loads(stream.getvalue())['state']=='SOURCE_PREVIEW_NO_ORIGINAL_READ_NO_GENERATION'
        finally:sys.argv=oldargv
        return {'generation_calls':0,'phone_calls':0}
    check('both default entries perform source preview only',preview)
    check('unbound actual Root manifest is refused',lambda:reject(G.capture_manifest_pin,'exact original descriptor'))
    G.ROOT_CAPTURE_MANIFEST=root_desc
    def capture_success():
        c=G.capture_dependencies(SourceReader(originals),binding)
        assert c['root_raw']==actual_root and c['root_slots']==expected
        return {'seven_slots_bound':7,'source_controls_are_synthetic':True}
    check('actual Root namespace and seven-slot reviewed source inverse join the dependency generation',capture_success)
    capture=G.capture_dependencies(SourceReader(originals),binding)
    packages,proof,patches=G.derive_packages(parents,binding)
    def unchanged_six():
        prior=old.derive_packages(parents,binding)
        assert (packages,proof,patches)==prior
        return {'unchanged_output_packages':sorted(packages),'all_bytes_equal':True}
    check('all six original generated packages are byte-identical to6adb',unchanged_six)
    closure,cproof,cpatch=G.derive_capture_closure(packages,binding,capture)
    def closure_success():
        negative=load(closure['source/negative_originals.py'],out/'SYNTHETIC-CLOSURE/source/negative_originals.py','test_bound_assembly')
        deps=negative.final_dependencies();assert len(deps['sources'])==5 and len(negative.DEP_HASH_NAMES)==9
        assert deps['sources']['root_transport']==G.pin(actual_root)
        before=capture['references'];assert G.functions(closure['source/negative_originals.py'])==G.functions(before['negative_originals'])
        assert G.functions(closure['source/root_cpu_negative.py'])==G.functions(before['root_cpu_negative'])
        assert closure['source/close_cpu_negative.py']==before['close_cpu_negative'] and closure['source/ledger_prefix_negative.py']==before['ledger_prefix_negative']
        assert G.value(closure['source/root_cpu_negative.py'],'PURE_MODULES')=={
            'negative_originals':G.pin(closure['source/negative_originals.py']),
            'close_cpu_negative':G.pin(closure['source/close_cpu_negative.py'])}
        contract=G.strict(closure['HOST-CAPTURE-INPUT-CONTRACT.json'])
        assert len(contract['phase_inputs'])==4 and all('output_capture' in r['required_records'] for r in contract['phase_inputs'].values())
        assert 'output_capture' not in contract['success_RESULT_fields']
        return {'dependency_sources':5,'dependency_SHA_fields':9,'sidecar_phase_inputs':4,'success_result_fields':7}
    check('closure binds exact five sources nine SHA fields and separate original capture sidecars',closure_success)
    def damaged_root(raw,expected_message):
        changed=dict(root_bodies);changed['source/run_component_root_once.py']=raw
        mf=dict(root_mf,files=G.rowset(changed));mfraw=G.encoded(mf);mfd=dict(root_desc,**G.pin(mfraw))
        values=dict(originals);values[str(root_directory/'source/run_component_root_once.py')]=raw;values[mfd['path']]=mfraw
        G.ROOT_CAPTURE_MANIFEST=mfd
        try:return reject(lambda:G.capture_dependencies(SourceReader(values),binding),expected_message)
        finally:G.ROOT_CAPTURE_MANIFEST=root_desc
    check('old Q2 capture source is refused even with rehashed manifest',lambda:damaged_root(
        capture['references']['root_parent'],'one_actual_R8_slot'))
    check('one byte outside seven Root slots is refused',lambda:damaged_root(actual_root+b'\n',
        'actual_R8_root_not_exact_reviewed_capture_template'))
    wrong,unused=G.changed_source(actual_root,[('ROOT_SCOPE_SHA',None,repr('0'*64))])
    check('valid-shaped wrong actual Root scope SHA is refused',lambda:damaged_root(wrong,
        'all seven actual capture Root slots'))
    def old_namespace():
        G.ROOT_CAPTURE_MANIFEST=dict(root_desc,path=str(G.B/'native-guard-r10-r1-operator-r8/root-chain/SOURCE-MANIFEST.json'))
        try:return reject(G.capture_manifest_pin,'only the actual frozen R8 Root source manifest')
        finally:G.ROOT_CAPTURE_MANIFEST=root_desc
    check('canonical old Root package cannot substitute for reviewed successor',old_namespace)
    def bind_two():
        final={'schema':G.FINAL_SCHEMA,'consumer_manifest':binding['consumer_manifest'],
            'acceptance_manifest':binding['acceptance_manifest'],
            'policy_adoption':{'path':str(G.B/'SYNTHETIC-NOT-ACTUAL-adoption.json'),**binding['adoption']},
            'current_policy':{'path':str(G.B/'SYNTHETIC-NOT-ACTUAL-policy'),**binding['policy']}}
        value={'schema':'hepta.r10.cpu-negative-capture-source-binding-inputs.v1',
            'out':str(G.B/'property-r8-negative-capture-bound-SYNTHETIC-NOT-ACTUAL'),
            'finalization':final,'root_capture_manifest':root_desc}
        target,bound,edits=P.prepare(G,source,value)
        assert len(edits)==2 and G.inverse(bound,edits,source)
        assert G.value(bound,'ROOT_CAPTURE_MANIFEST')==root_desc and G.value(bound,'FINALIZATION')==final
        return {'only_two_binding_RHS':True,'actual_source_binding_created':False}
    check('source-only preparer changes exactly original finalization and explicit Root manifest',bind_two)
    def unchanged_cases():
        n=load(closure['source/negative_originals.py'],out/'negative.py','test_case_whitelist')
        value={k:None for k in ('schema','state','case_id','nonce','scope','owner_request_sha256','native_request_sha256',
            'combination_sha256','sources','phone','p4','actor_execution','sender','out')}
        value.update(schema=n.SCHEMA,state='ROOT_REVIEWED_EXISTING_NEGATIVE_ORIGINALS_ONLY',case_id='NEG-04',nonce='1'*32)
        return reject(lambda:n.validate_plan(value),'fixed_negative_case_existing_nonce')
    check('CPU closer still refuses physical fault case04',unchanged_cases)
    def actual_loader():
        directory=out/'SYNTHETIC-CLOSURE';(directory/'source').mkdir(parents=True)
        for name,body in closure.items():
            target=directory/name;target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('xb') as stream:stream.write(body)
        root=load(closure['source/root_cpu_negative.py'],directory/'source/root_cpu_negative.py','test_generated_root_loader')
        # Process-local fixture namespace only; the generated source bytes and production B remain unchanged.
        root.B=str(directory)
        loaded=root.load_pure();assert set(loaded)=={'negative_originals','close_cpu_negative'}
        assert loaded['negative_originals']['module'].final_dependencies()==G.strict(closure['FINAL-DEPENDENCIES.json'])
        return {'actual_pinned_loader_ran_on_synthetic_source_files':True,'case_execution_calls':0,
            'B_mapped_only_in_test_module_memory':True,'production_source_bytes_unchanged':True}
    check('unchanged Root pinned loader loads generated closure modules and final dependencies',actual_loader)
    result={'schema':'hepta.cpu-negative-capture-generator.source-checks.v1','state':'PASS' if all(x['passed'] for x in rows) else 'FAIL',
        'checks':rows,'passed':sum(x['passed'] for x in rows),'total':len(rows),
        'generator_source':{'bytes':len(source),'sha256':sha(source)},'preparer_source':{'bytes':len(prep_raw),'sha256':sha(prep_raw)},
        'all_bindings_are_explicit_synthetic_source_controls':True,'actual_generations':0,'remote_calls':0,
        'phone_calls':0,'fault_actor_calls':0,'native_cases':0,'physical_case_pass':False}
    with (out/'RESULT.json').open('xb') as stream:stream.write(enc(result))
    print(json.dumps(result,sort_keys=True));return 0 if result['state']=='PASS' else 1
def main():
    p=argparse.ArgumentParser();p.add_argument('--package',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    a.out.mkdir(mode=0o700);return run(a.package.resolve(strict=True),a.out.resolve(strict=True))
if __name__=='__main__':raise SystemExit(main())
