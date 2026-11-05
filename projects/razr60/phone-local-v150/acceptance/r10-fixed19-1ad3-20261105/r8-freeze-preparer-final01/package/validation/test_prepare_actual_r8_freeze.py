#!/usr/bin/env python3
"""Local source/interface gates only; no actual adoption or R8 freeze is run."""
import argparse
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types


def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--freezer-reference',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    sys.dont_write_bytecode=True
    H=load(args.source,'reviewed_r8_preparation_test');raw=args.freezer_reference.read_bytes()
    F=H.freezer_source(raw);checks=[]
    def check(name,call):
        call();checks.append({'name':name,'passed':True})
    def rejects(call):
        try:call()
        except (ValueError,FileNotFoundError):return
        raise AssertionError('expected a fail-closed rejection')
    def descriptor_shape():
        for row in ({'path':'/fixture/a','bytes':True,'sha256':'a'*64},
                    {'path':'relative','bytes':1,'sha256':'a'*64},
                    {'path':'/fixture/../a','bytes':1,'sha256':'a'*64},
                    {'path':'/fixture/a','bytes':1,'sha256':'a'*64,'extra':1}):
            rejects(lambda row=row:H.exact3(row))
    check('malformed_original_descriptors_rejected',descriptor_shape)
    check('source_drift_outside_finalization_rejected',lambda:rejects(
        lambda:H.freezer_source(raw.replace(b'PARENT_POLICY=',b'PARENT_POLICY_CHANGED=',1))))
    with tempfile.TemporaryDirectory(prefix='r8-source-gate-') as tmp:
        d=Path(tmp)
        p=d/'original';p.write_bytes(b'original')
        row=H.descriptor(p,p.read_bytes());o=H.Originals();assert o.read(row)==b'original'
        def changed():
            p.write_bytes(b'original')
            rejects(lambda:o.read(row))
        check('same_path_same_bytes_changed_metadata_rejected',changed)
        link=d/'alias';link.symlink_to(p)
        check('symlink_original_rejected',lambda:rejects(lambda:H.Originals().read({**row,'path':str(link)})))
        preview_out=d/'not-created'
        def preview():
            done=subprocess.run([sys.executable,'-I','-B',str(args.source),
                '--policy-adoption-desc','THIS IS DELIBERATELY NOT JSON',
                '--out',str(preview_out)],capture_output=True,check=True)
            result=json.loads(done.stdout)
            assert result['state']=='PREVIEW_NO_ORIGINAL_READ_NO_RUNTIME_FREEZE'
            assert done.stderr==b'' and not preview_out.exists()
        check('default_preview_does_not_read_parse_or_write_actual_inputs',preview)
    # This fixture exercises extraction and inverse properties only. It has no
    # actual proof or accepted policy, and never calls original build/main.
    parent={'schema':'SYNTHETIC_INTERFACE_FIXTURE_NOT_AN_ACTUAL_COMBINATION',
        'live_policy_sha256':F.PARENT_POLICY,'configuration':{'sha256':'b'*64},
        'untouched':['a','b']}
    parent_raw=F.enc(parent);parent_path=Path('/fixture/parent.json')
    FF=types.SimpleNamespace(enc=F.enc,OUT=Path('/fixture/runtime'),
        PARENT_POLICY=F.PARENT_POLICY,PARENT_COMBINATION=H.sha(parent_raw),
        FIXED={'parent_combination':(parent_path,len(parent_raw),H.sha(parent_raw))})
    template={'schema':'hepta.native-guard.property-r8-freeze-inputs.v1','out':str(FF.OUT),
        'finalization':None,'parent_combination':H.descriptor(parent_path,parent_raw)}
    template_raw=F.enc(template);actual_raw=b'UNQUALIFIED_LOCAL_POLICY_BYTE_FIXTURE'
    actual=H.descriptor('/fixture/actual-policy.bin',actual_raw)
    adoption={'schema':'hepta.runtime-properties-r10.policy-adoption.v1',
        'actual_export':actual,'root_scope_decision':{'path':'/fixture/scope','bytes':1,'sha256':'c'*64},
        'verification_originals':[dict(H.VERIFIER),{'path':'/fixture/applied',**H.APPLIED}],
        'root_decision':{'schema':'hepta.root.runtime-properties-policy-adoption-decision.v1',
            'decision':'ADOPT_INDEPENDENTLY_VERIFIED_ACTUAL_EXPORTED_POLICY',
            'actual_policy_sha256':actual['sha256']}}
    adoption_row=H.descriptor('/fixture/adoption.json',F.enc(adoption))
    frozen,input_raw,combo_raw=H.derive_inputs(FF,template_raw,adoption_row,adoption,actual_raw,parent_raw)
    def extracted():
        assert frozen['actual_export']==actual
        assert frozen['verifier_source']==H.VERIFIER
        assert frozen['combination_sha256']==H.sha(combo_raw)
        combo=json.loads(combo_raw);combo['live_policy_sha256']=F.PARENT_POLICY
        assert F.enc(combo)==parent_raw
        inputs=json.loads(input_raw);inputs['finalization']=None
        assert F.enc(inputs)==template_raw
    check('actual_export_drives_only_policy_and_finalization_fields',extracted)
    def inverse():
        derived=H.bind_source(F,raw,frozen)
        assert F.fill(derived,'FINALIZATION',frozen,None)==raw
        compile(derived,'source-only-derived-freezer','exec')
        nodes=ast.parse(derived).body
        slots=[n for n in nodes if isinstance(n,ast.Assign) and len(n.targets)==1
            and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='FINALIZATION']
        assert len(slots)==1 and ast.literal_eval(slots[0].value)==frozen
    check('single_rhs_whole_source_inverse_to_exact62bc',inverse)
    def missing_decision():
        bad=copy.deepcopy(adoption);bad['root_decision']=None
        rejects(lambda:H.derive_inputs(FF,template_raw,adoption_row,bad,actual_raw,parent_raw))
        bad=copy.deepcopy(adoption);bad['schema']='hepta.runtime-properties-r10.policy-adoption-inputs.v1'
        rejects(lambda:H.derive_inputs(FF,template_raw,adoption_row,bad,actual_raw,parent_raw))
    check('unadopted_or_preview_input_rejected',missing_decision)
    def source_identity_swap():
        bad=copy.deepcopy(adoption);bad['verification_originals'][0]={**H.VERIFIER,'sha256':H.APPLIED['sha256']}
        rejects(lambda:H.derive_inputs(FF,template_raw,adoption_row,bad,actual_raw,parent_raw))
        bad=copy.deepcopy(adoption);bad['verification_originals'].append({**H.VERIFIER,'path':'/fixture/duplicate-independent'})
        rejects(lambda:H.derive_inputs(FF,template_raw,adoption_row,bad,actual_raw,parent_raw))
    check('independent_and_actual_verifier_swap_rejected',source_identity_swap)
    def ordering():
        tree=ast.parse(args.source.read_bytes())
        main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
        calls=[n for n in ast.walk(main) if isinstance(n,ast.Call)]
        build=[n for n in calls if isinstance(n.func,ast.Attribute) and n.func.attr=='build']
        writes=[n for n in calls if isinstance(n.func,ast.Attribute) and n.func.attr=='mkdir']
        assert len(build)==1 and writes and build[0].lineno<min(n.lineno for n in writes)
        assert not any(isinstance(n.func,ast.Attribute) and n.func.attr=='main' for n in calls)
    check('original_full_build_precedes_every_package_write_and_main_never_called',ordering)
    args.out.mkdir(mode=0o700)
    result={'schema':'hepta.actual-r8-freeze-preparation.local-source-gates.v1',
        'state':'LOCAL_SOURCE_AND_INTERFACE_CHECKS_PASSED_NO_ACTUAL_ADOPTION_OR_FREEZE',
        'source':H.descriptor(args.source,args.source.read_bytes()),
        'freezer_reference':H.descriptor(args.freezer_reference,raw),'checks':checks,
        'original_build_calls':0,'actual_verifier_calls':0,'actual_adoptions':0,
        'runtime_freezes':0,'phone_calls':0,'remote_calls':0,'qualified_cases':0}
    body=H.encoded(result);(args.out/'TEST-RESULT.json').write_bytes(body)
    print(json.dumps({'checks':len(checks),'result':H.descriptor(args.out/'TEST-RESULT.json',body)},sort_keys=True))


if __name__=='__main__':main()
