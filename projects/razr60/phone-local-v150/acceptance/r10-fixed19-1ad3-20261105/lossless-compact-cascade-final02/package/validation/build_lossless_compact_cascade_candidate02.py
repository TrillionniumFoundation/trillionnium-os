#!/usr/bin/env python3
"""Local source derivation only. No generator, preparer, remote or phone main."""
import ast
import base64
import copy
import difflib
import hashlib
import json
from pathlib import Path
import sys
import types
import zlib

sys.dont_write_bytecode = True
W = Path('/workspace/scratch/1ad3d6f55439')
B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
EXTERNAL = B/'property-r8-lossless-bundle-generators-candidate01'
STAGE = B/'property-r8-lossless-compact-generators-1ad3-candidate02'
OUT = W/'property_diagnostic/lossless_compact_cascade_candidate02/package'
OLD_C = 'a4341c41c26c4327c6d5a8c6ba9ec86f59e4e220b8d84e80e35b443fcd11096f'
OLD_I = '8d8f75698296cecd9dcc6e302bbfa1546e47401bde74235872c7192da73615bb'
OLD_H = '72c36078084821e22f2707e081a9eee81f90e99ce69d97768987eb5f23a62195'
TMF = {'path':str(EXTERNAL/'SOURCE-MANIFEST.json'),'bytes':24857,
    'sha256':'81663c38554d20335928c4de2980036aa090babef33ab8d1a070efbbface3e54'}


def sha(raw): return hashlib.sha256(raw).hexdigest()
def enc(value): return (json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def row(path,raw): return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}


def read(name,size,digest):
    raw=(W/name).read_bytes()
    assert len(raw)==size and sha(raw)==digest,name
    return raw


def change(raw,pairs):
    result=raw
    for old,new in pairs:
        assert result.count(old)==1,(old,result.count(old))
        result=result.replace(old,new,1)
    reverse=result
    for old,new in reversed(pairs):
        assert reverse.count(new)==1,(new,reverse.count(new))
        reverse=reverse.replace(new,old,1)
    assert reverse==raw
    compile(result,'<derived source only>','exec')
    return result


def module(raw,path,name):
    value=types.ModuleType(name);value.__file__=str(path)
    exec(compile(raw,str(path),'exec'),value.__dict__)
    return value


def patch(old,new,label):
    return ''.join(difflib.unified_diff(old.decode().splitlines(True),new.decode().splitlines(True),
        fromfile='retained-parent/'+label,tofile='candidate/'+label)).encode()


def must_reject(call):
    try:call()
    except (ValueError,TypeError,zlib.error):return
    raise AssertionError('required rejection absent')


def main():
    assert not OUT.exists(),'new candidate directory required'
    c0=read('lossless_bundle_source_cache/source/derive_final_cascade_property_r8.py',56190,OLD_C)
    i0=read('cascade_source_cache/source/write_final_seal_interface_property_r8.py',33096,OLD_I)
    h0=read('property_diagnostic/prepare_final_cascade.py',9712,OLD_H)
    mfraw=read('lossless_bundle_source_cache/SOURCE-MANIFEST.json',TMF['bytes'],TMF['sha256'])
    consumer=read('lossless_bundle_source_cache/templates/release_boundaries.py',77700,
        '619589ce59c209d491f1994d67008327604ce07894d101a278c3ebc06052a5f1')
    ctor=read('lossless_bundle_source_cache/templates/make_component_boundary_inputs.py',34626,
        'ed12bbeb717c19a4608ee402fa45b575a78ecbd664cb24eef1bf29bbe331f5fc')
    parent=read('r8_freeze_preparation_candidate01/actual_parent/COMBINATION.original.json',4702,
        'ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837')
    adoption=read('independent_post_execution/POLICY-ADOPTION.original.json',208226,
        '527374778e62717d837d546cfa56bd144c8415b52006a9be4a33935c8592d08a')
    ce=b"def encode(value):\n    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,\n                       allow_nan=False)+'\\n').encode()\n"
    ie=b"def encode(value): return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\\n').encode()\n"
    added=b"\ndef combination_encode(value):\n    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\\n').encode()\n"
    cpairs=[(ce,ce+added),
        (b'encode(parent_combo) == parent_raw',b'combination_encode(parent_combo) == parent_raw'),
        (b'encode(combo) == combo_raw',b'combination_encode(combo) == combo_raw'),
        (b'encode(reversed_combo) == parent_raw',b'combination_encode(reversed_combo) == parent_raw')]
    ipairs=[(ie,ie+added),
        (b'encode(strict(parent_combo_raw))==parent_combo_raw',b'combination_encode(strict(parent_combo_raw))==parent_combo_raw'),
        (b'encode(combination)==coraw',b'combination_encode(combination)==coraw'),
        (b'encode(reversed_combo)==parent_combo_raw',b'combination_encode(reversed_combo)==parent_combo_raw')]
    c1=change(c0,cpairs);i1=change(i0,ipairs)
    cdesc=row(STAGE/'source/derive_final_cascade_property_r8.py',c1)
    idesc=row(STAGE/'source/write_final_seal_interface_property_r8.py',i1)
    C=module(c1,cdesc['path'],'source_only_compact_cascade')
    I=module(i1,idesc['path'],'source_only_compact_interface')
    assert C.FINALIZATION is None and I.DELIVERY is None and I.OUT is None
    for before,after in [(c0,c1),(i0,i1)]:
        old,new=ast.parse(before),ast.parse(after)
        new.body=[n for n in new.body if not(isinstance(n,ast.FunctionDef) and n.name=='combination_encode')]
        seen=0
        for n in ast.walk(new):
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='combination_encode':
                seen+=1;n.func.id='encode'
        assert seen==3 and ast.dump(old,include_attributes=False)==ast.dump(new,include_attributes=False)
    pv=C.strict(parent);combo=copy.deepcopy(pv)
    combo['live_policy_sha256']=json.loads(adoption)['actual_export']['sha256']
    combo_raw=C.combination_encode(combo)
    assert C.encode(pv)!=parent and len(C.encode(pv))==5832
    assert I.encode(pv)!=parent and C.encode(pv)==I.encode(pv)
    assert C.combination_encode(pv)==I.combination_encode(pv)==parent
    assert I.combination_encode(combo)==combo_raw and sha(combo_raw)=='54b1d9aef4c16ebc0989b3e13345238bfbd4e400e5bfc9a97e27648a2385057e'
    reverse=copy.deepcopy(combo);reverse['live_policy_sha256']=pv['live_policy_sha256']
    assert C.combination_encode(reverse)==I.combination_encode(reverse)==parent
    # Source identity fixes only; no actual adoption or complete cascade gate is run.
    gm={'schema':'hepta.property-r8.lossless-compact-generators.source-package.v1',
        'state':'SOURCE_ONLY_FINALIZATION_AND_DELIVERY_UNFILLED',
        'files':[{'path':'source/derive_final_cascade_property_r8.py','bytes':len(c1),'sha256':sha(c1)},
                 {'path':'source/write_final_seal_interface_property_r8.py','bytes':len(i1),'sha256':sha(i1)}],
        'template_source_manifest':TMF,
        'parent_sources':[
            {'path':str(EXTERNAL/'source/derive_final_cascade_property_r8.py'),'bytes':len(c0),'sha256':sha(c0)},
            {'path':str(EXTERNAL/'source/write_final_seal_interface_property_r8.py'),'bytes':len(i0),'sha256':sha(i0)}],
        'change':'Each source adds one dedicated compact combination encoder and changes exactly three combination call sites.',
        'generic_encoders_unchanged':True,'all_other_ast_nodes_unchanged':True,
        'caps_unchanged':True,'actual_generator_mains':0,'phone_calls':0,'new_nonces':0}
    gmraw=enc(gm);gmdesc=row(STAGE/'GENERATOR-SOURCE-MANIFEST.json',gmraw)
    new_header=("PARENT = B/'property-r8-lossless-bundle-generators-candidate01'\n"
        "SOURCE = "+repr(cdesc)+"\nINTERFACE = "+repr(idesc)+"\n"
        "GENERATOR_MANIFEST = "+repr(gmdesc)+"\nTEMPLATE_MANIFEST = "+repr(TMF)+"\n")
    start=h0.index(b"PARENT = B/");end=h0.index(b'META = ',start)
    old_header=h0[start:end]
    validation=b'''def validate_source_manifests(originals, template_module):
    generators = strict(originals.read(GENERATOR_MANIFEST))
    templates = strict(originals.read(TEMPLATE_MANIFEST))
    need(generators['schema']=='hepta.property-r8.lossless-compact-generators.source-package.v1'
         and generators['state']=='SOURCE_ONLY_FINALIZATION_AND_DELIVERY_UNFILLED'
         and generators['template_source_manifest']==TEMPLATE_MANIFEST,
         'exact compact generator lineage differs')
    expected_sources = [dict(path='source/derive_final_cascade_property_r8.py',
                             **{k:SOURCE[k] for k in ('bytes','sha256')}),
                        dict(path='source/write_final_seal_interface_property_r8.py',
                             **{k:INTERFACE[k] for k in ('bytes','sha256')})]
    need(generators['files']==expected_sources, 'exact two compact generator sources required')
    need(templates['schema']=='hepta.r8.lossless-bundle-generator-source-package.v1'
         and templates['state']=='SOURCE_ONLY_FUTURE_FINALIZATION_NONE',
         'exact lossless template package required')
    rows = templates['files']
    need(type(rows) is list and all(type(r) is dict and set(r)=={'path','bytes','sha256'} for r in rows)
         and len(rows)==len({r['path'] for r in rows}), 'unique exact template package inventory required')
    expected_templates = {('templates/'+name):dict(path='templates/'+name,**pin)
                          for name,pin in template_module.TEMPLATE_PINS.items()}
    observed_templates = {r['path']:r for r in rows if r['path'].startswith('templates/')}
    need(len(expected_templates)==19 and observed_templates==expected_templates,
         'all nineteen pinned lossless templates must match the actual package manifest')


'''
    hpairs=[(old_header,new_header.encode()),
        (b'def main():\n',validation+b'def main():\n'),
        (b"    template_module = module(SOURCE, source_raw, 'reviewed_final_cascade_template')\n",
         b"    template_module = module(SOURCE, source_raw, 'reviewed_final_cascade_template')\n    validate_source_manifests(originals, template_module)\n")]
    h1=change(h0,hpairs)
    H=module(h1,STAGE/'preparer/prepare_final_cascade.py','source_only_lossless_compact_preparer')
    assert H.SOURCE==cdesc and H.INTERFACE==idesc and H.GENERATOR_MANIFEST==gmdesc and H.TEMPLATE_MANIFEST==TMF
    class OriginalBytes:
        def __init__(self,a,b):self.bodies={gmdesc['path']:a,TMF['path']:b}
        def read(self,r):
            body=self.bodies[r['path']];assert row(r['path'],body)==r;return body
    H.validate_source_manifests(OriginalBytes(gmraw,mfraw),C)
    assert len(C.TEMPLATE_PINS)==19 and C.TEMPLATE_PINS['release_boundaries.py']=={'bytes':77700,'sha256':sha(consumer)}
    assert C.TEMPLATE_PINS['make_component_boundary_inputs.py']=={'bytes':34626,'sha256':sha(ctor)}
    # All existing actual R8/adoption/finalization gates remain byte-identical.
    block=h0[h0.index(b'    adoption_row, verifier_row = '):h0.index(b'    before = ',h0.index(b'    adoption_row, verifier_row = '))]
    assert h1.count(block)==1
    finalization_ast=next(n for n in ast.walk(ast.parse(h1)) if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name) and t.id=='frozen' for t in n.targets))
    assert isinstance(finalization_ast.value,ast.Dict) and len(finalization_ast.value.keys)==8
    # Pure codec checks. No valid complete bundle, model or policy verifier is run.
    L=module(consumer,EXTERNAL/'templates/release_boundaries.py','source_only_lossless_codec')
    fixtures=[b'',b'abc\x00\xff',parent,adoption,bytes(range(256))*16]
    for body in fixtures:
        descriptor={'path':'/pure-codec-fixture/original','bytes':len(body),'sha256':sha(body)}
        item=L.pack_original(body)
        assert L.original_from({'originals':{sha(body):item}},descriptor)==body
    body=b'A'*4096;descriptor={'path':'/pure-codec-fixture/original','bytes':len(body),'sha256':sha(body)}
    item=L.pack_original(body);assert 'zlib_b64' in item
    def tryitem(x,desc=descriptor):return L.original_from({'originals':{desc['sha256']:x}},desc)
    for bad in [dict(item,raw_b64=''),dict(item,bytes=True),dict(item,bytes=4095),
        {'bytes':4096,'zlib_b64':'!'}, {'bytes':4096,'zlib_b64':base64.b64encode(zlib.compress(body)+b'x').decode()},
        {'bytes':4096,'zlib_b64':base64.b64encode(zlib.compress(body)+zlib.compress(body)).decode()},
        {'bytes':4096,'zlib_b64':base64.b64encode(zlib.compress(body)[:-1]).decode()},
        {'bytes':4096,'zlib_b64':base64.b64encode(zlib.compress(body+b'B')).decode()}]:
        must_reject(lambda bad=bad:tryitem(bad))
    must_reject(lambda:tryitem(item,{**descriptor,'bytes':L.MAX_ORIGINAL+1}))
    must_reject(lambda:tryitem(item,{**descriptor,'sha256':'0'*64}))
    assert L.MAX_ORIGINAL==16*1024*1024 and L.MAX_BUNDLE==32*1024*1024 and L.PACKAGE_FILE_COUNT==32
    old_consumer=read('cascade_source_cache/templates/release_boundaries.py',76433,
        'c844b4924397ffcdd30500c395395ade0bd0ad3eaa746f0a007c1b8ae274b0d6')
    old_t,new_t=ast.parse(old_consumer),ast.parse(consumer)
    for name in ['read_pinned','file_descriptor','meta','validate_component','validate_policy','input_value','current_preservation']:
        old_fn=next(n for n in old_t.body if isinstance(n,ast.FunctionDef) and n.name==name)
        new_fn=next(n for n in new_t.body if isinstance(n,ast.FunctionDef) and n.name==name)
        assert ast.dump(old_fn,include_attributes=False)==ast.dump(new_fn,include_attributes=False),name
    report={'schema':'hepta.property-r8.lossless-compact-local-review.v1',
        'state':'NARROW_SOURCE_AND_PURE_CODEC_CHECKS_PASSED_NO_ACTUAL_CASCADE',
        'retained_external_manifest':TMF,'new_generator_manifest':gmdesc,
        'new_cascade':cdesc,'new_interface':idesc,
        'new_preparer':row(STAGE/'preparer/prepare_final_cascade.py',h1),
        'parent_encoding_rejection':{'actual_bytes':4702,'actual_sha256':sha(parent),
            'old_pretty_bytes':5832,'old_pretty_sha256':sha(C.encode(pv)),
            'actual_source_functions_run':['encode'],'actual_adoption_check_run':False},
        'compact_combination_check':{'bytes':len(combo_raw),'sha256':sha(combo_raw),
            'only_field_changed':'live_policy_sha256','inverse_exact_original_parent':True},
        'generator_change':{'cascade_calls':3,'interface_calls':3,'new_encoders':2,
            'other_ast_nodes_unchanged':True,'whole_source_inverses_exact':True},
        'preparer_change':{'source_manifest_validation_added':True,'exact_template_count':19,
            'actual_r8_and_adoption_gate_bytes_unchanged':True,'finalization_exact_field_count':8,
            'whole_source_inverse_to_72c3':True},
        'codec_review':{'roundtrip_fixtures':len(fixtures),'malformed_rejections':10,
            'per_original_raw_byte_cap':L.MAX_ORIGINAL,'decompress_output_limit':'declared raw bytes + 1',
            'single_complete_zlib_stream_required':True,'unused_data_or_unconsumed_tail_rejected':True,
            'decoded_raw_length_and_sha256_verified':True,'base64_canonical_required':True,
            'full9_read_identity_and_recheck_unchanged':True,'full_component_and_adoption_validation_unchanged':True,
            'serialized_bundle_byte_cap':L.MAX_BUNDLE,'aggregate_decoded_byte_cap_added':False,
            'budget_meaning':'32 MiB remains the serialized bundle admission cap; individual decoded originals remain at most16 MiB. Full actual union and serialized size must still be measured and validated.'},
        'actual_bundle_fit_claimed':False,'actual_union_checked':False,'main_calls':0,
        'actual_verify_adoption_calls':0,'phone_calls':0,'remote_process_starts':0,
        'new_nonces':0,'runtime_freezes':0,'qualified_cases':0}
    files={
        'source/derive_final_cascade_property_r8.py':c1,
        'source/write_final_seal_interface_property_r8.py':i1,
        'GENERATOR-SOURCE-MANIFEST.json':gmraw,
        'preparer/prepare_final_cascade.py':h1,
        'reference/derive_final_cascade_property_r8.a434.original.py':c0,
        'reference/write_final_seal_interface_property_r8.8d8f.original.py':i0,
        'reference/prepare_final_cascade.72c3.original.py':h0,
        'reference/LOSSLESS-SOURCE-MANIFEST.81663.original.json':mfraw,
        'reference/COMBINATION.ba5c.original.json':parent,
        'validation/CASCADE-COMPACT-INCREMENT.patch':patch(c0,c1,'derive_final_cascade_property_r8.py'),
        'validation/INTERFACE-COMPACT-INCREMENT.patch':patch(i0,i1,'write_final_seal_interface_property_r8.py'),
        'validation/PREPARER-INCREMENT.patch':patch(h0,h1,'prepare_final_cascade.py'),
        'validation/REVIEW.json':enc(report),
        'validation/EXACT-REPLACEMENTS.json':enc({k:[{'before':a.decode(),'after':b.decode()} for a,b in pairs]
            for k,pairs in [('cascade',cpairs),('interface',ipairs),('preparer',hpairs)]}),
        'validation/build_lossless_compact_cascade_candidate02.py':Path(__file__).read_bytes(),
        'INTERFACE.json':enc({'schema':'hepta.property-r8.lossless-compact-preparation-interface.v1',
            'staging_directory':str(STAGE),'source_template_package_manifest':TMF,
            'generator_manifest':gmdesc,'actual_runtime_binding_source':'Caller supplied actual completed R8 FREEZE-RESULT, never an unpublished predicted Root manifest.',
            'prepare_argv_template':['/usr/bin/python3','-I','-B',str(STAGE/'preparer/prepare_final_cascade.py'),
                '--runtime-freeze-result-desc','<actual complete R8 FREEZE-RESULT exact3>',
                '--out','<fresh host cascade source output>','--execute-host-preparation'],
            'next_action':'Only the actual generated EXECUTION-ENTRY may be invoked by Root afterward.',
            'default_is_read_only_actual_preflight':True,'auto_execute_cascade':False,
            'future_finalization_values_written':False,'actual_bundle_fit_claimed':False}),
    }
    manifest={'schema':'hepta.property-r8.lossless-compact-source-delivery.v1',
        'state':report['state'],'staging_directory':str(STAGE),
        'files':[{'path':name,'bytes':len(raw),'sha256':sha(raw)} for name,raw in sorted(files.items())],
        'preparer':report['new_preparer'],'generator_manifest':gmdesc,
        'template_manifest':TMF,'old_sources_and_namespace_retained':True,
        'source_only':True,'actual_bundle_fit_claimed':False,'main_calls':0,'phone_calls':0,'new_nonces':0}
    files['SOURCE-MANIFEST.json']=enc(manifest)
    OUT.mkdir(mode=0o700,parents=True)
    for name,raw in sorted(files.items()):
        p=OUT/name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        with p.open('xb') as f:f.write(raw)
        assert p.read_bytes()==raw
    delivery={'package':str(OUT),'staging_directory':str(STAGE),
        'manifest':row(STAGE/'SOURCE-MANIFEST.json',files['SOURCE-MANIFEST.json']),
        'files':[{'path':name,'bytes':len(raw),'sha256':sha(raw)} for name,raw in sorted(files.items())],
        'preparer':report['new_preparer'],'cascade':cdesc,'interface':idesc,
        'source_only':True,'actual_bundle_fit_claimed':False,'phone_calls':0,'new_nonces':0}
    with (OUT.parent/'DELIVERY.json').open('xb') as f:f.write(enc(delivery))
    print(enc({k:delivery[k] for k in ['package','staging_directory','manifest','preparer','cascade','interface']}).decode(),end='')


if __name__=='__main__':main()
