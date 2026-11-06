#!/usr/bin/env python3
"""Assemble a source candidate from exact R4 bytes and reviewed deltas only."""
from pathlib import Path
import ast, copy, gzip, hashlib, json, sys, types, base64
sys.dont_write_bytecode=True
B=Path(__file__).resolve().parent
OLD=B/'R4'; NEW=B/'R5-root'; LATE=B/'R5-agent-late'
FROZEN='/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-fc33-native-v3-r5'
REVISION='r10-r1-fc33-native-bound-v3-r5'

def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def enc(v):return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def put(p,b):p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b);assert p.read_bytes()==b
def main():
    transfer=json.loads((B/'shared-v3-original-transfer.json').read_bytes())
    originals={Path(r['path']).name:r for r in transfer}
    material=json.loads(originals['DERIVATION.json']['text'])
    assert pin(originals['DERIVATION.json']['text'].encode())=={'bytes':19087,'sha256':'adaba62c40a49d61f0f809ad5f389ca52d900ec4b6415de829a5f9a708a738e3'}
    for row in transfer:assert pin(row['text'].encode())=={k:row[k] for k in ('bytes','sha256')}
    for rel in ['runtime/source/late_boundary.py','runtime/reference/source_parent_late_boundary_r4.py']:
        put(NEW/rel,(LATE/rel).read_bytes())
    assert pin((NEW/'runtime/reference/source_parent_late_boundary_r4.py').read_bytes())==pin((OLD/'runtime/source/late_boundary.py').read_bytes())
    rp='runtime/reference/REVIEWED-PRODUCTION-PINS.json'
    oldraw=(OLD/rp).read_bytes();oldpins=json.loads(oldraw)
    newpins={Path(r['path']).name:r['sha256'] for r in material['files'] if r['path'].startswith('shared/provider/source/')}
    assert set(oldpins)==set(newpins) and len(newpins)==15
    raw=oldraw
    changed=[]
    for name in sorted(oldpins):
        if oldpins[name]!=newpins[name]:
            assert raw.count(oldpins[name].encode())==1
            raw=raw.replace(oldpins[name].encode(),newpins[name].encode(),1);changed.append(name)
    assert changed==material['changed_sources'] and json.loads(raw)==newpins
    inverse=raw
    for name in changed:inverse=inverse.replace(newpins[name].encode(),oldpins[name].encode(),1)
    assert inverse==oldraw
    put(NEW/rp,raw)
    sources={str(p.relative_to(NEW/'runtime')):p.read_bytes() for p in sorted((NEW/'runtime').rglob('*')) if p.is_file() and p.name!='MANIFEST.json'}
    assert len(sources)==38
    saved=sys.modules.get('component_common');oldpath=sys.path[:]
    try:
        common=types.ModuleType('component_common');common.__file__=str(NEW/'runtime/source/component_common.py')
        sys.modules['component_common']=common;exec(compile(sources['source/component_common.py'],common.__file__,'exec'),common.__dict__)
        late=types.ModuleType('fc33_r5_late');late.__file__=str(NEW/'runtime/source/late_boundary.py')
        late.__reviewed_package_sources__=sources;late.__reviewed_source_sha256__=pin(sources['source/late_boundary.py'])['sha256']
        exec(compile(sources['source/late_boundary.py'],late.__file__,'exec'),late.__dict__)
        fields=late.manifest_source_parent_binding()
        assert fields==json.loads((LATE/'MANIFEST-SOURCE-PARENT-FIELDS.json').read_bytes())
        assert (late.SOURCE_PARENT_COUNT,late.MAX_CHAIN,late.COMPONENT_ROLE_CAP,late.MAX_FIXTURE_ROOTS,late.SOURCE_PARENT_INVENTORY_ROOT_COUNT,late.MAX_CURRENT_INVENTORY_ROOTS)==(1,12,42,14,44,50)
        manifest=json.loads((OLD/'runtime/MANIFEST.json').read_bytes())
        old_provenance=manifest['current_source_increment_provenance']
        delta=pin((NEW/'RUNTIME-ROOT-DELTA.json').read_bytes())
        new_provenance={'schema':'hepta.fc33.native-bound.source-propagation.v1',
            'reviewed_shared_derivation':pin(originals['DERIVATION.json']['text'].encode()),
            'runtime_source_delta':delta,'source_parent_late':pin(sources['source/late_boundary.py']),
            'previous_source_increment_provenance':old_provenance,
            'same_policy_and_adoption':True,'new_tuple_qualification':False}
        manifest.update(fields)
        manifest.update(revision=REVISION,current_combination_sha256=material['combination']['sha256'],
            current_mapper_source_sha256=newpins['phone_observation_tools.py'],
            reviewed_production_pins_sha256=pin(raw)['sha256'],
            current37_reader_is_explicit_not_historical_C32_mutation=False,
            current38_reader_is_explicit_not_historical_C32_mutation=True,
            mapper_change_is_exact_helper_selection_only=False,
            current_native_request_configuration_observation_binding=True,
            immediate_source_parent_package_sha256=pin((OLD/'runtime/MANIFEST.json').read_bytes())['sha256'],
            current_source_increment_provenance=new_provenance)
        manifest['files']=[{'path':name,**pin(body)} for name,body in sorted(sources.items())]
        late.validate_current_package_manifest(manifest)
        manifest_raw=enc(manifest);put(NEW/'runtime/MANIFEST.json',manifest_raw)
    finally:
        sys.path[:]=oldpath
        if saved is None:sys.modules.pop('component_common',None)
        else:sys.modules['component_common']=saved
    package=pin(manifest_raw)
    root_changes=[]
    for name in ['run_component_root_once.py','phone_chain_bridge.py']:
        p=NEW/'root-chain/source'/name;template=p.read_bytes()
        assert template.count(b'PKG = None')==1,(name,'run driver derivation before assembly')
        bound=template.replace(b'PKG = None',('PKG = '+repr(package['sha256'])).encode(),1)
        assert bound.replace(('PKG = '+repr(package['sha256'])).encode(),b'PKG = None',1)==template
        ast.parse(bound);put(p,bound);root_changes.append({'path':'source/'+name,'template':pin(template),'bound':pin(bound),'exact_slot_inverse':True})
    root=json.loads((OLD/'root-chain/SOURCE-MANIFEST.json').read_bytes())
    root.update(fields)
    root.update(revision=REVISION,current_combination_sha256=material['combination']['sha256'],
        frozen_component_package_sha256=package['sha256'],fixed_shared_material_root=FROZEN+'/shared',
        shared_materials_sha256=material['shared_manifest']['sha256'],
        current_source_increment_provenance=new_provenance,
        immediate_source_parent_package_sha256=pin((OLD/'root-chain/SOURCE-MANIFEST.json').read_bytes())['sha256'])
    root['files']=[{'path':r['path'],**pin((NEW/'root-chain'/r['path']).read_bytes())} for r in root['files']]
    assert len(root['files'])==3
    root_raw=enc(root);put(NEW/'root-chain/SOURCE-MANIFEST.json',root_raw)
    files={}
    for family in ['runtime','root-chain']:
        manifest_name='MANIFEST.json' if family=='runtime' else 'SOURCE-MANIFEST.json'
        paths=[family+'/'+r['path'] for r in json.loads((NEW/family/manifest_name).read_bytes())['files']]+[family+'/'+manifest_name]
        for name in paths:
            body=(NEW/name).read_bytes();old=OLD/name
            if not old.exists() or body!=old.read_bytes():files[name]=body
    proof={'schema':'hepta.fc33.runtime-source-assembly.v1','state':'SOURCE_CANDIDATE_NO_PHONE_QUALIFICATION',
        'runtime_manifest':package,'root_manifest':pin(root_raw),'root_package_constant_binding':root_changes,
        'material_derivation':pin(originals['DERIVATION.json']['text'].encode()),
        'changed_production_pin_names':changed,'production_pin_whole_byte_inverse':True,
        'runtime_member_count':38,'root_member_count':3,'source_parent_count':1,
        'native_chain_cap':12,'component_role_cap':42,'fixture_root_cap':14,'baseline_roots':44,'maximum_roots':50,
        'phone_calls':0,'new_nonces':0,'all_python_compiled':False,
        'files':[{ 'path':n,**pin(b)} for n,b in sorted(files.items())]}
    for n,b in files.items():
        if n.endswith('.py'):ast.parse(b,filename=n)
    proof['all_python_compiled']=True
    proofraw=enc(proof);put(NEW/'ASSEMBLY.json',proofraw)
    bundle={'schema':'hepta.fc33.reviewed-runtime-delta-bundle.v1','assembly':proof,
        'files':[{'path':n,**pin(b),'base64':base64.b64encode(b).decode()} for n,b in sorted(files.items())]}
    bundle_raw=gzip.compress(enc(bundle),mtime=0);put(NEW/'RUNTIME-DELTA.json.gz',bundle_raw)
    print(json.dumps({'assembly':pin(proofraw),'runtime_manifest':package,'root_manifest':pin(root_raw),'delta_files':len(files),'bundle':pin(bundle_raw),'phone_calls':0}))

if __name__=='__main__':main()
