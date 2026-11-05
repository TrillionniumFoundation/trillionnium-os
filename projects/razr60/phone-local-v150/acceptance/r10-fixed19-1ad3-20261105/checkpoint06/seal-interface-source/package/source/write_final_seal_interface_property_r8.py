#!/usr/bin/env python3
"""Prepare only a host interface for FC8/C8 after actual R8 source finalization.

Default is a zero-I/O preview. It never invokes the constructor, builder, suite,
phone or policy tools. Empty current cases make its plan template unexecutable.
"""
import argparse
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

sys.dont_write_bytecode = True
B=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
DELIVERY={'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/r10-boundary-consumers-final-r8-inventory-prefix-1ad3-01/DELIVERY-RESULT.json', 'bytes': 28755, 'sha256': '4683e907b33377d657bb0f4b7c2cd772b6d84881ab09ad66e77a6445f36ed714'}
FC=B/'r10-boundary-consumers-final-r8-inventory-prefix-1ad3-01'
C=B/'r10-component-boundary-input-entry-r8-inventory-prefix-1ad3-01'
RUNTIME_PARENT=B/'native-guard-r10-r1-operator-r7/runtime'
OLD_RUNTIME=B/'native-guard-r10-r1-operator-r4/runtime'
E=B/'native-guard-attempt03-external-publication-r1/actual-02'
F04=B/'native-guard-root-chains-r10-r1/root-r10-neg01-20261104-04'
F06=B/'native-guard-root-chains-r10-r1/root-r10-neg01-20261105-06'
ENVIRONMENT_PARENT_BOUNDARY_SHA='eca628a18327146b7710a478fc2c2f716f79d55907b2821666828a0795e2060f'
RET=B/'module-r10-r1-retirement-reconciliation-01'
S=B/'r10-boundary-consumers-material-r1/actual-material-01/SHARED-MATERIALS.json'
OUT=B/'property-policy-final-seal-interface-r8-r1-inventory-prefix-1ad3-01'
PRE_POLICY_BOUNDARY_SHA='3216ab18adcafa0dda95e8a93ad35a2070e7aec286d7a518794918068ce31d12'
EXTERNAL_BOUNDARY_SHA='ee008c3b2adec701be4c0bdfd38ca7ac0d650da9b7783f51d3fe4638bfdc5b58'
F08=B/'native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08'
F07=B/'native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07'
PROPERTY_PARENT_BOUNDARY_SHAS=['eca941303197228ebe03561e612bfe41eb0518c590ff21253444db25a11adc10',
    '46b03cd66426395198b4a3093117659d5cfb128cc981815934fc1ea695c97be0']
POLICY_PARENT_SHA='50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'
PARENT_ADOPTION_SHA='a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5'
POLICY_PARENT_COMBINATION_SHA='ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837'
SEEN={}


def need(ok, reason):
    if not ok: raise ValueError(reason)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def encode(value): return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()

def combination_encode(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()


def meta(info): return tuple(getattr(info,x) for x in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def read(path, size, digest):
    path=Path(path)
    need(path.is_absolute() and path.resolve(strict=True)==path, 'canonical input required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==size and 0<=size<=16*1024*1024,'input metadata differs')
        with os.fdopen(fd,'rb',closefd=False) as stream: raw=stream.read(size+1)
        need(len(raw)==size and sha(raw)==digest and meta(before)==meta(os.fstat(fd))==meta(path.lstat()),'input original differs')
    finally: os.close(fd)
    entry=dict(path=str(path),bytes=size,sha256=digest)
    need(str(path) not in SEEN or SEEN[str(path)]==(entry,meta(before)),'input changed between reads')
    SEEN[str(path)]=(entry,meta(before))
    return entry,raw


def flags(raw):
    tree=ast.parse(raw)
    return {a.value for n in ast.walk(tree) if isinstance(n,ast.Call)
            and isinstance(n.func,ast.Attribute) and n.func.attr=='add_argument'
            for a in n.args if isinstance(a,ast.Constant) and isinstance(a.value,str)
            and a.value.startswith('--')}


def sync(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def put(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    sync(path.parent)
    need(path.read_bytes()==raw and path.lstat().st_nlink==1,'output readback differs')
    return dict(path=str(path),bytes=len(raw),sha256=sha(raw))


def strict(raw):
    def pairs(rows):
        value = {}
        for key,item in rows:
            need(key not in value, 'duplicate original JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _:need(False, 'nonfinite original JSON'))


def original(row):
    need(isinstance(row, dict) and set(row) == {'path','bytes','sha256'}
         and type(row['bytes']) is int
         and (0 < row['bytes'] <= 16*1024*1024 or row in (
             {'path':str(F06/'phone-late-publish/stderr.original'), 'bytes':0,
              'sha256':'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
             {'path':str(F08/'phone-late-publish/stderr.original'), 'bytes':0,
              'sha256':'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
             {'path':str(F07/'phone-late-publish/stderr.original'), 'bytes':0,
              'sha256':'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}))
         and isinstance(row['sha256'], str) and re.fullmatch('[0-9a-f]{64}',row['sha256']),
         'explicit positive original or one of the exact actual06/08/07 empty publication stderr originals required')
    return read(row['path'],row['bytes'],row['sha256'])


RUNTIME_SOURCE_INCREMENT = {'base_freeze_result': {'bytes': 22392,
                        'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8/FREEZE-RESULT.json',
                        'sha256': 'f1e9f063468d1bfdbed0f1e877afb70acafcddf78bbc872dc4078d472afddc67'},
 'base_freezer_source': {'bytes': 36899,
                         'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-property-r8-freeze-final01/source/freeze_property_runtime.py',
                         'sha256': '70e0ccc9844438aeee54ba4e734e886c81c2e640f92a997a766015e7bb5b285d'},
 'base_runtime_manifest': {'bytes': 16808,
                           'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8/runtime/MANIFEST.json',
                           'sha256': '67dc40470b8ecb1e10cb57f8953a3d0b6db309b45079216eb24cd65f0760107c'},
 'changed_member': {'parent': {'bytes': 66996,
                               'sha256': 'c50a219efd992ce1353494ace2656af20c932cbc32530b0085e38a79975d8add'},
                    'path': 'source/late_boundary.py',
                    'successor': {'bytes': 67005,
                                  'sha256': '147cf49e91fb4bcbddeba6591d48c8782efe20452db2b2d6179e7addd68c27e4'}},
 'inherited_metadata_scope': 'original_r7_to_r8_generation_preserved_not_successor_actions',
 'runtime_member_count': 32,
 'schema': 'hepta.native-guard.runtime-source-increment.v1',
 'state': 'EXACT_RUNTIME32_SINGLE_EXPRESSION_SUCCESSOR_SOURCE_ONLY',
 'successor_actions': {'historical_reference_changes': 0,
                       'host_source_derivation': True,
                       'new_nonces': 0,
                       'phone_operations': 0,
                       'policy_adoptions_created': 0,
                       'policy_applications': 0},
 'transformation': {'accepted_path_domain': 'canonical_absolute_posix_without_dotdot',
                    'function': 'inventory_value',
                    'new_utf8': 'sum(p.parts[:len(q.parts)] == q.parts for q in paths) == 1',
                    'old_utf8': 'sum(p == q or q in p.parents for q in paths) == 1',
                    'whole_source_inverse_required': True},
 'unchanged_member_count': 31}


def verify_runtime_source_increment(manifest_raw, source_files):
    """Pure exact32/source-and-manifest inverse; never opens or executes a file.

    Dependencies are only this module's fixed RUNTIME_SOURCE_INCREMENT object
    and the standard json/hashlib modules. All parsing/encoding helpers are
    local to prevent caller strict/encode implementations changing semantics.
    The caller still performs its original proof, filesystem and case gates.
    """
    def require(value, reason):
        if not value:
            raise ValueError('runtime source increment: ' + reason)

    def digest(raw):
        return hashlib.sha256(raw).hexdigest()

    def encode(value):
        return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                           allow_nan=False) + '\n').encode('utf-8')

    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result

    def nonfinite(_value):
        raise ValueError('runtime source increment: nonfinite JSON')

    require(type(manifest_raw) is bytes and 0 < len(manifest_raw) <= 65536,
            'bounded exact manifest bytes required')
    manifest = json.loads(manifest_raw, object_pairs_hook=pairs, parse_constant=nonfinite)
    require(type(manifest) is dict and encode(manifest) == manifest_raw,
            'original manifest encoding differs')
    require(type(manifest.get('runtime_source_increment')) is dict
            and encode(manifest['runtime_source_increment']) == encode(RUNTIME_SOURCE_INCREMENT),
            'one exact-typed fixed reviewed runtime increment required')
    require(type(source_files) is dict and type(manifest.get('files')) is list
            and len(manifest['files']) == len(source_files) == 32,
            'exact32 source container required')
    rows = {}
    for row in manifest['files']:
        require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
                and type(row['path']) is str and row['path'] not in rows
                and type(row['bytes']) is int and 0 <= row['bytes'] <= 8 * 1024 * 1024
                and type(row['sha256']) is str,
                'exact bounded unique source row required')
        rows[row['path']] = row
    require(set(rows) == set(source_files), 'complete32 source names differ')
    for name, row in rows.items():
        body = source_files[name]
        require(type(body) is bytes and len(body) == row['bytes']
                and digest(body) == row['sha256'], 'source bytes differ: ' + name)
    change = RUNTIME_SOURCE_INCREMENT['changed_member']
    name = change['path']
    require(name in rows and rows[name] == dict(path=name, **change['successor']),
            'only the exact reviewed current reader can be changed')
    candidate = source_files[name]
    transformation = RUNTIME_SOURCE_INCREMENT['transformation']
    before = transformation['old_utf8'].encode('ascii')
    after = transformation['new_utf8'].encode('ascii')
    require(candidate.count(after) == 1, 'one exact successor expression required')
    restored_source = candidate.replace(after, before, 1)
    require(restored_source.count(before) == 1
            and {'bytes': len(restored_source), 'sha256': digest(restored_source)} == change['parent'],
            'complete current reader inverse differs from actual c50a')
    retained_increment = manifest.pop('runtime_source_increment')
    restored_rows = []
    for row in manifest['files']:
        restored_rows.append(dict(path=name, **change['parent']) if row['path'] == name else row)
    manifest['files'] = restored_rows
    restored_manifest = encode(manifest)
    parent = RUNTIME_SOURCE_INCREMENT['base_runtime_manifest']
    require({'bytes': len(restored_manifest), 'sha256': digest(restored_manifest)}
            == {key: parent[key] for key in ('bytes', 'sha256')},
            'whole manifest inverse differs from actual16808/67dc')
    return {'schema': 'hepta.native-guard.runtime-source-increment-proof.v1',
            'state': 'EXACT_RUNTIME32_SINGLE_EXPRESSION_AND_PARENT_INVERSES_VERIFIED',
            'runtime_manifest': {'bytes': len(manifest_raw), 'sha256': digest(manifest_raw)},
            'base_runtime_manifest': dict(parent), 'runtime_source_increment': retained_increment,
            'member_count': 32, 'unchanged_member_count': 31,
            'all32_source_bytes_verified': True, 'whole_source_inverse_verified': True,
            'whole_manifest_inverse_verified': True,
            'target_source_executed': False, 'historical_reference_changes': 0,
            'phone_calls': 0, 'component_qualified': False, 'business_qualified': False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-host-interface-once',action='store_true')
    args=parser.parse_args()
    if not args.execute_host_interface_once:
        print(json.dumps({'state':'PROPERTY_POLICY_SEAL_INTERFACE_PREVIEW_NO_IO',
            'phone_calls':0,'host_reads':0,'host_writes':0,'qualification_granted':False},sort_keys=True))
        return 0
    need(isinstance(DELIVERY,dict) and set(DELIVERY)=={'path','bytes','sha256'},
         'actual reviewed final cascade delivery is not frozen')
    need(isinstance(OUT,Path) and OUT == B/'property-policy-final-seal-interface-r8-r1-inventory-prefix-1ad3-01',
         'the explicit create-only R8 host-interface output has not been frozen')
    os.umask(0o077)
    need(not OUT.exists() and not OUT.is_symlink() and OUT.parent.resolve(strict=True)==OUT.parent,
         'new interface output required')
    delivery,draw=original(DELIVERY);d=strict(draw)
    need(d['schema']=='hepta.property-policy.final-boundary-cascade-delivery.v1'
         and d['state']=='HOST_ONLY_PUBLISHED' and d['phone_calls']==0
         and d['nonce_generated'] is False and d['final_release_generated'] is False
         and d['new_component_qualification'] is False
         and d['pre_policy_ancestor_sha256']==PRE_POLICY_BOUNDARY_SHA
         and d['external_ancestor_sha256']==EXTERNAL_BOUNDARY_SHA
         and d['environment_parent_ancestor_sha256']==ENVIRONMENT_PARENT_BOUNDARY_SHA
         and d['property_parent_boundary_sha256']==PROPERTY_PARENT_BOUNDARY_SHAS[0]
         and d['property_parent_failed_ancestor_count']==2
         and d['historical_native_failed_case_count']==5
         and d['policy_parent_sha256']==POLICY_PARENT_SHA
         and d['parent_adoption_sha256']==PARENT_ADOPTION_SHA
         and d['module_replacement_reapplied'] is False,
         'actual source cascade delivery differs')
    frozen=d['reviewed_finalization']
    need(frozen['schema']=='hepta.property-policy.final-pin-freeze.v1'
         and set(frozen)=={'schema','runtime_manifest','component_combination',
                         'policy_adoption','policy_verifier','actual_policy','scope_decision','full_rule'},
         'reviewed future pin record differs')
    manifest,mraw=original(frozen['runtime_manifest']);runtime=strict(mraw)
    need(runtime['schema']=='hepta.native-guard.adapter-package.v1'
         and len(runtime['files'])==32 and len({r['path'] for r in runtime['files']})==32,
         'actual new runtime manifest differs')
    old_manifest,oldraw=read(OLD_RUNTIME/'MANIFEST.json',5284,
        '1cd57949621b36e46dc72d3df55e6ec3814fa76fb046c15ae71524463e3e8996')
    oldpaths={r['path'] for r in strict(oldraw)['files']}
    parent_manifest,parent_raw=read(RUNTIME_PARENT/'MANIFEST.json',13446,
        '683481bdb653bd7cb97bd6171d6b14f6ecaf4f9948ed2691c7b7c420fea5fe3c')
    parentpaths={r['path'] for r in strict(parent_raw)['files']}
    sidebranch_added={'reference/component_common_r5.py','reference/non_native_attempt05.py',
           'reference/attempt05-SIDE-PROOF.original.json',
           'reference/attempt05-CLOSURE.original.json',
           'reference/attempt05-AFTER-INVENTORY.original.json'}
    added={'reference/property_parent_late_boundary_r7.py'}
    need(len(oldpaths)==24 and len(parentpaths)==31
         and parentpaths==oldpaths|{'reference/policy_parent_late_boundary_r4.py',
                                  'reference/environment_parent_late_boundary_r6.py'}|sidebranch_added
         and not (parentpaths & added)
         and {r['path'] for r in runtime['files']}==parentpaths|added,
         'exact R8 path set or immutable historical24 versus parent31 distinction differs')
    parent_rows={r['path']:r for r in strict(parent_raw)['files']}
    current_rows={r['path']:r for r in runtime['files']}
    need(all(current_rows[name]==parent_rows[name] for name in parentpaths
             if name!='source/late_boundary.py')
         and {k:current_rows['reference/property_parent_late_boundary_r7.py'][k] for k in ('bytes','sha256')}==
             {k:parent_rows['source/late_boundary.py'][k] for k in ('bytes','sha256')},
         'the other30 R7 files and the exact original reader reference must remain unchanged')
    runtime_files={}
    for row in runtime['files']:
        need(set(row)=={'path','bytes','sha256'} and row['path'] not in runtime_files,
             'runtime original source row differs')
        name=Path(row['path'])
        need(not name.is_absolute() and '..' not in name.parts and str(name)==row['path'],
             'runtime original source path differs')
        _,runtime_files[row['path']]=read(Path(manifest['path']).parent/name,row['bytes'],row['sha256'])
    increment_proof=verify_runtime_source_increment(mraw,runtime_files)
    need(encode(d.get('runtime_source_increment_proof'))==encode(increment_proof),
         'actual delivery did not retain the exact32 source increment proof')
    fc_manifest,fcraw=original(d['consumer']);fc=strict(fcraw)
    c_manifest,ccraw=original(d['constructor']);cc=strict(ccraw)
    need(d['consumer']['path']==str(FC/'MANIFEST.json')
         and d['constructor']['path']==str(C/'MANIFEST.json')
         and fc['schema']=='hepta.r10.final-boundary-consumers.v8'
         and cc['schema']=='hepta.r10.component-boundary-input-entry.v8'
         and fc['component_package_sha256']==cc['component_package_sha256']==manifest['sha256'],
         'actual FC8/C8 identity differs')
    def source(root,value,name):
        rows=[r for r in value['files'] if r['path']==name]
        need(len(rows)==1 and set(rows[0])=={'path','bytes','sha256'}, 'one exact source row required')
        row=rows[0]
        return read(root/name,row['bytes'],row['sha256'])
    constructor,craw=source(C,cc,'source/make_component_boundary_inputs.py')
    builder,braw=source(FC,fc,'source/build_release_r10.py')
    helper,hraw=source(FC,fc,'source/release_boundaries.py')
    need({k:constructor[k] for k in ('bytes','sha256')}==d['constructor_source']
         and {k:builder[k] for k in ('bytes','sha256')}==d['runtime_sources']['build_release_r10.py']
         and {k:helper[k] for k in ('bytes','sha256')}==d['runtime_sources']['release_boundaries.py'],
         'delivered source descriptors differ')
    need(flags(craw)=={'--plan','--plan-sha256','--out','--execute-host-inputs'},
         'constructor actual CLI differs')
    required={'--inputs','--inputs-sha256','--output','--retirement-inputs',
        '--retirement-inputs-sha256','--component-boundary-inputs','--component-boundary-inputs-sha256',
        '--policy-adoption-inputs','--policy-adoption-inputs-sha256','--shared-materials','--shared-materials-sha256'}
    need(required<=flags(braw) and '--out' not in flags(braw),'builder actual CLI differs')
    assignments={n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(hraw).body
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)
        and n.targets[0].id in {'PACKAGE_SHA','PACKAGE_FILE_COUNT','CURRENT_COMBINATION_SHA',
                              'POLICY_VERIFIER_SHA','POLICY_VERIFIER_BYTES','CURRENT_POLICY_SHA',
                               'CURRENT_POLICY_ADOPTION_SHA','CURRENT_SCOPE_DECISION_SHA'}}
    bound_nodes=[n.value for n in ast.parse(hraw).body
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)
        and n.targets[0].id=='MAX_BUNDLE']
    need(len(bound_nodes)==1 and ast.dump(bound_nodes[0])==ast.dump(ast.parse('32 * 1024 * 1024',mode='eval').body),
         'exact aggregate boundary capacity expression changed')
    need(assignments=={'PACKAGE_SHA':manifest['sha256'],'PACKAGE_FILE_COUNT':32,
        'CURRENT_COMBINATION_SHA':frozen['component_combination']['sha256'],
        'POLICY_VERIFIER_SHA':frozen['policy_verifier']['sha256'],
        'POLICY_VERIFIER_BYTES':frozen['policy_verifier']['bytes'],
         'CURRENT_POLICY_SHA':frozen['actual_policy']['sha256'],
         'CURRENT_POLICY_ADOPTION_SHA':frozen['policy_adoption']['sha256'],
         'CURRENT_SCOPE_DECISION_SHA':frozen['scope_decision']['sha256']},
        'final helper does not contain the independently reviewed new pins and unchanged capacity')
    need(b"SCHEMA = 'hepta.r10.component-boundary-construction-plan.v6'" in craw
         and b"schema='hepta.r10.component-boundary-inputs.v5'" in craw,
         'current component constructor must separate the old failed tail')
    need(b"component_package_sha256=state['component_input']['component_package_manifest']['sha256']" in braw,
         'builder activation must use the consumer-verified actual current package')
    module=types.ModuleType('reviewed_r8_interface_boundary_consumer')
    module.__file__=helper['path']
    exec(compile(hraw,module.__file__,'exec',optimize=0),module.__dict__)
    need(encode(module.verify_runtime_source_increment(mraw,runtime_files))==encode(increment_proof),
         'delivered consumer runtime increment gate differs')
    with module.component_modules({'package_sources':runtime_files}) as modules:
        late=modules['late_boundary']
        proof=d['environment_parent_ancestor'];reviewed=late.reviewed_environment_parent_ancestor()
        need(proof['boundary']==reviewed['boundary']
             and proof['boundary']['sha256']==ENVIRONMENT_PARENT_BOUNDARY_SHA,
             'delivered exact environment-parent proof differs')
        pool={}
        def collect_environment(row):
            _descriptor,body=original(row)
            item={'bytes':len(body),'raw_b64':base64.b64encode(body).decode('ascii')}
            need(row['sha256'] not in pool or pool[row['sha256']]==item,'environment original collision')
            pool[row['sha256']]=item
            return body
        for key,row in proof.items():
            if key not in ('schema','boundary'):collect_environment(row)
        raw06={}
        for key,name in [('boundary','LATE-BOUNDARY.original.json'),
                         ('closure','CLOSURE.json'),('inventory','INVENTORY.json')]:
            row=reviewed[key]
            raw06[key]=collect_environment(dict(path=str(F06/name),
                **{k:row[k] for k in ('bytes','sha256')}))
        head06,inventory06,closure06=late.closed_boundary_originals(
            raw06['boundary'],raw06['inventory'],raw06['closure'],
            original_descriptor=reviewed['boundary'],
            combination_sha256=frozen['component_combination']['sha256'],
            package_sha256=manifest['sha256'])
        module.validate_environment_parent_ancestor({'originals':pool},proof,
            {'package_sources':runtime_files},head06,late)
        environment_input={'root_result':proof['root_result'],'package_manifest':proof['package_manifest']}
        property_proofs=d['property_parent_ancestors']
        reviewed_properties=late.reviewed_property_parent_ancestors()
        need(isinstance(property_proofs,list) and len(property_proofs)==2
             and property_proofs==fc['property_parent_ancestors']
             and [r['boundary']['sha256'] for r in property_proofs]==PROPERTY_PARENT_BOUNDARY_SHAS,
             'delivered property ancestors must remain exact08 then07')
        property_values=[];property_inventories=[];property_inputs=[]
        for index,(home,attempt) in enumerate(((F08,'attempt08'),(F07,'attempt07'))):
            property_proof=property_proofs[index]
            need(property_proof['attempt']==attempt
                 and property_proof['boundary']==reviewed_properties[index]['boundary'],
                 'historical property ancestor identity or order differs')
            for key,row in property_proof.items():
                if key not in ('schema','attempt','boundary'):collect_environment(row)
            raw_property={}
            for key,name in [('boundary','LATE-BOUNDARY.original.json'),
                             ('closure','CLOSURE.json'),('inventory','INVENTORY.json')]:
                row=reviewed_properties[index][key]
                raw_property[key]=collect_environment(dict(path=str(home/name),
                    **{k:row[k] for k in ('bytes','sha256')}))
            old_value,old_inventory,_=late.closed_boundary_originals(
                raw_property['boundary'],raw_property['inventory'],raw_property['closure'],
                original_descriptor=reviewed_properties[index]['boundary'],
                combination_sha256=frozen['component_combination']['sha256'],
                package_sha256=manifest['sha256'])
            property_values.append(old_value);property_inventories.append(old_inventory)
            property_inputs.append({key:property_proof[key] for key in ('root_result','package_manifest')})
        module.validate_property_parent_ancestors({'originals':pool},property_proofs,
            {'package_sources':runtime_files},property_values,late)
        older_values=[]
        all_records=late.property_parent_records()
        for index,(home,names) in enumerate(((F04,('LATE-BOUNDARY.original.json','INVENTORY.json','CLOSURE.json')),
                (E/'originals',('BOUNDARY.original.json','AFTER-INVENTORY.original.json','CLOSURE.original.json'))),start=3):
            record=all_records[index];raw_old={}
            for key,name in zip(('boundary','inventory','closure'),names):
                row=record[key]
                _,raw_old[key]=original(dict(path=str(home/name),
                    **{k:row[k] for k in ('bytes','sha256')}))
            old_value,_,_=late.closed_boundary_originals(raw_old['boundary'],raw_old['inventory'],
                raw_old['closure'],original_descriptor=record['boundary'],
                combination_sha256=frozen['component_combination']['sha256'],
                package_sha256=manifest['sha256'])
            older_values.append(old_value)
        all_values=property_values+[head06]+older_values
        late.require_failed_ancestor_tail(all_values)
        sidebranch=late.non_native_sidebranch()
        late.preserve_non_native_private(sidebranch['inventory'],sidebranch)
        binding=sidebranch['binding']
        need(binding==d['non_native_sidebranch']==fc['non_native_sidebranch']
             and binding['native_case_count']==0 and binding['component_qualified'] is False
             and binding['native_predecessor']['sha256']==PRE_POLICY_BOUNDARY_SHA
             and d['non_native_attempt_count']==1 and d['non_native_case_count']==0,
             'actual R8 source delivery lost or reinterpreted the independent non-native sidebranch')
        late.preserve_non_native_private(property_inventories[0],sidebranch)
        need(late.effective_prior_inventory(property_values[0],property_inventories[0],sidebranch)
             is property_inventories[0], 'actual08 must retain its own cumulative inventory')
        roles=[tuple(row) for value in all_values for row in value['component_role_identities'].values()]
        roles.extend(tuple(row) for row in binding['component_role_identities'].values())
        need(len(roles)==len(set(roles))==18 and len(roles)<=24,
             'the actual five native failures and separate05 role set differs')
        sidebranch_sources={name:{'bytes':len(runtime_files[name]),'sha256':sha(runtime_files[name])}
            for name in ('reference/non_native_attempt05.py',
                         'reference/attempt05-SIDE-PROOF.original.json',
                         'reference/attempt05-CLOSURE.original.json',
                         'reference/attempt05-AFTER-INVENTORY.original.json')}
    formal,fraw=original(d['formal_input'])
    need(formal['path']==str(FC/'inputs/FINAL-INTEGRATION-INPUTS.json'), 'formal original path differs')
    module_replacement,module_raw=original(d['module_input_replacement']);replacement=strict(module_raw)
    module_rows=strict(fraw)['module_sources']
    need(len(module_rows)==14 and len({r['name'] for r in module_rows})==14
         and [r for r in module_rows if r['name']=='launch-sidecar.sh']==[replacement['candidate_module_source']]
         and [r for r in module_rows if r['name']!='launch-sidecar.sh']==
             replacement['other_thirteen_module_source_rows_unchanged'],
         'formal module input is not the reviewed single-sidecar replacement')
    original({k:replacement['candidate_module_source'][k] for k in ('path','bytes','sha256')})
    shared,_=read(S,3519,'121416839ffdac15485270cda0e95445e376b0a24801fa283659a3da084ae45f')
    adoption,araw=original(frozen['policy_adoption']);adopted=strict(araw)
    combo,coraw=original(frozen['component_combination']);combination=strict(coraw)
    verifier,vraw=original(frozen['policy_verifier'])
    scope,sraw=original(frozen['scope_decision']);full_rule,frraw=original(frozen['full_rule'])
    _,actual_raw=original(adopted['actual_export'])
    policy_verifier=types.ModuleType('reviewed_r8_interface_policy_verifier')
    policy_verifier.__file__=verifier['path'];policy_verifier.__reviewed_source_sha256__=sha(vraw)
    exec(compile(vraw,verifier['path'],'exec',optimize=0),policy_verifier.__dict__)
    policy_summary=policy_verifier.verify_adoption(araw,read_pinned=lambda row:original(row)[1])
    need(policy_summary['current_adoption_sha256']==adoption['sha256']
         and policy_summary['runtime_policy']==frozen['actual_policy']==
             {'bytes':len(actual_raw),'sha256':sha(actual_raw)}
         and policy_summary['parent_policy']=={'bytes':2667608,'sha256':POLICY_PARENT_SHA}
         and policy_summary['parent_adoption_sha256']==PARENT_ADOPTION_SHA
         and policy_summary['prior_boundary_sha256']==PROPERTY_PARENT_BOUNDARY_SHAS[0]
         and policy_summary['root_scope_decision_sha256']==scope['sha256']
         and policy_summary['full_rule']==adopted['full_rule']==full_rule
         and policy_summary['retirement_sha256']==property_values[0]['retirement']['proof']['sha256']
         and frozen['actual_policy']['sha256']!=POLICY_PARENT_SHA
         and adoption['sha256']!=PARENT_ADOPTION_SHA,
         'new policy evidence must retain exact50f/a5f/08 and the separately reviewed scope/full rule')
    verifier_rows=[row for row in adopted['verification_originals']
        if row.get('bytes')==len(vraw) and row.get('sha256')==sha(vraw)]
    need(len(verifier_rows)==1 and original(verifier_rows[0])[1]==vraw
         and original(adopted['full_rule'])[1]==frraw,
         'new adoption must retain the same exact reviewed verifier and complete rule')
    _,parent_combo_raw=read(RUNTIME_PARENT.parent/'COMBINATION.json',4702,POLICY_PARENT_COMBINATION_SHA)
    need(combination_encode(strict(parent_combo_raw))==parent_combo_raw and combination_encode(combination)==coraw
         and combination['live_policy_sha256']==frozen['actual_policy']['sha256'],
         'actual canonical property-policy combination differs')
    reversed_combo=dict(combination);reversed_combo['live_policy_sha256']=POLICY_PARENT_SHA
    need(combination_encode(reversed_combo)==parent_combo_raw and sha(coraw)!=POLICY_PARENT_COMBINATION_SHA,
         'only the adopted current policy may change in the original R7 combination')
    retirement,rraw=read(RET/'ACTUAL-RETIREMENT-INPUTS.json',2220,
        'e3c8411f3d85440018392597d4f9f8795cfd7a60c44fc1680068a60949d20999')
    retired=strict(rraw)['files'];retirement_originals={}
    for name,phone in retired.items():
        retirement_originals[name],_=read(RET/'retirement-originals'/(name+'.original'),phone['bytes'],phone['sha256'])
    builder_retirement,_=read(B/'r10-final-seal-preparation-r1/ACTUAL-BUILDER-RETIREMENT-INPUTS.json',2414,
        '1cd133d03c687d671aa87b3a813379020e0779941ebdd638de2b5b79652cdf4f')
    publication,praw=read(E/'PUBLICATION-RESULT.json',13450,
        '5799fac9fcc837c61e2990b56d0feab9140affd97b988f80419feeefeb7167ce')
    published=strict(praw)
    descriptor,raw=read(E/'BOUNDARY-DESCRIPTOR.json',302,
        '48be797e4413795ba332114124121d23c8fb1968462c93f432d29c7d0e4c89ae')
    need(strict(raw)==published['boundary'] and published['boundary']['sha256']==EXTERNAL_BOUNDARY_SHA,
         'actual published full9 external descriptor differs')
    legacy={'boundary_descriptor':descriptor}
    for name,key in [('boundary','boundary_original'),('closure','closure_original'),('inventory','inventory_original')]:
        legacy[key],_=original(published['originals'][name]['host'])
    _,hraw=original(published['publication_host_result']);host=strict(hraw)
    need(host['state']=='ORIGINAL_HOST_CHILD_JOINED' and host['phase']=='phone-external-publish'
         and type(host['returncode']) is int and host['returncode']==0,
         'actual external publication terminal differs')
    legacy['publication_operation'],operation=original(host['stdout'])
    need(Path(host['stdout']['path'])==E/'phone-external-publish/stdout.original',
         'actual original publication stdout path differs')
    alias,alias_raw=original(published['publication_operation'])
    need(operation==alias_raw and legacy['publication_operation']['path']!=alias['path'],
         'publication stdout and alias must have the same bytes and separate identity')
    transport=strict(operation)
    need(type(transport['actor_rc']) is int and transport['actor_rc']==0
         and type(transport['wrapper']['phone']['rc']) is int and transport['wrapper']['phone']['rc']==0,
         'original publication did not complete')
    pre_root,pre_raw=read(F04/'ROOT-RESULT.json',10980,
        'c92382e0841375fc0a1fb19ff0271381ac044f1dad01427342fca4e4f6e9c638')
    pre=strict(pre_raw)
    need(pre['late_boundary']['sha256']==PRE_POLICY_BOUNDARY_SHA
         and pre['component_qualified'] is False and pre['native_status']=='provider_failed',
         'fixed old04 Root result was changed or upgraded')
    pre_policy={'root_result':pre_root,'package_manifest':old_manifest}
    template=dict(schema='hepta.r10.component-boundary-construction-plan.v6',package_manifest=manifest,
        retirement_descriptor=retirement,retirement_originals=retirement_originals,
        shared_materials=shared,policy_adoption=adoption,cases=[],
        legacy_ancestor=legacy,pre_policy_ancestor=pre_policy,
        environment_parent_ancestor=environment_input,property_parent_ancestors=property_inputs)
    preview=['/usr/bin/python3','-I','-B',constructor['path'],'--plan','<ACTUAL_PLAN_PATH>',
        '--plan-sha256','<ACTUAL_PLAN_SHA256>','--out','<FRESH_COMPONENT_INPUT_OUTPUT>']
    build=['/usr/bin/python3','-I','-B',builder['path'],'--inputs',formal['path'],
        '--inputs-sha256',formal['sha256'],'--output','<FRESH_FINAL_SEALED_OUTPUT>',
        '--retirement-inputs',builder_retirement['path'],'--retirement-inputs-sha256',builder_retirement['sha256'],
        '--component-boundary-inputs','<ACTUAL_COMPONENT_BOUNDARY_INPUT_PATH>',
        '--component-boundary-inputs-sha256','<ACTUAL_COMPONENT_BOUNDARY_INPUT_SHA256>',
        '--policy-adoption-inputs',adoption['path'],'--policy-adoption-inputs-sha256',adoption['sha256'],
        '--shared-materials',shared['path'],'--shared-materials-sha256',shared['sha256']]
    interface=dict(schema='hepta.property-policy.final-seal-interface.v1',
        state='WAITING_FOR_ACTUAL_CURRENT_COMPONENT_CASE_ORIGINALS',actual_source_delivery=delivery,
        actual_runtime_manifest=manifest,actual_runtime_parent_manifest=parent_manifest,
        consumer_manifest=fc_manifest,constructor_manifest=c_manifest,
        property_parent_ancestors=property_proofs,property_parent_failed_ancestor_count=2,
        exact_retained_component_roles=[list(row) for row in roles],
        historical_native_failed_case_count=5,environment_parent_ancestor=proof,
        module_input_replacement=module_replacement,
        non_native_sidebranch=binding,non_native_original_references=sidebranch_sources,
        non_native_attempt_count=1,non_native_case_count=0,
        non_native_role_identities_in_activation=True,
        constructor=constructor,builder=builder,formal_input=formal,builder_retirement_input=builder_retirement,
        policy_adoption=adoption,component_combination=combo,policy_verifier=verifier,
        root_scope_decision=scope,full_rule=full_rule,
        policy_parent_sha256=POLICY_PARENT_SHA,parent_adoption_sha256=PARENT_ADOPTION_SHA,
        component_plan_template_filename='COMPONENT-PLAN.template.json',template_is_executable=False,
        missing_actual_inputs=['Latest-first current ROOT-RESULT descriptors for the entire new-combination prefix',
            'Every current closed case must use the same actual new package and combination',
            'Fixed failed08 and07 retain their original R7 package, policy, recovery and publication proof outside cases',
             'Exact failed06 remains a separately verified original R6 ancestor before fixed04 and external03',
            'Every current boundary/closure retains the separately verified ended05 sidebranch and private roots',
            'True NEG-01 and NEG-02 qualification in their own original closed results',
            'Actual complete component/policy evidence-union byte count within the unchanged 32MiB bound',
            'Explicit fresh host output paths; no generated nonce or lease'],
        required_case_files=['ROOT-RESULT.json','LATE-BOUNDARY.original.json','CLOSURE.json','INVENTORY.json',
            'material/tree/inputs/COMBINATION.json','phone-late-publish/stdout.original','phone-late-publish/stderr.original'],
        case_order='latest first current prefix, then exact old08,07,06,04,external03; ended05 remains a separate non-native sidebranch',
        old_tail_separate_from_current_cases=True,old_tail_qualification=False,
        constructor_preview_argv=preview,constructor_execute_argv=preview+['--execute-host-inputs'],
        constructor_outputs=['PUBLISH-RESULT.original.json','COMPONENT-BOUNDARY-INPUTS.json','PREPARATION-RESULT.json'],
        component_input_schema='hepta.r10.component-boundary-inputs.v5',
        pre_seal_checks=['Actual qualified_component_cases must include NEG-01 and NEG-02',
            'Actual release_bundle_preview bytes <= 33554432, only the exact aggregate evidence member',
            'Actual shared17 must remain the exact source/config/service materials used by current components',
            'Three ended05 role identities join the existing bounded activation absence set; 05 never supplies native-case credit',
            'Fixed06 is outside current cases and retains its original failure, recovery, package, scope and one tool call',
            'New policy must retain actual50f/a5f/08 and its separately reviewed scope/full rule; old296b/7899/04 are never current'],
        actual_complete_component_and_policy_union_bytes=None,exact_boundary_member_maximum_bytes=33554432,
        final_builder_argv=build,expected_builder_state='SEALED_ACTUAL_RETIREMENT_BOUND',
        final_expected_outputs=['BUILD-RESULT.json','release.json','module/SEALED','phone-release-v150-r10-r1.tar.gz'],
        downstream='Root alone reviews/stages/starts and obtains actual four-role readiness; only that release feeds host six/UI/fault.',
        automatic_execution=False,case_or_nonce_created=False,qualification_granted=False,release_created=False,
        phone_calls=0,policy_operations=0,production_signals=0,automatic_retry=False)
    for row,identity in tuple(SEEN.values()):
        read(row['path'],row['bytes'],row['sha256'])
        need(SEEN[row['path']][1]==identity,'input changed before interface publication')
    OUT.mkdir(mode=0o700);sync(OUT.parent)
    rows=[put(OUT/'COMPONENT-PLAN.template.json',encode(template)),put(OUT/'INTERFACE.json',encode(interface))]
    report=dict(schema='hepta.property-policy.final-seal-interface-preparation.v1',
        state='STATIC_ORIGINALS_AND_ACTUAL_CLI_VERIFIED_CURRENT_CASE_INPUTS_PENDING',
        files=rows,static_original_count=len(SEEN),originals=[row for row,_ in SEEN.values()],
        constructor_run=False,builder_run=False,phone_calls=0,nonce_created=False,qualification_granted=False)
    result=put(OUT/'RESULT.json',encode(report));print(json.dumps(result,sort_keys=True))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
