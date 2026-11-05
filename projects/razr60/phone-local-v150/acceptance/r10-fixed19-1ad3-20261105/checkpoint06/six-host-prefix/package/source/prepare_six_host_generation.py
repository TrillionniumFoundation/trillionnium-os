#!/usr/bin/env python3
"""Bind the reviewed six-host source generator to an actual cascade delivery.

This creates only a new source binding package. It never publishes the generated
operator, prepares a release, transfers files, starts a process or runs a case.
The original generator's read-only prepare function checks the proposed binding.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import types

B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
PARENT = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/fixed19-six-host-inventory-prefix-generation-1ad3-candidate01/generator')
SOURCE = {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/fixed19-six-host-inventory-prefix-generation-1ad3-candidate01/generator/source/derive_six_host_property_pins.py', 'bytes': 17186, 'sha256': '9ef4c79511e8b3cee5098eb8c9bf292d21b04bfbec7747cbd345efc673ac9df3'}
SOURCE_MANIFEST = {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/fixed19-six-host-inventory-prefix-generation-1ad3-candidate01/generator/MANIFEST.json', 'bytes': 2308, 'sha256': '5ad06a9c1992590421872caf03abc2cbbaf09957c2d20576ba2a1dd9a77d5b26'}
DELIVERY = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/r10-boundary-consumers-final-r8-inventory-prefix-1ad3-01/DELIVERY-RESULT.json')
ACTUAL_DELIVERY = {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/r10-boundary-consumers-final-r8-inventory-prefix-1ad3-01/DELIVERY-RESULT.json', 'bytes': 28755, 'sha256': '4683e907b33377d657bb0f4b7c2cd772b6d84881ab09ad66e77a6445f36ed714'}
ACTUAL_FINALIZATION = {'consumer_manifest': {'bytes': 30832, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/r10-boundary-consumers-final-r8-inventory-prefix-1ad3-01/MANIFEST.json', 'sha256': 'b26a60719eed3b6548d8e2a1b52abac25f5678afdace72d9865de24e17d24a53'}, 'acceptance_manifest': {'bytes': 21485, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/scoped-acceptance-v150-r10-r1-readiness-r9-inventory-prefix-1ad3-01/MANIFEST.json', 'sha256': '00ea6a0575b41ecc4cbbe47b93799b6d8ed176a1f02bc9a80d458fba97f45671'}, 'policy_adoption': {'bytes': 208226, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-runtime-properties-r10-live-02/POLICY-ADOPTION.json', 'sha256': '527374778e62717d837d546cfa56bd144c8415b52006a9be4a33935c8592d08a'}, 'current_policy': {'bytes': 2667740, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-runtime-properties-r10-live-02/capture/originals/live-policy-after.bin', 'sha256': 'f8219f9c3ad2e1d16a95fda8d5f0bc7612a31e00c0a661e53bf9a6e921c49d70'}}
META = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
LIMIT = 16*1024*1024


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()


def strict(raw):
    def pairs(rows):
        result = {}
        for name,value in rows:
            need(name not in result,'duplicate JSON key')
            result[name] = value
        return result
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def descriptor(path, raw):
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}


def bare(row):
    return {key:row[key] for key in ('bytes','sha256')}


def exact3(row):
    need(type(row) is dict and set(row)=={'path','bytes','sha256'},'exact3 original required')
    need(type(row['path']) is str and type(row['bytes']) is int and 0<row['bytes']<=LIMIT
        and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),
        'bounded original descriptor required')
    path = Path(row['path'])
    need(path.is_absolute() and str(path)==row['path'] and '..' not in path.parts
        and '\0' not in row['path'],'canonical original path required')
    return row


class Originals:
    def __init__(self):
        self.seen = {}

    def read(self, row):
        exact3(row); path = Path(row['path'])
        need(path.resolve(strict=True)==path,'original symlink or alias rejected')
        fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink==1
                and before.st_size==row['bytes'],'exact single-link regular original required')
            with os.fdopen(fd,'rb',closefd=False) as stream:
                raw = stream.read(row['bytes']+1)
            meta = tuple(getattr(before,key) for key in META)
            need(meta==tuple(getattr(os.fstat(fd),key) for key in META)
                ==tuple(getattr(path.lstat(),key) for key in META),'original changed during read')
        finally:
            os.close(fd)
        need(descriptor(path,raw)==row,'original bytes differ')
        record = {'descriptor':dict(row),'metadata':meta}
        need(str(path) not in self.seen or self.seen[str(path)]==record,'original changed between reads')
        self.seen[str(path)] = record
        return raw

    def recheck(self):
        for row in list(self.seen.values()):
            self.read(row['descriptor'])


def finalization_from_delivery(row, raw, read):
    exact3(row)
    need(row==ACTUAL_DELIVERY and row['path']==str(DELIVERY) and descriptor(DELIVERY,raw)==row,'exact completed cascade original')
    value = strict(raw)
    need(value.get('schema')=='hepta.property-policy.final-boundary-cascade-delivery.v1'
        and value.get('state')=='HOST_ONLY_PUBLISHED' and type(value.get('phone_calls')) is int
        and value['phone_calls']==0 and value.get('nonce_generated') is False
        and value.get('final_release_generated') is False and value.get('new_component_qualification') is False
        and value.get('module_replacement_reapplied') is False,'actual source-only cascade delivery required')
    frozen = value['reviewed_finalization']
    need(frozen['schema']=='hepta.property-policy.final-pin-freeze.v1','actual cascade finalization required')
    adoption_row = exact3(frozen['policy_adoption'])
    adoption = strict(read(adoption_row))
    need(adoption['schema']=='hepta.runtime-properties-r10.policy-adoption.v1',
        'actual adopted policy original required')
    policy_row = exact3(adoption['actual_export'])
    need(frozen['actual_policy']==bare(policy_row),
        'cascade policy must equal the adopted actual export, including bytes')
    decision = adoption['root_decision']
    need(type(decision) is dict and decision.get('decision')=='ADOPT_INDEPENDENTLY_VERIFIED_ACTUAL_EXPORTED_POLICY'
        and decision.get('actual_policy_sha256')==policy_row['sha256'],
        'actual Root adoption decision required')
    read(policy_row)
    final = {'consumer_manifest':exact3(value['consumer']),
        'acceptance_manifest':exact3(value['acceptance']),
        'policy_adoption':adoption_row,'current_policy':policy_row}
    need(final==ACTUAL_FINALIZATION,'only the actual inventory-prefix cascade dependencies are admitted')
    return final,value


def bind_source(raw, final):
    need(len(raw)==SOURCE['bytes'] and sha(raw)==SOURCE['sha256'],'fixed generator original differs')
    nodes = [node for node in ast.parse(raw).body if isinstance(node,ast.Assign)
        and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)
        and node.targets[0].id=='FINALIZATION']
    need(len(nodes)==1 and ast.literal_eval(nodes[0].value) is None,'one unchanged unbound source slot required')
    before = b'FINALIZATION = None\n'
    after = ('FINALIZATION = '+repr(final)+'\n').encode()
    need(raw.count(before)==1,'exact original FINALIZATION line required')
    derived = raw.replace(before,after,1)
    need(derived.count(after)==1 and derived.replace(after,before,1)==raw,'whole-source inverse differs')
    compile(derived,'<six-host-reviewed-source-binding>','exec')
    return derived


def load(raw, path, name):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw,str(path),'exec'),module.__dict__)
    return module


def sync(path):
    fd = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def put(path, raw):
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        before = os.fstat(fd)
        with os.fdopen(fd,'wb',closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(fd)
        after,named = os.fstat(fd),path.lstat()
        need((before.st_dev,before.st_ino)==(after.st_dev,after.st_ino)==(named.st_dev,named.st_ino)
            and stat.S_ISREG(named.st_mode) and named.st_nlink==1,'created source path replaced')
    finally:
        os.close(fd)
    sync(path.parent)
    need(path.read_bytes()==raw,'created source readback differs')
    return descriptor(path,raw)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cascade-delivery-desc',required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--execute-host-preparation',action='store_true')
    args = parser.parse_args(argv)
    out = args.out
    need(out.is_absolute() and str(out)==str(args.out) and '..' not in out.parts and B in out.parents
        and out.parent.resolve(strict=True)==out.parent and not out.exists() and not out.is_symlink(),
        'fresh canonical Mac source-binding directory required')
    originals = Originals()
    source = originals.read(SOURCE)
    manifest_raw = originals.read(SOURCE_MANIFEST); manifest = strict(manifest_raw)
    need(manifest['schema']=='hepta.fixed19.runtime-properties-thirteen-slot-generation-candidate.v1'
        and [row for row in manifest['files'] if row['path']=='source/derive_six_host_property_pins.py']
        ==[{'path':'source/derive_six_host_property_pins.py',**bare(SOURCE)}],
        'exact original source package relation differs')
    delivery_row = strict(args.cascade_delivery_desc); delivery_raw = originals.read(delivery_row)
    final,delivery = finalization_from_delivery(delivery_row,delivery_raw,originals.read)
    derived = bind_source(source,final)
    target = out/'source/derive_six_host_property_pins.py'
    generator = load(derived,target,'reviewed_six_host_generator_bound_to_actual_delivery')
    need(generator.require_finalization()==final,'derived finalization differs')
    need(out!=generator.OUT and out not in generator.OUT.parents and generator.OUT not in out.parents
        and not os.path.lexists(generator.OUT),'generated operator destination must remain fresh and separate')
    # This existing function only verifies originals and derives bytes in memory.
    # It does not invoke main(), publish files, run a harness, or run a preparer.
    generated,proof,generator_originals = generator.prepare()
    need(proof['actual_finalization']==final and proof['replacement_counts']=={'preparer':7,'importer':6}
        and proof['complete_inverse_to_reviewed_parent'] is True
        and proof['functions_and_classes_byte_identical'] is True
        and proof['harness_import_provenance_byte_identical'] is True,
        'reviewed generator source-only validation differs')
    fc = strict(originals.read(final['consumer_manifest']))
    need(fc['component_package_sha256']==delivery['reviewed_finalization']['runtime_manifest']['sha256']
        and fc['actual_policy_adoption_sha256']==final['policy_adoption']['sha256'],
        'actual cascade consumer generation differs')
    preview_entry = {'executable':'/usr/bin/python3','argv':['-I','-B',str(target),
        '--preview','--out',str(generator.OUT)]}
    execute_entry = {'executable':'/usr/bin/python3','argv':['-I','-B',str(target),
        '--execute-host-only','--out',str(generator.OUT)]}
    predicted = {name:bare(descriptor(generator.OUT/'source'/name,generated['source/'+name]))
        for name in generator.PARENT_SOURCES}
    originals.recheck(); generator_originals.finish()
    result = {'schema':'hepta.fixed19.six-host-generator-source-preparation.v1',
        'state':'ACTUAL_CASCADE_SOURCE_BINDING_PREVIEW_NO_OUTPUT','cascade_delivery':delivery_row,
        'original_generator':SOURCE,'original_generator_manifest':SOURCE_MANIFEST,
        'finalization':final,'bound_generator':descriptor(target,derived),
        'predicted_generated_source_pins':predicted,'generator_preview_entry':preview_entry,
        'generator_execute_entry':execute_entry,'generator_output':str(generator.OUT),
        'changed_source_literals':['FINALIZATION'],'whole_source_inverse_to_reviewed_generator':True,
        'original_generator_prepare_validated_only':True,'generator_main_calls':0,
        'generated_operator_published':False,'sealed_release_required_by_preparer_later':True,
        'complete_adoption_reverified_by_this_constructor':False,
        'adoption_precondition':'The actual cascade already independently verified adoption; this constructor checks exact raw identities and selected cross-links.',
        'phone_calls':0,'case_runs':0,'processes_started':0,'automatic_retry':False}
    if not args.execute_host_preparation:
        print(json.dumps(result,sort_keys=True)); return 0
    os.umask(0o077); out.mkdir(mode=0o700); sync(out.parent)
    for name in ('source','reference'):
        (out/name).mkdir(mode=0o700); sync(out)
    outputs = {'source/derive_six_host_property_pins.py':derived,
        'reference/derive_six_host_property_pins.original.py':source,
        'reference/GENERATOR-MANIFEST.original.json':manifest_raw,
        'reference/CASCADE-DELIVERY.original.json':delivery_raw,
        'FINALIZATION.json':enc(final),'GENERATION-PREVIEW-ENTRY.json':enc(preview_entry),
        'GENERATION-EXECUTE-ENTRY.json':enc(execute_entry)}
    rows = []
    for name,raw in sorted(outputs.items()):
        item = put(out/name,raw); rows.append({'path':name,**bare(item)})
    originals.recheck(); generator_originals.finish()
    result.update(state='ACTUAL_CASCADE_SOURCE_BINDING_WRITTEN_OPERATOR_NOT_PUBLISHED',files=rows,
        original_bookends=list(originals.seen.values()),generator_original_bookends=list(generator_originals.rows.values()))
    report = put(out/'PREPARATION-RESULT.json',enc(result))
    print(json.dumps({key:value for key,value in result.items()
        if key not in ('original_bookends','generator_original_bookends','files')}|{'result':report},sort_keys=True))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
