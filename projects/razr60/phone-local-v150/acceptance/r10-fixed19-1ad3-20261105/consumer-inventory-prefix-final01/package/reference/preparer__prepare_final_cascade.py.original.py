#!/usr/bin/env python3
"""Create a source-only final cascade package from an actual verified R8 freeze.

This helper reads retained host originals and creates a new directory. It does
not invoke the cascade, a builder, a phone operation, or any policy setter.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import types

B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
PARENT = B/'property-r8-lossless-bundle-generators-candidate01'
SOURCE = {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/property-r8-lossless-compact-generators-1ad3-candidate02/source/derive_final_cascade_property_r8.py', 'bytes': 56374, 'sha256': 'd21fcd14bb5171938456e790318b09c0854ac1f2a1ce121a6f0b38d5d34aad26'}
INTERFACE = {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/property-r8-lossless-compact-generators-1ad3-candidate02/source/write_final_seal_interface_property_r8.py', 'bytes': 33280, 'sha256': '4fd182f8d8eba5b053b432da86e6503f6f18921ba9521a8413a65c5899bd8b0f'}
GENERATOR_MANIFEST = {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/property-r8-lossless-compact-generators-1ad3-candidate02/GENERATOR-SOURCE-MANIFEST.json', 'bytes': 1845, 'sha256': '5dda147dd1beb6cc02750fbf04b9eeebc599aca1a214d9e8bcf5d72a8f03954a'}
TEMPLATE_MANIFEST = {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/property-r8-lossless-bundle-generators-candidate01/SOURCE-MANIFEST.json', 'bytes': 24857, 'sha256': '81663c38554d20335928c4de2980036aa090babef33ab8d1a070efbbface3e54'}
META = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)+'\n').encode()


def strict(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def desc(path, raw):
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


class Originals:
    def __init__(self):
        self.seen = {}

    def read(self, row):
        need(type(row) is dict and set(row)=={'path','bytes','sha256'}, 'exact original descriptor')
        path = Path(row['path'])
        need(path.is_absolute() and path.resolve(strict=True)==path, 'canonical original path')
        need(type(row['bytes']) is int and 0<=row['bytes']<=64*1024*1024, 'bounded original')
        fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==row['bytes'],
                 'exact single-link regular original')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(row['bytes']+1)
            metadata = tuple(getattr(before, key) for key in META)
            need(metadata==tuple(getattr(os.fstat(fd), key) for key in META)
                 ==tuple(getattr(path.lstat(), key) for key in META), 'original metadata changed')
            need(desc(path, raw)==row, 'original bytes changed: '+str(path))
        finally:
            os.close(fd)
        record = (row, metadata)
        need(str(path) not in self.seen or self.seen[str(path)]==record, 'original changed between reads')
        self.seen[str(path)] = record
        return raw

    def recheck(self):
        for row, _metadata in list(self.seen.values()):
            self.read(row)


def module(row, raw, name):
    result = types.ModuleType(name)
    result.__file__ = row['path']
    result.__reviewed_source_sha256__ = row['sha256']
    exec(compile(raw, row['path'], 'exec'), result.__dict__)
    return result


def create(path, raw):
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    need(path.read_bytes()==raw, 'new source readback differs')
    return desc(path, raw)


def validate_source_manifests(originals, template_module):
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-freeze-result-desc', required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--execute-host-preparation', action='store_true')
    args = parser.parse_args()
    originals = Originals()
    result_row = strict(args.runtime_freeze_result_desc)
    result = strict(originals.read(result_row))
    need(result['schema']=='hepta.native-guard.property-r8-freeze-result.v1'
         and result['state']=='REVIEWED_PROPERTY_POLICY_R8_HOST_SOURCES_FROZEN_NOT_PHONE_QUALIFIED'
         and result['all_inputs_rechecked'] is True and result['all_output_files_read_back'] is True
         and result['runtime_path_count']==32 and result['root_source_path_count']==3
         and result['phone_operations']==result['active_policy_writes']==result['native_submissions']==0,
         'actual completed R8 host freeze required')
    source_raw = originals.read(SOURCE)
    interface_raw = originals.read(INTERFACE)
    template_module = module(SOURCE, source_raw, 'reviewed_final_cascade_template')
    validate_source_manifests(originals, template_module)
    adoption_row, verifier_row = result['policy_adoption'], result['verifier']
    adoption_raw = originals.read(adoption_row)
    adoption = strict(adoption_raw)
    verifier = module(verifier_row, originals.read(verifier_row), 'reviewed_actual_property_verifier')
    verified = verifier.verify_adoption(adoption_raw, read_pinned=originals.read)
    runtime_row, combination_row = result['runtime_manifest'], result['combination']
    runtime = strict(originals.read(runtime_row))
    combination = strict(originals.read(combination_row))
    actual = originals.read(adoption['actual_export'])
    need(verified['current_adoption_sha256']==adoption_row['sha256']
         and verified['runtime_policy']=={key:adoption['actual_export'][key] for key in ('bytes','sha256')}
         and result['actual_adopted_policy_sha256']==sha(actual)==combination['live_policy_sha256']
         and runtime['current_policy_sha256']==sha(actual)
         and runtime['current_combination_sha256']==combination_row['sha256']
         and runtime['explicit_policy_adoption_sha256']==adoption_row['sha256'], 'actual generation mismatch')
    derivation = strict(originals.read(result['derivation']))
    scope_row = derivation['finalization']['scope_decision']
    need(scope_row['sha256']==verified['root_scope_decision_sha256'], 'actual scope mismatch')
    originals.read(scope_row); originals.read(adoption['full_rule'])
    frozen = {'schema':'hepta.property-policy.final-pin-freeze.v1',
        'runtime_manifest':runtime_row, 'component_combination':combination_row,
        'policy_adoption':adoption_row, 'policy_verifier':verifier_row,
        'actual_policy':verified['runtime_policy'], 'scope_decision':scope_row,
        'full_rule':adoption['full_rule']}
    before = b'FINALIZATION = None\n'
    after = ('FINALIZATION = '+repr(frozen)+'\n').encode()
    need(source_raw.count(before)==1, 'one unchanged finalization slot required')
    finalized = source_raw.replace(before, after, 1)
    need(finalized.replace(after, before, 1)==source_raw, 'source increment not reversible')
    compile(finalized, str(args.out/'source/derive_final_cascade_property_r8.py'), 'exec')
    final_module = module(desc(args.out/'source/derive_final_cascade_property_r8.py', finalized), finalized,
                          'final_actual_cascade_source')
    need(final_module.finalization()==frozen, 'actual source finalization validation failed')
    files = {'source/derive_final_cascade_property_r8.py':finalized,
             'source/write_final_seal_interface_property_r8.py':interface_raw,
             'reference/derive_final_cascade_property_r8.original.py':source_raw,
             'FINALIZATION.json':enc(frozen), 'RUNTIME-FREEZE-RESULT-DESCRIPTOR.json':enc(result_row)}
    for name, pin in template_module.TEMPLATE_PINS.items():
        need(Path(name).name==name, 'simple template filename required')
        row = {'path':str(PARENT/'templates'/name), **pin}
        files['templates/'+name] = originals.read(row)
    out = args.out
    need(out.is_absolute() and out.parent.resolve(strict=True)==out.parent
         and not out.exists() and not out.is_symlink(), 'new canonical host source package required')
    originals.recheck()
    entry = {'executable':'/usr/bin/python3', 'argv':['-I','-B',
        str(out/'source/derive_final_cascade_property_r8.py'),'--execute-host-cascade-once'],
        'phone_calls':0, 'policy_writes':0}
    if not args.execute_host_preparation:
        print(json.dumps({'state':'HOST_SOURCE_PREVIEW_NO_WRITES', 'file_count':len(files),
                          'finalization':frozen, 'entry':entry}, sort_keys=True)); return 0
    os.umask(0o077); out.mkdir(mode=0o700)
    rows = []
    for name, raw in sorted(files.items()):
        path = out/name; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        row = create(path, raw); rows.append({'path':name, 'bytes':row['bytes'], 'sha256':row['sha256']})
    manifest = create(out/'SOURCE-MANIFEST.json', enc({
        'schema':'hepta.root.actual-property-cascade-source-package.v1', 'files':rows,
        'state':'ACTUAL_PINS_HOST_SOURCE_ONLY', 'phone_calls':0, 'policy_writes':0}))
    entry_row = create(out/'EXECUTION-ENTRY.json', enc(entry))
    originals.recheck()
    result = create(out/'PREPARATION-RESULT.json', enc({
        'state':'ACTUAL_FINAL_CASCADE_SOURCES_CREATED_HOST_ONLY', 'source_manifest':manifest,
        'entry':entry_row, 'runtime_freeze':result_row, 'finalization':frozen,
        'phone_calls':0, 'policy_writes':0, 'cascade_executed':False}))
    print(json.dumps({'result':result, 'entry':entry}, sort_keys=True)); return 0


if __name__=='__main__':
    raise SystemExit(main())
