#!/usr/bin/env python3
"""Reconstruct v3 source identities without private fixtures or artifact writes."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import types

ROOT=Path(__file__).resolve().parents[1]


def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def build(base):
    constructor=(ROOT/'candidate/source_parent_reader.py').read_bytes()
    loader_raw=(ROOT/'candidate/bound_loader.py').read_bytes()
    loader=types.ModuleType('manifest_bound_loader')
    exec(compile(loader_raw,'<manifest-bound-loader>','exec'),loader.__dict__)
    module=loader.load_bound(constructor,constructor)
    old=(base/'originals/source_parent_late_boundary_r4.original.py').read_bytes()
    fragment=(base/'candidate/derived/source_parent_inventory_value.py').read_bytes()
    helper=module.function_source(fragment,'inventory_value')
    derived,receipt=module.derive_source(old,helper)
    anchor=(base/'originals/late_boundary.r10.original.py').read_bytes()
    literals={}
    for node in ast.parse(anchor).body:
        if isinstance(node,ast.Assign):
            for target in node.targets:
                if isinstance(target,ast.Name):
                    try:literals[target.id]=ast.literal_eval(node.value)
                    except (ValueError,TypeError):pass
    assert literals['SOURCE_PARENT_READER_DEPENDENCIES']==module.DEPENDENCIES
    return {'schema':'hepta.UNADOPTED.source-parent-candidate-manifest.v3',
        'state':'SOURCE_CONSTRUCTED_NOT_ADOPTED',
        'constructor':{'path':'candidate/source_parent_reader.py',**pin(constructor)},
        'bound_loader':{'path':'candidate/bound_loader.py',**pin(loader_raw)},
        'base_original_source':{'path':'originals/source_parent_late_boundary_r4.original.py',**pin(old)},
        'base_original_current_factory':{'path':'originals/late_boundary.r10.original.py',**pin(anchor)},
        'base_inventory_fragment':{'path':'candidate/derived/source_parent_inventory_value.py',**pin(fragment)},
        'actual_derived_whole_source':pin(derived),
        'historical_dependency_pins':{k:dict(v) for k,v in module.DEPENDENCIES.items()},
        'historical_context':{'combination_sha256':module.COMBINATION,'package_sha256':module.PACKAGE,
            'policy_sha256':module.POLICY,'adoption_sha256':module.POLICY_ADOPTION},
        'derivation':receipt,
        'new_reader_schema':'hepta.UNADOPTED.derived-source-parent-reader.v1',
        'new_result_schema':'hepta.UNADOPTED.derived-source-parent-result.v1',
        'historical_result_location':'historical_result (data projection only)',
        'historical_reader_functions_changed':True,
        'original_source_bytes_changed':False,'original_receipts_rewritten':False,
        'validation_result_cache':False,'live_observation_cache':False,
        'production_selector_adopted':False,'production_outer_exact_original_binding_replaced':False,
        'complete_production_IO_metering_verified':False,'whole_stage_budget_verified':False,
        'runtime_admission':False,'current_native_case_credit':0,
        'portable_command':'HEPTA_TOPOLOGY_SYNTHETIC_ONLY=1 python3 -B source-parent-v3/tests/test_source_parent_candidate.py --base .',
        'constructor_command':'python3 -B source-parent-v3/tools/build_manifest.py --base .'}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--base',type=Path,required=True);p.add_argument('--output',type=Path)
    a=p.parse_args();text=json.dumps(build(a.base.resolve()),ensure_ascii=False,sort_keys=True,indent=2)+'\n'
    if a.output:
        with a.output.open('x',encoding='utf-8') as out:out.write(text)
    print(text,end='')
