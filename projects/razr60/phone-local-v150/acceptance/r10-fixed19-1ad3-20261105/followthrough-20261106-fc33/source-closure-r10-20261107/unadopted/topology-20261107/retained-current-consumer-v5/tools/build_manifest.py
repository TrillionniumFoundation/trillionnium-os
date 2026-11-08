#!/usr/bin/env python3
"""Deterministic source-construction manifest; no private proof replay or I/O."""
from __future__ import annotations
import argparse
import ast
import json
from pathlib import Path
import types

PACKAGE=Path(__file__).resolve().parents[1]


def graph(raw,entries):
    definitions={node.name:node for node in ast.parse(raw).body if isinstance(node,(ast.FunctionDef,ast.ClassDef))}
    edges={name:sorted({node.id for node in ast.walk(value) if isinstance(node,ast.Name)} & set(definitions))
           for name,value in definitions.items()}
    seen=set();pending=[name for name in entries if name in definitions]
    while pending:
        name=pending.pop()
        if name in seen:continue
        seen.add(name);pending.extend(edges[name])
    return {'entries':[name for name in entries if name in definitions],
        'reachable_function_count':sum(isinstance(definitions[name],ast.FunctionDef) for name in seen),
        'reachable_class_count':sum(isinstance(definitions[name],ast.ClassDef) for name in seen),
        'reachable_names':sorted(seen),'edges':{name:edges[name] for name in sorted(seen)},
        'static_name_reference_overapproximation':True,'full_production_IO_metering':False,
        'explicit_dynamic_edges':['v3 source-parent factory and result consumer',
            'bound v2 R7/R8/R9 reader construction and nested scopes/inventories',
            'new runtime adapter facade and same-instance result consumer',
            'retained-stage full9 original provider','retained-source/archive exact3 original provider',
            'unchanged historical sidebranch/property/environment reader modules',
            'stdlib Path resolve/stat/readlink plus common helper implementations']}


def build(base,v3,v4):
    raw=(PACKAGE/'candidate/retained_current_consumer.py').read_bytes()
    loader_raw=(PACKAGE/'candidate/bound_loader.py').read_bytes()
    loader=types.ModuleType('manifest_bound_v5_loader');exec(compile(loader_raw,'<manifest-v5-loader>','exec'),loader.__dict__)
    candidate=loader.load_bound(raw,raw)
    files={'frozen_current':base/'originals/late_boundary.r10.original.py',
        'historical_adapter':PACKAGE/'originals/retained_transport_r9_adapter.original.py',
        'v4_constructor':v4/'candidate/source_parent_consumer.py','v4_loader':v4/'candidate/bound_loader.py',
        'v3_constructor':v3/'candidate/source_parent_reader.py','v3_loader':v3/'candidate/bound_loader.py',
        'v2_selector':base/'candidate/derived/reader_selector.py','v2_loader':base/'candidate/derived/bound_selector_loader.py'}
    values={name:path.read_bytes() for name,path in files.items()}
    for name,pin_name in [('frozen_current','FROZEN_CURRENT'),('historical_adapter','ORIGINAL_ADAPTER'),
        ('v4_constructor','V4_CONSTRUCTOR'),('v4_loader','V4_LOADER'),('v3_constructor','V3_CONSTRUCTOR'),
        ('v3_loader','V3_LOADER'),('v2_selector','V2_SELECTOR'),('v2_loader','V2_LOADER')]:
        candidate.need(candidate.pin(values[name])==getattr(candidate,pin_name),'actual sealed source dependency '+name)
    v4module=candidate.module(values['v4_loader'],'manifest_v4_loader').load_bound(values['v4_constructor'],values['v4_constructor'])
    inv=candidate.function_source((base/'candidate/derived/source_parent_inventory_value.py').read_bytes(),'inventory_value')
    scope=candidate.function_source((base/'candidate/derived/retained_r8_verify_complete_scope.py').read_bytes(),'verify_complete_scope')
    source4,receipt4=v4module.derive_source(values['frozen_current'],inv)
    source5,receipt5=candidate.derive_current(source4)
    adapter5,adapter_receipt=candidate.derive_adapter(values['historical_adapter'])
    candidate.module(values['v2_loader'],'manifest_v2_loader').make_selector(selector_source=values['v2_selector'],
        implementation_source=values['v2_selector'],inventory_function=inv,scope_function=scope)
    call_graph=graph(source5,candidate.METHODS)
    candidate.need(not {'main','publish','verify_current','chain_originals','retired_originals','current_inventory'}
                   & set(call_graph['reachable_names']),'selected pure entry closure excludes runtime/publication/observation entrypoints')
    return {'schema':'hepta.UNADOPTED.retained-current-construction.v5','constructor_source':candidate.pin(raw),
        'bound_loader_source':candidate.pin(loader_raw),'exact_source_dependencies':{name:candidate.pin(value) for name,value in values.items()},
        'inventory_function':candidate.pin(inv),'scope_function':candidate.pin(scope),
        'intermediate_v4_source_construction':candidate.pin(source4),'actual_current_execution_source':candidate.pin(source5),
        'actual_adapter_execution_source':candidate.pin(adapter5),'v4_transformation':receipt4,
        'current_transformation':receipt5,'adapter_transformation':adapter_receipt,
        'current_static_call_graph':call_graph,'methods':list(candidate.METHODS),
        'same_guarded_current_retained_consumers_composed':True,'original_sources_or_receipts_modified':False,
        'validation_result_cache':False,'production_adopted':False,'runtime_admission':False,'current_native_case_credit':0,
        'complete_production_IO_metering_verified':False,'whole_stage_budget_verified':False}


def main():
    p=argparse.ArgumentParser();p.add_argument('--base',type=Path,required=True)
    p.add_argument('--v3',type=Path);p.add_argument('--v4',type=Path);p.add_argument('--check',action='store_true')
    p.add_argument('--output',type=Path);a=p.parse_args()
    if a.check and a.output:p.error('--check and --output are exclusive')
    base=a.base.resolve();v3=a.v3.resolve() if a.v3 else base/'source-parent-v3'
    v4=a.v4.resolve() if a.v4 else base/'source-parent-consumer-v4'
    value=build(base,v3,v4);raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    if a.check:
        if raw!=(PACKAGE/'RETAINED-CURRENT-CANDIDATE-MANIFEST-v5.json').read_bytes():
            raise ValueError('saved current-retained construction manifest differs')
        print(json.dumps({'state':'PASS','current':value['actual_current_execution_source'],
            'adapter':value['actual_adapter_execution_source'],'whole_byte_inverse_verified':True,
            'production_adopted':False,'runtime_admission':False},sort_keys=True))
    elif a.output:
        with a.output.open('xb') as stream:stream.write(raw)
    else:print(raw.decode(),end='')


if __name__=='__main__':main()
