#!/usr/bin/env python3
"""Host-only exact-source R5 consumer preview; no actual runtime pin is bound."""
from pathlib import Path
import ast
import difflib
import hashlib
import json
import types

HERE = Path(__file__).resolve().parent
REVIEW = HERE.parent
ORIGINAL = {'bytes':243806, 'sha256':'3de6208604022671d4db21e2b479e3ef4d4bba4aaa9d2faa360f1865aec428da'}
LATE = {'bytes':181669, 'sha256':'0a9f52cf8fb71177d0816f561cce279811a7182e986c12912d9431bde5997cda'}
PACKAGE = {'bytes':57078, 'sha256':'990c726a1fff139761494cc19cf091deb269201f27ea947dda4a5833e3a72f2a'}
COMBINATION = {'bytes':4695, 'sha256':'7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}


def pin(raw):
    return {'bytes':len(raw), 'sha256':hashlib.sha256(raw).hexdigest()}


def enc(value):
    return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()


def read(path, expected=None):
    raw=path.read_bytes()
    if expected is not None:
        assert pin(raw)=={key:expected[key] for key in ('bytes','sha256')}, str(path)
    return raw


def write(path, raw):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as f:
        f.write(raw)
    assert path.read_bytes()==raw
    return {'path':str(path.relative_to(HERE)), **pin(raw)}


def main():
    original=read(HERE/'references/release_boundaries.original.py',ORIGINAL)
    text=original.decode()
    module=types.ModuleType('original_release_consumer_for_pure_source_preview')
    module.__file__=str(HERE/'references/release_boundaries.original.py')
    exec(compile(original,module.__file__,'exec'),module.__dict__)
    package_raw=read(REVIEW/'R5-root/runtime/MANIFEST.json',PACKAGE)
    manifest=json.loads(package_raw)
    source={row['path']:read(REVIEW/'R5-root/runtime'/row['path'],row) for row in manifest['files']}
    assert pin(source['source/late_boundary.py'])==LATE
    transfer=json.loads(read(REVIEW/'shared-v3-original-transfer.json'))
    combinations=[row for row in transfer if Path(row['path']).name=='COMBINATION.json']
    assert len(combinations)==1
    combination_raw=combinations[0]['text'].encode()
    assert pin(combination_raw)==COMBINATION
    assert {key:combinations[0][key] for key in ('bytes','sha256')}==COMBINATION
    with module.component_modules({'package_sources':source}) as modules:
        late=modules['late_boundary']
        late.validate_current_package_manifest(manifest)
        records=late.reviewed_source_parent_records()
        assert records==json.loads(read(REVIEW/'R5-agent-late/SOURCE-PARENT-RECORDS.json'))
        chain=late.MAX_CHAIN
        roles=late.COMPONENT_ROLE_CAP
        assert type(chain) is int and chain==9+len(records)+2
        assert type(roles) is int and roles==3*(chain+2)
        assert manifest['native_chain_cap']==chain and manifest['component_role_cap']==roles
    changes=[]
    def replace(old,new):
        nonlocal text
        assert old!=new and text.count(old)==1, old[:120]
        text=text.replace(old,new)
        changes.append((old,new))
    old_constants="PACKAGE_SHA = '72d6dcb4c20547549debad6ef55001aa5c8d115574ac222312b158f9722e2515'\nPACKAGE_FILE_COUNT = 37\nCURRENT_COMBINATION_SHA = '02c2a26af79e367afe48cb1bc378808f3c5a32800548498a0262ea0265c9f708'"
    new_constants=("PACKAGE_SHA = None\nPACKAGE_FILE_COUNT = "+str(len(source))
        +"\nCURRENT_COMBINATION_SHA = "+repr(COMBINATION['sha256'])
        +"\nCURRENT_COMPONENT_CHAIN_LENGTH = "+str(chain)
        +"\nCOMPONENT_ROLE_BUDGET = "+str(roles))
    replace(old_constants,new_constants)
    tree=ast.parse(original)
    old_function=next(node for node in tree.body if isinstance(node,ast.FunctionDef)
                      and node.name=='validate_final_component_prefix')
    lines=original.decode().splitlines(keepends=True)
    old_prefix=''.join(lines[old_function.lineno-1:old_function.end_lineno])
    replacement=read(HERE/'current_prefix_replacement.py').decode()
    replace(old_prefix,replacement)
    replace("and type(PACKAGE_FILE_COUNT) is int and PACKAGE_FILE_COUNT == 37",
            "and type(PACKAGE_FILE_COUNT) is int and PACKAGE_FILE_COUNT > 0\n         and type(CURRENT_COMPONENT_CHAIN_LENGTH) is int and CURRENT_COMPONENT_CHAIN_LENGTH > 0\n         and type(COMPONENT_ROLE_BUDGET) is int and COMPONENT_ROLE_BUDGET > 0")
    replace("if (boundary['schema'] == late.SCHEMA\n                    and not late.is_pre_policy_ancestor(boundary)",
            "if (boundary['schema'] == late.SCHEMA\n                    and not late.is_source_parent_ancestor(boundary)\n                    and not late.is_pre_policy_ancestor(boundary)")
    replace("validate_final_component_prefix(chain, late,retained)",
            "validate_final_component_prefix(chain, late, retained, read_pinned=body,\n            combination_descriptor=descriptor(combination_raw))")
    raw=text.encode()
    ast.parse(raw)
    inverse=text
    for old,new in reversed(changes):
        assert inverse.count(new)==1
        inverse=inverse.replace(new,old)
    assert inverse.encode()==original
    compiled=types.ModuleType('unbound_release_consumer_preview')
    compiled.__file__=str(HERE/'source/release_boundaries.py')
    exec(compile(raw,compiled.__file__,'exec'),compiled.__dict__)
    assert compiled.PACKAGE_SHA is None
    try:
        compiled.validate_component(None,None)
    except ValueError as error:
        assert str(error)=='current policy component runtime has not been frozen and reviewed'
    else:
        raise AssertionError('unbound consumer admitted component input')
    patch=''.join(difflib.unified_diff(original.decode().splitlines(keepends=True),
        text.splitlines(keepends=True),fromfile='references/release_boundaries.original.py',
        tofile='source/release_boundaries.py'))
    outputs=[write(HERE/'source/release_boundaries.py',raw),write(HERE/'SOURCE.patch',patch.encode())]
    result={'schema':'hepta.fc33.release-consumer-source-derivation.v1',
        'state':'UNBOUND_SOURCE_CANDIDATE_NOT_FROZEN_OR_QUALIFIED',
        'original':ORIGINAL,'late_source':LATE,'observed_runtime_source_candidate':PACKAGE,
        'actual_shared_combination':COMBINATION,'package_pin':None,
        'package_file_count':len(source),'actual_source_parent_count':len(records),
        'current_component_chain_length':chain,'component_role_budget':roles,
        'historical_qualification_grants_current_tuple_credit':False,
        'replacement_count':len(changes),'full_source_inverse_verified':True,
        'unbound_rejected_before_component_input':True,'phone_calls':0,
        'actual_BUILD':False,'actual_install':False,'actual_READY':False,
        'source_changes':[
            'explicit unbound package and actual reviewed combination/count literals',
            'pure closed-current original lease validation and exact cumulative root growth',
            'exact source-parent prefix classification without new qualification credit',
            'exclude source-parent closure from new current closure source pin',
            'read two new lease originals through existing original-copy callback'],
        'outputs':outputs}
    write(HERE/'DERIVATION.json',enc(result))
    print(json.dumps({'source':pin(raw),'patch':pin(patch.encode()),'chain_length':chain,
        'component_role_budget':roles,'package_pin':None,'state':result['state']},sort_keys=True))


if __name__=='__main__':
    main()
