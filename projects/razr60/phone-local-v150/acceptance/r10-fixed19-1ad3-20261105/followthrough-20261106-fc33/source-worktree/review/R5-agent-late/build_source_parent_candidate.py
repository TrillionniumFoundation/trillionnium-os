#!/usr/bin/env python3
"""Deterministically extend only reviewed R4 LATE; no phone access or dispatch."""
from pathlib import Path
import ast
import difflib
import hashlib
import json
import pprint

HERE = Path(__file__).resolve().parent
OLD = HERE.parent/'R4/runtime'
OLD_PIN = {'bytes': 153138, 'sha256': '27350db238c5ca31796af91c77b5c2fdb9d02b838d35140f759df907903d4fa4'}
NEW_COMBINATION = '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'


def need(value, reason):
    if not value:
        raise ValueError(reason)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)+'\n').encode()


def replace_once(text, old, new):
    need(text.count(old) == 1, 'unique exact replacement: '+old[:100])
    return text.replace(old, new, 1)


def replace_function(text, name, body):
    nodes = [n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef) and n.name == name]
    need(len(nodes) == 1, 'one function: '+name)
    n = nodes[0]; lines = text.splitlines(keepends=True)
    return ''.join(lines[:n.lineno-1])+body.rstrip()+'\n'+''.join(lines[n.end_lineno:])


def main():
    raw = (OLD/'source/late_boundary.py').read_bytes()
    need(pin(raw) == OLD_PIN, 'exact frozen R4 original')
    retained = HERE/'runtime/reference/source_parent_late_boundary_r4.py'
    need(retained.read_bytes() == raw, 'byte-identical explicit source-parent reference')
    original = text = raw.decode()
    previous_raw = (HERE/'history-inputs/ACTUAL-PREVIOUS-INPUT.original.json').read_bytes()
    head_raw = (HERE/'history-inputs/NEG01-BOUNDARY.original.json').read_bytes()
    request_raw = (HERE/'history-inputs/CAPTURE-REQUEST.original.json').read_bytes()
    need(pin(previous_raw) == {'bytes': 1426, 'sha256': 'fcdf8a456f663d6963d3cd9caf231a210aad92d8f5e192a71917381d10ea10f0'}, 'actual previous original')
    need(pin(head_raw) == {'bytes': 29342, 'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'}, 'actual source-parent boundary')
    need(pin(request_raw) == {'bytes': 42253, 'sha256': '3d716252466d6afe1d582047b221816394bf5740399ade9da0b9678da6002056'}, 'actual complete capture request')
    prev, head, request = map(json.loads, (previous_raw, head_raw, request_raw))
    manifest = json.loads((OLD/'MANIFEST.json').read_bytes())
    index = {r['path']: r for r in manifest['files']}
    need(len(index) == 37 and pin((OLD/'MANIFEST.json').read_bytes())['sha256'] == head['package_sha256'], 'actual old package identity')
    need(prev['late_boundary'] == request['native_boundaries'][0]
         and prev['identity'] == head['scope'] and prev['component_qualified'] is True
         and head['component_qualified'] is True and head['case_id'] == 'NEG-01'
         and len(request['native_boundaries']) == 10 and head['prior_boundary'] == request['native_boundaries'][1],
         'one actual closed NEG01 plus nine original failures')
    homes = head['retained_stage_parent_profiles']['allowed_new_homes']
    need(len(homes) == 1, 'actual source-parent one completed home')
    home = Path(homes[0]); label = home.name
    private_roots = [f'/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/{label}/executor',
                     str(home), '/proc/1/root/data/local/tmp/hepta-native-guard-'+head['nonce']]
    need(head['roots'][-3:] == private_roots and len(head['roots']) == 44,
         'actual source-parent exact three-root addition')
    record = {k: head[k] for k in ('inventory', 'closure', 'case_id', 'nonce', 'scope', 'roots',
        'prior_boundary', 'component_qualified', 'native_status', 'actual_native_calls', 'owner_request_sha256')}
    record.update(boundary=prev['late_boundary'], label=label, home=str(home), private_roots=private_roots,
        closure_source_sha256=index['source/close_component.py']['sha256'],
        closed_previous={'path': str(Path(prev['closed_component']['path']).parent/'ACTUAL-PREVIOUS-INPUT.json'), **pin(previous_raw)})
    dependency_names = ['source/component_common.py', 'reference/component_common_r5.py',
        'reference/policy_parent_late_boundary_r4.py', 'reference/environment_parent_late_boundary_r6.py',
        'reference/property_parent_late_boundary_r7.py', 'reference/non_native_attempt05.py',
        'reference/non_native_diag02.py', 'reference/retained_unstarted_stage_final02.py',
        'reference/attempt05-AFTER-INVENTORY.original.json', 'reference/attempt05-CLOSURE.original.json',
        'reference/attempt05-SIDE-PROOF.original.json', 'reference/diag02-AFTER-INVENTORY.original.json',
        'reference/diag02-CLOSURE.original.json', 'reference/diag02-SIDE-PROOF.original.json']
    dependencies = {n: {k:index[n][k] for k in ('bytes','sha256')} for n in dependency_names}
    dependencies['reference/source_parent_late_boundary_r4.py'] = OLD_PIN
    for name, desc in dependencies.items():
        path = retained if name == 'reference/source_parent_late_boundary_r4.py' else OLD/name
        need(pin(path.read_bytes()) == desc, 'actual complete immutable dependency: '+name)
    constants = {
        'SOURCE_PARENT_REFERENCE': 'reference/source_parent_late_boundary_r4.py',
        'SOURCE_PARENT_READER_BYTES': OLD_PIN['bytes'],
        'SOURCE_PARENT_READER_SHA256': OLD_PIN['sha256'],
        'SOURCE_PARENT_COMMON_SHA256': dependencies['source/component_common.py']['sha256'],
        'SOURCE_PARENT_COMBINATION_SHA256': head['combination_sha256'],
        'SOURCE_PARENT_PACKAGE_SHA256': head['package_sha256'],
        'SOURCE_PARENT_POLICY_SHA256': manifest['current_policy_sha256'],
        'SOURCE_PARENT_POLICY_ADOPTION_SHA256': manifest['explicit_policy_adoption_sha256'],
        'SOURCE_PARENT_CLOSURE_SHA256': record['closure_source_sha256'],
        'SOURCE_PARENT_RECORDS': (record,),
        'SOURCE_PARENT_READER_DEPENDENCIES': dependencies,
        'HISTORICAL_FAILED_BOUNDARY_COUNT': 9,
        'MAX_NEW_CURRENT_CASE_PREFIX': 2,
        'RETAINED_BASE_ROOT_COUNT': len(head['roots'])-3*len(homes),
    }
    block = ('# Exactly one previously closed source tuple, not current qualification.\n'
        + ''.join(name+' = '+pprint.pformat(value, width=110, sort_dicts=True)+'\n' for name,value in constants.items())
        + 'SOURCE_PARENT_COUNT = len(SOURCE_PARENT_RECORDS)\n'
        + 'SOURCE_PARENT_HOME_COUNT = len({row[\'home\'] for row in SOURCE_PARENT_RECORDS})\n'
        + 'SOURCE_PARENT_INVENTORY_ROOT_COUNT = len(SOURCE_PARENT_RECORDS[0][\'roots\'])\n'
        + 'MAX_CHAIN = HISTORICAL_FAILED_BOUNDARY_COUNT + SOURCE_PARENT_COUNT + MAX_NEW_CURRENT_CASE_PREFIX\n'
        + 'COMPONENT_ROLE_CAP = 3*(MAX_CHAIN+2)\n'
        + 'MAX_FIXTURE_ROOTS = MAX_CHAIN+2\n'
        + 'MAX_CURRENT_INVENTORY_ROOTS = SOURCE_PARENT_INVENTORY_ROOT_COUNT+3*MAX_NEW_CURRENT_CASE_PREFIX\n')
    text = replace_once(text, 'MAX_CHAIN = 11\n', block)
    text = replace_once(text, 'REVIEWED_CURRENT_COMBINATION_SHA256 = '+repr(head['combination_sha256']),
                        'REVIEWED_CURRENT_COMBINATION_SHA256 = '+repr(NEW_COMBINATION))
    text = replace_once(text,
        '    C.need(REVIEWED_CURRENT_COMBINATION_SHA256 != LEGACY_COMBINATION_SHA256,',
        '    C.need(REVIEWED_CURRENT_COMBINATION_SHA256 != SOURCE_PARENT_COMBINATION_SHA256\n'
        '           and REVIEWED_CURRENT_COMBINATION_SHA256 != LEGACY_COMBINATION_SHA256,')
    text = replace_once(text, 'and package_sha256 not in (V3_RUNTIME_DIAGNOSTIC_PACKAGE_SHA256,',
                        'and package_sha256 not in (SOURCE_PARENT_PACKAGE_SHA256, V3_RUNTIME_DIAGNOSTIC_PACKAGE_SHA256,')
    text = replace_once(text,
        '    if C.descriptor(raw) == {k:reviewed_v3_runtime_diagnostic_ancestor()[\'boundary\'][k]\n',
        '    if _source_parent_original(raw, original_descriptor) is not None:\n'
        '        return source_parent_boundary_from_original(raw, original_descriptor=original_descriptor)\n'
        '    if C.descriptor(raw) == {k:reviewed_v3_runtime_diagnostic_ancestor()[\'boundary\'][k]\n')
    text = replace_once(text, '    C.need(checked[\'nonce\'] not in (V3_RUNTIME_DIAGNOSTIC_NONCE,',
        '    C.need(checked[\'nonce\'] not in (*(r[\'nonce\'] for r in reviewed_source_parent_records()), V3_RUNTIME_DIAGNOSTIC_NONCE,')
    text = replace_once(text,
        '    retained = _retained_property_parent_original(raw, original_descriptor)\n'
        '    if retained is not None:\n        index, _record = retained\n',
        '    if _source_parent_original(raw, original_descriptor) is not None:\n'
        '        return source_parent_closed_boundary_originals(raw, inventory_raw, closure_raw,\n'
        '            original_descriptor=original_descriptor)\n'
        '    retained = _retained_property_parent_original(raw, original_descriptor)\n'
        '    if retained is not None:\n        index, _record = retained\n')
    text = replace_function(text, 'require_failed_ancestor_tail', (HERE/'tail_replacement.py').read_text())
    text = replace_once(text, 'len(component_roles)+3 <= 39', 'len(component_roles)+3 <= COMPONENT_ROLE_CAP')
    text = replace_once(text, 'type(roles) is list and len(roles) <= 39',
                        'type(roles) is list and len(roles) <= COMPONENT_ROLE_CAP')
    text = replace_once(text, 'Pure validation against this complete admitted native prefix, at most two homes.',
                        'Pure validation of exact source-parent homes plus at most two new homes.')
    text = replace_once(text,
        '    C.need(0<=len(homes)<=2 and len(current[\'roots\'])==41+3*counted\n',
        '    C.need(set(source_parent_homes()) <= set(homes)\n'
        '           and SOURCE_PARENT_HOME_COUNT<=len(homes)<=SOURCE_PARENT_HOME_COUNT+MAX_NEW_CURRENT_CASE_PREFIX\n'
        '           and len(summary[\'inventory\'][\'roots\'])==RETAINED_BASE_ROOT_COUNT\n'
        '           and len(current[\'roots\'])==len(summary[\'inventory\'][\'roots\'])+3*counted\n')
    text = replace_once(text,
        "    current_context(boundary['combination_sha256'],boundary['package_sha256'])\n",
        "    if is_source_parent_ancestor(boundary):\n"
        "        record=reviewed_source_parent_records()[0]\n"
        "        C.need(C.descriptor(C.encoded(boundary))=={k:record['boundary'][k]for k in('bytes','sha256')}\n"
        "               and boundary['inventory']==record['inventory']\n"
        "               and C.descriptor(C.encoded(inventory))=={k:record['inventory'][k]for k in('bytes','sha256')},\n"
        "               'only the exact newest source-parent complete inventory can be selected')\n"
        "        source_parent_boundary_from_original(C.encoded(boundary),original_descriptor=record['boundary'])\n"
        "        current_retained_stage_binding(boundary)\n"
        "        preserve_retained_unstarted_stage(inventory,retained=retained)\n"
        "        return inventory,record['inventory'],'exact_previous_source_component_head_with_retained_unstarted_stage'\n"
        "    current_context(boundary['combination_sha256'],boundary['package_sha256'])\n")
    text = replace_once(text, "'reference/retained_unstarted_stage_final02.py'])",
                        "'reference/retained_unstarted_stage_final02.py', SOURCE_PARENT_REFERENCE])")
    text = text.replace('_verify_current_package37_original', '_verify_current_package38_original')
    text = replace_once(text, "5 <= len(names) <= 37, 'package inventory bound'",
                        "len(names) == 38, 'exact current 38-member package inventory required'")
    text = replace_once(text, 'len(rows) == 37 and set(index) == CURRENT_RUNTIME_PATHS',
                        'len(rows) == 38 and set(index) == CURRENT_RUNTIME_PATHS')
    text = replace_once(text, "manifest.get('runtime_file_count') == 37", "manifest.get('runtime_file_count') == 38")
    text = replace_once(text, "manifest.get('current_complete_inventory_root_count') == 41",
                        "manifest.get('current_complete_inventory_root_count') == SOURCE_PARENT_INVENTORY_ROOT_COUNT")
    text = replace_once(text, "manifest.get('maximum_complete_inventory_roots_after_two_final_NEG_cases') == 47",
                        "manifest.get('maximum_complete_inventory_roots_after_two_final_NEG_cases') == MAX_CURRENT_INVENTORY_ROOTS")
    text = replace_once(text, "manifest.get('component_role_cap') == 39", "manifest.get('component_role_cap') == COMPONENT_ROLE_CAP")
    text = replace_once(text, "manifest.get('native_chain_cap') == 11", "manifest.get('native_chain_cap') == MAX_CHAIN")
    text = replace_once(text, "manifest.get('historical_native_boundary_count') == 9",
                        "manifest.get('historical_native_boundary_count') == HISTORICAL_FAILED_BOUNDARY_COUNT+SOURCE_PARENT_COUNT")
    text = replace_once(text, "explicit current 37-member package and finite resource contract required",
                        "explicit current 38-member package and actual source-parent resource contract required")
    text = replace_once(text,
        "    C.need({k:index['source/component_common.py'][k] for k in ('bytes','sha256')} ==\n",
        "    C.need(all(manifest.get(key)==value for key,value in manifest_source_parent_binding().items())\n"
        "           and {k:index[SOURCE_PARENT_REFERENCE][k] for k in ('bytes','sha256')} ==\n"
        "               {'bytes':SOURCE_PARENT_READER_BYTES,'sha256':SOURCE_PARENT_READER_SHA256},\n"
        "           'manifest must preserve exact source-parent provenance without current tuple credit')\n"
        "    C.need({k:index['source/component_common.py'][k] for k in ('bytes','sha256')} ==\n")
    text = replace_once(text, 'Only this exact new 37-member generation; historical Common remains C32.',
                        'Only this exact new 38-member generation; historical Common remains C32.')
    text = replace_once(text, 'Read one current final component or one of nine exact retained failed originals.',
                        'Read a new component, the exact prior source prefix, or nine fixed failed originals.')
    extension = (HERE/'source_parent_extension.py').read_text()
    text = replace_once(text, "if __name__ == '__main__':\n", extension+"\n\nif __name__ == '__main__':\n")
    ast.parse(text)
    out = HERE/'runtime/source/late_boundary.py'; out.parent.mkdir(parents=True,exist_ok=True);out.write_text(text)
    (HERE/'SOURCE.patch').write_text(''.join(difflib.unified_diff(original.splitlines(keepends=True), text.splitlines(keepends=True),
        fromfile='R4/runtime/source/late_boundary.py', tofile='R5/runtime/source/late_boundary.py')))
    (HERE/'SOURCE-PARENT-RECORDS.json').write_bytes(encoded([record]))
    result = {'schema': 'hepta.fc33.source-parent-late-candidate.v1', 'source': pin(text.encode()), 'source_parent':OLD_PIN,
        'new_combination_sha256':NEW_COMBINATION, 'source_parent_records': [record],
        'new_runtime_files_written': 2, 'original_R4_files_modified':0,
        'source_parent_count':1,'native_chain_cap':12,'component_role_cap':42,'fixture_root_cap':14,
        'current_complete_inventory_roots':44,'maximum_complete_inventory_roots':50,
        'controls_run':False,'phone_calls':0,'current_tuple_qualified':False}
    (HERE/'CANDIDATE.json').write_bytes(encoded(result));print(json.dumps({k:v for k,v in result.items()if k!='source_parent_records'},sort_keys=True))


if __name__ == '__main__':
    main()
