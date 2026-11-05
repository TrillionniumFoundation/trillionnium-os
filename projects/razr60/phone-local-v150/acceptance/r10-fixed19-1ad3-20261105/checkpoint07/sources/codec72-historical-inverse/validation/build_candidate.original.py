#!/usr/bin/env python3
"""Create a separate, data-only historical-byte inverse and pure API capsule.

No historical/runtime module is imported, compiled or executed. The tests may
execute only the new pure validator and its exact current-source capsule.
"""
from pathlib import Path
import ast
import base64
import copy
import difflib
import gzip
import hashlib
import json
import sys
import zlib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUT = HERE / 'draft01'
PURE = ROOT / 'codec72_generation_candidate01/pure-api-preview01/source/codec72_runtime_source_increment.py'
CAPSULE = ROOT / 'codec72_generation_candidate01/pure-api-capsule-preview01/source/codec72_runtime_source_capsule.py'
PARENT = ROOT / 'codec72_generation_candidate01/runtime-source-preview02/reference/late_boundary.396d.original.py'
BASE = ROOT / 'runtime_prefix_successor_candidate01/delivery-final01/package/proof/reference/late_boundary.c50a.original.py'
EXPECTED = {
    'pure': {'bytes': 81573, 'sha256': '724507280b8180874e43dc11f93f313a712aa23cf410d0e3c49774d2a757fef5'},
    'capsule': {'bytes': 45036, 'sha256': 'e7a6707393773ae2e76b1d54e228ed18a25e82cb7549a926296d30a75f15a592'},
    'parent': {'bytes': 74287, 'sha256': '396da713d4b7cab45d0eda80b65df82d7b570440a9c9ea1f74f342b81031ec97'},
    'base': {'bytes': 66996, 'sha256': 'c50a219efd992ce1353494ace2656af20c932cbc32530b0085e38a79975d8add'},
}


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def enc(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                       allow_nan=False) + '\n').encode('utf-8')


def put(relative, raw):
    path = OUT / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)


def node(source, name):
    tree = ast.parse(source)
    matches = [n for n in tree.body if
               isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == name or
               isinstance(n, ast.Assign) and len(n.targets) == 1 and
               isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
    assert len(matches) == 1, name
    return matches[0]


def segment(source, name):
    return ast.get_source_segment(source, node(source, name))


def replace_one(source, old, new):
    assert source.count(old) == 1
    return source.replace(old, new)


def main():
    originals = {key: path.read_bytes() for key, path in (
        ('pure', PURE), ('capsule', CAPSULE), ('parent', PARENT), ('base', BASE))}
    assert {key: pin(raw) for key, raw in originals.items()} == EXPECTED
    source = originals['pure'].decode('utf-8')
    parent, base = originals['parent'], originals['base']
    source_lines, target_lines = parent.splitlines(keepends=True), base.splitlines(keepends=True)
    starts = [0]
    for line in source_lines:
        starts.append(starts[-1] + len(line))
    ends = [0]
    for line in target_lines:
        ends.append(ends[-1] + len(line))
    matcher = difflib.SequenceMatcher(None, source_lines, target_lines, autojunk=False)
    operations = []
    for tag, a, b, c, d in matcher.get_opcodes():
        operation = {'kind': 'copy' if tag == 'equal' else 'replace',
                     'start': starts[a], 'bytes': starts[b] - starts[a]}
        if tag != 'equal':
            operation['literal_utf8'] = base[ends[c]:ends[d]].decode('utf-8', 'strict')
        operations.append(operation)
    assert len(operations) == 15
    assert sum(len(o.get('literal_utf8', '').encode('utf-8')) for o in operations) == 192
    recipe = {'schema': 'hepta.codec72.exact-historical-byte-inverse.v1',
              'parent': EXPECTED['parent'], 'result': EXPECTED['base'],
              'operations': operations}
    new_constant = 'CODEC72_BASE67_LATE = ' + repr(recipe)
    helper = '''def _codec72_base_late_bytes(parent_raw):
    """Recover exact c50a bytes from actual396d as data, without executing either.

    This is one reviewed contiguous byte-range recipe, not a general patch or
    source-normalization API. Both complete input and output identities bind it.
    """
    packet = CODEC72_BASE67_LATE
    _codec72_need(type(packet) is dict and set(packet) == {
        'schema', 'parent', 'result', 'operations'} and packet['schema'] ==
        'hepta.codec72.exact-historical-byte-inverse.v1', 'codec72 historical inverse packet differs')
    _codec72_pin(parent_raw, packet['parent'], 'actual396d complete source before historical inverse')
    _codec72_need(packet['parent'] == {'bytes': 74287, 'sha256':
        '396da713d4b7cab45d0eda80b65df82d7b570440a9c9ea1f74f342b81031ec97'}
        and type(packet['result']) is dict and set(packet['result']) == {'bytes', 'sha256'}
        and type(packet['result']['bytes']) is int and packet['result'] == {'bytes': 66996, 'sha256':
        'c50a219efd992ce1353494ace2656af20c932cbc32530b0085e38a79975d8add'},
        'codec72 fixed historical input/output identity differs')
    operations = packet['operations']
    _codec72_need(type(operations) is list and len(operations) == 15,
                  'codec72 exact historical operation count differs')
    cursor = 0; result = bytearray()
    for item in operations:
        _codec72_need(type(item) is dict and item.get('kind') in ('copy', 'replace')
            and set(item) == ({'kind', 'start', 'bytes'} if item['kind'] == 'copy' else
                             {'kind', 'start', 'bytes', 'literal_utf8'})
            and type(item['start']) is int and type(item['bytes']) is int
            and item['start'] == cursor and 0 <= item['bytes'] <= len(parent_raw) - cursor,
            'codec72 historical ranges are incomplete, overlapping, reordered or malformed')
        end = cursor + item['bytes']
        if item['kind'] == 'copy':
            _codec72_need(item['bytes'] > 0, 'codec72 empty historical copy range')
            piece = parent_raw[cursor:end]
        else:
            _codec72_need(type(item['literal_utf8']) is str,
                          'codec72 exact historical literal must be UTF-8 text')
            piece = item['literal_utf8'].encode('utf-8', 'strict')
            _codec72_need(len(piece) <= 192, 'codec72 historical literal exceeds fixed recipe budget')
        _codec72_need(len(result) + len(piece) <= 66996,
                      'codec72 historical reconstruction exceeds exact original size')
        result.extend(piece); cursor = end
    _codec72_need(cursor == len(parent_raw), 'codec72 historical inverse did not consume the complete source')
    return _codec72_pin(bytes(result), packet['result'], 'whole inverse to retained c50a proof-only bytes')'''
    old_constant = segment(source, 'CODEC72_BASE67_LATE')
    old_helper = segment(source, '_codec72_base_late_bytes')
    old_call = 'base_late = _codec72_base_late_bytes()'
    new_call = "base_late = _codec72_base_late_bytes(parent_files['source/late_boundary.py'])"
    derived = replace_one(source, old_constant, new_constant)
    derived = replace_one(derived, old_helper, helper)
    derived = replace_one(derived, old_call, new_call)
    restored = replace_one(derived, new_call, old_call)
    restored = replace_one(restored, helper, old_helper)
    restored = replace_one(restored, new_constant, old_constant)
    assert restored.encode('utf-8') == originals['pure']
    old_functions = {n.name: ast.get_source_segment(source, n) for n in ast.parse(source).body
                     if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
    new_functions = {n.name: ast.get_source_segment(derived, n) for n in ast.parse(derived).body
                     if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
    unchanged = [name for name in old_functions if old_functions[name] == new_functions[name]]
    assert set(old_functions) - set(unchanged) == {
        '_codec72_base_late_bytes', 'codec72_historical_runtime_view'}
    assert new_functions['codec72_historical_runtime_view'].replace(new_call, old_call) == old_functions['codec72_historical_runtime_view']
    derived_raw = derived.encode('utf-8')
    compile(derived_raw, '<codec72-inverse-pure-api-candidate>', 'exec')
    compressed = gzip.compress(derived_raw, compresslevel=9, mtime=0)
    packet = dict(pin(compressed), encoding='canonical-base85-gzip-single-member',
                  data=base64.b85encode(compressed).decode('ascii'))
    old_capsule = originals['capsule'].decode('utf-8')
    capsule = replace_one(old_capsule, segment(old_capsule, '_CODEC72_CAPSULE_SOURCE'),
                          '_CODEC72_CAPSULE_SOURCE = ' + repr(pin(derived_raw)))
    capsule = replace_one(capsule, segment(old_capsule, '_CODEC72_CAPSULE_PACKET'),
                          '_CODEC72_CAPSULE_PACKET = ' + repr(packet))
    capsule = replace_one(capsule, 'len(encoded) != 42475', 'len(encoded) != ' + str(len(packet['data'])))
    capsule = replace_one(capsule, 'hepta_exact_codec72_pure_source_validator_72450728',
                          'hepta_exact_codec72_pure_source_validator_' + pin(derived_raw)['sha256'][:8])
    capsule_raw = capsule.encode('utf-8')
    compile(capsule_raw, '<codec72-current-inverse-pure-capsule>', 'exec')

    OUT.mkdir(exist_ok=False)
    for key, raw in originals.items():
        name = {'pure': 'codec72_runtime_source_increment.7245.original.py',
                'capsule': 'codec72_runtime_source_capsule.e7a.original.py',
                'parent': 'late_boundary.396d.original.py',
                'base': 'late_boundary.c50a.original.py'}[key]
        put('reference/' + name, raw)
    put('source/codec72_runtime_source_increment.py', derived_raw)
    put('source/codec72_runtime_source_capsule.py', capsule_raw)
    put('source/codec72_base67_inverse.fragment.py', (new_constant + '\n\n\n' + helper + '\n').encode('utf-8'))
    put('payload/codec72_runtime_source_increment.py.gz', compressed)
    put('validation/BYTE-RANGE-RECIPE.json', enc(recipe))
    put('validation/PURE-API-INCREMENT.patch', ''.join(difflib.unified_diff(
        source.splitlines(True), derived.splitlines(True), fromfile='7245.original.py',
        tofile='codec72_runtime_source_increment.py')).encode('utf-8'))
    put('validation/CAPSULE-PIN-INCREMENT.patch', ''.join(difflib.unified_diff(
        old_capsule.splitlines(True), capsule.splitlines(True), fromfile='e7a.original.py',
        tofile='codec72_runtime_source_capsule.py')).encode('utf-8'))
    checks = []
    def check(name, fn):
        result = fn()
        checks.append({'name': name, 'passed': True, 'detail': result})
    def reject(fn):
        try:
            fn()
        except (ValueError, UnicodeError, TypeError) as error:
            return {'type': type(error).__name__, 'reason': str(error)}
        raise AssertionError('malformed historical inverse was accepted')

    namespace = {'__name__': 'codec72_current_pure_inverse_local_check'}
    exec(compile(derived_raw, '<reviewed-current-pure-inverse-candidate>', 'exec'), namespace)
    restore = namespace['_codec72_base_late_bytes']
    check('actual396d_to_exact_complete_c50', lambda: {
        'equal': restore(parent) == base, 'result': pin(restore(parent))})
    assert restore(parent) == base
    for name, value in [('changed_parent', parent[:-1] + b'X'),
                        ('truncated_parent', parent[:-1]), ('appended_parent', parent + b'\n')]:
        check(name + '_refused', lambda value=value: reject(lambda: restore(value)))
    def mutated_recipe(fn):
        original = namespace['CODEC72_BASE67_LATE']
        replacement = copy.deepcopy(original); fn(replacement)
        namespace['CODEC72_BASE67_LATE'] = replacement
        try:
            return reject(lambda: restore(parent))
        finally:
            namespace['CODEC72_BASE67_LATE'] = original
    mutations = [
        ('bool_start', lambda p: p['operations'][0].update(start=False)),
        ('bool_length', lambda p: p['operations'][0].update(bytes=True)),
        ('negative_length', lambda p: p['operations'][0].update(bytes=-1)),
        ('gap', lambda p: p['operations'][2].update(start=p['operations'][2]['start']+1)),
        ('omitted_operation', lambda p: p['operations'].pop(1)),
        ('reordered_operation', lambda p: p['operations'].reverse()),
        ('changed_literal', lambda p: p['operations'][3].update(literal_utf8=p['operations'][3]['literal_utf8']+'X')),
        ('oversized_literal', lambda p: p['operations'][1].update(literal_utf8='X'*193)),
        ('short_complete_coverage', lambda p: p['operations'][-1].update(bytes=p['operations'][-1]['bytes']-1)),
        ('altered_output_pin', lambda p: p['result'].update(sha256='0'*64)),
    ]
    for name, mutation in mutations:
        check(name + '_refused', lambda mutation=mutation: mutated_recipe(mutation))
    runtime = ROOT / 'codec72_generation_candidate01/runtime-source-preview02/runtime'
    runtime_raw = (runtime / 'MANIFEST.json').read_bytes()
    runtime_files = {row['path']: (runtime / row['path']).read_bytes()
                     for row in json.loads(runtime_raw)['files']}
    shared_root = ROOT / 'codec72_generation_candidate01/deterministic-preview01/materials'
    shared_manifest = json.loads((ROOT / 'codec72_generation_candidate01/deterministic-shared-preview02/materials/SHARED-MATERIALS.json').read_bytes())
    shared_files = {row['path']: (shared_root / row['path']).read_bytes() for row in shared_manifest['files']}
    combination = (ROOT / 'codec72_generation_candidate01/deterministic-preview01/expected-component/COMBINATION.json').read_bytes()
    expected_proof = (ROOT / 'codec72_generation_candidate01/pure-api-preview01/validation/EXACT-VERIFICATION.json').read_bytes()
    proof = namespace['verify_codec72_runtime_increment'](runtime_raw, runtime_files, combination, shared_files)
    assert enc(proof) == expected_proof
    historical = namespace['codec72_historical_runtime_view'](runtime_raw, runtime_files, combination, shared_files)
    assert pin(historical[0]) == {'bytes': 16808, 'sha256': '67dc40470b8ecb1e10cb57f8953a3d0b6db309b45079216eb24cd65f0760107c'}
    assert historical[2]['source/late_boundary.py'] == base
    assert pin(historical[3]) == {'bytes': 4702, 'sha256': '54b1d9aef4c16ebc0989b3e13345238bfbd4e400e5bfc9a97e27648a2385057e'}
    check('existing_four_argument_full_runtime32_shared17_proof_unchanged', lambda: pin(enc(proof)))
    check('historical67dc_c50_and54b1_exact_bytes', lambda: {
        'runtime': pin(historical[0]), 'late': pin(historical[2]['source/late_boundary.py']),
        'combination': pin(historical[3])})
    capsule_namespace = {'__name__': 'codec72_current_inverse_capsule_local_check'}
    exec(compile(capsule_raw, '<reviewed-current-inverse-pure-capsule>', 'exec'), capsule_namespace)
    assert capsule_namespace['_codec72_capsule_decode'](packet['data']) == derived_raw
    assert enc(capsule_namespace['verify_codec72_runtime_increment'](
        runtime_raw, runtime_files, combination, shared_files)) == expected_proof
    capsule_historical = capsule_namespace['codec72_historical_runtime_view'](
        runtime_raw, runtime_files, combination, shared_files)
    assert capsule_historical == historical
    check('exact_new_capsule_decode_and_both_public_functions', lambda: pin(capsule_raw))
    for name, data in [('short', packet['data'][:-1]), ('suffix', packet['data']+'0'),
                       ('byte', ('0' if packet['data'][0] != '0' else '1') + packet['data'][1:])]:
        check('capsule_' + name + '_refused', lambda data=data: reject(
            lambda: capsule_namespace['_codec72_capsule_decode'](data)))
    report = {
        'schema': 'hepta.codec72.exact-historical-inverse-local-review.v1',
        'state': 'SOURCE_ONLY_EXACT_HISTORICAL_BYTE_RECOVERY_NO_RUNTIME_EXECUTION_ADMISSION',
        'parents': EXPECTED,
        'derived_pure_source': pin(derived_raw), 'derived_capsule_source': pin(capsule_raw),
        'compressed_pure_source': pin(compressed), 'recipe_operations': len(operations),
        'retained_old_literal_bytes': 192, 'recipe_generation':
        'offline difflib.SequenceMatcher on original whole LF-retaining byte lines, autojunk=False; fixed byte ranges at runtime; no dynamic diff or textual normalization',
        'source_inverse_to_7245_complete': True, 'unchanged_old_function_count': len(unchanged),
        'unchanged_old_functions': unchanged,
        'changed_functions': ['_codec72_base_late_bytes', 'codec72_historical_runtime_view'],
        'historical_view_only_one_call_argument_changed': True,
        'source_bytes_saved': len(originals['pure'])-len(derived_raw),
        'capsule_source_bytes_saved': len(originals['capsule'])-len(capsule_raw),
        'source_execution_scope': 'Only this current pure validator and its current exact capsule; runtime, production and historical source files are bytes only, never compiled/executed.',
        'historical_source_executions': 0, 'target_runtime_imports': 0,
        'new_epoch_integration_performed': False, 'final_consumer_size_verified': False,
        'phone_calls': 0, 'remote_calls': 0, 'nonces_generated': 0,
        'tests': checks, 'passed': len(checks), 'total': len(checks),
    }
    put('validation/LOCAL-REVIEW.json', enc(report))
    put('validation/EXACT-VERIFICATION.json', expected_proof)
    print(json.dumps({'out': str(OUT), 'pure': pin(derived_raw), 'capsule': pin(capsule_raw),
                      'saved_capsule_bytes': report['capsule_source_bytes_saved'],
                      'tests': len(checks)}, sort_keys=True))


if __name__ == '__main__':
    main()
