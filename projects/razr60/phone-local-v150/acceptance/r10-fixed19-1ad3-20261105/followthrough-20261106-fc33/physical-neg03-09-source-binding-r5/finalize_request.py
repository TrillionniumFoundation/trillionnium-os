"""Finalize review artifacts only; never call a constructor or publisher."""
from pathlib import Path
import ast
import difflib
import hashlib
import json
import zlib

D = Path(__file__).resolve().parent
OUT = D / 'publisher-final02'
OUT.mkdir(exist_ok=True)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def enc(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode()


def put(name, raw):
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        assert path.read_bytes() == raw, name
    else:
        path.write_bytes(raw)


def function(raw, name):
    nodes = [n for n in ast.parse(raw).body if isinstance(n, ast.FunctionDef) and n.name == name]
    assert len(nodes) == 1
    n = nodes[0]
    return b''.join(raw.splitlines(keepends=True)[n.lineno - 1:n.end_lineno])


source = (D / 'transport/publish_negative_sources_once.py').read_bytes()
assert pin(source) == {'bytes': 19482, 'sha256': '67f91f8c92161d5e7c63fa8e01a0d5b902355a61f1867cba84e4136f73189152'}
changed = source
substitutions = []
for before, after in [
    (b'    publish_binding(binding_root, files)\n',
     b'    directories(files)  # Recheck final bytes/count including terminal/proof records.\n    publish_binding(binding_root, files)\n'),
    (b'    publish_derived(derived_root, out)\n',
     b'    directories(out)  # Recheck final bytes/count including terminal/proof records.\n    publish_derived(derived_root, out)\n'),
]:
    assert changed.count(before) == 1
    changed = changed.replace(before, after, 1)
    substitutions.append((before, after))
inverse = changed
for before, after in reversed(substitutions):
    assert inverse.count(after) == 1
    inverse = inverse.replace(after, before, 1)
assert inverse == source
compile(changed, '<prepared-final-negative-source-publisher>', 'exec')
put('publish_negative_sources_once.py', changed)
put('PUBLISHER.patch', ''.join(difflib.unified_diff(source.decode().splitlines(True), changed.decode().splitlines(True),
    fromfile='candidate01/publish_negative_sources_once.py', tofile='publisher-final02/publish_negative_sources_once.py')).encode())

material = (D.parent / 'derive_reviewed_source_material_v3.py').read_bytes()
assert pin(material) == {'bytes': 16399, 'sha256': '842f893107dfff481e516419da3fd9b1e2c2445378903012658530d83429ac82'}
original_read = function(material, 'read')
assert original_read.count(b'<=1048576') == 1 and b'<=16777216' not in original_read
candidate_read = original_read.replace(b'<=1048576', b'<=16777216', 1)
assert candidate_read.replace(b'<=16777216', b'<=1048576', 1) == original_read
put('reference/read.original.py', original_read)
put('source/read_projected.py', candidate_read)
put('SOURCE-READER.patch', ''.join(difflib.unified_diff(original_read.decode().splitlines(True), candidate_read.decode().splitlines(True),
    fromfile='reference/read.original.py', tofile='source/read_projected.py')).encode())
put('SOURCE-READER-DERIVATION.json', enc({
    'schema': 'hepta.fc33.negative-source-caller-reader-bound-review.v1',
    'parent_full_source': pin(material), 'parent_function': pin(original_read),
    'candidate_function': pin(candidate_read), 'one_literal_before': '<=1048576',
    'one_literal_after': '<=16777216', 'complete_function_inverse': True,
    'all_other_reader_bytes_unchanged': True,
    'scope': 'Only this source-only publisher caller; constructor MAX_FILE remains16MiB.',
    'no_changes_to': ['frozen material source', 'production15', 'phone', 'actor8MiB', 'image budgets'],
    'not_executed': True,
}))
helpers = json.loads((D / 'PUBLISHER-HELPER-DERIVATION.json').read_bytes())
for name, expected in helpers['copied_function_bytes_unchanged'].items():
    assert pin(function(changed, name)) == expected
put('PUBLISHER-DERIVATION.json', enc({
    'schema': 'hepta.fc33.negative-source-publisher-final-bound-review.v1',
    'parent': pin(source), 'candidate': pin(changed), 'complete_inverse': True,
    'changes': ['Recheck the same existing finite file/count/directory bound after terminal/proof records are added to each output tree.'],
    'copied_function_bytes_unchanged': helpers['copied_function_bytes_unchanged'],
    'source_reader_projection': 'SOURCE-READER-DERIVATION.json',
    'syntax_compiled_only': True, 'public_constructor_executed': False,
    'source_publication_executed': False, 'phone_calls': 0,
}))

request = json.loads((D / 'PROCESS-REQUEST.UNEXECUTED.json').read_bytes())
request['args'][-1] = pin(changed)['sha256']
put('PROCESS-REQUEST.UNEXECUTED.json', enc(request))
transport = json.loads((D / 'TRANSPORT-PLAN.UNEXECUTED.json').read_bytes())
transport['required_existing_staged_files_before_the_one_process_request'][0].update(pin(changed))
transport['request'] = {'local_path': str(OUT / 'PROCESS-REQUEST.UNEXECUTED.json'), **pin(enc(request))}
put('TRANSPORT-PLAN.UNEXECUTED.json', enc(transport))

payload = json.loads(zlib.decompress((D / 'transport/SOURCE-PAYLOAD.zlib').read_bytes()))
inputs = json.loads((D / 'SOURCE-INPUTS.json').read_bytes())
direct = [inputs['release_source_chain'][key] for key in ('constructor', 'inputs')]
direct += [inputs[key] for key in ('root_manifest', 'actual_policy', 'policy_adoption', 'materializer')]
direct += [helpers['actual_publish_material_body_source'], {
    'path': str(Path(inputs['release_source_chain']['inputs']['path']).parent.parent / 'followthrough-fc33-release-source-chain-r5-derived01/SOURCE-BINDING.json'),
    'bytes': 3608, 'sha256': 'c7b074b529b4bbe258303842b3d0b2f3912d8cdf606f803522775b79ba147003',
}]
refs = [r for r in payload['files'] if r['path'].startswith('inputs/') and r['path'] != 'inputs/REVIEWED-INPUTS.json']
put('BYTE-BOUNDS.json', enc({
    'schema': 'hepta.fc33.negative-source-prepared-byte-boundaries.v1',
    'prepared_payload_members': {'count': len(payload['files']), 'bytes': sum(r['bytes'] for r in payload['files']),
        'maximum': max(payload['files'], key=lambda r: r['bytes']), 'all_file_pins': payload['files']},
    'reference_sources': {'count': len(refs), 'bytes': sum(r['bytes'] for r in refs)},
    'direct_existing_source_inputs': direct,
    'direct_existing_source_input_bytes': sum(r['bytes'] for r in direct),
    'largest_direct_existing_source_input': max(direct, key=lambda r: r['bytes']),
    'prepared_compressed_payload': pin((D / 'transport/SOURCE-PAYLOAD.zlib').read_bytes()),
    'prepared_raw_payload': pin(zlib.decompress((D / 'transport/SOURCE-PAYLOAD.zlib').read_bytes())),
    'envelopes': {'caller_individual_original': 16777216, 'constructor_unique_path_pool': 67108864,
        'complete_raw_payload': 8388608, 'prepared_member': 4194304, 'each_final_published_tree': 33554432,
        'each_final_published_tree_files': 256, 'closed_directories': 128},
    'future_actual_transitive_original_count': None, 'future_actual_transitive_original_bytes': None,
    'future_published_tree_file_count': None, 'future_published_tree_bytes': None,
    'actual_book_full9_and_transitive_byte_count_recorded_only_after_public_constructor': True,
    'source_publication_executed': False,
}))

protocol_path = D.parent / 'neg03-09-plan/reference/physical-fault-final01/package/reference/original-protocol.json'
protocol = protocol_path.read_bytes()
assert pin(protocol) == {'bytes': 37318, 'sha256': 'c573959e59fd9fbe7a850d6d2d6d747e3135718493f15de4a8acde850bad93b0'}
row = next(v for v in json.loads(protocol)['cases'] if v['id'] == 'NEG-03')
put('NEG03-PROTOCOL-BOUNDARY.json', enc({
    'schema': 'hepta.fc33.neg03.protocol-boundary.v1', 'protocol': pin(protocol),
    'exact_original_case': row,
    'interpretation': 'Original protocol explicitly allows frozen mapper/parser component_direct receipts OR an explicitly scheduled physical negative; it does not require an actual external display.',
    'component_direct_fixtures': 'Unqualified display/rotation receipts through actual current mapper/parser must reject screenshot/tap/public-return before any input. Synthetic fixtures remain labelled synthetic.',
    'physical_rotation_branch': 'Actual baseline, rotated observation, rejection/no input, and restoration receipts remain necessary for the scheduled physical branch; fixture results cannot close an unfinished physical branch.',
    'actual_external_display_tested': False,
    'same_release_fixture_and_actual_physical_rotation_not_yet_run': True,
    'actual_BUILD': None, 'actual_READY': None, 'case_qualified': False,
}))
print(json.dumps({'publisher': pin(changed), 'request': pin(enc(request)),
    'prepared_source_files': len(payload['files']), 'prepared_source_bytes': sum(r['bytes'] for r in payload['files']),
    'direct_existing_source_input_bytes': sum(r['bytes'] for r in direct), 'executed': False}, sort_keys=True))
