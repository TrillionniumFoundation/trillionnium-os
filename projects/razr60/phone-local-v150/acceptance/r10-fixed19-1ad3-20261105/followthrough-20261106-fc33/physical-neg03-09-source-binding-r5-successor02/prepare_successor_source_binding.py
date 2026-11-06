"""Prepare one independent source-only successor. Never publish or dispatch."""
from pathlib import Path
import ast
import base64
import copy
import difflib
import hashlib
import json
import zlib

D = Path(__file__).resolve().parent
OLD = D.parent / 'R5-negative-source-binding01'
C = D / 'candidate01'
OUT = D.parent / 'R5-negative-source-binding02'
B = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
BINDING = B + '/followthrough-fc33-negative-source-binding-r5-02'
DERIVED = B + '/fc33-negative-sources-native-v3-r5-02'
TRANSPORT = B + '/followthrough-fc33-negative-source-transport-r5-02'
CONTROL_ROOT = B + '/followthrough-fc33-negative-adoption-host-controls01'


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def enc(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2,
                       allow_nan=False) + '\n').encode()


def row(path, raw):
    return {'path': path, **pin(raw)}


def put(name, raw):
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        assert path.read_bytes() == raw, 'refuse changed successor artifact: ' + name
    else:
        with path.open('xb') as f:
            f.write(raw)


def patch(name, before, after, first, second):
    put(name, ''.join(difflib.unified_diff(before.decode().splitlines(True),
        after.decode().splitlines(True), fromfile=first, tofile=second)).encode())


def assignment(raw, name, value):
    nodes = [n for n in ast.parse(raw).body if isinstance(n, ast.Assign)
             and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
             and n.targets[0].id == name]
    assert len(nodes) == 1
    n = nodes[0]
    before = b''.join(raw.splitlines(keepends=True)[n.lineno - 1:n.end_lineno])
    after = (name + ' = ' + repr(value) + '\n').encode()
    assert raw.count(before) == 1
    return raw.replace(before, after, 1), (before, after)


compressed_old = (OLD / 'transport/SOURCE-PAYLOAD.zlib').read_bytes()
assert pin(compressed_old) == {'bytes': 711272, 'sha256': '324bf65adb34b22e870ab8d791216ffcc50f360685934ab7696694b866b5a873'}
old_payload = json.loads(zlib.decompress(compressed_old))
prepared = {}
for item in old_payload['files']:
    blob = old_payload['blobs'][item['sha256']]
    raw = blob['content'].encode() if blob['encoding'] == 'utf-8' else base64.b64decode(blob['content'], validate=True)
    assert pin(raw) == {k: item[k] for k in ('bytes', 'sha256')}
    prepared[item['path']] = raw
assert len(prepared) == 177

common = (C / 'source/physical_fault_common.py').read_bytes()
assert pin(common) == {'bytes': 28157, 'sha256': '60f5a7b64cf055db153fc20e49951866fabf3e7c0b2b28d29290fec4d722eae9'}
index_raw = (C / 'source/REVIEWED-INPUTS.json').read_bytes()
assert pin(index_raw) == {'bytes': 38100, 'sha256': 'bccd3fb4c6d785ea1edbca3442430f041e0e86b4df95be60c8882eba7ef3000c'}
parent_candidate = (C / 'source/derive_negative_sources_UNBOUND.py').read_bytes()
assert pin(parent_candidate) == {'bytes': 43142, 'sha256': 'c9d6b80bbfbf1daa69132331511ad6a28e6f8c09a83072f2508021ca35603c4b'}
comment_before = b'''    # This retained function checks the complete runtime source package, actual
    # policy/adoption original links and all 44 exact permission atoms.  It does
    # not award independent policy verification, BUILD, READY or physical credit.
'''
comment_after = b'''    # The current consumer-pinned pure verifier checks the complete retained
    # parent adoption, actual export, full rule and its one declared delta.
    # That verification grants no BUILD, READY or physical qualification.
'''
assert parent_candidate.count(comment_before) == 1
unbound = parent_candidate.replace(comment_before, comment_after, 1)
assert unbound.replace(comment_after, comment_before, 1) == parent_candidate
assert ast.dump(ast.parse(unbound), include_attributes=False) == ast.dump(ast.parse(parent_candidate), include_attributes=False)
put('reference/derive_negative_sources_api_candidate.py', parent_candidate)
put('reference/derive_negative_sources_UNBOUND.py', unbound)
patch('CONSTRUCTOR-COMMENT.patch', parent_candidate, unbound,
      'reference/derive_negative_sources_api_candidate.py', 'reference/derive_negative_sources_UNBOUND.py')
put('source/physical_fault_common.py', common)
put('source/REVIEWED-INPUTS.json', index_raw)
for name in ('COMMON.patch', 'REFERENCE-INDEX.patch', 'CONSTRUCTOR.patch', 'DERIVATION.json'):
    put('adoption-repair/' + name, (C / name).read_bytes())
put('adoption-repair/derive_adoption_compatible_operator.py', (D / 'derive_adoption_compatible_operator.py').read_bytes())
put('reference/physical_fault_common.original.py', (C / 'reference/physical_fault_common.original.py').read_bytes())
put('reference/REVIEWED-INPUTS.original.json', (C / 'reference/REVIEWED-INPUTS.original.json').read_bytes())
put('reference/derive_negative_sources.original.py', (C / 'reference/derive_negative_sources_UNBOUND.original.py').read_bytes())

inputs = json.loads(prepared['SOURCE-INPUTS.json'])
inputs['reference_root'] = BINDING + '/inputs'
inputs['output_root'] = DERIVED
inputs['host_neg06_namespace'] = '/home/alex/razr60-local-model-v150/fc33-neg06-native-v3-r5-02'
inputs_raw = enc(inputs)
input_descriptor = row(BINDING + '/SOURCE-INPUTS.json', inputs_raw)
before = b'FROZEN_INPUTS = None'
after = ('FROZEN_INPUTS = ' + repr(input_descriptor)).encode()
assert unbound.count(before) == 1
bound = unbound.replace(before, after, 1)
assert bound.replace(after, before, 1) == unbound
compile(bound, '<unexecuted-successor-constructor>', 'exec')
put('source/derive_negative_sources_BOUND.py', bound)
put('SOURCE-INPUTS.json', inputs_raw)
patch('SOURCE.patch', unbound, bound, 'reference/derive_negative_sources_UNBOUND.py', 'source/derive_negative_sources_BOUND.py')

control_result_raw = (C / 'RESULT.json').read_bytes()
assert pin(control_result_raw) == {'bytes': 2637, 'sha256': '4f7ee4da09c8d5230169b72ce0f94442dea200b9dc42f4052b5be55fab4425b1'}
control = json.loads(control_result_raw)
assert len(control['cases']) == 3 and all(r['passed'] is True for r in control['cases'])
assert control['phone_calls'] == control['native_dispatches'] == control['model_requests'] == 0
assert control['complete_original_bookend_passed'] is True
assert control['unique_original_count'] == 130 and control['unique_original_bytes'] == 16265924
for name in ('test_current_adoption_api.py', 'CONTROL-REQUEST.json', 'CONTROL-START.original.mcp.json',
             'CONTROL-STATUS.original.mcp.json', 'CONTROL-READ.original.mcp.json',
             'CONTROL-STDOUT.original.json', 'CONTROL-RESULT-READ.original.mcp.json',
             'RESULT.json', 'ACTUAL-GENERATION-INPUTS.json', 'ORIGINALS.json'):
    put('actual-host-controls/' + name, (C / name).read_bytes())

proof = json.loads(prepared['BINDING-PROOF.json'])
proof.update(constructor_parent=pin(unbound), constructor=row(BINDING + '/source/derive_negative_sources_BOUND.py', bound),
             source_inputs=input_descriptor, binding_output=BINDING, derived_output=DERIVED,
             reference_index=row(BINDING + '/inputs/REVIEWED-INPUTS.json', index_raw),
             reference_bytes=sum(r['bytes'] for r in json.loads(index_raw)['files']),
             new_owned_input_copies_not_yet_published=BINDING, new_source_output_not_yet_published=DERIVED,
             host_neg06_namespace_is_only_a_future_output_literal_not_an_execution=inputs['host_neg06_namespace'],
             previous_source_publication={'job_id': '1a1b2488d00-fc05-7d52', 'exit_code': 1,
                'input_binding_tree_preserved': old_payload['binding_root'],
                'independent_observed_input_file_count': 181, 'derived_tree_observed_absent': old_payload['derived_root'],
                'no_replay_or_overwrite': True},
             operator_adoption_current_API_control=row(CONTROL_ROOT + '/RESULT.json', control_result_raw),
             operator_control_scope='One actual current retained-original API positive plus two explicit corruption rejections; no whole case or full source publication positive.',
             original_production15_and_runtime38_unchanged=True)
proof_raw = enc(proof)
put('BINDING-PROOF.json', proof_raw)
prepared.update({'source/derive_negative_sources_BOUND.py': bound,
                 'reference/derive_negative_sources_UNBOUND.py': unbound,
                 'SOURCE-INPUTS.json': inputs_raw, 'SOURCE.patch': (OUT / 'SOURCE.patch').read_bytes(),
                 'BINDING-PROOF.json': proof_raw, 'inputs/REVIEWED-INPUTS.json': index_raw,
                 'inputs/candidate/templates/physical-fault/physical_fault_common.py': common})
index = json.loads(index_raw)
assert len(index['files']) == 171
for item in index['files']:
    assert pin(prepared['inputs/' + item['path']]) == {k: item[k] for k in ('bytes', 'sha256')}
assert len(prepared) == 177
blobs = {}
members = []
for name, raw in sorted(prepared.items()):
    digest = pin(raw)['sha256']
    try:
        blob = {'encoding': 'utf-8', 'content': raw.decode('utf-8')}
    except UnicodeDecodeError:
        blob = {'encoding': 'base64', 'content': base64.b64encode(raw).decode()}
    blobs.setdefault(digest, blob)
    members.append({'path': name, **pin(raw)})
payload = dict(schema=old_payload['schema'], binding_root=BINDING, derived_root=DERIVED,
               files=members, blobs=blobs)
payload_raw = (json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False) + '\n').encode()
compressed = zlib.compress(payload_raw, 9)
put('transport/SOURCE-PAYLOAD.zlib', compressed)
payload_descriptor = row(TRANSPORT + '/SOURCE-PAYLOAD.zlib', compressed)
put('transport/PAYLOAD-MANIFEST.json', enc({'schema': 'hepta.fc33.negative-source-publication-payload-manifest.v1',
    'payload': payload_descriptor, 'raw_payload': pin(payload_raw), 'files': members,
    'file_count': len(members), 'all_171_reference_bytes_verified': True,
    'input_publication_executed': False, 'source_derivation_executed': False}))

publisher_parent = (OLD / 'publisher-final02/publish_negative_sources_once.py').read_bytes()
assert pin(publisher_parent) == {'bytes': 19652, 'sha256': '581efadeed85af47e98c68c4037cee4b2599d00987df1f78ca753e917e729335'}
publisher = publisher_parent
edits = []
for name, value in [('SOURCE_PAYLOAD', payload_descriptor), ('PAYLOAD_RAW', pin(payload_raw)),
                    ('EXPECTED_INPUTS', input_descriptor), ('SOURCE_PARENT', pin(unbound)),
                    ('REFERENCE_INDEX', pin(index_raw))]:
    publisher, edit = assignment(publisher, name, value)
    edits.append(edit)
for before, after in [(b"binding_root.name == 'followthrough-fc33-negative-source-binding-r5-01'",
                       b"binding_root.name == 'followthrough-fc33-negative-source-binding-r5-02'"),
                      (b"derived_root.name == 'fc33-negative-sources-native-v3-r5-01'",
                       b"derived_root.name == 'fc33-negative-sources-native-v3-r5-02'")]:
    assert publisher.count(before) == 1
    publisher = publisher.replace(before, after, 1)
    edits.append((before, after))
inverse = publisher
for before, after in reversed(edits):
    assert inverse.count(after) == 1
    inverse = inverse.replace(after, before, 1)
assert inverse == publisher_parent
compile(publisher, '<unexecuted-successor-source-publisher>', 'exec')
put('reference/publish_negative_sources_once.original.py', publisher_parent)
put('transport/publish_negative_sources_once.py', publisher)
patch('PUBLISHER.patch', publisher_parent, publisher,
      'reference/publish_negative_sources_once.original.py', 'transport/publish_negative_sources_once.py')
put('PUBLISHER-DERIVATION.json', enc({'schema': 'hepta.fc33.negative-source-successor-publisher-derivation.v1',
    'parent': pin(publisher_parent), 'candidate': pin(publisher), 'complete_inverse': True,
    'changed_constant_assignments': ['SOURCE_PAYLOAD', 'PAYLOAD_RAW', 'EXPECTED_INPUTS', 'SOURCE_PARENT', 'REFERENCE_INDEX'],
    'changed_literal_namespace_checks': [BINDING, DERIVED],
    'all_other_bytes_unchanged': True, 'old_16MiB_reader_and_final_tree_bounds_unchanged': True,
    'existing_publisher_source_not_overwritten': True, 'actual_execution': None, 'phone_calls': 0}))

script = row(TRANSPORT + '/publish_negative_sources_once.py', publisher)
request = {'host': 'mac', 'executable': '/usr/bin/python3',
    'args': ['-I', '-B', script['path'], '--publish-negative-source-candidate-once', script['sha256']],
    'idempotency_key': 'fc33-negative-source-only-native-v3-r5-02', 'timeout_seconds': 120}
put('PROCESS-REQUEST.UNEXECUTED.json', enc(request))
chunks = []
for offset in range(0, len(compressed), 65536):
    raw = compressed[offset:offset + 65536]
    name = 'chunks/source-payload-%03d.bin' % len(chunks)
    put('transport/' + name, raw)
    chunks.append({'local_relative_path': name, 'offset': offset, **pin(raw)})
put('TRANSPORT-PLAN.UNEXECUTED.json', enc({'schema': 'hepta.fc33.negative-source-only-unexecuted-transport.v1',
    'state': 'PREPARED_SUCCESSOR_FOR_ROOT_REVIEW_NOT_TRANSPORTED_OR_EXECUTED',
    'new_owned_transport_root': TRANSPORT, 'required_existing_staged_files_before_the_one_process_request': [script, payload_descriptor],
    'source_payload_chunks': chunks, 'request': row(str(OUT / 'PROCESS-REQUEST.UNEXECUTED.json'), enc(request)),
    'old181_inputs_and_failed_controller_preserved': True, 'no_delete_or_automatic_retry': True,
    'actual_process': None, 'actual_source_outputs': None, 'actual_BUILD': None, 'actual_READY': None,
    'actual_case_plans': None, 'phone_calls': 0, 'native_dispatches': 0, 'model_requests': 0}))
bounds = json.loads((OLD / 'publisher-final02/BYTE-BOUNDS.json').read_bytes())
bounds['prepared_payload_members'] = {'count': len(members), 'bytes': sum(r['bytes'] for r in members),
    'maximum': max(members, key=lambda r: r['bytes']), 'all_file_pins': members}
bounds['reference_sources'] = {'count': 171, 'bytes': sum(r['bytes'] for r in index['files'])}
bounds['prepared_compressed_payload'] = pin(compressed)
bounds['prepared_raw_payload'] = pin(payload_raw)
bounds['actual_generation_only_control_measured_pool'] = {'unique_files': 130, 'unique_bytes': 16265924,
    'result': row(CONTROL_ROOT + '/RESULT.json', control_result_raw),
    'does_not_claim_future_full_constructor_total': True}
put('BYTE-BOUNDS.json', enc(bounds))
put('NEG03-PROTOCOL-BOUNDARY.json', (OLD / 'publisher-final02/NEG03-PROTOCOL-BOUNDARY.json').read_bytes())
put('reference/SOURCE-READER-DERIVATION.json', (OLD / 'publisher-final02/SOURCE-READER-DERIVATION.json').read_bytes())
put('prepare_successor_source_binding.py', Path(__file__).read_bytes())
print(json.dumps({'output': str(OUT), 'common': pin(common), 'constructor_unbound': pin(unbound),
    'constructor_bound': pin(bound), 'source_inputs': pin(inputs_raw), 'publisher': pin(publisher),
    'payload': pin(compressed), 'payload_raw': pin(payload_raw), 'prepared_files': len(members),
    'prepared_file_bytes': sum(r['bytes'] for r in members), 'request': pin(enc(request)),
    'actual_execution': None, 'phone_calls': 0}, sort_keys=True))
