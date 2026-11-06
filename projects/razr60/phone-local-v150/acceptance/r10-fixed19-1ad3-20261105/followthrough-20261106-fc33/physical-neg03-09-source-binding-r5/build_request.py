"""Materialize the reviewed request artifact; never execute or publish it."""
from pathlib import Path
import ast
import hashlib
import json

D = Path(__file__).resolve().parent
B = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
T = B + '/followthrough-fc33-negative-source-transport-r5-01'


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def enc(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode()


def put(name, raw):
    path = D / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        assert path.read_bytes() == raw, 'different prepared artifact: ' + name
    else:
        path.write_bytes(raw)


parent_file = D.parent / 'R5-release-source-publisher-v2/publish_and_derive_source_chain_v2.py'
parent_raw = parent_file.read_bytes()
parent_tree = ast.parse(parent_raw)
lines = parent_raw.splitlines(keepends=True)
helpers = {}
for name in ('need', 'pin', 'meta', 'initial', 'module', 'writer', 'located'):
    nodes = [n for n in parent_tree.body if isinstance(n, ast.FunctionDef) and n.name == name]
    assert len(nodes) == 1
    n = nodes[0]
    helpers[name] = b''.join(lines[n.lineno - 1:n.end_lineno])
template = (D / 'publish_negative_sources_once.template.py').read_bytes()
assert template.count(b'# REVIEWED_IO_HELPERS') == 1
source = template.replace(b'# REVIEWED_IO_HELPERS', b'\n\n'.join(helpers.values()), 1)
payload_manifest = json.loads((D / 'transport/PAYLOAD-MANIFEST.json').read_bytes())
proof = json.loads((D / 'BINDING-PROOF.json').read_bytes())
for name, value in [('SOURCE_PAYLOAD', payload_manifest['payload']),
                    ('PAYLOAD_RAW', payload_manifest['raw_payload']),
                    ('EXPECTED_INPUTS', proof['source_inputs'])]:
    before = (name + ' = None').encode()
    after = (name + ' = ' + repr(value)).encode()
    assert source.count(before) == 1
    source = source.replace(before, after, 1)
compile(source, '<prepared-negative-source-publisher>', 'exec')
put('transport/publish_negative_sources_once.py', source)
helper_proof = {
    'schema': 'hepta.fc33.negative-source-publication-helper-derivation.v1',
    'parent': {'local_path': str(parent_file), **pin(parent_raw)},
    'copied_function_bytes_unchanged': {name: pin(raw) for name, raw in helpers.items()},
    'publisher_source': pin(source),
    'actual_publish_material_body_source': {
        'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/followthrough-20261106-fc33-source-propagation01/derive_reviewed_source_material_v3.py',
        'bytes': 16399, 'sha256': '842f893107dfff481e516419da3fd9b1e2c2445378903012658530d83429ac82',
    },
    'publish_material_change_at_execution': 'Only the exact closed directory tuple; unchanged reviewed held-dirfd/full9/readback/terminal-last body with full inverse proof.',
    'input_files': 177, 'actual_source_constructor_positive_executed': False,
    'source_publication_executed': False, 'phone_calls': 0,
}
put('PUBLISHER-HELPER-DERIVATION.json', enc(helper_proof))
script = {'path': T + '/publish_negative_sources_once.py', **pin(source)}
request = {
    'host': 'mac', 'executable': '/usr/bin/python3',
    'args': ['-I', '-B', script['path'], '--publish-negative-source-candidate-once', script['sha256']],
    'idempotency_key': 'fc33-negative-source-only-native-v3-r5-01',
    'timeout_seconds': 120,
}
put('PROCESS-REQUEST.UNEXECUTED.json', enc(request))
chunks = []
compressed = (D / 'transport/SOURCE-PAYLOAD.zlib').read_bytes()
for offset in range(0, len(compressed), 65536):
    raw = compressed[offset:offset + 65536]
    name = 'chunks/source-payload-%03d.bin' % len(chunks)
    put('transport/' + name, raw)
    chunks.append({'local_relative_path': name, 'offset': offset, **pin(raw)})
transport = {
    'schema': 'hepta.fc33.negative-source-only-unexecuted-transport.v1',
    'state': 'PREPARED_FOR_ROOT_REVIEW_NOT_TRANSPORTED_OR_EXECUTED',
    'new_owned_transport_root': T,
    'required_existing_staged_files_before_the_one_process_request': [script, payload_manifest['payload']],
    'source_payload_chunks': chunks,
    'request': {'local_path': str(D / 'PROCESS-REQUEST.UNEXECUTED.json'), **pin(enc(request))},
    'no_input_copies_or_derived_sources_claimed_published': True,
    'no_existing_source_overwrite': True, 'no_delete_or_automatic_retry': True,
    'actual_process': None, 'actual_source_outputs': None,
    'actual_BUILD': None, 'actual_READY': None, 'actual_case_plans': None,
    'phone_calls': 0, 'model_requests': 0, 'native_dispatches': 0,
}
put('TRANSPORT-PLAN.UNEXECUTED.json', enc(transport))
print(json.dumps({'publisher': pin(source), 'request': pin(enc(request)), 'transport': pin(enc(transport)),
                  'chunks': len(chunks), 'executed': False}, sort_keys=True))
