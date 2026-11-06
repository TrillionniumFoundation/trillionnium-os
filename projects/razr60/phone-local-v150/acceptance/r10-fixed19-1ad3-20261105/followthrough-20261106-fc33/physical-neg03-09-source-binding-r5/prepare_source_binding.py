"""Prepare complete host-source inputs and an unexecuted publication request.

Local artifact construction only. No remote publication or actual constructor
positive execution takes place here. Root owns the later source-only request.
"""
from pathlib import Path
import ast
import base64
import difflib
import hashlib
import json
import zlib

D = Path(__file__).resolve().parent
P = D.parent / 'neg03-09-plan'
B = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
BINDING_ROOT = B + '/followthrough-fc33-negative-source-binding-r5-01'
DERIVED_ROOT = B + '/fc33-negative-sources-native-v3-r5-01'
TRANSPORT_ROOT = B + '/followthrough-fc33-negative-source-transport-r5-01'
PARENT = (43142, 'd539cb12c5b3d99f4b6066de148f11db78d3ad4210bc034669ebc1bc99c44903')


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def enc(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode()


def put(name, raw):
    target = D / name
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        assert target.read_bytes() == raw, 'refuse a changed prepared artifact: ' + name
    else:
        target.write_bytes(raw)


def row(path, raw):
    return {'path': path, **pin(raw)}


def literal(raw, name):
    matches = [n for n in ast.parse(raw).body if isinstance(n, ast.Assign)
               and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
    assert len(matches) == 1
    return ast.literal_eval(matches[0].value)


source = (P / 'derive_negative_sources_UNBOUND.py').read_bytes()
assert pin(source) == dict(zip(('bytes', 'sha256'), PARENT))
chain = D.parent / 'R5-actual-release-source-chain' / 'binding'
chain_source = (chain / 'source/derive_reviewed_release_sources_BOUND.py').read_bytes()
chain_inputs_raw = (chain / 'SOURCE-CHAIN-INPUTS.json').read_bytes()
assert pin(chain_source) == {'bytes': 34103, 'sha256': '342cf03f11fcb6cc02fd98f68f44a567603389788de45999c6182ad0a4426c5a'}
assert pin(chain_inputs_raw) == {'bytes': 3515, 'sha256': 'e3cc22536e42074ba3fe662101dd4a4c98224de285b0a5c13c32f84d2fac322b'}
chain_inputs = literal(chain_source, 'FROZEN_INPUTS')
assert chain_inputs == row(B + '/followthrough-fc33-release-source-binding-r5-01/SOURCE-CHAIN-INPUTS.json', chain_inputs_raw)
old_boundary = json.loads((P / 'CURRENT-SOURCE-BOUNDARY.json').read_bytes())
inputs = {
    'schema': 'hepta.fc33.negative-source-inputs.v1',
    'reference_root': BINDING_ROOT + '/inputs',
    'release_source_chain': {
        'constructor': row(B + '/followthrough-fc33-release-source-binding-r5-01/source/derive_reviewed_release_sources_BOUND.py', chain_source),
        'inputs': chain_inputs,
    },
    'root_manifest': {
        'path': B + '/native-guard-r10-r1-operator-fc33-native-v3-r5/root-chain/SOURCE-MANIFEST.json',
        'bytes': 50107, 'sha256': 'f9145ce2f0e5864a78ed8bece2d926187dc83e8baf15799758200bb646057282',
    },
    'actual_policy': old_boundary['actual_policy_original_descriptor_from_retained_adoption'],
    'policy_adoption': old_boundary['retained_adoption'],
    'materializer': {
        'path': B + '/followthrough-fc33-e2e-bound-source-r5-01/operator/materialize_case_r10.py',
        'bytes': 24834, 'sha256': 'b25125bc0e204ea7aefde6f2a17fa2fb8e5edf132a4b62dfbb546964c1c09290',
    },
    'output_root': DERIVED_ROOT,
    'host_neg06_namespace': '/home/alex/razr60-local-model-v150/fc33-neg06-native-v3-r5-01',
}
inputs_raw = enc(inputs)
input_descriptor = row(BINDING_ROOT + '/SOURCE-INPUTS.json', inputs_raw)
before = b'FROZEN_INPUTS = None'
after = ('FROZEN_INPUTS = ' + repr(input_descriptor)).encode()
assert source.count(before) == 1
bound = source.replace(before, after, 1)
assert bound.count(after) == 1 and bound.replace(after, before, 1) == source
assert literal(bound, 'FROZEN_INPUTS') == input_descriptor
compile(bound, '<prepared-negative-source-constructor>', 'exec')
put('reference/derive_negative_sources_UNBOUND.py', source)
put('source/derive_negative_sources_BOUND.py', bound)
put('SOURCE-INPUTS.json', inputs_raw)
put('SOURCE.patch', ''.join(difflib.unified_diff(source.decode().splitlines(True), bound.decode().splitlines(True),
    fromfile='reference/derive_negative_sources_UNBOUND.py', tofile='source/derive_negative_sources_BOUND.py')).encode())
index_raw = (P / 'REVIEWED-INPUTS.json').read_bytes()
assert pin(index_raw) == {'bytes': 38100, 'sha256': '1a7f17faf1d6705dac356076ce1d0df0292a35a805bceb117eeea50f52f15e32'}
index = json.loads(index_raw)
assert len(index['files']) == len({item['path'] for item in index['files']}) == 171
prepared = {
    'source/derive_negative_sources_BOUND.py': bound,
    'reference/derive_negative_sources_UNBOUND.py': source,
    'SOURCE-INPUTS.json': inputs_raw,
    'SOURCE.patch': (D / 'SOURCE.patch').read_bytes(),
    'inputs/REVIEWED-INPUTS.json': index_raw,
}
for item in index['files']:
    body = (P / item['path']).read_bytes()
    assert pin(body) == {key: item[key] for key in ('bytes', 'sha256')}
    prepared['inputs/' + item['path']] = body
proof = {
    'schema': 'hepta.fc33.negative-source-binding-preparation.v1',
    'state': 'PREPARED_FOR_ROOT_REVIEW_NOT_PUBLISHED_OR_EXECUTED',
    'constructor_parent': {'bytes': len(source), 'sha256': pin(source)['sha256']},
    'constructor': row(BINDING_ROOT + '/source/derive_negative_sources_BOUND.py', bound),
    'source_inputs': input_descriptor,
    'binding_output': BINDING_ROOT, 'derived_output': DERIVED_ROOT,
    'reference_index': row(BINDING_ROOT + '/inputs/REVIEWED-INPUTS.json', index_raw),
    'reference_count': 171, 'reference_bytes': sum(item['bytes'] for item in index['files']),
    'only_constructor_change': 'FROZEN_INPUTS: None -> exact source-only input descriptor',
    'complete_constructor_inverse': True,
    'existing_actual_inputs': {key: value for key, value in inputs.items()
                              if key in ('release_source_chain', 'root_manifest', 'actual_policy', 'policy_adoption', 'materializer')},
    'new_owned_input_copies_not_yet_published': BINDING_ROOT,
    'new_source_output_not_yet_published': DERIVED_ROOT,
    'host_neg06_namespace_is_only_a_future_output_literal_not_an_execution': inputs['host_neg06_namespace'],
    'actual_freeze_admission': None, 'actual_BUILD': None, 'actual_install': None, 'actual_READY': None,
    'actual_case_plans': None, 'new_native_scope': None, 'new_nonce': None,
    'source_constructor_positive_executed': False, 'phone_calls': 0, 'model_requests': 0,
    'signals_sent': 0, 'whole_case_qualification': False,
}
proof_raw = enc(proof)
put('BINDING-PROOF.json', proof_raw)
prepared['BINDING-PROOF.json'] = proof_raw
blobs = {}
members = []
for name, body in sorted(prepared.items()):
    digest = pin(body)['sha256']
    try:
        blob = {'encoding': 'utf-8', 'content': body.decode('utf-8')}
    except UnicodeDecodeError:
        blob = {'encoding': 'base64', 'content': base64.b64encode(body).decode()}
    blobs.setdefault(digest, blob)
    members.append({'path': name, **pin(body)})
payload = {'schema': 'hepta.fc33.negative-source-publication-payload.v1',
           'binding_root': BINDING_ROOT, 'derived_root': DERIVED_ROOT, 'files': members, 'blobs': blobs}
payload_raw = (json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False) + '\n').encode()
compressed = zlib.compress(payload_raw, 9)
put('transport/SOURCE-PAYLOAD.zlib', compressed)
put('transport/PAYLOAD-MANIFEST.json', enc({
    'schema': 'hepta.fc33.negative-source-publication-payload-manifest.v1',
    'payload': row(TRANSPORT_ROOT + '/SOURCE-PAYLOAD.zlib', compressed),
    'raw_payload': pin(payload_raw), 'files': members, 'file_count': len(members),
    'full_source_inverse': True, 'all_171_reference_bytes_verified': True,
    'input_publication_executed': False, 'source_derivation_executed': False,
}))
print(json.dumps({'source_inputs': pin(inputs_raw), 'bound_constructor': pin(bound),
                  'proof': pin(proof_raw), 'payload_compressed': pin(compressed),
                  'payload_raw': pin(payload_raw), 'prepared_file_count': len(members),
                  'phone_calls': 0, 'source_constructor_positive_executed': False}, sort_keys=True))
