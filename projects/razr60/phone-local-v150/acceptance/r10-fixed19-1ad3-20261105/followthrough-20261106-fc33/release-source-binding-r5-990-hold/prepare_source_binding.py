"""Prepare exact source-only bytes locally; no Mac or phone operation."""
import hashlib
import json
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
REVIEW = HERE.parent
B = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
BINDING_ROOT = B + '/followthrough-fc33-release-source-binding-r5-01'
DERIVED_ROOT = B + '/followthrough-fc33-release-source-chain-r5-derived01'
RUNTIME = {'path': B + '/native-guard-r10-r1-operator-fc33-native-v3-r5/runtime/MANIFEST.json',
           'bytes': 57078, 'sha256': '990c726a1fff139761494cc19cf091deb269201f27ea947dda4a5833e3a72f2a'}
CONSUMER_PARENT = {'path': B + '/followthrough-fc33-release-consumer-r5-source01/source/release_boundaries.py',
                   'bytes': 249798, 'sha256': '016d25b5467c96f96f25f7b2d9d606e40ea18a72421e549d0ab630a01f9c2349'}
CONSTRUCTOR_PARENT = {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/followthrough-20261106-fc33-release-source-chain01/source/derive_reviewed_release_sources_UNBOUND.py',
                      'bytes': 33827, 'sha256': '4c8f32d518c4cf17308f561587eeaf12702b8b9addf0bd8e5ad335a33e941835'}

def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

def enc(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()

def put(name, raw):
    p = HERE / name
    with p.open('xb') as f:
        f.write(raw)
    assert p.read_bytes() == raw
    return {'path': BINDING_ROOT + '/' + name, **pin(raw)}

constructor = (REVIEW / 'install-source-chain43/source/derive_reviewed_release_sources_UNBOUND.py').read_bytes()
consumer = (REVIEW / 'R5-release-consumer/source/release_boundaries.py').read_bytes()
runtime = (REVIEW / 'R5-root/runtime/MANIFEST.json').read_bytes()
for raw, row in [(constructor, CONSTRUCTOR_PARENT), (consumer, CONSUMER_PARENT), (runtime, RUNTIME)]:
    assert pin(raw) == {k: row[k] for k in ('bytes', 'sha256')}
M = types.ModuleType('reviewed_source_constructor')
exec(compile(constructor, CONSTRUCTOR_PARENT['path'], 'exec'), M.__dict__)
assert M.FROZEN_INPUTS is None and M.literal(consumer, 'PACKAGE_SHA') is None
c = M.Changes(consumer)
c.rhs('PACKAGE_SHA', RUNTIME['sha256'])
bound_consumer, consumer_change = c.finish()
assert len(consumer_change['changes']) == 1
consumer_desc = put('source/release_boundaries.py', bound_consumer)
inputs = json.loads((REVIEW / 'install-ready-input-templates/templates/01-SOURCE-CHAIN-INPUTS.template.json').read_bytes())
inputs['consumer'] = {'source': consumer_desc, 'runtime_package': RUNTIME}
inputs['output_root'] = DERIVED_ROOT
input_raw = enc(inputs)
input_desc = put('SOURCE-CHAIN-INPUTS.json', input_raw)
c = M.Changes(constructor)
c.rhs('FROZEN_INPUTS', input_desc)
bound_constructor, constructor_change = c.finish()
assert len(constructor_change['changes']) == 1
constructor_desc = put('source/derive_reviewed_release_sources_BOUND.py', bound_constructor)
authority = json.loads((REVIEW / 'R5-PREPARER-ACTUAL-INPUTS.json').read_bytes())
admission = json.loads((REVIEW / 'R5-PREPARER-BINDING.json').read_bytes())
proof = {
    'schema': 'hepta.fc33.reviewed-release-source-binding-preparation.v1',
    'state': 'PREPARED_SOURCE_ONLY_BYTES_MAC_PUBLICATION_NOT_EXECUTED',
    'binding_output': BINDING_ROOT,
    'derived_output': DERIVED_ROOT,
    'consumer_parent': CONSUMER_PARENT,
    'consumer': consumer_desc,
    'consumer_change': consumer_change,
    'constructor_parent': CONSTRUCTOR_PARENT,
    'constructor': constructor_desc,
    'constructor_change': constructor_change,
    'source_inputs': input_desc,
    'runtime_package': RUNTIME,
    'root_supplied_actual_freeze_inputs': authority,
    'root_supplied_independent_preparer_source': admission['source'],
    'root_reported_independent_preparer_job_id': '1a1b1d041f4-fc05-7aed',
    'root_reported_independent_preparer_exit_code': 0,
    'root_reported_independent_preparer_stdout_bytes': 3031,
    'root_reported_independent_preparer_stderr_bytes': 0,
    'independent_preparer_was_not_rerun_here': True,
    'new_case_inputs': None,
    'actual_BUILD': None,
    'actual_install': None,
    'actual_READY': None,
    'phone_calls': 0,
    'new_acceptance_nonces': 0,
    'new_control_scenarios': 0,
    'source_chain_derive_called': False,
    'full_source_inverse': True,
}
put('BINDING-PROOF.json', enc(proof))
print(json.dumps({'consumer': consumer_desc, 'constructor': constructor_desc,
                  'inputs': input_desc, 'full_inverse': True, 'phone_calls': 0}, sort_keys=True))
