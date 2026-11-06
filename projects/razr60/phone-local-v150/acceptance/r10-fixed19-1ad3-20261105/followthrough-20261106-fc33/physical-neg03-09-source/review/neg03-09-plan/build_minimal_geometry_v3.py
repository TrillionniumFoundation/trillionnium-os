#!/usr/bin/env python3
"""Derive only the explicit synthetic geometry fixture's native schema adapter.

No production source, component direct-return helper or actual input changes.
The complete reference digest functions are copied from the already retained
v3 regression and remain independent of the production digest implementation.
"""
import ast
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OLD = ROOT / 'reference/cpu-negative-capture-generation-final01/package/validation/parent-source-fixtures/component/source/verify_unqualified_geometry_fixture.py'
HELPER = ROOT.parent / 'source-audit-v3/test_shared_business_admission_v3.py'
OUT = ROOT / 'candidate/component/verify_unqualified_geometry_fixture.py'


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def function(raw, name):
    rows = [n for n in ast.parse(raw).body if isinstance(n, ast.FunctionDef) and n.name == name]
    assert len(rows) == 1
    lines = raw.splitlines(keepends=True)
    return b''.join(lines[rows[0].lineno - 1:rows[0].end_lineno])


def derive():
    original, helper = OLD.read_bytes(), HELPER.read_bytes()
    assert pin(original) == {'bytes': 18636, 'sha256': '3cbc0d9d77629c2183f706fc897075a16952e4cb586f16fef29a65e521c81487'}
    assert pin(helper) == {'bytes': 40884, 'sha256': 'dbbfece5877955b68a98770af41a9010365990b3fdbe29a8c9c37e648ec6756a'}
    names = ('sha', 'reference_field', 'reference_claims', 'reference_observation', 'seal_native_fixture', 'native')
    fragments = [function(helper, name) for name in names]
    replacement = b'\n\n'.join(fragments) + b'''\n\ndef synthetic_reply(call,raw):
 # Only explicitly synthetic fixture scopes enter this constructor.
 assert all(isinstance(value,str) and value.startswith('synthetic-') for value in call['turn'].values())
 return native(call['call_id'],raw,call['wire_tool'],wire_call=call['wire_call'],scope=call['turn'])
'''
    old_identity = b'''  identity={'schema':'hepta.operator-isolated-component-fixture.v1','case_id':'NEG-03',
            'fixture_id':self.fixture_id,'instance':label,'synthetic':True}
  self.check(label+' no fabricated native task scope',not ({'session_id','profile_id','task_id','turn_id','stream_id'}&set(identity)))
'''
    new_identity = b'''  token=self.C.sha(canonical([self.fixture_id,label]))[:32]
  identity={key:'synthetic-'+key+'-'+token for key in
            ('session_id','profile_id','task_id','turn_id','turn_stream_id')}
  self.check(label+' explicitly synthetic native scope with no actual task',
             all(value.startswith('synthetic-') for value in identity.values()))
'''
    old_report = b"   'all_receipts_synthetic':True,'actual_phone_observations':0,'no_original_native_task_identity_fabricated':True,\n"
    new_report = old_report + b"   'all_native_scopes_synthetic':True,'actual_native_scope_or_generation_attested':False,\n"
    edits = [(function(original, 'synthetic_reply'), replacement),
             (old_identity, new_identity), (old_report, new_report)]
    candidate = original
    for before, after in edits:
        assert candidate.count(before) == 1
        candidate = candidate.replace(before, after, 1)
    reverse = candidate
    for before, after in reversed(edits):
        assert reverse.count(after) == 1
        reverse = reverse.replace(after, before, 1)
    assert reverse == original
    compile(candidate, str(OUT), 'exec')
    return original, candidate, {'schema': 'fc33.geometry-native-schema-derivation.v1',
        'original': pin(original), 'candidate': pin(candidate), 'independent_fixture_helper': pin(helper),
        'exact_reference_functions': {name: pin(fragment) for name, fragment in zip(names, fragments)},
        'complete_inverse': True, 'production_changed': False, 'direct_return_helper_changed': False,
        'synthetic_only': True, 'actual_release': None, 'actual_ready': None,
        'phone_calls': 0, 'physical_qualification': False}


if __name__ == '__main__':
    original, candidate, proof = derive()
    OUT.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    for path, raw in [(OUT, candidate),
                      (OUT.with_suffix('.py.patch'), ''.join(difflib.unified_diff(
                          original.decode().splitlines(True), candidate.decode().splitlines(True),
                          fromfile='reference/verify_unqualified_geometry_fixture.py',
                          tofile='candidate/verify_unqualified_geometry_fixture.py')).encode()),
                      (OUT.parent / 'DERIVATION.json', (json.dumps(proof, sort_keys=True, indent=2)+'\n').encode())]:
        with path.open('xb') as handle:
            handle.write(raw)
    print(json.dumps(proof, sort_keys=True))
