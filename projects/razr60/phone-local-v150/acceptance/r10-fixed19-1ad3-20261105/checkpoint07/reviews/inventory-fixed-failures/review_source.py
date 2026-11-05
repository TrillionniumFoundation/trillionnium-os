import ast
import hashlib
import json
from pathlib import Path

ROOT = Path('/workspace/scratch/1ad3d6f55439')
OUT = Path(__file__).parent
OLD = ROOT / 'property_diagnostic/epoch_inventory_core_candidate01/delivery-final01/package/source/component_lifecycle.py'
NEW = ROOT / 'property_diagnostic/epoch_inventory_failed_fixture_candidate01/draft02/source/component_lifecycle.py'


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def nodes(raw):
    text = raw.decode()
    lines = text.splitlines(keepends=True)
    result = {}
    for node in ast.parse(text).body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            result[node.name] = (node, ''.join(lines[node.lineno - 1:node.end_lineno]))
    return result, lines


old = OLD.read_bytes()
new = NEW.read_bytes()
assert pin(old) == {'bytes': 102896, 'sha256': 'bace77b9bfc6550f2a9ea29b102fc7d20b917ff11994ba30007a6affae167048'}
assert pin(new) == {'bytes': 106287, 'sha256': '8efadfa585529c538da263de75c2bff6f4995def9f8e4061f9e43e52f4d4b928'}
before, oldlines = nodes(old)
after, newlines = nodes(new)
assert set(before) == set(after)
changed = {name for name in before if before[name][1] != after[name][1]}
assert changed == {'inventory_epoch_spec_value', '_epoch_inventory_observation_value', 'verify_epoch_inventory_observation'}
inverse = newlines[:]
for name in sorted(changed, key=lambda n: after[n][0].lineno, reverse=True):
    node = after[name][0]
    inverse[node.lineno - 1:node.end_lineno] = [before[name][1]]
inverse = ''.join(inverse)
added = ('# These exact failed identities can never become an active fixture.\n'
         '# Historical intents bind names only; every operation must obtain fresh\n'
         '# positive ENOENT with the original canonical-parent observations.\n')
tree = ast.parse(inverse)
binding = [node for node in tree.body if isinstance(node, ast.Assign)
           and any(isinstance(target, ast.Name) and target.id == 'EPOCH_INVENTORY_RETAINED_FAILED_FIXTURE_ABSENCES'
                   for target in node.targets)]
assert len(binding) == 1
constant = ast.literal_eval(binding[0].value)
line = ast.get_source_segment(inverse, binding[0]) + '\n'
assert inverse.count(added + line) == 1
inverse = inverse.replace(added + line, '', 1).encode()
assert inverse == old

refs = ROOT / 'property_diagnostic/epoch_inventory_failed_fixture_candidate01/reference'
for row, name in zip(constant, ['external09', 'own01', 'own02']):
    raw = (refs / (name + '-CHAIN-INTENT.original.json')).read_bytes()
    value = json.loads(raw)
    assert row == dict(label=value['label'], nonce=value['nonce'],
                       path='/proc/1/root/data/local/tmp/hepta-native-guard-' + value['nonce'],
                       presence='absent', chain_intent=pin(raw))

result = json.loads((ROOT / 'property_diagnostic/epoch_inventory_failed_fixture_candidate01/validation/local-checks-run01/RESULT.json').read_bytes())
assert result['passed'] == result['total'] == 9 and all(row['passed'] for row in result['checks'])
assert result['phone_calls'] == result['remote_calls'] == 0
report = {
    'schema': 'hepta.root-independent-failed-fixture-v2-source-review.v1',
    'state': 'NARROW_SOURCE_INCREMENT_REVIEWED_UNBOUND_NOT_RUNTIME_READY',
    'source': dict(path=str(NEW), **pin(new)),
    'parent': dict(path=str(OLD), **pin(old)),
    'whole_source_inverse': pin(inverse),
    'whole_source_inverse_equals_actual_parent': True,
    'changed_functions_read_in_full_diff': sorted(changed),
    'unchanged_functions_and_classes': sorted(set(before) - changed),
    'fixed_identities_independently_matched_to_three_original_intents': constant,
    'review_findings': [
        'All three exact historical nonces are permanently forbidden for active reservations.',
        'The v2 domain is fixed and forced absent; a fourth arbitrary namespace and generic reclassification are refused.',
        'Required absence reaches the unchanged physical walker; any present type is refused before traversal.',
        'Positive ENOENT requires actual canonical-parent observations and full metadata bookends; intent bytes do not establish current absence.',
        'The three namespaces are charged to the same root/entry/byte/time pool and omitted from both directory-root v1 projections.',
        'Seven legacy plus at most eight active potentially present fixtures retain the 15 limit; 18 named namespaces explicitly include three forced absences.',
        'All old single-domain functions and the epoch physical walker, budget, split/join and main entrypoint remain byte-identical.',
        'EPOCH_INVENTORY_EXTRA_ROOTS remains None and rejects production use before actual binding.'
    ],
    'existing_necessary_local_checks_reviewed': {'passed': 9, 'total': 9, 'rerun': False},
    'phone_calls': 0,
    'remote_calls': 0,
    'target_source_executed': False,
    'fresh_phone_absence_proved_by_this_review': False,
    'fixed19_case_credit': 0
}
OUT.mkdir(parents=True, exist_ok=True)
raw = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()
target = OUT / 'REVIEW.json'
with target.open('xb') as handle:
    handle.write(raw)
print(json.dumps(dict(path=str(target), **pin(raw))))
