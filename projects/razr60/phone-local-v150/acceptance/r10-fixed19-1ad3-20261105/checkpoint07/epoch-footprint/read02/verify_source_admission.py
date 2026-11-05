import ast
import hashlib
import json
from pathlib import Path

ROOT = Path('/workspace/scratch/1ad3d6f55439')
BASE = ROOT / 'epoch_footprint_observer_candidate02/delivery-final01/package'
PARENT = ROOT / 'epoch_footprint_observer_candidate01/delivery-final01/package'
OUT = Path(__file__).parent


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def definitions(raw):
    lines = raw.splitlines(keepends=True)
    return {n.name: (n, b''.join(lines[n.lineno-1:n.end_lineno]))
            for n in ast.parse(raw).body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}, lines


mfraw = (BASE / 'SOURCE-MANIFEST.json').read_bytes()
assert pin(mfraw) == dict(bytes=4594, sha256='cdbc7163b3367c42d0f251ef7321d4d224ba4bd8a879a036f6c7c0ef9b71fe28')
mf = json.loads(mfraw); names = {'SOURCE-MANIFEST.json'}
for row in mf['files']:
    p = Path(row['path'])
    assert not p.is_absolute() and '..' not in p.parts and str(p) == row['path']
    assert row['path'] not in names
    actual = BASE / p
    assert not actual.is_symlink() and actual.stat().st_nlink == 1
    assert pin(actual.read_bytes()) == {k: row[k] for k in ('bytes', 'sha256')}
    names.add(row['path'])
assert names == {str(p.relative_to(BASE)) for p in BASE.rglob('*') if p.is_file()} and len(names) == 24
source = (BASE / 'source/observe_fixed_epoch_footprint_once.py').read_bytes()
old = (PARENT / 'source/observe_fixed_epoch_footprint_once.py').read_bytes()
assert pin(source) == dict(bytes=58657, sha256='779546dde4ed021be8851c0c1410dfdabc7019533986530e78bd58e3924aaf34')
assert pin(old) == dict(bytes=57213, sha256='2a3e0b1d40afdf8ce535975e5fdb7068bd0d4c56429f2d6492f755f441719b98')
before, _ = definitions(old); after, lines = definitions(source)
changed = {n for n in before if before[n][1] != after[n][1]}
assert changed == {'metadata_budget', 'read_fixed_absence', 'main'}
assert set(after) - set(before) == {'parent_observation_reference', 'expand_parent_observation_reference'}
assert len(before) - len(changed) == 23
edits = [(after[n][0].lineno-1, after[n][0].end_lineno, before[n][1]) for n in changed]
edits.append((after['parent_observation_reference'][0].lineno-1,
              after['pid1_generation'][0].lineno-1, b''))
inverse = lines[:]
for start, end, replacement in sorted(edits, reverse=True):
    inverse[start:end] = [replacement]
inverse = b''.join(inverse)
assert inverse.count(b'LAST_METADATA_BYTES = 0\n') == 1
inverse = inverse.replace(b'LAST_METADATA_BYTES = 0\n', b'', 1)
assert inverse == old

caller = (BASE / 'operator/P4-LAUNCHER.py').read_bytes()
oldcaller = (PARENT / 'operator/P4-LAUNCHER.py').read_bytes()
assert pin(caller) == dict(bytes=126692, sha256='536c7c53f0b9287e187b449a9dcf6a5e15c2585c4f2db0fd3ad4aea2e159c5d3')
assert pin(oldcaller) == dict(bytes=123662, sha256='380baa2c9d3547e9b48dbc2d5939b0a28340f497080de8e9fca4b9a477aa6a63')
review = json.loads((BASE / 'validation/SOURCE-CALLER-REVIEW.json').read_bytes())
inverse = caller
assert len(review['caller_exact_five_splices']) == 5
for row in sorted(review['caller_exact_five_splices'], key=lambda v: v['new_start'], reverse=True):
    actual = caller[row['new_start']:row['new_end']]
    prior = oldcaller[row['start']:row['end']]
    assert pin(actual) == row['new'] and pin(prior) == row['old']
    inverse = inverse[:row['new_start']] + prior + inverse[row['new_end']:]
assert inverse == oldcaller
values = {n.targets[0].id: ast.literal_eval(n.value) for n in ast.parse(caller).body
          if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
          and n.targets[0].id in ('PROBE', 'REQ', 'LABEL')}
assert values['PROBE'] == source and values['LABEL'] == 'ng-epoch-retained-footprint-1ad3-read02'
request_raw = (BASE / 'operator/CONTROLLER-REQUEST.json').read_bytes()
assert pin(request_raw) == dict(bytes=131130, sha256='02ca2db8c876a5fece9c92691dca4a1dc515b1a8108e3b4e26102ec99d5911a4')
request = json.loads(request_raw)
assert set(request) == {'host', 'executable', 'args', 'cwd', 'stdin', 'idempotency_key'}
assert request['host'] == 'pocket4' and request['stdin'].encode() == caller
assert request['idempotency_key'] == 'root-1ad3-epoch-retained-footprint-read02-20261105'
req = json.loads((BASE / 'operator/PHONE-REQUEST.original.json').read_bytes())
assert req == values['REQ'] and set(req) == {'kind', 'root', 'command', 'timeout_seconds'}
assert req['kind'] == 'shell' and req['root'] is True and req['timeout_seconds'] == 210
marker = 'FIXED_EPOCH_FOOTPRINT_READ02'
head, body = req['command'].split("<<'" + marker + "'\n", 1)
assert body.endswith('\n' + marker + '\n') and body[:-len(marker)-1].encode() == source
assert review['wire']['actual_shell_v2_service_bytes'] == 63904 < 65536
assert len(caller) < 131072 and review['passive_actor_wait_seconds'] == 240
independent_path = ROOT / 'property_diagnostic/reviews/epoch-footprint-reference-codec-independent02/REVIEW.json'
assert pin(independent_path.read_bytes()) == dict(bytes=3882, sha256='7fd37b223a1d9d638cf544a945c69de8cb02b98da6ecd938ede1f2466d36a8a6')
measurement = json.loads((BASE / 'validation/CACHED-METADATA-MEASUREMENT.json').read_bytes())
assert measurement['current_complete_metadata_measurement'] is False
assert measurement['failed_read01_phase_reconstructed'] is False
assert measurement['unchanged_metadata_limit_bytes'] == 524288
report = {
    'schema': 'hepta.epoch.footprint-root-source-admission.v2',
    'state': 'EXACT_FIXED_READ02_FORMAT_FIX_REVIEWED_FOR_ONE_READONLY_INVOCATION',
    'source_manifest': pin(mfraw), 'source_members': 24,
    'source': pin(source), 'caller': pin(caller), 'request': pin(request_raw),
    'source_whole_inverse_to_actual_read01': True,
    'unchanged_physical_reader_functions_and_classes': 23,
    'caller_five_splice_whole_inverse_to_actual_read01': True,
    'complete_footprint_literal_and_read_scope_unchanged': True,
    'full_parent_rows_retained_in_unique_table': True,
    'canonical_reference_digest_and_index_exactly_expandable': True,
    'physical_absence_reads_and_parent_bookends_unchanged': True,
    'new_failure_report_retains_original_failure_phase_and_counts': True,
    'fixed_metadata_limit_bytes': 524288,
    'fresh_total_metadata_bytes_unknown_before_observation': True,
    'failed_read01_original_outcome_preserved': True,
    'phone_source_exact_heredoc_including_trailing_LF': True,
    'controller_stdin_bytes': len(caller), 'phone_wire_bytes': 63904,
    'phone_readonly_observations_max': 1,
    'new_case_nonce_or_lease': False,
    'outer_timeout': False,
    'owned_child_passive_wait_seconds': 240,
    'phone_timeout_seconds': 210,
    'shared_observer_seconds': 30,
    'independent_review': dict(path=str(independent_path), **pin(independent_path.read_bytes())),
    'case_credit': False,
    'already_executed': False
}
OUT.mkdir(exist_ok=True)
raw = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
with (OUT / 'ROOT-SOURCE-ADMISSION.json').open('xb') as f:
    f.write(raw)
print(json.dumps(dict(path=str(OUT / 'ROOT-SOURCE-ADMISSION.json'), **pin(raw),
                     request_fields={k: v for k, v in request.items() if k != 'stdin'}, phone_command_prefix=head)))
