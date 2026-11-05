"""Bind the already-derived codec72 shared17 manifest, retaining the old draft."""
import ast
import hashlib
import json
from pathlib import Path

BASE = Path('/workspace/scratch/1ad3d6f55439/epoch_consumer_candidate01')
SOURCE = BASE / 'shared-gate-preview03'
TARGET = BASE / 'shared-gate-preview04'
OLD = '121416839ffdac15485270cda0e95445e376b0a24801fa283659a3da084ae45f'
NEW = 'af0d3e6b15a4eab40a52573db1ba5a24f1f1051f3965cad1b78039d889c0b8a5'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


assert not TARGET.exists()
parent = json.loads((SOURCE / 'SOURCE-DELTA.json').read_bytes())
rows = []
shared = BASE.parent / 'codec72_generation_candidate01/deterministic-shared-preview02/materials/SHARED-MATERIALS.json'
assert len(shared.read_bytes()) == 3519 and sha(shared.read_bytes()) == NEW
for row in parent['files']:
    p = Path(row['path']); old = p.read_bytes(); raw = old
    assert len(old) == row['bytes'] and sha(old) == row['sha256']
    changes = []
    if p.name in ('release_boundaries.py', 'make_component_boundary_inputs.py'):
        name = 'SHARED_MATERIALS_SHA' if p.name == 'release_boundaries.py' else 'SHARED_SHA'
        before = (name + ' = ' + repr(OLD) + '\n').encode()
        after = (name + ' = ' + repr(NEW) + '\n').encode()
        assert raw.count(before) == 1
        offset = raw.index(before)
        raw = raw.replace(before, after, 1)
        assert raw[:offset] + before + raw[offset+len(after):] == old
        changes = [dict(start=offset, old_utf8=before.decode(), new_utf8=after.decode())]
    ast.parse(raw); compile(raw, '<source-only-' + p.name + '>', 'exec')
    target = TARGET / p.relative_to(SOURCE); target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('xb') as handle:
        handle.write(raw)
    rows.append(dict(path=str(target), bytes=len(raw), sha256=sha(raw),
                     parent={k: row[k] for k in ('path', 'bytes', 'sha256')}, inverse_byte_splices=changes))
report = dict(schema='hepta.epoch.shared17-manifest-binding-source-preview.v1',
              state='SOURCE_ONLY_PENDING_FINAL_EPOCH_VERIFIER_AND_TWO_DOMAIN_CONSUMPTION', files=rows,
              shared_manifest=dict(path=str(shared), bytes=3519, sha256=NEW),
              old_parent_manifest_sha256=OLD,
              reason='The old manifest describes parent production/configuration/service bytes; exact shared-byte checking refused it against codec72 material bytes.',
              all_whole_source_inverses_verified=True, source_only_manifest_not_deployed_generation=True,
              final_four_argument_verifier_inserted=False, cascade_four_argument_gate_integration_pending=True,
              final_epoch_source_generation_bound=False, target_source_executed=False,
              phone_calls=0, remote_calls=0, case_credit=False)
with (TARGET / 'SOURCE-DELTA.json').open('x') as handle:
    json.dump(report, handle, sort_keys=True, indent=2); handle.write('\n')
print(json.dumps([{k: r[k] for k in ('path', 'bytes', 'sha256')} for r in rows], indent=2))
