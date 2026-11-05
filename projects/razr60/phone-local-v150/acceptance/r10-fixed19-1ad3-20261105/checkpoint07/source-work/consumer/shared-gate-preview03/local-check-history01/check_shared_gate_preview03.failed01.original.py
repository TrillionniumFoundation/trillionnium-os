"""Exercise the new pre-exec source gate with actual cached bytes, locally only."""
import ast
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import types
import zlib

ROOT = Path('/workspace/scratch/1ad3d6f55439')
BASE = ROOT / 'epoch_consumer_candidate01/shared-gate-preview03'
MATERIAL = ROOT / 'codec72_generation_candidate01/deterministic-preview01/materials'
PREVIEW = ROOT / 'codec72_generation_candidate01/deterministic-preview01'
RUNTIME = next(PREVIEW.rglob('REVIEWED-PRODUCTION-PINS.json')).parent.parent


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def desc(path):
    return dict(path=str(path), **pin(path.read_bytes()))


def load_selected(path, names, env):
    raw = path.read_bytes()
    nodes = [node for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert {node.name for node in nodes} == names
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<selected-local-source-gates>', 'exec'), env)
    return raw


names = {'need', 'sha', 'strict', 'encode', 'descriptor', 'file_descriptor', 'meta', 'read_pinned',
         'original_from', 'pack_original', 'checked_actual_context', 'verify_shared_runtime_originals',
         'shared_runtime_originals', 'validate_component'}
env = dict(__name__='local_shared_gate_check', hashlib=hashlib, json=json, Path=Path,
           re=re, os=os, stat=stat, base64=base64, zlib=zlib,
           HASH=re.compile(r'[0-9a-f]{64}\Z'), MAX_ORIGINAL=16*1024*1024, MAX_BUNDLE=32*1024*1024,
           SHARED_MATERIALS_SHA='121416839ffdac15485270cda0e95445e376b0a24801fa283659a3da084ae45f')
source_path = BASE / 'templates/release_boundaries.py'
source_raw = load_selected(source_path, names, env)
assert pin(source_raw) == dict(bytes=91611, sha256='c2027adeebb55662deb97e4f7fa7ddde5f3b21098ae0e0de1fc768f723549ed0')
tree = ast.parse(source_raw)
for node in tree.body:
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        if node.targets[0].id in ('COMPONENT_FIELDS', 'RELEASE', 'BOOT'):
            env[node.targets[0].id] = ast.literal_eval(node.value)

manifest_path = RUNTIME / 'MANIFEST.json'
manifest_raw = manifest_path.read_bytes(); manifest = json.loads(manifest_raw)
assert len(manifest['files']) == 32
source_files = {row['path']: (RUNTIME / row['path']).read_bytes() for row in manifest['files']}
for row in manifest['files']:
    assert pin(source_files[row['path']]) == {k: row[k] for k in ('bytes', 'sha256')}
shared_path = ROOT / 'codec72_generation_inputs_read01/SHARED-MATERIALS.json'
shared_raw = shared_path.read_bytes(); shared = json.loads(shared_raw)
shared_files = {row['path']: (MATERIAL / row['path']).read_bytes() for row in shared['files']}
combination_path = MATERIAL / 'COMBINATION.json'
if not combination_path.is_file():
    matches = [p for p in PREVIEW.rglob('COMBINATION.json')
               if pin(p.read_bytes())['sha256'] == '7616a1995a9bc346924db48560ff5b2d5de3b6b7836817c1674bedd1e723cfd0']
    assert len(matches) == 1
    combination_path = matches[0]
combination_raw = combination_path.read_bytes()
assert pin(combination_raw) == dict(bytes=4702, sha256='7616a1995a9bc346924db48560ff5b2d5de3b6b7836817c1674bedd1e723cfd0')
env.update(PACKAGE_SHA=pin(manifest_raw)['sha256'], PACKAGE_FILE_COUNT=32,
           CURRENT_COMBINATION_SHA=pin(combination_raw)['sha256'])
value = {k: None for k in env['COMPONENT_FIELDS']}
value.update(schema='hepta.r10.component-boundary-inputs.v6', release_id=env['RELEASE'], boot_id=env['BOOT'],
             component_package_manifest=desc(manifest_path),
             component_package_files=[dict(name=row['path'], copy=desc(RUNTIME / row['path'])) for row in manifest['files']],
             component_combination=desc(combination_path), component_shared_material_manifest=desc(shared_path),
             component_shared_material_files=[dict(name=row['path'], copy=desc(MATERIAL / row['path'])) for row in shared['files']])
all_raw = [manifest_raw, shared_raw, combination_raw, *source_files.values(), *shared_files.values()]
bundle = {'originals': {pin(raw)['sha256']: env['pack_original'](raw) for raw in all_raw}}
events = []


class BeforeRuntime(Exception):
    pass


def gate(m, s, c, f):
    assert m == manifest_raw and s == source_files and c == combination_raw and f == shared_files
    events.append('all_four_original_inputs_received_before_runtime')
    raise BeforeRuntime()


def forbidden_loader(*args, **kwargs):
    events.append('FORBIDDEN_RUNTIME_EXEC')
    raise AssertionError('component runtime loaded before pure source gate')


env['verify_epoch_runtime_increment'] = gate
env['component_modules'] = forbidden_loader
checks = []


def expect(name, action, exception):
    events.clear()
    try:
        action()
    except exception:
        assert 'FORBIDDEN_RUNTIME_EXEC' not in events
        checks.append(dict(name=name, result='observed_expected_gate', events=events[:]))
    else:
        raise AssertionError(name + ' did not reach the required refusal/stop')


for context in ('phone', 'mac', 'p4'):
    expect('consumer_' + context + '_complete32_plus17_and_combo_before_first_exec',
           lambda c=context: env['validate_component'](bundle, value, actual_context=c), BeforeRuntime)
missing = copy.deepcopy(value); missing['component_shared_material_files'].pop()
expect('missing_shared_original_refused_before_epoch_gate',
       lambda: env['validate_component'](bundle, missing, actual_context='mac'), ValueError)
duplicate = copy.deepcopy(value)
duplicate['component_shared_material_files'][-1] = copy.deepcopy(duplicate['component_shared_material_files'][0])
expect('duplicate_shared_original_refused_before_epoch_gate',
       lambda: env['validate_component'](bundle, duplicate, actual_context='mac'), ValueError)
corrupt = copy.deepcopy(bundle)
digest = shared['files'][0]['sha256']; raw = shared_files[shared['files'][0]['path']]
corrupt['originals'][digest] = env['pack_original'](raw[:-1] + bytes([raw[-1] ^ 1]))
expect('same_length_changed_shared_bytes_refused_before_epoch_gate',
       lambda: env['validate_component'](corrupt, value, actual_context='mac'), ValueError)
wrong = copy.deepcopy(value); wrong['component_combination'] = desc(shared_path)
expect('different_combination_refused_before_epoch_gate',
       lambda: env['validate_component'](bundle, wrong, actual_context='mac'), ValueError)
legacy = copy.deepcopy(value); legacy['schema'] = 'hepta.r10.component-boundary-inputs.v5'
expect('old_input_schema_cannot_omit_new_source_gate_materials',
       lambda: env['validate_component'](bundle, legacy, actual_context='mac'), ValueError)

# The constructor test uses real local complete-byte/full9 reads of the cached
# source package. Its gate raises before retirement, case or runtime loaders.
constructor_path = BASE / 'templates/make_component_boundary_inputs.py'
cenv = dict(__name__='local_constructor_gate_check', Path=Path, json=json, hashlib=hashlib,
            PACKAGE_SHA=env['PACKAGE_SHA'], SHARED_SHA=env['SHARED_MATERIALS_SHA'],
            SCHEMA='hepta.r10.component-boundary-construction-plan.v7')
constructor_raw = load_selected(constructor_path, {'need', 'sha', 'build'}, cenv)
h = types.SimpleNamespace(**{k: v for k, v in env.items() if k != '__name__'})
plan = dict(schema=cenv['SCHEMA'], package_manifest=desc(manifest_path), combination=desc(combination_path),
            retirement_descriptor=None, retirement_originals=None, shared_materials=desc(shared_path),
            policy_adoption=None, cases=[{'root_result': None}], legacy_ancestor=None, pre_policy_ancestor=None,
            environment_parent_ancestor=None, property_parent_ancestors=None)
# The shared manifest's real host sibling paths differ from this cached material
# layout. Repoint only the local manifest descriptor to an exact-byte local copy.
with tempfile.TemporaryDirectory(prefix='epoch-shared-gate-check-') as td:
    local = Path(td)
    (local / 'SHARED-MATERIALS.json').write_bytes(shared_raw)
    for name, raw in shared_files.items():
        target = local / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
    plan['shared_materials'] = desc(local / 'SHARED-MATERIALS.json')
    expect('constructor_collects_complete_sources_and_explicit_combo_before_any_ancestor_exec',
           lambda: cenv['build'](h, plan, local / 'new-output'), BeforeRuntime)
    assert not (local / 'new-output').exists()

report = dict(schema='hepta.epoch.shared-gate-local-checks.v1',
              state='PRE_EXEC_SHARED_ORIGINAL_GATES_CHECKED_NOT_EPOCH_RUNTIME_QUALIFIED',
              consumer=dict(path=str(source_path), **pin(source_raw)),
              constructor=dict(path=str(constructor_path), **pin(constructor_raw)),
              checks=checks, check_count=len(checks),
              actual_cached_runtime=pin(manifest_raw), actual_cached_combination=pin(combination_raw),
              actual_shared_manifest=pin(shared_raw),
              test_only_overrides=['pre-epoch package/combination trust pins in isolated local namespace',
                                   'epoch gate validates all four complete inputs then raises a local sentinel',
                                   'component module loader is a trap and must never be reached'],
              runtime_source_executed=False, new_epoch_verifier_executed=False,
              phone_calls=0, remote_calls=0, fixed19_case_credit=False,
              full_epoch_integration_verified=False)
raw = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
with (BASE / 'LOCAL-SHARED-GATE-CHECKS.json').open('xb') as handle:
    handle.write(raw)
print(json.dumps(dict(checks=len(checks), report=pin(raw), runtime_source_executed=False)))
