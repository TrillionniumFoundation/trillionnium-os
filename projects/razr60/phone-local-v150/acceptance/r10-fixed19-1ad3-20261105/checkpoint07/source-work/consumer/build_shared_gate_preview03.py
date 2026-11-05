"""Collect all four pure-gate inputs before the first component module executes.

This is an unbound source integration step. The final epoch verifier and the
two-domain boundary consumer must still be inserted and independently reviewed.
"""
import ast
import difflib
import hashlib
import json
from pathlib import Path

BASE = Path('/workspace/scratch/1ad3d6f55439/epoch_consumer_candidate01')
SOURCE = BASE / 'context-budget-preview02'
TARGET = BASE / 'shared-gate-preview03'


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def once(raw, old, new):
    old, new = old.encode(), new.encode()
    need(raw.count(old) == 1, 'exact source splice differs: ' + old[:100].decode())
    return raw.replace(old, new, 1)


SHARED_HELPERS = '''def verify_shared_runtime_originals(manifest_raw, files, reviewed_production):
    """Pure closed shared17 byte verification before loading any runtime source."""
    need(type(manifest_raw) is bytes and 0 < len(manifest_raw) <= 65536
         and sha(manifest_raw) == SHARED_MATERIALS_SHA,
         'the fixed complete shared material manifest is required')
    manifest = strict(manifest_raw)
    need(type(reviewed_production) is dict and len(reviewed_production) == 15
         and all(type(name) is str and Path(name).name == name and name.endswith('.py')
                 for name in reviewed_production), 'exact reviewed production names required')
    expected = {'provider/source/' + name for name in reviewed_production}
    expected.update({'local-config-r10-r1.json', 'PHONE-SERVICE-INPUTS-v150-r10-r1.json'})
    need(type(manifest) is dict
         and manifest['schema'] == 'hepta.r10.shared-production-materials.v1'
         and type(manifest['files']) is list and len(manifest['files']) == 17
         and type(files) is dict and set(files) == expected,
         'all seventeen exact shared originals are required before runtime loading')
    pins = {}
    for row in manifest['files']:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
             and type(row['path']) is str and row['path'] in expected
             and row['path'] not in pins and type(row['bytes']) is int
             and 0 < row['bytes'] <= MAX_ORIGINAL
             and type(row['sha256']) is str and HASH.fullmatch(row['sha256']),
             'closed shared material manifest member differs')
        pins[row['path']] = row
    need(set(pins) == expected, 'shared material manifest path set differs')
    for name, raw in files.items():
        need(type(raw) is bytes and descriptor(raw) == {k: pins[name][k] for k in ('bytes', 'sha256')},
             'complete shared original bytes or hash differ')
        if name.startswith('provider/source/'):
            need(pins[name]['sha256'] == reviewed_production[Path(name).name],
                 'shared production original differs from the runtime reviewed source pin')
    return manifest


def shared_runtime_originals(bundle, value, source):
    manifest_raw = original_from(bundle, value['component_shared_material_manifest'])
    rows = value['component_shared_material_files']
    need(type(rows) is list and len(rows) == 17, 'exact shared17 host-copy descriptors required')
    files = {}
    for row in rows:
        need(type(row) is dict and set(row) == {'name', 'copy'}
             and type(row['name']) is str and row['name'] not in files,
             'unique named shared material host copies required')
        files[row['name']] = original_from(bundle, row['copy'])
    reviewed = strict(source['reference/REVIEWED-PRODUCTION-PINS.json'])
    verify_shared_runtime_originals(manifest_raw, files, reviewed)
    return files


'''

EARLY_SHARED = '''    combination_copy = plan['combination']
    combination_raw = collect(combination_copy)
    need(sha(combination_raw) == h.CURRENT_COMBINATION_SHA,
         'the explicitly reviewed current combination must be known before runtime loading')
    shared_raw = collect(plan['shared_materials'])
    need(sha(shared_raw) == SHARED_SHA == h.SHARED_MATERIALS_SHA,
         'actual original shared17 manifest required')
    shared = h.strict(shared_raw); shared_dir = Path(plan['shared_materials']['path']).parent
    need(type(shared) is dict and shared['schema'] == 'hepta.r10.shared-production-materials.v1'
         and type(shared['files']) is list and len(shared['files']) == 17,
         'actual shared material manifest schema/count differs')
    shared_files = {}; shared_package_files = []
    for entry in shared['files']:
        need(type(entry) is dict and set(entry) == {'path', 'bytes', 'sha256'},
             'exact shared original descriptor required')
        relative = Path(entry['path'])
        need(not relative.is_absolute() and '..' not in relative.parts and str(relative) == entry['path'],
             'unsafe shared material path')
        need(entry['path'] not in shared_files, 'duplicate shared material original')
        row = dict(path=str(shared_dir/relative), bytes=entry['bytes'], sha256=entry['sha256'])
        shared_files[entry['path']] = collect(row)
        shared_package_files.append(dict(name=entry['path'], copy=row))
    runtime_files = {item['path']: bodies[item['sha256']] for item in manifest['files']}
    reviewed_production = h.strict(runtime_files['reference/REVIEWED-PRODUCTION-PINS.json'])
    h.verify_shared_runtime_originals(shared_raw, shared_files, reviewed_production)
    # The final four-argument epoch capsule must be inserted before this source can run.
    # Every new runtime byte, combination and shared17 original precedes the first exec.
    h.verify_epoch_runtime_increment(manifest_raw, runtime_files, combination_raw, shared_files)
'''


def build():
    need(not TARGET.exists(), 'source candidate already exists')
    previous = json.loads((SOURCE / 'SOURCE-DELTA.json').read_bytes())
    outputs = []
    for row in previous['files']:
        p = Path(row['path']); old = p.read_bytes(); raw = old
        need(len(old) == row['bytes'] and sha(old) == row['sha256'], 'previous whole source differs')
        if p.name == 'release_boundaries.py':
            raw = once(raw, 'CURRENT_COMBINATION_SHA = None\n',
                       "CURRENT_COMBINATION_SHA = None\nSHARED_MATERIALS_SHA = '121416839ffdac15485270cda0e95445e376b0a24801fa283659a3da084ae45f'\n")
            raw = once(raw, "    'component_package_files', 'component_combination', 'latest_boundary',",
                       "    'component_package_files', 'component_combination', 'latest_boundary',\n    'component_shared_material_manifest', 'component_shared_material_files',")
            raw = once(raw, 'def validate_component(bundle, value, *, actual_context):\n',
                       SHARED_HELPERS + 'def validate_component(bundle, value, *, actual_context):\n')
            raw = once(raw, "value['schema'] == 'hepta.r10.component-boundary-inputs.v5'",
                       "value['schema'] == 'hepta.r10.component-boundary-inputs.v6'")
            raw = once(raw,
                       "    # Validate every new runtime byte before any component source is executed.\n    verify_runtime_source_increment(manifest_raw, source)\n    combination_raw = original_from(bundle, value['component_combination'])\n    need(sha(combination_raw)==CURRENT_COMBINATION_SHA,'current reviewed policy combination differs')\n",
                       "    combination_raw = original_from(bundle, value['component_combination'])\n    need(sha(combination_raw)==CURRENT_COMBINATION_SHA,'current reviewed policy combination differs')\n    shared_files = shared_runtime_originals(bundle, value, source)\n    # All four exact source inputs must pass the final epoch gate before the first exec.\n    verify_epoch_runtime_increment(manifest_raw, source, combination_raw, shared_files)\n")
            raw = once(raw,
                       "             'component_combination': combination, 'component_originals': copies}",
                       "             'component_combination': combination, 'component_originals': copies,\n             'shared_runtime_originals': shared_files}")
        elif p.name == 'make_component_boundary_inputs.py':
            raw = once(raw, "SCHEMA = 'hepta.r10.component-boundary-construction-plan.v6'",
                       "SCHEMA = 'hepta.r10.component-boundary-construction-plan.v7'")
            raw = once(raw, "    need(set(plan) == {'schema', 'package_manifest', 'retirement_descriptor',",
                       "    need(set(plan) == {'schema', 'package_manifest', 'combination', 'retirement_descriptor',")
            raw = once(raw,
                       "    # The constructor must pass the same complete-byte gate before any runtime loader.\n    h.verify_runtime_source_increment(manifest_raw,\n        {item['path']: bodies[item['sha256']] for item in manifest['files']})\n",
                       EARLY_SHARED)
            raw = once(raw,
                       '    results = []; boundary_rows = []; combination_copy = None; combination_raw = None; publish_raw = None',
                       '    results = []; boundary_rows = []; publish_raw = None')
            raw = once(raw,
                       "        combo_raw = collect(combo)\n        if index == 0:\n            combination_copy, combination_raw = combo, combo_raw\n",
                       "        combo_raw = collect(combo)\n        need(combo_raw == combination_raw,\n             'closed case combination differs from the original reviewed pre-exec combination')\n        if index == 0:\n")
            raw = once(raw,
                       "        else:\n            need(combo_raw == combination_raw, 'closed cases used different combinations')\n        results.append((result, boundary))",
                       "        results.append((result, boundary))")
            raw = once(raw,
                       "    value = dict(schema='hepta.r10.component-boundary-inputs.v5', release_id=h.RELEASE, boot_id=h.BOOT,\n        component_package_manifest=plan['package_manifest'], component_package_files=package_files,",
                       "    value = dict(schema='hepta.r10.component-boundary-inputs.v6', release_id=h.RELEASE, boot_id=h.BOOT,\n        component_package_manifest=plan['package_manifest'], component_package_files=package_files,\n        component_shared_material_manifest=plan['shared_materials'],\n        component_shared_material_files=shared_package_files,")
            late_start = raw.index(b"    shared_raw = collect(plan['shared_materials'])\n", raw.index(b"    state = h.validate_bundle(bundle_raw, sha(bundle_raw), actual_context='mac')\n"))
            late_end = raw.index(b"    sources = {Path(name).name: body for name, body in shared_files.items()", late_start)
            raw = raw[:late_start] + raw[late_end:]
            raw = once(raw, "'schema':'hepta.r10.component-boundary-construction-result.v5'",
                       "'schema':'hepta.r10.component-boundary-construction-result.v6'")
            raw = once(raw,
                       "        'release_bundle_preview':h.descriptor(bundle_raw), 'shared_materials':plan['shared_materials'],",
                       "        'release_bundle_preview':h.descriptor(bundle_raw), 'shared_materials':plan['shared_materials'],\n        'reviewed_combination_before_runtime_loading':combination_copy,")
        elif p.name in ('derive_final_cascade_property_r8.py', 'write_final_seal_interface_property_r8.py'):
            need(raw.count(b'hepta.r10.component-boundary-construction-plan.v6') == 2,
                 'current construction schema sites differ')
            need(raw.count(b'hepta.r10.component-boundary-inputs.v5') == (3 if p.name.startswith('derive') else 2),
                 'current component schema sites differ')
            raw = raw.replace(b'hepta.r10.component-boundary-construction-plan.v6',
                              b'hepta.r10.component-boundary-construction-plan.v7')
            raw = raw.replace(b'hepta.r10.component-boundary-inputs.v5',
                              b'hepta.r10.component-boundary-inputs.v6')
            if p.name == 'write_final_seal_interface_property_r8.py':
                raw = once(raw,
                           "    template=dict(schema='hepta.r10.component-boundary-construction-plan.v7',package_manifest=manifest,\n",
                           "    template=dict(schema='hepta.r10.component-boundary-construction-plan.v7',package_manifest=manifest,\n        combination=combo,\n")
        ast.parse(raw); compile(raw, '<source-only-' + p.name + '>', 'exec')
        old_lines, new_lines = old.splitlines(keepends=True), raw.splitlines(keepends=True)
        delta = []
        for tag, a, b, c, d in difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False).get_opcodes():
            if tag != 'equal':
                delta.append(dict(new_start_line=c, new_end_line=d,
                                  new_utf8=b''.join(new_lines[c:d]).decode(),
                                  old_utf8=b''.join(old_lines[a:b]).decode()))
        inverse = new_lines[:]
        for edit in reversed(delta):
            a, b = edit['new_start_line'], edit['new_end_line']
            need(b''.join(inverse[a:b]).decode() == edit['new_utf8'], 'inverse observed bytes differ')
            inverse[a:b] = edit['old_utf8'].encode().splitlines(keepends=True)
        need(b''.join(inverse) == old, 'whole source inverse differs')
        target = TARGET / p.relative_to(SOURCE)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as handle:
            handle.write(raw)
        outputs.append(dict(path=str(target), bytes=len(raw), sha256=sha(raw),
                            parent={k: row[k] for k in ('path', 'bytes', 'sha256')}, inverse=delta))
    report = dict(schema='hepta.epoch.shared17-four-input-gate-source-preview.v1',
                  state='SOURCE_ONLY_PENDING_FINAL_EPOCH_VERIFIER_AND_TWO_DOMAIN_CONSUMPTION',
                  files=outputs, all_whole_source_inverses_verified=True,
                  component_input_schema='hepta.r10.component-boundary-inputs.v6',
                  construction_plan_schema='hepta.r10.component-boundary-construction-plan.v7',
                  explicit_combination_and_shared17_collected_before_component_exec=True,
                  shared_originals_in_complete_bundle_descriptor_pool=True,
                  case_combinations_must_equal_pre_exec_original=True,
                  final_four_argument_verifier_inserted=False,
                  old_two_argument_verifier_is_not_new_gate_authority=True,
                  cascade_four_argument_gate_integration_pending=True,
                  final_epoch_source_generation_bound=False,
                  target_source_executed=False, phone_calls=0, remote_calls=0, case_credit=False)
    with (TARGET / 'SOURCE-DELTA.json').open('x') as handle:
        json.dump(report, handle, sort_keys=True, indent=2); handle.write('\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'files'}, indent=2))
    print(json.dumps([{k: r[k] for k in ('path', 'bytes', 'sha256')} for r in outputs], indent=2))


if __name__ == '__main__':
    build()
