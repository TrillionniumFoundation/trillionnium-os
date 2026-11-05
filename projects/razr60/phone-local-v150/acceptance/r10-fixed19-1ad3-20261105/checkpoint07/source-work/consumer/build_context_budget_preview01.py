#!/usr/bin/env python3
"""Build a source-only exact delta; no target modules or target operations."""
import ast
import hashlib
import json
from pathlib import Path

ROOT = Path('/workspace/scratch/1ad3d6f55439')
OUT = ROOT / 'epoch_consumer_candidate01/context-budget-preview01'
MAP = ROOT / 'transport_fix/consumer-actual-context-call-map01/CALL-MAP.json'

def need(ok, reason):
    if not ok:
        raise ValueError(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def once(raw, old, new, count=1):
    old, new = old.encode(), new.encode()
    need(raw.count(old) == count, 'exact replacement occurrence count differs: ' + old[:100].decode())
    return raw.replace(old, new)

def calls(raw, keyword_values):
    tree = ast.parse(raw)
    lines = raw.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    changes = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else None
        if isinstance(fn, ast.Subscript) and isinstance(fn.slice, ast.Constant):
            name = fn.slice.value
        if name not in keyword_values:
            continue
        need(not any(k.arg == 'actual_context' for k in node.keywords), 'context was already supplied')
        start = offsets[node.lineno - 1] + node.col_offset
        end = offsets[node.end_lineno - 1] + node.end_col_offset
        old = raw[start:end]
        need(old.endswith(b')'), 'call does not end at closing parenthesis')
        new = old[:-1] + b', actual_context=' + keyword_values[name].encode() + b')'
        changes.append((start, end, old, new))
    for start, end, old, new in sorted(changes, reverse=True):
        need(raw[start:end] == old, 'overlapping source call delta')
        raw = raw[:start] + new + raw[end:]
    return raw, len(changes)

ADDED = '''def checked_actual_context(value):
    need(type(value) is str and value in ('phone', 'mac', 'p4'),
         'explicit actual phone/mac/p4 execution context required')
    return value


def decoded_bundle_budget(bundle):
    """Charge all decoded payloads before any body decode or source execution."""
    need(type(bundle['originals']) is dict, 'exact original byte pool required')
    total = 0
    for name in ('component', 'policy'):
        row = bundle['inputs'][name]
        need(type(row) is dict and set(row) == {'descriptor', 'raw_b64'},
             'input payload fields differ')
        descriptor = file_descriptor(row['descriptor'])
        need(type(row['raw_b64']) is str
             and len(row['raw_b64']) <= 4 * ((descriptor['bytes'] + 2) // 3),
             'input payload exceeds its exact decoded bound')
        total += descriptor['bytes']
    need(total <= MAX_BUNDLE, 'decoded input payloads exceed fixed shared bundle budget')
    for digest, item in bundle['originals'].items():
        need(type(digest) is str and HASH.fullmatch(digest)
             and type(item) is dict
             and set(item) in ({'bytes', 'raw_b64'}, {'bytes', 'zlib_b64'})
             and type(item['bytes']) is int and 0 <= item['bytes'] <= MAX_ORIGINAL,
             'bounded decoded original pool entry required')
        total += item['bytes']
        need(total <= MAX_BUNDLE, 'decoded originals exceed one fixed shared bundle budget')
    return total


'''

def build():
    map_raw = MAP.read_bytes()
    need(len(map_raw) == 14506 and sha(map_raw) == '53ad641704b632323a56b3f4fed6540622593029bc1a05633e320bdd498ad91c',
         'reviewed exact call map differs')
    rows = json.loads(map_raw)['sources']
    selected = {
        'release_boundaries.py': 'templates/release_boundaries.py',
        'make_component_boundary_inputs.py': 'templates/make_component_boundary_inputs.py',
        'derive_final_cascade_property_r8.py': 'source/derive_final_cascade_property_r8.py',
        'write_final_seal_interface_property_r8.py': 'source/write_final_seal_interface_property_r8.py',
        'prepare_final_cascade.py': 'preparer/prepare_final_cascade.py',
        'build_release_r10.py': 'templates/build_release_r10.py',
        'component_source_context.py': 'downstream/component_source_context.py',
        'prepare_fixed19_host_r10.py': 'downstream/prepare_fixed19_host_r10.py',
    }
    need(not OUT.exists(), 'new source-only candidate already exists')
    output_rows = []
    for row in rows:
        name = Path(row['path']).name
        if name not in selected:
            continue
        old = Path(row['path']).read_bytes()
        need(len(old) == row['bytes'] and sha(old) == row['sha256'], 'source map pin mismatch')
        raw = old
        if name == 'release_boundaries.py':
            raw, count = calls(raw, {'component_modules': "state['actual_context']", 'validate_bundle': 'actual_context', 'validate_component': 'actual_context'})
            need(count == 8, 'consumer exact context callsite set differs')
            raw = once(raw, 'def prepare_bundle(component_input, policy_input):',
                       'def prepare_bundle(component_input, policy_input, *, actual_context):')
            raw = once(raw, '    inputs = {}; originals = {}; observed = {}',
                       "    actual_context = checked_actual_context(actual_context)\n    need(actual_context == 'mac', 'this fixed host constructor requires actual Mac context')\n    inputs = {}; originals = {}; observed = {}")
            raw = once(raw, 'def component_modules(state, *, runtime=False):',
                       'def component_modules(state, *, actual_context, runtime=False):')
            raw = once(raw, "    names = ['component_common', 'late_boundary']",
                       "    actual_context = checked_actual_context(actual_context)\n    need('actual_context' not in state or state['actual_context'] == actual_context,\n         'actual execution context changed between validation and module loading')\n    need(not runtime or actual_context == 'phone', 'live runtime modules require actual phone context')\n    names = ['component_common', 'late_boundary']")
            raw = once(raw, "            module.__reviewed_source_sha256__ = sha(raw)",
                       "            module.__actual_context__ = actual_context\n            module.__reviewed_source_sha256__ = sha(raw)")
            raw = once(raw, 'def validate_component(bundle, value):',
                       'def validate_component(bundle, value, *, actual_context):\n    actual_context = checked_actual_context(actual_context)')
            raw = once(raw, "    state = {'package_sources': source, 'component_input': value,",
                       "    state = {'actual_context': actual_context, 'package_sources': source, 'component_input': value,")
            raw = once(raw, 'def validate_bundle(raw, expected_sha256):',
                       'def validate_bundle(raw, expected_sha256, *, actual_context):\n    actual_context = checked_actual_context(actual_context)')
            raw = once(raw, "    component_value = input_value(bundle, 'component'); policy_value = input_value(bundle, 'policy')",
                       "    decoded_bundle_budget(bundle)\n    component_value = input_value(bundle, 'component'); policy_value = input_value(bundle, 'policy')")
            raw = once(raw, 'def prepare_bundle(component_input, policy_input, *, actual_context):',
                       ADDED + 'def prepare_bundle(component_input, policy_input, *, actual_context):')
        else:
            raw, count = calls(raw, {'component_modules': "'mac'", 'validate_bundle': "'mac'", 'prepare_bundle': "'mac'"})
            need(count == {'make_component_boundary_inputs.py':5,
                'derive_final_cascade_property_r8.py':1, 'write_final_seal_interface_property_r8.py':1,
                'prepare_final_cascade.py':0, 'build_release_r10.py':1,
                'component_source_context.py':1, 'prepare_fixed19_host_r10.py':1}[name],
                'host caller exact callsite set differs')
        ast.parse(raw)
        compile(raw, '<source-only-context-preview-' + name + '>', 'exec')
        target = OUT / selected[name]
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as f:
            f.write(raw)
        # Whole-source inversion is mechanically retained as exact splice rows.
        import difflib
        old_lines, new_lines = old.splitlines(keepends=True), raw.splitlines(keepends=True)
        delta = []
        for tag, a, b, c, d in difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False).get_opcodes():
            if tag != 'equal':
                delta.append({'new_start_line':c, 'new_end_line':d,
                    'new_utf8':b''.join(new_lines[c:d]).decode(),
                    'old_utf8':b''.join(old_lines[a:b]).decode()})
        restored = list(new_lines)
        for part in reversed(delta):
            a,b = part['new_start_line'],part['new_end_line']
            need(b''.join(restored[a:b]).decode() == part['new_utf8'], 'whole inverse splice differs')
            restored[a:b] = part['old_utf8'].encode().splitlines(keepends=True)
        need(b''.join(restored) == old, 'complete original source inverse failed')
        output_rows.append({'path':str(target),'bytes':len(raw),'sha256':sha(raw),
            'original':row, 'inverse':delta, 'all_other_source_bytes_unchanged':True})
    need(len(output_rows) == 8, 'complete source-only preview set required')
    report = {'schema':'hepta.epoch.consumer-context-budget-source-preview.v1',
        'state':'EXPLICIT_CONTEXT_AND_DECODED_POOL_SOURCE_ONLY_NOT_EPOCH_READY',
        'files':output_rows, 'actual_context_keyword_required':True,
        'runtime_false_never_selects_a_host':True,
        'old_source_inverse_complete':True,'target_modules_executed':False,
        'phone_calls':0,'new_nonce_or_lease':False,'case_credit':False,
        'still_required':['Final epoch four-argument pure gate and source freeze',
            'Two-domain epoch originals/constructor/current preservation integration',
            'Phone caller source updates and final all-caller compatibility',
            'Actual full decoded bundle size and final consumer131072 cap']}
    with (OUT/'SOURCE-DELTA.json').open('x') as f:
        json.dump(report,f,ensure_ascii=False,sort_keys=True,indent=2);f.write('\n')
    print(json.dumps({'state':report['state'],'files':[{k:r[k] for k in ('path','bytes','sha256')} for r in output_rows]},indent=2))

if __name__ == '__main__':
    build()
