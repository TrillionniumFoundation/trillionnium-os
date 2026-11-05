#!/usr/bin/env python3
"""Compare original and single-expression candidate on actual and adversarial data."""
import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import stat
import sys
import types

import profile_pure_history as H


def snapshot_load(args, candidate):
    selected = argparse.Namespace(archive=args.archive, stage_source=args.stage_source,
                                  candidate_source=candidate)
    files, lease, manifest, module, old_path, old_modules = H.load(selected)
    sys.path[:] = old_path
    for key, value in old_modules.items():
        if value is None:
            sys.modules.pop(key, None)
        else:
            sys.modules[key] = value
    return files, module


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def specimen(roots, leaves):
    """A complete little directory tree, independent of the ancestry predicate."""
    entries = {}
    def directory(path):
        entries[str(path)] = {'kind': 'directory', 'metadata': [1, 1, stat.S_IFDIR | 0o700, 0, 0, 2, 0, 10, 10], 'names': []}
    for root in roots:
        directory(Path(root))
    for root, components in leaves:
        parent = Path(root)
        for component in components[:-1]:
            child = parent / component
            if str(child) not in entries:
                directory(child)
            if component not in entries[str(parent)]['names']:
                entries[str(parent)]['names'].append(component)
            parent = child
        child = parent / components[-1]
        entries[str(child)] = {'kind': 'file', 'metadata': [1, 2, stat.S_IFREG | 0o600, 0, 0, 1, 1, 10, 10],
                               'bytes': 1, 'sha256': hashlib.sha256(b'x').hexdigest()}
        entries[str(parent)]['names'].append(components[-1])
    for row in entries.values():
        if row['kind'] == 'directory':
            row['names'].sort()
    return {'schema': 'hepta.native-guard.complete-inventory.v1', 'roots': list(roots),
            'entries': entries, 'file_bytes_hashed': len(leaves), 'elapsed_seconds': 0.25,
            'inventory_is_closure_or_retirement': False}


def outcome(module, value):
    before = encode(value)
    try:
        with H.no_external_effects():
            result = module.inventory_value(value)
        answer = {'accepted': True, 'output': {'bytes': len(encode(result)), 'sha256': H.sha(encode(result))}}
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        answer = {'accepted': False, 'error_type': type(error).__name__, 'detail': str(error)}
    H.require(before == encode(value), 'validator mutated input')
    return answer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--stage-source', type=Path, required=True)
    parser.add_argument('--candidate-source', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(mode=0o700)
    files, original = snapshot_load(args, None)
    _files, candidate = snapshot_load(args, args.candidate_source)
    parent_raw = files['package/source/late_boundary.py']
    candidate_raw = H.read_exact(args.candidate_source, H.CANDIDATE)
    H.require(candidate_raw.replace(H.NEW_EXPRESSION, H.OLD_EXPRESSION) == parent_raw,
              'whole-source inverse changed')
    parent_nodes = ast.parse(parent_raw).body
    candidate_nodes = ast.parse(candidate_raw).body
    changed = [getattr(a, 'name', a.__class__.__name__) for a, b in zip(parent_nodes, candidate_nodes)
               if ast.dump(a, include_attributes=False) != ast.dump(b, include_attributes=False)]
    H.require(len(parent_nodes) == len(candidate_nodes) and changed == ['inventory_value'],
              'unexpected AST delta')
    actual = json.loads(files['package/reference/attempt05-AFTER-INVENTORY.original.json'])
    base = specimen(['/scope/a', '/scope/ab'], [('/scope/a', ['child', 'item']), ('/scope/ab', ['item'])])
    cases = [('actual_1877_entry_retained_inventory', actual, True),
             ('shared_string_prefix_distinct_component_roots', base, True),
             ('unicode_emoji_components', specimen(['/审查/🧪'], [('/审查/🧪', ['中文', 'emoji😀.bin'])]), True),
             ('double_slash_anchor_kept_lexically_distinct', specimen(['//scope/a', '/scope/a'],
                 [('//scope/a', ['item']), ('/scope/a', ['item'])]), True),
             ('deep_150_component_tree', specimen(['/deep'], [('/deep', ['d%03d' % i for i in range(150)]+['leaf'])]), True)]
    def add(name, change, accepted=False):
        value = copy.deepcopy(base)
        change(value)
        cases.append((name, value, accepted))
    add('substring_sibling_outside_root', lambda v: v['entries'].update({'/scope/abc': copy.deepcopy(v['entries']['/scope/ab/item'])}))
    add('relative_entry', lambda v: v['entries'].update({'relative': copy.deepcopy(v['entries']['/scope/ab/item'])}))
    add('dot_entry_noncanonical', lambda v: v['entries'].update({'/scope/a/./x': copy.deepcopy(v['entries']['/scope/ab/item'])}))
    add('dotdot_entry', lambda v: v['entries'].update({'/scope/a/../x': copy.deepcopy(v['entries']['/scope/ab/item'])}))
    add('duplicate_root', lambda v: v['roots'].append(v['roots'][0]))
    add('overlapping_root', lambda v: v['roots'].append('/scope/a/child'))
    add('missing_root_record', lambda v: v['entries'].pop('/scope/a'))
    add('unlisted_child', lambda v: v['entries']['/scope/a']['names'].clear())
    add('fabricated_child_name', lambda v: v['entries']['/scope/ab']['names'].append('missing'))
    add('orphan_entry_parent_missing', lambda v: v['entries'].pop('/scope/a/child'))
    add('hardlinked_original_file', lambda v: v['entries']['/scope/ab/item']['metadata'].__setitem__(5, 2))
    add('file_metadata_size_differs', lambda v: v['entries']['/scope/ab/item']['metadata'].__setitem__(6, 2))
    add('wrong_total_bytes', lambda v: v.__setitem__('file_bytes_hashed', 100))
    add('bad_file_digest', lambda v: v['entries']['/scope/ab/item'].__setitem__('sha256', '0'*63))
    add('metadata_bool_not_int', lambda v: v['entries']['/scope/ab/item']['metadata'].__setitem__(0, True))
    add('claimed_closure', lambda v: v.__setitem__('inventory_is_closure_or_retirement', True))
    add('extra_schema_field', lambda v: v.__setitem__('synthetic_extra', True))
    fixture = '/proc/1/root/data/local/tmp/hepta-native-guard-'+'a'*32
    absent = specimen([fixture], [])
    absent['entries'][fixture] = {'kind': 'absent', 'absence': 'ENOENT'}
    cases.append(('explicit_fixture_enoent', absent, True))
    invalid_absent = copy.deepcopy(absent)
    invalid_absent['entries'][fixture]['absence'] = 'EACCES'
    cases.append(('permission_error_not_absence', invalid_absent, False))
    rows = []
    for name, value, expected in cases:
        a = outcome(original, copy.deepcopy(value))
        b = outcome(candidate, copy.deepcopy(value))
        rows.append({'case': name, 'input_sha256': H.sha(encode(value)),
                     'expected_accept': expected, 'original': a, 'candidate': b,
                     'passed': a == b and a['accepted'] is expected})
    result = {'schema': 'hepta.inventory-parts-equivalence-checks.v1',
              'state': 'ALL_PURE_EQUIVALENCE_CHECKS_PASSED' if all(r['passed'] for r in rows) else 'PURE_EQUIVALENCE_CHECK_FAILED',
              'checks_passed': sum(r['passed'] for r in rows), 'checks_total': len(rows),
              'whole_source_inverse_verified': True, 'only_changed_ast_function': changed,
              'source_parent': {'bytes': len(parent_raw), 'sha256': H.sha(parent_raw)},
              'source_candidate': {'bytes': H.CANDIDATE[0], 'sha256': H.CANDIDATE[1]},
              'actual_archive': {'bytes': H.ARCHIVE[0], 'sha256': H.ARCHIVE[1]},
              'phone_calls': 0, 'p4_calls': 0, 'process_starts': 0,
              'live_current_admission_executed': False, 'case_qualification': False,
              'checks': rows}
    report = H.save(args.out / 'EQUIVALENCE.json', result)
    print(json.dumps({'state': result['state'], 'passed': result['checks_passed'],
                      'total': result['checks_total'], 'report': report}, sort_keys=True))
    H.require(all(r['passed'] for r in rows), 'one or more exact-equivalence checks failed; retain this run')


if __name__ == '__main__':
    main()
