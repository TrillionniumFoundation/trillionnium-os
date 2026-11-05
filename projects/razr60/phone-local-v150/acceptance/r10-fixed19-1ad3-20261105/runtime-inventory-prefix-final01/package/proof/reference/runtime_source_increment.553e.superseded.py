#!/usr/bin/env python3
"""Exact pure verifier for the one reviewed R8 inventory-prefix source increment."""
import hashlib
import json

RUNTIME_SOURCE_INCREMENT = {'base_freeze_result': {'bytes': 22392,
                        'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8/FREEZE-RESULT.json',
                        'sha256': 'f1e9f063468d1bfdbed0f1e877afb70acafcddf78bbc872dc4078d472afddc67'},
 'base_freezer_source': {'bytes': 36899,
                         'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-property-r8-freeze-final01/source/freeze_property_runtime.py',
                         'sha256': '70e0ccc9844438aeee54ba4e734e886c81c2e640f92a997a766015e7bb5b285d'},
 'base_runtime_manifest': {'bytes': 16808,
                           'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8/runtime/MANIFEST.json',
                           'sha256': '67dc40470b8ecb1e10cb57f8953a3d0b6db309b45079216eb24cd65f0760107c'},
 'changed_member': {'parent': {'bytes': 66996,
                               'sha256': 'c50a219efd992ce1353494ace2656af20c932cbc32530b0085e38a79975d8add'},
                    'path': 'source/late_boundary.py',
                    'successor': {'bytes': 67005,
                                  'sha256': '147cf49e91fb4bcbddeba6591d48c8782efe20452db2b2d6179e7addd68c27e4'}},
 'inherited_metadata_scope': 'original_r7_to_r8_generation_preserved_not_successor_actions',
 'runtime_member_count': 32,
 'schema': 'hepta.native-guard.runtime-source-increment.v1',
 'state': 'EXACT_RUNTIME32_SINGLE_EXPRESSION_SUCCESSOR_SOURCE_ONLY',
 'successor_actions': {'historical_reference_changes': 0,
                       'host_source_derivation': True,
                       'new_nonces': 0,
                       'phone_operations': 0,
                       'policy_adoptions_created': 0,
                       'policy_applications': 0},
 'transformation': {'accepted_path_domain': 'canonical_absolute_posix_without_dotdot',
                    'function': 'inventory_value',
                    'new_utf8': 'sum(p.parts[:len(q.parts)] == q.parts for q in paths) == 1',
                    'old_utf8': 'sum(p == q or q in p.parents for q in paths) == 1',
                    'whole_source_inverse_required': True},
 'unchanged_member_count': 31}


def verify_runtime_source_increment(manifest_raw, source_files):
    """Pure exact32/source-and-manifest inverse; never opens or executes a file.

    Dependencies are only this module's fixed RUNTIME_SOURCE_INCREMENT object
    and the standard json/hashlib modules. All parsing/encoding helpers are
    local to prevent caller strict/encode implementations changing semantics.
    The caller still performs its original proof, filesystem and case gates.
    """
    def require(value, reason):
        if not value:
            raise ValueError('runtime source increment: ' + reason)

    def digest(raw):
        return hashlib.sha256(raw).hexdigest()

    def encode(value):
        return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                           allow_nan=False) + '\n').encode('utf-8')

    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result

    def nonfinite(_value):
        raise ValueError('runtime source increment: nonfinite JSON')

    require(type(manifest_raw) is bytes and 0 < len(manifest_raw) <= 65536,
            'bounded exact manifest bytes required')
    manifest = json.loads(manifest_raw, object_pairs_hook=pairs, parse_constant=nonfinite)
    require(type(manifest) is dict and encode(manifest) == manifest_raw,
            'original manifest encoding differs')
    require(manifest.get('runtime_source_increment') == RUNTIME_SOURCE_INCREMENT,
            'one fixed reviewed runtime increment required')
    require(type(source_files) is dict and type(manifest.get('files')) is list
            and len(manifest['files']) == len(source_files) == 32,
            'exact32 source container required')
    rows = {}
    for row in manifest['files']:
        require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
                and type(row['path']) is str and row['path'] not in rows
                and type(row['bytes']) is int and 0 <= row['bytes'] <= 8 * 1024 * 1024
                and type(row['sha256']) is str,
                'exact bounded unique source row required')
        rows[row['path']] = row
    require(set(rows) == set(source_files), 'complete32 source names differ')
    for name, row in rows.items():
        body = source_files[name]
        require(type(body) is bytes and len(body) == row['bytes']
                and digest(body) == row['sha256'], 'source bytes differ: ' + name)
    change = RUNTIME_SOURCE_INCREMENT['changed_member']
    name = change['path']
    require(name in rows and rows[name] == dict(path=name, **change['successor']),
            'only the exact reviewed current reader can be changed')
    candidate = source_files[name]
    transformation = RUNTIME_SOURCE_INCREMENT['transformation']
    before = transformation['old_utf8'].encode('ascii')
    after = transformation['new_utf8'].encode('ascii')
    require(candidate.count(after) == 1, 'one exact successor expression required')
    restored_source = candidate.replace(after, before, 1)
    require(restored_source.count(before) == 1
            and {'bytes': len(restored_source), 'sha256': digest(restored_source)} == change['parent'],
            'complete current reader inverse differs from actual c50a')
    retained_increment = manifest.pop('runtime_source_increment')
    restored_rows = []
    for row in manifest['files']:
        restored_rows.append(dict(path=name, **change['parent']) if row['path'] == name else row)
    manifest['files'] = restored_rows
    restored_manifest = encode(manifest)
    parent = RUNTIME_SOURCE_INCREMENT['base_runtime_manifest']
    require({'bytes': len(restored_manifest), 'sha256': digest(restored_manifest)}
            == {key: parent[key] for key in ('bytes', 'sha256')},
            'whole manifest inverse differs from actual16808/67dc')
    return {'schema': 'hepta.native-guard.runtime-source-increment-proof.v1',
            'state': 'EXACT_RUNTIME32_SINGLE_EXPRESSION_AND_PARENT_INVERSES_VERIFIED',
            'runtime_manifest': {'bytes': len(manifest_raw), 'sha256': digest(manifest_raw)},
            'base_runtime_manifest': dict(parent), 'runtime_source_increment': retained_increment,
            'member_count': 32, 'unchanged_member_count': 31,
            'all32_source_bytes_verified': True, 'whole_source_inverse_verified': True,
            'whole_manifest_inverse_verified': True,
            'target_source_executed': False, 'historical_reference_changes': 0,
            'phone_calls': 0, 'component_qualified': False, 'business_qualified': False}
