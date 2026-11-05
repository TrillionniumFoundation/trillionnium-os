#!/usr/bin/env python3
"""Build only a local exact source candidate from the retained actual archive."""
import ast
import copy
import hashlib
import io
import json
from pathlib import Path
import types
import zlib
import tarfile

BASE = Path('/workspace/scratch/1ad3d6f55439')
HERE = BASE / 'runtime_prefix_successor_candidate01'
PACKAGE = HERE / 'package'
DEST = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-inventory-prefix-1ad3-01')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + '\n').encode()


def desc(path, raw):
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def put(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
    assert path.read_bytes() == raw


def main():
    assert not PACKAGE.exists()
    archive_path = BASE / 'actual_neg01_1ad3_01/reconciliation/component-inputs.original.tar.gz'
    archive_raw = archive_path.read_bytes()
    assert len(archive_raw) == 469829 and sha(archive_raw) == '9aacc5789a65dd875ab9fe7456e2258e0bf4e54575d3be71a50d5542a489b288'
    decoder = zlib.decompressobj(31)
    plain = decoder.decompress(archive_raw, 16 * 1024 * 1024 + 1)
    assert len(plain) <= 16 * 1024 * 1024 and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
    files = {}
    with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as archive:
        for item in archive:
            path = Path(item.name)
            assert str(path) == item.name and not path.is_absolute() and '..' not in path.parts
            assert item.isreg() and not item.pax_headers and item.uid == item.gid == 0
            assert item.mode == 0o600 and item.mtime == 0 and 0 <= item.size <= 8 * 1024 * 1024
            assert item.name not in files and len(files) < 80
            stream = archive.extractfile(item)
            raw = stream.read(item.size + 1)
            assert len(raw) == item.size
            files[item.name] = raw
    assert len(files) == 56 and sum(map(len, files.values())) <= 8 * 1024 * 1024
    parent_raw = files['package/MANIFEST.json']
    assert parent_raw == (BASE / 'actual_r8_external_freeze/runtime/MANIFEST.json').read_bytes()
    assert len(parent_raw) == 16808 and sha(parent_raw) == '67dc40470b8ecb1e10cb57f8953a3d0b6db309b45079216eb24cd65f0760107c'
    parent = json.loads(parent_raw)
    assert encode(parent) == parent_raw and len(parent['files']) == 32
    source = {}
    for row in parent['files']:
        raw = files['package/' + row['path']]
        assert len(raw) == row['bytes'] and sha(raw) == row['sha256']
        assert row['path'] not in source
        source[row['path']] = raw
    old_source = source['source/late_boundary.py']
    candidate = (BASE / 'prelaunch_pure_history_candidate01/source/late_boundary.py').read_bytes()
    assert len(old_source) == 66996 and sha(old_source) == 'c50a219efd992ce1353494ace2656af20c932cbc32530b0085e38a79975d8add'
    assert len(candidate) == 67005 and sha(candidate) == '147cf49e91fb4bcbddeba6591d48c8782efe20452db2b2d6179e7addd68c27e4'
    record_raw = (HERE / 'RUNTIME-SOURCE-INCREMENT.json').read_bytes()
    record = json.loads(record_raw)
    pure_raw = (HERE / 'source/runtime_source_increment.v2.py').read_bytes()
    assert len(pure_raw) == 7269 and sha(pure_raw) == '6282d6d5478d3bd65acc368198db3af550c7284f9c8e66d0b101d6d8269628e4'
    verifier = types.ModuleType('local_pure_runtime_increment_verifier')
    exec(compile(pure_raw, str(HERE / 'source/runtime_source_increment.v2.py'), 'exec'), verifier.__dict__)
    assert encode(verifier.RUNTIME_SOURCE_INCREMENT) == record_raw
    current = copy.deepcopy(parent)
    current['runtime_source_increment'] = record
    for row in current['files']:
        if row['path'] == 'source/late_boundary.py':
            row.update(bytes=len(candidate), sha256=sha(candidate))
    source['source/late_boundary.py'] = candidate
    current_raw = encode(current)
    proof = verifier.verify_runtime_source_increment(current_raw, source)
    checks = [{'case': 'actual32_source_successor', 'passed': True, 'proof': proof}]

    def reject(name, manifest, bodies):
        try:
            verifier.verify_runtime_source_increment(encode(manifest), bodies)
        except (ValueError, TypeError, KeyError) as error:
            checks.append({'case': name, 'passed': True, 'error_type': type(error).__name__, 'detail': str(error)})
        else:
            raise AssertionError('invalid increment accepted: ' + name)

    value = copy.deepcopy(current)
    value['runtime_source_increment']['successor_actions']['phone_operations'] = False
    reject('boolean_cannot_replace_integer_zero_in_fixed_increment', value, source)
    value = copy.deepcopy(current)
    value['runtime_source_increment']['successor_actions']['host_source_derivation'] = 1
    reject('integer_one_cannot_replace_boolean_in_fixed_increment', value, source)
    value = copy.deepcopy(current)
    value.pop('runtime_source_increment')
    reject('missing_increment', value, source)
    bodies = dict(source)
    selected = next(name for name in bodies if name != 'source/late_boundary.py')
    bodies[selected] += b'\n'
    reject('changed_one_of_other31_source_bytes', current, bodies)
    value = copy.deepcopy(current)
    value['current_policy_sha256'] = '0' * 64
    reject('changed_parent_metadata_cannot_inverse_to67dc', value, source)
    bodies = dict(source)
    bodies['source/late_boundary.py'] = old_source
    reject('old_reader_cannot_masquerade_as_successor', current, bodies)

    put(HERE / 'reference/component-inputs.original.tar.gz', archive_raw)
    put(HERE / 'reference/runtime32/MANIFEST.json', parent_raw)
    for row in parent['files']:
        put(HERE / 'reference/runtime32' / row['path'], files['package/' + row['path']])
    put(PACKAGE / 'runtime/MANIFEST.json', current_raw)
    for name, raw in sorted(source.items()):
        put(PACKAGE / 'runtime' / name, raw)
    put(PACKAGE / 'proof/RUNTIME-SOURCE-INCREMENT.json', record_raw)
    put(PACKAGE / 'proof/source/runtime_source_increment.py', pure_raw)
    validation = {'schema': 'hepta.runtime-increment.local-pure-checks.v1',
                  'state': 'LOCAL_EXACT_RUNTIME32_AND_TARGETED_REJECTIONS_PASSED',
                  'checks': checks, 'checks_passed': len(checks), 'checks_total': len(checks),
                  'runtime_target_modules_executed': 0, 'phone_calls': 0, 'remote_calls': 0,
                  'pure_verifier_executed': True, 'case_qualification': False}
    validation_raw = encode(validation)
    put(PACKAGE / 'proof/validation/RUNTIME-PURE-CHECKS.json', validation_raw)
    result = {'schema': 'hepta.native-guard.runtime-source-increment-result.v1',
              'state': 'LOCAL_SOURCE_SUCCESSOR_PREPARED_NOT_REMOTE_STAGED_OR_EXECUTED',
              'base_freeze_result': record['base_freeze_result'],
              'base_freezer_source': record['base_freezer_source'],
              'base_runtime_manifest': record['base_runtime_manifest'],
              'runtime_manifest': desc(DEST / 'runtime/MANIFEST.json', current_raw),
              'runtime_source_increment': desc(DEST / 'proof/RUNTIME-SOURCE-INCREMENT.json', record_raw),
              'pure_verifier_source': desc(DEST / 'proof/source/runtime_source_increment.py', pure_raw),
              'source_inverse_proof': proof,
              'local_source_checks': desc(DEST / 'proof/validation/RUNTIME-PURE-CHECKS.json', validation_raw),
              'runtime_member_count': 32, 'unchanged_member_count': 31,
              'canonical_originals_modified': False, 'original_freeze_claimed_this_successor': False,
              'remote_directories_created_by_this_derivation': 0, 'phone_calls': 0, 'policy_applications': 0,
              'case_nonces_created': 0, 'root_execution_started': False,
              'component_qualified': False, 'business_qualified': False}
    result_raw = encode(result)
    put(PACKAGE / 'proof/RUNTIME-INCREMENT-RESULT.json', result_raw)
    print(json.dumps({'runtime_manifest': result['runtime_manifest'],
                      'runtime_increment_result': desc(DEST / 'proof/RUNTIME-INCREMENT-RESULT.json', result_raw),
                      'pure_verifier': result['pure_verifier_source'], 'checks': len(checks),
                      'changed_members': ['source/late_boundary.py'], 'unchanged_members': 31}, sort_keys=True))


if __name__ == '__main__':
    main()
