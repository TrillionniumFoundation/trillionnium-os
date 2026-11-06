#!/usr/bin/env python3
"""Derive E2E source candidates only. No task material, nonce, process or phone call."""
import argparse
import ast
import difflib
import hashlib
import json
import os
from pathlib import Path
import stat

HERE = Path(__file__).resolve().parent
META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns')
PARENT_COLLECTOR = (19271, 'b8513e925526059be82f3063af0add9dd7a1d2824c7ca9fa783173f5e9c7220b')
PARENT_OPERATORS = (1754, 'd8b106084b5329e6e991a1d81aa3542c19421bab2142e001604f2c79b0563d50')
PARENT_COORDINATOR = (20119, 'fd892ebb871442fb984068881dfcecd32af899bd3aa43fe21f891a518fbf706a')
TRANSFER_PIN = (46645, '2217ec199c9d11e2fcc4c65a75f4ab13fbf4262e1df723f8261c3c42b95589fa')
COMBINATION_PIN = (4695, '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411')
SHARED_PIN = (3519, 'cc7eb624333216e510b540c3af8277e948aa689a108950fa78e8d01c2177e5b1')
READINESS_PARENT = (16407, '2b4ff90f7078af2481feb8a2d33c39d1a0e260102cd769a4ee3b46d9bec47e11')
MATERIALIZER_INPUTS = {
    'materialize_case_r10.py': (24834, 'b25125bc0e204ea7aefde6f2a17fa2fb8e5edf132a4b62dfbb546964c1c09290'),
    'references/materialize_case_r4.py': (9783, 'f2b2416cd895e9235fc36cbad07cc32f763420410fc48829c99ac9c566a3fb81'),
    'RUNTIME-COMPONENT-QUALIFICATION.json': (1872, 'e3e10557b7ece137916c7cb8bb9b5c049224c851dd47546f9a729a9a98557d81'),
}
CHANGED = {'daily_phone_local.py', 'phone_local_tools.py', 'phone_observation_tools.py',
           'provider_codex_host.py', 'provider_phone_local.py'}
PROJECTION_PIN = 'b86a027b0fcb6aea55b845c42c7b3af916eebeee20148eb8d49485f08d86127b'
PROJECTION_FUNCTIONS = {'_mobile_schema_matches', 'mobile_use_schema', 'mobile_use_policy',
                        'normalize_mobile_use', 'mobile_mapping_evidence'}
PROJECTION_CONSTANTS = {'MOBILE_USE_POLICY', 'MOBILE_USE_HINTS'}


def need(value, why):
    if not value:
        raise ValueError(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def strict(raw):
    def pairs(rows):
        out = {}
        for key, value in rows:
            need(key not in out, 'duplicate JSON key')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))


def desc(path, raw):
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def read(path, pin=None):
    path = Path(path).absolute()
    need(path.resolve(strict=True) == path, 'canonical source path required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 < before.st_size <= 1048576, 'bounded one-link source required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(before.st_size + 1)
        need(len(raw) == before.st_size and [getattr(before, k) for k in META]
             == [getattr(os.fstat(fd), k) for k in META]
             == [getattr(path.lstat(), k) for k in META], 'source changed during read')
        need(pin is None or (len(raw), sha(raw)) == tuple(pin), 'source pin differs: ' + str(path))
        return raw
    finally:
        os.close(fd)


def literal(raw, name):
    nodes = [n for n in ast.parse(raw).body if isinstance(n, ast.Assign)
             and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
             and n.targets[0].id == name]
    need(len(nodes) == 1, 'one literal required: ' + name)
    return ast.literal_eval(nodes[0].value)


def replace_once(raw, old, new):
    need(raw.count(old) == 1, 'one exact substitution required')
    value = raw.replace(old, new)
    need(value.replace(new, old, 1) == raw, 'whole-byte inverse differs')
    return value


def derive():
    refs = HERE / 'references'
    cm_path = refs / 'acceptance-tools-v150-r10-v3-shared-a1055-r2/MANIFEST.json'
    om_path = refs / 'readiness-r9/operator-chain/SOURCE-MANIFEST.json'
    co_path = HERE.parent / 'formal-originals/E2E-COORDINATOR.original.py'
    transfer_path = HERE.parent / 'shared-v3-original-transfer.json'
    cm_raw, om_raw = read(cm_path, PARENT_COLLECTOR), read(om_path, PARENT_OPERATORS)
    cm, om = strict(cm_raw), strict(om_raw)
    transfer_raw = read(transfer_path, TRANSFER_PIN)
    transfer = strict(transfer_raw)
    need(type(transfer) is list and len(transfer) == 6, 'six actual shared originals required')
    originals = {}
    for row in transfer:
        need(set(row) == {'path', 'bytes', 'sha256', 'text'}, 'actual transfer fields differ')
        raw = row['text'].encode('utf-8')
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'transferred original differs')
        name = Path(row['path']).name
        need(name not in originals, 'duplicate original basename')
        originals[name] = (row, raw)
    combination_raw = originals['COMBINATION.json'][1]
    shared_raw = originals['SHARED-MATERIALS.json'][1]
    need((len(combination_raw), sha(combination_raw)) == COMBINATION_PIN, 'exact actual source combination')
    need((len(shared_raw), sha(shared_raw)) == SHARED_PIN, 'exact actual shared source manifest')
    combination, shared = strict(combination_raw), strict(shared_raw)
    production_rows = {Path(r['path']).name: r for r in combination['production_files']}
    need(len(production_rows) == len(combination['production_files']) == 15, 'exact fifteen sources')
    selected = {}
    files = {}
    for name, row in production_rows.items():
        path = HERE.parent / 'source-audit-v3/candidate/source' / name
        raw = read(path, (row['bytes'], row['sha256']))
        ast.parse(raw, filename=name)
        selected[name] = row['sha256']
        files['shared/provider/source/' + name] = raw
    need(set(selected) == set(cm['reviewed_production_source_pins']), 'reviewed source set changed')
    need({n for n in selected if selected[n] != cm['reviewed_production_source_pins'][n]} == CHANGED,
         'only the five reviewed source identities may change')
    for name in ('local-config-r10-r1.json', 'PHONE-SERVICE-INPUTS-v150-r10-r1.json'):
        files['shared/' + name] = originals[name][1]
    need(len(shared['files']) == 17 and len({r['path'] for r in shared['files']}) == 17,
         'exact shared seventeen rows')
    for row in shared['files']:
        raw = files['shared/' + row['path']]
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'shared exact member mismatch')
    files['shared/SHARED-MATERIALS.json'] = shared_raw
    for name in ('COMBINATION.json', 'SOURCE-SEAL.json', 'DERIVATION.json'):
        files['source-origin/' + name] = originals[name][1]

    collector_rows = [r for r in cm['files'] if r['path'].startswith('collector/')]
    need(len(collector_rows) == 7 and len({r['path'] for r in collector_rows}) == 7, 'seven collectors')
    changes = []
    for row in collector_rows:
        raw = read(cm_path.parent / row['path'], (row['bytes'], row['sha256']))
        candidate = raw
        if row['path'] == 'collector/mobile_use_evidence.py':
            need(literal(raw, 'REVIEWED_HELPER_SOURCE_PINS') == cm['reviewed_production_source_pins'],
                 'parent manifest and parser source map differ')
            for name in sorted(CHANGED):
                candidate = replace_once(candidate, cm['reviewed_production_source_pins'][name].encode(),
                                         selected[name].encode())
            inverse = candidate
            for name in sorted(CHANGED):
                inverse = replace_once(inverse, selected[name].encode(),
                                       cm['reviewed_production_source_pins'][name].encode())
            need(inverse == raw and literal(candidate, 'REVIEWED_HELPER_SOURCE_PINS') == selected,
                 'five literal propagation must invert to exact full parent')
            need(literal(candidate, 'PROJECTION_FRAGMENTS_SHA256') == PROJECTION_PIN,
                 'projection hash cannot change')
            changes.append((row['path'], raw, candidate))
        ast.parse(candidate, filename=row['path'])
        files['collector-package/' + row['path']] = candidate
    provider = files['shared/provider/source/provider_phone_local.py'].decode()
    selected_nodes = [n for n in ast.parse(provider).body
                      if (isinstance(n, ast.FunctionDef) and n.name in PROJECTION_FUNCTIONS)
                      or (isinstance(n, ast.Assign) and len(n.targets) == 1
                          and isinstance(n.targets[0], ast.Name) and n.targets[0].id in PROJECTION_CONSTANTS)]
    fragments = {n.name if isinstance(n, ast.FunctionDef) else n.targets[0].id:
                 sha(ast.get_source_segment(provider, n).encode()) for n in selected_nodes}
    need(len(fragments) == 7 and sha(json.dumps(fragments, ensure_ascii=False, sort_keys=True,
             separators=(',', ':'), allow_nan=False).encode()) == PROJECTION_PIN,
         'all seven actual production projection bodies must remain exact')
    collector_manifest = {
        'schema': 'hepta.r10.acceptance-tools.v1',
        'state': 'SOURCE_REBOUND_UNQUALIFIED_NO_ACTUAL_CASE',
        'parent_manifest': desc(cm_path, cm_raw),
        'current_shared_materials': {k: originals['SHARED-MATERIALS.json'][0][k]
                                     for k in ('path', 'bytes', 'sha256')},
        'current_source_combination': {k: originals['COMBINATION.json'][0][k]
                                      for k in ('path', 'bytes', 'sha256')},
        'reviewed_production_source_pins': selected,
        'files': [desc(name.removeprefix('collector-package/'), body)
                  for name, body in sorted(files.items()) if name.startswith('collector-package/')],
        'source_change': 'Exactly five SHA256 literals in mobile_use_evidence; six other collectors byte-identical.',
        'projection_fragments_sha256_unchanged': PROJECTION_PIN,
        'historical_suites_rerun': False, 'historical_pass_inherited': False,
        'current_collector_executions': 0, 'current_business_qualification': False,
        'phone_calls': 0, 'model_requests': 0, 'native_dispatches': 0, 'fixed19_credit': 0,
        'physical_qualification': False, 'automatic_retry': False,
    }
    files['collector-package/MANIFEST.json'] = enc(collector_manifest)
    need(len(om['files']) == 6, 'six original operator sources')
    for row in om['files']:
        raw = read(om_path.parent / row['path'], (row['bytes'], row['sha256']))
        candidate = raw
        if row['path'] == 'root_acceptance_r10.py':
            need(literal(raw, 'READINESS_SHA') == 'b0a3f3b4fbda835506c3d0f9099abbe3b47a10b6a131ee2069c9ef7350c6ba63',
                 'exact readiness parent')
            candidate = replace_once(raw, b"READINESS_SHA='b0a3f3b4fbda835506c3d0f9099abbe3b47a10b6a131ee2069c9ef7350c6ba63'",
                                      b'READINESS_SHA=None')
            changes.append(('operator-chain/' + row['path'], raw, candidate))
        ast.parse(candidate, filename=row['path'])
        files['operator-chain-template/' + row['path']] = candidate
    coordinator = read(co_path, PARENT_COORDINATOR)
    candidate = replace_once(coordinator,
                             b'2ea9a478b366d6a69fdb8942699b6241d72330cfa789baa4b3132fdaca169e68',
                             SHARED_PIN[1].encode())
    need(literal(candidate, 'OPERATOR_MANIFEST_PIN') is None, 'coordinator stays unbound')
    need(literal(candidate, 'SHARED_PIN') == {'bytes': SHARED_PIN[0], 'sha256': SHARED_PIN[1]},
         'current shared literal')
    files['coordinator/run_fixed19_e2e_root_once_UNBOUND.py'] = candidate
    changes.append(('coordinator/run_fixed19_e2e_root_once.py', coordinator, candidate))
    for name, pin in MATERIALIZER_INPUTS.items():
        files['operator/' + name] = read(refs / 'readiness-r9/operator' / name, pin)
    ready_path = HERE.parent / 'install-ready-input-templates/references/readiness.original.py'
    files['reference/readiness.original.py'] = read(ready_path, READINESS_PARENT)
    files['reference/PARENT-COLLECTOR-MANIFEST.original.json'] = cm_raw
    files['reference/PARENT-OPERATOR-MANIFEST.original.json'] = om_raw
    files['reference/PARENT-COORDINATOR.original.py'] = coordinator
    for name in ('FAILURE.json', 'operator-chain/SOURCE-MANIFEST.json'):
        files['reference/failed-e2e-r4/' + name] = read(refs / 'fixed19-e2e-final-r4-a1055-r1' / name)
    patch = ''.join(''.join(difflib.unified_diff(old.decode().splitlines(True), new.decode().splitlines(True),
                    fromfile='parent/' + name, tofile='candidate/' + name)) for name, old, new in changes)
    files['SOURCE.patch'] = patch.encode()
    report = {
        'schema': 'hepta.fc33.e2e.source-candidates.v1',
        'state': 'SOURCE_CANDIDATES_ONLY_FINAL_READINESS_UNBOUND',
        'repository': 'TrillionniumFoundation/trillionnium-os',
        'reviewed_repository_head': 'be7cea6dee3f8b7192e43833ab320b406fa57218',
        'source_combination': {'bytes': COMBINATION_PIN[0], 'sha256': COMBINATION_PIN[1]},
        'shared_materials': {'bytes': SHARED_PIN[0], 'sha256': SHARED_PIN[1]},
        'reviewed_production_source_pins': selected,
        'changed_production_pin_names': sorted(CHANGED),
        'collector_six_bodies_unchanged': True, 'collector_five_literal_inverse': True,
        'operator_five_bodies_unchanged': True, 'operator_only_readiness_literal_unbound': True,
        'coordinator_only_shared_literal_changed': True,
        'all_seven_projection_fragments_unchanged': True,
        'materializer_original_body_unchanged': True,
        'source_origin_is_not_formal_release_seal': True,
        'actual_runtime_freeze': None, 'actual_formal_source_binding': None,
        'actual_readiness_source': None, 'actual_BUILD': None, 'actual_READY': None,
        'actual_context': None, 'actual_native_scope': None,
        'phone_calls': 0, 'model_requests': 0, 'new_nonces': 0, 'fixed19_credit': 0,
        'historical_pass_inherited': False, 'automatic_retry': False,
        'inputs': [desc(cm_path, cm_raw), desc(om_path, om_raw), desc(co_path, coordinator),
                   desc(transfer_path, transfer_raw)],
        'files': [desc(name, body) for name, body in sorted(files.items())],
    }
    files['CANDIDATE-SOURCES.json'] = enc(report)
    return files


def publish(out, files):
    out = Path(out).absolute()
    need(out.parent.resolve(strict=True) == out.parent and not out.exists() and not out.is_symlink(),
         'fresh canonical output directory required')
    os.umask(0o077)
    out.mkdir(mode=0o700)
    for name, raw in sorted(files.items()):
        rel = Path(name)
        need(not rel.is_absolute() and '..' not in rel.parts and str(rel) == name, 'relative member')
        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        need(read(target) == raw, 'new member readback differs')
    for directory in sorted([p for p in out.rglob('*') if p.is_dir()] + [out], reverse=True):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return desc(out / 'CANDIDATE-SOURCES.json', files['CANDIDATE-SOURCES.json'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    files = derive()
    result = publish(args.out, files)
    print(json.dumps({'state': 'SOURCE_CANDIDATES_CREATED', 'result': result,
                      'files': len(files), 'phone_calls': 0, 'new_nonces': 0}, sort_keys=True))


if __name__ == '__main__':
    main()
