#!/usr/bin/env python3
"""Create one source-only six-host operator revision from thirteen reviewed pins.

No preparer, importer, harness, case, policy parser, network or phone operation
runs here. FINALIZATION is a reviewed source literal, never caller-supplied.
"""
import argparse
import ast
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
B = Path("/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1")
PARENT = B / 'fixed19-six-host-native5-provenance-candidate01'
OUT = B / 'fixed19-six-host-runtime-properties-r8-operator-inventory-prefix-1ad3-01'
FINALIZATION = None
PARENT_MANIFEST = {'path': str(PARENT / 'MANIFEST.json'), 'bytes': 3977,
    'sha256': 'b28556e5ce6b2cba4dd69bbc29b00843446554de5b7d2427ae297372d2ed276b'}
PARENT_SOURCES = {
    'prepare_fixed19_host_r10.py': (29515, '40a0beee0c53e138fd1f06d45450d444ca701cabb826ab243adfedcd270add6b'),
    'import_six_host_results.py': (44478, '996c1fe01688d1394013498b095051243af689beb6a29a14aff18821ab3e20f8'),
    'harness_import_provenance.py': (16474, 'ef468183f4a32063a98c30336460a7362524be8080cdeaf345fc0553d9b061d0'),
}
PREPARER_SLOTS = ('ADOPTION', 'POLICY', 'MATERIALIZER', 'CONSUMER_MANIFEST',
                  'CONSUMER', 'READINESS', 'CONSUMER_SCHEMA')
IMPORTER_SLOTS = ('PREPARER', 'POLICY', 'ADOPTION', 'CONSUMER', 'READINESS',
                 'CONSUMER_MANIFEST')
REFERENCE_NAMES = (
    'component/execute_namespace_once.py', 'component/host_negative_runner.py',
    'service/binding_adapter.py', 'service/execute_namespace_once.py',
    'service/fixture_server.py', 'service/service_negative_runner.py',
    'inputs/original-protocol.json', 'inputs/historical-protocol-binding-r7-r3.json',
    'inputs/protocol.json',
)
CONSUMER_ROOT = B / 'r10-boundary-consumers-final-r8-inventory-prefix-1ad3-01'
ACCEPTANCE_ROOT = B / 'scoped-acceptance-v150-r10-r1-readiness-r9-inventory-prefix-1ad3-01'
CONSUMER_SCHEMA = 'hepta.r10.final-boundary-consumers.v8'
MATERIALIZER_BYTES = 24834
MATERIALIZER_SHA = 'b25125bc0e204ea7aefde6f2a17fa2fb8e5edf132a4b62dfbb546964c1c09290'
SCOPE_SHA = '5a08041da77eeec9168c869ae76adae0a117a5e34872aa07a1a096bc06a36132'
PARENT_POLICY_SHA = '50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'
PARENT_ADOPTION_SHA = 'a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5'
HASH = re.compile(r'[0-9a-f]{64}\Z')
MAXIMUM = 16 * 1024 * 1024


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                       allow_nan=False) + '\n').encode()


def strict(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))


def metadata(value):
    return [getattr(value, name) for name in ('st_dev', 'st_ino', 'st_mode',
        'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')]


def exact3(value):
    need(isinstance(value, dict) and set(value) == {'path', 'bytes', 'sha256'},
         'exact3 descriptor required')
    path = Path(value['path'])
    need(path.is_absolute() and str(path) == value['path'] and '..' not in path.parts
         and '\x00' not in value['path'], 'canonical absolute input required')
    need(type(value['bytes']) is int and 0 < value['bytes'] <= MAXIMUM
         and type(value['sha256']) is str and HASH.fullmatch(value['sha256']),
         'nonempty bounded pinned source input required')
    return value


def relative(value):
    need(type(value) is str and value and '\x00' not in value,
         'relative manifest name required')
    path = Path(value)
    need(not path.is_absolute() and str(path) == value and '..' not in path.parts,
         'canonical relative manifest name required')
    return path


class Originals:
    def __init__(self):
        self.rows = {}
        self.bodies = {}

    def read(self, descriptor):
        row = exact3(descriptor)
        path = Path(row['path'])
        need(path.resolve(strict=True) == path, 'symlink or alias input rejected')
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_size == row['bytes'], 'regular exact input required')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(row['bytes'] + 1)
            full9 = metadata(before)
            need(full9 == metadata(os.fstat(fd)) == metadata(path.lstat()),
                 'input metadata changed while reading')
        finally:
            os.close(fd)
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'input bytes differ')
        if row['path'] in self.rows:
            need(self.rows[row['path']]['metadata'] == full9
                 and self.bodies[row['path']] == raw, 'input bookend changed')
        self.rows[row['path']] = dict(row, metadata=full9)
        self.bodies[row['path']] = raw
        return raw

    def finish(self):
        for row in list(self.rows.values()):
            self.read({key: row[key] for key in ('path', 'bytes', 'sha256')})


def require_finalization():
    value = FINALIZATION
    need(isinstance(value, dict) and set(value) == {
        'consumer_manifest', 'acceptance_manifest', 'policy_adoption', 'current_policy'},
        'actual reviewed finalization is absent')
    for row in value.values():
        exact3(row)
    need(value['consumer_manifest']['path'] == str(CONSUMER_ROOT / 'MANIFEST.json')
         and value['acceptance_manifest']['path'] == str(ACCEPTANCE_ROOT / 'MANIFEST.json'),
         'only the explicit final R8 consumer and acceptance packages are allowed')
    need(value['current_policy']['sha256'] != PARENT_POLICY_SHA
         and value['policy_adoption']['sha256'] != PARENT_ADOPTION_SHA,
         'parent policy/adoption cannot be relabelled as the new generation')
    return value


def manifest_rows(value):
    need(isinstance(value, dict) and isinstance(value.get('files'), list),
         'manifest files array required')
    rows = {}
    for row in value['files']:
        need(isinstance(row, dict) and set(row) == {'path', 'bytes', 'sha256'},
             'exact manifest member required')
        relative(row['path'])
        need(type(row['bytes']) is int and 0 <= row['bytes'] <= MAXIMUM
             and type(row['sha256']) is str and HASH.fullmatch(row['sha256'])
             and row['path'] not in rows, 'duplicate or invalid manifest member')
        rows[row['path']] = row
    return rows


def member(root, rows, name, originals):
    need(name in rows, 'missing exact required manifest member: ' + name)
    row = dict(rows[name], path=str(root / relative(name)))
    return row, originals.read(row)


def assignment(raw, name):
    text = raw.decode()
    nodes = [node for node in ast.parse(text).body if isinstance(node, ast.Assign)
             and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
             and node.targets[0].id == name]
    need(len(nodes) == 1, 'one top-level literal assignment required: ' + name)
    node = nodes[0]
    need(node.lineno == node.end_lineno, 'one line constant required: ' + name)
    return node, ast.literal_eval(node.value)


def functions_and_classes(raw):
    text = raw.decode()
    return [(type(node).__name__, node.name, ast.get_source_segment(text, node))
            for node in ast.parse(text).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]


def fill_slots(parent, slots, replacements):
    need(set(replacements) == set(slots), 'exact declared slot set required')
    text = parent.decode()
    for name in slots:
        _, value = assignment(parent, name)
        need(value is None and text.count(name + ' = None\n') == 1,
             'parent slot must be the one reviewed None literal: ' + name)
        new = replacements[name]
        need(type(new) is str and
             (new == CONSUMER_SCHEMA if name == 'CONSUMER_SCHEMA'
              else HASH.fullmatch(new)), 'invalid replacement literal: ' + name)
        text = text.replace(name + ' = None\n', name + ' = ' + repr(new) + '\n')
    raw = text.encode()
    compile(raw, '<generated-source-syntax-only>', 'exec')
    inverse = raw.decode()
    for name in slots:
        _, value = assignment(raw, name)
        need(value == replacements[name], 'generated literal differs')
        old = name + ' = ' + repr(value) + '\n'
        need(inverse.count(old) == 1, 'generated slot is not unique')
        inverse = inverse.replace(old, name + ' = None\n')
    need(inverse.encode() == parent, 'whole-file inverse differs from pinned parent')
    need(functions_and_classes(parent) == functions_and_classes(raw),
         'function or class body changed')
    return raw


def prepare():
    final = require_finalization()
    originals = Originals()
    parent_raw = originals.read(PARENT_MANIFEST)
    parent = strict(parent_raw)
    need(parent.get('schema') == 'hepta.fixed19.native5-import-provenance-candidate.v1',
         'reviewed provenance parent schema differs')
    parents = manifest_rows(parent)
    source_bodies = {}
    for name, (size, digest) in PARENT_SOURCES.items():
        row, raw = member(PARENT, parents, 'source/' + name, originals)
        need((row['bytes'], row['sha256']) == (size, digest), 'reviewed parent source differs')
        source_bodies[name] = raw
    references = {}
    for name in REFERENCE_NAMES:
        _, references[name] = member(PARENT, parents, 'reference/parent-r9/' + name, originals)
    fc_raw = originals.read(final['consumer_manifest'])
    fc = strict(fc_raw)
    need(fc.get('schema') == CONSUMER_SCHEMA, 'actual final consumer schema differs')
    fc_rows = manifest_rows(fc)
    consumer, consumer_raw = member(CONSUMER_ROOT, fc_rows, 'source/release_boundaries.py', originals)
    readiness, _ = member(CONSUMER_ROOT, fc_rows, 'source/collect_r10_readiness.py', originals)
    ac_raw = originals.read(final['acceptance_manifest'])
    ac = strict(ac_raw)
    need(ac.get('schema') == 'hepta.r10.scoped-acceptance-package.v1',
         'actual final acceptance schema differs')
    materializer, _ = member(ACCEPTANCE_ROOT, manifest_rows(ac), 'operator/materialize_case_r10.py', originals)
    need((materializer['bytes'], materializer['sha256']) ==
         (MATERIALIZER_BYTES, MATERIALIZER_SHA), 'materializer behavior must remain the reviewed source')
    originals.read(final['current_policy'])
    originals.read(final['policy_adoption'])
    for name, expected in {
        'CURRENT_POLICY_SHA': final['current_policy']['sha256'],
        'CURRENT_POLICY_ADOPTION_SHA': final['policy_adoption']['sha256'],
        'CURRENT_SCOPE_DECISION_SHA': SCOPE_SHA, 'PACKAGE_FILE_COUNT': 32,
    }.items():
        need(assignment(consumer_raw, name)[1] == expected,
             'actual consumer generation binding differs: ' + name)
    pre_values = {
        'ADOPTION': final['policy_adoption']['sha256'],
        'POLICY': final['current_policy']['sha256'],
        'MATERIALIZER': materializer['sha256'],
        'CONSUMER_MANIFEST': final['consumer_manifest']['sha256'],
        'CONSUMER': consumer['sha256'], 'READINESS': readiness['sha256'],
        'CONSUMER_SCHEMA': fc['schema'],
    }
    preparer = fill_slots(source_bodies['prepare_fixed19_host_r10.py'], PREPARER_SLOTS, pre_values)
    importer_values = {name: pre_values[name] for name in IMPORTER_SLOTS if name != 'PREPARER'}
    importer_values['PREPARER'] = sha(preparer)
    importer = fill_slots(source_bodies['import_six_host_results.py'], IMPORTER_SLOTS, importer_values)
    generated = {
        'source/prepare_fixed19_host_r10.py': preparer,
        'source/import_six_host_results.py': importer,
        'source/harness_import_provenance.py': source_bodies['harness_import_provenance.py'],
        'reference/provenance-parent/MANIFEST.original.json': parent_raw,
    }
    for name, raw in references.items():
        generated['reference/parent-r9/' + name] = raw
    for name, raw in source_bodies.items():
        generated['reference/provenance-parent/' + name] = raw
    for name in ('prepare_fixed19_host_r10.py', 'import_six_host_results.py'):
        generated['validation/' + name + '.patch'] = ''.join(difflib.unified_diff(
            source_bodies[name].decode().splitlines(True),
            generated['source/' + name].decode().splitlines(True),
            fromfile='reviewed-parent/source/' + name,
            tofile='generated/source/' + name)).encode()
    proof = {
        'schema': 'hepta.fixed19.runtime-properties-pin-derivation.v1',
        'state': 'REVIEWED_CONSTANTS_ONLY_NOT_CASE_EXECUTION',
        'parent_manifest': PARENT_MANIFEST, 'actual_finalization': final,
        'preparer_replacements': pre_values, 'importer_replacements': importer_values,
        'replacement_counts': {'preparer': 7, 'importer': 6},
        'complete_inverse_to_reviewed_parent': True,
        'functions_and_classes_byte_identical': True,
        'harness_import_provenance_byte_identical': True,
        'original_harness_and_protocol_members_unchanged': list(REFERENCE_NAMES),
        'actual_dependency_originals': [final['consumer_manifest'], final['acceptance_manifest'],
            consumer, readiness, materializer, final['policy_adoption'], final['current_policy']],
        'input_originals': list(originals.rows.values()),
        'six_host_cases_executed': 0, 'phone_operations': 0,
        'release_ready_or_case_qualification_claimed': False,
    }
    generated['validation/PIN-SLOTS-DERIVATION.json'] = encode(proof)
    originals.finish()
    return generated, proof, originals


def put(root, name, raw):
    path = root / relative(name)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    need(path.parent.resolve(strict=True) == path.parent, 'output parent changed')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    need(path.read_bytes() == raw and stat.S_ISREG(path.lstat().st_mode)
         and path.lstat().st_nlink == 1, 'output readback differs')
    return {'path': name, 'bytes': len(raw), 'sha256': sha(raw)}


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--preview', action='store_true')
    mode.add_argument('--execute-host-only', action='store_true')
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    require_finalization()
    need(Path(args.out) == OUT and str(Path(args.out)) == args.out,
         'only the one reviewed fresh operator output is allowed')
    need(OUT.parent.resolve(strict=True) == OUT.parent and not os.path.lexists(OUT),
         'output must be fresh and canonical')
    generated, proof, originals = prepare()
    preview = {
        'schema': 'hepta.fixed19.runtime-properties-pin-preview.v1',
        'out': str(OUT), 'files': [{'path': name, 'bytes': len(raw), 'sha256': sha(raw)}
                                for name, raw in sorted(generated.items())],
        'actual_finalization': FINALIZATION, 'literal_changes': 13,
        'complete_inverse_to_reviewed_parent': True,
        'six_host_cases_executed': 0, 'phone_operations': 0,
    }
    if args.preview:
        print(encode(preview).decode(), end='')
        return
    OUT.mkdir(mode=0o700)
    rows = [put(OUT, name, raw) for name, raw in sorted(generated.items())]
    originals.finish()
    manifest = {
        'schema': 'hepta.fixed19.runtime-properties-source-operator.v1',
        'state': 'HOST_SOURCE_PINS_FROZEN_NO_ACCEPTANCE_EXECUTION',
        'files': rows, 'actual_finalization': FINALIZATION,
        'parent_manifest': PARENT_MANIFEST, 'literal_changes': 13,
        'six_host_cases_executed': 0, 'phone_operations': 0,
        'release_ready_or_case_qualification_claimed': False,
    }
    mf = put(OUT, 'MANIFEST.json', encode(manifest))
    result = put(OUT, 'GENERATION-RESULT.json', encode(dict(preview, manifest=mf,
               state='SOURCE_GENERATION_COMPLETE_NOT_SIX_HOST_ACCEPTANCE')))
    for row in rows + [mf, result]:
        path = OUT / row['path']
        raw = path.read_bytes()
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'final output bytes changed')
    originals.finish()
    print(encode({'manifest': dict(mf, path=str(OUT / mf['path'])),
                  'result': dict(result, path=str(OUT / result['path'])),
                  'six_host_cases_executed': 0, 'phone_operations': 0}).decode(), end='')


if __name__ == '__main__':
    main()
