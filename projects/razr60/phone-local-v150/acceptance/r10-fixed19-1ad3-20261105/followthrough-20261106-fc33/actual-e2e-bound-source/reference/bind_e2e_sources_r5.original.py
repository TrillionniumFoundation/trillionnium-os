#!/usr/bin/env python3
"""Publish source bindings only after actual frozen source descriptors are supplied.

This program never materializes a task, allocates a nonce, imports a production
module, launches a process, opens a socket, or calls a phone. The resulting
coordinator still requires a real sealed BUILD, four-role READY and context.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat

FROZEN_INPUTS = {'boundary_consumer': {'bytes': 249860, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-release-source-chain-r5-derived01/source/release_boundaries.py', 'sha256': 'd65923a2323f4590d41291f3606e4b7bc550eaf800826f819c8f4bb1a102f479'}, 'candidate_manifest': {'bytes': 12133, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-e2e-source-plan01/candidate01/CANDIDATE-SOURCES.json', 'sha256': 'd352e5aeafe52777ccbfe8d3deec15b76eb54ee9f9b61e62a7b1f7f4c6f5ee44'}, 'formal_source_binding': {'bytes': 3608, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-release-source-chain-r5-derived01/SOURCE-BINDING.json', 'sha256': 'c7b074b529b4bbe258303842b3d0b2f3912d8cdf606f803522775b79ba147003'}, 'output': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-e2e-bound-source-r5-01', 'owned_capture_source': {'bytes': 37720, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/fixed19-e2e-owned-transport-a1055-r1/source/owned_e2e_capture.py', 'sha256': '9d273d66adc09c670ae09aa06fae699d2d1de9e1981afd3980bec7e4eda6cb29'}, 'readiness_source': {'bytes': 16407, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-release-source-chain-r5-derived01/source/collect_r10_readiness.py', 'sha256': '8fcf151ebeeeeaa38f0d8e057b4340f7c681f402d6a5a9670ca95f79737935e5'}, 'runtime_freeze': {'bytes': 1039896, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-fc33-native-v3-r5/FREEZE-RESULT.json', 'sha256': 'd6ae0199011ddb9bfa86d8d0c4b9818e3a9037141f5441e85d43085874fd4a3c'}, 'runtime_manifest': {'bytes': 57078, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-fc33-native-v3-r5/runtime/MANIFEST.json', 'sha256': '990c726a1fff139761494cc19cf091deb269201f27ea947dda4a5833e3a72f2a'}}
B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
CANDIDATE_PIN = {'bytes': 12133, 'sha256': 'd352e5aeafe52777ccbfe8d3deec15b76eb54ee9f9b61e62a7b1f7f4c6f5ee44'}
COMBINATION_SHA = '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'
SHARED_PIN = {'bytes': 3519, 'sha256': 'cc7eb624333216e510b540c3af8277e948aa689a108950fa78e8d01c2177e5b1'}
CAPTURE_PIN = {'bytes': 37720, 'sha256': '9d273d66adc09c670ae09aa06fae699d2d1de9e1981afd3980bec7e4eda6cb29'}
CONSUMER_TEMPLATE_PIN = {'bytes': 249798, 'sha256': '016d25b5467c96f96f25f7b2d9d606e40ea18a72421e549d0ab630a01f9c2349'}
READINESS_PARENT_PIN = {'bytes': 16407, 'sha256': '2b4ff90f7078af2481feb8a2d33c39d1a0e260102cd769a4ee3b46d9bec47e11'}
OLD_CONSUMER_SHA = '3de6208604022671d4db21e2b479e3ef4d4bba4aaa9d2faa360f1865aec428da'
META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns')
INPUT_FIELDS = {'candidate_manifest', 'runtime_freeze', 'runtime_manifest', 'formal_source_binding',
                'boundary_consumer', 'readiness_source', 'owned_capture_source', 'output'}
SOURCE_BINDING_FIELDS = {'formal_parent', 'formal', 'readiness', 'production_replacements',
                         'configuration', 'service', 'material_parent_configuration_sha256',
                         'material_parent_service_sha256', 'material_source_input'}


def need(value, why):
    if not value:
        raise ValueError(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}


def descriptor(path, raw):
    return {'path': str(path), **pin(raw)}


def enc(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def strict(raw):
    def pairs(rows):
        out = {}
        for key, value in rows:
            need(key not in out, 'duplicate JSON field')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))


def full9(st):
    return [getattr(st, key) for key in META]


class Originals:
    def __init__(self):
        self.reads = {}

    def read(self, row):
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
             and type(row['path']) is str and type(row['bytes']) is int
             and 0 < row['bytes'] <= 32 * 1024 * 1024
             and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
             'explicit bounded original descriptor')
        path = Path(row['path'])
        need(path.is_absolute() and path.resolve(strict=True) == path, 'canonical original required')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_size == row['bytes'], 'one-link original size differs')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(before.st_size + 1)
            need(pin(raw) == {k: row[k] for k in ('bytes', 'sha256')}
                 and full9(before) == full9(os.fstat(fd)) == full9(path.lstat()),
                 'original complete bytes/full9 differ')
            previous = self.reads.get(str(path))
            observed = {'descriptor': dict(row), 'metadata': full9(before)}
            need(previous is None or previous == observed, 'original descriptor or metadata changed')
            self.reads[str(path)] = observed
            return raw
        finally:
            os.close(fd)

    def recheck(self):
        for row in list(self.reads.values()):
            self.read(row['descriptor'])


def literal_node(raw, name):
    nodes = [n for n in ast.parse(raw).body if isinstance(n, ast.Assign)
             and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
             and n.targets[0].id == name]
    need(len(nodes) == 1, 'one exact assignment required: ' + name)
    return nodes[0].value


def literal(raw, name):
    return ast.literal_eval(literal_node(raw, name))


def replace_literal(raw, name, expected, replacement):
    node = literal_node(raw, name)
    need(ast.literal_eval(node) == expected and type(ast.literal_eval(node)) is type(expected),
         'exact old literal differs: ' + name)
    lines = raw.splitlines(keepends=True)
    start = sum(map(len, lines[:node.lineno - 1])) + node.col_offset
    end = sum(map(len, lines[:node.end_lineno - 1])) + node.end_col_offset
    old = raw[start:end]
    value = repr(replacement).encode('utf-8')
    result = raw[:start] + value + raw[end:]
    need(result[:start] + old + result[start + len(value):] == raw, 'full-byte literal inverse')
    ast.parse(result)
    return result


def safe_relative(value):
    path = Path(value)
    need(type(value) is str and not path.is_absolute() and str(path) == value
         and all(re.fullmatch('[A-Za-z0-9._-]+', part) and part not in ('.', '..') for part in path.parts),
         'safe relative source member')
    return path


def derive(inputs, originals):
    need(type(inputs) is dict and set(inputs) == INPUT_FIELDS, 'complete actual source binding inputs')
    package_raw = originals.read(inputs['candidate_manifest'])
    need(pin(package_raw) == CANDIDATE_PIN, 'only exact reviewed E2E candidate package')
    package = strict(package_raw)
    root = Path(inputs['candidate_manifest']['path']).parent
    rows = package['files']
    need(len(rows) == 46 and len({r['path'] for r in rows}) == 46, 'candidate member count differs')
    candidate = {}
    for row in rows:
        rel = safe_relative(row['path'])
        candidate[str(rel)] = originals.read({**row, 'path': str(root / rel)})
    freeze_raw = originals.read(inputs['runtime_freeze'])
    freeze = strict(freeze_raw)
    runtime_raw = originals.read(inputs['runtime_manifest'])
    runtime = strict(runtime_raw)
    need(freeze['schema'] == 'hepta.fc33.native-bound.actual-host-freeze.v1'
         and freeze['state'] == 'FROZEN_FOR_NEW_NEG01_THEN_NEG02_NOT_QUALIFIED'
         and freeze['runtime_manifest'] == inputs['runtime_manifest']
         and freeze['files']['runtime/MANIFEST.json'] == inputs['runtime_manifest']
         and freeze['combination']['sha256'] == COMBINATION_SHA
         and {k: freeze['shared_materials'][k] for k in ('bytes', 'sha256')} == SHARED_PIN
         and freeze['all_inputs_bookended_before_publication'] is True
         and freeze['all_output_files_read_back'] is True
         and freeze['production_ready'] is False and freeze['full19_qualified'] is False,
         'actual host freeze source relationship differs')
    need(len(runtime['files']) == 38, 'exact runtime source layout')
    consumer = originals.read(inputs['boundary_consumer'])
    need(literal(consumer, 'PACKAGE_SHA') == sha(runtime_raw)
         and literal(consumer, 'PACKAGE_FILE_COUNT') == 38
         and literal(consumer, 'CURRENT_COMBINATION_SHA') == COMBINATION_SHA
         and literal(consumer, 'CURRENT_COMPONENT_CHAIN_LENGTH') == 12
         and literal(consumer, 'COMPONENT_ROLE_BUDGET') == 42, 'consumer exact runtime/source tuple')
    inverse = replace_literal(consumer, 'PACKAGE_SHA', sha(runtime_raw), None)
    need(pin(inverse) == CONSUMER_TEMPLATE_PIN, 'consumer full body must invert to reviewed template')
    ready = originals.read(inputs['readiness_source'])
    need(literal(ready, 'BOUNDARY_CONSUMER_SHA256') == sha(consumer), 'readiness exact bound consumer')
    inverse = replace_literal(ready, 'BOUNDARY_CONSUMER_SHA256', sha(consumer), OLD_CONSUMER_SHA)
    need(pin(inverse) == READINESS_PARENT_PIN, 'readiness only one actual consumer literal may change')
    binding_raw = originals.read(inputs['formal_source_binding'])
    source_binding = strict(binding_raw)
    need(type(source_binding) is dict and set(source_binding) == SOURCE_BINDING_FIELDS
         and source_binding['readiness'] == inputs['readiness_source'],
         'formal source construction must name this complete readiness descriptor')
    capture = originals.read(inputs['owned_capture_source'])
    need(pin(capture) == CAPTURE_PIN, 'same reviewed bounded host capture source')
    out = Path(inputs['output'])
    need(out.is_absolute() and B in out.parents and out.parent.resolve(strict=True) == out.parent
         and not out.exists() and not out.is_symlink(), 'new canonical project source output')

    files = {name: raw for name, raw in candidate.items()
             if name.startswith(('collector-package/', 'operator/', 'shared/', 'source-origin/'))}
    operator_files = {}
    for name, raw in candidate.items():
        if name.startswith('operator-chain-template/'):
            target = name.replace('operator-chain-template/', 'operator-chain/', 1)
            if target.endswith('/root_acceptance_r10.py'):
                raw = replace_literal(raw, 'READINESS_SHA', None, sha(ready))
            files[target] = raw
            operator_files[Path(target).name] = raw
    need(len(operator_files) == 6, 'exact six final operator bodies')
    cm = files['collector-package/MANIFEST.json']
    om = {
        'schema': 'hepta.root-acceptance-sources.v150.r10.1',
        'release_id': 'v150-r10-r1',
        'qualification': 'HOST_PREPARED_ONLY_REQUIRES_ACTUAL_SEALED_RELEASE_AND_READY',
        'files': [descriptor(name, raw) for name, raw in sorted(operator_files.items())],
        'parent_operator_manifest_sha256': sha(candidate['reference/PARENT-OPERATOR-MANIFEST.original.json']),
        'collector_manifest_sha256': sha(cm),
        'current_collector_manifest': descriptor(out / 'collector-package/MANIFEST.json', cm),
        'reviewed_production_source_pins': package['reviewed_production_source_pins'],
        'current_shared_materials': descriptor(out / 'shared/SHARED-MATERIALS.json',
                                              files['shared/SHARED-MATERIALS.json']),
        'actual_component_runtime_manifest': inputs['runtime_manifest'],
        'actual_runtime_host_freeze': inputs['runtime_freeze'],
        'current_formal_source_binding': inputs['formal_source_binding'],
        'reviewed_readiness_helper_sha256': sha(ready),
        'sender_sha256': literal(operator_files['root_acceptance_r10.py'], 'SENDER_SHA'),
        'materializer_sha256': literal(operator_files['root_acceptance_r10.py'], 'MATERIALIZER_SHA'),
        'actual_formal_BUILD': False, 'actual_four_role_READY': False,
        'phone_calls': 0, 'model_requests': 0, 'new_acceptance_nonce_generated': False,
        'historical_pass_inherited': False, 'automatic_retry': False,
    }
    om_raw = enc(om)
    files['operator-chain/SOURCE-MANIFEST.json'] = om_raw
    coordinator = candidate['coordinator/run_fixed19_e2e_root_once_UNBOUND.py']
    files['source/run_fixed19_e2e_root_once.py'] = replace_literal(coordinator,
                                            'OPERATOR_MANIFEST_PIN', None, pin(om_raw))
    for label, raw in [('RUNTIME-FREEZE.original.json', freeze_raw),
                       ('RUNTIME-MANIFEST.original.json', runtime_raw),
                       ('FORMAL-SOURCE-BINDING.original.json', binding_raw),
                       ('readiness.source.original.py', ready),
                       ('release_boundaries.source.original.py', consumer),
                       ('owned_capture.source.original.py', capture),
                       ('CANDIDATE-SOURCES.original.json', package_raw)]:
        files['reference/' + label] = raw
    files['BINDING-INPUTS.json'] = enc(inputs)
    for name, raw in files.items():
        if name.endswith('.py'):
            ast.parse(raw, filename=name)
    originals.recheck()
    result = {
        'schema': 'hepta.fc33.e2e.actual-source-binding.v1',
        'state': 'SOURCE_BOUND_TASK_EXECUTION_UNBOUND',
        'inputs': inputs, 'original_full9': originals.reads,
        'source_combination_sha256': COMBINATION_SHA,
        'operator_manifest': descriptor(out / 'operator-chain/SOURCE-MANIFEST.json', om_raw),
        'collector_manifest': descriptor(out / 'collector-package/MANIFEST.json', cm),
        'coordinator': descriptor(out / 'source/run_fixed19_e2e_root_once.py',
                                  files['source/run_fixed19_e2e_root_once.py']),
        'shared_materials': descriptor(out / 'shared/SHARED-MATERIALS.json',
                                       files['shared/SHARED-MATERIALS.json']),
        'owned_capture_source': inputs['owned_capture_source'],
        'readiness_only_consumer_literal_changed': True,
        'consumer_only_actual_runtime_literal_bound': True,
        'operator_only_readiness_literal_bound': True,
        'coordinator_only_operator_manifest_literal_bound': True,
        'actual_BUILD': None, 'actual_READY': None, 'actual_context': None,
        'actual_native_scope': None, 'actual_request': None,
        'phone_calls': 0, 'model_requests': 0, 'native_dispatches': 0,
        'new_nonces': 0, 'fixed19_credit': 0, 'automatic_retry': False,
        'historical_pass_inherited': False,
        'files': [descriptor(out / name, raw) for name, raw in sorted(files.items())],
    }
    files['BINDING.json'] = enc(result)
    return out, files


def publish(out, files):
    os.umask(0o077)
    out.mkdir(mode=0o700)
    for name in sorted(n for n in files if n != 'BINDING.json') + ['BINDING.json']:
        raw = files[name]
        path = out / safe_relative(name)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        need(path.parent.resolve(strict=True) == path.parent, 'new parent changed')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        Originals().read(descriptor(path, raw))
    for directory in sorted([p for p in out.rglob('*') if p.is_dir()] + [out], reverse=True):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return descriptor(out / 'BINDING.json', files['BINDING.json'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bind-source-once', action='store_true')
    args = parser.parse_args()
    if not args.bind_source_once:
        print(json.dumps({'state': 'SOURCE_BINDER_PREVIEW_UNBOUND' if FROZEN_INPUTS is None
                          else 'SOURCE_BINDER_PREVIEW_NO_PUBLICATION', 'phone_calls': 0,
                          'new_nonces': 0, 'actual_BUILD': None, 'actual_READY': None}, sort_keys=True))
        return 0
    need(FROZEN_INPUTS is not None, 'UNBOUND_ACTUAL_SOURCE_INPUTS_NO_PUBLICATION')
    out, files = derive(FROZEN_INPUTS, Originals())
    result = publish(out, files)
    print(json.dumps({'state': 'SOURCE_BOUND_TASK_EXECUTION_UNBOUND', 'result': result,
                      'phone_calls': 0, 'new_nonces': 0, 'automatic_retry': False}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
