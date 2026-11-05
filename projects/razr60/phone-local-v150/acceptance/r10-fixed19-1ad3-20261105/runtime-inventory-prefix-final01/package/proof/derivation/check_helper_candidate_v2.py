#!/usr/bin/env python3
"""Exercise only the new source admission functions against exact cached bytes."""
import ast
import hashlib
import json
from pathlib import Path
import types

BASE = Path('/workspace/scratch/1ad3d6f55439')
HERE = BASE / 'runtime_prefix_successor_candidate01'
PACKAGE = HERE / 'package'
PREVIOUS = BASE / 'r8_root_capture_successor_candidate01/delivery-final01/package'
DEST = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-inventory-prefix-1ad3-01')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + '\n').encode()


def main():
    source_path = HERE / 'helper-draft02/source/prepare_native_guard_root_plan.py'
    source = source_path.read_bytes()
    assert len(source) == 42223 and sha(source) == '0d742ad23def3dfd4cf3bed1e50065b98b67de9d499c55168747e88ff74d5f0c'
    mod = types.ModuleType('local_exact_runtime_capture_source_admission_only')
    mod.__file__ = str(source_path)
    exec(compile(source, str(source_path), 'exec'), mod.__dict__)
    cached = {}

    def add(path, raw):
        key = str(path)
        assert key not in cached or cached[key] == raw
        cached[key] = raw

    for path in PACKAGE.rglob('*'):
        if path.is_file():
            add(DEST / path.relative_to(PACKAGE), path.read_bytes())
    freeze = json.loads((BASE / 'actual_r8_external_freeze/FREEZE-RESULT.json').read_bytes())
    inputs = json.loads((BASE / 'actual_r8_external_freeze/FREEZE-INPUTS.original.json').read_bytes())
    add(freeze['runtime_manifest']['path'], (BASE / 'actual_r8_external_freeze/runtime/MANIFEST.json').read_bytes())
    root_manifest = json.loads((BASE / 'actual_r8_external_freeze/root-chain/SOURCE-MANIFEST.json').read_bytes())
    root_rows = {row['path']: dict(row, path=str(Path(freeze['root_chain_manifest']['path']).parent / row['path']))
                 for row in root_manifest['files']}
    root_raw = {
        'source/run_component_root_once.py': (BASE / 'actual_r8_external_freeze/root-chain/source/run_component_root_once.py').read_bytes(),
        'source/phone_chain_bridge.py': (PREVIOUS / 'root-package/source/phone_chain_bridge.py').read_bytes(),
        'reference/policy_native5_verifier.py': (PREVIOUS / 'root-package/reference/policy_native5_verifier.py').read_bytes(),
    }
    for name, raw in root_raw.items():
        row = root_rows[name]
        assert len(raw) == row['bytes'] and sha(raw) == row['sha256']
        add(row['path'], raw)
    add(freeze['verifier']['path'], root_raw['reference/policy_native5_verifier.py'])
    increment = json.loads((PACKAGE / 'proof/ROOT-CAPTURE-INCREMENT.json').read_bytes())
    add(increment['reviewed_capture_template']['path'], (PACKAGE / 'proof/reference/run_component_root_once.50a5.original.py').read_bytes())
    slots = {'PKG': freeze['runtime_manifest']['sha256'], 'COMBINATION': freeze['combination']['sha256'],
             'VERIFIER_SHA': freeze['verifier']['sha256'], 'VERIFIER_BYTES': freeze['verifier']['bytes'],
             'POLICY_SHA': freeze['actual_adopted_policy_sha256'], 'ADOPTION_SHA': freeze['policy_adoption']['sha256'],
             'ROOT_SCOPE_SHA': inputs['finalization']['scope_decision']['sha256']}
    canonical = {'manifest': root_manifest, 'rows': root_rows, 'raw': root_raw, 'slots': slots}

    class CachedOriginals:
        """Test adapter over already pinned local originals; no remote path I/O."""
        def __init__(self):
            self.reads = []

        def read(self, row):
            assert type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
            assert type(row['bytes']) is int and 0 <= row['bytes'] <= mod.MAX_ORIGINAL
            raw = cached[row['path']]
            assert len(raw) == row['bytes'] and sha(raw) == row['sha256']
            self.reads.append(dict(row))
            return raw

    originals = CachedOriginals()
    runtime = mod.validate_runtime_increment(originals, freeze, mod.EXECUTION_RUNTIME_INCREMENT_RESULT)
    assert runtime['source_package']['sha256'] == 'a33474b4479b8bb47acb6407525e30e82151e9f4b83dc0081851051003b144d7'
    capture = mod.validate_capture_increment(originals, freeze, inputs, canonical, runtime, mod.ROOT_CAPTURE_INCREMENT)
    assert capture['source_package']['sha256'] == '4eb4eeeb604e5526fd0c477a9a180b6b1e6d08f8016b3add7c605b62cdac22f3'
    assert freeze['runtime_manifest']['sha256'] == '67dc40470b8ecb1e10cb57f8953a3d0b6db309b45079216eb24cd65f0760107c'
    assert canonical['slots']['PKG'] == freeze['runtime_manifest']['sha256']
    checks = [
        {'case': 'actual32_runtime_increment_interface', 'passed': True},
        {'case': 'actual3_capture_increment_interface_with_rebound_bridge', 'passed': True},
        {'case': 'original_freeze_and_canonical_slots_not_mutated', 'passed': True},
    ]

    def rejects(name, call):
        before = len(originals.reads)
        try:
            call()
        except ValueError as error:
            checks.append({'case': name, 'passed': True, 'error': str(error),
                           'new_cached_original_reads': len(originals.reads) - before})
        else:
            raise AssertionError('negative source admission accepted: ' + name)

    rejects('canonical_runtime_cannot_replace_explicit_new_increment',
            lambda: mod.validate_runtime_increment(originals, freeze, freeze['runtime_manifest']))
    previous_increment = json.loads((PREVIOUS / 'proof/ROOT-CAPTURE-INCREMENT.json').read_bytes())
    rejects('old_capture_only_package_cannot_replace_explicit_new_increment',
            lambda: mod.validate_capture_increment(originals, freeze, inputs, canonical, runtime,
                                                  previous_increment['execution_source_package']))
    for name, value in (('missing_failed_prelaunch_evidence', None),
                        ('summary_label_cannot_replace_unfrozen_verifier', {'state': 'TWO_FAILED_PRELAUNCH_ATTEMPTS_RECONCILED_LAST_NATIVE08_UNCHANGED'})):
        rejects(name, lambda value=value: mod.validate_failed_prelaunch_admission(originals, inputs, value))

    tree = ast.parse(source)
    main_node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
    calls = {n.func.id: n.lineno for n in ast.walk(main_node) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id in ('validate_failed_prelaunch_admission', 'load_capture_coordinator', 'assemble')}
    assert calls['validate_failed_prelaunch_admission'] < calls['load_capture_coordinator'] < calls['assemble']
    assemble_node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'assemble')
    assemble_source = ast.get_source_segment(source.decode(), assemble_node)
    assert "prior_nonces.update(admission['forbidden_nonces'])" in assemble_source
    assert "package=copy.deepcopy(execution_runtime)" in assemble_source
    checks.append({'case': 'required_closure_precedes_coordinator_and_identity_assembly', 'passed': True})
    checks.append({'case': 'both_failed_nonces_feed_existing_identity_rejection', 'passed': True})
    assert mod.FAILED_PRELAUNCH_VERIFIER is None
    report = {'schema': 'hepta.runtime-prefix.helper-source-checks.v1',
              'state': 'NEW_RUNTIME_CAPTURE_INTERFACES_PASSED_FAILED_PRELAUNCH_GATE_REMAINS_CLOSED',
              'helper': {'bytes': len(source), 'sha256': sha(source)},
              'checks': checks, 'checks_total': len(checks), 'checks_passed': len(checks),
              'exact_cached_original_read_count': len(originals.reads),
              'read_adapter_scope': 'exact cached bytes mapped to retained original descriptors; not remote filesystem proof',
              'full_validate_freeze_executed': False, 'coordinator_loaded': False,
              'runtime_target_modules_executed': False, 'main_executed': False,
              'plan_assembled': False, 'nonce_generated': False,
              'remote_calls': 0, 'phone_calls': 0, 'case_qualification': False}
    raw = enc(report)
    path = HERE / 'helper-draft02/validation/LOCAL-INTERFACE-CHECKS.json'
    with path.open('xb') as stream:
        stream.write(raw)
    print(json.dumps({'path': str(path), 'bytes': len(raw), 'sha256': sha(raw),
                      'checks_passed': len(checks), 'main_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
