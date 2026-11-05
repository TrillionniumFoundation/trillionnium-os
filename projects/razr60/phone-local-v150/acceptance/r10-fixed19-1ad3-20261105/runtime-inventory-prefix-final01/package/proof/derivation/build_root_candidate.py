#!/usr/bin/env python3
"""Derive the local Root3 successor; no target module is imported or executed."""
import ast
import copy
import hashlib
import json
from pathlib import Path

BASE = Path('/workspace/scratch/1ad3d6f55439')
HERE = BASE / 'runtime_prefix_successor_candidate01'
PACKAGE = HERE / 'package'
PREVIOUS = BASE / 'r8_root_capture_successor_candidate01/delivery-final01/package'
DEST = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-inventory-prefix-1ad3-01')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + '\n').encode()


def desc(path, raw):
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def put(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
    assert path.read_bytes() == raw


def set_literal(raw, name, old, new):
    nodes = [n for n in ast.parse(raw).body if isinstance(n, ast.Assign) and len(n.targets) == 1
             and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
    assert len(nodes) == 1 and nodes[0].lineno == nodes[0].end_lineno
    node = nodes[0]
    assert ast.literal_eval(node.value) == old
    lines = raw.decode().splitlines(keepends=True)
    original = lines[node.lineno - 1]
    prefix = original.split('#', 1)[0].rstrip()
    lines[node.lineno - 1] = name + '=' + repr(new) + original[len(prefix):]
    return ''.join(lines).encode()


def checked(path, size, digest):
    raw = path.read_bytes()
    assert len(raw) == size and sha(raw) == digest
    return raw


def main():
    assert not (PACKAGE / 'root-chain').exists()
    previous_increment_raw = checked(PREVIOUS / 'proof/ROOT-CAPTURE-INCREMENT.json', 8100,
        'd972a2d67a0f55cd0fadc0a92c172f03b142d2eb85f59eedb01ec35e2dcd1887')
    previous_increment = json.loads(previous_increment_raw)
    canonical_raw = checked(BASE / 'actual_r8_external_freeze/root-chain/SOURCE-MANIFEST.json', 11442,
        '7315f6561e221fb59429f9daa8ec1a34a944681fd2a117773611c11fa82a81ca')
    canonical = json.loads(canonical_raw)
    assert enc(canonical) == canonical_raw
    previous_raw = checked(PREVIOUS / 'root-package/SOURCE-MANIFEST.json', 13013,
        '52897bea5de19270c4a5d2ab8285c831a39f7d33376a8eb47ad873e31370c17e')
    previous_manifest = json.loads(previous_raw)
    runtime_raw = checked(PACKAGE / 'runtime/MANIFEST.json', 19020,
        'a33474b4479b8bb47acb6407525e30e82151e9f4b83dc0081851051003b144d7')
    runtime_result_raw = checked(PACKAGE / 'proof/RUNTIME-INCREMENT-RESULT.json', 6132,
        'b13be5219320c82c9a440d2adfa83758d0ba06ee6d3e50468f7c28bb5658e171')
    runtime_result = json.loads(runtime_result_raw)
    runtime_row = desc(DEST / 'runtime/MANIFEST.json', runtime_raw)
    assert runtime_result['runtime_manifest'] == runtime_row
    template = checked(PREVIOUS / 'proof/reference/run_component_root_once.50a5.original.py', 71820,
        '50a500e0c1cc014d3d4043f8c86172bf0b6068719473eb5646aca818416ed649')
    bridge_template = checked(PREVIOUS / 'proof/reference/phone_chain_bridge.6694.original.py', 8036,
        '6694b106ee8ccf2177bf758367fda214f27b7ebfbea1611e11e67604a2bfd572')
    sources = {}
    for row in previous_manifest['files']:
        sources[row['path']] = checked(PREVIOUS / 'root-package' / row['path'], row['bytes'], row['sha256'])
    assert set(sources) == {'source/run_component_root_once.py', 'source/phone_chain_bridge.py',
                            'reference/policy_native5_verifier.py'}
    actual_slots = previous_increment['seven_actual_bindings']
    execution_slots = dict(actual_slots, PKG=runtime_row['sha256'])
    assert actual_slots['PKG'] == runtime_result['base_runtime_manifest']['sha256']
    for name in ('source/run_component_root_once.py', 'source/phone_chain_bridge.py'):
        original = sources[name]
        sources[name] = set_literal(original, 'PKG', actual_slots['PKG'], execution_slots['PKG'])
        assert set_literal(sources[name], 'PKG', execution_slots['PKG'], actual_slots['PKG']) == original
    inverse = sources['source/run_component_root_once.py']
    for name, value in execution_slots.items():
        inverse = set_literal(inverse, name, value, None)
    assert inverse == template
    assert set_literal(sources['source/phone_chain_bridge.py'], 'PKG', execution_slots['PKG'], None) == bridge_template
    assert len(sources['reference/policy_native5_verifier.py']) == 126796 <= 131072
    assert sha(sources['reference/policy_native5_verifier.py']) == '74f4c89b32b36b074971b247de1951962b45384ef821330b94656d144e512152'

    runtime_result_row = desc(DEST / 'proof/RUNTIME-INCREMENT-RESULT.json', runtime_result_raw)
    source_scope = {
        'schema': 'hepta.native-guard.root-source-scope.v2',
        'actual_r8_freeze_result': previous_increment['actual_freeze_result'],
        'actual_freezer_source': previous_increment['actual_freezer_source'],
        'actual_r8_root_chain_manifest': previous_increment['actual_root_manifest'],
        'actual_r8_runtime_manifest': previous_increment['actual_runtime_manifest'],
        'execution_capture_template': previous_increment['reviewed_capture_template'],
        'execution_runtime_manifest': runtime_row,
        'runtime_source_increment': runtime_result['runtime_source_increment'],
        'runtime_increment_result': runtime_result_row,
        'runtime_increment_verifier': runtime_result['pure_verifier_source'],
        'replacement_scope': 'runtime_inventory_prefix_and_root_host_transport_capture',
        'execution_runtime_changed_members': ['source/late_boundary.py'],
        'canonical_originals_modified': False,
        'original_freeze_claimed_repaired_capture': False,
        'original_freeze_claimed_runtime_increment': False,
        'inherited_metadata_scope': 'original_r7_to_r8_generation_preserved_not_successor_actions',
    }
    current = copy.deepcopy(canonical)
    current['state'] = 'ACTUAL_R8_RUNTIME_CAPTURE_SUCCESSOR_SOURCE_ONLY'
    current['source_scope'] = source_scope
    current['frozen_component_package_sha256'] = runtime_row['sha256']
    current['files'] = [desc(name, raw) for name, raw in sorted(sources.items())]
    current_raw = enc(current)
    manifest_row = desc(DEST / 'root-chain/SOURCE-MANIFEST.json', current_raw)
    restored = copy.deepcopy(current)
    restored.pop('source_scope')
    for key in ('state', 'frozen_component_package_sha256', 'files'):
        restored[key] = canonical[key]
    assert enc(restored) == canonical_raw
    source_rows = {name: desc(DEST / 'root-chain' / name, raw) for name, raw in sources.items()}
    increment = {
        'schema': 'hepta.native-guard.actual-r8-runtime-root-capture-increment.v1',
        'state': 'ACTUAL_R8_RUNTIME_CAPTURE_SUCCESSOR_SOURCE_ONLY',
        'actual_freeze_result': previous_increment['actual_freeze_result'],
        'actual_freezer_source': previous_increment['actual_freezer_source'],
        'actual_freeze_inputs': previous_increment['actual_freeze_inputs'],
        'actual_runtime_manifest': previous_increment['actual_runtime_manifest'],
        'actual_combination': previous_increment['actual_combination'],
        'actual_policy_adoption': previous_increment['actual_policy_adoption'],
        'actual_root_manifest': previous_increment['actual_root_manifest'],
        'actual_coordinator': previous_increment['actual_coordinator'],
        'previous_independent_capture_package': previous_increment['execution_source_package'],
        'previous_capture_increment': desc(Path(previous_increment['execution_source_package']['path']).parent.with_name(
            'native-guard-property-root-r8-capture-successor01-1ad3-proof') / 'ROOT-CAPTURE-INCREMENT.json', previous_increment_raw),
        'reviewed_capture_template': previous_increment['reviewed_capture_template'],
        'reviewed_bridge_template': desc(DEST / 'proof/reference/phone_chain_bridge.6694.original.py', bridge_template),
        'execution_source_package': manifest_row,
        'execution_coordinator': source_rows['source/run_component_root_once.py'],
        'execution_bridge': source_rows['source/phone_chain_bridge.py'],
        'unchanged_verifier': source_rows['reference/policy_native5_verifier.py'],
        'execution_runtime_manifest': runtime_row,
        'runtime_increment_result': runtime_result_row,
        'runtime_source_increment': runtime_result['runtime_source_increment'],
        'runtime_increment_verifier': runtime_result['pure_verifier_source'],
        'seven_canonical_bindings': actual_slots,
        'seven_execution_bindings': execution_slots,
        'source_scope': source_scope,
        'root_manifest_changes_from_canonical': ['files', 'frozen_component_package_sha256', 'source_scope', 'state'],
        'whole_byte_inverse_to_50a5_template': True,
        'whole_bridge_inverse_to_6694_template': True,
        'runtime_member_count': 32, 'execution_root_source_count': 3,
        'verifier_byte_limit_unchanged': 131072,
        'actual_old_freeze_used_repaired_capture': False,
        'actual_old_freeze_used_runtime_increment': False,
        'actual_old_freeze_outputs_preserved': True,
        'phone_calls': 0, 'native_submissions': 0, 'new_nonces_generated': 0,
        'runtime_freezes': 0, 'root_executions': 0,
        'failed_prelaunch_admission_frozen': False,
        'business_qualified': False, 'component_qualified': False, 'whole_cases_passed': 0,
    }
    increment_raw = enc(increment)
    put(PACKAGE / 'root-chain/SOURCE-MANIFEST.json', current_raw)
    for name, raw in sorted(sources.items()):
        put(PACKAGE / 'root-chain' / name, raw)
    put(PACKAGE / 'proof/ROOT-CAPTURE-INCREMENT.json', increment_raw)
    for name, raw in (
            ('run_component_root_once.50a5.original.py', template),
            ('phone_chain_bridge.6694.original.py', bridge_template),
            ('root-capture-parent.SOURCE-MANIFEST.original.json', previous_raw),
            ('root-capture-parent.INCREMENT.original.json', previous_increment_raw),
            ('root-canonical7315.SOURCE-MANIFEST.original.json', canonical_raw)):
        put(PACKAGE / 'proof/reference' / name, raw)
    checks = {
        'schema': 'hepta.runtime-root-increment.local-source-checks.v1',
        'state': 'WHOLE_SOURCE_AND_MANIFEST_INVERSES_PASSED_NO_TARGET_EXECUTION',
        'coordinator_seven_slot_inverse50a5': True,
        'coordinator_one_pkg_inverse_c1b03': True,
        'bridge_one_pkg_inverse6694': True,
        'bridge_one_pkg_inverse04f6': True,
        'verifier_original74f4_unchanged': True,
        'root_manifest_exact_four_field_derivation_from7315': True,
        'old_generation_pins_unchanged_except_execution_pkg': True,
        'source_count': 3, 'runtime_count': 32, 'verifier_limit': 131072,
        'source_modules_executed': 0, 'remote_calls': 0, 'phone_calls': 0,
        'new_case_nonces': 0, 'case_qualification': False,
    }
    put(PACKAGE / 'proof/validation/ROOT-INVERSE-CHECKS.json', enc(checks))
    print(json.dumps({'manifest': manifest_row,
        'increment': desc(DEST / 'proof/ROOT-CAPTURE-INCREMENT.json', increment_raw),
        'source_rows': source_rows}, sort_keys=True))


if __name__ == '__main__':
    main()
