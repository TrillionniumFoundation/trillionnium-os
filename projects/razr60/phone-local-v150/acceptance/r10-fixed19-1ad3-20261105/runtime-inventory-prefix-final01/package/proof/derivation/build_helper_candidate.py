#!/usr/bin/env python3
"""Derive a blocked, source-only plan helper with explicit runtime/capture inputs."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

BASE = Path('/workspace/scratch/1ad3d6f55439')
HERE = BASE / 'runtime_prefix_successor_candidate01'
PACKAGE = HERE / 'package'
PARENT = BASE / 'r8_root_capture_successor_candidate01/delivery-final01/package/proof/source/prepare_native_guard_root_plan.py'
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


RUNTIME_BLOCK = '''def validate_runtime_increment(originals, freeze, increment_result_row):
    need(increment_result_row==EXECUTION_RUNTIME_INCREMENT_RESULT,
        'one exact independently reviewed runtime increment result required')
    result = strict(originals.read(increment_result_row))
    parent = strict(originals.read(freeze['runtime_manifest']))
    expected = {row['path'] for row in parent['files']}
    manifest,rows,raw = member_map(originals,EXECUTION_RUNTIME_MANIFEST,expected)
    manifest_raw = originals.read(EXECUTION_RUNTIME_MANIFEST)
    verifier_raw = originals.read(RUNTIME_INCREMENT_VERIFIER)
    module = types.ModuleType('reviewed_pure_runtime_source_increment')
    module.__file__ = RUNTIME_INCREMENT_VERIFIER['path']
    exec(compile(verifier_raw,module.__file__,'exec'),module.__dict__)
    proof = module.verify_runtime_source_increment(manifest_raw,raw)
    increment_raw = originals.read(RUNTIME_SOURCE_INCREMENT_RECORD)
    increment = strict(increment_raw)
    need(encoded(module.RUNTIME_SOURCE_INCREMENT)==increment_raw
        and encoded(manifest['runtime_source_increment'])==increment_raw,
        'runtime source increment and exact fixed verifier object differ')
    need(result['schema']=='hepta.native-guard.runtime-source-increment-result.v1'
        and result['state']=='LOCAL_SOURCE_SUCCESSOR_PREPARED_NOT_REMOTE_STAGED_OR_EXECUTED'
        and result['base_freeze_result']==ACTUAL_FREEZE_RESULT
        and result['base_freezer_source']==freeze['source']
        and result['base_runtime_manifest']==freeze['runtime_manifest']
        and result['runtime_manifest']==EXECUTION_RUNTIME_MANIFEST
        and result['runtime_source_increment']==RUNTIME_SOURCE_INCREMENT_RECORD
        and result['pure_verifier_source']==RUNTIME_INCREMENT_VERIFIER
        and encoded(result['source_inverse_proof'])==encoded(proof)
        and increment['base_freeze_result']==ACTUAL_FREEZE_RESULT
        and increment['base_runtime_manifest']==freeze['runtime_manifest']
        and result['runtime_member_count']==32 and result['unchanged_member_count']==31
        and result['canonical_originals_modified'] is False
        and result['original_freeze_claimed_this_successor'] is False
        and result['root_execution_started'] is False
        and result['component_qualified'] is False and result['business_qualified'] is False
        and all(type(result[key]) is int and result[key]==0 for key in
            ('remote_directories_created_by_this_derivation','phone_calls',
             'policy_applications','case_nonces_created')),
        'exact original freeze and independent runtime derivation differ')
    checks = strict(originals.read(result['local_source_checks']))
    need(checks['state']=='LOCAL_EXACT_RUNTIME32_AND_TARGETED_REJECTIONS_PASSED'
        and checks['checks_total']==checks['checks_passed']==len(checks['checks'])==7
        and all(row['passed'] is True for row in checks['checks'])
        and checks['case_qualification'] is False,
        'retained source checks are required but do not qualify a physical case')
    need(Path(EXECUTION_RUNTIME_MANIFEST['path'])==SUCCESSOR_HOME/'runtime/MANIFEST.json'
        and manifest['current_combination_sha256']==parent['current_combination_sha256']
        and manifest['current_policy_sha256']==parent['current_policy_sha256']
        and manifest['explicit_policy_adoption_sha256']==parent['explicit_policy_adoption_sha256'],
        'one exact runtime namespace with unchanged policy generation required')
    return {'manifest':manifest,'rows':rows,'raw':raw,'source_package':EXECUTION_RUNTIME_MANIFEST,
        'increment_result':increment_result_row,'increment':RUNTIME_SOURCE_INCREMENT_RECORD,
        'verifier':RUNTIME_INCREMENT_VERIFIER,'proof':proof}


def validate_failed_prelaunch_admission(originals, evidence_row):
    # No acceptance schema is invented here.  A profile of actual08 alone does
    # not close failed1ad3-01, its sender, the namespace, or external09.  A new
    # independently reviewed revision must consume their completed originals.
    need(FAILED_PRELAUNCH_ADMISSION is None,
        'unreviewed failed-prelaunch admission literal cannot enable execution')
    raise ValueError('failed-prelaunch admission is not frozen: the composed original-evidence '
        'verifier and actual closed proof are required before any new Root plan; '
        'a state label or successful global profile alone is insufficient')


'''


CAPTURE_BLOCK = '''def validate_capture_increment(originals, freeze, inputs, canonical, runtime, increment_row):
    need(increment_row==ROOT_CAPTURE_INCREMENT,'one explicitly reviewed runtime/capture increment required')
    increment = strict(originals.read(increment_row))
    execution_slots = dict(canonical['slots'],PKG=runtime['source_package']['sha256'])
    need(increment['schema']=='hepta.native-guard.actual-r8-runtime-root-capture-increment.v1'
        and increment['state']=='ACTUAL_R8_RUNTIME_CAPTURE_SUCCESSOR_SOURCE_ONLY'
        and increment['actual_freeze_result']==ACTUAL_FREEZE_RESULT
        and increment['actual_freezer_source']==freeze['source']
        and increment['actual_freeze_inputs']==freeze['inputs']
        and increment['actual_runtime_manifest']==freeze['runtime_manifest']
        and increment['actual_combination']==freeze['combination']
        and increment['actual_policy_adoption']==freeze['policy_adoption']
        and increment['actual_root_manifest']==freeze['root_chain_manifest']
        and increment['actual_coordinator']==canonical['rows']['source/run_component_root_once.py']
        and increment['execution_source_package']==ROOT_CAPTURE_MANIFEST
        and increment['execution_runtime_manifest']==runtime['source_package']
        and increment['runtime_increment_result']==runtime['increment_result']
        and increment['runtime_source_increment']==runtime['increment']
        and increment['runtime_increment_verifier']==runtime['verifier']
        and encoded(increment['seven_canonical_bindings'])==encoded(canonical['slots'])
        and encoded(increment['seven_execution_bindings'])==encoded(execution_slots)
        and increment['actual_old_freeze_used_repaired_capture'] is False
        and increment['actual_old_freeze_used_runtime_increment'] is False
        and increment['actual_old_freeze_outputs_preserved'] is True
        and all(type(increment[k]) is int and increment[k]==0 for k in
            ('phone_calls','native_submissions','new_nonces_generated','runtime_freezes','root_executions')),
        'actual freeze and separate runtime/capture provenance differ')
    source_names = {'source/run_component_root_once.py','source/phone_chain_bridge.py',
        'reference/policy_native5_verifier.py'}
    manifest,rows,raw = member_map(originals,ROOT_CAPTURE_MANIFEST,source_names)
    need(Path(ROOT_CAPTURE_MANIFEST['path'])==ROOT_CAPTURE_HOME/'SOURCE-MANIFEST.json'
        and manifest['schema']=='hepta.native-guard.root-chain-source-package.v1'
        and manifest['state']=='ACTUAL_R8_RUNTIME_CAPTURE_SUCCESSOR_SOURCE_ONLY'
        and manifest['frozen_component_package_sha256']==runtime['source_package']['sha256']
        and manifest['current_combination_sha256']==freeze['combination']['sha256']
        and manifest['explicit_policy_adoption_sha256']==freeze['policy_adoption']['sha256'],
        'only the independently reviewed exact runtime/capture source package is executable')
    source_scope = {'schema':'hepta.native-guard.root-source-scope.v2',
        'actual_r8_freeze_result':ACTUAL_FREEZE_RESULT,'actual_r8_root_chain_manifest':freeze['root_chain_manifest'],
        'actual_freezer_source':freeze['source'],'actual_r8_runtime_manifest':freeze['runtime_manifest'],
        'execution_capture_template':increment['reviewed_capture_template'],
        'execution_runtime_manifest':runtime['source_package'],
        'runtime_source_increment':runtime['increment'],'runtime_increment_result':runtime['increment_result'],
        'runtime_increment_verifier':runtime['verifier'],
        'replacement_scope':'runtime_inventory_prefix_and_root_host_transport_capture',
        'execution_runtime_changed_members':['source/late_boundary.py'],
        'canonical_originals_modified':False,'original_freeze_claimed_repaired_capture':False,
        'original_freeze_claimed_runtime_increment':False,
        'inherited_metadata_scope':'original_r7_to_r8_generation_preserved_not_successor_actions'}
    need(encoded(manifest['source_scope'])==encoded(source_scope)==encoded(increment['source_scope']),
        'separate canonical and execution runtime/source identities required')
    template = originals.read(increment['reviewed_capture_template'])
    need(len(template)==71820 and sha(template)==ROOT_TEMPLATE_SHA,
        'exact reviewed 50a5 transport template required')
    coordinator = raw['source/run_component_root_once.py']
    restored = coordinator
    for name,value in execution_slots.items():
        restored = set_literal(restored,name,value,None)
    need(restored==template and sha(restored)==ROOT_TEMPLATE_SHA
        and rows['source/run_component_root_once.py']==increment['execution_coordinator'],
        'capture coordinator differs beyond the seven exact execution bindings')
    bridge = raw['source/phone_chain_bridge.py']
    bridge_template = originals.read(increment['reviewed_bridge_template'])
    need(sha(bridge_template)==BRIDGE_TEMPLATE_SHA
        and set_literal(bridge,'PKG',execution_slots['PKG'],None)==bridge_template
        and set_literal(bridge,'PKG',execution_slots['PKG'],canonical['slots']['PKG'])
            ==canonical['raw']['source/phone_chain_bridge.py']
        and rows['source/phone_chain_bridge.py']==increment['execution_bridge'],
        'bridge may change only its execution runtime package pin')
    need(raw['reference/policy_native5_verifier.py']==canonical['raw']['reference/policy_native5_verifier.py']
        ==originals.read(freeze['verifier'])
        and rows['reference/policy_native5_verifier.py']==increment['unchanged_verifier']
        and len(raw['reference/policy_native5_verifier.py'])<=131072,
        'actual independent verifier must retain its exact original identity and bound')
    expected_manifest = copy.deepcopy(canonical['manifest'])
    expected_manifest['state'] = 'ACTUAL_R8_RUNTIME_CAPTURE_SUCCESSOR_SOURCE_ONLY'
    expected_manifest['source_scope'] = source_scope
    expected_manifest['frozen_component_package_sha256'] = runtime['source_package']['sha256']
    expected_manifest['files'] = [descriptor(name,body) for name,body in sorted(raw.items())]
    need(encoded(expected_manifest)==originals.read(ROOT_CAPTURE_MANIFEST),
        'Root manifest changed historical metadata beyond files/state/pkg/source_scope')
    return {'manifest':manifest,'rows':rows,'raw':raw,'source_scope':source_scope,
        'source_package':ROOT_CAPTURE_MANIFEST,'increment':increment_row}
'''


def main():
    parent_raw = PARENT.read_bytes()
    assert len(parent_raw) == 31714 and sha(parent_raw) == '1ff5c00fa4dfd0930e8d22590f14795e9adcd8a49163d3b1bd88550bc6ee2d63'
    source = parent_raw.decode()
    changes = []

    def replace(old, new, reason):
        nonlocal source
        assert old != new and source.count(old) == 1, (reason, source.count(old))
        source = source.replace(old, new, 1)
        changes.append({'reason': reason, 'before': old, 'after': new})

    def replace_function(name, new):
        tree = ast.parse(source)
        nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name]
        assert len(nodes) == 1
        lines = source.splitlines(keepends=True)
        old = ''.join(lines[nodes[0].lineno - 1:nodes[0].end_lineno])
        replace(old, new, 'replace explicit source admission: ' + name)

    def replace_literal(name, value):
        nodes = [n for n in ast.parse(source).body if isinstance(n, ast.Assign) and len(n.targets) == 1
                 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
        assert len(nodes) == 1 and nodes[0].lineno == nodes[0].end_lineno
        old = source.splitlines(keepends=True)[nodes[0].lineno - 1]
        replace(old, name + ' = ' + repr(value) + '\n', 'pin separate successor descriptor: ' + name)

    increment_raw = (PACKAGE / 'proof/ROOT-CAPTURE-INCREMENT.json').read_bytes()
    assert len(increment_raw) == 12350 and sha(increment_raw) == 'bb3d8fbb1133b4b46e5d389508577727414cfb7556791602d4f503fde6b15860'
    increment = json.loads(increment_raw)
    runtime_result_raw = (PACKAGE / 'proof/RUNTIME-INCREMENT-RESULT.json').read_bytes()
    runtime_result = json.loads(runtime_result_raw)
    replace('The default performs the complete pure validation without creating files.\n',
        'This source-only revision is blocked until the separate failed-prelaunch\n'
        'original-evidence verifier is reviewed and frozen. No state label can\n'
        'substitute for it. After that revision, default validation creates no files.\n',
        'declare intentionally unfrozen failed-prelaunch admission')
    old = "ROOT_CAPTURE_HOME = B/'native-guard-property-root-r8-capture-successor01-1ad3'\nROOT_CAPTURE_PROOF_HOME = B/'native-guard-property-root-r8-capture-successor01-1ad3-proof'\n"
    new = "SUCCESSOR_HOME = B/'native-guard-r10-r1-operator-r8-inventory-prefix-1ad3-01'\nROOT_CAPTURE_HOME = SUCCESSOR_HOME/'root-chain'\nROOT_CAPTURE_PROOF_HOME = SUCCESSOR_HOME/'proof'\n"
    replace(old, new, 'one independent runtime/capture namespace')
    replace_literal('ROOT_CAPTURE_MANIFEST', increment['execution_source_package'])
    replace_literal('ROOT_CAPTURE_INCREMENT', desc(DEST / 'proof/ROOT-CAPTURE-INCREMENT.json', increment_raw))
    added = ''.join(name + ' = ' + repr(value) + '\n' for name, value in (
        ('EXECUTION_RUNTIME_MANIFEST', runtime_result['runtime_manifest']),
        ('EXECUTION_RUNTIME_INCREMENT_RESULT', desc(DEST / 'proof/RUNTIME-INCREMENT-RESULT.json', runtime_result_raw)),
        ('RUNTIME_SOURCE_INCREMENT_RECORD', runtime_result['runtime_source_increment']),
        ('RUNTIME_INCREMENT_VERIFIER', runtime_result['pure_verifier_source']),
        ('FAILED_PRELAUNCH_ADMISSION', None)))
    replace('FIRST_PRIOR = {\n', added + 'FIRST_PRIOR = {\n', 'fixed runtime provenance plus required unfrozen failed-prelaunch admission')
    replace('def validate_capture_increment(originals, freeze, inputs, canonical, increment_row):\n',
        RUNTIME_BLOCK + 'def validate_capture_increment(originals, freeze, inputs, canonical, increment_row):\n',
        'add pure runtime increment gate and explicit fail-closed prelaunch evidence gate')
    replace_function('validate_capture_increment', CAPTURE_BLOCK)
    replace('def choose_prior(originals, inputs, freeze, case_id, result_row, execution_manifest):',
        'def choose_prior(originals, inputs, freeze, case_id, result_row, execution_manifest, execution_runtime):',
        'pass execution runtime explicitly into predecessor validation')
    replace("and predecessor['package']==freeze['runtime_manifest']", "and predecessor['package']==execution_runtime",
        'qualified NEG02 predecessor must use this independent runtime')
    replace('def assemble(originals, inputs, freeze, base_row, case_id, label, nonce, request_row, prior, execution_manifest):',
        'def assemble(originals, inputs, freeze, base_row, case_id, label, nonce, request_row, prior, execution_manifest, execution_runtime):',
        'pass execution runtime explicitly into plan assembly')
    replace('request=copy.deepcopy(request_row),package=copy.deepcopy(freeze[\'runtime_manifest\']),',
        'request=copy.deepcopy(request_row),package=copy.deepcopy(execution_runtime),',
        'plan binds execution runtime without mutating original freeze identity')
    replace('and R8 not in host_out.parents and CHAINS not in host_out.parents\n',
        'and R8 not in host_out.parents and CHAINS not in host_out.parents\n'
        '        and SUCCESSOR_HOME not in host_out.parents and host_out!=SUCCESSOR_HOME\n',
        'exclude every successor source/proof namespace from host plan output')
    replace("'request','qualified_neg01_result','host_out','root_capture_increment'}", 
        "'request','qualified_neg01_result','host_out','root_capture_increment',\n"
        "        'runtime_source_increment_result','failed_prelaunch_evidence'}",
        'require explicit runtime derivation and failed-prelaunch evidence inputs')
    replace("and value['schema']=='hepta.native-guard.r8-root-plan-preparation-inputs.v1',",
        "and value['schema']=='hepta.native-guard.runtime-successor-root-plan-preparation-inputs.v1',",
        'distinct source-increment input protocol')
    replace("capture = validate_capture_increment(originals,freeze,freeze_inputs,canonical,value['root_capture_increment'])\n",
        "runtime = validate_runtime_increment(originals,freeze,value['runtime_source_increment_result'])\n"
        "    capture = validate_capture_increment(originals,freeze,freeze_inputs,canonical,runtime,value['root_capture_increment'])\n"
        "    admission = validate_failed_prelaunch_admission(originals,value['failed_prelaunch_evidence'])\n",
        'runtime and original-evidence gates precede loading any coordinator')
    replace("prior = choose_prior(originals,freeze_inputs,freeze,value['case_id'],value['qualified_neg01_result'],capture['source_package'])",
        "prior = choose_prior(originals,freeze_inputs,freeze,value['case_id'],value['qualified_neg01_result'],\n"
        "        capture['source_package'],runtime['source_package'])", 'forward independent runtime to current predecessor gate')
    replace("value['nonce'],value['request'],prior,capture['source_package'])",
        "value['nonce'],value['request'],prior,capture['source_package'],runtime['source_package'])",
        'forward independent runtime to exact Root plan')
    replace("'runtime_manifest':freeze['runtime_manifest'],'root_chain_manifest':capture['source_package'],",
        "'canonical_runtime_manifest':freeze['runtime_manifest'],\n"
        "        'runtime_manifest':runtime['source_package'],'root_chain_manifest':capture['source_package'],\n"
        "        'runtime_source_increment_result':runtime['increment_result'],\n"
        "        'failed_prelaunch_evidence':value['failed_prelaunch_evidence'],'failed_prelaunch_admission':admission,",
        'preparation report exposes canonical and execution sources plus required admission')
    candidate = source.encode()
    compile(candidate, str(DEST / 'proof/source/prepare_native_guard_root_plan.py'), 'exec')
    inverse = source
    for change in reversed(changes):
        assert inverse.count(change['after']) == 1, change['reason']
        inverse = inverse.replace(change['after'], change['before'], 1)
    assert inverse.encode() == parent_raw
    parent_tree, child_tree = ast.parse(parent_raw), ast.parse(candidate)
    parent_functions = {n.name: ast.get_source_segment(parent_raw.decode(), n) for n in parent_tree.body if isinstance(n, ast.FunctionDef)}
    child_functions = {n.name: ast.get_source_segment(candidate.decode(), n) for n in child_tree.body if isinstance(n, ast.FunctionDef)}
    unchanged = sorted(k for k in parent_functions if parent_functions[k] == child_functions[k])
    changed = sorted(k for k in parent_functions if parent_functions[k] != child_functions[k])
    assert changed == ['assemble', 'choose_prior', 'main', 'require_unused', 'validate_capture_increment']
    assert parent_functions['validate_freeze'] == child_functions['validate_freeze']
    assert sorted(set(child_functions) - set(parent_functions)) == ['validate_failed_prelaunch_admission', 'validate_runtime_increment']
    put(PACKAGE / 'proof/source/prepare_native_guard_root_plan.py', candidate)
    put(PACKAGE / 'proof/reference/prepare_native_guard_root_plan.1ff5.original.py', parent_raw)
    patch = ''.join(difflib.unified_diff(parent_raw.decode().splitlines(keepends=True), source.splitlines(keepends=True),
        fromfile='prepare_native_guard_root_plan.1ff5.original.py', tofile='prepare_native_guard_root_plan.py')).encode()
    put(PACKAGE / 'proof/validation/PLAN-HELPER-INCREMENT.patch', patch)
    put(PACKAGE / 'proof/validation/PLAN-HELPER-EXACT-REPLACEMENTS.json', enc({
        'schema': 'hepta.exact-source-replacements.v1', 'parent': desc(PARENT, parent_raw),
        'candidate': desc(DEST / 'proof/source/prepare_native_guard_root_plan.py', candidate),
        'whole_byte_inverse_verified': True, 'replacements': changes,
        'unchanged_top_level_functions': unchanged, 'changed_top_level_functions': changed,
        'added_top_level_functions': ['validate_failed_prelaunch_admission', 'validate_runtime_increment'],
        'validate_freeze_byte_identical': True, 'failed_prelaunch_admission': None,
        'main_executed': False, 'phone_calls': 0, 'new_nonces': 0}))
    print(json.dumps({'helper': desc(DEST / 'proof/source/prepare_native_guard_root_plan.py', candidate),
        'patch': desc('proof/validation/PLAN-HELPER-INCREMENT.patch', patch),
        'replacement_count': len(changes), 'unchanged_functions': len(unchanged),
        'failed_prelaunch_admission': None}, sort_keys=True))


if __name__ == '__main__':
    main()
