#!/usr/bin/env python3
"""Bind the agreed failed-prelaunch verifier API; its future source stays None."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path('/workspace/scratch/1ad3d6f55439/runtime_prefix_successor_candidate01')
OUT = HERE / 'helper-draft02'
DEST = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-inventory-prefix-1ad3-01/proof/source/prepare_native_guard_root_plan.py'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + '\n').encode()


def put(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
    assert path.read_bytes() == raw


GATE = '''def validate_failed_prelaunch_admission(originals, freeze_inputs, evidence_row):
    # The exact verifier source must be reviewed and frozen in a successor
    # revision.  A global actual08 profile alone cannot close either attempt.
    need(type(FAILED_PRELAUNCH_VERIFIER) is dict
        and set(FAILED_PRELAUNCH_VERIFIER)=={'path','bytes','sha256'}
        and type(FAILED_PRELAUNCH_VERIFIER['bytes']) is int
        and 0<FAILED_PRELAUNCH_VERIFIER['bytes']<=262144,
        'failed-prelaunch verifier is not frozen: actual two-attempt original-evidence '
        'closure is required before a new Root plan; no state label substitutes for it')
    verifier_raw = originals.read(FAILED_PRELAUNCH_VERIFIER)
    module = types.ModuleType('reviewed_failed_prelaunch_original_evidence_verifier')
    module.__file__ = FAILED_PRELAUNCH_VERIFIER['path']
    module.__reviewed_source_sha256__ = FAILED_PRELAUNCH_VERIFIER['sha256']
    exec(compile(verifier_raw,module.__file__,'exec'),module.__dict__)
    value = strict(originals.read(evidence_row))
    result = module.verify_failed_prelaunch_admission(value,read_pinned=originals.read)
    prior = strict(originals.read(freeze_inputs['history08_descriptor']))
    need(type(result) is dict
        and result['schema']=='hepta.native-guard.failed-prelaunch-admission.v1'
        and result['state']=='TWO_FAILED_PRELAUNCH_ATTEMPTS_RECONCILED_LAST_NATIVE08_UNCHANGED'
        and encoded(result['last_real_native_boundary'])==encoded(prior)
        and result['failed_prelaunch_labels']==['root-r10-neg01-20261105-09','root-r10-neg01-1ad3-01']
        and result['component_qualified'] is False and result['business_qualified'] is False
        and result['native_boundary_created'] is False and result['nonce_reuse_forbidden'] is True,
        'recomputed two-attempt closure and exact retained actual08 frontier required')
    nonces = result['failed_prelaunch_nonces']
    need(type(nonces) is list and len(nonces)==2 and len(set(nonces))==2
        and all(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce) for nonce in nonces),
        'both actual failed-prelaunch nonces must be independently recovered and forbidden')
    return {'verifier_source':FAILED_PRELAUNCH_VERIFIER,'admission_original':evidence_row,
        'verification':result,'forbidden_nonces':nonces}
'''


def main():
    assert not OUT.exists()
    old = (HERE / 'package/proof/source/prepare_native_guard_root_plan.py').read_bytes()
    assert len(old) == 40101 and sha(old) == 'f7f2c7d7d1daccba8ac218e4f224767fa545d6522e0ce5f4450b6075bc0f1f90'
    parent = (HERE / 'package/proof/reference/prepare_native_guard_root_plan.1ff5.original.py').read_bytes()
    first = json.loads((HERE / 'package/proof/validation/PLAN-HELPER-EXACT-REPLACEMENTS.json').read_bytes())
    text = old.decode()
    changes = []

    def replace(before, after, reason):
        nonlocal text
        assert before != after and text.count(before) == 1, (reason, text.count(before))
        text = text.replace(before, after, 1)
        changes.append({'reason': reason, 'before': before, 'after': after})

    replace('FAILED_PRELAUNCH_ADMISSION = None\n', 'FAILED_PRELAUNCH_VERIFIER = None\n',
        'require reviewed future verifier identity, not a completion label')
    node = next(n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef) and n.name == 'validate_failed_prelaunch_admission')
    before = ''.join(text.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])
    replace(before, GATE, 'exact agreed read-pinned original-evidence API; None rejects before loading')
    replace('def assemble(originals, inputs, freeze, base_row, case_id, label, nonce, request_row, prior, execution_manifest, execution_runtime):',
        'def assemble(originals, inputs, freeze, base_row, case_id, label, nonce, request_row, prior, execution_manifest, execution_runtime, admission):',
        'include recovered failed-attempt nonce set in identity admission')
    replace("prior_nonces = {OLD08_NONCE,boundary['nonce']}\n",
        "prior_nonces = {OLD08_NONCE,boundary['nonce']}\n"
        "    prior_nonces.update(admission['forbidden_nonces'])\n",
        'failed prelaunch may not reuse a nonce under another label')
    replace("parser.add_argument('--execute-host-plan',action='store_true')\n",
        "parser.add_argument('--failed-prelaunch-admission-desc',required=True,\n"
        "        help='exact descriptor of the independently recomputed two-attempt closure originals')\n"
        "    parser.add_argument('--execute-host-plan',action='store_true')\n",
        'require explicit actual failed-prelaunch admission CLI input')
    replace("freeze,freeze_inputs,canonical = validate_freeze(originals,value['freeze_result'])\n",
        "failed_evidence_row = strict(args.failed_prelaunch_admission_desc)\n"
        "    need(encoded(failed_evidence_row)==encoded(value['failed_prelaunch_evidence']),\n"
        "        'explicit admission descriptor and pinned preparation input differ')\n"
        "    freeze,freeze_inputs,canonical = validate_freeze(originals,value['freeze_result'])\n",
        'bind CLI evidence to the exact preparation input original')
    replace("admission = validate_failed_prelaunch_admission(originals,value['failed_prelaunch_evidence'])",
        "admission = validate_failed_prelaunch_admission(originals,freeze_inputs,failed_evidence_row)",
        'verify the complete closure and retained native08 before coordinator loading')
    replace("value['nonce'],value['request'],prior,capture['source_package'],runtime['source_package'])",
        "value['nonce'],value['request'],prior,capture['source_package'],runtime['source_package'],admission)",
        'apply verified failed-nonce exclusions to the new request')
    new = text.encode()
    compile(new, DEST, 'exec')
    combined = first['replacements'] + changes
    reverse = text
    for change in reversed(combined):
        assert reverse.count(change['after']) == 1, change['reason']
        reverse = reverse.replace(change['after'], change['before'], 1)
    assert reverse.encode() == parent
    old_validate = ast.get_source_segment(parent.decode(), next(n for n in ast.parse(parent).body
        if isinstance(n, ast.FunctionDef) and n.name == 'validate_freeze'))
    new_validate = ast.get_source_segment(text, next(n for n in ast.parse(new).body
        if isinstance(n, ast.FunctionDef) and n.name == 'validate_freeze'))
    assert old_validate == new_validate
    put(OUT / 'source/prepare_native_guard_root_plan.py', new)
    put(OUT / 'reference/prepare_native_guard_root_plan.f7f2.blocked-draft01.py', old)
    put(OUT / 'reference/prepare_native_guard_root_plan.1ff5.original.py', parent)
    patch = ''.join(difflib.unified_diff(parent.decode().splitlines(keepends=True), text.splitlines(keepends=True),
        fromfile='prepare_native_guard_root_plan.1ff5.original.py', tofile='prepare_native_guard_root_plan.py')).encode()
    put(OUT / 'validation/PLAN-HELPER-INCREMENT.patch', patch)
    put(OUT / 'validation/PLAN-HELPER-EXACT-REPLACEMENTS.json', enc({
        'schema': 'hepta.exact-source-replacements.v1',
        'parent': {'bytes': len(parent), 'sha256': sha(parent)},
        'candidate': {'path': DEST, 'bytes': len(new), 'sha256': sha(new)},
        'whole_byte_inverse_verified': True, 'replacements': combined,
        'validate_freeze_byte_identical': True, 'failed_prelaunch_verifier': None,
        'required_original_closure_not_yet_admissible': True,
        'main_executed': False, 'phone_calls': 0, 'new_nonces': 0}))
    print(json.dumps({'helper': {'path': DEST, 'bytes': len(new), 'sha256': sha(new)},
        'required_verifier': None, 'whole_byte_inverse_to1ff5': True, 'replacements': len(combined)}, sort_keys=True))


if __name__ == '__main__':
    main()
