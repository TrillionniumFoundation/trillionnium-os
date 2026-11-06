#!/usr/bin/env python3
"""Reproduce the actual binder mismatch and normalize its two nested descriptors.

Only the actual controller_context assignment is evaluated. No source stage,
BUILD, device command, case materialization or coordinator is executed.
"""
import ast
import difflib
import hashlib
import json
from pathlib import Path, PurePosixPath
import types

HERE = Path(__file__).resolve().parent
REVIEW = HERE.parent
B = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
OUTPUT = B + '/followthrough-fc33-r6-source-rebind-casefix01'
BEFORE = "'SOURCES': {'component_build': report['helper'], 'release_install_stage': report['stage']}})"
AFTER = "'SOURCES': {'component_build': descriptor(report['helper']), 'release_install_stage': descriptor(report['stage'])}})"


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def enc(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def load(raw, name, file):
    m = types.ModuleType(name); m.__file__ = str(file)
    exec(compile(raw, str(file), 'exec'), m.__dict__)
    return m


def put(name, raw):
    p = HERE / name; p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with p.open('xb') as stream:
        stream.write(raw)


def main():
    carrier = json.loads((HERE / 'evidence/ACTUAL-BINDER-READ.original.mcp.json').read_bytes())
    assert carrier['isError'] is False
    observed = json.loads(carrier['content'][0]['text'])
    bodies = {}
    for row in observed['files']:
        candidates = [row['text']]
        try:
            candidates.append(json.loads('"' + row['text'] + '"'))
        except json.JSONDecodeError:
            pass
        body = next((text.encode() for text in candidates if type(text) is str
            and len(text.encode()) == row['size'] and hashlib.sha256(text.encode()).hexdigest() == row['sha256']), None)
        assert body is not None and row['eof'] is True
        bodies[Path(row['path']).name] = body
    report = json.loads(bodies['DERIVATION.json'])
    actual_binder = bodies['bind_actual_controller_input.py']
    assert pin(actual_binder) == dict(bytes=9462, sha256='0f7af3752228f720640d9449ef54eb7d5aa7740b5b4d096f5542eceb9db447b1')
    parent = (REVIEW / 'R6-source-rebind/actual-readback/actual/source/derive_r6_source_rebindings_UNBOUND.py').read_bytes()
    assert pin(parent) == dict(bytes=45097, sha256='3d6cf7e6c7129f7433762de03bbe612c4181e5b63835e692c02604415bf5cef4')
    assert parent.decode().count(BEFORE) == 1 and parent.decode().count(AFTER) == 0
    candidate = parent.replace(BEFORE.encode(), AFTER.encode(), 1)
    assert candidate.replace(AFTER.encode(), BEFORE.encode(), 1) == parent
    M = load(parent, 'actual_original_r6_rebinder', 'actual-published-r6-rebinder.py')
    N = load(candidate, 'nested_descriptor_normalized_r6_rebinder', 'candidate-r6-rebinder.py')
    constructor_raw = (REVIEW / 'install-source-chain43/source/derive_reviewed_release_sources_UNBOUND.py').read_bytes()
    assert pin(constructor_raw) == {k: M.CONSTRUCTOR[k] for k in ('bytes', 'sha256')}
    R = load(constructor_raw, 'actual_reviewed_change_constructor', 'reviewed-4c8.py')
    old_binder = (REVIEW / 'install-build-controller/bind_actual_controller_input.py').read_bytes()
    assert pin(old_binder) == {k: M.BINDER_PARENT[k] for k in ('bytes', 'sha256')}
    def evaluate_assignment(module, source):
        ctx = object.__new__(module.Context); ctx.R = R
        reads = []
        def actual_parent_reader(row):
            assert module.same(row, M.BINDER_PARENT)
            reads.append(row)
            return old_binder
        ctx.pool = module.Pool(actual_parent_reader)
        function = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'controller_context')
        statement = next(n for n in function.body if isinstance(n, ast.Assign)
            and isinstance(n.targets[0], ast.Tuple)
            and any(isinstance(t, ast.Name) and t.id == 'binder' for t in n.targets[0].elts))
        namespace = dict(ctx=ctx, report=report, root=PurePosixPath(report['binder']['path']).parent.parent,
                         BINDER_PARENT=M.BINDER_PARENT, descriptor=module.descriptor)
        exec(compile(ast.Module(body=[statement], type_ignores=[]), '<actual-controller-context-assignment>', 'exec'), namespace)
        assert len(reads) == 1
        return namespace['binder']
    before = evaluate_assignment(M, parent)
    after = evaluate_assignment(N, candidate)
    assert before != actual_binder and after == actual_binder
    assert R.literal(before, 'SOURCES') == R.literal(actual_binder, 'SOURCES')
    assert enc(R.literal(before, 'SOURCES')) == enc(R.literal(actual_binder, 'SOURCES'))
    assert list(report['helper']) == list(report['stage']) == ['bytes', 'path', 'sha256']
    assert list(N.descriptor(report['helper'])) == list(N.descriptor(report['stage'])) == ['path', 'bytes', 'sha256']
    callbacks = []
    try:
        N.derive_rebindings(b'not json', read_pinned=lambda row: callbacks.append(row))
    except ValueError as error:
        assert str(error) == 'UNBOUND_R6_SOURCE_REBINDING_NO_IO'
    else:
        raise AssertionError('unbound successor executed')
    assert not callbacks and N.FROZEN_INPUTS is None
    binder_parent = (REVIEW / 'R6-source-rebind/actual-readback/actual/source/bind_r6_source_input.py').read_bytes()
    source_row = dict(path=OUTPUT + '/source/derive_r6_source_rebindings_UNBOUND.py', **pin(candidate))
    change = R.Changes(binder_parent); change.rhs('SOURCE', source_row)
    successor_binder, binder_inverse = change.finish()
    source_patch = ''.join(difflib.unified_diff(parent.decode().splitlines(True), candidate.decode().splitlines(True),
        fromfile='actual-published/derive_r6_source_rebindings_UNBOUND.py', tofile='successor/derive_r6_source_rebindings_UNBOUND.py')).encode()
    mismatch = ''.join(difflib.unified_diff(actual_binder.decode().splitlines(True), before.decode().splitlines(True),
        fromfile='actual-published/bind_actual_controller_input.py', tofile='old-controller-context/recomputed.py')).encode()
    put('source/derive_r6_source_rebindings_UNBOUND.py', candidate)
    put('source/bind_r6_source_input.py', successor_binder)
    put('reference/REBINDER.PARENT.original.py', parent)
    put('reference/BINDING-HELPER.PARENT.original.py', binder_parent)
    put('reference/ACTUAL-BINDER.original.py', actual_binder)
    put('reference/ACTUAL-CONTROLLERS-DERIVATION.original.json', bodies['DERIVATION.json'])
    put('SOURCE.patch', source_patch); put('ACTUAL-BINDER-MISMATCH.patch', mismatch)
    proof = dict(schema='hepta.fc33.r6.case-controller-nested-descriptor-inverse.v1',
        parent=pin(parent), candidate=source_row, one_complete_source_replacement=dict(before=BEFORE, after=AFTER),
        full_source_inverse=True, old_recomputed_binder=pin(before), actual_published_binder=report['binder'],
        corrected_recomputed_binder=pin(after), actual_nested_input_order=['bytes', 'path', 'sha256'],
        exact_source_descriptor_order=['path', 'bytes', 'sha256'], binding_helper_inverse=binder_inverse,
        existing_release_controllers_E2E_sources_changed=False, prior_failed_job='1a1b2a31057-fc05-7f16',
        actual_R6_case_controller_publication=None, phone_calls=0, actual_BUILD=None, actual_READY=None)
    put('SOURCE-INVERSE.json', enc(proof))
    result = dict(schema='hepta.fc33.r6.case-controller-source-compatibility-controls.v1',
        state='ACTUAL_BINDER_BYTE_ORDER_FAILURE_REPRODUCED_SUCCESSOR_SOURCE_CHECKED_ONLY',
        control_count=5, controls=[
            'actual_original_callsite_reproduces_whole_binder_byte_mismatch',
            'difference_is_nested_descriptor_order_in_semantically_identical_SOURCES',
            'corrected_exact_callsite_reconstructs_actual_published_binder_whole_bytes',
            'successor_rebinder_and_binding_helper_have_complete_source_inverses',
            'unbound_successor_refuses_before_parse_or_original_callback'],
        passed=True, parent=pin(parent), candidate=pin(candidate), actual_binder=pin(actual_binder),
        corrected_binder=pin(after), actual_freeze_or_source_stage_rerun=False,
        actual_R6_case_controller_success=False, callback_count_in_unbound_control=len(callbacks),
        source_controls_from_previous_candidate_not_added=True, phone_calls=0, native_dispatches=0,
        BUILD_executed=False, new_nonces=0, fixed19_credit=0)
    put('RESULT.json', enc(result))
    print(json.dumps(dict(source=pin(candidate), binder=pin(successor_binder), controls=5,
        result=pin(enc(result)), actual_whole_binder_equal=True, phone_calls=0), sort_keys=True))


if __name__ == '__main__':
    main()
