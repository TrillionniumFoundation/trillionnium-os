#!/usr/bin/env python3
"""One real isolated host child; no E2E registration, nonce or phone call."""
import argparse
import ast
import difflib
import hashlib
import json
from pathlib import Path
import sys
import types

HERE = Path(__file__).resolve().parent
REVIEW = HERE.parent
ORIGINAL = REVIEW / 'R5-actual-e2e-bound-source/actual/source/run_fixed19_e2e_root_once.py'
CAPTURE = REVIEW / 'R5-actual-e2e-bound-source/actual/reference/owned_capture.source.original.py'
BEFORE = b'   receipts.append(dict(phase=phase,**result))\n'
AFTER = b"   receipts.append({**result,'phase':phase})\n"
ORIGINAL_PIN = {'bytes': 20208, 'sha256': 'd1959bfc46c0dc0e347a1a438062f6f6259d85bd6f17cf0b4aae967f1e488b53'}
CAPTURE_PIN = {'bytes': 37720, 'sha256': '9d273d66adc09c670ae09aa06fae699d2d1de9e1981afd3980bec7e4eda6cb29'}


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def enc(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def put(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    a = parser.parse_args(); out = a.out.absolute(); out.mkdir(mode=0o700)
    original = ORIGINAL.read_bytes(); capture_raw = CAPTURE.read_bytes()
    assert pin(original) == ORIGINAL_PIN and pin(capture_raw) == CAPTURE_PIN
    assert original.count(BEFORE) == 1 and original.count(AFTER) == 0
    candidate = original.replace(BEFORE, AFTER)
    assert candidate.count(AFTER) == 1 and candidate.replace(AFTER, BEFORE) == original
    compile(candidate, 'candidate-coordinator', 'exec')
    put(out/'run_fixed19_e2e_root_once.py', candidate)
    patch = ''.join(difflib.unified_diff(original.decode().splitlines(True), candidate.decode().splitlines(True),
        fromfile='actual49/source/run_fixed19_e2e_root_once.py', tofile='candidate/source/run_fixed19_e2e_root_once.py'))
    put(out/'SOURCE.patch', patch.encode())
    put(out/'INVERSE.json', enc(dict(original=ORIGINAL_PIN, candidate=pin(candidate),
        replaced_line=209, before=BEFORE.decode(), after=AFTER.decode(), complete_byte_inverse=True,
        production_source_changes=0, operator_manifest_changes=0, child_phase_program_changes=0)))
    capture = types.ModuleType('actual_reviewed_owned_capture')
    capture.__file__ = str(CAPTURE)
    exec(compile(capture_raw, str(CAPTURE), 'exec'), capture.__dict__)
    probe_raw = b"print('host-only owned capture interface probe')\n"
    probe_path = out/'probe.py'; put(probe_path, probe_raw)
    probe = dict(path=str(probe_path), **pin(probe_raw))
    # These are explicitly source-control identities, not an actual task proof.
    binding = dict(schema='hepta.fixed19.e2e.phase-command.v1', case_id='E2E-01', phase_kind='register',
        context_sha256=pin(b'HOST_ONLY_SOURCE_INTERFACE_PROBE')['sha256'],
        owner_request_sha256=pin(b'NO_PHONE_NO_REGISTRATION')['sha256'],
        source=probe, plan=None, manifest=None, input_originals=[probe],
        expected_result_state='ORIGINAL_HOST_CHILD_JOINED')
    owner = capture.OwnedCapture(out/'owned-probe')
    result = owner.run_phase_original('01-register', [sys.executable, '-I', '-B', str(probe_path)],
        20, command_binding=binding)
    assert result['phase'] == '01-register' and type(result['returncode']) is int and result['returncode'] == 0
    assert Path(result['stdout']['path']).read_bytes() == b'host-only owned capture interface probe\n'
    assert Path(result['stderr']['path']).read_bytes() == b''
    assert all(not owner.__dict__.get(name) for name in
        ('_owned_host_children', '_owned_host_streams', '_owned_host_deadlines', '_owned_host_captures'))
    original_node = next(n for n in ast.walk(ast.parse(original)) if isinstance(n, ast.Expr)
        and n.lineno == 209)
    candidate_node = next(n for n in ast.walk(ast.parse(candidate)) if isinstance(n, ast.Expr)
        and n.lineno == 209)
    failed = {'receipts': [], 'phase': 'register', 'result': result}
    try:
        exec(compile(ast.Module(body=[original_node], type_ignores=[]), 'original-line-209', 'exec'), failed)
    except TypeError as error:
        failure = dict(type=type(error).__name__, message=str(error), original_receipts=failed['receipts'])
    else:
        raise AssertionError('original line unexpectedly accepted duplicate keyword')
    before_result = enc(result)
    fixed = {'receipts': [], 'phase': 'register', 'result': result}
    exec(compile(ast.Module(body=[candidate_node], type_ignores=[]), 'candidate-line-209', 'exec'), fixed)
    expected = dict(result); expected['phase'] = 'register'
    assert enc(fixed['receipts']) == enc([expected]) and enc(result) == before_result
    checks = ['exact_two_frozen_sources', 'one_line_full_byte_inverse', 'candidate_compiles',
        'actual_owned_child_completed_with_two_full_streams', 'actual_child_result_includes_phase',
        'original_line_reproduces_duplicate_keyword_TypeError', 'replacement_accepts_actual_original_result',
        'only_logical_phase_changes_in_receipt', 'original_child_result_not_mutated', 'owned_resources_released']
    report = dict(schema='hepta.fc33.e2e.coordinator-phase-compatibility.source-control.v1',
        state='SOURCE_INTERFACE_DEFECT_REPRODUCED_AND_ONE_LINE_CANDIDATE_VERIFIED',
        original=ORIGINAL_PIN, candidate=pin(candidate), capture=CAPTURE_PIN,
        original_failure=failure, actual_host_probe_result=result,
        controls=[dict(name=name, passed=True) for name in checks],
        control_count=len(checks), actual_host_probe_count=1, phone_calls=0, registrations=0,
        native_sends=0, model_requests=0, new_nonces=0, actual_E2E=False, fixed19_credit=0)
    put(out/'RESULT.json', enc(report))
    print(json.dumps(dict(state=report['state'], source=pin(candidate), result=pin(enc(report)),
        controls=len(checks), phone_calls=0, registrations=0, native_sends=0), sort_keys=True))


if __name__ == '__main__':
    main()
