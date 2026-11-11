#!/usr/bin/env python3
"""Run one synthetic lane and an optional pinned external historical-prefix lane.

Only explicit host model/Android IO continues the recovery. No device operation,
native inference, or raw private history copied into the repository is involved.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--classes', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--trace', type=Path)
    args = parser.parse_args()
    source, classes, output = args.source.resolve(), args.classes.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    pins_file = source / 'tests/notes-task-phase/fixtures/v46-notes-recovery-pins.json'
    pins = json.loads(pins_file.read_text())['files']
    external = {}
    if args.trace:
        for name, expected in pins.items():
            path = args.trace.resolve() / name
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != expected:
                raise RuntimeError(f'external fixture input SHA mismatch: {name}')
            external[str(path)] = actual
    lanes = [('synthetic', None)]
    if args.trace:
        lanes.append(('external_actual_trace', args.trace.resolve()))
    report = {'schema': 'hepta.notes-recovery-lanes.v1', 'phone_operations': False,
              'native_inference': False, 'fresh_model_task_success': False,
              'external_inputs_sha256': external, 'lanes': [], 'passed': False}
    all_passed = True
    for mode, trace in lanes:
        lane_output = output / mode
        java = ['java', '-cp', str(classes), 'org.trillionnium.hepta.local.NotesRecoveryHostTest', str(lane_output), str(pins_file)]
        if trace:
            java.append(str(trace))
        commands = [('java', java), ('grammar', [sys.executable, str(source / 'tests/notes-task-phase/test_phase_grammar.py'), str(lane_output / 'grammar-cases.json')])]
        lane = {'fixture_mode': mode, 'stages': [], 'passed': False}
        for stage, argv in commands:
            started = time.monotonic()
            process = subprocess.run(argv, capture_output=True, text=True, timeout=60)
            (output / f'{mode}-{stage}.stdout').write_text(process.stdout)
            (output / f'{mode}-{stage}.stderr').write_text(process.stderr)
            lane['stages'].append({'name': stage, 'argv': argv, 'exit_code': process.returncode, 'elapsed_s': time.monotonic() - started})
            if process.returncode:
                print(process.stdout[-2000:])
                print(process.stderr[-4000:])
                all_passed = False
                break
        if len(lane['stages']) == len(commands) and all(x['exit_code'] == 0 for x in lane['stages']):
            lane['evidence'] = json.loads((lane_output / 'RESULT.json').read_text())
            if lane['evidence']['fixture_mode'] != mode or not lane['evidence']['passed']:
                raise RuntimeError('lane receipt identity mismatch')
            if mode == 'external_actual_trace' and lane['evidence']['input_files_sha256'] != pins:
                raise RuntimeError('external lane did not read every pinned input')
            lane['passed'] = True
        report['lanes'].append(lane)
        if not all_passed:
            break
    if any(hashlib.sha256(Path(path).read_bytes()).hexdigest() != sha for path, sha in external.items()):
        raise RuntimeError('external input changed during replay')
    report['passed'] = all_passed and len(report['lanes']) == len(lanes) and all(x['passed'] for x in report['lanes'])
    (output / 'RESULT.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'fixture_modes': [x['fixture_mode'] for x in report['lanes']], 'phone_tested': False, 'fresh_model_task_success': False}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
