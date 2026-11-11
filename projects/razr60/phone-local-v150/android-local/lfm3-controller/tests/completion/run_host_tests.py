#!/usr/bin/env python3
"""Real controller/service/adapter contracts with explicit Android/model IO fakes."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--release8', action='store_true')
    args = parser.parse_args()
    source = args.source.resolve()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    helper = source / 'tests/qualification-scope/prepare_fixture.py'
    spec = importlib.util.spec_from_file_location('fixed_intent_actual_fixture', helper)
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    files, extraction = fixture.prepare(source, out / 'fixture')
    # Android UID IO is synthetic. The surrounding host files remain real and all
    # private-file/symlink/fsync production checks still execute against these IO fakes.
    uid_io = out / 'uid-io'
    uid_io.mkdir()
    process = uid_io / 'Process.java'
    process.write_text('package android.os;public final class Process {private Process(){}public static int myUid(){return 10481;}public static int myPid(){return 123;}}\n')
    os_source = source / 'tests/qualification-scope/fixtures/android/system/Os.java'
    os_text = os_source.read_text()
    needle = 'r.st_uid=((Number)a.get("uid")).intValue();'
    if os_text.count(needle) != 1:
        raise RuntimeError('exact filesystem UID IO anchor changed')
    os_fake = uid_io / 'Os.java'
    os_fake.write_text(os_text.replace(needle, needle + f'if(r.st_uid=={os.getuid()})r.st_uid=10481;'))
    files = [p for p in files if p != os_source and p != source / 'tests/qualification-scope/fixtures/android/os/Process.java']
    files += [process, os_fake]
    extraction['ordinary_android_uid_io_fake'] = {'uid': 10481, 'host_uid_mapped': os.getuid(), 'not_android_permission_proof': True}
    files += [source / 'tests/fixed-intent-tools/FixedIntentIntegrationHostTest.java', source / 'tests/completion/TaskCompletionGateHostTest.java']
    files += [source / 'tests/notes-task-phase/NotesTaskPhaseHostTest.java']
    files += [source / 'tests/notes-task-phase/NotesListProvenanceHostTest.java']
    files += [source / 'tests/notes-task-phase/NotesRecoveryHostTest.java']
    files += [source / 'tests/notes-task-phase/NotesTaskScopeHostTest.java']
    files += [source / 'tests/calculator-input/CalculatorInputGuardHostTest.java',
              source / 'tests/calculator-input/FailedActionObservationHostTest.java']
    files += [source / 'tests/notes-editor-phase/NotesEditorPhaseHostTest.java']
    files += [source / 'tests/completion-status/CompletionStatusHostTest.java']
    pins = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    phase_fixture = source / 'tests/notes-task-phase/fixtures/v45-notes-trace.json'
    phase_recognizer = source / 'tests/notes-task-phase/test_phase_grammar.py'
    list_fixture = source / 'tests/notes-task-phase/fixtures/manual-notes-list.xml'
    recovery_fixture = source / 'tests/notes-task-phase/fixtures/v46-notes-recovery-trace.json'
    scope_fixture = source / 'tests/notes-task-phase/fixtures/v47-notes-scope-trace.json'
    calculator_fixture = source / 'tests/calculator-input/fixtures/v47-background-type-failure.json'
    editor_fixture = source / 'tests/notes-editor-phase/fixtures/v48-editor-click-trace.json'
    completion_status_fixture = source / 'tests/completion-status/fixtures/v49-premature-success-trace.json'
    for p in (phase_fixture, phase_recognizer, list_fixture, recovery_fixture, scope_fixture, calculator_fixture, editor_fixture, completion_status_fixture):
        pins[str(p)] = hashlib.sha256(p.read_bytes()).hexdigest()
    classes = out / 'classes'
    classes.mkdir()
    compiler = [shutil.which('javac')] if shutil.which('javac') else ['java', '-m', 'jdk.compiler/com.sun.tools.javac.Main']
    flags = ['--release', '8'] if args.release8 else ['-source', '8', '-target', '8']
    lint = '-Xlint:all' if args.release8 else '-Xlint:all,-options'
    commands = [
        ('compile', compiler + flags + ['-encoding', 'UTF-8', lint, '-Werror', '-d', str(classes), *map(str, files)]),
        ('actual-completion', ['java', '-cp', str(classes), 'org.trillionnium.hepta.local.TaskCompletionGateHostTest', str(out / 'cases')]),
        ('notes-task-phase', ['java', '-cp', str(classes), 'org.trillionnium.hepta.local.NotesTaskPhaseHostTest', str(phase_fixture), str(out / 'notes-task-phase')]),
        ('notes-task-phase-grammar', [sys.executable, str(phase_recognizer), str(out / 'notes-task-phase/grammar-cases.json')]),
        ('notes-list-provenance', ['java', '-cp', str(classes), 'org.trillionnium.hepta.local.NotesListProvenanceHostTest', str(list_fixture)]),
        ('notes-recovery', ['java', '-cp', str(classes), 'org.trillionnium.hepta.local.NotesRecoveryHostTest', str(recovery_fixture), str(out / 'notes-recovery')]),
        ('notes-recovery-grammar', [sys.executable, str(phase_recognizer), str(out / 'notes-recovery/grammar-cases.json')]),
        ('notes-task-scope', ['java', '-cp', str(classes), 'org.trillionnium.hepta.local.NotesTaskScopeHostTest', str(scope_fixture), str(out / 'notes-task-scope')]),
        ('notes-task-scope-grammar', [sys.executable, str(phase_recognizer), str(out / 'notes-task-scope/grammar-cases.json')]),
        ('calculator-input', ['java', '-cp', str(classes), 'org.trillionnium.hepta.local.CalculatorInputGuardHostTest', str(calculator_fixture), str(out / 'calculator-input')]),
        ('calculator-input-grammar', [sys.executable, str(phase_recognizer), str(out / 'calculator-input/grammar-cases.json')]),
        ('failed-action-observation', ['java', '-cp', str(classes), 'org.trillionnium.hepta.local.FailedActionObservationHostTest', str(out / 'failed-action-observation')]),
        ('notes-editor-phase', ['java', '-cp', str(classes), 'org.trillionnium.hepta.local.NotesEditorPhaseHostTest', str(editor_fixture), str(out / 'notes-editor-phase')]),
        ('notes-editor-phase-grammar', [sys.executable, str(phase_recognizer), str(out / 'notes-editor-phase/grammar-cases.json')]),
        ('completion-status', ['java', '-cp', str(classes), 'org.trillionnium.hepta.local.CompletionStatusHostTest', str(completion_status_fixture), str(out / 'completion-status')]),
        ('completion-status-grammar', [sys.executable, str(phase_recognizer), str(out / 'completion-status/grammar-cases.json')]),
    ]
    report = {'schema': 'hepta.task-completion-host.v1', 'source_inputs': pins, 'extraction': extraction,
              'compiler_contract': 'Java 8 API release' if args.release8 else 'Java 8 syntax/target only; not release8 or Android proof',
              'phone_operations': False, 'native_inference': False, 'android_runtime': False, 'stages': [], 'passed': False}
    for name, argv in commands:
        started = time.monotonic()
        result = subprocess.run(argv, capture_output=True, text=True, timeout=90)
        (out / (name + '.stdout')).write_text(result.stdout)
        (out / (name + '.stderr')).write_text(result.stderr)
        report['stages'].append({'name': name, 'argv': argv, 'exit_code': result.returncode, 'elapsed_s': time.monotonic() - started})
        if result.returncode:
            print(result.stdout[-3000:])
            print(result.stderr[-5000:])
            break
    report['passed'] = len(report['stages']) == len(commands) and all(r['exit_code'] == 0 for r in report['stages'])
    if any(hashlib.sha256(Path(path).read_bytes()).hexdigest() != sha for path, sha in pins.items()):
        raise RuntimeError('source changed during real-class tests')
    (out / 'RESULT.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('passed', 'compiler_contract', 'phone_operations')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
