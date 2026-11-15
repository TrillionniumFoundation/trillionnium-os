#!/usr/bin/env python3
"""Compile the actual pure NotesOwnerIntent and fixed-payload validator, Java 8."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--release8', action='store_true')
    args = parser.parse_args()
    source, out = args.source.resolve(), args.output.resolve()
    if out.is_relative_to(source):
        raise ValueError('test output must be outside immutable source')
    out.mkdir(parents=True, exist_ok=False)
    # The unchanged actual Owner grammar closure supplies the real authority compiler.
    names = ('BackgroundTaskTarget', 'NativeAppGoal', 'NotesOwnerIntent', 'TaskAuthorization', 'ActionDecision', 'DecisionGrammar',
             'ObservedTargetLabels', 'ObservedAppLabels', 'ObservedScrollActions',
             'ObservedImeEnter', 'AppCatalogueRanker')
    files = [source / 'src/org/trillionnium/hepta/local' / (name + '.java') for name in names]
    files += [source / 'src/org/trillionnium/hepta/background' / (name + '.java')
              for name in ('FixedIntentTools', 'FixedIntentTarget')]
    files += [source / 'src/org/trillionnium/hepta/local/web' / (name + '.java')
              for name in ('WebFlightGoal', 'WebShoppingGoal')]
    files.append(source / 'tests/notes-owner-intent/NotesOwnerIntentHostTest.java')
    pins = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    classes = out / 'classes'
    classes.mkdir()
    compiler = [shutil.which('javac')] if shutil.which('javac') else ['java', '-m', 'jdk.compiler/com.sun.tools.javac.Main']
    flags = ['--release', '8'] if args.release8 else ['-source', '8', '-target', '8']
    lint = '-Xlint:all' if args.release8 else '-Xlint:all,-options'
    stages = [('compile', compiler + flags + ['-encoding', 'UTF-8', lint, '-Werror', '-d', str(classes), *map(str, files)]),
              ('notes-owner-intent', ['java', '-cp', str(classes), 'org.trillionnium.hepta.local.NotesOwnerIntentHostTest'])]
    report = {'schema': 'hepta.notes-owner-intent-host.v1', 'phone_operations': False,
              'android_runtime': False, 'native_inference': False, 'source_inputs': pins,
              'compiler_contract': 'Java 8 API release' if args.release8 else 'Java 8 syntax/target only',
              'stages': [], 'passed': False}
    outputs = {}
    for name, argv in stages:
        started = time.monotonic()
        result = subprocess.run(argv, capture_output=True, timeout=60)
        (out / (name + '.stdout')).write_bytes(result.stdout)
        (out / (name + '.stderr')).write_bytes(result.stderr)
        outputs[name] = result.stdout.decode('utf-8', 'strict')
        report['stages'].append({'name': name, 'argv': argv, 'exit_code': result.returncode,
                                 'elapsed_s': time.monotonic() - started})
        if result.returncode:
            break
    passed = len(report['stages']) == 2 and all(x['exit_code'] == 0 for x in report['stages'])
    text = outputs.get('notes-owner-intent', '')
    case = re.fullmatch(r'NOTES_OWNER_INTENT_CASES=(\d+)\nNOTES_OWNER_INTENT_ASSERTIONS=(\d+)\n'
                       r'NOTES_OWNER_INTENT_PASSED phone_tested=false android_io=false model_io=false\n', text)
    report['passed'] = passed and case is not None
    if case is not None:
        report['cases'], report['assertions'] = int(case[1]), int(case[2])
    report['source_unchanged'] = all(hashlib.sha256((source / name).read_bytes()).hexdigest() == digest
                                     for name, digest in pins.items())
    if not report['source_unchanged']:
        report['passed'] = False
    (out / 'RESULT.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('passed', 'source_unchanged', 'phone_operations')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
