#!/usr/bin/env python3
"""Pure Calculator contracts; actual Java production, explicit synthetic host IO.

Does not start ADB, inference, a UI, or any action. Archived legacy observations
remain incomplete inputs. A pass never qualifies a phone calculation or task.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--release8', action='store_true')
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    helper = source / 'tests/qualification-scope/prepare_fixture.py'
    spec = importlib.util.spec_from_file_location('calculator_actual_class_fixture', helper)
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    files, extraction = fixture.prepare(source, output / 'fixture')
    package = source / 'src/org/trillionnium/hepta/local'
    files += [package / 'CalculatorGoalContract.java', package / 'CalculatorCompletionEvidence.java',
              source / 'tests/calculator-completion/CalculatorCompletionHostTest.java']
    files = list(dict.fromkeys(files))
    original = source / 'tests/calculator-completion/fixtures'
    inputs = list(dict.fromkeys(files + [helper, Path(__file__).resolve()] + sorted(original.iterdir())))
    pins = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    classes = output / 'classes'
    classes.mkdir()
    compiler = [shutil.which('javac')] if shutil.which('javac') else ['java', '-m', 'jdk.compiler/com.sun.tools.javac.Main']
    flags = ['--release', '8'] if args.release8 else ['-source', '8', '-target', '8']
    commands = [
        ('compile', compiler + flags + ['-encoding', 'UTF-8', '-Xlint:all' if args.release8 else '-Xlint:all,-options',
             '-Werror', '-d', str(classes), *map(str, files)]),
        ('calculator-pure', ['java', '-cp', str(classes), 'org.trillionnium.hepta.local.CalculatorCompletionHostTest',
             str(original), str(output / 'TEST-RESULTS.json')]),
    ]
    report = {'schema': 'hepta.calculator-pure-host-run.v1', 'source_inputs': pins, 'extraction': extraction,
              'compiler_contract': 'Java 8 API release' if args.release8 else 'Java 8 syntax/target only',
              'stages': [], 'passed': False, 'controller_integrated': False, 'causal_gate_implemented': False,
              'phone_tested': False, 'native_inference': False}
    for name, argv in commands:
        started = time.monotonic()
        result = subprocess.run(argv, capture_output=True, text=True, timeout=90)
        (output / (name + '.stdout')).write_text(result.stdout)
        (output / (name + '.stderr')).write_text(result.stderr)
        report['stages'].append({'name': name, 'argv': argv, 'exit_code': result.returncode,
                                 'elapsed_s': time.monotonic() - started})
        if result.returncode:
            break
    report['passed'] = len(report['stages']) == len(commands) and all(x['exit_code'] == 0 for x in report['stages'])
    for path, sha in pins.items():
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != sha:
            raise RuntimeError('source changed while checking actual production classes')
    (output / 'RESULT.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('passed', 'compiler_contract', 'phone_tested', 'controller_integrated')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
