#!/usr/bin/env python3
"""Strict Java 8 lifecycle test, including a real delayed host child process.

No Android, proprietary SDK, DSP, phone or business-task execution is claimed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    if output.is_relative_to(source):
        raise ValueError('host output must be outside immutable source')
    output.mkdir(parents=True, exist_ok=False)
    classes = output / 'classes'
    classes.mkdir()
    names = ('OwnedWorkerCancellation', 'WarmProcessSession')
    files = [source / 'src/org/trillionnium/hepta/local' / (name + '.java') for name in names]
    files += [source / 'tests/owned-worker-cancellation' / name for name in
              ('OwnedWorkerCancellationHostTest.java', 'NativeCancellationPipeHostTest.java')]
    pins = {str(path.relative_to(source)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    java, javac = shutil.which('java'), shutil.which('javac')
    if not java or not javac:
        raise RuntimeError('existing complete JDK required')
    commands = [('compile', [javac, '--release', '8', '-encoding', 'UTF-8', '-Xlint:all', '-Werror',
                            '-d', str(classes), *map(str, files)]),
                ('tests', [java, '-cp', str(classes), 'org.trillionnium.hepta.local.OwnedWorkerCancellationHostTest'])]
    report = {'schema': 'hepta.owned-worker-cancellation-host.v1', 'passed': False,
              'compiler_contract': 'Java 8 API release, Xlint:all, Werror', 'source_inputs': pins,
              'phone_tested': False, 'android_runtime': False, 'proprietary_sdk_executed': False, 'stages': []}
    for name, command in commands:
        started = time.monotonic()
        result = subprocess.run(command, capture_output=True, timeout=60, check=False)
        (output / (name + '.stdout')).write_bytes(result.stdout)
        (output / (name + '.stderr')).write_bytes(result.stderr)
        report['stages'].append({'name': name, 'argv': command, 'exit_code': result.returncode,
                                 'elapsed_s': time.monotonic() - started})
        if result.returncode:
            break
    report['source_unchanged'] = all(hashlib.sha256((source / name).read_bytes()).hexdigest() == pin
                                     for name, pin in pins.items())
    report['passed'] = (len(report['stages']) == len(commands)
                        and all(stage['exit_code'] == 0 for stage in report['stages'])
                        and report['source_unchanged'])
    (output / 'RESULT.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'source_unchanged': report['source_unchanged'],
                      'phone_tested': False}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
