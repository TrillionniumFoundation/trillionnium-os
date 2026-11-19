#!/usr/bin/env python3
"""Actual immutable handoff contract with synthetic complete-census inputs only."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--java-home', type=Path, required=True)
    p.add_argument('--json-jar', type=Path, required=True)
    a = p.parse_args()
    root, out = a.source.resolve(), a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    bg = root/'src/org/trillionnium/hepta/background'
    local = root/'src/org/trillionnium/hepta/local'
    test = root/'tests/controller-display-handoff/ControllerDisplayHandoffHostTest.java'
    sources = [bg/'ControllerDisplayHandoff.java', test]
    inputs = sources+[bg/'ControllerDisplayHandoffMain.java', local/'ControllerDisplayHandoffClient.java',
                      local/'LocalTaskController.java', local/'LocalTaskSession.java', local/'MainActivity.java',
                      Path(__file__).resolve(), a.json_jar.resolve()]

    def pin(path):
        raw = path.read_bytes()
        return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

    before = [pin(path) for path in inputs]
    if before[-1]['sha256'] != '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed':
        raise RuntimeError('exact real JSON jar required')
    classes = out/'classes'
    classes.mkdir()
    commands = [
        ('compile', [str(a.java_home/'bin/javac'), '--release', '8', '-Xlint:all', '-Werror',
                     '-encoding', 'UTF-8', '-cp', str(a.json_jar), '-d', str(classes), *map(str, sources)]),
        ('contract', [str(a.java_home/'bin/java'), '-cp', str(classes)+':'+str(a.json_jar),
                      'org.trillionnium.hepta.background.ControllerDisplayHandoffHostTest'])]
    report = {'schema': 'hepta.controller-display-handoff-host.v1', 'all_pass': False,
              'strict_release8': True, 'phone_operations': 0, 'android_runtime': False,
              'root_reader_executed': False, 'synthetic_contract_tests': True,
              'inputs_before': before, 'stages': []}
    for name, argv in commands:
        started = time.monotonic()
        actual = subprocess.run(argv, capture_output=True, timeout=45)
        so, se = out/(name+'.stdout'), out/(name+'.stderr')
        so.write_bytes(actual.stdout)
        se.write_bytes(actual.stderr)
        report['stages'].append({'name': name, 'argv': argv, 'exit_code': actual.returncode,
                                 'elapsed_seconds': time.monotonic()-started,
                                 'stdout': pin(so), 'stderr': pin(se)})
        if actual.returncode:
            break
        if name == 'contract':
            lines = actual.stdout.decode('utf-8').splitlines()
            report['test'] = json.loads(lines[-1])
            report['case_names'] = [line[5:] for line in lines[:-1] if line.startswith('PASS ')]
            if len(lines) != 46 or len(report['case_names']) != 45 or len(set(report['case_names'])) != 45:
                raise RuntimeError('actual contract cases missing or duplicated')
    report['inputs_after'] = [pin(path) for path in inputs]
    report['all_pass'] = (len(report['stages']) == 2
                          and all(row['exit_code'] == 0 for row in report['stages'])
                          and report['inputs_after'] == before
                          and report.get('test') == {'all_pass': True, 'phone_operations': 0, 'cases': 45,
                                                    'assertions': 54, 'synthetic_contract_tests': True})
    dest = out/'RESULT.json'
    dest.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'all_pass': report['all_pass'], 'result': pin(dest), 'test': report.get('test')}))
    return 0 if report['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
