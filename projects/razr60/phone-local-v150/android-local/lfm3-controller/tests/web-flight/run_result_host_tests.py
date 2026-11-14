#!/usr/bin/env python3
"""Compile current flight result bindings and completion composition on Java 8.

Runs the byte-pinned original query40 driver first, then the result lifecycle and
composition suites. The result Page is a declared synthetic carrier: no website
result parser or phone business acceptance is represented by this gate.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(value, message):
    if not value:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'java-home', 'json-jar', 'calendar-dom', 'calendar-ax'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    driver = root / 'tests/web-flight/run_query_host_tests.py'
    tests = [root / ('tests/web-flight/' + name + '.java') for name in
             ('WebFlightResultLifetimeHostTest', 'WebFlightResultCompositionHostTest')]
    inputs = [driver, *tests, *[root / ('src/org/trillionnium/hepta/local/' + name + '.java') for name in
              ('WebFlightResult', 'WebFlightProgress', 'WebFlightDomain', 'WebTaskDomain', 'TaskCompletionGate', 'WebFlightSession')]]
    before = {str(p): sha(p.read_bytes()) for p in inputs}
    report = {'schema': 'hepta.flight-result-host-gate.v1', 'all_pass': False, 'phone_actions': 0,
              'provider_carriers_injected_synthetically': True, 'actual_results_dom_parser_executed': False,
              'actual_results_verified': False, 'source_inputs': before, 'stages': []}

    def command(name, argv, timeout):
        start = time.monotonic()
        run = subprocess.run(list(map(str, argv)), cwd=root, stdin=subprocess.DEVNULL,
                             capture_output=True, timeout=timeout)
        (output / (name + '.stdout')).write_bytes(run.stdout)
        (output / (name + '.stderr')).write_bytes(run.stderr)
        report['stages'].append({'name': name, 'argv': list(map(str, argv)), 'exit_code': run.returncode,
                                'elapsed_s': time.monotonic() - start,
                                'stdout_sha256': sha(run.stdout), 'stderr_sha256': sha(run.stderr)})
        need(run.returncode == 0, 'host command failed: ' + name)

    try:
        query = output / 'query40'
        command('query40', [sys.executable, '-B', driver, '--source', root, '--output', query,
                           '--java-home', args.java_home, '--json-jar', args.json_jar,
                           '--calendar-dom', args.calendar_dom, '--calendar-ax', args.calendar_ax], 150)
        prior = json.loads((query / 'RESULT.json').read_text())
        need(prior['all_pass'] is True and prior['cases']['cases'] == 40, 'original query40 did not pass')
        report['query40_result_sha256'] = sha((query / 'RESULT.json').read_bytes())
        report['query40'] = prior['cases']
        classes = output / 'classes'
        cp = str(query / 'classes') + ':' + str(args.json_jar)
        command('compile-results', [args.java_home / 'bin/javac', '--release', '8', '-encoding', 'UTF-8',
                                   '-proc:none', '-cp', cp, '-d', classes, *tests], 60)
        classpath = str(classes) + ':' + cp
        command('lifetime', [args.java_home / 'bin/java', '-cp', classpath,
                            'org.trillionnium.hepta.local.WebFlightResultLifetimeHostTest', output / 'LIFETIME.json'], 30)
        command('composition', [args.java_home / 'bin/java', '-cp', classpath,
                               'org.trillionnium.hepta.local.WebFlightResultCompositionHostTest',
                               args.calendar_dom, args.calendar_ax, output / 'COMPOSITION.json'], 60)
        for name, count in [('lifetime', 31), ('composition', 17)]:
            cases = json.loads((output / (name.upper() + '.json')).read_text())
            need(cases['all_pass'] is True and cases['cases'] == count
                 and cases['actual_results_verified'] is False and cases['phone_actions'] == 0,
                 'result suite count or scope differs: ' + name)
            report[name] = cases
        report['all_pass'] = True
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        report['source_inputs_unchanged'] = all(sha(Path(path).read_bytes()) == digest for path, digest in before.items())
        report['all_pass'] = report['all_pass'] and report['source_inputs_unchanged']
        (output / 'RESULT.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'all_pass': report['all_pass'], 'error': report.get('error'),
                      'result': str(output / 'RESULT.json'), 'result_sha256': sha((output / 'RESULT.json').read_bytes())}))
    return 0 if report['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
