#!/usr/bin/env python3
"""Compile the real pure-Java ownership policy against synthetic framework fixtures.

No Android subprocess, device connection, package install or test-app launch occurs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source', type=Path, required=True, help='Directory containing background Java sources')
    p.add_argument('--java-home', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    test = Path(__file__).with_name('ProfileBrokerHostTest.java')
    names = ['ProfileIdentity', 'ProfileTarget', 'WindowOwnership', 'BrokerProtocol', 'PublicOwnGroupPolicy', 'FixedIntentTools',
             'BackgroundOwnedTaskPolicy', 'BackgroundOwnedSingleTask', 'ProfileTaskPolicy',
             'ProfileOwnedTask','ProfilePermissionTransient', 'ProfileDisplayCustody']
    inputs = [a.source / (n + '.java') for n in names] + [test]
    pins = {x.name: digest(x) for x in inputs}
    classes = a.output / 'classes'
    command = [str(a.java_home / 'bin/javac'), '-encoding', 'UTF-8', '-source', '8', '-target', '8',
               '-d', str(classes)] + [str(x) for x in inputs]
    compile_result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    (a.output / 'compile.stdout').write_text(compile_result.stdout)
    (a.output / 'compile.stderr').write_text(compile_result.stderr)
    result = {'schema': 'hepta.profile-broker-host-run.v1', 'source_sha256': pins,
              'runner_sha256': digest(Path(__file__)), 'compile_exit': compile_result.returncode,
              'phone_contacted': False, 'framework_fixtures_synthetic': True,
              'run_exit': None, 'summary': None}
    if compile_result.returncode == 0:
        run = subprocess.run([str(a.java_home / 'bin/java'), '-cp', str(classes),
                              'org.trillionnium.hepta.background.ProfileBrokerHostTest'],
                             capture_output=True, text=True, timeout=30)
        (a.output / 'run.stdout').write_text(run.stdout)
        (a.output / 'run.stderr').write_text(run.stderr)
        result['run_exit'] = run.returncode
        if run.returncode == 0:
            result['summary'] = json.loads(run.stdout.splitlines()[0])
    result['inputs_unchanged'] = all(digest(x) == pins[x.name] for x in inputs)
    result['passed'] = (result['compile_exit'] == 0 and result['run_exit'] == 0
                        and result['inputs_unchanged'] and result['summary']['passed'])
    (a.output / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
