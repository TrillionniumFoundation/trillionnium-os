#!/usr/bin/env python3
"""Actual immutable/profile wire and existing v1 protocol tests; no Android or phone IO."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[2])
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--java-home', type=Path, required=True)
    a = p.parse_args()
    source, out = a.source.resolve(), a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    classes = out / 'classes'
    classes.mkdir()
    pkg = source / 'src/org/trillionnium/hepta/background'
    files = [pkg / (name + '.java') for name in (
        'ProfileIdentity', 'ProfileTarget', 'WindowOwnership', 'BrokerProtocol', 'FixedIntentTools')]
    files += [Path(__file__).with_name('ProfileIdentityHostTest.java'),
              source / 'tests/background-broker/BrokerProtocolHostTest.java']
    pins = {str(x.relative_to(source)): hashlib.sha256(x.read_bytes()).hexdigest() for x in files}
    commands = [
        ('compile', [a.java_home / 'bin/javac', '--release', '8', '-encoding', 'UTF-8', '-proc:none',
                     '-Xlint:all,-options', '-Werror', '-d', classes, *files]),
        ('profile-identity', [a.java_home / 'bin/java', '-cp', classes,
                              'org.trillionnium.hepta.background.ProfileIdentityHostTest', out / 'CASES.json']),
        ('legacy-protocol', [a.java_home / 'bin/java', '-cp', classes,
                             'org.trillionnium.hepta.background.BrokerProtocolHostTest'])]
    stages = []
    for name, argv in commands:
        started = time.monotonic()
        r = subprocess.run([str(v) for v in argv], cwd=out, capture_output=True, timeout=90)
        (out / (name + '.stdout')).write_bytes(r.stdout)
        (out / (name + '.stderr')).write_bytes(r.stderr)
        stages.append({'name': name, 'exit_code': r.returncode, 'elapsed_seconds': time.monotonic() - started})
        if r.returncode:
            result = {'all_pass': False, 'stages': stages, 'source_inputs': pins}
            (out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
            print(r.stderr.decode('utf-8', errors='replace')[-10000:])
            return r.returncode
    assert pins == {str(x.relative_to(source)): hashlib.sha256(x.read_bytes()).hexdigest() for x in files}
    result = {'schema': 'hepta.profile-identity-host-validation.v1', 'all_pass': True,
              'cases': json.loads((out / 'CASES.json').read_text()), 'stages': stages,
              'source_inputs': pins, 'source_inputs_unchanged': True, 'phone_actions': 0,
              'android_runtime': False, 'live_broker_or_window_authority_proved': False}
    (out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'all_pass': True, 'cases': result['cases']['cases'],
                      'assertions': result['cases']['assertions']}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
