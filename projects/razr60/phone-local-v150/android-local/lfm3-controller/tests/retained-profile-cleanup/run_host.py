#!/usr/bin/env python3
"""Real cleanup coordinator/protocol/history with fixed archived recents; no Android or phone."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'output', 'java-home', 'json-jar', 'actual-recents'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    jar = args.json_jar.resolve()
    assert sha(jar) == '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
    actual = args.actual_recents.resolve()
    actual_pins = {'before-recents.txt': 'bb1335844af98cf8a2a435ab8b10a6bf9930ccd96bc162bff38150c9a7d1ee6a',
                   'after-recents.txt': '5755f3c99126d9f093272b7b73cce47a74049d5398110a1c8d97465e1952c4f3'}
    assert {n: sha(actual / n) for n in actual_pins} == actual_pins
    names = ['ProfileIdentity', 'ProfileTarget', 'WindowOwnership', 'BrokerProtocol', 'PublicPermissionControllerUi',
             'PublicOwnGroupPolicy', 'FixedIntentTools', 'BackgroundOwnedTaskPolicy', 'BackgroundOwnedSingleTask',
             'ProfileTaskPolicy', 'ProfileOwnedTask', 'ProfilePermissionTransient', 'ProfileDisplayCustody',
             'PublicOwnGroupPhysicalFence', 'PublicProfileRecentHistory', 'RetainedProfileCleanupAttempt']
    files = [source / 'src/org/trillionnium/hepta/background' / (name + '.java') for name in names]
    files += [source / 'tests/profile-broker/ProfileBrokerHostTest.java',
              source / 'tests/public-profile-history/PublicProfileHistoryHostTest.java',
              source / 'tests/retained-profile-cleanup/RetainedProfileCleanupHostTest.java']
    tracked = files + [Path(__file__).resolve()]
    pins = {str(path): sha(path) for path in tracked}
    classes = output / 'classes'
    classes.mkdir()
    jdk = args.java_home.resolve() / 'bin'
    classpath = str(classes) + os.pathsep + str(jar)
    commands = [('compile', [str(jdk / 'javac'), '--release', '8', '-Xlint:all', '-Werror', '-proc:none',
                             '-encoding', 'UTF-8', '-cp', str(jar), '-d', str(classes), *map(str, files)]),
                ('cleanup', [str(jdk / 'java'), '-cp', classpath, 'org.trillionnium.hepta.background.RetainedProfileCleanupHostTest', str(actual)]),
                ('original-private', [str(jdk / 'java'), '-cp', classpath, 'org.trillionnium.hepta.background.ProfileBrokerHostTest']),
                ('original-public-history', [str(jdk / 'java'), '-cp', classpath, 'org.trillionnium.hepta.background.PublicProfileHistoryHostTest', str(actual)])]
    result = {'all_pass': False, 'strict_release8': True, 'source_inputs': pins, 'json_jar_sha256': sha(jar),
              'actual_recents': actual_pins, 'android_runtime': False, 'phone_operations': 0,
              'framework_and_effect_ports_synthetic': True, 'stages': []}
    env = dict(os.environ)
    for name in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'CLASSPATH'):
        env.pop(name, None)
    for name, argv in commands:
        started = time.monotonic()
        run = subprocess.run(argv, capture_output=True, timeout=60, env=env)
        (output / (name + '.stdout')).write_bytes(run.stdout)
        (output / (name + '.stderr')).write_bytes(run.stderr)
        result['stages'].append({'name': name, 'argv': argv, 'exit_code': run.returncode,
                                 'elapsed_seconds': time.monotonic() - started,
                                 'stdout_sha256': hashlib.sha256(run.stdout).hexdigest(),
                                 'stderr_sha256': hashlib.sha256(run.stderr).hexdigest()})
        if run.returncode:
            break
        if name != 'compile':
            result[name] = json.loads(run.stdout.decode().splitlines()[0])
    result['inputs_unchanged'] = pins == {str(path): sha(path) for path in tracked}
    result['actual_recents_unchanged'] = actual_pins == {n: sha(actual / n) for n in actual_pins}
    result['all_pass'] = len(result['stages']) == len(commands) and all(stage['exit_code'] == 0 for stage in result['stages']) and result['inputs_unchanged'] and result['actual_recents_unchanged']
    (output / 'RESULT.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'all_pass': result['all_pass'], 'result': str(output / 'RESULT.json'),
                      'cleanup': result.get('cleanup'), 'stages': [(s['name'], s['exit_code']) for s in result['stages']]}))
    return 0 if result['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
