#!/usr/bin/env python3
"""Exercise real runtime custody and receipt readers; Android IO is synthetic.

No device, model, network or task operations are performed. This gate preserves
the separate strict accident-recovery and physical-isolation host gates.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time

JSON_SHA = '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
CONTRACTS = {
    'custody': (23, 44, '1634b5644fbb6accc3c4e9dce37d6c10203fa9954d0b0cbe26079c256c1fcdc6'),
    'receipts': (25, 30, 'c503a5913d9899568542aa784d996a8822fc25302eee3b962d6d5730477fbe8b'),
    'recovery_entry': (6, 8, '02d4d12aead56f784df256a64a920dce313d364ee0edcf71e54aeb6023384fa0'),
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    return {'path': str(path.resolve()), 'bytes': path.stat().st_size, 'sha256': sha(path)}


def case_summary(raw, name):
    lines = raw.decode('utf-8').splitlines()
    summaries = [line for line in lines if line.startswith('{')]
    if len(summaries) != 1:
        raise RuntimeError('One complete case summary required: ' + name)
    summary = json.loads(summaries[0])
    names = [line[5:] for line in lines if line.startswith('PASS ')]
    names_sha = hashlib.sha256(json.dumps(names, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
    count, assertions, expected_names = CONTRACTS[name]
    if (summary.get('passed') is not True or type(summary.get('cases')) is not int
            or summary['cases'] != count or type(summary.get('assertions')) is not int
            or summary['assertions'] != assertions or type(summary.get('phone_operations')) is not int
            or summary['phone_operations'] != 0 or len(names) != count or len(set(names)) != count
            or names_sha != expected_names):
        raise RuntimeError('Original concurrency case contract differs: ' + name)
    summary.update(case_names=names, case_names_sha256=names_sha)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'output', 'java-home', 'json-jar'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    if sha(args.json_jar) != JSON_SHA:
        raise RuntimeError('Existing pinned org.json dependency differs')
    spec = importlib.util.spec_from_file_location('concurrency_android_io', source / 'tests/background-session/prepare_fixture.py')
    fixture_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture_module)
    fixture = out / 'android-io-fixture'
    files, projection = fixture_module.prepare(source, fixture)
    (fixture / 'android/os/Process.java').write_text(
        'package android.os;public final class Process {public static int myUid(){return 10481;}public static int myPid(){return 123;}}\n')
    io = fixture / 'android/system/Os.java'
    body = io.read_text()
    seam = 'r.st_uid=((Number)a.get("uid")).intValue();'
    if body.count(seam) != 1:
        raise RuntimeError('Nonunique existing Android UID IO seam')
    io.write_text(body.replace(seam, seam + 'if(r.st_uid==' + str(os.getuid()) + ')r.st_uid=10481;'))
    files = [path for path in files if not (fixture / 'org/json') in path.parents]
    files.append(source / 'src/org/trillionnium/hepta/background/PublicPersonalNotesCustody.java')
    files.extend(source / name for name in (
        'tests/profile-broker/ProfileBrokerHostTest.java',
        'tests/public-own-group-policy/PublicPhysicalAuditHostTest.java',
        'tests/public-own-group-policy/PersonalNotesCustodyHostTest.java',
        'tests/public-own-group-policy/PersonalNotesSessionHostTest.java',
        'tests/public-profile-cleanup/PublicProfileCleanupHostTest.java',
        'tests/personal-notes-absence/PersonalNotesAbsenceHostTest.java',
        'tests/public-profile-history/ForegroundConcurrencyHostTest.java',
        'tests/public-profile-history/ForegroundConcurrencySessionHostTest.java',
        'tests/public-profile-history/ForegroundConcurrencyRecoveryHostTest.java'))
    files = list(dict.fromkeys(path.resolve() for path in files))
    tracked = files + [Path(__file__).resolve(), source / 'tests/background-session/prepare_fixture.py']
    inputs = {str(path): ref(path) for path in tracked}
    classes = out / 'classes'
    classes.mkdir()
    jdk = args.java_home.resolve() / 'bin'
    cp = str(classes) + os.pathsep + str(args.json_jar.resolve())
    commands = [('compile', [str(jdk / 'javac'), '--release', '8', '-encoding', 'UTF-8', '-proc:none',
        '-Xlint:all,-options', '-Werror', '-cp', str(args.json_jar.resolve()), '-d', str(classes), *map(str, files)])]
    for name, cls, extra in (
        ('custody', 'background.ForegroundConcurrencyHostTest', [str(out / 'actual-producer-samples')]),
        ('receipts', 'local.ForegroundConcurrencySessionHostTest', []),
        ('recovery_entry', 'background.ForegroundConcurrencyRecoveryHostTest', [])):
        commands.append((name, [str(jdk / 'java'), '-cp', cp, 'org.trillionnium.hepta.' + cls, *extra]))
    report = {'schema': 'hepta.foreground-concurrency-host.v1', 'all_pass': False,
        'strict_release8': True, 'phone_operations': 0, 'android_runtime': False,
        'framework_and_user_activity_synthetic': True, 'actual_production_custody_and_receipt_readers': True,
        'native_model_executed': False, 'source_inputs': inputs, 'android_io_projection': projection,
        'json_jar': ref(args.json_jar), 'cases': {}, 'stages': []}
    try:
        for name, argv in commands:
            started = time.monotonic()
            run = subprocess.run(argv, capture_output=True, stdin=subprocess.DEVNULL, timeout=120)
            stdout, stderr = out / (name + '.stdout'), out / (name + '.stderr')
            stdout.write_bytes(run.stdout)
            stderr.write_bytes(run.stderr)
            report['stages'].append({'name': name, 'argv': argv, 'exit_code': run.returncode,
                'elapsed_seconds': time.monotonic() - started, 'stdout': ref(stdout), 'stderr': ref(stderr)})
            if run.returncode:
                raise RuntimeError(name + ' failed; raw stdout and stderr retained')
            if name != 'compile':
                report['cases'][name] = case_summary(run.stdout, name)
        report['source_inputs_unchanged'] = inputs == {str(path): ref(path) for path in tracked}
        report['json_jar_unchanged'] = sha(args.json_jar) == JSON_SHA
        if not report['source_inputs_unchanged'] or not report['json_jar_unchanged']:
            raise RuntimeError('Concurrency host input changed')
        report['all_pass'] = True
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    (out / 'RESULT.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'all_pass': report['all_pass'], 'result': ref(out / 'RESULT.json'),
        'cases': report['cases'], 'phone_operations': 0, 'error': report.get('error')}, ensure_ascii=False))
    return 0 if report['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
