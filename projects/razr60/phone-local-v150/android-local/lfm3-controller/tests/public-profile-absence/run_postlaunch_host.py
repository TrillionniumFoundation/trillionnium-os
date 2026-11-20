#!/usr/bin/env python3
"""Actual postlaunch policy/client and unchanged legacy regressions; no phone.

Android/PM/clock/owned Process boundaries remain explicit synthetic fixtures.
Only archived original bytes are accepted as fixture inputs.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    for name in ('source', 'java-home', 'json-jar', 'output', 'actual-originals', 'postlaunch-originals'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--java8-syntax-only', action='store_true')
    args = parser.parse_args()
    source, out = args.source.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    test = source / 'tests/public-profile-absence'
    source_before = {str(p.relative_to(source)): sha(p) for p in source.rglob('*') if p.is_file()}
    cmd = [os.sys.executable, '-B', str(test / 'run_host.py'), '--source', str(source), '--java-home', str(args.java_home),
           '--json-jar', str(args.json_jar), '--output', str(out / 'legacy'), '--actual-originals', str(args.actual_originals)]
    if args.java8_syntax_only:
        cmd.append('--java8-syntax-only')
    began_wall = time.time(); began = time.monotonic()
    run = subprocess.run(cmd, capture_output=True, timeout=180)
    (out / 'legacy.stdout').write_bytes(run.stdout); (out / 'legacy.stderr').write_bytes(run.stderr)
    result = {'schema': 'hepta.public-postlaunch-host-validation.v1', 'all_pass': False,
              'strict_release8': not args.java8_syntax_only, 'phone_contacted': False,
              'android_framework_clock_installation_and_owned_process_synthetic': True,
              'legacy_exit': run.returncode, 'legacy_result_sha256': sha(out / 'legacy/RESULT.json'), 'stages': []}
    legacy = json.loads((out / 'legacy/RESULT.json').read_bytes())
    manifest = source / 'SOURCE-MANIFEST.json'
    def ref(path):
        return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': sha(path)}
    invocation = {'schema': 'hepta.public-recovery-extra-gate-invocation.244ec.v1',
                  'name': 'public-profile-absence', 'argv': cmd, 'exit_code': run.returncode,
                  'source_root': str(source), 'source_manifest_sha256': sha(manifest),
                  'production_input_map_sha256': json.loads(manifest.read_bytes())['production_input_map_sha256'],
                  'started_unix': began_wall, 'elapsed_seconds': time.monotonic() - began,
                  'source_unchanged': source_before == {str(p.relative_to(source)): sha(p) for p in source.rglob('*') if p.is_file()},
                  'phone_operations': 0, 'result': ref(out / 'legacy/RESULT.json'),
                  'stdout': ref(out / 'legacy.stdout'), 'stderr': ref(out / 'legacy.stderr')}
    (out / 'LEGACY-INVOCATION.json').write_text(json.dumps(invocation, indent=2) + '\n')
    result['legacy_invocation'] = ref(out / 'LEGACY-INVOCATION.json')
    if run.returncode or legacy.get('all_pass') is not True:
        (out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
        print(run.stderr.decode()); print(run.stdout.decode()); return 1
    classes = out / 'post-classes'
    shutil.copytree(out / 'legacy/client-classes', classes)
    fixtures = out / 'post-fixture'; fixtures.mkdir()
    fake = (test / 'FakePublicRecoveryProcess.java').read_text()
    fake = fake.replace('import org.trillionnium.hepta.background.PublicProfileAbsenceHostTest;',
                        'import org.trillionnium.hepta.background.PublicProfilePostlaunchAbsenceHostTest;')
    fake = fake.replace('PublicProfileAbsenceHostTest.proof(r)', 'PublicProfilePostlaunchAbsenceHostTest.proof(r)')
    fake = fake.replace('PublicProfileAbsenceRecovery.SCHEMA', 'r.proofSchema()')
    (fixtures / 'FakePublicRecoveryProcess.java').write_text(fake)
    idle = (out / 'legacy/fixture/org/trillionnium/hepta/local/PublicRecoveryIdleFixture.java').read_text()
    idle = idle.replace('PublicRecoveryIdleFixture', 'PublicPostlaunchRecoveryIdleFixture')
    idle = idle.replace('9579cd438a7f46b598c2c21b714f02b3', '36c0bbe7910a4b72a728adbe72141419')
    (fixtures / 'PublicPostlaunchRecoveryIdleFixture.java').write_text(idle)
    files = [test / 'PublicProfilePostlaunchAbsenceHostTest.java', test / 'PublicProfilePostlaunchRecoveryClientHostTest.java',
             fixtures / 'FakePublicRecoveryProcess.java', fixtures / 'PublicPostlaunchRecoveryIdleFixture.java']
    production = [source / 'src/org/trillionnium/hepta' / name for name in (
        'background/PublicProfileAbsenceRecovery.java', 'background/PublicProfileRecoveryMain.java',
        'local/PublicProfileRecoveryClient.java', 'local/BackgroundSession.java')]
    inputs = {str(p): sha(p) for p in files + production}
    original_inputs = {p.name: sha(p) for p in args.postlaunch_originals.iterdir()
                       if p.name in ('journal.bin', 'owner.bin', 'bootstrap.bin', 'cleanup.bin', 'result.bin',
                                     'broker_receipt.bin', 'broker_output.bin', 'ORIGINALS.json',
                                     'before-recents.stdout', 'after-recents.stdout')}
    result.update(source_inputs=inputs, actual_archived_postlaunch_inputs=original_inputs)
    jdk = args.java_home.resolve() / 'bin'
    flags = ['-source', '8', '-target', '8'] if args.java8_syntax_only else ['--release', '8']
    cp = str(classes) + os.pathsep + str(args.json_jar.resolve())
    commands = [('post-compile', [str(jdk / 'javac'), *flags, '-Xlint:all,-options', '-Werror', '-encoding', 'UTF-8',
                                 '-proc:none', '-cp', cp, '-d', str(classes), *map(str, files)]),
                ('post-policy', [str(jdk / 'java'), '-cp', cp, 'org.trillionnium.hepta.background.PublicProfilePostlaunchAbsenceHostTest', str(args.postlaunch_originals.resolve())]),
                ('post-client', [str(jdk / 'java'), '-cp', cp, 'org.trillionnium.hepta.local.PublicProfilePostlaunchRecoveryClientHostTest', str(args.postlaunch_originals.resolve())])]
    for name, argv in commands:
        started = time.monotonic(); run = subprocess.run(argv, capture_output=True, timeout=90)
        (out / (name + '.stdout')).write_bytes(run.stdout); (out / (name + '.stderr')).write_bytes(run.stderr)
        result['stages'].append({'name': name, 'exit_code': run.returncode, 'elapsed_s': time.monotonic() - started,
                                 'stdout_sha256': sha(out / (name + '.stdout')), 'stderr_sha256': sha(out / (name + '.stderr'))})
        if run.returncode:
            print(run.stderr.decode()); print(run.stdout.decode()); break
        if name != 'post-compile':
            result[name] = json.loads(run.stdout)
    result['all_pass'] = len(result['stages']) == len(commands) and all(x['exit_code'] == 0 for x in result['stages'])
    result['inputs_unchanged'] = inputs == {str(p): sha(p) for p in files + production}
    result['originals_unchanged'] = original_inputs == {name: sha(args.postlaunch_originals / name) for name in original_inputs}
    result['complete_source_unchanged'] = source_before == {str(p.relative_to(source)): sha(p) for p in source.rglob('*') if p.is_file()}
    result['all_pass'] &= result['inputs_unchanged'] and result['originals_unchanged'] and result['complete_source_unchanged'] and invocation['source_unchanged']
    (out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'all_pass': result['all_pass'], 'result': str(out / 'RESULT.json'), 'strict_release8': result['strict_release8'], 'stages': result['stages']}))
    return 0 if result['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
