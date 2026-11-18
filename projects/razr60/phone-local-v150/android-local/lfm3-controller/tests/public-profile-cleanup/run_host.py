#!/usr/bin/env python3
"""Compile the full production consumer; preserve the unchanged private suite."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def digest(path):
    raw = path.read_bytes()
    return {'path': str(path.resolve()), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--java-home', type=Path, required=True)
    p.add_argument('--json-jar', type=Path, required=True)
    p.add_argument('--actual-originals', type=Path)
    p.add_argument('--baseline-source', type=Path)
    p.add_argument('--java8-syntax-only', action='store_true', help='Local draft only; never Java 8 API qualification.')
    a = p.parse_args()
    source, out = a.source.resolve(), a.output.resolve()
    java = a.java_home.resolve() / 'bin/java'
    javac = a.java_home.resolve() / 'bin/javac'
    jar = a.json_jar.resolve()
    if digest(jar)['sha256'] != '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed':
        raise RuntimeError('fixed JSON dependency differs')
    if a.baseline_source and not a.actual_originals:
        raise RuntimeError('baseline reproduction requires the actual archived originals')
    out.mkdir(parents=True, exist_ok=False)
    snapshots, stages = {}, []
    for path in source.rglob('*'):
        if path.is_file():
            snapshots[str(path)] = digest(path)
    actual_pins = {}
    if a.actual_originals:
        for name in ('background-bootstrap.json', 'background-cleanup.json', 'result.json'):
            path = a.actual_originals.resolve() / name
            actual_pins[name] = digest(path)

    def run(name, argv, timeout=180):
        started = time.monotonic()
        process = subprocess.run([str(v) for v in argv], cwd=out, capture_output=True, timeout=timeout)
        stdout, stderr = out / (name + '.stdout'), out / (name + '.stderr')
        stdout.write_bytes(process.stdout)
        stderr.write_bytes(process.stderr)
        stages.append({'name': name, 'argv': [str(v) for v in argv], 'exit_code': process.returncode,
                       'elapsed_seconds': time.monotonic() - started,
                       'stdout': digest(stdout), 'stderr': digest(stderr)})
        if process.returncode:
            (out / 'RESULT.json').write_text(json.dumps({'all_pass': False, 'stages': stages,
                'source_inputs': snapshots, 'actual_originals': actual_pins, 'phone_actions': 0}, indent=2) + '\n')
            sys.stderr.buffer.write(process.stderr)
            raise RuntimeError(name + ' failed with exit ' + str(process.returncode))

    def compile_source(root, label):
        helper = root / 'tests/background-session/prepare_fixture.py'
        spec = importlib.util.spec_from_file_location('public_cleanup_' + label, helper)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        fixture = out / (label + '-fixture')
        files, extraction = module.prepare(root, fixture)
        # App UID and matching host-file UID are explicit Android IO ports. The
        # production public-scope constructor still enforces the real App range.
        process_java = fixture / 'android/os/Process.java'
        process_java.write_text('package android.os;public final class Process {public static int myUid(){return 10481;}public static int myPid(){return 123;}}\n')
        os_java = fixture / 'android/system/Os.java'
        raw = os_java.read_text()
        seam = 'r.st_uid=((Number)a.get("uid")).intValue();'
        if raw.count(seam) != 1:
            raise RuntimeError('nonunique explicit host UID IO seam')
        os_java.write_text(raw.replace(seam, seam + 'if(r.st_uid==' + str(os.getuid()) + ')r.st_uid=10481;'))
        extraction['public_cleanup_uid_io_fixture'] = {'app_uid': 10481,
            'host_uid_mapping_is_android_qualification': False,
            'process': digest(process_java), 'private_file_io': digest(os_java)}
        # Only JSON IO and Android/process IO are seams; all consumer code is the
        # full production class. Legacy tests retain their own unchanged JSON IO.
        files = [f for f in files if not (fixture / 'org/json') in f.parents]
        files.append(source / 'tests/public-profile-cleanup/PublicProfileCleanupHostTest.java')
        files = list(dict.fromkeys(files))
        inputs = {str(f.resolve()): digest(f) for f in files}
        classes = out / (label + '-classes')
        classes.mkdir()
        flags = ['-source', '8', '-target', '8'] if a.java8_syntax_only else ['--release', '8']
        run(label + '-compile', [javac, *flags, '-encoding', 'UTF-8', '-proc:none', '-Xlint:all,-options',
                                 '-Werror', '-cp', jar, '-d', classes, *files])
        if inputs != {str(f.resolve()): digest(f) for f in files}:
            raise RuntimeError('compile source bytes changed')
        return classes, inputs, extraction

    classes, inputs, extraction = compile_source(source, 'candidate')
    actual_arg = str(a.actual_originals.resolve()) if a.actual_originals else '-'
    run('candidate-tests', [java, '-cp', str(classes) + ':' + str(jar),
                           'org.trillionnium.hepta.local.PublicProfileCleanupHostTest', out / 'CASES.json', actual_arg])
    legacy_report = None
    if not a.java8_syntax_only:
        run('unchanged-private', [sys.executable, '-B', source / 'tests/background-session/run_profile_host.py',
            '--source', source, '--output', out / 'unchanged-private', '--java-home', a.java_home.resolve()])
        legacy_report = json.loads((out / 'unchanged-private/RESULT.json').read_text())
        if legacy_report.get('all_pass') is not True:
            raise RuntimeError('unchanged private gate failed')
    baseline = None
    if a.baseline_source:
        baseline_classes, baseline_inputs, baseline_extraction = compile_source(a.baseline_source.resolve(), 'baseline')
        run('baseline-reproduction', [java, '-cp', str(baseline_classes) + ':' + str(jar),
            'org.trillionnium.hepta.local.PublicProfileCleanupHostTest', out / 'BASELINE-CASES.json', actual_arg, 'legacy'])
        baseline = {'result': json.loads((out / 'BASELINE-CASES.json').read_text()), 'source_inputs': baseline_inputs,
                    'extraction': baseline_extraction}
    current = {str(p): digest(p) for p in source.rglob('*') if p.is_file()}
    if snapshots != current:
        raise RuntimeError('source files changed during validation')
    if actual_pins != {name: digest(Path(ref['path'])) for name, ref in actual_pins.items()}:
        raise RuntimeError('archived originals changed')
    cases = json.loads((out / 'CASES.json').read_text())
    result = {'schema': 'hepta.public-profile-cleanup-host-validation.v1', 'all_pass': True,
              'java8_api_checked': not a.java8_syntax_only, 'java8_syntax_only': a.java8_syntax_only,
              'cases': cases, 'stages': stages, 'source_inputs': inputs, 'source_inputs_unchanged': True,
              'json_dependency': digest(jar), 'actual_originals': actual_pins, 'actual_originals_unchanged': True,
              'unchanged_private_gate': legacy_report, 'baseline_reproduction': baseline, 'extraction': extraction,
              'android_runtime': False, 'root_process_started': False, 'phone_actions': 0,
              'actual_device_cleanup_granted_by_this_test': False}
    (out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'all_pass': True, 'cases': cases['cases'], 'assertions': cases['assertions'],
                      'java8_api_checked': not a.java8_syntax_only,
                      'actual_archived_broker_projection_replayed': bool(a.actual_originals),
                      'unchanged_private_gate_pass': legacy_report is not None, 'phone_actions': 0}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
