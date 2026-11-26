#!/usr/bin/env python3
"""Actual full Selection producer -> actual full PhoneObservation regression gate."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--java-home', type=Path)
    parser.add_argument('--release8', action='store_true')
    parser.add_argument('--baseline-observation', type=Path,
                        help='Optional exact c7 PhoneObservation: require the real pre-fix exception before candidate tests.')
    args = parser.parse_args()
    source, out = args.source.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    fixture = out/'fixture'
    helper = source/'tests/background-session/prepare_fixture.py'
    spec = importlib.util.spec_from_file_location('observation_display_scope_session_fixture', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    files, extraction = module.prepare(source, fixture)
    # Explicit legacy-only grammar closure; actual typed search has separate gates.
    search_helper = source/'tests/native-app/legacy-boundary/prepare_search_pure.py'
    search_spec = importlib.util.spec_from_file_location('display_scope_search_pure', search_helper)
    search_pure = importlib.util.module_from_spec(search_spec); search_spec.loader.exec_module(search_pure)
    files = search_pure.add(source, files)
    pkg = source/'src/org/trillionnium/hepta/local'
    files += [pkg/(name+'.java') for name in ('NativeXiaomiSearchInputObservation', 'NativeActionSnapshotCheck', 'NativeCtripFormObservation', 'ObservationCaptureEvidence', 'PhoneObservation','PixelNativeCensusEvidence', 'ObservationState', 'ImeVisibility',
                                            'ObservedWindowMetadata', 'ObservedChildText')]
    files += [source/'tests/qualification-scope/fixtures/android/graphics/Rect.java',
              source/'tests/observation-display-scope/ObservationDisplayScopeHostTest.java']
    files = list(dict.fromkeys(files))
    before = {str(path): sha(path.read_bytes()) for path in files + [search_helper]}
    java = str(args.java_home.resolve()/'bin/java') if args.java_home else shutil.which('java')
    javac = str(args.java_home.resolve()/'bin/javac') if args.java_home else shutil.which('javac')
    if not java:
        raise RuntimeError('existing Java runtime required')
    compiler = [javac] if javac else [java, '-m', 'jdk.compiler/com.sun.tools.javac.Main']
    flags = ['--release', '8', '-Xlint:all'] if args.release8 else ['-source', '8', '-target', '8', '-Xlint:all,-options']
    env = dict(os.environ)
    for key in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'CLASSPATH'):
        env.pop(key, None)
    stages = []
    report = {'schema': 'hepta.observation-display-scope.host-validation.v1', 'all_pass': False,
              'status': 'NOT_DEPLOYED', 'source_inputs': before, 'fixture': extraction,
              'actual_full_classes': ['BackgroundSession.Selection', 'BackgroundTaskTarget', 'PhoneObservation',
                                      'ProfileTarget', 'ProfileIdentity', 'WindowOwnership'],
              'boundary': 'Only synthetic JSON/Rect/clock/Android transport IO. No socket, frame capture, phone, root, model, or live authorization.',
              'compiler_contract': 'Java8 API release' if args.release8 else 'supplemental Java8 syntax/class target',
              'android_runtime': False, 'phone_actions': 0, 'stages': stages}
    def save():
        (out/'RESULT.json').write_text(json.dumps(report, indent=2)+'\n')
    def run(name, argv):
        began = time.monotonic()
        completed = subprocess.run(argv, cwd=out, env=env, capture_output=True, timeout=60)
        (out/(name+'.stdout')).write_bytes(completed.stdout)
        (out/(name+'.stderr')).write_bytes(completed.stderr)
        stages.append({'name': name, 'exit_code': completed.returncode, 'elapsed_seconds': time.monotonic()-began,
                       'argv': argv})
        save()
        print(name, completed.returncode)
        return completed
    try:
        if args.baseline_observation:
            raw = args.baseline_observation.read_bytes()
            if sha(raw) != '7fc16f870b9245c6f1499db365463028561b31144a836c618c993e3e590ef290':
                raise RuntimeError('exact reviewed c7 baseline PhoneObservation required')
            legacy = out/'baseline/PhoneObservation.java'
            legacy.parent.mkdir()
            legacy.write_bytes(raw)
            legacy_classes = out/'baseline-classes'
            legacy_classes.mkdir()
            legacy_files = [legacy if path == pkg/'PhoneObservation.java' else path for path in files]
            check = run('baseline-compile', compiler+flags+['-Werror', '-encoding', 'UTF-8', '-d', str(legacy_classes), *map(str, legacy_files)])
            if check.returncode:
                raise RuntimeError('baseline compile failed: '+check.stderr.decode(errors='replace')[-6000:])
            check = run('baseline-actual-regression', [java, '-cp', str(legacy_classes),
                        'org.trillionnium.hepta.local.ObservationDisplayScopeHostTest', str(out/'BASELINE-CASES.json')])
            if check.returncode == 0 or b'exact Selection projection fields required' not in check.stderr:
                raise RuntimeError('expected actual pre-fix Selection/observation failure not reproduced')
            report['baseline_regression_reproduced'] = True
            report['baseline_observation_sha256'] = sha(raw)
        classes = out/'classes'
        classes.mkdir()
        check = run('compile', compiler+flags+['-Werror', '-encoding', 'UTF-8', '-d', str(classes), *map(str, files)])
        if check.returncode:
            raise RuntimeError('candidate compile failed: '+check.stderr.decode(errors='replace')[-6000:])
        check = run('actual-selection-to-observation', [java, '-cp', str(classes),
                    'org.trillionnium.hepta.local.ObservationDisplayScopeHostTest', str(out/'CASES.json')])
        if check.returncode:
            raise RuntimeError('actual boundary cases failed: '+check.stderr.decode(errors='replace')[-6000:])
        cases = json.loads((out/'CASES.json').read_text())
        if cases.get('all_pass') is not True or cases.get('cases', 0) < 40 or cases.get('phone_actions') != 0:
            raise RuntimeError('missing actual boundary cases')
        report['source_inputs_unchanged'] = all(sha(Path(path).read_bytes()) == digest for path, digest in before.items())
        if not report['source_inputs_unchanged']:
            raise RuntimeError('source changed during actual boundary tests')
        report['cases'] = cases
        report['all_pass'] = True
        save()
        print(json.dumps({'all_pass': True, 'cases': cases['cases'], 'assertions': cases['assertions'],
                          'phone_actions': 0, 'status': 'NOT_DEPLOYED'}))
        return 0
    except Exception as error:
        report['error'] = type(error).__name__+': '+str(error)
        save()
        print(report['error'])
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
