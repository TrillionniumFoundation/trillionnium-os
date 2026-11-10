#!/usr/bin/env python3
"""Execute the actual owner policy/controller/service bodies with explicit IO fakes.

All outputs are create-only. This host contract does not establish Android,
model inference, phone effects, or independent task success.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--release8', action='store_true', help='Require the Java 8 API release gate; never fall back')
    args = parser.parse_args()
    source, out = args.source.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    pkg = source / 'src/org/trillionnium/hepta/local'
    test_root = Path(__file__).resolve().parent
    fixture_root = test_root.parent / 'qualification-scope'
    inputs = set(pkg.glob('*.java')) | set(fixture_root.rglob('*.java'))
    inputs |= set(fixture_root.glob('*.py')) | set(fixture_root.glob('*.template')) | set(test_root.glob('*'))
    inputs = sorted(p for p in inputs if p.is_file())
    if any(p.is_symlink() for p in inputs):
        raise RuntimeError('Host inputs must be regular source files')
    before = {str(p.relative_to(source)): sha(p) for p in inputs}
    helper = fixture_root / 'prepare_fixture.py'
    spec = importlib.util.spec_from_file_location('actual_scope_fixture', helper)
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    files, record = fixture.prepare(source, out / 'fixture')
    service = out / 'fixture/HeptaAccessibilityService.java'
    text = service.read_text()
    old = '    private void coordinateClick(String task,PhoneObservation expected,ActionDecision action,ObservedTargetLabels targets,Cancellation cancel,ActionCallback callback,OwnerActionPolicy dispatchOwner){gestures++;callback.onResult(new ActionOutcome(true,true,false,"fake gesture"));}'
    if text.count(old) != 1:
        raise RuntimeError('Coordinate fixture seam is absent or ambiguous')
    production = (pkg / 'HeptaAccessibilityService.java').read_text()
    coordinate = fixture.section(production, '    private void coordinateClick(', '    private static boolean samePatch(')
    service.write_text(text.replace(old, (test_root / 'coordinate_io_fixture.txt').read_text() + coordinate))
    files.append(test_root / 'OwnerActionHostTest.java')
    record['actual_coordinate_callback_sha256'] = hashlib.sha256(coordinate.encode()).hexdigest()
    record['boundary'] = ('Actual full LocalTaskController and OwnerActionPolicy; exact service lease, scope, dispatch and coordinate callback bodies. '
                          'Android observation/effects/model/JSON use explicit synthetic fixtures. The scope suite runs separately.')
    record['source_inputs_sha256'] = before
    (out / 'EXTRACTION.json').write_text(json.dumps(record, indent=2) + '\n')
    classes = out / 'classes'
    classes.mkdir()
    compiler = [shutil.which('javac')] if shutil.which('javac') else ['java', '-m', 'jdk.compiler/com.sun.tools.javac.Main']
    flags = ['--release', '8'] if args.release8 else ['-source', '8', '-target', '8']
    stages = []
    commands = [('compile', compiler + flags + ['-encoding', 'UTF-8', '-Xlint:all,-options', '-Werror', '-d', str(classes)] + list(map(str, files))),
                ('actual-production-boundaries', ['java', '-cp', str(classes), 'org.trillionnium.hepta.local.OwnerActionHostTest', str(out / 'cases')])]
    for name, command in commands:
        started = time.monotonic()
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)
        (out / (name + '.stdout')).write_text(result.stdout)
        (out / (name + '.stderr')).write_text(result.stderr)
        stages.append(dict(name=name, exit_code=result.returncode, elapsed_seconds=time.monotonic() - started))
        if result.returncode:
            (out / 'HOST-RESULT.json').write_text(json.dumps(dict(status='failed', scope='host_only', stages=stages), indent=2) + '\n')
            print(result.stdout[-3000:])
            print(result.stderr[-12000:])
            return result.returncode
    if before != {str(p.relative_to(source)): sha(p) for p in inputs}:
        raise RuntimeError('Source changed during host checks')
    cases = json.loads((out / 'cases/RESULT.json').read_text())
    report = dict(schema='hepta.owner-action-java-host-validation.v1', status='passed', phone_contacted=False,
                  android_runtime=False, native_inference=False, source_unchanged=True, stages=stages, tests=cases,
                  source_inputs_sha256=before, extraction_sha256=sha(out / 'EXTRACTION.json'),
                  compiler_contract='Java 8 API release, syntax and class target' if args.release8 else 'Java 8 syntax and class target; Java 8 API release gate not claimed')
    (out / 'HOST-RESULT.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(status=report['status'], passed=cases['passed'], compiler_contract=report['compiler_contract'], phone_contacted=False)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
