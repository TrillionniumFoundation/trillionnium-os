#!/usr/bin/env python3
"""Replay one actual failed shopping bracket and bounded synthetic retry sequences.

The original v59 failure is compiled separately. Real current observe/retry bodies
are compiled without semantic edits; host service/clock/IPC/publisher are explicit
instrumentation and confer no device or business acceptance.
"""
import argparse
import ast
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import time


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'json-jar', 'java-home'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    test = Path(__file__).resolve().parent
    root = test.parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = root / 'src/org/trillionnium/hepta/local/WebFlightSession.java'
    legacy = test / 'reference-v59/WebFlightSession.java.reference'
    need(sha(legacy.read_bytes()) == 'd413bd893e3ca01404b1e76a1a188b7c741f3d6699c8d8e97655dcd9590e6a4d',
         'exact c6a1d9 v59 Session reference changed')
    jar = args.json_jar.resolve()
    need(sha(jar.read_bytes()) == '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed',
         'host JSON dependency differs')
    original_fixture = test / 'fixtures/actual-shopping-v57-r1'
    provenance = json.loads((original_fixture / 'PROVENANCE.json').read_text())
    fixture = output / 'originals'
    fixture.mkdir()
    for row in provenance['files']:
        compressed = (original_fixture / row['fixture_file']).read_bytes()
        need(len(compressed) == row['gzip_bytes'] and sha(compressed) == row['gzip_sha256'], 'compressed original differs')
        raw = gzip.decompress(compressed)
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'original retained bytes differ')
        (fixture / row['name']).write_bytes(raw)
    (fixture / 'PROVENANCE.json').write_bytes((original_fixture / 'PROVENANCE.json').read_bytes())
    spec = importlib.util.spec_from_file_location('method_extractor', root / 'tests/action-worker/run_host_tests.py')
    extractor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(extractor)
    parsed = ast.parse((root / 'tests/web-flight/run_query_host_tests.py').read_text())
    paths = next(ast.literal_eval(n.value) for n in parsed.body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == 'PURE_PATHS' for t in n.targets))
    inputs = [root / p for p in paths if p != 'tests/web-flight/WebFlightQueryHostTest.java']
    signatures = ['PhoneObservation observe(PhoneObservation initial,Observer observer,long deadline)',
                  'private boolean retryLoadingDocument(WebEvidenceReceipt first,WebEvidenceReceipt last,PhoneObservation frame,',
                  'private static boolean sameFrame(PhoneObservation a,PhoneObservation b)']
    template = test / 'ShoppingObservationRetryHost.template'
    report = {'schema': 'hepta.shopping-retry-host-run.v1', 'all_pass': False,
              'source_sha256': sha(source.read_bytes()), 'reference_v59_sha256': sha(legacy.read_bytes()),
              'template_sha256': sha(template.read_bytes()), 'originals': provenance,
              'source_inputs': [{'path': str(p), 'sha256': sha(p.read_bytes())} for p in inputs],
              'phone_actions': 0, 'actual_authenticated_ipc_or_native_authority_proven': False,
              'future_stable_sequences_synthetic': True, 'stages': []}

    def command(name, argv):
        start = time.monotonic()
        run = subprocess.run(list(map(str, argv)), cwd=root, stdin=subprocess.DEVNULL,
                             capture_output=True, timeout=60)
        (output / (name + '.stdout')).write_bytes(run.stdout)
        (output / (name + '.stderr')).write_bytes(run.stderr)
        report['stages'].append({'name': name, 'argv': list(map(str, argv)), 'exit_code': run.returncode,
                                'elapsed_s': time.monotonic() - start,
                                'stdout_sha256': sha(run.stdout), 'stderr_sha256': sha(run.stderr)})
        need(run.returncode == 0, 'host command failed: ' + name)

    try:
        for name, original in [('legacy', legacy), ('current', source)]:
            selected = signatures + ([] if name == 'legacy' else ['private static String loadingKey(WebEvidenceReceipt receipt)'])
            methods = [extractor.body(original.read_text(), sig) for sig in selected]
            destination = output / name
            destination.mkdir()
            java = destination / 'ShoppingObservationRetryHost.java'
            java.write_text(template.read_text().replace('/* EXACT_PRODUCTION_METHODS */', '\n\n'.join(methods)))
            (destination / 'METHODS.json').write_text(json.dumps([
                {'signature': sig, 'bytes': len(body.encode()), 'sha256': sha(body.encode())}
                for sig, body in zip(selected, methods)], indent=2) + '\n')
            classes = destination / 'classes'
            command(name + '-compile', [args.java_home / 'bin/javac', '--release', '8', '-encoding', 'UTF-8',
                                       '-proc:none', '-cp', jar, '-d', classes, *inputs, java])
            command(name + '-run', [args.java_home / 'bin/java', '-cp', str(classes) + ':' + str(jar),
                                   'org.trillionnium.hepta.local.ShoppingObservationRetryHost', fixture,
                                   destination / 'CASES.json', name])
            report[name] = json.loads((destination / 'CASES.json').read_text())
        report['all_pass'] = report['legacy']['all_pass'] and report['current']['all_pass']
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        (output / 'RESULT.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'all_pass': report['all_pass'], 'error': report.get('error'),
                      'legacy_cases': report.get('legacy', {}).get('cases'),
                      'current_cases': report.get('current', {}).get('cases'), 'result': str(output / 'RESULT.json')}))
    return 0 if report['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
