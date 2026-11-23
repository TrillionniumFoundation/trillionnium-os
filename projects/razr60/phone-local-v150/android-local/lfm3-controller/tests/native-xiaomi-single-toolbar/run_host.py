#!/usr/bin/env python3
"""Actual provider regression plus isolated new single-toolbar cases; no phone."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

JSON_SHA256 = '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
PROVIDER_RUNNER_SHA256 = '72cfa0936e14eca98c2e15db4caa9bf255d0d98f201c91348e380755e68e09e0'
BASELINE_RESULT_SHA256 = '252dc8c0e9e91f655200a89504caeb8456bd41cdec3352f154e9c92c80d54dd2'
ORIGINALS = {
    'owner': (9323, 'b517dba7b04680d8934f185c9f7a5466d24837bace01114b2ef8df09eeed6c09'),
    'frame': (100079, 'be47773986e53bd1f63cc676305cc6c123de43faca90cf39a5a1d3774275091f'),
    'native_ax': (234378, '100c6206ec8d06345a0daa0f0e7b25bfdb1090540f39a0c1811c383058fdbccf'),
}


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def ref(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'regular source or output required')
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_mode)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode), 'file changed while reading')
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw), 'mode': after.st_mode & 0o777}


def inventory(source):
    result = {}
    for p in sorted(source.rglob('*')):
        require(not p.is_symlink(), 'source symlink refused')
        if p.is_file() and '__pycache__' not in p.parts:
            record = ref(p)
            result[str(p.relative_to(source))] = {k: record[k] for k in ('bytes', 'sha256', 'mode')}
    return result


def write(path, value):
    raw = value if isinstance(value, bytes) else (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()
    with path.open('xb') as stream:
        stream.write(raw)


def main():
    ap = argparse.ArgumentParser()
    for key in ('source', 'output', 'java-home', 'json-jar', 'fixture-map', 'baseline-result'):
        ap.add_argument('--' + key, required=True, type=Path)
    a = ap.parse_args()
    source, out, jdk, jar, fixture_map, baseline = [getattr(a, k).resolve() for k in
                                                 ('source', 'output', 'java_home', 'json_jar', 'fixture_map', 'baseline_result')]
    require(source.is_dir() and not out.exists() and source not in out.parents, 'fresh output outside source required')
    require(ref(jar)['sha256'] == JSON_SHA256 and jar.stat().st_size == 78332, 'fixed complete org.json jar required')
    own = source / 'tests/native-xiaomi-single-toolbar'
    java = own / 'NativeXiaomiSingleToolbarHostTest.java'
    provider = source / 'tests/native-app-provider/run_host.py'
    require(ref(provider)['sha256'] == PROVIDER_RUNNER_SHA256, 'original provider runner bytes required')
    require(ref(baseline)['sha256'] == BASELINE_RESULT_SHA256, 'fixed actual r23 provider reference required')
    prior = json.loads(baseline.read_bytes())
    require(prior.get('all_pass') is True and (prior['cases']['cases'], prior['cases']['assertions']) == (384, 1792),
            'original complete provider baseline must have passed')
    fixtures = json.loads(fixture_map.read_bytes())
    require(fixtures.get('schema') == 'hepta.xiaomi-single-toolbar-external-fixture.v1'
            and fixtures.get('source_bytes_modified') is False and set(fixtures['files']) == set(ORIGINALS), 'exact external fixture index')
    originals_before = {}
    for key, (size, digest) in ORIGINALS.items():
        row = fixtures['files'][key]
        actual = ref(Path(row['path']).resolve())
        require((actual['bytes'], actual['sha256']) == (size, digest)
                and all(actual[k] == row[k] for k in ('path', 'bytes', 'sha256', 'mode')), 'complete original differs: ' + key)
        originals_before[key] = actual
    before = inventory(source)
    tool_paths = [Path(sys.executable).resolve(), jdk / 'bin/java', jdk / 'bin/javac', jdk / 'lib/modules', jar]
    tools_before = {str(p): ref(p) for p in tool_paths}
    out.mkdir(mode=0o700)
    env = dict(os.environ)
    env['PATH'] = str(jdk / 'bin') + ':' + env.get('PATH', '')
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    cleared = {}
    for key in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'CLASSPATH'):
        cleared[key] = env.pop(key, None)
    report = {'schema': 'hepta.native-xiaomi-single-toolbar-host-gate.v1', 'all_pass': False,
              'source': str(source), 'output': str(out), 'argv': sys.argv, 'cwd': str(Path.cwd()),
              'source_before': before, 'tools_before': tools_before, 'originals_before': originals_before,
              'fixture_map': ref(fixture_map), 'baseline_result': ref(baseline), 'runner': ref(Path(__file__).resolve()),
              'stages': [], 'cleared_environment': cleared, 'phone_operations': 0, 'model_executed': False,
              'business_verified': False, 'android_runtime': False,
              'boundary': 'Actual full provider and evidence classes. Archived complete native AX/profile facts only. Android traversal, current authority, model and UI effects are not executed. Query-readback and negative variants are explicit pure host Frame values.'}

    def run(name, argv, timeout=180):
        started = time.monotonic()
        p = subprocess.run(list(map(str, argv)), cwd=out, env=env, capture_output=True, timeout=timeout)
        write(out / (name + '.stdout'), p.stdout)
        write(out / (name + '.stderr'), p.stderr)
        report['stages'].append({'name': name, 'argv': list(map(str, argv)), 'cwd': str(out),
                                 'exit_code': p.returncode, 'elapsed_seconds': time.monotonic() - started,
                                 'stdout': ref(out / (name + '.stdout')), 'stderr': ref(out / (name + '.stderr'))})
        require(p.returncode == 0, 'actual stage failed: ' + name)

    try:
        retained = out / 'retained-provider'
        run('original-provider', [sys.executable, '-B', provider, '--source', source, '--output', retained,
                                  '--java-home', jdk, '--json-jar', jar])
        result = json.loads((retained / 'RESULT.json').read_bytes())
        require(result.get('all_pass') is True and result.get('inputs_unchanged') is True and result.get('tools_unchanged') is True,
                'actual original provider did not pass unchanged')
        require(result['cases'] == prior['cases'], 'all original 384 cases and 1792 assertions must remain exactly equal')
        report['retained_provider'] = {'result': ref(retained / 'RESULT.json'), 'cases': ref(retained / 'CASES.json'),
                                      'cases_unchanged': True, 'case_count': 384, 'assertions': 1792, 'executed_on_candidate': True}
        inputs = {}
        for row in result['compile_inputs']:
            p = Path(row['path'])
            actual = ref(p)
            require(all(actual[k] == row[k] for k in ('path', 'bytes', 'sha256')), 'actual original compile input changed')
            inputs[str(p)] = actual
        inputs[str(java)] = ref(java)
        inputs[str(provider)] = ref(provider)
        inputs[str(Path(__file__).resolve())] = ref(Path(__file__).resolve())
        report['source_inputs'] = inputs
        actual_classes = retained / 'classes'
        report['compiled_provider_classes_before'] = inventory(actual_classes)
        classes = out / 'classes'
        classes.mkdir()
        cp = str(actual_classes) + os.pathsep + str(jar)
        run('compile-single-toolbar', [jdk / 'bin/javac', '--release', '8', '-encoding', 'UTF-8', '-proc:none',
                                      '-Xlint:all,-options', '-Werror', '-classpath', cp, '-d', classes, java])
        run('single-toolbar-cases', [jdk / 'bin/java', '-cp', str(classes) + os.pathsep + cp,
                                     'org.trillionnium.hepta.local.NativeXiaomiSingleToolbarHostTest', fixture_map, out / 'CASES.json'])
        cases = json.loads((out / 'CASES.json').read_bytes())
        expected = re.findall(r'one\("([a-z0-9_]+)"', java.read_text())
        require(cases.get('all_pass') is True and cases.get('case_names') == expected and cases.get('cases') == len(expected)
                and cases.get('assertions', 0) > 0 and len(set(expected)) == len(expected), 'complete new case identity or result differs')
        require(all(cases.get(k) is False for k in ('current_android_ownership_qualified', 'android_runtime', 'model_executed',
                                                  'platform_dispatch_executed', 'business_verified')) and cases.get('phone_operations') == 0,
                'host test must not claim current Android authority or execution')
        report['cases'] = cases
        report['compiled_provider_classes_after'] = inventory(actual_classes)
        require(report['compiled_provider_classes_before'] == report['compiled_provider_classes_after'], 'actual compiled provider changed')
        require(all(ref(p) == row for p, row in inputs.items()), 'actual compiled input changed')
        report['all_pass'] = True
    except Exception as error:
        report['failure'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        report['source_after'] = inventory(source)
        report['tools_after'] = {str(p): ref(p) for p in tool_paths}
        report['originals_after'] = {k: ref(v['path']) for k, v in originals_before.items()}
        report['source_unchanged'] = before == report['source_after']
        report['tools_unchanged'] = tools_before == report['tools_after']
        report['originals_unchanged'] = originals_before == report['originals_after']
        report['all_pass'] &= report['source_unchanged'] and report['tools_unchanged'] and report['originals_unchanged']
        report['outputs'] = {str(p): ref(p) for p in sorted(out.rglob('*')) if p.is_file()}
        write(out / 'RESULT.json', report)
        print(json.dumps({'all_pass': report['all_pass'], 'cases': report.get('cases', {}).get('cases'),
                          'assertions': report.get('cases', {}).get('assertions'), 'failure': report.get('failure'),
                          'result': ref(out / 'RESULT.json')}, ensure_ascii=False))
    return 0 if report['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
