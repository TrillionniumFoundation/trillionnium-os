#!/usr/bin/env python3
"""Original public/private cleanup gates plus the d4 producer/consumer evidence seam."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def ref(path):
    path = Path(path)
    raw = path.read_bytes()
    return {'path': str(path.resolve()), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


def inventory(root):
    return {str(p.relative_to(root)): ref(p) for p in sorted(root.rglob('*')) if p.is_file()}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--java-home', required=True, type=Path)
    p.add_argument('--json-jar', required=True, type=Path)
    p.add_argument('--actual-originals', required=True, type=Path)
    a = p.parse_args()
    source, out, actual = a.source.resolve(), a.output.resolve(), a.actual_originals.resolve()
    java, javac = a.java_home.resolve()/'bin/java', a.java_home.resolve()/'bin/javac'
    jar = a.json_jar.resolve()
    if ref(jar)['sha256'] != '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed':
        raise RuntimeError('original fixed JSON dependency differs')
    out.mkdir(parents=True, exist_ok=False)
    before = inventory(source)
    originals = {name: ref(actual/name) for name in (
        'background-cleanup.json', 'background-bootstrap.json',
        'background-broker-a17672ea-79fb-46d8-bfc3-e11f3a8ff712.json',
        'background-broker-a17672ea-79fb-46d8-bfc3-e11f3a8ff712.bin', 'result.json')}
    tool_refs = {'java': ref(java), 'javac': ref(javac), 'json': ref(jar)}
    stages = []
    result = {'schema': 'hepta.profile-normal-cleanup-evidence-host-validation.v1',
              'all_pass': False, 'stages': stages, 'source_inputs': before,
              'actual_originals': originals, 'tools': tool_refs,
              'phone_actions': 0, 'android_runtime': False,
              'fresh_device_absence_or_recovery_claimed': False}
    env = dict(os.environ)
    env['JAVA_TOOL_OPTIONS'] = '-Xmx512m'

    def run(name, argv):
        start = time.monotonic()
        proc = subprocess.run([str(v) for v in argv], cwd=out, env=env,
                              capture_output=True, timeout=240)
        stdout, stderr = out/(name+'.stdout'), out/(name+'.stderr')
        stdout.write_bytes(proc.stdout)
        stderr.write_bytes(proc.stderr)
        stages.append({'name': name, 'argv': [str(v) for v in argv], 'exit_code': proc.returncode,
                       'elapsed_seconds': time.monotonic()-start, 'stdout': ref(stdout),
                       'stderr': ref(stderr), 'java_heap_limit': '512m'})
        if proc.returncode != 0:
            raise RuntimeError(name+' failed with exit '+str(proc.returncode))

    try:
        run('original-public-and-private', [
            sys.executable, '-B', source/'tests/public-profile-cleanup/run_host.py',
            '--source', source, '--output', out/'original-public',
            '--java-home', a.java_home.resolve(), '--json-jar', jar])
        legacy = json.loads((out/'original-public/RESULT.json').read_text())
        if legacy['all_pass'] is not True or legacy['unchanged_private_gate']['all_pass'] is not True:
            raise RuntimeError('original public/private result was not accepted')
        result['original_public_and_private'] = ref(out/'original-public/RESULT.json')
        result['original_public_cases'] = legacy['cases']
        result['original_private_cases'] = legacy['unchanged_private_gate']
        inherited = out/'original-public/candidate-classes'
        inherited_before = inventory(inherited)
        test_source = source/'tests/profile-cleanup-evidence/ProfileNormalCleanupEvidenceHostTest.java'
        classes = out/'evidence-classes'
        classes.mkdir()
        run('new-evidence-compile', [javac, '--release', '8', '-encoding', 'UTF-8', '-proc:none',
            '-Xlint:all,-options', '-Werror', '-cp', str(inherited)+':'+str(jar),
            '-d', classes, test_source])
        run('new-evidence-tests', [java, '-cp', str(classes)+':'+str(inherited)+':'+str(jar),
            'org.trillionnium.hepta.local.ProfileNormalCleanupEvidenceHostTest', out/'CASES.json', actual])
        cases = json.loads((out/'CASES.json').read_text())
        if cases['schema'] != 'hepta.profile-normal-cleanup-evidence-host-tests.v1' or cases['all_pass'] is not True:
            raise RuntimeError('new evidence report was not accepted')
        if inherited_before != inventory(inherited):
            raise RuntimeError('original compiled class bytes changed')
        result['inherited_actual_compiled_classes'] = inherited_before
        result['new_compiled_classes'] = inventory(classes)
        result['new_cases'] = cases
        result['all_pass'] = True
    except Exception as error:
        result['error'] = type(error).__name__+': '+str(error)
    finally:
        result['source_inputs_unchanged'] = before == inventory(source)
        result['actual_originals_unchanged'] = originals == {n: ref(actual/n) for n in originals}
        result['tools_unchanged'] = tool_refs == {'java': ref(java), 'javac': ref(javac), 'json': ref(jar)}
        if not all(result[k] for k in ('source_inputs_unchanged', 'actual_originals_unchanged', 'tools_unchanged')):
            result['all_pass'] = False
        (out/'RESULT.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps({'all_pass': result['all_pass'], 'stages': [
        {'name': s['name'], 'exit_code': s['exit_code']} for s in stages],
        'new_cases': result.get('new_cases', {}).get('cases'),
        'new_assertions': result.get('new_cases', {}).get('assertions'),
        'error': result.get('error'), 'phone_actions': 0}))
    return 0 if result['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
