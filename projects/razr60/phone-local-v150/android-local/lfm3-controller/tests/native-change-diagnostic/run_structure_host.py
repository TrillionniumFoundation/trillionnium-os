#!/usr/bin/env python3
"""Compile real classes and synthetic bounded failure diagnostics; no device access."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

p = argparse.ArgumentParser()
p.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[2])
for name in ('output', 'java-home', 'json-jar'):
    p.add_argument('--' + name, type=Path, required=True)
p.add_argument('--test-source', type=Path, default=Path(__file__).resolve().parent / 'NativeRejectedRowStructureHostTest.java')
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
(a.output / 'classes').mkdir()
sha = lambda b: hashlib.sha256(b).hexdigest()
tree = ast.parse((a.source / 'tests/web-flight/run_query_host_tests.py').read_text())
paths = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
             and any(isinstance(v, ast.Name) and v.id == 'PURE_PATHS' for v in n.targets))
paths = [v for v in paths if not v.endswith('/WebFlightQueryHostTest.java')]
paths.append('src/org/trillionnium/hepta/local/WebObservationTiming.java')
assert len(paths) == len(set(paths))
inputs = {v: (a.source / v).read_bytes() for v in paths}
test_bytes = a.test_source.read_bytes()
jar_bytes = a.json_jar.read_bytes()
assert sha(jar_bytes) == '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
report = dict(schema='hepta.native-rejected-row-structure-validation.v1', all_pass=False, host_only=True,
              phone_actions=0, native_authority_tested_here=False,
              source_inputs=[dict(path=k, sha256=sha(v), bytes=len(v)) for k, v in sorted(inputs.items())],
              test_sha256=sha(test_bytes), json_dependency_sha256=sha(jar_bytes), steps=[])
try:
    commands = [
        ('compile', [a.java_home / 'bin/javac', '--release', '8', '-encoding', 'UTF-8', '-proc:none',
                     '-cp', a.json_jar, '-d', a.output / 'classes', *[a.source / v for v in paths], a.test_source]),
        ('run', [a.java_home / 'bin/java', '-Xmx512m', '-cp', str(a.output / 'classes') + os.pathsep + str(a.json_jar),
                 'org.trillionnium.hepta.local.NativeRejectedRowStructureHostTest'])]
    for name, command in commands:
        started = time.monotonic()
        result = subprocess.run(list(map(str, command)), capture_output=True, timeout=150)
        (a.output / (name + '.stdout')).write_bytes(result.stdout)
        (a.output / (name + '.stderr')).write_bytes(result.stderr)
        report['steps'].append(dict(name=name, exit_code=result.returncode, elapsed_seconds=time.monotonic() - started,
                                    stdout_sha256=sha(result.stdout), stderr_sha256=sha(result.stderr)))
        if result.returncode:
            raise RuntimeError(name + ': ' + result.stderr.decode()[-1500:])
        if name == 'run':
            report['tests'] = json.loads(result.stdout)
            assert report['tests']['all_pass'] and report['tests']['cases'] == 8
    report['all_pass'] = True
except Exception as error:
    report['error'] = str(error)
report['inputs_unchanged'] = all((a.source / k).read_bytes() == v for k, v in inputs.items())
report['inputs_unchanged'] &= a.test_source.read_bytes() == test_bytes and a.json_jar.read_bytes() == jar_bytes
report['all_pass'] &= report['inputs_unchanged']
raw = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode()
(a.output / 'RESULT.json').write_bytes(raw)
print(json.dumps(dict(all_pass=report['all_pass'], result_sha256=sha(raw), tests=report.get('tests'), error=report.get('error'))))
raise SystemExit(0 if report['all_pass'] else 1)
