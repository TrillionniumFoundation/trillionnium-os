"""Create one exact isolated source tree and run strict host-only verification.

This driver has no device, owner-lock, signing or deployment operations.
"""
from pathlib import Path, PurePosixPath
import base64
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import time

ROOT = Path('/home/alex/hepta-v55-01c5-20261112')
PACKED_SHA = 'b8a5b9752d0b5bdfb86121566b3af81e27dd61dc8b7ca622bc57b5ec71e32a0f'
JDK = Path('/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64')
SOURCE = ROOT / 'source'
STAGING = ROOT / 'source.staging'
EVIDENCE = ROOT / 'host-r1-driver'
GATE = ROOT / 'host-r1'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def gitblob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()

def dump(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')

def regular(path):
    if not path.is_file() or any(p.is_symlink() for p in [path, *path.parents]):
        raise RuntimeError('non-regular/symlink source: ' + str(path))
    return path.read_bytes()

EVIDENCE.mkdir(mode=0o700, exist_ok=False)
report = {'schema': 'hepta.v55-host-integration.v1', 'scope': 'host_only',
          'phone_operations': False, 'android_compiled': False, 'external_model_used': False,
          'all_pass': False, 'started_unix_ms': int(time.time() * 1000), 'steps': []}
env = dict(os.environ)
env['JAVA_HOME'] = str(JDK)
env['PATH'] = str(JDK / 'bin') + os.pathsep + env['PATH']
env['PYTHONDONTWRITEBYTECODE'] = '1'

def run(name, command, timeout=1800):
    print(json.dumps({'event': 'start', 'name': name}), flush=True)
    started = time.monotonic()
    with (EVIDENCE / (name + '.stdout')).open('wb') as stdout, (EVIDENCE / (name + '.stderr')).open('wb') as stderr:
        result = subprocess.run(command, cwd=SOURCE, env=env, stdout=stdout, stderr=stderr, timeout=timeout)
    row = {'name': name, 'argv': command, 'exit_code': result.returncode,
           'elapsed_s': time.monotonic() - started,
           'stdout_sha256': sha((EVIDENCE / (name + '.stdout')).read_bytes()),
           'stderr_sha256': sha((EVIDENCE / (name + '.stderr')).read_bytes())}
    report['steps'].append(row)
    dump(EVIDENCE / 'RUNNING.json', report)
    print(json.dumps({'event': 'finish', **row}), flush=True)
    return result.returncode

try:
    packed = regular(ROOT / 'host-source-transfer.json.gz')
    if sha(packed) != PACKED_SHA:
        raise RuntimeError('source transfer digest mismatch')
    payload = json.loads(gzip.decompress(packed))
    if payload['destination'] != str(SOURCE) or payload['schema'] != 'hepta.host-source-transfer.v1':
        raise RuntimeError('unexpected source target/schema')
    seed = Path(payload['source_seed'])
    STAGING.mkdir(mode=0o700, exist_ok=False)
    if SOURCE.exists():
        raise RuntimeError('create-only destination exists')
    seen = set()
    seeded = overlaid = 0
    for row in payload['files']:
        name = row['path']
        rel = PurePosixPath(name)
        if rel.is_absolute() or '..' in rel.parts or name in seen or row['mode'] not in ('100644', '100755'):
            raise RuntimeError('unsafe source member')
        seen.add(name)
        if 'data_base64' in row:
            data = base64.b64decode(row['data_base64'], validate=True)
            overlaid += 1
        else:
            data = regular(seed / name)
            seeded += 1
        if len(data) != row['bytes'] or sha(data) != row['sha256'] or gitblob(data) != row['git_blob']:
            raise RuntimeError('seed or overlay source mismatch: ' + name)
        dest = STAGING / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open('xb') as output:
            output.write(data)
        dest.chmod(0o755 if row['mode'] == '100755' else 0o644)
    STAGING.rename(SOURCE)
    report['source_transfer'] = {'payload_sha256': PACKED_SHA, 'local_component_commit': payload['local_component_commit'],
        'component_tree': payload['component_tree'], 'members': len(seen), 'seeded': seeded, 'overlaid': overlaid,
        'manifest_sha256': sha((SOURCE / 'SOURCE-MANIFEST.json').read_bytes()),
        'full_file_map': 'host-source-transfer.json.gz:files', 'all_materialized_git_blobs_verified': True}
    dump(ROOT / 'SOURCE-TRANSFER-RECEIPT.json', report['source_transfer'])
    if not (JDK / 'bin/javac').is_file() or not (JDK / 'lib/ct.sym').is_file():
        raise RuntimeError('strict complete JDK gate unavailable')
    if run('javac-version', [str(JDK / 'bin/javac'), '-version'], 30):
        raise RuntimeError('javac unavailable')
    if run('source-closure-before', ['/usr/bin/python3', '-B', 'tools/verify_source.py'], 30):
        raise RuntimeError('source closure failed')

    # Mutation is deliberately limited to a separate two-file source projection.
    # The production callsite, not a test helper, is removed in this negative.
    negative = ROOT / 'guard-negative-source'
    pkg = Path('src/org/trillionnium/hepta/background')
    (negative / pkg).mkdir(parents=True, exist_ok=False)
    actual_broker = (SOURCE / pkg / 'BackgroundDisplayBroker.java').read_text()
    target = '                    requireIsolatedTaskLaunch(taskPolicy);\n'
    if actual_broker.count(target) != 1:
        raise RuntimeError('negative mutation callsite not unique')
    mutated_broker = actual_broker.replace(target, '', 1)
    (negative / pkg / 'BackgroundDisplayBroker.java').write_text(mutated_broker)
    shutil.copyfile(SOURCE / pkg / 'BackgroundOwnedTaskPolicy.java', negative / pkg / 'BackgroundOwnedTaskPolicy.java')
    negative_code = run('launch-callsite-negative', ['/usr/bin/python3', '-B',
        str(SOURCE / 'tests/background-launch-isolation/run_host_tests.py'), '--source', str(negative),
        '--output', str(ROOT / 'guard-negative-r1'), '--release8'], 120)
    negative_output = (EVIDENCE / 'launch-callsite-negative.stdout').read_text() + (EVIDENCE / 'launch-callsite-negative.stderr').read_text()
    report['launch_guard_negative'] = {
        'production_broker_sha256': sha(actual_broker.encode()), 'mutated_broker_sha256': sha(mutated_broker.encode()),
        'mutation': 'remove exactly one production requireIsolatedTaskLaunch(taskPolicy) call',
        'compiler_contract': '--release 8 -Xlint:all -Werror', 'exit_code': negative_code,
        'expected_assertion_observed': negative_code != 0 and 'unsupported launch must return a stable capability refusal' in negative_output,
        'phone_operations': False,
    }
    if not report['launch_guard_negative']['expected_assertion_observed']:
        raise RuntimeError('negative did not reject missing production guard for expected reason')
    code = run('strict-host-gate', ['/usr/bin/python3', '-B', 'tools/run_host_checks.py', '--out', str(GATE)])
    if (GATE / 'HOST-CHECKS.json').is_file():
        gate = json.loads((GATE / 'HOST-CHECKS.json').read_text())
        report['strict_gate'] = {'exit_code': code, 'all_pass': gate.get('all_pass'),
            'checks': len(gate.get('checks', [])), 'error': gate.get('error'),
            'receipt': str(GATE / 'HOST-CHECKS.json'), 'receipt_sha256': sha((GATE / 'HOST-CHECKS.json').read_bytes())}
    if run('source-closure-after', ['/usr/bin/python3', '-B', 'tools/verify_source.py'], 30):
        raise RuntimeError('source changed during host execution')
    report['all_pass'] = code == 0 and report.get('strict_gate', {}).get('all_pass') is True
except Exception as error:
    report['error'] = str(error)
finally:
    report['finished_unix_ms'] = int(time.time() * 1000)
    dump(EVIDENCE / 'RESULT.json', report)
    print(json.dumps(report), flush=True)
raise SystemExit(0 if report['all_pass'] else 1)
