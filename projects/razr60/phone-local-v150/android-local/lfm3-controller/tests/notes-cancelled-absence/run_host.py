#!/usr/bin/env python3
"""Actual cancelled history admission and real client/CAS with explicit IO ports.

No phone connection or actual current-absence assertion. Private originals are
external, hash pinned and byte unchanged. Host framework/PM/clock and the future
startup/EOF successors are explicitly synthetic. Existing legacy cases execute.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
sys.dont_write_bytecode = True

JSON_SHA = '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'

def need(ok, message):
    if not ok:
        raise RuntimeError(message)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def read(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path, 'absolute nonsymlink path required')
    with path.open('rb') as handle:
        before = os.fstat(handle.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'regular single-link input required')
        raw = handle.read()
        after = os.fstat(handle.fileno())
    fields = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_nlink)
    need(fields(before) == fields(after) == fields(path.lstat()), 'input changed during read')
    return raw

def pin(path):
    raw = read(path)
    return {'path': str(path), 'bytes': len(raw), 'sha256': digest(raw)}

def originals(path):
    value = json.loads(read(path))
    need(value['schema'] == 'hepta.notes-cancelled-actual-inputs.v1', 'actual map schema')
    refs = {}
    for section in ('inputs', 'task_files'):
        for key, row in value[section].items():
            actual = pin(Path(row['path']))
            need(actual == row, 'actual original differs: ' + key)
            refs[section + '/' + key] = row
    return refs

def run(name, argv, output, result, env):
    (output / (name + '.command.json')).write_text(json.dumps(argv, indent=2) + '\n')
    started = time.monotonic()
    completed = subprocess.run(argv, env=env, capture_output=True, timeout=180)
    (output / (name + '.stdout')).write_bytes(completed.stdout)
    (output / (name + '.stderr')).write_bytes(completed.stderr)
    result['stages'].append({'stage': name, 'exit_code': completed.returncode,
                             'seconds': time.monotonic() - started,
                             'stdout_sha256': digest(completed.stdout), 'stderr_sha256': digest(completed.stderr)})
    need(completed.returncode == 0 and completed.stderr == b'', name + ' failed or produced stderr')
    return completed.stdout

def main():
    parser = argparse.ArgumentParser()
    for name in ('source', 'java-home', 'json-jar', 'private-input-map', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    own = source / 'tests/notes-cancelled-absence'
    java = args.java_home.resolve() / 'bin'
    jar = args.json_jar.resolve()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', JAVA_HOME=str(args.java_home.resolve()))
    tools = {str(path): pin(path) for path in (java / 'java', java / 'javac', jar)}
    need(tools[str(jar)]['sha256'] == JSON_SHA, 'pinned org.json required')
    inputs = originals(args.private_input_map.resolve())
    mapping = pin(args.private_input_map.resolve())
    source_inputs = {str(path): pin(path)['sha256'] for path in
                     (own / 'run_host.py', own / 'NotesCancelledAbsenceHostTest.java', own / 'README.md')}
    result = {'schema': 'hepta.notes-cancelled-absence-host-validation.v1', 'all_pass': False,
              'phone_operations': 0, 'current_absence_claimed': False, 'business_success_claimed': False,
              'actual_historical_inputs': True, 'framework_pm_clock_and_checker_samples_synthetic': True,
              'startup_and_eof_successor_authored': True, 'actual_client_archive_and_journal_CAS': True,
              'actual_android_UI_ACK_executed': False, 'strict_release8': True, 'stages': [],
              'source_inputs': source_inputs, 'tool_inputs': tools, 'private_inputs': inputs,
              'private_input_map': mapping}
    try:
        run('legacy', [sys.executable, str(source / 'tests/personal-notes-absence/run_host.py'),
                      '--source', str(source), '--java-home', str(args.java_home.resolve()),
                      '--json-jar', str(jar), '--output', str(output / 'legacy')], output, result, env)
        legacy_path = output / 'legacy/RESULT.json'
        legacy = json.loads(read(legacy_path))
        need(legacy['all_pass'] and legacy['inputs_unchanged'] and legacy['strict_release8'] and
             len(legacy['stages']) == 6 and all(row['exit_code'] == 0 for row in legacy['stages']), 'actual retained legacy gates required')
        result['legacy_result'] = pin(legacy_path)
        result['legacy_counts'] = {key: {k: legacy[key][k] for k in ('cases', 'assertions') if k in legacy[key]}
                                   for key in ('policy', 'display-census', 'client', 'post-model')}
        for path, value in legacy['source_inputs'].items():
            if Path(path).is_relative_to(source):
                need(pin(Path(path))['sha256'] == value, 'source changed after actual legacy compilation')
                source_inputs[path] = value
        classes = output / 'legacy/client-classes'
        cp = str(classes) + os.pathsep + str(jar)
        run('compile', [str(java / 'javac'), '--release', '8', '-Xlint:all,-options', '-Werror', '-encoding', 'UTF-8', '-proc:none',
                        '-cp', cp, '-d', str(classes), str(own / 'NotesCancelledAbsenceHostTest.java')], output, result, env)
        raw = run('cancelled', [str(java / 'java'), '-cp', cp, 'org.trillionnium.hepta.local.NotesCancelledAbsenceHostTest',
                               str(args.private_input_map.resolve()), str(output / 'scratch')], output, result, env)
        result['cancelled'] = json.loads(raw)
        need(result['cancelled']['all_pass'], 'cancelled gate did not pass')
        result['all_pass'] = True
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        result['inputs_unchanged'] = all(pin(Path(path))['sha256'] == value for path, value in source_inputs.items())
        result['tools_unchanged'] = all(pin(Path(path)) == value for path, value in tools.items())
        result['original_bytes_unchanged'] = inputs == originals(args.private_input_map.resolve()) and mapping == pin(args.private_input_map.resolve())
        result['all_pass'] = result['all_pass'] and result['inputs_unchanged'] and result['tools_unchanged'] and result['original_bytes_unchanged']
        (output / 'RESULT.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'all_pass': result['all_pass'], 'result': str(output / 'RESULT.json'), 'error': result.get('error'),
                      'cases': result.get('cancelled', {}).get('cases'), 'assertions': result.get('cancelled', {}).get('assertions')}))
    return 0 if result['all_pass'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
