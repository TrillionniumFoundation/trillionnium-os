#!/usr/bin/env python3
"""Compile a byte-pinned Java-only candidate with real Android javac and D8.

No native build, APK, signing, installation, adb, phone task or source publication.
The source manifest is deliberately not a complete component build inventory.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


def need(ok, message):
    if not ok:
        raise ValueError(message)


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(path, maximum=64 << 20):
    need(path.is_absolute() and '..' not in path.parts, 'absolute file path required')
    need(all(not p.is_symlink() for p in (path, *path.parents)), 'symlink input refused')
    before = path.stat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= maximum,
         'bounded single-link regular input required')
    raw = path.read_bytes()
    after = path.stat()
    key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(len(raw) == before.st_size and key(before) == key(after), 'input changed while reading')
    return raw


def pin(path, relative=None, maximum=64 << 20):
    raw = regular(path, maximum)
    return {'path': str(relative if relative is not None else path),
            'size': len(raw), 'sha256': digest(raw)}


def valid_row(row):
    need(type(row) is dict and set(row) == {'path', 'size', 'sha256'}, 'exact file row keys required')
    need(type(row['path']) is str and type(row['size']) is int and row['size'] > 0
         and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']) is not None,
         'invalid file row')


def write_new(path, raw):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-manifest', type=Path, required=True)
    parser.add_argument('--source-manifest-sha256', required=True)
    for name in ('android-jar', 'javac', 'java', 'd8-jar'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(re.fullmatch('[0-9a-f]{64}', args.source_manifest_sha256) is not None,
         'full source manifest pin required')
    original_manifest = regular(args.source_manifest, 2 << 20)
    need(digest(original_manifest) == args.source_manifest_sha256, 'source manifest bytes differ')
    manifest = json.loads(original_manifest.decode('utf-8'), object_pairs_hook=pairs)
    need(set(manifest) == {'schema', 'base_commit', 'base_component_tree', 'candidate_source_commit',
                          'java_source_count', 'java_sources', 'compiler_driver', 'tool_inputs', 'min_api',
                          'full_component_build_inventory', 'native_compilation', 'phone_operations'},
         'exact source manifest fields required')
    need(manifest['schema'] == 'hepta.action-worker-java-snapshot.v1'
         and manifest['base_commit'] == '5da3c83fe46edb2617934a92c06a10608accb68e'
         and manifest['base_component_tree'] == '24e8d82d4befdab6f4f32ef7efeba7faad345a04'
         and manifest['candidate_source_commit'] is None and manifest['java_source_count'] == 112
         and manifest['full_component_build_inventory'] is False
         and manifest['native_compilation'] is False and manifest['phone_operations'] == 0
         and manifest['min_api'] == 30, 'isolated Java-only candidate scope differs')
    root = Path(__file__).resolve().parents[2]
    rows = manifest['java_sources']
    need(type(rows) is list and len(rows) == 112, 'complete current 112 Java inputs required')
    names = []
    for row in rows:
        valid_row(row)
        name = row['path']
        need(re.fullmatch(r'src/[A-Za-z0-9_./-]+\.java', name) is not None
             and all(part not in ('', '.', '..') for part in name.split('/')),
             'Java source traversal refused')
        names.append(name)
    need(names == sorted(set(names)), 'unique sorted Java source inventory required')

    def source_pins():
        observed = sorted(str(p.relative_to(root)) for p in (root / 'src').rglob('*.java'))
        need(observed == names, 'Java closure has missing or additional files')
        return [pin(root / name, name, 2 << 20) for name in names]

    before_sources = source_pins()
    need(before_sources == rows, 'actual source bytes differ from reviewed snapshot')
    driver_path = Path(__file__).absolute()
    valid_row(manifest['compiler_driver'])
    before_driver = pin(driver_path, driver_path.relative_to(root), 2 << 20)
    need(before_driver == manifest['compiler_driver'], 'compiler driver bytes differ')
    tools = {'android_jar': args.android_jar, 'javac': args.javac,
             'java': args.java, 'd8_jar': args.d8_jar}
    need(type(manifest['tool_inputs']) is dict and set(manifest['tool_inputs']) == set(tools),
         'exact four tool pins required')
    before_tools = {}
    for name, path in tools.items():
        valid_row(manifest['tool_inputs'][name])
        before_tools[name] = pin(path)
        need(before_tools[name] == manifest['tool_inputs'][name], 'actual tool pin differs: ' + name)

    output = args.output
    need(output.is_absolute() and '..' not in output.parts and not output.exists()
         and not output.is_symlink() and output.parent.is_dir()
         and all(not p.is_symlink() for p in output.parents)
         and root != output and root not in output.parents,
         'new output outside the source tree required')
    output.mkdir(mode=0o700)
    classes_dir = output / 'classes'; classes_dir.mkdir(mode=0o700)
    dex_dir = output / 'dex'; dex_dir.mkdir(mode=0o700)
    report = {'schema': 'hepta.action-worker-android-java-dex-compile.v1', 'all_pass': False,
              'started_utc': datetime.now(timezone.utc).isoformat(), 'source_manifest_sha256': digest(original_manifest),
              'base_commit': manifest['base_commit'], 'base_component_tree': manifest['base_component_tree'],
              'candidate_source_commit': None, 'java_source_count': len(rows), 'source_inputs': before_sources,
              'compiler_driver': before_driver, 'tool_inputs': before_tools, 'commands': [],
              'java_compiled': False, 'dex_compiled': False, 'android_runtime_test': False,
              'full_component_build_inventory': False, 'native_compilation': False,
              'apk_assembled': False, 'apk_signed': False, 'phone_operations': 0, 'device_qualification': False}

    def run(label, command, timeout):
        row = {'name': label, 'argv': command, 'returncode': None, 'timed_out': False}
        report['commands'].append(row)
        try:
            result = subprocess.run(command, cwd=str(root), capture_output=True, timeout=timeout)
            stdout, stderr = result.stdout, result.stderr
            row['returncode'] = result.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b'', error.stderr or b''
            row['timed_out'] = True
        write_new(output / (label + '.stdout'), stdout)
        write_new(output / (label + '.stderr'), stderr)
        row['stdout'] = {'path': label + '.stdout', 'size': len(stdout), 'sha256': digest(stdout)}
        row['stderr'] = {'path': label + '.stderr', 'size': len(stderr), 'sha256': digest(stderr)}
        need(row['returncode'] == 0 and not row['timed_out'], label + ' did not complete successfully')

    try:
        write_new(output / 'SOURCE-MANIFEST-ORIGINAL.json', original_manifest)
        run('javac', [str(tools['javac']), '-encoding', 'UTF-8', '--release', '8',
                      '-classpath', str(tools['android_jar']), '-d', str(classes_dir)]
            + [str(root / name) for name in names], 120)
        need(source_pins() == before_sources, 'source changed during Java compilation')
        classes = sorted(classes_dir.rglob('*.class'))
        need(bool(classes), 'compiler produced no classes')
        class_pins = [pin(path, path.relative_to(output), 8 << 20) for path in classes]
        report['java_compiled'] = True
        report['output_classes'] = class_pins
        run('d8', [str(tools['java']), '-cp', str(tools['d8_jar']), 'com.android.tools.r8.D8',
                   '--lib', str(tools['android_jar']), '--min-api', str(manifest['min_api']),
                   '--output', str(dex_dir)] + [str(path) for path in classes], 120)
        need(classes == sorted(classes_dir.rglob('*.class'))
             and class_pins == [pin(path, path.relative_to(output), 8 << 20) for path in classes],
             'class input changed during D8 compilation')
        dex_files = sorted(dex_dir.glob('*.dex'))
        need(bool(dex_files) and (dex_dir / 'classes.dex') in dex_files, 'D8 produced no primary DEX')
        for path in dex_files:
            raw = regular(path)
            need(re.fullmatch(rb'dex\n[0-9]{3}\x00', raw[:8]) is not None, 'DEX magic differs')
        report['output_dex'] = [pin(path, path.relative_to(output)) for path in dex_files]
        report['dex_compiled'] = True
        report['source_inputs_unchanged'] = source_pins() == before_sources
        report['tool_inputs_unchanged'] = {name: pin(path) for name, path in tools.items()} == before_tools
        report['driver_unchanged'] = pin(driver_path, driver_path.relative_to(root), 2 << 20) == before_driver
        report['manifest_unchanged'] = regular(args.source_manifest, 2 << 20) == original_manifest
        need(all(report[key] for key in ('source_inputs_unchanged', 'tool_inputs_unchanged',
                                        'driver_unchanged', 'manifest_unchanged')), 'compile inputs changed')
        report['all_pass'] = True
    except Exception as error:
        report['failure_class'] = type(error).__name__
        report['failure'] = str(error)
    report['finished_utc'] = datetime.now(timezone.utc).isoformat()
    raw_report = (json.dumps(report, indent=2) + '\n').encode()
    write_new(output / 'RESULT.json', raw_report)
    print(json.dumps({'all_pass': report['all_pass'], 'java_sources': len(rows),
                      'class_count': len(report.get('output_classes', [])),
                      'dex_count': len(report.get('output_dex', [])),
                      'result': str(output / 'RESULT.json'), 'result_sha256': digest(raw_report),
                      'phone_operations': 0}))
    return 0 if report['all_pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
