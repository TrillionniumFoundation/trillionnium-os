#!/usr/bin/env python3
"""Build this isolated candidate from a pinned archive. Never contacts a phone."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import time


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''):
            digest.update(chunk)
    return digest.hexdigest()


def put(path, content):
    with path.open('xb') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', choices=['mac', 'pocket4'], required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--archive-sha256', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--base-root', type=Path)
    parser.add_argument('--base-inventory-sha256')
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    archive = root / ('candidate-delta.tar.gz' if args.base_root else 'candidate-source.tar.gz')
    source = root / 'source'
    if sha(archive) != args.archive_sha256:
        raise RuntimeError('Source archive identity differs')
    if source.exists():
        raise RuntimeError('Fresh source destination required')
    source.mkdir()
    expected_inventory = None
    if args.base_root:
        prior = args.base_root.resolve(strict=True)
        prior_inventory_path = prior / 'SOURCE-INVENTORY.json'
        if sha(prior_inventory_path) != args.base_inventory_sha256:
            raise RuntimeError('Base source inventory changed')
        prior_inventory = json.loads(prior_inventory_path.read_text())
        for row in prior_inventory:
            relative = Path(row['path'])
            if relative.is_absolute() or '..' in relative.parts:
                raise RuntimeError('Unsafe base source member')
            old = prior / 'source' / relative
            if old.is_symlink() or not stat.S_ISREG(old.lstat().st_mode) or old.stat().st_size != row['size'] or sha(old) != row['sha256']:
                raise RuntimeError('Base source changed: ' + row['path'])
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            put(target, old.read_bytes())
    with tarfile.open(archive, 'r:gz') as packed:
        seen = set()
        for member in packed.getmembers():
            name = Path(member.name)
            if name.is_absolute() or '..' in name.parts or not member.isfile() or name.as_posix() in seen:
                raise RuntimeError('Unsafe or duplicate source archive member')
            seen.add(name.as_posix())
            if member.size > 8 * 1024 * 1024:
                raise RuntimeError('Unexpected source member size')
            payload = packed.extractfile(member).read()
            if len(payload) != member.size:
                raise RuntimeError('Truncated archive member')
            if args.base_root and name.as_posix() == 'INVENTORY.json':
                expected_inventory = json.loads(payload)
                continue
            if args.base_root:
                if len(name.parts) < 2 or name.parts[0] != 'files':
                    raise RuntimeError('Unexpected delta member')
                name = Path(*name.parts[1:])
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if args.base_root and target.exists():
                target.unlink()
            put(target, payload)
    inventory = [{'path': str(path.relative_to(source)), 'size': path.stat().st_size, 'sha256': sha(path)}
                 for path in sorted(source.rglob('*')) if path.is_file()]
    if args.base_root and inventory != expected_inventory:
        raise RuntimeError('Complete reconstructed source differs from candidate inventory')
    def unchanged():
        observed = [{'path': str(path.relative_to(source)), 'size': path.stat().st_size, 'sha256': sha(path)}
                    for path in sorted(source.rglob('*')) if path.is_file() and '__pycache__' not in path.parts]
        if observed != inventory:
            raise RuntimeError('Source changed during build')
    put(root / 'SOURCE-INVENTORY.json', (json.dumps(inventory, indent=2) + '\n').encode())
    report = {'schema': 'hepta.background-host-stage.v1', 'host': args.host,
              'source_commit': args.source_commit, 'archive_sha256': args.archive_sha256,
              'source_assembly_type': 'pinned_base_plus_delta' if args.base_root else 'complete_archive',
              'base_inventory_sha256': args.base_inventory_sha256,
              'source_file_count': len(inventory), 'all_pass': False, 'phone_contacted': False,
              'phone_tested': False, 'installed_on_phone': False, 'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'steps': []}
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', SOURCE_HEAD_SHA=args.source_commit)
    def run(name, argv, timeout=600):
        begin = time.monotonic()
        with (root / (name + '.stdout')).open('xb') as out, (root / (name + '.stderr')).open('xb') as err:
            result = subprocess.run(argv, cwd=source, env=env, stdout=out, stderr=err, timeout=timeout)
        report['steps'].append({'name': name, 'exit_code': result.returncode, 'elapsed_seconds': time.monotonic() - begin,
                               'stdout_sha256': sha(root / (name + '.stdout')), 'stderr_sha256': sha(root / (name + '.stderr'))})
        print(json.dumps(report['steps'][-1]), flush=True)
        if result.returncode:
            raise RuntimeError(name + ' failed; original logs retained')
    try:
        if args.host == 'mac':
            env.update(JAVA_HOME='/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home',
                       ANDROID_SDK_ROOT='/Users/qianqi/Library/Android/sdk',
                       ANDROID_NDK_ROOT='/Users/qianqi/Library/Android/sdk/ndk/28.2.13676358',
                       GENIEX_ANDROID_LIB_DIR='/Users/qianqi/Documents/Codex/2026-11-08/razr-local-profiles-dda84ccf-code4/runtime/lib',
                       HEPTA_BUILD_OUT=str(root / 'out'))
            run('android-build', [sys.executable, '-B', str(source / 'build_mac.py')])
            receipt = json.loads((root / 'out/mac-build-receipt.json').read_text())
            spec = importlib.util.spec_from_file_location('build_identity', source / 'tools/build_identity.py')
            identity = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(identity)
            if receipt['source_inputs'] != identity.source_inputs(source) or receipt['source_head_from_ci'] != args.source_commit:
                raise RuntimeError('Compiled source identity mismatch')
            for row in receipt['artifacts']:
                if sha(Path(row['path'])) != row['sha256']:
                    raise RuntimeError('Compiled artifact changed')
            members = ['out/base.apk', 'out/dex/classes.dex', 'out/libhepta_local_runner.so',
                       'out/mac-build-receipt.json', 'out/worker-appuid.c', 'out/native-sha256-disassembly.txt']
            transfer = root / 'mac-artifacts.tar.gz'
            with tarfile.open(transfer, 'x:gz') as packed:
                for name in members:
                    path = root / name
                    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
                        raise RuntimeError('Unexpected Android build artifact')
                    packed.add(path, arcname=name, recursive=False)
            report.update(android_compiled=True, compiler_input_count=len(receipt['source_inputs']),
                          transfer_archive={'path': str(transfer), 'size': transfer.stat().st_size, 'sha256': sha(transfer)})
        else:
            jdk_path = Path('/home/alex/hepta-v31-nanbeige42-e59-r1/toolchains/old-jdk17-revalidation-r1/RESULT.json')
            if sha(jdk_path) != '349939390c8b19e8cea03e28ce6c5bc2c1d010dd06d3a435b7f1517221f0dd1c':
                raise RuntimeError('Complete JDK receipt differs')
            jdk = json.loads(jdk_path.read_text())
            java_home = Path(jdk['java_home'])
            if jdk['status'] != 'ready' or jdk['release8_positive_exit'] != 0 or jdk['release8_negative_exit'] == 0:
                raise RuntimeError('JDK release 8 positive/negative contract missing')
            for name, pin in jdk['member_pins'].items():
                path = java_home / name
                if path.is_symlink() or path.stat().st_size != pin['bytes'] or sha(path) != pin['sha256']:
                    raise RuntimeError('JDK member changed: ' + name)
            env.update(JAVA_HOME=str(java_home), PATH=str(java_home / 'bin') + ':' + os.environ.get('PATH', ''),
                       HEPTA_TEST_JAVA=str(java_home / 'bin/java'), HEPTA_TEST_JAVAC=str(java_home / 'bin/javac'))
            run('full-host-checks', [sys.executable, '-B', str(source / 'tools/run_host_checks.py'), '--out', str(root / 'host-checks')])
            receipt = json.loads((root / 'host-checks/HOST-CHECKS.json').read_text())
            if receipt['all_pass'] is not True or any(row['exit_code'] != 0 for row in receipt['checks']):
                raise RuntimeError('Host regression suite failed')
            report.update(android_compiled=False, java_home=str(java_home), java8_release_gate=True,
                          host_check_records=len(receipt['checks']))
        unchanged()
        report['all_pass'] = True
    except Exception as error:
        report.update(error_type=type(error).__name__, error=str(error))
    finally:
        report['finished_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        put(root / 'STAGE-RESULT.json', (json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
        print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report['all_pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
