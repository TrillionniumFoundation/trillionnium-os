#!/usr/bin/env python3
"""Host ownership, permission-init and physical-fence policy checks.

This runner does not execute or qualify Android Binder/A11y adapters or build an APK.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import shutil
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    classes = output / 'classes'
    classes.mkdir()
    background = source / 'src/org/trillionnium/hepta/background'
    names = ['ProfileIdentity', 'ProfileTarget', 'WindowOwnership', 'BrokerProtocol','PublicPermissionControllerUi', 'PublicOwnGroupPolicy',
             'FixedIntentTools', 'BackgroundOwnedTaskPolicy', 'BackgroundOwnedSingleTask',
             'ProfileTaskPolicy', 'ProfileOwnedTask', 'ProfilePermissionTransient', 'ProfileDisplayCustody',
             'PermissionWindowObservation', 'PhysicalDisplayFence']
    inputs = [background / (name + '.java') for name in names]
    inputs += [source / 'src/org/trillionnium/hepta/local/NativeAppGoal.java',
               source / 'src/org/trillionnium/hepta/local/ProfilePermissionInitialization.java',
               source / 'tests/profile-broker/ProfileBrokerHostTest.java',
               source / 'tests/profile-permission-transient/ProfilePermissionTransientHostTest.java',
               source / 'tests/profile-permission-transient/ProfileStateSettleHostTest.java',
               source / 'tests/profile-permission-initialization/ProfilePermissionInitializationHostTest.java',
               source / 'tests/profile-permission-initialization/PhysicalDisplayFenceHostTest.java']
    fixture = source / 'tests/profile-permission-transient/fixtures/synthetic-activities.txt'
    pair_runner = source / 'tests/profile-permission-transient/run_host.py'
    platform = background / 'ProfileTaskPlatform.java'
    tracked = inputs + [fixture, Path(__file__).resolve(), pair_runner, platform]
    pins = {str(p): digest(p) for p in tracked}
    result = {'schema': 'hepta.permission-init-core-host.v1', 'all_pass': False,
              'base_head': 'f7dbe2f1c06e34c992b140d5d88995a8e99c03db',
              'source_head_from_ci': None,
              'candidate_android_integration_present': True, 'android_adapters_compiled': False,
              'phone_contacted': False, 'apk_built': False, 'fixtures_synthetic': True,
              'java_source_level': 8, 'java_target_level': 8, 'java_release_api_check': True,
              'compiler_contract': 'Java 8 API release; no fallback from --release 8',
              'source_inputs_sha256': pins, 'stages': []}

    def run(name, argv):
        begun = time.monotonic()
        process = subprocess.run(argv, capture_output=True, timeout=60)
        (output / (name + '.stdout')).write_bytes(process.stdout)
        (output / (name + '.stderr')).write_bytes(process.stderr)
        result['stages'].append({'name': name, 'exit_code': process.returncode,
                                 'elapsed_seconds': time.monotonic() - begun,
                                 'stdout_sha256': hashlib.sha256(process.stdout).hexdigest(),
                                 'stderr_sha256': hashlib.sha256(process.stderr).hexdigest()})
        if process.returncode:
            raise RuntimeError(name + ' failed; see original stdout/stderr')
        return process.stdout.decode('utf-8')

    try:
        original_tests = {'tests/profile-broker/ProfileBrokerHostTest.java': '5880a651260aa18566364f4dbca427c5adbba8048eee7f1b8a3d55f4a6f69e04', 'tests/profile-permission-transient/ProfilePermissionTransientHostTest.java': '7ac5d394010ca7e42e87ea7902bd96dd425530df3eaf4f485a8ce5efb529f162', 'tests/profile-permission-transient/ProfileStateSettleHostTest.java': 'e1b13341ce3db24921f78b4c378c7635253d659abb44027b3d582a0d808a2cf1'}
        for name, expected in original_tests.items():
            if digest(source/name) != expected:
                raise RuntimeError("Original ownership test changed: "+name)
        result["original_ownership_test_files_unchanged"] = True
        java=args.java_home.resolve()/"bin/java"
        javac=args.java_home.resolve()/"bin/javac"
        if not java.is_file() or not javac.is_file():
            raise RuntimeError("Existing full JDK required; no fallback")
        if digest(fixture) != '7f8adcb158486f74a1ebe342e54902b9fc7550ed7b0dd7bf11b36d1d97ab63f0':
            raise RuntimeError('synthetic fixture pin differs')
        pair_spec = importlib.util.spec_from_file_location('permission_init_pair_fixture', pair_runner)
        pair_module = importlib.util.module_from_spec(pair_spec)
        pair_spec.loader.exec_module(pair_module)
        generated, pair_receipt = pair_module.prepare_permission_pair_adapters(platform, output)
        inputs += generated
        pins.update({str(path): digest(path) for path in generated})
        result['permission_pair_adapter'] = pair_receipt
        result['compiler'] = run('compiler-version', [str(javac), '-version']).strip()
        run('compile', [str(javac), '--release', '8',
                        '-encoding', 'UTF-8', '-d', str(classes)] + [str(p) for p in inputs])
        run('original-profile-broker', [str(java), '-cp', str(classes),
                                       'org.trillionnium.hepta.background.ProfileBrokerHostTest'])
        run('original-permission-transient', [str(java), '-cp', str(classes),
                    'org.trillionnium.hepta.background.ProfilePermissionTransientHostTest', str(fixture), 'synthetic'])
        run('original-state-settle', [str(java), '-cp', str(classes),
                    'org.trillionnium.hepta.background.ProfileStateSettleHostTest', str(fixture)])
        new_output = run('permission-initialization', [str(java), '-cp', str(classes),
                    'org.trillionnium.hepta.background.ProfilePermissionInitializationHostTest', str(fixture)])
        result['new_policy_cases'] = json.loads(new_output.rstrip().splitlines()[-1])
        fence_output = run('physical-fence', [str(java), '-cp', str(classes),
                    'org.trillionnium.hepta.background.PhysicalDisplayFenceHostTest'])
        result['physical_fence_cases'] = json.loads(fence_output.rstrip().splitlines()[-1])
        for path, before in pins.items():
            if digest(Path(path)) != before:
                raise RuntimeError('input changed during execution: ' + path)
        result['source_inputs_unchanged'] = True
        result['all_pass'] = True
    except Exception as error:
        result['error']=str(error)
    finally:
        (output / 'RESULT.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'all_pass': result['all_pass'], 'new_policy_cases': result.get('new_policy_cases'),
                      'result': str(output / 'RESULT.json'), 'error':result.get('error')}, ensure_ascii=False))
    return 0 if result['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
