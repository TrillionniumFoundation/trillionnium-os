#!/usr/bin/env python3
"""Rebuild the pinned ordinary-App worker and bind its exact bytes to one CI attempt.

The original build receipt remains historical provenance. A new build has its own
receipt, and both the producer and consumer must verify the unchanged whole ELF.
No model, phone, installed application, runtime pin or source file is modified.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys

APP_SHA = 'f4af9855da4e62a2eeaa1cc8d734082c6c31d17f95d001b58b412dbd7604978a'
ORIGINAL_RECEIPT_SHA = '3dac4c0e91bd9c088e7330394953f6df74596feff04c7e815672ee8d3392e705'
ORIGINAL_BUILDER_SHA = '8ffbf2f722cc7279d7495ef96c62fe1b60fe9463f2b29e7e9fa396f190ed112d'
WORKER_SHA = '5fa2dcae05fb649157d96481c5890c157301c76dab3522fcabcbe01b9b0d8551'
WORKER_BYTES = 58144
CURRENT = 'CURRENT-CI-SOURCE.json'
NEW_REPORT = 'NEW-BUILD-RECEIPT.json'
COMPILER = 'COMPILER-IDENTITY.json'
WORKER = 'libhepta_ui_venus_runner.so'
REMOVED_ENV = ('CC', 'CXX', 'CPP', 'AS', 'AR', 'CFLAGS', 'CXXFLAGS', 'CPPFLAGS',
               'LDFLAGS', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LIBRARY_PATH', 'CPATH',
               'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'SDKROOT')


def require(condition, message):
    if condition is not True:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path, maximum=1048576):
    path = Path(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                0 < before.st_size <= maximum, 'bounded single-link regular file required')
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink,
                          s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(len(data) == before.st_size and
            identity(before) == identity(after) == identity(os.lstat(path)), 'file changed during read')
    return data


def obj(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate metadata key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite metadata')))


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_identity(head, run, attempt):
    require(re.fullmatch(r'[0-9a-f]{40}', head) is not None, 'exact source HEAD required')
    require(re.fullmatch(r'[1-9][0-9]*', run) is not None and
            re.fullmatch(r'[1-9][0-9]*', attempt) is not None, 'current CI run and attempt required')
    return {'source_head_sha': head, 'github_run_id': run, 'github_run_attempt': attempt}


def frozen_app(root):
    root = Path(root).resolve(strict=True)
    require(digest(read(root / 'SOURCE-MANIFEST.json')) == APP_SHA, 'complete App source identity differs')
    sys.path.insert(0, str(root / 'tools'))
    load(root / 'tools/verify_source.py', 'ui_venus_frozen_source').verify(root)
    api = load(root / 'tools/verify_ui_venus_runtime.py', 'ui_venus_frozen_packaging')
    pins = api.load_pins(root)
    require(pins['worker']['sha256'] == WORKER_SHA and pins['worker']['bytes'] == WORKER_BYTES,
            'fixed App worker pin changed')
    original = read(root / 'provenance/ui-venus-app-r1/NATIVE-BUILD-RECEIPT.json')
    require(digest(original) == ORIGINAL_RECEIPT_SHA, 'historical build receipt changed')
    native = root / 'provenance/ui-venus-app-r1/native-worker'
    require(digest(read(native / 'tools/build_android.py')) == ORIGINAL_BUILDER_SHA,
            'original independent build helper changed')
    return root, api, pins, native, original


def check_new_report(report, original, pins):
    # Only observations that necessarily depend on the new host paths or elapsed
    # time may differ. All model, source, boundary, ABI and claim fields are exact.
    variable = {'compile_command', 'ndk_directory', 'compiler_version', 'sdk_libraries', 'elapsed_seconds'}
    require(set(report) == set(original), 'new build receipt membership differs')
    for key in set(original) - variable:
        require(type(report[key]) is type(original[key]) and report[key] == original[key],
                'new build differs from the fixed original contract: ' + key)
    require(type(report['elapsed_seconds']) in (int, float) and report['elapsed_seconds'] >= 0,
            'invalid actual build duration')
    require(isinstance(report['compile_command'], list) and len(report['compile_command']) > 0 and
            all(isinstance(value, str) and value for value in report['compile_command']), 'actual compile argv absent')
    require(isinstance(report['ndk_directory'], str) and report['ndk_directory'].startswith('/'),
            'actual NDK directory absent')
    require(isinstance(report['compiler_version'], str) and '13324770' in report['compiler_version'] and
            '19.0.0' in report['compiler_version'], 'actual compiler family differs')
    require(isinstance(report['sdk_libraries'], list) and len(report['sdk_libraries']) == 12,
            'complete twelve-library SDK build closure required')
    project = lambda rows: [{k: row[k] for k in ('name', 'bytes', 'sha256')} for row in rows]
    require(project(report['sdk_libraries']) == project(original['sdk_libraries']), 'actual SDK identity differs')
    require(all(isinstance(row.get('source_path'), str) and row['source_path'].startswith('/')
                for row in report['sdk_libraries']), 'actual SDK paths absent')
    command = report['compile_command']
    units = [Path(value) for value in command if value.endswith('/native/probe-worker.c')]
    require(len(units) == 1 and units[0].is_absolute(), 'one actual native compilation unit required')
    native = units[0].parent
    libs = Path(next(row['source_path'] for row in report['sdk_libraries'] if row['name'] == 'libgeniex.so')).parent
    target = Path(command[-1])
    require(target.is_absolute() and target.name == WORKER, 'actual worker output path differs')
    compiler = Path(report['ndk_directory']) / 'toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android30-clang'
    expected_command = [str(compiler), '-std=c11', '-O2', '-fPIE', '-pie', '-Wall', '-Wextra', '-Werror',
                        '-I' + str(native / 'vendor'), '-I' + str(native), str(units[0]),
                        '-L' + str(libs), '-L' + str(libs / 'llama_cpp'), '-lgeniex', '-lllama', '-ldl', '-lm',
                        '-Wl,-rpath,$ORIGIN', '-Wl,-rpath-link,' + str(libs / 'llama_cpp'),
                        '-Wl,-z,max-page-size=16384', '-o', str(target)]
    require(command == expected_command, 'actual compiler arguments differ from the fixed source recipe')
    require(report['worker']['sha256'] == pins['worker']['sha256'] == WORKER_SHA and
            report['worker']['bytes'] == pins['worker']['bytes'] == WORKER_BYTES,
            'new worker whole-file identity differs')


def check_compiler(identity, qualifier):
    qualifier.check_identity(identity)
    require(identity.get('qualified') is True and
            identity.get('compiler_bytes_outside_signatures_identical') is True and
            identity.get('binary_rewritten') is False and identity.get('error') is None,
            'actual macOS compiler did not qualify')
    require(type(identity.get('actual_version', {}).get('exit_code')) is int and
            identity['actual_version']['exit_code'] == 0, 'compiler observation failed')


def expected_binding(expected, report_bytes, compiler_bytes, qualifier_bytes):
    compiler = obj(compiler_bytes)
    return {'schema': 'hepta.ci.ui-venus-runtime-transfer.v1', **expected,
            'app_source_manifest_sha256': APP_SHA,
            'ci_helper_sha256': digest(read(__file__)),
            'original_build_helper_sha256': ORIGINAL_BUILDER_SHA,
            'original_build_receipt_sha256': ORIGINAL_RECEIPT_SHA,
            'new_build_receipt_sha256': digest(report_bytes),
            'compiler_qualifier_sha256': digest(qualifier_bytes),
            'compiler_identity_sha256': digest(compiler_bytes),
            'actual_compiler_container_sha256': compiler['macho']['sha256'],
            'worker_bytes': WORKER_BYTES, 'worker_sha256': WORKER_SHA,
            'worker_recompiled_on_macos': True, 'original_receipt_is_new_build_receipt': False,
            'original_worker_fully_verified': True, 'pins_modified': False,
            'app_source_modified': False, 'phone_contacted': False, 'model_inference_performed': False}


def write_new(path, data):
    with Path(path).open('xb') as stream:
        os.chmod(path, 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def execute(args):
    expected = source_identity(args.source_head, args.run_id, args.run_attempt)
    app, api, pins, native, original_bytes = frozen_app(args.app_source)
    original = obj(original_bytes)
    qualifier_bytes = read(args.compiler_qualifier)
    qualifier = load(args.compiler_qualifier, 'ui_venus_ci_compiler_qualifier')
    bundle = args.bundle.resolve()
    if args.operation == 'build':
        require(platform.system() == 'Darwin', 'independent worker build requires the actual macOS producer')
        require(args.ndk is not None and args.sdk_libs is not None and args.compiler_identity is not None,
                'build dependencies and actual compiler identity are required')
        require(not bundle.exists(), 'new independent build output required')
        bundle.mkdir(parents=True)
        compiler_bytes = read(args.compiler_identity)
        compiler = obj(compiler_bytes)
        check_compiler(compiler, qualifier)
        ndk = args.ndk.resolve(strict=True)
        clang = ndk / 'toolchains/llvm/prebuilt/darwin-x86_64/bin/clang'
        require(digest(read(clang.resolve(), 512 * 1024 * 1024)) == compiler['macho']['sha256'],
                'compiler observation belongs to different bytes')
        child = bundle / 'actual-build'
        command = [sys.executable, '-B', str(native / 'tools/build_android.py'),
                   '--source', str(native), '--ndk', str(ndk),
                   '--sdk-libs', str(args.sdk_libs.resolve(strict=True)), '--output', str(child)]
        environment = dict(os.environ)
        for key in REMOVED_ENV:
            environment.pop(key, None)
        result = subprocess.run(command, capture_output=True, env=environment, timeout=600)
        write_new(bundle / 'actual-build.stdout', result.stdout)
        write_new(bundle / 'actual-build.stderr', result.stderr)
        require(result.returncode == 0, 'actual original worker compiler failed')
        report_bytes = read(child / 'BUILD-RECEIPT.json')
        report = obj(report_bytes)
        check_new_report(report, original, pins)
        worker = read(child / WORKER, WORKER_BYTES)
        require(len(worker) == WORKER_BYTES and digest(worker) == WORKER_SHA,
                'new worker failed the complete original-byte gate')
        frozen_app(app)
        runtime = bundle / 'runtime'
        runtime.mkdir()
        write_new(runtime / WORKER, worker)
        write_new(runtime / 'BUILD-RECEIPT.json', original_bytes)
        write_new(bundle / NEW_REPORT, report_bytes)
        write_new(bundle / COMPILER, compiler_bytes)
        api.verify_ui_venus_runtime(app, runtime)
        binding = expected_binding(expected, report_bytes, compiler_bytes, qualifier_bytes)
        write_new(bundle / CURRENT, (json.dumps(binding, indent=2) + '\n').encode())
    else:
        require(platform.system() == 'Linux', 'consumer qualification must run on Linux')
        require(args.ndk is None and args.sdk_libs is None and args.compiler_identity is None,
                'consumer must use only the bound producer evidence')
        require(not bundle.is_symlink() and bundle.is_dir(), 'real transfer directory required')
        require({path.name for path in bundle.iterdir()} == {'runtime', NEW_REPORT, CURRENT, COMPILER},
                'unexpected transferred member')
        runtime = bundle / 'runtime'
        require(not runtime.is_symlink() and runtime.is_dir() and
                {path.name for path in runtime.iterdir()} == {WORKER, 'BUILD-RECEIPT.json'},
                'unexpected runtime member')
        api.verify_ui_venus_runtime(app, runtime)
        report_bytes = read(bundle / NEW_REPORT)
        check_new_report(obj(report_bytes), original, pins)
        compiler_bytes = read(bundle / COMPILER)
        check_compiler(obj(compiler_bytes), qualifier)
        binding = expected_binding(expected, report_bytes, compiler_bytes, qualifier_bytes)
        require(obj(read(bundle / CURRENT)) == binding, 'runtime belongs to a different source, run or attempt')
    print(json.dumps({**binding, 'operation': args.operation, 'verifier_host': platform.system(),
                      'original_assembler_allowed': True, 'runtime_directory': str(runtime)}))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('build', 'verify'))
    parser.add_argument('--app-source', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--compiler-qualifier', type=Path, required=True)
    parser.add_argument('--source-head', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--run-attempt', required=True)
    parser.add_argument('--compiler-identity', type=Path)
    parser.add_argument('--ndk', type=Path)
    parser.add_argument('--sdk-libs', type=Path)
    return execute(parser.parse_args())


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'state': 'rejected', 'original_assembler_allowed': False,
                          'error': type(error).__name__ + ': ' + str(error)}))
        raise SystemExit(2)
