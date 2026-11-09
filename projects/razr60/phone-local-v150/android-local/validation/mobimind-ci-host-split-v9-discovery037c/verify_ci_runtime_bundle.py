#!/usr/bin/env python3
"""Bind a real macOS rebuild to this CI run, then reverify it on Linux.

This transport verifier never builds or edits an ELF, downloads a runtime,
changes a pin, or substitutes a report for complete payload verification.
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
import stat

HELPER_SHA = 'c6a6af2b0f6995a57e202d7b39263285890f70641de5b77cad635afab909566e'
APP_SHA = 'eb85ee802f2718233553281529cc7c8cc166b6a37c0c09a3a3c58b75b0e4a26e'
MAC_CLANG_SHAS = {
    'ff1800041e683dd1c51ce470a291669a67d6cdee1258c409db33c4124dd175f6',
    '9f980ecd6dd9e20641589dfd653b2cccbc3f09808f0809387e9673747285a3b3',
}
CURRENT = 'CURRENT-CI-SOURCE.json'
NEW_REPORT = 'NEW-BUILD-RECEIPT.json'
COMPILER = 'COMPILER-IDENTITY.json'


def require(value, message):
    if value is not True:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path, maximum=1048576):
    path = Path(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                0 < before.st_size <= maximum, 'bounded single-link regular metadata required')
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(len(data) == before.st_size and identity(before) == identity(after) == identity(os.lstat(path)),
            'metadata changed during read')
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


def check_report(report):
    for key in ('source_build_completed', 'original_runtime_byte_identity', 'original_assembler_allowed',
                'mnn_library_rebuilt', 'worker_rebuilt', 'original_receipt_copied_unchanged'):
        require(report.get(key) is True, 'incomplete original-runtime rebuild: ' + key)
    for key in ('phone_contacted', 'pins_modified', 'elf_rewritten', 'app_source_modified'):
        require(report.get(key) is False, 'unexpected rebuild mutation: ' + key)
    require(report.get('state') == 'exact_original_runtime_rebuilt' and
            type(report.get('process_exit_code')) is int and report['process_exit_code'] == 0,
            'rebuild did not pass the exact original-byte gate')
    require(report.get('app_manifest_sha256') == APP_SHA and report.get('helper_sha256') == HELPER_SHA,
            'rebuild source/helper differs')
    require(report.get('ndk_revision_observed') == '28.1.13356709', 'actual NDK revision differs')
    toolchain = report.get('toolchain', {})
    require(toolchain.get('host_tag') == 'darwin-x86_64' and toolchain.get('clang_sha256') in MAC_CLANG_SHAS,
            'runtime was not rebuilt with a recognized actual macOS compiler container')


def check_compiler(report, identity):
    qualifier = load(Path(__file__).with_name('qualify_macos_compiler.py'), 'macho_compiler_qualification')
    qualifier.check_identity(identity)
    require(identity.get('qualified') is True and identity.get('compiler_bytes_outside_signatures_identical') is True
            and identity.get('binary_rewritten') is False and identity.get('error') is None,
            'compiler byte comparison did not qualify')
    require(type(identity.get('actual_version', {}).get('exit_code')) is int and
            identity['actual_version']['exit_code'] == 0, 'compiler observation failed')
    require(identity['macho']['sha256'] == report['toolchain']['clang_sha256'], 'compiler report is for different bytes')
    require(identity.get('original_container_byte_identical') is (identity['macho']['sha256'] == qualifier.ORIGINAL_SHA),
            'compiler container identity label differs')


def source_identity(head, run, attempt):
    require(re.fullmatch(r'[0-9a-f]{40}', head) is not None, 'exact source HEAD required')
    require(re.fullmatch(r'[1-9][0-9]*', run) is not None and
            re.fullmatch(r'[1-9][0-9]*', attempt) is not None, 'current workflow run/attempt required')
    return {'source_head_sha': head, 'github_run_id': run, 'github_run_attempt': attempt}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('bind', 'verify'))
    parser.add_argument('--app-source', type=Path, required=True)
    parser.add_argument('--rebuild-helper', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--source-head', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--run-attempt', required=True)
    parser.add_argument('--compiler-identity', type=Path,
                        help='producer-only read-only observation of the actual compiler')
    args = parser.parse_args()
    expected = source_identity(args.source_head, args.run_id, args.run_attempt)
    require(digest(read(args.rebuild_helper)) == HELPER_SHA, 'pinned rebuild helper changed')
    helper = load(args.rebuild_helper, 'fixed_mnn_rebuilder')
    app = helper.verify_frozen_source(args.app_source)
    runtime_api = load(app / 'tools/verify_mobimind_runtime.py', 'frozen_mnn_runtime_verifier')
    bundle = args.bundle.resolve(strict=True)
    runtime = bundle / 'runtime'
    require(not runtime.is_symlink() and runtime.is_dir(), 'real runtime directory required')
    original = runtime_api.verify_mobimind_runtime(app, runtime)
    report_bytes = read(bundle / NEW_REPORT)
    report = obj(report_bytes)
    check_report(report)
    if args.operation == 'bind':
        require(args.compiler_identity is not None, 'producer compiler identity is required')
        compiler_bytes = read(args.compiler_identity)
    else:
        require(args.compiler_identity is None, 'consumer must use the bound compiler report')
        compiler_bytes = read(bundle / COMPILER)
    compiler = obj(compiler_bytes)
    check_compiler(report, compiler)
    binding = {'schema': 'hepta.ci.mac-runtime-transfer.v2', **expected,
               'runtime_build_host': 'macOS', 'runtime_build_host_tag': 'darwin-x86_64',
               'runtime_compiled_on_linux': False, 'app_source_manifest_sha256': APP_SHA,
               'rebuild_helper_sha256': HELPER_SHA, 'new_build_receipt_sha256': digest(report_bytes),
               'compiler_identity_sha256': digest(compiler_bytes),
               'actual_compiler_container_sha256': compiler['macho']['sha256'],
               'compiler_bytes_outside_signatures_identical': True,
               'original_payloads_fully_verified': True}
    expected_runtime_names = {value['source_name'] for value in original.values()} | {'BUILD-RECEIPT.json'}
    require({p.name for p in runtime.iterdir()} == expected_runtime_names, 'unexpected runtime member')
    if args.operation == 'bind':
        require(platform.system() == 'Darwin', 'producer binding must run on the actual macOS build host')
        with (bundle / COMPILER).open('xb') as stream:
            os.chmod(bundle / COMPILER, 0o600)
            stream.write(compiler_bytes)
            stream.flush()
            os.fsync(stream.fileno())
        with (bundle / CURRENT).open('xb') as stream:
            os.chmod(bundle / CURRENT, 0o600)
            stream.write((json.dumps(binding, indent=2) + '\n').encode())
            stream.flush()
            os.fsync(stream.fileno())
    else:
        require(platform.system() == 'Linux', 'consumer qualification must run on Linux')
        current = obj(read(bundle / CURRENT))
        require(type(current) is dict and json.dumps(current, sort_keys=True) == json.dumps(binding, sort_keys=True),
                'artifact belongs to a different source/run/build receipt')
        require({p.name for p in bundle.iterdir()} == {'runtime', CURRENT, NEW_REPORT, COMPILER}, 'unexpected transfer member')
    print(json.dumps({**binding, 'operation': args.operation, 'verifier_host': platform.system(),
                      'original_assembler_allowed': True, 'runtime_directory': str(runtime)}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'state': 'rejected', 'original_assembler_allowed': False,
                          'error': type(error).__name__ + ': ' + str(error)}))
        raise SystemExit(2)
