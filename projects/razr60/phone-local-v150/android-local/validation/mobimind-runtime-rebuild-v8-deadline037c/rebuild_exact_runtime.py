#!/usr/bin/env python3
"""Rebuild the pinned MNN/r4 closure, then require all three original ELF hashes.

No download, APK assembly, phone, release, or pin rewrite is performed here.
The input MNN Git repository is read through a local, non-hardlinked clone.
The only modified source is the new independent build checkout.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time

APP_MANIFEST_SHA = 'fdab3c67d726aa44c19c9efe4d65cc845ee433dbabe2d97f7fe7fb07b92bcec7'
MNN_COMMIT = 'bce7456ce60b5e51b4d3b357f303515860353d8c'
MNN_REPOSITORY = 'https://github.com/doulujiyao12/mobiinfer'
# The original directory was NAMED 28.2.13676358. Its actual source.properties
# and cached compiler are r28b; do not infer a package revision from its path.
NDK_REVISION = '28.1.13356709'
ORIGINAL_CMAKE_VERSION = '4.3.2'
ORIGINAL_RECEIPT_SHA = '86c25f372be4b47ce1b6563919434a035f5fd171a8a993e09ac08d7fba0bbbab'
WORKER_MANIFEST_SHA = 'b642269f327219c23d9fd778621921c85fd19cb8a35def970e5097ca88d2d8f5'
# These paths are compiler debug-data destinations from the retained original
# build. They are not writable build locations and need not exist on a CI host.
ORIGINAL_ROOT = '/Users/qianqi/Documents/Codex/2026-11-08/mobiinfer-dda84ccf-r1'
ORIGINAL_WORKER_SOURCE = ORIGINAL_ROOT + '/opencl-probe-build-r4/mobimind-opencl-probe-r4'
ORIGINAL_WORKER_BUILD = ORIGINAL_ROOT + '/opencl-probe-build-r4/probe-build'
ORIGINAL_MNN_SOURCE = ORIGINAL_ROOT + '/source'
ORIGINAL_NDK_PREBUILT = '/Users/qianqi/Library/Android/sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/darwin-x86_64'
MNN_OPTIONS = [
    '-DCMAKE_CXX_STANDARD=17', '-DCMAKE_POLICY_VERSION_MINIMUM=3.5',
    '-DMNN_BUILD_SHARED_LIBS=ON', '-DMNN_SEP_BUILD=OFF', '-DMNN_BUILD_FOR_ANDROID_COMMAND=ON',
    '-DMNN_OPENCL=ON', '-DMNN_BUILD_LLM=ON', '-DMNN_BUILD_LLM_OMNI=ON',
    '-DMNN_BUILD_OPENCV=ON', '-DMNN_IMGCODECS=ON', '-DMNN_BUILD_TOOLS=OFF',
    '-DMNN_BUILD_DEMO=OFF', '-DMNN_LLM_BUILD_DEMO=OFF', '-DLLM_SUPPORT_HTTP_RESOURCE=OFF',
    '-DBUILD_MLS=OFF', '-DMNN_QNN=OFF', '-DMNN_HIAI=OFF', '-DMNN_SME2=OFF', '-DMNN_USE_LOGCAT=OFF',
]
REMOVED_BUILD_ENV = ('CC', 'CXX', 'CPP', 'AS', 'AR', 'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS',
                     'LD_PRELOAD', 'LD_LIBRARY_PATH', 'CMAKE_PREFIX_PATH', 'CMAKE_TOOLCHAIN_FILE',
                     'CMAKE_GENERATOR', 'CMAKE_GENERATOR_TOOLSET', 'CMAKE_GENERATOR_PLATFORM',
                     'CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH', 'SDKROOT',
                     'MACOSX_DEPLOYMENT_TARGET')


def worker_debug_path_flags(worker_source, worker_build, mnn_source, ndk_prebuilt):
    """Reproduce only recorded debug/file path spelling, never edit an ELF."""
    mappings = [(str(worker_source), ORIGINAL_WORKER_SOURCE),
                (str(worker_build), ORIGINAL_WORKER_BUILD),
                (str(mnn_source), ORIGINAL_MNN_SOURCE)]
    if str(ndk_prebuilt) != ORIGINAL_NDK_PREBUILT:
        mappings.append((str(ndk_prebuilt), ORIGINAL_NDK_PREBUILT))
    flags = []
    for current, original in mappings:
        # A CMake cache flag string must round-trip to these exact arguments.
        # Reject exotic roots rather than letting whitespace or '=' change it.
        if not current.startswith('/') or any(c.isspace() or c in '=;\"\'\\' for c in current):
            raise ValueError('unsupported debug prefix path spelling: ' + current)
        flags += ['-fdebug-prefix-map=' + current + '=' + original,
                  '-ffile-prefix-map=' + current + '=' + original]
    return mappings, flags


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = value if isinstance(value, bytes) else (json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode()
    with path.open('xb') as stream:
        stream.write(data)


def module(path, name):
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def verify_frozen_source(root):
    root = Path(root).resolve(strict=True)
    manifest_file = root / 'SOURCE-MANIFEST.json'
    if sha(manifest_file) != APP_MANIFEST_SHA:
        raise ValueError('only the exact Code19 deadline037c candidate source is admitted')
    manifest = json.loads(manifest_file.read_bytes())
    if manifest['schema'] != 'hepta.local-source.v3':
        raise ValueError('source manifest schema differs')
    expected = set()
    for row in manifest['files']:
        relative = PurePosixPath(row['path'])
        if relative.is_absolute() or '..' in relative.parts or row['path'] in expected or row['path'] == 'SOURCE-MANIFEST.json':
            raise ValueError('invalid source manifest member')
        expected.add(row['path'])
        path = root / relative
        if path.resolve() != path or not path.is_file() or path.stat().st_size != row['bytes'] or sha(path) != row['sha256']:
            raise ValueError('frozen source changed: ' + row['path'])
    actual = {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()
              and p != manifest_file and p.relative_to(root).parts[0] not in ('out', '.git', 'keys')
              and not ('__pycache__' in p.parts and p.suffix == '.pyc')}
    if actual != expected:
        raise ValueError('unlisted or missing frozen source member')
    return root


def ndk_revision(text):
    matches = re.findall(r'^Pkg\.Revision\s*=\s*([0-9.]+)\s*$', text, re.M)
    if matches != [NDK_REVISION]:
        raise ValueError('actual source.properties revision is not pinned r28b: ' + repr(matches))
    return matches[0]


def compare_payloads(runtime, pins):
    rows = []
    for pin in pins['libraries']:
        path = runtime / pin['source_name']
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise ValueError('new payload must be a standalone regular file')
        size, digest = st.st_size, sha(path)
        rows.append({'name': pin['source_name'], 'bytes': size, 'sha256': digest,
                     'expected_bytes': pin['bytes'], 'expected_sha256': pin['sha256'],
                     'exact_original_bytes': size == pin['bytes'] and digest == pin['sha256']})
    if len(rows) != 3:
        raise ValueError('exactly three runtime members required')
    identity = hashlib.sha256(json.dumps([{k: r[k] for k in ('name', 'bytes', 'sha256')} for r in rows],
                                        sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return rows, all(row['exact_original_bytes'] for row in rows), identity


class Build:
    def __init__(self, args):
        self.args = args
        self.out = args.output.resolve()
        for source in (args.app_source, args.mnn_checkout, args.ndk):
            source = source.resolve()
            if self.out == source or source in self.out.parents:
                raise ValueError('output must be outside every original source/toolchain directory')
        self.out.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.env = dict(os.environ)
        removed = [key for key in REMOVED_BUILD_ENV if key in self.env]
        for key in REMOVED_BUILD_ENV:
            self.env.pop(key, None)
        self.env['GIT_LFS_SKIP_SMUDGE'] = '1'
        self.env['PYTHONDONTWRITEBYTECODE'] = '1'
        self.report = {'schema': 'hepta.mobimind.fixed-source-rebuild.v1', 'helper_revision': 'r8-code19-deadline037c-source', 'state': 'preflight',
                       'helper_sha256': sha(Path(__file__).resolve()),
                       'app_manifest_sha256': APP_MANIFEST_SHA, 'mnn_source_commit': MNN_COMMIT,
                       'mnn_repository': MNN_REPOSITORY, 'ndk_revision_required': NDK_REVISION,
                       'original_ndk_directory_name_is_not_revision': True,
                       'source_build_completed': False, 'original_runtime_byte_identity': False,
                       'original_assembler_allowed': False, 'phone_contacted': False, 'android_execution_performed': False,
                       'model_inference_performed': False, 'apk_assembled': False, 'runtime_uploaded': False,
                       'app_source_modified': False, 'pins_modified': False, 'elf_rewritten': False,
                       'removed_build_environment_keys': removed,
                       'commands': [], 'errors': []}
        self.child = None

    def run(self, argv, label, cwd=None, timeout=2400):
        argv = [str(value) for value in argv]
        record = {'stage': label, 'argv': argv, 'cwd': str(cwd or self.out)}
        self.report['commands'].append(record)
        print(json.dumps({'event': 'command_start', **record}), flush=True)
        started, last = time.monotonic(), time.monotonic()
        log = self.out / (label + '.log')
        with log.open('xb') as stream:
            self.child = subprocess.Popen(argv, cwd=cwd or self.out, env=self.env, stdout=stream,
                                          stderr=subprocess.STDOUT, start_new_session=True)
            try:
                while self.child.poll() is None:
                    now = time.monotonic()
                    if now - started > timeout:
                        raise TimeoutError(label + ' exceeded bounded build time')
                    if now - last > 30:
                        print(json.dumps({'event': 'build_progress', 'stage': label,
                                          'elapsed_seconds': round(now - started, 1), 'log_bytes': log.stat().st_size}), flush=True)
                        last = now
                    time.sleep(0.2)
                record['exit_code'] = self.child.returncode
            finally:
                if self.child.poll() is None:
                    # Only this explicitly created isolated host build process group.
                    os.killpg(self.child.pid, signal.SIGTERM)
                    try:
                        self.child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(self.child.pid, signal.SIGKILL)
                        self.child.wait(timeout=5)
                self.child = None
        record['elapsed_seconds'] = round(time.monotonic() - started, 3)
        record['log_sha256'] = sha(log)
        print(json.dumps({'event': 'command_exit', 'stage': label, 'exit_code': record['exit_code'],
                          'elapsed_seconds': record['elapsed_seconds']}), flush=True)
        if record['exit_code']:
            raise RuntimeError(label + ' failed; exact output retained in ' + log.name)
        return log.read_text(errors='replace')

    def prepare(self):
        self.app = verify_frozen_source(self.args.app_source)
        self.verify_api = module(self.app / 'tools/verify_mobimind_runtime.py', 'frozen_mobimind_runtime')
        self.pins = self.verify_api.load_pins(self.app)
        receipt_path = self.app / 'provenance/mobimind-worker-r4-build.json'
        if sha(receipt_path) != ORIGINAL_RECEIPT_SHA or self.pins['build_receipt_sha256'] != ORIGINAL_RECEIPT_SHA:
            raise ValueError('original retained receipt differs')
        self.original_receipt = json.loads(receipt_path.read_bytes())
        self.ndk = self.args.ndk.resolve(strict=True)
        properties = (self.ndk / 'source.properties').read_text()
        self.report['ndk_properties'] = properties
        self.report['ndk_directory'] = str(self.ndk)
        self.report['ndk_source_properties_sha256'] = sha(self.ndk / 'source.properties')
        self.report['ndk_revision_observed'] = ndk_revision(properties)
        host = {'Linux': 'linux-x86_64', 'Darwin': 'darwin-x86_64'}.get(platform.system())
        if host is None:
            raise ValueError('Linux or macOS NDK host required')
        self.prebuilt = self.ndk / 'toolchains/llvm/prebuilt' / host
        self.toolchain = self.ndk / 'build/cmake/android.toolchain.cmake'
        self.clang = self.prebuilt / 'bin/clang'
        self.readelf = self.prebuilt / 'bin/llvm-readelf'
        self.objdump = self.prebuilt / 'bin/llvm-objdump'
        self.cxx = self.prebuilt / 'sysroot/usr/lib/aarch64-linux-android/libc++_shared.so'
        self.cmake = Path(self.args.cmake or shutil.which('cmake') or '').resolve(strict=True)
        for path in (self.toolchain, self.clang, self.readelf, self.objdump, self.cxx, self.cmake):
            if not path.is_file():
                raise ValueError('required cached toolchain member absent: ' + str(path))
        version = self.run([self.cmake, '--version'], 'cmake-version', timeout=30).splitlines()[0]
        match = re.fullmatch(r'cmake version ([0-9]+)\.([0-9]+)\.([0-9]+)(?:-.*)?', version)
        if not match or tuple(map(int, match.groups())) < (3, 22, 0):
            raise ValueError('CMake 3.22 or newer required')
        clang_version = self.run([self.clang, '--version'], 'clang-version', timeout=30)
        if not all(token in clang_version for token in ('Android (13324770,', 'based on r530567d)', 'clang version 19.0.0')):
            raise ValueError('compiler family differs from the actual original r28b cache')
        self.report['toolchain'] = {'host_tag': host, 'clang_version': clang_version, 'clang_sha256': sha(self.clang),
                                    'cmake_version': version, 'cmake_sha256': sha(self.cmake),
                                    'matches_original_cmake_version': match.group(0) == 'cmake version ' + ORIGINAL_CMAKE_VERSION,
                                    'toolchain_file_sha256': sha(self.toolchain), 'libcxx_sha256': sha(self.cxx)}
        cache = self.args.mnn_checkout.resolve(strict=True)
        commit = self.run(['git', '-C', cache, 'rev-parse', MNN_COMMIT + '^{commit}'], 'cached-mnn-commit', timeout=30).strip()
        if commit != MNN_COMMIT:
            raise ValueError('fixed MNN commit not present in the local Git cache')
        self.mnn = self.out / 'mnn-source'
        # A non-hardlinked local clone preserves Git version discovery while neither
        # altering the original checkout nor borrowing its patched working-tree bytes.
        self.run(['git', '-c', 'init.templateDir=', '-c', 'core.hooksPath=/dev/null', 'clone',
                  '--no-hardlinks', '--no-checkout', str(cache), self.mnn], 'clone-mnn', timeout=180)
        self.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.autocrlf=false', '-C', self.mnn,
                  'checkout', '--detach', MNN_COMMIT], 'checkout-mnn', timeout=180)
        if self.run(['git', '-C', self.mnn, 'status', '--porcelain'], 'clean-mnn', timeout=30).strip():
            raise ValueError('independent source checkout is not clean')
        self.worker = self.out / 'worker-source'
        original = self.app / 'provenance/mobimind-worker-r4'
        if sha(original / 'SOURCE-MANIFEST.json') != WORKER_MANIFEST_SHA:
            raise ValueError('worker manifest identity differs')
        shutil.copytree(original, self.worker)
        patch = module(self.worker / 'patch_runtime.py', 'pinned_observer_transform')
        if patch.REVISION != MNN_COMMIT:
            raise ValueError('observer source revision differs')
        transformed = patch.apply(self.mnn)
        if set(transformed) != set(self.original_receipt['source_qualification']):
            raise ValueError('observer membership differs')
        for name, row in transformed.items():
            old = self.original_receipt['source_qualification'][name]
            if row['upstream_sha256'] != old['upstream_sha256'] or row['patched_sha256'] != old['existing_telemetry_sha256']:
                raise ValueError('observer transformation bytes differ: ' + name)
        self.report['observer_transforms'] = transformed
        self.report['mnn_license_sha256'] = sha(self.mnn / 'LICENSE.txt')
        write(self.out / 'source-qualification.json', {'commit': commit, 'transforms': transformed,
                                                       'worker_manifest_sha256': WORKER_MANIFEST_SHA})

    def build(self):
        common = ['-G', 'Unix Makefiles', '-DCMAKE_TOOLCHAIN_FILE=' + str(self.toolchain),
                  '-DANDROID_ABI=arm64-v8a', '-DANDROID_PLATFORM=android-26',
                  '-DANDROID_STL=c++_shared', '-DCMAKE_BUILD_TYPE=Release']
        mnn_build, worker_build = self.out / 'mnn-build', self.out / 'worker-build'
        self.run([self.cmake, '-S', self.mnn, '-B', mnn_build, *common, *MNN_OPTIONS], 'configure-mnn')
        cache = (mnn_build / 'CMakeCache.txt').read_text()
        for option in MNN_OPTIONS:
            name, expected = option[2:].split('=', 1)
            if re.findall(r'^' + re.escape(name) + r':[A-Z_]+=(.*)$', cache, re.M) != [expected]:
                raise ValueError('actual MNN CMake option differs: ' + name)
        self.run([self.cmake, '--build', mnn_build, '--target', 'MNN', '--parallel', '6'], 'build-mnn')
        library = mnn_build / 'libMNN.so'
        mappings, debug_flags = worker_debug_path_flags(self.worker, worker_build, self.mnn, self.prebuilt)
        # The pinned r28b toolchain prepends its own -O3 -DNDEBUG to the cache
        # value. Supply only extra debug mappings, then verify the final argv
        # still contains exactly one copy of the original optimization flags.
        release_flags = ' '.join(debug_flags)
        self.report['worker_debug_prefix_mappings'] = [{'from': a, 'to': b} for a, b in mappings]
        self.report['worker_debug_prefix_flags'] = debug_flags
        self.run([self.cmake, '-S', self.worker, '-B', worker_build, *common, '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
                  '-DCMAKE_CXX_FLAGS_RELEASE=' + release_flags,
                  '-DMNN_SOURCE=' + str(self.mnn), '-DMNN_LIBRARY=' + str(library)], 'configure-worker')
        self.run([self.cmake, '--build', worker_build, '--parallel', '2'], 'build-worker')
        commands = json.loads((worker_build / 'compile_commands.json').read_bytes())
        if len(commands) != 1 or not commands[0]['file'].endswith('/native/worker.cpp'):
            raise ValueError('unexpected worker compilation units')
        command = commands[0].get('command', ' '.join(commands[0].get('arguments', [])))
        actual_argv = commands[0].get('arguments') or shlex.split(command)
        if any(actual_argv.count(flag) != 1 for flag in debug_flags) or '-g' not in actual_argv:
            raise ValueError('actual compiler did not receive the exact debug path maps and original -g')
        if actual_argv.count('-O3') != 1 or actual_argv.count('-DNDEBUG') != 1:
            raise ValueError('original Release optimization flags changed')
        write(self.out / 'worker-compile-commands.json', commands)
        if re.search(r'(?:-march=\S*\+(?:crypto|sha2)|-mattr=\S*\+sha2)', command):
            raise ValueError('SHA2 was enabled globally instead of in the guarded function')
        runtime = self.out / 'candidate-runtime'
        runtime.mkdir()
        for source in (worker_build / 'hepta-mobimind-probe', library, self.cxx):
            shutil.copy2(source, runtime / source.name)
        rows, matches, identity = compare_payloads(runtime, self.pins)
        self.report.update(source_build_completed=True, libraries=rows, runtime_content_identity_sha256=identity,
                           original_runtime_byte_identity=matches, new_runtime_candidate=not matches,
                           mnn_library_rebuilt=True, worker_rebuilt=True, cxx_library_rebuilt=False)
        write(self.out / 'three-elf-comparison.json', {'libraries': rows, 'all_exact_original_bytes': matches,
                                                      'new_runtime_candidate': not matches, 'runtime_content_identity_sha256': identity})
        self.inspect(runtime)
        verify_frozen_source(self.app)
        if matches:
            # This remains the unchanged ORIGINAL provenance, not a fabricated
            # receipt of this new build. The new build has its own separate report.
            exact = self.out / 'runtime'
            exact.mkdir()
            for pin in self.pins['libraries']:
                shutil.copy2(runtime / pin['source_name'], exact / pin['source_name'])
            shutil.copy2(self.app / 'provenance/mobimind-worker-r4-build.json', exact / 'BUILD-RECEIPT.json')
            self.verify_api.verify_mobimind_runtime(self.app, exact)
            self.report.update(state='exact_original_runtime_rebuilt', original_assembler_allowed=True,
                               exact_runtime_directory=str(exact), original_receipt_copied_unchanged=True,
                               original_receipt_is_new_build_receipt=False)
            return 0
        self.report.update(state='new_runtime_candidate_bytes_differ', original_assembler_allowed=False,
                           original_receipt_copied_unchanged=False,
                           next_step='separate candidate review and new Android/device qualification; original pins remain unchanged')
        return 3

    def inspect(self, runtime):
        results = []
        for pin in self.pins['libraries']:
            path = runtime / pin['source_name']
            with path.open('rb') as stream:
                header = stream.read(64)
            if header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != 183:
                raise ValueError('built runtime is not 64-bit little-endian AArch64 ELF')
            info = self.run([self.readelf, '-h', '-l', '-d', '--dyn-syms', '--wide', path], pin['source_name'] + '-elf', timeout=60)
            needed = re.findall(r'\(NEEDED\).*?\[([^]]+)\]', info)
            if needed != pin['needed']:
                raise ValueError('ELF dependency order/closure differs: ' + pin['source_name'])
            row = {'name': pin['source_name'], 'needed': needed, 'elf_class': 64, 'machine': 'AArch64'}
            if pin['source_name'] == 'hepta-mobimind-probe':
                if int.from_bytes(header[16:18], 'little') != 3 or 'INTERP' not in info:
                    raise ValueError('worker is not an Android PIE executable')
                row['linker_policy'] = self.verify_api.verify_worker_linker_policy(info)
                if not any('getauxval' in line and 'UND' in line for line in info.splitlines()):
                    raise ValueError('runtime CPU capability gate import absent')
                for name in ('hepta_mnn_runtime', 'hepta_mnn_observe', 'hepta_mnn_input_ids'):
                    if not any(name in line and 'GLOBAL' in line and 'DEFAULT' in line and ' UND ' not in line for line in info.splitlines()):
                        raise ValueError('worker observational export absent: ' + name)
            if pin['source_name'] == 'libMNN.so':
                for name in ('hepta_mnn_runtime', 'hepta_mnn_observe', 'hepta_mnn_input_ids'):
                    if not any(name in line and 'WEAK' in line and 'DEFAULT' in line and 'UND' in line for line in info.splitlines()):
                        raise ValueError('MNN observation hook absent: ' + name)
            results.append(row)
        assembly = self.run([self.objdump, '-d', '--demangle', runtime / 'hepta-mobimind-probe'], 'worker-disassembly', timeout=120)
        function, instructions = '', []
        for line in assembly.splitlines():
            match = re.match(r'^\s*[0-9a-f]+ <(.+)>:$', line)
            if match:
                function = match.group(1)
            match = re.search(r'\b(sha256h2?|sha256su0|sha256su1)\b', line)
            if match:
                if 'hepta_sha256_armv8_blocks' not in function:
                    raise ValueError('SHA2 instruction escaped the capability-gated function')
                instructions.append(match.group(1))
        if set(instructions) != {'sha256h', 'sha256h2', 'sha256su0', 'sha256su1'}:
            raise ValueError('expected SHA2 implementation absent')
        self.report['static_runtime_evidence'] = {'libraries': results, 'sha2_instruction_count': len(instructions),
                                                  'sha2_only_in_guarded_function': True, 'actual_android_loading_proven': False}

    def execute(self):
        code = 2
        started = time.monotonic()
        def interrupted(signum, _frame):
            raise RuntimeError('host build interrupted by signal ' + str(signum))
        old = {s: signal.signal(s, interrupted) for s in (signal.SIGTERM, signal.SIGINT)}
        try:
            self.prepare()
            code = self.build()
        except Exception as error:
            self.report['state'] = 'failed'
            self.report['errors'].append(type(error).__name__ + ': ' + str(error))
        finally:
            self.report['elapsed_seconds'] = round(time.monotonic() - started, 3)
            self.report['process_exit_code'] = code
            write(self.out / 'NEW-BUILD-RECEIPT.json', self.report)
            print(json.dumps({k: self.report[k] for k in ('state', 'source_build_completed', 'original_runtime_byte_identity',
                                                         'original_assembler_allowed', 'errors')}), flush=True)
            for signum, handler in old.items():
                signal.signal(signum, handler)
        return code


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--app-source', type=Path, required=True)
    p.add_argument('--mnn-checkout', type=Path, required=True)
    p.add_argument('--ndk', type=Path, required=True)
    p.add_argument('--cmake')
    p.add_argument('--output', type=Path, required=True)
    return Build(p.parse_args()).execute()


if __name__ == '__main__':
    raise SystemExit(main())
