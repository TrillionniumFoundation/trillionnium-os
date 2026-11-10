#!/usr/bin/env python3
"""One isolated compiler/linker reproduction; no patching or rewriting an ELF."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time

BASE = Path('/Users/qianqi/Documents/Codex/2026-11-08')
ORIGINAL = BASE / 'mobiinfer-dda84ccf-r1'
OLD_BUILD = ORIGINAL / 'opencl-probe-build-r4/probe-build'
OLD_SOURCE = ORIGINAL / 'opencl-probe-build-r4/mobimind-opencl-probe-r4'
CI_OUT = BASE / 'hepta-mnn-ci-rebuild-dda84ccf-r1/out'
OUT = BASE / 'hepta-mnn-worker-path-repro-dda84ccf-r1'
EXPECTED = 'b3899c03f88070e0042132dc9f17d81437d2b018c3406598f97939fc52ff9020'
EXPECTED_MNN = '5019009bfc9b209afeb89d23db0f1c52985cc1111e3364a448f7c7ed7a4c457d'
EXPECTED_MANIFEST = 'b642269f327219c23d9fd778621921c85fd19cb8a35def970e5097ca88d2d8f5'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def checked(path, expected):
    raw = path.read_bytes()
    if sha(raw) != expected:
        raise ValueError('Source identity differs: ' + str(path))
    return raw


def main():
    OUT.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {'schema': 'hepta.mobimind.worker-debug-path-reproduction.v1',
              'original_elf_sha256': EXPECTED, 'phone_contacted': False,
              'elf_rewritten': False, 'original_source_modified': False,
              'compiler_rebuilt': False, 'linker_rebuilt': False,
              'original_assembler_allowed': False, 'errors': [], 'commands': []}
    try:
        manifest_raw = checked(OLD_SOURCE / 'SOURCE-MANIFEST.json', EXPECTED_MANIFEST)
        manifest = json.loads(manifest_raw)
        source = OUT / 'worker-source'
        source.mkdir(mode=0o700)
        inputs = []
        for pin in manifest['files']:
            rel = Path(pin['path'])
            if rel.is_absolute() or '..' in rel.parts:
                raise ValueError('Nonrelative manifest path')
            raw = checked(OLD_SOURCE / rel, pin['sha256'])
            if len(raw) != pin['bytes']:
                raise ValueError('Member size differs')
            dest = source / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
            inputs.append({'path': str(rel), 'bytes': len(raw), 'sha256': sha(raw)})
        (source / 'SOURCE-MANIFEST.json').write_bytes(manifest_raw)
        original_elf = checked(OLD_BUILD / 'hepta-mobimind-probe', EXPECTED)
        compile_raw = checked(OLD_BUILD / 'compile_commands.json',
                              '8a67350afdd6c22035e4d5a411b53b16b47ca5c9f32aae74d95e6c405018cb8d')
        compile_record, = json.loads(compile_raw)
        link_raw = checked(OLD_BUILD / 'CMakeFiles/hepta-mobimind-probe.dir/link.txt',
                           'c2c2955a6a5d1ac38b8e433c6bdac160322e2aee24a673075ff51ca8707f7294')
        compiler = Path(shlex.split(compile_record['command'])[0])
        checked(compiler, 'ff1800041e683dd1c51ce470a291669a67d6cdee1258c409db33c4124dd175f6')
        mnn = CI_OUT / 'mnn-build/libMNN.so'
        checked(mnn, EXPECTED_MNN)
        # Include files use the separately rebuilt fixed-source tree. Their
        # exact bytes are compared with the original compiler dependency list.
        mnn_source = CI_OUT / 'mnn-source'
        old_mnn_source = ORIGINAL / 'source'
        dep_raw = (OLD_BUILD / 'CMakeFiles/hepta-mobimind-probe.dir/native/worker.cpp.o.d').read_bytes()
        dep_text = dep_raw.decode().replace('\\\n', '')
        if ': ' not in dep_text:
            raise ValueError('Original compiler dependency list unavailable')
        dependencies = []
        for value in shlex.split(dep_text.split(': ', 1)[1]):
            old = Path(value)
            if str(old).startswith(str(OLD_SOURCE) + '/'):
                new = source / old.relative_to(OLD_SOURCE)
            elif str(old).startswith(str(old_mnn_source) + '/'):
                new = mnn_source / old.relative_to(old_mnn_source)
            else:
                new = old
            a, b = old.read_bytes(), new.read_bytes()
            if a != b:
                raise ValueError('Compiler header input differs: ' + str(old))
            dependencies.append({'original_path': str(old), 'new_path': str(new),
                                 'bytes': len(a), 'sha256': sha(a)})
        build = OUT / 'worker-build'
        build.mkdir(mode=0o700)
        (build / 'CMakeFiles/hepta-mobimind-probe.dir/native').mkdir(parents=True)
        mappings = [(source, OLD_SOURCE), (build, OLD_BUILD), (mnn_source, old_mnn_source)]
        flags = [flag + str(a) + '=' + str(b)
                 for a, b in mappings for flag in ('-fdebug-prefix-map=', '-ffile-prefix-map=')]
        compile_cmd = shlex.split(compile_record['command'])
        compile_cmd = [x.replace(str(OLD_SOURCE), str(source)).replace(str(old_mnn_source), str(mnn_source))
                       for x in compile_cmd]
        compile_cmd += flags
        # CMake's link.txt is a shell spelling. Only its observed escaped dollar
        # in $ORIGIN needs decoding; use argv execution rather than a shell.
        link_cmd = shlex.split(link_raw.decode())
        origin = '-Wl,-rpath,\\$ORIGIN'
        if link_cmd.count(origin) != 1:
            raise ValueError('Original unique origin argument differs')
        old_mnn = str(ORIGINAL / 'opencl-probe-build-r2/mnn-build/libMNN.so')
        if link_cmd.count(old_mnn) != 1:
            raise ValueError('Original MNN linker input differs')
        link_cmd = ['-Wl,-rpath,$ORIGIN' if x == origin else str(mnn) if x == old_mnn else x for x in link_cmd]
        env = dict(os.environ)
        removed = []
        for key in ('CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'CPATH', 'C_INCLUDE_PATH',
                    'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH', 'SDKROOT', 'MACOSX_DEPLOYMENT_TARGET'):
            if key in env:
                removed.append(key)
                del env[key]
        for stage, cmd in [('compile', compile_cmd), ('link', link_cmd)]:
            started = time.monotonic()
            run = subprocess.run(cmd, cwd=build, env=env, capture_output=True, timeout=120)
            (OUT / (stage + '.stdout')).write_bytes(run.stdout)
            (OUT / (stage + '.stderr')).write_bytes(run.stderr)
            report['commands'].append({'stage': stage, 'argv': cmd, 'cwd': str(build),
                                       'exit_code': run.returncode, 'elapsed_seconds': round(time.monotonic()-started, 3),
                                       'stdout_sha256': sha(run.stdout), 'stderr_sha256': sha(run.stderr)})
            if run.returncode:
                raise ValueError('Compiler/linker failed: ' + stage)
            report['compiler_rebuilt' if stage == 'compile' else 'linker_rebuilt'] = True
        rebuilt = (build / 'hepta-mobimind-probe').read_bytes()
        report.update(removed_build_environment_keys=removed, prefix_mappings=[{'from': str(a), 'to': str(b)} for a,b in mappings],
                      worker_source_manifest_sha256=EXPECTED_MANIFEST, source_members=inputs,
                      compiler_dependencies=dependencies, original_dependency_sha256=sha(dep_raw),
                      rebuilt_sha256=sha(rebuilt), rebuilt_bytes=len(rebuilt),
                      original_bytes=len(original_elf), exact_original_bytes=rebuilt == original_elf,
                      original_assembler_allowed=rebuilt == original_elf)
        report['state'] = 'byte_identical' if rebuilt == original_elf else 'byte_identity_mismatch'
    except Exception as exc:
        report['state'] = 'failed'
        report['errors'].append(type(exc).__name__ + ': ' + str(exc))
    (OUT / 'REPORT.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ('compiler_dependencies','source_members','commands')}, ensure_ascii=False))
    return 0 if report.get('exact_original_bytes') else 3


if __name__ == '__main__':
    sys.exit(main())
