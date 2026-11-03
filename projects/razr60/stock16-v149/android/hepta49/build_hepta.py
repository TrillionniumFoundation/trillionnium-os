#!/usr/bin/env python3
"""Build HEPTA v47 from a frozen source snapshot; no phone operations.

The local profile produces an explicitly unsigned candidate. The pocket4 profile
can sign with --sign using the existing, certificate-matched platform key there.
No private key is imported, printed, or copied by this script.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import sys
import uuid
import zipfile

ROOT = Path(__file__).resolve().parent
PACKAGE = 'org.trillionnium.owneropen'
VERSION_CODE = 49
VERSION_NAME = '1.4.3'
APK_STEM = 'HEPTA-SystemUI-v49'
MIN_SDK = 36
TARGET_SDK = 37
CERT_SHA256 = 'c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8'


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def inventory(root: Path) -> list[dict]:
    files = [root / 'AndroidManifest.xml']
    files += sorted((root / 'src').rglob('*.java'))
    for folder in ('res', 'assets'):
        files += [p for p in (root / folder).rglob('*') if p.is_file()]
    if not (root / 'src').is_dir() or not (root / 'res').is_dir():
        raise RuntimeError('Expected a complete application source directory')
    result = []
    for p in sorted(files):
        if p.is_symlink() or not p.resolve().is_relative_to(root.resolve()):
            raise RuntimeError('Source must contain regular files within its root')
        result.append({'path': p.relative_to(root).as_posix(), 'bytes': p.stat().st_size, 'sha256': sha(p)})
    return result


def profile(name: str, args: argparse.Namespace) -> dict:
    if name == 'local':
        tools = (args.build_tools or ROOT / 'toolchain/build-tools/android-16').resolve()
        return {'java': ['java', '-XX:ActiveProcessorCount=2', '-Xmx2g'],
                'javac': ['java', '-XX:ActiveProcessorCount=2', '-Xmx2g', '-m', 'jdk.compiler/com.sun.tools.javac.Main'],
                'sdk': (args.android_jar or ROOT / 'toolchain/platform/android-36/android.jar').resolve(),
                'system': (args.system_modules or ROOT / 'toolchain/android-system-modules-r3/system').resolve(),
                'aapt2': tools / 'aapt2', 'zipalign': tools / 'zipalign',
                'd8': tools / 'lib/d8.jar', 'signer': tools / 'lib/apksigner.jar',
                'lib64': tools / 'lib64', 'cert': None, 'key': None}
    reference = Path('/home/alex/razr-flash-validation-canonical-20261014/staging/rog-r57-count8-source-and-build')
    aosp = reference / 'inputs/source_3'
    jdk = aosp / 'prebuilts/jdk/jdk21/linux-x86'
    tools = aosp / 'prebuilts/sdk/tools/linux'
    security = aosp / 'build/make/target/product/security'
    return {'java': [str(jdk / 'bin/java'), '-XX:ActiveProcessorCount=2', '-Xmx2g'],
            'javac': [str(jdk / 'bin/javac'), '-J-XX:ActiveProcessorCount=2', '-J-Xmx2g'],
            'sdk': aosp / 'prebuilts/sdk/current/public/android.jar',
            'system': reference / 'private/count8-native-636cdc93-1aaf-4c49-8c0d-88922aec6943/upper/soong/.intermediates/libcore/core-all-system-modules/android_common/system',
            'aapt2': tools / 'bin/aapt2', 'zipalign': tools / 'bin/zipalign',
            'd8': reference / 'inputs/R8_9_3_27/r8-9.3.27.jar',
            'signer': tools / 'lib/apksigner.jar', 'lib64': tools / 'lib64',
            'cert': security / 'platform.x509.pem', 'key': security / 'platform.pk8'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / 'owneropen/app-source')
    parser.add_argument('--profile', choices=['local', 'pocket4'], default='local')
    parser.add_argument('--out', type=Path)
    parser.add_argument('--android-jar', type=Path)
    parser.add_argument('--build-tools', type=Path)
    parser.add_argument('--system-modules', type=Path)
    parser.add_argument('--sign', action='store_true')
    args = parser.parse_args()
    if args.sign and args.profile != 'pocket4':
        parser.error('--sign is available only with the existing Pocket4 platform key')
    source = args.source.resolve(strict=True)
    files = inventory(source)
    digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = (args.out or ROOT / 'builds' / f'v47-{digest[:12]}-{stamp}-{uuid.uuid4().hex[:6]}').resolve()
    out.mkdir(parents=True, exist_ok=False)
    for d in ('source', 'generated', 'classes', 'dex', 'tmp'):
        (out / d).mkdir()
    conf = profile(args.profile, args)
    env = dict(os.environ)
    for k in ('JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS'):
        env.pop(k, None)
    env.update(LD_LIBRARY_PATH=str(conf['lib64']), TMPDIR=str(out / 'tmp'), LANG='C.UTF-8', LC_ALL='C.UTF-8')
    receipt = {'schema': 'razr.owneropen.ui.r8.build.v1', 'state': 'BUILDING',
               'started_utc': utc(), 'profile': args.profile, 'output': str(out),
               'source': str(source), 'source_sha256': digest, 'build_script_sha256': sha(Path(__file__)),
               'package': PACKAGE, 'version_code': VERSION_CODE, 'version_name': VERSION_NAME,
               'min_sdk': MIN_SDK, 'target_sdk': TARGET_SDK, 'java_language_level': 17,
               'compiled': False, 'signed': False, 'signature_verified': False,
               'installed': False, 'phone_operations': 0, 'model_requests_issued': False,
               'stop_reset': False, 'whole_device_acceptance': 'closed_by_user', 'steps': []}

    def save() -> None:
        tmp = out / 'build-receipt.json.tmp'
        tmp.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
        tmp.replace(out / 'build-receipt.json')

    def run(name: str, argv: list, timeout: int = 120) -> str:
        command = [str(x) for x in argv]
        shown = list(command)
        if '--key' in shown:
            shown[shown.index('--key') + 1] = '<existing-platform-key>'
        step = {'name': name, 'argv': shown, 'started_utc': utc(), 'state': 'running'}
        receipt['steps'].append(step)
        save()
        print('STEP', name, flush=True)
        result = subprocess.run(command, cwd=out, env=env, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=timeout)
        (out / (name + '.stdout')).write_text(result.stdout)
        (out / (name + '.stderr')).write_text(result.stderr)
        step.update(exit_code=result.returncode, finished_utc=utc(), state='passed' if result.returncode == 0 else 'failed')
        save()
        if result.returncode:
            raise RuntimeError(name + ' failed; see retained stdout/stderr')
        return result.stdout

    try:
        for key in ('sdk', 'aapt2', 'zipalign', 'd8'):
            if not conf[key].is_file():
                raise RuntimeError('Missing compiler input: ' + str(conf[key]))
        if not (conf['system'] / 'lib/modules').is_file():
            raise RuntimeError('Missing Android compiler system image; run prepare_android_system_modules.py')
        receipt['compiler_inputs'] = {k: {'path': str(conf[k]), 'sha256': sha(conf[k])}
                                      for k in ('sdk', 'aapt2', 'zipalign', 'd8')}
        receipt['compiler_inputs']['system_modules'] = {'path': str(conf['system']), 'sha256': sha(conf['system'] / 'lib/modules')}
        for f in files:
            destination = out / 'source' / f['path']
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / f['path'], destination)
            if sha(destination) != f['sha256']:
                raise RuntimeError('Source changed while snapshotting')
        if files != inventory(source):
            raise RuntimeError('Source changed while snapshotting')
        (out / 'source-hash-manifest.json').write_text(json.dumps({'source_sha256': digest, 'files': files}, indent=2) + '\n')
        run('aapt2-version', [conf['aapt2'], 'version'])
        run('resources-compile', [conf['aapt2'], 'compile', '--dir', out / 'source/res', '-o', out / 'compiled-res.zip'])
        link = [conf['aapt2'], 'link', '-I', conf['sdk'], '--manifest', out / 'source/AndroidManifest.xml',
                '-R', out / 'compiled-res.zip', '-o', out / 'resources.apk', '--java', out / 'generated',
                '--min-sdk-version', MIN_SDK, '--target-sdk-version', TARGET_SDK,
                '--version-code', VERSION_CODE, '--version-name', VERSION_NAME, '--replace-version', '--auto-add-overlay']
        if (out / 'source/assets').is_dir():
            link += ['-A', out / 'source/assets']
        run('resources-link', link)
        java_sources = sorted((out / 'source/src').rglob('*.java')) + sorted((out / 'generated').rglob('*.java'))
        run('javac', conf['javac'] + ['-encoding', 'UTF-8', '-source', '17', '-target', '17',
            '-XDstringConcat=inline', '--system', conf['system'], '-classpath', conf['sdk'], '-d', out / 'classes', *java_sources])
        classes = sorted((out / 'classes').rglob('*.class'))
        if not classes:
            raise RuntimeError('No class files generated')
        receipt.update(java_source_count=len(java_sources), class_count=len(classes))
        jar = out / 'classes.jar'
        with zipfile.ZipFile(jar, 'x', zipfile.ZIP_STORED) as z:
            for p in classes:
                z.write(p, p.relative_to(out / 'classes').as_posix())
        run('d8', conf['java'] + ['-cp', conf['d8'], 'com.android.tools.r8.D8', '--release', '--min-api', MIN_SDK,
             '--lib', conf['sdk'], '--output', out / 'dex', jar])
        dex = sorted((out / 'dex').glob('classes*.dex'))
        if not dex or any(p.read_bytes()[:4] != b'dex\n' for p in dex):
            raise RuntimeError('Invalid or absent DEX output')
        receipt['dex'] = [{'name': p.name, 'bytes': p.stat().st_size, 'sha256': sha(p)} for p in dex]
        unaligned = out / (APK_STEM + '-unaligned.apk')
        with zipfile.ZipFile(out / 'resources.apk') as src, zipfile.ZipFile(unaligned, 'x') as target:
            for info in src.infolist():
                if info.filename.startswith('META-INF/'):
                    raise RuntimeError('Unexpected signature in the resource package')
                target.writestr(info, src.read(info))
            for p in dex:
                target.write(p, p.name, compress_type=zipfile.ZIP_STORED)
        apk = out / (APK_STEM + '-unsigned.apk')
        run('zipalign', [conf['zipalign'], '-p', '4', unaligned, apk])
        receipt['compiled'] = True
        if args.sign:
            if not conf['cert'].is_file() or not conf['key'].is_file():
                raise RuntimeError('Existing Pocket4 platform signing material is unavailable')
            certificate = hashlib.sha256(ssl.PEM_cert_to_DER_cert(conf['cert'].read_text('ascii'))).hexdigest()
            if certificate != CERT_SHA256:
                raise RuntimeError('Existing platform certificate does not match the installed application')
            signed = out / (APK_STEM + '-platform.apk')
            run('platform-sign', conf['java'] + ['-jar', conf['signer'], 'sign', '--key', conf['key'], '--cert', conf['cert'],
                '--min-sdk-version', MIN_SDK, '--v1-signing-enabled', 'false', '--v2-signing-enabled', 'false',
                '--v3-signing-enabled', 'true', '--v4-signing-enabled', 'false', '--out', signed, apk])
            verification = run('signature-verify', conf['java'] + ['-jar', conf['signer'], 'verify', '--verbose', '--print-certs', signed])
            signers = re.findall(r'Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]+)', verification)
            if [s.lower() for s in signers] != [CERT_SHA256] or not re.search(r'Verified using v3 scheme .*?: true', verification):
                raise RuntimeError('Final APK did not verify with the expected platform certificate and v3 signature')
            receipt.update(signed=True, signature_verified=True, certificate_sha256=certificate)
            apk = signed
        run('alignment-verify', [conf['zipalign'], '-c', '-p', '4', apk])
        badging = run('manifest-badging', [conf['aapt2'], 'dump', 'badging', apk])
        first = next((l for l in badging.splitlines() if l.startswith('package: ')), '')
        fields = dict(re.findall(r"([A-Za-z]+)='([^']*)'", first))
        if fields.get('name') != PACKAGE or fields.get('versionCode') != str(VERSION_CODE) or fields.get('versionName') != VERSION_NAME:
            raise RuntimeError('Compiled package/version mismatch')
        minimum_sdk_lines = (f"minSdkVersion:'{MIN_SDK}'", f"sdkVersion:'{MIN_SDK}'")
        if f"targetSdkVersion:'{TARGET_SDK}'" not in badging.splitlines() or not any(
                line in badging.splitlines() for line in minimum_sdk_lines):
            raise RuntimeError('Compiled SDK levels mismatch')
        receipt['compile_sdk'] = int(fields.get('compileSdkVersion', '0'))
        if receipt['compile_sdk'] != 36:
            raise RuntimeError('Unexpected compiler SDK version')
        receipt.update(state='SIGNED_UI_APK_BUILT' if args.sign else 'UNSIGNED_UI_CANDIDATE_BUILT',
                       apk={'path': str(apk), 'bytes': apk.stat().st_size, 'sha256': sha(apk)})
    except BaseException as exc:
        receipt.update(state='FAILED_BUILD_PRESERVED', error=type(exc).__name__ + ': ' + str(exc))
    finally:
        receipt['finished_utc'] = utc()
        save()
    print(json.dumps({'state': receipt['state'], 'receipt': str(out / 'build-receipt.json'),
                      'apk': receipt.get('apk'), 'error': receipt.get('error')}, ensure_ascii=False), flush=True)
    return 0 if receipt['state'] in ('SIGNED_UI_APK_BUILT', 'UNSIGNED_UI_CANDIDATE_BUILT') else 1


if __name__ == '__main__':
    sys.exit(main())
